//! [`CgkaController`]: a synchronous, deterministic wrapper over `beekem::cgka::Cgka`.
//!
//! This is the whole cryptographic surface of the workspace. It owns the CGKA
//! tree, the local signing key and the local leaf secret, and it exposes group
//! membership and content encryption as ordinary synchronous methods.
//!
//! # Causal delivery is the caller's job
//!
//! beekem states plainly that it "assume[s] that all operations are received in
//! causal order". [`CgkaController::merge`] surfaces that as
//! [`MergeOutcome::Deferred`] rather than an error: an operation whose
//! predecessors have not arrived yet is normal under gossip, not a fault. The
//! caller is expected to park it and retry — see
//! [`CgkaController::merge_pending`].
//!
//! # Authentication is also the caller's job
//!
//! beekem verifies no signatures at all — `Cgka::merge_concurrent_operation`
//! checks only the operation hash and the causal predecessors, and
//! `Cgka::apply_operation` mutates the tree without ever consulting the issuer.
//! Since the control plane is a public broadcast topic, an unverified `merge`
//! would let anyone splice their own leaf into the tree and read everything
//! written afterwards.
//!
//! [`CgkaController::merge`] therefore applies two checks that beekem does not:
//!
//! 1. **Signature.** The operation must verify against its own embedded issuer
//!    key, or it is rejected as [`CoreError::BadSignature`].
//! 2. **Membership.** That issuer must be someone an accepted `Add` introduced,
//!    or it is rejected as [`CoreError::Unauthorized`]. A valid signature alone
//!    proves only that the issuer signed its own message, which a freshly
//!    minted keypair can do just as well as a member.
//!
//! Neither check is a substitute for the other, and both are cheap next to the
//! tree operations they guard.

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use beekem::{
    cgka::Cgka,
    error::CgkaError,
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
use future_form::Local;
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    content::{Chunk, ChunkRef},
    error::CoreError,
    sync_poll::now_or_never,
};

/// A signed CGKA operation as it travels over the control plane.
pub type ControlOp = Arc<Signed<CgkaOperation>>;

/// How many out-of-order operations may wait for their predecessors at once.
///
/// Parking is unavoidable — gossip does not deliver in causal order — but an
/// unbounded parking area is a remote memory-exhaustion vector: an operation
/// naming predecessors that will never exist waits forever, and nothing stops a
/// peer from sending a great many of them. Signature and membership checks run
/// before anything is parked, so reaching this limit means a *member* is
/// misbehaving or the local node is very far behind.
///
/// Overflow evicts oldest-first. That is safe rather than merely expedient: the
/// operation log is re-exchanged whenever a neighbour appears, so an evicted
/// operation is recoverable, whereas exhausted memory is not.
pub const MAX_PARKED_OPS: usize = 1024;

/// Which group epoch key a ciphertext names.
///
/// The digest of the PCS key a chunk was encrypted under, carried as plain
/// bytes so it can cross the wire in a repair request without exposing
/// beekem's `Digest<PcsKey>` in this crate's public API. It identifies a key,
/// it is not one: the digest of a key is safe to broadcast, which is what makes
/// "I cannot decrypt epoch E" a sayable sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EpochId([u8; 32]);

impl EpochId {
    /// The epoch a chunk was encrypted under.
    #[must_use]
    pub fn of(chunk: &Chunk) -> Self {
        Self(*chunk.pcs_key_hash.raw.as_bytes())
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

/// What the local CGKA could make of an arriving ciphertext.
///
/// The distinction between the two failing cases is the whole point of this
/// type, and it is decidable rather than heuristic: a chunk names the operation
/// that established its epoch, so either that operation is in our graph or it
/// is not.
///
/// * absent — the control plane has not caught up yet, and this chunk becomes
///   readable the moment it does. Park it.
/// * present, and the key still cannot be derived — our leaf was not in the
///   tree at that epoch, so no amount of waiting will help. That is forward
///   secrecy, and the only repair is somebody re-encrypting the content under a
///   live epoch.
///
/// Collapsing these two into one "not applicable" answer is what let
/// permanently undecryptable ciphertext accumulate in the pending queue with
/// nothing able to notice.
#[derive(Debug)]
pub enum DecryptOutcome {
    /// The chunk was decrypted.
    Plaintext(Vec<u8>),
    /// The operation that established this epoch has not arrived yet.
    AwaitingOp,
    /// This node can never derive the key: the epoch predates its membership.
    Unreachable,
}

/// What happened when an operation was offered to the local CGKA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The operation was new and has been applied.
    Applied,
    /// The operation was already known; nothing changed.
    Duplicate,
    /// The operation's causal predecessors have not arrived yet. It has been
    /// parked and will be retried by [`CgkaController::merge_pending`].
    Deferred,
}

/// What an applied operation did to the group's membership.
///
/// Extracted before the merge consumes the operation, and applied after it
/// succeeds. Named rather than left as a pair of `Option`s so that the two
/// cases cannot both be set — an operation is an `Add` or a `Remove`, never
/// both, and a tuple would let a future edit express otherwise.
#[derive(Debug, Clone, Copy)]
enum MembershipChange {
    /// An `Add` introduced this identity.
    Added(MemberId),
    /// A `Remove` retracted this identity.
    Removed(MemberId),
}

/// Synchronous, deterministic owner of the local CGKA state.
///
/// Every method is pure with respect to the outside world: no clock, no
/// sockets, no filesystem. The only ambient input is the caller-supplied
/// `csprng`, which a simulation seeds deterministically.
#[derive(Clone)]
pub struct CgkaController {
    cgka: Cgka,
    signer: MemorySigner,
    member_id: MemberId,
    share_secret: ShareSecretKey,
    share_key: ShareKey,
    /// Every identity an accepted `Add` has ever introduced.
    ///
    /// Deliberately monotone: a `Remove` does *not* retract an entry. Two peers
    /// that observe a removal and a concurrent operation by the removed member
    /// in opposite orders would otherwise disagree about whether that operation
    /// is admissible, and one of them would drop an operation the other kept —
    /// divergence, from a check meant to prevent tampering. Nothing is lost by
    /// being permissive here: a removed member's operations cannot reach the
    /// root key, so beekem's own tree semantics already neutralise them. What
    /// this set exists to stop is the *unrelated* keypair, which no `Add` names
    /// under any ordering.
    known_members: HashSet<MemberId>,
    /// Every identity that is a member *right now*.
    ///
    /// Non-monotone: a `Remove` retracts an entry, which is exactly what
    /// [`Self::known_members`] must never do.
    ///
    /// # Why these cannot be one set
    ///
    /// They answer different questions and pay for the answer differently.
    ///
    /// `known_members` is the **authorisation** predicate, applied to every
    /// operation before it is merged. It must be monotone so that two peers
    /// which observe a removal and a concurrent operation by the removed member
    /// in opposite orders still agree on admissibility — the cost of
    /// disagreeing there is a *dropped operation*, which diverges the group
    /// permanently.
    ///
    /// `current_members` is the **enumeration and connection-policy** predicate:
    /// who to list in the UI, and whose connections to accept. It is allowed to
    /// be order-sensitive because the cost of disagreeing is a *refused
    /// connection*, which the next merge repairs. Eviction is eventual by
    /// construction, and no amount of set discipline here would make it
    /// otherwise.
    ///
    /// Collapsing them into one set therefore has no safe direction. Made
    /// monotone, a removed device stays on every roster forever and revocation
    /// stops meaning anything. Made non-monotone, `merge` starts rejecting
    /// operations on an order-dependent predicate and peers diverge. This field
    /// is consequently never read from [`Self::merge_verified`].
    current_members: HashSet<MemberId>,
    /// Operations received out of causal order, awaiting their predecessors.
    ///
    /// A queue rather than a stack: eviction takes the oldest, which is the one
    /// least likely to still be waiting on something in flight.
    parked: VecDeque<ControlOp>,
    /// Operations dropped because [`MAX_PARKED_OPS`] was reached.
    evicted_ops: u64,
}

impl std::fmt::Debug for CgkaController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CgkaController")
            .field("member_id", &self.member_id)
            .field("group_size", &self.cgka.group_size())
            .field("ops_count", &self.cgka.ops_count())
            .field("known_members", &self.known_members.len())
            .field("current_members", &self.current_members.len())
            .field("parked", &self.parked.len())
            .finish_non_exhaustive()
    }
}

impl CgkaController {
    /// Found a new workspace with the local member as its sole occupant.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the initial tree cannot be built, or
    /// [`CoreError::SignerYielded`] if `signer` is not synchronous.
    pub fn create<R: CryptoRng + RngCore>(
        tree_id: TreeId,
        signer: MemorySigner,
        csprng: &mut R,
    ) -> Result<Self, CoreError> {
        let member_id = MemberId::from(signer.verifying_key());
        let share_secret = ShareSecretKey::generate(csprng);
        let share_key = share_secret.share_key();

        let mut cgka = now_or_never(Cgka::new::<Local, _>(
            tree_id, member_id, share_key, &signer,
        ))
        .ok_or(CoreError::SignerYielded)??;

        // `Cgka::new` leaves `owner_sks` empty; without our own leaf secret in
        // it we cannot encrypt our path on the first update.
        cgka.owner_sks.insert(share_key, share_secret);

        Ok(Self {
            cgka,
            signer,
            member_id,
            share_secret,
            share_key,
            // The founder is a member by construction: their own init `Add` is
            // self-issued and has no predecessors to authorise it against.
            known_members: HashSet::from([member_id]),
            current_members: HashSet::from([member_id]),
            parked: VecDeque::new(),
            evicted_ops: 0,
        })
    }

    /// Join an existing workspace by replaying its operation log.
    ///
    /// `ops` must be in causal order and start with the founding `Add`. The
    /// invitee's own secret never leaves their device: the log is public,
    /// signed data, and the local leaf secret is spliced in when the replay
    /// reaches this member's own `Add` operation.
    ///
    /// `share_secret` must be the secret half of the [`ShareKey`] the inviter
    /// used in the `Add`, which is why an invite is a two-step exchange: the
    /// invitee publishes a `ShareKey`, the inviter names it in an `Add`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::MissingInitAdd`] if the log does not begin with a
    /// founding `Add`, or [`CoreError::NotInvited`] if it contains no `Add` for
    /// this member.
    pub fn join(
        tree_id: TreeId,
        signer: MemorySigner,
        share_secret: ShareSecretKey,
        ops: &[Signed<CgkaOperation>],
    ) -> Result<Self, CoreError> {
        let member_id = MemberId::from(signer.verifying_key());
        let share_key = share_secret.share_key();

        let Some((init, rest)) = ops.split_first() else {
            return Err(CoreError::MissingInitAdd);
        };
        let CgkaOperation::Add {
            added_id: founder_id,
            pk: founder_pk,
            ref predecessors,
            ..
        } = init.payload
        else {
            return Err(CoreError::MissingInitAdd);
        };
        if !predecessors.is_empty() {
            return Err(CoreError::MissingInitAdd);
        }

        // The init `Add` bypasses `merge` — it is handed straight to
        // `Cgka::new_from_init_add` — so its two checks have to be repeated
        // here, or the entire replayed history would rest on an unverified
        // root. The founder's `Add` is self-issued, which is the one case where
        // "the issuer introduced themselves" is legitimate; requiring that
        // stops an attacker from presenting a log that crowns someone else.
        init.try_verify().map_err(|_| CoreError::BadSignature)?;
        let init_issuer = MemberId::from(*init.issuer());
        if init_issuer != founder_id {
            return Err(CoreError::Unauthorized {
                issuer: init_issuer.to_bytes(),
            });
        }

        let cgka = Cgka::new_from_init_add(tree_id, founder_id, founder_pk, init.clone())?;

        let mut this = Self {
            cgka,
            signer,
            member_id,
            share_secret,
            share_key,
            known_members: HashSet::from([founder_id]),
            current_members: HashSet::from([founder_id]),
            parked: VecDeque::new(),
            evicted_ops: 0,
        };

        let mut invited = founder_id == member_id;
        for op in rest {
            // Taking ownership of the tree happens exactly at our own `Add`:
            // we inherit the current owner's public key map, splice in our own
            // leaf secret, and only then apply the operation.
            if let CgkaOperation::Add { added_id, pk, .. } = op.payload
                && added_id == member_id
            {
                let mut owner_sks = this.cgka.owner_sks.clone();
                owner_sks.insert(pk, share_secret);
                this.cgka = this.cgka.with_new_owner(member_id, owner_sks)?;
                invited = true;
            }
            this.merge(Arc::new(op.clone()))?;
        }

        if !invited {
            return Err(CoreError::NotInvited);
        }
        this.merge_pending()?;
        if this.parked_len() > 0 {
            // Some operation's predecessors never appeared, so the log has a
            // hole. Failing here is far kinder than handing back a controller
            // that silently cannot decrypt anything.
            return Err(CoreError::IncompleteLog {
                unresolved: this.parked_len(),
            });
        }
        Ok(this)
    }

    /// This member's identity in the CGKA tree.
    #[must_use]
    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// The number of members currently holding a leaf.
    #[must_use]
    pub fn group_size(&self) -> u32 {
        self.cgka.group_size()
    }

    /// The founding `Add` operation, needed to bootstrap any joiner.
    #[must_use]
    pub fn init_add_op(&self) -> Signed<CgkaOperation> {
        self.cgka.init_add_op()
    }

    /// The complete operation log in causal order — the payload of an invite.
    ///
    /// beekem topologically sorts its operation graph into epochs of mutually
    /// concurrent operations; flattening those in order yields a log that
    /// [`Self::join`] can replay. A *partial* log is not enough: a joiner whose
    /// log is missing an intermediate operation will park their own `Add`
    /// forever, because its predecessors never arrive.
    ///
    /// The log is public, signed data. It contains no secrets, which is why an
    /// invite can be handed over without any confidential channel.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the operation graph cannot be sorted.
    pub fn op_log(&self) -> Result<Vec<Signed<CgkaOperation>>, CoreError> {
        Ok(self
            .cgka
            .ops()?
            .into_iter()
            .flatten()
            .map(|op| (*op).clone())
            .collect())
    }

    /// Operations parked awaiting their causal predecessors.
    #[must_use]
    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// Operations discarded because the parking area was full.
    ///
    /// Non-zero means this node has lost control-plane history it may still
    /// need. That is recoverable — the next neighbour exchange re-sends the log
    /// — but a value that climbs steadily indicates a peer flooding the topic.
    #[must_use]
    pub fn evicted_ops(&self) -> u64 {
        self.evicted_ops
    }

    /// Park an out-of-order operation, evicting the oldest if the queue is full.
    fn park(&mut self, op: ControlOp) {
        if self.parked.len() >= MAX_PARKED_OPS {
            self.parked.pop_front();
            self.evicted_ops += 1;
        }
        self.parked.push_back(op);
    }

    /// Whether an accepted `Add` has ever introduced this identity.
    ///
    /// This is the authorisation predicate applied to every incoming operation.
    /// It is monotone, so it answers "was ever a member", not "is a member
    /// now"; [`Self::group_size`] answers the latter.
    #[must_use]
    pub fn is_known_member(&self, member: MemberId) -> bool {
        self.known_members.contains(&member)
    }

    /// Whether this identity is a member *now*, removals taken into account.
    ///
    /// This is the enumeration and connection-policy predicate. It is **not**
    /// an authorisation predicate and must never be used as one — see the field
    /// documentation on `current_members` for why the two cannot be the same
    /// question.
    #[must_use]
    pub fn is_current_member(&self, member: MemberId) -> bool {
        self.current_members.contains(&member)
    }

    /// Every identity that is a member now, in arbitrary order.
    ///
    /// Ordering is genuinely arbitrary — it comes from a `HashSet` — so callers
    /// that need determinism must sort. The roster does not care, and a
    /// simulation that did would be asserting on hash iteration order.
    pub fn current_members(&self) -> impl Iterator<Item = MemberId> + '_ {
        self.current_members.iter().copied()
    }

    /// Admit a new member who has published `share_key`.
    ///
    /// Returns `None` if the member is already present. The returned operation
    /// must be broadcast on the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the tree rejects the addition.
    pub fn add_member(
        &mut self,
        member: MemberId,
        share_key: ShareKey,
    ) -> Result<Option<Signed<CgkaOperation>>, CoreError> {
        let op = now_or_never(self.cgka.add::<Local, _>(member, share_key, &self.signer))
            .ok_or(CoreError::SignerYielded)??;
        // A locally issued `Add` applies straight to the tree without passing
        // through `merge`, so it has to register the new member here or we
        // would reject their very first operation as unauthorised.
        if op.is_some() {
            self.known_members.insert(member);
            self.current_members.insert(member);
        }
        Ok(op)
    }

    /// Remove a member, revoking their ability to read future content.
    ///
    /// Returns `None` if the member is not present. The returned operation must
    /// be broadcast on the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] wrapping [`CgkaError::RemoveLastMember`] if
    /// this would empty the group.
    pub fn remove_member(
        &mut self,
        member: MemberId,
    ) -> Result<Option<Signed<CgkaOperation>>, CoreError> {
        let op = now_or_never(self.cgka.remove::<Local, _>(member, &self.signer))
            .ok_or(CoreError::SignerYielded)??;
        // Mirrors the `add_member` case: a locally issued `Remove` never passes
        // through `merge`, so nothing else would retract the member here. Note
        // the asymmetry with `known_members`, which is deliberately left alone
        // — retracting there would make admissibility delivery-order dependent.
        if op.is_some() {
            self.current_members.remove(&member);
        }
        Ok(op)
    }

    /// Rotate this member's leaf key, re-keying the path to the root.
    ///
    /// This is the post-compromise security primitive: after a rotation an
    /// attacker holding the old leaf secret can no longer derive group keys.
    /// The returned operation must be broadcast on the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the path cannot be re-encrypted.
    pub fn rotate<R: CryptoRng + RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Signed<CgkaOperation>, CoreError> {
        let new_secret = ShareSecretKey::generate(csprng);
        let new_key = new_secret.share_key();
        let (_, op) = now_or_never(self.cgka.update::<Local, _, R>(
            new_key,
            new_secret,
            &self.signer,
            csprng,
        ))
        .ok_or(CoreError::SignerYielded)??;
        self.share_secret = new_secret;
        self.share_key = new_key;
        Ok(op)
    }

    /// Encrypt a chunk of plaintext under a freshly derived application secret.
    ///
    /// `pred_refs` are the refs of the chunks this one causally follows; they
    /// are bound into the derived key, so a peer can only decrypt once it has
    /// caught up.
    ///
    /// The optional operation in the return value is beekem performing an
    /// implicit PCS update because the tree had no root key. **It must be
    /// broadcast**, or no other peer will be able to decrypt this chunk.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if no application secret can be derived, or
    /// [`CoreError::Aead`] if encryption fails.
    pub fn encrypt<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        pred_refs: &[ChunkRef],
        csprng: &mut R,
    ) -> Result<(Chunk, Option<Signed<CgkaOperation>>), CoreError> {
        let content_ref = ChunkRef::of(plaintext);
        let preds = pred_refs.to_vec();
        let (secret, op) = now_or_never(self.cgka.new_app_secret_for::<Local, _, _, R>(
            &content_ref,
            plaintext,
            &preds,
            &self.signer,
            csprng,
        ))
        .ok_or(CoreError::SignerYielded)??;
        Ok((secret.try_encrypt(plaintext)?, op))
    }

    /// Encrypt a chunk under an epoch key minted for the occasion.
    ///
    /// This is [`Self::encrypt`] with the guarantee that
    /// [`Self::encrypt`] cannot give: the ciphertext is keyed under an epoch
    /// that did not exist a moment ago, and that therefore *every* leaf
    /// currently in the tree can derive — including one admitted since the last
    /// time anybody published. Nothing outside the tree can derive it, so a
    /// removed member gains nothing from it.
    ///
    /// It is the only sound answer to "I cannot read what you published":
    /// `encrypt` reuses the current PCS key whenever beekem has one, so
    /// re-publishing unchanged content reproduces a byte-identical chunk and
    /// tells a stuck peer nothing it did not already know.
    ///
    /// The returned operations **must be broadcast before the chunk**, in the
    /// order given, or the re-key is invisible to peers and the ciphertext is
    /// unreadable to everyone.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the path cannot be re-encrypted or no
    /// application secret can be derived, or [`CoreError::Aead`] if encryption
    /// fails.
    pub fn encrypt_fresh<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        pred_refs: &[ChunkRef],
        csprng: &mut R,
    ) -> Result<(Chunk, Vec<Signed<CgkaOperation>>), CoreError> {
        let rotation = self.rotate(csprng)?;
        let (chunk, implicit) = self.encrypt(plaintext, pred_refs, csprng)?;
        // The rotation leaves the tree with a root key, so `encrypt` normally
        // adds nothing here. It is still collected rather than asserted away:
        // a concurrent operation merged between the two calls can blank the
        // root again, and dropping the resulting update would make this very
        // chunk undecryptable — the failure this method exists to prevent.
        let ops = std::iter::once(rotation).chain(implicit).collect();
        Ok((chunk, ops))
    }

    /// Decrypt a chunk produced by any member of the group.
    ///
    /// Failure to decrypt is not an error: it is the ordinary condition of a
    /// peer whose control plane has not caught up, and the *permanent*
    /// condition of a peer that was not a member when the chunk was written.
    /// [`DecryptOutcome`] tells those two apart so the caller can park one and
    /// ask for a repair of the other.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Aead`] if the key was derived and authentication
    /// then failed — which is tampering rather than ordering, and the one case
    /// here that really is a fault.
    pub fn decrypt(&mut self, chunk: &Chunk) -> Result<DecryptOutcome, CoreError> {
        let Ok(key) = self.cgka.decryption_key_for(chunk) else {
            // Ask the graph, not the error code: the chunk names the operation
            // that established its epoch, so "have I seen that operation?" is
            // exactly the question that separates "not yet" from "never", and
            // it is one beekem answers directly.
            let establishing = HashSet::from([chunk.pcs_update_op_hash]);
            return if self.cgka.contains_predecessors(&establishing) {
                Ok(DecryptOutcome::Unreachable)
            } else {
                Ok(DecryptOutcome::AwaitingOp)
            };
        };
        Ok(DecryptOutcome::Plaintext(chunk.try_decrypt(key)?))
    }

    /// Offer a remote operation to the local CGKA.
    ///
    /// The operation's signature is checked first, then — once its causal
    /// predecessors are present — its issuer is checked against the membership
    /// this controller has accepted. Out-of-order arrivals are parked rather
    /// than rejected; call [`Self::merge_pending`] after any successful merge to
    /// drain them.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BadSignature`] if the operation is forged or
    /// tampered with, [`CoreError::Unauthorized`] if it is validly signed by a
    /// non-member, and [`CoreError::Cgka`] for genuine tree failures. An
    /// out-of-order operation is *not* an error.
    pub fn merge(&mut self, op: ControlOp) -> Result<MergeOutcome, CoreError> {
        // Cheapest meaningful check, and the only context-free one: do it
        // before the operation is allowed to occupy a slot in `parked`, so
        // unverifiable traffic cannot accumulate.
        op.try_verify().map_err(|_| CoreError::BadSignature)?;
        self.merge_verified(op)
    }

    /// Merge an operation whose signature has already been checked.
    ///
    /// Parked operations were verified on the way in, so re-verifying them on
    /// every drain would repeat an Ed25519 check per operation per round.
    fn merge_verified(&mut self, op: ControlOp) -> Result<MergeOutcome, CoreError> {
        let preds: HashSet<_> = op.payload.predecessors().into_iter().collect();
        if !self.cgka.contains_predecessors(&preds) {
            self.park(op);
            return Ok(MergeOutcome::Deferred);
        }

        // Authorise only once the predecessors are in hand. Causality is what
        // makes this sound: an operation naming its predecessors can only have
        // been issued by someone who already saw them, so the `Add` that
        // introduced a legitimate issuer is necessarily among the operations
        // already accepted. Checking earlier would reject a member whose own
        // `Add` is still in flight.
        let issuer = MemberId::from(*op.issuer());
        if !self.known_members.contains(&issuer) {
            return Err(CoreError::Unauthorized {
                issuer: issuer.to_bytes(),
            });
        }

        // Read this before the merge consumes the operation.
        let membership_change = match op.payload {
            CgkaOperation::Add { added_id, .. } => Some(MembershipChange::Added(added_id)),
            CgkaOperation::Remove { id, .. } => Some(MembershipChange::Removed(id)),
            CgkaOperation::Update { .. } => None,
        };

        match self.cgka.merge_concurrent_operation(op) {
            Ok(true) => {
                // Applied only. A `Duplicate` changed nothing in the tree and
                // must change nothing here either, or a re-delivered `Add`
                // would resurrect a member a later `Remove` had already
                // retracted from `current_members`.
                match membership_change {
                    Some(MembershipChange::Added(added)) => {
                        self.known_members.insert(added);
                        self.current_members.insert(added);
                    }
                    Some(MembershipChange::Removed(removed)) => {
                        // `known_members` is deliberately not touched: see its
                        // field documentation. Only the roster shrinks.
                        self.current_members.remove(&removed);
                    }
                    None => {}
                }
                Ok(MergeOutcome::Applied)
            }
            Ok(false) => Ok(MergeOutcome::Duplicate),
            // beekem re-checks predecessors internally; treat a race here the
            // same way we treat the check above rather than failing the peer.
            Err(CgkaError::OutOfOrderOperation) => Ok(MergeOutcome::Deferred),
            Err(err) => Err(err.into()),
        }
    }

    /// Retry every parked operation, repeating until no further progress.
    ///
    /// Returns the number of operations that became applicable.
    ///
    /// A parked operation that turns out to be unauthorised once its
    /// predecessors arrive is discarded rather than reported: it was hostile,
    /// and it must not take the legitimate operations queued behind it with it.
    /// Anything depending on a discarded operation stays parked, which is what
    /// surfaces the gap to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if a parked operation fails for a reason
    /// other than missing predecessors — but only after the round has finished,
    /// so the rest of the queue survives the report.
    pub fn merge_pending(&mut self) -> Result<usize, CoreError> {
        let mut total = 0;
        let mut first_error = None;
        loop {
            let candidates = std::mem::take(&mut self.parked);
            let before = total;
            for op in candidates {
                #[allow(
                    clippy::match_same_arms,
                    reason = "a benign no-op and a discarded hostile operation \
                              are the same statement but not the same decision; \
                              collapsing them would erase why each is ignored"
                )]
                match self.merge_verified(op) {
                    Ok(MergeOutcome::Applied) => total += 1,
                    // Already known, or still waiting on predecessors — it was
                    // re-parked by `merge_verified` either way.
                    Ok(MergeOutcome::Duplicate | MergeOutcome::Deferred) => {}
                    // Hostile: drop it, and specifically do not let it abort the
                    // round and strand the legitimate operations behind it.
                    Err(CoreError::Unauthorized { .. }) => {}
                    Err(err) => first_error = first_error.or(Some(err)),
                }
            }
            if total == before {
                return first_error.map_or(Ok(total), Err);
            }
        }
    }
}
