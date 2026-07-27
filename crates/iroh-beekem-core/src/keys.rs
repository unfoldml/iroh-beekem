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
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

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
            tree_id,
            member_id,
            share_key,
            &signer,
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

    /// Decrypt a chunk produced by any member of the group.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the local tree cannot reach the PCS key
    /// the chunk names — which is exactly what a revoked member sees — or
    /// [`CoreError::Aead`] if authentication fails.
    pub fn decrypt(&mut self, chunk: &Chunk) -> Result<Vec<u8>, CoreError> {
        let key = self.cgka.decryption_key_for(chunk)?;
        Ok(chunk.try_decrypt(key)?)
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
        let introduces = match op.payload {
            CgkaOperation::Add { added_id, .. } => Some(added_id),
            CgkaOperation::Remove { .. } | CgkaOperation::Update { .. } => None,
        };

        match self.cgka.merge_concurrent_operation(op) {
            Ok(true) => {
                if let Some(added) = introduces {
                    self.known_members.insert(added);
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
