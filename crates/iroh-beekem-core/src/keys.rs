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
    capability::{
        AdminAction, AdminProposal, Approval, CapabilityStore, Certificate, DEFAULT_THRESHOLD,
        DeviceBinding, Grant, Policy, Role, member_from_bytes,
    },
    content::{Chunk, ChunkRef},
    error::CoreError,
    snapshot::CgkaSnapshot,
    sync_poll::now_or_never,
};

/// A signed CGKA operation as it travels over the control plane.
pub type ControlOp = Arc<Signed<CgkaOperation>>;

/// A control operation together with the certificates that authorise it.
///
/// `CgkaOperation` is beekem's type and cannot carry a field, so the proof rides
/// beside the operation rather than inside it.
///
/// # Why the proof is bundled rather than shipped separately
///
/// It makes admissibility decidable **on receipt**. If certificates travelled on
/// their own, an operation arriving before them could not be judged yet, so it
/// would have to be parked — and an insider could then flood the parking area
/// with operations that will never be certified, evicting honest ones under
/// [`MAX_PARKED_OPS`]. Bundling means this phase adds no new parking and no new
/// eviction path: the only reason to park is still a missing causal predecessor.
///
/// The bundle need not be minimal or ordered. Certificates are individually
/// signed and the closure that consumes them reaches a fixpoint, so a receiver
/// may be sent more than it needs, in any order, and still reach the same verdict
/// as everyone else.
#[derive(Debug, Clone)]
pub struct AuthorizedOp {
    /// The operation itself.
    pub op: ControlOp,
    /// Certificates the receiver may not hold yet.
    pub proof: Vec<Certificate>,
}

impl AuthorizedOp {
    /// An operation with a proof bundle.
    #[must_use]
    pub fn new(op: Signed<CgkaOperation>, proof: Vec<Certificate>) -> Self {
        Self {
            op: Arc::new(op),
            proof,
        }
    }

    /// An operation carrying no certificates.
    ///
    /// Correct for an `Update`, which needs no capability beyond membership, and
    /// for any operation whose proof the receiver is known to hold already.
    #[must_use]
    pub fn bare(op: ControlOp) -> Self {
        Self {
            op,
            proof: Vec::new(),
        }
    }
}

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
    /// Who is permitted to do what, rooted at the founder's key.
    ///
    /// The third check `merge_verified` applies, after the signature and
    /// `known_members`. Held here rather than on `WorkspaceState` because this is
    /// where operations are admitted, and a check that lived a layer up would be
    /// one an operation could reach the tree without passing.
    certs: CapabilityStore,
    /// Operations received out of causal order, awaiting their predecessors.
    ///
    /// A queue rather than a stack: eviction takes the oldest, which is the one
    /// least likely to still be waiting on something in flight.
    ///
    /// Holds the whole [`AuthorizedOp`], proof included: a parked operation must
    /// still be judgeable when it is drained, and re-deriving its proof from the
    /// store would fail for exactly the operation that arrived before its own
    /// certificates.
    parked: VecDeque<AuthorizedOp>,
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
            // The founder is the root of the capability closure for the same
            // reason: `tree_id` *is* their key, so their authority is axiomatic
            // rather than granted.
            certs: CapabilityStore::new(member_id.to_bytes()),
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
    /// `certs` are the capability certificates for the workspace. They are
    /// inserted **before** the log is replayed, because replay goes through
    /// [`Self::merge`] and every `Add` in the log must be authorised against
    /// them; a joiner handed the log without the certificates would reject the
    /// history it is trying to adopt, including its own admission.
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
        certs: &[Certificate],
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
            // Rooted at the founder named by the init `Add` verified just above,
            // which is what makes this a trust root and not a claim.
            certs: CapabilityStore::new(founder_id.to_bytes()),
            parked: VecDeque::new(),
            evicted_ops: 0,
        };
        this.certs.extend(certs.iter().cloned());

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
            // The proof is already in the store, inserted above, so the log
            // itself carries no bundles.
            this.merge(AuthorizedOp::bare(Arc::new(op.clone())))?;
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

    /// Capture the whole cryptographic state as a serializable value.
    ///
    /// Everything needed to resume: the tree (with `owner_sks` and every cached
    /// PCS key), the signing key, the leaf secret, both member sets and the
    /// certificate store. `parked` is excluded — see the
    /// [module documentation](crate::snapshot) for why a recoverable cache is
    /// not state.
    #[must_use]
    pub fn snapshot(&self) -> CgkaSnapshot {
        CgkaSnapshot {
            cgka: self.cgka.clone(),
            signer: self.signer.0.to_bytes(),
            share_secret: self.share_secret,
            known_members: self.known_members.iter().map(MemberId::to_bytes).collect(),
            current_members: self
                .current_members
                .iter()
                .map(MemberId::to_bytes)
                .collect(),
            founder: self.certs.founder(),
            certificates: self.certs.certificates(),
            evicted_ops: self.evicted_ops,
        }
    }

    /// Resume from a snapshot taken by [`Self::snapshot`].
    ///
    /// The capability closure is *recomputed* from the stored certificates
    /// rather than restored from a stored derivation, which is what keeps a
    /// resumed node's verdicts identical to a peer that never restarted.
    ///
    /// `share_key` is likewise recomputed from `share_secret`: storing both
    /// would create a pair that a corrupted file could make inconsistent, and an
    /// inconsistent pair fails at the first encryption rather than at load.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::MalformedKey`] if any stored identity is not a valid
    /// Ed25519 verifying key.
    pub fn from_snapshot(snapshot: CgkaSnapshot) -> Result<Self, CoreError> {
        let CgkaSnapshot {
            cgka,
            signer,
            share_secret,
            known_members,
            current_members,
            founder,
            certificates,
            evicted_ops,
        } = snapshot;

        let signer = MemorySigner(ed25519_dalek::SigningKey::from_bytes(&signer));
        let member_id = MemberId::from(signer.verifying_key());

        let known_members = known_members
            .into_iter()
            .map(member_from_bytes)
            .collect::<Result<HashSet<_>, _>>()?;
        let current_members = current_members
            .into_iter()
            .map(member_from_bytes)
            .collect::<Result<HashSet<_>, _>>()?;

        let mut certs = CapabilityStore::new(founder);
        certs.extend(certificates);

        Ok(Self {
            cgka,
            signer,
            member_id,
            share_secret,
            share_key: share_secret.share_key(),
            known_members,
            current_members,
            certs,
            // Empty by design: parked operations return with the next log
            // exchange, and a snapshot is not the place to preserve a queue of
            // operations whose predecessors may already have arrived.
            parked: VecDeque::new(),
            evicted_ops,
        })
    }

    /// This member's identity in the CGKA tree.
    #[must_use]
    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// The tree this controller belongs to.
    ///
    /// Read back off the founding `Add` rather than kept as a field, because
    /// that operation is the one piece of state every member agrees on by
    /// construction — a stored copy could disagree with the tree it labels.
    #[must_use]
    pub fn tree_id(&self) -> TreeId {
        *self.cgka.init_add_op().payload.doc_id()
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
    fn park(&mut self, op: AuthorizedOp) {
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

    /// Who is permitted to do what in this workspace.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilityStore {
        &self.certs
    }

    /// Accept certificates a peer sent, returning how many were new.
    ///
    /// Invalid ones are dropped rather than reported; see
    /// [`CapabilityStore::extend`].
    pub fn absorb_certificates<I: IntoIterator<Item = Certificate>>(&mut self, certs: I) -> usize {
        self.certs.extend(certs)
    }

    /// Mint a signed binding of `device` to `user`, and record it locally.
    ///
    /// The returned certificate must be broadcast, or peers will refuse the
    /// operations the bound device goes on to issue.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn certify_device(
        &mut self,
        device: [u8; 32],
        user: [u8; 32],
        nonce: [u8; 16],
    ) -> Result<Certificate, CoreError> {
        let cert = DeviceBinding::new(device, user, nonce).sign(&self.signer)?;
        self.certs.insert(cert.clone())?;
        Ok(cert)
    }

    /// Mint a signed grant of `capability` to `user`, and record it locally.
    ///
    /// The generation is chosen by [`CapabilityStore::next_seq`], so a grant
    /// always supersedes every grant for that subject this node has seen —
    /// including one a member minted for itself with an inflated `seq`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn certify_role(
        &mut self,
        user: [u8; 32],
        capability: Role,
        nonce: [u8; 16],
    ) -> Result<Certificate, CoreError> {
        let cert = Grant::new(user, capability, self.certs.next_seq(&user), None, nonce)
            .sign(&self.signer)?;
        self.certs.insert(cert.clone())?;
        Ok(cert)
    }

    /// Mint a signed proposal, and record it locally.
    ///
    /// The returned certificate must be broadcast, or no peer can approve
    /// something it has never seen.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn certify_proposal(
        &mut self,
        action: AdminAction,
        seq: u64,
        expires: Option<u64>,
        nonce: [u8; 16],
    ) -> Result<Certificate, CoreError> {
        let cert = AdminProposal::new(action, seq, expires, nonce).sign(&self.signer)?;
        self.certs.insert(cert.clone())?;
        Ok(cert)
    }

    /// Mint a signed approval of `proposal`, and record it locally.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn certify_approval(
        &mut self,
        proposal: [u8; 32],
        nonce: [u8; 16],
    ) -> Result<Certificate, CoreError> {
        let cert = Approval::new(proposal, nonce).sign(&self.signer)?;
        self.certs.insert(cert.clone())?;
        Ok(cert)
    }

    /// Mint the workspace's threshold policy, and record it locally.
    ///
    /// Only meaningful from the founding device: [`CapabilityStore`] honours a
    /// policy signed by the founder and ignores everyone else's, which is what
    /// makes the threshold a constant rather than something a member can move.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn certify_policy(
        &mut self,
        threshold: u32,
        nonce: [u8; 16],
    ) -> Result<Certificate, CoreError> {
        let cert = Policy::new(threshold, nonce).sign(&self.signer)?;
        self.certs.insert(cert.clone())?;
        Ok(cert)
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
    pub fn merge(&mut self, authorized: AuthorizedOp) -> Result<MergeOutcome, CoreError> {
        // Cheapest meaningful check, and the only context-free one: do it
        // before the operation is allowed to occupy a slot in `parked`, so
        // unverifiable traffic cannot accumulate.
        authorized
            .op
            .try_verify()
            .map_err(|_| CoreError::BadSignature)?;
        // Absorb the proof before judging the operation, and before parking it:
        // the certificates are what make the verdict decidable now rather than
        // later, and they are individually signed so absorbing them commits to
        // nothing about the operation carrying them.
        self.certs.extend(authorized.proof.iter().cloned());
        self.merge_verified(authorized)
    }

    /// Merge an operation whose signature has already been checked.
    ///
    /// Parked operations were verified on the way in, so re-verifying them on
    /// every drain would repeat an Ed25519 check per operation per round.
    fn merge_verified(&mut self, authorized: AuthorizedOp) -> Result<MergeOutcome, CoreError> {
        let op = Arc::clone(&authorized.op);
        let preds: HashSet<_> = op.payload.predecessors().into_iter().collect();
        if !self.cgka.contains_predecessors(&preds) {
            self.park(authorized);
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

        // Third check, and the one phase 5 exists for: is this issuer permitted
        // to make *this* change? Strictly after `known_members`, so that the
        // error a caller sees distinguishes "not of this group" from "not
        // allowed to do that" — see `CoreError::Uncertified`.
        self.authorize(&op, issuer)?;

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

    /// Decide whether `issuer` holds a capability admitting this operation.
    ///
    /// A pure function of the operation and the certificate closure, which is
    /// what makes it safe to apply at merge time: two peers holding the same
    /// certificates reach the same verdict whatever order anything arrived in.
    /// Nothing here reads `current_members`, and that omission is deliberate —
    /// a non-monotone input would make one peer drop an operation another keeps,
    /// and the group would diverge permanently. The cost of that choice is the
    /// revenant case, which `WorkspaceState` handles by eviction rather than by
    /// rejection.
    fn authorize(&self, op: &Signed<CgkaOperation>, issuer: MemberId) -> Result<(), CoreError> {
        let issuer = issuer.to_bytes();
        let refuse = || CoreError::Uncertified { issuer };
        match op.payload {
            CgkaOperation::Add { added_id, .. } => {
                // The added leaf must itself be certified, and the binding must
                // name *this* operation's `added_id`. Without that second
                // condition an insider could lift a legitimate bundle off the
                // wire and reattach it to an `Add` of its own keypair.
                let added = added_id.to_bytes();
                let Some(added_user) = self.certs.user_of(&added) else {
                    return Err(refuse());
                };
                // Either the issuer may administer, or it is enrolling a further
                // device of its own user — which is not an administrative act.
                if self.certs.may_bind_device_to(&issuer, &added_user) {
                    Ok(())
                } else {
                    Err(refuse())
                }
            }
            CgkaOperation::Remove { id, .. } => {
                // Anyone may remove their own devices, which is what
                // `Workspace::leave` is built on, and no quorum governs it: a
                // member walking away needs nobody's permission.
                let target = id.to_bytes();
                let same_user = self
                    .certs
                    .user_of(&target)
                    .is_some_and(|owner| self.certs.user_of(&issuer) == Some(owner));
                if same_user {
                    return Ok(());
                }
                if !self.certs.may_administer(&issuer) {
                    return Err(refuse());
                }
                // Removing somebody *else* is what a threshold governs, and the
                // check happens here — on the receiver — rather than only on the
                // node that issued it. `WorkspaceState::require_quorum` is a
                // local courtesy that a malicious admin simply would not run;
                // this is what makes the threshold binding on the group.
                //
                // Sound because both inputs are monotone. The threshold is fixed
                // by the founder's policy, which every member holds before it can
                // join, and `is_executed_action` counts approvers with
                // `ever_admin`. A peer that knows more therefore accepts at least
                // as much — never less — so no two peers can merge different sets
                // of operations and split the group.
                if self.certs.threshold() <= DEFAULT_THRESHOLD
                    || self
                        .certs
                        .is_executed_action(&AdminAction::RemoveMember { member: target })
                {
                    Ok(())
                } else {
                    Err(refuse())
                }
            }
            // An `Update` re-keys only the issuer's own path, so membership is
            // the whole of the authority it needs and `known_members` already
            // established that. Requiring a certificate here would strand a
            // member whose binding had not yet reached this peer, and would gain
            // nothing: an update cannot introduce or remove anybody.
            CgkaOperation::Update { .. } => Ok(()),
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
                    // `Uncertified` joins `Unauthorized` here for the same
                    // reason — an operation its issuer was never permitted to
                    // make does not become permitted by waiting, and the honest
                    // operations queued behind it must still be drained.
                    Err(CoreError::Unauthorized { .. } | CoreError::Uncertified { .. }) => {}
                    Err(err) => first_error = first_error.or(Some(err)),
                }
            }
            if total == before {
                return first_error.map_or(Ok(total), Err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use beekem::id::{MemberId, TreeId};
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{AuthorizedOp, CgkaController, MergeOutcome};
    use crate::{
        capability::{AdminAction, Certificate, Role},
        error::CoreError,
    };

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    /// A founder and one other admin, in a workspace whose threshold is two.
    ///
    /// Built at this layer rather than through `WorkspaceState` because these
    /// tests are about `authorize`, which is the *receiver's* check — and the
    /// point is to issue operations the local guards would have refused, which a
    /// controller can do and a `WorkspaceState` deliberately cannot.
    struct Pair {
        founder: CgkaController,
        peer: CgkaController,
        victim: MemberId,
    }

    fn two_of_two() -> Pair {
        let signer = MemorySigner::generate(&mut rng(1));
        let tree = TreeId::from(signer.verifying_key());
        let founder_id = MemberId::from(signer.verifying_key());
        let peer_signer = MemorySigner::generate(&mut rng(2));
        let peer_id = MemberId::from(peer_signer.verifying_key());
        let victim_signer = MemorySigner::generate(&mut rng(3));
        let victim = MemberId::from(victim_signer.verifying_key());

        let mut founder =
            CgkaController::create(tree, signer, &mut rng(10)).expect("the tree is founded");
        founder
            .certify_device(founder_id.to_bytes(), founder_id.to_bytes(), [0u8; 16])
            .expect("the founder binds itself");
        founder
            .certify_role(founder_id.to_bytes(), Role::Admin, [0u8; 16])
            .expect("the founder is an admin");
        founder
            .certify_policy(2, [0u8; 16])
            .expect("the founder fixes the threshold");

        let peer_secret = ShareSecretKey::generate(&mut rng(20));
        founder
            .certify_device(peer_id.to_bytes(), peer_id.to_bytes(), [1u8; 16])
            .expect("the founder binds the peer");
        founder
            .certify_role(peer_id.to_bytes(), Role::Admin, [1u8; 16])
            .expect("the founder appoints a second admin");
        founder
            .add_member(peer_id, peer_secret.share_key())
            .expect("the peer is added");

        let victim_secret = ShareSecretKey::generate(&mut rng(30));
        founder
            .certify_device(victim.to_bytes(), victim.to_bytes(), [2u8; 16])
            .expect("the founder binds the victim");
        founder
            .certify_role(victim.to_bytes(), Role::Editor, [2u8; 16])
            .expect("the victim is an editor");
        founder
            .add_member(victim, victim_secret.share_key())
            .expect("the victim is added");

        let log = founder.op_log().expect("the log sorts");
        let certs = founder.capabilities().certificates();
        let peer = CgkaController::join(tree, peer_signer, peer_secret, &log, &certs)
            .expect("the peer joins");

        Pair {
            founder,
            peer,
            victim,
        }
    }

    /// Given a workspace whose threshold is two, when an admin issues a removal
    /// that no quorum authorised, we expect the *receiver* to refuse to merge it.
    ///
    /// **The property M-of-N is worth having for.** `WorkspaceState::require_quorum`
    /// runs on the node taking the action, and an attacker running modified code
    /// simply would not call it: the operation below is well-formed, correctly
    /// signed, and issued by a genuine administrator. Nothing but a check on the
    /// receiving side distinguishes it from a legitimate removal, so without this
    /// a threshold would constrain only the nodes that chose to honour it.
    #[test]
    fn a_removal_no_quorum_authorised_is_refused_by_the_receiver() {
        let mut pair = two_of_two();
        let op = pair
            .founder
            .remove_member(pair.victim)
            .expect("the tree accepts the removal")
            .expect("the victim is a member, so an operation is minted");

        let before = pair.peer.group_size();
        let err = pair
            .peer
            .merge(AuthorizedOp::bare(std::sync::Arc::new(op)))
            .expect_err("an unauthorised removal must be refused");
        assert!(
            matches!(err, CoreError::Uncertified { .. }),
            "the refusal must name a missing capability rather than a bad \
             signature: the operation is genuine, it is the authority that is \
             absent — {err}"
        );
        assert_eq!(
            pair.peer.group_size(),
            before,
            "the receiver merged a removal that no quorum authorised, so the \
             threshold constrains only nodes that choose to honour it"
        );
    }

    /// Given a workspace whose threshold is two, when two distinct admins have
    /// approved a removal, we expect the receiver to merge it.
    ///
    /// The counterweight: a receiver that refused every removal would satisfy the
    /// property above while making the workspace unusable.
    #[test]
    fn a_removal_two_admins_approved_is_merged_by_the_receiver() {
        let mut pair = two_of_two();
        let action = AdminAction::RemoveMember {
            member: pair.victim.to_bytes(),
        };

        let proposal = pair
            .founder
            .certify_proposal(action, 0, None, [9u8; 16])
            .expect("the founder proposes");
        let digest = proposal.digest();
        let first = pair
            .founder
            .certify_approval(digest, [10u8; 16])
            .expect("the founder approves");

        // The second approval is minted by the peer's own key, which is what
        // makes it a *distinct user* rather than a second device.
        let second = pair
            .peer
            .certify_approval(digest, [11u8; 16])
            .expect("the peer approves");
        pair.founder
            .absorb_certificates(vec![second, proposal, first]);
        assert!(
            pair.founder.capabilities().is_executed_action(&action),
            "two distinct admins approved and the action was still not authorised"
        );

        let op = pair
            .founder
            .remove_member(pair.victim)
            .expect("the tree accepts the removal")
            .expect("an operation is minted");
        let proof: Vec<Certificate> = pair.founder.capabilities().proof_of(&action);
        assert!(
            !proof.is_empty(),
            "a quorum-authorised action must be able to prove itself to a peer \
             that has not seen the approvals"
        );

        let before = pair.peer.group_size();
        let outcome = pair
            .peer
            .merge(AuthorizedOp::new(op, proof))
            .expect("a quorum-authorised removal must be accepted");
        assert!(
            matches!(outcome, MergeOutcome::Applied),
            "the removal was not applied: {outcome:?}"
        );
        assert_eq!(
            pair.peer.group_size(),
            before - 1,
            "the receiver accepted the removal but the leaf is still in the tree"
        );
    }

    /// Given a workspace whose threshold is two, when a member removes its own
    /// device, we expect the receiver to merge it without any quorum.
    ///
    /// A threshold governs what the group does *to* a member, never what a member
    /// does about itself — otherwise a group could hold somebody in a workspace
    /// against their will.
    #[test]
    fn a_self_removal_needs_no_quorum() {
        let mut pair = two_of_two();
        let me = pair.peer.member_id();
        let op = pair
            .peer
            .remove_member(me)
            .expect("the tree accepts the removal")
            .expect("an operation is minted");

        let before = pair.founder.group_size();
        pair.founder
            .merge(AuthorizedOp::bare(std::sync::Arc::new(op)))
            .expect("a member's own departure needs nobody's approval");
        assert_eq!(
            pair.founder.group_size(),
            before - 1,
            "a receiver refused a member's own departure for want of a quorum"
        );
    }
}
