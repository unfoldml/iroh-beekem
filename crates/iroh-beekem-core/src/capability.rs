//! Offline-verifiable authorization: who is allowed to act, and on whose word.
//!
//! # The problem this replaces
//!
//! Every role check in the workspace used to read the manifest, and the manifest
//! is a CRDT that merges whatever any member writes. So a member holding the
//! lowest role could write `roles[me] = Admin`, or bind a device of theirs to an
//! admin's user, and every replica would faithfully converge on it. The checks
//! constrained well-behaved peers and nothing else.
//!
//! The tempting fix — have the receiver consult the manifest for the issuer's
//! role — is worse than no fix. The manifest is replicated and converges at
//! different times on different peers, so two peers evaluating the same operation
//! against different manifest views reach different verdicts, one drops an
//! operation the other keeps, and the group diverges *permanently*. Any
//! authorization predicate over mutable replicated state has that shape.
//!
//! Authorization must therefore be **carried by the thing being authorised and
//! verifiable offline**, against a root nobody can argue about.
//!
//! # The root
//!
//! `tree_id` is the founder's Ed25519 verifying key, and the founding `Add` is
//! self-issued and checked in
//! [`CgkaController::join`](crate::keys::CgkaController::join) before any other
//! operation is replayed. So the founder's public key is already an identity
//! every peer holds, agrees on, and cannot be talked out of. A certificate set
//! rooted there needs no new distribution channel, no new secret, and no new
//! convergence argument.
//!
//! # Two predicates, not one
//!
//! [`CapabilityStore`] answers two different questions, and collapsing them has
//! no safe direction — the same conclusion, for the same reason, that
//! `known_members` and `current_members` already reached in [`crate::keys`].
//!
//! * [`CapabilityStore::ever_admin`] is **monotone**: once a user has held an
//!   admin grant, it stays true. This is what decides whether a *certificate* is
//!   admitted, and it must be monotone so that the closure is a pure,
//!   terminating, order-independent function of the certificate set. Two peers
//!   holding the same certificates then always agree, however those certificates
//!   arrived — which is the entire point.
//! * [`CapabilityStore::role_of`] is **non-monotone**: a later grant supersedes
//!   an earlier one, so a user can be demoted. This is what enforces *actions*.
//!   Order-sensitivity is affordable here for the same reason it is on
//!   `current_members`: the cost of two peers disagreeing is a refused action
//!   that the next exchange repairs, not a dropped operation that diverges the
//!   group forever.
//!
//! The consequence is worth stating plainly, because it is not obvious and it is
//! load-bearing: **demotion is a courtesy against a well-behaved peer; removal is
//! the enforcement.** A demoted admin is still `ever_admin`, so certificates it
//! issues are still admitted, and it can issue itself a higher-`seq` grant. What
//! actually strips a malicious admin of authority is CGKA-removing every device
//! of that user, which is already a first-class operation and already converges.
//! This mirrors monotone `known_members` exactly.
//!
//! # What is deliberately not here
//!
//! * **No clock.** [`Grant::not_after`] is carried so the wire format need not
//!   change later, but it is **not evaluated** by anything in this module.
//!   Evaluating an expiry inside an authorization predicate would make
//!   admissibility depend on clock skew, and two peers disagreeing about whether
//!   a grant had expired would drop different operations — reintroducing exactly
//!   the divergence this design exists to avoid. Expiry belongs where a *local*
//!   decision is being made and disagreement is cheap: invite acceptance, in
//!   `iroh-beekem`, which has a clock.
//! * **No retraction.** Certificates are never withdrawn. Revocation is a CGKA
//!   removal.

use std::collections::{BTreeMap, BTreeSet};

use keyhive_crypto::{signed::Signed, signer::memory::MemorySigner};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// What a member is authorised to do.
///
/// Lives here rather than beside the manifest because this is the module that
/// *decides* it. While roles were recorded in the manifest the type sat there
/// too, which read as though a role were a piece of document metadata; it is a
/// capability, and the only thing that can establish one is a signed [`Grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// May change roles and add or remove members.
    Admin,
    /// May read and write documents.
    Editor,
    /// May read documents only.
    Viewer,
}

impl Role {
    /// Whether this role may write document content.
    #[must_use]
    pub fn can_write(self) -> bool {
        matches!(self, Self::Admin | Self::Editor)
    }

    /// Whether this role may change roles or membership.
    #[must_use]
    pub fn can_administer(self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// Domain separation for a [`Grant`] signature.
///
/// See [`BINDING_DOMAIN`] for why these exist and what they are worth.
pub const GRANT_DOMAIN: [u8; 16] = *b"iroh-beekem/grnt";

/// Domain separation for a [`DeviceBinding`] signature.
///
/// # What a tag buys
///
/// [`Signed`] covers `bincode(payload)` with no type name and no discriminator,
/// and `try_verify` recomputes it for whatever `T` the *deserializer* chose — and
/// on the wire a [`Certificate`] is an enum, so a receiver's choice of `T` is the
/// attacker's choice. A genuine `(issuer, signature)` pair is therefore
/// transferable between any two payload types whose encodings match byte for
/// byte. The attacker forges nothing; they lift the pair and reattach it.
///
/// That is not hypothetical here. Untagged, a `DeviceBinding` encoded to exactly
/// 80 bytes and *every* 80-byte string decoded as one, while
/// `CgkaOperation::Remove` encoded to 88 — eight bytes apart, signed by the same
/// member key, and an admin's `Remove` lifted into a
/// `DeviceBinding { device: attacker, user: admin }` is an escalation the closure
/// admits without further question. What held those eight bytes apart was
/// `CgkaOperation`'s field list, which belongs to beekem and is a *version*
/// dependency here rather than a pinned revision. A release that shrank `Remove`
/// would have been a silent break.
///
/// # Why an ASCII tag closes it structurally, not probabilistically
///
/// Every domain constant in this workspace is 16 bytes of printable ASCII, and
/// that is load-bearing. bincode encodes an enum discriminant as a little-endian
/// `u32`, so for any variant index below 2^24 the second, third and fourth bytes
/// of the encoding are **zero**. A tagged payload's are not. A tagged payload can
/// therefore never share an encoding with an untagged bincode enum — which is
/// exactly what `CgkaOperation` is — regardless of what beekem does to its
/// fields later. The two tags differ from each other, and from
/// `iroh-beekem`'s invite tag, so no pair of tagged types can collide either.
///
/// `the_signed_payload_types_cannot_share_an_encoding` in this module's tests is
/// what keeps all of that true.
///
/// Public so that `iroh-beekem` can assert its own invite tag differs from both
/// of these. A constant an attacker already knows; publishing it costs nothing
/// and the alternative is a cross-crate test that cannot see what it is checking.
pub const BINDING_DOMAIN: [u8; 16] = *b"iroh-beekem/bind";

/// An admin's statement that a user holds a role.
///
/// Roles attach to *users*, not devices — a laptop that is an admin while its
/// owner's phone is a viewer is a distinction nobody wants to reason about. A
/// device's role is its owner's; see [`CapabilityStore::role_of_member`].
///
/// Build one with [`Grant::new`]: the domain tag is not a field a caller fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Domain separation, always [`GRANT_DOMAIN`]. First field, so it is the
    /// first bytes of the signed encoding.
    domain: [u8; 16],
    /// The user this grant is about.
    pub subject: [u8; 32],
    /// What that user may do.
    pub capability: Role,
    /// Which generation of this subject's role this is.
    ///
    /// Ordered first when choosing between grants for one subject, with the
    /// certificate digest breaking ties — the same total order
    /// [`NamespaceEpoch`](crate::state::NamespaceEpoch) uses to settle two
    /// concurrent rotations, and for the same reason. A bare "latest wins" has
    /// no meaning in a set with no order, and letting the highest *capability*
    /// win would make demotion impossible.
    pub seq: u64,
    /// When this grant stops being honoured, in absolute milliseconds.
    ///
    /// **Carried, not enforced.** Nothing in this crate reads it; see the module
    /// documentation for why an expiry inside an authorization predicate would
    /// diverge the group.
    pub not_after: Option<u64>,
    /// Distinguishes two otherwise identical grants, so each has its own digest.
    pub nonce: [u8; 16],
}

/// Domain tag for [`AdminProposal`]. Sixteen bytes of printable ASCII.
///
/// Small fixed-size payloads are exactly the ones that collide, and a
/// `RemoveMember` proposal encodes to very nearly the length of a [`Grant`] — so
/// this tag is not hygiene here, it is the whole of what keeps an admin's
/// routine grant from being lifted onto a proposal to remove somebody.
pub const PROPOSAL_DOMAIN: [u8; 16] = *b"iroh-beekem/prop";

/// Domain tag for [`Approval`]. Sixteen bytes of printable ASCII.
pub const APPROVAL_DOMAIN: [u8; 16] = *b"iroh-beekem/aprv";

/// Domain tag for [`Policy`]. Sixteen bytes of printable ASCII.
pub const POLICY_DOMAIN: [u8; 16] = *b"iroh-beekem/plcy";

/// The threshold a workspace has when its founder set none.
///
/// One, so that every workspace founded before quorum existed keeps behaving
/// exactly as it did: a single admin acting alone *is* a quorum of one, and
/// `require_quorum` degenerates to the `require_admin` it replaced.
pub const DEFAULT_THRESHOLD: u32 = 1;

/// The workspace's administrative threshold, fixed by its founder.
///
/// # Why this is immutable, and why it has to be
///
/// A quorum is only worth anything if **every receiver** refuses an action that
/// did not reach it. That check is *stricter the more a node knows*: a peer
/// holding the certificates that raised the bar rejects an operation that a peer
/// still catching up would accept. If the threshold could change, those two peers
/// would merge different sets of operations and the group would diverge
/// permanently — the one failure this whole design is built to avoid, and the
/// reason `known_members` is monotone and `roles` is not consulted on merge.
///
/// Fixing the threshold at founding removes the asymmetry entirely. The policy is
/// minted by [`WorkspaceState::found`](crate::state::WorkspaceState::found),
/// self-signed by the founder — valid for exactly the reason the founder's own
/// admin grant is, because `tree_id` **is** that key — and it travels in the
/// invite beside it. A member cannot be behind on it: it arrives with the
/// certificates without which they could not have joined at all.
///
/// The cost is stated plainly rather than worked around: **a workspace's
/// threshold cannot be changed after it is created.** Raising it later would be
/// the unsound operation above; lowering it would let one compromised admin undo
/// the protection the rest of the group is relying on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Domain separation, always [`POLICY_DOMAIN`].
    domain: [u8; 16],
    /// How many distinct admins an administrative action needs.
    ///
    /// Clamped to at least one on read: zero would not mean "no quorum needed"
    /// but "every proposal executes with no approvals at all".
    pub threshold: u32,
    /// Distinguishes two otherwise identical policies.
    pub nonce: [u8; 16],
}

/// An administrative action that a quorum of admins can authorise.
///
/// Deliberately a small, closed set: every variant must be expressible in a
/// certificate, because a proposal travels as one and a replica executes it from
/// the certificate alone. That rules out `AddUser` and `AddDevice`, whose
/// enrolment data — a leaf key, an endpoint — is not here and could not be
/// reconstructed. Those stay single-admin, and the asymmetry is defensible:
/// admitting somebody is reversible by removing them, whereas the actions below
/// are the ones that take access away or hand it out.
///
/// There is no `Rotate` variant either, although namespace rotation is an
/// administrative act. It is not independently proposable — `on_remove_member`
/// emits it as a *consequence* of a removal — so gating the removal already gates
/// the rotation, and a variant nobody could propose would be a wire format with
/// no caller.
///
/// And there is no `SetThreshold`: the threshold is fixed at founding by
/// [`Policy`], for the divergence reason recorded there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminAction {
    /// Retract one device's leaf.
    RemoveMember {
        /// The device to remove.
        member: [u8; 32],
    },
    /// Assign a role to a user.
    SetRole {
        /// The user whose role changes.
        user: [u8; 32],
        /// The role to assign.
        role: Role,
    },
}

/// A proposed administrative action, awaiting approvals.
///
/// Data, not an instruction: proposing costs nothing and grants nothing. What
/// makes it happen is [`Approval`]s from enough distinct admins, at which point
/// **every** replica performs the action independently. Nobody coordinates, and
/// nobody needs to: duplicate removals merge as `MergeOutcome::Duplicate`, which
/// is the same property the revenant eviction path already relies on.
///
/// Build one with [`AdminProposal::new`]: the domain tag is not a field a caller
/// fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminProposal {
    /// Domain separation, always [`PROPOSAL_DOMAIN`]. First field, so it is the
    /// first bytes of the signed encoding.
    domain: [u8; 16],
    /// What is being proposed.
    pub action: AdminAction,
    /// Which generation of proposal this is.
    ///
    /// Orders proposals against each other, with the digest breaking ties — the
    /// same `(seq, digest)` total order [`Grant`] uses, and needed for the same
    /// reason: a set has no order of its own, so two `SetRole` proposals naming
    /// one user would otherwise have no defined winner and two peers holding the
    /// same certificates could resolve that user's role differently.
    pub seq: u64,
    /// When this proposal stops being offered, in absolute milliseconds.
    ///
    /// **Carried, not enforced**, exactly as [`Grant::not_after`] is. The core
    /// has no clock, and an expiry inside the quorum predicate would make two
    /// peers with skewed clocks execute different sets of proposals. A caller
    /// with a clock may refuse to *approve* an expired proposal, which is a local
    /// decision by one device and diverges nobody.
    pub expires: Option<u64>,
    /// Distinguishes two otherwise identical proposals.
    pub nonce: [u8; 16],
}

/// One admin's approval of a proposal.
///
/// Names the proposal by digest rather than repeating its contents, which is
/// what makes an approval unambiguous: an approver signs over the exact bytes
/// that will be executed, so there is no way to approve one action and have
/// another performed.
///
/// Build one with [`Approval::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// Domain separation, always [`APPROVAL_DOMAIN`].
    domain: [u8; 16],
    /// The digest of the [`AdminProposal`] certificate being approved.
    pub proposal: [u8; 32],
    /// Distinguishes two otherwise identical approvals.
    pub nonce: [u8; 16],
}

/// A statement that a CGKA leaf belongs to a particular user.
///
/// This is the binding that makes a leaf attributable to a person, and therefore
/// to a role. It may be issued by an admin, or by an existing device of the same
/// user — enrolling your own phone is not an act of administration. It may never
/// be self-attested, because a device that could name its own user would inherit
/// that user's role.
///
/// Build one with [`DeviceBinding::new`]: the domain tag is not a field a caller
/// fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBinding {
    /// Domain separation, always [`BINDING_DOMAIN`]. First field, so it is the
    /// first bytes of the signed encoding.
    domain: [u8; 16],
    /// The device's CGKA member id — its leaf in the tree.
    pub device: [u8; 32],
    /// The user this device acts for.
    pub user: [u8; 32],
    /// Distinguishes two otherwise identical bindings.
    pub nonce: [u8; 16],
}

/// One signed authorization statement.
///
/// Both variants travel together — on the control plane beside the operation
/// they authorise, in an invite, and in a snapshot — so they share one type and
/// one store rather than two of each.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Certificate {
    /// A user's role.
    Grant(Signed<Grant>),
    /// A device's owner.
    Binding(Signed<DeviceBinding>),
    /// An administrative action awaiting approvals.
    Proposal(Signed<AdminProposal>),
    /// One admin's approval of a proposal.
    Approval(Signed<Approval>),
    /// The workspace's administrative threshold, fixed by its founder.
    Policy(Signed<Policy>),
}

impl Grant {
    /// A grant of `capability` to `subject`, stamped with its domain tag.
    ///
    /// The only way to build one, so a `Grant` that exists is a `Grant` that
    /// verification will recognise as one.
    #[must_use]
    pub fn new(
        subject: [u8; 32],
        capability: Role,
        seq: u64,
        not_after: Option<u64>,
        nonce: [u8; 16],
    ) -> Self {
        Self {
            domain: GRANT_DOMAIN,
            subject,
            capability,
            seq,
            not_after,
            nonce,
        }
    }

    /// Sign a grant with the issuing device's key.
    ///
    /// Synchronous: `MemorySigner::try_sign_sync` does no I/O, so unlike the
    /// CGKA operations in [`crate::keys`] this needs no `now_or_never` dance and
    /// cannot produce [`CoreError::SignerYielded`].
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn sign(self, signer: &MemorySigner) -> Result<Certificate, CoreError> {
        signer
            .try_sign_sync(self)
            .map(Certificate::Grant)
            .map_err(|e| CoreError::Signing(e.to_string()))
    }
}

impl DeviceBinding {
    /// A binding of `device` to `user`, stamped with its domain tag.
    ///
    /// The only way to build one, for the reason given on [`Grant::new`].
    #[must_use]
    pub fn new(device: [u8; 32], user: [u8; 32], nonce: [u8; 16]) -> Self {
        Self {
            domain: BINDING_DOMAIN,
            device,
            user,
            nonce,
        }
    }

    /// Sign a binding with the issuing device's key.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn sign(self, signer: &MemorySigner) -> Result<Certificate, CoreError> {
        signer
            .try_sign_sync(self)
            .map(Certificate::Binding)
            .map_err(|e| CoreError::Signing(e.to_string()))
    }
}

impl AdminProposal {
    /// A proposal to perform `action`, stamped with its domain tag.
    #[must_use]
    pub fn new(action: AdminAction, seq: u64, expires: Option<u64>, nonce: [u8; 16]) -> Self {
        Self {
            domain: PROPOSAL_DOMAIN,
            action,
            seq,
            expires,
            nonce,
        }
    }

    /// Sign a proposal with the proposing device's key.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn sign(self, signer: &MemorySigner) -> Result<Certificate, CoreError> {
        signer
            .try_sign_sync(self)
            .map(Certificate::Proposal)
            .map_err(|e| CoreError::Signing(e.to_string()))
    }
}

impl Approval {
    /// An approval of the proposal with this digest, stamped with its tag.
    #[must_use]
    pub fn new(proposal: [u8; 32], nonce: [u8; 16]) -> Self {
        Self {
            domain: APPROVAL_DOMAIN,
            proposal,
            nonce,
        }
    }

    /// Sign an approval with the approving device's key.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn sign(self, signer: &MemorySigner) -> Result<Certificate, CoreError> {
        signer
            .try_sign_sync(self)
            .map(Certificate::Approval)
            .map_err(|e| CoreError::Signing(e.to_string()))
    }
}

impl Policy {
    /// A policy fixing the workspace threshold, stamped with its domain tag.
    #[must_use]
    pub fn new(threshold: u32, nonce: [u8; 16]) -> Self {
        Self {
            domain: POLICY_DOMAIN,
            threshold,
            nonce,
        }
    }

    /// Sign a policy with the founding device's key.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn sign(self, signer: &MemorySigner) -> Result<Certificate, CoreError> {
        signer
            .try_sign_sync(self)
            .map(Certificate::Policy)
            .map_err(|e| CoreError::Signing(e.to_string()))
    }
}

impl Certificate {
    /// The device that issued this certificate, as raw verifying-key bytes.
    ///
    /// Raw bytes rather than a `MemberId` because a `MemberId` wraps an expanded
    /// Ed25519 point: rebuilding one costs a point decompression, and this is
    /// read once per certificate per recompute.
    #[must_use]
    pub fn issuer(&self) -> [u8; 32] {
        match self {
            Self::Grant(signed) => signed.issuer().to_bytes(),
            Self::Binding(signed) => signed.issuer().to_bytes(),
            Self::Proposal(signed) => signed.issuer().to_bytes(),
            Self::Approval(signed) => signed.issuer().to_bytes(),
            Self::Policy(signed) => signed.issuer().to_bytes(),
        }
    }

    /// This certificate's digest, which identifies it in the store.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        match self {
            Self::Grant(signed) => signed.digest().into(),
            Self::Binding(signed) => signed.digest().into(),
            Self::Proposal(signed) => signed.digest().into(),
            Self::Approval(signed) => signed.digest().into(),
            Self::Policy(signed) => signed.digest().into(),
        }
    }

    /// Check the domain tag, then the signature against the embedded issuer key.
    ///
    /// The tag first, and the order matters for what a failure *means*: a
    /// payload signed for another purpose has a perfectly good signature, and
    /// reporting it as [`CoreError::BadSignature`] would describe a
    /// cross-protocol lift as a corrupt message.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::WrongDomain`] if the payload is not a certificate of
    /// this kind, and [`CoreError::BadSignature`] if it is forged or was tampered
    /// with in transit.
    pub fn verify(&self) -> Result<(), CoreError> {
        let domain_ok = match self {
            Self::Grant(signed) => signed.payload().domain == GRANT_DOMAIN,
            Self::Binding(signed) => signed.payload().domain == BINDING_DOMAIN,
            Self::Proposal(signed) => signed.payload().domain == PROPOSAL_DOMAIN,
            Self::Approval(signed) => signed.payload().domain == APPROVAL_DOMAIN,
            Self::Policy(signed) => signed.payload().domain == POLICY_DOMAIN,
        };
        if domain_ok {
            let verified = match self {
                Self::Grant(signed) => signed.try_verify(),
                Self::Binding(signed) => signed.try_verify(),
                Self::Proposal(signed) => signed.try_verify(),
                Self::Approval(signed) => signed.try_verify(),
                Self::Policy(signed) => signed.try_verify(),
            };
            verified.map_err(|_| CoreError::BadSignature)
        } else {
            Err(CoreError::WrongDomain)
        }
    }
}

/// One proposal as an application sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalStatus {
    /// Identifies the proposal; what [`Approval`] names and what a caller
    /// passes to approve it.
    pub digest: [u8; 32],
    /// What would happen if it reached quorum.
    pub action: AdminAction,
    /// How many distinct admin users have approved so far.
    pub approvals: usize,
    /// How many distinct admins are needed. Constant for the workspace.
    pub required: u32,
    /// Whether it has reached quorum and is being performed.
    pub executable: bool,
}

/// Every authorization statement this node has accepted, plus what they imply.
///
/// Grow-only. `insert` is idempotent on the certificate digest, and the derived
/// closure is recomputed from scratch rather than patched — a patched closure
/// would depend on insertion order, which is the one thing this type must not do.
#[derive(Debug, Clone)]
pub struct CapabilityStore {
    /// The founder's device id, which is also the founder's user id.
    ///
    /// The axiom. `tree_id` *is* this key, so a certificate chain terminating
    /// here terminates at something every peer already agreed on by joining.
    founder: [u8; 32],
    /// Accepted grants, keyed by digest.
    ///
    /// `BTreeMap` rather than `HashMap` throughout: the closure iterates these,
    /// and iterating in digest order rather than hash order is what makes the
    /// result a deterministic function of the set on every peer and every run.
    grants: BTreeMap<[u8; 32], Signed<Grant>>,
    /// Accepted bindings, keyed by digest.
    bindings: BTreeMap<[u8; 32], Signed<DeviceBinding>>,
    /// Derived: which user each certified device acts for.
    device_user: BTreeMap<[u8; 32], [u8; 32]>,
    /// Derived: every user that has *ever* held an admin grant. Monotone.
    ever_admin: BTreeSet<[u8; 32]>,
    /// Derived: each user's current role, by `(seq, digest)`. Non-monotone.
    roles: BTreeMap<[u8; 32], Role>,
    /// Accepted proposals, keyed by digest.
    proposals: BTreeMap<[u8; 32], Signed<AdminProposal>>,
    /// Accepted approvals, keyed by digest.
    approvals: BTreeMap<[u8; 32], Signed<Approval>>,
    /// Accepted policies, keyed by digest. Only the founder's is honoured.
    policies: BTreeMap<[u8; 32], Signed<Policy>>,
    /// Derived: the threshold, from the founder's policy. Constant per workspace.
    threshold: u32,
    /// Derived: proposals that have reached quorum, by proposal digest.
    ///
    /// **Monotone.** Approvers are counted with `ever_admin`, not `role_of`, so
    /// gaining certificates can only add to this set — which is what makes the
    /// receiver-side check in `CgkaController::authorize` safe: a peer that
    /// knows more accepts more, never less.
    executed: BTreeSet<[u8; 32]>,
}

impl CapabilityStore {
    /// An empty store rooted at `founder`.
    ///
    /// The founder needs no certificate to be an admin — that is what makes this
    /// a root rather than an infinite regress — so a fresh store already answers
    /// `role_of(founder) == Some(Admin)`. A founder that also mints an explicit
    /// self-signed grant supersedes this seed, because the seed is recorded at
    /// the smallest possible `(seq, digest)`.
    #[must_use]
    pub fn new(founder: [u8; 32]) -> Self {
        let mut this = Self {
            founder,
            grants: BTreeMap::new(),
            bindings: BTreeMap::new(),
            device_user: BTreeMap::new(),
            ever_admin: BTreeSet::new(),
            roles: BTreeMap::new(),
            proposals: BTreeMap::new(),
            approvals: BTreeMap::new(),
            policies: BTreeMap::new(),
            threshold: DEFAULT_THRESHOLD,
            executed: BTreeSet::new(),
        };
        this.recompute();
        this
    }

    /// The founder's id, which is the root of every valid chain.
    #[must_use]
    pub fn founder(&self) -> [u8; 32] {
        self.founder
    }

    /// Accept one certificate, if its signature checks out and it is new.
    ///
    /// Returns whether the store changed. An already-known certificate is not an
    /// error: certificates ride along with the operations they authorise and are
    /// re-shipped with every log exchange, so re-receiving one is the ordinary
    /// case rather than a fault.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BadSignature`] if the certificate does not verify.
    pub fn insert(&mut self, cert: Certificate) -> Result<bool, CoreError> {
        let changed = self.stage(cert)?;
        if changed {
            self.recompute();
        }
        Ok(changed)
    }

    /// Accept many certificates, recomputing the closure once.
    ///
    /// Returns how many were new. Invalid certificates are **dropped rather than
    /// reported**: a bundle arrives from the network beside an operation, and one
    /// bad entry must not cost the operation or the certificates queued behind
    /// it. Each certificate is independently signed, so dropping one loses
    /// nothing but itself.
    pub fn extend<I: IntoIterator<Item = Certificate>>(&mut self, certs: I) -> usize {
        let mut added = 0_usize;
        for cert in certs {
            if let Ok(true) = self.stage(cert) {
                added += 1;
            } else {
                // Already known, or unverifiable. Neither is worth failing for;
                // see the method documentation.
            }
        }
        if added > 0 {
            self.recompute();
        } else {
            // Nothing new, so the closure cannot have changed.
        }
        added
    }

    /// Verify and store one certificate without recomputing the closure.
    fn stage(&mut self, cert: Certificate) -> Result<bool, CoreError> {
        cert.verify()?;
        let digest = cert.digest();
        Ok(match cert {
            Certificate::Grant(signed) => self.grants.insert(digest, signed).is_none(),
            Certificate::Binding(signed) => self.bindings.insert(digest, signed).is_none(),
            Certificate::Proposal(signed) => self.proposals.insert(digest, signed).is_none(),
            Certificate::Approval(signed) => self.approvals.insert(digest, signed).is_none(),
            Certificate::Policy(signed) => self.policies.insert(digest, signed).is_none(),
        })
    }

    /// Every certificate this store holds, for a log exchange or a snapshot.
    ///
    /// Deterministically ordered, so two peers with the same store ship the same
    /// bytes and a test can compare them.
    #[must_use]
    pub fn certificates(&self) -> Vec<Certificate> {
        self.bindings
            .values()
            .cloned()
            .map(Certificate::Binding)
            .chain(self.grants.values().cloned().map(Certificate::Grant))
            .chain(self.proposals.values().cloned().map(Certificate::Proposal))
            .chain(self.approvals.values().cloned().map(Certificate::Approval))
            .chain(self.policies.values().cloned().map(Certificate::Policy))
            .collect()
    }

    /// How many certificates are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
            + self.bindings.len()
            + self.proposals.len()
            + self.approvals.len()
            + self.policies.len()
    }

    /// Whether the store holds no certificates beyond the founder axiom.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Recompute everything derived, from the certificate set alone.
    ///
    /// Two nested fixpoints in one loop, because they feed each other: admitting
    /// a binding can reveal the device of a user who turns out to be an admin,
    /// and admitting an admin grant can in turn admit further bindings.
    ///
    /// Termination rests on both derived sets being **monotone within this
    /// function**: `device_user` and `ever_admin` only ever gain entries, and both
    /// are bounded by the certificate set, so the loop runs at most `len()`
    /// rounds. This is why admission consults `ever_admin` and not `roles` — a
    /// non-monotone input could retract an admission made in an earlier round and
    /// the fixpoint would not be well defined, never mind order-independent.
    fn recompute(&mut self) {
        // The threshold first: it is a constant of the workspace, read straight
        // off the founder's policy, so nothing below can move it.
        let threshold = self.resolve_threshold();

        // The axiom: the founder is their own user, and is an admin. Seeded
        // before any certificate is considered, since every chain terminates
        // here and nothing can authorise it.
        let mut device_user = BTreeMap::from([(self.founder, self.founder)]);
        let mut ever_admin = BTreeSet::from([self.founder]);
        let mut executed: BTreeSet<[u8; 32]> = BTreeSet::new();

        loop {
            let mut changed = false;

            for (digest, signed) in &self.bindings {
                let binding = signed.payload();
                // A device's first admitted binding is final. Rebinding a
                // certified device would let whoever wins an iteration race
                // decide who a leaf belongs to — and since iteration is in
                // digest order, that race would be winnable by grinding a
                // nonce. Only an admin can get a second binding admitted at
                // all, and an admin able to rebind a peer's device could
                // equally have removed them.
                if device_user.contains_key(&binding.device) {
                    continue;
                }
                let Some(issuer_user) = device_user.get(&signed.issuer().to_bytes()).copied()
                else {
                    // The issuer is not (yet) a certified device, so it speaks
                    // for nobody. It may become one in a later round.
                    continue;
                };
                // Either the issuer is enrolling a further device of its own
                // user, or it is an admin enrolling anybody.
                if issuer_user == binding.user || ever_admin.contains(&issuer_user) {
                    device_user.insert(binding.device, binding.user);
                    changed = true;
                } else {
                    // Not authorised to make this binding. Deliberately not
                    // remembered as rejected: a later round may make the issuer
                    // an admin, and the certificate is then admissible.
                    let _ = digest;
                }
            }

            // Proposals that have collected enough approvals. Inside the loop
            // because it feeds `ever_admin` and is fed by it: an approval only
            // counts once its issuer's device is bound and their user is known
            // to have been an admin, and a quorum can in turn admit a grant that
            // makes somebody else one. Both sets only grow, so the loop still
            // terminates in at most `len()` rounds.
            for (digest, signed) in &self.proposals {
                if executed.contains(digest) {
                    continue;
                }
                // The proposer must be an admin. Without this, any member could
                // fill the group's proposal list, and a quorum of admins who
                // approved carelessly would execute an action nobody with
                // authority ever put forward.
                let Some(issuer_user) = device_user.get(&signed.issuer().to_bytes()).copied()
                else {
                    continue;
                };
                if !ever_admin.contains(&issuer_user) {
                    continue;
                }
                let approvers =
                    Self::approving_users(&self.approvals, &device_user, &ever_admin, digest);
                if approvers.len() >= threshold as usize {
                    executed.insert(*digest);
                    changed = true;
                } else {
                    // Not enough distinct admins yet. May become enough in a
                    // later round, or when more certificates arrive.
                }
            }

            for signed in self.grants.values() {
                let grant = signed.payload();
                if !grant.capability.can_administer() {
                    // Only admin grants feed the monotone set; the rest are
                    // resolved into `roles` after the fixpoint settles.
                    continue;
                }
                let Some(issuer_user) = device_user.get(&signed.issuer().to_bytes()).copied()
                else {
                    continue;
                };
                if !ever_admin.contains(&issuer_user) {
                    continue;
                }
                if !Self::grant_is_authorised(
                    threshold,
                    issuer_user,
                    self.founder,
                    grant,
                    &executed,
                    &self.proposals,
                ) {
                    continue;
                }
                if ever_admin.insert(grant.subject) {
                    changed = true;
                } else {
                    // The subject was already known to have been an admin.
                }
            }

            if !changed {
                break;
            }
        }

        let roles = Self::resolve_roles(
            threshold,
            self.founder,
            &self.grants,
            &self.proposals,
            &device_user,
            &ever_admin,
            &executed,
        );

        self.threshold = threshold;
        self.executed = executed;
        self.device_user = device_user;
        self.ever_admin = ever_admin;
        self.roles = roles;
    }

    /// Resolve each user's current role, once the closure has settled.
    ///
    /// Split from [`Self::recompute`] because it is a different question asked of
    /// the same fixpoint: that loop decides what is *admissible*, monotonically;
    /// this decides what is *current*, by `(seq, digest)`, and is allowed to be
    /// order-sensitive because the cost of disagreeing is a refused action rather
    /// than a dropped operation.
    #[allow(
        clippy::too_many_arguments,
        reason = "every argument is a piece of the fixpoint this reads; bundling \
                  them into a struct would add a type whose only purpose is to be \
                  destructured on the next line"
    )]
    fn resolve_roles(
        threshold: u32,
        founder: [u8; 32],
        grants: &BTreeMap<[u8; 32], Signed<Grant>>,
        proposals: &BTreeMap<[u8; 32], Signed<AdminProposal>>,
        device_user: &BTreeMap<[u8; 32], [u8; 32]>,
        ever_admin: &BTreeSet<[u8; 32]>,
        executed: &BTreeSet<[u8; 32]>,
    ) -> BTreeMap<[u8; 32], Role> {
        // The founder's seed is recorded at the smallest possible
        // `(seq, digest)` — the all-zero digest trick `NamespaceEpoch::INITIAL`
        // already uses — so any real grant naming the founder supersedes it
        // rather than tying with it.
        let mut best: BTreeMap<[u8; 32], (u64, [u8; 32])> =
            BTreeMap::from([(founder, (0, [0u8; 32]))]);
        let mut roles = BTreeMap::from([(founder, Role::Admin)]);

        for (digest, signed) in grants {
            let grant = signed.payload();
            let Some(issuer_user) = device_user.get(&signed.issuer().to_bytes()).copied() else {
                continue;
            };
            if !ever_admin.contains(&issuer_user) {
                continue;
            }
            if !Self::grant_is_authorised(
                threshold,
                issuer_user,
                founder,
                grant,
                executed,
                proposals,
            ) {
                // Above a threshold of one, a role is the founder's to set or a
                // quorum's — see `grant_is_authorised`.
                continue;
            }
            let rank = (grant.seq, *digest);
            let supersedes = best
                .get(&grant.subject)
                .is_none_or(|current| rank > *current);
            if supersedes {
                best.insert(grant.subject, rank);
                roles.insert(grant.subject, grant.capability);
            } else {
                // An older generation of this subject's role, or a concurrent
                // grant that lost the digest tie-break.
            }
        }

        // Roles a quorum set directly. An executed `SetRole` proposal is the
        // authority in its own right: nobody has to mint a grant afterwards, and
        // nobody should, because every replica executes independently and would
        // mint a different certificate for the same decision.
        for (digest, signed) in proposals {
            if !executed.contains(digest) {
                continue;
            }
            let AdminAction::SetRole { user, role } = signed.payload().action else {
                continue;
            };
            let rank = (signed.payload().seq, *digest);
            if best.get(&user).is_none_or(|current| rank > *current) {
                best.insert(user, rank);
                roles.insert(user, role);
            } else {
                // An older decision about this user, or one that lost the
                // digest tie-break with a concurrent proposal.
            }
        }

        roles
    }

    /// The workspace threshold, from the founder's policy.
    ///
    /// Only the founder's own policy is honoured — anyone else's is inert — which
    /// is what makes this a constant rather than something a member can move.
    /// `max` across them so a duplicate can never *lower* the bar; an honest
    /// founder mints exactly one, in [`WorkspaceState::found`](crate::state::WorkspaceState::found).
    fn resolve_threshold(&self) -> u32 {
        self.policies
            .values()
            .filter(|signed| signed.issuer().to_bytes() == self.founder)
            .map(|signed| signed.payload().threshold.max(1))
            .max()
            .unwrap_or(DEFAULT_THRESHOLD)
    }

    /// The distinct users who have approved `proposal` and have ever been admins.
    ///
    /// **`ever_admin`, not `role_of`, and that is the whole soundness argument.**
    /// This set is consulted by `CgkaController::authorize` when it decides
    /// whether to merge somebody else's removal, so it must be monotone: a peer
    /// holding more certificates has to reach *at least* the same verdict, or two
    /// peers would merge different operations and the group would split. Counting
    /// by `role_of` would let a demotion retract an approval and do exactly that.
    ///
    /// The cost is the one already recorded for `ever_admin` everywhere else: a
    /// demoted admin's approval keeps counting. Demotion is a courtesy; removal
    /// is the enforcement.
    ///
    /// Users and not devices, because counting devices would let one admin with
    /// three computers satisfy a threshold of three.
    fn approving_users(
        approvals: &BTreeMap<[u8; 32], Signed<Approval>>,
        device_user: &BTreeMap<[u8; 32], [u8; 32]>,
        ever_admin: &BTreeSet<[u8; 32]>,
        proposal: &[u8; 32],
    ) -> BTreeSet<[u8; 32]> {
        approvals
            .values()
            .filter(|signed| signed.payload().proposal == *proposal)
            .filter_map(|signed| device_user.get(&signed.issuer().to_bytes()).copied())
            .filter(|user| ever_admin.contains(user))
            .collect()
    }

    /// Whether a grant may set a role, given the workspace threshold.
    ///
    /// At a threshold of one this is unconditional and the whole quorum
    /// mechanism is absent. Above it, a role may be set only by **the founder**
    /// or by **a quorum**, and both halves are load-bearing:
    ///
    /// * the founder's exemption is what lets a workspace bootstrap at all — with
    ///   a threshold of two and one admin, no proposal could ever reach quorum,
    ///   so somebody has to be able to appoint the second admin unilaterally, and
    ///   the founder already is the root of every chain here;
    /// * requiring a quorum of everyone else is what closes the obvious way round
    ///   a threshold: an admin who could appoint a second admin alone could
    ///   appoint a puppet and then approve its own actions twice.
    fn grant_is_authorised(
        threshold: u32,
        issuer_user: [u8; 32],
        founder: [u8; 32],
        grant: &Grant,
        executed: &BTreeSet<[u8; 32]>,
        proposals: &BTreeMap<[u8; 32], Signed<AdminProposal>>,
    ) -> bool {
        if threshold <= DEFAULT_THRESHOLD || issuer_user == founder {
            return true;
        }
        executed.iter().any(|digest| {
            proposals.get(digest).is_some_and(|signed| {
                signed.payload().action
                    == AdminAction::SetRole {
                        user: grant.subject,
                        role: grant.capability,
                    }
            })
        })
    }

    /// How many **distinct admin users** have approved this proposal.
    ///
    /// Users and not devices, and the difference is the whole security property:
    /// counting devices would let one admin satisfy a threshold of three by
    /// approving from a laptop, a phone and a tablet — which is not a quorum, it
    /// is one person with three computers.
    #[must_use]
    pub fn approver_count(&self, proposal: &[u8; 32]) -> usize {
        self.approvers(proposal).len()
    }

    /// The distinct admin users who have approved this proposal, in id order.
    #[must_use]
    pub fn approvers(&self, proposal: &[u8; 32]) -> BTreeSet<[u8; 32]> {
        Self::approving_users(
            &self.approvals,
            &self.device_user,
            &self.ever_admin,
            proposal,
        )
    }

    /// How many distinct admins an administrative action needs.
    ///
    /// Fixed by the founder at creation and never changed; see [`Policy`].
    /// [`DEFAULT_THRESHOLD`] when no policy was minted, so a workspace that never
    /// uses this machinery behaves exactly as it did before the machinery
    /// existed.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Whether some proposal for exactly this action has reached quorum.
    ///
    /// The receiver-side predicate. `CgkaController::authorize` asks it before
    /// merging somebody else's `Remove`, which is what makes a threshold binding
    /// on the group rather than on the node that happens to be issuing.
    #[must_use]
    pub fn is_executed_action(&self, action: &AdminAction) -> bool {
        self.executed.iter().any(|digest| {
            self.proposals
                .get(digest)
                .is_some_and(|signed| signed.payload().action == *action)
        })
    }

    /// Whether this proposal has reached the threshold that applied to it.
    #[must_use]
    pub fn is_executable(&self, proposal: &[u8; 32]) -> bool {
        self.executed.contains(proposal)
    }

    /// The certificates proving a quorum authorised `action`.
    ///
    /// The founder's policy, the executed proposal, and the approvals that
    /// carried it — everything a receiver needs to reach the same verdict
    /// without already holding any of it. Bundled with the operation for the
    /// reason [`AuthorizedOp`](crate::keys::AuthorizedOp) gives: an operation
    /// whose proof travels separately cannot be judged on arrival, and one that
    /// cannot be judged has to be parked, which is a flooding surface.
    ///
    /// Empty if no proposal for this action has reached quorum.
    #[must_use]
    pub fn proof_of(&self, action: &AdminAction) -> Vec<Certificate> {
        let Some(digest) = self.executed.iter().find(|digest| {
            self.proposals
                .get(*digest)
                .is_some_and(|signed| signed.payload().action == *action)
        }) else {
            return Vec::new();
        };

        let mut proof: Vec<Certificate> = self
            .policies
            .values()
            .filter(|signed| signed.issuer().to_bytes() == self.founder)
            .cloned()
            .map(Certificate::Policy)
            .collect();
        if let Some(signed) = self.proposals.get(digest) {
            proof.push(Certificate::Proposal(signed.clone()));
        } else {
            // Unreachable: `digest` came from a lookup in this same map.
        }
        proof.extend(
            self.approvals
                .values()
                .filter(|signed| signed.payload().proposal == *digest)
                .cloned()
                .map(Certificate::Approval),
        );
        proof
    }

    /// Every proposal that has reached quorum, with its action, in digest order.
    ///
    /// What a replica performs. Every node holding the same certificates derives
    /// the same list, so each one acts independently and the duplicates merge.
    #[must_use]
    pub fn executable(&self) -> Vec<([u8; 32], AdminAction)> {
        self.executed
            .iter()
            .filter_map(|digest| {
                let signed = self.proposals.get(digest)?;
                Some((*digest, signed.payload().action))
            })
            .collect()
    }

    /// Every proposal this store holds, executed or not, in digest order.
    ///
    /// For an application that wants to show what is awaiting approval, together
    /// with how close each one is.
    #[must_use]
    pub fn proposals(&self) -> Vec<ProposalStatus> {
        self.proposals
            .iter()
            .map(|(digest, signed)| ProposalStatus {
                digest: *digest,
                action: signed.payload().action,
                approvals: self.approver_count(digest),
                required: self.threshold,
                executable: self.executed.contains(digest),
            })
            .collect()
    }

    /// The next `seq` to use for a new proposal.
    ///
    /// One past the highest any proposal carries, admitted or not — the same
    /// reasoning as [`Self::next_seq`]: counting rejected proposals too stops a
    /// member freezing the sequence with one absurd value.
    #[must_use]
    pub fn next_proposal_seq(&self) -> u64 {
        self.proposals
            .values()
            .map(|signed| signed.payload().seq)
            .max()
            .map_or(0, |highest| highest.saturating_add(1))
    }

    /// Whether this user has ever held an admin grant. **Monotone.**
    ///
    /// The predicate that admits certificates. Never use it to decide whether an
    /// action is permitted *now* — that is [`Self::role_of`] — and see the module
    /// documentation for why the two cannot be the same question.
    #[must_use]
    pub fn ever_admin(&self, user: &[u8; 32]) -> bool {
        self.ever_admin.contains(user)
    }

    /// This user's current role, if any valid grant names them.
    #[must_use]
    pub fn role_of(&self, user: &[u8; 32]) -> Option<Role> {
        self.roles.get(user).copied()
    }

    /// The user a certified device acts for.
    ///
    /// `None` means the device holds no admitted binding — either its
    /// certificate has not arrived yet, or nobody authorised to bind it ever
    /// did. Both answers are "this leaf speaks for nobody", which is what
    /// callers need.
    #[must_use]
    pub fn user_of(&self, device: &[u8; 32]) -> Option<[u8; 32]> {
        self.device_user.get(device).copied()
    }

    /// The role a *device* acts under: its owner's.
    #[must_use]
    pub fn role_of_member(&self, device: &[u8; 32]) -> Option<Role> {
        self.role_of(&self.user_of(device)?)
    }

    /// Whether this device holds an admitted binding.
    #[must_use]
    pub fn is_certified_device(&self, device: &[u8; 32]) -> bool {
        self.device_user.contains_key(device)
    }

    /// Every certified device, in ascending id order.
    pub fn certified_devices(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.device_user.keys().copied()
    }

    /// Every certified device belonging to one user, in ascending id order.
    #[must_use]
    pub fn devices_of(&self, user: &[u8; 32]) -> Vec<[u8; 32]> {
        self.device_user
            .iter()
            .filter(|(_, owner)| *owner == user)
            .map(|(device, _)| *device)
            .collect()
    }

    /// Every user holding a role, with that role, in ascending id order.
    #[must_use]
    pub fn roles(&self) -> Vec<([u8; 32], Role)> {
        self.roles.iter().map(|(u, r)| (*u, *r)).collect()
    }

    /// How many users currently hold an administrative role.
    ///
    /// Counted per user, not per device: a person with three devices is one
    /// administrator, and counting leaves would let the last admin be removed
    /// while the count still looked healthy.
    #[must_use]
    pub fn admin_count(&self) -> usize {
        self.roles
            .values()
            .filter(|role| role.can_administer())
            .count()
    }

    /// Whether this device may issue membership changes.
    #[must_use]
    pub fn may_administer(&self, device: &[u8; 32]) -> bool {
        self.role_of_member(device)
            .is_some_and(Role::can_administer)
    }

    /// Whether `issuer` may enrol a device for `user`.
    ///
    /// True when the issuer acts for that same user — enrolling your own phone —
    /// or when it may administer. Anything else would let a member bind a device
    /// of theirs to an admin's user and inherit the role.
    #[must_use]
    pub fn may_bind_device_to(&self, issuer: &[u8; 32], user: &[u8; 32]) -> bool {
        self.user_of(issuer) == Some(*user) || self.may_administer(issuer)
    }

    /// The next generation number to use when re-granting `subject`'s role.
    ///
    /// One past the highest `seq` any grant for this subject carries, admitted or
    /// not. Counting rejected grants too is deliberate: a member that mints
    /// itself a grant with a huge `seq` would otherwise be able to freeze a
    /// legitimate admin's ability to supersede it.
    #[must_use]
    pub fn next_seq(&self, subject: &[u8; 32]) -> u64 {
        self.grants
            .values()
            .filter(|signed| signed.payload().subject == *subject)
            .map(|signed| signed.payload().seq)
            .max()
            .map_or(0, |highest| highest.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{
        APPROVAL_DOMAIN, AdminAction, AdminProposal, Approval, BINDING_DOMAIN, CapabilityStore,
        Certificate, DeviceBinding, GRANT_DOMAIN, Grant, POLICY_DOMAIN, PROPOSAL_DOMAIN, Policy,
        Role,
    };

    /// A signer and its device id.
    fn device(seed: u64) -> (MemorySigner, [u8; 32]) {
        let signer = MemorySigner::generate(&mut ChaCha20Rng::seed_from_u64(seed));
        let id = signer.verifying_key().to_bytes();
        (signer, id)
    }

    fn grant(
        signer: &MemorySigner,
        subject: [u8; 32],
        capability: Role,
        seq: u64,
        nonce: u8,
    ) -> Certificate {
        Grant::new(subject, capability, seq, None, [nonce; 16])
            .sign(signer)
            .expect("signing a grant is infallible with a memory signer")
    }

    fn bind(signer: &MemorySigner, dev: [u8; 32], user: [u8; 32], nonce: u8) -> Certificate {
        DeviceBinding::new(dev, user, [nonce; 16])
            .sign(signer)
            .expect("signing a binding is infallible with a memory signer")
    }

    /// Given a store rooted at a founder, when nothing has been inserted, we
    /// expect the founder to already be an admin.
    ///
    /// The root has to be axiomatic. If the founder needed a certificate to be an
    /// admin, that certificate would need an issuer who was already an admin, and
    /// no workspace could ever bootstrap.
    #[test]
    fn the_founder_is_an_admin_without_any_certificate() {
        let (_, founder) = device(1);
        let store = CapabilityStore::new(founder);

        assert_eq!(
            store.role_of(&founder),
            Some(Role::Admin),
            "the founder must be an admin by axiom, or no workspace can bootstrap"
        );
        assert_eq!(
            store.user_of(&founder),
            Some(founder),
            "the founding device must resolve to the founding user, or the founder's own \
             leaf speaks for nobody"
        );
    }

    /// Given a founder who grants a viewer role to a new user and binds their
    /// device, when that user's role is read back, we expect the granted role.
    #[test]
    fn an_admin_can_admit_a_user_and_bind_their_device() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let mut store = CapabilityStore::new(founder);

        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder may bind any device");
        store
            .insert(grant(&founder_signer, bob, Role::Viewer, 0, 2))
            .expect("the founder may grant any role");

        assert_eq!(
            store.role_of_member(&bob),
            Some(Role::Viewer),
            "a device admitted by an admin must resolve to the role it was granted"
        );
    }

    /// Given a member holding a non-administrative role, when that member signs a
    /// grant promoting itself, we expect the store to ignore it.
    ///
    /// This is the escalation the whole module exists to refuse. The certificate
    /// verifies — it is genuinely signed by a genuine member — and it is still
    /// not admitted, because its issuer holds no capability that admits it.
    #[test]
    fn a_viewer_cannot_promote_itself() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder binds bob's device");
        store
            .insert(grant(&founder_signer, bob, Role::Viewer, 0, 2))
            .expect("bob is a viewer");

        store
            .insert(grant(&bob_signer, bob, Role::Admin, 99, 3))
            .expect("a validly signed certificate is stored even when it grants nothing");

        assert_eq!(
            store.role_of(&bob),
            Some(Role::Viewer),
            "a viewer promoted itself by signing its own grant, so the certificate closure \
             is not checking who was permitted to issue it"
        );
        assert!(
            !store.ever_admin(&bob),
            "a self-issued admin grant made its subject permanently able to admit further \
             certificates, which would make the escalation irreversible"
        );
    }

    /// Given a member with no administrative role, when that member binds a
    /// device to another user's account, we expect the binding to be ignored.
    #[test]
    fn a_viewer_cannot_bind_a_device_to_another_users_account() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let (_, mallory) = device(3);
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder binds bob's device");
        store
            .insert(grant(&founder_signer, bob, Role::Viewer, 0, 2))
            .expect("bob is a viewer");

        store
            .insert(bind(&bob_signer, mallory, founder, 3))
            .expect("the certificate is stored");

        assert_eq!(
            store.user_of(&mallory),
            None,
            "a viewer bound a device it controls to the founder's user, so that device \
             would inherit the founder's admin role"
        );
    }

    /// Given a user who owns one device, when that device binds a second device
    /// to the same user, we expect the second device to be certified.
    ///
    /// Enrolling your own phone is not an act of administration, and requiring an
    /// admin for it would make multi-device support an administrative burden.
    #[test]
    fn a_device_may_enrol_a_sibling_device_of_its_own_user() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let (_, bob_phone) = device(3);
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder binds bob's laptop");
        store
            .insert(grant(&founder_signer, bob, Role::Editor, 0, 2))
            .expect("bob is an editor");

        store
            .insert(bind(&bob_signer, bob_phone, bob, 3))
            .expect("bob enrols his own phone");

        assert_eq!(
            store.role_of_member(&bob_phone),
            Some(Role::Editor),
            "a second device of the same user must inherit that user's role, since roles \
             attach to people rather than to leaves"
        );
    }

    /// Given two grants for one subject, when they carry different `seq` values,
    /// we expect the higher one to decide the role regardless of insertion order.
    ///
    /// Demotion depends on this. Insertion order is the thing a network controls
    /// and the thing a convergent store must not depend on, so both orders are
    /// asserted rather than one.
    #[test]
    fn the_highest_seq_grant_decides_the_role_in_either_order() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let promote = grant(&founder_signer, bob, Role::Admin, 1, 1);
        let demote = grant(&founder_signer, bob, Role::Viewer, 2, 2);

        let mut forwards = CapabilityStore::new(founder);
        forwards.insert(bind(&founder_signer, bob, bob, 3)).unwrap();
        forwards.insert(promote.clone()).unwrap();
        forwards.insert(demote.clone()).unwrap();

        let mut backwards = CapabilityStore::new(founder);
        backwards
            .insert(bind(&founder_signer, bob, bob, 3))
            .unwrap();
        backwards.insert(demote).unwrap();
        backwards.insert(promote).unwrap();

        assert_eq!(
            forwards.role_of(&bob),
            Some(Role::Viewer),
            "the later generation of a role must win, or an admin cannot be demoted"
        );
        assert_eq!(
            forwards.role_of(&bob),
            backwards.role_of(&bob),
            "two peers that received the same two grants in opposite orders disagreed about \
             the resulting role, so the closure depends on delivery order"
        );
        assert!(
            forwards.ever_admin(&bob),
            "demotion must not retract `ever_admin`: it is the monotone predicate that keeps \
             certificate admission order-independent"
        );
    }

    /// Given certificates that arrive before the certificate authorising their
    /// issuer, when the closure is recomputed, we expect the same result as if
    /// they had arrived in causal order.
    ///
    /// This is the property that lets a certificate bundle be shipped in any
    /// order and a log be replayed from any starting point. The fixpoint exists
    /// precisely so that a certificate rejected on one pass is reconsidered once
    /// its issuer becomes admissible.
    #[test]
    fn a_certificate_arriving_before_its_issuers_is_admitted_once_the_issuer_is() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let (_, bob_phone) = device(3);

        // Bob's phone is enrolled by bob, whose own binding comes last.
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&bob_signer, bob_phone, bob, 1))
            .expect("stored, though not yet admissible");
        assert_eq!(
            store.user_of(&bob_phone),
            None,
            "a binding whose issuer is not yet certified must not be admitted, or the order \
             of arrival would decide who is a member"
        );

        store
            .insert(bind(&founder_signer, bob, bob, 2))
            .expect("the founder certifies bob");

        assert_eq!(
            store.user_of(&bob_phone),
            Some(bob),
            "the out-of-order binding was never reconsidered once its issuer became \
             certified, so a bundle would have to be delivered in causal order"
        );
    }

    /// Given two bindings naming different users for one device, when they are
    /// inserted in either order, we expect one to win and both orders to pick
    /// the same one.
    ///
    /// **Not "the first-issued binding stands"** — the closure iterates in digest
    /// order and takes the first admissible binding per device, so which one wins
    /// is a function of the certificate *set* and not of who issued first. That
    /// distinction is the whole guarantee: two peers holding the same
    /// certificates must resolve a leaf to the same user however those
    /// certificates reached them, or a receiver-side check diverges the group
    /// permanently.
    ///
    /// This test previously asserted that the binding inserted first survived,
    /// which held only because the nonce it used happened to hash below the
    /// other's. Adding the domain tag changed both digests and flipped the
    /// winner, failing a test whose subject had not changed at all — so the
    /// assertion is now on the property the code actually has.
    #[test]
    fn a_certified_devices_user_does_not_depend_on_arrival_order() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let (_, carol) = device(3);

        let first = bind(&founder_signer, bob, bob, 1);
        let second = bind(&founder_signer, bob, carol, 2);

        let mut forwards = CapabilityStore::new(founder);
        forwards.insert(first.clone()).expect("stored");
        forwards.insert(second.clone()).expect("stored");

        let mut backwards = CapabilityStore::new(founder);
        backwards.insert(second).expect("stored");
        backwards.insert(first).expect("stored");

        let resolved = forwards.user_of(&bob);
        assert_eq!(
            resolved,
            backwards.user_of(&bob),
            "two peers holding the same certificates resolved one leaf to two \
             different users; a receiver-side authorization check on that would \
             diverge the group and never recover"
        );
        assert!(
            resolved == Some(bob) || resolved == Some(carol),
            "the leaf must resolve to one of the two users named, not to neither \
             and not to something invented, got {resolved:?}"
        );
        assert_eq!(
            forwards.devices_of(&bob).len() + forwards.devices_of(&carol).len(),
            1,
            "one device must act for exactly one user, or a second binding is a \
             way to inherit somebody else's role"
        );
    }

    /// Given a forged certificate, when it is offered to the store, we expect a
    /// signature error and no change.
    #[test]
    fn a_certificate_with_a_broken_signature_is_refused() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let mut store = CapabilityStore::new(founder);

        // Re-sign a different payload under the same signature by swapping the
        // payload out of a valid certificate.
        let Certificate::Grant(valid) = grant(&founder_signer, bob, Role::Viewer, 0, 1) else {
            unreachable!("grant() returns a Grant variant")
        };
        let forged = Certificate::Grant(keyhive_crypto::signed::Signed::new(
            Grant::new(bob, Role::Admin, 0, None, [1u8; 16]),
            *valid.issuer(),
            *valid.signature(),
        ));

        assert!(
            store.insert(forged).is_err(),
            "a certificate whose payload does not match its signature was accepted, so the \
             capability closure could be rewritten by anyone who has seen one certificate"
        );
        assert_eq!(
            store.role_of(&bob),
            None,
            "the refused certificate still changed the closure"
        );
    }

    /// Given the domain tags this crate stamps, we expect all of them to be
    /// sixteen bytes of printable ASCII and pairwise distinct.
    ///
    /// Both halves are load-bearing rather than tidy. **Distinct** is what stops
    /// a `Grant` signature being read as a `DeviceBinding`. **Printable ASCII**
    /// is what stops either being read as a `CgkaOperation`: bincode writes an
    /// enum discriminant as a little-endian `u32`, so bytes 1–3 of any variant
    /// index below 2^24 are zero, and no ASCII byte is. A tag containing a NUL
    /// would satisfy the first property and quietly lose the second, which is
    /// why this asserts the encoding and not just the inequality.
    #[test]
    fn the_domain_tags_are_distinct_and_free_of_nul_bytes() {
        let tags = [
            ("grant", GRANT_DOMAIN),
            ("binding", BINDING_DOMAIN),
            ("proposal", PROPOSAL_DOMAIN),
            ("approval", APPROVAL_DOMAIN),
            ("policy", POLICY_DOMAIN),
        ];
        for (i, (a_name, a)) in tags.iter().enumerate() {
            for (b_name, b) in tags.iter().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "the {a_name} and {b_name} tags are identical; two certificate \
                     kinds sharing a tag are mutually confusable, which is the \
                     whole thing the tags exist to prevent"
                );
            }
        }
        for (name, tag) in tags {
            assert!(
                tag.iter().all(u8::is_ascii_graphic),
                "the {name} tag must be printable ASCII: a zero byte in positions \
                 1..4 would let the payload alias a bincode enum discriminant"
            );
        }
    }

    /// Given the signed payload types this protocol defines, when each is
    /// encoded the way `Signed` encodes it, we expect no two to produce the same
    /// bytes — and we expect the certificate payloads to be unreadable as any
    /// `CgkaOperation`.
    ///
    /// **The test that would have caught the original defect.** `Signed<T>` signs
    /// `bincode(payload)` with no type tag, and verification recomputes it for
    /// whatever `T` the deserializer chose, so a genuine `(issuer, signature)`
    /// pair transfers between any two payload types with equal encodings. Before
    /// the domain tags, `DeviceBinding` was exactly 80 bytes — *every* 80-byte
    /// string decoded as one — and `CgkaOperation::Remove` was 88. Eight bytes,
    /// both signed by the same member key, and an admin's `Remove` lifted into a
    /// `DeviceBinding { device: attacker, user: admin }` is an escalation the
    /// closure admits. Nothing in the build would have failed had a beekem
    /// release closed that gap.
    ///
    /// The first-byte assertions are the structural argument and the reason this
    /// is not merely a size pin: they hold whatever beekem does to its fields.
    /// The size assertions are the loud-failure half — they pin what the wire
    /// format *is*, so a bincode or dependency change that silently alters it
    /// fails here rather than in a peer's decoder.
    #[test]
    fn the_signed_payload_types_cannot_share_an_encoding() {
        use beekem::{
            id::{MemberId, TreeId},
            operation::CgkaOperation,
        };

        let (_, id) = device(1);
        let member = MemberId::from(
            ed25519_dalek::VerifyingKey::from_bytes(&id).expect("a signer's key is a valid point"),
        );
        let tree = TreeId::from(
            ed25519_dalek::VerifyingKey::from_bytes(&id).expect("a signer's key is a valid point"),
        );

        let grant = bincode::serialize(&Grant::new(id, Role::Admin, 0, None, [0u8; 16]))
            .expect("a grant serializes");
        let binding = bincode::serialize(&DeviceBinding::new(id, id, [0u8; 16])).expect(
            "a binding
 serializes",
        );
        // The smallest `CgkaOperation` there is: no removed keys, no
        // predecessors. Anything larger is further away, so bounding the
        // smallest bounds them all.
        let remove = bincode::serialize(&CgkaOperation::Remove {
            id: member,
            leaf_idx: 0,
            removed_keys: Vec::new(),
            predecessors: Vec::new(),
            doc_id: tree,
        })
        .expect("an operation serializes");

        let proposal = bincode::serialize(&AdminProposal::new(
            AdminAction::RemoveMember { member: id },
            0,
            None,
            [0u8; 16],
        ))
        .expect("a proposal serializes");
        let approval = bincode::serialize(&Approval::new([0u8; 32], [0u8; 16]))
            .expect("an approval serializes");
        let policy = bincode::serialize(&Policy::new(2, [0u8; 16])).expect("a policy serializes");

        // Pairwise, not just against the grant: five types means ten pairs, and
        // the newest are the smallest payloads in the protocol — exactly
        // the shape that collides.
        let all = [
            ("grant", &grant),
            ("binding", &binding),
            ("proposal", &proposal),
            ("approval", &approval),
            ("policy", &policy),
        ];
        for (i, (a_name, a)) in all.iter().enumerate() {
            for (b_name, b) in all.iter().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "a {a_name} and a {b_name} must never encode alike, or one \
                     signature authorises both"
                );
            }
        }
        for (name, encoded) in all {
            assert_ne!(
                encoded[..],
                remove[..],
                "a {name} must never encode as a CGKA operation: both are signed \
                 by the same member key, so a lifted signature would be genuine"
            );
            assert!(
                encoded[1..4].iter().any(|b| *b != 0),
                "a {name} must not begin with bytes a bincode enum discriminant \
                 could produce; that is what makes the previous assertion hold \
                 for every CgkaOperation rather than just this one"
            );
        }
        assert_eq!(
            remove[1..4],
            [0u8; 3],
            "the discriminant argument above assumes a CGKA operation's variant \
             index is small enough to leave bytes 1..4 zero; if beekem ever \
             exceeds 2^24 variants, the argument needs redoing"
        );

        // The wire format, pinned. Untagged these were 61 and 80.
        assert_eq!(grant.len(), 77, "a grant with no expiry is 16+32+4+8+1+16");
        assert_eq!(binding.len(), 96, "a binding is 16+32+32+16");
        assert_eq!(
            proposal.len(),
            77,
            "a removal proposal with no expiry is 16+4+32+8+1+16 — the same \
             length as a grant, which is fine and is the point: what separates \
             them is the domain tag in the first sixteen bytes, not their size. \
             An implementer who reads a length collision here as a defect has \
             misread the property."
        );
        assert_eq!(approval.len(), 64, "an approval is 16+32+16");
        assert_eq!(policy.len(), 36, "a policy is 16+4+16");
        assert_eq!(
            bincode::serialize(&Grant::new(id, Role::Admin, 0, Some(1), [0u8; 16]))
                .expect("a grant serializes")
                .len(),
            85,
            "an expiring grant carries eight more bytes than one without"
        );
    }

    /// Given a payload signed for another purpose, when it is presented as a
    /// certificate, we expect `WrongDomain` rather than a signature failure.
    ///
    /// The two verdicts say opposite things about the issuer, and only one of
    /// them is a security event: a bad signature means nobody vouched for these
    /// bytes, while a wrong domain means somebody *did* and their signature is
    /// being pointed at something they never agreed to. Reporting the second as
    /// the first would file a cross-protocol lift under "corrupt message".
    #[test]
    fn a_certificate_carrying_another_types_tag_is_refused_as_such() {
        let (signer, id) = device(1);

        // Signed genuinely, so the signature is perfectly valid — the tag is the
        // only thing wrong with it.
        let mut mislabelled = Grant::new(id, Role::Admin, 0, None, [0u8; 16]);
        mislabelled.domain = BINDING_DOMAIN;
        let cert = mislabelled
            .sign(&signer)
            .expect("signing is infallible with a memory signer");

        assert!(
            matches!(cert.verify(), Err(crate::error::CoreError::WrongDomain)),
            "a grant wearing the binding tag must be refused as the wrong kind of \
             certificate, not as a forgery"
        );

        let mut untagged = DeviceBinding::new(id, id, [0u8; 16]);
        untagged.domain = [0u8; 16];
        let cert = untagged
            .sign(&signer)
            .expect("signing is infallible with a memory signer");
        assert!(
            matches!(cert.verify(), Err(crate::error::CoreError::WrongDomain)),
            "an untagged payload must be refused too, which is what makes the tag \
             a requirement rather than a hint"
        );
    }

    /// Given a certificate whose tag is wrong, when it reaches the store, we
    /// expect it to change nothing.
    ///
    /// `verify` returning an error is only half the guarantee; the half that
    /// matters is that `insert` consults it. A store that recomputed its closure
    /// before checking would satisfy every assertion above and still admit the
    /// certificate.
    #[test]
    fn a_wrongly_tagged_certificate_never_reaches_the_closure() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let mut store = CapabilityStore::new(founder);

        let mut mislabelled = Grant::new(bob, Role::Admin, 0, None, [0u8; 16]);
        mislabelled.domain = BINDING_DOMAIN;
        let cert = mislabelled
            .sign(&founder_signer)
            .expect("signing is infallible with a memory signer");

        assert!(
            store.insert(cert).is_err(),
            "the store must refuse a certificate its own verifier rejects"
        );
        assert_eq!(
            store.role_of(&bob),
            None,
            "a refused certificate must leave the closure untouched, however \
             genuine the signature over it was"
        );
    }
}
