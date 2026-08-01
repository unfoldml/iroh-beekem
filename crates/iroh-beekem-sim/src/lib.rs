//! Deterministic simulation of the `iroh-beekem` workspace protocol.
//!
//! [`WorkspaceNode`] implements `propsim_core::Node`, which lets the whole
//! protocol — onboarding, control-plane gossip, encrypted content sync — run on
//! a single-threaded simulator with virtual time, a seeded RNG, and scripted
//! partitions and reordering.
//!
//! This is possible only because `iroh-beekem-core` is I/O-free: `Node::on_msg`
//! is a synchronous callback, so a state machine that needed an async runtime
//! could not be plugged in at all.
//!
//! # The simulated protocol
//!
//! Node 0 founds the workspace. Every other node publishes its leaf key with
//! [`Msg::Hello`], the founder admits it and replies with [`Msg::Welcome`]
//! carrying the full CGKA operation log, and the joiner replays that log to
//! reconstruct the group. Thereafter all nodes gossip [`Msg::Op`] (control
//! plane) and [`Msg::Entry`] (data plane), with [`Msg::Log`] and
//! [`Msg::Repair`] as the two repair paths — one for a lost operation, one for
//! an epoch a node was admitted too late to derive.
//!
//! Messages that arrive before a node has joined are buffered rather than
//! dropped, because under an unordered transport a `Welcome` routinely loses
//! the race against the operations that follow it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};

use beekem::{
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
// Re-exported rather than merely used: a property asserting "this member holds
// exactly the role it was granted" needs to name a role, and making the test
// depend on `iroh-beekem-core` directly for one enum would obscure that the
// simulator is the thing under test.
pub use iroh_beekem_core::Role;
use iroh_beekem_core::{
    AdminAction, AssetMeta, AuthorizedOp, Certificate, CgkaController, Chunk, DocumentUuid, Effect,
    EpochId, Event, FileEntry, NamespaceEpoch, ProposalStatus, RepairTarget, StorageKey,
    UnixSeconds, WorkspaceSecret, WorkspaceState,
    asset::{ContentDigest, open_segment, seal_segment},
    state::AssetKeyVerdict,
    version::AssetVersion,
};
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use propsim_core::{
    ClientCodec, FrozenOp, NodeId,
    history::{Function, Value},
    node::{Completion, Ctx, Node, OpOutcome, OpToken},
};
use proptest::{
    prelude::prop_oneof,
    strategy::{BoxedStrategy, Strategy},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// The documents every simulated node knows about.
///
/// A fixed pool rather than UUIDs invented per node: generated operations name
/// a document by *index*, and an index only means the same thing everywhere if
/// the pool is agreed in advance. Generating random UUIDs would produce
/// operations that address documents nobody else has, which tests nothing.
pub const DOCS: [DocumentUuid; 3] = [
    DocumentUuid([7u8; 16]),
    DocumentUuid([8u8; 16]),
    DocumentUuid([9u8; 16]),
];

/// The asset entry the [`Assets`] scenarios attach.
pub const ASSET: DocumentUuid = DocumentUuid([11u8; 16]);

/// The key space of that asset's first version.
///
/// Distinct from [`ASSET`] on purpose, and the distinction is the point: an
/// entry is an identity, a *version* is a body of segments, and each version is
/// blinded under a UUID of its own so that attaching a new one cannot overwrite
/// the index entries protecting the previous one's blobs. Using the entry's own
/// UUID here would model a shape the facade no longer writes.
pub const ASSET_V1: DocumentUuid = DocumentUuid([12u8; 16]);

/// Plaintext bytes per segment in the simulator.
///
/// Small on purpose. Padding to the four-mebibyte default would make every
/// broadcast in a run megabytes wide for no gain: nothing asserted here depends
/// on the segment size, only on whether a member can obtain the segments at all.
pub const SIM_SEGMENT_BYTES: u32 = 256;

/// The asset's plaintext, spanning several segments with a padded tail.
#[must_use]
pub fn asset_plaintext() -> Vec<u8> {
    // Deterministic and non-uniform, so a reassembly that lost or reordered a
    // segment cannot pass by accident.
    (0..(SIM_SEGMENT_BYTES as usize * 2 + 37))
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// When the founder attaches its asset.
///
/// After the group has formed and before any revocation, so that a member
/// removed later was demonstrably able to read it beforehand — otherwise "the
/// victim cannot read the asset" would be true for a reason that has nothing to
/// do with the removal.
const ATTACH_AT: Duration = Duration::from_millis(900);

/// The document the timer-driven scenarios edit.
pub const DOC: DocumentUuid = DOCS[0];

/// Which node founds the workspace.
const FOUNDER: u64 = 0;

/// How long after start a node makes its first edit, leaving time to onboard.
const FIRST_EDIT: Duration = Duration::from_millis(300);

/// Interval between a node's successive edits.
const EDIT_INTERVAL: Duration = Duration::from_millis(200);

/// How many edits each node makes before going quiet, so runs terminate.
const EDITS_PER_NODE: u32 = 2;

/// How often an unjoined node retries its `Hello`.
const JOIN_RETRY: Duration = Duration::from_millis(100);

/// How often a joined node re-announces its document state.
///
/// Every event causes the simulator to deep-clone all node state for its world
/// snapshot, and a deep clone here means serializing every CRDT document. The
/// interval and [`MAX_RESYNCS`] are therefore tuned to keep runs to seconds
/// while still giving lost chunks several chances to be re-announced.
const RESYNC_INTERVAL: Duration = Duration::from_millis(600);

/// How many times a node re-announces before going quiet, so runs terminate.
///
/// A real node re-announces forever — `iroh-docs` reconciles continuously — and
/// this budget exists only so a simulated run ends. It must therefore outlast
/// **the faults**, not merely the writes. A partition that heals after the last
/// re-announcement leaves the two sides permanently disagreeing, which reads as
/// a convergence bug and is really a harness that stopped trying: the very
/// artefact this comment used to warn about, one cause further out.
///
/// Sized against the fault schedule rather than the write schedule: at
/// [`RESYNC_INTERVAL`] this covers the horizon of every property in the suite.
/// Raising the *interval* rather than the count is deliberate — every event
/// makes the simulator deep-clone all node state, so coverage is bought far
/// more cheaply in duration than in frequency.
const MAX_RESYNCS: u32 = 24;

/// The re-announcement budget when generated operations drive the run.
const MAX_RESYNCS_UNDER_WORKLOAD: u32 = 24;

/// How many anti-entropy rounds pass between control-plane log repairs.
///
/// The control plane needs its own repair — a lost operation is unrecoverable
/// by any amount of data-plane re-announcement — but a log broadcast carries the
/// whole history to every peer, which makes it the most expensive message in the
/// simulation. Production is event-driven and cooldown-limited here; this is the
/// closest cheap analogue.
const LOG_REPAIR_EVERY: u32 = 4;

/// How many anti-entropy rounds pass between data-plane reconciliations.
///
/// Sparser than every round for the same reason [`LOG_REPAIR_EVERY`] is, and the
/// error it guards against is the *opposite* of the one reconciliation exists to
/// fix. `iroh-docs` reconciles pairwise and differentially: two peers compare key
/// ranges and transfer only what one of them lacks, which is usually nothing.
/// The harness has no range structure to compare, so it re-offers everything to
/// everyone — and doing that on every round makes the simulated data plane far
/// **more** talkative than production, crowding out the control plane under a
/// fault plan that drops and delays messages. A quorum whose approvals lose that
/// race then fails a liveness property, which is an artefact of the model in
/// exactly the way a missing reconciliation was.
///
/// Four rounds still leaves several reconciliations inside [`MAX_RESYNCS`], which
/// is what the lost-entry recovery needs; it does not need one per round.
const RECONCILE_EVERY: u32 = 4;

/// How long one repair request is suppressed before the same one is re-sent.
///
/// A stuck peer receives an unreachable chunk on every anti-entropy round from
/// every publisher, and the core raises a request for each — deliberately, so a
/// request lost in transit is retried. This is where that is turned back into a
/// bounded rate. Keyed on `(target, epoch)`, so becoming stuck on a *new* epoch
/// is served at once rather than waiting the window out.
///
/// Shorter than [`RESYNC_INTERVAL`] on purpose: a window longer than the round
/// that produces the request would suppress every retry, which is the failure
/// this whole mechanism exists to prevent. The real `Workspace` uses the same
/// relationship at a larger scale.
const REPAIR_COOLDOWN: Duration = Duration::from_millis(500);

/// How often a rotating node re-keys its leaf.
const ROTATE_INTERVAL: Duration = Duration::from_millis(350);

/// When the first rotation happens, once the group has had time to form.
const FIRST_ROTATE: Duration = Duration::from_millis(700);

/// How many times a node rotates before going quiet, so runs terminate.
const MAX_ROTATIONS: u32 = 12;

/// When the founder revokes the victim, in scenarios that revoke.
///
/// Deliberately late enough that the victim has stopped writing, and early
/// enough that rotations are still in flight — a `Remove` concurrent with an
/// `Update` is the interleaving BeeKEM claims to handle and MLS/TreeKEM cannot.
const REVOKE_AT: Duration = Duration::from_millis(3600);

/// The document written only after the revocation, in scenarios that do so.
///
/// Deliberately one the timer-driven edits never touch, so that every entry
/// under its blinded key postdates the removal and the victim seeing *any* of
/// them is a failure rather than a leftover.
pub const POST_REVOCATION_DOC: DocumentUuid = DOCS[2];

/// When the founder writes to [`POST_REVOCATION_DOC`].
///
/// Far enough past [`REVOKE_AT`] that the rotation has been announced and
/// adopted; otherwise the property would be testing a race rather than the
/// eviction.
const WRITE_AFTER_REVOKE_AT: Duration = Duration::from_secs(6);

/// When the departing member of a `Departure` run walks away.
///
/// After the first edits and the first few resyncs, so the leaver is a settled,
/// fully-synced member when it goes — and early enough that the rest of the
/// horizon shows what the remaining members do about it.
const LEAVE_AT: Duration = Duration::from_secs(3);

/// When the founder promotes a co-admin and raises the threshold.
///
/// After the group has formed and the co-admin's certificates have had time to
/// reach everybody: a promotion that raced the co-admin's own admission would
/// leave a workspace whose threshold is two and whose second admin nobody has
/// heard of, which deadlocks rather than tests anything.
const APPOINT_CO_ADMIN_AT: Duration = Duration::from_millis(1500);

/// When the founder proposes the removal a quorum has to authorise.
const PROPOSE_AT: Duration = Duration::from_millis(2500);

/// How often each admin looks for something to approve.
///
/// Polled rather than driven by the arrival of a proposal, because an admin in a
/// real workspace approves when a person decides to — and because a timer keeps
/// the simulated approval independent of the delivery order the transport
/// happens to produce.
const APPROVE_INTERVAL: Duration = Duration::from_millis(600);

/// How often a forging node emits an operation signed by a non-member key.
const FORGE_INTERVAL: Duration = Duration::from_millis(300);

/// How many forgeries an attacking node attempts.
const MAX_FORGERIES: u32 = 10;

/// How often an insider tries to act beyond the role it was granted.
const OVERREACH_INTERVAL: Duration = Duration::from_millis(400);

/// How many times an insider tries.
///
/// Bounded like [`MAX_FORGERIES`], and for a sharper reason in the revenant
/// case: each splice that lands costs the honest group a removal and a namespace
/// rotation, so an unbounded attacker would keep the group rotating for the whole
/// run and the convergence properties would be measuring the attack rather than
/// the protocol.
const MAX_OVERREACHES: u32 = 6;

/// What a simulated run exercises beyond the honest base protocol.
///
/// A compile-time parameter rather than a runtime field because `propsim`
/// builds nodes through [`Default`]: there is no constructor to pass a config
/// to, and a global would break the determinism the whole harness rests on.
pub trait Scenario: Clone + Default + 'static {
    /// Whether nodes periodically re-key their leaf (post-compromise security).
    const ROTATE: bool = false;
    /// Whether content changes come from generated client operations.
    ///
    /// When set, nodes stop scheduling their own edits: the workload drives
    /// every mutation instead. Leaving both on would mix a fixed script into
    /// the generated one and make it impossible to say which produced a result.
    const WORKLOAD: bool = false;
    /// Which node the founder revokes partway through, if any.
    const REVOKE: Option<u64> = None;
    /// Whether non-founder nodes also broadcast operations signed by a key that
    /// no `Add` ever introduced.
    const FORGE: bool = false;
    /// Whether the founder creates fresh content *after* the revocation.
    ///
    /// Without this, every "the victim never sees X" property is vacuous: in a
    /// run where all content predates the removal there is no X to miss, and a
    /// rotation that did nothing at all would pass. This writes to a document
    /// nothing has touched, so the entry it produces is one that exists only in
    /// the post-rotation namespace.
    const WRITE_AFTER_REVOKE: bool = false;
    /// Which node acts beyond the role it was granted, if any.
    ///
    /// Distinct from both [`Self::FORGE`] and [`Self::OUTSIDER`], and the
    /// distinction is the whole point. A forging node signs with a key no `Add`
    /// ever introduced, so `known_members` refuses it; an outsider never joins at
    /// all, so the roster refuses it. An **insider** signs with a key the group
    /// itself admitted, holding a role the group itself granted — nothing about
    /// its identity is wrong, only what it is trying to do. Until the capability
    /// closure existed there was nothing that could tell the difference.
    const INSIDER: Option<u64> = None;
    /// Whether the insider keeps acting *after* it has been removed.
    ///
    /// The revenant. Its capability is not retracted by removal — the certificate
    /// store is grow-only — and its signature stays admissible because
    /// `known_members` is monotone, so it is the one attacker the capability check
    /// deliberately does not refuse. What must happen instead is eviction.
    const REVENANT: bool = false;
    /// Which node never asks to be admitted, if any.
    ///
    /// Distinct from [`Self::FORGE`]: a forging node attacks the control plane
    /// with signatures it genuinely holds, while an outsider does nothing at
    /// all. It is on the network and receives every broadcast, and the only
    /// thing standing between it and the workspace is the roster.
    const OUTSIDER: Option<u64> = None;
    /// Which node redeems a ticket that was issued to somebody else, if any.
    ///
    /// A third kind of outsider, and the distinction from [`Self::OUTSIDER`] is
    /// what makes the scenario worth having: a plain outsider knows nothing and
    /// is refused by the roster before it observes anything at all. A thief holds
    /// a genuine [`Msg::Welcome`] — the inviter's identity, the replica the
    /// ticket names, the whole operation log — and is refused by *less*. What it
    /// still cannot obtain is the invitee's leaf secret, which never travels in a
    /// ticket, so it can watch the replica and decrypt nothing.
    ///
    /// The thief ignores the invitee binding, as an attacker running its own code
    /// would. Modelling it as honouring the check would make every property below
    /// pass for the wrong reason.
    const INVITE_THIEF: Option<u64> = None;

    /// A node that walks away of its own accord partway through the run.
    ///
    /// Distinct from [`Self::REVOKE`] in who acts and in what it costs. A
    /// revocation is issued by an admin and rotates the namespace, so the target
    /// is locked out of the replica as well as the tree. A departure is issued
    /// by the member itself, needs no role, and rotates nothing — the leaver
    /// keeps every key it ever derived and every entry it already synced.
    ///
    /// Modelled because that difference is exactly what a property can get
    /// wrong: a `leave` implemented as a self-issued `RemoveMember` would rotate,
    /// and every convergence property would still pass while the departing
    /// member quietly minted and received the capability it was leaving.
    const LEAVE: Option<u64> = None;

    /// How many distinct admins an administrative action needs.
    ///
    /// One by default, which is the threshold every workspace starts at and the
    /// one under which `require_quorum` behaves exactly like the `require_admin`
    /// it replaced — so every scenario that does not set this is unaffected by
    /// the machinery existing.
    ///
    /// Above one, the founder promotes [`Self::CO_ADMIN`] and then proposes and
    /// approves the raise, both of which it can still do alone because the raise
    /// is judged at the threshold in force *before* it.
    const THRESHOLD: u32 = 1;

    /// Whether the founder attaches a binary asset partway through the run.
    ///
    /// Modelled with a small segmentation rather than the four-mebibyte default,
    /// because what these properties are about is *distribution* — whether the
    /// content key reaches a member, whether a removed one is locked out, whether
    /// an asset survives a rotation — and none of that depends on how big a
    /// segment is. The sealing itself is specified where it belongs, in
    /// `iroh_beekem_core::asset`'s own tests, and the real segmentation is
    /// exercised over real `iroh` in `tests/assets.rs`.
    const ATTACH_ASSET: bool = false;

    /// A second node the founder promotes to admin, so a quorum is reachable.
    ///
    /// Without one, raising the threshold to two would deadlock the workspace:
    /// no action could ever collect two approvals, and every property about a
    /// quorum being *reached* would be vacuous rather than false.
    const CO_ADMIN: Option<u64> = None;
}

/// The base protocol: joins, edits and anti-entropy, nothing adversarial.
#[derive(Clone, Copy, Debug, Default)]
pub struct Honest;
impl Scenario for Honest {}

/// The founder attaches a binary asset that every member must be able to read.
///
/// User story 4. Beside [`Honest`] rather than derived from it because the
/// asset path shares almost nothing with the document path: it does not go
/// through the CRDT, it is not parked, and it is keyed by an envelope rather
/// than by the CGKA directly.
#[derive(Clone, Copy, Debug, Default)]
pub struct Assets;
impl Scenario for Assets {
    const ATTACH_ASSET: bool = true;
}

/// An asset attached before a member is removed, so the removal must not cost
/// the survivors their attachment.
#[derive(Clone, Copy, Debug, Default)]
pub struct AssetChurn;
impl Scenario for AssetChurn {
    const ATTACH_ASSET: bool = true;
    const REVOKE: Option<u64> = Some(2);
}

/// Concurrent key rotation and membership revocation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Churn;
impl Scenario for Churn {
    const ROTATE: bool = true;
    const REVOKE: Option<u64> = Some(2);
}

/// An attacker on the control plane, signing operations with an unrelated key.
#[derive(Clone, Copy, Debug, Default)]
pub struct Forging;
impl Scenario for Forging {
    const FORGE: bool = true;
}

/// Revocation, rotation, and content created after the victim is gone.
///
/// The scenario Story 3 is actually about: *"remove a departing team member so
/// they can no longer read documents, document updates or workspace changes"*.
/// [`Churn`] establishes that the remaining members survive a removal; this one
/// establishes what the removed member stops being able to see.
#[derive(Clone, Copy, Debug, Default)]
pub struct Eviction;
impl Scenario for Eviction {
    const ROTATE: bool = true;
    const REVOKE: Option<u64> = Some(2);
    const WRITE_AFTER_REVOKE: bool = true;
}

/// A node that never asks to join, sitting on the network and listening.
///
/// The scenario for the claim admission control is supposed to make true: that
/// confidentiality against a stranger rests on them not being a member, and not
/// merely on them not knowing the topic id. Node 3 is chosen rather than node 1
/// so that the honest group still has more than two members and the properties
/// about *them* stay meaningful.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outsider;
impl Scenario for Outsider {
    const OUTSIDER: Option<u64> = Some(3);
}

/// A member that joins legitimately, then acts beyond the role it was granted.
///
/// The scenario for the finding that phase 5 closed: every role check ran on the
/// node *issuing* an action, so a member holding the lowest role could add
/// members, remove the admin, and promote itself, and every peer merged all
/// three. Node 2 is the insider, and it attacks with the strongest proof it can
/// actually produce — certificates it signs itself, which are genuinely signed by
/// a genuine member and still admit nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Insider;
impl Scenario for Insider {
    const INSIDER: Option<u64> = Some(2);
}

/// An insider that keeps acting after it has been removed.
///
/// The one attacker the merge-time check deliberately lets through, because
/// refusing it would mean consulting `current_members` — an order-sensitive
/// predicate, so two peers seeing the removal and the operation in opposite
/// orders would drop different operations and diverge permanently. The splice is
/// accepted and then undone, so what this scenario asserts is *eviction* rather
/// than rejection.
#[derive(Clone, Copy, Debug, Default)]
pub struct Revenant;
impl Scenario for Revenant {
    const INSIDER: Option<u64> = Some(2);
    const REVENANT: bool = true;
    const REVOKE: Option<u64> = Some(2);
    const WRITE_AFTER_REVOKE: bool = true;
}

/// A stranger holding a copy of somebody else's admission ticket.
///
/// The scenario for what an `Invite` is actually worth to a thief. It is *not*
/// a read capability: joining needs the invitee's leaf secret, which never
/// travels in a ticket, so the thief reconstructs no group state and decrypts
/// nothing. What it does hold is a metadata capability — the inviter to dial and
/// the replica to watch — and the properties are about the size of that.
///
/// Node 3 steals; node 2 is removed partway through, which is the group's actual
/// remedy for a leaked ticket: the removal rotates the namespace, and the thief
/// cannot follow because following needs the group key it never had.
/// `WRITE_AFTER_REVOKE` is what makes "stops growing" mean something — without
/// post-rotation content there is nothing the thief could have gone on seeing,
/// and a rotation that did nothing at all would pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct StolenInvite;

/// A member that leaves the workspace of its own accord.
///
/// Node 2 joins, participates, and then issues `Event::Leave`. Nobody removes
/// it, nothing rotates, and the remaining members have to converge through a
/// membership change that arrived from an unexpected direction — every other
/// scenario's membership changes are issued by the founder.
///
/// The founder does not rotate here either (`ROTATE` stays false), and that is
/// deliberate: a concurrent rotation would give the remaining members a second
/// reason to re-key, and `a_departure_never_rotates_the_namespace` could then
/// pass or fail according to which one they observed first.
#[derive(Clone, Copy, Debug, Default)]
pub struct Departure;

impl Scenario for Departure {
    const LEAVE: Option<u64> = Some(2);
}

/// A workspace that needs two admins to agree before anything happens.
///
/// The founder promotes node 1 to admin and raises the threshold to two — both
/// while the threshold is still one, which is the only way a workspace can ever
/// get off the default. It then proposes removing node 2, which now needs node
/// 1's approval as well as its own.
///
/// Four nodes rather than three, so that the victim of the proposed removal is
/// neither of the two admins deciding on it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Quorum;

impl Scenario for Quorum {
    const THRESHOLD: u32 = 2;
    const CO_ADMIN: Option<u64> = Some(1);
    const REVOKE: Option<u64> = Some(2);
}
impl Scenario for StolenInvite {
    const INVITE_THIEF: Option<u64> = Some(3);
    const REVOKE: Option<u64> = Some(2);
    const WRITE_AFTER_REVOKE: bool = true;
}

/// Content driven entirely by generated CRUD operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct Crud;
impl Scenario for Crud {
    const WORKLOAD: bool = true;
}

/// Generated CRUD operations while members rotate keys and one is revoked.
#[derive(Clone, Copy, Debug, Default)]
pub struct CrudChurn;
impl Scenario for CrudChurn {
    const WORKLOAD: bool = true;
    const ROTATE: bool = true;
    const REVOKE: Option<u64> = Some(2);
}

/// Messages exchanged between simulated nodes.
#[derive(Clone, Debug)]
pub enum Msg {
    /// A prospective member publishes its leaf key.
    Hello {
        /// The joiner's CGKA identity.
        member: MemberId,
        /// The joiner's published leaf key.
        share_key: ShareKey,
    },
    /// The founder admits a joiner and ships the state needed to reconstruct
    /// the group.
    ///
    /// The operation log is public, signed data. The workspace secret is not,
    /// and in a real deployment this message must travel over an authenticated,
    /// encrypted channel — which is exactly what an `iroh` QUIC stream to a
    /// known public key provides.
    ///
    /// The counterpart of `Invite`. It models the two fields of a hardened
    /// invite that change what the *protocol* does — the invitee binding and the
    /// namespace generation — and deliberately not the two that do not:
    /// `not_after` and the single-use nonce are decided against a wall clock and
    /// a per-node ledger, both of which live in `iroh-beekem` for the same reason
    /// the core has no clock. Modelling them here would be modelling the
    /// transport's bookkeeping rather than the protocol's behaviour.
    Welcome {
        /// The device this ticket admits, and the only one that may redeem it.
        ///
        /// An honest node that receives a `Welcome` naming somebody else drops
        /// it. That is not what stops a thief — a thief runs its own code — it is
        /// what stops a misdirected or replayed ticket from being redeemed by a
        /// well-behaved peer, and it is the modelled half of `Invite.invitee`.
        invitee: MemberId,
        /// The replica this admission is against.
        ///
        /// The whole [`NamespaceEpoch`] and not merely its generation, because
        /// here it *is* the replica identifier: production hands the joiner an
        /// `iroh-docs` ticket, which names one replica exactly, and the digest is
        /// this model's stand-in for that. Only the generation reaches
        /// `WorkspaceState::joined`, mirroring production exactly — the joiner is
        /// given the half of the capability its role allows and so cannot
        /// reproduce the digest the rest of the group computed over the whole of
        /// it. Seeding the generation is what stops a peer still on an older one
        /// from re-announcing it and pulling a fresh joiner onto a replica the
        /// group has already abandoned.
        namespace: NamespaceEpoch,
        /// The full CGKA operation log, in causal order.
        log: Vec<Signed<CgkaOperation>>,
        /// The capability certificates for the workspace.
        ///
        /// Public, signed data like the log, and not optional: they authorise
        /// every `Add` the log contains, so a joiner replaying it without them
        /// would refuse the whole history including its own admission. The
        /// counterpart of `Invite.certs`.
        certs: Vec<Certificate>,
        /// The blinding secret for storage keys.
        secret: [u8; 32],
    },
    /// Control plane: a signed CGKA operation, with the certificates that
    /// authorise it.
    ///
    /// The proof travels *with* the operation because the receiver checks the
    /// issuer's capability before merging: one shipped without it is refused
    /// rather than parked, and no later certificate brings it back. Modelling
    /// them as separate messages would make the simulator strictly more fragile
    /// than production, which is the mistake `Msg::Log` exists to avoid.
    Op {
        /// The operation.
        op: Box<Signed<CgkaOperation>>,
        /// Certificates authorising it.
        proof: Vec<Certificate>,
    },
    /// Control plane: capability certificates with no operation behind them.
    ///
    /// A role change mints a grant and no CGKA operation, so it needs its own
    /// carrier. The counterpart of `ControlMsg::Certs`.
    Certs(Vec<Certificate>),
    /// Control plane repair: the sender's whole operation log.
    ///
    /// The counterpart of `ControlMsg::Log`, which the real `Workspace` ships
    /// whenever a neighbour appears. Without it a single lost [`Msg::Op`] is
    /// lost *forever*, and the consequences are unrecoverable rather than
    /// merely slow: a peer that misses the operation establishing a PCS key can
    /// never derive it, so every later chunk and every later manifest encrypted
    /// under that key is permanently undecryptable to it. Anti-entropy on the
    /// data plane cannot repair that, because re-announcing re-encrypts under
    /// the same key the peer already could not derive.
    ///
    /// Modelling the data plane's repair but not the control plane's would have
    /// made the simulator strictly more fragile than production, and every
    /// resulting failure an artefact of the harness.
    Log {
        /// The operation log, in causal order.
        ops: Vec<Signed<CgkaOperation>>,
        /// The sender's whole certificate store.
        ///
        /// Not optional, for the same reason the log itself is not: the
        /// certificates authorise every `Add` it contains, and they are the only
        /// anti-entropy a role change gets. Shipping the log without them would
        /// make log repair reinstate the very hole phase 5 closed.
        certs: Vec<Certificate>,
    },
    /// Control plane repair: "I can never decrypt what you are publishing."
    ///
    /// The counterpart of `ControlMsg::Repair`. A peer admitted after content
    /// already existed cannot derive the epoch that content was keyed under,
    /// and no amount of re-announcement helps — anti-entropy re-encrypts under
    /// that same epoch. This is how it says so, and a member that can read the
    /// content answers by minting a new epoch and publishing under it.
    ///
    /// Carried on the control plane rather than the data plane because that is
    /// where the answer's key material has to travel anyway, and because it is
    /// gated by the same roster: a node nobody admits cannot make the group
    /// re-key.
    Repair {
        /// Who is stuck. Checked against current membership by the receiver.
        member: MemberId,
        /// What they cannot read.
        target: RepairTarget,
        /// The epoch they cannot derive, which keys the sender's cooldown.
        epoch: EpochId,
    },
    /// Data plane: one entry in the replicated index.
    ///
    /// Carries the *blinded key* rather than a document id, because that is all
    /// `iroh-docs` ever sees and all a receiver ever gets. Working out which
    /// document an entry belongs to — or that it belongs to none this node
    /// knows about — is the receiver's job, exactly as it is in the real
    /// `ingest_all`. Modelling it any other way would hand the receiver
    /// information the wire does not carry, and would make it impossible to ask
    /// what a node can *see* as distinct from what it can *read*.
    Entry {
        /// Which replicated index this entry belongs to.
        ///
        /// `iroh-docs` reconciles *within* a namespace, so an entry written to
        /// one is simply invisible in another — there is no filtering step in
        /// production, only a peer syncing a replica it holds no capability
        /// for. Carrying the namespace here and dropping mismatches on receipt
        /// is the modelled equivalent, and it is what makes "the removed device
        /// stops seeing entries" expressible at all.
        namespace: NamespaceEpoch,
        /// The blinded key this entry is stored under.
        key: StorageKey,
        /// Which node wrote it.
        author: NodeId,
        /// The ciphertext.
        chunk: Box<Chunk>,
    },
    /// One sealed segment of a binary asset.
    ///
    /// Separate from [`Self::Entry`] because an asset segment is not a beekem
    /// `EncryptedContent`: it is sealed under the asset's own content key, and
    /// the CGKA protects that key rather than the bytes. Modelling it as a
    /// `Chunk` would mean inventing an epoch it does not have.
    ///
    /// Broadcast rather than pulled, which is where the model is deliberately
    /// *less* faithful than production: `iroh-docs` indexes an asset segment
    /// without downloading it, and a peer fetches the payload only when somebody
    /// opens the file. Pull-on-demand cannot make a property fail that broadcast
    /// would pass — it delays availability, it does not change what is
    /// available — and modelling the fetch would mean modelling a request/response
    /// exchange the harness has no notion of. What the download policy actually
    /// does is proved over real `iroh` in `tests/assets.rs`.
    Segment {
        /// Which replicated index this segment belongs to.
        namespace: NamespaceEpoch,
        /// The blinded key this segment is stored under.
        key: StorageKey,
        /// Which node wrote it.
        author: NodeId,
        /// The sealed segment.
        bytes: Vec<u8>,
    },
    /// A rotation to a fresh replicated index.
    ///
    /// The capability travels encrypted under the group key, so a device
    /// removed before the rotation cannot read it and stays on the abandoned
    /// namespace. Carried on the control plane because the data plane is the
    /// thing being replaced.
    Namespace {
        /// The generation being announced.
        epoch: u32,
        /// The encrypted capability.
        chunk: Box<Chunk>,
    },
}

/// A generated client operation: the CRUD surface an application drives.
///
/// This mirrors the public `Workspace` API rather than the internal `Event`
/// enum, because the point is to check the workspace as an application uses it.
/// Documents are named by index into [`DOCS`]; see there for why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsOp {
    /// Append text to a document.
    Append {
        /// Index into [`DOCS`].
        doc: usize,
        /// Text to append.
        text: String,
    },
    /// Replace a document's contents.
    Write {
        /// Index into [`DOCS`].
        doc: usize,
        /// The new contents.
        text: String,
    },
    /// Insert text at an offset, clamped to the document's length.
    Insert {
        /// Index into [`DOCS`].
        doc: usize,
        /// Character offset.
        pos: usize,
        /// Text to insert.
        text: String,
    },
    /// Delete a range, clamped to what the document holds.
    Remove {
        /// Index into [`DOCS`].
        doc: usize,
        /// Character offset.
        pos: usize,
        /// How many characters.
        len: usize,
    },
    /// Read a document's current text.
    Read {
        /// Index into [`DOCS`].
        doc: usize,
    },
    /// Put a document back to a version this node holds.
    ///
    /// `back` counts versions from the newest: 0 is the state the document is
    /// already in, 1 the state before the last change, and so on, clamped to what
    /// this node's history actually holds. Expressed that way because the
    /// generated workload cannot know a [`VersionId`](iroh_beekem_core::VersionId)
    /// — those are minted by the very edits the workload is producing — and
    /// because "undo the last thing" is what an application offers a person.
    ///
    /// A node holding no history for the document applies nothing, which is the
    /// same answer the real facade gives.
    Revert {
        /// Index into [`DOCS`].
        doc: usize,
        /// How many changes to step back from the newest.
        back: usize,
    },
}

impl WsOp {
    /// Which document in [`DOCS`] this operation names.
    #[must_use]
    pub fn doc_index(&self) -> usize {
        match self {
            Self::Append { doc, .. }
            | Self::Write { doc, .. }
            | Self::Insert { doc, .. }
            | Self::Remove { doc, .. }
            | Self::Revert { doc, .. }
            | Self::Read { doc } => *doc,
        }
    }
}

/// What a completed [`WsOp`] yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsResp {
    /// A read, carrying the text observed.
    Text(String),
    /// A mutation that took effect locally.
    Applied,
}

/// What a node can observe about an index entry without decrypting it.
///
/// This is the whole of the metadata the data plane leaks: who wrote it, how
/// big it is, and that it exists at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryMeta {
    /// Which node wrote the entry.
    pub author: NodeId,
    /// Ciphertext length.
    pub size: usize,
}

/// Timers a node arms for itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tick {
    /// Retry the join handshake.
    ///
    /// The transport drops messages, so a one-shot `Hello` is not enough: a
    /// node whose `Hello` or whose founder's `Welcome` is lost would never
    /// join. Retrying until joined is what a real onboarding flow does too.
    Join,
    /// Time to make another local edit.
    Edit,
    /// Time to re-announce local document state (anti-entropy).
    Resync,
    /// Time for the founder to attach a binary asset.
    Attach,
    /// Time to re-key this node's leaf.
    Rotate,
    /// Time for the founder to revoke the scenario's victim.
    Revoke,
    /// Time for the founder to write content the victim must never see.
    LateEdit,
    /// Time for an attacking node to emit a forged operation.
    Forge,
    /// Time for a member to act beyond the role it was granted.
    Overreach,
    /// Time for a member to leave the workspace of its own accord.
    Leave,
    /// Time for the founder to appoint the co-admin a quorum needs.
    AppointCoAdmin,
    /// Time for the founder to propose a removal that needs a quorum.
    ProposeRemoval,
    /// Time for an admin to approve whatever is awaiting approval.
    ApproveProposals,
}

/// One simulated workspace participant.
///
/// Constructed by the simulator via [`Default`], then bootstrapped in
/// [`Node::on_start`] once `cx.me()` reveals which node this is.
#[derive(Clone, Default)]
pub struct WorkspaceNode<S: Scenario = Honest> {
    state: Option<WorkspaceState>,
    signer: Option<MemorySigner>,
    share_secret: Option<ShareSecretKey>,
    /// Messages received before this node finished joining.
    inbox: Vec<Msg>,
    edits_made: u32,
    resyncs_done: u32,
    rotations_done: u32,
    forgeries_made: u32,
    /// How many times this node has acted beyond its role.
    overreaches_made: u32,
    /// This node's own id, recorded at start so properties can identify it.
    me: u64,
    /// Text this node has contributed locally, for convergence assertions.
    contributed: Vec<String>,
    /// The modelled `iroh-docs` replica: every entry this node can see.
    ///
    /// Deliberately separate from [`WorkspaceState`], which holds only what this
    /// node could *decrypt*. Keeping the two apart is what lets a property
    /// distinguish "cannot read the content" from "cannot even tell the content
    /// exists" — and a revoked member is supposed to be denied both.
    index: BTreeMap<StorageKey, EntryMeta>,
    /// The payloads behind [`Self::index`] — what this node could serve a peer.
    ///
    /// # Why the harness has to hold these at all
    ///
    /// Without them the simulated data plane is **pure broadcast**: an entry that
    /// misses a peer is gone unless its author encrypts and announces it again.
    /// `iroh-docs` does not work that way. It reconciles key ranges between any
    /// two peers, so a node that lacks an entry gets it from whoever has it, and
    /// the blob follows by hash — no republish, and not necessarily from the
    /// author. Modelling only the broadcast makes the harness strictly more
    /// fragile than production, and every failure that follows is an artefact of
    /// the model rather than a defect in the library. It is the same trap
    /// [`Msg::Log`] exists to avoid on the control plane.
    ///
    /// This became load-bearing with delta publishing. Before it, a republish
    /// re-exported the whole history, so re-announcing *was* accidentally a
    /// repair for a lost entry; now a re-announcement of an unchanged document
    /// emits nothing at all, and reconciliation is the only thing that carries a
    /// lost entry. See [`WorkspaceNode::reconcile`].
    ///
    /// Kept beside [`Self::index`] rather than inside it because `EntryMeta` is
    /// the *metadata* view properties assert over, and it is `Copy`.
    replica: BTreeMap<StorageKey, (NodeId, Chunk)>,
    /// Sealed asset segments this node holds, by blinded key.
    ///
    /// Kept apart from [`Self::replica`] because they survive a namespace
    /// rotation. That is the point of the rotation change: an asset segment is
    /// immutable ciphertext, so it is re-*indexed* into the new replica rather
    /// than re-encrypted, and a model that dropped it on adoption would be
    /// modelling the behaviour that change removed.
    segments: BTreeMap<StorageKey, Vec<u8>>,
    /// The asset as this node last managed to reassemble it.
    ///
    /// Cached because reading it needs `&mut` — unwrapping the content key goes
    /// through the CGKA, which caches derived keys — and a property is handed a
    /// shared reference. Refreshed whenever new segments or key material could
    /// have changed the answer, which models an application opening the file.
    asset_view: Option<Vec<u8>>,
    /// The modelled overlay: peers this node currently accepts messages from.
    ///
    /// Recomputed from [`WorkspaceState::roster`] — the same derivation the real
    /// `RosterGuard` is fed — and mapped back to node ids through
    /// [`node_of_endpoint`]. Messages from anyone else are dropped on receipt,
    /// before they are observed, which models the *effect* of refusing the
    /// connection. The real-QUIC suite is what proves the guard is actually
    /// wired to `iroh`; this proves the membership rule feeding it is right.
    roster: BTreeSet<NodeId>,
    /// Peers accepted unconditionally, to break the bootstrap circle.
    ///
    /// A joiner cannot derive a roster until a manifest reaches it, and no
    /// manifest can reach it until it accepts something — so it accepts its
    /// inviter on faith, exactly as `Workspace::join` seeds the real roster from
    /// `Invite.inviter`. Deliberately one peer, and never pruned.
    bootstrap: BTreeSet<NodeId>,
    /// Which generation of the replicated index this node is syncing.
    ///
    /// Mirrors what the core decided, so that outgoing entries are stamped and
    /// incoming ones filtered. A removed device never receives the capability
    /// for the next generation, so it stays here while the group moves on —
    /// which is what makes its index stop growing.
    namespace: NamespaceEpoch,
    /// Control-plane operations seen, whether or not they applied.
    observed_ops: u64,
    /// When each distinct repair request was last put on the wire.
    ///
    /// The rate limiter the core cannot own, because the core has no clock.
    /// A `BTreeMap` rather than a `HashMap` so that nothing about this node's
    /// behaviour can depend on hash iteration order, which is the kind of
    /// nondeterminism `the_simulation_is_reproducible` exists to catch.
    repair_sent: BTreeMap<(RepairTarget, EpochId), Duration>,
    /// Client operations that arrived before this node finished joining.
    ///
    /// Held rather than failed. The harness allows one operation in flight per
    /// process, so failing them during onboarding would burn the workload before
    /// any node could apply anything — and a real client queues an edit made
    /// while it is still connecting rather than discarding it.
    deferred_ops: Vec<(OpToken, WsOp)>,
    /// Proposals this node has already cast an approval for.
    ///
    /// Local bookkeeping only. Re-approving is idempotent on the certificate
    /// digest, but each round would mint a *fresh* nonce and so a fresh
    /// certificate — filling the store with duplicates that all resolve to one
    /// approver and make `certificates()` grow without bound.
    approved: BTreeSet<[u8; 32]>,
    /// Whether this node has walked away from the workspace.
    ///
    /// Recorded rather than inferred from [`Scenario::LEAVE`], because the
    /// constant is true from `on_start` and the departure happens seconds later.
    /// A property about what a departure changes is vacuous before it has
    /// happened, so it asserts on this and not on the scenario.
    left: bool,
    /// Whether this node has redeemed a ticket issued to somebody else.
    ///
    /// Only ever true for [`Scenario::INVITE_THIEF`]. Recorded rather than
    /// inferred from the scenario constant because it marks the moment the leak
    /// *landed*: before it, the thief is indistinguishable from an outsider, and
    /// a property that could not tell the two apart would pass in a run where the
    /// ticket never arrived.
    stolen_invite: bool,
    /// This node's simulated disk, or `None` if it has never written one.
    ///
    /// The one field a reboot deliberately keeps. Everything else a restarted
    /// node has, it has because it read it back from here.
    disk: Option<Disk>,
    /// Whether [`Node::on_start`] has already run once on this node.
    ///
    /// propsim calls `on_start` a second time on the *same object* when a
    /// crashed node restarts — it does not rebuild the node, and there is no
    /// `on_crash` hook — so this flag is the only way a node can tell a restart
    /// from a first start, and authoring the amnesia is entirely up to it.
    started: bool,
    /// How many times this node has restarted.
    ///
    /// Observable so that a `sometimes` property can prove a run actually
    /// crashed somebody. Swarm faults omit each enabled kind with probability
    /// one half per seed, so without this guard the whole restart suite could
    /// pass on seeds where nothing ever went down.
    reboots: u32,
    /// How many times this node has founded or joined the workspace.
    ///
    /// Must never exceed one. It is the guard against the harness quietly
    /// degenerating into what it replaced: `on_start` re-running `found` would
    /// fork the group under the founder, and re-running the join handshake would
    /// make "a restart" mean "a re-invitation" — under which every convergence
    /// property below would still pass while testing nothing about persistence.
    initialisations: u32,
    _scenario: PhantomData<S>,
}

/// What a simulated node keeps across a crash.
///
/// The modelled filesystem. Its contents mirror what a real persistent node
/// writes: [`WorkspaceState::export`] bytes plus the facade-level state that
/// lives outside the core — here, the modelled `iroh-docs` replica and the
/// bookkeeping a property reads.
///
/// Written at the same instant the real one is: **before** a client operation is
/// acknowledged (see [`WorkspaceNode::apply_op`]), which is what makes "an
/// acknowledged write survives a restart" a claim the harness can actually
/// falsify rather than one it assumes.
#[derive(Clone, Debug)]
struct Disk {
    /// The core snapshot.
    state: Vec<u8>,
    /// The modelled replica, which is redb-backed in production and so durable.
    index: BTreeMap<StorageKey, EntryMeta>,
    /// The payloads behind [`Self::index`], durable for the same reason: in
    /// production they are blobs on disk.
    replica: BTreeMap<StorageKey, (NodeId, Chunk)>,
    /// Sealed asset segments, durable for the same reason.
    segments: BTreeMap<StorageKey, Vec<u8>>,
    /// Peers accepted on faith. Durable because the real bootstrap entry comes
    /// from the invite, and a restarting node has no invite to re-read.
    bootstrap: BTreeSet<NodeId>,
    /// Text this node acknowledged writing.
    ///
    /// Durable because it is the *record* of acknowledgement: a property that
    /// compared a restarted node's text against a list of writes it never
    /// promised to keep would be asserting something the library never claimed.
    contributed: Vec<String>,
}

impl<S: Scenario> std::fmt::Debug for WorkspaceNode<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceNode")
            .field("joined", &self.state.is_some())
            .field("edits_made", &self.edits_made)
            .field("buffered", &self.inbox.len())
            .finish_non_exhaustive()
    }
}

/// The workspace's tree id, identical on every node.
fn tree_id() -> TreeId {
    TreeId::from(MemorySigner::generate(&mut ChaCha20Rng::seed_from_u64(0xFEED)).verifying_key())
}

/// The simulated wall clock every node reads, from propsim's virtual time.
///
/// The core takes the instant of an event as a parameter rather than reading a
/// clock, which is what lets this harness date a version history: virtual time is
/// a pure function of the seed, so two runs of one seed produce byte-identical
/// timestamps and a property may assert on them.
///
/// Offset from [`SIM_EPOCH`] rather than used raw so the dates a test prints are
/// plausible ones. Every node reads the same virtual clock, which makes this
/// harness *kinder* than production on one point worth remembering: a real group
/// has skewed clocks, and a timestamp is a claim for that reason.
fn wall_clock(elapsed: Duration) -> UnixSeconds {
    UnixSeconds::new(SIM_EPOCH.saturating_add(i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)))
}

/// The wall-clock instant a simulated run starts at: 2026-01-01T00:00:00Z.
const SIM_EPOCH: i64 = 1_767_225_600;

/// Per-node deterministic randomness.
///
/// Derived from the node id rather than drawn from `cx.rng()` so that a node's
/// key material is a pure function of its identity; the simulator's own RNG
/// still governs message timing and delivery.
fn node_rng(me: NodeId, salt: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(me.0.wrapping_mul(0x9E37_79B9).wrapping_add(salt))
}

/// The blinded key a document is stored under, as every node computes it.
#[must_use]
pub fn doc_key(doc: DocumentUuid) -> StorageKey {
    WorkspaceSecret::new(workspace_secret_bytes()).storage_key(doc)
}

/// The blinding secret, fixed so every simulated node agrees on storage keys.
fn workspace_secret_bytes() -> [u8; 32] {
    [0x5Au8; 32]
}

/// Tag distinguishing a simulated transport address from anything else.
///
/// Present so that a stray 32-byte value cannot be mistaken for an address of
/// node zero, which is the founder and the most damaging one to impersonate.
const ENDPOINT_TAG: [u8; 8] = *b"propsim\0";

/// The transport address a simulated node publishes.
///
/// Stands in for an `iroh` `EndpointId`. It is derived from — and invertible
/// back to — the node id, which is what lets the modelled overlay check the
/// *real* roster [`WorkspaceState::roster`] computes, rather than a parallel
/// membership model maintained alongside it. Deriving a roster twice by two
/// different rules is how a simulation ends up proving something the production
/// code does not do.
#[must_use]
pub fn endpoint_of(node: NodeId) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&ENDPOINT_TAG);
    bytes[8..16].copy_from_slice(&node.0.to_le_bytes());
    bytes
}

/// The capability a node mints for a rotation.
///
/// Production hands back an `iroh-docs` ticket; here the bytes only have to be
/// *distinguishable*, because what the simulation models is which generation a
/// node is on rather than how a replica is addressed. Derived from the minting
/// node as well as the epoch, so that two admins rotating concurrently produce
/// different digests — which is precisely the case the `(epoch, digest)`
/// tie-break exists to settle.
#[must_use]
fn minted_ticket(minter: NodeId, epoch: u32) -> Vec<u8> {
    let mut ticket = b"propsim-namespace".to_vec();
    ticket.extend_from_slice(&minter.0.to_le_bytes());
    ticket.extend_from_slice(&epoch.to_le_bytes());
    ticket
}

/// Which node published this transport address, if any.
///
/// Returns `None` for anything this simulation did not mint, so a malformed or
/// forged address is treated as "not on the roster" rather than resolving to
/// some node by accident.
#[must_use]
fn node_of_endpoint(bytes: &[u8; 32]) -> Option<NodeId> {
    if bytes[..8] != ENDPOINT_TAG || bytes[16..] != [0u8; 16] {
        return None;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[8..16]);
    Some(NodeId(u64::from_le_bytes(id)))
}

/// The CGKA identity node `id` will hold, as raw bytes.
///
/// Every node's key material is a pure function of its simulator id, which is
/// what lets the founder name a revocation victim without a lookup. Exposed so a
/// property can compute the set of legitimate identities **without depending on
/// which nodes have finished joining** — a set derived from `has_joined()` shrinks
/// during onboarding, and a property built on it reports a failure the moment the
/// founder certifies a node that has not yet replayed its own `Welcome`.
#[must_use]
pub fn member_bytes_of(id: u64) -> [u8; 32] {
    MemberId::from(MemorySigner::generate(&mut node_rng(NodeId(id), 0xA1)).verifying_key())
        .to_bytes()
}

impl<S: Scenario> WorkspaceNode<S> {
    /// This node's simulator id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.me
    }

    /// Whether this node is the one the scenario revokes.
    #[must_use]
    pub fn is_revocation_target(&self) -> bool {
        S::REVOKE == Some(self.me)
    }

    /// Whether this node has joined the group.
    #[must_use]
    pub fn has_joined(&self) -> bool {
        self.state.is_some()
    }

    /// Whether this node is the one the scenario has steal a ticket.
    #[must_use]
    pub fn is_invite_thief(&self) -> bool {
        S::INVITE_THIEF == Some(self.me)
    }

    /// How many distinct admins an action currently needs here.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.state
            .as_ref()
            .map_or(1, |state| state.capabilities().threshold())
    }

    /// How many distinct admin users have approved this proposal here.
    #[must_use]
    pub fn approvals_for(&self, proposal: &[u8; 32]) -> usize {
        self.state
            .as_ref()
            .map_or(0, |state| state.capabilities().approver_count(proposal))
    }

    /// Every proposal this node knows of, with how close each is to its quorum.
    #[must_use]
    pub fn proposals(&self) -> Vec<ProposalStatus> {
        self.state
            .as_ref()
            .map_or_else(Vec::new, |state| state.capabilities().proposals())
    }

    /// Whether this node has left the workspace of its own accord.
    #[must_use]
    pub fn has_left(&self) -> bool {
        self.left
    }

    /// Whether this node is the one the scenario has walk away.
    #[must_use]
    pub fn is_departing(&self) -> bool {
        S::LEAVE == Some(self.me)
    }

    /// How many times this node has restarted from its simulated disk.
    ///
    /// Read by the `sometimes` guard that proves a run actually crashed
    /// somebody: swarm faults omit each enabled kind with probability one half
    /// per seed, so a restart suite with no such guard can pass entirely on
    /// seeds where nothing ever went down.
    #[must_use]
    pub fn reboots(&self) -> u32 {
        self.reboots
    }

    /// How many times this node has founded or joined the workspace.
    ///
    /// Must never exceed one, and the property asserting so is what stops the
    /// restart harness degenerating into a re-invitation test — see
    /// [`WorkspaceNode::reboot`] for the two ways that happens.
    #[must_use]
    pub fn initialisations(&self) -> u32 {
        self.initialisations
    }

    /// Whether this node holds a simulated disk it could restart from.
    ///
    /// The counterweight to [`Self::reboots`]: a run in which every crash hit a
    /// node that had never written anything would satisfy "somebody restarted"
    /// while proving nothing about resumption.
    #[must_use]
    pub fn has_disk(&self) -> bool {
        self.disk.is_some()
    }

    /// Whether a stolen ticket has actually reached this node yet.
    ///
    /// Distinct from [`Self::is_invite_thief`], which is true from `on_start`.
    /// A property about what a stolen ticket buys is vacuous until the theft has
    /// happened, so it asserts on this and not on the scenario constant.
    #[must_use]
    pub fn holds_stolen_invite(&self) -> bool {
        self.stolen_invite
    }

    /// The default document's text as this node currently sees it.
    #[must_use]
    pub fn document_text(&self) -> String {
        self.document_text_of(DOC)
    }

    /// One document's text as this node currently sees it.
    #[must_use]
    pub fn document_text_of(&self, doc: DocumentUuid) -> String {
        self.state
            .as_ref()
            .map_or_else(String::new, |s| s.document_text(doc))
    }

    /// Every document's text, in pool order — the whole visible state.
    #[must_use]
    pub fn all_text(&self) -> Vec<String> {
        DOCS.iter().map(|d| self.document_text_of(*d)).collect()
    }

    /// Chunks parked awaiting keys or CRDT dependencies.
    #[must_use]
    pub fn pending_chunks(&self) -> usize {
        self.state.as_ref().map_or(0, WorkspaceState::pending_len)
    }

    /// Chunks dropped because the pending budget was exhausted.
    #[must_use]
    pub fn evicted_chunks(&self) -> u64 {
        self.state
            .as_ref()
            .map_or(0, WorkspaceState::evicted_chunks)
    }

    /// Control operations parked awaiting their predecessors.
    #[must_use]
    pub fn parked_ops(&self) -> usize {
        self.state.as_ref().map_or(0, WorkspaceState::parked_ops)
    }

    /// Chunks and control operations discarded because a queue overflowed.
    ///
    /// The queue limits exist for hostile traffic. A well-behaved run must
    /// never reach them, so a property asserting this stays zero is really a
    /// guard against the eviction logic firing when it should not — which
    /// would show up as silent data loss rather than as a failure.
    #[must_use]
    pub fn evictions(&self) -> u64 {
        self.state
            .as_ref()
            .map_or(0, |s| s.evicted_chunks() + s.evicted_ops())
    }

    /// Chunks dropped because their epoch predates this node's membership.
    ///
    /// Expected to be non-zero for a node admitted after content existed: that
    /// is forward secrecy, and each one is answered with a repair request. What
    /// would be a defect is this climbing while [`Self::repairs_answered`] stays
    /// flat across the group — that is a peer asking and nobody answering.
    #[must_use]
    pub fn unreadable_chunks(&self) -> u64 {
        self.state
            .as_ref()
            .map_or(0, WorkspaceState::unreadable_chunks)
    }

    /// Chunks whose key was derived and whose authentication then failed.
    #[must_use]
    pub fn corrupt_chunks(&self) -> u64 {
        self.state
            .as_ref()
            .map_or(0, WorkspaceState::corrupt_chunks)
    }

    /// Repair requests this node answered by minting a fresh epoch.
    ///
    /// One tree operation each, so this is what a bounded-cost property counts:
    /// repair must scale with the number of peers that are actually stuck, not
    /// with how many anti-entropy rounds have gone by.
    #[must_use]
    pub fn repairs_answered(&self) -> u64 {
        self.state
            .as_ref()
            .map_or(0, WorkspaceState::repairs_answered)
    }

    /// The text this node has contributed locally.
    #[must_use]
    pub fn contributed(&self) -> &[String] {
        &self.contributed
    }

    /// Every blinded key this node has seen an entry under.
    ///
    /// This is *visibility*, not readability. A node appears here for content it
    /// could never decrypt, which is the point: "cannot read the file" and
    /// "cannot tell the file exists" are different guarantees, and a removed
    /// member is meant to be denied both.
    #[must_use]
    pub fn observed_keys(&self) -> Vec<StorageKey> {
        self.index.keys().copied().collect()
    }

    /// How many entries this node can see in the modelled replica.
    #[must_use]
    pub fn index_len(&self) -> usize {
        self.index.len()
    }

    /// What this node can observe about one entry, if it has seen it.
    #[must_use]
    pub fn entry(&self, key: &StorageKey) -> Option<EntryMeta> {
        self.index.get(key).copied()
    }

    /// How many control-plane operations this node has seen.
    ///
    /// Counts arrivals, not applications: a revoked member that still receives
    /// broadcasts is still learning who joined and who left, whether or not it
    /// can do anything with them.
    #[must_use]
    pub fn observed_ops(&self) -> u64 {
        self.observed_ops
    }

    /// How many members this node believes are in the group.
    ///
    /// beekem's tree count, and **not** the one to assert a membership change
    /// over: it is read without replaying the operations graph, so between
    /// merging a concurrent removal and the next replay it still counts the
    /// removed member. Use [`Self::current_member_count`] for that. See
    /// `beekem_group_size_disagrees_with_current_members` in
    /// `iroh-beekem-core/tests/beekem_loop.rs`.
    #[must_use]
    pub fn group_size(&self) -> u32 {
        self.state.as_ref().map_or(0, WorkspaceState::group_size)
    }

    /// How many members this node counts, from the set this crate maintains.
    ///
    /// Updated by `merge` the moment a removal is applied, so unlike
    /// [`Self::group_size`] it is never behind the operations it has accepted.
    #[must_use]
    pub fn current_member_count(&self) -> usize {
        self.state
            .as_ref()
            .map_or(0, WorkspaceState::current_member_count)
    }

    /// Which generation of the replicated index this node is syncing.
    ///
    /// A device removed at generation *n* never receives the capability for
    /// *n+1*, so this is how "the group moved on without you" is observed.
    #[must_use]
    pub fn namespace(&self) -> NamespaceEpoch {
        self.namespace
    }

    /// The role this node believes `user` holds, per its capability closure.
    ///
    /// `None` means no valid chain grants that user anything — which is the
    /// answer for a user whose certificates have not arrived *and* for one whose
    /// only certificate was self-issued. The two are indistinguishable from
    /// outside and should be: neither grants anything.
    #[must_use]
    pub fn role_of(&self, user: [u8; 32]) -> Option<Role> {
        self.state
            .as_ref()
            .and_then(|state| state.capabilities().role_of(&user))
    }

    /// How many users this node believes hold an administrative role.
    ///
    /// The single number a self-promotion would move, which is what makes it the
    /// right thing for a cross-cutting property to watch: it needs no knowledge of
    /// who the attacker is.
    #[must_use]
    pub fn admin_count(&self) -> usize {
        self.state
            .as_ref()
            .map_or(0, |state| state.capabilities().admin_count())
    }

    /// How many devices this node believes hold a valid binding.
    ///
    /// Grows only when somebody authorised to bind a device did so — which
    /// includes a member enrolling further devices of its *own* user, so this is
    /// not by itself a measure of whether an attack landed. See
    /// [`Self::certified_users`] for the question that is.
    #[must_use]
    pub fn certified_device_count(&self) -> usize {
        self.state
            .as_ref()
            .map_or(0, |state| state.capabilities().certified_devices().count())
    }

    /// Every user that some certified device resolves to, in ascending order.
    ///
    /// The right observable for "did an unauthorised binding land". A member may
    /// legitimately enrol further devices of its own user, so the device *count*
    /// grows under attack without anything being wrong; what must never happen is
    /// a device resolving to a user nobody admitted, or to somebody else's.
    #[must_use]
    pub fn certified_users(&self) -> Vec<[u8; 32]> {
        let Some(state) = self.state.as_ref() else {
            return Vec::new();
        };
        let mut out: Vec<[u8; 32]> = state
            .capabilities()
            .certified_devices()
            .filter_map(|device| state.capabilities().user_of(&device))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// This node's own member id, as raw bytes.
    ///
    /// Zero before the node has joined, which no property should be reading.
    #[must_use]
    pub fn member_bytes(&self) -> [u8; 32] {
        self.state
            .as_ref()
            .map_or([0u8; 32], |state| state.member_id().to_bytes())
    }

    /// Whether this node has moved off the founding namespace.
    ///
    /// A device removed before a rotation never receives the capability for it,
    /// so this is false for the victim and true for everyone else — which is
    /// what makes "the group moved on without you" a single readable check.
    #[must_use]
    pub fn has_rotated(&self) -> bool {
        self.namespace != NamespaceEpoch::INITIAL
    }

    /// The peers this node currently accepts messages from, bootstrap included.
    ///
    /// Sorted, because it comes from a `BTreeSet`, so two nodes with the same
    /// membership produce identical vectors and a convergence property can
    /// compare them directly.
    #[must_use]
    pub fn roster(&self) -> Vec<NodeId> {
        let mut out: Vec<NodeId> = self.roster.union(&self.bootstrap).copied().collect();
        out.sort_unstable();
        out
    }

    /// Whether this node currently accepts messages from `peer`.
    #[must_use]
    pub fn is_on_roster(&self, peer: NodeId) -> bool {
        self.roster.contains(&peer) || self.bootstrap.contains(&peer)
    }

    /// The peers this node derived from workspace membership alone.
    ///
    /// Excludes the bootstrap exception, so a property can assert that eviction
    /// reaches the *derived* set even while a stale bootstrap entry lingers.
    #[must_use]
    pub fn derived_roster(&self) -> Vec<NodeId> {
        let mut out: Vec<NodeId> = self.roster.iter().copied().collect();
        out.sort_unstable();
        out
    }

    /// Announce this node's leaf key so the founder can admit it.
    fn send_hello(&self, cx: &mut dyn Ctx<Self>) {
        let (Some(signer), Some(share_secret)) = (self.signer.as_ref(), self.share_secret) else {
            return;
        };
        cx.broadcast(Msg::Hello {
            member: MemberId::from(signer.verifying_key()),
            share_key: share_secret.share_key(),
        });
    }

    /// Broadcast this node's whole operation log, so peers can fill in gaps.
    ///
    /// Bounded by nothing here because the simulated log is tiny; the real
    /// `Workspace` caps the receive side with `MAX_LOG_OPS` and rate-limits the
    /// send side with a per-peer cooldown, both of which are transport concerns
    /// rather than protocol ones.
    fn send_log(&mut self, cx: &mut dyn Ctx<Self>) {
        let Some(state) = self.state.as_ref() else {
            return;
        };
        let Ok(ops) = state.op_log() else {
            return;
        };
        let certs = state.capabilities().certificates();
        if !ops.is_empty() {
            cx.broadcast(Msg::Log { ops, certs });
        }
    }

    /// Merge every operation in a peer's repair broadcast.
    ///
    /// Counted as observed one operation at a time, exactly like [`Msg::Op`]:
    /// what a node saw on the control plane is the question the revocation
    /// properties ask, and a repair carrying ten operations is ten things seen.
    fn on_log(
        &mut self,
        ops: Vec<Signed<CgkaOperation>>,
        certs: Vec<Certificate>,
        cx: &mut dyn Ctx<Self>,
    ) {
        // Certificates strictly first: they authorise the `Add`s in the log, so
        // replaying the operations against an empty closure would refuse the
        // history this message exists to hand over.
        self.drive(Event::CertsArrived(certs), cx, 5);
        for op in ops {
            self.observed_ops += 1;
            self.drive(Event::ControlOp(AuthorizedOp::bare(Arc::new(op))), cx, 4);
        }
        self.flush_deferred_ops(cx);
    }

    /// Answer a peer that says it can never decrypt what we publish.
    ///
    /// The salt is derived from the epoch the requester named rather than being
    /// a constant: `drive` seeds a fresh RNG per call, and two repairs answered
    /// with the same salt would re-key with the identical random stream — which
    /// would mint the *same* epoch twice and leave the second requester exactly
    /// as stuck as it was.
    fn on_repair(
        &mut self,
        member: MemberId,
        target: RepairTarget,
        epoch: EpochId,
        cx: &mut dyn Ctx<Self>,
    ) {
        let salt = u64::from_le_bytes(epoch.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
        self.drive(
            Event::RepairRequested {
                requester: member,
                target,
                epoch,
            },
            cx,
            salt,
        );
    }

    /// Recompute the modelled overlay from the workspace state.
    ///
    /// Called after every drive rather than only after membership events: the
    /// roster derives from the manifest, and a manifest arrives as an ordinary
    /// chunk, so there is no event this node can look at locally that reliably
    /// says "membership just moved". The recompute is a scan of the device list,
    /// which in a simulation of a handful of nodes is free.
    fn refresh_roster(&mut self) {
        let Some(state) = self.state.as_ref() else {
            return;
        };
        self.roster = state.roster().iter().filter_map(node_of_endpoint).collect();
    }

    /// Whether a message from `from` should be accepted at all.
    ///
    /// The join handshake is exempt, and only the join handshake. [`Msg::Hello`]
    /// carries a public leaf key and is broadcast, so accepting one from a
    /// stranger reveals nothing; [`Msg::Welcome`] carries the workspace secret
    /// but is *unicast* to a peer the sender chose to admit, so a node only ever
    /// receives one it was meant to have. Everything else — the control plane
    /// and the index — is gated.
    fn admits(&self, from: NodeId, msg: &Msg) -> bool {
        match msg {
            Msg::Hello { .. } | Msg::Welcome { .. } => true,
            Msg::Op { .. }
            | Msg::Log { .. }
            | Msg::Certs(_)
            | Msg::Entry { .. }
            | Msg::Segment { .. }
            | Msg::Repair { .. }
            | Msg::Namespace { .. } => {
                self.roster.contains(&from) || self.bootstrap.contains(&from)
            }
        }
    }

    /// Record an entry in the modelled replica.
    ///
    /// Recorded whether or not it can ever be decrypted: seeing an entry is a
    /// separate capability from reading it, and conflating the two is what made
    /// "a removed member should not see files" impossible to state.
    fn observe(&mut self, key: StorageKey, author: NodeId, chunk: &Chunk) {
        self.index.insert(
            key,
            EntryMeta {
                author,
                size: chunk.ciphertext.len(),
            },
        );
        // The payload as well as the fact of it, so this node can hand the entry
        // on to a peer that missed it — which is what `iroh-docs` reconciliation
        // does and what [`Self::reconcile`] models.
        self.replica.insert(key, (author, chunk.clone()));
    }

    /// Re-offer every entry this node holds, as range reconciliation would.
    ///
    /// The counterpart to [`Self::republish`], and a different thing entirely.
    /// `republish` asks the *core* to produce fresh chunks for content it has not
    /// announced; this re-sends chunks that already exist, unchanged, from
    /// whichever node happens to hold them. Only the second recovers an entry
    /// lost in transit, because the author has nothing left to say about a
    /// document it has fully published.
    ///
    /// The recorded author travels with the entry rather than being replaced by
    /// this node's id: `iroh-docs` reconciliation preserves authorship, and the
    /// receiver's `author_may_write` check is meaningless if a relaying peer can
    /// launder an entry into its own name.
    fn reconcile(&mut self, cx: &mut dyn Ctx<Self>) {
        let namespace = self.namespace;
        for (key, (author, chunk)) in self.replica.clone() {
            cx.broadcast(Msg::Entry {
                namespace,
                key,
                author,
                chunk: Box::new(chunk),
            });
        }
        // Asset segments too, and under the *current* namespace whatever
        // namespace they were written in: that is precisely what re-indexing
        // does — the same ciphertext, announced in the replica the group has
        // moved to, with no re-encryption.
        let me = self.me;
        for (key, bytes) in self.segments.clone() {
            cx.broadcast(Msg::Segment {
                namespace,
                key,
                author: NodeId(me),
                bytes,
            });
        }
    }

    /// Record an asset segment this node can now serve.
    fn on_segment(&mut self, namespace: NamespaceEpoch, key: StorageKey, bytes: Vec<u8>) {
        // Dropped before it is recorded, for the same reason an entry from
        // another namespace is: a peer that holds no capability for a replica
        // does not merely decline to read it, it never hears about it.
        if namespace != self.namespace {
            return;
        }
        self.segments.insert(key, bytes);
        self.refresh_asset_view();
    }

    /// Handle an arriving index entry.
    ///
    /// The wire carries a blinded key and nothing else, so this has to work out
    /// what the entry *is* the same way the real `ingest_all` does: by comparing
    /// against the keys it can derive. An entry under a key this node cannot
    /// place is still recorded — it can see that something exists — but there is
    /// nothing to apply it to.
    fn on_entry(
        &mut self,
        namespace: NamespaceEpoch,
        key: StorageKey,
        author: NodeId,
        chunk: Box<Chunk>,
        cx: &mut dyn Ctx<Self>,
        salt: u64,
    ) {
        // Dropped before it is observed, not merely before it is applied.
        // `iroh-docs` reconciles within a namespace, so an entry in a replica
        // this node holds no capability for is not something it declines to
        // read — it is something it never hears about. Recording it and then
        // ignoring it would hand a removed device exactly the metadata the
        // rotation exists to take away: that the entry exists, how big it is,
        // and who wrote it.
        if namespace != self.namespace {
            return;
        }
        self.observe(key, author, &chunk);
        let secret = WorkspaceSecret::new(workspace_secret_bytes());
        if key == secret.manifest_key() {
            self.drive(Event::ManifestArrived { chunk }, cx, salt);
            return;
        }
        // Every document in the pool, not just the first. Matching only one key
        // would leave entries for the others sitting in the index, seen but
        // never applied — which looks exactly like a convergence bug and is
        // really a receiver that never tried.
        if let Some(doc) = DOCS.into_iter().find(|d| key == secret.storage_key(*d)) {
            self.drive(Event::ChunkArrived { doc, chunk }, cx, salt);
        }
    }

    /// Apply one client operation to the local replica.
    fn apply_op(&mut self, op: &WsOp, cx: &mut dyn Ctx<Self>) -> WsResp {
        // Local-first: a write takes effect on the local replica immediately, so
        // it completes synchronously. That is the semantics, not a shortcut —
        // there is no acknowledgement to wait for, and convergence is checked by
        // properties over the world rather than by an oracle waiting on a quorum.
        let doc = DOCS[op.doc_index() % DOCS.len()];
        let event = match op {
            WsOp::Read { .. } => return WsResp::Text(self.document_text_of(doc)),
            WsOp::Append { text, .. } => {
                self.contributed.push(text.clone());
                Event::LocalEdit {
                    doc,
                    text: text.clone(),
                }
            }
            // Deliberately *not* recorded as contributed: a whole-document write
            // or a deletion can remove text an earlier append added, so counting
            // it as a contribution would make the "own edits survive" property
            // assert something false.
            WsOp::Write { text, .. } => Event::WriteFile {
                doc,
                text: text.clone(),
            },
            WsOp::Insert { pos, text, .. } => Event::InsertText {
                doc,
                pos: *pos,
                text: text.clone(),
            },
            WsOp::Remove { pos, len, .. } => Event::RemoveText {
                doc,
                pos: *pos,
                len: *len,
            },
            // Deliberately *not* recorded as contributed, for the same reason a
            // whole-document write is not: a revert can remove text an earlier
            // append added, so counting it would make the "own edits survive"
            // property assert something false.
            WsOp::Revert { back, .. } => {
                let versions = self
                    .state
                    .as_ref()
                    .map(|state| state.document_versions(doc))
                    .unwrap_or_default();
                // Clamped rather than refused, exactly as a text offset is: the
                // workload names a step back without knowing how much history
                // this node holds, and on a partitioned node that is less than
                // the author of the edits has.
                let Some(target) = versions
                    .len()
                    .checked_sub(1 + *back)
                    .and_then(|i| versions.get(i))
                else {
                    // Nothing to revert to yet. A no-op rather than a failure,
                    // since a node that has merged one change has no earlier
                    // state to name.
                    return WsResp::Applied;
                };
                Event::RevertDocument {
                    doc,
                    to: target.id.clone(),
                }
            }
        };
        self.drive(event, cx, 11);
        WsResp::Applied
    }

    /// Arm this node's scenario timers.
    ///
    /// Shared by a first start and a restart so that a resumed node keeps
    /// participating: a restarted node that never re-armed `Tick::Resync` would
    /// go silent, and the convergence it then failed to reach would be an
    /// artefact of the harness rather than a fact about the protocol.
    ///
    /// The one-shot timers are re-armed too, and that is safe rather than
    /// merely convenient: a second `Tick::Revoke` removes a member who is
    /// already gone, which `on_remove_member` answers with no effects at all
    /// precisely so that repeating a removal cannot churn the group's namespace.
    fn arm_timers(&mut self, cx: &mut dyn Ctx<Self>) {
        let me = cx.me();
        cx.set_timer(Tick::Edit, FIRST_EDIT);
        cx.set_timer(Tick::Resync, RESYNC_INTERVAL);

        // The victim does not rotate: an operation it issued after its own
        // removal could never be applied by anyone, and would sit parked on
        // every honest node forever — a property failure about the scenario
        // rather than about the protocol.
        if S::ROTATE && !self.is_revocation_target() {
            cx.set_timer(Tick::Rotate, FIRST_ROTATE);
        }
        // The founder attaches, because it is the one node certain to hold a
        // writing role from the first instant.
        if S::ATTACH_ASSET && me.0 == FOUNDER {
            cx.set_timer(Tick::Attach, ATTACH_AT);
        }
        if me.0 == FOUNDER && S::REVOKE.is_some() {
            cx.set_timer(Tick::Revoke, REVOKE_AT);
        }
        if me.0 == FOUNDER && S::WRITE_AFTER_REVOKE {
            cx.set_timer(Tick::LateEdit, WRITE_AFTER_REVOKE_AT);
        }
        if S::INSIDER == Some(me.0) {
            // Deliberately *after* the first edits, so the insider is a settled
            // member of a working group before it misbehaves. An attack that ran
            // during onboarding would be indistinguishable from a joiner whose
            // certificates had not arrived, and the properties would not be able
            // to say which they had caught.
            cx.set_timer(Tick::Overreach, OVERREACH_INTERVAL * 3);
        } else {
            // Not the insider, or no insider in this scenario.
        }
        if S::FORGE && me.0 != FOUNDER {
            cx.set_timer(Tick::Forge, FORGE_INTERVAL);
        }
        if S::THRESHOLD > 1 {
            if me.0 == FOUNDER {
                cx.set_timer(Tick::AppointCoAdmin, APPOINT_CO_ADMIN_AT);
                cx.set_timer(Tick::ProposeRemoval, PROPOSE_AT);
            } else {
                // Only the founder drives the scenario's script; every admin
                // approves.
            }
            cx.set_timer(Tick::ApproveProposals, APPROVE_INTERVAL);
        } else {
            // The default threshold, under which no quorum machinery runs.
        }
        if S::LEAVE == Some(me.0) {
            // Late enough that the leaver has joined, edited and been seen by
            // everybody. A departure during onboarding would be
            // indistinguishable from a join that never completed, and the
            // properties could not say which they had observed.
            cx.set_timer(Tick::Leave, LEAVE_AT);
        } else {
            // Not the leaver, or nobody leaves in this scenario.
        }
    }

    /// The quorum half of [`Self::apply_timer`].
    ///
    /// Split out because the three arms below are one mechanism with its own
    /// script — appoint, propose, approve — and inlining them buried the
    /// scenario timers they sit among.
    fn apply_quorum_timer(&mut self, timer: &Tick, cx: &mut dyn Ctx<Self>) {
        match timer {
            Tick::AppointCoAdmin => {
                // The founder's exemption in action, and the only way a workspace
                // above a threshold of one can ever get a second admin: with one
                // admin no proposal could reach a quorum of two, so a group that
                // required one here would be deadlocked from birth.
                if let Some(co_admin) = S::CO_ADMIN {
                    let signer = MemorySigner::generate(&mut node_rng(NodeId(co_admin), 0xA1));
                    let user = MemberId::from(signer.verifying_key()).to_bytes();
                    self.drive(
                        Event::SetRole {
                            user,
                            role: Role::Admin,
                        },
                        cx,
                        0x9001,
                    );
                } else {
                    // No co-admin; nothing this workspace could ever authorise.
                }
            }
            Tick::ProposeRemoval => {
                if let Some(victim) = S::REVOKE {
                    let signer = MemorySigner::generate(&mut node_rng(NodeId(victim), 0xA1));
                    let member = MemberId::from(signer.verifying_key()).to_bytes();
                    self.propose_and_approve(AdminAction::RemoveMember { member }, cx, 0x9003);
                } else {
                    // Nothing to propose in this scenario.
                }
            }
            Tick::ApproveProposals => {
                // Every proposal this node has not already approved. Re-approving
                // is harmless — the certificate is idempotent on its digest — but
                // minting a fresh nonce each round would fill the store with
                // duplicates that all count once.
                let pending: Vec<[u8; 32]> = self.state.as_ref().map_or_else(Vec::new, |state| {
                    state
                        .capabilities()
                        .proposals()
                        .iter()
                        .filter(|status| !status.executable)
                        .map(|status| status.digest)
                        .filter(|digest| !self.approved.contains(digest))
                        .collect()
                });
                for (i, proposal) in pending.into_iter().enumerate() {
                    self.approved.insert(proposal);
                    self.drive(Event::Approve { proposal }, cx, 0x9100 + i as u64);
                }
                cx.set_timer(Tick::ApproveProposals, APPROVE_INTERVAL);
            }
            _ => {
                // Every other tick is handled by `apply_timer`; this arm exists
                // because a match must be total, not because it is reachable.
            }
        }
    }

    /// Propose an action and immediately approve it as this node.
    ///
    /// The proposer's own approval is not automatic in the core — proposing and
    /// approving are separate acts, and a node that wanted to abstain from its
    /// own proposal should be able to. The scenario chooses to approve, because a
    /// proposer that did not would need one more admin than the threshold names.
    fn propose_and_approve(&mut self, action: AdminAction, cx: &mut dyn Ctx<Self>, salt: u64) {
        let before: BTreeSet<[u8; 32]> = self.proposal_digests();
        self.drive(
            Event::Propose {
                action,
                expires: None,
            },
            cx,
            salt,
        );
        for (i, digest) in self
            .proposal_digests()
            .difference(&before)
            .copied()
            .collect::<Vec<_>>()
            .into_iter()
            .enumerate()
        {
            self.approved.insert(digest);
            self.drive(Event::Approve { proposal: digest }, cx, salt + 1 + i as u64);
        }
    }

    /// Every proposal digest this node currently holds.
    fn proposal_digests(&self) -> BTreeSet<[u8; 32]> {
        self.state.as_ref().map_or_else(BTreeSet::new, |state| {
            state
                .capabilities()
                .proposals()
                .iter()
                .map(|status| status.digest)
                .collect()
        })
    }

    /// Write this node's simulated disk.
    ///
    /// Called at the boundaries where a batch of work finishes — one per
    /// message, timer or client operation — which is the same rule
    /// `Workspace::persist` follows and for the same reason: a write per effect
    /// batch would cost O(documents) per arriving chunk.
    ///
    /// A node with no state writes nothing rather than writing an empty disk, so
    /// that a node crashed before it ever joined comes back as one that never
    /// joined rather than as one that joined and lost everything.
    fn save(&mut self) {
        let Some(state) = self.state.as_ref() else {
            return;
        };
        let Ok(bytes) = state.export() else {
            // Matching the facade, which logs and keeps running: a snapshot that
            // cannot be captured must not turn an applied local edit into a
            // failure the caller might retry.
            return;
        };
        self.disk = Some(Disk {
            state: bytes.to_vec(),
            index: self.index.clone(),
            replica: self.replica.clone(),
            segments: self.segments.clone(),
            bootstrap: self.bootstrap.clone(),
            contributed: self.contributed.clone(),
        });
    }

    /// Come back from a crash: discard everything volatile, then read the disk.
    ///
    /// **The discarding is the point.** propsim freezes a crashed node rather
    /// than destroying it — `dispatch_start` hands `on_start` the same object,
    /// with `state`, `index` and every counter intact — so a harness that only
    /// *restored* from disk would be testing a node that never forgot anything.
    /// Every convergence property would pass, and none of them would be about
    /// persistence. The wipe below is what makes the disk load-bearing.
    ///
    /// Kept across the boundary: the disk itself, this node's identity, and the
    /// per-scenario budget counters. Those last are harness bookkeeping — how
    /// much of the scripted workload has already run — not node state, and
    /// resetting them would let a restarted node edit, rotate and forge all over
    /// again, changing the scenario rather than restarting a participant.
    fn reboot(&mut self) {
        self.reboots += 1;

        // Volatile by nature: buffered and deferred work, the repair rate
        // limiter, and the derived roster. Each is rebuilt from what arrives
        // next, and none of it is anything a real node writes down.
        self.inbox.clear();
        self.deferred_ops.clear();
        self.repair_sent.clear();
        self.roster.clear();
        self.observed_ops = 0;

        // Volatile because the disk is authoritative for all three. Clearing
        // them first means a node whose disk is absent or unreadable comes back
        // genuinely empty rather than half-remembering.
        self.state = None;
        self.index.clear();
        self.replica.clear();
        self.segments.clear();
        self.bootstrap.clear();
        self.contributed.clear();
        self.namespace = NamespaceEpoch::INITIAL;

        let Some(disk) = self.disk.clone() else {
            // Crashed before it ever wrote anything. Correct, and not the same
            // as a fresh node: it does not re-run the join handshake, so it
            // stays out of the group. A node in this state is exactly what
            // `no_node_ever_initialises_more_than_once` is protecting.
            return;
        };
        let Ok(state) = WorkspaceState::import(&disk.state) else {
            return;
        };
        self.namespace = state.namespace();
        self.state = Some(state);
        self.index = disk.index;
        self.replica = disk.replica;
        self.segments = disk.segments;
        self.bootstrap = disk.bootstrap;
        self.contributed = disk.contributed;
        self.refresh_roster();
    }

    /// Attach the scenario's binary asset: seal its key, then its segments, then
    /// declare it.
    ///
    /// The same order the real `attach_file` uses, and for the same two reasons.
    /// Key material first, because a peer holding a segment and no key chunk
    /// cannot read it. The manifest entry last, because until it exists the
    /// asset is not in `files()` — so a run that stops halfway leaves segments
    /// nobody references rather than a truncated file somebody can open.
    fn attach_asset(&mut self, cx: &mut dyn Ctx<Self>) {
        let me = cx.me();
        let Some(state) = self.state.as_mut() else {
            return;
        };
        let mut rng = node_rng(me, 0xA55E7);
        let Ok((key, effects)) = state.seal_asset_key(ASSET_V1, &mut rng) else {
            return;
        };
        self.apply_effects(effects, cx, 0xA55E8);

        let plaintext = asset_plaintext();
        let size = plaintext.len() as u64;
        let segments = AssetMeta::segments_for(size, SIM_SEGMENT_BYTES);
        let secret = WorkspaceSecret::new(workspace_secret_bytes());
        let mut digest = ContentDigest::new();

        for index in 0..segments {
            let start = usize::try_from(index)
                .unwrap_or(usize::MAX)
                .saturating_mul(SIM_SEGMENT_BYTES as usize);
            let end = (start + SIM_SEGMENT_BYTES as usize).min(plaintext.len());
            let piece = &plaintext[start..end];
            digest.update(piece);
            let Ok(sealed) =
                seal_segment(&key, ASSET_V1, index, segments, SIM_SEGMENT_BYTES, piece)
            else {
                return;
            };
            let key_at = secret.asset_part_key(ASSET_V1, index);
            // Held locally as well as broadcast, exactly as a real node holds
            // what it wrote.
            self.segments.insert(key_at, sealed.clone());
            cx.broadcast(Msg::Segment {
                namespace: self.namespace,
                key: key_at,
                author: me,
                bytes: sealed,
            });
        }

        // The entry first, empty, then the version that declares the segments —
        // the order `Workspace::attach_file` uses, and it has to be this way
        // round: a version of a file the manifest has never heard of is refused,
        // which is what stops indexed segments existing with nothing naming them.
        self.drive(
            Event::UpsertFile {
                entry: FileEntry {
                    uuid: ASSET,
                    logical_path: "/asset.bin".into(),
                    mime_type: "application/octet-stream".into(),
                    asset: None,
                },
            },
            cx,
            0xA55E9,
        );
        let now = wall_clock(cx.now());
        let Some(state) = self.state.as_mut() else {
            return;
        };
        let mut rng = node_rng(me, 0xA55EA);
        let Ok(effects) = state.add_asset_version(
            ASSET,
            ASSET_V1,
            AssetMeta {
                size,
                segments,
                segment_bytes: SIM_SEGMENT_BYTES,
                content_hash: digest.finish(),
            },
            &mut rng,
            now,
        ) else {
            return;
        };
        self.apply_effects(effects, cx, 0xA55EB);
    }

    /// Reassemble the scenario's asset, or say why this node cannot.
    ///
    /// `None` covers every reason a node might not have it *yet* — no manifest
    /// entry, no key chunk, an unreachable epoch, a missing segment — because a
    /// property asking "can everyone read this" wants one answer, and the
    /// distinctions between the not-yet cases are the subject of the facade's own
    /// tests rather than of a convergence property.
    #[must_use]
    pub fn read_asset(&mut self) -> Option<Vec<u8>> {
        let secret = WorkspaceSecret::new(workspace_secret_bytes());
        // The current version by precedence, exactly as `Workspace::export_asset`
        // picks it — never "the last one recorded", which is a fact about merge
        // order rather than about what anybody attached.
        let current = self
            .state
            .as_ref()?
            .asset_versions(ASSET)
            .into_iter()
            .max_by_key(AssetVersion::precedence)?;
        let meta = current.meta;
        let content = current.content;

        let (_, key_chunk) = self.replica.get(&secret.asset_key_key(content))?.clone();
        let AssetKeyVerdict::Ready(key) = self.state.as_mut()?.open_asset_key(&key_chunk) else {
            return None;
        };

        let mut out = Vec::with_capacity(usize::try_from(meta.size).unwrap_or_default());
        for index in 0..meta.segments {
            let sealed = self.segments.get(&secret.asset_part_key(content, index))?;
            let piece = open_segment(
                &key,
                content,
                index,
                meta.segments,
                meta.segment_bytes,
                meta.payload_len(index),
                sealed,
            )
            .ok()?;
            out.extend_from_slice(&piece);
        }
        // The digest recorded in the manifest, checked over what was
        // reassembled — the manifest is writable by any member, and this is what
        // makes a rewritten `size` or `segments` a refusal rather than a
        // different file.
        if ContentDigest::new_over(&out) == meta.content_hash {
            Some(out)
        } else {
            None
        }
    }

    /// The asset as this node last reassembled it, if it could.
    #[must_use]
    pub fn read_asset_view(&self) -> Option<&[u8]> {
        self.asset_view.as_deref()
    }

    /// Re-attempt the reassembly, recording the result for a property to read.
    fn refresh_asset_view(&mut self) {
        if !S::ATTACH_ASSET {
            return;
        }
        if let Some(view) = self.read_asset() {
            self.asset_view = Some(view);
        } else {
            // Left as it was: an asset that has been read once does not stop
            // existing because a later attempt raced a rotation.
        }
    }

    /// Whether this node holds the asset's wrapped content key at all.
    ///
    /// The observable a removal property needs: a member locked out of an asset
    /// is one that cannot obtain the key, whatever it can still see of the
    /// segments.
    #[must_use]
    pub fn holds_asset_key(&self) -> bool {
        let secret = WorkspaceSecret::new(workspace_secret_bytes());
        self.replica.contains_key(&secret.asset_key_key(ASSET))
    }

    /// Re-announce every document this node holds.
    ///
    /// The simulator's counterpart to the facade's republish-on-neighbour-up.
    fn republish(&mut self, cx: &mut dyn Ctx<Self>) {
        // Range reconciliation first, and it is not interchangeable with the
        // resyncs below: those produce nothing for a document already fully
        // published, which is exactly the state a node is in when one of its
        // entries was lost in transit. See [`Self::reconcile`].
        self.reconcile(cx);
        for (i, doc) in DOCS.into_iter().enumerate() {
            self.drive(Event::Resync { doc }, cx, 9000 + i as u64);
        }
        // The manifest too, and it is not an afterthought: it is published only
        // when it *changes*, so a dropped manifest chunk has nothing behind it
        // to carry the content. Device records live there, and the roster is
        // derived from device records — omit this and a peer whose record was
        // lost in transit is refused forever, which looks like a membership bug
        // and is really a missing re-announcement.
        self.drive(Event::ResyncManifest, cx, 9100);
        self.drive(Event::ResyncNamespace, cx, 9101);
        // Certificates too, and for a sharper reason than either of the above: a
        // lost approval leaves a quorum that formed on one node and nowhere
        // else, so the action is performed there and refused everywhere.
        self.drive(Event::ResyncCertificates, cx, 9102);
    }

    /// Apply and complete everything queued while this node was still joining.
    fn flush_deferred_ops(&mut self, cx: &mut dyn Ctx<Self>) {
        if self.state.is_none() {
            return;
        }
        for (token, op) in std::mem::take(&mut self.deferred_ops) {
            let resp = self.apply_op(&op, cx);
            cx.complete_op(token, Completion::Ok(resp));
        }
    }

    /// Feed an event to the local state machine, gossiping whatever it emits.
    fn drive(&mut self, event: Event, cx: &mut dyn Ctx<Self>, salt: u64) {
        let me = cx.me();
        let now = wall_clock(cx.now());
        let Some(state) = self.state.as_mut() else {
            return;
        };
        let mut rng = node_rng(me, salt);
        let Ok(effects) = state.handle(event, &mut rng, now) else {
            return;
        };
        self.apply_effects(effects, cx, salt);
    }

    /// Perform what the core asked for.
    ///
    /// Split from [`Self::drive`] because the asset path produces effects
    /// without going through an `Event`: sealing a content key is a direct call
    /// on `WorkspaceState`, since the bulk encryption that follows it cannot live
    /// in a crate that does no I/O.
    fn apply_effects(&mut self, effects: Vec<Effect>, cx: &mut dyn Ctx<Self>, salt: u64) {
        let me = cx.me();
        // Two follow-ups that must happen *after* this loop, because both feed
        // more events into `drive` and the borrow of `state` is still live here.
        let mut pending_mint: Option<(u32, Vec<u8>)> = None;
        let mut pending_republish = false;
        let mut pending_eviction: Option<MemberId> = None;
        for effect in effects {
            match effect {
                Effect::BroadcastOp { op, proof } => cx.broadcast(Msg::Op { op, proof }),
                Effect::BroadcastCerts(certs) => cx.broadcast(Msg::Certs(certs)),
                // A removed member spliced a leaf back into the tree. Undoing it
                // is a `Remove`, fed back as an ordinary event so the
                // removal-before-rotation ordering is the same one a deliberate
                // removal takes. Unlike production this is not rate-limited: the
                // simulated attacker splices a bounded number of times, and a
                // cooldown would need a clock the harness deliberately controls
                // rather than the node.
                Effect::EvictUncertified { member } => pending_eviction = Some(member),
                Effect::StoreChunk { key, chunk, .. } | Effect::StoreManifest { key, chunk } => {
                    // Recorded locally as well as broadcast: a node sees its own
                    // writes in its own index, exactly as it would after writing
                    // them into `iroh-docs`.
                    self.observe(key, me, &chunk);
                    cx.broadcast(Msg::Entry {
                        namespace: self.namespace,
                        key,
                        author: me,
                        chunk,
                    });
                }
                Effect::DeleteEntry { key, .. } => {
                    self.index.remove(&key);
                    // The payload goes with the record. Keeping it would have
                    // this node re-offer a withdrawn entry on the next
                    // reconciliation and resurrect a deleted document.
                    self.replica.remove(&key);
                }
                // The ranged counterpart, which `iroh-docs` performs as a single
                // prefix deletion. Modelled as a scan because the simulated
                // replica is a map rather than a range-reconciled store, and the
                // entry counts here are small.
                Effect::DeleteAssetSegments { prefix, .. } => {
                    self.index.retain(|key, _| !key.0.starts_with(&prefix));
                    self.replica.retain(|key, _| !key.0.starts_with(&prefix));
                }
                Effect::RequestRepair { target, epoch } => {
                    self.ask_for_repair(target, epoch, cx);
                }
                // Minting is I/O in production — the caller creates a namespace
                // and hands its capability back. Here the "capability" is the
                // generation itself, derived from the minting node and epoch so
                // that two admins rotating concurrently mint distinguishable
                // ones and the tie-break has something to work with.
                Effect::RotateNamespace { epoch } => {
                    pending_mint = Some((epoch, minted_ticket(me, epoch)));
                }
                Effect::PublishNamespace { epoch, chunk } => {
                    cx.broadcast(Msg::Namespace { epoch, chunk });
                }
                // The new index starts empty, so adopting without re-publishing
                // would take this node's documents out of circulation.
                Effect::AdoptNamespace { epoch, ticket } => {
                    self.namespace = NamespaceEpoch::of(epoch, &ticket);
                    // Entries from the abandoned namespace are no longer
                    // reachable, exactly as they would not be after switching
                    // replicas: the index this node can see starts empty again.
                    //
                    // Except the assets, which are **re-indexed** rather than
                    // re-encrypted. An asset segment is immutable ciphertext and
                    // the removed device could already read everything published
                    // before its removal, so carrying the same bytes into the
                    // new replica gives it nothing — while re-encrypting would
                    // cost the group the whole asset on every removal. This is
                    // the modelled half of `reindex_assets`; the real one is
                    // proved over `iroh` in `tests/assets.rs`.
                    let carried: Vec<StorageKey> = self
                        .state
                        .as_ref()
                        .map(WorkspaceState::asset_index_keys)
                        .unwrap_or_default();
                    self.index.retain(|key, _| carried.contains(key));
                    self.replica.retain(|key, _| carried.contains(key));
                    pending_republish = true;
                }
                // Purely local; nothing to tell the network about.
                Effect::Applied { .. } | Effect::ManifestUpdated => {}
            }
        }
        self.refresh_roster();
        if let Some((epoch, ticket)) = pending_mint {
            // Straight back into the core, which encrypts the capability under
            // the post-removal key and asks for it to be announced.
            self.drive(Event::NamespaceMinted { epoch, ticket }, cx, salt ^ 0xE0E0);
        } else {
            // No rotation was requested by this event.
        }
        if pending_republish {
            self.republish(cx);
        } else {
            // Still on the same namespace; nothing to re-announce.
        }
        if let Some(member) = pending_eviction {
            self.drive(Event::RemoveMember { member }, cx, salt ^ 0xE71C);
        } else {
            // No leaf was spliced in by a former member.
        }
    }

    /// Broadcast a repair request, at most once per window per `(target, epoch)`.
    ///
    /// The core raises one of these for every unreachable chunk that arrives,
    /// which is what makes a lost request recoverable; turning that into a
    /// bounded rate is this side's job, because the rate depends on a clock and
    /// the core has none.
    fn ask_for_repair(&mut self, target: RepairTarget, epoch: EpochId, cx: &mut dyn Ctx<Self>) {
        let Some(member) = self.state.as_ref().map(WorkspaceState::member_id) else {
            return;
        };
        let now = cx.now();
        let fresh = match self.repair_sent.get(&(target, epoch)) {
            Some(sent) => now.saturating_sub(*sent) >= REPAIR_COOLDOWN,
            // Never asked for this one, so there is nothing to suppress.
            None => true,
        };
        if fresh {
            self.repair_sent.insert((target, epoch), now);
            cx.broadcast(Msg::Repair {
                member,
                target,
                epoch,
            });
        } else {
            // Already asked within the window. Silence is correct here: the
            // answer is a group-wide re-key, so asking twice for the same epoch
            // costs everyone and tells nobody anything new.
        }
    }

    /// Replay everything buffered while this node was still joining.
    fn flush_inbox(&mut self, cx: &mut dyn Ctx<Self>) {
        for msg in std::mem::take(&mut self.inbox) {
            match msg {
                Msg::Op { op, proof } => {
                    self.observed_ops += 1;
                    self.drive(Event::ControlOp(AuthorizedOp::new(*op, proof)), cx, 0);
                    self.flush_deferred_ops(cx);
                }
                Msg::Certs(certs) => self.drive(Event::CertsArrived(certs), cx, 0),
                Msg::Log { ops, certs } => self.on_log(ops, certs, cx),
                Msg::Entry {
                    namespace,
                    key,
                    author,
                    chunk,
                } => self.on_entry(namespace, key, author, chunk, cx, 0),
                Msg::Segment {
                    namespace,
                    key,
                    bytes,
                    ..
                } => self.on_segment(namespace, key, bytes),
                Msg::Namespace { epoch, chunk } => {
                    self.drive(Event::NamespaceArrived { epoch, chunk }, cx, 0);
                }
                Msg::Repair {
                    member,
                    target,
                    epoch,
                } => self.on_repair(member, target, epoch, cx),
                // Join-protocol messages; by the time we flush, joining is done.
                Msg::Hello { .. } | Msg::Welcome { .. } => {}
            }
        }
    }

    /// Broadcast an operation signed by a key no `Add` ever introduced.
    ///
    /// The signature is genuine — the attacker really does hold this key — so
    /// only the membership check can stop it. A well-formed `Add` naming the
    /// attacker is the highest-value forgery available: applied, it would splice
    /// an attacker's leaf into the tree and hand them every subsequent key.
    fn forge(&mut self, cx: &mut dyn Ctx<Self>) {
        let rogue = MemorySigner::generate(&mut node_rng(NodeId(self.me), 0xDEAD));
        let rogue_secret = ShareSecretKey::generate(&mut node_rng(NodeId(self.me), 0xBEE5));
        let op = CgkaOperation::init_add(
            tree_id(),
            MemberId::from(rogue.verifying_key()),
            rogue_secret.share_key(),
        );
        if let Ok(signed) = rogue.try_sign_sync(op) {
            // No proof: the attacker holds no certificate, which is the point.
            // It is refused by the membership check before the capability check
            // is even reached.
            cx.broadcast(Msg::Op {
                op: Box::new(signed),
                proof: Vec::new(),
            });
        }
    }

    /// Act beyond the role this node was granted.
    ///
    /// Three attacks in one, because they share a victim and a shape: splice a
    /// keypair we control into the group, bind it to our own account, and grant
    /// ourselves an administrative role. Every certificate here is *genuinely
    /// signed by this node*, which is exactly what makes the scenario worth
    /// having — nothing about the identity is forged, only the authority.
    ///
    /// Issued through the `CgkaController` directly rather than through
    /// `Event::AddUser`, because the local `require_admin` would refuse it. That
    /// refusal is the fail-fast courtesy, not the enforcement; an attacker simply
    /// does not run it, and modelling the attack through the guarded path would
    /// test the guard instead of the receiver.
    fn overreach(&mut self, cx: &mut dyn Ctx<Self>) {
        let me = cx.me();
        let Some(state) = self.state.as_mut() else {
            return;
        };
        let my_user = state.member_id().to_bytes();
        let salt = u64::from(self.overreaches_made);
        let victim = MemorySigner::generate(&mut node_rng(me, 0x1_5DE0 ^ salt));
        let victim_secret = ShareSecretKey::generate(&mut node_rng(me, 0x1_5DE1 ^ salt));
        let victim_id = MemberId::from(victim.verifying_key());

        // A binding we sign ourselves, claiming the new leaf for our own user.
        // The most an insider can honestly claim, and deliberately the *strongest*
        // form of the attack: a binding naming somebody else's user is refused by
        // the closure outright, so this is the variant that gets furthest.
        let nonce = |tag: u8| {
            let mut bytes = [0u8; 16];
            bytes[0] = tag;
            bytes[1] = u8::try_from(salt & 0xFF).unwrap_or(0);
            bytes
        };
        let cgka = state.controller_mut();
        let mut proof = Vec::new();
        if let Ok(cert) = cgka.certify_device(victim_id.to_bytes(), my_user, nonce(1)) {
            proof.push(cert);
        }
        // And a grant promoting ourselves. `certify_role` picks the highest
        // generation this node has seen, which is the most an attacker could
        // compute anyway — so a refusal here cannot be mistaken for merely losing
        // a `(seq, digest)` tie-break.
        if let Ok(cert) = cgka.certify_role(my_user, Role::Admin, nonce(2)) {
            proof.push(cert);
        }

        if let Ok(Some(op)) = cgka.add_member(victim_id, victim_secret.share_key()) {
            cx.broadcast(Msg::Op {
                op: Box::new(op),
                proof,
            });
        } else {
            // Nothing minted; the certificates still go out on their own, since
            // the self-promotion does not depend on the splice landing.
            cx.broadcast(Msg::Certs(proof));
        }
    }

    fn on_hello(
        &mut self,
        from: NodeId,
        member: MemberId,
        share_key: ShareKey,
        cx: &mut dyn Ctx<Self>,
    ) {
        if cx.me().0 != FOUNDER {
            return;
        }
        // Each simulated node is one device belonging to one person, so a join
        // admits a new user rather than enrolling a device onto an existing one.
        self.drive(
            Event::AddUser {
                member,
                share_key,
                role: Role::Editor,
                display_name: format!("node-{}", from.0),
                // Recorded by the admitter, which is the only way the joiner
                // reaches anyone's roster before it has synced a manifest.
                endpoint: Some(endpoint_of(from)),
            },
            cx,
            1,
        );

        let Some(state) = self.state.as_ref() else {
            return;
        };
        let Ok(log) = state.op_log() else { return };
        // Taken after the admission above, so the bundle already contains the
        // joiner's own binding and grant — which is what lets it arrive certified
        // rather than needing a second exchange.
        let certs = state.capabilities().certificates();
        let welcome = Msg::Welcome {
            invitee: member,
            namespace: self.namespace,
            log,
            certs,
            secret: workspace_secret_bytes(),
        };
        cx.send(from, welcome.clone());

        // The leak, injected where the ticket exists rather than modelled as an
        // interception: a `Welcome` is unicast, exactly as an `Invite` travels
        // over an authenticated QUIC stream, so no eavesdropper on this network
        // could obtain one. What `StolenInvite` models is a ticket copied *out of
        // band* — pasted into a chat, left in a shell history — and the only
        // faithful way to inject that is to hand the thief the same bytes the
        // invitee got.
        if let Some(thief) = S::INVITE_THIEF {
            cx.send(NodeId(thief), welcome);
        } else {
            // No thief in this scenario.
        }

        // Re-announce current state, exactly as `Workspace` does when a peer
        // appears on the gossip overlay. Without this the simulator omits a
        // protocol step the real facade performs, and the omission is not
        // cosmetic: a joiner cannot derive the key for anything written before
        // its `Add`, so content that predates it stays unreadable forever
        // unless somebody re-encrypts it under a key the joiner *can* reach.
        // Ordering matters for the same reason it does in the facade — the
        // `Welcome` above carries the operation log the joiner needs before any
        // of this becomes decryptable.
        self.republish(cx);
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per `Msg::Welcome` field, destructured at the call site; \
                  passing the message itself would only move the destructuring inside"
    )]
    fn on_welcome(
        &mut self,
        from: NodeId,
        invitee: MemberId,
        namespace: NamespaceEpoch,
        log: &[Signed<CgkaOperation>],
        certs: &[Certificate],
        secret: [u8; 32],
        cx: &mut dyn Ctx<Self>,
    ) {
        if self.state.is_some() {
            return;
        }
        let (Some(signer), Some(share_secret)) = (self.signer.clone(), self.share_secret) else {
            return;
        };
        // Somebody else's ticket. Refused rather than attempted: `CgkaController::join`
        // would fail anyway for want of the leaf secret, but failing *there* would
        // report "the log does not admit me", which is the diagnosis for a lost race
        // and not for a misaddressed ticket. An honest node must be able to tell the
        // two apart, and after Phase 6 the real `Workspace::join` can.
        if MemberId::from(signer.verifying_key()) != invitee {
            return;
        }
        // A `Welcome` that lost a race against a later membership change may not
        // yet name us; that is an early arrival, not a failure.
        let Ok(cgka) = CgkaController::join(tree_id(), signer, share_secret, log, certs) else {
            return;
        };
        self.initialisations += 1;
        self.state = Some(WorkspaceState::joined(
            cgka,
            WorkspaceSecret::new(secret),
            namespace.epoch,
        ));
        // The replica the ticket named is now this node's, so entries stamped
        // with it are the ones it should be seeing. Set from the message rather
        // than left at `INITIAL`, which would have a joiner admitted after a
        // rotation filtering out every entry the group is actually writing.
        self.namespace = namespace;
        // The inviter, accepted on faith until a manifest arrives to derive a
        // real roster from. `Invite.inviter` plays exactly this role in
        // `Workspace::join`; without it the joiner would refuse the very
        // manifest that would tell it whom to accept.
        self.bootstrap.insert(from);
        self.announce_endpoint(cx);
        self.flush_inbox(cx);
        // Client operations issued while this node was still onboarding apply
        // now, in arrival order, rather than having been discarded.
        self.flush_deferred_ops(cx);
    }

    /// Take everything a ticket issued to somebody else can be made to give up.
    ///
    /// The thief's path, and deliberately not a call into [`Self::on_welcome`]:
    /// that function honours the invitee binding, and an attacker running its own
    /// code would not. What is modelled here is the *maximum* a thief can extract
    /// from the bytes, so that the properties bound the real exposure rather than
    /// the exposure of an attacker that plays fair.
    ///
    /// It takes two things and fails at a third:
    ///
    /// * the inviter, accepted on faith and so a peer whose broadcasts it will
    ///   admit — the modelled counterpart of importing `Invite.doc_ticket`, whose
    ///   embedded addresses are what a thief would dial;
    /// * the replica the ticket names, so entries stamped with it are visible;
    /// * and **not** a [`WorkspaceState`], because building one needs the
    ///   invitee's leaf secret and no ticket carries it. `state` stays `None`,
    ///   which is why the thief decrypts nothing however much it can see.
    ///
    /// The blinding secret is a simulation-wide constant, so "the ticket carried
    /// the workspace secret" is not observable here and is not what these
    /// properties are about. What the ticket confers in this model is visibility,
    /// and visibility is exactly what the index measures.
    fn on_stolen_welcome(&mut self, from: NodeId, namespace: NamespaceEpoch) {
        if self.stolen_invite {
            // One ticket is enough; later copies add nothing.
            return;
        }
        self.stolen_invite = true;
        self.bootstrap.insert(from);
        self.namespace = namespace;
    }

    /// Publish this node's transport address into the manifest.
    ///
    /// A joiner has no device record to attach it to yet, so the core holds it
    /// and re-applies it when the first manifest arrives. Skipping this would
    /// leave the node off every peer's derived roster, and every peer would go
    /// on refusing it once its inviter's bootstrap entry stopped being the only
    /// thing carrying it.
    fn announce_endpoint(&mut self, cx: &mut dyn Ctx<Self>) {
        let me = cx.me();
        self.drive(
            Event::AnnounceEndpoint {
                endpoint_id: endpoint_of(me),
            },
            cx,
            0xE7,
        );
    }
}

impl<S: Scenario> Node for WorkspaceNode<S> {
    type Msg = Msg;
    type Timer = Tick;
    type Op = WsOp;
    type Response = WsResp;

    fn on_start(&mut self, cx: &mut dyn Ctx<Self>) {
        let me = cx.me();
        self.me = me.0;
        let signer = MemorySigner::generate(&mut node_rng(me, 0xA1));
        let share_secret = ShareSecretKey::generate(&mut node_rng(me, 0xB2));
        self.signer = Some(signer.clone());
        self.share_secret = Some(share_secret);

        if self.started {
            // A restart, not a start. Neither branch below may run: re-founding
            // would give the group a second root and fork it, and re-sending a
            // `Hello` would make this a re-invitation rather than a resumption.
            // The founder is genuinely reachable here — a swarm `crash_restart`
            // picks its victim uniformly over every node, node zero included.
            self.reboot();
            self.arm_timers(cx);
            return;
        }
        self.started = true;

        if me.0 == FOUNDER {
            if let Ok(cgka) = CgkaController::create(tree_id(), signer, &mut node_rng(me, 0xC3))
                && let Ok(state) = WorkspaceState::found(
                    cgka,
                    WorkspaceSecret::new(workspace_secret_bytes()),
                    S::THRESHOLD,
                )
            {
                self.state = Some(state);
                self.initialisations += 1;
                // The founder already holds its own device record, so this
                // lands immediately and puts it on its own derived roster.
                self.announce_endpoint(cx);
                self.save();
            }
        } else if S::OUTSIDER == Some(me.0) {
            // Deliberately silent, and deliberately given no bootstrap peer: an
            // outsider holds no invite, so there is nobody it accepts on faith
            // and nobody who accepts it. It still receives every broadcast the
            // simulator delivers, which is what makes "observes nothing" a
            // claim about the roster rather than about the network.
        } else if S::INVITE_THIEF == Some(me.0) {
            // Silent for the same reason as an outsider, and for one more: a
            // thief that sent a `Hello` would be *legitimately admitted*, and
            // the scenario would stop being about a stolen ticket. It waits for
            // the leak, and everything it gains it gains from those bytes.
        } else {
            // A joiner accepts its inviter from the outset, before it has any
            // state of its own. This models `Invite.inviter`, which reaches the
            // joiner out of band and which `Workspace::join` puts on the roster
            // *before* subscribing to anything.
            //
            // Seeding it here rather than on `Welcome` is not a convenience.
            // A joiner must accept operations and entries that arrive while it
            // is still onboarding — under an unordered transport the `Welcome`
            // routinely loses the race against them, which is why there is an
            // inbox at all — and a node that refused them until the `Welcome`
            // landed would discard exactly the messages the inbox exists to
            // keep. That is the difference between a joiner and an outsider:
            // holding an invite, not having already joined.
            self.bootstrap.insert(NodeId(FOUNDER));
            self.send_hello(cx);
            cx.set_timer(Tick::Join, JOIN_RETRY);
        }

        self.arm_timers(cx);
    }

    fn on_msg(&mut self, from: NodeId, msg: Msg, cx: &mut dyn Ctx<Self>) {
        // Refused before it is observed, not merely before it is applied. The
        // distinction is the whole point: a node that recorded the entry and
        // then declined to decrypt it would still have learned that the entry
        // exists, how big it is and who wrote it — which is the metadata leak
        // admission control exists to close.
        if !self.admits(from, &msg) {
            return;
        }
        self.apply_msg(from, msg, cx);
        // One write per message, not per effect batch: a `Msg::Log` replays a
        // whole operation history, and a save inside that loop would be
        // quadratic in the log. Mirrors `handle_control_msg` in the facade.
        self.save();
    }

    fn on_timer(&mut self, timer: Tick, cx: &mut dyn Ctx<Self>) {
        self.apply_timer(&timer, cx);
        self.save();
    }

    fn on_client_op(
        &mut self,
        op: WsOp,
        token: OpToken,
        cx: &mut dyn Ctx<Self>,
    ) -> OpOutcome<WsResp> {
        self.apply_client_op(op, token, cx)
    }
}

impl<S: Scenario> WorkspaceNode<S> {
    /// The protocol half of [`Node::on_msg`], split out so that persistence
    /// happens exactly once however many effect batches a message produced.
    fn apply_msg(&mut self, from: NodeId, msg: Msg, cx: &mut dyn Ctx<Self>) {
        match msg {
            Msg::Hello { member, share_key } => self.on_hello(from, member, share_key, cx),
            // The thief first, because the two paths differ in exactly the way
            // the scenario is about: `on_welcome` honours the invitee binding and
            // an attacker does not.
            Msg::Welcome { namespace, .. } if self.is_invite_thief() => {
                self.on_stolen_welcome(from, namespace);
            }
            Msg::Welcome {
                invitee,
                namespace,
                log,
                certs,
                secret,
            } => {
                self.on_welcome(from, invitee, namespace, &log, &certs, secret, cx);
            }
            // A thief never builds state, so without this arm every entry it
            // receives would land in the inbox below and its index would stay
            // empty — which would make "a stolen ticket lets you watch the
            // replica" untestable by making it look already false. Observed and
            // never decrypted, which is precisely the exposure being bounded.
            Msg::Entry {
                namespace,
                key,
                author,
                chunk,
            } if self.stolen_invite && self.state.is_none() => {
                if namespace == self.namespace {
                    self.observe(key, author, &chunk);
                } else {
                    // A replica this ticket does not name. After the rotation
                    // that is every entry, which is the point.
                }
            }
            other if self.state.is_none() => {
                // Not joined yet: hold this rather than dropping it. A dropped
                // control operation is unrecoverable — every later chunk becomes
                // permanently undecryptable.
                self.inbox.push(other);
            }
            Msg::Op { op, proof } => {
                // Counted before merging, and regardless of the outcome: this is
                // what the node *saw* on the control plane, which is the
                // question the revocation properties ask.
                self.observed_ops += 1;
                self.drive(Event::ControlOp(AuthorizedOp::new(*op, proof)), cx, 2);
                self.flush_deferred_ops(cx);
            }
            Msg::Certs(certs) => self.drive(Event::CertsArrived(certs), cx, 2),
            Msg::Log { ops, certs } => self.on_log(ops, certs, cx),
            Msg::Entry {
                namespace,
                key,
                author,
                chunk,
            } => self.on_entry(namespace, key, author, chunk, cx, 3),
            Msg::Segment {
                namespace,
                key,
                bytes,
                ..
            } => self.on_segment(namespace, key, bytes),
            // The group has abandoned the namespace this node was syncing. A
            // device removed before the rotation cannot decrypt the capability
            // and stays behind, which is the entire mechanism.
            Msg::Namespace { epoch, chunk } => {
                self.drive(Event::NamespaceArrived { epoch, chunk }, cx, 5);
            }
            Msg::Repair {
                member,
                target,
                epoch,
            } => self.on_repair(member, target, epoch, cx),
        }
    }

    /// The protocol half of [`Node::on_client_op`].
    fn apply_client_op(
        &mut self,
        op: WsOp,
        token: OpToken,
        cx: &mut dyn Ctx<Self>,
    ) -> OpOutcome<WsResp> {
        // Not joined yet, so there is nothing to apply this to. Held open rather
        // than failed: the harness allows one operation in flight per process,
        // so failing during onboarding would burn the workload before any node
        // could apply anything — and a real client queues an edit made while it
        // is still connecting rather than throwing it away.
        if self.state.is_none() {
            self.deferred_ops.push((token, op));
            return OpOutcome::Pending;
        }
        let resp = self.apply_op(&op, cx);
        // Before the response, exactly as `Workspace::drive` writes before
        // returning `Ok`. Acknowledging first and saving afterwards would make
        // "an acknowledged write survives a restart" true only most of the time,
        // and the harness would be modelling a weaker library than the one that
        // ships.
        self.save();
        OpOutcome::Done(resp)
    }

    /// The protocol half of [`Node::on_timer`].
    fn apply_timer(&mut self, timer: &Tick, cx: &mut dyn Ctx<Self>) {
        match timer {
            Tick::Join => {
                if self.state.is_none() {
                    self.send_hello(cx);
                    cx.set_timer(Tick::Join, JOIN_RETRY);
                }
            }
            // Suppressed under a generated workload: content changes come from
            // client operations there, and running both would blend a fixed
            // script into the generated one.
            Tick::Edit if S::WORKLOAD => {}
            Tick::Edit => {
                if self.state.is_some() && self.edits_made < EDITS_PER_NODE {
                    let text = format!("<{}:{}>", cx.me().0, self.edits_made);
                    self.contributed.push(text.clone());
                    self.edits_made += 1;
                    self.drive(Event::LocalEdit { doc: DOC, text }, cx, 4);
                }
                if self.edits_made < EDITS_PER_NODE {
                    cx.set_timer(Tick::Edit, EDIT_INTERVAL);
                }
            }
            Tick::Resync => {
                // Range reconciliation, before the re-announcements below and
                // not replaceable by them. `Event::Resync` produces a chunk only
                // for a document this node has *not* fully published, so it
                // cannot recover an entry that was lost in transit — the author
                // has nothing left to say. Re-offering what this node already
                // holds is what `iroh-docs` does between any two peers, and
                // leaving it out makes the harness strictly more fragile than
                // production. On a sparser cadence than the resyncs below,
                // because doing it every round makes it more talkative than
                // production instead — see [`RECONCILE_EVERY`].
                if self.resyncs_done.is_multiple_of(RECONCILE_EVERY) {
                    self.reconcile(cx);
                } else {
                    // Not a reconciliation round; the re-announcements below
                    // still run, as they do every round.
                }
                // A distinct salt per document *and* per round. `drive` seeds a
                // fresh RNG from the salt, so reusing one would hand three
                // different encryptions the identical random stream, and hand
                // successive rounds the same one again.
                for (i, doc) in DOCS.into_iter().enumerate() {
                    let salt = 5000 + u64::from(self.resyncs_done) * 16 + i as u64;
                    self.drive(Event::Resync { doc }, cx, salt);
                }
                // The manifest shares the round's salt space, one slot past the
                // documents. It is re-announced on the same schedule because it
                // is lost the same way, and because the roster derives from it:
                // a device record that never arrives costs its owner a place on
                // that peer's roster indefinitely.
                let manifest_salt = 5000 + u64::from(self.resyncs_done) * 16 + DOCS.len() as u64;
                self.drive(Event::ResyncManifest, cx, manifest_salt);
                // And the rotation. Announced once when it happens, so a member
                // that missed it is stranded on a replica the group abandoned
                // until one of these reaches it.
                self.drive(Event::ResyncNamespace, cx, manifest_salt + 1);
                // Control-plane repair, on a deliberately sparser cadence. The
                // real `Workspace` ships its log on `NeighborUp` behind a
                // ten-second per-peer cooldown, so a log broadcast every
                // anti-entropy round would make the simulator *more* talkative
                // than production — and it is the expensive message, since one
                // carries the whole history to every peer.
                if self.resyncs_done.is_multiple_of(LOG_REPAIR_EVERY) {
                    self.send_log(cx);
                }
                self.resyncs_done += 1;
                let budget = if S::WORKLOAD {
                    MAX_RESYNCS_UNDER_WORKLOAD
                } else {
                    MAX_RESYNCS
                };
                if self.resyncs_done < budget {
                    cx.set_timer(Tick::Resync, RESYNC_INTERVAL);
                }
            }
            Tick::Attach => self.attach_asset(cx),
            Tick::Rotate => {
                if self.state.is_some() {
                    self.drive(Event::Rotate, cx, 7 + u64::from(self.rotations_done));
                    self.rotations_done += 1;
                }
                if self.rotations_done < MAX_ROTATIONS {
                    cx.set_timer(Tick::Rotate, ROTATE_INTERVAL);
                }
            }
            Tick::Overreach => {
                // A removed insider keeps going only in the revenant scenario.
                // Elsewhere, an attacker that carried on after its own removal
                // would fold two distinct questions — what a member may do, and
                // what a *former* member may do — into one run, and a failure
                // would not say which had been caught.
                if self.is_revocation_target() && !S::REVENANT {
                    return;
                }
                self.overreach(cx);
                self.overreaches_made += 1;
                if self.overreaches_made < MAX_OVERREACHES {
                    cx.set_timer(Tick::Overreach, OVERREACH_INTERVAL);
                } else {
                    // Bounded, so the honest group's convergence is measured
                    // rather than the attacker's persistence.
                }
            }
            Tick::Revoke => {
                if let Some(victim) = S::REVOKE {
                    // Every node's key material is a pure function of its id,
                    // so the founder can name the victim without a lookup.
                    let victim_signer = MemorySigner::generate(&mut node_rng(NodeId(victim), 0xA1));
                    let member = MemberId::from(victim_signer.verifying_key());
                    self.drive(Event::RemoveMember { member }, cx, 0xBEEF);
                }
            }
            Tick::AppointCoAdmin | Tick::ProposeRemoval | Tick::ApproveProposals => {
                self.apply_quorum_timer(timer, cx);
            }
            Tick::Leave => {
                // Driven once and never re-armed. `Event::Leave` retracts every
                // device of this user in one batch, so a second firing would
                // find nothing to remove and broadcast nothing — but arming it
                // again would still be a claim that leaving is repeatable, and
                // it is not.
                self.drive(Event::Leave, cx, 0x1EA7);
                self.left = true;
            }
            Tick::LateEdit => {
                // A document nothing has written to before, so every entry
                // under its key belongs to the post-rotation namespace.
                self.drive(
                    Event::LocalEdit {
                        doc: POST_REVOCATION_DOC,
                        text: "written after the removal".into(),
                    },
                    cx,
                    0x1A7E,
                );
            }
            Tick::Forge => {
                self.forge(cx);
                self.forgeries_made += 1;
                if self.forgeries_made < MAX_FORGERIES {
                    cx.set_timer(Tick::Forge, FORGE_INTERVAL);
                }
            }
        }
    }
}

/// Bridges generated workload values to typed [`WsOp`]s and back.
///
/// One struct so the `:f` names and the value encoding are written once; the
/// engine decodes with it at invoke time and any history-reading property
/// decodes with the same shapes at check time.
///
/// Deliberately *not* paired with a `SequentialModel`. propsim ships a
/// linearizability oracle, but a CRDT workspace is not linearizable by design —
/// concurrent writes commute rather than serialising — so that oracle would
/// report anomalies for entirely correct behaviour. Convergence is checked by
/// properties over the world instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkspaceSpec;

impl<S: Scenario> ClientCodec<WorkspaceNode<S>> for WorkspaceSpec {
    fn decode(&self, value: &Value) -> Option<(Function, WsOp)> {
        let Value::List(items) = value else {
            return None;
        };
        let idx = |v: &Value| -> Option<usize> {
            match v {
                Value::Int(i) => usize::try_from(*i).ok(),
                _ => None,
            }
        };
        match items.as_slice() {
            [Value::Keyword(f), d, Value::Str(text)] if f == "append" => Some((
                Function::new("append"),
                WsOp::Append {
                    doc: idx(d)?,
                    text: text.clone(),
                },
            )),
            [Value::Keyword(f), d, Value::Str(text)] if f == "write" => Some((
                Function::new("write"),
                WsOp::Write {
                    doc: idx(d)?,
                    text: text.clone(),
                },
            )),
            [Value::Keyword(f), d, p, Value::Str(text)] if f == "insert" => Some((
                Function::new("insert"),
                WsOp::Insert {
                    doc: idx(d)?,
                    pos: idx(p)?,
                    text: text.clone(),
                },
            )),
            [Value::Keyword(f), d, p, l] if f == "remove" => Some((
                Function::new("remove"),
                WsOp::Remove {
                    doc: idx(d)?,
                    pos: idx(p)?,
                    len: idx(l)?,
                },
            )),
            [Value::Keyword(f), d, b] if f == "revert" => Some((
                Function::new("revert"),
                WsOp::Revert {
                    doc: idx(d)?,
                    back: idx(b)?,
                },
            )),
            [Value::Keyword(f), d] if f == "read" => {
                Some((Function::new("read"), WsOp::Read { doc: idx(d)? }))
            }
            _ => None,
        }
    }

    fn encode_response(&self, _op_f: &Function, resp: &WsResp) -> Value {
        match resp {
            WsResp::Text(text) => Value::Str(text.clone()),
            WsResp::Applied => Value::keyword("applied"),
        }
    }
}

/// A generated stream of CRUD operations across `nodes` processes.
///
/// Offsets and lengths are drawn small and are allowed to run past the end of a
/// document: the core clamps them, and that clamping is exactly the behaviour a
/// caller holding a view a concurrent edit has already shortened depends on. A
/// strategy that only ever produced in-range offsets would never exercise it.
/// # Panics
///
/// Panics if the built-in text pattern is not a valid regex, which would be a
/// bug in this function rather than anything a caller can cause.
pub fn crud_workload(nodes: usize) -> BoxedStrategy<FrozenOp> {
    // Rebuilt per branch rather than cloned: `RegexGeneratorStrategy` is not
    // `Clone`, and a closure keeps the intent obvious at each use.
    let text = || proptest::string::string_regex("[a-z]{1,6}").expect("valid regex");
    let doc = || (0..DOCS.len()).prop_map(|d| Value::Int(i64::try_from(d).unwrap_or(0)));
    let small = || (0usize..12).prop_map(|n| Value::Int(i64::try_from(n).unwrap_or(0)));

    let op = prop_oneof![
        // Weighted towards appends: they are the operation whose effect a
        // convergence property can state without ambiguity, since an append
        // can only ever add text.
        4 => (doc(), text())
            .prop_map(|(d, t)| Value::List(vec![Value::keyword("append"), d, Value::Str(t)])),
        1 => (doc(), text())
            .prop_map(|(d, t)| Value::List(vec![Value::keyword("write"), d, Value::Str(t)])),
        2 => (doc(), small(), text())
            .prop_map(|(d, p, t)| Value::List(vec![
                Value::keyword("insert"),
                d,
                p,
                Value::Str(t)
            ])),
        1 => (doc(), small(), small())
            .prop_map(|(d, p, l)| Value::List(vec![Value::keyword("remove"), d, p, l])),
        // Reverts, drawn as often as whole-document writes. They are what makes
        // the convergence properties cover the feature at all: a revert is an
        // ordinary forward edit, and if it were ever implemented as a rewrite of
        // history, a peer that had already merged the operations being undone
        // would diverge permanently — which is what these plans detect.
        1 => (doc(), small())
            .prop_map(|(d, b)| Value::List(vec![Value::keyword("revert"), d, b])),
        2 => doc().prop_map(|d| Value::List(vec![Value::keyword("read"), d])),
    ];

    (0..nodes, op)
        .prop_map(|(process, value)| FrozenOp::new(NodeId(process as u64), value))
        .boxed()
}
