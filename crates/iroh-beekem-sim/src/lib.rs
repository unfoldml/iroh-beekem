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
    AuthorizedOp, Certificate, CgkaController, Chunk, DocumentUuid, Effect, EpochId, Event,
    NamespaceEpoch, RepairTarget, StorageKey, WorkspaceSecret, WorkspaceState,
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
}

/// The base protocol: joins, edits and anti-entropy, nothing adversarial.
#[derive(Clone, Copy, Debug, Default)]
pub struct Honest;
impl Scenario for Honest {}

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
    Welcome {
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
    _scenario: PhantomData<S>,
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

    /// Control operations parked awaiting causal predecessors.
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
    #[must_use]
    pub fn group_size(&self) -> u32 {
        self.state.as_ref().map_or(0, WorkspaceState::group_size)
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
        };
        self.drive(event, cx, 11);
        WsResp::Applied
    }

    /// Re-announce every document this node holds.
    ///
    /// The simulator's counterpart to the facade's republish-on-neighbour-up.
    fn republish(&mut self, cx: &mut dyn Ctx<Self>) {
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
        let Some(state) = self.state.as_mut() else {
            return;
        };
        let mut rng = node_rng(me, salt);
        let Ok(effects) = state.handle(event, &mut rng) else {
            return;
        };
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
                    self.index.clear();
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
        cx.send(
            from,
            Msg::Welcome {
                log,
                certs,
                secret: workspace_secret_bytes(),
            },
        );

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

    fn on_welcome(
        &mut self,
        from: NodeId,
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
        // A `Welcome` that lost a race against a later membership change may not
        // yet name us; that is an early arrival, not a failure.
        let Ok(cgka) = CgkaController::join(tree_id(), signer, share_secret, log, certs) else {
            return;
        };
        self.state = Some(WorkspaceState::joined(cgka, WorkspaceSecret::new(secret)));
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

        if me.0 == FOUNDER {
            if let Ok(cgka) = CgkaController::create(tree_id(), signer, &mut node_rng(me, 0xC3))
                && let Ok(state) =
                    WorkspaceState::found(cgka, WorkspaceSecret::new(workspace_secret_bytes()))
            {
                self.state = Some(state);
                // The founder already holds its own device record, so this
                // lands immediately and puts it on its own derived roster.
                self.announce_endpoint(cx);
            }
        } else if S::OUTSIDER == Some(me.0) {
            // Deliberately silent, and deliberately given no bootstrap peer: an
            // outsider holds no invite, so there is nobody it accepts on faith
            // and nobody who accepts it. It still receives every broadcast the
            // simulator delivers, which is what makes "observes nothing" a
            // claim about the roster rather than about the network.
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

        cx.set_timer(Tick::Edit, FIRST_EDIT);
        cx.set_timer(Tick::Resync, RESYNC_INTERVAL);

        // The victim does not rotate: an operation it issued after its own
        // removal could never be applied by anyone, and would sit parked on
        // every honest node forever — a property failure about the scenario
        // rather than about the protocol.
        if S::ROTATE && !self.is_revocation_target() {
            cx.set_timer(Tick::Rotate, FIRST_ROTATE);
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
        match msg {
            Msg::Hello { member, share_key } => self.on_hello(from, member, share_key, cx),
            Msg::Welcome { log, certs, secret } => {
                self.on_welcome(from, &log, &certs, secret, cx);
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

    fn on_client_op(
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
        OpOutcome::Done(resp)
    }

    fn on_timer(&mut self, timer: Tick, cx: &mut dyn Ctx<Self>) {
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
        2 => doc().prop_map(|d| Value::List(vec![Value::keyword("read"), d])),
    ];

    (0..nodes, op)
        .prop_map(|(process, value)| FrozenOp::new(NodeId(process as u64), value))
        .boxed()
}
