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
//! plane) and [`Msg::Chunk`] (data plane).
//!
//! Messages that arrive before a node has joined are buffered rather than
//! dropped, because under an unordered transport a `Welcome` routinely loses
//! the race against the operations that follow it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{collections::BTreeMap, marker::PhantomData, sync::Arc, time::Duration};

use beekem::{
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
use iroh_beekem_core::{
    CgkaController, Chunk, DocumentUuid, Effect, Event, Role, StorageKey, WorkspaceSecret,
    WorkspaceState,
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
const RESYNC_INTERVAL: Duration = Duration::from_millis(400);

/// How many times a node re-announces before going quiet, so runs terminate.
///
/// A real node re-announces forever; this budget exists only so a run ends. The
/// fixed-script scenarios finish writing within the first second, so eight
/// rounds comfortably outlast them — but a generated workload keeps issuing
/// writes for the whole run, and anti-entropy that stopped first would leave a
/// late chunk lost by the lossy transport with nothing to recover it. That
/// would look exactly like a convergence bug while being an artefact of the
/// harness, so workload scenarios get a budget that outlasts the run.
const MAX_RESYNCS: u32 = 8;

/// The re-announcement budget when generated operations drive the run.
const MAX_RESYNCS_UNDER_WORKLOAD: u32 = 32;

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

/// How often a forging node emits an operation signed by a non-member key.
const FORGE_INTERVAL: Duration = Duration::from_millis(300);

/// How many forgeries an attacking node attempts.
const MAX_FORGERIES: u32 = 10;

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
        /// The blinding secret for storage keys.
        secret: [u8; 32],
    },
    /// Control plane: a signed CGKA operation.
    Op(Box<Signed<CgkaOperation>>),
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
        /// The blinded key this entry is stored under.
        key: StorageKey,
        /// Which node wrote it.
        author: NodeId,
        /// The ciphertext.
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
    /// Time for an attacking node to emit a forged operation.
    Forge,
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
    /// Control-plane operations seen, whether or not they applied.
    observed_ops: u64,
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
        key: StorageKey,
        author: NodeId,
        chunk: Box<Chunk>,
        cx: &mut dyn Ctx<Self>,
        salt: u64,
    ) {
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
        for effect in effects {
            match effect {
                Effect::BroadcastOp(op) => cx.broadcast(Msg::Op(op)),
                Effect::StoreChunk { key, chunk, .. } | Effect::StoreManifest { key, chunk } => {
                    // Recorded locally as well as broadcast: a node sees its own
                    // writes in its own index, exactly as it would after writing
                    // them into `iroh-docs`.
                    self.observe(key, me, &chunk);
                    cx.broadcast(Msg::Entry {
                        key,
                        author: me,
                        chunk,
                    });
                }
                Effect::DeleteEntry { key, .. } => {
                    self.index.remove(&key);
                }
                // Purely local; nothing to tell the network about.
                Effect::Applied { .. } | Effect::ManifestUpdated => {}
            }
        }
    }

    /// Replay everything buffered while this node was still joining.
    fn flush_inbox(&mut self, cx: &mut dyn Ctx<Self>) {
        for msg in std::mem::take(&mut self.inbox) {
            match msg {
                Msg::Op(op) => {
                    self.observed_ops += 1;
                    self.drive(Event::ControlOp(Arc::new(*op)), cx, 0);
                    self.flush_deferred_ops(cx);
                }
                Msg::Entry { key, author, chunk } => self.on_entry(key, author, chunk, cx, 0),
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
            cx.broadcast(Msg::Op(Box::new(signed)));
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
            },
            cx,
            1,
        );

        let Some(state) = self.state.as_ref() else {
            return;
        };
        let Ok(log) = state.op_log() else { return };
        cx.send(
            from,
            Msg::Welcome {
                log,
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
        log: &[Signed<CgkaOperation>],
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
        let Ok(cgka) = CgkaController::join(tree_id(), signer, share_secret, log) else {
            return;
        };
        self.state = Some(WorkspaceState::joined(cgka, WorkspaceSecret::new(secret)));
        self.flush_inbox(cx);
        // Client operations issued while this node was still onboarding apply
        // now, in arrival order, rather than having been discarded.
        self.flush_deferred_ops(cx);
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
            }
        } else {
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
        if S::FORGE && me.0 != FOUNDER {
            cx.set_timer(Tick::Forge, FORGE_INTERVAL);
        }
    }

    fn on_msg(&mut self, from: NodeId, msg: Msg, cx: &mut dyn Ctx<Self>) {
        match msg {
            Msg::Hello { member, share_key } => self.on_hello(from, member, share_key, cx),
            Msg::Welcome { log, secret } => self.on_welcome(&log, secret, cx),
            other if self.state.is_none() => {
                // Not joined yet: hold this rather than dropping it. A dropped
                // control operation is unrecoverable — every later chunk becomes
                // permanently undecryptable.
                self.inbox.push(other);
            }
            Msg::Op(op) => {
                // Counted before merging, and regardless of the outcome: this is
                // what the node *saw* on the control plane, which is the
                // question the revocation properties ask.
                self.observed_ops += 1;
                self.drive(Event::ControlOp(Arc::new(*op)), cx, 2);
                self.flush_deferred_ops(cx);
            }
            Msg::Entry { key, author, chunk } => self.on_entry(key, author, chunk, cx, 3),
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
            Tick::Revoke => {
                if let Some(victim) = S::REVOKE {
                    // Every node's key material is a pure function of its id,
                    // so the founder can name the victim without a lookup.
                    let victim_signer = MemorySigner::generate(&mut node_rng(NodeId(victim), 0xA1));
                    let member = MemberId::from(victim_signer.verifying_key());
                    self.drive(Event::RemoveMember { member }, cx, 0xBEEF);
                }
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
