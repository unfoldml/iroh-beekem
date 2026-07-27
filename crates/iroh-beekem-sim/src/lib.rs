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

use std::{marker::PhantomData, sync::Arc, time::Duration};

use beekem::{
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
use iroh_beekem_core::{
    CgkaController, Chunk, DocumentUuid, Effect, Event, WorkspaceSecret, WorkspaceState,
};
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use propsim_core::{
    node::{Ctx, Node},
    NodeId,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// The single document every simulated node edits.
pub const DOC: DocumentUuid = DocumentUuid([7u8; 16]);

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
const MAX_RESYNCS: u32 = 8;

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
    /// Data plane: an encrypted content chunk.
    Chunk(Box<Chunk>),
    /// Data plane: an encrypted manifest replica.
    ///
    /// Carried separately from [`Msg::Chunk`] because it lands at the manifest's
    /// well-known key rather than a document's, and because a receiver must not
    /// try to import it into a CRDT document.
    Manifest(Box<Chunk>),
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

    /// The document text as this node currently sees it.
    #[must_use]
    pub fn document_text(&self) -> String {
        self.state
            .as_ref()
            .map_or_else(String::new, |s| s.document_text(DOC))
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

    /// Feed an event to the local state machine, gossiping whatever it emits.
    fn drive(&mut self, event: Event, cx: &mut dyn Ctx<Self>, salt: u64) {
        let Some(state) = self.state.as_mut() else {
            return;
        };
        let mut rng = node_rng(cx.me(), salt);
        let Ok(effects) = state.handle(event, &mut rng) else {
            return;
        };
        for effect in effects {
            match effect {
                Effect::BroadcastOp(op) => cx.broadcast(Msg::Op(op)),
                Effect::StoreChunk { chunk, .. } => cx.broadcast(Msg::Chunk(chunk)),
                Effect::StoreManifest { chunk, .. } => cx.broadcast(Msg::Manifest(chunk)),
                // Purely local; nothing to tell the network about.
                Effect::Applied { .. } | Effect::ManifestUpdated => {}
            }
        }
    }

    /// Replay everything buffered while this node was still joining.
    fn flush_inbox(&mut self, cx: &mut dyn Ctx<Self>) {
        for msg in std::mem::take(&mut self.inbox) {
            match msg {
                Msg::Op(op) => self.drive(Event::ControlOp(Arc::new(*op)), cx, 0),
                Msg::Chunk(chunk) => self.drive(Event::ChunkArrived { doc: DOC, chunk }, cx, 0),
                Msg::Manifest(chunk) => self.drive(Event::ManifestArrived { chunk }, cx, 0),
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
        self.drive(Event::AddMember { member, share_key }, cx, 1);

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
    }
}

impl<S: Scenario> Node for WorkspaceNode<S> {
    type Msg = Msg;
    type Timer = Tick;
    type Op = ();
    type Response = ();

    fn on_start(&mut self, cx: &mut dyn Ctx<Self>) {
        let me = cx.me();
        self.me = me.0;
        let signer = MemorySigner::generate(&mut node_rng(me, 0xA1));
        let share_secret = ShareSecretKey::generate(&mut node_rng(me, 0xB2));
        self.signer = Some(signer.clone());
        self.share_secret = Some(share_secret);

        if me.0 == FOUNDER {
            if let Ok(cgka) = CgkaController::create(tree_id(), signer, &mut node_rng(me, 0xC3))
                && let Ok(state) = WorkspaceState::found(
                    cgka,
                    WorkspaceSecret::new(workspace_secret_bytes()),
                )
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
            Msg::Op(op) => self.drive(Event::ControlOp(Arc::new(*op)), cx, 2),
            Msg::Chunk(chunk) => self.drive(Event::ChunkArrived { doc: DOC, chunk }, cx, 3),
            Msg::Manifest(chunk) => self.drive(Event::ManifestArrived { chunk }, cx, 6),
        }
    }

    fn on_timer(&mut self, timer: Tick, cx: &mut dyn Ctx<Self>) {
        match timer {
            Tick::Join => {
                if self.state.is_none() {
                    self.send_hello(cx);
                    cx.set_timer(Tick::Join, JOIN_RETRY);
                }
            }
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
                self.drive(Event::Resync { doc: DOC }, cx, 5);
                self.resyncs_done += 1;
                if self.resyncs_done < MAX_RESYNCS {
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
