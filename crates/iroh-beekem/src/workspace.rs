//! The [`Workspace`] facade: a pump between `iroh` and the I/O-free core.
//!
//! This module contains no cryptography. Its whole job is to turn network
//! arrivals into [`Event`]s for [`WorkspaceState`], and the [`Effect`]s that
//! come back into gossip broadcasts and blob writes. All key handling lives in
//! `iroh-beekem-core`, where it can be simulated and property-tested.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use beekem::id::{MemberId, TreeId};
use bytes::Bytes;
use iroh::{EndpointAddr, EndpointId};
use iroh_beekem_core::{
    AuthorizedOp, CgkaController, DeviceRecord, DocumentUuid, Effect, EpochId, Event, FileEntry,
    NamespaceEpoch, RepairTarget, Role, WorkspaceInfo, WorkspaceSecret, WorkspaceState,
};
use iroh_blobs::api::Store as BlobStore;
use iroh_docs::{
    Author, AuthorId, NamespaceId,
    api::{
        Doc,
        protocol::{AddrInfoOptions, ShareMode},
    },
    engine::LiveEvent,
    store::Query,
};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipSender},
    proto::TopicId,
};
use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};
use n0_future::StreamExt;
use rand::{CryptoRng, RngCore};
use tokio::{
    sync::{Mutex, Notify, RwLock},
    task::JoinHandle,
};

use crate::{
    error::WorkspaceError,
    identity::{Enrollment, Identity},
    invite::{INVITE_DOMAIN, Invite, InviteError, InviteTerms, unix_now},
    node::Node,
    roster::Roster,
    store::WorkspaceRecord,
    wire::{ControlMsg, NamespaceCapability, decode_chunk, encode_chunk},
};

/// One person in the workspace, with everything an application needs to show
/// them: their role, and the devices acting on their behalf.
#[derive(Debug, Clone)]
pub struct User {
    /// Stable identifier — the member id of this user's founding device.
    pub id: [u8; 32],
    /// Human-readable name, for display only.
    pub display_name: String,
    /// This user's role, if an admin has assigned one yet.
    pub role: Option<Role>,
    /// The devices acting for this user, each holding one CGKA leaf.
    pub devices: Vec<DeviceRecord>,
}

/// What identifies one index entry: the blinded key and the author who wrote it.
///
/// Every member writes to the same blinded key for a given document, so the
/// author is what distinguishes their entries from each other.
type EntrySlot = ([u8; 32], [u8; 32]);

/// Rebuild a `MemberId` from raw verifying-key bytes.
fn member_id_from_bytes(bytes: &[u8; 32]) -> Option<MemberId> {
    ed25519_verifying_key(bytes).map(MemberId::from)
}

/// Shared state behind the pump loops.
struct Inner {
    state: Mutex<WorkspaceState>,
    blobs: BlobStore,
    /// The replicated index this node currently syncs.
    ///
    /// Behind a lock because it is *replaced* on a namespace rotation, not
    /// merely mutated: removal abandons one namespace for a fresh one whose
    /// capability the removed device never receives. Every reader takes a clone
    /// and releases the lock immediately — `Doc` is a cheap handle, and holding
    /// it across an await would let a rotation deadlock behind a slow sync.
    doc: RwLock<Doc>,
    /// The task pumping data-plane events for the current namespace.
    ///
    /// Owned here rather than on [`Workspace`] because a rotation has to abort
    /// and respawn it, and rotations arrive through the effect pump, which sees
    /// only `Inner`. A subscription is to one namespace; after a swap the old
    /// one delivers nothing and the new one has nobody listening.
    data_task: Mutex<Option<JoinHandle<()>>>,
    author: AuthorId,
    gossip_tx: GossipSender,
    secret: WorkspaceSecret,
    /// This device's signing key, for signing invites.
    ///
    /// A second handle on the key `CgkaController` already holds, not a second
    /// key. Kept here because an [`Invite`] is a transport-layer object — it
    /// names an `iroh-docs` ticket and an `EndpointId`, neither of which the
    /// I/O-free core knows about — so the core has no business signing one, and
    /// the alternative of a generic `sign<T>` on `CgkaController` would be a
    /// signing oracle over the device key for any payload a caller invents.
    signer: MemorySigner,
    /// The content hash last ingested for each (blinded key, author) pair.
    ///
    /// `ingest_all` re-reads every entry on every sync event, and with several
    /// documents that is N fetch-and-decrypt cycles per event for content that
    /// has usually not changed. Skipping unchanged hashes keeps the cost
    /// proportional to what actually moved.
    ///
    /// Keyed by author as well as by key: every member writes to the *same*
    /// blinded key for a given document, so a single slot per key would be
    /// overwritten by each peer's entry in turn and never register a hit.
    seen_entries: Mutex<HashMap<EntrySlot, iroh_blobs::Hash>>,
    /// Rate limiter for the neighbour-up repair path.
    neighbor_cooldown: Mutex<Cooldown<EndpointId>>,
    /// Rate limiter for outgoing repair requests, per `(target, epoch)`.
    ///
    /// Answering one costs the whole group a tree operation, so asking twice
    /// for the same epoch is pure waste; asking about a *different* epoch is
    /// new information and must get through, which is why the epoch is part of
    /// the key rather than just the target.
    repair_cooldown: Mutex<Cooldown<(RepairTarget, EpochId)>>,
    /// Rate limiter for *answering* repair requests, per requesting member.
    ///
    /// The limiter above binds only well-behaved peers, since it lives on the
    /// sending side. This one binds everyone: a member that ignores its own
    /// cooldown and floods requests costs the group one re-key per window
    /// rather than one per message. Keyed by member rather than by
    /// `(target, epoch)` because it is the *requester* being limited — an
    /// attacker can mint fresh epoch bytes for free, so a key they control
    /// would be no limit at all.
    ///
    /// Not a confidentiality boundary. A member can already force tree work by
    /// rotating its own leaf; this keeps the repair path from being a cheaper
    /// way to do the same thing.
    repair_answer_cooldown: Mutex<Cooldown<[u8; 32]>>,
    /// Rate limiter for evicting a leaf spliced in by a former member.
    ///
    /// Keyed on the spliced leaf rather than on the splicer: an attacker mints a
    /// fresh keypair per attempt, so limiting per *attempt* is the only bound that
    /// holds, and each distinct leaf genuinely does need removing once.
    eviction_cooldown: Mutex<Cooldown<[u8; 32]>>,
    /// Raised when the current document state should be re-announced.
    ///
    /// A [`Notify`] rather than a timestamp check because the republish must be
    /// *deferred*, never dropped — see [`republish_loop`].
    republish_wanted: Notify,
    /// The node's admission list, shared with the guard on every ALPN.
    ///
    /// Held here rather than reached through [`Node`] so that the effect pump —
    /// which sees every membership change — can update it without needing the
    /// whole node.
    roster: Roster,
    /// Which workspace's entry in that list this pump owns.
    ///
    /// The roster is keyed by tree id because two workspaces on one node share a
    /// [`Roster`], and `set_derived` replaces rather than merges: without a key,
    /// each workspace's refresh would evict the other's members. Kept as raw
    /// bytes because that is what the registry is keyed on.
    workspace_key: [u8; 32],
    /// The node this workspace runs on.
    ///
    /// Cloned onto `Inner` because minting and importing a namespace happen in
    /// the effect pump, which sees only `Inner`. `Node` is a handle, so this is
    /// a second reference to the same endpoint and router rather than a copy.
    node: Node,
}

/// One stored workspace, as [`Workspace::list`] reports it.
///
/// Enough to choose which workspace to [`open`](Workspace::open) and no more:
/// listing must not require decrypting content or contacting a peer, because its
/// whole purpose is to run before either is possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSummary {
    /// The workspace's identity, and the argument [`Workspace::open`] takes.
    pub tree_id: TreeId,
    /// Its name and description, as the manifest records them.
    pub info: WorkspaceInfo,
    /// The `iroh-docs` replica it was on when the snapshot was taken.
    pub namespace: NamespaceId,
}

/// A running, networked workspace.
pub struct Workspace {
    node: Node,
    inner: Arc<Inner>,
    tree_id: TreeId,
    topic: TopicId,
    /// The long-lived pumps. The data-plane pump is not among them: it is
    /// replaced on rotation and therefore lives on [`Inner`].
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace")
            .field("endpoint", &self.node.endpoint().id())
            .finish_non_exhaustive()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // The data pump is reachable only through the lock, and `Drop` cannot
        // await. `blocking_lock` is safe here because nothing else holds this
        // lock across an await point — every other holder clones and releases.
        if let Ok(mut task) = self.inner.data_task.try_lock()
            && let Some(task) = task.take()
        {
            task.abort();
        } else {
            // Contended or poisoned: the task holds only an `Arc<Inner>` and a
            // subscription, both of which drop with the workspace, so leaving
            // it to be reaped is a leak of nothing.
        }
    }
}

/// How many operations a peer's log-repair broadcast may contain.
///
/// `ControlMsg::Log` is the repair mechanism: any peer may send its whole
/// history when a neighbour appears, and the receiver merges all of it. That
/// makes it the cheapest amplification point on the control plane, since one
/// message can cost the receiver an unbounded number of signature checks. The
/// limit is well above any realistic workspace history and exists purely to
/// bound that cost.
const MAX_LOG_OPS: usize = 100_000;

/// How many certificates a peer's log-repair or certificate broadcast may carry.
///
/// The same amplification argument as [`MAX_LOG_OPS`], and a tighter bound
/// because the realistic count is far smaller: one binding per device plus a few
/// grants per user. Each certificate costs the receiver a signature check, and a
/// batch that is all new costs a closure recompute as well.
const MAX_LOG_CERTS: usize = 10_000;

/// How long the eviction of one spliced leaf is suppressed after the last.
///
/// `Effect::EvictUncertified` answers a removed member re-entering the tree, and
/// answering costs a `Remove` *and* a namespace rotation — the most expensive
/// thing the group does. An attacker re-adding in a loop would otherwise churn
/// every member's replica, so the response is rate-limited per spliced leaf.
///
/// Longer than [`REPAIR_COOLDOWN`] because the work is heavier and the trigger is
/// adversarial rather than ordinary: a peer legitimately stuck on an epoch needs a
/// prompt answer, whereas a revenant needs a bounded one.
const EVICTION_COOLDOWN: Duration = Duration::from_secs(30);

/// How long one peer's neighbour-up repair is suppressed after the last.
///
/// The topic is derived from the tree id, which every past invitee knows, so
/// anyone who has ever held an invite can join the overlay — and rejoin it in a
/// loop. Each arrival costs us a full operation-log broadcast and costs every
/// receiver a signature check per operation, so without this a single peer can
/// spend the whole group's CPU by reconnecting. [`MAX_LOG_OPS`] bounds one
/// message; this bounds their rate.
const NEIGHBOR_COOLDOWN: Duration = Duration::from_secs(10);

/// The minimum gap between two re-announcements of document state.
///
/// Distinct from [`NEIGHBOR_COOLDOWN`] because it is a *global* budget rather
/// than a per-peer one: twenty peers arriving at once are twenty legitimate
/// reasons to re-publish, but the work is identical each time and only needs
/// doing once.
const REPUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// How long the same repair request is suppressed after being broadcast.
///
/// The core raises `Effect::RequestRepair` for *every* unreachable chunk that
/// arrives, deliberately: a request lost in transit has to be retried, and the
/// core has no clock to schedule a retry with. This is where that becomes a
/// bounded rate. Deliberately shorter than [`NEIGHBOR_COOLDOWN`] and than
/// [`REPUBLISH_MIN_INTERVAL`] — a window longer than the republish that
/// produces the unreadable chunk would suppress every retry, which is the
/// stall this mechanism exists to break.
const REPAIR_COOLDOWN: Duration = Duration::from_secs(2);

/// Rate limiter keyed on whatever distinguishes one occasion from the next.
///
/// Takes `now` as an argument rather than reading the clock, which is what
/// makes the policy testable without waiting on wall time — the same reasoning
/// that keeps `iroh-beekem-core` clock-free.
///
/// Generic in the key because its three users disagree about what "the same
/// event" means, and each disagreement is deliberate: neighbour-up repair is
/// per peer; an *outgoing* repair request is per `(target, epoch)`, so a peer
/// that becomes stuck on a new epoch is not silenced by the window it opened
/// for the old one; and *answering* a repair request is per requesting member,
/// because there the point is to limit the requester rather than the request.
#[derive(Debug)]
struct Cooldown<K> {
    seen: HashMap<K, Instant>,
    window: Duration,
}

impl<K: std::hash::Hash + Eq> Cooldown<K> {
    /// A limiter that suppresses a repeated key for `window`.
    fn new(window: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            window,
        }
    }

    /// Whether `key` may trigger its action now, recording it if so.
    ///
    /// Expired entries are pruned on the way through, so the map stays
    /// proportional to the keys seen in one window rather than to every key
    /// ever seen. Without that, a map keyed by peer id would simply move the
    /// exhaustion vector this exists to close from CPU to memory.
    fn claim(&mut self, key: K, now: Instant) -> bool {
        // An entry older than the cooldown says nothing its absence does not.
        let window = self.window;
        self.seen.retain(|_, at| now.duration_since(*at) < window);
        match self.seen.get(&key) {
            Some(at) if now.duration_since(*at) < window => false,
            _ => {
                self.seen.insert(key, now);
                true
            }
        }
    }

    /// How many keys are currently being tracked.
    ///
    /// Only the pruning test needs this; the policy itself never asks.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.seen.len()
    }
}

/// Derive the gossip topic for a workspace.
///
/// The topic is derived from the tree id rather than being random so that every
/// member computes the same one without extra coordination.
fn topic_for(tree_id: TreeId) -> TopicId {
    TopicId::from_bytes(*tree_id.as_bytes())
}

impl Workspace {
    /// Found a new workspace on this node, with `identity` as its first admin.
    ///
    /// The workspace's tree id is derived from `identity`, so founding twice
    /// with the same identity yields the same tree id — which is what makes the
    /// founder's identity worth persisting rather than generating in passing.
    ///
    /// # Errors
    ///
    /// Propagates endpoint, storage and CGKA failures.
    pub async fn create<R: CryptoRng + RngCore>(
        node: Node,
        identity: &Identity,
        info: WorkspaceInfo,
        csprng: &mut R,
    ) -> Result<Self, WorkspaceError> {
        let signer = identity.signer();
        let tree_id = TreeId::from(signer.verifying_key());
        let cgka = CgkaController::create(tree_id, signer, csprng)?;
        let secret = WorkspaceSecret::generate(csprng);

        let doc = node
            .docs()
            .api()
            .create()
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        let state = WorkspaceState::found(cgka, WorkspaceSecret::new(secret.to_bytes()))?;
        let workspace = Self::assemble(
            node,
            state,
            secret,
            doc,
            tree_id,
            identity.signer(),
            Vec::new(),
        )
        .await?;
        workspace.set_info(info).await?;
        Ok(workspace)
    }

    /// Join an existing workspace from an [`Invite`].
    ///
    /// `identity` must be the device whose [`share_key`](Identity::share_key)
    /// the inviter named when admitting it. The secret half never travels in
    /// the invite, which is what makes an intercepted invite useless for
    /// *reading*; the checks below are what make it useless for joining.
    ///
    /// Four things are checked before any state is built, in this order:
    /// the ticket's signature and the issuer's authority, that it names this
    /// device, that it has not expired, and that this node has not redeemed it
    /// before. The first three are [`Invite::verify`]; the fourth is
    /// [`Node::claim_invite`], and it comes last on purpose — a ticket that
    /// fails any earlier check must not consume the nonce, or a garbled copy
    /// would burn a legitimate ticket.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Invite`] if any of those checks fails,
    /// [`WorkspaceError::NotAdmitted`] if the log the ticket carries does not
    /// admit this device, and propagates endpoint and storage failures.
    pub async fn join<R: CryptoRng + RngCore>(
        node: Node,
        invite: &Invite,
        identity: &Identity,
        _csprng: &mut R,
    ) -> Result<Self, WorkspaceError> {
        let signer = identity.signer();
        let share_secret = identity.share_secret();

        invite.verify(identity.member_id().to_bytes(), unix_now()?)?;
        if node.claim_invite(invite.tree_id(), invite.nonce()) {
            // First redemption on this node; the nonce is now spent.
        } else {
            return Err(WorkspaceError::Invite(InviteError::Replayed));
        }
        let terms = invite.terms();

        let tree_id = TreeId::from(
            ed25519_verifying_key(&terms.tree_id).ok_or(InviteError::MalformedTreeId)?,
        );
        let cgka = CgkaController::join(tree_id, signer, share_secret, &terms.log, &terms.certs)
            .map_err(|e| WorkspaceError::NotAdmitted(e.to_string()))?;
        let secret = WorkspaceSecret::new(terms.workspace_secret);

        // `import` installs the capability *and* starts syncing with the peers
        // named in the ticket; `open` would fail here because a joiner has
        // never seen the namespace before.
        let doc = node
            .docs()
            .api()
            .import(terms.doc_ticket.clone())
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        // Bootstrap the gossip overlay against the inviter. Without a bootstrap
        // peer each node forms its own disjoint overlay and no CGKA operation
        // ever crosses between them — the data plane would sync while the
        // control plane silently did not, leaving every chunk undecryptable.
        //
        // The namespace generation comes from the ticket because the joiner
        // cannot derive it: starting at `INITIAL` instead would let a peer that
        // is itself behind re-announce an older generation and pull this node
        // onto a replica the group abandoned before it arrived.
        let state =
            WorkspaceState::joined(cgka, WorkspaceSecret::new(secret.to_bytes()), terms.epoch);
        let inviter = terms.inviter;
        let workspace = Self::assemble(
            node,
            state,
            secret,
            doc,
            tree_id,
            identity.signer(),
            vec![inviter],
        )
        .await?;
        workspace.sync_with(inviter).await?;
        Ok(workspace)
    }

    /// Resume a workspace this node already holds a snapshot for.
    ///
    /// The counterpart to [`Self::create`] and [`Self::join`], and distinct from
    /// both: neither `found` nor `joined` runs, because a restart is neither of
    /// those events. `found` would mint a second set of founding certificates
    /// for a workspace that already has them, and `joined` would restart the
    /// node at an empty manifest and namespace generation zero, walking it onto
    /// a replica the group abandoned long ago.
    ///
    /// `identity` is checked against the snapshot rather than used to rebuild
    /// it. The snapshot is self-sufficient — it carries the signing key and the
    /// leaf secret — so the argument exists to catch the caller opening somebody
    /// else's snapshot, which would otherwise succeed and quietly act as them.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::NotPersistent`] if `node` has no store,
    /// [`WorkspaceError::NoSuchWorkspace`] if it holds no snapshot for
    /// `tree_id`, [`WorkspaceError::IdentityMismatch`] if the snapshot belongs
    /// to another device, and propagates storage failures.
    pub async fn open(
        node: Node,
        tree_id: TreeId,
        identity: &Identity,
    ) -> Result<Self, WorkspaceError> {
        let store = node.store().ok_or(WorkspaceError::NotPersistent)?;
        let key = tree_id.to_bytes();
        let record = store
            .load_workspace(key)?
            .ok_or(WorkspaceError::NoSuchWorkspace { tree_id: key })?;

        let state = WorkspaceState::import(&record.core)?;
        if state.member_id() != identity.member_id() {
            return Err(WorkspaceError::IdentityMismatch);
        }
        // A snapshot names the tree it came from, so a file renamed to another
        // tree's id would otherwise resume as a workspace it is not.
        if state.tree_id() != tree_id {
            return Err(WorkspaceError::NoSuchWorkspace { tree_id: key });
        }

        let secret = WorkspaceSecret::new(state.workspace_secret());

        // `open` rather than `import`: the replica is already in this node's docs
        // store, put there by the run that took the snapshot. Re-importing would
        // need a ticket, and a founder has none — nobody ever announced the
        // namespace it created.
        let doc = node
            .docs()
            .api()
            .open(record.namespace)
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?
            .ok_or_else(|| {
                WorkspaceError::Storage(format!(
                    "workspace {} names replica {} but the docs store does not hold it",
                    tree_id, record.namespace
                ))
            })?;

        // A restarting member needs bootstrap peers just as a joiner does, and
        // for the same reason: `Gossip::subscribe` with an empty peer list forms
        // an overlay of one. Nothing else would ever reconnect it — a joiner is
        // dialled into the group by its inviter, and a restart has no inviter.
        //
        // Where a joiner is handed one peer in its ticket, a restarting member
        // already knows the whole group: its own manifest records every device's
        // endpoint, and `roster` is exactly that list intersected with current,
        // certified membership. Dialling all of them rather than one also means
        // a restart survives any single peer being offline.
        let me = *node.endpoint().id().as_bytes();
        let peers: Vec<EndpointId> = state
            .roster()
            .into_iter()
            .filter(|endpoint| *endpoint != me)
            .filter_map(|endpoint| EndpointId::from_bytes(&endpoint).ok())
            .collect();

        let workspace = Self::assemble(
            node,
            state,
            secret,
            doc,
            tree_id,
            identity.signer(),
            peers.clone(),
        )
        .await?;

        // Index sync as well as the gossip overlay, and both are needed: gossip
        // carries the control plane, `sync_with` starts the docs reconciliation
        // that carries content. Failures are logged rather than fatal — a peer
        // that has gone away must not stop a workspace from opening, and the
        // remaining peers still bring it up to date.
        for peer in peers {
            if let Err(e) = workspace.sync_with(peer).await {
                tracing::debug!(%peer, %e, "a known peer could not be reached on reopen");
            }
        }
        Ok(workspace)
    }

    /// Withdraw this user's devices from the group.
    ///
    /// Broadcasts a CGKA `Remove` for every device of the local user and stops
    /// reconciling the replica. The local copy is left in place — call
    /// [`delete`](Self::delete) for that, and see below for why the two are
    /// separate.
    ///
    /// # This is a courtesy, not a security boundary
    ///
    /// Worth being explicit about, because "leave" sounds like it revokes
    /// something and it revokes nothing:
    ///
    /// * It **does not rotate the namespace.** A removal by an admin does; a
    ///   departure cannot, because the leaver would be minting the capability it
    ///   is walking away from and announcing it under a key it still holds.
    /// * It **unlearns nothing.** The leaver keeps every key it ever derived,
    ///   the blinding secret, and whatever it already synced.
    /// * It is **self-reported.** A departing member cannot be trusted to have
    ///   done it, and a hostile one simply will not.
    ///
    /// An administrator who wants any of those guarantees must follow a `leave`
    /// with [`remove_user`](Self::remove_user), which rotates the namespace and
    /// evicts the departed device from every peer's roster. Until they do, the
    /// group has lost a member's leaf and gained nothing else.
    ///
    /// # This announces the departure; it does not stop the workspace
    ///
    /// Deliberately `&self`, and the reason is a property of `iroh-gossip` rather
    /// than a preference. `GossipSender::broadcast` enqueues a command on a
    /// channel the topic actor drains: it returns when the message is *accepted*,
    /// not when it has reached anybody, and there is no flush and no
    /// acknowledgement to wait on. Dropping the subscription discards whatever is
    /// still queued.
    ///
    /// So a `leave` that consumed `self` and tore the transport down would be
    /// racing its own announcement, and losing often enough to matter — with no
    /// second chance, because a `Remove` has no anti-entropy behind it and the
    /// one node that would re-announce it is the one that just left. Bounding
    /// that race with a sleep only turns a frequent failure into an occasional
    /// one; keeping the workspace alive removes it, and puts the lifetime
    /// decision where the caller can actually see it.
    ///
    /// The usual sequence is therefore:
    ///
    /// ```ignore
    /// workspace.leave().await?;   // announce
    /// // ... the workspace keeps running, which is what lets the announcement out
    /// workspace.delete().await?;  // when the local copy is no longer wanted
    /// ```
    ///
    /// A departure that never reaches a peer simply did not happen, which is one
    /// more reason an admin should follow it with
    /// [`remove_user`](Self::remove_user).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::LastAdmin`](iroh_beekem_core::CoreError::LastAdmin)
    /// if this user is the workspace's only administrator — a workspace that
    /// lost its last admin could never appoint another.
    pub async fn leave(&self) -> Result<(), WorkspaceError> {
        self.drive(Event::Leave).await?;

        // Stop reconciling the index. Distinct from `drop_doc` in `delete`,
        // which removes the replica: this stops the exchange, so a peer that has
        // not yet merged the removal stops receiving from us immediately rather
        // than at whatever point it works out we are gone.
        if let Err(e) = doc(&self.inner).await.leave().await {
            tracing::debug!(%e, "the replica could not be left cleanly");
        }
        Ok(())
    }

    /// Stop holding this workspace on this node, locally and completely.
    ///
    /// Drops the replica, the snapshot and this workspace's entry in the
    /// admission registry, then shuts the pumps down. Consumes `self` because
    /// every one of those makes the handle unusable, and returning one that
    /// silently fails on its next call would be worse than not returning one.
    ///
    /// # This is a local action, not a membership one
    ///
    /// The group is not told and does not change: this device keeps its leaf,
    /// stays on every peer's roster, and still appears in
    /// [`users`](Self::users) everywhere else. Deleting is "I no longer keep a
    /// copy", not "I am no longer a member" — for the latter an admin must
    /// [`remove_user`](Self::remove_user), which is what rotates the namespace
    /// and actually withdraws reading.
    ///
    /// The blinding secret is dropped here and is `ZeroizeOnDrop`, but that
    /// buys less than it looks: every other member holds the same 32 bytes, and
    /// anything already synced into the blobs store stays there.
    ///
    /// # Errors
    ///
    /// Propagates storage failures. The snapshot is removed *last*, so a failure
    /// to drop the replica leaves a workspace that still opens rather than one
    /// whose files are orphaned with no way to name them.
    pub async fn delete(self) -> Result<(), WorkspaceError> {
        let namespace = self.namespace().await;
        self.node
            .docs()
            .api()
            .drop_doc(namespace)
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        // Before the snapshot is removed: a peer admitted by this workspace and
        // by no other must stop being admitted, and `admits` is a union over
        // workspaces, so only forgetting the entry achieves that.
        self.inner.roster.forget(self.inner.workspace_key);

        if let Some(store) = self.node.store() {
            store.remove_workspace(self.inner.workspace_key)?;
        }
        // `Drop` aborts the pumps; taking `self` by value is what guarantees it
        // runs before the caller can drive this workspace again.
        Ok(())
    }

    /// Every workspace this node holds a snapshot for.
    ///
    /// Each entry is decoded far enough to name itself, which means importing
    /// the core snapshot — the display name lives in the encrypted manifest and
    /// there is nowhere cheaper to read it from. A snapshot that cannot be
    /// decoded is *skipped* rather than failing the listing, so one damaged
    /// workspace does not hide the others from a caller trying to recover.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::NotPersistent`] if `node` has no store, and
    /// propagates a failure to list the directory.
    pub fn list(node: &Node) -> Result<Vec<WorkspaceSummary>, WorkspaceError> {
        let store = node.store().ok_or(WorkspaceError::NotPersistent)?;
        Ok(store
            .list_workspaces()?
            .into_iter()
            .filter_map(|key| {
                let record = store.load_workspace(key).ok().flatten()?;
                let state = WorkspaceState::import(&record.core).ok()?;
                Some(WorkspaceSummary {
                    tree_id: state.tree_id(),
                    info: state.manifest().info(),
                    namespace: record.namespace,
                })
            })
            .collect())
    }

    /// Wire up the pump loops shared by [`Self::create`] and [`Self::join`].
    #[allow(
        clippy::too_many_arguments,
        reason = "every argument is a distinct piece of already-constructed state that \
                  `create` and `join` build differently; bundling them into a struct would \
                  add a type whose only purpose is to be destructured on the next line"
    )]
    async fn assemble(
        node: Node,
        state: WorkspaceState,
        secret: WorkspaceSecret,
        doc: Doc,
        tree_id: TreeId,
        signer: MemorySigner,
        bootstrap: Vec<EndpointId>,
    ) -> Result<Self, WorkspaceError> {
        let topic = topic_for(tree_id);

        // A per-workspace author, *derived* rather than random, and both halves
        // of that matter.
        //
        // Per-workspace: `AuthorId` syncs in the clear on every entry, so reusing
        // one identity across workspaces would let a syncing peer link them to
        // the same device. `author_seed` is keyed on the workspace secret, so two
        // workspaces on one device get unrelated authors.
        //
        // Derived: a random author is a new identity on every start. After a
        // restart every peer's `author_may_write` would reject this node's
        // entries — the author→member mapping they hold names an id that no
        // longer writes — and it would stay mute until an admin noticed and
        // granted a role to an identity nobody had ever seen. The seed is a
        // function of the workspace secret and this member id, both of which
        // survive a restart, so the identity does too.
        let author = Author::from_bytes(&secret.author_seed(&state.member_id().to_bytes()));
        let author_id = author.id();
        node.docs()
            .api()
            .author_import(author)
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        // The gossip bootstrap peers are also the connection bootstrap: a joiner
        // must be able to reach its inviter before it holds the manifest that
        // would derive a roster, and the inviter's guard must let it back in.
        // Seeding both from the same list is what keeps the two in step.
        let workspace_key = *tree_id.as_bytes();
        for peer in &bootstrap {
            node.roster().add_bootstrap(workspace_key, *peer);
        }

        let gossip_topic = node
            .gossip()
            .subscribe(topic, bootstrap)
            .await
            .map_err(|e| WorkspaceError::Gossip(e.to_string()))?;
        let (gossip_tx, gossip_rx) = gossip_topic.split();

        let endpoint_id = node.endpoint().id();
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            blobs: node.blobs().clone(),
            doc: RwLock::new(doc.clone()),
            data_task: Mutex::new(None),
            author: author_id,
            gossip_tx,
            secret,
            signer,
            seen_entries: Mutex::new(HashMap::new()),
            neighbor_cooldown: Mutex::new(Cooldown::new(NEIGHBOR_COOLDOWN)),
            repair_cooldown: Mutex::new(Cooldown::new(REPAIR_COOLDOWN)),
            repair_answer_cooldown: Mutex::new(Cooldown::new(REPAIR_COOLDOWN)),
            eviction_cooldown: Mutex::new(Cooldown::new(EVICTION_COOLDOWN)),
            republish_wanted: Notify::new(),
            roster: node.roster().clone(),
            workspace_key,
            node: node.clone(),
        });

        // Claim this workspace's author identity in the manifest. Until a peer
        // has seen this, it has no way to connect entries signed by this author
        // to the member the roles are written about, and will refuse them. This
        // also performs the manifest's first write to the replica.
        //
        // The endpoint announcement rides alongside for the same reason one
        // step further out: until a peer has seen it, this device is on nobody's
        // roster and its connections are refused. A joiner's manifest has no
        // device record to attach it to yet, so the core remembers it and
        // re-applies it on the first manifest that does.
        let announce = {
            let mut state = inner.state.lock().await;
            let mut effects = report_rejection(state.handle(
                Event::AnnounceAuthor {
                    author: author_id.to_bytes(),
                },
                &mut rand::rngs::OsRng,
            ));
            effects.extend(report_rejection(state.handle(
                Event::AnnounceEndpoint {
                    endpoint_id: *endpoint_id.as_bytes(),
                },
                &mut rand::rngs::OsRng,
            )));
            effects
        };
        apply_effects(&inner, announce).await;
        // The founder already has its own device record, so it derives a roster
        // straight away; a joiner derives an empty one and relies on the
        // bootstrap entry until its first manifest arrives.
        refresh_roster(&inner).await;

        // Control plane: CGKA operations arriving over gossip.
        let control = Arc::clone(&inner);
        let control_task = tokio::spawn(control_loop(control, gossip_rx));

        // Data plane: entries and content arriving over docs and blobs. Held on
        // `Inner` rather than alongside the others because a rotation replaces
        // it; see `spawn_data_loop`.
        spawn_data_loop(&inner).await?;

        // Anti-entropy: re-announcements requested by the control loop, run at
        // a bounded rate but never discarded.
        let republish = Arc::clone(&inner);
        let republish_task = tokio::spawn(republish_loop(republish));

        // The first snapshot, so that a workspace created or joined and then
        // immediately shut down is still there on the next start. Without it the
        // earliest durable point would be the first edit, and a founder that
        // crashed before writing anything would have lost the founding
        // certificates that make it the root of its own capability closure.
        persist(&inner).await;

        Ok(Self {
            node,
            inner,
            tree_id,
            topic,
            tasks: vec![control_task, republish_task],
        })
    }

    /// Begin syncing the index with a peer.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the sync cannot be started.
    pub async fn sync_with(&self, peer: EndpointId) -> Result<(), WorkspaceError> {
        doc(&self.inner)
            .await
            .start_sync(vec![peer.into()])
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))
    }

    /// This node's dialable address: its endpoint id plus the paths to reach it.
    ///
    /// [`Self::endpoint_id`] is what identifies and authorises a peer; this is
    /// what a peer needs to actually open a connection to one.
    #[must_use]
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.node.endpoint().addr()
    }

    /// The node this workspace runs on.
    #[must_use]
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// This node's endpoint id, for peers to dial.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.node.endpoint().id()
    }

    /// The `iroh-docs` namespace backing this workspace *right now*.
    ///
    /// Not stable for the lifetime of the workspace: a removal abandons the
    /// namespace for a fresh one, so an application holding this across a
    /// membership change is holding a stale identifier.
    pub async fn namespace(&self) -> NamespaceId {
        doc(&self.inner).await.id()
    }

    /// Which generation of the replicated index this node is syncing.
    ///
    /// Advances on every removal. A device removed at generation *n* never
    /// receives the capability for *n+1*, so a peer stuck on an older
    /// generation is one the group has moved on without.
    pub async fn namespace_epoch(&self) -> NamespaceEpoch {
        self.inner.state.lock().await.namespace()
    }

    /// The CGKA tree id.
    #[must_use]
    pub fn tree_id(&self) -> TreeId {
        self.tree_id
    }

    /// This node's identity in the CGKA tree.
    pub async fn member_id(&self) -> MemberId {
        self.inner.state.lock().await.member_id()
    }

    /// The control-plane gossip topic.
    #[must_use]
    pub fn topic(&self) -> TopicId {
        self.topic
    }

    /// Feed one event to the core and perform whatever it asks for.
    ///
    /// Every mutating method funnels through here. Before this existed the same
    /// eight lines — lock, handle, drop the guard, apply — were repeated in a
    /// dozen methods, and the CRUD surface below would have repeated them in a
    /// dozen more. Note that the guard is dropped *before* the effects are
    /// performed: holding it across the network writes in `apply_effects` would
    /// serialise the whole workspace behind one blob upload.
    async fn drive(&self, event: Event) -> Result<(), WorkspaceError> {
        // Checked before the event is consumed, and only for the handful of
        // events that can move the roster. Refreshing unconditionally would put
        // a manifest device scan behind every keystroke; refreshing nowhere
        // would mean a locally issued removal took effect on every peer except
        // the one that issued it.
        let membership_moved = matches!(
            event,
            Event::AddUser { .. }
                | Event::AddDevice { .. }
                | Event::RemoveMember { .. }
                | Event::AnnounceEndpoint { .. }
        );
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(event, &mut rand::rngs::OsRng)?
        };
        apply_effects(&self.inner, effects).await;
        if membership_moved {
            refresh_roster(&self.inner).await;
        }
        // Before `Ok`, not after: a caller told its write succeeded must find
        // that write again after a restart.
        persist(&self.inner).await;
        Ok(())
    }

    // ---- users and devices -------------------------------------------------

    /// Admit a new person, along with their first device, and build the invite
    /// they need.
    ///
    /// The role is chosen here rather than defaulted, because it decides what
    /// capability the invite carries: a viewer's ticket grants read access to
    /// the replica, an editor's grants write.
    ///
    /// The [`Enrollment`] carries the invitee's transport address as well as
    /// their key material, and that address admits them to this node's roster
    /// before the invite is handed over. It is required rather than optional
    /// because the alternative is a deadlock: an admitted device cannot sync
    /// until it is on somebody's roster, and it cannot reach a roster until its
    /// address has propagated through the manifest — which it cannot receive
    /// without syncing. The caller already has to obtain the invitee's key
    /// material out of band, so their `EndpointId` comes from the same exchange
    /// at no extra cost.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `NotAnAdmin` unless this node
    /// is an admin, [`WorkspaceError::Identity`] if the enrollment is malformed,
    /// and propagates CGKA failures.
    pub async fn add_user(
        &self,
        enrollment: &Enrollment,
        role: Role,
        display_name: &str,
    ) -> Result<Invite, WorkspaceError> {
        self.drive(Event::AddUser {
            member: enrollment.member_id()?,
            share_key: enrollment.share_key(),
            role,
            display_name: display_name.to_string(),
            endpoint: Some(enrollment.endpoint()?.as_bytes().to_owned()),
        })
        .await?;
        self.build_invite(enrollment.member_bytes(), role).await
    }

    /// Admit another device for an existing person.
    ///
    /// Enrolling a device for *your own* user needs no administrative role;
    /// binding one to somebody else's does, or any member could inherit an
    /// admin's permissions by claiming to be one of their devices.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `NotThisUsersDevice` if this
    /// node may not act for `user`, and [`WorkspaceError::Identity`] if the
    /// enrollment is malformed.
    pub async fn add_device(
        &self,
        enrollment: &Enrollment,
        user: [u8; 32],
        label: &str,
    ) -> Result<Invite, WorkspaceError> {
        self.drive(Event::AddDevice {
            member: enrollment.member_id()?,
            share_key: enrollment.share_key(),
            user,
            label: label.to_string(),
            endpoint: Some(enrollment.endpoint()?.as_bytes().to_owned()),
        })
        .await?;
        let role = {
            let state = self.inner.state.lock().await;
            state.capabilities().role_of(&user).unwrap_or(Role::Viewer)
        };
        self.build_invite(enrollment.member_bytes(), role).await
    }

    /// Build the ticket a freshly admitted device needs.
    ///
    /// A viewer gets a read-only capability. `iroh-docs` has no per-member write
    /// key, so a write ticket is impossible to withdraw short of rotating the
    /// namespace — handing one to somebody who is not supposed to write is a
    /// capability given away for nothing.
    ///
    /// `invitee` is the device the ticket is minted *for*, and it goes inside
    /// the signature: without it a leaked ticket is a bearer token any holder
    /// can redeem, and with it a thief has to break Ed25519 to re-address one.
    ///
    /// The log and the certificates are taken *after* the admission that
    /// preceded this call, so the bundle already contains the invitee's own
    /// binding and grant — which is what lets it arrive certified rather than
    /// waiting for a second exchange.
    async fn build_invite(&self, invitee: [u8; 32], role: Role) -> Result<Invite, WorkspaceError> {
        let (log, certs, epoch) = {
            let state = self.inner.state.lock().await;
            (
                state.op_log()?,
                state.capabilities().certificates(),
                state.namespace().epoch,
            )
        };
        let mode = if role.can_write() {
            ShareMode::Write
        } else {
            ShareMode::Read
        };
        let doc_ticket = doc(&self.inner)
            .await
            .share(mode, AddrInfoOptions::RelayAndAddresses)
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        let (nonce, not_after) = Invite::terms_now(&mut rand::rngs::OsRng)?;
        Ok(Invite::sign(
            InviteTerms {
                domain: INVITE_DOMAIN,
                tree_id: *self.tree_id.as_bytes(),
                invitee,
                not_after,
                nonce,
                epoch,
                doc_ticket,
                workspace_secret: self.inner.secret.to_bytes(),
                log,
                certs,
                inviter: self.endpoint_id(),
            },
            &self.inner.signer,
        )?)
    }

    /// Revoke one device, so it cannot read anything written afterwards.
    ///
    /// A person's other devices are unaffected. To remove a person entirely,
    /// use [`Self::remove_user`].
    ///
    /// # Errors
    ///
    /// Propagates CGKA failures.
    pub async fn remove_device(&self, member: MemberId) -> Result<(), WorkspaceError> {
        self.drive(Event::RemoveMember { member }).await
    }

    /// Revoke every device belonging to a person.
    ///
    /// # Errors
    ///
    /// Propagates CGKA failures. If one device cannot be removed the rest are
    /// still attempted, and the first failure is returned.
    pub async fn remove_user(&self, user: [u8; 32]) -> Result<(), WorkspaceError> {
        let devices: Vec<MemberId> = {
            let state = self.inner.state.lock().await;
            state
                .devices_of(&user)
                .iter()
                .filter_map(|d| member_id_from_bytes(&d.member))
                .collect()
        };
        let mut first_error = None;
        for device in devices {
            if let Err(err) = self.remove_device(device).await {
                first_error = first_error.or(Some(err));
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Assign a role to a **user**, covering all of their devices.
    ///
    /// Demoting an admin who stays in the workspace is a pure manifest edit
    /// with no key rotation; removing them entirely also needs
    /// [`Self::remove_user`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `NotAnAdmin` if this node is
    /// not an admin, or `LastAdmin` if the change would leave none.
    pub async fn set_role(&self, user: [u8; 32], role: Role) -> Result<(), WorkspaceError> {
        self.drive(Event::SetRole { user, role }).await
    }

    /// Every person in the workspace, with their devices and role.
    pub async fn users(&self) -> Vec<User> {
        let state = self.inner.state.lock().await;
        // Display names come from the manifest; roles and devices from the
        // capability closure. The join is deliberate rather than incidental —
        // it is what keeps the attacker-writable half separate from the half
        // that grants something.
        state
            .manifest()
            .users()
            .into_iter()
            .map(|record| User {
                role: state.capabilities().role_of(&record.id),
                devices: state.devices_of(&record.id),
                id: record.id,
                display_name: record.display_name,
            })
            .collect()
    }

    /// Look up one person.
    pub async fn user(&self, user: [u8; 32]) -> Option<User> {
        self.users().await.into_iter().find(|u| u.id == user)
    }

    /// This device, and the person it belongs to.
    ///
    /// Returns `None` until the records naming this device have synced, which
    /// for a joiner is a normal early state rather than an error.
    pub async fn me(&self) -> Option<User> {
        let member = {
            let state = self.inner.state.lock().await;
            state.member_id().to_bytes()
        };
        let user = {
            let state = self.inner.state.lock().await;
            state.capabilities().user_of(&member)?
        };
        self.user(user).await
    }

    /// Set the display name of the person this device belongs to.
    ///
    /// Self-only, by design: a display name is how someone presents themselves,
    /// and letting one member rename another is an impersonation vector rather
    /// than a convenience.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `UnknownDevice` if the records
    /// naming this device have not synced yet.
    pub async fn set_display_name(&self, display_name: &str) -> Result<(), WorkspaceError> {
        self.drive(Event::SetDisplayName {
            display_name: display_name.to_string(),
        })
        .await
    }

    /// Every role the capability closure grants, keyed by user.
    pub async fn roles(&self) -> Vec<([u8; 32], Role)> {
        self.inner.state.lock().await.capabilities().roles()
    }

    // ---- workspace ---------------------------------------------------------

    /// This workspace's name and description.
    pub async fn info(&self) -> WorkspaceInfo {
        self.inner.state.lock().await.manifest().info()
    }

    /// Rename or re-describe the workspace.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `NotAnAdmin` unless this node
    /// is an admin.
    pub async fn set_info(&self, info: WorkspaceInfo) -> Result<(), WorkspaceError> {
        self.drive(Event::SetInfo { info }).await
    }

    // ---- files -------------------------------------------------------------

    /// Create a document and record it in the manifest.
    ///
    /// The returned UUID, not the path, is what identifies the document from
    /// here on: renaming changes only a manifest field, leaving every stored
    /// chunk exactly where it is.
    ///
    /// # Errors
    ///
    /// Propagates encryption and manifest failures.
    pub async fn create_file(
        &self,
        path: &str,
        mime_type: &str,
    ) -> Result<DocumentUuid, WorkspaceError> {
        let uuid = DocumentUuid::generate(&mut rand::rngs::OsRng);
        self.drive(Event::UpsertFile {
            entry: FileEntry {
                uuid,
                logical_path: path.to_string(),
                mime_type: mime_type.to_string(),
            },
        })
        .await?;
        Ok(uuid)
    }

    /// Record or replace a document's metadata.
    ///
    /// Logical paths live only here, never in `iroh-docs`, which sees a blinded
    /// 32-byte key and nothing else.
    ///
    /// # Errors
    ///
    /// Propagates encryption and manifest failures.
    pub async fn upsert_file(&self, entry: FileEntry) -> Result<(), WorkspaceError> {
        self.drive(Event::UpsertFile { entry }).await
    }

    /// Every document the manifest records, with its logical path.
    pub async fn files(&self) -> Vec<FileEntry> {
        self.inner.state.lock().await.manifest().files()
    }

    /// Resolve a logical path to the document it names.
    pub async fn resolve(&self, path: &str) -> Option<DocumentUuid> {
        self.inner.state.lock().await.manifest().resolve_path(path)
    }

    /// A document's current text as this node sees it.
    pub async fn read(&self, doc: DocumentUuid) -> String {
        self.inner.state.lock().await.document_text(doc)
    }

    /// Read a document by its logical path.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::NoSuchPath`] if the manifest has no such path.
    pub async fn read_path(&self, path: &str) -> Result<String, WorkspaceError> {
        let doc = self
            .resolve(path)
            .await
            .ok_or_else(|| WorkspaceError::NoSuchPath(path.to_string()))?;
        Ok(self.read(doc).await)
    }

    /// Append text to a document.
    ///
    /// # Errors
    ///
    /// Propagates encryption and storage failures.
    pub async fn append(&self, doc: DocumentUuid, text: &str) -> Result<(), WorkspaceError> {
        self.drive(Event::LocalEdit {
            doc,
            text: text.to_string(),
        })
        .await
    }

    /// Replace a document's entire contents.
    ///
    /// Diffed against the current text rather than cleared and rewritten, so a
    /// one-word change stays a one-word change in the CRDT and still merges
    /// with a concurrent edit elsewhere in the document.
    ///
    /// # Errors
    ///
    /// Propagates encryption and storage failures.
    pub async fn write(&self, doc: DocumentUuid, text: &str) -> Result<(), WorkspaceError> {
        self.drive(Event::WriteFile {
            doc,
            text: text.to_string(),
        })
        .await
    }

    /// Insert text at a character offset, clamped to the document's length.
    ///
    /// # Errors
    ///
    /// Propagates encryption and storage failures.
    pub async fn insert(
        &self,
        doc: DocumentUuid,
        pos: usize,
        text: &str,
    ) -> Result<(), WorkspaceError> {
        self.drive(Event::InsertText {
            doc,
            pos,
            text: text.to_string(),
        })
        .await
    }

    /// Delete a range of text, clamped to what the document actually holds.
    ///
    /// # Errors
    ///
    /// Propagates encryption and storage failures.
    pub async fn remove(
        &self,
        doc: DocumentUuid,
        pos: usize,
        len: usize,
    ) -> Result<(), WorkspaceError> {
        self.drive(Event::RemoveText { doc, pos, len }).await
    }

    /// Move or rename a document.
    ///
    /// Touches only the manifest: the document's UUID, and therefore its
    /// blinded key and every chunk already stored under it, are untouched.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `UnknownDocument` if the
    /// manifest has no such document.
    pub async fn rename(&self, doc: DocumentUuid, path: &str) -> Result<(), WorkspaceError> {
        self.drive(Event::RenameFile {
            doc,
            path: path.to_string(),
        })
        .await
    }

    /// Delete a document from the workspace.
    ///
    /// **Not erasure.** It withdraws this node's index entry and tombstones the
    /// manifest record, so the document disappears from every peer's view as
    /// they observe it. It cannot remove the plaintext from the disk of anyone
    /// who already synced it, and `iroh-docs` deletion is per author, so each
    /// member withdraws their own entry as they process the tombstone.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `UnknownDocument` if the
    /// manifest has no such document.
    pub async fn delete_file(&self, doc: DocumentUuid) -> Result<(), WorkspaceError> {
        self.drive(Event::DeleteFile { doc }).await
    }

    // ---- maintenance -------------------------------------------------------

    /// Rotate this device's leaf key, re-keying its path to the root.
    ///
    /// This is the post-compromise security primitive, and the reason BeeKEM is
    /// here rather than a static group key: an attacker holding this device's
    /// old leaf secret can derive no group key produced after the rotation.
    /// Recovery from a compromise is therefore something a member can do
    /// unilaterally, without the group re-forming around them.
    ///
    /// Needs no administrative role — rotating your own key harms nobody, and
    /// requiring permission to recover from a compromise would be backwards.
    ///
    /// # Errors
    ///
    /// Propagates CGKA failures.
    pub async fn rotate(&self) -> Result<(), WorkspaceError> {
        self.drive(Event::Rotate).await
    }

    /// Re-publish every document's current state under the current epoch key.
    ///
    /// Two distinct jobs, both necessary:
    ///
    /// * **Granting a new member access to existing content.** A joiner
    ///   reconstructs the group from the operation log, but not the historical
    ///   PCS keys, so they *cannot* decrypt anything written before they were
    ///   admitted. That is forward secrecy working as intended, not a defect.
    ///   Re-publishing after an invite re-encrypts current state under a key the
    ///   new member can derive.
    /// * **Anti-entropy.** A chunk lost in transit has no later chunk to carry
    ///   its content until someone edits again; a periodic re-announcement
    ///   closes that gap.
    ///
    /// # Errors
    ///
    /// Propagates encryption and storage failures.
    pub async fn resync(&self) -> Result<(), WorkspaceError> {
        for doc in self.files().await.into_iter().map(|f| f.uuid) {
            self.drive(Event::Resync { doc }).await?;
        }
        // The manifest is published only when it changes, so unlike a document
        // it has no later write to carry lost content. Device records live
        // there and the roster derives from them, which makes a lost manifest
        // chunk cost a peer its place on somebody's roster until the next
        // membership change happens to republish it.
        self.drive(Event::ResyncManifest).await?;
        // And the rotation, for the same reason one step further out: a
        // rotation is announced once, so a member that missed it goes on
        // syncing a replica the group has abandoned.
        self.drive(Event::ResyncNamespace).await
    }

    /// Chunks parked awaiting key material or CRDT dependencies.
    pub async fn pending(&self) -> usize {
        self.inner.state.lock().await.pending_len()
    }

    /// How many members this node believes are in the group.
    pub async fn group_size(&self) -> u32 {
        self.inner.state.lock().await.group_size()
    }

    /// Diagnostic: how many index entries exist across this workspace's
    /// documents, and how many of their payloads are locally available.
    pub async fn index_status(&self) -> (usize, usize) {
        let mut keys: Vec<[u8; 32]> = self
            .files()
            .await
            .into_iter()
            .map(|f| *self.inner.secret.storage_key(f.uuid).as_bytes())
            .collect();
        keys.push(*self.inner.secret.manifest_key().as_bytes());

        let (mut total, mut local) = (0, 0);
        for key in keys {
            let Ok(entries) = doc(&self.inner)
                .await
                .get_many(Query::key_exact(Bytes::copy_from_slice(&key)))
                .await
            else {
                continue;
            };
            let mut entries = std::pin::pin!(entries);
            while let Some(Ok(entry)) = entries.next().await {
                total += 1;
                if self
                    .inner
                    .blobs
                    .get_bytes(entry.content_hash())
                    .await
                    .is_ok()
                {
                    local += 1;
                }
            }
        }
        (total, local)
    }

    /// Pull and apply anything already present in the index.
    ///
    /// Called automatically on sync events; exposed so tests and applications
    /// can force a catch-up without waiting for the next event.
    pub async fn ingest(&self) {
        ingest_all(&self.inner).await;
    }

    /// Shut down the underlying node.
    ///
    /// # Errors
    ///
    /// Propagates router shutdown failures.
    pub async fn shutdown(&self) -> Result<(), WorkspaceError> {
        self.node.shutdown().await
    }
}

/// Pump the control plane: verified CGKA operations arriving over gossip.
async fn control_loop<E>(
    inner: Arc<Inner>,
    mut gossip_rx: impl n0_future::Stream<Item = Result<GossipEvent, E>> + Unpin,
) {
    while let Some(event) = gossip_rx.next().await {
        let msg = match event {
            Ok(GossipEvent::Received(msg)) => msg,
            // A peer just joined the overlay. They cannot decrypt anything
            // written before they were admitted — that is forward secrecy — so
            // re-publish current state under the present epoch key, which they
            // *can* derive. This is the moment to do it: before now they were
            // not listening.
            Ok(GossipEvent::NeighborUp(peer)) => {
                let allowed = {
                    let mut cooldown = inner.neighbor_cooldown.lock().await;
                    cooldown.claim(peer, Instant::now())
                };
                if !allowed {
                    // This peer already had its repair recently. Suppressing the
                    // repeat is safe precisely because the first one succeeded.
                    tracing::debug!(%peer, "suppressing a repeat neighbour-up repair");
                    continue;
                }
                // Order matters: the peer needs our operation log before it can
                // derive the key for anything we re-publish afterwards.
                send_log(&inner).await;
                // Requested, not performed. The republish is rate-limited
                // globally, and dropping it outright would be a correctness bug
                // rather than a mere optimisation — see `republish_loop`.
                inner.republish_wanted.notify_one();
                continue;
            }
            _ => continue,
        };
        let Ok(decoded) = ControlMsg::decode(&msg.content) else {
            continue;
        };
        handle_control_msg(&inner, decoded).await;
    }
}

/// Handle one decoded control-plane message.
///
/// Split out of [`control_loop`] so the loop stays about *stream lifecycle* —
/// neighbour arrivals, decode failures — and this stays about protocol. They grew
/// together and the seam is the natural one: everything here takes the state lock,
/// nothing here touches the gossip stream.
async fn handle_control_msg(inner: &Arc<Inner>, decoded: ControlMsg) {
    apply_control_msg(inner, decoded).await;
    // One write per message rather than one per effect batch: a `Log` exchange
    // replays the whole operation history under a single lock, and this is the
    // boundary at which that history has finished being applied.
    persist(inner).await;
}

/// The protocol half of [`handle_control_msg`], separated so persistence happens
/// exactly once however many effect batches the message produced.
async fn apply_control_msg(inner: &Arc<Inner>, decoded: ControlMsg) {
    match decoded {
        ControlMsg::Op { op, proof } => {
            let effects = {
                let mut state = inner.state.lock().await;
                report_rejection(state.handle(
                    Event::ControlOp(AuthorizedOp::new(*op, proof)),
                    &mut rand::rngs::OsRng,
                ))
            };
            apply_effects(inner, effects).await;
            ingest_all(inner).await;
        }
        ControlMsg::Certs(certs) => {
            if certs.len() > MAX_LOG_CERTS {
                tracing::warn!(
                    len = certs.len(),
                    "discarding an oversized certificate batch"
                );
                return;
            }
            let effects = {
                let mut state = inner.state.lock().await;
                report_rejection(state.handle(Event::CertsArrived(certs), &mut rand::rngs::OsRng))
            };
            apply_effects(inner, effects).await;
            ingest_all(inner).await;
        }
        ControlMsg::Log { ops, certs } => {
            if ops.len() > MAX_LOG_OPS || certs.len() > MAX_LOG_CERTS {
                tracing::warn!(
                    ops = ops.len(),
                    certs = certs.len(),
                    "discarding an oversized operation log"
                );
                return;
            }
            let mut effects = Vec::new();
            {
                let mut state = inner.state.lock().await;
                // Certificates strictly first: they authorise the `Add`s in
                // the log, so replaying the operations against an empty
                // closure would refuse the history this exchange exists to
                // hand over.
                effects.append(&mut report_rejection(
                    state.handle(Event::CertsArrived(certs), &mut rand::rngs::OsRng),
                ));
                for op in ops {
                    let outcome = state.handle(
                        Event::ControlOp(AuthorizedOp::bare(Arc::new(op))),
                        &mut rand::rngs::OsRng,
                    );
                    effects.append(&mut report_rejection(outcome));
                }
            }
            apply_effects(inner, effects).await;
            // Newly recovered key material may unlock chunks that have been
            // parked since before this peer caught up.
            ingest_all(inner).await;
        }
        // The index sync will surface the entry; the announce only prompts
        // us to look sooner.
        ControlMsg::Announce { .. } => {
            ingest_all(inner).await;
        }
        // The group has abandoned the namespace this node is syncing. The
        // capability is encrypted under the group key, so a device removed
        // before the rotation simply cannot read it and stays behind —
        // which is the whole purpose of rotating rather than asking nicely.
        ControlMsg::Namespace { epoch, chunk } => {
            let effects = {
                let mut state = inner.state.lock().await;
                report_rejection(state.handle(
                    Event::NamespaceArrived { epoch, chunk },
                    &mut rand::rngs::OsRng,
                ))
            };
            apply_effects(inner, effects).await;
        }
        // Somebody cannot read what we publish. Answering re-keys the
        // group, so the core checks the requester is a member *now* before
        // any of that happens; a refusal is logged rather than fatal, since
        // a revoked device asking is an expected thing to see on a topic
        // every past invitee can reach.
        ControlMsg::Repair {
            member,
            target,
            epoch,
        } => {
            let Some(requester) = member_id_from_bytes(&member) else {
                tracing::warn!("discarding a repair request naming an unparseable member");
                return;
            };
            // Checked before the core is asked to do anything, because what
            // is being limited is the *work*: a member ignoring its own
            // sending cooldown must not be able to buy more re-keys by
            // shouting.
            let allowed = {
                let mut cooldown = inner.repair_answer_cooldown.lock().await;
                cooldown.claim(member, Instant::now())
            };
            if !allowed {
                tracing::debug!("suppressing a repeat repair answer for one peer");
                return;
            }
            let effects = {
                let mut state = inner.state.lock().await;
                report_rejection(state.handle(
                    Event::RepairRequested {
                        requester,
                        target,
                        epoch,
                    },
                    &mut rand::rngs::OsRng,
                ))
            };
            apply_effects(inner, effects).await;
        }
    }
}

/// Pump the data plane: entries and payloads arriving over docs and blobs.
async fn data_loop<E>(
    inner: Arc<Inner>,
    mut doc_events: impl n0_future::Stream<Item = Result<LiveEvent, E>> + Unpin,
) {
    while let Some(event) = doc_events.next().await {
        // `InsertRemote` fires when the index entry lands, which may be before
        // the payload has been fetched; `ContentReady` fires once the bytes are
        // actually local. React to both, so a payload that happened to be
        // present already is not missed.
        if let Ok(LiveEvent::InsertRemote { .. } | LiveEvent::ContentReady { .. }) = event {
            ingest_all(&inner).await;
        }
    }
}

/// Unwrap the effects of handling a control operation, logging any rejection.
///
/// A rejected operation is a normal, expected outcome on a public topic that
/// anyone with an old invite can reach — it is not a reason to tear down the
/// pump. It is, however, exactly the event an operator wants to see, so it is
/// logged rather than discarded the way an ordinary `unwrap_or_default` would.
fn report_rejection(outcome: Result<Vec<Effect>, iroh_beekem_core::CoreError>) -> Vec<Effect> {
    match outcome {
        Ok(effects) => effects,
        Err(err) => {
            tracing::warn!(%err, "rejected an incoming control operation");
            Vec::new()
        }
    }
}

/// Re-announce document state on request, at a bounded rate.
///
/// The republish is **deferred, never dropped**, and the distinction is the
/// whole point of this task. A member cannot decrypt anything written before
/// they were admitted, so this re-announcement is the only thing that makes
/// existing content readable to a peer that has just joined. Rate-limiting it
/// by discarding requests would therefore not cost throughput, it would leave
/// new members permanently unable to see documents that already exist.
///
/// [`Notify::notify_one`] stores a single permit, which gives coalescing for
/// free: any number of requests arriving during a republish or its quiet period
/// collapse into exactly one follow-up, and none is lost.
async fn republish_loop(inner: Arc<Inner>) {
    loop {
        inner.republish_wanted.notified().await;
        republish(&inner).await;
        // Quiet period. Requests raised during it are remembered by the stored
        // permit and serviced on the next turn of the loop.
        tokio::time::sleep(REPUBLISH_MIN_INTERVAL).await;
    }
}

/// Broadcast our full CGKA operation log, so a peer that missed anything can
/// repair its own state.
async fn send_log(inner: &Inner) {
    let (log, certs) = {
        let state = inner.state.lock().await;
        (state.op_log(), state.capabilities().certificates())
    };
    let Ok(ops) = log else { return };
    // The certificates go with the log, not after it. They authorise every `Add`
    // it contains, so a receiver replaying the operations without them refuses
    // the history — including, for a joiner, its own admission. They are also the
    // only anti-entropy a role change gets, since a grant mints no operation.
    if let Ok(bytes) = (ControlMsg::Log { ops, certs }).encode()
        && let Err(err) = inner.gossip_tx.broadcast(Bytes::from(bytes)).await
    {
        tracing::error!(%err, "failed to broadcast the operation log");
    }
}

/// Remove a leaf that a member outside the group spliced into the tree.
///
/// The other half of [`Effect::EvictUncertified`]. Rate-limited per spliced leaf,
/// because answering costs a `Remove` and a namespace rotation and the trigger is
/// adversarial: without the limiter, a revenant re-adding in a loop would make the
/// group rotate its replica indefinitely.
///
/// Feeding the removal back as an ordinary [`Event::RemoveMember`] rather than
/// calling into the CGKA directly is what keeps the ordering guarantee intact —
/// the `Remove` is broadcast before the rotation is minted, exactly as for a
/// deliberate removal.
async fn evict_uncertified(inner: &Arc<Inner>, member: MemberId) {
    if !inner
        .eviction_cooldown
        .lock()
        .await
        .claim(member.to_bytes(), Instant::now())
    {
        return;
    }
    tracing::warn!(
        %member,
        "removing a leaf introduced by a member no longer in the group"
    );
    let effects = {
        let mut state = inner.state.lock().await;
        state
            .handle(Event::RemoveMember { member }, &mut rand::rngs::OsRng)
            .unwrap_or_default()
    };
    apply_effects(inner, effects).await;
}

/// Re-encrypt and re-announce every document this node knows about, and the
/// manifest that indexes them.
async fn republish(inner: &Arc<Inner>) {
    let docs: Vec<DocumentUuid> = {
        let state = inner.state.lock().await;
        state
            .manifest()
            .files()
            .into_iter()
            .map(|f| f.uuid)
            .collect()
    };
    for doc in docs {
        let effects = {
            let mut state = inner.state.lock().await;
            state
                .handle(Event::Resync { doc }, &mut rand::rngs::OsRng)
                .unwrap_or_default()
        };
        apply_effects(inner, effects).await;
    }
    // See `Workspace::resync`: the manifest needs re-announcing too, and this
    // is the path a neighbour appearing takes, which is exactly when a peer is
    // most likely to be missing it.
    for event in [Event::ResyncManifest, Event::ResyncNamespace] {
        let effects = {
            let mut state = inner.state.lock().await;
            state
                .handle(event, &mut rand::rngs::OsRng)
                .unwrap_or_default()
        };
        apply_effects(inner, effects).await;
    }
    // A resync republishes rather than mutating, but `Keying::Current` can still
    // make beekem re-key — and a re-key this node forgot would leave it unable to
    // read its own next publish after a restart.
    persist(inner).await;
}

/// Perform the effects the core asked for.
async fn apply_effects(inner: &Arc<Inner>, effects: Vec<Effect>) {
    for effect in effects {
        match effect {
            Effect::BroadcastOp { op, proof } => {
                // A dropped control operation is unrecoverable for peers, so
                // failures here are logged loudly rather than swallowed.
                if let Ok(bytes) = (ControlMsg::Op { op, proof }).encode()
                    && let Err(err) = inner.gossip_tx.broadcast(Bytes::from(bytes)).await
                {
                    tracing::error!(%err, "failed to broadcast a CGKA operation");
                }
            }
            Effect::BroadcastCerts(certs) => {
                // Lost certificates are recoverable — the next log exchange
                // re-ships the whole store — but a lost one costs its subject
                // their role until then, so this is still logged rather than
                // ignored.
                if let Ok(bytes) = ControlMsg::Certs(certs).encode()
                    && let Err(err) = inner.gossip_tx.broadcast(Bytes::from(bytes)).await
                {
                    tracing::error!(%err, "failed to broadcast capability certificates");
                }
            }
            Effect::EvictUncertified { member } => {
                Box::pin(evict_uncertified(inner, member)).await;
            }
            Effect::StoreChunk { key, chunk, .. } => {
                if let Err(err) = store_chunk(inner, key.as_bytes(), &chunk).await {
                    tracing::error!(%err, "failed to store an encrypted chunk");
                }
            }
            Effect::StoreManifest { key, chunk } => {
                if let Err(err) = store_chunk(inner, key.as_bytes(), &chunk).await {
                    tracing::error!(%err, "failed to store the encrypted manifest");
                }
            }
            Effect::DeleteEntry { key, .. } => {
                // Withdraws only *our* entry: `Doc::del` is scoped to an author,
                // so each member must retract their own as they observe the
                // manifest tombstone. Forget every cached hash under this key
                // too, or a document later recreated at the same UUID would be
                // skipped as unchanged.
                inner
                    .seen_entries
                    .lock()
                    .await
                    .retain(|(k, _), _| k != key.as_bytes());
                if let Err(err) = doc(inner)
                    .await
                    .del(inner.author, Bytes::copy_from_slice(key.as_bytes()))
                    .await
                {
                    tracing::error!(%err, "failed to withdraw an index entry");
                }
            }
            // A manifest arrival is the only way membership changes reach a node
            // that did not issue them, so it is also the only place a peer
            // learns it should stop accepting a removed device — or start
            // accepting a newly admitted one.
            Effect::ManifestUpdated => refresh_roster(inner).await,
            Effect::RequestRepair { target, epoch } => {
                request_repair(inner, target, epoch).await;
            }
            // Removal abandons the namespace for a fresh one. Minting is I/O,
            // so the core asks rather than doing it, and the capability comes
            // straight back for encryption under the *post-removal* key.
            // Boxed because minting announces through this same pump: the
            // capability has to be encrypted and broadcast, and that is an
            // `apply_effects` call inside an `apply_effects` call.
            Effect::RotateNamespace { epoch } => Box::pin(mint_namespace(inner, epoch)).await,
            Effect::PublishNamespace { epoch, chunk } => {
                if let Ok(bytes) = (ControlMsg::Namespace { epoch, chunk }).encode()
                    && let Err(err) = inner.gossip_tx.broadcast(Bytes::from(bytes)).await
                {
                    // Not fatal: rotations are re-announced on every resync, so
                    // a lost one costs latency rather than a split group.
                    tracing::error!(%err, "failed to announce a namespace rotation");
                }
            }
            // Boxed for the same reason as the arm above: adopting re-publishes
            // every document, which comes straight back through this pump.
            Effect::AdoptNamespace { ticket, .. } => {
                let may_write = local_role_may_write(inner).await;
                let node = inner.node.clone();
                Box::pin(adopt_namespace(inner, &node, &ticket, may_write)).await;
            }
            Effect::Applied { .. } => {}
        }
    }
}

/// Whether this node's own role permits writing to the replica.
///
/// A member with no role recorded yet is treated as a writer, matching the
/// escape hatch the core's `require_write` already uses: a joiner holds no
/// certificates until its first exchange, and refusing it a write capability
/// then would leave it unable to publish the very records that establish it.
async fn local_role_may_write(inner: &Inner) -> bool {
    let state = inner.state.lock().await;
    state
        .capabilities()
        .role_of_member(&state.member_id().to_bytes())
        .is_none_or(Role::can_write)
}

/// Mint a fresh namespace and hand its capability back to the core.
///
/// Both tickets are minted here, from one namespace: beekem encrypts to the
/// whole tree, so the announcement cannot be tailored per recipient and each
/// node picks the ticket its own role allows. See [`NamespaceCapability`].
///
/// This node does not adopt the result — it created the namespace and is
/// already able to use it — but it does have to *switch* to it, which is what
/// feeding the reply back through the core arranges: `on_namespace_minted`
/// records the new generation, and the caller swaps the handle below.
async fn mint_namespace(inner: &Arc<Inner>, epoch: u32) {
    let fresh = match inner.node.docs().api().create().await {
        Ok(fresh) => fresh,
        Err(err) => {
            tracing::error!(%err, "failed to mint a namespace for a rotation");
            return;
        }
    };
    let (Ok(write), Ok(read)) = (
        fresh
            .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
            .await,
        fresh
            .share(ShareMode::Read, AddrInfoOptions::RelayAndAddresses)
            .await,
    ) else {
        tracing::error!("failed to mint capabilities for a rotated namespace");
        return;
    };
    let Ok(ticket) = (NamespaceCapability { write, read }).encode() else {
        tracing::error!("failed to encode a rotated namespace capability");
        return;
    };

    // Encrypt and announce. The core emits the key operations that make the
    // announcement readable *before* the announcement itself; `apply_effects`
    // preserves that order, and reversing it would leave the group unable to
    // decrypt the capability and permanently split across two namespaces.
    let effects = {
        let mut state = inner.state.lock().await;
        state
            .handle(
                Event::NamespaceMinted {
                    epoch,
                    ticket: ticket.clone(),
                },
                &mut rand::rngs::OsRng,
            )
            .unwrap_or_default()
    };
    if effects.is_empty() {
        // A later rotation overtook this one, so the namespace just minted is
        // stale. Nothing to undo: it was never announced and nobody holds it.
        return;
    }
    // The batch ends with an `AdoptNamespace` naming what was just minted, so
    // switching onto it happens by the same path a peer's rotation takes rather
    // than by a second implementation here.
    Box::pin(apply_effects(inner, effects)).await;
}

/// Ask the group to re-encrypt something this node can never decrypt.
///
/// Rate-limited here rather than in the core, which has no clock. The core
/// raises the effect on *every* unreachable arrival on purpose — that is what
/// makes a request lost in transit recoverable — so without a window a stuck
/// peer would broadcast once per republish per publisher.
async fn request_repair(inner: &Inner, target: RepairTarget, epoch: EpochId) {
    let allowed = {
        let mut cooldown = inner.repair_cooldown.lock().await;
        cooldown.claim((target, epoch), Instant::now())
    };
    if !allowed {
        tracing::debug!(?target, %epoch, "suppressing a repeat repair request");
        return;
    }
    let member = inner.state.lock().await.member_id().to_bytes();
    let msg = ControlMsg::Repair {
        member,
        target,
        epoch,
    };
    tracing::info!(?target, %epoch, "asking the group to re-key and republish");
    if let Ok(bytes) = msg.encode()
        && let Err(err) = inner.gossip_tx.broadcast(Bytes::from(bytes)).await
    {
        // Not fatal, and not silent either: while this fails, content written
        // before this node joined stays unreadable to it.
        tracing::error!(%err, "failed to broadcast a repair request");
    }
}

/// Start the data-plane pump against the current namespace, replacing any
/// pump already running.
///
/// A subscription is to *one* namespace. After a rotation the old subscription
/// delivers nothing and the new namespace has nobody listening, so the two must
/// be swapped together — aborting first, so that two pumps never race to ingest
/// the same arrival into the same state.
///
/// The return type is boxed rather than `impl Future` to break a cycle the
/// compiler cannot see through: this spawns `data_loop`, whose effect pump can
/// adopt a rotation, which calls back here. Inferring `Send` for that would
/// require already knowing it. Asserting it in the signature settles the
/// question instead.
///
/// # Errors
///
/// Returns [`WorkspaceError::Storage`] if the namespace cannot be subscribed to.
fn spawn_data_loop(
    inner: &Arc<Inner>,
) -> Pin<Box<dyn Future<Output = Result<(), WorkspaceError>> + Send + '_>> {
    Box::pin(async move {
        let events = doc(inner)
            .await
            .subscribe()
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;
        let task = tokio::spawn(data_loop(Arc::clone(inner), events));
        if let Some(previous) = inner.data_task.lock().await.replace(task) {
            previous.abort();
        } else {
            // First start; there is nothing to replace.
        }
        Ok(())
    })
}

/// Move this node onto a namespace the group has rotated to.
///
/// Four things have to happen together, and the order is not arbitrary:
///
/// 1. **Import the capability**, which also starts syncing with the peers named
///    in the ticket.
/// 2. **Swap the handle**, so every subsequent read and write addresses the new
///    namespace.
/// 3. **Forget the ingestion cache.** It is keyed by blinded key and author,
///    and those repeat across namespaces — a surviving entry would make the new
///    namespace's first copy of a document look like one already ingested, and
///    it would be skipped.
/// 4. **Re-publish everything.** The new namespace starts empty, so a node that
///    switched without re-publishing would take its documents out of
///    circulation entirely.
///
/// The old namespace is abandoned rather than dropped: peers that have not yet
/// seen the rotation are still catching up on it, and reclaiming its storage is
/// blob GC's problem rather than this function's.
async fn adopt_namespace(inner: &Arc<Inner>, node: &Node, ticket: &[u8], role_may_write: bool) {
    let capability = match NamespaceCapability::decode(ticket) {
        Ok(capability) => capability,
        Err(err) => {
            tracing::error!(%err, "a namespace rotation carried an unreadable capability");
            return;
        }
    };
    // Each node takes the ticket its own role allows. Both travel together
    // because beekem encrypts to the whole tree and cannot hand writers one
    // secret and viewers another; see `NamespaceCapability`.
    let chosen = if role_may_write {
        capability.write
    } else {
        capability.read
    };

    // Open it if this node already holds it, and only import otherwise. The
    // minter reaches here for the namespace it just created, and importing a
    // ticket for a replica you already have means dialling the addresses inside
    // it — including your own, which `iroh` refuses and logs. Opening is also
    // simply the correct operation: there is no capability to install.
    let id = chosen.capability.id();
    let existing = node.docs().api().open(id).await.ok().flatten();
    let replacement = match existing {
        Some(existing) => existing,
        None => match node.docs().api().import(chosen).await {
            Ok(imported) => imported,
            Err(err) => {
                tracing::error!(%err, "failed to import a rotated namespace");
                return;
            }
        },
    };

    let previous = std::mem::replace(&mut *inner.doc.write().await, replacement);
    // Stop reconciling the abandoned namespace. Not dropped: peers that have
    // not yet seen the rotation may still be catching up on it.
    if let Err(err) = previous.leave().await {
        tracing::warn!(%err, "failed to stop syncing the abandoned namespace");
    } else {
        // Left cleanly.
    }
    inner.seen_entries.lock().await.clear();

    if let Err(err) = spawn_data_loop(inner).await {
        tracing::error!(%err, "failed to subscribe to a rotated namespace");
    } else {
        // The pump is live on the new namespace.
    }
    republish(inner).await;
}

/// The replicated index this node currently syncs.
///
/// Clones the handle and releases the lock immediately. Holding the guard
/// across an await would let a slow sync block a rotation — and a rotation is
/// what stops a removed device from watching the index, so blocking it is a
/// security cost, not merely a latency one.
async fn doc(inner: &Inner) -> Doc {
    inner.doc.read().await.clone()
}

/// Recompute the node's admission list from the current workspace state.
///
/// Cheap and idempotent, which is why it runs on every manifest arrival rather
/// than trying to detect whether membership actually moved: the manifest is a
/// CRDT, so "did this import change the roster" is a diff over two derived sets,
/// and computing the new set is the cheaper half of answering it.
async fn refresh_roster(inner: &Inner) {
    let endpoints = {
        let state = inner.state.lock().await;
        state.roster()
    };
    inner.roster.set_derived(inner.workspace_key, endpoints);
}

/// Write one encrypted chunk to blobs and index it in docs.
async fn store_chunk(
    inner: &Inner,
    key: &[u8; 32],
    chunk: &iroh_beekem_core::Chunk,
) -> Result<(), WorkspaceError> {
    let bytes = encode_chunk(chunk)?;
    let size = bytes.len() as u64;
    let tag = inner
        .blobs
        .add_bytes(bytes)
        .await
        .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

    doc(inner)
        .await
        .set_hash(inner.author, Bytes::copy_from_slice(key), tag.hash, size)
        .await
        .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

    // Nudge peers rather than waiting for the next reconciliation round.
    if let Ok(msg) = (ControlMsg::Announce { key: *key }).encode() {
        let _ = inner.gossip_tx.broadcast(Bytes::from(msg)).await;
    }
    Ok(())
}

/// Write this workspace's snapshot, if the node it runs on persists at all.
///
/// A no-op for a [`Node::spawn`](crate::Node::spawn) node, so the in-memory path
/// pays nothing for the existence of the persistent one.
///
/// # Where this is called from, and why not from `apply_effects`
///
/// At the five boundaries where a *batch* of work finishes: [`Workspace::drive`],
/// [`handle_control_msg`], [`ingest_all`], [`republish`] and [`Workspace::assemble`].
/// Not inside `apply_effects`, which looks like the obvious place and is not:
/// `ingest_all` calls it once per document and `evict_uncertified` re-enters it,
/// so a write there would be O(documents) per gossip message rather than O(1).
///
/// Not gated on the effect batch being non-empty either, which is the other
/// tempting shortcut. `on_certs_arrived` absorbs certificates — durable state —
/// and returns no effects at all when nothing was waiting on them, so "the batch
/// was empty" does not mean "nothing changed".
///
/// # Written before the caller is told the write succeeded
///
/// `drive` awaits this before returning `Ok`, so a `create_file` or an `append`
/// that has been acknowledged is on disk. That is what makes "a node's own
/// acknowledged writes survive a restart" a fact rather than a likelihood, and it
/// is why the cost — one snapshot per event — is accepted here. Phase 9's delta
/// publishing is what makes that cost proportional to the change rather than to
/// the workspace.
///
/// # Failure is logged, not propagated
///
/// A full disk must not turn an accepted local edit into an error the caller
/// might respond to by retrying, because the edit *is* applied in memory and a
/// retry would duplicate it. The node keeps running against the last snapshot
/// that landed; the operator sees the warning.
async fn persist(inner: &Arc<Inner>) {
    let Some(store) = inner.node.store().cloned() else {
        return;
    };
    let namespace = doc(inner).await.id();
    let tree_id = inner.workspace_key;

    let core = {
        let state = inner.state.lock().await;
        match state.export() {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(%e, "could not capture the workspace snapshot");
                return;
            }
        }
    };

    // The encode-and-write is blocking file I/O, so it goes to the blocking pool
    // rather than stalling the reactor that is also driving gossip and docs.
    let record = WorkspaceRecord {
        core: core.to_vec(),
        namespace,
    };
    let written =
        tokio::task::spawn_blocking(move || store.store_workspace(tree_id, &record)).await;
    match written {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(%e, "could not write the workspace snapshot"),
        Err(e) => tracing::warn!(%e, "the snapshot writer panicked or was cancelled"),
    }
}

/// Read every entry under this workspace's blinded key and feed it to the core.
///
/// Entries whose payload has not been fetched yet are skipped; the next
/// `ContentReady` event brings us back here.
async fn ingest_all(inner: &Arc<Inner>) {
    // Manifest first. Document entries are accepted based on whether their
    // author holds a writing role, and that mapping lives in the manifest — so
    // ingesting documents first would reject entries purely because the roles
    // proving them legitimate had not been read yet.
    let manifest_key = inner.secret.manifest_key();
    for chunk in fetch_chunks(inner, manifest_key.as_bytes(), false).await {
        let effects = {
            let mut state = inner.state.lock().await;
            report_rejection(state.handle(
                Event::ManifestArrived {
                    chunk: Box::new(chunk),
                },
                &mut rand::rngs::OsRng,
            ))
        };
        apply_effects(inner, effects).await;
    }

    // Now every document the manifest knows about. Reading the list *after*
    // ingesting the manifest matters: a document created by a peer becomes
    // visible on the same pass that learns of it, rather than the next one.
    let docs: Vec<DocumentUuid> = {
        let state = inner.state.lock().await;
        state
            .manifest()
            .files()
            .into_iter()
            .map(|f| f.uuid)
            .collect()
    };
    for doc in docs {
        let key = inner.secret.storage_key(doc);
        for chunk in fetch_chunks(inner, key.as_bytes(), true).await {
            let effects = {
                let mut state = inner.state.lock().await;
                report_rejection(state.handle(
                    Event::ChunkArrived {
                        doc,
                        chunk: Box::new(chunk),
                    },
                    &mut rand::rngs::OsRng,
                ))
            };
            apply_effects(inner, effects).await;
        }
    }

    // Once per pass, not once per document: an ingest touches every document the
    // manifest knows about, and a write inside the loop would make persistence
    // cost O(documents) per arriving chunk.
    persist(inner).await;
}

/// Read and decode every locally-available payload stored under one blinded key.
///
/// When `check_author` is set, entries whose author the manifest does not
/// recognise as a writer are skipped. This is the check README limitation 1
/// asks for: the `iroh-docs` write capability is all-or-nothing, so a revoked
/// member keeps it and can still push entries into the replica — including
/// overwriting the entry at a document's key, since every chunk for a document
/// lands at the same one. Refusing their entries here is what stops that from
/// being a rollback channel.
///
/// The manifest itself is exempt, and has to be: the mapping that identifies
/// legitimate authors is *inside* it, so requiring the check to pass before
/// reading it could never bootstrap. It is protected instead by the CGKA — a
/// non-member cannot produce a manifest this node can decrypt.
async fn fetch_chunks(
    inner: &Inner,
    key: &[u8; 32],
    check_author: bool,
) -> Vec<iroh_beekem_core::Chunk> {
    let Ok(entries) = doc(inner)
        .await
        .get_many(Query::key_exact(Bytes::copy_from_slice(key)))
        .await
    else {
        return Vec::new();
    };
    let mut entries = std::pin::pin!(entries);

    let mut chunks = Vec::new();
    while let Some(Ok(entry)) = entries.next().await {
        let author = entry.author().to_bytes();
        if check_author {
            // Our own entries always pass: we have not necessarily read back
            // our own author claim from the manifest yet, and refusing our own
            // writes would be a startup deadlock.
            let accepted = author == inner.author.to_bytes() || {
                let state = inner.state.lock().await;
                state.author_may_write(&author)
            };
            if !accepted {
                // Routine during catch-up, not necessarily an attack: until the
                // manifest naming this author has synced, a perfectly legitimate
                // peer's entries look exactly like an outsider's. `ingest_all`
                // re-reads every entry on each sync event, so this self-corrects
                // once the manifest lands — which is why it is not a warning.
                tracing::debug!("skipping an entry whose author has no writing role yet");
                continue;
            }
        }
        // Skip anything already ingested. `ingest_all` re-reads every entry on
        // every sync event, and with several documents that is a fetch and a
        // decrypt per document per event for content that has usually not
        // moved. The hash is what changed or did not, so it is what to compare.
        let hash = entry.content_hash();
        if inner.seen_entries.lock().await.get(&(*key, author)) == Some(&hash) {
            continue;
        }
        // Recorded only once the payload is genuinely in hand. An index entry
        // routinely arrives before its blob, and marking it seen on sight would
        // make the `ContentReady` event that finally delivers the content skip
        // it as unchanged — losing that content for good.
        if let Ok(bytes) = inner.blobs.get_bytes(hash).await
            && let Ok(chunk) = decode_chunk(&bytes)
        {
            inner.seen_entries.lock().await.insert((*key, author), hash);
            chunks.push(chunk);
        }
    }
    chunks
}

/// Rebuild a verifying key from raw bytes.
fn ed25519_verifying_key(bytes: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()
}

/// The neighbour-up repair path is reachable by anyone who has ever held an
/// invite, because the gossip topic is derived from the tree id. Each arrival
/// costs a full operation-log broadcast and a signature check per operation on
/// every receiver, so the rate limit is a denial-of-service control, not a
/// tuning knob. It takes `now` as an argument so the policy can be checked
/// without waiting on wall time.
#[cfg(test)]
mod cooldown {
    use std::time::Instant;

    use iroh::{EndpointId, SecretKey};

    use super::{Cooldown, NEIGHBOR_COOLDOWN};

    fn peer(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn a_first_arrival_is_always_allowed() {
        let mut cooldown = Cooldown::new(NEIGHBOR_COOLDOWN);
        assert!(
            cooldown.claim(peer(1), Instant::now()),
            "a peer that has never been seen must be able to repair"
        );
    }

    #[test]
    fn a_repeat_arrival_within_the_window_is_refused() {
        let mut cooldown = Cooldown::new(NEIGHBOR_COOLDOWN);
        let start = Instant::now();

        assert!(cooldown.claim(peer(1), start));
        assert!(
            !cooldown.claim(peer(1), start + NEIGHBOR_COOLDOWN / 2),
            "a peer reconnecting inside the window must not trigger a second repair"
        );
    }

    #[test]
    fn the_same_peer_is_allowed_again_once_the_window_passes() {
        let mut cooldown = Cooldown::new(NEIGHBOR_COOLDOWN);
        let start = Instant::now();

        assert!(cooldown.claim(peer(1), start));
        assert!(
            cooldown.claim(peer(1), start + NEIGHBOR_COOLDOWN),
            "the limit is a rate, not a ban: a genuine later reconnect must repair"
        );
    }

    #[test]
    fn one_peers_cooldown_does_not_suppress_another() {
        let mut cooldown = Cooldown::new(NEIGHBOR_COOLDOWN);
        let start = Instant::now();

        assert!(cooldown.claim(peer(1), start));
        assert!(
            cooldown.claim(peer(2), start),
            "the budget is per peer; one noisy peer must not starve a quiet one"
        );
    }

    #[test]
    fn expired_entries_are_pruned_so_the_map_cannot_grow_without_bound() {
        let mut cooldown = Cooldown::new(NEIGHBOR_COOLDOWN);
        let start = Instant::now();

        // A flood of distinct peers, which is what an attacker controls: peer
        // ids are free to mint.
        for seed in 0..64u8 {
            cooldown.claim(peer(seed), start);
        }
        assert_eq!(cooldown.tracked(), 64, "all should be tracked while fresh");

        // One arrival after the window must collect every stale entry, or the
        // rate limit would trade a CPU vector for a memory one.
        cooldown.claim(peer(200), start + NEIGHBOR_COOLDOWN);
        assert_eq!(
            cooldown.tracked(),
            1,
            "expired entries must be pruned, leaving only the live one"
        );
    }
}
