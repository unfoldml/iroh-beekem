//! The [`Workspace`] facade: a pump between `iroh` and the I/O-free core.
//!
//! This module contains no cryptography. Its whole job is to turn network
//! arrivals into [`Event`]s for [`WorkspaceState`], and the [`Effect`]s that
//! come back into gossip broadcasts and blob writes. All key handling lives in
//! `iroh-beekem-core`, where it can be simulated and property-tested.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use beekem::{
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
use bytes::Bytes;
use iroh::EndpointId;
use iroh_beekem_core::{
    CgkaController, DocumentUuid, Effect, Event, FileEntry, Role, WorkspaceSecret, WorkspaceState,
};
use iroh_blobs::store::mem::MemStore;
use iroh_docs::{
    AuthorId, DocTicket, NamespaceId,
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
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use n0_future::StreamExt;
use rand::{CryptoRng, RngCore};
use tokio::{
    sync::{Mutex, Notify},
    task::JoinHandle,
};

use crate::{
    error::WorkspaceError,
    node::Node,
    wire::{ControlMsg, decode_chunk, encode_chunk},
};

/// Everything a new member needs to join.
///
/// The operation log is public, signed data; the other two fields are not.
/// This whole ticket must therefore be delivered over an authenticated,
/// confidential channel — a direct `iroh` QUIC stream to a known public key
/// qualifies, a public gossip topic does not.
///
/// # The write-capability caveat
///
/// `doc_ticket` carries the `iroh-docs` **write** capability, which is
/// all-or-nothing: there is no per-member write key. A revoked member keeps
/// this capability and can still push entries into the replica. They cannot
/// *read* anything written after their removal — that is what the CGKA
/// guarantees — but shutting off their writes requires rotating to a fresh
/// namespace, which is not automatic. Applications that care should check the
/// author against the manifest roles before accepting an entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Invite {
    /// The CGKA tree id, as raw bytes.
    pub tree_id: [u8; 32],
    /// A write ticket for the `iroh-docs` namespace, including peer addresses.
    pub doc_ticket: DocTicket,
    /// The blinding secret for storage keys.
    pub workspace_secret: [u8; 32],
    /// The full CGKA operation log, in causal order.
    pub log: Vec<Signed<CgkaOperation>>,
    /// The inviter's endpoint, so the joiner can also gossip with them.
    pub inviter: EndpointId,
}

/// Shared state behind the pump loops.
struct Inner {
    state: Mutex<WorkspaceState>,
    blobs: MemStore,
    doc: Doc,
    author: AuthorId,
    gossip_tx: GossipSender,
    secret: WorkspaceSecret,
    document: DocumentUuid,
    /// Rate limiter for the neighbour-up repair path.
    neighbor_cooldown: Mutex<Cooldown>,
    /// Raised when the current document state should be re-announced.
    ///
    /// A [`Notify`] rather than a timestamp check because the republish must be
    /// *deferred*, never dropped — see [`republish_loop`].
    republish_wanted: Notify,
}

/// A running, networked workspace.
pub struct Workspace {
    node: Node,
    inner: Arc<Inner>,
    namespace: NamespaceId,
    tree_id: TreeId,
    topic: TopicId,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace")
            .field("namespace", &self.namespace)
            .field("endpoint", &self.node.endpoint().id())
            .finish_non_exhaustive()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
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

/// Per-peer rate limiter for the neighbour-up repair path.
///
/// Takes `now` as an argument rather than reading the clock, which is what
/// makes the policy testable without waiting on wall time — the same reasoning
/// that keeps `iroh-beekem-core` clock-free.
#[derive(Debug, Default)]
struct Cooldown {
    seen: HashMap<EndpointId, Instant>,
}

impl Cooldown {
    /// Whether `peer` may trigger the repair path now, recording it if so.
    ///
    /// Expired entries are pruned on the way through, so the map stays
    /// proportional to the peers seen in one window rather than to every peer
    /// ever seen. Without that, a map keyed by peer id would simply move the
    /// exhaustion vector this exists to close from CPU to memory.
    fn claim(&mut self, peer: EndpointId, now: Instant) -> bool {
        // An entry older than the cooldown says nothing its absence does not.
        self.seen
            .retain(|_, at| now.duration_since(*at) < NEIGHBOR_COOLDOWN);
        match self.seen.get(&peer) {
            Some(at) if now.duration_since(*at) < NEIGHBOR_COOLDOWN => false,
            _ => {
                self.seen.insert(peer, now);
                true
            }
        }
    }

    /// How many peers are currently being tracked.
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
    /// Found a new workspace on this node.
    ///
    /// # Errors
    ///
    /// Propagates endpoint, storage and CGKA failures.
    pub async fn create<R: CryptoRng + RngCore>(
        node: Node,
        document: DocumentUuid,
        csprng: &mut R,
    ) -> Result<Self, WorkspaceError> {
        let signer = MemorySigner::generate(csprng);
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
        Self::assemble(node, state, secret, doc, tree_id, document, Vec::new()).await
    }

    /// Join an existing workspace from an [`Invite`].
    ///
    /// `share_secret` must be the secret half of the [`ShareKey`] the inviter
    /// named in the `Add` operation.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Invite`] if the log does not admit this member,
    /// and propagates endpoint and storage failures.
    pub async fn join<R: CryptoRng + RngCore>(
        node: Node,
        invite: &Invite,
        signer: MemorySigner,
        share_secret: ShareSecretKey,
        document: DocumentUuid,
        _csprng: &mut R,
    ) -> Result<Self, WorkspaceError> {
        let tree_id = TreeId::from(
            ed25519_verifying_key(&invite.tree_id)
                .ok_or_else(|| WorkspaceError::Invite("malformed tree id".into()))?,
        );
        let cgka = CgkaController::join(tree_id, signer, share_secret, &invite.log)?;
        let secret = WorkspaceSecret::new(invite.workspace_secret);

        // `import` installs the capability *and* starts syncing with the peers
        // named in the ticket; `open` would fail here because a joiner has
        // never seen the namespace before.
        let doc = node
            .docs()
            .api()
            .import(invite.doc_ticket.clone())
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        // Bootstrap the gossip overlay against the inviter. Without a bootstrap
        // peer each node forms its own disjoint overlay and no CGKA operation
        // ever crosses between them — the data plane would sync while the
        // control plane silently did not, leaving every chunk undecryptable.
        let state = WorkspaceState::joined(cgka, WorkspaceSecret::new(secret.to_bytes()));
        let workspace = Self::assemble(
            node,
            state,
            secret,
            doc,
            tree_id,
            document,
            vec![invite.inviter],
        )
        .await?;
        workspace.sync_with(invite.inviter).await?;
        Ok(workspace)
    }

    /// Wire up the pump loops shared by [`Self::create`] and [`Self::join`].
    async fn assemble(
        node: Node,
        state: WorkspaceState,
        secret: WorkspaceSecret,
        doc: Doc,
        tree_id: TreeId,
        document: DocumentUuid,
        bootstrap: Vec<EndpointId>,
    ) -> Result<Self, WorkspaceError> {
        let namespace = doc.id();
        let topic = topic_for(tree_id);

        // A per-workspace author, not the node's global identity: `AuthorId`
        // syncs in the clear on every entry, so reusing one identity across
        // workspaces would let a syncing peer link them to the same device.
        let author = node
            .docs()
            .api()
            .author_create()
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        let gossip_topic = node
            .gossip()
            .subscribe(topic, bootstrap)
            .await
            .map_err(|e| WorkspaceError::Gossip(e.to_string()))?;
        let (gossip_tx, gossip_rx) = gossip_topic.split();

        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            blobs: node.blobs().clone(),
            doc: doc.clone(),
            author,
            gossip_tx,
            secret,
            document,
            neighbor_cooldown: Mutex::new(Cooldown::default()),
            republish_wanted: Notify::new(),
        });

        // Claim this workspace's author identity in the manifest. Until a peer
        // has seen this, it has no way to connect entries signed by this author
        // to the member the roles are written about, and will refuse them. This
        // also performs the manifest's first write to the replica.
        let announce = {
            let mut state = inner.state.lock().await;
            report_rejection(state.handle(
                Event::AnnounceAuthor {
                    author: author.to_bytes(),
                },
                &mut rand::rngs::OsRng,
            ))
        };
        apply_effects(&inner, announce).await;

        // Control plane: CGKA operations arriving over gossip.
        let control = Arc::clone(&inner);
        let control_task = tokio::spawn(control_loop(control, gossip_rx));

        // Data plane: entries and content arriving over docs and blobs.
        let data = Arc::clone(&inner);
        let doc_events = doc
            .subscribe()
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;
        let data_task = tokio::spawn(data_loop(data, doc_events));

        // Anti-entropy: re-announcements requested by the control loop, run at
        // a bounded rate but never discarded.
        let republish = Arc::clone(&inner);
        let republish_task = tokio::spawn(republish_loop(republish));

        Ok(Self {
            node,
            inner,
            namespace,
            tree_id,
            topic,
            tasks: vec![control_task, data_task, republish_task],
        })
    }

    /// Begin syncing the index with a peer.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the sync cannot be started.
    pub async fn sync_with(&self, peer: EndpointId) -> Result<(), WorkspaceError> {
        self.inner
            .doc
            .start_sync(vec![peer.into()])
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))
    }

    /// This node's endpoint id, for peers to dial.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.node.endpoint().id()
    }

    /// The `iroh-docs` namespace backing this workspace.
    #[must_use]
    pub fn namespace(&self) -> NamespaceId {
        self.namespace
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

    /// Admit a new member and build the invite they need.
    ///
    /// # Errors
    ///
    /// Propagates CGKA failures.
    pub async fn invite(
        &self,
        member: MemberId,
        share_key: ShareKey,
    ) -> Result<Invite, WorkspaceError> {
        let (effects, log) = {
            let mut state = self.inner.state.lock().await;
            let effects = state.handle(
                Event::AddMember { member, share_key },
                &mut rand::rngs::OsRng,
            )?;
            let log = state.op_log()?;
            (effects, log)
        };
        apply_effects(&self.inner, effects).await;

        let doc_ticket = self
            .inner
            .doc
            .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        Ok(Invite {
            tree_id: *self.tree_id.as_bytes(),
            doc_ticket,
            workspace_secret: self.inner.secret.to_bytes(),
            log,
            inviter: self.endpoint_id(),
        })
    }

    /// Revoke a member, so they cannot read anything written afterwards.
    ///
    /// # Errors
    ///
    /// Propagates CGKA failures.
    pub async fn revoke(&self, member: MemberId) -> Result<(), WorkspaceError> {
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(Event::RemoveMember { member }, &mut rand::rngs::OsRng)?
        };
        apply_effects(&self.inner, effects).await;
        Ok(())
    }

    /// Rotate this member's leaf key, re-keying its path to the root.
    ///
    /// This is the post-compromise security primitive, and the reason BeeKEM is
    /// here rather than a static group key: an attacker holding this member's
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
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(Event::Rotate, &mut rand::rngs::OsRng)?
        };
        apply_effects(&self.inner, effects).await;
        Ok(())
    }

    /// Append text to the workspace document.
    ///
    /// # Errors
    ///
    /// Propagates encryption and storage failures.
    pub async fn append(&self, text: &str) -> Result<(), WorkspaceError> {
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(
                Event::LocalEdit {
                    doc: self.inner.document,
                    text: text.to_string(),
                },
                &mut rand::rngs::OsRng,
            )?
        };
        apply_effects(&self.inner, effects).await;
        Ok(())
    }

    /// Re-publish the document's current state under the current epoch key.
    ///
    /// Two distinct jobs, both necessary:
    ///
    /// * **Granting a new member access to existing content.** A joiner
    ///   reconstructs the group from the operation log, but not the historical
    ///   PCS keys, so they *cannot* decrypt anything written before they were
    ///   admitted. That is forward secrecy working as intended, not a defect.
    ///   Re-publishing after an invite re-encrypts the current state under a
    ///   key the new member can derive.
    /// * **Anti-entropy.** A chunk lost in transit has no later chunk to carry
    ///   its content until someone edits again; a periodic re-announcement
    ///   closes that gap.
    ///
    /// # Errors
    ///
    /// Propagates encryption and storage failures.
    pub async fn resync(&self) -> Result<(), WorkspaceError> {
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(
                Event::Resync {
                    doc: self.inner.document,
                },
                &mut rand::rngs::OsRng,
            )?
        };
        apply_effects(&self.inner, effects).await;
        Ok(())
    }

    /// Every document the manifest records, with its logical path.
    pub async fn files(&self) -> Vec<FileEntry> {
        self.inner.state.lock().await.manifest().files()
    }

    /// Every role assignment the manifest records.
    pub async fn roles(&self) -> Vec<([u8; 32], Role)> {
        self.inner.state.lock().await.manifest().roles()
    }

    /// Record or replace a document's metadata in the manifest.
    ///
    /// Logical paths live only here, never in `iroh-docs`, which sees a blinded
    /// 32-byte key and nothing else.
    ///
    /// # Errors
    ///
    /// Propagates encryption and manifest failures.
    pub async fn upsert_file(&self, entry: FileEntry) -> Result<(), WorkspaceError> {
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(Event::UpsertFile { entry }, &mut rand::rngs::OsRng)?
        };
        apply_effects(&self.inner, effects).await;
        Ok(())
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
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(
                Event::RenameFile {
                    doc,
                    path: path.to_string(),
                },
                &mut rand::rngs::OsRng,
            )?
        };
        apply_effects(&self.inner, effects).await;
        Ok(())
    }

    /// Assign a role to a member.
    ///
    /// Demoting an admin who stays in the workspace is a pure manifest edit
    /// with no key rotation; removing them entirely also needs [`Self::revoke`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Core`] wrapping `NotAnAdmin` if this node is
    /// not an admin, or `LastAdmin` if the change would leave none.
    pub async fn set_role(&self, member: MemberId, role: Role) -> Result<(), WorkspaceError> {
        let effects = {
            let mut state = self.inner.state.lock().await;
            state.handle(
                Event::SetRole {
                    member: member.to_bytes(),
                    role,
                },
                &mut rand::rngs::OsRng,
            )?
        };
        apply_effects(&self.inner, effects).await;
        Ok(())
    }

    /// The document's current text as this node sees it.
    pub async fn text(&self) -> String {
        self.inner
            .state
            .lock()
            .await
            .document_text(self.inner.document)
    }

    /// Chunks parked awaiting key material or CRDT dependencies.
    pub async fn pending(&self) -> usize {
        self.inner.state.lock().await.pending_len()
    }

    /// How many members this node believes are in the group.
    pub async fn group_size(&self) -> u32 {
        self.inner.state.lock().await.group_size()
    }

    /// Diagnostic: how many index entries exist under this workspace's key,
    /// and how many of their payloads are locally available.
    pub async fn index_status(&self) -> (usize, usize) {
        let key = self.inner.secret.storage_key(self.inner.document);
        let Ok(entries) = self
            .inner
            .doc
            .get_many(Query::key_exact(Bytes::copy_from_slice(key.as_bytes())))
            .await
        else {
            return (0, 0);
        };
        let mut entries = std::pin::pin!(entries);
        let (mut total, mut local) = (0, 0);
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
        match decoded {
            ControlMsg::Op(op) => {
                let effects = {
                    let mut state = inner.state.lock().await;
                    report_rejection(
                        state.handle(Event::ControlOp(Arc::new(*op)), &mut rand::rngs::OsRng),
                    )
                };
                apply_effects(&inner, effects).await;
                ingest_all(&inner).await;
            }
            ControlMsg::Log(ops) => {
                if ops.len() > MAX_LOG_OPS {
                    tracing::warn!(len = ops.len(), "discarding an oversized operation log");
                    continue;
                }
                let mut effects = Vec::new();
                {
                    let mut state = inner.state.lock().await;
                    for op in ops {
                        let outcome =
                            state.handle(Event::ControlOp(Arc::new(op)), &mut rand::rngs::OsRng);
                        effects.append(&mut report_rejection(outcome));
                    }
                }
                apply_effects(&inner, effects).await;
                // Newly recovered key material may unlock chunks that have been
                // parked since before this peer caught up.
                ingest_all(&inner).await;
            }
            // The index sync will surface the entry; the announce only prompts
            // us to look sooner.
            ControlMsg::Announce { .. } => {
                ingest_all(&inner).await;
            }
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
    let log = {
        let state = inner.state.lock().await;
        state.op_log()
    };
    let Ok(log) = log else { return };
    if let Ok(bytes) = (ControlMsg::Log(log)).encode()
        && let Err(err) = inner.gossip_tx.broadcast(Bytes::from(bytes)).await
    {
        tracing::error!(%err, "failed to broadcast the operation log");
    }
}

/// Re-encrypt and re-announce the current document state.
async fn republish(inner: &Inner) {
    let effects = {
        let mut state = inner.state.lock().await;
        state
            .handle(
                Event::Resync {
                    doc: inner.document,
                },
                &mut rand::rngs::OsRng,
            )
            .unwrap_or_default()
    };
    apply_effects(inner, effects).await;
}

/// Perform the effects the core asked for.
async fn apply_effects(inner: &Inner, effects: Vec<Effect>) {
    for effect in effects {
        match effect {
            Effect::BroadcastOp(op) => {
                // A dropped control operation is unrecoverable for peers, so
                // failures here are logged loudly rather than swallowed.
                if let Ok(bytes) = ControlMsg::Op(op).encode()
                    && let Err(err) = inner.gossip_tx.broadcast(Bytes::from(bytes)).await
                {
                    tracing::error!(%err, "failed to broadcast a CGKA operation");
                }
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
            Effect::Applied { .. } | Effect::ManifestUpdated => {}
        }
    }
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

    inner
        .doc
        .set_hash(inner.author, Bytes::copy_from_slice(key), tag.hash, size)
        .await
        .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

    // Nudge peers rather than waiting for the next reconciliation round.
    if let Ok(msg) = (ControlMsg::Announce { key: *key }).encode() {
        let _ = inner.gossip_tx.broadcast(Bytes::from(msg)).await;
    }
    Ok(())
}

/// Read every entry under this workspace's blinded key and feed it to the core.
///
/// Entries whose payload has not been fetched yet are skipped; the next
/// `ContentReady` event brings us back here.
async fn ingest_all(inner: &Inner) {
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

    let key = inner.secret.storage_key(inner.document);
    for chunk in fetch_chunks(inner, key.as_bytes(), true).await {
        let effects = {
            let mut state = inner.state.lock().await;
            report_rejection(state.handle(
                Event::ChunkArrived {
                    doc: inner.document,
                    chunk: Box::new(chunk),
                },
                &mut rand::rngs::OsRng,
            ))
        };
        apply_effects(inner, effects).await;
    }
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
    let Ok(entries) = inner
        .doc
        .get_many(Query::key_exact(Bytes::copy_from_slice(key)))
        .await
    else {
        return Vec::new();
    };
    let mut entries = std::pin::pin!(entries);

    let mut chunks = Vec::new();
    while let Some(Ok(entry)) = entries.next().await {
        if check_author {
            let author = entry.author().to_bytes();
            // Our own entries always pass: we have not necessarily read back
            // our own author claim from the manifest yet, and refusing our own
            // writes would be a startup deadlock.
            let accepted = author == inner.author.to_bytes() || {
                let state = inner.state.lock().await;
                state.manifest().author_may_write(&author)
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
        if let Ok(bytes) = inner.blobs.get_bytes(entry.content_hash()).await
            && let Ok(chunk) = decode_chunk(&bytes)
        {
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
        let mut cooldown = Cooldown::default();
        assert!(
            cooldown.claim(peer(1), Instant::now()),
            "a peer that has never been seen must be able to repair"
        );
    }

    #[test]
    fn a_repeat_arrival_within_the_window_is_refused() {
        let mut cooldown = Cooldown::default();
        let start = Instant::now();

        assert!(cooldown.claim(peer(1), start));
        assert!(
            !cooldown.claim(peer(1), start + NEIGHBOR_COOLDOWN / 2),
            "a peer reconnecting inside the window must not trigger a second repair"
        );
    }

    #[test]
    fn the_same_peer_is_allowed_again_once_the_window_passes() {
        let mut cooldown = Cooldown::default();
        let start = Instant::now();

        assert!(cooldown.claim(peer(1), start));
        assert!(
            cooldown.claim(peer(1), start + NEIGHBOR_COOLDOWN),
            "the limit is a rate, not a ban: a genuine later reconnect must repair"
        );
    }

    #[test]
    fn one_peers_cooldown_does_not_suppress_another() {
        let mut cooldown = Cooldown::default();
        let start = Instant::now();

        assert!(cooldown.claim(peer(1), start));
        assert!(
            cooldown.claim(peer(2), start),
            "the budget is per peer; one noisy peer must not starve a quiet one"
        );
    }

    #[test]
    fn expired_entries_are_pruned_so_the_map_cannot_grow_without_bound() {
        let mut cooldown = Cooldown::default();
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
