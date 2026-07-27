//! The [`Workspace`] facade: a pump between `iroh` and the I/O-free core.
//!
//! This module contains no cryptography. Its whole job is to turn network
//! arrivals into [`Event`]s for [`WorkspaceState`], and the [`Effect`]s that
//! come back into gossip broadcasts and blob writes. All key handling lives in
//! `iroh-beekem-core`, where it can be simulated and property-tested.

use std::sync::Arc;

use beekem::{
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
use bytes::Bytes;
use iroh::EndpointId;
use iroh_beekem_core::{
    CgkaController, DocumentUuid, Effect, Event, WorkspaceSecret, WorkspaceState,
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
use tokio::{sync::Mutex, task::JoinHandle};

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

        Self::assemble(node, cgka, secret, doc, tree_id, document, Vec::new()).await
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
        let workspace = Self::assemble(
            node,
            cgka,
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
        cgka: CgkaController,
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
        let (gossip_tx, mut gossip_rx) = gossip_topic.split();

        let inner = Arc::new(Inner {
            state: Mutex::new(WorkspaceState::new(
                cgka,
                WorkspaceSecret::new(secret.to_bytes()),
            )),
            blobs: node.blobs().clone(),
            doc: doc.clone(),
            author,
            gossip_tx,
            secret,
            document,
        });

        // Control plane: CGKA operations arriving over gossip.
        let control = Arc::clone(&inner);
        let control_task = tokio::spawn(async move {
            while let Some(event) = gossip_rx.next().await {
                let msg = match event {
                    Ok(GossipEvent::Received(msg)) => msg,
                    // A peer just joined the overlay. They cannot decrypt
                    // anything written before they were admitted — that is
                    // forward secrecy — so re-publish current state under the
                    // present epoch key, which they *can* derive. This is the
                    // moment to do it: before now they were not listening.
                    Ok(GossipEvent::NeighborUp(_)) => {
                        // Order matters: the peer needs our operation log
                        // before it can derive the key for anything we
                        // re-publish afterwards.
                        send_log(&control).await;
                        republish(&control).await;
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
                            let mut state = control.state.lock().await;
                            let outcome =
                                state.handle(Event::ControlOp(Arc::new(*op)), &mut rand::rngs::OsRng);
                            report_rejection(outcome)
                        };
                        apply_effects(&control, effects).await;
                        ingest_all(&control).await;
                    }
                    ControlMsg::Log(ops) => {
                        if ops.len() > MAX_LOG_OPS {
                            tracing::warn!(
                                len = ops.len(),
                                "discarding an oversized operation log"
                            );
                            continue;
                        }
                        let mut effects = Vec::new();
                        {
                            let mut state = control.state.lock().await;
                            for op in ops {
                                let outcome = state
                                    .handle(Event::ControlOp(Arc::new(op)), &mut rand::rngs::OsRng);
                                effects.append(&mut report_rejection(outcome));
                            }
                        }
                        apply_effects(&control, effects).await;
                        // Newly recovered key material may unlock chunks that
                        // have been parked since before this peer caught up.
                        ingest_all(&control).await;
                    }
                    // The index sync will surface the entry; the announce only
                    // prompts us to look sooner.
                    ControlMsg::Announce { .. } => {
                        ingest_all(&control).await;
                    }
                }
            }
        });

        // Data plane: entries and content arriving over docs and blobs.
        let data = Arc::clone(&inner);
        let mut doc_events = doc
            .subscribe()
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;
        let data_task = tokio::spawn(async move {
            while let Some(event) = doc_events.next().await {
                // `InsertRemote` fires when the index entry lands, which may be
                // before the payload has been fetched; `ContentReady` fires
                // once the bytes are actually local. React to both, so a
                // payload that happened to be present already is not missed.
                if let Ok(LiveEvent::InsertRemote { .. } | LiveEvent::ContentReady { .. }) = event {
                    ingest_all(&data).await;
                }
            }
        });

        Ok(Self {
            node,
            inner,
            namespace,
            tree_id,
            topic,
            tasks: vec![control_task, data_task],
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
            Effect::Applied { .. } => {}
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
    let key = inner.secret.storage_key(inner.document);
    let Ok(entries) = inner
        .doc
        .get_many(Query::key_exact(Bytes::copy_from_slice(key.as_bytes())))
        .await
    else {
        return;
    };
    let mut entries = std::pin::pin!(entries);

    let mut chunks = Vec::new();
    while let Some(Ok(entry)) = entries.next().await {
        if let Ok(bytes) = inner.blobs.get_bytes(entry.content_hash()).await
            && let Ok(chunk) = decode_chunk(&bytes)
        {
            chunks.push(chunk);
        }
    }

    for chunk in chunks {
        let effects = {
            let mut state = inner.state.lock().await;
            state
                .handle(
                    Event::ChunkArrived {
                        doc: inner.document,
                        chunk: Box::new(chunk),
                    },
                    &mut rand::rngs::OsRng,
                )
                .unwrap_or_default()
        };
        apply_effects(inner, effects).await;
    }
}

/// Rebuild a verifying key from raw bytes.
fn ed25519_verifying_key(bytes: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()
}
