//! Endpoint and protocol wiring.
//!
//! One `iroh::Endpoint` carries three protocols, multiplexed by ALPN on a
//! `Router`:
//!
//! * `iroh-gossip` — the **control plane**. CGKA operations must reach every
//!   peer promptly, because a peer that has not seen an operation cannot derive
//!   the keys for anything encrypted after it.
//! * `iroh-docs` — the **data plane** index. Blinded 32-byte keys pointing at
//!   content hashes, reconciled between peers with range-based set
//!   reconciliation.
//! * `iroh-blobs` — the **data plane** payloads. The encrypted chunks
//!   themselves, fetched on demand over QUIC and verified end-to-end by BLAKE3.
//!
//! Spawn order matters: blobs and gossip must exist before docs, which is
//! handed both. Since blob collection landed there is a third thing that must
//! come first: the [`ProtectCallbackHandler`] pair, because one half is an
//! option on the blob store and the other an option on the docs engine. See
//! [`gc_pair`].
//!
//! All three are wrapped in a [`RosterGuard`] before being registered, so a peer
//! that is not a member of the workspace is refused at the connection level on
//! every ALPN. Guarding only gossip would leave the docs index — and with it
//! every document's existence, size, author and timing — readable by anyone who
//! learned the namespace.

use std::{
    ops::Deref,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::{Endpoint, endpoint::presets, protocol::Router};
use iroh_blobs::{
    BlobsProtocol,
    api::Store as BlobStore,
    store::{GcConfig, fs::FsStore, mem::MemStore},
};
use iroh_docs::{engine::ProtectCallbackHandler, protocol::Docs};
use iroh_gossip::net::Gossip;

use crate::{
    error::WorkspaceError,
    roster::{Roster, RosterGuard},
    store::{BLOBS_DIR, DOCS_DIR, SpentNonces, Store},
};

/// A bound endpoint with all three workspace protocols running.
#[derive(Debug, Clone)]
pub struct Node {
    endpoint: Endpoint,
    router: Router,
    /// The blob store, in-memory or filesystem-backed.
    ///
    /// Typed as the API-level `Store` rather than as either concrete backend so
    /// that [`Self::spawn`] and [`Self::spawn_persistent`] produce the same
    /// `Node`. `MemStore` and `FsStore` both `Deref` to this, so the router
    /// registration and every caller are identical either way.
    blobs: BlobStore,
    gossip: Gossip,
    docs: Docs,
    /// Who this node accepts connections from.
    ///
    /// Owned by the node rather than by the workspace because the guards must
    /// be installed when the router is built, which happens before any
    /// workspace exists. The workspace populates it; until it does, the node
    /// accepts nobody.
    roster: Roster,
    /// Invite nonces this node has already redeemed, per workspace.
    ///
    /// What makes a ticket single-use. Owned by the node rather than by the
    /// workspace for the obvious reason: redeeming an invite is what *creates* a
    /// workspace, so there is no workspace to ask at the moment of the check.
    ///
    /// A `std::sync::Mutex` and not tokio's: the critical section is a set
    /// lookup and an insert with no await inside it, so an async lock would buy
    /// nothing and cost a scheduler round trip on the join path.
    redeemed: RedeemedInvites,
    /// Where this node persists, if it does.
    ///
    /// `None` for [`Self::spawn`], which is entirely in memory. Its presence is
    /// what [`Workspace`](crate::Workspace) consults to decide whether to write a
    /// snapshot after each change, so an in-memory node pays nothing for the
    /// existence of the persistent one.
    store: Option<Store>,
}

/// The spent-nonce ledger as the node holds it: shared, and mutable in place.
type RedeemedInvites = Arc<Mutex<SpentNonces>>;

/// How often the blob store sweeps for content no document references.
///
/// Not aggressive, deliberately. A sweep walks every record in the replica store
/// to build the live set, so the cost is proportional to the workspace rather
/// than to what was superseded since the last run. Five minutes bounds the store
/// at roughly one republish cycle's worth of dead blobs, which is a far smaller
/// number than the unbounded growth it replaces.
///
/// Spelled in seconds rather than with `Duration::from_mins`, which clippy
/// prefers: that constructor is newer than this crate's MSRV of 1.91.
#[allow(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_mins postdates the 1.91 MSRV"
)]
pub const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(300);

/// Tunables a [`Node`] is spawned with.
///
/// Exists because the sweep interval is the only way to observe collection at
/// all: `iroh-blobs` runs it on a timer inside the store and exposes no
/// single-shot sweep, so a test — or an application that wants a tighter bound on
/// disk than [`DEFAULT_GC_INTERVAL`] gives — has nothing else to reach for.
#[derive(Debug, Clone)]
pub struct NodeOptions {
    /// How often to reclaim blobs no document entry references.
    ///
    /// Shortening this trades CPU and store reads for a tighter bound on disk
    /// used by superseded content; it never affects correctness, because what a
    /// sweep may delete is decided by the protection callback rather than by how
    /// often it runs.
    pub gc_interval: Duration,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            gc_interval: DEFAULT_GC_INTERVAL,
        }
    }
}

/// The two halves of blob collection, which must be created before either store.
///
/// A blob is reachable if some `iroh-docs` record names its hash, and neither
/// crate knows that on its own: the sweep lives in `iroh-blobs` and the records
/// live in `iroh-docs`. [`ProtectCallbackHandler::new`] returns the two ends of
/// the channel that joins them — the [`ProtectCb`](iroh_blobs::store::ProtectCb)
/// goes into the blob store's
/// [`GcConfig`], the handler into the docs builder — and a store built with only
/// one of them either collects nothing (no config) or collects **everything not
/// currently being written** (config without the callback), because an unanswered
/// protect callback yields an empty live set.
///
/// Returned as a pair from one call site so the two cannot drift apart.
fn gc_pair(interval: Duration) -> (ProtectCallbackHandler, GcConfig) {
    let (handler, protect_cb) = ProtectCallbackHandler::new();
    let config = GcConfig {
        interval,
        add_protected: Some(protect_cb),
    };
    (handler, config)
}

impl Node {
    /// Bind an endpoint and start the blobs, gossip and docs protocols.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Bind`] if the endpoint cannot bind, or
    /// [`WorkspaceError::Storage`] if the docs engine fails to start.
    pub async fn spawn() -> Result<Self, WorkspaceError> {
        Self::spawn_with_options(NodeOptions::default()).await
    }

    /// [`Self::spawn`], with the tunables in [`NodeOptions`] chosen explicitly.
    ///
    /// # Errors
    ///
    /// The same as [`Self::spawn`].
    pub async fn spawn_with_options(options: NodeOptions) -> Result<Self, WorkspaceError> {
        let endpoint = Endpoint::builder(presets::N0)
            .bind()
            .await
            .map_err(|e| WorkspaceError::Bind(e.to_string()))?;

        let (protect_handler, gc) = gc_pair(options.gc_interval);
        let blobs = MemStore::new_with_opts(iroh_blobs::store::mem::Options {
            gc_config: Some(gc),
        });
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::memory()
            .protect_handler(protect_handler)
            .spawn(endpoint.clone(), blobs.deref().clone(), gossip.clone())
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        // Every ALPN behind the same roster. Adding a fourth protocol without
        // wrapping it would silently reopen the hole this closes, which is why
        // registration goes through one shared helper rather than being spelled
        // out once per constructor.
        let admission = Roster::default();
        let blobs = blobs.deref().clone();
        let router = Self::route(&endpoint, &blobs, &gossip, &docs, &admission);

        Ok(Self {
            endpoint,
            router,
            blobs,
            gossip,
            docs,
            roster: admission,
            redeemed: Arc::new(Mutex::new(SpentNonces::new())),
            store: None,
        })
    }

    /// Bind an endpoint backed by `root`, resuming whatever it already holds.
    ///
    /// Everything a restart needs lives under `root`: the endpoint secret key,
    /// the spent-invite ledger, the blob and docs stores, and one snapshot per
    /// workspace. See [`crate::store`] for the layout and for what each file
    /// exposes.
    ///
    /// The endpoint key is the part that is easy to underrate. An `EndpointId`
    /// *is* the peer's public key and *is* its entry on every peer's roster, so a
    /// node that generated a new one on each start would be refused at the
    /// connection level by the workspace it still cryptographically belongs to.
    /// Persistence and admission control are one problem, and this is where they
    /// meet.
    ///
    /// Workspaces are not opened here — the node knows only that snapshots
    /// exist. Use [`Workspace::list`](crate::Workspace::list) to enumerate them
    /// and [`Workspace::open`](crate::Workspace::open) to resume one.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if `root` cannot be prepared, if the
    /// stored endpoint key is unreadable, or if either backing store fails to
    /// open; [`WorkspaceError::Bind`] if the endpoint cannot bind.
    pub async fn spawn_persistent(root: impl AsRef<Path>) -> Result<Self, WorkspaceError> {
        Self::spawn_persistent_with_options(root, NodeOptions::default()).await
    }

    /// [`Self::spawn_persistent`], with the tunables in [`NodeOptions`] chosen
    /// explicitly.
    ///
    /// # Errors
    ///
    /// The same as [`Self::spawn_persistent`].
    pub async fn spawn_persistent_with_options(
        root: impl AsRef<Path>,
        options: NodeOptions,
    ) -> Result<Self, WorkspaceError> {
        let store = Store::open(root)?;

        // Bound to the stored key rather than a fresh one. This is the single
        // line that makes a restart a restart rather than a new node.
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(store.endpoint_key()?)
            .bind()
            .await
            .map_err(|e| WorkspaceError::Bind(e.to_string()))?;

        let (protect_handler, gc) = gc_pair(options.gc_interval);
        // `FsStore::load` is `load_with_opts` with `gc: None`; spelling it out is
        // the only way to hand the store a sweep configuration, and the database
        // filename must match what `load` would have chosen or a restart opens a
        // different store.
        let blob_root = store.subdir(BLOBS_DIR);
        let blob_options = iroh_blobs::store::fs::options::Options {
            gc: Some(gc),
            ..iroh_blobs::store::fs::options::Options::new(&blob_root)
        };
        let blobs = FsStore::load_with_opts(blob_root.join("blobs.db"), blob_options)
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(store.subdir(DOCS_DIR))
            .protect_handler(protect_handler)
            .spawn(endpoint.clone(), blobs.deref().clone(), gossip.clone())
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        let redeemed = store.load_redeemed()?;
        let admission = Roster::default();
        let router = Self::route(&endpoint, &blobs, &gossip, &docs, &admission);

        Ok(Self {
            endpoint,
            router,
            blobs: blobs.deref().clone(),
            gossip,
            docs,
            roster: admission,
            redeemed: Arc::new(Mutex::new(redeemed)),
            store: Some(store),
        })
    }

    /// Register all three protocols behind the roster guard.
    ///
    /// Shared by both constructors so that a protocol added to one is never
    /// missing from the other, and so that no future ALPN can be registered
    /// unguarded on one path only.
    fn route(
        endpoint: &Endpoint,
        blobs: &BlobStore,
        gossip: &Gossip,
        docs: &Docs,
        admission: &Roster,
    ) -> Router {
        Router::builder(endpoint.clone())
            .accept(
                iroh_blobs::ALPN,
                RosterGuard::new(admission.clone(), BlobsProtocol::new(blobs, None)),
            )
            .accept(
                iroh_gossip::ALPN,
                RosterGuard::new(admission.clone(), gossip.clone()),
            )
            .accept(
                iroh_docs::ALPN,
                RosterGuard::new(admission.clone(), docs.clone()),
            )
            .spawn()
    }

    /// Record an invite nonce as redeemed, and say whether it was fresh.
    ///
    /// Returns `true` the first time a `(tree_id, nonce)` pair is presented and
    /// `false` on every repeat, which is what makes an [`Invite`](crate::Invite)
    /// single-use. Keyed by tree id as well as nonce so that two workspaces
    /// cannot collide, however their inviters generate nonces.
    ///
    /// # What this does and does not defend
    ///
    /// It stops a ticket being redeemed twice *on this node* — the accidental
    /// double-join, and a replay against the device the ticket names. It does
    /// nothing about a thief redeeming the same ticket on a machine of their
    /// own; nothing a bearer token carries could. The defences that reach that
    /// case are the roster, which refuses the thief's endpoint, and namespace
    /// rotation, which abandons the replica the ticket points at.
    ///
    /// # Durable on a persistent node, in memory otherwise
    ///
    /// A node from [`Self::spawn_persistent`] writes the ledger through on every
    /// claim, so a ticket redeemed before a crash stays spent after one. A node
    /// from [`Self::spawn`] keeps it in memory only, and a restart un-consumes
    /// every nonce — bounded by the invite's one-hour expiry, which is the
    /// guarantee that holds either way.
    ///
    /// The write happens *after* the in-memory insert and its failure is logged
    /// rather than returned, and the order is deliberate. Refusing the join
    /// because the ledger could not be written would deny a legitimate invitee
    /// over a full disk; accepting it leaves this node in exactly the position an
    /// in-memory node is always in, which is a state the design already tolerates.
    ///
    /// Returns `false` if the lock is poisoned, which is the safe direction: a
    /// node that cannot consult its ledger must refuse the join rather than
    /// assume the nonce is fresh.
    #[must_use]
    pub fn claim_invite(&self, tree_id: [u8; 32], nonce: [u8; 16]) -> bool {
        let Ok(mut redeemed) = self.redeemed.lock() else {
            return false;
        };
        if !redeemed.insert((tree_id, nonce)) {
            return false;
        }
        if let Some(store) = &self.store
            && let Err(e) = store.store_redeemed(&redeemed)
        {
            tracing::warn!(
                %e,
                "an invite nonce was spent but could not be recorded; a restart \
                 before it expires would make the ticket redeemable again"
            );
        }
        true
    }

    /// This node's endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The blob store holding encrypted chunk payloads.
    #[must_use]
    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// Where this node persists, or `None` if it is entirely in memory.
    pub(crate) fn store(&self) -> Option<&Store> {
        self.store.as_ref()
    }

    /// The gossip instance carrying the control plane.
    #[must_use]
    pub fn gossip(&self) -> &Gossip {
        &self.gossip
    }

    /// The docs engine holding the blinded entry index.
    #[must_use]
    pub fn docs(&self) -> &Docs {
        &self.docs
    }

    /// This node's admission list, shared with the guard on every ALPN.
    ///
    /// Crate-internal: the roster is derived from workspace membership, and
    /// letting an application write to it directly would let it admit peers the
    /// group never agreed on.
    pub(crate) fn roster(&self) -> &Roster {
        &self.roster
    }

    /// Shut the node down, closing all protocol handlers.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Bind`] if the router fails to stop cleanly.
    pub async fn shutdown(&self) -> Result<(), WorkspaceError> {
        self.router
            .shutdown()
            .await
            .map_err(|e| WorkspaceError::Bind(e.to_string()))
    }
}
