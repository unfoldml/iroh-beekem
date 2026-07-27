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
//! handed both.

use std::ops::Deref;

use iroh::{Endpoint, endpoint::presets, protocol::Router};
use iroh_blobs::{BlobsProtocol, store::mem::MemStore};
use iroh_docs::protocol::Docs;
use iroh_gossip::net::Gossip;

use crate::error::WorkspaceError;

/// A bound endpoint with all three workspace protocols running.
#[derive(Debug, Clone)]
pub struct Node {
    endpoint: Endpoint,
    router: Router,
    blobs: MemStore,
    gossip: Gossip,
    docs: Docs,
}

impl Node {
    /// Bind an endpoint and start the blobs, gossip and docs protocols.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Bind`] if the endpoint cannot bind, or
    /// [`WorkspaceError::Storage`] if the docs engine fails to start.
    pub async fn spawn() -> Result<Self, WorkspaceError> {
        let endpoint = Endpoint::builder(presets::N0)
            .bind()
            .await
            .map_err(|e| WorkspaceError::Bind(e.to_string()))?;

        let blobs = MemStore::new();
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::memory()
            .spawn(endpoint.clone(), blobs.deref().clone(), gossip.clone())
            .await
            .map_err(|e| WorkspaceError::Storage(e.to_string()))?;

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None))
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_docs::ALPN, docs.clone())
            .spawn();

        Ok(Self {
            endpoint,
            router,
            blobs,
            gossip,
            docs,
        })
    }

    /// This node's endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The blob store holding encrypted chunk payloads.
    #[must_use]
    pub fn blobs(&self) -> &MemStore {
        &self.blobs
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
