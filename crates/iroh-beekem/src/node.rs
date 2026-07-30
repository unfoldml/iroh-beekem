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
//!
//! All three are wrapped in a [`RosterGuard`] before being registered, so a peer
//! that is not a member of the workspace is refused at the connection level on
//! every ALPN. Guarding only gossip would leave the docs index — and with it
//! every document's existence, size, author and timing — readable by anyone who
//! learned the namespace.

use std::{
    collections::HashSet,
    ops::Deref,
    sync::{Arc, Mutex},
};

use iroh::{Endpoint, endpoint::presets, protocol::Router};
use iroh_blobs::{BlobsProtocol, store::mem::MemStore};
use iroh_docs::protocol::Docs;
use iroh_gossip::net::Gossip;

use crate::{
    error::WorkspaceError,
    roster::{Roster, RosterGuard},
};

/// A bound endpoint with all three workspace protocols running.
#[derive(Debug, Clone)]
pub struct Node {
    endpoint: Endpoint,
    router: Router,
    blobs: MemStore,
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
}

/// Invite nonces already spent, keyed by `(tree id, nonce)`.
///
/// A named type only because the nesting is otherwise unreadable; the tree id is
/// part of the key so two workspaces on one node cannot collide.
type RedeemedInvites = Arc<Mutex<HashSet<([u8; 32], [u8; 16])>>>;

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

        // Every ALPN behind the same roster. Adding a fourth protocol without
        // wrapping it would silently reopen the hole this closes, which is why
        // the guard is applied here rather than inside each protocol.
        let admission = Roster::default();
        let router = Router::builder(endpoint.clone())
            .accept(
                iroh_blobs::ALPN,
                RosterGuard::new(admission.clone(), BlobsProtocol::new(&blobs, None)),
            )
            .accept(
                iroh_gossip::ALPN,
                RosterGuard::new(admission.clone(), gossip.clone()),
            )
            .accept(
                iroh_docs::ALPN,
                RosterGuard::new(admission.clone(), docs.clone()),
            )
            .spawn();

        Ok(Self {
            endpoint,
            router,
            blobs,
            gossip,
            docs,
            roster: admission,
            redeemed: Arc::new(Mutex::new(HashSet::new())),
        })
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
    /// # In memory only, and a restart un-consumes every nonce
    ///
    /// Stated rather than implied, because it is a real gap: this set does not
    /// survive a process restart, so a ticket redeemed before a crash is
    /// redeemable again after one — for as long as it has not expired, which is
    /// the bound that still holds. Phase 7 persists it alongside the node's
    /// endpoint secret key.
    ///
    /// Returns `false` if the lock is poisoned, which is the safe direction: a
    /// node that cannot consult its ledger must refuse the join rather than
    /// assume the nonce is fresh.
    #[must_use]
    pub fn claim_invite(&self, tree_id: [u8; 32], nonce: [u8; 16]) -> bool {
        match self.redeemed.lock() {
            Ok(mut redeemed) => redeemed.insert((tree_id, nonce)),
            Err(_) => false,
        }
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
