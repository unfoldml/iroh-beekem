//! Connection-level admission control.
//!
//! Every one of the three protocols on the endpoint is wrapped in a
//! [`RosterGuard`], which refuses inbound connections from endpoints that are
//! not currently members of the workspace. Without it, confidentiality against
//! an outsider rests on them not knowing two 32-byte identifiers — the gossip
//! topic and the docs namespace — rather than on holding a key, because neither
//! `iroh-gossip` nor `iroh-docs` applies any admission control of its own.
//!
//! # Why the endpoint id is a real check
//!
//! An [`EndpointId`] *is* the peer's public key, and the QUIC/TLS handshake
//! proves possession of the matching secret. So an allowlist of endpoint ids is
//! an authenticated allowlist, not a hint that a peer could simply assert its
//! way past. This is the one property that makes the whole mechanism worth
//! having.
//!
//! # What it does not do
//!
//! * **Eviction is eventual.** The roster is derived from the manifest and the
//!   CGKA membership, both of which converge asynchronously, so a removed
//!   device still reaches peers that have not yet merged the removal.
//! * **It is an availability boundary, not a confidentiality one.** It decides
//!   who may attempt to sync. What a peer can *read* is decided by the CGKA,
//!   and nothing here retracts data that was already synced.
//! * **It hides nothing from a member in good standing**, and relays still
//!   observe connection metadata either way.

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use iroh::{
    EndpointId,
    endpoint::{Accepting, Connection, VarInt},
    protocol::{AcceptError, ProtocolHandler},
};

/// The QUIC application error code sent when a connection is refused.
///
/// A distinct code rather than a generic close so that a peer can tell "you are
/// not on the roster" apart from "the node is shutting down" — the two call for
/// completely different responses, and only one of them is worth retrying.
const REFUSED_CODE: VarInt = VarInt::from_u32(0x1E_E1);

/// Who this node currently accepts connections from.
///
/// Two sets rather than one, because they are maintained by different means and
/// have different lifetimes.
#[derive(Debug, Default)]
struct Allowed {
    /// Endpoints derived from the manifest and current CGKA membership.
    ///
    /// Replaced wholesale on every recompute, which is what makes removal take
    /// effect: an evicted device simply stops appearing.
    derived: HashSet<EndpointId>,
    /// Endpoints admitted unconditionally, to break the bootstrap circle.
    ///
    /// A joiner must be able to reach its inviter before it holds the manifest
    /// that would authorise the inviter — and before the inviter's peers hold
    /// the manifest that would authorise *it*. This set is the exception, and
    /// it is deliberately small: exactly the inviter named in the invite.
    ///
    /// Never pruned when the derived set takes over. A workspace whose inviter
    /// later leaves should not become unjoinable partway through a handshake,
    /// and the cost of keeping the entry is that one endpoint stays reachable —
    /// which grants nothing on its own, since reading still needs the CGKA.
    bootstrap: HashSet<EndpointId>,
}

/// A shared handle to this node's admission list.
///
/// Created by the node so the guard can exist before any workspace does, and
/// populated by the workspace, which is what actually knows the membership.
/// Until a workspace populates it the node accepts nothing — failing closed,
/// because a node with no workspace has no data anybody could legitimately want
/// and no way to tell a member from an outsider.
#[derive(Clone, Debug, Default)]
pub(crate) struct Roster {
    allowed: Arc<RwLock<Allowed>>,
}

impl Roster {
    /// Replace the derived set with a freshly computed one.
    ///
    /// Takes raw bytes because that is what `WorkspaceState::roster` produces;
    /// entries that are not valid endpoint ids are dropped rather than
    /// rejected, since the manifest they came from is remote input and one
    /// malformed record must not cost every other peer their access.
    pub(crate) fn set_derived(&self, endpoints: impl IntoIterator<Item = [u8; 32]>) {
        let derived: HashSet<EndpointId> = endpoints
            .into_iter()
            .filter_map(|bytes| EndpointId::from_bytes(&bytes).ok())
            .collect();
        if let Ok(mut allowed) = self.allowed.write() {
            allowed.derived = derived;
        } else {
            // A poisoned lock means a previous holder panicked while updating
            // the set. Leaving the stale set in place is the safe failure: it
            // was itself a valid roster, so the node keeps refusing outsiders
            // rather than falling open.
        }
    }

    /// Admit one endpoint unconditionally, for the bootstrap case only.
    pub(crate) fn add_bootstrap(&self, endpoint: EndpointId) {
        if let Ok(mut allowed) = self.allowed.write() {
            allowed.bootstrap.insert(endpoint);
        } else {
            // Same reasoning as `set_derived`: fail closed. The joiner will
            // retry, and a refused handshake is recoverable.
        }
    }

    /// Whether a connection from `peer` should be accepted.
    fn admits(&self, peer: EndpointId) -> bool {
        match self.allowed.read() {
            Ok(allowed) => allowed.derived.contains(&peer) || allowed.bootstrap.contains(&peer),
            Err(_) => false,
        }
    }

    /// How many endpoints are currently admitted, bootstrap included.
    ///
    /// Only tests ask; the policy itself never counts.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        match self.allowed.read() {
            Ok(allowed) => allowed.derived.union(&allowed.bootstrap).count(),
            Err(_) => 0,
        }
    }
}

/// Why a connection was refused, as it appears in logs and to the peer.
#[derive(Debug)]
struct NotOnRoster(EndpointId);

impl std::fmt::Display for NotOnRoster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "endpoint {} is not a member of this workspace", self.0)
    }
}

impl std::error::Error for NotOnRoster {}

/// Wraps a protocol handler so it only ever sees connections from members.
///
/// All three ALPNs must be wrapped. Guarding only the control plane would leave
/// `iroh-docs` open, and the docs index is where the metadata leak lives —
/// entry existence, size, author and timing for every document.
#[derive(Debug)]
pub(crate) struct RosterGuard<P: ProtocolHandler> {
    roster: Roster,
    inner: P,
}

impl<P: ProtocolHandler> RosterGuard<P> {
    /// Wrap `inner` so that `roster` decides who reaches it.
    pub(crate) fn new(roster: Roster, inner: P) -> Self {
        Self { roster, inner }
    }
}

impl<P: ProtocolHandler> ProtocolHandler for RosterGuard<P> {
    /// Refuse non-members at the earliest point iroh offers.
    ///
    /// The handshake has to complete before the decision can be made: the peer's
    /// identity is what the handshake establishes, and `Accepting` does not
    /// expose it. Completing it is therefore not a weakness — it is what makes
    /// `remote_id` trustworthy rather than a self-reported claim.
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        let conn = self.inner.on_accepting(accepting).await?;
        let peer = conn.remote_id();
        if self.roster.admits(peer) {
            Ok(conn)
        } else {
            // Close explicitly rather than dropping, so the peer learns it was
            // refused instead of waiting out a timeout and retrying.
            conn.close(REFUSED_CODE, b"not on roster");
            Err(AcceptError::from_err(NotOnRoster(peer)))
        }
    }

    /// Delegate; anything reaching here has already passed `on_accepting`.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        self.inner.accept(connection).await
    }

    /// Delegate, so wrapping a handler does not change its shutdown behaviour.
    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    /// A real endpoint id.
    ///
    /// Generated rather than byte-filled: an `EndpointId` is a compressed
    /// Edwards point, and almost no fixed byte pattern decompresses to one — a
    /// test built on `[7u8; 32]` fails in `from_bytes` before it reaches the
    /// behaviour it meant to check.
    fn endpoint() -> EndpointId {
        SecretKey::generate().public()
    }

    /// 32 bytes that are not a valid endpoint id.
    ///
    /// Searched for rather than hard-coded: most byte patterns *do* decompress
    /// to a curve point — `[0xFF; 32]` among them — so a hand-picked constant
    /// silently turns this test into a second copy of the happy path. Failure to
    /// find one within the budget is itself reported, because that would mean
    /// the premise no longer holds.
    fn not_an_endpoint() -> [u8; 32] {
        (0u32..4096)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&i.to_le_bytes());
                // The high bit of the last byte is the sign of x; setting it on
                // a y that has no square root is the cheapest way to land off
                // the curve.
                bytes[31] = 0x80;
                bytes
            })
            .find(|bytes| EndpointId::from_bytes(bytes).is_err())
            .expect(
                "no invalid encoding found in 4096 tries, so this test cannot pose its question",
            )
    }

    /// Given a freshly created roster, when nothing has populated it yet, we
    /// expect every peer to be refused.
    ///
    /// Failing closed is the whole point: a node that accepted by default until
    /// its first manifest sync would leave a window in which any outsider who
    /// knew the topic id could join the overlay, which is precisely the state
    /// this module exists to end.
    #[test]
    fn an_unpopulated_roster_admits_nobody() {
        let roster = Roster::default();
        assert!(
            !roster.admits(endpoint()),
            "an empty roster admitted a peer, so a node would accept connections \
             before it knows who its members are"
        );
    }

    /// Given a roster holding two derived endpoints, when it is recomputed
    /// without one of them, we expect that one to stop being admitted and the
    /// other to keep being admitted.
    ///
    /// This is revocation. `set_derived` replaces rather than merges for exactly
    /// this reason: a merging update could never shrink, and a roster that only
    /// grows makes removal decorative.
    #[test]
    fn recomputing_the_derived_set_evicts_what_it_omits() {
        let roster = Roster::default();
        let (member, other) = (endpoint(), endpoint());

        roster.set_derived([*member.as_bytes(), *other.as_bytes()]);
        assert!(
            roster.admits(member),
            "an endpoint that was just derived into the roster was not admitted"
        );

        roster.set_derived([*other.as_bytes()]);
        assert!(
            !roster.admits(member),
            "an endpoint omitted from the recomputed roster was still admitted, \
             so removing a device would not stop it connecting"
        );
        assert!(
            roster.admits(other),
            "recomputing the roster evicted an endpoint it still contained"
        );
    }

    /// Given a bootstrap endpoint admitted at join time, when the derived set is
    /// later recomputed without it, we expect it to stay admitted.
    ///
    /// The inviter is reachable before any manifest has propagated, and a
    /// recompute that dropped it could strand a joiner mid-handshake — it would
    /// lose the one peer able to send it the manifest that would authorise
    /// everyone else.
    #[test]
    fn a_bootstrap_endpoint_survives_a_derived_recompute() {
        let roster = Roster::default();
        let inviter = endpoint();

        roster.add_bootstrap(inviter);
        roster.set_derived(Vec::new());

        assert!(
            roster.admits(inviter),
            "the bootstrap inviter was evicted by a derived recompute, so a joiner \
             could lose its only route to the manifest before receiving it"
        );
    }

    /// Given a device record whose stored address is not a valid endpoint id,
    /// when the roster is recomputed, we expect the malformed entry to be
    /// dropped and its valid siblings kept.
    ///
    /// The manifest is remote input. One malformed device record must not cost
    /// every other member their access, and must not panic the recompute.
    #[test]
    fn a_malformed_endpoint_does_not_discard_the_valid_ones() {
        let roster = Roster::default();
        let good = endpoint();
        let malformed = not_an_endpoint();

        roster.set_derived([malformed, *good.as_bytes()]);

        assert!(
            roster.admits(good),
            "a malformed sibling record cost a valid member their place on the roster"
        );
        assert_eq!(
            roster.len(),
            1,
            "the malformed entry was admitted rather than dropped"
        );
    }
}
