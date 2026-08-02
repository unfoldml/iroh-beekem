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
//! * **It does not isolate two workspaces on one node from each other.** See
//!   below; this is a property of the transport, not a gap in the bookkeeping.
//!
//! # Per workspace, but admission is still a union
//!
//! [`Roster`] keys its admission sets by tree id, and that is load-bearing: a
//! single flat set would be *replaced* by whichever workspace recomputed last,
//! so two workspaces on one node would clobber each other's members on every
//! refresh and admit them in alternation. Keying by workspace is what makes each
//! recompute affect only its own members.
//!
//! What it does **not** buy is isolation. [`RosterGuard::on_accepting`] sees an
//! [`EndpointId`] and nothing else: `iroh-gossip` multiplexes every topic and
//! `iroh-docs` every namespace over one connection per ALPN, so there is no
//! workspace to attribute the connection to at the moment the decision is made.
//! [`Roster::admits`] therefore answers "is this peer a member of *any*
//! workspace on this node", and a member of one may open a connection that
//! carries traffic for another.
//!
//! That residual is not closable here. Closing it means one endpoint per
//! workspace — a separate [`Node`](crate::Node) — which costs an `EndpointId`,
//! a relay registration and a hole-punching path per workspace. It is worth
//! knowing that the confidentiality boundary is unaffected either way: reaching
//! a namespace is not reading it, and every chunk in it is encrypted to a CGKA
//! this peer holds no leaf in.

use std::{
    collections::{BTreeMap, HashSet},
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

/// A shared handle to this node's admission lists, one per workspace.
///
/// Created by the node so the guard can exist before any workspace does, and
/// populated by each workspace, which is what actually knows its own membership.
/// Until a workspace populates it the node accepts nothing — failing closed,
/// because a node with no workspace has no data anybody could legitimately want
/// and no way to tell a member from an outsider.
///
/// Keyed by tree id, and see the module documentation for both halves of what
/// that does: it stops two workspaces overwriting each other's members, and it
/// does not stop a member of one connecting to the other.
#[derive(Clone, Debug, Default)]
pub(crate) struct Roster {
    workspaces: Arc<RwLock<BTreeMap<[u8; 32], Allowed>>>,
}

impl Roster {
    /// Replace one workspace's derived set with a freshly computed one.
    ///
    /// Takes raw bytes because that is what `WorkspaceState::roster` produces;
    /// entries that are not valid endpoint ids are dropped rather than
    /// rejected, since the manifest they came from is remote input and one
    /// malformed record must not cost every other peer their access.
    ///
    /// Scoped to `workspace` so that a recompute driven by one workspace's
    /// manifest cannot evict another's members — which a single shared set,
    /// replaced wholesale, would do on every refresh.
    pub(crate) fn set_derived(
        &self,
        workspace: [u8; 32],
        endpoints: impl IntoIterator<Item = [u8; 32]>,
    ) {
        let derived: HashSet<EndpointId> = endpoints
            .into_iter()
            .filter_map(|bytes| EndpointId::from_bytes(&bytes).ok())
            .collect();
        if let Ok(mut workspaces) = self.workspaces.write() {
            workspaces.entry(workspace).or_default().derived = derived;
        } else {
            // A poisoned lock means a previous holder panicked while updating
            // the set. Leaving the stale set in place is the safe failure: it
            // was itself a valid roster, so the node keeps refusing outsiders
            // rather than falling open.
        }
    }

    /// Admit one endpoint to one workspace unconditionally, for bootstrap only.
    pub(crate) fn add_bootstrap(&self, workspace: [u8; 32], endpoint: EndpointId) {
        if let Ok(mut workspaces) = self.workspaces.write() {
            workspaces
                .entry(workspace)
                .or_default()
                .bootstrap
                .insert(endpoint);
        } else {
            // Same reasoning as `set_derived`: fail closed. The joiner will
            // retry, and a refused handshake is recoverable.
        }
    }

    /// Drop one workspace's admission set entirely.
    ///
    /// Called when a workspace is deleted or left. Without it the departed
    /// workspace's members would keep being admitted for the lifetime of the
    /// node, since [`Self::admits`] is a union and nothing else ever shrinks a
    /// workspace's entry to nothing.
    pub(crate) fn forget(&self, workspace: [u8; 32]) {
        if let Ok(mut workspaces) = self.workspaces.write() {
            workspaces.remove(&workspace);
        } else {
            // Fail closed in the other direction here: keeping a stale set
            // admits peers of a workspace this node no longer holds, which costs
            // an accepted connection that then finds nothing to sync.
        }
    }

    /// Whether a connection from `peer` should be accepted.
    ///
    /// A union over every workspace on this node, because the decision has to be
    /// made from an `EndpointId` alone — see the module documentation.
    fn admits(&self, peer: EndpointId) -> bool {
        match self.workspaces.read() {
            Ok(workspaces) => workspaces.values().any(|allowed| {
                allowed.derived.contains(&peer) || allowed.bootstrap.contains(&peer)
            }),
            Err(_) => false,
        }
    }

    /// How many distinct endpoints are admitted across every workspace.
    ///
    /// Only tests ask; the policy itself never counts.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        match self.workspaces.read() {
            Ok(workspaces) => workspaces
                .values()
                .flat_map(|allowed| allowed.derived.union(&allowed.bootstrap))
                .collect::<HashSet<_>>()
                .len(),
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

    /// The workspace these single-workspace tests all speak about.
    const WS: [u8; 32] = [1u8; 32];

    /// A second workspace, for the tests that need two.
    const OTHER_WS: [u8; 32] = [2u8; 32];

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

        roster.set_derived(WS, [*member.as_bytes(), *other.as_bytes()]);
        assert!(
            roster.admits(member),
            "an endpoint that was just derived into the roster was not admitted"
        );

        roster.set_derived(WS, [*other.as_bytes()]);
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

        roster.add_bootstrap(WS, inviter);
        roster.set_derived(WS, Vec::new());

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

        roster.set_derived(WS, [malformed, *good.as_bytes()]);

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

    /// Given two workspaces on one node, when the second recomputes its derived
    /// set, we expect the first's members to stay admitted.
    ///
    /// This is the defect that keying by workspace exists to fix. `set_derived`
    /// *replaces* rather than merges — it has to, or removal would never take
    /// effect — so with one shared set the two workspaces would evict each
    /// other's members on every refresh, and since both refresh on every
    /// manifest arrival, membership would flap for as long as the node ran.
    #[test]
    fn one_workspaces_recompute_does_not_evict_anothers_members() {
        let roster = Roster::default();
        let (theirs, mine) = (endpoint(), endpoint());

        roster.set_derived(WS, [*theirs.as_bytes()]);
        roster.set_derived(OTHER_WS, [*mine.as_bytes()]);

        assert!(
            roster.admits(theirs),
            "a second workspace's recompute evicted the first workspace's member, \
             so two workspaces on one node would flap each other's admission"
        );
        assert!(
            roster.admits(mine),
            "the workspace that recomputed last did not admit its own member"
        );
    }

    /// Given a member of one workspace only, when a second workspace recomputes
    /// without them, we expect them to remain admitted — admission is a union.
    ///
    /// Asserted rather than left implicit because it is a *limitation* being
    /// pinned, not a feature: `on_accepting` sees an `EndpointId` and no
    /// workspace, so this is the strongest answer the guard can give. Writing it
    /// down means a future reader finds the residual here rather than assuming
    /// the per-workspace keying bought isolation it does not.
    #[test]
    fn admission_is_a_union_across_workspaces() {
        let roster = Roster::default();
        let outsider_to_ws = endpoint();

        roster.set_derived(OTHER_WS, [*outsider_to_ws.as_bytes()]);
        roster.set_derived(WS, Vec::new());

        assert!(
            roster.admits(outsider_to_ws),
            "a member of one workspace was refused although it is admitted to \
             another on the same node; admission cannot be workspace-scoped, so \
             this must hold or the guard would refuse legitimate peers"
        );
    }

    /// Given two workspaces, when one is forgotten, we expect only its members
    /// to stop being admitted.
    ///
    /// This is what `delete` and `leave` rely on. `admits` is a union, so a
    /// workspace whose entry is merely emptied of *derived* members would still
    /// admit its bootstrap inviter forever.
    #[test]
    fn forgetting_a_workspace_evicts_only_its_own_members() {
        let roster = Roster::default();
        let (leaving, staying) = (endpoint(), endpoint());

        roster.add_bootstrap(WS, leaving);
        roster.set_derived(WS, [*leaving.as_bytes()]);
        roster.set_derived(OTHER_WS, [*staying.as_bytes()]);

        roster.forget(WS);

        assert!(
            !roster.admits(leaving),
            "a member of a deleted workspace was still admitted, including via the              bootstrap set that a derived recompute deliberately never prunes"
        );
        assert!(
            roster.admits(staying),
            "forgetting one workspace evicted another's members"
        );
    }

    /// Given a workspace whose derived set is emptied, when nothing else has
    /// admitted the peer, we expect it to be refused.
    ///
    /// The counterweight to the union test above: without this, `admits`
    /// returning `true` unconditionally would satisfy that one.
    #[test]
    fn emptying_the_last_workspace_refuses_everyone_again() {
        let roster = Roster::default();
        let member = endpoint();

        roster.set_derived(WS, [*member.as_bytes()]);
        roster.set_derived(WS, Vec::new());

        assert!(
            !roster.admits(member),
            "a member remained admitted after the only workspace admitting it \
             recomputed to empty, so removal would not stop it connecting"
        );
    }
}
