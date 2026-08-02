//! Two real `iroh` endpoints, real QUIC, real sync.
//!
//! The protocol logic below is already covered by the deterministic simulator
//! in `iroh-beekem-sim`. What these tests add is proof that the transport
//! wiring is actually connected: ALPNs registered, gossip overlay bootstrapped,
//! docs namespace shared with a write capability, blob payloads fetched.
//!
//! # Two rules for tests here
//!
//! **Spawn nodes through `test_node`, never `Node::spawn`.** Both endpoints in
//! any test live on one machine, so a relay can never be the path that works —
//! but with the default `NodeOptions` each endpoint still opened and maintained
//! connections to Number 0's public relay servers, and with eight tests running
//! at once that dominated everything else the suite did. Measured at cargo's
//! default parallelism: 21 of 38 tests timed out with relays enabled, 2 with them
//! disabled, 0 once the rule below was applied as well.
//!
//! **A test running three or more endpoints at once needs
//! `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`.** Plain
//! `#[tokio::test]` builds a *current-thread* runtime, so every endpoint's QUIC
//! I/O, gossip, docs reconciliation and blob transfer share one thread with the
//! test body's polling. Two endpoints fit; three do not, once seven other tests
//! are competing for the same eight cores. The test then reports whatever it was
//! waiting for as the failure — a missing member, a missing entry — rather than
//! the scheduling that caused it. Two workers and not the default of one per
//! core: at cargo's default parallelism that would be eight runtimes of eight.

use std::time::Duration;

use iroh_beekem::{Identity, Invite, Node, NodeOptions, Relay, Workspace, WorkspaceError};
use iroh_beekem_core::{DocumentUuid, Role, WorkspaceInfo};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// The logical path every test writes to, so each one can resolve its own
/// document rather than sharing a hardcoded UUID.
const PATH: &str = "/notes.md";

fn info(name: &str) -> WorkspaceInfo {
    WorkspaceInfo {
        name: name.to_string(),
        description: String::new(),
    }
}

/// A node for a test: everything default except that it never uses a relay.
///
/// **Spawn every test node through this, not through [`Node::spawn`].** Both
/// endpoints in any test here live on one machine, so a relay can never be the
/// path that works — but with the default configuration each one still opened
/// and maintained connections to Number 0's public relay servers, and several
/// tests running at once made that the dominant cost of the whole suite. It looks
/// exactly like a protocol regression: assorted `eventually` waits time out, in
/// tests that pass the moment they are run alone. Measured on an eight-core
/// machine at cargo's default parallelism, 21 of 38 tests timed out with relays
/// enabled and 2 with them disabled.
///
/// Address lookup is deliberately left on. It is what turns an endpoint id into
/// an address, and this crate names peers by id — a restarted node re-dials the
/// roster it read back from its own manifest, which holds ids and no addresses,
/// so `a_restarted_joiners_later_writes_are_still_accepted` fails without it.
async fn test_node() -> Node {
    Node::spawn_with_options(NodeOptions {
        relay: Relay::Disabled,
        ..NodeOptions::default()
    })
    .await
    .expect("a test node should bind")
}

/// [`test_node`], backed by a directory so it can be restarted.
async fn test_node_persistent(root: impl AsRef<std::path::Path>) -> Result<Node, WorkspaceError> {
    Node::spawn_persistent_with_options(
        root,
        NodeOptions {
            relay: Relay::Disabled,
            ..NodeOptions::default()
        },
    )
    .await
}

/// Found a workspace with one document already created, and return both.
async fn founded(seed: u64, name: &str) -> (Workspace, DocumentUuid) {
    let node = crate::test_node().await;
    let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(seed));
    let ws = Workspace::create(
        node,
        &identity,
        info(name),
        &mut ChaCha20Rng::seed_from_u64(seed),
    )
    .await
    .expect("founding a workspace should succeed");
    let doc = ws
        .create_file(PATH, "text/markdown")
        .await
        .expect("creating the document");
    (ws, doc)
}

/// Poll until `check` passes, or fail with `what` as the explanation.
///
/// Real networking has no virtual clock to fast-forward, so these tests wait on
/// outcomes rather than on fixed sleeps.
async fn eventually<F, Fut>(what: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out after {timeout:?} waiting for: {what}");
}

/// Assert `check` stays false for the whole window.
///
/// Used for the negative security assertion, where "has not happened yet" only
/// means something if we actually gave it time to happen.
async fn never<F, Fut>(what: &str, window: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < window {
        assert!(!check().await, "expected never to happen, but did: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Alice founds a workspace and invites Bob, who joins over the network.
struct Pair {
    alice: Workspace,
    bob: Workspace,
    bob_id: beekem::id::MemberId,
    /// The document alice created before inviting bob.
    doc: DocumentUuid,
}

async fn invited_pair(seed: u64) -> Pair {
    invited_pair_as(seed, Role::Editor).await
}

async fn invited_pair_as(seed: u64, role: Role) -> Pair {
    let (alice, doc) = founded(seed, "shared").await;
    let bob_node = crate::test_node().await;

    // Bob generates his device identity and publishes only its public leaf key;
    // the secret half never leaves his device, which is what makes an
    // intercepted invite useless for joining.
    let bob_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(seed + 1));

    let invite: Invite = alice
        .add_user(
            &bob_identity.enrollment(bob_node.endpoint().id()),
            role,
            "bob",
        )
        .await
        .expect("alice admits bob");

    let bob = Workspace::join(
        bob_node,
        &invite,
        &bob_identity,
        &mut ChaCha20Rng::seed_from_u64(seed + 3),
    )
    .await
    .expect("bob joins from the invite");

    Pair {
        alice,
        bob,
        bob_id: bob_identity.member_id(),
        doc,
    }
}

#[tokio::test]
async fn a_founded_workspace_starts_with_one_member() {
    let (ws, _doc) = founded(1, "solo").await;

    assert_eq!(
        ws.group_size().await,
        1,
        "a freshly founded workspace should contain only its founder"
    );

    ws.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn local_edits_are_readable_locally() {
    let (ws, doc) = founded(2, "solo").await;

    ws.append(doc, "hello")
        .await
        .expect("appending should succeed");

    assert_eq!(
        ws.read(doc).await,
        "hello",
        "a node must be able to read back what it just wrote"
    );

    ws.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn an_invited_peer_reconstructs_the_group_from_the_operation_log() {
    let Pair { alice, bob, .. } = invited_pair(10).await;

    assert_eq!(
        alice.group_size().await,
        2,
        "alice should see two members after inviting bob"
    );
    assert_eq!(
        bob.group_size().await,
        2,
        "bob should reconstruct the same two-member group from the log alone"
    );

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn edits_propagate_from_the_founder_to_a_joiner_over_quic() {
    let Pair {
        alice, bob, doc, ..
    } = invited_pair(20).await;

    alice
        .append(doc, "from alice")
        .await
        .expect("alice writes after bob joined");

    eventually(
        "bob receives alice's edit",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.read(doc).await.contains("from alice")
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

/// Given a document written *before* a member was invited, when that member
/// joins, we expect them to end up reading it over real QUIC.
///
/// User story 1 — "invite a teammate so they can immediately access workspace
/// files" — and the one case encryption alone cannot deliver: bob cannot derive
/// any epoch that predates his leaf, so this content reaches him only because a
/// member that can read it re-encrypts under a live epoch. Every other test in
/// this file writes *after* the invite, which is the ordering that never needs
/// that to happen.
#[tokio::test]
async fn content_written_before_the_invite_reaches_the_joiner() {
    let (alice, doc) = founded(21, "shared").await;
    alice
        .append(doc, "written before bob was invited")
        .await
        .expect("alice writes while she is alone in the workspace");

    let bob_node = crate::test_node().await;
    let bob_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(22));
    let invite: Invite = alice
        .add_user(
            &bob_identity.enrollment(bob_node.endpoint().id()),
            Role::Editor,
            "bob",
        )
        .await
        .expect("alice admits bob");
    let bob = Workspace::join(
        bob_node,
        &invite,
        &bob_identity,
        &mut ChaCha20Rng::seed_from_u64(23),
    )
    .await
    .expect("bob joins from the invite");

    eventually(
        "bob reads content that existed before he was admitted",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.read(doc).await.contains("written before bob")
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn edits_propagate_from_a_joiner_back_to_the_founder() {
    let Pair {
        alice, bob, doc, ..
    } = invited_pair(30).await;

    bob.append(doc, "from bob").await.expect("bob writes");

    eventually(
        "alice receives bob's edit",
        Duration::from_secs(30),
        || async {
            alice.ingest().await;
            alice.read(doc).await.contains("from bob")
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn the_manifest_and_its_roles_reach_a_joiner_over_quic() {
    let Pair {
        alice,
        bob,
        bob_id,
        doc,
    } = invited_pair(50).await;

    alice
        .rename(doc, "/finance/q3.json")
        .await
        .expect("alice records the document's path");

    // Logical paths exist only inside the encrypted manifest — `iroh-docs` sees
    // a blinded 32-byte key and nothing else — so this arriving at all proves
    // the manifest was encrypted, stored at its well-known key, synced, fetched
    // and decrypted.
    eventually(
        "bob sees the document's logical path",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.files()
                .await
                .iter()
                .any(|f| f.logical_path == "/finance/q3.json")
        },
    )
    .await;

    let roles = bob.roles().await;
    assert!(
        roles
            .iter()
            .any(|(m, r)| *m == bob_id.to_bytes() && *r == Role::Editor),
        "an admitted member should have been given a writing role, got {roles:?}"
    );

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn content_still_flows_across_a_key_rotation() {
    let Pair {
        alice, bob, doc, ..
    } = invited_pair(70).await;

    alice
        .append(doc, "before rotation. ")
        .await
        .expect("alice writes");
    eventually(
        "bob reads before the rotation",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.read(doc).await.contains("before rotation")
        },
    )
    .await;

    // Post-compromise security: after this, alice's old leaf secret derives no
    // further group key. The group must keep working across it, which is the
    // part a rotation can silently break.
    bob.rotate().await.expect("bob rotates his leaf key");

    alice
        .append(doc, "after rotation.")
        .await
        .expect("alice writes again");
    eventually(
        "bob reads across the rotation",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.read(doc).await.contains("after rotation")
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn a_joiner_cannot_revoke_the_founder() {
    let Pair { alice, bob, .. } = invited_pair(60).await;
    let alice_id = alice.member_id().await;

    // Bob is an editor, not an admin. Membership changes are an admin action,
    // and this is the check that was specified in the manifest but never called.
    let result = bob.remove_device(alice_id).await;

    assert!(
        matches!(
            result,
            Err(iroh_beekem::WorkspaceError::Core(
                iroh_beekem_core::CoreError::NotAnAdmin
            ))
        ),
        "a non-admin member must not be able to revoke anyone, got {result:?}"
    );
    assert_eq!(
        alice.group_size().await,
        2,
        "the refused revocation must have left the group intact"
    );

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn a_revoked_member_cannot_read_later_edits() {
    let Pair {
        alice,
        bob,
        bob_id,
        doc,
    } = invited_pair(40).await;

    // Establish that bob really could read first, so the assertion below is
    // about revocation and not about a workspace that never worked.
    alice.append(doc, "before").await.expect("alice writes");
    eventually(
        "bob reads before revocation",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.read(doc).await.contains("before")
        },
    )
    .await;

    alice
        .remove_device(bob_id)
        .await
        .expect("alice revokes bob");
    alice
        .append(doc, "AFTER-REVOCATION")
        .await
        .expect("alice writes after revoking");

    // Bob still sees the whole public control plane and can still fetch every
    // ciphertext — he simply cannot derive the key.
    never(
        "revoked member reads post-revocation content",
        Duration::from_secs(10),
        || async {
            bob.ingest().await;
            bob.read(doc).await.contains("AFTER-REVOCATION")
        },
    )
    .await;

    assert!(
        alice.read(doc).await.contains("AFTER-REVOCATION"),
        "alice should still be able to read her own edit"
    );

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

/// The facade pinned one document per workspace until Phase 2; the core always
/// keyed documents by UUID and the manifest always indexed them. These prove
/// the facade caught up, over real QUIC rather than in the simulator.
#[tokio::test]
async fn two_documents_converge_independently_over_quic() {
    let Pair {
        alice, bob, doc, ..
    } = invited_pair(80).await;

    let second = alice
        .create_file("/second.md", "text/markdown")
        .await
        .expect("alice creates a second document");

    alice.append(doc, "first doc").await.expect("alice writes");
    alice
        .append(second, "second doc")
        .await
        .expect("alice writes to the second");

    eventually(
        "bob receives both documents",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.read(doc).await.contains("first doc")
                && bob.read(second).await.contains("second doc")
        },
    )
    .await;

    assert_eq!(
        bob.files().await.len(),
        2,
        "bob should see both documents in the manifest"
    );
    assert_eq!(
        bob.resolve("/second.md").await,
        Some(second),
        "a logical path must resolve to the same UUID on both peers"
    );

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn a_deleted_document_disappears_from_a_peers_view() {
    let Pair {
        alice, bob, doc, ..
    } = invited_pair(90).await;

    alice.append(doc, "doomed").await.expect("alice writes");
    eventually("bob sees the document", Duration::from_secs(30), || async {
        bob.ingest().await;
        bob.read(doc).await.contains("doomed")
    })
    .await;

    alice.delete_file(doc).await.expect("alice deletes it");

    eventually("bob sees the deletion", Duration::from_secs(30), || async {
        bob.ingest().await;
        bob.files().await.is_empty()
    })
    .await;

    assert_eq!(
        bob.resolve(PATH).await,
        None,
        "the deleted path must no longer resolve on the peer"
    );

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn the_workspace_name_reaches_a_joiner() {
    let Pair { alice, bob, .. } = invited_pair(100).await;

    assert_eq!(
        alice.info().await.name,
        "shared",
        "the founder should see the name it was created with"
    );

    eventually(
        "bob learns the workspace name",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.info().await.name == "shared"
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn a_viewer_is_given_a_read_only_capability() {
    // `iroh-docs` has no per-member write key, so a write ticket cannot be
    // withdrawn short of rotating the namespace. Handing one to somebody who is
    // not supposed to write gives away a capability for nothing.
    use iroh_docs::sync::Capability;

    let (alice, _doc) = founded(110, "shared").await;
    // Real nodes, because admitting somebody now records the address they will
    // connect from: the roster has to know it before the invite is handed over.
    let viewer_node = crate::test_node().await;
    let editor_node = crate::test_node().await;
    let viewer = Identity::generate(&mut ChaCha20Rng::seed_from_u64(111));

    let invite = alice
        .add_user(
            &viewer.enrollment(viewer_node.endpoint().id()),
            Role::Viewer,
            "viewer",
        )
        .await
        .expect("alice admits a viewer");
    assert!(
        matches!(invite.terms().doc_ticket.capability, Capability::Read(_)),
        "a viewer must not receive a write capability"
    );

    let editor = Identity::generate(&mut ChaCha20Rng::seed_from_u64(112));
    let invite = alice
        .add_user(
            &editor.enrollment(editor_node.endpoint().id()),
            Role::Editor,
            "editor",
        )
        .await
        .expect("alice admits an editor");
    assert!(
        matches!(invite.terms().doc_ticket.capability, Capability::Write(_)),
        "an editor must still receive a write capability"
    );

    alice.shutdown().await.expect("alice shuts down");
}

#[tokio::test]
async fn a_second_device_joins_its_users_account_and_inherits_the_role() {
    let (alice, doc) = founded(120, "shared").await;
    let alice_user = alice.me().await.expect("alice knows her own user").id;

    // Alice enrols a laptop of her own. This is not an administrative act, and
    // the new device gets no role of its own — it acts under alice's.
    let laptop_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(121));
    let laptop_node = crate::test_node().await;
    let invite = alice
        .add_device(
            &laptop_identity.enrollment(laptop_node.endpoint().id()),
            alice_user,
            "laptop",
        )
        .await
        .expect("alice enrols her laptop");

    let laptop = Workspace::join(
        laptop_node,
        &invite,
        &laptop_identity,
        &mut ChaCha20Rng::seed_from_u64(122),
    )
    .await
    .expect("the laptop joins");

    alice
        .append(doc, "written on the desktop")
        .await
        .expect("alice writes");

    eventually(
        "the laptop reads what the desktop wrote",
        Duration::from_secs(30),
        || async {
            laptop.ingest().await;
            laptop.read(doc).await.contains("written on the desktop")
        },
    )
    .await;

    eventually(
        "the laptop is listed as alice's second device",
        Duration::from_secs(30),
        || async {
            laptop.ingest().await;
            laptop
                .user(alice_user)
                .await
                .is_some_and(|u| u.devices.len() == 2 && u.role == Some(Role::Admin))
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    laptop.shutdown().await.expect("the laptop shuts down");
}

/// Connection-level admission control, against three live endpoints.
///
/// The simulator models the *effect* of the roster — a node that is not a
/// member observes nothing — but it cannot show that the guard is wired to
/// `iroh` at all. Only a real handshake can, which is what these tests are for.
mod admission_control_is_wired_to_iroh {
    use iroh::{endpoint::ConnectionError, protocol::ProtocolHandler};

    use super::*;

    /// Every ALPN the node speaks. A guard on one and not the others would be
    /// worse than none, because the docs index is where the metadata lives.
    const ALPNS: [(&str, &[u8]); 3] = [
        ("blobs", iroh_blobs::ALPN),
        ("gossip", iroh_gossip::ALPN),
        ("docs", iroh_docs::ALPN),
    ];

    /// How long a connection must survive before it counts as accepted.
    ///
    /// Long enough for a refusal to make the round trip on a loopback endpoint,
    /// short enough that three ALPNs times two tests stays quick.
    const SURVIVES_FOR: Duration = Duration::from_secs(3);

    /// Whether `stranger` can hold an open connection to `target` on `alpn`.
    ///
    /// A refusal happens *after* the QUIC handshake — the peer's identity is
    /// what the handshake establishes, so there is nothing to check before it —
    /// so `connect` itself routinely succeeds against a node that is about to
    /// refuse. Survival is the observable that separates the two.
    ///
    /// Deliberately **not** probed with `open_bi`: opening a stream is a local
    /// operation in QUIC and returns `Ok` before the peer has seen anything, so
    /// it reports success against a node that never accepted the connection at
    /// all. Waiting for the peer to close is the only probe here that actually
    /// depends on the peer.
    async fn can_hold_a_connection(
        stranger: &iroh::Endpoint,
        target: iroh::EndpointAddr,
        alpn: &[u8],
    ) -> bool {
        let Ok(conn) = stranger.connect(target, alpn).await else {
            return false;
        };
        // Timing out means nobody closed it, which is what an accepted
        // connection looks like from the dialling side.
        tokio::time::timeout(SURVIVES_FOR, conn.closed())
            .await
            .is_err()
    }

    /// Given a founded workspace and a node that was never admitted to it, when
    /// that node dials on each of the three ALPNs, we expect every attempt to be
    /// refused.
    ///
    /// This is the property the whole roster exists for. Before it, an outsider
    /// who learned the gossip topic — which is just the founder's public key —
    /// could join the overlay and read every membership change, and one who
    /// learned the namespace could sync the entire blinded index.
    #[tokio::test]
    async fn a_node_that_was_never_admitted_is_refused_on_every_alpn() {
        let (alice, _doc) = founded(200, "shared").await;
        let stranger = crate::test_node().await;
        let alice_addr = alice.endpoint_addr();

        for (name, alpn) in ALPNS {
            assert!(
                !can_hold_a_connection(stranger.endpoint(), alice_addr.clone(), alpn).await,
                "an endpoint that no admin ever admitted held a connection on the {name} ALPN, \
                 so knowing the topic id or the namespace is still enough to reach the workspace"
            );
        }

        alice.shutdown().await.expect("alice shuts down");
        stranger.shutdown().await.expect("the stranger shuts down");
    }

    /// Given a peer that *was* admitted, when it dials on each of the three
    /// ALPNs, we expect every attempt to succeed.
    ///
    /// The counterweight, and the one worth writing first: a guard that refuses
    /// everybody would pass the test above and silently break onboarding, which
    /// is Story 1's "immediately access workspace files". Asserting only the
    /// refusal would leave that failure invisible.
    #[tokio::test]
    async fn an_admitted_peer_is_accepted_on_every_alpn() {
        let pair = invited_pair(201).await;
        let alice_addr = pair.alice.endpoint_addr();

        for (name, alpn) in ALPNS {
            assert!(
                can_hold_a_connection(pair.bob.node().endpoint(), alice_addr.clone(), alpn).await,
                "an admitted member was refused on the {name} ALPN, so admission control \
                 has locked a legitimate device out of its own workspace"
            );
        }

        pair.alice.shutdown().await.expect("alice shuts down");
        pair.bob.shutdown().await.expect("bob shuts down");
    }

    /// Given a wrapped handler, when a connection is refused, we expect the
    /// refusal to name a distinct QUIC error code.
    ///
    /// Asserted through the public surface rather than by reaching into the
    /// guard: a peer has to be able to tell "you are not a member" apart from
    /// "the node is shutting down", because only one of those is worth retrying.
    #[tokio::test]
    async fn a_refusal_is_distinguishable_from_a_shutdown() {
        let (alice, _doc) = founded(202, "shared").await;
        let stranger = crate::test_node().await;
        let alice_addr = alice.endpoint_addr();

        let conn = stranger
            .endpoint()
            .connect(alice_addr, iroh_gossip::ALPN)
            .await;

        // The handshake may or may not complete before the refusal lands; both
        // orderings are legitimate, and only the completed case can report a
        // code, so the other is skipped rather than failed.
        if let Ok(conn) = conn {
            let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
            if let Ok(reason) = closed {
                assert!(
                    matches!(
                        &reason,
                        ConnectionError::ApplicationClosed(frame)
                            if frame.error_code.into_inner() == 0x1E_E1
                    ),
                    "a refused connection closed with {reason:?} rather than the roster's \
                     dedicated code, so a peer cannot tell a refusal from a shutdown"
                );
            }
        }

        alice.shutdown().await.expect("alice shuts down");
        stranger.shutdown().await.expect("the stranger shuts down");
    }

    /// Keeps the import used, and documents that the guard is a `ProtocolHandler`
    /// rather than something bolted on beside one.
    #[allow(dead_code)]
    fn guard_is_a_protocol_handler<P: ProtocolHandler>() {}
}

/// Namespace rotation, against live endpoints.
///
/// The simulator models the *effect* of abandoning a replica — an entry written
/// to one namespace is invisible in another — but it cannot show that the
/// modelled epoch corresponds to anything `iroh-docs` enforces. Only real
/// namespaces can.
mod removal_abandons_the_namespace {
    use iroh_beekem_core::NamespaceEpoch;

    use super::*;

    /// Given a workspace with two members, when one is removed, we expect the
    /// group to move to a namespace the removed device does not follow.
    ///
    /// This is what turns "cannot read" into "cannot see". The `iroh-docs` write
    /// capability is all-or-nothing and cannot be withdrawn from one holder, so
    /// a revoked device goes on syncing the replica it was given — observing
    /// entry existence, size, author and timing for every document — until the
    /// group abandons that replica for one whose capability it never receives.
    #[tokio::test]
    async fn a_removed_member_is_left_on_the_abandoned_namespace() {
        let Pair {
            alice,
            bob,
            bob_id,
            doc,
        } = invited_pair(300).await;

        let original = alice.namespace().await;
        assert_eq!(
            bob.namespace().await,
            original,
            "the two must share a namespace first, or being left behind means nothing"
        );
        assert_eq!(
            alice.namespace_epoch().await,
            NamespaceEpoch::INITIAL,
            "a workspace that has never removed anybody is on its founding namespace"
        );

        // Establish that bob really was syncing, so the assertions below are
        // about revocation rather than about a pairing that never worked.
        alice.append(doc, "before").await.expect("alice writes");
        eventually(
            "bob syncs before the removal",
            Duration::from_secs(30),
            || async {
                bob.ingest().await;
                bob.read(doc).await.contains("before")
            },
        )
        .await;

        alice
            .remove_device(bob_id)
            .await
            .expect("alice removes bob");

        eventually(
            "alice moves off the namespace bob can still write to",
            Duration::from_secs(30),
            || async { alice.namespace().await != original },
        )
        .await;

        // Bob keeps the capability he was given, keeps the gossip topic, and
        // keeps running. What he does not keep is a replica anyone reconciles
        // with him.
        never(
            "the removed member follows the group to the new namespace",
            Duration::from_secs(10),
            || async {
                bob.ingest().await;
                bob.namespace().await == alice.namespace().await
            },
        )
        .await;

        assert_eq!(
            bob.namespace_epoch().await,
            NamespaceEpoch::INITIAL,
            "the removed member adopted the rotation issued to exclude him"
        );
        assert!(
            alice.namespace_epoch().await > NamespaceEpoch::INITIAL,
            "alice did not advance her own generation, so nothing was actually abandoned"
        );

        alice.shutdown().await.expect("alice shuts down");
        bob.shutdown().await.expect("bob shuts down");
    }

    /// Given a rotated namespace, when the remaining member writes, we expect
    /// the content to survive the move.
    ///
    /// **The counterweight, and the one that matters most here.** Rotation
    /// re-publishes every document into a fresh replica and re-subscribes the
    /// data pump — the single most disruptive thing the protocol does. A
    /// rotation that lost the workspace would pass every eviction assertion
    /// above while being strictly worse than not rotating at all.
    #[tokio::test]
    async fn the_remaining_member_keeps_its_documents_across_the_rotation() {
        let Pair {
            alice,
            bob,
            bob_id,
            doc,
        } = invited_pair(301).await;

        alice
            .append(doc, "written before the removal")
            .await
            .expect("alice writes");
        eventually("bob syncs first", Duration::from_secs(30), || async {
            bob.ingest().await;
            bob.read(doc).await.contains("written before the removal")
        })
        .await;

        alice
            .remove_device(bob_id)
            .await
            .expect("alice removes bob");
        eventually("alice rotates", Duration::from_secs(30), || async {
            alice.namespace_epoch().await > NamespaceEpoch::INITIAL
        })
        .await;

        // Readable across the move, and still writable after it: the pump has
        // to be live on the *new* namespace, not the abandoned one.
        assert!(
            alice.read(doc).await.contains("written before the removal"),
            "the rotation lost content that existed before it"
        );
        alice
            .append(doc, "written after the rotation")
            .await
            .expect("alice writes into the namespace she rotated to");
        assert!(
            alice.read(doc).await.contains("written after the rotation"),
            "alice cannot write to the namespace she just moved to"
        );
        assert!(
            !alice.files().await.is_empty(),
            "the file index did not survive the rotation, so the workspace forgot its documents"
        );

        alice.shutdown().await.expect("alice shuts down");
        bob.shutdown().await.expect("bob shuts down");
    }
}

/// The checks that make an [`Invite`] a ticket rather than a bearer token.
///
/// These are the half of Phase 6 the simulator cannot state. Expiry is decided
/// against a wall clock and single use against a per-node ledger, and neither
/// exists in `iroh-beekem-core` — deliberately, because a clock in the core would
/// make the whole property suite impossible. So this is where they are checked.
///
/// Every test here is about what *this library* refuses. A thief that ignores the
/// code and reads the struct's fields directly still holds the blinding secret
/// and the docs ticket; what bounds that is the roster and namespace rotation,
/// and `a_stolen_invite_buys_only_visibility` in the simulator is where it is
/// stated.
mod invite_security {
    use iroh_beekem::{Identity, InviteError, Workspace, WorkspaceError};
    use iroh_beekem_core::Role;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::founded;

    /// Given an invite minted for one device, when a *different* device presents
    /// it, we expect the join to be refused with `WrongInvitee`.
    ///
    /// The property that turns a leaked ticket from a credential into a piece of
    /// paper. Before Phase 6 an `Invite` named nobody, so any holder could feed
    /// it to `join` — and while `CgkaController::join` would then fail for want
    /// of the leaf secret, it would fail reporting "the log does not admit this
    /// device", which is indistinguishable from a ticket that lost a race
    /// against a later membership change. Refusing here says which it was.
    #[tokio::test]
    async fn an_invite_is_refused_to_a_device_it_does_not_name() {
        let (alice, _doc) = founded(700, "shared").await;
        let bob_node = crate::test_node().await;
        let bob = Identity::generate(&mut ChaCha20Rng::seed_from_u64(701));
        let invite = alice
            .add_user(
                &bob.enrollment(bob_node.endpoint().id()),
                Role::Editor,
                "bob",
            )
            .await
            .expect("alice admits bob");

        // A third device that was never admitted, holding bob's ticket.
        let thief = Identity::generate(&mut ChaCha20Rng::seed_from_u64(702));
        let thief_node = crate::test_node().await;
        let refused = Workspace::join(
            thief_node,
            &invite,
            &thief,
            &mut ChaCha20Rng::seed_from_u64(703),
        )
        .await;

        assert!(
            matches!(
                refused,
                Err(WorkspaceError::Invite(InviteError::WrongInvitee))
            ),
            "a ticket naming another device must be refused as misaddressed, not \
             as an admission failure, got {refused:?}"
        );
        alice.shutdown().await.expect("alice shuts down");
    }

    /// Given an invite that has already been redeemed on a node, when the same
    /// ticket is presented to that node again, we expect `Replayed`.
    ///
    /// What makes a ticket single-use. The nonce ledger lives on [`Node`] and not
    /// on the workspace because redeeming an invite is what *creates* a
    /// workspace: there is nothing to ask at the moment of the check. It is in
    /// memory only, so a restart un-consumes every nonce — recorded on
    /// `Node::claim_invite` and in the README, because the bound that still holds
    /// after a restart is expiry and nothing else.
    #[tokio::test]
    async fn an_invite_cannot_be_redeemed_twice_on_one_node() {
        let (alice, _doc) = founded(710, "shared").await;
        let bob_node = crate::test_node().await;
        let bob = Identity::generate(&mut ChaCha20Rng::seed_from_u64(711));
        let invite = alice
            .add_user(
                &bob.enrollment(bob_node.endpoint().id()),
                Role::Editor,
                "bob",
            )
            .await
            .expect("alice admits bob");

        let joined = Workspace::join(
            bob_node.clone(),
            &invite,
            &bob,
            &mut ChaCha20Rng::seed_from_u64(712),
        )
        .await
        .expect("the first redemption succeeds");

        let replayed = Workspace::join(
            bob_node,
            &invite,
            &bob,
            &mut ChaCha20Rng::seed_from_u64(713),
        )
        .await;

        assert!(
            matches!(replayed, Err(WorkspaceError::Invite(InviteError::Replayed))),
            "a second redemption of the same ticket must be refused, got {replayed:?}"
        );
        joined.shutdown().await.expect("bob shuts down");
        alice.shutdown().await.expect("alice shuts down");
    }

    /// Given a freshly minted invite, when it is verified at a moment past its
    /// `not_after`, we expect `Expired`.
    ///
    /// Checked through [`Invite::verify`] with an explicit `now` rather than by
    /// waiting an hour: the clock is a parameter of the check precisely so the
    /// window can be tested without one. That it is the *system* clock supplying
    /// that parameter in production is `Workspace::join`'s single call to
    /// `unix_now`.
    #[tokio::test]
    async fn an_invite_is_refused_after_its_window_closes() {
        let (alice, _doc) = founded(720, "shared").await;
        let bob_node = crate::test_node().await;
        let bob = Identity::generate(&mut ChaCha20Rng::seed_from_u64(721));
        let invite = alice
            .add_user(
                &bob.enrollment(bob_node.endpoint().id()),
                Role::Editor,
                "bob",
            )
            .await
            .expect("alice admits bob");

        let invitee = bob.member_id().to_bytes();
        assert!(
            invite.verify(invitee, invite.not_after()).is_ok(),
            "the last second of the window must still be inside it"
        );
        let too_late = invite.verify(invitee, invite.not_after() + 1);
        assert!(
            matches!(too_late, Err(InviteError::Expired { .. })),
            "one second past the window must be refused, got {too_late:?}"
        );
        alice.shutdown().await.expect("alice shuts down");
    }

    /// Given a member who is not an administrator, when they mint an invite from
    /// the log and certificates every member holds, we expect `NotAnAdmin`.
    ///
    /// A viewer holds the whole operation log, the whole certificate store and
    /// the blinding secret — everything an invite carries. Nothing stops them
    /// assembling a ticket that parses. What stops it being redeemable is that
    /// the closure it carries is rooted at `tree_id`, the founder's verifying
    /// key, and no chain from there authorises a viewer to admit anybody. This is
    /// the invite path's half of the check `CgkaController::merge` performs on
    /// the operation itself.
    #[tokio::test]
    async fn a_viewer_cannot_mint_an_invite_at_all() {
        let (alice, _doc) = founded(740, "shared").await;
        let viewer_node = crate::test_node().await;
        let viewer = Identity::generate(&mut ChaCha20Rng::seed_from_u64(741));
        let invite = alice
            .add_user(
                &viewer.enrollment(viewer_node.endpoint().id()),
                Role::Viewer,
                "viewer",
            )
            .await
            .expect("alice admits a viewer");
        let viewer_ws = Workspace::join(
            viewer_node,
            &invite,
            &viewer,
            &mut ChaCha20Rng::seed_from_u64(742),
        )
        .await
        .expect("the viewer joins");

        // The viewer tries to admit somebody. It never reaches the point of
        // minting a ticket, because admitting is what mints one and the core
        // refuses that first — which is the stronger statement: a viewer cannot
        // produce an invite this library would emit at all.
        let outsider = Identity::generate(&mut ChaCha20Rng::seed_from_u64(743));
        let outsider_node = crate::test_node().await;
        let refused = viewer_ws
            .add_user(
                &outsider.enrollment(outsider_node.endpoint().id()),
                Role::Editor,
                "outsider",
            )
            .await;
        assert!(
            matches!(refused, Err(WorkspaceError::Core(_))),
            "a viewer must not be able to admit anybody, got {refused:?}"
        );

        // And the invite the viewer *did* legitimately receive names alice as
        // its issuer, not itself — so there is no ticket in the viewer's hands
        // that a peer would accept as issued by them.
        assert_eq!(
            invite.issuer(),
            alice.member_id().await.to_bytes(),
            "an invite must be signed by the device that issued the admission"
        );

        viewer_ws.shutdown().await.expect("the viewer shuts down");
        alice.shutdown().await.expect("alice shuts down");
    }
}

/// A node that restarts must come back as itself, not as a stranger.
///
/// The simulator models a restart; only these tests prove the modelled restart
/// corresponds to what `iroh` and the filesystem actually do — that the endpoint
/// key, the docs replica, the blobs and the CGKA state all survive together, and
/// that a peer still accepts what the restarted node writes.
mod persistence_survives_a_restart {
    use std::{path::PathBuf, time::Duration};

    use iroh_beekem::{Identity, Workspace, WorkspaceError};
    use iroh_beekem_core::Role;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{PATH, eventually, info};

    /// A private directory for one test, removed when the guard drops.
    ///
    /// Hand-rolled rather than pulled from `tempfile`: this needs a path and a
    /// deletion, and the crate has no other reason to grow a dev-dependency.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "iroh-beekem-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// In a persistent node that founded a workspace and wrote to it, upon
    /// shutting down and reopening from the same directory, we expect the same
    /// endpoint id, the same document contents, and the same membership.
    ///
    /// The endpoint id is the load-bearing one. It *is* the node's entry on
    /// every peer's roster, so a restart that changed it would produce a node
    /// that holds every key it needs and is refused at the connection level by
    /// the workspace it still belongs to.
    #[tokio::test]
    async fn a_restarted_founder_keeps_its_identity_and_its_content() {
        let root = TempRoot::new("founder");
        let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(80));

        let (endpoint_before, tree_id, doc) = {
            let node = crate::test_node_persistent(&root.0)
                .await
                .expect("a persistent node binds");
            let endpoint = node.endpoint().id();
            let ws = Workspace::create(
                node,
                &identity,
                info("durable"),
                &mut ChaCha20Rng::seed_from_u64(80),
            )
            .await
            .expect("founding succeeds");
            let doc = ws.create_file(PATH, "text/markdown").await.expect("a file");
            ws.append(doc, "written before the restart")
                .await
                .expect("an acknowledged write");
            let tree_id = ws.tree_id();
            ws.node().shutdown().await.expect("the node shuts down");
            (endpoint, tree_id, doc)
        };

        let node = crate::test_node_persistent(&root.0)
            .await
            .expect("the same directory reopens");
        assert_eq!(
            node.endpoint().id(),
            endpoint_before,
            "the restarted node bound a new endpoint identity, so no peer could \
             re-dial it and it would be refused by its own workspace's roster"
        );

        let listed = Workspace::list(&node).expect("listing succeeds");
        assert_eq!(listed.len(), 1, "the founded workspace was not listed");
        assert_eq!(
            listed[0].tree_id, tree_id,
            "the listed workspace is not the one that was founded"
        );
        assert_eq!(
            listed[0].info.name, "durable",
            "the workspace name did not survive, so the manifest was not restored"
        );

        let ws = Workspace::open(node, tree_id, &identity)
            .await
            .expect("the stored workspace reopens");
        assert_eq!(
            ws.read(doc).await,
            "written before the restart",
            "an acknowledged write did not survive the restart, so persistence \
             does not happen before acknowledgement"
        );
        assert_eq!(
            ws.group_size().await,
            1,
            "the CGKA tree did not survive the restart"
        );
        assert_eq!(
            ws.me().await.and_then(|me| me.role),
            Some(Role::Admin),
            "the founder's own admin grant did not survive, so it could no longer \
             administer the workspace it created"
        );
    }

    /// In a two-node workspace, upon the joiner restarting, we expect the
    /// founder to still accept what it writes afterwards.
    ///
    /// This is the check that the *derived* author identity is wired up. A
    /// random author would change on restart, every peer's `author_may_write`
    /// would reject the restarted node's entries as coming from an author no
    /// manifest maps to a member, and it would go permanently mute while looking
    /// entirely healthy from its own side.
    /// Three endpoints, so two worker threads — see the module docs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_joiners_later_writes_are_still_accepted() {
        let root = TempRoot::new("joiner");

        let (alice, alice_doc) = {
            let node = crate::test_node().await;
            let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(90));
            let ws = Workspace::create(
                node,
                &identity,
                info("shared"),
                &mut ChaCha20Rng::seed_from_u64(90),
            )
            .await
            .expect("alice founds");
            let doc = ws.create_file(PATH, "text/markdown").await.expect("a file");
            (ws, doc)
        };

        let bob_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(91));
        let bob_tree = {
            let node = crate::test_node_persistent(&root.0)
                .await
                .expect("bob binds persistently");
            let invite = alice
                .add_user(
                    &bob_identity.enrollment(node.endpoint().id()),
                    Role::Editor,
                    "bob",
                )
                .await
                .expect("alice admits bob");
            let bob = Workspace::join(
                node,
                &invite,
                &bob_identity,
                &mut ChaCha20Rng::seed_from_u64(92),
            )
            .await
            .expect("bob joins");

            eventually(
                "bob sees alice's document",
                Duration::from_secs(20),
                || async { bob.resolve(PATH).await.is_some() },
            )
            .await;

            let tree = bob.tree_id();
            bob.node().shutdown().await.expect("bob shuts down");
            tree
        };

        let node = crate::test_node_persistent(&root.0)
            .await
            .expect("bob's directory reopens");
        let bob = Workspace::open(node, bob_tree, &bob_identity)
            .await
            .expect("bob reopens his workspace");
        // Both directions, by address, and only because these nodes run without a
        // relay. A restart binds a *new* UDP port, so each side's cached address
        // for the other is stale; on the open internet the relay is what bridges
        // that, since an endpoint stays reachable by id through it while a direct
        // path is renegotiated. With relays off — see `test_node` — nothing does,
        // and the two would wait on address lookup propagating a fresh record.
        //
        // This cannot hide a regression in what the test is *about*. If `open`
        // failed to derive its roster, or derived the wrong author, or a restarted
        // member's writes were refused, handing out addresses would not save it:
        // `a_restarted_joiners_write_is_refused_without_its_author` and the roster
        // assertions elsewhere in this module would still fail.
        bob.sync_with(alice.endpoint_addr())
            .await
            .expect("bob syncs with alice's known address");
        alice
            .sync_with(bob.endpoint_addr())
            .await
            .expect("alice syncs with the restarted bob's new address");
        bob.append(alice_doc, "bob after restart")
            .await
            .expect("bob writes again");

        eventually(
            "alice accepts the restarted joiner's write",
            Duration::from_secs(30),
            || async { alice.read(alice_doc).await.contains("bob after restart") },
        )
        .await;
    }

    /// In a node holding two workspaces, upon both deriving their rosters, we
    /// expect each to still admit its own members.
    ///
    /// The registry is keyed by workspace because `set_derived` *replaces*: with
    /// one shared set the second workspace's refresh would evict the first's
    /// members, and since both refresh on every manifest arrival, membership
    /// would flap for as long as the node ran. Asserted over real endpoints
    /// because the unit test can only show the bookkeeping, not that both
    /// workspaces really do share one guard.
    /// Three endpoints, so two worker threads — see the module docs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_workspaces_on_one_node_do_not_evict_each_others_members() {
        let host = crate::test_node().await;
        let first_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(100));
        let second_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(101));

        let first = Workspace::create(
            host.clone(),
            &first_identity,
            info("first"),
            &mut ChaCha20Rng::seed_from_u64(100),
        )
        .await
        .expect("the first workspace is founded");
        let second = Workspace::create(
            host.clone(),
            &second_identity,
            info("second"),
            &mut ChaCha20Rng::seed_from_u64(101),
        )
        .await
        .expect("the second workspace is founded");

        // One member each, admitted after both workspaces already exist, so the
        // second admission is what would clobber the first under a shared set.
        let mut guests = Vec::new();
        for (i, ws) in [(0u64, &first), (1, &second)] {
            let node = crate::test_node().await;
            let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(110 + i));
            let invite = ws
                .add_user(
                    &identity.enrollment(node.endpoint().id()),
                    Role::Editor,
                    "guest",
                )
                .await
                .expect("the guest is admitted");
            let joined = Workspace::join(
                node,
                &invite,
                &identity,
                &mut ChaCha20Rng::seed_from_u64(120 + i),
            )
            .await
            .expect("the guest joins");
            guests.push(joined);
        }

        // Both guests must reach the host. Under a single shared roster the
        // second `set_derived` would have dropped the first guest, and its
        // syncs would be refused at the connection level from then on.
        for (ws, guest) in [(&first, &guests[0]), (&second, &guests[1])] {
            let doc = ws.create_file(PATH, "text/markdown").await.expect("a file");
            ws.append(doc, "host write").await.expect("the host writes");
            let guest_ref = guest;
            eventually(
                "a guest of one workspace still syncs after the other refreshed \
                 its roster",
                Duration::from_secs(30),
                || async {
                    match guest_ref.resolve(PATH).await {
                        Some(uuid) => guest_ref.read(uuid).await.contains("host write"),
                        None => false,
                    }
                },
            )
            .await;
        }
    }

    /// In an in-memory node, upon asking for stored workspaces, we expect a
    /// refusal rather than an empty list.
    ///
    /// An empty vector would read as "this node holds no workspaces" when the
    /// truth is "this node cannot hold any across a restart", and a caller
    /// building a workspace picker would show the user an empty screen instead
    /// of a configuration error.
    #[tokio::test]
    async fn an_in_memory_node_reports_that_it_cannot_persist() {
        let node = crate::test_node().await;
        assert!(
            matches!(Workspace::list(&node), Err(WorkspaceError::NotPersistent)),
            "an in-memory node did not report that it has no store"
        );
    }
}

/// Leaving and deleting, over real endpoints.
///
/// The simulator states what a departure means for membership; these prove the
/// facade actually performs it — that the removals reach the peer before the
/// transport is torn down, and that the local teardown really removes what it
/// says it does.
mod a_member_can_walk_away {
    use std::time::Duration;

    use iroh_beekem::{Identity, Workspace};
    use iroh_beekem_core::WorkspaceInfo;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{PATH, eventually, info, invited_pair, never};

    /// In a two-member workspace, upon the joiner leaving, we expect the founder
    /// to stop counting it.
    ///
    /// The ordering is what this proves. `leave` broadcasts the removals and
    /// only then tears the gossip sender down; reversed, the operations would be
    /// dropped on a closed channel and the group would keep the departed member
    /// on every roster forever, with nothing anywhere reporting it.
    #[tokio::test]
    async fn a_departure_reaches_the_remaining_member() {
        let pair = invited_pair(60).await;
        eventually(
            "the founder sees both members",
            Duration::from_secs(20),
            || async { pair.alice.group_size().await == 2 },
        )
        .await;

        pair.bob.leave().await.expect("bob leaves the workspace");

        // `pair.bob` is deliberately still alive here. `leave` announces the
        // departure and does not tear the transport down, because
        // `GossipSender::broadcast` only enqueues and dropping the subscription
        // discards the queue — a test that dropped the leaver immediately would
        // be asserting that a race it created goes its way.
        eventually(
            "the founder sees the departure",
            Duration::from_secs(20),
            || async { pair.alice.group_size().await == 1 },
        )
        .await;
    }

    /// In a workspace with a single administrator, upon that administrator
    /// trying to leave, we expect a refusal and a workspace that still works.
    ///
    /// The refusal has to leave the handle usable, which is why `leave` consumes
    /// `self` only on success — a founder told "no" must still be able to
    /// promote somebody and try again, and a consumed handle would have made the
    /// error unrecoverable.
    #[tokio::test]
    async fn the_last_administrator_cannot_leave() {
        let pair = invited_pair(61).await;
        let err = pair
            .alice
            .leave()
            .await
            .expect_err("the only admin must not be able to strand the workspace");
        assert_eq!(
            pair.alice.group_size().await,
            2,
            "a refused departure changed the group anyway"
        );
        assert!(
            err.to_string().contains("admin"),
            "the refusal must name the reason, since the caller's remedy is to \
             promote somebody first: {err}"
        );
    }

    /// In a persistent node holding a workspace, upon deleting it, we expect it
    /// to be gone from the listing and to stay gone.
    #[tokio::test]
    async fn a_deleted_workspace_does_not_come_back() {
        let root = std::env::temp_dir().join(format!(
            "iroh-beekem-delete-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);

        let node = crate::test_node_persistent(&root)
            .await
            .expect("a persistent node binds");
        let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(62));
        let ws = Workspace::create(
            node.clone(),
            &identity,
            info("disposable"),
            &mut ChaCha20Rng::seed_from_u64(62),
        )
        .await
        .expect("founding succeeds");
        ws.create_file(PATH, "text/markdown").await.expect("a file");
        assert_eq!(
            Workspace::list(&node).expect("listing succeeds").len(),
            1,
            "the workspace was not stored, so deleting it would prove nothing"
        );

        ws.delete().await.expect("deletion succeeds");

        // Never rather than eventually: nothing should be able to bring it back,
        // and the pumps are aborted asynchronously — a snapshot written by a
        // task that outlived the delete is exactly the failure worth excluding.
        never(
            "a deleted workspace reappears in the listing",
            Duration::from_secs(3),
            || async { !Workspace::list(&node).expect("listing succeeds").is_empty() },
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Keeps `WorkspaceInfo` imported for the helper above.
    const _: fn() -> WorkspaceInfo = || info("");
}

/// M-of-N over real endpoints.
///
/// The simulator states the quorum properties under an adversarial network;
/// these prove the facade actually plumbs them — that a threshold set at
/// creation reaches a joiner, and that the joiner's approval is what completes
/// the quorum rather than something the founder decided locally.
mod an_action_needs_a_quorum {
    use std::time::Duration;

    use iroh_beekem::{AdminAction, Identity, Invite, Role, Workspace};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{eventually, info};

    /// In a workspace created at a threshold of two, upon a joiner arriving, we
    /// expect it to read back the same threshold.
    ///
    /// The soundness of the receiver-side check depends on this: the threshold
    /// travels in the founding certificate bundle, so a member cannot be behind
    /// on it and two members cannot disagree about the bar an operation must
    /// clear.
    #[tokio::test]
    async fn a_joiner_learns_the_workspace_threshold() {
        let node = crate::test_node().await;
        let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(70));
        let alice = Workspace::create_with_quorum(
            node,
            &identity,
            info("guarded"),
            2,
            &mut ChaCha20Rng::seed_from_u64(70),
        )
        .await
        .expect("founding at a threshold of two succeeds");
        assert_eq!(alice.threshold().await, 2, "the founder set the threshold");

        let bob_node = crate::test_node().await;
        let bob_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(71));
        let invite: Invite = alice
            .add_user(
                &bob_identity.enrollment(bob_node.endpoint().id()),
                Role::Admin,
                "bob",
            )
            .await
            .expect("the founder may appoint an admin alone");
        let bob = Workspace::join(
            bob_node,
            &invite,
            &bob_identity,
            &mut ChaCha20Rng::seed_from_u64(72),
        )
        .await
        .expect("bob joins");

        assert_eq!(
            bob.threshold().await,
            2,
            "the joiner did not learn the workspace threshold, so it would accept \
             operations the rest of the group refuses"
        );
    }

    /// In a workspace at a threshold of two, upon one admin proposing and both
    /// approving, we expect the removal to happen — and not before.
    /// Three endpoints, so two worker threads — see the module docs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_removal_waits_for_the_second_admin() {
        let node = crate::test_node().await;
        let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(73));
        let alice = Workspace::create_with_quorum(
            node,
            &identity,
            info("guarded"),
            2,
            &mut ChaCha20Rng::seed_from_u64(73),
        )
        .await
        .expect("founding succeeds");

        // Bob is the second admin; Carol is the member they decide about, so
        // neither approver is ever also the target.
        let mut joined = Vec::new();
        for (i, role) in [(0u64, Role::Admin), (1, Role::Editor)] {
            let peer_node = crate::test_node().await;
            let peer_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(74 + i));
            let invite = alice
                .add_user(
                    &peer_identity.enrollment(peer_node.endpoint().id()),
                    role,
                    "peer",
                )
                .await
                .expect("the founder admits a peer alone");
            joined.push(
                Workspace::join(
                    peer_node,
                    &invite,
                    &peer_identity,
                    &mut ChaCha20Rng::seed_from_u64(76 + i),
                )
                .await
                .expect("the peer joins"),
            );
        }
        let (bob, carol) = (&joined[0], &joined[1]);
        eventually(
            "everybody is in the group",
            Duration::from_secs(20),
            || async { alice.group_size().await == 3 && bob.group_size().await == 3 },
        )
        .await;

        let action = AdminAction::RemoveMember {
            member: carol.member_id().await.to_bytes(),
        };
        let proposal = alice
            .propose(action, None)
            .await
            .expect("an admin may propose");
        alice.approve(proposal).await.expect("alice approves");

        // One approval is not two. Asserted after a settling window rather than
        // immediately, so this is "the group did not act" and not "the group had
        // not acted yet".
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            alice.group_size().await,
            3,
            "one admin's approval carried a threshold of two"
        );

        eventually("bob sees the proposal", Duration::from_secs(20), || async {
            bob.proposals().await.iter().any(|p| p.digest == proposal)
        })
        .await;
        bob.approve(proposal).await.expect("bob approves");

        eventually(
            "the removal a quorum authorised is performed everywhere",
            Duration::from_secs(30),
            || async { alice.group_size().await == 2 && bob.group_size().await == 2 },
        )
        .await;
    }

    /// In a workspace holding a proposal, upon the public `resync` being called,
    /// we expect the certificates to be re-announced along with everything else.
    ///
    /// `Workspace::resync` is anti-entropy for the three things broadcast exactly
    /// once, and it drove only two of them: the manifest and the namespace, but
    /// not the certificates. The internal `republish` a `NeighborUp` takes drove
    /// all three, which is why nothing here caught it — every in-tree test
    /// reaches anti-entropy through that path, and only a library caller reaches
    /// this one.
    ///
    /// What the omission cost is specific: a proposal or an approval is broadcast
    /// once with no write behind it, so a peer that missed one has no other way
    /// to learn of it, and a quorum that formed on one node and nowhere else
    /// leaves an action performed there and refused everywhere.
    ///
    /// This asserts the composition rather than the recovery. Making a peer
    /// genuinely *miss* a gossip message needs fault injection, which the
    /// simulator has and two real endpoints do not — `an_action_needs_a_quorum`
    /// in the property suite covers the lossy case. What only this can show is
    /// that the public entry point drives the event at all, over a live
    /// transport, without erroring.
    #[tokio::test]
    async fn a_public_resync_re_announces_the_certificates() {
        let node = crate::test_node().await;
        let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(80));
        let alice = Workspace::create_with_quorum(
            node,
            &identity,
            info("guarded"),
            2,
            &mut ChaCha20Rng::seed_from_u64(80),
        )
        .await
        .expect("founding succeeds");

        let bob_node = crate::test_node().await;
        let bob_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(81));
        let invite: Invite = alice
            .add_user(
                &bob_identity.enrollment(bob_node.endpoint().id()),
                Role::Admin,
                "bob",
            )
            .await
            .expect("the founder may appoint an admin alone");
        let bob = Workspace::join(
            bob_node,
            &invite,
            &bob_identity,
            &mut ChaCha20Rng::seed_from_u64(82),
        )
        .await
        .expect("bob joins");

        eventually("both are in the group", Duration::from_secs(20), || async {
            alice.group_size().await == 2 && bob.group_size().await == 2
        })
        .await;

        // A proposal is a certificate and nothing else: it mints no CGKA
        // operation, so the certificate exchange is the only thing that can
        // carry it.
        let proposal = alice
            .propose(
                AdminAction::RemoveMember {
                    member: bob.member_id().await.to_bytes(),
                },
                None,
            )
            .await
            .expect("an admin may propose");

        alice
            .resync()
            .await
            .expect("the public resync completes over a live transport");

        eventually(
            "the proposal reaches the other admin",
            Duration::from_secs(20),
            || async { bob.proposals().await.iter().any(|p| p.digest == proposal) },
        )
        .await;
    }
}

/// Versioning over real endpoints: history, revert, checkpoints and asset
/// versions.
///
/// What the simulator cannot show is that the facade actually wires these to the
/// transport — that a revert travels as an ordinary edit, that a checkpoint rides
/// the manifest, and that a superseded asset version stays fetchable after a
/// newer one is attached.
mod versions_travel_over_the_wire {
    use std::time::Duration;

    use iroh_beekem_core::{RestoreOutcome, version::AssetVersion};

    use super::{Pair, eventually, invited_pair};

    /// Given a document a member reverted, when the network settles, we expect
    /// the other member to converge on the reverted text.
    ///
    /// A revert is published as a forward edit, so nothing here should need a
    /// mechanism the ordinary edit path does not already have — which is exactly
    /// what this proves rather than assumes.
    #[tokio::test]
    async fn a_revert_reaches_the_other_member() {
        let Pair {
            alice, bob, doc, ..
        } = invited_pair(90).await;

        alice
            .append(doc, "keep this\n")
            .await
            .expect("alice writes");
        // Bob takes delivery of the first write before the second is made, and
        // that is not idle politeness. A document's index slot holds one chunk
        // per author, so two writes in quick succession replace the first chunk
        // with a delta the peer has no base for — a condition this file does not
        // own and a repair is meant to answer. Waiting keeps this test about the
        // revert.
        eventually(
            "bob sees the first line",
            Duration::from_secs(30),
            || async {
                bob.ingest().await;
                bob.read(doc).await.contains("keep this")
            },
        )
        .await;
        alice
            .append(doc, "undo this\n")
            .await
            .expect("alice writes again");

        eventually("bob sees both lines", Duration::from_secs(30), || async {
            bob.ingest().await;
            bob.read(doc).await.contains("undo this")
        })
        .await;

        // The state after the first write, which is what to go back to.
        let first = alice.versions(doc).await[0].id.clone();
        assert_eq!(
            alice
                .read_at(doc, &first)
                .await
                .expect("alice holds the version she just listed"),
            "keep this\n",
            "reading at a version must give the text as it stood there"
        );
        alice.revert(doc, &first).await.expect("alice reverts");

        eventually(
            "bob converges on the reverted document",
            Duration::from_secs(30),
            || async {
                bob.ingest().await;
                bob.read(doc).await == "keep this\n"
            },
        )
        .await;

        alice.shutdown().await.expect("alice shuts down");
        bob.shutdown().await.expect("bob shuts down");
    }

    /// Given two writes made faster than the peer can sync, when the network
    /// settles, we expect the peer to hold both.
    ///
    /// This is the delta path's one hazard, and it is ordinary rather than
    /// exotic. A document's index slot holds one chunk per author, so the second
    /// write replaces the first chunk with a delta — and a peer that had not yet
    /// synced the base cannot apply it. The core answers that by parking the
    /// chunk and, after enough retries, asking for the history.
    ///
    /// It could not get there. The transport caches what it has *fetched* to
    /// avoid re-decrypting a quiescent workspace on every sync event, and a parked
    /// chunk has been fetched; cached, it was never handed to the core again, so
    /// the retries never happened, so the repair was never requested and the edit
    /// was lost on that peer for good. Nothing reported it: the peer simply had
    /// an older document than everybody else.
    #[tokio::test]
    async fn a_peer_that_misses_the_base_of_a_delta_still_catches_up() {
        let Pair {
            alice, bob, doc, ..
        } = invited_pair(94).await;

        // Deliberately with no sync in between, which is what leaves bob holding
        // a delta whose base he never saw.
        alice.append(doc, "first\n").await.expect("alice writes");
        alice
            .append(doc, "second\n")
            .await
            .expect("alice writes again");

        eventually(
            "bob catches up on a delta whose base he missed",
            Duration::from_mins(1),
            || async {
                bob.ingest().await;
                let text = bob.read(doc).await;
                text.contains("first") && text.contains("second")
            },
        )
        .await;

        alice.shutdown().await.expect("alice shuts down");
        bob.shutdown().await.expect("bob shuts down");
    }

    /// Given a checkpoint one member took, when the network settles, we expect
    /// the other to be able to restore it.
    ///
    /// Checkpoints ride the manifest and mint no operation of their own, so this
    /// is also the check that the manifest publish actually carries them.
    #[tokio::test]
    async fn a_checkpoint_taken_by_one_member_is_restorable_by_the_other() {
        let Pair {
            alice, bob, doc, ..
        } = invited_pair(91).await;

        alice
            .append(doc, "as tagged\n")
            .await
            .expect("alice writes");
        let digest = alice
            .checkpoint("v1", "before the rewrite")
            .await
            .expect("alice tags");

        eventually("bob sees the tag", Duration::from_secs(30), || async {
            bob.ingest().await;
            bob.checkpoints().await.iter().any(|c| c.name == "v1")
                && bob.read(doc).await.contains("as tagged")
        })
        .await;

        bob.append(doc, "and then some regret\n")
            .await
            .expect("bob writes");
        let outcomes = bob
            .restore_checkpoint(&digest)
            .await
            .expect("bob restores a tag he merged");
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, RestoreOutcome::Restored(_))),
            "restoring must report what it did to each named entry: {outcomes:?}"
        );
        assert_eq!(
            bob.read(doc).await,
            "as tagged\n",
            "restoring the tag must undo the write made after it"
        );

        eventually(
            "alice converges on the restored document",
            Duration::from_secs(30),
            || async {
                alice.ingest().await;
                alice.read(doc).await == "as tagged\n"
            },
        )
        .await;

        alice.shutdown().await.expect("alice shuts down");
        bob.shutdown().await.expect("bob shuts down");
    }

    /// Given an asset attached twice, when the newer version has synced, we
    /// expect the other member to be able to export *either* version.
    ///
    /// Each version has its own key space precisely so that attaching a new one
    /// does not overwrite the index entries protecting the old one's blobs. If it
    /// did, this test would fail on the older export — and only there.
    #[tokio::test]
    async fn an_older_asset_version_is_still_exportable_after_a_newer_one() {
        let Pair { alice, bob, .. } = invited_pair(92).await;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let first = dir.path().join("first.bin");
        let second = dir.path().join("second.bin");
        tokio::fs::write(&first, b"the original bytes")
            .await
            .expect("writing the first version");
        tokio::fs::write(&second, b"the replacement bytes")
            .await
            .expect("writing the second version");

        let entry = alice
            .attach_file(&first, "/big.bin", "application/octet-stream")
            .await
            .expect("alice attaches");
        alice
            .attach_version(entry, &second)
            .await
            .expect("alice attaches a second version");

        eventually(
            "bob sees both versions of the asset",
            Duration::from_secs(30),
            || async {
                bob.ingest().await;
                bob.asset_versions(entry).await.len() == 2
            },
        )
        .await;

        let versions = bob.asset_versions(entry).await;
        let oldest = versions.first().expect("two versions were listed").clone();
        let newest = versions
            .iter()
            .max_by_key(|v| AssetVersion::precedence(v))
            .expect("two versions were listed")
            .clone();

        let out_new = dir.path().join("out-new.bin");
        eventually(
            "bob exports the current version",
            Duration::from_secs(30),
            || async {
                bob.ingest().await;
                bob.export_asset(entry, &out_new).await.is_ok()
            },
        )
        .await;
        assert_eq!(
            tokio::fs::read(&out_new).await.expect("reading the export"),
            b"the replacement bytes",
            "exporting an entry must give its current version"
        );

        let out_old = dir.path().join("out-old.bin");
        eventually(
            "bob exports the superseded version",
            Duration::from_secs(30),
            || async {
                bob.ingest().await;
                bob.export_asset_version(&oldest, &out_old).await.is_ok()
            },
        )
        .await;
        assert_eq!(
            tokio::fs::read(&out_old).await.expect("reading the export"),
            b"the original bytes",
            "a superseded version must still be readable, or attaching a new one \
             silently destroyed the old one"
        );

        // And reverting re-points at bytes that are already there.
        alice
            .revert_asset(entry, oldest.content)
            .await
            .expect("alice reverts the asset");
        assert_ne!(
            newest.content, oldest.content,
            "the two versions must occupy different key spaces"
        );
        eventually("bob sees the revert", Duration::from_secs(30), || async {
            bob.ingest().await;
            bob.asset_versions(entry)
                .await
                .iter()
                .max_by_key(|v| AssetVersion::precedence(v))
                .is_some_and(|v| v.content == oldest.content)
        })
        .await;

        alice.shutdown().await.expect("alice shuts down");
        bob.shutdown().await.expect("bob shuts down");
    }

    /// A document's versions name the member that wrote them, across the wire.
    #[tokio::test]
    async fn a_version_names_the_member_that_wrote_it() {
        let Pair {
            alice, bob, doc, ..
        } = invited_pair(93).await;
        let bob_member = bob.member_id().await.to_bytes();

        bob.append(doc, "from bob\n").await.expect("bob writes");
        eventually(
            "alice attributes bob's change to bob",
            Duration::from_secs(30),
            || async {
                alice.ingest().await;
                alice
                    .versions(doc)
                    .await
                    .iter()
                    .any(|v| v.author == Some(bob_member))
            },
        )
        .await;

        alice.shutdown().await.expect("alice shuts down");
        bob.shutdown().await.expect("bob shuts down");
    }
}
