//! Two real `iroh` endpoints, real QUIC, real sync.
//!
//! The protocol logic below is already covered by the deterministic simulator
//! in `iroh-beekem-sim`. What these tests add is proof that the transport
//! wiring is actually connected: ALPNs registered, gossip overlay bootstrapped,
//! docs namespace shared with a write capability, blob payloads fetched.

use std::time::Duration;

use iroh_beekem::{Identity, Invite, Node, Workspace};
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

/// Found a workspace with one document already created, and return both.
async fn founded(seed: u64, name: &str) -> (Workspace, DocumentUuid) {
    let node = Node::spawn().await.expect("node should bind");
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
    let bob_node = Node::spawn().await.expect("bob should bind");

    // Bob generates his device identity and publishes only its public leaf key;
    // the secret half never leaves his device, which is what makes an
    // intercepted invite useless for joining.
    let bob_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(seed + 1));
    let bob_id = bob_identity.member_id();

    let invite: Invite = alice
        .add_user(
            bob_id,
            bob_identity.share_key(),
            bob_node.endpoint().id(),
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
        bob_id,
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
    let viewer_node = Node::spawn().await.expect("the viewer's node should bind");
    let editor_node = Node::spawn().await.expect("the editor's node should bind");
    let viewer = Identity::generate(&mut ChaCha20Rng::seed_from_u64(111));

    let invite = alice
        .add_user(
            viewer.member_id(),
            viewer.share_key(),
            viewer_node.endpoint().id(),
            Role::Viewer,
            "viewer",
        )
        .await
        .expect("alice admits a viewer");
    assert!(
        matches!(invite.doc_ticket.capability, Capability::Read(_)),
        "a viewer must not receive a write capability"
    );

    let editor = Identity::generate(&mut ChaCha20Rng::seed_from_u64(112));
    let invite = alice
        .add_user(
            editor.member_id(),
            editor.share_key(),
            editor_node.endpoint().id(),
            Role::Editor,
            "editor",
        )
        .await
        .expect("alice admits an editor");
    assert!(
        matches!(invite.doc_ticket.capability, Capability::Write(_)),
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
    let laptop_node = Node::spawn().await.expect("laptop should bind");
    let invite = alice
        .add_device(
            laptop_identity.member_id(),
            laptop_identity.share_key(),
            laptop_node.endpoint().id(),
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
        let stranger = Node::spawn()
            .await
            .expect("the stranger's node should bind");
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
        let stranger = Node::spawn()
            .await
            .expect("the stranger's node should bind");
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
