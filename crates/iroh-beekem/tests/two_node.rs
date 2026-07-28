//! Two real `iroh` endpoints, real QUIC, real sync.
//!
//! The protocol logic below is already covered by the deterministic simulator
//! in `iroh-beekem-sim`. What these tests add is proof that the transport
//! wiring is actually connected: ALPNs registered, gossip overlay bootstrapped,
//! docs namespace shared with a write capability, blob payloads fetched.

use std::time::Duration;

use iroh_beekem::{Invite, Node, Workspace};
use iroh_beekem_core::DocumentUuid;
use keyhive_crypto::{
    share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DOC: DocumentUuid = DocumentUuid([9u8; 16]);

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
}

async fn invited_pair(seed: u64) -> Pair {
    let alice_node = Node::spawn().await.expect("alice should bind");
    let bob_node = Node::spawn().await.expect("bob should bind");

    let alice = Workspace::create(alice_node, DOC, &mut ChaCha20Rng::seed_from_u64(seed))
        .await
        .expect("alice founds the workspace");

    // Bob generates a leaf keypair and publishes only its public half; his
    // secret never leaves his device.
    let bob_signer = MemorySigner::generate(&mut ChaCha20Rng::seed_from_u64(seed + 1));
    let bob_secret = ShareSecretKey::generate(&mut ChaCha20Rng::seed_from_u64(seed + 2));
    let bob_id = beekem::id::MemberId::from(bob_signer.verifying_key());

    let invite: Invite = alice
        .invite(bob_id, bob_secret.share_key())
        .await
        .expect("alice invites bob");

    let bob = Workspace::join(
        bob_node,
        &invite,
        bob_signer,
        bob_secret,
        DOC,
        &mut ChaCha20Rng::seed_from_u64(seed + 3),
    )
    .await
    .expect("bob joins from the invite");

    Pair { alice, bob, bob_id }
}

#[tokio::test]
async fn a_founded_workspace_starts_with_one_member() {
    let node = Node::spawn().await.expect("node should bind");
    let ws = Workspace::create(node, DOC, &mut ChaCha20Rng::seed_from_u64(1))
        .await
        .expect("founding a workspace should succeed");

    assert_eq!(
        ws.group_size().await,
        1,
        "a freshly founded workspace should contain only its founder"
    );

    ws.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn local_edits_are_readable_locally() {
    let node = Node::spawn().await.expect("node should bind");
    let ws = Workspace::create(node, DOC, &mut ChaCha20Rng::seed_from_u64(2))
        .await
        .expect("founding a workspace should succeed");

    ws.append("hello").await.expect("appending should succeed");

    assert_eq!(
        ws.text().await,
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
    let Pair { alice, bob, .. } = invited_pair(20).await;

    alice
        .append("from alice")
        .await
        .expect("alice writes after bob joined");

    eventually(
        "bob receives alice's edit",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.text().await.contains("from alice")
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn edits_propagate_from_a_joiner_back_to_the_founder() {
    let Pair { alice, bob, .. } = invited_pair(30).await;

    bob.append("from bob").await.expect("bob writes");

    eventually(
        "alice receives bob's edit",
        Duration::from_secs(30),
        || async {
            alice.ingest().await;
            alice.text().await.contains("from bob")
        },
    )
    .await;

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}

#[tokio::test]
async fn the_manifest_and_its_roles_reach_a_joiner_over_quic() {
    use iroh_beekem_core::{FileEntry, Role};

    let Pair { alice, bob, bob_id } = invited_pair(50).await;

    alice
        .upsert_file(FileEntry {
            uuid: DOC,
            logical_path: "/finance/q3.json".into(),
            mime_type: "application/json".into(),
        })
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
    let Pair { alice, bob, .. } = invited_pair(70).await;

    alice
        .append("before rotation. ")
        .await
        .expect("alice writes");
    eventually(
        "bob reads before the rotation",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.text().await.contains("before rotation")
        },
    )
    .await;

    // Post-compromise security: after this, alice's old leaf secret derives no
    // further group key. The group must keep working across it, which is the
    // part a rotation can silently break.
    bob.rotate().await.expect("bob rotates his leaf key");

    alice
        .append("after rotation.")
        .await
        .expect("alice writes again");
    eventually(
        "bob reads across the rotation",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.text().await.contains("after rotation")
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
    let result = bob.revoke(alice_id).await;

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
    let Pair { alice, bob, bob_id } = invited_pair(40).await;

    // Establish that bob really could read first, so the assertion below is
    // about revocation and not about a workspace that never worked.
    alice.append("before").await.expect("alice writes");
    eventually(
        "bob reads before revocation",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.text().await.contains("before")
        },
    )
    .await;

    alice.revoke(bob_id).await.expect("alice revokes bob");
    alice
        .append("AFTER-REVOCATION")
        .await
        .expect("alice writes after revoking");

    // Bob still sees the whole public control plane and can still fetch every
    // ciphertext — he simply cannot derive the key.
    never(
        "revoked member reads post-revocation content",
        Duration::from_secs(10),
        || async {
            bob.ingest().await;
            bob.text().await.contains("AFTER-REVOCATION")
        },
    )
    .await;

    assert!(
        alice.text().await.contains("AFTER-REVOCATION"),
        "alice should still be able to read her own edit"
    );

    alice.shutdown().await.expect("alice shuts down");
    bob.shutdown().await.expect("bob shuts down");
}
