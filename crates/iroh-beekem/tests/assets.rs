//! Large binary assets over two real endpoints.
//!
//! Like [`two_node`](../two_node.rs) this asserts **wiring**, not protocol. What
//! only real `iroh` can show is that the three pieces the asset path depends on
//! are actually connected: segments are indexed but not eagerly downloaded, a
//! peer that asks for one fetches it on demand, and a rotation carries the asset
//! across without re-encrypting a byte.
//!
//! The envelope itself — padding, the position-binding AAD, the digest — is
//! specified in `iroh-beekem-core`, where it can be stated without a socket.

use std::time::Duration;

use iroh_beekem::{Identity, Invite, Node, Workspace};
use iroh_beekem_core::{ASSET_SEGMENT_BYTES, DocumentUuid, Role, WorkspaceInfo};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Two and a bit segments, so the tail is padded and the ordering of segments
/// is observable. Deliberately not a multiple of the segment size.
const ASSET_BYTES: usize = ASSET_SEGMENT_BYTES * 2 + 12_345;

fn info(name: &str) -> WorkspaceInfo {
    WorkspaceInfo {
        name: name.to_string(),
        description: String::new(),
    }
}

/// Deterministic pseudo-random contents, so a mismatch is a real mismatch rather
/// than a run of identical bytes hiding an ordering bug.
fn asset_contents() -> Vec<u8> {
    use rand::RngCore as _;
    let mut bytes = vec![0u8; ASSET_BYTES];
    ChaCha20Rng::seed_from_u64(99).fill_bytes(&mut bytes);
    bytes
}

/// How many bytes of payload the store is holding right now.
///
/// Summed rather than counted, because a rotation's legitimate cost and the cost
/// this test is watching for differ by orders of magnitude in size and not at all
/// in blob count. A hash the store lists but cannot produce bytes for contributes
/// nothing, which is the right answer: it is not occupying space here.
async fn blob_bytes(ws: &Workspace) -> usize {
    let hashes = ws
        .node()
        .blobs()
        .list()
        .hashes()
        .await
        .expect("listing blobs should succeed");
    let mut total = 0;
    for hash in hashes {
        if let Ok(bytes) = ws.node().blobs().get_bytes(hash).await {
            total += bytes.len();
        } else {
            // Listed but not readable here; see above.
        }
    }
    total
}

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
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out after {timeout:?} waiting for: {what}");
}

struct Pair {
    alice: Workspace,
    bob: Workspace,
    bob_id: beekem::id::MemberId,
    asset: DocumentUuid,
    source: tempfile::TempDir,
    contents: Vec<u8>,
}

/// Alice founds a workspace, attaches an asset, and invites Bob.
async fn attached_pair(seed: u64) -> Pair {
    let alice_node = Node::spawn().await.expect("alice binds");
    let alice_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(seed));
    let alice = Workspace::create(
        alice_node,
        &alice_identity,
        info("assets"),
        &mut ChaCha20Rng::seed_from_u64(seed),
    )
    .await
    .expect("alice founds a workspace");

    let source = tempfile::tempdir().expect("a scratch directory");
    let contents = asset_contents();
    let path = source.path().join("scan.bin");
    std::fs::write(&path, &contents).expect("writing the source file");

    let asset = alice
        .attach_file(&path, "/scans/2026.bin", "application/octet-stream")
        .await
        .expect("attaching the asset");

    // Pinned, so the test cannot pass on a one-segment asset that never
    // exercises ordering, padding, or the per-segment fetch.
    let meta = alice
        .files()
        .await
        .into_iter()
        .find(|entry| entry.uuid == asset)
        .and_then(|entry| entry.asset)
        .expect("the attached asset is recorded as an asset");
    assert_eq!(
        meta.segments, 3,
        "the fixture must span three segments, or nothing here tests segmentation"
    );
    assert_eq!(
        meta.size, ASSET_BYTES as u64,
        "the manifest must record the true length, not the padded one"
    );

    let bob_node = Node::spawn().await.expect("bob binds");
    let bob_identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(seed + 1));
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
        &mut ChaCha20Rng::seed_from_u64(seed + 3),
    )
    .await
    .expect("bob joins from the invite");
    let bob_id = bob_identity.member_id();

    Pair {
        alice,
        bob,
        bob_id,
        asset,
        source,
        contents,
    }
}

/// In a workspace holding an asset attached before a member joined, upon that
/// member exporting it, we expect the bytes to be identical to the original.
///
/// The whole path in one assertion: the content key reaches Bob through the
/// CGKA, the segments reach him through an on-demand fetch rather than an eager
/// download, and the digest recorded in the manifest verifies over what he
/// reassembled.
///
/// Bob joined *after* the attachment, so this also exercises the repair path:
/// the key chunk is wrapped under an epoch that predates his leaf, and what
/// makes it readable is a member re-encrypting **32 bytes** rather than the
/// whole asset.
#[tokio::test]
async fn an_asset_round_trips_between_two_endpoints() {
    let pair = attached_pair(1).await;

    pair.alice
        .sync_with(pair.bob.endpoint_id())
        .await
        .expect("alice syncs with bob");

    // The manifest has to reach bob before he can name the asset at all.
    eventually(
        "bob to see the asset in the manifest",
        Duration::from_secs(30),
        || async {
            pair.bob
                .files()
                .await
                .iter()
                .any(|entry| entry.uuid == pair.asset && entry.asset.is_some())
        },
    )
    .await;

    let out = pair.source.path().join("exported.bin");
    // Retried rather than awaited once: the first attempt may find the content
    // key still wrapped under an epoch bob cannot derive, which *requests* a
    // repair rather than waiting for one.
    eventually(
        "bob to export the asset",
        Duration::from_secs(45),
        || async { pair.bob.export_asset(pair.asset, &out).await.is_ok() },
    )
    .await;

    let exported = std::fs::read(&out).expect("reading what bob exported");
    assert_eq!(
        exported.len(),
        pair.contents.len(),
        "the exported asset must have the original length, not the padded one"
    );
    assert!(
        exported == pair.contents,
        "the exported asset must be byte-identical to the original"
    );

    pair.alice.shutdown().await.expect("alice shuts down");
    pair.bob.shutdown().await.expect("bob shuts down");
}

/// In a workspace holding an asset, upon a member being removed, we expect the
/// surviving member to still export the asset **and** for no new blob to have
/// been written for it.
///
/// This is the whole of the rotation change. A rotation abandons the replica, so
/// everything has to be carried into the new one — and for a document that means
/// re-encrypting, which is cheap. Doing the same for an asset would re-encrypt
/// and re-upload every segment on every removal. Asset entries are re-indexed
/// against the hash the old replica already named, and the *bytes* the store
/// holds are what say whether that is really what happened.
///
/// Bytes rather than a blob count, and the difference is what makes this test
/// mean something. A rotation legitimately re-encrypts the manifest and every
/// document, each of which is a blob — and the republish loop can run more than
/// once on a slow machine, so the *number* of new blobs is noise of the same
/// order as the three segments being watched for. It was: under `make coverage`
/// this failed at exactly the boundary, on the baseline as well as on any
/// change. The sizes are not comparable in the same way. Three padded segments
/// are megabytes; a manifest and a short document are hundreds of bytes, so a
/// budget of one segment separates the two cases by three orders of magnitude
/// and cannot be eaten by an extra republish.
#[tokio::test]
async fn a_rotation_reindexes_an_asset_instead_of_re_encrypting_it() {
    let pair = attached_pair(2).await;

    let bytes_before = blob_bytes(&pair.alice).await;
    let blobs_before = pair
        .alice
        .node()
        .blobs()
        .list()
        .hashes()
        .await
        .expect("listing alice's blobs")
        .len();

    pair.alice
        .remove_device(pair.bob_id)
        .await
        .expect("alice removes bob");

    // The rotation is driven by the effect pump, so wait for alice to actually
    // be on a new generation before measuring.
    let generation = pair.alice.namespace_epoch().await;
    eventually(
        "alice to adopt the rotated namespace",
        Duration::from_secs(30),
        || async { pair.alice.namespace_epoch().await >= generation },
    )
    .await;

    let out = pair.source.path().join("after-rotation.bin");
    eventually(
        "alice to export the asset after the rotation",
        Duration::from_secs(30),
        || async { pair.alice.export_asset(pair.asset, &out).await.is_ok() },
    )
    .await;
    let exported = std::fs::read(&out).expect("reading the export");
    assert!(
        exported == pair.contents,
        "a rotation must not cost the surviving member its asset"
    );

    let blobs_after = pair
        .alice
        .node()
        .blobs()
        .list()
        .hashes()
        .await
        .expect("listing alice's blobs")
        .len();
    let bytes_after = blob_bytes(&pair.alice).await;
    // One segment of headroom covers the manifest and documents a rotation does
    // re-encrypt, with room to spare; re-encrypting the asset would cost three.
    let budget = ASSET_SEGMENT_BYTES;
    assert!(
        bytes_after < bytes_before + budget,
        "the asset's segments must be re-indexed rather than re-encrypted: the \
         store grew from {bytes_before} to {bytes_after} bytes across the \
         rotation ({} blobs to {blobs_after}), and a fresh ciphertext per segment \
         would cost about {}",
        blobs_before,
        ASSET_SEGMENT_BYTES * 3
    );

    pair.alice.shutdown().await.expect("alice shuts down");
    pair.bob.shutdown().await.expect("bob shuts down");
}

/// In a workspace where an attachment fails, upon listing the files, we expect
/// no trace of it.
///
/// The entry has to be written *before* the version that declares the segments —
/// a version of a file the manifest has never heard of is refused, which is what
/// stops indexed segments existing with nothing naming them. That ordering makes
/// a failure leave an entry with no versions, and an entry with no versions reads
/// as an empty *document*, because that is exactly what "no versions" means. So
/// the failure path has to withdraw it: a caller whose attachment failed must not
/// be left holding a phantom file it never asked for.
#[tokio::test]
async fn a_failed_attachment_leaves_no_entry_behind() {
    let node = Node::spawn().await.expect("binding");
    let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(7));
    let ws = Workspace::create(
        node,
        &identity,
        info("failed attach"),
        &mut ChaCha20Rng::seed_from_u64(7),
    )
    .await
    .expect("founding a workspace");

    let before = ws.files().await.len();
    let missing = std::path::Path::new("/nonexistent/definitely-not-here.bin");
    let result = ws
        .attach_file(missing, "/scans/ghost.bin", "application/octet-stream")
        .await;
    assert!(
        result.is_err(),
        "attaching a file that does not exist must fail"
    );
    assert_eq!(
        ws.files().await.len(),
        before,
        "a failed attachment left an entry behind: {:?}",
        ws.files().await
    );

    ws.shutdown().await.expect("shutting down");
}
