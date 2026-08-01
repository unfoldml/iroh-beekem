//! Blob collection: proof that superseded payloads are actually reclaimed.
//!
//! This is the counterpart to [`two_node`](../two_node.rs) for the storage side
//! of the data plane. Like that suite it asserts **wiring**, not protocol: the
//! sweep itself is `iroh-blobs`' code and is tested there. What can only be
//! tested here is that this crate hands it the two things it needs — a blob that
//! is not permanently tagged, and a protection callback that reports what the
//! `iroh-docs` index still references.
//!
//! Both were absent before, and each fails silently on its own: with a permanent
//! tag the sweep runs and reclaims nothing; without the callback it would reclaim
//! everything not currently being written.

use std::time::Duration;

use iroh_beekem::{Identity, Node, NodeOptions, Workspace};
use iroh_beekem_core::WorkspaceInfo;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Short enough that a test observes several sweeps, long enough that it is not
/// competing with the writes it is meant to follow.
const SWEEP: Duration = Duration::from_millis(500);

/// The logical path every test here writes to.
const PATH: &str = "/notes.md";

/// A workspace on a node whose blob store sweeps often enough to watch.
async fn founded(seed: u64) -> Workspace {
    let node = Node::spawn_with_options(NodeOptions { gc_interval: SWEEP })
        .await
        .expect("node should bind");
    let identity = Identity::generate(&mut ChaCha20Rng::seed_from_u64(seed));
    Workspace::create(
        node,
        &identity,
        WorkspaceInfo {
            name: "gc".to_string(),
            description: String::new(),
        },
        &mut ChaCha20Rng::seed_from_u64(seed),
    )
    .await
    .expect("founding a workspace should succeed")
}

/// Poll until `check` passes, or fail with `what` as the explanation.
///
/// The sweep runs on a timer inside the store, so there is no completion to
/// await — only an outcome to wait for.
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

/// How many blobs the store is holding right now.
async fn blob_count(ws: &Workspace) -> usize {
    ws.node()
        .blobs()
        .list()
        .hashes()
        .await
        .expect("listing blobs should succeed")
        .len()
}

/// In a workspace that has published anything at all, upon listing the blob
/// store's tags, we expect none — because a permanently tagged blob is one no
/// sweep can ever reclaim.
///
/// This is the whole of the `store_chunk` half of collection, stated separately
/// from the reclamation test below because it fails in a distinctive way: with a
/// permanent tag every other assertion here still holds at t=0 and only the
/// steady-state store size is wrong, which is exactly the kind of regression a
/// timing-sensitive test reports as flakiness.
#[tokio::test]
async fn publishing_creates_no_permanent_tag() {
    let ws = founded(1).await;
    let doc = ws
        .create_file(PATH, "text/markdown")
        .await
        .expect("creating the document");
    ws.append(doc, "hello").await.expect("appending");

    let tags = ws
        .node()
        .blobs()
        .tags()
        .list()
        .await
        .expect("listing tags should succeed");
    let tags: Vec<_> = n0_future::StreamExt::collect::<Vec<_>>(tags).await;
    assert!(
        tags.is_empty(),
        "a published chunk must be protected by the docs entry that names it and by \
         nothing else; {} permanent tag(s) would pin every superseded blob forever",
        tags.len()
    );

    ws.shutdown().await.expect("shutting down");
}

/// In a workspace where one document is rewritten many times, upon letting the
/// sweep run, we expect the blob store to settle at the number of entries the
/// index actually names rather than growing with the number of writes.
///
/// Each write publishes a fresh chunk at the same blinded key, so every previous
/// blob becomes unreferenced the moment `set_hash` replaces the record. Before
/// collection existed the store grew without bound; the whole point of phase 9 is
/// that this number stops depending on `WRITES`.
#[tokio::test]
async fn superseded_blobs_are_reclaimed() {
    const WRITES: usize = 20;

    let ws = founded(2).await;
    let doc = ws
        .create_file(PATH, "text/markdown")
        .await
        .expect("creating the document");
    for i in 0..WRITES {
        ws.append(doc, &format!("line {i}\n"))
            .await
            .expect("appending");
    }

    // Two keys are live: the document and the manifest. The bound is generous
    // rather than exact because a sweep landing between a blob being written and
    // its index entry replacing the old one legitimately sees both.
    let live = 4;
    assert!(
        blob_count(&ws).await > live,
        "the test is only meaningful if the writes actually accumulated blobs first"
    );
    eventually(
        "the blob store to settle at what the index references",
        Duration::from_secs(20),
        || async {
            let count = blob_count(&ws).await;
            count <= live
        },
    )
    .await;

    // The content must survive its own collection: a sweep that reclaimed the
    // live chunk would pass the count assertion above and lose the document.
    let text = ws.read(doc).await;
    assert_eq!(
        text.lines().count(),
        WRITES,
        "every acknowledged write must still be readable after a sweep, got {text:?}"
    );

    ws.shutdown().await.expect("shutting down");
}
