//! Standalone reproduction for beekem 0.3.0.
//!
//! `Cgka::remove` returns `CgkaError::IdentifierNotFound` for a member its own
//! `contains_id` guard has just approved, because the guard runs against the
//! un-replayed tree and the lookup runs against the replayed one.
//!
//! Drop this into a crate with:
//!
//! ```toml
//! [dev-dependencies]
//! beekem = "0.3.0"
//! keyhive_crypto = "*"        # the version beekem re-exports
//! future_form = "*"
//! rand = "0.8.5"
//! rand_chacha = "0.3"
//! ```
//!
//! and run `cargo test -- --nocapture`.

use std::sync::Arc;

use beekem::{
    cgka::Cgka,
    id::{MemberId, TreeId},
    keys::ShareKeyMap,
    operation::CgkaOperation,
};
use future_form::Local;
use keyhive_crypto::{
    share_key::ShareSecretKey,
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// What the *operation log* says about a member, as distinct from what
/// `group_size` says about the tree. The whole point of the reproduction is that
/// these two disagree until something replays the graph.
fn log_says_present(cgka: &Cgka, id: MemberId) -> bool {
    let mut present = false;
    for op in ops_of(cgka) {
        match op.payload {
            CgkaOperation::Add { added_id, .. } if added_id == id => {
                present = true;
            }
            CgkaOperation::Remove { id: removed, .. } if removed == id => {
                present = false;
            }
            _ => {}
        }
    }
    present
}

/// Every operation the graph holds, in causal order.
fn ops_of(cgka: &Cgka) -> Vec<Arc<Signed<CgkaOperation>>> {
    cgka.ops()
        .expect("sortable log")
        .into_iter()
        .flat_map(IntoIterator::into_iter)
        .collect()
}

/// beekem's signing is `async` but a `MemorySigner` never yields, so every
/// future here is already complete on first poll.
fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    use std::task::{Context, Poll, Waker};
    let mut fut = Box::pin(fut);
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("an in-memory signer must not yield"),
    }
}

#[test]
fn remove_reports_identifier_not_found_for_a_member_it_just_approved() {
    let doc = TreeId::from(MemorySigner::generate(&mut rng(0)).verifying_key());

    let alice_signer = MemorySigner::generate(&mut rng(1));
    let bob_signer = MemorySigner::generate(&mut rng(2));
    let carol_signer = MemorySigner::generate(&mut rng(3));
    let dave_signer = MemorySigner::generate(&mut rng(4));

    let alice_id = MemberId::from(alice_signer.verifying_key());
    let bob_id = MemberId::from(bob_signer.verifying_key());
    let carol_id = MemberId::from(carol_signer.verifying_key());
    let dave_id = MemberId::from(dave_signer.verifying_key());

    let alice_sk = ShareSecretKey::generate(&mut rng(10));
    let bob_sk = ShareSecretKey::generate(&mut rng(11));
    let carol_sk = ShareSecretKey::generate(&mut rng(12));
    let dave_sk = ShareSecretKey::generate(&mut rng(13));

    // Alice founds the group and admits the other three.
    let mut alice = now(Cgka::new::<Local, _>(
        doc,
        alice_id,
        alice_sk.share_key(),
        &alice_signer,
    ))
    .expect("founding");
    alice.owner_sks.insert(alice_sk.share_key(), alice_sk);

    for (id, sk) in [
        (bob_id, bob_sk.share_key()),
        (carol_id, carol_sk.share_key()),
        (dave_id, dave_sk.share_key()),
    ] {
        now(alice.add::<Local, _>(id, sk, &alice_signer))
            .expect("adding")
            .expect("each member is new");
    }

    // Bob and Dave reconstruct the same group from Alice's operation log.
    let log = ops_of(&alice);
    let rebuild = |signer: &MemorySigner, sk: ShareSecretKey| {
        let init: Signed<CgkaOperation> = (**log.first().expect("a founding add")).clone();
        let CgkaOperation::Add { added_id, pk, .. } = init.payload else {
            panic!("the log must start with the founding add");
        };
        let mut cgka =
            Cgka::new_from_init_add(doc, added_id, pk, init).expect("rebuilding from the log");
        for op in log.iter().skip(1) {
            cgka.merge_concurrent_operation(Arc::clone(op))
                .expect("replaying the log");
        }
        let mut keys = ShareKeyMap::new();
        keys.insert(sk.share_key(), sk);
        cgka.with_new_owner(MemberId::from(signer.verifying_key()), keys)
            .expect("re-owning")
    };
    let mut bob = rebuild(&bob_signer, bob_sk);
    let mut dave = rebuild(&dave_signer, dave_sk);

    // Two operations minted from the same head, so they are concurrent: Alice
    // removes Carol, Bob rotates his own leaf.
    let removal = now(alice.remove::<Local, _>(carol_id, &alice_signer))
        .expect("alice removes carol")
        .expect("carol was a member");
    let (_, rotation) = now(bob.update::<Local, _, _>(
        ShareSecretKey::generate(&mut rng(20)).share_key(),
        ShareSecretKey::generate(&mut rng(20)),
        &bob_signer,
        &mut rng(21),
    ))
    .expect("bob rotates");

    // Dave merges both. The removal is a structural change arriving
    // concurrently, so it is queued in the operations graph rather than applied
    // to the tree.
    dave.merge_concurrent_operation(Arc::new(rotation))
        .expect("merging the rotation");
    dave.merge_concurrent_operation(Arc::new(removal))
        .expect("merging the removal");

    println!(
        "before: group_size={} log_says_carol_present={}",
        dave.group_size(),
        log_says_present(&dave, carol_id)
    );
    assert_eq!(
        dave.group_size(),
        4,
        "the queued removal has not been applied to the tree yet, so the tree \
         still counts four members"
    );
    assert!(
        !log_says_present(&dave, carol_id),
        "while the operation graph already holds the removal — this is the \
         disagreement the bug rests on"
    );

    // Dave now performs the same removal himself. `contains_id` says Carol is
    // present, the replay inside `remove` takes her out, and the lookup after it
    // fails.
    let outcome = now(dave.remove::<Local, _>(carol_id, &dave_signer));
    println!("remove(carol) -> {outcome:?}");
    assert!(
        matches!(outcome, Err(beekem::error::CgkaError::IdentifierNotFound)),
        "expected the spurious IdentifierNotFound this reproduction is about, got {outcome:?}"
    );

    println!(
        "after:  group_size={} log_says_carol_present={}",
        dave.group_size(),
        log_says_present(&dave, carol_id)
    );
    let retry = now(dave.remove::<Local, _>(carol_id, &dave_signer));
    println!("retry:  remove(carol) -> {retry:?}");
    assert!(
        matches!(retry, Ok(None)),
        "the replay performed by the failing call persists, so the error is \
         spurious rather than fatal — got {retry:?}"
    );
}
