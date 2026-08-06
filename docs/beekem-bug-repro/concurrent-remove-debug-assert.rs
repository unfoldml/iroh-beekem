//! Standalone reproduction for beekem 0.3.0.
//!
//! `BeeKem::sort_leaves_and_blank_paths_for_concurrent_membership_changes`
//! asserts that a leaf named by a concurrent `Remove` is already blank, and then
//! blanks it anyway. The two lines disagree, and the assertion is the one that is
//! wrong: an ordinary interleaving of two concurrent adds and a removal reaches it
//! with the leaf still occupied, and every debug build aborts.
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
    share_key::ShareSecretKey, signed::Signed, signer::memory::MemorySigner, verifiable::Verifiable,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// beekem's signing is `async` but a `MemorySigner` never yields, so every future
/// here is already complete on first poll.
fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    use std::task::{Context, Poll, Waker};
    let mut fut = Box::pin(fut);
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("an in-memory signer must not yield"),
    }
}

/// Every operation the graph holds, in causal order.
fn ops_of(cgka: &Cgka) -> Vec<Arc<Signed<CgkaOperation>>> {
    cgka.ops()
        .expect("sortable log")
        .into_iter()
        .flat_map(IntoIterator::into_iter)
        .collect()
}

/// Two concurrent adds and a removal, merged by a peer that then re-keys.
///
/// In a debug build this panics inside beekem. In a release build it completes and
/// the group converges, which is what identifies the assertion as too strict rather
/// than as a symptom of divergence — so the test asserts the panic where the panic
/// happens and asserts convergence where it does not.
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "assertion failed: self.leaf(leaf_idx).is_none()")
)]
#[test]
fn a_concurrent_removal_trips_a_debug_assertion_in_beekems_tree() {
    let doc = TreeId::from(MemorySigner::generate(&mut rng(0)).verifying_key());

    let alice_signer = MemorySigner::generate(&mut rng(1));
    let bob_signer = MemorySigner::generate(&mut rng(2));
    let alice_id = MemberId::from(alice_signer.verifying_key());
    let bob_id = MemberId::from(bob_signer.verifying_key());
    let alice_sk = ShareSecretKey::generate(&mut rng(10));
    let bob_sk = ShareSecretKey::generate(&mut rng(11));

    // Alice founds the group and admits Bob and Carol. Three members, so the next
    // leaf on the right is index 3. Two members is not enough: the tree is then
    // exactly full, and growing it takes a different path that resolves the
    // conflict below without ever reaching the assertion.
    let mut alice = now(Cgka::new::<Local, _>(
        doc,
        alice_id,
        alice_sk.share_key(),
        &alice_signer,
    ))
    .expect("founding");
    alice.owner_sks.insert(alice_sk.share_key(), alice_sk);
    let carol_id = MemberId::from(MemorySigner::generate(&mut rng(3)).verifying_key());
    for (id, sk) in [
        (bob_id, bob_sk.share_key()),
        (carol_id, ShareSecretKey::generate(&mut rng(12)).share_key()),
    ] {
        now(alice.add::<Local, _>(id, sk, &alice_signer))
            .expect("adding")
            .expect("each member is new");
    }

    // Bob reconstructs the same group from Alice's operation log.
    let log = ops_of(&alice);
    let init: Signed<CgkaOperation> = (**log.first().expect("a founding add")).clone();
    let CgkaOperation::Add { added_id, pk, .. } = init.payload else {
        panic!("the log must start with the founding add");
    };
    let mut bob = Cgka::new_from_init_add(doc, added_id, pk, init).expect("rebuilding");
    for op in log.iter().skip(1) {
        bob.merge_concurrent_operation(Arc::clone(op))
            .expect("replaying the log");
    }
    let mut bob_keys = ShareKeyMap::new();
    bob_keys.insert(bob_sk.share_key(), bob_sk);
    let mut bob = bob.with_new_owner(bob_id, bob_keys).expect("re-owning");

    // From that shared head, each of them admits somebody. `add` calls `push_leaf`
    // straight away, so **both operations record leaf index 3** — the concurrent
    // add conflict the sorting exists to resolve.
    let x_id = MemberId::from(MemorySigner::generate(&mut rng(5)).verifying_key());
    let y_id = MemberId::from(MemorySigner::generate(&mut rng(6)).verifying_key());
    let add_x = now(alice.add::<Local, _>(
        x_id,
        ShareSecretKey::generate(&mut rng(14)).share_key(),
        &alice_signer,
    ))
    .expect("alice adds x")
    .expect("x is new");
    let add_y = now(bob.add::<Local, _>(
        y_id,
        ShareSecretKey::generate(&mut rng(15)).share_key(),
        &bob_signer,
    ))
    .expect("bob adds y")
    .expect("y is new");
    let (
        CgkaOperation::Add { leaf_index: lx, .. },
        CgkaOperation::Add { leaf_index: ly, .. },
    ) = (&add_x.payload, &add_y.payload)
    else {
        panic!("both operations are adds");
    };
    println!("add_x leaf_index={lx}  add_y leaf_index={ly}");
    assert_eq!(
        (lx, ly),
        (&3, &3),
        "the two concurrent adds must claim the same leaf, or there is no conflict \
         to resolve and nothing below is exercised"
    );

    alice
        .merge_concurrent_operation(Arc::new(add_y))
        .expect("alice merges bob's add");
    bob.merge_concurrent_operation(Arc::new(add_x))
        .expect("bob merges alice's add");

    // Alice removes the member she admitted. The operation records the leaf index
    // **as Alice's tree has it**, and that index travels to every peer.
    let removal = now(alice.remove::<Local, _>(x_id, &alice_signer))
        .expect("alice removes x")
        .expect("x was a member");
    let CgkaOperation::Remove { leaf_idx, .. } = removal.payload else {
        panic!("the operation is a removal");
    };
    println!("removal records leaf_idx={leaf_idx}");

    // Bob re-keys his own leaf, concurrently with that removal. This is what makes
    // the epoch hold more than one operation, and it is **required**: an epoch of
    // one operation is applied directly and never reaches the sorting path. Drop
    // this rotation and the reproduction stops reproducing.
    let (_, rotation) = now(bob.update::<Local, _, _>(
        ShareSecretKey::generate(&mut rng(24)).share_key(),
        ShareSecretKey::generate(&mut rng(24)),
        &bob_signer,
        &mut rng(25),
    ))
    .expect("bob rotates");
    bob.merge_concurrent_operation(Arc::new(rotation))
        .expect("bob merges his own rotation");
    bob.merge_concurrent_operation(Arc::new(removal))
        .expect("bob merges the removal");

    // Anything that replays the graph walks that epoch. In a debug build the
    // assertion fires here and nothing below runs.
    let outcome = now(bob.update::<Local, _, _>(
        ShareSecretKey::generate(&mut rng(26)).share_key(),
        ShareSecretKey::generate(&mut rng(26)),
        &bob_signer,
        &mut rng(27),
    ));
    println!(
        "bob update -> ok={} group_size={}",
        outcome.is_ok(),
        bob.group_size()
    );

    // Reached only without debug assertions. The blanking the assertion guards is
    // harmless: both trees still hold four members and neither has lost Y, the
    // member whose leaf the stale index could have taken.
    assert!(outcome.is_ok(), "the replay itself succeeds");
    assert_eq!(bob.group_size(), 4, "alice, bob, carol and y");
    for (who, cgka, signer) in [
        ("bob", &mut bob, &bob_signer),
        ("alice", &mut alice, &alice_signer),
    ] {
        let held = now(cgka.remove::<Local, _>(y_id, signer));
        println!("{who} still holds Y: {}", matches!(held, Ok(Some(_))));
        assert!(
            matches!(held, Ok(Some(_))),
            "{who} must still hold Y — `remove` answers `Ok(None)` for a member the \
             tree no longer has, which is the only membership question beekem's \
             public surface can answer, and it is what would expose the stale index \
             blanking the wrong leaf"
        );
    }
}
