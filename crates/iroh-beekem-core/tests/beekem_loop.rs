//! M0 spike: prove the end-to-end BeeKEM loop before anything is built on it.
//!
//! create → add → encrypt → join by replaying the op log → decrypt → revoke →
//! prove the revoked member is locked out.
//!
//! Everything here is deterministic: a seeded `ChaCha20Rng` stands in for the
//! system CSPRNG, so a failure reproduces exactly.

use beekem::{id::TreeId, operation::CgkaOperation};
use iroh_beekem_core::{CgkaController, MergeOutcome};
use keyhive_crypto::{
    share_key::ShareSecretKey, signed::Signed, signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// A workspace is identified by a keypair; only its public half matters here.
fn workspace_id(seed: u64) -> TreeId {
    TreeId::from(MemorySigner::generate(&mut rng(seed)).verifying_key())
}

/// Alice founds a workspace, invites Bob, and both converge on the op log.
struct Invited {
    alice: CgkaController,
    bob: CgkaController,
    bob_id: beekem::id::MemberId,
    /// The full causal log, as a joiner would receive it.
    log: Vec<Signed<CgkaOperation>>,
}

fn invite_bob() -> Invited {
    let doc = workspace_id(0);
    let alice_signer = MemorySigner::generate(&mut rng(1));
    let bob_signer = MemorySigner::generate(&mut rng(2));
    let bob_id = beekem::id::MemberId::from(bob_signer.verifying_key());

    let mut alice = CgkaController::create(doc, alice_signer, &mut rng(10))
        .expect("alice should be able to found a workspace");

    // Bob generates a leaf secret and publishes only its public half.
    let bob_secret = ShareSecretKey::generate(&mut rng(20));
    let bob_share_key = bob_secret.share_key();

    alice
        .add_member(bob_id, bob_share_key)
        .expect("adding bob should succeed")
        .expect("bob is not yet a member, so an operation must be produced");

    let log = alice.op_log().expect("alice should be able to export her log");

    let bob = CgkaController::join(doc, bob_signer, bob_secret, &log)
        .expect("bob should be able to join by replaying the log");

    Invited {
        alice,
        bob,
        bob_id,
        log,
    }
}

#[test]
fn founder_starts_as_the_only_member() {
    let alice = CgkaController::create(workspace_id(0), MemorySigner::generate(&mut rng(1)), &mut rng(10))
        .expect("founding a workspace should succeed");

    assert_eq!(
        alice.group_size(),
        1,
        "a freshly founded workspace should contain only its founder"
    );
}

#[test]
fn invited_member_joins_by_replaying_the_operation_log() {
    let Invited {
        alice, bob, bob_id, ..
    } = invite_bob();

    assert_eq!(alice.group_size(), 2, "alice should see a two-member group");
    assert_eq!(
        bob.group_size(),
        2,
        "bob should reconstruct the same two-member group from the log alone"
    );
    assert_eq!(
        bob.member_id(),
        bob_id,
        "bob should own the leaf he was invited into"
    );
}

#[test]
fn join_rejects_a_log_with_a_causal_hole() {
    let Invited { mut alice, .. } = invite_bob();

    let carol_signer = MemorySigner::generate(&mut rng(3));
    let carol_secret = ShareSecretKey::generate(&mut rng(21));
    let carol_id = beekem::id::MemberId::from(carol_signer.verifying_key());

    alice.rotate(&mut rng(40)).expect("rotation");
    alice
        .add_member(carol_id, carol_secret.share_key())
        .expect("adding carol")
        .expect("carol is new");

    // Drop the intermediate rotation: carol's own `Add` now depends on an
    // operation she will never see.
    let full = alice.op_log().expect("exporting alice's log");
    let holed: Vec<_> = full
        .iter()
        .filter(|op| !matches!(op.payload, CgkaOperation::Update { .. }))
        .cloned()
        .collect();
    assert!(
        holed.len() < full.len(),
        "the test must actually remove an operation to be meaningful"
    );

    let result = CgkaController::join(workspace_id(0), carol_signer, carol_secret, &holed);

    assert!(
        matches!(
            result,
            Err(iroh_beekem_core::CoreError::IncompleteLog { .. })
        ),
        "a log missing a causal predecessor must be rejected outright, got {result:?}"
    );
}

#[test]
fn join_fails_for_a_member_who_was_never_added() {
    let Invited { log, .. } = invite_bob();

    let mallory_signer = MemorySigner::generate(&mut rng(99));
    let mallory_secret = ShareSecretKey::generate(&mut rng(98));

    let result = CgkaController::join(workspace_id(0), mallory_signer, mallory_secret, &log);

    assert!(
        matches!(result, Err(iroh_beekem_core::CoreError::NotInvited)),
        "replaying a log that never adds you must not yield a usable controller, got {result:?}"
    );
}

#[test]
fn member_decrypts_content_written_by_another_member() {
    let Invited {
        mut alice,
        mut bob,
        ..
    } = invite_bob();

    let plaintext = b"the q3 numbers are confidential";
    let (chunk, implicit_op) = alice
        .encrypt(plaintext, &[], &mut rng(30))
        .expect("alice should be able to encrypt");

    // Encrypting can force an implicit PCS update. If it does, that operation
    // is load-bearing: without it bob cannot reach the key.
    if let Some(op) = implicit_op {
        assert_eq!(
            bob.merge(Arc::new(op)).expect("merging alice's update"),
            MergeOutcome::Applied,
            "bob should apply alice's implicit PCS update"
        );
    }

    let recovered = bob
        .decrypt(&chunk)
        .expect("bob is a member and should decrypt alice's chunk");

    assert_eq!(
        recovered, plaintext,
        "bob should recover exactly the plaintext alice encrypted"
    );
}

#[test]
fn revoked_member_cannot_decrypt_later_content() {
    let Invited {
        mut alice,
        mut bob,
        ..
    } = invite_bob();

    // Establish that bob really could read before the revocation, so that the
    // assertion below is about revocation and not about a broken setup.
    let (before, before_op) = alice
        .encrypt(b"readable by bob", &[], &mut rng(30))
        .expect("encrypting before revocation");
    if let Some(op) = before_op {
        bob.merge(Arc::new(op)).expect("merging pre-revocation op");
    }
    assert!(
        bob.decrypt(&before).is_ok(),
        "bob must be able to read before he is revoked"
    );

    let bob_id = bob.member_id();
    let remove_op = alice
        .remove_member(bob_id)
        .expect("removing bob should succeed")
        .expect("bob is a member, so an operation must be produced");

    // Bob observes his own removal — he cannot be prevented from seeing the
    // public control plane.
    bob.merge(Arc::new(remove_op)).expect("bob merges his own removal");

    let (after, after_op) = alice
        .encrypt(b"not readable by bob", &[], &mut rng(31))
        .expect("encrypting after revocation");
    if let Some(op) = after_op {
        let _ = bob.merge(Arc::new(op));
    }

    assert!(
        bob.decrypt(&after).is_err(),
        "a revoked member must not be able to decrypt content written after their removal"
    );
}

#[test]
fn out_of_order_operations_are_parked_then_applied() {
    let Invited { mut alice, .. } = invite_bob();

    let doc = workspace_id(0);
    let carol_signer = MemorySigner::generate(&mut rng(3));
    let carol_secret = ShareSecretKey::generate(&mut rng(21));
    let carol_id = beekem::id::MemberId::from(carol_signer.verifying_key());
    alice
        .add_member(carol_id, carol_secret.share_key())
        .expect("adding carol")
        .expect("carol is new");

    let log = alice.op_log().expect("exporting alice's log");
    let mut carol =
        CgkaController::join(doc, carol_signer, carol_secret, &log).expect("carol joins");

    // Two chained operations produced *after* carol's snapshot, so she has
    // neither of them yet and their order of arrival is observable.
    let first = alice.rotate(&mut rng(40)).expect("first rotation");
    let second = alice.rotate(&mut rng(41)).expect("second rotation");

    // Deliver out of causal order: the later rotation arrives first.
    assert_eq!(
        carol.merge(Arc::new(second)).expect("merging the later op first"),
        MergeOutcome::Deferred,
        "an operation whose predecessors are missing should be parked, not rejected"
    );
    assert_eq!(carol.parked_len(), 1, "the early arrival should be parked");

    carol
        .merge(Arc::new(first))
        .expect("merging the earlier op unblocks the parked one");
    carol.merge_pending().expect("draining parked operations");

    assert_eq!(
        carol.parked_len(),
        0,
        "once predecessors arrive, no operation should remain parked"
    );
}
