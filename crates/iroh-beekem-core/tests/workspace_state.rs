//! End-to-end tests of the workspace state machine, with the network replaced
//! by a hand-rolled in-memory bus.
//!
//! Everything here is deterministic: seeded RNG, no clock, explicit delivery.
//! Reordering and partitioning are expressed by choosing when to hand a message
//! to a node, which is exactly the seam the `propsim` harness plugs into.

use beekem::{id::TreeId, operation::CgkaOperation};
use iroh_beekem_core::{
    CgkaController, DocumentUuid, Effect, Event, WorkspaceSecret, WorkspaceState,
};
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

const DOC: DocumentUuid = DocumentUuid([42u8; 16]);

/// A two-node workspace with an explicit, inspectable message bus.
struct Bus {
    alice: WorkspaceState,
    bob: WorkspaceState,
    /// Control-plane messages alice has emitted but bob has not yet received.
    to_bob: Vec<Signed<CgkaOperation>>,
    /// Data-plane chunks alice has emitted but bob has not yet received.
    chunks_to_bob: Vec<iroh_beekem_core::Chunk>,
}

fn two_node_workspace() -> Bus {
    let doc_id = TreeId::from(MemorySigner::generate(&mut rng(0)).verifying_key());
    let alice_signer = MemorySigner::generate(&mut rng(1));
    let bob_signer = MemorySigner::generate(&mut rng(2));
    let bob_id = beekem::id::MemberId::from(bob_signer.verifying_key());

    let secret = WorkspaceSecret::generate(&mut rng(5));

    let mut alice_cgka =
        CgkaController::create(doc_id, alice_signer, &mut rng(10)).expect("alice founds workspace");

    let bob_secret = ShareSecretKey::generate(&mut rng(20));
    alice_cgka
        .add_member(bob_id, bob_secret.share_key())
        .expect("adding bob")
        .expect("bob is new");

    let log = alice_cgka.op_log().expect("exporting log");
    let bob_cgka =
        CgkaController::join(doc_id, bob_signer, bob_secret, &log).expect("bob joins");

    Bus {
        alice: WorkspaceState::new(alice_cgka, WorkspaceSecret::new(secret.to_bytes())),
        bob: WorkspaceState::new(bob_cgka, secret),
        to_bob: Vec::new(),
        chunks_to_bob: Vec::new(),
    }
}

impl Bus {
    /// Apply an event to alice, queueing whatever she emits for bob.
    fn alice_does(&mut self, event: Event, seed: u64) {
        let effects = self
            .alice
            .handle(event, &mut rng(seed))
            .expect("alice should handle the event");
        for effect in effects {
            match effect {
                Effect::BroadcastOp(op) => self.to_bob.push(*op),
                Effect::StoreChunk { chunk, .. } => self.chunks_to_bob.push(*chunk),
                Effect::Applied { .. } => {}
            }
        }
    }

    /// Deliver everything queued for bob, control plane first.
    fn deliver_all_to_bob(&mut self) {
        for op in std::mem::take(&mut self.to_bob) {
            self.bob
                .handle(Event::ControlOp(Arc::new(op)), &mut rng(0))
                .expect("bob should handle a control op");
        }
        for chunk in std::mem::take(&mut self.chunks_to_bob) {
            self.bob
                .handle(
                    Event::ChunkArrived {
                        doc: DOC,
                        chunk: Box::new(chunk),
                    },
                    &mut rng(0),
                )
                .expect("bob should handle a chunk arrival");
        }
    }

    /// Deliver only the data plane, holding back the control plane.
    fn deliver_chunks_only_to_bob(&mut self) {
        for chunk in std::mem::take(&mut self.chunks_to_bob) {
            self.bob
                .handle(
                    Event::ChunkArrived {
                        doc: DOC,
                        chunk: Box::new(chunk),
                    },
                    &mut rng(0),
                )
                .expect("bob should handle a chunk arrival");
        }
    }
}

#[test]
fn edit_by_one_member_converges_on_the_other() {
    let mut bus = two_node_workspace();

    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "hello world".into(),
        },
        30,
    );
    bus.deliver_all_to_bob();

    assert_eq!(
        bus.bob.document_text(DOC),
        "hello world",
        "bob should converge on alice's edit"
    );
    assert_eq!(
        bus.bob.pending_len(),
        0,
        "nothing should remain parked once the network has settled"
    );
}

#[test]
fn chunk_arriving_before_its_key_is_parked_then_applied() {
    let mut bus = two_node_workspace();

    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "secret".into(),
        },
        30,
    );

    // Data plane overtakes the control plane: bob gets the ciphertext before
    // the operation that lets him derive its key.
    bus.deliver_chunks_only_to_bob();

    assert_eq!(
        bus.bob.document_text(DOC),
        "",
        "bob must not be able to read the chunk before its key material arrives"
    );
    assert_eq!(
        bus.bob.pending_len(),
        1,
        "the undecryptable chunk should be parked, not discarded"
    );

    // Control plane catches up.
    bus.deliver_all_to_bob();

    assert_eq!(
        bus.bob.document_text(DOC),
        "secret",
        "once the key material arrives the parked chunk should apply"
    );
    assert_eq!(
        bus.bob.pending_len(),
        0,
        "no chunk should stay parked forever"
    );
}

#[test]
fn concurrent_edits_from_both_members_converge() {
    let mut bus = two_node_workspace();

    // Alice writes and bob receives, so both share a base.
    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "a".into(),
        },
        30,
    );
    bus.deliver_all_to_bob();

    // Now both edit while partitioned.
    let bob_effects = bus
        .bob
        .handle(
            Event::LocalEdit {
                doc: DOC,
                text: "b".into(),
            },
            &mut rng(31),
        )
        .expect("bob edits locally");
    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "c".into(),
        },
        32,
    );

    // Heal: bob's traffic to alice, then alice's to bob.
    for effect in bob_effects {
        match effect {
            Effect::BroadcastOp(op) => {
                bus.alice
                    .handle(Event::ControlOp(Arc::new(*op)), &mut rng(0))
                    .expect("alice handles bob's op");
            }
            Effect::StoreChunk { chunk, .. } => {
                bus.alice
                    .handle(
                        Event::ChunkArrived {
                            doc: DOC,
                            chunk,
                        },
                        &mut rng(0),
                    )
                    .expect("alice handles bob's chunk");
            }
            Effect::Applied { .. } => {}
        }
    }
    bus.deliver_all_to_bob();

    let alice_text = bus.alice.document_text(DOC);
    let bob_text = bus.bob.document_text(DOC);

    assert_eq!(
        alice_text, bob_text,
        "concurrent edits must converge to an identical document on both peers"
    );
    for expected in ["a", "b", "c"] {
        assert!(
            alice_text.contains(expected),
            "no concurrent edit should be lost; {expected:?} missing from {alice_text:?}"
        );
    }
    assert_eq!(bus.alice.pending_len(), 0, "alice should have nothing parked");
    assert_eq!(bus.bob.pending_len(), 0, "bob should have nothing parked");
}

#[test]
fn revoked_member_cannot_read_subsequent_edits() {
    let mut bus = two_node_workspace();

    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "before revocation".into(),
        },
        30,
    );
    bus.deliver_all_to_bob();
    assert_eq!(
        bus.bob.document_text(DOC),
        "before revocation",
        "bob must be able to read before he is revoked, or the test proves nothing"
    );

    let bob_id = bus.bob.member_id();
    bus.alice_does(Event::RemoveMember { member: bob_id }, 40);
    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: " AFTER revocation".into(),
        },
        41,
    );

    // Bob sees the whole public control plane and every ciphertext; he simply
    // cannot derive the new keys.
    bus.deliver_all_to_bob();

    assert_eq!(
        bus.bob.document_text(DOC),
        "before revocation",
        "a revoked member must not learn the content of edits made after their removal"
    );
    assert!(
        bus.alice.document_text(DOC).contains("AFTER revocation"),
        "alice should still see her own edit"
    );
}
