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
    /// Encrypted manifest replicas alice has emitted but bob has not received.
    manifests_to_bob: Vec<iroh_beekem_core::Chunk>,
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
        alice: WorkspaceState::found(alice_cgka, WorkspaceSecret::new(secret.to_bytes()))
            .expect("alice founds the workspace"),
        bob: WorkspaceState::joined(bob_cgka, secret),
        to_bob: Vec::new(),
        chunks_to_bob: Vec::new(),
        manifests_to_bob: Vec::new(),
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
                Effect::StoreManifest { chunk, .. } => self.manifests_to_bob.push(*chunk),
                Effect::Applied { .. } | Effect::ManifestUpdated => {}
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
        for chunk in std::mem::take(&mut self.manifests_to_bob) {
            self.bob
                .handle(
                    Event::ManifestArrived {
                        chunk: Box::new(chunk),
                    },
                    &mut rng(0),
                )
                .expect("bob should handle a manifest arrival");
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
            Effect::StoreManifest { chunk, .. } => {
                bus.alice
                    .handle(Event::ManifestArrived { chunk }, &mut rng(0))
                    .expect("alice handles bob's manifest");
            }
            Effect::Applied { .. } | Effect::ManifestUpdated => {}
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

/// Roles were fully implemented in the manifest but had no caller: nothing
/// consulted them before acting. These cover the enforcement points.
mod roles_are_enforced {
    use super::{rng, two_node_workspace, DOC};
    use iroh_beekem_core::{CoreError, Event, FileEntry, Role};

    #[test]
    fn the_founder_is_an_admin_and_a_joiner_is_not() {
        let bus = two_node_workspace();

        assert_eq!(
            bus.alice.manifest().role_of(&bus.alice.member_id().to_bytes()),
            Some(Role::Admin),
            "founding a workspace must make you its first admin"
        );
        assert_eq!(
            bus.bob.manifest().role_of(&bus.bob.member_id().to_bytes()),
            None,
            "a joiner's manifest starts empty and is filled by sync, not by \
             self-assignment"
        );
    }

    #[test]
    fn a_non_admin_cannot_change_membership() {
        let mut bus = two_node_workspace();
        let alice_id = bus.alice.member_id();

        // Bob has synced no manifest, so he holds no role at all.
        let result = bus
            .bob
            .handle(Event::RemoveMember { member: alice_id }, &mut rng(9));

        assert!(
            matches!(result, Err(CoreError::NotAnAdmin)),
            "a member with no administrative role must not be able to revoke \
             anyone, got {result:?}"
        );
    }

    #[test]
    fn an_admitted_member_is_given_a_writing_role() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::UpsertFile {
                entry: FileEntry {
                    uuid: DOC,
                    logical_path: "/notes.md".into(),
                    mime_type: "text/markdown".into(),
                },
            },
            50,
        );
        bus.deliver_all_to_bob();

        // `two_node_workspace` admits bob through the controller directly, so
        // drive the manifest half of an admission here.
        let bob_id = bus.bob.member_id();
        bus.alice_does(
            Event::SetRole {
                member: bob_id.to_bytes(),
                role: Role::Editor,
            },
            51,
        );
        bus.deliver_all_to_bob();

        assert_eq!(
            bus.bob.manifest().role_of(&bob_id.to_bytes()),
            Some(Role::Editor),
            "bob should learn his own role once the manifest reaches him"
        );
        assert_eq!(
            bus.bob.manifest().resolve_path("/notes.md"),
            Some(DOC),
            "the manifest's file index must survive the encrypt/sync round trip"
        );
    }

    #[test]
    fn the_last_admin_cannot_be_demoted_or_removed() {
        let mut bus = two_node_workspace();
        let alice_id = bus.alice.member_id();

        let demote = bus.alice.handle(
            Event::SetRole {
                member: alice_id.to_bytes(),
                role: Role::Editor,
            },
            &mut rng(60),
        );
        assert!(
            matches!(demote, Err(CoreError::LastAdmin)),
            "demoting the only admin would leave a workspace nobody can ever \
             administer again, got {demote:?}"
        );

        let remove = bus
            .alice
            .handle(Event::RemoveMember { member: alice_id }, &mut rng(61));
        assert!(
            matches!(remove, Err(CoreError::LastAdmin)),
            "removing the only admin must be refused for the same reason, got {remove:?}"
        );

        assert_eq!(
            bus.alice.manifest().admin_count(),
            1,
            "the refused operations must have left the admin in place"
        );
    }

    #[test]
    fn an_author_may_write_only_once_claimed_and_roled() {
        let mut bus = two_node_workspace();
        let bob_id = bus.bob.member_id();
        let bob_author = [0xB0_u8; 32];

        // Claimed by bob, but no role assigned yet.
        bus.bob
            .handle(Event::AnnounceAuthor { author: bob_author }, &mut rng(70))
            .expect("announcing your own author id needs no privilege");
        assert!(
            !bus.bob.manifest().author_may_write(&bob_author),
            "self-attestation alone must not confer the right to write"
        );

        // Now an admin grants the role. Applied to bob's own replica directly,
        // standing in for the sync that would carry it.
        bus.bob
            .manifest()
            .set_role(&bob_id.to_bytes(), Role::Editor)
            .expect("recording the role");
        assert!(
            bus.bob.manifest().author_may_write(&bob_author),
            "a claimed author whose member holds a writing role should be accepted"
        );

        assert!(
            !bus.bob.manifest().author_may_write(&[0xFF_u8; 32]),
            "an author nobody has claimed must never be accepted"
        );
    }
}

/// The pending-chunk queue holds ciphertext that arrived before its key, so it
/// is filled by anyone who can write to the data plane. Both of its limits are
/// checked here against chunks that can never become applicable, which is what
/// a flood looks like.
mod the_pending_queue_is_bounded {
    use super::{rng, two_node_workspace, DOC};
    use iroh_beekem_core::{
        state::{MAX_PENDING_CHUNKS, MAX_PENDING_CHUNK_BYTES},
        Chunk, ChunkRef, Event,
    };
    use keyhive_crypto::{digest::Digest, siv::Siv, symmetric_key::SymmetricKey};

    /// A syntactically valid chunk that no key in the workspace can open.
    ///
    /// `content_ref` varies per chunk so the arrival-side deduplication does
    /// not collapse them into one entry — otherwise this would test dedup
    /// rather than the budget.
    fn undecryptable_chunk(index: u64, size: usize) -> Chunk {
        let mut ciphertext = vec![0u8; size];
        ciphertext[..8].copy_from_slice(&index.to_le_bytes());

        let mut content_ref = [0u8; 32];
        content_ref[..8].copy_from_slice(&index.to_le_bytes());

        Chunk::new(
            Siv::new(&SymmetricKey::from([7u8; 32]), &ciphertext, b"doc"),
            ciphertext,
            Digest::from([1u8; 32]),
            Digest::from([2u8; 32]),
            ChunkRef(content_ref),
            Digest::from([3u8; 32]),
        )
    }

    #[test]
    fn a_flood_of_small_chunks_is_capped_by_count() {
        let mut bus = two_node_workspace();
        let flood = MAX_PENDING_CHUNKS + 100;

        for i in 0..flood {
            bus.bob
                .handle(
                    Event::ChunkArrived {
                        doc: DOC,
                        chunk: Box::new(undecryptable_chunk(i as u64, 64)),
                    },
                    &mut rng(0),
                )
                .expect("an undecryptable chunk parks rather than failing");
        }

        assert_eq!(
            bus.bob.pending_len(),
            MAX_PENDING_CHUNKS,
            "the queue should sit exactly at its count limit"
        );
        assert_eq!(
            bus.bob.evicted_chunks(),
            (flood - MAX_PENDING_CHUNKS) as u64,
            "every chunk past the cap should be accounted for as an eviction"
        );
    }

    #[test]
    fn a_flood_of_large_chunks_is_capped_by_total_bytes() {
        let mut bus = two_node_workspace();

        // Well under MAX_PENDING_CHUNKS, so only the byte budget can stop this.
        let chunk_size = 1024 * 1024;
        let flood = MAX_PENDING_CHUNK_BYTES / chunk_size + 8;

        for i in 0..flood {
            bus.bob
                .handle(
                    Event::ChunkArrived {
                        doc: DOC,
                        chunk: Box::new(undecryptable_chunk(i as u64, chunk_size)),
                    },
                    &mut rng(0),
                )
                .expect("an undecryptable chunk parks rather than failing");
        }

        assert!(
            bus.bob.pending_len() < MAX_PENDING_CHUNKS,
            "the count cap must not be what stopped this, or the test proves nothing"
        );
        assert!(
            bus.bob.pending_len() * chunk_size <= MAX_PENDING_CHUNK_BYTES,
            "parked ciphertext must stay within the byte budget, got {} chunks",
            bus.bob.pending_len()
        );
        assert!(
            bus.bob.evicted_chunks() > 0,
            "exceeding the byte budget should have evicted something"
        );
    }
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
