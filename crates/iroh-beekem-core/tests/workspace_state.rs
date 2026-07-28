//! End-to-end tests of the workspace state machine, with the network replaced
//! by a hand-rolled in-memory bus.
//!
//! Everything here is deterministic: seeded RNG, no clock, explicit delivery.
//! Reordering and partitioning are expressed by choosing when to hand a message
//! to a node, which is exactly the seam the `propsim` harness plugs into.

use std::sync::Arc;

use beekem::{id::TreeId, operation::CgkaOperation};
use iroh_beekem_core::{
    CgkaController, DocumentUuid, Effect, Event, Role, WorkspaceSecret, WorkspaceState,
};
use keyhive_crypto::{
    share_key::ShareSecretKey, signed::Signed, signer::memory::MemorySigner, verifiable::Verifiable,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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
    let bob_cgka = CgkaController::join(doc_id, bob_signer, bob_secret, &log).expect("bob joins");

    let alice = WorkspaceState::found(alice_cgka, WorkspaceSecret::new(secret.to_bytes()))
        .expect("alice founds the workspace");

    // `add_member` above admits bob at the CGKA level only. A real admission
    // goes through `Event::AddUser`, which also writes the manifest records
    // that give the new leaf an owner and therefore a role; mirror that here,
    // or bob would hold a leaf belonging to nobody.
    let bob_bytes = bob_id.to_bytes();
    alice
        .manifest()
        .set_user(&bob_bytes, "bob")
        .expect("recording bob's user");
    alice
        .manifest()
        .set_device(&bob_bytes, &bob_bytes, "first device")
        .expect("recording bob's device");
    alice
        .manifest()
        .set_role(&bob_bytes, Role::Editor)
        .expect("granting bob a writing role");

    Bus {
        alice,
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
                Effect::Applied { .. } | Effect::ManifestUpdated | Effect::DeleteEntry { .. } => {}
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
                    .handle(Event::ChunkArrived { doc: DOC, chunk }, &mut rng(0))
                    .expect("alice handles bob's chunk");
            }
            Effect::StoreManifest { chunk, .. } => {
                bus.alice
                    .handle(Event::ManifestArrived { chunk }, &mut rng(0))
                    .expect("alice handles bob's manifest");
            }
            Effect::Applied { .. } | Effect::ManifestUpdated | Effect::DeleteEntry { .. } => {}
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
    assert_eq!(
        bus.alice.pending_len(),
        0,
        "alice should have nothing parked"
    );
    assert_eq!(bus.bob.pending_len(), 0, "bob should have nothing parked");
}

/// Roles were fully implemented in the manifest but had no caller: nothing
/// consulted them before acting. These cover the enforcement points.
mod roles_are_enforced {
    use iroh_beekem_core::{CoreError, Event, FileEntry, Role};

    use super::{DOC, rng, two_node_workspace};

    #[test]
    fn the_founder_is_an_admin_and_a_joiner_is_not() {
        let bus = two_node_workspace();

        assert_eq!(
            bus.alice
                .manifest()
                .role_of(&bus.alice.member_id().to_bytes()),
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
                user: bob_id.to_bytes(),
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
                user: alice_id.to_bytes(),
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
        // standing in for the sync that would carry it — which means writing
        // the device record too, since a role is granted to a *user* and it is
        // that record which says whose device this leaf is.
        bus.bob
            .manifest()
            .set_device(&bob_id.to_bytes(), &bob_id.to_bytes(), "first device")
            .expect("recording the device");
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

    /// A viewer publishing is not merely futile — every receiver would reject
    /// the entry anyway — it is *expensive*: encrypting a chunk can force an
    /// implicit PCS update, re-keying the whole group to protect bytes nobody
    /// will accept. These cover the three mutations that had no check at all,
    /// plus the resync that runs the same publish path.
    #[test]
    fn a_viewer_cannot_mutate_content_or_the_file_index() {
        let mut bus = two_node_workspace();
        let bob_id = bus.bob.member_id();

        // Record the demotion on bob's own replica, standing in for the sync
        // that would carry it. Both records: the role names a user, and the
        // device record is what ties bob's leaf to that user.
        bus.bob
            .manifest()
            .set_device(&bob_id.to_bytes(), &bob_id.to_bytes(), "first device")
            .expect("recording the device");
        bus.bob
            .manifest()
            .set_role(&bob_id.to_bytes(), Role::Viewer)
            .expect("recording the role");

        let refusals = [
            (
                "edit",
                bus.bob.handle(
                    Event::LocalEdit {
                        doc: DOC,
                        text: "viewers may not write".into(),
                    },
                    &mut rng(80),
                ),
            ),
            (
                "resync",
                bus.bob.handle(Event::Resync { doc: DOC }, &mut rng(81)),
            ),
            (
                "upsert",
                bus.bob.handle(
                    Event::UpsertFile {
                        entry: FileEntry {
                            uuid: DOC,
                            logical_path: "/viewer.md".into(),
                            mime_type: "text/markdown".into(),
                        },
                    },
                    &mut rng(82),
                ),
            ),
            (
                "rename",
                bus.bob.handle(
                    Event::RenameFile {
                        doc: DOC,
                        path: "/renamed-by-viewer.md".into(),
                    },
                    &mut rng(83),
                ),
            ),
        ];

        for (what, result) in refusals {
            assert!(
                matches!(result, Err(CoreError::NotAWriter)),
                "a viewer's {what} must be refused, got {result:?}"
            );
        }

        assert_eq!(
            bus.bob.document_text(DOC),
            "",
            "a refused edit must not have reached the local document either"
        );
    }

    /// The bootstrap case, and the reason `require_write` is permissive about
    /// members it has never heard of. A joiner's manifest is empty until it
    /// syncs, so a role-less member is indistinguishable from an unsynced one.
    /// Refusing here would deadlock onboarding: no publish, so no author
    /// announcement, so no peer ever accepts anything from this node.
    #[test]
    fn a_member_whose_role_has_not_synced_yet_may_still_write() {
        let mut bus = two_node_workspace();

        assert_eq!(
            bus.bob.manifest().role_of(&bus.bob.member_id().to_bytes()),
            None,
            "precondition: bob has synced no manifest and holds no role"
        );

        let result = bus.bob.handle(
            Event::LocalEdit {
                doc: DOC,
                text: "written before my role arrived".into(),
            },
            &mut rng(84),
        );

        assert!(
            result.is_ok(),
            "a member whose role has not yet synced must not be refused, got {result:?}"
        );
    }
}

/// The pending-chunk queue holds ciphertext that arrived before its key, so it
/// is filled by anyone who can write to the data plane. Both of its limits are
/// checked here against chunks that can never become applicable, which is what
/// a flood looks like.
mod the_pending_queue_is_bounded {
    use iroh_beekem_core::{
        Chunk, ChunkRef, Event,
        state::{MAX_PENDING_CHUNK_BYTES, MAX_PENDING_CHUNKS},
    };
    use keyhive_crypto::{digest::Digest, siv::Siv, symmetric_key::SymmetricKey};

    use super::{DOC, rng, two_node_workspace};

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

/// A CGKA leaf is a device, not a person. These cover the consequences: roles
/// resolve through the owning user, one user's devices are independent leaves,
/// and a device cannot enrol itself into somebody else's user — which would be
/// a privilege escalation rather than a mere bookkeeping error.
mod users_own_devices {
    use iroh_beekem_core::{CoreError, Event, Role};
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
    };

    use super::{rng, two_node_workspace};

    #[test]
    fn a_device_acts_under_its_owners_role() {
        let bus = two_node_workspace();
        let alice = bus.alice.member_id().to_bytes();

        assert_eq!(
            bus.alice.manifest().role_of_member(&alice),
            Some(Role::Admin),
            "the founding device must resolve to the founding user's role"
        );
        assert_eq!(
            bus.alice.manifest().user_of(&alice),
            Some(alice),
            "a founder's user id is their founding device's member id"
        );
    }

    #[test]
    fn a_second_device_inherits_its_users_role_without_a_new_grant() {
        let mut bus = two_node_workspace();
        let alice_user = bus.alice.member_id().to_bytes();

        // Alice enrols a laptop of her own.
        let laptop = MemorySigner::generate(&mut rng(300));
        let laptop_id = beekem::id::MemberId::from(laptop.verifying_key());
        let laptop_secret = ShareSecretKey::generate(&mut rng(301));
        bus.alice_does(
            Event::AddDevice {
                member: laptop_id,
                share_key: laptop_secret.share_key(),
                user: alice_user,
                label: "laptop".into(),
            },
            302,
        );

        assert_eq!(
            bus.alice.manifest().role_of_member(&laptop_id.to_bytes()),
            Some(Role::Admin),
            "a new device must inherit its user's role rather than needing its own grant"
        );
        assert_eq!(
            bus.alice.manifest().devices_of(&alice_user).len(),
            2,
            "alice should now own two devices"
        );
        assert_eq!(
            bus.alice.manifest().users().len(),
            2,
            "enrolling a device must not invent a new user; alice and bob only"
        );
    }

    #[test]
    fn a_member_cannot_enrol_a_device_into_someone_elses_user() {
        let mut bus = two_node_workspace();
        let alice_user = bus.alice.member_id().to_bytes();

        // Bob is an editor, not an admin, and the device he is trying to bind
        // would inherit alice's admin role.
        let rogue = MemorySigner::generate(&mut rng(310));
        let rogue_id = beekem::id::MemberId::from(rogue.verifying_key());
        let rogue_secret = ShareSecretKey::generate(&mut rng(311));

        // Give bob his records locally so he is a fully-formed editor.
        let bob = bus.bob.member_id().to_bytes();
        bus.bob
            .manifest()
            .set_device(&bob, &bob, "first device")
            .expect("recording bob's device");
        bus.bob
            .manifest()
            .set_role(&bob, Role::Editor)
            .expect("granting bob a role");

        let result = bus.bob.handle(
            Event::AddDevice {
                member: rogue_id,
                share_key: rogue_secret.share_key(),
                user: alice_user,
                label: "not really alice's".into(),
            },
            &mut rng(312),
        );

        assert!(
            matches!(result, Err(CoreError::NotThisUsersDevice)),
            "binding a device to another user's account must be refused, got {result:?}"
        );
    }

    #[test]
    fn removing_one_device_leaves_the_users_other_devices_alone() {
        let mut bus = two_node_workspace();
        let alice_user = bus.alice.member_id().to_bytes();

        let laptop = MemorySigner::generate(&mut rng(320));
        let laptop_id = beekem::id::MemberId::from(laptop.verifying_key());
        let laptop_secret = ShareSecretKey::generate(&mut rng(321));
        bus.alice_does(
            Event::AddDevice {
                member: laptop_id,
                share_key: laptop_secret.share_key(),
                user: alice_user,
                label: "laptop".into(),
            },
            322,
        );

        // Removing one of the sole admin's two devices must be allowed: the
        // user keeps administering the workspace from the other one. Guarding
        // on the leaf rather than the user would refuse this.
        let removed = bus
            .alice
            .handle(Event::RemoveMember { member: laptop_id }, &mut rng(323));
        assert!(
            removed.is_ok(),
            "removing one device of a multi-device admin must be allowed, got {removed:?}"
        );
        assert_eq!(
            bus.alice.manifest().role_of(&alice_user),
            Some(Role::Admin),
            "the user keeps their role when one of their devices is removed"
        );
    }
}

/// Content mutation beyond append-only. Each of these publishes through the
/// same path as a plain edit, so what is being checked is the text semantics
/// and the delete bookkeeping, not the transport.
mod file_crud {
    use iroh_beekem_core::{CoreError, Effect, Event, FileEntry};

    use super::{DOC, rng, two_node_workspace};

    fn entry() -> FileEntry {
        FileEntry {
            uuid: DOC,
            logical_path: "/notes.md".into(),
            mime_type: "text/markdown".into(),
        }
    }

    #[test]
    fn write_replaces_the_whole_document() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "original".into(),
            },
            400,
        );
        bus.alice_does(
            Event::WriteFile {
                doc: DOC,
                text: "replaced".into(),
            },
            401,
        );
        bus.deliver_all_to_bob();

        assert_eq!(bus.alice.document_text(DOC), "replaced");
        assert_eq!(
            bus.bob.document_text(DOC),
            "replaced",
            "a whole-document write must converge like any other edit"
        );
    }

    #[test]
    fn insert_and_remove_address_character_offsets() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "hello world".into(),
            },
            410,
        );
        bus.alice_does(
            Event::InsertText {
                doc: DOC,
                pos: 5,
                text: ",".into(),
            },
            411,
        );
        assert_eq!(bus.alice.document_text(DOC), "hello, world");

        bus.alice_does(
            Event::RemoveText {
                doc: DOC,
                pos: 0,
                len: 7,
            },
            412,
        );
        assert_eq!(bus.alice.document_text(DOC), "world");

        bus.deliver_all_to_bob();
        assert_eq!(
            bus.bob.document_text(DOC),
            "world",
            "positional edits must converge, not just apply locally"
        );
    }

    #[test]
    fn out_of_range_positions_are_clamped_rather_than_rejected() {
        // A caller's offsets come from a view a concurrent remote edit may
        // already have shortened. That is ordinary in a CRDT, so it clamps.
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "abc".into(),
            },
            420,
        );

        bus.alice_does(
            Event::InsertText {
                doc: DOC,
                pos: 999,
                text: "!".into(),
            },
            421,
        );
        assert_eq!(bus.alice.document_text(DOC), "abc!");

        bus.alice_does(
            Event::RemoveText {
                doc: DOC,
                pos: 2,
                len: 999,
            },
            422,
        );
        assert_eq!(bus.alice.document_text(DOC), "ab");
    }

    #[test]
    fn delete_removes_the_document_and_withdraws_its_entry() {
        let mut bus = two_node_workspace();
        bus.alice_does(Event::UpsertFile { entry: entry() }, 430);
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "doomed".into(),
            },
            431,
        );

        let effects = bus
            .alice
            .handle(Event::DeleteFile { doc: DOC }, &mut rng(432))
            .expect("alice may delete her own document");

        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::DeleteEntry { doc, .. } if *doc == DOC)),
            "deleting must withdraw this node's index entry, got {effects:?}"
        );
        assert_eq!(
            bus.alice.manifest().resolve_path("/notes.md"),
            None,
            "the deleted document must leave the file index"
        );
        assert_eq!(
            bus.alice.document_text(DOC),
            "",
            "the local replica must be dropped too"
        );
    }

    #[test]
    fn a_chunk_arriving_after_a_delete_does_not_resurrect_the_document() {
        let mut bus = two_node_workspace();
        bus.alice_does(Event::UpsertFile { entry: entry() }, 440);

        // Bob writes; his chunk is in flight when alice deletes.
        bus.bob
            .handle(
                Event::LocalEdit {
                    doc: DOC,
                    text: "in flight".into(),
                },
                &mut rng(441),
            )
            .expect("bob writes");

        bus.alice
            .handle(Event::DeleteFile { doc: DOC }, &mut rng(442))
            .expect("alice deletes");

        assert_eq!(
            bus.alice.pending_len(),
            0,
            "deleting must also drop anything parked for that document"
        );
        assert_eq!(
            bus.alice.document_text(DOC),
            "",
            "a delete must leave the document empty locally"
        );
    }

    #[test]
    fn deleting_an_unknown_document_is_an_error() {
        let mut bus = two_node_workspace();
        let result = bus
            .alice
            .handle(Event::DeleteFile { doc: DOC }, &mut rng(450));
        assert!(
            matches!(result, Err(CoreError::UnknownDocument)),
            "deleting a document that was never recorded should fail, got {result:?}"
        );
    }
}
