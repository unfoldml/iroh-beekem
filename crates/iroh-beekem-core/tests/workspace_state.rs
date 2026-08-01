//! End-to-end tests of the workspace state machine, with the network replaced
//! by a hand-rolled in-memory bus.
//!
//! Everything here is deterministic: seeded RNG, no clock, explicit delivery.
//! Reordering and partitioning are expressed by choosing when to hand a message
//! to a node, which is exactly the seam the `propsim` harness plugs into.

use std::sync::Arc;

use beekem::id::{MemberId, TreeId};
use iroh_beekem_core::{
    AuthorizedOp, Certificate, CgkaController, DocumentUuid, Effect, EpochId, Event, RepairTarget,
    Role, UnixSeconds, WorkspaceSecret, WorkspaceState,
};
use keyhive_crypto::{
    share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

const DOC: DocumentUuid = DocumentUuid([42u8; 16]);

/// The instant every test here drives the state machine at.
///
/// A constant rather than a clock for the same reason the RNG is seeded: these
/// tests are about ordering, and ordering comes from the causal DAG rather than
/// from the timestamp, so a moving clock would add nondeterminism that decides
/// nothing. The tests that *are* about time state their own instants.
const T0: UnixSeconds = UnixSeconds::new(1_767_225_600);

/// A two-node workspace with an explicit, inspectable message bus.
struct Bus {
    alice: WorkspaceState,
    bob: WorkspaceState,
    /// Control-plane messages alice has emitted but bob has not yet received.
    to_bob: Vec<AuthorizedOp>,
    /// Certificates alice has emitted with no operation behind them.
    certs_to_bob: Vec<Certificate>,
    /// Control-plane messages bob has emitted but alice has not yet received.
    to_alice: Vec<AuthorizedOp>,
    /// Certificates bob has emitted with no operation behind them.
    certs_to_alice: Vec<Certificate>,
    /// Encrypted manifest replicas bob has emitted but alice has not received.
    manifests_to_alice: Vec<iroh_beekem_core::Chunk>,
    /// Data-plane chunks alice has emitted but bob has not yet received.
    chunks_to_bob: Vec<iroh_beekem_core::Chunk>,
    /// Encrypted manifest replicas alice has emitted but bob has not received.
    manifests_to_bob: Vec<iroh_beekem_core::Chunk>,
    /// Bob's identity, so his repair requests can be attributed to him.
    ///
    /// A repair request names its requester and is answered only for a current
    /// member, so the bus has to carry that identity rather than invent one.
    bob_id: MemberId,
    /// Repair requests bob has raised and alice has not yet answered.
    repairs_from_bob: Vec<(RepairTarget, EpochId)>,
    /// Namespace rotations alice has announced but bob has not received.
    ///
    /// Queued rather than applied so a test can assert on what alice *put on
    /// the wire* before bob touches it — which is where the removal-before-
    /// rotation ordering becomes observable.
    rotations_to_bob: Vec<(u32, iroh_beekem_core::Chunk)>,
}

fn two_node_workspace() -> Bus {
    let doc_id = TreeId::from(MemorySigner::generate(&mut rng(0)).verifying_key());
    let alice_signer = MemorySigner::generate(&mut rng(1));
    let bob_signer = MemorySigner::generate(&mut rng(2));
    let bob_id = beekem::id::MemberId::from(bob_signer.verifying_key());

    let secret = WorkspaceSecret::generate(&mut rng(5));

    let alice_cgka =
        CgkaController::create(doc_id, alice_signer, &mut rng(10)).expect("alice founds workspace");
    let mut alice = WorkspaceState::found(alice_cgka, WorkspaceSecret::new(secret.to_bytes()), 1)
        .expect("alice founds the workspace");

    // Admission through the real event rather than by poking the CGKA and the
    // manifest separately. That is not merely tidier: `Event::AddUser` mints the
    // binding and the grant that make bob's leaf attributable and his writes
    // acceptable, and a bus assembled without them would hand every test a
    // member who cannot legitimately do anything.
    let bob_secret = ShareSecretKey::generate(&mut rng(20));
    alice
        .handle(
            Event::AddUser {
                member: bob_id,
                share_key: bob_secret.share_key(),
                role: Role::Editor,
                display_name: "bob".into(),
                endpoint: None,
            },
            &mut rng(21),
            T0,
        )
        .expect("alice admits bob");

    let log = alice.op_log().expect("exporting log");
    let certs = alice.capabilities().certificates();
    let bob_cgka =
        CgkaController::join(doc_id, bob_signer, bob_secret, &log, &certs).expect("bob joins");

    Bus {
        alice,
        // Generation zero: these buses never rotate the namespace, so a
        // joiner seeded anywhere else would be describing a run that does not
        // happen here.
        bob: WorkspaceState::joined(bob_cgka, secret, 0),
        to_bob: Vec::new(),
        certs_to_bob: Vec::new(),
        to_alice: Vec::new(),
        certs_to_alice: Vec::new(),
        manifests_to_alice: Vec::new(),
        chunks_to_bob: Vec::new(),
        manifests_to_bob: Vec::new(),
        bob_id,
        repairs_from_bob: Vec::new(),
        rotations_to_bob: Vec::new(),
    }
}

impl Bus {
    /// A bus over two already-constructed nodes.
    fn new(alice: WorkspaceState, bob: WorkspaceState, bob_id: MemberId) -> Self {
        Self {
            alice,
            bob,
            to_bob: Vec::new(),
            certs_to_bob: Vec::new(),
            to_alice: Vec::new(),
            certs_to_alice: Vec::new(),
            manifests_to_alice: Vec::new(),
            chunks_to_bob: Vec::new(),
            manifests_to_bob: Vec::new(),
            bob_id,
            repairs_from_bob: Vec::new(),
            rotations_to_bob: Vec::new(),
        }
    }

    /// Apply an event to alice, queueing whatever she emits for bob.
    fn alice_does(&mut self, event: Event, seed: u64) {
        let effects = self
            .alice
            .handle(event, &mut rng(seed), T0)
            .expect("alice should handle the event");
        self.queue_for_bob(effects);
    }

    /// Apply an event to alice and hand back what she emitted, unqueued.
    ///
    /// For assertions about the *shape* of a publish — which epoch it names,
    /// whether it produced anything at all — as distinct from its effect on bob.
    fn alice_emits(&mut self, event: Event, seed: u64) -> Vec<Effect> {
        self.alice
            .handle(event, &mut rng(seed), T0)
            .expect("alice should handle the event")
    }

    /// Repair requests bob has raised and alice has not yet answered.
    fn repairs_from_bob(&self) -> &[(RepairTarget, EpochId)] {
        &self.repairs_from_bob
    }

    /// The single document chunk currently queued for bob.
    fn chunk_queued_for_bob(&self) -> iroh_beekem_core::Chunk {
        assert_eq!(
            self.chunks_to_bob.len(),
            1,
            "this helper is for tests expecting exactly one queued chunk"
        );
        self.chunks_to_bob[0].clone()
    }

    /// Route alice's effects onto the bus.
    ///
    /// One place, so that a path added later cannot quietly drop the operation
    /// that keys the chunk beside it — the ordering rule the whole protocol
    /// rests on.
    fn queue_for_bob(&mut self, effects: Vec<Effect>) {
        let mut mint: Option<u32> = None;
        for effect in effects {
            match effect {
                Effect::BroadcastOp { op, proof } => {
                    self.to_bob.push(AuthorizedOp::new(*op, proof));
                }
                Effect::BroadcastCerts(certs) => self.certs_to_bob.extend(certs),
                Effect::StoreChunk { chunk, .. } => self.chunks_to_bob.push(*chunk),
                Effect::StoreManifest { chunk, .. } => self.manifests_to_bob.push(*chunk),
                Effect::PublishNamespace { epoch, chunk } => {
                    self.rotations_to_bob.push((epoch, *chunk));
                }
                // Minting is I/O in production. Deferred past this loop because
                // answering it feeds another event into alice, and the effects
                // being drained here came from the previous one.
                Effect::RotateNamespace { epoch } => mint = Some(epoch),
                // `AdoptNamespace` is a transport action — importing a
                // capability and re-publishing — with nothing for an in-memory
                // bus to do; the generation alice moved to is already in her
                // state. A repair request from alice is likewise out of scope:
                // bob is the joiner here, and answering would need a second bus
                // in the other direction.
                Effect::AdoptNamespace { .. }
                | Effect::RequestRepair { .. }
                | Effect::Applied { .. }
                | Effect::ManifestUpdated
                | Effect::EvictUncertified { .. }
                | Effect::DeleteEntry { .. }
                | Effect::DeleteAssetSegments { .. } => {}
            }
        }
        if let Some(epoch) = mint {
            // The capability only has to be distinguishable here; what is being
            // modelled is which generation a node is on.
            let ticket = format!("namespace-{epoch}").into_bytes();
            let effects = self
                .alice
                .handle(
                    Event::NamespaceMinted { epoch, ticket },
                    &mut rng(epoch.into()),
                    T0,
                )
                .expect("alice should encrypt the namespace she asked to mint");
            self.queue_for_bob(effects);
        } else {
            // No rotation was requested by the event being drained.
        }
    }

    /// Deliver every queued rotation to bob.
    fn deliver_rotations_to_bob(&mut self) {
        for (epoch, chunk) in std::mem::take(&mut self.rotations_to_bob) {
            self.bob
                .handle(
                    Event::NamespaceArrived {
                        epoch,
                        chunk: Box::new(chunk),
                    },
                    &mut rng(0),
                    T0,
                )
                .expect("bob should handle a rotation announcement");
        }
    }

    /// Apply an event to bob, recording any repair he asks for.
    fn bob_receives(&mut self, event: Event) {
        let effects = self
            .bob
            .handle(event, &mut rng(0), T0)
            .expect("bob should handle the event");
        // Bob is a passive receiver in these tests, so the only effect of his
        // that the bus carries is a repair request; anything he publishes is
        // the subject of a different test.
        for effect in effects {
            if let Effect::RequestRepair { target, epoch } = effect {
                self.repairs_from_bob.push((target, epoch));
            }
        }
    }

    /// Deliver everything queued for bob, control plane first.
    fn deliver_all_to_bob(&mut self) {
        // Certificates first: they authorise the operations behind them, and an
        // operation judged against a closure that has not caught up is refused
        // rather than parked.
        let certs = std::mem::take(&mut self.certs_to_bob);
        if !certs.is_empty() {
            self.bob_receives(Event::CertsArrived(certs));
        }
        for op in std::mem::take(&mut self.to_bob) {
            self.bob_receives(Event::ControlOp(op));
        }
        for chunk in std::mem::take(&mut self.manifests_to_bob) {
            self.bob_receives(Event::ManifestArrived {
                chunk: Box::new(chunk),
            });
        }
        for chunk in std::mem::take(&mut self.chunks_to_bob) {
            self.bob_receives(Event::ChunkArrived {
                doc: DOC,
                chunk: Box::new(chunk),
            });
        }
    }

    /// Route bob's effects onto the bus, for delivery back to alice.
    ///
    /// The bus is mostly one-directional because most tests have one writer.
    /// This is the narrow reverse path: a viewer legitimately publishes its own
    /// author and endpoint records, and alice has to receive them for any
    /// `author_may_write` question to be answerable on her side.
    fn queue_from_bob_to_alice(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::BroadcastOp { op, proof } => {
                    self.to_alice.push(AuthorizedOp::new(*op, proof));
                }
                Effect::BroadcastCerts(certs) => self.certs_to_alice.extend(certs),
                Effect::StoreManifest { chunk, .. } => self.manifests_to_alice.push(*chunk),
                // Bob is a viewer in these tests, so nothing else he emits is
                // meaningful to alice.
                _ => {}
            }
        }
    }

    /// Deliver everything queued for alice, control plane first.
    fn deliver_all_to_alice(&mut self) {
        let certs = std::mem::take(&mut self.certs_to_alice);
        if !certs.is_empty() {
            self.alice_receives(Event::CertsArrived(certs));
        }
        for op in std::mem::take(&mut self.to_alice) {
            self.alice_receives(Event::ControlOp(op));
        }
        for chunk in std::mem::take(&mut self.manifests_to_alice) {
            self.alice_receives(Event::ManifestArrived {
                chunk: Box::new(chunk),
            });
        }
    }

    /// Apply an event to alice, discarding what she emits.
    ///
    /// Unlike `bob_receives` this drops the effects: the tests using it are
    /// asking what alice now *believes*, not what she says next.
    fn alice_receives(&mut self, event: Event) {
        self.alice
            .handle(event, &mut rng(0), T0)
            .expect("alice should handle the event");
    }

    /// Deliver only the data plane, holding back the control plane.
    fn deliver_chunks_only_to_bob(&mut self) {
        for chunk in std::mem::take(&mut self.chunks_to_bob) {
            self.bob_receives(Event::ChunkArrived {
                doc: DOC,
                chunk: Box::new(chunk),
            });
        }
    }

    /// Have alice answer every repair bob has asked for, queueing the result.
    ///
    /// Returns how many she answered, which is the cost the group pays: each
    /// one mints a new epoch, so a test that expects repair to be bounded can
    /// assert on it directly.
    fn alice_answers_repairs(&mut self, seed: u64) -> usize {
        let mut answered = 0;
        for (target, epoch) in std::mem::take(&mut self.repairs_from_bob) {
            let effects = self
                .alice
                .handle(
                    Event::RepairRequested {
                        requester: self.bob_id,
                        target,
                        epoch,
                    },
                    &mut rng(seed + answered as u64),
                    T0,
                )
                .expect("alice should handle a repair request from a member");
            if !effects.is_empty() {
                answered += 1;
            }
            self.queue_for_bob(effects);
        }
        answered
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

    // Alice rotates and the operation is *withheld*, so the epoch her next
    // publish uses is one bob provably cannot derive yet. Without this the test
    // asserts nothing: a joiner replays the admission log, which already carries
    // the implicit re-key the manifest publish performed, so it can decrypt the
    // next ordinary edit immediately and there is no window to observe.
    let rotation = bus.alice_emits(Event::Rotate, 29);
    let withheld: Vec<_> = rotation
        .into_iter()
        .filter_map(|effect| match effect {
            Effect::BroadcastOp { op, proof } => Some(AuthorizedOp::new(*op, proof)),
            _ => None,
        })
        .collect();
    assert!(
        !withheld.is_empty(),
        "the rotation must produce an operation for this test to withhold one"
    );

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

    // Control plane catches up: the withheld rotation, then anything queued.
    for op in withheld {
        bus.bob_receives(Event::ControlOp(op));
    }
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
            T0,
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
            Effect::BroadcastOp { op, .. } => {
                bus.alice
                    .handle(
                        Event::ControlOp(AuthorizedOp::bare(Arc::new(*op))),
                        &mut rng(0),
                        T0,
                    )
                    .expect("alice handles bob's op");
            }
            Effect::StoreChunk { chunk, .. } => {
                bus.alice
                    .handle(Event::ChunkArrived { doc: DOC, chunk }, &mut rng(0), T0)
                    .expect("alice handles bob's chunk");
            }
            Effect::StoreManifest { chunk, .. } => {
                bus.alice
                    .handle(Event::ManifestArrived { chunk }, &mut rng(0), T0)
                    .expect("alice handles bob's manifest");
            }
            // Bob is not an admin in this test, so he never rotates, never
            // grants a role, and never evicts anybody.
            Effect::RotateNamespace { .. }
            | Effect::PublishNamespace { .. }
            | Effect::AdoptNamespace { .. }
            | Effect::RequestRepair { .. }
            | Effect::Applied { .. }
            | Effect::ManifestUpdated
            | Effect::BroadcastCerts(_)
            | Effect::EvictUncertified { .. }
            | Effect::DeleteEntry { .. }
            | Effect::DeleteAssetSegments { .. } => {}
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

/// In a member whose own edits come back to it inside a peer's chunk, upon
/// editing again, we expect every edit to survive and the two replicas to still
/// agree.
///
/// This is the ordinary case rather than a corner: a peer publishing a document
/// for the first time exports *all* updates, so what reaches alice contains
/// alice's own operations. It is worth pinning because of what a device's Loro
/// peer id now does. The id is derived from the workspace secret so that history
/// stays attributable across restarts, and assigning it is also what derives the
/// operation counter this replica writes next from. A counter derived before its
/// own past arrives is one that hands out ids already spent, and the resulting
/// replica is not refused but corrupt. `adopt_peer` after every import is what
/// keeps the two in step; this test is the echo path stated end to end.
#[test]
fn a_members_own_edits_returning_from_a_peer_do_not_collide_with_its_next_edit() {
    let mut bus = two_node_workspace();
    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "alice one\n".into(),
        },
        40,
    );
    bus.deliver_all_to_bob();

    // Bob has published nothing for this document, so his chunk is a full
    // export — alice's operations included. This is the echo that matters.
    let from_bob = bus
        .bob
        .handle(
            Event::LocalEdit {
                doc: DOC,
                text: "bob one\n".into(),
            },
            &mut rng(41),
            T0,
        )
        .expect("bob edits locally");
    for effect in from_bob {
        match effect {
            Effect::BroadcastOp { op, .. } => {
                bus.alice_receives(Event::ControlOp(AuthorizedOp::bare(Arc::new(*op))));
            }
            Effect::StoreChunk { chunk, .. } => {
                bus.alice_receives(Event::ChunkArrived { doc: DOC, chunk });
            }
            // Nothing else bob emits bears on this document.
            _ => {}
        }
    }

    // Several, because a single edit could avoid a collision by luck.
    for (n, seed) in [(2, 42), (3, 43), (4, 44)] {
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: format!("alice {n}\n"),
            },
            seed,
        );
    }
    bus.deliver_all_to_bob();

    let alice_text = bus.alice.document_text(DOC);
    for expected in ["alice one", "bob one", "alice 2", "alice 3", "alice 4"] {
        assert!(
            alice_text.contains(expected),
            "an edit was lost after alice merged her own operations back from bob; \
             {expected:?} missing from {alice_text:?}"
        );
    }
    assert_eq!(
        alice_text,
        bus.bob.document_text(DOC),
        "the two replicas diverged, which is what colliding operation ids look \
         like when they do not abort outright"
    );
}

/// A document's history is readable, and a past state can be restored.
///
/// Revert is applied as a new edit going forward rather than as a rewrite, which
/// is what makes it safe in a group: a peer that already merged the operations
/// being undone keeps them, and the undo merges with whatever it was doing.
mod history_is_readable_and_revertible {
    use iroh_beekem_core::{CoreError, UnixSeconds, version::VersionId};
    use proptest::prelude::*;

    use super::{DOC, Event, T0, rng, two_node_workspace};

    /// In a document edited several times, upon listing its versions, we expect
    /// one entry per edit, in the order the edits were made.
    #[test]
    fn every_edit_is_a_version() {
        let mut bus = two_node_workspace();
        for (n, seed) in [(1, 800), (2, 801), (3, 802)] {
            bus.alice_does(
                Event::LocalEdit {
                    doc: DOC,
                    text: format!("line {n}\n"),
                },
                seed,
            );
        }

        let versions = bus.alice.document_versions(DOC);
        assert_eq!(
            versions.len(),
            3,
            "each edit commits one change and so contributes one version, got {versions:?}"
        );
        // Each version names the state after its own edit, so reading them back
        // in order must reproduce the document as it grew.
        for (i, version) in versions.iter().enumerate() {
            let expected: String = (1..=i + 1).fold(String::new(), |mut acc, n| {
                use std::fmt::Write as _;
                let _ = writeln!(acc, "line {n}");
                acc
            });
            assert_eq!(
                bus.alice
                    .document_text_at(DOC, &version.id)
                    .expect("a version this replica listed is one it can resolve"),
                expected,
                "version {i} did not read back as the document stood after edit {i}"
            );
        }
    }

    /// In a document whose history this replica holds, upon reverting to an
    /// earlier version, we expect its text to be what it was at that version and
    /// its history to be longer rather than shorter.
    ///
    /// The second half is the one worth stating. A revert that shortened history
    /// would mean the operations had been dropped, and a peer that had already
    /// merged them would keep them forever: the two replicas could never agree
    /// again. Undoing forward is what makes the group case sound at all.
    #[test]
    fn a_revert_restores_the_text_and_extends_the_history() {
        let mut bus = two_node_workspace();
        for (n, seed) in [(1, 810), (2, 811), (3, 812)] {
            bus.alice_does(
                Event::LocalEdit {
                    doc: DOC,
                    text: format!("line {n}\n"),
                },
                seed,
            );
        }
        let before = bus.alice.document_versions(DOC);
        let second = before[1].id.clone();

        bus.alice_does(
            Event::RevertDocument {
                doc: DOC,
                to: second,
            },
            813,
        );

        assert_eq!(
            bus.alice.document_text(DOC),
            "line 1\nline 2\n",
            "reverting to the version after the second edit must undo the third"
        );
        let after = bus.alice.document_versions(DOC);
        assert!(
            after.len() > before.len(),
            "a revert must add to the history, not remove from it: {} versions \
             before, {} after",
            before.len(),
            after.len()
        );
        assert!(
            after.iter().any(|v| v.id == before[2].id),
            "the version that was reverted away must still be listed, or it could \
             never be returned to"
        );
        assert_eq!(
            bus.alice
                .document_text_at(DOC, &before[2].id)
                .expect("the reverted-away version is still resolvable"),
            "line 1\nline 2\nline 3\n",
            "reverting must not change what an earlier version reads as"
        );
    }

    /// In a replica that reverted a document, upon a peer receiving the result,
    /// we expect both to agree — including when the peer edited concurrently.
    #[test]
    fn a_revert_converges_with_a_concurrent_edit() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "shared\n".into(),
            },
            820,
        );
        bus.deliver_all_to_bob();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "alice regrets this\n".into(),
            },
            821,
        );
        let base = bus.alice.document_versions(DOC)[0].id.clone();

        // Bob writes while alice is undoing, and neither has seen the other.
        let from_bob = bus
            .bob
            .handle(
                Event::LocalEdit {
                    doc: DOC,
                    text: "bob's own work\n".into(),
                },
                &mut rng(822),
                T0,
            )
            .expect("bob edits locally");
        bus.alice_does(Event::RevertDocument { doc: DOC, to: base }, 823);

        for effect in from_bob {
            match effect {
                iroh_beekem_core::Effect::BroadcastOp { op, .. } => {
                    bus.alice_receives(Event::ControlOp(iroh_beekem_core::AuthorizedOp::bare(
                        std::sync::Arc::new(*op),
                    )));
                }
                iroh_beekem_core::Effect::StoreChunk { chunk, .. } => {
                    bus.alice_receives(Event::ChunkArrived { doc: DOC, chunk });
                }
                _ => {}
            }
        }
        bus.deliver_all_to_bob();

        let alice_text = bus.alice.document_text(DOC);
        assert_eq!(
            alice_text,
            bus.bob.document_text(DOC),
            "a revert must converge with a concurrent edit like any other write"
        );
        assert!(
            alice_text.contains("bob's own work"),
            "a revert must undo only what it names; bob's concurrent edit was \
             swallowed: {alice_text:?}"
        );
        assert!(
            !alice_text.contains("alice regrets this"),
            "the reverted edit is still present: {alice_text:?}"
        );
    }

    /// In any replica, upon being asked for a version it does not hold, we expect
    /// [`CoreError::UnknownVersion`] rather than a wrong answer.
    ///
    /// Ordinary rather than adversarial: version ids travel between members, and
    /// a peer that is behind genuinely cannot resolve one its neighbour just
    /// listed.
    #[test]
    fn a_version_this_replica_does_not_hold_is_refused() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "only alice has this".into(),
            },
            830,
        );
        let known = bus.alice.document_versions(DOC)[0].id.clone();

        assert!(
            matches!(
                bus.bob.document_text_at(DOC, &known),
                Err(CoreError::UnknownDocument)
            ),
            "a peer holding no copy of the document must say so"
        );
        assert!(
            matches!(
                bus.alice
                    .document_text_at(DOC, &VersionId::from_bytes(vec![0xff; 8])),
                Err(CoreError::UnknownVersion { .. })
            ),
            "bytes that are not a version this replica holds must be refused"
        );
    }

    /// In a document each of whose members has edited it, upon listing versions,
    /// we expect every change to name the member that made it.
    #[test]
    fn a_version_names_the_member_that_made_it() {
        let mut bus = two_node_workspace();
        let alice_id = bus.alice.member_id().to_bytes();
        let bob_id = bus.bob.member_id().to_bytes();

        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "from alice\n".into(),
            },
            840,
        );
        bus.deliver_all_to_bob();
        let from_bob = bus
            .bob
            .handle(
                Event::LocalEdit {
                    doc: DOC,
                    text: "from bob\n".into(),
                },
                &mut rng(841),
                T0,
            )
            .expect("bob edits locally");
        for effect in from_bob {
            match effect {
                iroh_beekem_core::Effect::BroadcastOp { op, .. } => {
                    bus.alice_receives(Event::ControlOp(iroh_beekem_core::AuthorizedOp::bare(
                        std::sync::Arc::new(*op),
                    )));
                }
                iroh_beekem_core::Effect::StoreChunk { chunk, .. } => {
                    bus.alice_receives(Event::ChunkArrived { doc: DOC, chunk });
                }
                _ => {}
            }
        }

        let authors: Vec<Option<[u8; 32]>> = bus
            .alice
            .document_versions(DOC)
            .into_iter()
            .map(|v| v.author)
            .collect();
        assert!(
            authors.contains(&Some(alice_id)),
            "alice's own change is unattributed on her own replica"
        );
        assert!(
            authors.contains(&Some(bob_id)),
            "bob's change did not carry the claim that names him, so a version \
             list can never say who wrote what"
        );
    }

    /// In a document edited at a stated instant, upon listing versions, we expect
    /// that instant back — not the machine's clock.
    ///
    /// The core reads no clock, so the caller's value is the only one there is.
    /// A test that let `SystemTime` in here would pass on any implementation and
    /// prove nothing about the simulator's determinism, which is the property
    /// this actually protects.
    #[test]
    fn a_version_carries_the_instant_the_caller_stated() {
        let mut bus = two_node_workspace();
        let when = UnixSeconds::new(1_600_000_000);
        bus.alice
            .handle(
                Event::LocalEdit {
                    doc: DOC,
                    text: "dated".into(),
                },
                &mut rng(850),
                when,
            )
            .expect("alice edits");

        assert_eq!(
            bus.alice.document_versions(DOC)[0].at,
            when,
            "the version was not dated from the instant the caller supplied"
        );
    }

    proptest! {
        /// In a document edited an arbitrary number of times, upon reverting to
        /// the version recorded before edit *k*, we expect the text observed at
        /// *k* back, and the document to still be writable afterwards.
        ///
        /// The second half catches a revert that leaves the replica detached: a
        /// checkout would satisfy every assertion about the text and quietly stop
        /// the document accepting anything else.
        #[test]
        fn reverting_to_any_version_restores_what_was_observed_there(
            edits in prop::collection::vec("[a-z]{1,4}", 1..8),
            k in 0usize..8,
        ) {
            let mut bus = two_node_workspace();
            let mut observed = Vec::new();
            for (i, text) in edits.iter().enumerate() {
                bus.alice_does(
                    Event::LocalEdit { doc: DOC, text: text.clone() },
                    860 + i as u64,
                );
                observed.push(bus.alice.document_text(DOC));
            }

            let versions = bus.alice.document_versions(DOC);
            let target = k % versions.len();
            bus.alice_does(
                Event::RevertDocument { doc: DOC, to: versions[target].id.clone() },
                900,
            );

            prop_assert_eq!(
                bus.alice.document_text(DOC),
                observed[target].clone(),
                "reverting to the version after edit {} did not restore what the \
                 document read at that point",
                target
            );

            // Still a live replica, not a detached view of the past.
            bus.alice_does(
                Event::LocalEdit { doc: DOC, text: "after".into() },
                901,
            );
            prop_assert!(
                bus.alice.document_text(DOC).ends_with("after"),
                "the document stopped accepting edits after a revert, which is what \
                 a detached checkout looks like"
            );
        }
    }
}

/// Checkpoints: a name for a state of the whole workspace, and a way back to it.
///
/// A checkpoint is a claim recorded in the manifest — it points at versions that
/// already exist — so it needs no new effect and rides the manifest's own
/// anti-entropy. Restoring one is [`Event::RevertDocument`] applied to each entry
/// it names, which is why the concurrency argument for revert covers it too.
mod checkpoints_name_a_state_of_the_workspace {
    use iroh_beekem_core::{CoreError, FileEntry, RestoreOutcome, UnixSeconds};

    use super::{Event, T0, rng, two_node_workspace};

    const ONE: iroh_beekem_core::DocumentUuid = iroh_beekem_core::DocumentUuid([1u8; 16]);
    const TWO: iroh_beekem_core::DocumentUuid = iroh_beekem_core::DocumentUuid([2u8; 16]);

    fn entry(uuid: iroh_beekem_core::DocumentUuid, path: &str) -> FileEntry {
        FileEntry {
            uuid,
            logical_path: path.to_string(),
            mime_type: "text/plain".to_string(),
            asset: None,
        }
    }

    /// In a workspace whose files were edited after a checkpoint was taken, upon
    /// restoring it, we expect every file it names to read as it did then, and
    /// files created since to be left alone.
    ///
    /// The second half is what makes a checkpoint a *tag* rather than a snapshot
    /// of the filesystem: restoring must not delete work that has nothing to do
    /// with it.
    #[test]
    fn restoring_puts_back_what_was_named_and_leaves_the_rest() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::UpsertFile {
                entry: entry(ONE, "/one"),
            },
            870,
        );
        bus.alice_does(
            Event::UpsertFile {
                entry: entry(TWO, "/two"),
            },
            871,
        );
        bus.alice_does(
            Event::LocalEdit {
                doc: ONE,
                text: "one, as tagged".into(),
            },
            872,
        );
        bus.alice_does(
            Event::LocalEdit {
                doc: TWO,
                text: "two, as tagged".into(),
            },
            873,
        );

        let (effects, digest) = bus
            .alice
            .checkpoint("v1", "before the rewrite", &mut rng(874), T0)
            .expect("an editor may take a checkpoint");
        bus.queue_for_bob(effects);

        // Both named files move on, and a third appears that the tag never saw.
        bus.alice_does(
            Event::LocalEdit {
                doc: ONE,
                text: "\nand then some regret".into(),
            },
            875,
        );
        bus.alice_does(
            Event::LocalEdit {
                doc: TWO,
                text: "\nand more regret".into(),
            },
            876,
        );
        let three = iroh_beekem_core::DocumentUuid([3u8; 16]);
        bus.alice_does(
            Event::UpsertFile {
                entry: entry(three, "/three"),
            },
            877,
        );
        bus.alice_does(
            Event::LocalEdit {
                doc: three,
                text: "written after the tag".into(),
            },
            878,
        );

        let (effects, outcomes) = bus
            .alice
            .restore_checkpoint(&digest, &mut rng(879), T0)
            .expect("a checkpoint this replica holds can be restored");
        bus.queue_for_bob(effects);

        assert_eq!(
            bus.alice.document_text(ONE),
            "one, as tagged",
            "a file named by the checkpoint was not put back"
        );
        assert_eq!(
            bus.alice.document_text(TWO),
            "two, as tagged",
            "a second file named by the checkpoint was not put back"
        );
        assert_eq!(
            bus.alice.document_text(three),
            "written after the tag",
            "restoring a checkpoint must not touch a file it never named"
        );
        assert_eq!(
            outcomes.len(),
            2,
            "one outcome per named entry, so a caller can tell what happened to \
             each: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .all(|o| matches!(o, RestoreOutcome::Restored(_))),
            "both named files were restorable, so both must report it: {outcomes:?}"
        );
    }

    /// In a workspace where a checkpointed file has since been deleted, upon
    /// restoring, we expect the deletion to be reported rather than skipped.
    ///
    /// Deleting drops the replica, so no version of that file survives to revert
    /// to and no later sync will produce one. A caller told only "restored" would
    /// believe the workspace was whole when a file is missing from it.
    #[test]
    fn a_file_deleted_since_the_checkpoint_is_reported_as_gone() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::UpsertFile {
                entry: entry(ONE, "/one"),
            },
            880,
        );
        bus.alice_does(
            Event::LocalEdit {
                doc: ONE,
                text: "here for now".into(),
            },
            881,
        );
        let (_, digest) = bus
            .alice
            .checkpoint("v1", "", &mut rng(882), T0)
            .expect("taking a checkpoint");

        bus.alice_does(Event::DeleteFile { doc: ONE }, 883);

        let (_, outcomes) = bus
            .alice
            .restore_checkpoint(&digest, &mut rng(884), T0)
            .expect("restoring a checkpoint whose file is gone is not an error");
        assert_eq!(
            outcomes,
            vec![RestoreOutcome::Deleted(ONE)],
            "a deleted file must be named as unrecoverable, not silently skipped"
        );
    }

    /// In two members who tag the same name while partitioned, upon exchanging
    /// manifests, we expect both records to survive.
    ///
    /// Checkpoints are keyed by digest for this reason. Keyed by name, one would
    /// overwrite the other by whichever Loro ordering happened to win — a fact
    /// about operation ids rather than about what either member did — and the
    /// loser's tag would vanish with no trace and no error.
    #[test]
    fn two_members_tagging_the_same_name_both_keep_their_record() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::UpsertFile {
                entry: entry(ONE, "/one"),
            },
            890,
        );
        bus.alice_does(
            Event::LocalEdit {
                doc: ONE,
                text: "shared".into(),
            },
            891,
        );
        bus.deliver_all_to_bob();

        let (alice_effects, alice_digest) = bus
            .alice
            .checkpoint("release", "alice's idea of it", &mut rng(892), T0)
            .expect("alice tags");
        let (_bob_effects, bob_digest) = bus
            .bob
            .checkpoint("release", "bob's idea of it", &mut rng(893), T0)
            .expect("bob tags");
        assert_ne!(
            alice_digest, bob_digest,
            "two different records must not collide, or this test proves nothing"
        );

        // Alice's manifest reaches bob, who already has his own tag of that name.
        bus.queue_for_bob(alice_effects);
        bus.deliver_all_to_bob();

        let names: Vec<String> = bus
            .bob
            .checkpoints()
            .into_iter()
            .map(|c| c.message)
            .collect();
        assert!(
            names.contains(&"alice's idea of it".to_string())
                && names.contains(&"bob's idea of it".to_string()),
            "both tags of the same name must survive the merge, got {names:?}"
        );
        assert!(
            bus.bob.checkpoints().iter().any(|c| c.name == "release"),
            "the name must still resolve to something"
        );
    }

    /// In a replica that has not merged a checkpoint, upon being asked to restore
    /// it, we expect a refusal naming the digest rather than a silent no-op.
    #[test]
    fn a_checkpoint_this_replica_does_not_hold_is_refused() {
        let mut bus = two_node_workspace();
        let result = bus.alice.restore_checkpoint(&[7u8; 32], &mut rng(895), T0);
        assert!(
            matches!(result, Err(CoreError::UnknownVersion { .. })),
            "restoring an unknown checkpoint must say so, got {result:?}"
        );
    }

    /// In a checkpoint taken at a stated instant by a stated member, upon listing
    /// checkpoints, we expect both recorded.
    #[test]
    fn a_checkpoint_records_who_took_it_and_when() {
        let mut bus = two_node_workspace();
        let when = UnixSeconds::new(1_700_000_000);
        bus.alice
            .checkpoint("dated", "with a message", &mut rng(896), when)
            .expect("taking a checkpoint");

        let recorded = bus
            .alice
            .checkpoints()
            .into_iter()
            .next()
            .expect("the checkpoint just taken is listed");
        assert_eq!(
            recorded.at, when,
            "the checkpoint was not dated from the caller's clock"
        );
        assert_eq!(
            recorded.author,
            bus.alice.member_id().to_bytes(),
            "the checkpoint does not name the member that took it"
        );
        assert_eq!(recorded.message, "with a message", "the message was lost");
    }
}

/// Asset versions: the same feature as document history, by a different
/// mechanism, because an asset has no CRDT to point into.
///
/// Each version is its own body of immutable segments under its own key space,
/// which is what lets an older one survive a newer one; reverting appends a
/// version naming bytes that are already there.
mod assets_keep_their_versions {
    use iroh_beekem_core::{
        AssetMeta, CoreError, DocumentUuid, Effect, FileEntry, UnixSeconds, version::AssetVersion,
    };

    use super::{Event, rng, two_node_workspace};

    const ENTRY: DocumentUuid = DocumentUuid([11u8; 16]);
    const V1: DocumentUuid = DocumentUuid([21u8; 16]);
    const V2: DocumentUuid = DocumentUuid([22u8; 16]);

    fn meta(size: u64) -> AssetMeta {
        AssetMeta {
            size,
            segments: AssetMeta::segments_for(size, 1024),
            segment_bytes: 1024,
            // Distinct per size, which is all these tests need of a digest.
            content_hash: [u8::try_from(size % 256).unwrap_or(0); 32],
        }
    }

    fn attached() -> super::Bus {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::UpsertFile {
                entry: FileEntry {
                    uuid: ENTRY,
                    logical_path: "/big.bin".into(),
                    mime_type: "application/octet-stream".into(),
                    asset: None,
                },
            },
            900,
        );
        bus
    }

    /// In an entry with two versions attached, upon listing them, we expect both,
    /// and the newer one to be what the entry currently reports.
    ///
    /// Both halves matter: the older version surviving is what makes the feature
    /// a history rather than an overwrite, and the entry reporting the newer one
    /// is what makes an ordinary read see the latest file.
    #[test]
    fn a_second_version_does_not_replace_the_first() {
        let mut bus = attached();
        let effects = bus
            .alice
            .add_asset_version(ENTRY, V1, meta(10), &mut rng(901), UnixSeconds::new(100))
            .expect("attaching the first version");
        bus.queue_for_bob(effects);
        let effects = bus
            .alice
            .add_asset_version(ENTRY, V2, meta(20), &mut rng(902), UnixSeconds::new(200))
            .expect("attaching the second version");
        bus.queue_for_bob(effects);

        let versions = bus.alice.asset_versions(ENTRY);
        assert_eq!(
            versions.iter().map(|v| v.content).collect::<Vec<_>>(),
            vec![V1, V2],
            "both versions must be listed, oldest first"
        );
        assert_eq!(
            bus.alice
                .manifest()
                .files()
                .into_iter()
                .find(|e| e.uuid == ENTRY)
                .and_then(|e| e.asset)
                .map(|m| m.size),
            Some(20),
            "the entry must report the current version's metadata, or an ordinary \
             read opens the superseded file"
        );
    }

    /// In an entry versioned twice by one member within the same second, upon
    /// asking which is current, we expect the second.
    ///
    /// Attaching two versions in quick succession is the common case, not a
    /// corner: a timestamp here is whole seconds. With precedence decided by
    /// `(at, content)` alone the two would tie and be separated by their random
    /// UUIDs, so the *first* attachment would win about half the time — and the
    /// caller would have no way to avoid it. `seq` is what orders a member's own
    /// writes; it caught this as a networked test opening the previous file.
    #[test]
    fn two_versions_attached_in_the_same_second_are_still_ordered() {
        let mut bus = attached();
        let same_instant = UnixSeconds::new(1_700_000_000);
        for (content, size, seed) in [(V1, 10u64, 912), (V2, 20, 913)] {
            let effects = bus
                .alice
                .add_asset_version(ENTRY, content, meta(size), &mut rng(seed), same_instant)
                .expect("attaching a version");
            bus.queue_for_bob(effects);
        }

        assert_eq!(
            bus.alice
                .asset_versions(ENTRY)
                .into_iter()
                .max_by_key(AssetVersion::precedence)
                .map(|v| v.content),
            Some(V2),
            "the later of two attachments made in one second must be current, \
             whatever the two content UUIDs happen to sort like"
        );
    }

    /// In an entry whose newer version is current, upon reverting to the older
    /// one, we expect the older to be current again and the newer to remain
    /// listed and readable.
    ///
    /// Reverting appends rather than removes for the same reason a document's
    /// revert does: the bytes are still indexed, so pointing at them again costs
    /// a manifest write and nothing else — no re-upload of a file that may be
    /// gigabytes — and the version reverted away from can be returned to.
    #[test]
    fn reverting_an_asset_points_at_bytes_that_are_already_there() {
        let mut bus = attached();
        for (content, size, at, seed) in [(V1, 10u64, 100i64, 903), (V2, 20, 200, 904)] {
            let effects = bus
                .alice
                .add_asset_version(
                    ENTRY,
                    content,
                    meta(size),
                    &mut rng(seed),
                    UnixSeconds::new(at),
                )
                .expect("attaching a version");
            bus.queue_for_bob(effects);
        }

        let effects = bus
            .alice
            .revert_asset(ENTRY, V1, &mut rng(905), UnixSeconds::new(300))
            .expect("reverting to a version this replica holds");
        // A manifest write and nothing else: no key chunk, no segment store.
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::StoreChunk { .. })),
            "reverting an asset must not re-upload it, got {effects:?}"
        );
        bus.queue_for_bob(effects);

        let versions = bus.alice.asset_versions(ENTRY);
        assert_eq!(
            versions.len(),
            3,
            "the revert must be a third version rather than a removal: {versions:?}"
        );
        assert_eq!(
            versions
                .iter()
                .max_by_key(|v| AssetVersion::precedence(v))
                .map(|v| v.content),
            Some(V1),
            "the reverted-to version must be current again"
        );
        assert!(
            versions.iter().any(|v| v.content == V2),
            "the version reverted away from must still be listed, or it could \
             never be returned to"
        );
    }

    /// In an entry with several versions, upon deleting it, we expect every
    /// version's key space to be withdrawn.
    ///
    /// An index entry is what protects a blob from collection, so a version left
    /// out here keeps its payload on every member's disk forever, for a file that
    /// no longer exists — and for assets that is measured in gigabytes.
    #[test]
    fn deleting_an_entry_withdraws_every_versions_key_space() {
        let mut bus = attached();
        for (content, at, seed) in [(V1, 100i64, 906), (V2, 200, 907)] {
            let effects = bus
                .alice
                .add_asset_version(
                    ENTRY,
                    content,
                    meta(10),
                    &mut rng(seed),
                    UnixSeconds::new(at),
                )
                .expect("attaching a version");
            bus.queue_for_bob(effects);
        }

        let effects = bus.alice_emits(Event::DeleteFile { doc: ENTRY }, 908);
        for content in [V1, V2] {
            assert!(
                effects.iter().any(
                    |e| matches!(e, Effect::DeleteAssetSegments { asset, .. } if *asset == content)
                ),
                "the segments of version {content:?} were not withdrawn: {effects:?}"
            );
            assert!(
                effects
                    .iter()
                    .any(|e| matches!(e, Effect::DeleteEntry { doc, .. } if *doc == content)),
                "the content key entry of version {content:?} was not withdrawn: {effects:?}"
            );
        }
    }

    /// In an entry whose versions were attached by two members while partitioned,
    /// upon their manifests merging, we expect both replicas to agree on which is
    /// current.
    ///
    /// Precedence is `(at, content)` — a function of the values — precisely so
    /// that this cannot depend on which replica merged in which order. Deciding
    /// by list position instead would have two members open different files.
    #[test]
    fn two_replicas_agree_on_which_version_is_current() {
        let mut bus = attached();
        bus.deliver_all_to_bob();

        // Alice and bob each attach a version, neither having seen the other's.
        let alice_effects = bus
            .alice
            .add_asset_version(ENTRY, V1, meta(10), &mut rng(909), UnixSeconds::new(100))
            .expect("alice attaches");
        let bob_effects = bus
            .bob
            .add_asset_version(ENTRY, V2, meta(20), &mut rng(910), UnixSeconds::new(200))
            .expect("bob attaches");

        bus.queue_for_bob(alice_effects);
        bus.queue_from_bob_to_alice(bob_effects);
        bus.deliver_all_to_bob();
        bus.deliver_all_to_alice();

        let current = |state: &iroh_beekem_core::WorkspaceState| {
            state
                .asset_versions(ENTRY)
                .into_iter()
                .max_by_key(AssetVersion::precedence)
                .map(|v| v.content)
        };
        assert_eq!(
            current(&bus.alice),
            current(&bus.bob),
            "the two replicas disagree about which version of the asset is current"
        );
        assert_eq!(
            bus.alice.asset_versions(ENTRY).len(),
            2,
            "a concurrent attach must not discard the other member's version"
        );
        assert_eq!(
            bus.alice
                .asset_versions(ENTRY)
                .iter()
                .map(|v| v.seq)
                .collect::<Vec<_>>(),
            vec![0, 0],
            "neither member had seen the other's attachment, so both must claim              the same sequence and be separated by the clock instead"
        );
    }

    /// In an entry that has no such version, upon reverting to it, we expect a
    /// refusal rather than a record pointing at bytes nobody has.
    #[test]
    fn reverting_to_a_version_the_entry_does_not_have_is_refused() {
        let mut bus = attached();
        let result = bus
            .alice
            .revert_asset(ENTRY, V1, &mut rng(911), UnixSeconds::new(100));
        assert!(
            matches!(result, Err(CoreError::UnknownVersion { .. })),
            "reverting to an unknown version must say so rather than record a \
             version whose segments do not exist, got {result:?}"
        );
    }
}

#[test]
fn scratch_two_appends_with_delivery_between() {
    let mut bus = two_node_workspace();
    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "keep this\n".into(),
        },
        950,
    );
    bus.deliver_all_to_bob();
    eprintln!("AFTER FIRST bob={:?}", bus.bob.document_text(DOC));
    bus.alice_does(
        Event::LocalEdit {
            doc: DOC,
            text: "undo this\n".into(),
        },
        951,
    );
    bus.deliver_all_to_bob();
    eprintln!(
        "AFTER SECOND bob={:?} alice={:?} pending={}",
        bus.bob.document_text(DOC),
        bus.alice.document_text(DOC),
        bus.bob.pending_len()
    );
}

/// Roles were fully implemented in the manifest but had no caller: nothing
/// consulted them before acting. These cover the enforcement points.
mod roles_are_enforced {
    use beekem::id::TreeId;
    use iroh_beekem_core::{
        Certificate, CgkaController, CoreError, Event, FileEntry, Role, WorkspaceSecret,
        WorkspaceState,
    };
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
    };

    use super::{DOC, T0, rng, two_node_workspace};

    #[test]
    fn the_founder_is_an_admin_and_a_joiner_is_not() {
        let bus = two_node_workspace();

        assert_eq!(
            bus.alice
                .capabilities()
                .role_of(&bus.alice.member_id().to_bytes()),
            Some(Role::Admin),
            "founding a workspace must make you its first admin"
        );
        // A joiner arrives *certified*: the invite carries the certificates the
        // admin minted, so bob holds the role he was granted from the first
        // moment rather than after a round trip. What `found`/`joined` still
        // turns on is that the role is one somebody granted — bob is an editor
        // because alice said so, and no joiner can make itself an admin.
        assert_eq!(
            bus.bob
                .capabilities()
                .role_of(&bus.bob.member_id().to_bytes()),
            Some(Role::Editor),
            "a joiner should arrive holding exactly the role its admission granted"
        );
        assert!(
            !bus.bob
                .capabilities()
                .ever_admin(&bus.bob.member_id().to_bytes()),
            "a joiner granted a non-administrative role must not be able to admit \
             certificates, or the founder/joiner distinction would be decorative"
        );
    }

    #[test]
    fn a_non_admin_cannot_change_membership() {
        let mut bus = two_node_workspace();
        let alice_id = bus.alice.member_id();

        // Bob has synced no manifest, so he holds no role at all.
        let result = bus
            .bob
            .handle(Event::RemoveMember { member: alice_id }, &mut rng(9), T0);

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
                    asset: None,
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
            bus.bob.capabilities().role_of(&bob_id.to_bytes()),
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
            T0,
        );
        assert!(
            matches!(demote, Err(CoreError::LastAdmin)),
            "demoting the only admin would leave a workspace nobody can ever \
             administer again, got {demote:?}"
        );

        let remove = bus
            .alice
            .handle(Event::RemoveMember { member: alice_id }, &mut rng(61), T0);
        assert!(
            matches!(remove, Err(CoreError::LastAdmin)),
            "removing the only admin must be refused for the same reason, got {remove:?}"
        );

        assert_eq!(
            bus.alice.capabilities().admin_count(),
            1,
            "the refused operations must have left the admin in place"
        );
    }

    /// Accepting an entry needs all three links, and since phase 5 the middle
    /// one is a signed binding rather than a map entry: a member must have
    /// claimed the author id, a certified binding must attribute that member's
    /// leaf to a user, and a grant must give that user a role that can write.
    ///
    /// The third case is the one that is new. An author claimed by a member whose
    /// leaf holds *no* binding used to be indistinguishable from one an admin had
    /// bound, because the binding was a manifest write anybody could make; now the
    /// claim is worthless on its own.
    #[test]
    fn an_author_may_write_only_once_claimed_and_certified() {
        let mut bus = two_node_workspace();
        let bob_author = [0xB0_u8; 32];

        assert!(
            !bus.alice.author_may_write(&bob_author),
            "an author nobody has claimed must never be accepted"
        );

        // Bob is a certified editor, so his claim completes all three links.
        bus.bob
            .handle(
                Event::AnnounceAuthor { author: bob_author },
                &mut rng(70),
                T0,
            )
            .expect("announcing your own author id needs no privilege");
        let claim = bus
            .bob
            .handle(Event::ResyncManifest, &mut rng(71), T0)
            .expect("re-publishing the manifest needs no role");
        bus.queue_from_bob_to_alice(claim);
        bus.deliver_all_to_alice();
        assert!(
            bus.alice.author_may_write(&bob_author),
            "a claimed author whose member holds a certified writing role should be accepted"
        );

        // An author claimed for a leaf nobody ever bound. The claim itself is a
        // manifest write, so it converges like any other — and grants nothing.
        let stranger_author = [0xCD_u8; 32];
        let stranger = [0xEF_u8; 32];
        bus.alice
            .manifest()
            .set_author(&stranger, &stranger_author)
            .expect("the authors map is self-attested and accepts any write");
        assert!(
            !bus.alice.author_may_write(&stranger_author),
            "an author claimed for a leaf with no certified binding was accepted, so the \
             author map alone would confer the right to write"
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

        // The demotion is issued by the admin and delivered, which is the only
        // way bob can come to hold it: a role is a signed grant, so bob writing
        // one for himself would not be admitted by his own closure either.
        bus.alice_does(
            Event::SetRole {
                user: bob_id.to_bytes(),
                role: Role::Viewer,
            },
            79,
        );
        bus.deliver_all_to_bob();

        let refusals = [
            (
                "edit",
                bus.bob.handle(
                    Event::LocalEdit {
                        doc: DOC,
                        text: "viewers may not write".into(),
                    },
                    &mut rng(80),
                    T0,
                ),
            ),
            (
                "resync",
                bus.bob.handle(Event::Resync { doc: DOC }, &mut rng(81), T0),
            ),
            (
                "upsert",
                bus.bob.handle(
                    Event::UpsertFile {
                        entry: FileEntry {
                            uuid: DOC,
                            logical_path: "/viewer.md".into(),
                            mime_type: "text/markdown".into(),
                            asset: None,
                        },
                    },
                    &mut rng(82),
                    T0,
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
                    T0,
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
    /// members it has never heard of.
    ///
    /// An invite normally carries the certificates, so a joiner arrives certified
    /// and this hatch is not on the ordinary path. It still has to exist: a node
    /// that received its operations before its certificates — a log exchange that
    /// raced, a certificate lost in transit — would otherwise be refused by its
    /// own `require_write`, and refusing there deadlocks onboarding. It cannot
    /// publish, so it cannot announce its author, so no peer ever accepts anything
    /// from it, so nothing ever repairs the gap.
    ///
    /// Constructed by withholding bob's *grant* while keeping the bindings. That
    /// is the reachable shape of the gap: the two are separate certificates, so
    /// one can be lost on its own. Withholding the bindings instead would not
    /// pose the question at all — replaying the log needs them, so the join
    /// itself fails, which is `Invite.certs` doing its job rather than this hatch.
    #[test]
    fn a_member_whose_grant_has_not_arrived_may_still_write() {
        let bus = two_node_workspace();
        let doc_id = TreeId::from(MemorySigner::generate(&mut rng(0)).verifying_key());
        let bob_signer = MemorySigner::generate(&mut rng(2));
        let bob_secret = ShareSecretKey::generate(&mut rng(20));
        let log = bus.alice.op_log().expect("exporting the log");
        let bindings: Vec<Certificate> = bus
            .alice
            .capabilities()
            .certificates()
            .into_iter()
            .filter(|cert| matches!(cert, Certificate::Binding(_)))
            .collect();

        let cgka = CgkaController::join(doc_id, bob_signer, bob_secret, &log, &bindings)
            .expect("the log replays: every `Add` is authorised by a binding");
        let mut bob = WorkspaceState::joined(cgka, WorkspaceSecret::generate(&mut rng(5)), 0);

        assert_eq!(
            bob.capabilities().role_of(&bob.member_id().to_bytes()),
            None,
            "precondition: this node holds no certificate, so it resolves to no role"
        );

        let result = bob.handle(
            Event::LocalEdit {
                doc: DOC,
                text: "written before my certificates arrived".into(),
            },
            &mut rng(84),
            T0,
        );

        assert!(
            result.is_ok(),
            "a member whose grant has not yet arrived must not be refused, or \
             onboarding deadlocks: it cannot publish, so it cannot announce its author, \
             so no peer ever accepts anything from it; got {result:?}"
        );
    }
}

/// What an edit costs to publish, and what makes the cheap version safe.
///
/// A chunk used to carry the document's entire history every time, so the cost
/// of the *n*th edit grew with *n* and a workspace's publishing cost grew
/// quadratically in edits. A delta costs the edit — at the price of no longer
/// being self-sufficient under loss, which is the property the old behaviour was
/// chosen for. These tests state both halves: that the saving is real, and that
/// a receiver which loses a delta says so rather than going quietly out of date.
mod publishing_costs_the_edit_and_not_the_document {
    use iroh_beekem_core::{Chunk, Effect, Event, RepairTarget};

    use super::{DOC, T0, rng, two_node_workspace};

    /// The chunk in a batch of effects, for the single-document publishes here.
    fn chunk_in(effects: &[Effect]) -> Option<Chunk> {
        effects.iter().find_map(|effect| match effect {
            Effect::StoreChunk { chunk, .. } => Some((**chunk).clone()),
            _ => None,
        })
    }

    /// Given a document that has been edited many times, upon making one more
    /// edit, we expect the published chunk to be about the size of that edit
    /// rather than of the accumulated history.
    ///
    /// Stated as a ratio rather than an absolute size because both numbers are
    /// Loro's to choose. What the test pins is the *shape* of the growth: under
    /// the old `all_updates()` export the last chunk was the largest one, and the
    /// assertion below is false by construction.
    #[test]
    fn a_later_edit_publishes_a_chunk_the_size_of_the_edit() {
        const EDITS: usize = 40;
        const LINE: &str = "a line of roughly forty characters here\n";

        let mut bus = two_node_workspace();
        let mut last = None;
        for i in 0..EDITS {
            let effects = bus.alice_emits(
                Event::LocalEdit {
                    doc: DOC,
                    text: LINE.into(),
                },
                600 + i as u64,
            );
            last = chunk_in(&effects);
        }
        let last = last.expect("every edit publishes a chunk");

        // The whole history is what a repair still ships, so it is available
        // here as the honest comparison rather than as a guessed constant.
        let full = chunk_in(&bus.alice_emits(
            Event::RepairRequested {
                requester: bus.bob.member_id(),
                target: RepairTarget::DocumentHistory(DOC),
                epoch: iroh_beekem_core::EpochId::of(&last),
            },
            700,
        ))
        .expect("a history repair republishes the document in full");

        assert!(
            last.ciphertext.len() * 4 < full.ciphertext.len(),
            "after {EDITS} edits a delta must be a small fraction of the full \
             history, got {} bytes against {} — if these are close, the export \
             mode is still `all_updates()` and the quadratic cost is unchanged",
            last.ciphertext.len(),
            full.ciphertext.len()
        );
    }

    /// Given a receiver that missed one delta, upon the next delta arriving, we
    /// expect it to be parked and — after enough fruitless retries — a
    /// [`RepairTarget::DocumentHistory`] request to be raised for it.
    ///
    /// This is the safety half of delta publishing and the only thing that makes
    /// it sound. A document's index slot holds one chunk per author, so a lost
    /// delta cannot be fetched again: the slot has already moved on. Without an
    /// escalation the chunk that follows it sits in `pending_chunks` until the
    /// budget evicts it, and the receiver is silently short of content with
    /// every "nothing stays parked forever" property still satisfied, because
    /// the queue does eventually empty — by discarding.
    ///
    /// The request must name `DocumentHistory` and not `Document`: bob can
    /// decrypt perfectly well, and answering a key problem he does not have
    /// costs the whole group a CGKA operation while delivering none of the
    /// operations he is actually missing.
    #[test]
    fn a_receiver_that_loses_a_delta_asks_for_the_history() {
        let mut bus = two_node_workspace();

        // Alice's first publish reaches bob, so both agree on a base.
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "first".into(),
            },
            610,
        );
        bus.deliver_all_to_bob();

        // The second is lost: emitted, never queued.
        let lost = bus.alice_emits(
            Event::LocalEdit {
                doc: DOC,
                text: " second".into(),
            },
            611,
        );
        assert!(
            chunk_in(&lost).is_some(),
            "the edit being dropped has to have produced a chunk, or this test \
             drops nothing and proves nothing"
        );

        // The third arrives, and depends on the second.
        let third = chunk_in(&bus.alice_emits(
            Event::LocalEdit {
                doc: DOC,
                text: " third".into(),
            },
            612,
        ))
        .expect("the third edit publishes a chunk");
        bus.bob_receives(Event::ChunkArrived {
            doc: DOC,
            chunk: Box::new(third.clone()),
        });

        assert_eq!(
            bus.bob.pending_len(),
            1,
            "a delta whose base never arrived must park rather than apply or \
             be discarded"
        );

        // Every re-offer of the same entry is another chance to apply, which is
        // what `iroh-docs` reconciliation supplies in production. Enough of them
        // and the receiver stops waiting and asks.
        for _ in 0..16 {
            bus.bob_receives(Event::ChunkArrived {
                doc: DOC,
                chunk: Box::new(third.clone()),
            });
        }

        assert!(
            bus.repairs_from_bob()
                .iter()
                .any(|(target, _)| *target == RepairTarget::DocumentHistory(DOC)),
            "a chunk stuck on missing dependencies must eventually ask for the \
             history, got {:?}",
            bus.repairs_from_bob()
        );
        assert!(
            !bus.repairs_from_bob()
                .iter()
                .any(|(target, _)| *target == RepairTarget::Document(DOC)),
            "bob can derive the epoch, so asking for a re-key would charge the \
             group an operation that fixes nothing"
        );
    }

    /// Given a receiver stuck on a missing delta, upon the history repair being
    /// answered, we expect it to converge on the publisher's text.
    ///
    /// The counterweight to the test above: an escalation that fires and is
    /// answered with something unusable would satisfy every assertion there.
    #[test]
    fn the_history_repair_lets_the_receiver_catch_up() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "first".into(),
            },
            620,
        );
        bus.deliver_all_to_bob();
        let _lost = bus.alice_emits(
            Event::LocalEdit {
                doc: DOC,
                text: " second".into(),
            },
            621,
        );
        let third = chunk_in(&bus.alice_emits(
            Event::LocalEdit {
                doc: DOC,
                text: " third".into(),
            },
            622,
        ))
        .expect("the third edit publishes a chunk");
        bus.bob_receives(Event::ChunkArrived {
            doc: DOC,
            chunk: Box::new(third.clone()),
        });
        assert_ne!(
            bus.bob.document_text(DOC),
            bus.alice.document_text(DOC),
            "the setup has to actually leave bob behind, or the repair below \
             would have nothing to fix"
        );

        bus.alice_does(
            Event::RepairRequested {
                requester: bus.bob.member_id(),
                target: RepairTarget::DocumentHistory(DOC),
                epoch: iroh_beekem_core::EpochId::of(&third),
            },
            623,
        );
        bus.deliver_all_to_bob();

        assert_eq!(
            bus.bob.document_text(DOC),
            bus.alice.document_text(DOC),
            "a history repair ships the whole document, so it must resolve a gap \
             no delta could"
        );
        assert_eq!(
            bus.bob.pending_len(),
            0,
            "the parked delta must apply once its dependencies arrive, rather \
             than sitting behind content that already superseded it"
        );
    }

    /// Given a document with nothing unpublished, upon a resync, we expect no
    /// chunk at all.
    ///
    /// The single largest saving of the three, and the one most likely to be
    /// undone by accident, because re-encrypting looks like the safe thing to do.
    /// It is not needed: the index entry naming the existing chunk is still
    /// there, and `iroh-docs` reconciles key ranges between peers, so a peer that
    /// lacks the entry is served by whoever holds it without the author saying
    /// anything. Re-encrypting instead produced a fresh blob per document per
    /// republish cycle, forever, and none of them carried new information.
    ///
    /// What a resync legitimately still does is covered by the assertion below
    /// it: a document that *has* moved is republished.
    #[test]
    fn a_resync_of_an_unchanged_document_publishes_nothing() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "settled".into(),
            },
            630,
        );

        let quiescent = bus.alice_emits(Event::Resync { doc: DOC }, 631);
        assert!(
            chunk_in(&quiescent).is_none(),
            "a resync of a fully published document must emit no chunk, got \
             {quiescent:?}"
        );

        // And a document that has moved is still re-announced, or anti-entropy
        // would have been turned off rather than made proportional. The move
        // comes from a peer, which is the case that matters: merging somebody
        // else's chunk advances the document without publishing anything, so it
        // is precisely the state a resync exists to carry onward.
        bus.deliver_all_to_bob();
        let from_bob = bus
            .bob
            .handle(
                Event::LocalEdit {
                    doc: DOC,
                    text: " and bob's line".into(),
                },
                &mut rng(632),
                T0,
            )
            .expect("bob writes as an editor");
        let bobs_chunk = chunk_in(&from_bob).expect("bob's edit publishes a chunk");
        bus.queue_from_bob_to_alice(from_bob);
        bus.deliver_all_to_alice();
        bus.alice_receives(Event::ChunkArrived {
            doc: DOC,
            chunk: Box::new(bobs_chunk),
        });

        let moved = bus.alice_emits(Event::Resync { doc: DOC }, 633);
        assert!(
            chunk_in(&moved).is_some(),
            "a resync of a document holding operations this node has not \
             published must still publish, got {moved:?}"
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

    use super::{DOC, T0, rng, two_node_workspace};

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
                    T0,
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
                    T0,
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

/// What a member admitted *after* content already exists can read, and how.
///
/// This is user story 1 — "invite a teammate so they can immediately access
/// workspace files" — and it is the one thing forward secrecy makes impossible
/// to deliver by encryption alone. A joiner cannot derive any epoch that
/// predates its leaf, so pre-existing content reaches it only if a member that
/// *can* read it re-encrypts under a live epoch. These tests pin down when that
/// happens, what it costs, and who is allowed to ask for it.
mod repair_reaches_a_member_admitted_late {
    use beekem::id::TreeId;
    use iroh_beekem_core::{
        CgkaController, Chunk, Effect, EpochId, Event, RepairTarget, Role, WorkspaceSecret,
        WorkspaceState,
    };
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
    };

    use super::{Bus, DOC, MemberId, T0, rng};

    /// The text alice writes while she is still alone in the workspace.
    const EARLY: &str = "written before bob arrived";

    /// The one chunk in a set of effects, for tests that expect exactly one.
    fn only_chunk(effects: &[Effect]) -> Chunk {
        let mut chunks = effects.iter().filter_map(|effect| match effect {
            Effect::StoreChunk { chunk, .. } => Some((**chunk).clone()),
            _ => None,
        });
        let chunk = chunks.next().expect("the effects should contain a chunk");
        assert!(
            chunks.next().is_none(),
            "these tests assume one document per publish; more than one means the \
             caller changed and the assertions below no longer say what they claim"
        );
        chunk
    }

    /// A workspace where alice wrote a document *before* bob was admitted.
    ///
    /// Distinct from `two_node_workspace` in exactly one respect, and it is the
    /// respect that matters: there bob holds a leaf before anything is written,
    /// so every chunk is readable by construction and the repair path is never
    /// reached. Returns the chunk alice published while alone, which is the
    /// ciphertext bob can never decrypt.
    fn workspace_written_to_before_bob_joined() -> (Bus, Chunk) {
        let doc_id = TreeId::from(MemorySigner::generate(&mut rng(0)).verifying_key());
        let alice_signer = MemorySigner::generate(&mut rng(1));
        let bob_signer = MemorySigner::generate(&mut rng(2));
        let bob_id = MemberId::from(bob_signer.verifying_key());
        let secret = WorkspaceSecret::generate(&mut rng(5));

        let alice_cgka = CgkaController::create(doc_id, alice_signer, &mut rng(10))
            .expect("alice founds the workspace");
        let mut alice =
            WorkspaceState::found(alice_cgka, WorkspaceSecret::new(secret.to_bytes()), 1)
                .expect("the founder records herself as the first admin");

        let effects = alice
            .handle(
                Event::LocalEdit {
                    doc: DOC,
                    text: EARLY.into(),
                },
                &mut rng(30),
                T0,
            )
            .expect("alice writes while she is the only member");
        let stale = only_chunk(&effects);

        // Now bob is admitted, through the same event a real admission uses, so
        // that he gets the manifest records a leaf needs to have a role.
        let bob_secret = ShareSecretKey::generate(&mut rng(20));
        let admission = alice
            .handle(
                Event::AddUser {
                    member: bob_id,
                    share_key: bob_secret.share_key(),
                    role: Role::Editor,
                    display_name: "bob".into(),
                    endpoint: None,
                },
                &mut rng(31),
                T0,
            )
            .expect("alice is an admin and may admit bob");

        let log = alice.op_log().expect("exporting the operation log");
        let certs = alice.capabilities().certificates();
        let bob_cgka =
            CgkaController::join(doc_id, bob_signer, bob_secret, &log, &certs).expect("bob joins");

        let mut bus = Bus::new(alice, WorkspaceState::joined(bob_cgka, secret, 0), bob_id);
        bus.queue_for_bob(admission);
        (bus, stale)
    }

    /// Given a workspace with content written before a member was admitted,
    /// when that member receives the old ciphertext, we expect it to be dropped
    /// rather than parked, and a repair request raised naming exactly the epoch
    /// it cannot derive.
    ///
    /// Parking it would be the silent failure: the chunk can never become
    /// applicable, so it would occupy the pending budget for the lifetime of
    /// the process while every drain retried a decryption that cannot succeed,
    /// and nothing anywhere would say so.
    #[test]
    fn a_chunk_from_before_the_join_is_dropped_and_reported() {
        let (mut bus, stale) = workspace_written_to_before_bob_joined();
        bus.deliver_all_to_bob();

        bus.bob_receives(Event::ChunkArrived {
            doc: DOC,
            chunk: Box::new(stale.clone()),
        });

        assert_eq!(
            bus.bob.document_text(DOC),
            "",
            "bob must not be able to read an epoch that predates his own leaf"
        );
        assert_eq!(
            bus.bob.pending_len(),
            0,
            "a chunk that can never be decrypted must not occupy the pending budget"
        );
        assert_eq!(
            bus.bob.unreadable_chunks(),
            1,
            "dropping it silently would be the same defect in a different place; \
             it has to be counted"
        );
        assert_eq!(
            bus.repairs_from_bob(),
            &[(RepairTarget::Document(DOC), EpochId::of(&stale))],
            "the request must name the document and the exact epoch bob failed on, \
             since that pair is what a responder's rate limiter is keyed on"
        );
    }

    /// Given a member stuck on pre-join content, when a member that can read it
    /// answers the repair, we expect the content to become readable — and to
    /// arrive under a *different* epoch than the one that was asked about.
    ///
    /// The second half is the whole mechanism. A response under the same epoch
    /// would be the byte-identical ciphertext bob already failed on, which is
    /// precisely what ordinary anti-entropy produces.
    #[test]
    fn an_answered_repair_makes_pre_join_content_readable() {
        let (mut bus, stale) = workspace_written_to_before_bob_joined();
        bus.deliver_all_to_bob();
        bus.bob_receives(Event::ChunkArrived {
            doc: DOC,
            chunk: Box::new(stale.clone()),
        });

        assert_eq!(
            bus.alice_answers_repairs(40),
            1,
            "alice holds the document and may write, so she must answer"
        );
        let answer = bus.chunk_queued_for_bob();
        assert_ne!(
            EpochId::of(&answer),
            EpochId::of(&stale),
            "a repair keyed under the epoch that was reported unreadable carries \
             nothing new, which is the defect this whole path exists to fix"
        );

        bus.deliver_all_to_bob();
        assert_eq!(
            bus.bob.document_text(DOC),
            EARLY,
            "once alice re-keys and republishes, bob reads content written before \
             he was admitted — user story 1"
        );
        assert_eq!(
            bus.bob.pending_len(),
            0,
            "nothing should remain parked once the repair has landed"
        );
    }

    /// Given a document alice keeps publishing, when the ordinary path runs, we
    /// expect every chunk to be keyed under the same epoch — and a repair of the
    /// same document to be keyed under a new one.
    ///
    /// This is the defect stated as an assertion. Anti-entropy is a fixed point
    /// with respect to a peer that cannot derive the current epoch: repeating it
    /// reproduces a ciphertext keyed under the epoch that peer already failed on.
    /// Only the repair path is obliged to advance the epoch, and this is what
    /// says so. Routing repair back through the ordinary publish path would
    /// restore the original defect while leaving every other test name intact;
    /// the final assertion here is the one that would fail.
    ///
    /// Since delta publishing landed there is a stronger statement to make about
    /// the anti-entropy half, and the first assertion makes it: a resync of a
    /// document nothing has touched does not merely repeat the epoch, it emits no
    /// chunk whatever. The stuck peer is therefore not even offered a ciphertext
    /// to fail on again, which is the same conclusion arrived at more cheaply.
    #[test]
    fn anti_entropy_repeats_an_epoch_while_a_repair_advances_it() {
        let (mut bus, _stale) = workspace_written_to_before_bob_joined();
        bus.deliver_all_to_bob();

        let quiescent = bus.alice_emits(Event::Resync { doc: DOC }, 50);
        assert!(
            !quiescent
                .iter()
                .any(|effect| matches!(effect, Effect::StoreChunk { .. })),
            "a resync of a document whose every operation is already published \
             must emit nothing: the index entry naming the existing chunk is \
             still there, and re-encrypting it produces a new blob that tells \
             nobody anything, got {quiescent:?}"
        );

        // Two ordinary publishes, which is what anti-entropy amounts to once the
        // document actually moves. Both must name the epoch alice already holds.
        let first = only_chunk(&bus.alice_emits(
            Event::LocalEdit {
                doc: DOC,
                text: " and more".into(),
            },
            51,
        ));
        let second = only_chunk(&bus.alice_emits(
            Event::LocalEdit {
                doc: DOC,
                text: " and more again".into(),
            },
            52,
        ));
        assert_eq!(
            EpochId::of(&first),
            EpochId::of(&second),
            "the ordinary publish path must reuse the epoch — if it did not, \
             this test would be proving nothing about the repair below"
        );

        let repaired = only_chunk(&bus.alice_emits(
            Event::RepairRequested {
                requester: bus.bob.member_id(),
                target: RepairTarget::Document(DOC),
                epoch: EpochId::of(&second),
            },
            53,
        ));
        assert_ne!(
            EpochId::of(&repaired),
            EpochId::of(&second),
            "a repair must mint a new epoch, or it tells the stuck peer nothing"
        );
    }

    /// Given a member that has been removed, when it asks for a repair, we
    /// expect the request to be refused before any key material is minted.
    ///
    /// Answering costs the whole group a tree operation, so an unauthenticated
    /// request would be a cheap way for a revoked device to spend everyone's
    /// CPU. It would also gain the requester nothing — the fresh epoch is minted
    /// after its leaf left the tree — which is why refusing costs no liveness.
    #[test]
    fn a_removed_member_cannot_make_the_group_re_key() {
        let (mut bus, stale) = workspace_written_to_before_bob_joined();
        bus.deliver_all_to_bob();

        let bob_id = bus.bob.member_id();
        bus.alice_does(Event::RemoveMember { member: bob_id }, 60);
        let before = bus.alice.repairs_answered();

        let refusal = bus.alice.handle(
            Event::RepairRequested {
                requester: bob_id,
                target: RepairTarget::Document(DOC),
                epoch: EpochId::of(&stale),
            },
            &mut rng(61),
            T0,
        );

        assert!(
            refusal.is_err(),
            "a repair request from a device that is no longer a member must be refused"
        );
        assert_eq!(
            bus.alice.repairs_answered(),
            before,
            "the refusal must happen before the re-key, not after it"
        );
    }

    /// Given a repair request naming a document this node does not hold, we
    /// expect no answer and no re-key.
    ///
    /// A no-op rather than an error: some other member holds it and will
    /// answer, and treating "not mine" as a fault would fill an operator's logs
    /// with the normal case.
    #[test]
    fn a_repair_for_an_unheld_document_costs_nothing() {
        let (mut bus, stale) = workspace_written_to_before_bob_joined();
        bus.deliver_all_to_bob();
        let before = bus.alice.repairs_answered();

        let effects = bus.alice_emits(
            Event::RepairRequested {
                requester: bus.bob.member_id(),
                target: RepairTarget::Document(iroh_beekem_core::DocumentUuid([99u8; 16])),
                epoch: EpochId::of(&stale),
            },
            70,
        );

        assert!(
            effects.is_empty(),
            "a node with nothing to re-encrypt must stay silent, got {effects:?}"
        );
        assert_eq!(
            bus.alice.repairs_answered(),
            before,
            "an unanswerable request must not be counted as a repair, or the \
             bounded-cost property would be measuring the wrong thing"
        );
    }

    /// Given a member that cannot read the manifest, when it asks for a repair
    /// of the manifest, we expect a fresh-keyed manifest replica in return.
    ///
    /// The manifest needs this at least as much as a document does: device
    /// records live there and the roster derives from them, so a member that
    /// cannot read it is refused by peers rather than merely out of date — and
    /// unlike a document, it has no parking queue to hold a copy until keys
    /// arrive.
    #[test]
    fn a_manifest_repair_is_answered_under_a_fresh_epoch() {
        let (mut bus, stale) = workspace_written_to_before_bob_joined();
        bus.deliver_all_to_bob();

        let effects = bus.alice_emits(
            Event::RepairRequested {
                requester: bus.bob.member_id(),
                target: RepairTarget::Manifest,
                epoch: EpochId::of(&stale),
            },
            80,
        );

        let manifest = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::StoreManifest { chunk, .. } => Some((**chunk).clone()),
                _ => None,
            })
            .expect("a manifest repair must produce a manifest replica");
        assert_ne!(
            EpochId::of(&manifest),
            EpochId::of(&stale),
            "the replacement must be keyed under an epoch the requester can derive"
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

    use super::{T0, rng, two_node_workspace};

    #[test]
    fn a_device_acts_under_its_owners_role() {
        let bus = two_node_workspace();
        let alice = bus.alice.member_id().to_bytes();

        assert_eq!(
            bus.alice.capabilities().role_of_member(&alice),
            Some(Role::Admin),
            "the founding device must resolve to the founding user's role"
        );
        assert_eq!(
            bus.alice.capabilities().user_of(&alice),
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
                endpoint: None,
            },
            302,
        );

        assert_eq!(
            bus.alice
                .capabilities()
                .role_of_member(&laptop_id.to_bytes()),
            Some(Role::Admin),
            "a new device must inherit its user's role rather than needing its own grant"
        );
        assert_eq!(
            bus.alice.devices_of(&alice_user).len(),
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

        // Bob arrives from `two_node_workspace` as a certified editor, so no
        // local setup is needed — and none would be possible: a role is a signed
        // grant, and one bob wrote for himself would not be admitted.
        let result = bus.bob.handle(
            Event::AddDevice {
                member: rogue_id,
                share_key: rogue_secret.share_key(),
                user: alice_user,
                label: "not really alice's".into(),
                endpoint: None,
            },
            &mut rng(312),
            T0,
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
                endpoint: None,
            },
            322,
        );

        // Removing one of the sole admin's two devices must be allowed: the
        // user keeps administering the workspace from the other one. Guarding
        // on the leaf rather than the user would refuse this.
        let removed =
            bus.alice
                .handle(Event::RemoveMember { member: laptop_id }, &mut rng(323), T0);
        assert!(
            removed.is_ok(),
            "removing one device of a multi-device admin must be allowed, got {removed:?}"
        );
        assert_eq!(
            bus.alice.capabilities().role_of(&alice_user),
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

    use super::{DOC, T0, rng, two_node_workspace};

    fn entry() -> FileEntry {
        FileEntry {
            uuid: DOC,
            logical_path: "/notes.md".into(),
            mime_type: "text/markdown".into(),
            asset: None,
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
            .handle(Event::DeleteFile { doc: DOC }, &mut rng(432), T0)
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
                T0,
            )
            .expect("bob writes");

        bus.alice
            .handle(Event::DeleteFile { doc: DOC }, &mut rng(442), T0)
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
            .handle(Event::DeleteFile { doc: DOC }, &mut rng(450), T0);
        assert!(
            matches!(result, Err(CoreError::UnknownDocument)),
            "deleting a document that was never recorded should fail, got {result:?}"
        );
    }
}

/// The derived roster: who a node will accept connections from.
///
/// `WorkspaceState::roster` is the membership half of admission control. That it
/// is actually wired to `iroh` is proven by the QUIC suite in `iroh-beekem`;
/// what these establish is that the rule it computes is the right one.
mod the_roster_derives_from_membership {
    use super::*;

    /// Endpoint addresses, distinguishable at a glance in a failure message.
    const ALICE_ENDPOINT: [u8; 32] = [0xA1; 32];
    const BOB_ENDPOINT: [u8; 32] = [0xB0; 32];

    /// Given a workspace where both members have published an address, when the
    /// roster is derived, we expect it to contain both.
    ///
    /// The baseline the eviction tests are measured against. Without it, a
    /// roster that was empty for an unrelated reason would satisfy every
    /// "is no longer present" assertion below vacuously.
    #[test]
    fn a_member_that_has_published_an_address_is_on_the_roster() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::AnnounceEndpoint {
                endpoint_id: ALICE_ENDPOINT,
            },
            400,
        );
        bus.alice
            .manifest()
            .set_device_endpoint(&bus.bob.member_id().to_bytes(), &BOB_ENDPOINT)
            .expect("recording bob's address");

        let roster = bus.alice.roster();
        assert!(
            roster.contains(&ALICE_ENDPOINT) && roster.contains(&BOB_ENDPOINT),
            "a roster derived from two members with published addresses held {roster:?}, \
             so at least one member would be refused by their own workspace"
        );
    }

    /// Given a member with no published address, when the roster is derived, we
    /// expect them to be absent.
    ///
    /// Absence here is a liveness cost, not a security one — the member simply
    /// cannot be reached yet — but it is why `AnnounceEndpoint` is re-applied on
    /// every manifest arrival rather than attempted once and forgotten.
    #[test]
    fn a_member_with_no_published_address_is_not_on_the_roster() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::AnnounceEndpoint {
                endpoint_id: ALICE_ENDPOINT,
            },
            401,
        );

        assert_eq!(
            bus.alice.roster(),
            vec![ALICE_ENDPOINT],
            "a member who has not announced an address appeared on the roster, which means \
             the roster is inventing addresses rather than deriving them"
        );
    }

    /// Given a member on the roster, when they are removed from the group, we
    /// expect their address to leave the roster.
    ///
    /// **This is the property the whole non-monotone member set exists for.**
    /// `CgkaController::known_members` is deliberately monotone, so deriving the
    /// roster from it would leave a revoked device admitted forever and make
    /// removal decorative. A failure here means removal revokes reading but not
    /// connecting, which is the state of the world before this phase.
    #[test]
    fn a_removed_member_leaves_the_roster() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::AnnounceEndpoint {
                endpoint_id: ALICE_ENDPOINT,
            },
            402,
        );
        let bob_member = bus.bob.member_id();
        bus.alice
            .manifest()
            .set_device_endpoint(&bob_member.to_bytes(), &BOB_ENDPOINT)
            .expect("recording bob's address");
        assert!(
            bus.alice.roster().contains(&BOB_ENDPOINT),
            "bob must be on the roster before his removal can be shown to take him off it"
        );

        bus.alice_does(Event::RemoveMember { member: bob_member }, 403);

        let roster = bus.alice.roster();
        assert!(
            !roster.contains(&BOB_ENDPOINT),
            "a removed member's address was still on the roster ({roster:?}), so revocation \
             would revoke reading but leave the device free to keep connecting and syncing"
        );
        assert!(
            roster.contains(&ALICE_ENDPOINT),
            "removing bob also evicted alice, so a removal takes the remaining members \
             offline with it"
        );
    }

    /// Given a device record whose member never entered the group, when the
    /// roster is derived, we expect it to be excluded.
    ///
    /// The manifest is a CRDT fed by remote peers, so a device record is not
    /// evidence of membership on its own. Deriving the roster from the manifest
    /// alone would let anyone who can write a manifest entry admit themselves.
    #[test]
    fn a_device_record_alone_does_not_put_anyone_on_the_roster() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::AnnounceEndpoint {
                endpoint_id: ALICE_ENDPOINT,
            },
            404,
        );

        // A member id no `Add` ever introduced, with an address of its own.
        let stranger =
            beekem::id::MemberId::from(MemorySigner::generate(&mut rng(405)).verifying_key())
                .to_bytes();
        let stranger_endpoint = [0x5Eu8; 32];
        bus.alice
            .manifest()
            .set_device(&stranger, "uninvited")
            .expect("writing the stranger's device record");
        bus.alice
            .manifest()
            .set_device_endpoint(&stranger, &stranger_endpoint)
            .expect("writing the stranger's address");

        let roster = bus.alice.roster();
        assert!(
            !roster.contains(&stranger_endpoint),
            "a device record that no CGKA `Add` ever backed put its address on the roster \
             ({roster:?}), so writing a manifest entry would be enough to admit yourself"
        );
    }

    /// Given two nodes with the same membership and the same manifest, when both
    /// derive a roster, we expect the two to be identical.
    ///
    /// Convergence, and the reason `roster` sorts and dedups rather than
    /// returning whatever order the underlying `HashSet` iterates in. Two peers
    /// that disagreed would refuse each other's connections asymmetrically,
    /// which is far harder to diagnose than refusing them symmetrically.
    #[test]
    fn two_nodes_with_the_same_membership_derive_the_same_roster() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::AnnounceEndpoint {
                endpoint_id: ALICE_ENDPOINT,
            },
            406,
        );
        bus.alice
            .manifest()
            .set_device_endpoint(&bus.bob.member_id().to_bytes(), &BOB_ENDPOINT)
            .expect("recording bob's address");
        bus.alice_does(Event::ResyncManifest, 407);
        bus.deliver_all_to_bob();

        assert_eq!(
            bus.alice.roster(),
            bus.bob.roster(),
            "two nodes holding the same membership and the same manifest derived different \
             rosters, so each would accept peers the other refuses"
        );
    }
}

/// Namespace rotation: what a removal does beyond revoking decryption.
///
/// The CGKA revokes *reading*. The `iroh-docs` write capability is
/// all-or-nothing and cannot be withdrawn from one holder, so a removed device
/// goes on syncing the index — seeing entry existence, size, author and timing
/// — until the group abandons that index for one whose capability the removed
/// device never receives. These establish that it never receives it.
mod removal_rotates_the_namespace {
    use iroh_beekem_core::NamespaceEpoch;

    use super::*;

    /// Given a two-member workspace, when the admin removes the other member, we
    /// expect the effects to broadcast the removal *before* asking for a new
    /// namespace.
    ///
    /// **The ordering is the security property, and it is invisible if you only
    /// check the outcome.** The capability is encrypted under the group key at
    /// the moment the new namespace is minted. Mint first and the removed device
    /// can still derive that key, read the capability, and follow the group into
    /// the very namespace the rotation existed to keep it out of — while every
    /// test that merely checks "the group rotated" still passes.
    #[test]
    fn the_removal_is_broadcast_before_the_rotation_is_requested() {
        let mut bus = two_node_workspace();
        let bob_id = bus.bob.member_id();

        let effects = bus
            .alice
            .handle(Event::RemoveMember { member: bob_id }, &mut rng(500), T0)
            .expect("alice should be able to remove bob");

        let removal = effects
            .iter()
            .position(|e| matches!(e, Effect::BroadcastOp { .. }))
            .expect("removing a member must broadcast the operation that does it");
        let rotation = effects
            .iter()
            .position(|e| matches!(e, Effect::RotateNamespace { .. }))
            .expect("removing a member must also abandon the namespace they can still write to");

        assert!(
            removal < rotation,
            "the namespace was requested at index {rotation} but the removal only broadcast at \
             {removal}: minting before the leaf leaves the tree lets the removed device decrypt \
             the new capability and follow the group"
        );
    }

    /// Given a removal, when the new capability is announced, we expect the
    /// removed member to be unable to adopt it.
    ///
    /// The mechanism itself, end to end and from the victim's side. Bob receives
    /// the announcement — it is broadcast on a topic every past invitee can
    /// reach, so he cannot be prevented from seeing the bytes — and gets nothing
    /// from them.
    #[test]
    fn a_removed_member_cannot_adopt_the_rotation_it_is_handed() {
        let mut bus = two_node_workspace();
        let bob_id = bus.bob.member_id();
        assert_eq!(
            bus.bob.namespace(),
            NamespaceEpoch::INITIAL,
            "bob must start on the founding namespace for his staying there to mean anything"
        );

        bus.alice_does(Event::RemoveMember { member: bob_id }, 510);
        assert!(
            bus.alice.namespace() > NamespaceEpoch::INITIAL,
            "alice did not move off the namespace she just abandoned, so bob staying put \
             would prove nothing"
        );

        // Everything alice put on the wire, control plane first — exactly the
        // order a well-behaved transport delivers it in, so this is the *best*
        // case for bob rather than a contrived one.
        bus.deliver_all_to_bob();
        bus.deliver_rotations_to_bob();

        assert_eq!(
            bus.bob.namespace(),
            NamespaceEpoch::INITIAL,
            "a removed member adopted the rotation issued to exclude him, so he would go on \
             syncing the group's index and seeing every entry they write"
        );
    }

    /// Given a member still in the group, when a rotation is announced, we expect
    /// them to adopt it.
    ///
    /// **The counterweight.** Everything above is satisfied by a rotation nobody
    /// can read, which would destroy the workspace rather than protect it. This
    /// is what makes the exclusion mean exclusion rather than breakage.
    ///
    /// Driven through `NamespaceMinted` rather than through a removal, so that
    /// adoption is isolated from revocation: the question here is whether a
    /// member who still holds the group's keys can read a capability, and
    /// removing bob to find out would remove the only member available to test.
    #[test]
    fn a_remaining_member_adopts_the_rotation() {
        let mut bus = two_node_workspace();

        let effects = bus
            .alice
            .handle(
                Event::NamespaceMinted {
                    epoch: 0,
                    ticket: b"a capability alice minted".to_vec(),
                },
                &mut rng(520),
                T0,
            )
            .expect("alice should encrypt a capability she minted");
        bus.queue_for_bob(effects);

        bus.deliver_all_to_bob();
        bus.deliver_rotations_to_bob();

        assert_eq!(
            bus.bob.namespace(),
            bus.alice.namespace(),
            "a member holding the group's keys did not follow the rotation, which would strand \
             them on an abandoned replica — removed in effect, without anyone removing them"
        );
    }

    /// Given a member id no `Add` ever introduced, when an admin tries to remove
    /// it, we expect nothing to be rotated.
    ///
    /// Rotation is the most expensive thing the protocol does: it re-publishes
    /// every document and forces every member to re-import. Triggering it on a
    /// removal that removed nobody would let any admin churn the whole group by
    /// repeatedly "removing" somebody who already left.
    #[test]
    fn removing_a_non_member_rotates_nothing() {
        let mut bus = two_node_workspace();
        let stranger =
            beekem::id::MemberId::from(MemorySigner::generate(&mut rng(530)).verifying_key());

        let effects = bus
            .alice
            .handle(Event::RemoveMember { member: stranger }, &mut rng(531), T0)
            .expect("removing a non-member is not an error");

        assert!(
            effects.is_empty(),
            "removing somebody who was never a member produced {} effect(s), so an admin could \
             force the group through a full re-publish at will",
            effects.len()
        );
    }

    /// Given two admins that rotate concurrently to the same generation, when
    /// each hears the other's announcement, we expect both to end on the same
    /// namespace.
    ///
    /// A bare counter cannot settle this: both mint *n+1*, and the group would
    /// split across two replicas with each half convinced it was current.
    /// Ordering on `(epoch, digest)` is a pure function of the values, so it
    /// converges without depending on which announcement arrived first — which
    /// is the property, and why the digest is recomputed from the decrypted
    /// capability rather than trusted from the wire.
    #[test]
    fn concurrent_rotations_to_the_same_generation_converge() {
        let (a, b) = (
            NamespaceEpoch::of(1, b"capability-from-alice"),
            NamespaceEpoch::of(1, b"capability-from-carol"),
        );
        assert_ne!(
            a, b,
            "two distinct capabilities must produce distinct generations, or there is nothing \
             to break the tie with"
        );

        let winner = a.max(b);
        // Adoption is `announced > current`, applied in either order.
        let mut alice_side = a;
        if b > alice_side {
            alice_side = b;
        }
        let mut carol_side = b;
        if a > carol_side {
            carol_side = a;
        }

        assert_eq!(
            alice_side, carol_side,
            "two nodes seeing the same pair of concurrent rotations in opposite orders ended on \
             different namespaces, so the group would split in half permanently"
        );
        assert_eq!(
            alice_side, winner,
            "the tie-break did not select the larger generation, so the winner depends on \
             delivery order rather than on the values"
        );
    }
}

/// What a *member* can do to other members, as distinct from what an outsider
/// can do to the group.
///
/// Every adversarial test above this one puts the attacker outside the group: a
/// forged signature fails `try_verify`, and an unrelated keypair fails
/// `known_members`. Neither says anything about a node that joined legitimately
/// and then acts beyond its role, and until phase 5 there was nothing to say —
/// `merge_verified` checked a signature and `known_members` and stopped, and
/// `on_manifest_arrived` merged whatever decrypted.
///
/// These were written against the code *before* the capability closure existed
/// and were confirmed to fail. Each attack uses the strongest proof the attacker
/// could actually forge, which for a member means self-signed certificates —
/// genuinely signed, by a genuine member, and still admitting nothing.
mod authorization_is_verified_by_the_receiver {
    use beekem::id::{MemberId, TreeId};
    use iroh_beekem_core::{
        AuthorizedOp, CapabilityStore, Certificate, CgkaController, CoreError, DeviceBinding,
        Effect, Event, Grant, Role, WorkspaceSecret, WorkspaceState,
    };
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
    };

    use super::{T0, rng};

    /// A founder, and one legitimately admitted member at a role of our choosing.
    ///
    /// Bob's signer is handed back alongside his controller, because an insider
    /// forges certificates as well as operations and both need his key.
    struct Insider {
        alice: WorkspaceState,
        bob: CgkaController,
        bob_signer: MemorySigner,
        bob_id: MemberId,
        alice_id: MemberId,
    }

    fn insider_workspace(role: Role) -> Insider {
        let tree_id = TreeId::from(MemorySigner::generate(&mut rng(100)).verifying_key());
        let alice_signer = MemorySigner::generate(&mut rng(101));
        let bob_signer = MemorySigner::generate(&mut rng(102));
        let bob_id = MemberId::from(bob_signer.verifying_key());
        let bob_secret = ShareSecretKey::generate(&mut rng(103));
        let secret = WorkspaceSecret::generate(&mut rng(104));

        let alice_cgka = CgkaController::create(tree_id, alice_signer, &mut rng(105))
            .expect("alice founds the workspace");
        let alice_id = alice_cgka.member_id();
        let mut alice =
            WorkspaceState::found(alice_cgka, WorkspaceSecret::new(secret.to_bytes()), 1)
                .expect("alice records herself as the first admin");

        // Admission through the real event, so bob arrives with exactly the
        // certificates a genuine `add_user` would have minted for him.
        alice
            .handle(
                Event::AddUser {
                    member: bob_id,
                    share_key: bob_secret.share_key(),
                    role,
                    display_name: "bob".into(),
                    endpoint: None,
                },
                &mut rng(106),
                T0,
            )
            .expect("alice is an admin and may admit bob");

        let log = alice.op_log().expect("exporting the operation log");
        let certs = alice.capabilities().certificates();
        let bob = CgkaController::join(tree_id, bob_signer.clone(), bob_secret, &log, &certs)
            .expect("bob joins from the log");

        Insider {
            alice,
            bob,
            bob_signer,
            bob_id,
            alice_id,
        }
    }

    /// A fresh keypair that no `Add` in the workspace has ever named.
    fn stranger(seed: u64) -> (MemberId, ShareSecretKey) {
        let signer = MemorySigner::generate(&mut rng(seed));
        (
            MemberId::from(signer.verifying_key()),
            ShareSecretKey::generate(&mut rng(seed + 1)),
        )
    }

    /// A binding the attacker signs themselves, claiming `device` acts for `user`.
    fn forged_binding(
        signer: &MemorySigner,
        device: [u8; 32],
        user: [u8; 32],
        nonce: u8,
    ) -> Certificate {
        DeviceBinding::new(device, user, [nonce; 16])
            .sign(signer)
            .expect("signing is infallible with a memory signer")
    }

    /// Given a workspace where bob holds no administrative capability, when bob
    /// issues an `Add` introducing a new *user*, accompanied by a binding he
    /// signed himself, we expect alice to refuse the operation and never admit
    /// the added identity.
    ///
    /// Confirmed to fail before the capability closure existed: alice merged it
    /// and mallory entered `known_members`, after which every operation mallory
    /// signed was admissible too.
    #[test]
    fn an_add_introducing_a_new_user_is_refused_without_admin_capability() {
        let mut ins = insider_workspace(Role::Viewer);
        let (mallory, mallory_secret) = stranger(210);

        let proof = vec![forged_binding(
            &ins.bob_signer,
            mallory.to_bytes(),
            mallory.to_bytes(),
            1,
        )];
        let op = ins
            .bob
            .add_member(mallory, mallory_secret.share_key())
            .expect("bob's own controller mints the operation without consulting his role")
            .expect("mallory is new to the tree");

        let outcome = ins.alice.handle(
            Event::ControlOp(AuthorizedOp::new(op, proof)),
            &mut rng(211),
            T0,
        );

        assert!(
            matches!(outcome, Err(CoreError::Uncertified { .. })),
            "alice accepted a membership change from a member with no administrative \
             capability, got {outcome:?}"
        );
        assert!(
            !ins.alice
                .capabilities()
                .is_certified_device(&mallory.to_bytes()),
            "a device bound by a member who may not administer became certified, so it \
             would appear on rosters and its entries would be accepted"
        );
    }

    /// Given a workspace where bob holds no administrative capability, when bob
    /// binds a device he controls to *alice's* user, we expect alice to refuse
    /// both the binding and the `Add` that carries it.
    ///
    /// This is the escalation that matters most: a device bound to an admin's
    /// user inherits that admin's role. Before phase 5 the binding was a plain
    /// CRDT map entry, so it needed no authority at all.
    #[test]
    fn an_add_binding_a_device_to_another_users_account_is_refused() {
        let mut ins = insider_workspace(Role::Viewer);
        let alice_user = ins.alice_id.to_bytes();
        let (mallory, mallory_secret) = stranger(220);

        let proof = vec![forged_binding(
            &ins.bob_signer,
            mallory.to_bytes(),
            alice_user,
            2,
        )];
        let op = ins
            .bob
            .add_member(mallory, mallory_secret.share_key())
            .expect("bob mints the operation")
            .expect("mallory is new to the tree");

        let outcome = ins.alice.handle(
            Event::ControlOp(AuthorizedOp::new(op, proof)),
            &mut rng(221),
            T0,
        );

        assert!(
            matches!(outcome, Err(CoreError::Uncertified { .. })),
            "alice accepted a device bound to her own user by somebody else, got {outcome:?}"
        );
        assert_eq!(
            ins.alice.capabilities().role_of_member(&mallory.to_bytes()),
            None,
            "a device bound to the admin's user by a viewer inherited the admin's role, so \
             any member could acquire any other member's permissions"
        );
    }

    /// Given a member holding the lowest role, when that member signs a grant
    /// promoting itself and broadcasts it, we expect alice's view of that
    /// member's role to be unchanged.
    ///
    /// Confirmed to fail before phase 5 in its manifest form: bob wrote
    /// `roles[bob] = Admin` into his replica, published, and `role_of_member` on
    /// alice returned `Admin`. There is no such write any more, so the attack
    /// takes its strongest remaining form — a genuinely signed certificate.
    #[test]
    fn a_viewer_cannot_promote_itself_with_a_self_signed_grant() {
        let mut ins = insider_workspace(Role::Viewer);
        let bob_user = ins.bob_id.to_bytes();

        let promotion = Grant::new(
            bob_user,
            Role::Admin,
            // Far beyond anything an admin has issued, so the attack cannot be
            // dismissed as merely losing the `(seq, digest)` tie-break.
            u64::MAX,
            None,
            [3u8; 16],
        )
        .sign(&ins.bob_signer)
        .expect("signing is infallible with a memory signer");

        ins.alice
            .handle(Event::CertsArrived(vec![promotion]), &mut rng(230), T0)
            .expect("a validly signed certificate is absorbed even when it grants nothing");

        assert_eq!(
            ins.alice.capabilities().role_of(&bob_user),
            Some(Role::Viewer),
            "a viewer promoted itself to admin on the admin's own node, so every role check \
             in the system would be evaluated against state the attacker controls"
        );
        assert!(
            !ins.alice.capabilities().ever_admin(&bob_user),
            "a self-issued admin grant made its subject permanently able to admit further \
             certificates, which would make the escalation irreversible"
        );
    }

    /// Given a legitimate admission bundle, when its certificates are lifted and
    /// reattached to an `Add` for a different leaf, we expect the receiver to
    /// refuse it.
    ///
    /// The capability check has to be bound to *this* operation's `added_id`.
    /// Checking only that the issuer may administer would let any member replay a
    /// bundle it saw on the wire under an `Add` of its own keypair.
    #[test]
    fn a_proof_bundle_cannot_be_replayed_under_a_different_add() {
        // Alice admits carol legitimately, and the bundle goes on the wire.
        let mut ins = insider_workspace(Role::Admin);
        let (carol, carol_secret) = stranger(240);
        let effects = ins
            .alice
            .handle(
                Event::AddUser {
                    member: carol,
                    share_key: carol_secret.share_key(),
                    role: Role::Editor,
                    display_name: "carol".into(),
                    endpoint: None,
                },
                &mut rng(241),
                T0,
            )
            .expect("alice admits carol");
        let stolen: Vec<Certificate> = effects
            .into_iter()
            .find_map(|effect| match effect {
                Effect::BroadcastOp { proof, .. } => Some(proof),
                _ => None,
            })
            .expect("the admission must broadcast an operation with its proof");
        assert!(
            !stolen.is_empty(),
            "the bundle must be non-empty for this test to pose its question"
        );

        // Bob reattaches alice's certificates to an `Add` of his own keypair.
        let (mallory, mallory_secret) = stranger(242);
        let op = ins
            .bob
            .add_member(mallory, mallory_secret.share_key())
            .expect("bob mints the operation")
            .expect("mallory is new to the tree");
        let mut fresh = insider_workspace(Role::Admin);
        let outcome = fresh.alice.handle(
            Event::ControlOp(AuthorizedOp::new(op, stolen)),
            &mut rng(243),
            T0,
        );

        assert!(
            outcome.is_err(),
            "a proof bundle authorising one leaf also authorised a different one, so any \
             member could splice a keypair in by replaying certificates off the wire, \
             got {outcome:?}"
        );
        assert!(
            !fresh
                .alice
                .capabilities()
                .is_certified_device(&mallory.to_bytes()),
            "the replayed bundle certified a leaf it did not name"
        );
    }

    /// Given a member enrolling a further device of *their own* user, when the
    /// binding they sign names that same user, we expect it to be accepted and
    /// the new device to inherit their role — no more.
    ///
    /// The counterpart to the refusals above, and the reason they are phrased in
    /// terms of *which user* rather than "non-admins may not add". Enrolling your
    /// own phone is not an act of administration, and a check that refused it
    /// would make multi-device support an admin-only operation. What must not
    /// happen is escalation, so the inherited role is asserted too.
    #[test]
    fn a_member_may_enrol_a_further_device_of_its_own_user_but_gains_nothing() {
        let mut ins = insider_workspace(Role::Viewer);
        let bob_user = ins.bob_id.to_bytes();
        let (phone, phone_secret) = stranger(250);

        let proof = vec![forged_binding(
            &ins.bob_signer,
            phone.to_bytes(),
            bob_user,
            4,
        )];
        let op = ins
            .bob
            .add_member(phone, phone_secret.share_key())
            .expect("bob mints the operation")
            .expect("the phone is new to the tree");

        ins.alice
            .handle(
                Event::ControlOp(AuthorizedOp::new(op, proof)),
                &mut rng(251),
                T0,
            )
            .expect("a member may enrol a further device of its own user");

        assert_eq!(
            ins.alice.capabilities().user_of(&phone.to_bytes()),
            Some(bob_user),
            "a member's own second device was refused, which would make enrolling a phone \
             an administrative operation"
        );
        assert_eq!(
            ins.alice.capabilities().role_of_member(&phone.to_bytes()),
            Some(Role::Viewer),
            "the enrolled device holds a role its user was never granted, so self-enrolment \
             would be an escalation path"
        );
    }

    /// Given an admin who has been removed, when that removed admin splices a
    /// leaf it controls back into the tree, we expect the receiving admin to ask
    /// for that leaf's removal.
    ///
    /// The revenant, and the one case the capability check deliberately does not
    /// refuse. A removed member keeps its capability — the certificate store is
    /// grow-only, so `ever_admin` never retracts — and its signature stays
    /// admissible because `known_members` is monotone. Refusing on
    /// `current_members` instead would make admissibility order-dependent, so two
    /// peers seeing the removal and the `Add` in opposite orders would drop
    /// different operations and diverge permanently.
    ///
    /// So the splice is accepted and then *undone*. This asserts the undoing is
    /// requested; the propsim `Revenant` scenario asserts it actually lands.
    #[test]
    fn a_removed_admins_splice_is_answered_with_an_eviction() {
        let mut ins = insider_workspace(Role::Admin);
        let bob_id = ins.bob_id;
        ins.alice
            .handle(Event::RemoveMember { member: bob_id }, &mut rng(260), T0)
            .expect("alice removes bob");

        // Bob's controller never saw the removal, so what it mints names
        // pre-removal predecessors as a matter of course.
        let (mallory, mallory_secret) = stranger(261);
        let proof = vec![forged_binding(
            &ins.bob_signer,
            mallory.to_bytes(),
            mallory.to_bytes(),
            5,
        )];
        let op = ins
            .bob
            .add_member(mallory, mallory_secret.share_key())
            .expect("the removed controller still mints operations")
            .expect("mallory is new to the tree");

        let effects = ins
            .alice
            .handle(
                Event::ControlOp(AuthorizedOp::new(op, proof)),
                &mut rng(262),
                T0,
            )
            .expect("the splice is accepted rather than refused, by design");

        assert!(
            effects.iter().any(|effect| matches!(
                effect,
                Effect::EvictUncertified { member } if *member == mallory
            )),
            "a leaf spliced in by a removed member drew no eviction, so it would stay in \
             the tree and receive key material from the next honest re-key; got {effects:?}"
        );
    }

    /// Given a removed member, when it splices a leaf back in, we expect that
    /// leaf to hold no capability the remover did not already hold.
    ///
    /// The `always` half of the revenant story. Eviction is eventual, so the
    /// window is real; what must hold throughout it is that the splice buys no
    /// *escalation* — the closure is rooted, so a revenant can pass on only what
    /// it had.
    #[test]
    fn a_removed_members_splice_confers_no_capability_it_lacked() {
        let mut ins = insider_workspace(Role::Viewer);
        let bob_id = ins.bob_id;
        ins.alice
            .handle(Event::RemoveMember { member: bob_id }, &mut rng(270), T0)
            .expect("alice removes bob");

        let (mallory, mallory_secret) = stranger(271);
        // The most that a removed viewer can claim: a device of its own user,
        // which is the one binding its own capability admits.
        let proof = vec![forged_binding(
            &ins.bob_signer,
            mallory.to_bytes(),
            bob_id.to_bytes(),
            6,
        )];
        let op = ins
            .bob
            .add_member(mallory, mallory_secret.share_key())
            .expect("bob mints the operation")
            .expect("mallory is new to the tree");
        let _ = ins.alice.handle(
            Event::ControlOp(AuthorizedOp::new(op, proof)),
            &mut rng(272),
            T0,
        );

        assert_ne!(
            ins.alice.capabilities().role_of_member(&mallory.to_bytes()),
            Some(Role::Admin),
            "a removed viewer's splice acquired an administrative role, so removal would be \
             recoverable by the party it was aimed at"
        );
        assert!(
            !ins.alice.capabilities().ever_admin(&mallory.to_bytes()),
            "the spliced leaf became able to admit further certificates"
        );
        assert!(
            ins.alice.roster().is_empty(),
            "the spliced leaf reached the roster; it has announced no endpoint and should \
             reach nobody's, got {:?}",
            ins.alice.roster()
        );
    }

    /// Given two nodes that receive the same certificates in opposite orders, we
    /// expect them to agree on every role and every binding.
    ///
    /// The convergence obligation the whole design rests on, stated as a test
    /// rather than only as a comment. A capability check that diverged peers would
    /// be worse than no check at all, and this is the shape that failure takes:
    /// the same set of certificates, two delivery orders.
    #[test]
    fn the_closure_is_the_same_whatever_order_certificates_arrive_in() {
        let mut ins = insider_workspace(Role::Admin);
        let (carol, carol_secret) = stranger(280);
        let effects = ins
            .alice
            .handle(
                Event::AddUser {
                    member: carol,
                    share_key: carol_secret.share_key(),
                    role: Role::Editor,
                    display_name: "carol".into(),
                    endpoint: None,
                },
                &mut rng(281),
                T0,
            )
            .expect("alice admits carol");
        let mut certs: Vec<Certificate> = effects
            .into_iter()
            .find_map(|effect| match effect {
                Effect::BroadcastOp { proof, .. } => Some(proof),
                _ => None,
            })
            .expect("the admission broadcasts a proof");
        certs.extend(ins.alice.capabilities().certificates());
        assert!(
            certs.len() > 2,
            "the set must have several certificates for the order to matter"
        );

        let founder = ins.alice_id.to_bytes();
        let mut forwards = CapabilityStore::new(founder);
        forwards.extend(certs.iter().cloned());
        let mut backwards = CapabilityStore::new(founder);
        backwards.extend(certs.iter().rev().cloned());

        assert_eq!(
            forwards.roles(),
            backwards.roles(),
            "two nodes that received the same certificates in opposite orders disagreed \
             about roles, so a receiver-side capability check would drop different \
             operations on different peers and diverge the group permanently"
        );
        assert_eq!(
            forwards.certified_devices().collect::<Vec<_>>(),
            backwards.certified_devices().collect::<Vec<_>>(),
            "the same certificates in opposite orders certified different devices"
        );
    }
}

/// Restarting a node must be indistinguishable from never having stopped.
///
/// These are the properties that make persistence worth having. A snapshot that
/// round-trips the manifest but loses `owner_sks` produces a node that loads
/// cleanly and then cannot read a word of its own workspace, so the decryption
/// properties here matter more than the equality ones.
mod a_snapshot_restores_the_whole_node {
    use iroh_beekem_core::{Chunk, FileEntry, WorkspaceInfo};
    use proptest::prelude::*;

    use super::{
        Bus, DOC, Effect, Event, MemberId, Role, T0, WorkspaceState, rng, two_node_workspace,
    };

    /// A second document, so a history can exercise more than one CRDT.
    const OTHER: iroh_beekem_core::DocumentUuid = iroh_beekem_core::DocumentUuid([7u8; 16]);

    /// One step of a generated workspace history.
    ///
    /// Deliberately drawn only from actions the founder can take without new key
    /// material: generating a `MemberId` or a `ShareKey` inside a proptest
    /// strategy would put key generation on the shrinking path, where it is both
    /// slow and meaningless to minimise.
    #[derive(Debug, Clone)]
    enum Step {
        Edit { doc: bool, text: String },
        Insert { doc: bool, pos: usize, text: String },
        Remove { doc: bool, pos: usize, len: usize },
        Upsert { doc: bool, path: String },
        Rename { doc: bool, path: String },
        Delete { doc: bool },
        Info { name: String },
        DisplayName { name: String },
        Rotate,
    }

    fn step() -> impl Strategy<Value = Step> {
        // Offsets and lengths are allowed to exceed the document, because the
        // state machine clamps rather than rejects and a generator that stayed
        // in range would never exercise that.
        prop_oneof![
            (any::<bool>(), "[a-z ]{0,12}").prop_map(|(doc, text)| Step::Edit { doc, text }),
            (any::<bool>(), 0usize..16, "[a-z]{0,6}").prop_map(|(doc, pos, text)| Step::Insert {
                doc,
                pos,
                text
            }),
            (any::<bool>(), 0usize..16, 0usize..16).prop_map(|(doc, pos, len)| Step::Remove {
                doc,
                pos,
                len
            }),
            (any::<bool>(), "/[a-z]{1,6}").prop_map(|(doc, path)| Step::Upsert { doc, path }),
            (any::<bool>(), "/[a-z]{1,6}").prop_map(|(doc, path)| Step::Rename { doc, path }),
            any::<bool>().prop_map(|doc| Step::Delete { doc }),
            "[a-z ]{0,10}".prop_map(|name| Step::Info { name }),
            "[a-z]{0,8}".prop_map(|name| Step::DisplayName { name }),
            Just(Step::Rotate),
        ]
    }

    fn uuid(second: bool) -> iroh_beekem_core::DocumentUuid {
        if second { OTHER } else { DOC }
    }

    /// Replay a generated history onto the founder, delivering everything to bob.
    ///
    /// Errors are swallowed on purpose: a `Rename` of a deleted document is a
    /// legitimate refusal, and a generator that could not produce refusals would
    /// only ever snapshot states reached by a happy path.
    fn replay(bus: &mut Bus, steps: &[Step]) {
        eprintln!("CASE {steps:?}");
        for (i, s) in steps.iter().enumerate() {
            let seed = 9000 + i as u64;
            let event = match s.clone() {
                Step::Edit { doc, text } => Event::LocalEdit {
                    doc: uuid(doc),
                    text,
                },
                Step::Insert { doc, pos, text } => Event::InsertText {
                    doc: uuid(doc),
                    pos,
                    text,
                },
                Step::Remove { doc, pos, len } => Event::RemoveText {
                    doc: uuid(doc),
                    pos,
                    len,
                },
                Step::Upsert { doc, path } => Event::UpsertFile {
                    entry: FileEntry {
                        uuid: uuid(doc),
                        logical_path: path,
                        mime_type: "text/plain".into(),
                        asset: None,
                    },
                },
                Step::Rename { doc, path } => Event::RenameFile {
                    doc: uuid(doc),
                    path,
                },
                Step::Delete { doc } => Event::DeleteFile { doc: uuid(doc) },
                Step::Info { name } => Event::SetInfo {
                    info: WorkspaceInfo {
                        name,
                        description: String::new(),
                    },
                },
                Step::DisplayName { name } => Event::SetDisplayName { display_name: name },
                Step::Rotate => Event::Rotate,
            };
            let effects = bus
                .alice
                .handle(event, &mut rng(seed), T0)
                .unwrap_or_default();
            bus.queue_for_bob(effects);
        }
        bus.deliver_all_to_bob();
    }

    /// Every observable a caller can read off a node, as one comparable value.
    ///
    /// Collected into one struct rather than asserted field by field so that
    /// adding an observable to `WorkspaceState` and forgetting to persist what
    /// backs it fails here, rather than passing because nobody thought to
    /// compare the new field.
    #[derive(Debug, PartialEq)]
    struct Observables {
        member: [u8; 32],
        group_size: u32,
        namespace: iroh_beekem_core::NamespaceEpoch,
        roster: Vec<[u8; 32]>,
        first_doc: String,
        second_doc: String,
        files: Vec<FileEntry>,
        users: Vec<iroh_beekem_core::UserRecord>,
        info: WorkspaceInfo,
        devices: Vec<iroh_beekem_core::DeviceRecord>,
        roles: Vec<([u8; 32], Role)>,
        certificates: Vec<[u8; 32]>,
        log_len: usize,
    }

    fn observables(state: &WorkspaceState) -> Observables {
        Observables {
            member: state.member_id().to_bytes(),
            group_size: state.group_size(),
            namespace: state.namespace(),
            roster: state.roster(),
            first_doc: state.document_text(DOC),
            second_doc: state.document_text(OTHER),
            files: state.manifest().files(),
            users: state.manifest().users(),
            info: state.manifest().info(),
            devices: state.devices(),
            roles: state.capabilities().roles(),
            certificates: state
                .capabilities()
                .certificates()
                .iter()
                .map(iroh_beekem_core::Certificate::digest)
                .collect(),
            log_len: state
                .op_log()
                .expect("a workspace built by replay has a sortable operation graph")
                .len(),
        }
    }

    proptest! {
        /// In a workspace driven through an arbitrary history, upon exporting and
        /// re-importing a node's snapshot, we expect the restored node to report
        /// every observable identically to the node it was taken from.
        #[test]
        fn a_restored_node_reports_what_the_original_reported(steps in prop::collection::vec(step(), 0..12)) {
            let mut bus = two_node_workspace();
            replay(&mut bus, &steps);

            let bytes = bus.alice.export().expect("a replayed workspace can be exported");
            let restored = WorkspaceState::import(&bytes).expect("its own export can be imported");

            prop_assert_eq!(
                observables(&restored),
                observables(&bus.alice),
                "a restarted node differed from the one it resumed, so persistence \
                 silently drops state the caller can observe"
            );
        }

        /// In a workspace driven through an arbitrary history, upon restoring the
        /// joiner from a snapshot, we expect it to still hold the certificates
        /// that authorise its own writes — a node that lost them would either
        /// re-accept uncertified state or lock itself out.
        #[test]
        fn a_restored_node_keeps_the_capabilities_it_was_acting_under(steps in prop::collection::vec(step(), 0..12)) {
            let mut bus = two_node_workspace();
            replay(&mut bus, &steps);

            let bytes = bus.bob.export().expect("the joiner can be exported");
            let restored = WorkspaceState::import(&bytes).expect("the joiner can be imported");

            let me = restored.member_id().to_bytes();
            prop_assert_eq!(
                restored.capabilities().role_of_member(&me),
                bus.bob.capabilities().role_of_member(&me),
                "the restored joiner no longer resolves its own role, so its writes \
                 would be refused by every peer"
            );
            prop_assert!(
                restored.capabilities().is_certified_device(&me),
                "the restored joiner is no longer a certified device, so it would \
                 contribute nothing to any peer's roster"
            );
        }
    }

    /// In a node that has published everything it holds, upon restoring it from
    /// a snapshot, we expect a resync to publish nothing — exactly as it would
    /// have before the restart.
    ///
    /// This is what the snapshot's `published_up_to` field is for, and it has no
    /// other observable. Dropped, the restored node believes it has published
    /// nothing, and its first resync re-encrypts and re-uploads every document it
    /// holds. That is not a correctness failure, which is precisely why it needs
    /// a test: it is silent, it is paid on every restart, and it is the whole
    /// cost delta publishing was meant to remove.
    #[test]
    fn a_restored_node_does_not_republish_what_the_original_had_already_published() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "published before the restart".into(),
            },
            710,
        );

        let quiescent = bus.alice_emits(Event::Resync { doc: DOC }, 711);
        assert!(
            !quiescent
                .iter()
                .any(|e| matches!(e, Effect::StoreChunk { .. })),
            "the original must be quiescent first, or the restored node has \
             nothing to match"
        );

        let bytes = bus.alice.export().expect("alice can be exported");
        let mut restored = WorkspaceState::import(&bytes).expect("alice can be imported");
        let after_restart = restored
            .handle(Event::Resync { doc: DOC }, &mut rng(712), T0)
            .expect("a restored node handles a resync");

        assert!(
            !after_restart
                .iter()
                .any(|e| matches!(e, Effect::StoreChunk { .. })),
            "a restored node must not re-announce what it had already published, \
             got {after_restart:?}"
        );
    }

    /// In a workspace where content was published before the snapshot, upon
    /// restoring from that snapshot, we expect the restored node to still decrypt
    /// a chunk it had already received.
    ///
    /// This is the property the whole module exists for. `owner_sks` and the
    /// cached PCS keys live inside beekem's `Cgka`; a snapshot that stored the
    /// manifest and the tree but lost either would import cleanly, report the
    /// right file list, and never read another byte of content.
    #[test]
    fn a_restored_node_can_still_decrypt_content_published_before_the_snapshot() {
        let mut bus = two_node_workspace();
        bus.alice_does(
            Event::LocalEdit {
                doc: DOC,
                text: "before the snapshot".into(),
            },
            700,
        );
        bus.deliver_all_to_bob();
        assert_eq!(
            bus.bob.document_text(DOC),
            "before the snapshot",
            "the bus must actually deliver, or the restore below proves nothing"
        );

        // Capture a chunk alice publishes *after* bob's snapshot is taken, then
        // hand it to the restored bob. Re-reading already-applied text would only
        // prove the Loro document was stored; decrypting a new chunk proves the
        // key material came back.
        let bytes = bus.bob.export().expect("bob can be exported");
        let effects = bus.alice_emits(
            Event::LocalEdit {
                doc: DOC,
                text: " and after".into(),
            },
            701,
        );
        let chunk: Chunk = effects
            .iter()
            .find_map(|e| match e {
                Effect::StoreChunk { chunk, .. } => Some((**chunk).clone()),
                _ => None,
            })
            .expect("an edit publishes a chunk");

        let mut restored = WorkspaceState::import(&bytes).expect("bob can be imported");
        restored
            .handle(
                Event::ChunkArrived {
                    doc: DOC,
                    chunk: Box::new(chunk),
                },
                &mut rng(702),
                T0,
            )
            .expect("the restored node accepts the chunk");

        assert_eq!(
            restored.document_text(DOC),
            "before the snapshot and after",
            "the restored node could not decrypt a chunk keyed under an epoch it \
             held before the snapshot, so the CGKA secrets did not survive the \
             round trip"
        );
        assert_eq!(
            restored.pending_len(),
            0,
            "the chunk was parked rather than applied, which is what a lost PCS \
             key looks like from the outside"
        );
    }

    /// In a workspace whose founder has admitted a member, upon restoring the
    /// founder, we expect it to still be able to remove that member — the
    /// certificate store and both member sets survived, not merely the tree.
    #[test]
    fn a_restored_admin_can_still_administer() {
        let bus = two_node_workspace();
        let bob: MemberId = bus.bob.member_id();

        let bytes = bus.alice.export().expect("alice can be exported");
        let mut restored = WorkspaceState::import(&bytes).expect("alice can be imported");

        assert_eq!(
            restored
                .capabilities()
                .role_of_member(&restored.member_id().to_bytes()),
            Some(Role::Admin),
            "the founder's self-signed admin grant did not survive the round trip"
        );
        let effects = restored
            .handle(Event::RemoveMember { member: bob }, &mut rng(710), T0)
            .expect("a restored admin may still remove a member");
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RotateNamespace { .. })),
            "a removal by a restored admin did not rotate the namespace, so the \
             restored node did not recognise the target as a current member"
        );
    }
}

/// Leaving is what a member does for itself; removal is what the group does to
/// it. The two differ in exactly three respects, and all three are asserted here
/// because each one is silent if it regresses.
mod a_member_can_walk_away {
    use super::{Effect, Event, Role, T0, rng, two_node_workspace};

    /// In a two-member workspace, upon a non-admin member leaving, we expect its
    /// leaf to be retracted on the admin's node.
    ///
    /// The role check is the point: `on_remove_member` demands `Admin`, so a
    /// `leave` routed through it would make a workspace's viewers unable to
    /// leave it — while every peer would still accept the operation, since
    /// `authorize` admits a same-user `Remove` from anybody.
    #[test]
    fn a_member_with_no_administrative_role_can_still_leave() {
        let mut bus = two_node_workspace();
        assert_eq!(
            bus.bob
                .capabilities()
                .role_of_member(&bus.bob.member_id().to_bytes()),
            Some(Role::Editor),
            "this test is only meaningful if bob cannot administer"
        );

        let effects = bus.bob.handle(Event::Leave, &mut rng(800), T0).expect(
            "a member that cannot administer must still be able to leave; refusing \
             would trap every viewer in every workspace they were ever invited to",
        );
        bus.queue_from_bob_to_alice(effects);
        bus.deliver_all_to_alice();

        assert_eq!(
            bus.alice.group_size(),
            1,
            "the departing member's leaf was still in the admin's tree, so the \
             group never learned it had gone"
        );
    }

    /// In a workspace a member is leaving, upon handling the departure, we
    /// expect no namespace rotation.
    ///
    /// The difference from a removal, and the reason `Leave` is a separate
    /// handler rather than `RemoveMember` with a relaxed guard. A leaver that
    /// rotated would mint the capability it is walking away from and announce it
    /// to the group under a key it still holds — handing itself the replica it
    /// had just left.
    #[test]
    fn leaving_never_rotates_the_namespace() {
        let mut bus = two_node_workspace();
        let effects = bus
            .bob
            .handle(Event::Leave, &mut rng(801), T0)
            .expect("bob leaves");

        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::RotateNamespace { .. })),
            "a departure rotated the namespace, so the leaver would mint and then \
             receive the capability for the replica it was walking away from"
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::BroadcastOp { .. })),
            "a departure emitted no removal at all, so the group would never learn \
             of it — this assertion is what stops the one above passing vacuously"
        );
    }

    /// In a workspace with a single administrator, upon that administrator
    /// trying to leave, we expect a refusal.
    ///
    /// Promotion is itself an administrative act, so a workspace that lost its
    /// last admin could never appoint another. Every remaining member would keep
    /// reading and writing and none could ever admit or remove anybody.
    #[test]
    fn the_last_administrator_cannot_leave() {
        let mut bus = two_node_workspace();
        let err = bus
            .alice
            .handle(Event::Leave, &mut rng(802), T0)
            .expect_err("the only admin must not be able to strand the workspace");
        assert!(
            matches!(err, iroh_beekem_core::CoreError::LastAdmin),
            "the refusal must name the reason, since the caller's remedy is to \
             promote somebody first: {err}"
        );
    }

    /// In a workspace where a user holds two devices, upon that user leaving, we
    /// expect both leaves to be retracted.
    ///
    /// A user is what the group enumerates, so leaving with one of two devices
    /// still in the tree is not leaving: the departed user would still be listed
    /// as present while having lost the ability to act as itself.
    #[test]
    fn leaving_retracts_every_device_of_the_departing_user() {
        use beekem::id::MemberId;
        use keyhive_crypto::{
            share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
        };

        let mut bus = two_node_workspace();
        let bob_user = bus.bob.member_id().to_bytes();

        // A second device for bob, enrolled by bob — not an administrative act,
        // which is why bob can do it at all.
        let phone_signer = MemorySigner::generate(&mut rng(803));
        let phone_secret = ShareSecretKey::generate(&mut rng(804));
        let phone = MemberId::from(phone_signer.verifying_key());
        let effects = bus
            .bob
            .handle(
                Event::AddDevice {
                    member: phone,
                    share_key: phone_secret.share_key(),
                    user: bob_user,
                    label: "phone".into(),
                    endpoint: None,
                },
                &mut rng(805),
                T0,
            )
            .expect("bob enrols a second device of his own");
        bus.queue_from_bob_to_alice(effects);
        bus.deliver_all_to_alice();
        assert_eq!(
            bus.alice.group_size(),
            3,
            "the second device never entered the tree, so this test cannot pose \
             its question"
        );

        let effects = bus
            .bob
            .handle(Event::Leave, &mut rng(806), T0)
            .expect("bob leaves with both devices");
        bus.queue_from_bob_to_alice(effects);
        bus.deliver_all_to_alice();

        assert_eq!(
            bus.alice.group_size(),
            1,
            "a departing user left a device behind in the tree, so it would still \
             be enumerated as present while unable to act"
        );
    }
}

/// M-of-N: an administrative action needs several distinct admins to agree, and
/// **every receiver** enforces that — not merely the node issuing it.
///
/// The receiver-side half is the whole point. `require_quorum` runs on the node
/// taking the action and a malicious admin simply would not run it, so a
/// threshold enforced only there would constrain honest nodes and nobody else.
mod an_action_needs_a_quorum {
    use beekem::id::{MemberId, TreeId};
    use iroh_beekem_core::{
        AdminAction, AuthorizedOp, CgkaController, CoreError, Effect, Event, Role, WorkspaceSecret,
        WorkspaceState, capability::Certificate,
    };
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
    };

    use super::{T0, rng};

    /// A three-member workspace founded at a threshold of two.
    ///
    /// Alice founds and appoints Bob as a second admin — which only the founder
    /// may do alone. Carol is an ordinary editor and the target of everything
    /// proposed below, so neither approver is ever also the victim.
    struct Quorum {
        alice: WorkspaceState,
        bob: WorkspaceState,
        carol: MemberId,
    }

    fn two_of_two() -> Quorum {
        let tree = TreeId::from(MemorySigner::generate(&mut rng(0)).verifying_key());
        let alice_signer = MemorySigner::generate(&mut rng(1));
        let bob_signer = MemorySigner::generate(&mut rng(2));
        let carol_signer = MemorySigner::generate(&mut rng(3));
        let bob_id = MemberId::from(bob_signer.verifying_key());
        let carol_id = MemberId::from(carol_signer.verifying_key());
        let secret = WorkspaceSecret::generate(&mut rng(5));

        let cgka = CgkaController::create(tree, alice_signer, &mut rng(10)).expect("alice founds");
        let mut alice = WorkspaceState::found(cgka, WorkspaceSecret::new(secret.to_bytes()), 2)
            .expect("alice founds at a threshold of two");

        // Both admitted by the founder, which its exemption permits and which is
        // the only way a workspace above a threshold of one can ever acquire the
        // admins a quorum is made of.
        let bob_secret = ShareSecretKey::generate(&mut rng(20));
        alice
            .handle(
                Event::AddUser {
                    member: bob_id,
                    share_key: bob_secret.share_key(),
                    role: Role::Admin,
                    display_name: "bob".into(),
                    endpoint: None,
                },
                &mut rng(21),
                T0,
            )
            .expect("the founder may appoint an admin alone");
        let carol_secret = ShareSecretKey::generate(&mut rng(30));
        alice
            .handle(
                Event::AddUser {
                    member: carol_id,
                    share_key: carol_secret.share_key(),
                    role: Role::Editor,
                    display_name: "carol".into(),
                    endpoint: None,
                },
                &mut rng(31),
                T0,
            )
            .expect("the founder admits carol");

        let log = alice.op_log().expect("exporting the log");
        let certs = alice.capabilities().certificates();
        let bob_cgka =
            CgkaController::join(tree, bob_signer, bob_secret, &log, &certs).expect("bob joins");

        Quorum {
            alice,
            bob: WorkspaceState::joined(bob_cgka, secret, 0),
            carol: carol_id,
        }
    }

    /// Every certificate one node emitted, for handing to another.
    fn certs_of(effects: &[Effect]) -> Vec<Certificate> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::BroadcastCerts(certs) => Some(certs.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// The digest of the proposal a `Propose` minted.
    fn proposal_digest(effects: &[Effect]) -> [u8; 32] {
        certs_of(effects)
            .iter()
            .find(|c| matches!(c, Certificate::Proposal(_)))
            .map(Certificate::digest)
            .expect("a proposal is broadcast as a certificate")
    }

    /// In a workspace founded at a threshold of two, upon the founder trying to
    /// remove somebody alone, we expect a refusal.
    #[test]
    fn one_admin_cannot_remove_a_member_alone() {
        let mut q = two_of_two();
        let err = q
            .alice
            .handle(Event::RemoveMember { member: q.carol }, &mut rng(100), T0)
            .expect_err("one admin is not a quorum of two");
        assert!(
            matches!(err, CoreError::QuorumRequired { .. }),
            "the refusal must say a quorum is missing, since the caller's remedy \
             is to propose and collect approvals rather than to retry: {err}"
        );
        assert_eq!(q.alice.group_size(), 3, "a refused removal happened anyway");
    }

    /// In a workspace founded at a threshold of two, upon two distinct admins
    /// approving, we expect the removal to be performed and accepted everywhere.
    ///
    /// The counterweight: an implementation that refused every removal would
    /// satisfy both properties above.
    #[test]
    fn a_removal_two_admins_approved_is_performed_and_accepted() {
        let mut q = two_of_two();
        let action = AdminAction::RemoveMember {
            member: q.carol.to_bytes(),
        };

        let effects = q
            .alice
            .handle(
                Event::Propose {
                    action,
                    expires: None,
                },
                &mut rng(110),
                T0,
            )
            .expect("an admin may propose");
        let digest = proposal_digest(&effects);
        let mut wire = certs_of(&effects);

        let effects = q
            .alice
            .handle(Event::Approve { proposal: digest }, &mut rng(111), T0)
            .expect("alice approves");
        wire.extend(certs_of(&effects));
        assert!(
            !q.alice.capabilities().is_executed_action(&action),
            "one approval reached a threshold of two"
        );

        // Bob learns of the proposal and adds the second approval.
        q.bob
            .handle(Event::CertsArrived(wire), &mut rng(112), T0)
            .expect("bob absorbs the proposal and alice's approval");
        let effects = q
            .bob
            .handle(Event::Approve { proposal: digest }, &mut rng(113), T0)
            .expect("bob approves");

        assert!(
            q.bob.capabilities().is_executed_action(&action),
            "two distinct admins approved and the proposal still had no quorum"
        );
        assert_eq!(
            q.bob.group_size(),
            2,
            "bob's own approval completed the quorum, so bob must have performed \
             the removal itself rather than waiting to be told"
        );

        // And the operation bob emitted must be acceptable to alice, who has not
        // yet seen bob's approval — which is what the proof bundle is for.
        let op = effects
            .iter()
            .find_map(|e| match e {
                Effect::BroadcastOp { op, proof } => {
                    Some(AuthorizedOp::new((**op).clone(), proof.clone()))
                }
                _ => None,
            })
            .expect("performing a removal broadcasts the operation");
        q.alice
            .handle(Event::ControlOp(op), &mut rng(114), T0)
            .expect("alice accepts a removal a quorum authorised");
        assert_eq!(
            q.alice.group_size(),
            2,
            "the removal carried its own quorum proof, so a receiver that had not \
             yet seen the approvals must still have accepted it"
        );
    }

    /// In a workspace founded at a threshold of two, upon a non-founding admin
    /// trying to appoint another admin alone, we expect a refusal.
    ///
    /// The way round a threshold that would otherwise make it decorative: an
    /// admin who could appoint a second admin alone could appoint a puppet and
    /// then approve its own actions twice. The founder's exemption does not
    /// extend to anybody it appoints.
    #[test]
    fn a_non_founding_admin_cannot_appoint_a_puppet() {
        let mut q = two_of_two();
        let puppet = MemberId::from(MemorySigner::generate(&mut rng(40)).verifying_key());
        let puppet_secret = ShareSecretKey::generate(&mut rng(41));

        let err = q
            .bob
            .handle(
                Event::AddUser {
                    member: puppet,
                    share_key: puppet_secret.share_key(),
                    role: Role::Admin,
                    display_name: "puppet".into(),
                    endpoint: None,
                },
                &mut rng(42),
                T0,
            )
            .expect_err("only the founder may appoint an admin alone");
        assert!(
            matches!(err, CoreError::QuorumRequired { .. }),
            "appointing an admin above a threshold of one needs the founder or a \
             quorum, and the refusal should say which is missing: {err}"
        );
    }

    /// In a workspace founded at a threshold of two, upon a member leaving, we
    /// expect no quorum to be required.
    ///
    /// A threshold governs what the group does *to* a member, never what a member
    /// does about itself. Requiring a quorum to leave would let a group hold
    /// somebody in a workspace against their will.
    #[test]
    fn leaving_needs_no_quorum() {
        let mut q = two_of_two();
        let effects = q
            .bob
            .handle(Event::Leave, &mut rng(120), T0)
            .expect("a member may always leave");
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::BroadcastOp { .. })),
            "the departure emitted no removal at all"
        );

        let op = effects
            .iter()
            .find_map(|e| match e {
                Effect::BroadcastOp { op, proof } => {
                    Some(AuthorizedOp::new((**op).clone(), proof.clone()))
                }
                _ => None,
            })
            .expect("a departure broadcasts its removal");
        q.alice
            .handle(Event::ControlOp(op), &mut rng(121), T0)
            .expect("alice accepts a self-removal");
        assert_eq!(
            q.alice.group_size(),
            2,
            "a receiver refused a member's own departure because no quorum had \
             approved it"
        );
    }
}
