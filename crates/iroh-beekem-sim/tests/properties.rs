//! Property tests over the simulated workspace.
//!
//! These are the assertions unit tests cannot reach: they hold across every
//! interleaving the simulator generates, under an unordered and lossy
//! transport, over many seeds.

use std::time::Duration;

use iroh_beekem_sim::{Honest, Role, Scenario, WorkspaceNode, member_bytes_of};
use propsim::prelude::*;

const NODES: usize = 3;
const SEEDS: usize = 6;

/// Nodes that have finished joining the group.
fn joined<'a, S: Scenario>(w: &'a World<'a, WorkspaceNode<S>>) -> Vec<&'a WorkspaceNode<S>> {
    w.nodes().filter(|n| n.has_joined()).collect()
}

/// The network conditions every plan runs under.
///
/// Partitions in particular are not decoration. The roster and the namespace
/// both derive from state that converges asynchronously, so admission and
/// eviction are *eventual* — and on a perfect network every "eventually"
/// collapses to "immediately", which would let a roster that never converges
/// pass. Reordering matters for the same reason: a device record and the `Add`
/// that authorises it travel on different planes and routinely arrive out of
/// order.
///
/// # Why the mode is set explicitly
///
/// `Faults::swarm()` defaults to [`Mode::Safety`], which injures uniformly and
/// **never heals a partition**. Under that mode no `eventually_within` property
/// in this file is sound: a permanently severed node cannot converge with the
/// group, so the property is asserting something false about the scenario
/// rather than something true about the protocol, and it fails or passes
/// according to whether the seed happened to enable partitions at all.
///
/// [`Mode::Liveness`] injures, heals, and then leaves a window in which
/// progress can be asserted — which is exactly the shape of every property here
/// (`documents_converge_once_the_network_settles` says so in its name). The
/// injury window is still exercised, so the `always` properties lose nothing.
fn network_faults() -> Faults {
    Faults::swarm()
        .partitions()
        .latency_ms(1..40)
        .reorder()
        .mode(Mode::Liveness)
}

fn plan<S: Scenario>(properties: Vec<Property<WorkspaceNode<S>>>) -> TestPlan<WorkspaceNode<S>> {
    plan_of_size(NODES, properties)
}

/// A plan over an explicit number of nodes.
///
/// The outsider scenario needs one more node than the honest group, so that
/// removing the outsider from the picture still leaves a group large enough for
/// the properties about *members* to say anything.
fn plan_of_size<S: Scenario>(
    nodes: usize,
    properties: Vec<Property<WorkspaceNode<S>>>,
) -> TestPlan<WorkspaceNode<S>> {
    Simulation::plan::<WorkspaceNode<S>>()
        .nodes(nodes)
        .transport(InMemory::unordered_lossy())
        .faults(network_faults())
        .state_machine()
        .check(properties)
        .seeds(SEEDS)
        .finish()
}

/// The honest base protocol, which most properties are stated against.
fn base_plan(properties: Vec<Property<WorkspaceNode<Honest>>>) -> TestPlan<WorkspaceNode<Honest>> {
    plan(properties)
}

#[test]
fn every_node_eventually_joins_the_group() {
    base_plan(vec![property::eventually_within(
        "all nodes join",
        Duration::from_secs(5),
        |w: &World<'_, WorkspaceNode<Honest>>| joined(w).len() == NODES,
    )])
    .run(deterministic());
}

#[test]
fn joined_nodes_never_disagree_about_group_size_beyond_the_cluster() {
    // A sanity invariant: no node should ever believe the group is larger than
    // the cluster. A violation would mean membership operations are being
    // applied more than once.
    base_plan(vec![property::always(
        "group size is bounded by the cluster",
        |w: &World<'_, WorkspaceNode<Honest>>| {
            joined(w).iter().all(|n| n.group_size() as usize <= NODES)
        },
    )])
    .run(deterministic());
}

#[test]
fn documents_converge_once_the_network_settles() {
    // Every joined node that has seen any content must agree with every other.
    // Nodes still catching up have not converged *yet*, which is why this is an
    // `eventually` rather than an `always`.
    base_plan(vec![property::eventually_within(
        "joined nodes agree on document content",
        Duration::from_secs(10),
        |w: &World<'_, WorkspaceNode<Honest>>| {
            let texts: Vec<String> = joined(w).iter().map(|n| n.document_text()).collect();
            if texts.len() < NODES {
                return false;
            }
            let mut sorted: Vec<Vec<char>> = texts
                .iter()
                .map(|t| {
                    let mut cs: Vec<char> = t.chars().collect();
                    cs.sort_unstable();
                    cs
                })
                .collect();
            sorted.dedup();
            sorted.len() == 1
        },
    )])
    .run(deterministic());
}

#[test]
fn a_nodes_own_edits_are_always_present_in_its_own_view() {
    // The weakest possible sanity check on the encryption pipeline: whatever a
    // node wrote, it can still read. If encryption or the pending-chunk logic
    // ever dropped a local write, this fails immediately.
    base_plan(vec![property::always(
        "local edits are visible locally",
        |w: &World<'_, WorkspaceNode<Honest>>| {
            joined(w).iter().all(|n| {
                let text = n.document_text();
                n.contributed().iter().all(|c| text.contains(c.as_str()))
            })
        },
    )])
    .run(deterministic());
}

#[test]
fn no_chunk_stays_parked_forever() {
    // The two-DAG hazard: a chunk needs both its CGKA key material and its CRDT
    // dependencies. If those two conditions could deadlock against each other,
    // chunks would accumulate and never drain.
    base_plan(vec![property::eventually_within(
        "parked chunks drain",
        Duration::from_secs(10),
        |w: &World<'_, WorkspaceNode<Honest>>| {
            let members = joined(w);
            members.len() == NODES && members.iter().all(|n| n.pending_chunks() == 0)
        },
    )])
    .run(deterministic());
}

#[test]
fn no_control_operation_stays_parked_forever() {
    base_plan(vec![property::eventually_within(
        "parked control operations drain",
        Duration::from_secs(10),
        |w: &World<'_, WorkspaceNode<Honest>>| {
            let members = joined(w);
            members.len() == NODES && members.iter().all(|n| n.parked_ops() == 0)
        },
    )])
    .run(deterministic());
}

/// In an entirely honest run, upon any interleaving, we expect no node's roles or
/// device bindings ever to move except under a valid capability chain.
///
/// Cross-cutting deliberately, and asserted *here* rather than only in the
/// insider scenario. An authorization property stated only against an attacker
/// says nothing about whether the honest path quietly accepts uncertified state —
/// and "the honest path quietly accepted uncertified state" is exactly the shape
/// of the finding phase 5 closed. A suite that only watches attackers can be
/// green while every check is dead code.
#[test]
fn no_role_or_binding_ever_moves_without_a_valid_chain() {
    base_plan(vec![property::always(
        "roles and bindings only ever reflect what was actually granted",
        |w: &World<'_, WorkspaceNode<Honest>>| {
            let admitted: Vec<[u8; 32]> = (0..NODES as u64).map(member_bytes_of).collect();
            w.nodes().filter(|n| n.has_joined()).all(|n| {
                // Exactly one admin — the founder — because nothing in an honest
                // run grants another.
                n.admin_count() <= 1
                    // No device resolving to a person nobody admitted.
                    && n.certified_users().iter().all(|u| admitted.contains(u))
                    // And every member holding exactly what its admission gave it.
                    && admitted.iter().enumerate().all(|(id, user)| {
                        let expected = if id == 0 { Role::Admin } else { Role::Editor };
                        n.role_of(*user).is_none_or(|role| role == expected)
                    })
            })
        },
    )])
    .run(deterministic());
}

#[test]
fn a_healthy_run_never_evicts_anything() {
    // The parking limits are there for a peer flooding the control or data
    // plane. Under ordinary lossy, unordered delivery they must never bind: if
    // they do, the eviction path is discarding content that was going to
    // become applicable, which converges to the wrong answer silently rather
    // than failing. This is the property that catches that.
    base_plan(vec![property::always(
        "no queue overflows under honest traffic",
        |w: &World<'_, WorkspaceNode<Honest>>| joined(w).iter().all(|n| n.evictions() == 0),
    )])
    .run(deterministic());
}

/// BeeKEM's headline claim over MLS/TreeKEM is that it merges *concurrent*
/// membership and key-rotation operations with no central sequencer. Nothing
/// exercised that: the simulator only ever added members and edited text.
mod concurrent_rotation_and_revocation {
    use std::time::Duration;

    use iroh_beekem_sim::{Churn, WorkspaceNode};
    use propsim::prelude::*;

    use super::{NODES, plan};

    /// The nodes still in the group after the scenario's revocation.
    fn remaining<'a>(w: &'a World<'a, WorkspaceNode<Churn>>) -> Vec<&'a WorkspaceNode<Churn>> {
        w.nodes()
            .filter(|n| n.has_joined() && !n.is_revocation_target())
            .collect()
    }

    #[test]
    fn the_remaining_members_still_converge() {
        plan::<Churn>(vec![property::eventually_within(
            "members converge across concurrent rotations and a revocation",
            Duration::from_secs(15),
            |w: &World<'_, WorkspaceNode<Churn>>| {
                let members = remaining(w);
                if members.len() != NODES - 1 {
                    return false;
                }
                let mut sorted: Vec<Vec<char>> = members
                    .iter()
                    .map(|n| {
                        let mut cs: Vec<char> = n.document_text().chars().collect();
                        cs.sort_unstable();
                        cs
                    })
                    .collect();
                sorted.dedup();
                sorted.len() == 1
            },
        )])
        .run(deterministic());
    }

    #[test]
    fn rotation_never_strands_a_remaining_members_own_writes() {
        // A rotation re-keys the path to the root. If it were mishandled, the
        // most visible symptom would be a node losing the ability to read back
        // what it wrote itself.
        plan::<Churn>(vec![property::always(
            "local edits survive rotation",
            |w: &World<'_, WorkspaceNode<Churn>>| {
                remaining(w).iter().all(|n| {
                    let text = n.document_text();
                    n.contributed().iter().all(|c| text.contains(c.as_str()))
                })
            },
        )])
        .run(deterministic());
    }

    #[test]
    fn the_run_is_reproducible() {
        assert_deterministic(|| plan::<Churn>(Vec::new()), Seed(0x0BAD_F00D));
    }
}

/// An attacker holding a keypair that no `Add` ever introduced, broadcasting
/// well-formed self-admitting operations onto the control topic. beekem applies
/// operations without checking signatures or issuers, so these properties hold
/// only because the core checks both before merging.
mod a_forging_peer_is_rejected {
    use std::time::Duration;

    use iroh_beekem_sim::{Forging, WorkspaceNode};
    use propsim::prelude::*;

    use super::{NODES, plan};

    #[test]
    fn no_forged_member_ever_enters_the_group() {
        // The cluster has NODES nodes. A forgery that landed would splice an
        // extra leaf into the tree, so the group would outgrow the cluster —
        // which is precisely what this counts.
        plan::<Forging>(vec![property::always(
            "the group never exceeds the cluster",
            |w: &World<'_, WorkspaceNode<Forging>>| {
                w.nodes()
                    .filter(|n| n.has_joined())
                    .all(|n| n.group_size() as usize <= NODES)
            },
        )])
        .run(deterministic());
    }

    #[test]
    fn honest_nodes_still_converge_while_under_attack() {
        // Rejecting forgeries is worth little if the rejection path also stalls
        // legitimate traffic — a plausible way to "fix" the first property.
        plan::<Forging>(vec![property::eventually_within(
            "honest nodes converge despite the forgery traffic",
            Duration::from_secs(15),
            |w: &World<'_, WorkspaceNode<Forging>>| {
                let members: Vec<_> = w.nodes().filter(|n| n.has_joined()).collect();
                if members.len() != NODES {
                    return false;
                }
                let mut sorted: Vec<Vec<char>> = members
                    .iter()
                    .map(|n| {
                        let mut cs: Vec<char> = n.document_text().chars().collect();
                        cs.sort_unstable();
                        cs
                    })
                    .collect();
                sorted.dedup();
                sorted.len() == 1
            },
        )])
        .run(deterministic());
    }

    #[test]
    fn forgery_traffic_never_fills_the_parking_queues() {
        // The flood guard's real job: unverifiable traffic is rejected before it
        // can occupy a slot, so an attacker cannot push out legitimate parked
        // operations.
        plan::<Forging>(vec![property::always(
            "no evictions under forgery traffic",
            |w: &World<'_, WorkspaceNode<Forging>>| {
                w.nodes()
                    .filter(|n| n.has_joined())
                    .all(|n| n.evictions() == 0)
            },
        )])
        .run(deterministic());
    }
}

#[test]
fn the_simulation_is_reproducible() {
    // Guards the whole harness: if any nondeterminism (a hash map iteration
    // order, an unseeded RNG, a clock read) crept into the core, the same seed
    // would stop reproducing the same history and every property above would
    // become untrustworthy.
    assert_deterministic(|| base_plan(Vec::new()), Seed(0x00C0_FFEE));
    assert_deterministic(|| base_plan(Vec::new()), Seed(0x1234_5678));
}

/// What a removed member can still *see*, as distinct from what it can read.
///
/// The confidentiality properties above cover the crypto plane: a revoked member
/// cannot decrypt content or manifests written after its removal. They say
/// nothing about the data plane, and until the simulator modelled an index there
/// was no way to ask. The answer today is uncomfortable, and these properties
/// are written to record exactly where the line currently sits rather than to
/// flatter it.
///
/// A removed member retains the `iroh-docs` write capability, the blinding
/// secret and its place in the gossip overlay, so it keeps observing entry
/// existence, size, author and timing — and keeps watching membership churn.
/// Closing that is what namespace rotation and the device roster are for; see
/// the plan's Phases 3 and 4.
/// Story 3: *"remove a departing team member so they can no longer read
/// documents, document updates or workspace changes."*
///
/// Split by plane, because the two fail independently and the implementation
/// used to get exactly one of them right. **Confidentiality** is the CGKA: the
/// victim cannot decrypt what the group writes afterwards. **Visibility** is
/// the namespace: the victim cannot even tell that it was written. Before
/// namespace rotation only the first held, and the properties in this module
/// were inverted — they asserted that the victim went on watching, so that the
/// line could not move without a test noticing. It has now moved.
mod a_removed_member_stops_seeing {
    use std::time::Duration;

    use iroh_beekem_sim::{Eviction, POST_REVOCATION_DOC, WorkspaceNode, doc_key};
    use propsim::prelude::*;

    use super::plan;

    /// The removed device, once it has joined and been revoked.
    fn victim<'a>(
        w: &'a World<'a, WorkspaceNode<Eviction>>,
    ) -> Option<&'a WorkspaceNode<Eviction>> {
        w.nodes()
            .find(|n| n.is_revocation_target() && n.has_joined())
    }

    /// The members still in the group after the revocation.
    fn remaining<'a>(
        w: &'a World<'a, WorkspaceNode<Eviction>>,
    ) -> Vec<&'a WorkspaceNode<Eviction>> {
        w.nodes()
            .filter(|n| n.has_joined() && !n.is_revocation_target())
            .collect()
    }

    /// Given a revoked device, at every point after the group rotates, we expect
    /// it never to observe an index entry for a document first written after its
    /// removal.
    ///
    /// **The property this phase exists for.** Not "cannot read it" — the CGKA
    /// already gave that — but cannot see that it exists, how big it is, or who
    /// wrote it. `always` rather than `eventually`: there is no moment at which
    /// the victim is allowed to have seen the entry and then forgotten it, and
    /// no later rotation can unlearn what it already observed.
    #[test]
    fn the_victim_never_sees_an_entry_written_after_its_removal() {
        plan::<Eviction>(vec![property::always(
            "the victim observes no post-revocation entry",
            |w: &World<'_, WorkspaceNode<Eviction>>| {
                victim(w).is_none_or(|v| v.entry(&doc_key(POST_REVOCATION_DOC)).is_none())
            },
        )])
        .run(deterministic());
    }

    /// Given the same run, when it settles, we expect every *remaining* member
    /// to hold that entry.
    ///
    /// **The counterweight, and the one that makes the property above mean
    /// anything.** A rotation that stranded everybody would satisfy the
    /// eviction property perfectly while destroying the workspace. It also
    /// guards the vacuity: if the late write never happened, this fails rather
    /// than passing silently alongside it.
    #[test]
    fn every_remaining_member_sees_the_entry_the_victim_does_not() {
        plan::<Eviction>(vec![property::eventually_within(
            "remaining members observe the post-revocation entry",
            Duration::from_secs(20),
            |w: &World<'_, WorkspaceNode<Eviction>>| {
                let members = remaining(w);
                members.len() >= 2
                    && members
                        .iter()
                        .all(|n| n.entry(&doc_key(POST_REVOCATION_DOC)).is_some())
            },
        )])
        .run(deterministic());
    }

    /// Given a revoked device, at every point in the run, we expect it never to
    /// move off the namespace it was on when it was removed.
    ///
    /// The cause behind the two properties above, asserted separately so that a
    /// failure says *why*. A victim that saw no new entry while sitting on the
    /// group's current namespace would be excluded by luck — by message timing,
    /// or by a run in which nobody happened to write — rather than by the
    /// rotation. The capability travels encrypted under a key minted after the
    /// victim's leaf left the tree, so there is nothing for it to decrypt.
    #[test]
    fn the_victim_never_adopts_the_rotation() {
        plan::<Eviction>(vec![property::always(
            "the victim stays on the namespace it was removed from",
            |w: &World<'_, WorkspaceNode<Eviction>>| victim(w).is_none_or(|v| !v.has_rotated()),
        )])
        .run(deterministic());
    }

    /// Given the group has rotated, when the run settles, we expect every
    /// remaining member to agree on which generation is current.
    ///
    /// Two admins removing different members concurrently both mint the same
    /// counter, and without the `(epoch, digest)` tie-break the group would
    /// split across two namespaces with each half convinced it was current.
    /// This is what says the tie-break is total and computed identically
    /// everywhere.
    #[test]
    fn the_remaining_members_converge_on_one_namespace() {
        plan::<Eviction>(vec![property::eventually_within(
            "remaining members agree on the current namespace",
            Duration::from_secs(20),
            |w: &World<'_, WorkspaceNode<Eviction>>| {
                let members = remaining(w);
                let Some(first) = members.first() else {
                    return false;
                };
                members.len() >= 2 && members.iter().all(|n| n.namespace() == first.namespace())
            },
        )])
        .run(deterministic());
    }

    /// Given a revoked device, at every point in the run, we expect no remaining
    /// member's index to contain an entry the victim authored after its removal.
    ///
    /// The write half of eviction. The `iroh-docs` write capability is
    /// all-or-nothing and cannot be withdrawn from one holder, so the victim
    /// keeps the one it was given — abandoning the namespace is what makes it
    /// worthless. A failure here means the group is still reconciling the
    /// replica the victim can still write to.
    #[test]
    fn no_remaining_member_accepts_a_post_revocation_entry_from_the_victim() {
        plan::<Eviction>(vec![property::always(
            "no remaining member holds a post-revocation entry authored by the victim",
            |w: &World<'_, WorkspaceNode<Eviction>>| {
                let Some(victim) = victim(w) else {
                    return true;
                };
                let victim_id = propsim::NodeId(victim.id());
                remaining(w).iter().all(|n| {
                    n.entry(&doc_key(POST_REVOCATION_DOC))
                        .is_none_or(|meta| meta.author != victim_id)
                })
            },
        )])
        .run(deterministic());
    }

    /// Given the group has rotated away from the victim, when the run settles,
    /// we expect the remaining members still to converge on document content.
    ///
    /// Rotation re-publishes every document into a fresh namespace, which is the
    /// single most disruptive thing the protocol does. This is the property that
    /// notices if it strands content rather than moving it.
    #[test]
    fn rotation_does_not_cost_the_remaining_members_their_content() {
        plan::<Eviction>(vec![property::eventually_within(
            "remaining members converge across the rotation",
            Duration::from_secs(20),
            |w: &World<'_, WorkspaceNode<Eviction>>| {
                let members = remaining(w);
                if members.len() < 2 {
                    return false;
                }
                let mut sorted: Vec<Vec<char>> = members
                    .iter()
                    .map(|n| {
                        let mut cs: Vec<char> = n.all_text().join("").chars().collect();
                        cs.sort_unstable();
                        cs
                    })
                    .collect();
                sorted.dedup();
                sorted.len() == 1
            },
        )])
        .run(deterministic());
    }
}

/// The CRUD surface an application actually calls, driven by generated
/// operations rather than a fixed script.
///
/// Everything above this point exercises one hardcoded sequence: each node
/// appends twice, on a timer, to one document. These plans instead sample from
/// [`crud_workload`] — appends, whole-document writes, positional inserts and
/// deletes, and reads, spread across a pool of documents and across processes —
/// so the properties hold over many op orderings rather than one.
///
/// No linearizability oracle: a CRDT workspace is deliberately not linearizable,
/// concurrent writes commute rather than serialising, and checking it against a
/// sequential model would report anomalies for correct behaviour. Convergence is
/// the right specification, and it is what these assert.
mod generated_crud_workloads {
    use std::time::Duration;

    use iroh_beekem_sim::{Crud, CrudChurn, Scenario, WorkspaceNode, WorkspaceSpec, crud_workload};
    use propsim::prelude::*;

    use super::{NODES, SEEDS, network_faults};

    /// The ceiling on how many repairs one node may answer in a run.
    ///
    /// Deliberately equal to the simulator's anti-entropy budget: one forced
    /// re-key per round is the most a healthy run can need, since a round is
    /// what produces the unreadable chunk that raises the request.
    const MAX_REPAIRS_PER_NODE: u64 = 24;

    fn workload_plan<S: Scenario>(
        properties: Vec<Property<WorkspaceNode<S>>>,
    ) -> TestPlan<WorkspaceNode<S>> {
        Simulation::plan::<WorkspaceNode<S>>()
            .nodes(NODES)
            .transport(InMemory::unordered_lossy())
            .faults(network_faults())
            .state_machine()
            .workload(crud_workload(NODES))
            .client(WorkspaceSpec)
            .check(properties)
            .seeds(SEEDS)
            .finish()
    }

    fn joined<'a, S: Scenario>(w: &'a World<'a, WorkspaceNode<S>>) -> Vec<&'a WorkspaceNode<S>> {
        w.nodes().filter(|n| n.has_joined()).collect()
    }

    /// Full convergence across every document under a generated workload.
    ///
    /// This is the property the whole repair path exists to make true, and it
    /// was `#[ignore]`d as a known defect until that path existed.
    ///
    /// Under a fixed script every node has joined before the first write, so
    /// nothing is ever written that a peer cannot decrypt. A generated workload
    /// removes that accident: the founder is live at t=0 and writes before
    /// anyone else has joined, so joiners receive chunks encrypted under a key
    /// they will never hold. That much is forward secrecy working as designed.
    /// What was missing was the repair: `Event::Resync` routes through
    /// `publish`, which reuses the *current* epoch key, so re-announcing
    /// unchanged content reproduced a chunk with the same `content_ref` **and**
    /// the same `pcs_key_hash` the stuck peer had already failed on — correctly
    /// deduped by the receiver, and carrying no new information either way.
    /// `Effect::RequestRepair` and `Event::RepairRequested` close that loop by
    /// making the answer mint a fresh epoch.
    ///
    /// Reproduced before the fix with `PROPSIM_SEED=0x03317bb4875fb038`, which
    /// is the seed to reach for if this ever regresses.
    #[test]
    fn every_document_converges_under_a_generated_workload() {
        // Byte-identical, not merely "contains what I wrote". Concurrent inserts
        // have no canonical order, so the assertion is that all replicas agree —
        // never that they agree on a particular string, which would be asserting
        // Loro's internal ordering rather than our convergence.
        workload_plan::<Crud>(vec![property::eventually_within(
            "all documents converge",
            Duration::from_secs(9),
            |w: &World<'_, WorkspaceNode<Crud>>| {
                let nodes = joined(w);
                let Some(first) = nodes.first() else {
                    return false;
                };
                nodes.len() == NODES && nodes.iter().all(|n| n.all_text() == first.all_text())
            },
        )])
        .run(deterministic());
    }

    #[test]
    fn a_generated_workload_never_evicts_anything() {
        // The queue limits exist for hostile traffic. A generated but honest
        // workload reaching them would mean the eviction logic fires when it
        // should not, which shows up as silent data loss rather than a failure.
        workload_plan::<Crud>(vec![property::always(
            "no evictions",
            |w: &World<'_, WorkspaceNode<Crud>>| joined(w).iter().all(|n| n.evictions() == 0),
        )])
        .run(deterministic());
    }

    /// Given a generated workload under partitions, when the network settles,
    /// we expect every node to have joined and every parking queue to be empty.
    ///
    /// The `nodes.len() == NODES` guard is load-bearing and was missing: at t=0
    /// only the founder has joined and its queues are trivially empty, so
    /// without it this `eventually` is satisfied at the first sampled instant
    /// and can never observe a chunk that parks later and never drains — which
    /// is exactly what pre-join ciphertext used to do. The honest-scenario
    /// counterpart has always carried the guard; this one had drifted.
    #[test]
    fn no_chunk_stays_parked_under_a_generated_workload() {
        workload_plan::<Crud>(vec![property::eventually_within(
            "parking drains",
            Duration::from_secs(9),
            |w: &World<'_, WorkspaceNode<Crud>>| {
                let nodes = joined(w);
                nodes.len() == NODES
                    && nodes
                        .iter()
                        .all(|n| n.pending_chunks() == 0 && n.parked_ops() == 0)
            },
        )])
        .run(deterministic());
    }

    /// Given a generated workload, we expect at least one node to receive
    /// content it can never decrypt.
    ///
    /// The counterweight to every property above it. Convergence and empty
    /// parking queues are both satisfied by a run in which the awkward case
    /// never arises — where every node happens to join before anything is
    /// written — and such a run would say nothing about repair. This asserts
    /// the situation the repair path exists for actually occurs, so the
    /// properties that depend on it are not passing vacuously.
    #[test]
    fn a_generated_workload_really_does_strand_a_late_joiner() {
        workload_plan::<Crud>(vec![property::sometimes(
            "some node receives an epoch it cannot derive",
            |w: &World<'_, WorkspaceNode<Crud>>| {
                joined(w).iter().any(|n| n.unreadable_chunks() > 0)
            },
        )])
        .run(deterministic());
    }

    /// Given a node stranded on an epoch it cannot derive, we expect some other
    /// node to answer with a fresh-keyed republish.
    ///
    /// Stated separately from convergence because the two fail differently: a
    /// run where nobody answers still converges if the stranded content happens
    /// to be superseded by a later write, and that would leave the repair path
    /// dead code that nothing notices.
    #[test]
    fn a_stranded_node_is_answered_by_a_repair() {
        workload_plan::<Crud>(vec![property::sometimes(
            "some node answers a repair request",
            |w: &World<'_, WorkspaceNode<Crud>>| joined(w).iter().any(|n| n.repairs_answered() > 0),
        )])
        .run(deterministic());
    }

    /// Given an honest run, we expect no node to answer more repairs than it
    /// performs anti-entropy rounds.
    ///
    /// The hazard this guards is a repair loop that feeds itself: an answer
    /// mints a new epoch and publishes under it, so if that publish could
    /// itself strand somebody the group would re-key without bound, converting
    /// one lost message into permanent churn. A bound of one re-key per
    /// anti-entropy round is far above what a healthy run needs — the runs this
    /// was written against sit around a quarter of it — and far below what a
    /// self-sustaining loop would reach within seconds.
    #[test]
    fn repair_does_not_feed_itself() {
        workload_plan::<Crud>(vec![property::always(
            "repairs stay proportional to anti-entropy rounds",
            |w: &World<'_, WorkspaceNode<Crud>>| {
                joined(w)
                    .iter()
                    .all(|n| n.repairs_answered() <= MAX_REPAIRS_PER_NODE)
            },
        )])
        .run(deterministic());
    }

    #[test]
    fn generated_operations_actually_reach_the_documents() {
        // Guards the harness, not the protocol. If the codec stopped decoding,
        // or ops were never dispatched, every property above would pass
        // vacuously over an empty workspace — so assert the workload did work.
        workload_plan::<Crud>(vec![property::sometimes(
            "some document has content",
            |w: &World<'_, WorkspaceNode<Crud>>| {
                joined(w)
                    .iter()
                    .any(|n| n.all_text().iter().any(|t| !t.is_empty()))
            },
        )])
        .run(deterministic());
    }

    /// Given generated CRUD against a group that is concurrently rotating keys
    /// and losing a member, when the network settles, we expect every surviving
    /// member to hold identical text.
    ///
    /// The hardest combination the simulator can express today. The
    /// `remaining.len() == NODES - 1` guard matters for the same reason it does
    /// in `no_chunk_stays_parked_under_a_generated_workload`: at t=0 only the
    /// founder has joined, so a one-element set agrees with itself and the
    /// property is satisfied before the run has done anything.
    #[test]
    fn the_remaining_members_converge_under_workload_and_churn() {
        workload_plan::<CrudChurn>(vec![property::eventually_within(
            "survivors converge",
            Duration::from_secs(9),
            |w: &World<'_, WorkspaceNode<CrudChurn>>| {
                let remaining: Vec<_> = w
                    .nodes()
                    .filter(|n| n.has_joined() && !n.is_revocation_target())
                    .collect();
                let Some(first) = remaining.first() else {
                    return false;
                };
                remaining.len() == NODES - 1
                    && remaining.iter().all(|n| n.all_text() == first.all_text())
            },
        )])
        .run(deterministic());
    }

    #[test]
    fn a_generated_run_is_reproducible() {
        // The workload is sampled from the seed, so this covers op generation as
        // well as scheduling: a fixed seed must produce the same ops in the same
        // order, or a failing run could never be replayed.
        assert_deterministic(|| workload_plan::<Crud>(Vec::new()), Seed(0x0C0D_E123));
    }
}

/// Admission control: what a node that was never admitted can observe.
///
/// The claim these exist to make executable is that confidentiality against a
/// stranger rests on them not being a member, rather than on them not knowing
/// the gossip topic — which is only the founder's public key, and which every
/// past invitee knows permanently.
///
/// The simulator models the *effect* of refusing a connection: a message from a
/// peer that is not on the roster is dropped before it is observed. That the
/// guard is genuinely wired to `iroh` is proven separately, by
/// `admission_control_is_wired_to_iroh` in the `iroh-beekem` QUIC suite.
mod an_outsider_observes_nothing {
    use std::time::Duration;

    use iroh_beekem_sim::{Outsider, WorkspaceNode};
    use propsim::prelude::*;

    use super::{NODES, plan_of_size};

    /// One more node than the honest group, so the outsider's presence does not
    /// shrink the set of members the other properties are about.
    const NODES_WITH_OUTSIDER: usize = NODES + 1;

    /// Which node never asks to be admitted.
    const OUTSIDER: u64 = 3;

    fn outsider<'a>(
        w: &'a World<'a, WorkspaceNode<Outsider>>,
    ) -> Option<&'a WorkspaceNode<Outsider>> {
        w.nodes().find(|n| n.id() == OUTSIDER)
    }

    fn members<'a>(w: &'a World<'a, WorkspaceNode<Outsider>>) -> Vec<&'a WorkspaceNode<Outsider>> {
        w.nodes()
            .filter(|n| n.id() != OUTSIDER && n.has_joined())
            .collect()
    }

    /// Given a node that never asked to be admitted, at every point in a run in
    /// which the members are actively gossiping, we expect its view of the data
    /// plane to stay empty.
    ///
    /// `always` rather than `eventually`: there is no moment at which an
    /// outsider is allowed to have seen an entry and then forgotten it. Seeing
    /// one at all means it learned that a document exists, how big it is and who
    /// wrote it — the metadata leak the roster exists to close, and one that no
    /// later eviction can undo.
    #[test]
    fn an_unadmitted_node_never_observes_an_index_entry() {
        plan_of_size::<Outsider>(
            NODES_WITH_OUTSIDER,
            vec![property::always(
                "an outsider's modelled replica stays empty",
                |w: &World<'_, WorkspaceNode<Outsider>>| {
                    outsider(w).is_none_or(|n| n.index_len() == 0)
                },
            )],
        )
        .run(deterministic());
    }

    /// Given the same node, at every point in the run, we expect it to observe
    /// no control-plane operation.
    ///
    /// Separate from the property above because the two planes fail
    /// independently: wrapping the gossip ALPN and not the docs one would pass
    /// this and fail that, and wrapping docs and not gossip the reverse. Stating
    /// them together would let either hole hide behind the other.
    #[test]
    fn an_unadmitted_node_never_observes_a_control_operation() {
        plan_of_size::<Outsider>(
            NODES_WITH_OUTSIDER,
            vec![property::always(
                "an outsider sees no CGKA operation",
                |w: &World<'_, WorkspaceNode<Outsider>>| {
                    outsider(w).is_none_or(|n| n.observed_ops() == 0)
                },
            )],
        )
        .run(deterministic());
    }

    /// Given the same node, at every point in the run, we expect it never to
    /// appear on any member's roster.
    ///
    /// The cause behind the two properties above. Asserted separately so that a
    /// failure says *why*: an outsider observing nothing while sitting on
    /// somebody's roster would mean it is being excluded by accident — by
    /// message timing, or by a scenario that happens not to broadcast — rather
    /// than by the membership rule.
    #[test]
    fn an_unadmitted_node_is_on_nobodys_roster() {
        plan_of_size::<Outsider>(
            NODES_WITH_OUTSIDER,
            vec![property::always(
                "no member admits the outsider",
                |w: &World<'_, WorkspaceNode<Outsider>>| {
                    members(w)
                        .iter()
                        .all(|n| !n.is_on_roster(propsim::NodeId(OUTSIDER)))
                },
            )],
        )
        .run(deterministic());
    }

    /// Given a group of members under partitions and reordering, when the
    /// network settles, we expect every member to admit every other member.
    ///
    /// **The counterweight, and the property to write first.** Everything above
    /// is satisfied by a guard that refuses everybody, and such a guard would
    /// break Story 1 — "immediately access workspace files" — in a way that
    /// looks exactly like slow onboarding. This is what makes the refusals mean
    /// something.
    ///
    /// `eventually_within` because the roster derives from the manifest and the
    /// CGKA log, which converge asynchronously. Admission is eventual by
    /// construction, and asserting `always` here would be asserting that the
    /// network is synchronous.
    #[test]
    fn every_member_eventually_admits_every_other_member() {
        plan_of_size::<Outsider>(
            NODES_WITH_OUTSIDER,
            vec![property::eventually_within(
                "members converge on a roster containing each other",
                Duration::from_secs(15),
                |w: &World<'_, WorkspaceNode<Outsider>>| {
                    let members = members(w);
                    if members.len() != NODES {
                        return false;
                    }
                    members.iter().all(|n| {
                        members
                            .iter()
                            .all(|peer| n.is_on_roster(propsim::NodeId(peer.id())))
                    })
                },
            )],
        )
        .run(deterministic());
    }

    /// Given a group whose members admit each other, when the network settles,
    /// we expect the *derived* rosters to agree.
    ///
    /// Derived rather than effective, so the bootstrap exception cannot carry
    /// the property: a joiner accepts its inviter on faith, and if that were the
    /// only thing keeping the overlay connected, a roster that never converged
    /// would still pass `every_member_eventually_admits_every_other_member`.
    #[test]
    fn members_converge_on_the_same_derived_roster() {
        plan_of_size::<Outsider>(
            NODES_WITH_OUTSIDER,
            vec![property::eventually_within(
                "derived rosters agree",
                Duration::from_secs(15),
                |w: &World<'_, WorkspaceNode<Outsider>>| {
                    let members = members(w);
                    if members.len() != NODES {
                        return false;
                    }
                    let mut rosters: Vec<Vec<propsim::NodeId>> =
                        members.iter().map(|n| n.derived_roster()).collect();
                    rosters.dedup();
                    rosters.len() == 1 && rosters[0].len() == NODES
                },
            )],
        )
        .run(deterministic());
    }
}

/// A member that joined legitimately and then acts beyond the role it holds.
///
/// The distinction from [`a_forging_peer_is_rejected`] is the whole point, and it
/// is the reason a green suite hid this for four phases. A forging node signs with
/// a key no `Add` ever introduced, so `known_members` refuses it — that check has
/// always existed. An insider signs with a key the group itself admitted, holding
/// a role the group itself granted. Nothing about its identity is wrong. Until the
/// capability closure existed, no receiver asked what its role permitted, so every
/// operation it issued was merged.
///
/// Every attack here uses certificates the insider genuinely signed. That is what
/// makes the scenario worth having: a check that only rejected malformed input
/// would pass it while changing nothing.
mod an_insider_cannot_exceed_its_role {
    use std::time::Duration;

    use iroh_beekem_sim::{Insider, Role, WorkspaceNode, member_bytes_of};
    use propsim::prelude::*;

    use super::{NODES, plan};

    /// In a workspace where only the founder was granted an administrative role,
    /// upon a member issuing grants promoting itself, we expect no node ever to
    /// see more than one administrator.
    ///
    /// Confirmed to fail before phase 5, in its manifest form: the insider wrote
    /// its own role into the manifest and every replica merged it.
    #[test]
    fn no_node_ever_sees_more_administrators_than_were_granted() {
        plan::<Insider>(vec![property::always(
            "the workspace never has more than its one granted admin",
            |w: &World<'_, WorkspaceNode<Insider>>| {
                w.nodes()
                    .filter(|n| n.has_joined())
                    .all(|n| n.admin_count() <= 1)
            },
        )])
        .run(deterministic());
    }

    /// In a workspace where every member was granted the editor role, upon the
    /// insider issuing an administrative grant for itself, we expect every node to
    /// go on resolving that member to the role it was actually granted.
    ///
    /// Distinct from the count above: a self-promotion that also demoted somebody
    /// else would keep the count at one while still being an escalation.
    #[test]
    fn no_member_ever_holds_a_role_it_was_not_granted() {
        plan::<Insider>(vec![property::always(
            "every member resolves to the role its admission granted",
            |w: &World<'_, WorkspaceNode<Insider>>| {
                let members: Vec<_> = w.nodes().filter(|n| n.has_joined()).collect();
                members.iter().all(|observer| {
                    members.iter().all(|subject| {
                        // The founder is an admin by axiom; every other node was
                        // admitted as an editor by `on_hello`, and nothing in this
                        // scenario legitimately changes that.
                        let expected = if subject.id() == 0 {
                            Role::Admin
                        } else {
                            Role::Editor
                        };
                        observer
                            .role_of(subject.member_bytes())
                            .is_none_or(|role| role == expected)
                    })
                })
            },
        )])
        .run(deterministic());
    }

    /// In a workspace where the insider splices leaves it controls into the tree,
    /// upon those bindings reaching every peer, we expect every certified device
    /// to resolve to a user that was legitimately admitted.
    ///
    /// **Not** stated as "the group never grows", and the difference is a real
    /// design property rather than a weakened assertion. A member may enrol
    /// further devices of its *own* user without an administrative role —
    /// enrolling your own phone is not an act of administration, and requiring an
    /// admin for it would make multi-device support an admin-only operation. So
    /// the tree legitimately grows under this attack, and the leaf count says
    /// nothing about whether anything went wrong.
    ///
    /// What must never happen is a device resolving to a user nobody admitted, or
    /// to somebody else's user — which is the escalation, since a device inherits
    /// its user's role. That is what this counts.
    #[test]
    fn every_certified_device_resolves_to_a_legitimately_admitted_user() {
        plan::<Insider>(vec![property::always(
            "no device is bound to a user the group never admitted",
            |w: &World<'_, WorkspaceNode<Insider>>| {
                // Computed from the cluster rather than from the nodes that have
                // joined: the founder certifies a node before that node has
                // replayed its own `Welcome`, so a set derived from `has_joined`
                // would report a failure during ordinary onboarding.
                let admitted: Vec<[u8; 32]> = (0..NODES as u64).map(member_bytes_of).collect();
                w.nodes().filter(|n| n.has_joined()).all(|observer| {
                    observer
                        .certified_users()
                        .iter()
                        .all(|user| admitted.contains(user))
                })
            },
        )])
        .run(deterministic());
    }

    /// In a workspace where the insider enrols devices for itself, we expect the
    /// number of distinct users to stay at the number of people admitted.
    ///
    /// The sharper form of the property above: self-enrolment may add leaves, but
    /// it must never add *people*, because a person is what a role attaches to.
    #[test]
    fn the_insider_never_creates_a_new_user() {
        plan::<Insider>(vec![property::always(
            "no attack introduces a person the group did not admit",
            |w: &World<'_, WorkspaceNode<Insider>>| {
                w.nodes()
                    .filter(|n| n.has_joined())
                    .all(|n| n.certified_users().len() <= NODES)
            },
        )])
        .run(deterministic());
    }

    /// In a workspace under attack from one of its own members, upon the network
    /// settling, we expect the honest nodes still to converge on identical
    /// documents.
    ///
    /// This is what stops the fix from being "reject more aggressively". A check
    /// that diverged the group or stalled legitimate traffic would satisfy every
    /// property above and be strictly worse than the defect it replaced.
    #[test]
    fn honest_nodes_still_converge_while_under_attack() {
        plan::<Insider>(vec![property::eventually_within(
            "every node converges on the same document despite the insider",
            Duration::from_secs(15),
            |w: &World<'_, WorkspaceNode<Insider>>| {
                let members: Vec<_> = w.nodes().filter(|n| n.has_joined()).collect();
                if members.len() != NODES {
                    return false;
                }
                let mut sorted: Vec<Vec<char>> = members
                    .iter()
                    .map(|n| {
                        let mut cs: Vec<char> = n.document_text().chars().collect();
                        cs.sort_unstable();
                        cs
                    })
                    .collect();
                sorted.dedup();
                sorted.len() == 1 && !sorted[0].is_empty()
            },
        )])
        .run(deterministic());
    }

    /// In a workspace under attack from one of its own members, upon the network
    /// settling, we expect no chunk and no control operation to remain parked.
    ///
    /// The other half of the same concern, and the sharper one. Rejecting an
    /// operation must not strand the legitimate operations queued behind it, and a
    /// rejected insider must not be able to spin the repair path — both are
    /// reachable failure modes of a check applied carelessly, and neither shows up
    /// in a convergence property.
    #[test]
    fn rejection_never_strands_the_queues() {
        plan::<Insider>(vec![property::eventually_within(
            "nothing stays parked once the network settles",
            Duration::from_secs(15),
            |w: &World<'_, WorkspaceNode<Insider>>| {
                w.nodes()
                    .filter(|n| n.has_joined())
                    .all(|n| n.pending_chunks() == 0 && n.parked_ops() == 0)
            },
        )])
        .run(deterministic());
    }

    /// In a workspace under attack from one of its own members, upon the run
    /// completing, we expect the insider's own view to stay usable.
    ///
    /// A node whose operations everyone rejects must not diverge into a permanent
    /// repair loop. It is still a member in good standing for reading, and a fix
    /// that made the attacker's own replica unusable would be punishing the wrong
    /// thing — and would show up in production as a member that mysteriously
    /// stopped syncing.
    #[test]
    fn the_insiders_own_view_stays_self_consistent() {
        plan::<Insider>(vec![property::eventually_within(
            "the insider still reads what the group wrote",
            Duration::from_secs(15),
            |w: &World<'_, WorkspaceNode<Insider>>| {
                w.nodes()
                    .filter(|n| n.has_joined() && n.id() == 2)
                    .all(|n| !n.document_text().is_empty() && n.pending_chunks() == 0)
            },
        )])
        .run(deterministic());
    }
}

/// A member that keeps acting after it has been removed.
///
/// The one attacker the merge-time capability check deliberately does **not**
/// refuse, and the reason is worth restating because it looks like a gap: a
/// removed member keeps whatever capability it held, since the certificate store
/// is grow-only, and its signature stays admissible, since `known_members` is
/// monotone. The only thing distinguishing its operations is `current_members`,
/// which is order-sensitive — so refusing on it would make two peers that saw the
/// removal and the operation in opposite orders drop *different* operations, and
/// the group would diverge permanently. That is a worse failure than the one being
/// fixed.
///
/// So the splice is accepted and then undone. These properties are therefore
/// `eventually_within` where the insider's are `always`, and that difference is
/// the honest statement of what removal buys: a bounded window, not zero.
mod a_removed_member_is_evicted_again {
    use std::time::Duration;

    use iroh_beekem_sim::{Revenant, WorkspaceNode};
    use propsim::prelude::*;

    use super::{NODES, plan};

    /// The nodes still in the group after the scenario's revocation.
    fn remaining<'a>(
        w: &'a World<'a, WorkspaceNode<Revenant>>,
    ) -> Vec<&'a WorkspaceNode<Revenant>> {
        w.nodes()
            .filter(|n| n.has_joined() && n.id() != 2)
            .collect()
    }

    /// In a workspace where a removed member splices leaves it controls back into
    /// the tree, upon the network settling, we expect every remaining member's
    /// group to be back down to the members that belong in it.
    ///
    /// Eviction, stated as the observable it produces. Each honest admin reaches
    /// this conclusion independently from the same operation, and duplicate
    /// removals merge as `MergeOutcome::Duplicate`, so no coordination is needed.
    #[test]
    fn every_spliced_leaf_is_eventually_removed_again() {
        plan::<Revenant>(vec![property::eventually_within(
            "the group returns to its legitimate size after the splices",
            Duration::from_secs(20),
            |w: &World<'_, WorkspaceNode<Revenant>>| {
                let members = remaining(w);
                !members.is_empty()
                    // The victim is gone, so the legitimate size is below the
                    // cluster; anything at or above it is a leaf still spliced in.
                    && members.iter().all(|n| (n.group_size() as usize) < NODES)
            },
        )])
        .run(deterministic());
    }

    /// In a workspace where a removed member splices leaves back in, we expect
    /// no remaining member ever to see more administrators than were granted.
    ///
    /// The `always` half, and the one that must hold *throughout* the eviction
    /// window rather than after it. A splice buys the revenant a leaf for a while;
    /// what it must never buy is authority, because the closure is rooted and a
    /// revenant can pass on only what it already had.
    #[test]
    fn a_splice_never_confers_authority_the_splicer_lacked() {
        plan::<Revenant>(vec![property::always(
            "the admin count never rises, splice or no splice",
            |w: &World<'_, WorkspaceNode<Revenant>>| {
                remaining(w).iter().all(|n| n.admin_count() <= 1)
            },
        )])
        .run(deterministic());
    }

    /// In a workspace where a removed member keeps issuing, upon the network
    /// settling, we expect the remaining members still to converge.
    ///
    /// Eviction costs a removal *and* a namespace rotation each time, so an
    /// eviction path that fired without bound would keep the group rotating
    /// forever and nothing would ever converge. This is the property that would
    /// catch that.
    #[test]
    fn the_remaining_members_still_converge_through_the_evictions() {
        plan::<Revenant>(vec![property::eventually_within(
            "the remaining members agree on one namespace and one document",
            Duration::from_secs(20),
            |w: &World<'_, WorkspaceNode<Revenant>>| {
                let members = remaining(w);
                if members.len() < 2 {
                    return false;
                }
                let mut namespaces: Vec<_> = members.iter().map(|n| n.namespace()).collect();
                namespaces.dedup();
                let mut sorted: Vec<Vec<char>> = members
                    .iter()
                    .map(|n| {
                        let mut cs: Vec<char> = n.document_text().chars().collect();
                        cs.sort_unstable();
                        cs
                    })
                    .collect();
                sorted.dedup();
                namespaces.len() == 1 && sorted.len() == 1
            },
        )])
        .run(deterministic());
    }
}

/// What a stolen admission ticket is actually worth — Story 4, property 4.6.
///
/// The README used to say invites are "replayable", which understated one half
/// and overstated the other. A leaked ticket does **not** grant read access:
/// joining needs the invitee's leaf secret, whose public half the inviter named
/// in the `Add`, and that secret never travels in a ticket. What it does grant is
/// visibility — the inviter to dial and the replica to watch.
///
/// The scenario models a thief that ignores every check this library performs,
/// because an attacker runs its own code. So none of what follows is a claim
/// about the invitee binding, the expiry or the single-use nonce; those are
/// verified against the real `Invite` in the `iroh-beekem` suite, where the clock
/// and the nonce ledger live. What follows is a claim about what remains once an
/// attacker has ignored all three: it can watch, it cannot read, and a namespace
/// rotation ends even the watching.
mod a_stolen_invite_buys_only_visibility {
    use std::time::Duration;

    use iroh_beekem_sim::{
        POST_REVOCATION_DOC, StolenInvite, WorkspaceNode, doc_key, member_bytes_of,
    };
    use propsim::prelude::*;

    use super::{NODES, plan_of_size};

    /// One more node than the honest group, so the thief's presence does not
    /// shrink the set of members the other properties are about.
    const NODES_WITH_THIEF: usize = NODES + 1;

    /// Which node redeems a ticket it was never issued.
    const THIEF: u64 = 3;

    fn thief<'a>(
        w: &'a World<'a, WorkspaceNode<StolenInvite>>,
    ) -> Option<&'a WorkspaceNode<StolenInvite>> {
        w.nodes().find(|n| n.id() == THIEF)
    }

    /// The members still in the group after the revocation the leak provokes.
    fn remaining<'a>(
        w: &'a World<'a, WorkspaceNode<StolenInvite>>,
    ) -> Vec<&'a WorkspaceNode<StolenInvite>> {
        w.nodes()
            .filter(|n| n.id() != THIEF && n.has_joined() && !n.is_revocation_target())
            .collect()
    }

    /// Given a node holding a ticket issued to somebody else, at every point in
    /// the run, we expect no member to record it as a person or a device.
    ///
    /// The first clause of 4.6. A ticket carries the operation log and the
    /// certificate store, both public, signed data — so a thief can read the
    /// whole membership. Reading it must not put the thief *in* it: nothing in a
    /// ticket is an admission, because the admission is the `Add` the inviter
    /// already issued for a leaf the thief does not hold.
    #[test]
    fn a_stolen_invite_never_enters_any_members_user_list() {
        plan_of_size::<StolenInvite>(
            NODES_WITH_THIEF,
            vec![property::always(
                "no member's capability closure resolves any device to the thief",
                |w: &World<'_, WorkspaceNode<StolenInvite>>| {
                    let thief_user = member_bytes_of(THIEF);
                    w.nodes().filter(|n| n.has_joined()).all(|n| {
                        !n.certified_users().contains(&thief_user)
                            && n.role_of(thief_user).is_none()
                    })
                },
            )],
        )
        .run(deterministic());
    }

    /// Given the same node, at every point in the run, we expect it to hold no
    /// group state and to read no document text.
    ///
    /// The second clause of 4.6, and the one that says the README's old wording
    /// was wrong in the thief's favour. `has_joined()` is false because
    /// `CgkaController::join` needs the leaf secret to derive the group key, and
    /// `all_text()` is empty because there is no state to read it out of. Both
    /// are asserted, not just the second: a thief that somehow built state and
    /// happened to read nothing would be one lucky delivery order away from
    /// reading everything.
    #[test]
    fn a_stolen_invite_never_reconstructs_the_group_or_reads_content() {
        plan_of_size::<StolenInvite>(
            NODES_WITH_THIEF,
            vec![property::always(
                "the thief joins nothing and decrypts nothing",
                |w: &World<'_, WorkspaceNode<StolenInvite>>| {
                    thief(w).is_none_or(|t| {
                        !t.has_joined() && t.all_text().iter().all(String::is_empty)
                    })
                },
            )],
        )
        .run(deterministic());
    }

    /// Given the group rotates its namespace, at every point in the run, we
    /// expect the thief never to observe an entry written after the rotation.
    ///
    /// The third clause of 4.6, and the group's actual remedy for a leaked
    /// ticket: there is nothing in a bearer token to revoke, so what ends the
    /// exposure is abandoning the replica the token names. `always` rather than
    /// `eventually`, for the same reason as the revoked victim's counterpart —
    /// seeing the entry once is a leak no later rotation can unlearn.
    #[test]
    fn a_stolen_invite_stops_seeing_entries_once_the_group_rotates() {
        plan_of_size::<StolenInvite>(
            NODES_WITH_THIEF,
            vec![property::always(
                "the thief observes no entry written after the rotation",
                |w: &World<'_, WorkspaceNode<StolenInvite>>| {
                    thief(w).is_none_or(|t| t.entry(&doc_key(POST_REVOCATION_DOC)).is_none())
                },
            )],
        )
        .run(deterministic());
    }

    /// Given the same run, when it settles, we expect the theft to have actually
    /// happened and to have bought the thief *something*.
    ///
    /// **The counterweight, and the property to write first.** Every assertion
    /// above is satisfied by a run in which the leaked ticket never arrived, or
    /// in which nobody ever wrote anything — and such a run proves nothing about
    /// the protocol. This is what makes the three above claims about a bound on
    /// real exposure rather than accidents of timing. It is also the honest half
    /// of the README's new wording: a stolen ticket *does* let a stranger watch
    /// the replica until the group rotates, and that is a residual to state
    /// rather than one to imply.
    #[test]
    fn the_stolen_invite_does_reach_the_thief_and_does_show_it_the_replica() {
        plan_of_size::<StolenInvite>(
            NODES_WITH_THIEF,
            vec![property::eventually_within(
                "the thief holds the ticket and has seen at least one entry",
                Duration::from_secs(10),
                |w: &World<'_, WorkspaceNode<StolenInvite>>| {
                    thief(w).is_some_and(|t| t.holds_stolen_invite() && t.index_len() > 0)
                },
            )],
        )
        .run(deterministic());
    }

    /// Given the members whose ticket leaked, when the run settles, we expect
    /// them to converge regardless.
    ///
    /// The other counterweight. Everything above is satisfied by a group that
    /// rotated itself into oblivion, and the rotation here is provoked by a
    /// removal — so this is what says the remedy for a leaked ticket costs the
    /// remaining members nothing but a generation.
    #[test]
    fn the_remaining_members_converge_through_the_rotation() {
        plan_of_size::<StolenInvite>(
            NODES_WITH_THIEF,
            vec![property::eventually_within(
                "the remaining members agree on one namespace and one document",
                Duration::from_secs(20),
                |w: &World<'_, WorkspaceNode<StolenInvite>>| {
                    let members = remaining(w);
                    if members.len() < 2 {
                        return false;
                    }
                    let mut namespaces: Vec<_> = members.iter().map(|n| n.namespace()).collect();
                    namespaces.dedup();
                    let mut sorted: Vec<Vec<char>> = members
                        .iter()
                        .map(|n| {
                            let mut cs: Vec<char> = n.document_text().chars().collect();
                            cs.sort_unstable();
                            cs
                        })
                        .collect();
                    sorted.dedup();
                    namespaces.len() == 1 && sorted.len() == 1
                },
            )],
        )
        .run(deterministic());
    }
}

/// Story 2, `OfflineEdit` — "offline" in the two senses it can mean.
///
/// A node can be offline because it cannot *reach* anybody, or because it is not
/// *running*. Both variants converge afterwards, and only the second says
/// anything about persistence — which is why they are separate plans rather than
/// one plan with more faults.
///
/// Both use [`Faults::scripted`] rather than the swarm plan every other module
/// here runs under, and the choice costs something worth naming. Scripted and
/// swarm specs are mutually exclusive in propsim, so these plans get no
/// `latency_ms` or `reorder` from `Faults`; what they still get is
/// `InMemory::unordered_lossy`, which supplies delay, reordering, two percent
/// loss and one percent duplication at the transport layer regardless. What
/// scripting buys in exchange is the one thing the swarm plan cannot do: place
/// the fault at a chosen instant, so the run is guaranteed to contain the window
/// the properties are about.
mod an_offline_node_catches_up {
    use propsim::prelude::*;

    use super::{Duration, Honest, NODES, SEEDS, WorkspaceNode, joined};

    /// When the fault lands, and when it is undone.
    ///
    /// Late enough that the group has formed and written something — the first
    /// edit fires at 300ms and the first resync at 600ms — and early enough to
    /// leave the rest of the horizon for catching up. The horizon is
    /// `last scripted event + 10s`, so healing at four seconds gives a fourteen
    /// second run and ten seconds of settling.
    const FAULT_AT: Duration = Duration::from_millis(1500);
    const REPAIR_AT: Duration = Duration::from_secs(4);

    /// The ordinary member that goes away in the partition and crash variants.
    const VICTIM: u64 = 2;

    /// The founder, which gets a crash variant of its own.
    ///
    /// Both are needed, and the reason is that they fail differently. A crashed
    /// *member* that resumed wrongly would re-run the join handshake — except
    /// that `on_welcome` refuses to act on a node that already has state, so a
    /// harness that forgot to branch on a restart would still look correct from
    /// the member's side. A crashed *founder* has no such guard:
    /// `on_start`'s founding branch is unconditional, so it would overwrite the
    /// live workspace with a brand-new tree and fork the group under a second
    /// root. Only this variant can catch that, which makes it the one that keeps
    /// `no_node_ever_initialises_the_workspace_more_than_once` from being
    /// vacuous.
    const FOUNDER_VICTIM: u64 = 0;

    fn scripted_plan(
        faults: Faults,
        properties: Vec<Property<WorkspaceNode<Honest>>>,
    ) -> TestPlan<WorkspaceNode<Honest>> {
        Simulation::plan::<WorkspaceNode<Honest>>()
            .nodes(NODES)
            .transport(InMemory::unordered_lossy())
            .faults(faults)
            .state_machine()
            .check(properties)
            .seeds(SEEDS)
            .finish()
    }

    /// The disconnected variant: node 2 is severed, then reconnected.
    fn partitioned(
        properties: Vec<Property<WorkspaceNode<Honest>>>,
    ) -> TestPlan<WorkspaceNode<Honest>> {
        scripted_plan(
            Faults::scripted()
                .at(FAULT_AT)
                .partition(&[0, 1], &[VICTIM])
                .at(REPAIR_AT)
                .heal_all(),
            properties,
        )
    }

    /// The shut-down variant: one node stops, then starts again.
    fn crashed_node(
        victim: u64,
        properties: Vec<Property<WorkspaceNode<Honest>>>,
    ) -> TestPlan<WorkspaceNode<Honest>> {
        scripted_plan(
            Faults::scripted()
                .at(FAULT_AT)
                .crash(victim)
                .at(REPAIR_AT)
                .restart(victim),
            properties,
        )
    }

    /// An ordinary member stops and starts again.
    fn crashed(
        properties: Vec<Property<WorkspaceNode<Honest>>>,
    ) -> TestPlan<WorkspaceNode<Honest>> {
        crashed_node(VICTIM, properties)
    }

    /// The group's only admin stops and starts again.
    fn crashed_founder(
        properties: Vec<Property<WorkspaceNode<Honest>>>,
    ) -> TestPlan<WorkspaceNode<Honest>> {
        crashed_node(FOUNDER_VICTIM, properties)
    }

    /// The multiset of characters in a node's every document.
    ///
    /// Compared rather than the string itself because Loro's ordering of
    /// concurrent inserts is an implementation detail; what convergence claims
    /// is that no node holds a character another does not.
    fn shape(node: &WorkspaceNode<Honest>) -> Vec<char> {
        let mut chars: Vec<char> = node.all_text().concat().chars().collect();
        chars.sort_unstable();
        chars
    }

    /// In a group partitioned in two and later healed, upon the network
    /// settling, we expect every node to hold the same content.
    ///
    /// The severed node keeps editing throughout — nothing suppresses its
    /// timers — so this is a genuine two-sided reconciliation and not a
    /// catch-up by an idle peer.
    #[test]
    fn every_document_converges_after_the_partition_heals() {
        partitioned(vec![
            property::eventually_within(
                "every node holds the same content after the partition heals",
                Duration::from_secs(9),
                |w: &World<'_, WorkspaceNode<Honest>>| {
                    let nodes = joined(w);
                    // Guarded on the count: at t=0 only the founder has joined, and
                    // a one-element set agrees with itself trivially.
                    nodes.len() == NODES && nodes.windows(2).all(|p| shape(p[0]) == shape(p[1]))
                },
            )
            .after(Event::NetworkHealed),
        ])
        .run(deterministic());
    }

    /// In a partitioned group, upon a node writing on either side of the split,
    /// we expect that node to be able to read its own write immediately.
    ///
    /// Local-first means a partition costs reachability, never local progress. A
    /// node that could not read back what it just wrote while cut off would have
    /// made the write conditional on the network, which is the property this
    /// whole design exists to avoid.
    #[test]
    fn a_nodes_own_writes_are_readable_locally_throughout_the_partition() {
        partitioned(vec![property::always(
            "every joined node can read its own contributions at all times",
            |w: &World<'_, WorkspaceNode<Honest>>| {
                joined(w).iter().all(|n| {
                    let text = n.document_text();
                    n.contributed().iter().all(|frag| text.contains(frag))
                })
            },
        )])
        .run(deterministic());
    }

    /// In a partitioned group, upon healing, we expect the derived rosters and
    /// the role assignments to agree again.
    ///
    /// Content converging is not enough on its own: the roster and the
    /// capability closure travel on the control plane, and a heal that restored
    /// the data plane while leaving membership split would look like success
    /// from every text-only property.
    #[test]
    fn membership_and_roles_converge_after_the_partition_heals() {
        partitioned(vec![
            property::eventually_within(
                "every node derives the same roster after the partition heals",
                Duration::from_secs(9),
                |w: &World<'_, WorkspaceNode<Honest>>| {
                    let nodes = joined(w);
                    nodes.len() == NODES
                        && nodes
                            .windows(2)
                            .all(|p| p[0].derived_roster() == p[1].derived_roster())
                        && nodes.iter().all(|n| n.admin_count() == 1)
                },
            )
            .after(Event::NetworkHealed),
        ])
        .run(deterministic());
    }

    /// In a group where one node crashes and restarts, upon the node rejoining,
    /// we expect every node to hold the same content again.
    #[test]
    fn every_document_converges_after_the_crashed_node_restarts() {
        crashed(vec![
            property::eventually_within(
                "every node holds the same content after the restart",
                Duration::from_secs(9),
                |w: &World<'_, WorkspaceNode<Honest>>| {
                    let nodes = joined(w);
                    nodes.len() == NODES && nodes.windows(2).all(|p| shape(p[0]) == shape(p[1]))
                },
            )
            .after(Event::NodeRejoined),
        ])
        .run(deterministic());
    }

    /// In a group where a node restarts, upon it coming back, we expect it never
    /// to have founded or joined the workspace a second time.
    ///
    /// **This is the property that keeps the harness honest**, and without it
    /// every other property in this module would pass against a restart that was
    /// really a re-invitation. propsim freezes a crashed node rather than
    /// destroying it, so a node that did nothing on its second `on_start` would
    /// still hold all its state and still converge; and a node that re-ran
    /// `on_start`'s founding branch would fork the group under a second root
    /// while *also* still converging on the honest path, because there is only
    /// one node that founds.
    #[test]
    fn no_node_ever_initialises_the_workspace_more_than_once() {
        crashed_founder(vec![property::always(
            "no node founds or joins the workspace twice",
            |w: &World<'_, WorkspaceNode<Honest>>| w.nodes().all(|n| n.initialisations() <= 1),
        )])
        .run(deterministic());
    }

    /// In a group where a node restarts, upon it coming back, we expect the
    /// writes it had acknowledged before the crash to still be in its own view.
    ///
    /// This is what "written before acknowledged" buys. The simulated disk is
    /// updated inside `on_client_op` before the response is returned, exactly as
    /// `Workspace::drive` writes before returning `Ok`, so a fragment this node
    /// promised to keep must survive its own amnesia.
    #[test]
    fn a_restarted_node_still_holds_the_writes_it_acknowledged() {
        crashed(vec![property::always(
            "a node's acknowledged writes are in its own view even after a restart",
            |w: &World<'_, WorkspaceNode<Honest>>| {
                w.nodes().filter(|n| n.has_joined()).all(|n| {
                    let text = n.document_text();
                    n.contributed().iter().all(|frag| text.contains(frag))
                })
            },
        )])
        .run(deterministic());
    }

    /// In this plan, upon the scripted crash firing, we expect a node to have
    /// actually restarted from a disk it had actually written.
    ///
    /// The anti-vacuity guard for the four properties above. Every one of them
    /// is satisfied by a run in which nothing ever crashed, and three of them by
    /// a run in which the crashed node had never written a snapshot — so without
    /// this the module could go green while testing none of what it names.
    #[test]
    fn the_run_really_does_crash_a_node_that_had_something_to_lose() {
        crashed(vec![property::sometimes(
            "some node restarts from a disk it had written",
            |w: &World<'_, WorkspaceNode<Honest>>| {
                w.nodes().any(|n| n.reboots() > 0 && n.has_disk())
            },
        )])
        .run(deterministic());
    }

    /// In this plan, upon a node restarting, we expect it to be a member again.
    ///
    /// Separate from convergence on purpose. A restarted node that came back
    /// with no state would trivially satisfy every `always` above — it
    /// contributes nothing to compare — and would be filtered out of `joined`
    /// entirely. This is the property that says the disk was actually read.
    #[test]
    fn a_restarted_node_is_a_member_again_without_being_re_invited() {
        crashed(vec![
            property::eventually_within(
                "every node is joined again after the restart",
                Duration::from_secs(9),
                |w: &World<'_, WorkspaceNode<Honest>>| joined(w).len() == NODES,
            )
            .after(Event::NodeRejoined),
        ])
        .run(deterministic());
    }

    /// In a group whose founder crashes and restarts, upon the network settling,
    /// we expect every node to hold the same content.
    ///
    /// The second of the two properties that catch a founder resuming as a fresh
    /// start, and it catches it by a different route than
    /// `no_node_ever_initialises_the_workspace_more_than_once`: a re-founded
    /// node holds an empty workspace over a second tree, so it converges with
    /// nobody.
    ///
    /// Worth recording what does *not* catch it, because it looks like it
    /// should: asserting `admin_count() == 1` everywhere. A re-founded node is
    /// the sole admin of its own new tree, so it reports exactly one
    /// administrator, and so does everybody else. The fork is invisible to any
    /// property that asks each node about itself rather than comparing them.
    #[test]
    fn every_document_converges_after_the_founder_restarts() {
        crashed_founder(vec![
            property::eventually_within(
                "every node holds the same content after the founder restarts",
                Duration::from_secs(9),
                |w: &World<'_, WorkspaceNode<Honest>>| {
                    let nodes = joined(w);
                    nodes.len() == NODES && nodes.windows(2).all(|p| shape(p[0]) == shape(p[1]))
                },
            )
            .after(Event::NodeRejoined),
        ])
        .run(deterministic());
    }

    /// Reproducibility, as every other scenario asserts it.
    #[test]
    fn the_restart_run_is_reproducible() {
        assert_deterministic(|| crashed(Vec::new()), Seed(0x0DEA_D515));
    }
}

/// A member that walks away, as distinct from one the group throws out.
///
/// Every other membership change in this suite is issued by the founder. A
/// departure is issued by the departing member, needs no administrative role,
/// and — the part that is easy to get wrong — rotates nothing. Getting it wrong
/// is silent: a `leave` built as a self-issued `RemoveMember` would rotate the
/// namespace, every convergence property would still pass, and the leaver would
/// have minted and then received the capability for the replica it was leaving.
mod a_member_leaves_of_its_own_accord {
    use std::time::Duration;

    use iroh_beekem_sim::{Departure, WorkspaceNode};
    use propsim::prelude::*;

    use super::{NODES, joined, plan};

    /// The nodes that are staying.
    fn remaining<'a>(
        w: &'a World<'a, WorkspaceNode<Departure>>,
    ) -> Vec<&'a WorkspaceNode<Departure>> {
        joined(w)
            .into_iter()
            .filter(|n| !n.is_departing())
            .collect()
    }

    /// In a group one of whose members leaves, upon the network settling, we
    /// expect the remaining members to stop counting it.
    #[test]
    fn a_departing_member_eventually_leaves_every_remaining_members_group() {
        plan::<Departure>(vec![property::eventually_within(
            "every remaining member's group has shrunk by one",
            Duration::from_secs(12),
            |w: &World<'_, WorkspaceNode<Departure>>| {
                let staying = remaining(w);
                staying.len() == NODES - 1
                    && staying
                        .iter()
                        .all(|n| u32::try_from(NODES - 1) == Ok(n.group_size()))
            },
        )])
        .run(deterministic());
    }

    /// In a group one of whose members leaves, upon the departure, we expect no
    /// node to move to a new namespace.
    ///
    /// The behavioural difference from a removal, stated as the property that
    /// would catch it collapsing. A leaver cannot usefully rotate: it would mint
    /// the capability and announce it under a group key it still holds, giving
    /// itself the replica it had just walked away from. Rotation after a
    /// departure is the group's job, and this scenario deliberately has nobody
    /// do it.
    #[test]
    fn a_departure_never_rotates_the_namespace() {
        plan::<Departure>(vec![property::always(
            "no node ever adopts a rotated namespace",
            |w: &World<'_, WorkspaceNode<Departure>>| w.nodes().all(|n| !n.has_rotated()),
        )])
        .run(deterministic());
    }

    /// In a group one of whose members leaves, upon the network settling, we
    /// expect every *remaining* member to still be on every other remaining
    /// member's roster.
    ///
    /// `Event::Leave` retracts every device of the *local* user and no others.
    /// A version that removed by role, or that iterated the wrong certificate
    /// map, would let a departing viewer take the administrator with it — and
    /// every peer would accept it, since a `Remove` naming a member of the
    /// issuer's own user is authorised without any role at all.
    ///
    /// Stated as an eventual claim about *who* is left, not as an invariant
    /// about how many. `group_size` legitimately climbs from one as the group
    /// onboards, so an `always` bound on it is false at t=0 for reasons that
    /// have nothing to do with departures — the "guard the length" hazard this
    /// suite runs into whenever a count is asserted before the group has formed.
    #[test]
    fn a_departure_never_retracts_anybody_elses_leaf() {
        plan::<Departure>(vec![property::eventually_within(
            "every remaining member derives a roster containing every other one",
            Duration::from_secs(12),
            |w: &World<'_, WorkspaceNode<Departure>>| {
                let staying = remaining(w);
                staying.len() == NODES - 1
                    && staying.iter().all(|n| {
                        staying
                            .iter()
                            .all(|other| n.is_on_roster(NodeId(other.id())))
                            && n.admin_count() == 1
                    })
            },
        )])
        .run(deterministic());
    }

    /// In a group one of whose members leaves, upon the network settling, we
    /// expect the remaining members to hold identical content.
    ///
    /// A departure removes leaves from the tree, which forces a re-key on
    /// everyone still in it. Convergence through that is the liveness half of
    /// the story: the safety properties above are all satisfied by a group that
    /// simply stopped.
    #[test]
    fn the_remaining_members_converge_through_the_departure() {
        plan::<Departure>(vec![property::eventually_within(
            "the remaining members hold the same content",
            Duration::from_secs(12),
            |w: &World<'_, WorkspaceNode<Departure>>| {
                let staying = remaining(w);
                staying.len() == NODES - 1 && staying.windows(2).all(|p| shape(p[0]) == shape(p[1]))
            },
        )])
        .run(deterministic());
    }

    /// The multiset of characters across every document.
    fn shape(node: &WorkspaceNode<Departure>) -> Vec<char> {
        let mut chars: Vec<char> = node.all_text().concat().chars().collect();
        chars.sort_unstable();
        chars
    }

    /// In this plan, upon the run finishing, we expect the departure to have
    /// actually happened.
    ///
    /// The anti-vacuity guard. `a_departure_never_rotates_the_namespace` and
    /// `a_departure_never_retracts_anybody_elses_leaf` are both satisfied by a
    /// run in which nobody ever left.
    #[test]
    fn somebody_really_does_leave_in_this_run() {
        plan::<Departure>(vec![property::sometimes(
            "the departing node has issued its departure",
            |w: &World<'_, WorkspaceNode<Departure>>| w.nodes().any(WorkspaceNode::has_left),
        )])
        .run(deterministic());
    }

    /// Reproducibility, as every other scenario asserts it.
    #[test]
    fn the_departure_run_is_reproducible() {
        assert_deterministic(|| plan::<Departure>(Vec::new()), Seed(0x0DEA_2712));
    }
}

/// M-of-N: a workspace where one admin acting alone is not enough.
///
/// The founder promotes node 1 and raises the threshold to two — both while the
/// threshold is still one, which is the only route off the default — and then
/// proposes removing node 2. Four nodes, so the victim is neither of the admins
/// deciding on it.
///
/// What makes this worth asserting under a network rather than in a unit test is
/// that the quorum is computed from a *replicated* certificate set: every node
/// resolves the threshold and the approver count for itself, and two nodes that
/// disagreed would execute different actions.
mod an_action_needs_a_quorum {
    use std::time::Duration;

    use iroh_beekem_sim::{Quorum, WorkspaceNode};
    use propsim::prelude::*;

    use super::{SEEDS, joined, plan_of_size};

    /// One more than the honest group, so the removal target is not an approver.
    const NODES_WITH_VICTIM: usize = 4;
    /// The node the founder proposes to remove.
    const VICTIM: u64 = 2;

    fn quorum_plan(
        properties: Vec<Property<WorkspaceNode<Quorum>>>,
    ) -> TestPlan<WorkspaceNode<Quorum>> {
        plan_of_size(NODES_WITH_VICTIM, properties)
    }

    /// Nodes that are not the removal target.
    fn survivors<'a>(w: &'a World<'a, WorkspaceNode<Quorum>>) -> Vec<&'a WorkspaceNode<Quorum>> {
        joined(w).into_iter().filter(|n| n.id() != VICTIM).collect()
    }

    /// In a workspace whose threshold is two, upon any proposal, we expect no
    /// node ever to treat it as executable on fewer than two approvals.
    ///
    /// The core property of the phase, asserted where it is hardest to hold: the
    /// approver count is derived from certificates that arrive in any order, are
    /// duplicated by the transport, and are re-shipped whole on every log
    /// exchange. A count that double-counted a re-delivered approval would
    /// satisfy a unit test and fail here.
    #[test]
    fn no_proposal_is_executable_below_the_threshold() {
        quorum_plan(vec![property::always(
            "no node treats a proposal as executable on too few approvals",
            |w: &World<'_, WorkspaceNode<Quorum>>| {
                w.nodes().all(|n| {
                    n.proposals().iter().all(|status| {
                        !status.executable || status.approvals >= status.required as usize
                    })
                })
            },
        )])
        .run(deterministic());
    }

    /// In a workspace whose threshold is two, upon the network settling, we
    /// expect the proposed removal to have been carried out everywhere.
    ///
    /// The counterweight to every `always` here: an implementation that refused
    /// all quorum actions would satisfy them and fail this.
    #[test]
    fn a_proposal_with_enough_approvals_is_eventually_performed_everywhere() {
        quorum_plan(vec![property::eventually_within(
            "every remaining admin's group has lost the proposed member",
            Duration::from_secs(12),
            |w: &World<'_, WorkspaceNode<Quorum>>| {
                let staying = survivors(w);
                staying.len() == NODES_WITH_VICTIM - 1
                    && staying.iter().all(|n| {
                        u32::try_from(NODES_WITH_VICTIM).is_ok_and(|all| n.group_size() < all)
                    })
            },
        )])
        .run(deterministic());
    }

    /// In a workspace founded at a threshold of two, upon every node joining, we
    /// expect all of them to agree on what the threshold is.
    ///
    /// The soundness of the receiver-side check rests on this. The threshold is
    /// read off the founder's policy, which travels in the same certificate
    /// bundle without which a node could not have joined at all — so a member
    /// cannot be behind on it, and no two members can merge different sets of
    /// operations because they disagreed about the bar.
    #[test]
    fn every_node_resolves_the_same_threshold() {
        quorum_plan(vec![property::eventually_within(
            "every joined node reports the same threshold",
            Duration::from_secs(12),
            |w: &World<'_, WorkspaceNode<Quorum>>| {
                let nodes = joined(w);
                nodes.len() == NODES_WITH_VICTIM && nodes.iter().all(|n| n.threshold() == 2)
            },
        )])
        .run(deterministic());
    }

    /// In a workspace founded at a threshold of two, upon the run finishing, we
    /// expect no node ever to have seen more administrators than the founder
    /// appointed.
    ///
    /// The founder's bootstrap exemption is narrow on purpose, and this is what
    /// keeps it narrow: nobody the founder appoints inherits the power to appoint
    /// further admins, or an admin could raise a puppet and approve its own
    /// actions twice.
    #[test]
    fn nobody_but_the_founder_can_add_an_administrator() {
        quorum_plan(vec![property::always(
            "no node ever sees more than two administrators",
            |w: &World<'_, WorkspaceNode<Quorum>>| joined(w).iter().all(|n| n.admin_count() <= 2),
        )])
        .run(deterministic());
    }

    /// In this plan, upon the run finishing, we expect a quorum to have actually
    /// been reached.
    ///
    /// The anti-vacuity guard. `no_proposal_is_executable_below_the_threshold`
    /// is satisfied by a run in which nothing was ever proposed, and
    /// `nobody_but_the_founder_can_add_an_administrator` by one in which nobody
    /// tried.
    #[test]
    fn a_quorum_is_actually_reached_in_this_run() {
        quorum_plan(vec![property::sometimes(
            "some node holds a proposal that reached a threshold above one",
            |w: &World<'_, WorkspaceNode<Quorum>>| {
                w.nodes().any(|n| {
                    n.threshold() > 1
                        && n.proposals()
                            .iter()
                            .any(|status| status.executable && status.approvals >= 2)
                })
            },
        )])
        .run(deterministic());
    }

    /// In a workspace under a quorum, upon the network settling, we expect the
    /// remaining members still to converge.
    ///
    /// Refusing more aggressively is not a fix. A threshold that stalled the
    /// group, or an execution path that every replica ran differently, would
    /// satisfy every safety property above.
    #[test]
    fn the_remaining_members_still_converge_under_a_quorum() {
        quorum_plan(vec![property::eventually_within(
            "the remaining members hold the same content",
            Duration::from_secs(12),
            |w: &World<'_, WorkspaceNode<Quorum>>| {
                let staying = survivors(w);
                staying.len() == NODES_WITH_VICTIM - 1
                    && staying.windows(2).all(|p| {
                        let mut a: Vec<char> = p[0].all_text().concat().chars().collect();
                        let mut b: Vec<char> = p[1].all_text().concat().chars().collect();
                        a.sort_unstable();
                        b.sort_unstable();
                        a == b
                    })
            },
        )])
        .run(deterministic());
    }

    /// Reproducibility, as every other scenario asserts it.
    #[test]
    fn the_quorum_run_is_reproducible() {
        let _ = SEEDS;
        assert_deterministic(|| quorum_plan(Vec::new()), Seed(0x0000_9401));
    }
}
