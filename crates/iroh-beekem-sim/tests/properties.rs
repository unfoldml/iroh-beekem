//! Property tests over the simulated workspace.
//!
//! These are the assertions unit tests cannot reach: they hold across every
//! interleaving the simulator generates, under an unordered and lossy
//! transport, over many seeds.

use std::time::Duration;

use iroh_beekem_sim::{Honest, Scenario, WorkspaceNode};
use propsim::prelude::*;

const NODES: usize = 3;
const SEEDS: usize = 6;

/// Nodes that have finished joining the group.
fn joined<'a, S: Scenario>(w: &'a World<'a, WorkspaceNode<S>>) -> Vec<&'a WorkspaceNode<S>> {
    w.nodes().filter(|n| n.has_joined()).collect()
}

/// The network conditions every plan runs under.
///
/// Partitions in particular are not decoration. The roster derives from state
/// that converges asynchronously, so eviction and admission are both *eventual*
/// — and on a perfect network every "eventually" collapses to "immediately",
/// which would let a roster that never converges pass. Reordering matters for
/// the same reason: a device record and the `Add` that authorises it travel on
/// different planes and routinely arrive out of order.
fn network_faults() -> Faults {
    Faults::swarm().partitions().latency_ms(1..40).reorder()
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
mod a_removed_member_still_watches {
    use iroh_beekem_sim::{Churn, WorkspaceNode};
    use propsim::prelude::*;

    use super::plan;

    /// The victim's own view, once the run has settled.
    fn victim<'a>(w: &'a World<'a, WorkspaceNode<Churn>>) -> Option<&'a WorkspaceNode<Churn>> {
        w.nodes()
            .find(|n| n.is_revocation_target() && n.has_joined())
    }

    #[test]
    fn the_victim_sees_index_entries_it_can_never_decrypt() {
        // Visibility is not readability. This passing is not a good thing — it
        // is the statement of the gap, and it should be inverted the moment
        // namespace rotation lands.
        plan::<Churn>(vec![property::sometimes(
            "the victim observes entries",
            |w: &World<'_, WorkspaceNode<Churn>>| victim(w).is_some_and(|v| v.index_len() > 0),
        )])
        .run(deterministic());
    }

    #[test]
    fn the_victim_keeps_observing_the_control_plane() {
        // The gossip topic is derived from the tree id, which every past invitee
        // knows, so removal does not unsubscribe anyone. Membership churn stays
        // visible to the removed member indefinitely.
        plan::<Churn>(vec![property::sometimes(
            "the victim observes control operations",
            |w: &World<'_, WorkspaceNode<Churn>>| victim(w).is_some_and(|v| v.observed_ops() > 0),
        )])
        .run(deterministic());
    }

    #[test]
    fn every_node_sees_the_same_entries_once_settled() {
        // The index is replicated, so it converges like everything else. This
        // one is a genuine invariant rather than a recorded gap, and it is what
        // the visibility properties above are stated against.
        plan::<Churn>(vec![property::eventually_within(
            "indices converge",
            Duration::from_secs(8),
            |w: &World<'_, WorkspaceNode<Churn>>| {
                let joined: Vec<_> = w.nodes().filter(|n| n.has_joined()).collect();
                let Some(first) = joined.first() else {
                    return false;
                };
                joined
                    .iter()
                    .all(|n| n.observed_keys() == first.observed_keys())
            },
        )])
        .run(deterministic());
    }

    use std::time::Duration;
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
