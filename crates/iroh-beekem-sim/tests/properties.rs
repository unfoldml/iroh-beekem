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

fn plan<S: Scenario>(properties: Vec<Property<WorkspaceNode<S>>>) -> TestPlan<WorkspaceNode<S>> {
    Simulation::plan::<WorkspaceNode<S>>()
        .nodes(NODES)
        .transport(InMemory::unordered_lossy())
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
            joined(w)
                .iter()
                .all(|n| n.group_size() as usize <= NODES)
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
    use super::{plan, NODES};
    use iroh_beekem_sim::{Churn, WorkspaceNode};
    use propsim::prelude::*;
    use std::time::Duration;

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
    use super::{plan, NODES};
    use iroh_beekem_sim::{Forging, WorkspaceNode};
    use propsim::prelude::*;
    use std::time::Duration;

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
                w.nodes().filter(|n| n.has_joined()).all(|n| n.evictions() == 0)
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
