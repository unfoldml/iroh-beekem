//! Property tests over the simulated workspace.
//!
//! These are the assertions unit tests cannot reach: they hold across every
//! interleaving the simulator generates, under an unordered and lossy
//! transport, over many seeds.

use std::time::Duration;

use iroh_beekem_sim::WorkspaceNode;
use propsim::prelude::*;

const NODES: usize = 3;
const SEEDS: usize = 6;

/// Nodes that have finished joining the group.
fn joined<'a>(w: &'a World<'a, WorkspaceNode>) -> Vec<&'a WorkspaceNode> {
    w.nodes().filter(|n| n.has_joined()).collect()
}

fn base_plan(properties: Vec<Property<WorkspaceNode>>) -> TestPlan<WorkspaceNode> {
    Simulation::plan::<WorkspaceNode>()
        .nodes(NODES)
        .transport(InMemory::unordered_lossy())
        .state_machine()
        .check(properties)
        .seeds(SEEDS)
        .finish()
}

#[test]
fn every_node_eventually_joins_the_group() {
    base_plan(vec![property::eventually_within(
        "all nodes join",
        Duration::from_secs(5),
        |w: &World<'_, WorkspaceNode>| joined(w).len() == NODES,
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
        |w: &World<'_, WorkspaceNode>| {
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
        |w: &World<'_, WorkspaceNode>| {
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
        |w: &World<'_, WorkspaceNode>| {
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
        |w: &World<'_, WorkspaceNode>| {
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
        |w: &World<'_, WorkspaceNode>| {
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
        |w: &World<'_, WorkspaceNode>| joined(w).iter().all(|n| n.evictions() == 0),
    )])
    .run(deterministic());
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
