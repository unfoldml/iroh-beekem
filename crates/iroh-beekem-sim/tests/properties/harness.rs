//! The world runner: one simulation per seed, every property read from every trace.
//!
//! # Why this exists rather than `TestPlan::run`
//!
//! `Run::run` drives every seed, but it **aborts at the first failing property of
//! the first failing seed**, and it throws away the shrunk counterexample it just
//! computed — `RunFailure::Violation` carries a `Scenario`, and `run` renders only
//! the property name and the seed. That was tolerable when a plan carried one
//! property. It is not tolerable now that a plan carries a world's whole vector,
//! because "one property failed on one seed" and "every property failed on every
//! seed" are different defects with different causes, and the abort cannot tell
//! them apart.
//!
//! So this module drives the engine directly. Everything it uses is public API:
//! [`TestPlan::into_parts`], [`run_deterministic`], [`evaluate_properties`] and
//! [`TestPlan::replay`]. It is the same path `propsim::assert_deterministic` and
//! propsim's own `worked_example` test take.
//!
//! # What it costs
//!
//! Nothing extra on the passing path: one `run_deterministic` per seed, exactly as
//! `drive` does, and a read-only scan of the recorded frames per property. The
//! failure path pays for the shrink, which is bounded by the operation count.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use iroh_beekem_sim::{Scenario, WorkspaceNode, WorkspaceSpec};
use propsim::prelude::{Faults, InMemory, Property, Seed, Simulation, TestPlan};
use propsim::{FrozenOp, NodeId, OpKind, Scenario as OpStream, Value, Verdict};
use propsim_sim::{evaluate_properties, run_deterministic};

/// The seeds every world runs.
///
/// Written out rather than derived, because propsim's `effective_seed` is
/// private: reproducing it would tie this suite to an implementation detail of a
/// pinned revision, and it offers no way to add a seed or to drop one that turns
/// out to duplicate another's fault subset.
///
/// The six values are propsim's own derived seeds for run indices 0 to 5, adopted
/// verbatim. That is deliberate: taking the runner into this crate then changed
/// **no** verdict, so a failure appearing afterwards is a real finding and not an
/// artefact of a different random stream. Index 1 is `0x03317bb4875fb038`, the
/// seed `a_generated_crud_workload` names as its regression handle.
///
/// A seed is world diversity in its own right. propsim lowers a swarm fault plan
/// by enabling each declared fault kind with probability one half, so two seeds
/// of the same world meet different networks.
pub const SEEDS: [Seed; 6] = [
    Seed(0x1CC1_52E4_7D17_4D3C),
    Seed(0x0331_7BB4_875F_B038),
    Seed(0x8C44_E9EF_30CA_4931),
    Seed(0xAC4D_D164_1A6E_5CA4),
    Seed(0xC42D_DC64_6A6F_A046),
    Seed(0x7060_FF71_0DF8_D712),
];

/// How many client operations a generated workload samples in one run.
///
/// propsim spells this `.seeds(n)`, and on a plan it means two unrelated things:
/// how many seeds `drive` loops over, and how many operations to draw from the
/// workload strategy (`data.seeds.clamp(1, 64)`). This runner does not call
/// `drive`, so under it only the second meaning survives. **How many seeds a world
/// runs is [`SEEDS`]**, and the two numbers are free to differ.
///
/// It stays at six because that is what the suite generated before the runner
/// moved into this crate, and holding it fixed is what makes that move assert
/// exactly what it asserted before.
const OPS_PER_RUN: usize = 6;

/// The generated workload a world draws its content changes from.
///
/// A function pointer rather than a `BoxedStrategy`, because a [`Shape`] is a
/// constant and a strategy is neither `Copy` nor constructible in a `const`.
pub type Workload = fn(usize) -> proptest::strategy::BoxedStrategy<FrozenOp>;

/// What distinguishes one simulated world from another, beside its scenario.
///
/// A world is a scenario placed in a shape. Holding the shape as data is what
/// makes a new world cost a line: the same property vector under a clean network
/// and under a cruel one is two worlds, and neither needs the properties rewritten.
#[derive(Clone, Copy)]
pub struct Shape {
    /// Cluster size.
    ///
    /// It must exceed every node id its scenario names — `Outsider` names node 3,
    /// so four is that scenario's floor. Nodes above the named ids are ordinary
    /// members, so raising this is always meaningful and never changes the roles.
    pub nodes: usize,
    /// The network the world runs on.
    ///
    /// A function rather than a value, because `Faults` is not `Copy` and a shape
    /// is a constant.
    pub faults: fn() -> Faults,
    /// The generated workload, or `None` to let the scenario run its own fixed
    /// script of edits.
    ///
    /// This must agree with `Scenario::WORKLOAD`. That constant is what stops a
    /// node scheduling its own edits, and running both mixes a fixed script into a
    /// generated one, after which neither explains a result.
    pub workload: Option<Workload>,
}

impl Shape {
    /// A world of `nodes` devices on the given network, with no generated workload.
    pub const fn new(nodes: usize, faults: fn() -> Faults) -> Self {
        Shape {
            nodes,
            faults,
            workload: None,
        }
    }

    /// The same shape, with content driven by a generated workload.
    pub const fn driven_by(self, workload: Workload) -> Self {
        Shape {
            workload: Some(workload),
            ..self
        }
    }

    /// The same shape over a different cluster size.
    pub const fn sized(self, nodes: usize) -> Self {
        Shape { nodes, ..self }
    }

}

/// The plan one world builds.
fn world_plan<S: Scenario>(
    shape: Shape,
    properties: Vec<Property<WorkspaceNode<S>>>,
) -> TestPlan<WorkspaceNode<S>> {
    let plan = Simulation::plan::<WorkspaceNode<S>>()
        .nodes(shape.nodes)
        .transport(InMemory::unordered_lossy())
        .faults((shape.faults)())
        .state_machine()
        .check(properties)
        .seeds(OPS_PER_RUN);
    match shape.workload {
        Some(workload) => plan
            .workload(workload(shape.nodes))
            .client(WorkspaceSpec)
            .finish(),
        None => plan.finish(),
    }
}

/// The same plan a world runs, for the determinism guards.
///
/// `assert_deterministic` compares two histories and reads no property, so it is
/// given an empty vector: a history is a function of the shape and the seed.
pub fn plan_of<S: Scenario>(shape: Shape) -> TestPlan<WorkspaceNode<S>> {
    world_plan::<S>(shape, Vec::new())
}

/// Run one world and assert every property in it, on every seed.
///
/// `properties` is a closure rather than a value for two reasons: a `Property`
/// holds a boxed closure and is not `Clone`, so each seed needs its own vector;
/// and it receives the cluster size, so one vector states its claims for whatever
/// size the shape gives it instead of hard-coding one.
///
/// On failure this panics with the whole failing (property, seed) matrix and, for
/// a world that generates client operations, the shortest operation stream that
/// still reproduces the first failure.
pub fn check_world<S, MakeProps>(world: &str, shape: Shape, properties: MakeProps)
where
    S: Scenario,
    MakeProps: Fn(usize) -> Vec<Property<WorkspaceNode<S>>>,
{
    let mut failures: BTreeMap<String, Vec<Seed>> = BTreeMap::new();
    let mut reasons: BTreeMap<String, String> = BTreeMap::new();
    let mut checked = 0usize;

    for &seed in &SEEDS {
        let (data, node_def, workload, client, props) =
            world_plan(shape, properties(shape.nodes)).into_parts();
        checked = props.len();
        let run = run_deterministic::<WorkspaceNode<S>>(
            &data,
            node_def.as_ref(),
            workload.as_ref(),
            client.as_deref(),
            seed,
        )
        .unwrap_or_else(|failure| {
            panic!("world `{world}`: the executor refused the plan at seed {seed}: {failure}")
        });

        for named in evaluate_properties(&props, &run.world_trace, &run.events) {
            if !named.verdict.valid {
                reasons
                    .entry(named.name.clone())
                    .or_insert_with(|| reason(&named.verdict));
                failures.entry(named.name).or_default().push(seed);
            }
        }
    }

    assert!(checked > 0, "world `{world}` asserts no properties at all");
    if failures.is_empty() {
        return;
    }
    panic!(
        "{}",
        report(world, checked, &failures, &reasons, shape, &properties)
    );
}

/// The anomaly a verdict recorded, as one line.
///
/// propsim names the kind (`invariant-violated`, `reachability-unmet`,
/// `deadline-exceeded`) and carries the frame time in the detail, which together
/// say whether a property was never true, or was true and then stopped being so.
fn reason(verdict: &Verdict) -> String {
    verdict
        .anomalies
        .iter()
        .map(|a| match &a.detail {
            Some(d) => format!("{}: {d}", a.kind),
            None => a.kind.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The failure message: the matrix first, then the counterexample.
fn report<S, MakeProps>(
    world: &str,
    checked: usize,
    failures: &BTreeMap<String, Vec<Seed>>,
    reasons: &BTreeMap<String, String>,
    shape: Shape,
    properties: &MakeProps,
) -> String
where
    S: Scenario,
    MakeProps: Fn(usize) -> Vec<Property<WorkspaceNode<S>>>,
{
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\nworld `{world}`: {} of {checked} properties failed over {} seeds \
         ({} nodes)\n",
        failures.len(),
        SEEDS.len(),
        shape.nodes,
    );
    for (name, seeds) in failures {
        let all = if seeds.len() == SEEDS.len() {
            " (every seed)"
        } else {
            ""
        };
        let _ = writeln!(out, "  `{name}`{all}");
        let _ = writeln!(
            out,
            "      seeds: {}",
            seeds
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(why) = reasons.get(name) {
            let _ = writeln!(out, "      {why}");
        } else {
            // Every failing verdict carries at least one anomaly, so this arm is
            // unreachable in practice; it exists because a silent gap here would
            // read as "no reason given" rather than as a defect in this runner.
            let _ = writeln!(out, "      (no anomaly recorded — report this)");
        }
    }
    let _ = writeln!(
        out,
        "\n  {} of {checked} properties held on every seed.",
        checked - failures.len()
    );

    // Shrink the first failure only. Every shrink step is a full simulation, and
    // one minimal counterexample is what a reader acts on.
    let (name, seeds) = failures.iter().next().expect("failures is not empty");
    let seed = seeds[0];
    match shrink(shape, properties, name, seed) {
        Shrunk::NoOperations => {
            let _ = writeln!(
                out,
                "\n  This world generates no client operations, so there is nothing to shrink:\n  \
                 the counterexample is seed {seed} and the world's own fault plan."
            );
        }
        Shrunk::Stream { minimal, full } => {
            let _ = writeln!(
                out,
                "\n  Shortest operation stream still failing `{name}` at seed {seed} \
                 ({} of {full} operations):",
                minimal.len()
            );
            for op in &minimal {
                let _ = writeln!(out, "      process {} {}", op.process.0, edn(&op.op));
            }
        }
    }
    let _ = writeln!(
        out,
        "\n  Re-run this world alone:\n      \
         cargo test -p iroh-beekem-sim --test properties {world}"
    );
    out
}

/// The outcome of shrinking: a world without a workload has no stream at all.
enum Shrunk {
    /// The world generates no client operations.
    NoOperations,
    /// The shortest failing prefix, and how long the full stream was.
    Stream { minimal: Vec<FrozenOp>, full: usize },
}

/// The shortest prefix of the generated operation stream that still fails `name`.
///
/// The same shrink propsim performs — truncation of the operation stream, which is
/// the cheap deterministic one — reimplemented here because `Run::run` discards its
/// result. It shrinks the operations and **nothing else**: not the fault schedule,
/// not the cluster size, not the seed. A world with no workload therefore has no
/// counterexample beyond its seed, which is why the worlds that can carry a
/// workload do.
fn shrink<S, MakeProps>(shape: Shape, properties: &MakeProps, name: &str, seed: Seed) -> Shrunk
where
    S: Scenario,
    MakeProps: Fn(usize) -> Vec<Property<WorkspaceNode<S>>>,
{
    if shape.workload.is_none() {
        return Shrunk::NoOperations;
    }
    let (data, node_def, workload, client, _props) =
        world_plan(shape, properties(shape.nodes)).into_parts();
    let faults = data.faults.clone().unwrap_or_else(Faults::swarm);
    let Ok(run) = run_deterministic::<WorkspaceNode<S>>(
        &data,
        node_def.as_ref(),
        workload.as_ref(),
        client.as_deref(),
        seed,
    ) else {
        return Shrunk::NoOperations;
    };

    // Recover the generated stream from the recorded invocations.
    let full: Vec<FrozenOp> = run
        .history
        .entries()
        .iter()
        .filter(|e| matches!(e.kind, OpKind::Invoke))
        .map(|e| FrozenOp::new(NodeId(e.process.0), e.value.clone()))
        .collect();
    if full.is_empty() {
        return Shrunk::NoOperations;
    }

    // Greedy prefix minimisation: drop the last operation for as long as the
    // failure survives. Linear in the stream length, which propsim caps at 64.
    let mut best = full.clone();
    while best.len() > 1 {
        let candidate = best[..best.len() - 1].to_vec();
        if still_fails(shape, properties, name, seed, &candidate, &faults) {
            best = candidate;
        } else {
            break;
        }
    }
    Shrunk::Stream {
        minimal: best,
        full: full.len(),
    }
}

/// Whether `name` still fails at `seed` with the operation stream pinned to `ops`.
fn still_fails<S, MakeProps>(
    shape: Shape,
    properties: &MakeProps,
    name: &str,
    seed: Seed,
    ops: &[FrozenOp],
    faults: &Faults,
) -> bool
where
    S: Scenario,
    MakeProps: Fn(usize) -> Vec<Property<WorkspaceNode<S>>>,
{
    let plan = world_plan(shape, properties(shape.nodes))
        .replay(OpStream::new(ops.to_vec(), faults.clone()));
    let (data, node_def, _workload, client, props) = plan.into_parts();
    // The workload is deliberately dropped: a pinned replay must issue the given
    // operations and not sample fresh ones.
    let Ok(run) = run_deterministic::<WorkspaceNode<S>>(
        &data,
        node_def.as_ref(),
        None,
        client.as_deref(),
        seed,
    ) else {
        return false;
    };
    evaluate_properties(&props, &run.world_trace, &run.events)
        .iter()
        .any(|named| named.name == name && !named.verdict.valid)
}

/// A generated operation in the notation `WorkspaceSpec` decodes, so a
/// counterexample can be read back into the workload that produced it.
fn edn(value: &Value) -> String {
    match value {
        Value::Nil => "nil".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Str(s) => format!("{s:?}"),
        Value::Keyword(k) => format!(":{k}"),
        Value::List(items) => format!("[{}]", items.iter().map(edn).collect::<Vec<_>>().join(" ")),
        Value::Map(pairs) => format!(
            "{{{}}}",
            pairs
                .iter()
                .map(|(k, v)| format!("{} {}", edn(k), edn(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
