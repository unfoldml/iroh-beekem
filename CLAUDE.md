# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

[docs/USER_STORIES.md](docs/USER_STORIES.md) states what this project is *for* and takes precedence
over anything here. This file describes what exists *today* — the project is early, and most of what
follows is a current choice rather than a settled one.

## Commands

```bash
cargo test -p iroh-beekem-core   # pure engine: CGKA loop, state machine, forgery rejection
cargo test -p iroh-beekem-sim    # propsim: convergence, rotation/revocation, forging peer, outsiders
                                 # ~5 min: runs under swarm faults (partitions, latency, reorder)
cargo test -p iroh-beekem        # two real endpoints over real QUIC

cargo run -p iroh-beekem --example two_node   # full two-peer session, prints progress
cargo clippy --workspace --all-targets -- -D warnings
```

Integration tests live in `crates/<crate>/tests/*.rs`; select one file with `--test <file-stem>`
and one test by name:

```bash
cargo test -p iroh-beekem-sim --test properties documents_converge_once_the_network_settles
cargo test -p iroh-beekem-core --test workspace_state
```

`cargo clippy --all-features` pulls in a substantially larger dependency set (`arbitrary`, `objc2`, …)
and needs several GB of free disk ; check available disk space and confirm with the user before calling with --all-features .

## Crates

Three crates ([Cargo.toml](Cargo.toml)):

| Crate | Role |
|---|---|
| `iroh-beekem-core` | The state machine and the crypto |
| `iroh-beekem` | iroh wiring and the async `Workspace` facade |
| `iroh-beekem-sim` | `propsim` nodes and property tests driving the core deterministically |

## The one structural rule

**`iroh-beekem-core` performs no I/O.** `WorkspaceState::handle(Event, csprng) -> Vec<Effect>`
([state.rs](crates/iroh-beekem-core/src/state.rs)) is the single entry point to the protocol; the
core returns what it wants done and two backends perform it — `apply_effects`
([workspace.rs](crates/iroh-beekem/src/workspace.rs)) and `WorkspaceNode::drive`
([lib.rs](crates/iroh-beekem-sim/src/lib.rs)).

This is the only thing in this file framed as an invariant, and it earns that because it constrains
*where code lives*, not *what the protocol is* — no design option below is foreclosed by keeping it.
It is also mechanically enforced; this must match nothing:

```bash
cargo tree -p iroh-beekem-core -e normal --prefix none \
  | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'
```

- Never add tokio, iroh, quinn, an async runtime, a clock, or filesystem access to the core.
  `sync_poll::now_or_never` lets beekem's `async fn`s be called from sync code, and propsim's
  `Node::on_msg` is a synchronous callback — a state machine needing a runtime could not be plugged
  into the simulator at all. `CoreError::SignerYielded` is the loud failure if a signer ever stops
  being ready-on-poll.
- **Adding an `Event` or `Effect` variant means updating both backends**, or the simulator and the
  real transport silently diverge in behaviour.


## Engineering and Coding practices

- Priorities when building a new feature or refactoring a preexisting one: first, make it correct. Second, make it principled (the API must follow textbook implementation and adhere to theory). Then, make it performant.
- Never, ever stub out implementations, or make simplifying assumptions without asking the user. Only deliver complete features.
- If you find code that is stubbed out, ask the user to expand the scope and fix it.
- Don't guess performance; set up targeted benchmarks and measure instead.
- Prefer total functions (i.e. producing an output for each value of the input). When total functions are not possible, use a sum type (e.g. Option, or implement an informative custom one) to enumerate the output cases.
- As a corollary of the above, do not panic but use an "error"-like enum branch
- Every "if" must have an "else" branch.
- Comment all code with its purpose
- When building or refactoring a feature, strive to balance terse implementations with readability. Micro-functions (e.g. helpers used once) should be inlined, whereas shared functionality should be exported.
- **Use the Rust Analyzer plugin** for symbol references, go-to-definition, and warnings rather than grepping (ask "What's the definition for this symbol?").
- **Implement property tests rather than unit tests** for algorithms and data transformations (`proptest`). Test "business" logic, not trivial data-structure properties.
- Use straight and unambiguous language in all the descriptive test comments: in <precondition> , upon <input / triggering event> , we expect <state change / output >. This is necessary because the property tests are the living documentation of the project.
- **Improve coverage of code you touch.** When you add or change a code path, add tests that exercise it — property tests first (per the bullet above), unit tests only for the irreducible cases. Measure with `make coverage`, which regenerates [COVERAGE.md](COVERAGE.md) (a merged report across every test manifest); its "lowest-covered files" list is the standing to-do surface. Coverage is advisory today (`make coverage-check` enforces a soft floor but is not yet in `make check`) — treat a coverage drop on files you edited as a defect to fix before declaring done.
- **In-memory / referentially-pure** implementations wherever possible : pure algorithms do no IO (disk, sockets), which keeps them in-memory-testable. For distributed algorithms, test with `propsim`. 
- **No mocking** : test real implementations only.
- Architecture and designs live in [docs/](docs/) and must be periodically reviewed. Mark or remove assumptions/conventions that no longer hold or are speculative.


## Current implementation — revisable

These are today's answers, with the reasoning that produced them and what else moves if they change.
None of them is settled; if a user story needs a different answer, change it.

- **Three protocols by ALPN on one `iroh::Endpoint`** ([node.rs](crates/iroh-beekem/src/node.rs)):
  gossip carries `Signed<CgkaOperation>` on a topic derived from the CGKA tree id, docs carries the
  index of blinded keys → content hashes, blobs carries the encrypted payloads. Spawn order matters
  as written: blobs and gossip before docs, which is handed both.
- **Missed control operations are repaired by re-shipping the whole log** on `NeighborUp`
  (`ControlMsg::Log`, [wire.rs](crates/iroh-beekem/src/wire.rs)). A peer that misses an operation can
  never derive keys for anything encrypted after it, so *some* repair is needed; whole-log resend is
  simply the cheapest one to write.
- **Unreadable content is repaired on demand, by the peer that cannot read it.** A member admitted
  after content existed can never derive the epoch that content was keyed under, and anti-entropy
  cannot fix that: `Event::Resync` re-encrypts under the *current* epoch, so for such a peer every
  repeat reproduces a ciphertext it already failed on. `Effect::RequestRepair` names the
  `(target, epoch)` it is stuck on, and `Event::RepairRequested` is answered by re-publishing through
  `Keying::Fresh`, which mints an epoch every leaf in the tree can derive and nothing outside it can
  ([state.rs](crates/iroh-beekem-core/src/state.rs)). Demand-driven rather than scheduled because
  answering costs a tree operation: the alternative, re-keying on a timer, charges the whole group
  for a peer that may not exist.
- **Content flows through Loro as CRDT updates**, so a chunk applies only when the CGKA can reach the
  PCS key it names *and* Loro has the operations it depends on — that second condition is what
  `park_chunk` / `drain_pending` / `try_apply` in [state.rs](crates/iroh-beekem-core/src/state.rs)
  exist for. Both parking areas are bounded (`MAX_PARKED_OPS`, `MAX_PENDING_CHUNK_BYTES`,
  `MAX_PENDING_CHUNKS`) and evict oldest-first, because unbounded queues are a remote
  memory-exhaustion vector; a property test asserts an honest run never evicts. A payload path that
  did not route through the CRDT would not need the second condition at all.
- **Storage keys are blinded**: `BLAKE3-MAC(workspace_secret, document_uuid)`, fixed 32 bytes, keyed
  on a stable UUID rather than a path so a rename touches only the encrypted manifest
  ([blinding.rs](crates/iroh-beekem-core/src/blinding.rs)). Follows from `iroh-docs` reconciling by
  key with keys in the clear.
- **The manifest is where permissions live**
  ([manifest.rs](crates/iroh-beekem-core/src/manifest.rs)): logical paths, roles, and the `iroh-docs`
  author → CGKA member mapping. The CGKA decides who *can* decrypt; the manifest decides who is
  *authorised* to act. `ingest_all` ([workspace.rs](crates/iroh-beekem/src/workspace.rs)) therefore
  reads the manifest before document entries — `author_may_write` needs the mapping, so the reverse
  order rejects legitimate entries.
- **Authentication is ours, not beekem's.** beekem verifies nothing, so `CgkaController::merge`
  ([keys.rs](crates/iroh-beekem-core/src/keys.rs)) adds the two checks that make a public gossip topic
  safe: signature against the embedded issuer key, then issuer ∈ `known_members`. Order matters —
  membership is checked only *after* predecessors are in hand, or a member whose own `Add` is still in
  flight would be rejected. `known_members` is currently monotone (a `Remove` does not retract) because
  retracting would make admissibility depend on delivery order and diverge peers.
- **Admission control is an authenticated allowlist over endpoint ids.** All three ALPNs are wrapped
  in `RosterGuard` ([roster.rs](crates/iroh-beekem/src/roster.rs)); an `EndpointId` is the peer's
  public key, authenticated by the QUIC handshake. The roster is *derived*, never authored —
  `WorkspaceState::roster` ([state.rs](crates/iroh-beekem-core/src/state.rs)) intersects the
  manifest's device addresses with `current_members` — so it converges like everything else and
  inherits the admin gating on `AddUser`/`AddDevice`. Computed in the core so the rule is testable
  without a socket. Eviction is eventual, and it is an availability boundary, not a confidentiality
  one.

## Easy to break by accident

Properties of the code as currently written. Changing the surrounding design may retire these; changing
them *without* noticing will not fail loudly.

- **Key material must be broadcast before the chunk it keys.** `encrypt_keyed` returns the operations
  a publish minted — beekem's implicit PCS update, or the deliberate re-key of a repair — and
  `publish_keyed`/`publish_manifest` push every one as `Effect::BroadcastOp` ahead of the store
  effect. Reordering them makes content permanently undecryptable for peers.
- **A repair must go through `Keying::Fresh`; anti-entropy must not.** They differ in exactly one
  respect and it is the whole mechanism: `Keying::Current` lets beekem decide whether to re-key,
  which for a peer that cannot derive the current epoch means "no" forever. Routing repair through
  the ordinary publish path would restore the original defect while leaving every test name intact —
  `anti_entropy_repeats_an_epoch_while_a_repair_advances_it` in
  [workspace_state.rs](crates/iroh-beekem-core/tests/workspace_state.rs) is the one that would fail.
- **"Not yet" and "never" are different verdicts on an undecryptable chunk.** `CgkaController::decrypt`
  distinguishes them by asking whether the operation that established the chunk's epoch is in the
  local graph; `try_apply` parks the first and drops the second. Collapsing them back into a bool
  fails silently — permanently unreadable ciphertext accumulates in the pending queue, and the
  `eventually` properties that watch that queue can still be satisfied at t=0.
- **`WorkspaceState`'s `Clone` is hand-written on purpose.** `LoroDoc::clone` returns another handle
  onto the *same* document; a derived `Clone` would give the simulator a snapshot that keeps mutating
  underneath it. The impl round-trips through a Loro snapshot.
- **`WorkspaceState::found` vs `joined`.** The founder records itself as the first admin; a joiner
  must not, or Loro converges on a workspace with an administrator nobody appointed.
- **`known_members` and `current_members` are two sets on purpose.** The first is the
  *authorisation* predicate and must stay monotone, because disagreeing costs a dropped operation and
  permanent divergence. The second is the *enumeration and connection-policy* predicate and is allowed
  to be order-sensitive, because disagreeing costs a refused connection the next merge repairs.
  Collapsing them has no safe direction: monotone, and a revoked device stays admitted forever;
  non-monotone, and `merge` starts rejecting on a delivery-order-dependent predicate.
- **The manifest needs its own anti-entropy.** It is published only when it *changes*, so unlike a
  document it has no later write to carry lost content. `Event::ResyncManifest` exists for that, and
  both `Workspace::resync`/`republish` and the simulator's resync tick must drive it — device records
  live in the manifest, and the roster derives from device records, so a lost manifest chunk costs a
  peer its place on somebody's roster until the next membership change happens to republish it.
- **The simulator must model the control plane's repair, not just the data plane's.** A lost
  `Msg::Op` is unrecoverable — a peer that misses the operation establishing a PCS key can never
  derive it, and re-announcing content re-encrypts under that same key. `Msg::Log` is the simulator's
  counterpart to `ControlMsg::Log`; without it the harness is strictly more fragile than production
  and every resulting failure is an artefact.
- **Pinned dependencies are pinned for a reason** (see comments in the manifests): `rand` at 0.8.5 to
  unify with beekem's public API, `propsim` at a git rev because it has no semver.

## Conventions

- Workspace lints (`[workspace.lints.clippy]`) deny `all` and `redundant_clone`, warn `pedantic`.
  Both library crates are `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.
- [clippy.toml](clippy.toml) holds `doc-valid-idents` for protocol names (BeeKEM, CGKA, RBSR, …).
  Extend that list rather than backticking a protocol name in prose.
- rustfmt: `imports_granularity = "Crate"`, `group_imports = "StdExternalCrate"`.
- Doc comments and test assertion messages here explain *why* a rule exists, often naming the failure
  it prevents. Match that density; a bare `assert!` with no message is out of place.
- Tests are deterministic wherever possible: seeded `ChaCha20Rng` in core and sim, `eventually`/`never`
  polling helpers (not fixed sleeps) in the networked tests.

## Known gaps

[README.md](README.md) has the authoritative "Current trade-offs" and "Not yet implemented" lists.
Consult them before proposing a fix for something already recorded.
