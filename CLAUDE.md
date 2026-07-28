# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

[docs/USER_STORIES.md](docs/USER_STORIES.md) states what this project is *for* and takes precedence
over anything here. This file describes what exists *today* — the project is early, and most of what
follows is a current choice rather than a settled one.

## Commands

```bash
cargo test -p iroh-beekem-core   # pure engine: CGKA loop, state machine, forgery rejection
cargo test -p iroh-beekem-sim    # propsim: convergence, concurrent rotation/revocation, forging peer
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

## Easy to break by accident

Properties of the code as currently written. Changing the surrounding design may retire these; changing
them *without* noticing will not fail loudly.

- **An implicit PCS update must be broadcast before the chunk it keys.** `CgkaController::encrypt`
  returns `Option<Signed<CgkaOperation>>`; both `publish` and `publish_manifest` push
  `Effect::BroadcastOp` ahead of the store effect for this reason. Reordering them makes content
  permanently undecryptable for peers.
- **`WorkspaceState`'s `Clone` is hand-written on purpose.** `LoroDoc::clone` returns another handle
  onto the *same* document; a derived `Clone` would give the simulator a snapshot that keeps mutating
  underneath it. The impl round-trips through a Loro snapshot.
- **`WorkspaceState::found` vs `joined`.** The founder records itself as the first admin; a joiner
  must not, or Loro converges on a workspace with an administrator nobody appointed.
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
