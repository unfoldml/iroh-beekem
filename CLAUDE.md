# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

[docs/USER_STORIES.md](docs/USER_STORIES.md) states what this project is *for* and takes precedence
over anything here. This file describes what exists *today* — the project is early, and most of what
follows is a current choice rather than a settled one.

## Commands

```bash
cargo test -p iroh-beekem-core   # pure engine: CGKA loop, state machine, capability closure,
                                 # forgery rejection, insider falsification tests
cargo test -p iroh-beekem-sim    # propsim: convergence, rotation/revocation, forging peer,
                                 # outsiders, insiders, revenants
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


## Current design

Today's answers — the three ALPNs, blinded storage keys, log and demand-driven repair, the two-DAG
content path, removal-then-rotation, the derived roster — live in
[docs/IMPLEMENTATION_PLAN_PROGRESS.md](docs/IMPLEMENTATION_PLAN_PROGRESS.md) under *The design as it
stands*, each with the reasoning that produced it and what else moves if it changes. None is settled;
if a user story needs a different answer, change it. **Read that section before proposing a design
change** — read it before proposing a design change.

Phase 5 has since landed: authorization is now carried by signed certificates and checked by every
receiver ([capability.rs](crates/iroh-beekem-core/src/capability.rs)), and the manifest no longer
holds roles or device bindings. The standing phrasing is **"the capability closure decides who is
authorised to act; the manifest records what that produced"** — if you find the older "the manifest
decides who is authorised to act" anywhere, it is stale.

Phase 6 has since landed: an [`Invite`](crates/iroh-beekem/src/invite.rs) is a signed ticket bound to
one device, with an expiry and a single-use nonce, and `add_user`/`add_device` take an `Enrollment`
rather than raw `beekem`/`keyhive_crypto` types. The standing phrasing is **"a stolen invite buys
visibility, not membership and not plaintext"** — if you find "invites are replayable" anywhere, it is
stale, and if you find a claim that signing a ticket protects a *leaked* one, it is wrong: what bounds
a thief is the roster and namespace rotation.

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
- **A capability certificate must travel *with* the operation it authorises.** `Effect::BroadcastOp`
  carries a `proof`, and `ControlMsg::Log` ships the whole certificate store beside the operation
  log. A receiver checks the issuer's capability *before* merging, so an operation that arrives
  without its certificates is **refused, not parked** — no later certificate brings it back. Shipping
  the log without the store reinstates the exact hole phase 5 closed, on every `NeighborUp`. A role
  change is worse still: it mints a grant and no operation, so the log exchange is its *only*
  anti-entropy.

- **The invite's nonce is claimed *after* every other check, and the order is the point.**
  `Workspace::join` runs `Invite::verify` first and `Node::claim_invite` last. Claiming first would
  let a garbled, expired or misaddressed copy of a ticket burn the nonce of the one that would have
  worked — a denial of service anybody who can hand the invitee a file can mount. The nonce ledger
  also lives on `Node` and not on `Workspace`, because redeeming a ticket is what *creates* a
  workspace: there is nothing else to ask at the moment of the check.

- **Every new `Signed<T>` needs a domain tag and a line in the encoding test.** Phase 8 added
  `AdminProposal` and `Approval`; a `RemoveMember` proposal encodes to 77 bytes, exactly the length
  of a `Grant`, and that is fine — what separates them is the tag in the first sixteen bytes, not
  their size. `the_signed_payload_types_cannot_share_an_encoding` now checks all six pairs, and
  `the_invite_tag_is_distinct_from_every_certificate_tag` checks all four tags across the crate
  boundary.
- **Every signed payload carries a 16-byte printable-ASCII domain tag, and both halves of that
  sentence are load-bearing.** `Signed<T>` covers `bincode(payload)` with no type name and no
  discriminator, and verification recomputes it for whatever `T` the *deserializer* chose — on the
  wire a `Certificate` is an enum, so that choice is the attacker's. A genuine `(issuer, signature)`
  pair therefore transfers between any two payload types whose encodings match byte for byte.
  **Distinct** tags stop a `Grant` being read as a `DeviceBinding`. **Printable ASCII** stops either
  being read as a `CgkaOperation`: bincode writes an enum discriminant as a little-endian `u32`, so
  bytes 1–3 of any variant index below 2^24 are zero, and no ASCII byte is. A tag containing a NUL
  would keep the first property and silently lose the second. Untagged, `DeviceBinding` was exactly
  80 bytes — every 80-byte string decoded as one — against `CgkaOperation::Remove` at 88, both signed
  by the same member key, and an admin's `Remove` lifted into a
  `DeviceBinding { device: attacker, user: admin }` is an escalation the closure admits.
  `the_signed_payload_types_cannot_share_an_encoding` in [capability.rs](crates/iroh-beekem-core/src/capability.rs)
  is what keeps this true; **any new `Signed<T>` needs a tag and a line in that test**, phase 8's
  `Policy` and `Approval` included.

- **A joiner's namespace generation comes from the invite, and it is not cosmetic.**
  `WorkspaceState::joined` takes it from `Invite.epoch`. Seeded at `NamespaceEpoch::INITIAL` instead,
  a member admitted at generation 3 will adopt an announcement of generation 1 — peers that are
  themselves behind re-announce on the ordinary `ResyncNamespace` schedule, under the *current* group
  key, so the joiner can decrypt it — and move onto a replica the group abandoned before it arrived.
  It recovers at the next rotation, so the failure is a silent stall rather than an error.

- **`ever_admin` and `role_of` are two predicates on purpose**, and it is the same split as
  `known_members`/`current_members` for the same reason. `ever_admin` is monotone and decides whether
  a *certificate* is admitted, which is what makes the closure an order-independent function of the
  set — two peers holding the same certificates must always agree, or a receiver-side check diverges
  the group permanently. `role_of` is non-monotone, resolved by `(seq, digest)`, and decides whether
  an *action* is permitted, where disagreeing costs a refused action the next exchange repairs.
  Making admission consult `role_of` would let a demotion retract an earlier admission and the
  fixpoint would no longer be well defined.

- **Authority never goes back into the manifest.** `Manifest::import` is an unconditional CRDT merge,
  so anything recorded there is writable by any member — that is what the whole of phase 5 was about.
  The manifest holds claims whose forgery grants nothing (paths, labels, display names, the
  self-attested author and endpoint maps); roles and device bindings live in `capability.rs`. There is
  no way to filter a Loro import, so "record it in the manifest and validate on the way in" is not an
  available design, only an available bug.

- **`known_members` and `current_members` are two sets on purpose.** The first is the
  *authorisation* predicate and must stay monotone, because disagreeing costs a dropped operation and
  permanent divergence. The second is the *enumeration and connection-policy* predicate and is allowed
  to be order-sensitive, because disagreeing costs a refused connection the next merge repairs.
  Collapsing them has no safe direction: monotone, and a revoked device stays admitted forever;
  non-monotone, and `merge` starts rejecting on a delivery-order-dependent predicate.
- **A rotation is announced once, so it needs both anti-entropy and repair.** Unlike a document, it
  has no later write behind it. `Event::ResyncNamespace` re-announces under the current epoch on the
  ordinary schedule (for a peer that missed the message), and `RepairTarget::Namespace` mints a
  *fresh* epoch (for a peer that cannot derive the key at all). Dropping either strands a member on
  an abandoned replica — removed in effect, without anyone having removed them. Both backends must
  drive `ResyncNamespace` from their resync path.
- **The minter adopts its own rotation through `Effect::AdoptNamespace`,** not through a second code
  path in each backend. `on_namespace_minted` appends it deliberately; without it the admin who
  issued the removal is the one member still publishing into the namespace it just abandoned.
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
- **Fault plans must set `Mode::Liveness` explicitly.** `Faults::swarm()` defaults to `Mode::Safety`,
  which injures uniformly and **never heals a partition** — under which no `eventually_within`
  property is sound, because a permanently severed node cannot converge. Such a property then passes
  or fails according to whether the seed happened to enable partitions at all, which looks like
  flakiness and is really an unsound scenario. See `network_faults` in
  [properties.rs](crates/iroh-beekem-sim/tests/properties.rs).
- **A restart in propsim is a freeze, not amnesia.** `dispatch_start` calls `on_start` on the *same*
  node object; there is no `on_crash` hook and no per-node storage seam. `WorkspaceNode::reboot`
  therefore authors the wipe itself, and `no_node_ever_initialises_the_workspace_more_than_once`
  plus the founder-crash variant are what stop the harness degenerating into a re-invitation test.
  A crashed *member* cannot catch that — `on_welcome` already refuses a node that has state — so the
  scenario has to crash the **founder**, whose founding branch is unconditional.
- **A snapshot is written before the write it covers is acknowledged.** `Workspace::drive` awaits
  `persist` before returning `Ok`, and the simulator's `apply_client_op` does the same. `persist` is
  called at *batch boundaries* — drive, control message, ingest pass, republish, assemble — and never
  from `apply_effects`, which would make it O(documents) per arriving chunk. Do not gate it on the
  effect batch being non-empty: `on_certs_arrived` absorbs certificates and can return no effects.
- **`Workspace::leave` takes `&self` and does not tear anything down.** `GossipSender::broadcast`
  enqueues without acknowledgement, offers no flush, and dropping the subscription discards the
  queue — so a `leave` that consumed `self` would race its own departure, and a `Remove` has no
  anti-entropy behind it to repair the loss. Teardown is `delete`, called by the caller when ready.
- **The quorum threshold is a founder-signed certificate, fixed at creation, never the manifest and
  never mutable.** A receiver-side quorum check is *stricter the more a node knows*, so a movable
  threshold would let a peer holding the certificates that raised it refuse an operation a peer still
  catching up had merged — permanent divergence. `Policy` is minted in `WorkspaceState::found` and
  travels in the bundle without which nobody could have joined, so no member is ever behind on it.
  Approvals are counted with `ever_admin`, not `role_of`, for the same monotonicity reason, and by
  **distinct users**, not devices — counting devices lets one person with three computers satisfy a
  threshold of three.
- **Enforcement is on the receiver, in `CgkaController::authorize`.** `require_quorum` is a local
  fail-fast an attacker would simply not run. Above a threshold of one, a `Remove` naming somebody
  else is refused unless a matching proposal has reached quorum, and `Effect::BroadcastOp` carries the
  policy, the proposal and the approvals so a peer that has not seen them can still verify. A
  self-removal is never gated: a threshold governs what the group does *to* a member.
- **Above a threshold of one only the founder may set a role alone.** Two things depend on it:
  bootstrap, since a workspace with one admin and a threshold of two could otherwise never reach a
  quorum; and the puppet hole, since an admin who could appoint a second admin alone could approve
  its own actions twice. `AddUser` is gated with `SetRole` because admitting somebody assigns a role.
- **Certificates need anti-entropy like the manifest and the namespace do.** A grant, proposal or
  approval is broadcast once with no write behind it, so `Event::ResyncCertificates` must be driven
  from both backends' resync paths. Without it a dropped approval leaves a quorum that formed on one
  node and nowhere else — an action performed there and refused everywhere.
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
