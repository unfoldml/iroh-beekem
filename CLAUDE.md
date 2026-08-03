# CLAUDE.md

## Language

Important:  Only write in ASD-STE100 (Simplified Technical English )


## User stories
[docs/USER_STORIES.md](docs/USER_STORIES.md) states what this project is *for* and takes precedence
over library functionality described here. 


## Commands

```bash
cargo test -p iroh-beekem-core   # pure engine: CGKA loop, state machine, capability closure,
                                 # forgery rejection, insider falsification tests
cargo test -p iroh-beekem-sim    # propsim: convergence, rotation/revocation, forging peer,
                                 # outsiders, insiders, revenants, assets
                                 # ~3 min: runs under swarm faults (partitions, latency, reorder).
                                 # Cost is proportional to the *number of events*, because the
                                 # simulator deep-clones every node's state per event, and that
                                 # clone is four Loro snapshot round trips plus the CGKA tree.
                                 # This is why the root manifest optimises dependencies: at
                                 # `opt-level = 0` the same suite took over 45 min and one
                                 # property test alone took 40 s. Do not remove those profiles.
                                 # Neither `RESYNC_INTERVAL` nor `MAX_RESYNCS` is a free lever —
                                 # propsim ends every run here at 15 virtual seconds and their
                                 # product already fills it; see `MAX_RESYNCS` in sim/src/lib.rs.
cargo test -p iroh-beekem        # two real endpoints over real QUIC, plus blob collection
                                 # and the large-asset round trip. Do NOT run alongside the
                                 # simulator: these wait on wall-clock outcomes and a
                                 # saturated machine starves them into false failures.
                                 # `make test` runs the three suites in sequence for that
                                 # reason; `cargo test --workspace` does not and should not
                                 # be used.

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

**`iroh-beekem-core` performs no I/O.** The protocol has two entry points, both in
[state.rs](crates/iroh-beekem-core/src/state.rs):

* `WorkspaceState::handle(Event, csprng, now) -> Vec<Effect>` — one event.
* `WorkspaceState::on_control(ControlMsg, csprng, now) -> Vec<Effect>` — one control-plane message.

`on_control` is `handle` with the wire's framing in front of it. It exists because that framing was
written twice — once in the facade and once in the simulator — and the two copies drifted.

The core returns what it wants done and two backends perform it — `apply_effects`
([workspace.rs](crates/iroh-beekem/src/workspace.rs)) and `WorkspaceNode::apply_effects`
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
- **Two things in the core look like exceptions and are not.** `wire.rs` frames bytes, which opens no
  socket; `cooldown.rs` is *given* an instant and never reads one, exactly as `handle` is given
  `now`. A limiter that called `Instant::now` would break the rule; one that takes the instant as an
  argument is what lets the same policy be checked against wall time and against virtual time.
- **Adding an `Event`, `Effect` or `ControlMsg` variant means updating both backends**, or the
  simulator and the real transport silently diverge in behaviour. 


## Engineering and Coding practices

- Priorities when building a new feature or refactoring a preexisting one: first, make it correct. Second, make it principled (the API must follow textbook implementation and adhere to theory). Then, make it performant.
- Never, ever stub out implementations, or make simplifying assumptions without asking the user. Only deliver complete features.
- If you find code that is stubbed out, ask the user to expand the scope and fix it. Be a good repository citizen: if you see something broken or done poorly, fix it.
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

Phase 9 has since landed: publishing costs the edit rather than the document, superseded blobs in the
live namespace are collected, and a workspace entry may be a **binary asset** as well as a CRDT
document ([asset.rs](crates/iroh-beekem-core/src/asset.rs),
[workspace.rs](crates/iroh-beekem/src/workspace.rs)). Three standing phrasings:

* **"a publish costs the change, not the workspace"** — if you find "every edit and every resync
  exports all updates" anywhere, it is stale.
* **"an asset is sealed under its own content key, and the group holds that key"** — if you find a
  claim that content is always keyed directly by beekem application secrets, it is now true of
  documents only.
* **"a rotation re-encrypts documents and re-indexes assets"** — if you find "a rotation costs a full
  re-publish" without that qualification, it is stale.

`FileEntry.asset` is what distinguishes the two, and `None` means *document* rather than *unknown*:
an entry written before assets existed is a document, and reading it as anything else would make an
old manifest unreadable.

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

- **Neither backend may re-implement the control-plane dispatch.** `WorkspaceState::on_control`
  ([state.rs](crates/iroh-beekem-core/src/state.rs)) maps a `ControlMsg` to the events it stands for,
  and both `handle_control_msg` ([workspace.rs](crates/iroh-beekem/src/workspace.rs)) and the
  simulator's `on_control` ([lib.rs](crates/iroh-beekem-sim/src/lib.rs)) call it. The failure it
  prevents is the one phase 11 records: the receiver-side author check lived in the facade alone, so
  a property that read as "no honest node accepts a forged entry" asserted something weaker than its
  name. Three things stay outside, and each for a reason the core cannot argue away:

  * the **rate limit**, which needs a clock — the core says *which* messages are chargeable
    (`ControlMsg::answer_cooldown_key`) and each backend says how often;
  * the **re-ingest**, which needs an index to re-read — this is why `ControlMsg::Announce` returns
    no effects, and it is deliberate rather than an omission;
  * the **instrumentation** the properties read, which is harness bookkeeping and not protocol.

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
  `ControlMsg::Op` is unrecoverable — a peer that misses the operation establishing a PCS key can
  never derive it, and re-announcing content re-encrypts under that same key. `ControlMsg::Log` is
  the repair, and the simulator carries the *same type* rather than a counterpart to it: `Msg`
  wraps it as `Msg::Control`. Without the log exchange the harness is strictly more fragile than
  production and every resulting failure is an artefact.
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
  node and nowhere else — an action performed there and refused everywhere. The three live in
  `ANNOUNCED_ONCE` ([state.rs](crates/iroh-beekem-core/src/state.rs)), and **three paths across two
  backends** iterate it: the facade's public `resync` and internal `republish`, and the simulator's
  `republish` and resync tick. They are one list because they had drifted twice — first inside the
  facade, where `resync` drove two of the three and was reachable by a library caller and by no
  in-tree test; then across the crate boundary, where the simulator's tick drove two and its
  `republish` drove three. Adding a fourth thing announced once means adding it there, not at a
  call site.
- **A published chunk must not be permanently tagged.** Awaiting `AddProgress` resolves through
  `with_tag()`, which mints a *permanent* tag — so `store_chunk` uses `.temp_tag()` and holds the guard
  across `set_hash` and no longer. Before it, blob collection reclaimed nothing however it was
  configured, and the store grew without bound. The two halves of collection are created together in
  `Node::gc_pair` ([node.rs](crates/iroh-beekem/src/node.rs)) because a store built with only one of
  them either collects nothing or collects everything not currently being written.
  `publishing_creates_no_permanent_tag` in [blob_gc.rs](crates/iroh-beekem/tests/blob_gc.rs) is what
  keeps this true.

- **A quiescent resync publishes nothing, and the simulator has to model reconciliation for that to be
  sound.** `on_resync` returns no effects when `published_up_to[doc]` equals the document's current
  version: the index entry is still there and `iroh-docs` reconciles key ranges between peers, so
  re-encrypting produced a fresh blob per document per republish cycle that carried no new information.
  What this *removed* is the accidental repair a republish used to provide for an entry lost in
  transit — production never needed it, but the harness did, because it modelled the data plane as
  pure broadcast. `WorkspaceNode::reconcile` ([sim/lib.rs](crates/iroh-beekem-sim/src/lib.rs)) is the
  counterpart, on a sparser cadence (`RECONCILE_EVERY`) because re-offering everything to everyone
  every round makes the harness *more* talkative than production and starves the control plane.

- **`published_up_to` is a claim about a namespace, not about a document.** A rotation abandons the
  index, so `forget_published` clears it on both adoption paths. Missed, every node's post-rotation
  resync emits nothing at all and the group converges on a replica holding only what was edited
  afterwards — silently.

- **A delta needs an escalation path or it is a silent stall.** A document's index slot holds one chunk
  per author, so a receiver that misses a delta cannot go back for it. `ChunkVerdict::AwaitingDeps`
  therefore ages (`Parked::drains`) and past `MAX_DEP_WAIT_DRAINS` raises
  `RepairTarget::DocumentHistory` — answered with `(Keying::Current, Extent::Full)`, because the
  requester can decrypt perfectly well and re-keying would charge the group for something no key change
  fixes. Without it the chunk sits until the pending budget evicts it and *`no chunk stays parked
  forever` still passes*, because the queue does empty — by discarding.

- **`group_size()` is beekem's tree count and can lag its own operations graph.** `Cgka::remove` checks
  `contains_id` before replaying the graph and calls `remove_id` after, so a node holding a merged but
  unreplayed concurrent removal reports the removed member *and* refuses to remove it with
  `IdentifierNotFound`. Assert membership over `current_member_count`/`sees_member` instead. Two things
  exist because of it: `run_quorum_actions` marks a proposal executed **only on success** — burning the
  digest first turned that transient failure into a permanent divergence — and `on_certs_arrived` runs
  the quorum pass whether or not anything was new. `beekem_group_size_disagrees_with_current_members`
  in [beekem_loop.rs](crates/iroh-beekem-core/tests/beekem_loop.rs) pins it; the upstream reproduction
  is in [docs/beekem-bug-repro/](docs/beekem-bug-repro/).

- **An asset is keyed by an envelope, and that is what makes it repairable.** Segments are sealed under
  a per-asset content key with XChaCha20-Poly1305; only that 32-byte key is encrypted to the group. So
  a member admitted after the asset was written is stuck on one small chunk rather than on gigabytes,
  and `RepairTarget::AssetKey` costs one re-encryption of 32 bytes. Keying segments with CGKA
  application secrets directly would have made both repair and rotation O(bytes).

  That repair is the one the core cannot answer from state, because the key is in a blob it
  deliberately does not cache. So it *asks*: `on_repair_requested` emits `Effect::ResealAssetKey`,
  each backend fetches the chunk and calls `WorkspaceState::reseal_asset_key`. Returning no effects
  instead — which is what the arm used to do — is why the simulator answered no asset repair at all
  for as long as that mechanism existed, and why no property could see it.

- **A receiver refuses an entry whose author holds no writing role, and there is one predicate.**
  `WorkspaceState::author_may_write` has three links: the self-attested author claim in the manifest,
  the signed binding from that device to a user, and the signed grant from that user to a role.
  `ingest_all` in [workspace.rs](crates/iroh-beekem/src/workspace.rs) calls it, and the simulator's
  `on_entry` calls the same method. It used to ask the closure directly and skip the first link,
  because it published no author claim — a shorter check, admitting entries the real one refuses.
  That is the phase-11 defect happening inside the harness meant to catch it.

  The entry is **observed and then refused**, in that order, and the order is the design: a forging
  node is a *member*, so it holds the namespace write capability and its entry genuinely reconciles
  into every peer's replica whatever author it claims. Nothing stops it arriving; the author check is
  what stops it counting. A property asserting such an entry "never enters the index" is therefore
  asserting something false — `no_honest_node_ever_accepts_a_forged_entry` in
  [properties.rs](crates/iroh-beekem-sim/tests/properties.rs) states it over the *document* instead,
  and its counterpart asserts the entry does arrive, which is what keeps the first non-vacuous.

  Two things follow, and both are load-bearing. **The manifest is exempt.** The predicate resolves an
  author *through* the manifest, so author-checking the manifest is a deadlock — a joiner could never
  read the record that would let it read the record. What protects that key is the CGKA. **A refusal
  is a delay, not a verdict.** The claim or the grant may still be in flight, so the entry must be
  re-offered: production gets this free, because `ingest_all` re-reads the index every pass and
  records an entry as seen only once *applied*; the simulator keeps a `refused` list and replays it
  on `Effect::ManifestUpdated`. Dropping on refusal turns an ordinary catch-up race into lost
  content. The list is cleared on adopting a namespace, or a held entry would be replayed as though
  it had arrived on the new replica.

- **A test node must be spawned with `Relay::Disabled`, through `test_node`.** Both endpoints in any
  test live on one machine, so a relay can never be the path that works — but with the default
  `NodeOptions` each endpoint still opened and maintained connections to Number 0's public relay
  servers, and with eight tests running at once that dominated everything else the suite did.
  Measured over the real-QUIC suite at cargo's default parallelism: **21 of 38 timed out with relays
  enabled, 2 with them disabled, 0 after the two remaining fixes below.** The failures name assorted
  `eventually` waits and look exactly like a protocol regression, which is what makes this worth
  knowing rather than merely worth doing.

  The other two, both in [two_node.rs](crates/iroh-beekem/tests/two_node.rs): a restart binds a *new*
  UDP port, so with no relay each side's cached address for the other is stale and
  `a_restarted_joiners_later_writes_are_still_accepted` must be handed both addresses; and
  `a_removal_waits_for_the_second_admin` runs three endpoints, which do not fit on the
  **current-thread** runtime `#[tokio::test]` builds, so it asks for two workers. Address lookup stays
  **on** in tests — it is what turns an endpoint id into an address, and the roster path has nothing
  else, so disabling it does not slow a node down, it stops it reconnecting.

- **`make test` runs the three suites in sequence, and `cargo test --workspace` must not be used.**
  The workspace form builds one job graph and runs the simulator and the real-QUIC suite
  concurrently — the combination the Commands section says never to run. `make test` existed and did
  exactly that until phase 11.

- **A history property is only non-vacuous in a plan with a workload.** `World::history()` is empty
  unless the plan supplies `.workload()` and `.client()`, which only `generated_crud_workloads` does —
  every other module builds plans without them, so a loss property added there passes while reading
  nothing. Loss also needs `append_only_workload`: under `crud_workload` a `write`, `remove` or
  `revert` may legitimately delete an acknowledged append, so "every acknowledged write survives" is
  false there and every weakening of it that becomes true is vacuous.

- **Asset segments must stay out of the download policy, the parked queue, and `ingest_all`.** Without
  `refresh_download_policy` every member fetches every asset the moment its entries reconcile — the
  "slowing down document synchronization" the user story rules out. Segments are pulled at export time,
  never pushed, so they never consume `MAX_PENDING_CHUNK_BYTES`; a design that routed them through
  `Event::ChunkArrived` would quietly evict documents under load.

- **A rotation re-indexes assets and re-encrypts documents.** `reindex_assets` writes the *same*
  `(hash, size)` into the new replica for every asset key the manifest names and this node can serve.
  Sound because the removed device could already read everything published before its removal and
  cannot reach the new replica at all; what the rotation protects is everything published after. Both
  backends do it — the simulator retains `asset_index_keys` across `AdoptNamespace` instead of clearing
  wholesale — and `a_rotation_reindexes_an_asset_instead_of_re_encrypting_it` in
  [assets.rs](crates/iroh-beekem/tests/assets.rs) fails without it.

- **An interrupted attachment is only recoverable through the intent log.** `attach_file` indexes
  segments before the manifest entry that declares them, and a segment key is a blinded MAC of a UUID
  that exists only in memory until that entry lands — so a process killed halfway leaves blobs that are
  protected from collection and nameable by nothing. `Store::store_pending_assets` records the UUID
  first and `sweep_orphaned_assets` reads it back on the next start.

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
