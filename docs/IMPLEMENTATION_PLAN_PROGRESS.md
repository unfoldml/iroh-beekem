# Progress and implementation plan — iroh-beekem

## Context

The near-term goal is **a publishable 0.1 crate**.

Phases 0–6 are closed. Phase 5 answered the post-Phase-4 security review finding that outranked
everything else on the list:

> **Authorization is enforced only on the node that issues an action.** Every role check —
> `require_admin`, `require_write`, `require_may_add_device_to`, `require_not_last_admin` — runs
> against the *issuer's own* manifest view before it acts. **No receiving node checks the issuer's
> role for anything.** `CgkaController::merge_verified` verifies the signature and `known_members`
> and stops there; `on_manifest_arrived` calls `manifest.import()` with no attribution at all. So a
> member holding the *lowest* role can add members, remove the admin, and promote itself, and every
> peer will merge all three.

That made Phase 5 the 0.1 blocker: the admission control of Phase 3 and the removal machinery of
Phase 4 were both downstream of predicates any member could rewrite.

**It is closed.** Authorization is now carried by signed certificates
([capability.rs](crates/iroh-beekem-core/src/capability.rs)) rooted at the founder's key, checked by
every receiver in `CgkaController::merge`, and roles and device bindings no longer live in the
manifest at all. Three corrections to this document's own Phase 5 plan came out of building it, and
each is recorded in place below: the manifest filter of §5.3 was not implementable, property 3.7 as
drafted was unachievable, and a grow-only certificate set cannot express demotion without an explicit
`(seq, digest)` order.

Phase 6 then closed the invite surface, which 0.1 freezes: a ticket is now signed, bound to one
device, dated, and single-use, and `add_user`/`add_device` no longer force `beekem` and
`keyhive_crypto` into a caller's manifest. Two residuals are stated rather than implied. Signing a
ticket does not encrypt it, so what bounds a thief who reads one is the roster and namespace
rotation. And `INVITE_DOMAIN` shipped described as closing a signature-confusion hole, which it did
not — the invite was the least confusable payload in the protocol. The exposed pair was
`DeviceBinding` against `CgkaOperation::Remove`; both certificate payloads are now tagged too, and
the whole analysis is recorded under *Signature domain separation*.

Phases 7 and 8 have since landed. Persistence is real — snapshots, a filesystem-backed node, a
stable derived author identity, and a crash/restart harness whose amnesia had to be authored by the
node itself because propsim freezes rather than forgets. Lifecycle is closed with `leave`, `delete`,
`open` and `list`. And M-of-N admin actions ship as certificates rather than as manifest state, which
is where §8.2 as drafted was wrong.

Seven corrections came out of building them, each recorded in place below: §8.2's manifest-held
threshold was not implementable, a *mutable* threshold could not be receiver-enforced at all,
certificates had no anti-entropy, §7.4's account of how propsim restarts a node was wrong about the
mechanism, §7.2's per-workspace roster only half-closes what it claims, `Workspace::open` needed
bootstrap peers the plan did not mention, and `leave` could not consume its own workspace.

What remains is Phase 9.

NB: Where this document and the code disagree on detail, the
code wins.

---

## What has landed

| Phase | Shipped | Lives in |
|---|---|---|
| 0 | versioned core dependency, both LICENSEs, crates.io metadata and per-crate READMEs, five-job CI (test / lint / purity / msrv / publish-dry-run) | [ci.yml](.github/workflows/ci.yml) |
| 1 | `author_seed(&self, member)`; `require_write` + `CoreError::NotAWriter`; `NeighborUp` and republish cooldowns | [blinding.rs](crates/iroh-beekem-core/src/blinding.rs), [state.rs](crates/iroh-beekem-core/src/state.rs), [workspace.rs](crates/iroh-beekem/src/workspace.rs) |
| 2 | `Identity`; `users`/`devices`/`meta` containers with roles per *user*; multi-document facade; `drive()`; `WsOp` + `crud_workload` + `ClientCodec`; `Msg::Entry` with per-node `index` and `roster` | [identity.rs](crates/iroh-beekem/src/identity.rs), [manifest.rs](crates/iroh-beekem-core/src/manifest.rs), [sim/lib.rs](crates/iroh-beekem-sim/src/lib.rs) |
| 3 | `RosterGuard` on all three ALPNs, roster derived from manifest devices ∩ `current_members`, bootstrap admission for cold joiners | [roster.rs](crates/iroh-beekem/src/roster.rs), `WorkspaceState::roster` |
| 4 | `Remove`-before-rotate ordering, `NamespaceEpoch` on `(epoch, digest)`, `Effect::AdoptNamespace`, demand-driven repair via `Keying::Fresh`, read-only invite tickets for Viewers | [state.rs](crates/iroh-beekem-core/src/state.rs), [workspace.rs](crates/iroh-beekem/src/workspace.rs) |
| 5 | `Grant`/`DeviceBinding`/`CapabilityStore` with a monotone `ever_admin` and `(seq, digest)`-ordered `role_of`; the third check in `merge`; `AuthorizedOp` proof bundles on `BroadcastOp`/`ControlMsg::Op`/`Msg::Op`; `ControlMsg::Log` ships the whole store; `Effect::BroadcastCerts` and `Effect::EvictUncertified`; roles and bindings removed from the manifest; `Insider` and `Revenant` scenarios | [capability.rs](crates/iroh-beekem-core/src/capability.rs), [keys.rs](crates/iroh-beekem-core/src/keys.rs), [state.rs](crates/iroh-beekem-core/src/state.rs) |
| 7 | `snapshot.rs` with `CgkaSnapshot`/`WorkspaceSnapshot`; `WorkspaceState::export`/`import`; `Node::spawn_persistent` with a persisted endpoint key and nonce ledger; `Workspace::open`/`list`/`delete`; derived `iroh-docs` author from `author_seed`; roster registry keyed by tree id; a simulated disk and an authored wipe in `WorkspaceNode` | [snapshot.rs](crates/iroh-beekem-core/src/snapshot.rs), [store.rs](crates/iroh-beekem/src/store.rs), [roster.rs](crates/iroh-beekem/src/roster.rs) |
| 8 | `Event::Leave` and `Workspace::leave`; `Policy`/`AdminProposal`/`Approval` as tagged certificates; a founder-fixed threshold; `require_quorum` on the issuer **and** a quorum check in `CgkaController::authorize` on every receiver; `Event::ResyncCertificates`; `propose`/`approve`/`proposals`/`threshold`; `Departure` and `Quorum` scenarios | [capability.rs](crates/iroh-beekem-core/src/capability.rs), [state.rs](crates/iroh-beekem-core/src/state.rs) |
| 6 | `Signed<InviteTerms>` with `invitee`/`not_after`/`nonce`/`epoch`; domain tags on all three signed payload types, checked before the signature; `Node::claim_invite` nonce ledger; `Enrollment` plus `MemberId`/`ShareKey`/`Role` re-exports; `WorkspaceState::joined` seeded with the joiner's namespace generation; `Msg::Welcome` carries the invitee and the replica; `StolenInvite` scenario | [invite.rs](crates/iroh-beekem/src/invite.rs), [identity.rs](crates/iroh-beekem/src/identity.rs), [node.rs](crates/iroh-beekem/src/node.rs) |

### Residuals from the landed phases

Small, verified, and homeless — each is picked up by a phase below.

- **`author_seed` has no production caller.** `Workspace::assemble` still calls `author_create()`,
  minting a random author every spawn. Harmless until restart exists → **Phase 7.3**.
- ~~**`keyhive_crypto` is still a required downstream dependency.**~~ **Done in Phase 6.**
  `add_user`/`add_device` take an [`Enrollment`](crates/iroh-beekem/src/identity.rs), built by
  `Identity::enrollment`, and [lib.rs](crates/iroh-beekem/src/lib.rs) re-exports `MemberId`,
  `ShareKey` and `Role` for callers that need to name them anyway. Wrapped *and* re-exported rather
  than one or the other: the wrapper is what an ordinary caller uses, and the re-exports are what
  stops the wrapper from being a wall.
- **Spent invite nonces do not survive a restart.** `Node::claim_invite` keeps them in memory, so a
  crash makes an already-redeemed ticket redeemable again until it expires. Persisting them belongs
  with the endpoint secret key → **Phase 7.2**.
- ~~**`Signed<T>` has no domain separation, and only `InviteTerms` is tagged.**~~ **Done in Phase 6**,
  after the first pass got the analysis wrong. `Grant` and `DeviceBinding` now carry 16-byte
  printable-ASCII domain tags checked by `Certificate::verify`, alongside the invite's. Full reasoning
  under *Signature domain separation* below; the standing rule is that **a new `Signed<T>` needs a tag
  and a line in `the_signed_payload_types_cannot_share_an_encoding`** → **Phase 8**, whose `Policy` and
  `Approval` are the next two.
- **`Workspace::delete()` was specified and never built.** `open`/`list` land in Phase 7 and `leave`
  in Phase 8; `delete` joins the latter.
- ~~**CLAUDE.md's coverage workflow is dangling.**~~ **Done in Phase 5.** [Makefile](Makefile) and
  [scripts/coverage_report.py](scripts/coverage_report.py) now back `make coverage`,
  `make coverage-check`, `make check` and `COVERAGE.md`. Coverage is merged across every test
  manifest — a per-crate report understates the core badly, since most of its coverage comes from
  propsim driving it. Baseline at the close of Phase 5: **88.6% lines**, with `capability.rs` at
  95.2%.

---

## The design as it stands

Today's answers, with the reasoning that produced them and what else moves if they change. None is
settled; if a user story needs a different answer, change it. Three entries carried a qualifier the
post-Phase-4 security review added; all three are now marked **Resolved in Phase 5** with a note on
what the resolution was, because the reasoning is worth keeping even though the defect is gone.

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
  `Keying::Fresh`, which mints an epoch every leaf in the tree can derive and nothing outside it can.
  Demand-driven rather than scheduled because answering costs a tree operation: re-keying on a timer
  charges the whole group for a peer that may not exist.

- **Content flows through Loro as CRDT updates**, so a chunk applies only when the CGKA can reach the
  PCS key it names *and* Loro has the operations it depends on — that second condition is what
  `park_chunk` / `drain_pending` / `try_apply` exist for. Both parking areas are bounded
  (`MAX_PARKED_OPS`, `MAX_PENDING_CHUNK_BYTES`, `MAX_PENDING_CHUNKS`) and evict oldest-first, because
  unbounded queues are a remote memory-exhaustion vector; a property test asserts an honest run never
  evicts. A payload path that did not route through the CRDT would not need the second condition.

- **Storage keys are blinded**: `BLAKE3-MAC(workspace_secret, document_uuid)`, fixed 32 bytes, keyed
  on a stable UUID rather than a path so a rename touches only the encrypted manifest
  ([blinding.rs](crates/iroh-beekem-core/src/blinding.rs)). Follows from `iroh-docs` reconciling by
  key with keys in the clear.

- **Removal rotates to a fresh `iroh-docs` namespace**: the `Doc` lives behind an `RwLock` because it
  is *replaced*, and the data-plane pump is respawned against the new subscription with the ingestion
  cache cleared. The removed device keeps the write capability it was given — `iroh-docs` has no
  per-member key to withdraw — so the capability is made worthless rather than revoked. The old
  namespace is left rather than dropped, since peers may still be catching up on it.

- **The order of a removal is the security property.** `on_remove_member` broadcasts the CGKA
  `Remove` *before* emitting `Effect::RotateNamespace`; the capability for the new namespace is then
  encrypted under a group key the removed leaf can no longer derive. Reversed, the removed device
  reads the announcement and follows the group. `NamespaceEpoch` orders on `(epoch, digest)` — a bare
  counter cannot settle two concurrent rotations, and the digest is recomputed from the decrypted
  capability so it cannot be claimed. Rotation is skipped when the target was not a member, or any
  admin could force a full re-publish at will.

- **Permissions are certificates; the manifest holds display data**
  ([capability.rs](crates/iroh-beekem-core/src/capability.rs),
  [manifest.rs](crates/iroh-beekem-core/src/manifest.rs)). The manifest keeps logical paths, display
  names, labels and the `iroh-docs` author → CGKA member mapping. `ingest_all` still reads the
  manifest before document entries — `author_may_write` needs that mapping, so the reverse order
  rejects legitimate entries — but the *role* half of that check now comes from the closure.

  **Resolved in Phase 5.** Roles and device bindings used to live here, and the standing phrasing was
  *"the CGKA decides who can decrypt; the manifest decides who is authorised to act"* — which read as
  a settled separation of concerns while assuming the manifest was trustworthy. It was not:
  `on_manifest_arrived` gated only on *decryptability*. The fix was not to filter the import, which is
  impossible (`LoroDoc::import` merges an update atomically, so there is nowhere to hook), but to move
  the authority out. The split is now by **what a lie costs**: a forged display name grants nothing, a
  forged role grants everything.

- **Authentication is ours, not beekem's.** beekem verifies nothing, so `CgkaController::merge`
  ([keys.rs](crates/iroh-beekem-core/src/keys.rs)) adds the two checks that make a public gossip topic
  safe: signature against the embedded issuer key, then issuer ∈ `known_members`. Order matters —
  membership is checked only *after* predecessors are in hand, or a member whose own `Add` is still in
  flight would be rejected. `known_members` is monotone (a `Remove` does not retract) because
  retracting would make admissibility depend on delivery order and diverge peers.
  **Resolved in Phase 5.** There is now a third check: the issuer must hold a certificate admitting
  *this* operation. The monotonicity qualifier stands and has been written into the README — "cannot
  reach the root key anyway" is true for `Update` and **false for `Add`**, so monotonicity is a
  divergence argument and never was a containment one. What contains a removed member is eviction
  (`Effect::EvictUncertified`), not admissibility.

- **Admission control is an authenticated allowlist over endpoint ids.** All three ALPNs are wrapped
  in `RosterGuard` ([roster.rs](crates/iroh-beekem/src/roster.rs)); an `EndpointId` is the peer's
  public key, authenticated by the QUIC handshake. The roster is *derived*, never authored —
  `WorkspaceState::roster` intersects the manifest's device addresses with `current_members` — so it
  converges like everything else and inherits the admin gating on `AddUser`/`AddDevice`. Computed in
  the core so the rule is testable without a socket. Eviction is eventual, and it is an availability
  boundary, not a confidentiality one.
  **Resolved in Phase 5.** `roster` now intersects *certified* devices with `current_members` and
  announced endpoints, so a device with no signed binding contributes nothing whatever it writes.
  "Derived, never authored" is true as written.

---

## Threat model — what is confidential, from whom

Belongs in the README as well; its absence is what let the findings above go unnoticed.

| Layer | Protected by | An outsider holding the identifiers sees |
|---|---|---|
| **Blob payloads** | Per-chunk AEAD keys from the CGKA, bound to content ref + predecessor refs | Ciphertext only. **This part genuinely delivers.** |
| **Data-plane index** (`iroh-docs`) | `RosterGuard`, then knowledge of the `NamespaceId` | Nothing, unless admitted. Once admitted: blinded keys (document count, which changed, when), entry sizes, author ids, timestamps |
| **Control plane** (`iroh-gossip`) | `RosterGuard`, then knowledge of the `TopicId` | Nothing, unless admitted. Once admitted: **four of the five `ControlMsg` variants in plaintext** — `Op` and `Log`, so every `Signed<CgkaOperation>`, every member key added or removed, every rotation, and the whole log replayed on each `NeighborUp`; `Announce { key }`, which is real-time telemetry for every write; and `Repair { member }`, which names who is stuck. The fifth, `Namespace`, is **not** plaintext: its capability travels as a `Chunk` encrypted under the group key, which is the entire reason a removed device cannot follow a rotation |

"Plaintext" here means *readable by an admitted overlay participant*, not *readable on the wire*.
Gossip runs over iroh's QUIC/TLS and every ALPN sits behind `RosterGuard`
([node.rs](crates/iroh-beekem/src/node.rs)), which fails closed.

**Encrypting the four is not an available fix**, and the reasoning is the module doc on
[wire.rs](crates/iroh-beekem/src/wire.rs) plus one case it does not cover:

- `Op`/`Log` are what a peer consumes in order to *derive* the group key, so encrypting them under
  that key is circular. `Invite.log` is documented as public, signed data for the same reason.
- They carry no secrets to protect. An `Update`'s `PathChange` holds inner-node secrets already
  encrypted to sibling resolutions, as TreeKEM requires; broadcasting the operation exposes the
  membership graph, not key material. What makes a public topic safe is authentication on receipt in
  `CgkaController::merge`, not confidentiality in transit.
- Encrypting `Announce`/`Repair` under the current group key — the only two where it is even
  possible — buys nothing against the one adversary it would target. A member in good standing holds
  that key already; and the sole peer still relaying to a *removed* device is one that has not merged
  the removal, so it is broadcasting under an epoch that device can still derive. The residual there
  is eventual eviction (README, "Not yet implemented" #4), a membership-convergence problem that an
  encryption layer does not touch.

Two structural points survive the roster:

- **The topic id is the founder's public key** and never rotates, so everyone ever invited knows it
  permanently. Rotating it would require a new tree id — that is, a new workspace. The roster is what
  refuses them.
- **One leaked invite, ever, is permanent.** Phase 6's signature, binding, expiry and nonce stop the
  *join* from being replayed, and they are what a thief running this library hits. They do not
  unlearn what the ticket already told a thief running its own: the `tree_id`, the `TopicId` and the
  blinding secret it carries never rotate. What ends the exposure is the namespace rotation, which is
  why a leak is a reason to remove somebody rather than a reason to reissue a ticket.

### The axis this table does not have: an insider

Every row above asks *"what does an outsider see"*. Nothing asks *"what can a member do"*, and that
omission is the finding this plan now leads with.

| Actor | Constrained by | Can actually do today |
|---|---|---|
| **Outsider** (never admitted) | `known_members` on merge, `RosterGuard` on connect | Nothing. This genuinely holds; the `Outsider` and `Forging` scenarios prove it. |
| **Member, any role** | `require_*` on their **own** node only | Issue an `Add` of any keypair; issue a `Remove` of the admin; write `roles[me] = Admin` or any device→user binding into the manifest. Every peer merges all of it. |
| **Removed member** | `current_members`, roster, rotated namespace | Everything in the row above, given one connection window or one lagging peer, because `known_members` is monotone and their signature stays admissible forever. |

**Out of scope, and stated so honestly:** traffic analysis by a member in good standing, and
connection metadata visible to relay servers. Neither is fixable at this layer. Note how much work
"in good standing" does in that sentence until Phase 5 lands.

---

## Testing philosophy — read before writing any test

**We specify behaviour as property tests over simulated user stories, not unit tests over data
structures.** Each phase ships its properties as part of the phase. A phase whose behaviour cannot be
stated as a property over [docs/USER_STORIES.md](docs/USER_STORIES.md) is a phase whose requirements
are not yet understood.

`propsim` is a Jepsen-style harness. Typed client operations, generated workloads, `ClientCodec` and
swarm faults are all in use today (`WsOp`, `crud_workload`, `WorkspaceSpec`, `network_faults`). What
remains unused:

| Capability | API | Why not |
|---|---|---|
| Recorded history with real op spans | `Ctx::complete_op`, `World::history()` | Needed for Story 2's "no acknowledged write is lost" as a *history* property rather than a converged-text one |
| Scripted faults | `Faults::scripted().at(t).partition(..) / .heal_all()` | Needed for `OfflineEdit`; the swarm plan cannot place a fault at a chosen instant |
| Crash/restart | `Faults::swarm().crash_restart()` | Blocked on Phase 7 — a modelled restart is currently a re-join |
| Reference model | `SequentialModel` | **Deliberately not used.** A CRDT workspace is not linearizable — concurrent writes commute rather than serialising — so a linearizability oracle reports anomalies for correct behaviour. The reasoning is in the code beside `WorkspaceSpec`. |

The oracle is **convergence**, not linearizability: (1) every node's `read(doc)` is byte-identical;
(2) no loss, no fabrication — the multiset of acknowledged fragments equals the multiset in the
converged text. Asserting an exact string would assert an implementation detail of Loro's ordering.

**Keep and grow:** panic-freedom on hostile input ([wire.rs](crates/iroh-beekem/src/wire.rs)); the
real-QUIC suite in [two_node.rs](crates/iroh-beekem/tests/two_node.rs), which proves **the transport
wiring is connected** and should *not* grow protocol assertions; focused crypto regressions in
[beekem_loop.rs](crates/iroh-beekem-core/tests/beekem_loop.rs).

**Stop writing:** tests asserting over internal data structures. Convergence is a system property
under an adversarial network, and the simulator states it far more strongly than
`concurrent_edits_on_two_replicas_converge` in [manifest.rs](crates/iroh-beekem-core/src/manifest.rs)
does.

---

## Phase 5 — Verifiable authorization

**The 0.1 blocker.** Everything Phases 3 and 4 built is downstream of role and device-binding state
that any member can rewrite.

### 5.0 Why the obvious fix is wrong

The tempting change is to have `merge_verified` consult the manifest for the issuer's role. **Do
not.** The manifest is replicated, mutable, and converges at different times on different peers, so
two peers evaluating the same operation against different manifest views reach different verdicts —
one drops an operation the other keeps, and the group diverges permanently. That is the exact failure
mode monotone `known_members` was chosen to avoid, and reintroducing it through a role lookup would
be strictly worse, because a role lookup is *also* attacker-controlled.

This also disposes of the rule as originally drafted in Phase 2 — *"an `Add` introducing a device is
admissible only if its issuer is already a device of that same user"*. That predicate is over the
manifest, so evaluating it at merge time is order-dependent. What shipped instead was
`require_may_add_device_to`, which applies the rule on the **issuing** node only.

Authorization must therefore be **carried by the operation and verifiable offline**, with an
order-independent root.

### 5.1 The root already exists

`tree_id = TreeId::from(founder_signing_key.verifying_key())`, and the founding `Add` is self-issued
and verified in `CgkaController::join` before anything else is replayed. So **the founder's public
key is already a cryptographic identity every peer holds, agrees on, and cannot be argued out of.** A
certificate chain rooted there needs no new distribution channel, no new secret, and no new
convergence argument — which is what makes this tractable rather than a redesign. The module docs in
[manifest.rs](crates/iroh-beekem-core/src/manifest.rs) already name it as the right answer.

### 5.2 Capabilities

New in `iroh-beekem-core`, alongside the manifest rather than inside it — the manifest goes on
*recording* roles for enumeration and UI, and stops being the thing anyone trusts:

```
Grant {
    subject: [u8; 32],         // user id (= founding device's member id)
    capability: Role,          // Admin | Editor | Viewer
    issuer: [u8; 32],          // member id of the granting device
    not_after: Option<u64>,    // absolute ms; see 5.4
    nonce: [u8; 16],
}
DeviceBinding {
    device: [u8; 32],          // member id of the new leaf
    user: [u8; 32],            // user this device belongs to
    issuer: [u8; 32],          // an existing device of the same user, or an admin
    nonce: [u8; 16],
}
```

Both travel as `Signed<..>`. A chain is *valid* when every link verifies, each issuer holds a
capability admitting the link (an `Admin` grant for a `Grant` or a first-device `DeviceBinding`; a
same-user `DeviceBinding` for a sibling device), and the chain terminates at the founder, whose
authority is axiomatic because `tree_id` **is** their key. Validity is a pure function of the chain
bytes — no shared state, no ordering, so two peers always agree.

### 5.3 Where the checks go

| Site | Check to add |
|---|---|
| `CgkaController::merge_verified` | An `Add` or `Remove` must carry a chain proving its issuer held `Admin` (or, for `Add`, a same-user `DeviceBinding`). Reject otherwise — this is the check that closes the `Add` re-entry path. |
| `WorkspaceState::on_manifest_arrived` | Import roles and device records only where a valid chain accompanies them. Everything else in the manifest (paths, mime types, display names) stays an unconditional CRDT merge — it grants nothing. |
| `WorkspaceState::roster` | Derives from *certified* device records only. Falls out for free once the import is filtered. |

Keep `require_admin`/`require_write` where they are. They become a fail-fast local courtesy — a clear
error instead of an operation every peer will drop — which is a good thing to have and a terrible
thing to rely on. Say so in their doc comments, because they currently read as enforcement.

**Wire impact.** `CgkaOperation` is beekem's type and cannot carry a field, so the chain rides in
`ControlMsg` beside the operation, and `ControlOp` becomes `(Signed<CgkaOperation>, Chain)`. Both
backends change — `apply_effects` and `WorkspaceNode::drive` — per CLAUDE.md's standing rule.
`ControlMsg::Log` must ship chains too, or log repair reintroduces the hole on every `NeighborUp`.

### 5.4 Revocation, and the one honest trade

Revoking a *grant* has the same order-dependence problem as everything else, so do not try to make
grants retractable in 0.1. Instead:

- A grant is revoked by **CGKA-removing every device of the granting user**, which is already a
  first-class operation and already converges.
- Chains carry `not_after`, evaluated against the timestamp *the verifying node* holds. The clock
  stays in `iroh-beekem`; the core receives it as data, per the `cargo tree` rule.
- **The trade, for the README:** a demoted admin's previously-issued grants stay valid until they
  expire. Record it beside the monotone-`known_members` entry it mirrors.

### 5.5 Bootstrap

The founder issues its own `Grant { subject: self, capability: Admin }`, self-signed, valid exactly
because the chain terminating at `tree_id` is the axiom. `WorkspaceState::found` must mint it;
`joined` must not — the same distinction `found`/`joined` already turns on. An `Invite` carries the
invitee's `DeviceBinding` and `Grant`, which the inviter has at admit time since `add_user` already
knows the role, so a joiner arrives certified rather than needing a second round trip.

**Ships with:** the Story 3 insider properties and the `Insider` scenario. Write those **first** —
they must fail against today's `main`, and a fix whose test passed before it was written has proved
nothing.

---

## Phase 6 — Invite security and the public surface — **closed**

The README's "invites are replayable" understated one half and overstated the other. A leaked
`Invite` **does not grant read access**: `CgkaController::join` requires the `share_secret` whose
`ShareKey` the inviter named in the `Add`, and that never travels in the ticket. What it *does* grant
is visibility — the replica to watch, the inviter to dial, and the blinding secret.

What landed:

- `Invite` is `Signed<InviteTerms>`, carrying `invitee`, `not_after` (absolute Unix seconds, one hour
  out), `nonce`, `epoch`, and the Phase 5 certificate store beside the log.
- `Invite::verify` checks, in order: the domain tag, the signature, the invitee binding, the window,
  and that the issuer may administer under a `CapabilityStore` rooted at `tree_id`. `Workspace::join`
  calls it and then claims the nonce — **last**, so a ticket failing an earlier check cannot burn a
  legitimate one.
- **Domain tags on every signed payload type**, checked before the signature: `INVITE_DOMAIN` on the
  invite, and `GRANT_DOMAIN`/`BINDING_DOMAIN` on the certificates. The invite's alone was hygiene —
  it was never the confusable type — and the certificates' is the part that closes something. See
  *Signature domain separation* below, including what the first pass got wrong about this.
- `Node::claim_invite` is the nonce ledger, on the node rather than the workspace because redeeming a
  ticket is what *creates* a workspace. In memory only — see the residual above.
- No clock in `iroh-beekem-core`, and none needed: every check above is local, decided once, by one
  device, and the cost of two peers disagreeing is a refused join. The `cargo tree` check still
  matches nothing.
- **The `keyhive_crypto` leak is closed.** `Identity::enrollment(endpoint)` produces an `Enrollment`
  carrying member id, leaf key and endpoint; `add_user`/`add_device` take one. `MemberId`, `ShareKey`
  and `Role` are re-exported for callers that name them anyway.

One thing was added that the plan did not name, because building it made the need visible:
`WorkspaceState::joined` now takes the joiner's namespace generation, seeded from `Invite.epoch`. A
joiner used to start at `NamespaceEpoch::INITIAL`, and a peer that is itself behind re-announces its
own generation under the *current* group key on the ordinary anti-entropy schedule — so a member
admitted at generation 3 could decrypt an announcement of generation 1, compare it against `INITIAL`,
and move onto a replica the group abandoned before it arrived. That is the field's only consumer, and
without it `epoch` would have been dead weight on the wire.

**Shipped with:** the `StolenInvite` scenario and property 4.6 in three parts, plus two counterweights
— one asserting the theft actually happened and bought the thief visibility, so the other three are
not vacuous, and one asserting the remaining members converge through the rotation that ends it.
Seven pure unit tests in [invite.rs](crates/iroh-beekem/src/invite.rs) cover the checks themselves,
and four real-QUIC tests in `invite_security` cover the two that need a node and a clock.

**The residual, stated:** signing a ticket does not encrypt it. A thief who reads one holds the
blinding secret and the docs ticket whatever this library refuses, and the bound on that is
`RosterGuard` plus namespace rotation — not the ticket. There is nothing in a bearer token to revoke.

### Signature domain separation — closed, and larger than the invite

Phase 6 first shipped `INVITE_DOMAIN` described as closing a hole. **That description was wrong, and
the correction was worth more than the constant.** Recording both, because the wrong version is the
kind that survives review: it names a real mechanism and points it at the wrong type.

`Signed<T>` signs `bincode(payload)` with no type name and no discriminator, and `try_verify`
recomputes it for whatever `T` the *deserializer* chose. The type is therefore decided by the
receiving code path, not by the signed bytes, so a genuine `(issuer, signature)` pair transfers
between any two payload types whose encodings are byte-identical. The attacker forges nothing — they
lift the pair and reattach it. On the wire `Certificate` is an enum, so they choose the destination
type freely.

Three conditions have to hold for that to bite:

1. two signed types encode to the same bytes — same length, with the attacker able to steer content;
2. an honest key signs the source type over content the attacker influenced;
3. the destination type grants something.

Under bincode 1.3 (fixint, `u64` `Vec` prefixes, `u32` enum discriminants), **before** the tags:

| Signed payload | Encoded size | Notes |
|---|---|---|
| `Grant` | 61 or 69 | needs a valid `Role` discriminant and `Option` tag |
| `DeviceBinding` | **80** | *any* 80 bytes decode as one |
| `CgkaOperation::Remove` | **≥ 88** | 4+32+4+8+8+32, plus 32 per removed key and predecessor |
| `CgkaOperation::Add` | ≥ 120 | |
| `InviteTerms` | ≥ ~232 | 188 fixed plus a `DocTicket`, before any log or certificates |

Nothing was exploitable — condition 1 failed everywhere. But **the invite was the safest of the
five, not the one at risk**: it missed by ~150 bytes, and the only bytes an attacker contributes
(`invitee`) must be a valid Ed25519 point at a fixed offset, so its encoding could not be steered at
all. Tagging it alone achieved close to nothing.

**The pair that mattered was `DeviceBinding` (80) against `CgkaOperation::Remove` (≥ 88).** Eight
bytes, both signed by the same member key, with conditions 2 and 3 already satisfied: an admin issues
`Remove`s routinely, and an admin-signed `DeviceBinding { device: attacker, user: admin }` is a full
escalation the closure admits without further checks. What held the eight bytes apart was
`CgkaOperation`'s field list, which lives in `beekem` and is a **version** dependency here, not a
pinned revision.

#### What closed it

`Grant` and `DeviceBinding` now begin with `GRANT_DOMAIN` and `BINDING_DOMAIN`, sixteen bytes of
printable ASCII each, private fields stamped by `Grant::new`/`DeviceBinding::new` and checked by
`Certificate::verify` **before** the signature — a payload signed for another purpose has a perfectly
good signature, and `CoreError::WrongDomain` says so rather than calling it corrupt.

Both properties of the tag are load-bearing, and the second is the one that is easy to lose:

- **Distinct** tags mean no two tagged types can collide, whatever their sizes.
- **Printable ASCII** means no *tagged* type can collide with an *untagged* bincode enum. A
  discriminant is a little-endian `u32`, so bytes 1–3 of any variant index below 2²⁴ are zero, and no
  ASCII byte is. This is what makes the `CgkaOperation` argument structural rather than a size
  coincidence — it survives anything beekem does to its fields. A tag containing a NUL would keep the
  first property and silently lose the second, which is why the test asserts the encoding and not
  merely the inequality.

`the_signed_payload_types_cannot_share_an_encoding` in
[capability.rs](crates/iroh-beekem-core/src/capability.rs) holds all of it: pairwise distinctness, the
no-zero-bytes property, the certificate-versus-operation inequality, and the encoded sizes pinned so a
bincode or dependency change fails loudly. `the_invite_tag_is_distinct_from_every_certificate_tag` in
[invite.rs](crates/iroh-beekem/src/invite.rs) is the cross-crate half — the constants live in crates
with different release cadences, and nothing else notices a future tag chosen to collide.

**The standing rule: a new `Signed<T>` needs a tag and a line in that test.** Phase 8.2's
`Signed<Policy>` (~12 bytes) and `Signed<Approval>` (32 bytes) are the next two, and small
fixed-size payloads are exactly the ones that collide.

#### One thing this surfaced

`a_certified_device_cannot_be_rebound` failed once the payloads grew 16 bytes, and it was right to.
The closure iterates bindings in **digest** order and takes the first admissible one per device, so
which of two competing bindings wins is a function of the certificate set — not of who issued first.
The test asserted the first-*inserted* binding survived, which held only because its nonce happened to
hash lower. It now asserts the property the code actually has: both insertion orders resolve the leaf
to the same user, and one device resolves to exactly one. Renamed to
`a_certified_devices_user_does_not_depend_on_arrival_order`.

#### Wire-format note

This is a breaking change to the certificate store: certificates minted before it fail
`Certificate::verify` with `WrongDomain`. Nothing depends on that ordering yet — Phase 6 had already
broken `iroh-beekem-core`'s API — but it lands before 0.1 rather than after for exactly that reason.

---

## Phase 7 — Persistence — **closed**

Implements `Workspace::open` / `list` and turns "local-first" from a claim into a fact.

### Three corrections this phase produced

**§7.4's account of propsim is wrong, and building to it would have produced a test that passes
while testing nothing.** The claim was that "propsim reconstructs a crashed node through `Default`".
It does not: `dispatch_start` takes the existing node out of its slot, calls `on_start` on the *same
object*, and puts it back. A crash is a **freeze**, not amnesia — `state`, `index`, `roster` and
every counter survive intact. So the harness work was never "give the node a store to reload from";
it was "give the node a store **and make it wipe everything else**, because the harness will not".
`WorkspaceNode::reboot` authors that wipe, and the conclusion §7.4 drew still stands.

This was confirmed rather than assumed: with the restore disabled,
`a_restarted_node_is_a_member_again_without_being_re_invited` fails; with the restart branch
disabled, `no_node_ever_initialises_the_workspace_more_than_once` and
`every_document_converges_after_the_founder_restarts` fail.

**A crashed *member* cannot catch the initialisation bug; only a crashed founder can.** The first
version of the restart scenario crashed node 2 and the initialisation property passed even against a
harness that treated a restart as a fresh start — because `on_welcome` already refuses to act on a
node that has state. `on_start`'s *founding* branch has no such guard, so a restarted founder would
overwrite the live workspace with a second tree. The scenario now has both variants.

Also worth recording: `admin_count() == 1` does **not** catch a forked founder. A re-founded node is
the sole admin of its own new tree and so reports exactly one administrator, as does everybody else.
The fork is invisible to any property that asks each node about itself rather than comparing them.

**§7.2's per-workspace roster only half-closes what it claims.** Keying by tree id fixes a real
defect — `set_derived` replaces wholesale, so two workspaces on one node clobbered each other on
every refresh and membership flapped for as long as the node ran. But admission stays a **union**:
`RosterGuard::on_accepting` sees an `EndpointId` and nothing else, because gossip multiplexes every
topic and docs every namespace over one connection per ALPN. `admission_is_a_union_across_workspaces`
pins that limitation deliberately, so a later reader finds the residual rather than assuming the
keying bought isolation. README *Not yet implemented* #3 carries it.

**`Workspace::open` needs bootstrap peers, which the plan did not say.** A joiner is dialled into the
group by its inviter; a restart has no inviter, and `Gossip::subscribe` with an empty peer list forms
an overlay of one. Nothing would ever reconnect it. `open` now seeds bootstrap from its own derived
roster — the manifest records every device's endpoint — and `sync_with`s each. Found by
`a_restarted_joiners_later_writes_are_still_accepted`, which timed out until it was fixed.

### 7.1 Core snapshots

**`beekem::cgka::Cgka` already derives `Serialize`/`Deserialize`**, including `owner_sks` and
`pcs_keys`, so the full decryption capability round-trips. `ShareSecretKey` derives serde;
`MemorySigner` does not, but its field is `pub ed25519_dalek::SigningKey`.

New `crates/iroh-beekem-core/src/snapshot.rs`:

```
CgkaSnapshot      { version, cgka, signer: [u8;32], share_secret,
                    known_members: Vec<[u8;32]>, current_members: Vec<[u8;32]> }
WorkspaceSnapshot { version, cgka, secret: [u8;32], epoch: u32, manifest: Vec<u8>,
                    docs: Vec<(DocumentUuid, Vec<u8>)>, last_ref: Vec<(DocumentUuid, ChunkRef)>,
                    chains: Vec<Signed<Grant>>, bindings: Vec<Signed<DeviceBinding>> }
```

The last two fields are Phase 5's and are not optional: a restarted node that kept its manifest but
lost its chains cannot re-verify the roles it is already acting on, and would either re-accept
uncertified state or lock itself out. Also persist `namespace_ticket` — `republish_namespace` is the
only path back for a member that missed a rotation, and it is a no-op when the ticket is empty.

- On import rebuild `share_key` from `share_secret.share_key()`. Store member sets as raw bytes;
  `MemberId` wraps an expanded Ed25519 point, the reasoning already in
  [error.rs](crates/iroh-beekem-core/src/error.rs).
- **Deliberately not persisted:** `parked` and `pending_chunks`. Parked ops return on the next
  `ControlMsg::Log` exchange and parked chunks on the next resync. Document as a decision; eviction
  counters reset.
- Reuse the existing Loro round-trip: `WorkspaceState::clone` already does snapshot export/import for
  the simulator's sake. Factor one helper for both `Clone` and `export`.
- **The snapshot is the whole read capability at rest** — signing key, leaf secret, `owner_sks`, every
  cached PCS key, the blinding secret. Wrap in `Zeroizing`, carry a prominent `#[doc]` warning, keep
  encryption-at-rest out of the core (no I/O by design); `iroh-beekem` writes it at a caller-supplied
  path with `0600`.
- Carry `version: u16` and reserve room for Phase 9's per-document version vector.

### 7.2 Node, store, and per-workspace rosters

`FsStore::load(path)` and `Docs::persistent(path)` both exist. Add `Node::spawn_persistent(root)`,
keeping `Node::spawn()` in-memory. `Node.blobs` is typed `MemStore` — change to
`iroh_blobs::api::Store`, where the router registration already converges via `blobs.deref()`.

- **Persist the endpoint secret key**, or the `EndpointId` changes on restart, no peer can re-dial,
  *and* the node falls off every roster. Persistence and admission control are coupled here.
- **Key the roster by workspace.** It currently lives on `Node`, because the guards must be installed
  when the router is built and before any workspace exists, so two workspaces on one node union their
  rosters and admit a member of either to both (README *Not yet implemented* item 6). `open`/`list`
  is what makes two workspaces per node reachable, so the fix belongs here.

### 7.3 Stable author identity

`Workspace::assemble` mints a **random** author every spawn. Harmless today; after a restart the node
presents a new author id, every peer's `author_may_write` rejects its entries, and it stays mute
until an admin grants a role to an identity nobody has seen. Fix with
`author_import(Author::from_bytes(seed))`, `seed` from `author_seed(&self, member)` — its first real
caller.

### 7.4 The crash/restart harness

This is a deliverable, not a testing footnote. propsim reconstructs a crashed node through `Default`,
and `WorkspaceNode::on_start` currently re-founds or re-joins unconditionally, so a modelled restart
*is* a re-join. `WorkspaceNode` needs a `NodeId`-keyed in-memory store standing in for disk, written
on snapshot and read in `on_start`. That store is the simulated filesystem; getting it wrong silently
turns property 2.5 into a re-join test, so the scenario must assert that the restarted node never
re-runs the join handshake.

**Ships with:** the Story 2 crash/restart properties.

---

## Phase 8 — Lifecycle and M-of-N admin — **closed**

### Two corrections this phase produced

**§8.2's `admin_threshold` in the manifest is not implementable, and the section contradicts
itself.** `Manifest::import` is an unconditional CRDT merge — that is the whole of phase 5 — so a
manifest-held threshold is writable by any member, who would set it to one and act alone. The
threshold is authority and had to be a certificate. §8.2's own later sentence ("approvals reuse
Phase 5's machinery") was the correct instinct; the container was the mistake, and the
*Signature domain separation* section had already anticipated `Signed<Policy>`/`Signed<Approval>` as
the next two tagged payloads.

**And a mutable threshold cannot be enforced by a receiver at all.** The first attempt shipped
`AdminAction::SetThreshold` and enforced the quorum only on the node *issuing* an action — which is
no enforcement, because an attacker running modified code simply does not run the issuer's guard.
Moving the check to `CgkaController::authorize`, where it belongs, exposed why the mutable version
could not have it: a receiver-side quorum check is **stricter the more a node knows**, so a peer
holding the certificates that raised the bar would refuse an operation a peer still catching up had
already merged — permanent divergence, the one failure this design exists to avoid, and the same
argument that keeps `known_members` monotone.

What shipped instead is a `Policy` certificate, self-signed by the founder in `WorkspaceState::found`
and valid for exactly the reason the founder's own admin grant is. The threshold is therefore a
constant of the workspace, delivered in the certificate bundle without which nobody could have joined
— so no member can ever be behind on it, and the asymmetry disappears. Approvals are counted with
`ever_admin` rather than `role_of` for the same reason: a peer that knows more must accept *at least*
as much, never less. The cost is stated as a trade rather than a gap: **a workspace's threshold
cannot be changed after it is created.**

Two consequences that had to be designed rather than discovered:

- **Bootstrap.** A workspace founded at a threshold of two starts with one admin, so no proposal
  could ever reach quorum. The founder is exempt for *roles only* — never removals — which is
  sound because the founder is already the axiom every chain terminates at.
- **The puppet.** An admin who could appoint a second admin alone could appoint a puppet and approve
  its own actions twice, making any threshold decorative. Above a threshold of one, everyone except
  the founder needs a quorum to set a role, `AddUser` included.

Three falsifications were confirmed red before the fix: with the receiver-side check removed,
`a_removal_no_quorum_authorised_is_refused_by_the_receiver` fails; with issuer-side enforcement
removed, `one_admin_cannot_remove_a_member_alone` fails; with approvals counted per device rather
than per user, the quorum forms on one admin's two machines.

**Certificates needed anti-entropy, and nothing had noticed.** A grant, proposal or approval is
broadcast exactly once with no write behind it — the position `Event::ResyncManifest` and
`Event::ResyncNamespace` already exist for — so a single dropped gossip message stranded it until a
neighbour happened to reappear. Survivable for a grant; not for an approval, where a quorum that
formed on one node and reached no other leaves an action performed there and refused everywhere else.
`Event::ResyncCertificates` closes it, driven from both backends' resync paths. Found by the
real-QUIC quorum test, which hung with the second admin's approval sitting on the wrong node.

`AdminAction` carries no `Rotate` variant, although §8.2 lists one. Namespace rotation is not
independently proposable — `on_remove_member` emits it as a *consequence* — so gating the removal
already gates the rotation, and the variant would have been a wire format with no caller.

**`Workspace::leave` cannot consume its own workspace.** `GossipSender::broadcast` enqueues a command
on a channel the topic actor drains: it returns when the message is accepted, not when it reaches
anybody, and there is no flush and no acknowledgement. Dropping the subscription discards the queue.
A `leave` that broadcast and immediately tore down was therefore racing its own announcement and
losing often enough to fail under test load — and losing is terminal, because a `Remove` has no
anti-entropy behind it and the one node that would re-announce it is the one that left. A one-second
grace made it flaky; three seconds made it a coin flip. `leave` is now `&self` and announce-only,
with teardown left to `delete`, which removes the race rather than bounding it.



### 8.1 `leave` and `delete`

- `Workspace::leave()`: broadcast a self-issued `Remove` of every device of the local user,
  `Doc::leave()` to stop syncing, unsubscribe from the topic, then the local teardown of `delete()`.
  Guard with `require_not_last_admin`; `remove_member` already returns `CgkaError::RemoveLastMember`
  if it would empty the group — the natural second guard.
- `Workspace::delete()`: `Docs::drop_doc(namespace)`, drop the snapshot, drop the `WorkspaceSecret`
  (already `ZeroizeOnDrop`). Specified in Phase 2 and never built.
- **Say what `leave` isn't.** It is a courtesy, not a security boundary: it does not unlearn what the
  leaver could already read, and unlike `remove_user` it triggers no rotation and no roster eviction —
  the group must do that, and a departing member cannot be trusted to have done it. Note in the doc
  comment that an admin should follow a `leave` with a `remove_user`.

### 8.2 M-of-N admin actions

- **Policy** in the manifest: a `policy` container holding `admin_threshold: u32`, changeable only by
  a quorum at the *current* threshold. Default 1, so existing workspaces are unaffected and
  `require_not_last_admin` keeps working.
- **Proposals** are data: `AdminProposal { nonce, action, expires }`, digest `BLAKE3(postcard(..))`.
- **Approvals reuse Phase 5's machinery** rather than inventing a parallel one: an approval is a
  `Signed<Grant>`-shaped capability over a proposal digest, and quorum is "≥ threshold valid chains
  from distinct admin users". This matters — the hard part of M-of-N is that the threshold is
  evaluated against the admin set at execution time, and two peers can disagree under concurrency.
  Phase 5.4 already solves that with expiry, so it is solved once here instead of with a second
  monotone set.
- **Execution** is deterministic given the manifest: any replica seeing ≥ threshold valid approvals
  performs the action. Whoever gets there first broadcasts; everyone else sees
  `MergeOutcome::Duplicate`, so no coordination is needed to avoid double execution.
- **Enforcement:** `require_admin` becomes `require_quorum(action)`. API adds `propose`, `approve`,
  `proposals()`. Rotation additionally becomes a quorum action here, which serialises the concurrent
  rotation that `NamespaceEpoch` currently settles after the fact.

---

## Phase 9 — Publishing cost and blob GC

Post-0.1 and non-breaking, which is why it ranks last despite the quadratic growth.

- Track a per-document `published_up_to` version vector (reserved in 7.1) and export with
  `ExportMode::updates_from(vv)` instead of `all_updates()`.
- **Not a straight swap.** The comment at the export site is correct: `all_updates()` is what makes
  each chunk self-sufficient under loss. The design is delta chunks plus a periodic full-snapshot
  chunk. The machinery exists — `last_ref` gives the receiver the DAG to see what it is missing, and
  an unresolvable delta parks in `pending_chunks`, which already retries.
- **GC.** `store_chunk` writes at a fixed key per document, so the *index* does not grow — but every
  superseded *blob* stays forever. Add a tag/GC pass keyed on each entry's current `content_hash`.
  `delete_file` and namespace rotation both depend on this to reclaim space.

---

## Testing strategy: user stories → scenarios → properties

One `Scenario` per user story in [docs/USER_STORIES.md](docs/USER_STORIES.md). Existing scenarios:
`Honest`, `Churn`, `Forging`, `Eviction`, `Outsider`, `Crud`, `CrudChurn`. Absent, and named by the
phase that brings them: `Insider` and `Revenant` (Phase 5), `StolenInvite` (Phase 6, landed), `OfflineEdit`
(Phase 7), `Onboarding` (unblocked already — see Story 1).

### Cross-cutting — asserted in *every* scenario

| Property | Kind | Status |
|---|---|---|
| No chunk / control op stays parked forever | `eventually_within` | exists |
| A healthy run never evicts anything | `always` | exists |
| Runs are reproducible for a fixed seed | — | exists |
| A node's own acknowledged writes are always in its own view | `always` | exists |
| Every node's `users()`/`devices()` and `index` converge after quiescence | `eventually_within` | exists |
| No node accepts an entry from an author with no writing role | `always` | exists |
| No node's membership, roles or device bindings ever change except under a valid capability chain | `always` | **new** (Phase 5) |

The last row is the one that would have caught the finding, and it is cross-cutting deliberately: an
insider property asserted only in an insider scenario tells you nothing about whether the honest path
quietly accepts uncertified state. Assert it everywhere, including in `Honest`.

### Story 1 — User invitation

**Scenario `Onboarding` (new).** Founder creates files and content, then admits users at staggered
times, some with several devices. Faults: `swarm().partitions().latency_ms(..).reorder()`.

| # | Property | Kind |
|---|---|---|
| 1.1 | Every admitted device eventually reads the same content as the founder for **every** file — the literal "immediately access workspace files" claim | `eventually_within` |
| 1.2 | A joiner never reads content written before its own `Add` unless re-published afterwards — forward secrecy as an *observable* property | `always` |
| 1.3 | No node holds a role it was not granted — guards the `found()`/`joined()` distinction | `always` |
| 1.4 | All of a user's devices converge to the same view of every file | `eventually_within` |

Property 1.1 protects the republish rate limiter shipped in Phase 1: throttled too hard, onboarding
silently breaks, and nothing currently states that as a property.

### Story 2 — Diff reconciliation

**Scenario `OfflineEdit` (new, Phase 7),** two variants because "offline" means two things:
**disconnected** — `scripted().at(t1).partition(&[0,1],&[2]).at(t2).heal_all()`; **shut down** —
`scripted().at(t1).crash(2).at(t2).restart(2)`, the variant that forces the 7.4 harness.

| # | Property | Kind |
|---|---|---|
| 2.1 | After heal, every node's `read(doc)` is byte-identical for every document | `eventually_within` |
| 2.2 | No acknowledged write is lost: the multiset of `Ok` fragments equals the multiset in the converged text | `eventually_within` |
| 2.3 | A node's own writes are readable locally the instant they are acknowledged, partition or not | `always` |
| 2.4 | `files()`, `users()` and roles converge after heal | `eventually_within` |
| 2.5 | Convergence holds across a crash/restart with no re-invite | `eventually_within` |
| 2.6 | A restarted device keeps its `EndpointId` and stays on every peer's roster | `always` |

### Story 3 — User removal

**Scenario `Eviction`** carries the confidentiality and visibility properties already, under names
that should be matched to rather than renamed: `the_victim_never_sees_an_entry_written_after_its_removal`,
`every_remaining_member_sees_the_entry_the_victim_does_not`,
`the_victim_never_adopts_the_rotation`, `the_remaining_members_converge_on_one_namespace`,
`no_remaining_member_accepts_a_post_revocation_entry_from_the_victim`,
`rotation_does_not_cost_the_remaining_members_their_content`. `Churn` carries convergence under
concurrent removal and rotation.

Still open on the honest-victim axis:

| # | Property | Kind | Status |
|---|---|---|---|
| 3.1 | The victim never observes a **manifest** update after removal — no new file names, no role changes. "Or workspace changes" in the story | `always` | **new** |
| 3.2 | Removing one device of a user leaves that user's other devices fully functional | `always` | core-only today (`removing_one_device_leaves_the_users_other_devices_alone`); **new** as a sim property |

**Insider (Phase 5) — the block that does not exist.**

**Scenario `Insider`.** A node that joins legitimately, is granted the *lowest* role, and then issues
operations its role does not permit. Distinct from `Forging`, and the distinction is the whole point:
a forging node signs with a key no `Add` ever introduced, so `known_members` refuses it; an insider
signs with a key the group itself admitted. A second variant, `Revenant`, is an `Eviction` victim
that keeps issuing after its removal, exercising the monotone-`known_members` re-entry path.

| # | Property | Kind | Status |
|---|---|---|---|
| 3.3 | A member whose role cannot administer never causes a membership change on any other node — its `Add` and `Remove` are dropped, not merged | `always` | **new**, fails today |
| 3.4 | No node's `role_of(user)` ever exceeds what a valid chain grants — a member cannot promote itself by writing the manifest | `always` | **new**, fails today |
| 3.5 | No device→user binding is accepted without a chain from an existing device of that user or an admin | `always` | **new**, fails today |
| 3.6 | `group_size()` never increases except by an `Add` issued under an admin capability | `always` | **new**, fails today |
| 3.7 | A removed member's later `Add` never enters any remaining member's tree, however long the run goes and whatever the delivery order — the `Revenant` variant | `always` | **new**, fails today |
| 3.8 | Under 3.3–3.7, honest nodes still converge and never evict — the insider must be *neutralised*, not merely survived | `eventually_within` | **new** |
| 3.9 | An insider's own view stays self-consistent: rejecting its operations must not make it diverge into a permanent repair loop | `eventually_within` | **new** |

3.8 and 3.9 are what stop the fix from being "reject more aggressively". A check that diverges the
group or spins the repair path is not a fix, and both failure modes are reachable — 3.9 in particular
guards against a rejected insider issuing `RequestRepair` forever.

### Story 4 — Outsiders and adversaries

**Scenarios `Forging`** and **`Outsider`** exist and cover 4.1–4.4:
`no_forged_member_ever_enters_the_group`, `honest_nodes_still_converge_while_under_attack`,
`forgery_traffic_never_fills_the_parking_queues`, `an_unadmitted_node_never_observes_an_index_entry`,
`an_unadmitted_node_never_observes_a_control_operation`, `an_unadmitted_node_is_on_nobodys_roster`.

| # | Property | Status |
|---|---|---|
| 4.5 | A forging node's entries never enter any honest node's index | **new** |
| 4.6 | A replayed invite never enters `users()`, never decrypts content, and after the next rotation its `observed_keys()` stops growing | **landed** (Phase 6, `a_stolen_invite_buys_only_visibility`) |

**Read the scope of this story literally.** Every adversary here sits *outside* the group. **No
property in this story constrains a member** — that is why the insider finding survived a green
suite. The insider is Story 3's problem and lives in the block above. When adding an adversarial
property, decide first which of the two families it belongs to; putting an insider property here is
how it ends up written against the wrong scenario and passing vacuously.

---

## Verification

```bash
cargo test -p iroh-beekem-core        # focused crypto + hostile-input regressions
cargo test -p iroh-beekem-sim         # the property suite — where behaviour is specified
cargo test -p iroh-beekem             # two real endpoints: transport wiring only
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly-2025-11-21 fmt --all --check   # rustfmt.toml uses nightly-only options; the
                                              # toolchain is pinned because an unpinned nightly
                                              # changes the expected formatting
cargo run -p iroh-beekem --example two_node

# core purity — must match nothing:
cargo tree -p iroh-beekem-core -e normal --prefix none \
  | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'

# Workspace mode, not two per-crate runs: `iroh-beekem` depends on `iroh-beekem-core`
# by version as well as path, so a per-crate dry run cannot resolve it against the
# registry until core is actually released.
cargo publish --dry-run --workspace
```

Raise `SEEDS` once faults are in play; consider propsim's `rigorous()` preset nightly while keeping
`deterministic()` for the fast path.

**Two real-QUIC tests are required, because the simulator models effects rather than mechanisms:**

1. A node whose `EndpointId` is not on the roster must fail to connect on **all three** ALPNs — this
   is what proves `RosterGuard` is wired to iroh, not merely modelled.
2. A removed member's node, kept running against two live endpoints, must fail to sync the rotated
   namespace, proving the modelled epoch capability check corresponds to what `iroh-docs` enforces.

**Falsification tests for Phase 5 — write these before the fix and confirm they fail.** A security
fix whose test was never seen red has proved nothing. Each is three or four lines against the
existing `two_node_workspace()` bus in
[workspace_state.rs](crates/iroh-beekem-core/tests/workspace_state.rs), so there is no reason to
defer them behind the propsim scenario work.

- **Insider `Add`:** build a two-member workspace, give member B a Viewer role, have B's
  `CgkaController` issue an `Add` for a fresh keypair, feed the operation to A's `WorkspaceState`.
  **Expected today: accepted, and `group_size()` increments on A.**
- **Revenant `Add`:** remove B, then have the removed `CgkaController` sign an `Add` naming
  pre-removal predecessors and feed it to A. **Expected today: accepted**, because `known_members` is
  monotone. This is the one that contradicts User Story 3 directly.
- **Manifest escalation:** have a Viewer write `roles[self] = Admin` into its manifest, publish, and
  ingest on the admin's node. **Expected today: `role_of_member` on A returns `Admin` for B.**

The example at [two_node.rs](crates/iroh-beekem/examples/two_node.rs) is the readable proof the CRUD
API is usable; keep it that way as the API grows.

---

## README maintenance

Outstanding as of this revision — everything else previously listed here has been actioned.

- **Add a *Threat model* section** from the two tables above. `grep -i "threat|insider|adversar"`
  over README.md and CLAUDE.md currently returns nothing.
- **Add the insider gap to *Current trade-offs* until Phase 5 lands, and delete it after.** Trade-off
  9 ("roles are advisory against a cryptographically capable member") is *understated*: it reads as
  "roles do not constrain what a malicious member can read", which is forward secrecy working as
  designed. The unstated half is that roles do not constrain what a malicious member can **do** — add
  members, remove the admin, promote itself — and that is a defect, not a trade. Keep the two claims
  visibly separate; conflating them is what made this look already documented.
- **Amend the `known_members` monotonicity paragraph.** Its "removed members' operations cannot reach
  the root key anyway" clause is true for `Update` and false for `Add`. Monotonicity stays; the
  justification needs the qualifier, or the next reader inherits the same false comfort.
- **Restate the CGKA/manifest split.** "The CGKA decides who *can* decrypt; the manifest decides who
  is *authorised* to act" appears in both README and CLAUDE.md and is the root framing behind the
  finding. Until Phase 5, write it as "the manifest *records* what well-behaved peers agreed to";
  after, "the capability chain decides who is authorised to act; the manifest records it."
- **Add the `Announce` write-telemetry leak** to *Deliberate trade-offs* — real-time per-write
  metadata to the whole overlay is not currently listed anywhere.
- **Add the grant-expiry trade** (Phase 5.4) beside the monotone `known_members` entry it mirrors.
- **Update *Verification*** to match what CI actually runs: the nightly `fmt --check` and
  `cargo publish --dry-run --workspace` are both missing from the README block.
