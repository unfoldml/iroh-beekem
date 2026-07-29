# Progress and implementation plan — iroh-beekem

## Context

The near-term goal is **a publishable 0.1 crate**, so the governing question is *"what freezes the
public API, and what would be embarrassing to ship."*

Phases 0–4 are closed. What remains is ordered by one finding from the post-Phase-4 security review,
which outranks everything else on the list:

> **Authorization is enforced only on the node that issues an action.** Every role check —
> `require_admin`, `require_write`, `require_may_add_device_to`, `require_not_last_admin` — runs
> against the *issuer's own* manifest view before it acts. **No receiving node checks the issuer's
> role for anything.** `CgkaController::merge_verified` verifies the signature and `known_members`
> and stops there; `on_manifest_arrived` calls `manifest.import()` with no attribution at all. So a
> member holding the *lowest* role can add members, remove the admin, and promote itself, and every
> peer will merge all three.

That makes Phase 5 a 0.1 blocker: the admission control of Phase 3 and the removal machinery of
Phase 4 are both downstream of predicates any member can rewrite, so until a receiver can check *who
was allowed to issue this*, they constrain well-behaved peers and nothing else.

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

### Residuals from the landed phases

Small, verified, and homeless — each is picked up by a phase below.

- **`author_seed` has no production caller.** `Workspace::assemble` still calls `author_create()`,
  minting a random author every spawn. Harmless until restart exists → **Phase 7.3**.
- **`keyhive_crypto` is still a required downstream dependency.** `add_user` and `add_device` take
  `MemberId` and `ShareKey`, and [lib.rs](crates/iroh-beekem/src/lib.rs) re-exports neither, so a
  caller cannot invite anyone without adding `keyhive_crypto` to their own manifest. **0.1 freezes
  this** — re-export both types, or wrap them → **Phase 6**, with the rest of the invite surface.
- **`Workspace::delete()` was specified and never built.** `open`/`list` land in Phase 7 and `leave`
  in Phase 8; `delete` joins the latter.
- **CLAUDE.md's coverage workflow is dangling.** It cites `make coverage`, `make coverage-check`,
  `make check` and `COVERAGE.md`; there is no `Makefile` and no `COVERAGE.md` in the repo. Either
  build the target or correct the reference — it is the "standing to-do surface" contributors are
  pointed at.

---

## The design as it stands

Today's answers, with the reasoning that produced them and what else moves if they change. None is
settled; if a user story needs a different answer, change it. Three of them carry a qualifier the
security review added, marked **⚠**.

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

- **The manifest is where permissions are recorded** ([manifest.rs](crates/iroh-beekem-core/src/manifest.rs)):
  logical paths, roles, and the `iroh-docs` author → CGKA member mapping. `ingest_all` therefore
  reads the manifest before document entries — `author_may_write` needs the mapping, so the reverse
  order rejects legitimate entries.
  **⚠** The standing phrasing, *"the CGKA decides who can decrypt; the manifest decides who is
  authorised to act"*, reads as a settled separation of concerns while assuming the manifest is
  trustworthy. It is not: `on_manifest_arrived` gates only on *decryptability*, so any member can
  write any `roles`/`devices` record and every replica merges it. Until Phase 5, the honest statement
  is "the manifest *records* what well-behaved peers agreed to."

- **Authentication is ours, not beekem's.** beekem verifies nothing, so `CgkaController::merge`
  ([keys.rs](crates/iroh-beekem-core/src/keys.rs)) adds the two checks that make a public gossip topic
  safe: signature against the embedded issuer key, then issuer ∈ `known_members`. Order matters —
  membership is checked only *after* predecessors are in hand, or a member whose own `Add` is still in
  flight would be rejected. `known_members` is monotone (a `Remove` does not retract) because
  retracting would make admissibility depend on delivery order and diverge peers.
  **⚠** Two checks are all there are; there is no third check on what the issuer's role permits.
  Monotonicity is also defended in the field docs on the grounds that a removed member's operations
  "cannot reach the root key anyway" — true for `Update`, which must re-key a path the issuer can
  derive, and **false for `Add`**, which needs no root key: the injected leaf receives key material
  from the next honest re-key, because that re-key encrypts the path to every resolution including
  the new leaf. Monotonicity remains the right call for the divergence reason it was chosen for; it
  is simply not, on its own, a containment argument.

- **Admission control is an authenticated allowlist over endpoint ids.** All three ALPNs are wrapped
  in `RosterGuard` ([roster.rs](crates/iroh-beekem/src/roster.rs)); an `EndpointId` is the peer's
  public key, authenticated by the QUIC handshake. The roster is *derived*, never authored —
  `WorkspaceState::roster` intersects the manifest's device addresses with `current_members` — so it
  converges like everything else and inherits the admin gating on `AddUser`/`AddDevice`. Computed in
  the core so the rule is testable without a socket. Eviction is eventual, and it is an availability
  boundary, not a confidentiality one.
  **⚠** "Derived, never authored" is the security argument for the whole phase, and it holds only as
  far as the inputs it derives *from* are trustworthy. Both are member-writable today:
  `current_members` moves on any member's `Remove`, and the `devices` container merges whatever any
  member writes. The guarantee is real against an outsider and vacuous against a member. Phase 5 is
  what makes the sentence true as written.

---

## Threat model — what is confidential, from whom

Belongs in the README as well; its absence is what let the findings above go unnoticed.

| Layer | Protected by | An outsider holding the identifiers sees |
|---|---|---|
| **Blob payloads** | Per-chunk AEAD keys from the CGKA, bound to content ref + predecessor refs | Ciphertext only. **This part genuinely delivers.** |
| **Data-plane index** (`iroh-docs`) | `RosterGuard`, then knowledge of the `NamespaceId` | Nothing, unless admitted. Once admitted: blinded keys (document count, which changed, when), entry sizes, author ids, timestamps |
| **Control plane** (`iroh-gossip`) | `RosterGuard`, then knowledge of the `TopicId` | Nothing, unless admitted. Once admitted: **everything, in plaintext** — every `Signed<CgkaOperation>`, so every member key added or removed, every rotation, the full log replayed on each `NeighborUp`, plus `ControlMsg::Announce { key }`, which is real-time telemetry for every write |

Two structural points survive the roster:

- **The topic id is the founder's public key** and never rotates, so everyone ever invited knows it
  permanently. Rotating it would require a new tree id — that is, a new workspace. The roster is what
  refuses them.
- **One leaked invite, ever, is permanent.** Phase 6's expiry stops *replay of the join*, but the
  `tree_id`, `TopicId` and blinding secret it carries never rotate.

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

## Phase 6 — Invite security and the public surface

The README's "invites are replayable" understates one half and overstates the other. A leaked
`Invite` **does not grant read access**: `CgkaController::join` requires the `share_secret` whose
`ShareKey` the inviter named in the `Add`, and that never travels in the ticket. What it *does* grant
is the whole threat-model surface: sync and write capability on the data plane, and the topic id.

- Add `invitee: [u8; 32]`, `not_after: u64` (absolute ms), `nonce: [u8; 16]`, and `epoch: u32` to
  `Invite`, plus the Phase 5 `Grant` and `DeviceBinding`.
- Sign the whole `Invite`; `join` verifies the signature and that `invitee` matches the joining
  `Identity`.
- **Do not add a clock to `iroh-beekem-core`.** Expiry is checked in `iroh-beekem`, which has one; if
  the core ever needs the timestamp it arrives as data. That constraint is what makes the simulator
  possible and is enforced by the `cargo tree` check.
- Track consumed nonces so a ticket is single-use.
- **Close the `keyhive_crypto` leak** while the invite surface is open: re-export or wrap `MemberId`
  and `ShareKey` so a caller of `add_user`/`add_device` needs only `iroh-beekem`. 0.1 freezes this.

**Ships with:** the `StolenInvite` scenario.

---

## Phase 7 — Persistence

Implements `Workspace::open` / `list` and turns "local-first" from a claim into a fact.

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

## Phase 8 — Lifecycle and M-of-N admin

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
phase that brings them: `Insider` and `Revenant` (Phase 5), `StolenInvite` (Phase 6), `OfflineEdit`
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
| 4.6 | A replayed invite never enters `users()`, never decrypts content, and after the next rotation its `observed_keys()` stops growing | **new** (Phase 6, `StolenInvite`) |

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
