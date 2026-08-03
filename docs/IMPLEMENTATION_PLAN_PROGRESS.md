# Progress and implementation plan — iroh-beekem

## Context

The near-term goal is **a publishable 0.1 crate**.

Phases 0–11 are closed: the crate metadata and CI, per-user roles over a multi-document facade, roster
admission on every ALPN, removal-then-rotation with demand-driven repair, receiver-checked capability
certificates, signed single-use invites, persistence and restart, M-of-N admin actions, publishing
cost with blob collection and large binary assets, versioning with checkpoints and revert, and — now —
the named gaps in the property suite.

Phase 11 is worth a sentence of its own because it changed the *system* and not only the tests. Two of
the four gaps could not be stated as written until the simulator gained something it was missing: a
receiver-side author check on arriving entries, which existed only in the facade, and any notion of a
person owning more than one device. A third turned out to be mis-stated in a way that would have made
it pass while asserting nothing. Those findings are recorded under
[the gaps](#the-gaps-that-were-in-the-property-suite-and-what-closing-them-found); what is left is
under [What remains open](#what-remains-open).

This document records **what exists and why it is that way**. Where it and the code disagree on
detail, the code wins. [docs/USER_STORIES.md](USER_STORIES.md) states what the project is *for* and
outranks both.

---

## What has landed

| Phase | Shipped | Lives in |
|---|---|---|
| 0 | versioned core dependency, both LICENSEs, crates.io metadata and per-crate READMEs, five-job CI (test / lint / purity / msrv / publish-dry-run) | [ci.yml](../.github/workflows/ci.yml) |
| 1 | `author_seed(&self, member)`; `require_write` + `CoreError::NotAWriter`; `NeighborUp` and republish cooldowns | [blinding.rs](../crates/iroh-beekem-core/src/blinding.rs), [state.rs](../crates/iroh-beekem-core/src/state.rs), [workspace.rs](../crates/iroh-beekem/src/workspace.rs) |
| 2 | `Identity`; `users`/`devices`/`meta` containers with roles per *user*; multi-document facade; `drive()`; `WsOp` + `crud_workload` + `ClientCodec`; `Msg::Entry` with per-node `index` and `roster` | [identity.rs](../crates/iroh-beekem/src/identity.rs), [manifest.rs](../crates/iroh-beekem-core/src/manifest.rs), [sim/lib.rs](../crates/iroh-beekem-sim/src/lib.rs) |
| 3 | `RosterGuard` on all three ALPNs, roster derived from certified devices ∩ `current_members`, bootstrap admission for cold joiners | [roster.rs](../crates/iroh-beekem/src/roster.rs), `WorkspaceState::roster` |
| 4 | `Remove`-before-rotate ordering, `NamespaceEpoch` on `(epoch, digest)`, `Effect::AdoptNamespace`, demand-driven repair via `Keying::Fresh`, read-only invite tickets for Viewers | [state.rs](../crates/iroh-beekem-core/src/state.rs), [workspace.rs](../crates/iroh-beekem/src/workspace.rs) |
| 5 | `Grant`/`DeviceBinding`/`CapabilityStore` with a monotone `ever_admin` and `(seq, digest)`-ordered `role_of`; the third check in `merge`; `AuthorizedOp` proof bundles on `BroadcastOp`/`ControlMsg::Op`/`Msg::Op`; `ControlMsg::Log` ships the whole store; `Effect::BroadcastCerts` and `Effect::EvictUncertified`; roles and bindings removed from the manifest; `Insider` and `Revenant` scenarios | [capability.rs](../crates/iroh-beekem-core/src/capability.rs), [keys.rs](../crates/iroh-beekem-core/src/keys.rs), [state.rs](../crates/iroh-beekem-core/src/state.rs) |
| 6 | `Signed<InviteTerms>` with `invitee`/`not_after`/`nonce`/`epoch`; domain tags on all three signed payload types, checked before the signature; `Node::claim_invite` nonce ledger; `Enrollment` plus `MemberId`/`ShareKey`/`Role` re-exports; `WorkspaceState::joined` seeded with the joiner's namespace generation; `Msg::Welcome` carries the invitee and the replica; `StolenInvite` scenario | [invite.rs](../crates/iroh-beekem/src/invite.rs), [identity.rs](../crates/iroh-beekem/src/identity.rs), [node.rs](../crates/iroh-beekem/src/node.rs) |
| 7 | `snapshot.rs` with `CgkaSnapshot`/`WorkspaceSnapshot`; `WorkspaceState::export`/`import`; `Node::spawn_persistent` with a persisted endpoint key and nonce ledger; `Workspace::open`/`list`/`delete`; derived `iroh-docs` author from `author_seed`; roster registry keyed by tree id; a simulated disk and an authored wipe in `WorkspaceNode` | [snapshot.rs](../crates/iroh-beekem-core/src/snapshot.rs), [store.rs](../crates/iroh-beekem/src/store.rs), [roster.rs](../crates/iroh-beekem/src/roster.rs) |
| 8 | `Event::Leave` and `Workspace::leave`; `Policy`/`AdminProposal`/`Approval` as tagged certificates; a founder-fixed threshold; `require_quorum` on the issuer **and** a quorum check in `CgkaController::authorize` on every receiver; `Event::ResyncCertificates`; `propose`/`approve`/`proposals`/`threshold`; `Departure` and `Quorum` scenarios | [capability.rs](../crates/iroh-beekem-core/src/capability.rs), [state.rs](../crates/iroh-beekem-core/src/state.rs) |
| 9 | blob collection (`temp_tag` + the `iroh-docs` protect callback, `NodeOptions`); delta publishing (`Extent`, `published_up_to`, quiescent resync, `RepairTarget::DocumentHistory`); large assets (`asset.rs`, envelope encryption, blinded segment key spaces, `attach_file`/`export_asset`, lazy download policy, the pending-asset intent log); rotation re-indexes assets; `Msg::Segment` and range reconciliation in the simulator; `Assets`/`AssetChurn` scenarios | [asset.rs](../crates/iroh-beekem-core/src/asset.rs), [blinding.rs](../crates/iroh-beekem-core/src/blinding.rs), [workspace.rs](../crates/iroh-beekem/src/workspace.rs), [node.rs](../crates/iroh-beekem/src/node.rs) |
| 10 | versioning: `version.rs` with `UnixSeconds`/`VersionId`/`VersionInfo`/`Checkpoint`/`AssetVersion`; a supplied clock on `WorkspaceState::handle`; per-document `authors` claims and `set_change_merge_interval(-1)`; `document_versions`/`document_text_at`/`Event::RevertDocument`; digest-keyed checkpoints with `RestoreOutcome`; per-version asset key spaces with `attach_version`/`export_asset_version`/`revert_asset`; `WsOp::Revert` in the generated workload; parked chunks no longer cached as delivered | [version.rs](../crates/iroh-beekem-core/src/version.rs), [state.rs](../crates/iroh-beekem-core/src/state.rs), [manifest.rs](../crates/iroh-beekem-core/src/manifest.rs), [workspace.rs](../crates/iroh-beekem/src/workspace.rs) |
| 11 | the named suite gaps: multi-device enrolment (`Scenario::SECOND_DEVICE`, `Msg::Hello::as_device_of`, `Onboarding`/`DeviceChurn`); the receiver-side author check in the simulator's `on_entry` and a data-plane forger (`FORGED_DOC`, `ROGUE_AUTHOR`); `AssetAfterRemoval`; loss and fabrication over `World::history()` with `append_only_workload`; post-revocation manifest and role changes (`FILE_AFTER_REVOKE`, `PROMOTE_AFTER_REVOKE`); `ANNOUNCED_ONCE` shared by `resync` and `republish` | [sim/lib.rs](../crates/iroh-beekem-sim/src/lib.rs), [properties.rs](../crates/iroh-beekem-sim/tests/properties.rs), [workspace.rs](../crates/iroh-beekem/src/workspace.rs) |
| 12 | one control-plane dispatch: `ControlMsg` and the chunk codec move to [core/wire.rs](../crates/iroh-beekem-core/src/wire.rs) with `MAX_LOG_OPS`/`MAX_LOG_CERTS`; `WorkspaceState::on_control` replaces the facade's `apply_control_msg` and the simulator's `apply_msg` control arms; `Msg::Control(ControlMsg)`; `ANNOUNCED_ONCE` and `Cooldown` move to the core, the latter generic over wall and virtual time; `Effect::ResealAssetKey` gives the asset-key repair an answer on **both** backends, where the core previously returned nothing and the simulator answered nobody; one `author_may_write`, with the simulator publishing an author claim, exempting the manifest and replaying refused entries | [state.rs](../crates/iroh-beekem-core/src/state.rs), [wire.rs](../crates/iroh-beekem-core/src/wire.rs), [cooldown.rs](../crates/iroh-beekem-core/src/cooldown.rs) |

The threat model — what is confidential and from whom, and what a member, a removed member and the
holder of a leaked invite can each actually do — lives in [README.md](../README.md) under *Threat
model*, together with *Current trade-offs* and *Not yet implemented*. Those three lists are
authoritative; consult them before proposing a fix for something already recorded.

---

## The design as it stands

Today's answers, with the reasoning that produced them and what else moves if they change. None is
settled; if a user story needs a different answer, change it.

### Transport and repair

- **Three protocols by ALPN on one `iroh::Endpoint`** ([node.rs](../crates/iroh-beekem/src/node.rs)):
  gossip carries `Signed<CgkaOperation>` on a topic derived from the CGKA tree id, docs carries the
  index of blinded keys → content hashes, blobs carries the encrypted payloads. Spawn order matters as
  written: blobs and gossip before docs, which is handed both.

- **Missed control operations are repaired by re-shipping the whole log** on `NeighborUp`
  (`ControlMsg::Log`, [wire.rs](../crates/iroh-beekem-core/src/wire.rs)). A peer that misses an operation
  can never derive keys for anything encrypted after it, so *some* repair is needed; whole-log resend
  is simply the cheapest one to write.

- **Unreadable content is repaired on demand, by the peer that cannot read it.** A member admitted
  after content existed can never derive the epoch that content was keyed under, and anti-entropy
  cannot fix that: `Event::Resync` re-encrypts under the *current* epoch, so for such a peer every
  repeat reproduces a ciphertext it already failed on. `Effect::RequestRepair` names the
  `(target, epoch)` it is stuck on, and `Event::RepairRequested` is answered by re-publishing through
  `Keying::Fresh`, which mints an epoch every leaf in the tree can derive and nothing outside it can.
  Demand-driven rather than scheduled because answering costs a tree operation: re-keying on a timer
  charges the whole group for a peer that may not exist.

- **Everything broadcast once needs its own anti-entropy.** A document has a later write behind it; a
  rotation, a manifest change and a certificate do not. `Event::ResyncNamespace`,
  `Event::ResyncManifest` and `Event::ResyncCertificates` exist for exactly that, and **both backends
  must drive all three from their resync paths**. Dropping any one has a distinct cost: a stranded
  member on an abandoned replica, a peer missing from somebody's roster until the next membership
  change, or — worst — a quorum that formed on one node and nowhere else, leaving an action performed
  there and refused everywhere.

  There are **three such paths across two backends**, and the list had drifted twice. First inside
  `iroh-beekem`, between the public `Workspace::resync` and the internal `republish` a `NeighborUp`
  takes: `republish` drove all three while `resync` drove only the manifest and the namespace, a hole
  reachable by a library caller and by no in-tree test, since every one of them reaches anti-entropy
  through the other path. Then across the crate boundary, where the simulator's `republish` drove all
  three and its periodic `Tick::Resync` drove two, leaving certificates to the sparser `Msg::Log`
  cadence. All three now share `ANNOUNCED_ONCE`
  ([state.rs](../crates/iroh-beekem-core/src/state.rs)), which makes both divergences
  unrepresentable rather than merely fixed. A per-path cadence is precisely what the shared list
  exists to refuse: if the certificate broadcast proves too talkative for the harness, the fix is to
  lengthen `RESYNC_INTERVAL`, not to shorten the list.

- **Content flows through Loro as CRDT updates**, so a chunk applies only when the CGKA can reach the
  PCS key it names *and* Loro has the operations it depends on — that second condition is what
  `park_chunk` / `drain_pending` / `try_apply` exist for. Both parking areas are bounded
  (`MAX_PARKED_OPS`, `MAX_PENDING_CHUNK_BYTES`, `MAX_PENDING_CHUNKS`) and evict oldest-first, because
  unbounded queues are a remote memory-exhaustion vector; a property test asserts an honest run never
  evicts. A payload path that did not route through the CRDT would not need the second condition.

- **Storage keys are blinded**: `BLAKE3-MAC(workspace_secret, document_uuid)`, fixed 32 bytes, keyed on
  a stable UUID rather than a path so a rename touches only the encrypted manifest
  ([blinding.rs](../crates/iroh-beekem-core/src/blinding.rs)). Follows from `iroh-docs` reconciling by
  key with keys in the clear.

### Publishing cost, assets and collection

- **An ordinary edit publishes a delta; a resync of an unchanged document publishes nothing.**
  `Extent` is orthogonal to `Keying` — how much history versus which epoch key — and all four
  combinations are reachable. The quiescent-resync case is the larger saving and the one that looks
  unsafe and is not: the index entry naming the existing chunk is still there, and `iroh-docs`
  reconciles key ranges between peers, so a peer lacking it is served by whoever holds it. What makes
  *deltas* safe is that a receiver stuck on one says so — `AwaitingDeps` ages and raises
  `RepairTarget::DocumentHistory`, answered with a full export under the current epoch rather than a
  re-key, because the requester can decrypt perfectly well.

- **`published_up_to` describes a namespace, not a document.** A rotation abandons the index, so
  `forget_published` clears it on both adoption paths — otherwise the post-rotation republish emits
  nothing and the group converges on a replica holding only later edits.

- **An asset is an envelope, and that is the whole design.** Segments are sealed with
  XChaCha20-Poly1305 under a per-asset content key; only that 32-byte key is encrypted to the group.
  Keying segments with CGKA application secrets directly costs nothing to write and everything
  afterwards: a member admitted later could only be served by re-encrypting every segment under a
  fresh epoch, and a rotation would re-upload every byte. With the envelope both are one small chunk.
  Nothing is weakened — anyone who could decrypt the segments could decrypt the key — and forward
  secrecy keeps its granularity because an asset is immutable and a new version draws a new key.

- **Asset segments are indexed eagerly and fetched lazily.** They share a blinded 24-byte prefix so a
  `DownloadPolicy::EverythingExcept` can name their key space; without that every member downloads
  every asset the moment its entries reconcile, which is the "slowing down document synchronization"
  the user story rules out. They never enter `pending_chunks`, because they are pulled at export time
  rather than pushed at ingest time.

- **Blob collection is `temp_tag` plus the `iroh-docs` protect callback, and both halves are
  required.** Awaiting `AddProgress` mints a *permanent* tag, so before this the sweep reclaimed
  nothing however it was configured; a sweep without the callback would reclaim everything not
  currently being written. What it does *not* reach is anything indexed only in an abandoned
  namespace, since those replicas are kept for peers still catching up.

- **`attach_file` records the asset's UUID durably before its first segment.** Segments are indexed
  before the manifest entry that declares them, and a segment key is a blinded MAC of a UUID that
  lives only in memory until that entry lands — so an interrupted attachment would leave blobs that
  are protected from collection and nameable by nothing. The intent log is what makes the startup
  sweep possible.

### Versioning

- **A revert is a forward edit; history is never rewritten.** A document reverts through Loro's
  `revert_to`, which appends the inverse of everything after the named version, and an asset reverts by
  appending a version record naming segments that are already stored. The alternative — dropping the
  operations after that point — is not available in a group at all: a peer that had already merged them
  would keep them and the two replicas could never agree again. Two properties fall out and both are
  tested: a revert converges with a concurrent edit like any other write, and the version reverted away
  from stays listed, so a revert can be reverted.

- **Attribution is recorded, not derived, and that is a correctness decision rather than a taste one.**
  The obvious design — derive each device's Loro peer id from the workspace secret and the member id, so
  every peer can invert it — corrupts documents. Assigning a peer id also fixes the operation counter a
  replica writes next, so any device that loses a document's local history while another replica keeps
  it (deleting and recreating a UUID, resuming a wipe) restarts its counter and mints operation ids that
  already name different operations. Loro says plainly that this can corrupt a document and recommends
  the random per-session id it defaults to. Peer ids therefore stay random and each writing replica adds
  one `peer id → member id` claim to an `authors` container inside the document. It is a claim in the
  manifest's sense — it grants nothing, so a lie costs a wrong name beside a change.

- **Time is a parameter of `WorkspaceState::handle`, never read.** The core has no clock; the simulator
  supplies `cx.now()`, so a seeded run produces byte-identical version timestamps and a property can
  assert on them. Loro raises a change's timestamp to at least the greatest on its causal ancestry, so a
  slow clock cannot date work before what it followed — but a fast one can date its own work in the
  future, which is why a timestamp is presented as a claim.

- **Change merging is off (`set_change_merge_interval(-1)`).** Loro merges consecutive local commits
  within an interval defaulting to a thousand seconds, which is right for an undo stack and wrong here:
  a change is what a version *is*, so three edits a minute apart would collapse into one entry nobody
  can revert past. Negative rather than zero, because the comparison is `<=` and a supplied clock can
  date a whole simulated run to one second.

- **Checkpoints are keyed by digest, asset versions too.** Keyed by name, two members tagging `v1.0`
  while partitioned would have one silently overwrite the other under Loro's own ordering — a fact about
  operation ids rather than about what either member did. Keyed by digest both survive and a name
  resolves by `(at, digest)`, a pure function of the values. Asset versions are separate map keys for the
  same reason *and* one more: a nested list would be *created* by whoever wrote the first version, and two
  replicas doing that concurrently create two containers, discarding a whole history rather than one
  record.

- **Each asset version owns its key space, and precedence leads with a per-entry sequence.** A new
  version publishing into the old one's blinded key space would replace the index entries, and an index
  entry is the only thing protecting a blob from collection — the previous version would be gone.
  Precedence is `(seq, at, content)`: `seq` is one past the highest the publisher had merged, because a
  timestamp is whole seconds and a member attaching twice in quick succession would otherwise have the
  order of its own writes settled by a coin toss between two random UUIDs. `asset_prefixes` covers every
  version, not just the current one — that list is what a peer declines to fetch eagerly, so leaving a
  superseded version out would have every member download it in full.

- **Deleting an entry withdraws every version's key space.** Missing one leaves its payload on every
  member's disk forever, for a file that no longer exists, and for assets that is measured in gigabytes.

- **A parked chunk must not be cached as delivered.** `seen_entries` in the transport caches what has
  been *fetched*, to stop a quiescent workspace re-decrypting everything on every sync event. A chunk
  awaiting CRDT dependencies has been fetched and not applied, and it is rescued only by the
  `DocumentHistory` repair the core raises after enough retries — so caching it meant no retries, no
  repair, and an edit missing on that peer permanently, with nothing reporting it. `ingest_all` now
  forgets the cache entry for any document still holding parked chunks.
  `a_peer_that_misses_the_base_of_a_delta_still_catches_up` in
  [two_node.rs](../crates/iroh-beekem/tests/two_node.rs) is the regression: two writes made faster than
  the peer can sync, which is ordinary rather than exotic.

### Removal and rotation

- **Removal rotates to a fresh `iroh-docs` namespace**: the `Doc` lives behind an `RwLock` because it
  is *replaced*, and the data-plane pump is respawned against the new subscription with the ingestion
  cache cleared. The removed device keeps the write capability it was given — `iroh-docs` has no
  per-member key to withdraw — so the capability is made worthless rather than revoked. The old
  namespace is left rather than dropped, since peers may still be catching up on it.

- **The order of a removal is the security property.** `on_remove_member` broadcasts the CGKA `Remove`
  *before* emitting `Effect::RotateNamespace`; the capability for the new namespace is then encrypted
  under a group key the removed leaf can no longer derive. Reversed, the removed device reads the
  announcement and follows the group. `NamespaceEpoch` orders on `(epoch, digest)` — a bare counter
  cannot settle two concurrent rotations, and the digest is recomputed from the decrypted capability so
  it cannot be claimed. Rotation is skipped when the target was not a member, or any admin could force
  a full re-publish at will.

- **A rotation re-encrypts documents and re-indexes assets.** The new replica starts empty, so a
  document is republished into it — small, and the right place to spend it. An asset is not: its
  segments are immutable ciphertext, so the same content hash is written into the new index. Sound
  rather than merely cheap, because the removed device could already read everything published before
  its removal and cannot reach the new replica at all; what the rotation protects is everything
  published after, which is under an epoch it can no longer derive. Only entries this node can
  actually serve are carried, since an index entry is a promise to serve.

- **The minter adopts its own rotation through `Effect::AdoptNamespace`**, not through a second code
  path in each backend. Without it, the admin who issued the removal is the one member still
  publishing into the namespace it just abandoned.

- **`leave` is announce-only and takes `&self`.** `GossipSender::broadcast` enqueues without
  acknowledgement, offers no flush, and dropping the subscription discards the queue — so a `leave`
  that consumed `self` would race its own departure, and a `Remove` has no anti-entropy behind it to
  repair the loss. Teardown is `delete`, called by the caller when ready. `leave` is a courtesy, not a
  security boundary: it triggers no rotation and no roster eviction, so an admin should follow it with
  a `remove_user`.

### Authorization

- **Authorization is carried by the operation and verifiable offline, rooted in the founder's key.**
  `tree_id = TreeId::from(founder_signing_key.verifying_key())`, and the founding `Add` is self-issued
  and verified in `CgkaController::join` before anything else is replayed — so the founder's public key
  is already a cryptographic identity every peer holds and cannot be argued out of. A certificate
  terminating there needs no new distribution channel, no new secret and no new convergence argument,
  which is what made this tractable rather than a redesign.

- **A role lookup at merge time was not an available design.** The tempting fix is to have `merge`
  consult the manifest for the issuer's role. The manifest is replicated, mutable, and converges at
  different times on different peers, so two peers evaluating one operation against different views
  reach different verdicts — one drops what the other keeps and the group diverges permanently. The
  same argument disposes of *"an `Add` introducing a device is admissible only if its issuer is already
  a device of that same user"*: that predicate is over the manifest, so evaluating it at merge time is
  order-dependent. What shipped is `require_may_add_device_to`, applied on the issuing node only.

- **`require_admin`, `require_write` and `require_quorum` are a local fail-fast, not enforcement.**
  They give a clear error instead of an operation every peer will drop, which is a good thing to have
  and a terrible thing to rely on: an attacker running modified code simply does not run them. Their
  doc comments say so ([state.rs](../crates/iroh-beekem-core/src/state.rs)). Enforcement is
  `CgkaController::merge` and `CgkaController::authorize`, on every receiver.

- **Authority never goes back into the manifest.** `Manifest::import` is an unconditional CRDT merge —
  `LoroDoc::import` merges an update atomically, so there is nowhere to hook a filter. "Record it in
  the manifest and validate on the way in" is not an available design, only an available bug. The
  split is by **what a lie costs**: the manifest holds logical paths, display names, labels and the
  self-attested author → member mapping, whose forgery grants nothing; roles and device bindings are
  certificates. **The capability closure decides who is authorised to act; the manifest records what
  that produced.** `ingest_all` still reads the manifest before document entries — `author_may_write`
  needs that mapping — but the *role* half of the check comes from the closure.

- **Authentication is ours, not beekem's.** beekem verifies nothing, so `CgkaController::merge`
  ([keys.rs](../crates/iroh-beekem-core/src/keys.rs)) adds three checks: signature against the embedded
  issuer key, issuer ∈ `known_members`, and a certificate admitting *this* operation. Order matters —
  membership is checked only *after* predecessors are in hand, or a member whose own `Add` is still in
  flight would be rejected. `known_members` is monotone because retracting would make admissibility
  depend on delivery order and diverge peers; that is a divergence argument and never was a containment
  one. What contains a removed member is eviction (`Effect::EvictUncertified`), not admissibility.

- **`ever_admin` and `role_of` are two predicates on purpose**, the same split as
  `known_members`/`current_members` for the same reason. `ever_admin` is monotone and decides whether a
  *certificate* is admitted, which is what makes the closure an order-independent function of the set —
  two peers holding the same certificates must always agree, or a receiver-side check diverges the group
  permanently. `role_of` is non-monotone, resolved by `(seq, digest)`, and decides whether an *action*
  is permitted, where disagreeing costs a refused action the next exchange repairs. Making admission
  consult `role_of` would let a demotion retract an earlier admission and the fixpoint would no longer
  be well defined.

- **A capability certificate must travel *with* the operation it authorises.** `Effect::BroadcastOp`
  carries a `proof`, and `ControlMsg::Log` ships the whole certificate store beside the operation log. A
  receiver checks the issuer's capability *before* merging, so an operation arriving without its
  certificates is **refused, not parked** — no later certificate brings it back.

- **Every signed payload carries a 16-byte printable-ASCII domain tag, and both halves are
  load-bearing.** `Signed<T>` covers `bincode(payload)` with no type name and no discriminator, so a
  genuine `(issuer, signature)` pair transfers between any two payload types whose encodings match byte
  for byte — and on the wire `Certificate` is an enum, so the destination type is the attacker's choice.
  Distinct tags stop a `Grant` being read as a `DeviceBinding`; printable ASCII stops either being read
  as a `CgkaOperation`. The full analysis, including the `DeviceBinding`-versus-`CgkaOperation::Remove`
  pair that motivated it, is in [README.md](../README.md) under *Signature domain separation*. **The
  standing rule: a new `Signed<T>` needs a tag and a line in
  `the_signed_payload_types_cannot_share_an_encoding`**
  ([capability.rs](../crates/iroh-beekem-core/src/capability.rs)), plus one in
  `the_invite_tag_is_distinct_from_every_certificate_tag`
  ([invite.rs](../crates/iroh-beekem/src/invite.rs)) — the constants live in crates with different
  release cadences, and nothing else notices a future tag chosen to collide.

- **`Grant::not_after` is carried on the wire and deliberately never evaluated.** An expiry inside an
  authorization predicate makes admissibility depend on clock skew, and two peers disagreeing would drop
  different operations. Revocation is CGKA-removing every device of the granting user, which is already
  a first-class operation and already converges. README trade-offs 14 (*Demotion is a courtesy*) and 19 (*Certificates are never retracted*) record the cost.

### A beekem caveat this design works around

- **`Cgka::group_size()` can disagree with the membership this crate maintains.** beekem checks
  `tree.contains_id` *before* replaying its operations graph and calls `tree.remove_id` *after*, so a
  node holding a merged-but-unreplayed concurrent removal both reports the removed member and refuses
  to remove it with `IdentifierNotFound`. Three things here exist because of it: assert membership
  over `current_member_count`/`sees_member`, never `group_size`; `run_quorum_actions` marks a proposal
  executed **only on success**, because burning the digest first turned a transient failure into
  permanent divergence; and `on_certs_arrived` runs the quorum pass whether or not a certificate was
  new, because a proposal can become executable without one arriving. A quorum removal makes
  concurrent identical removals the normal case, which is why this surfaced there.
  `beekem_group_size_disagrees_with_current_members` pins the behaviour so a fixed beekem is noticed;
  [docs/beekem-bug-repro/](beekem-bug-repro/) is the standalone reproduction for upstream.

### Quorum

- **The threshold is a founder-signed certificate, fixed at creation, never the manifest and never
  mutable.** A receiver-side quorum check is *stricter the more a node knows*, so a movable threshold
  would let a peer holding the certificates that raised it refuse an operation a peer still catching up
  had merged — permanent divergence. `Policy` is minted in `WorkspaceState::found` and travels in the
  bundle without which nobody could have joined, so no member is ever behind on it. Approvals are counted
  with `ever_admin` for the same monotonicity reason, and by **distinct users**, not devices — counting
  devices lets one person with three computers satisfy a threshold of three.

- **Enforcement is on the receiver, in `CgkaController::authorize`.** Above a threshold of one, a
  `Remove` naming somebody else is refused unless a matching proposal has reached quorum, and
  `Effect::BroadcastOp` carries the policy, the proposal and the approvals so a peer that has not seen
  them can still verify. A self-removal is never gated: a threshold governs what the group does *to* a
  member.

- **Above a threshold of one only the founder may set a role alone.** Two things depend on it:
  bootstrap, since a workspace with one admin and a threshold of two could otherwise never reach a
  quorum; and the puppet hole, since an admin who could appoint a second admin alone could approve its
  own actions twice. `AddUser` is gated with `SetRole` because admitting somebody assigns a role. The
  exemption covers roles only, never removals.

- **`AdminAction` has two variants — `RemoveMember` and `SetRole` — and deliberately no `Rotate`.**
  Namespace rotation is not independently proposable: `on_remove_member` emits it as a *consequence*, so
  gating the removal already gates the rotation and the variant would have been a wire format with no
  caller.

### Membership, admission and identity

- **Admission control is an authenticated allowlist over endpoint ids.** All three ALPNs are wrapped in
  `RosterGuard` ([roster.rs](../crates/iroh-beekem/src/roster.rs)); an `EndpointId` is the peer's public
  key, authenticated by the QUIC handshake. The roster is *derived*, never authored —
  `WorkspaceState::roster` intersects *certified* devices with `current_members` and announced endpoints,
  so a device with no signed binding contributes nothing whatever it writes. Computed in the core so the
  rule is testable without a socket. Eviction is eventual, and it is an availability boundary, not a
  confidentiality one.

- **The roster registry is keyed by workspace, but admission is a union across them.** Keying fixes a
  real defect — `set_derived` replaces wholesale, so two workspaces on one node clobbered each other on
  every refresh. It does not buy isolation: `RosterGuard::on_accepting` sees an `EndpointId` and nothing
  else, because gossip multiplexes every topic and docs every namespace over one connection per ALPN, so
  there is no workspace to attribute a connection to at the moment of the decision. Closing it means one
  endpoint per workspace. `admission_is_a_union_across_workspaces` pins the boundary deliberately; README
  *Not yet implemented* #3 carries it.

- **`known_members` and `current_members` are two sets on purpose.** The first is the *authorisation*
  predicate and must stay monotone, because disagreeing costs a dropped operation and permanent
  divergence. The second is the *enumeration and connection-policy* predicate and is allowed to be
  order-sensitive, because disagreeing costs a refused connection the next merge repairs. Collapsing them
  has no safe direction.

- **`WorkspaceState::found` records the founder as the first admin; `joined` must not**, or Loro
  converges on a workspace with an administrator nobody appointed.

- **A joiner's namespace generation comes from the invite, and it is not cosmetic.** `joined` takes it
  from `Invite.epoch`. Seeded at `NamespaceEpoch::INITIAL` instead, a member admitted at generation 3
  will adopt an announcement of generation 1 — peers that are themselves behind re-announce on the
  ordinary `ResyncNamespace` schedule, under the *current* group key, so the joiner can decrypt it — and
  move onto a replica the group abandoned before it arrived. It recovers at the next rotation, so the
  failure is a silent stall rather than an error. That field has no other consumer.

- **The invite's nonce is claimed *after* every other check, and the order is the point.**
  `Workspace::join` runs `Invite::verify` first and `Node::claim_invite` last. Claiming first would let a
  garbled, expired or misaddressed copy of a ticket burn the nonce of the one that would have worked — a
  denial of service anybody who can hand the invitee a file can mount. The ledger lives on `Node` and not
  on `Workspace` because redeeming a ticket is what *creates* a workspace: there is nothing else to ask
  at the moment of the check. It is written through to the store on a persistent node and held in memory
  only on `Node::spawn`. **A stolen invite buys visibility, not membership and not plaintext** — signing
  binds who may redeem it, not who may read it, and what bounds a thief is the roster and namespace
  rotation.

### Persistence

- **The snapshot is the whole read capability at rest** — signing key, leaf secret, `owner_sks`, every
  cached PCS key, the blinding secret and the plaintext-equivalent documents. It is written at
  `0600` and not otherwise encrypted, deliberately: `Identity::to_bytes` already made the application
  responsible for an equivalent secret, so encrypting the snapshot while the identity beside it sits in
  the clear would move the boundary without raising it (README trade-off 18, *A snapshot is the whole read capability*). Encryption-at-rest stays
  out of the core, which does no I/O.

- **`parked` and `pending_chunks` are deliberately not persisted.** Parked operations return on the next
  `ControlMsg::Log` exchange and parked chunks on the next resync; eviction counters reset.

- **A snapshot is written before the write it covers is acknowledged.** `Workspace::drive` awaits
  `persist` before returning `Ok`, and the simulator's `apply_client_op` does the same. `persist` is
  called at *batch boundaries* — drive, control message, ingest pass, republish, assemble — and never
  from `apply_effects`, which would make it O(documents) per arriving chunk. It must not be gated on the
  effect batch being non-empty: `on_certs_arrived` absorbs certificates and can return no effects.

- **`Workspace::open` seeds bootstrap peers from its own derived roster.** A joiner is dialled into the
  group by its inviter; a restart has no inviter, and `Gossip::subscribe` with an empty peer list forms
  an overlay of one that nothing would ever reconnect. The manifest records every device's endpoint, so
  `open` `sync_with`s each. `a_restarted_joiners_later_writes_are_still_accepted` is what caught this.

- **The `iroh-docs` author is derived, not minted.** `Workspace::assemble` builds it from
  `WorkspaceSecret::author_seed(member_id)` and calls `author_import`. A random author per spawn would
  present a new identity after every restart, every peer's `author_may_write` would reject its entries,
  and it would stay mute until an admin granted a role to an identity nobody had seen.

---

## Testing

**We specify behaviour as property tests over simulated user stories, not unit tests over data
structures.** A phase whose behaviour cannot be stated as a property over
[docs/USER_STORIES.md](USER_STORIES.md) is a phase whose requirements are not yet understood.

The oracle is **convergence**, not linearizability: (1) every node's `read(doc)` is byte-identical;
(2) no loss, no fabrication — the multiset of acknowledged fragments equals the multiset in the
converged text. Asserting an exact string would assert an implementation detail of Loro's ordering.

`propsim` is a Jepsen-style harness. What it offers and what this project does with it:

| Capability | API | Status |
|---|---|---|
| Typed client operations and generated workloads | `WsOp`, `crud_workload`, `append_only_workload`, `ClientCodec`, `WorkspaceSpec` | in use |
| Swarm faults | `Faults::swarm().partitions().latency_ms(..).reorder()` | in use, with `Mode::Liveness` set **explicitly** — see below |
| Scripted faults at a chosen instant | `Faults::scripted().at(t).partition(..) / .heal_all() / .crash(n) / .restart(n)` | in use in `an_offline_node_catches_up`, for both the partition and the crash/restart variants |
| Completed op spans | `Ctx::complete_op` | in use ([sim/lib.rs](../crates/iroh-beekem-sim/src/lib.rs), `flush_deferred_ops`) — but **only under a `WORKLOAD` scenario**. A plan built without `.workload()` and `.client()` issues no client op and so records no history at all, which is every plan but the two in `generated_crud_workloads` |
| Recorded history | `World::history()` | in use in `generated_crud_workloads`: `no_node_ever_holds_content_nobody_wrote` and `every_acknowledged_write_reaches_every_node` |
| Reference model | `SequentialModel` | **deliberately unused.** A CRDT workspace is not linearizable — concurrent writes commute rather than serialising — so a linearizability oracle reports anomalies for correct behaviour. The reasoning is in the code beside `WorkspaceSpec`. |

**Fault plans must set `Mode::Liveness` explicitly.** `Faults::swarm()` defaults to `Mode::Safety`,
which injures uniformly and never heals a partition — under which no `eventually_within` property is
sound, because a permanently severed node cannot converge. Such a property then passes or fails
according to whether the seed happened to enable partitions at all, which looks like flakiness and is
really an unsound scenario.

**The simulator must model the control plane's repair, not just the data plane's.** A lost
`ControlMsg::Op` is unrecoverable — a peer that misses the operation establishing a PCS key can never
derive it, and re-announcing content re-encrypts under that same key. `ControlMsg::Log` is the
repair, and the simulator no longer *models* it: `Msg::Control` wraps the core's own type, and both
backends dispatch it through `WorkspaceState::on_control`. Without the log exchange the harness is
strictly more fragile than production and every resulting failure is an artefact.

**A restart in propsim is a freeze, not amnesia.** `dispatch_start` calls `on_start` on the *same* node
object; there is no `on_crash` hook and no per-node storage seam, so `WorkspaceNode::reboot` authors the
wipe itself. Two properties stop the harness degenerating into a re-invitation test:
`no_node_ever_initialises_the_workspace_more_than_once` and the founder-crash variant. It has to be the
**founder** that crashes — `on_welcome` already refuses a node that has state, so a crashed *member*
cannot catch the bug, while `on_start`'s founding branch is unconditional. Note also that
`admin_count() == 1` does not detect a forked founder: a re-founded node is the sole admin of its own
new tree and so reports exactly one administrator, as does everybody else. The fork is invisible to any
property that asks each node about itself rather than comparing them.

**Keep and grow:** panic-freedom on hostile input
([wire.rs](../crates/iroh-beekem-core/src/wire.rs)); the
real-QUIC suite in [two_node.rs](../crates/iroh-beekem/tests/two_node.rs), which proves **the transport
wiring is connected** and should *not* grow protocol assertions; focused crypto regressions in
[beekem_loop.rs](../crates/iroh-beekem-core/tests/beekem_loop.rs).

**Stop writing:** tests asserting over internal data structures. Convergence is a system property under
an adversarial network, and the simulator states it far more strongly than
`concurrent_edits_on_two_replicas_converge` in
[manifest.rs](../crates/iroh-beekem-core/src/manifest.rs) does.

### What the suite covers today

One or more scenarios per user story, all in
[sim/lib.rs](../crates/iroh-beekem-sim/src/lib.rs) with their properties in
[properties.rs](../crates/iroh-beekem-sim/tests/properties.rs):

| Story | Scenarios | Property module |
|---|---|---|
| 1 — invitation | `Honest`, `Onboarding` | top level (`every_node_eventually_joins_the_group`, …), `devices_onboard_without_losing_content` |
| 2 — reconciliation | `Honest` + `Faults::scripted` | `an_offline_node_catches_up` — ten properties across the partition and the crash/restart variants |
| 3 — removal | `Eviction`, `Churn`, `Insider`, `Revenant`, `Departure`, `Quorum`, `DeviceChurn` | `a_removed_member_stops_seeing`, `concurrent_rotation_and_revocation`, `an_insider_cannot_exceed_its_role`, `a_removed_member_is_evicted_again`, `a_member_leaves_of_its_own_accord`, `an_action_needs_a_quorum`, `removing_one_device_leaves_the_user_working` |
| 4 — outsiders | `Forging`, `Outsider`, `StolenInvite` | `a_forging_peer_is_rejected`, `an_outsider_observes_nothing`, `a_stolen_invite_buys_only_visibility` |
| 4 — large assets | `Assets`, `AssetChurn`, `AssetAfterRemoval` | `an_asset_reaches_every_member` |
| workloads | `Crud`, `CrudChurn` | `generated_crud_workloads` — the generated stream includes `WsOp::Revert`, so every convergence property covers reverting too; and the history-based loss and fabrication properties live here, because this is the only module with a workload |

Story 2 has no scenario type of its own by design: "offline" is `Honest` under a scripted fault, in two
variants — **disconnected** (`partition` then `heal_all`) and **shut down** (`crash` then `restart`) —
and a distinct type would carry no state the fault plan does not already supply.

**Story 1 gained a scenario, and the reason is the shape of `Honest`.** There every node asks to join
at t=0, so the group is complete before the first edit and no joiner ever meets content it cannot
decrypt — the easy half of onboarding. `Onboarding` staggers admission so a joiner arrives *after*
content exists, which is what the republish on admission and the demand-driven repair are for, and
gives one person two devices so "all of one user's devices converge" has a referent at all. Anything
else in this file is one device per person.

Asserted in *every* scenario:

| Property | Kind |
|---|---|
| No chunk / control op stays parked forever | `eventually_within` |
| A healthy run never evicts anything | `always` |
| Runs are reproducible for a fixed seed | — |
| A node's own acknowledged writes are always in its own view | `always` |
| Every node's `users()`/`devices()` and `index` converge after quiescence | `eventually_within` |
| `no_role_or_binding_ever_moves_without_a_valid_chain` | `always` |

**An entry from an author with no writing role is refused, and that is asserted in
`a_forging_peer_is_rejected` rather than everywhere.** This row previously claimed the check held in
every scenario; it held in none, because `on_entry` performed no author check at all — the predicate
existed only in the facade's `ingest_all`. It is now modelled where production has it, and stated
where an author with no role actually occurs.

The last is cross-cutting deliberately, `Honest` included: an insider property asserted only in an
insider scenario tells you nothing about whether the honest path quietly accepts uncertified state.

The two properties that stop an authorization fix from degenerating into "reject more aggressively" are
`honest_nodes_still_converge_while_under_attack` and `the_insiders_own_view_stays_self_consistent` — a
check that diverges the group or spins a rejected insider's repair path is not a fix, and both failure
modes are reachable.

**Read the scope of Story 4 literally.** Every adversary there sits *outside* the group; no property in
it constrains a member. The insider is Story 3's problem. When adding an adversarial property, decide
first which family it belongs to — putting an insider property in Story 4 is how it ends up written
against the wrong scenario and passing vacuously.

**Every module needs a `sometimes` guard, and the guard has to discriminate.** A property about an
adversary being refused, a victim seeing nothing or a write surviving is satisfied by a run in which
the thing never happened — and under a lossy transport with bounded budgets, that is a reachable run
rather than a hypothetical one. The test of a guard is mechanical and worth doing: **switch off the
scenario constant it depends on and confirm the guard fails.** Two of the guards written for phase 11
did not survive that check first time. One asserted a symptom (`unreadable_chunks` grew) that a lossy
network produces on its own, and passed with the feature disabled; it was replaced by one stating the
scenario's premise. Prefer the premise — it is what the plan is *for*, and a symptom the harness can
manufacture by other means proves nothing.

Three modules had no guard at all until phase 11, and the outsider's is the one worth understanding.
"An unadmitted node observes nothing" is satisfied by a run in which the network never offered it
anything — and because admission is checked *before* a message is recorded, every counter on that node
reads zero in that case too, exactly as it does when the roster is working. No existing observable
could tell the two apart, which is why `refused_messages` exists: a count of what was *turned away* is
the only evidence that there was anything to turn away. `an_insider_cannot_exceed_its_role` and
`concurrent_rotation_and_revocation` gained the same treatment through `overreaches_made` and a shrunk
`current_member_count`.

---

## Where the suite stands

### Versioning, and where it is tested

Versioning adds no scenario of its own, deliberately. A revert is an ordinary edit, so the question it
raises — does the group still converge — is the question every existing plan already asks; the way to
cover it is to put reverts into the generated workload rather than to build a plan that only reverts.
`WsOp::Revert` names a version by counting back from the newest, because a generated workload cannot
know a `VersionId`: those are minted by the very edits it is producing.

The rest sits where it can be stated exactly:

| Claim | Where |
|---|---|
| Every edit is a version; reading at one gives the text as it stood | `history_is_readable_and_revertible` in [workspace_state.rs](../crates/iroh-beekem-core/tests/workspace_state.rs) |
| Reverting restores the text *and lengthens* the history | same, plus a proptest over arbitrary edit sequences |
| A revert converges with a concurrent edit | same, and every workload plan in the simulator |
| A version names the member that made it, and the instant the caller stated | same |
| Restoring a checkpoint puts back what it named and leaves the rest | `checkpoints_name_a_state_of_the_workspace` |
| Two members tagging one name both keep their record | same |
| A second asset version does not replace the first; delete withdraws every key space | `assets_keep_their_versions` |
| Two versions attached in the same second are still ordered | same |
| It all works over real QUIC, including exporting a superseded version | `versions_travel_over_the_wire` in [two_node.rs](../crates/iroh-beekem/tests/two_node.rs) |
| A peer that missed the base of a delta still catches up | same — the regression for the `seen_entries` gap |

### The gaps that were in the property suite, and what closing them found

All four are closed, along with the asset-confidentiality case and the device-removal counterpart.
Three of them could not be written as originally stated, and *why* is worth more than the properties
themselves — each was mis-stated in a way that would have produced a passing test asserting nothing.

1. **`Onboarding`.** Closed by `Onboarding` and `devices_onboard_without_losing_content`. Multi-device
   needed real machinery: the simulator was one device per person by construction, so `Event::AddDevice`
   appeared nowhere. `Msg::Hello` now carries `as_device_of`, and the **primary** device answers it
   rather than the founder — `may_bind_device_to` admits both, and the non-admin disjunct ("enrolling
   your own laptop is not an administrative act") is the one nothing else exercises.

   The anti-vacuity guard is worth copying. The obvious one — some node reached a non-zero
   `unreadable_chunks` — passes with the stagger *switched off*, because a lossy partitioned transport
   strands chunks by itself. It is a true statement that proves nothing about the plan. The guard that
   works states the premise: the founder had written while a device was still outside the group, which
   is false without the stagger and true by construction with it.
2. **History-based loss.** Closed by `no_node_ever_holds_content_nobody_wrote` and
   `every_acknowledged_write_reaches_every_node` — in `generated_crud_workloads`, **not** in
   `an_offline_node_catches_up` as this document used to say. That module builds its plans with
   `scripted_plan`, which supplies neither `.workload()` nor `.client()`, so no client op is ever
   issued and `World::history()` is empty: the property would have passed while reading nothing.

   Loss also needs a monotone workload to be *definable*. Under `crud_workload` a `write`, `remove` or
   `revert` may legitimately delete an acknowledged append, so "every acknowledged write survives" is
   false — and every weakening that becomes true is vacuous, since with three documents and a
   destructive op drawn one time in three, every document sees one. Hence `append_only_workload`, and
   hence the loss bound stated there while the fabrication bound stays on the full workload, where it
   is total.
3. **The removed victim's manifest.** Closed by `the_victim_never_sees_a_file_created_after_its_removal`
   — but the "no role changes" half of the original wording was wrong twice over. Roles left the
   manifest in phase 5, so it was never a manifest claim; and the victim **does** still learn of a
   promotion made after its removal. A certificate travels on the control plane, which has no namespace
   to rotate, and what should stop the victim receiving one is eviction — which is an availability
   boundary, not a confidentiality one. The victim keeps its inviter on the bootstrap exception and
   certificate admission is monotone by design.

   `a_removed_device_still_learns_of_later_membership_changes` records that inverted, exactly as this
   module's visibility properties once were, so the line cannot move without a test noticing. Closing it
   means expiring the bootstrap exception — which exists because a joiner must accept its inviter
   *before* it has state to derive a roster from.
4. **The forger's index entries.** Closed by `no_honest_node_ever_accepts_a_forged_entry`, and this one
   needed two fixes. The simulator applied **no author check at all** — `author_may_write` existed only
   in the facade — so the harness was strictly weaker than production on the one plane an attacker
   reaches without holding a key. And the forger had no data plane: `forge()` broadcast only a
   control-plane operation, while `FORGE` applies to legitimate members whose entries *should* be
   indexed.

   Phase 12 finished it, because the first fix had been made by *writing the check again* rather than
   by calling the one that existed — and the copy was shorter. `WorkspaceState::author_may_write` has
   three links: the self-attested author claim in the manifest, the binding from that device to a
   user, and the grant from that user to a role. The simulator asked the closure directly and skipped
   the first, which it had to, because it published no author claim. It now publishes one beside its
   endpoint, calls the core's predicate, exempts the manifest from it — the predicate resolves an
   author *through* the manifest, so checking the manifest with it is a deadlock — and replays
   entries refused while a claim or a grant was still in flight, which production gets free by
   re-reading the index every pass. This is the entry that motivates the whole of phase 12: a check
   living in one backend is a check the properties do not bind, whichever backend it lives in.

   "Never enters the index" is also the wrong claim, and this document said it. A forging node is a
   member: it holds the namespace write capability, so its entry really does reconcile into every
   peer's replica whatever author id it writes under, and nothing can stop it *arriving*. What stops it
   counting is the receiver's author check. The forgery re-announces ciphertext the group can genuinely
   decrypt, so that check is the only thing refusing it — sealing under a rogue key would have
   decryption refuse it anyway and the property could not tell a working check from a missing one.

Also closed: the asset-confidentiality case (`AssetAfterRemoval`, attaching after the revocation rather
than before) and the device-removal counterpart (`DeviceChurn`, the simulator counterpart of the core's
`removing_one_device_leaves_the_users_other_devices_alone`).

Closing the asset case turned up a latent defect in `holds_asset_key`, which is the shape to watch for:
it asked under `asset_key_key(ASSET)` while the key is sealed under `ASSET_V1`, so it returned `false`
for every node at every instant. Harmless for as long as no property called it — and a confidentiality
property built on it would have passed while asserting nothing. **An accessor no property calls is not
covered by anything.**

### What remains open

* **Abandoned namespaces are never dropped**, so blob collection does not reach anything indexed only
  in one. Closing it needs a policy for when an old replica is safe to drop — peers may still be
  catching up on it — and until then a workspace's floor is set by how often it rotates.
* **A removed member still sees membership changes.** Recorded above and pinned by
  `a_removed_device_still_learns_of_later_membership_changes`. It is the bootstrap exception, not a
  missing check, and README *Current trade-offs* already carries eviction as an availability boundary.

* **The real-QUIC suite is wall-clock sensitive, and phase 11 removed three of the reasons it was.**
  Every test node now spawns with `Relay::Disabled` (`test_node` in
  [two_node.rs](../crates/iroh-beekem/tests/two_node.rs)), a restart is handed both addresses rather
  than waiting on address lookup, and the three tests running three endpoints ask for two worker
  threads instead of the current-thread runtime `#[tokio::test]` gives. Measured at cargo's default
  parallelism on eight cores: **21 of 38 timed out before, 0 of 39 after.** What remains is that the
  suite must not run *alongside* the simulator — `make test` runs the three in sequence, and
  `cargo test --workspace` (which does not) should not be used.

### Smaller items

- **Decide the seed budget now that faults are in play.** Consider propsim's `rigorous()` preset
  nightly while keeping `deterministic()` for the fast path. More pressing now than it was: phase 11
  added three scenarios and an extra plan, and the suite's runtime is the constraint on raising
  `SEEDS`.

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
cargo check -p iroh-beekem-core --all-targets   # MSRV 1.90
cargo check -p iroh-beekem --all-targets        # MSRV 1.91

# core purity — must match nothing:
cargo tree -p iroh-beekem-core -e normal --prefix none \
  | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'

# Workspace mode, not two per-crate runs: `iroh-beekem` depends on `iroh-beekem-core`
# by version as well as path, so a per-crate dry run cannot resolve it against the
# registry until core is actually released.
cargo publish --dry-run --workspace
```

`make check` runs test, lint, fmt-check and purity. `make coverage` regenerates
[COVERAGE.md](../COVERAGE.md) as a merged report across every test manifest — a per-crate report
understates the core badly, since most of its coverage comes from propsim driving it. Coverage is
advisory (`make coverage-check` enforces a soft floor and is not in `make check`); treat a drop on files
you edited as a defect to fix before declaring done.

**Several real-QUIC tests exist because the simulator models effects rather than mechanisms**, and
none can move into it:

1. `a_node_that_was_never_admitted_is_refused_on_every_alpn` — proves `RosterGuard` is wired to iroh
   rather than merely modelled.
2. `a_removed_member_is_left_on_the_abandoned_namespace` — proves the modelled epoch capability check
   corresponds to what `iroh-docs` actually enforces.
3. `publishing_creates_no_permanent_tag` and `superseded_blobs_are_reclaimed`
   ([blob_gc.rs](../crates/iroh-beekem/tests/blob_gc.rs)) — the simulator has no blob store, so
   whether collection is wired to `iroh-blobs` at all can only be shown here.
4. `an_asset_round_trips_between_two_endpoints` and
   `a_rotation_reindexes_an_asset_instead_of_re_encrypting_it`
   ([assets.rs](../crates/iroh-beekem/tests/assets.rs)) — the download policy and the on-demand fetch
   are `iroh-docs`/`iroh-blobs` mechanisms, and the blob count after a rotation is the only direct
   evidence that re-indexing happened rather than re-encryption.
5. `a_public_resync_re_announces_the_certificates` — the simulator drives anti-entropy through its own
   `republish`, so the *facade's* public entry point is a path only this can reach. It asserts the
   composition, not the recovery: making a peer genuinely miss a gossip message needs fault injection,
   which two real endpoints do not have, and the lossy case is `an_action_needs_a_quorum` in the
   property suite.

The example at [two_node.rs](../crates/iroh-beekem/examples/two_node.rs) is the readable proof the CRUD
API is usable; keep it that way as the API grows.
