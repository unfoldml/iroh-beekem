# iroh-beekem

Group-confidential, local-first collaborative workspaces: groups of people editing a shared set of
documents, every edit versioned, signed and concurrent-safe, without needing a trusted server.

The goals this is built against are in [docs/USER_STORIES.md](docs/USER_STORIES.md). The project is
early; what follows describes the current implementation, not a settled specification.

- **[iroh](https://crates.io/crates/iroh)** — P2P QUIC transport, NAT hole punching, peer identity by public key.
- **[beekem](https://crates.io/crates/beekem)** — decentralized Continuous Group Key Agreement. Forward
  secrecy and post-compromise security over a dynamic group and, unlike MLS/TreeKEM, merges *concurrent*
  membership and key-rotation operations with no central sequencer.
- **[iroh-docs](https://crates.io/crates/iroh-docs) / [iroh-blobs](https://crates.io/crates/iroh-blobs) /
  [iroh-gossip](https://crates.io/crates/iroh-gossip)** — replicated index, content-addressed payloads, control-plane pub/sub.
- **[loro](https://crates.io/crates/loro)** — CRDT for document contents and the workspace manifest.

## Crates

| Crate | Role |
|---|---|
| `iroh-beekem` | The public crate: iroh wiring and the async `Workspace` facade |
| `iroh-beekem-core` | The pure engine — **no tokio, no iroh, no clock**. All crypto and state lives here |
| `iroh-beekem-sim` | Deterministic simulation and property tests, via [propsim](https://github.com/unfoldml/propsim) |

`iroh-beekem-core` returns every effect as data instead of performing it, which is what lets the entire protocol run on a single-threaded simulator with virtual
time and a seeded RNG. `propsim`'s `Node::on_msg` is a *synchronous* callback — a state machine that needed an async runtime could not be plugged in at all.

## Usage

```rust,no_run
use iroh_beekem::{Identity, Node, Workspace};
use iroh_beekem_core::{Role, WorkspaceInfo};

// A device identity, not a person's. Persist these bytes: they are this
// device's leaf, and a new one is a new member as far as the group is concerned.
let me = Identity::generate(&mut rand::rngs::OsRng);

let ws = Workspace::create(
    Node::spawn().await?,
    &me,
    WorkspaceInfo { name: "Q3 planning".into(), description: String::new() },
    &mut rand::rngs::OsRng,
).await?;

// Files are addressed by UUID; the logical path lives only in the encrypted
// manifest, so renaming never moves a stored chunk.
let notes = ws.create_file("/notes.md", "text/markdown").await?;
ws.write(notes, "# Agenda").await?;
ws.append(notes, "\n1. ship 0.1").await?;

// Admitting someone returns the invite they need. The role is chosen here
// because it decides what capability the ticket carries.
let invite = ws.add_user(their_member_id, their_share_key, Role::Editor, "Bob").await?;

for user in ws.users().await {
    println!("{:?}: {:?} on {} device(s)", user.display_name, user.role, user.devices.len());
}
```

A person may hold several devices, each with its own leaf and its own
`Identity`; roles attach to the person, so a laptop and a phone always agree.
Enrol one with `add_device`, revoke one with `remove_device`, and remove someone
entirely with `remove_user`. See [`examples/two_node.rs`](crates/iroh-beekem/examples/two_node.rs)
for a complete session over real QUIC.

## Design

```
       CONTROL PLANE (iroh-gossip)              DATA PLANE (iroh-docs + iroh-blobs)
   Signed<CgkaOperation> broadcast on a       Blinded 32-byte keys → BLAKE3 hashes of
   topic derived from the CGKA tree id;       serialized EncryptedContent chunks;
   membership, key rotation, log repair       RBSR index sync + verified blob streaming
                        \                    /
                         iroh Endpoint (QUIC, hole punching, relays)
```

### Keys are per-chunk and causal, not per-epoch

Key identity is `Digest<PcsKey>` plus the digest of the PCS update operation, and each content chunk gets its own `ApplicationSecret` bound to its content ref and
predecessor refs. We do not define an envelope: beekem's `EncryptedContent` already carries the nonce,
both digests, and the refs, and `Cgka::decryption_key_for` closes the loop on the receiving side.

### Blinded storage keys

`iroh-docs` reconciles entries *by key*, and keys cross the wire in the clear. Storage keys are
therefore `BLAKE3-MAC(workspace_secret, document_uuid)` — fixed 32 bytes, so nothing leaks about path
depth or filename length, and derived from a stable UUID rather than the path, so renaming a document
touches only the encrypted manifest and never invalidates a stored chunk.

### The control plane is authenticated here, not by beekem

beekem verifies nothing. `Cgka::merge_concurrent_operation` checks the operation
hash and the causal predecessors; `Cgka::apply_operation` mutates the tree without
ever looking at the issuer. Since the gossip topic is derived from the tree id, which
every past invitee knows, an unchecked `merge` would let anyone broadcast a self-issued
`Add` and read everything written afterwards.

`CgkaController::merge` therefore applies two checks beekem does not, and neither
substitutes for the other:

* **Signature** — the operation must verify against its own embedded issuer key.
  Catches a payload spliced onto an observed signature.
* **Membership** — that issuer must be someone an accepted `Add` introduced.
  Catches the freshly minted keypair, which can sign its own messages perfectly well.

The membership set is deliberately monotone: a `Remove` does not retract it. Two peers
seeing a removal and a concurrent operation by the removed member in opposite orders
would otherwise disagree about admissibility and diverge. A removed member's operations
cannot reach the root key anyway, so beekem's tree semantics already neutralise them.

A *second*, non-monotone set (`current_members`) tracks who is a member **now**. The two
cannot be one set, and the difference is which failure you are willing to pay for.
`known_members` answers "may this operation be merged", where disagreeing costs a dropped
operation and permanent divergence, so it must be order-independent. `current_members`
answers "may this peer connect" and "who do I list", where disagreeing costs a refused
connection that the next merge repairs. Merging them in either direction breaks something:
made monotone, a revoked device stays admitted forever; made non-monotone, `merge` starts
rejecting operations on a delivery-order-dependent predicate.

### Admission control is an authenticated allowlist

Neither `iroh-gossip` nor `iroh-docs` applies admission control of its own, so before this
existed, confidentiality against an outsider rested on them not knowing two 32-byte
identifiers — the gossip topic and the docs namespace — rather than on holding a key.

Every ALPN is now wrapped in a `RosterGuard` (`roster.rs`), which refuses inbound
connections from endpoints that are not currently members. An `EndpointId` *is* the peer's
public key and the QUIC/TLS handshake proves possession of the secret, so this is an
authenticated allowlist rather than a claim a peer can assert its way past. All three ALPNs
are wrapped: guarding only gossip would leave the docs index — every document's existence,
size, author and timing — readable by anyone who learned the namespace.

The roster is **derived, never authored**: it is the set of `endpoint_id` values from the
manifest's `devices` container whose member is in `current_members`. Both halves converge
on their own, so it needs no distribution channel and inherits the admin gating already on
`AddUser`/`AddDevice`. `WorkspaceState::roster` computes it in the I/O-free core, which is
what makes the rule property-testable without a socket.

Two limits are inherent rather than incidental:

* **Eviction is eventual.** A removed device still reaches peers that have not yet merged
  the removal.
* **It is an availability boundary, not a confidentiality one.** It decides who may attempt
  to sync; what they can *read* is decided by the CGKA, and nothing here retracts data
  already synced.

Bootstrapping is the one exception. A joiner must reach its inviter before it holds the
manifest that would authorise anyone, so `Invite.inviter` is admitted unconditionally and
never pruned — a workspace whose inviter later leaves should not become unjoinable
mid-handshake.

### Removal abandons the namespace

The CGKA revokes *reading*. It cannot revoke *watching*, because the `iroh-docs`
write capability is all-or-nothing: every writer holds the same `NamespaceSecret`, so
there is no per-member key to withdraw. A removed device therefore went on syncing the
index — entry existence, size, author and timing for every document — and on receiving
every control-plane broadcast, for as long as it cared to look.

Removal now **rotates the namespace**, and the order is the security property:

1. **Broadcast the CGKA `Remove` first.** This takes the leaf out of the tree.
2. **Mint a fresh namespace** and encrypt its capability under the group key — which,
   after step 1, is a key the removed device can no longer derive.
3. **Announce it** on the control plane, since the data plane is the thing being replaced.
4. **Re-publish everything** into it, and abandon the old one.

Reversed, the removed device could still read the announcement and follow the group into
the namespace the rotation existed to keep it out of. `NamespaceEpoch` orders on
`(epoch, digest)` rather than on a bare counter: two admins removing different members
concurrently both mint *n+1*, and without a total order computable from the values the
group would split across two replicas with each half convinced it was current. The digest
is recomputed from the decrypted capability, so a peer cannot win a tie by claiming a
large one.

A rotation is announced **once**, so unlike a document it has nothing behind it to carry
a lost copy. Two mechanisms close that: `Event::ResyncNamespace` re-announces under the
current epoch on the ordinary anti-entropy schedule, and `RepairTarget::Namespace` lets a
member that cannot decrypt any of them ask for one keyed under a fresh epoch. Without
them a single lost announcement strands a member on an abandoned replica — removed in
effect, without anyone having removed them.

### Two DAGs must both be satisfied

An arriving chunk applies only when the CGKA operation graph has caught up far enough to reach its PCS
key **and** Loro has the CRDT operations it depends on. Neither ordering is guaranteed by the network,
so chunks failing either test are parked and retried. This pairing is the most likely source of silent
data loss in the system, and it is what the property tests are aimed at.

## Verification

```bash
cargo test -p iroh-beekem-core     # unit + handshake spike + state machine + forgery rejection
cargo test -p iroh-beekem-sim      # propsim: convergence, concurrent rotation/revocation, forging peer
cargo test -p iroh-beekem          # two real endpoints over real QUIC: revocation, roles, rotation
cargo clippy --workspace --all-targets -- -D warnings

# The core's purity is enforced mechanically; this must match nothing:
cargo tree -p iroh-beekem-core -e normal --prefix none \
  | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'
```

Note: `cargo clippy --all-features` pulls in a substantially larger dependency set (`arbitrary`,
`objc2`, …) and needs several GB of free disk.

## Current trade-offs

These follow from the choices the implementation makes today, and each one buys something. They are
not work left undone — but nor are they permanent: a user story that needs a different answer is
reason enough to revisit the choice underneath.

1. **`iroh-docs` write capability is all-or-nothing.** Every writer holds the same `NamespaceSecret`,
   so a revoked member keeps the one they were given. It is made worthless rather than withdrawn:
   removal rotates to a namespace whose capability they never receive, so the replica they can
   still write to is one nobody reconciles with. Between the removal and a peer merging it, that
   peer still accepts their entries — eviction is eventual on both planes.
2. **A rotation costs a full re-publish.** Every document is re-encrypted and re-announced into
   the new namespace, and every member re-imports. This is expensive by construction and is the
   right place to spend it: removal is rare, and the alternative is a removed device that keeps
   watching. Superseded blobs in the abandoned namespace are not reclaimed until blob GC exists.
3. **Viewers hold a write capability after a rotation, though not after an invite.** The
   announcement carries both tickets and each node takes the one its role allows, because beekem
   encrypts to the whole tree and cannot hand writers one secret and viewers another. A viewer who
   ignores their role gains write capability on the replica; `Manifest::author_may_write` still
   rejects their entries, which is the same guarantee trade-off 9 describes. `build_invite` does
   better — a viewer is handed only a read ticket — and closing the gap needs per-role key material
   the CGKA does not provide.
4. **A new member cannot read content written before they joined — until somebody re-encrypts it.**
   They reconstruct the group from the operation log but not the historical PCS keys, which is
   forward secrecy working as intended. What makes the workspace usable anyway is re-encryption:
   `Workspace` re-publishes current state when a peer joins the overlay, and a peer that is *still*
   stuck says so with `ControlMsg::Repair`, which a member that can read the content answers by
   minting a fresh epoch and publishing under it. Anti-entropy alone cannot do this — it re-encrypts
   under the same epoch the stuck peer already failed on — so the demand-driven path is load-bearing
   rather than an optimisation. The cost is one CGKA operation per genuinely stuck `(target, epoch)`,
   rate-limited per peer; content that was superseded before the join is never recovered, only
   current state is.
5. **Timestamp quantization is not achievable with `iroh-docs` as the index.** `Doc::set_bytes`/`set_hash`
   do not accept a timestamp; `iroh-docs` sets it internally. Modification times leak to any syncing
   peer. This is a property of the index we chose, not of the problem.
6. **Blinding hides names, not traffic.** Entry count, sizes, write frequency and author activity all
   remain visible during reconciliation.
7. **Forward secrecy is bounded by retention.** Decryption keys are recovered from the CGKA operation
   graph, so pruning old operations to gain forward secrecy also destroys the ability to read old
   content. Retention is a policy knob, not a free win.
8. **The workspace blinding secret does not rotate.** A revoked member can still recognise which
   blinded key belongs to a document UUID they already knew. Rotating it under the current scheme —
   one secret keying every entry — would force every peer to rewrite every entry, which is why it is
   not done. They learn nothing about documents created after their removal, and can read no content
   either way.
9. **Roles are advisory against a cryptographically capable member.** Anyone holding a leaf can
   decrypt, whatever the manifest says. Roles constrain what a well-behaved peer accepts, not what a
   malicious one can read. Genuine read revocation is a CGKA removal.
10. **Parked queues evict under pressure.** Out-of-order operations and undecryptable chunks are
   bounded (`MAX_PARKED_OPS`, `MAX_PENDING_CHUNK_BYTES`) and evict oldest-first, because an unbounded
   queue is a remote memory-exhaustion vector. Evicted operations return with the next neighbour log
   exchange; evicted chunks wait for a resync. A property test asserts honest runs never evict.
   A chunk that can *never* be decrypted is not parked at all — it is dropped, counted, and answered
   with a repair request, because holding it would occupy the budget for the life of the process
   while every drain retried a decryption that cannot succeed.

## Not yet implemented

These are gaps, not trades. Nothing in the design prevents them.

1. **No persistence.** `MemStore` and `Docs::memory()` only, and neither `CgkaController` nor
   `WorkspaceState` can be serialized — so there is no export/import to build persistence on, and
   nothing survives a restart.
2. **M-of-N admin actions.** The manifest has the role schema; the threshold enforcement is not
   written. Single-admin rules *are* enforced: admin-only membership changes, and a refusal to
   demote or remove a user's last admin device.
3. **Publishing re-ships whole document history.** Every edit and every resync exports all updates,
   re-encrypts them and writes a new blob; superseded blobs are never collected. Cost grows
   quadratically in edits.
4. **Eviction is eventual on every plane.** Removal now revokes reading (the CGKA), connecting
   (the roster) and watching (namespace rotation) — but all three converge asynchronously, so a
   peer that has not yet merged the removal still accepts the removed device's connections and
   entries, and nothing retracts what it already synced. The `a_removed_member_stops_seeing`
   properties in `iroh-beekem-sim` state exactly where the line now sits.

5. **Invites are replayable.** No expiry, no nonce, no binding to the invitee — and the ticket
   carries the raw workspace secret, so it must travel over an authenticated, confidential channel.
   It does *not* grant read access: joining also needs the leaf secret, which never leaves the
   invitee's device.
6. **One roster per node, not per workspace.** The roster lives on `Node` because the guards must
   be installed when the router is built, before any workspace exists. Two workspaces on one node
   would therefore union their rosters, admitting a member of either to both. Fixing it means
   keying the roster by workspace, which belongs with `Workspace::open`/`list` and persistence.
7. **The gossip topic still never rotates.** It is derived from the tree id, which is the founder's
   public key, so every past invitee knows it permanently. The roster is what refuses them; without
   a new tree id — that is, a new workspace — the topic itself cannot change.



