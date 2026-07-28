# iroh-beekem

Group-confidential, local-first collaborative workspaces: groups of people editing a shared set of
documents, every edit versioned, signed and concurrent-safe, with no trusted server anywhere.

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
   so a revoked member keeps it and can still push entries into the replica. They cannot *read*
   anything written after their removal — that is the CGKA — and peers now refuse their entries
   (see `Manifest::author_may_write`), but genuinely shutting off their writes needs a namespace
   rotation, which is not automatic.
2. **A new member cannot read content written before they joined.** They reconstruct the group from
   the operation log but not the historical PCS keys. This is forward secrecy working as intended;
   `Workspace` re-publishes current state when a peer joins the overlay so they can catch up.
3. **Timestamp quantization is not achievable with `iroh-docs` as the index.** `Doc::set_bytes`/`set_hash`
   do not accept a timestamp; `iroh-docs` sets it internally. Modification times leak to any syncing
   peer. This is a property of the index we chose, not of the problem.
4. **Blinding hides names, not traffic.** Entry count, sizes, write frequency and author activity all
   remain visible during reconciliation.
5. **Forward secrecy is bounded by retention.** Decryption keys are recovered from the CGKA operation
   graph, so pruning old operations to gain forward secrecy also destroys the ability to read old
   content. Retention is a policy knob, not a free win.
6. **The workspace blinding secret does not rotate.** A revoked member can still recognise which
   blinded key belongs to a document UUID they already knew. Rotating it under the current scheme —
   one secret keying every entry — would force every peer to rewrite every entry, which is why it is
   not done. They learn nothing about documents created after their removal, and can read no content
   either way.
7. **Roles are advisory against a cryptographically capable member.** Anyone holding a leaf can
   decrypt, whatever the manifest says. Roles constrain what a well-behaved peer accepts, not what a
   malicious one can read. Genuine read revocation is a CGKA removal.
8. **Parked queues evict under pressure.** Out-of-order operations and undecryptable chunks are
   bounded (`MAX_PARKED_OPS`, `MAX_PENDING_CHUNK_BYTES`) and evict oldest-first, because an unbounded
   queue is a remote memory-exhaustion vector. Evicted operations return with the next neighbour log
   exchange; evicted chunks wait for a resync. A property test asserts honest runs never evict.

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
4. **Removal revokes reading, not watching.** A removed device keeps the docs write capability and
   stays subscribed to the control topic, so it goes on observing membership churn *and* the
   replicated index — entry existence, size, author and timing — for as long as it cares to look.
   It reads no content and no manifest written afterwards, but "removed" currently means *cannot
   read*, not *cannot see*. Closing it needs namespace rotation plus connection-level admission
   control. The `a_removed_member_still_watches` properties in `iroh-beekem-sim` record exactly
   where the line sits today, so it cannot move without a test noticing.
5. **Invites are replayable.** No expiry, no nonce, no binding to the invitee — and the ticket
   carries the raw workspace secret, so it must travel over an authenticated, confidential channel.
   It does *not* grant read access: joining also needs the leaf secret, which never leaves the
   invitee's device.
6. **No admission control on either transport.** Anyone who learns the gossip topic (the founder's
   public key) or the docs namespace can participate. There is no allowlist, so confidentiality
   against an outsider rests on them not knowing two 32-byte identifiers rather than on a key.



