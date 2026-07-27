# iroh-beekem

Group-confidential, local-first collaborative workspaces: groups of people editing a shared set of
documents, every edit versioned, signed and concurrent-safe, with no trusted server anywhere.

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

### Two DAGs must both be satisfied

An arriving chunk applies only when the CGKA operation graph has caught up far enough to reach its PCS
key **and** Loro has the CRDT operations it depends on. Neither ordering is guaranteed by the network,
so chunks failing either test are parked and retried. This pairing is the most likely source of silent
data loss in the system, and it is what the property tests are aimed at.

## Verification

```bash
cargo test -p iroh-beekem-core     # unit + the beekem handshake spike + state-machine tests
cargo test -p iroh-beekem-sim      # propsim: convergence, join, no permanent parking, determinism
cargo test -p iroh-beekem          # two real endpoints over real QUIC, including revocation
cargo clippy --workspace --all-targets -- -D warnings

# The core's purity is enforced mechanically; this must match nothing:
cargo tree -p iroh-beekem-core -e normal --prefix none \
  | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'
```

Note: `cargo clippy --all-features` pulls in a substantially larger dependency set (`arbitrary`,
`objc2`, …) and needs several GB of free disk.

## Known limitations

These are real and deliberate, not oversights:

1. **`iroh-docs` write capability is all-or-nothing.** Every writer holds the same `NamespaceSecret`.
   A revoked member keeps it and can still push entries; they cannot *read* anything written after
   their removal, but shutting off their writes needs a namespace rotation. Check the entry author
   against the manifest roles before accepting an entry.
2. **A new member cannot read content written before they joined.** They reconstruct the group from
   the operation log but not the historical PCS keys. This is forward secrecy working as intended;
   `Workspace` re-publishes current state when a peer joins the overlay so they can catch up.
3. **Timestamp quantization is not achievable.** `Doc::set_bytes`/`set_hash` do not accept a timestamp;
   `iroh-docs` sets it internally. Modification times leak to any syncing peer.
4. **Blinding hides names, not traffic.** Entry count, sizes, write frequency and author activity all
   remain visible during reconciliation.
5. **Forward secrecy is bounded by retention.** Decryption keys are recovered from the CGKA operation
   graph, so pruning old operations to gain forward secrecy also destroys the ability to read old
   content. Retention is a policy knob, not a free win.
6. **M-of-N admin actions are not implemented.** The manifest has the role schema to support them;
   the enforcement is not written.
7. the networked facade covers a single document per workspace and uses in-memory stores.



