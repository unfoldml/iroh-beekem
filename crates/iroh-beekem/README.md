# iroh-beekem

Group-confidential, local-first collaborative workspaces: groups of people editing a shared set of
documents, every edit versioned, signed and concurrent-safe, with no trusted server anywhere.

- **[iroh](https://crates.io/crates/iroh)** — P2P QUIC transport, NAT hole punching, peer identity by
  public key.
- **[beekem](https://crates.io/crates/beekem)** — decentralized Continuous Group Key Agreement.
  Forward secrecy and post-compromise security over a dynamic group and, unlike MLS/TreeKEM, merges
  *concurrent* membership and key-rotation operations with no central sequencer.
- **[iroh-docs](https://crates.io/crates/iroh-docs) /
  [iroh-blobs](https://crates.io/crates/iroh-blobs) /
  [iroh-gossip](https://crates.io/crates/iroh-gossip)** — replicated index, content-addressed
  payloads, control-plane pub/sub.
- **[loro](https://crates.io/crates/loro)** — CRDT for document contents and the workspace manifest.

```
       CONTROL PLANE (iroh-gossip)              DATA PLANE (iroh-docs + iroh-blobs)
   Signed<CgkaOperation> broadcast on a       Blinded 32-byte keys → BLAKE3 hashes of
   topic derived from the CGKA tree id;       chunks, and of asset segments sealed
   membership, key rotation, log repair       under a per-asset content key;
                                              RBSR index sync + verified blob streaming
                        \                    /
                         iroh Endpoint (QUIC, hole punching, relays)
```

A workspace entry is either a CRDT **document**, replicated as encrypted Loro updates, or a binary
**asset** — attached from a path and written back to one, a segment at a time, so a multi-gigabyte
file is bounded by the disk rather than by memory. Peers index an asset's segments without fetching
them and pull only what somebody opens.

This crate is the `iroh` wiring and the async `Workspace` facade. All cryptography and state live in
[`iroh-beekem-core`](https://crates.io/crates/iroh-beekem-core), which is I/O-free and therefore
runnable under a deterministic simulator.

For the full design, threat model and deliberate trade-offs — including what blinding does *not*
hide — see the [workspace README](https://github.com/ocramz/iroh-beekem).

## License

MIT OR Apache-2.0
