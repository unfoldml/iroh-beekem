# iroh-beekem-core

The pure engine behind [`iroh-beekem`](https://crates.io/crates/iroh-beekem): BeeKEM continuous group
key agreement, blinded storage keys, the encrypted workspace manifest, and the workspace state
machine.

**No tokio, no iroh, no clock, no sockets.** Every effect is returned to the caller as data rather
than performed. That constraint is not stylistic — it is what allows the entire protocol to be driven
by a deterministic simulator with virtual time and a seeded RNG, so that partitions, reordering and
concurrent membership changes can be property-tested rather than hoped about.

The purity is enforced mechanically; this must match nothing:

```bash
cargo tree -p iroh-beekem-core -e normal --prefix none \
  | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'
```

## What lives here

| Module | Role |
|---|---|
| `keys` | `CgkaController` — the whole cryptographic surface: group membership, key rotation, content encryption. Adds the signature and membership checks that beekem deliberately does not perform. |
| `state` | `WorkspaceState` — the `(state, event) -> effects` machine, including the parking queues for out-of-order chunks and operations. |
| `blinding` | Fixed-length storage keys derived from a workspace secret, so `iroh-docs` never sees a path or a filename. |
| `manifest` | The encrypted directory index and role assignments, as a Loro CRDT. |
| `content` | Content refs and the on-the-wire ciphertext type. |

For the full design, threat model and trade-offs, see the
[workspace README](https://github.com/ocramz/iroh-beekem).

## License

MIT OR Apache-2.0
