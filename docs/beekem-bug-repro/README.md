# `Cgka::remove` reports `IdentifierNotFound` for a member it has just approved

Filed against `beekem` 0.3.0.

> **Other reproductions in this directory.** A second, unrelated defect is written up in
> [concurrent-remove-debug-assert.md](concurrent-remove-debug-assert.md), with its own
> standalone test: a `debug_assert!` in `BeeKem` that denies the case the line below it
> handles, and aborts every debug build on an ordinary concurrent interleaving.

## Summary

`Cgka::remove` (`src/cgka.rs:283`) evaluates its
membership guard against the tree *before* replaying the operations graph, and then acts on
the tree *after* replaying it. When the replay is what removes the member, the guard passes
and the subsequent lookup fails, so the call returns `Err(CgkaError::IdentifierNotFound)`
for a member the caller was just told is present.

```rust
// beekem-0.3.0/src/cgka.rs:283
pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
    &mut self, id: MemberId, signer: &S,
) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
    if !self.tree.contains_id(&id) {
        return Ok(None);           // (1) evaluated against the *un-replayed* tree
    }
    if self.should_replay() {
        self.replay_ops_graph()?;  // (2) may remove `id` from the tree
    }
    if self.group_size() == 1 {
        return Err(CgkaError::RemoveLastMember);
    }
    let (leaf_idx, removed_keys) = self.tree.remove_id(id)?;   // (3) IdentifierNotFound
    ...
}
```

A caller that already holds a queued, unreplayed `Remove` for `id` — which is the normal
state after merging a concurrent membership change, since
`merge_concurrent_operation` deliberately queues structural changes rather than applying
them — hits (1) true, (2) removes `id`, (3) error.

The error is **spurious rather than fatal**: the replay at (2) is a side effect that
persists, so an immediate second call returns `Ok(None)` as it should. But a caller that
treats the first error as final never retries, and callers reasonably do.

## A second, related observation

`Cgka::group_size()` is `tree.member_count()` and is likewise read without replaying, so
between merging a concurrent removal and the next replay it reports a member the node has
already accounted for as gone. In the reproduction below, `group_size()` is `4` while the
caller's own membership set is `3` and the tree is about to agree.

## Reproduction

`repro.rs` is a standalone `#[test]`. Expected output:

```
before: group_size=4 log_says_carol_present=false
remove(carol) -> Err(IdentifierNotFound)
after:  group_size=3 log_says_carol_present=false
retry:  remove(carol) -> Ok(None)
```

The first line is the disagreement in one place: the operation graph already holds Carol's
removal, and `group_size()` still counts her, because nothing has replayed the graph into
the tree yet.

The assertions encode the *current* behaviour, so the test fails if the bug is fixed.

## Suggested fix

Replay before the guard, so that both the `contains_id` check and the `remove_id` lookup
see the same tree:

```rust
if self.should_replay() {
    self.replay_ops_graph()?;
}
if !self.tree.contains_id(&id) {
    return Ok(None);
}
```

The same reordering applies to `group_size()` if it is meant to be an authoritative
membership count rather than a view of the last-replayed tree.

## Impact downstream

Found in [`iroh-beekem`](https://github.com/ocramz/iroh-beekem), where every admin
independently performs a removal once a quorum forms — so concurrent identical removals are
the normal case, not an edge case. A node that took the first error as final kept a member
the rest of the group had removed, permanently and silently.
