# A `debug_assert!` denies the case the next line handles, and aborts every debug build

Filed against `beekem` 0.3.0.

## Summary

`BeeKem::sort_leaves_and_blank_paths_for_concurrent_membership_changes`
(`src/tree.rs:122`) asserts that a leaf named by a concurrent `Remove` is already blank,
and then blanks it:

```rust
// beekem-0.3.0/src/tree.rs:113
pub fn sort_leaves_and_blank_paths_for_concurrent_membership_changes(
    &mut self,
    mut added_ids: Set<MemberId>,
    removed_ids: Set<(MemberId, u32)>,
) {
    let mut leaves_to_sort = Vec::new();
    for (id, idx) in removed_ids {
        added_ids.remove(&id);
        let leaf_idx = LeafNodeIndex::new(idx);
        debug_assert!(self.leaf(leaf_idx).is_none());          // <-- aborts
        // We should have already removed this id during merge, but concurrent
        // updates at other leaves with intersecting paths must be overridden by
        // this remove.
        self.blank_leaf_and_path(leaf_idx);                    // <-- handles it
        ...
```

**The assertion and the comment two lines below it disagree, and the comment is right.**
The comment says the leaf *should* already be blank *but* that a concurrent update may
have left it otherwise, which is precisely why `blank_leaf_and_path` is called
unconditionally. The assertion denies that this can happen. It can, on an ordinary
interleaving, and it takes the process down with it.

The index is also worth noting on its own: `idx` comes from the `CgkaOperation::Remove`
payload, so it is the leaf index **as the removing node's tree had it** at mint time. A
receiver that has sorted its leaves differently does not necessarily hold the removed
member there.

## What it costs

A `debug_assert!` is compiled in by every `cargo test` and every `cargo run` at default
settings. There is no way for a downstream crate to reach this state and recover: the
process aborts before any error can be returned. Keeping `debug-assertions` on is
ordinarily the right choice for a test suite — this one has to weigh that against an
upstream abort.

## Not a correctness bug

Verified, and the reproduction asserts both halves: with debug assertions **off**, the same
interleaving completes, the replay succeeds, both nodes report four members, and neither has
lost the member whose leaf the stale index could have taken. The blanking the assertion
guards against is harmless here. So this is an over-strict assertion rather than a symptom
of divergence, and the fix is to delete it rather than to change the code below it.

## Reproduction

`concurrent-remove-debug-assert.rs` is a standalone `#[test]`. It expects the panic where
the panic happens and asserts convergence where it does not, so it passes today in both
profiles and fails if either half changes.

```
$ cargo test -- --nocapture
add_x leaf_index=3  add_y leaf_index=3
removal records leaf_idx=3
thread '...' panicked at beekem-0.3.0/src/tree.rs:122:13:
assertion failed: self.leaf(leaf_idx).is_none()
test a_concurrent_removal_trips_a_debug_assertion_in_beekems_tree - should panic ... ok

$ cargo test --release -- --nocapture
add_x leaf_index=3  add_y leaf_index=3
removal records leaf_idx=3
bob update -> ok=true group_size=4
bob still holds Y: true
alice still holds Y: true
test a_concurrent_removal_trips_a_debug_assertion_in_beekems_tree ... ok
```

### The interleaving, and why each part is needed

1. Alice founds a group and admits Bob and Carol. **Three members**, so the next free leaf
   is index 3. Two members is not enough: the tree is then exactly full, and growing it
   takes a path that resolves step 2 without reaching the assertion.
2. From that shared head, Alice admits X and Bob admits Y. `Cgka::add` calls `push_leaf`
   immediately, so **both operations record leaf index 3** — the concurrent add conflict
   the sorting exists to resolve.
3. Each merges the other's add.
4. Alice removes X. The operation records leaf index 3, as Alice's tree has it.
5. Bob re-keys his own leaf, concurrently with that removal. **This is required.**
   `Cgka::apply_epochs` only takes the sorting path for an epoch holding more than one
   operation; an epoch of one is applied directly. Drop the rotation and the reproduction
   stops reproducing.
6. Bob merges the removal and then re-keys again, which replays the graph — and the replay
   walks the epoch from step 5 and asserts.

Neither an attacker nor an unusual configuration is involved. Two members admitting
somebody at the same time, and one of those admissions being undone while somebody re-keys,
is ordinary traffic for a group with more than one administrator.

## Suggested fix

Delete the assertion. The line below it already does the right thing in both cases, and the
comment already explains why:

```rust
for (id, idx) in removed_ids {
    added_ids.remove(&id);
    let leaf_idx = LeafNodeIndex::new(idx);
    // We should have already removed this id during merge, but concurrent
    // updates at other leaves with intersecting paths must be overridden by
    // this remove.
    self.blank_leaf_and_path(leaf_idx);
```

If the invariant is meant to hold, then the thing to correct is the *index*: resolve the
removed member's leaf locally with `self.id_to_leaf_idx`, rather than trusting the index the
removing node recorded in the operation. That would also make the blanking independent of
whatever leaf sorting the receiver has performed since.

## Impact downstream

Found in [`iroh-beekem`](https://github.com/ocramz/iroh-beekem) by a simulated world running
a removed member that keeps acting, on a network that loses, duplicates and reorders
messages — `a_revenant_on_a_cruel_network` in `crates/iroh-beekem-sim/tests/properties.rs`,
which is `#[ignore]`d for this reason. That workspace deliberately keeps `debug-assertions`
on in its test profiles, so the abort ends the run before any property is evaluated.
