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

// What the invitee sends out of band: their member id, their public leaf key,
// and the endpoint they will connect from. `Identity::enrollment` builds it, so
// neither side has to name a `beekem` or `keyhive_crypto` type to invite anyone.
let bob = their_identity.enrollment(their_endpoint_id);

// Admitting someone returns the invite they need. The role is chosen here
// because it decides what capability the ticket carries. The ticket is signed,
// names Bob's device, expires within the hour, and is single-use.
let invite = ws.add_user(&bob, Role::Editor, "Bob").await?;

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

`CgkaController::merge` therefore applies three checks beekem does not, and none
substitutes for another:

* **Signature** — the operation must verify against its own embedded issuer key.
  Catches a payload spliced onto an observed signature.
* **Membership** — that issuer must be someone an accepted `Add` introduced.
  Catches the freshly minted keypair, which can sign its own messages perfectly well.
* **Capability** — that issuer must hold a certificate permitting *this* operation.
  Catches the member in good standing doing something its role does not allow, which
  the first two checks pass without comment. See
  [Authorization is verifiable offline](#authorization-is-verifiable-offline).

The membership set is deliberately monotone: a `Remove` does not retract it. Two peers
seeing a removal and a concurrent operation by the removed member in opposite orders
would otherwise disagree about admissibility and diverge.

It is worth being precise about *why* that is safe, because the obvious justification is
half wrong. A removed member's `Update` cannot reach the root key — it must re-key a path
the issuer can derive — so beekem's tree semantics do neutralise it. An `Add` needs no root
key at all: the injected leaf receives key material from the next honest re-key, because
that re-key encrypts the path to every resolution including the new one. Monotonicity
remains the right call for the divergence reason it was chosen for, and it is not on its
own a containment argument. What contains the removed member is
[eviction](#a-removed-member-is-evicted-again), not admissibility.

A *second*, non-monotone set (`current_members`) tracks who is a member **now**. The two
cannot be one set, and the difference is which failure you are willing to pay for.
`known_members` answers "may this operation be merged", where disagreeing costs a dropped
operation and permanent divergence, so it must be order-independent. `current_members`
answers "may this peer connect" and "who do I list", where disagreeing costs a refused
connection that the next merge repairs. Merging them in either direction breaks something:
made monotone, a revoked device stays admitted forever; made non-monotone, `merge` starts
rejecting operations on a delivery-order-dependent predicate.

### Authorization is verifiable offline

Every role check used to run on the node *issuing* an action, against a manifest that is a
CRDT — so a member holding the lowest role could write `roles[me] = Admin`, bind a device of
theirs to an admin's user, add members, or remove the admin, and every peer merged all of it.
The checks constrained well-behaved peers and nothing else.

The tempting fix — have the receiver look up the issuer's role in the manifest — is worse
than no fix. The manifest is replicated and converges at different times on different peers,
so two peers evaluating the same operation against different views reach different verdicts,
one drops an operation the other keeps, and the group diverges *permanently*. Any
authorization predicate over mutable replicated state has that shape.

So authorization is carried by the thing being authorised and verified offline. `tree_id` is
the founder's verifying key and the founding `Add` is self-issued and checked before anything
else replays, so the founder is an identity every peer already agreed on by joining. Rooted
there, two certificate types close the loop:

* `Grant { subject, capability, seq, .. }` — an admin's statement that a user holds a role.
* `DeviceBinding { device, user, .. }` — a statement that a leaf belongs to a user, issued by
  an admin or by an existing device of that same user.

Both travel as `Signed<..>` in a bundle beside the operation they authorise, so admissibility
is decidable on receipt rather than requiring the operation to be parked — which matters,
because a parked operation is one an insider could flood the queue with.

Validity is a pure function of the certificate set, computed as a fixpoint. That is what makes
it safe at merge time: two peers holding the same certificates reach the same verdict however
they arrived. It rests on the same two-predicate split as `known_members`/`current_members`:
`ever_admin` is monotone and decides whether a *certificate* is admitted, keeping the closure
order-independent; `role_of` is non-monotone, resolved by `(seq, digest)` so a later grant
supersedes an earlier one, and decides whether an *action* is permitted.

The manifest keeps logical paths, display names, labels, and the self-attested author and
endpoint claims — everything whose forgery grants nothing. **The capability closure decides who
is authorised to act; the manifest records what that produced.**

`require_admin` and `require_write` still run on the issuing node. They are a fail-fast local
courtesy — a clear error instead of an operation every peer will drop — and are documented as
such. They are not the enforcement.

### A removed member is evicted again

A removed member keeps whatever capability it held, because the certificate store is grow-only,
and its signature stays admissible, because `known_members` is monotone. So it can still mint a
binding for a keypair it controls and issue a valid `Add`. This is the one attack the merge-time
check deliberately does not refuse — the only thing distinguishing it is `current_members`, and
refusing on an order-sensitive predicate is the divergence the whole design avoids.

The splice is accepted and then undone. On merging an `Add` whose issuer is no longer a current
member, an honest admin raises `Effect::EvictUncertified` and removes the injected leaf; every
admin reaches that conclusion independently, duplicate removals merge as `MergeOutcome::Duplicate`,
and the response is rate-limited per spliced leaf because each one costs a removal and a namespace
rotation.

What this buys is a bounded window, not zero. During it the injected leaf can read what the group
publishes. What it never buys the attacker is *escalation*: the closure is rooted, so a revenant can
pass on only what it already held. Both halves are property-tested — `always` for the no-escalation
claim, `eventually_within` for the eviction.

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

### An invite is a ticket, not a bearer token

An `Invite` is `Signed<InviteTerms>`, and the terms name the device they admit (`invitee`), the
moment they stop being redeemable (`not_after`, an hour out), the ticket that identifies them
(`nonce`), and the namespace generation their `doc_ticket` belongs to (`epoch`). `Workspace::join`
checks the signature, that the issuer may administer under a closure rooted at `tree_id`, that the
terms name *this* device, that the window is still open, and that this node has not redeemed the
nonce before — in that order, with the nonce claimed last so a ticket that fails an earlier check
does not burn one that would have worked.

Every check is in `iroh-beekem`, not in the core. Expiry needs a clock and single use needs a
ledger, and the core has neither by design; an invite is redeemed once, locally, by one device, so
the decision is local and the cost of two peers disagreeing is a refused join rather than a diverged
group. That is the same line drawn for `Grant::not_after`, which is carried on the wire and
deliberately never evaluated during a merge.

**What this does and does not buy.** A leaked ticket has never granted read access: joining needs
the leaf secret whose public half the inviter named in the `Add`, and that secret never travels.
What it grants is *visibility* — the blinding secret, the replica to watch, the inviter to dial. The
checks above stop a thief redeeming a ticket **through this library**; they cannot stop one reading
the struct's fields directly. Two things do, and they are the group's real remedy: `RosterGuard`
refuses the thief's endpoint because it is on nobody's roster, and a namespace rotation abandons the
replica the ticket names. There is nothing in a bearer token to revoke, so rotation is the answer to
a leak. The `StolenInvite` scenario in `iroh-beekem-sim` states exactly that boundary: the thief
never enters anyone's `users()`, never reconstructs the group, never decrypts a byte, and stops
seeing entries the moment the group rotates — but it *does* see the replica until then.

### Two DAGs must both be satisfied

An arriving chunk applies only when the CGKA operation graph has caught up far enough to reach its PCS
key **and** Loro has the CRDT operations it depends on. Neither ordering is guaranteed by the network,
so chunks failing either test are parked and retried. This pairing is the most likely source of silent
data loss in the system, and it is what the property tests are aimed at.

## Threat model

What is confidential, and from whom. Its absence is what let the authorization finding above go
unnoticed for four phases: every row of the first table asks *"what does an outsider see"*, and
nothing asked *"what can a member do"*.

| Layer | Protected by | An outsider holding the identifiers sees |
|---|---|---|
| **Blob payloads** | Per-chunk AEAD keys from the CGKA, bound to content ref + predecessor refs | Ciphertext only |
| **Data-plane index** (`iroh-docs`) | `RosterGuard`, then knowledge of the `NamespaceId` | Nothing, unless admitted. Once admitted: blinded keys (document count, which changed, when), entry sizes, author ids, timestamps |
| **Control plane** (`iroh-gossip`) | `RosterGuard`, then knowledge of the `TopicId` | Nothing, unless admitted. Once admitted: four of the six `ControlMsg` variants in plaintext — `Op`, `Log` and `Certs`, so every operation, certificate and membership change; and `Announce { key }`, which is real-time telemetry for every write. `Namespace` is **not** plaintext: its capability travels encrypted under the group key, which is the whole reason a removed device cannot follow a rotation |

"Plaintext" means *readable by an admitted overlay participant*, not *readable on the wire*: gossip
runs over iroh's QUIC/TLS and every ALPN sits behind `RosterGuard`, which fails closed.

Encrypting the first four is not an available fix. `Op`/`Log`/`Certs` are what a peer consumes in
order to *derive* the group key, so encrypting them under that key is circular — and they carry no
secrets: an `Update`'s `PathChange` holds inner-node secrets already encrypted to sibling
resolutions, as TreeKEM requires. What makes a public topic safe is authentication on receipt, not
confidentiality in transit. Encrypting `Announce` buys nothing against the only adversary it would
target, since a member in good standing holds that key already.

### What a member can do

| Actor | Constrained by | Can actually do |
|---|---|---|
| **Outsider** (never admitted) | `known_members` on merge, `RosterGuard` on connect | Nothing. The `Outsider` and `Forging` scenarios prove it |
| **Member, any role** | The capability closure, checked by **every receiver** | Read everything (that is forward secrecy, not a defect); enrol further devices of *its own* user; nothing else. Its `Add` of a new user, its `Remove` of an admin, and any grant it writes itself are all dropped by every peer |
| **Removed member** | The same, plus eviction | Splice a leaf it controls into the tree, and read what is published during the window before an admin evicts it. It cannot escalate: the leaf inherits only what the revenant itself held |
| **Thief holding a leaked invite** | The invite's own signature and binding, then `RosterGuard`, then rotation | Read the operation log and the certificate store, both public anyway; compute the blinded key of a document whose uuid it can name; watch the replica until the group rotates. It cannot join — that needs the invitee's leaf secret, which no ticket carries — and it decrypts nothing. The `StolenInvite` scenario proves the bound |

**Out of scope, and stated so:** traffic analysis by a member in good standing, and connection
metadata visible to relay servers. Neither is fixable at this layer.

### Signature domain separation

`Signed<T>` covers `bincode(payload)` with no type name and no discriminator, and verification
recomputes it for whatever `T` the *deserializer* chose — and on the wire a `Certificate` is an enum,
so that choice is the attacker's. A genuine `(issuer, signature)` pair is therefore transferable
between any two payload types whose encodings match byte for byte. The attacker forges nothing; they
lift the pair and reattach it.

Every payload this project signs — `Grant`, `DeviceBinding`, `InviteTerms` — begins with a 16-byte
printable-ASCII domain tag, checked before the signature. Both properties do work. **Distinct** tags
stop a grant being read as a binding. **Printable ASCII** stops either being read as a
`CgkaOperation`: bincode writes an enum discriminant as a little-endian `u32`, so bytes 1–3 of any
variant index below 2²⁴ are zero, and no ASCII byte is. A tagged payload therefore cannot share an
encoding with an untagged bincode enum, whatever beekem later does to its fields.

That last point is why the tags exist rather than an argument from sizes. Untagged, a
`DeviceBinding` encoded to exactly 80 bytes — and *every* 80-byte string decoded as one — against a
`CgkaOperation::Remove` at 88. Eight bytes, both signed by the same member key, and an admin's
`Remove` lifted into a `DeviceBinding { device: attacker, user: admin }` is an escalation the
capability closure admits. Nothing was exploitable, but what held those eight bytes apart was
beekem's field list, which this project depends on by version rather than by revision — so a release
that shrank `Remove` would have been a silent break.
`the_signed_payload_types_cannot_share_an_encoding` is what keeps this true; a new signed type needs
a tag and a line in that test.

## Verification

```bash
cargo test -p iroh-beekem-core     # unit + handshake spike + state machine + forgery rejection
cargo test -p iroh-beekem-sim      # propsim: convergence, concurrent rotation/revocation, forging peer
cargo test -p iroh-beekem          # two real endpoints over real QUIC: revocation, roles, rotation
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly-2025-11-21 fmt --all --check   # rustfmt.toml uses nightly-only options, so the
                                              # toolchain is pinned: an unpinned nightly changes
                                              # the expected formatting

# Workspace mode, not two per-crate runs: `iroh-beekem` depends on `iroh-beekem-core` by version as
# well as by path, so a per-crate dry run cannot resolve it until core is actually released.
cargo publish --dry-run --workspace

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
   ignores their role gains write capability on the replica; `WorkspaceState::author_may_write` still
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
9. **A workspace's admin threshold is fixed when it is created.** `create_with_quorum` sets it and
   nothing can change it afterwards. This is what makes the threshold *enforceable by receivers*
   rather than merely by the node issuing an action: the check is stricter the more a node knows, so
   a movable threshold would let a peer holding the certificates that raised it refuse an operation
   a peer still catching up had already merged — and the group would split. Pinning it to the
   founding certificate bundle, which every member holds before it can join, removes the asymmetry.
   Raising it later would be that unsound operation; lowering it would let one compromised admin undo
   the protection everyone else is relying on.
10. **Above a threshold of one, the founder may set roles alone.** Everybody else needs a quorum,
   including to appoint an admin — which is what stops an admin raising a puppet and approving its
   own actions twice. The founder is exempt because a workspace with one admin and a threshold of two
   could otherwise never reach a quorum, and because the founder is already the axiom every capability
   chain terminates at: `tree_id` *is* its key. The exemption covers roles only, never removals.
11. **Roles do not constrain what a member can *read*.** Anyone holding a leaf can decrypt, whatever
   any certificate says. That is forward secrecy working as designed, and genuine read revocation is
   a CGKA removal. This is deliberately stated as a claim about *reading only*: roles do now
   constrain what a member can **do**, and every receiver enforces it — see
   [Authorization is verifiable offline](#authorization-is-verifiable-offline). Conflating the two
   is what made a defect look like a documented trade.
12. **Demotion is a courtesy; removal is the enforcement.** A user who has ever held an admin grant
   stays `ever_admin`, so certificates it issues are still admitted and it can grant itself a higher
   `seq`. Demoting a *cooperative* admin works and needs no key rotation; stripping a *malicious* one
   means CGKA-removing every device of that user. This mirrors monotone `known_members` exactly, and
   for the same reason: the alternative is an order-dependent predicate that diverges the group.
13. **A member may enrol unlimited devices for its own user.** Enrolling your own phone is not an act
   of administration, so it needs no role — which means a member can also grow the tree without bound.
   Every such leaf inherits only that member's own role, so it is not an escalation; it is a resource
   cost, and bounding it needs a policy the group has no way to express yet.
14. **A removed member can splice a leaf in, and read for one eviction window.** It cannot escalate.
   See [A removed member is evicted again](#a-removed-member-is-evicted-again) for why refusing the
   operation outright is not available.
15. **An invite still carries the workspace secret, and must travel confidentially.** Signing it
   binds who may redeem it and for how long; it does not encrypt it. A ticket read in transit hands
   the reader the blinding secret and the `iroh-docs` ticket, and no signature over a plaintext
   struct can change that. Deliver it over an authenticated, confidential channel — a direct `iroh`
   QUIC stream to a known public key qualifies, a public gossip topic does not — and treat a leak as
   a reason to rotate. What signing buys is that a *leaked* ticket is not a *redeemable* one.
16. **A snapshot is the whole read capability, and it is not encrypted at rest.** `Node::spawn_persistent`
   writes the signing key, the leaf secret, every cached PCS key, the blinding secret and the
   plaintext-equivalent documents under `<root>`, `0600` and no further. Deliberate rather than
   omitted: `Identity::to_bytes` already made the application responsible for storing an equivalent
   secret, so encrypting the snapshot while the identity beside it sits in the clear would move the
   boundary without raising it. Hold `<root>` on an encrypted volume if that matters — which also
   covers the blobs and docs stores, neither of which this crate controls.
17. **Certificates are never retracted.** The store is grow-only, so a lost or stolen device's
   certificates remain valid documents; what stops them mattering is CGKA removal. There is no
   expiry either: `Grant::not_after` is carried on the wire but deliberately **not** evaluated,
   because an expiry inside an authorization predicate makes admissibility depend on clock skew and
   two peers disagreeing would drop different operations.
18. **Parked queues evict under pressure.** Out-of-order operations and undecryptable chunks are
   bounded (`MAX_PARKED_OPS`, `MAX_PENDING_CHUNK_BYTES`) and evict oldest-first, because an unbounded
   queue is a remote memory-exhaustion vector. Evicted operations return with the next neighbour log
   exchange; evicted chunks wait for a resync. A property test asserts honest runs never evict.
   A chunk that can *never* be decrypted is not parked at all — it is dropped, counted, and answered
   with a repair request, because holding it would occupy the budget for the life of the process
   while every drain retried a decryption that cannot succeed.

## Not yet implemented

These are gaps, not trades. Nothing in the design prevents them.

1. **Publishing re-ships whole document history.** Every edit and every resync exports all updates,
   re-encrypts them and writes a new blob; superseded blobs are never collected. Cost grows
   quadratically in edits.
2. **Eviction is eventual on every plane.** Removal now revokes reading (the CGKA), connecting
   (the roster) and watching (namespace rotation) — but all three converge asynchronously, so a
   peer that has not yet merged the removal still accepts the removed device's connections and
   entries, and nothing retracts what it already synced. The `a_removed_member_stops_seeing`
   properties in `iroh-beekem-sim` state exactly where the line now sits.

3. **Admission is a union across the workspaces on one node.** The roster is now keyed by workspace,
   so two workspaces no longer clobber each other's members — but `RosterGuard::on_accepting` sees
   only an `EndpointId`, and `iroh-gossip` multiplexes every topic and `iroh-docs` every namespace
   over one connection per ALPN, so there is no workspace to attribute a connection to at the moment
   the decision is made. A member of one workspace may therefore open a connection that carries
   traffic for another on the same node. Closing it means one endpoint per workspace. It is an
   availability boundary either way: reaching a namespace is not reading it, and every chunk in it is
   encrypted to a CGKA the peer holds no leaf in.
4. **`leave` is announce-only and best-effort.** `GossipSender::broadcast` enqueues without
   acknowledgement and offers no flush, so a departure that never reaches a peer simply did not
   happen — and unlike a rotation it has no anti-entropy behind it, because the one node that would
   re-announce it is the one that left. An admin should follow a `leave` with a `remove_user`.
5. **The gossip topic still never rotates.** It is derived from the tree id, which is the founder's
   public key, so every past invitee knows it permanently. The roster is what refuses them; without
   a new tree id — that is, a new workspace — the topic itself cannot change.



