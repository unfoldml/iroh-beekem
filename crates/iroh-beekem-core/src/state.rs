//! The workspace state machine: `(state, event) -> effects`, with no I/O.
//!
//! This is the piece both the deterministic simulator and the real `iroh`
//! transport drive. It never opens a socket, reads a clock, or spawns a task;
//! everything it wants the outside world to do comes back as an [`Effect`] for
//! the caller to perform.
//!
//! # Two causal DAGs, one pipeline
//!
//! An incoming chunk is only applicable when *both* of these hold:
//!
//! 1. the local CGKA can reach the PCS key the chunk names — which requires the
//!    control-plane operation graph to have caught up; and
//! 2. Loro has the CRDT operations this chunk's updates depend on.
//!
//! Neither ordering is guaranteed by the network, so a chunk that fails either
//! test is parked in [`WorkspaceState::pending_chunks`] and retried whenever new
//! control operations arrive. Getting this pairing wrong is the most likely
//! source of silent data loss in the whole system, which is why
//! [`WorkspaceState::pending_len`] is exposed for properties to assert on.
//!
//! # A third outcome, and why repair exists
//!
//! There is a case neither of those covers: a chunk keyed under an epoch that
//! predates this node's membership. Waiting cannot fix it — that is forward
//! secrecy — and neither can anti-entropy, because [`Event::Resync`]
//! re-encrypts under the *current* epoch key, which for such a peer is a key it
//! already could not derive. Re-publishing unchanged content then reproduces a
//! byte-identical chunk, so the repair loop is a fixed point that carries no
//! information.
//!
//! [`Effect::RequestRepair`] and [`Event::RepairRequested`] close that loop:
//! the stuck peer names what it cannot read, and a peer that *can* read it
//! answers by minting a new epoch ([`Keying::Fresh`]) and re-publishing under
//! it. A freshly minted epoch is derivable by every leaf in the tree and by
//! nothing outside it, so the repair reaches new members without reaching
//! removed ones.

use std::collections::{HashMap, HashSet, VecDeque};

use beekem::{
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
use keyhive_crypto::{share_key::ShareKey, signed::Signed};
use loro::{CommitOptions, ExportMode, Frontiers, LoroDoc};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    asset::{AssetKey, AssetMeta},
    blinding::{DocumentUuid, StorageKey, WorkspaceSecret},
    capability::{AdminAction, CapabilityStore, Certificate, DEFAULT_THRESHOLD, Role},
    content::{Chunk, ChunkRef},
    error::CoreError,
    keys::{AuthorizedOp, CgkaController, DecryptOutcome, EpochId, MergeOutcome},
    manifest::{DeviceRecord, FileEntry, Manifest, WorkspaceInfo, hex},
    snapshot::{SNAPSHOT_VERSION, WorkspaceSnapshot, member_from_bytes},
    version::{AssetVersion, Checkpoint, RestoreOutcome, UnixSeconds, VersionId, VersionInfo},
};

/// How much ciphertext may sit parked awaiting keys or CRDT dependencies.
///
/// A count limit would be the wrong shape here: chunks carry whole document
/// histories, so a hundred of them and a hundred thousand of them differ by
/// orders of magnitude in memory. The budget is on bytes for that reason, with
/// [`MAX_PENDING_CHUNKS`] as a second guard against a flood of tiny ones.
///
/// Unlike a parked control operation, an evicted chunk is *not* recoverable
/// from a peer exchange — it comes back only on the next resync. The budget is
/// therefore generous: eviction here means losing content until someone
/// re-announces, so it should be a genuine last resort.
pub const MAX_PENDING_CHUNK_BYTES: usize = 64 * 1024 * 1024;

/// How many chunks may be parked at once, regardless of their size.
pub const MAX_PENDING_CHUNKS: usize = 4096;

/// What a repair request is asking somebody to re-encrypt.
///
/// The manifest is a target in its own right rather than a document with a
/// well-known UUID, because it is the one thing whose loss is not merely
/// invisible content: device records live there and the roster derives from
/// them, so a member that cannot read the manifest is refused by peers rather
/// than merely out of date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RepairTarget {
    /// The current namespace capability.
    ///
    /// A member that missed a rotation is not merely out of date, it is *gone*:
    /// it goes on syncing a replica the group has abandoned, so it sees no new
    /// entry and publishes where nobody reads. And unlike content, a rotation
    /// is announced once — there is no later write to carry it — so without a
    /// way to ask, a single lost announcement strands a member permanently.
    Namespace,
    /// One document, named by the UUID both sides already agree on.
    ///
    /// Asked for by a peer that cannot derive the epoch the content was keyed
    /// under, and answered by minting a fresh one. Contrast
    /// [`Self::DocumentHistory`], which is the same document and a different
    /// problem.
    Document(DocumentUuid),
    /// The history of one document, for a peer that can decrypt but cannot apply.
    ///
    /// Delta publishing makes this reachable and nothing else does. A chunk
    /// carrying updates since the publisher's last version is useless to a
    /// receiver that never saw the base, and the two failures are indistinguishable
    /// from the outside: both leave the document unreadable. They are opposite
    /// inside, though, and answering the wrong one is expensive or useless.
    /// [`Self::Document`] is a key problem, answered with `Keying::Fresh`, which
    /// charges the whole group a CGKA operation. This is a *history* problem: the
    /// requester holds the key perfectly well, so re-keying would cost the group a
    /// rotation and still not deliver the operations it is missing. The answer is
    /// a full export under the current epoch.
    DocumentHistory(DocumentUuid),
    /// The wrapped content key of one binary asset.
    ///
    /// The asset counterpart of [`Self::Document`], and it is cheap in a way that
    /// one is not. An asset's segments are keyed by a per-asset content key
    /// rather than by the CGKA directly, so a member admitted after the asset was
    /// published is stuck on exactly 32 bytes of ciphertext — the key chunk — and
    /// repairing it means re-encrypting those 32 bytes under a fresh epoch, not
    /// the gigabytes behind them.
    AssetKey(DocumentUuid),
    /// The workspace manifest.
    Manifest,
}

/// Which generation of the replicated index a node is syncing.
///
/// Removal revokes *reading* through the CGKA, but the `iroh-docs` write
/// capability is all-or-nothing and cannot be withdrawn from one holder — so a
/// removed device keeps syncing the index, and goes on observing entry
/// existence, size, author and timing for every document. The only way to stop
/// that is to abandon the namespace for a fresh one whose capability the removed
/// device never receives. This identifies which one the group is on.
///
/// # Why a digest as well as a counter
///
/// Two admins removing different members concurrently both mint epoch *n+1*,
/// and a bare counter gives no way to choose between them — the group would
/// split across two namespaces, each half convinced it was current. Ordering on
/// `(epoch, digest)` makes the choice total and identical everywhere, so both
/// sides converge on the same winner without a coordinator.
///
/// The losing namespace is not wrong, merely abandoned: it held correctly
/// encrypted data the whole time. This is a convergence device, not a
/// correctness argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NamespaceEpoch {
    /// Generation counter. Ordered first, so a later rotation always wins.
    pub epoch: u32,
    /// BLAKE3 of the capability, breaking ties between concurrent rotations.
    pub digest: [u8; 32],
}

impl Default for NamespaceEpoch {
    /// A workspace starts on [`Self::INITIAL`], which every rotation supersedes.
    fn default() -> Self {
        Self::INITIAL
    }
}

impl NamespaceEpoch {
    /// The epoch a workspace starts on, before any rotation.
    ///
    /// The all-zero digest is not a real capability digest and does not need to
    /// be: it is only ever the *smallest* value, which is exactly right for a
    /// founding namespace that any rotation should supersede.
    pub const INITIAL: Self = Self {
        epoch: 0,
        digest: [0u8; 32],
    };

    /// The epoch a freshly minted capability belongs to.
    #[must_use]
    pub fn of(epoch: u32, ticket: &[u8]) -> Self {
        Self {
            epoch,
            digest: blake3::hash(ticket).into(),
        }
    }
}

impl std::fmt::Display for NamespaceEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "e{}/", self.epoch)?;
        for byte in &self.digest[..4] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Something that happened to this node.
#[derive(Debug, Clone)]
pub enum Event {
    /// A signed CGKA operation arrived on the control plane, with its proof.
    ///
    /// The certificates travel with the operation rather than separately so that
    /// admissibility is decidable on receipt; see [`AuthorizedOp`].
    ControlOp(AuthorizedOp),
    /// Capability certificates arrived on the control plane with no operation.
    ///
    /// A role change mints a grant but no CGKA operation, so it needs a way to
    /// travel on its own. Absorbing them can unblock operations already parked,
    /// which is why this returns effects like any other arrival.
    CertsArrived(Vec<Certificate>),
    /// An encrypted chunk arrived on the data plane.
    ChunkArrived {
        /// Which document the chunk belongs to.
        doc: DocumentUuid,
        /// The ciphertext, exactly as stored.
        chunk: Box<Chunk>,
    },
    /// The local user appended text to a document.
    LocalEdit {
        /// Which document to edit.
        doc: DocumentUuid,
        /// Text to append.
        text: String,
    },
    /// The local user replaced a document's entire contents.
    WriteFile {
        /// Which document to overwrite.
        doc: DocumentUuid,
        /// The new contents.
        text: String,
    },
    /// The local user inserted text at a position.
    InsertText {
        /// Which document to edit.
        doc: DocumentUuid,
        /// Character offset to insert at, clamped to the document's length.
        pos: usize,
        /// Text to insert.
        text: String,
    },
    /// The local user deleted a range of text.
    RemoveText {
        /// Which document to edit.
        doc: DocumentUuid,
        /// Character offset to delete from, clamped to the document's length.
        pos: usize,
        /// How many characters to delete, clamped to what remains.
        len: usize,
    },
    /// The local user put a document back the way it was at an earlier version.
    ///
    /// Applied as a **new edit going forward**, never as a rewrite of history:
    /// Loro is asked for the operations that undo everything since that version,
    /// and those are committed and published like any other edit. Two properties
    /// follow, and both are the reason it is done this way. It converges with a
    /// member editing concurrently — their work is not silently discarded, it
    /// merges with the revert exactly as two ordinary edits would. And every
    /// version stays listed afterwards, including the ones reverted away, so a
    /// revert can itself be reverted.
    ///
    /// The alternative — dropping the operations after that point — is not
    /// available at all in a group: a peer that had already merged them would
    /// keep them, and the two replicas would never agree again.
    RevertDocument {
        /// Which document to put back.
        doc: DocumentUuid,
        /// The state to restore, from [`WorkspaceState::document_versions`].
        to: VersionId,
    },
    /// The local user deleted a document.
    ///
    /// Removes it from this workspace; it does not erase it from the disk of
    /// any member who already synced it. See `WorkspaceState::delete_file`.
    DeleteFile {
        /// Which document to delete.
        doc: DocumentUuid,
    },
    /// The local user admitted a new person, along with their first device.
    ///
    /// The new user's id is that first device's member id; see the
    /// [manifest module documentation](crate::manifest) for why.
    AddUser {
        /// The new device's identity, which also becomes the user id.
        member: MemberId,
        /// The new device's published leaf key.
        share_key: ShareKey,
        /// The role to grant the new user.
        role: Role,
        /// Human-readable name, for display only.
        display_name: String,
        /// The new device's transport address, if the admitter knows it.
        ///
        /// Recorded by the admitter rather than waiting for the joiner to
        /// announce it, because the joiner cannot be admitted to the overlay
        /// until it is on a roster, and it cannot get onto a roster until its
        /// address is recorded. Supplying it here breaks that circle. `None` is
        /// legitimate — the joiner's own `AnnounceEndpoint` fills it in — but
        /// then somebody must let the joiner connect in the meantime.
        endpoint: Option<[u8; 32]>,
    },
    /// The local user admitted another device for an existing person.
    ///
    /// Needs no administrative role when adding a device to *your own* user —
    /// enrolling your own phone is not an act of administration — but binding a
    /// device to somebody else's user is, or any member could inherit an
    /// admin's permissions by claiming to be one of their devices.
    AddDevice {
        /// The new device's identity.
        member: MemberId,
        /// The new device's published leaf key.
        share_key: ShareKey,
        /// The user this device will act for.
        user: [u8; 32],
        /// Human-readable label, for display only.
        label: String,
        /// The new device's transport address, if the admitter knows it. See
        /// [`Event::AddUser::endpoint`].
        endpoint: Option<[u8; 32]>,
    },
    /// The local user revoked a member.
    RemoveMember {
        /// The member to remove.
        member: MemberId,
    },
    /// The local user proposed an administrative action for a quorum to approve.
    ///
    /// Costs nothing and grants nothing on its own: a proposal is data, and the
    /// action happens only once enough distinct admins have approved it.
    Propose {
        /// What is being proposed.
        action: AdminAction,
        /// When the proposal stops being offered, in absolute milliseconds.
        ///
        /// Carried on the wire and **not** evaluated here — the core has no
        /// clock, and an expiry inside the quorum predicate would make two peers
        /// with skewed clocks execute different sets of proposals. A caller with
        /// a clock may decline to *approve* something expired.
        expires: Option<u64>,
    },
    /// Anti-entropy for the certificate store: re-announce everything it holds.
    ///
    /// Certificates are the one kind of state with **no write behind them**. A
    /// document lost in transit is carried by the next edit; a manifest chunk by
    /// [`Self::ResyncManifest`]; a rotation by [`Self::ResyncNamespace`]. A
    /// grant, a proposal or an approval is broadcast exactly once and has nothing
    /// following it, so a single dropped gossip message strands it until a
    /// neighbour happens to reappear and trigger a whole-log exchange — which on
    /// a stable overlay may be never.
    ///
    /// That is survivable for a grant, which costs its subject a role until the
    /// next membership change. It is **not** survivable for an approval: a quorum
    /// that formed on one node and reached no other leaves an action performed
    /// there and refused everywhere else, which is exactly the divergence the
    /// receiver-side check exists to prevent.
    ResyncCertificates,
    /// The local user approved a proposal, naming it by digest.
    Approve {
        /// The digest of the proposal certificate being approved.
        proposal: [u8; 32],
    },
    /// The local user is walking away from the workspace.
    ///
    /// Removes every device of the *local* user, and nobody else's. Distinct
    /// from [`Self::RemoveMember`] in two ways that both matter:
    ///
    /// * it needs no administrative role, because removing your own leaf is not
    ///   an act of administration — `CgkaController::authorize` already admits a
    ///   same-user `Remove`; and
    /// * it emits **no** [`Effect::RotateNamespace`]. A leaver that rotated
    ///   would mint the very capability it is walking away from and announce it
    ///   to the group under a key the leaver still holds, which is a strictly
    ///   worse position than not rotating at all.
    ///
    /// The consequence is worth stating plainly: **leaving is a courtesy, not a
    /// security boundary.** It unlearns nothing the leaver could already read
    /// and withdraws nothing it was given. An admin who wants the guarantees of
    /// a removal must issue one.
    Leave,
    /// The local user rotated their leaf key for post-compromise security.
    Rotate,
    /// An encrypted manifest replica arrived on the data plane.
    ManifestArrived {
        /// The ciphertext, exactly as stored.
        chunk: Box<Chunk>,
    },
    /// The local user recorded or replaced a document's metadata.
    UpsertFile {
        /// The metadata to record.
        entry: FileEntry,
    },
    /// The local user moved or renamed a document.
    RenameFile {
        /// Which document to rename.
        doc: DocumentUuid,
        /// The new logical path.
        path: String,
    },
    /// The local user assigned a role. Requires the local member to be an admin.
    SetRole {
        /// The **user** whose role changes, as raw id bytes — not a device.
        user: [u8; 32],
        /// The role to assign.
        role: Role,
    },
    /// The local user renamed the workspace. Requires an administrative role.
    SetInfo {
        /// The metadata to record.
        info: WorkspaceInfo,
    },
    /// The local user set their own display name.
    ///
    /// Deliberately self-only: a display name is how a person presents
    /// themselves, and letting one member rename another is an impersonation
    /// vector rather than a convenience.
    SetDisplayName {
        /// The name to present.
        display_name: String,
    },
    /// Publish the local member's data-plane author identity.
    ///
    /// Self-attestation, so it needs no privilege: it says only "entries signed
    /// by this author are mine", and grants nothing on its own. Until an admin
    /// has also given this member a writing role, peers still reject the
    /// entries it names.
    AnnounceAuthor {
        /// The local `iroh-docs` author id.
        author: [u8; 32],
    },
    /// Publish the local device's transport address.
    ///
    /// Self-attestation, like [`Event::AnnounceAuthor`], and safe for the same
    /// reason inverted: an endpoint id grants nothing on its own, because the
    /// roster admits an address only when the *member* holding it is one the
    /// group already accepted. Claiming somebody else's address would at worst
    /// let them connect.
    ///
    /// Recorded locally even when the manifest cannot yet accept it, and
    /// re-applied on every manifest arrival — a joiner announces before its
    /// first sync, when it has no device record to attach the address to.
    AnnounceEndpoint {
        /// The local `iroh` endpoint id, as raw bytes.
        endpoint_id: [u8; 32],
    },
    /// Re-publish a document's current state without editing it.
    ///
    /// This is anti-entropy. Over a lossy transport a chunk can be dropped with
    /// no later chunk to carry its content, so peers need a periodic
    /// re-announcement to converge. `iroh-docs` provides this for real via
    /// range-based set reconciliation; in a simulation it has to be explicit.
    Resync {
        /// Which document to re-publish.
        doc: DocumentUuid,
    },
    /// The caller minted the namespace this node asked for.
    ///
    /// The reply to [`Effect::RotateNamespace`]. `ticket` is the capability for
    /// the new namespace, opaque here: what it *means* is a transport concern,
    /// and naming `iroh_docs::DocTicket` in this crate would drag iroh into a
    /// crate that must not depend on it.
    NamespaceMinted {
        /// The generation the caller was asked to mint.
        epoch: u32,
        /// The capability, in whatever encoding the caller chose.
        ticket: Vec<u8>,
    },
    /// A peer announced a namespace rotation.
    ///
    /// The capability is encrypted under the group key, so a device removed
    /// before the rotation cannot read it — which is the entire mechanism. It
    /// arrives as an ordinary chunk and is decrypted the same way as any other.
    NamespaceArrived {
        /// The generation the sender claims to have minted.
        ///
        /// Not trusted on its own: the digest is recomputed from the decrypted
        /// capability, so a peer cannot win a tie by asserting a large one.
        epoch: u32,
        /// The encrypted capability.
        chunk: Box<Chunk>,
    },
    /// Re-announce the current namespace capability without rotating.
    ///
    /// Anti-entropy for a rotation. A rotation is announced *once*, so unlike a
    /// document it has nothing behind it: a member whose copy was lost, or that
    /// received it before the operation establishing its key, is stranded on an
    /// abandoned replica — publishing where nobody reads and seeing nothing
    /// anybody writes.
    ///
    /// Keyed under the *current* epoch rather than a fresh one, which is the
    /// difference between this and answering a repair. This runs on a timer and
    /// minting an epoch each round would re-key the whole tree for nothing; a
    /// repair runs once per stuck peer and is worth an epoch.
    ResyncNamespace,
    /// Re-publish the manifest without changing it.
    ///
    /// Anti-entropy for the manifest, and needed for the same reason
    /// [`Event::Resync`] is needed for a document: over a lossy transport a
    /// manifest chunk can be dropped with no later chunk to carry its content,
    /// because the manifest is otherwise published *only when it changes*.
    ///
    /// The consequence of omitting it is not cosmetic. Device records live in
    /// the manifest, and the roster is derived from them — so a member whose
    /// record was lost in transit is refused by that peer indefinitely, and the
    /// group silently partitions along the lines of which manifest chunks
    /// happened to arrive.
    ///
    /// Deliberately **not** gated on a writing role, unlike [`Event::Resync`].
    /// A viewer has something legitimate to re-announce here — its own author
    /// and endpoint records, which it published without needing a role in the
    /// first place — and refusing would leave viewers permanently unreachable.
    ResyncManifest,
    /// A peer reports that it can never decrypt what it received from us.
    ///
    /// The other half of [`Effect::RequestRepair`], and the only thing in the
    /// protocol that turns "somebody is stuck" into "somebody re-keys".
    /// Ordinary anti-entropy cannot do it: [`Event::Resync`] re-encrypts under
    /// the *current* epoch key, so for a peer that cannot derive that key every
    /// repeat carries exactly the information the first one did — none. The
    /// answer to this event mints a new epoch instead, which every leaf in the
    /// tree can derive and nothing outside it can.
    ///
    /// Answering costs a tree operation, so the request is gated on the
    /// requester being a member *now*: a removed device must not be able to
    /// spend the group's CPU, and it gains nothing from the answer either way,
    /// since the fresh epoch is minted after its leaf left the tree.
    RepairRequested {
        /// Who is stuck. Must be a current member for the request to be honoured.
        requester: MemberId,
        /// What they cannot read.
        target: RepairTarget,
        /// The epoch they named, for the caller's rate limiting and for logs.
        epoch: EpochId,
    },
}

/// Something the caller must do on this node's behalf.
#[derive(Debug, Clone)]
pub enum Effect {
    /// Broadcast a CGKA operation, with the certificates that authorise it.
    ///
    /// Dropping one of these is not a recoverable performance choice: peers
    /// that miss it cannot derive the keys for anything encrypted afterwards.
    ///
    /// **The proof must travel with the operation.** A receiver checks the
    /// issuer's capability before merging, so an operation shipped without its
    /// certificates is refused — not parked — and the membership change it
    /// carries is lost.
    BroadcastOp {
        /// The operation to broadcast.
        op: Box<Signed<CgkaOperation>>,
        /// Certificates the receiver may not hold yet. Empty is correct for an
        /// `Update`, which needs no capability beyond membership.
        proof: Vec<Certificate>,
    },
    /// Broadcast capability certificates that authorise no particular operation.
    ///
    /// A role change produces a grant and nothing else. Like a namespace
    /// rotation, it is announced *once* and has no later write behind it, so it
    /// also needs anti-entropy — which is why a log exchange ships the whole
    /// certificate store rather than just the operations.
    BroadcastCerts(Vec<Certificate>),
    /// Ask the caller to remove a leaf that a non-member spliced into the tree.
    ///
    /// Raised when an `Add` is merged whose issuer is validly certified but is no
    /// longer a current member — a removed admin re-entering. The operation
    /// cannot simply be refused: admissibility must not depend on
    /// `current_members`, or two peers that observe the removal and the `Add` in
    /// opposite orders drop different operations and diverge permanently. So the
    /// splice is accepted and then undone.
    ///
    /// **The caller must rate-limit this**, and feed it back as
    /// [`Event::RemoveMember`]. Answering costs a removal and a namespace
    /// rotation, so an attacker re-adding in a loop would otherwise churn the
    /// whole group. The core has no clock to limit with; both backends already
    /// keep a `Cooldown` for the repair path and this reuses the pattern.
    EvictUncertified {
        /// The leaf to remove.
        member: MemberId,
    },
    /// Persist a chunk and announce it under its blinded storage key.
    StoreChunk {
        /// The blinded `iroh-docs` key to write under.
        key: StorageKey,
        /// Which document the chunk belongs to.
        doc: DocumentUuid,
        /// The ciphertext to store.
        chunk: Box<Chunk>,
    },
    /// Persist the encrypted manifest and announce it under its well-known key.
    ///
    /// Separate from [`Effect::StoreChunk`] because it lands at a key derived
    /// from a constant label rather than from a document UUID: every member
    /// must be able to find the manifest without first being told where it is,
    /// which is the one thing a random UUID cannot provide.
    StoreManifest {
        /// The blinded `iroh-docs` key the manifest always lives at.
        key: StorageKey,
        /// The ciphertext to store.
        chunk: Box<Chunk>,
    },
    /// Withdraw this node's index entry for a deleted document.
    ///
    /// Only *this* node's entry: `iroh-docs` deletion is per author, so every
    /// member must withdraw their own. A deleted document therefore disappears
    /// from the index gradually, as each peer observes the manifest tombstone,
    /// rather than atomically.
    DeleteEntry {
        /// The blinded `iroh-docs` key to withdraw.
        key: StorageKey,
        /// Which document was deleted.
        doc: DocumentUuid,
    },
    /// Withdraw this node's index entries for every segment of a deleted asset.
    ///
    /// A prefix rather than a list of keys, and the difference is not cosmetic: a
    /// multi-gigabyte asset has thousands of segments, and naming them
    /// individually would make deleting one file thousands of index writes. The
    /// segment key space of one asset is contiguous by construction — see
    /// [`WorkspaceSecret::asset_prefix`] — precisely so that a single ranged
    /// deletion covers it.
    ///
    /// The asset's *key* entry is withdrawn by an ordinary [`Self::DeleteEntry`]
    /// beside this one; it lives under a different derivation and is not in the
    /// range.
    ///
    /// [`WorkspaceSecret::asset_prefix`]: crate::blinding::WorkspaceSecret::asset_prefix
    DeleteAssetSegments {
        /// The blinded prefix every segment of the asset shares.
        prefix: [u8; 24],
        /// Which asset was deleted.
        asset: DocumentUuid,
    },
    /// A remote chunk was decrypted and merged into a local document.
    Applied {
        /// Which document changed.
        doc: DocumentUuid,
    },
    /// A remote manifest replica was decrypted and merged.
    ManifestUpdated,
    /// Mint a fresh replicated index and hand its capability back.
    ///
    /// Raised after a removal. The caller creates a new namespace and replies
    /// with [`Event::NamespaceMinted`]; the core then encrypts the capability
    /// under the *post-removal* group key and asks for it to be published.
    ///
    /// Split into three steps rather than one because minting is I/O and
    /// encrypting is not, and the split is what keeps the key handling in a
    /// crate that can be simulated.
    RotateNamespace {
        /// The generation to mint.
        epoch: u32,
    },
    /// Broadcast an encrypted namespace capability to the group.
    ///
    /// **Ordering matters, and it is a security property.** Any implicit key
    /// update this encryption produced is emitted immediately before this, and
    /// reordering the two makes the new namespace undecryptable to everyone.
    /// The removal that triggered the rotation must likewise already have been
    /// broadcast — issued first, so that the key protecting this announcement
    /// is one the removed device can no longer derive.
    PublishNamespace {
        /// The generation being announced.
        epoch: u32,
        /// The encrypted capability.
        chunk: Box<Chunk>,
    },
    /// Switch to a namespace a peer minted, and re-publish everything into it.
    ///
    /// Re-publishing is not optional: the new namespace starts empty, so a node
    /// that switched without re-publishing would take its documents out of
    /// circulation. The old namespace is abandoned rather than deleted, because
    /// peers that have not yet seen the rotation are still catching up on it.
    AdoptNamespace {
        /// The generation being adopted.
        epoch: u32,
        /// The decrypted capability, in the caller's own encoding.
        ticket: Vec<u8>,
    },
    /// Tell the group that this node can never decrypt what it just received.
    ///
    /// Raised when a chunk names an epoch whose establishing operation is in
    /// hand and whose key still cannot be derived — that is, one that predates
    /// this node's membership. Waiting cannot fix it and neither can ordinary
    /// anti-entropy, which re-encrypts under the same unreachable key; only a
    /// holder re-keying and re-publishing can, and this is how it is asked.
    ///
    /// **The caller must rate-limit this.** It is emitted on every arrival of
    /// an unreachable chunk, deliberately: a request lost in transit must be
    /// retried, and the core has no clock to schedule a retry with. Both
    /// backends key their cooldown on `(target, epoch)`, which bounds the rate
    /// while still letting a peer that becomes stuck on a *new* epoch be served
    /// at once rather than waiting the window out.
    RequestRepair {
        /// What this node cannot read.
        target: RepairTarget,
        /// The epoch it cannot derive.
        epoch: EpochId,
    },
}

impl Effect {
    /// Broadcast an operation that needs no certificate of its own.
    ///
    /// Correct for an `Update` and for the implicit re-keys `encrypt` performs:
    /// neither introduces nor removes a member, so membership is the whole of the
    /// authority they need and the receiver already established that. An `Add` or
    /// a `Remove` must **not** use this — it would ship without the binding that
    /// authorises it and be refused.
    fn broadcast(op: Signed<CgkaOperation>) -> Self {
        Self::BroadcastOp {
            op: Box::new(op),
            proof: Vec::new(),
        }
    }
}

/// What the local node could do with one parked chunk.
///
/// Separating "not yet" from "never" is what makes the pending queue
/// terminating: without it, ciphertext from before this node joined is retried
/// on every drain for the lifetime of the process, occupying the budget meant
/// for chunks that are genuinely in flight, and nothing anywhere reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkVerdict {
    /// Decrypted and merged into the document.
    Applied,
    /// The operation establishing its epoch has not arrived. Keep it.
    AwaitingKey,
    /// Decrypted, but Loro is missing operations it depends on. Keep it.
    AwaitingDeps,
    /// Keyed under an epoch this node can never derive. Drop it and ask for a
    /// re-encryption; no amount of waiting turns this into `Applied`.
    Unreachable,
    /// The key was derived and authentication then failed. Drop it, and do
    /// *not* ask for a repair: the epoch is one this node can read, so the
    /// fault is the ciphertext, and a repair request would hand any peer able
    /// to corrupt a byte a way to force group-wide re-keys.
    Corrupt,
}

/// What came of trying to unwrap an asset's content key.
///
/// The same four answers [`ChunkVerdict`] gives, for the same reason: "not yet"
/// and "never" call for different responses, and only one of them is worth
/// asking the group about. It is a separate type because the remedies differ —
/// an undecryptable document chunk asks for [`RepairTarget::Document`], an
/// undecryptable asset key for [`RepairTarget::AssetKey`], and the second is
/// thousands of times cheaper to answer.
#[derive(Debug)]
pub enum AssetKeyVerdict {
    /// Unwrapped. The caller can now open segments with it.
    Ready(AssetKey),
    /// The operation establishing the key chunk's epoch has not arrived. It may
    /// still, so there is nothing to ask for yet.
    AwaitingKey,
    /// Keyed under an epoch this node can never derive — the ordinary state of a
    /// member admitted after the asset was written. Only a re-encryption helps.
    Unreachable,
    /// The key was derived and what came out was not a 32-byte key, or
    /// authentication failed.
    Corrupt,
}

/// One chunk waiting in [`WorkspaceState::pending_chunks`].
///
/// Carries its own age because [`ChunkVerdict::AwaitingDeps`] has no other way
/// out. `AwaitingKey` resolves itself — the control plane delivers the operation
/// and the next drain applies the chunk — but a missing *dependency* is a gap in
/// somebody else's publishing history, and no amount of waiting produces it. The
/// age is what turns "still waiting" into a repair request; without it a chunk
/// sits until the pending budget evicts it and the document is silently short of
/// content nobody ever asked for again.
#[derive(Debug, Clone)]
struct Parked {
    doc: DocumentUuid,
    chunk: Chunk,
    /// Drain passes this chunk has survived without applying.
    ///
    /// Counted in passes rather than in wall time because the core has no clock,
    /// and a pass is the better unit anyway: it is one opportunity to apply, so
    /// the count is "how many chances this has had" rather than "how long the
    /// process has been up".
    drains: u32,
}

/// How many fruitless drain passes a chunk endures before its history is asked
/// for.
///
/// Not one: a chunk and the chunk it depends on routinely arrive in the same
/// ingest pass in the wrong order, and escalating on the first miss would send a
/// repair request for every such pair. Not large either — each pass needs new
/// key material or new operations to arrive, so this is already several rounds of
/// network activity.
const MAX_DEP_WAIT_DRAINS: u32 = 8;

/// How many delta publishes a document gets before one carries its whole history.
///
/// A delta is only applicable to a receiver holding its base, and a document's
/// index slot holds exactly one chunk per author — so a receiver that misses one
/// delta is stuck until a full export comes past. The demand-driven
/// [`RepairTarget::DocumentHistory`] path exists for exactly that and is the
/// reliable answer; this is the cheap one that usually gets there first, and it
/// bounds how long a peer that never speaks up stays behind.
const FULL_PUBLISH_EVERY: u32 = 16;

/// The container inside a document mapping hex Loro peer id to hex member id.
///
/// Lives in the document rather than in the manifest because it describes that
/// document's own history, and a version listing must be answerable from the
/// replica alone — a peer that has the document but not yet the manifest can
/// still say who wrote what. See [`claim_authorship`] for why the mapping is
/// recorded at all rather than derived.
const DOC_AUTHORS_CONTAINER: &str = "authors";

/// One node's complete workspace state.
pub struct WorkspaceState {
    cgka: CgkaController,
    secret: WorkspaceSecret,
    manifest: Manifest,
    docs: HashMap<DocumentUuid, LoroDoc>,
    /// Chunks that could not yet be decrypted or merged.
    pending_chunks: VecDeque<Parked>,
    /// Running total of `ciphertext` bytes held in `pending_chunks`.
    ///
    /// Tracked incrementally because the budget is checked on every arrival and
    /// summing the queue each time would make ingestion quadratic.
    pending_bytes: usize,
    /// Chunks dropped because the pending budget was exhausted.
    evicted_chunks: u64,
    /// Chunks dropped because their epoch predates this node's membership.
    ///
    /// Not a fault: it is forward secrecy, and it is the ordinary experience of
    /// a member admitted after content already existed. It is counted because
    /// each one costs a repair request, so a value that keeps climbing after
    /// the group has settled means repairs are not landing.
    unreadable_chunks: u64,
    /// Chunks whose key was derived and whose authentication then failed.
    ///
    /// Distinct from [`Self::unreadable_chunks`] because the cause is
    /// different in kind: this is a corrupted or tampered ciphertext from a
    /// peer allowed to write, not an ordering or membership condition. It
    /// should be zero in any honest run.
    corrupt_chunks: u64,
    /// Repair requests this node answered.
    ///
    /// Most of them mint a fresh epoch, which is a tree operation the whole group
    /// pays for — which is exactly why it is counted: repair must stay
    /// proportional to the number of peers that are actually stuck, not to how
    /// often anti-entropy runs. [`RepairTarget::DocumentHistory`] is the one that
    /// does not, and it is counted with the rest anyway: it still costs a full
    /// re-encryption and a blob, and the number worth watching is "how much work
    /// are peers asking of us", not "how many epochs did we mint".
    repairs_answered: u64,
    /// The most recent chunk this node published or applied, per document.
    ///
    /// This is what makes each chunk's key causally bound rather than bound to
    /// nothing: beekem mixes the predecessor refs into the derived application
    /// secret, so a chunk names the state it follows. The receiver does not
    /// need the predecessor chunk to decrypt — the digest travels inside the
    /// ciphertext's metadata — so this costs nothing in liveness.
    last_ref: HashMap<DocumentUuid, ChunkRef>,
    /// The Loro version vector this node has already published, per document.
    ///
    /// Two things read it, and they are why it has to be *published* rather than
    /// merely *current*. An ordinary edit exports `ExportMode::updates` from here,
    /// so the chunk carries the edit rather than the document. And a resync
    /// compares it against the document's live version to decide whether there is
    /// anything to say at all — a quiescent workspace re-encrypting every document
    /// on every republish is pure cost, since `iroh-docs` reconciliation already
    /// re-delivers an entry to a peer that lacks it.
    ///
    /// Stored as encoded bytes rather than as a `VersionVector` because that is
    /// what the snapshot holds, and decoding once per publish is cheaper than
    /// keeping two representations honest.
    published_up_to: HashMap<DocumentUuid, Vec<u8>>,
    /// Delta publishes since this document last shipped its whole history.
    ///
    /// Drives [`FULL_PUBLISH_EVERY`]. Deliberately not persisted: a restart
    /// starting the count at zero publishes a full export sooner than strictly
    /// necessary, which is the safe direction to be wrong in.
    deltas_since_full: HashMap<DocumentUuid, u32>,
    /// This device's transport address, once the caller has announced one.
    ///
    /// Held here as well as in the manifest because the manifest cannot always
    /// accept it. `Manifest::set_device_endpoint` needs a device record to
    /// attach to, and a joiner's manifest is empty until its first sync — so
    /// the announcement is remembered and re-applied every time a manifest
    /// arrives. Without that a joiner never appears on any peer's roster, and
    /// admission control would lock it out of the workspace it just joined.
    endpoint_id: Option<[u8; 32]>,
    /// Which generation of the replicated index this node is syncing.
    ///
    /// Held here rather than in the manifest on purpose. The manifest is a CRDT
    /// whose conflict resolution is Loro's internal ordering, which is a fact
    /// about operation ids rather than about the values — so two concurrent
    /// rotations would converge on an arbitrary winner rather than on the one
    /// every node can compute for itself. Comparing `(epoch, digest)` is a pure
    /// function of the values, so it converges without depending on how the
    /// updates happened to be ordered.
    namespace: NamespaceEpoch,
    /// Quorum proposals this node has already performed.
    ///
    /// Local dedup, so an executable proposal is not re-run on every certificate
    /// arrival. Deliberately *not* persisted: re-running after a restart is
    /// idempotent, and a stored copy would be one more thing that could disagree
    /// with the certificates it summarises.
    executed_here: HashSet<[u8; 32]>,
    /// The capability for [`Self::namespace`], kept so it can be re-announced.
    ///
    /// A rotation is published once and has nothing behind it, so a peer that
    /// missed the announcement can only be served by somebody re-encrypting the
    /// capability they already hold. Empty on the founding namespace, which was
    /// never announced to anybody.
    namespace_ticket: Vec<u8>,
}

impl Clone for WorkspaceState {
    /// Deep-clone, including the CRDT documents.
    ///
    /// This is written by hand rather than derived because `LoroDoc`'s own
    /// `Clone` returns another handle onto the *same* document. A derived clone
    /// would therefore alias: a simulator taking a world snapshot would hold a
    /// view that keeps mutating underneath it, and any property evaluated
    /// against that snapshot would be reading live state. Round-tripping
    /// through a snapshot gives a genuinely independent copy.
    fn clone(&self) -> Self {
        // Shares its mechanism with [`Self::export`] and differs only in error
        // policy, which is forced: `Clone` cannot fail, so a document whose
        // export errors becomes an empty copy here where `export` refuses. That
        // is tolerable for a clone — the simulator's world snapshot loses one
        // document's text — and would not be for a snapshot, where it would
        // silently discard content the node is responsible for.
        let docs = self
            .docs
            .iter()
            .map(|(uuid, doc)| {
                let copy = snapshot_doc(doc)
                    .and_then(|bytes| restore_doc(&bytes))
                    .unwrap_or_else(|_| new_doc());
                (*uuid, copy)
            })
            .collect();

        let manifest = Manifest::new();
        if let Ok(bytes) = self.manifest.export_snapshot() {
            let _ = manifest.import(&bytes);
        }

        Self {
            cgka: self.cgka.clone(),
            secret: self.secret.clone(),
            manifest,
            docs,
            pending_chunks: self.pending_chunks.clone(),
            pending_bytes: self.pending_bytes,
            evicted_chunks: self.evicted_chunks,
            unreadable_chunks: self.unreadable_chunks,
            corrupt_chunks: self.corrupt_chunks,
            repairs_answered: self.repairs_answered,
            last_ref: self.last_ref.clone(),
            published_up_to: self.published_up_to.clone(),
            deltas_since_full: self.deltas_since_full.clone(),
            endpoint_id: self.endpoint_id,
            namespace: self.namespace,
            namespace_ticket: self.namespace_ticket.clone(),
            executed_here: self.executed_here.clone(),
        }
    }
}

impl std::fmt::Debug for WorkspaceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceState")
            .field("member", &self.cgka.member_id())
            .field("group_size", &self.cgka.group_size())
            .field("docs", &self.docs.len())
            .field("pending_chunks", &self.pending_chunks.len())
            .finish_non_exhaustive()
    }
}

impl WorkspaceState {
    /// Build a node's state around an already-initialised CGKA controller.
    ///
    /// The manifest starts empty, which for a joiner is correct — theirs
    /// arrives by sync. A *founder* must use [`Self::found`] instead, or the
    /// workspace begins with no admin and can never gain one.
    ///
    /// `namespace_epoch` is the generation the joiner's replica capability
    /// belongs to, which the admitter knows and the joiner does not. Starting a
    /// joiner at [`NamespaceEpoch::INITIAL`] instead is not merely imprecise: a
    /// peer that is itself behind re-announces its own generation on the
    /// ordinary [`Event::ResyncNamespace`] schedule, and that announcement is
    /// encrypted under the *current* group key, so a joiner admitted at
    /// generation 3 can decrypt an announcement of generation 1 and — comparing
    /// it against `INITIAL` — adopt it. It would then leave the namespace the
    /// group is actually using for one it has abandoned, and stay there until
    /// the next rotation. Seeding the generation is what makes the
    /// "an announcement no newer than what we hold is dropped" test mean what it
    /// says from the joiner's first message onwards.
    ///
    /// The digest stays all-zero rather than being derived from the joiner's own
    /// ticket, because the joiner is handed the *role-appropriate half* of the
    /// capability and cannot reproduce the digest the rest of the group computed
    /// over the whole of it. All-zero is the smallest digest, so a re-announcement
    /// of the generation the joiner is already on is adopted a second time —
    /// a redundant re-import, never a move backwards.
    #[must_use]
    pub fn joined(cgka: CgkaController, secret: WorkspaceSecret, namespace_epoch: u32) -> Self {
        Self {
            cgka,
            secret,
            manifest: Manifest::new(),
            docs: HashMap::new(),
            pending_chunks: VecDeque::new(),
            pending_bytes: 0,
            evicted_chunks: 0,
            unreadable_chunks: 0,
            corrupt_chunks: 0,
            repairs_answered: 0,
            last_ref: HashMap::new(),
            published_up_to: HashMap::new(),
            deltas_since_full: HashMap::new(),
            endpoint_id: None,
            namespace: NamespaceEpoch {
                epoch: namespace_epoch,
                ..NamespaceEpoch::INITIAL
            },
            namespace_ticket: Vec::new(),
            executed_here: HashSet::new(),
        }
    }

    /// Build the founding node's state, recording it as the first admin.
    ///
    /// Distinct from [`Self::joined`] because the two cases genuinely differ and
    /// getting it wrong is silent: a joiner that granted itself `Admin` would
    /// concurrently edit the roles map with the real admin's copy, and Loro
    /// would faithfully converge on a workspace with an administrator nobody
    /// appointed.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the initial role cannot be recorded.
    pub fn found(
        cgka: CgkaController,
        secret: WorkspaceSecret,
        threshold: u32,
    ) -> Result<Self, CoreError> {
        // Generation zero by definition: the founder *is* the first namespace,
        // so there is no earlier one it could be told about.
        let mut this = Self::joined(cgka, secret, NamespaceEpoch::INITIAL.epoch);
        // The founder is their own user, and this device is that user's first —
        // which makes the user id and the member id the same bytes here, and
        // only here.
        let me = this.member_id().to_bytes();
        this.manifest.set_user(&me, "")?;
        this.manifest.set_device(&me, "first device")?;
        // Both certificates are self-signed, and both verify, because the store
        // is rooted at this key: `tree_id` *is* the founder's verifying key, so
        // "the founder says so" is the axiom rather than a claim needing support.
        //
        // Minted explicitly even though `CapabilityStore::new` already seeds the
        // founder as an admin, because the seed is local and these are what
        // travel. A joiner reconstructs the closure from certificates alone, and
        // one that never received the founder's own pair would hold a store whose
        // root granted nothing.
        this.cgka.certify_device(me, me, [0u8; 16])?;
        this.cgka.certify_role(me, Role::Admin, [0u8; 16])?;
        // Minted here and nowhere else. The threshold is a constant of the
        // workspace precisely so that no member can ever be behind on it: this
        // certificate ships in the same bundle as the grant above, without which
        // nobody could have joined at all. See `Policy` for why a mutable
        // threshold cannot be enforced by a receiver without splitting the group.
        this.cgka.certify_policy(threshold, [0u8; 16])?;
        Ok(this)
    }

    /// Capture this node's entire resumable state.
    ///
    /// See the [snapshot module documentation](crate::snapshot) for what is left
    /// out and why, and for the warning that this value *is* the read capability.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the manifest or any document cannot be
    /// exported. Unlike `Clone`, which cannot fail and so substitutes an empty
    /// document, this refuses — a snapshot that silently dropped a document
    /// would lose content on the next restart with nothing to indicate it.
    pub fn snapshot(&self) -> Result<WorkspaceSnapshot, CoreError> {
        // Both maps are iterated in sorted order rather than hash order, so that
        // identical state encodes to identical bytes. That is what lets a test
        // compare two snapshots directly, and what stops a storage backend from
        // rewriting an unchanged file every time it is asked to save.
        let mut docs: Vec<(DocumentUuid, Vec<u8>)> = self
            .docs
            .iter()
            .map(|(uuid, doc)| snapshot_doc(doc).map(|bytes| (*uuid, bytes)))
            .collect::<Result<_, _>>()?;
        docs.sort_unstable_by_key(|(uuid, _)| *uuid);

        let mut last_ref: Vec<(DocumentUuid, ChunkRef)> =
            self.last_ref.iter().map(|(k, v)| (*k, *v)).collect();
        last_ref.sort_unstable_by_key(|(uuid, _)| *uuid);

        let mut published_up_to: Vec<(DocumentUuid, Vec<u8>)> = self
            .published_up_to
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        published_up_to.sort_unstable_by_key(|(uuid, _)| *uuid);

        Ok(WorkspaceSnapshot {
            version: SNAPSHOT_VERSION,
            cgka: self.cgka.snapshot(),
            secret: self.secret.to_bytes(),
            manifest: self.manifest.export_snapshot()?,
            docs,
            last_ref,
            endpoint_id: self.endpoint_id,
            namespace: self.namespace,
            namespace_ticket: self.namespace_ticket.clone(),
            published_up_to,
        })
    }

    /// Encode [`Self::snapshot`] for storage.
    ///
    /// The result is wrapped in [`Zeroizing`] because these bytes are the local
    /// signing key, the leaf secret, every cached PCS key and the blinding
    /// secret. Storing them is the caller's job and so is protecting them; this
    /// crate does no I/O.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the state cannot be captured, or
    /// [`CoreError::Serialization`] if it cannot be encoded.
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        Ok(Zeroizing::new(postcard::to_stdvec(&self.snapshot()?)?))
    }

    /// Resume from a snapshot, reconstructing every observable it recorded.
    ///
    /// Neither [`Self::found`] nor [`Self::joined`] is involved, and that is the
    /// point: `found` would mint a second set of founding certificates for a
    /// workspace that already has them, and `joined` would start the node at an
    /// empty manifest and a zero namespace generation. A restart is neither of
    /// those events.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::SnapshotVersion`] if the layout is from another
    /// build, [`CoreError::MalformedKey`] if a stored identity is not a valid
    /// verifying key, or [`CoreError::Manifest`] if a stored document cannot be
    /// read back.
    pub fn from_snapshot(snapshot: WorkspaceSnapshot) -> Result<Self, CoreError> {
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(CoreError::SnapshotVersion {
                found: snapshot.version,
                expected: SNAPSHOT_VERSION,
            });
        }

        let manifest = Manifest::new();
        manifest.import(&snapshot.manifest)?;

        let docs = snapshot
            .docs
            .into_iter()
            .map(|(uuid, bytes)| restore_doc(&bytes).map(|doc| (uuid, doc)))
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Self {
            cgka: CgkaController::from_snapshot(snapshot.cgka)?,
            secret: WorkspaceSecret::new(snapshot.secret),
            manifest,
            docs,
            // The parking areas start empty and the counters start at zero: both
            // queues refill from the ordinary log exchange and resync, and a
            // counter carried across a restart would describe a process that no
            // longer exists. `evicted_ops` is the exception and is restored,
            // because it counts a fault worth watching accumulate.
            pending_chunks: VecDeque::new(),
            pending_bytes: 0,
            evicted_chunks: 0,
            unreadable_chunks: 0,
            corrupt_chunks: 0,
            repairs_answered: 0,
            last_ref: snapshot.last_ref.into_iter().collect(),
            published_up_to: snapshot.published_up_to.into_iter().collect(),
            // Not carried across a restart, so the first publish per document
            // after one is a full export. See the field's own comment for why
            // that is the safe direction.
            deltas_since_full: HashMap::new(),
            endpoint_id: snapshot.endpoint_id,
            namespace: snapshot.namespace,
            namespace_ticket: snapshot.namespace_ticket,
            executed_here: HashSet::new(),
        })
    }

    /// Decode and resume from [`Self::export`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Serialization`] if the bytes are not a snapshot, and
    /// anything [`Self::from_snapshot`] returns.
    pub fn import(bytes: &[u8]) -> Result<Self, CoreError> {
        Self::from_snapshot(postcard::from_bytes(bytes)?)
    }

    /// This node's CGKA identity.
    #[must_use]
    pub fn member_id(&self) -> MemberId {
        self.cgka.member_id()
    }

    /// The tree this workspace is, which is also the root of its capability
    /// closure and the seed of its gossip topic.
    ///
    /// Needed by a storage backend to name what it is storing: a node may hold
    /// several workspaces and the snapshot itself does not say which one it is.
    #[must_use]
    pub fn tree_id(&self) -> TreeId {
        self.cgka.tree_id()
    }

    /// The blinding secret this workspace's storage keys are derived from.
    ///
    /// Exposed because a backend resuming from a snapshot has to rebuild its own
    /// copy, and the snapshot is the only place it survives. It is not a new
    /// disclosure: an [`Invite`] already carries the same 32 bytes to every
    /// admitted device, and [`Self::export`] carries them to disk.
    ///
    /// It does not rotate, so a member who ever held it can always recognise
    /// which blinded key belongs to a document UUID they knew — see the blinding
    /// module for why rotating it is not free.
    ///
    /// [`Invite`]: https://docs.rs/iroh-beekem
    #[must_use]
    pub fn workspace_secret(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// The workspace manifest: the directory index and display data.
    ///
    /// Deliberately holds no authority. Roles and device bindings live in
    /// [`Self::capabilities`]; see the [manifest module documentation](crate::manifest)
    /// for why a CRDT cannot hold either.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Who is permitted to do what, rooted at the founder's key.
    ///
    /// This is the authority. Every role question — may this member administer,
    /// may it write, which user does this leaf act for — is answered here, and
    /// the answer is a pure function of a set of signed certificates rather than
    /// of replicated mutable state.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilityStore {
        self.cgka.capabilities()
    }

    /// Every device the workspace knows of, display data joined to its binding.
    ///
    /// Only *certified* devices appear: a leaf with no admitted binding speaks
    /// for nobody, so it has no user to report and no role to inherit. That
    /// filter is what makes a leaf spliced in by a revenant inert rather than
    /// merely unwelcome.
    #[must_use]
    pub fn devices(&self) -> Vec<DeviceRecord> {
        self.capabilities()
            .certified_devices()
            .filter_map(|member| {
                let user = self.capabilities().user_of(&member)?;
                let display = self.manifest.device(&member);
                Some(DeviceRecord {
                    member,
                    user,
                    endpoint_id: display.as_ref().and_then(|d| d.endpoint_id),
                    label: display.map(|d| d.label).unwrap_or_default(),
                })
            })
            .collect()
    }

    /// Direct access to the CGKA controller, bypassing every local role check.
    ///
    /// **This exists to model a malicious member, and nothing else.** The
    /// `require_*` checks in this type are a fail-fast local courtesy — a clear
    /// error instead of an operation every peer will drop — and an attacker
    /// simply does not run them. A scenario that drove an attack through
    /// [`Self::handle`] would be testing that courtesy rather than the receiver's
    /// enforcement, which is precisely the mistake that let authorization be
    /// issuer-side for four phases.
    ///
    /// Gated behind a feature so it cannot be reached by accident: an application
    /// that finds itself wanting this wants [`Self::handle`].
    #[cfg(feature = "adversarial-testing")]
    #[must_use]
    pub fn controller_mut(&mut self) -> &mut CgkaController {
        &mut self.cgka
    }

    /// Every certified device belonging to one user.
    #[must_use]
    pub fn devices_of(&self, user: &[u8; 32]) -> Vec<DeviceRecord> {
        self.devices()
            .into_iter()
            .filter(|device| device.user == *user)
            .collect()
    }

    /// Whether an entry signed by `author` should be accepted.
    ///
    /// Requires all three links, and the middle one is now the certificate rather
    /// than a map entry: a member must have claimed the author id (self-attested,
    /// in the manifest), a *signed binding* must attribute that member's device to
    /// a user, and a *signed grant* must give that user a role that can write. An
    /// unclaimed author, an uncertified device, or a viewer's device all fail.
    ///
    /// Still advisory in one specific sense — it constrains what a well-behaved
    /// peer accepts, not what a peer holding the namespace write capability can
    /// push into the replica — but no longer advisory in the sense that mattered:
    /// the role it consults cannot be rewritten by the member being checked.
    #[must_use]
    pub fn author_may_write(&self, author: &[u8; 32]) -> bool {
        self.manifest
            .member_for_author(author)
            .and_then(|member| self.capabilities().role_of_member(&member))
            .is_some_and(Role::can_write)
    }

    /// Which generation of the replicated index this node is syncing.
    ///
    /// A device removed at generation *n* never receives the capability for
    /// *n+1*, so comparing this against a peer's is how "still in the group" is
    /// observed from the outside — including by a property test, which is why
    /// it is public rather than internal.
    #[must_use]
    pub fn namespace(&self) -> NamespaceEpoch {
        self.namespace
    }

    /// How many identities this node currently counts as members.
    ///
    /// # Prefer this to [`Self::group_size`] for anything that must be right
    ///
    /// The two answer the same question from different sides and **they can
    /// disagree**. This one counts `CgkaController`'s own `current_members`,
    /// which is maintained by `merge` and `remove_member` in this crate.
    /// `group_size` asks beekem for `tree.member_count()`, and a node has been
    /// observed reporting four there while this reported three — with beekem
    /// itself then refusing to remove the missing member with
    /// `CgkaError::IdentifierNotFound`, so the removal had in fact happened.
    ///
    /// See [`Self::group_size`] for the reproduction and the standing caveat.
    #[must_use]
    pub fn current_member_count(&self) -> usize {
        self.cgka.current_members().count()
    }

    /// Whether this node still counts `member` as part of the group.
    #[must_use]
    pub fn sees_member(&self, member: MemberId) -> bool {
        self.cgka.is_current_member(member)
    }

    /// How many leaves beekem's tree reports.
    ///
    /// # This is not always [`Self::current_member_count`], and the difference
    /// has bitten
    ///
    /// Under concurrent removals of the same member — which a quorum action
    /// produces by construction, since every admin that sees the proposal reach
    /// its threshold performs it independently — a node has been observed with
    /// `group_size() == 4` while `current_members` held three and beekem's own
    /// `remove` answered `IdentifierNotFound` for the fourth. The removal had
    /// happened; only this counter disagreed.
    ///
    /// It is kept because it is the *tree's* view and some properties genuinely
    /// want that, but anything asserting "is this member still in the group"
    /// must use [`Self::sees_member`] or [`Self::current_member_count`]. A
    /// simulator property that used this one failed for seeds where nothing was
    /// wrong, which is how the divergence was found;
    /// `beekem_group_size_disagrees_with_current_members` in
    /// [`tests/beekem_loop.rs`](../../tests/beekem_loop.rs) pins the behaviour so
    /// a future beekem release changing it is noticed rather than assumed.
    #[must_use]
    pub fn group_size(&self) -> u32 {
        self.cgka.group_size()
    }

    /// The transport addresses this node should currently accept connections
    /// from: every device that is still a member and has published an address.
    ///
    /// Derived, never authored. Both halves converge on their own — membership
    /// through the CGKA operation log, addresses through the manifest — so the
    /// roster needs no distribution channel of its own and inherits the
    /// admin-gating that already guards `AddUser` and `AddDevice`.
    ///
    /// Computed here rather than in the transport layer so the eviction rule is
    /// testable without a socket, which is what the no-I/O rule buys.
    ///
    /// Two limits are inherent rather than incidental, and callers must not
    /// mistake this for more than it is:
    ///
    /// * **Eviction is eventual.** A removed device stays on the roster of any
    ///   peer that has not yet merged the `Remove`.
    /// * **This is an availability boundary, not a confidentiality one.** It
    ///   decides who may attempt to sync. What they can *read* is decided by
    ///   the CGKA, and nothing here retracts data already synced.
    ///
    /// Sorted, so that two nodes with the same membership produce byte-identical
    /// rosters and a property can compare them directly.
    #[must_use]
    pub fn roster(&self) -> Vec<[u8; 32]> {
        // Compared as bytes rather than by rebuilding a `MemberId` per device:
        // `MemberId` wraps a decompressed Ed25519 point, so parsing one costs a
        // point decompression that would be paid per device per recompute, and
        // a member id that fails to parse could never have entered the tree in
        // the first place. The manifest is remote input, so "unparseable" must
        // mean "not on the roster", not "propagate an error".
        let members: HashSet<[u8; 32]> =
            self.cgka.current_members().map(|m| m.to_bytes()).collect();
        let mut out: Vec<[u8; 32]> = self
            .manifest
            .devices()
            .into_iter()
            // Certified: a signed binding attributes this leaf to a user. This is
            // the clause that makes the phrase "derived, never authored" true —
            // without it the set derives from a map any member can write.
            .filter(|device| self.capabilities().is_certified_device(&device.member))
            // Still a member: the CGKA has not removed the leaf.
            .filter(|device| members.contains(&device.member))
            .filter_map(|device| device.endpoint_id)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Chunks parked awaiting keys or CRDT dependencies.
    ///
    /// A healthy system drains this to zero once the network settles; a
    /// property test should assert exactly that.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending_chunks.len()
    }

    /// Control-plane operations parked awaiting causal predecessors.
    #[must_use]
    pub fn parked_ops(&self) -> usize {
        self.cgka.parked_len()
    }

    /// Chunks discarded because the pending budget was exhausted.
    ///
    /// Should be zero in any healthy run. Unlike an evicted control operation,
    /// an evicted chunk does not come back on the next neighbour exchange — it
    /// waits for a resync — so a non-zero value here means content is
    /// temporarily unreadable on this node.
    #[must_use]
    pub fn evicted_chunks(&self) -> u64 {
        self.evicted_chunks
    }

    /// Control-plane operations discarded because the parking area was full.
    #[must_use]
    pub fn evicted_ops(&self) -> u64 {
        self.cgka.evicted_ops()
    }

    /// Chunks dropped because this node can never derive their epoch key.
    ///
    /// Expected to be non-zero for any member admitted after content already
    /// existed — that is forward secrecy. Each one raises
    /// [`Effect::RequestRepair`], so what matters is that it stops climbing
    /// once the repair lands, not that it stays at zero.
    #[must_use]
    pub fn unreadable_chunks(&self) -> u64 {
        self.unreadable_chunks
    }

    /// Chunks whose key was derived and whose authentication then failed.
    ///
    /// Zero in any honest run; a non-zero value means a peer that may write is
    /// producing ciphertext this node cannot authenticate.
    #[must_use]
    pub fn corrupt_chunks(&self) -> u64 {
        self.corrupt_chunks
    }

    /// Repair requests answered by minting a fresh epoch.
    ///
    /// One tree operation each, paid for by the whole group, so this is the
    /// number to watch: it should track admissions and lost operations, not
    /// anti-entropy rounds.
    #[must_use]
    pub fn repairs_answered(&self) -> u64 {
        self.repairs_answered
    }

    /// The current text of a document, or the empty string if unknown.
    #[must_use]
    pub fn document_text(&self, doc: DocumentUuid) -> String {
        self.docs
            .get(&doc)
            .map_or_else(String::new, |d| d.get_text("content").to_string())
    }

    /// Which documents are holding chunks that could not be applied yet.
    ///
    /// A backend needs this because *delivered* and *applied* are different
    /// facts, and a transport that caches what it has delivered will otherwise
    /// stop re-offering a chunk that never applied. That matters here in a way it
    /// does not for a chunk awaiting key material: the control plane pushes key
    /// material on its own, but a chunk awaiting *dependencies* is only ever
    /// rescued by the [`RepairTarget::DocumentHistory`] request that
    /// [`Self::handle`] raises after enough retries — and a retry only happens
    /// when something re-offers the chunk. Cache it as seen and the retries never
    /// come, so neither does the repair, and the edit is missing on that peer for
    /// good.
    ///
    /// Deduplicated, and in arbitrary order: this answers "which documents should
    /// be re-offered", not "how much is stuck".
    #[must_use]
    pub fn pending_docs(&self) -> Vec<DocumentUuid> {
        let mut docs: Vec<DocumentUuid> = self
            .pending_chunks
            .iter()
            .map(|parked| parked.doc)
            .collect();
        docs.sort_unstable();
        docs.dedup();
        docs
    }

    /// Everything this replica knows about how a document reached its current
    /// state, oldest change first.
    ///
    /// Empty for a document this node does not hold, which is the same answer
    /// [`Self::document_text`] gives and for the same reason: not holding a
    /// document is an ordinary condition on a peer that has not synced it, not a
    /// fault to report.
    ///
    /// The list is this *replica's* history and not the group's. A member admitted
    /// yesterday sees everything a full export carried to it, which in practice is
    /// the whole history — see [`Extent::Full`] — but a peer that has only ever
    /// received deltas sees from where it joined. Two members may therefore list
    /// different lengths and neither is wrong.
    #[must_use]
    pub fn document_versions(&self, doc: DocumentUuid) -> Vec<VersionInfo> {
        let Some(loro) = self.docs.get(&doc) else {
            return Vec::new();
        };
        let authors = Self::claimed_authors(loro);

        let heads = loro.oplog_frontiers().to_vec();
        let mut changes: Vec<loro::ChangeMeta> = Vec::new();
        // Walking back from the heads visits every change that is an ancestor of
        // the current state, which is the whole graph — a change with no
        // descendant *is* a head. An error here means a head named an id the
        // oplog does not hold, which is not something a caller can act on, so the
        // walk keeps whatever it collected.
        let _ = loro.travel_change_ancestors(&heads, &mut |meta| {
            changes.push(meta);
            std::ops::ControlFlow::Continue(())
        });
        // `ChangeMeta`'s own order: by the lamport of the change's *end*, then by
        // peer. Causal order where there is one, and a stable tie-break where
        // there is not — two concurrent changes have no true order, and inventing
        // one that varied between replicas would make two members disagree about
        // what their shared history looks like.
        changes.sort_unstable();

        changes
            .into_iter()
            .map(|meta| {
                // A change spans `len` operations from its first id, so the state
                // *after* it is named by the last of them.
                // Saturating, so a document with an implausibly long history
                // names its last operation rather than wrapping into a counter
                // that belongs to somebody else's change.
                let span = i32::try_from(meta.len).unwrap_or(i32::MAX);
                let last = loro::ID::new(
                    meta.id.peer,
                    meta.id.counter.saturating_add(span).saturating_sub(1),
                );
                VersionInfo {
                    id: VersionId::from_frontiers(&Frontiers::from_id(last)),
                    author: authors.get(&meta.id.peer).copied(),
                    at: UnixSeconds::new(meta.timestamp),
                    ops: meta.len,
                }
            })
            .collect()
    }

    /// The state this replica's copy of a document is in right now.
    ///
    /// `None` for a document this node does not hold. What a checkpoint records,
    /// and what a caller compares against to ask whether a version is current.
    #[must_use]
    pub fn document_version(&self, doc: DocumentUuid) -> Option<VersionId> {
        self.docs
            .get(&doc)
            .map(|loro| VersionId::from_frontiers(&loro.oplog_frontiers()))
    }

    /// A document's text as it stood at `version`.
    ///
    /// Reads through a fork rather than by checking the live document out. The
    /// difference is not stylistic: a checkout *detaches* the replica the data
    /// plane is concurrently importing chunks into, and a detached replica that
    /// takes an import is a defect that will not reproduce on demand. A fork is a
    /// separate document that is dropped when this returns.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::UnknownDocument`] if this node holds no such document,
    /// and [`CoreError::UnknownVersion`] if the id is malformed or names a state
    /// this replica has not merged.
    pub fn document_text_at(
        &self,
        doc: DocumentUuid,
        version: &VersionId,
    ) -> Result<String, CoreError> {
        let loro = self.docs.get(&doc).ok_or(CoreError::UnknownDocument)?;
        let frontiers = version.to_frontiers()?;
        let at = loro
            .fork_at(&frontiers)
            .map_err(|_| CoreError::UnknownVersion {
                version: version.to_string(),
            })?;
        Ok(at.get_text("content").to_string())
    }

    /// The peer-id-to-member claims recorded inside one document.
    ///
    /// See [`claim_authorship`] for what these are and why they are claims. A
    /// record that is not a pair of hex keys is skipped rather than reported: the
    /// container is writable by any member, so a bad entry means somebody wrote
    /// nonsense, and the answer to that is an unattributed change rather than a
    /// failed listing.
    fn claimed_authors(loro: &LoroDoc) -> HashMap<u64, [u8; 32]> {
        let mut out = HashMap::new();
        loro.get_map(DOC_AUTHORS_CONTAINER).for_each(|key, value| {
            let peer = unhex_u64(key);
            let member = value
                .into_value()
                .ok()
                .and_then(|v| v.into_string().ok())
                .and_then(|s| unhex_member(&s));
            if let (Some(peer), Some(member)) = (peer, member) {
                out.insert(peer, member);
            } else {
                // Not a claim this replica can use; see above.
            }
        });
        out
    }

    /// The complete CGKA operation log, for inviting a new member.
    ///
    /// # Errors
    ///
    /// Propagates [`CoreError::Cgka`] if the operation graph cannot be sorted.
    pub fn op_log(&self) -> Result<Vec<Signed<CgkaOperation>>, CoreError> {
        self.cgka.op_log()
    }

    /// Handle one event, returning the effects the caller must perform.
    ///
    /// `now` is the wall-clock instant the caller is acting at, and it is a
    /// parameter rather than something read here because this crate has no clock:
    /// the simulator drives the same state machine with virtual time, and a
    /// version history dated from `SystemTime::now` would be unreproducible under
    /// a seed. It reaches Loro as the timestamp on the change a content edit
    /// commits, and the manifest as the date on a checkpoint. Events that write
    /// no history ignore it.
    ///
    /// # Errors
    ///
    /// Propagates CGKA, AEAD and CRDT failures. Note that an out-of-order
    /// arrival is *not* an error: it parks silently and is retried later.
    pub fn handle<R: CryptoRng + RngCore>(
        &mut self,
        event: Event,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        match event {
            Event::ControlOp(op) => self.on_control_op(op),
            Event::CertsArrived(certs) => self.on_certs_arrived(certs),
            Event::ChunkArrived { doc, chunk } => self.on_chunk_arrived(doc, *chunk),
            Event::LocalEdit { doc, text } => self.on_append(doc, &text, csprng, now),
            Event::WriteFile { doc, text } => self.on_write(doc, &text, csprng, now),
            Event::InsertText { doc, pos, text } => self.on_insert(doc, pos, &text, csprng, now),
            Event::RemoveText { doc, pos, len } => self.on_delete(doc, pos, len, csprng, now),
            Event::RevertDocument { doc, to } => self.on_revert(doc, &to, csprng, now),
            Event::DeleteFile { doc } => self.on_delete_file(doc, csprng),
            Event::Resync { doc } => self.on_resync(doc, csprng),
            Event::AddUser {
                member,
                share_key,
                role,
                display_name,
                endpoint,
            } => {
                self.require_admin()?;
                self.on_add_user(member, share_key, role, &display_name, endpoint, csprng)
            }
            Event::AddDevice {
                member,
                share_key,
                user,
                label,
                endpoint,
            } => {
                self.require_may_add_device_to(&user)?;
                self.on_add_device(member, share_key, &user, &label, endpoint, csprng)
            }
            Event::RemoveMember { member } => self.on_remove_member(member),
            Event::Leave => self.on_leave(),
            Event::Propose { action, expires } => self.on_propose(action, expires, csprng),
            Event::Approve { proposal } => self.on_approve(proposal, csprng),
            // Unconditional rather than diffed against what peers might hold:
            // there is nothing to diff against, since a broadcast has no
            // recipient list. Receivers absorb it idempotently and
            // `on_certs_arrived` returns early when nothing was new.
            Event::ResyncCertificates => Ok(vec![Effect::BroadcastCerts(
                self.capabilities().certificates(),
            )]),
            Event::Rotate => {
                let op = self.cgka.rotate(csprng)?;
                Ok(vec![Effect::broadcast(op)])
            }
            Event::ManifestArrived { chunk } => self.on_manifest_arrived(&chunk, csprng),
            Event::UpsertFile { entry } => {
                self.require_write()?;
                self.manifest.upsert_file(&entry)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::RenameFile { doc, path } => {
                self.require_write()?;
                self.manifest.rename(doc, &path)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::SetRole { user, role } => self.on_set_role(&user, role, csprng),
            Event::SetInfo { info } => {
                self.require_admin()?;
                self.manifest.set_info(&info)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::SetDisplayName { display_name } => {
                let me = self.cgka.member_id().to_bytes();
                let user = self
                    .capabilities()
                    .user_of(&me)
                    .ok_or(CoreError::UnknownDevice)?;
                self.manifest.set_user(&user, &display_name)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::AnnounceAuthor { author } => {
                self.manifest
                    .set_author(&self.cgka.member_id().to_bytes(), &author)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::ResyncManifest => self.publish_manifest(Keying::Current, csprng),
            Event::ResyncNamespace => self.republish_namespace(Keying::Current, csprng),
            Event::NamespaceMinted { epoch, ticket } => {
                self.on_namespace_minted(epoch, &ticket, csprng)
            }
            Event::NamespaceArrived { epoch, chunk } => self.on_namespace_arrived(epoch, &chunk),
            Event::RepairRequested {
                requester,
                target,
                epoch: _,
            } => self.on_repair_requested(requester, target, csprng),
            Event::AnnounceEndpoint { endpoint_id } => {
                self.endpoint_id = Some(endpoint_id);
                // The manifest may have nowhere to put it yet — a joiner has no
                // device record until its first sync. Remembering it above is
                // what makes that recoverable; `record_endpoint` reports
                // whether the write landed so we only publish when it did.
                if self.record_endpoint()? {
                    self.publish_manifest(Keying::Current, csprng)
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    /// Write the announced endpoint id into the manifest if it will fit.
    ///
    /// Returns whether the manifest changed, so callers can avoid re-publishing
    /// it for nothing — this runs on every manifest arrival, and an
    /// unconditional publish would turn each arrival into an outgoing write and
    /// two peers into a broadcast loop.
    ///
    /// `UnknownDevice` is not an error here: it is the ordinary state of a
    /// joiner between announcing and first sync, and the next arrival retries.
    fn record_endpoint(&mut self) -> Result<bool, CoreError> {
        let Some(endpoint_id) = self.endpoint_id else {
            return Ok(false);
        };
        let me = self.cgka.member_id().to_bytes();
        // Already correct — most arrivals land here, since the record persists.
        if self.manifest.device(&me).and_then(|d| d.endpoint_id) == Some(endpoint_id) {
            return Ok(false);
        }
        match self.manifest.set_device_endpoint(&me, &endpoint_id) {
            Ok(()) => Ok(true),
            Err(CoreError::UnknownDevice) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Refuse an administrative action unless the local member is an admin.
    ///
    /// This is the *permissions* layer, not the cryptographic one, and it binds
    /// only well-behaved peers: a member holding a leaf can still decrypt
    /// whatever the manifest says. Genuine read revocation is a CGKA removal.
    fn require_admin(&self) -> Result<(), CoreError> {
        let me = self.cgka.member_id().to_bytes();
        if self.capabilities().may_administer(&me) {
            return Ok(());
        }
        Err(CoreError::NotAnAdmin)
    }

    /// Refuse an administrative action that has not been authorised by a quorum.
    ///
    /// Replaces the bare [`Self::require_admin`] on the actions a threshold
    /// governs, and degenerates to exactly it at [`DEFAULT_THRESHOLD`] — so a
    /// workspace that never raises the threshold behaves as it always did, and
    /// the whole of this machinery costs it one comparison.
    ///
    /// # Which actions this governs, and which it does not
    ///
    /// Only what [`AdminAction`] can express: removals, role changes, and the
    /// threshold itself. `AddUser` and `AddDevice` stay single-admin because
    /// their enrolment data — a leaf key, an endpoint — cannot travel in a
    /// certificate, so no replica could perform them from a proposal alone. The
    /// asymmetry is defensible rather than merely convenient: admitting somebody
    /// is undone by removing them, and removing is the side a quorum protects.
    ///
    /// # Still local, still advisory
    ///
    /// Like `require_admin` before it, this constrains what a well-behaved node
    /// *emits*. What constrains a malicious one is the receiver-side check in
    /// `CgkaController::merge` — and, for the quorum specifically, the fact that
    /// every replica computes `is_executable` for itself from the same
    /// certificates. A node that skipped this check would put an operation on
    /// the wire that its peers merge, so the guarantee here is weaker than the
    /// role checks it sits beside; see the module notes on the standing plan to
    /// carry a quorum proof in the operation bundle.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotAnAdmin`] if the local device cannot administer
    /// at all, and [`CoreError::QuorumRequired`] if it can but no matching
    /// proposal has reached the threshold.
    fn require_quorum(&self, action: &AdminAction) -> Result<(), CoreError> {
        self.require_admin()?;
        let required = self.capabilities().threshold();
        if required <= DEFAULT_THRESHOLD {
            return Ok(());
        }
        let authorised = self
            .capabilities()
            .executable()
            .iter()
            .any(|(_, executed)| executed == action);
        if authorised {
            Ok(())
        } else {
            Err(CoreError::QuorumRequired {
                required,
                held: self.matching_approvals(action),
            })
        }
    }

    /// The best approval count any proposal for this exact action has reached.
    ///
    /// Reported in the error so a caller can tell "nobody has proposed this"
    /// from "two of the three approvals are in", which are different situations
    /// with different remedies.
    fn matching_approvals(&self, action: &AdminAction) -> u32 {
        self.capabilities()
            .proposals()
            .iter()
            .filter(|status| status.action == *action)
            .map(|status| u32::try_from(status.approvals).unwrap_or(u32::MAX))
            .max()
            .unwrap_or(0)
    }

    /// Mint and broadcast a proposal.
    ///
    /// Proposing is itself an administrative act — a member with no role has no
    /// business filling the group's proposal list — but it is *not* a quorum
    /// action, or proposing would need a proposal and nothing could ever start.
    fn on_propose<R: CryptoRng + RngCore>(
        &mut self,
        action: AdminAction,
        expires: Option<u64>,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_admin()?;
        let seq = self.capabilities().next_proposal_seq();
        let cert = self
            .cgka
            .certify_proposal(action, seq, expires, random_nonce(csprng))?;
        Ok(vec![Effect::BroadcastCerts(vec![cert])])
    }

    /// Mint and broadcast an approval, then perform anything it just carried.
    ///
    /// The second half is what makes a quorum happen without coordination: the
    /// approver that tips a proposal over the threshold executes it immediately,
    /// and so does every peer the moment the certificate reaches them. Duplicate
    /// removals merge as `MergeOutcome::Duplicate`, which is the same property
    /// the revenant eviction path already depends on.
    fn on_approve<R: CryptoRng + RngCore>(
        &mut self,
        proposal: [u8; 32],
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_admin()?;
        let cert = self.cgka.certify_approval(proposal, random_nonce(csprng))?;
        let mut effects = vec![Effect::BroadcastCerts(vec![cert])];
        effects.extend(self.run_quorum_actions());
        Ok(effects)
    }

    /// Whether this device speaks for the founding user.
    ///
    /// The founder is the axiom of the capability closure — `tree_id` *is* its
    /// key — so this is a fact every peer already agrees on, not a role anybody
    /// granted. It is consulted only where a bootstrap needs it; see
    /// [`Self::on_set_role`].
    fn is_founder_device(&self) -> bool {
        let me = self.member_id().to_bytes();
        self.capabilities().user_of(&me) == Some(self.capabilities().founder())
    }

    /// The certificates a receiver needs to verify this action's quorum.
    ///
    /// Empty at a threshold of one, where no quorum is required and the bundle
    /// would be dead weight on every removal.
    fn quorum_proof(&self, action: &AdminAction) -> Vec<Certificate> {
        if self.capabilities().threshold() <= DEFAULT_THRESHOLD {
            return Vec::new();
        }
        self.capabilities().proof_of(action)
    }

    /// Perform every proposal that has reached quorum and has not run here yet.
    ///
    /// Deterministic given the certificate set, so every replica reaches the
    /// same list independently. `executed_here` is local dedup only: it is not
    /// persisted, because re-running an action after a restart is harmless —
    /// `remove_member` returns `None` for somebody already gone and a repeated
    /// grant is superseded by `seq` — and persisting it would be one more thing
    /// that could disagree with the certificates.
    fn run_quorum_actions(&mut self) -> Vec<Effect> {
        let pending: Vec<([u8; 32], AdminAction)> = self
            .capabilities()
            .executable()
            .into_iter()
            .filter(|(digest, _)| !self.executed_here.contains(digest))
            .collect();

        let mut effects = Vec::new();
        for (digest, action) in pending {
            match action {
                AdminAction::RemoveMember { member } => {
                    let Ok(member) = member_from_bytes(member) else {
                        // Thirty-two bytes that are not a verifying key. No
                        // amount of catching up turns them into one, so this is
                        // final and marking it costs nothing.
                        self.executed_here.insert(digest);
                        continue;
                    };
                    // **Marked done only on success, and a failure is left to
                    // be retried.** The attempt runs against *this node's*
                    // CGKA, which may not yet hold the leaf the quorum voted to
                    // remove — certificates and operations travel on the same
                    // plane but not in lockstep — so `Cgka(IdentifierNotFound)`
                    // here means "not yet", not "never".
                    //
                    // Marking first, which is what this used to do, turned that
                    // transient failure into a permanent one: the digest was
                    // burned, every later pass skipped it, and the node kept a
                    // member the rest of the group had removed. Forever,
                    // silently, on a node that agreed the proposal was
                    // executable — the "performed there and refused everywhere"
                    // split the quorum design exists to prevent, reached from
                    // the other direction.
                    //
                    // Retrying is safe because a failed `perform_removal` has
                    // no partial effect: every fallible step runs before the
                    // namespace generation is bumped or any effect is built.
                    // And it is cheap — one closure walk per unexecuted
                    // proposal per certificate arrival — which is the right
                    // price for not diverging. A genuinely permanent refusal
                    // (the last admin) costs that walk forever, bounded by the
                    // number of proposals.
                    if let Ok(produced) = self.perform_removal(member) {
                        self.executed_here.insert(digest);
                        effects.extend(produced);
                    } else {
                        // Retried on the next pass. See above.
                    }
                }
                // Nothing to perform. An executed `SetRole` proposal *is* the
                // role — `CapabilityStore` reads it straight out of the closure
                // — and minting a grant on top would have every replica sign a
                // different certificate for one decision.
                AdminAction::SetRole { .. } => {
                    self.executed_here.insert(digest);
                }
            }
        }
        effects
    }

    /// Refuse to enrol a device for a user the local device may not act for.
    ///
    /// Adding a device to *your own* user is not an administrative act — it is
    /// enrolling your own phone — so it needs no role. Adding one to somebody
    /// else's user is, and must be refused, or any member could bind a device
    /// of theirs to an admin's user and inherit the role.
    ///
    /// As everywhere else in this layer, this binds well-behaved nodes only;
    /// the manifest is a CRDT that merges whatever a malicious peer writes. See
    /// the [manifest module documentation](crate::manifest) for what would
    /// close that properly.
    fn require_may_add_device_to(&self, user: &[u8; 32]) -> Result<(), CoreError> {
        let me = self.cgka.member_id().to_bytes();
        if self.capabilities().may_bind_device_to(&me, user) {
            return Ok(());
        }
        Err(CoreError::NotThisUsersDevice)
    }

    /// Merge an arriving manifest replica.
    ///
    /// There is no parking queue for the manifest, unlike for document chunks:
    /// it is re-published on every change and on every resync, so a copy that
    /// cannot be decrypted yet is replaced by one that can rather than needing
    /// to be held. Holding it would also mean a second unbounded queue.
    fn on_manifest_arrived<R: CryptoRng + RngCore>(
        &mut self,
        chunk: &Chunk,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let plaintext = match self.cgka.decrypt(chunk) {
            Ok(DecryptOutcome::Plaintext(plaintext)) => plaintext,
            // The control plane has not caught up. The next re-announcement,
            // or this same one after the missing operation lands, will read.
            Ok(DecryptOutcome::AwaitingOp) => return Ok(Vec::new()),
            // Published before this node joined, so no re-announcement under
            // that epoch will ever be readable. Ask for one under a live epoch:
            // without the manifest this node has no device records, so it
            // derives no roster and peers derive none containing it.
            Ok(DecryptOutcome::Unreachable) => {
                self.unreadable_chunks += 1;
                return Ok(vec![Effect::RequestRepair {
                    target: RepairTarget::Manifest,
                    epoch: EpochId::of(chunk),
                }]);
            }
            // Authenticated decryption failed under a key we *did* derive:
            // count it and move on, exactly as for a document chunk, rather
            // than letting one bad ciphertext abort the arrival pump.
            Err(_) => {
                self.corrupt_chunks += 1;
                return Ok(Vec::new());
            }
        };
        self.manifest.import(&plaintext)?;
        // The arriving replica may be the one that finally carries this
        // device's record, so retry the endpoint announcement that had nowhere
        // to go before. This is the only path by which a joiner ever reaches a
        // peer's roster.
        let mut effects = vec![Effect::ManifestUpdated];
        if self.record_endpoint()? {
            effects.extend(self.publish_manifest(Keying::Current, csprng)?);
        }
        Ok(effects)
    }

    /// Assign a role to a user.
    ///
    /// Demoting the last admin is refused rather than merely discouraged: a
    /// workspace with no administrator can never gain one, because granting a
    /// role is itself an administrative act.
    fn on_set_role<R: CryptoRng + RngCore>(
        &mut self,
        user: &[u8; 32],
        role: Role,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        // The founder may set a role alone whatever the threshold, and the
        // exemption is what makes a quorum reachable at all: a workspace founded
        // at a threshold of two has one admin, so without this no proposal could
        // ever collect two approvals and the group would be deadlocked from
        // birth. It is narrow on purpose — it covers *roles*, never removals —
        // and the founder is already the root of every chain here, so it grants
        // no authority that `tree_id` did not.
        if self.is_founder_device() {
            self.require_admin()?;
        } else {
            self.require_quorum(&AdminAction::SetRole { user: *user, role })?;
            if self.capabilities().threshold() > DEFAULT_THRESHOLD {
                // The executed proposal already *is* the role, on every replica,
                // so there is nothing left to mint. Returning early rather than
                // minting a redundant grant keeps one decision represented by
                // one certificate.
                return Ok(Vec::new());
            }
        }
        if role.can_administer() {
            // Promoting cannot leave the group without an admin.
        } else {
            self.require_not_last_admin(user)?;
        }
        // A grant supersedes every earlier grant for this subject by carrying a
        // higher `seq`; `certify_role` chooses it. Nothing is written to the
        // manifest — a role is a capability, not document metadata.
        let cert = self.cgka.certify_role(*user, role, random_nonce(csprng))?;
        // Broadcast on its own, because a role change mints no CGKA operation to
        // ride along with. Like a rotation it is announced once, so the log
        // exchange that ships the whole certificate store is what repairs a loss.
        Ok(vec![Effect::BroadcastCerts(vec![cert])])
    }

    /// Admit a new person along with their first device.
    ///
    /// Both certificates are minted here and both travel with the `Add`: without
    /// the binding, every peer refuses the `Add` itself, and without the grant the
    /// new member holds a certified leaf that may do nothing. The display record
    /// goes in the manifest, where it grants nothing.
    fn on_add_user<R: CryptoRng + RngCore>(
        &mut self,
        member: MemberId,
        share_key: ShareKey,
        role: Role,
        display_name: &str,
        endpoint: Option<[u8; 32]>,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        // A new user's id is their first device's member id; see the manifest
        // module documentation for why that identifier rather than a fresh one.
        let user = member.to_bytes();
        // Admitting somebody *assigns them a role*, so above a threshold of one
        // it is governed exactly as `SetRole` is: by the founder, or by a
        // quorum. Refused up front rather than allowed to half-succeed — without
        // this the `Add` would land and the grant would be inadmissible, leaving
        // a member in the tree whom nobody can attribute a role to and no error
        // anywhere saying why.
        if self.capabilities().threshold() > DEFAULT_THRESHOLD && !self.is_founder_device() {
            self.require_quorum(&AdminAction::SetRole { user, role })?;
        } else {
            // At a threshold of one, or as the founder, the ordinary admin check
            // inside `admit` is the whole of it.
        }
        let certs = vec![
            self.cgka
                .certify_device(member.to_bytes(), user, random_nonce(csprng))?,
            self.cgka.certify_role(user, role, random_nonce(csprng))?,
        ];
        self.admit(member, share_key, certs, csprng, |manifest, member| {
            manifest.set_user(member, display_name)?;
            manifest.set_device(member, "first device")?;
            // Strictly after `set_device`, which creates the record this
            // attaches to; reversed, it returns `UnknownDevice`.
            if let Some(endpoint) = endpoint {
                manifest.set_device_endpoint(member, &endpoint)?;
            }
            Ok(())
        })
    }

    /// Admit another device acting for an existing person.
    ///
    /// No role is granted here: the device inherits its user's, which is the
    /// whole reason roles are keyed by user rather than by leaf.
    fn on_add_device<R: CryptoRng + RngCore>(
        &mut self,
        member: MemberId,
        share_key: ShareKey,
        user: &[u8; 32],
        label: &str,
        endpoint: Option<[u8; 32]>,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let certs =
            vec![
                self.cgka
                    .certify_device(member.to_bytes(), *user, random_nonce(csprng))?,
            ];
        self.admit(member, share_key, certs, csprng, |manifest, member| {
            manifest.set_device(member, label)?;
            if let Some(endpoint) = endpoint {
                manifest.set_device_endpoint(member, &endpoint)?;
            }
            Ok(())
        })
    }

    /// Park an arriving chunk if it is new, then retry the whole queue.
    fn on_chunk_arrived(
        &mut self,
        doc: DocumentUuid,
        chunk: Chunk,
    ) -> Result<Vec<Effect>, CoreError> {
        // The data plane re-offers the same entry on every sync round, so
        // without this the parked list would grow without bound and every drain
        // would redo the same failed decryptions.
        let already_parked = self.pending_chunks.iter().any(|parked| {
            parked.doc == doc
                && parked.chunk.content_ref == chunk.content_ref
                && parked.chunk.pcs_key_hash == chunk.pcs_key_hash
        });
        if !already_parked {
            self.park_chunk(doc, chunk);
        }
        self.drain_pending()
    }

    /// Revoke one device's leaf.
    fn on_remove_member(&mut self, member: MemberId) -> Result<Vec<Effect>, CoreError> {
        self.require_quorum(&AdminAction::RemoveMember {
            member: member.to_bytes(),
        })?;
        self.perform_removal(member)
    }

    /// Retract one leaf, with the authorisation decision already made.
    ///
    /// Split from [`Self::on_remove_member`] so that a quorum execution and a
    /// direct call run *identical* code: a second copy of the removal-then-rotate
    /// ordering would be a second place to get it wrong, and getting it wrong is
    /// silent — the removed device simply follows the group.
    fn perform_removal(&mut self, member: MemberId) -> Result<Vec<Effect>, CoreError> {
        // Guard on the device's *user*: removing one of an admin's three
        // devices is fine, removing their last one is not, and the difference
        // is invisible if you look at the leaf alone. A device with no record
        // stands in for its own user, which is the pre-sync case.
        let owner = self
            .capabilities()
            .user_of(&member.to_bytes())
            .unwrap_or_else(|| member.to_bytes());
        if self.capabilities().devices_of(&owner).len() <= 1 {
            self.require_not_last_admin(&owner)?;
        }
        let op = self.cgka.remove_member(member)?;
        let Some(op) = op else {
            // Not a member, so nothing was revoked and nothing needs rotating.
            // Rotating anyway would let an admin churn the whole group's
            // namespace by repeatedly "removing" somebody who already left.
            return Ok(Vec::new());
        };

        // **Ordering is the security property.** The removal is broadcast
        // first; only then is a new namespace minted, and its capability is
        // encrypted after this leaf is out of the tree. Reversed, the removed
        // device could still derive the key protecting the announcement, read
        // the new capability, and follow the group into the very namespace the
        // rotation existed to keep it out of.
        self.namespace.epoch = self.namespace.epoch.saturating_add(1);
        // The proof travels with the operation, exactly as a `Grant` does for an
        // `Add`. A receiver checks the quorum before merging, so a removal that
        // arrived ahead of the certificates authorising it would be *refused,
        // not parked* — and no later certificate brings it back.
        let proof = self.quorum_proof(&AdminAction::RemoveMember {
            member: member.to_bytes(),
        });
        Ok(vec![
            Effect::BroadcastOp {
                op: Box::new(op),
                proof,
            },
            Effect::RotateNamespace {
                epoch: self.namespace.epoch,
            },
        ])
    }

    /// Append text to the end of a document.
    fn on_append<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        text: &str,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        self.on_text_edit(doc, csprng, now, |content| {
            let at = content.len_unicode();
            content.insert(at, text)
        })
    }

    /// Replace a document's whole contents.
    ///
    /// `update` diffs against the current contents rather than clearing and
    /// re-inserting, so replacing one word stays a one-word change in the CRDT —
    /// and merges with a concurrent edit elsewhere in the document instead of
    /// clobbering it.
    fn on_write<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        text: &str,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        self.on_text_edit(doc, csprng, now, |content| {
            content
                .update(text, loro::UpdateOptions::default())
                .map_err(|e| loro::LoroError::Unknown(e.to_string().into()))
        })
    }

    /// Insert text at a character offset.
    ///
    /// Positions are clamped rather than rejected: they come from a caller
    /// holding a view that a concurrent remote edit may already have shortened,
    /// which is ordinary in a CRDT rather than a fault.
    fn on_insert<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        pos: usize,
        text: &str,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        self.on_text_edit(doc, csprng, now, |content| {
            content.insert(pos.min(content.len_unicode()), text)
        })
    }

    /// Delete a run of characters, clamped as [`Self::on_insert`] is.
    fn on_delete<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        pos: usize,
        len: usize,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        self.on_text_edit(doc, csprng, now, |content| {
            let end = content.len_unicode();
            let at = pos.min(end);
            content.delete(at, len.min(end - at))
        })
    }

    /// Retract every leaf belonging to the local user.
    ///
    /// # Why this is not `on_remove_member` in a loop
    ///
    /// Three differences, and each one would be a defect if it went the other
    /// way.
    ///
    /// **No `require_admin`.** Leaving is not administration. `require_admin`
    /// would make a workspace's viewers unable to leave it, which is both
    /// absurd and unenforceable — `CgkaController::authorize` admits a same-user
    /// `Remove` from any member, so every peer would accept the operation the
    /// local guard had refused to emit.
    ///
    /// **No rotation.** `on_remove_member` mints a fresh namespace so the
    /// removed device cannot follow the group. A leaver doing that would encrypt
    /// the new capability under a group key it still holds and announce it to
    /// everyone — handing itself the replica it is leaving. Rotation after a
    /// departure is the *group's* job, and a departing member cannot be trusted
    /// to have done it.
    ///
    /// **Every device at once.** Leaving with one of three devices still in the
    /// tree is not leaving. The group is enumerated by user, so a partial
    /// departure would show the leaver as still present while it had lost the
    /// ability to act.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::LastAdmin`] if this user is the only administrator.
    /// A workspace that lost its last admin can never gain another — promotion
    /// is itself an admin action — so the departure has to be refused rather
    /// than allowed to strand everybody else.
    fn on_leave(&mut self) -> Result<Vec<Effect>, CoreError> {
        let me = self.member_id().to_bytes();
        let user = self.capabilities().user_of(&me).unwrap_or(me);
        self.require_not_last_admin(&user)?;

        // Sorted so that the operations a leaver broadcasts are a function of
        // its membership rather than of iteration order — two runs of the same
        // scenario must put the same bytes on the wire.
        let mut devices = self.capabilities().devices_of(&user);
        devices.sort_unstable();
        // A device with no binding stands in for itself, which is the case
        // before this user's certificates have synced anywhere.
        if devices.is_empty() {
            devices.push(me);
        } else {
            // Certified devices found; the binding is authoritative.
        }

        let mut effects = Vec::new();
        for device in devices {
            let Ok(member) = member_from_bytes(device) else {
                // A certificate carrying an off-curve device id cannot name a
                // leaf, so there is nothing to remove. Skipped rather than
                // fatal: one malformed record must not trap a user in a
                // workspace they are trying to leave.
                continue;
            };
            // `None` means the leaf is already gone — removed by an admin while
            // this departure was in flight, or listed twice by two certificates.
            if let Some(op) = self.cgka.remove_member(member)? {
                effects.push(Effect::broadcast(op));
            } else {
                // Already not a member; nothing to broadcast for this device.
            }
        }
        Ok(effects)
    }

    /// Encrypt a freshly minted namespace capability for the group.
    ///
    /// The counter was already advanced by the removal that asked for this, so
    /// a reply naming a different generation is stale — a second rotation
    /// overtook it — and is dropped rather than published. Publishing it would
    /// announce a namespace nobody is moving to.
    ///
    /// Uses [`CgkaController::encrypt_fresh`] rather than `encrypt`, and the
    /// difference matters: `encrypt` reuses the current epoch key whenever
    /// beekem has one, which a member admitted since the last publish cannot
    /// derive. That member would be unable to read the capability and would be
    /// stranded in the abandoned namespace — removed in effect, without anyone
    /// having removed them.
    fn on_namespace_minted<R: CryptoRng + RngCore>(
        &mut self,
        epoch: u32,
        ticket: &[u8],
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        if epoch != self.namespace.epoch {
            return Ok(Vec::new());
        }
        let minted = NamespaceEpoch::of(epoch, ticket);
        let (chunk, ops) = self.cgka.encrypt_fresh(ticket, &[], csprng)?;
        self.namespace = minted;
        self.namespace_ticket = ticket.to_vec();
        // The index this node had published into is the one it just abandoned.
        self.forget_published();

        // The key operations strictly first: they are what let the group derive
        // the key this chunk is under, and a peer receiving them the other way
        // round would fail to decrypt and never retry.
        let mut effects: Vec<Effect> = ops.into_iter().map(Effect::broadcast).collect();
        effects.push(Effect::PublishNamespace {
            epoch,
            chunk: Box::new(chunk),
        });
        // The minter moves onto its own namespace by the same effect every
        // other member uses, rather than by a second path in each backend.
        // Without this the admin who issued the removal would be the one member
        // still publishing into the namespace it just abandoned — and since it
        // is usually the only admin, the group would follow nobody.
        effects.push(Effect::AdoptNamespace {
            epoch,
            ticket: ticket.to_vec(),
        });
        Ok(effects)
    }

    /// Consider a rotation a peer announced.
    ///
    /// Adoption is a pure comparison of `(epoch, digest)`, so every node that
    /// can decrypt the announcement reaches the same verdict however the
    /// announcements were ordered on the way in. A device removed before the
    /// rotation cannot decrypt it at all, which is the point.
    fn on_namespace_arrived(
        &mut self,
        epoch: u32,
        chunk: &Chunk,
    ) -> Result<Vec<Effect>, CoreError> {
        let ticket = match self.cgka.decrypt(chunk)? {
            DecryptOutcome::Plaintext(ticket) => ticket,
            // The establishing operation has not arrived yet. Deliberately not
            // parked: rotations are re-announced on every resync, and a queue of
            // capabilities would be a second unbounded one.
            DecryptOutcome::AwaitingOp => return Ok(Vec::new()),
            // Either this node was removed — in which case the request below
            // is refused, because answering is gated on current membership —
            // or it is a member that missed the epoch this was keyed under and
            // genuinely needs it. The two are indistinguishable from here, and
            // deliberately so: the check belongs with the peer that can see the
            // current tree, not with the peer asking.
            DecryptOutcome::Unreachable => {
                return Ok(vec![Effect::RequestRepair {
                    target: RepairTarget::Namespace,
                    epoch: EpochId::of(chunk),
                }]);
            }
        };

        // The digest is recomputed from what was decrypted rather than trusted
        // from the wire, so a member cannot win a tie by claiming a large one.
        let announced = NamespaceEpoch::of(epoch, &ticket);
        if announced <= self.namespace {
            return Ok(Vec::new());
        }
        self.namespace = announced;
        self.namespace_ticket.clone_from(&ticket);
        self.forget_published();
        Ok(vec![Effect::AdoptNamespace { epoch, ticket }])
    }

    /// Apply a mutation to a document's text and publish the result.
    ///
    /// Every content edit funnels through here so the permission check, the
    /// container name, the commit and the publish live in one place rather than
    /// being repeated — and so that no future edit can accidentally skip the
    /// write check or forget to publish.
    fn on_text_edit<R, F>(
        &mut self,
        doc: DocumentUuid,
        csprng: &mut R,
        now: UnixSeconds,
        mutate: F,
    ) -> Result<Vec<Effect>, CoreError>
    where
        R: CryptoRng + RngCore,
        F: FnOnce(&loro::LoroText) -> Result<(), loro::LoroError>,
    {
        self.require_write()?;
        let me = self.cgka.member_id().to_bytes();
        let loro = self.docs.entry(doc).or_insert_with(new_doc);
        // Before the edit, so the claim and the change it describes land in one
        // commit and no reader can observe a change whose author is unnamed.
        claim_authorship(loro, &me);
        let content = loro.get_text("content");
        mutate(&content).map_err(|e| CoreError::Manifest(e.to_string()))?;
        commit_at(loro, now);
        self.publish(doc, csprng)
    }

    /// Name the state the workspace is in, and return what to call it back.
    ///
    /// A direct method rather than an [`Event`] for the reason
    /// [`Self::seal_asset_key`] is one: the caller needs a value back — the digest
    /// that identifies what it just took — and an event returns only effects. It
    /// also keeps the two backends honest by not adding a variant they must both
    /// learn to drive.
    ///
    /// Records the version of every entry the manifest holds *right now* whose
    /// content this replica actually has. An entry it has heard of but not synced
    /// is left out rather than named at some invented version — there is no state
    /// to point at. The reverse case is what [`RestoreOutcome::Unavailable`] is
    /// for: somebody else's checkpoint naming a version this replica has not
    /// merged, which a sync fixes.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotAWriter`] if this member's role cannot write — a
    /// checkpoint is a manifest write like any other — and propagates encoding and
    /// publish failures.
    pub fn checkpoint<R: CryptoRng + RngCore>(
        &mut self,
        name: &str,
        message: &str,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<(Vec<Effect>, [u8; 32]), CoreError> {
        self.require_write()?;
        // Sorted, so the encoding and therefore the digest is a function of the
        // contents rather than of the manifest's iteration order — two members
        // taking the same checkpoint of the same state agree on its identity.
        let mut entries: Vec<(DocumentUuid, VersionId)> = self
            .manifest
            .files()
            .into_iter()
            .filter_map(|entry| {
                self.document_version(entry.uuid)
                    .map(|version| (entry.uuid, version))
            })
            .collect();
        entries.sort_by_key(|(uuid, _)| *uuid);

        let checkpoint = Checkpoint {
            name: name.to_string(),
            message: message.to_string(),
            author: self.cgka.member_id().to_bytes(),
            at: now,
            entries,
        };
        let digest = checkpoint.digest();
        self.manifest.add_checkpoint(&checkpoint)?;
        let effects = self.publish_manifest(Keying::Current, csprng)?;
        Ok((effects, digest))
    }

    /// Put every entry a checkpoint names back to the version it names.
    ///
    /// Each entry is reverted exactly as [`Event::RevertDocument`] would revert
    /// it — a forward edit — so a restore is as safe under concurrency as a single
    /// revert, being several of them. Entries created since the checkpoint are
    /// left alone: a checkpoint says what those files *were*, not that nothing
    /// else existed.
    ///
    /// Returns one [`RestoreOutcome`] per named entry beside the effects, because
    /// "restored 3 of 5" leaves a caller unable to say which two and what to do
    /// about them. A deleted entry can never come back; an unavailable one is
    /// waiting on a sync.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotAWriter`] if this member's role cannot write, and
    /// [`CoreError::UnknownVersion`] if no checkpoint with this digest is on this
    /// replica — the digest names a record, and a record that has not merged yet
    /// is the same "not here, ask again later" condition a version id has.
    pub fn restore_checkpoint<R: CryptoRng + RngCore>(
        &mut self,
        digest: &[u8; 32],
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<(Vec<Effect>, Vec<RestoreOutcome>), CoreError> {
        self.require_write()?;
        let checkpoint =
            self.manifest
                .checkpoint(digest)
                .ok_or_else(|| CoreError::UnknownVersion {
                    version: hex(digest),
                })?;

        let live: HashSet<DocumentUuid> =
            self.manifest.files().into_iter().map(|e| e.uuid).collect();
        let mut effects = Vec::new();
        let mut outcomes = Vec::new();
        for (doc, version) in checkpoint.entries {
            if !live.contains(&doc) {
                // Deleted since. `on_delete_file` drops the replica, so there is
                // no history left to revert to and no later sync will bring one.
                outcomes.push(RestoreOutcome::Deleted(doc));
            } else if self.document_version(doc).as_ref() == Some(&version) {
                // Already there. Reverting would be a no-op that still costs a
                // publish, so it is named rather than performed.
                outcomes.push(RestoreOutcome::Unchanged(doc));
            } else {
                match self.on_revert(doc, &version, csprng, now) {
                    Ok(mut produced) => {
                        effects.append(&mut produced);
                        outcomes.push(RestoreOutcome::Restored(doc));
                    }
                    // This replica is behind on that document's history. Not
                    // terminal, and not a reason to abandon the other entries:
                    // restoring again after a sync finishes the job.
                    Err(CoreError::UnknownVersion { .. } | CoreError::UnknownDocument) => {
                        outcomes.push(RestoreOutcome::Unavailable(doc));
                    }
                    Err(other) => return Err(other),
                }
            }
        }
        Ok((effects, outcomes))
    }

    /// Every checkpoint this replica holds, newest first.
    #[must_use]
    pub fn checkpoints(&self) -> Vec<Checkpoint> {
        self.manifest.checkpoints()
    }

    /// Put a document back the way it was at `version`, as a forward edit.
    ///
    /// Deliberately *not* routed through [`Self::on_text_edit`], because the
    /// mutation is not one on the text container: `revert_to` computes the
    /// inverse of everything after `version` across the whole document, which is
    /// what makes the result correct when several containers moved. The three
    /// things that funnel does are still done here in the same order — check the
    /// write capability, claim authorship, commit at the caller's instant — and
    /// the publish is the ordinary one.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotAWriter`] if this member's role cannot write,
    /// [`CoreError::UnknownDocument`] if this node holds no such document, and
    /// [`CoreError::UnknownVersion`] if the version is malformed or names a state
    /// this replica has not merged. Reverting to the state a document is already
    /// in is not an error: it produces no operations, so the publish that follows
    /// finds nothing to say.
    fn on_revert<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        version: &VersionId,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_write()?;
        let frontiers = version.to_frontiers()?;
        let me = self.cgka.member_id().to_bytes();
        // Not `entry().or_default()`: reverting a document this node has never
        // seen would otherwise create an empty one and then revert it to a state
        // it cannot hold, which is a confusing way to spell "ask a peer first".
        let loro = self.docs.get(&doc).ok_or(CoreError::UnknownDocument)?;
        claim_authorship(loro, &me);
        loro.revert_to(&frontiers)
            .map_err(|_| CoreError::UnknownVersion {
                version: version.to_string(),
            })?;
        commit_at(loro, now);
        self.publish(doc, csprng)
    }

    /// Delete a document and withdraw this node's entry for it.
    fn on_delete_file<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_write()?;
        // Read before the tombstone lands: the manifest entry is what says
        // whether this is an asset, and which key spaces its versions occupy.
        let versions = self.manifest.asset_versions(doc);
        self.manifest.delete_file(doc)?;
        self.docs.remove(&doc);
        self.last_ref.remove(&doc);
        // Cleared alongside `last_ref` and for the same reason: they describe a
        // document that no longer exists, and a stale entry would make the next
        // publish under a recreated UUID export a delta from a version vector
        // belonging to the deleted one.
        self.published_up_to.remove(&doc);
        self.deltas_since_full.remove(&doc);
        // Drop anything parked for it too, or a chunk still in flight would
        // silently resurrect the document once its key arrived.
        let pending_bytes = &mut self.pending_bytes;
        self.pending_chunks.retain(|parked| {
            let keep = parked.doc != doc;
            if !keep {
                *pending_bytes = pending_bytes.saturating_sub(parked.chunk.ciphertext.len());
            }
            keep
        });
        let mut effects = Vec::new();
        if versions.is_empty() {
            // A document: one entry, holding its chunks.
            effects.push(Effect::DeleteEntry {
                key: self.secret.storage_key(doc),
                doc,
            });
        } else {
            // An asset, and **every version** has to go, not just the current
            // one. Each occupies two key spaces — the entry holding its wrapped
            // content key, and the contiguous range of its segments — and an
            // index entry is precisely what protects a blob from collection. Miss
            // a version and its payload stays on every member's disk forever, for
            // a file that no longer exists.
            for version in versions {
                effects.push(Effect::DeleteEntry {
                    key: self.secret.asset_key_key(version.content),
                    doc: version.content,
                });
                effects.push(Effect::DeleteAssetSegments {
                    prefix: self.secret.asset_prefix(version.content),
                    asset: version.content,
                });
            }
        }
        effects.extend(self.publish_manifest(Keying::Current, csprng)?);
        Ok(effects)
    }

    /// Record a new version of an asset entry and publish the manifest.
    ///
    /// A direct method rather than an [`Event`], like [`Self::seal_asset_key`] and
    /// for the same reason: the caller has already sealed and stored the segments,
    /// because bulk encryption cannot live in a crate that does no I/O, and what
    /// it needs from here is the manifest write that makes them a version.
    ///
    /// **Call this after the segments are stored, never before.** The version
    /// record is what declares them, so a crash between the two leaves segments
    /// nobody references — recoverable, since the writer's intent log names them —
    /// where the reverse order leaves a version whose payload does not exist,
    /// which readers can only discover by failing.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotAWriter`] if this member's role cannot write,
    /// [`CoreError::UnknownDocument`] if the manifest has no such entry, and
    /// propagates encoding and publish failures.
    pub fn add_asset_version<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        content: DocumentUuid,
        meta: AssetMeta,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_write()?;
        // One past the highest this replica has merged, which is what makes a
        // second attachment by one member beat its own first even though both
        // are dated to the same second.
        let seq = self
            .manifest
            .asset_versions(doc)
            .iter()
            .map(|version| version.seq)
            .max()
            .map_or(0, |highest| highest.saturating_add(1));
        let version = AssetVersion {
            content,
            meta,
            author: self.cgka.member_id().to_bytes(),
            at: now,
            seq,
        };
        self.manifest.add_asset_version(doc, &version)?;
        self.publish_manifest(Keying::Current, csprng)
    }

    /// Make an earlier version of an asset the current one again.
    ///
    /// Appends a version naming the *same* content UUID the earlier one used, so
    /// nothing is re-uploaded, re-encrypted or re-keyed — the ciphertext is
    /// immutable and still indexed. This is the asset counterpart of reverting a
    /// document forward, and it has the same property: the list only grows, so
    /// the version reverted away from stays readable and can be returned to.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotAWriter`] if this member's role cannot write, and
    /// [`CoreError::UnknownVersion`] if this entry has no version with that
    /// content UUID — which is what a caller naming another file's version, or one
    /// this replica has not merged, produces.
    pub fn revert_asset<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        content: DocumentUuid,
        csprng: &mut R,
        now: UnixSeconds,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_write()?;
        let target = self
            .manifest
            .asset_versions(doc)
            .into_iter()
            .find(|version| version.content == content)
            .ok_or_else(|| CoreError::UnknownVersion {
                version: hex(&content.0),
            })?;
        self.add_asset_version(doc, content, target.meta, csprng, now)
    }

    /// Every version recorded for an asset, oldest first.
    ///
    /// Empty for a document. An asset attached before versioning existed reports
    /// the single version it is, so a caller has one shape to handle.
    #[must_use]
    pub fn asset_versions(&self, doc: DocumentUuid) -> Vec<AssetVersion> {
        self.manifest.asset_versions(doc)
    }

    /// Admit a leaf to the group and record whatever the manifest needs.
    ///
    /// The CGKA half is identical for a new user and a new device; only the
    /// records differ, so `record` supplies those. It runs only when the
    /// operation was genuinely new, since re-recording on a duplicate `Add`
    /// would let a repeat admission quietly overwrite a role.
    fn admit<R, F>(
        &mut self,
        member: MemberId,
        share_key: ShareKey,
        certs: Vec<Certificate>,
        csprng: &mut R,
        record: F,
    ) -> Result<Vec<Effect>, CoreError>
    where
        R: CryptoRng + RngCore,
        F: FnOnce(&Manifest, &[u8; 32]) -> Result<(), CoreError>,
    {
        let op = self.cgka.add_member(member, share_key)?;
        if op.is_some() {
            record(&self.manifest, &member.to_bytes())?;
        }
        // The certificates ride *with* the `Add` rather than before it. A peer
        // checks the issuer's capability and the added leaf's binding before
        // merging, so an `Add` that arrived first would be refused outright —
        // not parked — and no later certificate would bring it back.
        let mut effects: Vec<Effect> = op
            .map(|op| Effect::BroadcastOp {
                op: Box::new(op),
                proof: certs.clone(),
            })
            .into_iter()
            .collect();
        if effects.is_empty() {
            // A duplicate admission: no operation was minted, so the
            // certificates have no carrier. Ship them anyway — the peer that
            // missed the original may still be missing them.
            effects.push(Effect::BroadcastCerts(certs));
        } else {
            // Already attached as the operation's proof.
        }
        effects.extend(self.publish_manifest(Keying::Current, csprng)?);
        Ok(effects)
    }

    /// Refuse a content or manifest mutation unless the local member may write.
    ///
    /// Deliberately permissive about the *unknown* case, and that asymmetry is
    /// the whole design. A joiner's manifest starts empty (see [`Self::joined`]),
    /// so a member whose role assignment has not yet synced is indistinguishable
    /// from one who was never given a role. Refusing there would deadlock
    /// onboarding: the joiner could not publish, so it could never announce its
    /// author, so no peer would ever accept anything from it. This mirrors the
    /// exemption the data plane already makes for a node's own entries before
    /// it has read back its own author claim.
    ///
    /// So: refuse only when a role *is* recorded and that role cannot write.
    /// That still catches what this exists for — a Viewer, or a member demoted
    /// from Editor — while leaving the bootstrap path open.
    ///
    /// Like [`Self::require_admin`] this is the permissions layer, not the
    /// cryptographic one. It does not stop a malicious peer from publishing;
    /// what stops that is every receiver's `author_may_write` check. What it
    /// does stop is a well-behaved node emitting writes it knows will be
    /// rejected — and, more importantly, forcing an implicit PCS update on the
    /// entire group to encrypt them.
    fn require_write(&self) -> Result<(), CoreError> {
        let me = self.cgka.member_id().to_bytes();
        match self.capabilities().role_of_member(&me) {
            Some(role) if !role.can_write() => Err(CoreError::NotAWriter),
            _ => Ok(()),
        }
    }

    /// Refuse to strip the last admin of their powers.
    ///
    /// A workspace with no admin can never gain one — promoting someone is
    /// itself an admin action — so this is unrecoverable rather than merely
    /// inconvenient. [`Manifest::admin_count`] has documented this rule since
    /// before there was a caller to enforce it.
    fn require_not_last_admin(&self, member: &[u8; 32]) -> Result<(), CoreError> {
        let is_admin = self
            .capabilities()
            .role_of(member)
            .is_some_and(Role::can_administer);
        if is_admin && self.capabilities().admin_count() <= 1 {
            return Err(CoreError::LastAdmin);
        }
        Ok(())
    }

    /// Re-announce a document without editing it.
    ///
    /// Gated like any other publish, and for the same reason: a re-announcement
    /// runs the identical `publish` path, so it can force a group-wide key
    /// change on everyone's behalf. A member who may not write has nothing
    /// legitimate to re-announce anyway, since peers reject its entries either
    /// way.
    ///
    /// # A quiescent document re-announces nothing
    ///
    /// If everything this node holds is already published, this returns no
    /// effects at all. That is not an optimisation of the anti-entropy, it is a
    /// correction of it: the index entry naming the existing chunk is still
    /// there, and `iroh-docs` range reconciliation re-delivers it to any peer
    /// that lacks it without anybody republishing. Encrypting the same content
    /// again produced a *new* blob with a new hash on every republish cycle, for
    /// every document, forever — which is most of what made publishing cost grow
    /// with the workspace rather than with the changes to it.
    ///
    /// What this does **not** cover is a peer that cannot decrypt or cannot
    /// apply what is already there; both of those are repairs, and both are
    /// demand-driven precisely because anti-entropy cannot answer them.
    ///
    /// When the document *has* moved, the re-announcement is
    /// [`Extent::Full`]: unlike an edit, a resync exists for peers that are
    /// behind by an unknown amount, and a delta keyed to this node's own
    /// publishing history is not what they are missing.
    fn on_resync<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_write()?;
        if !self.docs.contains_key(&doc) {
            // Nothing known about this document yet; nothing to re-announce.
            return Ok(Vec::new());
        }
        if self.is_published(doc) {
            return Ok(Vec::new());
        }
        self.publish_keyed(doc, Keying::Current, Extent::Full, csprng)
    }

    /// Forget what has been published, because the replica it was published to
    /// is gone.
    ///
    /// `published_up_to` is not a claim about this node's documents, it is a
    /// claim about **a namespace**: "the entries in that index already carry
    /// these operations". A rotation abandons the index for an empty one, so
    /// every such claim becomes false at once.
    ///
    /// Missing this is silent and total. The adoption path re-announces every
    /// document into the new namespace by driving [`Event::Resync`] — which,
    /// since a quiescent resync publishes nothing, would emit nothing at all for
    /// a node that had published everything before the rotation. Its documents
    /// would never reach the new replica, and the group would converge on a
    /// namespace containing only whatever happened to be edited afterwards.
    fn forget_published(&mut self) {
        self.published_up_to.clear();
        self.deltas_since_full.clear();
    }

    /// Whether everything this node holds for `doc` has already been published.
    ///
    /// Compares the live oplog version against the one recorded at the last
    /// publish. A document this node has never published answers `false`, which
    /// is the safe direction: the cost of being wrong here is one redundant
    /// chunk, and the cost of being wrong the other way is content nobody ever
    /// announces.
    fn is_published(&self, doc: DocumentUuid) -> bool {
        let Some(loro) = self.docs.get(&doc) else {
            return false;
        };
        let Some(published) = self.published_up_to.get(&doc) else {
            return false;
        };
        loro.commit();
        loro.oplog_vv().encode() == *published
    }

    /// Answer a peer that reports it can never read what we publish.
    ///
    /// Three distinct outcomes, and the difference between them matters:
    ///
    /// * **Not a current member** — refused, loudly. Answering costs a tree
    ///   operation, so this is the one place where being permissive would let a
    ///   revoked device spend the group's CPU indefinitely. `current_members`
    ///   rather than `known_members` for exactly that reason; disagreeing about
    ///   it costs a refused repair the next merge repairs, which is the cheap
    ///   direction.
    /// * **Nothing to offer** — a viewer, or a node that does not hold this
    ///   document, has nothing to re-encrypt. That is not the requester's
    ///   fault and not an error: some other member will answer.
    /// * **Able to help** — re-key and republish, so the answer is keyed under
    ///   an epoch minted *after* the request and therefore derivable by every
    ///   leaf currently in the tree, the requester's included.
    fn on_repair_requested<R: CryptoRng + RngCore>(
        &mut self,
        requester: MemberId,
        target: RepairTarget,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        if !self.cgka.is_current_member(requester) {
            return Err(CoreError::Unauthorized {
                issuer: requester.to_bytes(),
            });
        }
        let effects = match target {
            // Not gated on a writing role, exactly as `Event::ResyncManifest`
            // is not: a viewer's own device record lives in the manifest too,
            // and a group where only writers can repair the manifest is one
            // where a viewer can be locked off every roster permanently.
            RepairTarget::Manifest => self.publish_manifest(Keying::Fresh, csprng)?,
            // Ungated for the same reason as the manifest: a viewer stranded on
            // an abandoned namespace is a viewer removed in all but name, and
            // requiring a writing role to re-announce would make that
            // permanent. Re-announcing costs a fresh epoch, which every leaf
            // currently in the tree can derive and nothing outside it can.
            RepairTarget::Namespace => self.republish_namespace(Keying::Fresh, csprng)?,
            RepairTarget::Document(doc) => {
                if self.docs.contains_key(&doc) && self.require_write().is_ok() {
                    self.publish_keyed(doc, Keying::Fresh, Extent::Full, csprng)?
                } else {
                    Vec::new()
                }
            }
            // A history problem, not a key problem: the requester can decrypt
            // what we publish and simply lacks operations some delta depended
            // on. `Keying::Current` because re-keying would charge the whole
            // group for something no key change fixes, and `Extent::Full`
            // because a delta from *our* publishing history is exactly the thing
            // that already failed.
            RepairTarget::DocumentHistory(doc) => {
                if self.docs.contains_key(&doc) && self.require_write().is_ok() {
                    self.publish_keyed(doc, Keying::Current, Extent::Full, csprng)?
                } else {
                    Vec::new()
                }
            }
            // Answered by [`Self::reseal_asset_key`] and not from here, because
            // it is the one repair target whose ciphertext is not in state: an
            // asset's content key lives in a blob, recoverable by any member, and
            // is deliberately not cached. The caller fetches that blob and calls
            // the method; reaching this arm means a request arrived through a
            // path that has not been taught to, which is worth no effects rather
            // than a silent partial answer.
            RepairTarget::AssetKey(_) => Vec::new(),
        };
        if effects.is_empty() {
            // Nothing to offer: no epoch was minted, so nothing is counted.
            Ok(effects)
        } else {
            self.repairs_answered += 1;
            Ok(effects)
        }
    }

    /// Re-announce the capability this node holds, under a fresh epoch.
    ///
    /// The ticket is kept precisely so this is possible. A rotation is
    /// published once, and if it is lost there is no later write behind it —
    /// unlike a document, whose next edit carries the same content again. This
    /// is the only path by which a member that missed one gets back.
    fn republish_namespace<R: CryptoRng + RngCore>(
        &mut self,
        keying: Keying,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        if self.namespace_ticket.is_empty() {
            // Still on the founding namespace, which nobody was handed and
            // nobody can therefore have missed.
            return Ok(Vec::new());
        }
        let ticket = self.namespace_ticket.clone();
        let (chunk, ops) = self.encrypt_keyed(&ticket, &[], keying, csprng)?;
        let mut effects: Vec<Effect> = ops.into_iter().map(Effect::broadcast).collect();
        effects.push(Effect::PublishNamespace {
            epoch: self.namespace.epoch,
            chunk: Box::new(chunk),
        });
        Ok(effects)
    }

    /// Encrypt the manifest and emit it for storage at its well-known key.
    fn publish_manifest<R: CryptoRng + RngCore>(
        &mut self,
        keying: Keying,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let snapshot = self.manifest.export_snapshot()?;
        let (chunk, ops) = self.encrypt_keyed(&snapshot, &[], keying, csprng)?;

        // As in `publish`: an implicit PCS update has to reach peers before the
        // ciphertext it keys, or nobody can read what follows.
        let mut effects: Vec<Effect> = ops.into_iter().map(Effect::broadcast).collect();
        effects.push(Effect::StoreManifest {
            key: self.secret.manifest_key(),
            chunk: Box::new(chunk),
        });
        Ok(effects)
    }

    /// Encrypt one payload under either the current epoch or a fresh one.
    ///
    /// The single place the choice is made, so that no future publish path can
    /// silently pick the wrong one. Both arms return their operations in the
    /// order they must be broadcast.
    fn encrypt_keyed<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        preds: &[ChunkRef],
        keying: Keying,
        csprng: &mut R,
    ) -> Result<(Chunk, Vec<Signed<CgkaOperation>>), CoreError> {
        match keying {
            Keying::Current => {
                let (chunk, implicit) = self.cgka.encrypt(plaintext, preds, csprng)?;
                Ok((chunk, implicit.into_iter().collect()))
            }
            Keying::Fresh => self.cgka.encrypt_fresh(plaintext, preds, csprng),
        }
    }

    fn on_control_op(&mut self, authorized: AuthorizedOp) -> Result<Vec<Effect>, CoreError> {
        // Read before the merge consumes it: an `Add` that turns out to have been
        // issued by a member no longer in the group has to be undone, and after
        // the merge the issuer looks like any other.
        let splice = match authorized.op.payload {
            CgkaOperation::Add { added_id, .. } => {
                let issuer = MemberId::from(*authorized.op.issuer());
                Some((issuer, added_id))
            }
            CgkaOperation::Remove { .. } | CgkaOperation::Update { .. } => None,
        };

        let outcome = self.cgka.merge(authorized)?;
        if outcome == MergeOutcome::Applied {
            self.cgka.merge_pending()?;
            // New key material may have unblocked chunks that previously had
            // no reachable PCS key.
            let mut effects = self.drain_pending()?;
            effects.extend(self.evict_if_spliced(splice.as_ref()));
            return Ok(effects);
        }
        Ok(Vec::new())
    }

    /// Absorb certificates that arrived without an operation.
    ///
    /// Draining both queues afterwards is not merely tidy: a parked operation may
    /// have been waiting on a predecessor that is now admissible, and a parked
    /// chunk may be keyed under an epoch established by such an operation. Only
    /// bothering when something was new keeps a re-sent store from costing a full
    /// drain on every log exchange.
    ///
    /// # The quorum pass runs whether or not anything was new
    ///
    /// It used to sit behind the same early return, and that was a liveness
    /// defect rather than an optimisation. The two questions are not the same
    /// one: "did this message teach me a certificate I did not have" and "is
    /// there an executable proposal I have not carried out". A node can answer
    /// *no* to the first and *yes* to the second — most obviously when the
    /// approval that completed the quorum arrived in a batch this node had
    /// already absorbed from another peer, and every later exchange is then a
    /// duplicate that returns early.
    ///
    /// The consequence was permanent and silent. `run_quorum_actions` has only
    /// two triggers, this and `on_approve`; a node that misses both never
    /// re-evaluates, so the removal is performed on the peers that happened to
    /// see a new certificate at the right moment and never on the rest — which is
    /// exactly the "action performed there and refused everywhere" split the
    /// whole quorum design exists to avoid. It surfaced as
    /// `a_proposal_with_enough_approvals_is_eventually_performed_everywhere`
    /// failing on some seeds and not others.
    ///
    /// The cost of running it unconditionally is a walk over the certificate
    /// closure, which is small and bounded; the expensive part behind the early
    /// return is the queue drain, and that stays behind it.
    fn on_certs_arrived(&mut self, certs: Vec<Certificate>) -> Result<Vec<Effect>, CoreError> {
        let mut effects = Vec::new();
        if self.cgka.absorb_certificates(certs) > 0 {
            self.cgka.merge_pending()?;
            effects = self.drain_pending()?;
        } else {
            // A re-sent store with nothing new in it. Nothing to merge and
            // nothing to drain — but see above for why that does not mean there
            // is nothing to do.
        }
        // Newly arrived approvals may have tipped a proposal over the threshold.
        // Performed here rather than only in `on_approve` because the approval
        // that completes a quorum is usually somebody *else's*: without this, a
        // proposal would execute only on the node that happened to cast the last
        // vote, and every other replica would wait for an announcement that the
        // design deliberately does not send.
        effects.extend(self.run_quorum_actions());
        Ok(effects)
    }

    /// Ask for the removal of a leaf a non-member introduced.
    ///
    /// The revenant case. A removed member keeps whatever capability it held —
    /// the certificate store is grow-only, so `ever_admin` never retracts — and
    /// its signature stays admissible because `known_members` is monotone. It can
    /// therefore mint a binding for a keypair it controls and issue a valid `Add`.
    ///
    /// Refusing that `Add` is not available: the only thing distinguishing it is
    /// `current_members`, which is order-sensitive, so one peer would drop an
    /// operation another kept and the group would diverge permanently — the
    /// failure mode the whole design is built to avoid. The splice is accepted and
    /// then *undone* instead, which converges because every honest admin reaches
    /// the same conclusion independently and duplicate removals merge as
    /// [`MergeOutcome::Duplicate`].
    ///
    /// Only an admin can act, since only an admin's `Remove` will be honoured.
    /// Non-admins raise nothing and wait; there is nothing useful they could do.
    fn evict_if_spliced(&self, splice: Option<&(MemberId, MemberId)>) -> Vec<Effect> {
        let Some(&(issuer, added)) = splice else {
            return Vec::new();
        };
        if self.cgka.is_current_member(issuer) {
            // The ordinary case: an admission by a member in good standing.
            return Vec::new();
        }
        let me = self.cgka.member_id().to_bytes();
        if self.capabilities().may_administer(&me) {
            vec![Effect::EvictUncertified { member: added }]
        } else {
            // Not ours to fix. An admin will see the same operation and act.
            Vec::new()
        }
    }

    /// Draw a content key for a new asset and emit the chunk that wraps it.
    ///
    /// Returns the key **and** the effects that publish it, and the caller must
    /// apply the effects before storing a single segment. This is the ordinary
    /// key-material-before-content rule with a longer fuse than usual: a peer
    /// that fetches a segment before the key chunk exists cannot decrypt it and,
    /// unlike a document chunk, has nothing to park — asset delivery is pull-based,
    /// so the read simply fails and is retried by a human.
    ///
    /// # Why the key comes back to the caller at all
    ///
    /// Because the core does no I/O and an asset does not fit in memory. Sealing
    /// happens a segment at a time, next to whatever is reading them, which means
    /// the bulk AEAD cannot live here. What does live here is the part that needs
    /// the group's key material: drawing the content key and encrypting it to the
    /// CGKA. The caller gets a [`AssetKey`], which zeroizes on drop, and hands
    /// each segment to [`crate::asset::seal_segment`].
    ///
    /// Each call draws a *fresh* key, which is what keeps forward secrecy at the
    /// granularity it has for documents: a new version of an asset is unreadable
    /// to anyone removed before it was written. Re-using a key across versions
    /// would also reuse the derived per-segment nonces, which for a stream cipher
    /// is fatal rather than merely untidy.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotAWriter`] if this node holds no writing role, or a
    /// CGKA error if the key chunk cannot be encrypted.
    pub fn seal_asset_key<R: CryptoRng + RngCore>(
        &mut self,
        asset: DocumentUuid,
        csprng: &mut R,
    ) -> Result<(AssetKey, Vec<Effect>), CoreError> {
        self.require_write()?;
        let key = AssetKey::generate(csprng);
        let effects = self.publish_asset_key(asset, &key, Keying::Current, csprng)?;
        Ok((key, effects))
    }

    /// Recover an asset's content key from the chunk that wraps it.
    ///
    /// Takes the key chunk rather than reading a cached copy, deliberately. The
    /// key is recoverable by any member from a blob any member can fetch, so
    /// holding it in state would be storing a secret to save a decryption — and
    /// it would then have to be persisted, snapshot-versioned, and reasoned about
    /// on every membership change.
    #[must_use]
    pub fn open_asset_key(&mut self, key_chunk: &Chunk) -> AssetKeyVerdict {
        match self.cgka.decrypt(key_chunk) {
            Ok(DecryptOutcome::Plaintext(bytes)) => <[u8; 32]>::try_from(bytes.as_slice())
                .map_or(AssetKeyVerdict::Corrupt, |raw| {
                    AssetKeyVerdict::Ready(AssetKey::from_bytes(raw))
                }),
            Ok(DecryptOutcome::AwaitingOp) => AssetKeyVerdict::AwaitingKey,
            Ok(DecryptOutcome::Unreachable) => AssetKeyVerdict::Unreachable,
            Err(_) => AssetKeyVerdict::Corrupt,
        }
    }

    /// Answer a peer stuck on an asset it cannot decrypt.
    ///
    /// The counterpart of [`Self::on_repair_requested`] for
    /// [`RepairTarget::AssetKey`], and a separate method for the reason
    /// [`Self::open_asset_key`] takes its chunk as an argument: the key being
    /// repaired is not in state, so answering needs the caller to supply the
    /// ciphertext it is re-encrypting. Every other repair target is answered from
    /// state alone, which is why they all fit one event and this does not.
    ///
    /// The gate is the same one, and for the same reason: re-keying costs the
    /// whole group a tree operation, so a device that is no longer a member must
    /// not be able to ask for one.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Unauthorized`] if `requester` is not a current
    /// member, [`CoreError::NotAWriter`] if this node may not publish, and a CGKA
    /// error if the key cannot be recovered or re-encrypted.
    pub fn reseal_asset_key<R: CryptoRng + RngCore>(
        &mut self,
        requester: MemberId,
        asset: DocumentUuid,
        key_chunk: &Chunk,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        if !self.cgka.is_current_member(requester) {
            return Err(CoreError::Unauthorized {
                issuer: requester.to_bytes(),
            });
        }
        self.require_write()?;
        let AssetKeyVerdict::Ready(key) = self.open_asset_key(key_chunk) else {
            // This node cannot read the key either, so it has nothing to offer.
            // Not an error: some other member will answer, exactly as with a
            // document repair a viewer cannot serve.
            return Ok(Vec::new());
        };
        let effects = self.publish_asset_key(asset, &key, Keying::Fresh, csprng)?;
        if effects.is_empty() {
            // Nothing was minted, so nothing is counted.
        } else {
            self.repairs_answered += 1;
        }
        Ok(effects)
    }

    /// Encrypt an asset's content key to the group and emit it for storage.
    ///
    /// `Keying::Fresh` on the repair path for the identical reason a document
    /// repair uses it: re-encrypting under the epoch the stuck peer already
    /// failed on reproduces a ciphertext it cannot read.
    fn publish_asset_key<R: CryptoRng + RngCore>(
        &mut self,
        asset: DocumentUuid,
        key: &AssetKey,
        keying: Keying,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let wrapped = key.to_bytes();
        let (chunk, ops) = self.encrypt_keyed(wrapped.as_ref(), &[], keying, csprng)?;
        // Key material first, as everywhere else.
        let mut effects: Vec<Effect> = ops.into_iter().map(Effect::broadcast).collect();
        effects.push(Effect::StoreChunk {
            key: self.secret.asset_key_key(asset),
            doc: asset,
            chunk: Box::new(chunk),
        });
        Ok(effects)
    }

    /// Every blinded key an asset occupies in the index: for each version, its
    /// key chunk and then each of its segments in order.
    ///
    /// Used by a namespace rotation. The new replica starts empty, and documents
    /// are carried into it by being re-encrypted — which for an asset would mean
    /// re-encrypting and re-uploading gigabytes that have not changed. Asset
    /// entries are re-*indexed* instead, by writing the hash the old replica
    /// already names, and this is the list of keys to do it for.
    ///
    /// **Every version, and keyed by the version's content UUID rather than the
    /// entry's.** A rotation abandons the old replica, so a key left out here is
    /// content that no live index names: the current version would be lost
    /// outright, and a superseded one would become unreadable while still listed
    /// — a history with holes in it.
    #[must_use]
    pub fn asset_index_keys(&self) -> Vec<StorageKey> {
        let mut keys = Vec::new();
        for entry in self.manifest.files() {
            for version in self.manifest.asset_versions(entry.uuid) {
                keys.push(self.secret.asset_key_key(version.content));
                for index in 0..version.meta.segments {
                    keys.push(self.secret.asset_part_key(version.content, index));
                }
            }
        }
        keys
    }

    /// The blinded prefix of every asset version the manifest records.
    ///
    /// What a caller turns into an `iroh-docs` download policy. Without one every
    /// member fetches every asset's payload the moment its entries reconcile,
    /// which is the "slowing down document synchronization" the large-asset user
    /// story exists to rule out.
    ///
    /// **Every version, not just the current one**, and the direction matters:
    /// this list is what a peer declines to fetch eagerly. A superseded version
    /// left out of it would be downloaded in full by every member the moment its
    /// entries reconciled — the opposite of the intent, and worse for an asset
    /// nobody is reading. Fetching an old version on demand does not need the
    /// policy's permission; declining to fetch it does.
    #[must_use]
    pub fn asset_prefixes(&self) -> Vec<[u8; 24]> {
        self.manifest
            .files()
            .into_iter()
            .flat_map(|entry| self.manifest.asset_versions(entry.uuid))
            .map(|version| self.secret.asset_prefix(version.content))
            .collect()
    }

    /// Encrypt and emit an ordinary edit to a document.
    ///
    /// [`Extent::Delta`] every [`FULL_PUBLISH_EVERY`] publishes but the last, so
    /// a receiver that missed a delta is carried by the next full export without
    /// having to ask.
    fn publish<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let extent = if self.published_up_to.contains_key(&doc)
            && self.deltas_since_full.get(&doc).copied().unwrap_or(0) < FULL_PUBLISH_EVERY
        {
            Extent::Delta
        } else {
            // Nothing published yet, or the delta run is long enough that a peer
            // which missed one has been stuck for a while.
            Extent::Full
        };
        self.publish_keyed(doc, Keying::Current, extent, csprng)
    }

    /// Encrypt and emit a document.
    ///
    /// `keying` decides which epoch key the chunk is under; `extent` decides how
    /// much history is inside it. The two are orthogonal and all four
    /// combinations are used:
    ///
    /// | Caller | `keying` | `extent` |
    /// |---|---|---|
    /// | an ordinary edit | `Current` | `Delta` |
    /// | every `FULL_PUBLISH_EVERY`th edit | `Current` | `Full` |
    /// | a resync of a document that moved | `Current` | `Full` |
    /// | `RepairTarget::Document` — cannot decrypt | `Fresh` | `Full` |
    /// | `RepairTarget::DocumentHistory` — cannot apply | `Current` | `Full` |
    ///
    /// A repair is always `Full`: a peer that asked for help has already shown
    /// that what it holds is not enough, and answering with a delta keyed to
    /// *this* node's publishing history would be answering a different question.
    fn publish_keyed<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        keying: Keying,
        extent: Extent,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let published = self.published_up_to.get(&doc).cloned();
        let loro = self.docs.entry(doc).or_insert_with(new_doc);

        // `all_updates()` is what makes a chunk self-sufficient under loss, and
        // that is exactly what a `Delta` gives up in exchange for costing the
        // edit rather than the document. What makes the trade safe is that a
        // receiver stuck on a delta says so — see `RepairTarget::DocumentHistory`.
        let mode = match extent {
            Extent::Delta => published
                .as_deref()
                .and_then(|bytes| loro::VersionVector::decode(bytes).ok())
                .map_or(ExportMode::all_updates(), |vv| {
                    ExportMode::updates_owned(vv)
                }),
            Extent::Full => ExportMode::all_updates(),
        };
        let update = loro
            .export(mode)
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        // Recorded before the encryption can fail, because it describes what this
        // node is *about* to hand out and the caller cannot retry a partial
        // publish: a failure here leaves the document unpublished either way, and
        // the next publish exporting from an older version merely repeats work.
        let now_at = loro.oplog_vv().encode();

        // Bind this chunk to the last state we know of for this document.
        let preds: Vec<ChunkRef> = self.last_ref.get(&doc).copied().into_iter().collect();
        let (chunk, ops) = self.encrypt_keyed(&update, &preds, keying, csprng)?;
        self.last_ref.insert(doc, chunk.content_ref);
        self.published_up_to.insert(doc, now_at);
        match extent {
            Extent::Delta => *self.deltas_since_full.entry(doc).or_insert(0) += 1,
            Extent::Full => {
                self.deltas_since_full.insert(doc, 0);
            }
        }

        // Key material must go out *before* anything else can read the chunk,
        // so it is emitted first — whether it is an implicit update beekem
        // performed for us or the deliberate re-key of a repair.
        let mut effects: Vec<Effect> = ops.into_iter().map(Effect::broadcast).collect();
        effects.push(Effect::StoreChunk {
            key: self.secret.storage_key(doc),
            doc,
            chunk: Box::new(chunk),
        });
        Ok(effects)
    }

    /// Park a chunk that is not yet applicable, enforcing the pending budget.
    ///
    /// Eviction is oldest-first. A chunk that has been waiting longest is the
    /// one whose key material has had the most time to show up and has not, so
    /// it is the least likely of the queue to still be worth holding.
    fn park_chunk(&mut self, doc: DocumentUuid, chunk: Chunk) {
        let size = chunk.ciphertext.len();
        while !self.pending_chunks.is_empty()
            && (self.pending_chunks.len() >= MAX_PENDING_CHUNKS
                || self.pending_bytes + size > MAX_PENDING_CHUNK_BYTES)
        {
            if let Some(evicted) = self.pending_chunks.pop_front() {
                self.pending_bytes = self
                    .pending_bytes
                    .saturating_sub(evicted.chunk.ciphertext.len());
                self.evicted_chunks += 1;
            }
        }
        self.pending_bytes += size;
        self.pending_chunks.push_back(Parked {
            doc,
            chunk,
            drains: 0,
        });
    }

    /// Retry every parked chunk, repeating while progress is being made.
    ///
    /// Progress is counted as *applications*, not as effects: a repair request
    /// is an effect too, and counting it would spin this loop forever over a
    /// chunk that can never apply.
    ///
    /// # Why the two "keep it" verdicts are no longer treated alike
    ///
    /// `AwaitingKey` needs nothing from anybody: the operation establishing the
    /// epoch is already in flight on the control plane, and the next drain after
    /// it lands applies the chunk. `AwaitingDeps` needs a *publisher* to send
    /// something it has not sent, and with delta publishing that is a state a
    /// chunk can sit in forever — a delta whose base this node never received is
    /// not going to become applicable by waiting, because the index slot holding
    /// it has already been overwritten. Both are re-queued, but the second is
    /// aged, and past [`MAX_DEP_WAIT_DRAINS`] it asks. Without that a delta lost
    /// in transit costs the receiver that document until the next full publish,
    /// silently, with a satisfied `no chunk stays parked forever` property right
    /// up until the pending budget evicts it.
    fn drain_pending(&mut self) -> Result<Vec<Effect>, CoreError> {
        let mut effects = Vec::new();
        loop {
            let candidates = std::mem::take(&mut self.pending_chunks);
            self.pending_bytes = 0;
            let mut applied = 0_usize;
            for parked in candidates {
                let Parked { doc, chunk, drains } = parked;
                match self.try_apply(doc, &chunk) {
                    ChunkVerdict::Applied => {
                        applied += 1;
                        effects.push(Effect::Applied { doc });
                    }
                    // Not applicable yet: re-queue and try again next time new
                    // key material or new operations arrive. Re-queueing goes
                    // through the plain path rather than `park_chunk`, because
                    // these chunks were already admitted under the budget and
                    // re-checking it here could evict a chunk mid-drain.
                    verdict @ (ChunkVerdict::AwaitingKey | ChunkVerdict::AwaitingDeps) => {
                        let drains = drains.saturating_add(1);
                        if verdict == ChunkVerdict::AwaitingDeps && drains >= MAX_DEP_WAIT_DRAINS {
                            // Asked for repeatedly rather than once: the request
                            // itself can be lost, and the backends rate-limit on
                            // `(target, epoch)` so a repeat costs nothing until
                            // the window closes.
                            effects.push(Effect::RequestRepair {
                                target: RepairTarget::DocumentHistory(doc),
                                epoch: EpochId::of(&chunk),
                            });
                        } else {
                            // Still within the window where the missing chunk
                            // may simply be behind this one in the same pass.
                        }
                        self.pending_bytes += chunk.ciphertext.len();
                        self.pending_chunks.push_back(Parked { doc, chunk, drains });
                    }
                    // Never applicable. Holding it would occupy the budget for
                    // the life of the process and retry a decryption that
                    // cannot succeed on every drain; the content comes back
                    // instead as a re-encryption under an epoch we can derive.
                    ChunkVerdict::Unreachable => {
                        self.unreadable_chunks += 1;
                        effects.push(Effect::RequestRepair {
                            target: RepairTarget::Document(doc),
                            epoch: EpochId::of(&chunk),
                        });
                    }
                    ChunkVerdict::Corrupt => self.corrupt_chunks += 1,
                }
            }
            if applied == 0 {
                return Ok(effects);
            }
        }
    }

    /// Attempt to decrypt and merge one chunk.
    ///
    /// Out-of-order delivery is not a failure, so "not applicable" is a verdict
    /// rather than an error — but it is *two* verdicts, and which one it is
    /// decides whether the chunk is worth keeping. A chunk waiting on key
    /// material becomes readable the moment the control plane catches up; a
    /// chunk keyed under an epoch that predates this node's membership never
    /// does, and the only thing that can help is somebody re-encrypting it.
    fn try_apply(&mut self, doc: DocumentUuid, chunk: &Chunk) -> ChunkVerdict {
        let plaintext = match self.cgka.decrypt(chunk) {
            Ok(DecryptOutcome::Plaintext(plaintext)) => plaintext,
            Ok(DecryptOutcome::AwaitingOp) => return ChunkVerdict::AwaitingKey,
            Ok(DecryptOutcome::Unreachable) => return ChunkVerdict::Unreachable,
            Err(_) => return ChunkVerdict::Corrupt,
        };
        let loro = self.docs.entry(doc).or_insert_with(new_doc);
        // Loro reports its own missing dependencies separately from the
        // key-availability question. This one really is "not yet": the chunk
        // carrying the operations this one depends on is still in flight.
        let applied = matches!(loro.import(&plaintext), Ok(status) if status.pending.is_none());
        if applied {
            // Anything we publish next genuinely follows this chunk, so it is
            // the predecessor to name.
            self.last_ref.insert(doc, chunk.content_ref);
            ChunkVerdict::Applied
        } else {
            ChunkVerdict::AwaitingDeps
        }
    }
}

/// Serialize one CRDT document for local copying or storage.
///
/// `ExportMode::Snapshot` rather than `all_updates()`, and the difference is not
/// cosmetic: `all_updates()` is what makes a *published* chunk self-sufficient
/// under loss, which nothing downstream of this needs — both callers hand the
/// bytes straight to `restore_doc` on the same machine.
///
/// # Errors
///
/// Returns [`CoreError::Manifest`], which is this crate's catch-all for a Loro
/// failure whatever container it came from.
fn snapshot_doc(doc: &LoroDoc) -> Result<Vec<u8>, CoreError> {
    doc.commit();
    doc.export(ExportMode::Snapshot)
        .map_err(|e| CoreError::Manifest(e.to_string()))
}

/// Rebuild a CRDT document from [`snapshot_doc`] bytes.
///
/// Always a *fresh* [`LoroDoc`], because `LoroDoc::clone` returns another handle
/// onto the same document — the aliasing hazard that makes
/// [`WorkspaceState`]'s `Clone` hand-written in the first place.
///
/// # Errors
///
/// Returns [`CoreError::Manifest`] if the bytes are not a readable snapshot.
fn restore_doc(bytes: &[u8]) -> Result<LoroDoc, CoreError> {
    let doc = new_doc();
    doc.import(bytes)
        .map_err(|e| CoreError::Manifest(e.to_string()))?;
    Ok(doc)
}

/// Commit a document's pending operations, dated `now`.
///
/// `LoroDoc::commit` would date the change from the system clock, which this
/// crate must not read — see the [`crate::version`] module documentation. Loro
/// raises the value to at least the greatest timestamp in the change's causal
/// ancestry, so a node with a slow clock cannot date its work before what it
/// followed; a node with a fast one can date its own work in the future, which is
/// why a timestamp is presented as a claim rather than as evidence.
fn commit_at(doc: &LoroDoc, now: UnixSeconds) {
    doc.commit_with(CommitOptions::new().timestamp(now.get()));
}

/// An empty document, configured the way every document here must be.
///
/// The only place a document `LoroDoc` is constructed, so that the one setting
/// below cannot be forgotten on a path added later.
///
/// # Why change merging is off
///
/// Loro merges consecutive local commits from the same peer into a single change
/// when they fall within a merge interval, which defaults to a thousand seconds.
/// That is a sound default for an editor whose history is an undo stack, and it
/// is the wrong one here: a change is what a version *is*, so three edits a
/// minute apart would collapse into one entry a person cannot revert past. Worse,
/// they collapse by wall-clock time, and this crate's clock is supplied by its
/// caller — the simulator drives a whole run at one instant, so the merging would
/// differ between the harness and production.
///
/// The cost is oplog metadata per commit rather than per interval, which is a few
/// tens of bytes against a chunk that carries the edit itself.
///
/// **Negative, not zero.** Loro merges when `next.timestamp - last.timestamp <=
/// interval`, so zero still merges two commits made in the same second — which,
/// with a supplied clock, can be a whole simulated run. Any negative value makes
/// the comparison unsatisfiable.
fn new_doc() -> LoroDoc {
    let doc = LoroDoc::new();
    doc.set_change_merge_interval(-1);
    doc
}

/// Read a hex-encoded Loro peer id back, as [`claim_authorship`] wrote it.
fn unhex_u64(raw: &str) -> Option<u64> {
    let bytes = unhex_bytes(raw)?;
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_be_bytes)
}

/// Read a hex-encoded member id back.
fn unhex_member(raw: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(unhex_bytes(raw)?).ok()
}

/// Decode a hex string, or `None` if it is not one.
fn unhex_bytes(raw: &str) -> Option<Vec<u8>> {
    if raw.len().is_multiple_of(2) {
        (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).ok())
            .collect()
    } else {
        None
    }
}

/// Record that this replica's current Loro peer id belongs to `member`.
///
/// Attribution is *recorded* rather than derived, and the reason is a hazard
/// rather than a preference. A version list has to resolve the peer id on a
/// change back to a member, and the obvious answer — derive the peer id from the
/// workspace secret and the member id, so that every peer can invert it without
/// being told — is wrong in a way that corrupts documents. Assigning a peer id
/// also fixes the operation counter this replica writes next, so a device that
/// loses a document's local history while another replica keeps it — deleting and
/// recreating a UUID, or resuming from a wipe — restarts its counter and mints
/// operation ids that already name different operations. Loro says plainly that
/// this can corrupt a document and recommends the random per-session id it
/// defaults to. This keeps that default and writes the mapping down instead.
///
/// The record is a **claim**, in exactly the sense [`crate::manifest`] uses the
/// word: it lives in content any member may write, so a member could name
/// somebody else. It grants nothing — whether an entry is accepted at all is
/// decided by the capability closure against its *author key* — so a lie costs a
/// wrong name beside a change and nothing else. See [`crate::version`].
///
/// Idempotent, and cheap for that reason: a peer id changes only when a
/// `LoroDoc` is constructed, so this writes one entry per document per session.
fn claim_authorship(doc: &LoroDoc, member: &[u8; 32]) {
    let peer = hex(&doc.peer_id().to_be_bytes());
    let authors = doc.get_map(DOC_AUTHORS_CONTAINER);
    if authors.get(&peer).is_some() {
        // Already claimed by this session; the value cannot have changed, since
        // a peer id belongs to one `LoroDoc` and that document is this one.
    } else {
        // A failed insert costs this session's attribution and nothing else, so
        // it is absorbed rather than failing the edit it precedes.
        let _ = authors.insert(&peer, hex(member).as_str());
    }
}

/// A fresh nonce, so two otherwise identical certificates have distinct digests.
///
/// Certificates are keyed by digest and ordered by it when a tie must be broken,
/// so two grants that agreed in every field would collapse into one entry and a
/// re-grant would silently do nothing.
fn random_nonce<R: CryptoRng + RngCore>(csprng: &mut R) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    csprng.fill_bytes(&mut nonce);
    nonce
}

/// Whether a publish reuses the group's current epoch key or mints a new one.
///
/// The distinction is the difference between anti-entropy and repair.
/// [`Keying::Current`] is right for every ordinary publish: beekem re-keys on
/// its own whenever the tree has no root key, so a normal write pays for a
/// re-key only when membership actually moved. [`Keying::Fresh`] is for the one
/// case that rule cannot cover — a peer that reports it cannot derive the
/// current epoch at all — where re-publishing under the current key reproduces
/// a byte-identical chunk and repairs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keying {
    /// Reuse the current epoch key, letting beekem re-key if it must.
    Current,
    /// Mint a new epoch, so every leaf now in the tree can read the result.
    Fresh,
}

/// How much of a document's history a publish carries.
///
/// Orthogonal to [`Keying`], and the two answer genuinely different questions:
/// *which key* the chunk is encrypted under, and *how much* is inside it. Every
/// one of the four combinations is reachable and means something — see the table
/// on [`WorkspaceState::publish_keyed`].
///
/// [`Extent::Delta`] is what makes an ordinary edit cost the edit rather than the
/// document. [`Extent::Full`] is what makes a chunk **self-sufficient under
/// loss**, which is the property `all_updates()` was chosen for in the first
/// place: a receiver can apply it without holding anything that came before. A
/// document's index slot holds one chunk per author, so a receiver that misses a
/// delta cannot go back for it — the only way through is a later `Full`, either
/// on the periodic schedule or on demand via
/// [`RepairTarget::DocumentHistory`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extent {
    /// Only what this node has not published yet.
    Delta,
    /// Everything, so the chunk stands alone.
    Full,
}
