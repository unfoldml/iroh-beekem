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
use loro::{ExportMode, LoroDoc};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    blinding::{DocumentUuid, StorageKey, WorkspaceSecret},
    capability::{CapabilityStore, Certificate, Role},
    content::{Chunk, ChunkRef},
    error::CoreError,
    keys::{AuthorizedOp, CgkaController, DecryptOutcome, EpochId, MergeOutcome},
    manifest::{DeviceRecord, FileEntry, Manifest, WorkspaceInfo},
    snapshot::{SNAPSHOT_VERSION, WorkspaceSnapshot, member_from_bytes},
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
    Document(DocumentUuid),
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

/// One node's complete workspace state.
pub struct WorkspaceState {
    cgka: CgkaController,
    secret: WorkspaceSecret,
    manifest: Manifest,
    docs: HashMap<DocumentUuid, LoroDoc>,
    /// Chunks that could not yet be decrypted or merged.
    pending_chunks: VecDeque<(DocumentUuid, Chunk)>,
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
    /// Repair requests this node answered by minting a fresh epoch.
    ///
    /// Each one is a tree operation the whole group pays for, which is exactly
    /// why it is counted: repair must stay proportional to the number of peers
    /// that are actually stuck, not to how often anti-entropy runs.
    repairs_answered: u64,
    /// The most recent chunk this node published or applied, per document.
    ///
    /// This is what makes each chunk's key causally bound rather than bound to
    /// nothing: beekem mixes the predecessor refs into the derived application
    /// secret, so a chunk names the state it follows. The receiver does not
    /// need the predecessor chunk to decrypt — the digest travels inside the
    /// ciphertext's metadata — so this costs nothing in liveness.
    last_ref: HashMap<DocumentUuid, ChunkRef>,
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
                    .unwrap_or_else(|_| LoroDoc::new());
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
            endpoint_id: self.endpoint_id,
            namespace: self.namespace,
            namespace_ticket: self.namespace_ticket.clone(),
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
            endpoint_id: None,
            namespace: NamespaceEpoch {
                epoch: namespace_epoch,
                ..NamespaceEpoch::INITIAL
            },
            namespace_ticket: Vec::new(),
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
    pub fn found(cgka: CgkaController, secret: WorkspaceSecret) -> Result<Self, CoreError> {
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
            published_up_to: Vec::new(),
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
            endpoint_id: snapshot.endpoint_id,
            namespace: snapshot.namespace,
            namespace_ticket: snapshot.namespace_ticket,
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

    /// How many members currently hold a leaf.
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
    /// # Errors
    ///
    /// Propagates CGKA, AEAD and CRDT failures. Note that an out-of-order
    /// arrival is *not* an error: it parks silently and is retried later.
    pub fn handle<R: CryptoRng + RngCore>(
        &mut self,
        event: Event,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        match event {
            Event::ControlOp(op) => self.on_control_op(op),
            Event::CertsArrived(certs) => self.on_certs_arrived(certs),
            Event::ChunkArrived { doc, chunk } => self.on_chunk_arrived(doc, *chunk),
            Event::LocalEdit { doc, text } => self.on_text_edit(doc, csprng, |content| {
                let at = content.len_unicode();
                content.insert(at, &text)
            }),
            // `update` diffs against the current contents rather than clearing
            // and re-inserting, so replacing one word stays a one-word change
            // in the CRDT — and merges with a concurrent edit elsewhere in the
            // document instead of clobbering it.
            Event::WriteFile { doc, text } => self.on_text_edit(doc, csprng, |content| {
                content
                    .update(&text, loro::UpdateOptions::default())
                    .map_err(|e| loro::LoroError::Unknown(e.to_string().into()))
            }),
            // Positions are clamped rather than rejected: they come from a
            // caller holding a view that a concurrent remote edit may already
            // have shortened, which is ordinary in a CRDT rather than a fault.
            Event::InsertText { doc, pos, text } => self.on_text_edit(doc, csprng, |content| {
                content.insert(pos.min(content.len_unicode()), &text)
            }),
            Event::RemoveText { doc, pos, len } => self.on_text_edit(doc, csprng, |content| {
                let end = content.len_unicode();
                let at = pos.min(end);
                content.delete(at, len.min(end - at))
            }),
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
        self.require_admin()?;
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
        let already_parked = self.pending_chunks.iter().any(|(d, c)| {
            *d == doc && c.content_ref == chunk.content_ref && c.pcs_key_hash == chunk.pcs_key_hash
        });
        if !already_parked {
            self.park_chunk(doc, chunk);
        }
        self.drain_pending()
    }

    /// Revoke one device's leaf.
    fn on_remove_member(&mut self, member: MemberId) -> Result<Vec<Effect>, CoreError> {
        self.require_admin()?;
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
        Ok(vec![
            Effect::broadcast(op),
            Effect::RotateNamespace {
                epoch: self.namespace.epoch,
            },
        ])
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
        mutate: F,
    ) -> Result<Vec<Effect>, CoreError>
    where
        R: CryptoRng + RngCore,
        F: FnOnce(&loro::LoroText) -> Result<(), loro::LoroError>,
    {
        self.require_write()?;
        let loro = self.docs.entry(doc).or_default();
        let content = loro.get_text("content");
        mutate(&content).map_err(|e| CoreError::Manifest(e.to_string()))?;
        loro.commit();
        self.publish(doc, csprng)
    }

    /// Delete a document and withdraw this node's entry for it.
    fn on_delete_file<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_write()?;
        self.manifest.delete_file(doc)?;
        self.docs.remove(&doc);
        self.last_ref.remove(&doc);
        // Drop anything parked for it too, or a chunk still in flight would
        // silently resurrect the document once its key arrived.
        let pending_bytes = &mut self.pending_bytes;
        self.pending_chunks.retain(|(d, chunk)| {
            let keep = *d != doc;
            if !keep {
                *pending_bytes = pending_bytes.saturating_sub(chunk.ciphertext.len());
            }
            keep
        });
        let mut effects = vec![Effect::DeleteEntry {
            key: self.secret.storage_key(doc),
            doc,
        }];
        effects.extend(self.publish_manifest(Keying::Current, csprng)?);
        Ok(effects)
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
    fn on_resync<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.require_write()?;
        if self.docs.contains_key(&doc) {
            self.publish(doc, csprng)
        } else {
            // Nothing known about this document yet; nothing to re-announce.
            Ok(Vec::new())
        }
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
                    self.publish_keyed(doc, Keying::Fresh, csprng)?
                } else {
                    Vec::new()
                }
            }
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
    fn on_certs_arrived(&mut self, certs: Vec<Certificate>) -> Result<Vec<Effect>, CoreError> {
        if self.cgka.absorb_certificates(certs) > 0 {
            self.cgka.merge_pending()?;
            self.drain_pending()
        } else {
            Ok(Vec::new())
        }
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

    /// Encrypt and emit the current state of a document under the current epoch.
    fn publish<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.publish_keyed(doc, Keying::Current, csprng)
    }

    /// Encrypt and emit the current state of a document.
    fn publish_keyed<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        keying: Keying,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let loro = self.docs.entry(doc).or_default();

        // Ship the whole document history. A production build would export
        // updates since the last acknowledged version vector; shipping
        // everything keeps this deterministic and correct while the transport
        // has no per-peer acknowledgement to key off, and makes each chunk
        // self-sufficient under loss.
        let update = loro
            .export(ExportMode::all_updates())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;

        // Bind this chunk to the last state we know of for this document.
        let preds: Vec<ChunkRef> = self.last_ref.get(&doc).copied().into_iter().collect();
        let (chunk, ops) = self.encrypt_keyed(&update, &preds, keying, csprng)?;
        self.last_ref.insert(doc, chunk.content_ref);

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
            if let Some((_, evicted)) = self.pending_chunks.pop_front() {
                self.pending_bytes = self.pending_bytes.saturating_sub(evicted.ciphertext.len());
                self.evicted_chunks += 1;
            }
        }
        self.pending_bytes += size;
        self.pending_chunks.push_back((doc, chunk));
    }

    /// Retry every parked chunk, repeating while progress is being made.
    ///
    /// Progress is counted as *applications*, not as effects: a repair request
    /// is an effect too, and counting it would spin this loop forever over a
    /// chunk that can never apply.
    fn drain_pending(&mut self) -> Result<Vec<Effect>, CoreError> {
        let mut effects = Vec::new();
        loop {
            let candidates = std::mem::take(&mut self.pending_chunks);
            self.pending_bytes = 0;
            let mut applied = 0_usize;
            for (doc, chunk) in candidates {
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
                    ChunkVerdict::AwaitingKey | ChunkVerdict::AwaitingDeps => {
                        self.pending_bytes += chunk.ciphertext.len();
                        self.pending_chunks.push_back((doc, chunk));
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
        let loro = self.docs.entry(doc).or_default();
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
    let doc = LoroDoc::new();
    doc.import(bytes)
        .map_err(|e| CoreError::Manifest(e.to_string()))?;
    Ok(doc)
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
