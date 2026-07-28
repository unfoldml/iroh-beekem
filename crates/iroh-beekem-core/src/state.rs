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

use beekem::{id::MemberId, operation::CgkaOperation};
use keyhive_crypto::{share_key::ShareKey, signed::Signed};
use loro::{ExportMode, LoroDoc};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    blinding::{DocumentUuid, StorageKey, WorkspaceSecret},
    content::{Chunk, ChunkRef},
    error::CoreError,
    keys::{CgkaController, ControlOp, DecryptOutcome, EpochId, MergeOutcome},
    manifest::{FileEntry, Manifest, Role, WorkspaceInfo},
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
    /// One document, named by the UUID both sides already agree on.
    Document(DocumentUuid),
    /// The workspace manifest.
    Manifest,
}

/// Something that happened to this node.
#[derive(Debug, Clone)]
pub enum Event {
    /// A signed CGKA operation arrived on the control plane.
    ControlOp(ControlOp),
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
    /// Broadcast a CGKA operation to every peer.
    ///
    /// Dropping one of these is not a recoverable performance choice: peers
    /// that miss it cannot derive the keys for anything encrypted afterwards.
    BroadcastOp(Box<Signed<CgkaOperation>>),
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
        let docs = self
            .docs
            .iter()
            .map(|(uuid, doc)| {
                let copy = LoroDoc::new();
                if let Ok(bytes) = doc.export(ExportMode::Snapshot) {
                    let _ = copy.import(&bytes);
                }
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
    #[must_use]
    pub fn joined(cgka: CgkaController, secret: WorkspaceSecret) -> Self {
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
        let this = Self::joined(cgka, secret);
        // The founder is their own user, and this device is that user's first —
        // which makes the user id and the member id the same bytes here, and
        // only here. All three records are needed: without the device record
        // the founder's own leaf resolves to no user, hence to no role, and the
        // workspace would begin with an admin nobody can look up.
        let me = this.member_id().to_bytes();
        this.manifest.set_user(&me, "")?;
        this.manifest.set_device(&me, &me, "first device")?;
        this.manifest.set_role(&me, Role::Admin)?;
        Ok(this)
    }

    /// This node's CGKA identity.
    #[must_use]
    pub fn member_id(&self) -> MemberId {
        self.cgka.member_id()
    }

    /// The workspace manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
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
            Event::Rotate => {
                let op = self.cgka.rotate(csprng)?;
                Ok(vec![Effect::BroadcastOp(Box::new(op))])
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
            Event::SetRole { user, role } => {
                self.require_admin()?;
                if !role.can_administer() {
                    self.require_not_last_admin(&user)?;
                }
                self.manifest.set_role(&user, role)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::SetInfo { info } => {
                self.require_admin()?;
                self.manifest.set_info(&info)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::SetDisplayName { display_name } => {
                let me = self.cgka.member_id().to_bytes();
                let user = self.manifest.user_of(&me).ok_or(CoreError::UnknownDevice)?;
                self.manifest.set_user(&user, &display_name)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::AnnounceAuthor { author } => {
                self.manifest
                    .set_author(&self.cgka.member_id().to_bytes(), &author)?;
                self.publish_manifest(Keying::Current, csprng)
            }
            Event::ResyncManifest => self.publish_manifest(Keying::Current, csprng),
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
        if self
            .manifest
            .role_of_member(&me)
            .is_some_and(Role::can_administer)
        {
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
        if self.manifest.user_of(&me) == Some(*user) {
            return Ok(());
        }
        if self
            .manifest
            .role_of_member(&me)
            .is_some_and(Role::can_administer)
        {
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

    /// Admit a new person along with their first device.
    ///
    /// The caller checks the permission; this writes the records. All three go
    /// in together because a leaf with no device record has no user, so it has
    /// no role, so every peer's `author_may_write` rejects its entries — the
    /// new member would appear to join and then silently fail to publish
    /// anything.
    fn on_add_user<R: CryptoRng + RngCore>(
        &mut self,
        member: MemberId,
        share_key: ShareKey,
        role: Role,
        display_name: &str,
        endpoint: Option<[u8; 32]>,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        self.admit(member, share_key, csprng, |manifest, member| {
            manifest.set_user(member, display_name)?;
            manifest.set_device(member, member, "first device")?;
            // Strictly after `set_device`, which creates the record this
            // attaches to; reversed, it returns `UnknownDevice`.
            if let Some(endpoint) = endpoint {
                manifest.set_device_endpoint(member, &endpoint)?;
            }
            manifest.set_role(member, role)
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
        self.admit(member, share_key, csprng, |manifest, member| {
            manifest.set_device(member, user, label)?;
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
            .manifest
            .user_of(&member.to_bytes())
            .unwrap_or_else(|| member.to_bytes());
        if self.manifest.devices_of(&owner).len() <= 1 {
            self.require_not_last_admin(&owner)?;
        }
        let op = self.cgka.remove_member(member)?;
        Ok(op
            .map(|o| Effect::BroadcastOp(Box::new(o)))
            .into_iter()
            .collect())
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
        let mut effects: Vec<Effect> = op
            .map(|o| Effect::BroadcastOp(Box::new(o)))
            .into_iter()
            .collect();
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
        match self.manifest.role_of_member(&me) {
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
            .manifest
            .role_of(member)
            .is_some_and(Role::can_administer);
        if is_admin && self.manifest.admin_count() <= 1 {
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
        let mut effects: Vec<Effect> = ops
            .into_iter()
            .map(|op| Effect::BroadcastOp(Box::new(op)))
            .collect();
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

    fn on_control_op(&mut self, op: ControlOp) -> Result<Vec<Effect>, CoreError> {
        let outcome = self.cgka.merge(op)?;
        if outcome == MergeOutcome::Applied {
            self.cgka.merge_pending()?;
            // New key material may have unblocked chunks that previously had
            // no reachable PCS key.
            return self.drain_pending();
        }
        Ok(Vec::new())
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
        let mut effects: Vec<Effect> = ops
            .into_iter()
            .map(|op| Effect::BroadcastOp(Box::new(op)))
            .collect();
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
