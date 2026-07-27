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

use std::collections::{HashMap, VecDeque};

use beekem::{id::MemberId, operation::CgkaOperation};
use keyhive_crypto::{share_key::ShareKey, signed::Signed};
use loro::{ExportMode, LoroDoc};
use rand::{CryptoRng, RngCore};

use crate::{
    blinding::{DocumentUuid, StorageKey, WorkspaceSecret},
    content::{Chunk, ChunkRef},
    error::CoreError,
    keys::{CgkaController, ControlOp, MergeOutcome},
    manifest::{FileEntry, Manifest, Role},
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
    /// The local user admitted a new member.
    AddMember {
        /// The new member's identity.
        member: MemberId,
        /// The new member's published leaf key.
        share_key: ShareKey,
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
        /// The member whose role changes, as raw verifying-key bytes.
        member: [u8; 32],
        /// The role to assign.
        role: Role,
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
    /// A remote chunk was decrypted and merged into a local document.
    Applied {
        /// Which document changed.
        doc: DocumentUuid,
    },
    /// A remote manifest replica was decrypted and merged.
    ManifestUpdated,
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
    /// The most recent chunk this node published or applied, per document.
    ///
    /// This is what makes each chunk's key causally bound rather than bound to
    /// nothing: beekem mixes the predecessor refs into the derived application
    /// secret, so a chunk names the state it follows. The receiver does not
    /// need the predecessor chunk to decrypt — the digest travels inside the
    /// ciphertext's metadata — so this costs nothing in liveness.
    last_ref: HashMap<DocumentUuid, ChunkRef>,
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
            last_ref: self.last_ref.clone(),
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
            last_ref: HashMap::new(),
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
        this.manifest
            .set_role(&this.member_id().to_bytes(), Role::Admin)?;
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
            Event::ChunkArrived { doc, chunk } => {
                // The data plane re-offers the same entry on every sync round,
                // so without this the parked list would grow without bound and
                // every drain would redo the same failed decryptions.
                let already_parked = self.pending_chunks.iter().any(|(d, c)| {
                    *d == doc
                        && c.content_ref == chunk.content_ref
                        && c.pcs_key_hash == chunk.pcs_key_hash
                });
                if !already_parked {
                    self.park_chunk(doc, *chunk);
                }
                self.drain_pending()
            }
            Event::LocalEdit { doc, text } => self.on_local_edit(doc, &text, csprng),
            Event::Resync { doc } => {
                if self.docs.contains_key(&doc) {
                    self.publish(doc, csprng)
                } else {
                    // Nothing known about this document yet; nothing to re-announce.
                    Ok(Vec::new())
                }
            }
            Event::AddMember { member, share_key } => {
                self.require_admin()?;
                let op = self.cgka.add_member(member, share_key)?;
                if op.is_some() {
                    // A new member is useless without a role: with none, every
                    // peer's `author_may_write` check rejects their entries and
                    // they would appear to join successfully and then silently
                    // fail to publish anything.
                    self.manifest.set_role(&member.to_bytes(), Role::Editor)?;
                }
                let mut effects: Vec<Effect> =
                    op.map(|o| Effect::BroadcastOp(Box::new(o))).into_iter().collect();
                effects.extend(self.publish_manifest(csprng)?);
                Ok(effects)
            }
            Event::RemoveMember { member } => {
                self.require_admin()?;
                self.require_not_last_admin(&member.to_bytes())?;
                let op = self.cgka.remove_member(member)?;
                Ok(op.map(|o| Effect::BroadcastOp(Box::new(o))).into_iter().collect())
            }
            Event::Rotate => {
                let op = self.cgka.rotate(csprng)?;
                Ok(vec![Effect::BroadcastOp(Box::new(op))])
            }
            Event::ManifestArrived { chunk } => {
                // No parking queue for the manifest: it is re-published on every
                // change and on every resync, so a copy that cannot be decrypted
                // yet is replaced by one that can, rather than needing to be
                // held. Holding it would also mean a second unbounded queue.
                let Ok(plaintext) = self.cgka.decrypt(&chunk) else {
                    return Ok(Vec::new());
                };
                self.manifest.import(&plaintext)?;
                Ok(vec![Effect::ManifestUpdated])
            }
            Event::UpsertFile { entry } => {
                self.manifest.upsert_file(&entry)?;
                self.publish_manifest(csprng)
            }
            Event::RenameFile { doc, path } => {
                self.manifest.rename(doc, &path)?;
                self.publish_manifest(csprng)
            }
            Event::SetRole { member, role } => {
                self.require_admin()?;
                if !role.can_administer() {
                    self.require_not_last_admin(&member)?;
                }
                self.manifest.set_role(&member, role)?;
                self.publish_manifest(csprng)
            }
            Event::AnnounceAuthor { author } => {
                self.manifest
                    .set_author(&self.cgka.member_id().to_bytes(), &author)?;
                self.publish_manifest(csprng)
            }
        }
    }

    /// Refuse an administrative action unless the local member is an admin.
    ///
    /// This is the *permissions* layer, not the cryptographic one, and it binds
    /// only well-behaved peers: a member holding a leaf can still decrypt
    /// whatever the manifest says. Genuine read revocation is a CGKA removal.
    fn require_admin(&self) -> Result<(), CoreError> {
        let me = self.cgka.member_id().to_bytes();
        if self.manifest.role_of(&me).is_some_and(Role::can_administer) {
            return Ok(());
        }
        Err(CoreError::NotAnAdmin)
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

    /// Encrypt the manifest and emit it for storage at its well-known key.
    fn publish_manifest<R: CryptoRng + RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let snapshot = self.manifest.export_snapshot()?;
        let (chunk, implicit_op) = self.cgka.encrypt(&snapshot, &[], csprng)?;

        let mut effects = Vec::new();
        // As in `publish`: an implicit PCS update has to reach peers before the
        // ciphertext it keys, or nobody can read what follows.
        if let Some(op) = implicit_op {
            effects.push(Effect::BroadcastOp(Box::new(op)));
        }
        effects.push(Effect::StoreManifest {
            key: self.secret.manifest_key(),
            chunk: Box::new(chunk),
        });
        Ok(effects)
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

    fn on_local_edit<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
        text: &str,
        csprng: &mut R,
    ) -> Result<Vec<Effect>, CoreError> {
        let loro = self.docs.entry(doc).or_default();
        let content = loro.get_text("content");
        let at = content.len_utf8();
        content
            .insert(at, text)
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        loro.commit();

        self.publish(doc, csprng)
    }

    /// Encrypt and emit the current state of a document.
    fn publish<R: CryptoRng + RngCore>(
        &mut self,
        doc: DocumentUuid,
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
        let (chunk, implicit_op) = self.cgka.encrypt(&update, &preds, csprng)?;
        self.last_ref.insert(doc, chunk.content_ref);

        let mut effects = Vec::new();
        // The implicit PCS update must go out *before* anything else can read
        // the chunk, so it is emitted first.
        if let Some(op) = implicit_op {
            effects.push(Effect::BroadcastOp(Box::new(op)));
        }
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
    fn drain_pending(&mut self) -> Result<Vec<Effect>, CoreError> {
        let mut effects = Vec::new();
        loop {
            let candidates = std::mem::take(&mut self.pending_chunks);
            self.pending_bytes = 0;
            let before = effects.len();
            for (doc, chunk) in candidates {
                if self.try_apply(doc, &chunk) {
                    effects.push(Effect::Applied { doc });
                } else {
                    // Not applicable yet: re-queue and try again next time new
                    // key material or new operations arrive. Re-queueing goes
                    // through the plain path rather than `park_chunk`, because
                    // these chunks were already admitted under the budget and
                    // re-checking it here could evict a chunk mid-drain.
                    self.pending_bytes += chunk.ciphertext.len();
                    self.pending_chunks.push_back((doc, chunk));
                }
            }
            if effects.len() == before {
                return Ok(effects);
            }
        }
    }

    /// Attempt to decrypt and merge one chunk.
    ///
    /// Returns `false` when the chunk is simply not applicable yet — a missing
    /// key or a missing CRDT dependency — rather than treating the normal case
    /// of out-of-order delivery as a failure. A revoked member sees the same
    /// `false` forever, which is the intended outcome.
    fn try_apply(&mut self, doc: DocumentUuid, chunk: &Chunk) -> bool {
        let Ok(plaintext) = self.cgka.decrypt(chunk) else {
            return false;
        };
        let loro = self.docs.entry(doc).or_default();
        // Loro reports its own missing dependencies separately from the
        // key-availability question; both mean "not yet".
        let applied = matches!(loro.import(&plaintext), Ok(status) if status.pending.is_none());
        if applied {
            // Anything we publish next genuinely follows this chunk, so it is
            // the predecessor to name.
            self.last_ref.insert(doc, chunk.content_ref);
        }
        applied
    }
}
