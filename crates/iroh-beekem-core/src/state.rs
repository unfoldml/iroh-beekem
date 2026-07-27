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

use std::collections::HashMap;

use beekem::{id::MemberId, operation::CgkaOperation};
use keyhive_crypto::{share_key::ShareKey, signed::Signed};
use loro::{ExportMode, LoroDoc};
use rand::{CryptoRng, RngCore};

use crate::{
    blinding::{DocumentUuid, StorageKey, WorkspaceSecret},
    content::{Chunk, ChunkRef},
    error::CoreError,
    keys::{CgkaController, ControlOp, MergeOutcome},
    manifest::Manifest,
};

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
    /// A remote chunk was decrypted and merged into a local document.
    Applied {
        /// Which document changed.
        doc: DocumentUuid,
    },
}

/// One node's complete workspace state.
pub struct WorkspaceState {
    cgka: CgkaController,
    secret: WorkspaceSecret,
    manifest: Manifest,
    docs: HashMap<DocumentUuid, LoroDoc>,
    /// Chunks that could not yet be decrypted or merged.
    pending_chunks: Vec<(DocumentUuid, Chunk)>,
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
    #[must_use]
    pub fn new(cgka: CgkaController, secret: WorkspaceSecret) -> Self {
        Self {
            cgka,
            secret,
            manifest: Manifest::new(),
            docs: HashMap::new(),
            pending_chunks: Vec::new(),
        }
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
                    self.pending_chunks.push((doc, *chunk));
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
                let op = self.cgka.add_member(member, share_key)?;
                Ok(op.map(|o| Effect::BroadcastOp(Box::new(o))).into_iter().collect())
            }
            Event::RemoveMember { member } => {
                let op = self.cgka.remove_member(member)?;
                Ok(op.map(|o| Effect::BroadcastOp(Box::new(o))).into_iter().collect())
            }
            Event::Rotate => {
                let op = self.cgka.rotate(csprng)?;
                Ok(vec![Effect::BroadcastOp(Box::new(op))])
            }
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

        let preds: Vec<ChunkRef> = Vec::new();
        let (chunk, implicit_op) = self.cgka.encrypt(&update, &preds, csprng)?;

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

    /// Retry every parked chunk, repeating while progress is being made.
    fn drain_pending(&mut self) -> Result<Vec<Effect>, CoreError> {
        let mut effects = Vec::new();
        loop {
            let candidates = std::mem::take(&mut self.pending_chunks);
            let before = effects.len();
            for (doc, chunk) in candidates {
                if self.try_apply(doc, &chunk) {
                    effects.push(Effect::Applied { doc });
                } else {
                    // Not applicable yet: park it and try again next time new
                    // key material or new operations arrive.
                    self.pending_chunks.push((doc, chunk));
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
        matches!(loro.import(&plaintext), Ok(status) if status.pending.is_none())
    }
}
