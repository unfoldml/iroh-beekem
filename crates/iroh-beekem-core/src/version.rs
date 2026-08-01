//! Versions: naming a past state of a document, and dating the change that made
//! it.
//!
//! A document is a Loro replica, and Loro keeps every operation it has ever
//! merged. Everything in this module is therefore a *view* onto history the
//! engine already holds — nothing here makes a node store more than it did
//! before, and nothing here travels on the wire that did not travel before.
//!
//! # Time is supplied, never read
//!
//! Loro can stamp each change with the system clock, and this crate must not:
//! [`crate::state::WorkspaceState`] is driven by a deterministic simulator with
//! virtual time, and a state machine that read a clock could not be. Time is
//! passed into [`WorkspaceState::handle`] as [`UnixSeconds`] and set explicitly
//! on the commit, so the simulator supplies `cx.now()` and gets reproducible
//! version listings out of a seeded run.
//!
//! # How a change is attributed
//!
//! Loro attributes a change to a 64-bit *peer id*, which says nothing about
//! members. The mapping is recorded inside the document itself, in an `authors`
//! container each writing replica adds one entry to — see `claim_authorship` in
//! [`crate::state`], which also explains why the peer id is Loro's random default
//! rather than something derived from the member id. The short version is that
//! assigning a peer id also fixes the operation counter a replica writes next, so
//! a derived, reused id turns any local loss of history into a document that
//! mints operation ids which already exist.
//!
//! # What a version can and cannot prove
//!
//! Author is a **claim**, in the same sense as the self-attested author and
//! endpoint records in [`crate::manifest`]: the mapping lives in content any
//! member may write, so a member running a dishonest client could name somebody
//! else. What stops that mattering is what makes the manifest's claims safe — it
//! grants nothing. An entry is accepted because its *author key* may write, which
//! the capability closure decides; attribution only says who to thank.
//!
//! Time is weaker still: it is whatever the authoring node passed in. Loro raises
//! it to at least the greatest timestamp on the change's causal ancestry, so a
//! wrong clock cannot make a change look older than what it followed, but a node
//! with a fast clock can date its own work in the future.

use loro::Frontiers;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Seconds since the Unix epoch, as supplied by whoever drives the state machine.
///
/// A newtype rather than a bare `i64` because the core has no clock of its own:
/// every value of this type entered from outside, and naming it that way is what
/// stops a plain integer parameter being filled in with a duration, a lamport
/// value, or a byte count. Signed, and the sign is not decorative — it is Loro's
/// own `Timestamp`, and pre-1970 dates are representable rather than a wraparound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UnixSeconds(i64);

impl UnixSeconds {
    /// The epoch itself, and the value a caller uses when it has no clock.
    ///
    /// Tests that are not *about* time drive the machine at this instant; the
    /// resulting versions are still ordered, because ordering comes from the
    /// causal DAG rather than from the timestamp.
    pub const EPOCH: Self = Self(0);

    /// Wrap a count of seconds since the Unix epoch.
    #[must_use]
    pub const fn new(seconds: i64) -> Self {
        Self(seconds)
    }

    /// The raw count, for handing to Loro or formatting for a person.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for UnixSeconds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The identity of one past state of a document.
///
/// Opaque on purpose. Inside is an encoded Loro *frontier* — the set of change
/// ids that have no successor in that state — and it has to be a set rather than
/// a single id because concurrent edits are the normal case here: two members
/// editing while partitioned produce a state that follows both, and no one change
/// names it.
///
/// It is **not** a hash of the content. Two documents that read alike after
/// different histories have different version ids, which is the right answer for
/// "put it back the way it was on Tuesday": what is being named is a point in the
/// document's history, not a string that happened to appear at one.
///
/// A version id is meaningful in the document it came from and nowhere else, and
/// it is only resolvable on a replica that holds the history it names — a peer
/// that is behind will refuse it with [`CoreError::UnknownVersion`] until it
/// catches up.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionId(Vec<u8>);

impl VersionId {
    /// Name the state a set of frontiers describes.
    #[must_use]
    pub fn from_frontiers(frontiers: &Frontiers) -> Self {
        Self(frontiers.encode())
    }

    /// Recover the frontiers this id names.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::UnknownVersion`] if the bytes are not a frontier
    /// encoding at all — which is what a caller passing a value from somewhere
    /// else, or a truncated copy, produces.
    pub fn to_frontiers(&self) -> Result<Frontiers, CoreError> {
        Frontiers::decode(&self.0).map_err(|_| CoreError::UnknownVersion {
            version: self.to_string(),
        })
    }

    /// The raw encoding, for a caller that needs to store or transport one.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rebuild an id from [`Self::as_bytes`].
    ///
    /// Unvalidated here rather than fallible: the bytes are checked when they are
    /// resolved against a document, which is the only place that can tell a
    /// malformed encoding from one this replica has simply not caught up to.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for VersionId {
    /// Hex, truncated, in the style of [`ChunkRef`](crate::content::ChunkRef).
    ///
    /// For logs and for a person choosing between versions; the full encoding is
    /// [`VersionId::as_bytes`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.iter().take(6) {
            write!(f, "{byte:02x}")?;
        }
        if self.0.len() > 6 {
            f.write_str("..")
        } else {
            Ok(())
        }
    }
}

/// One version of a binary asset.
///
/// Documents and assets need the same feature and cannot share a mechanism.
/// A document's history is inside its CRDT, so a version is a point in it and a
/// revert is an inverse operation. An asset is immutable ciphertext under a key
/// drawn for it: there is no history to point into, so a version *is* a separate
/// body of segments, and the history is this list.
///
/// # Each version owns its key space
///
/// [`Self::content`] is the UUID that blinds the version's segment keys and the
/// entry holding its wrapped content key — see
/// [`WorkspaceSecret::asset_prefix`](crate::blinding::WorkspaceSecret::asset_prefix).
/// It is drawn fresh for each version, and that is what makes an older version
/// survive a newer one: publishing into the same key space would overwrite the
/// index entries, the old blobs would lose the only thing protecting them from
/// collection, and the previous version would be gone. It is also what keeps the
/// segment nonces safe, since each is derived from `(content, index)` under a key
/// drawn for that version alone.
///
/// # Reverting
///
/// Appending a version that names a `content` some earlier version already used.
/// No re-upload, no re-encryption, no new key: the ciphertext is immutable and
/// still indexed, so pointing at it again is a manifest write. That is the asset
/// counterpart of a document's forward revert, and it has the same property —
/// history only grows, so a revert can be reverted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetVersion {
    /// The UUID this version's segments and content key are blinded under.
    pub content: crate::blinding::DocumentUuid,
    /// Size, segmentation and plaintext digest of this version.
    pub meta: crate::asset::AssetMeta,
    /// The member that published it, self-attested like every author claim here.
    pub author: [u8; 32],
    /// When they published it, from their clock.
    pub at: UnixSeconds,
    /// One past the highest sequence the publisher had seen for this entry.
    ///
    /// A per-entry logical clock, and it is what decides precedence, because a
    /// wall clock cannot. Timestamps here are whole seconds, so a member
    /// attaching two versions in quick succession dates both the same and the
    /// order of their own writes would be settled by a coin toss between two
    /// random UUIDs — the second attachment losing to the first is not a race
    /// condition a caller can avoid, it is the common case.
    ///
    /// Derived from what the publisher had merged, so it orders *causally*: a
    /// version attached by somebody who had seen version 3 is 4 and wins, while
    /// two members who both attached without seeing the other's tie here and are
    /// separated by `(at, content)` below. That is the same shape as a Lamport
    /// clock and the same trade the rest of the manifest makes — a concurrent
    /// pair is ordered arbitrarily but *identically everywhere*, and the loser is
    /// still listed and still readable.
    pub seq: u64,
}

impl AssetVersion {
    /// This record's identity: a digest over everything in it.
    ///
    /// Versions are stored under this rather than under [`Self::content`], and
    /// the difference is what a revert *is*. Keyed by content, re-pointing at an
    /// earlier body would overwrite that body's original record — the history
    /// would show one entry whose date had silently moved, and the fact that a
    /// revert happened at all would be unrecoverable. Keyed by digest, the revert
    /// is a new record naming the same bytes, so the list only ever grows, which
    /// is the same property a document's forward revert has.
    ///
    /// Writing one record twice remains idempotent, since the key derives from
    /// the value.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        // As `Checkpoint::digest`: encoding a struct of owned, sized fields
        // cannot fail, and an all-zero digest is a usable key rather than a panic
        // if it ever does.
        postcard::to_stdvec(self).map_or([0u8; 32], |bytes| *blake3::hash(&bytes).as_bytes())
    }

    /// The order that decides which version of an entry is current.
    ///
    /// By value — `(seq, at, content)` — and never by position in the container,
    /// for the same reason [`NamespaceEpoch`](crate::state::NamespaceEpoch)
    /// compares `(epoch, digest)`: two members attaching concurrently would
    /// otherwise have "current" decided by Loro's internal ordering, which is a
    /// fact about operation ids rather than about what either member did, and a
    /// reader on one replica would open a different file from a reader on another.
    ///
    /// [`Self::seq`] leads because it is the only term that respects causality;
    /// the clock breaks ties between genuinely concurrent attachments and the
    /// UUID breaks ties between clocks that agree. Every term is a pure function
    /// of the record, so every replica computes the same order.
    #[must_use]
    pub fn precedence(&self) -> (u64, UnixSeconds, [u8; 16]) {
        (self.seq, self.at, self.content.0)
    }
}

/// A name given to a state of the whole workspace, in the spirit of a git tag.
///
/// Records the version *every* entry was at when it was taken, so restoring one
/// is a question about the workspace rather than about a file. An entry created
/// after the checkpoint is simply not named by it, and restoring does not delete
/// it: a checkpoint says "these files were like this", not "nothing else existed".
///
/// # Why this lives in the manifest
///
/// It is a claim that grants nothing — a label pointing at a version that already
/// exists — which is precisely the test [`crate::manifest`] applies to decide what
/// may live in an unconditional CRDT merge. Forging one at worst names a state the
/// forger could already read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// What a person calls it. Not unique — see [`Self::digest`].
    pub name: String,
    /// Why it was taken, if whoever took it said.
    pub message: String,
    /// The member that took it, self-attested like every other author claim.
    pub author: [u8; 32],
    /// When it was taken, from the clock of whoever took it.
    pub at: UnixSeconds,
    /// The version of each entry the workspace held at that moment.
    ///
    /// Sorted by UUID so that the encoding — and therefore [`Self::digest`] — is
    /// a function of the contents rather than of a map's iteration order.
    pub entries: Vec<(crate::blinding::DocumentUuid, VersionId)>,
}

impl Checkpoint {
    /// This checkpoint's identity: a digest over everything in it.
    ///
    /// Checkpoints are stored under this rather than under [`Self::name`], and
    /// the reason is the same one that keeps `role_of` separate from `ever_admin`.
    /// Two members tagging `v1.0` while partitioned would, under a name key, have
    /// one silently overwrite the other by whichever Loro ordering happened to
    /// win — a fact about operation ids rather than about what anybody did. Keyed
    /// by digest both survive, and a lookup by name resolves them by `(at,
    /// digest)`, which is a pure function of the values and so agrees everywhere.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        // Encoding failure is not reachable for a struct of owned, sized fields,
        // and an all-zero digest is a valid key rather than a panic if it ever is.
        postcard::to_stdvec(self).map_or([0u8; 32], |bytes| *blake3::hash(&bytes).as_bytes())
    }
}

/// What became of one entry named by a checkpoint being restored.
///
/// A sum type rather than a count, because "restored 3 of 5" leaves the caller
/// unable to say which two and why — and the two failures have different remedies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Put back to the version the checkpoint recorded.
    Restored(crate::blinding::DocumentUuid),
    /// Already at that version; nothing was published for it.
    Unchanged(crate::blinding::DocumentUuid),
    /// Deleted since the checkpoint was taken, so its history is gone.
    ///
    /// Terminal, and reported rather than skipped: deleting a document drops the
    /// replica, so no version of it survives anywhere this node can reach. A
    /// caller that saw a silent success would believe the workspace had been put
    /// back when a file is missing from it.
    Deleted(crate::blinding::DocumentUuid),
    /// Named by the checkpoint but not resolvable on this replica yet.
    ///
    /// Distinct from [`Self::Deleted`] because it is *not* terminal: the entry
    /// exists and this node is merely behind on its history. Restoring again
    /// after a sync is the remedy.
    Unavailable(crate::blinding::DocumentUuid),
}

/// One entry in a document's history.
///
/// A *change* in Loro's sense: the run of operations one commit produced. An edit
/// event therefore contributes one of these however many characters it touched,
/// which is what makes a version list the size of the edit history rather than
/// the size of the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// The state of the document immediately after this change.
    pub id: VersionId,
    /// The member whose device authored it, if the document says.
    ///
    /// `None` has one ordinary cause and one adversarial one, and they are not
    /// distinguishable here: the authoring replica wrote no claim, or the claim
    /// has not merged yet. Either way this is the honest answer — see the module
    /// documentation for why a *present* author is a claim rather than a proof.
    pub author: Option<[u8; 32]>,
    /// When the authoring node said it made the change.
    pub at: UnixSeconds,
    /// How many operations the change carries, as a rough size.
    pub ops: usize,
}

#[cfg(test)]
mod tests {
    use super::{UnixSeconds, VersionId};

    /// In a version id, upon being taken apart and put back together, we expect
    /// the same id — and the same frontiers.
    ///
    /// The round trip is the whole contract of the type: an id is opaque, so a
    /// caller that stores one has only these two functions to get it back, and a
    /// caller that stored a *displayed* id rather than its bytes would find that
    /// out the hard way. Hence a case where the two differ.
    #[test]
    fn a_version_id_survives_being_stored_as_bytes() {
        let id = VersionId::from_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            VersionId::from_bytes(id.as_bytes().to_vec()),
            id,
            "a version id must round-trip through the only encoding a caller has"
        );
        assert_eq!(
            id.to_string(),
            "010203040506..",
            "the display form is a truncated label for a person, and must stay \
             distinguishable from the encoding it is *not* a substitute for"
        );
        assert_eq!(
            VersionId::from_bytes(vec![9, 9]).to_string(),
            "0909",
            "an id short enough to print whole must not claim to be truncated"
        );
    }

    /// In an instant supplied by a caller, upon being displayed, we expect the
    /// seconds it was built from.
    ///
    /// Displayed as a bare count rather than a formatted date on purpose: this
    /// crate has no clock and no locale, and rendering a date is a decision for
    /// whoever is showing it to a person.
    #[test]
    fn an_instant_displays_as_the_count_it_wraps() {
        assert_eq!(UnixSeconds::new(1_700_000_000).to_string(), "1700000000");
        assert_eq!(
            UnixSeconds::EPOCH.to_string(),
            "0",
            "the epoch is a value like any other, not an absence"
        );
        assert_eq!(
            UnixSeconds::new(-1).to_string(),
            "-1",
            "the type is signed because Loro's is; a pre-epoch date must not wrap"
        );
    }
}
