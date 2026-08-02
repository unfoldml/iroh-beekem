//! Blinded storage keys: hiding file names and paths from syncing peers.
//!
//! `iroh-docs` reconciles entries by key, and those keys cross the wire in the
//! clear during range-based set reconciliation. Storing `"finance/q3.json"` as
//! a key would therefore publish the entire directory tree to anyone who can
//! sync the replica.
//!
//! Two properties matter, and hashing the path directly gives neither:
//!
//! * **Fixed length.** A key derived from a path leaks the path's length, and
//!   thus a great deal about its depth and contents. Every key here is exactly
//!   32 bytes regardless of the logical path.
//! * **Stability across renames.** Keys are derived from a random
//!   [`DocumentUuid`], never from the path, so moving `/finance/q3.json` to
//!   `/archive/2026-q3.json` changes only a field inside the encrypted
//!   manifest. If keys were derived from paths, a rename would mean deleting
//!   and re-inserting entries on every peer.
//!
//! What this does *not* hide: the number of entries, their sizes, their
//! authors, and when they change. Blinding conceals names, not traffic.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Domain separator for storage-key derivation.
const STORAGE_KEY_CONTEXT: &[u8] = b"iroh-beekem/storage-key/v1";

/// Domain separator for the manifest's well-known key.
const MANIFEST_LABEL: &[u8] = b"iroh-beekem/manifest/v1";

/// Domain separator for per-workspace author-key derivation.
const AUTHOR_SEED_CONTEXT: &str = "iroh-beekem/author-seed/v1";

/// Domain separator for the entry holding an asset's wrapped content key.
const ASSET_KEY_LABEL: &[u8] = b"iroh-beekem/asset-key/v1";

/// Domain separator for the blinded prefix an asset's segments share.
const ASSET_PART_LABEL: &[u8] = b"iroh-beekem/asset-part/v1";

/// How many bytes of an asset segment key are the blinded per-asset prefix.
///
/// The remaining eight carry the segment index, big-endian so the keys sort into
/// segment order — which is what makes a range query over one asset's segments
/// contiguous.
const ASSET_PREFIX_BYTES: usize = 24;

/// A random, stable identifier for one logical document.
///
/// Unlike a path, this never changes over a document's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DocumentUuid(pub [u8; 16]);

impl DocumentUuid {
    /// Draw a fresh identifier.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        let mut bytes = [0u8; 16];
        csprng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// A 32-byte blinded key, as written into `iroh-docs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StorageKey(pub [u8; 32]);

impl StorageKey {
    /// The raw bytes to hand to `iroh-docs`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for StorageKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The long-lived secret from which all blinding is derived.
///
/// This is *not* a content encryption key — content is encrypted under
/// per-chunk application secrets from the CGKA. This secret only blinds
/// storage keys, so it can be distributed once at invite time and does not
/// rotate on membership change.
///
/// # Revocation caveat
///
/// Because it does not rotate, a revoked member retains the ability to
/// recognise which blinded key corresponds to which document UUID they already
/// knew about. They cannot read any content, and cannot learn about documents
/// created after their removal without also learning the UUID. Rotating this
/// secret would force every peer to rewrite every entry, which is why it is a
/// deliberate trade rather than an oversight.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WorkspaceSecret([u8; 32]);

impl std::fmt::Debug for WorkspaceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkspaceSecret([redacted])")
    }
}

impl WorkspaceSecret {
    /// Wrap existing secret bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Draw a fresh workspace secret.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Expose the raw bytes, for inclusion in an invite.
    ///
    /// The invite must be delivered confidentially; unlike the CGKA operation
    /// log, this *is* a secret.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Derive the blinded `iroh-docs` key for a document.
    #[must_use]
    pub fn storage_key(&self, doc: DocumentUuid) -> StorageKey {
        let mut input = Vec::with_capacity(STORAGE_KEY_CONTEXT.len() + 16);
        input.extend_from_slice(STORAGE_KEY_CONTEXT);
        input.extend_from_slice(&doc.0);
        StorageKey(blake3::keyed_hash(&self.0, &input).into())
    }

    /// Derive the well-known blinded key at which the manifest lives.
    ///
    /// Every member needs to find the manifest without being told where it is,
    /// so unlike document keys this one is derived from a constant label.
    #[must_use]
    pub fn manifest_key(&self) -> StorageKey {
        StorageKey(blake3::keyed_hash(&self.0, MANIFEST_LABEL).into())
    }

    /// Derive the blinded key at which an asset's wrapped content key lives.
    ///
    /// A full-width MAC like [`Self::storage_key`], because there is exactly one
    /// of these per asset and nothing needs to enumerate them by prefix.
    #[must_use]
    pub fn asset_key_key(&self, asset: DocumentUuid) -> StorageKey {
        let mut input = Vec::with_capacity(ASSET_KEY_LABEL.len() + 16);
        input.extend_from_slice(ASSET_KEY_LABEL);
        input.extend_from_slice(&asset.0);
        StorageKey(blake3::keyed_hash(&self.0, &input).into())
    }

    /// The blinded prefix every segment of one asset shares.
    ///
    /// # Why a prefix at all, when every other key here is a full-width MAC
    ///
    /// Because `iroh-docs` decides what to *download* by matching key prefixes,
    /// and without a prefix to name there is no way to say "index these entries
    /// but do not fetch their payloads". Every member would then auto-download
    /// every asset the moment its entries reconciled — which is exactly the
    /// "slowing down document synchronization" the large-asset user story rules
    /// out, and it would do it with multi-gigabyte payloads on machines that may
    /// never open the file.
    ///
    /// The cost is that a syncing peer can tell which entries belong to one
    /// asset, and therefore count its segments. That is a size to segment
    /// granularity, which the padding already concedes, and it is visible in the
    /// traffic regardless: blinding conceals names, not volume.
    #[must_use]
    pub fn asset_prefix(&self, asset: DocumentUuid) -> [u8; ASSET_PREFIX_BYTES] {
        let mut input = Vec::with_capacity(ASSET_PART_LABEL.len() + 16);
        input.extend_from_slice(ASSET_PART_LABEL);
        input.extend_from_slice(&asset.0);
        let full: [u8; 32] = blake3::keyed_hash(&self.0, &input).into();
        let mut prefix = [0u8; ASSET_PREFIX_BYTES];
        prefix.copy_from_slice(&full[..ASSET_PREFIX_BYTES]);
        prefix
    }

    /// Derive the blinded key for one segment of an asset.
    ///
    /// Still exactly 32 bytes, like every other key here: 24 of blinded prefix
    /// and 8 of big-endian index. Fixed width is the same property
    /// [`Self::storage_key`] needs — a variable-length key leaks through the
    /// range reconciliation that carries it.
    #[must_use]
    pub fn asset_part_key(&self, asset: DocumentUuid, part: u64) -> StorageKey {
        let mut key = [0u8; 32];
        key[..ASSET_PREFIX_BYTES].copy_from_slice(&self.asset_prefix(asset));
        key[ASSET_PREFIX_BYTES..].copy_from_slice(&part.to_be_bytes());
        StorageKey(key)
    }

    /// Derive this member's author seed for this workspace.
    ///
    /// `iroh-docs` signs every entry with an `AuthorId` that syncs in the
    /// clear, so the seed has to satisfy two properties at once, and both
    /// inputs are load-bearing:
    ///
    /// * **Unlinkable across workspaces**, from the workspace secret. Reusing a
    ///   long-term identity would let anyone who can sync two workspaces tie
    ///   them to the same device.
    /// * **Distinct across members**, from `member`. The workspace secret is
    ///   shared by everyone — it travels in the invite — so deriving from it
    ///   alone would hand every member of a workspace *the same* author id.
    ///   That would collapse [`WorkspaceState::author_may_write`] into a single
    ///   map entry that each member overwrites in turn, and with it every
    ///   per-author decision the data plane makes.
    ///
    /// It must also be stable across restarts: an author id that changes when
    /// the process does is one whose entries every peer rejects until an admin
    /// grants a role to an identity nobody has seen. That is what makes this a
    /// derivation rather than a stored random value — `Workspace::assemble` calls
    /// it on every start and gets the same author back.
    ///
    /// [`WorkspaceState::author_may_write`]: crate::state::WorkspaceState::author_may_write
    #[must_use]
    pub fn author_seed(&self, member: &[u8; 32]) -> [u8; 32] {
        // Concatenated rather than chained: BLAKE3's key material is a byte
        // string, and both halves are fixed-length, so there is no ambiguity
        // about where the secret ends and the member begins.
        let mut material = Zeroizing::new([0u8; 64]);
        material[..32].copy_from_slice(&self.0);
        material[32..].copy_from_slice(member);
        blake3::derive_key(AUTHOR_SEED_CONTEXT, material.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{DocumentUuid, WorkspaceSecret};

    fn secret(seed: u64) -> WorkspaceSecret {
        WorkspaceSecret::generate(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    #[test]
    fn storage_keys_are_deterministic_for_the_same_secret_and_uuid() {
        let s = secret(1);
        let doc = DocumentUuid([7u8; 16]);
        assert_eq!(
            s.storage_key(doc),
            s.storage_key(doc),
            "the same workspace secret and UUID must always blind to the same key"
        );
    }

    #[test]
    fn storage_keys_differ_across_documents() {
        let s = secret(1);
        assert_ne!(
            s.storage_key(DocumentUuid([1u8; 16])),
            s.storage_key(DocumentUuid([2u8; 16])),
            "distinct documents must not collide on a storage key"
        );
    }

    #[test]
    fn storage_keys_differ_across_workspaces() {
        let doc = DocumentUuid([7u8; 16]);
        assert_ne!(
            secret(1).storage_key(doc),
            secret(2).storage_key(doc),
            "a peer without the workspace secret must not be able to recognise a document"
        );
    }

    #[test]
    fn manifest_key_is_distinct_from_any_document_key() {
        let s = secret(1);
        let manifest = s.manifest_key();
        // The manifest label is a constant, so a document UUID cannot be chosen
        // to collide with it without breaking BLAKE3.
        assert_ne!(
            manifest,
            s.storage_key(DocumentUuid([0u8; 16])),
            "the manifest must not share a key with a document"
        );
    }

    #[test]
    fn asset_segment_keys_are_contiguous_under_one_prefix() {
        // What makes a download policy expressible: the segments of one asset
        // share a prefix, and nothing else does.
        let s = secret(1);
        let asset = DocumentUuid([3u8; 16]);
        let prefix = s.asset_prefix(asset);
        for part in [0u64, 1, 7, u64::MAX] {
            assert!(
                s.asset_part_key(asset, part).0.starts_with(&prefix),
                "segment {part} must fall under its asset's prefix, or no \
                 download policy can name the asset's key space"
            );
        }
    }

    #[test]
    fn asset_segment_keys_are_distinct_per_segment_and_per_asset() {
        let s = secret(1);
        let first = DocumentUuid([3u8; 16]);
        let second = DocumentUuid([4u8; 16]);
        assert_ne!(
            s.asset_part_key(first, 0),
            s.asset_part_key(first, 1),
            "two segments of one asset must not collide, or the second \
             overwrites the first in the index"
        );
        assert_ne!(
            s.asset_part_key(first, 0),
            s.asset_part_key(second, 0),
            "two assets must not share a segment key"
        );
    }

    #[test]
    fn an_assets_key_entry_is_distinct_from_its_segments_and_from_a_document() {
        // Three key spaces derived from the same secret and the same UUID, kept
        // apart by their domain separators. Sharing one would have an asset's
        // wrapped content key silently overwrite a document, or a segment
        // overwrite the key that decrypts it.
        let s = secret(1);
        let uuid = DocumentUuid([5u8; 16]);
        assert_ne!(
            s.asset_key_key(uuid),
            s.asset_part_key(uuid, 0),
            "an asset's key entry must not collide with its first segment"
        );
        assert_ne!(
            s.asset_key_key(uuid),
            s.storage_key(uuid),
            "an asset's key entry must not collide with a document of the same uuid"
        );
        assert_ne!(
            s.asset_key_key(uuid),
            s.manifest_key(),
            "an asset's key entry must not collide with the manifest"
        );
    }

    #[test]
    fn asset_keys_differ_across_workspaces() {
        let uuid = DocumentUuid([7u8; 16]);
        assert_ne!(
            secret(1).asset_part_key(uuid, 0),
            secret(2).asset_part_key(uuid, 0),
            "a peer without the workspace secret must not be able to recognise \
             an asset segment"
        );
    }

    #[test]
    fn author_seed_is_workspace_specific() {
        let alice = [1u8; 32];
        assert_ne!(
            secret(1).author_seed(&alice),
            secret(2).author_seed(&alice),
            "the same device in two workspaces must not present the same author identity"
        );
    }

    #[test]
    fn author_seed_is_member_specific() {
        // The workspace secret is shared by every member — it travels in the
        // invite — so a derivation keyed on it alone gives every member of a
        // workspace the same author id. That silently collapses
        // `Manifest::author_may_write` into one entry each member overwrites,
        // and with it every per-author decision on the data plane.
        let s = secret(1);
        assert_ne!(
            s.author_seed(&[1u8; 32]),
            s.author_seed(&[2u8; 32]),
            "two members of one workspace must not derive the same author identity"
        );
    }

    #[test]
    fn author_seed_is_stable_for_the_same_inputs() {
        // Restart stability: an author id that changes with the process is one
        // whose entries every peer rejects until an admin re-grants a role.
        let s = secret(1);
        let member = [7u8; 32];
        assert_eq!(
            s.author_seed(&member),
            s.author_seed(&member),
            "the same secret and member must always derive the same author identity"
        );
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let s = WorkspaceSecret::new([0xab; 32]);
        assert!(
            !format!("{s:?}").contains("ab"),
            "Debug must not print secret material, got {s:?}"
        );
    }
}
