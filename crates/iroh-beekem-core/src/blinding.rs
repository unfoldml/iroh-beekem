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
    ///   That would collapse [`Manifest::author_may_write`] into a single map
    ///   entry that each member overwrites in turn, and with it every
    ///   per-author decision the data plane makes.
    ///
    /// It must also be stable across restarts: an author id that changes when
    /// the process does is one whose entries every peer rejects until an admin
    /// grants a role to an identity nobody has seen.
    ///
    /// [`Manifest::author_may_write`]: crate::manifest::Manifest::author_may_write
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
