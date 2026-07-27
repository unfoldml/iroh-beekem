//! Content references and the on-the-wire ciphertext type.

use beekem::encrypted::EncryptedContent;
use serde::{Deserialize, Serialize};

/// An opaque, fixed-length reference to one encrypted content chunk.
///
/// This is the BLAKE3 hash of the *plaintext* chunk. It plays two roles:
///
/// * it is the `ContentRef` beekem binds each application secret to, so a
///   ciphertext can only ever be decrypted under the ref it was encrypted for;
/// * together with `pred_refs` it reconstructs the causal DAG of edits, which
///   is what makes decryption order-independent.
///
/// Fixed length matters on the storage side too: variable-length keys leak
/// path depth and filename length during range-based set reconciliation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct ChunkRef(pub [u8; 32]);

impl ChunkRef {
    /// Compute the reference for a plaintext chunk.
    #[must_use]
    pub fn of(plaintext: &[u8]) -> Self {
        Self(blake3::hash(plaintext).into())
    }

    /// The raw bytes of this reference.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for ChunkRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

/// Phantom tag recording that a ciphertext's plaintext is a CRDT update chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrdtChunk;

/// A ciphertext exactly as it is stored in `iroh-blobs`.
///
/// Note that we deliberately do *not* define an envelope of our own. beekem's
/// [`EncryptedContent`] already carries the nonce, the `Digest<PcsKey>`, the
/// digest of the PCS update operation, the content ref and the predecessor
/// refs — everything a receiving peer needs to ask its own CGKA for the
/// decryption key. Wrapping it again would only add a second, redundant, and
/// potentially inconsistent copy of that metadata.
pub type Chunk = EncryptedContent<CrdtChunk, ChunkRef>;

#[cfg(test)]
mod tests {
    use super::ChunkRef;

    #[test]
    fn ref_of_is_deterministic() {
        assert_eq!(
            ChunkRef::of(b"hello"),
            ChunkRef::of(b"hello"),
            "the same plaintext must always produce the same chunk ref"
        );
    }

    #[test]
    fn ref_of_distinguishes_different_plaintexts() {
        assert_ne!(
            ChunkRef::of(b"hello"),
            ChunkRef::of(b"world"),
            "different plaintexts must produce different chunk refs"
        );
    }
}
