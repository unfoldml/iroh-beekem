//! Large binary assets: fixed-size encrypted segments behind a wrapped key.
//!
//! Documents flow through Loro, so a chunk is a CRDT update and every publish is
//! a merge. An asset is not that. It is a fixed sequence of bytes that is written
//! once, read whole, and may be several gigabytes — and pushing it through the
//! same path would be wrong three times over: the plaintext would have to be
//! resident to be exported, the whole thing would be re-encrypted on every
//! republish, and it would sit in the parked-chunk budget waiting for
//! dependencies it does not have.
//!
//! # The envelope, and why the CGKA does not key the bytes directly
//!
//! Segments are encrypted with XChaCha20-Poly1305 under a **per-asset content
//! key**, drawn fresh for each asset, and it is that 32-byte key which is
//! encrypted to the group through the CGKA. The alternative — keying every
//! segment with a beekem application secret, as document chunks are — costs
//! nothing to write and everything to repair:
//!
//! * a member admitted after an asset was published cannot derive the epoch it
//!   was keyed under, and the only answer available is re-encrypting **every
//!   segment** under a fresh epoch. With the envelope, the answer is re-encrypting
//!   one 32-byte key chunk.
//! * a namespace rotation abandons the replica, and re-announcing the asset in
//!   the new one is a re-index of unchanged ciphertext rather than a re-upload.
//!
//! Nothing is weakened by the indirection. Anyone who could decrypt the segments
//! directly could equally decrypt the key that protects them, and forward secrecy
//! keeps the same granularity it had: an asset is immutable, so a new version
//! draws a new key wrapped at the current epoch, and a member removed at epoch
//! *e* cannot read a version published at *e+1*. What a removed member keeps is
//! what it could already read — which is true of every chunk in the system.
//!
//! # What is hidden and what is not
//!
//! Every segment is exactly [`ASSET_SEGMENT_BYTES`] of plaintext, the tail padded
//! and the true length recorded only inside the encrypted manifest, so a
//! syncing peer learns the size to segment granularity rather than to the byte.
//! It does learn the segment *count*, because the entries are there to be
//! counted — blinding conceals names, not traffic. An empty asset still has one
//! segment, so that everything from zero to four mebibytes looks alike.

use chacha20poly1305::{
    AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce, aead::generic_array::GenericArray,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{blinding::DocumentUuid, error::CoreError};

/// The default plaintext bytes per segment, before encryption.
///
/// Four mebibytes is a compromise between two costs that pull in opposite
/// directions. Larger segments mean fewer index entries and less per-segment
/// overhead, but a bigger resident buffer on both the writing and the reading
/// side — and the point of segmenting at all is that a multi-gigabyte asset
/// never has to be resident. Smaller segments mean the opposite, plus a longer
/// entry list in the replica for every peer to reconcile.
///
/// The *default*, not the only value: an asset records the size it was sealed
/// with in [`AssetMeta::segment_bytes`], because a workspace full of small
/// attachments should not pay four mebibytes of padding each. What must stay
/// uniform is the segmentation *within* one asset, which is what hides its exact
/// length; making it uniform across every asset in the world would hide nothing
/// extra, since the segment count is visible either way.
pub const ASSET_SEGMENT_BYTES: usize = 4 * 1024 * 1024;

/// Domain separator for per-segment nonce derivation.
const ASSET_NONCE_CONTEXT: &str = "iroh-beekem/asset-nonce/v1";

/// Domain separator for the whole-asset plaintext digest.
const ASSET_CONTENT_CONTEXT: &str = "iroh-beekem/asset-content/v1";

/// The symmetric key protecting one asset's segments.
///
/// Never leaves this crate in the clear: it travels wrapped in a [`Chunk`] the
/// CGKA keys, and it is zeroized on drop like every other secret here.
///
/// [`Chunk`]: crate::content::Chunk
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AssetKey([u8; 32]);

impl std::fmt::Debug for AssetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AssetKey([redacted])")
    }
}

impl AssetKey {
    /// Draw a fresh key for a new asset, or a new version of one.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wrap key bytes recovered from a decrypted key chunk.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for encrypting into the key chunk.
    ///
    /// Wrapped in [`Zeroizing`] so a caller cannot leave a copy on the stack by
    /// accident; the one legitimate caller hands them straight to the CGKA.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }
}

/// What the manifest records about an asset.
///
/// Everything here is a *claim*, in the same sense as a logical path or a display
/// name: the manifest is an unconditional CRDT merge, so any member can rewrite
/// it. That is why [`Self::content_hash`] is present. A forged `size` or
/// `segments` makes an export fail a digest check rather than silently return
/// the wrong bytes, which reduces the lie to a denial of service — something any
/// member can already do by overwriting a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetMeta {
    /// True length in bytes, before padding.
    pub size: u64,
    /// How many segments the asset occupies. Always at least one.
    pub segments: u64,
    /// Plaintext bytes per segment, before padding.
    ///
    /// Recorded rather than assumed so a reader can open an asset sealed with a
    /// different default, and authenticated in every segment's AAD so it cannot
    /// be changed after the fact by editing the manifest.
    pub segment_bytes: u32,
    /// BLAKE3 of the whole *unpadded* plaintext, for end-to-end verification.
    pub content_hash: [u8; 32],
}

impl AssetMeta {
    /// How many segments an asset of `size` bytes occupies at `segment_bytes`.
    ///
    /// At least one even for an empty asset, so that every asset from zero bytes
    /// to a full segment presents the same shape to a peer counting entries.
    /// Total in `segment_bytes`: zero would divide by zero, and one segment is
    /// the only sensible answer for a segmentation that cannot hold anything.
    #[must_use]
    pub fn segments_for(size: u64, segment_bytes: u32) -> u64 {
        let per = u64::from(segment_bytes);
        if per == 0 {
            return 1;
        }
        let full = size / per;
        if size.is_multiple_of(per) {
            full.max(1)
        } else {
            full + 1
        }
    }

    /// How many bytes of segment `index` are real rather than padding.
    ///
    /// Total in `index`: a segment past the end of the asset contributes
    /// nothing, which is the right answer for a manifest entry that has been
    /// tampered with rather than a reason to fail.
    #[must_use]
    pub fn payload_len(&self, index: u64) -> usize {
        let per = u64::from(self.segment_bytes);
        let start = index.saturating_mul(per);
        let remaining = self.size.saturating_sub(start);
        usize::try_from(remaining.min(per)).unwrap_or(usize::MAX)
    }
}

/// The result of decrypting one segment.
///
/// A sum type rather than a `Result<Vec<u8>, _>` because "cannot read this yet"
/// and "cannot ever read this" are different answers with different remedies,
/// exactly as they are for a document chunk — and collapsing them is how a peer
/// ends up waiting forever for content nobody will ever send it again.
#[derive(Debug)]
pub enum SegmentVerdict {
    /// Decrypted and authenticated.
    Plaintext(Zeroizing<Vec<u8>>),
    /// The operation establishing the key chunk's epoch has not arrived yet.
    /// It may still; nothing needs to be asked for.
    AwaitingKey,
    /// The key chunk is under an epoch this node can never derive. Only a
    /// re-encryption of the key chunk helps, and that is a repair to request.
    Unreachable,
    /// The key was recovered and authentication then failed: the ciphertext is
    /// damaged, or the manifest claims a position this segment does not hold.
    Corrupt,
}

/// The nonce for one segment.
///
/// Derived rather than random, and safe because of the one property the whole
/// scheme rests on: an asset's key is drawn fresh for that asset, and each
/// `(uuid, index)` pair is encrypted exactly once under it. Reusing a key across
/// two assets would break this, which is why [`AssetKey::generate`] is called per
/// asset and never cached across one.
fn segment_nonce(uuid: DocumentUuid, index: u64) -> XNonce {
    let mut material = Vec::with_capacity(24);
    material.extend_from_slice(&uuid.0);
    material.extend_from_slice(&index.to_be_bytes());
    let derived = blake3::derive_key(ASSET_NONCE_CONTEXT, &material);
    *XNonce::from_slice(&derived[..24])
}

/// The additional authenticated data binding a segment to its position.
///
/// Without it a valid segment could be moved: to another index of the same
/// asset, reordering the file, or — since the manifest is writable by any member
/// — used to claim a length the asset does not have. The AAD makes every such
/// move an authentication failure rather than a silently different file.
fn segment_aad(uuid: DocumentUuid, index: u64, segments: u64, segment_bytes: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(36);
    aad.extend_from_slice(&uuid.0);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&segments.to_be_bytes());
    aad.extend_from_slice(&segment_bytes.to_be_bytes());
    aad
}

/// Encrypt one segment, padding it to [`ASSET_SEGMENT_BYTES`] first.
///
/// `plaintext` is what the caller read from the source; anything short of a full
/// segment is zero-padded here rather than by the caller, so no code path can
/// produce a short segment and leak its length.
///
/// # Errors
///
/// Returns [`CoreError::MalformedSegment`] if the plaintext is longer than one
/// segment, which is a caller bug rather than a runtime condition, and
/// [`CoreError::Aead`] if the cipher itself refuses.
pub fn seal_segment(
    key: &AssetKey,
    uuid: DocumentUuid,
    index: u64,
    segments: u64,
    segment_bytes: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let width = segment_bytes as usize;
    if plaintext.len() > width {
        return Err(CoreError::MalformedSegment(format!(
            "a segment carries at most {width} bytes, got {}",
            plaintext.len()
        )));
    }
    let mut buffer = Zeroizing::new(vec![0u8; width]);
    buffer[..plaintext.len()].copy_from_slice(plaintext);

    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key.to_bytes().as_ref()));
    let mut sealed = buffer.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            &segment_nonce(uuid, index),
            &segment_aad(uuid, index, segments, segment_bytes),
            &mut sealed,
        )
        .map_err(CoreError::Aead)?;
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Decrypt one segment and trim it to the bytes that are really there.
///
/// `payload` is how much of the segment is not padding, which the caller takes
/// from [`AssetMeta::payload_len`]. Trimming happens after authentication, so a
/// tampered length cannot be used to read past what was sealed.
///
/// # Errors
///
/// Returns [`CoreError::MalformedSegment`] if `sealed` is too short to hold an
/// authentication tag, and [`CoreError::Aead`] if authentication fails — a
/// damaged ciphertext, or a segment presented at a position it was not sealed
/// for.
pub fn open_segment(
    key: &AssetKey,
    uuid: DocumentUuid,
    index: u64,
    segments: u64,
    segment_bytes: u32,
    payload: usize,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    // 16 is the Poly1305 tag; anything shorter cannot be a sealed segment and
    // splitting it would panic.
    let Some(split) = sealed.len().checked_sub(16) else {
        return Err(CoreError::MalformedSegment(
            "shorter than its authentication tag".into(),
        ));
    };
    let (body, tag) = sealed.split_at(split);

    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key.to_bytes().as_ref()));
    let mut opened = Zeroizing::new(body.to_vec());
    cipher
        .decrypt_in_place_detached(
            &segment_nonce(uuid, index),
            &segment_aad(uuid, index, segments, segment_bytes),
            &mut opened,
            GenericArray::from_slice(tag),
        )
        .map_err(CoreError::Aead)?;

    let keep = payload.min(opened.len());
    opened.truncate(keep);
    Ok(opened)
}

/// Accumulates the digest of an asset's plaintext as it is written or read.
///
/// Over the *unpadded* bytes, so the value is a property of the file rather than
/// of the segmentation — a reader that computed it over padded segments could
/// not compare it against a hash of the original.
#[derive(Debug, Default)]
pub struct ContentDigest {
    hasher: Option<blake3::Hasher>,
}

impl ContentDigest {
    /// Start a digest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: Some(blake3::Hasher::new_derive_key(ASSET_CONTENT_CONTEXT)),
        }
    }

    /// Absorb the next run of real bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(bytes);
        } else {
            // Default-constructed rather than started; `finish` reports the same
            // empty digest either way, so there is nothing to do.
        }
    }

    /// The digest of a complete buffer, for a caller that already has one.
    #[must_use]
    pub fn new_over(bytes: &[u8]) -> [u8; 32] {
        let mut digest = Self::new();
        digest.update(bytes);
        digest.finish()
    }

    /// The digest of everything absorbed so far.
    #[must_use]
    pub fn finish(&self) -> [u8; 32] {
        self.hasher.as_ref().map_or_else(
            || {
                *blake3::Hasher::new_derive_key(ASSET_CONTENT_CONTEXT)
                    .finalize()
                    .as_bytes()
            },
            |hasher| *hasher.finalize().as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{AssetKey, AssetMeta, DocumentUuid, open_segment, seal_segment};

    fn key(seed: u64) -> AssetKey {
        AssetKey::generate(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    const UUID: DocumentUuid = DocumentUuid([9u8; 16]);

    /// A small segmentation, so these tests do not allocate four mebibytes each.
    /// Nothing here depends on the size beyond it being uniform.
    const WIDTH: u32 = 512;

    #[test]
    fn a_sealed_segment_opens_to_what_went_in() {
        let key = key(1);
        let plaintext = b"the quick brown fox";
        let sealed =
            seal_segment(&key, UUID, 0, 1, WIDTH, plaintext).expect("sealing a short segment");
        let opened = open_segment(&key, UUID, 0, 1, WIDTH, plaintext.len(), &sealed)
            .expect("opening what we just sealed");
        assert_eq!(
            opened.as_slice(),
            plaintext,
            "a round trip must return the original bytes, trimmed of padding"
        );
    }

    #[test]
    fn every_sealed_segment_is_the_same_length() {
        // The point of padding: a peer counting ciphertext bytes must not be
        // able to tell a one-byte asset from a full segment.
        let key = key(2);
        let short = seal_segment(&key, UUID, 0, 1, WIDTH, b"x").expect("sealing one byte");
        let full = seal_segment(&key, UUID, 0, 1, WIDTH, &vec![7u8; WIDTH as usize])
            .expect("sealing a whole segment");
        assert_eq!(
            short.len(),
            full.len(),
            "segment ciphertexts must not reveal how much of the segment is real"
        );
    }

    #[test]
    fn a_segment_cannot_be_moved_to_another_position() {
        // The AAD binds the index, so reordering an asset is an authentication
        // failure rather than a silently different file.
        let key = key(3);
        let sealed = seal_segment(&key, UUID, 0, 4, WIDTH, b"first").expect("sealing at index 0");
        assert!(
            open_segment(&key, UUID, 1, 4, WIDTH, 5, &sealed).is_err(),
            "a segment opened at a position it was not sealed for must fail"
        );
    }

    #[test]
    fn a_segment_cannot_be_moved_to_another_asset() {
        let key = key(4);
        let sealed = seal_segment(&key, UUID, 0, 1, WIDTH, b"mine").expect("sealing");
        let other = DocumentUuid([1u8; 16]);
        assert!(
            open_segment(&key, other, 0, 1, WIDTH, 4, &sealed).is_err(),
            "the asset uuid is authenticated, so a segment cannot be spliced \
             into a different asset"
        );
    }

    #[test]
    fn a_segment_cannot_be_reinterpreted_under_a_different_length_claim() {
        // `segments` is in the AAD because the manifest is writable by any
        // member: without it, truncating an asset would be a manifest edit.
        let key = key(5);
        let sealed =
            seal_segment(&key, UUID, 0, 4, WIDTH, b"data").expect("sealing as one of four");
        assert!(
            open_segment(&key, UUID, 0, 2, WIDTH, 4, &sealed).is_err(),
            "claiming a different segment count must not open the segment"
        );
    }

    #[test]
    fn a_segment_cannot_be_reinterpreted_at_a_different_segment_width() {
        // `segment_bytes` lives in the manifest, so it is writable by any
        // member. Authenticating it is what stops a rewritten width turning a
        // padded segment into a longer read.
        let key = key(9);
        let sealed = seal_segment(&key, UUID, 0, 1, WIDTH, b"data").expect("sealing at WIDTH");
        assert!(
            open_segment(&key, UUID, 0, 1, WIDTH * 2, 4, &sealed).is_err(),
            "claiming a different segment width must not open the segment"
        );
    }

    #[test]
    fn a_damaged_segment_is_refused_rather_than_returned() {
        let key = key(6);
        let mut sealed = seal_segment(&key, UUID, 0, 1, WIDTH, b"intact").expect("sealing");
        sealed[0] ^= 0xff;
        assert!(
            open_segment(&key, UUID, 0, 1, WIDTH, 6, &sealed).is_err(),
            "a flipped bit must fail authentication rather than decrypt to garbage"
        );
    }

    #[test]
    fn another_key_cannot_open_a_segment() {
        let sealed = seal_segment(&key(7), UUID, 0, 1, WIDTH, b"secret").expect("sealing");
        assert!(
            open_segment(&key(8), UUID, 0, 1, WIDTH, 6, &sealed).is_err(),
            "the per-asset key is what protects the bytes, so a different one \
             must not open them"
        );
    }

    #[test]
    fn an_empty_asset_still_occupies_one_segment() {
        // So that everything from zero bytes to a full segment presents the same
        // shape to a peer counting entries.
        assert_eq!(
            AssetMeta::segments_for(0, WIDTH),
            1,
            "an empty asset must still have a segment, or its emptiness is visible"
        );
    }

    #[test]
    fn segment_counts_round_up() {
        assert_eq!(
            AssetMeta::segments_for(1, WIDTH),
            1,
            "one byte fits in one segment"
        );
        assert_eq!(
            AssetMeta::segments_for(u64::from(WIDTH), WIDTH),
            1,
            "an exactly full segment is one segment, not two"
        );
        assert_eq!(
            AssetMeta::segments_for(u64::from(WIDTH) + 1, WIDTH),
            2,
            "one byte past a segment boundary needs a second segment"
        );
    }

    #[test]
    fn payload_length_is_total_over_out_of_range_indices() {
        // A tampered manifest can name a segment past the end of the asset, and
        // the answer has to be a number rather than a panic.
        let meta = AssetMeta {
            size: 10,
            segments: 1,
            segment_bytes: WIDTH,
            content_hash: [0u8; 32],
        };
        assert_eq!(
            meta.payload_len(0),
            10,
            "the only segment carries the whole asset"
        );
        assert_eq!(
            meta.payload_len(99),
            0,
            "a segment past the end of the asset contributes nothing"
        );
    }
}
