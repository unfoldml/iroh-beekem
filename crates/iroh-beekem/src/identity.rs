//! [`Identity`]: one device's long-term key material.
//!
//! # A device, not a person
//!
//! An `Identity` holds exactly one CGKA leaf, and a leaf belongs to a *device*.
//! Sharing one `Identity` across a person's laptop and phone is not untidy, it
//! is unsound: rotating a leaf replaces the local secret, so two devices
//! rotating the same leaf concurrently issue conflicting updates for it and the
//! group is left unable to agree on who holds what.
//!
//! Each device therefore generates its own `Identity`, and the manifest records
//! which user it belongs to. That also buys per-device revocation for free: a
//! lost laptop is one leaf to remove, not an account to rebuild.
//!
//! # Why this type exists at all
//!
//! Without it, joining a workspace meant handing in a `MemorySigner` and a
//! `ShareSecretKey` — `keyhive_crypto` types this crate does not re-export — so
//! every application had to depend on the crypto crate directly just to call
//! [`Workspace::join`](crate::Workspace::join). Worse, founding a workspace
//! generated a signer internally and dropped it, leaving no way to reuse the
//! founder's identity on the next run.

use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::WorkspaceError;

/// How many bytes [`Identity::to_bytes`] produces: two 32-byte secrets.
pub const IDENTITY_BYTES: usize = 64;

/// One device's key material: a signing key and a leaf secret.
///
/// Both halves are secret. [`Identity::to_bytes`] exists so an application can
/// persist them, and hands back a [`Zeroizing`] buffer so the copy does not
/// outlive its use.
#[derive(Clone)]
pub struct Identity {
    signer: MemorySigner,
    share_secret: ShareSecretKey,
}

impl std::fmt::Debug for Identity {
    /// Prints the public member id only.
    ///
    /// The member id is public — it is in every operation this device signs —
    /// but the two secrets must never reach a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("member_id", &self.member_id())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generate fresh key material for a new device.
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self {
            signer: MemorySigner::generate(csprng),
            share_secret: ShareSecretKey::generate(csprng),
        }
    }

    /// Restore an identity from [`Self::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Identity`] if the buffer is not exactly
    /// [`IDENTITY_BYTES`] long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WorkspaceError> {
        let bytes: &[u8; IDENTITY_BYTES] = bytes
            .try_into()
            .map_err(|_| WorkspaceError::Identity("identity must be 64 bytes".into()))?;
        let (signing, share) = bytes.split_at(32);
        let signing: [u8; 32] = signing
            .try_into()
            .map_err(|_| WorkspaceError::Identity("malformed signing key".into()))?;
        let share: [u8; 32] = share
            .try_into()
            .map_err(|_| WorkspaceError::Identity("malformed leaf secret".into()))?;
        Ok(Self {
            signer: MemorySigner(ed25519_dalek::SigningKey::from_bytes(&signing)),
            share_secret: ShareSecretKey::force_from_bytes(share),
        })
    }

    /// Serialize this identity: signing key first, then the leaf secret.
    ///
    /// This is the whole of a device's long-term secret material. Store it as
    /// carefully as you would a private key, because that is what it is.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; IDENTITY_BYTES]> {
        let mut out = Zeroizing::new([0u8; IDENTITY_BYTES]);
        out[..32].copy_from_slice(&self.signer.0.to_bytes());
        out[32..].copy_from_slice(&self.share_secret.to_bytes());
        out
    }

    /// This device's identity in the CGKA tree.
    #[must_use]
    pub fn member_id(&self) -> beekem::id::MemberId {
        beekem::id::MemberId::from(self.signer.verifying_key())
    }

    /// The public leaf key to hand an admin so they can admit this device.
    ///
    /// Public by construction: an invite names it, and the corresponding secret
    /// never leaves this device — which is what makes a stolen invite useless
    /// for joining.
    #[must_use]
    pub fn share_key(&self) -> ShareKey {
        self.share_secret.share_key()
    }

    pub(crate) fn signer(&self) -> MemorySigner {
        self.signer.clone()
    }

    pub(crate) fn share_secret(&self) -> ShareSecretKey {
        self.share_secret
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::Identity;

    fn identity(seed: u64) -> Identity {
        Identity::generate(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    #[test]
    fn an_identity_survives_a_byte_round_trip() {
        // The restart path: the same device must come back as the same member,
        // or every peer treats it as a stranger.
        let original = identity(1);
        let restored = Identity::from_bytes(original.to_bytes().as_slice())
            .expect("round trip should succeed");

        assert_eq!(
            original.member_id(),
            restored.member_id(),
            "a restored identity must be the same member"
        );
        assert_eq!(
            original.share_key(),
            restored.share_key(),
            "a restored identity must present the same leaf key"
        );
    }

    #[test]
    fn distinct_identities_are_distinct_members() {
        assert_ne!(
            identity(1).member_id(),
            identity(2).member_id(),
            "two devices must never collide on a member id"
        );
    }

    #[test]
    fn malformed_input_is_rejected_rather_than_truncated() {
        assert!(
            Identity::from_bytes(&[0u8; 32]).is_err(),
            "a short buffer must be refused, not silently padded"
        );
        assert!(
            Identity::from_bytes(&[0u8; 128]).is_err(),
            "an over-long buffer must be refused, not silently truncated"
        );
    }

    #[test]
    fn debug_does_not_leak_secret_material() {
        let id = identity(1);
        let rendered = format!("{id:?}");
        let secret = hex_of(id.to_bytes().as_slice());
        assert!(
            !rendered.contains(&secret),
            "Debug must not print key material, got {rendered}"
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}
