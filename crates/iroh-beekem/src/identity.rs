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

use beekem::id::MemberId;
use iroh::EndpointId;
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
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

    /// Everything an admin needs to admit this device, in one value.
    ///
    /// The three halves of an admission travel together because they are useless
    /// apart: the member id says *who*, the leaf key is what the CGKA encrypts
    /// to, and the endpoint is what puts the device on the admitter's roster
    /// before it has synced anything. See [`Enrollment`].
    #[must_use]
    pub fn enrollment(&self, endpoint: EndpointId) -> Enrollment {
        Enrollment {
            member: self.member_id().to_bytes(),
            share_key: self.share_key(),
            endpoint: *endpoint.as_bytes(),
        }
    }

    pub(crate) fn signer(&self) -> MemorySigner {
        self.signer.clone()
    }

    pub(crate) fn share_secret(&self) -> ShareSecretKey {
        self.share_secret
    }
}

/// What a prospective device hands an admin, out of band, to be admitted.
///
/// # Why this is a type and not three arguments
///
/// [`Workspace::add_user`](crate::Workspace::add_user) previously took a
/// `MemberId` and a `ShareKey` positionally — two `keyhive_crypto` and `beekem`
/// types this crate did not re-export — so no application could invite anybody
/// without adding those crates to its own manifest and pinning them to whatever
/// version this one happens to resolve. That is the leak Phase 6 closes, and 0.1
/// freezes the answer: an admission is one value, produced by
/// [`Identity::enrollment`], and the raw types are re-exported for callers that
/// genuinely need them rather than being the only way in.
///
/// Public in every field: the member id and the leaf key are in every operation
/// the device will ever sign, and the endpoint is what it dials from. Nothing
/// here is secret, which is why it can cross an unauthenticated channel — unlike
/// the [`Invite`](crate::Invite) that comes back the other way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    /// The device's CGKA identity, as raw verifying-key bytes.
    ///
    /// Raw bytes rather than a `MemberId`, which wraps an *expanded* Ed25519
    /// point and is an order of magnitude larger on the wire for no gain — the
    /// same reasoning `CoreError::Unauthorized` records.
    member: [u8; 32],
    /// The public half of the device's leaf secret.
    share_key: ShareKey,
    /// The device's transport address, as raw bytes.
    endpoint: [u8; 32],
}

impl Enrollment {
    /// Assemble an enrollment from parts an application obtained some other way.
    ///
    /// [`Identity::enrollment`] is the ordinary route; this exists for a caller
    /// holding the three values already, and takes the re-exported types rather
    /// than raw bytes so that a malformed member id cannot be constructed here
    /// at all.
    #[must_use]
    pub fn new(member: MemberId, share_key: ShareKey, endpoint: EndpointId) -> Self {
        Self {
            member: member.to_bytes(),
            share_key,
            endpoint: *endpoint.as_bytes(),
        }
    }

    /// The device's CGKA identity.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Identity`] if the bytes are not a valid Ed25519
    /// point. Deserialization cannot check that — a member id round-trips as raw
    /// bytes on purpose — so it is checked here, where the failure is one value
    /// refused rather than a whole message.
    pub fn member_id(&self) -> Result<MemberId, WorkspaceError> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.member)
            .map(MemberId::from)
            .map_err(|_| WorkspaceError::Identity("malformed member id".into()))
    }

    /// The device's CGKA identity, unparsed.
    #[must_use]
    pub fn member_bytes(&self) -> [u8; 32] {
        self.member
    }

    /// The public half of the device's leaf secret.
    #[must_use]
    pub fn share_key(&self) -> ShareKey {
        self.share_key
    }

    /// The device's transport address.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Identity`] if the bytes are not a valid
    /// endpoint id, for the same reason [`Self::member_id`] can.
    pub fn endpoint(&self) -> Result<EndpointId, WorkspaceError> {
        EndpointId::from_bytes(&self.endpoint)
            .map_err(|_| WorkspaceError::Identity("malformed endpoint id".into()))
    }
}

#[cfg(test)]
mod tests {
    use iroh::EndpointId;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{Enrollment, Identity};

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

    /// An endpoint id derived from a fixed key, so the tests are reproducible.
    fn endpoint() -> EndpointId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        EndpointId::from_bytes(&key.to_bytes()).expect("a verifying key is a valid endpoint id")
    }

    #[test]
    fn an_enrollment_carries_exactly_what_an_admission_needs() {
        // The three values an admin needs, and the reason they travel together:
        // an `Add` names the member and encrypts to the leaf key, and the
        // endpoint is what puts the device on the admitter's roster before it
        // has synced anything. Any one of them missing is a deadlock, not an
        // inconvenience.
        let id = identity(1);
        let enrollment = id.enrollment(endpoint());

        assert_eq!(
            enrollment
                .member_id()
                .expect("a freshly built enrollment parses"),
            id.member_id(),
            "an enrollment must name the device it was built from"
        );
        assert_eq!(
            enrollment.share_key(),
            id.share_key(),
            "an enrollment must carry the leaf key the CGKA will encrypt to"
        );
        assert_eq!(
            enrollment
                .endpoint()
                .expect("a freshly built enrollment parses"),
            endpoint(),
            "an enrollment must carry the address the admitter will admit"
        );
        assert_eq!(
            enrollment.member_bytes(),
            id.member_id().to_bytes(),
            "the unparsed accessor must agree with the parsed one"
        );
    }

    #[test]
    fn assembling_an_enrollment_from_parts_matches_deriving_one() {
        // `Enrollment::new` exists for a caller that already holds the three
        // values. It must produce the same value `Identity::enrollment` does, or
        // the two routes into `add_user` would admit subtly different devices.
        let id = identity(1);

        assert_eq!(
            Enrollment::new(id.member_id(), id.share_key(), endpoint()),
            id.enrollment(endpoint()),
            "the two ways to build an enrollment must agree"
        );
    }

    #[test]
    fn a_malformed_enrollment_is_refused_rather_than_coerced() {
        // An enrollment crosses an out-of-band channel and comes back as bytes,
        // and neither a member id nor an endpoint id is checked by
        // deserialization — both round-trip as raw arrays on purpose, because a
        // `MemberId` on the wire would carry an expanded Ed25519 point. So the
        // check happens on the way out, where the failure is one value refused.
        // `0x02` repeated is not a point on the curve. Any value that fails
        // decompression would do; this one is named rather than searched for so
        // the test says nothing about *which* invalid encodings exist.
        let malformed = Enrollment {
            member: [0x02u8; 32],
            share_key: identity(1).share_key(),
            endpoint: [0x02u8; 32],
        };

        assert!(
            malformed.member_id().is_err(),
            "a member id that is not a valid Ed25519 point must be refused"
        );
        assert!(
            malformed.endpoint().is_err(),
            "an endpoint id that is not a valid Ed25519 point must be refused"
        );
    }
}
