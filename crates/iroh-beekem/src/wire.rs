//! Wire encoding for the control plane.
//!
//! Control-plane messages carry no secrets: a `Signed<CgkaOperation>` is public,
//! signed data, and its confidentiality is not what protects the workspace. It
//! is broadcast over `iroh-gossip` in the clear (inside QUIC's own encryption).
//!
//! What *does* protect the workspace is authentication, and it happens on the
//! receiving side rather than here. Decoding a message says nothing about who
//! wrote it: the topic is derived from a tree id every past invitee knows, so
//! anyone who has ever held an invite can broadcast onto it. Every operation is
//! therefore checked for a valid signature and a known-member issuer by
//! `CgkaController::merge` in `iroh-beekem-core` before it can touch the tree —
//! beekem itself verifies neither. This module only frames bytes.

use beekem::operation::CgkaOperation;
use iroh_beekem_core::{Certificate, EpochId, RepairTarget};
use iroh_docs::DocTicket;
use keyhive_crypto::signed::Signed;
use serde::{Deserialize, Serialize};

use crate::error::WorkspaceError;

/// A message on the workspace control-plane gossip topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMsg {
    /// A CGKA membership or key-rotation operation, with its proof.
    ///
    /// The receiver checks the issuer's capability before merging, so the
    /// certificates must travel *with* the operation: one shipped without them is
    /// refused rather than parked, and no later certificate brings it back. See
    /// [`AuthorizedOp`](iroh_beekem_core::AuthorizedOp).
    Op {
        /// The operation.
        op: Box<Signed<CgkaOperation>>,
        /// Certificates authorising it that the receiver may not hold.
        proof: Vec<Certificate>,
    },
    /// A peer's complete operation log and certificate store.
    ///
    /// Gossip is best-effort and does not retransmit to a peer that joins the
    /// overlay later, but a missed CGKA operation is *unrecoverable*: every
    /// chunk encrypted after it stays undecryptable forever. So peers exchange
    /// full logs whenever a neighbour appears. Merging is idempotent, which is
    /// what makes re-sending the whole log a safe repair rather than a
    /// disruption.
    ///
    /// **The certificates are not optional.** They are what authorises every
    /// `Add` in the log, so a log shipped without them would be rejected
    /// operation by operation — and a role change, which mints a grant and no
    /// operation at all, has no other anti-entropy path. This exchange is what
    /// repairs a lost [`ControlMsg::Certs`].
    Log {
        /// The operation log, in causal order.
        ops: Vec<Signed<CgkaOperation>>,
        /// The sender's whole certificate store.
        certs: Vec<Certificate>,
    },
    /// Capability certificates with no operation behind them.
    ///
    /// A role change produces a grant and nothing else, so it needs a carrier of
    /// its own. Announced once, like a namespace rotation, and repaired by the
    /// certificate half of [`ControlMsg::Log`].
    Certs(Vec<Certificate>),
    /// A peer announcing that it has content available under a blinded key.
    ///
    /// `iroh-docs` reconciles entries on its own schedule; this nudge lets a
    /// peer react immediately rather than waiting for the next sync round.
    Announce {
        /// The blinded storage key the content was written under.
        key: [u8; 32],
    },
    /// A peer reporting that it can never decrypt what the group publishes.
    ///
    /// A member admitted after content already existed cannot derive the epoch
    /// that content was keyed under, and re-announcing does not help: anti-
    /// entropy re-encrypts under that same epoch, reproducing a ciphertext the
    /// peer already failed on. This asks a member that *can* read it to mint a
    /// new epoch and publish under that instead.
    ///
    /// Carried here rather than on the data plane because the answer's key
    /// material travels on this topic anyway, and because answering costs a
    /// tree operation — so the receiver checks the named member against current
    /// membership before doing any work.
    /// Carries the requester as raw verifying-key bytes rather than a
    /// `MemberId`, which wraps an expanded Ed25519 point and would make this
    /// variant an order of magnitude larger than every other one — the same
    /// reasoning `CoreError::Unauthorized` records. A value that does not parse
    /// back into a member id could never have entered the tree, so the receiver
    /// treats it as a request from a non-member.
    Repair {
        /// Who is stuck, as raw verifying-key bytes.
        member: [u8; 32],
        /// What they cannot read.
        target: RepairTarget,
        /// The epoch they cannot derive.
        epoch: EpochId,
    },
    /// A rotation to a fresh replicated index.
    ///
    /// The `iroh-docs` write capability is all-or-nothing, so it cannot be
    /// withdrawn from one holder: a removed device keeps syncing the index and
    /// goes on observing entry existence, size, author and timing. Abandoning
    /// the namespace for a new one is the only way to stop that.
    ///
    /// The capability travels **encrypted under the group key**, which is what
    /// makes this work at all — a device removed before the rotation cannot
    /// derive that key, so it cannot follow. The chunk is an ordinary
    /// `Chunk` and is decrypted by the same path as any content.
    ///
    /// Carried on the control plane and not the data plane for the obvious
    /// reason: the data plane is the thing being replaced, so a peer that has
    /// not yet moved could not be told where to move to.
    Namespace {
        /// The generation being announced.
        epoch: u32,
        /// The encrypted capability.
        chunk: Box<iroh_beekem_core::Chunk>,
    },
}

/// How a namespace capability is encoded inside the encrypted announcement.
///
/// Both tickets travel together because the group key is a *group* key: beekem
/// encrypts to the whole tree, so there is no way to hand writers one secret
/// and viewers another. Each node picks the one its own role allows.
///
/// That is weaker than the invite path, where a viewer is handed a read ticket
/// and never holds the write capability at all. The gap is real and is recorded
/// in the README: a viewer who ignores their role gains write capability on the
/// replica, and `Manifest::author_may_write` — not the capability — is what
/// still rejects their entries. Closing it needs per-role key material the CGKA
/// does not provide.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceCapability {
    /// The ticket for members who may write.
    pub write: DocTicket,
    /// The ticket for members who may only read.
    pub read: DocTicket,
}

impl NamespaceCapability {
    /// Encode for encryption.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Codec`] if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, WorkspaceError> {
        postcard::to_stdvec(self).map_err(WorkspaceError::Codec)
    }

    /// Decode after decryption.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Codec`] if the bytes are not a capability.
    pub fn decode(bytes: &[u8]) -> Result<Self, WorkspaceError> {
        postcard::from_bytes(bytes).map_err(WorkspaceError::Codec)
    }
}

impl ControlMsg {
    /// Encode for broadcast.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Codec`] if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, WorkspaceError> {
        postcard::to_stdvec(self).map_err(WorkspaceError::Codec)
    }

    /// Decode a received broadcast.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Codec`] if the bytes are not a valid message.
    pub fn decode(bytes: &[u8]) -> Result<Self, WorkspaceError> {
        postcard::from_bytes(bytes).map_err(WorkspaceError::Codec)
    }
}

/// Encode an encrypted chunk for storage in `iroh-blobs`.
///
/// # Errors
///
/// Returns [`WorkspaceError::Codec`] if serialization fails.
pub fn encode_chunk(chunk: &iroh_beekem_core::Chunk) -> Result<Vec<u8>, WorkspaceError> {
    postcard::to_stdvec(chunk).map_err(WorkspaceError::Codec)
}

/// Decode an encrypted chunk fetched from `iroh-blobs`.
///
/// # Errors
///
/// Returns [`WorkspaceError::Codec`] if the bytes are not a valid chunk.
pub fn decode_chunk(bytes: &[u8]) -> Result<iroh_beekem_core::Chunk, WorkspaceError> {
    postcard::from_bytes(bytes).map_err(WorkspaceError::Codec)
}

#[cfg(test)]
mod tests {
    use super::ControlMsg;

    #[test]
    fn announce_round_trips() {
        let msg = ControlMsg::Announce { key: [3u8; 32] };
        let bytes = msg.encode().expect("encoding should succeed");
        let back = ControlMsg::decode(&bytes).expect("decoding should succeed");

        assert!(
            matches!(back, ControlMsg::Announce { key } if key == [3u8; 32]),
            "an announce should survive a round trip unchanged, got {back:?}"
        );
    }

    #[test]
    fn garbage_bytes_are_rejected() {
        assert!(
            ControlMsg::decode(&[0xff; 4]).is_err(),
            "malformed input must be rejected rather than silently misinterpreted"
        );
    }

    /// Both decoders parse bytes an attacker controls: chunk payloads come from
    /// `iroh-blobs`, and control messages from a public gossip topic that any
    /// past invitee can reach. Neither may panic on anything it is handed —
    /// a panic in a pump loop takes the task down and stops the node syncing.
    mod decoders_survive_hostile_input {
        use iroh_beekem_core::{Chunk, ChunkRef};
        use keyhive_crypto::{digest::Digest, siv::Siv, symmetric_key::SymmetricKey};
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        use super::super::{ControlMsg, decode_chunk, encode_chunk};

        fn sample_chunk() -> Chunk {
            let ciphertext = b"not really encrypted, but the right shape".to_vec();
            Chunk::new(
                Siv::new(&SymmetricKey::from([7u8; 32]), &ciphertext, b"doc"),
                ciphertext,
                Digest::from([1u8; 32]),
                Digest::from([2u8; 32]),
                ChunkRef([3u8; 32]),
                Digest::from([4u8; 32]),
            )
        }

        #[test]
        fn a_chunk_survives_an_encode_decode_round_trip() {
            let chunk = sample_chunk();
            let bytes = encode_chunk(&chunk).expect("encoding should succeed");
            let back = decode_chunk(&bytes).expect("decoding should succeed");

            assert_eq!(
                back.ciphertext, chunk.ciphertext,
                "the ciphertext must survive the round trip byte for byte"
            );
            assert_eq!(
                back.content_ref, chunk.content_ref,
                "the content ref binds the decryption key and must not drift"
            );
        }

        #[test]
        fn random_bytes_never_panic_either_decoder() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
            for len in [0usize, 1, 7, 32, 200, 4096] {
                for _ in 0..64 {
                    let mut buf = vec![0u8; len];
                    rng.fill_bytes(&mut buf);
                    // The results are meant to be errors; what is asserted is
                    // simply that returning at all is possible.
                    let _ = decode_chunk(&buf);
                    let _ = ControlMsg::decode(&buf);
                }
            }
        }

        #[test]
        fn truncated_and_corrupted_chunks_never_panic() {
            let bytes = encode_chunk(&sample_chunk()).expect("encoding should succeed");

            // Truncation is the likeliest real-world corruption, and the case a
            // length-prefixed format is most apt to mishandle.
            for cut in 0..bytes.len() {
                let _ = decode_chunk(&bytes[..cut]);
            }

            // Single-bit corruption, walking the whole buffer.
            for i in 0..bytes.len() {
                let mut corrupted = bytes.clone();
                corrupted[i] ^= 0x01;
                let _ = decode_chunk(&corrupted);
            }
        }
    }
}
