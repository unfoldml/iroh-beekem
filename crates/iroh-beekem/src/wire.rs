//! Wire encoding for the control plane.
//!
//! Control-plane messages carry no secrets: a `Signed<CgkaOperation>` is public,
//! signed data, and its confidentiality is not what protects the workspace. It
//! is broadcast over `iroh-gossip` in the clear (inside QUIC's own encryption),
//! and every peer verifies the signature before acting on it.

use beekem::operation::CgkaOperation;
use keyhive_crypto::signed::Signed;
use serde::{Deserialize, Serialize};

use crate::error::WorkspaceError;

/// A message on the workspace control-plane gossip topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMsg {
    /// A CGKA membership or key-rotation operation.
    Op(Box<Signed<CgkaOperation>>),
    /// A peer's complete operation log, in causal order.
    ///
    /// Gossip is best-effort and does not retransmit to a peer that joins the
    /// overlay later, but a missed CGKA operation is *unrecoverable*: every
    /// chunk encrypted after it stays undecryptable forever. So peers exchange
    /// full logs whenever a neighbour appears. Merging is idempotent, which is
    /// what makes re-sending the whole log a safe repair rather than a
    /// disruption.
    Log(Vec<Signed<CgkaOperation>>),
    /// A peer announcing that it has content available under a blinded key.
    ///
    /// `iroh-docs` reconciles entries on its own schedule; this nudge lets a
    /// peer react immediately rather than waiting for the next sync round.
    Announce {
        /// The blinded storage key the content was written under.
        key: [u8; 32],
    },
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
}
