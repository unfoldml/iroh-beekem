//! Wire encoding for the parts of the protocol that name `iroh` types.
//!
//! The control-plane message itself is [`ControlMsg`], and it lives in
//! `iroh-beekem-core` rather than here: turning one into the events it stands
//! for is protocol, and it was written twice — once in this crate and once in
//! the simulator — before it moved. It is re-exported below, so
//! `crate::wire::ControlMsg` and `iroh_beekem::ControlMsg` both still resolve.
//!
//! What stays is [`NamespaceCapability`], which holds two `iroh-docs` tickets
//! and so cannot go anywhere near a crate that must not depend on `iroh`.

pub use iroh_beekem_core::wire::{
    ControlMsg, MAX_LOG_CERTS, MAX_LOG_OPS, decode_chunk, encode_chunk,
};
use iroh_docs::DocTicket;
use serde::{Deserialize, Serialize};

use crate::error::WorkspaceError;

/// How a namespace capability is encoded inside the encrypted announcement.
///
/// Both tickets travel together because the group key is a *group* key: beekem
/// encrypts to the whole tree, so there is no way to hand writers one secret
/// and viewers another. Each node picks the one its own role allows.
///
/// That is weaker than the invite path, where a viewer is handed a read ticket
/// and never holds the write capability at all. The gap is real and is recorded
/// in the README: a viewer who ignores their role gains write capability on the
/// replica, and `WorkspaceState::author_may_write` — not the capability — is what
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
