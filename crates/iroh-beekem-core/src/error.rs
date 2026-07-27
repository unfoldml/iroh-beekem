//! Error types for the `iroh-beekem` core.

use beekem::error::CgkaError;

/// Everything that can go wrong inside the I/O-free core.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A CGKA operation failed.
    #[error(transparent)]
    Cgka(#[from] CgkaError),

    /// Authenticated decryption or encryption failed.
    #[error("AEAD operation failed")]
    Aead(chacha20poly1305::Error),

    /// A signing future yielded instead of completing immediately.
    ///
    /// See [`crate::sync_poll`] — with a synchronous signer this is impossible,
    /// so it indicates the controller was handed a signer that does real I/O.
    #[error("signer returned a pending future; the core requires a synchronous signer")]
    SignerYielded,

    /// The operation log handed to [`CgkaController::join`] did not begin with
    /// the founding `Add`.
    ///
    /// [`CgkaController::join`]: crate::keys::CgkaController::join
    #[error("operation log does not start with a founding add operation")]
    MissingInitAdd,

    /// The joining member never found their own `Add` in the operation log, so
    /// they hold no leaf and cannot derive any key.
    #[error("operation log contains no add operation for the joining member")]
    NotInvited,

    /// The operation log had a causal hole: some operations could never be
    /// applied because their predecessors were absent.
    #[error("operation log is incomplete: {unresolved} operation(s) have unmet predecessors")]
    IncompleteLog {
        /// How many operations were left unapplied.
        unresolved: usize,
    },

    /// Serialization of a payload failed.
    #[error("serialization failed: {0}")]
    Serialization(#[from] postcard::Error),

    /// A manifest (Loro) operation failed.
    #[error("manifest operation failed: {0}")]
    Manifest(String),

    /// The manifest has no record of the requested document.
    #[error("no such document in the workspace manifest")]
    UnknownDocument,
}

impl From<chacha20poly1305::Error> for CoreError {
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::Aead(err)
    }
}
