//! Errors from the networked workspace layer.

/// Everything that can go wrong once real networking is involved.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    /// The I/O-free core rejected an operation.
    #[error(transparent)]
    Core(#[from] iroh_beekem_core::CoreError),

    /// Encoding or decoding a wire message failed.
    #[error("wire codec failure: {0}")]
    Codec(postcard::Error),

    /// Binding the endpoint failed.
    #[error("failed to bind endpoint: {0}")]
    Bind(String),

    /// A gossip operation failed.
    #[error("gossip failure: {0}")]
    Gossip(String),

    /// A docs or blobs operation failed.
    #[error("storage failure: {0}")]
    Storage(String),

    /// The invite ticket could not be parsed or applied.
    #[error("invalid invite: {0}")]
    Invite(String),

    /// Stored device key material could not be restored.
    #[error("invalid identity: {0}")]
    Identity(String),

    /// The manifest has no document at the requested path.
    #[error("no document at path: {0}")]
    NoSuchPath(String),
}
