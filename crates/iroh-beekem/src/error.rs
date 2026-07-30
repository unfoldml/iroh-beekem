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

    /// The invite ticket was refused, or could not be applied.
    ///
    /// Wraps [`InviteError`](crate::InviteError) rather than a string because a
    /// caller acts on the difference: an expired ticket means "ask for another",
    /// a wrong invitee means "you were handed somebody else's".
    #[error("invalid invite: {0}")]
    Invite(#[from] crate::invite::InviteError),

    /// The invite verified, but the log it carries does not admit this device.
    ///
    /// Distinct from [`Self::Invite`]: the ticket itself is in order, and what
    /// failed is reconstructing the group from it — a race against a later
    /// membership change, or a ticket for a workspace this identity was never
    /// added to.
    #[error("invite does not admit this device: {0}")]
    NotAdmitted(String),

    /// Stored device key material could not be restored.
    #[error("invalid identity: {0}")]
    Identity(String),

    /// The manifest has no document at the requested path.
    #[error("no document at path: {0}")]
    NoSuchPath(String),
}
