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

    /// An operation that needs durable storage was asked of an in-memory node.
    ///
    /// Reported rather than silently doing nothing, because the two nodes differ
    /// in exactly the property the caller is relying on. A `list` that returned
    /// an empty vector for a [`Node::spawn`](crate::Node::spawn) node would read
    /// as "this node holds no workspaces" when the truth is "this node cannot
    /// hold any across a restart".
    #[error("this node has no persistent store; use Node::spawn_persistent")]
    NotPersistent,

    /// This node holds no snapshot for the requested workspace.
    #[error("no stored workspace with tree id {}", hex(tree_id))]
    NoSuchWorkspace {
        /// The tree id that was asked for.
        tree_id: [u8; 32],
    },

    /// The stored workspace belongs to a different device than the one opening
    /// it.
    ///
    /// A snapshot carries its own signing key, so opening it under the wrong
    /// identity would otherwise succeed and quietly act as its owner — writing
    /// entries under their author id and issuing operations under their
    /// capabilities. Refusing is the only way the mistake is visible.
    #[error("this snapshot belongs to a different device")]
    IdentityMismatch,
}

/// Lowercase hex, for naming a workspace in an error message.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}
