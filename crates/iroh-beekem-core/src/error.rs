//! Error types for the `iroh-beekem` core.

use beekem::error::CgkaError;

use crate::manifest::hex;

/// Everything that can go wrong inside the I/O-free core.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A CGKA operation failed.
    #[error(transparent)]
    Cgka(#[from] CgkaError),

    /// A control-plane operation carried an invalid signature.
    ///
    /// beekem verifies nothing: neither `Cgka::merge_concurrent_operation` nor
    /// `Cgka::apply_operation` looks at the signature, and the control plane is
    /// a public gossip topic derived from a tree id that every past invitee
    /// knows. This check is therefore the only thing between that topic and a
    /// forged membership change.
    #[error("control operation signature verification failed")]
    BadSignature,

    /// A correctly-signed operation was issued by a key that no `Add` in the
    /// accepted history ever named.
    ///
    /// A valid signature only proves the issuer signed its own message; it says
    /// nothing about whether that issuer belongs to this group. Without this
    /// second check anyone could mint a keypair and sign themselves an `Add`.
    ///
    /// The issuer is kept as raw bytes rather than a `MemberId`, which wraps an
    /// expanded Ed25519 point and would make every `Result` in the crate pay
    /// for the error variant.
    #[error("control operation issued by a non-member: {}", hex(issuer))]
    Unauthorized {
        /// The issuing verifying key, which no accepted `Add` introduced.
        issuer: [u8; 32],
    },

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

    /// An administrative action was attempted by a member without the role.
    ///
    /// Advisory against a cryptographically capable member — anyone holding a
    /// leaf can still decrypt — but it is what stops a well-behaved peer from
    /// issuing membership changes it has no authority to make.
    #[error("this member does not hold an administrative role")]
    NotAnAdmin,

    /// The action would leave the workspace with no administrator.
    ///
    /// Promoting an admin is itself an admin action, so a workspace that loses
    /// its last one can never get another. Refusing is the only recovery.
    #[error("refusing to remove or demote the last remaining admin")]
    LastAdmin,
}

impl From<chacha20poly1305::Error> for CoreError {
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::Aead(err)
    }
}
