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

    /// A correctly-signed payload was not a certificate of the kind it arrived
    /// as: its domain tag is absent or belongs to another type.
    ///
    /// Distinct from [`Self::BadSignature`] because the two say opposite things
    /// about the issuer. A bad signature means nobody vouched for these bytes; a
    /// wrong domain means somebody *did* — and the signature is being presented
    /// as authorising something they never agreed to. See the domain constants in
    /// [`crate::capability`] for the confusion this refuses.
    #[error("certificate carries the wrong domain tag")]
    WrongDomain,

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

    /// A correctly-signed operation was issued by a member the capability
    /// closure does not permit to issue it.
    ///
    /// Distinct from [`Self::Unauthorized`], and the distinction is the whole of
    /// phase 5: `Unauthorized` means "no `Add` ever named this key", which an
    /// outsider triggers; this means "this key belongs to a member who is not
    /// allowed to do *that*", which only an insider can trigger. Conflating them
    /// would make it impossible to tell an attack on the group from an attack by
    /// the group.
    ///
    /// Raw issuer bytes for the same reason as [`Self::Unauthorized`].
    #[error(
        "operation not permitted by the issuer's capabilities: {}",
        hex(issuer)
    )]
    Uncertified {
        /// The issuing device, which holds no capability admitting the operation.
        issuer: [u8; 32],
    },

    /// Signing a capability certificate failed.
    ///
    /// Unreachable with an in-memory signer, which is the only kind the core
    /// accepts; kept as a branch rather than a panic because the signer is
    /// supplied by the caller.
    #[error("signing a capability certificate failed: {0}")]
    Signing(String),

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

    /// The manifest has no record binding this device to a user.
    ///
    /// Usually means the record has not synced yet rather than that the device
    /// is illegitimate — a joiner's manifest starts empty.
    #[error("no such device in the workspace manifest")]
    UnknownDevice,

    /// A device tried to join a user it was not authorised to act for.
    ///
    /// Admitting a user's first device is an admin action; admitting a further
    /// device for that user requires already holding one of them. Without this,
    /// any member could bind a device of their own to an admin's user and
    /// inherit the role.
    #[error("not authorised to add a device to this user")]
    NotThisUsersDevice,

    /// An administrative action was attempted by a member without the role.
    ///
    /// Advisory against a cryptographically capable member — anyone holding a
    /// leaf can still decrypt — but it is what stops a well-behaved peer from
    /// issuing membership changes it has no authority to make.
    #[error("this member does not hold an administrative role")]
    NotAnAdmin,

    /// A content or manifest mutation was attempted by a member whose recorded
    /// role cannot write.
    ///
    /// Advisory in the same sense as [`Self::NotAnAdmin`]: it constrains what a
    /// well-behaved node emits, not what a peer holding the namespace write
    /// capability can push. Its real value is that a rejected write is not free
    /// — encrypting one can force an implicit PCS update on the whole group.
    ///
    /// A member whose role has simply not synced yet is *not* refused; see
    /// `WorkspaceState::require_write`.
    #[error("this member's role does not permit writing")]
    NotAWriter,

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
