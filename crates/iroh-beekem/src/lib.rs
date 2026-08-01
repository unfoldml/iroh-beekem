//! Group-confidential, local-first collaborative workspaces over iroh.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod identity;
pub mod invite;
pub mod node;
mod roster;
mod store;
pub mod wire;
pub mod workspace;

/// A device's identity in the CGKA tree.
///
/// Re-exported from `beekem` because [`Workspace`] hands it back from
/// [`Workspace::member_id`] and [`Enrollment::member_id`] returns it. Before
/// this, an application could not name the type it was being given without
/// adding `beekem` to its own manifest and pinning it to whatever version this
/// crate happens to resolve — and a mismatch there is a type error with no
/// obvious cause. The same applies to [`ShareKey`].
pub use beekem::id::MemberId;
pub use error::WorkspaceError;
pub use identity::{Enrollment, Identity};
pub use invite::{Invite, InviteError, InviteTerms};
/// What the core decided a member may do.
///
/// Re-exported from `iroh-beekem-core` because [`Workspace::add_user`] takes one
/// and [`Workspace::set_role`] takes one, so it is unavoidable in any caller.
pub use iroh_beekem_core::{AdminAction, ProposalStatus, Role};
/// The public half of a device's leaf secret.
///
/// Re-exported from `keyhive_crypto` for the reason given on [`MemberId`].
/// [`Identity::share_key`] produces one and [`Enrollment`] carries it; ordinary
/// callers never need to name it, because [`Identity::enrollment`] packages both.
pub use keyhive_crypto::share_key::ShareKey;
pub use node::{DEFAULT_GC_INTERVAL, Node, NodeOptions};
pub use wire::ControlMsg;
pub use workspace::{Workspace, WorkspaceSummary};
