//! Group-confidential, local-first collaborative workspaces over iroh.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod identity;
pub mod node;
pub mod wire;
pub mod workspace;

pub use error::WorkspaceError;
pub use identity::Identity;
pub use node::Node;
pub use wire::ControlMsg;
pub use workspace::{Invite, Workspace};
