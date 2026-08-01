//! Pure, I/O-free core of `iroh-beekem`.
//!
//! This crate holds the cryptographic state machine for group-confidential,
//! local-first workspaces: BeeKEM continuous group key agreement, content
//! encryption, and (later) the blinded storage-key scheme and the encrypted
//! manifest.
//!
//! # What this crate deliberately does not do
//!
//! No sockets, no filesystem, no clock, no async runtime. Every effect is
//! returned to the caller as data. That constraint is not stylistic: it is what
//! allows the entire protocol to be driven by a deterministic simulator with
//! virtual time and a seeded RNG, so that partitions, reordering and concurrent
//! membership changes can be property-tested rather than hoped about.
//!
//! This is enforced mechanically; see `xtask-style` check in the README:
//!
//! ```text
//! cargo tree -p iroh-beekem-core -e normal --prefix none \
//!   | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'
//! ```
//!
//! must match nothing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod asset;
pub mod blinding;
pub mod capability;
pub mod content;
pub mod error;
pub mod keys;
pub mod manifest;
pub mod snapshot;
pub mod state;
pub mod sync_poll;

pub use asset::{ASSET_SEGMENT_BYTES, AssetKey, AssetMeta, SegmentVerdict};
pub use blinding::{DocumentUuid, StorageKey, WorkspaceSecret};
pub use capability::{
    AdminAction, AdminProposal, Approval, CapabilityStore, Certificate, DEFAULT_THRESHOLD,
    DeviceBinding, Grant, Policy, ProposalStatus, Role,
};
pub use content::{Chunk, ChunkRef};
pub use error::CoreError;
pub use keys::{AuthorizedOp, CgkaController, ControlOp, DecryptOutcome, EpochId, MergeOutcome};
pub use manifest::{DeviceDisplay, DeviceRecord, FileEntry, Manifest, UserRecord, WorkspaceInfo};
pub use snapshot::{CgkaSnapshot, SNAPSHOT_VERSION, WorkspaceSnapshot};
pub use state::{Effect, Event, NamespaceEpoch, RepairTarget, WorkspaceState};
