//! On-disk layout for a persistent [`Node`](crate::Node).
//!
//! Every byte this library writes to a filesystem is written from here, so that
//! "what does persistence expose" has one place to look rather than being spread
//! across the workspace pump.
//!
//! ```text
//! <root>/
//!   endpoint.key            32 bytes, 0600 — the node's QUIC identity
//!   redeemed                spent invite nonces
//!   blobs/                  iroh-blobs FsStore
//!   docs/                   iroh-docs redb
//!   workspaces/<hex>.snapshot   one per workspace, keyed by tree id, 0600
//! ```
//!
//! # What is at stake in each file
//!
//! `endpoint.key` is the node's identity. Lose it and the `EndpointId` changes,
//! no peer can re-dial, and — because the roster is an allowlist of endpoint ids
//! — the node falls off every peer's roster and is refused at the connection
//! level by the workspace it still belongs to. Persistence and admission control
//! are the same problem here, which is why the key is written on first bind
//! rather than left to the application.
//!
//! A `.snapshot` is the whole read capability for one workspace: signing key,
//! leaf secret, every cached PCS key, the blinding secret, and the documents in
//! plaintext-equivalent form. See [`iroh_beekem_core::snapshot`].
//!
//! # Not encrypted at rest, and what that is worth
//!
//! Both are written `0600` and no further. This is a deliberate trade rather
//! than an omission: [`Identity::to_bytes`](crate::Identity::to_bytes) already
//! made the application responsible for storing an equivalent secret, so
//! encrypting the snapshot while the identity beside it sits in the clear would
//! move the boundary without raising it. An application that needs
//! encryption-at-rest should hold `<root>` on an encrypted volume, where the
//! blobs and docs stores — neither of which this crate controls — are covered
//! too.
//!
//! # Every write is atomic
//!
//! Writes go to a sibling temporary file and are renamed into place. A snapshot
//! is frequently the only copy of a node's CGKA state: a crash partway through
//! an in-place rewrite would leave a file that decodes to nothing, and the node
//! would have no way back into its own workspace. `rename` within a directory is
//! atomic on every platform this targets, so a reader sees either the previous
//! snapshot or the new one.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use iroh::SecretKey;
use iroh_docs::NamespaceId;
use serde::{Deserialize, Serialize};

use crate::error::WorkspaceError;

/// Subdirectory holding one snapshot per workspace.
const WORKSPACES_DIR: &str = "workspaces";
/// File holding the node's QUIC secret key.
const ENDPOINT_KEY: &str = "endpoint.key";
/// File holding the spent-invite-nonce ledger.
const REDEEMED: &str = "redeemed";

/// Assets whose segments were being written when the process last stopped.
const PENDING_ASSETS: &str = "pending-assets";
/// Extension for a workspace snapshot.
const SNAPSHOT_EXT: &str = "snapshot";

/// Directory for the `iroh-blobs` store.
pub(crate) const BLOBS_DIR: &str = "blobs";
/// Directory for the `iroh-docs` store.
pub(crate) const DOCS_DIR: &str = "docs";

/// Invite nonces already spent, keyed by `(tree id, nonce)`.
///
/// The tree id is part of the key so two workspaces on one node cannot collide,
/// however their inviters happen to generate nonces.
pub(crate) type SpentNonces = HashSet<([u8; 32], [u8; 16])>;

/// Assets this node has begun writing and not yet declared, by
/// `(tree id, asset uuid)`.
///
/// An intent log, and the only thing that makes an interrupted attachment
/// recoverable. `Workspace::attach_file` indexes segments *before* the manifest
/// entry that declares them — it must, since the entry records a digest over
/// bytes it has not read yet — and an index entry is exactly what protects a
/// blob from collection. A process killed halfway would otherwise leave segments
/// no manifest will ever name, under a blinded key derived from a UUID that
/// existed only in memory: unreachable, unnameable, and never reclaimed.
///
/// Recording the UUID first turns that into a startup sweep. Per workspace as
/// well as per asset, because one node can hold several and each has its own
/// blinding secret.
pub(crate) type PendingAssets = HashSet<([u8; 32], [u8; 16])>;

/// A workspace snapshot plus the facade-level state the core does not hold.
///
/// The core snapshot is carried as opaque bytes rather than as a typed field so
/// that the two layers version independently: a change to
/// [`WorkspaceSnapshot`](iroh_beekem_core::WorkspaceSnapshot) is caught by its
/// own version check, not by failing to decode this envelope.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WorkspaceRecord {
    /// [`WorkspaceState::export`](iroh_beekem_core::WorkspaceState::export) bytes.
    pub(crate) core: Vec<u8>,
    /// Which `iroh-docs` replica this workspace is on.
    ///
    /// Stored here because it is **not** recoverable from core state. The core
    /// keeps `namespace_ticket`, but that is empty for a founding namespace —
    /// nobody ever announced it — so a founder reopened from its core snapshot
    /// alone would have no replica to open and would silently sync nothing.
    pub(crate) namespace: NamespaceId,
}

/// The root directory of a persistent node, and the operations over it.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    root: PathBuf,
}

impl Store {
    /// Open `root`, creating the directory tree if it is not there yet.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if any directory cannot be created.
    pub(crate) fn open(root: impl AsRef<Path>) -> Result<Self, WorkspaceError> {
        let root = root.as_ref().to_path_buf();
        for dir in [
            root.clone(),
            root.join(WORKSPACES_DIR),
            root.join(BLOBS_DIR),
            root.join(DOCS_DIR),
        ] {
            std::fs::create_dir_all(&dir)
                .map_err(|e| WorkspaceError::Storage(format!("creating {}: {e}", dir.display())))?;
        }
        Ok(Self { root })
    }

    /// The blobs and docs subdirectories, for the stores that own them.
    pub(crate) fn subdir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The node's QUIC secret key, generating and storing one on first use.
    ///
    /// Reusing the key is what keeps the `EndpointId` — and therefore this
    /// node's place on every peer's roster — stable across a restart.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the key cannot be read or written,
    /// or if the stored key is not exactly 32 bytes. A short read is refused
    /// rather than padded: silently binding a *different* endpoint is the exact
    /// failure persistence exists to prevent, and it would look like the node
    /// working right up until no peer would talk to it.
    pub(crate) fn endpoint_key(&self) -> Result<SecretKey, WorkspaceError> {
        let path = self.root.join(ENDPOINT_KEY);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                    WorkspaceError::Storage(format!(
                        "{} is not a 32-byte secret key; refusing to bind a different \
                         endpoint identity than the one this node is known by",
                        path.display()
                    ))
                })?;
                Ok(SecretKey::from_bytes(&bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = SecretKey::generate();
                write_private(&path, &key.to_bytes())?;
                Ok(key)
            }
            Err(e) => Err(WorkspaceError::Storage(format!(
                "reading {}: {e}",
                path.display()
            ))),
        }
    }

    /// Spent invite nonces recorded by an earlier run.
    ///
    /// A malformed or truncated ledger is treated as **empty** rather than as an
    /// error, and the direction is a judgement worth stating: refusing to start
    /// would deny the operator their whole node over a replay ledger, while
    /// starting empty re-opens a window that is already bounded by the invite's
    /// one-hour expiry. The expiry is what makes losing this file survivable.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] only if the file exists and cannot be
    /// read at all.
    pub(crate) fn load_redeemed(&self) -> Result<SpentNonces, WorkspaceError> {
        let path = self.root.join(REDEEMED);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(postcard::from_bytes(&bytes).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
            Err(e) => Err(WorkspaceError::Storage(format!(
                "reading {}: {e}",
                path.display()
            ))),
        }
    }

    /// Record the spent-nonce ledger.
    ///
    /// Written whole rather than appended, because the set is small — one entry
    /// per invite this node has ever redeemed — and a whole-file rename cannot
    /// leave a half-written entry behind.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the ledger cannot be encoded or
    /// written.
    pub(crate) fn store_redeemed(&self, redeemed: &SpentNonces) -> Result<(), WorkspaceError> {
        let bytes = postcard::to_stdvec(redeemed)
            .map_err(|e| WorkspaceError::Storage(format!("encoding the invite ledger: {e}")))?;
        write_private(&self.root.join(REDEEMED), &bytes)
    }

    /// Read the pending-asset intent log.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] only if the file exists and cannot be
    /// read at all. Unreadable contents are treated as an empty log, matching
    /// [`Self::load_redeemed`]: the cost of forgetting an orphan is storage, and
    /// the cost of refusing to start is the workspace.
    pub(crate) fn load_pending_assets(&self) -> Result<PendingAssets, WorkspaceError> {
        let path = self.root.join(PENDING_ASSETS);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(postcard::from_bytes(&bytes).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
            Err(e) => Err(WorkspaceError::Storage(format!(
                "reading {}: {e}",
                path.display()
            ))),
        }
    }

    /// Record the pending-asset intent log.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the log cannot be encoded or
    /// written.
    pub(crate) fn store_pending_assets(
        &self,
        pending: &PendingAssets,
    ) -> Result<(), WorkspaceError> {
        let bytes = postcard::to_stdvec(pending)
            .map_err(|e| WorkspaceError::Storage(format!("encoding the pending-asset log: {e}")))?;
        write_private(&self.root.join(PENDING_ASSETS), &bytes)
    }

    /// Where one workspace's snapshot lives.
    fn workspace_path(&self, tree_id: [u8; 32]) -> PathBuf {
        self.root
            .join(WORKSPACES_DIR)
            .join(format!("{}.{SNAPSHOT_EXT}", hex(&tree_id)))
    }

    /// Write one workspace's snapshot, replacing any previous one atomically.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the record cannot be encoded or
    /// written.
    pub(crate) fn store_workspace(
        &self,
        tree_id: [u8; 32],
        record: &WorkspaceRecord,
    ) -> Result<(), WorkspaceError> {
        let bytes = postcard::to_stdvec(record)
            .map_err(|e| WorkspaceError::Storage(format!("encoding a workspace snapshot: {e}")))?;
        write_private(&self.workspace_path(tree_id), &bytes)
    }

    /// Read one workspace's snapshot, or `None` if this node holds no such
    /// workspace.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the file exists but cannot be read
    /// or decoded. Unlike the nonce ledger, a corrupt snapshot is fatal to the
    /// workspace it names: there is nothing to fall back to, and continuing with
    /// an empty state would present this device to the group as a stranger.
    pub(crate) fn load_workspace(
        &self,
        tree_id: [u8; 32],
    ) -> Result<Option<WorkspaceRecord>, WorkspaceError> {
        let path = self.workspace_path(tree_id);
        match std::fs::read(&path) {
            Ok(bytes) => postcard::from_bytes(&bytes)
                .map(Some)
                .map_err(|e| WorkspaceError::Storage(format!("decoding {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(WorkspaceError::Storage(format!(
                "reading {}: {e}",
                path.display()
            ))),
        }
    }

    /// Every workspace this node has a snapshot for, by tree id.
    ///
    /// Files that are not named like a snapshot are skipped rather than
    /// reported: the directory is on the user's disk and may hold an editor's
    /// backup file or a partially-copied restore, neither of which should stop
    /// the workspaces beside them from opening.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the directory cannot be listed.
    pub(crate) fn list_workspaces(&self) -> Result<Vec<[u8; 32]>, WorkspaceError> {
        let dir = self.root.join(WORKSPACES_DIR);
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| WorkspaceError::Storage(format!("listing {}: {e}", dir.display())))?;

        let mut found: Vec<[u8; 32]> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                if path.extension()?.to_str()? != SNAPSHOT_EXT {
                    return None;
                }
                unhex(path.file_stem()?.to_str()?)
            })
            .collect();
        // Sorted so `list` is a function of the directory's contents rather than
        // of the order the filesystem happens to enumerate it in.
        found.sort_unstable();
        Ok(found)
    }

    /// Forget one workspace's snapshot.
    ///
    /// Absence is success: `delete` is expected to be reachable twice, and the
    /// caller's intent — "this node no longer holds that workspace" — is
    /// satisfied either way.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Storage`] if the file exists and cannot be
    /// removed.
    pub(crate) fn remove_workspace(&self, tree_id: [u8; 32]) -> Result<(), WorkspaceError> {
        let path = self.workspace_path(tree_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WorkspaceError::Storage(format!(
                "removing {}: {e}",
                path.display()
            ))),
        }
    }
}

/// Write `bytes` to `path` atomically, owner-readable only.
///
/// Permissions are set on the temporary file *before* the rename, so the secret
/// is never briefly world-readable at its final name. On platforms without Unix
/// permission bits this is a plain atomic write, and the module documentation
/// says what that costs.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), WorkspaceError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .map_err(|e| WorkspaceError::Storage(format!("writing {}: {e}", tmp.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| WorkspaceError::Storage(format!("securing {}: {e}", tmp.display())))?;
    }

    std::fs::rename(&tmp, path)
        .map_err(|e| WorkspaceError::Storage(format!("replacing {}: {e}", path.display())))
}

/// Lowercase hex, for naming a snapshot after its tree id.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The inverse of [`hex`], rejecting anything that is not 64 hex digits.
fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store rooted in a fresh temporary directory.
    ///
    /// Rolled by hand rather than pulled from `tempfile`: the crate has no
    /// test-only dependency on it today, and this needs a directory and a
    /// deletion, not a library.
    fn temp_store() -> (Store, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "iroh-beekem-store-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        (Store::open(&root).expect("a fresh root opens"), root)
    }

    /// In a store that has generated an endpoint key, upon reopening it, we
    /// expect the same key back.
    ///
    /// This is the whole of why a node can be restarted at all: the
    /// `EndpointId` is the peer's public key *and* its entry on every roster, so
    /// a key that changed on restart would be an identity nobody admits.
    #[test]
    fn an_endpoint_key_survives_a_reopen() {
        let (store, root) = temp_store();
        let first = store
            .endpoint_key()
            .expect("a key is generated on first use");
        let second = Store::open(&root)
            .expect("the root reopens")
            .endpoint_key()
            .expect("the stored key is read back");

        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "the node generated a new endpoint identity on restart, so no peer \
             could re-dial it and it would fall off every roster"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// In a store holding a truncated key file, upon reading it, we expect a
    /// refusal rather than a silently different identity.
    #[test]
    fn a_truncated_endpoint_key_is_refused() {
        let (store, root) = temp_store();
        std::fs::write(root.join(ENDPOINT_KEY), [1u8, 2, 3]).expect("a short file is written");

        assert!(
            store.endpoint_key().is_err(),
            "a truncated key file was accepted, so the node would bind an identity \
             other than the one its peers know it by"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// In a store with several workspaces, upon listing, we expect exactly the
    /// tree ids written and nothing the directory happens to also contain.
    #[test]
    fn listing_returns_the_workspaces_and_ignores_other_files() {
        let (store, root) = temp_store();
        let record = |n: u8| WorkspaceRecord {
            core: vec![n],
            namespace: NamespaceId::from(&[n; 32]),
        };
        store
            .store_workspace([9u8; 32], &record(9))
            .expect("first stores");
        store
            .store_workspace([4u8; 32], &record(4))
            .expect("second stores");
        std::fs::write(root.join(WORKSPACES_DIR).join("notes.txt"), b"unrelated")
            .expect("an unrelated file is written");

        assert_eq!(
            store.list_workspaces().expect("listing succeeds"),
            vec![[4u8; 32], [9u8; 32]],
            "listing did not return exactly the stored workspaces in sorted order"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// In a store holding a workspace, upon round-tripping it, we expect the
    /// namespace back — the field the core snapshot cannot reconstruct.
    #[test]
    fn a_workspace_record_round_trips_with_its_namespace() {
        let (store, root) = temp_store();
        let namespace = NamespaceId::from(&[3u8; 32]);
        store
            .store_workspace(
                [1u8; 32],
                &WorkspaceRecord {
                    core: vec![7, 7],
                    namespace,
                },
            )
            .expect("a record stores");

        let read = store
            .load_workspace([1u8; 32])
            .expect("a stored record loads")
            .expect("a stored record is present");
        assert_eq!(
            read.core,
            vec![7, 7],
            "the core snapshot bytes did not survive"
        );
        assert_eq!(
            read.namespace, namespace,
            "the namespace did not survive, so a reopened founder would have no \
             replica to sync and would silently exchange nothing"
        );

        store.remove_workspace([1u8; 32]).expect("removal succeeds");
        assert!(
            store
                .load_workspace([1u8; 32])
                .expect("a removed workspace loads as absent")
                .is_none(),
            "a deleted workspace was still readable"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// In a hex round trip, upon decoding what was encoded, we expect the same
    /// bytes, and upon decoding anything else, we expect `None`.
    ///
    /// The filename *is* the lookup key for a workspace, so a decoder that
    /// accepted a short or non-hex name would let a stray file be opened as a
    /// workspace with a tree id that is not the one it holds.
    #[test]
    fn a_tree_id_survives_the_filename_round_trip() {
        let id = [0xABu8; 32];
        assert_eq!(unhex(&hex(&id)), Some(id), "hex did not round-trip");
        assert_eq!(unhex("short"), None, "a short name decoded as a tree id");
        assert_eq!(
            unhex(&"z".repeat(64)),
            None,
            "a non-hex name of the right length decoded as a tree id"
        );
    }
}
