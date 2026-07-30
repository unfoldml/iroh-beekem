//! The encrypted workspace manifest: the directory index and display data.
//!
//! Two things live here that deliberately do *not* live in `iroh-docs`:
//!
//! * **Logical paths.** `iroh-docs` only ever sees blinded 32-byte keys (see
//!   [`crate::blinding`]). The mapping from those keys back to
//!   `/finance/q3.json` exists only inside this manifest, which is itself
//!   encrypted like any other content.
//! * **Display data.** Human-readable names and labels for users, devices and
//!   documents, plus the self-attested author and endpoint claims.
//!
//! The manifest is a Loro document, so two peers who edit it concurrently while
//! partitioned converge without a coordinator.
//!
//! # What deliberately does *not* live here any more
//!
//! Roles and the device-to-user binding used to. They moved to
//! [`crate::capability`], and the reason is the whole of phase 5.
//!
//! `Manifest::import` is an unconditional CRDT merge — that is what a CRDT *is*
//! — so anything recorded here is writable by any member and converges on every
//! replica. While roles lived here, a member holding the lowest role could write
//! `roles[me] = Admin`, or bind a device of theirs to an admin's user, and every
//! peer accepted it. There was no filter to add: Loro merges an update atomically,
//! so "import only the records that are authorised" has nowhere to hook.
//!
//! The split is therefore not by *topic* but by **what a lie costs**:
//!
//! | Here | In [`crate::capability`] |
//! |---|---|
//! | Claims that grant nothing: a display name, a label, a mime type, a path | Claims that grant something: who may administer, who may write, which user a leaf acts for |
//!
//! The author and endpoint claims stay here and stay self-attested, because they
//! genuinely grant nothing on their own. An author id is worthless until the
//! *capability closure* separately says that member may write, and an endpoint id
//! is worthless until the closure separately says that device is certified. Both
//! are joins against authority held elsewhere, which is what makes them safe to
//! let anyone write.
//!
//! # Users and devices
//!
//! A CGKA leaf is a *device*, not a person. Sharing one leaf across a person's
//! laptop and phone is not merely untidy, it is unsound: rotating a leaf
//! replaces the local secret, so two devices rotating the same leaf concurrently
//! issue conflicting updates for it. Each device therefore holds its own leaf,
//! and a signed [`DeviceBinding`](crate::capability::DeviceBinding) records which
//! user it belongs to.
//!
//! **Roles attach to users, not devices** — a laptop that is an admin while its
//! owner's phone is a viewer is a distinction nobody wants to reason about. Use
//! [`CapabilityStore::role_of_member`](crate::capability::CapabilityStore::role_of_member)
//! to resolve a device to its owner's role.
//!
//! A user id is the member id of that user's founding device. It needs no new
//! key material and is stable for the user's lifetime, even after the founding
//! device is itself removed.
//!
//! # Trust boundary
//!
//! Roles remain advisory against a *cryptographically* capable member: anyone
//! holding a leaf can decrypt, whatever any certificate says. That is forward
//! secrecy working as designed, and it is a different statement from the one
//! phase 5 fixed — roles now constrain what a malicious member can **do**, and
//! never constrained what one can **read**. Genuine read revocation is a CGKA
//! removal; see
//! [`CgkaController::remove_member`](crate::keys::CgkaController::remove_member).

use std::fmt::Write as _;

use loro::{ExportMode, LoroDoc, LoroMap};

use crate::{blinding::DocumentUuid, error::CoreError};

/// Root container holding document metadata, keyed by hex document UUID.
const FILES_CONTAINER: &str = "files";

/// Root container holding user records, keyed by hex user id.
const USERS_CONTAINER: &str = "users";

/// Root container holding device *display* records, keyed by hex member id.
///
/// Label and endpoint id only. The device-to-user binding that used to live here
/// is now a signed [`DeviceBinding`](crate::capability::DeviceBinding), because a
/// binding recorded in a CRDT is a binding any member can forge — see the module
/// documentation.
const DEVICES_CONTAINER: &str = "devices";

/// Root container holding workspace-level metadata: name and description.
const META_CONTAINER: &str = "meta";

/// Root container mapping hex data-plane author id to hex CGKA member id.
///
/// The two identities are necessarily distinct. A member is an Ed25519 key in
/// the CGKA tree; an `iroh-docs` author is a *separate*, per-workspace key that
/// signs index entries and syncs in the clear. Without this mapping there is no
/// way to answer the only question that matters when an entry arrives — "is the
/// author of this entry someone the manifest says may write?" — because the
/// entry names an author and the roles name a member.
///
/// Each member publishes its own mapping. That is self-attestation, and it is
/// safe precisely because it grants nothing: the entry is still worthless
/// unless an *admin* separately assigned that member a writing role.
const AUTHORS_CONTAINER: &str = "authors";

/// One person in the workspace.
///
/// The `id` is the member id of this user's founding device; see the module
/// documentation for why that identifier rather than a fresh random one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// Stable identifier for this user.
    pub id: [u8; 32],
    /// Human-readable name, for display only.
    pub display_name: String,
}

/// What the manifest records about one device: display data, nothing more.
///
/// Separate from [`DeviceRecord`] because the two have different trust
/// properties, and giving them one type would invite writing a `user` here
/// again. Everything in this struct is self-attested and grants nothing;
/// [`DeviceRecord`] is the join of this against the capability closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDisplay {
    /// This device's CGKA member id — its leaf in the tree.
    pub member: [u8; 32],
    /// This device's `iroh` endpoint id, once it has announced one.
    ///
    /// Self-attested, and safe to be: claiming an endpoint id grants nothing on
    /// its own, because a peer is admitted only when the member holding it is
    /// both certified and still in the group.
    pub endpoint_id: Option<[u8; 32]>,
    /// Human-readable label, for display only.
    pub label: String,
}

/// One device belonging to a user, holding exactly one CGKA leaf.
///
/// The joined view an application sees: display data from the manifest, plus the
/// owning user from the capability closure. Built by
/// [`WorkspaceState::devices`](crate::state::WorkspaceState::devices) rather than
/// by this module, because the manifest alone cannot answer `user` — and the
/// point of phase 5 is that it must not try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// This device's CGKA member id — its leaf in the tree.
    pub member: [u8; 32],
    /// The user this device belongs to, per its signed binding.
    pub user: [u8; 32],
    /// This device's `iroh` endpoint id, once it has announced one.
    pub endpoint_id: Option<[u8; 32]>,
    /// Human-readable label, for display only.
    pub label: String,
}

/// Workspace-level metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceInfo {
    /// Human-readable workspace name.
    pub name: String,
    /// Longer description, if any.
    pub description: String,
}

/// Metadata for one logical document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Stable identifier; the blinded storage key is derived from this.
    pub uuid: DocumentUuid,
    /// Human-readable path. Changing this is a pure manifest edit.
    pub logical_path: String,
    /// Media type, for applications that care.
    pub mime_type: String,
}

/// The workspace manifest.
///
/// Wraps a [`LoroDoc`]; all mutations go through this type so the container
/// layout stays in one place.
pub struct Manifest {
    doc: LoroDoc,
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manifest")
            .field("files", &self.files().len())
            .field("devices", &self.devices().len())
            .finish()
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn unhex_16(raw: &str) -> Option<[u8; 16]> {
    let bytes = unhex(raw)?;
    bytes.try_into().ok()
}

fn unhex_32(raw: &str) -> Option<[u8; 32]> {
    let bytes = unhex(raw)?;
    bytes.try_into().ok()
}

fn unhex(raw: &str) -> Option<Vec<u8>> {
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).ok())
        .collect()
}

impl Manifest {
    /// Create an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            doc: LoroDoc::new(),
        }
    }

    /// Set the peer identity used to attribute this replica's Loro operations.
    ///
    /// Use the per-workspace author identity, not the node's global one; the
    /// reasoning is the same as for
    /// [`WorkspaceSecret::author_seed`](crate::blinding::WorkspaceSecret::author_seed).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if Loro rejects the peer id.
    pub fn set_peer_id(&self, peer: u64) -> Result<(), CoreError> {
        self.doc
            .set_peer_id(peer)
            .map_err(|e| CoreError::Manifest(e.to_string()))
    }

    fn files_map(&self) -> LoroMap {
        self.doc.get_map(FILES_CONTAINER)
    }

    fn authors_map(&self) -> LoroMap {
        self.doc.get_map(AUTHORS_CONTAINER)
    }

    fn users_map(&self) -> LoroMap {
        self.doc.get_map(USERS_CONTAINER)
    }

    fn devices_map(&self) -> LoroMap {
        self.doc.get_map(DEVICES_CONTAINER)
    }

    fn meta_map(&self) -> LoroMap {
        self.doc.get_map(META_CONTAINER)
    }

    /// Read one string field from a nested container in `map`.
    ///
    /// Nested records must be resolved as containers rather than read from the
    /// shallow `get_value()` snapshot, which is easy to get wrong once and then
    /// copy; this keeps it in one place.
    fn nested_field(map: &LoroMap, key: &str, field: &str) -> Option<String> {
        let node = map.get(key)?.into_container().ok()?.into_map().ok()?;
        node.get(field)?
            .into_value()
            .ok()?
            .into_string()
            .ok()
            .map(|s| s.to_string())
    }

    /// Record or replace this workspace's name and description.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the Loro write fails.
    pub fn set_info(&self, info: &WorkspaceInfo) -> Result<(), CoreError> {
        let meta = self.meta_map();
        meta.insert("name", info.name.as_str())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        meta.insert("description", info.description.as_str())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// This workspace's name and description, empty until one is set.
    #[must_use]
    pub fn info(&self) -> WorkspaceInfo {
        let meta = self.meta_map();
        let get = |field: &str| -> String {
            meta.get(field)
                .and_then(|v| v.into_value().ok())
                .and_then(|v| v.into_string().ok())
                .map(|s| s.to_string())
                .unwrap_or_default()
        };
        WorkspaceInfo {
            name: get("name"),
            description: get("description"),
        }
    }

    /// Record or replace a user.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the Loro write fails.
    pub fn set_user(&self, user: &[u8; 32], display_name: &str) -> Result<(), CoreError> {
        let node = self
            .users_map()
            .insert_container(&hex(user), LoroMap::new())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        node.insert("display_name", display_name)
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// Look up one user.
    #[must_use]
    pub fn user(&self, user: &[u8; 32]) -> Option<UserRecord> {
        let display_name = Self::nested_field(&self.users_map(), &hex(user), "display_name")?;
        Some(UserRecord {
            id: *user,
            display_name,
        })
    }

    /// Every recorded user, in arbitrary order.
    #[must_use]
    pub fn users(&self) -> Vec<UserRecord> {
        let mut out = Vec::new();
        let users = self.users_map();
        users.for_each(|key, _| {
            let Some(id) = unhex_32(key) else { return };
            if let Some(record) = self.user(&id) {
                out.push(record);
            }
        });
        out
    }

    /// Record a device's display label.
    ///
    /// Creates the record that [`Self::set_device_endpoint`] attaches to, so it
    /// must run first. Carries no authority: which user this device acts for is
    /// decided by its signed [`DeviceBinding`](crate::capability::DeviceBinding),
    /// not by anything written here.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the Loro write fails.
    pub fn set_device(&self, member: &[u8; 32], label: &str) -> Result<(), CoreError> {
        let node = self
            .devices_map()
            .insert_container(&hex(member), LoroMap::new())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        node.insert("label", label)
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// Record this device's `iroh` endpoint id.
    ///
    /// Self-attested, and safe to be: an endpoint id grants nothing on its own,
    /// since a peer is admitted only when the member holding it is one the
    /// group already accepted.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::UnknownDevice`] if no record binds this member yet,
    /// or [`CoreError::Manifest`] if the Loro write fails.
    pub fn set_device_endpoint(
        &self,
        member: &[u8; 32],
        endpoint_id: &[u8; 32],
    ) -> Result<(), CoreError> {
        let node = self
            .devices_map()
            .get(&hex(member))
            .and_then(|v| v.into_container().ok())
            .and_then(|c| c.into_map().ok())
            .ok_or(CoreError::UnknownDevice)?;
        node.insert("endpoint_id", hex(endpoint_id).as_str())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// Look up one device's display record.
    ///
    /// `None` means no record exists yet — the label write has not synced. A
    /// device with a record but no binding is a device that speaks for nobody,
    /// which is a question for the capability closure rather than for this map.
    #[must_use]
    pub fn device(&self, member: &[u8; 32]) -> Option<DeviceDisplay> {
        let devices = self.devices_map();
        let key = hex(member);
        // The record exists if it has *either* field; `label` may legitimately be
        // empty, so its presence rather than its content is what is asked.
        let label = Self::nested_field(&devices, &key, "label");
        let endpoint_id =
            Self::nested_field(&devices, &key, "endpoint_id").and_then(|s| unhex_32(&s));
        if label.is_none() && endpoint_id.is_none() {
            return None;
        }
        Some(DeviceDisplay {
            member: *member,
            endpoint_id,
            label: label.unwrap_or_default(),
        })
    }

    /// Every recorded device, in arbitrary order.
    #[must_use]
    pub fn devices(&self) -> Vec<DeviceDisplay> {
        let mut out = Vec::new();
        let devices = self.devices_map();
        devices.for_each(|key, _| {
            let Some(member) = unhex_32(key) else { return };
            if let Some(record) = self.device(&member) {
                out.push(record);
            }
        });
        out
    }

    /// Record that `author` is the data-plane identity of `member`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the Loro write fails.
    pub fn set_author(&self, member: &[u8; 32], author: &[u8; 32]) -> Result<(), CoreError> {
        self.authors_map()
            .insert(&hex(author), hex(member).as_str())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// The member an author id belongs to, if one has claimed it.
    #[must_use]
    pub fn member_for_author(&self, author: &[u8; 32]) -> Option<[u8; 32]> {
        self.authors_map()
            .get(&hex(author))
            .and_then(|v| v.into_value().ok())
            .and_then(|v| v.into_string().ok())
            .and_then(|s| unhex(&s))
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
    }

    /// Record or replace a document's metadata.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the Loro write fails.
    pub fn upsert_file(&self, entry: &FileEntry) -> Result<(), CoreError> {
        let files = self.files_map();
        let key = hex(&entry.uuid.0);
        let node = files
            .insert_container(&key, LoroMap::new())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        node.insert("logical_path", entry.logical_path.as_str())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        node.insert("mime_type", entry.mime_type.as_str())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// Move or rename a document.
    ///
    /// This touches only the manifest: the document's UUID, and therefore its
    /// blinded `iroh-docs` key and all of its stored chunks, are untouched.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::UnknownDocument`] if no such document is recorded.
    pub fn rename(&self, uuid: DocumentUuid, new_path: &str) -> Result<(), CoreError> {
        let files = self.files_map();
        let key = hex(&uuid.0);
        let Some(node) = files.get(&key).and_then(|v| v.into_container().ok()) else {
            return Err(CoreError::UnknownDocument);
        };
        let node = node
            .into_map()
            .map_err(|_| CoreError::Manifest("files entry is not a map".into()))?;
        node.insert("logical_path", new_path)
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// Remove a document from the index.
    ///
    /// A CRDT tombstone, so it converges: a peer that concurrently renamed the
    /// document sees the deletion win or lose deterministically, rather than
    /// the two replicas disagreeing.
    ///
    /// This removes the document from the *workspace*. It does not erase it
    /// from the disk of any member who already synced it, and it cannot: they
    /// hold the plaintext already.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::UnknownDocument`] if no such document is recorded.
    pub fn delete_file(&self, uuid: DocumentUuid) -> Result<(), CoreError> {
        let files = self.files_map();
        let key = hex(&uuid.0);
        if files.get(&key).is_none() {
            return Err(CoreError::UnknownDocument);
        }
        files
            .delete(&key)
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// Every recorded document, in arbitrary order.
    #[must_use]
    pub fn files(&self) -> Vec<FileEntry> {
        let mut out = Vec::new();
        // Each value is a nested container, so this must resolve containers
        // rather than read the shallow `get_value()` snapshot.
        self.files_map().for_each(|key, value| {
            let Some(uuid) = unhex_16(key) else { return };
            let Ok(fields) = value
                .into_container()
                .map_err(|_| ())
                .and_then(|c| c.into_map().map_err(|_| ()))
            else {
                return;
            };
            let get = |name: &str| -> String {
                fields
                    .get(name)
                    .and_then(|v| v.into_value().ok())
                    .and_then(|v| v.into_string().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            };
            out.push(FileEntry {
                uuid: DocumentUuid(uuid),
                logical_path: get("logical_path"),
                mime_type: get("mime_type"),
            });
        });
        out
    }

    /// Look up a document by its logical path.
    #[must_use]
    pub fn resolve_path(&self, path: &str) -> Option<DocumentUuid> {
        self.files()
            .into_iter()
            .find(|f| f.logical_path == path)
            .map(|f| f.uuid)
    }

    /// Export the full manifest state, for a peer joining from scratch.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if Loro cannot encode the state.
    pub fn export_snapshot(&self) -> Result<Vec<u8>, CoreError> {
        self.doc.commit();
        self.doc
            .export(ExportMode::Snapshot)
            .map_err(|e| CoreError::Manifest(e.to_string()))
    }

    /// Merge another replica's manifest bytes into this one.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the bytes cannot be decoded.
    pub fn import(&self, bytes: &[u8]) -> Result<(), CoreError> {
        self.doc
            .import(bytes)
            .map(|_| ())
            .map_err(|e| CoreError::Manifest(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{FileEntry, Manifest};
    use crate::blinding::DocumentUuid;

    fn entry(uuid: u8, path: &str) -> FileEntry {
        FileEntry {
            uuid: DocumentUuid([uuid; 16]),
            logical_path: path.to_string(),
            mime_type: "application/json".to_string(),
        }
    }

    #[test]
    fn records_and_resolves_a_document_path() {
        let m = Manifest::new();
        m.upsert_file(&entry(1, "/finance/q3.json")).unwrap();

        assert_eq!(
            m.resolve_path("/finance/q3.json"),
            Some(DocumentUuid([1u8; 16])),
            "a recorded path should resolve to its document UUID"
        );
    }

    #[test]
    fn rename_preserves_the_document_uuid() {
        let m = Manifest::new();
        m.upsert_file(&entry(1, "/finance/q3.json")).unwrap();
        m.rename(DocumentUuid([1u8; 16]), "/archive/2026-q3.json")
            .unwrap();

        assert_eq!(
            m.resolve_path("/archive/2026-q3.json"),
            Some(DocumentUuid([1u8; 16])),
            "renaming must keep the same UUID, so stored chunks stay reachable"
        );
        assert_eq!(
            m.resolve_path("/finance/q3.json"),
            None,
            "the old path must no longer resolve"
        );
    }

    #[test]
    fn rename_of_an_unknown_document_is_an_error() {
        let m = Manifest::new();
        assert!(
            matches!(
                m.rename(DocumentUuid([9u8; 16]), "/nowhere"),
                Err(crate::CoreError::UnknownDocument)
            ),
            "renaming a document that was never recorded should fail"
        );
    }

    #[test]
    fn concurrent_edits_on_two_replicas_converge() {
        let alice = Manifest::new();
        alice.set_peer_id(1).unwrap();
        let bob = Manifest::new();
        bob.set_peer_id(2).unwrap();

        // Start from a shared base so both replicas share history.
        alice.upsert_file(&entry(1, "/shared.json")).unwrap();
        bob.import(&alice.export_snapshot().unwrap()).unwrap();

        // Partitioned, concurrent edits to different documents.
        alice.upsert_file(&entry(2, "/alice-only.json")).unwrap();
        bob.upsert_file(&entry(3, "/bob-only.json")).unwrap();

        // Heal the partition, exchanging state in both directions.
        let from_alice = alice.export_snapshot().unwrap();
        let from_bob = bob.export_snapshot().unwrap();
        alice.import(&from_bob).unwrap();
        bob.import(&from_alice).unwrap();

        let mut alice_paths: Vec<_> = alice.files().into_iter().map(|f| f.logical_path).collect();
        let mut bob_paths: Vec<_> = bob.files().into_iter().map(|f| f.logical_path).collect();
        alice_paths.sort();
        bob_paths.sort();

        assert_eq!(
            alice_paths, bob_paths,
            "concurrent manifest edits must converge once peers exchange state"
        );
        assert_eq!(
            alice_paths.len(),
            3,
            "no concurrent edit should be lost, got {alice_paths:?}"
        );
    }
}
