//! The encrypted workspace manifest: directory index plus role assignments.
//!
//! Two things live here that deliberately do *not* live in `iroh-docs`:
//!
//! * **Logical paths.** `iroh-docs` only ever sees blinded 32-byte keys (see
//!   [`crate::blinding`]). The mapping from those keys back to
//!   `/finance/q3.json` exists only inside this manifest, which is itself
//!   encrypted like any other content.
//! * **Roles.** This is the *permissions* layer, kept separate from the
//!   *cryptographic* layer. The CGKA tree decides who can decrypt; the manifest
//!   decides who is authorised to act. That separation is what makes multiple
//!   admins and admin hand-off tractable: demoting an admin who remains in the
//!   workspace is a manifest edit with no key rotation at all, whereas removing
//!   them entirely is a manifest edit *plus* a CGKA removal.
//!
//! The manifest is a Loro document, so two peers who edit it concurrently while
//! partitioned converge without a coordinator.
//!
//! # Trust boundary
//!
//! Roles are advisory against a *cryptographically* capable member: anyone
//! holding a leaf can decrypt, whatever the manifest says. Roles constrain what
//! a well-behaved peer will accept, not what a malicious one can read. Genuine
//! read revocation is a CGKA removal; see
//! [`CgkaController::remove_member`](crate::keys::CgkaController::remove_member).

use std::fmt::Write as _;

use loro::{ExportMode, LoroDoc, LoroMap};
use serde::{Deserialize, Serialize};

use crate::{blinding::DocumentUuid, error::CoreError};

/// Root container holding document metadata, keyed by hex document UUID.
const FILES_CONTAINER: &str = "files";
/// Root container holding role assignments, keyed by hex member id.
const ROLES_CONTAINER: &str = "roles";

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

/// What a member is authorised to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// May change roles and add or remove members.
    Admin,
    /// May read and write documents.
    Editor,
    /// May read documents only.
    Viewer,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
        }
    }

    fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "admin" => Some(Self::Admin),
            "editor" => Some(Self::Editor),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// Whether this role may write document content.
    #[must_use]
    pub fn can_write(self) -> bool {
        matches!(self, Self::Admin | Self::Editor)
    }

    /// Whether this role may change roles or membership.
    #[must_use]
    pub fn can_administer(self) -> bool {
        matches!(self, Self::Admin)
    }
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
            .field("roles", &self.roles().len())
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

fn unhex(raw: &str) -> Option<Vec<u8>> {
    if raw.len() % 2 != 0 {
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
        Self { doc: LoroDoc::new() }
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

    fn roles_map(&self) -> LoroMap {
        self.doc.get_map(ROLES_CONTAINER)
    }

    fn authors_map(&self) -> LoroMap {
        self.doc.get_map(AUTHORS_CONTAINER)
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

    /// Whether an entry signed by `author` should be accepted.
    ///
    /// Requires *both* halves: a member must have claimed the author id, and an
    /// admin must have given that member a role that can write. An unclaimed
    /// author, or a claimed one belonging to a viewer, fails.
    ///
    /// This is advisory in the same sense as every other role check — it
    /// constrains what a well-behaved peer accepts, not what a peer holding the
    /// namespace write capability can push into the replica.
    #[must_use]
    pub fn author_may_write(&self, author: &[u8; 32]) -> bool {
        self.member_for_author(author)
            .and_then(|member| self.role_of(&member))
            .is_some_and(Role::can_write)
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

    /// Every recorded document, in arbitrary order.
    #[must_use]
    pub fn files(&self) -> Vec<FileEntry> {
        let mut out = Vec::new();
        // Each value is a nested container, so this must resolve containers
        // rather than read the shallow `get_value()` snapshot.
        self.files_map().for_each(|key, value| {
            let Some(uuid) = unhex_16(key) else { return };
            let Ok(fields) = value.into_container().map_err(|_| ()).and_then(|c| {
                c.into_map().map_err(|_| ())
            }) else {
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

    /// Assign a role to a member.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Manifest`] if the Loro write fails.
    pub fn set_role(&self, member: &[u8; 32], role: Role) -> Result<(), CoreError> {
        self.roles_map()
            .insert(&hex(member), role.as_str())
            .map_err(|e| CoreError::Manifest(e.to_string()))?;
        self.doc.commit();
        Ok(())
    }

    /// The role assigned to a member, if any.
    #[must_use]
    pub fn role_of(&self, member: &[u8; 32]) -> Option<Role> {
        self.roles_map()
            .get(&hex(member))
            .and_then(|v| v.into_value().ok())
            .and_then(|v| v.as_string().map(|s| s.to_string()))
            .as_deref()
            .and_then(Role::from_str)
    }

    /// Every role assignment, in arbitrary order.
    #[must_use]
    pub fn roles(&self) -> Vec<([u8; 32], Role)> {
        let mut out = Vec::new();
        self.roles_map().for_each(|key, value| {
            let Some(bytes) = unhex(key).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                return;
            };
            let Some(role) = value
                .into_value()
                .ok()
                .and_then(|v| v.into_string().ok())
                .and_then(|s| Role::from_str(&s))
            else {
                return;
            };
            out.push((bytes, role));
        });
        out
    }

    /// How many admins the workspace currently has.
    ///
    /// Callers should refuse to demote or remove the last admin; losing every
    /// admin leaves a workspace that nobody can ever administer again.
    #[must_use]
    pub fn admin_count(&self) -> usize {
        self.roles()
            .iter()
            .filter(|(_, role)| role.can_administer())
            .count()
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
    use super::{FileEntry, Manifest, Role};
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
    fn roles_round_trip() {
        let m = Manifest::new();
        let alice = [1u8; 32];
        m.set_role(&alice, Role::Admin).unwrap();

        assert_eq!(m.role_of(&alice), Some(Role::Admin));
        assert_eq!(m.role_of(&[2u8; 32]), None, "unassigned members have no role");
    }

    #[test]
    fn viewer_cannot_write_and_only_admin_can_administer() {
        assert!(!Role::Viewer.can_write(), "viewers are read-only");
        assert!(Role::Editor.can_write(), "editors may write");
        assert!(!Role::Editor.can_administer(), "editors are not admins");
        assert!(Role::Admin.can_administer(), "admins may administer");
    }

    #[test]
    fn admin_count_tracks_demotion() {
        let m = Manifest::new();
        m.set_role(&[1u8; 32], Role::Admin).unwrap();
        m.set_role(&[2u8; 32], Role::Admin).unwrap();
        assert_eq!(m.admin_count(), 2);

        // An admin stepping down while staying in the workspace: a pure
        // manifest edit, with no CGKA rotation.
        m.set_role(&[2u8; 32], Role::Editor).unwrap();
        assert_eq!(
            m.admin_count(),
            1,
            "demoting an admin should reduce the admin count"
        );
        assert_eq!(
            m.role_of(&[2u8; 32]),
            Some(Role::Editor),
            "the demoted admin should remain a member, just without admin rights"
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
