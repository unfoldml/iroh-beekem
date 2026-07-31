//! Durable snapshots: the whole of a node's workspace state as bytes.
//!
//! This module is what turns "local-first" from a claim into a fact. Without it
//! a restart is indistinguishable from a re-join — a new signing key, a new
//! tree, no history — and every peer sees a stranger.
//!
//! # This is the read capability, at rest
//!
//! A snapshot contains the local signing key, the local leaf secret, beekem's
//! `owner_sks`, **every cached PCS key**, the workspace blinding secret and the
//! plaintext-equivalent CRDT documents. Anyone who reads the encoded form can
//! decrypt everything this node can decrypt, now and for as long as the group
//! keeps using epochs derivable from it. It is not encrypted here: this crate
//! does no I/O and holds no key-derivation policy, so protecting the bytes is
//! the storage backend's job — see `iroh-beekem`, which writes them `0600`.
//!
//! [`WorkspaceState::export`](crate::state::WorkspaceState::export) hands back a
//! [`Zeroizing`](zeroize::Zeroizing) buffer, so the encoded copy is scrubbed when
//! the caller drops it.
//!
//! # What is deliberately not persisted
//!
//! Parked control operations, pending chunks, and the four ingestion counters.
//!
//! Both parking areas are *recoverable caches*, not state: a parked operation
//! returns with the next `ControlMsg::Log` exchange on `NeighborUp`, and a
//! parked chunk returns with the next resync. Persisting them would grow the
//! snapshot by up to `MAX_PARKED_OPS` operations plus `MAX_PENDING_CHUNK_BYTES`
//! of ciphertext, to save a round trip that happens anyway.
//!
//! The counters reset as a consequence, and that has a testing implication worth
//! stating: a property asserting `evictions() == 0` across a restart is reading a
//! counter that was zeroed by the restart, not observing a healthy run.
//!
//! # What must be persisted, and is easy to miss
//!
//! Three fields of [`WorkspaceState`](crate::state::WorkspaceState) have no
//! accessor, so a snapshot that reconstructed the node by re-running
//! `found`/`joined` would drop them silently:
//!
//! - `last_ref` — the per-document predecessor refs that causally bind chunk
//!   keys. Lost, this node's next publish claims to follow nothing.
//! - `namespace_ticket` — the only path back for a peer that missed a rotation,
//!   because `Event::ResyncNamespace` is a no-op when it is empty.
//! - `endpoint_id` — re-applied to the manifest on every manifest arrival. Lost,
//!   this node never reappears on any peer's roster and admission control locks
//!   it out of the workspace it already belongs to.

use beekem::{cgka::Cgka, id::MemberId};
use keyhive_crypto::share_key::ShareSecretKey;
use serde::{Deserialize, Serialize};

use crate::{
    blinding::DocumentUuid, capability::Certificate, content::ChunkRef, error::CoreError,
    state::NamespaceEpoch,
};

/// The snapshot layout this build writes and reads.
///
/// Bumped whenever a field is added, removed or reinterpreted. Reading is a
/// strict equality check rather than a `<=` — see [`CoreError::SnapshotVersion`]
/// for why a best-effort decode is the wrong failure mode for a file that holds
/// decryption keys.
pub const SNAPSHOT_VERSION: u16 = 1;

/// The cryptographic half of a snapshot: tree, keys, members, certificates.
///
/// # Why the derived closure is not stored
///
/// [`CapabilityStore`](crate::capability::CapabilityStore) keeps four derived
/// maps — `device_user`, `ever_admin`, `roles` and the rest — and none of them
/// are here. `CapabilityStore::new(founder)` followed by `extend(certificates)`
/// reproduces all of it exactly, because the closure is an order-independent
/// function of the certificate set by construction. Storing the derivation as
/// well as its inputs would create a second thing that can disagree with the
/// first, and the disagreement would be silent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgkaSnapshot {
    /// beekem's tree, carrying `owner_sks` and every cached PCS key.
    pub(crate) cgka: Cgka,
    /// The local signing key's 32 secret bytes.
    ///
    /// `MemorySigner` has no serde derive, but it is a newtype over
    /// `ed25519_dalek::SigningKey`, so the secret round-trips as raw bytes.
    pub(crate) signer: [u8; 32],
    /// The local leaf secret. `share_key` is recomputed from it on import
    /// rather than stored, since a stored copy could disagree with the secret.
    pub(crate) share_secret: ShareSecretKey,
    /// The monotone authorisation predicate, as raw keys.
    ///
    /// Raw bytes rather than `MemberId` because `MemberId` wraps an *expanded*
    /// Ed25519 point: the compressed form is what is 32 bytes, and restoring one
    /// is a decompression that can fail. Keeping the fallible step at the
    /// snapshot boundary is what stops it leaking into every `Result` in the
    /// crate — the same reasoning as [`CoreError::Unauthorized`].
    pub(crate) known_members: Vec<[u8; 32]>,
    /// The non-monotone enumeration and connection-policy predicate.
    pub(crate) current_members: Vec<[u8; 32]>,
    /// The root of the capability closure: the founder's verifying key.
    pub(crate) founder: [u8; 32],
    /// Every certificate this node holds, in the store's deterministic order.
    pub(crate) certificates: Vec<Certificate>,
    /// Operations dropped because the parking area was full.
    ///
    /// Kept even though `parked` itself is not: this counts a *fault* the
    /// operator wants to see accumulate, and resetting it on every restart would
    /// hide a peer that floods the topic slowly.
    pub(crate) evicted_ops: u64,
}

/// One node's complete workspace state, ready to encode.
///
/// # Not zeroized on drop, deliberately
///
/// The struct holds secrets and does *not* scrub them, for two reasons that
/// both point the same way. `Cgka` and `ShareSecretKey` are upstream types with
/// no `Zeroize` impl, so a `Drop` here could scrub `signer` and `secret` while
/// leaving every cached PCS key in place — protection thin enough to be
/// misleading. And a `Drop` impl forbids moving fields out, which is exactly
/// what import does, so it would force the restore path through a sequence of
/// `mem::take`s that leave the same secrets in the same heap.
///
/// The encoded form is what gets protected, and
/// [`WorkspaceState::export`](crate::state::WorkspaceState::export) returns it
/// already wrapped in [`Zeroizing`](zeroize::Zeroizing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    /// Layout version; checked against [`SNAPSHOT_VERSION`] on import.
    pub(crate) version: u16,
    /// Tree, keys, members and certificates.
    pub(crate) cgka: CgkaSnapshot,
    /// The workspace blinding secret. Never rotates, so it is safe to store as
    /// the single value that keys every storage key this node ever computes.
    pub(crate) secret: [u8; 32],
    /// The manifest as a Loro snapshot.
    pub(crate) manifest: Vec<u8>,
    /// Each document as a Loro snapshot.
    ///
    /// `ExportMode::Snapshot` rather than `all_updates()`: this is a local
    /// restore, not a publish, so nothing downstream needs the history to be
    /// self-sufficient under loss.
    pub(crate) docs: Vec<(DocumentUuid, Vec<u8>)>,
    /// The most recent chunk published or applied, per document.
    pub(crate) last_ref: Vec<(DocumentUuid, ChunkRef)>,
    /// This device's announced transport address.
    pub(crate) endpoint_id: Option<[u8; 32]>,
    /// Which generation of the replicated index this node is syncing.
    pub(crate) namespace: NamespaceEpoch,
    /// The capability for that generation, kept so it can be re-announced.
    pub(crate) namespace_ticket: Vec<u8>,
    /// Reserved for phase 9's per-document `published_up_to` version vector.
    ///
    /// Present and empty rather than absent so that adding delta publishing does
    /// not need a version bump and a migration for every existing snapshot.
    pub(crate) published_up_to: Vec<(DocumentUuid, Vec<u8>)>,
}

/// Restore a member identity from its compressed 32-byte form.
///
/// # Errors
///
/// Returns [`CoreError::MalformedKey`] if the bytes are not a point on the
/// curve, which a truncated or corrupted snapshot can produce.
pub(crate) fn member_from_bytes(bytes: [u8; 32]) -> Result<MemberId, CoreError> {
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map(MemberId::from)
        .map_err(|_| CoreError::MalformedKey { key: bytes })
}

#[cfg(test)]
mod tests {
    use beekem::id::TreeId;
    use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{SNAPSHOT_VERSION, member_from_bytes};
    use crate::{
        blinding::WorkspaceSecret, capability::DEFAULT_THRESHOLD, error::CoreError,
        keys::CgkaController, state::WorkspaceState,
    };

    /// A one-member workspace, which is all these checks need.
    fn founded() -> WorkspaceState {
        let mut csprng = ChaCha20Rng::seed_from_u64(1);
        let signer = MemorySigner::generate(&mut csprng);
        let tree_id = TreeId::from(signer.verifying_key());
        let cgka = CgkaController::create(tree_id, signer, &mut csprng).expect("founds a tree");
        WorkspaceState::found(
            cgka,
            WorkspaceSecret::generate(&mut csprng),
            DEFAULT_THRESHOLD,
        )
        .expect("founds a workspace")
    }

    /// In a snapshot recorded by another build, upon import, we expect a refusal
    /// naming both versions rather than a best-effort decode.
    ///
    /// Lives here rather than beside the other snapshot tests because `version`
    /// is `pub(crate)`: nothing outside this crate should be able to mint a
    /// snapshot claiming a layout it was not written in.
    #[test]
    fn a_snapshot_from_another_layout_version_is_refused() {
        let mut snapshot = founded()
            .snapshot()
            .expect("a founded workspace is capturable");
        snapshot.version = SNAPSHOT_VERSION.wrapping_add(1);

        let err = WorkspaceState::from_snapshot(snapshot)
            .expect_err("a snapshot from another layout must not load");
        assert!(
            matches!(err, CoreError::SnapshotVersion { .. }),
            "a version mismatch must say so rather than surface as a decode failure \
             or, worse, as a node that loads and cannot decrypt: {err}"
        );
    }

    /// In a snapshot whose stored identity is not a curve point, upon import, we
    /// expect [`CoreError::MalformedKey`] rather than a panic.
    ///
    /// `MemberId` wraps an *expanded* Ed25519 point, so restoring one from the
    /// 32-byte compressed form is a decompression, and decompression of
    /// arbitrary bytes fails. A snapshot is a file on somebody's disk: it can be
    /// truncated by a full volume or corrupted by the storage layer, and neither
    /// is a reason to abort the process.
    #[test]
    fn a_corrupted_identity_in_a_snapshot_is_an_error_not_a_panic() {
        // Thirty-two `0x02` bytes encode a `y` for which no `x` exists, so
        // decompression fails. Most byte patterns *do* decompress — an arbitrary
        // corruption usually yields a valid key belonging to nobody — which is
        // itself the reason this path returns an error rather than trusting that
        // stored bytes are well formed.
        let err =
            member_from_bytes([0x02; 32]).expect_err("an off-curve encoding must not decompress");
        assert!(
            matches!(err, CoreError::MalformedKey { .. }),
            "corrupted stored identities must be reported, not panicked on: {err}"
        );
    }

    /// In a founded workspace, upon exporting and re-importing, we expect the
    /// tree identity to be unchanged.
    ///
    /// `tree_id` is read back off the founding `Add` rather than stored, so this
    /// is the check that the operation graph — not merely the current tree —
    /// survived the round trip.
    #[test]
    fn a_round_trip_preserves_the_tree_identity() {
        let state = founded();
        let before = state.tree_id();
        let bytes = state.export().expect("a founded workspace exports");
        let after = WorkspaceState::import(&bytes)
            .expect("its own export imports")
            .tree_id();
        assert_eq!(
            before.to_bytes(),
            after.to_bytes(),
            "the restored node belongs to a different tree than the one it resumed, \
             so its gossip topic and its capability root would both be wrong"
        );
    }
}
