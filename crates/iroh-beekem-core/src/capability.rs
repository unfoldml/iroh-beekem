//! Offline-verifiable authorization: who is allowed to act, and on whose word.
//!
//! # The problem this replaces
//!
//! Every role check in the workspace used to read the manifest, and the manifest
//! is a CRDT that merges whatever any member writes. So a member holding the
//! lowest role could write `roles[me] = Admin`, or bind a device of theirs to an
//! admin's user, and every replica would faithfully converge on it. The checks
//! constrained well-behaved peers and nothing else.
//!
//! The tempting fix — have the receiver consult the manifest for the issuer's
//! role — is worse than no fix. The manifest is replicated and converges at
//! different times on different peers, so two peers evaluating the same operation
//! against different manifest views reach different verdicts, one drops an
//! operation the other keeps, and the group diverges *permanently*. Any
//! authorization predicate over mutable replicated state has that shape.
//!
//! Authorization must therefore be **carried by the thing being authorised and
//! verifiable offline**, against a root nobody can argue about.
//!
//! # The root
//!
//! `tree_id` is the founder's Ed25519 verifying key, and the founding `Add` is
//! self-issued and checked in
//! [`CgkaController::join`](crate::keys::CgkaController::join) before any other
//! operation is replayed. So the founder's public key is already an identity
//! every peer holds, agrees on, and cannot be talked out of. A certificate set
//! rooted there needs no new distribution channel, no new secret, and no new
//! convergence argument.
//!
//! # Two predicates, not one
//!
//! [`CapabilityStore`] answers two different questions, and collapsing them has
//! no safe direction — the same conclusion, for the same reason, that
//! `known_members` and `current_members` already reached in [`crate::keys`].
//!
//! * [`CapabilityStore::ever_admin`] is **monotone**: once a user has held an
//!   admin grant, it stays true. This is what decides whether a *certificate* is
//!   admitted, and it must be monotone so that the closure is a pure,
//!   terminating, order-independent function of the certificate set. Two peers
//!   holding the same certificates then always agree, however those certificates
//!   arrived — which is the entire point.
//! * [`CapabilityStore::role_of`] is **non-monotone**: a later grant supersedes
//!   an earlier one, so a user can be demoted. This is what enforces *actions*.
//!   Order-sensitivity is affordable here for the same reason it is on
//!   `current_members`: the cost of two peers disagreeing is a refused action
//!   that the next exchange repairs, not a dropped operation that diverges the
//!   group forever.
//!
//! The consequence is worth stating plainly, because it is not obvious and it is
//! load-bearing: **demotion is a courtesy against a well-behaved peer; removal is
//! the enforcement.** A demoted admin is still `ever_admin`, so certificates it
//! issues are still admitted, and it can issue itself a higher-`seq` grant. What
//! actually strips a malicious admin of authority is CGKA-removing every device
//! of that user, which is already a first-class operation and already converges.
//! This mirrors monotone `known_members` exactly.
//!
//! # What is deliberately not here
//!
//! * **No clock.** [`Grant::not_after`] is carried so the wire format need not
//!   change later, but it is **not evaluated** by anything in this module.
//!   Evaluating an expiry inside an authorization predicate would make
//!   admissibility depend on clock skew, and two peers disagreeing about whether
//!   a grant had expired would drop different operations — reintroducing exactly
//!   the divergence this design exists to avoid. Expiry belongs where a *local*
//!   decision is being made and disagreement is cheap: invite acceptance, in
//!   `iroh-beekem`, which has a clock.
//! * **No retraction.** Certificates are never withdrawn. Revocation is a CGKA
//!   removal.

use std::collections::{BTreeMap, BTreeSet};

use keyhive_crypto::{signed::Signed, signer::memory::MemorySigner};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// What a member is authorised to do.
///
/// Lives here rather than beside the manifest because this is the module that
/// *decides* it. While roles were recorded in the manifest the type sat there
/// too, which read as though a role were a piece of document metadata; it is a
/// capability, and the only thing that can establish one is a signed [`Grant`].
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

/// An admin's statement that a user holds a role.
///
/// Roles attach to *users*, not devices — a laptop that is an admin while its
/// owner's phone is a viewer is a distinction nobody wants to reason about. A
/// device's role is its owner's; see [`CapabilityStore::role_of_member`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The user this grant is about.
    pub subject: [u8; 32],
    /// What that user may do.
    pub capability: Role,
    /// Which generation of this subject's role this is.
    ///
    /// Ordered first when choosing between grants for one subject, with the
    /// certificate digest breaking ties — the same total order
    /// [`NamespaceEpoch`](crate::state::NamespaceEpoch) uses to settle two
    /// concurrent rotations, and for the same reason. A bare "latest wins" has
    /// no meaning in a set with no order, and letting the highest *capability*
    /// win would make demotion impossible.
    pub seq: u64,
    /// When this grant stops being honoured, in absolute milliseconds.
    ///
    /// **Carried, not enforced.** Nothing in this crate reads it; see the module
    /// documentation for why an expiry inside an authorization predicate would
    /// diverge the group.
    pub not_after: Option<u64>,
    /// Distinguishes two otherwise identical grants, so each has its own digest.
    pub nonce: [u8; 16],
}

/// A statement that a CGKA leaf belongs to a particular user.
///
/// This is the binding that makes a leaf attributable to a person, and therefore
/// to a role. It may be issued by an admin, or by an existing device of the same
/// user — enrolling your own phone is not an act of administration. It may never
/// be self-attested, because a device that could name its own user would inherit
/// that user's role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBinding {
    /// The device's CGKA member id — its leaf in the tree.
    pub device: [u8; 32],
    /// The user this device acts for.
    pub user: [u8; 32],
    /// Distinguishes two otherwise identical bindings.
    pub nonce: [u8; 16],
}

/// One signed authorization statement.
///
/// Both variants travel together — on the control plane beside the operation
/// they authorise, in an invite, and in a snapshot — so they share one type and
/// one store rather than two of each.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Certificate {
    /// A user's role.
    Grant(Signed<Grant>),
    /// A device's owner.
    Binding(Signed<DeviceBinding>),
}

impl Grant {
    /// Sign a grant with the issuing device's key.
    ///
    /// Synchronous: `MemorySigner::try_sign_sync` does no I/O, so unlike the
    /// CGKA operations in [`crate::keys`] this needs no `now_or_never` dance and
    /// cannot produce [`CoreError::SignerYielded`].
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn sign(self, signer: &MemorySigner) -> Result<Certificate, CoreError> {
        signer
            .try_sign_sync(self)
            .map(Certificate::Grant)
            .map_err(|e| CoreError::Signing(e.to_string()))
    }
}

impl DeviceBinding {
    /// Sign a binding with the issuing device's key.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Signing`] if the signer rejects the payload.
    pub fn sign(self, signer: &MemorySigner) -> Result<Certificate, CoreError> {
        signer
            .try_sign_sync(self)
            .map(Certificate::Binding)
            .map_err(|e| CoreError::Signing(e.to_string()))
    }
}

impl Certificate {
    /// The device that issued this certificate, as raw verifying-key bytes.
    ///
    /// Raw bytes rather than a `MemberId` because a `MemberId` wraps an expanded
    /// Ed25519 point: rebuilding one costs a point decompression, and this is
    /// read once per certificate per recompute.
    #[must_use]
    pub fn issuer(&self) -> [u8; 32] {
        match self {
            Self::Grant(signed) => signed.issuer().to_bytes(),
            Self::Binding(signed) => signed.issuer().to_bytes(),
        }
    }

    /// This certificate's digest, which identifies it in the store.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        match self {
            Self::Grant(signed) => signed.digest().into(),
            Self::Binding(signed) => signed.digest().into(),
        }
    }

    /// Check the signature against the embedded issuer key.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BadSignature`] if the certificate is forged or was
    /// tampered with in transit.
    pub fn verify(&self) -> Result<(), CoreError> {
        let verified = match self {
            Self::Grant(signed) => signed.try_verify(),
            Self::Binding(signed) => signed.try_verify(),
        };
        verified.map_err(|_| CoreError::BadSignature)
    }
}

/// Every authorization statement this node has accepted, plus what they imply.
///
/// Grow-only. `insert` is idempotent on the certificate digest, and the derived
/// closure is recomputed from scratch rather than patched — a patched closure
/// would depend on insertion order, which is the one thing this type must not do.
#[derive(Debug, Clone)]
pub struct CapabilityStore {
    /// The founder's device id, which is also the founder's user id.
    ///
    /// The axiom. `tree_id` *is* this key, so a certificate chain terminating
    /// here terminates at something every peer already agreed on by joining.
    founder: [u8; 32],
    /// Accepted grants, keyed by digest.
    ///
    /// `BTreeMap` rather than `HashMap` throughout: the closure iterates these,
    /// and iterating in digest order rather than hash order is what makes the
    /// result a deterministic function of the set on every peer and every run.
    grants: BTreeMap<[u8; 32], Signed<Grant>>,
    /// Accepted bindings, keyed by digest.
    bindings: BTreeMap<[u8; 32], Signed<DeviceBinding>>,
    /// Derived: which user each certified device acts for.
    device_user: BTreeMap<[u8; 32], [u8; 32]>,
    /// Derived: every user that has *ever* held an admin grant. Monotone.
    ever_admin: BTreeSet<[u8; 32]>,
    /// Derived: each user's current role, by `(seq, digest)`. Non-monotone.
    roles: BTreeMap<[u8; 32], Role>,
}

impl CapabilityStore {
    /// An empty store rooted at `founder`.
    ///
    /// The founder needs no certificate to be an admin — that is what makes this
    /// a root rather than an infinite regress — so a fresh store already answers
    /// `role_of(founder) == Some(Admin)`. A founder that also mints an explicit
    /// self-signed grant supersedes this seed, because the seed is recorded at
    /// the smallest possible `(seq, digest)`.
    #[must_use]
    pub fn new(founder: [u8; 32]) -> Self {
        let mut this = Self {
            founder,
            grants: BTreeMap::new(),
            bindings: BTreeMap::new(),
            device_user: BTreeMap::new(),
            ever_admin: BTreeSet::new(),
            roles: BTreeMap::new(),
        };
        this.recompute();
        this
    }

    /// The founder's id, which is the root of every valid chain.
    #[must_use]
    pub fn founder(&self) -> [u8; 32] {
        self.founder
    }

    /// Accept one certificate, if its signature checks out and it is new.
    ///
    /// Returns whether the store changed. An already-known certificate is not an
    /// error: certificates ride along with the operations they authorise and are
    /// re-shipped with every log exchange, so re-receiving one is the ordinary
    /// case rather than a fault.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BadSignature`] if the certificate does not verify.
    pub fn insert(&mut self, cert: Certificate) -> Result<bool, CoreError> {
        let changed = self.stage(cert)?;
        if changed {
            self.recompute();
        }
        Ok(changed)
    }

    /// Accept many certificates, recomputing the closure once.
    ///
    /// Returns how many were new. Invalid certificates are **dropped rather than
    /// reported**: a bundle arrives from the network beside an operation, and one
    /// bad entry must not cost the operation or the certificates queued behind
    /// it. Each certificate is independently signed, so dropping one loses
    /// nothing but itself.
    pub fn extend<I: IntoIterator<Item = Certificate>>(&mut self, certs: I) -> usize {
        let mut added = 0_usize;
        for cert in certs {
            if let Ok(true) = self.stage(cert) {
                added += 1;
            } else {
                // Already known, or unverifiable. Neither is worth failing for;
                // see the method documentation.
            }
        }
        if added > 0 {
            self.recompute();
        } else {
            // Nothing new, so the closure cannot have changed.
        }
        added
    }

    /// Verify and store one certificate without recomputing the closure.
    fn stage(&mut self, cert: Certificate) -> Result<bool, CoreError> {
        cert.verify()?;
        let digest = cert.digest();
        Ok(match cert {
            Certificate::Grant(signed) => self.grants.insert(digest, signed).is_none(),
            Certificate::Binding(signed) => self.bindings.insert(digest, signed).is_none(),
        })
    }

    /// Every certificate this store holds, for a log exchange or a snapshot.
    ///
    /// Deterministically ordered, so two peers with the same store ship the same
    /// bytes and a test can compare them.
    #[must_use]
    pub fn certificates(&self) -> Vec<Certificate> {
        self.bindings
            .values()
            .cloned()
            .map(Certificate::Binding)
            .chain(self.grants.values().cloned().map(Certificate::Grant))
            .collect()
    }

    /// How many certificates are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len() + self.bindings.len()
    }

    /// Whether the store holds no certificates beyond the founder axiom.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Recompute everything derived, from the certificate set alone.
    ///
    /// Two nested fixpoints in one loop, because they feed each other: admitting
    /// a binding can reveal the device of a user who turns out to be an admin,
    /// and admitting an admin grant can in turn admit further bindings.
    ///
    /// Termination rests on both derived sets being **monotone within this
    /// function**: `device_user` and `ever_admin` only ever gain entries, and both
    /// are bounded by the certificate set, so the loop runs at most `len()`
    /// rounds. This is why admission consults `ever_admin` and not `roles` — a
    /// non-monotone input could retract an admission made in an earlier round and
    /// the fixpoint would not be well defined, never mind order-independent.
    fn recompute(&mut self) {
        // The axiom: the founder is their own user, and is an admin. Seeded
        // before any certificate is considered, since every chain terminates
        // here and nothing can authorise it.
        let mut device_user = BTreeMap::from([(self.founder, self.founder)]);
        let mut ever_admin = BTreeSet::from([self.founder]);

        loop {
            let mut changed = false;

            for (digest, signed) in &self.bindings {
                let binding = signed.payload();
                // A device's first admitted binding is final. Rebinding a
                // certified device would let whoever wins an iteration race
                // decide who a leaf belongs to — and since iteration is in
                // digest order, that race would be winnable by grinding a
                // nonce. Only an admin can get a second binding admitted at
                // all, and an admin able to rebind a peer's device could
                // equally have removed them.
                if device_user.contains_key(&binding.device) {
                    continue;
                }
                let Some(issuer_user) = device_user.get(&signed.issuer().to_bytes()).copied()
                else {
                    // The issuer is not (yet) a certified device, so it speaks
                    // for nobody. It may become one in a later round.
                    continue;
                };
                // Either the issuer is enrolling a further device of its own
                // user, or it is an admin enrolling anybody.
                if issuer_user == binding.user || ever_admin.contains(&issuer_user) {
                    device_user.insert(binding.device, binding.user);
                    changed = true;
                } else {
                    // Not authorised to make this binding. Deliberately not
                    // remembered as rejected: a later round may make the issuer
                    // an admin, and the certificate is then admissible.
                    let _ = digest;
                }
            }

            for signed in self.grants.values() {
                let grant = signed.payload();
                if !grant.capability.can_administer() {
                    // Only admin grants feed the monotone set; the rest are
                    // resolved into `roles` after the fixpoint settles.
                    continue;
                }
                let Some(issuer_user) = device_user.get(&signed.issuer().to_bytes()).copied()
                else {
                    continue;
                };
                if ever_admin.contains(&issuer_user) && ever_admin.insert(grant.subject) {
                    changed = true;
                } else {
                    // Either the issuer cannot administer, or the subject was
                    // already known to have been an admin.
                }
            }

            if !changed {
                break;
            }
        }

        // Now the roles, from the admitted grants only. The founder's seed is
        // recorded at the smallest possible `(seq, digest)` — the all-zero
        // digest trick `NamespaceEpoch::INITIAL` already uses — so any real
        // grant naming the founder supersedes it rather than tying with it.
        let mut best: BTreeMap<[u8; 32], (u64, [u8; 32])> =
            BTreeMap::from([(self.founder, (0, [0u8; 32]))]);
        let mut roles = BTreeMap::from([(self.founder, Role::Admin)]);

        for (digest, signed) in &self.grants {
            let grant = signed.payload();
            let Some(issuer_user) = device_user.get(&signed.issuer().to_bytes()).copied() else {
                continue;
            };
            if !ever_admin.contains(&issuer_user) {
                continue;
            }
            let rank = (grant.seq, *digest);
            let supersedes = best
                .get(&grant.subject)
                .is_none_or(|current| rank > *current);
            if supersedes {
                best.insert(grant.subject, rank);
                roles.insert(grant.subject, grant.capability);
            } else {
                // An older generation of this subject's role, or a concurrent
                // grant that lost the digest tie-break.
            }
        }

        self.device_user = device_user;
        self.ever_admin = ever_admin;
        self.roles = roles;
    }

    /// Whether this user has ever held an admin grant. **Monotone.**
    ///
    /// The predicate that admits certificates. Never use it to decide whether an
    /// action is permitted *now* — that is [`Self::role_of`] — and see the module
    /// documentation for why the two cannot be the same question.
    #[must_use]
    pub fn ever_admin(&self, user: &[u8; 32]) -> bool {
        self.ever_admin.contains(user)
    }

    /// This user's current role, if any valid grant names them.
    #[must_use]
    pub fn role_of(&self, user: &[u8; 32]) -> Option<Role> {
        self.roles.get(user).copied()
    }

    /// The user a certified device acts for.
    ///
    /// `None` means the device holds no admitted binding — either its
    /// certificate has not arrived yet, or nobody authorised to bind it ever
    /// did. Both answers are "this leaf speaks for nobody", which is what
    /// callers need.
    #[must_use]
    pub fn user_of(&self, device: &[u8; 32]) -> Option<[u8; 32]> {
        self.device_user.get(device).copied()
    }

    /// The role a *device* acts under: its owner's.
    #[must_use]
    pub fn role_of_member(&self, device: &[u8; 32]) -> Option<Role> {
        self.role_of(&self.user_of(device)?)
    }

    /// Whether this device holds an admitted binding.
    #[must_use]
    pub fn is_certified_device(&self, device: &[u8; 32]) -> bool {
        self.device_user.contains_key(device)
    }

    /// Every certified device, in ascending id order.
    pub fn certified_devices(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.device_user.keys().copied()
    }

    /// Every certified device belonging to one user, in ascending id order.
    #[must_use]
    pub fn devices_of(&self, user: &[u8; 32]) -> Vec<[u8; 32]> {
        self.device_user
            .iter()
            .filter(|(_, owner)| *owner == user)
            .map(|(device, _)| *device)
            .collect()
    }

    /// Every user holding a role, with that role, in ascending id order.
    #[must_use]
    pub fn roles(&self) -> Vec<([u8; 32], Role)> {
        self.roles.iter().map(|(u, r)| (*u, *r)).collect()
    }

    /// How many users currently hold an administrative role.
    ///
    /// Counted per user, not per device: a person with three devices is one
    /// administrator, and counting leaves would let the last admin be removed
    /// while the count still looked healthy.
    #[must_use]
    pub fn admin_count(&self) -> usize {
        self.roles
            .values()
            .filter(|role| role.can_administer())
            .count()
    }

    /// Whether this device may issue membership changes.
    #[must_use]
    pub fn may_administer(&self, device: &[u8; 32]) -> bool {
        self.role_of_member(device)
            .is_some_and(Role::can_administer)
    }

    /// Whether `issuer` may enrol a device for `user`.
    ///
    /// True when the issuer acts for that same user — enrolling your own phone —
    /// or when it may administer. Anything else would let a member bind a device
    /// of theirs to an admin's user and inherit the role.
    #[must_use]
    pub fn may_bind_device_to(&self, issuer: &[u8; 32], user: &[u8; 32]) -> bool {
        self.user_of(issuer) == Some(*user) || self.may_administer(issuer)
    }

    /// The next generation number to use when re-granting `subject`'s role.
    ///
    /// One past the highest `seq` any grant for this subject carries, admitted or
    /// not. Counting rejected grants too is deliberate: a member that mints
    /// itself a grant with a huge `seq` would otherwise be able to freeze a
    /// legitimate admin's ability to supersede it.
    #[must_use]
    pub fn next_seq(&self, subject: &[u8; 32]) -> u64 {
        self.grants
            .values()
            .filter(|signed| signed.payload().subject == *subject)
            .map(|signed| signed.payload().seq)
            .max()
            .map_or(0, |highest| highest.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{CapabilityStore, Certificate, DeviceBinding, Grant, Role};

    /// A signer and its device id.
    fn device(seed: u64) -> (MemorySigner, [u8; 32]) {
        let signer = MemorySigner::generate(&mut ChaCha20Rng::seed_from_u64(seed));
        let id = signer.verifying_key().to_bytes();
        (signer, id)
    }

    fn grant(
        signer: &MemorySigner,
        subject: [u8; 32],
        capability: Role,
        seq: u64,
        nonce: u8,
    ) -> Certificate {
        Grant {
            subject,
            capability,
            seq,
            not_after: None,
            nonce: [nonce; 16],
        }
        .sign(signer)
        .expect("signing a grant is infallible with a memory signer")
    }

    fn bind(signer: &MemorySigner, dev: [u8; 32], user: [u8; 32], nonce: u8) -> Certificate {
        DeviceBinding {
            device: dev,
            user,
            nonce: [nonce; 16],
        }
        .sign(signer)
        .expect("signing a binding is infallible with a memory signer")
    }

    /// Given a store rooted at a founder, when nothing has been inserted, we
    /// expect the founder to already be an admin.
    ///
    /// The root has to be axiomatic. If the founder needed a certificate to be an
    /// admin, that certificate would need an issuer who was already an admin, and
    /// no workspace could ever bootstrap.
    #[test]
    fn the_founder_is_an_admin_without_any_certificate() {
        let (_, founder) = device(1);
        let store = CapabilityStore::new(founder);

        assert_eq!(
            store.role_of(&founder),
            Some(Role::Admin),
            "the founder must be an admin by axiom, or no workspace can bootstrap"
        );
        assert_eq!(
            store.user_of(&founder),
            Some(founder),
            "the founding device must resolve to the founding user, or the founder's own \
             leaf speaks for nobody"
        );
    }

    /// Given a founder who grants a viewer role to a new user and binds their
    /// device, when that user's role is read back, we expect the granted role.
    #[test]
    fn an_admin_can_admit_a_user_and_bind_their_device() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let mut store = CapabilityStore::new(founder);

        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder may bind any device");
        store
            .insert(grant(&founder_signer, bob, Role::Viewer, 0, 2))
            .expect("the founder may grant any role");

        assert_eq!(
            store.role_of_member(&bob),
            Some(Role::Viewer),
            "a device admitted by an admin must resolve to the role it was granted"
        );
    }

    /// Given a member holding a non-administrative role, when that member signs a
    /// grant promoting itself, we expect the store to ignore it.
    ///
    /// This is the escalation the whole module exists to refuse. The certificate
    /// verifies — it is genuinely signed by a genuine member — and it is still
    /// not admitted, because its issuer holds no capability that admits it.
    #[test]
    fn a_viewer_cannot_promote_itself() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder binds bob's device");
        store
            .insert(grant(&founder_signer, bob, Role::Viewer, 0, 2))
            .expect("bob is a viewer");

        store
            .insert(grant(&bob_signer, bob, Role::Admin, 99, 3))
            .expect("a validly signed certificate is stored even when it grants nothing");

        assert_eq!(
            store.role_of(&bob),
            Some(Role::Viewer),
            "a viewer promoted itself by signing its own grant, so the certificate closure \
             is not checking who was permitted to issue it"
        );
        assert!(
            !store.ever_admin(&bob),
            "a self-issued admin grant made its subject permanently able to admit further \
             certificates, which would make the escalation irreversible"
        );
    }

    /// Given a member with no administrative role, when that member binds a
    /// device to another user's account, we expect the binding to be ignored.
    #[test]
    fn a_viewer_cannot_bind_a_device_to_another_users_account() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let (_, mallory) = device(3);
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder binds bob's device");
        store
            .insert(grant(&founder_signer, bob, Role::Viewer, 0, 2))
            .expect("bob is a viewer");

        store
            .insert(bind(&bob_signer, mallory, founder, 3))
            .expect("the certificate is stored");

        assert_eq!(
            store.user_of(&mallory),
            None,
            "a viewer bound a device it controls to the founder's user, so that device \
             would inherit the founder's admin role"
        );
    }

    /// Given a user who owns one device, when that device binds a second device
    /// to the same user, we expect the second device to be certified.
    ///
    /// Enrolling your own phone is not an act of administration, and requiring an
    /// admin for it would make multi-device support an administrative burden.
    #[test]
    fn a_device_may_enrol_a_sibling_device_of_its_own_user() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let (_, bob_phone) = device(3);
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&founder_signer, bob, bob, 1))
            .expect("the founder binds bob's laptop");
        store
            .insert(grant(&founder_signer, bob, Role::Editor, 0, 2))
            .expect("bob is an editor");

        store
            .insert(bind(&bob_signer, bob_phone, bob, 3))
            .expect("bob enrols his own phone");

        assert_eq!(
            store.role_of_member(&bob_phone),
            Some(Role::Editor),
            "a second device of the same user must inherit that user's role, since roles \
             attach to people rather than to leaves"
        );
    }

    /// Given two grants for one subject, when they carry different `seq` values,
    /// we expect the higher one to decide the role regardless of insertion order.
    ///
    /// Demotion depends on this. Insertion order is the thing a network controls
    /// and the thing a convergent store must not depend on, so both orders are
    /// asserted rather than one.
    #[test]
    fn the_highest_seq_grant_decides_the_role_in_either_order() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let promote = grant(&founder_signer, bob, Role::Admin, 1, 1);
        let demote = grant(&founder_signer, bob, Role::Viewer, 2, 2);

        let mut forwards = CapabilityStore::new(founder);
        forwards.insert(bind(&founder_signer, bob, bob, 3)).unwrap();
        forwards.insert(promote.clone()).unwrap();
        forwards.insert(demote.clone()).unwrap();

        let mut backwards = CapabilityStore::new(founder);
        backwards
            .insert(bind(&founder_signer, bob, bob, 3))
            .unwrap();
        backwards.insert(demote).unwrap();
        backwards.insert(promote).unwrap();

        assert_eq!(
            forwards.role_of(&bob),
            Some(Role::Viewer),
            "the later generation of a role must win, or an admin cannot be demoted"
        );
        assert_eq!(
            forwards.role_of(&bob),
            backwards.role_of(&bob),
            "two peers that received the same two grants in opposite orders disagreed about \
             the resulting role, so the closure depends on delivery order"
        );
        assert!(
            forwards.ever_admin(&bob),
            "demotion must not retract `ever_admin`: it is the monotone predicate that keeps \
             certificate admission order-independent"
        );
    }

    /// Given certificates that arrive before the certificate authorising their
    /// issuer, when the closure is recomputed, we expect the same result as if
    /// they had arrived in causal order.
    ///
    /// This is the property that lets a certificate bundle be shipped in any
    /// order and a log be replayed from any starting point. The fixpoint exists
    /// precisely so that a certificate rejected on one pass is reconsidered once
    /// its issuer becomes admissible.
    #[test]
    fn a_certificate_arriving_before_its_issuers_is_admitted_once_the_issuer_is() {
        let (founder_signer, founder) = device(1);
        let (bob_signer, bob) = device(2);
        let (_, bob_phone) = device(3);

        // Bob's phone is enrolled by bob, whose own binding comes last.
        let mut store = CapabilityStore::new(founder);
        store
            .insert(bind(&bob_signer, bob_phone, bob, 1))
            .expect("stored, though not yet admissible");
        assert_eq!(
            store.user_of(&bob_phone),
            None,
            "a binding whose issuer is not yet certified must not be admitted, or the order \
             of arrival would decide who is a member"
        );

        store
            .insert(bind(&founder_signer, bob, bob, 2))
            .expect("the founder certifies bob");

        assert_eq!(
            store.user_of(&bob_phone),
            Some(bob),
            "the out-of-order binding was never reconsidered once its issuer became \
             certified, so a bundle would have to be delivered in causal order"
        );
    }

    /// Given a device already bound to a user, when a second binding names a
    /// different user for it, we expect the first to stand.
    #[test]
    fn a_certified_device_cannot_be_rebound() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let (_, carol) = device(3);
        let mut store = CapabilityStore::new(founder);
        store.insert(bind(&founder_signer, bob, bob, 1)).unwrap();

        store
            .insert(bind(&founder_signer, bob, carol, 2))
            .expect("the certificate is stored");

        assert_eq!(
            store.user_of(&bob),
            Some(bob),
            "a device's binding was overwritten, so whoever issues the last binding decides \
             which user a leaf acts for"
        );
    }

    /// Given a forged certificate, when it is offered to the store, we expect a
    /// signature error and no change.
    #[test]
    fn a_certificate_with_a_broken_signature_is_refused() {
        let (founder_signer, founder) = device(1);
        let (_, bob) = device(2);
        let mut store = CapabilityStore::new(founder);

        // Re-sign a different payload under the same signature by swapping the
        // payload out of a valid certificate.
        let Certificate::Grant(valid) = grant(&founder_signer, bob, Role::Viewer, 0, 1) else {
            unreachable!("grant() returns a Grant variant")
        };
        let forged = Certificate::Grant(keyhive_crypto::signed::Signed::new(
            Grant {
                subject: bob,
                capability: Role::Admin,
                seq: 0,
                not_after: None,
                nonce: [1u8; 16],
            },
            *valid.issuer(),
            *valid.signature(),
        ));

        assert!(
            store.insert(forged).is_err(),
            "a certificate whose payload does not match its signature was accepted, so the \
             capability closure could be rewritten by anyone who has seen one certificate"
        );
        assert_eq!(
            store.role_of(&bob),
            None,
            "the refused certificate still changed the closure"
        );
    }
}
