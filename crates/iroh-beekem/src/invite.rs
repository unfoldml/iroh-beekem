//! [`Invite`]: a signed, single-use, expiring admission ticket.
//!
//! # What an invite is and is not
//!
//! An invite is **not** a read capability. Joining needs the leaf secret whose
//! [`ShareKey`](keyhive_crypto::share_key::ShareKey) the inviter named in the
//! `Add`, and that secret never travels here — which is why an intercepted
//! ticket cannot decrypt a single chunk, however complete it looks.
//!
//! What it *does* carry is real: the blinding secret (so the holder can compute
//! the storage key of any document whose uuid it can name), an `iroh-docs`
//! ticket for the current namespace, the gossip topic by way of the tree id, and
//! the whole operation log. A holder learns which entries exist, how big they
//! are and when they change. That is a metadata capability, and it is the reason
//! this type is signed, bound, dated and counted rather than being a plain
//! struct anyone can copy.
//!
//! # Where each check runs, and why here rather than in the core
//!
//! Expiry is a clock, and `iroh-beekem-core` has none by design — the whole
//! simulator rests on that, and the `cargo tree` check in CLAUDE.md enforces it.
//! An invite is redeemed exactly once, locally, by the device it names, so the
//! decision is a *local* one whose cost of disagreement is a refused join rather
//! than a diverged group. That is the same line §5.5 of the plan draws for
//! `Grant::not_after`, and it is why every check below lives in this crate.
//!
//! # The residual, stated rather than implied
//!
//! Every check here runs in *this* implementation. A thief who ignores the code
//! and reads the fields directly still holds the blinding secret and the docs
//! ticket, and nothing in a bearer token can prevent that. Two things do: the
//! [`RosterGuard`](crate::Node) refuses their connection because their endpoint
//! is on nobody's roster, and a namespace rotation abandons the replica their
//! ticket names. The group's remedy for a leaked invite is therefore to rotate,
//! not to revoke the ticket — there is nothing to revoke.

use std::time::{SystemTime, UNIX_EPOCH};

use beekem::operation::CgkaOperation;
use iroh::EndpointId;
use iroh_beekem_core::{CapabilityStore, Certificate};
use iroh_docs::DocTicket;
use keyhive_crypto::{signed::Signed, signer::memory::MemorySigner};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// How long a freshly minted invite stays redeemable.
///
/// An hour is long enough for a human to copy a ticket between two machines and
/// short enough that a ticket found in a chat log months later is inert. The
/// admin can always mint another; nothing is lost by expiring early, and the
/// blinding secret is exposed for as long as an unexpired ticket exists.
pub const INVITE_LIFETIME_SECS: u64 = 60 * 60;

/// Domain separation for the invite signature.
///
/// One of three, alongside
/// [`GRANT_DOMAIN`](iroh_beekem_core::capability::GRANT_DOMAIN) and
/// [`BINDING_DOMAIN`](iroh_beekem_core::capability::BINDING_DOMAIN), which carry
/// the full reasoning. In short: [`Signed`] covers `bincode(payload)` with no
/// type name and no discriminator, and verification recomputes it for whatever
/// `T` the deserializer chose — so a genuine `(issuer, signature)` pair transfers
/// between any two payload types whose encodings match byte for byte, and the
/// attacker forges nothing.
///
/// Sixteen bytes of **printable ASCII**, like the other two, and that is not
/// stylistic. bincode writes an enum discriminant as a little-endian `u32`, so
/// bytes 1–3 of any variant index below 2^24 are zero, while an ASCII tag's are
/// not: a tagged payload can therefore never share an encoding with an untagged
/// bincode enum, which is what `CgkaOperation` is. The three tags differ from
/// each other, so no two tagged types can collide either.
///
/// Honest about what this one in particular buys: an invite was never the
/// confusable payload. It encodes to ~232 bytes at minimum against a
/// `DeviceBinding`'s 80, and the only bytes an attacker contributes (`invitee`)
/// must be a valid Ed25519 point at a fixed offset, so its encoding cannot be
/// steered. The tag matters because the *certificates* are tagged now and a
/// uniform rule is checkable, and because it survives the invite growing a
/// smaller wire form later.
pub(crate) const INVITE_DOMAIN: [u8; 16] = *b"iroh-beekem/invt";

/// Why an invite was refused.
///
/// One variant per check rather than a string, because a caller genuinely acts
/// on the difference: an expired ticket means "ask for another", a wrong invitee
/// means "you were handed somebody else's", and a bad signature means the ticket
/// was tampered with in transit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    /// The payload is not an invite: the domain tag is absent or wrong.
    #[error("not an invite: wrong domain tag")]
    WrongDomain,

    /// The signature does not match the payload and the named issuer.
    #[error("invite signature is invalid")]
    BadSignature,

    /// The issuer is not a device the capability closure lets administer.
    #[error("invite was not issued by an administrator")]
    NotAnAdmin,

    /// The invite names a different device.
    #[error("invite was issued to a different device")]
    WrongInvitee,

    /// The invite's validity window has passed.
    #[error("invite expired at {not_after} (now {now})")]
    Expired {
        /// The last second at which the invite was redeemable.
        not_after: u64,
        /// The wall clock at the moment of the check.
        now: u64,
    },

    /// This node has already redeemed an invite with this nonce.
    #[error("invite has already been redeemed")]
    Replayed,

    /// The tree id is not a valid Ed25519 point, so no closure can be rooted.
    #[error("invite carries a malformed tree id")]
    MalformedTreeId,

    /// The local clock is before the Unix epoch, so expiry cannot be decided.
    ///
    /// Refusing rather than treating the invite as fresh: a clock that cannot be
    /// read is a reason to decline, not a reason to skip the check.
    #[error("the system clock cannot be read")]
    NoClock,
}

/// Everything a new member needs to join, and the terms it was granted under.
///
/// Signed as a whole by the admitting device — see [`Invite`]. Every field is
/// inside the signature, so a thief cannot re-address a ticket to themselves,
/// extend its life, or swap the namespace it points at without invalidating it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteTerms {
    /// Domain separation, always `INVITE_DOMAIN`. First field so it is the first
    /// bytes of the signed encoding, and not public so that only this crate can
    /// assemble a well-formed set of terms.
    pub(crate) domain: [u8; 16],
    /// The CGKA tree id, as raw bytes. Also the root of the capability closure
    /// and the seed of the gossip topic.
    pub tree_id: [u8; 32],
    /// The device this ticket admits, as raw verifying-key bytes.
    ///
    /// The binding that makes the ticket non-transferable: [`Invite::verify`]
    /// refuses unless the redeeming [`Identity`](crate::Identity) is this device.
    pub invitee: [u8; 32],
    /// The last second, in Unix time, at which this ticket may be redeemed.
    pub not_after: u64,
    /// Uniquely identifies this ticket, so a redeemed one can be recognised.
    pub nonce: [u8; 16],
    /// The namespace generation [`Self::doc_ticket`] belongs to.
    ///
    /// Carried because the joiner cannot derive it and needs it: seeded into
    /// `WorkspaceState::joined`, it is what stops a peer that is itself behind
    /// from re-announcing an older generation and dragging a fresh joiner onto a
    /// namespace the group abandoned before it arrived.
    pub epoch: u32,
    /// A ticket for the `iroh-docs` namespace, including peer addresses.
    ///
    /// Read or write according to the role the invitee was granted: `iroh-docs`
    /// has no per-member write key, so a write capability handed to a viewer
    /// could never be taken back short of rotating the namespace.
    pub doc_ticket: DocTicket,
    /// The blinding secret for storage keys.
    pub workspace_secret: [u8; 32],
    /// The full CGKA operation log, in causal order.
    pub log: Vec<Signed<CgkaOperation>>,
    /// The capability certificates for the workspace.
    ///
    /// Public, signed data like the log, and not optional: they authorise every
    /// `Add` the log contains, so a joiner handed the log without them would
    /// refuse the whole history including its own admission. They also carry the
    /// joiner's own binding and grant, which is what lets it arrive certified
    /// rather than needing a second round trip.
    pub certs: Vec<Certificate>,
    /// The inviter's endpoint, so the joiner can also gossip with them.
    pub inviter: EndpointId,
}

/// A signed admission ticket.
///
/// The signature is by the *device* that admitted the invitee, and
/// [`Self::verify`] checks that device may administer under the closure the
/// ticket itself carries. That is not circular: the closure is rooted at
/// `tree_id`, which is the founder's verifying key, so the only way to produce a
/// ticket this accepts is to hold a key some chain from the founder authorises.
/// A stranger's fabricated workspace fails at the root.
///
/// This whole ticket should still be delivered over an authenticated,
/// confidential channel — a direct `iroh` QUIC stream to a known public key
/// qualifies, a public gossip topic does not. Signing tells the *invitee* the
/// ticket is genuine; it does nothing to keep a third party from reading one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite(Signed<InviteTerms>);

impl Invite {
    /// Sign a set of terms.
    ///
    /// Crate-internal: an application cannot mint an invite, because minting one
    /// without the `Add` that admits the invitee would produce a ticket that
    /// verifies and admits nothing. The domain tag is not stamped here — it is a
    /// field the caller fills and [`Self::verify`] checks, because a hostile
    /// ticket never passes through this function and the receiving side is the
    /// only side where the check does any work.
    ///
    /// # Errors
    ///
    /// Returns [`InviteError::BadSignature`] if the signer rejects the payload,
    /// which for an in-memory Ed25519 key means the key itself is unusable.
    pub(crate) fn sign(terms: InviteTerms, signer: &MemorySigner) -> Result<Self, InviteError> {
        signer
            .try_sign_sync(terms)
            .map(Self)
            .map_err(|_| InviteError::BadSignature)
    }

    /// A fresh nonce and expiry for a ticket minted now.
    ///
    /// Returns [`InviteError::NoClock`] rather than defaulting the timestamp: an
    /// invite with a fabricated `not_after` is one that never expires or expires
    /// immediately, and neither is a safe guess to make silently.
    pub(crate) fn terms_now<R: CryptoRng + RngCore>(
        csprng: &mut R,
    ) -> Result<([u8; 16], u64), InviteError> {
        let mut nonce = [0u8; 16];
        csprng.fill_bytes(&mut nonce);
        Ok((nonce, unix_now()?.saturating_add(INVITE_LIFETIME_SECS)))
    }

    /// The terms, **unverified**.
    ///
    /// Reading a field is not the same as trusting it. Every caller that acts on
    /// one must have called [`Self::verify`] first; this accessor exists for
    /// display and for the join path, which verifies and then reads.
    #[must_use]
    pub fn terms(&self) -> &InviteTerms {
        self.0.payload()
    }

    /// The device that signed this ticket, as raw verifying-key bytes.
    #[must_use]
    pub fn issuer(&self) -> [u8; 32] {
        self.0.issuer().to_bytes()
    }

    /// The CGKA tree id this ticket admits to.
    #[must_use]
    pub fn tree_id(&self) -> [u8; 32] {
        self.terms().tree_id
    }

    /// The device this ticket admits.
    #[must_use]
    pub fn invitee(&self) -> [u8; 32] {
        self.terms().invitee
    }

    /// This ticket's identifier, which a redeemer records to make it single-use.
    #[must_use]
    pub fn nonce(&self) -> [u8; 16] {
        self.terms().nonce
    }

    /// The last second at which this ticket may be redeemed.
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.terms().not_after
    }

    /// The endpoint that issued this ticket.
    #[must_use]
    pub fn inviter(&self) -> EndpointId {
        self.terms().inviter
    }

    /// Check everything decidable from the ticket alone, for `invitee` at `now`.
    ///
    /// The order is deliberate and cheapest-first, but only after the signature:
    /// nothing in the payload means anything until it is known to be the payload
    /// the issuer signed, so `invitee`, `not_after` and the closure are all read
    /// *after* that check and never before.
    ///
    /// Replay is not checked here, because a ticket is single-use against a
    /// *node*, which this type has no handle on. [`Node::claim_invite`](crate::Node::claim_invite)
    /// is the other half, and `Workspace::join` calls both.
    ///
    /// # Errors
    ///
    /// One [`InviteError`] per failed check; see that type.
    pub fn verify(&self, invitee: [u8; 32], now: u64) -> Result<(), InviteError> {
        let terms = self.terms();

        // The tag first, because a payload that is not an invite at all should
        // not be reported as a signature failure.
        (terms.domain == INVITE_DOMAIN)
            .then_some(())
            .ok_or(InviteError::WrongDomain)?;

        self.0.try_verify().map_err(|_| InviteError::BadSignature)?;

        (terms.invitee == invitee)
            .then_some(())
            .ok_or(InviteError::WrongInvitee)?;

        (terms.not_after >= now).then_some(()).ok_or({
            InviteError::Expired {
                not_after: terms.not_after,
                now,
            }
        })?;

        // Rooted at `tree_id`, which *is* the founder's verifying key, so this
        // asks "does some chain from the founder let the signing device
        // administer" and not merely "did a member sign it". A Viewer holds the
        // log and the workspace secret and could assemble a ticket that parses;
        // this is what stops one being redeemable.
        let mut closure = CapabilityStore::new(terms.tree_id);
        closure.extend(terms.certs.iter().cloned());
        if closure.may_administer(&self.issuer()) {
            Ok(())
        } else {
            Err(InviteError::NotAnAdmin)
        }
    }
}

/// The wall clock in Unix seconds.
///
/// # Errors
///
/// Returns [`InviteError::NoClock`] if the clock is before the Unix epoch.
pub(crate) fn unix_now() -> Result<u64, InviteError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|_| InviteError::NoClock)
}

#[cfg(test)]
mod tests {
    use beekem::id::MemberId;
    use iroh::EndpointId;
    use iroh_beekem_core::{DeviceBinding, Grant, Role};
    use iroh_docs::{DocTicket, NamespaceId, sync::Capability};
    use keyhive_crypto::{signed::Signed, signer::memory::MemorySigner, verifiable::Verifiable};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{INVITE_DOMAIN, Invite, InviteError, InviteTerms};

    /// A signer that is a pure function of `seed`, so a test can name the same
    /// device twice without threading a value between helpers.
    fn signer(seed: u64) -> MemorySigner {
        MemorySigner::generate(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    fn member_bytes(signer: &MemorySigner) -> [u8; 32] {
        MemberId::from(signer.verifying_key()).to_bytes()
    }

    /// A ticket whose only job is to occupy the field.
    ///
    /// None of the checks under test read it: what an invite points *at* is the
    /// transport's problem, and what these tests are about is whether the terms
    /// were agreed by somebody entitled to agree them.
    fn placeholder_ticket() -> DocTicket {
        DocTicket {
            capability: Capability::Read(NamespaceId::from([9u8; 32])),
            nodes: Vec::new(),
        }
    }

    /// An endpoint id derived from a fixed key, so the terms are reproducible.
    fn placeholder_endpoint() -> EndpointId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        EndpointId::from_bytes(&key.to_bytes()).expect("a verifying key is a valid endpoint id")
    }

    /// Terms admitting `invitee`, expiring at `not_after`, into `founder`'s tree.
    ///
    /// `certs` is empty throughout: a store rooted at the founder already answers
    /// `may_administer(founder)` without any certificate, which is what makes the
    /// root a root rather than an infinite regress. Every test below therefore
    /// isolates one check instead of also depending on a certificate chain.
    fn terms(founder: &MemorySigner, invitee: [u8; 32], not_after: u64) -> InviteTerms {
        InviteTerms {
            domain: INVITE_DOMAIN,
            tree_id: member_bytes(founder),
            invitee,
            not_after,
            nonce: [1u8; 16],
            epoch: 0,
            doc_ticket: placeholder_ticket(),
            workspace_secret: [2u8; 32],
            log: Vec::new(),
            certs: Vec::new(),
            inviter: placeholder_endpoint(),
        }
    }

    /// Given terms signed by the founder and presented by the device they name,
    /// inside the validity window, we expect verification to succeed.
    ///
    /// The baseline every negative test below is a single deviation from. Without
    /// it, a `verify` that refused everything would satisfy all of them.
    #[test]
    fn a_well_formed_invite_verifies() {
        let founder = signer(1);
        let invitee = member_bytes(&signer(2));
        let invite = Invite::sign(terms(&founder, invitee, 1_000), &founder)
            .expect("an in-memory key signs");

        assert_eq!(
            invite.verify(invitee, 999),
            Ok(()),
            "a ticket signed by the founder, naming this device, inside its window \
             must verify"
        );
    }

    /// Given a well-formed invite, when a device other than the named invitee
    /// presents it, we expect `WrongInvitee`.
    ///
    /// The binding that makes a ticket non-transferable. Refused before the
    /// closure is even built, so the answer does not depend on who the thief is.
    #[test]
    fn an_invite_names_exactly_one_device() {
        let founder = signer(1);
        let invitee = member_bytes(&signer(2));
        let thief = member_bytes(&signer(3));
        let invite = Invite::sign(terms(&founder, invitee, 1_000), &founder)
            .expect("an in-memory key signs");

        assert_eq!(
            invite.verify(thief, 999),
            Err(InviteError::WrongInvitee),
            "a ticket must be redeemable only by the device inside its signature"
        );
    }

    /// Given a well-formed invite, when it is verified one second past
    /// `not_after`, we expect `Expired`, and at `not_after` exactly, success.
    ///
    /// Both ends of the boundary, because an off-by-one here is either a ticket
    /// that dies a second early — a support call — or one that outlives its
    /// window, which is the whole thing expiry exists to prevent.
    #[test]
    fn an_invite_stops_verifying_at_the_end_of_its_window() {
        let founder = signer(1);
        let invitee = member_bytes(&signer(2));
        let invite = Invite::sign(terms(&founder, invitee, 1_000), &founder)
            .expect("an in-memory key signs");

        assert_eq!(
            invite.verify(invitee, 1_000),
            Ok(()),
            "the last second of the window is still inside it"
        );
        assert_eq!(
            invite.verify(invitee, 1_001),
            Err(InviteError::Expired {
                not_after: 1_000,
                now: 1_001,
            }),
            "one second past the window must be refused, and must say by how much"
        );
    }

    /// Given a signed invite, when any term is altered and the original
    /// signature reattached, we expect `BadSignature`.
    ///
    /// The reason the signature covers the *whole* of the terms rather than a
    /// digest of some of them. Three fields are altered independently because
    /// they are the three an attacker would want: who may redeem it, how long it
    /// lives, and which replica it points at. A field left outside the signed
    /// payload would pass this test in the other two and fail only in its own.
    #[test]
    fn altering_any_term_invalidates_the_signature() {
        let founder = signer(1);
        let invitee = member_bytes(&signer(2));
        let thief = member_bytes(&signer(3));
        let original = Invite::sign(terms(&founder, invitee, 1_000), &founder)
            .expect("an in-memory key signs");

        let readdressed = {
            let mut altered = original.terms().clone();
            altered.invitee = thief;
            altered
        };
        let extended = {
            let mut altered = original.terms().clone();
            altered.not_after = u64::MAX;
            altered
        };
        let redirected = {
            let mut altered = original.terms().clone();
            altered.workspace_secret = [0xAAu8; 32];
            altered
        };

        for (what, altered, presenter) in [
            ("re-addressing the ticket", readdressed, thief),
            ("extending its life", extended, invitee),
            ("swapping the blinding secret", redirected, invitee),
        ] {
            // Reattaching the original signature is the strongest forgery
            // available without the founder's key, which is what makes it the
            // right one to test.
            let forged = Invite(Signed::new(
                altered,
                *original.0.issuer(),
                *original.0.signature(),
            ));
            assert_eq!(
                forged.verify(presenter, 999),
                Err(InviteError::BadSignature),
                "{what} must break the signature"
            );
        }
    }

    /// Given terms carrying the wrong domain tag, when they are verified, we
    /// expect `WrongDomain` — even though the signature over them is genuine.
    ///
    /// This asserts the check is *run*, not that it defends anything today —
    /// nothing in this protocol encodes to the same bytes as an `InviteTerms`,
    /// with or without the tag, and `INVITE_DOMAIN` says why in detail. What the
    /// test protects is the tag surviving: a `verify` that read the field and
    /// never compared it would pass every other test in this module.
    #[test]
    fn a_payload_without_the_domain_tag_is_not_an_invite() {
        let founder = signer(1);
        let invitee = member_bytes(&signer(2));
        let mut mislabelled = terms(&founder, invitee, 1_000);
        mislabelled.domain = *b"something\0\0\0\0\0\0\0";
        let invite = Invite::sign(mislabelled, &founder).expect("an in-memory key signs");

        assert_eq!(
            invite.verify(invitee, 999),
            Err(InviteError::WrongDomain),
            "a genuinely signed payload that is not an invite must be refused as \
             such, not accepted because the signature checks out"
        );
    }

    /// Given an invite signed by a member who is not an administrator, when it
    /// is verified, we expect `NotAnAdmin`.
    ///
    /// A viewer holds the operation log, the certificate store and the blinding
    /// secret, so nothing stops it assembling a ticket that parses. What stops
    /// one being redeemable is that the closure is rooted at `tree_id` — the
    /// founder's verifying key — and no chain from there authorises a viewer to
    /// admit anybody. Here the impostor holds no certificate at all, which is the
    /// strongest form of the case: not even a self-signed grant helps, because a
    /// self-signed grant is admitted by nothing.
    #[test]
    fn an_invite_signed_by_a_non_admin_is_refused() {
        let founder = signer(1);
        let impostor = signer(4);
        let invitee = member_bytes(&signer(2));

        // Terms naming the founder's tree, signed by somebody else.
        let invite = Invite::sign(terms(&founder, invitee, 1_000), &impostor)
            .expect("an in-memory key signs");

        assert_eq!(
            invite.verify(invitee, 999),
            Err(InviteError::NotAnAdmin),
            "a ticket into the founder's tree must be signed by a device some chain \
             from the founder authorises"
        );
    }

    /// Given an impostor that mints itself a binding and an admin grant, when it
    /// signs an invite carrying them, we expect `NotAnAdmin` all the same.
    ///
    /// The self-promotion case, at the invite layer. The certificates in a ticket
    /// are inputs to a closure, not statements the closure believes: an
    /// unadmitted device's grant is admitted by nothing, so `ever_admin` never
    /// grows to include it. Without this test the one above would pass against an
    /// implementation that trusted the certificate set as given.
    #[test]
    fn an_impostor_cannot_certify_itself_into_authority() {
        let founder = signer(1);
        let impostor = signer(4);
        let invitee = member_bytes(&signer(2));
        let impostor_id = member_bytes(&impostor);

        let mut forged = terms(&founder, invitee, 1_000);
        forged.certs = vec![
            DeviceBinding::new(impostor_id, impostor_id, [3u8; 16])
                .sign(&impostor)
                .expect("an in-memory key signs"),
            Grant::new(impostor_id, Role::Admin, 0, None, [4u8; 16])
                .sign(&impostor)
                .expect("an in-memory key signs"),
        ];
        let invite = Invite::sign(forged, &impostor).expect("an in-memory key signs");

        assert_eq!(
            invite.verify(invitee, 999),
            Err(InviteError::NotAnAdmin),
            "certificates an impostor signed for itself must add nothing, or the \
             closure would not be rooted at all"
        );
    }

    /// Given the three domain tags this workspace stamps, we expect them to be
    /// pairwise distinct and free of the byte patterns a bincode enum produces.
    ///
    /// The certificate half of this is asserted inside `iroh-beekem-core`; this
    /// is the cross-crate half, and it is the one that can actually fail. The two
    /// constants live in different crates with different release cadences, so
    /// nothing but a test spanning both notices if a future tag is chosen to
    /// collide with one already in use.
    #[test]
    fn the_invite_tag_is_distinct_from_every_certificate_tag() {
        use iroh_beekem_core::capability::{BINDING_DOMAIN, GRANT_DOMAIN};

        assert!(
            INVITE_DOMAIN != GRANT_DOMAIN && INVITE_DOMAIN != BINDING_DOMAIN,
            "an invite sharing a tag with a certificate would make the tag useless \
             for exactly the pair it is supposed to separate"
        );
        assert!(
            INVITE_DOMAIN.iter().all(u8::is_ascii_graphic),
            "the invite tag must be printable ASCII: bytes 1..4 of a bincode enum \
             discriminant are zero, and it is the absence of zeroes there that \
             stops a tagged payload aliasing an untagged `CgkaOperation`"
        );
    }

    /// Given a set of invite terms, when they are encoded the way [`Signed`]
    /// encodes them, we expect the tag to be the first bytes on the wire.
    ///
    /// The tag only separates anything if it is at the *front*: a domain field
    /// buried after a variable-length member would let a payload be shifted
    /// underneath it. Moving the field is a one-line refactor that breaks the
    /// property and nothing else, which is why the position is asserted rather
    /// than assumed.
    #[test]
    fn the_domain_tag_is_the_first_thing_signed() {
        let founder = signer(1);
        let invitee = member_bytes(&signer(2));
        let encoded =
            bincode::serialize(&terms(&founder, invitee, 1_000)).expect("invite terms serialize");

        assert_eq!(
            encoded[..16],
            INVITE_DOMAIN[..],
            "the domain tag must lead the signed encoding, or a payload could be \
             positioned under it"
        );
    }
}
