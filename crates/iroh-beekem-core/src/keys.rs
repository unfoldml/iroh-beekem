//! [`CgkaController`]: a synchronous, deterministic wrapper over `beekem::cgka::Cgka`.
//!
//! This is the whole cryptographic surface of the workspace. It owns the CGKA
//! tree, the local signing key and the local leaf secret, and it exposes group
//! membership and content encryption as ordinary synchronous methods.
//!
//! # Causal delivery is the caller's job
//!
//! beekem states plainly that it "assume[s] that all operations are received in
//! causal order". [`CgkaController::merge`] surfaces that as
//! [`MergeOutcome::Deferred`] rather than an error: an operation whose
//! predecessors have not arrived yet is normal under gossip, not a fault. The
//! caller is expected to park it and retry — see
//! [`CgkaController::merge_pending`].

use beekem::{
    cgka::Cgka,
    error::CgkaError,
    id::{MemberId, TreeId},
    operation::CgkaOperation,
};
use future_form::Local;
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{CryptoRng, RngCore};
use std::{collections::HashSet, sync::Arc};

use crate::{
    content::{Chunk, ChunkRef},
    error::CoreError,
    sync_poll::now_or_never,
};

/// A signed CGKA operation as it travels over the control plane.
pub type ControlOp = Arc<Signed<CgkaOperation>>;

/// What happened when an operation was offered to the local CGKA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The operation was new and has been applied.
    Applied,
    /// The operation was already known; nothing changed.
    Duplicate,
    /// The operation's causal predecessors have not arrived yet. It has been
    /// parked and will be retried by [`CgkaController::merge_pending`].
    Deferred,
}

/// Synchronous, deterministic owner of the local CGKA state.
///
/// Every method is pure with respect to the outside world: no clock, no
/// sockets, no filesystem. The only ambient input is the caller-supplied
/// `csprng`, which a simulation seeds deterministically.
#[derive(Clone)]
pub struct CgkaController {
    cgka: Cgka,
    signer: MemorySigner,
    member_id: MemberId,
    share_secret: ShareSecretKey,
    share_key: ShareKey,
    /// Operations received out of causal order, awaiting their predecessors.
    parked: Vec<ControlOp>,
}

impl std::fmt::Debug for CgkaController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CgkaController")
            .field("member_id", &self.member_id)
            .field("group_size", &self.cgka.group_size())
            .field("ops_count", &self.cgka.ops_count())
            .field("parked", &self.parked.len())
            .finish_non_exhaustive()
    }
}

impl CgkaController {
    /// Found a new workspace with the local member as its sole occupant.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the initial tree cannot be built, or
    /// [`CoreError::SignerYielded`] if `signer` is not synchronous.
    pub fn create<R: CryptoRng + RngCore>(
        tree_id: TreeId,
        signer: MemorySigner,
        csprng: &mut R,
    ) -> Result<Self, CoreError> {
        let member_id = MemberId::from(signer.verifying_key());
        let share_secret = ShareSecretKey::generate(csprng);
        let share_key = share_secret.share_key();

        let mut cgka = now_or_never(Cgka::new::<Local, _>(
            tree_id,
            member_id,
            share_key,
            &signer,
        ))
        .ok_or(CoreError::SignerYielded)??;

        // `Cgka::new` leaves `owner_sks` empty; without our own leaf secret in
        // it we cannot encrypt our path on the first update.
        cgka.owner_sks.insert(share_key, share_secret);

        Ok(Self {
            cgka,
            signer,
            member_id,
            share_secret,
            share_key,
            parked: Vec::new(),
        })
    }

    /// Join an existing workspace by replaying its operation log.
    ///
    /// `ops` must be in causal order and start with the founding `Add`. The
    /// invitee's own secret never leaves their device: the log is public,
    /// signed data, and the local leaf secret is spliced in when the replay
    /// reaches this member's own `Add` operation.
    ///
    /// `share_secret` must be the secret half of the [`ShareKey`] the inviter
    /// used in the `Add`, which is why an invite is a two-step exchange: the
    /// invitee publishes a `ShareKey`, the inviter names it in an `Add`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::MissingInitAdd`] if the log does not begin with a
    /// founding `Add`, or [`CoreError::NotInvited`] if it contains no `Add` for
    /// this member.
    pub fn join(
        tree_id: TreeId,
        signer: MemorySigner,
        share_secret: ShareSecretKey,
        ops: &[Signed<CgkaOperation>],
    ) -> Result<Self, CoreError> {
        let member_id = MemberId::from(signer.verifying_key());
        let share_key = share_secret.share_key();

        let Some((init, rest)) = ops.split_first() else {
            return Err(CoreError::MissingInitAdd);
        };
        let CgkaOperation::Add {
            added_id: founder_id,
            pk: founder_pk,
            ref predecessors,
            ..
        } = init.payload
        else {
            return Err(CoreError::MissingInitAdd);
        };
        if !predecessors.is_empty() {
            return Err(CoreError::MissingInitAdd);
        }

        let cgka = Cgka::new_from_init_add(tree_id, founder_id, founder_pk, init.clone())?;

        let mut this = Self {
            cgka,
            signer,
            member_id,
            share_secret,
            share_key,
            parked: Vec::new(),
        };

        let mut invited = founder_id == member_id;
        for op in rest {
            // Taking ownership of the tree happens exactly at our own `Add`:
            // we inherit the current owner's public key map, splice in our own
            // leaf secret, and only then apply the operation.
            if let CgkaOperation::Add { added_id, pk, .. } = op.payload
                && added_id == member_id
            {
                let mut owner_sks = this.cgka.owner_sks.clone();
                owner_sks.insert(pk, share_secret);
                this.cgka = this.cgka.with_new_owner(member_id, owner_sks)?;
                invited = true;
            }
            this.merge(Arc::new(op.clone()))?;
        }

        if !invited {
            return Err(CoreError::NotInvited);
        }
        this.merge_pending()?;
        if this.parked_len() > 0 {
            // Some operation's predecessors never appeared, so the log has a
            // hole. Failing here is far kinder than handing back a controller
            // that silently cannot decrypt anything.
            return Err(CoreError::IncompleteLog {
                unresolved: this.parked_len(),
            });
        }
        Ok(this)
    }

    /// This member's identity in the CGKA tree.
    #[must_use]
    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// The number of members currently holding a leaf.
    #[must_use]
    pub fn group_size(&self) -> u32 {
        self.cgka.group_size()
    }

    /// The founding `Add` operation, needed to bootstrap any joiner.
    #[must_use]
    pub fn init_add_op(&self) -> Signed<CgkaOperation> {
        self.cgka.init_add_op()
    }

    /// The complete operation log in causal order — the payload of an invite.
    ///
    /// beekem topologically sorts its operation graph into epochs of mutually
    /// concurrent operations; flattening those in order yields a log that
    /// [`Self::join`] can replay. A *partial* log is not enough: a joiner whose
    /// log is missing an intermediate operation will park their own `Add`
    /// forever, because its predecessors never arrive.
    ///
    /// The log is public, signed data. It contains no secrets, which is why an
    /// invite can be handed over without any confidential channel.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the operation graph cannot be sorted.
    pub fn op_log(&self) -> Result<Vec<Signed<CgkaOperation>>, CoreError> {
        Ok(self
            .cgka
            .ops()?
            .into_iter()
            .flatten()
            .map(|op| (*op).clone())
            .collect())
    }

    /// Operations parked awaiting their causal predecessors.
    #[must_use]
    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// Admit a new member who has published `share_key`.
    ///
    /// Returns `None` if the member is already present. The returned operation
    /// must be broadcast on the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the tree rejects the addition.
    pub fn add_member(
        &mut self,
        member: MemberId,
        share_key: ShareKey,
    ) -> Result<Option<Signed<CgkaOperation>>, CoreError> {
        let op = now_or_never(self.cgka.add::<Local, _>(member, share_key, &self.signer))
            .ok_or(CoreError::SignerYielded)??;
        Ok(op)
    }

    /// Remove a member, revoking their ability to read future content.
    ///
    /// Returns `None` if the member is not present. The returned operation must
    /// be broadcast on the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] wrapping [`CgkaError::RemoveLastMember`] if
    /// this would empty the group.
    pub fn remove_member(
        &mut self,
        member: MemberId,
    ) -> Result<Option<Signed<CgkaOperation>>, CoreError> {
        let op = now_or_never(self.cgka.remove::<Local, _>(member, &self.signer))
            .ok_or(CoreError::SignerYielded)??;
        Ok(op)
    }

    /// Rotate this member's leaf key, re-keying the path to the root.
    ///
    /// This is the post-compromise security primitive: after a rotation an
    /// attacker holding the old leaf secret can no longer derive group keys.
    /// The returned operation must be broadcast on the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the path cannot be re-encrypted.
    pub fn rotate<R: CryptoRng + RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Signed<CgkaOperation>, CoreError> {
        let new_secret = ShareSecretKey::generate(csprng);
        let new_key = new_secret.share_key();
        let (_, op) = now_or_never(self.cgka.update::<Local, _, R>(
            new_key,
            new_secret,
            &self.signer,
            csprng,
        ))
        .ok_or(CoreError::SignerYielded)??;
        self.share_secret = new_secret;
        self.share_key = new_key;
        Ok(op)
    }

    /// Encrypt a chunk of plaintext under a freshly derived application secret.
    ///
    /// `pred_refs` are the refs of the chunks this one causally follows; they
    /// are bound into the derived key, so a peer can only decrypt once it has
    /// caught up.
    ///
    /// The optional operation in the return value is beekem performing an
    /// implicit PCS update because the tree had no root key. **It must be
    /// broadcast**, or no other peer will be able to decrypt this chunk.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if no application secret can be derived, or
    /// [`CoreError::Aead`] if encryption fails.
    pub fn encrypt<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        pred_refs: &[ChunkRef],
        csprng: &mut R,
    ) -> Result<(Chunk, Option<Signed<CgkaOperation>>), CoreError> {
        let content_ref = ChunkRef::of(plaintext);
        let preds = pred_refs.to_vec();
        let (secret, op) = now_or_never(self.cgka.new_app_secret_for::<Local, _, _, R>(
            &content_ref,
            plaintext,
            &preds,
            &self.signer,
            csprng,
        ))
        .ok_or(CoreError::SignerYielded)??;
        Ok((secret.try_encrypt(plaintext)?, op))
    }

    /// Decrypt a chunk produced by any member of the group.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if the local tree cannot reach the PCS key
    /// the chunk names — which is exactly what a revoked member sees — or
    /// [`CoreError::Aead`] if authentication fails.
    pub fn decrypt(&mut self, chunk: &Chunk) -> Result<Vec<u8>, CoreError> {
        let key = self.cgka.decryption_key_for(chunk)?;
        Ok(chunk.try_decrypt(key)?)
    }

    /// Offer a remote operation to the local CGKA.
    ///
    /// Out-of-order arrivals are parked rather than rejected; call
    /// [`Self::merge_pending`] after any successful merge to drain them.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] for genuine failures — an out-of-order
    /// operation is *not* one of them.
    pub fn merge(&mut self, op: ControlOp) -> Result<MergeOutcome, CoreError> {
        let preds: HashSet<_> = op.payload.predecessors().into_iter().collect();
        if !self.cgka.contains_predecessors(&preds) {
            self.parked.push(op);
            return Ok(MergeOutcome::Deferred);
        }
        match self.cgka.merge_concurrent_operation(op) {
            Ok(true) => Ok(MergeOutcome::Applied),
            Ok(false) => Ok(MergeOutcome::Duplicate),
            // beekem re-checks predecessors internally; treat a race here the
            // same way we treat the check above rather than failing the peer.
            Err(CgkaError::OutOfOrderOperation) => Ok(MergeOutcome::Deferred),
            Err(err) => Err(err.into()),
        }
    }

    /// Retry every parked operation, repeating until no further progress.
    ///
    /// Returns the number of operations that became applicable.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Cgka`] if a parked operation fails for a reason
    /// other than missing predecessors.
    pub fn merge_pending(&mut self) -> Result<usize, CoreError> {
        let mut total = 0;
        loop {
            let candidates = std::mem::take(&mut self.parked);
            let before = total;
            for op in candidates {
                match self.merge(op)? {
                    MergeOutcome::Applied => total += 1,
                    MergeOutcome::Duplicate | MergeOutcome::Deferred => {}
                }
            }
            if total == before {
                return Ok(total);
            }
        }
    }
}
