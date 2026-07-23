//! # Output locking
//!
//! This module is the single home for the wallet's advisory output-locking
//! vocabulary: the identity of a lock holder ([`LockOwner`]), the error surface
//! of lock acquisition ([`LockError`]), the request through which
//! proposal-creation functions acquire locks ([`LockRequest`] and
//! [`unlock_proposal_inputs`]), and the policy types through which input
//! selection interacts with lock state ([`LockedInputPolicy`] and
//! [`LockFilter`]).
//!
//! ## Semantics
//!
//! All lock state is a pair of columns on each received output: a
//! `lock_expiry_height` and a `lock_owner`. Every behavior is derived from the
//! following invariants, stated here once:
//!
//! * **Locked**: an output is *locked* while `lock_expiry_height >=
//!   target_height`, where the target height is the height at which a new
//!   transaction would be mined (chain tip + 1). Balance computations tally an
//!   output as locked under exactly this condition.
//! * **Eligible for selection**: input selection eligibility is the exact
//!   complement of the locked condition, owner-scoped under a
//!   [`LockedInputPolicy`]: an output is eligible when it carries no lock, when
//!   its lock has expired (`lock_expiry_height < target_height`), or when its
//!   `lock_owner` is one of the owners the policy admits. An output locked by
//!   any other owner is never selected.
//! * **Acquisition**: a lock may be acquired ([`WalletWrite::lock_outputs`])
//!   when the output is unlocked, when its existing lock has expired as of the
//!   chain tip, or when the existing lock is held by the *same* owner (an
//!   idempotent re-acquire/extend, so a flow that crashed after locking may
//!   safely retry under its original owner token). Acquisition fails only on
//!   an active foreign lock. There is no stealing: because "expired as of the
//!   chain tip" (`h <= chain_tip`) is exactly "not locked for selection"
//!   (`h < target_height`), a foreign lock is replaceable exactly when the
//!   output has already become selectable again.
//! * **Advisory**: locks are advisory in selection. An owner-scoped policy
//!   override *spends through* a lock during selection; it never releases the
//!   lock.
//! * **Release**: there are exactly four release paths: owner-scoped unlock
//!   ([`WalletWrite::unlock_output`], [`unlock_proposal_inputs`]),
//!   owner-agnostic clearing ([`WalletWrite::clear_locked_outputs`]),
//!   unlock-on-store (implementations of
//!   [`WalletWrite::store_transactions_to_be_sent`] unlock outputs recorded as
//!   spent, the spend records having taken over double-selection protection),
//!   and expiry (the passage of the chain tip beyond `lock_expiry_height`).
//! * **Expiry re-opens the race**: if an operation outlasts its lock window,
//!   the lock expires and a concurrent proposal may select and spend the same
//!   outputs. Lock windows must be chosen conservatively with respect to the
//!   worst-case time between proposal creation and transaction storage.
//!
//! ## Integration map
//!
//! The locking feature touches the codebase at the following points, by role:
//!
//! * **Schema**: the `note_locking` migration in `zcash_client_sqlite`
//!   (`wallet::init::migrations::note_locking`) adds the `lock_expiry_height`
//!   and `lock_owner` columns to the four received-output tables; the table
//!   definitions in `zcash_client_sqlite::wallet::db` carry them forward.
//! * **Acquisition**: the five proposal-creation functions
//!   ([`propose_transfer`], [`propose_standard_transfer_to_address`],
//!   [`propose_send_max_transfer`], [`propose_shielding`], and
//!   [`propose_shielding_coinbase`]) accept an optional [`LockRequest`] and
//!   lock every selected input via [`WalletWrite::lock_outputs`].
//! * **Selection**: the seven `zcash_client_sqlite` leaf queries that select
//!   spendable outputs (`get_spendable_note`, `select_unspent_notes`,
//!   `select_spendable_notes_matching_value`, and `unspent_notes_meta` in
//!   `wallet::common`; `get_spendable_transparent_outputs`,
//!   `get_spendable_transparent_outputs_for_addresses`, and
//!   `select_spendable_transparent_outputs` in `wallet::transparent`) embed
//!   the eligibility fragment parameterized by a [`LockFilter`].
//! * **Balance**: four classification sites tally locked value separately:
//!   the shielded-note branch of `get_wallet_summary` and the three
//!   transparent tallies (`get_transparent_balances` and the two branches of
//!   `add_transparent_account_balances`, including the coinbase arm) in
//!   `zcash_client_sqlite`.
//! * **Release**: the four release paths listed under Semantics above.
//! * **Proposal decoding**: proposal decoding in [`crate::proto`] reads wallet
//!   contents with [`LockFilter::Unfiltered`], since a persisted proposal must
//!   be reconstructible regardless of current lock state.
//! * **Consumers**: `zcash_client_sqlite`'s
//!   `PoolMigrations::migration_lock_owners` exposes the owners of a pool
//!   migration's in-flight locks so callers can construct owner-scoped
//!   policies; Zallet consumes the locking API for its transaction flows.
//!
//! [`WalletWrite::lock_outputs`]: crate::data_api::WalletWrite::lock_outputs
//! [`WalletWrite::unlock_output`]: crate::data_api::WalletWrite::unlock_output
//! [`WalletWrite::clear_locked_outputs`]: crate::data_api::WalletWrite::clear_locked_outputs
//! [`WalletWrite::store_transactions_to_be_sent`]: crate::data_api::WalletWrite::store_transactions_to_be_sent
//! [`propose_transfer`]: crate::data_api::wallet::propose_transfer
//! [`propose_standard_transfer_to_address`]: crate::data_api::wallet::propose_standard_transfer_to_address
//! [`propose_send_max_transfer`]: crate::data_api::wallet::propose_send_max_transfer
//! [`propose_shielding`]: crate::data_api::wallet::propose_shielding
//! [`propose_shielding_coinbase`]: crate::data_api::wallet::propose_shielding_coinbase

use std::collections::BTreeSet;
use std::error;
use std::fmt::{self, Display};

use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, consensus::BlockHeight};

use crate::{
    data_api::{WalletWrite, error::Error, wallet::input_selection::NonEmptyBTreeSet},
    proposal::{Proposal, ProposalError},
    wallet::OutputRef,
};

/// An opaque token identifying the holder of an output lock.
///
/// A caller that locks outputs (directly via [`WalletWrite::lock_outputs`], or through a
/// proposal-creation function's lock request) supplies an owner token and must retain it: the
/// token is what authorizes releasing the locks ([`WalletWrite::unlock_output`],
/// [`unlock_proposal_inputs`]) and what makes re-locking idempotent (an owner may re-acquire or
/// extend its own active lock, for example when retrying a flow after a crash, while a different
/// owner's lock attempt fails until the lock expires).
///
/// The token is not a cryptographic secret: everything that can reach the wallet database can
/// read it. It exists to prevent *accidental* cross-flow interference between concurrent
/// in-process operations, not to protect against an adversary with database access.
///
/// [`WalletWrite::lock_outputs`]: crate::data_api::WalletWrite::lock_outputs
/// [`WalletWrite::unlock_output`]: crate::data_api::WalletWrite::unlock_output
/// [`unlock_proposal_inputs`]: crate::data_api::wallet::unlock_proposal_inputs
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockOwner([u8; 32]);

impl LockOwner {
    /// Constructs a `LockOwner` from the given bytes.
    ///
    /// Callers that persist their own operation state may derive a stable token from it; all
    /// others should prefer [`LockOwner::random`].
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generates a fresh random `LockOwner`.
    pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Returns the byte representation of this token.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A transaction id may serve as a lock owner.
///
/// This is the right owner choice for flows that hold a durable transaction identity while
/// their locks are alive; most notably a persisted PCZT, whose v5 txid is fixed once its
/// effecting data is final. Deriving the owner from the txid lets such a flow re-derive its
/// token after a restart and release (or re-acquire) exactly its own locks.
///
/// It is NOT a suitable owner for proposal-time locking in general: at proposal creation no
/// transaction exists yet, a multi-step proposal builds several transactions, and a
/// transaction rebuilt after a crash generally has a different txid, which would defeat the
/// idempotent same-owner re-lock. Flows without a durable transaction identity should use
/// [`LockOwner::random`] and retain the token.
impl From<TxId> for LockOwner {
    fn from(txid: TxId) -> Self {
        Self(txid.into())
    }
}

/// Errors that occur when attempting to lock an output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockError<S> {
    /// Wrapper for storage errors.
    Storage(S),
    /// The wrapped output reference was not found, or the output it refers to was already locked.
    LockFailure(OutputRef),
}

impl<S: Display> Display for LockError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Storage(e) => write!(f, "Note locking failed: {e}"),
            LockError::LockFailure(output) => {
                write!(
                    f,
                    "Lock conflict or missing output for reference {output:?}"
                )
            }
        }
    }
}

impl<S: error::Error + 'static> error::Error for LockError<S> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LockError::Storage(e) => Some(e),
            LockError::LockFailure(_) => None,
        }
    }
}

/// Returns the [`OutputRef`] identifying each output that the given proposal consumes as an
/// input.
///
/// Each note or UTXO selected for spending is an *input* to the proposal's transaction, but is at
/// the same time an *output* of the earlier transaction that created it; an [`OutputRef`] names it
/// by that creating transaction's id, which is the stable identity the lock tables are keyed on.
fn proposal_input_refs<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
) -> Vec<OutputRef> {
    proposal
        .steps()
        .iter()
        .flat_map(|step| {
            step.shielded_inputs()
                .into_iter()
                .flat_map(|shielded_inputs| {
                    shielded_inputs.notes().iter().map(|note| {
                        OutputRef::new(
                            *note.txid(),
                            PoolType::Shielded(note.note().pool()),
                            u32::from(note.output_index()),
                        )
                    })
                })
                .chain(step.transparent_inputs().iter().map(|utxo| {
                    let outpoint = utxo.outpoint();
                    OutputRef::new(
                        TxId::from_bytes(*outpoint.hash()),
                        PoolType::TRANSPARENT,
                        outpoint.n(),
                    )
                }))
        })
        .collect()
}

/// A request to lock the inputs selected by a proposal, made when calling one of the
/// proposal-creation functions ([`propose_transfer`] and friends).
///
/// The caller supplies the [`LockOwner`] under which the locks are taken and must retain it: the
/// owner token is what authorizes releasing the locks with [`unlock_proposal_inputs`], and what
/// allows the same flow to re-lock its own inputs when retrying after a crash.
///
/// [`propose_transfer`]: crate::data_api::wallet::propose_transfer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockRequest {
    owner: LockOwner,
    for_blocks: u32,
}

impl LockRequest {
    /// Constructs a request to lock the proposal's inputs on behalf of `owner` until
    /// `for_blocks` blocks past the proposal's target height.
    ///
    /// Choose `for_blocks` conservatively with respect to the worst-case time between proposal
    /// creation and transaction storage: once the lock expires, a concurrent proposal may
    /// select the same inputs.
    pub fn new(owner: LockOwner, for_blocks: u32) -> Self {
        Self { owner, for_blocks }
    }

    /// Returns the owner under which the locks will be taken.
    pub fn owner(&self) -> LockOwner {
        self.owner
    }

    /// Returns the number of blocks past the proposal's target height at which the locks will
    /// expire.
    pub fn for_blocks(&self) -> u32 {
        self.for_blocks
    }
}

/// Locks all inputs selected by the given proposal, preventing them from being
/// selected by subsequent proposals. The lock expires at the given height.
#[allow(clippy::type_complexity)]
pub(crate) fn lock_proposal_inputs<DbT, FeeRuleT, NoteRef, TE, SE, FE, CE>(
    wallet_db: &mut DbT,
    proposal: &Proposal<FeeRuleT, NoteRef>,
    owner: LockOwner,
    lock_expiry_height: BlockHeight,
) -> Result<(), Error<DbT::Error, TE, SE, FE, CE, NoteRef>>
where
    DbT: WalletWrite,
{
    match wallet_db.lock_outputs(&proposal_input_refs(proposal), owner, lock_expiry_height) {
        Ok(_) => Ok(()),
        Err(LockError::LockFailure(out_ref)) => {
            Err(Error::Proposal(ProposalError::InputsLocked(out_ref)))
        }
        Err(LockError::Storage(e)) => Err(Error::DataSource(e)),
    }
}

/// Unlocks all inputs selected by the given proposal, reversing the locks acquired when the
/// proposal was created with a [`LockRequest`] under the same `owner`.
///
/// This is useful when a proposal is rejected or abandoned after its inputs were locked, so that
/// the outputs become available for selection and balance computation once again. Because
/// unlocking is scoped to `owner`, inputs that are not locked, or whose locks are held by a
/// different owner (for example a concurrently-created proposal), are left unchanged.
pub fn unlock_proposal_inputs<DbT, FeeRuleT, NoteRef>(
    wallet_db: &mut DbT,
    proposal: &Proposal<FeeRuleT, NoteRef>,
    owner: LockOwner,
) -> Result<(), DbT::Error>
where
    DbT: WalletWrite,
{
    for output_ref in proposal_input_refs(proposal) {
        wallet_db.unlock_output(&output_ref, owner)?;
    }
    Ok(())
}

/// Governs whether input selection may draw on locked outputs, and with what preference.
///
/// Locks are advisory. The default, [`Self::Exclude`], never selects a locked output. The
/// overriding variants each carry the set of lock owners whose locks may be drawn upon; a locked
/// output whose owner is not in that set is never selected, regardless of variant. This keeps an
/// override scoped to a known reason (e.g. the wallet's own pool-migration PCZTs) and leaves every
/// other flow's locks intact. Overriding here only *spends through* a lock during selection; it
/// never releases the lock.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum LockedInputPolicy {
    /// Never select locked outputs.
    #[default]
    Exclude,
    /// Prefer unlocked outputs; draw on outputs locked by one of these owners only as needed to
    /// reach the target value.
    PreferUnlocked(NonEmptyBTreeSet<LockOwner>),
    /// Prefer outputs locked by one of these owners; draw on unlocked outputs only as needed to
    /// reach the target value.
    PreferLocked(NonEmptyBTreeSet<LockOwner>),
}

impl LockedInputPolicy {
    /// The set of lock owners whose locked outputs this policy admits (empty for `Exclude`).
    pub fn overridable_owners(&self) -> &BTreeSet<LockOwner> {
        static EMPTY: BTreeSet<LockOwner> = BTreeSet::new();
        match self {
            LockedInputPolicy::Exclude => &EMPTY,
            LockedInputPolicy::PreferUnlocked(o) | LockedInputPolicy::PreferLocked(o) => o.as_set(),
        }
    }

    /// Whether locked (overridable) outputs are preferred ahead of unlocked ones.
    pub fn prefers_locked(&self) -> bool {
        matches!(self, LockedInputPolicy::PreferLocked(_))
    }

    /// Whether any locked outputs may be selected at all.
    pub fn admits_locked(&self) -> bool {
        !matches!(self, LockedInputPolicy::Exclude)
    }
}

/// How a query filters candidate outputs by lock state.
///
/// Input selection for a proposal passes [`Self::Policy`], carrying the caller's owner-scoped
/// [`LockedInputPolicy`]. Retrieval/decoding paths that must expose wallet contents regardless of
/// locks (proposal decoding, low-level and test accessors) pass [`Self::Unfiltered`]. Keeping the
/// two separate means a `SpendPolicy` can only ever request an owner-scoped override, never an
/// unscoped "ignore all locks".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockFilter<'a> {
    /// Apply the given owner-scoped selection policy.
    Policy(&'a LockedInputPolicy),
    /// Ignore lock state entirely; every matching output is eligible.
    Unfiltered,
}
