//! Types related to the construction and evaluation of transaction proposals.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Display},
};

use nonempty::NonEmpty;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis, PoolType, ShieldedProtocol};
use zip321::{TransactionRequest, Zip321Error};

use crate::{
    fees::TransactionBalance,
    wallet::{Note, ReceivedNote, WalletTransparentOutput},
};

/// Errors that can occur in construction of a [`Step`].
#[derive(Debug, Clone)]
pub enum ProposalError {
    /// The total output value of the transaction request is not a valid Zcash amount.
    RequestTotalInvalid,
    /// The total of transaction inputs overflows the valid range of Zcash values.
    Overflow,
    /// The input total and output total of the payment request are not equal to one another. The
    /// sum of transaction outputs, change, and fees is required to be exactly equal to the value
    /// of provided inputs.
    BalanceError {
        input_total: Zatoshis,
        output_total: Zatoshis,
    },
    /// The `is_shielding` flag may only be set to `true` under the following conditions:
    /// * The total of transparent inputs is nonzero
    /// * There exist no Sapling inputs
    /// * There provided transaction request is empty; i.e. the only output values specified
    ///   are change and fee amounts.
    ShieldingInvalid,
    /// No anchor information could be obtained for the specified block height.
    AnchorNotFound(BlockHeight),
    /// A reference to the output of a prior step is invalid.
    ReferenceError(StepOutput),
    /// An attempted double-spend of a prior step output was detected.
    StepDoubleSpend(StepOutput),
    /// An attempted double-spend of an output belonging to the wallet was detected.
    ChainDoubleSpend(PoolType, TxId, u32),
    /// There was a mismatch between the payments in the proposal's transaction request
    /// and the payment pool selection values.
    PaymentPoolsMismatch,
    /// The proposal tried to spend a change output. Mark the `ChangeValue` as ephemeral if this is intended.
    SpendsChange(StepOutput),
    /// The proposal results in an invalid payment request according to ZIP-321.
    Zip321(Zip321Error),
    /// A proposal step created an ephemeral output that was not spent in any later step.
    #[cfg(feature = "transparent-inputs")]
    EphemeralOutputLeftUnspent(StepOutput),
    /// The proposal included a payment to a TEX address and a spend from a shielded input in the same step.
    #[cfg(feature = "transparent-inputs")]
    PaysTexFromShielded,
    /// The change strategy provided to input selection failed to correctly generate an ephemeral
    /// change output when needed for sending to a TEX address.
    #[cfg(feature = "transparent-inputs")]
    EphemeralOutputsInvalid,
}

impl Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProposalError::RequestTotalInvalid => write!(
                f,
                "The total requested output value is not a valid Zcash amount."
            ),
            ProposalError::Overflow => write!(
                f,
                "The total of transaction inputs overflows the valid range of Zcash values."
            ),
            ProposalError::BalanceError {
                input_total,
                output_total,
            } => write!(
                f,
                "Balance error: the output total {} was not equal to the input total {}",
                u64::from(*output_total),
                u64::from(*input_total)
            ),
            ProposalError::ShieldingInvalid => write!(
                f,
                "The proposal violates the rules for a shielding transaction."
            ),
            ProposalError::AnchorNotFound(h) => {
                write!(f, "Unable to compute anchor for block height {h:?}")
            }
            ProposalError::ReferenceError(r) => {
                write!(f, "No prior step output found for reference {r:?}")
            }
            ProposalError::StepDoubleSpend(r) => write!(
                f,
                "The proposal uses the output of step {r:?} in more than one place."
            ),
            ProposalError::ChainDoubleSpend(pool, txid, index) => write!(
                f,
                "The proposal attempts to spend the same output twice: {pool}, {txid}, {index}"
            ),
            ProposalError::PaymentPoolsMismatch => write!(
                f,
                "The chosen payment pools did not match the payments of the transaction request."
            ),
            ProposalError::SpendsChange(r) => write!(
                f,
                "The proposal attempts to spends the change output created at step {r:?}.",
            ),
            ProposalError::Zip321(r) => write!(
                f,
                "The proposal results in an invalid payment {:?}.",
                r,
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalError::EphemeralOutputLeftUnspent(r) => write!(
                f,
                "The proposal created an ephemeral output at step {r:?} that was not spent in any later step.",
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalError::PaysTexFromShielded => write!(
                f,
                "The proposal included a payment to a TEX address and a spend from a shielded input in the same step.",
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalError::EphemeralOutputsInvalid => write!(
                f,
                "The proposal generator failed to correctly generate an ephemeral change output when needed for sending to a TEX address."
            ),
        }
    }
}

impl std::error::Error for ProposalError {}

/// The Sapling inputs to a proposed transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct ShieldedInputs<NoteRef> {
    anchor_height: BlockHeight,
    notes: NonEmpty<ReceivedNote<NoteRef, Note>>,
}

impl<NoteRef> ShieldedInputs<NoteRef> {
    /// Constructs a [`ShieldedInputs`] from its constituent parts.
    pub fn from_parts(
        anchor_height: BlockHeight,
        notes: NonEmpty<ReceivedNote<NoteRef, Note>>,
    ) -> Self {
        Self {
            anchor_height,
            notes,
        }
    }

    /// Returns the anchor height for Sapling inputs that should be used when constructing the
    /// proposed transaction.
    pub fn anchor_height(&self) -> BlockHeight {
        self.anchor_height
    }

    /// Returns the list of Sapling notes to be used as inputs to the proposed transaction.
    pub fn notes(&self) -> &NonEmpty<ReceivedNote<NoteRef, Note>> {
        &self.notes
    }
}

/// A proposal for a series of transactions to be created.
///
/// Each step of the proposal represents a separate transaction to be created. At present, only
/// transparent outputs of earlier steps may be spent in later steps; the ability to chain shielded
/// transaction steps may be added in a future update.
#[derive(Clone, PartialEq, Eq)]
pub struct Proposal<FeeRuleT, NoteRef> {
    fee_rule: FeeRuleT,
    min_target_height: BlockHeight,
    steps: NonEmpty<Step<NoteRef>>,
}

impl<FeeRuleT, NoteRef> Proposal<FeeRuleT, NoteRef> {
    /// Constructs a validated multi-step [`Proposal`].
    ///
    /// This operation validates the proposal for agreement between outputs and inputs
    /// in the case of multi-step proposals, and ensures that no double-spends are being
    /// proposed.
    ///
    /// Parameters:
    /// * `fee_rule`: The fee rule observed by the proposed transaction.
    /// * `min_target_height`: The minimum block height at which the transaction may be created.
    /// * `steps`: A vector of steps that make up the proposal.
    pub fn multi_step(
        fee_rule: FeeRuleT,
        min_target_height: BlockHeight,
        steps: NonEmpty<Step<NoteRef>>,
    ) -> Result<Self, ProposalError> {
        let mut consumed_chain_inputs: BTreeSet<(PoolType, TxId, u32)> = BTreeSet::new();
        let mut consumed_prior_inputs: BTreeSet<StepOutput> = BTreeSet::new();

        for (i, step) in steps.iter().enumerate() {
            for prior_ref in step.prior_step_inputs() {
                // check that there are no forward references
                if prior_ref.step_index() >= i {
                    return Err(ProposalError::ReferenceError(*prior_ref));
                }
                // check that the reference is valid
                let prior_step = &steps[prior_ref.step_index()];
                match prior_ref.output_index() {
                    StepOutputIndex::Payment(idx) => {
                        if prior_step.transaction_request().payments().len() <= idx {
                            return Err(ProposalError::ReferenceError(*prior_ref));
                        }
                    }
                    StepOutputIndex::Change(idx) => {
                        if prior_step.balance().proposed_change().len() <= idx {
                            return Err(ProposalError::ReferenceError(*prior_ref));
                        }
                    }
                }
                // check that there are no double-spends
                if !consumed_prior_inputs.insert(*prior_ref) {
                    return Err(ProposalError::StepDoubleSpend(*prior_ref));
                }
            }

            for t_out in step.transparent_inputs() {
                let key = (
                    PoolType::TRANSPARENT,
                    TxId::from_bytes(*t_out.outpoint().hash()),
                    t_out.outpoint().n(),
                );
                if !consumed_chain_inputs.insert(key) {
                    return Err(ProposalError::ChainDoubleSpend(key.0, key.1, key.2));
                }
            }

            for s_out in step.shielded_inputs().iter().flat_map(|i| i.notes().iter()) {
                let key = (
                    match &s_out.note() {
                        Note::Sapling(_) => PoolType::SAPLING,
                        #[cfg(feature = "orchard")]
                        Note::Orchard(_) => PoolType::ORCHARD,
                    },
                    *s_out.txid(),
                    s_out.output_index().into(),
                );
                if !consumed_chain_inputs.insert(key) {
                    return Err(ProposalError::ChainDoubleSpend(key.0, key.1, key.2));
                }
            }
        }

        Ok(Self {
            fee_rule,
            min_target_height,
            steps,
        })
    }

    /// Constructs a validated [`Proposal`] having only a single step from its constituent parts.
    ///
    /// This operation validates the proposal for balance consistency and agreement between
    /// the `is_shielding` flag and the structure of the proposal.
    ///
    /// Parameters:
    /// * `transaction_request`: The ZIP 321 transaction request describing the payments to be
    ///   made.
    /// * `payment_pools`: A map from payment index to pool type.
    /// * `transparent_inputs`: The set of previous transparent outputs to be spent.
    /// * `shielded_inputs`: The sets of previous shielded outputs to be spent.
    /// * `balance`: The change outputs to be added the transaction and the fee to be paid.
    /// * `fee_rule`: The fee rule observed by the proposed transaction.
    /// * `min_target_height`: The minimum block height at which the transaction may be created.
    /// * `is_shielding`: A flag that identifies whether this is a wallet-internal shielding
    ///   transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn single_step(
        transaction_request: TransactionRequest,
        payment_pools: BTreeMap<usize, PoolType>,
        transparent_inputs: Vec<WalletTransparentOutput>,
        shielded_inputs: Option<ShieldedInputs<NoteRef>>,
        balance: TransactionBalance,
        fee_rule: FeeRuleT,
        min_target_height: BlockHeight,
        is_shielding: bool,
    ) -> Result<Self, ProposalError> {
        Ok(Self {
            fee_rule,
            min_target_height,
            steps: NonEmpty::singleton(Step::from_parts(
                &[],
                transaction_request,
                payment_pools,
                transparent_inputs,
                shielded_inputs,
                vec![],
                balance,
                is_shielding,
            )?),
        })
    }

    /// Returns the fee rule to be used by the transaction builder.
    pub fn fee_rule(&self) -> &FeeRuleT {
        &self.fee_rule
    }

    /// Returns the target height for which the proposal was prepared.
    ///
    /// The chain must contain at least this many blocks in order for the proposal to
    /// be executed.
    pub fn min_target_height(&self) -> BlockHeight {
        self.min_target_height
    }

    /// Returns the steps of the proposal. Each step corresponds to an independent transaction to
    /// be generated as a result of this proposal.
    pub fn steps(&self) -> &NonEmpty<Step<NoteRef>> {
        &self.steps
    }
}

impl<FeeRuleT: Debug, NoteRef> Debug for Proposal<FeeRuleT, NoteRef> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proposal")
            .field("fee_rule", &self.fee_rule)
            .field("min_target_height", &self.min_target_height)
            .field("steps", &self.steps)
            .finish()
    }
}

/// A reference to either a payment or change output within a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepOutputIndex {
    Payment(usize),
    Change(usize),
}

/// A reference to the output of a step in a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepOutput {
    step_index: usize,
    output_index: StepOutputIndex,
}

impl StepOutput {
    /// Constructs a new [`StepOutput`] from its constituent parts.
    pub fn new(step_index: usize, output_index: StepOutputIndex) -> Self {
        Self {
            step_index,
            output_index,
        }
    }

    /// Returns the step index to which this reference refers.
    pub fn step_index(&self) -> usize {
        self.step_index
    }

    /// Returns the identifier for the payment or change output within
    /// the referenced step.
    pub fn output_index(&self) -> StepOutputIndex {
        self.output_index
    }
}

/// The inputs to be consumed and outputs to be produced in a proposed transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct Step<NoteRef> {
    transaction_request: TransactionRequest,
    payment_pools: BTreeMap<usize, PoolType>,
    transparent_inputs: Vec<WalletTransparentOutput>,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    prior_step_inputs: Vec<StepOutput>,
    balance: TransactionBalance,
    is_shielding: bool,
}

impl<NoteRef> Step<NoteRef> {
    /// Constructs a validated [`Step`] from its constituent parts.
    ///
    /// This operation validates the proposal for balance consistency and agreement between
    /// the `is_shielding` flag and the structure of the proposal.
    ///
    /// Parameters:
    /// * `transaction_request`: The ZIP 321 transaction request describing the payments
    ///   to be made.
    /// * `payment_pools`: A map from payment index to pool type. The set of payment indices
    ///   provided here must exactly match the set of payment indices in the [`TransactionRequest`],
    ///   and the selected pool for an index must correspond to a valid receiver of the
    ///   address at that index (or the address itself in the case of bare transparent or Sapling
    ///   addresses).
    /// * `transparent_inputs`: The set of previous transparent outputs to be spent.
    /// * `shielded_inputs`: The sets of previous shielded outputs to be spent.
    /// * `balance`: The change outputs to be added the transaction and the fee to be paid.
    /// * `is_shielding`: A flag that identifies whether this is a wallet-internal shielding
    ///   transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        prior_steps: &[Step<NoteRef>],
        transaction_request: TransactionRequest,
        payment_pools: BTreeMap<usize, PoolType>,
        transparent_inputs: Vec<WalletTransparentOutput>,
        shielded_inputs: Option<ShieldedInputs<NoteRef>>,
        prior_step_inputs: Vec<StepOutput>,
        balance: TransactionBalance,
        is_shielding: bool,
    ) -> Result<Self, ProposalError> {
        // Verify that the set of payment pools matches exactly a set of valid payment recipients
        if transaction_request.payments().len() != payment_pools.len() {
            return Err(ProposalError::PaymentPoolsMismatch);
        }
        for (idx, pool) in &payment_pools {
            if !transaction_request
                .payments()
                .get(idx)
                .iter()
                .any(|payment| payment.recipient_address().can_receive_as(*pool))
            {
                return Err(ProposalError::PaymentPoolsMismatch);
            }
        }

        let transparent_input_total = transparent_inputs
            .iter()
            .map(|out| out.txout().value)
            .try_fold(Zatoshis::ZERO, |acc, a| {
                (acc + a).ok_or(ProposalError::Overflow)
            })?;

        let shielded_input_total = shielded_inputs
            .iter()
            .flat_map(|s_in| s_in.notes().iter())
            .map(|out| out.note().value())
            .try_fold(Zatoshis::ZERO, |acc, a| (acc + a))
            .ok_or(ProposalError::Overflow)?;

        let prior_step_input_total = prior_step_inputs
            .iter()
            .map(|s_ref| {
                let step = prior_steps
                    .get(s_ref.step_index)
                    .ok_or(ProposalError::ReferenceError(*s_ref))?;
                Ok(match s_ref.output_index {
                    StepOutputIndex::Payment(i) => step
                        .transaction_request
                        .payments()
                        .get(&i)
                        .ok_or(ProposalError::ReferenceError(*s_ref))?
                        .amount(),
                    StepOutputIndex::Change(i) => step
                        .balance
                        .proposed_change()
                        .get(i)
                        .ok_or(ProposalError::ReferenceError(*s_ref))?
                        .value(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .try_fold(Zatoshis::ZERO, |acc, a| (acc + a))
            .ok_or(ProposalError::Overflow)?;

        let input_total = (transparent_input_total + shielded_input_total + prior_step_input_total)
            .ok_or(ProposalError::Overflow)?;

        let request_total = transaction_request
            .total()
            .map_err(|_| ProposalError::RequestTotalInvalid)?;
        let output_total = (request_total + balance.total()).ok_or(ProposalError::Overflow)?;

        if is_shielding
            && (transparent_input_total == Zatoshis::ZERO
                || shielded_input_total > Zatoshis::ZERO
                || request_total > Zatoshis::ZERO)
        {
            return Err(ProposalError::ShieldingInvalid);
        }

        if input_total == output_total {
            Ok(Self {
                transaction_request,
                payment_pools,
                transparent_inputs,
                shielded_inputs,
                prior_step_inputs,
                balance,
                is_shielding,
            })
        } else {
            Err(ProposalError::BalanceError {
                input_total,
                output_total,
            })
        }
    }

    /// Returns the transaction request that describes the payments to be made.
    pub fn transaction_request(&self) -> &TransactionRequest {
        &self.transaction_request
    }
    /// Returns the map from payment index to the pool that has been selected
    /// for the output that will fulfill that payment.
    pub fn payment_pools(&self) -> &BTreeMap<usize, PoolType> {
        &self.payment_pools
    }
    /// Returns the transparent inputs that have been selected to fund the transaction.
    pub fn transparent_inputs(&self) -> &[WalletTransparentOutput] {
        &self.transparent_inputs
    }
    /// Returns the shielded inputs that have been selected to fund the transaction.
    pub fn shielded_inputs(&self) -> Option<&ShieldedInputs<NoteRef>> {
        self.shielded_inputs.as_ref()
    }
    /// Returns the inputs that should be obtained from the outputs of the transaction
    /// created to satisfy a previous step of the proposal.
    pub fn prior_step_inputs(&self) -> &[StepOutput] {
        self.prior_step_inputs.as_ref()
    }
    /// Returns the change outputs to be added to the transaction and the fee to be paid.
    pub fn balance(&self) -> &TransactionBalance {
        &self.balance
    }
    /// Returns a flag indicating whether or not the proposed transaction
    /// is exclusively wallet-internal (if it does not involve any external
    /// recipients).
    pub fn is_shielding(&self) -> bool {
        self.is_shielding
    }

    /// Returns whether or not this proposal requires interaction with the specified pool.
    pub fn involves(&self, pool_type: PoolType) -> bool {
        let input_in_this_pool = || match pool_type {
            PoolType::Transparent => self.is_shielding || !self.transparent_inputs.is_empty(),
            PoolType::Shielded(ShieldedProtocol::Sapling) => {
                self.shielded_inputs.iter().any(|s_in| {
                    s_in.notes()
                        .iter()
                        .any(|note| matches!(note.note(), Note::Sapling(_)))
                })
            }
            #[cfg(feature = "orchard")]
            PoolType::Shielded(ShieldedProtocol::Orchard) => {
                self.shielded_inputs.iter().any(|s_in| {
                    s_in.notes()
                        .iter()
                        .any(|note| matches!(note.note(), Note::Orchard(_)))
                })
            }
            #[cfg(not(feature = "orchard"))]
            PoolType::Shielded(ShieldedProtocol::Orchard) => false,
        };
        let output_in_this_pool = || self.payment_pools().values().any(|pool| *pool == pool_type);
        let change_in_this_pool = || {
            self.balance
                .proposed_change()
                .iter()
                .any(|c| c.output_pool() == pool_type)
        };

        input_in_this_pool() || output_in_this_pool() || change_in_this_pool()
    }
}

impl<NoteRef> Debug for Step<NoteRef> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("transaction_request", &self.transaction_request)
            .field("transparent_inputs", &self.transparent_inputs)
            .field(
                "shielded_inputs",
                &self.shielded_inputs().map(|i| i.notes.len()),
            )
            .field("prior_step_inputs", &self.prior_step_inputs)
            .field(
                "anchor_height",
                &self.shielded_inputs().map(|i| i.anchor_height),
            )
            .field("balance", &self.balance)
            .field("is_shielding", &self.is_shielding)
            .finish_non_exhaustive()
    }
}
