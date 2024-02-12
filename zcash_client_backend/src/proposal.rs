use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Display},
};

use nonempty::NonEmpty;
use zcash_primitives::{
    consensus::BlockHeight, transaction::components::amount::NonNegativeAmount,
};

use crate::{
    fees::TransactionBalance,
    wallet::{Note, ReceivedNote, WalletTransparentOutput},
    zip321::TransactionRequest,
    PoolType,
};

/// Errors that can occur in construction of a [`Proposal`].
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
        input_total: NonNegativeAmount,
        output_total: NonNegativeAmount,
    },
    /// The `is_shielding` flag may only be set to `true` under the following conditions:
    /// * The total of transparent inputs is nonzero
    /// * There exist no Sapling inputs
    /// * There provided transaction request is empty; i.e. the only output values specified
    ///   are change and fee amounts.
    ShieldingInvalid,
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

/// The inputs to be consumed and outputs to be produced in a proposed transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct Proposal<FeeRuleT, NoteRef> {
    transaction_request: TransactionRequest,
    payment_pools: BTreeMap<usize, PoolType>,
    transparent_inputs: Vec<WalletTransparentOutput>,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    balance: TransactionBalance,
    fee_rule: FeeRuleT,
    min_target_height: BlockHeight,
    is_shielding: bool,
}

impl<FeeRuleT, NoteRef> Proposal<FeeRuleT, NoteRef> {
    /// Constructs a validated [`Proposal`] from its constituent parts.
    ///
    /// This operation validates the proposal for balance consistency and agreement between
    /// the `is_shielding` flag and the structure of the proposal.
    ///
    /// Parameters:
    /// * `transaction_request`: The ZIP 321 transaction request describing the payments
    ///   to be made.
    /// * `payment_pools`: A map from payment index to pool type.
    /// * `transparent_inputs`: The set of previous transparent outputs to be spent.
    /// * `shielded_inputs`: The sets of previous shielded outputs to be spent.
    /// * `balance`: The change outputs to be added the transaction and the fee to be paid.
    /// * `fee_rule`: The fee rule observed by the proposed transaction.
    /// * `min_target_height`: The minimum block height at which the transaction may be created.
    /// * `is_shielding`: A flag that identifies whether this is a wallet-internal shielding
    ///   transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        transaction_request: TransactionRequest,
        payment_pools: BTreeMap<usize, PoolType>,
        transparent_inputs: Vec<WalletTransparentOutput>,
        shielded_inputs: Option<ShieldedInputs<NoteRef>>,
        balance: TransactionBalance,
        fee_rule: FeeRuleT,
        min_target_height: BlockHeight,
        is_shielding: bool,
    ) -> Result<Self, ProposalError> {
        let transparent_input_total = transparent_inputs
            .iter()
            .map(|out| out.txout().value)
            .fold(Ok(NonNegativeAmount::ZERO), |acc, a| {
                (acc? + a).ok_or(ProposalError::Overflow)
            })?;
        let shielded_input_total = shielded_inputs
            .iter()
            .flat_map(|s_in| s_in.notes().iter())
            .map(|out| out.note().value())
            .fold(Some(NonNegativeAmount::ZERO), |acc, a| (acc? + a))
            .ok_or(ProposalError::Overflow)?;
        let input_total =
            (transparent_input_total + shielded_input_total).ok_or(ProposalError::Overflow)?;

        let request_total = transaction_request
            .total()
            .map_err(|_| ProposalError::RequestTotalInvalid)?;
        let output_total = (request_total + balance.total()).ok_or(ProposalError::Overflow)?;

        if is_shielding
            && (transparent_input_total == NonNegativeAmount::ZERO
                || shielded_input_total > NonNegativeAmount::ZERO
                || request_total > NonNegativeAmount::ZERO)
        {
            return Err(ProposalError::ShieldingInvalid);
        }

        if input_total == output_total {
            Ok(Self {
                transaction_request,
                payment_pools,
                transparent_inputs,
                shielded_inputs,
                balance,
                fee_rule,
                min_target_height,
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
    /// Returns the Sapling inputs that have been selected to fund the transaction.
    pub fn shielded_inputs(&self) -> Option<&ShieldedInputs<NoteRef>> {
        self.shielded_inputs.as_ref()
    }
    /// Returns the change outputs to be added to the transaction and the fee to be paid.
    pub fn balance(&self) -> &TransactionBalance {
        &self.balance
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
    /// Returns a flag indicating whether or not the proposed transaction
    /// is exclusively wallet-internal (if it does not involve any external
    /// recipients).
    pub fn is_shielding(&self) -> bool {
        self.is_shielding
    }
}

impl<FeeRuleT, NoteRef> Debug for Proposal<FeeRuleT, NoteRef> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proposal")
            .field("transaction_request", &self.transaction_request)
            .field("transparent_inputs", &self.transparent_inputs)
            .field(
                "shielded_inputs",
                &self.shielded_inputs().map(|i| i.notes.len()),
            )
            .field(
                "anchor_height",
                &self.shielded_inputs().map(|i| i.anchor_height),
            )
            .field("balance", &self.balance)
            //.field("fee_rule", &self.fee_rule)
            .field("min_target_height", &self.min_target_height)
            .field("is_shielding", &self.is_shielding)
            .finish_non_exhaustive()
    }
}
