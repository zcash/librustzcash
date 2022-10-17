use zcash_primitives::{
    consensus::{self, BlockHeight},
    transaction::{
        components::{
            amount::{Amount, BalanceError},
            sapling::fees as sapling,
            transparent::fees as transparent,
        },
        fees::{FeeRule, FixedFeeRule},
    },
};

/// A proposed change amount and output pool.
pub enum ChangeValue {
    Sapling(Amount),
}

impl ChangeValue {
    pub fn value(&self) -> Amount {
        match self {
            ChangeValue::Sapling(value) => *value,
        }
    }
}

/// The amount of change and fees required to make a transaction's inputs and
/// outputs balance under a specific fee rule, as computed by a particular
/// [`ChangeStrategy`] that is aware of that rule.
pub struct TransactionBalance {
    proposed_change: Vec<ChangeValue>,
    fee_required: Amount,
    total: Amount,
}

impl TransactionBalance {
    /// Constructs a new balance from its constituent parts.
    pub fn new(proposed_change: Vec<ChangeValue>, fee_required: Amount) -> Option<Self> {
        proposed_change
            .iter()
            .map(|v| v.value())
            .chain(Some(fee_required))
            .sum::<Option<Amount>>()
            .map(|total| TransactionBalance {
                proposed_change,
                fee_required,
                total,
            })
    }

    /// The change values proposed by the [`ChangeStrategy`] that computed this balance.  
    pub fn proposed_change(&self) -> &[ChangeValue] {
        &self.proposed_change
    }

    /// Returns the fee computed for the transaction, assuming that the suggested
    /// change outputs are added to the transaction.
    pub fn fee_required(&self) -> Amount {
        self.fee_required
    }

    /// Returns the sum of the proposed change outputs and the required fee.
    pub fn total(&self) -> Amount {
        self.total
    }
}

/// Errors that can occur in computing suggested change and/or fees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeError<E> {
    /// Insufficient inputs were provided to change selection to fund the
    /// required outputs and fees.
    InsufficientFunds {
        /// The total of the inputs provided to change selection
        available: Amount,
        /// The total amount of input value required to fund the requested outputs,
        /// including the required fees.
        required: Amount,
    },
    /// An error occurred that was specific to the change selection strategy in use.
    StrategyError(E),
}

/// A trait that represents the ability to compute the suggested change and fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait ChangeStrategy {
    type FeeRule: FeeRule;
    type Error;

    /// Returns the fee rule that this change strategy will respect when performing
    /// balance computations.
    fn fee_rule(&self) -> &Self::FeeRule;

    /// Computes the totals of inputs, suggested change amounts, and fees given the
    /// provided inputs and outputs being used to construct a transaction.
    ///
    /// The fee computed as part of this operation should take into account the prospective
    /// change outputs recommended by this operation. If insufficient funds are available to
    /// supply the requested outputs and required fees, implementations should return
    /// [`ChangeError::InsufficientFunds`].
    fn compute_balance<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling_inputs: &[impl sapling::InputView],
        sapling_outputs: &[impl sapling::OutputView],
    ) -> Result<TransactionBalance, ChangeError<Self::Error>>;
}

/// A change strategy that and proposes change as a single output to the most current supported
/// shielded pool and delegates fee calculation to the provided fee rule.
pub struct SingleOutputFixedFeeChangeStrategy {
    fee_rule: FixedFeeRule,
}

impl SingleOutputFixedFeeChangeStrategy {
    /// Constructs a new [`SingleOutputFixedFeeChangeStrategy`] with the specified fee rule.
    pub fn new(fee_rule: FixedFeeRule) -> Self {
        Self { fee_rule }
    }
}

impl From<BalanceError> for ChangeError<BalanceError> {
    fn from(err: BalanceError) -> ChangeError<BalanceError> {
        ChangeError::StrategyError(err)
    }
}

impl ChangeStrategy for SingleOutputFixedFeeChangeStrategy {
    type FeeRule = FixedFeeRule;
    type Error = BalanceError;

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn compute_balance<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling_inputs: &[impl sapling::InputView],
        sapling_outputs: &[impl sapling::OutputView],
    ) -> Result<TransactionBalance, ChangeError<Self::Error>> {
        let t_in = transparent_inputs
            .iter()
            .map(|t_in| t_in.coin().value)
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;
        let t_out = transparent_outputs
            .iter()
            .map(|t_out| t_out.value())
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;
        let sapling_in = sapling_inputs
            .iter()
            .map(|s_in| s_in.value())
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;
        let sapling_out = sapling_outputs
            .iter()
            .map(|s_out| s_out.value())
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;

        let fee_amount = self
            .fee_rule
            .fee_required(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling_inputs.len(),
                sapling_outputs.len() + 1,
            )
            .unwrap(); // FixedFeeRule::fee_required is infallible.

        let total_in = (t_in + sapling_in).ok_or(BalanceError::Overflow)?;
        let total_out = [t_out, sapling_out, fee_amount]
            .iter()
            .sum::<Option<Amount>>()
            .ok_or(BalanceError::Overflow)?;

        let proposed_change = (total_in - total_out).ok_or(BalanceError::Underflow)?;
        if proposed_change < Amount::zero() {
            Err(ChangeError::InsufficientFunds {
                available: total_in,
                required: total_out,
            })
        } else {
            TransactionBalance::new(vec![ChangeValue::Sapling(proposed_change)], fee_amount)
                .ok_or_else(|| BalanceError::Overflow.into())
        }
    }
}
