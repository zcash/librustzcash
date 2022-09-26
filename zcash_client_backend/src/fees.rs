use zcash_primitives::{
    consensus::{self, BlockHeight},
    transaction::{
        components::{
            amount::{Amount, BalanceError},
            sapling::builder::{SaplingInput, SaplingOutput},
            transparent::{builder::TransparentInput, TxOut},
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
}

impl TransactionBalance {
    /// Constructs a new balance from its constituent parts.
    pub fn new(proposed_change: Vec<ChangeValue>, fee_required: Amount) -> Self {
        TransactionBalance {
            proposed_change,
            fee_required,
        }
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
}

/// Errors that can occur in balance
pub enum ChangeError<E> {
    InsufficientFunds { available: Amount, required: Amount },
    StrategyError(E),
}

/// A trait that represents the ability to compute the suggested change and fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait ChangeStrategy {
    type FeeRule: FeeRule;
    type Error;

    /// Returns the fee rule that this change strategy will respect when performing
    /// balance computations.
    fn fee_rule(&self) -> Self::FeeRule;

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
        transparent_inputs: &[impl TransparentInput],
        transparent_outputs: &[TxOut],
        sapling_inputs: &[impl SaplingInput],
        sapling_outputs: &[SaplingOutput],
    ) -> Result<TransactionBalance, ChangeError<Self::Error>>;
}

/// A change strategy that uses a fixed fee amount and proposes change as a single output
/// to the most current supported pool.
pub struct BasicFixedFeeChangeStrategy {
    fixed_fee: Amount,
}

impl BasicFixedFeeChangeStrategy {
    // Constructs a new [`BasicFixedFeeChangeStrategy`] with the specified fixed fee
    // amount.
    pub fn new(fixed_fee: Amount) -> Self {
        Self { fixed_fee }
    }
}

impl ChangeStrategy for BasicFixedFeeChangeStrategy {
    type FeeRule = FixedFeeRule;
    type Error = BalanceError;

    fn fee_rule(&self) -> Self::FeeRule {
        FixedFeeRule::new(self.fixed_fee)
    }

    fn compute_balance<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        transparent_inputs: &[impl TransparentInput],
        transparent_outputs: &[TxOut],
        sapling_inputs: &[impl SaplingInput],
        sapling_outputs: &[SaplingOutput],
    ) -> Result<TransactionBalance, ChangeError<Self::Error>> {
        let overflow = || ChangeError::StrategyError(BalanceError::Overflow);
        let underflow = || ChangeError::StrategyError(BalanceError::Underflow);

        let t_in = transparent_inputs
            .iter()
            .map(|t_in| t_in.coin().value)
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;
        let t_out = transparent_outputs
            .iter()
            .map(|t_out| t_out.value)
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;
        let sapling_in = sapling_inputs
            .iter()
            .map(|s_in| s_in.value())
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;
        let sapling_out = sapling_outputs
            .iter()
            .map(|s_out| s_out.value())
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;

        let total_in = (t_in + sapling_in).ok_or_else(overflow)?;
        let total_out = [t_out, sapling_out, self.fixed_fee]
            .iter()
            .sum::<Option<Amount>>()
            .ok_or_else(overflow)?;

        let proposed_change = (total_in - total_out).ok_or_else(underflow)?;
        if proposed_change < Amount::zero() {
            Err(ChangeError::InsufficientFunds {
                available: total_in,
                required: total_out,
            })
        } else {
            Ok(TransactionBalance::new(
                vec![ChangeValue::Sapling(proposed_change)],
                self.fixed_fee,
            ))
        }
    }
}
