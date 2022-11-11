use std::fmt;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    transaction::{
        components::{
            amount::{Amount, BalanceError},
            sapling::fees as sapling,
            transparent::fees as transparent,
            OutPoint,
        },
        fees::FeeRule,
    },
};

pub mod fixed;
pub mod zip317;

/// A proposed change amount and output pool.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
pub enum ChangeError<E, NoteRefT> {
    /// Insufficient inputs were provided to change selection to fund the
    /// required outputs and fees.
    InsufficientFunds {
        /// The total of the inputs provided to change selection
        available: Amount,
        /// The total amount of input value required to fund the requested outputs,
        /// including the required fees.
        required: Amount,
    },
    /// Some of the inputs provided to the transaction were determined to currently have no
    /// economic value (i.e. their inclusion in a transaction causes fees to rise in an amount
    /// greater than their value.)
    DustInputs {
        /// The outpoints corresponding to transparent inputs having no current economic value.
        transparent: Vec<OutPoint>,
        /// The identifiers for Sapling inputs having not current economic value
        sapling: Vec<NoteRefT>,
    },
    /// An error occurred that was specific to the change selection strategy in use.
    StrategyError(E),
}

impl<CE: fmt::Display, N: fmt::Display> fmt::Display for ChangeError<CE, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ChangeError::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "Insufficient funds: required {} zatoshis, but only {} zatoshis were available.",
                i64::from(required),
                i64::from(available)
            ),
            ChangeError::DustInputs {
                transparent,
                sapling,
            } => {
                // we can't encode the UA to its string representation because we
                // don't have network parameters here
                write!(f, "Insufficient funds: {} dust inputs were present, but would cost more to spend than they are worth.", transparent.len() + sapling.len())
            }
            ChangeError::StrategyError(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl<NoteRefT> From<BalanceError> for ChangeError<BalanceError, NoteRefT> {
    fn from(err: BalanceError) -> ChangeError<BalanceError, NoteRefT> {
        ChangeError::StrategyError(err)
    }
}

/// An enumeration of actions to tak when a transaction would potentially create dust
/// outputs (outputs that are likely to be without economic value due to fee rules.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DustAction {
    /// Do not allow creation of dust outputs; instead, require that additional inputs be provided.
    Reject,
    /// Explicitly allow the creation of dust change amounts greater than the specified value.
    AllowDustChange,
    /// Allow dust amounts to be added to the transaction fee
    AddDustToFee,
}

/// A policy describing how a [`ChangeStrategy`] should treat potentially dust-valued change
/// outputs (outputs that are likely to be without economic value due to fee rules.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DustOutputPolicy {
    action: DustAction,
    dust_threshold: Option<Amount>,
}

impl DustOutputPolicy {
    /// Constructs a new dust output policy.
    ///
    /// A dust policy created with `None` as the dust threshold will delegate determination
    /// of the dust threshold to the change strategy that is evaluating the strategy; this
    /// recommended, but an explicit value (including zero) may be provided to explicitly
    /// override the determination of the change strategy.
    pub fn new(action: DustAction, dust_threshold: Option<Amount>) -> Self {
        Self {
            action,
            dust_threshold,
        }
    }

    /// Returns the action to take in the event that a dust change amount would be produced
    pub fn action(&self) -> DustAction {
        self.action
    }
    /// Returns a value that will be used to override the dust determination logic of the
    /// change policy, if any.
    pub fn dust_threshold(&self) -> Option<Amount> {
        self.dust_threshold
    }
}

impl Default for DustOutputPolicy {
    fn default() -> Self {
        DustOutputPolicy::new(DustAction::Reject, None)
    }
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
    #[allow(clippy::too_many_arguments)]
    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling_inputs: &[impl sapling::InputView<NoteRefT>],
        sapling_outputs: &[impl sapling::OutputView],
        dust_output_policy: &DustOutputPolicy,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>>;
}

#[cfg(test)]
pub(crate) mod tests {
    use zcash_primitives::transaction::components::{
        amount::Amount,
        sapling::fees as sapling,
        transparent::{fees as transparent, OutPoint, TxOut},
    };

    pub(crate) struct TestTransparentInput {
        pub outpoint: OutPoint,
        pub coin: TxOut,
    }

    impl transparent::InputView for TestTransparentInput {
        fn outpoint(&self) -> &OutPoint {
            &self.outpoint
        }
        fn coin(&self) -> &TxOut {
            &self.coin
        }
    }

    pub(crate) struct TestSaplingInput {
        pub note_id: u32,
        pub value: Amount,
    }

    impl sapling::InputView<u32> for TestSaplingInput {
        fn note_id(&self) -> &u32 {
            &self.note_id
        }
        fn value(&self) -> Amount {
            self.value
        }
    }
}
