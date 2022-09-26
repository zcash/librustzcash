use crate::{
    consensus::{self, BlockHeight},
    transaction::components::{
        amount::Amount,
        sapling::builder::{SaplingInput, SaplingOutput},
        transparent::{builder::TransparentInput, TxOut},
    },
};

#[cfg(feature = "zfuture")]
use crate::transaction::components::tze::{TzeInput, TzeOut};

/// A trait that represents the ability to compute the fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait FeeRule {
    type Error;

    /// Computes the totals of inputs, required change amount, and fees given the
    /// provided inputs and outputs being used to construct a transaction.
    ///
    /// Implementations of this method should compute the fee amount given exactly
    /// the inputs and outputs specified, and should NOT compute speculative fees
    /// given any additional change outputs that may need to be created in order for
    /// inputs and outputs to balance.
    fn fee_required<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl TransparentInput],
        transparent_outputs: &[TxOut],
        sapling_inputs: &[impl SaplingInput],
        sapling_outputs: &[SaplingOutput],
    ) -> Result<Amount, Self::Error>;
}

/// A trait that represents the ability to compute the fees that must be paid
/// by a transaction having a specified set of inputs and outputs, for use
/// when experimenting with the TZE feature.
///
/// Implementations of this method should compute the fee amount given exactly
/// the inputs and outputs specified, and should NOT compute speculative fees
/// given any additional change outputs that may need to be created in order for
/// inputs and outputs to balance.
#[cfg(feature = "zfuture")]
pub trait FutureFeeRule: FeeRule {
    /// Computes the totals of inputs, required change amount, and fees given the
    /// provided inputs and outputs being used to construct a transaction.
    ///
    /// Implementations of this method should compute the fee amount given exactly
    /// the inputs and outputs specified, and should NOT compute speculative fees
    /// given any additional change outputs that may need to be created in order for
    /// inputs and outputs to balance.
    #[allow(clippy::too_many_arguments)]
    fn fee_required_zfuture<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl TransparentInput],
        transparent_outputs: &[TxOut],
        sapling_inputs: &[impl SaplingInput],
        sapling_outputs: &[SaplingOutput],
        tze_inputs: &[impl TzeInput],
        tze_outputs: &[TzeOut],
    ) -> Result<Amount, Self::Error>;
}

/// An uninhabited error type used to indicate when an operation
/// that returns a `Result` cannot fail.
pub enum Infallible {}

/// A fee rule that always returns a fixed fee, irrespective of the structure of
/// the transaction being constructed.
pub struct FixedFeeRule {
    fixed_fee: Amount,
}

impl FixedFeeRule {
    /// Creates a new fixed fee rule with the specified fixed fee.
    pub fn new(fixed_fee: Amount) -> Self {
        Self { fixed_fee }
    }
}

impl FeeRule for FixedFeeRule {
    type Error = Infallible;

    fn fee_required<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_inputs: &[impl TransparentInput],
        _transparent_outputs: &[TxOut],
        _sapling_inputs: &[impl SaplingInput],
        _sapling_outputs: &[SaplingOutput],
    ) -> Result<Amount, Self::Error> {
        Ok(self.fixed_fee)
    }
}

#[cfg(feature = "zfuture")]
impl FutureFeeRule for FixedFeeRule {
    fn fee_required_zfuture<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_inputs: &[impl TransparentInput],
        _transparent_outputs: &[TxOut],
        _sapling_inputs: &[impl SaplingInput],
        _sapling_outputs: &[SaplingOutput],
        _tze_inputs: &[impl TzeInput],
        _tze_outputs: &[TzeOut],
    ) -> Result<Amount, Self::Error> {
        Ok(self.fixed_fee)
    }
}
