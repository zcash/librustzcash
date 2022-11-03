//! Abstractions and types related to fee calculations.

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

    /// Computes the total fee required for a transaction given the provided inputs and outputs.
    ///
    /// Implementations of this method should compute the fee amount given exactly the inputs and
    /// outputs specified, and should NOT compute speculative fees given any additional change
    /// outputs that may need to be created in order for inputs and outputs to balance.
    fn fee_required<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl TransparentInput],
        transparent_outputs: &[TxOut],
        sapling_inputs: &[impl SaplingInput],
        sapling_outputs: &[impl SaplingOutput],
    ) -> Result<Amount, Self::Error>;
}

/// A trait that represents the ability to compute the fees that must be paid by a transaction
/// having a specified set of inputs and outputs, for use when experimenting with the TZE feature.
#[cfg(feature = "zfuture")]
pub trait FutureFeeRule: FeeRule {
    /// Computes the total fee required for a transaction given the provided inputs and outputs.
    ///
    /// Implementations of this method should compute the fee amount given exactly the inputs and
    /// outputs specified, and should NOT compute speculative fees given any additional change
    /// outputs that may need to be created in order for inputs and outputs to balance.
    #[allow(clippy::too_many_arguments)]
    fn fee_required_zfuture<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl TransparentInput],
        transparent_outputs: &[TxOut],
        sapling_inputs: &[impl SaplingInput],
        sapling_outputs: &[impl SaplingOutput],
        tze_inputs: &[impl TzeInput],
        tze_outputs: &[TzeOut],
    ) -> Result<Amount, Self::Error>;
}

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
    type Error = std::convert::Infallible;

    fn fee_required<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_inputs: &[impl TransparentInput],
        _transparent_outputs: &[TxOut],
        _sapling_inputs: &[impl SaplingInput],
        _sapling_outputs: &[impl SaplingOutput],
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
        _sapling_outputs: &[impl SaplingOutput],
        _tze_inputs: &[impl TzeInput],
        _tze_outputs: &[TzeOut],
    ) -> Result<Amount, Self::Error> {
        Ok(self.fixed_fee)
    }
}
