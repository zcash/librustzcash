//! Abstractions and types related to fee calculations.

use crate::{
    consensus::{self, BlockHeight},
    transaction::components::{amount::Amount, transparent::fees as transparent},
};

#[cfg(feature = "zfuture")]
use crate::transaction::components::tze::fees as tze;

pub mod fixed;
pub mod zip317;

/// A trait that represents the ability to compute the fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait FeeRule {
    type Error;

    /// Computes the total fee required for a transaction given the provided inputs and outputs.
    ///
    /// Implementations of this method should compute the fee amount given exactly the inputs and
    /// outputs specified, and should NOT compute speculative fees given any additional change
    /// outputs that may need to be created in order for inputs and outputs to balance.
    #[allow(clippy::too_many_arguments)]
    fn fee_required<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling_input_count: usize,
        sapling_output_count: usize,
        orchard_action_count: usize,
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
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling_input_count: usize,
        sapling_output_count: usize,
        tze_inputs: &[impl tze::InputView],
        tze_outputs: &[impl tze::OutputView],
    ) -> Result<Amount, Self::Error>;
}
