//! Abstractions and types related to fee calculations.

use crate::transaction::fees::transparent::InputSize;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::Zatoshis,
};

#[cfg(feature = "non-standard-fees")]
pub mod fixed;
pub mod transparent;
pub mod zip317;

#[cfg(zcash_unstable = "zfuture")]
pub mod tze;

/// A trait that represents the ability to compute the fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait FeeRule {
    type Error;

    /// Computes the total fee required for a transaction given the provided inputs and outputs.
    ///
    /// Implementations of this method should compute the fee amount given exactly the inputs and
    /// outputs specified, and should NOT compute speculative fees given any additional change
    /// outputs that may need to be created in order for inputs and outputs to balance.
    ///
    /// The asset_creation_count and total_issue_note_count parameters are only included with the
    /// NU7 network upgrade.
    /// - asset_creation_count: The number of assets created for the first time in the transaction.
    ///   This needs to be obtained from the global issuance state.
    /// - total_issue_note_count: The total number of issue notes across all assets in the transaction.
    #[allow(clippy::too_many_arguments)]
    fn fee_required<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_input_sizes: impl IntoIterator<Item = InputSize>,
        transparent_output_sizes: impl IntoIterator<Item = usize>,
        sapling_input_count: usize,
        sapling_output_count: usize,
        orchard_action_count: usize,
        #[cfg(zcash_unstable = "nu7")] asset_creation_count: usize,
        #[cfg(zcash_unstable = "nu7")] total_issue_note_count: usize,
    ) -> Result<Zatoshis, Self::Error>;
}

/// A trait that represents the ability to compute the fees that must be paid by a transaction
/// having a specified set of inputs and outputs, for use when experimenting with the TZE feature.
#[cfg(zcash_unstable = "zfuture")]
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
        transparent_input_sizes: impl IntoIterator<Item = InputSize>,
        transparent_output_sizes: impl IntoIterator<Item = usize>,
        sapling_input_count: usize,
        sapling_output_count: usize,
        orchard_action_count: usize,
        #[cfg(zcash_unstable = "nu7")] asset_creation_count: usize,
        #[cfg(zcash_unstable = "nu7")] total_issue_note_count: usize,
        tze_inputs: &[impl tze::InputView],
        tze_outputs: &[impl tze::OutputView],
    ) -> Result<Zatoshis, Self::Error>;
}
