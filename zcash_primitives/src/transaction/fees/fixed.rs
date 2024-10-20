use crate::{
    consensus::{self, BlockHeight},
    transaction::components::amount::NonNegativeAmount,
    transaction::fees::transparent,
};

#[cfg(zcash_unstable = "zfuture")]
use crate::transaction::fees::tze;

/// A fee rule that always returns a fixed fee, irrespective of the structure of
/// the transaction being constructed.
#[derive(Clone, Copy, Debug)]
pub struct FeeRule {
    fixed_fee: NonNegativeAmount,
}

impl FeeRule {
    /// Creates a new nonstandard fixed fee rule with the specified fixed fee.
    #[deprecated(
        note = "Using a fixed fee may result in a transaction that cannot be mined. \
                To calculate the ZIP 317 fee, use `transaction::fees::zip317::FeeRule::standard()`."
    )]
    pub fn non_standard(fixed_fee: NonNegativeAmount) -> Self {
        Self { fixed_fee }
    }

    /// Returns the fixed fee amount which this rule was configured.
    pub fn fixed_fee(&self) -> NonNegativeAmount {
        self.fixed_fee
    }
}

impl super::FeeRule for FeeRule {
    type Error = std::convert::Infallible;

    fn fee_required<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_input_sizes: impl IntoIterator<Item = transparent::InputSize>,
        _transparent_output_sizes: impl IntoIterator<Item = usize>,
        _sapling_input_count: usize,
        _sapling_output_count: usize,
        _orchard_action_count: usize,
    ) -> Result<NonNegativeAmount, Self::Error> {
        Ok(self.fixed_fee)
    }
}

#[cfg(zcash_unstable = "zfuture")]
impl super::FutureFeeRule for FeeRule {
    fn fee_required_zfuture<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_input_sizes: impl IntoIterator<Item = transparent::InputSize>,
        _transparent_output_sizes: impl IntoIterator<Item = usize>,
        _sapling_input_count: usize,
        _sapling_output_count: usize,
        _orchard_action_count: usize,
        _tze_inputs: &[impl tze::InputView],
        _tze_outputs: &[impl tze::OutputView],
    ) -> Result<NonNegativeAmount, Self::Error> {
        Ok(self.fixed_fee)
    }
}
