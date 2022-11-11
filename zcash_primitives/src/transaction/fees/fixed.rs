use crate::{
    consensus::{self, BlockHeight},
    transaction::components::{
        amount::{Amount, DEFAULT_FEE},
        transparent::fees as transparent,
    },
};

#[cfg(feature = "zfuture")]
use crate::transaction::components::tze::fees as tze;

/// A fee rule that always returns a fixed fee, irrespective of the structure of
/// the transaction being constructed.
#[derive(Clone, Copy, Debug)]
pub struct FeeRule {
    fixed_fee: Amount,
}

impl FeeRule {
    /// Creates a new nonstandard fixed fee rule with the specified fixed fee.
    pub fn non_standard(fixed_fee: Amount) -> Self {
        Self { fixed_fee }
    }

    /// Creates a new fixed fee rule with the standard default fee.
    pub fn standard() -> Self {
        Self {
            fixed_fee: DEFAULT_FEE,
        }
    }

    /// Returns the fixed fee amount which which this rule was configured.
    pub fn fixed_fee(&self) -> Amount {
        self.fixed_fee
    }
}

impl super::FeeRule for FeeRule {
    type Error = std::convert::Infallible;

    fn fee_required<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_inputs: &[impl transparent::InputView],
        _transparent_outputs: &[impl transparent::OutputView],
        _sapling_input_count: usize,
        _sapling_output_count: usize,
    ) -> Result<Amount, Self::Error> {
        Ok(self.fixed_fee)
    }
}

#[cfg(feature = "zfuture")]
impl super::FutureFeeRule for FeeRule {
    fn fee_required_zfuture<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_inputs: &[impl transparent::InputView],
        _transparent_outputs: &[impl transparent::OutputView],
        _sapling_input_count: usize,
        _sapling_output_count: usize,
        _tze_inputs: &[impl tze::InputView],
        _tze_outputs: &[impl tze::OutputView],
    ) -> Result<Amount, Self::Error> {
        Ok(self.fixed_fee)
    }
}
