//! Change strategies designed for use with a fixed fee.

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::BalanceError,
        fees::{fixed::FeeRule as FixedFeeRule, transparent},
    },
};

use crate::ShieldedProtocol;

use super::{
    common::single_change_output_balance, sapling as sapling_fees, ChangeError, ChangeStrategy,
    DustOutputPolicy, TransactionBalance,
};

#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;

/// A change strategy that proposes change as a single output to the most current supported
/// shielded pool and delegates fee calculation to the provided fee rule.
pub struct SingleOutputChangeStrategy {
    fee_rule: FixedFeeRule,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
}

impl SingleOutputChangeStrategy {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified fee rule
    /// and change memo.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: FixedFeeRule,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
    ) -> Self {
        Self {
            fee_rule,
            change_memo,
            fallback_change_pool,
        }
    }
}

impl ChangeStrategy for SingleOutputChangeStrategy {
    type FeeRule = FixedFeeRule;
    type Error = BalanceError;

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        dust_output_policy: &DustOutputPolicy,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        single_change_output_balance(
            params,
            &self.fee_rule,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            dust_output_policy,
            self.fee_rule().fixed_fee(),
            self.change_memo.clone(),
            self.fallback_change_pool,
        )
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "orchard")]
    use std::convert::Infallible;

    use zcash_primitives::{
        consensus::{Network, NetworkUpgrade, Parameters},
        transaction::{
            components::{amount::NonNegativeAmount, transparent::TxOut},
            fees::fixed::FeeRule as FixedFeeRule,
        },
    };

    use super::SingleOutputChangeStrategy;
    use crate::{
        data_api::wallet::input_selection::SaplingPayment,
        fees::{
            tests::{TestSaplingInput, TestTransparentInput},
            ChangeError, ChangeStrategy, ChangeValue, DustOutputPolicy,
        },
        ShieldedProtocol,
    };

    #[test]
    fn change_without_dust() {
        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::standard();
        let change_strategy =
            SingleOutputChangeStrategy::new(fee_rule, None, ShieldedProtocol::Sapling);

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &Vec::<TestTransparentInput>::new(),
            &Vec::<TxOut>::new(),
            &(
                sapling::builder::BundleType::DEFAULT,
                &[TestSaplingInput {
                    note_id: 0,
                    value: NonNegativeAmount::const_from_u64(60000),
                }][..],
                &[SaplingPayment::new(NonNegativeAmount::const_from_u64(
                    40000,
                ))][..],
            ),
            #[cfg(feature = "orchard")]
            &(
                orchard::builder::BundleType::DEFAULT_VANILLA,
                &[] as &[Infallible],
                &[] as &[Infallible],
            ),
            &DustOutputPolicy::default(),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(NonNegativeAmount::const_from_u64(10000), None)] &&
                balance.fee_required() == NonNegativeAmount::const_from_u64(10000)
        );
    }

    #[test]
    fn dust_change() {
        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::standard();
        let change_strategy =
            SingleOutputChangeStrategy::new(fee_rule, None, ShieldedProtocol::Sapling);

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &Vec::<TestTransparentInput>::new(),
            &Vec::<TxOut>::new(),
            &(
                sapling::builder::BundleType::DEFAULT,
                &[
                    TestSaplingInput {
                        note_id: 0,
                        value: NonNegativeAmount::const_from_u64(40000),
                    },
                    // enough to pay a fee, plus dust
                    TestSaplingInput {
                        note_id: 0,
                        value: NonNegativeAmount::const_from_u64(10100),
                    },
                ][..],
                &[SaplingPayment::new(NonNegativeAmount::const_from_u64(
                    40000,
                ))][..],
            ),
            #[cfg(feature = "orchard")]
            &(
                orchard::builder::BundleType::DEFAULT_VANILLA,
                &[] as &[Infallible],
                &[] as &[Infallible],
            ),
            &DustOutputPolicy::default(),
        );

        assert_matches!(
            result,
            Err(ChangeError::InsufficientFunds { available, required })
            if available == NonNegativeAmount::const_from_u64(50100) && required == NonNegativeAmount::const_from_u64(60000)
        );
    }
}
