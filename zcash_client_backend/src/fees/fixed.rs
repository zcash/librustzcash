//! Change strategies designed for use with a fixed fee.

use std::marker::PhantomData;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::{BalanceError, NonNegativeAmount},
        fees::{fixed::FeeRule as FixedFeeRule, transparent},
    },
};

use crate::{data_api::InputSource, ShieldedProtocol};

use super::{
    common::{single_pool_output_balance, SinglePoolBalanceConfig},
    sapling as sapling_fees, ChangeError, ChangeStrategy, DustOutputPolicy, EphemeralBalance,
    SplitPolicy, TransactionBalance,
};

#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
pub struct SingleOutputChangeStrategy<I> {
    fee_rule: FixedFeeRule,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
    dust_output_policy: DustOutputPolicy,
    meta_source: PhantomData<I>,
}

impl<I> SingleOutputChangeStrategy<I> {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified fee rule
    /// and change memo.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: FixedFeeRule,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
        dust_output_policy: DustOutputPolicy,
    ) -> Self {
        Self {
            fee_rule,
            change_memo,
            fallback_change_pool,
            dust_output_policy,
            meta_source: PhantomData,
        }
    }
}

impl<I: InputSource> ChangeStrategy for SingleOutputChangeStrategy<I> {
    type FeeRule = FixedFeeRule;
    type Error = BalanceError;
    type MetaSource = I;
    type WalletMeta = ();

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn fetch_wallet_meta(
        &self,
        _meta_source: &Self::MetaSource,
        _account: <Self::MetaSource as InputSource>::AccountId,
        _exclude: &[<Self::MetaSource as crate::data_api::InputSource>::NoteRef],
    ) -> Result<Self::WalletMeta, <Self::MetaSource as crate::data_api::InputSource>::Error> {
        Ok(())
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        ephemeral_balance: Option<&EphemeralBalance>,
        _wallet_meta: Option<&Self::WalletMeta>,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let split_policy = SplitPolicy::single_output();
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            self.fee_rule.fixed_fee(),
            &split_policy,
            self.fallback_change_pool,
            NonNegativeAmount::ZERO,
            0,
        );

        single_pool_output_balance(
            cfg,
            None,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            self.change_memo.as_ref(),
            ephemeral_balance,
        )
    }
}

#[cfg(test)]
mod tests {
    use zcash_primitives::{
        consensus::{Network, NetworkUpgrade, Parameters},
        transaction::{
            components::{amount::NonNegativeAmount, transparent::TxOut},
            fees::fixed::FeeRule as FixedFeeRule,
        },
    };

    use super::SingleOutputChangeStrategy;
    use crate::{
        data_api::{testing::MockWalletDb, wallet::input_selection::SaplingPayment},
        fees::{
            tests::{TestSaplingInput, TestTransparentInput},
            ChangeError, ChangeStrategy, ChangeValue, DustOutputPolicy,
        },
        ShieldedProtocol,
    };

    #[cfg(feature = "orchard")]
    use crate::fees::orchard as orchard_fees;

    #[test]
    fn change_without_dust() {
        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::standard();
        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            fee_rule,
            None,
            ShieldedProtocol::Sapling,
            DustOutputPolicy::default(),
        );

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
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
            &orchard_fees::EmptyBundleView,
            None,
            None,
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
        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            fee_rule,
            None,
            ShieldedProtocol::Sapling,
            DustOutputPolicy::default(),
        );

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
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
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        assert_matches!(
            result,
            Err(ChangeError::InsufficientFunds { available, required })
            if available == NonNegativeAmount::const_from_u64(50100) && required == NonNegativeAmount::const_from_u64(60000)
        );
    }
}
