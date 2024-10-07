//! Change strategies designed to implement the ZIP 317 fee rules.
//!
//! Change selection in ZIP 317 requires careful handling of low-valued inputs
//! to ensure that inputs added to a transaction do not cause fees to rise by
//! an amount greater than their value.

use std::marker::PhantomData;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::fees::{
        transparent,
        zip317::{FeeError as Zip317FeeError, FeeRule as Zip317FeeRule},
    },
};

use crate::{data_api::InputSource, ShieldedProtocol};

use super::{
    common::{single_change_output_balance, SinglePoolBalanceConfig},
    sapling as sapling_fees, ChangeError, ChangeStrategy, DustOutputPolicy, EphemeralBalance,
    TransactionBalance,
};

#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
pub struct SingleOutputChangeStrategy<I> {
    fee_rule: Zip317FeeRule,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
    dust_output_policy: DustOutputPolicy,
    meta_source: PhantomData<I>,
}

impl<I> SingleOutputChangeStrategy<I> {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified ZIP 317
    /// fee parameters and change memo.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: Zip317FeeRule,
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
    type FeeRule = Zip317FeeRule;
    type Error = Zip317FeeError;
    type MetaSource = I;
    type WalletMeta = ();

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn fetch_wallet_meta(
        &self,
        _meta_source: &Self::MetaSource,
        _account: <Self::MetaSource as InputSource>::AccountId,
        _exclude: &[<Self::MetaSource as InputSource>::NoteRef],
    ) -> Result<Self::WalletMeta, <Self::MetaSource as InputSource>::Error> {
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
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            self.fee_rule.marginal_fee(),
            self.fallback_change_pool,
            self.fee_rule.marginal_fee(),
            self.fee_rule.grace_actions(),
        );

        single_change_output_balance(
            cfg,
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
    use std::convert::Infallible;

    use zcash_primitives::{
        consensus::{Network, NetworkUpgrade, Parameters},
        legacy::Script,
        transaction::{
            components::{amount::NonNegativeAmount, transparent::TxOut},
            fees::zip317::FeeRule as Zip317FeeRule,
        },
    };

    use super::SingleOutputChangeStrategy;
    use crate::{
        data_api::{testing::MockWalletDb, wallet::input_selection::SaplingPayment},
        fees::{
            tests::{TestSaplingInput, TestTransparentInput},
            ChangeError, ChangeStrategy, ChangeValue, DustAction, DustOutputPolicy,
        },
        ShieldedProtocol,
    };

    #[cfg(feature = "orchard")]
    use {
        crate::data_api::wallet::input_selection::OrchardPayment,
        crate::fees::orchard as orchard_fees,
    };

    #[test]
    fn change_without_dust() {
        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
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
                    value: NonNegativeAmount::const_from_u64(55000),
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
                balance.proposed_change() == [ChangeValue::sapling(NonNegativeAmount::const_from_u64(5000), None)] &&
                balance.fee_required() == NonNegativeAmount::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn cross_pool_change_without_dust() {
        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedProtocol::Orchard,
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
                    value: NonNegativeAmount::const_from_u64(55000),
                }][..],
                &[] as &[Infallible],
            ),
            &(
                orchard::builder::BundleType::DEFAULT,
                &[] as &[Infallible],
                &[OrchardPayment::new(NonNegativeAmount::const_from_u64(
                    30000,
                ))][..],
            ),
            None,
            None,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::orchard(NonNegativeAmount::const_from_u64(5000), None)] &&
                balance.fee_required() == NonNegativeAmount::const_from_u64(20000)
        );
    }

    #[test]
    fn change_with_transparent_payments_implicitly_allowing_zero_change() {
        change_with_transparent_payments(DustOutputPolicy::default())
    }

    #[test]
    fn change_with_transparent_payments_explicitly_allowing_zero_change() {
        change_with_transparent_payments(DustOutputPolicy::new(
            DustAction::AllowDustChange,
            Some(NonNegativeAmount::ZERO),
        ))
    }

    fn change_with_transparent_payments(dust_output_policy: DustOutputPolicy) {
        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedProtocol::Sapling,
            dust_output_policy,
        );

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[] as &[TestTransparentInput],
            &[TxOut {
                value: NonNegativeAmount::const_from_u64(40000),
                script_pubkey: Script(vec![]),
            }],
            &(
                sapling::builder::BundleType::DEFAULT,
                &[TestSaplingInput {
                    note_id: 0,
                    value: NonNegativeAmount::const_from_u64(55000),
                }][..],
                &[] as &[Infallible],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(NonNegativeAmount::ZERO, None)]
                && balance.fee_required() == NonNegativeAmount::const_from_u64(15000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_no_change() {
        use crate::fees::sapling as sapling_fees;
        use zcash_primitives::{legacy::TransparentAddress, transaction::components::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedProtocol::Sapling,
            DustOutputPolicy::default(),
        );

        // Spend a single transparent UTXO that is exactly sufficient to pay the fee.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut {
                    value: NonNegativeAmount::const_from_u64(50000),
                    script_pubkey: TransparentAddress::PublicKeyHash([0u8; 20]).script(),
                },
            }],
            &[TxOut {
                value: NonNegativeAmount::const_from_u64(40000),
                script_pubkey: Script(vec![]),
            }],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change().is_empty() &&
                balance.fee_required() == NonNegativeAmount::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_transparent_flows_with_shielded_change() {
        use crate::fees::sapling as sapling_fees;
        use zcash_primitives::{legacy::TransparentAddress, transaction::components::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedProtocol::Sapling,
            DustOutputPolicy::default(),
        );

        // Spend a single transparent UTXO that is sufficient to pay the fee.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut {
                    value: NonNegativeAmount::const_from_u64(63000),
                    script_pubkey: TransparentAddress::PublicKeyHash([0u8; 20]).script(),
                },
            }],
            &[TxOut {
                value: NonNegativeAmount::const_from_u64(40000),
                script_pubkey: Script(vec![]),
            }],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(NonNegativeAmount::const_from_u64(8000), None)] &&
                balance.fee_required() == NonNegativeAmount::const_from_u64(15000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_transparent_flows_with_shielded_dust_change() {
        use crate::fees::sapling as sapling_fees;
        use zcash_primitives::{legacy::TransparentAddress, transaction::components::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedProtocol::Sapling,
            DustOutputPolicy::new(
                DustAction::AllowDustChange,
                Some(NonNegativeAmount::const_from_u64(1000)),
            ),
        );

        // Spend a single transparent UTXO that is sufficient to pay the fee.
        // The change will go to the fallback shielded change pool even though all inputs
        // and payments are transparent, and even though the change amount (1000) would
        // normally be considered dust, because we set the dust policy to allow that.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut {
                    value: NonNegativeAmount::const_from_u64(56000),
                    script_pubkey: TransparentAddress::PublicKeyHash([0u8; 20]).script(),
                },
            }],
            &[TxOut {
                value: NonNegativeAmount::const_from_u64(40000),
                script_pubkey: Script(vec![]),
            }],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(NonNegativeAmount::const_from_u64(1000), None)] &&
                balance.fee_required() == NonNegativeAmount::const_from_u64(15000)
        );
    }

    #[test]
    fn change_with_allowable_dust_implicitly_allowing_zero_change() {
        change_with_allowable_dust(DustOutputPolicy::default())
    }

    #[test]
    fn change_with_allowable_dust_explicitly_allowing_zero_change() {
        change_with_allowable_dust(DustOutputPolicy::new(
            DustAction::AllowDustChange,
            Some(NonNegativeAmount::ZERO),
        ))
    }

    fn change_with_allowable_dust(dust_output_policy: DustOutputPolicy) {
        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedProtocol::Sapling,
            dust_output_policy,
        );

        // Spend two Sapling notes, one of them dust. There is sufficient to
        // pay the fee: if only one note is spent then we are 1000 short, but
        // if both notes are spent then the fee stays at 10000 (even with a
        // zero-valued change output), so we have just enough.
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
                        value: NonNegativeAmount::const_from_u64(49000),
                    },
                    TestSaplingInput {
                        note_id: 1,
                        value: NonNegativeAmount::const_from_u64(1000),
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
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(NonNegativeAmount::ZERO, None)] &&
                balance.fee_required() == NonNegativeAmount::const_from_u64(10000)
        );
    }

    #[test]
    fn change_with_disallowed_dust() {
        let change_strategy = SingleOutputChangeStrategy::<MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedProtocol::Sapling,
            DustOutputPolicy::default(),
        );

        // Attempt to spend three Sapling notes, one of them dust. Adding the third
        // note increases the number of actions, and so it is uneconomic to spend it.
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
                        value: NonNegativeAmount::const_from_u64(29000),
                    },
                    TestSaplingInput {
                        note_id: 1,
                        value: NonNegativeAmount::const_from_u64(20000),
                    },
                    TestSaplingInput {
                        note_id: 2,
                        value: NonNegativeAmount::const_from_u64(1000),
                    },
                ][..],
                &[SaplingPayment::new(NonNegativeAmount::const_from_u64(
                    30000,
                ))][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        // We will get an error here, because the dust input isn't free to add
        // to the transaction.
        assert_matches!(
            result,
            Err(ChangeError::DustInputs { sapling, .. }) if sapling == vec![2]
        );
    }
}
