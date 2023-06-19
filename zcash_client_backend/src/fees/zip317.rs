//! Change strategies designed to implement the ZIP 317 fee rules.
//!
//! Change selection in ZIP 317 requires careful handling of low-valued inputs
//! to ensure that inputs added to a transaction do not cause fees to rise by
//! an amount greater than their value.
use core::cmp::Ordering;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    transaction::{
        components::{
            amount::{Amount, BalanceError},
            sapling::fees as sapling,
            transparent::fees as transparent,
        },
        fees::{
            zip317::{FeeError as Zip317FeeError, FeeRule as Zip317FeeRule},
            FeeRule,
        },
    },
};

use super::{
    ChangeError, ChangeStrategy, ChangeValue, DustAction, DustOutputPolicy, TransactionBalance,
};

/// A change strategy that and proposes change as a single output to the most current supported
/// shielded pool and delegates fee calculation to the provided fee rule.
pub struct SingleOutputChangeStrategy {
    fee_rule: Zip317FeeRule,
}

impl SingleOutputChangeStrategy {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified ZIP 317
    /// fee parameters.
    pub fn new(fee_rule: Zip317FeeRule) -> Self {
        Self { fee_rule }
    }
}

impl ChangeStrategy for SingleOutputChangeStrategy {
    type FeeRule = Zip317FeeRule;
    type Error = Zip317FeeError;

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling_inputs: &[impl sapling::InputView<NoteRefT>],
        sapling_outputs: &[impl sapling::OutputView],
        dust_output_policy: &DustOutputPolicy,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let mut transparent_dust: Vec<_> = transparent_inputs
            .iter()
            .filter_map(|i| {
                // for now, we're just assuming p2pkh inputs, so we don't check the size of the input
                // script
                if i.coin().value < self.fee_rule.marginal_fee() {
                    Some(i.outpoint().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut sapling_dust: Vec<_> = sapling_inputs
            .iter()
            .filter_map(|i| {
                if i.value() < self.fee_rule.marginal_fee() {
                    Some(i.note_id().clone())
                } else {
                    None
                }
            })
            .collect();

        // Depending on the shape of the transaction, we may be able to spend up to
        // `grace_actions - 1` dust inputs. If we don't have any dust inputs though,
        // we don't need to worry about any of that.
        if !(transparent_dust.is_empty() && sapling_dust.is_empty()) {
            let t_non_dust = transparent_inputs.len() - transparent_dust.len();
            let t_allowed_dust = transparent_outputs.len().saturating_sub(t_non_dust);

            // We add one to the sapling outputs for the (single) change output Note that this
            // means that wallet-internal shielding transactions are an opportunity to spend a dust
            // note.
            let s_non_dust = sapling_inputs.len() - sapling_dust.len();
            let s_allowed_dust = (sapling_outputs.len() + 1).saturating_sub(s_non_dust);

            let available_grace_inputs = self
                .fee_rule
                .grace_actions()
                .saturating_sub(t_non_dust)
                .saturating_sub(s_non_dust);

            let mut t_disallowed_dust = transparent_dust.len().saturating_sub(t_allowed_dust);
            let mut s_disallowed_dust = sapling_dust.len().saturating_sub(s_allowed_dust);

            if available_grace_inputs > 0 {
                // If we have available grace inputs, allocate them first to transparent dust
                // and then to Sapling dust. The caller has provided inputs that it is willing
                // to spend, so we don't need to consider privacy effects at this layer.
                let t_grace_dust = available_grace_inputs.saturating_sub(t_disallowed_dust);
                t_disallowed_dust = t_disallowed_dust.saturating_sub(t_grace_dust);

                let s_grace_dust = available_grace_inputs
                    .saturating_sub(t_grace_dust)
                    .saturating_sub(s_disallowed_dust);
                s_disallowed_dust = s_disallowed_dust.saturating_sub(s_grace_dust);
            }

            // Truncate the lists of inputs to be disregarded in input selection to just the
            // disallowed lengths. This has the effect of prioritizing inputs for inclusion by the
            // order of the original input slices, with the most preferred inputs first.
            transparent_dust.reverse();
            transparent_dust.truncate(t_disallowed_dust);
            sapling_dust.reverse();
            sapling_dust.truncate(s_disallowed_dust);

            if !(transparent_dust.is_empty() && sapling_dust.is_empty()) {
                return Err(ChangeError::DustInputs {
                    transparent: transparent_dust,
                    sapling: sapling_dust,
                });
            }
        }

        let overflow = || ChangeError::StrategyError(Zip317FeeError::from(BalanceError::Overflow));
        let underflow =
            || ChangeError::StrategyError(Zip317FeeError::from(BalanceError::Underflow));

        let t_in = transparent_inputs
            .iter()
            .map(|t_in| t_in.coin().value)
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;
        let t_out = transparent_outputs
            .iter()
            .map(|t_out| t_out.value())
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;
        let sapling_in = sapling_inputs
            .iter()
            .map(|s_in| s_in.value())
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;
        let sapling_out = sapling_outputs
            .iter()
            .map(|s_out| s_out.value())
            .sum::<Option<_>>()
            .ok_or_else(overflow)?;

        let fee_amount = self
            .fee_rule
            .fee_required(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling_inputs.len(),
                // add one for Sapling change, then account for Sapling output padding performed by
                // the transaction builder
                std::cmp::max(sapling_outputs.len() + 1, 2),
            )
            .map_err(ChangeError::StrategyError)?;

        let total_in = (t_in + sapling_in).ok_or_else(overflow)?;

        let total_out = [t_out, sapling_out, fee_amount]
            .iter()
            .sum::<Option<Amount>>()
            .ok_or_else(overflow)?;

        let proposed_change = (total_in - total_out).ok_or_else(underflow)?;
        match proposed_change.cmp(&Amount::zero()) {
            Ordering::Less => Err(ChangeError::InsufficientFunds {
                available: total_in,
                required: total_out,
            }),
            Ordering::Equal => TransactionBalance::new(vec![], fee_amount).ok_or_else(overflow),
            Ordering::Greater => {
                let dust_threshold = dust_output_policy
                    .dust_threshold()
                    .unwrap_or_else(|| self.fee_rule.marginal_fee());

                if dust_threshold > proposed_change {
                    match dust_output_policy.action() {
                        DustAction::Reject => {
                            let shortfall =
                                (dust_threshold - proposed_change).ok_or_else(underflow)?;

                            Err(ChangeError::InsufficientFunds {
                                available: total_in,
                                required: (total_in + shortfall).ok_or_else(overflow)?,
                            })
                        }
                        DustAction::AllowDustChange => TransactionBalance::new(
                            vec![ChangeValue::Sapling(proposed_change)],
                            fee_amount,
                        )
                        .ok_or_else(overflow),
                        DustAction::AddDustToFee => {
                            TransactionBalance::new(vec![], (fee_amount + proposed_change).unwrap())
                                .ok_or_else(overflow)
                        }
                    }
                } else {
                    TransactionBalance::new(vec![ChangeValue::Sapling(proposed_change)], fee_amount)
                        .ok_or_else(overflow)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use zcash_primitives::{
        consensus::{Network, NetworkUpgrade, Parameters},
        legacy::Script,
        transaction::{
            components::{amount::Amount, transparent::TxOut},
            fees::zip317::FeeRule as Zip317FeeRule,
        },
    };

    use super::SingleOutputChangeStrategy;
    use crate::{
        data_api::wallet::input_selection::SaplingPayment,
        fees::{
            tests::{TestSaplingInput, TestTransparentInput},
            ChangeError, ChangeStrategy, ChangeValue, DustOutputPolicy,
        },
    };

    #[test]
    fn change_without_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(Zip317FeeRule::standard());

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &Vec::<TestTransparentInput>::new(),
            &Vec::<TxOut>::new(),
            &[TestSaplingInput {
                note_id: 0,
                value: Amount::from_u64(55000).unwrap(),
            }],
            &[SaplingPayment::new(Amount::from_u64(40000).unwrap())],
            &DustOutputPolicy::default(),
        );

        assert_matches!(
            result,
            Ok(balance) if balance.proposed_change() == [ChangeValue::Sapling(Amount::from_u64(5000).unwrap())]
                && balance.fee_required() == Amount::from_u64(10000).unwrap()
        );
    }

    #[test]
    fn change_with_transparent_payments() {
        let change_strategy = SingleOutputChangeStrategy::new(Zip317FeeRule::standard());

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &Vec::<TestTransparentInput>::new(),
            &[TxOut {
                value: Amount::from_u64(40000).unwrap(),
                script_pubkey: Script(vec![]),
            }],
            &[TestSaplingInput {
                note_id: 0,
                value: Amount::from_u64(55000).unwrap(),
            }],
            &Vec::<SaplingPayment>::new(),
            &DustOutputPolicy::default(),
        );

        assert_matches!(
            result,
            Ok(balance) if balance.proposed_change().is_empty()
                && balance.fee_required() == Amount::from_u64(15000).unwrap()
        );
    }

    #[test]
    fn change_with_allowable_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(Zip317FeeRule::standard());

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &Vec::<TestTransparentInput>::new(),
            &Vec::<TxOut>::new(),
            &[
                TestSaplingInput {
                    note_id: 0,
                    value: Amount::from_u64(49000).unwrap(),
                },
                TestSaplingInput {
                    note_id: 1,
                    value: Amount::from_u64(1000).unwrap(),
                },
            ],
            &[SaplingPayment::new(Amount::from_u64(40000).unwrap())],
            &DustOutputPolicy::default(),
        );

        assert_matches!(
            result,
            Ok(balance) if balance.proposed_change().is_empty()
                && balance.fee_required() == Amount::from_u64(10000).unwrap()
        );
    }

    #[test]
    fn change_with_disallowed_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(Zip317FeeRule::standard());

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &Vec::<TestTransparentInput>::new(),
            &Vec::<TxOut>::new(),
            &[
                TestSaplingInput {
                    note_id: 0,
                    value: Amount::from_u64(29000).unwrap(),
                },
                TestSaplingInput {
                    note_id: 1,
                    value: Amount::from_u64(20000).unwrap(),
                },
                TestSaplingInput {
                    note_id: 2,
                    value: Amount::from_u64(1000).unwrap(),
                },
            ],
            &[SaplingPayment::new(Amount::from_u64(40000).unwrap())],
            &DustOutputPolicy::default(),
        );

        // We will get an error here, because the dust input now isn't free to add
        // to the transaction.
        assert_matches!(
            result,
            Err(ChangeError::DustInputs { sapling, .. }) if sapling == vec![2]
        );
    }
}
