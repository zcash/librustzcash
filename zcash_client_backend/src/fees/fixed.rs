//! Change strategies designed for use with a fixed fee.
use std::cmp::Ordering;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    transaction::{
        components::{
            amount::{Amount, BalanceError},
            sapling::fees as sapling,
            transparent::fees as transparent,
        },
        fees::{fixed::FeeRule as FixedFeeRule, FeeRule},
    },
};

use super::{
    ChangeError, ChangeStrategy, ChangeValue, DustAction, DustOutputPolicy, TransactionBalance,
};

/// A change strategy that and proposes change as a single output to the most current supported
/// shielded pool and delegates fee calculation to the provided fee rule.
pub struct SingleOutputChangeStrategy {
    fee_rule: FixedFeeRule,
}

impl SingleOutputChangeStrategy {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified fee rule.
    pub fn new(fee_rule: FixedFeeRule) -> Self {
        Self { fee_rule }
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
        sapling_inputs: &[impl sapling::InputView<NoteRefT>],
        sapling_outputs: &[impl sapling::OutputView],
        dust_output_policy: &DustOutputPolicy,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let t_in = transparent_inputs
            .iter()
            .map(|t_in| t_in.coin().value)
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;
        let t_out = transparent_outputs
            .iter()
            .map(|t_out| t_out.value())
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;
        let sapling_in = sapling_inputs
            .iter()
            .map(|s_in| s_in.value())
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;
        let sapling_out = sapling_outputs
            .iter()
            .map(|s_out| s_out.value())
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)?;

        let fee_amount = self
            .fee_rule
            .fee_required(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling_inputs.len(),
                sapling_outputs.len() + 1,
            )
            .unwrap(); // fixed::FeeRule::fee_required is infallible.

        let total_in = (t_in + sapling_in).ok_or(BalanceError::Overflow)?;

        if (!transparent_inputs.is_empty() || !sapling_inputs.is_empty()) && fee_amount > total_in {
            // For the fixed-fee selection rule, the only time we consider inputs dust is when the fee
            // exceeds the value of all input values.
            Err(ChangeError::DustInputs {
                transparent: transparent_inputs
                    .iter()
                    .map(|i| i.outpoint())
                    .cloned()
                    .collect(),
                sapling: sapling_inputs
                    .iter()
                    .map(|i| i.note_id())
                    .cloned()
                    .collect(),
            })
        } else {
            let total_out = [t_out, sapling_out, fee_amount]
                .iter()
                .sum::<Option<Amount>>()
                .ok_or(BalanceError::Overflow)?;

            let proposed_change = (total_in - total_out).ok_or(BalanceError::Underflow)?;
            match proposed_change.cmp(&Amount::zero()) {
                Ordering::Less => Err(ChangeError::InsufficientFunds {
                    available: total_in,
                    required: total_out,
                }),
                Ordering::Equal => TransactionBalance::new(vec![], fee_amount)
                    .ok_or_else(|| BalanceError::Overflow.into()),
                Ordering::Greater => {
                    let dust_threshold = dust_output_policy
                        .dust_threshold()
                        .unwrap_or_else(|| self.fee_rule.fixed_fee());

                    if dust_threshold > proposed_change {
                        match dust_output_policy.action() {
                            DustAction::Reject => {
                                let shortfall = (dust_threshold - proposed_change)
                                    .ok_or(BalanceError::Underflow)?;
                                Err(ChangeError::InsufficientFunds {
                                    available: total_in,
                                    required: (total_in + shortfall)
                                        .ok_or(BalanceError::Overflow)?,
                                })
                            }
                            DustAction::AllowDustChange => TransactionBalance::new(
                                vec![ChangeValue::Sapling(proposed_change)],
                                fee_amount,
                            )
                            .ok_or_else(|| BalanceError::Overflow.into()),
                            DustAction::AddDustToFee => TransactionBalance::new(
                                vec![],
                                (fee_amount + proposed_change).unwrap(),
                            )
                            .ok_or_else(|| BalanceError::Overflow.into()),
                        }
                    } else {
                        TransactionBalance::new(
                            vec![ChangeValue::Sapling(proposed_change)],
                            fee_amount,
                        )
                        .ok_or_else(|| BalanceError::Overflow.into())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use zcash_primitives::{
        consensus::{Network, NetworkUpgrade, Parameters},
        transaction::{
            components::{amount::Amount, transparent::TxOut},
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
    };

    #[test]
    fn change_without_dust() {
        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::standard();
        let change_strategy = SingleOutputChangeStrategy::new(fee_rule);

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
                value: Amount::from_u64(60000).unwrap(),
            }],
            &[SaplingPayment::new(Amount::from_u64(40000).unwrap())],
            &DustOutputPolicy::default(),
        );

        assert_matches!(
            result,
            Ok(balance) if balance.proposed_change() == [ChangeValue::Sapling(Amount::from_u64(10000).unwrap())]
                && balance.fee_required() == Amount::from_u64(10000).unwrap()
        );
    }

    #[test]
    fn dust_change() {
        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::standard();
        let change_strategy = SingleOutputChangeStrategy::new(fee_rule);

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
                    value: Amount::from_u64(40000).unwrap(),
                },
                // enough to pay a fee, plus dust
                TestSaplingInput {
                    note_id: 0,
                    value: Amount::from_u64(10100).unwrap(),
                },
            ],
            &[SaplingPayment::new(Amount::from_u64(40000).unwrap())],
            &DustOutputPolicy::default(),
        );

        assert_matches!(
            result,
            Err(ChangeError::InsufficientFunds { available, required })
            if available == Amount::from_u64(50100).unwrap() && required == Amount::from_u64(60000).unwrap()
        );
    }
}
