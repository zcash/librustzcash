use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::{BalanceError, NonNegativeAmount},
        fees::{transparent, FeeRule},
    },
};

use super::{sapling, ChangeError, ChangeValue, DustAction, DustOutputPolicy, TransactionBalance};

#[allow(clippy::too_many_arguments)]
pub(crate) fn single_change_output_balance<
    P: consensus::Parameters,
    NoteRefT: Clone,
    F: FeeRule,
    E,
>(
    params: &P,
    fee_rule: &F,
    target_height: BlockHeight,
    transparent_inputs: &[impl transparent::InputView],
    transparent_outputs: &[impl transparent::OutputView],
    sapling_inputs: &[impl sapling::InputView<NoteRefT>],
    sapling_outputs: &[impl sapling::OutputView],
    dust_output_policy: &DustOutputPolicy,
    default_dust_threshold: NonNegativeAmount,
    change_memo: Option<MemoBytes>,
) -> Result<TransactionBalance, ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    let overflow = || ChangeError::StrategyError(E::from(BalanceError::Overflow));
    let underflow = || ChangeError::StrategyError(E::from(BalanceError::Underflow));

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

    let fee_amount = fee_rule
        .fee_required(
            params,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling_inputs.len(),
            if sapling_inputs.is_empty() {
                sapling_outputs.len() + 1
            } else {
                std::cmp::max(sapling_outputs.len() + 1, 2)
            },
            //Orchard is not yet supported in zcash_client_backend
            0,
        )
        .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?;

    let total_in = (t_in + sapling_in).ok_or_else(overflow)?;

    let total_out = [t_out, sapling_out, fee_amount]
        .iter()
        .sum::<Option<NonNegativeAmount>>()
        .ok_or_else(overflow)?;

    let proposed_change = (total_in - total_out).ok_or(ChangeError::InsufficientFunds {
        available: total_in,
        required: total_out,
    })?;

    if proposed_change == NonNegativeAmount::ZERO {
        TransactionBalance::new(vec![], fee_amount).map_err(|_| overflow())
    } else {
        let dust_threshold = dust_output_policy
            .dust_threshold()
            .unwrap_or(default_dust_threshold);

        if proposed_change < dust_threshold {
            match dust_output_policy.action() {
                DustAction::Reject => {
                    let shortfall = (dust_threshold - proposed_change).ok_or_else(underflow)?;

                    Err(ChangeError::InsufficientFunds {
                        available: total_in,
                        required: (total_in + shortfall).ok_or_else(overflow)?,
                    })
                }
                DustAction::AllowDustChange => TransactionBalance::new(
                    vec![ChangeValue::sapling(proposed_change, change_memo)],
                    fee_amount,
                )
                .map_err(|_| overflow()),
                DustAction::AddDustToFee => TransactionBalance::new(
                    vec![],
                    (fee_amount + proposed_change).ok_or_else(overflow)?,
                )
                .map_err(|_| overflow()),
            }
        } else {
            TransactionBalance::new(
                vec![ChangeValue::sapling(proposed_change, change_memo)],
                fee_amount,
            )
            .map_err(|_| overflow())
        }
    }
}
