// Ported from vizor-wallet `rust/src/wallet/sync/migration.rs`
// (origin/adam/qleak-pr73-orchard-librustzcash), © Chainapsis, Apache-2.0.

//! Note-split planning: deterministic power-of-10 decomposition (ported from vizor's
//! `plan_denominations` via the zodl_ironwood_migration prototype crate). Pure arithmetic, fully unit-tested.
//!
//! Two properties differ from the vizor original:
//!
//! * **Self-funding notes.** Each prepared note holds `power_of_ten + TRANSFER_FEE_BUFFER_ZATOSHI`,
//!   so when it is later spent in a migration transfer it pays its own fee (2 Orchard + 2 Ironwood
//!   actions) while an exact power-of-ten value crosses the turnstile.
//! * **Dust stays in Orchard.** Any residual that cannot form a whole self-funding note is returned
//!   as Orchard change — never folded into the transaction fee (folding an identifiable dust amount
//!   into the fee would deanonymise a dust-attacked wallet).

pub(crate) const ZATOSHIS_PER_ZEC: u64 = 100_000_000;
pub(crate) const MIGRATION_MAX_PREPARED_NOTES_PER_RUN: usize = 64;
/// Per-note fee buffer: 4 × the ZIP-317 marginal fee (5_000), covering 2 Orchard + 2 Ironwood
/// actions, so each prepared note can pay its own migration-transfer fee.
pub(crate) const TRANSFER_FEE_BUFFER_ZATOSHI: u64 = 20_000;
/// Below this, a leftover balance is true dust: moving it would cost more in fees than it is
/// worth, so it is never offered to the user as an optional migration, only ever left in the
/// wallet. At or above it, a leftover is a genuine *residual* — too small to form a whole
/// self-funding note, but large enough to be worth an opt-in "migrate the rest too" transfer (see
/// `MigrationContext::propose_migration_transfers`).
pub(crate) const RESIDUAL_MIGRATION_MIN_ZATOSHI: u64 = 100_000;

/// The outcome of planning a note split.
///
/// `migration_outputs[i]` is a prepared note's value (`crossing_values[i] + TRANSFER_FEE_BUFFER`);
/// `crossing_values[i]` is the power-of-ten value that will cross the turnstile when that note is
/// spent. `orchard_change` is any residual kept in the Orchard pool (including dust).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DenominationPlan {
    pub migration_outputs: Vec<u64>,
    pub crossing_values: Vec<u64>,
    pub orchard_change: Option<u64>,
    pub prep_fee_zatoshi: u64,
    pub total_input_zatoshi: u64,
    pub total_migratable_zatoshi: u64,
}

/// Decompose `total_input_zatoshi` (after reserving `prep_fee_zatoshi`) into self-funding
/// power-of-ten ZEC notes, capped at [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`]. Each note costs
/// `power_of_ten + TRANSFER_FEE_BUFFER_ZATOSHI` from the budget; whatever cannot form a whole note
/// stays in Orchard as change.
pub(crate) fn plan_denominations(
    total_input_zatoshi: u64,
    prep_fee_zatoshi: u64,
) -> Result<DenominationPlan, String> {
    let base = |orchard_change: Option<u64>| DenominationPlan {
        migration_outputs: Vec::new(),
        crossing_values: Vec::new(),
        orchard_change,
        prep_fee_zatoshi,
        total_input_zatoshi,
        total_migratable_zatoshi: 0,
    };

    if total_input_zatoshi <= prep_fee_zatoshi {
        return Ok(base(None));
    }
    let mut budget = total_input_zatoshi - prep_fee_zatoshi;

    let mut migration_outputs = Vec::new();
    let mut crossing_values = Vec::new();
    loop {
        // Smallest self-funding note is 1 ZEC + buffer.
        if budget < ZATOSHIS_PER_ZEC + TRANSFER_FEE_BUFFER_ZATOSHI {
            break;
        }
        // Largest power-of-ten ZEC denomination `d` (in zatoshi) with `d + buffer <= budget`.
        let mut d = ZATOSHIS_PER_ZEC;
        while d
            .checked_mul(10)
            .and_then(|d10| d10.checked_add(TRANSFER_FEE_BUFFER_ZATOSHI))
            .is_some_and(|cost| cost <= budget)
        {
            d *= 10;
        }
        let note = d + TRANSFER_FEE_BUFFER_ZATOSHI;
        migration_outputs.push(note);
        crossing_values.push(d);
        budget -= note;
        if migration_outputs.len() > MIGRATION_MAX_PREPARED_NOTES_PER_RUN {
            return Err(format!(
                "Migration plan would create {} prepared notes, above the {} note limit",
                migration_outputs.len(),
                MIGRATION_MAX_PREPARED_NOTES_PER_RUN
            ));
        }
    }

    let total_migratable_zatoshi = crossing_values.iter().sum();
    Ok(DenominationPlan {
        migration_outputs,
        crossing_values,
        orchard_change: if budget > 0 { Some(budget) } else { None },
        prep_fee_zatoshi,
        total_input_zatoshi,
        total_migratable_zatoshi,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_output_is_power_of_ten_plus_self_funding_buffer() {
        let plan = plan_denominations(1_234_500_000, 0).unwrap();
        assert_eq!(
            plan.crossing_values,
            vec![1_000_000_000, 100_000_000, 100_000_000]
        );
        assert_eq!(
            plan.migration_outputs,
            vec![1_000_020_000, 100_020_000, 100_020_000]
        );
        assert_eq!(plan.total_migratable_zatoshi, 1_200_000_000);
        // 0.345 ZEC residual minus three 20_000 buffers stays in Orchard.
        assert_eq!(plan.orchard_change, Some(34_440_000));
    }

    #[test]
    fn dust_is_left_in_orchard_never_folded_into_fee() {
        let plan = plan_denominations(100_030_000, 0).unwrap();
        assert_eq!(plan.migration_outputs, vec![100_020_000]);
        assert_eq!(plan.crossing_values, vec![100_000_000]);
        assert_eq!(plan.orchard_change, Some(10_000)); // dust kept in Orchard, not fee
    }

    #[test]
    fn exact_funding_leaves_no_change() {
        let plan = plan_denominations(100_020_000, 0).unwrap();
        assert_eq!(plan.migration_outputs, vec![100_020_000]);
        assert_eq!(plan.orchard_change, None);
    }

    #[test]
    fn sub_one_zec_input_migrates_nothing_keeps_all_in_orchard() {
        let plan = plan_denominations(50_000_000, 0).unwrap();
        assert!(plan.migration_outputs.is_empty());
        assert_eq!(plan.orchard_change, Some(50_000_000));
        assert_eq!(plan.total_migratable_zatoshi, 0);
    }

    #[test]
    fn noops_when_prep_fee_consumes_balance() {
        let plan = plan_denominations(5_000, 10_000).unwrap();
        assert!(plan.migration_outputs.is_empty());
        assert_eq!(plan.orchard_change, None);
        assert_eq!(plan.total_migratable_zatoshi, 0);
    }

    #[test]
    fn reserves_prep_fee_before_decomposition() {
        // 1.0001 ZEC, prep fee 10_000: budget 100_000_000 funds exactly one 1-ZEC self-funding
        // note? No — note costs 1 ZEC + 20_000 > budget, so nothing migrates and all stays in Orchard.
        let plan = plan_denominations(100_010_000, 10_000).unwrap();
        assert!(plan.migration_outputs.is_empty());
        assert_eq!(plan.orchard_change, Some(100_000_000));
    }

    #[test]
    fn rejects_more_than_max_prepared_outputs() {
        // 99,999,999.5 ZEC decomposes into 72 power-of-ten notes (digit sum 9*8), exceeding 64.
        let err = plan_denominations(9_999_999_950_000_000, 0).unwrap_err();
        assert!(err.contains("above the 64 note limit"));
    }
}
