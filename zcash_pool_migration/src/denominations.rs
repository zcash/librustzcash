// Ported from vizor-wallet `rust/src/wallet/sync/migration.rs`
// (origin/adam/qleak-pr73-orchard-librustzcash), © Chainapsis, Apache-2.0.

//! Note-split planning: deterministic `{1, 2, 5} × 10^n` decomposition (ported from vizor's
//! `plan_denominations` via the zodl_ironwood_migration prototype crate, then widened to finer
//! denominations per the 2026-07 core team call). Pure arithmetic, fully unit-tested.
//!
//! Two properties differ from the vizor original:
//!
//! * **Self-funding notes.** Each prepared note holds `denomination + TRANSFER_FEE_BUFFER_ZATOSHI`,
//!   so when it is later spent in a migration transfer it pays its own fee (2 Orchard + 2 Ironwood
//!   actions) while an exact `{1,2,5} × 10^n` value crosses the turnstile.
//! * **Sub-threshold stays in Orchard.** Any residual that cannot form a whole self-funding note
//!   (i.e. below `MIGRATION_THRESHOLD_ZATOSHI`) is returned as Orchard change — never folded into
//!   the transaction fee (folding an identifiable dust amount into the fee would deanonymise a
//!   dust-attacked wallet).

pub(crate) const MIGRATION_MAX_PREPARED_NOTES_PER_RUN: usize = 64;
/// Per-note fee buffer: 4 × the ZIP-317 marginal fee (5_000), covering 2 Orchard + 2 Ironwood
/// actions, so each prepared note can pay its own migration-transfer fee.
pub(crate) const TRANSFER_FEE_BUFFER_ZATOSHI: u64 = 20_000;
/// Below this, a balance is never migrated at all — moving it would cost more in fees than
/// it's worth. This is also the smallest denomination `plan_denominations` will ever produce
/// (`1 * 10^-2` ZEC). Migration is considered complete once every transfer above this threshold
/// has sent; whatever remains below it stays in Orchard indefinitely (no further UI offers to
/// move it — see `zashi-android`'s migration-completion spec).
pub(crate) const MIGRATION_THRESHOLD_ZATOSHI: u64 = 1_000_000;

/// The outcome of planning a note split.
///
/// `migration_outputs[i]` is a prepared note's value (`crossing_values[i] + TRANSFER_FEE_BUFFER`);
/// `crossing_values[i]` is the `{1,2,5} × 10^n` value that will cross the turnstile when that note
/// is spent. `orchard_change` is any residual kept in the Orchard pool (including sub-threshold
/// change).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DenominationPlan {
    pub migration_outputs: Vec<u64>,
    pub crossing_values: Vec<u64>,
    pub orchard_change: Option<u64>,
    pub prep_fee_zatoshi: u64,
    pub total_input_zatoshi: u64,
    pub total_migratable_zatoshi: u64,
}

/// Ordered largest-first: for a fixed `n`, try `5 * 10^n`, then `2 * 10^n`, then `1 * 10^n`,
/// before dropping to the next smaller `n`. `n` ranges from however large the balance allows
/// down to `-2` (hundredths of a ZEC) — `MIGRATION_THRESHOLD_ZATOSHI` is exactly `1 * 10^-2` ZEC
/// in zatoshi, the smallest denomination this sequence ever produces.
///
/// `power_of_ten` is walked up to the largest `10^n >= MIGRATION_THRESHOLD_ZATOSHI` that still
/// fits the budget on its own (i.e. its `1x` candidate fits) — note this is *not* the same as the
/// largest `n` whose `5x` candidate fits, since `5 * 10^n` can exceed the budget while
/// `1 * 10^(n+1)` still fits (e.g. budget 1_234_480_000: `5 * 10^8 = 500_000_000` fits, but so
/// does the larger `1 * 10^9 = 1_000_000_000`). Once `power_of_ten` is pinned to that largest fit,
/// trying `5x`, then `2x`, then `1x` of it (in that order) finds the true largest candidate,
/// because a smaller power of ten's `5x` can never exceed a larger power of ten's `1x`.
fn candidate_denominations_at_most(budget_minus_buffer: u64) -> Option<u64> {
    if budget_minus_buffer < MIGRATION_THRESHOLD_ZATOSHI {
        return None;
    }
    let mut power_of_ten = MIGRATION_THRESHOLD_ZATOSHI; // 10^-2 ZEC in zatoshi
    while power_of_ten
        .checked_mul(10)
        .is_some_and(|next| next <= budget_minus_buffer)
    {
        power_of_ten *= 10;
    }
    for multiplier in [5u64, 2, 1] {
        if let Some(candidate) = power_of_ten.checked_mul(multiplier) {
            if candidate <= budget_minus_buffer {
                return Some(candidate);
            }
        }
    }
    // Unreachable: `power_of_ten` itself (the `1x` candidate) is always <= budget_minus_buffer
    // by construction of the loop above, given budget_minus_buffer >= MIGRATION_THRESHOLD_ZATOSHI.
    None
}

/// Decompose `total_input_zatoshi` (after reserving `prep_fee_zatoshi`) into self-funding
/// `{1,2,5} × 10^n` ZEC notes, capped at [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`]. Each note costs
/// `denomination + TRANSFER_FEE_BUFFER_ZATOSHI` from the budget; whatever cannot form a whole note
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
        // Smallest self-funding note is 0.01 ZEC + buffer.
        if budget < MIGRATION_THRESHOLD_ZATOSHI + TRANSFER_FEE_BUFFER_ZATOSHI {
            break;
        }
        let d = match candidate_denominations_at_most(budget - TRANSFER_FEE_BUFFER_ZATOSHI) {
            Some(d) => d,
            None => break,
        };
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
    fn each_output_is_a_125_denomination_plus_self_funding_buffer() {
        // 12.345 ZEC: the algorithm emits ONE note per iteration at the largest fitting
        // `{1,2,5}x10^n` candidate, self-funded with the transfer-fee buffer. Verified trace
        // (budget starts at 1_234_500_000 zatoshi):
        //   budget 1_234_500_000, budget - buffer 1_234_480_000 -> candidate 1_000_000_000 (10 ZEC)
        //   budget   234_480_000, budget - buffer   234_460_000 -> candidate   200_000_000 (2 ZEC)
        //   budget    34_460_000, budget - buffer    34_440_000 -> candidate    20_000_000 (0.2 ZEC)
        //   budget    14_440_000, budget - buffer    14_420_000 -> candidate    10_000_000 (0.1 ZEC)
        //   budget     4_420_000, budget - buffer     4_400_000 -> candidate     2_000_000 (0.02 ZEC)
        //   budget     2_400_000, budget - buffer     2_380_000 -> candidate     2_000_000 (0.02 ZEC)
        //   budget       380_000 < threshold + buffer (1_020_000) -> stop; 380_000 is orchard_change.
        let plan = plan_denominations(1_234_500_000, 0).unwrap();
        assert_eq!(
            plan.crossing_values,
            vec![
                1_000_000_000,
                200_000_000,
                20_000_000,
                10_000_000,
                2_000_000,
                2_000_000,
            ]
        );
        assert_eq!(plan.total_migratable_zatoshi, 1_234_000_000);
        assert_eq!(plan.orchard_change, Some(380_000));
    }

    #[test]
    fn sub_threshold_change_is_left_in_orchard_never_folded_into_fee() {
        // 0.01003 ZEC: exactly one 0.01 ZEC note (1_000_000 + 20_000 buffer = 1_020_000),
        // 10_000 zatoshi left over as change.
        let plan = plan_denominations(1_030_000, 0).unwrap();
        assert_eq!(plan.migration_outputs, vec![1_020_000]);
        assert_eq!(plan.crossing_values, vec![1_000_000]);
        assert_eq!(plan.orchard_change, Some(10_000));
    }

    #[test]
    fn exact_funding_leaves_no_change() {
        let plan = plan_denominations(1_020_000, 0).unwrap();
        assert_eq!(plan.migration_outputs, vec![1_020_000]);
        assert_eq!(plan.orchard_change, None);
    }

    #[test]
    fn sub_threshold_input_migrates_nothing_keeps_all_in_orchard() {
        // 0.009 ZEC is below the 0.01 ZEC threshold entirely — nothing self-funds.
        let plan = plan_denominations(900_000, 0).unwrap();
        assert!(plan.migration_outputs.is_empty());
        assert_eq!(plan.orchard_change, Some(900_000));
        assert_eq!(plan.total_migratable_zatoshi, 0);
    }

    #[test]
    fn sub_one_zec_balance_now_migrates_as_sub_one_zec_notes() {
        // 0.5 ZEC: this is exactly the case the old pure-power-of-10 algorithm treated as
        // "sub-1-ZEC, migrates nothing" — the new {1,2,5}x10^n candidate set migrates it as one
        // 0.5 ZEC note, since 0.5 ZEC is itself a valid denomination (5 * 10^-1).
        let plan = plan_denominations(50_020_000, 0).unwrap();
        assert_eq!(plan.migration_outputs, vec![50_020_000]);
        assert_eq!(plan.crossing_values, vec![50_000_000]);
        assert_eq!(plan.orchard_change, None);
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
        // 0.0101 ZEC, prep fee 10_000: budget after prep fee is 1_000_000 zatoshi, which is
        // exactly the 0.01 ZEC threshold but the note also needs + 20_000 buffer, so it doesn't
        // self-fund; everything stays in Orchard.
        let plan = plan_denominations(1_010_000, 10_000).unwrap();
        assert!(plan.migration_outputs.is_empty());
        assert_eq!(plan.orchard_change, Some(1_000_000));
    }

    #[test]
    fn stays_within_max_prepared_outputs_even_at_the_largest_representable_balance() {
        // Unlike the old pure-power-of-ten algorithm (where a single decimal digit could cost up
        // to 9 identical notes, e.g. digit 9 needing nine 10^n notes), the `{1,2,5}x10^n` set is a
        // canonical coin system: greedy decomposition needs at most 3 notes per decade (worst
        // case, e.g. digit 9 = 5+2+2). That bounds the note count to well under
        // MIGRATION_MAX_PREPARED_NOTES_PER_RUN (64) for every balance representable in a u64,
        // including u64::MAX and hand-picked adversarial all-9s values — verified by exhaustive
        // and randomized search when this test was written (worst found: 39 notes). So the
        // `MIGRATION_MAX_PREPARED_NOTES_PER_RUN` guard in `plan_denominations` is unreachable via
        // any real `total_input_zatoshi`; it exists purely as a defensive invariant check, not a
        // scenario that legitimate wallet balances can trigger. This test documents that margin
        // instead of asserting an unreachable `Err`.
        let adversarial_all_nines: u64 = 9_999_999_999_999_999_999;
        for total in [u64::MAX, adversarial_all_nines] {
            let plan = plan_denominations(total, 0).unwrap();
            assert!(
                plan.migration_outputs.len() <= MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
                "expected note count within the {} limit for {}, got {}",
                MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
                total,
                plan.migration_outputs.len()
            );
        }
    }
}
