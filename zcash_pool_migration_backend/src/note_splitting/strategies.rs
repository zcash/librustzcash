//! The concrete [`DenominationStrategy`] implementation: the canonical `{1, 2, 5} * 10^k`
//! quantization of the Orchard -> Ironwood migration ([ZIP 318]). It decomposes a balance by taking,
//! at each step, the largest `{1, 2, 5} * 10^k` denomination the remaining budget can fund
//! (equivalently, decimal-digit expansion into `{5, 2, 1}` times each place value), working in
//! zatoshi so it mints sub-1-ZEC denominations down to a dust floor. See the [parent module](super)
//! for the value-collision privacy rationale.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;

use rand_core::RngCore;

use zcash_protocol::value::COIN;

use super::utils::largest_one_two_five;
use super::{
    DenominationStrategy, FeePolicy, MIGRATION_MAX_DENOMINATION_ZEC,
    MIGRATION_MAX_PREPARED_NOTES_PER_RUN, NoteSplitPlan, RESIDUAL_MIGRATION_MIN_ZATOSHI,
    Zip317FeePolicy,
};

/// The canonical `{1, 2, 5} * 10^k` quantization of [ZIP 318]: at each step it takes the largest such
/// denomination the remaining budget can fund (bounded by the maximum denomination), so the parts are
/// non-increasing. This is exactly the ZIP's greedy decimal-digit expansion, where each decimal digit
/// expands into `{5, 2, 1}` times its place value. It works in zatoshi, minting sub-1-ZEC
/// denominations down to the dust floor: 0.53 ZEC decomposes into `0.5 + 0.02 + 0.01`, 540 ZEC into
/// `500 + 20 + 20`, 123.45 ZEC into `100 + 20 + 2 + 1 + 0.2 + 0.2 + 0.05`, and 25,000 ZEC into
/// `10,000 + 10,000 + 5,000` (a balance above the cap emits multiple cap-sized parts). The
/// decomposition is a pure function of the balance; the `rng` argument is ignored.
///
/// Every crossing value is a canonical denomination shared across wallets, so privacy rests on value
/// collision rather than on unpredictability (see [ZIP 318]).
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub struct CanonicalOneTwoFive {
    max_notes: usize,
    max_denomination_zatoshi: u64,
    dust_floor_zatoshi: u64,
    buffer_zatoshi: u64,
}

impl CanonicalOneTwoFive {
    /// A strategy with an explicit note cap, maximum denomination (in whole ZEC), dust floor (in
    /// zatoshi, which MUST be a power of ten), and fee model.
    pub fn new(
        max_notes: usize,
        max_denomination_zec: u64,
        dust_floor_zatoshi: u64,
        fee: &impl FeePolicy,
    ) -> Self {
        Self {
            max_notes,
            max_denomination_zatoshi: max_denomination_zec.saturating_mul(COIN),
            dust_floor_zatoshi,
            buffer_zatoshi: fee.transfer_fee_buffer_zatoshi(),
        }
    }

    /// The recommended configuration: [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`] notes,
    /// [`MIGRATION_MAX_DENOMINATION_ZEC`] cap, [`RESIDUAL_MIGRATION_MIN_ZATOSHI`] dust floor, ZIP-317
    /// fees.
    pub fn recommended() -> Self {
        Self::new(
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
            MIGRATION_MAX_DENOMINATION_ZEC,
            RESIDUAL_MIGRATION_MIN_ZATOSHI,
            &Zip317FeePolicy,
        )
    }
}

impl DenominationStrategy for CanonicalOneTwoFive {
    fn plan<R: RngCore>(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        _rng: &mut R,
    ) -> NoteSplitPlan {
        if total_input_zatoshi <= prep_fee_zatoshi {
            return NoteSplitPlan::empty(total_input_zatoshi, prep_fee_zatoshi, None);
        }
        let buffer = self.buffer_zatoshi;
        // Smallest self-funding note: the dust floor plus its transfer buffer.
        let min_note = self.dust_floor_zatoshi + buffer;
        let mut budget = total_input_zatoshi - prep_fee_zatoshi;

        let mut crossing_values = Vec::new();
        while budget >= min_note && crossing_values.len() < self.max_notes {
            // Largest `{1, 2, 5} * 10^k` denomination whose note fits the budget, capped.
            let affordable = (budget - buffer).min(self.max_denomination_zatoshi);
            let crossing = largest_one_two_five(affordable, self.dust_floor_zatoshi);
            if crossing < self.dust_floor_zatoshi {
                break;
            }
            // The prepared note is `crossing + buffer`; only the crossing is stored (the buffer is
            // constant), but the whole note is what the budget must fund.
            budget -= crossing + buffer;
            crossing_values.push(crossing);
        }

        NoteSplitPlan::from_notes(
            total_input_zatoshi,
            prep_fee_zatoshi,
            crossing_values,
            buffer,
            budget,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::MAX_MONEY;

    /// Upper bound on the prep fee sampled by [`arb_plan_input`], in zatoshi.
    const MAX_SAMPLED_PREP_FEE_ZATOSHI: u64 = 1_000_000;
    /// Upper bound on the note cap sampled by [`arb_plan_input`].
    const MAX_SAMPLED_NOTE_CAP: usize = 64;

    /// A plan input: a spendable balance anywhere in `[0, MAX_MONEY]`, a small prep fee, and a note
    /// cap. The balance is drawn from the whole range so arbitrary (not round) zatoshi amounts are
    /// exercised.
    fn arb_plan_input() -> impl Strategy<Value = (u64, u64, usize)> {
        (
            0u64..=MAX_MONEY,
            0u64..MAX_SAMPLED_PREP_FEE_ZATOSHI,
            1usize..=MAX_SAMPLED_NOTE_CAP,
        )
    }

    /// Whether `zat` is a `{1, 2, 5} * 10^k` amount (in zatoshi), including sub-1-ZEC denominations.
    fn is_one_two_five_zat(zat: u64) -> bool {
        if zat == 0 {
            return false;
        }
        let mut n = zat;
        while n.is_multiple_of(10) {
            n /= 10;
        }
        matches!(n, 1 | 2 | 5)
    }

    /// A zero-fee policy, so the canonical digit expansion is exact (no buffer eats into the budget).
    struct NoFeePolicy;
    impl FeePolicy for NoFeePolicy {
        fn marginal_fee_zatoshi(&self) -> u64 {
            0
        }
    }

    /// The canonical strategy with the given note cap and ZIP-317 fees.
    fn canonical(max_notes: usize) -> CanonicalOneTwoFive {
        CanonicalOneTwoFive::new(
            max_notes,
            MIGRATION_MAX_DENOMINATION_ZEC,
            RESIDUAL_MIGRATION_MIN_ZATOSHI,
            &Zip317FeePolicy,
        )
    }

    /// The exact fee-free crossing decomposition of `total`, for the golden vectors.
    fn crossings(total: u64) -> Vec<u64> {
        let s = CanonicalOneTwoFive::new(
            64,
            MIGRATION_MAX_DENOMINATION_ZEC,
            RESIDUAL_MIGRATION_MIN_ZATOSHI,
            &NoFeePolicy,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        s.plan(total, 0, &mut rng).crossing_values().to_vec()
    }

    proptest! {
        /// The trait contract, over the whole input range: value is conserved, each note is its
        /// crossing plus the buffer, the note cap holds, the migratable total is the crossing sum,
        /// every crossing is a valid, non-increasing `{1, 2, 5} * 10^k` denomination within bounds,
        /// the residual is small unless the cap was reached, and the plan ignores the RNG.
        #[test]
        fn honours_the_contract((total, fee, max_notes) in arb_plan_input()) {
            let s = canonical(max_notes);
            let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
            let cap = MIGRATION_MAX_DENOMINATION_ZEC * COIN;
            let floor = RESIDUAL_MIGRATION_MIN_ZATOSHI;
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            let p = s.plan(total, fee, &mut rng);

            let notes: u64 = p.migration_outputs().iter().sum();
            let change = p.change().unwrap_or(0);
            if total <= fee {
                prop_assert!(p.migration_outputs().is_empty());
                prop_assert_eq!(change, 0);
            } else {
                prop_assert_eq!(notes + change, total - fee);
            }

            prop_assert_eq!(p.migration_outputs().len(), p.crossing_values().len());
            for (n, c) in p.migration_outputs().iter().zip(p.crossing_values()) {
                prop_assert_eq!(*n, c + buffer);
            }
            prop_assert!(p.migration_outputs().len() <= max_notes);
            let sum: u64 = p.crossing_values().iter().sum();
            prop_assert_eq!(p.total_migratable_zatoshi(), sum);

            for &cv in p.crossing_values() {
                prop_assert!(is_one_two_five_zat(cv), "invalid denom {}", cv);
                prop_assert!(cv >= floor && cv <= cap, "out of bounds {}", cv);
            }
            for w in p.crossing_values().windows(2) {
                prop_assert!(w[0] >= w[1], "crossings must be non-increasing");
            }
            if p.migration_outputs().len() < max_notes {
                prop_assert!(change < floor + buffer, "residual {}", change);
            }

            // The RNG is ignored: a different seed yields the same plan.
            let mut other = ChaCha8Rng::seed_from_u64(1);
            prop_assert_eq!(&p, &s.plan(total, fee, &mut other));
        }
    }

    /// A whale's balance is split into capped notes, so one run migrates at most `max_notes * cap`
    /// and the rest rolls over as change.
    #[test]
    fn whale_is_capped_and_rolls_over() {
        let s = canonical(MIGRATION_MAX_PREPARED_NOTES_PER_RUN);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let p = s.plan(MAX_MONEY, 0, &mut rng);
        let per_run_cap =
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN as u64 * MIGRATION_MAX_DENOMINATION_ZEC * COIN;
        assert!(p.total_migratable_zatoshi() <= per_run_cap);
        assert!(p.change().unwrap_or(0) > per_run_cap, "should roll over");
    }

    /// A balance below the smallest self-funding note migrates nothing and keeps it all as change.
    #[test]
    fn below_min_note_migrates_nothing() {
        let s = canonical(MIGRATION_MAX_PREPARED_NOTES_PER_RUN);
        let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
        let below = RESIDUAL_MIGRATION_MIN_ZATOSHI + buffer - 1;
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let p = s.plan(below, 0, &mut rng);
        assert!(p.crossing_values().is_empty());
        assert_eq!(p.change(), Some(below));
    }

    /// The ZIP 318 worked examples: canonical `{1, 2, 5} * 10^k` quantization.
    #[test]
    fn matches_the_zip_worked_examples() {
        // 540 -> [500, 20, 20].
        assert_eq!(
            crossings(540 * COIN),
            vec![500 * COIN, 20 * COIN, 20 * COIN]
        );
        // 123.45 -> [100, 20, 2, 1, 0.2, 0.2, 0.05].
        assert_eq!(
            crossings(12_345 * (COIN / 100)),
            vec![
                100 * COIN,
                20 * COIN,
                2 * COIN,
                COIN,
                COIN / 5,
                COIN / 5,
                COIN / 20
            ]
        );
        // 25000 -> [10000, 10000, 5000]: above the cap emits multiple cap-sized parts.
        assert_eq!(
            crossings(25_000 * COIN),
            vec![10_000 * COIN, 10_000 * COIN, 5_000 * COIN]
        );
    }

    /// A larger balance across the full 1-2-5 series, and a sub-1-ZEC balance down to the dust floor.
    #[test]
    fn expands_large_and_sub_one_zec() {
        let zec: Vec<u64> = crossings(12_345 * COIN).iter().map(|&c| c / COIN).collect();
        assert_eq!(zec, vec![10_000, 2_000, 200, 100, 20, 20, 5]);
        // 0.53 -> [0.5, 0.02, 0.01].
        assert_eq!(
            crossings(53 * (COIN / 100)),
            vec![COIN / 2, COIN / 50, COIN / 100]
        );
    }

    /// Each note is capped at the maximum denomination: 45,000 ZEC = four 10,000 (the cap) plus 5,000.
    #[test]
    fn caps_each_note_at_the_maximum_denomination() {
        let zec: Vec<u64> = crossings(45_000 * COIN).iter().map(|&c| c / COIN).collect();
        assert_eq!(zec, vec![10_000, 10_000, 10_000, 10_000, 5_000]);
    }
}
