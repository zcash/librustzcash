//! The concrete [`DenominationStrategy`] implementations: a randomized and a deterministic
//! `{1, 2, 5} * 10^k` decomposition ([`RandomizedOneTwoFive`], [`CanonicalOneTwoFive`]) and the
//! deterministic canonical power-of-ten decomposition ([`CanonicalPowerOfTen`]). All three work in
//! zatoshi and mint sub-1-ZEC denominations down to a dust floor. See the [parent module](super) for
//! why they coexist and how the choice is deferred to a strategy selection.

use rand_core::RngCore;

use zcash_protocol::value::COIN;

use super::utils::{denominations_between, largest_one_two_five, largest_power_of_ten};
use super::{
    DenominationStrategy, FeePolicy, MIGRATION_MAX_DENOMINATION_ZEC,
    MIGRATION_MAX_PREPARED_NOTES_PER_RUN, NoteSplitPlan, RESIDUAL_MIGRATION_MIN_ZATOSHI,
    ZIP_DENOM_CAP_ZEC, Zip317FeePolicy,
};

/// How many random draws [`RandomizedOneTwoFive`] takes per plan, keeping the one that migrates the
/// most. An unlucky single draw can exhaust the note cap while a remainder is left; keeping the best
/// of a few draws makes that vanishingly rare while preserving randomness.
const RANDOMIZED_PLAN_ATTEMPTS: usize = 8;

/// The shared greedy, descending decomposition behind the deterministic strategies
/// ([`CanonicalOneTwoFive`], [`CanonicalPowerOfTen`]): repeatedly take the largest denomination the
/// remaining budget can fund (bounded by `max_denomination_zatoshi`), stopping at the note cap or
/// when the budget can no longer fund a note down to `dust_floor_zatoshi`. The two strategies differ
/// only in `largest_denomination`, which returns the largest value of their denomination lattice in
/// `[dust_floor_zatoshi, hi]` (or `0` if none fits).
fn greedy_descending_plan(
    total_input_zatoshi: u64,
    prep_fee_zatoshi: u64,
    max_notes: usize,
    max_denomination_zatoshi: u64,
    dust_floor_zatoshi: u64,
    buffer_zatoshi: u64,
    largest_denomination: fn(u64, u64) -> u64,
) -> NoteSplitPlan {
    if total_input_zatoshi <= prep_fee_zatoshi {
        return NoteSplitPlan::empty(total_input_zatoshi, prep_fee_zatoshi, None);
    }
    // Smallest self-funding note: the dust floor plus its transfer buffer.
    let min_note = dust_floor_zatoshi + buffer_zatoshi;
    let mut budget = total_input_zatoshi - prep_fee_zatoshi;

    let mut migration_outputs = Vec::new();
    let mut crossing_values = Vec::new();
    while budget >= min_note && migration_outputs.len() < max_notes {
        // Largest denomination whose note fits the budget, capped.
        let affordable = (budget - buffer_zatoshi).min(max_denomination_zatoshi);
        let crossing = largest_denomination(affordable, dust_floor_zatoshi);
        if crossing < dust_floor_zatoshi {
            break;
        }
        let note = crossing + buffer_zatoshi;
        migration_outputs.push(note);
        crossing_values.push(crossing);
        budget -= note;
    }

    NoteSplitPlan::from_notes(
        total_input_zatoshi,
        prep_fee_zatoshi,
        migration_outputs,
        crossing_values,
        budget,
    )
}

/// A randomized decomposition whose crossing values follow the `{1, 2, 5} * 10^k` series (in
/// zatoshi, so it mints sub-1-ZEC denominations down to a dust floor). The same balance yields
/// different crossing amounts on different runs, varying both which denominations appear and their
/// order of magnitude, so 723 ZEC is as likely to be split into hundreds and tens as into one large
/// note plus smaller ones. Privacy rests on per-wallet unpredictability while every individual value
/// stays canonical (drawn from the shared 1-2-5 set) and hence collision-prone.
///
/// Each plan keeps the best of a few independent draws (`RANDOMIZED_PLAN_ATTEMPTS`, the one that
/// migrates the most), so an unlucky draw that exhausts the note cap while leaving a remainder is
/// discarded.
pub struct RandomizedOneTwoFive {
    max_notes: usize,
    max_denomination_zatoshi: u64,
    dust_floor_zatoshi: u64,
    buffer_zatoshi: u64,
}

impl RandomizedOneTwoFive {
    /// A strategy with an explicit note cap, maximum denomination (in whole ZEC), dust floor (in
    /// zatoshi, which MUST be a power of ten), and fee model.
    pub fn new(
        max_notes: usize,
        max_denomination_zec: u64,
        dust_floor_zatoshi: u64,
        fee: &dyn FeePolicy,
    ) -> Self {
        Self {
            max_notes,
            max_denomination_zatoshi: max_denomination_zec * COIN,
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

    /// The smallest self-funding note: the dust floor plus its transfer buffer. A draw leaving less
    /// than this cannot migrate any more value.
    fn min_note_zatoshi(&self) -> u64 {
        self.dust_floor_zatoshi + self.buffer_zatoshi
    }

    /// One random decomposition draw. Assumes `total_input_zatoshi > prep_fee_zatoshi`.
    fn draw(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        rng: &mut dyn RngCore,
    ) -> NoteSplitPlan {
        let buffer = self.buffer_zatoshi;
        let floor = self.dust_floor_zatoshi;
        let min_note = self.min_note_zatoshi();
        let mut budget = total_input_zatoshi - prep_fee_zatoshi;

        let mut migration_outputs = Vec::new();
        let mut crossing_values = Vec::new();
        while budget >= min_note && migration_outputs.len() < self.max_notes {
            let slots_left = (self.max_notes - migration_outputs.len()) as u64; // >= 1
            // Largest denomination whose note fits the budget, never above the cap. >= the floor,
            // since `budget >= min_note` guarantees `budget - buffer >= floor`.
            let affordable = (budget - buffer).min(self.max_denomination_zatoshi);
            // Floor the pick so `slots_left` notes could still drain the budget (using the real,
            // uncapped budget so a whale is pushed toward the cap), but never above the affordable
            // ceiling. As the budget shrinks the floor drops, widening the choice; in the last slot
            // it collapses to the largest affordable denomination.
            let floor_target = ((budget - buffer) / slots_left).max(floor).min(affordable);
            let floor_denom = largest_one_two_five(floor_target, floor);
            let candidates = denominations_between(floor_denom, affordable);
            let crossing = candidates[(rng.next_u64() % candidates.len() as u64) as usize];

            let note = crossing + buffer;
            migration_outputs.push(note);
            crossing_values.push(crossing);
            budget -= note;
        }

        NoteSplitPlan::from_notes(
            total_input_zatoshi,
            prep_fee_zatoshi,
            migration_outputs,
            crossing_values,
            budget,
        )
    }
}

impl DenominationStrategy for RandomizedOneTwoFive {
    fn plan(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        rng: &mut dyn RngCore,
    ) -> NoteSplitPlan {
        if total_input_zatoshi <= prep_fee_zatoshi {
            return NoteSplitPlan::empty(total_input_zatoshi, prep_fee_zatoshi, None);
        }
        // Keep the best of several random draws. An unlucky draw can exhaust the note cap while a
        // remainder is left, so draw again and keep the one that migrates the most, stopping early
        // once a draw leaves less than one note (nothing more could be migrated from it).
        let min_note = self.min_note_zatoshi();
        let mut best = self.draw(total_input_zatoshi, prep_fee_zatoshi, rng);
        for _ in 1..RANDOMIZED_PLAN_ATTEMPTS {
            if best.change().unwrap_or(0) < min_note {
                break;
            }
            let candidate = self.draw(total_input_zatoshi, prep_fee_zatoshi, rng);
            if candidate.total_migratable_zatoshi() > best.total_migratable_zatoshi() {
                best = candidate;
            }
        }
        best
    }
}

/// A deterministic, descending `{1, 2, 5} * 10^k` decomposition: at each step it takes the largest
/// such denomination the remaining budget can afford (capped), so the parts are non-increasing. It
/// is the deterministic sibling of [`RandomizedOneTwoFive`] (same denomination set, cap, and dust
/// floor) and the 1-2-5 sibling of [`CanonicalPowerOfTen`]. It works in zatoshi, so it mints
/// sub-1-ZEC denominations down to the dust floor (e.g. 0.53 ZEC decomposes into
/// `0.5 + 0.02 + 0.01`), while 12,345 ZEC decomposes into
/// `10,000 + 2,000 + 200 + 100 + 20 + 20 + 5`. The `rng` argument is ignored.
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
        fee: &dyn FeePolicy,
    ) -> Self {
        Self {
            max_notes,
            max_denomination_zatoshi: max_denomination_zec * COIN,
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
    fn plan(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        _rng: &mut dyn RngCore,
    ) -> NoteSplitPlan {
        greedy_descending_plan(
            total_input_zatoshi,
            prep_fee_zatoshi,
            self.max_notes,
            self.max_denomination_zatoshi,
            self.dust_floor_zatoshi,
            self.buffer_zatoshi,
            largest_one_two_five,
        )
    }
}

/// The deterministic decimal-digit expansion into pure powers of ten (`..., 100, 10, 1, 0.1, 0.01,
/// ...` ZEC) of the Ironwood migration ZIP draft. The decomposition is a pure function of the balance
/// (the `rng` argument is ignored). Privacy rests on value collision: many wallets emit identical
/// canonical denominations, so no single crossing is distinctive. Denominations run from a maximum
/// (`DENOM_CAP`) down to a dust floor (`DUST_FLOOR`, below which value is left unmigrated), and
/// balances above the cap emit multiple cap-sized parts.
pub struct CanonicalPowerOfTen {
    max_notes: usize,
    denom_cap_zatoshi: u64,
    dust_floor_zatoshi: u64,
    buffer_zatoshi: u64,
}

impl CanonicalPowerOfTen {
    /// A strategy with an explicit note cap, maximum denomination (in whole ZEC), dust floor (in
    /// zatoshi, which MUST be a power of ten), and fee model.
    pub fn new(
        max_notes: usize,
        denom_cap_zec: u64,
        dust_floor_zatoshi: u64,
        fee: &dyn FeePolicy,
    ) -> Self {
        Self {
            max_notes,
            denom_cap_zatoshi: denom_cap_zec * COIN,
            dust_floor_zatoshi,
            buffer_zatoshi: fee.transfer_fee_buffer_zatoshi(),
        }
    }

    /// The Ironwood migration ZIP draft configuration: [`ZIP_DENOM_CAP_ZEC`] cap,
    /// [`RESIDUAL_MIGRATION_MIN_ZATOSHI`] dust floor, ZIP-317 fees, and a per-run note cap of
    /// [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`].
    pub fn zip_draft() -> Self {
        Self::new(
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
            ZIP_DENOM_CAP_ZEC,
            RESIDUAL_MIGRATION_MIN_ZATOSHI,
            &Zip317FeePolicy,
        )
    }
}

impl DenominationStrategy for CanonicalPowerOfTen {
    fn plan(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        _rng: &mut dyn RngCore,
    ) -> NoteSplitPlan {
        greedy_descending_plan(
            total_input_zatoshi,
            prep_fee_zatoshi,
            self.max_notes,
            self.denom_cap_zatoshi,
            self.dust_floor_zatoshi,
            self.buffer_zatoshi,
            largest_power_of_ten,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::MAX_MONEY;

    /// Upper bound on the prep fee sampled by [`arb_plan_input`], in zatoshi.
    const MAX_SAMPLED_PREP_FEE_ZATOSHI: u64 = 1_000_000;
    /// Upper bound on the note cap sampled by [`arb_plan_input`].
    const MAX_SAMPLED_NOTE_CAP: usize = 64;

    /// A plan input: a spendable balance anywhere in `[0, MAX_MONEY]`, a small prep fee, an RNG seed,
    /// and a note cap. The balance is drawn from the whole range so arbitrary (not round) zatoshi
    /// amounts are exercised.
    fn arb_plan_input() -> impl Strategy<Value = (u64, u64, u64, usize)> {
        (
            0u64..=MAX_MONEY,
            0u64..MAX_SAMPLED_PREP_FEE_ZATOSHI,
            any::<u64>(),
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

    /// Whether `zat` is a power of ten (in zatoshi).
    fn is_power_of_ten_zat(zat: u64) -> bool {
        if zat == 0 {
            return false;
        }
        let mut n = zat;
        while n.is_multiple_of(10) {
            n /= 10;
        }
        n == 1
    }

    /// A strategy plus the facts a generic test needs to know about it: the denomination bounds (in
    /// zatoshi), the note cap, the fee buffer, and a predicate for a valid crossing value.
    struct Case {
        name: &'static str,
        strategy: Box<dyn DenominationStrategy>,
        min_denom_zat: u64,
        max_denom_zat: u64,
        max_notes: usize,
        buffer_zat: u64,
        valid_denom: fn(u64) -> bool,
    }

    /// Every strategy, configured with the given note cap and ZIP-317 fees.
    fn all_cases(max_notes: usize) -> Vec<Case> {
        let fee = Zip317FeePolicy;
        let buffer = fee.transfer_fee_buffer_zatoshi();
        vec![
            Case {
                name: "randomized-1-2-5",
                strategy: Box::new(RandomizedOneTwoFive::new(
                    max_notes,
                    MIGRATION_MAX_DENOMINATION_ZEC,
                    RESIDUAL_MIGRATION_MIN_ZATOSHI,
                    &fee,
                )),
                min_denom_zat: RESIDUAL_MIGRATION_MIN_ZATOSHI,
                max_denom_zat: MIGRATION_MAX_DENOMINATION_ZEC * COIN,
                max_notes,
                buffer_zat: buffer,
                valid_denom: is_one_two_five_zat,
            },
            Case {
                name: "canonical-power-of-ten",
                strategy: Box::new(CanonicalPowerOfTen::new(
                    max_notes,
                    ZIP_DENOM_CAP_ZEC,
                    RESIDUAL_MIGRATION_MIN_ZATOSHI,
                    &fee,
                )),
                min_denom_zat: RESIDUAL_MIGRATION_MIN_ZATOSHI,
                max_denom_zat: ZIP_DENOM_CAP_ZEC * COIN,
                max_notes,
                buffer_zat: buffer,
                valid_denom: is_power_of_ten_zat,
            },
            Case {
                name: "canonical-1-2-5",
                strategy: Box::new(CanonicalOneTwoFive::new(
                    max_notes,
                    MIGRATION_MAX_DENOMINATION_ZEC,
                    RESIDUAL_MIGRATION_MIN_ZATOSHI,
                    &fee,
                )),
                min_denom_zat: RESIDUAL_MIGRATION_MIN_ZATOSHI,
                max_denom_zat: MIGRATION_MAX_DENOMINATION_ZEC * COIN,
                max_notes,
                buffer_zat: buffer,
                valid_denom: is_one_two_five_zat,
            },
        ]
    }

    fn plan_with(case: &Case, total: u64, fee: u64, seed: u64) -> NoteSplitPlan {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        case.strategy.plan(total, fee, &mut rng)
    }

    proptest! {
        /// The trait contract every strategy must honour, over the whole input range: value is
        /// conserved, each note is its crossing plus the buffer, the note cap holds, the migratable
        /// total is the crossing sum, every crossing is a valid denomination within the strategy's
        /// bounds, the residual is small unless the cap was reached, and the plan is reproducible for
        /// a fixed seed.
        #[test]
        fn every_strategy_honours_the_contract(
            (total, fee, seed, max_notes) in arb_plan_input(),
        ) {
            for case in all_cases(max_notes) {
                let p = plan_with(&case, total, fee, seed);

                let notes: u64 = p.migration_outputs().iter().sum();
                let change = p.change().unwrap_or(0);
                if total <= fee {
                    prop_assert!(p.migration_outputs().is_empty(), "{}", case.name);
                    prop_assert_eq!(change, 0, "{}", case.name);
                } else {
                    prop_assert_eq!(notes + change, total - fee, "{}", case.name);
                }

                prop_assert_eq!(
                    p.migration_outputs().len(),
                    p.crossing_values().len(),
                    "{}",
                    case.name
                );
                for (n, c) in p.migration_outputs().iter().zip(p.crossing_values()) {
                    prop_assert_eq!(*n, c + case.buffer_zat, "{}", case.name);
                }

                prop_assert!(p.migration_outputs().len() <= case.max_notes, "{}", case.name);
                let sum: u64 = p.crossing_values().iter().sum();
                prop_assert_eq!(p.total_migratable_zatoshi(), sum, "{}", case.name);

                for &cv in p.crossing_values() {
                    prop_assert!((case.valid_denom)(cv), "{} invalid denom {}", case.name, cv);
                    prop_assert!(cv >= case.min_denom_zat, "{} below min {}", case.name, cv);
                    prop_assert!(cv <= case.max_denom_zat, "{} above cap {}", case.name, cv);
                }

                if p.migration_outputs().len() < case.max_notes {
                    prop_assert!(
                        change < case.min_denom_zat + case.buffer_zat,
                        "{} residual {}",
                        case.name,
                        change
                    );
                }

                // Reproducible: the same seed yields the same plan.
                let again = plan_with(&case, total, fee, seed);
                prop_assert_eq!(p, again, "{}", case.name);
            }
        }

        /// A whale's balance is split into capped notes, so one run migrates at most
        /// `max_notes * cap` and the rest rolls over as change. Holds for every strategy and seed.
        #[test]
        fn every_strategy_caps_and_rolls_over_a_whale(seed in any::<u64>()) {
            for case in all_cases(MIGRATION_MAX_PREPARED_NOTES_PER_RUN) {
                let p = plan_with(&case, MAX_MONEY, 0, seed);
                let per_run_cap = case.max_notes as u64 * case.max_denom_zat;
                prop_assert!(p.total_migratable_zatoshi() <= per_run_cap, "{}", case.name);
                prop_assert!(
                    p.change().unwrap_or(0) > per_run_cap,
                    "{} should roll over",
                    case.name
                );
            }
        }

        /// The canonical strategy is deterministic: the RNG seed does not affect its output.
        #[test]
        fn canonical_ignores_the_seed((total, fee, seed, max_notes) in arb_plan_input()) {
            let s = CanonicalPowerOfTen::new(
                max_notes,
                ZIP_DENOM_CAP_ZEC,
                RESIDUAL_MIGRATION_MIN_ZATOSHI,
                &Zip317FeePolicy,
            );
            let mut a = ChaCha8Rng::seed_from_u64(seed);
            let mut b = ChaCha8Rng::seed_from_u64(seed ^ 0xdead_beef);
            prop_assert_eq!(s.plan(total, fee, &mut a), s.plan(total, fee, &mut b));
        }

        /// The canonical strategy matches an independent reference greedy power-of-ten expansion when
        /// there is no fee buffer to consume budget.
        #[test]
        fn canonical_matches_reference_expansion(
            (total, _fee, _seed, max_notes) in arb_plan_input(),
        ) {
            struct NoFee;
            impl FeePolicy for NoFee {
                fn marginal_fee_zatoshi(&self) -> u64 {
                    0
                }
            }
            let cap = ZIP_DENOM_CAP_ZEC * COIN;
            let floor = RESIDUAL_MIGRATION_MIN_ZATOSHI;
            let s = CanonicalPowerOfTen::new(max_notes, ZIP_DENOM_CAP_ZEC, floor, &NoFee);
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            let got: Vec<u64> = s.plan(total, 0, &mut rng).crossing_values().to_vec();

            let mut want = Vec::new();
            let mut budget = total;
            while budget >= floor && want.len() < max_notes {
                let d = largest_power_of_ten(budget.min(cap), floor);
                want.push(d);
                budget -= d;
            }
            prop_assert_eq!(got, want);
        }
    }

    /// The canonical strategy reproduces the ZIP draft's worked example: 540 ZEC decomposes into five
    /// 100-ZEC parts then four 10-ZEC parts (fee-free planning).
    #[test]
    fn canonical_matches_zip_example() {
        struct NoFee;
        impl FeePolicy for NoFee {
            fn marginal_fee_zatoshi(&self) -> u64 {
                0
            }
        }
        let s = CanonicalPowerOfTen::new(64, ZIP_DENOM_CAP_ZEC, COIN, &NoFee);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let p = s.plan(540 * COIN, 0, &mut rng);
        let zec: Vec<u64> = p.crossing_values().iter().map(|&c| c / COIN).collect();
        assert_eq!(zec, vec![100, 100, 100, 100, 100, 10, 10, 10, 10]);
        assert_eq!(p.change(), None);
    }

    /// The randomized strategy varies across seeds: distinct multisets of crossing values, and
    /// crossings spanning more than one order of magnitude (the scale is randomised, not just the
    /// digits). Inherently a multi-sample property, so it draws many seeds for one balance.
    #[test]
    fn randomized_varies_across_seeds() {
        let s = RandomizedOneTwoFive::recommended();
        let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
        let total = 723 * COIN + 100 * buffer;
        let mut patterns = HashSet::new();
        let mut magnitudes = HashSet::new();
        for seed in 0..64u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let p = s.plan(total, 0, &mut rng);
            let mut sorted = p.crossing_values().to_vec();
            sorted.sort_unstable();
            patterns.insert(sorted);
            for &cv in p.crossing_values() {
                // Magnitude in zatoshi (crossings can be sub-1-ZEC, so `cv / COIN` may be 0).
                magnitudes.insert(cv.ilog10());
            }
        }
        assert!(
            patterns.len() >= 2,
            "decomposition should vary across seeds"
        );
        assert!(magnitudes.len() >= 2, "denomination scale should vary");
    }

    /// A zero-fee policy, so the canonical digit expansion is exact (no buffer eats into the budget).
    struct NoFeePolicy;
    impl FeePolicy for NoFeePolicy {
        fn marginal_fee_zatoshi(&self) -> u64 {
            0
        }
    }

    fn canonical_no_fee() -> CanonicalPowerOfTen {
        CanonicalPowerOfTen::new(
            64,
            ZIP_DENOM_CAP_ZEC,
            RESIDUAL_MIGRATION_MIN_ZATOSHI,
            &NoFeePolicy,
        )
    }

    fn canonical_crossings(total: u64) -> Vec<u64> {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        canonical_no_fee()
            .plan(total, 0, &mut rng)
            .crossing_values()
            .to_vec()
    }

    /// Canonical: whole-ZEC digit expansion, capped at DENOM_CAP. 250 ZEC = two 100s and five 10s.
    #[test]
    fn canonical_expands_250_zec() {
        assert_eq!(
            canonical_crossings(250 * COIN),
            vec![
                100 * COIN,
                100 * COIN,
                10 * COIN,
                10 * COIN,
                10 * COIN,
                10 * COIN,
                10 * COIN
            ]
        );
    }

    /// Canonical crosses sub-1-ZEC denominations down to the dust floor: 0.53 ZEC = five 0.1 + three
    /// 0.01.
    #[test]
    fn canonical_expands_sub_one_zec() {
        let tenth = COIN / 10;
        let hundredth = COIN / 100;
        assert_eq!(
            canonical_crossings(53 * (COIN / 100)),
            vec![
                tenth, tenth, tenth, tenth, tenth, hundredth, hundredth, hundredth
            ]
        );
    }

    /// Canonical reproduces the ZIP draft's full worked example: 123.45 ZEC, including its 0.1 and
    /// 0.01 parts.
    #[test]
    fn canonical_expands_123_point_45_zec() {
        let (one, tenth, hundredth) = (COIN, COIN / 10, COIN / 100);
        let (hundred, ten) = (100 * COIN, 10 * COIN);
        assert_eq!(
            canonical_crossings(12_345 * (COIN / 100)),
            vec![
                hundred, ten, ten, one, one, one, tenth, tenth, tenth, tenth, hundredth, hundredth,
                hundredth, hundredth, hundredth
            ]
        );
    }

    /// Every strategy: a balance below its smallest self-funding note migrates nothing and keeps it
    /// all as change.
    #[test]
    fn every_strategy_below_min_note_migrates_nothing() {
        for case in all_cases(MIGRATION_MAX_PREPARED_NOTES_PER_RUN) {
            let below = case.min_denom_zat + case.buffer_zat - 1; // just under the smallest note
            let p = plan_with(&case, below, 0, 0);
            assert!(p.crossing_values().is_empty(), "{}", case.name);
            assert_eq!(p.change(), Some(below), "{}", case.name);
        }
    }

    /// Canonical: a whale is split into DENOM_CAP-sized parts. 1000 ZEC = ten 100-ZEC parts.
    #[test]
    fn canonical_whale_is_capped_at_denom_cap() {
        assert_eq!(canonical_crossings(1_000 * COIN), vec![100 * COIN; 10]);
    }

    fn canonical_1_2_5_crossings(total: u64) -> Vec<u64> {
        let s = CanonicalOneTwoFive::new(
            64,
            MIGRATION_MAX_DENOMINATION_ZEC,
            RESIDUAL_MIGRATION_MIN_ZATOSHI,
            &NoFeePolicy,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        s.plan(total, 0, &mut rng).crossing_values().to_vec()
    }

    /// Deterministic descending 1-2-5: 12,345 ZEC = 10,000 + 2,000 + 200 + 100 + 20 + 20 + 5 (each
    /// decimal digit expressed in the 1-2-5 series, largest denomination first).
    #[test]
    fn canonical_1_2_5_expands_12345_zec() {
        let zec: Vec<u64> = canonical_1_2_5_crossings(12_345 * COIN)
            .iter()
            .map(|&c| c / COIN)
            .collect();
        assert_eq!(zec, vec![10_000, 2_000, 200, 100, 20, 20, 5]);
    }

    /// Deterministic descending 1-2-5 caps each note and is independent of the RNG seed. 45,000 ZEC
    /// = four 10,000 (the cap) plus 5,000.
    #[test]
    fn canonical_1_2_5_is_descending_capped_and_deterministic() {
        let zec: Vec<u64> = canonical_1_2_5_crossings(45_000 * COIN)
            .iter()
            .map(|&c| c / COIN)
            .collect();
        assert_eq!(zec, vec![10_000, 10_000, 10_000, 10_000, 5_000]);

        let s = CanonicalOneTwoFive::recommended();
        let mut ra = ChaCha8Rng::seed_from_u64(1);
        let mut rb = ChaCha8Rng::seed_from_u64(2);
        let a = s.plan(12_345 * COIN, 0, &mut ra);
        assert_eq!(a, s.plan(12_345 * COIN, 0, &mut rb));
        for w in a.crossing_values().windows(2) {
            assert!(w[0] >= w[1], "crossings should be non-increasing");
        }
    }

    /// The randomized strategy at a FIXED seed (42) is deterministic; pin its exact decomposition as
    /// a regression and check the invariants concretely.
    #[test]
    fn randomized_seed_42_is_a_stable_golden() {
        let s = RandomizedOneTwoFive::recommended();
        let total = 1_000 * COIN;
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let p = s.plan(total, 0, &mut rng);
        // Crossings in centi-ZEC (hundredths), so any sub-1-ZEC part is captured exactly.
        let centi: Vec<u64> = p
            .crossing_values()
            .iter()
            .map(|&c| c / (COIN / 100))
            .collect();
        // GOLDEN: the exact decomposition of 1000 ZEC at seed 42, in centi-ZEC. It drains down to the
        // 0.01-ZEC (`1` centi) dust floor, so the strategy mints sub-1-ZEC crossings too.
        assert_eq!(
            centi,
            vec![
                10000, 20000, 20000, 2000, 20000, 2000, 2000, 500, 10000, 5000, 200, 2000, 1000,
                5000, 100, 5, 20, 50, 5, 100, 10, 1, 5, 1, 1, 1
            ]
        );
        for &cv in p.crossing_values() {
            assert!(is_one_two_five_zat(cv));
            assert!(cv <= MIGRATION_MAX_DENOMINATION_ZEC * COIN);
        }
        let notes: u64 = p.migration_outputs().iter().sum();
        assert_eq!(notes + p.change().unwrap_or(0), total);
    }

    /// The randomized strategy at seed 42 conserves value and respects the cap across several
    /// (including non-round) balances.
    #[test]
    fn randomized_seed_42_conserves_and_caps() {
        let s = RandomizedOneTwoFive::recommended();
        for &total in &[71 * COIN, 12_345 * COIN, 21_439_281 * (COIN / 100)] {
            let mut rng = ChaCha8Rng::seed_from_u64(42);
            let p = s.plan(total, 0, &mut rng);
            let notes: u64 = p.migration_outputs().iter().sum();
            assert_eq!(notes + p.change().unwrap_or(0), total, "total {total}");
            assert!(p.migration_outputs().len() <= MIGRATION_MAX_PREPARED_NOTES_PER_RUN);
            for &cv in p.crossing_values() {
                assert!(is_one_two_five_zat(cv), "not 1-2-5: {cv}");
                assert!(cv <= MIGRATION_MAX_DENOMINATION_ZEC * COIN);
            }
        }
    }
}
