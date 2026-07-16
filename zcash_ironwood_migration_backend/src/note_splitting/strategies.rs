//! The concrete [`DenominationStrategy`] implementations: a randomized
//! `{1, 2, 5} * 10^k` decomposition and the deterministic canonical power-of-ten decomposition. See
//! the [parent module](super) for why both exist and how the choice is deferred to a strategy
//! selection.

use rand_core::RngCore;

use zcash_protocol::value::COIN;

use super::{
    DenominationStrategy, FeePolicy, MIGRATION_MAX_DENOMINATION_ZEC,
    MIGRATION_MAX_PREPARED_NOTES_PER_RUN, NoteSplitPlan, RESIDUAL_MIGRATION_MIN_ZATOSHI,
    ZIP_DENOM_CAP_ZEC, Zip317FeePolicy,
};

/// The base of the denomination scale: every denomination is a multiple of a power of this radix.
const DENOMINATION_RADIX: u64 = 10;

/// The significand multipliers of the `{1, 2, 5} * 10^k` series, ascending.
const ONE_TWO_FIVE_ASCENDING: [u64; 3] = [1, 2, 5];

/// The significand multipliers of the `{1, 2, 5} * 10^k` series, descending (largest first).
const ONE_TWO_FIVE_DESCENDING: [u64; 3] = [5, 2, 1];

/// The smallest denomination [`RandomizedOneTwoFive`] will mint, in whole ZEC.
const MIN_ONE_TWO_FIVE_DENOMINATION_ZEC: u64 = 1;

/// How many random draws [`RandomizedOneTwoFive`] takes per plan, keeping the one that migrates the
/// most. An unlucky single draw can exhaust the note cap while a remainder is left; keeping the best
/// of a few draws makes that vanishingly rare while preserving randomness.
const RANDOMIZED_PLAN_ATTEMPTS: usize = 8;

/// A randomized decomposition whose crossing values follow the `{1, 2, 5} * 10^k` ZEC series. The
/// same balance yields different crossing amounts on different runs, varying both which denominations
/// appear and their order of magnitude, so 723 ZEC is as likely to be split into hundreds and tens as
/// into one large note plus smaller ones. Privacy rests on per-wallet unpredictability while every
/// individual value stays canonical (drawn from the shared 1-2-5 set) and hence collision-prone.
///
/// Each plan keeps the best of a few independent draws (`RANDOMIZED_PLAN_ATTEMPTS`, the one that
/// migrates the most), so an unlucky draw that exhausts the note cap while leaving a remainder is
/// discarded.
pub struct RandomizedOneTwoFive {
    max_notes: usize,
    max_denomination_zec: u64,
    buffer_zatoshi: u64,
}

impl RandomizedOneTwoFive {
    /// A strategy with an explicit note cap, maximum denomination (in whole ZEC), and fee model.
    pub fn new(max_notes: usize, max_denomination_zec: u64, fee: &dyn FeePolicy) -> Self {
        Self {
            max_notes,
            max_denomination_zec,
            buffer_zatoshi: fee.transfer_fee_buffer_zatoshi(),
        }
    }

    /// The recommended configuration: [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`] notes,
    /// [`MIGRATION_MAX_DENOMINATION_ZEC`] cap, ZIP-317 fees.
    pub fn recommended() -> Self {
        Self::new(
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
            MIGRATION_MAX_DENOMINATION_ZEC,
            &Zip317FeePolicy,
        )
    }

    /// The smallest self-funding note: the minimum denomination plus its transfer buffer. A draw
    /// leaving less than this cannot migrate any more value.
    fn min_note_zatoshi(&self) -> u64 {
        MIN_ONE_TWO_FIVE_DENOMINATION_ZEC * COIN + self.buffer_zatoshi
    }

    /// One random decomposition draw. Assumes `total_input_zatoshi > prep_fee_zatoshi`.
    fn draw(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        rng: &mut dyn RngCore,
    ) -> NoteSplitPlan {
        let buffer = self.buffer_zatoshi;
        let min_note = self.min_note_zatoshi();
        let mut budget = total_input_zatoshi - prep_fee_zatoshi;

        let mut migration_outputs = Vec::new();
        let mut crossing_values = Vec::new();
        while budget >= min_note && migration_outputs.len() < self.max_notes {
            let slots_left = (self.max_notes - migration_outputs.len()) as u64; // >= 1
            // Largest whole-ZEC denomination whose note fits the budget, never above the cap.
            let affordable_zec = ((budget - buffer) / COIN).min(self.max_denomination_zec); // >= 1
            // Floor the pick so `slots_left` notes could still drain the budget (using the real,
            // uncapped budget so a whale is pushed toward the cap), but never above the affordable
            // ceiling. As the budget shrinks the floor drops, widening the choice; in the last slot
            // it collapses to the largest affordable denomination.
            let floor_target = ((budget - buffer) / COIN / slots_left)
                .max(MIN_ONE_TWO_FIVE_DENOMINATION_ZEC)
                .min(affordable_zec);
            let floor_zec = largest_denomination_zec(floor_target);
            let candidates = denominations_between(floor_zec, affordable_zec);
            let d_zec = candidates[(rng.next_u64() % candidates.len() as u64) as usize];

            let crossing = d_zec * COIN;
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
        if total_input_zatoshi <= prep_fee_zatoshi {
            return NoteSplitPlan::empty(total_input_zatoshi, prep_fee_zatoshi, None);
        }
        let buffer = self.buffer_zatoshi;
        let min_note = self.dust_floor_zatoshi + buffer; // smallest self-funding note
        let mut budget = total_input_zatoshi - prep_fee_zatoshi;

        let mut migration_outputs = Vec::new();
        let mut crossing_values = Vec::new();
        while budget >= min_note && migration_outputs.len() < self.max_notes {
            // Largest power-of-ten denomination whose note fits the budget, capped at DENOM_CAP.
            let affordable = (budget - buffer).min(self.denom_cap_zatoshi);
            let d = largest_power_of_ten(affordable, self.dust_floor_zatoshi);
            if d < self.dust_floor_zatoshi {
                break;
            }
            let note = d + buffer;
            migration_outputs.push(note);
            crossing_values.push(d);
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

/// The largest `{1, 2, 5} * 10^k` whole-ZEC value not exceeding `n`, for `n >= 1`.
fn largest_denomination_zec(n: u64) -> u64 {
    // Largest power of the radix not exceeding `n`.
    let mut pow = 1u64;
    while pow.checked_mul(DENOMINATION_RADIX).is_some_and(|p| p <= n) {
        pow *= DENOMINATION_RADIX;
    }
    // Prefer the largest significand multiple of that power that still fits.
    for multiple in ONE_TWO_FIVE_DESCENDING {
        if let Some(v) = pow.checked_mul(multiple) {
            if v <= n {
                return v;
            }
        }
    }
    pow
}

/// Every `{1, 2, 5} * 10^k` whole-ZEC denomination `d` with `lo <= d <= hi`, in ascending order.
/// Empty when `hi == 0`.
fn denominations_between(lo: u64, hi: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut pow = 1u64;
    'outer: loop {
        for multiple in ONE_TWO_FIVE_ASCENDING {
            let v = multiple * pow;
            if v > hi {
                break 'outer;
            }
            if v >= lo {
                out.push(v);
            }
        }
        match pow.checked_mul(DENOMINATION_RADIX) {
            Some(p) => pow = p,
            None => break,
        }
    }
    out
}

/// The largest power of the radix `p` (a multiple of the power-of-radix `floor`) with
/// `floor <= p <= hi`, or `0` if `hi < floor`.
fn largest_power_of_ten(hi: u64, floor: u64) -> u64 {
    if hi < floor {
        return 0;
    }
    let mut p = floor;
    while p.checked_mul(DENOMINATION_RADIX).is_some_and(|q| q <= hi) {
        p *= DENOMINATION_RADIX;
    }
    p
}
