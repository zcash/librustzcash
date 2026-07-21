//! Note-split planning: how to break a wallet's spendable source-pool balance into the notes that
//! will cross the turnstile into the destination pool during migration.
//!
//! The plan and the strategy are pool-agnostic (any source pool -> destination pool); the code names
//! no specific pool. Zcash's first use is the Orchard -> Ironwood migration enabled by NU6.3
//! ([ZIP 318]), which the prose below uses as the running example.
//!
//! # The problem
//!
//! When a wallet migrates, every note it spends makes a value cross the turnstile in a transaction a
//! chain observer can see. The rule that picks those crossing amounts is a privacy-critical choice:
//! it decides whether an observer can recognise a specific balance, link all the crossings of one
//! migration together, or single out large holders ("whales").
//!
//! [ZIP 318] settles this by *canonical quantization*: every crossing amount is drawn from the small,
//! shared `{1, 2, 5} * 10^k` denomination set, so many wallets emit identical values that collide and
//! cannot be attributed. Privacy rests on value collision (k-anonymity), explicitly not on
//! unpredictability: a random or high-entropy amount would collide with no other wallet and become a
//! near-unique fingerprint, which is why the ZIP rejects random or arbitrary sizing.
//!
//! The composition rule is abstracted behind the [`DenominationStrategy`] trait, with one
//! implementation (in [`strategies`]):
//!
//! - [`CanonicalOneTwoFive`]: the ZIP 318 canonical quantization, a deterministic descending greedy
//!   decomposition over the `{1, 2, 5} * 10^k` ZEC series (equivalently, decimal-digit expansion into
//!   `{5, 2, 1}` times each place value), e.g. 12,345 ZEC -> 10,000 + 2,000 + 200 + 100 + 20 + 20 + 5.
//!
//! The trait is kept as the seam for a future variant, such as the ZIP's optional
//! frequency-constrained randomized substitution (which only varies which canonical denomination is
//! chosen, never the values themselves).
//!
//! The other tunables are pluggable too: the per-note transfer-fee buffer and the per-transaction
//! preparation fee are computed by the caller from the canonical transaction shapes (using the
//! ZIP-317 fee rule) and passed in, and the maximum denomination, minimum denomination, and note cap
//! are constructor parameters of the strategy.
//!
//! # Common structure
//!
//! Whatever the strategy, the result is a [`NoteSplitPlan`]: a multiset of *denomination notes*,
//! each holding `denomination + fee buffer` so that when it is later spent in a migration transfer
//! it pays its own fee (the buffer is the ZIP-317 fee of the canonical transfer shape). Every note is bounded by a maximum
//! denomination, so even a whale crosses many bounded, collision-prone amounts rather than one
//! distinctive one, and a balance beyond a single run's capacity migrates over several runs.
//! Whatever cannot form a whole self-funding note is left in the source pool as change, never folded
//! into a transaction fee (folding an identifiable dust amount into a fee would deanonymise a
//! dust-attacked wallet).
//!
//! # Relation to known problems
//!
//! Note splitting is fundamentally a *constrained integer partition* problem: writing a known integer
//! as an unordered sum of positive parts. The known integer is `N`, the migratable balance to
//! decompose (in zatoshi, after the note-split transaction fee is reserved), with
//! `0 <= N <= MAX_MONEY`. We choose a multiset of parts `n_1, n_2, ..., n_k` (the crossing values)
//! such that
//!
//! ```text
//! N = (n_1 + n_2 + ... + n_k) + k * f + r
//! ```
//!
//! where `f` is the per-note fee buffer (each prepared note holds `n_i + f`, so it funds its own
//! migration transfer) and `r >= 0` is the residual left in the source pool as change. In the fee-free
//! idealisation (`f = 0`, `r = 0`) this reduces to the plain integer partition `N = n_1 + ... + n_k`.
//!
//! The strategy fixes the remaining parameters: `D`, the denomination set the parts are drawn from (a
//! `{1, 2, 5} * 10^k` series, the powers of ten, ...); `d_min` and `d_max`, the smallest and largest
//! permitted denomination (minimum denomination and cap); `K`, the maximum number of parts (the note cap); and
//! `f`, the per-note fee buffer (from the fee policy). The decision variables are the count `k` and
//! the parts themselves. Each part `n_i` must obey these principles:
//!
//! 1. Canonical: `n_i` is a member of `D`.
//! 2. Bounded magnitude: `d_min <= n_i <= d_max`.
//! 3. Bounded count: `k <= K`.
//! 4. Feasible and self-funding: `(n_1 + f) + ... + (n_k + f) <= N`, so the budget covers every note
//!    plus its own fee and hence `r >= 0`.
//! 5. Drained: if `k < K` then `r < d_min + f` (no further note could be formed); reaching the cap
//!    `k = K` may leave a larger `r`, which migrates on a later run.
//!
//! There is no cost function to minimise: any partition meeting principles 1 to 5 is admissible. The
//! classical partition function counts the partitions of an integer; here the parts are restricted
//! (to the `{1, 2, 5} * 10^k` set) and their number bounded. [`CanonicalOneTwoFive`] returns the
//! single deterministic, non-increasing digit-expansion partition that ZIP 318 prescribes; a future
//! strategy could instead *sample* from a distribution over admissible partitions.
//!
//! The neighbouring problems below are worth knowing, both because a future strategy might implement
//! one and because this crate is meant to be reusable. Each notes the usual solution approach and a
//! reference.
//!
//! - Integer partition, and restricted partitions (parts drawn from a fixed set): counted with
//!   generating functions and computed by dynamic programming.
//!   <https://en.wikipedia.org/wiki/Partition_(number_theory)>
//! - Change-making problem: the *minimum* number of coins from a denomination set summing to a
//!   target. Solved optimally by pseudo-polynomial dynamic programming; greedy is optimal only for
//!   "canonical" coin systems (testable by Pearson's algorithm). A fewest-notes strategy would
//!   minimise this. <https://en.wikipedia.org/wiki/Change-making_problem>
//! - Bounded knapsack and bin packing: fitting parts under a capacity or a bounded count. Bounding
//!   the note count makes the exact decision NP-hard in general (dynamic programming is
//!   pseudo-polynomial); the strategies here sidestep it by not requiring optimality.
//!   <https://en.wikipedia.org/wiki/Knapsack_problem>,
//!   <https://en.wikipedia.org/wiki/Bin_packing_problem>
//! - Subset-sum and the (equal-sum) partition problem: the privacy adversary's problem, namely
//!   whether a subset of the observed crossing amounts sums to a suspected balance. NP-complete, but
//!   weak against canonical, collision-prone amounts (many unrelated subsets hit clean totals).
//!   <https://en.wikipedia.org/wiki/Subset_sum_problem>,
//!   <https://en.wikipedia.org/wiki/Partition_problem>
//! - Random generation of partitions: sampling a partition from a chosen distribution rather than
//!   constructing one greedily. Approaches include the recursive method of Nijenhuis and Wilf
//!   (*Combinatorial Algorithms*) and Boltzmann samplers (Duchon, Flajolet, Louchard and Schaeffer,
//!   2004). A future strategy could sample from a principled distribution over partitions.
//!   <https://en.wikipedia.org/wiki/Boltzmann_sampler>
//! - Denomination design: the `{1, 2, 5} * 10^k` set is the "1-2-5" Renard preferred-number series
//!   used for banknotes and measurement scales; pure powers of ten and the equal outputs of
//!   privacy-coin mixing (CoinJoin) are related choices.
//!   <https://en.wikipedia.org/wiki/Preferred_number>
//!
//! The strategy here is a deterministic greedy expansion; the list above sketches the space a reused
//! version of this crate could grow into.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;

use corez::io::{self, Read, Write};
use rand_core::RngCore;
use zcash_encoding::{Optional, Vector};

use zcash_protocol::value::{BalanceError, COIN, Zatoshis};

pub mod strategies;
mod utils;

pub use strategies::CanonicalOneTwoFive;

/// The default cap on how many notes one migration run prepares. Bounding the note count keeps the
/// decomposition a bounded problem and bounds each run's transaction and proving cost; a larger
/// balance migrates over several runs.
pub const MIGRATION_MAX_PREPARED_NOTES_PER_RUN: usize = 50;

/// The default largest denomination (in whole ZEC) the canonical `{1, 2, 5} * 10^k` strategy gives a
/// single note: `1 * 10^4 = 10_000` ZEC, itself a `{1, 2, 5} * 10^k` value. This is ZIP 318's
/// `DENOM_CAP`. Capping the top denomination keeps even a whale's crossings within the shared
/// denomination set, so no single crossing is a near-unique fingerprint. This is only a default: the
/// actual cap is chosen per run by the caller (the wallet) and passed to the strategy constructor.
pub const MIGRATION_MAX_DENOMINATION_ZEC: u64 = 10_000;

/// The sub-threshold (0.01 ZEC) below which a leftover source-pool balance is never migrated: it is
/// left untouched in the wallet, preserving privacy. Once the main migration completes, a leftover
/// at or above this threshold (but too small to form a whole self-funding note) is surfaced to the
/// user as an opt-in choice: migrate the remainder too (which can compromise privacy, so it is shown
/// with a disclaimer) or lock it to keep that privacy. Consumed by the context module in a later
/// slice. Also the default minimum denomination of [`CanonicalOneTwoFive`] (ZIP 318's `MAX_RESIDUAL_VALUE`).
pub const RESIDUAL_MIGRATION_MIN: Zatoshis = Zatoshis::const_from_u64(COIN / 100); // 0.01 ZEC

/// Source-pool (Orchard) logical actions in a canonical migration transfer: the spend and its
/// change. With [`DESTINATION_ACTIONS_PER_TRANSFER`], this is the canonical transfer shape whose
/// ZIP-317 fee is the per-note transfer-fee buffer.
pub(crate) const SOURCE_ACTIONS_PER_TRANSFER: usize = 2;

/// Destination-pool (Ironwood) logical actions in a canonical migration transfer: the single
/// canonical output, UNPADDED. The Ironwood builder permits a one-action bundle (no padding dummy),
/// which the migration uses to save proving bandwidth on hardware signers; every migration transfer
/// shares this shape, so the action count reveals nothing a canonical transfer does not already
/// reveal.
pub(crate) const DESTINATION_ACTIONS_PER_TRANSFER: usize = 1;

/// The outcome of planning a note split: the self-funding notes to create, the values that will
/// cross the turnstile, and the residual kept in the source pool. Produced by a
/// [`DenominationStrategy`].
///
/// The plan stores the [`crossing_values`](Self::crossing_values) and one constant per-note fee
/// buffer (the ZIP-317 fee of the canonical transfer shape); the prepared-note values are derived, not
/// stored, since every prepared note is exactly its crossing value plus that buffer. Each index `i`
/// describes one prepared note at the two phases of the migration:
/// - `crossing_values[i]` is the denomination that CROSSES the turnstile into the destination pool
///   when the note is spent (the privacy-relevant value an observer sees; their sum is
///   [`total_migratable`](Self::total_migratable)).
/// - [`migration_outputs`](Self::migration_outputs)`[i] == crossing_values[i] + buffer` is the note
///   CREATED in the source pool during the prep phase, so it self-funds its own migration transfer
///   (the buffer pays that transfer's fee, and the crossing value is what remains to cross).
///
/// Value the strategy could not pack into a whole self-funding note is neither of these; it is
/// [`change`](Self::change), left untouched in the source pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSplitPlan {
    crossing_values: Vec<Zatoshis>,
    note_fee_buffer: Zatoshis,
    change: Option<Zatoshis>,
    prep_fees: Zatoshis,
    total_input: Zatoshis,
    total_migratable: Zatoshis,
}

impl NoteSplitPlan {
    /// Assemble a plan from a strategy's computed `crossing_values`, the per-note fee buffer they each
    /// carry (the prepared-note values are `crossing + note_fee_buffer`), and the `remaining_budget`
    /// left after them, which becomes source-pool change. The strategy's arithmetic partitions the
    /// validated total input, so every part converts to a valid [`Zatoshis`] amount.
    pub(crate) fn from_notes(
        total_input_zatoshi: u64,
        prep_fees_zatoshi: u64,
        crossing_values: Vec<u64>,
        note_fee_buffer_zatoshi: u64,
        remaining_budget: u64,
    ) -> Self {
        let total_migratable_zatoshi: u64 = crossing_values.iter().sum();
        Self {
            crossing_values: crossing_values.into_iter().map(zat).collect(),
            note_fee_buffer: zat(note_fee_buffer_zatoshi),
            change: (remaining_budget > 0).then(|| zat(remaining_budget)),
            prep_fees: zat(prep_fees_zatoshi),
            total_input: zat(total_input_zatoshi),
            total_migratable: zat(total_migratable_zatoshi),
        }
    }

    /// Reassemble a plan from its stored fields, exactly as they were persisted. This is the inverse
    /// of the accessors below: a store (for example `zcash_pool_migration_sqlite`) reads the columns
    /// back and reconstructs the plan verbatim, so `total_migratable` is taken as stored
    /// rather than recomputed (the caller is responsible for having persisted a consistent set, which
    /// for a plan produced by `Self::from_notes` means `total_migratable` equals the sum of
    /// `crossing_values`).
    /// Returns [`BalanceError::Overflow`] if any stored crossing value plus the fee buffer would
    /// exceed the maximum money supply (such a pair cannot have come from a valid plan, and the
    /// derived [`migration_outputs`](Self::migration_outputs) would not be representable).
    pub fn from_stored_parts(
        crossing_values: Vec<Zatoshis>,
        note_fee_buffer: Zatoshis,
        change: Option<Zatoshis>,
        prep_fees: Zatoshis,
        total_input: Zatoshis,
        total_migratable: Zatoshis,
    ) -> Result<Self, BalanceError> {
        for &crossing in &crossing_values {
            let _ = (crossing + note_fee_buffer).ok_or(BalanceError::Overflow)?;
        }
        Ok(Self {
            crossing_values,
            note_fee_buffer,
            change,
            prep_fees,
            total_input,
            total_migratable,
        })
    }

    /// The value of each prepared note the split will create: the crossing value at the same index
    /// plus the [fee buffer](Self::note_fee_buffer), so the note can later pay its own
    /// migration-transfer fee. Derived from [`crossing_values`](Self::crossing_values); the plan
    /// stores only the crossings and the constant buffer. The sums are representable by
    /// construction (both constructors establish it).
    pub fn migration_outputs(&self) -> Vec<Zatoshis> {
        self.crossing_values
            .iter()
            .map(|&c| {
                (c + self.note_fee_buffer)
                    .expect("both constructors validate crossing + buffer sums")
            })
            .collect()
    }

    /// The denomination values (in zatoshi) that will cross the turnstile into the destination pool
    /// when the note at the same index is spent. Their exact form (a `{1, 2, 5} * 10^k` ZEC value, a
    /// power of ten, ...) depends on the strategy. Each prepared note (see
    /// [`migration_outputs`](Self::migration_outputs)) is one of these plus the fee buffer.
    pub fn crossing_values(&self) -> &[Zatoshis] {
        &self.crossing_values
    }

    /// The constant fee buffer added to every crossing value to form the prepared note, so each
    /// note self-funds its own migration transfer. The same for every note in the plan.
    pub fn note_fee_buffer(&self) -> Zatoshis {
        self.note_fee_buffer
    }

    /// The source-pool CHANGE: value that stays in the wallet's source-pool balance, untouched by
    /// the migration, because it could not form a whole self-funding note (or the note cap was
    /// reached). It is neither migrated nor spent on fees; `None` when the decomposition consumed
    /// the balance exactly. Includes dust.
    pub fn change(&self) -> Option<Zatoshis> {
        self.change
    }

    /// The total preparation fees this plan reserves: the per-transaction fee times the number of
    /// preparation transactions the decomposition determined it needs. Zero when nothing is
    /// migrated (no preparation happens) or when every funding note is an exact match for a wallet
    /// note (used directly, with no preparation transaction).
    pub fn prep_fees(&self) -> Zatoshis {
        self.prep_fees
    }

    /// The total spendable source-pool balance this plan decomposes.
    pub fn total_input(&self) -> Zatoshis {
        self.total_input
    }

    /// The total value that will migrate to the destination pool: the sum of the crossing values.
    pub fn total_migratable(&self) -> Zatoshis {
        self.total_migratable
    }

    /// Serialize this plan into its canonical binary form, covering every stored field: the
    /// [`crossing_values`](Self::crossing_values) as a [`Vector`] of little-endian `u64` amounts,
    /// then the [`note_fee_buffer`](Self::note_fee_buffer), the optional [`change`](Self::change),
    /// the [`prep_fees`](Self::prep_fees), the [`total_input`](Self::total_input), and the
    /// [`total_migratable`](Self::total_migratable), each as a little-endian `u64`. The inverse of
    /// [`read`](Self::read).
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.crossing_values, |w, v| v.write(w))?;
        self.note_fee_buffer.write(&mut writer)?;
        Optional::write(&mut writer, self.change, |w, v| v.write(w))?;
        self.prep_fees.write(&mut writer)?;
        self.total_input.write(&mut writer)?;
        self.total_migratable.write(&mut writer)
    }

    /// Deserialize a plan written by [`write`](Self::write), reconstructing it through
    /// [`from_stored_parts`](Self::from_stored_parts) (which validates that each crossing value plus
    /// the fee buffer is representable). Maps a [`BalanceError`] from that validation to
    /// [`io::ErrorKind::InvalidData`].
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let crossing_values = Vector::read(&mut reader, |r| Zatoshis::read(r))?;
        let note_fee_buffer = Zatoshis::read(&mut reader)?;
        let change = Optional::read(&mut reader, Zatoshis::read)?;
        let prep_fees = Zatoshis::read(&mut reader)?;
        let total_input = Zatoshis::read(&mut reader)?;
        let total_migratable = Zatoshis::read(&mut reader)?;
        Self::from_stored_parts(
            crossing_values,
            note_fee_buffer,
            change,
            prep_fees,
            total_input,
            total_migratable,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid note split"))
    }
}

/// A rule for decomposing a spendable source-pool balance into the notes a migration run will prepare.
/// See the module docs for the implementation and its denomination set.
pub trait DenominationStrategy {
    /// Decompose `total_input_zatoshi` into self-funding notes, accounting the preparation fees at
    /// each step of the decomposition.
    ///
    /// `prep_tx_fee_zatoshi` is the ZIP-317 fee of one canonical (padded) preparation transaction,
    /// computed by the caller from the canonical shape. `prep_tx_count` is the capability that
    /// answers, for a candidate multiset of prepared-note values (each `crossing + buffer`), how
    /// many preparation transactions minting them will take — `None` when the wallet's notes cannot
    /// mint that multiset at all. The engine backs it with the preparation planner, so the
    /// decomposition reserves the TRUE preparation cost (consolidation, fan-out layers, and all) as
    /// it grows, instead of a fixed guess repaired after the fact. `rng` is used by randomized
    /// strategies and ignored by deterministic ones.
    fn plan<R: RngCore>(
        &self,
        total_input: Zatoshis,
        prep_tx_fee: Zatoshis,
        prep_tx_count: &dyn Fn(&[Zatoshis]) -> Option<usize>,
        rng: &mut R,
    ) -> NoteSplitPlan;
}

/// Convert a strategy-internal value to [`Zatoshis`]. Infallible by construction: the strategies'
/// arithmetic only partitions the total input, which arrives as an already-valid [`Zatoshis`]
/// amount, so every part is bounded by it.
pub(crate) fn zat(value: u64) -> Zatoshis {
    Zatoshis::from_u64(value).expect("split values are bounded by the validated total input")
}

/// Convenience wrapper: plan with the recommended [`CanonicalOneTwoFive`] strategy (ZIP 318 canonical
/// quantization), sized by the caller-computed canonical fees (see [`DenominationStrategy::plan`]).
pub fn plan_note_split<R: RngCore>(
    total_input: Zatoshis,
    transfer_fee_buffer: Zatoshis,
    prep_tx_fee: Zatoshis,
    prep_tx_count: &dyn Fn(&[Zatoshis]) -> Option<usize>,
    rng: &mut R,
) -> NoteSplitPlan {
    CanonicalOneTwoFive::recommended(transfer_fee_buffer).plan(
        total_input,
        prep_tx_fee,
        prep_tx_count,
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    use zcash_encoding::testing::check_roundtrip;

    use crate::testing::arb_note_split_plan;

    proptest! {
        /// `write` and `read` are exact inverses for every [`NoteSplitPlan`].
        #[test]
        fn note_split_plan_round_trips(plan in arb_note_split_plan()) {
            check_roundtrip(&plan, |v, buf| v.write(buf), |b| NoteSplitPlan::read(b));
        }
    }
}
