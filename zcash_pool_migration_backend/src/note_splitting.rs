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
//! The other tunables are pluggable too: the per-note fee comes from a [`FeePolicy`], and the
//! maximum denomination, minimum denomination, and note cap are constructor parameters of the strategy.
//!
//! # Common structure
//!
//! Whatever the strategy, the result is a [`NoteSplitPlan`]: a multiset of *denomination notes*,
//! each holding `denomination + fee buffer` so that when it is later spent in a migration transfer
//! it pays its own fee (the [`FeePolicy`] sizes the buffer). Every note is bounded by a maximum
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

use rand_core::RngCore;

use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
use zcash_protocol::value::COIN;

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
pub const RESIDUAL_MIGRATION_MIN_ZATOSHI: u64 = COIN / 100; // 0.01 ZEC

/// Source-pool logical actions in a migration transfer (the spend and its change), each charged the
/// marginal fee.
const SOURCE_ACTIONS_PER_TRANSFER: u64 = 2;

/// Destination-pool logical actions in a migration transfer (the output and a dummy), each charged the
/// marginal fee.
const DESTINATION_ACTIONS_PER_TRANSFER: u64 = 2;

/// How each prepared note is sized to fund the migration transfer that later spends it. Abstracted
/// so the fee model can be swapped independently of the composition strategy.
pub trait FeePolicy {
    /// The per-logical-action fee (in zatoshi).
    fn marginal_fee_zatoshi(&self) -> u64;

    /// The fee buffer (in zatoshi) added to each prepared note so it self-funds its migration
    /// transfer. The default charges the source-pool plus destination-pool actions of a transfer at the
    /// marginal fee (see `SOURCE_ACTIONS_PER_TRANSFER` and `DESTINATION_ACTIONS_PER_TRANSFER`).
    fn transfer_fee_buffer_zatoshi(&self) -> u64 {
        (SOURCE_ACTIONS_PER_TRANSFER + DESTINATION_ACTIONS_PER_TRANSFER)
            * self.marginal_fee_zatoshi()
    }

    /// The fee (in zatoshi) reserved for one note-preparation transaction: a transaction padded to
    /// [`PREP_TX_ACTIONS`](crate::preparation::PREP_TX_ACTIONS) logical actions (per ZIP 318), each
    /// charged the marginal fee. This is the per-transaction reserve
    /// [`plan_preparation`](crate::preparation::plan_preparation) subtracts from the inputs.
    fn prep_transaction_fee_zatoshi(&self) -> u64 {
        crate::preparation::PREP_TX_ACTIONS as u64 * self.marginal_fee_zatoshi()
    }
}

/// The ZIP-317 fee model: the marginal fee is the ZIP-317 [`MARGINAL_FEE`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Zip317FeePolicy;

impl FeePolicy for Zip317FeePolicy {
    fn marginal_fee_zatoshi(&self) -> u64 {
        MARGINAL_FEE.into_u64()
    }
}

/// The outcome of planning a note split: the self-funding notes to create, the values that will
/// cross the turnstile, and the residual kept in the source pool. Produced by a
/// [`DenominationStrategy`].
///
/// The plan stores the [`crossing_values`](Self::crossing_values) and one constant per-note fee
/// buffer (see [`FeePolicy::transfer_fee_buffer_zatoshi`]); the prepared-note values are derived, not
/// stored, since every prepared note is exactly its crossing value plus that buffer. Each index `i`
/// describes one prepared note at the two phases of the migration:
/// - `crossing_values[i]` is the denomination that CROSSES the turnstile into the destination pool
///   when the note is spent (the privacy-relevant value an observer sees; their sum is
///   [`total_migratable_zatoshi`](Self::total_migratable_zatoshi)).
/// - [`migration_outputs`](Self::migration_outputs)`[i] == crossing_values[i] + buffer` is the note
///   CREATED in the source pool during the prep phase, so it self-funds its own migration transfer
///   (the buffer pays that transfer's fee, and the crossing value is what remains to cross).
///
/// Value the strategy could not pack into a whole self-funding note is neither of these; it is
/// [`change`](Self::change), left untouched in the source pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSplitPlan {
    crossing_values: Vec<u64>,
    note_fee_buffer_zatoshi: u64,
    change: Option<u64>,
    prep_fee_zatoshi: u64,
    total_input_zatoshi: u64,
    total_migratable_zatoshi: u64,
}

impl NoteSplitPlan {
    /// Assemble a plan from a strategy's computed `crossing_values`, the per-note fee buffer they each
    /// carry (the prepared-note values are `crossing + note_fee_buffer_zatoshi`), and the
    /// `remaining_budget` left after them, which becomes source-pool change.
    pub(crate) fn from_notes(
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        crossing_values: Vec<u64>,
        note_fee_buffer_zatoshi: u64,
        remaining_budget: u64,
    ) -> Self {
        let total_migratable_zatoshi = crossing_values.iter().sum();
        Self {
            crossing_values,
            note_fee_buffer_zatoshi,
            change: (remaining_budget > 0).then_some(remaining_budget),
            prep_fee_zatoshi,
            total_input_zatoshi,
            total_migratable_zatoshi,
        }
    }

    /// An empty plan (nothing migrated), with the caller-supplied residual as `change`.
    pub(crate) fn empty(
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        change: Option<u64>,
    ) -> Self {
        Self {
            crossing_values: Vec::new(),
            note_fee_buffer_zatoshi: 0,
            change,
            prep_fee_zatoshi,
            total_input_zatoshi,
            total_migratable_zatoshi: 0,
        }
    }

    /// Reassemble a plan from its stored fields, exactly as they were persisted. This is the inverse
    /// of the accessors below: a store (for example `zcash_pool_migration_sqlite`) reads the columns
    /// back and reconstructs the plan verbatim, so `total_migratable_zatoshi` is taken as stored
    /// rather than recomputed (the caller is responsible for having persisted a consistent set, which
    /// for a plan produced by `Self::from_notes` means `total_migratable_zatoshi` equals the sum of
    /// `crossing_values`).
    pub fn from_stored_parts(
        crossing_values: Vec<u64>,
        note_fee_buffer_zatoshi: u64,
        change: Option<u64>,
        prep_fee_zatoshi: u64,
        total_input_zatoshi: u64,
        total_migratable_zatoshi: u64,
    ) -> Self {
        Self {
            crossing_values,
            note_fee_buffer_zatoshi,
            change,
            prep_fee_zatoshi,
            total_input_zatoshi,
            total_migratable_zatoshi,
        }
    }

    /// The value (in zatoshi) of each prepared note the split will create: the crossing value at the
    /// same index plus the [fee buffer](Self::note_fee_buffer_zatoshi), so the note can later pay its
    /// own migration-transfer fee. Derived from [`crossing_values`](Self::crossing_values); the plan
    /// stores only the crossings and the constant buffer.
    pub fn migration_outputs(&self) -> Vec<u64> {
        self.crossing_values
            .iter()
            .map(|&c| c + self.note_fee_buffer_zatoshi)
            .collect()
    }

    /// The denomination values (in zatoshi) that will cross the turnstile into the destination pool
    /// when the note at the same index is spent. Their exact form (a `{1, 2, 5} * 10^k` ZEC value, a
    /// power of ten, ...) depends on the strategy. Each prepared note (see
    /// [`migration_outputs`](Self::migration_outputs)) is one of these plus the fee buffer.
    pub fn crossing_values(&self) -> &[u64] {
        &self.crossing_values
    }

    /// The constant fee buffer (in zatoshi) added to every crossing value to form the prepared note,
    /// so each note self-funds its own migration transfer. The same for every note in the plan.
    pub fn note_fee_buffer_zatoshi(&self) -> u64 {
        self.note_fee_buffer_zatoshi
    }

    /// Any residual left in the source pool (in zatoshi) because it could not form a whole
    /// self-funding note, or the note cap was reached, or `None` if the balance was consumed
    /// exactly. Includes dust.
    pub fn change(&self) -> Option<u64> {
        self.change
    }

    /// The fee (in zatoshi) reserved for the note-split ("prep") transaction before decomposition.
    pub fn prep_fee_zatoshi(&self) -> u64 {
        self.prep_fee_zatoshi
    }

    /// The total spendable source-pool balance (in zatoshi) this plan decomposes.
    pub fn total_input_zatoshi(&self) -> u64 {
        self.total_input_zatoshi
    }

    /// The total value (in zatoshi) that will migrate to the destination pool: the sum of the
    /// crossing values.
    pub fn total_migratable_zatoshi(&self) -> u64 {
        self.total_migratable_zatoshi
    }
}

/// A rule for decomposing a spendable source-pool balance into the notes a migration run will prepare.
/// See the module docs for the implementation and its denomination set.
pub trait DenominationStrategy {
    /// Decompose `total_input_zatoshi`, after reserving `prep_fee_zatoshi` for the note-split
    /// transaction, into self-funding notes. `prep_fee_zatoshi` is a single constant (the fee for the
    /// note-split transaction padded to the maximum split action count), not a fee rule, because the
    /// migration pads that transaction to the maximum anyway; sizing the reservation to that padded
    /// maximum lets the decomposition proceed without re-deriving a fee per candidate split. `rng` is
    /// used by randomized strategies and ignored by deterministic ones.
    fn plan<R: RngCore>(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        rng: &mut R,
    ) -> NoteSplitPlan;
}

/// Convenience wrapper: plan with the recommended [`CanonicalOneTwoFive`] strategy (ZIP 318 canonical
/// quantization).
pub fn plan_note_split<R: RngCore>(
    total_input_zatoshi: u64,
    prep_fee_zatoshi: u64,
    rng: &mut R,
) -> NoteSplitPlan {
    CanonicalOneTwoFive::recommended().plan(total_input_zatoshi, prep_fee_zatoshi, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The default fee buffer is four marginal fees (2 source-pool + 2 destination-pool
        /// actions), for any marginal-fee model.
        #[test]
        fn default_buffer_is_four_marginal_fees(m in 0u64..10_000_000) {
            struct FlatFee(u64);
            impl FeePolicy for FlatFee {
                fn marginal_fee_zatoshi(&self) -> u64 {
                    self.0
                }
            }
            prop_assert_eq!(FlatFee(m).transfer_fee_buffer_zatoshi(), 4 * m);
        }
    }

    #[test]
    fn zip317_marginal_fee_is_5000() {
        assert_eq!(Zip317FeePolicy.marginal_fee_zatoshi(), 5_000);
        assert_eq!(Zip317FeePolicy.transfer_fee_buffer_zatoshi(), 20_000);
    }
}
