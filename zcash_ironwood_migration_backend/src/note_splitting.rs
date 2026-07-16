//! Note-split planning: how to break a wallet's spendable source-pool balance into the notes that
//! will cross the turnstile into the destination pool during migration.
//!
//! The plan and the strategies are pool-agnostic (any source pool -> destination pool); the code
//! names no specific pool. Zcash's first use is the Orchard -> Ironwood migration enabled by NU6.3,
//! which the prose below uses as the running example.
//!
//! # The problem
//!
//! When a wallet migrates, every note it spends makes a value cross the turnstile in a transaction a
//! chain observer can see. The rule that picks those crossing amounts is a privacy-critical choice:
//! it decides whether an observer can recognise a specific balance, link all the crossings of one
//! migration together, or single out large holders ("whales"). Two families of rules are in the
//! literature, and they optimise for opposite things:
//!
//! - *Sampling* a random decomposition per wallet, so no fixed pattern maps a sequence of amounts
//!   back to a balance or a migration plan (privacy from unpredictability).
//! - *Canonicalising* to a small shared set of standard amounts, so many wallets emit identical
//!   values that collide and cannot be attributed (privacy from value collision / k-anonymity).
//!
//! Which family is preferable is a live design discussion. This module does not settle it: the
//! composition rule is abstracted behind the [`DenominationStrategy`] trait, and three
//! implementations (in [`strategies`]) are provided so the choice can be made (and reviewed) later by
//! selecting a strategy rather than by rewriting code:
//!
//! - [`RandomizedOneTwoFive`]: samples a random decomposition whose crossing values follow the
//!   `{1, 2, 5} * 10^k` ZEC series (1, 2, 5, 10, 20, 50, ... ZEC).
//! - [`CanonicalOneTwoFive`]: the deterministic, descending greedy decomposition over that same
//!   `{1, 2, 5} * 10^k` ZEC series (e.g. 12,345 ZEC -> 10,000 + 2,000 + 200 + 100 + 20 + 20 + 5).
//! - [`CanonicalPowerOfTen`]: the deterministic decimal-digit expansion into pure powers of ten
//!   (`..., 100, 10, 1, 0.1, 0.01, ...` ZEC) described by the Ironwood migration ZIP draft.
//!
//! The other tunables are pluggable too: the per-note fee comes from a [`FeePolicy`], and the
//! maximum denomination, dust floor, and note cap are constructor parameters of each strategy.
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
//! permitted denomination (dust floor and cap); `K`, the maximum number of parts (the note cap); and
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
//! and their number bounded, and the two strategies differ only in which admissible partition they
//! return. `CanonicalPowerOfTen` returns the single deterministic digit-expansion partition (its
//! parts are additionally non-increasing); `RandomizedOneTwoFive` *samples* one, because for privacy
//! the objective is a distribution over partitions, not a minimal or maximal one.
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
//!   used for banknotes and measurement scales; the canonical strategy's powers of ten and the equal
//!   outputs of privacy-coin mixing (CoinJoin) are related choices.
//!   <https://en.wikipedia.org/wiki/Preferred_number>
//!
//! The two strategies here are a deterministic greedy expansion and a floor-biased random sampler;
//! the list above sketches the space a reused version of this crate could grow into.

use rand_core::RngCore;

use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
use zcash_protocol::value::COIN;

pub mod strategies;
mod utils;

pub use strategies::{CanonicalOneTwoFive, CanonicalPowerOfTen, RandomizedOneTwoFive};

/// The default cap on how many notes one migration run prepares. Bounding the note count keeps the
/// decomposition a bounded problem and bounds each run's transaction and proving cost; a larger
/// balance migrates over several runs.
pub const MIGRATION_MAX_PREPARED_NOTES_PER_RUN: usize = 50;

/// The default largest denomination (in whole ZEC) the `{1, 2, 5} * 10^k` strategies give a single
/// note: `1 * 10^4 = 10_000` ZEC, itself a `{1, 2, 5} * 10^k` value. Capping the top denomination
/// keeps even a whale's crossings within the shared denomination set, so no single crossing is a
/// near-unique fingerprint. This is only a default: the actual cap is chosen per run by the caller
/// (the wallet) and passed to the strategy constructor.
pub const MIGRATION_MAX_DENOMINATION_ZEC: u64 = 10_000;

/// The maximum denomination (in whole ZEC) of the Ironwood migration ZIP draft's canonical
/// power-of-ten scheme (`DENOM_CAP`), provisionally 100 ZEC. Default for [`CanonicalPowerOfTen`].
pub const ZIP_DENOM_CAP_ZEC: u64 = 100;

/// The sub-threshold (0.01 ZEC) below which a leftover source-pool balance is never migrated: it is
/// left untouched in the wallet, preserving privacy. Once the main migration completes, a leftover
/// at or above this threshold (but too small to form a whole self-funding note) is surfaced to the
/// user as an opt-in choice: migrate the remainder too (which can compromise privacy, so it is shown
/// with a disclaimer) or lock it to keep that privacy. Consumed by the context module in a later
/// slice. Also the default dust floor of [`CanonicalPowerOfTen`] (the ZIP draft's `DUST_FLOOR`).
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
/// [`migration_outputs`](Self::migration_outputs) and [`crossing_values`](Self::crossing_values) are
/// PARALLEL (index `i` describes the same prepared note) and differ by exactly the per-note fee
/// buffer (see [`FeePolicy::transfer_fee_buffer_zatoshi`]), so for every `i`:
///
/// ```text
/// migration_outputs[i] == crossing_values[i] + buffer
/// ```
///
/// They describe that one note at the two phases of the migration:
/// - `crossing_values[i]` is the denomination that CROSSES the turnstile into the destination pool
///   when the note is spent (the privacy-relevant value an observer sees; their sum is
///   [`total_migratable_zatoshi`](Self::total_migratable_zatoshi)).
/// - `migration_outputs[i]` is the note CREATED in the source pool during the prep phase: the
///   crossing value plus the buffer, so the note self-funds its own migration transfer (the buffer
///   pays that transfer's fee, and the crossing value is what remains to cross).
///
/// Value the strategy could not pack into a whole self-funding note is neither of these; it is
/// [`change`](Self::change), left untouched in the source pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSplitPlan {
    migration_outputs: Vec<u64>,
    crossing_values: Vec<u64>,
    change: Option<u64>,
    prep_fee_zatoshi: u64,
    total_input_zatoshi: u64,
    total_migratable_zatoshi: u64,
}

impl NoteSplitPlan {
    /// Assemble a plan from a strategy's computed notes (`migration_outputs`, parallel
    /// `crossing_values`) and the `remaining_budget` left after them, which becomes source-pool change.
    pub(crate) fn from_notes(
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        migration_outputs: Vec<u64>,
        crossing_values: Vec<u64>,
        remaining_budget: u64,
    ) -> Self {
        let total_migratable_zatoshi = crossing_values.iter().sum();
        Self {
            migration_outputs,
            crossing_values,
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
            migration_outputs: Vec::new(),
            crossing_values: Vec::new(),
            change,
            prep_fee_zatoshi,
            total_input_zatoshi,
            total_migratable_zatoshi: 0,
        }
    }

    /// The value (in zatoshi) of each prepared note the split will create: the crossing value at the
    /// same index plus the fee buffer, so the note can later pay its own migration-transfer fee.
    pub fn migration_outputs(&self) -> &[u64] {
        &self.migration_outputs
    }

    /// The denomination values (in zatoshi) that will cross the turnstile into the destination pool
    /// when the note at the same index is spent; parallel to [`Self::migration_outputs`]. Their
    /// exact form (a `{1, 2, 5} * 10^k` ZEC value, a power of ten, ...) depends on the strategy.
    pub fn crossing_values(&self) -> &[u64] {
        &self.crossing_values
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
/// Implementations differ in the denomination set they use and in whether the decomposition is
/// random or deterministic; see the module docs. Object-safe, so a wallet can hold a selected
/// `Box<dyn DenominationStrategy>`.
pub trait DenominationStrategy {
    /// Decompose `total_input_zatoshi`, after reserving `prep_fee_zatoshi` for the note-split
    /// transaction, into self-funding notes. `rng` is used by randomized strategies and ignored by
    /// deterministic ones.
    fn plan(
        &self,
        total_input_zatoshi: u64,
        prep_fee_zatoshi: u64,
        rng: &mut dyn RngCore,
    ) -> NoteSplitPlan;
}

/// Convenience wrapper: plan with the recommended [`RandomizedOneTwoFive`] strategy.
pub fn plan_note_split<R: RngCore>(
    total_input_zatoshi: u64,
    prep_fee_zatoshi: u64,
    rng: &mut R,
) -> NoteSplitPlan {
    RandomizedOneTwoFive::recommended().plan(total_input_zatoshi, prep_fee_zatoshi, rng)
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
