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
//! Whatever the strategy, the result is a [`DenominationPlan`]: a multiset of *denomination notes*,
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
//! Denomination planning is fundamentally a *constrained integer partition* problem: writing a known integer
//! as an unordered sum of positive parts. The known integer is `N`, the migratable balance to
//! decompose (in zatoshi, after the preparation transaction fee is reserved), with
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
use core::num::NonZeroUsize;

use rand_core::{CryptoRng, RngCore};

use zcash_protocol::value::{BalanceError, Zatoshis};

pub mod strategies;

pub use strategies::CanonicalOneTwoFive;

/// The ZIP 318 denomination bounds, re-exported from the crate that defines them. [`DENOM_CAP`] is
/// the largest denomination a single crossing may carry; [`MAX_RESIDUAL_VALUE`] is the smallest, and
/// equally the sub-threshold below which a leftover source-pool balance is never migrated at all —
/// it is left untouched in the wallet, preserving privacy.
///
/// Once the main migration completes, a leftover at or above [`MAX_RESIDUAL_VALUE`] (but too small
/// to form a whole self-funding note) is surfaced to the user as an opt-in choice: migrate the
/// remainder too (which can compromise privacy, so it is shown with a disclaimer) or lock it to keep
/// that privacy.
///
/// Both are NORMATIVE: they are the bounds ZIP 318 fixes for the denomination set, so they are not
/// caller-settable. A wallet chooses how many notes a run prepares (see
/// [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`]), never which values may cross.
pub use zcash_protocol::zip318::{DENOM_CAP, MAX_RESIDUAL_VALUE};

/// The default cap on how many notes one migration run prepares. Bounding the note count keeps the
/// decomposition a bounded problem and bounds each run's transaction and proving cost; a larger
/// balance migrates over several runs.
///
/// This is a policy default of this crate, not a ZIP 318 constant: the ZIP fixes the denomination
/// set (`{1, 2, 5} * 10^k`) and its bounds ([`DENOM_CAP`] and [`MAX_RESIDUAL_VALUE`]), but says
/// nothing about how many notes one run may prepare. The count is therefore the caller's to choose
/// — a wallet may override it per run — while the set and its bounds are not caller-settable.
pub const MIGRATION_MAX_PREPARED_NOTES_PER_RUN: NonZeroUsize = match NonZeroUsize::new(50) {
    Some(v) => v,
    None => panic!("nonzero"),
};

/// The outcome of denomination planning: the self-funding notes to create, the values that will
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
pub struct DenominationPlan {
    crossing_values: Vec<Zatoshis>,
    note_fee_buffer: Zatoshis,
    change: Option<Zatoshis>,
    prep_fees: Zatoshis,
    total_input: Zatoshis,
    total_migratable: Zatoshis,
}

impl DenominationPlan {
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
    /// of the accessors below: a store (for example `zcash_client_sqlite`'s `pool_migration`
    /// module) reads the columns
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
}

/// A rule for decomposing a spendable source-pool balance into the notes a migration run will prepare.
/// See the module docs for the implementation and its denomination set.
pub trait DenominationStrategy {
    /// Decompose `total_input_zatoshi` into self-funding notes, accounting the preparation fees at
    /// each step of the decomposition.
    ///
    /// `spendable_note_count` is how many spendable notes hold `total_input`. A strategy may
    /// consult it only through the single predicate `spendable_note_count == 1`, which decides
    /// whether preparation is avoidable at all: a lone note necessarily equals the balance, so a
    /// balance of exactly one denomination plus its buffer is certain to fund that crossing
    /// directly with no preparation fee, while with two or more notes no note can equal that
    /// funding value and the fee reserve is mandatory. Beyond that bit, the published values must
    /// remain a function of the balance alone. `prep_tx_fee_zatoshi` is the ZIP-317 fee of one
    /// canonical (padded) preparation transaction, computed by the caller from the canonical
    /// shape. `prep_tx_count` is the capability that answers, for a candidate multiset of
    /// prepared-note values (each `crossing + buffer`), how many preparation transactions minting
    /// them will take — `None` when the wallet's notes cannot mint that multiset at all. The
    /// engine backs it with the preparation planner. A strategy must use it only to RECONCILE a
    /// split it computed as above — dropping parts the wallet cannot fund, never substituting
    /// different denominations — so the published values cannot otherwise depend on the wallet's
    /// note shape. `rng` is used by randomized strategies and ignored by deterministic ones; it is
    /// bound as [`CryptoRng`] because a randomized strategy's draws decide the on-chain crossing
    /// values, which are privacy-relevant.
    fn plan<R: RngCore + CryptoRng>(
        &self,
        total_input: Zatoshis,
        spendable_note_count: usize,
        prep_tx_fee: Zatoshis,
        prep_tx_count: &dyn Fn(&[Zatoshis]) -> Option<usize>,
        rng: &mut R,
    ) -> DenominationPlan;
}

/// Convert a strategy-internal value to [`Zatoshis`]. Infallible by construction: the strategies'
/// arithmetic only partitions the total input, which arrives as an already-valid [`Zatoshis`]
/// amount, so every part is bounded by it.
pub(crate) fn zat(value: u64) -> Zatoshis {
    Zatoshis::from_u64(value).expect("split values are bounded by the validated total input")
}

/// Convenience wrapper: plan with the canonical [`CanonicalOneTwoFive`] strategy (ZIP 318 canonical
/// quantization) capped at `max_notes` prepared notes, sized by the caller-computed canonical fees
/// (see [`DenominationStrategy::plan`]).
///
/// `max_notes` is the ONLY knob: the denomination set and its [`DENOM_CAP`]/[`MAX_RESIDUAL_VALUE`]
/// bounds are normative ZIP 318 values, not parameters. Pass
/// [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`] for this crate's default.
pub fn plan_denominations<R>(
    total_input: Zatoshis,
    spendable_note_count: usize,
    max_notes: NonZeroUsize,
    transfer_fee_buffer: Zatoshis,
    prep_tx_fee: Zatoshis,
    prep_tx_count: &dyn Fn(&[Zatoshis]) -> Option<usize>,
    rng: &mut R,
) -> DenominationPlan
where
    R: RngCore + CryptoRng,
{
    CanonicalOneTwoFive::with_max_notes(max_notes, transfer_fee_buffer).plan(
        total_input,
        spendable_note_count,
        prep_tx_fee,
        prep_tx_count,
        rng,
    )
}

/// Whether `total_input`, held as `spendable_note_count` notes, quantizes to at least one canonical
/// part under the recommended strategy — that is, whether a wallet in this state could migrate part
/// of its balance if its note values allowed. Independent of the note VALUES: reconciliation
/// against them can only truncate the canonical split, never extend it, so a state for which this
/// is `false` has nothing to migrate regardless of how the notes hold the value, while `true` with
/// an empty reconciled plan means the note values — not the balance — blocked the run (see
/// [`MigrationError::UnfundableSplit`](crate::engine::MigrationError::UnfundableSplit)).
///
/// The answer does not in fact depend on `max_notes`: a first part forms or not from the balance,
/// the transfer buffer and the preparation fee alone, and every positive cap admits that first
/// part, so the emptiness of the split is invariant across caps. The cap is taken anyway so that
/// the question is asked of the run actually being planned rather than of a hypothetical default
/// one.
pub(crate) fn balance_has_canonical_split(
    total_input: Zatoshis,
    spendable_note_count: usize,
    max_notes: NonZeroUsize,
    transfer_fee_buffer: Zatoshis,
    prep_tx_fee: Zatoshis,
) -> bool {
    !CanonicalOneTwoFive::with_max_notes(max_notes, transfer_fee_buffer)
        .unconstrained_split(
            u64::from(total_input),
            spendable_note_count,
            u64::from(prep_tx_fee),
        )
        .is_empty()
}
