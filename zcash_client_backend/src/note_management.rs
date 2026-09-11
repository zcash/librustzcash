//! Note management: maintaining a target distribution of note values in the most recent
//! shielded pool.
//!
//! A [`ValueLadder`] partitions note values into buckets. A [`TargetDistribution`] assigns a
//! target count to each bucket, and a [`NoteHistogram`] records how many notes an account holds
//! in each. A [`NoteManagementPolicy`] turns the difference between the two into a [`SplitPlan`]
//! for a transaction's change and a [`ConsolidationPlan`] for the small notes it may sweep.
//!
//! The residual of the change beyond the planned pieces is added to the largest piece, so that
//! piece may land in a higher bucket than the one it was planned for. A sweep fills free slots
//! (spend sides the transaction's real outputs already pay for) with notes of any positive value,
//! and enlarging slots only with notes that pay for themselves; see [`ConsolidationBudget`].
//!
//! Every approximation in the planner errs toward the account holding fewer notes, with one
//! exception: the histogram's lock filter excludes the notes another in-flight proposal has
//! locked, so a proposal built concurrently with another sees fewer notes than the account holds
//! and may plan more pieces than it needs.

use core::{fmt, num::NonZeroUsize};

use nonempty::NonEmpty;
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, NetworkUpgrade},
    value::Zatoshis,
    zip318::{DENOM_CAP, MAX_RESIDUAL_VALUE},
};

use crate::data_api::{
    InputSource,
    wallet::{TargetHeight, input_selection::LockFilter},
};

/// The significands of the [ZIP 318] denomination series.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
const ZIP318_SIGNIFICANDS: [u64; 3] = [1, 2, 5];

/// The base of the [ZIP 318] denomination scale: each denomination is a significand times a power
/// of this radix. `zcash_protocol::zip318` keeps its own copy of this constant private, so the
/// ladder restates it.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
const ZIP318_RADIX: u64 = 10;

/// The smallest value a ladder rung may take: one zatoshi. Every rung must be positive, so a
/// requested rung below this is raised to it.
const MIN_RUNG: Zatoshis = Zatoshis::const_from_u64(1);

/// The number of change outputs a policy that does not split change asks for.
const SINGLE_CHANGE_OUTPUT: usize = 1;

/// Returns the pool in which note management maintains a note distribution at `target_height`:
/// Ironwood once NU6.3 is active, Orchard otherwise. Sapling is never this pool.
pub fn most_recent_shielded_pool<P: consensus::Parameters>(
    params: &P,
    target_height: TargetHeight,
) -> ShieldedPool {
    if params.is_nu_active(NetworkUpgrade::Nu6_3, target_height.into()) {
        ShieldedPool::Ironwood
    } else {
        ShieldedPool::Orchard
    }
}

/// Errors in constructing note-management values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoteManagementError {
    /// A ladder must have at least one rung, every rung must be positive, and rungs must strictly
    /// ascend.
    InvalidLadder,
    /// A target must have one count per bucket of its ladder, and no count for bucket zero.
    InvalidTarget,
    /// Sweep caps must have one cap per bucket of their ladder, and no positive cap above a zero
    /// cap.
    InvalidSweepCaps,
}

impl fmt::Display for NoteManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoteManagementError::InvalidLadder => write!(
                f,
                "A value ladder must have at least one rung, and its rungs must be positive and strictly ascending."
            ),
            NoteManagementError::InvalidTarget => write!(
                f,
                "A target distribution must have one count per bucket of its ladder, and the count for bucket zero must be zero."
            ),
            NoteManagementError::InvalidSweepCaps => write!(
                f,
                "Sweep caps must have one cap for each bucket of their ladder, and no positive cap above a zero cap."
            ),
        }
    }
}

impl std::error::Error for NoteManagementError {}

/// A strictly ascending sequence of positive note values that partitions values into buckets.
///
/// A ladder with `n` rungs defines `n + 1` buckets: bucket `0` holds values below the first rung,
/// and bucket `i` (for `1 <= i <= n`) holds values from rung `i` up to but excluding rung
/// `i + 1`, with the last bucket unbounded above.
///
/// Rungs and buckets are numbered from one in this documentation, while [`ValueLadder::rungs`]
/// returns a slice indexed from zero: rung `i` is `rungs()[i - 1]`, which is also what
/// [`ValueLadder::rung_value`] returns for bucket `i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueLadder {
    rungs: Vec<Zatoshis>,
}

impl ValueLadder {
    /// Constructs a ladder from its rungs. Fails unless there is at least one rung, every rung is
    /// positive, and the rungs strictly ascend.
    pub fn new(rungs: impl IntoIterator<Item = Zatoshis>) -> Result<Self, NoteManagementError> {
        let rungs: Vec<Zatoshis> = rungs.into_iter().collect();
        let ascending = rungs.windows(2).all(|pair| pair[0] < pair[1]);
        if rungs.is_empty() || !rungs[0].is_positive() || !ascending {
            return Err(NoteManagementError::InvalidLadder);
        }
        Ok(Self { rungs })
    }

    /// The [ZIP 318] denomination series `{1, 2, 5} * 10^k`, from 0.01 ZEC to 10,000 ZEC.
    ///
    /// [ZIP 318]: https://zips.z.cash/zip-0318
    pub fn zip318() -> Self {
        let cap = u64::from(DENOM_CAP);
        let mut rungs = Vec::new();
        let mut decade = u64::from(MAX_RESIDUAL_VALUE);
        while decade <= cap {
            for significand in ZIP318_SIGNIFICANDS {
                // `decade` is at most the cap and `significand` at most 5, so this cannot overflow.
                let value = decade * significand;
                if value <= cap {
                    rungs.push(Zatoshis::const_from_u64(value));
                }
            }
            let Some(next) = decade.checked_mul(ZIP318_RADIX) else {
                break;
            };
            decade = next;
        }
        Self::new(rungs).expect("the denomination series is positive and strictly ascending")
    }

    /// The rungs, ascending.
    pub fn rungs(&self) -> &[Zatoshis] {
        &self.rungs
    }

    /// The number of buckets: one more than the number of rungs.
    pub fn bucket_count(&self) -> usize {
        self.rungs.len() + 1
    }

    /// The bucket holding `value`: the number of rungs at or below it.
    pub fn bucket_of(&self, value: Zatoshis) -> usize {
        self.rungs.partition_point(|rung| *rung <= value)
    }

    /// The rung that opens `bucket`, or `None` for bucket zero or an out-of-range bucket.
    pub fn rung_value(&self, bucket: usize) -> Option<Zatoshis> {
        bucket
            .checked_sub(1)
            .and_then(|i| self.rungs.get(i).copied())
    }
}

/// Per-bucket counts of an account's unspent notes in one pool, over the ladder the histogram
/// carries.
///
/// A note is counted as either spendable or pending, never both: "pending" means the note's
/// transaction is not yet mined, not that the note is mined but short of the confirmation
/// threshold. [`NoteHistogram::spendable`], [`NoteHistogram::pending`] and
/// [`NoteHistogram::present`] return zero for a bucket outside the ladder's range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteHistogram {
    ladder: ValueLadder,
    spendable: Vec<usize>,
    pending: Vec<usize>,
}

impl NoteHistogram {
    /// A histogram over `ladder` holding no notes.
    pub fn empty(ladder: ValueLadder) -> Self {
        let bucket_count = ladder.bucket_count();
        Self {
            ladder,
            spendable: vec![0; bucket_count],
            pending: vec![0; bucket_count],
        }
    }

    /// Buckets `spendable` and `pending` note values over `ladder`.
    ///
    /// The two sequences must be disjoint: each of the account's notes appears in exactly one of
    /// them.
    pub fn from_values(
        ladder: ValueLadder,
        spendable: impl IntoIterator<Item = Zatoshis>,
        pending: impl IntoIterator<Item = Zatoshis>,
    ) -> Self {
        let mut histogram = Self::empty(ladder);
        for value in spendable {
            let bucket = histogram.ladder.bucket_of(value);
            histogram.spendable[bucket] += 1;
        }
        for value in pending {
            let bucket = histogram.ladder.bucket_of(value);
            histogram.pending[bucket] += 1;
        }
        histogram
    }

    /// The ladder whose buckets this histogram counts.
    pub fn ladder(&self) -> &ValueLadder {
        &self.ladder
    }

    /// Spendable notes in `bucket`.
    pub fn spendable(&self, bucket: usize) -> usize {
        self.spendable.get(bucket).copied().unwrap_or(0)
    }

    /// Pending notes in `bucket`.
    pub fn pending(&self, bucket: usize) -> usize {
        self.pending.get(bucket).copied().unwrap_or(0)
    }

    /// All unspent notes in `bucket`, spendable and pending.
    pub fn present(&self, bucket: usize) -> usize {
        self.spendable(bucket) + self.pending(bucket)
    }

    /// The number of buckets.
    pub fn bucket_count(&self) -> usize {
        self.ladder.bucket_count()
    }

    /// The histogram after spending notes of the given values. Only spendable counts decrease;
    /// each saturates at zero, and pending counts are untouched.
    pub fn without(&self, spent: impl IntoIterator<Item = Zatoshis>) -> Self {
        let mut result = self.clone();
        for value in spent {
            let bucket = result.ladder.bucket_of(value);
            if let Some(count) = result.spendable.get_mut(bucket) {
                *count = count.saturating_sub(1);
            }
        }
        result
    }
}

/// A target count of notes in each bucket of a ladder. Bucket zero, below the first rung, always
/// has a target of zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetDistribution {
    ladder: ValueLadder,
    counts: Vec<usize>,
}

impl TargetDistribution {
    /// Constructs a target from a ladder and one count per bucket. Fails unless there is exactly
    /// one count per bucket and the count for bucket zero is zero.
    pub fn new(
        ladder: ValueLadder,
        counts: impl IntoIterator<Item = usize>,
    ) -> Result<Self, NoteManagementError> {
        let counts: Vec<usize> = counts.into_iter().collect();
        if counts.len() != ladder.bucket_count() || counts.first() != Some(&0) {
            return Err(NoteManagementError::InvalidTarget);
        }
        Ok(Self { ladder, counts })
    }

    /// A one-rung target of `count` notes worth at least `min_value`: the successor of a split
    /// policy with that target output count and minimum split output value.
    ///
    /// A `min_value` of zero is raised to one zatoshi, so bucket 1 counts every note of positive
    /// value and bucket 0 stays empty.
    pub fn single_bucket(min_value: Zatoshis, count: NonZeroUsize) -> Self {
        Self {
            ladder: ValueLadder::new([min_value.max(MIN_RUNG)])
                .expect("a single positive rung is a valid ladder"),
            counts: vec![0, count.get()],
        }
    }

    /// The ladder this target is expressed over.
    pub fn ladder(&self) -> &ValueLadder {
        &self.ladder
    }

    /// The target count for `bucket`.
    pub fn count(&self, bucket: usize) -> usize {
        self.counts.get(bucket).copied().unwrap_or(0)
    }

    /// The total number of notes the target asks for.
    pub fn total(&self) -> usize {
        self.counts.iter().sum()
    }

    /// How many notes the account lacks in `bucket`.
    ///
    /// `histogram` must count notes over the same ladder as this target.
    pub fn deficit_at(&self, histogram: &NoteHistogram, bucket: usize) -> usize {
        debug_assert_eq!(
            self.ladder(),
            histogram.ladder(),
            "histogram and target must share a ladder"
        );
        self.count(bucket).saturating_sub(histogram.present(bucket))
    }

    /// How many notes the account holds in `bucket` beyond the target.
    ///
    /// `histogram` must count notes over the same ladder as this target.
    pub fn surplus_at(&self, histogram: &NoteHistogram, bucket: usize) -> usize {
        debug_assert_eq!(
            self.ladder(),
            histogram.ladder(),
            "histogram and target must share a ladder"
        );
        histogram.present(bucket).saturating_sub(self.count(bucket))
    }

    /// How many notes the account lacks, in a vector of [`ValueLadder::bucket_count`] entries
    /// indexed by bucket.
    ///
    /// `histogram` must count notes over the same ladder as this target.
    pub fn deficits(&self, histogram: &NoteHistogram) -> Vec<usize> {
        debug_assert_eq!(
            self.ladder(),
            histogram.ladder(),
            "histogram and target must share a ladder"
        );
        (0..self.ladder.bucket_count())
            .map(|bucket| self.deficit_at(histogram, bucket))
            .collect()
    }

    /// How many notes the account holds beyond the target, in a vector of
    /// [`ValueLadder::bucket_count`] entries indexed by bucket.
    ///
    /// `histogram` must count notes over the same ladder as this target.
    pub fn surpluses(&self, histogram: &NoteHistogram) -> Vec<usize> {
        debug_assert_eq!(
            self.ladder(),
            histogram.ladder(),
            "histogram and target must share a ladder"
        );
        (0..self.ladder.bucket_count())
            .map(|bucket| self.surplus_at(histogram, bucket))
            .collect()
    }
}

/// Change piece values, largest first. Constructed only through [`SplitPlan::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitPieces(NonEmpty<Zatoshis>);

impl SplitPieces {
    /// The largest piece, which receives the residual of the change.
    pub fn largest(&self) -> Zatoshis {
        *self.0.first()
    }

    /// The pieces, largest first.
    pub fn iter(&self) -> impl Iterator<Item = Zatoshis> + '_ {
        self.0.iter().copied()
    }

    /// The number of pieces.
    pub fn len(&self) -> NonZeroUsize {
        self.0.len_nonzero()
    }
}

/// The change notes a transaction should produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitPlan {
    /// One change output carrying the whole change value.
    SingleOutput,
    /// Change split into these values; a strategy realizes the longest affordable prefix and adds
    /// the residual to [`SplitPieces::largest`].
    Pieces(SplitPieces),
}

impl SplitPlan {
    /// A plan for the given pieces, sorted largest first. An empty sequence of pieces is a plan
    /// for a single change output.
    ///
    /// Pieces are taken as given: a zero-valued piece is kept, and would be realized as a
    /// zero-valued change output. Callers supply positive values.
    pub fn new(mut pieces: Vec<Zatoshis>) -> Self {
        pieces.sort_unstable_by(|a, b| b.cmp(a));
        match NonEmpty::from_vec(pieces) {
            Some(pieces) => SplitPlan::Pieces(SplitPieces(pieces)),
            None => SplitPlan::SingleOutput,
        }
    }

    /// The most change outputs this plan asks for.
    pub fn max_outputs(&self) -> NonZeroUsize {
        match self {
            SplitPlan::SingleOutput => NonZeroUsize::MIN,
            SplitPlan::Pieces(pieces) => pieces.len(),
        }
    }
}

/// The shape of one shielded bundle of a converged funding-only balance.
///
/// Dummy outputs are the padding the balance recorded for the bundle beyond its real outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleShape {
    spends: usize,
    payment_outputs: usize,
    change_outputs: usize,
    dummy_outputs: usize,
}

impl BundleShape {
    /// Constructs a shape. The counts are those of one bundle of a converged funding-only
    /// balance: its spends fund the payment, and its dummy outputs are the padding the balance
    /// recorded beyond the bundle's real outputs.
    pub fn new(
        spends: usize,
        payment_outputs: usize,
        change_outputs: usize,
        dummy_outputs: usize,
    ) -> Self {
        Self {
            spends,
            payment_outputs,
            change_outputs,
            dummy_outputs,
        }
    }

    /// Spends in the bundle.
    pub fn spends(&self) -> usize {
        self.spends
    }

    /// Outputs of the bundle that pay the transaction's recipients.
    pub fn payment_outputs(&self) -> usize {
        self.payment_outputs
    }

    /// Outputs of the bundle that return change to the wallet.
    pub fn change_outputs(&self) -> usize {
        self.change_outputs
    }

    /// Payment outputs plus change outputs.
    pub fn real_outputs(&self) -> usize {
        self.payment_outputs.saturating_add(self.change_outputs)
    }

    /// The action count the bundle was costed for: real outputs plus dummy outputs.
    ///
    /// Note management manages only action-based (Orchard-family) bundles, in which each action
    /// carries one spend and one output, so this output count is also an action count.
    pub fn padded_actions(&self) -> usize {
        self.real_outputs().saturating_add(self.dummy_outputs)
    }
}

/// The consolidation slots an input selector may fill in one shielded bundle, by cost.
///
/// A free slot is a spend side paired with a real output the transaction already pays for; a note
/// of any positive value may fill one. An enlarging slot is a spend side beyond those real
/// outputs: filling one either opens an action or takes a padding side, and in either case the
/// note must exceed `economic_floor`, because the fee rule admits a dust input only against a real
/// output. A candidate ceiling, when present, bounds the value of every candidate strictly from
/// above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsolidationBudget {
    free_slots: usize,
    enlarging_slots: usize,
    economic_floor: Zatoshis,
    candidate_ceiling: Option<Zatoshis>,
}

impl ConsolidationBudget {
    /// Constructs a budget. A note of any positive value may fill a free slot; a note filling an
    /// enlarging slot must exceed `economic_floor`; and every candidate must stay strictly below
    /// `candidate_ceiling` when it is bounded.
    pub fn new(
        free_slots: usize,
        enlarging_slots: usize,
        economic_floor: Zatoshis,
        candidate_ceiling: Option<Zatoshis>,
    ) -> Self {
        Self {
            free_slots,
            enlarging_slots,
            economic_floor,
            candidate_ceiling,
        }
    }

    /// Spend sides the transaction already pays for.
    pub fn free_slots(&self) -> usize {
        self.free_slots
    }

    /// Spend sides beyond the bundle's real outputs. Filling one either opens an action or takes
    /// a padding side; either way the note must exceed [`ConsolidationBudget::economic_floor`],
    /// because the fee rule admits a dust input only against a real output.
    pub fn enlarging_slots(&self) -> usize {
        self.enlarging_slots
    }

    /// The value a note must exceed to fill an enlarging slot.
    pub fn economic_floor(&self) -> Zatoshis {
        self.economic_floor
    }

    /// The value every candidate must stay strictly below, if bounded.
    pub fn candidate_ceiling(&self) -> Option<Zatoshis> {
        self.candidate_ceiling
    }

    /// The most notes a sweep can take: every slot of either kind.
    pub fn economic_capacity(&self) -> usize {
        self.free_slots.saturating_add(self.enlarging_slots)
    }
}

/// A limit, for each bucket of a ladder, on the number of notes a sweep may take from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketCaps {
    ladder: ValueLadder,
    caps: Vec<usize>,
}

impl BucketCaps {
    /// Constructs caps over `ladder`, taking at most `caps[b]` notes from bucket `b`.
    ///
    /// Fails with [`NoteManagementError::InvalidSweepCaps`] unless there is exactly one cap per
    /// bucket of the ladder, and no bucket above a zero-capped bucket at or above bucket one is
    /// itself capped above zero. That zero suffix is what makes [`BucketCaps::ceiling`] a bound on
    /// everything the caps admit.
    pub fn new(ladder: ValueLadder, caps: Vec<usize>) -> Result<Self, NoteManagementError> {
        let zero_suffix = match caps.iter().skip(1).position(|cap| *cap == 0) {
            Some(first_zero) => caps[first_zero + 1..].iter().all(|cap| *cap == 0),
            None => true,
        };
        if caps.len() != ladder.bucket_count() || !zero_suffix {
            return Err(NoteManagementError::InvalidSweepCaps);
        }
        Ok(Self { ladder, caps })
    }

    /// Caps that let a sweep take each bucket down to its target, and no further.
    ///
    /// `histogram` must count notes over the same ladder as `target`.
    ///
    /// The cap on a bucket is its surplus, except that the lowest bucket above bucket zero that is
    /// not in surplus, and every bucket above it, is capped at zero: a sweep works upward from the
    /// smallest notes, and one [`BucketCaps::ceiling`] then describes everything it may take.
    pub fn for_surpluses(target: &TargetDistribution, histogram: &NoteHistogram) -> Self {
        let ladder = target.ladder().clone();
        let mut caps = target.surpluses(histogram);
        if let Some(bucket) = (1..ladder.bucket_count()).find(|bucket| caps[*bucket] == 0) {
            for cap in caps[bucket..].iter_mut() {
                *cap = 0;
            }
        }
        Self { ladder, caps }
    }

    /// The ladder whose buckets these caps are indexed by.
    pub fn ladder(&self) -> &ValueLadder {
        &self.ladder
    }

    /// The most notes a sweep may take from `bucket`; zero for a bucket outside the ladder's
    /// range.
    pub fn cap(&self, bucket: usize) -> usize {
        self.caps.get(bucket).copied().unwrap_or(0)
    }

    /// The value at or above which these caps admit nothing: the rung of the lowest bucket above
    /// bucket zero whose cap is zero, or `None` when every such bucket admits notes.
    ///
    /// The caps are authoritative. This bound is derived from them, so that a store's candidate
    /// query returns no note the caps would deny.
    pub fn ceiling(&self) -> Option<Zatoshis> {
        (1..self.ladder.bucket_count())
            .find(|bucket| self.cap(*bucket) == 0)
            .and_then(|bucket| self.ladder.rung_value(bucket))
    }
}

/// How many notes a sweep may take from each bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SweepCaps {
    /// Any candidate may be swept.
    Unrestricted,
    /// Notes may be swept only within these per-bucket caps.
    PerBucket(BucketCaps),
}

impl SweepCaps {
    /// Whether each of `values` is admitted, taking them in the order given and charging each
    /// admitted value against its bucket's cap.
    ///
    /// The result has one entry per value, in the same order. Present candidates ascending by
    /// value, so that the notes admitted from a bucket are its smallest.
    pub fn admit_all(&self, values: &[Zatoshis]) -> Vec<bool> {
        match self {
            SweepCaps::Unrestricted => vec![true; values.len()],
            SweepCaps::PerBucket(caps) => {
                let mut remaining = caps.caps.clone();
                values
                    .iter()
                    .map(|value| {
                        let bucket = caps.ladder.bucket_of(*value);
                        match remaining.get_mut(bucket) {
                            Some(cap) if *cap > 0 => {
                                *cap -= 1;
                                true
                            }
                            _ => false,
                        }
                    })
                    .collect()
            }
        }
    }

    /// The value at or above which these caps admit nothing, if bounded.
    ///
    /// See [`BucketCaps::ceiling`].
    pub fn ceiling(&self) -> Option<Zatoshis> {
        match self {
            SweepCaps::Unrestricted => None,
            SweepCaps::PerBucket(caps) => caps.ceiling(),
        }
    }
}

/// What a sweep may do to one shielded bundle: the slots it may fill, the action count it may not
/// exceed, and the caps on the notes it takes from each bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationPlan {
    pub(crate) budget: ConsolidationBudget,
    pub(crate) envelope: usize,
    pub(crate) sweep_caps: SweepCaps,
}

impl ConsolidationPlan {
    /// Constructs a plan from a slot budget, an envelope and per-bucket caps.
    ///
    /// The budget must be derived from the same [`BundleShape`] as the envelope, and its candidate
    /// ceiling must equal the caps' own [`SweepCaps::ceiling`]. [`ConsolidationPlan::for_shape`]
    /// derives all three from one shape and so satisfies this by construction.
    pub fn new(budget: ConsolidationBudget, envelope: usize, sweep_caps: SweepCaps) -> Self {
        debug_assert_eq!(budget.candidate_ceiling(), sweep_caps.ceiling());
        Self {
            budget,
            envelope,
            sweep_caps,
        }
    }

    /// The plan for a bundle of the given shape, under a policy that would never split change
    /// beyond `max_change_outputs` outputs.
    ///
    /// The slots and the envelope follow from the shape, and the budget's candidate ceiling from
    /// `sweep_caps`. `action_cap`, when set, is the padded action count a sweep may grow the
    /// bundle to; a bundle already wider than the cap keeps the shape it was costed for.
    pub fn for_shape(
        shape: &BundleShape,
        max_change_outputs: usize,
        action_cap: Option<NonZeroUsize>,
        economic_floor: Zatoshis,
        sweep_caps: SweepCaps,
    ) -> Self {
        let (free, enlarging, envelope) = slots_for(shape, max_change_outputs, action_cap);
        let budget =
            ConsolidationBudget::new(free, enlarging, economic_floor, sweep_caps.ceiling());
        Self::new(budget, envelope, sweep_caps)
    }

    /// The slots the sweep may fill.
    pub fn budget(&self) -> ConsolidationBudget {
        self.budget
    }

    /// The action count the swept bundle may not exceed: the count an ordinary payment under the
    /// same policy could have reached.
    pub fn envelope(&self) -> usize {
        self.envelope
    }

    /// The caps on the notes the sweep takes from each bucket.
    pub fn sweep_caps(&self) -> &SweepCaps {
        &self.sweep_caps
    }
}

/// A policy that turns an account's note holdings into a change split and a sweep budget.
///
/// [`NoteManagementPolicy::fetch`] reads the store once per proposal; every other method is a pure
/// function of the context it returned.
///
/// A policy that returns `None` from [`NoteManagementPolicy::consolidation_plan`] never sweeps,
/// and must return `None` for every shape and context. The associated
/// [`NoteManagementPolicy::Context`] makes the trait ineligible for `dyn` dispatch, so a choice of
/// policy made at runtime is expressed as an enum that implements the trait.
pub trait NoteManagementPolicy {
    /// What the policy needs from the wallet, fetched once per proposal.
    type Context;

    /// Reads the policy's context for `account` as of `target_height`.
    ///
    /// Notes identified in `exclude` are omitted, and locked notes are admitted according to
    /// `lock_filter` (see [`LockFilter`]; a [`LockFilter::Policy`] carrying the default
    /// [`LockedInputPolicy::Exclude`] admits none).
    ///
    /// [`LockedInputPolicy::Exclude`]: crate::data_api::wallet::input_selection::LockedInputPolicy::Exclude
    fn fetch<I: InputSource, P: consensus::Parameters>(
        &self,
        source: &I,
        params: &P,
        account: I::AccountId,
        target_height: TargetHeight,
        exclude: &[I::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<Self::Context, I::Error>;

    /// The context that remains after notes of the given values are spent from the pool the policy
    /// manages.
    fn without_spent(&self, context: &Self::Context, spent: &[Zatoshis]) -> Self::Context;

    /// The change pieces a transaction should produce, given an upper bound on its change value.
    ///
    /// The bound is an upper bound: a change strategy realizes the longest prefix of the plan that
    /// the change affords once fees are known.
    fn split_plan(&self, context: &Self::Context, change_upper_bound: Zatoshis) -> SplitPlan;

    /// The sweep a converged balance admits in the bundle of the pool the policy manages, or
    /// `None` if the policy never sweeps.
    ///
    /// `economic_floor` is the value a note must exceed for its spend side to pay for itself.
    fn consolidation_plan(
        &self,
        context: &Self::Context,
        shape: &BundleShape,
        economic_floor: Zatoshis,
    ) -> Option<ConsolidationPlan>;
}

/// The free slots, enlarging slots and envelope of a bundle whose change would never be split
/// beyond `max_change_outputs`, in that order.
///
/// The envelope is the action count an ordinary payment under the same policy could have reached,
/// held to `action_cap` where one is set; a bundle that returns no change to this pool cannot grow
/// beyond the count it was costed for, and neither can one already wider than the cap.
fn slots_for(
    shape: &BundleShape,
    max_change_outputs: usize,
    action_cap: Option<NonZeroUsize>,
) -> (usize, usize, usize) {
    let real = shape.real_outputs();
    let padded = shape.padded_actions();
    let envelope = if shape.change_outputs() > 0 {
        let uncapped = shape.payment_outputs().saturating_add(max_change_outputs);
        let capped = action_cap.map_or(uncapped, |cap| uncapped.min(cap.get()));
        padded.max(capped)
    } else {
        padded
    };
    let free = real.saturating_sub(shape.spends());
    let enlarging = envelope.saturating_sub(shape.spends().max(real));
    (free, enlarging, envelope)
}

/// A policy that neither splits change nor sweeps: a single change output, and inputs chosen only
/// to fund the payment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unmanaged;

impl NoteManagementPolicy for Unmanaged {
    type Context = ();

    fn fetch<I: InputSource, P: consensus::Parameters>(
        &self,
        _source: &I,
        _params: &P,
        _account: I::AccountId,
        _target_height: TargetHeight,
        _exclude: &[I::NoteRef],
        _lock_filter: LockFilter<'_>,
    ) -> Result<Self::Context, I::Error> {
        Ok(())
    }

    fn without_spent(&self, _context: &Self::Context, _spent: &[Zatoshis]) -> Self::Context {}

    fn split_plan(&self, _context: &Self::Context, _change_upper_bound: Zatoshis) -> SplitPlan {
        SplitPlan::SingleOutput
    }

    fn consolidation_plan(
        &self,
        _context: &Self::Context,
        _shape: &BundleShape,
        _economic_floor: Zatoshis,
    ) -> Option<ConsolidationPlan> {
        None
    }
}

/// A policy that never splits change and sweeps only within the bundle shape a payment with a
/// single change output could have had.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SingleOutputPolicy;

impl NoteManagementPolicy for SingleOutputPolicy {
    type Context = ();

    fn fetch<I: InputSource, P: consensus::Parameters>(
        &self,
        _source: &I,
        _params: &P,
        _account: I::AccountId,
        _target_height: TargetHeight,
        _exclude: &[I::NoteRef],
        _lock_filter: LockFilter<'_>,
    ) -> Result<Self::Context, I::Error> {
        Ok(())
    }

    fn without_spent(&self, _context: &Self::Context, _spent: &[Zatoshis]) -> Self::Context {}

    fn split_plan(&self, _context: &Self::Context, _change_upper_bound: Zatoshis) -> SplitPlan {
        SplitPlan::SingleOutput
    }

    fn consolidation_plan(
        &self,
        _context: &Self::Context,
        shape: &BundleShape,
        economic_floor: Zatoshis,
    ) -> Option<ConsolidationPlan> {
        Some(ConsolidationPlan::for_shape(
            shape,
            SINGLE_CHANGE_OUTPUT,
            None,
            economic_floor,
            SweepCaps::Unrestricted,
        ))
    }
}

/// A policy that maintains a static [`TargetDistribution`] in the most recent shielded pool.
///
/// Change is split into the rungs the account lacks, largest first, and a sweep takes only the
/// notes of buckets the account holds too many of.
///
/// The policy has no context when the store supplies no histogram, or supplies one over a ladder
/// other than the target's. It then behaves as [`SingleOutputPolicy`]: a single change output, and
/// a sweep into free and padding slots under unrestricted caps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LadderPolicy {
    target: TargetDistribution,
    max_actions: NonZeroUsize,
}

impl LadderPolicy {
    /// Constructs a policy that maintains `target` in bundles of at most `max_actions` padded
    /// actions.
    pub fn new(target: TargetDistribution, max_actions: NonZeroUsize) -> Self {
        Self {
            target,
            max_actions,
        }
    }

    /// The target this policy maintains.
    pub fn target(&self) -> &TargetDistribution {
        &self.target
    }

    /// The padded action count a sweep may grow the managed bundle to.
    ///
    /// A bundle already wider than the cap keeps its shape and its free slots. Five suits
    /// hardware-signed wallets.
    pub fn max_actions(&self) -> NonZeroUsize {
        self.max_actions
    }
}

impl NoteManagementPolicy for LadderPolicy {
    type Context = Option<NoteHistogram>;

    fn fetch<I: InputSource, P: consensus::Parameters>(
        &self,
        source: &I,
        params: &P,
        account: I::AccountId,
        target_height: TargetHeight,
        exclude: &[I::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<Self::Context, I::Error> {
        let histogram = source.get_note_histogram(
            account,
            most_recent_shielded_pool(params, target_height),
            self.target.ladder(),
            target_height,
            exclude,
            lock_filter,
        )?;
        // Counts over another ladder do not answer the question the target asks.
        Ok(histogram.filter(|histogram| histogram.ladder() == self.target.ladder()))
    }

    fn without_spent(&self, context: &Self::Context, spent: &[Zatoshis]) -> Self::Context {
        context
            .as_ref()
            .map(|histogram| histogram.without(spent.iter().copied()))
    }

    fn split_plan(&self, context: &Self::Context, change_upper_bound: Zatoshis) -> SplitPlan {
        let Some(histogram) = context else {
            return SplitPlan::SingleOutput;
        };
        let ladder = self.target.ladder();
        let deficits = self.target.deficits(histogram);
        let mut remaining = change_upper_bound;
        let mut pieces = Vec::new();
        for bucket in (1..ladder.bucket_count()).rev() {
            let Some(rung) = ladder.rung_value(bucket) else {
                continue;
            };
            for _ in 0..deficits[bucket] {
                match remaining - rung {
                    Some(rest) => {
                        pieces.push(rung);
                        remaining = rest;
                    }
                    // What the change cannot afford once it cannot afford again; a lower rung
                    // may still fit.
                    None => break,
                }
            }
        }
        SplitPlan::new(pieces)
    }

    fn consolidation_plan(
        &self,
        context: &Self::Context,
        shape: &BundleShape,
        economic_floor: Zatoshis,
    ) -> Option<ConsolidationPlan> {
        let Some(histogram) = context else {
            return SingleOutputPolicy.consolidation_plan(&(), shape, economic_floor);
        };
        Some(ConsolidationPlan::for_shape(
            shape,
            self.target.total(),
            Some(self.max_actions),
            economic_floor,
            SweepCaps::PerBucket(BucketCaps::for_surpluses(&self.target, histogram)),
        ))
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::{
        collection::{btree_set, vec},
        prelude::*,
    };
    use zcash_protocol::{value::Zatoshis, zip318::DENOM_CAP};

    use super::{NoteHistogram, TargetDistribution, ValueLadder};

    /// The widest note value these strategies generate: twice the ZIP 318 denomination cap, so
    /// that a ladder's unbounded top bucket is exercised. A caller composing its own values with
    /// [`arb_note_histogram`] should draw them from the same range.
    pub fn max_arb_value() -> u64 {
        2 * u64::from(DENOM_CAP)
    }

    /// A ladder of between one and `max_rungs` rungs; `max_rungs` of zero yields one rung.
    pub fn arb_value_ladder(max_rungs: usize) -> impl Strategy<Value = ValueLadder> {
        btree_set(1u64..=max_arb_value(), 1..=max_rungs.max(1)).prop_map(|rungs| {
            ValueLadder::new(rungs.into_iter().map(Zatoshis::const_from_u64))
                .expect("distinct ascending positive values are a valid ladder")
        })
    }

    /// A target over `ladder` asking for up to `max_count` notes in each bucket above bucket zero.
    pub fn arb_target_distribution(
        ladder: ValueLadder,
        max_count: usize,
    ) -> impl Strategy<Value = TargetDistribution> {
        let above_zero = ladder.bucket_count() - 1;
        vec(0usize..=max_count, above_zero).prop_map(move |counts| {
            TargetDistribution::new(ladder.clone(), core::iter::once(0).chain(counts))
                .expect("one count per bucket with bucket zero empty is a valid target")
        })
    }

    /// A histogram over `ladder` holding up to `max_notes` spendable and up to `max_notes` pending
    /// notes.
    pub fn arb_note_histogram(
        ladder: ValueLadder,
        max_notes: usize,
    ) -> impl Strategy<Value = NoteHistogram> {
        (
            vec(0u64..=max_arb_value(), 0..=max_notes),
            vec(0u64..=max_arb_value(), 0..=max_notes),
        )
            .prop_map(move |(spendable, pending)| {
                NoteHistogram::from_values(
                    ladder.clone(),
                    spendable.into_iter().map(Zatoshis::const_from_u64),
                    pending.into_iter().map(Zatoshis::const_from_u64),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroUsize;

    use proptest::prelude::*;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
    use zcash_protocol::{
        value::{COIN, Zatoshis},
        zip318::{DENOM_CAP, MAX_RESIDUAL_VALUE, is_canonical_denomination},
    };

    use super::{
        BucketCaps, BundleShape, ConsolidationBudget, LadderPolicy, NoteHistogram,
        NoteManagementError, NoteManagementPolicy, SingleOutputPolicy, SplitPlan, SweepCaps,
        TargetDistribution, Unmanaged, ValueLadder,
        testing::{arb_note_histogram, arb_target_distribution, arb_value_ladder, max_arb_value},
    };

    fn zat(v: u64) -> Zatoshis {
        Zatoshis::const_from_u64(v)
    }

    /// The `{1, 2, 5} * 10^k` values in `[MAX_RESIDUAL_VALUE, DENOM_CAP]`, enumerated
    /// independently of `ValueLadder::zip318`. The significands and the radix are spelled out
    /// here on purpose: reusing the implementation's constants would hide an error in them.
    fn canonical_denominations() -> Vec<Zatoshis> {
        let mut values = Vec::new();
        let mut decade = u64::from(MAX_RESIDUAL_VALUE);
        while decade <= u64::from(DENOM_CAP) {
            for significand in [1, 2, 5] {
                let value = decade * significand;
                if (u64::from(MAX_RESIDUAL_VALUE)..=u64::from(DENOM_CAP)).contains(&value) {
                    values.push(zat(value));
                }
            }
            decade *= 10;
        }
        values
    }

    #[test]
    fn zip318_ladder_runs_from_the_residual_bound_to_the_cap() {
        let ladder = ValueLadder::zip318();
        assert_eq!(ladder.rungs().first(), Some(&MAX_RESIDUAL_VALUE));
        assert_eq!(ladder.rungs().last(), Some(&DENOM_CAP));
        // The decades from 0.01 ZEC (10^6 zat) to 10,000 ZEC (10^12 zat) inclusive number seven,
        // each contributing three significands, less the two values above the cap (2 and 5 times
        // 10,000 ZEC).
        assert_eq!(ladder.rungs().len(), 7 * 3 - 2);
        assert!(ladder.rungs().contains(&zat(COIN)));
    }

    #[test]
    fn zip318_ladder_is_exactly_the_canonical_denominations() {
        let ladder = ValueLadder::zip318();
        for rung in ladder.rungs() {
            assert!(
                is_canonical_denomination(*rung),
                "rung {rung:?} is not a canonical ZIP 318 denomination"
            );
        }
        for denomination in canonical_denominations() {
            assert!(
                ladder.rungs().contains(&denomination),
                "denomination {denomination:?} is missing from the ladder"
            );
        }
    }

    #[test]
    fn ladder_rejects_unsorted_zero_or_empty_rungs() {
        assert!(ValueLadder::new([zat(5 * COIN), zat(2 * COIN)]).is_err());
        assert!(ValueLadder::new([zat(2 * COIN), zat(2 * COIN)]).is_err());
        assert!(ValueLadder::new([Zatoshis::ZERO, zat(2 * COIN)]).is_err());
        assert!(ValueLadder::new([]).is_err());
    }

    #[test]
    fn buckets_are_half_open_from_each_rung() {
        let ladder = ValueLadder::new([zat(COIN), zat(2 * COIN), zat(5 * COIN)]).unwrap();
        assert_eq!(ladder.bucket_count(), 4);
        assert_eq!(ladder.bucket_of(zat(COIN - 1)), 0);
        assert_eq!(ladder.bucket_of(zat(COIN)), 1);
        assert_eq!(ladder.bucket_of(zat(2 * COIN - 1)), 1);
        assert_eq!(ladder.bucket_of(zat(2 * COIN)), 2);
        assert_eq!(ladder.bucket_of(zat(5 * COIN)), 3);
        assert_eq!(ladder.bucket_of(zat(100 * COIN)), 3);
        assert_eq!(ladder.rung_value(0), None);
        assert_eq!(ladder.rung_value(2), Some(zat(2 * COIN)));
    }

    #[test]
    fn histogram_counts_spendable_and_pending_and_subtracts_spent() {
        let ladder = ValueLadder::new([zat(COIN), zat(2 * COIN)]).unwrap();
        let histogram = NoteHistogram::from_values(
            ladder,
            [
                zat(COIN / 2),
                zat(COIN),
                zat(3 * COIN / 2),
                zat(5 * COIN / 2),
            ],
            [zat(6 * COIN / 5)],
        );
        assert_eq!(histogram.spendable(0), 1);
        assert_eq!(histogram.spendable(1), 2);
        assert_eq!(histogram.pending(1), 1);
        assert_eq!(histogram.present(1), 3);
        assert_eq!(histogram.present(2), 1);

        let after = histogram.without([zat(3 * COIN / 2), zat(5 * COIN / 2), zat(5 * COIN / 2)]);
        assert_eq!(after.spendable(1), 1);
        assert_eq!(after.spendable(2), 0, "subtraction saturates at zero");
        assert_eq!(after.pending(1), 1, "pending notes are not subtracted");
        assert_eq!(after.ladder(), histogram.ladder());
    }

    #[test]
    fn deficits_and_surpluses_are_per_bucket() {
        let ladder = ValueLadder::new([zat(COIN), zat(2 * COIN)]).unwrap();
        let target = TargetDistribution::new(ladder.clone(), [0, 2, 1]).unwrap();
        let histogram = NoteHistogram::from_values(
            ladder,
            [
                zat(COIN / 2),
                zat(COIN / 2),
                zat(COIN),
                zat(5 * COIN / 2),
                zat(3 * COIN),
            ],
            [],
        );
        assert_eq!(target.deficits(&histogram), [0, 1, 0]);
        assert_eq!(target.surpluses(&histogram), [2, 0, 1]);
        assert_eq!(target.deficit_at(&histogram, 1), 1);
        assert_eq!(target.surplus_at(&histogram, 2), 1);
        assert_eq!(target.total(), 3);
    }

    #[test]
    fn target_rejects_bucket_zero_and_length_mismatch() {
        let ladder = ValueLadder::new([zat(COIN)]).unwrap();
        assert!(TargetDistribution::new(ladder.clone(), [1, 1]).is_err());
        assert!(TargetDistribution::new(ladder, [0, 1, 1]).is_err());
    }

    #[test]
    fn single_bucket_target_mirrors_a_split_policy() {
        let target =
            TargetDistribution::single_bucket(MAX_RESIDUAL_VALUE, NonZeroUsize::new(4).unwrap());
        assert_eq!(target.ladder().rungs(), &[MAX_RESIDUAL_VALUE]);
        assert_eq!(target.count(1), 4);
        assert_eq!(target.total(), 4);
    }

    #[test]
    fn single_bucket_raises_a_zero_minimum_to_one_zatoshi() {
        let target = TargetDistribution::single_bucket(Zatoshis::ZERO, NonZeroUsize::MIN);
        assert_eq!(target.ladder().rungs(), &[zat(1)]);

        // Every note of positive value lands in bucket 1, leaving bucket 0 empty.
        let histogram =
            NoteHistogram::from_values(target.ladder().clone(), [zat(1), zat(COIN)], []);
        assert_eq!(histogram.present(0), 0);
        assert_eq!(histogram.present(1), 2);
    }

    #[test]
    fn split_plan_orders_pieces_largest_first() {
        let plan = SplitPlan::new(vec![zat(COIN), zat(5 * COIN), zat(2 * COIN)]);
        assert_eq!(plan.max_outputs(), NonZeroUsize::new(3).unwrap());
        match &plan {
            SplitPlan::Pieces(pieces) => {
                assert_eq!(
                    pieces.iter().collect::<Vec<_>>(),
                    vec![zat(5 * COIN), zat(2 * COIN), zat(COIN)]
                );
                assert_eq!(pieces.largest(), zat(5 * COIN));
                assert_eq!(pieces.len(), NonZeroUsize::new(3).unwrap());
            }
            SplitPlan::SingleOutput => panic!("expected a plan with pieces"),
        }
        assert_eq!(SplitPlan::new(vec![]), SplitPlan::SingleOutput);
        assert_eq!(SplitPlan::SingleOutput.max_outputs(), NonZeroUsize::MIN);
    }

    /// The padded action count a sweep may grow a managed bundle to in these tests.
    const ACTION_CAP: NonZeroUsize = NonZeroUsize::new(5).unwrap();

    /// A target of one note in each of the buckets opened by the 1, 2 and 5 ZEC rungs.
    fn ladder_target() -> TargetDistribution {
        let ladder = ValueLadder::new([zat(COIN), zat(2 * COIN), zat(5 * COIN)]).unwrap();
        TargetDistribution::new(ladder, [0, 1, 1, 1]).unwrap()
    }

    #[test]
    fn split_plan_fills_deficits_from_the_top_rung_down() {
        let policy = LadderPolicy::new(ladder_target(), ACTION_CAP);
        // The wallet holds one note, in the bucket the 2 ZEC rung opens.
        let context = Some(NoteHistogram::from_values(
            policy.target().ladder().clone(),
            [zat(3 * COIN)],
            [],
        ));
        let plan = policy.split_plan(&context, zat(9 * COIN));
        assert_eq!(plan, SplitPlan::new(vec![zat(5 * COIN), zat(COIN)]));
    }

    #[test]
    fn split_plan_drops_pieces_the_change_cannot_afford() {
        let policy = LadderPolicy::new(ladder_target(), ACTION_CAP);
        let context = Some(NoteHistogram::empty(policy.target().ladder().clone()));
        // A 5 ZEC piece does not fit in 4 ZEC of change; the 2 and 1 ZEC pieces do.
        assert_eq!(
            policy.split_plan(&context, zat(4 * COIN)),
            SplitPlan::new(vec![zat(2 * COIN), zat(COIN)])
        );
        // Change below the lowest rung buys no piece at all.
        assert_eq!(
            policy.split_plan(&context, zat(COIN / 2)),
            SplitPlan::SingleOutput
        );
    }

    #[test]
    fn no_histogram_means_a_single_output_and_free_slots_only() {
        let policy = LadderPolicy::new(ladder_target(), ACTION_CAP);
        assert_eq!(
            policy.split_plan(&None, zat(9 * COIN)),
            SplitPlan::SingleOutput
        );
        let plan = policy
            .consolidation_plan(&None, &BundleShape::new(1, 1, 1, 0), MARGINAL_FEE)
            .unwrap();
        assert_eq!(
            plan.budget(),
            ConsolidationBudget::new(1, 0, MARGINAL_FEE, None)
        );
        assert_eq!(plan.envelope(), 2);
        assert_eq!(plan.sweep_caps(), &SweepCaps::Unrestricted);
    }

    #[test]
    fn consolidation_plan_caps_sweeps_at_each_bucket_surplus() {
        let policy = LadderPolicy::new(ladder_target(), ACTION_CAP);
        // Bucket 0 holds two notes, both surplus; bucket 1 holds three, two of them surplus;
        // bucket 2 holds exactly the note the target asks for; bucket 3 is empty.
        let context = Some(NoteHistogram::from_values(
            policy.target().ladder().clone(),
            [
                zat(COIN / 3),
                zat(COIN / 2),
                zat(COIN),
                zat(11 * COIN / 10),
                zat(12 * COIN / 10),
                zat(2 * COIN),
            ],
            [],
        ));
        let plan = policy
            .consolidation_plan(&context, &BundleShape::new(1, 1, 1, 0), MARGINAL_FEE)
            .unwrap();
        // One payment output plus the target's three notes of change.
        assert_eq!(plan.envelope(), 4);
        // Bucket 2 is the lowest bucket above bucket zero that is not in surplus, so its rung
        // bounds the candidates.
        assert_eq!(
            plan.budget(),
            ConsolidationBudget::new(1, 2, MARGINAL_FEE, Some(zat(2 * COIN)))
        );
        // Candidates are considered ascending; the third note of bucket 1 exhausts its surplus.
        assert_eq!(
            plan.sweep_caps().admit_all(&[
                zat(COIN / 3),
                zat(COIN / 2),
                zat(COIN),
                zat(11 * COIN / 10),
                zat(12 * COIN / 10),
            ]),
            [true, true, true, true, false]
        );
    }

    #[test]
    fn consolidation_plan_leaves_candidates_unbounded_when_every_bucket_is_in_surplus() {
        let policy = LadderPolicy::new(ladder_target(), ACTION_CAP);
        // Two notes in each bucket above bucket zero, against a target of one apiece.
        let context = Some(NoteHistogram::from_values(
            policy.target().ladder().clone(),
            [
                zat(COIN),
                zat(COIN),
                zat(2 * COIN),
                zat(2 * COIN),
                zat(5 * COIN),
                zat(5 * COIN),
            ],
            [],
        ));
        let plan = policy
            .consolidation_plan(&context, &BundleShape::new(1, 1, 1, 0), MARGINAL_FEE)
            .unwrap();
        assert_eq!(plan.budget().candidate_ceiling(), None);
        assert_eq!(plan.sweep_caps().ceiling(), None);
        // Each bucket gives up its one surplus note and no more.
        assert_eq!(
            plan.sweep_caps()
                .admit_all(&[zat(COIN), zat(COIN), zat(2 * COIN), zat(2 * COIN)]),
            [true, false, true, false]
        );
    }

    #[test]
    fn consolidation_plan_bounds_candidates_at_the_first_rung_held_at_target() {
        let policy = LadderPolicy::new(ladder_target(), ACTION_CAP);
        // Bucket 1 holds exactly the note the target asks for, so nothing at or above the first
        // rung may be swept, even though bucket 3 is in surplus.
        let context = Some(NoteHistogram::from_values(
            policy.target().ladder().clone(),
            [
                zat(COIN / 3),
                zat(COIN / 2),
                zat(COIN),
                zat(5 * COIN),
                zat(5 * COIN),
            ],
            [],
        ));
        let plan = policy
            .consolidation_plan(&context, &BundleShape::new(1, 1, 1, 0), MARGINAL_FEE)
            .unwrap();
        assert_eq!(plan.budget().candidate_ceiling(), Some(zat(COIN)));
        assert_eq!(
            plan.sweep_caps()
                .admit_all(&[zat(COIN / 3), zat(COIN / 2), zat(COIN), zat(5 * COIN)]),
            [true, true, false, false]
        );
    }

    #[test]
    fn consolidation_plan_holds_the_envelope_to_the_action_cap() {
        let ladder = ValueLadder::new([zat(COIN), zat(2 * COIN), zat(5 * COIN)]).unwrap();
        // Six notes of target plus the payment output ask for more actions than the cap allows.
        let target = TargetDistribution::new(ladder.clone(), [0, 3, 2, 1]).unwrap();
        let policy = LadderPolicy::new(target, ACTION_CAP);
        let context = Some(NoteHistogram::from_values(ladder, [zat(COIN / 2)], []));
        let plan = policy
            .consolidation_plan(&context, &BundleShape::new(1, 1, 1, 0), MARGINAL_FEE)
            .unwrap();
        assert_eq!(plan.envelope(), ACTION_CAP.get());
        // One free slot, and the cap leaves room for three more spends.
        assert_eq!(plan.budget().free_slots(), 1);
        assert_eq!(plan.budget().enlarging_slots(), 3);
    }

    #[test]
    fn a_bundle_wider_than_the_action_cap_keeps_its_shape_and_its_free_slots() {
        let policy = LadderPolicy::new(ladder_target(), ACTION_CAP);
        let context = Some(NoteHistogram::empty(policy.target().ladder().clone()));
        // Eight real outputs, well past the cap.
        let shape = BundleShape::new(1, 7, 1, 0);
        let plan = policy
            .consolidation_plan(&context, &shape, MARGINAL_FEE)
            .unwrap();
        assert_eq!(plan.envelope(), shape.padded_actions());
        // The eight outputs less the one spend the transaction already has.
        assert_eq!(plan.budget().free_slots(), 7);
        assert_eq!(plan.budget().enlarging_slots(), 0);
    }

    #[test]
    fn bucket_caps_require_one_cap_per_bucket_and_a_zero_suffix() {
        let ladder = ValueLadder::new([zat(COIN), zat(2 * COIN)]).unwrap();
        assert_eq!(
            BucketCaps::new(ladder.clone(), vec![0, 1]),
            Err(NoteManagementError::InvalidSweepCaps)
        );
        // A bucket capped above zero over a bucket capped at zero would put sweepable notes above
        // the ceiling.
        assert_eq!(
            BucketCaps::new(ladder.clone(), vec![0, 0, 5]),
            Err(NoteManagementError::InvalidSweepCaps)
        );
        assert!(BucketCaps::new(ladder, vec![0, 1, 2]).is_ok());
    }

    #[test]
    fn single_bucket_target_splits_change_into_the_notes_it_lacks() {
        let target = TargetDistribution::single_bucket(zat(COIN), NonZeroUsize::new(4).unwrap());
        let policy = LadderPolicy::new(target, ACTION_CAP);
        // Two of the four notes the target asks for are already held; the note below the rung is
        // not one of them.
        let context = Some(NoteHistogram::from_values(
            policy.target().ladder().clone(),
            [zat(COIN), zat(3 * COIN), zat(COIN / 2)],
            [],
        ));
        assert_eq!(
            policy.split_plan(&context, zat(10 * COIN)),
            SplitPlan::new(vec![zat(COIN), zat(COIN)])
        );
        // A wallet already at the target splits nothing.
        let at_target = Some(NoteHistogram::from_values(
            policy.target().ladder().clone(),
            [zat(COIN), zat(COIN), zat(COIN), zat(COIN)],
            [],
        ));
        assert_eq!(
            policy.split_plan(&at_target, zat(10 * COIN)),
            SplitPlan::SingleOutput
        );
    }

    #[test]
    fn unmanaged_policy_neither_splits_nor_sweeps() {
        let policy = Unmanaged;
        assert_eq!(
            policy.split_plan(&(), zat(9 * COIN)),
            SplitPlan::SingleOutput
        );
        assert_eq!(
            policy.consolidation_plan(&(), &BundleShape::new(1, 1, 1, 0), MARGINAL_FEE),
            None
        );
    }

    #[test]
    fn single_output_policy_never_splits_and_sweeps_only_within_the_costed_shape() {
        let policy = SingleOutputPolicy;
        assert_eq!(
            policy.split_plan(&(), zat(9 * COIN)),
            SplitPlan::SingleOutput
        );
        let plan = policy
            .consolidation_plan(&(), &BundleShape::new(1, 1, 1, 0), MARGINAL_FEE)
            .unwrap();
        assert_eq!(
            plan.budget(),
            ConsolidationBudget::new(1, 0, MARGINAL_FEE, None)
        );
        assert_eq!(plan.envelope(), 2);
        // A bundle whose only spare output is padding opens an enlarging slot, not a free one.
        let padded = policy
            .consolidation_plan(&(), &BundleShape::new(1, 1, 0, 1), MARGINAL_FEE)
            .unwrap();
        assert_eq!(
            padded.budget(),
            ConsolidationBudget::new(0, 1, MARGINAL_FEE, None)
        );
    }

    proptest! {
        /// `bucket_of` is monotone and agrees with the half-open rung intervals.
        #[test]
        fn bucket_of_is_monotone(
            ladder in arb_value_ladder(8),
            values in proptest::collection::vec(0u64..=max_arb_value(), 2..=64),
        ) {
            let mut sorted = values;
            sorted.sort_unstable();
            let buckets: Vec<usize> = sorted.iter().map(|v| ladder.bucket_of(zat(*v))).collect();
            prop_assert!(buckets.windows(2).all(|w| w[0] <= w[1]));
            for (v, b) in sorted.iter().zip(&buckets) {
                if let Some(rung) = ladder.rung_value(*b) {
                    prop_assert!(zat(*v) >= rung);
                }
                if let Some(next) = ladder.rung_value(*b + 1) {
                    prop_assert!(zat(*v) < next);
                }
            }
        }

        /// A ladder preserves the strictly ascending positive rungs it was built from.
        #[test]
        fn ladder_preserves_ascending_rungs(ladder in arb_value_ladder(12)) {
            let rungs: Vec<Zatoshis> = ladder.rungs().to_vec();
            prop_assert!(rungs[0].is_positive());
            prop_assert!(rungs.windows(2).all(|w| w[0] < w[1]));
            let rebuilt = ValueLadder::new(rungs.iter().copied()).unwrap();
            prop_assert_eq!(rebuilt.rungs(), &rungs[..]);
            prop_assert_eq!(rebuilt.bucket_count(), rungs.len() + 1);
        }

        /// Deficit and surplus are complementary and recover the target from the present count.
        #[test]
        fn deficit_and_surplus_are_complementary(
            (target, histogram) in arb_value_ladder(6).prop_flat_map(|ladder| {
                (
                    arb_target_distribution(ladder.clone(), 5),
                    arb_note_histogram(ladder, 20),
                )
            }),
        ) {
            let bucket_count = target.ladder().bucket_count();
            let deficits = target.deficits(&histogram);
            let surpluses = target.surpluses(&histogram);
            prop_assert_eq!(deficits.len(), bucket_count);
            prop_assert_eq!(surpluses.len(), bucket_count);
            for b in 0..bucket_count {
                prop_assert!(deficits[b] == 0 || surpluses[b] == 0);
                prop_assert_eq!(deficits[b], target.deficit_at(&histogram, b));
                prop_assert_eq!(surpluses[b], target.surplus_at(&histogram, b));
                prop_assert_eq!(
                    histogram.present(b) + deficits[b] - surpluses[b],
                    target.count(b)
                );
            }
        }

        /// Spending leaves pending counts alone and only lowers spendable counts, by at most the
        /// number of notes spent.
        #[test]
        fn without_saturates_and_leaves_pending_alone(
            (histogram, spent) in arb_value_ladder(6).prop_flat_map(|ladder| {
                (
                    arb_note_histogram(ladder, 12),
                    proptest::collection::vec(0u64..=max_arb_value(), 0..=12),
                )
            }),
        ) {
            let after = histogram.without(spent.iter().copied().map(zat));
            prop_assert_eq!(after.ladder(), histogram.ladder());
            let mut removed = 0;
            for b in 0..histogram.bucket_count() {
                prop_assert_eq!(after.pending(b), histogram.pending(b));
                prop_assert!(after.spendable(b) <= histogram.spendable(b));
                removed += histogram.spendable(b) - after.spendable(b);
            }
            prop_assert!(removed <= spent.len());
        }

        /// A split plan is `SingleOutput` exactly when it was given no pieces, and otherwise holds
        /// a descending permutation of them.
        #[test]
        fn split_plan_is_a_descending_permutation(
            values in proptest::collection::vec(0u64..=max_arb_value(), 0..=16),
        ) {
            let pieces: Vec<Zatoshis> = values.iter().copied().map(zat).collect();
            let plan = SplitPlan::new(pieces.clone());
            match &plan {
                SplitPlan::SingleOutput => {
                    prop_assert!(pieces.is_empty());
                    prop_assert_eq!(plan.max_outputs(), NonZeroUsize::MIN);
                }
                SplitPlan::Pieces(planned) => {
                    prop_assert!(!pieces.is_empty());
                    prop_assert_eq!(plan.max_outputs().get(), pieces.len());
                    prop_assert_eq!(planned.len(), plan.max_outputs());
                    let mut descending = pieces;
                    descending.sort_unstable_by(|a, b| b.cmp(a));
                    prop_assert_eq!(planned.largest(), descending[0]);
                    prop_assert_eq!(planned.iter().collect::<Vec<_>>(), descending);
                }
            }
        }

        /// Split pieces are rung values of deficit buckets, largest first, never more numerous
        /// than the target asks for, and never worth more than the change bound.
        #[test]
        fn split_plan_respects_deficits_and_affordability(
            counts in proptest::collection::vec(0usize..=3, 3..=5),
            spendable in proptest::collection::vec(0u64..=6 * COIN, 0..=8),
            change in 0u64..=20 * COIN,
        ) {
            // A ladder of `counts.len() - 1` rungs has exactly `counts.len()` buckets.
            let ladder = ValueLadder::new(
                (1..counts.len()).map(|i| zat(i as u64 * COIN))
            ).unwrap();
            let mut counts = counts;
            counts[0] = 0;
            let target = TargetDistribution::new(ladder.clone(), counts).unwrap();
            let histogram = NoteHistogram::from_values(
                ladder.clone(),
                spendable.iter().copied().map(zat),
                [],
            );
            let deficits = target.deficits(&histogram);
            let plan = LadderPolicy::new(target.clone(), ACTION_CAP).split_plan(&Some(histogram), zat(change));
            let pieces: Vec<Zatoshis> = match &plan {
                SplitPlan::SingleOutput => vec![],
                SplitPlan::Pieces(pieces) => pieces.iter().collect(),
            };
            let total: u64 = pieces.iter().copied().map(u64::from).sum();
            prop_assert!(total <= change);
            prop_assert!(pieces.len() <= target.total());
            prop_assert!(pieces.windows(2).all(|w| w[0] >= w[1]));
            let mut used = vec![0usize; ladder.bucket_count()];
            for piece in &pieces {
                let bucket = ladder.bucket_of(*piece);
                prop_assert_eq!(ladder.rung_value(bucket), Some(*piece), "pieces are rung values");
                used[bucket] += 1;
            }
            for bucket in 0..ladder.bucket_count() {
                prop_assert!(used[bucket] <= deficits[bucket]);
            }
        }

        /// A sweep admitted by the caps never takes a bucket below its target.
        #[test]
        fn sweep_caps_never_breach_the_target(
            counts in proptest::collection::vec(0usize..=3, 3..=5),
            spendable in proptest::collection::vec(0u64..=6 * COIN, 0..=12),
        ) {
            let ladder = ValueLadder::new(
                (1..counts.len()).map(|i| zat(i as u64 * COIN))
            ).unwrap();
            let mut counts = counts;
            counts[0] = 0;
            let target = TargetDistribution::new(ladder.clone(), counts.clone()).unwrap();
            let mut values: Vec<Zatoshis> = spendable.iter().copied().map(zat).collect();
            values.sort_unstable();
            let histogram = NoteHistogram::from_values(ladder.clone(), values.iter().copied(), []);
            let plan = LadderPolicy::new(target, ACTION_CAP)
                .consolidation_plan(
                    &Some(histogram.clone()),
                    &BundleShape::new(1, 1, 1, 0),
                    MARGINAL_FEE,
                )
                .unwrap();
            let admitted = plan.sweep_caps().admit_all(&values);
            let swept: Vec<Zatoshis> = values
                .iter()
                .zip(&admitted)
                .filter(|(_, admitted)| **admitted)
                .map(|(value, _)| *value)
                .collect();
            if let Some(ceiling) = plan.budget().candidate_ceiling() {
                prop_assert!(swept.iter().all(|value| *value < ceiling));
            }
            let after = histogram.without(swept.iter().copied());
            for (bucket, target_count) in counts.iter().enumerate().skip(1) {
                prop_assert!(
                    after.present(bucket) >= (*target_count).min(histogram.present(bucket))
                );
            }
        }
    }
}
