//! Note management: maintaining a target distribution of note values in the most recent
//! shielded pool.
//!
//! A [`ValueLadder`] partitions note values into buckets. A [`TargetDistribution`] assigns a
//! target count to each bucket, and a [`NoteHistogram`] records how many notes an account holds
//! in each. A `NoteManagementPolicy` turns the difference between the two into a [`SplitPlan`]
//! for a transaction's change and a `ConsolidationPlan` for the small notes it may sweep.

use core::{fmt, num::NonZeroUsize};

use nonempty::NonEmpty;
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, NetworkUpgrade},
    value::Zatoshis,
    zip318::{DENOM_CAP, MAX_RESIDUAL_VALUE},
};

use crate::data_api::wallet::TargetHeight;

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
    use zcash_protocol::{
        value::{COIN, Zatoshis},
        zip318::{DENOM_CAP, MAX_RESIDUAL_VALUE, is_canonical_denomination},
    };

    use super::{
        NoteHistogram, SplitPlan, TargetDistribution, ValueLadder,
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
    }
}
