//! Protocol parameters for [ZIP 318] pool migration: the canonical denomination series that
//! pool-crossing values are drawn from, the anchor bucket grid that crossings are proved against,
//! and the constants that shape and space the transactions carrying them.
//!
//! Privacy under ZIP 318 rests on *value collision*: every crossing amount is drawn from a small,
//! shared `{1, 2, 5} * 10^k` denomination set, so many unrelated wallets emit identical values that
//! cannot be attributed to any one of them. It explicitly does not rest on unpredictability — a
//! random or high-entropy amount would collide with nothing and become a near-unique fingerprint,
//! which is why the ZIP rejects arbitrary sizing.
//!
//! [`PoolMigrationConstants`] carries these as overridable parameters rather than as bare constants,
//! so that a test network can shorten the grid; see its documentation for why it is unsealed.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use core::{num::NonZeroU32, ops::ControlFlow, time::Duration};

use crate::consensus::{
    BlockHeight, NU7_POW_TARGET_SPACING_RATIO, POST_BLOSSOM_POW_TARGET_SPACING,
    POST_NU7_POW_TARGET_SPACING, POW_TARGET_SPACING_CHANGES, Parameters, PowTargetSpacingChange,
    pow_target_spacing_schedule, sum_of_spacings,
};
use crate::value::{COIN, Zatoshis};

/// The base of the denomination scale: every denomination is a multiple of a power of this radix.
const DENOMINATION_RADIX: u64 = 10;

/// The significand multipliers of the `{1, 2, 5} * 10^k` series, descending (largest first).
const ONE_TWO_FIVE_DESCENDING: [u64; 3] = [5, 2, 1];

/// The largest denomination [ZIP 318] gives a single pool crossing (the ZIP's `DENOM_CAP`): 10,000
/// ZEC, itself a `{1, 2, 5} * 10^k` value.
///
/// Capping the top denomination keeps even a very large holder's crossings within the shared
/// denomination set, so that no single crossing is a near-unique fingerprint; a balance beyond one
/// denomination's worth crosses as several bounded amounts instead.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const DENOM_CAP: Zatoshis = Zatoshis::const_from_u64(10_000 * COIN);

/// The smallest denomination [ZIP 318] admits (the ZIP's `MAX_RESIDUAL_VALUE`): 0.01 ZEC.
///
/// A leftover balance below this is never crossed; it stays in the source pool, since crossing a
/// distinctive dust amount would deanonymise the wallet holding it.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const MAX_RESIDUAL_VALUE: Zatoshis = Zatoshis::const_from_u64(COIN / 100);

/// The exact number of Orchard actions in every [ZIP 318] note-preparation transaction: each is
/// padded up to this count, so that no preparation transaction is distinguishable from another by
/// its action count, and one transaction handles at most this many notes in total (spends plus
/// outputs).
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const PREP_TX_ACTIONS: usize = 16;

/// The mean of the [ZIP 318] preparation inter-arrival delay distribution, in blocks: 16, about
/// twenty minutes at the 75-second target block spacing.
///
/// Preparation transactions are fully shielded self-sends: they need temporal decoupling from one
/// another (a burst of identically shaped transactions from one wallet is a linkable cluster), but
/// no anchor bucketing — only the pool-crossing transfers anchor to boundaries — so they are spaced
/// much more tightly than the transfers.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const PREP_DELAY_MEAN: NonZeroU32 = NonZeroU32::new(16).expect("16 is nonzero");

/// The inclusive cap on a single [ZIP 318] preparation delay draw, in blocks: 96, about two hours.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const PREP_DELAY_CAP: NonZeroU32 = NonZeroU32::new(96).expect("96 is nonzero");

/// The ratio a [ZIP 318] delay distribution's cap bears to its mean: a draw more than four times the
/// mean is discarded and redrawn, truncating the exponential's heavy tail so that nothing is starved
/// for an unbounded time.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[deprecated(note = "DO NOT USE; 
`zcash_protocol::zip318::DELAY_CAP_RATIO`. ZIP 318 no longer relates each
delay cap to its mean by a shared ratio; use `TRANSFER_DELAY_CAP` and
`PREP_DELAY_CAP` directly.")]
pub const DELAY_CAP_RATIO: NonZeroU32 = NonZeroU32::new(4).expect("4 is nonzero");

/// The mean of the [ZIP 318] transfer inter-arrival delay distribution, in blocks: 66, about ninety
/// minutes at the 75-second target block spacing.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const TRANSFER_DELAY_MEAN: NonZeroU32 = NonZeroU32::new(66).expect("66 is nonzero");

/// The inclusive cap on a single [ZIP 318] transfer delay draw, in blocks: 576, about twelve hours.
///
/// At more than eight mean delays, the cap preserves nearly all of the exponential's variance;
/// discarding and redrawing above it removes only the far tail, so that nothing is starved for an
/// unbounded time.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const TRANSFER_DELAY_CAP: NonZeroU32 = NonZeroU32::new(576).expect("576 is nonzero");

/// Maximum anchor AGE, in boundaries, that a recency-weighted anchor draw will accept.
///
/// Age `a` counts boundaries strictly before the most recent boundary observed at proving time; a
/// draw exceeding this cap (a very old anchor) is discarded and redrawn. This bounds how stale a
/// proof's anchor can be — 4 boundaries is about twelve hours.
pub const ANCHOR_AGE_CAP: u32 = 4;

/// Block-height modulus of the canonical rolling EXPIRY window, in blocks. 34,560 blocks is about 30
/// days at the target block spacing. An expiry height is anchored to the most recent multiple of
/// this modulus, plus [`EXPIRY_WINDOW`].
pub const EXPIRY_MODULUS: u32 = 34_560;

/// Width of the rolling expiry window added past the anchoring modulus, in blocks: two expiry moduli
/// (about 60 days), so that every transfer, whenever in the current modulus period it is scheduled,
/// keeps between one and two [`EXPIRY_MODULUS`] periods of validity.
pub const EXPIRY_WINDOW: u32 = 2 * EXPIRY_MODULUS;

/// Source-pool (Orchard) actions in a canonical [ZIP 318] pool crossing: the spend and its change,
/// or a padding dummy when the note's value exactly covers the crossing and its fee.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const CROSSING_SOURCE_ACTIONS: usize = 2;

/// Destination-pool (Ironwood) actions in a canonical [ZIP 318] pool crossing: the single
/// canonical output, unpadded.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const CROSSING_DESTINATION_ACTIONS: usize = 1;

/// Returns the largest `{1, 2, 5} * 10^k` value (a multiple of the power-of-radix `floor`) not
/// exceeding `hi`, or `0` if `hi < floor`.
///
/// `floor` must be a power of the radix. This works in whatever unit `hi` and `floor` share (here,
/// zatoshi), so it can yield sub-1-ZEC denominations down to `floor`.
pub fn largest_one_two_five(hi: u64, floor: u64) -> u64 {
    if hi < floor {
        return 0;
    }
    // Largest power of the radix, at least `floor`, not exceeding `hi`.
    let mut pow = floor;
    while pow.checked_mul(DENOMINATION_RADIX).is_some_and(|p| p <= hi) {
        pow *= DENOMINATION_RADIX;
    }
    // Prefer the largest significand multiple of that power that still fits.
    for multiple in ONE_TWO_FIVE_DESCENDING {
        if let Some(v) = pow.checked_mul(multiple)
            && v <= hi
        {
            return v;
        }
    }
    pow
}

/// Returns whether `value` lies on the `{1, 2, 5} * 10^k` series and within `[min, max]`.
///
/// Shared by the free function [`is_canonical_denomination`] and by
/// [`PoolMigrationConstants::is_canonical_denomination`], which differ only in where the bounds come
/// from.
fn is_canonical_within(value: Zatoshis, min: Zatoshis, max: Zatoshis) -> bool {
    if value < min || value > max {
        return false;
    }
    let mut n = u64::from(value);
    // A zero value is excluded by the `min` bound above, every admissible bound being positive.
    while n.is_multiple_of(DENOMINATION_RADIX) {
        n /= DENOMINATION_RADIX;
    }
    ONE_TWO_FIVE_DESCENDING.contains(&n)
}

/// Returns whether `value` is a canonical [ZIP 318] crossing denomination: a `{1, 2, 5} * 10^k`
/// zatoshi amount lying within `[MAX_RESIDUAL_VALUE, DENOM_CAP]`.
///
/// The range bound is load-bearing. `5` zatoshi lies on the `{1, 2, 5} * 10^k` series, but no
/// migration ever emits it, so a crossing of that amount would join no anonymity set. Only the
/// values a migration can actually produce are canonical.
///
/// Callers that have network parameters to hand should prefer
/// [`PoolMigrationConstants::is_canonical_denomination`], which respects overridden bounds.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub fn is_canonical_denomination(value: Zatoshis) -> bool {
    is_canonical_within(value, MAX_RESIDUAL_VALUE, DENOM_CAP)
}

/// The canonical rolling EXPIRY height for a transaction targeting `target_height` ([ZIP 318]'s
/// EXPIRY MUST): the most recent multiple of the expiry modulus at or below `target_height`, plus
/// twice the modulus.
///
/// The modulus is [`EXPIRY_MODULUS`] reference blocks, converted to blocks by `spacing` at
/// `target_height`: 34,560 blocks before NU7 activation and 103,680 blocks from activation, both
/// about 30 days.
///
/// This is a pure function of the height, so it reveals nothing per-wallet: every transaction in the
/// same modulus period shares one expiry, whereas an ordinary per-transaction expiry would single a
/// pool crossing out immediately. The result is always strictly greater than `target_height`, and
/// leaves between one and two moduli of remaining validity. Saturates at `u32::MAX`.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub fn expiry_height(spacing: &BlockSpacing, target_height: BlockHeight) -> BlockHeight {
    rolling_expiry(spacing, EXPIRY_MODULUS, EXPIRY_WINDOW, target_height)
}

/// The rolling expiry for `reference`, with `modulus` and `window` given in reference blocks and
/// scaled by `spacing` at `reference`. Saturates at `u32::MAX`.
fn rolling_expiry(
    spacing: &BlockSpacing,
    modulus: u32,
    window: u32,
    reference: BlockHeight,
) -> BlockHeight {
    let ratio = u64::from(spacing.blocks_per_reference_block(reference));
    let h = u64::from(u32::from(reference));
    let modulus = u64::from(modulus) * ratio;
    let expiry = h - (h % modulus) + u64::from(window) * ratio;
    BlockHeight::from_u32(u32::try_from(expiry).unwrap_or(u32::MAX))
}

/// The target spacing of a [ZIP 318] reference block: 75 seconds, the target spacing from Blossom
/// activation until NU7 activation.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const REFERENCE_BLOCK_SPACING: Duration = POST_BLOSSOM_POW_TARGET_SPACING;

/// [`REFERENCE_BLOCK_SPACING`] in whole seconds, the unit of a [`BlockSpacing`]'s time coordinate.
const REFERENCE_BLOCK_SECS: u64 = REFERENCE_BLOCK_SPACING.as_secs();

/// Returns the number of blocks at the target spacing `spacing` that one reference block spans, or
/// `None` unless `spacing` is a whole number of seconds that divides [`REFERENCE_BLOCK_SPACING`].
const fn blocks_per_reference_block_at(spacing: Duration) -> Option<NonZeroU32> {
    let secs = spacing.as_secs();
    if spacing.subsec_nanos() != 0 || secs == 0 || !REFERENCE_BLOCK_SECS.is_multiple_of(secs) {
        return None;
    }
    let ratio = REFERENCE_BLOCK_SECS / secs;
    if ratio > u32::MAX as u64 {
        return None;
    }
    NonZeroU32::new(ratio as u32)
}

/// Returns whether every spacing in `changes` spans a whole number of blocks per reference block.
const fn spacings_divide_the_reference_spacing(changes: &[PowTargetSpacingChange]) -> bool {
    let mut i = 0;
    while i < changes.len() {
        if blocks_per_reference_block_at(changes[i].spacing).is_none() {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    spacings_divide_the_reference_spacing(&POW_TARGET_SPACING_CHANGES),
    "every consensus target spacing must divide the ZIP 318 reference block spacing"
);

/// The number of blocks one reference block spans at the reference spacing.
const ONE_BLOCK_PER_REFERENCE_BLOCK: NonZeroU32 = NonZeroU32::MIN;

/// The number of blocks one reference block spans from NU7 activation.
const NU7_BLOCKS_PER_REFERENCE_BLOCK: NonZeroU32 =
    match blocks_per_reference_block_at(POST_NU7_POW_TARGET_SPACING) {
        Some(ratio) => ratio,
        None => panic!("the NU7 target spacing divides the reference block spacing"),
    };

const _: () = assert!(
    NU7_BLOCKS_PER_REFERENCE_BLOCK.get() == NU7_POW_TARGET_SPACING_RATIO,
    "the NU7 spacing ratio relates the reference and post-NU7 target spacings"
);

/// The largest number of segments a [`BlockSpacing`] holds: one per change of the consensus
/// target spacing.
const MAX_SPACING_SEGMENTS: usize = POW_TARGET_SPACING_CHANGES.len();

/// A run of heights, from `start` until the next segment, over which one reference block spans
/// `blocks_per_reference_block` blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpacingSegment {
    start: BlockHeight,
    blocks_per_reference_block: NonZeroU32,
}

impl SpacingSegment {
    /// The target spacing of each block in this segment, in seconds.
    fn block_secs(&self) -> u64 {
        REFERENCE_BLOCK_SECS / u64::from(self.blocks_per_reference_block.get())
    }
}

/// The maximal run of heights containing a given height over which the target spacing is
/// constant.
struct SpacingRun {
    /// The first height of the run.
    start: u64,
    /// The first height after the run, or `None` if the run extends past every height.
    end: Option<u64>,
    /// The number of blocks one reference block spans in the run.
    blocks_per_reference_block: NonZeroU32,
}

/// The block spacing of a chain, for converting [ZIP 318] durations into block heights.
///
/// ZIP 318 states each duration as a number of REFERENCE BLOCKS: blocks at the
/// [`REFERENCE_BLOCK_SPACING`] of 75 seconds. A `BlockSpacing` maps heights to times
/// piecewise-linearly, with one segment per change of the target block spacing. Within a segment a
/// reference block spans [`blocks_per_reference_block`](Self::blocks_per_reference_block) blocks,
/// and a duration that crosses a change keeps its exact length, each part counting the blocks of
/// its own segment.
///
/// Every height a `BlockSpacing` takes or returns is a TARGET height: the first height at which a
/// transaction can be mined. [ZIP 208] and [ZIP 218] give the block at height `h` the target
/// spacing [`pow_target_spacing`] at `h`, so the time from target height `h` to target height
/// `h + 1` is the time to mine block `h`, the target spacing at `h`. The time from target height
/// `from` to target height `to` is therefore
/// [`target_time_between`]`(from - 1, to - 1)`, the time to mine the blocks `from..to`, at every
/// height from Blossom activation on. Every height before Blossom activation is treated as having
/// the reference spacing instead; ZIP 318 never measures a duration across those heights, and
/// treating them so keeps every reference block a whole number of blocks.
///
/// [`pow_target_spacing`]: crate::consensus::pow_target_spacing
/// [`target_time_between`]: crate::consensus::target_time_between
/// [ZIP 208]: https://zips.z.cash/zip-0208
/// [ZIP 218]: https://zips.z.cash/zip-0218
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSpacing {
    /// The segments in order of height, as a prefix of `Some` entries. Their starts strictly
    /// increase, and each segment's spacing differs from the spacing before it (the reference
    /// spacing, for the first), so that equal mappings have equal representations.
    segments: [Option<SpacingSegment>; MAX_SPACING_SEGMENTS],
}

impl BlockSpacing {
    /// The spacing of a chain on which the target spacing never changes from the reference spacing:
    /// one block per reference block at every height.
    pub const UNIFORM: Self = Self {
        segments: [None; MAX_SPACING_SEGMENTS],
    };

    /// The spacing of the chain that `params` describe, following every change of the target
    /// spacing that activates on it.
    pub fn for_network<P: Parameters>(params: &P) -> Self {
        Self::from_schedule(pow_target_spacing_schedule(
            params,
            &POW_TARGET_SPACING_CHANGES,
        ))
        .expect(
            "the consensus schedule has `MAX_SPACING_SEGMENTS` changes, each dividing the \
             reference spacing",
        )
    }

    /// The spacing of a chain on which NU7 activates at `nu7_activation` and the target spacing
    /// changes nowhere else.
    pub const fn with_nu7_activation(nu7_activation: BlockHeight) -> Self {
        let mut segments = [None; MAX_SPACING_SEGMENTS];
        segments[0] = Some(SpacingSegment {
            start: nu7_activation,
            blocks_per_reference_block: NU7_BLOCKS_PER_REFERENCE_BLOCK,
        });
        Self { segments }
    }

    /// The NU7 activation height of this chain, or `None` if NU7 does not activate on it.
    ///
    /// This is the height at which the target spacing first changes after Blossom, a change that
    /// NU7 makes.
    #[deprecated(
        since = "0.12.0",
        note = "Use `Parameters::activation_height(NetworkUpgrade::Nu7)` instead."
    )]
    pub fn nu7_activation(&self) -> Option<BlockHeight> {
        self.segments().next().map(|segment| segment.start)
    }

    /// The spacing of the chain `params` describe under the spacing changes `changes` in place of
    /// the consensus ones, or `None` if it does not fit in a `BlockSpacing`.
    #[cfg(all(test, feature = "local-consensus"))]
    fn with_changes<P: Parameters>(params: &P, changes: &[PowTargetSpacingChange]) -> Option<Self> {
        Self::from_schedule(pow_target_spacing_schedule(params, changes))
    }

    /// Builds the spacing whose segments start at the given heights with the given target
    /// spacings, in order of non-decreasing height. Returns `None` if a spacing does not divide
    /// [`REFERENCE_BLOCK_SPACING`], or if more than [`MAX_SPACING_SEGMENTS`] segments remain once
    /// changes that leave the spacing unchanged, or are superseded at the same height, are removed.
    fn from_schedule(schedule: impl IntoIterator<Item = (BlockHeight, Duration)>) -> Option<Self> {
        let mut segments: [Option<SpacingSegment>; MAX_SPACING_SEGMENTS] =
            [None; MAX_SPACING_SEGMENTS];
        let mut len: usize = 0;
        for (start, spacing) in schedule {
            let blocks_per_reference_block = blocks_per_reference_block_at(spacing)?;
            // A change at the same height as the previous one supersedes it.
            if let Some(last) = len.checked_sub(1)
                && segments[last].is_some_and(|segment| segment.start == start)
            {
                segments[last] = None;
                len = last;
            }
            let prior = len
                .checked_sub(1)
                .and_then(|last| segments[last])
                .map_or(ONE_BLOCK_PER_REFERENCE_BLOCK, |segment| {
                    segment.blocks_per_reference_block
                });
            if blocks_per_reference_block != prior {
                *segments.get_mut(len)? = Some(SpacingSegment {
                    start,
                    blocks_per_reference_block,
                });
                len += 1;
            }
        }
        Some(Self { segments })
    }

    /// The segments of this spacing, in order of height.
    fn segments(&self) -> impl Iterator<Item = SpacingSegment> + '_ {
        self.segments.iter().map_while(|segment| *segment)
    }

    /// The run of heights containing `height` over which the spacing is constant.
    fn run_containing(&self, height: u64) -> SpacingRun {
        let current = self
            .segments()
            .take_while(|segment| u64::from(segment.start) <= height)
            .last();
        SpacingRun {
            start: current.map_or(0, |segment| u64::from(segment.start)),
            end: self
                .segments()
                .map(|segment| u64::from(segment.start))
                .find(|start| *start > height),
            blocks_per_reference_block: current.map_or(ONE_BLOCK_PER_REFERENCE_BLOCK, |segment| {
                segment.blocks_per_reference_block
            }),
        }
    }

    /// The number of blocks that one reference block spans at `height`: the reference spacing
    /// divided by the target spacing there. On a chain where NU7 is the only change of the target
    /// spacing after Blossom, this is 1 before NU7 activation and [`NU7_POW_TARGET_SPACING_RATIO`]
    /// from activation.
    pub fn blocks_per_reference_block(&self, height: BlockHeight) -> u32 {
        self.run_containing(u64::from(height))
            .blocks_per_reference_block
            .get()
    }

    /// Returns the least height whose time after `from` is at least `reference_blocks` reference
    /// blocks. Saturates at `u32::MAX`.
    ///
    /// The result is exactly that long after `from` unless the duration ends in a segment whose
    /// target spacing does not divide that of every earlier segment it crosses, in which case it
    /// rounds up to the next height. Successive advances therefore compose,
    /// `advance(advance(h, a), b) == advance(h, a + b)`, on every chain on which each target
    /// spacing divides every earlier one, as the consensus spacings do.
    pub fn advance(&self, from: BlockHeight, reference_blocks: u32) -> BlockHeight {
        self.height_at(self.time_of(from) + u64::from(reference_blocks) * REFERENCE_BLOCK_SECS)
    }

    /// Returns the least height whose time after `height` is at least the time from `from` to
    /// `to`, or `height` when `to` is not after `from`. Saturates at `u32::MAX`.
    ///
    /// The result rounds up to the next height when no height is exactly that long after
    /// `height`. That can happen even where each target spacing divides every earlier one,
    /// because the time from `from` to `to` need not be a whole number of blocks at the spacing
    /// of an earlier height. Where NU7 activates at height 10, for example, the time from height
    /// 10 to height 11 is 25 seconds, and `shift(0, 10, 11)` is height 1, which is 75 seconds
    /// after height 0. On a chain on which each target spacing divides every earlier one, the
    /// result is exact whenever `height` is not below `from`.
    pub fn shift(&self, height: BlockHeight, from: BlockHeight, to: BlockHeight) -> BlockHeight {
        let elapsed = self.time_of(to).saturating_sub(self.time_of(from));
        self.height_at(self.time_of(height) + elapsed)
    }

    /// Returns whether the time from `from` to `to` is more than `reference_blocks` reference
    /// blocks.
    ///
    /// `exceeds(from, advance(from, d), d)` is `false` whenever [`advance`](Self::advance) lands
    /// exactly, which it does on every chain on which each target spacing divides every earlier
    /// one; where it rounds up, the advanced height lies strictly more than `d` reference blocks
    /// after `from`.
    pub fn exceeds(&self, from: BlockHeight, to: BlockHeight, reference_blocks: u32) -> bool {
        self.time_of(to).saturating_sub(self.time_of(from))
            > u64::from(reference_blocks) * REFERENCE_BLOCK_SECS
    }

    /// The time at which target height `height` is reached, in seconds from the genesis block:
    /// the sum of the target spacings of the blocks at the heights below `height`.
    fn time_of(&self, height: BlockHeight) -> u64 {
        sum_of_spacings(
            REFERENCE_BLOCK_SPACING,
            self.segments()
                .map(|segment| (segment.start, Duration::from_secs(segment.block_secs()))),
            0,
            u64::from(height),
        )
        .as_secs()
    }

    /// The least height reached at or after `time`, in seconds from the genesis block. Saturates
    /// at `u32::MAX`.
    fn height_at(&self, time: u64) -> BlockHeight {
        // The run in which `time` is reached: its first height, the time of that height, and the
        // spacing of its blocks in seconds.
        let (ControlFlow::Break((run_start, run_time, block_secs))
        | ControlFlow::Continue((run_start, run_time, block_secs))) = self.segments().try_fold(
            (0u64, 0u64, REFERENCE_BLOCK_SECS),
            |(run_start, run_time, block_secs), segment| {
                let start = u64::from(segment.start);
                let end_time = run_time + start.saturating_sub(run_start) * block_secs;
                if time <= end_time {
                    ControlFlow::Break((run_start, run_time, block_secs))
                } else {
                    ControlFlow::Continue((start, end_time, segment.block_secs()))
                }
            },
        );
        let h = run_start + time.saturating_sub(run_time).div_ceil(block_secs);
        BlockHeight::from_u32(u32::try_from(h).unwrap_or(u32::MAX))
    }
}

/// The boundary heights of an [`AnchorBucketInterval`] on a chain with a given [`BlockSpacing`].
///
/// The interval is a number of reference blocks. A height is a boundary when it is a multiple of
/// the interval times the [`BlockSpacing::blocks_per_reference_block`] at that height, which keeps
/// the boundaries within each segment of the spacing the same time apart. Every boundary is
/// therefore also a multiple of the interval, so a wallet that retains the checkpoint at every
/// multiple of the interval retains every boundary.
///
/// On a chain where NU7 is the only change of the target spacing after Blossom, a height before
/// NU7 activation is a boundary when it is a multiple of the interval, and a height from
/// activation is a boundary when it is a multiple of the interval times
/// [`NU7_POW_TARGET_SPACING_RATIO`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorGrid {
    interval: AnchorBucketInterval,
    spacing: BlockSpacing,
}

impl AnchorGrid {
    /// The grid of `interval` on a chain with the given `spacing`.
    pub const fn new(interval: AnchorBucketInterval, spacing: BlockSpacing) -> Self {
        Self { interval, spacing }
    }

    /// The interval, in reference blocks, between successive boundaries.
    pub fn interval(&self) -> AnchorBucketInterval {
        self.interval
    }

    /// The block spacing of the chain this grid lies on.
    pub fn spacing(&self) -> BlockSpacing {
        self.spacing
    }

    /// The distance in blocks between successive boundaries within `run`.
    fn step_in(&self, run: &SpacingRun) -> u64 {
        u64::from(self.interval.block_count().get())
            * u64::from(run.blocks_per_reference_block.get())
    }

    /// Returns whether `height` is a boundary of this grid, i.e. whether the checkpoint at
    /// `height` is retained as a durable anchor.
    pub fn is_boundary(&self, height: BlockHeight) -> bool {
        let h = u64::from(height);
        h.is_multiple_of(self.step_in(&self.spacing.run_containing(h)))
    }

    /// Returns the greatest boundary height that does not exceed `height`.
    pub fn boundary_at_or_below(&self, height: BlockHeight) -> BlockHeight {
        let mut h = u64::from(height);
        let below = loop {
            let run = self.spacing.run_containing(h);
            let candidate = h - h % self.step_in(&run);
            if candidate >= run.start {
                break candidate;
            }
            // No boundary lies in `[run.start, h]`. The run's start is positive here, because 0
            // is a boundary of every step, so an earlier run exists.
            h = run.start - 1;
        };
        BlockHeight::from_u32(u32::try_from(below).expect("at most `height`"))
    }

    /// Returns the least boundary height that is not below `height`. Saturates at `u32::MAX`.
    pub fn boundary_at_or_above(&self, height: BlockHeight) -> BlockHeight {
        let mut h = u64::from(height);
        let above = loop {
            let run = self.spacing.run_containing(h);
            let step = self.step_in(&run);
            let candidate = h.div_ceil(step) * step;
            match run.end {
                // No boundary lies in `[h, run.end)`, so the least one is at or after the next
                // run's start.
                Some(end) if candidate >= end => h = end,
                _ => break candidate,
            }
        };
        BlockHeight::from_u32(u32::try_from(above).unwrap_or(u32::MAX))
    }

    /// Returns the greatest boundary height strictly below `height`, or `None` if `height` is 0.
    pub fn boundary_before(&self, height: BlockHeight) -> Option<BlockHeight> {
        let h = u32::from(height);
        h.checked_sub(1)
            .map(|below| self.boundary_at_or_below(BlockHeight::from_u32(below)))
    }

    /// Returns the least boundary height strictly above `height`. Saturates at `u32::MAX`.
    pub fn boundary_after(&self, height: BlockHeight) -> BlockHeight {
        self.boundary_at_or_above(BlockHeight::from_u32(u32::from(height).saturating_add(1)))
    }
}

/// The interval, in reference blocks, between the durable anchor checkpoints a wallet retains, and
/// equally the grid a [ZIP 318] pool-crossing transfer anchors to.
///
/// The boundaries of the interval on a particular chain are given by an [`AnchorGrid`], which
/// converts the interval to blocks at each height. Those are the heights whose checkpoints a wallet
/// keeps alive past ordinary pruning, and the only tree states a pool crossing may be proved
/// against. A crossing is proved long after its boundary has passed, so the grid a wallet retains
/// and the grid a crossing anchors to must be the same — which is why this is one type rather than
/// one per crate.
///
/// The interval is a modulus, so it is necessarily non-zero.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorBucketInterval(NonZeroU32);

impl AnchorBucketInterval {
    /// The interval specified by [ZIP 318]: 144 reference blocks, about three hours (8 per day).
    /// That is 144 blocks before NU7 activation and 432 blocks from activation.
    ///
    /// [ZIP 318]: https://zips.z.cash/zip-0318
    pub const ZIP_318: Self = Self(NonZeroU32::new(144).expect("144 is nonzero"));

    /// Constructs an interval other than the [ZIP 318] one. **Use this on a test network only.**
    ///
    /// A wallet on the production network MUST use [`Self::ZIP_318`]. The anonymity set a shared
    /// anchor provides is exactly the set of transfers that chose the same boundary, so a wallet
    /// retaining (and anchoring to) a different grid than its peers is distinguishable from every
    /// one of them — which defeats the entire purpose of anchoring to a grid. A shorter interval is
    /// useful only on test networks, where waiting out 144-block buckets makes exercising a
    /// migration impractical.
    ///
    /// This is also the inverse of [`Self::block_count`], for a store reading an interval back out
    /// of its own durable state. Such a store is reproducing an interval that was chosen elsewhere,
    /// so the restriction above binds whoever chose it, not the store.
    ///
    /// [ZIP 318]: https://zips.z.cash/zip-0318
    pub const fn custom(blocks: NonZeroU32) -> Self {
        Self(blocks)
    }

    /// Returns the interval as a number of reference blocks.
    pub fn block_count(&self) -> NonZeroU32 {
        self.0
    }
}

impl Default for AnchorBucketInterval {
    fn default() -> Self {
        Self::ZIP_318
    }
}

/// The [ZIP 318] pool-migration parameters in force for a given network.
///
/// Unlike [`NetworkConstants`], this trait is **unsealed**, and every method other than
/// [`block_spacing`](Self::block_spacing) carries a default body returning the ZIP 318 value. That is
/// deliberate. `NetworkConstants` is blanket-implemented for
/// every `P: Parameters`, which makes per-network override impossible; ZIP 318 needs the opposite,
/// because a test network must be able to shorten the anchor bucket grid so that a migration
/// completes in a workable time. An implementor overrides only the accessors it cares about and
/// inherits the specified values for the rest.
///
/// A wallet on the production network MUST use the defaults: the anonymity set a shared anchor or a
/// shared denomination provides is exactly the set of transfers that chose the same one, so a wallet
/// running on different parameters than its peers is distinguishable from them.
///
/// There is deliberately **no implementation for [`NetworkType`]**, nor a blanket one over
/// `Parameters`. The grid these parameters describe is the one a wallet actually retains its anchor
/// checkpoints on, so the wallet is the only thing that can answer authoritatively; a crossing
/// anchored to a boundary the wallet did not retain cannot be proved. Were the network types also
/// implementors, every call site with consensus parameters in scope — which is nearly all of them —
/// could reach a second, silently different answer, and on mainnet the two would agree by
/// coincidence. Obtain an implementor from the wallet instead.
///
/// [`NetworkConstants`]: crate::consensus::NetworkConstants
/// [`NetworkType`]: crate::consensus::NetworkType
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub trait PoolMigrationConstants {
    /// The block spacing of the chain these parameters apply to, which converts their durations
    /// from reference blocks into blocks.
    fn block_spacing(&self) -> BlockSpacing;

    /// The interval of the grid that durable anchor checkpoints are retained on, and that
    /// pool-crossing transfers are proved against.
    fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
        AnchorBucketInterval::ZIP_318
    }

    /// The boundaries of [`anchor_bucket_interval`](Self::anchor_bucket_interval) on the chain
    /// these parameters apply to.
    fn anchor_grid(&self) -> AnchorGrid {
        AnchorGrid::new(self.anchor_bucket_interval(), self.block_spacing())
    }

    /// The largest denomination a single pool crossing may carry.
    fn denomination_cap(&self) -> Zatoshis {
        DENOM_CAP
    }

    /// The smallest denomination a pool crossing may carry; a residual below this is left in the
    /// source pool rather than crossed.
    fn max_residual_value(&self) -> Zatoshis {
        MAX_RESIDUAL_VALUE
    }

    /// The exact Orchard action count that every note-preparation transaction is padded to.
    fn preparation_tx_actions(&self) -> usize {
        PREP_TX_ACTIONS
    }

    /// The mean and inclusive cap, in reference blocks, of the transfer inter-arrival delay
    /// distribution.
    fn transfer_delay(&self) -> (NonZeroU32, NonZeroU32) {
        (TRANSFER_DELAY_MEAN, TRANSFER_DELAY_CAP)
    }

    /// The mean and inclusive cap, in reference blocks, of the preparation inter-arrival delay
    /// distribution.
    fn preparation_delay(&self) -> (NonZeroU32, NonZeroU32) {
        (PREP_DELAY_MEAN, PREP_DELAY_CAP)
    }

    /// The maximum anchor age, in boundaries, that a recency-weighted anchor draw will accept.
    fn anchor_age_cap(&self) -> u32 {
        ANCHOR_AGE_CAP
    }

    /// The modulus and window, in reference blocks, of the canonical rolling expiry window.
    fn expiry_window(&self) -> (u32, u32) {
        (EXPIRY_MODULUS, EXPIRY_WINDOW)
    }

    /// Returns whether `value` is a canonical crossing denomination under these parameters: a
    /// `{1, 2, 5} * 10^k` amount within
    /// `[max_residual_value, denomination_cap]`.
    fn is_canonical_denomination(&self, value: Zatoshis) -> bool {
        is_canonical_within(value, self.max_residual_value(), self.denomination_cap())
    }

    /// The canonical rolling expiry height for a transaction targeting `reference`, under these
    /// parameters. See the free [`expiry_height`], which this generalizes to an overridden
    /// [`expiry_window`](Self::expiry_window).
    fn canonical_expiry(&self, reference: BlockHeight) -> BlockHeight {
        let (modulus, window) = self.expiry_window();
        rolling_expiry(&self.block_spacing(), modulus, window, reference)
    }

    /// Returns whether `expiry` is the canonical rolling expiry for a transaction targeting
    /// `reference`.
    ///
    /// This is the sharpest single ZIP 318 discriminator. An ordinary transaction expires a fixed
    /// short delta after its target height, so its expiry is essentially uniform; a ZIP 318
    /// transaction's expiry is one of the few heights the rolling window admits.
    ///
    /// Use [`is_canonical_expiry_value`](Self::is_canonical_expiry_value) instead when no
    /// reference height is available, or when the answer must not change as one becomes available.
    fn is_canonical_expiry(&self, expiry: BlockHeight, reference: BlockHeight) -> bool {
        expiry == self.canonical_expiry(reference)
    }

    /// Returns whether `expiry` could be a canonical rolling expiry for SOME height: whether it is
    /// a multiple of the expiry modulus and at least one whole window above zero.
    ///
    /// This is the height-INDEPENDENT form of
    /// [`is_canonical_expiry`](Self::is_canonical_expiry), and it exists because the reference
    /// height a transaction should be judged against is not always available when the judgement
    /// must be made. A transaction observed before it is mined has no mined height, and judging it
    /// against the chain tip instead would be unstable: the canonical expiry is a step function of
    /// the height, so the answer would change once the transaction was mined in a later modulus
    /// period, contradicting an earlier decision.
    ///
    /// It is weaker, deliberately. It admits a canonical expiry belonging to a different period
    /// than the one the transaction was mined in, which the reference-height form rejects. Nearly
    /// all of the discriminating power survives: an ordinary expiry is a short fixed delta past an
    /// arbitrary target height, so it lands on a multiple of the modulus with probability about one
    /// in the modulus.
    fn is_canonical_expiry_value(&self, expiry: BlockHeight) -> bool {
        let (modulus, window) = self.expiry_window();
        let expiry = u32::from(expiry);
        expiry >= window && expiry % modulus == 0
    }
}

/// The shape a [ZIP 318]-conforming transaction has.
///
/// This names a CONFORMANCE CLASS, never a provenance. ZIP 318's privacy argument is that every
/// migration transaction looks like every other one, so recognising the shape places a transaction
/// in the anonymity set and can never establish that it came from any particular wallet's
/// migration run. Present it to a user as "migration" if that is the useful word, but do not build
/// anything on the assumption that this identifies a run.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Zip318TxKind {
    /// A note-preparation transaction: an Orchard-only send-to-self, padded to exactly
    /// [`PoolMigrationConstants::preparation_tx_actions`] actions, restructuring the wallet's
    /// notes into the self-funding notes a migration spends.
    Preparation,
    /// A pool crossing: a canonical denomination carried across the turnstile by a transaction of
    /// the canonical shape.
    Transfer,
}

/// The result of classifying a transaction against [ZIP 318].
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Zip318Classification {
    /// The transaction has this ZIP 318 shape.
    Conforms(Zip318TxKind),
    /// The transaction definitely does not have any ZIP 318 shape. Emitted only when the evidence
    /// needed to refute is actually present.
    Nonconforming,
    /// Not enough evidence to decide yet. Render this as "no label yet", never as "not a
    /// migration"; [`Nonconforming`](Self::Nonconforming) is the latter.
    Unknown,
}

impl Zip318Classification {
    /// The stable integer encoding of this classification, for a store to persist and a foreign
    /// function interface to carry.
    ///
    /// [`Unknown`](Self::Unknown) is `0`, which is also the value a store should DEFAULT the
    /// column to. A row holding it has not been classified, and nothing will classify it on its
    /// own: it needs the transaction rescanned. That is deliberately a real value rather than
    /// NULL, so a store can find such rows with an ordinary query, and deliberately distinct from
    /// [`Nonconforming`](Self::Nonconforming), which is a decision that the transaction is not a
    /// ZIP 318 one. Confusing the two would present "we never looked" as "we looked and it is
    /// not", which is exactly the claim this type refuses to make without evidence.
    ///
    /// The encoding is APPEND-ONLY: existing values never change meaning, and new kinds take new
    /// codes. See [`from_code`](Self::from_code) for what an older consumer does with a newer one.
    pub fn to_code(&self) -> i64 {
        match self {
            Self::Unknown => 0,
            Self::Nonconforming => 1,
            Self::Conforms(Zip318TxKind::Preparation) => 2,
            Self::Conforms(Zip318TxKind::Transfer) => 3,
        }
    }

    /// Decodes [`to_code`](Self::to_code). An unrecognised code decodes to
    /// [`Unknown`](Self::Unknown).
    ///
    /// Unknown decodes to unknown rather than to a refusal on purpose. A consumer built against an
    /// older version of this crate meeting a code from a newer one has learned nothing about the
    /// transaction, and saying so is honest; deciding `Nonconforming` instead would assert a
    /// judgement it is not entitled to, and would break monotonicity the moment the consumer was
    /// updated and changed its mind.
    pub fn from_code(code: i64) -> Self {
        match code {
            1 => Self::Nonconforming,
            2 => Self::Conforms(Zip318TxKind::Preparation),
            3 => Self::Conforms(Zip318TxKind::Transfer),
            _ => Self::Unknown,
        }
    }
}

/// Everything [`classify`] needs to observe about a transaction, gathered by whichever component
/// can see it.
///
/// An unanswered clause means THIS SOURCE CANNOT ANSWER, which is not the same as an answer of
/// `false`. The struct is therefore a point in the information ordering described on
/// [`Zip318Classification`], and [`Default::default`] (everything unanswered) is its least element.
/// A source builds its evidence up from there, one clause at a time, through the `with_` methods.
///
/// Two obligations on whoever fills this in, both of which keep [`classify`] monotone:
///
/// - Each field is STABLE for a given transaction: `None` may become a value as wallet data
///   arrives, but a value must never change to a different value.
/// - The two CONFIRMATORY fields ([`anchor_on_grid`](Self::anchor_on_grid) and
///   [`fee_is_canonical`](Self::fee_is_canonical)) must reflect a fixed capability of the source,
///   not a per-transaction accident. A source that answers them for one transaction and not for
///   the next can contradict its own earlier decisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Zip318Evidence {
    source_actions: Option<usize>,
    destination_actions: Option<usize>,
    other_bundles_present: Option<bool>,
    source_is_send_to_self: Option<bool>,
    sole_destination_value: Option<Zatoshis>,
    expiry_is_canonical: Option<bool>,
    anchor_on_grid: Option<bool>,
    fee_is_canonical: Option<bool>,
}

impl Zip318Evidence {
    /// Records the number of actions in the source-pool (Orchard) bundle.
    pub fn with_source_actions(mut self, source_actions: Option<usize>) -> Self {
        self.source_actions = source_actions;
        self
    }

    /// Records the number of actions in the destination-pool (Ironwood) bundle.
    pub fn with_destination_actions(mut self, destination_actions: Option<usize>) -> Self {
        self.destination_actions = destination_actions;
        self
    }

    /// Records whether any transparent or Sapling bundle is present.
    pub fn with_other_bundles_present(mut self, other_bundles_present: Option<bool>) -> Self {
        self.other_bundles_present = other_bundles_present;
        self
    }

    /// Records whether the source-pool outputs are consistent with a send-to-self. See
    /// [`source_is_send_to_self`](Self::source_is_send_to_self) for how tightly a given source
    /// may claim this.
    pub fn with_source_is_send_to_self(mut self, source_is_send_to_self: Option<bool>) -> Self {
        self.source_is_send_to_self = source_is_send_to_self;
        self
    }

    /// Records the value carried by the single value-carrying destination-pool output.
    pub fn with_sole_destination_value(mut self, sole_destination_value: Option<Zatoshis>) -> Self {
        self.sole_destination_value = sole_destination_value;
        self
    }

    /// Records whether the expiry height is the canonical rolling expiry. See
    /// [`expiry_is_canonical`](Self::expiry_is_canonical) for the height it must be judged
    /// against.
    pub fn with_expiry_is_canonical(mut self, expiry_is_canonical: Option<bool>) -> Self {
        self.expiry_is_canonical = expiry_is_canonical;
        self
    }

    /// Records whether the shielded anchor lies on the retention grid.
    pub fn with_anchor_on_grid(mut self, anchor_on_grid: Option<bool>) -> Self {
        self.anchor_on_grid = anchor_on_grid;
        self
    }

    /// Records whether the fee is the one the canonical shape pays.
    pub fn with_fee_is_canonical(mut self, fee_is_canonical: Option<bool>) -> Self {
        self.fee_is_canonical = fee_is_canonical;
        self
    }

    /// The number of actions in the source-pool (Orchard) bundle, including padding dummies.
    pub fn source_actions(&self) -> Option<usize> {
        self.source_actions
    }

    /// The number of actions in the destination-pool (Ironwood) bundle, including padding dummies.
    /// Zero when there is no destination bundle at all.
    pub fn destination_actions(&self) -> Option<usize> {
        self.destination_actions
    }

    /// Whether any transparent or Sapling bundle is present. No ZIP 318 transaction carries one.
    pub fn other_bundles_present(&self) -> Option<bool> {
        self.other_bundles_present
    }

    /// Whether the source-pool outputs are consistent with a wallet-internal send-to-self, as
    /// precisely as the source that gathered this could tell.
    ///
    /// How tightly this can be established depends on the source:
    ///
    /// - From an unproven transaction the wallet is building, exactly: every value-carrying output
    ///   pays the account's own internal address, with zero-valued padding dummies excluded.
    /// - From a mined transaction, only that the account received on its own internal address and
    ///   on no external one. A padding dummy and an unrelated party's output are equally
    ///   undecryptable, which is what the padding is for, so no source can do better.
    ///
    /// The looser reading admits strictly more, keeping the direction [`classify`] already has: no
    /// false negatives, some admitted look-alikes.
    pub fn source_is_send_to_self(&self) -> Option<bool> {
        self.source_is_send_to_self
    }

    /// The value carried by the single value-carrying destination-pool output, when the
    /// transaction has one.
    pub fn sole_destination_value(&self) -> Option<Zatoshis> {
        self.sole_destination_value
    }

    /// Whether the expiry height is the canonical rolling expiry, judged against a height the
    /// source considers authoritative: the MINED height once mined, or the target height for a
    /// transaction the wallet is itself building.
    ///
    /// A source that has neither must leave this unanswered. Judging an unmined transaction
    /// against the chain tip is a monotonicity violation waiting to happen, because the canonical
    /// expiry is a step function of the height and the answer would change once the transaction is
    /// mined in the next period.
    pub fn expiry_is_canonical(&self) -> Option<bool> {
        self.expiry_is_canonical
    }

    /// Whether the shielded anchor lies on the retention grid. CONFIRMATORY: a source that cannot
    /// resolve the anchor leaves this unanswered, which widens the predicate rather than blocking
    /// it.
    pub fn anchor_on_grid(&self) -> Option<bool> {
        self.anchor_on_grid
    }

    /// Whether the fee is the one the canonical shape pays under the standard rule. CONFIRMATORY,
    /// on the same terms as [`anchor_on_grid`](Self::anchor_on_grid).
    pub fn fee_is_canonical(&self) -> Option<bool> {
        self.fee_is_canonical
    }
}

/// Classifies a transaction against [ZIP 318] from what `evidence` could observe.
///
/// The result is an OVER-APPROXIMATION whenever the evidence omits a confirmatory clause: dropping
/// a conjunct enlarges a predicate's extension, so every strictly canonical transaction is
/// recognised (no false negatives) while a transaction matching the shape but, say, anchored off
/// the grid may also be admitted. That is the right direction for a label, which should err
/// towards showing rather than hiding, but it means this is not a substitute for the pre-build
/// check when deciding whether to BUILD a canonical crossing.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub fn classify<C>(evidence: &Zip318Evidence, constants: &C) -> Zip318Classification
where
    C: PoolMigrationConstants + ?Sized,
{
    // A confirmatory clause refutes when it is answered negatively, and is simply absent
    // otherwise; see the over-approximation note above.
    if evidence.anchor_on_grid == Some(false) || evidence.fee_is_canonical == Some(false) {
        return Zip318Classification::Nonconforming;
    }

    // The clauses every ZIP 318 shape shares. Any one of them unanswered leaves the whole
    // classification at the least element, rather than allowing a refutation we could not support.
    let (
        Some(source_actions),
        Some(destination_actions),
        Some(other_bundles_present),
        Some(expiry_is_canonical),
    ) = (
        evidence.source_actions,
        evidence.destination_actions,
        evidence.other_bundles_present,
        evidence.expiry_is_canonical,
    )
    else {
        return Zip318Classification::Unknown;
    };

    if other_bundles_present || !expiry_is_canonical {
        return Zip318Classification::Nonconforming;
    }

    // The destination bundle decides which shape is even a candidate: a preparation transaction
    // never crosses, and a crossing carries exactly one destination action.
    match destination_actions {
        0 => classify_preparation(evidence, constants, source_actions),
        CROSSING_DESTINATION_ACTIONS => classify_crossing(evidence, constants, source_actions),
        _ => Zip318Classification::Nonconforming,
    }
}

/// The preparation branch of [`classify`]: an Orchard-only send-to-self padded to the specified
/// action count.
fn classify_preparation<C>(
    evidence: &Zip318Evidence,
    constants: &C,
    source_actions: usize,
) -> Zip318Classification
where
    C: PoolMigrationConstants + ?Sized,
{
    if source_actions != constants.preparation_tx_actions() {
        return Zip318Classification::Nonconforming;
    }

    match evidence.source_is_send_to_self {
        None => Zip318Classification::Unknown,
        Some(false) => Zip318Classification::Nonconforming,
        Some(true) => Zip318Classification::Conforms(Zip318TxKind::Preparation),
    }
}

/// The crossing branch of [`classify`]: the canonical two-action source bundle carrying a
/// canonical denomination across the turnstile.
fn classify_crossing<C>(
    evidence: &Zip318Evidence,
    constants: &C,
    source_actions: usize,
) -> Zip318Classification
where
    C: PoolMigrationConstants + ?Sized,
{
    if source_actions != CROSSING_SOURCE_ACTIONS {
        return Zip318Classification::Nonconforming;
    }

    let Some(value) = evidence.sole_destination_value else {
        return Zip318Classification::Unknown;
    };

    if !constants.is_canonical_denomination(value) {
        return Zip318Classification::Nonconforming;
    }

    Zip318Classification::Conforms(Zip318TxKind::Transfer)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn canonical_denominations_are_the_one_two_five_series_in_range() {
        // In range and on the series.
        for zat in [
            1_000_000u64,
            2_000_000,
            5_000_000,
            10_000_000,
            100_000_000,
            200_000_000,
            1_000_000_000_000,
        ] {
            assert!(
                is_canonical_denomination(Zatoshis::const_from_u64(zat)),
                "{zat} should be canonical"
            );
        }
        // On the series but below MAX_RESIDUAL_VALUE.
        for zat in [1u64, 2, 5, 100_000, 500_000] {
            assert!(
                !is_canonical_denomination(Zatoshis::const_from_u64(zat)),
                "{zat} is below the minimum denomination"
            );
        }
        // On the series but above DENOM_CAP.
        assert!(!is_canonical_denomination(Zatoshis::const_from_u64(
            2_000_000_000_000
        )));
        // In range but off the series.
        for zat in [3_000_000u64, 1_000_001, 999_999_999] {
            assert!(
                !is_canonical_denomination(Zatoshis::const_from_u64(zat)),
                "{zat} is off the series"
            );
        }
        // Zero is never canonical.
        assert!(!is_canonical_denomination(Zatoshis::ZERO));
    }

    #[test]
    fn largest_at_or_below_picks_the_greatest_series_member() {
        assert_eq!(largest_one_two_five(0, 1), 0);
        assert_eq!(largest_one_two_five(4, 1), 2);
        assert_eq!(largest_one_two_five(9, 1), 5);
        assert_eq!(largest_one_two_five(10, 1), 10);
        assert_eq!(largest_one_two_five(123_456, 1), 100_000);
        // Below the floor yields zero.
        assert_eq!(largest_one_two_five(999_999, 1_000_000), 0);
    }

    #[test]
    fn zip_318_bounds_are_themselves_canonical() {
        assert!(is_canonical_denomination(MAX_RESIDUAL_VALUE));
        assert!(is_canonical_denomination(DENOM_CAP));
    }

    #[test]
    fn zip_318_interval_is_144_blocks() {
        assert_eq!(AnchorBucketInterval::ZIP_318.block_count().get(), 144);
        assert_eq!(
            AnchorBucketInterval::default(),
            AnchorBucketInterval::ZIP_318
        );
    }

    /// The NU7 spacing ratio, as the `u32` the expected values below are computed in.
    const R: u32 = NU7_POW_TARGET_SPACING_RATIO;

    /// The height reached by advancing `d` reference blocks from `h` when NU7 activates at `a`,
    /// written as the three cases of the specification rather than through the time coordinate.
    fn specified_advance(a: u32, h: u32, d: u32) -> u32 {
        if h >= a {
            h + R * d
        } else if h + d <= a {
            h + d
        } else {
            a + R * (h + d - a)
        }
    }

    /// Whether `h` is a boundary of interval `i` when NU7 activates at `a`, per the specification.
    fn specified_is_boundary(a: u32, i: u32, h: u32) -> bool {
        if h < a {
            h.is_multiple_of(i)
        } else {
            h.is_multiple_of(R * i)
        }
    }

    #[test]
    fn uniform_spacing_counts_one_block_per_reference_block() {
        let s = BlockSpacing::UNIFORM;
        for (h, d) in [(0u32, 0u32), (0, 66), (2_000_000, 576)] {
            assert_eq!(
                s.advance(BlockHeight::from_u32(h), d),
                BlockHeight::from_u32(h + d)
            );
            assert_eq!(s.blocks_per_reference_block(BlockHeight::from_u32(h)), 1);
        }
    }

    #[test]
    fn advance_saturates() {
        let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(10));
        assert_eq!(
            s.advance(BlockHeight::from_u32(u32::MAX - 1), 1),
            BlockHeight::from_u32(u32::MAX)
        );
    }

    #[test]
    fn shift_rounds_up_onto_blocks_before_a_spacing_change() {
        let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(10));
        let h = BlockHeight::from_u32;
        // A block from height 10 on takes a third of the time of a block before it, so the time
        // from height 10 to height 11 rounds up to one whole block when shifted onto height 0.
        assert_eq!(s.shift(h(0), h(10), h(11)), h(1));
        // Three such blocks take exactly the time of one earlier block.
        assert_eq!(s.shift(h(0), h(10), h(13)), h(1));
        assert_eq!(s.shift(h(0), h(10), h(14)), h(2));
    }

    #[test]
    #[allow(deprecated)]
    fn uniform_spacing_has_no_nu7_activation() {
        assert_eq!(BlockSpacing::UNIFORM.nu7_activation(), None);
    }

    proptest! {
        #[test]
        #[allow(deprecated)]
        fn nu7_activation_returns_the_height_the_spacing_was_built_with(a in any::<u32>()) {
            let activation = BlockHeight::from_u32(a);
            prop_assert_eq!(
                BlockSpacing::with_nu7_activation(activation).nu7_activation(),
                Some(activation)
            );
        }
    }

    proptest! {
        #[test]
        fn advance_follows_the_piecewise_rule(
            a in 0u32..1_000_000,
            h in 0u32..1_000_000,
            d in 0u32..10_000,
        ) {
            let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(a));
            prop_assert_eq!(
                u32::from(s.advance(BlockHeight::from_u32(h), d)),
                specified_advance(a, h, d)
            );
        }

        #[test]
        fn successive_advances_compose(
            a in 0u32..1_000_000,
            h in 0u32..1_000_000,
            d1 in 0u32..10_000,
            d2 in 0u32..10_000,
        ) {
            let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(a));
            let h = BlockHeight::from_u32(h);
            prop_assert_eq!(s.advance(s.advance(h, d1), d2), s.advance(h, d1 + d2));
        }

        #[test]
        fn shifting_moves_by_the_elapsed_duration(
            a in 0u32..1_000_000,
            from in 0u32..1_000_000,
            h in 0u32..1_000_000,
            d in 0u32..10_000,
        ) {
            let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(a));
            let (from, h) = (BlockHeight::from_u32(from), BlockHeight::from_u32(h));
            let to = s.advance(from, d);
            // Shifting the start of a duration moves it to the end of the duration.
            prop_assert_eq!(s.shift(from, from, to), to);
            // Shifting any height by an elapsed duration of `d` reference blocks advances it by
            // `d` reference blocks.
            prop_assert_eq!(s.shift(h, from, to), s.advance(h, d));
            // A duration that does not move forward leaves the height in place.
            prop_assert_eq!(s.shift(h, to, from), h);
        }

        #[test]
        fn exceeds_compares_against_the_advanced_height(
            a in 0u32..1_000_000,
            from in 0u32..1_000_000,
            d in 0u32..10_000,
        ) {
            let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(a));
            let from = BlockHeight::from_u32(from);
            let end = s.advance(from, d);
            prop_assert!(!s.exceeds(from, end, d));
            prop_assert!(s.exceeds(from, end + 1, d));
        }

        #[test]
        fn grid_boundaries_follow_the_specification(
            a in 0u32..2_000,
            i in 1u32..50,
            h in 0u32..3_000,
        ) {
            let grid = AnchorGrid::new(
                AnchorBucketInterval::custom(NonZeroU32::new(i).expect("nonzero")),
                BlockSpacing::with_nu7_activation(BlockHeight::from_u32(a)),
            );
            let is = |h: u32| specified_is_boundary(a, i, h);
            prop_assert_eq!(grid.is_boundary(BlockHeight::from_u32(h)), is(h));
            // Every boundary from activation is a multiple of the interval.
            if h >= a && is(h) {
                prop_assert_eq!(h % i, 0);
            }

            let below = u32::from(grid.boundary_at_or_below(BlockHeight::from_u32(h)));
            prop_assert!(below <= h && is(below));
            prop_assert!((below + 1..=h).all(|x| !is(x)));

            let above = u32::from(grid.boundary_at_or_above(BlockHeight::from_u32(h)));
            prop_assert!(above >= h && is(above));
            prop_assert!((h..above).all(|x| !is(x)));

            let before = grid.boundary_before(BlockHeight::from_u32(h)).map(u32::from);
            prop_assert_eq!(before, (0..h).rev().find(|x| is(*x)));
            let after = u32::from(grid.boundary_after(BlockHeight::from_u32(h)));
            prop_assert_eq!(Some(after), (h + 1..).find(|x| is(*x)));
        }

        #[test]
        fn expiry_from_nu7_uses_the_scaled_modulus(
            a in 0u32..10_000_000,
            offset in 0u32..10_000_000,
        ) {
            let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(a));
            let h = a + offset;
            let modulus = R * EXPIRY_MODULUS;
            let expiry = u32::from(expiry_height(&s, BlockHeight::from_u32(h)));
            prop_assert_eq!(expiry, h - h % modulus + 2 * modulus);
            // Between one and two scaled moduli of validity.
            prop_assert!(expiry - h > modulus && expiry - h <= 2 * modulus);
            // The height-independent test still admits it.
            prop_assert!(Zip318Params.is_canonical_expiry_value(BlockHeight::from_u32(expiry)));
        }

        #[test]
        fn expiry_before_nu7_is_unchanged(a in 1u32..10_000_000, h in 0u32..10_000_000) {
            prop_assume!(h < a);
            let s = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(a));
            let h = BlockHeight::from_u32(h);
            prop_assert_eq!(
                expiry_height(&s, h),
                expiry_height(&BlockSpacing::UNIFORM, h)
            );
        }
    }

    #[test]
    fn boundaries_round_to_multiples_of_the_interval() {
        let i = AnchorGrid::new(AnchorBucketInterval::ZIP_318, BlockSpacing::UNIFORM);
        for (height, below, above) in [
            (0u32, 0u32, 0u32),
            (1, 0, 144),
            (143, 0, 144),
            (144, 144, 144),
            (145, 144, 288),
            (2_000_000, 1_999_872, 2_000_016),
        ] {
            let h = BlockHeight::from_u32(height);
            assert_eq!(
                u32::from(i.boundary_at_or_below(h)),
                below,
                "below({height})"
            );
            assert_eq!(
                u32::from(i.boundary_at_or_above(h)),
                above,
                "above({height})"
            );
        }
        assert!(i.is_boundary(BlockHeight::from_u32(288)));
        assert!(!i.is_boundary(BlockHeight::from_u32(289)));
    }

    /// Every height in one modulus period shares an expiry, and that expiry always leaves between
    /// one and two periods of validity. Sharing is the point: a per-transaction expiry would single
    /// a pool crossing out.
    #[test]
    fn expiry_is_shared_across_a_modulus_period() {
        let period_start = 3 * EXPIRY_MODULUS;
        let expected = BlockHeight::from_u32(period_start + EXPIRY_WINDOW);

        for offset in [0u32, 1, EXPIRY_MODULUS / 2, EXPIRY_MODULUS - 1] {
            let h = BlockHeight::from_u32(period_start + offset);
            assert_eq!(
                expiry_height(&BlockSpacing::UNIFORM, h),
                expected,
                "offset {offset} must share the expiry"
            );
            // Strictly in the future, and never more than a whole window ahead.
            assert!(expiry_height(&BlockSpacing::UNIFORM, h) > h);
            assert!(
                u32::from(expiry_height(&BlockSpacing::UNIFORM, h)) - u32::from(h) <= EXPIRY_WINDOW
            );
        }

        // The next period moves to the next shared expiry.
        let next = BlockHeight::from_u32(period_start + EXPIRY_MODULUS);
        assert_eq!(
            expiry_height(&BlockSpacing::UNIFORM, next),
            BlockHeight::from_u32(period_start + EXPIRY_MODULUS + EXPIRY_WINDOW)
        );
    }

    #[test]
    fn scheduling_constants_carry_the_zip_318_values() {
        assert_eq!(PREP_TX_ACTIONS, 16);
        assert_eq!(PREP_DELAY_MEAN.get(), 16);
        assert_eq!(PREP_DELAY_CAP.get(), 96);
        assert_eq!(TRANSFER_DELAY_MEAN.get(), 66);
        assert_eq!(TRANSFER_DELAY_CAP.get(), 576);
        assert_eq!(ANCHOR_AGE_CAP, 4);
        assert_eq!(EXPIRY_MODULUS, 34_560);
        assert_eq!(EXPIRY_WINDOW, 2 * EXPIRY_MODULUS);
    }

    /// An implementor that overrides nothing carries the ZIP 318 values unmodified.
    #[test]
    fn defaults_are_the_zip_318_values() {
        #[derive(Clone)]
        struct Specified;
        impl PoolMigrationConstants for Specified {
            fn block_spacing(&self) -> BlockSpacing {
                BlockSpacing::UNIFORM
            }
        }

        assert_eq!(
            Specified.anchor_bucket_interval(),
            AnchorBucketInterval::ZIP_318
        );
        assert_eq!(Specified.denomination_cap(), DENOM_CAP);
        assert_eq!(Specified.max_residual_value(), MAX_RESIDUAL_VALUE);
        assert_eq!(Specified.preparation_tx_actions(), PREP_TX_ACTIONS);
        assert_eq!(
            Specified.transfer_delay(),
            (TRANSFER_DELAY_MEAN, TRANSFER_DELAY_CAP)
        );
        assert_eq!(
            Specified.preparation_delay(),
            (PREP_DELAY_MEAN, PREP_DELAY_CAP)
        );
        assert_eq!(Specified.anchor_age_cap(), ANCHOR_AGE_CAP);
        assert_eq!(Specified.expiry_window(), (EXPIRY_MODULUS, EXPIRY_WINDOW));
    }

    /// The trait is unsealed with default bodies, so an implementor may shorten the grid while
    /// inheriting every other ZIP 318 value. This is what a test network needs, and what the sealed
    /// blanket-implemented `NetworkConstants` shape could not provide.
    #[test]
    fn an_implementor_may_override_only_the_interval() {
        #[derive(Clone)]
        struct ShortGrid;

        impl PoolMigrationConstants for ShortGrid {
            fn block_spacing(&self) -> BlockSpacing {
                BlockSpacing::UNIFORM
            }

            fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
                AnchorBucketInterval::custom(NonZeroU32::new(12).expect("12 is nonzero"))
            }
        }

        assert_eq!(ShortGrid.anchor_bucket_interval().block_count().get(), 12);
        assert_eq!(ShortGrid.denomination_cap(), DENOM_CAP);
        assert_eq!(ShortGrid.preparation_tx_actions(), PREP_TX_ACTIONS);
    }

    /// Overridden bounds narrow which values count as canonical, while the free function keeps
    /// reporting the ZIP 318 answer.
    #[test]
    fn overridden_bounds_narrow_the_canonical_set() {
        #[derive(Clone)]
        struct SmallCap;

        impl PoolMigrationConstants for SmallCap {
            fn block_spacing(&self) -> BlockSpacing {
                BlockSpacing::UNIFORM
            }

            fn denomination_cap(&self) -> Zatoshis {
                Zatoshis::const_from_u64(COIN)
            }
        }

        let two_zec = Zatoshis::const_from_u64(2 * COIN);
        assert!(is_canonical_denomination(two_zec));
        assert!(!SmallCap.is_canonical_denomination(two_zec));
        assert!(SmallCap.is_canonical_denomination(Zatoshis::const_from_u64(COIN)));
    }

    // --- classification ---------------------------------------------------------------------

    /// A wallet on the specified parameters.
    #[derive(Clone)]
    struct Zip318Params;
    impl PoolMigrationConstants for Zip318Params {
        fn block_spacing(&self) -> BlockSpacing {
            BlockSpacing::UNIFORM
        }
    }

    /// The canonical expiry agrees with the free function on the specified parameters, and an
    /// ordinary expiry (a short fixed delta past the target) never satisfies it.
    #[test]
    fn canonical_expiry_matches_the_specified_window() {
        for height in [0u32, 1, 144, 34_559, 34_560, 2_000_000] {
            let h = BlockHeight::from_u32(height);
            assert_eq!(
                Zip318Params.canonical_expiry(h),
                expiry_height(&BlockSpacing::UNIFORM, h)
            );
            assert!(Zip318Params.is_canonical_expiry(expiry_height(&BlockSpacing::UNIFORM, h), h));
            // An ordinary transaction's default expiry delta is 40 blocks before NU7 activation,
            // and 120 blocks from NU7 activation onward.
            for ordinary_expiry_delta in [40, 120] {
                assert!(!Zip318Params.is_canonical_expiry(h + ordinary_expiry_delta, h));
            }
        }
    }

    /// An implementor that shortens the expiry window is honoured, where the free function still
    /// reports the specified answer.
    #[test]
    fn canonical_expiry_honours_an_overridden_window() {
        #[derive(Clone)]
        struct ShortWindow;
        impl PoolMigrationConstants for ShortWindow {
            fn block_spacing(&self) -> BlockSpacing {
                BlockSpacing::UNIFORM
            }

            fn expiry_window(&self) -> (u32, u32) {
                (100, 200)
            }
        }

        let h = BlockHeight::from_u32(250);
        assert_eq!(ShortWindow.canonical_expiry(h), BlockHeight::from_u32(400));
        assert!(ShortWindow.is_canonical_expiry(BlockHeight::from_u32(400), h));
        assert!(!ShortWindow.is_canonical_expiry(expiry_height(&BlockSpacing::UNIFORM, h), h));
    }

    /// The height-independent expiry test admits every canonical expiry, and rejects the ordinary
    /// expiry of a transaction targeting any height.
    #[test]
    fn the_height_independent_expiry_test_admits_canonical_expiries() {
        for height in [0u32, 1, 144, 34_559, 34_560, 2_000_000] {
            let h = BlockHeight::from_u32(height);
            assert!(
                Zip318Params.is_canonical_expiry_value(expiry_height(&BlockSpacing::UNIFORM, h)),
                "the canonical expiry for {height} must be admitted without a reference height"
            );
            assert!(
                !Zip318Params.is_canonical_expiry_value(h + 40),
                "an ordinary expiry for {height} must be rejected"
            );
        }

        // Weaker than the reference-height form, and this is the gap: an expiry canonical for one
        // period is admitted while a transaction mined in another period is being judged.
        let other_period = expiry_height(&BlockSpacing::UNIFORM, BlockHeight::from_u32(0));
        let mined_much_later = BlockHeight::from_u32(10 * EXPIRY_MODULUS);
        assert!(Zip318Params.is_canonical_expiry_value(other_period));
        assert!(!Zip318Params.is_canonical_expiry(other_period, mined_much_later));
    }

    /// The persisted encoding round-trips, and the two ways of not having a label stay distinct:
    /// "never classified, needs a rescan" must never be stored or read as "classified, and not a
    /// ZIP 318 transaction".
    #[test]
    fn the_classification_encoding_round_trips() {
        for classification in [
            Zip318Classification::Unknown,
            Zip318Classification::Nonconforming,
            Zip318Classification::Conforms(Zip318TxKind::Preparation),
            Zip318Classification::Conforms(Zip318TxKind::Transfer),
        ] {
            assert_eq!(
                Zip318Classification::from_code(classification.to_code()),
                classification
            );
        }

        // Zero is `Unknown`, so a column defaulting to zero reads back as unclassified rather
        // than as a decision. This is what a backfill leaves behind.
        assert_eq!(Zip318Classification::Unknown.to_code(), 0);
        assert_eq!(
            Zip318Classification::from_code(0),
            Zip318Classification::Unknown
        );
        assert_ne!(
            Zip318Classification::Unknown.to_code(),
            Zip318Classification::Nonconforming.to_code(),
            "never classified must not encode as classified-and-refused"
        );

        // A code from a newer version teaches an older consumer nothing, which is `Unknown`.
        for unrecognised in [4, 99, -1] {
            assert_eq!(
                Zip318Classification::from_code(unrecognised),
                Zip318Classification::Unknown
            );
        }
    }

    /// Evidence for a well-formed preparation transaction, from a source that can answer every
    /// clause. Tests below knock out one field at a time.
    fn prep_evidence() -> Zip318Evidence {
        Zip318Evidence::default()
            .with_source_actions(Some(PREP_TX_ACTIONS))
            .with_destination_actions(Some(0))
            .with_other_bundles_present(Some(false))
            .with_source_is_send_to_self(Some(true))
            .with_expiry_is_canonical(Some(true))
            .with_anchor_on_grid(Some(true))
            .with_fee_is_canonical(Some(true))
    }

    /// Evidence for a well-formed pool crossing carrying `value`.
    fn crossing_evidence(value: Zatoshis) -> Zip318Evidence {
        Zip318Evidence::default()
            .with_source_actions(Some(CROSSING_SOURCE_ACTIONS))
            .with_destination_actions(Some(CROSSING_DESTINATION_ACTIONS))
            .with_other_bundles_present(Some(false))
            .with_sole_destination_value(Some(value))
            .with_expiry_is_canonical(Some(true))
            .with_anchor_on_grid(Some(true))
            .with_fee_is_canonical(Some(true))
    }

    /// The least element of the information ordering decides nothing.
    #[test]
    fn no_evidence_is_unknown() {
        assert_eq!(
            classify(&Zip318Evidence::default(), &Zip318Params),
            Zip318Classification::Unknown
        );
    }

    #[test]
    fn a_canonical_preparation_conforms() {
        assert_eq!(
            classify(&prep_evidence(), &Zip318Params),
            Zip318Classification::Conforms(Zip318TxKind::Preparation)
        );
    }

    /// A crossing conforms on its shape and its denomination alone. Nothing here observes the
    /// recipient, which is exactly the indistinguishability the canonical shape buys: a payment to
    /// a third party in this shape is the same transaction as a wallet's own migration transfer.
    #[test]
    fn a_canonical_crossing_conforms() {
        assert_eq!(
            classify(
                &crossing_evidence(Zatoshis::const_from_u64(COIN)),
                &Zip318Params
            ),
            Zip318Classification::Conforms(Zip318TxKind::Transfer)
        );
    }

    /// The shape clauses each refute on their own. These are the ordinary transactions that must
    /// never be labelled: a note split with the wrong action count, one carrying another bundle,
    /// one with an ordinary expiry, and a crossing of an off-series amount.
    #[test]
    fn each_clause_refutes_on_its_own() {
        let cases: [(&str, Zip318Evidence); 5] = [
            (
                "an ordinary split has a different action count",
                prep_evidence().with_source_actions(Some(PREP_TX_ACTIONS + 1)),
            ),
            (
                "no ZIP 318 transaction carries another bundle",
                prep_evidence().with_other_bundles_present(Some(true)),
            ),
            (
                "an ordinary expiry is not the rolling one",
                prep_evidence().with_expiry_is_canonical(Some(false)),
            ),
            (
                "a preparation output paying elsewhere is not a send-to-self",
                prep_evidence().with_source_is_send_to_self(Some(false)),
            ),
            (
                "a crossing of an off-series amount joins no anonymity set",
                crossing_evidence(Zatoshis::const_from_u64(3 * COIN)),
            ),
        ];

        for (why, evidence) in cases {
            assert_eq!(
                classify(&evidence, &Zip318Params),
                Zip318Classification::Nonconforming,
                "{why}"
            );
        }
    }

    /// A 16-action Orchard-only send-to-self that lands on a canonical expiry by coincidence is
    /// still refused if anything else about it is wrong. The clauses are conjoined precisely
    /// because no single one of them is rare enough on its own.
    #[test]
    fn a_coincidental_expiry_alone_does_not_conform() {
        let evidence = prep_evidence()
            .with_other_bundles_present(Some(true))
            .with_expiry_is_canonical(Some(true));
        assert_eq!(
            classify(&evidence, &Zip318Params),
            Zip318Classification::Nonconforming
        );
    }

    /// A confirmatory clause refutes when answered negatively, and is absent otherwise. Absence
    /// widens the predicate (the over-approximation), it does not block it.
    #[test]
    fn confirmatory_clauses_refute_but_do_not_block() {
        for knock_out in [
            prep_evidence().with_anchor_on_grid(Some(false)),
            prep_evidence().with_fee_is_canonical(Some(false)),
        ] {
            assert_eq!(
                classify(&knock_out, &Zip318Params),
                Zip318Classification::Nonconforming
            );
        }

        // A source that cannot answer either one still decides.
        let unanswerable = prep_evidence()
            .with_anchor_on_grid(None)
            .with_fee_is_canonical(None);
        assert_eq!(
            classify(&unanswerable, &Zip318Params),
            Zip318Classification::Conforms(Zip318TxKind::Preparation)
        );
    }

    /// A required clause left unanswered yields the least element, never a refutation: we do not
    /// claim a transaction is not a migration on evidence we do not have.
    #[test]
    fn an_unanswered_required_clause_is_unknown_not_a_refutation() {
        let knock_outs = [
            prep_evidence().with_source_actions(None),
            prep_evidence().with_destination_actions(None),
            prep_evidence().with_other_bundles_present(None),
            prep_evidence().with_expiry_is_canonical(None),
            prep_evidence().with_source_is_send_to_self(None),
        ];

        for evidence in knock_outs {
            assert_eq!(
                classify(&evidence, &Zip318Params),
                Zip318Classification::Unknown
            );
        }

        // The same for the crossing branch's own required clause.
        let no_output =
            crossing_evidence(Zatoshis::const_from_u64(COIN)).with_sole_destination_value(None);
        assert_eq!(
            classify(&no_output, &Zip318Params),
            Zip318Classification::Unknown
        );
    }

    /// MONOTONICITY. As evidence grows, the classification only ever moves up the flat
    /// information order: `Unknown` may become a decision, but a decision never becomes a
    /// different decision. This is what lets a consumer cache a label, and what stops a history
    /// row relabelling itself while the wallet catches up.
    #[test]
    fn classification_is_monotone_in_the_evidence() {
        // A chain of evidence values, each learning one more clause than the last, for both a
        // conforming and a refuted transaction.
        for full in [
            prep_evidence(),
            crossing_evidence(Zatoshis::const_from_u64(COIN)),
            prep_evidence().with_other_bundles_present(Some(true)),
        ] {
            let chain = [
                Zip318Evidence::default(),
                Zip318Evidence::default()
                    .with_source_actions(full.source_actions())
                    .with_destination_actions(full.destination_actions()),
                full.with_sole_destination_value(None)
                    .with_expiry_is_canonical(None),
                full,
            ];

            let mut decided: Option<Zip318Classification> = None;
            for evidence in chain {
                match classify(&evidence, &Zip318Params) {
                    Zip318Classification::Unknown => assert!(
                        decided.is_none(),
                        "evidence grew and a decision reverted to Unknown"
                    ),
                    settled => {
                        if let Some(earlier) = decided {
                            assert_eq!(earlier, settled, "evidence grew and the decision changed");
                        }
                        decided = Some(settled);
                    }
                }
            }
        }
    }

    /// Spacing on chains that [`LocalNetwork`] describes, including chains with two changes of
    /// the target spacing after Blossom.
    #[cfg(feature = "local-consensus")]
    mod local_network_spacing {
        use alloc::vec::Vec;
        use core::{num::NonZeroU32, time::Duration};

        use proptest::prelude::*;

        use crate::{
            consensus::{
                BlockHeight, NetworkUpgrade, POST_BLOSSOM_POW_TARGET_SPACING,
                POST_NU7_POW_TARGET_SPACING, Parameters, PowTargetSpacingChange,
                pow_target_spacing, pow_target_spacing_with,
                spacing_changes_are_in_activation_order, target_time_between,
                target_time_between_with,
            },
            local_consensus::LocalNetwork,
        };

        use super::super::{
            AnchorBucketInterval, AnchorGrid, BlockSpacing, EXPIRY_MODULUS, MAX_SPACING_SEGMENTS,
            REFERENCE_BLOCK_SPACING, expiry_height,
        };

        /// The upgrade that makes the first of two changes of the target spacing after Blossom.
        /// No upgrade follows NU7 to make a change after the NU7 one, so the second change is
        /// keyed to NU7 and the first to the upgrade before it.
        const FIRST_UPGRADE: NetworkUpgrade = NetworkUpgrade::Nu6_3;
        /// The upgrade that makes the second change.
        const SECOND_UPGRADE: NetworkUpgrade = NetworkUpgrade::Nu7;
        /// The target spacing from the first change: the post-NU7 spacing, so that one reference
        /// block spans 3 blocks.
        const FIRST_SPACING: Duration = POST_NU7_POW_TARGET_SPACING;
        /// The number of blocks one reference block spans at [`FIRST_SPACING`].
        const FIRST_BLOCKS_PER_REFERENCE_BLOCK: u32 = 3;
        /// The target spacing from the second change: one fifth of [`FIRST_SPACING`], so that one
        /// reference block spans 15 blocks.
        const SECOND_SPACING: Duration = Duration::from_secs(5);
        /// The number of blocks one reference block spans at [`SECOND_SPACING`].
        const SECOND_BLOCKS_PER_REFERENCE_BLOCK: u32 = 15;
        /// A target spacing for the second change that does not divide [`FIRST_SPACING`], so
        /// that a duration crossing into it need not land exactly on a height.
        const UNEVEN_SECOND_SPACING: Duration = Duration::from_secs(15);
        /// The number of blocks one reference block spans at [`UNEVEN_SECOND_SPACING`].
        const UNEVEN_BLOCKS_PER_REFERENCE_BLOCK: u32 = 5;
        /// The two changes of the target spacing after Blossom.
        const CHANGES: [PowTargetSpacingChange; 2] = [
            PowTargetSpacingChange {
                upgrade: FIRST_UPGRADE,
                spacing: FIRST_SPACING,
            },
            PowTargetSpacingChange {
                upgrade: SECOND_UPGRADE,
                spacing: SECOND_SPACING,
            },
        ];

        /// The Blossom spacing change followed by [`CHANGES`].
        const CHANGES_FROM_BLOSSOM: [PowTargetSpacingChange; 3] = [
            PowTargetSpacingChange {
                upgrade: NetworkUpgrade::Blossom,
                spacing: POST_BLOSSOM_POW_TARGET_SPACING,
            },
            CHANGES[0],
            CHANGES[1],
        ];

        /// The Blossom activation height of a chain on which Blossom is active from the genesis
        /// block, so that every height has at least the reference spacing.
        const BLOSSOM_AT_GENESIS: Option<u32> = Some(0);

        /// A local network on which every upgrade through Blossom activates at `blossom`, every
        /// later upgrade through [`FIRST_UPGRADE`] at `first`, and [`SECOND_UPGRADE`] at
        /// `second`. The heights must be in activation order: each that is `Some` follows one
        /// that is `Some` and no greater.
        fn network(blossom: Option<u32>, first: Option<u32>, second: Option<u32>) -> LocalNetwork {
            let steps: Vec<_> = [
                (NetworkUpgrade::Blossom, blossom),
                (FIRST_UPGRADE, first),
                (SECOND_UPGRADE, second),
            ]
            .into_iter()
            .filter_map(|(upgrade, height)| Some(upgrade).zip(height.map(BlockHeight::from_u32)))
            .collect();
            LocalNetwork::new(&steps).expect("the heights are in activation order")
        }

        /// The spacing under [`CHANGES`] of a chain on which the first change takes effect at
        /// `first` and the second at `second`, which must be no less.
        fn two_changes(first: u32, second: u32) -> BlockSpacing {
            BlockSpacing::with_changes(
                &network(BLOSSOM_AT_GENESIS, Some(first), Some(second)),
                &CHANGES,
            )
            .expect("both spacings divide the reference spacing")
        }

        /// The number of blocks one reference block spans at `h` under [`CHANGES`], on a chain on
        /// which the first change takes effect at `first` and the second at `second`, which must
        /// be no less.
        fn specified_ratio(first: u32, second: u32, h: u32) -> u32 {
            if h >= second {
                SECOND_BLOCKS_PER_REFERENCE_BLOCK
            } else if h >= first {
                FIRST_BLOCKS_PER_REFERENCE_BLOCK
            } else {
                1
            }
        }

        /// The least target height at least `d` reference blocks after target height `h`, found
        /// by walking block by block: the step from target height `height` to `height + 1` is the
        /// time to mine the block at `height`, the target spacing there, whose number of blocks
        /// per reference block `ratio` gives.
        fn walk(ratio: impl Fn(u32) -> u32, h: u32, d: u32) -> u32 {
            let reference_secs = REFERENCE_BLOCK_SPACING.as_secs();
            let target = u64::from(d) * reference_secs;
            let mut elapsed = 0u64;
            let mut height = h;
            while elapsed < target {
                elapsed += reference_secs / u64::from(ratio(height));
                height += 1;
            }
            height
        }

        /// The height reached by advancing `d` reference blocks from `h` under [`CHANGES`].
        fn specified_advance(first: u32, second: u32, h: u32, d: u32) -> u32 {
            walk(|height| specified_ratio(first, second, height), h, d)
        }

        #[test]
        fn the_second_spacing_is_one_fifteenth_of_a_reference_block() {
            assert_eq!(
                SECOND_SPACING * SECOND_BLOCKS_PER_REFERENCE_BLOCK,
                REFERENCE_BLOCK_SPACING
            );
            assert_eq!(
                FIRST_SPACING * FIRST_BLOCKS_PER_REFERENCE_BLOCK,
                REFERENCE_BLOCK_SPACING
            );
        }

        #[test]
        fn the_changes_are_in_activation_order() {
            assert!(spacing_changes_are_in_activation_order(
                &CHANGES_FROM_BLOSSOM
            ));
        }

        #[test]
        fn schedules_that_do_not_fit_are_rejected() {
            let net = network(Some(5), Some(10), Some(20));
            // A spacing that does not divide the reference spacing.
            let uneven = [PowTargetSpacingChange {
                upgrade: SECOND_UPGRADE,
                spacing: Duration::from_secs(10),
            }];
            assert_eq!(BlockSpacing::with_changes(&net, &uneven), None);
            // More distinct changes than a `BlockSpacing` holds. The spacings of successive
            // heights alternate, so that every change takes a segment.
            let alternating = |changes: usize| {
                (1u32..).take(changes).map(|height| {
                    let spacing = if height.is_multiple_of(2) {
                        REFERENCE_BLOCK_SPACING
                    } else {
                        FIRST_SPACING
                    };
                    (BlockHeight::from_u32(height), spacing)
                })
            };
            assert!(BlockSpacing::from_schedule(alternating(MAX_SPACING_SEGMENTS)).is_some());
            assert_eq!(
                BlockSpacing::from_schedule(alternating(MAX_SPACING_SEGMENTS + 1)),
                None
            );
            // Changes that leave the spacing unchanged take no room. The one change that remains
            // gives the spacing that `with_nu7_activation` builds.
            let redundant = [
                PowTargetSpacingChange {
                    upgrade: NetworkUpgrade::Blossom,
                    spacing: POST_BLOSSOM_POW_TARGET_SPACING,
                },
                CHANGES[0],
            ];
            assert_eq!(
                BlockSpacing::with_changes(&network(Some(5), Some(10), None), &redundant),
                Some(BlockSpacing::with_nu7_activation(BlockHeight::from_u32(10)))
            );
        }

        proptest! {
            /// On a chain where NU7 is the only change of the target spacing after Blossom, the
            /// spacing derived from the consensus schedule is the NU7-only spacing.
            #[test]
            #[allow(deprecated)]
            fn for_network_matches_the_nu7_only_spacing(
                blossom in proptest::option::of(0u32..1_000),
                nu7_delay in proptest::option::of(0u32..1_000),
            ) {
                // NU7 activates only on a chain on which Blossom activates, and no earlier.
                let nu7 = blossom.zip(nu7_delay).map(|(blossom, delay)| blossom + delay);
                let net = network(blossom, nu7, nu7);
                let spacing = BlockSpacing::for_network(&net);
                prop_assert_eq!(
                    spacing,
                    nu7.map_or(BlockSpacing::UNIFORM, |nu7| {
                        BlockSpacing::with_nu7_activation(BlockHeight::from_u32(nu7))
                    })
                );
                prop_assert_eq!(
                    spacing.nu7_activation(),
                    net.activation_height(NetworkUpgrade::Nu7)
                );
            }

            #[test]
            fn advance_walks_each_segment_at_its_own_spacing(
                first in 0u32..2_000,
                gap in 0u32..1_000,
                h in 0u32..3_000,
                d in 0u32..300,
            ) {
                let second = first + gap;
                let s = two_changes(first, second);
                prop_assert_eq!(
                    s.blocks_per_reference_block(BlockHeight::from_u32(h)),
                    specified_ratio(first, second, h)
                );
                prop_assert_eq!(
                    u32::from(s.advance(BlockHeight::from_u32(h), d)),
                    specified_advance(first, second, h, d)
                );
            }

            #[test]
            fn successive_advances_compose_across_both_changes(
                first in 0u32..2_000,
                gap in 0u32..1_000,
                h in 0u32..3_000,
                d1 in 0u32..300,
                d2 in 0u32..300,
            ) {
                let s = two_changes(first, first + gap);
                let h = BlockHeight::from_u32(h);
                prop_assert_eq!(s.advance(s.advance(h, d1), d2), s.advance(h, d1 + d2));
            }

            #[test]
            fn shift_and_exceeds_agree_with_advance_across_both_changes(
                first in 0u32..2_000,
                gap in 0u32..1_000,
                from in 0u32..3_000,
                h in 0u32..3_000,
                d in 0u32..300,
            ) {
                let s = two_changes(first, first + gap);
                let (from, h) = (BlockHeight::from_u32(from), BlockHeight::from_u32(h));
                let to = s.advance(from, d);
                prop_assert_eq!(s.shift(from, from, to), to);
                prop_assert_eq!(s.shift(h, from, to), s.advance(h, d));
                prop_assert_eq!(s.shift(h, to, from), h);
                prop_assert!(!s.exceeds(from, to, d));
                prop_assert!(s.exceeds(from, to + 1, d));
            }

            /// Where each target spacing divides every earlier one, a duration keeps its exact
            /// length when it is shifted onto a height that is not below its own start.
            #[test]
            fn shift_is_exact_onto_a_height_not_below_the_start(
                first in 0u32..2_000,
                gap in 0u32..1_000,
                from in 0u32..3_000,
                length in 0u32..1_000,
                delay in 0u32..1_000,
            ) {
                let s = two_changes(first, first + gap);
                let (to, h) = (
                    BlockHeight::from_u32(from + length),
                    BlockHeight::from_u32(from + delay),
                );
                let from = BlockHeight::from_u32(from);
                prop_assert_eq!(
                    s.time_of(s.shift(h, from, to)) - s.time_of(h),
                    s.time_of(to) - s.time_of(from)
                );
            }

            #[test]
            fn grid_boundaries_follow_the_spacing_of_each_segment(
                first in 0u32..2_000,
                gap in 0u32..1_000,
                i in 1u32..20,
                h in 0u32..3_000,
            ) {
                let second = first + gap;
                let grid = AnchorGrid::new(
                    AnchorBucketInterval::custom(NonZeroU32::new(i).expect("nonzero")),
                    two_changes(first, second),
                );
                let is = |h: u32| h.is_multiple_of(i * specified_ratio(first, second, h));
                prop_assert_eq!(grid.is_boundary(BlockHeight::from_u32(h)), is(h));

                let below = u32::from(grid.boundary_at_or_below(BlockHeight::from_u32(h)));
                prop_assert!(below <= h && is(below));
                prop_assert!((below + 1..=h).all(|x| !is(x)));

                let above = u32::from(grid.boundary_at_or_above(BlockHeight::from_u32(h)));
                prop_assert!(above >= h && is(above));
                prop_assert!((h..above).all(|x| !is(x)));

                let before = grid.boundary_before(BlockHeight::from_u32(h)).map(u32::from);
                prop_assert_eq!(before, (0..h).rev().find(|x| is(*x)));
                let after = u32::from(grid.boundary_after(BlockHeight::from_u32(h)));
                prop_assert_eq!(Some(after), (h + 1..).find(|x| is(*x)));
            }

            /// The time from target height `from` to target height `to` is the consensus target
            /// time to mine the blocks `from..to`, at every height from Blossom activation on,
            /// with several spacing changes after Blossom.
            #[test]
            fn elapsed_time_is_the_target_time_between(
                blossom in 0u32..1_000,
                first_delay in proptest::option::of(0u32..1_000),
                second_delay in proptest::option::of(0u32..1_000),
                from_offset in 0u32..2_000,
                to in 0u32..3_000,
            ) {
                // Each change takes effect only on a chain on which the change before it does,
                // and no earlier.
                let first = first_delay.map(|delay| blossom + delay);
                let second = first.zip(second_delay).map(|(first, delay)| first + delay);
                let net = network(Some(blossom), first, second);
                let from = blossom + from_offset;
                // The time to mine the blocks `from..to`, given the target spacing of one block
                // and the target time between two blocks. That is
                // `between(from - 1, to - 1)`; from target height 0, which has no block below it,
                // it is the spacing of block 0 plus `between(0, to - 1)`.
                let mining_time = |spacing_at: &dyn Fn(BlockHeight) -> Duration,
                                   between: &dyn Fn(BlockHeight, BlockHeight) -> Duration| {
                    if to <= from {
                        0
                    } else if from == 0 {
                        let genesis = BlockHeight::from_u32(0);
                        (spacing_at(genesis) + between(genesis, BlockHeight::from_u32(to - 1)))
                            .as_secs()
                    } else {
                        between(BlockHeight::from_u32(from - 1), BlockHeight::from_u32(to - 1))
                            .as_secs()
                    }
                };
                let (from_height, to_height) =
                    (BlockHeight::from_u32(from), BlockHeight::from_u32(to));

                let s = BlockSpacing::with_changes(&net, &CHANGES_FROM_BLOSSOM)
                    .expect("the changes after Blossom fit");
                prop_assert_eq!(
                    s.time_of(to_height).saturating_sub(s.time_of(from_height)),
                    mining_time(
                        &|h| pow_target_spacing_with(&CHANGES_FROM_BLOSSOM, &net, h),
                        &|a, b| target_time_between_with(&CHANGES_FROM_BLOSSOM, &net, a, b),
                    )
                );

                // The same holds for the consensus schedule itself.
                let consensus = BlockSpacing::for_network(&net);
                prop_assert_eq!(
                    consensus.time_of(to_height).saturating_sub(consensus.time_of(from_height)),
                    mining_time(
                        &|h| pow_target_spacing(&net, h),
                        &|a, b| target_time_between(&net, a, b),
                    )
                );
            }

            /// When a later spacing does not divide an earlier one, `advance` rounds up to the
            /// least height at least the duration later.
            #[test]
            fn advance_rounds_up_where_a_later_spacing_does_not_divide(
                first in 0u32..2_000,
                gap in 0u32..1_000,
                h in 0u32..3_000,
                d in 0u32..300,
            ) {
                let second = first + gap;
                let changes = [
                    CHANGES[0],
                    PowTargetSpacingChange {
                        upgrade: SECOND_UPGRADE,
                        spacing: UNEVEN_SECOND_SPACING,
                    },
                ];
                let s = BlockSpacing::with_changes(
                    &network(BLOSSOM_AT_GENESIS, Some(first), Some(second)),
                    &changes,
                )
                .expect("both spacings divide the reference spacing");
                let ratio = |height: u32| {
                    if height >= second {
                        UNEVEN_BLOCKS_PER_REFERENCE_BLOCK
                    } else if height >= first {
                        FIRST_BLOCKS_PER_REFERENCE_BLOCK
                    } else {
                        1
                    }
                };
                prop_assert_eq!(
                    u32::from(s.advance(BlockHeight::from_u32(h), d)),
                    walk(ratio, h, d)
                );
            }

            #[test]
            fn expiry_after_the_second_change_uses_its_scaled_modulus(
                first in 0u32..10_000_000,
                gap in 0u32..10_000_000,
                offset in 0u32..10_000_000,
            ) {
                let second = first + gap;
                let s = two_changes(first, second);
                let h = second + offset;
                let modulus = SECOND_BLOCKS_PER_REFERENCE_BLOCK * EXPIRY_MODULUS;
                let expiry = u32::from(expiry_height(&s, BlockHeight::from_u32(h)));
                prop_assert_eq!(expiry, h - h % modulus + 2 * modulus);
            }
        }
    }
}
