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

use core::num::NonZeroU32;

use crate::consensus::{BlockHeight, NU7_POW_TARGET_SPACING_RATIO, NetworkUpgrade, Parameters};
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

/// The block spacing of a chain, for converting [ZIP 318] durations into block heights.
///
/// ZIP 318 states each duration as a number of REFERENCE BLOCKS: blocks at the 75-second target
/// spacing. From NU7 activation the target spacing is 25 seconds, so the same duration spans
/// [`NU7_POW_TARGET_SPACING_RATIO`] times as many blocks. A duration that starts before activation
/// and ends after it keeps its exact length: its part before activation counts one block per
/// reference block, and its part after activation counts the ratio.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSpacing {
    nu7_activation: Option<BlockHeight>,
}

impl BlockSpacing {
    /// The spacing of a chain on which NU7 does not activate: one block per reference block at
    /// every height.
    pub const UNIFORM: Self = Self {
        nu7_activation: None,
    };

    /// The spacing of the chain that `params` describe.
    pub fn for_network<P: Parameters>(params: &P) -> Self {
        Self {
            nu7_activation: params.activation_height(NetworkUpgrade::Nu7),
        }
    }

    /// The spacing of a chain on which NU7 activates at `nu7_activation`.
    pub const fn with_nu7_activation(nu7_activation: BlockHeight) -> Self {
        Self {
            nu7_activation: Some(nu7_activation),
        }
    }

    /// The NU7 activation height of this chain, if NU7 activates on it.
    pub fn nu7_activation(&self) -> Option<BlockHeight> {
        self.nu7_activation
    }

    /// The number of blocks that one reference block spans at `height`: 1 before NU7 activation,
    /// and [`NU7_POW_TARGET_SPACING_RATIO`] from activation.
    pub fn blocks_per_reference_block(&self, height: BlockHeight) -> u32 {
        match self.nu7_activation {
            Some(activation) if height >= activation => NU7_POW_TARGET_SPACING_RATIO,
            _ => 1,
        }
    }

    /// Returns the height that is `reference_blocks` reference blocks after `from`. Saturates at
    /// `u32::MAX`.
    pub fn advance(&self, from: BlockHeight, reference_blocks: u32) -> BlockHeight {
        let ratio = u64::from(NU7_POW_TARGET_SPACING_RATIO);
        self.height_at(self.time_of(from) + u64::from(reference_blocks) * ratio)
    }

    /// Returns the height that is as long after `height` as `to` is after `from`, or `height` when
    /// `to` is not after `from`. Saturates at `u32::MAX`.
    pub fn shift(&self, height: BlockHeight, from: BlockHeight, to: BlockHeight) -> BlockHeight {
        let elapsed = self.time_of(to).saturating_sub(self.time_of(from));
        self.height_at(self.time_of(height) + elapsed)
    }

    /// Returns whether `to` is more than `reference_blocks` reference blocks after `from`.
    pub fn exceeds(&self, from: BlockHeight, to: BlockHeight, reference_blocks: u32) -> bool {
        let ratio = u64::from(NU7_POW_TARGET_SPACING_RATIO);
        self.time_of(to).saturating_sub(self.time_of(from)) > u64::from(reference_blocks) * ratio
    }

    /// The NU7 activation height as a `u64`, or one past `u32::MAX` when NU7 does not activate,
    /// so that every height is below it.
    fn activation(&self) -> u64 {
        self.nu7_activation
            .map_or(u64::from(u32::MAX) + 1, |h| u64::from(u32::from(h)))
    }

    /// The time at which `height` is reached, in units of the post-NU7 target spacing, measured
    /// from the genesis block. Each block before activation adds the spacing ratio, and each block
    /// from activation adds one.
    fn time_of(&self, height: BlockHeight) -> u64 {
        let ratio = u64::from(NU7_POW_TARGET_SPACING_RATIO);
        let activation = self.activation();
        let h = u64::from(u32::from(height));
        if h <= activation {
            h * ratio
        } else {
            activation * ratio + (h - activation)
        }
    }

    /// The least height reached at or after `time`. Saturates at `u32::MAX`.
    fn height_at(&self, time: u64) -> BlockHeight {
        let ratio = u64::from(NU7_POW_TARGET_SPACING_RATIO);
        let activation = self.activation();
        let h = if time <= activation * ratio {
            time.div_ceil(ratio)
        } else {
            activation + (time - activation * ratio)
        };
        BlockHeight::from_u32(u32::try_from(h).unwrap_or(u32::MAX))
    }
}

/// The boundary heights of an [`AnchorBucketInterval`] on a chain with a given [`BlockSpacing`].
///
/// The interval is a number of reference blocks. Before NU7 activation a height is a boundary when
/// it is a multiple of the interval. From activation it is a boundary when it is a multiple of the
/// interval times [`NU7_POW_TARGET_SPACING_RATIO`], which keeps the boundaries the same time apart.
/// Every boundary from activation is also a multiple of the interval, so a wallet that retains the
/// checkpoint at every multiple of the interval retains every boundary.
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

    /// The distance in blocks between boundaries at heights from `height` onward, while the
    /// spacing does not change.
    fn step_at(&self, height: u64) -> u64 {
        let ratio = if height >= self.spacing.activation() {
            NU7_POW_TARGET_SPACING_RATIO
        } else {
            1
        };
        u64::from(self.interval.block_count().get()) * u64::from(ratio)
    }

    /// Returns whether `height` is a boundary of this grid, i.e. whether the checkpoint at
    /// `height` is retained as a durable anchor.
    pub fn is_boundary(&self, height: BlockHeight) -> bool {
        let h = u64::from(u32::from(height));
        h.is_multiple_of(self.step_at(h))
    }

    /// Returns the greatest boundary height that does not exceed `height`.
    pub fn boundary_at_or_below(&self, height: BlockHeight) -> BlockHeight {
        let h = u64::from(u32::from(height));
        let activation = self.spacing.activation();
        let below = if h >= activation {
            let candidate = h - h % self.step_at(h);
            if candidate >= activation {
                candidate
            } else {
                // No boundary lies in `[activation, h]`. Activation is positive here, because 0
                // is a boundary of every step, so the greatest boundary below activation exists.
                let last_before = activation - 1;
                last_before - last_before % self.step_at(last_before)
            }
        } else {
            h - h % self.step_at(h)
        };
        BlockHeight::from_u32(u32::try_from(below).expect("at most `height`"))
    }

    /// Returns the least boundary height that is not below `height`. Saturates at `u32::MAX`.
    pub fn boundary_at_or_above(&self, height: BlockHeight) -> BlockHeight {
        let h = u64::from(u32::from(height));
        let activation = self.spacing.activation();
        let round_up = |h: u64, step: u64| h.div_ceil(step) * step;
        let above = if h >= activation {
            round_up(h, self.step_at(h))
        } else {
            let candidate = round_up(h, self.step_at(h));
            if candidate < activation {
                candidate
            } else {
                round_up(activation, self.step_at(activation))
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
}
