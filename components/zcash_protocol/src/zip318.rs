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

use crate::consensus::BlockHeight;
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
/// EXPIRY MUST): the most recent multiple of [`EXPIRY_MODULUS`] at or below `target_height`, plus
/// [`EXPIRY_WINDOW`] (`2 * EXPIRY_MODULUS`).
///
/// This is a pure function of the height, so it reveals nothing per-wallet: every transaction in the
/// same modulus period shares one expiry, whereas an ordinary per-transaction expiry would single a
/// pool crossing out immediately. It guarantees between one and two [`EXPIRY_MODULUS`] periods
/// (about one to two months) of remaining validity — the result is always strictly greater than
/// `target_height` and at most [`EXPIRY_WINDOW`] above it. Saturates at `u32::MAX`.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub fn expiry_height(target_height: BlockHeight) -> BlockHeight {
    let h = u32::from(target_height);
    // `BlockHeight`'s delta addition saturates at `u32::MAX`.
    BlockHeight::from_u32(h - (h % EXPIRY_MODULUS)) + EXPIRY_WINDOW
}

/// The interval, in blocks, between the durable anchor checkpoints a wallet retains, and equally the
/// grid a [ZIP 318] pool-crossing transfer anchors to.
///
/// A height `h` is a BOUNDARY of this interval exactly when `h` is a multiple of it (see
/// [`Self::is_boundary`]). Those are the heights whose checkpoints a wallet keeps alive past
/// ordinary pruning, and the only tree states a pool crossing may be proved against. A crossing is
/// proved long after its boundary has passed, so the grid a wallet retains and the grid a crossing
/// anchors to must be the same — which is why this is one type rather than one per crate.
///
/// The interval is a modulus, so it is necessarily non-zero.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorBucketInterval(NonZeroU32);

impl AnchorBucketInterval {
    /// The interval specified by [ZIP 318]: 144 blocks, about three hours (8 per day) at the Zcash
    /// ~75-second target block spacing.
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

    /// Returns the interval as a number of blocks.
    pub fn block_count(&self) -> NonZeroU32 {
        self.0
    }

    /// Returns whether `height` is a boundary of this interval, i.e. whether a checkpoint at
    /// `height` is retained as a durable anchor.
    pub fn is_boundary(&self, height: BlockHeight) -> bool {
        u32::from(height) % self.0 == 0
    }

    /// Returns the greatest boundary height that does not exceed `height`, i.e. `height` rounded
    /// DOWN to a multiple of this interval.
    pub fn boundary_at_or_below(&self, height: BlockHeight) -> BlockHeight {
        let h = u32::from(height);
        BlockHeight::from_u32(h - (h % self.0))
    }

    /// Returns the least boundary height that is not below `height`, i.e. `height` rounded UP to a
    /// multiple of this interval. Saturates at [`u32::MAX`].
    pub fn boundary_at_or_above(&self, height: BlockHeight) -> BlockHeight {
        let h = u32::from(height);
        let r = h % self.0;
        BlockHeight::from_u32(if r == 0 {
            h
        } else {
            h.saturating_add(self.0.get() - r)
        })
    }
}

impl Default for AnchorBucketInterval {
    fn default() -> Self {
        Self::ZIP_318
    }
}

/// The [ZIP 318] pool-migration parameters in force for a given network.
///
/// Unlike [`NetworkConstants`], this trait is **unsealed** and every method carries a default body
/// returning the ZIP 318 value. That is deliberate. `NetworkConstants` is blanket-implemented for
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
    /// The grid that durable anchor checkpoints are retained on, and that pool-crossing transfers
    /// are proved against.
    fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
        AnchorBucketInterval::ZIP_318
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

    /// The mean and inclusive cap, in blocks, of the transfer inter-arrival delay distribution.
    fn transfer_delay(&self) -> (NonZeroU32, NonZeroU32) {
        (TRANSFER_DELAY_MEAN, TRANSFER_DELAY_CAP)
    }

    /// The mean and inclusive cap, in blocks, of the preparation inter-arrival delay distribution.
    fn preparation_delay(&self) -> (NonZeroU32, NonZeroU32) {
        (PREP_DELAY_MEAN, PREP_DELAY_CAP)
    }

    /// The maximum anchor age, in boundaries, that a recency-weighted anchor draw will accept.
    fn anchor_age_cap(&self) -> u32 {
        ANCHOR_AGE_CAP
    }

    /// The modulus and window, in blocks, of the canonical rolling expiry window.
    fn expiry_window(&self) -> (u32, u32) {
        (EXPIRY_MODULUS, EXPIRY_WINDOW)
    }

    /// Returns whether `value` is a canonical crossing denomination under these parameters: a
    /// `{1, 2, 5} * 10^k` amount within
    /// `[max_residual_value, denomination_cap]`.
    fn is_canonical_denomination(&self, value: Zatoshis) -> bool {
        is_canonical_within(value, self.max_residual_value(), self.denomination_cap())
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn boundaries_round_to_multiples_of_the_interval() {
        let i = AnchorBucketInterval::ZIP_318;
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
                expiry_height(h),
                expected,
                "offset {offset} must share the expiry"
            );
            // Strictly in the future, and never more than a whole window ahead.
            assert!(expiry_height(h) > h);
            assert!(u32::from(expiry_height(h)) - u32::from(h) <= EXPIRY_WINDOW);
        }

        // The next period moves to the next shared expiry.
        let next = BlockHeight::from_u32(period_start + EXPIRY_MODULUS);
        assert_eq!(
            expiry_height(next),
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
        impl PoolMigrationConstants for Specified {}

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
            fn denomination_cap(&self) -> Zatoshis {
                Zatoshis::const_from_u64(COIN)
            }
        }

        let two_zec = Zatoshis::const_from_u64(2 * COIN);
        assert!(is_canonical_denomination(two_zec));
        assert!(!SmallCap.is_canonical_denomination(two_zec));
        assert!(SmallCap.is_canonical_denomination(Zatoshis::const_from_u64(COIN)));
    }
}
