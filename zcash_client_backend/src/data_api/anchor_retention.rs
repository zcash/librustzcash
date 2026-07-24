//! Durable anchor-checkpoint retention: the block-height grid on which note commitment tree
//! checkpoints are kept alive past the ordinary pruning window.
//!
//! A [ZIP 318] pool migration proves each pool-crossing transfer against the note commitment tree
//! state at a BOUNDARY block rather than at the chain tip, so that many wallets' transfers share a
//! small set of common anchors instead of each pinning a unique recent block. A transfer is proved
//! long after its boundary has passed, so the boundary's checkpoint must still be present in the
//! wallet's tree at proving time — ordinary checkpoint pruning would have discarded it. Retention
//! exempts the boundary checkpoints from that pruning.
//!
//! [`AnchorRetentionInterval`] defines the grid, and owns the arithmetic that decides whether a
//! height is a boundary. The migration scheduler MUST draw its anchors from the same grid the
//! wallet retains: a transfer anchored to a height the wallet did not retain cannot be proved. See
//! [`WalletRead::anchor_retention_interval`], the accessor through which a migration reads the grid
//! back off the wallet that maintains it.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318
//! [`WalletRead::anchor_retention_interval`]: super::WalletRead::anchor_retention_interval

use core::num::NonZeroU32;
use std::collections::BTreeSet;

use zcash_protocol::consensus::BlockHeight;

/// The interval, in blocks, between the durable anchor checkpoints a wallet retains.
///
/// A height `h` is a BOUNDARY of this interval exactly when `h` is a multiple of it (see
/// [`Self::is_boundary`]); those are the heights whose checkpoints are retained, and the only tree
/// states a migration transfer may anchor to. The interval is a modulus, so it is necessarily
/// non-zero.
///
/// The value recommended for use with this crate is supplied by the [`Default`] implementation,
/// which is [`Self::ZIP_318`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorRetentionInterval(NonZeroU32);

impl AnchorRetentionInterval {
    /// The interval specified by [ZIP 318]: 144 blocks, roughly three hours (8 per day) at the
    /// Zcash ~75-second target block spacing.
    ///
    /// [ZIP 318]: https://zips.z.cash/zip-0318
    pub const ZIP_318: Self = Self(NonZeroU32::new(144).expect("144 is nonzero"));

    /// Constructs an interval other than the [ZIP 318] one.
    ///
    /// A wallet on the production network MUST use [`Self::ZIP_318`]: the anonymity set a shared
    /// anchor provides is exactly the set of transfers that chose the same boundary, so a wallet
    /// retaining (and anchoring to) a different grid than its peers is distinguishable from them.
    /// A shorter interval is useful on test networks, where waiting out 144-block buckets makes
    /// exercising a migration impractical.
    ///
    /// This constructor is only available under the `unstable` feature, as it is not recommended
    /// for general use.
    ///
    /// [ZIP 318]: https://zips.z.cash/zip-0318
    #[cfg(any(test, feature = "test-dependencies", feature = "unstable"))]
    pub const fn custom(blocks: NonZeroU32) -> Self {
        Self(blocks)
    }

    /// Reconstructs an interval from a block count that was previously persisted, for a store
    /// reading back its own durable state.
    ///
    /// This is the inverse of [`Self::block_count`], and is not a way to CHOOSE an interval: a
    /// caller deciding what grid to retain on wants [`Self::ZIP_318`] or, deliberately and on a
    /// test network only, [`Self::custom`].
    pub const fn from_stored_block_count(blocks: NonZeroU32) -> Self {
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

impl Default for AnchorRetentionInterval {
    fn default() -> Self {
        Self::ZIP_318
    }
}

/// The anchor-retention policy in force while a range of blocks is being added to the wallet: the
/// set of grids whose boundaries are retained, and the height from which retention applies.
///
/// Retention applies only from [`Self::from_height`] upward: below the network upgrade that
/// introduces the destination pool there are no migration transfers to anchor, so retaining
/// checkpoints there would consume storage to no purpose.
///
/// The policy holds a SET of intervals rather than one because a wallet may owe retention to more
/// than one grid at a time. The note commitment trees are wallet-wide while a pool migration is
/// per-account, so two accounts migrating under different intervals each need their own boundaries
/// kept; and a migration already committed under one grid must keep being retained even if the
/// wallet is later configured with a different one, or the boundaries its transfers are anchored to
/// would be pruned out from under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRetention {
    from_height: BlockHeight,
    intervals: BTreeSet<AnchorRetentionInterval>,
}

impl AnchorRetention {
    /// Constructs a retention policy that retains the checkpoint at every boundary of `interval`
    /// at or above `from_height`.
    pub fn new(from_height: BlockHeight, interval: AnchorRetentionInterval) -> Self {
        Self {
            from_height,
            intervals: core::iter::once(interval).collect(),
        }
    }

    /// Constructs a retention policy that retains the checkpoint at every height that is a boundary
    /// of ANY of `intervals`, at or above `from_height`. Returns `None` if `intervals` is empty,
    /// there then being nothing to retain.
    pub fn union(
        from_height: BlockHeight,
        intervals: impl IntoIterator<Item = AnchorRetentionInterval>,
    ) -> Option<Self> {
        let intervals: BTreeSet<AnchorRetentionInterval> = intervals.into_iter().collect();
        (!intervals.is_empty()).then_some(Self {
            from_height,
            intervals,
        })
    }

    /// The height at or above which anchor retention applies (the activation height of the network
    /// upgrade that enables pool migration).
    pub fn from_height(&self) -> BlockHeight {
        self.from_height
    }

    /// The grids whose boundaries are retained as durable anchors.
    pub fn intervals(&self) -> &BTreeSet<AnchorRetentionInterval> {
        &self.intervals
    }

    /// Returns whether the checkpoint at `height` should be retained as a durable anchor under this
    /// policy: `height` is at or above [`Self::from_height`] and is a boundary of at least one of
    /// [`Self::intervals`].
    pub fn retains(&self, height: BlockHeight) -> bool {
        height >= self.from_height && self.intervals.iter().any(|i| i.is_boundary(height))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    fn interval(blocks: u32) -> AnchorRetentionInterval {
        AnchorRetentionInterval::custom(NonZeroU32::new(blocks).expect("nonzero"))
    }

    /// An empty grid set means there is nothing to retain, which the constructor reports as `None`
    /// rather than as a policy that silently retains nothing.
    #[test]
    fn union_of_no_intervals_is_none() {
        assert!(AnchorRetention::union(BlockHeight::from_u32(0), []).is_none());
        assert!(
            AnchorRetention::union(BlockHeight::from_u32(0), [AnchorRetentionInterval::ZIP_318])
                .is_some()
        );
    }

    #[test]
    fn zip_318_is_the_default() {
        assert_eq!(AnchorRetentionInterval::default(), interval(144));
        assert_eq!(AnchorRetentionInterval::ZIP_318.block_count().get(), 144);
    }

    #[test]
    fn zip_318_boundaries() {
        let i = AnchorRetentionInterval::ZIP_318;
        for (height, below, above) in [
            (0u32, 0u32, 0u32),
            (1, 0, 144),
            (143, 0, 144),
            (144, 144, 144),
            (145, 144, 288),
            (1_000_000, 999_936, 1_000_080),
        ] {
            let h = BlockHeight::from_u32(height);
            assert_eq!(
                u32::from(i.boundary_at_or_below(h)),
                below,
                "below {height}"
            );
            assert_eq!(
                u32::from(i.boundary_at_or_above(h)),
                above,
                "above {height}"
            );
        }
        assert!(i.is_boundary(BlockHeight::from_u32(288)));
        assert!(!i.is_boundary(BlockHeight::from_u32(289)));
    }

    proptest! {
        /// Rounding down yields a boundary that does not exceed the height and is within one
        /// interval of it; rounding up yields a boundary that is not below it, likewise within one
        /// interval (except where the round-up saturates).
        #[test]
        fn boundary_rounding_props(h in 0u32..5_000_000, blocks in 1u32..10_000) {
            let i = interval(blocks);
            let height = BlockHeight::from_u32(h);

            let below = u32::from(i.boundary_at_or_below(height));
            prop_assert!(i.is_boundary(BlockHeight::from_u32(below)));
            prop_assert!(below <= h);
            prop_assert!(h - below < blocks);

            let above = u32::from(i.boundary_at_or_above(height));
            prop_assert!(i.is_boundary(BlockHeight::from_u32(above)));
            prop_assert!(above >= h);
            prop_assert!(above - h < blocks);
        }

        /// A height is a boundary exactly when rounding it in either direction leaves it fixed.
        #[test]
        fn is_boundary_agrees_with_rounding(h in 0u32..5_000_000, blocks in 1u32..10_000) {
            let i = interval(blocks);
            let height = BlockHeight::from_u32(h);
            prop_assert_eq!(i.is_boundary(height), i.boundary_at_or_below(height) == height);
            prop_assert_eq!(i.is_boundary(height), i.boundary_at_or_above(height) == height);
        }

        /// A policy retains exactly the boundaries at or above its floor.
        #[test]
        fn retention_policy_props(
            floor in 0u32..1_000_000,
            offset in 0u32..2_000,
            blocks in 1u32..500,
        ) {
            let i = interval(blocks);
            let policy = AnchorRetention::new(BlockHeight::from_u32(floor), i);
            let h = BlockHeight::from_u32(floor.saturating_sub(1_000).saturating_add(offset));
            prop_assert_eq!(policy.retains(h), h >= BlockHeight::from_u32(floor) && i.is_boundary(h));
        }

        /// A union policy retains a height iff ANY of its grids does, so adding a grid only ever
        /// widens what survives pruning — a migration committed under one interval keeps its
        /// boundaries even once the wallet is retaining on another.
        #[test]
        fn union_retains_every_constituent_grid(
            floor in 0u32..100_000,
            offset in 0u32..5_000,
            a in 1u32..500,
            b in 1u32..500,
        ) {
            let (ia, ib) = (interval(a), interval(b));
            let f = BlockHeight::from_u32(floor);
            let union = AnchorRetention::union(f, [ia, ib]).expect("non-empty");
            let h = BlockHeight::from_u32(floor.saturating_add(offset));

            prop_assert_eq!(
                union.retains(h),
                AnchorRetention::new(f, ia).retains(h) || AnchorRetention::new(f, ib).retains(h)
            );
            // Widening never removes anything either grid alone would have kept.
            for single in [ia, ib] {
                if AnchorRetention::new(f, single).retains(h) {
                    prop_assert!(union.retains(h));
                }
            }
        }
    }
}
