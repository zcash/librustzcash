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

use std::collections::BTreeSet;

use zcash_protocol::{
    consensus::BlockHeight,
    zip318::{AnchorGrid, BlockSpacing},
};

/// The interval, in reference blocks, between the durable anchor checkpoints a wallet retains.
///
/// This is a re-export of [`zcash_protocol::zip318::AnchorBucketInterval`], the single definition
/// shared with `zcash_pool_migration`. The grid a wallet retains its checkpoints on and the grid a
/// pool-crossing transfer anchors to must be the same, so they are one type rather than two kept
/// aligned by a conversion.
///
/// The value recommended for use with this crate is supplied by the [`Default`] implementation,
/// which is `AnchorBucketInterval::ZIP_318`.
pub use zcash_protocol::zip318::AnchorBucketInterval as AnchorRetentionInterval;

/// The anchor-retention policy in force while a range of blocks is being added to the wallet: the
/// set of grids whose boundaries are retained, the block spacing that places those boundaries, and
/// the height from which retention applies.
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
    spacing: BlockSpacing,
    intervals: BTreeSet<AnchorRetentionInterval>,
}

impl AnchorRetention {
    /// Constructs a retention policy that retains the checkpoint at every boundary of `interval`
    /// on a chain with the given `spacing`, at or above `from_height`.
    pub fn new(
        from_height: BlockHeight,
        spacing: BlockSpacing,
        interval: AnchorRetentionInterval,
    ) -> Self {
        Self {
            from_height,
            spacing,
            intervals: core::iter::once(interval).collect(),
        }
    }

    /// Constructs a retention policy that retains the checkpoint at every height that is a boundary
    /// of ANY of `intervals` on a chain with the given `spacing`, at or above `from_height`. Returns
    /// `None` if `intervals` is empty, there then being nothing to retain.
    pub fn union(
        from_height: BlockHeight,
        spacing: BlockSpacing,
        intervals: impl IntoIterator<Item = AnchorRetentionInterval>,
    ) -> Option<Self> {
        let intervals: BTreeSet<AnchorRetentionInterval> = intervals.into_iter().collect();
        (!intervals.is_empty()).then_some(Self {
            from_height,
            spacing,
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

    /// The block spacing that places the boundaries of [`Self::intervals`].
    pub fn spacing(&self) -> BlockSpacing {
        self.spacing
    }

    /// The boundary grid of each retained interval.
    fn grids(&self) -> impl Iterator<Item = AnchorGrid> + '_ {
        self.intervals
            .iter()
            .map(|interval| AnchorGrid::new(*interval, self.spacing))
    }

    /// Returns whether the checkpoint at `height` should be retained as a durable anchor under this
    /// policy: `height` is at or above [`Self::from_height`] and is a boundary of at least one of
    /// [`Self::intervals`].
    pub fn retains(&self, height: BlockHeight) -> bool {
        height >= self.from_height && self.grids().any(|grid| grid.is_boundary(height))
    }

    /// Returns every height in `range` whose checkpoint this policy retains, ascending.
    ///
    /// This is the enumeration form of [`Self::retains`]: a height is in the result exactly when
    /// `range` contains it and [`Self::retains`] holds for it. It exists so that a caller adding a
    /// scanned range of blocks can CREATE the checkpoints the policy will need retained — a
    /// boundary block containing no note commitments produces no checkpoint of its own, and a
    /// policy can only keep alive a checkpoint that exists.
    pub fn retained_in_range(
        &self,
        range: core::ops::RangeInclusive<BlockHeight>,
    ) -> BTreeSet<BlockHeight> {
        let start = core::cmp::max(*range.start(), self.from_height);
        let end = *range.end();
        self.grids()
            .flat_map(|grid| {
                // The grid's rounding saturates at the top of the height range, so a height it
                // returns there may not be a boundary, and the walk stops once it stops rising.
                core::iter::successors(Some(grid.boundary_at_or_above(start)), move |boundary| {
                    let next = grid.boundary_after(*boundary);
                    (next > *boundary).then_some(next)
                })
                .take_while(move |boundary| *boundary <= end)
                .filter(move |boundary| grid.is_boundary(*boundary))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::num::NonZeroU32;

    use proptest::prelude::*;

    fn interval(blocks: u32) -> AnchorRetentionInterval {
        AnchorRetentionInterval::custom(NonZeroU32::new(blocks).expect("nonzero"))
    }

    /// An empty grid set means there is nothing to retain, which the constructor reports as `None`
    /// rather than as a policy that silently retains nothing.
    #[test]
    fn union_of_no_intervals_is_none() {
        assert!(
            AnchorRetention::union(BlockHeight::from_u32(0), BlockSpacing::UNIFORM, []).is_none()
        );
        assert!(
            AnchorRetention::union(
                BlockHeight::from_u32(0),
                BlockSpacing::UNIFORM,
                [AnchorRetentionInterval::ZIP_318]
            )
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
                u32::from(AnchorGrid::new(i, BlockSpacing::UNIFORM).boundary_at_or_below(h)),
                below,
                "below {height}"
            );
            assert_eq!(
                u32::from(AnchorGrid::new(i, BlockSpacing::UNIFORM).boundary_at_or_above(h)),
                above,
                "above {height}"
            );
        }
        assert!(AnchorGrid::new(i, BlockSpacing::UNIFORM).is_boundary(BlockHeight::from_u32(288)));
        assert!(!AnchorGrid::new(i, BlockSpacing::UNIFORM).is_boundary(BlockHeight::from_u32(289)));
    }

    /// The enumeration clamps to the policy's floor, includes both endpoints of the range, and
    /// yields the union of every constituent grid's boundaries.
    #[test]
    fn retained_in_range_examples() {
        let h = BlockHeight::from_u32;
        let heights = |policy: &AnchorRetention, lo: u32, hi: u32| {
            policy
                .retained_in_range(h(lo)..=h(hi))
                .into_iter()
                .map(u32::from)
                .collect::<Vec<_>>()
        };

        let single = AnchorRetention::new(h(25), BlockSpacing::UNIFORM, interval(10));
        // The floor excludes 20 even though it is a boundary within the range.
        assert_eq!(heights(&single, 15, 55), vec![30, 40, 50]);
        // Both endpoints are inclusive.
        assert_eq!(heights(&single, 30, 50), vec![30, 40, 50]);
        // An inverted range is empty rather than an error.
        assert_eq!(heights(&single, 50, 30), Vec::<u32>::new());
        // A range wholly below the floor is empty.
        assert_eq!(heights(&single, 0, 24), Vec::<u32>::new());

        let union =
            AnchorRetention::union(h(0), BlockSpacing::UNIFORM, [interval(10), interval(15)])
                .expect("non-empty");
        // Multiples of 10 and 15, deduplicated at the common multiple 30.
        assert_eq!(heights(&union, 1, 45), vec![10, 15, 20, 30, 40, 45]);
    }

    proptest! {
        /// Rounding down yields a boundary that does not exceed the height and is within one
        /// interval of it; rounding up yields a boundary that is not below it, likewise within one
        /// interval (except where the round-up saturates).
        #[test]
        fn boundary_rounding_props(h in 0u32..5_000_000, blocks in 1u32..10_000) {
            let i = interval(blocks);
            let height = BlockHeight::from_u32(h);

            let below = u32::from(AnchorGrid::new(i, BlockSpacing::UNIFORM).boundary_at_or_below(height));
            prop_assert!(AnchorGrid::new(i, BlockSpacing::UNIFORM).is_boundary(BlockHeight::from_u32(below)));
            prop_assert!(below <= h);
            prop_assert!(h - below < blocks);

            let above = u32::from(AnchorGrid::new(i, BlockSpacing::UNIFORM).boundary_at_or_above(height));
            prop_assert!(AnchorGrid::new(i, BlockSpacing::UNIFORM).is_boundary(BlockHeight::from_u32(above)));
            prop_assert!(above >= h);
            prop_assert!(above - h < blocks);
        }

        /// A height is a boundary exactly when rounding it in either direction leaves it fixed.
        #[test]
        fn is_boundary_agrees_with_rounding(h in 0u32..5_000_000, blocks in 1u32..10_000) {
            let i = interval(blocks);
            let height = BlockHeight::from_u32(h);
            prop_assert_eq!(AnchorGrid::new(i, BlockSpacing::UNIFORM).is_boundary(height), AnchorGrid::new(i, BlockSpacing::UNIFORM).boundary_at_or_below(height) == height);
            prop_assert_eq!(AnchorGrid::new(i, BlockSpacing::UNIFORM).is_boundary(height), AnchorGrid::new(i, BlockSpacing::UNIFORM).boundary_at_or_above(height) == height);
        }

        /// A policy retains exactly the boundaries at or above its floor.
        #[test]
        fn retention_policy_props(
            floor in 0u32..1_000_000,
            offset in 0u32..2_000,
            blocks in 1u32..500,
        ) {
            let i = interval(blocks);
            let policy = AnchorRetention::new(BlockHeight::from_u32(floor), BlockSpacing::UNIFORM, i);
            let h = BlockHeight::from_u32(floor.saturating_sub(1_000).saturating_add(offset));
            prop_assert_eq!(policy.retains(h), h >= BlockHeight::from_u32(floor) && AnchorGrid::new(i, BlockSpacing::UNIFORM).is_boundary(h));
        }

        /// Membership in the enumerated range agrees exactly with the predicate: `h` is in
        /// `retained_in_range(lo..=hi)` iff `lo <= h <= hi` and `retains(h)`.
        #[test]
        fn retained_in_range_agrees_with_retains(
            floor in 0u32..100_000,
            lo in 0u32..200_000,
            len in 0u32..2_000,
            a in 1u32..500,
            b in 1u32..500,
        ) {
            let f = BlockHeight::from_u32(floor);
            let policy = AnchorRetention::union(f, BlockSpacing::UNIFORM, [interval(a), interval(b)]).expect("non-empty");
            let (lo, hi) = (BlockHeight::from_u32(lo), BlockHeight::from_u32(lo + len));
            let enumerated = policy.retained_in_range(lo..=hi);

            for h in u32::from(lo)..=u32::from(hi) {
                let h = BlockHeight::from_u32(h);
                prop_assert_eq!(
                    enumerated.contains(&h),
                    policy.retains(h),
                    "height {:?}", h
                );
            }
            // Nothing outside the range is ever emitted.
            for h in &enumerated {
                prop_assert!((lo..=hi).contains(h));
            }
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
            let union = AnchorRetention::union(f, BlockSpacing::UNIFORM, [ia, ib]).expect("non-empty");
            let h = BlockHeight::from_u32(floor.saturating_add(offset));

            prop_assert_eq!(
                union.retains(h),
                AnchorRetention::new(f, BlockSpacing::UNIFORM, ia).retains(h) || AnchorRetention::new(f, BlockSpacing::UNIFORM, ib).retains(h)
            );
            // Widening never removes anything either grid alone would have kept.
            for single in [ia, ib] {
                if AnchorRetention::new(f, BlockSpacing::UNIFORM, single).retains(h) {
                    prop_assert!(union.retains(h));
                }
            }
        }
    }

    proptest! {
        /// From NU7 activation, retention keeps only the boundaries of the scaled grid, and the
        /// enumeration form agrees with the predicate across activation.
        #[test]
        fn retention_follows_the_scaled_grid_from_nu7(
            activation in 0u32..2_000,
            blocks in 1u32..50,
            start in 0u32..3_000,
            len in 0u32..1_000,
        ) {
            let spacing = BlockSpacing::with_nu7_activation(BlockHeight::from_u32(activation));
            let policy = AnchorRetention::new(BlockHeight::from_u32(0), spacing, interval(blocks));
            let range = BlockHeight::from_u32(start)..=BlockHeight::from_u32(start + len);
            let expected: BTreeSet<BlockHeight> = (start..=start + len)
                .map(BlockHeight::from_u32)
                .filter(|h| policy.retains(*h))
                .collect();
            prop_assert_eq!(policy.retained_in_range(range), expected);
            for h in start..=start + len {
                if h >= activation && policy.retains(BlockHeight::from_u32(h)) {
                    prop_assert_eq!(
                        h % (zcash_protocol::consensus::NU7_POW_TARGET_SPACING_RATIO * blocks),
                        0
                    );
                }
            }
        }
    }
}

/// The [ZIP 318] pool-migration parameters in force for a particular wallet: the specified values,
/// with the anchor bucket grid taken from the grid that wallet actually retains, on the block
/// spacing of the wallet's network.
///
/// The wallet is the authority on the grid, because it is the side that keeps the checkpoints
/// alive. A crossing anchored to a boundary the wallet did not retain cannot be proved, so every
/// decision that depends on the grid — whether to bucket an anchor, and whether the resulting
/// transaction is a canonical crossing — must consult the same source. Reading the grid from the
/// network defaults instead would agree with the wallet only by coincidence, and silently disagree
/// for any wallet configured with a different interval.
///
/// Obtained from [`WalletRead::pool_migration_params`].
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
/// [`WalletRead::pool_migration_params`]: super::WalletRead::pool_migration_params
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolMigrationParams {
    spacing: BlockSpacing,
    interval: AnchorRetentionInterval,
}

impl PoolMigrationParams {
    /// Constructs the parameters for a wallet on a chain with the given `spacing` that retains
    /// anchors on `interval`. Every other ZIP 318 value takes its specified default.
    pub fn new(spacing: BlockSpacing, interval: AnchorRetentionInterval) -> Self {
        Self { spacing, interval }
    }
}

impl zcash_protocol::zip318::PoolMigrationConstants for PoolMigrationParams {
    fn anchor_bucket_interval(&self) -> AnchorRetentionInterval {
        self.interval
    }

    fn block_spacing(&self) -> BlockSpacing {
        self.spacing
    }
}
