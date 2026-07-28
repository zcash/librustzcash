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

use zcash_protocol::consensus::BlockHeight;

/// The interval, in blocks, between the durable anchor checkpoints a wallet retains.
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

    use core::num::NonZeroU32;

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

/// The [ZIP 318] pool-migration parameters in force for a particular wallet: the specified values,
/// with the anchor bucket grid taken from the grid that wallet actually retains.
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
    interval: AnchorRetentionInterval,
}

impl PoolMigrationParams {
    /// Constructs the parameters for a wallet retaining anchors on `interval`. Every other ZIP 318
    /// value takes its specified default.
    pub fn new(interval: AnchorRetentionInterval) -> Self {
        Self { interval }
    }
}

impl From<AnchorRetentionInterval> for PoolMigrationParams {
    fn from(interval: AnchorRetentionInterval) -> Self {
        Self::new(interval)
    }
}

impl zcash_protocol::zip318::PoolMigrationConstants for PoolMigrationParams {
    fn anchor_bucket_interval(&self) -> AnchorRetentionInterval {
        self.interval
    }
}
