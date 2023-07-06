use std::ops::Range;

use zcash_primitives::consensus::BlockHeight;

/// Scanning range priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanPriority {
    /// Block ranges that have already been scanned have lowest priority.
    Scanned,
    /// Block ranges to be scanned to advance the fully-scanned height.
    Historic,
    /// Block ranges adjacent to wallet open heights.
    OpenAdjacent,
    /// Blocks that must be scanned to complete note commitment tree shards adjacent to found notes.
    FoundNote,
    /// Blocks that must be scanned to complete the latest note commitment tree shard.
    ChainTip,
    /// A previously-scanned range that must be verified has highest priority.
    Verify,
}

/// A range of blocks to be scanned, along with its associated priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRange {
    block_range: Range<BlockHeight>,
    priority: ScanPriority,
}

impl ScanRange {
    /// Constructs a scan range from its constituent parts.
    pub fn from_parts(block_range: Range<BlockHeight>, priority: ScanPriority) -> Self {
        assert!(block_range.end >= block_range.start);
        ScanRange {
            block_range,
            priority,
        }
    }

    /// Returns the range of block heights to be scanned.
    pub fn block_range(&self) -> &Range<BlockHeight> {
        &self.block_range
    }

    /// Returns the priority with which the scan range should be scanned.
    pub fn priority(&self) -> ScanPriority {
        self.priority
    }

    /// Returns whether or not the scan range is empty.
    pub fn is_empty(&self) -> bool {
        self.block_range.end == self.block_range.start
    }

    /// Returns the number of blocks in the scan range.
    pub fn len(&self) -> usize {
        usize::try_from(u32::from(self.block_range.end) - u32::from(self.block_range.start))
            .unwrap()
    }

    /// Shifts the start of the block range to the right if `block_height >
    /// self.block_range().start`. Returns `None` if the resulting range would
    /// be empty.
    pub fn truncate_start(&self, block_height: BlockHeight) -> Option<Self> {
        if block_height >= self.block_range.end {
            None
        } else {
            Some(ScanRange {
                block_range: block_height..self.block_range.end,
                priority: self.priority,
            })
        }
    }

    /// Shifts the end of the block range to the left if `block_height <
    /// self.block_range().end`. Returns `None` if the resulting range would
    /// be empty.
    pub fn truncate_end(&self, block_height: BlockHeight) -> Option<Self> {
        if block_height <= self.block_range.start {
            None
        } else {
            Some(ScanRange {
                block_range: self.block_range.start..block_height,
                priority: self.priority,
            })
        }
    }

    /// Splits this scan range at the specified height, such that the provided height becomes the
    /// end of the first range returned and the start of the second. Returns `None` if
    /// `p <= self.block_range().start || p >= self.block_range().end`.
    pub fn split_at(&self, p: BlockHeight) -> Option<(Self, Self)> {
        if p > self.block_range.start && p < self.block_range.end {
            Some((
                ScanRange {
                    block_range: self.block_range.start..p,
                    priority: self.priority,
                },
                ScanRange {
                    block_range: p..self.block_range.end,
                    priority: self.priority,
                },
            ))
        } else {
            None
        }
    }
}
