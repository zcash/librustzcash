




use std::{
    ops::{Deref, DerefMut, Range},
};



use zcash_primitives::{
    consensus::{BlockHeight},
};


use zcash_client_backend::{
    data_api::{
        scanning::{spanning_tree::SpanningTree, ScanPriority},
    },
};

use zcash_client_backend::data_api::{
    scanning::ScanRange,
};



#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "orchard")]
use {
    zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
    zcash_client_backend::wallet::WalletOrchardOutput,
};

use crate::error::Error;

/// A queue of scanning ranges. Contains the start and end heights of each range, along with the
/// priority of scanning that range.
pub struct ScanQueue(Vec<(BlockHeight, BlockHeight, ScanPriority)>);

impl ScanQueue {
    pub fn new() -> Self {
        ScanQueue(Vec::new())
    }

    pub fn suggest_scan_ranges(&self, min_priority: ScanPriority) -> Vec<ScanRange> {
        let mut priorities: Vec<_> = self
            .0
            .iter()
            .filter(|(_, _, p)| *p >= min_priority)
            .collect();
        priorities.sort_by(|(_, _, a), (_, _, b)| b.cmp(a));

        priorities
            .into_iter()
            .map(|(start, end, priority)| {
                let range = Range {
                    start: *start,
                    end: *end,
                };
                ScanRange::from_parts(range, *priority)
            })
            .collect()
    }
    pub fn insert_queue_entries<'a>(
        &mut self,
        entries: impl Iterator<Item = &'a ScanRange>,
    ) -> Result<(), Error> {
        for entry in entries {
            if entry.block_range().start >= entry.block_range().end {
                return Err(Error::InvalidScanRange(
                    entry.block_range().start,
                    entry.block_range().end,
                    "start must be less than end".to_string(),
                ));
            }

            for (start, end, _) in &self.0 {
                if *start == entry.block_range().start || *end == entry.block_range().end {
                    return Err(Error::InvalidScanRange(
                        entry.block_range().start,
                        entry.block_range().end,
                        "at least part of range is already covered by another range".to_string(),
                    ));
                }
            }

            self.0.push((
                entry.block_range().start,
                entry.block_range().end,
                entry.priority(),
            ));
        }
        Ok(())
    }
    pub fn replace_queue_entries(
        &mut self,
        query_range: &Range<BlockHeight>,
        entries: impl Iterator<Item = ScanRange>,
        force_rescans: bool,
    ) -> Result<(), Error> {
        let (to_create, to_delete_ends) = {
            let mut q_ranges: Vec<_> = self
                .0
                .iter()
                .filter(|(start, end, _)| {
                    //  Ignore ranges that do not overlap and are not adjacent to the query range.
                    !(start > &query_range.end || &query_range.start > end)
                })
                .collect();
            q_ranges.sort_by(|(_, end_a, _), (_, end_b, _)| end_a.cmp(end_b));

            // Iterate over the ranges in the scan queue that overlap the range that we have
            // identified as needing to be fully scanned. For each such range add it to the
            // spanning tree (these should all be nonoverlapping ranges, but we might coalesce
            // some in the process).
            let mut to_create: Option<SpanningTree> = None;
            let mut to_delete_ends: Vec<BlockHeight> = vec![];

            let q_ranges = q_ranges.into_iter();
            for (start, end, priority) in q_ranges {
                let entry = ScanRange::from_parts(
                    Range {
                        start: *start,
                        end: *end,
                    },
                    *priority,
                );
                to_delete_ends.push(entry.block_range().end);
                to_create = if let Some(cur) = to_create {
                    Some(cur.insert(entry, force_rescans))
                } else {
                    Some(SpanningTree::Leaf(entry))
                };
            }

            // Update the tree that we read from the database, or if we didn't find any ranges
            // start with the scanned range.
            for entry in entries {
                to_create = if let Some(cur) = to_create {
                    Some(cur.insert(entry, force_rescans))
                } else {
                    Some(SpanningTree::Leaf(entry))
                };
            }
            (to_create, to_delete_ends)
        };

        if let Some(tree) = to_create {
            self.0.retain(|(_, block_range_end, _)| {
                // if the block_range_end is equal to any in to_delete_ends, remove it
                !to_delete_ends.contains(block_range_end)
            });
            let scan_ranges = tree.into_vec();
            self.insert_queue_entries(scan_ranges.iter());
        }
        Ok(())
    }
}

impl IntoIterator for ScanQueue {
    type Item = (BlockHeight, BlockHeight, ScanPriority);
    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// We deref to slice so that we can reuse the slice impls
impl Deref for ScanQueue {
    type Target = [(BlockHeight, BlockHeight, ScanPriority)];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}
impl DerefMut for ScanQueue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}
