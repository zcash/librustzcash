use rusqlite::{self, named_params, types::Value, OptionalExtension};
use std::cmp::{max, min, Ordering};
use std::collections::BTreeSet;
use std::ops::{Not, Range};
use std::rc::Rc;
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};

use incrementalmerkletree::{Address, Position};
use zcash_primitives::consensus::{self, BlockHeight, NetworkUpgrade};

use zcash_client_backend::data_api::SAPLING_SHARD_HEIGHT;

use crate::error::SqliteClientError;
use crate::{PRUNING_DEPTH, VALIDATION_DEPTH};

use super::block_height_extrema;

#[derive(Debug, Clone, Copy)]
enum Insert {
    Left,
    Right,
}

impl Not for Insert {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Insert::Left => Insert::Right,
            Insert::Right => Insert::Left,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dominance {
    Left,
    Right,
    Equal,
}

impl From<Insert> for Dominance {
    fn from(value: Insert) -> Self {
        match value {
            Insert::Left => Dominance::Left,
            Insert::Right => Dominance::Right,
        }
    }
}

pub(crate) fn parse_priority_code(code: i64) -> Option<ScanPriority> {
    use ScanPriority::*;
    match code {
        10 => Some(Scanned),
        20 => Some(Historic),
        30 => Some(OpenAdjacent),
        40 => Some(FoundNote),
        50 => Some(ChainTip),
        60 => Some(Verify),
        _ => None,
    }
}

pub(crate) fn priority_code(priority: &ScanPriority) -> i64 {
    use ScanPriority::*;
    match priority {
        Scanned => 10,
        Historic => 20,
        OpenAdjacent => 30,
        FoundNote => 40,
        ChainTip => 50,
        Verify => 60,
    }
}

pub(crate) fn suggest_scan_ranges(
    conn: &rusqlite::Connection,
    min_priority: ScanPriority,
) -> Result<Vec<ScanRange>, SqliteClientError> {
    let mut stmt_scan_ranges = conn.prepare_cached(
        "SELECT block_range_start, block_range_end, priority
         FROM scan_queue
         WHERE priority >= :min_priority
         ORDER BY priority DESC, block_range_end DESC",
    )?;

    let mut rows =
        stmt_scan_ranges.query(named_params![":min_priority": priority_code(&min_priority)])?;

    let mut result = vec![];
    while let Some(row) = rows.next()? {
        let range = Range {
            start: row.get::<_, u32>(0).map(BlockHeight::from)?,
            end: row.get::<_, u32>(1).map(BlockHeight::from)?,
        };
        let code = row.get::<_, i64>(2)?;
        let priority = parse_priority_code(code).ok_or_else(|| {
            SqliteClientError::CorruptedData(format!("scan priority not recognized: {}", code))
        })?;

        result.push(ScanRange::from_parts(range, priority));
    }

    Ok(result)
}

// This implements the dominance rule for range priority. If the inserted range's priority is
// `Verify`, this replaces any existing priority. Otherwise, if the current priority is
// `Scanned`, this overwrites any priority
fn update_priority(current: ScanPriority, inserted: ScanPriority) -> ScanPriority {
    match (current, inserted) {
        (_, ScanPriority::Verify) => ScanPriority::Verify,
        (ScanPriority::Scanned, _) => ScanPriority::Scanned,
        (_, ScanPriority::Scanned) => ScanPriority::Scanned,
        (a, b) => max(a, b),
    }
}

fn dominance(current: &ScanPriority, inserted: &ScanPriority, insert: Insert) -> Dominance {
    match (current, inserted) {
        (_, ScanPriority::Verify | ScanPriority::Scanned) => Dominance::from(insert),
        (ScanPriority::Scanned, _) => Dominance::from(!insert),
        (a, b) => match a.cmp(b) {
            Ordering::Less => Dominance::from(insert),
            Ordering::Equal => Dominance::Equal,
            Ordering::Greater => Dominance::from(!insert),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeOrdering {
    LeftFirstDisjoint,
    LeftFirstOverlap,
    LeftContained,
    Equal,
    RightContained,
    RightFirstOverlap,
    RightFirstDisjoint,
}

impl RangeOrdering {
    fn cmp<A: Ord>(a: &Range<A>, b: &Range<A>) -> Self {
        use RangeOrdering::*;
        assert!(a.start <= a.end && b.start <= b.end);
        if a.end <= b.start {
            LeftFirstDisjoint
        } else if b.end <= a.start {
            RightFirstDisjoint
        } else if a.start < b.start {
            if a.end >= b.end {
                RightContained
            } else {
                LeftFirstOverlap
            }
        } else if b.start < a.start {
            if b.end >= a.end {
                LeftContained
            } else {
                RightFirstOverlap
            }
        } else {
            // a.start == b.start
            match a.end.cmp(&b.end) {
                Ordering::Less => LeftContained,
                Ordering::Equal => Equal,
                Ordering::Greater => RightContained,
            }
        }
    }
}

enum Joined {
    One(ScanRange),
    Two(ScanRange, ScanRange),
    Three(ScanRange, ScanRange, ScanRange),
}

fn join_nonoverlapping(left: ScanRange, right: ScanRange) -> Joined {
    assert!(left.block_range().end <= right.block_range().start);

    if left.block_range().end == right.block_range().start {
        if left.priority() == right.priority() {
            Joined::One(ScanRange::from_parts(
                left.block_range().start..right.block_range().end,
                left.priority(),
            ))
        } else {
            Joined::Two(left, right)
        }
    } else {
        // there is a gap that will need to be filled
        let gap = ScanRange::from_parts(
            left.block_range().end..right.block_range().start,
            ScanPriority::Historic,
        );

        match join_nonoverlapping(left, gap) {
            Joined::One(left) => join_nonoverlapping(left, right),
            Joined::Two(left, gap) => match join_nonoverlapping(gap, right) {
                Joined::One(right) => Joined::Two(left, right),
                Joined::Two(gap, right) => Joined::Three(left, gap, right),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}

fn insert(current: ScanRange, to_insert: ScanRange) -> Joined {
    fn join_overlapping(left: ScanRange, right: ScanRange, insert: Insert) -> Joined {
        assert!(
            left.block_range().start <= right.block_range().start
                && left.block_range().end > right.block_range().start
        );

        // recompute the range dominance based upon the queue entry priorities
        let dominance = match insert {
            Insert::Left => dominance(&right.priority(), &left.priority(), insert),
            Insert::Right => dominance(&left.priority(), &right.priority(), insert),
        };

        match dominance {
            Dominance::Left => {
                if let Some(right) = right.truncate_start(left.block_range().end) {
                    Joined::Two(left, right)
                } else {
                    Joined::One(left)
                }
            }
            Dominance::Equal => Joined::One(ScanRange::from_parts(
                left.block_range().start..max(left.block_range().end, right.block_range().end),
                left.priority(),
            )),
            Dominance::Right => {
                if let Some(left) = left.truncate_end(right.block_range().start) {
                    if let Some(end) = left.truncate_start(right.block_range().end) {
                        Joined::Three(left, right, end)
                    } else {
                        Joined::Two(left, right)
                    }
                } else if let Some(end) = left.truncate_start(right.block_range().end) {
                    Joined::Two(right, end)
                } else {
                    Joined::One(right)
                }
            }
        }
    }

    use RangeOrdering::*;
    match RangeOrdering::cmp(to_insert.block_range(), current.block_range()) {
        LeftFirstDisjoint => join_nonoverlapping(to_insert, current),
        LeftFirstOverlap | RightContained => join_overlapping(to_insert, current, Insert::Left),
        Equal => Joined::One(ScanRange::from_parts(
            to_insert.block_range().clone(),
            update_priority(current.priority(), to_insert.priority()),
        )),
        RightFirstOverlap | LeftContained => join_overlapping(current, to_insert, Insert::Right),
        RightFirstDisjoint => join_nonoverlapping(current, to_insert),
    }
}

#[derive(Debug, Clone)]
enum SpanningTree {
    Leaf(ScanRange),
    Parent {
        span: Range<BlockHeight>,
        left: Box<SpanningTree>,
        right: Box<SpanningTree>,
    },
}

impl SpanningTree {
    fn span(&self) -> Range<BlockHeight> {
        match self {
            SpanningTree::Leaf(entry) => entry.block_range().clone(),
            SpanningTree::Parent { span, .. } => span.clone(),
        }
    }

    fn from_joined(joined: Joined) -> Self {
        match joined {
            Joined::One(entry) => SpanningTree::Leaf(entry),
            Joined::Two(left, right) => SpanningTree::Parent {
                span: left.block_range().start..right.block_range().end,
                left: Box::new(SpanningTree::Leaf(left)),
                right: Box::new(SpanningTree::Leaf(right)),
            },
            Joined::Three(left, mid, right) => SpanningTree::Parent {
                span: left.block_range().start..right.block_range().end,
                left: Box::new(SpanningTree::Leaf(left)),
                right: Box::new(SpanningTree::Parent {
                    span: mid.block_range().start..right.block_range().end,
                    left: Box::new(SpanningTree::Leaf(mid)),
                    right: Box::new(SpanningTree::Leaf(right)),
                }),
            },
        }
    }

    fn insert(self, to_insert: ScanRange) -> Self {
        match self {
            SpanningTree::Leaf(cur) => Self::from_joined(insert(cur, to_insert)),
            SpanningTree::Parent { span, left, right } => {
                // TODO: this algorithm always preserves the existing partition point, and does not
                // do any rebalancing or unification of ranges within the tree; `into_vec`
                // performes such unification and the tree being unbalanced should be fine given
                // the relatively small number of ranges we should ordinarily be concerned with.
                use RangeOrdering::*;
                match RangeOrdering::cmp(&span, to_insert.block_range()) {
                    LeftFirstDisjoint => {
                        // extend the right-hand branch
                        SpanningTree::Parent {
                            span: left.span().start..to_insert.block_range().end,
                            left,
                            right: Box::new(right.insert(to_insert)),
                        }
                    }
                    LeftFirstOverlap => {
                        let split_point = left.span().end;
                        if split_point > to_insert.block_range().start {
                            let (l_insert, r_insert) = to_insert
                                .split_at(split_point)
                                .expect("Split point is within the range of to_insert");
                            let left = Box::new(left.insert(l_insert));
                            let right = Box::new(right.insert(r_insert));
                            SpanningTree::Parent {
                                span: left.span().start..right.span().end,
                                left,
                                right,
                            }
                        } else {
                            // to_insert is fully contained in or equals the right child
                            SpanningTree::Parent {
                                span: left.span().start
                                    ..max(right.span().end, to_insert.block_range().end),
                                left,
                                right: Box::new(right.insert(to_insert)),
                            }
                        }
                    }
                    RightContained => {
                        // to_insert is fully contained within the current span, so we will insert
                        // into one or both sides
                        let split_point = left.span().end;
                        if to_insert.block_range().start >= split_point {
                            // to_insert is fully contained in the right
                            SpanningTree::Parent {
                                span,
                                left,
                                right: Box::new(right.insert(to_insert)),
                            }
                        } else if to_insert.block_range().end <= split_point {
                            // to_insert is fully contained in the left
                            SpanningTree::Parent {
                                span,
                                left: Box::new(left.insert(to_insert)),
                                right,
                            }
                        } else {
                            // to_insert must be split.
                            let (l_insert, r_insert) = to_insert
                                .split_at(split_point)
                                .expect("Split point is within the range of to_insert");
                            let left = Box::new(left.insert(l_insert));
                            let right = Box::new(right.insert(r_insert));
                            SpanningTree::Parent {
                                span: left.span().start..right.span().end,
                                left,
                                right,
                            }
                        }
                    }
                    Equal => {
                        if left.span().end > to_insert.block_range().start {
                            let (l_insert, r_insert) = to_insert
                                .split_at(left.span().end)
                                .expect("Split point is within the range of to_insert");
                            let left = Box::new(left.insert(l_insert));
                            let right = Box::new(right.insert(r_insert));
                            SpanningTree::Parent {
                                span: left.span().start..right.span().end,
                                left,
                                right,
                            }
                        } else {
                            // to_insert is fully contained in the right subtree
                            right.insert(to_insert)
                        }
                    }
                    LeftContained => {
                        // the current span is fully contained within to_insert, so we will extend
                        // or overwrite both sides
                        let (l_insert, r_insert) = to_insert
                            .split_at(left.span().end)
                            .expect("Split point is within the range of to_insert");
                        let left = Box::new(left.insert(l_insert));
                        let right = Box::new(right.insert(r_insert));
                        SpanningTree::Parent {
                            span: left.span().start..right.span().end,
                            left,
                            right,
                        }
                    }
                    RightFirstOverlap => {
                        let split_point = left.span().end;
                        if split_point < to_insert.block_range().end {
                            let (l_insert, r_insert) = to_insert
                                .split_at(split_point)
                                .expect("Split point is within the range of to_insert");
                            let left = Box::new(left.insert(l_insert));
                            let right = Box::new(right.insert(r_insert));
                            SpanningTree::Parent {
                                span: left.span().start..right.span().end,
                                left,
                                right,
                            }
                        } else {
                            // to_insert is fully contained in or equals the left child
                            SpanningTree::Parent {
                                span: min(to_insert.block_range().start, left.span().start)
                                    ..right.span().end,
                                left: Box::new(left.insert(to_insert)),
                                right,
                            }
                        }
                    }
                    RightFirstDisjoint => {
                        // extend the left-hand branch
                        SpanningTree::Parent {
                            span: to_insert.block_range().start..right.span().end,
                            left: Box::new(left.insert(to_insert)),
                            right,
                        }
                    }
                }
            }
        }
    }

    fn into_vec(self) -> Vec<ScanRange> {
        fn go(acc: &mut Vec<ScanRange>, tree: SpanningTree) {
            match tree {
                SpanningTree::Leaf(entry) => {
                    if let Some(top) = acc.pop() {
                        match join_nonoverlapping(top, entry) {
                            Joined::One(entry) => acc.push(entry),
                            Joined::Two(l, r) => {
                                acc.push(l);
                                acc.push(r);
                            }
                            _ => unreachable!(),
                        }
                    } else {
                        acc.push(entry);
                    }
                }
                SpanningTree::Parent { left, right, .. } => {
                    go(acc, *left);
                    go(acc, *right);
                }
            }
        }

        let mut acc = vec![];
        go(&mut acc, self);
        acc
    }
}

pub(crate) fn insert_queue_entries<'a>(
    conn: &rusqlite::Connection,
    entries: impl Iterator<Item = &'a ScanRange>,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
        VALUES (:block_range_start, :block_range_end, :priority)",
    )?;

    for entry in entries {
        if entry.block_range().end > entry.block_range().start {
            stmt.execute(named_params![
                ":block_range_start": u32::from(entry.block_range().start) ,
                ":block_range_end": u32::from(entry.block_range().end),
                ":priority": priority_code(&entry.priority())
            ])?;
        }
    }

    Ok(())
}

pub(crate) fn replace_queue_entries(
    conn: &rusqlite::Connection,
    query_range: &Range<BlockHeight>,
    mut entries: impl Iterator<Item = ScanRange>,
) -> Result<(), SqliteClientError> {
    let (to_create, to_delete_ends) = {
        let mut suggested_stmt = conn.prepare_cached(
            "SELECT block_range_start, block_range_end, priority
            FROM scan_queue
            WHERE (
                -- the start is contained within the range
                :start >= block_range_start
                AND :start < block_range_end
            )
            OR (
                -- the end is contained within the range
                :end > block_range_start
                AND :end <= block_range_end
            )
            OR (
                -- start..end contains the entire range
                block_range_start >= :start
                AND block_range_end <= :end
            )
            ORDER BY block_range_end",
        )?;

        let mut rows = suggested_stmt.query(named_params![
            ":start": u32::from(query_range.start),
            ":end": u32::from(query_range.end),
        ])?;

        // Iterate over the ranges in the scan queue that overlaps the range that we have
        // identified as needing to be fully scanned. For each such range add it to the
        // spanning tree (these should all be nonoverlapping ranges, but we might coalesce
        // some in the process).
        let mut existing_ranges: Option<SpanningTree> = None;
        let mut to_delete_ends: Vec<Value> = vec![];
        while let Some(row) = rows.next()? {
            let entry = ScanRange::from_parts(
                Range {
                    start: BlockHeight::from(row.get::<_, u32>(0)?),
                    end: BlockHeight::from(row.get::<_, u32>(1)?),
                },
                {
                    let code = row.get::<_, i64>(2)?;
                    parse_priority_code(code).ok_or_else(|| {
                        SqliteClientError::CorruptedData(format!(
                            "scan priority not recognized: {}",
                            code
                        ))
                    })?
                },
            );
            to_delete_ends.push(Value::from(u32::from(entry.block_range().end)));
            existing_ranges = if let Some(cur) = existing_ranges {
                Some(cur.insert(entry))
            } else {
                Some(SpanningTree::Leaf(entry))
            };
        }

        // Update the tree that we read from the database, or if we didn't find any ranges
        // start with the scanned range.
        let mut to_create = match (existing_ranges, entries.next()) {
            (Some(cur), Some(entry)) => Some(cur.insert(entry)),
            (None, Some(entry)) => Some(SpanningTree::Leaf(entry)),
            (Some(cur), None) => Some(cur),
            (None, None) => None,
        };

        for entry in entries {
            to_create = to_create.map(|cur| cur.insert(entry));
        }

        (to_create, to_delete_ends)
    };

    if let Some(tree) = to_create {
        let ends_ptr = Rc::new(to_delete_ends);
        conn.execute(
            "DELETE FROM scan_queue WHERE block_range_end IN rarray(:ends)",
            named_params![":ends": ends_ptr],
        )?;

        let scan_ranges = tree.into_vec();
        insert_queue_entries(conn, scan_ranges.iter())?;
    }

    Ok(())
}

pub(crate) fn scan_complete<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    range: Range<BlockHeight>,
    wallet_note_positions: &[Position],
) -> Result<(), SqliteClientError> {
    // Determine the range of block heights for which we will be updating the scan queue.
    let extended_range = {
        // If notes have been detected in the scan, we need to extend any adjacent un-scanned ranges to
        // include the blocks needed to complete the note commitment tree subtrees containing the
        // positions of the discovered notes. We will query by subtree index to find these bounds.
        let required_subtrees = wallet_note_positions
            .iter()
            .map(|p| Address::above_position(SAPLING_SHARD_HEIGHT.into(), *p).index())
            .collect::<BTreeSet<_>>();

        // we'll either have both min and max bounds, or we'll have neither
        let subtree_bounds = required_subtrees
            .iter()
            .min()
            .zip(required_subtrees.iter().max());

        let mut sapling_shard_end_stmt = conn.prepare_cached(
            "SELECT subtree_end_height
            FROM sapling_tree_shards
            WHERE shard_index = :shard_index",
        )?;

        // if no notes belonging to the wallet were found, so don't need to extend the scanning
        // range suggestions to include the associated subtrees, and our bounds are just the
        // scanned range
        subtree_bounds
            .map(|(min_idx, max_idx)| {
                let range_min = if *min_idx > 0 {
                    // get the block height of the end of the previous shard
                    sapling_shard_end_stmt
                        .query_row(named_params![":shard_index": *min_idx - 1], |row| {
                            row.get::<_, Option<u32>>(0)
                                .map(|opt| opt.map(BlockHeight::from))
                        })
                        .optional()?
                        .flatten()
                } else {
                    // our lower bound is going to be the Sapling activation height
                    params.activation_height(NetworkUpgrade::Sapling)
                };

                // get the block height for the end of the current shard
                let range_max = sapling_shard_end_stmt
                    .query_row(named_params![":shard_index": max_idx], |row| {
                        row.get::<_, Option<u32>>(0)
                            .map(|opt| opt.map(BlockHeight::from))
                    })
                    .optional()?
                    .flatten();

                Ok::<Range<BlockHeight>, rusqlite::Error>(match (range_min, range_max) {
                    (Some(start), Some(end)) => Range { start, end },
                    (Some(start), None) => Range {
                        start,
                        end: range.end,
                    },
                    (None, Some(end)) => Range {
                        start: range.start,
                        end,
                    },
                    (None, None) => range.clone(),
                })
            })
            .transpose()
            .map_err(SqliteClientError::from)
    }?;

    let query_range = extended_range.clone().unwrap_or_else(|| range.clone());

    let scanned = ScanRange::from_parts(range.clone(), ScanPriority::Scanned);
    let extensions = if let Some(extended) = extended_range {
        vec![
            ScanRange::from_parts(extended.start..range.start, ScanPriority::FoundNote),
            ScanRange::from_parts(range.end..extended.end, ScanPriority::FoundNote),
        ]
    } else {
        vec![]
    };

    replace_queue_entries(
        conn,
        &query_range,
        Some(scanned).into_iter().chain(extensions.into_iter()),
    )?;

    Ok(())
}

pub(crate) fn update_chain_tip<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    new_tip: BlockHeight,
) -> Result<(), SqliteClientError> {
    // `ScanRange` uses an exclusive upper bound.
    let chain_end = new_tip + 1;

    // Read the maximum height from the shards table.
    let shard_start_height = conn.query_row(
        "SELECT MAX(subtree_end_height)
        FROM sapling_tree_shards",
        [],
        |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
    )?;

    // Create a scanning range for the fragment of the last shard leading up to new tip.
    // However, only do so if the start of the shard is at a stable height.
    let shard_entry = shard_start_height
        .filter(|h| h < &chain_end)
        .map(|h| ScanRange::from_parts(h..chain_end, ScanPriority::ChainTip));

    // Create scanning ranges to either validate potentially invalid blocks at the wallet's view
    // of the chain tip,
    let tip_entry = block_height_extrema(conn)?.map(|(_, prior_tip)| {
        // If we don't have shard metadata, this means we're doing linear scanning, so create a
        // scan range from the prior tip to the current tip with `Historic` priority.
        if shard_entry.is_none() {
            ScanRange::from_parts(prior_tip..chain_end, ScanPriority::Historic)
        } else {
            // Determine the height to which we expect blocks retrieved from the block source to be stable
            // and not subject to being reorg'ed.
            let stable_height = new_tip.saturating_sub(PRUNING_DEPTH);

            // if the wallet's prior tip is above the stable height, prioritize the range between
            // it and the new tip as `ChainTip`. Otherwise, prioritize the `VALIDATION_DEPTH`
            // blocks above the wallet's prior tip as `Verify`. Since `scan_cached_blocks`
            // retrieves the metadata for the block being connected to, the connectivity to the
            // prior tip will always be checked. Since `Verify` ranges have maximum priority, even
            // if the block source begins downloading blocks from the shard scan range (which ends
            // at the stable height) the scanner should not attempt to scan those blocks until the
            // tip range has been completely checked and any required rewinds have been performed.
            if prior_tip >= stable_height {
                // This may overlap the `shard_entry` range and if so will be coalesced with it.
                ScanRange::from_parts(prior_tip..chain_end, ScanPriority::ChainTip)
            } else {
                // The prior tip is in the range that we now expect to be stable, so we need to verify
                // and advance it up to at most the stable height. The shard entry will then cover
                // the range to the new tip at the lower `ChainTip` priority.
                ScanRange::from_parts(
                    prior_tip..min(stable_height, prior_tip + VALIDATION_DEPTH),
                    ScanPriority::Verify,
                )
            }
        }
    });

    let query_range = match (shard_entry.as_ref(), tip_entry.as_ref()) {
        (Some(se), Some(te)) => Some(Range {
            start: min(se.block_range().start, te.block_range().start),
            end: max(se.block_range().end, te.block_range().end),
        }),
        (Some(se), None) => Some(se.block_range().clone()),
        (None, Some(te)) => Some(te.block_range().clone()),
        (None, None) => None,
    };

    if let Some(query_range) = query_range {
        replace_queue_entries(
            conn,
            &query_range,
            shard_entry.into_iter().chain(tip_entry.into_iter()),
        )?;
    } else {
        // If we have neither shard data nor any existing block data in the database, we should also
        // have no existing scan queue entries and can fall back to linear scanning from Sapling
        // activation.
        if let Some(sapling_activation) = params.activation_height(NetworkUpgrade::Sapling) {
            let scan_range =
                ScanRange::from_parts(sapling_activation..chain_end, ScanPriority::Historic);
            insert_queue_entries(conn, Some(scan_range).iter())?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use incrementalmerkletree::{Hashable, Level};
    use rusqlite::Connection;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_client_backend::data_api::{
        chain::{scan_cached_blocks, CommitmentTreeRoot},
        scanning::{ScanPriority, ScanRange},
        WalletCommitmentTrees, WalletRead, WalletWrite,
    };
    use zcash_primitives::{
        block::BlockHash, consensus::BlockHeight, sapling::Node, transaction::components::Amount,
    };

    use crate::{
        chain::init::init_cache_database,
        tests::{
            self, fake_compact_block, init_test_accounts_table, insert_into_cache,
            sapling_activation_height, AddressType,
        },
        wallet::{init::init_wallet_db, scanning::suggest_scan_ranges},
        BlockDb, WalletDb,
    };

    use super::{RangeOrdering, SpanningTree};

    #[test]
    fn range_ordering() {
        use super::RangeOrdering::*;
        // Equal
        assert_eq!(RangeOrdering::cmp(&(0..1), &(0..1)), Equal);

        // Disjoint or contiguous
        assert_eq!(RangeOrdering::cmp(&(0..1), &(1..2)), LeftFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(1..2), &(0..1)), RightFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(0..1), &(2..3)), LeftFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(2..3), &(0..1)), RightFirstDisjoint);

        // Contained
        assert_eq!(RangeOrdering::cmp(&(1..2), &(0..3)), LeftContained);
        assert_eq!(RangeOrdering::cmp(&(0..3), &(1..2)), RightContained);
        assert_eq!(RangeOrdering::cmp(&(0..1), &(0..3)), LeftContained);
        assert_eq!(RangeOrdering::cmp(&(0..3), &(0..1)), RightContained);
        assert_eq!(RangeOrdering::cmp(&(2..3), &(0..3)), LeftContained);
        assert_eq!(RangeOrdering::cmp(&(0..3), &(2..3)), RightContained);

        // Overlap
        assert_eq!(RangeOrdering::cmp(&(0..2), &(1..3)), LeftFirstOverlap);
        assert_eq!(RangeOrdering::cmp(&(1..3), &(0..2)), RightFirstOverlap);
    }

    fn scan_range(range: Range<u32>, priority: ScanPriority) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from(range.start)..BlockHeight::from(range.end),
            priority,
        )
    }

    fn spanning_tree(to_insert: &[(Range<u32>, ScanPriority)]) -> Option<SpanningTree> {
        to_insert.iter().fold(None, |acc, (range, priority)| {
            let scan_range = scan_range(range.clone(), *priority);
            match acc {
                None => Some(SpanningTree::Leaf(scan_range)),
                Some(t) => Some(t.insert(scan_range)),
            }
        })
    }

    #[test]
    fn spanning_tree_insert_adjacent() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic),
            (3..6, Scanned),
            (6..8, ChainTip),
            (8..10, ChainTip),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic),
                scan_range(3..6, Scanned),
                scan_range(6..10, ChainTip),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_overlaps() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic),
            (2..5, Scanned),
            (6..8, ChainTip),
            (7..10, Scanned),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Historic),
                scan_range(2..5, Scanned),
                scan_range(5..6, Historic),
                scan_range(6..7, ChainTip),
                scan_range(7..10, Scanned),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_rfd_span() {
        use ScanPriority::*;

        // This sequence of insertions causes a RightFirstDisjoint on the last insertion,
        // which originally had a bug that caused the parent's span to only cover its left
        // child. The bug was otherwise unobservable as the insertion logic was able to
        // heal this specific kind of bug.
        let t = spanning_tree(&[
            // 6..8
            (6..8, Scanned),
            //       6..12
            // 6..8        8..12
            //         8..10  10..12
            (10..12, ChainTip),
            //          3..12
            //    3..8        8..12
            // 3..6  6..8  8..10  10..12
            (3..6, Historic),
        ])
        .unwrap();

        assert_eq!(t.span(), (3.into())..(12.into()));
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(3..6, Historic),
                scan_range(6..8, Scanned),
                scan_range(8..10, Historic),
                scan_range(10..12, ChainTip),
            ]
        );
    }

    #[test]
    fn spanning_tree_dominance() {
        use ScanPriority::*;

        let t = spanning_tree(&[(0..3, Verify), (2..8, Scanned), (6..10, Verify)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Verify),
                scan_range(2..6, Scanned),
                scan_range(6..10, Verify),
            ]
        );

        let t = spanning_tree(&[(0..3, Verify), (2..8, Historic), (6..10, Verify)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Verify),
                scan_range(3..6, Historic),
                scan_range(6..10, Verify),
            ]
        );

        let t = spanning_tree(&[(0..3, Scanned), (2..8, Verify), (6..10, Scanned)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Scanned),
                scan_range(2..6, Verify),
                scan_range(6..10, Scanned),
            ]
        );

        let t = spanning_tree(&[(0..3, Scanned), (2..8, Historic), (6..10, Scanned)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Scanned),
                scan_range(3..6, Historic),
                scan_range(6..10, Scanned),
            ]
        );

        // a `ChainTip` insertion should not overwrite a scanned range.
        let mut t = spanning_tree(&[(0..3, ChainTip), (3..5, Scanned), (5..7, ChainTip)]).unwrap();
        t = t.insert(scan_range(0..7, ChainTip));
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, ChainTip),
                scan_range(3..5, Scanned),
                scan_range(5..7, ChainTip),
            ]
        );

        let mut t =
            spanning_tree(&[(280300..280310, FoundNote), (280310..280320, Scanned)]).unwrap();
        assert_eq!(
            t.clone().into_vec(),
            vec![
                scan_range(280300..280310, FoundNote),
                scan_range(280310..280320, Scanned)
            ]
        );
        t = t.insert(scan_range(280300..280340, ChainTip));
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(280300..280310, ChainTip),
                scan_range(280310..280320, Scanned),
                scan_range(280320..280340, ChainTip)
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_coalesce_scanned() {
        use ScanPriority::*;

        let mut t = spanning_tree(&[
            (0..3, Historic),
            (2..5, Scanned),
            (6..8, ChainTip),
            (7..10, Scanned),
        ])
        .unwrap();

        t = t.insert(scan_range(0..3, Scanned));
        t = t.insert(scan_range(5..8, Scanned));

        assert_eq!(t.into_vec(), vec![scan_range(0..10, Scanned)]);
    }

    #[test]
    fn scan_complete() {
        use ScanPriority::*;

        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&mut db_data);

        assert_matches!(
            // in the following, we don't care what the root hashes are, they just need to be
            // distinct
            db_data.put_sapling_subtree_roots(
                0,
                &[
                    CommitmentTreeRoot::from_parts(
                        sapling_activation_height() + 100,
                        Node::empty_root(Level::from(0))
                    ),
                    CommitmentTreeRoot::from_parts(
                        sapling_activation_height() + 200,
                        Node::empty_root(Level::from(1))
                    ),
                    CommitmentTreeRoot::from_parts(
                        sapling_activation_height() + 300,
                        Node::empty_root(Level::from(2))
                    ),
                ]
            ),
            Ok(())
        );

        // We'll start inserting leaf notes 5 notes after the end of the third subtree, with a gap
        // of 10 blocks. After `scan_cached_blocks`, the scan queue should have a requested scan
        // range of 300..310 with `FoundNote` priority, 310..320 with `Scanned` priority.
        let initial_sapling_tree_size = (0x1 << 16) * 3 + 5;
        let initial_height = sapling_activation_height() + 310;

        let value = Amount::from_u64(50000).unwrap();
        let (mut cb, _) = fake_compact_block(
            initial_height,
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
            initial_sapling_tree_size,
        );
        insert_into_cache(&db_cache, &cb);

        for i in 1..=10 {
            cb = fake_compact_block(
                initial_height + i,
                cb.hash(),
                &dfvk,
                AddressType::DefaultExternal,
                Amount::from_u64(10000).unwrap(),
                initial_sapling_tree_size + i,
            )
            .0;
            insert_into_cache(&db_cache, &cb);
        }

        assert_matches!(
            scan_cached_blocks(
                &tests::network(),
                &db_cache,
                &mut db_data,
                initial_height,
                10,
            ),
            Ok(())
        );

        // Verify the that adjacent range needed to make the note spendable has been prioritized
        let sap_active = u32::from(sapling_activation_height());
        assert_matches!(
            db_data.suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 300)..(sap_active + 310), FoundNote)
            ]
        );

        // Check that the scanned range has been properly persisted
        assert_matches!(
            suggest_scan_ranges(&db_data.conn, Scanned),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 300)..(sap_active + 310), FoundNote),
                scan_range((sap_active + 310)..(sap_active + 320), Scanned)
            ]
        );

        // simulate the wallet going offline for a bit, update the chain tip to 30 blocks in the
        // future
        assert_matches!(
            db_data.update_chain_tip(sapling_activation_height() + 340),
            Ok(())
        );

        // Check the scan range again, we should see a `ChainTip` range for the period we've been
        // offline.
        assert_matches!(
            db_data.suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 320)..(sap_active + 341), ChainTip),
                scan_range((sap_active + 300)..(sap_active + 310), ChainTip)
            ]
        );

        // Now simulate a jump ahead more than 100 blocks
        assert_matches!(
            db_data.update_chain_tip(sapling_activation_height() + 450),
            Ok(())
        );

        // Check the scan range again, we should see a `Validate` range for the previous wallet
        // tip, and then a `ChainTip` for the remaining range.
        assert_matches!(
            db_data.suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 319)..(sap_active + 329), Verify),
                scan_range((sap_active + 329)..(sap_active + 451), ChainTip),
                scan_range((sap_active + 300)..(sap_active + 310), ChainTip)
            ]
        );
    }
}
