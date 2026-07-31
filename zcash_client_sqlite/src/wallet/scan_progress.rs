use std::ops::Range;

use rusqlite::{Connection, OptionalExtension, named_params};

use zcash_protocol::consensus::BlockHeight;

fn output_count_for_range(
    conn: &Connection,
    tree_size_col: &str,
    output_count_col: &str,
    range: &Range<BlockHeight>,
) -> Result<Option<u64>, rusqlite::Error> {
    if range.is_empty() {
        return Ok(Some(0));
    }

    let boundary_data = conn
        .query_row(
            &format!(
                "SELECT first.{tree_size_col},
                        first.{output_count_col},
                        last.{tree_size_col}
                 FROM blocks AS first
                 JOIN blocks AS last ON last.height = :last_height
                 WHERE first.height = :start_height"
            ),
            named_params! {
                ":start_height": u32::from(range.start),
                ":last_height": u32::from(range.end - 1),
            },
            |row| {
                Ok((
                    row.get::<_, Option<u64>>(0)?,
                    row.get::<_, Option<u64>>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                ))
            },
        )
        .optional()?;

    Ok(
        boundary_data.and_then(|(start_tree_size, start_output_count, end_tree_size)| {
            start_tree_size
                .zip(start_output_count)
                .and_then(|(tree_size, output_count)| tree_size.checked_sub(output_count))
                .zip(end_tree_size)
                .and_then(|(size_before_start, size_at_end)| {
                    size_at_end.checked_sub(size_before_start)
                })
        }),
    )
}

/// Returns whether this database was populated with per-block output counts.
///
/// The migration that introduced the output-count columns could only backfill
/// rows that had an immediately preceding block, so its first stored row is
/// always `NULL`. Treating that row as a migration marker keeps potentially
/// sparse historical data on the exact row-wise path. Databases populated by
/// the current scan code store the count on every inserted block.
fn has_output_count_for_first_stored_block(
    conn: &Connection,
    output_count_col: &str,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        &format!(
            "SELECT {output_count_col} IS NOT NULL
             FROM blocks
             ORDER BY height
             LIMIT 1"
        ),
        [],
        |row| row.get(0),
    )
    .optional()
    .map(Option::unwrap_or_default)
}

/// Returns the portions of `range` that the row-wise query counts.
///
/// The scan queue is maintained as a contiguous, non-overlapping partition.
/// Requiring that partition here lets tree-size deltas skip pending segments
/// without assuming that unrepresented interior blocks were scanned. Any
/// malformed or incomplete partition makes the fast path unavailable.
fn counted_ranges(
    conn: &Connection,
    range: &Range<BlockHeight>,
    scanned_priority: i64,
) -> Result<Option<Vec<Range<BlockHeight>>>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT MAX(block_range_start, :start_height),
                MIN(block_range_end, :end_height),
                priority
         FROM scan_queue
         WHERE :start_height < block_range_end
           AND block_range_start < :end_height
         ORDER BY block_range_start, block_range_end",
    )?;
    let mut rows = stmt.query(named_params! {
        ":start_height": u32::from(range.start),
        ":end_height": u32::from(range.end),
    })?;
    let mut cursor = range.start;
    let mut counted = vec![];
    while let Some(row) = rows.next()? {
        let next =
            BlockHeight::from(row.get::<_, u32>(0)?)..BlockHeight::from(row.get::<_, u32>(1)?);
        let priority = row.get::<_, i64>(2)?;
        if next.is_empty() || next.start != cursor {
            return Ok(None);
        }
        if priority <= scanned_priority {
            counted.push(next.clone());
        }
        cursor = next.end;
    }

    Ok((cursor == range.end).then_some(counted))
}

pub(super) fn scanned_output_count_from_tree_sizes(
    conn: &Connection,
    tree_size_col: &str,
    output_count_col: &str,
    start_height: BlockHeight,
    end_height: Option<BlockHeight>,
    scanned_priority: i64,
) -> Result<Option<u64>, rusqlite::Error> {
    if !has_output_count_for_first_stored_block(conn, output_count_col)? {
        return Ok(None);
    }

    let last_height = conn.query_row(
        "SELECT MAX(height)
         FROM blocks
         WHERE :start_height <= height
           AND (:end_height IS NULL OR height < :end_height)",
        named_params! {
            ":start_height": u32::from(start_height),
            ":end_height": end_height.map(u32::from),
        },
        |row| row.get::<_, Option<u32>>(0),
    )?;
    let Some(last_height) = last_height else {
        return Ok(None);
    };
    let Some(end_height) = last_height.checked_add(1).map(BlockHeight::from) else {
        return Ok(None);
    };
    let range = start_height..end_height;
    let Some(counted_ranges) = counted_ranges(conn, &range, scanned_priority)? else {
        return Ok(None);
    };

    let mut total_count: u64 = 0;
    for counted_range in counted_ranges {
        let Some(count) =
            output_count_for_range(conn, tree_size_col, output_count_col, &counted_range)?
        else {
            return Ok(None);
        };
        let Some(new_total_count) = total_count.checked_add(count) else {
            return Ok(None);
        };
        total_count = new_total_count;
    }

    Ok(Some(total_count))
}

pub(super) fn row_wise_scanned_output_count(
    conn: &Connection,
    output_count_col: &str,
    start_height: BlockHeight,
    end_height: Option<BlockHeight>,
    scanned_priority: i64,
) -> Result<Option<u64>, rusqlite::Error> {
    conn.query_row(
        &format!(
            "SELECT SUM({output_count_col})
             FROM blocks
             WHERE :start_height <= height
               AND (:end_height IS NULL OR height < :end_height)
               AND NOT EXISTS (
                   SELECT 1 FROM scan_queue
                   WHERE block_range_start <= blocks.height
                     AND blocks.height < block_range_end
                     AND priority > :scanned_priority
               )"
        ),
        named_params! {
            ":start_height": u32::from(start_height),
            ":end_height": end_height.map(u32::from),
            ":scanned_priority": scanned_priority,
        },
        |row| row.get(0),
    )
}

pub(super) fn scanned_output_count(
    conn: &Connection,
    tree_size_col: &str,
    output_count_col: &str,
    start_height: BlockHeight,
    end_height: Option<BlockHeight>,
    scanned_priority: i64,
) -> Result<Option<u64>, rusqlite::Error> {
    if let Some(count) = scanned_output_count_from_tree_sizes(
        conn,
        tree_size_col,
        output_count_col,
        start_height,
        end_height,
        scanned_priority,
    )? {
        return Ok(Some(count));
    }

    row_wise_scanned_output_count(
        conn,
        output_count_col,
        start_height,
        end_height,
        scanned_priority,
    )
}
