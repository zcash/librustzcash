use proptest::prelude::*;
use rusqlite::Connection;
use zcash_protocol::consensus::BlockHeight;

use super::scan_progress::{
    row_wise_scanned_output_count, scanned_output_count, scanned_output_count_from_tree_sizes,
};

/// Keeps generated heights away from protocol activation boundaries.
const FIRST_HEIGHT: u32 = 100;
/// Seeds the Sapling tree with a nonzero size.
const INITIAL_SAPLING_TREE_SIZE: u64 = 50;
/// Seeds the Orchard tree with a distinct nonzero size.
const INITIAL_ORCHARD_TREE_SIZE: u64 = 75;
/// Models the stored priority code for scanned queue entries.
const SCANNED_PRIORITY: i64 = 10;
/// Models a priority that causes a queue range to be rescanned.
const HISTORIC_PRIORITY: i64 = 20;
/// Keeps each generated database nonempty.
const MIN_GENERATED_BLOCK_COUNT: usize = 1;
/// Keeps generated cases small while exercising many queue partitions.
const MAX_GENERATED_BLOCK_COUNT_EXCLUSIVE: usize = 25;
/// Bounds per-block output counts to small fixture values.
const OUTPUT_COUNT_EXCLUSIVE_LIMIT: u8 = 8;
/// Provides broad differential coverage without slowing the focused test.
const GENERATED_CASE_COUNT: u32 = 64;

fn empty_progress_database() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE blocks (
             height INTEGER PRIMARY KEY,
             sapling_commitment_tree_size INTEGER,
             sapling_output_count INTEGER,
             orchard_commitment_tree_size INTEGER,
             orchard_action_count INTEGER
         );
         CREATE TABLE scan_queue (
             block_range_start INTEGER NOT NULL UNIQUE,
             block_range_end INTEGER NOT NULL UNIQUE,
             priority INTEGER NOT NULL
         );",
    )
    .unwrap();
    conn
}

fn assert_matches_row_wise(
    conn: &Connection,
    tree_size_col: &str,
    output_count_col: &str,
    start_height: BlockHeight,
    end_height: Option<BlockHeight>,
) {
    let optimized = scanned_output_count(
        conn,
        tree_size_col,
        output_count_col,
        start_height,
        end_height,
        SCANNED_PRIORITY,
    )
    .unwrap()
    .unwrap_or(0);
    let row_wise = row_wise_scanned_output_count(
        conn,
        output_count_col,
        start_height,
        end_height,
        SCANNED_PRIORITY,
    )
    .unwrap()
    .unwrap_or(0);
    assert_eq!(optimized, row_wise);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(GENERATED_CASE_COUNT))]

    #[test]
    fn generated_queue_partitions_match_row_wise_query(
        blocks in prop::collection::vec(
            (
                0..OUTPUT_COUNT_EXCLUSIVE_LIMIT,
                0..OUTPUT_COUNT_EXCLUSIVE_LIMIT,
                any::<bool>(),
            ),
            MIN_GENERATED_BLOCK_COUNT..MAX_GENERATED_BLOCK_COUNT_EXCLUSIVE,
        ),
        raw_start in any::<u8>(),
        raw_end in any::<u8>(),
        bounded in any::<bool>(),
    ) {
        let conn = empty_progress_database();
        let mut sapling_tree_size = INITIAL_SAPLING_TREE_SIZE;
        let mut orchard_tree_size = INITIAL_ORCHARD_TREE_SIZE;
        for (offset, (sapling_count, orchard_count, pending)) in
            blocks.iter().copied().enumerate()
        {
            let height = FIRST_HEIGHT + u32::try_from(offset).unwrap();
            sapling_tree_size += u64::from(sapling_count);
            orchard_tree_size += u64::from(orchard_count);
            conn.execute(
                "INSERT INTO blocks (
                     height,
                     sapling_commitment_tree_size,
                     sapling_output_count,
                     orchard_commitment_tree_size,
                     orchard_action_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    height,
                    sapling_tree_size,
                    sapling_count,
                    orchard_tree_size,
                    orchard_count,
                ),
            )
            .unwrap();
            conn.execute(
                "INSERT INTO scan_queue (
                     block_range_start,
                     block_range_end,
                     priority
                 ) VALUES (?1, ?2, ?3)",
                (
                    height,
                    height + 1,
                    if pending {
                        HISTORIC_PRIORITY
                    } else {
                        SCANNED_PRIORITY
                    },
                ),
            )
            .unwrap();
        }

        let start_offset = usize::from(raw_start) % blocks.len();
        let remaining_block_count = blocks.len() - start_offset;
        let end_offset = start_offset + 1
            + usize::from(raw_end) % remaining_block_count;
        let start_height = BlockHeight::from(
            FIRST_HEIGHT + u32::try_from(start_offset).unwrap(),
        );
        let end_height = bounded.then(|| {
            BlockHeight::from(FIRST_HEIGHT + u32::try_from(end_offset).unwrap())
        });

        for (tree_size_col, output_count_col) in [
            (
                "sapling_commitment_tree_size",
                "sapling_output_count",
            ),
            (
                "orchard_commitment_tree_size",
                "orchard_action_count",
            ),
        ] {
            let fast = scanned_output_count_from_tree_sizes(
                &conn,
                tree_size_col,
                output_count_col,
                start_height,
                end_height,
                SCANNED_PRIORITY,
            )
            .unwrap();
            prop_assert!(fast.is_some());

            let row_wise = row_wise_scanned_output_count(
                &conn,
                output_count_col,
                start_height,
                end_height,
                SCANNED_PRIORITY,
            )
            .unwrap();
            prop_assert_eq!(fast.unwrap_or(0), row_wise.unwrap_or(0));
        }
    }
}

#[test]
fn migrated_output_counts_use_row_wise_fallback() {
    /// Leaves an interior gap like a non-contiguous historical database.
    const SECOND_RANGE_START: u32 = FIRST_HEIGHT + 5;
    /// Models the Sapling delta backfilled for an adjacent row.
    const FIRST_SAPLING_COUNT: u64 = 2;
    /// Models the Orchard delta backfilled for an adjacent row.
    const FIRST_ORCHARD_COUNT: u64 = 3;
    /// Models a Sapling delta after the historical gap.
    const SECOND_SAPLING_COUNT: u64 = 5;
    /// Models an Orchard delta after the historical gap.
    const SECOND_ORCHARD_COUNT: u64 = 7;

    let conn = empty_progress_database();
    conn.execute(
        "INSERT INTO blocks VALUES (?1, ?2, NULL, ?3, NULL)",
        (
            FIRST_HEIGHT,
            INITIAL_SAPLING_TREE_SIZE,
            INITIAL_ORCHARD_TREE_SIZE,
        ),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO blocks VALUES (?1, ?2, ?3, ?4, ?5)",
        (
            FIRST_HEIGHT + 1,
            INITIAL_SAPLING_TREE_SIZE + FIRST_SAPLING_COUNT,
            FIRST_SAPLING_COUNT,
            INITIAL_ORCHARD_TREE_SIZE + FIRST_ORCHARD_COUNT,
            FIRST_ORCHARD_COUNT,
        ),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO blocks VALUES (?1, ?2, ?3, ?4, ?5)",
        (
            SECOND_RANGE_START,
            INITIAL_SAPLING_TREE_SIZE + FIRST_SAPLING_COUNT + SECOND_SAPLING_COUNT,
            SECOND_SAPLING_COUNT,
            INITIAL_ORCHARD_TREE_SIZE + FIRST_ORCHARD_COUNT + SECOND_ORCHARD_COUNT,
            SECOND_ORCHARD_COUNT,
        ),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO scan_queue VALUES (?1, ?2, ?3)",
        (FIRST_HEIGHT, SECOND_RANGE_START + 1, SCANNED_PRIORITY),
    )
    .unwrap();

    let start_height = BlockHeight::from(FIRST_HEIGHT + 1);
    for (tree_size_col, output_count_col) in [
        ("sapling_commitment_tree_size", "sapling_output_count"),
        ("orchard_commitment_tree_size", "orchard_action_count"),
    ] {
        assert_eq!(
            scanned_output_count_from_tree_sizes(
                &conn,
                tree_size_col,
                output_count_col,
                start_height,
                None,
                SCANNED_PRIORITY,
            )
            .unwrap(),
            None,
        );
        assert_matches_row_wise(&conn, tree_size_col, output_count_col, start_height, None);
    }
}
