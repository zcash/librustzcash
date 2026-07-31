use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use rusqlite::{Connection, named_params};
use tempfile::TempDir;
use zcash_protocol::consensus::BlockHeight;

#[path = "../src/wallet/scan_progress.rs"]
mod scan_progress;

/// Models a restored wallet with a substantial scanned history.
const SCANNED_BLOCK_COUNT: u32 = 600_000;
/// The first height in the synthetic wallet's scanned range.
const FIRST_SCANNED_HEIGHT: u32 = 1;
/// Models the stored priority code for a range that has been scanned.
const SCANNED_PRIORITY: i64 = 10;
/// Models a pending range whose priority is greater than `Scanned`.
const PENDING_PRIORITY: i64 = 20;
/// Produces a small repeating distribution of Sapling outputs across blocks.
const SAPLING_OUTPUT_COUNT_CYCLE: u32 = 4;
/// Produces a distinct distribution of Orchard actions across blocks.
const ORCHARD_ACTION_COUNT_CYCLE: u32 = 7;
/// Names the temporary, file-backed SQLite database.
const DATABASE_FILE_NAME: &str = "wallet.db";
/// Keeps the slower legacy query's benchmark runtime practical.
const SAMPLE_SIZE: usize = 10;
/// Provides stable measurements without making the benchmark onerous.
const MEASUREMENT_TIME: Duration = Duration::from_secs(5);

struct InOrderScanDatabase {
    _directory: TempDir,
    conn: Connection,
}

fn in_order_scan_database() -> InOrderScanDatabase {
    let directory = TempDir::new().unwrap();
    let mut conn = Connection::open(directory.path().join(DATABASE_FILE_NAME)).unwrap();
    conn.execute_batch(
        "CREATE TABLE blocks (
             height INTEGER PRIMARY KEY,
             sapling_commitment_tree_size INTEGER NOT NULL,
             sapling_output_count INTEGER NOT NULL,
             orchard_commitment_tree_size INTEGER NOT NULL,
             orchard_action_count INTEGER NOT NULL
         );
         CREATE TABLE scan_queue (
             block_range_start INTEGER NOT NULL UNIQUE,
             block_range_end INTEGER NOT NULL UNIQUE,
             priority INTEGER NOT NULL
         );",
    )
    .unwrap();

    let last_scanned_height = FIRST_SCANNED_HEIGHT + SCANNED_BLOCK_COUNT - 1;
    let tx = conn.transaction().unwrap();
    tx.execute(
        "WITH RECURSIVE scanned_blocks(
             height,
             sapling_tree_size,
             orchard_tree_size
         ) AS (
             SELECT :first_height,
                    :first_height % :sapling_output_count_cycle,
                    :first_height % :orchard_action_count_cycle
             UNION ALL
             SELECT height + 1,
                    sapling_tree_size
                        + ((height + 1) % :sapling_output_count_cycle),
                    orchard_tree_size
                        + ((height + 1) % :orchard_action_count_cycle)
             FROM scanned_blocks
             WHERE height < :last_height
         )
         INSERT INTO blocks (
             height,
             sapling_commitment_tree_size,
             sapling_output_count,
             orchard_commitment_tree_size,
             orchard_action_count
         )
         SELECT height,
                sapling_tree_size,
                height % :sapling_output_count_cycle,
                orchard_tree_size,
                height % :orchard_action_count_cycle
         FROM scanned_blocks",
        named_params! {
            ":first_height": FIRST_SCANNED_HEIGHT,
            ":last_height": last_scanned_height,
            ":sapling_output_count_cycle": SAPLING_OUTPUT_COUNT_CYCLE,
            ":orchard_action_count_cycle": ORCHARD_ACTION_COUNT_CYCLE,
        },
    )
    .unwrap();
    tx.execute(
        "INSERT INTO scan_queue (
             block_range_start,
             block_range_end,
             priority
         ) VALUES (
             :start_height,
             :pending_start,
             :scanned_priority
         ), (
             :pending_start,
             :pending_end,
             :pending_priority
        )",
        named_params! {
            ":start_height": FIRST_SCANNED_HEIGHT,
            ":pending_start": last_scanned_height + 1,
            ":pending_end": last_scanned_height + SCANNED_BLOCK_COUNT,
            ":scanned_priority": SCANNED_PRIORITY,
            ":pending_priority": PENDING_PRIORITY,
        },
    )
    .unwrap();
    tx.commit().unwrap();

    InOrderScanDatabase {
        _directory: directory,
        conn,
    }
}

fn unfiltered_output_count(conn: &Connection, output_count_col: &str) -> Option<u64> {
    conn.query_row(
        &format!(
            "SELECT SUM({output_count_col})
             FROM blocks
             WHERE :start_height <= height"
        ),
        named_params! {
            ":start_height": FIRST_SCANNED_HEIGHT,
        },
        |row| row.get(0),
    )
    .unwrap()
}

fn bench_in_order_scanned_output_count(c: &mut Criterion) {
    let database = in_order_scan_database();
    let conn = &database.conn;
    let mut group = c.benchmark_group("file_backed_in_order_scan_progress");

    group.bench_function("legacy_correlated_filter_both_pools", |b| {
        b.iter(|| {
            (
                scan_progress::row_wise_scanned_output_count(
                    conn,
                    "sapling_output_count",
                    BlockHeight::from(FIRST_SCANNED_HEIGHT),
                    None,
                    SCANNED_PRIORITY,
                )
                .unwrap(),
                scan_progress::row_wise_scanned_output_count(
                    conn,
                    "orchard_action_count",
                    BlockHeight::from(FIRST_SCANNED_HEIGHT),
                    None,
                    SCANNED_PRIORITY,
                )
                .unwrap(),
            )
        })
    });

    group.bench_function("unfiltered_sum_both_pools", |b| {
        b.iter(|| {
            (
                unfiltered_output_count(conn, "sapling_output_count"),
                unfiltered_output_count(conn, "orchard_action_count"),
            )
        })
    });

    group.bench_function("optimized_production_query_both_pools", |b| {
        b.iter(|| {
            (
                scan_progress::scanned_output_count(
                    conn,
                    "sapling_commitment_tree_size",
                    "sapling_output_count",
                    BlockHeight::from(FIRST_SCANNED_HEIGHT),
                    None,
                    SCANNED_PRIORITY,
                )
                .unwrap(),
                scan_progress::scanned_output_count(
                    conn,
                    "orchard_commitment_tree_size",
                    "orchard_action_count",
                    BlockHeight::from(FIRST_SCANNED_HEIGHT),
                    None,
                    SCANNED_PRIORITY,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(SAMPLE_SIZE)
        .measurement_time(MEASUREMENT_TIME);
    targets = bench_in_order_scanned_output_count
}
criterion_main!(benches);
