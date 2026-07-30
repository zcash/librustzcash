use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use rusqlite::{Connection, named_params};

/// Models a restored wallet with a substantial scanned history.
const SCANNED_BLOCK_COUNT: u32 = 500_000;
/// The first height in the synthetic wallet's scanned range.
const FIRST_SCANNED_HEIGHT: u32 = 1;
/// Models the stored priority code for a range that has been scanned.
const SCANNED_PRIORITY: i64 = 10;
/// Models a pending range whose priority is greater than `Scanned`.
const PENDING_PRIORITY: i64 = 20;
/// Keeps the slower legacy query's benchmark runtime practical.
const SAMPLE_SIZE: usize = 10;
/// Provides stable measurements without making the benchmark onerous.
const MEASUREMENT_TIME: Duration = Duration::from_secs(5);

fn in_order_scan_database() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE blocks (
             height INTEGER PRIMARY KEY,
             sapling_output_count INTEGER NOT NULL
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
        "WITH RECURSIVE scanned_blocks(height) AS (
             SELECT :first_height
             UNION ALL
             SELECT height + 1
             FROM scanned_blocks
             WHERE height < :last_height
         )
         INSERT INTO blocks (height, sapling_output_count)
         SELECT height, height % 4
         FROM scanned_blocks",
        named_params! {
            ":first_height": FIRST_SCANNED_HEIGHT,
            ":last_height": last_scanned_height,
        },
    )
    .unwrap();
    tx.execute(
        "INSERT INTO scan_queue (
             block_range_start,
             block_range_end,
             priority
         ) VALUES (:start_height, :end_height, :priority)",
        named_params! {
            ":start_height": last_scanned_height + 1,
            ":end_height": last_scanned_height + SCANNED_BLOCK_COUNT,
            ":priority": PENDING_PRIORITY,
        },
    )
    .unwrap();
    tx.commit().unwrap();

    conn
}

fn bench_in_order_scanned_output_count(c: &mut Criterion) {
    let conn = in_order_scan_database();
    let mut group = c.benchmark_group("in_order_scanned_output_count");

    group.bench_function("legacy_correlated_filter", |b| {
        b.iter(|| {
            conn.query_row(
                "SELECT SUM(sapling_output_count)
                 FROM blocks
                 WHERE :start_height <= height
                   AND NOT EXISTS (
                       SELECT 1 FROM scan_queue
                       WHERE block_range_start <= blocks.height
                         AND blocks.height < block_range_end
                         AND priority > :scanned_priority
                   )",
                named_params! {
                    ":start_height": FIRST_SCANNED_HEIGHT,
                    ":scanned_priority": SCANNED_PRIORITY,
                },
                |row| row.get::<_, Option<u64>>(0),
            )
            .unwrap()
        })
    });

    group.bench_function("overlap_aware_fast_path", |b| {
        b.iter(|| {
            let pending_ranges_overlap = conn
                .query_row(
                    "SELECT EXISTS (
                         SELECT 1 FROM scan_queue
                         WHERE priority > :scanned_priority
                           AND :start_height < block_range_end
                           AND block_range_start <= (SELECT MAX(height) FROM blocks)
                     )",
                    named_params! {
                        ":start_height": FIRST_SCANNED_HEIGHT,
                        ":scanned_priority": SCANNED_PRIORITY,
                    },
                    |row| row.get::<_, bool>(0),
                )
                .unwrap();
            assert!(!pending_ranges_overlap);

            conn.query_row(
                "SELECT SUM(sapling_output_count)
                 FROM blocks
                 WHERE :start_height <= height",
                named_params! {
                    ":start_height": FIRST_SCANNED_HEIGHT,
                },
                |row| row.get::<_, Option<u64>>(0),
            )
            .unwrap()
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
