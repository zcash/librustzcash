//! Replaces the boolean `witness_stabilized` flag on received-note tables with a
//! `witness_anchor_stable` column recording the height through which each note's
//! witness data is settled, then drops the old flag.
//!
//! The column is **recomputed from authoritative tree and scan state**, not converted
//! from the old boolean. The released `witness_stabilized_notes` migration set that
//! boolean using an earlier pruning-floor formula
//! (`block_max_scanned - (PRUNING_DEPTH - 1)`); recomputing here — mirroring the current
//! `mark_stabilized_notes` first-time stabilize rule — brings a migrated wallet into
//! exact agreement with one synced fresh under the current rule, and additionally
//! stabilizes notes in the active (tip) shard, which the boolean never covered. The
//! boolean value is therefore ignored entirely.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::data_api::{SAPLING_SHARD_HEIGHT, scanning::ScanPriority};
use zcash_protocol::consensus;

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::{IRONWOOD_SHARD_HEIGHT, ORCHARD_SHARD_HEIGHT};

use super::{note_locking, witness_stabilized_notes};
use crate::{
    SAPLING_TABLES_PREFIX,
    wallet::{
        chain_tip_height,
        init::WalletMigrationError,
        scanning::{priority_code, pruning_floor},
    },
};

#[cfg(feature = "orchard")]
use crate::{IRONWOOD_TABLES_PREFIX, ORCHARD_TABLES_PREFIX};

/// Replaces the `witness_stabilized` flag on received-note tables with a
/// `witness_anchor_stable` column holding the block height at which the note's witness
/// data was first determined to be stable modulo anchor choice.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xa3f1c4d8_5e21_4b9c_9f43_61c8a3e91a02);

// `witness_stabilized_notes` adds the column this migration replaces;
// creates the Ironwood table (with a `witness_stabilized` column) that this migration also
// converts. `note_locking` appends `lock_expiry_height` and `lock_owner` to the same tables;
// depending on it puts `witness_anchor_stable` after those columns, as the canonical schema
// declares it.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    witness_stabilized_notes::MIGRATION_ID,
    note_locking::MIGRATION_ID,
];

pub(super) struct Migration<P> {
    pub(super) _params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Replaces witness_stabilized boolean with witness_anchor_stable."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add the new column on both pool tables. The column is nullable; NULL means
        // "not yet stabilized", which is the same meaning the old `witness_stabilized = 0`
        // had.
        transaction.execute_batch(
            "ALTER TABLE sapling_received_notes
               ADD COLUMN witness_anchor_stable INTEGER;

             ALTER TABLE orchard_received_notes
               ADD COLUMN witness_anchor_stable INTEGER;

             ALTER TABLE ironwood_received_notes
               ADD COLUMN witness_anchor_stable INTEGER;",
        )?;

        // Backfill: recompute each note's anchor-stable height from authoritative tree and
        // scan state, mirroring `scanning::mark_stabilized_notes`'s first-time-stabilize arm
        // at the time this migration was authored. The old `witness_stabilized` boolean is
        // deliberately *not* consulted; see the module docs. The SQL is inlined rather than
        // calling `mark_stabilized_notes` so this migration stays stable as that helper evolves.
        //
        // For each note scanned above its own block (every block after the note's own block is
        // scanned, through the shard's end for a completed shard and through the chain tip for
        // the open one), the stored height is the shard's `subtree_end_height` when the shard is complete, and
        // otherwise the greater of the note's own `t.block` and the pruning floor. See
        // `mark_stabilized_notes`.
        if let Some(chain_tip) = chain_tip_height(transaction)? {
            let pruning_floor: u32 = u32::from(pruning_floor(chain_tip));
            let scanned_priority = priority_code(&ScanPriority::Scanned);
            let backfill = |table_prefix: &str| -> String {
                format!(
                    "UPDATE {table_prefix}_received_notes AS rn
                     SET witness_anchor_stable = IFNULL(
                         shard.subtree_end_height,
                         max(t.block, :pruning_floor)
                     )
                     FROM transactions t, {table_prefix}_tree_shards shard
                     WHERE t.id_tx = rn.transaction_id
                       AND shard.shard_index = (rn.commitment_tree_position >> :shard_height)
                       AND rn.commitment_tree_position IS NOT NULL
                       AND t.block IS NOT NULL
                       AND NOT EXISTS (
                           SELECT 1 FROM scan_queue q
                           WHERE q.priority > :scanned_priority
                             AND q.block_range_end > t.block + 1
                             AND (shard.subtree_end_height IS NULL
                                  OR q.block_range_start <= shard.subtree_end_height)
                       )"
                )
            };
            transaction.execute(
                &backfill(SAPLING_TABLES_PREFIX),
                named_params![
                    ":pruning_floor": pruning_floor,
                    ":shard_height": SAPLING_SHARD_HEIGHT,
                    ":scanned_priority": scanned_priority,
                ],
            )?;
            #[cfg(feature = "orchard")]
            transaction.execute(
                &backfill(ORCHARD_TABLES_PREFIX),
                named_params![
                    ":pruning_floor": pruning_floor,
                    ":shard_height": ORCHARD_SHARD_HEIGHT,
                    ":scanned_priority": scanned_priority,
                ],
            )?;
            #[cfg(feature = "orchard")]
            transaction.execute(
                &backfill(IRONWOOD_TABLES_PREFIX),
                named_params![
                    ":pruning_floor": pruning_floor,
                    ":shard_height": IRONWOOD_SHARD_HEIGHT,
                    ":scanned_priority": scanned_priority,
                ],
            )?;
            #[cfg(not(feature = "orchard"))]
            let _ = backfill;
        }

        // Replace the old column and its index with one keyed on the new column.
        transaction.execute_batch(
            "DROP INDEX idx_sapling_received_notes_witness_stabilized;
             DROP INDEX idx_orchard_received_notes_witness_stabilized;
             DROP INDEX idx_ironwood_received_notes_witness_stabilized;

             ALTER TABLE sapling_received_notes DROP COLUMN witness_stabilized;
             ALTER TABLE orchard_received_notes DROP COLUMN witness_stabilized;
             ALTER TABLE ironwood_received_notes DROP COLUMN witness_stabilized;

             CREATE INDEX idx_sapling_received_notes_witness_anchor_stable
                 ON sapling_received_notes (witness_anchor_stable);

             CREATE INDEX idx_orchard_received_notes_witness_anchor_stable
                 ON orchard_received_notes (witness_anchor_stable);

             CREATE INDEX idx_ironwood_received_notes_witness_anchor_stable
                 ON ironwood_received_notes (witness_anchor_stable);",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::named_params;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_client_backend::data_api::{SAPLING_SHARD_HEIGHT, scanning::ScanPriority};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use crate::{
        PRUNING_DEPTH, WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::{
            db,
            init::{
                WalletMigrator,
                migrations::tests::test_migrate,
                tests::{describe_tables, normalize_sql},
            },
            scanning::priority_code,
        },
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[cfg(feature = "orchard")]
    use zcash_client_backend::data_api::{IRONWOOD_SHARD_HEIGHT, ORCHARD_SHARD_HEIGHT};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// Migrating to this migration first and then completing the migration must produce the
    /// canonical schema, so that the columns this migration appends follow those of every
    /// migration that appends to the same tables.
    #[test]
    fn migrate_then_complete_yields_canonical_schema() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        let seed = vec![0xab; 32];
        WalletMigrator::new()
            .with_seed(Secret::new(seed.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        WalletMigrator::new()
            .with_seed(Secret::new(seed))
            .ignore_seed_relevance()
            .init_or_migrate(&mut db_data)
            .unwrap();

        let tables = describe_tables(&db_data.conn).unwrap();
        for expected in [
            db::TABLE_SAPLING_RECEIVED_NOTES,
            db::TABLE_ORCHARD_RECEIVED_NOTES,
            db::TABLE_IRONWOOD_RECEIVED_NOTES,
        ] {
            let expected = normalize_sql(expected);
            assert!(
                tables.iter().any(|actual| normalize_sql(actual) == expected),
                "no table matches the canonical schema {expected}",
            );
        }
    }

    /// End-to-end exercise of the recompute backfill: under a fully-`Scanned` queue, seed a
    /// note in a completed (buried) shard, a note in the active (tip) shard, and a note with
    /// no commitment-tree position; run the migration; and confirm `witness_anchor_stable` is
    /// the completed shard's end height for the buried-shard note,
    /// `max(t.block, pruning_floor)` for the tip-shard note (which the old boolean never
    /// covered), and `NULL` for the positionless note. The pre-migration `witness_stabilized`
    /// value is irrelevant (left at its default), since the backfill recomputes from tree/scan
    /// state.
    #[test]
    fn migrate_backfills_anchor_heights() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        let seed_bytes = vec![0xab; 32];

        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        // Heights well above the NU5 testnet activation (1,842,420) so each shard's extent
        // overlaps the scan_queue range. `chain_tip_height` reads `MAX(block_range_end) - 1`
        // from `scan_queue`, so a range ending at `chain_tip + 1` yields `chain_tip`, and the
        // migration's `pruning_floor(chain_tip) = chain_tip - PRUNING_DEPTH`.
        let base: u32 = 2_000_000;
        let birthday_height: u32 = base;
        let buried_shard_end: u32 = base + 250; // shard 0 subtree_end_height (below pruning floor)
        let pruning_floor_h: u32 = base + 301;
        let chain_tip: u32 = pruning_floor_h + PRUNING_DEPTH;
        let low_block: u32 = base + 10; // a tx mined well below the pruning floor
        let tip_block: u32 = base + 350; // a tx mined above the pruning floor

        let usk =
            UnifiedSpendingKey::from_seed(&network, &seed_bytes, zip32::AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let ufvk_str = ufvk.encode(&network).unwrap();
        let uivk_str = ufvk
            .to_unified_incoming_viewing_key()
            .encode(&network)
            .unwrap();
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (id, uuid, account_kind,
                 hd_seed_fingerprint, hd_account_index,
                 ufvk, uivk, has_spend_key, birthday_height)
                 VALUES (1, X'0000000000000000000000000000AAAA', 0,
                 X'00000000000000000000000000000000000000000000000000000000000000AB',
                 0, :ufvk, :uivk, 1, :birthday_height)",
                named_params![
                    ":ufvk": ufvk_str,
                    ":uivk": uivk_str,
                    ":birthday_height": birthday_height,
                ],
            )
            .unwrap();

        // A `blocks` row per mined height the transactions reference (`transactions.block`
        // is FK-bound to `blocks`).
        for height in [low_block, tip_block] {
            db_data
                .conn
                .execute(
                    "INSERT INTO blocks (
                         height, hash, time,
                         sapling_tree, sapling_commitment_tree_size
                     ) VALUES (:height, zeroblob(32), 0, X'', 0)",
                    named_params![":height": height],
                )
                .unwrap();
        }

        // Two transactions pinned to a mined `block`: a low one for the buried-shard and
        // positionless notes, and one above the pruning floor for the tip-shard note.
        for (id_tx, block) in [(1u32, low_block), (2u32, tip_block)] {
            db_data
                .conn
                .execute(
                    "INSERT INTO transactions (id_tx, txid, block, mined_height, min_observed_height)
                     VALUES (:id_tx, :txid, :block, :block, :block)",
                    named_params![
                        ":id_tx": id_tx,
                        ":txid": vec![id_tx as u8; 32],
                        ":block": block,
                    ],
                )
                .unwrap();
        }

        // A single contiguous `Scanned` range over `[birthday, chain_tip + 1)`: nothing above
        // `Scanned` overlaps any note, so the backfill's unscanned-range gate admits all
        // positioned notes.
        db_data
            .conn
            .execute(
                "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                 VALUES (:start, :end, :scanned)",
                named_params![
                    ":start": birthday_height,
                    ":end": chain_tip + 1,
                    ":scanned": priority_code(&ScanPriority::Scanned),
                ],
            )
            .unwrap();

        // Two shards:
        //   shard 0: subtree_end_height = buried_shard_end (completed, below pruning floor)
        //   shard 1: subtree_end_height = NULL (active tip shard)
        for pool in ["sapling", "orchard", "ironwood"] {
            db_data
                .conn
                .execute(
                    &format!(
                        "INSERT INTO {pool}_tree_shards (shard_index, subtree_end_height)
                         VALUES (0, :buried), (1, NULL)"
                    ),
                    named_params![":buried": buried_shard_end],
                )
                .unwrap();
        }

        // Seed rows: a buried-shard note (tx 1), a tip-shard note (tx 2), and a positionless
        // note (tx 1). `witness_stabilized` is left at its default — the backfill ignores it.
        // `position` of `None` exercises the `commitment_tree_position IS NOT NULL` gate.
        let pos_shard_0: i64 = 1;
        let sapling_pos_shard_1: i64 = 1 << SAPLING_SHARD_HEIGHT;
        for (output_index, transaction_id, position) in [
            (0, 1, Some(pos_shard_0)),         // buried shard
            (1, 2, Some(sapling_pos_shard_1)), // active tip shard
            (2, 1, None),                      // no position
        ] {
            db_data
                .conn
                .execute(
                    "INSERT INTO sapling_received_notes (
                         transaction_id, output_index, account_id,
                         diversifier, value, rcm, is_change, commitment_tree_position
                     ) VALUES (:transaction_id, :output_index, 1, X'00', 0, X'00', 0, :position)",
                    named_params![
                        ":transaction_id": transaction_id,
                        ":output_index": output_index,
                        ":position": position,
                    ],
                )
                .unwrap();
        }

        #[cfg(feature = "orchard")]
        {
            let orchard_pos_shard_1: i64 = 1 << ORCHARD_SHARD_HEIGHT;
            for (action_index, transaction_id, position) in [
                (0, 1, Some(pos_shard_0)),
                (1, 2, Some(orchard_pos_shard_1)),
                (2, 1, None),
            ] {
                db_data
                    .conn
                    .execute(
                        "INSERT INTO orchard_received_notes (
                             transaction_id, action_index, account_id,
                             diversifier, value, rho, rseed, is_change, commitment_tree_position
                         ) VALUES (:transaction_id, :action_index, 1, X'00', 0, X'00', X'00', 0, :position)",
                        named_params![
                            ":transaction_id": transaction_id,
                            ":action_index": action_index,
                            ":position": position,
                        ],
                    )
                    .unwrap();
            }
        }

        #[cfg(feature = "orchard")]
        {
            let ironwood_pos_shard_1: i64 = 1 << IRONWOOD_SHARD_HEIGHT;
            for (action_index, transaction_id, position) in [
                (0, 1, Some(pos_shard_0)),
                (1, 2, Some(ironwood_pos_shard_1)),
                (2, 1, None),
            ] {
                db_data
                    .conn
                    .execute(
                        "INSERT INTO ironwood_received_notes (
                             transaction_id, action_index, account_id,
                             diversifier, value, rho, rseed, is_change,
                             commitment_tree_position, note_version
                         ) VALUES (:transaction_id, :action_index, 1, X'00', 0, X'00', X'00', 0, :position, 3)",
                        named_params![
                            ":transaction_id": transaction_id,
                            ":action_index": action_index,
                            ":position": position,
                        ],
                    )
                    .unwrap();
            }
        }

        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let read = |table: &str, pk_col: &str| -> Vec<(i64, Option<i64>)> {
            let mut stmt = db_data
                .conn
                .prepare(&format!(
                    "SELECT {pk_col}, witness_anchor_stable FROM {table} ORDER BY {pk_col}"
                ))
                .unwrap();
            let rows: Vec<(i64, Option<i64>)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows
        };

        // Buried-shard note: its completed shard's end height. Tip-shard note:
        // `max(tip_block, pruning_floor)` = `tip_block` (the note's own block dominates).
        // Positionless note: excluded by the gate, so `NULL`.
        let expected = vec![
            (0, Some(i64::from(buried_shard_end))),
            (1, Some(i64::from(tip_block))),
            (2, None),
        ];
        assert_eq!(
            read("sapling_received_notes", "output_index"),
            expected,
            "sapling backfill must record the completed shard's end height, or \
             max(t.block, pruning_floor) in the tip shard, and NULL for positionless notes",
        );

        #[cfg(feature = "orchard")]
        assert_eq!(
            read("orchard_received_notes", "action_index"),
            expected,
            "orchard backfill must match the sapling behavior",
        );

        #[cfg(feature = "orchard")]
        assert_eq!(
            read("ironwood_received_notes", "action_index"),
            expected,
            "ironwood backfill must match the sapling behavior",
        );
    }
}
