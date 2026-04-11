//! Adds a `witness_stabilized` flag to received notes, indicating that the note's containing shard
//! has been fully scanned and its witness data is durably present in the shard tree. Once set, this
//! flag is preserved across truncations, ensuring that notes with intact witness data remain
//! spendable.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus::BlockHeight;

use super::account_delete_cascade;
use crate::wallet::init::WalletMigrationError;
use crate::wallet::scanning::mark_stabilized_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x688f7dd4_a8d4_45ba_94a3_dfc520fefed5);

// This migration only touches the shielded received-notes tables and reads from
// `scan_queue` / `<pool>_tree_shards`. The most recent migration to modify either
// `sapling_received_notes` or `orchard_received_notes` is `account_delete_cascade`,
// which transitively depends on `shardtree_support` and `orchard_shardtree` (where
// the scan queue and shard tables are created). No other existing leaf migration
// touches the schema we read or write here.
const DEPENDENCIES: &[Uuid] = &[account_delete_cascade::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds witness_stabilized flag to received notes for durable spendability."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add the column to both received notes tables.
        transaction.execute_batch(
            "ALTER TABLE sapling_received_notes
               ADD COLUMN witness_stabilized INTEGER NOT NULL DEFAULT 0;

             ALTER TABLE orchard_received_notes
               ADD COLUMN witness_stabilized INTEGER NOT NULL DEFAULT 0;",
        )?;

        // Backfill: derive the last-scanned height from the scan queue and delegate to
        // the shared `mark_stabilized_notes` helper so the migration and the per-scan
        // stabilization path share a single source of truth.
        //
        // When the scan queue is empty the subquery returns `NULL` and no rows are
        // backfilled, which is the correct behavior for a freshly-created wallet.
        let last_scanned_height: Option<u32> = transaction.query_row(
            "SELECT MAX(block_range_end) - 1 FROM scan_queue",
            [],
            |row| row.get(0),
        )?;

        if let Some(last_scanned_height) = last_scanned_height {
            mark_stabilized_notes(transaction, BlockHeight::from(last_scanned_height))?;
        }

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
    use zcash_client_backend::data_api::SAPLING_SHARD_HEIGHT;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use crate::{
        PRUNING_DEPTH, WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    // Local mirror of ORCHARD_SHARD_HEIGHT; see `mark_stabilized_notes` for why the
    // migration's SQL is feature-agnostic.
    const ORCHARD_SHARD_HEIGHT: u8 = 16;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// End-to-end exercise of the backfill:
    /// seeds the pre-migration schema with a variety of notes whose stabilization
    /// outcomes are fully determined, runs the migration, and asserts the expected
    /// `witness_stabilized` value for each.
    #[test]
    fn migrate_backfills_stabilized_notes() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        let seed_bytes = vec![0xab; 32];

        // Migrate to database state just prior to this migration. At this point
        // `sapling_received_notes` / `orchard_received_notes` do not yet have the
        // `witness_stabilized` column.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        // `block_range_end` is exclusive, so MAX(block_range_end) - 1 is the
        // last-scanned height. Choose it so that stable_height = 200.
        let last_scanned: u32 = 300 + PRUNING_DEPTH;
        let stable_height: u32 = 300 - 1;
        assert_eq!(last_scanned - 1 - PRUNING_DEPTH, stable_height);

        // Seed a minimal account (schema per `add_account_uuids`). The UFVK/UIVK
        // must be real encoded values because `verify_network_compatibility` parses
        // them when the migrator opens the database.
        let usk =
            UnifiedSpendingKey::from_seed(&network, &seed_bytes, zip32::AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let ufvk_str = ufvk.encode(&network);
        let uivk_str = ufvk.to_unified_incoming_viewing_key().encode(&network);
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (id, uuid, account_kind,
                 hd_seed_fingerprint, hd_account_index,
                 ufvk, uivk, has_spend_key, birthday_height)
                 VALUES (1, X'0000000000000000000000000000AAAA', 0,
                 X'00000000000000000000000000000000000000000000000000000000000000AB',
                 0, :ufvk, :uivk, 1, 1)",
                named_params![":ufvk": ufvk_str, ":uivk": uivk_str],
            )
            .unwrap();

        // Seed a single transaction; none of the backfill logic cares about the
        // block column, only that there is an `id_tx` the note rows can reference.
        db_data
            .conn
            .execute(
                "INSERT INTO transactions (id_tx, txid, min_observed_height)
                 VALUES (1, X'00', 1)",
                [],
            )
            .unwrap();

        // Seed the scan queue so that MAX(block_range_end) - 1 - PRUNING_DEPTH = stable_height.
        db_data
            .conn
            .execute(
                "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                 VALUES (1, :block_range_end, 10)",
                named_params![":block_range_end": last_scanned + 1],
            )
            .unwrap();

        // Sapling shards:
        //   shard 0: end height well below stable_height  (notes here should stabilize)
        //   shard 1: end height above stable_height       (notes here should NOT stabilize)
        //   shard 2: end height NULL                      (notes here should NOT stabilize)
        db_data
            .conn
            .execute(
                "INSERT INTO sapling_tree_shards (shard_index, subtree_end_height)
                 VALUES (0, :stable), (1, :above), (2, NULL)",
                named_params![
                    ":stable": stable_height - 10,
                    ":above": stable_height + 50,
                ],
            )
            .unwrap();

        // Same layout for Orchard shards.
        db_data
            .conn
            .execute(
                "INSERT INTO orchard_tree_shards (shard_index, subtree_end_height)
                 VALUES (0, :stable), (1, :above), (2, NULL)",
                named_params![
                    ":stable": stable_height - 10,
                    ":above": stable_height + 50,
                ],
            )
            .unwrap();

        // The six sapling seed rows below cover every branch of the backfill
        // predicate. `(commitment_tree_position >> SAPLING_SHARD_HEIGHT)` picks the
        // shard for a given position.
        let sapling_pos_shard_0: i64 = 1;
        let sapling_pos_shard_1: i64 = 1 << SAPLING_SHARD_HEIGHT;
        let sapling_pos_shard_2: i64 = 2 << SAPLING_SHARD_HEIGHT;
        let sapling_pos_shard_99: i64 = 99 << SAPLING_SHARD_HEIGHT; // no shard row

        for (output_index, position, label) in [
            (0, Some(sapling_pos_shard_0), "stable shard"),
            (1, Some(sapling_pos_shard_1), "unstable shard"),
            (2, Some(sapling_pos_shard_2), "null end-height shard"),
            (3, None::<i64>, "null commitment_tree_position"),
            (4, Some(sapling_pos_shard_99), "no matching shard row"),
        ] {
            let _ = label;
            db_data
                .conn
                .execute(
                    "INSERT INTO sapling_received_notes (
                         transaction_id, output_index, account_id,
                         diversifier, value, rcm, is_change,
                         commitment_tree_position
                     ) VALUES (1, :output_index, 1, X'00', 0, X'00', 0, :position)",
                    named_params![
                        ":output_index": output_index,
                        ":position": position,
                    ],
                )
                .unwrap();
        }

        // Same scenarios for orchard, reusing `action_index` in place of `output_index`.
        let orchard_pos_shard_0: i64 = 3;
        let orchard_pos_shard_1: i64 = 1 << ORCHARD_SHARD_HEIGHT;
        let orchard_pos_shard_2: i64 = 2 << ORCHARD_SHARD_HEIGHT;
        let orchard_pos_shard_99: i64 = 99 << ORCHARD_SHARD_HEIGHT;

        for (action_index, position, _label) in [
            (0, Some(orchard_pos_shard_0), "stable shard"),
            (1, Some(orchard_pos_shard_1), "unstable shard"),
            (2, Some(orchard_pos_shard_2), "null end-height shard"),
            (3, None::<i64>, "null commitment_tree_position"),
            (4, Some(orchard_pos_shard_99), "no matching shard row"),
        ] {
            db_data
                .conn
                .execute(
                    "INSERT INTO orchard_received_notes (
                         transaction_id, action_index, account_id,
                         diversifier, value, rho, rseed, is_change,
                         commitment_tree_position
                     ) VALUES (1, :action_index, 1, X'00', 0, X'00', X'00', 0, :position)",
                    named_params![
                        ":action_index": action_index,
                        ":position": position,
                    ],
                )
                .unwrap();
        }

        // Run the migration under test.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // Read back the witness_stabilized values by output_index / action_index.
        let read = |table: &str, key_col: &str| -> Vec<(i64, i64)> {
            let mut stmt = db_data
                .conn
                .prepare(&format!(
                    "SELECT {key_col}, witness_stabilized FROM {table} ORDER BY {key_col}"
                ))
                .unwrap();
            let rows: Vec<(i64, i64)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows
        };

        // Only output 0 (stable shard) should have been stabilized.
        assert_eq!(
            read("sapling_received_notes", "output_index"),
            vec![(0, 1), (1, 0), (2, 0), (3, 0), (4, 0)],
            "sapling backfill should stabilize only the note whose shard's \
             subtree_end_height <= stable_height and whose commitment_tree_position \
             maps to that shard",
        );

        assert_eq!(
            read("orchard_received_notes", "action_index"),
            vec![(0, 1), (1, 0), (2, 0), (3, 0), (4, 0)],
            "orchard backfill must match the sapling behavior",
        );
    }

    /// When no rows have been inserted into `scan_queue`, the `MAX(...)` subquery
    /// returns `NULL`; the migration must treat this as a no-op and not stabilize
    /// any notes — even ones whose shards have finite `subtree_end_height` values.
    #[test]
    fn migrate_empty_scan_queue_is_noop() {
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

        // Seed just enough for a received note, but leave scan_queue empty.
        let usk =
            UnifiedSpendingKey::from_seed(&network, &seed_bytes, zip32::AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let ufvk_str = ufvk.encode(&network);
        let uivk_str = ufvk.to_unified_incoming_viewing_key().encode(&network);
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (id, uuid, account_kind,
                 hd_seed_fingerprint, hd_account_index,
                 ufvk, uivk, has_spend_key, birthday_height)
                 VALUES (1, X'0000000000000000000000000000AAAA', 0,
                 X'00000000000000000000000000000000000000000000000000000000000000AB',
                 0, :ufvk, :uivk, 1, 1)",
                named_params![":ufvk": ufvk_str, ":uivk": uivk_str],
            )
            .unwrap();
        db_data
            .conn
            .execute(
                "INSERT INTO transactions (id_tx, txid, min_observed_height)
                 VALUES (1, X'00', 1)",
                [],
            )
            .unwrap();
        db_data
            .conn
            .execute(
                "INSERT INTO sapling_tree_shards (shard_index, subtree_end_height)
                 VALUES (0, 1)",
                [],
            )
            .unwrap();
        db_data
            .conn
            .execute(
                "INSERT INTO sapling_received_notes (
                     transaction_id, output_index, account_id,
                     diversifier, value, rcm, is_change,
                     commitment_tree_position
                 ) VALUES (1, 0, 1, X'00', 0, X'00', 0, 1)",
                [],
            )
            .unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let stabilized: i64 = db_data
            .conn
            .query_row(
                "SELECT witness_stabilized FROM sapling_received_notes WHERE output_index = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stabilized, 0,
            "empty scan_queue must cause the backfill to be a no-op",
        );
    }
}
