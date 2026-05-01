//! Replaces the boolean `witness_stabilized` flag on received-note tables with a
//! `witness_anchor_stable` column whose value is the containing shard's
//! `subtree_end_height` at the time of stabilization. The new column carries the same
//! "this note's witness data is durable" information as the old flag, plus the
//! specific anchor height up to which the leaf-level path has been finalized.
//!
//! This migration is semantics-preserving: every row that previously had
//! `witness_stabilized = 1` ends up with a non-NULL `witness_anchor_stable`, and
//! every row that had `witness_stabilized = 0` ends up with `NULL`. Subsequent
//! migrations and code may use the height value for finer-grained spendability
//! decisions.
//!
//! The backfill performs a per-row lookup of `subtree_end_height` against the matching
//! shard, derived from `commitment_tree_position >> shard_height`.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::data_api::SAPLING_SHARD_HEIGHT;
use zcash_protocol::consensus;

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

use super::witness_stabilized_notes;
use crate::{SAPLING_TABLES_PREFIX, wallet::init::WalletMigrationError};

#[cfg(feature = "orchard")]
use crate::ORCHARD_TABLES_PREFIX;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa3f1c4d8_5e21_4b9c_9f43_61c8a3e91a02);

const DEPENDENCIES: &[Uuid] = &[witness_stabilized_notes::MIGRATION_ID];

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
               ADD COLUMN witness_anchor_stable INTEGER;",
        )?;

        // Backfill: for every previously-stabilized row, look up the shard's
        // subtree_end_height. The old `mark_stabilized_notes` predicate required
        // `subtree_end_height IS NOT NULL` for stabilization, so the lookup is
        // guaranteed to find a height for every row with witness_stabilized = 1.
        let backfill = |table_prefix: &str, shard_height: u8| -> String {
            format!(
                "UPDATE {table_prefix}_received_notes
                 SET witness_anchor_stable = (
                     SELECT subtree_end_height
                     FROM {table_prefix}_tree_shards
                     WHERE shard_index =
                         ({table_prefix}_received_notes.commitment_tree_position >> {shard_height})
                 )
                 WHERE witness_stabilized = 1"
            )
        };
        transaction.execute_batch(&backfill(SAPLING_TABLES_PREFIX, SAPLING_SHARD_HEIGHT))?;
        #[cfg(feature = "orchard")]
        transaction.execute_batch(&backfill(ORCHARD_TABLES_PREFIX, ORCHARD_SHARD_HEIGHT))?;
        // Without the `orchard` feature the orchard tables exist but no orchard
        // received notes can have been recorded, so the backfill is unnecessary; we
        // still drop the column below so the schema matches across feature
        // configurations.
        #[cfg(not(feature = "orchard"))]
        let _ = backfill;

        // Replace the old column and its index with one keyed on the new column.
        transaction.execute_batch(
            "DROP INDEX idx_sapling_received_notes_witness_stabilized;
             DROP INDEX idx_orchard_received_notes_witness_stabilized;

             ALTER TABLE sapling_received_notes DROP COLUMN witness_stabilized;
             ALTER TABLE orchard_received_notes DROP COLUMN witness_stabilized;

             CREATE INDEX idx_sapling_received_notes_witness_anchor_stable
                 ON sapling_received_notes (witness_anchor_stable);

             CREATE INDEX idx_orchard_received_notes_witness_anchor_stable
                 ON orchard_received_notes (witness_anchor_stable);",
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
    use zcash_client_backend::data_api::SAPLING_SHARD_HEIGHT;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use crate::{
        PRUNING_DEPTH, WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[cfg(feature = "orchard")]
    use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// End-to-end exercise of the backfill: seed pre-migration rows with each of the
    /// four combinations of {`witness_stabilized` ∈ {0, 1}} × {shard has
    /// `subtree_end_height` ∈ {Some, None}}, run the migration, and confirm that
    /// `witness_anchor_stable` ends up with the shard's `subtree_end_height` exactly
    /// when `witness_stabilized` was 1 (and otherwise NULL).
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

        let base: u32 = 2_000_000;
        let stable_block_height: u32 = base + 301;
        let last_scanned: u32 = stable_block_height + (PRUNING_DEPTH - 1);
        let birthday_height: u32 = base;

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
                 0, :ufvk, :uivk, 1, :birthday_height)",
                named_params![
                    ":ufvk": ufvk_str,
                    ":uivk": uivk_str,
                    ":birthday_height": birthday_height,
                ],
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
                "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                 VALUES (:start, :end, 10)",
                named_params![
                    ":start": birthday_height,
                    ":end": last_scanned + 1,
                ],
            )
            .unwrap();

        db_data
            .conn
            .execute(
                "INSERT INTO blocks (
                     height, hash, time,
                     sapling_tree, sapling_commitment_tree_size
                 ) VALUES (:height, X'0000000000000000000000000000000000000000000000000000000000000000', 0,
                          X'', 0)",
                named_params![":height": last_scanned],
            )
            .unwrap();

        // Two shards:
        //   shard 0: subtree_end_height = stable_block_height
        //   shard 1: subtree_end_height = NULL (active shard)
        for pool in ["sapling", "orchard"] {
            db_data
                .conn
                .execute(
                    &format!(
                        "INSERT INTO {pool}_tree_shards (shard_index, subtree_end_height)
                         VALUES (0, :stable), (1, NULL)"
                    ),
                    named_params![":stable": stable_block_height],
                )
                .unwrap();
        }

        // Sapling seed rows. Each row's pre-migration `witness_stabilized` value is
        // set explicitly; the migration translates 1's into the matching shard's
        // `subtree_end_height` and leaves 0's as NULL.
        let sapling_pos_shard_0: i64 = 1;
        let sapling_pos_shard_1: i64 = 1 << SAPLING_SHARD_HEIGHT;

        for (output_index, position, witness_stabilized) in [
            (0, sapling_pos_shard_0, 1), // stabilized in completed shard
            (1, sapling_pos_shard_0, 0), // not stabilized but in completed shard
            (2, sapling_pos_shard_1, 0), // not stabilized, in active shard
        ] {
            db_data
                .conn
                .execute(
                    "INSERT INTO sapling_received_notes (
                         transaction_id, output_index, account_id,
                         diversifier, value, rcm, is_change,
                         commitment_tree_position, witness_stabilized
                     ) VALUES (1, :output_index, 1, X'00', 0, X'00', 0, :position, :stabilized)",
                    named_params![
                        ":output_index": output_index,
                        ":position": position,
                        ":stabilized": witness_stabilized,
                    ],
                )
                .unwrap();
        }

        #[cfg(feature = "orchard")]
        {
            let orchard_pos_shard_0: i64 = 1;
            let orchard_pos_shard_1: i64 = 1 << ORCHARD_SHARD_HEIGHT;

            for (action_index, position, witness_stabilized) in [
                (0, orchard_pos_shard_0, 1),
                (1, orchard_pos_shard_0, 0),
                (2, orchard_pos_shard_1, 0),
            ] {
                db_data
                    .conn
                    .execute(
                        "INSERT INTO orchard_received_notes (
                             transaction_id, action_index, account_id,
                             diversifier, value, rho, rseed, is_change,
                             commitment_tree_position, witness_stabilized
                         ) VALUES (1, :action_index, 1, X'00', 0, X'00', X'00', 0, :position, :stabilized)",
                        named_params![
                            ":action_index": action_index,
                            ":position": position,
                            ":stabilized": witness_stabilized,
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

        // The single row that had `witness_stabilized = 1` ends up with the matching
        // shard's `subtree_end_height`; the others end up NULL.
        assert_eq!(
            read("sapling_received_notes", "output_index"),
            vec![
                (0, Some(i64::from(stable_block_height))),
                (1, None),
                (2, None),
            ],
            "sapling backfill must translate witness_stabilized=1 rows to subtree_end_height",
        );

        #[cfg(feature = "orchard")]
        assert_eq!(
            read("orchard_received_notes", "action_index"),
            vec![
                (0, Some(i64::from(stable_block_height))),
                (1, None),
                (2, None),
            ],
            "orchard backfill must match the sapling behavior",
        );
    }
}
