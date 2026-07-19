//! Adds a `witness_stabilized` flag to received-note tables, indicating that the note's containing
//! shard's block extent has been fully scanned and that the shard's end height has received at
//! least `PRUNING_DEPTH` confirmations. Once set, the note has durable witness data. This can be
//! used to indicate note spendability during a rewind, when the scan queue may not provide a
//! usable indication.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use super::account_delete_cascade;
use crate::wallet::init::WalletMigrationError;
use crate::wallet::scanning::mark_stabilized_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x64925567_65ae_495e_b6cf_d5f56e99e422);

const DEPENDENCIES: &[Uuid] = &[account_delete_cascade::MIGRATION_ID];

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
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

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "ALTER TABLE sapling_received_notes
               ADD COLUMN witness_stabilized INTEGER NOT NULL DEFAULT 0;

             ALTER TABLE orchard_received_notes
               ADD COLUMN witness_stabilized INTEGER NOT NULL DEFAULT 0;

             CREATE INDEX idx_sapling_received_notes_witness_stabilized
                 ON sapling_received_notes (witness_stabilized);

             CREATE INDEX idx_orchard_received_notes_witness_stabilized
                 ON orchard_received_notes (witness_stabilized);",
        )?;

        // Backfill: Identify any notes which have stable witness data, and mark them as such.
        mark_stabilized_notes(transaction, &self.params)?;

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

    /// End-to-end exercise of the backfill: seed the pre-migration schema with a variety
    /// of notes whose stabilization outcomes are fully determined, run the migration, and
    /// assert the expected `witness_stabilized` value for each.
    #[test]
    fn migrate_backfills_stabilized_notes() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        let seed_bytes = vec![0xab; 32];

        // Migrate to the state just prior to this migration. At this point
        // `sapling_received_notes` / `orchard_received_notes` do not yet have the
        // `witness_stabilized` column.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        // Pick `last_scanned` so that the pruning floor `last_scanned - (PRUNING_DEPTH - 1)`
        // equals `stable_block_height`. Place all heights well above the Sapling and NU5
        // activation heights on TestNetwork (280,000 and 1,842,420 respectively) so that
        // each shard's block extent — `(prev.subtree_end_height, subtree_end_height]` with
        // `prev.subtree_end_height` defaulting to the pool's activation — actually
        // overlaps the scan_queue range inserted below. Otherwise the view's INNER JOIN
        // would return no rows for the shards and the test wouldn't exercise the
        // unscanned-ranges check.
        let base: u32 = 2_000_000;
        let stable_block_height: u32 = base + 301;
        let last_scanned: u32 = stable_block_height + (PRUNING_DEPTH - 1);
        let birthday_height: u32 = base;

        // Seed a minimal account. The UFVK/UIVK must be real encoded values because
        // `verify_network_compatibility` parses them when the migrator opens the database.
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

        // Seed a single transaction; none of the backfill logic cares about the block
        // column, only that there is an `id_tx` the note rows can reference.
        db_data
            .conn
            .execute(
                "INSERT INTO transactions (id_tx, txid, min_observed_height)
                 VALUES (1, X'00', 1)",
                [],
            )
            .unwrap();

        // A single `Scanned` range covering every height from the birthday through
        // `last_scanned` inclusive. Under this partition no non-Scanned range overlaps
        // any shard post-birthday, so the view `v_{pool}_shard_unscanned_ranges` is empty.
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

        // A `blocks` row is needed for `block_max_scanned` to return `Some`.
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

        // Tree shards. Shard 0 sits at the stabilization boundary and shard 1 sits one
        // block above it, so the test fails if the backfill picks either neighbour of
        // `<= pruning_floor`:
        //   shard 0: end height == stable_block_height       (notes here SHOULD stabilize)
        //   shard 1: end height == stable_block_height + 1   (notes here should NOT stabilize)
        //   shard 2: end height NULL                         (notes here should NOT stabilize)
        for pool in ["sapling", "orchard"] {
            db_data
                .conn
                .execute(
                    &format!(
                        "INSERT INTO {pool}_tree_shards (shard_index, subtree_end_height)
                         VALUES (0, :stable), (1, :above), (2, NULL)"
                    ),
                    named_params![
                        ":stable": stable_block_height,
                        ":above": stable_block_height + 1,
                    ],
                )
                .unwrap();
        }

        // Sapling seed rows cover every branch of the backfill predicate.
        // `(commitment_tree_position >> SAPLING_SHARD_HEIGHT)` picks the shard for a given
        // position.
        let sapling_pos_shard_0: i64 = 1;
        let sapling_pos_shard_1: i64 = 1 << SAPLING_SHARD_HEIGHT;
        let sapling_pos_shard_2: i64 = 2 << SAPLING_SHARD_HEIGHT;
        let sapling_pos_shard_99: i64 = 99 << SAPLING_SHARD_HEIGHT; // no shard row

        for (output_index, position, _label) in [
            (0, Some(sapling_pos_shard_0), "shard at boundary"),
            (
                1,
                Some(sapling_pos_shard_1),
                "shard one block above boundary",
            ),
            (2, Some(sapling_pos_shard_2), "null end-height shard"),
            (3, None::<i64>, "null commitment_tree_position"),
            (4, Some(sapling_pos_shard_99), "no matching shard row"),
        ] {
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

        // Orchard seed rows: identical coverage, with shard-height-appropriate positions.
        // The `orchard` feature gates the `ORCHARD_SHARD_HEIGHT` constant, so without it
        // this block is compiled out; the schema's `orchard_received_notes` table is
        // still created unconditionally but no notes exist to stabilize.
        #[cfg(feature = "orchard")]
        {
            let orchard_pos_shard_0: i64 = 1;
            let orchard_pos_shard_1: i64 = 1 << ORCHARD_SHARD_HEIGHT;
            let orchard_pos_shard_2: i64 = 2 << ORCHARD_SHARD_HEIGHT;
            let orchard_pos_shard_99: i64 = 99 << ORCHARD_SHARD_HEIGHT;

            for (action_index, position, _label) in [
                (0, Some(orchard_pos_shard_0), "shard at boundary"),
                (
                    1,
                    Some(orchard_pos_shard_1),
                    "shard one block above boundary",
                ),
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
        }

        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let read = |table: &str, pk_col: &str| -> Vec<(i64, i64)> {
            let mut stmt = db_data
                .conn
                .prepare(&format!(
                    "SELECT {pk_col}, witness_stabilized FROM {table} ORDER BY {pk_col}"
                ))
                .unwrap();
            let rows: Vec<(i64, i64)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows
        };

        // Only the note in the boundary shard (index 0) stabilizes; the other four
        // branches (above-boundary shard, null end-height shard, null position, no
        // matching shard row) must all remain unstabilized.
        assert_eq!(
            read("sapling_received_notes", "output_index"),
            vec![(0, 1), (1, 0), (2, 0), (3, 0), (4, 0)],
            "sapling backfill should stabilize only notes whose containing shard has \
             subtree_end_height <= pruning_floor and no non-Scanned scan_queue overlap",
        );

        #[cfg(feature = "orchard")]
        assert_eq!(
            read("orchard_received_notes", "action_index"),
            vec![(0, 1), (1, 0), (2, 0), (3, 0), (4, 0)],
            "orchard backfill must match the sapling behavior",
        );
    }

    /// When the wallet has no scan state yet — no `blocks` rows and no `scan_queue`
    /// rows — `block_max_scanned` returns `None` and the backfill must be a no-op, even
    /// for notes whose containing shard's `subtree_end_height` is finite.
    #[test]
    fn migrate_without_scan_state_is_noop() {
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
            "absent scan state must cause the backfill to be a no-op",
        );
    }

    /// Regression test: a note whose containing shard's `subtree_end_height` is known
    /// (e.g. populated by `put_shard_roots`) and lies at or below the pruning floor must
    /// NOT be treated as stabilized if any block inside the shard's extent is covered by
    /// a non-Scanned `scan_queue` range. An earlier criterion that only required
    /// `subtree_end_height <= last_scanned - (PRUNING_DEPTH - 1)` could spuriously
    /// stabilize such a note even though the wallet was missing the intra-shard
    /// commitments inside the unscanned gap, stranding the note at spend time. The fix is
    /// the per-shard view-based check in `mark_stabilized_notes`.
    #[test]
    fn gap_in_scanned_coverage_prevents_stabilization() {
        use zcash_client_backend::data_api::scanning::ScanPriority;

        use crate::wallet::scanning::{mark_stabilized_notes, priority_code};

        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        let seed_bytes = vec![0xab; 32];

        // Migrate through `witness_stabilized_notes` so the schema is in its final state.
        // Because there is no scan_queue / blocks / shards seeded yet, the migration's
        // backfill is a no-op and the column default (0) applies to all rows we're about
        // to insert.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // Scenario: the `scan_queue` partition covers `[birthday, chain_tip_exclusive)`
        // with a non-Scanned (here: Historic) gap `[low_end, high_start)` in the middle.
        // Shard 0's block extent is `(birthday, shard_end_height]`, which overlaps that
        // gap. The shard's end lies below the pruning floor, so the only remaining
        // barrier to stabilization is the view-based unscanned-range check.
        //
        //   birthday          low_end  gap    high_start           shard_end         max_scanned
        //   |--- Scanned --------|---Historic---|--------- Scanned -------|-- Scanned -----|
        //                                                 ^
        //                                   shard 0's extent covers (birthday, shard_end],
        //                                   which straddles the non-Scanned gap.
        // All heights sit above the NU5 testnet activation height (1,842,420) so that each
        // pool's shard scan-range view actually joins the shard to the scan_queue rows
        // below — otherwise the shard's view-frame extent would be empty and the gap
        // couldn't overlap.
        let base: u32 = 2_000_000;
        let birthday_height: u32 = base + 1;
        let low_end: u32 = base + 150; // exclusive upper bound of the low Scanned range
        let high_start: u32 = base + 200;
        let shard_end_height: u32 = base + 250;
        let max_scanned: u32 = shard_end_height + PRUNING_DEPTH + 50;
        let chain_tip_exclusive: u32 = max_scanned + 1;
        let pruning_floor: u32 = max_scanned - (PRUNING_DEPTH - 1);
        assert!(
            shard_end_height <= pruning_floor,
            "test invariant: shard end must lie at or below the pruning floor so the \
             only remaining barrier to stabilization is the unscanned-range check",
        );
        assert!(
            low_end < high_start && high_start < shard_end_height,
            "test invariant: non-Scanned gap must lie inside shard 0's extent",
        );

        // Seed a minimal account so `wallet_birthday(conn)` returns `Some(birthday_height)`.
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

        // Seed a single transaction; the note rows need an `id_tx` to reference.
        db_data
            .conn
            .execute(
                "INSERT INTO transactions (id_tx, txid, min_observed_height)
                 VALUES (1, X'00', 1)",
                [],
            )
            .unwrap();

        // `scan_queue` is a partition of `[birthday, chain_tip_exclusive)`:
        //   [birthday, low_end)       priority Scanned
        //   [low_end, high_start)     priority Historic  <-- the non-Scanned gap
        //   [high_start, chain_tip)   priority Scanned
        let scanned = priority_code(&ScanPriority::Scanned);
        let historic = priority_code(&ScanPriority::Historic);
        db_data
            .conn
            .execute(
                "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                 VALUES
                    (:start1, :end1, :scanned),
                    (:start2, :end2, :historic),
                    (:start3, :end3, :scanned)",
                named_params![
                    ":start1": birthday_height,
                    ":end1": low_end,
                    ":start2": low_end,
                    ":end2": high_start,
                    ":start3": high_start,
                    ":end3": chain_tip_exclusive,
                    ":scanned": scanned,
                    ":historic": historic,
                ],
            )
            .unwrap();

        // A `blocks` row at `max_scanned` so `block_max_scanned` reflects the high range's
        // tip and the helper can compute the pruning floor.
        db_data
            .conn
            .execute(
                "INSERT INTO blocks (
                     height, hash, time,
                     sapling_tree, sapling_commitment_tree_size
                 ) VALUES
                     (:max_scanned, X'0000000000000000000000000000000000000000000000000000000000000000', 0, X'', 0)",
                named_params![":max_scanned": max_scanned],
            )
            .unwrap();

        // Shard 0 with `subtree_end_height = shard_end_height`. Its block extent is
        // `(birthday, shard_end_height]`, which overlaps the non-Scanned gap. Its end
        // lies below the pruning floor, so the criterion's only remaining barrier is the
        // view-based unscanned-range check.
        for pool in ["sapling", "orchard"] {
            db_data
                .conn
                .execute(
                    &format!(
                        "INSERT INTO {pool}_tree_shards (shard_index, subtree_end_height)
                         VALUES (0, :end)"
                    ),
                    named_params![":end": shard_end_height],
                )
                .unwrap();
        }

        // One note per pool in shard 0. `commitment_tree_position = 1` places each note
        // inside shard index 0 for both SAPLING_SHARD_HEIGHT and ORCHARD_SHARD_HEIGHT.
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
        #[cfg(feature = "orchard")]
        db_data
            .conn
            .execute(
                "INSERT INTO orchard_received_notes (
                     transaction_id, action_index, account_id,
                     diversifier, value, rho, rseed, is_change,
                     commitment_tree_position
                 ) VALUES (1, 0, 1, X'00', 0, X'00', X'00', 0, 1)",
                [],
            )
            .unwrap();

        let read_stabilized = |conn: &rusqlite::Connection, table: &str, pk_col: &str| -> i64 {
            conn.query_row(
                &format!("SELECT witness_stabilized FROM {table} WHERE {pk_col} = 0"),
                [],
                |row| row.get(0),
            )
            .unwrap()
        };

        // First call: the non-Scanned gap lies inside shard 0's extent, so the note must
        // NOT stabilize.
        let tx = db_data.conn.transaction().unwrap();
        mark_stabilized_notes(&tx, &network).unwrap();
        tx.commit().unwrap();

        assert_eq!(
            read_stabilized(&db_data.conn, "sapling_received_notes", "output_index"),
            0,
            "sapling note must not be stabilized while a non-Scanned scan_queue \
             range overlaps its containing shard's extent",
        );
        #[cfg(feature = "orchard")]
        assert_eq!(
            read_stabilized(&db_data.conn, "orchard_received_notes", "action_index"),
            0,
            "orchard note must not be stabilized while a non-Scanned scan_queue \
             range overlaps its containing shard's extent",
        );

        // Replace the three ranges with a single contiguous Scanned range
        // `[birthday, chain_tip_exclusive)`. The view should now return no rows for
        // shard 0, so the note stabilizes.
        db_data.conn.execute("DELETE FROM scan_queue", []).unwrap();
        db_data
            .conn
            .execute(
                "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                 VALUES (:start, :end, :priority)",
                named_params![
                    ":start": birthday_height,
                    ":end": chain_tip_exclusive,
                    ":priority": scanned,
                ],
            )
            .unwrap();

        let tx = db_data.conn.transaction().unwrap();
        mark_stabilized_notes(&tx, &network).unwrap();
        tx.commit().unwrap();

        assert_eq!(
            read_stabilized(&db_data.conn, "sapling_received_notes", "output_index"),
            1,
            "sapling note must be stabilized once the gap is filled",
        );
        #[cfg(feature = "orchard")]
        assert_eq!(
            read_stabilized(&db_data.conn, "orchard_received_notes", "action_index"),
            1,
            "orchard note must be stabilized once the gap is filled",
        );
    }
}
