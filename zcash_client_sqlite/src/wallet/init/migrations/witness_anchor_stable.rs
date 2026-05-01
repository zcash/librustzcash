//! Replaces the boolean `witness_stabilized` flag on received-note tables with a
//! `witness_anchor_stable` column recording the lowest anchor at which each note's
//! witness is durably constructable, then drops the old flag.
//!
//! The column is **recomputed from authoritative tree and scan state**, not converted
//! from the old boolean. The released `witness_stabilized_notes` migration set that
//! boolean using an earlier pruning-floor formula (`block_max_scanned - (PRUNING_DEPTH
//! - 1)`); recomputing here — mirroring the current `mark_stabilized_notes` first-time
//! stabilize rule — brings a migrated wallet into exact agreement with one synced fresh
//! under the current rule, and additionally stabilizes notes in the active (tip) shard,
//! which the boolean never covered. The boolean value is therefore ignored entirely.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::data_api::SAPLING_SHARD_HEIGHT;
use zcash_protocol::consensus;

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

use super::witness_stabilized_notes;
use crate::{
    SAPLING_TABLES_PREFIX,
    wallet::{chain_tip_height, init::WalletMigrationError, scanning::pruning_floor},
};

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

        // Backfill: recompute each note's anchor-stable height from authoritative tree and
        // scan state, mirroring `scanning::mark_stabilized_notes`'s first-time-stabilize arm
        // at the time this migration was authored. The old `witness_stabilized` boolean is
        // deliberately *not* consulted; see the module docs. The SQL is inlined rather than
        // calling `mark_stabilized_notes` so this migration stays stable as that helper evolves.
        //
        // For each note whose containing shard has no unscanned ranges, the stored height is
        // the maximum of three lower bounds on a usable anchor: the note's own `t.block`, the
        // pruning floor, and the shard's `subtree_end_height` (`NULL`, coalesced to 0, for the
        // active chain-tip shard). See `mark_stabilized_notes` for the rationale of each term.
        if let Some(chain_tip) = chain_tip_height(transaction)? {
            let pruning_floor: u32 = u32::from(pruning_floor(chain_tip));
            let backfill = |table_prefix: &str| -> String {
                format!(
                    "UPDATE {table_prefix}_received_notes
                     SET witness_anchor_stable = max(
                         (SELECT t.block
                          FROM transactions t
                          WHERE t.id_tx = {table_prefix}_received_notes.transaction_id),
                         :pruning_floor,
                         IFNULL(
                             (SELECT shard.subtree_end_height
                              FROM {table_prefix}_tree_shards shard
                              WHERE shard.shard_index
                                    = ({table_prefix}_received_notes.commitment_tree_position
                                       >> :shard_height)),
                             0
                         )
                     )
                     WHERE commitment_tree_position IS NOT NULL
                       AND (commitment_tree_position >> :shard_height) NOT IN (
                           SELECT shard_index FROM v_{table_prefix}_shard_unscanned_ranges
                       )"
                )
            };
            transaction.execute(
                &backfill(SAPLING_TABLES_PREFIX),
                named_params![
                    ":pruning_floor": pruning_floor,
                    ":shard_height": SAPLING_SHARD_HEIGHT,
                ],
            )?;
            #[cfg(feature = "orchard")]
            transaction.execute(
                &backfill(ORCHARD_TABLES_PREFIX),
                named_params![
                    ":pruning_floor": pruning_floor,
                    ":shard_height": ORCHARD_SHARD_HEIGHT,
                ],
            )?;
            #[cfg(not(feature = "orchard"))]
            let _ = backfill;
        }

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

    /// End-to-end exercise of the recompute backfill: under a fully-`Scanned` queue, seed a
    /// note in a completed (buried) shard, a note in the active (tip) shard, and a note with
    /// no commitment-tree position; run the migration; and confirm `witness_anchor_stable` is
    /// the three-way `max(t.block, pruning_floor, subtree_end_height)` for the notes in
    /// scan-clean shards — including the tip-shard note, which the old boolean never covered —
    /// and `NULL` for the positionless note. The pre-migration `witness_stabilized` value is
    /// irrelevant (left at its default), since the backfill recomputes from tree/scan state.
    #[test]
    fn migrate_backfills_anchor_heights() {
        use zcash_client_backend::data_api::scanning::ScanPriority;

        use crate::wallet::scanning::priority_code;

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

        // A single contiguous `Scanned` range over `[birthday, chain_tip + 1)`: every shard is
        // scan-clean (nothing above `Scanned` overlaps), so the backfill's unscanned-range
        // gate admits all positioned notes.
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
        for pool in ["sapling", "orchard"] {
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

        // Buried-shard note: `max(low_block, pruning_floor, buried_shard_end)` = the pruning
        // floor (it lifts the stored height above the shard's own end). Tip-shard note:
        // `max(tip_block, pruning_floor, 0)` = `tip_block` (the note's own block dominates).
        // Positionless note: excluded by the gate, so `NULL`.
        let expected = vec![
            (0, Some(i64::from(pruning_floor_h))),
            (1, Some(i64::from(tip_block))),
            (2, None),
        ];
        assert_eq!(
            read("sapling_received_notes", "output_index"),
            expected,
            "sapling backfill must record max(t.block, pruning_floor, subtree_end_height) for \
             scan-clean shards and NULL for positionless notes",
        );

        #[cfg(feature = "orchard")]
        assert_eq!(
            read("orchard_received_notes", "action_index"),
            expected,
            "orchard backfill must match the sapling behavior",
        );
    }
}
