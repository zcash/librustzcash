//! This migration fixes a bug in `v_transactions` where distinct but otherwise identical notes
//! were being incorrectly deduplicated.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::v_transactions_shielding_balance;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xdba47c86_13b5_4601_94b2_0cde0abe1e45);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [v_transactions_shielding_balance::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Fixes a bug in v_transactions that was omitting value from identically-valued notes."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_transactions;
            CREATE VIEW v_transactions AS
            WITH
            notes AS (
                SELECT sapling_received_notes.id_note        AS id,
                       sapling_received_notes.account        AS account_id,
                       transactions.block                    AS block,
                       transactions.txid                     AS txid,
                       2                                     AS pool,
                       sapling_received_notes.value          AS value,
                       CASE
                            WHEN sapling_received_notes.is_change THEN 1
                            ELSE 0
                       END AS is_change,
                       CASE
                            WHEN sapling_received_notes.is_change THEN 0
                            ELSE 1
                       END AS received_count,
                       CASE
                         WHEN (sapling_received_notes.memo IS NULL OR sapling_received_notes.memo = X'F6')
                           THEN 0
                         ELSE 1
                       END AS memo_present
                FROM sapling_received_notes
                JOIN transactions
                     ON transactions.id_tx = sapling_received_notes.tx
                UNION
                SELECT utxos.id_utxo                 AS id,
                       utxos.received_by_account     AS account_id,
                       utxos.height                  AS block,
                       utxos.prevout_txid            AS txid,
                       0                             AS pool,
                       utxos.value_zat               AS value,
                       0                             AS is_change,
                       1                             AS received_count,
                       0                             AS memo_present
                FROM utxos
                UNION
                SELECT sapling_received_notes.id_note        AS id,
                       sapling_received_notes.account        AS account_id,
                       transactions.block                    AS block,
                       transactions.txid                     AS txid,
                       2                                     AS pool,
                       -sapling_received_notes.value         AS value,
                       0                             AS is_change,
                       0                             AS received_count,
                       0                             AS memo_present
                FROM sapling_received_notes
                JOIN transactions
                     ON transactions.id_tx = sapling_received_notes.spent
                UNION
                SELECT utxos.id_utxo                 AS id,
                       utxos.received_by_account     AS account_id,
                       transactions.block            AS block,
                       transactions.txid             AS txid,
                       0                             AS pool,
                       -utxos.value_zat              AS value,
                       0                             AS is_change,
                       0                             AS received_count,
                       0                             AS memo_present
                FROM utxos
                JOIN transactions
                     ON transactions.id_tx = utxos.spent_in_tx
            ),
            sent_note_counts AS (
                SELECT sent_notes.from_account AS account_id,
                       transactions.txid       AS txid,
                       COUNT(DISTINCT sent_notes.id_note) as sent_notes,
                       SUM(
                         CASE
                           WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR sapling_received_notes.tx IS NOT NULL)
                             THEN 0
                           ELSE 1
                         END
                       ) AS memo_count
                FROM sent_notes
                JOIN transactions
                     ON transactions.id_tx = sent_notes.tx
                LEFT JOIN sapling_received_notes
                          ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                             (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
                WHERE COALESCE(sapling_received_notes.is_change, 0) = 0
                GROUP BY account_id, txid
            ),
            blocks_max_height AS (
                SELECT MAX(blocks.height) as max_height FROM blocks
            )
            SELECT notes.account_id                  AS account_id,
                   notes.block                       AS mined_height,
                   notes.txid                        AS txid,
                   transactions.tx_index             AS tx_index,
                   transactions.expiry_height        AS expiry_height,
                   transactions.raw                  AS raw,
                   SUM(notes.value)                  AS account_balance_delta,
                   transactions.fee                  AS fee_paid,
                   SUM(notes.is_change) > 0          AS has_change,
                   MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
                   SUM(notes.received_count)         AS received_note_count,
                   SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
                   blocks.time                       AS block_time,
                   (
                        blocks.height IS NULL
                        AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
                   ) AS expired_unmined
            FROM notes
            LEFT JOIN transactions
                 ON notes.txid = transactions.txid
            JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = notes.block
            LEFT JOIN sent_note_counts
                      ON sent_note_counts.account_id = notes.account_id
                      AND sent_note_counts.txid = notes.txid
            GROUP BY notes.account_id, notes.txid;"
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{self, params};
    use tempfile::NamedTempFile;

    use zcash_client_backend::keys::UnifiedSpendingKey;
    use zcash_primitives::{consensus::Network, zip32::AccountId};

    use crate::{
        wallet::init::{init_wallet_db_internal, migrations::v_transactions_net},
        WalletDb,
    };

    #[test]
    fn v_transactions_note_uniqueness_migration() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
        init_wallet_db_internal(
            &mut db_data,
            None,
            &[v_transactions_net::MIGRATION_ID],
            false,
        )
        .unwrap();

        // Create an account in the wallet
        let usk0 = UnifiedSpendingKey::from_seed(&db_data.params, &[0u8; 32][..], AccountId::ZERO)
            .unwrap();
        let ufvk0 = usk0.to_unified_full_viewing_key();
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (account, ufvk) VALUES (0, ?)",
                params![ufvk0.encode(&db_data.params)],
            )
            .unwrap();

        // Tx 0 contains two received notes, both of 2 zatoshis, that are controlled by account 0.
        db_data.conn.execute_batch(
            "INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, x'00');
            INSERT INTO transactions (block, id_tx, txid) VALUES (0, 0, 'tx0');

            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
            VALUES (0, 0, 0, '', 2, '', 'nf_a', false);
            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
            VALUES (0, 3, 0, '', 2, '', 'nf_b', false);").unwrap();

        let check_balance_delta = |db_data: &mut WalletDb<rusqlite::Connection, Network>,
                                   expected_notes: i64| {
            let mut q = db_data
                .conn
                .prepare(
                    "SELECT account_id, account_balance_delta, has_change, memo_count, sent_note_count, received_note_count
                    FROM v_transactions",
                )
                .unwrap();
            let mut rows = q.query([]).unwrap();
            let mut row_count = 0;
            while let Some(row) = rows.next().unwrap() {
                row_count += 1;
                let account: i64 = row.get(0).unwrap();
                let account_balance_delta: i64 = row.get(1).unwrap();
                let has_change: bool = row.get(2).unwrap();
                let memo_count: i64 = row.get(3).unwrap();
                let sent_note_count: i64 = row.get(4).unwrap();
                let received_note_count: i64 = row.get(5).unwrap();
                match account {
                    0 => {
                        assert_eq!(account_balance_delta, 2 * expected_notes);
                        assert!(!has_change);
                        assert_eq!(memo_count, 0);
                        assert_eq!(sent_note_count, 0);
                        assert_eq!(received_note_count, expected_notes);
                    }
                    other => {
                        panic!(
                            "Account {:?} is not expected to exist in the wallet.",
                            other
                        );
                    }
                }
            }
            assert_eq!(row_count, 1);
        };

        // Check for the bug (#1020).
        check_balance_delta(&mut db_data, 1);

        // Apply the current migration.
        init_wallet_db_internal(&mut db_data, None, &[super::MIGRATION_ID], false).unwrap();

        // Now it should be correct.
        check_balance_delta(&mut db_data, 2);
    }
}
