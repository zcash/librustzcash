//! A migration that renames the `received_notes` table to `sapling_received_notes`
//! and makes the `nf` column nullable. This allows change notes to be added to the
//! table prior to being mined.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::v_transactions_net;
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0xbdcdcedc,
    0x7b29,
    0x4f1c,
    b"\x83\x07\x35\xf9\x37\xf0\xd3\x2a",
);

pub(crate) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [v_transactions_net::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Rename `received_notes` to `sapling_received_notes` and make the `nf` column nullable."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // As of this migration, the `received_notes` table only stores Sapling notes, so
        // we can hard-code the `output_pool` value.
        transaction.execute_batch(
            "CREATE TABLE sapling_received_notes (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                account INTEGER NOT NULL,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rcm BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                spent INTEGER,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (account) REFERENCES accounts(account),
                FOREIGN KEY (spent) REFERENCES transactions(id_tx),
                CONSTRAINT tx_output UNIQUE (tx, output_index)
            );
            INSERT INTO sapling_received_notes SELECT * FROM received_notes;",
        )?;

        transaction.execute_batch(
            "ALTER TABLE sapling_witnesses RENAME TO sapling_witnesses_old;
            CREATE TABLE sapling_witnesses (
                id_witness INTEGER PRIMARY KEY,
                note INTEGER NOT NULL,
                block INTEGER NOT NULL,
                witness BLOB NOT NULL,
                FOREIGN KEY (note) REFERENCES sapling_received_notes(id_note),
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT witness_height UNIQUE (note, block)
            );
            INSERT INTO sapling_witnesses SELECT * FROM sapling_witnesses_old;
            DROP TABLE sapling_witnesses_old;",
        )?;

        transaction.execute_batch(
            "DROP VIEW v_tx_outputs;
            CREATE VIEW v_tx_outputs AS
            SELECT sapling_received_notes.tx           AS id_tx,
                   2                                   AS output_pool,
                   sapling_received_notes.output_index AS output_index,
                   sent_notes.from_account             AS from_account,
                   sapling_received_notes.account      AS to_account,
                   NULL                                AS to_address,
                   sapling_received_notes.value        AS value,
                   sapling_received_notes.is_change    AS is_change,
                   sapling_received_notes.memo         AS memo
            FROM sapling_received_notes
            LEFT JOIN sent_notes
                      ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                         (sapling_received_notes.tx, 2, sent_notes.output_index)
            UNION
            SELECT transactions.id_tx          AS id_tx,
                   0                           AS output_pool,
                   utxos.prevout_idx           AS output_index,
                   NULL                        AS from_account,
                   utxos.received_by_account   AS to_account,
                   utxos.address               AS to_address,
                   utxos.value_zat             AS value,
                   false                       AS is_change,
                   NULL                        AS memo
            FROM utxos
            JOIN transactions
                 ON transactions.txid = utxos.prevout_txid
            UNION
            SELECT sent_notes.tx                  AS id_tx,
                   sent_notes.output_pool         AS output_pool,
                   sent_notes.output_index        AS output_index,
                   sent_notes.from_account        AS from_account,
                   sapling_received_notes.account AS to_account,
                   sent_notes.to_address          AS to_address,
                   sent_notes.value               AS value,
                   false                          AS is_change,
                   sent_notes.memo                AS memo
            FROM sent_notes
            LEFT JOIN sapling_received_notes
                      ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                         (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
            WHERE  sapling_received_notes.is_change IS NULL
               OR  sapling_received_notes.is_change = 0",
        )?;

        transaction.execute_batch(
            "DROP VIEW v_transactions;
            CREATE VIEW v_transactions AS
            WITH
            notes AS (
                SELECT sapling_received_notes.account        AS account_id,
                       sapling_received_notes.tx             AS id_tx,
                       2                             AS pool,
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
                           WHEN sapling_received_notes.memo IS NULL THEN 0
                           ELSE 1
                       END AS memo_present
                FROM   sapling_received_notes
                UNION
                SELECT utxos.received_by_account     AS account_id,
                       transactions.id_tx            AS id_tx,
                       0                             AS pool,
                       utxos.value_zat               AS value,
                       0                             AS is_change,
                       1                             AS received_count,
                       0                             AS memo_present
                FROM utxos
                JOIN transactions
                     ON transactions.txid = utxos.prevout_txid
                UNION
                SELECT sapling_received_notes.account        AS account_id,
                       sapling_received_notes.spent          AS id_tx,
                       2                             AS pool,
                       -sapling_received_notes.value         AS value,
                       0                             AS is_change,
                       0                             AS received_count,
                       0                             AS memo_present
                FROM   sapling_received_notes
                WHERE  sapling_received_notes.spent IS NOT NULL
            ),
            sent_note_counts AS (
                SELECT sent_notes.from_account AS account_id,
                       sent_notes.tx AS id_tx,
                       COUNT(DISTINCT sent_notes.id_note) as sent_notes,
                       SUM(
                         CASE
                             WHEN sent_notes.memo IS NULL THEN 0
                             ELSE 1
                         END
                       ) AS memo_count
                FROM sent_notes
                LEFT JOIN sapling_received_notes
                          ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                             (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
                WHERE  sapling_received_notes.is_change IS NULL
                   OR  sapling_received_notes.is_change = 0
                GROUP BY account_id, id_tx
            ),
            blocks_max_height AS (
                SELECT MAX(blocks.height) as max_height FROM blocks
            )
            SELECT notes.account_id                  AS account_id,
                   transactions.id_tx                AS id_tx,
                   transactions.block                AS mined_height,
                   transactions.tx_index             AS tx_index,
                   transactions.txid                 AS txid,
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
                        AND transactions.expiry_height <= blocks_max_height.max_height
                   ) AS expired_unmined
            FROM transactions
            JOIN notes ON notes.id_tx = transactions.id_tx
            JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = transactions.block
            LEFT JOIN sent_note_counts
                      ON sent_note_counts.account_id = notes.account_id
                      AND sent_note_counts.id_tx = notes.id_tx
            GROUP BY notes.account_id, transactions.id_tx",
        )?;

        transaction.execute_batch("DROP TABLE received_notes;")?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{self, params};
    use tempfile::NamedTempFile;

    use zcash_client_backend::keys::UnifiedSpendingKey;
    use zcash_primitives::zip32::AccountId;

    use crate::{
        tests,
        wallet::init::{init_wallet_db_internal, migrations::v_transactions_net},
        WalletDb,
    };

    #[test]
    fn received_notes_nullable_migration() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db_internal(&mut db_data, None, &[v_transactions_net::MIGRATION_ID]).unwrap();

        // Create an account in the wallet
        let usk0 =
            UnifiedSpendingKey::from_seed(&tests::network(), &[0u8; 32][..], AccountId::from(0))
                .unwrap();
        let ufvk0 = usk0.to_unified_full_viewing_key();
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (account, ufvk) VALUES (0, ?)",
                params![ufvk0.encode(&tests::network())],
            )
            .unwrap();

        // Tx 0 contains two received notes of 2 and 5 zatoshis that are controlled by account 0.
        db_data.conn.execute_batch(
            "INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, '');
            INSERT INTO transactions (block, id_tx, txid) VALUES (0, 0, 'tx0');

            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
            VALUES (0, 0, 0, '', 2, '', 'nf_a', false);
            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
            VALUES (0, 3, 0, '', 5, '', 'nf_b', false);").unwrap();

        // Apply the current migration
        init_wallet_db_internal(&mut db_data, None, &[super::MIGRATION_ID]).unwrap();

        {
            let mut q = db_data
                .conn
                .prepare(
                    "SELECT account_id, id_tx, account_balance_delta, has_change, memo_count, sent_note_count, received_note_count
                    FROM v_transactions",
                )
                .unwrap();
            let mut rows = q.query([]).unwrap();
            let mut row_count = 0;
            while let Some(row) = rows.next().unwrap() {
                row_count += 1;
                let account: i64 = row.get(0).unwrap();
                let tx: i64 = row.get(1).unwrap();
                let account_balance_delta: i64 = row.get(2).unwrap();
                let has_change: bool = row.get(3).unwrap();
                let memo_count: i64 = row.get(4).unwrap();
                let sent_note_count: i64 = row.get(5).unwrap();
                let received_note_count: i64 = row.get(6).unwrap();
                match (account, tx) {
                    (0, 0) => {
                        assert_eq!(account_balance_delta, 7);
                        assert!(!has_change);
                        assert_eq!(memo_count, 0);
                        assert_eq!(sent_note_count, 0);
                        assert_eq!(received_note_count, 2);
                    }
                    other => {
                        panic!("(Account, Transaction) pair {:?} is not expected to exist in the wallet.", other);
                    }
                }
            }
            assert_eq!(row_count, 1);
        }

        // Now create an unmined transaction that spends both of our notes
        db_data.conn.execute_batch(
            "INSERT INTO transactions (id_tx, txid) VALUES (1, 'tx1');

            -- Mark our existing notes as spent
            UPDATE sapling_received_notes SET spent = 1 WHERE tx = 0;

            -- The note sent to the external recipient.
            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, to_account, to_address, value)
            VALUES (1, 2, 0, 0, NULL, 'zfake', 4);

            -- The change notes. We send two notes to ensure that having multiple rows with NULL nullifiers
            -- does not violate the uniqueness constraint
            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, to_account, to_address, value)
            VALUES (1, 2, 1, 0, 0, NULL, 1);
            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, to_account, to_address, value)
            VALUES (1, 2, 2, 0, 0, NULL, 1);
            INSERT INTO sapling_received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
            VALUES (1,    1, 0, '', 1, '', NULL, true);
            INSERT INTO sapling_received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
            VALUES (1,    2, 0, '', 1, '', NULL, true);
            ").unwrap();
        {
            let mut q = db_data
                .conn
                .prepare(
                    "SELECT account_id, id_tx, account_balance_delta, has_change, memo_count, sent_note_count, received_note_count
                    FROM v_transactions",
                )
                .unwrap();
            let mut rows = q.query([]).unwrap();
            let mut row_count = 0;
            while let Some(row) = rows.next().unwrap() {
                row_count += 1;
                let account: i64 = row.get(0).unwrap();
                let tx: i64 = row.get(1).unwrap();
                let account_balance_delta: i64 = row.get(2).unwrap();
                let has_change: bool = row.get(3).unwrap();
                let memo_count: i64 = row.get(4).unwrap();
                let sent_note_count: i64 = row.get(5).unwrap();
                let received_note_count: i64 = row.get(6).unwrap();
                match (account, tx) {
                    (0, 0) => {
                        assert_eq!(account_balance_delta, 7);
                        assert!(!has_change);
                        assert_eq!(memo_count, 0);
                        assert_eq!(sent_note_count, 0);
                        assert_eq!(received_note_count, 2);
                    }
                    (0, 1) => {
                        assert_eq!(account_balance_delta, -6);
                        assert!(has_change);
                        assert_eq!(memo_count, 0);
                        assert_eq!(sent_note_count, 1);
                        assert_eq!(received_note_count, 0);
                    }
                    other => {
                        panic!("(Account, Transaction) pair {:?} is not expected to exist in the wallet.", other);
                    }
                }
            }
            assert_eq!(row_count, 2);
        }
    }
}
