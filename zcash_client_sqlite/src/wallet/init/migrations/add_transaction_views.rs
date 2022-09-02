//! Functions for initializing the various databases.
use rusqlite::{self, types::ToSql, NO_PARAMS};
use schemer::{self};
use schemer_rusqlite::RusqliteMigration;

use std::collections::HashSet;

use uuid::Uuid;

use zcash_primitives::{
    consensus::{self, BlockHeight, BranchId},
    transaction::{components::amount::Amount, Transaction},
};

use super::super::{WalletMigration2, WalletMigrationError};

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> Migration<P> {
    fn id() -> Uuid {
        Uuid::parse_str("282fad2e-8372-4ca0-8bed-71821320909f").unwrap()
    }
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        Migration::<P>::id()
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        let mut deps = HashSet::new();
        deps.insert(WalletMigration2::<P>::id());
        deps
    }

    fn description(&self) -> &'static str {
        "Add transaction summary views & add fee information to transactions."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("ALTER TABLE transactions ADD COLUMN fee INTEGER;")?;

        let mut stmt_list_txs =
            transaction.prepare("SELECT id_tx, raw, block FROM transactions")?;

        let mut stmt_set_fee =
            transaction.prepare("UPDATE transactions SET fee = ? WHERE id_tx = ?")?;

        let mut stmt_find_utxo_value = transaction
            .prepare("SELECT value_zat FROM utxos WHERE prevout_txid = ? AND prevout_idx = ?")?;

        let mut tx_rows = stmt_list_txs.query(NO_PARAMS)?;
        while let Some(row) = tx_rows.next()? {
            let id_tx: i64 = row.get(0)?;
            let tx_bytes: Vec<u8> = row.get(1)?;
            let h: u32 = row.get(2)?;
            let block_height = BlockHeight::from(h);

            let tx = Transaction::read(
                &tx_bytes[..],
                BranchId::for_height(&self.params, block_height),
            )
            .map_err(|e| {
                WalletMigrationError::CorruptedData(format!(
                    "Parsing failed for transaction {:?}: {:?}",
                    id_tx, e
                ))
            })?;

            let fee_paid = tx.fee_paid(|op| {
                stmt_find_utxo_value
                    .query_row(&[op.hash().to_sql()?, op.n().to_sql()?], |row| {
                        row.get(0).map(|i| Amount::from_i64(i).unwrap())
                    })
                    .map_err(WalletMigrationError::DbError)
            })?;

            stmt_set_fee.execute(&[i64::from(fee_paid), id_tx])?;
        }

        transaction.execute_batch(
            "CREATE VIEW v_tx_sent AS
            SELECT transactions.id_tx         AS id_tx,
                   transactions.block         AS mined_height,
                   transactions.tx_index      AS tx_index,
                   transactions.txid          AS txid,
                   transactions.expiry_height AS expiry_height,
                   transactions.raw           AS raw,
                   SUM(sent_notes.value)      AS sent_total,
                   COUNT(sent_notes.id_note)  AS sent_note_count,
                   SUM(
                       CASE
                           WHEN sent_notes.memo IS NULL THEN 0
                           WHEN SUBSTR(sent_notes.memo, 0, 2) = X'F6' THEN 0
                           ELSE 1
                       END
                   ) AS memo_count,
                   blocks.time                AS block_time
            FROM   transactions
                   JOIN sent_notes
                          ON transactions.id_tx = sent_notes.tx
                   LEFT JOIN blocks
                          ON transactions.block = blocks.height
            GROUP BY sent_notes.tx;
            CREATE VIEW v_tx_received AS
            SELECT transactions.id_tx            AS id_tx,
                   transactions.block            AS mined_height,
                   transactions.tx_index         AS tx_index,
                   transactions.txid             AS txid,
                   SUM(received_notes.value)     AS received_total,
                   COUNT(received_notes.id_note) AS received_note_count,
                   SUM(
                       CASE
                           WHEN received_notes.memo IS NULL THEN 0
                           WHEN SUBSTR(received_notes.memo, 0, 2) = X'F6' THEN 0
                           ELSE 1
                       END
                   ) AS memo_count,
                   blocks.time                   AS block_time
            FROM   transactions
                   JOIN received_notes
                          ON transactions.id_tx = received_notes.tx
                   LEFT JOIN blocks
                          ON transactions.block = blocks.height
            GROUP BY received_notes.tx;
            CREATE VIEW v_transactions AS
            SELECT id_tx,
                   mined_height,
                   tx_index,
                   txid,
                   expiry_height,
                   raw,
                   SUM(value) + MAX(fee) AS net_value,
                   SUM(is_change) > 0 AS has_change,
                   SUM(memo_present) AS memo_count
            FROM (
                SELECT transactions.id_tx            AS id_tx,
                       transactions.block            AS mined_height,
                       transactions.tx_index         AS tx_index,
                       transactions.txid             AS txid,
                       transactions.expiry_height    AS expiry_height,
                       transactions.raw              AS raw,
                       0                             AS fee,
                       CASE
                            WHEN received_notes.is_change THEN 0
                            ELSE value
                       END AS value,
                       received_notes.is_change      AS is_change,
                       CASE
                           WHEN received_notes.memo IS NULL THEN 0
                           WHEN SUBSTR(received_notes.memo, 0, 2) = X'F6' THEN 0
                           ELSE 1
                       END AS memo_present
                FROM   transactions
                       JOIN received_notes ON transactions.id_tx = received_notes.tx
                UNION
                SELECT transactions.id_tx            AS id_tx,
                       transactions.block            AS mined_height,
                       transactions.tx_index         AS tx_index,
                       transactions.txid             AS txid,
                       transactions.expiry_height    AS expiry_height,
                       transactions.raw              AS raw,
                       transactions.fee              AS fee,
                       -sent_notes.value             AS value,
                       false                         AS is_change,
                       CASE
                           WHEN sent_notes.memo IS NULL THEN 0
                           WHEN SUBSTR(sent_notes.memo, 0, 2) = X'F6' THEN 0
                           ELSE 1
                       END AS memo_present
                FROM   transactions
                       JOIN sent_notes ON transactions.id_tx = sent_notes.tx
            )
            GROUP BY id_tx;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{self, NO_PARAMS};

    use tempfile::NamedTempFile;

    use crate::{
        tests::{self},
        wallet::init::init_wallet_db,
        WalletDb,
    };

    #[test]
    fn transaction_views() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        db_data.conn.execute_batch(
            "INSERT INTO accounts (account, ufvk) VALUES (0, '');
            INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, '');
            INSERT INTO transactions (block, id_tx, txid) VALUES (0, 0, '');

            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value)
            VALUES (0, 2, 0, 0, '', 2);
            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value, memo)
            VALUES (0, 2, 1, 0, '', 3, X'61');
            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value, memo)
            VALUES (0, 2, 2, 0, '', 0, X'f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000');

            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change, memo)
            VALUES (0, 0, 0, '', 5, '', 'a', false, X'62');
            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change, memo)
            VALUES (0, 1, 0, '', 7, '', 'b', true, X'63');",
        ).unwrap();

        let mut q = db_data
            .conn
            .prepare("SELECT received_total, received_note_count, memo_count FROM v_tx_received")
            .unwrap();
        let mut rows = q.query(NO_PARAMS).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let total: i64 = row.get(0).unwrap();
            let count: i64 = row.get(1).unwrap();
            let memo_count: i64 = row.get(2).unwrap();
            assert_eq!(total, 12);
            assert_eq!(count, 2);
            assert_eq!(memo_count, 2);
        }
        assert_eq!(row_count, 1);

        let mut q = db_data
            .conn
            .prepare("SELECT sent_total, sent_note_count, memo_count FROM v_tx_sent")
            .unwrap();
        let mut rows = q.query(NO_PARAMS).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let total: i64 = row.get(0).unwrap();
            let count: i64 = row.get(1).unwrap();
            let memo_count: i64 = row.get(2).unwrap();
            assert_eq!(total, 5);
            assert_eq!(count, 3);
            assert_eq!(memo_count, 1);
        }
        assert_eq!(row_count, 1);

        let mut q = db_data
            .conn
            .prepare("SELECT net_value, has_change, memo_count FROM v_transactions")
            .unwrap();
        let mut rows = q.query(NO_PARAMS).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let net_value: i64 = row.get(0).unwrap();
            let has_change: bool = row.get(1).unwrap();
            let memo_count: i64 = row.get(2).unwrap();
            assert_eq!(net_value, 0);
            assert!(has_change);
            assert_eq!(memo_count, 3);
        }
        assert_eq!(row_count, 1);
    }
}
