//! This migration reads the wallet's raw transaction data and updates the `sent_notes` table to
//! ensure that memo entries are consistent with the decrypted transaction's outputs. The empty
//! memo is now consistently represented as a single `0xf6` byte.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::named_params;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::{decrypt_transaction, keys::UnifiedFullViewingKey};
use zcash_primitives::{consensus, transaction::TxId, zip32::AccountId};

use crate::{
    error::SqliteClientError,
    wallet::{get_transaction, init::WalletMigrationError, memo_repr},
};

use super::received_notes_nullable_nf;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x7029b904_6557_4aa1_9da5_6904b65d2ba5);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [received_notes_nullable_nf::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "This migration reads the wallet's raw transaction data and updates the `sent_notes` table to
        ensure that memo entries are consistent with the decrypted transaction's outputs. The empty
        memo is now consistently represented as a single `0xf6` byte."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let mut stmt_raw_tx = transaction.prepare(
            "SELECT DISTINCT
               transactions.id_tx, transactions.txid,
               accounts.account, accounts.ufvk
             FROM sent_notes
             JOIN accounts ON sent_notes.from_account = accounts.account
             JOIN transactions ON transactions.id_tx = sent_notes.tx
             WHERE transactions.raw IS NOT NULL",
        )?;

        let mut rows = stmt_raw_tx.query([])?;

        let mut tx_sent_notes: BTreeMap<(i64, TxId), HashMap<AccountId, UnifiedFullViewingKey>> =
            BTreeMap::new();
        while let Some(row) = rows.next()? {
            let id_tx: i64 = row.get(0)?;
            let txid = row.get(1).map(TxId::from_bytes)?;
            let account: u32 = row.get(2)?;
            let ufvk_str: String = row.get(3)?;
            let ufvk = UnifiedFullViewingKey::decode(&self.params, &ufvk_str).map_err(|e| {
                WalletMigrationError::CorruptedData(format!(
                    "Could not decode unified full viewing key for account {}: {:?}",
                    account, e
                ))
            })?;

            tx_sent_notes.entry((id_tx, txid)).or_default().insert(
                AccountId::try_from(account).map_err(|_| {
                    WalletMigrationError::CorruptedData("Account ID is invalid".to_owned())
                })?,
                ufvk,
            );
        }

        let mut stmt_update_sent_memo = transaction.prepare(
            "UPDATE sent_notes
            SET memo = :memo
            WHERE tx = :id_tx
            AND output_index = :output_index",
        )?;

        for ((id_tx, txid), ufvks) in tx_sent_notes {
            let (block_height, tx) = get_transaction(transaction, &self.params, txid)
                .map_err(|err| match err {
                    SqliteClientError::CorruptedData(msg) => {
                        WalletMigrationError::CorruptedData(msg)
                    }
                    SqliteClientError::DbError(err) => WalletMigrationError::DbError(err),
                    other => WalletMigrationError::CorruptedData(format!(
                        "An error was encountered decoding transaction data: {:?}",
                        other
                    )),
                })?
                .ok_or_else(|| {
                    WalletMigrationError::CorruptedData(format!(
                        "Transaction not found for id {:?}",
                        txid
                    ))
                })?;

            let decrypted_outputs = decrypt_transaction(&self.params, block_height, &tx, &ufvks);

            // Orchard outputs were not supported as of the wallet states that could require this
            // migration.
            for d_out in decrypted_outputs.sapling_outputs() {
                stmt_update_sent_memo.execute(named_params![
                    ":id_tx": id_tx,
                    ":output_index": d_out.index(),
                    ":memo": memo_repr(Some(d_out.memo()))
                ])?;
            }
        }

        // Update the `v_transactions` view to avoid counting the empty memo as a memo
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
                         WHEN (sapling_received_notes.memo IS NULL OR sapling_received_notes.memo = X'F6')
                           THEN 0
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
                           WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6')
                             THEN 0
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

        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
