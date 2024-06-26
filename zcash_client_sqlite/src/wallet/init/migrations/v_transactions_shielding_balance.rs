//! This migration reworks transaction history views to correctly include spent transparent utxo
//! value.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::v_tx_outputs_use_legacy_false;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xb8fe5112_4365_473c_8b42_2b07c0f0adaf);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [v_tx_outputs_use_legacy_false::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Updates v_transactions to include spent UTXOs."
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
                SELECT sapling_received_notes.account        AS account_id,
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
                SELECT utxos.received_by_account     AS account_id,
                       utxos.height                  AS block,
                       utxos.prevout_txid            AS txid,
                       0                             AS pool,
                       utxos.value_zat               AS value,
                       0                             AS is_change,
                       1                             AS received_count,
                       0                             AS memo_present
                FROM utxos
                UNION
                SELECT sapling_received_notes.account        AS account_id,
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
                SELECT utxos.received_by_account     AS account_id,
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
