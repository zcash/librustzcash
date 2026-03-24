//! Adds support for marking transactions as explicitly trusted for the purpose of satisfying the
//! ZIP 315 confirmations policy
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::{fix_v_transactions_expired_unmined, tx_observation_height};
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x4e68277f_6269_467e_9437_f3853cc4a41f);

const DEPENDENCIES: &[Uuid] = &[
    fix_v_transactions_expired_unmined::MIGRATION_ID,
    tx_observation_height::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds support for marking transactions as explicitly trusted."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "ALTER TABLE transactions ADD COLUMN trust_status INTEGER;

            DROP VIEW v_transactions;
            CREATE VIEW v_transactions AS
            WITH
            notes AS (
                -- Outputs received in this transaction
                SELECT ro.account_id              AS account_id,
                       transactions.mined_height  AS mined_height,
                       transactions.txid          AS txid,
                       ro.pool                    AS pool,
                       id_within_pool_table,
                       ro.value                   AS value,
                       ro.value                   AS received_value,
                       0                          AS spent_value,
                       0                          AS spent_note_count,
                       CASE
                            WHEN ro.is_change THEN 1
                            ELSE 0
                       END AS change_note_count,
                       CASE
                            WHEN ro.is_change THEN 0
                            ELSE 1
                       END AS received_count,
                       CASE
                         WHEN (ro.memo IS NULL OR ro.memo = X'F6')
                           THEN 0
                         ELSE 1
                       END AS memo_present,
                       -- The wallet cannot receive transparent outputs in shielding transactions.
                       CASE
                         WHEN ro.pool = 0
                           THEN 1
                         ELSE 0
                       END AS does_not_match_shielding
                FROM v_received_outputs ro
                JOIN transactions
                     ON transactions.id_tx = ro.transaction_id
                UNION
                -- Outputs spent in this transaction
                SELECT ro.account_id              AS account_id,
                       transactions.mined_height  AS mined_height,
                       transactions.txid          AS txid,
                       ro.pool                    AS pool,
                       id_within_pool_table,
                       -ro.value                  AS value,
                       0                          AS received_value,
                       ro.value                   AS spent_value,
                       1                          AS spent_note_count,
                       0                          AS change_note_count,
                       0                          AS received_count,
                       0                          AS memo_present,
                       -- The wallet cannot spend shielded outputs in shielding transactions.
                       CASE
                         WHEN ro.pool != 0
                           THEN 1
                         ELSE 0
                       END AS does_not_match_shielding
                FROM v_received_outputs ro
                JOIN v_received_output_spends ros
                     ON ros.pool = ro.pool
                     AND ros.received_output_id = ro.id_within_pool_table
                JOIN transactions
                     ON transactions.id_tx = ros.transaction_id
            ),
            -- Obtain a count of the notes that the wallet created in each transaction,
            -- not counting change notes.
            sent_note_counts AS (
                SELECT sent_notes.from_account_id     AS account_id,
                       transactions.txid              AS txid,
                       COUNT(DISTINCT sent_notes.id)  AS sent_notes,
                       SUM(
                         CASE
                           WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR ro.transaction_id IS NOT NULL)
                             THEN 0
                           ELSE 1
                         END
                       ) AS memo_count
                FROM sent_notes
                JOIN transactions
                     ON transactions.id_tx = sent_notes.tx
                LEFT JOIN v_received_outputs ro
                     ON sent_notes.id = ro.sent_note_id
                WHERE COALESCE(ro.is_change, 0) = 0
                GROUP BY account_id, txid
            ),
            blocks_max_height AS (
                SELECT MAX(blocks.height) AS max_height FROM blocks
            )
            SELECT accounts.uuid                AS account_uuid,
                   notes.mined_height           AS mined_height,
                   notes.txid                   AS txid,
                   transactions.tx_index        AS tx_index,
                   transactions.expiry_height   AS expiry_height,
                   transactions.raw             AS raw,
                   SUM(notes.value)             AS account_balance_delta,
                   SUM(notes.spent_value)       AS total_spent,
                   SUM(notes.received_value)    AS total_received,
                   transactions.fee             AS fee_paid,
                   SUM(notes.change_note_count) > 0  AS has_change,
                   MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
                   SUM(notes.received_count)         AS received_note_count,
                   SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
                   blocks.time                       AS block_time,
                   (
                        notes.mined_height IS NULL
                        AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
                   ) AS expired_unmined,
                   SUM(notes.spent_note_count) AS spent_note_count,
                   (
                        -- All of the wallet-spent and wallet-received notes are consistent with a
                        -- shielding transaction.
                        SUM(notes.does_not_match_shielding) = 0
                        -- The transaction contains at least one wallet-spent output.
                        AND SUM(notes.spent_note_count) > 0
                        -- The transaction contains at least one wallet-received note.
                        AND (SUM(notes.received_count) + SUM(notes.change_note_count)) > 0
                        -- We do not know about any external outputs of the transaction.
                        AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
                   ) AS is_shielding,
                   transactions.trust_status
            FROM notes
            LEFT JOIN accounts ON accounts.id = notes.account_id
            LEFT JOIN transactions
                 ON notes.txid = transactions.txid
            LEFT JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = notes.mined_height
            LEFT JOIN sent_note_counts
                 ON sent_note_counts.account_id = notes.account_id
                 AND sent_note_counts.txid = notes.txid
            GROUP BY notes.account_id, notes.txid"
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
