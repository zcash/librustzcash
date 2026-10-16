//! Adds pool-crossing classification to `v_transactions`.
//!
//! A wallet-internal transfer that moves an account's own funds between shielded pools, for
//! example a ZIP 318 Orchard -> Ironwood migration transfer, has an `account_balance_delta` of
//! only the transaction fee, which is correct but is not the quantity a wallet wants to present:
//! the user-meaningful amount is the value that crossed pools. Nothing in the view identified
//! such transactions or carried that amount, so clients could only improvise from `total_spent`
//! or `total_received`, both of which overstate the crossing whenever the transaction also
//! returns change to a pool it spent from.
//!
//! This migration recreates `v_transactions` with a new `pool_crossing_value` column: the total
//! value received in pools the account did not spend from, when every wallet-spent note and
//! wallet-received output in the transaction is shielded, the account spent at least one note, at
//! least one output was received in a pool the account spent nothing from, and no external outputs
//! are known; NULL otherwise.
//!
//! The classification and the amount are carried by that single column rather than by a separate
//! boolean mirroring `is_shielding`: a transaction is a pool crossing exactly when the column is
//! non-NULL, so a boolean would restate the same predicate in a second place that could drift.
//!
//! A payment that returns value to one of the wallet's own addresses is classified once the
//! wallet has observed the returned output: the scanner marks an output received by an account
//! that funded the transaction as change, at which point no external outputs remain and the
//! transaction presents as a wallet-internal crossing. While such a transaction is unmined its
//! returned output is not yet known to the wallet, so it is treated as an ordinary payment.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{account_delete_cascade, ironwood_pool_code_views};

/// This migration adds the `pool_crossing_value` column to `v_transactions`, identifying
/// wallet-internal transfers that move an account's own funds between shielded pools and
/// reporting the value that crossed.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x835d61e1_5b88_4f44_92b3_746fb9173360);

/// `account_delete_cascade` is the prior owner of the `v_transactions` definition this migration
/// recreates; `ironwood_pool_code_views` supplies the Ironwood arms of `v_received_outputs` and
/// `v_received_output_spends` that the crossing classification aggregates over.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    account_delete_cascade::MIGRATION_ID,
    ironwood_pool_code_views::MIGRATION_ID,
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
        "Adds the `pool_crossing_value` classification column to v_transactions."
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
                -- Outputs received in this transaction
                SELECT ro.account_id              AS account_id,
                       ro.transaction_id          AS transaction_id,
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
                UNION
                -- Outputs spent in this transaction
                SELECT ro.account_id              AS account_id,
                       ros.transaction_id         AS transaction_id,
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
            ),
            -- What each account spent and received in each pool, per transaction. A pool the account
            -- received value in but spent nothing from is a pool that value crossed into from
            -- elsewhere, which is what `pool_crossings` below is built on.
            notes_by_pool AS (
                SELECT account_id, transaction_id, pool,
                       SUM(spent_note_count)                   AS spent_note_count,
                       SUM(received_count + change_note_count) AS received_note_count,
                       SUM(received_value)                     AS received_value
                FROM notes
                GROUP BY account_id, transaction_id, pool
            ),
            -- Obtain a count of the notes that the wallet created in each transaction,
            -- not counting change notes.
            sent_note_counts AS (
                SELECT sent_notes.from_account_id     AS account_id,
                       sent_notes.transaction_id      AS transaction_id,
                       COUNT(DISTINCT sent_notes.id)  AS sent_notes,
                       SUM(
                         CASE
                           WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR ro.transaction_id IS NOT NULL)
                             THEN 0
                           ELSE 1
                         END
                       ) AS memo_count
                FROM sent_notes
                LEFT JOIN v_received_outputs ro ON sent_notes.id = ro.sent_note_id
                WHERE COALESCE(ro.is_change, 0) = 0
                GROUP BY account_id, sent_notes.transaction_id
            ),
            -- Identifies the transactions that are wallet-internal transfers moving an account's own
            -- funds between shielded pools, and reports the value that crossed. `crossing_value` is
            -- non-NULL exactly for such a transaction, so it carries both the classification and the
            -- amount; see the `pool_crossing_value` column below.
            pool_crossings AS (
                SELECT notes_by_pool.account_id     AS account_id,
                       notes_by_pool.transaction_id AS transaction_id,
                       CASE WHEN (
                            -- Every note spent and every output received by the wallet is shielded.
                            SUM(CASE WHEN notes_by_pool.pool = 0 THEN notes_by_pool.spent_note_count + notes_by_pool.received_note_count ELSE 0 END) = 0
                            -- The transaction spends at least one of the account's notes.
                            AND SUM(notes_by_pool.spent_note_count) > 0
                            -- At least one output was received in a pool the account spent nothing
                            -- from, so value crossed between pools.
                            AND SUM(CASE WHEN notes_by_pool.spent_note_count = 0 THEN notes_by_pool.received_note_count ELSE 0 END) > 0
                            -- We do not know about any external outputs of the transaction.
                            AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
                       )
                       -- The total value received in the pools the account did not spend from. The
                       -- condition above guarantees at least one such output, so when this branch is
                       -- taken the sum is never NULL.
                       THEN SUM(CASE WHEN notes_by_pool.spent_note_count = 0 THEN notes_by_pool.received_value ELSE 0 END)
                       END AS crossing_value
                FROM notes_by_pool
                LEFT JOIN sent_note_counts
                     ON sent_note_counts.account_id = notes_by_pool.account_id
                     AND sent_note_counts.transaction_id = notes_by_pool.transaction_id
                GROUP BY notes_by_pool.account_id, notes_by_pool.transaction_id
            ),
            blocks_max_height AS (
                SELECT MAX(blocks.height) AS max_height FROM blocks
            )
            SELECT accounts.uuid                AS account_uuid,
                   transactions.mined_height    AS mined_height,
                   transactions.txid            AS txid,
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
                        transactions.mined_height IS NULL
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
                   -- The value that crossed pools, when this transaction is a wallet-internal transfer
                   -- between shielded pools; NULL when it is not such a transfer. A transaction is one
                   -- exactly when this column is non-NULL.
                   pool_crossings.crossing_value AS pool_crossing_value,
                   transactions.trust_status
            FROM notes
            JOIN accounts ON accounts.id = notes.account_id
            JOIN transactions ON transactions.id_tx = notes.transaction_id
            LEFT JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = transactions.mined_height
            LEFT JOIN sent_note_counts
                 ON sent_note_counts.account_id = notes.account_id
                 AND sent_note_counts.transaction_id = notes.transaction_id
            LEFT JOIN pool_crossings
                 ON pool_crossings.account_id = notes.account_id
                 AND pool_crossings.transaction_id = notes.transaction_id
            GROUP BY notes.account_id, notes.transaction_id;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
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
