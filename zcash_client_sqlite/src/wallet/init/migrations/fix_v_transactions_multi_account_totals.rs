//! Stops `v_transactions` from multiplying a sending account's totals.
//!
//! The `sent_note_counts` subquery projected `sent_notes.from_account_id AS account_id` while
//! also joining `v_received_outputs`, which has its own `account_id`. SQLite resolves a bare name
//! in `GROUP BY` against the input columns before the output aliases, so the grouping key was the
//! RECEIVING account. A transaction whose sent notes were received into more than one account
//! therefore produced one subquery row per recipient, all carrying the same sending account, and
//! the outer join multiplied every aggregate of the sending account's row: `account_balance_delta`,
//! `total_spent`, `total_received`, `received_note_count`, `spent_note_count`, and the received
//! half of `memo_count` were scaled by the number of recipients, and `sent_note_count` reported
//! the largest single recipient's share instead of the whole.
//!
//! Every column reference in both recreated views now names its source, so no bare name is left
//! for that resolution order to capture. The only change in meaning is the grouping key.
//!
//! A view carries no data, so this migration discards nothing.
//!
//! `down` is deliberately a no-op, unlike the sibling view migrations that restore prior text:
//! no supported upgrade path runs `down`, and a bug fix must not offer a path that reinstates
//! the bug.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{v_migration_transactions, v_transactions_zip318_kind};

/// Identifies this migration in the wallet's schema-migration DAG.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xa7cd7bfd_2a92_4a7b_ba98_20d61893b260);

/// `v_transactions_zip318_kind` created the `v_transactions` text this replaces, and
/// `v_migration_transactions` created the `v_transactions_with_pending_migrations` text that
/// selects from it.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    v_transactions_zip318_kind::MIGRATION_ID,
    v_migration_transactions::MIGRATION_ID,
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
        "Stops v_transactions from multiplying a sending account's totals by its recipient count."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_transactions_with_pending_migrations;
            DROP VIEW v_transactions;
            CREATE VIEW v_transactions AS
            WITH
            notes AS (
                -- Outputs received in this transaction
                SELECT ro.account_id              AS account_id,
                       ro.transaction_id          AS transaction_id,
                       ro.pool                    AS pool,
                       ro.id_within_pool_table    AS id_within_pool_table,
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
                       ro.id_within_pool_table    AS id_within_pool_table,
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
                SELECT notes.account_id                                     AS account_id,
                       notes.transaction_id                                 AS transaction_id,
                       notes.pool                                           AS pool,
                       SUM(notes.spent_note_count)                          AS spent_note_count,
                       SUM(notes.received_count + notes.change_note_count)  AS received_note_count,
                       SUM(notes.received_value)                            AS received_value
                FROM notes
                GROUP BY notes.account_id, notes.transaction_id, notes.pool
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
                -- Group by the SENDING account. A bare `account_id` here binds `ro.account_id`, the
                -- receiving account, because SQLite resolves a GROUP BY name against the input columns
                -- before the output aliases.
                GROUP BY sent_notes.from_account_id, sent_notes.transaction_id
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
                   transactions.trust_status,
                   transactions.zip318_kind
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
            GROUP BY notes.account_id, notes.transaction_id;
            CREATE VIEW v_transactions_with_pending_migrations AS
            SELECT v_transactions.account_uuid           AS account_uuid,
                   v_transactions.mined_height           AS mined_height,
                   v_transactions.txid                   AS txid,
                   v_transactions.tx_index               AS tx_index,
                   v_transactions.expiry_height          AS expiry_height,
                   v_transactions.raw                    AS raw,
                   v_transactions.account_balance_delta  AS account_balance_delta,
                   v_transactions.total_spent            AS total_spent,
                   v_transactions.total_received         AS total_received,
                   v_transactions.fee_paid               AS fee_paid,
                   v_transactions.has_change             AS has_change,
                   v_transactions.sent_note_count        AS sent_note_count,
                   v_transactions.received_note_count    AS received_note_count,
                   v_transactions.memo_count             AS memo_count,
                   v_transactions.block_time             AS block_time,
                   v_transactions.expired_unmined        AS expired_unmined,
                   v_transactions.spent_note_count       AS spent_note_count,
                   v_transactions.is_shielding           AS is_shielding,
                   v_transactions.pool_crossing_value    AS pool_crossing_value,
                   v_transactions.trust_status           AS trust_status,
                   v_transactions.zip318_kind            AS zip318_kind
            FROM v_transactions
            UNION ALL
            SELECT vmt.account_uuid          AS account_uuid,
                   NULL                      AS mined_height,
                   vmt.txid                  AS txid,
                   NULL                      AS tx_index,
                   vmt.expiry_height         AS expiry_height,
                   NULL                      AS raw,
                   -vmt.fee                  AS account_balance_delta,
                   vmt.value_spent           AS total_spent,
                   vmt.value_received        AS total_received,
                   vmt.fee                   AS fee_paid,
                   vmt.has_change            AS has_change,
                   0                         AS sent_note_count,
                   vmt.received_note_count   AS received_note_count,
                   0                         AS memo_count,
                   NULL                      AS block_time,
                   (vmt.expiry_height BETWEEN 1 AND (SELECT MAX(blocks.height) FROM blocks))
                                             AS expired_unmined,
                   vmt.spent_note_count      AS spent_note_count,
                   0                         AS is_shielding,
                   vmt.pool_crossing_value   AS pool_crossing_value,
                   NULL                      AS trust_status,
                   vmt.zip318_kind           AS zip318_kind
            FROM v_migration_transactions vmt;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Nothing to do: no supported upgrade path runs `down`, and a bug fix must not
        // offer a path that reinstates the bug. The corrected views satisfy every reader
        // of the prior schema, so leaving them in place is sound.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    use crate::WalletDb;
    use crate::testing::db::{test_clock, test_rng};
    use crate::wallet::init::WalletMigrator;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// Both recreated views must be QUERYABLE, not merely creatable. SQLite stores a view's
    /// SELECT as text and does not resolve its column references until the view is used, so a
    /// `CREATE VIEW` naming a column that does not exist succeeds and fails only later, at the
    /// first query a client makes. Migrating cleanly is therefore not evidence that this
    /// migration worked, and qualifying every column reference is exactly the kind of edit a
    /// bad name survives.
    #[test]
    fn the_recreated_views_are_queryable() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[super::MIGRATION_ID])
            .unwrap();

        for view in ["v_transactions", "v_transactions_with_pending_migrations"] {
            // The wallet is empty, so each of these returns zero; preparing and stepping the
            // statement is what forces SQLite to resolve the view's column references.
            let count: i64 = db_data
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {view}"), [], |row| row.get(0))
                .unwrap_or_else(|e| panic!("{view} resolves when queried: {e}"));

            assert_eq!(count, 0);
        }
    }
}
