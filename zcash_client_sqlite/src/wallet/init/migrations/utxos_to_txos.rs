//! A migration that brings transparent UTXO handling into line with that for shielded outputs.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{migrations::orchard_received_notes, WalletMigrationError};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x3a2562b3_f174_46a1_aa8c_1d122ca2e884);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [orchard_received_notes::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Updates transparent UTXO handling to be similar to that for shielded notes."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(r#"
            PRAGMA legacy_alter_table = ON;

            CREATE TABLE transactions_new (
                id_tx INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                created TEXT,
                block INTEGER,
                mined_height INTEGER,
                tx_index INTEGER,
                expiry_height INTEGER,
                raw BLOB,
                fee INTEGER,
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT height_consistency CHECK (block IS NULL OR mined_height = block)
            );

            INSERT INTO transactions_new
            SELECT id_tx, txid, created, block, block, tx_index, expiry_height, raw, fee
            FROM transactions;

            -- We may initially set the block height to null, which will mean that the
            -- transaction may appear to be un-mined until we actually scan the block
            -- containing the transaction.
            INSERT INTO transactions_new (txid, block, mined_height)
            SELECT
                utxos.prevout_txid,
                blocks.height,
                blocks.height
            FROM utxos
            LEFT OUTER JOIN blocks ON blocks.height = utxos.height
            WHERE utxos.prevout_txid NOT IN (
                SELECT txid FROM transactions
            );

            DROP TABLE transactions;
            ALTER TABLE transactions_new RENAME TO transactions;

            CREATE TABLE transparent_received_outputs (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                max_observed_unspent_height INTEGER,
                FOREIGN KEY (transaction_id) REFERENCES transactions(id_tx),
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT transparent_output_unique UNIQUE (transaction_id, output_index)
            );
            CREATE INDEX idx_transparent_received_outputs_account_id
            ON "transparent_received_outputs" (account_id);

            INSERT INTO transparent_received_outputs SELECT
                u.id,
                t.id_tx,
                prevout_idx,
                received_by_account_id,
                address,
                script,
                value_zat,
                NULL
            FROM utxos u
            -- This being a `LEFT OUTER JOIN` provides defense in depth against dropping
            -- TXOs that reference missing `transactions` entries (which should never exist
            -- given the migrations above).
            LEFT OUTER JOIN transactions t ON t.txid = u.prevout_txid;

            CREATE TABLE transparent_received_output_spends_new (
                transparent_received_output_id INTEGER NOT NULL,
                transaction_id INTEGER NOT NULL,
                FOREIGN KEY (transparent_received_output_id)
                    REFERENCES transparent_received_outputs(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (transaction_id)
                    -- We do not delete transactions, so this does not cascade
                    REFERENCES transactions(id_tx),
                UNIQUE (transparent_received_output_id, transaction_id)
            );

            INSERT INTO transparent_received_output_spends_new
            SELECT * FROM transparent_received_output_spends;

            DROP VIEW v_tx_outputs;
            DROP VIEW v_transactions;
            DROP VIEW v_received_notes;
            DROP VIEW v_received_note_spends;
            DROP TABLE transparent_received_output_spends;
            ALTER TABLE transparent_received_output_spends_new
            RENAME TO transparent_received_output_spends;

            CREATE VIEW v_received_outputs AS
                SELECT
                    sapling_received_notes.id AS id_within_pool_table,
                    sapling_received_notes.tx AS transaction_id,
                    2 AS pool,
                    sapling_received_notes.output_index,
                    account_id,
                    sapling_received_notes.value,
                    is_change,
                    sapling_received_notes.memo,
                    sent_notes.id AS sent_note_id
                FROM sapling_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                   (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
            UNION
                SELECT
                    orchard_received_notes.id AS id_within_pool_table,
                    orchard_received_notes.tx AS transaction_id,
                    3 AS pool,
                    orchard_received_notes.action_index AS output_index,
                    account_id,
                    orchard_received_notes.value,
                    is_change,
                    orchard_received_notes.memo,
                    sent_notes.id AS sent_note_id
                FROM orchard_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                   (orchard_received_notes.tx, 3, orchard_received_notes.action_index)
            UNION
                SELECT
                    u.id AS id_within_pool_table,
                    u.transaction_id,
                    0 AS pool,
                    u.output_index,
                    u.account_id,
                    u.value_zat AS value,
                    0 AS is_change,
                    NULL AS memo,
                    sent_notes.id AS sent_note_id
                FROM transparent_received_outputs u
                LEFT JOIN sent_notes
                ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                   (u.transaction_id, 0, u.output_index);

            CREATE VIEW v_received_output_spends AS
            SELECT
                2 AS pool,
                sapling_received_note_id AS received_output_id,
                transaction_id
            FROM sapling_received_note_spends
            UNION
            SELECT
                3 AS pool,
                orchard_received_note_id AS received_output_id,
                transaction_id
            FROM orchard_received_note_spends
            UNION
            SELECT
                0 AS pool,
                transparent_received_output_id AS received_output_id,
                transaction_id
            FROM transparent_received_output_spends;

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
                       END AS memo_present
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
                       0                          AS change_note_count,
                       0                          AS received_count,
                       0                          AS memo_present
                FROM v_received_outputs ro
                JOIN v_received_output_spends ros
                     ON ros.pool = ro.pool
                     AND ros.received_output_id = ro.id_within_pool_table
                JOIN transactions
                     ON transactions.id_tx = ro.transaction_id
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
            SELECT notes.account_id             AS account_id,
                   notes.mined_height           AS mined_height,
                   notes.txid                   AS txid,
                   transactions.tx_index        AS tx_index,
                   transactions.expiry_height   AS expiry_height,
                   transactions.raw             AS raw,
                   SUM(notes.value)             AS account_balance_delta,
                   transactions.fee             AS fee_paid,
                   SUM(notes.change_note_count) > 0  AS has_change,
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
            LEFT JOIN blocks ON blocks.height = notes.mined_height
            LEFT JOIN sent_note_counts
                 ON sent_note_counts.account_id = notes.account_id
                 AND sent_note_counts.txid = notes.txid
            GROUP BY notes.account_id, notes.txid;

            CREATE VIEW v_tx_outputs AS
            -- select all outputs received by the wallet
            SELECT transactions.txid            AS txid,
                   ro.pool                      AS output_pool,
                   ro.output_index              AS output_index,
                   sent_notes.from_account_id   AS from_account_id,
                   ro.account_id                AS to_account_id,
                   NULL                         AS to_address,
                   ro.value                     AS value,
                   ro.is_change                 AS is_change,
                   ro.memo                      AS memo
            FROM v_received_outputs ro
            JOIN transactions
                ON transactions.id_tx = ro.transaction_id
            -- join to the sent_notes table to obtain `from_account_id`
            LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
            UNION
            -- select all outputs sent from the wallet to external recipients
            SELECT transactions.txid            AS txid,
                   sent_notes.output_pool       AS output_pool,
                   sent_notes.output_index      AS output_index,
                   sent_notes.from_account_id   AS from_account_id,
                   NULL                         AS to_account_id,
                   sent_notes.to_address        AS to_address,
                   sent_notes.value             AS value,
                   FALSE                        AS is_change,
                   sent_notes.memo              AS memo
            FROM sent_notes
            JOIN transactions
                ON transactions.id_tx = sent_notes.tx
            LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
            -- exclude any sent notes for which a row exists in the v_received_outputs view
            WHERE ro.account_id IS NULL;

            DROP TABLE utxos;

            PRAGMA legacy_alter_table = OFF;
        "#)?;

        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
