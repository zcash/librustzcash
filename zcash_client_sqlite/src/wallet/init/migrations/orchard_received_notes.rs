//! This migration adds tables to the wallet database that are needed to persist Orchard received
//! notes.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::{PoolType, ShieldedProtocol};

use super::full_account_ids;
use crate::wallet::{init::WalletMigrationError, pool_code};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x51d7a273_aa19_4109_9325_80e4a5545048);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [full_account_ids::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Add support for storage of Orchard received notes."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE orchard_received_notes (
                id INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                action_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rho BLOB NOT NULL,
                rseed BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT tx_output UNIQUE (tx, action_index)
            );
            CREATE INDEX orchard_received_notes_account ON orchard_received_notes (
                account_id ASC
            );
            CREATE INDEX orchard_received_notes_tx ON orchard_received_notes (
                tx ASC
            );

            CREATE TABLE orchard_received_note_spends (
                orchard_received_note_id INTEGER NOT NULL,
                transaction_id INTEGER NOT NULL,
                FOREIGN KEY (orchard_received_note_id)
                    REFERENCES orchard_received_notes(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (transaction_id)
                    -- We do not delete transactions, so this does not cascade
                    REFERENCES transactions(id_tx),
                UNIQUE (orchard_received_note_id, transaction_id)
            );",
        )?;

        transaction.execute_batch({
            let sapling_pool_code = pool_code(PoolType::Shielded(ShieldedProtocol::Sapling));
            let orchard_pool_code = pool_code(PoolType::Shielded(ShieldedProtocol::Orchard));
            &format!(
                "CREATE VIEW v_received_notes AS
                    SELECT
                        sapling_received_notes.id AS id_within_pool_table,
                        sapling_received_notes.tx,
                        {sapling_pool_code} AS pool,
                        sapling_received_notes.output_index AS output_index,
                        account_id,
                        sapling_received_notes.value,
                        is_change,
                        sapling_received_notes.memo,
                        sent_notes.id AS sent_note_id
                    FROM sapling_received_notes
                    LEFT JOIN sent_notes
                    ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                       (sapling_received_notes.tx, {sapling_pool_code}, sapling_received_notes.output_index)
                UNION
                    SELECT
                        orchard_received_notes.id AS id_within_pool_table,
                        orchard_received_notes.tx,
                        {orchard_pool_code} AS pool,
                        orchard_received_notes.action_index AS output_index,
                        account_id,
                        orchard_received_notes.value,
                        is_change,
                        orchard_received_notes.memo,
                        sent_notes.id AS sent_note_id
                    FROM orchard_received_notes
                    LEFT JOIN sent_notes
                    ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                       (orchard_received_notes.tx, {orchard_pool_code}, orchard_received_notes.action_index);"
            )
        })?;

        transaction.execute_batch({
            let sapling_pool_code = pool_code(PoolType::Shielded(ShieldedProtocol::Sapling));
            let orchard_pool_code = pool_code(PoolType::Shielded(ShieldedProtocol::Orchard));
            &format!(
                "CREATE VIEW v_received_note_spends AS
                SELECT
                    {sapling_pool_code} AS pool,
                    sapling_received_note_id AS received_note_id,
                    transaction_id
                FROM sapling_received_note_spends
                UNION
                SELECT
                    {orchard_pool_code} AS pool,
                    orchard_received_note_id AS received_note_id,
                    transaction_id
                FROM orchard_received_note_spends;"
            )
        })?;

        transaction.execute_batch({
            let transparent_pool_code = pool_code(PoolType::Transparent);
            &format!(
                "DROP VIEW v_transactions;
                CREATE VIEW v_transactions AS
                WITH
                notes AS (
                    -- Shielded notes received in this transaction
                    SELECT v_received_notes.account_id     AS account_id,
                           transactions.block              AS block,
                           transactions.txid               AS txid,
                           v_received_notes.pool           AS pool,
                           id_within_pool_table,
                           v_received_notes.value          AS value,
                           CASE
                                WHEN v_received_notes.is_change THEN 1
                                ELSE 0
                           END AS is_change,
                           CASE
                                WHEN v_received_notes.is_change THEN 0
                                ELSE 1
                           END AS received_count,
                           CASE
                             WHEN (v_received_notes.memo IS NULL OR v_received_notes.memo = X'F6')
                               THEN 0
                             ELSE 1
                           END AS memo_present
                    FROM v_received_notes
                    JOIN transactions
                         ON transactions.id_tx = v_received_notes.tx
                    UNION
                    -- Transparent TXOs received in this transaction
                    SELECT utxos.received_by_account_id AS account_id,
                           utxos.height                 AS block,
                           utxos.prevout_txid           AS txid,
                           {transparent_pool_code}      AS pool,
                           utxos.id                     AS id_within_pool_table,
                           utxos.value_zat              AS value,
                           0                            AS is_change,
                           1                            AS received_count,
                           0                            AS memo_present
                    FROM utxos
                    UNION
                    -- Shielded notes spent in this transaction
                    SELECT v_received_notes.account_id  AS account_id,
                           transactions.block           AS block,
                           transactions.txid            AS txid,
                           v_received_notes.pool        AS pool,
                           id_within_pool_table,
                           -v_received_notes.value      AS value,
                           0                            AS is_change,
                           0                            AS received_count,
                           0                            AS memo_present
                    FROM v_received_notes
                    JOIN v_received_note_spends rns
                         ON rns.pool = v_received_notes.pool
                         AND rns.received_note_id = v_received_notes.id_within_pool_table
                    JOIN transactions
                         ON transactions.id_tx = rns.transaction_id
                    UNION
                    -- Transparent TXOs spent in this transaction
                    SELECT utxos.received_by_account_id AS account_id,
                           transactions.block           AS block,
                           transactions.txid            AS txid,
                           {transparent_pool_code}      AS pool,
                           utxos.id                     AS id_within_pool_table,
                           -utxos.value_zat             AS value,
                           0                            AS is_change,
                           0                            AS received_count,
                           0                            AS memo_present
                    FROM utxos
                    JOIN transparent_received_output_spends tros
                         ON tros.transparent_received_output_id = utxos.id
                    JOIN transactions
                         ON transactions.id_tx = tros.transaction_id
                ),
                -- Obtain a count of the notes that the wallet created in each transaction,
                -- not counting change notes.
                sent_note_counts AS (
                    SELECT sent_notes.from_account_id AS account_id,
                           transactions.txid       AS txid,
                           COUNT(DISTINCT sent_notes.id) as sent_notes,
                           SUM(
                             CASE
                               WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR v_received_notes.tx IS NOT NULL)
                                 THEN 0
                               ELSE 1
                             END
                           ) AS memo_count
                    FROM sent_notes
                    JOIN transactions
                         ON transactions.id_tx = sent_notes.tx
                    LEFT JOIN v_received_notes
                         ON sent_notes.id = v_received_notes.sent_note_id
                    WHERE COALESCE(v_received_notes.is_change, 0) = 0
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
            )
        })?;

        transaction.execute_batch({
            let transparent_pool_code = pool_code(PoolType::Transparent);
            &format!(
                "DROP VIEW v_tx_outputs;
                CREATE VIEW v_tx_outputs AS
                SELECT transactions.txid              AS txid,
                       v_received_notes.pool          AS output_pool,
                       v_received_notes.output_index  AS output_index,
                       sent_notes.from_account_id     AS from_account_id,
                       v_received_notes.account_id    AS to_account_id,
                       NULL                           AS to_address,
                       v_received_notes.value         AS value,
                       v_received_notes.is_change     AS is_change,
                       v_received_notes.memo          AS memo
                FROM v_received_notes
                JOIN transactions
                    ON transactions.id_tx = v_received_notes.tx
                LEFT JOIN sent_notes
                    ON sent_notes.id = v_received_notes.sent_note_id
                UNION
                SELECT utxos.prevout_txid           AS txid,
                       {transparent_pool_code}      AS output_pool,
                       utxos.prevout_idx            AS output_index,
                       NULL                         AS from_account_id,
                       utxos.received_by_account_id AS to_account_id,
                       utxos.address                AS to_address,
                       utxos.value_zat              AS value,
                       0                            AS is_change,
                       NULL                         AS memo
                FROM utxos
                UNION
                SELECT transactions.txid            AS txid,
                       sent_notes.output_pool       AS output_pool,
                       sent_notes.output_index      AS output_index,
                       sent_notes.from_account_id   AS from_account_id,
                       v_received_notes.account_id  AS to_account_id,
                       sent_notes.to_address        AS to_address,
                       sent_notes.value             AS value,
                       0                            AS is_change,
                       sent_notes.memo              AS memo
                FROM sent_notes
                JOIN transactions
                    ON transactions.id_tx = sent_notes.tx
                LEFT JOIN v_received_notes
                    ON sent_notes.id = v_received_notes.sent_note_id
                WHERE COALESCE(v_received_notes.is_change, 0) = 0;"
            )
        })?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
