//! This migration adds `ON DELETE CASCADE` triggers to foreign keys throughout the database to
//! enable deletion of account records.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{
    WalletMigrationError,
    migrations::{
        add_transaction_trust_marker, support_zcashd_wallet_import, tx_retrieval_queue_expiry,
        v_received_output_spends_account, v_tx_outputs_return_addrs,
    },
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x07770bfd_c549_4069_9e05_822458f81cc4);

const DEPENDENCIES: &[Uuid] = &[
    tx_retrieval_queue_expiry::MIGRATION_ID,
    support_zcashd_wallet_import::MIGRATION_ID,
    v_received_output_spends_account::MIGRATION_ID,
    v_tx_outputs_return_addrs::MIGRATION_ID,
    add_transaction_trust_marker::MIGRATION_ID,
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
        "Adds `ON DELETE CASCADE` to foreign keys to support account deletion."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to addresses table
            CREATE TABLE addresses_new (
                id INTEGER NOT NULL PRIMARY KEY,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                key_scope INTEGER NOT NULL,
                diversifier_index_be BLOB,
                address TEXT NOT NULL,
                transparent_child_index INTEGER,
                cached_transparent_receiver_address TEXT,
                exposed_at_height INTEGER,
                receiver_flags INTEGER NOT NULL,
                transparent_receiver_next_check_time INTEGER,
                imported_transparent_receiver_pubkey BLOB,
                UNIQUE (account_id, key_scope, diversifier_index_be),
                UNIQUE (imported_transparent_receiver_pubkey),
                CONSTRAINT ck_addr_transparent_index_consistency CHECK (
                    (transparent_child_index IS NULL OR diversifier_index_be < x'0000000F00000000000000')
                    AND (
                        (
                            cached_transparent_receiver_address IS NULL
                            AND transparent_child_index IS NULL
                            AND imported_transparent_receiver_pubkey IS NULL
                        )
                        OR (
                            cached_transparent_receiver_address IS NOT NULL
                            AND (transparent_child_index IS NULL) == (imported_transparent_receiver_pubkey IS NOT NULL)
                        )
                    )
                ),
                CONSTRAINT ck_addr_foreign_or_diversified CHECK (
                    (diversifier_index_be IS NULL) == (key_scope = -1)
                )
            );
            INSERT INTO addresses_new SELECT * FROM addresses;
            DROP TABLE addresses;
            ALTER TABLE addresses_new RENAME TO addresses;
            CREATE INDEX idx_addresses_accounts ON addresses (account_id ASC);
            CREATE INDEX idx_addresses_indices ON addresses (diversifier_index_be ASC);
            CREATE INDEX idx_addresses_pubkeys ON addresses (imported_transparent_receiver_pubkey ASC);
            CREATE INDEX idx_addresses_t_indices ON addresses (transparent_child_index ASC);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to sapling_received_notes table
            CREATE TABLE sapling_received_notes_new (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rcm BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER,
                address_id INTEGER
                    REFERENCES addresses(id) ON DELETE CASCADE,
                UNIQUE (transaction_id, output_index)
            );
            INSERT INTO sapling_received_notes_new SELECT * FROM sapling_received_notes;
            DROP TABLE sapling_received_notes;
            ALTER TABLE sapling_received_notes_new RENAME TO sapling_received_notes;
            CREATE INDEX idx_sapling_received_notes_account ON sapling_received_notes (account_id ASC);
            CREATE INDEX idx_sapling_received_notes_address ON sapling_received_notes (address_id ASC);
            CREATE INDEX idx_sapling_received_notes_tx ON sapling_received_notes (transaction_id ASC);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to sapling_received_note_spends table
            CREATE TABLE sapling_received_note_spends_new (
                sapling_received_note_id INTEGER NOT NULL
                    REFERENCES sapling_received_notes(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (sapling_received_note_id, transaction_id)
            );
            INSERT INTO sapling_received_note_spends_new SELECT * FROM sapling_received_note_spends;
            DROP TABLE sapling_received_note_spends;
            ALTER TABLE sapling_received_note_spends_new RENAME TO sapling_received_note_spends;
            CREATE INDEX idx_sapling_received_note_spends_note_id ON sapling_received_note_spends (sapling_received_note_id ASC);
            CREATE INDEX idx_sapling_received_note_spends_transaction_id ON sapling_received_note_spends (transaction_id ASC);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to orchard_received_notes table
            CREATE TABLE orchard_received_notes_new (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                action_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rho BLOB NOT NULL,
                rseed BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER,
                address_id INTEGER
                    REFERENCES addresses(id) ON DELETE CASCADE,
                UNIQUE (transaction_id, action_index)
            );
            INSERT INTO orchard_received_notes_new SELECT * FROM orchard_received_notes;
            DROP TABLE orchard_received_notes;
            ALTER TABLE orchard_received_notes_new RENAME TO orchard_received_notes;
            CREATE INDEX idx_orchard_received_notes_account ON orchard_received_notes (account_id ASC);
            CREATE INDEX idx_orchard_received_notes_address ON orchard_received_notes (address_id ASC);
            CREATE INDEX idx_orchard_received_notes_tx ON orchard_received_notes (transaction_id ASC);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to orchard_received_note_spends table
            CREATE TABLE orchard_received_note_spends_new (
                orchard_received_note_id INTEGER NOT NULL
                    REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (orchard_received_note_id, transaction_id)
            );
            INSERT INTO orchard_received_note_spends_new SELECT * FROM orchard_received_note_spends;
            DROP TABLE orchard_received_note_spends;
            ALTER TABLE orchard_received_note_spends_new RENAME TO orchard_received_note_spends;
            CREATE INDEX idx_orchard_received_note_spends_note_id ON orchard_received_note_spends (orchard_received_note_id ASC);
            CREATE INDEX idx_orchard_received_note_spends_transaction_id ON orchard_received_note_spends (transaction_id ASC);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to transparent_received_outputs table
            CREATE TABLE transparent_received_outputs_new (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                address TEXT NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                max_observed_unspent_height INTEGER,
                address_id INTEGER NOT NULL
                    REFERENCES addresses(id) ON DELETE CASCADE,
                UNIQUE (transaction_id, output_index)
            );
            INSERT INTO transparent_received_outputs_new SELECT * FROM transparent_received_outputs;
            DROP TABLE transparent_received_outputs;
            ALTER TABLE transparent_received_outputs_new RENAME TO transparent_received_outputs;
            CREATE INDEX idx_transparent_received_outputs_account ON transparent_received_outputs (account_id);
            CREATE INDEX idx_transparent_received_outputs_address ON transparent_received_outputs (address_id);
            CREATE INDEX idx_transparent_received_outputs_tx ON transparent_received_outputs (transaction_id);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to transparent_received_output_spends table
            CREATE TABLE transparent_received_output_spends_new (
                transparent_received_output_id INTEGER NOT NULL
                    REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (transparent_received_output_id, transaction_id)
            );
            INSERT INTO transparent_received_output_spends_new SELECT * FROM transparent_received_output_spends;
            DROP TABLE transparent_received_output_spends;
            ALTER TABLE transparent_received_output_spends_new RENAME TO transparent_received_output_spends;
            CREATE INDEX idx_transparent_received_output_spends_output_id ON transparent_received_output_spends (transparent_received_output_id ASC);
            CREATE INDEX idx_transparent_received_output_spends_transaction_id ON transparent_received_output_spends (transaction_id ASC);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to transparent_spend_map table
            CREATE TABLE transparent_spend_map_new (
                spending_transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL,
                -- NOTE: We can't create a unique constraint on just (prevout_txid, prevout_output_index)
                -- because the same output may be attempted to be spent in multiple transactions, even
                -- though only one will ever be mined.
                UNIQUE (spending_transaction_id, prevout_txid, prevout_output_index)
            );
            INSERT INTO transparent_spend_map_new SELECT * FROM transparent_spend_map;
            DROP TABLE transparent_spend_map;
            ALTER TABLE transparent_spend_map_new RENAME TO transparent_spend_map;
            CREATE INDEX idx_transparent_spend_map_transaction_id ON transparent_spend_map (spending_transaction_id ASC);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to sent_notes table
            CREATE TABLE sent_notes_new (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_pool INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                from_account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                to_address TEXT,
                to_account_id INTEGER
                    REFERENCES accounts(id) ON DELETE SET NULL,
                value INTEGER NOT NULL,
                memo BLOB,
                UNIQUE (transaction_id, output_pool, output_index)
            );
            INSERT INTO sent_notes_new SELECT * FROM sent_notes;
            DROP TABLE sent_notes;
            ALTER TABLE sent_notes_new RENAME TO sent_notes;
            CREATE INDEX idx_sent_notes_from_account ON sent_notes (from_account_id);
            CREATE INDEX idx_sent_notes_to_account ON sent_notes (to_account_id);
            CREATE INDEX idx_sent_notes_transaction_id ON sent_notes (transaction_id);

            PRAGMA legacy_alter_table = OFF;
            "#,
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            CREATE TABLE tx_retrieval_queue_new (
                txid BLOB NOT NULL UNIQUE,
                query_type INTEGER NOT NULL,
                dependent_transaction_id INTEGER
                    REFERENCES transactions(id_tx) ON DELETE CASCADE
            );

            INSERT INTO tx_retrieval_queue_new
            SELECT txid, query_type, dependent_transaction_id
            FROM tx_retrieval_queue;

            DROP TABLE tx_retrieval_queue;
            ALTER TABLE tx_retrieval_queue_new RENAME TO tx_retrieval_queue;
            CREATE INDEX idx_tx_retrieval_queue_dependent_tx ON tx_retrieval_queue (dependent_transaction_id);

            PRAGMA legacy_alter_table = OFF;
            "#,
        )?;

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            -- Add deletion cascade to transparent_spend_search_queue table
            CREATE TABLE transparent_spend_search_queue_new (
                address TEXT NOT NULL,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL,
                UNIQUE (transaction_id, output_index)
            );
            INSERT INTO transparent_spend_search_queue_new SELECT * FROM transparent_spend_search_queue;
            DROP TABLE transparent_spend_search_queue;
            ALTER TABLE transparent_spend_search_queue_new RENAME TO transparent_spend_search_queue;
            CREATE INDEX idx_tssq_transaction_id ON transparent_spend_search_queue (transaction_id);

            PRAGMA legacy_alter_table = OFF;
            "#
        )?;

        conn.execute_batch(
            r#"
            DROP VIEW v_received_outputs;
            CREATE VIEW v_received_outputs AS
                SELECT
                    sapling_received_notes.id AS id_within_pool_table,
                    sapling_received_notes.transaction_id,
                    2 AS pool,
                    sapling_received_notes.output_index,
                    account_id,
                    sapling_received_notes.value,
                    is_change,
                    sapling_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    sapling_received_notes.address_id
                FROM sapling_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (sapling_received_notes.transaction_id, 2, sapling_received_notes.output_index)
            UNION
                SELECT
                    orchard_received_notes.id AS id_within_pool_table,
                    orchard_received_notes.transaction_id,
                    3 AS pool,
                    orchard_received_notes.action_index AS output_index,
                    account_id,
                    orchard_received_notes.value,
                    is_change,
                    orchard_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    orchard_received_notes.address_id
                FROM orchard_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (orchard_received_notes.transaction_id, 3, orchard_received_notes.action_index)
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
                    sent_notes.id AS sent_note_id,
                    u.address_id
                FROM transparent_received_outputs u
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (u.transaction_id, 0, u.output_index);

            DROP VIEW v_received_output_spends;
            CREATE VIEW v_received_output_spends AS
            SELECT
                2 AS pool,
                s.sapling_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM sapling_received_note_spends s
            JOIN sapling_received_notes rn ON rn.id = s.sapling_received_note_id
            UNION
            SELECT
                3 AS pool,
                s.orchard_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM orchard_received_note_spends s
            JOIN orchard_received_notes rn ON rn.id = s.orchard_received_note_id
            UNION
            SELECT
                0 AS pool,
                s.transparent_received_output_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM transparent_received_output_spends s
            JOIN transparent_received_outputs rn ON rn.id = s.transparent_received_output_id;

            DROP VIEW v_transactions;
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
                   transactions.trust_status
            FROM notes
            JOIN accounts ON accounts.id = notes.account_id
            JOIN transactions ON transactions.id_tx = notes.transaction_id
            LEFT JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = transactions.mined_height
            LEFT JOIN sent_note_counts
                 ON sent_note_counts.account_id = notes.account_id
                 AND sent_note_counts.transaction_id = notes.transaction_id
            GROUP BY notes.account_id, notes.transaction_id;

            DROP VIEW v_tx_outputs;
            CREATE VIEW v_tx_outputs AS
            WITH unioned AS (
                -- select all outputs received by the wallet
                SELECT transactions.txid            AS txid,
                       ro.pool                      AS output_pool,
                       ro.output_index              AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       to_account.uuid              AS to_account_uuid,
                       a.address                    AS to_address,
                       a.diversifier_index_be       AS diversifier_index_be,
                       ro.value                     AS value,
                       ro.is_change                 AS is_change,
                       ro.memo                      AS memo
                FROM v_received_outputs ro
                JOIN transactions
                    ON transactions.id_tx = ro.transaction_id
                LEFT JOIN addresses a ON a.id = ro.address_id
                -- join to the sent_notes table to obtain `from_account_id`
                LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
                LEFT JOIN accounts to_account ON to_account.id = ro.account_id
                UNION ALL
                -- select all outputs sent from the wallet to external recipients
                SELECT transactions.txid            AS txid,
                       sent_notes.output_pool       AS output_pool,
                       sent_notes.output_index      AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       NULL                         AS to_account_uuid,
                       sent_notes.to_address        AS to_address,
                       NULL                         AS diversifier_index_be,
                       sent_notes.value             AS value,
                       0                            AS is_change,
                       sent_notes.memo              AS memo
                FROM sent_notes
                JOIN transactions
                    ON transactions.id_tx = sent_notes.transaction_id
                LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
            )
            -- merge duplicate rows while retaining maximum information
            SELECT
                txid,
                output_pool,
                output_index,
                max(from_account_uuid) AS from_account_uuid,
                max(to_account_uuid) AS to_account_uuid,
                max(to_address) AS to_address,
                max(value) AS value,
                max(is_change) AS is_change,
                max(memo) AS memo
            FROM unioned
            GROUP BY txid, output_pool, output_index;

            DROP VIEW v_address_uses;
            CREATE VIEW v_address_uses AS
                SELECT orn.address_id, orn.account_id, orn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM orchard_received_notes orn
                JOIN addresses a ON a.id = orn.address_id
                JOIN transactions t ON t.id_tx = orn.transaction_id
            UNION
                SELECT srn.address_id, srn.account_id, srn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM sapling_received_notes srn
                JOIN addresses a ON a.id = srn.address_id
                JOIN transactions t ON t.id_tx = srn.transaction_id
            UNION
                SELECT tro.address_id, tro.account_id, tro.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM transparent_received_outputs tro
                JOIN addresses a ON a.id = tro.address_id
                JOIN transactions t ON t.id_tx = tro.transaction_id;
            "#
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
