//! This migration adds `ON DELETE CASCADE` triggers to foreign keys throughout the database to
//! enable deletion of account records.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{
    migrations::{add_transaction_trust_marker, v_received_output_spends_account},
    WalletMigrationError,
};

use super::{support_zcashd_wallet_import, tx_retrieval_queue_expiry, v_tx_outputs_return_addrs};

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
                address_id INTEGER NOT NULL
                    REFERENCES addresses(id) ON DELETE CASCADE,
                UNIQUE (transaction_id, output_index)
            );
            INSERT INTO sapling_received_notes_new SELECT * FROM sapling_received_notes;
            DROP TABLE sapling_received_notes;
            ALTER TABLE sapling_received_notes_new RENAME TO sapling_received_notes;
            CREATE INDEX idx_sapling_received_note_account ON sapling_received_notes (account_id ASC);
            CREATE INDEX idx_sapling_received_note_address ON sapling_received_notes (address_id ASC);
            CREATE INDEX idx_sapling_received_note_tx ON sapling_received_notes (transaction_id ASC);

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
            CREATE INDEX idx_orchard_received_note_address ON orchard_received_notes (address_id ASC);
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
            CREATE INDEX idx_transparent_received_outputs_account_id ON transparent_received_outputs (account_id);
            CREATE INDEX idx_transparent_received_outputs_transaction_id ON transparent_received_outputs (transaction_id);

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
                    REFERENCES accounts(id) ON DELETE CASCADE,
                value INTEGER NOT NULL,
                memo BLOB,
                UNIQUE (transaction_id, output_pool, output_index),
                CONSTRAINT ck_send_note_recipient CHECK (
                    (to_address IS NOT NULL) OR (to_account_id IS NOT NULL)
                )
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
