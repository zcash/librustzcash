use std::collections::HashSet;

use rusqlite::{params, Transaction};
use schemer_rusqlite::RusqliteMigration;
use secrecy::SecretVec;
use uuid::Uuid;
use zcash_client_backend::data_api::HDSeedFingerprint;

use crate::wallet::init::WalletMigrationError;

use super::{add_account_birthdays, receiving_key_scopes, sapling_memo_consistency};

/// The migration that switched from presumed seed-derived account IDs to supporting
/// HD accounts and all sorts of imported keys.
pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x1b104345_f27e_42da_a9e3_1de22694da43);

pub(crate) struct Migration {
    pub(super) seed: Option<SecretVec<u8>>,
}

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [
            receiving_key_scopes::MIGRATION_ID,
            add_account_birthdays::MIGRATION_ID,
            sapling_memo_consistency::MIGRATION_ID, // must run first because it references columns that this migration renames by their old name.
        ]
        .into_iter()
        .collect()
    }

    fn description(&self) -> &'static str {
        "Replaces the `account` column in the `accounts` table with columns to support all kinds of account and key types."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            r#"
            PRAGMA foreign_keys = OFF;
            PRAGMA legacy_alter_table = ON;

            CREATE TABLE accounts_new (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                account_type INTEGER NOT NULL DEFAULT 0,
                hd_seed_fingerprint BLOB,
                hd_account_index INTEGER,
                uvk TEXT NOT NULL,
                birthday_height INTEGER NOT NULL,
                recover_until_height INTEGER,
                CHECK (
                    (account_type = 0 AND hd_seed_fingerprint IS NOT NULL AND hd_account_index IS NOT NULL)
                    OR
                    (account_type = 1 AND hd_seed_fingerprint IS NULL AND hd_account_index IS NULL)
                )
            );
            CREATE UNIQUE INDEX accounts_uvk ON accounts_new ("uvk");
            "#,
        )?;

        // We require the seed *if* there are existing accounts in the table.
        if transaction.query_row("SELECT COUNT(*) FROM accounts", [], |row| {
            Ok(row.get::<_, u32>(0)? > 0)
        })? {
            if let Some(seed) = &self.seed {
                let seed_id = HDSeedFingerprint::from_seed(seed);
                // Although 'id' is an AUTOINCREMENT column, we'll set it explicitly to match the old account value
                // strictly as a matter of convenience to make this migration script easier,
                // specifically around updating tables with foreign keys to this one.
                transaction.execute(r#"
                INSERT INTO accounts_new (id, account_type, hd_seed_fingerprint, hd_account_index, uvk, birthday_height, recover_until_height)
                SELECT account, 0, :seed_id, account, ufvk, birthday_height, recover_until_height
                FROM accounts;
            "#, params![seed_id.as_bytes()])?;
            } else {
                return Err(WalletMigrationError::SeedRequired);
            }
        }

        transaction.execute_batch(
            r#"
            DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;

            -- Migrate addresses table
            CREATE TABLE addresses_new (
                account INTEGER NOT NULL,
                diversifier_index_be BLOB NOT NULL,
                address TEXT NOT NULL,
                cached_transparent_receiver_address TEXT,
                FOREIGN KEY (account) REFERENCES accounts(id),
                CONSTRAINT diversification UNIQUE (account, diversifier_index_be)
            );
            CREATE INDEX "addresses_accounts" ON "addresses_new" (
                "account" ASC
            );
            INSERT INTO addresses_new (account, diversifier_index_be, address, cached_transparent_receiver_address)
            SELECT account, diversifier_index_be, address, cached_transparent_receiver_address
            FROM addresses;

            DROP TABLE addresses;
            ALTER TABLE addresses_new RENAME TO addresses;

            -- Migrate sapling_received_notes table
            CREATE TABLE sapling_received_notes_new (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                account INTEGER NOT NULL,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rcm BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                spent INTEGER,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (account) REFERENCES accounts(id),
                FOREIGN KEY (spent) REFERENCES transactions(id_tx),
                CONSTRAINT tx_output UNIQUE (tx, output_index)
            );
            CREATE INDEX "sapling_received_notes_account" ON "sapling_received_notes_new" (
                "account" ASC
            );
            CREATE INDEX "sapling_received_notes_tx" ON "sapling_received_notes_new" (
                "tx" ASC
            );
            CREATE INDEX "sapling_received_notes_spent" ON "sapling_received_notes_new" (
                "spent" ASC
            );
            INSERT INTO sapling_received_notes_new (id_note, tx, output_index, account, diversifier, value, rcm, nf, is_change, memo, spent, commitment_tree_position, recipient_key_scope)
            SELECT id_note, tx, output_index, account, diversifier, value, rcm, nf, is_change, memo, spent, commitment_tree_position, recipient_key_scope
            FROM sapling_received_notes;

            DROP TABLE sapling_received_notes;
            ALTER TABLE sapling_received_notes_new RENAME TO sapling_received_notes;

            -- Migrate sent_notes table
            CREATE TABLE sent_notes_new (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                to_address TEXT,
                to_account INTEGER,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(id),
                FOREIGN KEY (to_account) REFERENCES accounts(id),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index),
                CONSTRAINT note_recipient CHECK (
                    (to_address IS NOT NULL) != (to_account IS NOT NULL)
                )
            );
            CREATE INDEX sent_notes_tx ON sent_notes_new (tx);
            CREATE INDEX sent_notes_from_account ON sent_notes_new (from_account);
            CREATE INDEX sent_notes_to_account ON sent_notes_new (to_account);
            INSERT INTO sent_notes_new (id_note, tx, output_pool, output_index, from_account, to_address, to_account, value, memo)
            SELECT id_note, tx, output_pool, output_index, from_account, to_address, to_account, value, memo
            FROM sent_notes;

            DROP TABLE sent_notes;
            ALTER TABLE sent_notes_new RENAME TO sent_notes;

            -- Migrate utxos table
            CREATE TABLE utxos_new (
                id_utxo INTEGER PRIMARY KEY,
                received_by_account INTEGER NOT NULL,
                address TEXT NOT NULL,
                prevout_txid BLOB NOT NULL,
                prevout_idx INTEGER NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                height INTEGER NOT NULL,
                spent_in_tx INTEGER,
                FOREIGN KEY (received_by_account) REFERENCES accounts(id),
                FOREIGN KEY (spent_in_tx) REFERENCES transactions(id_tx),
                CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
            );
            CREATE INDEX utxos_received_by_account ON utxos_new (received_by_account);
            CREATE INDEX utxos_spent_in_tx ON utxos_new (spent_in_tx);
            INSERT INTO utxos_new (id_utxo, received_by_account, address, prevout_txid, prevout_idx, script, value_zat, height, spent_in_tx)
            SELECT id_utxo, received_by_account, address, prevout_txid, prevout_idx, script, value_zat, height, spent_in_tx
            FROM utxos;

            DROP TABLE utxos;
            ALTER TABLE utxos_new RENAME TO utxos;
            "#,
            )?;

        transaction.execute_batch(
            r#"
                PRAGMA legacy_alter_table = OFF;
                PRAGMA foreign_keys = ON;
            "#,
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &Transaction) -> Result<(), WalletMigrationError> {
        panic!("Cannot revert this migration.");
    }
}
