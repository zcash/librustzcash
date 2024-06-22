//! The migration that records ephemeral addresses for each account.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::utxos_to_txos;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x0e1d4274_1f8e_44e2_909d_689a4bc2967b);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [utxos_to_txos::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Record ephemeral addresses for each account."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE ephemeral_addresses (
                account_id INTEGER NOT NULL,
                address_index INTEGER NOT NULL,
                address TEXT NOT NULL,
                used_in_tx INTEGER,
                mined_in_tx INTEGER,
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                FOREIGN KEY (used_in_tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (mined_in_tx) REFERENCES transactions(id_tx),
                PRIMARY KEY (account_id, address_index)
            ) WITHOUT ROWID;
            CREATE INDEX ephemeral_addresses_address ON ephemeral_addresses (
                address ASC
            );",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}