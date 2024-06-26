//! This migration adds a birthday height to each account record.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_primitives::consensus::{self, NetworkUpgrade};

use crate::wallet::init::WalletMigrationError;

use super::shardtree_support;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xeeec0d0d_fee0_4231_8c68_5f3a7c7c2245);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [shardtree_support::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a birthday height for each account."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(&format!(
            "ALTER TABLE accounts ADD COLUMN birthday_height INTEGER;

            -- set the birthday height to the height of the first block in the blocks table
            UPDATE accounts SET birthday_height = MIN(blocks.height) FROM blocks;
            -- if the blocks table is empty, set the birthday height to Sapling activation - 1
            UPDATE accounts SET birthday_height = {} WHERE birthday_height IS NULL;

            CREATE TABLE accounts_new (
                account INTEGER PRIMARY KEY,
                ufvk TEXT NOT NULL,
                birthday_height INTEGER NOT NULL,
                recover_until_height INTEGER
            );

            INSERT INTO accounts_new (account, ufvk, birthday_height)
            SELECT account, ufvk, birthday_height FROM accounts;

            PRAGMA foreign_keys=OFF;
            PRAGMA legacy_alter_table = ON;
            DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;
            PRAGMA legacy_alter_table = OFF;
            PRAGMA foreign_keys=ON;",
            u32::from(
                self.params
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap()
            )
        ))?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
