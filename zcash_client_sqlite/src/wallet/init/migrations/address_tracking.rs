//! The migration that records ephemeral addresses used beyond the last known mined address, for each account.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::full_account_ids;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x0e1d4274_1f8e_44e2_909d_689a4bc2967b);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [full_account_ids::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Record ephemeral addresses used beyond the last known mined address, for each account."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            r#"
            ALTER TABLE accounts ADD first_unmined_ephemeral_taddr_index INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE accounts ADD first_unused_ephemeral_taddr_index INTEGER NOT NULL DEFAULT 0
                CONSTRAINT unused_gte_unmined CHECK (first_unused_ephemeral_taddr_index >= first_unmined_ephemeral_taddr_index);
            "#,
        )?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Dropping first_unused_ephemeral_taddr_index also drops its constraint.
        transaction.execute_batch(
            r#"
            ALTER TABLE accounts DROP COLUMN first_unused_ephemeral_index;
            ALTER TABLE accounts DROP COLUMN first_unmined_ephemeral_index;
            "#,
        )?;
        Ok(())
    }
}
