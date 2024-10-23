//! The migration that records ephemeral addresses for each account.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::full_account_ids;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x07610aac_b0e3_4ba8_aaa6_cda606f0fd7b);

const DEPENDENCIES: &[Uuid] = &[full_account_ids::MIGRATION_ID];

#[allow(dead_code)]
pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Track which accounts have associated spending keys."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "ALTER TABLE accounts ADD COLUMN has_spend_key INTEGER NOT NULL DEFAULT 1",
        )?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("ALTER TABLE accounts DROP COLUMN has_spend_key")?;
        Ok(())
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
