//! Removes the `has_spend_key` column from the `accounts` table.
//!
//! The wallet no longer records whether the application holds spending keys for an account.
//! Callers state their spend authority per query instead.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{ivk_item_cache, standalone_address, v_address_uses_ironwood};

/// The migration that removes the `has_spend_key` column from the `accounts` table.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xded77015_af01_474e_b6e8_77baf12513c6);

/// The migrations that last touched the `accounts` table.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    ivk_item_cache::MIGRATION_ID,
    standalone_address::MIGRATION_ID,
    v_address_uses_ironwood::MIGRATION_ID,
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
        "Removes the has_spend_key column from the accounts table."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("ALTER TABLE accounts DROP COLUMN has_spend_key")?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "ALTER TABLE accounts ADD COLUMN has_spend_key INTEGER NOT NULL DEFAULT 1",
        )?;
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
