//! Adds support for marking transactions as explicitly trusted for the purpose of satisfying the
//! ZIP 315 confirmations policy
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{migrations::fix_v_transactions_expired_unmined, WalletMigrationError};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x4e68277f_6269_467e_9437_f3853cc4a41f);

const DEPENDENCIES: &[Uuid] = &[fix_v_transactions_expired_unmined::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds support for marking transactions as explicitly trusted."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("ALTER TABLE transactions ADD COLUMN trust_status INTEGER;")?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
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
