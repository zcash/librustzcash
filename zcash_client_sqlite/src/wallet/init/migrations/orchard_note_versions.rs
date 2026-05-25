//! Stores the Orchard note plaintext version for received notes.
//!
//! QR Orchard notes use a different note commitment randomness derivation from
//! ordinary Orchard notes. Persisting the version is required so wallets can
//! reconstruct spendable notes after reopening the database.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::witness_stabilized_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x2fc818c6_b900_4980_ae8e_d12ca17bc346);

const DEPENDENCIES: &[Uuid] = &[witness_stabilized_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the Orchard note plaintext version to received notes."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "ALTER TABLE orchard_received_notes
               ADD COLUMN note_version INTEGER NOT NULL DEFAULT 2;",
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
