//! This migration revises the `v_received_output_spends` view to add the account ID
//! to the returned fields.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{WalletMigrationError, migrations::fix_v_transactions_expired_unmined};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x50fd092d_97b9_44cf_ade9_86b526e4cd50);

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
        "Updates v_received_output_spends to include the account ID."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_received_output_spends;
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
             JOIN transparent_received_outputs rn ON rn.id = s.transparent_received_output_id",
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
