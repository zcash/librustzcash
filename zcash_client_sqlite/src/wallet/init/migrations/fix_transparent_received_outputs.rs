//! Fixes the `transparent_received_outputs` table schema to not depend on feature flags.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{
    ensure_default_transparent_address, fix_bad_change_flagging, v_transactions_additional_totals,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xb951587c_34fd_4f02_a313_05ff7adb6268);

const DEPENDENCIES: &[Uuid] = &[
    fix_bad_change_flagging::MIGRATION_ID,
    v_transactions_additional_totals::MIGRATION_ID,
    ensure_default_transparent_address::MIGRATION_ID,
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
        "Fixes the `transparent_received_outputs` table schema to not depend on feature flags"
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // This is the same table rewrite done in `transparent_gap_limit_handling`, but
        // unconditionally. If the wallet ran `transparent_gap_limit_handling` with the
        // `transparent-inputs` feature flag enabled, this will be a no-op.
        transaction.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            CREATE TABLE transparent_received_outputs_new (
                id INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                max_observed_unspent_height INTEGER,
                address_id INTEGER NOT NULL REFERENCES addresses(id),
                FOREIGN KEY (transaction_id) REFERENCES transactions(id_tx),
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT transparent_output_unique UNIQUE (transaction_id, output_index)
            );
            INSERT INTO transparent_received_outputs_new SELECT * FROM transparent_received_outputs;

            DROP TABLE transparent_received_outputs;
            ALTER TABLE transparent_received_outputs_new RENAME TO transparent_received_outputs;

            PRAGMA legacy_alter_table = OFF;
            "#,
        )?;

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
