//! Adds support for storing key material required for zcashd wallet import.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::{
    encoding::{KeyScope, LEGACY_ADDRESS_INDEX_NULL},
    init::WalletMigrationError,
};

use super::fix_transparent_received_outputs;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x254d4f20_f0f6_4635_80ed_9d52c536d5df);

const DEPENDENCIES: &[Uuid] = &[fix_transparent_received_outputs::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds support for storing key material required for zcashd wallet import."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        let foreign_key_scope = KeyScope::Foreign.encode();
        transaction.execute_batch(&format!(
            r#"
            ALTER TABLE accounts ADD COLUMN zcashd_legacy_address_index INTEGER NOT NULL DEFAULT {LEGACY_ADDRESS_INDEX_NULL};

            -- Alter the hd_account index to incorporate the new column.
            DROP INDEX hd_account;
            CREATE UNIQUE INDEX hd_account ON accounts (hd_seed_fingerprint, hd_account_index, zcashd_legacy_address_index);

            CREATE TABLE addresses_new (
                id INTEGER NOT NULL PRIMARY KEY,
                account_id INTEGER NOT NULL,
                key_scope INTEGER NOT NULL,
                diversifier_index_be BLOB,
                address TEXT NOT NULL,
                transparent_child_index INTEGER,
                cached_transparent_receiver_address TEXT,
                exposed_at_height INTEGER,
                receiver_flags INTEGER NOT NULL,
                transparent_receiver_next_check_time INTEGER,
                imported_transparent_receiver_pubkey BLOB,
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT diversification UNIQUE (account_id, key_scope, diversifier_index_be),
                CONSTRAINT transparent_pubkey_unique UNIQUE (imported_transparent_receiver_pubkey),
                CONSTRAINT transparent_index_consistency CHECK (
                    (transparent_child_index IS NULL OR diversifier_index_be < x'0000000F00000000000000')
                    AND (
                        (
                            cached_transparent_receiver_address IS NULL
                            AND transparent_child_index IS NULL
                            AND imported_transparent_receiver_pubkey IS NULL
                        )
                        OR (
                            cached_transparent_receiver_address IS NOT NULL
                            AND (transparent_child_index IS NULL) == (imported_transparent_receiver_pubkey IS NOT NULL)
                        )
                    )
                ),
                CONSTRAINT foreign_or_diversified CHECK (
                    (diversifier_index_be IS NULL) == (key_scope = {foreign_key_scope})
                )
            );

            INSERT INTO addresses_new (
                id, account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags, transparent_receiver_next_check_time
            )
            SELECT
                id, account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags, transparent_receiver_next_check_time
            FROM addresses;

            PRAGMA legacy_alter_table = ON;

            DROP TABLE addresses;
            ALTER TABLE addresses_new RENAME TO addresses;
            CREATE INDEX idx_addresses_accounts ON addresses (
                account_id ASC
            );
            CREATE INDEX idx_addresses_indices ON addresses (
                diversifier_index_be ASC
            );
            CREATE INDEX idx_addresses_t_indices ON addresses (
                transparent_child_index ASC
            );
            CREATE INDEX idx_addresses_pubkeys ON addresses (
                imported_transparent_receiver_pubkey ASC
            );

            PRAGMA legacy_alter_table = OFF;
            "#,
        ))?;

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
