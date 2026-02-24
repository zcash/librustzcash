//! This migration adds support for tracking ZIP 48 transparent P2SH multisig wallets.
//!
//! Schema changes:
//! - Adds `zip48_fvk BLOB` column to `accounts` table for storing the ZIP 48 full viewing key
//! - Adds `redeem_script BLOB` column to `addresses` table for P2SH addresses
//! - Updates the `accounts` CHECK constraint to allow `account_kind = 2` (ZIP 48 multisig)

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::v_tx_outputs_key_scopes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x99f5cdee_3b82_45cc_bd56_c79779ca02a3);

const DEPENDENCIES: &[Uuid] = &[v_tx_outputs_key_scopes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds support for tracking ZIP 48 transparent P2SH multisig wallets."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Add zip48_fvk column to accounts table and update CHECK constraint
        // to allow account_kind = 2 for ZIP 48 multisig accounts.
        //
        // We need to recreate the table because SQLite doesn't support
        // ALTER TABLE ... DROP CONSTRAINT.
        transaction.execute_batch(
            r#"
            CREATE TABLE accounts_new (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                uuid BLOB NOT NULL,
                account_kind INTEGER NOT NULL DEFAULT 0,
                key_source TEXT,
                hd_seed_fingerprint BLOB,
                hd_account_index INTEGER,
                ufvk TEXT,
                uivk TEXT,
                orchard_fvk_item_cache BLOB,
                sapling_fvk_item_cache BLOB,
                p2pkh_fvk_item_cache BLOB,
                birthday_height INTEGER NOT NULL,
                birthday_sapling_tree_size INTEGER,
                birthday_orchard_tree_size INTEGER,
                recover_until_height INTEGER,
                has_spend_key INTEGER NOT NULL DEFAULT 1,
                zcashd_legacy_address_index INTEGER NOT NULL DEFAULT -1,
                zip48_fvk BLOB,
                CHECK (
                  (
                    account_kind = 0
                    AND hd_seed_fingerprint IS NOT NULL
                    AND hd_account_index IS NOT NULL
                    AND ufvk IS NOT NULL
                    AND uivk IS NOT NULL
                    AND zip48_fvk IS NULL
                  )
                  OR
                  (
                    account_kind = 1
                    AND (hd_seed_fingerprint IS NULL) = (hd_account_index IS NULL)
                    AND uivk IS NOT NULL
                    AND zip48_fvk IS NULL
                  )
                  OR
                  (
                    account_kind = 2
                    AND zip48_fvk IS NOT NULL
                    AND uivk IS NULL
                    AND hd_seed_fingerprint IS NULL
                    AND hd_account_index IS NULL
                    AND ufvk IS NULL
                    AND orchard_fvk_item_cache IS NULL
                    AND sapling_fvk_item_cache IS NULL
                    AND p2pkh_fvk_item_cache IS NULL
                  )
                )
            );
            "#,
        )?;

        // Copy existing data to the new table
        transaction.execute_batch(
            r#"
            INSERT INTO accounts_new (
                id, name, uuid, account_kind, key_source,
                hd_seed_fingerprint, hd_account_index,
                ufvk, uivk,
                orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
                birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                recover_until_height, has_spend_key, zcashd_legacy_address_index
            )
            SELECT
                id, name, uuid, account_kind, key_source,
                hd_seed_fingerprint, hd_account_index,
                ufvk, uivk,
                orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
                birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                recover_until_height, has_spend_key, zcashd_legacy_address_index
            FROM accounts;

            PRAGMA legacy_alter_table = ON;

            DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;

            PRAGMA legacy_alter_table = OFF;

            -- Recreate the existing indices
            CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);
            CREATE UNIQUE INDEX accounts_ufvk ON accounts (ufvk);
            CREATE UNIQUE INDEX accounts_uivk ON accounts (uivk);
            CREATE UNIQUE INDEX hd_account ON accounts (hd_seed_fingerprint, hd_account_index, zcashd_legacy_address_index);
            "#,
        )?;

        // Add redeem_script column to addresses table for P2SH multisig addresses.
        // This stores the script needed to spend funds at the address.
        transaction.execute_batch(
            r#"
            ALTER TABLE addresses ADD COLUMN redeem_script BLOB;
            "#,
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
