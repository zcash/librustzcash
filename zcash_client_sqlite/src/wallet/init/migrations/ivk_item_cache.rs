//! Replaces FVK item cache columns with IVK item cache columns in the `accounts` table.
//!
//! IVK-based collision detection subsumes FVK-based detection: if two accounts share an
//! FVK they necessarily share an IVK, and the IVK check also catches collisions between
//! FVK-imported and IVK-imported accounts.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus;

#[cfg(feature = "transparent-inputs")]
use ::transparent::keys::IncomingViewingKey as _;

use crate::wallet::init::WalletMigrationError;

use super::standalone_p2sh;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x93278b0f_77fe_473c_b88e_7f285da38dd3);

const DEPENDENCIES: &[Uuid] = &[standalone_p2sh::MIGRATION_ID];

pub(crate) struct Migration<P: consensus::Parameters> {
    pub(super) params: P,
}

impl<P: consensus::Parameters> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Replaces FVK item cache columns with IVK item cache columns for collision detection."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // First, compute and collect IVK items for all existing accounts.
        let mut stmt = transaction.prepare("SELECT id, ufvk, uivk FROM accounts")?;
        let mut rows = stmt.query([])?;

        #[allow(clippy::type_complexity)]
        let mut ivk_updates: Vec<(i64, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> =
            Vec::new();
        while let Some(row) = rows.next()? {
            let account_id: i64 = row.get("id")?;
            let ufvk_str: Option<String> = row.get("ufvk")?;
            let uivk_str: String = row.get("uivk")?;

            let uivk = if let Some(ufvk_str) = ufvk_str {
                let ufvk = UnifiedFullViewingKey::decode(&self.params, &ufvk_str).map_err(|e| {
                    WalletMigrationError::CorruptedData(format!(
                        "Unable to parse UFVK for account {}: {}",
                        account_id, e
                    ))
                })?;
                ufvk.to_unified_incoming_viewing_key()
            } else {
                zcash_keys::keys::UnifiedIncomingViewingKey::decode(&self.params, &uivk_str)
                    .map_err(|e| {
                        WalletMigrationError::CorruptedData(format!(
                            "Unable to parse UIVK for account {}: {}",
                            account_id, e
                        ))
                    })?
            };

            #[cfg(feature = "orchard")]
            let orchard_ivk_item: Option<Vec<u8>> =
                uivk.orchard().as_ref().map(|k| k.to_bytes().to_vec());
            #[cfg(not(feature = "orchard"))]
            let orchard_ivk_item: Option<Vec<u8>> = None;

            let sapling_ivk_item: Option<Vec<u8>> =
                uivk.sapling().as_ref().map(|k| k.to_bytes().to_vec());

            #[cfg(feature = "transparent-inputs")]
            let transparent_ivk_item: Option<Vec<u8>> =
                uivk.transparent().as_ref().map(|k| k.serialize());
            #[cfg(not(feature = "transparent-inputs"))]
            let transparent_ivk_item: Option<Vec<u8>> = None;

            ivk_updates.push((
                account_id,
                orchard_ivk_item,
                sapling_ivk_item,
                transparent_ivk_item,
            ));
        }
        // Drop stmt/rows before modifying the table.
        drop(rows);
        drop(stmt);

        // Rebuild the accounts table: drop FVK cache columns, add IVK cache columns.
        // Use PRAGMA legacy_alter_table to preserve views and foreign key references.
        transaction.execute_batch(
            "CREATE TABLE accounts_new (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                uuid BLOB NOT NULL,
                account_kind INTEGER NOT NULL DEFAULT 0,
                key_source TEXT,
                hd_seed_fingerprint BLOB,
                hd_account_index INTEGER,
                ufvk TEXT,
                uivk TEXT NOT NULL,
                orchard_ivk_item_cache BLOB,
                sapling_ivk_item_cache BLOB,
                p2pkh_ivk_item_cache BLOB,
                p2sh_ivk_item_cache BLOB,
                birthday_height INTEGER NOT NULL,
                birthday_sapling_tree_size INTEGER,
                birthday_orchard_tree_size INTEGER,
                recover_until_height INTEGER,
                has_spend_key INTEGER NOT NULL DEFAULT 1,
                zcashd_legacy_address_index INTEGER NOT NULL DEFAULT -1,
                CHECK (
                  (
                    account_kind = 0
                    AND hd_seed_fingerprint IS NOT NULL
                    AND hd_account_index IS NOT NULL
                    AND ufvk IS NOT NULL
                  )
                  OR
                  (
                    account_kind = 1
                    AND (hd_seed_fingerprint IS NULL) = (hd_account_index IS NULL)
                  )
                ),
                CHECK (
                  NOT (p2pkh_ivk_item_cache IS NOT NULL AND p2sh_ivk_item_cache IS NOT NULL)
                )
            );

            INSERT INTO accounts_new (
                id, name, uuid, account_kind, key_source,
                hd_seed_fingerprint, hd_account_index,
                ufvk, uivk,
                birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                recover_until_height, has_spend_key, zcashd_legacy_address_index
            )
            SELECT
                id, name, uuid, account_kind, key_source,
                hd_seed_fingerprint, hd_account_index,
                ufvk, uivk,
                birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                recover_until_height, has_spend_key, zcashd_legacy_address_index
            FROM accounts;

            PRAGMA legacy_alter_table = ON;
            DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;
            PRAGMA legacy_alter_table = OFF;",
        )?;

        // Populate the IVK cache columns.
        for (account_id, orchard_ivk, sapling_ivk, p2pkh_ivk) in &ivk_updates {
            transaction.execute(
                "UPDATE accounts
                 SET orchard_ivk_item_cache = :orchard_ivk,
                     sapling_ivk_item_cache = :sapling_ivk,
                     p2pkh_ivk_item_cache = :p2pkh_ivk
                 WHERE id = :account_id",
                named_params![
                    ":orchard_ivk": orchard_ivk,
                    ":sapling_ivk": sapling_ivk,
                    ":p2pkh_ivk": p2pkh_ivk,
                    ":account_id": account_id,
                ],
            )?;
        }

        // Re-create indices (the old ones were dropped with the table).
        transaction.execute_batch(
            "CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);
             CREATE UNIQUE INDEX accounts_ufvk ON accounts (ufvk);
             CREATE UNIQUE INDEX accounts_uivk ON accounts (uivk);
             CREATE UNIQUE INDEX hd_account ON accounts (hd_seed_fingerprint, hd_account_index, zcashd_legacy_address_index);
             CREATE UNIQUE INDEX accounts_orchard_ivk ON accounts (orchard_ivk_item_cache);
             CREATE UNIQUE INDEX accounts_sapling_ivk ON accounts (sapling_ivk_item_cache);
             CREATE UNIQUE INDEX accounts_p2pkh_ivk ON accounts (p2pkh_ivk_item_cache);
             CREATE UNIQUE INDEX accounts_p2sh_ivk ON accounts (p2sh_ivk_item_cache);",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
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
