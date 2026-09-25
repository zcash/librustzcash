//! Records which cosigner key of a ZIP 48 multisig account this wallet holds.
//!
//! A ZIP 48 account is defined by the set of its cosigners' account keys, and its ZIP 316
//! Revision 2 encoding carries a chain code and public key per cosigner and no key origin.
//! A wallet that has only the stored account therefore cannot work out which entry is its
//! own, and so cannot say whether it is able to contribute a signature. These columns
//! record that, so the question is answerable without unlocking the seed and re-deriving a
//! candidate key to compare.
//!
//! The three columns are written together or not at all; an account that this wallet merely
//! watches has none of them.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ivk_item_cache;

/// This migration adds ZIP 48 cosigner derivation metadata to the `accounts` table.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x6d0a3f2c_9b41_4f3e_a7d8_25c1e0b4f9a6);

/// `ivk_item_cache` is the prior owner of the `accounts` table definition.
pub(super) const DEPENDENCIES: &[Uuid] = &[ivk_item_cache::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds ZIP 48 cosigner derivation metadata to the accounts table."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Three nullable columns, so `ALTER TABLE ... ADD COLUMN` suffices and the table
        // does not have to be rebuilt. The all-or-nothing invariant between them is
        // maintained by the writer rather than by a CHECK, which SQLite cannot add to an
        // existing table without that rebuild.
        transaction.execute_batch(
            "ALTER TABLE accounts ADD COLUMN zip48_seed_fingerprint BLOB;
             ALTER TABLE accounts ADD COLUMN zip48_account_index INTEGER;
             ALTER TABLE accounts ADD COLUMN zip48_cosigner_index INTEGER;",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "ALTER TABLE accounts DROP COLUMN zip48_cosigner_index;
             ALTER TABLE accounts DROP COLUMN zip48_account_index;
             ALTER TABLE accounts DROP COLUMN zip48_seed_fingerprint;",
        )?;

        Ok(())
    }
}
