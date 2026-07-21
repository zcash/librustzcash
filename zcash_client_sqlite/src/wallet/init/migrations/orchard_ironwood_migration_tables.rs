//! Adds tables for storage of an in-progress Orchard -> Ironwood value-pool migration.
//!
//! A pool migration ([ZIP 318]) decomposes a spendable Orchard balance into self-funding notes and
//! crosses their value into the Ironwood pool as a set of pre-signed transactions. This migration
//! adds the `orchard_ironwood_migrations` and `orchard_ironwood_migration_transactions` tables that
//! persist that in-progress migration, so a wallet resumes it after being closed or restarted.
//!
//! The table DDL and the store implementation live in the `zcash_pool_migration_sqlite` crate; this
//! migration is the thin registration that runs its DDL inside the wallet schema. It depends on
//! [`ironwood_received_notes`] because the migration writes Ironwood notes, whose tables must exist.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_received_notes;

pub(super) const MIGRATION_ID: Uuid = zcash_pool_migration_sqlite::orchard_ironwood::MIGRATION_ID;

const DEPENDENCIES: &[Uuid] = &[ironwood_received_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds tables for storage of an in-progress Orchard -> Ironwood pool migration."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // `Transaction` derefs to `Connection`; the DDL and its evolution live in the store crate.
        zcash_pool_migration_sqlite::orchard_ironwood::init_migration_tables(transaction)?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
