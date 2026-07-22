//! Adds tables for storage of an in-progress Orchard -> Ironwood value-pool migration.
//!
//! A pool migration ([ZIP 318]) decomposes a spendable Orchard balance into self-funding notes and
//! crosses their value into the Ironwood pool as a set of pre-signed transactions. This migration
//! adds the `orchard_ironwood_migrations` and `orchard_ironwood_migration_transactions` tables that
//! persist that in-progress migration, so a wallet resumes it after being closed or restarted. Each
//! account's migration is tracked independently: `orchard_ironwood_migrations` keys by an
//! `account_id` foreign key into `accounts` (with `ON DELETE CASCADE`), enforced unique so an
//! account has at most one migration in progress.
//!
//! The table DDL and the store implementation over it live in [`crate::pool_migration`]; this
//! migration is the thin registration that runs that DDL inside the wallet schema. It depends on
//! [`ironwood_received_notes`] because the migration writes Ironwood notes, whose tables must exist.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_received_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x7b2f6a41_9c3d_4e58_8a17_2f6b9d0c4e11);

// The pool-migration tables have no foreign keys into the note or shardtree tables, but the engine
// works over both pools at runtime: it spends Orchard source notes (and their witnesses) and crosses
// into Ironwood. `ironwood_received_notes` is chosen as the single frontier dependency because its DAG
// closure transitively guarantees the whole stack the engine needs (Orchard received notes and
// shardtree, Ironwood received notes and shardtree), so listing those explicitly would be redundant
// under the codebase's minimal-frontier convention. If a future migration reshuffles the DAG such that
// `ironwood_received_notes` no longer pulls in the Orchard source infrastructure, add the Orchard
// dependencies here explicitly.
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
        // `Transaction` derefs to `Connection`; the DDL and its evolution live in the
        // `pool_migration` module.
        crate::pool_migration::orchard_ironwood::init_migration_tables(transaction)?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
