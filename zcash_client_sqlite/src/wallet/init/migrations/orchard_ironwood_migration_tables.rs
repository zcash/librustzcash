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
//! The store implementation over these tables lives in [`crate::pool_migration`]. This migration is
//! the registration that creates them inside the wallet schema, and it depends on
//! [`ironwood_received_notes`] because the migration writes Ironwood notes, whose tables must exist.
//!
//! The DDL below is a FROZEN COPY of the text a released build of this migration actually ran, not
//! a call into the store's canonical DDL. This migration is published, so its effect is observable
//! by anything that anchors to it: an external [`schemerz`] migration may declare this migration as
//! a dependency and a later one as a dependent, and it then runs against exactly the schema these
//! statements create — down to the `tx_id` column that
//! [`orchard_ironwood_migration_unsatisfiability`] renames to `transfer_id`. Sourcing the text from
//! a shared builder would let an edit made for a future database silently change what an
//! already-published migration does to an existing one. The canonical DDL in
//! `crate::pool_migration::store` states the FINAL shape instead; a fresh database reaches that
//! shape by running this migration and then the later ones, and the two are pinned together by
//! `verify_schema` and `canonical_pool_migration_ddl_matches_the_migration_path`.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318
//! [`orchard_ironwood_migration_unsatisfiability`]:
//!     super::orchard_ironwood_migration_unsatisfiability

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_received_notes;

/// Adds tables for storage of an in-progress Orchard -> Ironwood value-pool migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x7b2f6a41_9c3d_4e58_8a17_2f6b9d0c4e11);

// The pool-migration tables have no foreign keys into the note or shardtree tables, but the engine
// works over both pools at runtime: it spends Orchard source notes (and their witnesses) and crosses
// into Ironwood. `ironwood_received_notes` is chosen as the single frontier dependency because its DAG
// closure transitively guarantees the whole stack the engine needs (Orchard received notes and
// shardtree, Ironwood received notes and shardtree), so listing those explicitly would be redundant
// under the codebase's minimal-frontier convention. If a future migration reshuffles the DAG such that
// `ironwood_received_notes` no longer pulls in the Orchard source infrastructure, add the Orchard
// dependencies here explicitly.
pub(super) const DEPENDENCIES: &[Uuid] = &[ironwood_received_notes::MIGRATION_ID];

/// The pool-migration table and index DDL byte-for-byte as `zcash_client_sqlite 0.22.0-rc.6` ran
/// it — the store's `init` batch of that release, rendered for this pool's table names, down to the
/// `tx_id` column name and the `144` ZIP 318 anchor grid as a literal rather than the constant it
/// was interpolated from. Every release that ships these tables ran this text but for one
/// character-level difference: `0.22.0-rc.2` through `0.22.0-rc.5` created `anchor_bucket_interval`
/// without its `DEFAULT 144`, which `0.22.0-rc.6` added.
///
/// This MUST NEVER CHANGE. It is not a description of the current schema and must not be updated to
/// track one: see this module's documentation for why an already-published migration's effect
/// cannot follow the store's evolving DDL. The only edit it may ever take is a correction to what a
/// released build actually ran. The statements are idempotent (`IF NOT EXISTS`) and ordered so each
/// foreign-key target is created before the table referencing it.
pub(super) const CREATE_TABLES_SQL: &str = "CREATE TABLE IF NOT EXISTS orchard_ironwood_migrations (
            id INTEGER PRIMARY KEY,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            note_split_fee_buffer INTEGER NOT NULL,
            note_split_change INTEGER,
            note_split_prep_fees INTEGER NOT NULL,
            note_split_total_input INTEGER NOT NULL,
            note_split_total_migratable INTEGER NOT NULL,
            anchor_bucket_interval INTEGER NOT NULL DEFAULT 144
        );
CREATE TABLE IF NOT EXISTS orchard_ironwood_migration_crossing_values (
            migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        );
CREATE TABLE IF NOT EXISTS orchard_ironwood_migration_prep_inputs (
            migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            source TEXT NOT NULL,
            wallet_index INTEGER,
            prior_layer INTEGER,
            prior_transaction INTEGER,
            prior_output INTEGER,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        );
CREATE TABLE IF NOT EXISTS orchard_ironwood_migration_prep_outputs (
            migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            role TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        );
CREATE TABLE IF NOT EXISTS orchard_ironwood_migration_prep_direct_funding (
            migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            wallet_index INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        );
CREATE TABLE IF NOT EXISTS orchard_ironwood_migration_transactions (
            migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
            tx_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            kind_layer INTEGER,
            kind_index INTEGER,
            kind_crossing INTEGER,
            pczt BLOB NOT NULL,
            scheduled_height INTEGER NOT NULL,
            expiry_height INTEGER NOT NULL,
            anchor_boundary INTEGER,
            state TEXT NOT NULL,
            txid TEXT,
            mined_height INTEGER,
            lock_owner BLOB,
            PRIMARY KEY (migration_id, tx_id)
        );
CREATE TABLE IF NOT EXISTS orchard_ironwood_migration_transaction_deps (
            migration_id INTEGER NOT NULL,
            tx_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            depends_on_tx_id INTEGER NOT NULL,
            PRIMARY KEY (migration_id, tx_id, ordinal),
            FOREIGN KEY (migration_id, tx_id)
                REFERENCES orchard_ironwood_migration_transactions(migration_id, tx_id) ON DELETE CASCADE
        );
CREATE INDEX IF NOT EXISTS idx_orchard_ironwood_migration_tx_due ON orchard_ironwood_migration_transactions (state, scheduled_height);
CREATE UNIQUE INDEX IF NOT EXISTS idx_orchard_ironwood_migrations_account ON orchard_ironwood_migrations (account_id);";

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
        transaction.execute_batch(CREATE_TABLES_SQL)?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
