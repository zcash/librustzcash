//! SQLite persistence for value-pool migrations (ZIP 318).
//!
//! This module implements [`zcash_pool_migration_backend`]'s [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] store traits over a set of SQLite tables in the wallet database,
//! mirroring how this crate implements `zcash_client_backend`'s `WalletRead` / `WalletWrite`. A
//! committed migration is a set of pre-signed PCZTs plus their schedule and lifecycle state, so a
//! wallet resumes a migration entirely from these tables after being closed or restarted.
//!
//! The schema is fully NORMALIZED: every structured value (the note-split plan, the preparation
//! plan's transaction inputs/outputs and direct-funding notes, the transaction kind, and the
//! dependency graph) is stored in typed columns and child tables, so it can be queried directly.
//! The only `BLOB` column is the pre-signed transaction (`pczt`), which is genuinely unstructured,
//! already-versioned bytes; all amounts are zatoshi `INTEGER` columns and the broadcast `txid` is
//! hex `TEXT`. It is also MINIMAL: values derivable from other columns get no tables of their own
//! (the funding-note values are the crossing values plus the fee buffer, and the preparation
//! plan's layers/transactions grid is implied by the input and output rows' `(layer, tx_index)`
//! coordinates, since a real plan has no empty layer and no transaction without inputs and
//! outputs).
//!
//! # Structure: one generic store, one public submodule per pool
//!
//! The generic, pool-agnostic store machinery (the DDL builders and the SQL store logic) lives in
//! a private `store` submodule, parameterized over the per-pool table names, with the error type
//! in a private `error` submodule. Because the schema is normalized, the store maps the engine
//! types to and from typed columns and child-table rows directly (only the opaque `pczt` is stored
//! as bytes), rather than through a blob codec. Each pool migration is a public submodule that
//! instantiates the store with its own table names and exposes the concrete API; the generic store
//! type never appears in the public surface. This lets future pool migrations reuse the same
//! machinery under their own tables. Currently the only such submodule is [`orchard_ironwood`]
//! (the Orchard -> Ironwood migration), whose tables are all prefixed
//! `orchard_ironwood_migration[s]_`.
//!
//! # Schema registration
//!
//! Each pool submodule exposes its table DDL as an idempotent `init_migration_tables`; the
//! corresponding `schemerz` migration in `crate::wallet::init::migrations` (for Orchard ->
//! Ironwood, `orchard_ironwood_migration_tables`) runs that DDL inside the wallet schema, so the
//! pool-migration tables live in the same `wallet.db` and share its schema versioning.
//!
//! # Model
//!
//! There is at most one migration in progress per pool per account, stored as a row in the pool's
//! migrations table keyed by an `account_id` foreign key into `accounts` (with `ON DELETE CASCADE`,
//! so an account's migration is removed with the account), with its transactions, note split, and
//! preparation plan in the pool's child tables (addressed through that row's synthetic primary
//! key). The pool's `PoolMigrations` type is the store: construct it over a `rusqlite::Connection`
//! (the same one [`WalletDb`](crate::WalletDb) uses) and the [`AccountUuid`](crate::AccountUuid)
//! whose migration it tracks, which it resolves to that account's row up front.
//!
//! [`PoolMigrationRead`]: zcash_pool_migration_backend::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration_backend::engine::PoolMigrationWrite

mod error;
mod store;

pub mod orchard_ironwood;
