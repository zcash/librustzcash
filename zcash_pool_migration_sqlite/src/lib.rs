//! SQLite persistence for value-pool migrations (ZIP 318).
//!
//! This crate implements [`zcash_pool_migration_backend`]'s `PoolMigrationRead` /
//! `PoolMigrationWrite` store traits over two SQLite tables, mirroring how `zcash_client_sqlite`
//! implements `zcash_client_backend`'s `WalletRead` / `WalletWrite`. A committed migration is a set
//! of pre-signed PCZTs plus their schedule and lifecycle state, so a wallet resumes a migration
//! entirely from these tables after being closed or restarted.
//!
//! # Structure: one generic store, one public submodule per pool
//!
//! The generic, pool-agnostic store machinery (the DDL builders, the blob encode/decode helpers, and
//! the store logic) lives in a private `store` module, parameterized over the per-pool table names.
//! Each pool migration is a public submodule that instantiates the store with its own table names and
//! exposes the concrete API; the generic store type never appears in the public surface. This lets
//! future pool migrations reuse the same machinery under their own tables. Currently the only such
//! submodule is [`orchard_ironwood`] (the Orchard -> Ironwood migration), whose tables are
//! `orchard_ironwood_migrations` / `orchard_ironwood_migration_transactions`.
//!
//! # Dependency direction (no cycle)
//!
//! `zcash_client_sqlite` DEPENDS ON this crate, not the reverse. This crate depends only on
//! [`zcash_pool_migration_backend`] (the state types + traits) and `rusqlite`; it never names
//! `zcash_client_sqlite`. Because a `zcash_client_sqlite` schema migration's `up()` returns that
//! crate's `WalletMigrationError` and its `dependencies()` names
//! `ironwood_received_notes::MIGRATION_ID` (both defined there), this crate does NOT define the
//! `schemerz` migration itself. Instead each pool submodule exposes the table DDL (its
//! `init_migration_tables`) and a canonical `MIGRATION_ID`; `zcash_client_sqlite` defines the thin
//! `schemerz::Migration` that runs the DDL, sets the `ironwood_received_notes` dependency, maps the
//! error, and exposes the store through its `WalletDb`. The pool-migration tables then live in the
//! same `wallet.db` and share its schema versioning.
//!
//! # Model
//!
//! There is at most one migration in progress per pool, stored as a single row in the pool's
//! migrations table keyed by the singleton id, with its transactions in the pool's transactions
//! table. The pool's `PoolMigrations` type is the store: construct it over a `rusqlite::Connection`
//! (the same one `WalletDb` uses).

mod store;

pub mod orchard_ironwood;
