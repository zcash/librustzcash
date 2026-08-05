//! SQLite persistence for value-pool migrations (ZIP 318).
//!
//! This module implements [`zcash_pool_migration`]'s [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] store traits over a set of SQLite tables in the wallet database,
//! mirroring how this crate implements `zcash_client_backend`'s `WalletRead` / `WalletWrite`. A
//! committed migration is a set of pre-signed PCZTs plus their schedule and lifecycle state, so a
//! wallet resumes a migration entirely from these tables after being closed or restarted.
//!
//! The schema is fully NORMALIZED: every structured value (the denomination plan, the preparation
//! plan's transaction inputs/outputs and direct-funding notes, the transaction kind, and the
//! dependency graph) is stored in typed columns and child tables, so it can be queried directly.
//! The `BLOB` columns are the pre-signed transaction (`pczt`), which is genuinely unstructured,
//! already-versioned bytes, and the transaction's `lock_owner` (an opaque fixed-size token, not a
//! structured value); all amounts are zatoshi `INTEGER` columns and the broadcast `txid` is
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
//! The pool-migration tables live in the same `wallet.db` as everything else and share its schema
//! versioning: a `schemerz` migration in `crate::wallet::init::migrations` (for Orchard ->
//! Ironwood, `orchard_ironwood_migration_tables`) creates them, and later migrations evolve them.
//!
//! Each pool submodule also exposes its tables' CURRENT shape as an idempotent
//! `init_migration_tables`. That is the shape a wallet has once every migration has run — not the
//! DDL any released migration executes, since a published migration's effect on an existing
//! database must not change when the schema does. A pool whose creating migration has not shipped
//! yet can be created from it directly.
//!
//! # Chain-derived state, in both directions
//!
//! A stored migration's chain-derived state — the unsatisfiability marks, and which of its
//! transactions are mined — follows this wallet's scan, and neither direction is the consumer's
//! to drive.
//!
//! FORWARD, a transaction is recorded mined because the scan has seen it: the store answers
//! [`PoolMigrationRead::mined_height`] from the wallet's own `transactions` table, bounded by the
//! fully-scanned height, and [`advance_migration`] promotes every in-flight transaction it sweeps.
//! A consumer records that it BROADCAST — testimony no scan can supply — and nothing more.
//!
//! BACKWARD, it is rolled back with the wallet: [`WalletWrite::truncate_to_height`] (and
//! everything routed through it) drives each stored migration's own
//! [`MigrationState::truncate_to_height`] at the height it ACTUALLY truncated to, in the same
//! database transaction.
//!
//! So a consumer has no hook to remember in either direction: a mark can never rest on an
//! observation the wallet has discarded, and a transaction can neither stay recorded mined above
//! the wallet's own view of the chain nor lag behind it.
//!
//! [`WalletWrite::truncate_to_height`]: zcash_client_backend::data_api::WalletWrite::truncate_to_height
//! [`MigrationState::truncate_to_height`]: zcash_pool_migration::engine::MigrationState::truncate_to_height
//! [`PoolMigrationRead::mined_height`]: zcash_pool_migration::engine::PoolMigrationRead::mined_height
//! [`advance_migration`]: zcash_pool_migration::satisfiability::advance_migration
//!
//! # Model
//!
//! There is at most one migration in progress per pool per account, stored as a row in the pool's
//! migrations table keyed by an `account_id` foreign key into `accounts` (with `ON DELETE CASCADE`,
//! so an account's migration is removed with the account), with its transactions, denomination plan, and
//! preparation plan in the pool's child tables (addressed through that row's synthetic primary
//! key). The pool's `PoolMigrations` type is the store: construct it over a `rusqlite::Connection`
//! (the same one [`WalletDb`](crate::WalletDb) uses) and the [`AccountUuid`](crate::AccountUuid)
//! whose migration it tracks, which it resolves to that account's row up front.
//!
//! [`PoolMigrationRead`]: zcash_pool_migration::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration::engine::PoolMigrationWrite

mod error;
mod store;

pub mod orchard_ironwood;

use uuid::Uuid;
use zcash_pool_migration::engine::{MigrationStatus, MigrationTransferId};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

/// The stable external identity of one pool-migration record, following the
/// [`AccountUuid`](crate::AccountUuid) precedent: random per record, preserved across every
/// rewrite of the record's state, and safe to hand across an FFI — unlike the store's row ids,
/// which are not stable across a restore or an export. Obtained from
/// [`MigrationSummary::id`], and resolved back through a pool facade's `get_migration_by_id`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MigrationUuid(Uuid);

impl MigrationUuid {
    /// Constructs a `MigrationUuid` from a bare [`Uuid`] value.
    ///
    /// The resulting identifier is not guaranteed to correspond to any migration stored in a
    /// [`WalletDb`](crate::WalletDb).
    pub fn from_uuid(value: Uuid) -> Self {
        MigrationUuid(value)
    }

    /// Exposes the underlying [`Uuid`] value.
    pub fn expose_uuid(&self) -> Uuid {
        self.0
    }
}

/// One row of a migration-history listing: the identity, status, and aggregate progress of a
/// single migration an account has run, PROJECTED IN SQL from the store's typed columns.
///
/// Deliberately not a [`MigrationState`](zcash_pool_migration::engine::MigrationState): a full
/// state carries every transaction's (proven) PCZT and runs to megabytes, so a list of states
/// would deserialize every proof the account ever produced in order to render a history screen.
/// A summary is what the screen needs; the full state of one migration is a follow-up
/// `get_migration_by_id` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSummary {
    pub(crate) id: MigrationUuid,
    pub(crate) status: MigrationStatus,
    pub(crate) committed_height: Option<BlockHeight>,
    pub(crate) total_input: Zatoshis,
    pub(crate) total_migratable: Zatoshis,
    pub(crate) change: Option<Zatoshis>,
    pub(crate) transaction_count: usize,
    pub(crate) mined_count: usize,
    pub(crate) in_flight_count: usize,
    pub(crate) unsatisfiable_count: usize,
    pub(crate) value_migrated: Zatoshis,
}

impl MigrationSummary {
    /// The migration's stable identity, resolvable to its full state through the pool facade's
    /// `get_migration_by_id`.
    pub fn id(&self) -> MigrationUuid {
        self.id
    }

    /// The migration's lifecycle status.
    pub fn status(&self) -> MigrationStatus {
        self.status
    }

    /// The chain height the migration was committed at, if recorded (`None` for records that
    /// predate the column).
    pub fn committed_height(&self) -> Option<BlockHeight> {
        self.committed_height
    }

    /// The total value of the notes the migration's plan drew on.
    pub fn total_input(&self) -> Zatoshis {
        self.total_input
    }

    /// The total value the plan set out to migrate across the pool boundary.
    pub fn total_migratable(&self) -> Zatoshis {
        self.total_migratable
    }

    /// The value returned to the source pool as change by the plan, when any.
    pub fn change(&self) -> Option<Zatoshis> {
        self.change
    }

    /// How many transactions the migration comprises, whatever their state.
    pub fn transaction_count(&self) -> usize {
        self.transaction_count
    }

    /// How many of its transactions have been observed mined.
    pub fn mined_count(&self) -> usize {
        self.mined_count
    }

    /// How many of its transactions are broadcast but not yet observed mined.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight_count
    }

    /// How many of its transactions carry a standing unsatisfiability determination.
    pub fn unsatisfiable_count(&self) -> usize {
        self.unsatisfiable_count
    }

    /// The value that has actually crossed the pool boundary: the sum of the crossing values
    /// whose transfer has been observed mined.
    pub fn value_migrated(&self) -> Zatoshis {
        self.value_migrated
    }
}

/// What a [`cancel_migration`](orchard_ironwood::PoolMigrations::cancel_migration) call found and
/// did, transaction by transaction: cancel is honest about what it cannot undo, so it SUCCEEDS
/// and reports rather than refusing once something is in flight (refusal would reintroduce the
/// stuck state cancel exists to remove).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CancelOutcome {
    pub(crate) in_flight: Vec<MigrationTransferId>,
    pub(crate) mined: Vec<MigrationTransferId>,
    pub(crate) released: Vec<MigrationTransferId>,
}

impl CancelOutcome {
    /// Transactions already BROADCAST when cancel ran: they cannot be recalled, and coins may
    /// still land. Their wallet-side records (spend marks included) are untouched — a mempool may
    /// mine them whatever the wallet does next — and their inclusion or expiry plays out on
    /// chain. A UI renders these as "N transactions are already on their way".
    pub fn in_flight(&self) -> &[MigrationTransferId] {
        &self.in_flight
    }

    /// Transactions already MINED: part of chain history, reported for completeness.
    pub fn mined(&self) -> &[MigrationTransferId] {
        &self.mined
    }

    /// Never-broadcast transactions whose note reservations were released: their advisory locks
    /// are cleared, so the notes they would have spent return to DEFAULT note selection
    /// immediately rather than at lock expiry.
    pub fn released(&self) -> &[MigrationTransferId] {
        &self.released
    }
}
