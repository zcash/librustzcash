//! The SQLite pool-migration store instantiated for the Orchard -> Ironwood migration (ZIP 318);
//! tables `orchard_ironwood_migrations` / `orchard_ironwood_migration_transactions`.
//!
//! This is the only public surface of the crate: it wraps the generic (crate-internal) store with
//! this pool's table names, exposing a concrete [`PoolMigrations`] that implements
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`], the canonical [`MIGRATION_ID`], and
//! [`init_migration_tables`]. The generic store type never leaks into this API.

use std::borrow::{Borrow, BorrowMut};

use rusqlite::Connection;
use uuid::Uuid;

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

use crate::store::{self, Store, Tables};

/// The Orchard -> Ironwood table and index names this store operates over.
static TABLES: Tables = Tables {
    migrations: "orchard_ironwood_migrations",
    transactions: "orchard_ironwood_migration_transactions",
    tx_due_index: "idx_orchard_ironwood_migration_tx_due",
};

/// The `schemerz` migration id for the Orchard -> Ironwood pool-migration tables.
/// `zcash_client_sqlite` registers its (thin) migration under this id, depending on
/// `ironwood_received_notes::MIGRATION_ID`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x7b2f6a41_9c3d_4e58_8a17_2f6b9d0c4e11);

/// A failure reading or writing the pool-migration store.
pub use crate::error::Error;

/// Create the Orchard -> Ironwood pool-migration tables (and the due-transaction index) on `conn`.
/// This is the body a `zcash_client_sqlite` `schemerz` migration's `up()` calls; it is idempotent
/// (`IF NOT EXISTS`).
pub fn init_migration_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init(conn, &TABLES)
}

/// The Orchard -> Ironwood pool-migration store: a [`PoolMigrationRead`] / [`PoolMigrationWrite`] over
/// a `rusqlite::Connection`. Construct it with a connection borrow (`&Connection` for read-only
/// access, `&mut Connection` to also write); `zcash_client_sqlite` builds it over the same connection
/// its `WalletDb` uses, so the pool-migration tables share the wallet database.
pub struct PoolMigrations<C>(Store<C>);

impl<C> PoolMigrations<C> {
    /// Wrap a connection borrow as the store.
    pub fn new(conn: C) -> Self {
        Self(Store::new(conn, &TABLES))
    }

    /// Recover the wrapped connection borrow.
    pub fn into_inner(self) -> C {
        self.0.into_inner()
    }
}

impl<C: Borrow<Connection>> PoolMigrationRead for PoolMigrations<C> {
    type Error = Error;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.0.get_migration()
    }
}

impl<C: BorrowMut<Connection>> PoolMigrationWrite for PoolMigrations<C> {
    fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.0.put_migration(state)
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.0.update_transaction(id, state)
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolMigrations, init_migration_tables};

    use proptest::prelude::*;
    use rusqlite::Connection;

    use zcash_pool_migration_backend::engine::{
        MigrationTxId, MigrationTxState, PoolMigrationWrite,
    };
    use zcash_pool_migration_backend::testing::{
        arb_migration_state, arb_migration_tx_state, assert_empty_is_none,
        assert_put_get_roundtrip, assert_put_replaces, assert_update_transaction,
        first_transaction_id,
    };

    use crate::error::Error;

    /// A fresh, empty store over a new in-memory database with the migration tables created. Each
    /// proptest case and test gets its own, so writes never bleed between cases.
    fn fresh_store() -> PoolMigrations<Connection> {
        let conn = Connection::open_in_memory().expect("in-memory db");
        init_migration_tables(&conn).expect("create tables");
        PoolMigrations::new(conn)
    }

    #[test]
    fn get_migration_empty_is_none() {
        assert_empty_is_none(&fresh_store());
    }

    proptest! {
        /// Any generated migration round-trips through the SQLite store unchanged: the shared
        /// put/get conformance property, proving the SQLite backend satisfies the suite.
        #[test]
        fn put_then_get_round_trips(state in arb_migration_state()) {
            assert_put_get_roundtrip(&mut fresh_store(), &state);
        }

        /// A second put replaces the first migration (the shared replace property).
        #[test]
        fn put_replaces_previous_migration(
            first in arb_migration_state(),
            second in arb_migration_state(),
        ) {
            assert_put_replaces(&mut fresh_store(), &first, &second);
        }

        /// Updating a stored transaction's lifecycle state persists (the shared update property),
        /// exercised across every state variant, including the `Mined` and `Broadcast` payloads.
        #[test]
        fn update_transaction_advances_state(
            state in arb_migration_state(),
            new in arb_migration_tx_state(),
        ) {
            // The shared assertion needs an id the migration contains; skip the (valid) empty case.
            prop_assume!(!state.transactions().is_empty());
            let id = first_transaction_id(&state).expect("non-empty by the assumption above");
            assert_update_transaction(&mut fresh_store(), &state, id, new);
        }

        /// Updating a transaction the stored migration does not contain is a store error. This is
        /// SQLite-specific (the shared conformance suite covers only the success path).
        #[test]
        fn update_unknown_transaction_errors(state in arb_migration_state()) {
            let mut s = fresh_store();
            s.put_migration(&state).expect("write");
            // Generated ids are `0..transactions.len()` (< 6), so `u32::MAX` is always absent.
            let err = s
                .update_transaction(MigrationTxId::new(u32::MAX), MigrationTxState::Proved)
                .expect_err("no such transaction");
            prop_assert!(matches!(err, Error::Corrupt(_)));
        }
    }
}
