//! The SQLite pool-migration store instantiated for the Orchard -> Ironwood migration (ZIP 318);
//! tables `orchard_ironwood_migrations` / `orchard_ironwood_migration_transactions`.
//!
//! This is the only public surface of the crate: it wraps the generic (crate-internal) store with
//! this pool's table names, exposing a concrete [`PoolMigrations`] that implements
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`], the canonical [`MIGRATION_ID`] /
//! [`ACCOUNT_KEY_MIGRATION_ID`], and [`init_migration_tables`]. The generic store type never leaks
//! into this API.
//!
//! Rows are keyed by the owning account's UUID, and a [`PoolMigrations`] handle is scoped to one
//! account at construction ([`PoolMigrations::for_account`]), so the engine traits stay
//! account-agnostic while several accounts of one wallet database migrate independently —
//! concurrently or one after another.

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

/// The `schemerz` migration id for re-keying the pool-migration tables by account
/// (`account_uuid` replacing the former singleton row id). `zcash_client_sqlite` registers its
/// (thin) migration under this id, depending on [`MIGRATION_ID`]; databases whose tables were
/// created at the current (account-keyed) shape see it as a no-op.
pub const ACCOUNT_KEY_MIGRATION_ID: Uuid = Uuid::from_u128(0x8d1f42c9_5b3a_4e76_9c0d_e4a52b8f6371);

/// A failure reading or writing the pool-migration store.
pub use crate::error::Error;

/// Create the Orchard -> Ironwood pool-migration tables (and the due-transaction index) on `conn`.
/// This is the body a `zcash_client_sqlite` `schemerz` migration's `up()` calls; it is idempotent
/// (`IF NOT EXISTS`).
pub fn init_migration_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init(conn, &TABLES)
}

/// The Orchard -> Ironwood pool-migration store: a [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// over a `rusqlite::Connection`, scoped to one account's migration. Construct it with a connection
/// borrow (`&Connection` for read-only access, `&mut Connection` to also write) and the owning
/// account's UUID; `zcash_client_sqlite` builds it over the same connection its `WalletDb` uses, so
/// the pool-migration tables share the wallet database, with each account's migration in its own
/// row.
pub struct PoolMigrations<C>(Store<C>);

impl<C> PoolMigrations<C> {
    /// Wrap a connection borrow as the store for `account`'s migration.
    pub fn for_account(conn: C, account: Uuid) -> Self {
        Self(Store::new(conn, &TABLES, account))
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
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.0.replace_migration(state)
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
    use uuid::Uuid;

    use zcash_pool_migration_backend::engine::{
        MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration_backend::testing::{
        arb_migration_state, arb_migration_tx_state, assert_empty_is_none,
        assert_put_get_roundtrip, assert_put_replaces, assert_update_transaction,
        first_transaction_id,
    };

    use crate::error::Error;

    /// A fixed account for the single-account conformance cases.
    const ACCOUNT: Uuid = Uuid::from_u128(0x11111111_1111_1111_1111_111111111111);
    /// A second, distinct account for the isolation cases.
    const OTHER_ACCOUNT: Uuid = Uuid::from_u128(0x22222222_2222_2222_2222_222222222222);

    /// A fresh, empty store over a new in-memory database with the migration tables created. Each
    /// proptest case and test gets its own, so writes never bleed between cases.
    fn fresh_store() -> PoolMigrations<Connection> {
        let conn = Connection::open_in_memory().expect("in-memory db");
        init_migration_tables(&conn).expect("create tables");
        PoolMigrations::for_account(conn, ACCOUNT)
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
            s.replace_migration(&state).expect("write");
            // Generated ids are `0..transactions.len()` (< 6), so `u32::MAX` is always absent.
            let err = s
                .update_transaction(MigrationTxId::new(u32::MAX), MigrationTxState::Proved)
                .expect_err("no such transaction");
            prop_assert!(matches!(err, Error::Corrupt(_)));
        }

        /// Accounts are isolated: one account's writes are invisible to another account's handle
        /// over the same database, a replace under one account leaves the other's migration
        /// untouched, and a transaction update addresses only the owning account's rows.
        #[test]
        fn accounts_are_isolated(
            first in arb_migration_state(),
            second in arb_migration_state(),
            new in arb_migration_tx_state(),
        ) {
            let mut conn = Connection::open_in_memory().expect("in-memory db");
            init_migration_tables(&conn).expect("create tables");

            // A write under ACCOUNT is invisible to OTHER_ACCOUNT.
            let mut store_a = PoolMigrations::for_account(&mut conn, ACCOUNT);
            store_a.replace_migration(&first).expect("write A");
            let conn = store_a.into_inner();
            let store_b = PoolMigrations::for_account(&*conn, OTHER_ACCOUNT);
            prop_assert_eq!(store_b.get_migration().expect("read B"), None);

            // Both accounts hold their own migration after B writes too.
            let mut store_b = PoolMigrations::for_account(&mut *conn, OTHER_ACCOUNT);
            store_b.replace_migration(&second).expect("write B");
            let store_a = PoolMigrations::for_account(&*conn, ACCOUNT);
            prop_assert_eq!(store_a.get_migration().expect("read A"), Some(first.clone()));

            // A replace under B leaves A untouched.
            let mut store_b = PoolMigrations::for_account(&mut *conn, OTHER_ACCOUNT);
            store_b.replace_migration(&second).expect("re-write B");
            let store_a = PoolMigrations::for_account(&*conn, ACCOUNT);
            prop_assert_eq!(store_a.get_migration().expect("read A"), Some(first.clone()));

            // An update under A addresses only A's rows: B's copy of the same id is unchanged.
            if let Some(id) = first_transaction_id(&first) {
                let mut store_a = PoolMigrations::for_account(&mut *conn, ACCOUNT);
                store_a.update_transaction(id, new).expect("update A");
                let store_b = PoolMigrations::for_account(&*conn, OTHER_ACCOUNT);
                prop_assert_eq!(store_b.get_migration().expect("read B"), Some(second));
            }
        }
    }
}
