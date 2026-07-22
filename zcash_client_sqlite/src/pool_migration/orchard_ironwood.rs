//! The SQLite pool-migration store instantiated for the Orchard -> Ironwood migration (ZIP 318);
//! tables prefixed `orchard_ironwood_migration[s]_`.
//!
//! This is the only public surface of the pool-migration store: it wraps the generic (private)
//! store with this pool's table names, exposing a concrete [`PoolMigrations`] that implements
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`], and the `init_migration_tables` DDL its schema
//! migration runs. The generic store type never leaks into this API.

use std::borrow::{Borrow, BorrowMut};

use rusqlite::Connection;

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

use crate::AccountUuid;

use super::store::{self, Store, Tables};

/// A failure reading or writing the pool-migration store.
pub use super::error::Error;

/// The Orchard -> Ironwood table and index names this store operates over.
static TABLES: Tables = Tables {
    migrations: "orchard_ironwood_migrations",
    crossing_values: "orchard_ironwood_migration_crossing_values",
    prep_inputs: "orchard_ironwood_migration_prep_inputs",
    prep_outputs: "orchard_ironwood_migration_prep_outputs",
    prep_direct_funding: "orchard_ironwood_migration_prep_direct_funding",
    transactions: "orchard_ironwood_migration_transactions",
    transaction_deps: "orchard_ironwood_migration_transaction_deps",
    tx_due_index: "idx_orchard_ironwood_migration_tx_due",
    account_index: "idx_orchard_ironwood_migrations_account",
};

/// Create the Orchard -> Ironwood pool-migration tables (and the due-transaction and account
/// indexes) on `conn`. This is the body the `orchard_ironwood_migration_tables` schema migration's
/// `up()` calls; it is idempotent (`IF NOT EXISTS`).
pub(crate) fn init_migration_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init(conn, &TABLES)
}

/// Delete `account`'s in-progress Orchard -> Ironwood migration, if any.
///
/// The `orchard_ironwood_migrations` table keys by account UUID but has no foreign key into
/// `accounts` (the store is deliberately standalone), so an account's migration is not removed by
/// the account-deletion cascade. The wallet's `delete_account` path calls this to remove it
/// explicitly; the migration's child rows cascade from the parent via their own `ON DELETE CASCADE`
/// foreign keys (the wallet enforces foreign keys at runtime).
pub(crate) fn delete_account_migration(
    conn: &Connection,
    account: AccountUuid,
) -> rusqlite::Result<()> {
    conn.execute(
        &format!("DELETE FROM {} WHERE account_uuid = ?", TABLES.migrations),
        rusqlite::params![account.expose_uuid()],
    )?;
    Ok(())
}

/// The Orchard -> Ironwood pool-migration store: a [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// over a `rusqlite::Connection`, scoped to one account's migration. Construct it with a connection
/// borrow (`&Connection` for read-only access, `&mut Connection` to also write) over the same
/// connection a [`WalletDb`](crate::WalletDb) uses, so the pool-migration tables share the wallet
/// database.
pub struct PoolMigrations<C>(Store<C>);

impl<C> PoolMigrations<C> {
    /// Wrap a connection borrow as the store, scoped to `account`'s migration.
    pub fn for_account(conn: C, account: AccountUuid) -> Self {
        Self(Store::new(conn, &TABLES, account.expose_uuid()))
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

    use crate::AccountUuid;

    use super::Error;

    /// A fresh in-memory database with the migration tables created, but not yet wrapped as a
    /// store for any particular account. Used by tests that put more than one account's
    /// [`PoolMigrations`] over the same connection.
    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        init_migration_tables(&conn).expect("create tables");
        conn
    }

    /// A fresh, empty store over a new in-memory database with the migration tables created,
    /// scoped to a fresh random account. Each proptest case and test gets its own database and
    /// account, so writes never bleed between cases.
    fn fresh_store() -> PoolMigrations<Connection> {
        PoolMigrations::for_account(fresh_conn(), AccountUuid::from_uuid(Uuid::new_v4()))
    }

    #[test]
    fn get_migration_empty_is_none() {
        assert_empty_is_none(&fresh_store());
    }

    /// A state with an empty preparation layer is rejected on write rather than silently
    /// renumbered: the layers/transactions grid is stored only through the input and output rows,
    /// so an empty layer would leave no trace (and the engine never produces one).
    #[test]
    fn empty_prep_layer_is_rejected() {
        use zcash_pool_migration_backend::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
        use zcash_pool_migration_backend::preparation::PreparationPlan;
        use zcash_protocol::value::Zatoshis;

        let note_split = NoteSplitPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(vec![Vec::new()], Vec::new()),
            Vec::new(),
        );
        let err = fresh_store()
            .replace_migration(&state)
            .expect_err("an empty layer cannot be persisted");
        assert!(matches!(err, Error::Unrepresentable(_)));
    }

    /// `delete_account_migration` removes an account's in-progress migration (the cleanup the
    /// wallet's account-deletion path performs, since the store has no foreign key into `accounts`
    /// to cascade it). The migration's child rows cascade from the parent via their own foreign
    /// keys, so the whole subtree is gone; a different account's migration is untouched.
    #[test]
    fn delete_account_migration_removes_only_that_account() {
        use super::delete_account_migration;
        use zcash_pool_migration_backend::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
        use zcash_pool_migration_backend::preparation::PreparationPlan;
        use zcash_protocol::value::Zatoshis;

        let mut conn = fresh_conn();
        // The store's tables carry `ON DELETE CASCADE` foreign keys from each child to its parent
        // migration row; enable enforcement so deleting the parent is observed to reach the
        // children, exactly as the wallet database does after its migrations complete.
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable foreign keys");

        // A minimal but non-trivial migration (one crossing value) so the delete is observed to
        // reach a child table, not only the parent row.
        let note_split = NoteSplitPlan::from_stored_parts(
            vec![Zatoshis::const_from_u64(1)],
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::const_from_u64(1),
            Zatoshis::const_from_u64(1),
        )
        .expect("a one-crossing stored plan reconstructs");
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
        );

        let account_a = AccountUuid::from_uuid(Uuid::new_v4());
        let account_b = AccountUuid::from_uuid(Uuid::new_v4());
        PoolMigrations::for_account(&mut conn, account_a)
            .replace_migration(&state)
            .expect("write A's migration");
        PoolMigrations::for_account(&mut conn, account_b)
            .replace_migration(&state)
            .expect("write B's migration");

        let count = |conn: &Connection, table: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count")
        };
        assert_eq!(count(&conn, "orchard_ironwood_migrations"), 2);
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            2
        );

        delete_account_migration(&conn, account_a).expect("delete A's migration");

        // Only A's parent row and its child rows are gone; B's migration remains intact.
        assert_eq!(
            count(&conn, "orchard_ironwood_migrations"),
            1,
            "only account A's migration row must be deleted"
        );
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            1,
            "account A's child rows must cascade away, and only those"
        );
        assert_eq!(
            PoolMigrations::for_account(&conn, account_b)
                .get_migration()
                .expect("read B"),
            Some(state),
            "account B's migration must be untouched",
        );
    }

    /// Security: deleting an account's migration removes ONLY migration data. `account_uuid` is a
    /// bare column, not a foreign key into `accounts`, and no other table references the migration
    /// tables, so `delete_account_migration` can never cascade outward to delete the account itself
    /// or disturb any unrelated table. This guards against a future foreign key (or an errant
    /// cascade) turning a migration cleanup into account or wallet-data loss.
    #[test]
    fn delete_account_migration_does_not_touch_unrelated_data() {
        use super::delete_account_migration;
        use zcash_pool_migration_backend::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
        use zcash_pool_migration_backend::preparation::PreparationPlan;
        use zcash_protocol::value::Zatoshis;

        let mut conn = fresh_conn();
        // Stand up the wallet-side tables the migration cleanup must NOT disturb: the `accounts`
        // table the migration's account belongs to, and an unrelated table, each seeded with a row.
        conn.execute_batch(
            "CREATE TABLE accounts (id INTEGER PRIMARY KEY, uuid BLOB NOT NULL, name TEXT);
             CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);
             CREATE TABLE unrelated (id INTEGER PRIMARY KEY, note TEXT NOT NULL);",
        )
        .expect("create sibling tables");
        // Enforce foreign keys, so that any (unintended) cascade would actually fire and be caught.
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable foreign keys");

        let account = AccountUuid::from_uuid(Uuid::new_v4());
        conn.execute(
            "INSERT INTO accounts (uuid, name) VALUES (?, 'keeper')",
            rusqlite::params![account.expose_uuid()],
        )
        .expect("insert account");
        conn.execute("INSERT INTO unrelated (note) VALUES ('keep me')", [])
            .expect("insert unrelated row");

        let note_split = NoteSplitPlan::from_stored_parts(
            vec![Zatoshis::const_from_u64(1)],
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::const_from_u64(1),
            Zatoshis::const_from_u64(1),
        )
        .expect("a one-crossing stored plan reconstructs");
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
        );
        PoolMigrations::for_account(&mut conn, account)
            .replace_migration(&state)
            .expect("write the account's migration");

        delete_account_migration(&conn, account).expect("delete the account's migration");

        let count = |conn: &Connection, table: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count")
        };
        // The migration and its children are gone...
        assert_eq!(count(&conn, "orchard_ironwood_migrations"), 0);
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            0
        );
        // ...but the account row survives, unchanged, and so does every unrelated table.
        assert_eq!(
            count(&conn, "accounts"),
            1,
            "deleting a migration must NOT delete the account"
        );
        let name: String = conn
            .query_row(
                "SELECT name FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .expect("the account row must still be readable");
        assert_eq!(name, "keeper", "the account row must be unchanged");
        assert_eq!(
            count(&conn, "unrelated"),
            1,
            "deleting a migration must NOT affect unrelated tables"
        );
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

        /// Two accounts sharing one connection are isolated: writing account A's migration
        /// creates no row visible to account B (which reads back `None`, exactly as an untouched
        /// store would), while account A itself round-trips normally.
        #[test]
        fn accounts_are_isolated(state in arb_migration_state()) {
            let mut conn = fresh_conn();
            let account_a = AccountUuid::from_uuid(Uuid::new_v4());
            let account_b = AccountUuid::from_uuid(Uuid::new_v4());

            PoolMigrations::for_account(&mut conn, account_a)
                .replace_migration(&state)
                .expect("write for A");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .get_migration()
                    .expect("read for B"),
                None
            );
            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_a)
                    .get_migration()
                    .expect("read for A"),
                Some(state)
            );
        }

        /// Replacing account A's migration touches only A's row and children: account B's
        /// previously written migration, on the same connection, is unaffected.
        #[test]
        fn replace_migration_is_scoped_to_its_account(
            state_a_1 in arb_migration_state(),
            state_a_2 in arb_migration_state(),
            state_b in arb_migration_state(),
        ) {
            let mut conn = fresh_conn();
            let account_a = AccountUuid::from_uuid(Uuid::new_v4());
            let account_b = AccountUuid::from_uuid(Uuid::new_v4());

            PoolMigrations::for_account(&mut conn, account_a)
                .replace_migration(&state_a_1)
                .expect("write A first");
            PoolMigrations::for_account(&mut conn, account_b)
                .replace_migration(&state_b)
                .expect("write B");
            PoolMigrations::for_account(&mut conn, account_a)
                .replace_migration(&state_a_2)
                .expect("write A second");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_a)
                    .get_migration()
                    .expect("read A"),
                Some(state_a_2)
            );
            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .get_migration()
                    .expect("read B"),
                Some(state_b)
            );
        }

        /// A second `replace_migration` for the same account still replaces: the per-account
        /// singleton semantics hold (enforced by the unique index over `account_uuid`), because
        /// the account's existing row is deleted before the new one is inserted.
        #[test]
        fn replace_migration_replaces_same_account(
            first in arb_migration_state(),
            second in arb_migration_state(),
        ) {
            let account = AccountUuid::from_uuid(Uuid::new_v4());
            let mut store = PoolMigrations::for_account(fresh_conn(), account);
            store.replace_migration(&first).expect("write first");
            store.replace_migration(&second).expect("write second");
            prop_assert_eq!(store.get_migration().expect("read"), Some(second));
        }

        /// `update_transaction` is scoped to its account: advancing a transaction's state for
        /// account A does not affect account B's migration on the same connection, even when both
        /// accounts started from the same migration state (and so share the updated `tx_id`).
        #[test]
        fn update_transaction_is_scoped_to_its_account(
            state in arb_migration_state(),
            new in arb_migration_tx_state(),
        ) {
            prop_assume!(!state.transactions().is_empty());
            let id = first_transaction_id(&state).expect("non-empty by the assumption above");

            let mut conn = fresh_conn();
            let account_a = AccountUuid::from_uuid(Uuid::new_v4());
            let account_b = AccountUuid::from_uuid(Uuid::new_v4());

            PoolMigrations::for_account(&mut conn, account_a)
                .replace_migration(&state)
                .expect("write A");
            PoolMigrations::for_account(&mut conn, account_b)
                .replace_migration(&state)
                .expect("write B");

            PoolMigrations::for_account(&mut conn, account_a)
                .update_transaction(id, new)
                .expect("update A");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .get_migration()
                    .expect("read B"),
                Some(state),
                "account B's migration must be unaffected by account A's update_transaction",
            );
        }
    }
}
