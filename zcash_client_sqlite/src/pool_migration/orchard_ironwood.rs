//! The SQLite pool-migration store instantiated for the Orchard -> Ironwood migration (ZIP 318);
//! tables prefixed `orchard_ironwood_migration[s]_`.
//!
//! This is the only public surface of the pool-migration store: it wraps the generic (private)
//! store with this pool's table names, exposing a concrete [`PoolMigrations`] that implements
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`], and the `init_migration_tables` DDL its schema
//! migration runs. The generic store type never leaks into this API.

use std::borrow::{Borrow, BorrowMut};
use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};

use zcash_client_backend::wallet::LockOwner;
use zcash_pool_migration::engine::{
    MigrationState, MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

use crate::{AccountRef, AccountUuid};

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

/// The Orchard -> Ironwood pool-migration store: a [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// over a `rusqlite::Connection`, scoped to one account's migration. Construct it with a connection
/// borrow (`&Connection` for read-only access, `&mut Connection` to also write) over the same
/// connection a [`WalletDb`](crate::WalletDb) uses, so the pool-migration tables share the wallet
/// database.
///
/// An account's migration is owned by its row in the wallet's `accounts` table through the
/// `account_id` foreign key, so deleting the account removes its migration automatically (via
/// `ON DELETE CASCADE`); no explicit cleanup is required.
pub struct PoolMigrations<C>(Store<C>);

impl<C: Borrow<Connection>> PoolMigrations<C> {
    /// Wrap a connection borrow as the store, scoped to `account`'s migration.
    ///
    /// The account is resolved to its `accounts` row up front, so the store keys its migration by
    /// that row (the foreign key the schema uses) rather than by the external UUID. Returns
    /// [`Error::AccountUnknown`] if no account with this UUID exists in the wallet.
    pub fn for_account(conn: C, account: AccountUuid) -> Result<Self, Error> {
        let account_id = conn
            .borrow()
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0).map(AccountRef),
            )
            .optional()?
            .ok_or(Error::AccountUnknown)?;
        Ok(Self(Store::new(conn, &TABLES, account_id)))
    }
}

impl<C> PoolMigrations<C> {
    /// Recover the wrapped connection borrow.
    pub fn into_inner(self) -> C {
        self.0.into_inner()
    }
}

impl<C: Borrow<Connection>> PoolMigrations<C> {
    /// Returns the set of [`LockOwner`]s under which this account's in-progress pool migration
    /// has locked notes (empty if there is no migration, or it holds no locks).
    ///
    /// This is the set a caller passes to a `LockedInputPolicy::PreferUnlocked` /
    /// `PreferLocked` override so a proposal may draw on the migration's own locked notes
    /// without disturbing any other flow's locks. It is not part of [`PoolMigrationRead`]: that
    /// trait is shared with the pool-agnostic migration engine, which has no notion of
    /// [`LockOwner`] (a wallet-level concept).
    pub fn migration_lock_owners(&self) -> Result<BTreeSet<LockOwner>, Error> {
        self.0.migration_lock_owners()
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

    use zcash_pool_migration::engine::{
        MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration::testing::{
        arb_migration_state, arb_migration_tx_state, assert_empty_is_none,
        assert_put_get_roundtrip, assert_put_replaces, assert_update_transaction,
        first_transaction_id,
    };

    use crate::AccountUuid;

    use super::Error;

    /// A fresh in-memory database with a minimal `accounts` table (the `account_id` foreign-key
    /// target) and the migration tables created, but not yet wrapped as a store for any particular
    /// account. Used by tests that put more than one account's [`PoolMigrations`] over the same
    /// connection.
    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        // A minimal stand-in for the wallet's `accounts` table: the migration tables' `account_id`
        // foreign key references `accounts(id)`, and `for_account` resolves an `AccountUuid` to its
        // row through `accounts(uuid)`.
        conn.execute_batch(
            "CREATE TABLE accounts (id INTEGER PRIMARY KEY, uuid BLOB NOT NULL);
             CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);",
        )
        .expect("create accounts table");
        init_migration_tables(&conn).expect("create tables");
        conn
    }

    /// Insert a fresh random account into `conn`'s `accounts` table and return its UUID, so a store
    /// can be scoped to it.
    fn insert_account(conn: &Connection) -> AccountUuid {
        let account = AccountUuid::from_uuid(Uuid::new_v4());
        conn.execute(
            "INSERT INTO accounts (uuid) VALUES (?)",
            rusqlite::params![account.expose_uuid()],
        )
        .expect("insert account");
        account
    }

    /// A fresh, empty store over a new in-memory database with the migration tables created, scoped
    /// to a fresh account. Each proptest case and test gets its own database and account, so writes
    /// never bleed between cases.
    fn fresh_store() -> PoolMigrations<Connection> {
        let conn = fresh_conn();
        let account = insert_account(&conn);
        PoolMigrations::for_account(conn, account).expect("account exists")
    }

    #[test]
    fn get_migration_empty_is_none() {
        assert_empty_is_none(&fresh_store());
    }

    /// A transaction's `lock_owner` round-trips exactly through the store's `BLOB` column: a
    /// `Some` token comes back byte-for-byte and a `None` comes back as `None`, not a zeroed or
    /// otherwise substituted token. This pins the two cases the column must distinguish; the
    /// general `put_then_get_round_trips` property (whose generator also produces `lock_owner`)
    /// covers the type more broadly.
    #[test]
    fn lock_owner_round_trips() {
        use zcash_pool_migration::engine::{
            MigrationState, MigrationStatus, MigrationTransaction, MigrationTxKind,
        };
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::consensus::BlockHeight;
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

        let owner_bytes = [7u8; 32];
        let locked = MigrationTransaction::from_parts(
            MigrationTxId::new(0),
            MigrationTxKind::Preparation { layer: 0, index: 0 },
            vec![1, 2, 3],
            Vec::new(),
            BlockHeight::from_u32(100),
            BlockHeight::from_u32(200),
            None,
            MigrationTxState::Signed,
            Some(owner_bytes),
        );
        let unlocked = MigrationTransaction::from_parts(
            MigrationTxId::new(1),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![4, 5, 6],
            Vec::new(),
            BlockHeight::from_u32(100),
            BlockHeight::from_u32(200),
            None,
            MigrationTxState::Signed,
            None,
        );
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![locked, unlocked],
        );

        let mut store = fresh_store();
        store.replace_migration(&state).expect("write succeeds");
        let loaded = store
            .get_migration()
            .expect("read succeeds")
            .expect("a migration is stored");

        assert_eq!(
            loaded, state,
            "the whole migration, including lock_owner, must round-trip unchanged"
        );
        assert_eq!(
            loaded.transactions()[0].lock_owner(),
            Some(owner_bytes),
            "a `Some` lock_owner must survive exactly"
        );
        assert_eq!(
            loaded.transactions()[1].lock_owner(),
            None,
            "a `None` lock_owner must round-trip as `None`"
        );
    }

    /// `migration_lock_owners` returns exactly the distinct, non-`None` lock owners across an
    /// account's migration transactions: an account with no migration returns the empty set,
    /// a `None` lock_owner contributes nothing, and repeated owners collapse to one entry.
    #[test]
    fn migration_lock_owners_collects_distinct_non_none_owners() {
        use std::collections::BTreeSet;

        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::engine::{
            MigrationState, MigrationStatus, MigrationTransaction, MigrationTxKind,
        };
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::consensus::BlockHeight;
        use zcash_protocol::value::Zatoshis;

        let mut store = fresh_store();
        assert_eq!(
            store.migration_lock_owners().expect("read succeeds"),
            BTreeSet::new(),
            "an account with no migration must report no lock owners"
        );

        let owner_a_bytes = [0xA1u8; 32];
        let owner_b_bytes = [0xB2u8; 32];

        let note_split = NoteSplitPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");

        let tx = |id: u32, crossing: usize, lock_owner: Option<[u8; 32]>| {
            MigrationTransaction::from_parts(
                MigrationTxId::new(id),
                MigrationTxKind::Transfer { crossing },
                vec![id as u8],
                Vec::new(),
                BlockHeight::from_u32(100),
                BlockHeight::from_u32(200),
                None,
                MigrationTxState::Signed,
                lock_owner,
            )
        };

        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![
                tx(0, 0, Some(owner_a_bytes)),
                tx(1, 1, Some(owner_b_bytes)),
                tx(2, 2, None),
                // A second transaction locked by A, to prove duplicates collapse.
                tx(3, 3, Some(owner_a_bytes)),
            ],
        );

        store.replace_migration(&state).expect("write succeeds");

        let owners = store.migration_lock_owners().expect("read succeeds");
        assert_eq!(
            owners,
            BTreeSet::from([LockOwner::new(owner_a_bytes), LockOwner::new(owner_b_bytes)]),
            "must contain exactly the distinct non-None lock owners, deduped"
        );
    }

    /// A state with an empty preparation layer is rejected on write rather than silently
    /// renumbered: the layers/transactions grid is stored only through the input and output rows,
    /// so an empty layer would leave no trace (and the engine never produces one).
    #[test]
    fn empty_prep_layer_is_rejected() {
        use zcash_pool_migration::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
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

    /// Deleting an account cascades to its in-progress migration: the `account_id` foreign key
    /// carries `ON DELETE CASCADE`, so removing the account's row removes its migration, whose child
    /// rows cascade from it in turn. A different account's migration is untouched. This is the
    /// cleanup the wallet's account-deletion path now relies on entirely (no explicit delete).
    #[test]
    fn deleting_an_account_cascades_to_its_migration() {
        use zcash_pool_migration::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::value::Zatoshis;

        let mut conn = fresh_conn();
        // Enforce foreign keys so the account -> migration -> child cascade actually fires, exactly
        // as the wallet database does at runtime.
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable foreign keys");

        let account_a = insert_account(&conn);
        let account_b = insert_account(&conn);

        // A minimal but non-trivial migration (one crossing value) so the cascade is observed to
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

        PoolMigrations::for_account(&mut conn, account_a)
            .expect("account A exists")
            .replace_migration(&state)
            .expect("write A's migration");
        PoolMigrations::for_account(&mut conn, account_b)
            .expect("account B exists")
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

        // Delete account A directly, as the wallet's `delete_account` does; the cascade removes its
        // migration and children with it, and nothing else.
        conn.execute(
            "DELETE FROM accounts WHERE uuid = ?",
            rusqlite::params![account_a.expose_uuid()],
        )
        .expect("delete account A");

        // Only A's migration row and its child rows are gone; B's migration remains intact.
        assert_eq!(
            count(&conn, "orchard_ironwood_migrations"),
            1,
            "only account A's migration row must cascade away"
        );
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            1,
            "account A's child rows must cascade away, and only those"
        );
        assert_eq!(
            PoolMigrations::for_account(&conn, account_b)
                .expect("account B exists")
                .get_migration()
                .expect("read B"),
            Some(state),
            "account B's migration must be untouched",
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
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state)
                .expect("write for A");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read for B"),
                None
            );
            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_a)
                    .expect("account A exists")
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
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state_a_1)
                .expect("write A first");
            PoolMigrations::for_account(&mut conn, account_b)
                .expect("account B exists")
                .replace_migration(&state_b)
                .expect("write B");
            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state_a_2)
                .expect("write A second");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_a)
                    .expect("account A exists")
                    .get_migration()
                    .expect("read A"),
                Some(state_a_2)
            );
            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read B"),
                Some(state_b)
            );
        }

        /// A second `replace_migration` for the same account still replaces: the per-account
        /// singleton semantics hold (enforced by the unique index over `account_id`), because
        /// the account's existing row is deleted before the new one is inserted.
        #[test]
        fn replace_migration_replaces_same_account(
            first in arb_migration_state(),
            second in arb_migration_state(),
        ) {
            let conn = fresh_conn();
            let account = insert_account(&conn);
            let mut store = PoolMigrations::for_account(conn, account).expect("account exists");
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
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state)
                .expect("write A");
            PoolMigrations::for_account(&mut conn, account_b)
                .expect("account B exists")
                .replace_migration(&state)
                .expect("write B");

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .update_transaction(id, new)
                .expect("update A");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read B"),
                Some(state),
                "account B's migration must be unaffected by account A's update_transaction",
            );
        }
    }
}
