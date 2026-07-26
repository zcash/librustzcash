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
    MigrationState, MigrationTransferId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

use zcash_client_backend::data_api::anchor_retention::AnchorRetentionInterval;

use crate::error::SqliteClientError;
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

/// The anchor bucket grids, in blocks, of every Orchard -> Ironwood migration in this database
/// that is not yet complete.
///
/// A wallet must keep retaining the boundaries of the grid each in-flight migration was committed
/// under, whatever it is currently configured to retain, or that migration's transfers become
/// unprovable. Reading the grids back from the migrations themselves is what makes that
/// independent of the application remembering to reapply a setting. See
/// [`store::active_anchor_bucket_intervals`].
pub(crate) fn active_anchor_bucket_intervals(
    conn: &Connection,
) -> Result<BTreeSet<AnchorRetentionInterval>, SqliteClientError> {
    store::active_anchor_bucket_intervals(conn, &TABLES)
        .map(|blocks| {
            blocks
                .into_iter()
                .map(AnchorRetentionInterval::from_stored_block_count)
                .collect()
        })
        .map_err(|e| match e {
            Error::Db(e) => SqliteClientError::DbError(e),
            other => SqliteClientError::CorruptedData(other.to_string()),
        })
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
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.0.update_transaction(id, state)
    }
}

/// Retention follows the grid recorded WITH an in-flight migration, not the wallet's current
/// configuration, so an application that reopens the wallet without reapplying a non-default
/// interval cannot cause a scan to prune a boundary that migration still needs.
///
/// This is the gap the interval-mismatch check alone leaves: that check compares intervals at
/// proving time, but the damage is done at scan time, and reapplying the setting afterwards repairs
/// the comparison without bringing the checkpoint back.
#[cfg(all(test, feature = "orchard"))]
mod retention_follows_the_committed_migration {
    use core::num::NonZeroU32;
    use std::collections::BTreeSet;

    use shardtree::store::ShardStore;
    use zcash_client_backend::data_api::anchor_retention::AnchorRetentionInterval;
    use zcash_client_backend::data_api::testing::{
        TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
    };
    use zcash_client_backend::data_api::{Account as _, WalletCommitmentTrees, WalletRead};
    use zcash_pool_migration::denomination::DenominationPlan;
    use zcash_pool_migration::engine::{
        MigrationState, MigrationStatus, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration::preparation::PreparationPlan;
    use zcash_pool_migration::scheduling::AnchorBucketInterval;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::value::Zatoshis;

    use super::PoolMigrations;
    use crate::testing::{BlockCache, db::TestDbFactory};

    /// A migration carrying no transactions, recorded as committed under `interval`. Only the
    /// recorded grid matters here; the retention decision does not look at the transfers.
    fn migration_committed_under(interval: AnchorBucketInterval) -> MigrationState {
        MigrationState::from_parts(
            MigrationStatus::Committed,
            DenominationPlan::from_stored_parts(
                Vec::new(),
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
            )
            .expect("an empty stored plan reconstructs"),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
            interval,
        )
    }

    #[test]
    fn misconfigured_reopen_keeps_retaining_the_committed_grid() {
        let activation = zcash_protocol::consensus::BlockHeight::from_u32(100_000);
        let network = zcash_protocol::local_consensus::LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };

        // The wallet is left at the ZIP 318 default: this stands for an application that
        // configured a short grid when it committed, then reopened without reapplying it.
        let mut st = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        assert_eq!(
            st.wallet().anchor_retention_interval(),
            AnchorRetentionInterval::ZIP_318,
            "the wallet is configured with the default grid",
        );

        // Record a migration committed under a 12-block grid.
        let committed = AnchorBucketInterval::custom(NonZeroU32::new(12).expect("nonzero"));
        let account_id = st
            .test_account()
            .expect("the test account exists")
            .account()
            .id();
        PoolMigrations::for_account(st.wallet_mut().conn_mut(), account_id)
            .expect("the account exists")
            .replace_migration(&migration_committed_under(committed))
            .expect("persists the migration");

        // Scan enough blocks to cross several boundaries of both grids. The account's birthday is
        // the Sapling activation height, so the first generated block sits just above it.
        let fvk = OrchardPoolTester::test_account_fvk(&st);
        for _ in 0..600 {
            let (h, _, _) = st.generate_next_block(
                &fvk,
                zcash_client_backend::data_api::testing::AddressType::DefaultExternal,
                Zatoshis::const_from_u64(10_000),
            );
            st.scan_cached_blocks(h, 1);
        }
        let tip = u32::from(
            st.wallet()
                .chain_height()
                .expect("reads the chain height")
                .expect("the wallet has a chain tip"),
        );
        let start = u32::from(activation);

        let retained: BTreeSet<u32> = st
            .wallet_mut()
            .with_orchard_tree_mut(|tree| {
                Ok::<_, crate::error::SqliteClientError>(
                    tree.store()
                        .retained_checkpoints()
                        .expect("reads retained checkpoints"),
                )
            })
            .expect("reads the Orchard tree")
            .into_iter()
            .map(u32::from)
            .collect();

        // Every boundary of the MIGRATION's grid in the scanned range was retained, despite the
        // wallet being configured with a different one.
        let expected_committed: BTreeSet<u32> = (start..=tip)
            .filter(|h| h % 12 == 0 && *h > start)
            .collect();
        assert!(
            expected_committed.is_subset(&retained),
            "the committed 12-block grid must stay retained; missing {:?}",
            expected_committed.difference(&retained).collect::<Vec<_>>(),
        );

        // The configured grid is retained too: the policy is the union, not a replacement.
        let expected_configured: BTreeSet<u32> = (start..=tip)
            .filter(|h| h % 144 == 0 && *h > start)
            .collect();
        assert!(
            expected_configured.is_subset(&retained),
            "the configured grid must also stay retained",
        );

        // Sanity: with no migration recorded, the 12-block grid would NOT have been retained, so
        // the assertion above is load-bearing rather than incidentally true.
        assert!(
            !expected_committed.is_empty(),
            "the scan must cross at least one boundary of the committed grid",
        );
        assert!(
            PoolMigrations::for_account(st.wallet_mut().conn_mut(), account_id)
                .expect("the account exists")
                .get_migration()
                .expect("reads the migration")
                .is_some(),
            "the migration is still recorded",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolMigrations, init_migration_tables};

    use proptest::prelude::*;
    use rusqlite::Connection;
    use uuid::Uuid;

    use zcash_pool_migration::engine::{
        MigrationTransferId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration::scheduling::AnchorBucketInterval;
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
        use zcash_pool_migration::denomination::DenominationPlan;
        use zcash_pool_migration::engine::{
            MigrationState, MigrationStatus, MigrationTransaction, MigrationTxKind,
        };
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::consensus::BlockHeight;
        use zcash_protocol::value::Zatoshis;

        let denominations = DenominationPlan::from_stored_parts(
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
            MigrationTransferId::new(0),
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
            MigrationTransferId::new(1),
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
            denominations,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![locked, unlocked],
            AnchorBucketInterval::ZIP_318,
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
        use zcash_pool_migration::denomination::DenominationPlan;
        use zcash_pool_migration::engine::{
            MigrationState, MigrationStatus, MigrationTransaction, MigrationTxKind,
        };
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

        let denominations = DenominationPlan::from_stored_parts(
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
                MigrationTransferId::new(id),
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
            denominations,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![
                tx(0, 0, Some(owner_a_bytes)),
                tx(1, 1, Some(owner_b_bytes)),
                tx(2, 2, None),
                // A second transaction locked by A, to prove duplicates collapse.
                tx(3, 3, Some(owner_a_bytes)),
            ],
            AnchorBucketInterval::ZIP_318,
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
        use zcash_pool_migration::denomination::DenominationPlan;
        use zcash_pool_migration::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::value::Zatoshis;

        let denominations = DenominationPlan::from_stored_parts(
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
            denominations,
            PreparationPlan::from_parts(vec![Vec::new()], Vec::new()),
            Vec::new(),
            AnchorBucketInterval::ZIP_318,
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
        use zcash_pool_migration::denomination::DenominationPlan;
        use zcash_pool_migration::engine::{MigrationState, MigrationStatus};
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
        let denominations = DenominationPlan::from_stored_parts(
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
            denominations,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
            AnchorBucketInterval::ZIP_318,
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
                .update_transaction(MigrationTransferId::new(u32::MAX), MigrationTxState::Proved)
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
