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
pub use crate::store::Error;

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

    use rusqlite::Connection;

    use zcash_pool_migration_backend::engine::{
        MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
        MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
    use zcash_pool_migration_backend::preparation::{
        PrepInput, PrepOutput, PrepTransaction, PreparationPlan,
    };
    use zcash_protocol::TxId;
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::value::Zatoshis;

    use crate::store::Error;

    fn store() -> PoolMigrations<Connection> {
        let conn = Connection::open_in_memory().expect("in-memory db");
        init_migration_tables(&conn).expect("create tables");
        PoolMigrations::new(conn)
    }

    /// A representable amount, for terse test fixtures.
    fn zat(n: u64) -> Zatoshis {
        Zatoshis::from_u64(n).expect("valid amount")
    }

    /// A two-layer preparation plan exercising every input tag (Wallet, Prior), every output tag
    /// (Funding, Intermediate, Change), multiple layers, and a direct-funding note.
    fn sample_preparation() -> PreparationPlan {
        let layer0 = vec![PrepTransaction::from_parts(
            vec![PrepInput::Wallet {
                index: 0,
                value: zat(224_321),
            }],
            vec![
                PrepOutput::Intermediate(zat(220_000)),
                PrepOutput::Change(zat(4_321)),
            ],
        )];
        let layer1 = vec![PrepTransaction::from_parts(
            vec![PrepInput::Prior {
                layer: 0,
                transaction: 0,
                output: 0,
                value: zat(220_000),
            }],
            vec![
                PrepOutput::Funding(zat(120_000)),
                PrepOutput::Funding(zat(100_000)),
            ],
        )];
        PreparationPlan::from_parts(vec![layer0, layer1], vec![(2, zat(220_000))])
    }

    fn sample_state() -> MigrationState {
        let note_split = NoteSplitPlan::from_stored_parts(
            vec![zat(100_000), zat(200_000)], // crossing_values
            zat(20_000),                      // note_fee_buffer (outputs = crossings + buffer)
            Some(zat(4_321)),                 // change
            zat(10_000),                      // prep_fees
            zat(424_321),                     // total_input
            zat(300_000),                     // total_migratable
        )
        .expect("valid note split");
        MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            vec![zat(120_000), zat(220_000)],
            sample_preparation(),
            vec![
                MigrationTransaction::from_parts(
                    MigrationTxId::new(0),
                    MigrationTxKind::Preparation { layer: 0, index: 0 },
                    vec![1, 2, 3, 4],
                    vec![],
                    BlockHeight::from_u32(210),
                    BlockHeight::from_u32(250),
                    None,
                    MigrationTxState::Signed,
                ),
                MigrationTransaction::from_parts(
                    MigrationTxId::new(1),
                    MigrationTxKind::Transfer { crossing: 0 },
                    vec![5, 6, 7],
                    vec![MigrationTxId::new(0)],
                    BlockHeight::from_u32(260),
                    BlockHeight::from_u32(300),
                    Some(BlockHeight::from_u32(255)),
                    MigrationTxState::AwaitingSignature,
                ),
            ],
        )
    }

    #[test]
    fn get_migration_empty_is_none() {
        assert!(store().get_migration().expect("read").is_none());
    }

    #[test]
    fn put_then_get_round_trips() {
        let mut s = store();
        let state = sample_state();
        s.put_migration(&state).expect("write");

        let read = s.get_migration().expect("read").expect("some migration");
        assert_eq!(read.status(), state.status());
        assert_eq!(read.funding_notes(), state.funding_notes());
        assert_eq!(
            read.note_split().migration_outputs(),
            state.note_split().migration_outputs()
        );
        assert_eq!(
            read.note_split().crossing_values(),
            state.note_split().crossing_values()
        );
        assert_eq!(read.note_split().change(), state.note_split().change());
        assert_eq!(
            read.note_split().prep_fees(),
            state.note_split().prep_fees()
        );
        assert_eq!(
            read.note_split().total_input(),
            state.note_split().total_input()
        );
        assert_eq!(
            read.note_split().total_migratable(),
            state.note_split().total_migratable()
        );
        assert_eq!(read.transactions(), state.transactions());
        assert_eq!(read.preparation(), state.preparation());
    }

    #[test]
    fn put_replaces_previous_migration() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("first write");

        let base = sample_state();
        let mut txs = base.transactions().to_vec();
        txs.truncate(1);
        let second = MigrationState::from_parts(
            MigrationStatus::Complete,
            base.note_split().clone(),
            base.funding_notes().to_vec(),
            base.preparation().clone(),
            txs,
        );
        s.put_migration(&second).expect("second write");

        let read = s.get_migration().expect("read").expect("some migration");
        assert_eq!(read.status(), MigrationStatus::Complete);
        assert_eq!(read.transactions().len(), 1);
    }

    #[test]
    fn update_transaction_advances_state() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("write");

        let txid = TxId::from_bytes([7u8; 32]);
        s.update_transaction(MigrationTxId::new(1), MigrationTxState::Broadcast { txid })
            .expect("update");

        let read = s.get_migration().expect("read").expect("some migration");
        let transfer = read
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTxId::new(1))
            .expect("transfer present");
        assert_eq!(transfer.state(), MigrationTxState::Broadcast { txid });
    }

    #[test]
    fn update_unknown_transaction_errors() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("write");
        let err = s
            .update_transaction(MigrationTxId::new(99), MigrationTxState::Proved)
            .expect_err("no such transaction");
        assert!(matches!(err, Error::Corrupt(_)));
    }

    #[test]
    fn mined_state_round_trips() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("write");
        s.update_transaction(
            MigrationTxId::new(0),
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(231),
            },
        )
        .expect("update");
        let read = s.get_migration().expect("read").expect("some migration");
        let prep = read
            .transactions()
            .iter()
            .find(|t| t.id() == MigrationTxId::new(0))
            .expect("prep present");
        assert_eq!(
            prep.state(),
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(231)
            }
        );
    }
}
