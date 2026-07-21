//! The generic, pool-agnostic SQLite pool-migration store.
//!
//! This module is entirely crate-internal: it holds the machinery shared by every pool migration
//! (the DDL builders and the [`Store`] type that carries the [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] SQL logic), parameterized over the table names in [`Tables`]. The canonical
//! byte (de)serialization of the engine types is a property of those types and lives on them in
//! [`zcash_pool_migration_backend`] (`NoteSplitPlan::write`/`read`, `PreparationPlan::write`/`read`);
//! this module only maps those blobs and the scalar values to and from SQLite columns. Each concrete
//! migration lives in its own public submodule (currently only [`crate::orchard_ironwood`]) that
//! instantiates [`Store`] with its own [`Tables`]; the generic type never leaks into the public API.
//! Only [`Error`] is re-exported by a facade.
//!
//! The blob encodings and the column set are the same for every pool: only the table and index
//! names change from one migration to the next.
//!
//! Rows are keyed by the owning account's UUID: each account has at most one active migration, and
//! a [`Store`] handle is scoped to a single account at construction, so the engine traits it serves
//! ([`PoolMigrationRead`] / [`PoolMigrationWrite`]) stay account-agnostic. Wallets that host several
//! accounts (each potentially with its own seed or an imported viewing key) migrate them
//! independently — concurrently or one after another — over the same database.

use std::borrow::{Borrow, BorrowMut};

use rusqlite::{Connection, OptionalExtension, named_params, params};
use uuid::Uuid;

use zcash_encoding::Vector;

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
    MigrationTxState,
};
use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
use zcash_pool_migration_backend::preparation::PreparationPlan;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::error::Error;

/// The per-pool table and index names a [`Store`] operates over. A concrete migration submodule
/// supplies a `'static` value of this for its own pool; the generic store interpolates these into
/// every DDL and query, so one implementation serves every pool.
pub(crate) struct Tables {
    /// The migration-state table (one row per account's active migration).
    pub migrations: &'static str,
    /// The per-transaction table.
    pub transactions: &'static str,
    /// The index over `(account_uuid, state, scheduled_height)` on the transactions table.
    pub tx_due_index: &'static str,
}

/// DDL for the migrations table: the note-split decomposition and overall status of each account's
/// active migration, keyed by the account UUID (at most one active migration per account). The
/// `note_split` column holds the whole [`NoteSplitPlan`] blob (its crossing values, fee buffer,
/// change, and totals), the `funding_notes` column a [`Vector`] of little-endian `u64` amounts, and
/// the `preparation` column the [`PreparationPlan`] blob (retained so deferred preparation layers can
/// be rebuilt after their prior layer mines). The canonical byte encodings all live on the backend
/// types (`NoteSplitPlan::write`, `PreparationPlan::write`); the store only maps them to and from
/// these columns.
pub(crate) fn create_migrations_sql(t: &Tables) -> String {
    format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        account_uuid BLOB NOT NULL PRIMARY KEY,
        status TEXT NOT NULL,
        note_split BLOB NOT NULL,
        funding_notes BLOB NOT NULL,
        preparation BLOB NOT NULL
    )",
        t.migrations
    )
}

/// DDL for the transactions table: one row per migration transaction of an account's active
/// migration, its pre-signed PCZT (`pczt`, always present: every transaction is built when the
/// migration is committed, under one-phase signing), its dependency graph (`depends_on`, a
/// serialized vector of `u32` transaction ids), schedule, and lifecycle `state`. `kind` holds the
/// whole [`MigrationTxKind`] blob (its canonical [`MigrationTxKind::write`]); `state` is the
/// queryable-and-indexed lifecycle discriminant (the [`MigrationTxState`] `AsRef<str>` value) with
/// `txid`/`mined_height` carrying the `broadcast`/`mined` payloads.
///
/// [`MigrationTxKind`]: zcash_pool_migration_backend::engine::MigrationTxKind
/// [`MigrationTxKind::write`]: zcash_pool_migration_backend::engine::MigrationTxKind::write
/// [`MigrationTxState`]: zcash_pool_migration_backend::engine::MigrationTxState
pub(crate) fn create_transactions_sql(t: &Tables) -> String {
    format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        account_uuid BLOB NOT NULL REFERENCES {}(account_uuid) ON DELETE CASCADE,
        tx_id INTEGER NOT NULL,
        kind BLOB NOT NULL,
        pczt BLOB NOT NULL,
        depends_on BLOB NOT NULL,
        scheduled_height INTEGER NOT NULL,
        expiry_height INTEGER NOT NULL,
        anchor_boundary INTEGER,
        state TEXT NOT NULL,
        txid BLOB,
        mined_height INTEGER,
        PRIMARY KEY (account_uuid, tx_id)
    )",
        t.transactions, t.migrations
    )
}

/// DDL for the index over `(account_uuid, state, scheduled_height)`, so the application can query
/// an account's transactions that are due to prove or broadcast without scanning the table.
pub(crate) fn create_index_sql(t: &Tables) -> String {
    format!(
        "
    CREATE INDEX IF NOT EXISTS {}
        ON {} (account_uuid, state, scheduled_height)",
        t.tx_due_index, t.transactions
    )
}

/// Create the pool-migration tables (and the due-transaction index) named by `t` on `conn`. This is
/// the body a `zcash_client_sqlite` `schemerz` migration's `up()` calls; it is idempotent
/// (`IF NOT EXISTS`).
pub(crate) fn init(conn: &Connection, t: &Tables) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "{};\n{};\n{};",
        create_migrations_sql(t),
        create_transactions_sql(t),
        create_index_sql(t)
    ))
}

/// The generic pool-migration store: it carries the [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// logic over a `rusqlite::Connection`, parameterized by the [`Tables`] names for a given pool and
/// scoped to a single account's migration. Construct it with a connection borrow (`&Connection` for
/// read-only access, `&mut Connection` to also write), the pool's table names, and the owning
/// account's UUID; a concrete facade wraps it so the generic type never appears in the public API.
///
/// [`PoolMigrationRead`]: zcash_pool_migration_backend::engine::PoolMigrationRead
/// [`PoolMigrationWrite`]: zcash_pool_migration_backend::engine::PoolMigrationWrite
pub(crate) struct Store<C> {
    conn: C,
    tables: &'static Tables,
    account: Uuid,
}

impl<C> Store<C> {
    /// Wrap a connection borrow and the pool's table names as the store for `account`'s migration.
    pub(crate) fn new(conn: C, tables: &'static Tables, account: Uuid) -> Self {
        Self {
            conn,
            tables,
            account,
        }
    }

    /// Recover the wrapped connection borrow.
    pub(crate) fn into_inner(self) -> C {
        self.conn
    }
}

impl<C: Borrow<Connection>> Store<C> {
    /// Read the account's active migration, if any.
    pub(crate) fn get_migration(&self) -> Result<Option<MigrationState>, Error> {
        read_migration(self.conn.borrow(), self.tables, self.account)
    }
}

impl<C: BorrowMut<Connection>> Store<C> {
    /// Replace the account's active migration with `state`, atomically (deletes any existing one
    /// first).
    pub(crate) fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Error> {
        let tables = self.tables;
        let account = self.account;
        let tx = self.conn.borrow_mut().transaction()?;
        replace_migration(&tx, tables, account, state)?;
        tx.commit()?;
        Ok(())
    }

    /// Advance the lifecycle state of the account's transaction identified by `id`.
    pub(crate) fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Error> {
        let updated = self.conn.borrow_mut().execute(
            &format!(
                "UPDATE {}
                    SET state = :state, txid = :txid, mined_height = :mined_height
                  WHERE account_uuid = :account_uuid AND tx_id = :tx_id",
                self.tables.transactions
            ),
            named_params! {
                ":state": state.as_ref(),
                ":txid": state.broadcast_txid().map(|b| b.to_vec()),
                ":mined_height": state.mined_height().map(u32::from),
                ":account_uuid": self.account.as_bytes().as_slice(),
                ":tx_id": u32::from(id),
            },
        )?;
        if updated == 0 {
            return Err(Error::Corrupt("update_transaction: no such transaction"));
        }
        Ok(())
    }
}

/// Read `account`'s active migration from the tables named by `t`, if any.
fn read_migration(
    conn: &Connection,
    t: &Tables,
    account: Uuid,
) -> Result<Option<MigrationState>, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT status, note_split, funding_notes, preparation
                   FROM {} WHERE account_uuid = ?",
                t.migrations
            ),
            params![account.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;

    let Some((status, note_split, funding_notes, preparation)) = row else {
        return Ok(None);
    };

    let note_split =
        NoteSplitPlan::read(note_split.as_slice()).map_err(|_| Error::Corrupt("note_split"))?;

    let transactions = read_transactions(conn, t, account)?;

    let status =
        MigrationStatus::try_from(status.as_str()).map_err(|_| Error::Corrupt("status"))?;
    Ok(Some(MigrationState::from_parts(
        status,
        note_split,
        Vector::read(funding_notes.as_slice(), |r| Zatoshis::read(r))
            .map_err(|_| Error::Corrupt("funding_notes"))?,
        PreparationPlan::read(preparation.as_slice()).map_err(|_| Error::Corrupt("preparation"))?,
        transactions,
    )))
}

/// Read the transactions of `account`'s active migration from the table named by `t`.
fn read_transactions(
    conn: &Connection,
    t: &Tables,
    account: Uuid,
) -> Result<Vec<MigrationTransaction>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT tx_id, kind, pczt, depends_on, scheduled_height,
                expiry_height, anchor_boundary, state, txid, mined_height
           FROM {}
          WHERE account_uuid = ?
          ORDER BY tx_id",
        t.transactions
    ))?;
    let rows = stmt.query_map(params![account.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, u32>(0)?,             // tx_id
            row.get::<_, Vec<u8>>(1)?,         // kind
            row.get::<_, Vec<u8>>(2)?,         // pczt
            row.get::<_, Vec<u8>>(3)?,         // depends_on
            row.get::<_, u32>(4)?,             // scheduled_height
            row.get::<_, u32>(5)?,             // expiry_height
            row.get::<_, Option<u32>>(6)?,     // anchor_boundary
            row.get::<_, String>(7)?,          // state
            row.get::<_, Option<Vec<u8>>>(8)?, // txid
            row.get::<_, Option<u32>>(9)?,     // mined_height
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (
            tx_id,
            kind,
            pczt,
            depends_on,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state,
            txid,
            mined_height,
        ) = row?;

        // Heights are `u32` in the domain; SQLite stores integers as a signed 64-bit `INTEGER`, and
        // rusqlite maps `u32` to and from that column transparently (erroring on an out-of-range
        // value), so no manual `i64` widening is needed here.
        let id = MigrationTxId::new(tx_id);
        let scheduled_height = BlockHeight::from_u32(scheduled_height);
        let expiry_height = BlockHeight::from_u32(expiry_height);
        let anchor_boundary = anchor_boundary.map(BlockHeight::from_u32);

        let kind = MigrationTxKind::read(kind.as_slice()).map_err(|_| Error::Corrupt("kind"))?;
        let txid = txid
            .map(|b| <[u8; 32]>::try_from(b.as_slice()).map_err(|_| Error::Corrupt("state.txid")))
            .transpose()?;
        let mined_height = mined_height.map(BlockHeight::from_u32);
        let state = MigrationTxState::from_stored(&state, txid, mined_height)
            .map_err(|_| Error::Corrupt("state"))?;

        out.push(MigrationTransaction::from_parts(
            id,
            kind,
            pczt,
            Vector::read(depends_on.as_slice(), |r| MigrationTxId::read(r))
                .map_err(|_| Error::Corrupt("depends_on"))?,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state,
        ));
    }
    Ok(out)
}

/// Replace `account`'s active migration in the tables named by `t` with `state` (deletes the
/// account's existing migration and its transactions first). Runs inside the caller's transaction so
/// the replacement is atomic. Other accounts' rows are untouched.
fn replace_migration(
    tx: &rusqlite::Transaction,
    t: &Tables,
    account: Uuid,
    state: &MigrationState,
) -> Result<(), Error> {
    let account_bytes = account.as_bytes().as_slice();

    // Replace semantics: the store holds at most one migration per account.
    tx.execute(
        &format!("DELETE FROM {} WHERE account_uuid = ?", t.transactions),
        params![account_bytes],
    )?;
    tx.execute(
        &format!("DELETE FROM {} WHERE account_uuid = ?", t.migrations),
        params![account_bytes],
    )?;

    // Each type serializes itself through its own `write`; writing to a `Vec` is infallible, so
    // `map(|()| buf)` just yields the filled buffer.
    let mut buf = Vec::new();
    let note_split = state
        .note_split()
        .write(&mut buf)
        .map(|()| buf)
        .expect("writing to a Vec is infallible");
    let mut buf = Vec::new();
    let preparation = state
        .preparation()
        .write(&mut buf)
        .map(|()| buf)
        .expect("writing to a Vec is infallible");
    let mut buf = Vec::new();
    let funding_notes = Vector::write(&mut buf, state.funding_notes(), |w, v| v.write(w))
        .map(|()| buf)
        .expect("writing to a Vec is infallible");
    tx.execute(
        &format!(
            "INSERT INTO {}
                (account_uuid, status, note_split, funding_notes, preparation)
             VALUES
                (:account_uuid, :status, :note_split, :funding_notes, :preparation)",
            t.migrations
        ),
        named_params! {
            ":account_uuid": account_bytes,
            ":status": state.status().as_ref(),
            ":note_split": note_split,
            ":funding_notes": funding_notes,
            ":preparation": preparation,
        },
    )?;

    for mtx in state.transactions() {
        let tx_state = mtx.state();
        let mut buf = Vec::new();
        let kind = mtx
            .kind()
            .write(&mut buf)
            .map(|()| buf)
            .expect("writing to a Vec is infallible");
        let mut buf = Vec::new();
        let depends_on = Vector::write(&mut buf, mtx.depends_on(), |w, id| id.write(w))
            .map(|()| buf)
            .expect("writing to a Vec is infallible");
        tx.execute(
            &format!(
                "INSERT INTO {}
                    (account_uuid, tx_id, kind, pczt, depends_on,
                     scheduled_height, expiry_height, anchor_boundary, state, txid, mined_height)
                 VALUES
                    (:account_uuid, :tx_id, :kind, :pczt, :depends_on,
                     :scheduled_height, :expiry_height, :anchor_boundary, :state, :txid,
                     :mined_height)",
                t.transactions
            ),
            named_params! {
                ":account_uuid": account_bytes,
                ":tx_id": u32::from(mtx.id()),
                ":kind": kind,
                ":pczt": mtx.pczt().as_slice(),
                ":depends_on": depends_on,
                ":scheduled_height": u32::from(mtx.scheduled_height()),
                ":expiry_height": u32::from(mtx.expiry_height()),
                ":anchor_boundary": mtx.anchor_boundary().map(u32::from),
                ":state": tx_state.as_ref(),
                ":txid": tx_state.broadcast_txid().map(|b| b.to_vec()),
                ":mined_height": tx_state.mined_height().map(u32::from),
            },
        )?;
    }
    Ok(())
}
