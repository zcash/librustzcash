//! The generic, pool-agnostic SQLite pool-migration store.
//!
//! This module is entirely crate-internal: it holds the machinery shared by every pool migration
//! (the DDL builders and the [`Store`] type that carries the [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] SQL logic), parameterized over the table names in [`Tables`]. The blob
//! (de)serialization of the engine types to and from their stored form lives in a separate module,
//! [`crate::codec`]. Each concrete migration lives in its own public submodule (currently only
//! [`crate::orchard_ironwood`]) that instantiates [`Store`] with its own [`Tables`]; the generic
//! type never leaks into the public API. Only [`Error`] is re-exported by a facade.
//!
//! The blob encodings and the column set are the same for every pool: only the table and index
//! names change from one migration to the next.

use std::borrow::{Borrow, BorrowMut};

use rusqlite::{Connection, OptionalExtension, named_params, params};

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxState,
};
use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
use zcash_protocol::consensus::BlockHeight;

use crate::codec::{
    decode_dep_ids, decode_preparation, decode_tx_kind, decode_tx_state, decode_zatoshis,
    encode_dep_ids, encode_preparation, encode_tx_kind, encode_tx_state, encode_zatoshis,
    zatoshis_from_i64,
};
use crate::error::Error;

/// The per-pool table and index names a [`Store`] operates over. A concrete migration submodule
/// supplies a `'static` value of this for its own pool; the generic store interpolates these into
/// every DDL and query, so one implementation serves every pool.
pub(crate) struct Tables {
    /// The migration-state table (one row per active migration).
    pub migrations: &'static str,
    /// The per-transaction table.
    pub transactions: &'static str,
    /// The index over `(state, scheduled_height)` on the transactions table.
    pub tx_due_index: &'static str,
}

/// The primary-key value of the single active migration. There is at most one migration in progress,
/// so it is stored as one row; a future multi-account model would replace this with an account key.
pub(crate) const SINGLETON_ID: i64 = 0;

/// DDL for the migrations table: the note-split decomposition and overall status of the single active
/// migration. The `*_values` / `funding_notes` columns hold little-endian `u64` arrays (see
/// [`encode_zatoshis`]); the `preparation` column holds the tagged encoding of the preparation plan
/// (see [`encode_preparation`]), retained so deferred preparation layers can be rebuilt after their
/// prior layer mines; zatoshi and height scalars fit in SQLite's signed 64-bit integer.
pub(crate) fn create_migrations_sql(t: &Tables) -> String {
    format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        id INTEGER PRIMARY KEY,
        status TEXT NOT NULL,
        note_fee_buffer_zatoshi INTEGER NOT NULL,
        crossing_values BLOB NOT NULL,
        change INTEGER,
        prep_fee_zatoshi INTEGER NOT NULL,
        total_input_zatoshi INTEGER NOT NULL,
        total_migratable_zatoshi INTEGER NOT NULL,
        funding_notes BLOB NOT NULL,
        preparation BLOB NOT NULL
    )",
        t.migrations
    )
}

/// DDL for the transactions table: one row per migration transaction, its pre-signed PCZT (`pczt`,
/// always present: every transaction is built when the migration is committed, under one-phase
/// signing), its dependency graph
/// (`depends_on`, a little-endian `u32` array of transaction ids), schedule, and lifecycle `state`.
/// `kind` is `'preparation'` (with `layer`/`tx_index`) or `'transfer'` (with `crossing`); `state`
/// carries `txid`/`mined_height` for the `broadcast`/`mined` states.
pub(crate) fn create_transactions_sql(t: &Tables) -> String {
    format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
        tx_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        layer INTEGER,
        tx_index INTEGER,
        crossing INTEGER,
        pczt BLOB NOT NULL,
        depends_on BLOB NOT NULL,
        scheduled_height INTEGER NOT NULL,
        expiry_height INTEGER NOT NULL,
        anchor_boundary INTEGER,
        state TEXT NOT NULL,
        txid BLOB,
        mined_height INTEGER,
        PRIMARY KEY (migration_id, tx_id)
    )",
        t.transactions, t.migrations
    )
}

/// DDL for the index over `(state, scheduled_height)`, so the application can query the transactions
/// that are due to prove or broadcast without scanning the table.
pub(crate) fn create_index_sql(t: &Tables) -> String {
    format!(
        "
    CREATE INDEX IF NOT EXISTS {}
        ON {} (state, scheduled_height)",
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
/// logic over a `rusqlite::Connection`, parameterized by the [`Tables`] names for a given pool.
/// Construct it with a connection borrow (`&Connection` for read-only access, `&mut Connection` to
/// also write) plus the pool's table names; a concrete facade wraps it so the generic type never
/// appears in the public API.
///
/// [`PoolMigrationRead`]: zcash_pool_migration_backend::engine::PoolMigrationRead
/// [`PoolMigrationWrite`]: zcash_pool_migration_backend::engine::PoolMigrationWrite
pub(crate) struct Store<C> {
    conn: C,
    tables: &'static Tables,
}

impl<C> Store<C> {
    /// Wrap a connection borrow and the pool's table names as the store.
    pub(crate) fn new(conn: C, tables: &'static Tables) -> Self {
        Self { conn, tables }
    }

    /// Recover the wrapped connection borrow.
    pub(crate) fn into_inner(self) -> C {
        self.conn
    }
}

impl<C: Borrow<Connection>> Store<C> {
    /// Read the single active migration, if any.
    pub(crate) fn get_migration(&self) -> Result<Option<MigrationState>, Error> {
        read_migration(self.conn.borrow(), self.tables)
    }
}

impl<C: BorrowMut<Connection>> Store<C> {
    /// Persist `state` as the single active migration, replacing any existing one, atomically.
    pub(crate) fn put_migration(&mut self, state: &MigrationState) -> Result<(), Error> {
        let tables = self.tables;
        let tx = self.conn.borrow_mut().transaction()?;
        write_migration(&tx, tables, state)?;
        tx.commit()?;
        Ok(())
    }

    /// Advance the lifecycle state of the transaction identified by `id`.
    pub(crate) fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Error> {
        let (state_str, txid, mined_height) = encode_tx_state(&state);
        let updated = self.conn.borrow_mut().execute(
            &format!(
                "UPDATE {}
                    SET state = :state, txid = :txid, mined_height = :mined_height
                  WHERE migration_id = :migration_id AND tx_id = :tx_id",
                self.tables.transactions
            ),
            named_params! {
                ":state": state_str,
                ":txid": txid,
                ":mined_height": mined_height,
                ":migration_id": SINGLETON_ID,
                ":tx_id": u32::from(id),
            },
        )?;
        if updated == 0 {
            return Err(Error::Corrupt("update_transaction: no such transaction"));
        }
        Ok(())
    }
}

/// Read the single active migration from the tables named by `t`, if any.
fn read_migration(conn: &Connection, t: &Tables) -> Result<Option<MigrationState>, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT status, note_fee_buffer_zatoshi, crossing_values, change, prep_fee_zatoshi,
                        total_input_zatoshi, total_migratable_zatoshi, funding_notes, preparation
                   FROM {} WHERE id = ?",
                t.migrations
            ),
            params![SINGLETON_ID],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?;

    let Some((
        status,
        note_fee_buffer,
        crossing_values,
        change,
        prep_fee,
        total_input,
        total_migratable,
        funding_notes,
        preparation,
    )) = row
    else {
        return Ok(None);
    };

    let change = change.map(|c| zatoshis_from_i64(c, "change")).transpose()?;
    let note_split = NoteSplitPlan::from_stored_parts(
        decode_zatoshis(&crossing_values, "crossing_values")?,
        zatoshis_from_i64(note_fee_buffer, "note_fee_buffer")?,
        change,
        zatoshis_from_i64(prep_fee, "prep_fee")?,
        zatoshis_from_i64(total_input, "total_input")?,
        zatoshis_from_i64(total_migratable, "total_migratable")?,
    )
    .map_err(|_| Error::Corrupt("note_split"))?;

    let transactions = read_transactions(conn, t)?;

    let status =
        MigrationStatus::try_from(status.as_str()).map_err(|_| Error::Corrupt("status"))?;
    Ok(Some(MigrationState::from_parts(
        status,
        note_split,
        decode_zatoshis(&funding_notes, "funding_notes")?,
        decode_preparation(&preparation)?,
        transactions,
    )))
}

/// Read the transactions of the single active migration from the table named by `t`.
fn read_transactions(conn: &Connection, t: &Tables) -> Result<Vec<MigrationTransaction>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT tx_id, kind, layer, tx_index, crossing, pczt, depends_on, scheduled_height,
                expiry_height, anchor_boundary, state, txid, mined_height
           FROM {}
          WHERE migration_id = ?
          ORDER BY tx_id",
        t.transactions
    ))?;
    let rows = stmt.query_map(params![SINGLETON_ID], |row| {
        Ok((
            row.get::<_, i64>(0)?,              // tx_id
            row.get::<_, String>(1)?,           // kind
            row.get::<_, Option<i64>>(2)?,      // layer
            row.get::<_, Option<i64>>(3)?,      // tx_index
            row.get::<_, Option<i64>>(4)?,      // crossing
            row.get::<_, Vec<u8>>(5)?,          // pczt
            row.get::<_, Vec<u8>>(6)?,          // depends_on
            row.get::<_, i64>(7)?,              // scheduled_height
            row.get::<_, i64>(8)?,              // expiry_height
            row.get::<_, Option<i64>>(9)?,      // anchor_boundary
            row.get::<_, String>(10)?,          // state
            row.get::<_, Option<Vec<u8>>>(11)?, // txid
            row.get::<_, Option<i64>>(12)?,     // mined_height
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (
            tx_id,
            kind,
            layer,
            tx_index,
            crossing,
            pczt,
            depends_on,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state,
            txid,
            mined_height,
        ) = row?;

        let id = MigrationTxId::new(u32::try_from(tx_id).map_err(|_| Error::Corrupt("tx_id"))?);
        let scheduled_height = BlockHeight::from_u32(
            u32::try_from(scheduled_height).map_err(|_| Error::Corrupt("scheduled_height"))?,
        );
        let expiry_height = BlockHeight::from_u32(
            u32::try_from(expiry_height).map_err(|_| Error::Corrupt("expiry_height"))?,
        );
        let anchor_boundary = anchor_boundary
            .map(|h| {
                u32::try_from(h)
                    .map(BlockHeight::from_u32)
                    .map_err(|_| Error::Corrupt("anchor_boundary"))
            })
            .transpose()?;

        out.push(MigrationTransaction::from_parts(
            id,
            decode_tx_kind(&kind, layer, tx_index, crossing)?,
            pczt,
            decode_dep_ids(&depends_on)?,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            decode_tx_state(&state, txid, mined_height)?,
        ));
    }
    Ok(out)
}

/// Persist `state` as the single active migration in the tables named by `t`, replacing any existing
/// one. Runs inside the caller's transaction so the replacement is atomic.
fn write_migration(
    tx: &rusqlite::Transaction,
    t: &Tables,
    state: &MigrationState,
) -> Result<(), Error> {
    // Replace semantics: the store holds at most one migration.
    tx.execute(
        &format!("DELETE FROM {} WHERE migration_id = ?", t.transactions),
        params![SINGLETON_ID],
    )?;
    tx.execute(
        &format!("DELETE FROM {} WHERE id = ?", t.migrations),
        params![SINGLETON_ID],
    )?;

    let plan = state.note_split();
    tx.execute(
        &format!(
            "INSERT INTO {}
                (id, status, note_fee_buffer_zatoshi, crossing_values, change, prep_fee_zatoshi,
                 total_input_zatoshi, total_migratable_zatoshi, funding_notes, preparation)
             VALUES
                (:id, :status, :note_fee_buffer, :crossing_values, :change, :prep_fee,
                 :total_input, :total_migratable, :funding_notes, :preparation)",
            t.migrations
        ),
        named_params! {
            ":id": SINGLETON_ID,
            ":status": state.status().as_ref(),
            ":note_fee_buffer": plan.note_fee_buffer().into_u64() as i64,
            ":crossing_values": encode_zatoshis(plan.crossing_values()),
            ":change": plan.change().map(|c| c.into_u64() as i64),
            ":prep_fee": plan.prep_fees().into_u64() as i64,
            ":total_input": plan.total_input().into_u64() as i64,
            ":total_migratable": plan.total_migratable().into_u64() as i64,
            ":funding_notes": encode_zatoshis(state.funding_notes()),
            ":preparation": encode_preparation(state.preparation()),
        },
    )?;

    for mtx in state.transactions() {
        let (kind, layer, tx_index, crossing) = encode_tx_kind(mtx.kind());
        let (tx_state, txid, mined_height) = encode_tx_state(&mtx.state());
        tx.execute(
            &format!(
                "INSERT INTO {}
                    (migration_id, tx_id, kind, layer, tx_index, crossing, pczt, depends_on,
                     scheduled_height, expiry_height, anchor_boundary, state, txid, mined_height)
                 VALUES
                    (:migration_id, :tx_id, :kind, :layer, :tx_index, :crossing, :pczt, :depends_on,
                     :scheduled_height, :expiry_height, :anchor_boundary, :state, :txid,
                     :mined_height)",
                t.transactions
            ),
            named_params! {
                ":migration_id": SINGLETON_ID,
                ":tx_id": u32::from(mtx.id()),
                ":kind": kind,
                ":layer": layer,
                ":tx_index": tx_index,
                ":crossing": crossing,
                ":pczt": mtx.pczt().as_slice(),
                ":depends_on": encode_dep_ids(mtx.depends_on()),
                ":scheduled_height": i64::from(u32::from(mtx.scheduled_height())),
                ":expiry_height": i64::from(u32::from(mtx.expiry_height())),
                ":anchor_boundary": mtx.anchor_boundary().map(|h| i64::from(u32::from(h))),
                ":state": tx_state,
                ":txid": txid,
                ":mined_height": mined_height,
            },
        )?;
    }
    Ok(())
}
