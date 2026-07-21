//! The generic, pool-agnostic SQLite pool-migration store.
//!
//! This module is entirely crate-internal: it holds the machinery shared by every pool migration
//! (the DDL builders and the [`Store`] type that carries the [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] SQL logic), parameterized over the table names in [`Tables`]. The schema is
//! fully NORMALIZED: every structured value is stored in typed columns and child-table rows, so the
//! store maps the engine types to and from columns directly. The only `BLOB` column is the pre-signed
//! transaction (`pczt`), which is genuinely unstructured, already-versioned bytes. All amounts are
//! zatoshi `INTEGER` columns; the broadcast `txid` is stored as hex `TEXT`.
//!
//! The preparation plan's layers/transactions grid has no tables of its own: each input and output
//! row carries its transaction's `(layer, tx_index)` coordinate, and every transaction a real plan
//! produces has at least one input and one output (and no layer is empty), so the store
//! reconstructs the grid from those rows (and rejects a state it could not reconstruct with
//! [`Error::Unrepresentable`]). Likewise the funding-note values have no table: the engine derives
//! them from the note split (each crossing value plus the fee buffer).
//!
//! The column set is the same for every pool; only the table and index names change.
//!
//! [`PoolMigrationRead`]: zcash_pool_migration_backend::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration_backend::engine::PoolMigrationWrite

use std::borrow::{Borrow, BorrowMut};

use rusqlite::{Connection, OptionalExtension, named_params, params};

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
    MigrationTxState,
};
use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
use zcash_pool_migration_backend::preparation::{
    PrepInput, PrepOutput, PrepTransaction, PreparationPlan,
};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use super::error::Error;

/// The per-pool table and index names a [`Store`] operates over. A concrete migration submodule
/// supplies a `'static` value of this for its own pool; the generic store interpolates these into
/// every DDL and query, so one implementation serves every pool.
pub(crate) struct Tables {
    /// The migration-state table (one singleton row; holds the note-split scalars).
    pub migrations: &'static str,
    /// The note-split crossing values (an ordered list).
    pub crossing_values: &'static str,
    /// The inputs of each preparation transaction, keyed by the transaction's `(layer, tx_index)`
    /// grid coordinate.
    pub prep_inputs: &'static str,
    /// The outputs of each preparation transaction, keyed like the inputs.
    pub prep_outputs: &'static str,
    /// The preparation plan's direct-funding wallet notes (an ordered list).
    pub prep_direct_funding: &'static str,
    /// The per-migration-transaction table.
    pub transactions: &'static str,
    /// The dependency edges between migration transactions.
    pub transaction_deps: &'static str,
    /// The index over `(state, scheduled_height)` on the transactions table.
    pub tx_due_index: &'static str,
}

/// The primary-key value of the single active migration. There is at most one migration in progress,
/// so it is stored as one row; a future multi-account model would replace this with an account key.
pub(crate) const SINGLETON_ID: i64 = 0;

// ---------------------------------------------------------------------------
// DDL
// ---------------------------------------------------------------------------

fn create_migrations_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            note_split_fee_buffer INTEGER NOT NULL,
            note_split_change INTEGER,
            note_split_prep_fees INTEGER NOT NULL,
            note_split_total_input INTEGER NOT NULL,
            note_split_total_migratable INTEGER NOT NULL
        )",
        t.migrations
    )
}

fn create_crossing_values_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        )",
        t.crossing_values, t.migrations
    )
}

fn create_prep_inputs_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            source TEXT NOT NULL,
            wallet_index INTEGER,
            prior_layer INTEGER,
            prior_transaction INTEGER,
            prior_output INTEGER,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        )",
        t.prep_inputs, t.migrations
    )
}

fn create_prep_outputs_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            role TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        )",
        t.prep_outputs, t.migrations
    )
}

fn create_prep_direct_funding_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            wallet_index INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        )",
        t.prep_direct_funding, t.migrations
    )
}

fn create_transactions_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            tx_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            kind_layer INTEGER,
            kind_index INTEGER,
            kind_crossing INTEGER,
            pczt BLOB NOT NULL,
            scheduled_height INTEGER NOT NULL,
            expiry_height INTEGER NOT NULL,
            anchor_boundary INTEGER,
            state TEXT NOT NULL,
            txid TEXT,
            mined_height INTEGER,
            PRIMARY KEY (migration_id, tx_id)
        )",
        t.transactions, t.migrations
    )
}

fn create_transaction_deps_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL,
            tx_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            depends_on_tx_id INTEGER NOT NULL,
            PRIMARY KEY (migration_id, tx_id, ordinal),
            FOREIGN KEY (migration_id, tx_id)
                REFERENCES {}(migration_id, tx_id) ON DELETE CASCADE
        )",
        t.transaction_deps, t.transactions
    )
}

fn create_tx_due_index_sql(t: &Tables) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (state, scheduled_height)",
        t.tx_due_index, t.transactions
    )
}

/// Create the pool-migration tables (and the due-transaction index) named by `t` on `conn`. This is
/// the body the pool's schema migration's `up()` calls; it is idempotent (`IF NOT EXISTS`). Tables
/// are created in dependency order so each foreign-key target exists first.
pub(crate) fn init(conn: &Connection, t: &Tables) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "{};\n{};\n{};\n{};\n{};\n{};\n{};\n{};",
        create_migrations_sql(t),
        create_crossing_values_sql(t),
        create_prep_inputs_sql(t),
        create_prep_outputs_sql(t),
        create_prep_direct_funding_sql(t),
        create_transactions_sql(t),
        create_transaction_deps_sql(t),
        create_tx_due_index_sql(t),
    ))
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

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
    pub(crate) fn new(conn: C, tables: &'static Tables) -> Self {
        Self { conn, tables }
    }

    pub(crate) fn into_inner(self) -> C {
        self.conn
    }
}

impl<C: Borrow<Connection>> Store<C> {
    pub(crate) fn get_migration(&self) -> Result<Option<MigrationState>, Error> {
        read_migration(self.conn.borrow(), self.tables)
    }
}

impl<C: BorrowMut<Connection>> Store<C> {
    pub(crate) fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Error> {
        let tables = self.tables;
        let tx = self.conn.borrow_mut().transaction()?;
        replace_migration(&tx, tables, state)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Error> {
        let updated = self.conn.borrow_mut().execute(
            &format!(
                "UPDATE {}
                    SET state = :state, txid = :txid, mined_height = :mined_height
                  WHERE migration_id = :migration_id AND tx_id = :tx_id",
                self.tables.transactions
            ),
            named_params! {
                ":state": state.as_ref(),
                ":txid": state.broadcast_txid().map(hex::encode),
                ":mined_height": state.mined_height().map(u32::from),
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

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

fn read_migration(conn: &Connection, t: &Tables) -> Result<Option<MigrationState>, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT status, note_split_fee_buffer, note_split_change, note_split_prep_fees,
                        note_split_total_input, note_split_total_migratable
                   FROM {} WHERE id = ?",
                t.migrations
            ),
            params![SINGLETON_ID],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                ))
            },
        )
        .optional()?;

    let Some((status, fee_buffer, change, prep_fees, total_input, total_migratable)) = row else {
        return Ok(None);
    };

    let crossing_values = read_zatoshi_list(conn, t.crossing_values)?;
    let note_split = NoteSplitPlan::from_stored_parts(
        crossing_values,
        Zatoshis::from_u64(fee_buffer)?,
        change.map(Zatoshis::from_u64).transpose()?,
        Zatoshis::from_u64(prep_fees)?,
        Zatoshis::from_u64(total_input)?,
        Zatoshis::from_u64(total_migratable)?,
    )
    .map_err(|_| Error::Corrupt("note_split"))?;

    let preparation = read_preparation(conn, t)?;
    let transactions = read_transactions(conn, t)?;

    let status =
        MigrationStatus::try_from(status.as_str()).map_err(|_| Error::Corrupt("status"))?;
    Ok(Some(MigrationState::from_parts(
        status,
        note_split,
        preparation,
        transactions,
    )))
}

/// Read an ordered list of zatoshi amounts (`ordinal`, `value`) from a child table.
fn read_zatoshi_list(conn: &Connection, table: &str) -> Result<Vec<Zatoshis>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT value FROM {table} WHERE migration_id = ? ORDER BY ordinal"
    ))?;
    let rows = stmt.query_map(params![SINGLETON_ID], |row| row.get::<_, u64>(0))?;
    let mut out = Vec::new();
    for v in rows {
        out.push(Zatoshis::from_u64(v?)?);
    }
    Ok(out)
}

fn read_preparation(conn: &Connection, t: &Tables) -> Result<PreparationPlan, Error> {
    // The layers/transactions grid, reconstructed from the input and output rows: every transaction
    // has at least one such row (the write side rejects a state where one does not), so the distinct
    // `(layer, tx_index)` coordinates enumerate the full grid in order.
    let coords: Vec<(usize, usize)> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT layer, tx_index FROM {} WHERE migration_id = :id
             UNION
             SELECT layer, tx_index FROM {} WHERE migration_id = :id
             ORDER BY layer, tx_index",
            t.prep_inputs, t.prep_outputs
        ))?;
        let rows = stmt.query_map(named_params! { ":id": SINGLETON_ID }, |row| {
            Ok((
                row.get::<_, u64>(0)? as usize,
                row.get::<_, u64>(1)? as usize,
            ))
        })?;
        rows.collect::<Result<_, _>>()?
    };
    let mut layers: Vec<Vec<PrepTransaction>> = Vec::new();
    for (layer, tx_index) in coords {
        // Both indices must be contiguous from zero: a gap means a layer or transaction left no
        // rows, and silently renumbering would misdirect later layers' prior-output references.
        if layer == layers.len() && tx_index == 0 {
            layers.push(Vec::new());
        } else if !(layer + 1 == layers.len() && tx_index == layers[layer].len()) {
            return Err(Error::Corrupt(
                "preparation grid: non-contiguous coordinates",
            ));
        }
        let inputs = read_prep_inputs(conn, t, layer, tx_index)?;
        let outputs = read_prep_outputs(conn, t, layer, tx_index)?;
        layers[layer].push(PrepTransaction::from_parts(inputs, outputs));
    }

    let direct_funding = {
        let mut stmt = conn.prepare(&format!(
            "SELECT wallet_index, value FROM {} WHERE migration_id = ? ORDER BY ordinal",
            t.prep_direct_funding
        ))?;
        let rows = stmt.query_map(params![SINGLETON_ID], |row| {
            Ok((row.get::<_, u64>(0)? as usize, row.get::<_, u64>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (idx, value) = r?;
            out.push((idx, Zatoshis::from_u64(value)?));
        }
        out
    };

    Ok(PreparationPlan::from_parts(layers, direct_funding))
}

fn read_prep_inputs(
    conn: &Connection,
    t: &Tables,
    layer: usize,
    tx_index: usize,
) -> Result<Vec<PrepInput>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT source, wallet_index, prior_layer, prior_transaction, prior_output, value
           FROM {}
          WHERE migration_id = ? AND layer = ? AND tx_index = ?
          ORDER BY ordinal",
        t.prep_inputs
    ))?;
    let rows = stmt.query_map(
        params![SINGLETON_ID, layer as u64, tx_index as u64],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<u64>>(1)?,
                row.get::<_, Option<u64>>(2)?,
                row.get::<_, Option<u64>>(3)?,
                row.get::<_, Option<u64>>(4)?,
                row.get::<_, u64>(5)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for r in rows {
        let (source, wallet_index, prior_layer, prior_transaction, prior_output, value) = r?;
        let value = Zatoshis::from_u64(value)?;
        let input = match source.as_str() {
            "wallet" => PrepInput::Wallet {
                index: wallet_index.ok_or(Error::Corrupt("prep_input.wallet_index"))? as usize,
                value,
            },
            "prior" => PrepInput::Prior {
                layer: prior_layer.ok_or(Error::Corrupt("prep_input.prior_layer"))? as usize,
                transaction: prior_transaction
                    .ok_or(Error::Corrupt("prep_input.prior_transaction"))?
                    as usize,
                output: prior_output.ok_or(Error::Corrupt("prep_input.prior_output"))? as usize,
                value,
            },
            _ => return Err(Error::Corrupt("prep_input.source")),
        };
        out.push(input);
    }
    Ok(out)
}

fn read_prep_outputs(
    conn: &Connection,
    t: &Tables,
    layer: usize,
    tx_index: usize,
) -> Result<Vec<PrepOutput>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT role, value FROM {}
          WHERE migration_id = ? AND layer = ? AND tx_index = ?
          ORDER BY ordinal",
        t.prep_outputs
    ))?;
    let rows = stmt.query_map(
        params![SINGLETON_ID, layer as u64, tx_index as u64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
    )?;
    let mut out = Vec::new();
    for r in rows {
        let (role, value) = r?;
        let value = Zatoshis::from_u64(value)?;
        let output =
            PrepOutput::from_role(&role, value).map_err(|_| Error::Corrupt("prep_output.role"))?;
        out.push(output);
    }
    Ok(out)
}

fn read_transactions(conn: &Connection, t: &Tables) -> Result<Vec<MigrationTransaction>, Error> {
    let rows: Vec<TxRow> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT tx_id, kind, kind_layer, kind_index, kind_crossing, pczt,
                    scheduled_height, expiry_height, anchor_boundary, state, txid, mined_height
               FROM {}
              WHERE migration_id = ?
              ORDER BY tx_id",
            t.transactions
        ))?;
        let mapped = stmt.query_map(params![SINGLETON_ID], |row| {
            Ok(TxRow {
                tx_id: row.get(0)?,
                kind: row.get(1)?,
                kind_layer: row.get(2)?,
                kind_index: row.get(3)?,
                kind_crossing: row.get(4)?,
                pczt: row.get(5)?,
                scheduled_height: row.get(6)?,
                expiry_height: row.get(7)?,
                anchor_boundary: row.get(8)?,
                state: row.get(9)?,
                txid: row.get(10)?,
                mined_height: row.get(11)?,
            })
        })?;
        mapped.collect::<Result<_, _>>()?
    };

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id = MigrationTxId::new(r.tx_id);
        let kind = MigrationTxKind::from_stored(
            &r.kind,
            r.kind_layer.map(|x| x as usize),
            r.kind_index.map(|x| x as usize),
            r.kind_crossing.map(|x| x as usize),
        )
        .map_err(|_| Error::Corrupt("kind"))?;
        let txid = r
            .txid
            .map(|s| {
                hex::decode(&s)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v).ok())
                    .ok_or(Error::Corrupt("state.txid"))
            })
            .transpose()?;
        let state = MigrationTxState::from_stored(
            &r.state,
            txid,
            r.mined_height.map(BlockHeight::from_u32),
        )
        .map_err(|_| Error::Corrupt("state"))?;
        let depends_on = read_deps(conn, t, r.tx_id)?;

        out.push(MigrationTransaction::from_parts(
            id,
            kind,
            r.pczt,
            depends_on,
            BlockHeight::from_u32(r.scheduled_height),
            BlockHeight::from_u32(r.expiry_height),
            r.anchor_boundary.map(BlockHeight::from_u32),
            state,
        ));
    }
    Ok(out)
}

/// One row of the transactions table, before it is decoded into a [`MigrationTransaction`].
struct TxRow {
    tx_id: u32,
    kind: String,
    kind_layer: Option<u64>,
    kind_index: Option<u64>,
    kind_crossing: Option<u64>,
    pczt: Vec<u8>,
    scheduled_height: u32,
    expiry_height: u32,
    anchor_boundary: Option<u32>,
    state: String,
    txid: Option<String>,
    mined_height: Option<u32>,
}

fn read_deps(conn: &Connection, t: &Tables, tx_id: u32) -> Result<Vec<MigrationTxId>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT depends_on_tx_id FROM {}
          WHERE migration_id = ? AND tx_id = ?
          ORDER BY ordinal",
        t.transaction_deps
    ))?;
    let rows = stmt.query_map(params![SINGLETON_ID, tx_id], |row| row.get::<_, u32>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(MigrationTxId::new(r?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Replace the single active migration in the tables named by `t` with `state` (deletes any existing
/// migration and its children first). Runs inside the caller's transaction so the replacement is
/// atomic.
fn replace_migration(
    tx: &rusqlite::Transaction,
    t: &Tables,
    state: &MigrationState,
) -> Result<(), Error> {
    // The layers/transactions grid is stored only through the input and output rows, so a layer
    // with no transactions, or a transaction with neither inputs nor outputs, would leave no trace
    // and read back with later coordinates silently renumbered — misdirecting prior-output
    // references. A plan the engine produced never contains these; reject rather than corrupt.
    for transactions in state.preparation().layers() {
        if transactions.is_empty() {
            return Err(Error::Unrepresentable("empty preparation layer"));
        }
        for prep_tx in transactions {
            if prep_tx.inputs().is_empty() && prep_tx.outputs().is_empty() {
                return Err(Error::Unrepresentable(
                    "preparation transaction with no inputs or outputs",
                ));
            }
        }
    }

    // Replace semantics: the store holds at most one migration. Delete children first (in case
    // foreign-key cascades are not enabled), then the singleton row.
    for table in [
        t.transaction_deps,
        t.transactions,
        t.prep_inputs,
        t.prep_outputs,
        t.prep_direct_funding,
        t.crossing_values,
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE migration_id = ?"),
            params![SINGLETON_ID],
        )?;
    }
    tx.execute(
        &format!("DELETE FROM {} WHERE id = ?", t.migrations),
        params![SINGLETON_ID],
    )?;

    let ns = state.note_split();
    tx.execute(
        &format!(
            "INSERT INTO {} (id, status, note_split_fee_buffer, note_split_change,
                             note_split_prep_fees, note_split_total_input, note_split_total_migratable)
             VALUES (:id, :status, :fee_buffer, :change, :prep_fees, :total_input, :total_migratable)",
            t.migrations
        ),
        named_params! {
            ":id": SINGLETON_ID,
            ":status": state.status().as_ref(),
            ":fee_buffer": ns.note_fee_buffer().into_u64(),
            ":change": ns.change().map(Zatoshis::into_u64),
            ":prep_fees": ns.prep_fees().into_u64(),
            ":total_input": ns.total_input().into_u64(),
            ":total_migratable": ns.total_migratable().into_u64(),
        },
    )?;

    insert_zatoshi_list(tx, t.crossing_values, ns.crossing_values())?;

    let prep = state.preparation();
    for (layer, transactions) in prep.layers().iter().enumerate() {
        for (tx_index, prep_tx) in transactions.iter().enumerate() {
            for (ordinal, input) in prep_tx.inputs().iter().enumerate() {
                let (source, wallet_index, prior_layer, prior_transaction, prior_output) =
                    match input {
                        PrepInput::Wallet { index, .. } => {
                            ("wallet", Some(*index as u64), None, None, None)
                        }
                        PrepInput::Prior {
                            layer,
                            transaction,
                            output,
                            ..
                        } => (
                            "prior",
                            None,
                            Some(*layer as u64),
                            Some(*transaction as u64),
                            Some(*output as u64),
                        ),
                    };
                tx.execute(
                    &format!(
                        "INSERT INTO {} (migration_id, layer, tx_index, ordinal, source,
                                         wallet_index, prior_layer, prior_transaction, prior_output, value)
                         VALUES (:migration_id, :layer, :tx_index, :ordinal, :source,
                                 :wallet_index, :prior_layer, :prior_transaction, :prior_output, :value)",
                        t.prep_inputs
                    ),
                    named_params! {
                        ":migration_id": SINGLETON_ID,
                        ":layer": layer as u64,
                        ":tx_index": tx_index as u64,
                        ":ordinal": ordinal as u64,
                        ":source": source,
                        ":wallet_index": wallet_index,
                        ":prior_layer": prior_layer,
                        ":prior_transaction": prior_transaction,
                        ":prior_output": prior_output,
                        ":value": input.value().into_u64(),
                    },
                )?;
            }
            for (ordinal, output) in prep_tx.outputs().iter().enumerate() {
                tx.execute(
                    &format!(
                        "INSERT INTO {} (migration_id, layer, tx_index, ordinal, role, value)
                         VALUES (:migration_id, :layer, :tx_index, :ordinal, :role, :value)",
                        t.prep_outputs
                    ),
                    named_params! {
                        ":migration_id": SINGLETON_ID,
                        ":layer": layer as u64,
                        ":tx_index": tx_index as u64,
                        ":ordinal": ordinal as u64,
                        ":role": output.as_ref(),
                        ":value": output.value().into_u64(),
                    },
                )?;
            }
        }
    }
    for (ordinal, (wallet_index, value)) in prep.direct_funding_notes().iter().enumerate() {
        tx.execute(
            &format!(
                "INSERT INTO {} (migration_id, ordinal, wallet_index, value)
                 VALUES (:migration_id, :ordinal, :wallet_index, :value)",
                t.prep_direct_funding
            ),
            named_params! {
                ":migration_id": SINGLETON_ID,
                ":ordinal": ordinal as u64,
                ":wallet_index": *wallet_index as u64,
                ":value": (*value).into_u64(),
            },
        )?;
    }

    for mtx in state.transactions() {
        let kind = mtx.kind();
        let (kind_layer, kind_index) = kind
            .preparation_indices()
            .map_or((None, None), |(l, i)| (Some(l as u64), Some(i as u64)));
        let kind_crossing = kind.transfer_crossing().map(|c| c as u64);
        let tx_state = mtx.state();
        tx.execute(
            &format!(
                "INSERT INTO {} (migration_id, tx_id, kind, kind_layer, kind_index, kind_crossing,
                                 pczt, scheduled_height, expiry_height, anchor_boundary, state, txid,
                                 mined_height)
                 VALUES (:migration_id, :tx_id, :kind, :kind_layer, :kind_index, :kind_crossing,
                         :pczt, :scheduled_height, :expiry_height, :anchor_boundary, :state, :txid,
                         :mined_height)",
                t.transactions
            ),
            named_params! {
                ":migration_id": SINGLETON_ID,
                ":tx_id": u32::from(mtx.id()),
                ":kind": kind.as_ref(),
                ":kind_layer": kind_layer,
                ":kind_index": kind_index,
                ":kind_crossing": kind_crossing,
                ":pczt": mtx.pczt().as_slice(),
                ":scheduled_height": u32::from(mtx.scheduled_height()),
                ":expiry_height": u32::from(mtx.expiry_height()),
                ":anchor_boundary": mtx.anchor_boundary().map(u32::from),
                ":state": tx_state.as_ref(),
                ":txid": tx_state.broadcast_txid().map(hex::encode),
                ":mined_height": tx_state.mined_height().map(u32::from),
            },
        )?;
        for (ordinal, dep) in mtx.depends_on().iter().enumerate() {
            tx.execute(
                &format!(
                    "INSERT INTO {} (migration_id, tx_id, ordinal, depends_on_tx_id)
                     VALUES (:migration_id, :tx_id, :ordinal, :depends_on_tx_id)",
                    t.transaction_deps
                ),
                named_params! {
                    ":migration_id": SINGLETON_ID,
                    ":tx_id": u32::from(mtx.id()),
                    ":ordinal": ordinal as u64,
                    ":depends_on_tx_id": u32::from(*dep),
                },
            )?;
        }
    }
    Ok(())
}

/// Insert an ordered list of zatoshi amounts as `(ordinal, value)` rows into a child table.
fn insert_zatoshi_list(
    tx: &rusqlite::Transaction,
    table: &str,
    values: &[Zatoshis],
) -> Result<(), Error> {
    for (ordinal, value) in values.iter().enumerate() {
        tx.execute(
            &format!(
                "INSERT INTO {table} (migration_id, ordinal, value)
                 VALUES (:migration_id, :ordinal, :value)"
            ),
            named_params! {
                ":migration_id": SINGLETON_ID,
                ":ordinal": ordinal as u64,
                ":value": (*value).into_u64(),
            },
        )?;
    }
    Ok(())
}
