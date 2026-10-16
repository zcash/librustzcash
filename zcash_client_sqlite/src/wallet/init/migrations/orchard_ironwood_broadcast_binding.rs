//! Removes the wallet-side transaction records that the former store-at-prove behavior created
//! for migration transactions that were NEVER BROADCAST and whose migration has reached a
//! terminal status.
//!
//! The wallet-side record now binds at broadcast: a proved-but-unbroadcast migration transaction
//! lives only in the migration store, its input notes reserved by an advisory lock rather than by
//! hard spend marks. Records written at prove by earlier releases outlive that change, and for a
//! TERMINAL migration nothing will ever broadcast the transaction, so its marks freeze the input
//! notes out of the user's balance until the transaction's expiry with no possible benefit — the
//! stuck-balance state this whole branch of work exists to remove, including the rows the mobile
//! SDK's hand-rolled cancel (persisting `failed`) left in the field. Records belonging to a
//! PENDING migration are deliberately kept: its transactions are still on their way to broadcast,
//! where the new seam would recreate the record anyway.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_pool_migration::engine::MigrationStatus;

use super::orchard_ironwood_migration_history;
use crate::wallet::init::WalletMigrationError;

/// Identifies this migration in the wallet's schema-migration DAG.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x20091091_c736_4d1a_bd99_7adb16842951);

pub(super) const DEPENDENCIES: &[Uuid] = &[orchard_ironwood_migration_history::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Removes wallet-side transaction records for never-broadcast transactions of terminal \
         pool migrations."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // The target set: wallet `transactions` rows whose txid names a NEVER-BROADCAST
        // transaction of a TERMINAL Orchard -> Ironwood migration. Derived from the migration
        // store's own rows — never from a predicate over the wallet's tables that could match
        // anything else — and joined by txid (the store keeps lowercase hex text; `hex()` yields
        // uppercase, hence the case fold).
        //
        // The lifecycle states named here are the engine's stable wire names. Everything at or
        // past broadcast is EXCLUDED by construction: a broadcast transaction may sit in a
        // mempool, and its record — marks included — describes reality.
        let terminal = MigrationStatus::terminal()
            .map(|s| format!("'{}'", s.wire_name()))
            .collect::<Vec<_>>()
            .join(", ");
        transaction.execute_batch(&format!(
            "CREATE TEMPORARY TABLE tmp_dead_migration_wallet_txs AS
             SELECT t.id_tx AS id_tx, t.txid AS txid
               FROM transactions t
               JOIN orchard_ironwood_migration_transactions mt
                 ON lower(mt.txid) = lower(hex(t.txid))
               JOIN orchard_ironwood_migrations m
                 ON m.id = mt.migration_id
              WHERE mt.state IN ('awaiting_signature', 'signed', 'proved')
                AND m.status IN ({terminal});"
        ))?;

        // Foreign keys are OFF while schema migrations run, so the `ON DELETE CASCADE` these
        // children declare does not fire: everything a deleted transaction created or spent is
        // removed explicitly. Leaving a created output behind would be worse than the freeze
        // being fixed — the wallet would believe it holds notes that exist nowhere on chain —
        // and leaving a spend mark behind is the freeze itself.
        for (table, column) in [
            ("sapling_received_note_spends", "transaction_id"),
            ("orchard_received_note_spends", "transaction_id"),
            ("ironwood_received_note_spends", "transaction_id"),
            ("sapling_received_notes", "transaction_id"),
            ("orchard_received_notes", "transaction_id"),
            ("ironwood_received_notes", "transaction_id"),
            ("sent_notes", "transaction_id"),
        ] {
            transaction.execute(
                &format!(
                    "DELETE FROM {table}
                      WHERE {column} IN (SELECT id_tx FROM tmp_dead_migration_wallet_txs)"
                ),
                [],
            )?;
        }
        // The status-retrieval queue is keyed by txid; a never-broadcast txid must not be asked
        // after (pre-broadcast txid disclosure), and its entry is dead alongside the record.
        transaction.execute(
            "DELETE FROM tx_retrieval_queue
              WHERE txid IN (SELECT txid FROM tmp_dead_migration_wallet_txs)",
            named_params! {},
        )?;
        transaction.execute_batch(
            "DELETE FROM transactions
              WHERE id_tx IN (SELECT id_tx FROM tmp_dead_migration_wallet_txs);
             DROP TABLE tmp_dead_migration_wallet_txs;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// The dependency-state columns this migration TOUCHES, as reduced stand-ins (the full
    /// schema-path equality is `verify_schema`'s job): the wallet's transactions table and the
    /// children it deletes from, plus the migration store's parent and transactions tables.
    fn dependency_state(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL);
             CREATE TABLE sapling_received_note_spends (transaction_id INTEGER NOT NULL);
             CREATE TABLE orchard_received_note_spends (transaction_id INTEGER NOT NULL);
             CREATE TABLE ironwood_received_note_spends (transaction_id INTEGER NOT NULL);
             CREATE TABLE sapling_received_notes (transaction_id INTEGER NOT NULL);
             CREATE TABLE orchard_received_notes (transaction_id INTEGER NOT NULL);
             CREATE TABLE ironwood_received_notes (transaction_id INTEGER NOT NULL);
             CREATE TABLE sent_notes (transaction_id INTEGER NOT NULL);
             CREATE TABLE tx_retrieval_queue (txid BLOB NOT NULL);
             CREATE TABLE orchard_ironwood_migrations (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                status TEXT NOT NULL
             );
             CREATE TABLE orchard_ironwood_migration_transactions (
                migration_id INTEGER NOT NULL,
                transfer_id INTEGER NOT NULL,
                state TEXT NOT NULL,
                txid TEXT
             );",
        )
        .unwrap();
    }

    fn apply(conn: &mut Connection) {
        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();
    }

    fn counts(conn: &Connection) -> (i64, i64, i64, i64) {
        let one = |sql: &str| conn.query_row(sql, [], |r| r.get(0)).unwrap();
        (
            one("SELECT COUNT(*) FROM transactions"),
            one("SELECT COUNT(*) FROM orchard_received_note_spends"),
            one("SELECT COUNT(*) FROM orchard_received_notes"),
            one("SELECT COUNT(*) FROM tx_retrieval_queue"),
        )
    }

    /// Exactly the never-broadcast transactions of TERMINAL migrations lose their wallet-side
    /// records — spends, created outputs, queue entries, and the transaction row itself — while
    /// a pending migration's proved transaction and a terminal migration's BROADCAST transaction
    /// keep theirs untouched.
    #[test]
    fn deletes_only_terminal_never_broadcast_records() {
        let mut conn = Connection::open_in_memory().unwrap();
        dependency_state(&conn);
        // Three wallet transactions: A (proved, terminal migration: the stranded record), B
        // (proved, PENDING migration: kept), C (broadcast, terminal migration: kept — it may be
        // in a mempool). Txids as the store encodes them: lowercase hex of the wallet's blob.
        conn.execute_batch(
            "INSERT INTO transactions (id_tx, txid) VALUES
                (1, X'AA'), (2, X'BB'), (3, X'CC');
             INSERT INTO orchard_received_note_spends (transaction_id) VALUES (1), (2), (3);
             INSERT INTO orchard_received_notes (transaction_id) VALUES (1), (2), (3);
             INSERT INTO sent_notes (transaction_id) VALUES (1), (2), (3);
             INSERT INTO tx_retrieval_queue (txid) VALUES (X'AA'), (X'BB'), (X'CC');
             INSERT INTO orchard_ironwood_migrations (id, account_id, status) VALUES
                (10, 1, 'cancelled'), (11, 2, 'committed');
             INSERT INTO orchard_ironwood_migration_transactions
                (migration_id, transfer_id, state, txid) VALUES
                (10, 0, 'proved', 'aa'),
                (11, 0, 'proved', 'bb'),
                (10, 1, 'broadcast', 'cc');",
        )
        .unwrap();

        apply(&mut conn);

        assert_eq!(
            counts(&conn),
            (2, 2, 2, 2),
            "one stranded record removed, its two neighbors intact"
        );
        let survivors: Vec<i64> = conn
            .prepare("SELECT id_tx FROM transactions ORDER BY id_tx")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            survivors,
            vec![2, 3],
            "the pending migration's and the broadcast transaction's records survive"
        );
    }
}
