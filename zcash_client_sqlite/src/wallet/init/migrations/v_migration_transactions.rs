//! Adds two views over the pool-migration store's transactions:
//!
//! - `v_migration_transactions`: one row per SCHEDULED migration transaction (belonging to a
//!   non-terminal migration and not yet broadcast), with its identity, kind, lifecycle state,
//!   schedule, and values projected from the store's typed columns.
//! - `v_transactions_with_pending_migrations`: `v_transactions` plus those scheduled
//!   transactions projected into the same column shape, for a consumer that wants one merged
//!   activity feed. `v_transactions` itself is unchanged.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::{orchard_ironwood_migration_txid_blob, v_transactions_zip318_kind};
use crate::wallet::init::WalletMigrationError;

/// Identifies this migration in the wallet's schema-migration DAG.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x1060fd09_1dc8_4208_b368_295d297eb045);

pub(super) const DEPENDENCIES: &[Uuid] = &[
    orchard_ironwood_migration_txid_blob::MIGRATION_ID,
    v_transactions_zip318_kind::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds views exposing scheduled pool-migration transactions."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(&format!(
            "{};\n{};",
            crate::pool_migration::orchard_ironwood::migration_tx_view_sql(),
            crate::wallet::db::VIEW_TRANSACTIONS_WITH_PENDING_MIGRATIONS,
        ))?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_transactions_with_pending_migrations;
             DROP VIEW v_migration_transactions;",
        )?;
        Ok(())
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

    /// A reduced stand-in for the tables the views read (full schema-path equality is
    /// `verify_schema`'s job), populated with one of everything the row-set predicate
    /// distinguishes.
    fn fixture(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE accounts (id INTEGER PRIMARY KEY, uuid BLOB NOT NULL);
             CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL);
             CREATE TABLE blocks (height INTEGER PRIMARY KEY);
             INSERT INTO accounts (id, uuid) VALUES (1, X'11');",
        )
        .unwrap();
        crate::pool_migration::orchard_ironwood::init_migration_tables(conn).unwrap();
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations
                (id, account_id, status, note_split_fee_buffer, note_split_change,
                 note_split_prep_fees, note_split_total_input, note_split_total_migratable,
                 uuid)
             VALUES (10, 1, 'in_progress', 15000, NULL, 30000, 500000, 400000, X'AA'),
                    (11, 1, 'cancelled',   15000, NULL, 30000, 500000, 400000, X'BB');
             INSERT INTO orchard_ironwood_migration_crossing_values
                (migration_id, ordinal, value) VALUES (10, 0, 100000), (11, 0, 100000);
             INSERT INTO orchard_ironwood_migration_prep_inputs
                (migration_id, layer, tx_index, ordinal, source, value)
             VALUES (10, 0, 0, 0, 'wallet', 300000), (10, 0, 0, 1, 'wallet', 200000);
             INSERT INTO orchard_ironwood_migration_prep_outputs
                (migration_id, layer, tx_index, ordinal, role, value)
             VALUES (10, 0, 0, 0, 'funding', 115000), (10, 0, 0, 1, 'intermediate', 200000),
                    (10, 0, 0, 2, 'change', 155000);
             INSERT INTO orchard_ironwood_migration_transactions
                (migration_id, transfer_id, kind, kind_layer, kind_index, kind_crossing, pczt,
                 scheduled_height, expiry_height, state, txid)
             VALUES
                -- A signed preparation of the pending migration: scheduled.
                (10, 0, 'preparation', 0, 0, NULL, X'01', 1000, 40000, 'signed',    X'A0'),
                -- A proved transfer of the pending migration: scheduled.
                (10, 1, 'transfer', NULL, NULL, 0,   X'02', 1100, 40000, 'proved',  X'A1'),
                -- Broadcast: it lives in the wallet's transactions table, not here.
                (10, 2, 'transfer', NULL, NULL, 0,   X'03', 1200, 40000, 'broadcast', X'A2'),
                -- A proved transfer whose parent is TERMINAL: neither history nor pending.
                (11, 0, 'transfer', NULL, NULL, 0,   X'04', 1300, 40000, 'proved',  X'A3'),
                -- Proved, pending parent, but already recorded in the wallet (a legacy
                -- prove-stored row): the wallet's row wins.
                (10, 3, 'transfer', NULL, NULL, 0,   X'05', 1400, 40000, 'proved',  X'A4');
             INSERT INTO transactions (id_tx, txid) VALUES (1, X'A2'), (2, X'A4');
             INSERT INTO blocks (height) VALUES (500);",
        )
        .unwrap();
    }

    /// The dedicated view exposes exactly the scheduled transactions — pending parent, not yet
    /// broadcast, not already in the wallet's tables — with values projected per kind: a
    /// preparation's fee is inputs minus outputs, a transfer's is the per-note fee buffer (the
    /// canonical transfer's ZIP-317 fee), and the crossing value is the transfer's
    /// pool-crossing value.
    #[test]
    fn scheduled_rows_and_values() {
        let mut conn = Connection::open_in_memory().unwrap();
        fixture(&conn);
        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        type Row = (
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            Option<i64>,
            i64,
            i64,
            i64,
            i64,
        );
        let rows: Vec<Row> = conn
            .prepare(
                "SELECT kind, state, scheduled_height, value_spent, value_received, fee,
                        pool_crossing_value, spent_note_count, received_note_count, has_change,
                        zip318_kind
                   FROM v_migration_transactions ORDER BY scheduled_height",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(
            rows,
            vec![
                // The preparation: 500_000 in, 470_000 out (fee 30_000), one change output.
                (
                    "preparation".into(),
                    "signed".into(),
                    1000,
                    500_000,
                    470_000,
                    30_000,
                    None,
                    2,
                    2,
                    1,
                    2
                ),
                // The transfer: crossing 100_000 plus the 15_000 buffer spent; fee = buffer.
                (
                    "transfer".into(),
                    "proved".into(),
                    1100,
                    115_000,
                    100_000,
                    15_000,
                    Some(100_000),
                    1,
                    1,
                    0,
                    3
                ),
            ],
            "broadcast, terminal-parent, and wallet-recorded rows are excluded"
        );
    }

    /// The union view carries every `v_transactions` column: scheduled rows project into the
    /// common shape (no mined height, no raw bytes, balance delta = -fee) and sit beside the
    /// wallet's own rows without touching `v_transactions` itself.
    #[test]
    fn union_view_projects_the_common_shape() {
        let mut conn = Connection::open_in_memory().unwrap();
        fixture(&conn);
        // The union's first arm reads v_transactions; a reduced stand-in view over the fixture
        // table keeps this test about the PROJECTION, not about v_transactions' own body.
        conn.execute_batch(
            "CREATE VIEW v_transactions AS
             SELECT X'11' AS account_uuid, 500 AS mined_height, txid, 0 AS tx_index,
                    40000 AS expiry_height, X'00' AS raw, -1000 AS account_balance_delta,
                    2000 AS total_spent, 1000 AS total_received, 1000 AS fee_paid,
                    0 AS has_change, 1 AS sent_note_count, 1 AS received_note_count,
                    0 AS memo_count, 123 AS block_time, 0 AS expired_unmined,
                    1 AS spent_note_count, 0 AS is_shielding, NULL AS pool_crossing_value,
                    NULL AS trust_status, 0 AS zip318_kind
             FROM transactions;",
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        let rows: Vec<(Option<i64>, i64, Option<i64>, i64)> = conn
            .prepare(
                "SELECT mined_height, account_balance_delta, fee_paid, zip318_kind
                   FROM v_transactions_with_pending_migrations
                  ORDER BY mined_height IS NULL, account_balance_delta",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(
            rows,
            vec![
                // The wallet's own two rows...
                (Some(500), -1000, Some(1000), 0),
                (Some(500), -1000, Some(1000), 0),
                // ...then the scheduled preparation and transfer, deltas of minus their fees.
                (None, -30_000, Some(30_000), 2),
                (None, -15_000, Some(15_000), 3),
            ]
        );
    }
}
