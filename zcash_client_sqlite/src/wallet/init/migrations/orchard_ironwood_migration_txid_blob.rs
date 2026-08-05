//! Converts `orchard_ironwood_migration_transactions.txid` from hex `TEXT` to a raw-byte `BLOB`,
//! matching the wallet's own `transactions.txid` so the two can be compared and joined directly.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::TxId;

use super::orchard_ironwood_broadcast_binding;
use crate::wallet::init::WalletMigrationError;

/// Identifies this migration in the wallet's schema-migration DAG.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x62ccc269_f988_4bb2_8958_2cbaaa44dea3);

pub(super) const DEPENDENCIES: &[Uuid] = &[orchard_ironwood_broadcast_binding::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Stores pool-migration transaction ids as raw bytes rather than hex text."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // SQLite cannot change a column's declared type, so the table is rebuilt: rename aside,
        // create the current shape, copy rows across converting `txid`, drop the old table, and
        // recreate the index it carried. The rename runs under `legacy_alter_table` so the child
        // tables' foreign-key clauses keep naming `orchard_ironwood_migration_transactions` (the
        // replacement) rather than being rewritten to follow the doomed `_old` table.
        //
        // The conversion inverts the store's own HISTORICAL text encoding, which was
        // `hex::encode(TxId::as_ref())` — the id's INTERNAL bytes — at both of the sites that
        // ever wrote this column (`replace_migration` and the `..._unsatisfiability` repair).
        // That encoding is byte-reversed relative to the id's canonical display form, so
        // `TxId::from_hex` (the `Display` inverse) must NOT be used here: it would write reversed
        // blobs and silently break every txid join for migrated rows. The test below pins the
        // direction with an asymmetric byte pattern.
        transaction.execute_batch(&format!(
            "PRAGMA legacy_alter_table = ON;
             ALTER TABLE orchard_ironwood_migration_transactions
                RENAME TO orchard_ironwood_migration_transactions_old;
             PRAGMA legacy_alter_table = OFF;
             {};",
            crate::pool_migration::orchard_ironwood::transactions_table_sql(),
        ))?;

        {
            let mut read = transaction.prepare(
                "SELECT migration_id, transfer_id, kind, kind_layer, kind_index, kind_crossing,
                        pczt, scheduled_height, expiry_height, anchor_boundary, state, txid,
                        mined_height, lock_owner, unsatisfiable_at, unsatisfiable_kind,
                        broadcast_failure_at
                   FROM orchard_ironwood_migration_transactions_old",
            )?;
            let mut write = transaction.prepare(
                "INSERT INTO orchard_ironwood_migration_transactions (
                        migration_id, transfer_id, kind, kind_layer, kind_index, kind_crossing,
                        pczt, scheduled_height, expiry_height, anchor_boundary, state, txid,
                        mined_height, lock_owner, unsatisfiable_at, unsatisfiable_kind,
                        broadcast_failure_at)
                 VALUES (:migration_id, :transfer_id, :kind, :kind_layer, :kind_index,
                         :kind_crossing, :pczt, :scheduled_height, :expiry_height,
                         :anchor_boundary, :state, :txid, :mined_height, :lock_owner,
                         :unsatisfiable_at, :unsatisfiable_kind, :broadcast_failure_at)",
            )?;
            let mut rows = read.query([])?;
            while let Some(row) = rows.next()? {
                let txid: Option<[u8; 32]> = row
                    .get::<_, Option<String>>(11)?
                    .map(|s| {
                        // All previous encodings of the txid as hex wrote incorrect hexadecimal
                        // representations instead of the canonical, byte-reversed form.
                        // This decoding and storing as BLOB fixes that error.
                        hex::decode(&s)
                            .ok()
                            .and_then(|v| <[u8; 32]>::try_from(v).ok())
                            .ok_or(WalletMigrationError::CorruptedData(
                                "pool-migration txid is not 32 bytes of hex".into(),
                            ))
                    })
                    .transpose()?
                    .map(|bytes| *TxId::from_bytes(bytes).as_ref());
                let preserve = |idx: usize| row.get::<_, rusqlite::types::Value>(idx);
                write.execute(named_params! {
                    ":migration_id": preserve(0)?,
                    ":transfer_id": preserve(1)?,
                    ":kind": preserve(2)?,
                    ":kind_layer": preserve(3)?,
                    ":kind_index": preserve(4)?,
                    ":kind_crossing": preserve(5)?,
                    ":pczt": preserve(6)?,
                    ":scheduled_height": preserve(7)?,
                    ":expiry_height": preserve(8)?,
                    ":anchor_boundary": preserve(9)?,
                    ":state": preserve(10)?,
                    ":txid": txid,
                    ":mined_height": preserve(12)?,
                    ":lock_owner": preserve(13)?,
                    ":unsatisfiable_at": preserve(14)?,
                    ":unsatisfiable_kind": preserve(15)?,
                    ":broadcast_failure_at": preserve(16)?,
                })?;
            }
        }

        transaction.execute_batch(&format!(
            "DROP TABLE orchard_ironwood_migration_transactions_old;
             {};",
            crate::pool_migration::orchard_ironwood::tx_due_index_sql(),
        ))?;

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

    /// The stored hex encodes the id's INTERNAL bytes, so the converted blob equals the decoded
    /// hex — NOT its reverse, which is the id's display form (`TxId`'s `Display`). Both a real
    /// row and a NULL-txid row survive the rebuild.
    #[test]
    fn conversion_preserves_internal_byte_order() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "-- The migrator runs every schema migration with foreign-key enforcement off.
             PRAGMA foreign_keys = OFF;
             -- The parent table the transactions table's foreign key names: the rename step
             -- re-parses the schema, so the reference target must exist.
             CREATE TABLE orchard_ironwood_migrations (id INTEGER PRIMARY KEY);
             CREATE TABLE orchard_ironwood_migration_transactions (
                migration_id INTEGER NOT NULL,
                transfer_id INTEGER NOT NULL,
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
                lock_owner BLOB,
                unsatisfiable_at INTEGER,
                unsatisfiable_kind TEXT,
                broadcast_failure_at INTEGER,
                PRIMARY KEY (migration_id, transfer_id)
             );",
        )
        .unwrap();
        // An asymmetric byte pattern, so a byte-order reversal cannot go unnoticed.
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        conn.execute_batch(&format!(
            "INSERT INTO orchard_ironwood_migration_transactions
                (migration_id, transfer_id, kind, kind_crossing, pczt, scheduled_height,
                 expiry_height, state, txid)
             VALUES (1, 0, 'transfer', 0, X'AB', 10, 20, 'proved', '{}'),
                    (1, 1, 'transfer', 1, X'CD', 10, 20, 'signed', NULL);",
            hex::encode(bytes),
        ))
        .unwrap();

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        let stored: Vec<Option<[u8; 32]>> = conn
            .prepare(
                "SELECT txid FROM orchard_ironwood_migration_transactions ORDER BY transfer_id",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(stored, vec![Some(bytes), None]);
        // The executable statement of the encoding claim: the historical text was the internal
        // bytes' hex, which is NOT the id's display form — so a `Display`-inverting parse
        // (`TxId::from_hex`) would have produced the reversed bytes.
        let txid = zcash_protocol::TxId::from_bytes(bytes);
        assert_ne!(hex::encode(bytes), txid.to_string());
        assert_eq!(
            zcash_protocol::TxId::from_hex(&hex::encode(bytes)).map(|t| *t.as_ref()),
            Some({
                let mut r = bytes;
                r.reverse();
                r
            }),
            "the Display inverse reverses internal-order hex: exactly why it is not used here"
        );
    }
}
