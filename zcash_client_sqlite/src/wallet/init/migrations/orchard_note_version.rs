//! Adds a `note_version` column to the `orchard_received_notes` table.
//!
//! The Orchard protocol revision introduced by NU6.3 ([ZIP 2005]) versions Orchard note
//! plaintexts: pre-NU6.3 note plaintexts are version 2, and Ironwood note plaintexts are version
//! 3. The note plaintext version determines how the note commitment trapdoor is derived from the
//! note's `rseed`, so the version observed when a note was decrypted must be persisted in order
//! to reconstruct the note. Every existing row was decrypted under the Orchard note encryption
//! domain, which accepts only version 2 note plaintexts, so existing rows are backfilled as
//! version 2.
//!
//! [ZIP 2005]: https://zips.z.cash/zip-2005

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::witness_stabilized_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x2aa44e8e_e8a7_4760_8de4_501956c969ac);

const DEPENDENCIES: &[Uuid] = &[witness_stabilized_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a note_version column to the orchard_received_notes table."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "ALTER TABLE orchard_received_notes
                 ADD COLUMN note_version INTEGER NOT NULL DEFAULT 2;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, named_params};
    use schemerz_rusqlite::RusqliteMigration;

    use super::Migration;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// The `orchard_received_notes` schema exactly as left by `account_delete_cascade` (which
    /// recreated it with cascading foreign keys) and `witness_stabilized_notes` (which added
    /// the `witness_stabilized` column). This state does not exist as a single `CREATE TABLE`
    /// in any one migration, so it is spelled out here. Foreign-key enforcement stays off,
    /// matching the real migrator, which runs migrations with foreign keys disabled.
    const PRE_MIGRATION_SCHEMA: &str = "
        PRAGMA foreign_keys = OFF;
        CREATE TABLE orchard_received_notes (
            id INTEGER PRIMARY KEY,
            transaction_id INTEGER NOT NULL,
            action_index INTEGER NOT NULL,
            account_id INTEGER NOT NULL,
            diversifier BLOB NOT NULL,
            value INTEGER NOT NULL,
            rho BLOB NOT NULL,
            rseed BLOB NOT NULL,
            nf BLOB UNIQUE,
            is_change INTEGER NOT NULL,
            memo BLOB,
            commitment_tree_position INTEGER,
            recipient_key_scope INTEGER,
            address_id INTEGER,
            witness_stabilized INTEGER NOT NULL DEFAULT 0,
            UNIQUE (transaction_id, action_index)
        );";

    /// A wallet that received Orchard notes before NU6.3 must keep every one of those notes
    /// after the migration, tagged as note version 2 with their payloads intact, and the
    /// `(transaction_id, action_index)` uniqueness constraint must continue to reject a
    /// duplicate note at the same action index regardless of its note version.
    #[test]
    fn backfills_pre_nu6_3_orchard_notes_as_version_2() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(PRE_MIGRATION_SCHEMA).unwrap();

        let note_values: [i64; 3] = [10_000, 20_000, 30_000];
        {
            let mut stmt = conn
                .prepare(
                    "INSERT INTO orchard_received_notes (
                        transaction_id, action_index, account_id, diversifier, value,
                        rho, rseed, nf, is_change
                    ) VALUES (
                        1, :action_index, 1, :diversifier, :value,
                        :rho, :rseed, :nf, 0
                    )",
                )
                .unwrap();
            for (i, value) in note_values.iter().enumerate() {
                let action_index = i as i64;
                stmt.execute(named_params! {
                    ":action_index": action_index,
                    ":diversifier": [i as u8; 11].as_slice(),
                    ":value": value,
                    ":rho": [i as u8; 32].as_slice(),
                    ":rseed": [0x80 | i as u8; 32].as_slice(),
                    ":nf": action_index.to_le_bytes().as_slice(),
                })
                .unwrap();
            }
        }

        let tx = conn.transaction().unwrap();
        Migration.up(&tx).unwrap();

        // Every pre-existing note is still present, in order, tagged as version 2, with its
        // value preserved.
        let rows = tx
            .prepare(
                "SELECT action_index, value, note_version
                 FROM orchard_received_notes
                 ORDER BY action_index",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(rows.len(), note_values.len());
        for (i, (action_index, value, note_version)) in rows.iter().enumerate() {
            assert_eq!(*action_index, i as i64);
            assert_eq!(*value, note_values[i]);
            assert_eq!(*note_version, 2);
        }

        // A duplicate note at an existing action index is rejected even under a different note
        // version; the uniqueness constraint intentionally does not include `note_version`,
        // because Ironwood notes are not stored in this table.
        let duplicate = tx.execute(
            "INSERT INTO orchard_received_notes (
                transaction_id, action_index, account_id, diversifier, value,
                rho, rseed, nf, is_change, note_version
            ) VALUES (1, 0, 1, X'00', 1, X'01', X'02', X'ff', 0, 3)",
            [],
        );
        assert!(duplicate.is_err());
    }
}
