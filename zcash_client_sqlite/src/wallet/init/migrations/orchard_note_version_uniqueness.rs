//! Adds a note version to the Orchard received-note uniqueness constraint.
//!
//! Ironwood notes are stored in `orchard_received_notes` alongside Orchard notes. An Orchard
//! action and an Ironwood action in the same transaction can share an action index, so the
//! previous `UNIQUE (transaction_id, action_index)` constraint would spuriously collide. This
//! migration adds a `note_version` column (Orchard notes are version 2, Ironwood notes are
//! version 3, matching the Orchard protocol revision) and widens the uniqueness constraint to
//! `UNIQUE (transaction_id, action_index, note_version)`. Existing rows are backfilled as
//! version 2.

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
        "Adds note version to Orchard received-note uniqueness."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP INDEX IF EXISTS idx_orchard_received_notes_account;
             DROP INDEX IF EXISTS idx_orchard_received_notes_address;
             DROP INDEX IF EXISTS idx_orchard_received_notes_tx;
             DROP INDEX IF EXISTS idx_orchard_received_notes_witness_stabilized;

             PRAGMA legacy_alter_table = ON;

             CREATE TABLE orchard_received_notes_new (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL
                     REFERENCES transactions(id_tx) ON DELETE CASCADE,
                 action_index INTEGER NOT NULL,
                 account_id INTEGER NOT NULL
                     REFERENCES accounts(id) ON DELETE CASCADE,
                 diversifier BLOB NOT NULL,
                 value INTEGER NOT NULL,
                 rho BLOB NOT NULL,
                 rseed BLOB NOT NULL,
                 nf BLOB UNIQUE,
                 is_change INTEGER NOT NULL,
                 memo BLOB,
                 commitment_tree_position INTEGER,
                 recipient_key_scope INTEGER,
                 address_id INTEGER
                     REFERENCES addresses(id) ON DELETE CASCADE,
                 witness_stabilized INTEGER NOT NULL DEFAULT 0,
                 note_version INTEGER NOT NULL DEFAULT 2,
                 UNIQUE (transaction_id, action_index, note_version)
             );

             INSERT INTO orchard_received_notes_new (
                 id, transaction_id, action_index, account_id,
                 diversifier, value, rho, rseed, nf, is_change, memo,
                 commitment_tree_position, recipient_key_scope, address_id,
                 witness_stabilized, note_version
             )
             SELECT
                 id, transaction_id, action_index, account_id,
                 diversifier, value, rho, rseed, nf, is_change, memo,
                 commitment_tree_position, recipient_key_scope, address_id,
                 witness_stabilized, 2
             FROM orchard_received_notes;

             DROP TABLE orchard_received_notes;
             ALTER TABLE orchard_received_notes_new RENAME TO orchard_received_notes;

             CREATE INDEX idx_orchard_received_notes_account
                 ON orchard_received_notes (account_id ASC);
             CREATE INDEX idx_orchard_received_notes_address
                 ON orchard_received_notes (address_id ASC);
             CREATE INDEX idx_orchard_received_notes_tx
                 ON orchard_received_notes (transaction_id ASC);
             CREATE INDEX idx_orchard_received_notes_witness_stabilized
                 ON orchard_received_notes (witness_stabilized);

             PRAGMA legacy_alter_table = OFF;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    // The payload-preservation test references the Orchard/Ironwood note-version constants, which
    // live behind the `orchard` feature.
    #[cfg(feature = "orchard")]
    mod payload_preservation {
        use proptest::prelude::*;
        use rusqlite::{Connection, named_params};
        use schemerz_rusqlite::RusqliteMigration;

        use super::super::Migration;
        use crate::wallet::init::migrations::tests::arb_orchard_note;
        use crate::wallet::orchard::{IRONWOOD_NOTE_VERSION, ORCHARD_NOTE_VERSION};

        /// The `orchard_received_notes` schema exactly as left by `account_delete_cascade` (which
        /// recreated it with cascading foreign keys) and `witness_stabilized_notes` (which added
        /// the `witness_stabilized` column): no `note_version`, keyed on `UNIQUE
        /// (transaction_id, action_index)`. This state does not exist as a single `CREATE TABLE`
        /// in any one migration, so it is spelled out here. Stub parent tables are created so the
        /// migration's foreign-key references resolve; foreign-key enforcement stays off.
        const PRE_MIGRATION_SCHEMA: &str = "
            -- The real migrator runs migrations with foreign keys disabled; match that so the
            -- rebuild's copy step and the constraint checks below behave as in production.
            PRAGMA foreign_keys = OFF;
            CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY);
            CREATE TABLE accounts (id INTEGER PRIMARY KEY);
            CREATE TABLE addresses (id INTEGER PRIMARY KEY);
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

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            /// A wallet that received Orchard notes before NU6.3 must keep every one of those
            /// notes after the migration, tagged as [`ORCHARD_NOTE_VERSION`], with their payloads
            /// intact. The widened uniqueness constraint must then allow an Ironwood note
            /// ([`IRONWOOD_NOTE_VERSION`]) to share an action index with an existing Orchard note,
            /// while still rejecting a duplicate Orchard note at that index.
            #[test]
            fn preserves_pre_nu6_3_orchard_notes(
                notes in prop::collection::vec(arb_orchard_note(), 1..8),
            ) {
                let mut conn = Connection::open_in_memory().unwrap();
                conn.execute_batch(PRE_MIGRATION_SCHEMA).unwrap();

            // Insert the generated notes as a pre-NU6.3 wallet would have, assigning unique
            // identity columns. Using a single transaction id with distinct action indices also
            // exercises multiple notes sharing a transaction.
            {
                let mut stmt = conn
                    .prepare(
                        "INSERT INTO orchard_received_notes (
                            transaction_id, action_index, account_id, diversifier, value,
                            rho, rseed, nf, is_change, memo
                        ) VALUES (
                            1, :action_index, 1, :diversifier, :value,
                            :rho, :rseed, :nf, :is_change, :memo
                        )",
                    )
                    .unwrap();
                for (i, note) in notes.iter().enumerate() {
                    let action_index = i as i64;
                    stmt.execute(named_params! {
                        ":action_index": action_index,
                        ":diversifier": note.diversifier.as_slice(),
                        ":value": note.value,
                        ":rho": note.rho.as_slice(),
                        ":rseed": note.rseed.as_slice(),
                        ":nf": action_index.to_le_bytes().as_slice(),
                        ":is_change": note.is_change,
                        ":memo": note.memo.as_deref(),
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

            prop_assert_eq!(rows.len(), notes.len());
            for (i, (action_index, value, note_version)) in rows.iter().enumerate() {
                prop_assert_eq!(*action_index, i as i64);
                prop_assert_eq!(*value, notes[i].value);
                prop_assert_eq!(*note_version, ORCHARD_NOTE_VERSION);
            }

            // An Ironwood note may share action index 0 with the first Orchard note.
            tx.execute(
                "INSERT INTO orchard_received_notes (
                    transaction_id, action_index, account_id, diversifier, value,
                    rho, rseed, nf, is_change, note_version
                ) VALUES (1, 0, 1, X'00', 1, X'01', X'02', X'ff', 0, :note_version)",
                named_params! { ":note_version": IRONWOOD_NOTE_VERSION },
            )
            .unwrap();

            // But a duplicate Orchard note at action index 0 is still rejected.
            let duplicate = tx.execute(
                "INSERT INTO orchard_received_notes (
                    transaction_id, action_index, account_id, diversifier, value,
                    rho, rseed, nf, is_change, note_version
                ) VALUES (1, 0, 1, X'00', 1, X'03', X'04', X'fe', 0, :note_version)",
                named_params! { ":note_version": ORCHARD_NOTE_VERSION },
            );
            prop_assert!(duplicate.is_err());
            }
        }
    }
}
