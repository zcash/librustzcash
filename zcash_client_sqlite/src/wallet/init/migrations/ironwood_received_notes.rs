//! Adds tables for storage of received Ironwood notes.
//!
//! Ironwood notes ([ZIP 2005], NU6.3) are Orchard-protocol notes obtained from version 3 note
//! plaintexts, carried by the Ironwood bundle of a transaction and committed to the Ironwood
//! note commitment tree. They are stored separately from `orchard_received_notes` because the
//! two pools have distinct note commitment trees, and because an Orchard action and an Ironwood
//! action in the same transaction may share an action index.
//!
//! This migration adds the `ironwood_received_notes` and `ironwood_received_note_spends`
//! tables, mirroring the corresponding Orchard tables.
//!
//! [ZIP 2005]: https://zips.z.cash/zip-2005

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::orchard_note_version;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xdc0d6c91_b3db_429e_9a7b_d671cc19656e);

const DEPENDENCIES: &[Uuid] = &[orchard_note_version::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds tables for storage of received Ironwood notes."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE ironwood_received_notes (
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
                note_version INTEGER NOT NULL,
                UNIQUE (transaction_id, action_index)
            );
            CREATE INDEX idx_ironwood_received_notes_account ON ironwood_received_notes (
                account_id ASC
            );
            CREATE INDEX idx_ironwood_received_notes_address ON ironwood_received_notes (
                address_id ASC
            );
            CREATE INDEX idx_ironwood_received_notes_tx ON ironwood_received_notes (
                transaction_id ASC
            );
            CREATE INDEX idx_ironwood_received_notes_witness_stabilized ON ironwood_received_notes (
                witness_stabilized
            );

            CREATE TABLE ironwood_received_note_spends (
                ironwood_received_note_id INTEGER NOT NULL
                    REFERENCES ironwood_received_notes(id) ON DELETE CASCADE,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (ironwood_received_note_id, transaction_id)
            );
            CREATE INDEX idx_ironwood_received_note_spends_note_id ON ironwood_received_note_spends (
                ironwood_received_note_id ASC
            );
            CREATE INDEX idx_ironwood_received_note_spends_transaction_id ON ironwood_received_note_spends (
                transaction_id ASC
            );",
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
}
