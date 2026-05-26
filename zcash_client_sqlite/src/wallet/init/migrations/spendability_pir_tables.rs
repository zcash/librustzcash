//! This migration adds the `pir_witness_data` table for PIR (Private Information
//! Retrieval) Merkle authentication paths obtained from an external witness server.
//!
//! The table is created unconditionally (not gated by `#[cfg(feature = "spendability-pir")]`)
//! to keep the migration DAG identical across all builds. When the feature is off, the
//! table exists but is empty and unused.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{ivk_item_cache, v_tx_outputs_key_scopes, witness_stabilized_notes};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa40f05b9_1c3e_4b7a_9f2d_8e6c3d5a7b12);

const DEPENDENCIES: &[Uuid] = &[
    v_tx_outputs_key_scopes::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    witness_stabilized_notes::MIGRATION_ID,
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
        "Adds pir_witness_data table for PIR Merkle authentication paths."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        debug!("Creating PIR witness data table");
        transaction.execute(
            "CREATE TABLE pir_witness_data (
                note_id INTEGER NOT NULL PRIMARY KEY
                    REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
                siblings BLOB NOT NULL CHECK(length(siblings) = 1024),
                anchor_height INTEGER NOT NULL,
                anchor_root BLOB NOT NULL CHECK(length(anchor_root) = 32)
            )",
            [],
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute("DROP TABLE pir_witness_data", [])?;
        Ok(())
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
