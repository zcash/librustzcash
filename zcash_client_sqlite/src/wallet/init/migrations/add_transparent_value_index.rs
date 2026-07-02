//! Adds an index on `transparent_received_outputs.value_zat` to support
//! value-descending selection of spendable transparent outputs for an account.
//!
//! The `select_spendable_transparent_outputs` method (used by
//! `propose_transaction` to gather inputs for general transfers) orders eligible
//! outputs by descending value so that a value-bounded cutoff returns the
//! highest-value UTXOs first. Without a supporting index, that ordering would
//! require a full sort of the table, which becomes a severe bottleneck for
//! wallets that hold many transparent UTXOs across many addresses (e.g. a
//! recovered `zcashd` import with thousands of small outputs).
//!
//! The index covers the most common query path: the spendability filters
//! (unspent, mature, not wallet-internal-ephemeral) further restrict the
//! scanned set inside the query, so the index on `value_zat` alone is the
//! primary lever for keeping the gather cheap.

use std::collections::HashSet;

use rusqlite::params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::fix_transparent_received_outputs;
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x8b1a3c2d_4e5f_6a7b_8c9d_0e1f2a3b4c5d);

// `fix_transparent_received_outputs` drops and recreates the `transparent_received_outputs`
// table (via `DROP TABLE` + `ALTER TABLE ... RENAME TO`), which destroys any index that was
// created on the old table. Depending on it here (rather than on `utxos_to_txos`, which only
// creates the table initially) guarantees this migration always runs after that rebuild, so
// the index is created on the table that will actually persist. `utxos_to_txos` does not need
// to be listed explicitly: `fix_transparent_received_outputs` transitively depends on it.
const DEPENDENCIES: &[Uuid] = &[fix_transparent_received_outputs::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds an index on transparent_received_outputs.value_zat for value-bounded selection."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute(
            "CREATE INDEX IF NOT EXISTS idx_transparent_received_outputs_value_zat
                 ON transparent_received_outputs (value_zat DESC);",
            params![],
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::MIGRATION_ID;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// After the migration, the `idx_transparent_received_outputs_value_zat` index exists.
    #[test]
    fn creates_value_index() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            zcash_protocol::consensus::Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let count: i64 = db_data
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'idx_transparent_received_outputs_value_zat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "value_zat index should exist after migration");
    }
}
