//! Adds the `anchor_bucket_interval` column to `orchard_ironwood_migrations` where it is missing.
//!
//! The column records the anchor retention grid a pool migration was committed under. It was
//! introduced by editing the [`orchard_ironwood_migration_tables`] DDL in place, on the assumption
//! that no wallet had yet applied that migration. That assumption does not hold for a wallet built
//! from a git revision between the two commits: such a wallet has `orchard_ironwood_migrations`
//! without the column and has already recorded [`orchard_ironwood_migration_tables`] as applied, so
//! its `CREATE TABLE IF NOT EXISTS` never runs again and the column can never appear.
//!
//! The consequence is not confined to pool migration. [`WalletDb::put_blocks`] reads the committed
//! grids on every scan once NU6.3 has an activation height, and "no such column" is a prepare-time
//! error, so it fires even when no migration is in progress and the table is empty. Every scan then
//! fails, no block is ever written, and no transaction ever acquires a mined height.
//!
//! This migration adds the column where it is absent. On a wallet whose table was created after the
//! DDL edit the column is already present and this is a no-op, so both paths converge on the schema
//! in [`crate::wallet::db::TABLE_ORCHARD_IRONWOOD_MIGRATIONS`].
//!
//! [`WalletDb::put_blocks`]: crate::WalletDb

use std::collections::HashSet;
use std::num::NonZeroU32;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::zip318::AnchorBucketInterval;

use super::orchard_ironwood_migration_tables;
use crate::wallet::init::WalletMigrationError;

/// Adds the `anchor_bucket_interval` column to `orchard_ironwood_migrations` where it is missing.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x1ab3caf9_ef1e_482c_93a3_a3f1080038df);

pub(super) const DEPENDENCIES: &[Uuid] = &[orchard_ironwood_migration_tables::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the anchor_bucket_interval column to orchard_ironwood_migrations where missing."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // A wallet whose table was created from the current DDL already has the column; adding it
        // again is an error rather than a no-op, so the presence check is load-bearing.
        let has_column = transaction.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migrations')
                WHERE name = :column_name
             )",
            named_params![":column_name": COLUMN_NAME],
            |row| row.get::<_, bool>(0),
        )?;

        if !has_column {
            // The grid an existing row was committed under is not recoverable: it came from the
            // `SchedulingParams` the application planned with, which this migration cannot see. The
            // ZIP 318 grid is the only defensible reconstruction, and it is exact on the production
            // network, where a wallet MUST use it. It can be wrong on a test network, where a
            // shorter grid is legitimate: such a row is then rejected by the committed-vs-configured
            // check as `ProveError::AnchorIntervalMismatch` (or the `RebuildError` equivalent).
            // That is a loud, diagnosable failure of a migration that must be re-planned, not a
            // silent one — and it is confined to a test-network wallet that both planned under a
            // custom grid and was built from the affected revision range.
            //
            // The `DEFAULT` matches the one carried by the current `CREATE TABLE`, so the two paths
            // agree on the stored schema text; the store always binds the column explicitly, so no
            // insert ever falls back to it.
            transaction.execute_batch(&format!(
                "ALTER TABLE orchard_ironwood_migrations
                 ADD COLUMN {COLUMN_NAME} INTEGER NOT NULL DEFAULT {}",
                default_interval()
            ))?;
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

const COLUMN_NAME: &str = "anchor_bucket_interval";

/// The grid a pre-existing row is assumed to have been committed under. This is a reconstruction,
/// not a recovered value: the real grid came from the planning `SchedulingParams`, which is not
/// recorded anywhere this migration can read.
///
/// It is exact on the production network, where a wallet MUST use [`AnchorBucketInterval::ZIP_318`]
/// and [`AnchorBucketInterval::custom`] is documented as test-network-only. On a test network a
/// shorter grid is legitimate, so this can be wrong; see the comment at the `ADD COLUMN` for what
/// that costs.
///
/// [`AnchorBucketInterval::ZIP_318`]: zcash_protocol::zip318::AnchorBucketInterval::ZIP_318
/// [`AnchorBucketInterval::custom`]: zcash_protocol::zip318::AnchorBucketInterval::custom
fn default_interval() -> NonZeroU32 {
    AnchorBucketInterval::ZIP_318.block_count()
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

    /// The pre-fix schema: `orchard_ironwood_migrations` without `anchor_bucket_interval`, which is
    /// what a wallet built from the affected revision range has on disk.
    fn create_pre_fix_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE orchard_ironwood_migrations (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                note_split_fee_buffer INTEGER NOT NULL,
                note_split_change INTEGER,
                note_split_prep_fees INTEGER NOT NULL,
                note_split_total_input INTEGER NOT NULL,
                note_split_total_migratable INTEGER NOT NULL
            )",
        )
        .unwrap();
    }

    fn has_anchor_column(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migrations')
                WHERE name = 'anchor_bucket_interval'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    }

    /// The upgrade path: the column is added, and an existing row is backfilled with the ZIP 318
    /// grid rather than being dropped.
    #[test]
    fn adds_column_and_backfills_existing_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations (
                id, account_id, status, note_split_fee_buffer, note_split_change,
                note_split_prep_fees, note_split_total_input, note_split_total_migratable
             )
             VALUES (1, 1, 'planned', 100, NULL, 200, 300, 400)",
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_anchor_column(&conn));

        let (id, interval) = conn
            .query_row(
                "SELECT id, anchor_bucket_interval FROM orchard_ironwood_migrations",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?)),
            )
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(interval, default_interval().get());
    }

    /// The fresh path: the table already carries the column, so `up` must leave it alone rather
    /// than fail with "duplicate column name".
    #[test]
    fn is_a_no_op_when_the_column_is_present() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::pool_migration::orchard_ironwood::init_migration_tables(&conn).unwrap();
        assert!(has_anchor_column(&conn));

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_anchor_column(&conn));
    }
}
