//! Gives every pool-migration record a durable identity (`uuid`, `committed_height`) and scopes
//! the per-account uniqueness of migrations to the PENDING row, so terminal migrations accumulate
//! as retained history instead of being overwritten by their successor.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::orchard_ironwood_migration_unsatisfiability;
use crate::wallet::init::WalletMigrationError;

/// Identifies this migration in the wallet's schema-migration DAG.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xda66771b_b901_40a0_9ed8_50fa3150a5d1);

pub(super) const DEPENDENCIES: &[Uuid] =
    &[orchard_ironwood_migration_unsatisfiability::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds uuid and committed_height to pool-migration records, and scopes their per-account \
         uniqueness to the pending row."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // The two identity columns. `uuid` follows the `accounts.uuid` precedent: row ids must not
        // cross an FFI, since they are not stable across a restore, and a mobile client will cache
        // whatever handle it is given. Its empty-blob `DEFAULT` exists only because SQLite cannot
        // add a `NOT NULL` column without one; every pre-existing row is backfilled with a real
        // random uuid below, in this same transaction, and the store binds the column explicitly
        // on every insert, so the default is never stored. `committed_height` is the chain height
        // the migration was committed at — the "when" a history listing sorts by — and is
        // deliberately NOT backfilled: pre-existing rows have no truthful value, and NULL is the
        // honest one.
        transaction.execute_batch(
            "ALTER TABLE orchard_ironwood_migrations ADD COLUMN uuid BLOB NOT NULL DEFAULT X'';
             ALTER TABLE orchard_ironwood_migrations ADD COLUMN committed_height INTEGER;",
        )?;

        let ids: Vec<i64> = transaction
            .prepare("SELECT id FROM orchard_ironwood_migrations")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for id in ids {
            transaction.execute(
                "UPDATE orchard_ironwood_migrations SET uuid = :uuid WHERE id = :id",
                named_params! {":uuid": Uuid::new_v4(), ":id": id},
            )?;
        }

        // Scope the per-account uniqueness to the PENDING row: at most one migration per account
        // outside the terminal statuses, while terminal rows accumulate without limit. The index
        // is created from the store's own generator, whose `NOT IN` predicate is derived from
        // `MigrationStatus::terminal` — never restated as literals — so the migration path and the
        // canonical DDL cannot disagree about which statuses are terminal. Safe on live data: the
        // total unique index being dropped already guaranteed at most one row per account, hence
        // at most one non-terminal row.
        transaction.execute_batch(&format!(
            "DROP INDEX idx_orchard_ironwood_migrations_account;
             {};",
            crate::pool_migration::orchard_ironwood::account_index_sql(),
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
    use uuid::Uuid;

    use super::*;
    use crate::wallet::init::migrations::tests::test_migrate;
    use zcash_pool_migration::engine::MigrationStatus;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// The columns and rows of the dependency-state schema that this migration TOUCHES: the
    /// migrations table's identity and status columns plus the total unique index it replaces.
    /// A reduced stand-in is safe here — unlike a repair migration, this one reads none of the
    /// remaining columns, and full schema-text equality along the real migration path is enforced
    /// separately by `verify_schema` and `canonical_pool_migration_ddl_matches_the_migration_path`.
    fn dependency_state(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE orchard_ironwood_migrations (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                status TEXT NOT NULL
             );
             CREATE UNIQUE INDEX idx_orchard_ironwood_migrations_account
                ON orchard_ironwood_migrations (account_id);",
        )
        .unwrap();
    }

    fn apply(conn: &mut Connection) {
        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();
    }

    /// Every pre-existing migration row is backfilled with its OWN random uuid — never the
    /// empty-blob column default, never a shared value — and `committed_height` stays NULL, the
    /// only truthful value for a row that predates the column.
    #[test]
    fn backfill_gives_each_row_its_own_identity() {
        let mut conn = Connection::open_in_memory().unwrap();
        dependency_state(&conn);
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations (id, account_id, status)
             VALUES (1, 1, 'committed'), (2, 2, 'complete');",
        )
        .unwrap();

        apply(&mut conn);

        let identities: Vec<(Uuid, Option<i64>)> = conn
            .prepare("SELECT uuid, committed_height FROM orchard_ironwood_migrations ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(identities.len(), 2);
        assert_ne!(identities[0].0, identities[1].0, "identities are per-row");
        for (uuid, committed_height) in identities {
            assert!(!uuid.is_nil(), "a real uuid, not a zeroed placeholder");
            assert_eq!(committed_height, None, "no invented commit height");
        }
    }

    /// After the index swap, an account accumulates TERMINAL migrations without limit while a
    /// second PENDING one is still a constraint violation: the D3 invariant, upheld by the
    /// database rather than only by the engine's commit guard.
    #[test]
    fn uniqueness_is_scoped_to_the_pending_row() {
        let mut conn = Connection::open_in_memory().unwrap();
        dependency_state(&conn);
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations (id, account_id, status)
             VALUES (1, 1, 'committed');",
        )
        .unwrap();

        apply(&mut conn);

        // Terminal history accumulates freely beside the pending row...
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations (id, account_id, status, uuid)
             VALUES (2, 1, 'complete', X'01'), (3, 1, 'cancelled', X'02');",
        )
        .unwrap();
        // ...while a second pending migration for the same account is rejected.
        let err = conn
            .execute_batch(
                "INSERT INTO orchard_ironwood_migrations (id, account_id, status, uuid)
                 VALUES (4, 1, 'in_progress', X'03');",
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "a second pending migration violates the partial index: {err}"
        );
    }

    /// The generated index predicate names exactly the terminal statuses: every terminal wire
    /// name appears, and no non-terminal one does. A terminal status missing from the predicate
    /// silently permits two pending migrations per account, which is why the list is generated
    /// rather than written; this pins the generator to the enum in case that ever changes.
    #[test]
    fn index_predicate_matches_the_status_enum() {
        let sql = crate::pool_migration::orchard_ironwood::account_index_sql();
        for status in MigrationStatus::ALL {
            let quoted = format!("'{}'", status.wire_name());
            assert_eq!(
                sql.contains(&quoted),
                status.is_terminal(),
                "predicate membership of {quoted} does not match its terminality"
            );
        }
    }
}
