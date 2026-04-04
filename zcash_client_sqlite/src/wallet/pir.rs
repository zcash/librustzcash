//! PIR (Private Information Retrieval) spent-note tracking.
//!
//! When the `sync-nullifier-pir` feature is enabled, Orchard note spendability is
//! discovered by checking nullifiers against an external PIR server rather than
//! waiting for sequential shard-tree scanning. This module provides the data layer
//! for recording and querying PIR-detected spends.
//!
//! The `pir_spent_notes` table is created unconditionally by migration so the
//! schema is identical across all builds. When the feature is off, the table is
//! empty and unused.

use rusqlite::Connection;

use crate::error::SqliteClientError;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use rusqlite::Connection;

    use secrecy::SecretVec;
    use zcash_protocol::consensus::Network;

    use crate::{WalletDb, wallet::init::WalletMigrator};

    /// Runs the full wallet migration on `path`, then reopens a plain
    /// [`Connection`] with FK enforcement and prerequisite rows for PIR tests.
    fn migrate_and_setup(path: impl AsRef<std::path::Path>) -> Connection {
        let mut db = WalletDb::for_path(
            path.as_ref(),
            Network::TestNetwork,
            crate::util::SystemClock,
            rand_core::OsRng,
        )
        .unwrap();
        WalletMigrator::new()
            .with_seed(SecretVec::new(vec![0xab; 32]))
            .init_or_migrate(&mut db)
            .unwrap();
        drop(db);

        let conn = Connection::open(path.as_ref()).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (
                 uuid, account_kind, uivk, birthday_height, has_spend_key
             ) VALUES (
                 X'00000000000000000000000000000001', 1,
                 'test-uivk-for-pir', 1, 1
             );
             INSERT INTO transactions (id_tx, txid, min_observed_height)
             VALUES (
                 100,
                 X'0000000000000000000000000000000000000000000000000000000000000001',
                 1
             );",
        )
        .unwrap();

        conn
    }

    /// A migrated wallet database for PIR tests. Holds the temp file so the
    /// on-disk database is not cleaned up while tests are running.
    #[cfg(test)]
    pub struct PirTestDb {
        conn: Connection,
        _data_file: tempfile::NamedTempFile,
    }

    #[cfg(test)]
    impl PirTestDb {
        pub fn new() -> Self {
            let data_file = tempfile::NamedTempFile::new().unwrap();
            let conn = migrate_and_setup(data_file.path());
            Self {
                conn,
                _data_file: data_file,
            }
        }

        pub fn conn(&self) -> &Connection {
            &self.conn
        }
    }

    /// Creates an on-disk SQLite database with the full migrated wallet schema,
    /// ready for PIR tests. Caller is responsible for cleanup.
    pub fn create_pir_test_db_on_disk(suffix: &str) -> (Connection, std::path::PathBuf) {
        let db_path = std::env::temp_dir().join(format!(
            "pir_test_{}_{}_{}.db",
            std::process::id(),
            suffix,
            std::thread::current().name().unwrap_or("t")
        ));
        let conn = migrate_and_setup(&db_path);
        (conn, db_path)
    }

    /// Inserts a synthetic note row for testing.
    pub fn insert_test_note(conn: &Connection, id: i64, value: i64, nf: Option<&[u8]>) {
        conn.execute(
            "INSERT INTO orchard_received_notes \
             (id, transaction_id, action_index, account_id, diversifier, value, \
              rho, rseed, nf, is_change) \
             VALUES (?1, 100, ?1, 1, X'00', ?2, X'00', X'00', ?3, 0)",
            rusqlite::params![id, value, nf],
        )
        .unwrap();
    }
}

/// An unspent Orchard note with its nullifier, for PIR spend-checking.
pub struct UnspentOrchardNote {
    pub id: i64,
    pub nf: [u8; 32],
    pub value: u64,
}

/// A PIR-detected spend not yet confirmed by the block scanner.
pub struct PirPendingSpend {
    pub note_id: i64,
    pub value: u64,
}

/// Aggregate result from [`get_pir_pending_spends`]: the individual notes and
/// their summed value.
pub struct PirPendingSpendsResult {
    pub notes: Vec<PirPendingSpend>,
    pub total_value: u64,
}

const UNSPENT_ORCHARD_NOTES_SQL: &str = "\
    SELECT rn.id, rn.nf, rn.value FROM orchard_received_notes rn \
    WHERE rn.nf IS NOT NULL \
    AND NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = rn.id \
    ) \
    AND NOT EXISTS ( \
        SELECT 1 FROM pir_spent_notes pir \
        WHERE pir.note_id = rn.id \
    )";

const PIR_PENDING_SPENDS_SQL: &str = "\
    SELECT pir.note_id, rn.value FROM pir_spent_notes pir \
    JOIN orchard_received_notes rn ON pir.note_id = rn.id \
    WHERE NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = pir.note_id \
    )";

/// Returns unspent Orchard notes that have nullifiers, excluding both
/// scan-confirmed spends and PIR-detected spends. Used by the PIR FFI
/// to determine which nullifiers to check against the PIR server.
pub fn get_unspent_orchard_notes_for_pir(
    conn: &Connection,
) -> Result<Vec<UnspentOrchardNote>, SqliteClientError> {
    let mut stmt = conn.prepare(UNSPENT_ORCHARD_NOTES_SQL)?;

    let notes = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let nf_blob: Vec<u8> = row.get(1)?;
            let value: i64 = row.get(2)?;
            Ok((id, nf_blob, value as u64))
        })?
        .filter_map(|r| r.ok())
        .filter_map(|(id, nf_blob, value)| {
            let nf: [u8; 32] = nf_blob.try_into().ok()?;
            Some(UnspentOrchardNote { id, nf, value })
        })
        .collect();

    Ok(notes)
}

/// Returns PIR-detected spent notes whose spends have not yet been confirmed
/// by the block scanner.
pub fn get_pir_pending_spends(
    conn: &Connection,
) -> Result<PirPendingSpendsResult, SqliteClientError> {
    let mut stmt = conn.prepare(PIR_PENDING_SPENDS_SQL)?;

    let notes: Vec<PirPendingSpend> = stmt
        .query_map([], |row| {
            let note_id: i64 = row.get(0)?;
            let value: i64 = row.get(1)?;
            Ok(PirPendingSpend {
                note_id,
                value: value as u64,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    let total_value: u64 = notes.iter().map(|n| n.value).sum();
    Ok(PirPendingSpendsResult { notes, total_value })
}

/// Records a note as PIR-spent. The insert is conditional: it skips notes
/// that are already scan-confirmed spent or already in `pir_spent_notes`.
///
/// Does not retry on `SQLITE_BUSY` — that is the caller's responsibility
/// when using a separate connection from the main wallet writer.
pub fn insert_pir_spent_note(conn: &Connection, note_id: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO pir_spent_notes (note_id)
         SELECT ?1
         WHERE NOT EXISTS (
             SELECT 1 FROM orchard_received_note_spends
             WHERE orchard_received_note_id = ?1
         )
         AND NOT EXISTS (
             SELECT 1 FROM pir_spent_notes WHERE note_id = ?1
         )",
        [note_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::{PirTestDb, insert_test_note};

    fn make_nf(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn mark_spent(conn: &Connection, note_id: i64) {
        conn.execute(
            "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id) \
             VALUES (?1, 100)",
            [note_id],
        )
        .unwrap();
    }

    fn mark_pir_spent(conn: &Connection, note_id: i64) {
        conn.execute(
            "INSERT INTO pir_spent_notes (note_id) VALUES (?1)",
            [note_id],
        )
        .unwrap();
    }

    // =========================================================================
    // Unspent notes query
    // =========================================================================

    #[test]
    fn empty_table_returns_no_notes() {
        let db = PirTestDb::new();
        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn returns_unspent_notes_with_nullifiers() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0xAA);
        let nf2 = make_nf(0xBB);
        insert_test_note(db.conn(), 1, 50_000, Some(&nf1));
        insert_test_note(db.conn(), 2, 75_000, Some(&nf2));

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].id, 1);
        assert_eq!(notes[0].value, 50_000);
        assert_eq!(notes[0].nf, [0xAA; 32]);
        assert_eq!(notes[1].id, 2);
        assert_eq!(notes[1].value, 75_000);
    }

    #[test]
    fn excludes_notes_without_nullifier() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0xAA);
        insert_test_note(db.conn(), 1, 50_000, Some(&nf1));
        insert_test_note(db.conn(), 2, 75_000, None);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn excludes_spent_notes() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0xAA);
        let nf2 = make_nf(0xBB);
        let nf3 = make_nf(0xCC);
        insert_test_note(db.conn(), 1, 10_000, Some(&nf1));
        insert_test_note(db.conn(), 2, 20_000, Some(&nf2));
        insert_test_note(db.conn(), 3, 30_000, Some(&nf3));

        mark_spent(db.conn(), 2);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        let ids: Vec<i64> = notes.iter().map(|n| n.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2));
    }

    #[test]
    fn excludes_spent_notes_and_null_nf_combined() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0x01);
        let nf2 = make_nf(0x02);
        let nf3 = make_nf(0x03);
        insert_test_note(db.conn(), 1, 100, Some(&nf1));
        insert_test_note(db.conn(), 2, 200, Some(&nf2));
        insert_test_note(db.conn(), 3, 300, None);
        insert_test_note(db.conn(), 4, 400, Some(&nf3));

        mark_spent(db.conn(), 2);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        let total: u64 = notes.iter().map(|n| n.value).sum();
        assert_eq!(total, 500);
    }

    #[test]
    fn all_notes_spent_returns_empty() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0xAA);
        let nf2 = make_nf(0xBB);
        insert_test_note(db.conn(), 1, 10_000, Some(&nf1));
        insert_test_note(db.conn(), 2, 20_000, Some(&nf2));

        mark_spent(db.conn(), 1);
        mark_spent(db.conn(), 2);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    // =========================================================================
    // PIR spent notes
    // =========================================================================

    #[test]
    fn excludes_pir_spent_notes() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));
        insert_test_note(db.conn(), 2, 20_000, Some(&make_nf(0x02)));
        insert_test_note(db.conn(), 3, 30_000, Some(&make_nf(0x03)));

        mark_pir_spent(db.conn(), 2);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        let ids: Vec<i64> = notes.iter().map(|n| n.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2));
    }

    #[test]
    fn excludes_both_pir_and_real_spent() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));
        insert_test_note(db.conn(), 2, 20_000, Some(&make_nf(0x02)));
        insert_test_note(db.conn(), 3, 30_000, Some(&make_nf(0x03)));

        mark_spent(db.conn(), 2);
        mark_pir_spent(db.conn(), 3);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn pir_and_real_spend_same_note() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));

        mark_spent(db.conn(), 1);
        mark_pir_spent(db.conn(), 1);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn insert_pir_basic() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));

        insert_pir_spent_note(db.conn(), 1).unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_spent_notes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_pir_skips_real_spent() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));

        mark_spent(db.conn(), 1);
        insert_pir_spent_note(db.conn(), 1).unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_spent_notes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn insert_pir_idempotent() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));

        insert_pir_spent_note(db.conn(), 1).unwrap();
        insert_pir_spent_note(db.conn(), 1).unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_spent_notes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_pir_fk_cascade() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));

        mark_pir_spent(db.conn(), 1);

        db.conn()
            .execute("DELETE FROM orchard_received_notes WHERE id = 1", [])
            .unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_spent_notes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // =========================================================================
    // PIR pending spends
    // =========================================================================

    #[test]
    fn pending_spends_empty_when_no_pir_notes() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));

        let result = get_pir_pending_spends(db.conn()).unwrap();
        assert!(result.notes.is_empty());
        assert_eq!(result.total_value, 0);
    }

    #[test]
    fn pending_spends_returns_pir_only_notes() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));
        insert_test_note(db.conn(), 2, 20_000, Some(&make_nf(0x02)));
        insert_test_note(db.conn(), 3, 30_000, Some(&make_nf(0x03)));

        mark_pir_spent(db.conn(), 1);
        mark_pir_spent(db.conn(), 3);

        let result = get_pir_pending_spends(db.conn()).unwrap();
        assert_eq!(result.notes.len(), 2);
        assert_eq!(result.total_value, 40_000);
        let ids: Vec<i64> = result.notes.iter().map(|n| n.note_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
    }

    #[test]
    fn pending_spends_excludes_scan_confirmed() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));
        insert_test_note(db.conn(), 2, 20_000, Some(&make_nf(0x02)));
        insert_test_note(db.conn(), 3, 30_000, Some(&make_nf(0x03)));

        mark_pir_spent(db.conn(), 1);
        mark_pir_spent(db.conn(), 2);
        mark_pir_spent(db.conn(), 3);

        mark_spent(db.conn(), 2);

        let result = get_pir_pending_spends(db.conn()).unwrap();
        assert_eq!(result.notes.len(), 2);
        assert_eq!(result.total_value, 40_000);
        let ids: Vec<i64> = result.notes.iter().map(|n| n.note_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2));
    }

    #[test]
    fn pending_spends_empty_when_all_confirmed() {
        let db = PirTestDb::new();
        insert_test_note(db.conn(), 1, 10_000, Some(&make_nf(0x01)));
        insert_test_note(db.conn(), 2, 20_000, Some(&make_nf(0x02)));

        mark_pir_spent(db.conn(), 1);
        mark_pir_spent(db.conn(), 2);
        mark_spent(db.conn(), 1);
        mark_spent(db.conn(), 2);

        let result = get_pir_pending_spends(db.conn()).unwrap();
        assert!(result.notes.is_empty());
        assert_eq!(result.total_value, 0);
    }
}
