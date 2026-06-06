//! PIR (Private Information Retrieval) spendability data layer.
//!
//! This module provides:
//!
//! - **Nullifier gate check** — Reading unspent Orchard notes with nullifiers so
//!   an external PIR server can determine whether any have been spent. If any have,
//!   the wallet skips PIR entirely and falls back to standard scanning.
//!
//! - **Witness data** — Merkle authentication paths for Orchard notes obtained
//!   from an external PIR server during sync, enabling notes to be spent before
//!   the wallet finishes scanning. The `pir_witness_data` table stores these
//!   PIR-obtained witnesses.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::SqliteClientError;

#[cfg(feature = "orchard")]
use {
    incrementalmerkletree::{MerklePath, Position},
    orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard},
    zcash_client_backend::wallet::ReceivedNote,
    zcash_protocol::consensus,
};

// =========================================================================
// Types — nullifier gate check
// =========================================================================

/// An unspent Orchard note with its nullifier, for PIR spend-checking.
pub struct UnspentOrchardNote {
    /// Primary key in `orchard_received_notes`.
    pub id: i64,
    /// Orchard nullifier encoded as 32 bytes.
    pub nf: [u8; 32],
}

// =========================================================================
// Types — witness data
// =========================================================================

/// A stored PIR witness for an Orchard note.
pub struct PirWitnessRow {
    /// Primary key of the witnessed `orchard_received_notes` row.
    pub note_id: i64,
    /// Merkle authentication path siblings, ordered leaf-to-root.
    pub siblings: [[u8; 32]; 32],
    /// Height at which `anchor_root` was observed.
    pub anchor_height: u64,
    /// Orchard note commitment tree root for the witness anchor.
    pub anchor_root: [u8; 32],
}

#[cfg(feature = "orchard")]
type PirWitnessResult =
    Result<Option<(MerklePath<MerkleHashOrchard, 32>, u64, [u8; 32])>, SqliteClientError>;

#[cfg(feature = "orchard")]
#[derive(Debug, Clone, PartialEq, Eq)]
/// Result of validating a PIR witness against a wallet note commitment.
pub struct PirWitnessValidation {
    /// Anchor root supplied with the PIR witness.
    pub provided_anchor_root: [u8; 32],
    /// Root recomputed from the supplied path and the wallet note commitment.
    pub computed_root: [u8; 32],
}

#[cfg(feature = "orchard")]
impl PirWitnessValidation {
    /// Returns whether the supplied witness authenticates to the supplied anchor.
    pub fn witness_root_matches_anchor(&self) -> bool {
        self.computed_root == self.provided_anchor_root
    }
}

// =========================================================================
// SQL — nullifier gate check
// =========================================================================

const UNSPENT_ORCHARD_NOTES_SQL: &str = "\
    SELECT rn.id, rn.nf FROM orchard_received_notes rn \
    WHERE rn.nf IS NOT NULL \
    AND NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = rn.id \
    )";

// =========================================================================
// SQL — witness data
// =========================================================================

const NOTE_NEEDS_WITNESS_SQL: &str = "\
    SELECT rn.commitment_tree_position \
    FROM orchard_received_notes rn \
    WHERE rn.id = ?1 \
    AND rn.commitment_tree_position IS NOT NULL \
    AND rn.recipient_key_scope IS NOT NULL \
    AND NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = rn.id \
    )";
const POSITION_NEEDS_WITNESS_SQL: &str = "\
    SELECT rn.id \
    FROM orchard_received_notes rn \
    WHERE rn.commitment_tree_position = ?1 \
    AND rn.recipient_key_scope IS NOT NULL \
    AND NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = rn.id \
    )";

// =========================================================================
// Functions — nullifier gate check
// =========================================================================

/// Returns unspent Orchard notes that have nullifiers, excluding
/// scan-confirmed spends. Used by the PIR FFI to determine which
/// nullifiers to check against the PIR server.
pub fn get_unspent_orchard_notes_for_pir(
    conn: &Connection,
) -> Result<Vec<UnspentOrchardNote>, SqliteClientError> {
    let mut stmt = conn.prepare(UNSPENT_ORCHARD_NOTES_SQL)?;

    let notes = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let nf_blob: Vec<u8> = row.get(1)?;
            Ok((id, nf_blob))
        })?
        .filter_map(|r| r.ok())
        .filter_map(|(id, nf_blob)| {
            let nf: [u8; 32] = nf_blob.try_into().ok()?;
            Some(UnspentOrchardNote { id, nf })
        })
        .collect();

    Ok(notes)
}

// =========================================================================
// Functions — witness data
// =========================================================================

/// Returns the note's commitment tree position if it currently qualifies for
/// PIR witness fetch or refresh.
pub fn note_needs_pir_witness(
    conn: &Connection,
    note_id: i64,
) -> Result<Option<u64>, SqliteClientError> {
    let position = conn
        .query_row(NOTE_NEEDS_WITNESS_SQL, [note_id], |row| {
            let position: i64 = row.get(0)?;
            Ok(position as u64)
        })
        .optional()?;
    Ok(position)
}

/// Returns the note id at the given commitment tree position if it currently
/// qualifies for PIR witness fetch or refresh.
pub fn position_needs_pir_witness(
    conn: &Connection,
    position: u64,
) -> Result<Option<i64>, SqliteClientError> {
    Ok(conn
        .query_row(
        POSITION_NEEDS_WITNESS_SQL,
        [position as i64],
        |row| row.get(0),
    )
    .optional()?)
}

/// Stores a PIR-obtained witness for a note. Existing rows are refreshed only
/// when the incoming snapshot is at least as new as the stored anchor height.
pub fn insert_pir_witness(
    conn: &Connection,
    note_id: i64,
    siblings: &[[u8; 32]; 32],
    anchor_height: u64,
    anchor_root: &[u8; 32],
) -> Result<(), SqliteClientError> {
    let siblings_blob: Vec<u8> = siblings.iter().flat_map(|s| s.iter()).copied().collect();
    conn.execute(
        "INSERT INTO pir_witness_data (note_id, siblings, anchor_height, anchor_root)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(note_id) DO UPDATE SET
             siblings = excluded.siblings,
             anchor_height = excluded.anchor_height,
             anchor_root = excluded.anchor_root
         WHERE excluded.anchor_height >= pir_witness_data.anchor_height",
        params![
            note_id,
            siblings_blob,
            anchor_height as i64,
            anchor_root.as_slice()
        ],
    )?;
    Ok(())
}

/// Retrieves a stored PIR witness for a specific note.
fn get_pir_witness(
    conn: &Connection,
    note_id: i64,
) -> Result<Option<PirWitnessRow>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT note_id, siblings, anchor_height, anchor_root \
         FROM pir_witness_data WHERE note_id = ?1",
    )?;

    let result = stmt
        .query_row([note_id], |row| {
            let note_id: i64 = row.get(0)?;
            let siblings_blob: Vec<u8> = row.get(1)?;
            let anchor_height: i64 = row.get(2)?;
            let anchor_root_blob: Vec<u8> = row.get(3)?;
            Ok((
                note_id,
                siblings_blob,
                anchor_height as u64,
                anchor_root_blob,
            ))
        })
        .optional()?;

    match result {
        None => Ok(None),
        Some((note_id, siblings_blob, anchor_height, anchor_root_blob)) => {
            let siblings = parse_siblings(&siblings_blob)?;
            let anchor_root: [u8; 32] = anchor_root_blob.try_into().map_err(|_| {
                SqliteClientError::CorruptedData(
                    "pir_witness_data anchor_root is not 32 bytes".to_string(),
                )
            })?;
            Ok(Some(PirWitnessRow {
                note_id,
                siblings,
                anchor_height,
                anchor_root,
            }))
        }
    }
}

/// Checks whether a PIR witness exists for the given note.
pub fn has_pir_witness(conn: &Connection, note_id: i64) -> Result<bool, SqliteClientError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pir_witness_data WHERE note_id = ?1",
        [note_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Constructs an Orchard `MerklePath` from raw 32-byte sibling hashes at the given
/// tree position.
#[cfg(feature = "orchard")]
fn merkle_path_from_siblings(
    siblings: &[[u8; 32]; 32],
    position: Position,
) -> Result<MerklePath<MerkleHashOrchard, 32>, SqliteClientError> {
    let path: Vec<MerkleHashOrchard> = siblings
        .iter()
        .map(|bytes| {
            Option::from(MerkleHashOrchard::from_bytes(bytes)).ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "invalid MerkleHashOrchard in PIR witness sibling".to_string(),
                )
            })
        })
        .collect::<Result<_, _>>()?;

    MerklePath::from_parts(path, position).map_err(|_| {
        SqliteClientError::CorruptedData(
            "failed to construct MerklePath from PIR witness siblings".to_string(),
        )
    })
}

/// Retrieves a PIR witness for the given note and converts it into a `MerklePath`
/// suitable for the Orchard transaction builder.
///
/// Returns `Ok(None)` if no PIR witness exists for the note.
///
/// The `MerklePath` contains the same data as `ShardTree::witness_at_checkpoint_id_caching`
/// would return: 32 authentication path siblings ordered leaf-to-root, with the position
/// encoding the left/right direction at each level.
///
/// The caller is responsible for using `pir_witness.anchor_height` and
/// `pir_witness.anchor_root` to set the transaction's Orchard anchor — the PIR anchor
/// may differ from the proposal's computed anchor.
#[cfg(feature = "orchard")]
pub fn get_pir_merkle_path(
    conn: &Connection,
    note_id: i64,
    position: Position,
) -> PirWitnessResult {
    let witness = get_pir_witness(conn, note_id)?;
    match witness {
        None => Ok(None),
        Some(row) => {
            let merkle_path = merkle_path_from_siblings(&row.siblings, position)?;
            Ok(Some((merkle_path, row.anchor_height, row.anchor_root)))
        }
    }
}

/// Retrieves a PIR Merkle path by the note's commitment tree position.
///
/// Joins through `orchard_received_notes` to find the matching `note_id`, then
/// delegates to [`get_pir_merkle_path`].
#[cfg(feature = "orchard")]
pub fn get_pir_merkle_path_by_position(conn: &Connection, position: Position) -> PirWitnessResult {
    let note_id: Option<i64> = conn
        .query_row(
            "SELECT rn.id FROM orchard_received_notes rn \
             INNER JOIN pir_witness_data pw ON pw.note_id = rn.id \
             WHERE rn.commitment_tree_position = ?1",
            [u64::from(position) as i64],
            |row| row.get(0),
        )
        .optional()?;

    match note_id {
        Some(id) => get_pir_merkle_path(conn, id, position),
        None => Ok(None),
    }
}

/// Validates a PIR-obtained Orchard Merkle witness against the wallet's stored note.
///
/// Looks up the received note by `note_id`, reconstructs the Merkle path from the
/// provided `siblings` at the note's commitment tree position, then recomputes the
/// tree root from the note commitment. The caller can compare the computed root
/// against `anchor_root` via [`PirWitnessValidation::witness_root_matches_anchor`]
/// to decide whether to accept the witness.
///
/// This does **not** persist anything — it is a pure validation step intended to be
/// called before [`insert_pir_witness`].
#[cfg(feature = "orchard")]
pub fn validate_orchard_witness<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    note_id: i64,
    siblings: &[[u8; 32]; 32],
    anchor_root: &[u8; 32],
) -> Result<PirWitnessValidation, SqliteClientError> {
    let received_note = get_orchard_received_note(conn, params, note_id)?;
    let position = received_note.note_commitment_tree_position();

    let merkle_path = merkle_path_from_siblings(siblings, position)?;
    let note = received_note.note();
    let ecmx: ExtractedNoteCommitment = note.commitment().into();
    let cmx = MerkleHashOrchard::from_cmx(&ecmx);
    let computed_root = merkle_path.root(cmx).to_bytes();

    Ok(PirWitnessValidation {
        provided_anchor_root: *anchor_root,
        computed_root,
    })
}

#[cfg(feature = "orchard")]
fn get_orchard_received_note<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    note_id: i64,
) -> Result<ReceivedNote<crate::ReceivedNoteId, orchard::note::Note>, SqliteClientError> {
    let result = conn.query_row_and_then(
        "SELECT
             rn.id,
             t.txid,
             rn.action_index,
             rn.diversifier,
             rn.value,
             rn.rho,
             rn.rseed,
             rn.commitment_tree_position,
             accounts.ufvk,
             rn.recipient_key_scope,
             t.mined_height,
             NULL AS max_shielding_input_height
         FROM orchard_received_notes rn
         INNER JOIN accounts ON accounts.id = rn.account_id
         INNER JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE rn.id = ?1
         AND accounts.ufvk IS NOT NULL
         AND rn.recipient_key_scope IS NOT NULL
         AND rn.commitment_tree_position IS NOT NULL",
        [note_id],
        |row| super::orchard::to_received_note(params, row),
    );

    match result {
        Ok(Some(note)) => Ok(note),
        Ok(None) => Err(SqliteClientError::CorruptedData(format!(
            "failed to reconstruct Orchard note {note_id} for PIR witness validation"
        ))),
        Err(SqliteClientError::DbError(rusqlite::Error::QueryReturnedNoRows)) => {
            Err(SqliteClientError::CorruptedData(format!(
                "Orchard note {note_id} not found for PIR witness validation"
            )))
        }
        Err(e) => Err(e),
    }
}

/// Maps a `SqliteClientError` to the `commitment_tree::Error` expected by
/// `WalletCommitmentTrees` implementations. Used by the two
/// `get_pir_orchard_merkle_path` impls in `lib.rs`.
pub(crate) fn sqlite_to_commitment_tree_error(
    e: SqliteClientError,
) -> crate::wallet::commitment_tree::Error {
    use crate::wallet::commitment_tree::Error;
    match e {
        SqliteClientError::DbError(e) => Error::Query(e),
        other => Error::Query(rusqlite::Error::ToSqlConversionFailure(Box::new(other))),
    }
}

fn parse_siblings(blob: &[u8]) -> Result<[[u8; 32]; 32], SqliteClientError> {
    if blob.len() != 1024 {
        return Err(SqliteClientError::CorruptedData(format!(
            "pir_witness_data siblings blob is {} bytes, expected 1024",
            blob.len()
        )));
    }
    let mut siblings = [[0u8; 32]; 32];
    for (i, chunk) in blob.chunks_exact(32).enumerate() {
        siblings[i].copy_from_slice(chunk);
    }
    Ok(siblings)
}

// =========================================================================
// Test helpers
// =========================================================================

#[cfg(any(test, feature = "test-dependencies"))]
/// Test helpers for constructing wallet databases with PIR fixture data.
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
    impl Default for PirTestDb {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    impl PirTestDb {
        /// Creates a migrated temporary wallet database for PIR tests.
        pub fn new() -> Self {
            let data_file = tempfile::NamedTempFile::new().unwrap();
            let conn = migrate_and_setup(data_file.path());
            Self {
                conn,
                _data_file: data_file,
            }
        }

        /// Returns the underlying wallet database connection.
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

    /// Inserts a synthetic note row for testing, with optional tree position.
    pub fn insert_test_note_with_position(
        conn: &Connection,
        id: i64,
        value: i64,
        nf: Option<&[u8]>,
        position: Option<i64>,
    ) {
        conn.execute(
            "INSERT INTO orchard_received_notes \
             (id, transaction_id, action_index, account_id, diversifier, value, \
              rho, rseed, nf, is_change, commitment_tree_position, recipient_key_scope) \
             VALUES (?1, 100, ?1, 1, X'00', ?2, X'00', X'00', ?3, 0, ?4, 0)",
            rusqlite::params![id, value, nf, position],
        )
        .unwrap();
    }

    /// Inserts a synthetic note row for testing (no tree position).
    pub fn insert_test_note(conn: &Connection, id: i64, value: i64, nf: Option<&[u8]>) {
        insert_test_note_with_position(conn, id, value, nf, None);
    }

    /// Returns `(id, commitment_tree_position)` for all Orchard received notes,
    /// ordered by id.
    pub fn query_orchard_notes(conn: &Connection) -> Vec<(i64, i64)> {
        let mut stmt = conn
            .prepare("SELECT id, commitment_tree_position FROM orchard_received_notes ORDER BY id")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// Deletes ShardTree checkpoints, forcing the PIR witness path for Orchard
    /// spends.
    pub fn delete_orchard_checkpoints(conn: &Connection) {
        conn.execute_batch(
            "DELETE FROM orchard_tree_checkpoint_marks_removed;
             DELETE FROM orchard_tree_checkpoints;",
        )
        .unwrap();
    }

    /// Sets all `scan_queue` entries to ChainTip priority (50), which is above
    /// Scanned (10). Simulates a note in a shard that hasn't been fully scanned.
    pub fn mark_shards_unscanned(conn: &Connection) {
        conn.execute("UPDATE scan_queue SET priority = 50", [])
            .unwrap();
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use testing::{PirTestDb, insert_test_note, insert_test_note_with_position};

    #[cfg(feature = "orchard")]
    use std::convert::Infallible;
    #[cfg(feature = "orchard")]
    use testing::{delete_orchard_checkpoints, mark_shards_unscanned, query_orchard_notes};
    #[cfg(feature = "orchard")]
    use zcash_client_backend::{
        data_api::{
            Account as _,
            testing::{orchard::OrchardPoolTester, pool::ShieldedPoolTester},
            wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        },
        fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
        wallet::OvkPolicy,
    };
    #[cfg(feature = "orchard")]
    use zcash_protocol::value::Zatoshis;
    #[cfg(feature = "orchard")]
    use zip321::Payment;

    #[cfg(feature = "orchard")]
    macro_rules! real_orchard_witness_fixture {
        () => {{
            #[allow(unused_imports)]
            use zcash_client_backend::data_api::{Account as _, WalletCommitmentTrees};
            use zcash_client_backend::data_api::testing::{
                AddressType, TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
            };
            use zcash_primitives::block::BlockHash;
            use zcash_protocol::value::Zatoshis;

            use crate::{
                testing::{BlockCache, db::TestDbFactory},
                wallet::commitment_tree,
            };

            let mut st = TestBuilder::new()
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let account = st.test_account().cloned().unwrap();
            let dfvk = OrchardPoolTester::test_account_fvk(&st);
            let value = Zatoshis::const_from_u64(60_000);
            let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
            st.scan_cached_blocks(h, 1);

            let (note_id, note_position): (i64, i64) = st
                .wallet()
                .conn()
                .query_row(
                    "SELECT id, commitment_tree_position FROM orchard_received_notes LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();

            let position = incrementalmerkletree::Position::from(note_position as u64);
            let (siblings, anchor_root) = st
                .wallet_mut()
                .with_orchard_tree_mut::<
                    _,
                    _,
                    shardtree::error::ShardTreeError<commitment_tree::Error>,
                >(|orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h)?
                        .expect("root exists at scanned height");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h)?
                        .expect("witness exists for scanned note");

                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }

                    Ok((siblings, root.to_bytes()))
                })
                .unwrap();

            (st, account, note_id, note_position, siblings, anchor_root, u32::from(h) as u64)
        }};
    }

    fn make_nf(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn make_siblings(seed: u8) -> [[u8; 32]; 32] {
        let mut siblings = [[0u8; 32]; 32];
        for (i, sibling) in siblings.iter_mut().enumerate() {
            sibling.fill(seed.wrapping_add(i as u8));
        }
        siblings
    }

    fn make_root(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn mark_spent(conn: &Connection, note_id: i64) {
        conn.execute(
            "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id) \
             VALUES (?1, 100)",
            [note_id],
        )
        .unwrap();
    }

    // =====================================================================
    // Unspent notes query
    // =====================================================================

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
        assert_eq!(notes[0].nf, [0xAA; 32]);
        assert_eq!(notes[1].id, 2);
        assert_eq!(notes[1].nf, [0xBB; 32]);
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
        let ids: Vec<i64> = notes.iter().map(|n| n.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&4));
        assert!(!ids.contains(&2));
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

    // =====================================================================
    // Note-needs-witness query
    // =====================================================================

    #[test]
    fn note_needs_witness_true_for_eligible_note() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 7, 40_000, Some(&make_nf(0xAB)), Some(777));

        assert_eq!(note_needs_pir_witness(db.conn(), 7).unwrap(), Some(777));
    }

    #[test]
    fn note_needs_witness_false_for_spent_or_missing_note() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 8, 41_000, Some(&make_nf(0xCD)), Some(888));
        mark_spent(db.conn(), 8);

        assert_eq!(note_needs_pir_witness(db.conn(), 8).unwrap(), None);
        assert_eq!(note_needs_pir_witness(db.conn(), 999).unwrap(), None);
    }

    #[test]
    fn position_needs_witness_returns_note_id_for_eligible_position() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 9, 42_000, Some(&make_nf(0xEF)), Some(999));

        assert_eq!(position_needs_pir_witness(db.conn(), 999).unwrap(), Some(9));
    }

    #[test]
    fn position_needs_witness_returns_none_for_spent_or_missing_position() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 10, 43_000, Some(&make_nf(0xF1)), Some(1001));
        mark_spent(db.conn(), 10);

        assert_eq!(position_needs_pir_witness(db.conn(), 1001).unwrap(), None);
        assert_eq!(position_needs_pir_witness(db.conn(), 4040).unwrap(), None);
    }

    // =====================================================================
    // Insert witness
    // =====================================================================

    #[test]
    fn insert_witness_basic() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_witness_data", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_witness_replaces_existing() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        insert_pir_witness(db.conn(), 1, &make_siblings(0x20), 200, &make_root(0xEE)).unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_witness_data", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);

        let row = get_pir_witness(db.conn(), 1).unwrap().unwrap();
        assert_eq!(row.anchor_height, 200);
        assert_eq!(row.anchor_root, make_root(0xEE));
    }

    #[test]
    fn insert_witness_does_not_replace_newer_with_older() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let newer_siblings = make_siblings(0x20);
        let newer_root = make_root(0xEE);
        insert_pir_witness(db.conn(), 1, &newer_siblings, 200, &newer_root).unwrap();

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        let row = get_pir_witness(db.conn(), 1).unwrap().unwrap();
        assert_eq!(row.siblings, newer_siblings);
        assert_eq!(row.anchor_height, 200);
        assert_eq!(row.anchor_root, newer_root);
    }

    // =====================================================================
    // Get witness
    // =====================================================================

    #[test]
    fn get_witness_returns_none_when_absent() {
        let db = PirTestDb::new();
        let result = get_pir_witness(db.conn(), 999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_witness_returns_stored_data() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let siblings = make_siblings(0x10);
        let root = make_root(0xFF);
        insert_pir_witness(db.conn(), 1, &siblings, 100, &root).unwrap();

        let row = get_pir_witness(db.conn(), 1).unwrap().unwrap();
        assert_eq!(row.note_id, 1);
        assert_eq!(row.siblings, siblings);
        assert_eq!(row.anchor_height, 100);
        assert_eq!(row.anchor_root, root);
    }

    // =====================================================================
    // has_pir_witness
    // =====================================================================

    #[test]
    fn has_witness_false_when_absent() {
        let db = PirTestDb::new();
        assert!(!has_pir_witness(db.conn(), 999).unwrap());
    }

    #[test]
    fn has_witness_true_when_present() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        assert!(has_pir_witness(db.conn(), 1).unwrap());
    }

    // =====================================================================
    // get_pir_merkle_path_by_position
    // =====================================================================

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_returns_none_without_witness() {
        use incrementalmerkletree::Position;

        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(1000u64)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_returns_path_with_witness() {
        use incrementalmerkletree::Position;

        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let siblings = make_siblings(0x10);
        let root = make_root(0xFF);
        insert_pir_witness(db.conn(), 1, &siblings, 200, &root).unwrap();

        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(1000u64)).unwrap();
        assert!(result.is_some());

        let (merkle_path, anchor_height, anchor_root) = result.unwrap();
        assert_eq!(anchor_height, 200);
        assert_eq!(anchor_root, root);
        assert_eq!(u64::from(merkle_path.position()), 1000);
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_no_match_for_wrong_position() {
        use incrementalmerkletree::Position;

        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 200, &make_root(0xFF)).unwrap();

        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(9999u64)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn validate_orchard_witness_accepts_real_merkle_path() {
        let (st, _account, note_id, _note_position, siblings, anchor_root, _anchor_height) =
            real_orchard_witness_fixture!();

        let validation = validate_orchard_witness(
            st.wallet().conn(),
            st.network(),
            note_id,
            &siblings,
            &anchor_root,
        )
        .expect("real Orchard witness should validate");

        assert_eq!(validation.provided_anchor_root, anchor_root);
        assert_eq!(validation.computed_root, anchor_root);
        assert!(
            validation.witness_root_matches_anchor(),
            "real Orchard witness should hash back to the provided anchor"
        );
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn validate_orchard_witness_rejects_tampered_real_merkle_path() {
        let (st, _account, note_id, _note_position, mut siblings, anchor_root, _anchor_height) =
            real_orchard_witness_fixture!();

        siblings.swap(0, 1);
        let validation = validate_orchard_witness(
            st.wallet().conn(),
            st.network(),
            note_id,
            &siblings,
            &anchor_root,
        )
        .expect("tampered Orchard witness should still produce a validation result");

        assert!(
            !validation.witness_root_matches_anchor(),
            "tampered siblings should fail the note commitment -> anchor recomputation"
        );
    }

    // =====================================================================
    // FK cascade
    // =====================================================================

    #[test]
    fn witness_fk_cascade_on_note_delete() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        db.conn()
            .execute("DELETE FROM orchard_received_notes WHERE id = 1", [])
            .unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_witness_data", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // =====================================================================
    // Integration tests
    // =====================================================================

    /// `create_proposed_transactions` with `use_pir_witnesses = true` uses
    /// PIR-stored witnesses and anchors to build a valid Orchard spend, even
    /// when ShardTree checkpoints are unavailable.
    #[cfg(all(feature = "orchard", feature = "spendability-pir"))]
    #[test]
    fn pir_witness_fallback_creates_transaction() {
        let (mut st, account, note_id, _pos, siblings, anchor_root, anchor_height) =
            real_orchard_witness_fixture!();

        insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings,
            anchor_height,
            &anchor_root,
        )
        .unwrap();

        assert!(has_pir_witness(st.wallet().conn(), note_id).unwrap());

        delete_orchard_checkpoints(st.wallet().conn());

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions_pir::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_ok(),
            "PIR witnesses should create transaction: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().len(), 1);
    }

    /// A server-produced witness for the wallet's actual note commitment is
    /// rejected if tampered before insert, but succeeds end-to-end when
    /// inserted honestly and consumed via `use_pir_witnesses = true`.
    #[cfg(all(feature = "orchard", feature = "spendability-pir"))]
    #[test]
    fn pir_witness_server_round_trip_inserts_and_spends_real_note() {
        use incrementalmerkletree::{Hashable, Level};
        use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
        use zcash_client_backend::data_api::WalletCommitmentTrees;
        use zcash_client_backend::data_api::testing::{AddressType, TestBuilder};
        use zcash_primitives::block::BlockHash;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::commitment_tree,
        };

        const TREE_DEPTH: usize = 32;
        const SUBSHARD_HEIGHT: u8 = 8;
        const SHARD_HEIGHT: u8 = 16;

        fn hash_combine(level: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            let left = MerkleHashOrchard::from_bytes(left).unwrap();
            let right = MerkleHashOrchard::from_bytes(right).unwrap();
            <MerkleHashOrchard as Hashable>::combine(Level::from(level), &left, &right).to_bytes()
        }

        fn empty_root(level: u8) -> [u8; 32] {
            <MerkleHashOrchard as Hashable>::empty_root(Level::from(level)).to_bytes()
        }

        fn compute_subtree_root(nodes: &[[u8; 32]], base_level: u8) -> [u8; 32] {
            let mut current = nodes.to_vec();
            let mut level = base_level;
            while current.len() > 1 {
                current = current
                    .chunks(2)
                    .map(|pair| hash_combine(level, &pair[0], &pair[1]))
                    .collect();
                level += 1;
            }
            current[0]
        }

        fn extract_siblings(
            nodes: &[[u8; 32]],
            index: usize,
            base_level: u8,
            siblings: &mut [[u8; 32]; TREE_DEPTH],
        ) {
            let num_levels = nodes.len().trailing_zeros() as usize;
            let mut current_nodes = nodes.to_vec();
            let mut idx = index;

            for level_offset in 0..num_levels {
                let tree_level = base_level as usize + level_offset;
                let sibling_idx = idx ^ 1;
                siblings[tree_level] = if sibling_idx < current_nodes.len() {
                    current_nodes[sibling_idx]
                } else {
                    empty_root(tree_level as u8)
                };

                let mut next = Vec::with_capacity(current_nodes.len() / 2);
                for pair in current_nodes.chunks(2) {
                    let left = pair[0];
                    let right = if pair.len() > 1 {
                        pair[1]
                    } else {
                        empty_root(tree_level as u8)
                    };
                    next.push(hash_combine(tree_level as u8, &left, &right));
                }
                current_nodes = next;
                idx /= 2;
            }
        }

        fn compute_root_from_path(
            position: u64,
            leaf: &[u8; 32],
            siblings: &[[u8; 32]; TREE_DEPTH],
        ) -> [u8; 32] {
            let mut current = *leaf;
            let mut pos = position;

            for (level, sibling) in siblings.iter().enumerate() {
                let (left, right) = if pos & 1 == 0 {
                    (&current, sibling)
                } else {
                    (sibling, &current)
                };
                current = hash_combine(level as u8, left, right);
                pos >>= 1;
            }

            current
        }

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(60_000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        let notes = query_orchard_notes(st.wallet().conn());
        let (note_id, note_position) = notes[0];

        let position = incrementalmerkletree::Position::from(note_position as u64);
        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h)?
                        .expect("root exists at scanned height");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h)?
                        .expect("witness exists for scanned note");

                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }

                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        let anchor_height = u32::from(h) as u64;
        let initial_validation = st
            .wallet()
            .db()
            .validate_pir_orchard_witness(
                note_id,
                &siblings_bytes,
                &anchor_root_bytes,
            )
            .unwrap();
        assert!(
            initial_validation.witness_root_matches_anchor(),
            "wallet's own checkpoint witness should validate before the server round-trip"
        );

        let received_note = st
            .wallet()
            .conn()
            .query_row_and_then(
                "SELECT
                     rn.id,
                     t.txid,
                     rn.action_index,
                     rn.diversifier,
                     rn.value,
                     rn.rho,
                     rn.rseed,
                     rn.commitment_tree_position,
                     accounts.ufvk,
                     rn.recipient_key_scope,
                     t.mined_height,
                     NULL AS max_shielding_input_height
                 FROM orchard_received_notes rn
                 INNER JOIN accounts ON accounts.id = rn.account_id
                 INNER JOIN transactions t ON t.id_tx = rn.transaction_id
                 WHERE rn.id = ?1",
                [note_id],
                |row| super::super::orchard::to_received_note(st.network(), row),
            )
            .unwrap()
            .expect("stored note should be reconstructible");
        let note_commitment: ExtractedNoteCommitment = received_note.note().commitment().into();

        let empty_leaf = MerkleHashOrchard::empty_leaf().to_bytes();
        let mut server_leaves = vec![empty_leaf; note_position as usize];
        server_leaves.push(MerkleHashOrchard::from_cmx(&note_commitment).to_bytes());

        let server_position = note_position as u64;
        let shard_idx = (server_position >> SHARD_HEIGHT) as u32;
        let subshard_idx = ((server_position >> SUBSHARD_HEIGHT) & 0xFF) as u8;
        let leaf_idx = (server_position & 0xFF) as usize;
        assert_eq!(
            (shard_idx, subshard_idx),
            (0, 0),
            "test assumes note position fits in subshard 0"
        );

        server_leaves.resize(1 << SUBSHARD_HEIGHT, empty_leaf);

        let mut server_siblings = [[0u8; 32]; TREE_DEPTH];
        extract_siblings(&server_leaves, leaf_idx, 0, &mut server_siblings);

        let subshard_root = compute_subtree_root(&server_leaves, 0);
        for level in SUBSHARD_HEIGHT..SHARD_HEIGHT {
            server_siblings[level as usize] = empty_root(level);
        }

        let mut current = subshard_root;
        for level in SUBSHARD_HEIGHT..SHARD_HEIGHT {
            current = hash_combine(level, &current, &empty_root(level));
        }
        for level in SHARD_HEIGHT..(TREE_DEPTH as u8) {
            server_siblings[level as usize] = empty_root(level);
        }

        let mut expected_server_root = current;
        for level in SHARD_HEIGHT..(TREE_DEPTH as u8) {
            expected_server_root = hash_combine(level, &expected_server_root, &empty_root(level));
        }

        let server_anchor_root =
            compute_root_from_path(server_position, &server_leaves[leaf_idx], &server_siblings);
        let server_anchor_height = anchor_height;

        assert_eq!(server_anchor_root, expected_server_root);

        let mut tampered_siblings = server_siblings;
        tampered_siblings.swap(0, 1);
        let tampered_validation = st
            .wallet()
            .db()
            .validate_pir_orchard_witness(
                note_id,
                &tampered_siblings,
                &server_anchor_root,
            )
            .unwrap();
        assert!(
            !tampered_validation.witness_root_matches_anchor(),
            "tampered server witness should fail pre-insert validation"
        );
        assert!(
            !has_pir_witness(st.wallet().conn(), note_id).unwrap(),
            "failed validation must not persist a PIR witness row"
        );

        st.wallet()
            .db()
            .insert_pir_witness(
                note_id,
                &server_siblings,
                server_anchor_height,
                &server_anchor_root,
            )
            .unwrap();

        delete_orchard_checkpoints(st.wallet().conn());

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10_000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();
        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions_pir::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_ok(),
            "honest server witness should support PIR spending: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().len(), 1);
    }

    /// When no PIR witness is stored for a note, transaction creation should
    /// fail rather than silently produce an invalid spend.
    #[cfg(all(feature = "orchard", feature = "spendability-pir"))]
    #[test]
    fn pir_witness_missing_fails_transaction() {
        use zcash_client_backend::data_api::testing::{AddressType, TestBuilder};
        use zcash_primitives::block::BlockHash;

        use crate::testing::{BlockCache, db::TestDbFactory};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        delete_orchard_checkpoints(st.wallet().conn());

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions_pir::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_err(),
            "Should fail when no PIR witness is available"
        );
    }

    /// When two notes have PIR witnesses with different anchor roots,
    /// transaction creation should fail because the Orchard bundle requires a
    /// single anchor.
    #[cfg(all(feature = "orchard", feature = "spendability-pir"))]
    #[test]
    fn pir_witness_anchor_mismatch_fails_transaction() {
        use zcash_client_backend::data_api::WalletCommitmentTrees;
        use zcash_client_backend::data_api::testing::{AddressType, TestBuilder};
        use zcash_primitives::block::BlockHash;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::commitment_tree,
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(50000);
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h2, 1);

        let notes = query_orchard_notes(st.wallet().conn());
        assert_eq!(notes.len(), 2);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h2)?
                        .expect("root exists");
                    let pos = incrementalmerkletree::Position::from(notes[0].1 as u64);
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(pos, &h2)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        insert_pir_witness(
            st.wallet().conn(),
            notes[0].0,
            &siblings_bytes,
            u32::from(h2) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        let mut bad_root = anchor_root_bytes;
        bad_root[0] ^= 0xFF;
        insert_pir_witness(
            st.wallet().conn(),
            notes[1].0,
            &siblings_bytes,
            u32::from(h2) as u64,
            &bad_root,
        )
        .unwrap();

        delete_orchard_checkpoints(st.wallet().conn());

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(60000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions_pir::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        let err = result.expect_err("Should fail when PIR witnesses have incompatible anchors");
        assert!(
            format!("{err}").contains("incompatible PIR witness anchors"),
            "unexpected error: {err}"
        );
    }

    /// Coin selection includes a note whose shard is NOT fully scanned when a
    /// PIR witness is available. Exercises the `OR EXISTS` branch of
    /// `shard_scanned_condition`.
    #[cfg(all(feature = "orchard", feature = "spendability-pir"))]
    #[test]
    fn pir_witness_enables_selection_for_unscanned_shard() {
        let (mut st, account, note_id, _pos, siblings, anchor_root, anchor_height) =
            real_orchard_witness_fixture!();

        insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings,
            anchor_height,
            &anchor_root,
        )
        .unwrap();

        mark_shards_unscanned(st.wallet().conn());
        delete_orchard_checkpoints(st.wallet().conn());

        let max_priority: i64 = st
            .wallet()
            .conn()
            .query_row(
                "SELECT max_priority FROM v_orchard_shards_scan_state LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            max_priority > 10,
            "shard should appear unscanned (priority {max_priority} > Scanned=10)"
        );

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions_pir::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_ok(),
            "Note in unscanned shard with PIR witness should be spendable: {:?}",
            result.err()
        );
    }

    /// `get_wallet_summary` reports a PIR-witnessed note as spendable even when
    /// its shard is not fully scanned. Exercises the `|| has_pir_witness` branch
    /// in the wallet summary query, separate from coin selection.
    #[cfg(all(feature = "orchard", feature = "spendability-pir"))]
    #[test]
    fn wallet_summary_includes_pir_witnessed_note_as_spendable() {
        let (mut st, account, note_id, _pos, siblings, anchor_root, anchor_height) =
            real_orchard_witness_fixture!();
        let (tip, _) = st.generate_empty_block();
        st.scan_cached_blocks(tip, 1);

        insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings,
            anchor_height,
            &anchor_root,
        )
        .unwrap();

        mark_shards_unscanned(st.wallet().conn());

        let summary = st
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .expect("wallet summary should be present");
        let spendable = summary
            .account_balances()
            .get(&account.id())
            .expect("account balance should exist")
            .orchard_balance()
            .spendable_value();
        assert_eq!(
            spendable,
            Zatoshis::const_from_u64(60_000),
            "PIR-witnessed note in unscanned shard should appear spendable in wallet summary"
        );
    }

    /// Wallet summary aggregation remains note-specific when only a subset of
    /// Orchard notes have PIR witnesses available.
    #[cfg(all(feature = "orchard", feature = "spendability-pir"))]
    #[test]
    fn wallet_summary_only_upgrades_pir_witnessed_notes() {
        use zcash_client_backend::data_api::WalletCommitmentTrees;
        use zcash_client_backend::data_api::testing::{AddressType, TestBuilder};
        use zcash_primitives::block::BlockHash;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::commitment_tree,
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let first_value = Zatoshis::const_from_u64(60_000);
        let second_value = Zatoshis::const_from_u64(80_000);

        let (_h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, first_value);
        st.scan_cached_blocks(_h1, 1);
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, second_value);
        st.scan_cached_blocks(h2, 1);

        let notes = query_orchard_notes(st.wallet().conn());
        let (first_note_id, first_note_position) = notes[0];
        let first_position = incrementalmerkletree::Position::from(first_note_position as u64);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h2)?
                        .expect("root exists");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(first_position, &h2)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        insert_pir_witness(
            st.wallet().conn(),
            first_note_id,
            &siblings_bytes,
            u32::from(h2) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        mark_shards_unscanned(st.wallet().conn());

        let summary = st
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .expect("wallet summary should be present");
        let orchard_balance = summary
            .account_balances()
            .get(&account.id())
            .expect("account balance should exist")
            .orchard_balance();

        assert_eq!(
            orchard_balance.spendable_value(),
            first_value,
            "only the PIR-witnessed Orchard note should remain spendable"
        );
        assert_eq!(
            orchard_balance.value_pending_spendability(),
            second_value,
            "unresolved Orchard notes should remain pending spendability"
        );
        assert_eq!(
            orchard_balance.total(),
            (first_value + second_value).expect("sum should fit in Zatoshi range"),
            "wallet summary should preserve the full Orchard total"
        );
    }

    /// `truncate_to_height` clears the `pir_witness_data` table to avoid stale
    /// authentication paths after a reorg.
    #[cfg(feature = "orchard")]
    #[test]
    fn truncate_to_height_clears_pir_witness_data() {
        use zcash_client_backend::data_api::WalletCommitmentTrees;
        use zcash_client_backend::data_api::testing::{AddressType, TestBuilder};
        use zcash_primitives::block::BlockHash;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::commitment_tree,
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(60000);
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h2, 1);

        let notes = query_orchard_notes(st.wallet().conn());
        let (note_id, note_position) = notes[0];
        let position = incrementalmerkletree::Position::from(note_position as u64);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h2)?
                        .expect("root exists");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h2)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings_bytes,
            u32::from(h2) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        assert!(has_pir_witness(st.wallet().conn(), note_id).unwrap());

        st.truncate_to_height(h1);

        assert!(
            !has_pir_witness(st.wallet().conn(), note_id).unwrap(),
            "PIR witness data should be cleared after truncate_to_height"
        );
    }
}
