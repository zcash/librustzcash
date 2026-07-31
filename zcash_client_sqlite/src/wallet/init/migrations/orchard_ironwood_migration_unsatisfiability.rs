//! Adds the `unsatisfiable_at` and `spend_nullifiers` columns to
//! `orchard_ironwood_migration_transactions` where they are missing, backfills the
//! nullifier cache for existing rows, and adds the `replan_threshold` column to
//! `orchard_ironwood_migrations` where it is missing.
//!
//! `unsatisfiable_at` records the height of the chain state a spent-input observation rests on,
//! when a migration transaction has been determined UNSATISFIABLE — its inputs can never again
//! all exist unspent on chain — and is `NULL` while no such determination stands. Recording the
//! backing height rather than the observation time gives reorg truncation exact semantics: a
//! rewind below this height invalidates the observation itself.
//!
//! `spend_nullifiers` caches the nullifiers of each transaction's REAL spends — the
//! deferred-witness actions; the padded dummy spends carry their own witnesses (ZIP 374) — as a
//! concatenation of 32-byte values in action order. The cache is derivable from a not-yet-proven
//! stored PCZT, but the pool-migration state machine reads it through the store precisely so it never
//! has to parse a PCZT (in the engine crate, `pczt` parsing is `orchard`-gated while the state
//! machine is feature-free). Existing rows therefore must satisfy the same invariant the store's
//! write path maintains, so this migration derives the cache for them by parsing each row's
//! stored PCZT — using the base `pczt` data model, which needs no protocol feature. A stored
//! PCZT that does not parse is corrupt state and fails the migration, matching how the store's
//! read paths reject data they cannot reconstruct. So does a not-yet-`mined` row whose PCZT
//! parses but yields NO real spends: that is the shape of a PROVEN PCZT (proving installs the
//! deferred witnesses), from which the cache can no longer be reconstructed. A `mined` row with
//! such bytes is exempt and keeps an empty cache — hard-failing it would block every wallet
//! whose migration already completed, for no benefit while the row stays mined. The exemption
//! carries a residual hazard: mined-ness is chain-derived and revocable, so a chain rewind that
//! demotes such a row returns it to the watched set with an empty cache, which satisfiability
//! consumers must treat as loud corruption (the real spends were never identifiable), never as
//! a transaction with no inputs to observe.
//!
//! `replan_threshold` is the integer percent of planned transfer value, unsatisfiable, above which
//! a migration is re-planned immediately rather than after satisfiable work drains — stamped on
//! `orchard_ironwood_migrations` at commit. A migration committed before this column existed
//! carries no such stamp, so it backfills to the same default the store's `CREATE TABLE` and this
//! `ADD COLUMN` share (`ReplanThreshold::DEFAULT`'s percent), which is the policy every migration
//! committed before this migration was, in fact, evaluated under.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::orchard_ironwood_migration_anchor_interval;
use crate::wallet::init::WalletMigrationError;

/// Adds the `unsatisfiable_at` and `spend_nullifiers` columns to
/// `orchard_ironwood_migration_transactions`, and the `replan_threshold` column to
/// `orchard_ironwood_migrations`, where they are missing.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xd334a9fa_b9dc_46bd_9b31_1fba6aa47f55);

const DEPENDENCIES: &[Uuid] = &[orchard_ironwood_migration_anchor_interval::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the unsatisfiable_at and spend_nullifiers columns to \
         orchard_ironwood_migration_transactions, and the replan_threshold column to \
         orchard_ironwood_migrations, where missing."
    }
}

/// The concatenated nullifiers of the REAL spends of the PCZT serialized in `pczt_bytes`: the
/// Orchard actions whose spend carries no Merkle witness (ZIP 374 defers the real spends'
/// witnesses to proving time, while the padding dummies keep their arbitrary witnesses), in
/// action order. A PCZT that does not parse is corrupt state and yields
/// [`WalletMigrationError::CorruptedData`].
fn real_spend_nullifiers(pczt_bytes: &[u8]) -> Result<Vec<u8>, WalletMigrationError> {
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| {
        WalletMigrationError::CorruptedData(format!(
            "stored pool-migration PCZT does not parse: {e:?}"
        ))
    })?;
    Ok(pczt
        .orchard()
        .actions()
        .iter()
        .filter(|action| action.spend().witness().is_none())
        .flat_map(|action| *action.spend().nullifier())
        .collect())
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // A wallet whose table was created from the current DDL already has the columns; adding
        // them again is an error rather than a no-op, so the presence check is load-bearing. The
        // two columns are introduced together (by this migration or by the current `CREATE
        // TABLE`), so one check governs both — and on the fresh path the store itself wrote
        // `spend_nullifiers`, so there is nothing to backfill either.
        let has_tx_columns = transaction.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migration_transactions')
                WHERE name = :column_name
             )",
            named_params![":column_name": "spend_nullifiers"],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_tx_columns {
            // The `DEFAULT` matches the one carried by the current `CREATE TABLE`, so the two
            // paths agree on the stored schema text (SQLite cannot add a `NOT NULL` column
            // without one); the store always binds the column explicitly, so no insert ever
            // falls back to it.
            transaction.execute_batch(
                "ALTER TABLE orchard_ironwood_migration_transactions
                    ADD COLUMN unsatisfiable_at INTEGER;
                 ALTER TABLE orchard_ironwood_migration_transactions
                    ADD COLUMN spend_nullifiers BLOB NOT NULL DEFAULT X'';",
            )?;

            // Backfill the nullifier cache for every existing row from its stored PCZT. No
            // non-`mined` row is left at the empty default: an empty cache on a transaction that
            // HAS real spends would read as "no inputs to observe" to the unsatisfiability
            // machinery, silently exempting the transaction from detection.
            let rows: Vec<(i64, u32, Vec<u8>, String)> = {
                let mut stmt = transaction.prepare(
                    "SELECT migration_id, tx_id, pczt, state
                       FROM orchard_ironwood_migration_transactions",
                )?;
                let mapped = stmt.query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get(3)?,
                    ))
                })?;
                mapped.collect::<Result<_, _>>()?
            };
            for (migration_id, tx_id, pczt_bytes, state) in rows {
                let spend_nullifiers = real_spend_nullifiers(&pczt_bytes)?;
                // An empty extraction means the stored bytes are a PROVEN PCZT: every built
                // migration PCZT defers at least one real spend's witness, and proving is what
                // installs them all. The cache cannot be reconstructed from such bytes, which is
                // fatal for any row the unsatisfiability machinery still watches. A `mined` row
                // alone is exempt and keeps the empty cache — hard-failing it would block every
                // completed-migration wallet for no benefit — at the cost that a chain rewind
                // demoting the row leaves it watched with an empty cache, which downstream
                // satisfiability machinery must treat as loud corruption rather than vacuous
                // satisfiability.
                if spend_nullifiers.is_empty() && state != "mined" {
                    return Err(WalletMigrationError::CorruptedData(format!(
                        "pool-migration transaction (migration {migration_id}, tx {tx_id}, \
                         state '{state}') stores a PCZT whose real spends are no longer \
                         identifiable (proven bytes, or deeper corruption); this state was \
                         persisted before the nullifier cache existed, and the migration cannot \
                         be resumed: the remaining balance must be re-planned"
                    )));
                }
                transaction.execute(
                    "UPDATE orchard_ironwood_migration_transactions
                        SET spend_nullifiers = :spend_nullifiers
                      WHERE migration_id = :migration_id AND tx_id = :tx_id",
                    named_params! {
                        ":spend_nullifiers": spend_nullifiers,
                        ":migration_id": migration_id,
                        ":tx_id": tx_id,
                    },
                )?;
            }
        }

        // `replan_threshold` lives on a different table (`orchard_ironwood_migrations`), so its
        // presence is checked and repaired independently of the transactions-table columns above.
        let has_replan_threshold = transaction.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migrations')
                WHERE name = :column_name
             )",
            named_params![":column_name": "replan_threshold"],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_replan_threshold {
            // The `DEFAULT` matches the one carried by the current `CREATE TABLE`
            // (`ReplanThreshold::DEFAULT`'s percent), so the two paths agree on the stored schema
            // text. SQLite's `ADD COLUMN ... DEFAULT` itself backfills every existing row to that
            // value — the policy every migration committed before this column existed was, in
            // fact, evaluated under; the store always binds the column explicitly on write, so no
            // FUTURE insert ever falls back to it.
            transaction.execute_batch(
                "ALTER TABLE orchard_ironwood_migrations
                    ADD COLUMN replan_threshold INTEGER NOT NULL DEFAULT 20;",
            )?;
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, named_params};

    use super::*;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// The pre-fix schema: `orchard_ironwood_migration_transactions` without `unsatisfiable_at`
    /// and `spend_nullifiers`, which is what a wallet built before this migration has on disk.
    fn create_pre_fix_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE orchard_ironwood_migration_transactions (
                migration_id INTEGER NOT NULL,
                tx_id INTEGER NOT NULL,
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
                PRIMARY KEY (migration_id, tx_id)
            )",
        )
        .unwrap();
    }

    fn has_columns(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT (
                SELECT COUNT(*) FROM pragma_table_info('orchard_ironwood_migration_transactions')
                WHERE name IN ('unsatisfiable_at', 'spend_nullifiers')
             ) = 2",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    }

    /// The pre-fix schema: `orchard_ironwood_migrations` without `replan_threshold`, which is what
    /// a wallet built before this migration has on disk.
    fn create_pre_fix_migrations_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE orchard_ironwood_migrations (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                note_split_fee_buffer INTEGER NOT NULL,
                note_split_change INTEGER,
                note_split_prep_fees INTEGER NOT NULL,
                note_split_total_input INTEGER NOT NULL,
                note_split_total_migratable INTEGER NOT NULL,
                anchor_bucket_interval INTEGER NOT NULL DEFAULT 144
            )",
        )
        .unwrap();
    }

    fn has_replan_threshold_column(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migrations')
                WHERE name = 'replan_threshold'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    }

    /// Insert a pre-fix transactions row carrying `pczt`, a transfer in the given `state` (the
    /// other columns are immaterial to the backfill).
    fn insert_pre_fix_row(conn: &Connection, tx_id: u32, pczt: &[u8], state: &str) {
        conn.execute(
            "INSERT INTO orchard_ironwood_migration_transactions (
                migration_id, tx_id, kind, kind_crossing, pczt, scheduled_height, expiry_height,
                state
             )
             VALUES (1, :tx_id, 'transfer', 0, :pczt, 200, 240, :state)",
            named_params![":tx_id": tx_id, ":pczt": pczt, ":state": state],
        )
        .unwrap();
    }

    /// The fresh path: the tables already carry the columns, so `up` must leave them alone rather
    /// than fail with "duplicate column name".
    #[test]
    fn is_a_no_op_when_the_columns_are_present() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::pool_migration::orchard_ironwood::init_migration_tables(&conn).unwrap();
        assert!(has_columns(&conn));
        assert!(has_replan_threshold_column(&conn));

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_columns(&conn));
        assert!(has_replan_threshold_column(&conn));
    }

    /// A stored PCZT that does not parse is corrupt state: the migration surfaces
    /// [`WalletMigrationError::CorruptedData`] rather than leaving the row's nullifier cache
    /// silently empty (which would exempt the transaction from unsatisfiability detection).
    #[test]
    fn an_unparseable_stored_pczt_fails_the_migration() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        insert_pre_fix_row(&conn, 0, &[1, 2, 3], "signed");

        let tx = conn.transaction().unwrap();
        let result = RusqliteMigration::up(&Migration, &tx);
        assert!(matches!(
            result,
            Err(WalletMigrationError::CorruptedData(_))
        ));
    }

    /// The upgrade path on empty tables: both pre-fix tables (the sibling `orchard_ironwood_migrations`
    /// and `orchard_ironwood_migration_transactions` tables a real wallet always carries together)
    /// get their columns added, and nothing needs backfilling.
    #[test]
    fn adds_columns_to_empty_pre_fix_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        create_pre_fix_migrations_table(&conn);
        assert!(!has_columns(&conn));
        assert!(!has_replan_threshold_column(&conn));

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_columns(&conn));
        assert!(has_replan_threshold_column(&conn));
    }

    /// The upgrade path with data: an existing `orchard_ironwood_migrations` row is backfilled
    /// with `ReplanThreshold::DEFAULT`'s percent — the policy every migration committed before this
    /// column existed was, in fact, evaluated under.
    #[test]
    fn backfills_replan_threshold_to_the_default_for_existing_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        // The sibling transactions table is a real wallet's pre-fix state too, so `up` reaches
        // the migrations-table part in the same shape it would in production.
        create_pre_fix_table(&conn);
        create_pre_fix_migrations_table(&conn);
        conn.execute(
            "INSERT INTO orchard_ironwood_migrations (
                account_id, status, note_split_fee_buffer, note_split_prep_fees,
                note_split_total_input, note_split_total_migratable
             )
             VALUES (1, 'committed', 15000, 30000, 100000000, 100000000)",
            [],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        let replan_threshold: u32 = conn
            .query_row(
                "SELECT replan_threshold FROM orchard_ironwood_migrations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            replan_threshold,
            u32::from(zcash_pool_migration::engine::ReplanThreshold::DEFAULT.percent()),
        );
    }

    /// A REAL serialized migration transfer (built by `zcash_pool_migration`'s builder against a
    /// local network with NU6.3 active), paired with its one real spend's nullifier.
    #[cfg(feature = "orchard")]
    fn built_transfer_pczt() -> (Vec<u8>, [u8; 32]) {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
        use orchard::value::NoteValue;
        use rand_chacha::ChaCha8Rng;
        use rand_core::{RngCore, SeedableRng};
        use zcash_client_backend::data_api::testing::TestBuilder;
        use zcash_pool_migration::build::build_transfer_pczt;
        use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
        use zcash_protocol::consensus::BlockHeight;
        use zcash_protocol::local_consensus::LocalNetwork;
        use zcash_protocol::value::Zatoshis;

        /// A deterministic Orchard full viewing key (drawing bytes until they form a valid
        /// spending key).
        fn test_fvk() -> FullViewingKey {
            let mut rng = ChaCha8Rng::seed_from_u64(11);
            loop {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                if let Some(sk) = SpendingKey::from_bytes(bytes).into_option() {
                    return FullViewingKey::from(&sk);
                }
            }
        }

        /// An Orchard note of `value` owned by `fvk`, with deterministic randomness (drawing
        /// bytes until they form a valid `rho`/`rseed` pair).
        fn note_owned_by(fvk: &FullViewingKey, value: u64) -> Note {
            let mut rng = ChaCha8Rng::seed_from_u64(7);
            loop {
                let mut rho_bytes = [0u8; 32];
                rng.fill_bytes(&mut rho_bytes);
                let Some(rho) = Rho::from_bytes(&rho_bytes).into_option() else {
                    continue;
                };
                let mut rseed_bytes = [0u8; 32];
                rng.fill_bytes(&mut rseed_bytes);
                let Some(rseed) = RandomSeed::from_bytes(rseed_bytes, &rho).into_option() else {
                    continue;
                };
                if let Some(note) = Note::from_parts(
                    fvk.address_at(0u32, Scope::External),
                    NoteValue::from_raw(value),
                    rho,
                    rseed,
                    NoteVersion::V2,
                )
                .into_option()
                {
                    return note;
                }
            }
        }

        // A network with NU6.3 active below the transfer's target height, so the V6 format that
        // permits deferred anchors is available.
        let activation = BlockHeight::from_u32(100);
        let network = LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };

        // A self-funding note: the crossing value plus the transfer's exact ZIP 317 fee (three
        // actions: the real spend, its Orchard padding dummy, and the Ironwood output).
        let fvk = test_fvk();
        let crossing = 100_000_000u64;
        let fee = 3 * MARGINAL_FEE.into_u64();
        let note = note_owned_by(&fvk, crossing + fee);
        let nullifier = note.nullifier(&fvk).to_bytes();

        let pczt = build_transfer_pczt(
            &network,
            200,
            240,
            &fvk,
            note,
            Zatoshis::const_from_u64(crossing),
            None,
            ChaCha8Rng::seed_from_u64(13),
        )
        .expect("the self-funding note builds a balanced transfer");
        let pczt_bytes = pczt.serialize().expect("a built PCZT serializes");
        (pczt_bytes, nullifier)
    }

    /// The PROVEN shape of a built migration PCZT: every deferred spend witness installed, which
    /// is the structural effect proving has on the stored bytes, so the deferred-witness rule no
    /// longer identifies any real spend. The paths are arbitrary (single-leaf trees); nothing
    /// under test inspects them.
    #[cfg(feature = "orchard")]
    fn proven_shaped(pczt_bytes: &[u8]) -> Vec<u8> {
        use incrementalmerkletree::{Hashable, Level};
        use orchard::tree::{MerkleHashOrchard, MerklePath};

        let parsed = pczt::Pczt::parse(pczt_bytes).expect("the built PCZT parses");
        let deferred: Vec<usize> = parsed
            .orchard()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().witness().is_none())
            .map(|(index, _)| index)
            .collect();
        assert!(
            !deferred.is_empty(),
            "a built migration PCZT defers its real spends' witnesses"
        );
        let witnesses = deferred.into_iter().map(|index| {
            let auth_path = core::array::from_fn(|level| {
                MerkleHashOrchard::empty_root(Level::from(level as u8))
            });
            (index, MerklePath::from_parts(0, auth_path))
        });
        pczt::roles::updater::Updater::new(parsed)
            .set_orchard_spend_witnesses(witnesses)
            .expect("the witnesses install on the deferred spends")
            .finish()
            .serialize()
            .expect("the proven-shaped PCZT serializes")
    }

    /// The upgrade path with data: a row whose `pczt` column holds a REAL serialized migration
    /// transfer is backfilled with exactly its real spend's nullifier — the padding dummy spend
    /// (which carries its own witness) contributes nothing — and `unsatisfiable_at` starts out
    /// `NULL` (no spent-input observation stands).
    #[cfg(feature = "orchard")]
    #[test]
    fn backfills_real_spend_nullifiers_from_the_stored_pczt() {
        let (pczt_bytes, expected_nullifier) = built_transfer_pczt();

        // The bundle carries more spends than the one real one (the padding dummy at least), so
        // the exact-32-byte assertion below is load-bearing for the witness filter.
        let parsed = pczt::Pczt::parse(&pczt_bytes).expect("the serialized PCZT parses back");
        assert!(parsed.orchard().actions().len() >= 2);

        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        create_pre_fix_migrations_table(&conn);
        insert_pre_fix_row(&conn, 0, &pczt_bytes, "signed");

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        let (unsatisfiable_at, spend_nullifiers) = conn
            .query_row(
                "SELECT unsatisfiable_at, spend_nullifiers
                   FROM orchard_ironwood_migration_transactions",
                [],
                |row| Ok((row.get::<_, Option<u32>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .unwrap();
        assert_eq!(unsatisfiable_at, None);
        assert_eq!(spend_nullifiers, expected_nullifier.to_vec());
    }

    /// A not-yet-mined row whose stored PCZT is already PROVEN — every spend witness installed,
    /// the shape `proved` and `broadcast` rows have once the proving flow has run — fails the
    /// migration loudly: the deferred-witness rule extracts nothing from proven bytes, so the
    /// nullifier cache cannot be reconstructed, and writing it empty would silently exempt the
    /// transaction from unsatisfiability detection.
    #[cfg(feature = "orchard")]
    #[test]
    fn a_proven_pczt_on_a_non_mined_row_fails_the_migration() {
        let (pczt_bytes, _) = built_transfer_pczt();
        let proven = proven_shaped(&pczt_bytes);

        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        insert_pre_fix_row(&conn, 0, &proven, "broadcast");

        let tx = conn.transaction().unwrap();
        let result = RusqliteMigration::up(&Migration, &tx);
        assert!(matches!(
            result,
            Err(WalletMigrationError::CorruptedData(_))
        ));
    }

    /// The same proven bytes on a `mined` row are exempt: the transaction is terminal, so no
    /// satisfiability question remains for the cache to answer, and the row keeps the empty
    /// cache.
    #[cfg(feature = "orchard")]
    #[test]
    fn a_proven_pczt_on_a_mined_row_keeps_the_empty_cache() {
        let (pczt_bytes, _) = built_transfer_pczt();
        let proven = proven_shaped(&pczt_bytes);

        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        create_pre_fix_migrations_table(&conn);
        insert_pre_fix_row(&conn, 0, &proven, "mined");

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        let spend_nullifiers: Vec<u8> = conn
            .query_row(
                "SELECT spend_nullifiers FROM orchard_ironwood_migration_transactions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(spend_nullifiers.is_empty());
    }
}
