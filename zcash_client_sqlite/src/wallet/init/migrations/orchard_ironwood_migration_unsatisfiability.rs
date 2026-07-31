//! Renames the pool-migration transfer ordinal from `tx_id` to `transfer_id`, adds the
//! `unsatisfiable_at`, `spend_nullifiers`, `unsatisfiable_kind`, and `broadcast_failure_at` columns
//! to `orchard_ironwood_migration_transactions` where they are missing, backfills the nullifier
//! cache for existing rows, restores the erased `txid` of every `mined` row, and adds the
//! `replan_threshold` column to `orchard_ironwood_migrations` where it is missing.
//!
//! The rename removes a collision between two similarly spelled columns of
//! `orchard_ironwood_migration_transactions` that name unrelated things: the transaction's ordinal
//! WITHIN its migration (a `MigrationTransferId`, and the second half of the table's primary key,
//! which the dependency edges reference), and `txid`, the consensus transaction ID the transaction
//! was broadcast under. `transfer_id` names the first unambiguously, and the dependency table's two
//! columns follow it to `transfer_id` and `depends_on_transfer_id`, so no reader has to hold the
//! distinction in mind to read a query.
//!
//! `tx_id` is what [`orchard_ironwood_migration_tables`] creates, and — since that migration is
//! published — is what it will always create, from a frozen copy of its original DDL. That is what
//! makes the rename here unconditional: every database arrives at this migration with the old name,
//! whether it was created before these columns existed or a moment ago, so both paths leave the
//! same schema text behind.
//!
//! `unsatisfiable_at` records the height of the chain state a spent-input observation rests on,
//! when a migration transaction has been determined UNSATISFIABLE — its inputs can never again
//! all exist unspent on chain — and is `NULL` while no such determination stands. A rewind below
//! that height invalidates the observation itself, which is what reorg truncation clears the mark
//! by comparing against.
//!
//! `unsatisfiable_kind` records WHICH observation that was, as the wire name of an
//! `UnsatisfiableKind` (`inputs_spent`, `inputs_invalidated`, `anchor_invalidated`, or
//! `inherited` for a mark that arrived through the dependency closure rather than from anything
//! observed about the transaction itself). It is the mark's companion, not an independent
//! record: the two columns are `NULL` together or non-`NULL` together, and the store rejects a
//! row where they disagree. Existing rows need no backfill — a pre-existing database has no
//! `unsatisfiable_at` column either, so no mark can predate this one.
//!
//! `broadcast_failure_at` records the chain tip an application observed from a node that REJECTED
//! a broadcast of the transaction, and is `NULL` while no rejection stands unadjudicated. It is
//! testimony from another observer rather than an observation of this wallet's own, which is why
//! it is a separate column from the mark: it withholds the transaction from the broadcast queue
//! until the wallet has scanned to that tip and the engine can decide the question against
//! evidence. Existing rows need no backfill for the same reason the kind does not — a database
//! predating these columns recorded no such report.
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
//! The `txid` of a `mined` row is restored because a published release erased it: both store write
//! paths bound that column through one accessor covering the two states that carry a txid, and that
//! accessor answered `None` for `mined`, so every transaction that reached `mined` lost the txid it
//! had been broadcast under. The reconstructing reader now requires it, so without this repair a
//! wallet that completed a migration could never read its store back. See [`backfill_mined_txids`]
//! for where the txid is recovered from and why it is not derived from the stored transaction.
//!
//! `replan_threshold` is the integer percent of planned transfer value, unsatisfiable, above which
//! a migration is re-planned immediately rather than after satisfiable work drains — stamped on
//! `orchard_ironwood_migrations` at commit. A migration committed before this column existed
//! carries no such stamp, so it backfills to the same default the store's `CREATE TABLE` and this
//! `ADD COLUMN` share (`ReplanThreshold::DEFAULT`'s percent), which is the policy every migration
//! committed before this migration was, in fact, evaluated under.
//!
//! [`orchard_ironwood_migration_tables`]: super::orchard_ironwood_migration_tables

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::orchard_ironwood_migration_anchor_interval;
use crate::wallet::init::WalletMigrationError;

/// Renames `tx_id` to `transfer_id`, adds the `unsatisfiable_at`, `spend_nullifiers`,
/// `unsatisfiable_kind`, and `broadcast_failure_at` columns to
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
        "Renames the pool-migration transfer ordinal from tx_id to transfer_id, adds the \
         unsatisfiable_at, spend_nullifiers, unsatisfiable_kind, and broadcast_failure_at columns \
         to orchard_ironwood_migration_transactions, and the replan_threshold column to \
         orchard_ironwood_migrations, where missing."
    }
}

/// The concatenated nullifiers of the REAL spends of the PCZT serialized in `pczt_bytes`: the
/// Orchard actions whose spend carries no Merkle witness (ZIP 374 defers the real spends'
/// witnesses to proving time, while the padding dummies keep their arbitrary witnesses), in
/// action order. A PCZT that does not parse is corrupt state and yields
/// [`WalletMigrationError::CorruptedData`].
///
/// The witness filter is the real-spend RULE, not a defensive skip: `witness` is a genuinely
/// optional PCZT field, and in an unproven migration PCZT it is exactly the padding dummies that
/// have it. Dropping the filter would fold the dummies' nullifiers — which correspond to no note
/// this wallet holds — into the cache, and the satisfiability oracle would then ask the wallet
/// about notes it has never seen and answer `NotYetSatisfiable` forever. `zcash_pool_migration`'s
/// `pczt_spends` module is the canonical statement of the rule and pins it with a proptest over
/// builder-produced PCZTs; this is its feature-free mirror, because a wallet schema migration must
/// run in a build without this crate's `orchard` feature.
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

/// Restore the `txid` of every `mined` pool-migration transaction that carries none.
///
/// Two tables' `txid` columns appear below and hold the same kind of value from different sources:
/// on `orchard_ironwood_migration_transactions` it is what this repair writes, and on the wallet's
/// own `transactions` it is that consensus ID as the scanner recorded it, which is where the value
/// comes from. Every occurrence is qualified by its table. (This runs after the rename above, so
/// the transfer ordinal is `transfer_id` here and no longer reads as a third `txid`.)
///
/// A migration transaction's lifecycle state was stored through one accessor for both states that
/// carry a txid, and until recently that accessor answered `None` for `mined`: every row a
/// published release moved from `broadcast` to `mined` had its txid ERASED on the way. The
/// reconstructing reader now requires it — a mined transaction was always broadcast under a txid
/// first, so `mined` without one is not a state the type admits — which would leave every wallet
/// that completed a migration unable to read its own store back, permanently and with no way to
/// repair it. So the txid is recovered here, once, where the condition can still be reported.
///
/// It is recovered from the WALLET's own record of the same event, not from the stored transaction:
/// the migration transaction spent notes belonging to this wallet, and a note is spent by exactly
/// one mined transaction, so the spend the scanner recorded names the txid directly. The stored
/// PCZT supplies the nullifiers to look up — every action's, since a proven PCZT no longer
/// distinguishes the real spends from their padding dummies, and a dummy's nullifier simply
/// matches nothing.
///
/// Deriving the txid from the stored bytes instead would be self-contained but is the wrong
/// instrument here. The only public route to a txid over a PCZT is the Transaction Extractor,
/// which VERIFIES every proof on the way — building an Orchard verifying key on the fly when none
/// is supplied — so a schema migration would pay seconds to minutes of proof verification per
/// completed migration, to learn a hash the wallet already has. It is also unavailable in a build
/// without this crate's `orchard` feature, whereas the tables consulted here exist in every build.
///
/// A row whose txid cannot be recovered — the wallet never scanned the transaction that spent its
/// own notes, or the spend record is gone — fails the migration naming the row. That is a loud,
/// actionable condition at upgrade time, rather than a store that silently reads back as corrupt
/// ever after.
fn backfill_mined_txids(conn: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
    let rows: Vec<(i64, u32, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT mtx.migration_id, mtx.transfer_id, mtx.pczt
               FROM orchard_ironwood_migration_transactions mtx
              WHERE mtx.state = 'mined' AND mtx.txid IS NULL",
        )?;
        let mapped = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get::<_, Vec<u8>>(2)?))
        })?;
        mapped.collect::<Result<_, _>>()?
    };

    for (migration_id, transfer_id, pczt_bytes) in rows {
        let txid = recover_mined_txid(conn, &pczt_bytes)?.ok_or_else(|| {
            WalletMigrationError::CorruptedData(format!(
                "pool-migration transaction (migration {migration_id}, transfer {transfer_id}) is \
                 recorded mined but stores no txid, and none of the notes its stored PCZT spends \
                 is recorded as spent by a mined transaction in this wallet, so the txid it was \
                 mined under cannot be recovered"
            ))
        })?;
        conn.execute(
            "UPDATE orchard_ironwood_migration_transactions
                SET txid = :txid
              WHERE migration_id = :migration_id AND transfer_id = :transfer_id",
            named_params! {
                ":txid": txid,
                ":migration_id": migration_id,
                ":transfer_id": transfer_id,
            },
        )?;
    }
    Ok(())
}

/// The txid the transaction stored as `pczt_bytes` was mined under, as this wallet recorded it, or
/// `None` if its spends name no single mined transaction.
///
/// Every action's nullifier is looked up among the account's Orchard notes; a real spend matches
/// the note it consumed and a padding dummy matches nothing. All of a transaction's real spends
/// were consumed by the same mined transaction, so the recovered set has exactly one member for a
/// recoverable row — anything else (none, or a disagreement) declines rather than guessing.
///
/// The answer is read from the WALLET's `transactions` table, whose `txid` column holds the same
/// consensus identifier the pool-migration store's own `txid` column does — as raw bytes here, and
/// as hex text there, which is the encoding this returns.
fn recover_mined_txid(
    conn: &rusqlite::Transaction,
    pczt_bytes: &[u8],
) -> Result<Option<String>, WalletMigrationError> {
    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| {
        WalletMigrationError::CorruptedData(format!(
            "stored pool-migration PCZT does not parse: {e:?}"
        ))
    })?;

    let mut stmt = conn.prepare(
        "SELECT DISTINCT wallet_tx.txid
           FROM transactions wallet_tx
           JOIN orchard_received_note_spends spend
                ON spend.transaction_id = wallet_tx.id_tx
           JOIN orchard_received_notes note
                ON note.id = spend.orchard_received_note_id
          WHERE note.nf = :nf AND wallet_tx.mined_height IS NOT NULL",
    )?;
    let mut found = HashSet::new();
    for action in pczt.orchard().actions() {
        let rows = stmt.query_map(
            named_params! {":nf": action.spend().nullifier().as_slice()},
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        for txid in rows {
            found.insert(hex::encode(txid?));
        }
    }

    Ok(if found.len() == 1 {
        found.into_iter().next()
    } else {
        None
    })
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // The rename runs first, so every statement below — and every store query written against
        // the schema this migration leaves behind — speaks `transfer_id`.
        //
        // It is UNCONDITIONAL, unlike the column repairs below, because every database reaching
        // this migration has the old names: `orchard_ironwood_migration_tables` is published, so it
        // creates its tables from a frozen copy of the DDL it shipped with, and a database that
        // predates it does not have the tables at all. Fresh and upgraded wallets therefore travel
        // the identical path here, which is what lets the created and renamed schemas be one text.
        //
        // SQLite rewrites the stored schema for each rename: the transactions table's own
        // definition and primary key, the dependency table's foreign key into it, and (were there
        // one) any index naming the column. Only the schema text changes; no row is rewritten, and
        // the `ON DELETE CASCADE` from the transactions table to its dependency edges survives
        // because it is the same constraint under a new column name.
        transaction.execute_batch(
            "ALTER TABLE orchard_ironwood_migration_transactions
                RENAME COLUMN tx_id TO transfer_id;
             ALTER TABLE orchard_ironwood_migration_transaction_deps
                RENAME COLUMN tx_id TO transfer_id;
             ALTER TABLE orchard_ironwood_migration_transaction_deps
                RENAME COLUMN depends_on_tx_id TO depends_on_transfer_id;",
        )?;

        // A wallet whose table was created from the current DDL already has the columns; adding
        // them again is an error rather than a no-op, so the presence check is load-bearing. The
        // four columns are introduced together (by this migration or by the current `CREATE
        // TABLE`), so one check governs all of them — and on the fresh path the store itself wrote
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
            //
            // `unsatisfiable_kind` and `broadcast_failure_at` need no backfill and no default: a
            // database that lacked `unsatisfiable_at` carried neither a mark nor a
            // broadcast-failure report, so every existing row is correctly unmarked and
            // unreported with all three columns `NULL`. The columns are added in the same order
            // the current `CREATE TABLE` lists them, so the created and repaired schemas stay
            // comparable.
            transaction.execute_batch(
                "ALTER TABLE orchard_ironwood_migration_transactions
                    ADD COLUMN unsatisfiable_at INTEGER;
                 ALTER TABLE orchard_ironwood_migration_transactions
                    ADD COLUMN spend_nullifiers BLOB NOT NULL DEFAULT X'';
                 ALTER TABLE orchard_ironwood_migration_transactions
                    ADD COLUMN unsatisfiable_kind TEXT;
                 ALTER TABLE orchard_ironwood_migration_transactions
                    ADD COLUMN broadcast_failure_at INTEGER;",
            )?;

            // Backfill the nullifier cache for every existing row from its stored PCZT. No
            // non-`mined` row is left at the empty default: an empty cache on a transaction that
            // HAS real spends would read as "no inputs to observe" to the unsatisfiability
            // machinery, silently exempting the transaction from detection.
            let rows: Vec<(i64, u32, Vec<u8>, String)> = {
                let mut stmt = transaction.prepare(
                    "SELECT migration_id, transfer_id, pczt, state
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
            for (migration_id, transfer_id, pczt_bytes, state) in rows {
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
                        "pool-migration transaction (migration {migration_id}, transfer \
                         {transfer_id}, state '{state}') stores a PCZT whose real spends are no \
                         longer identifiable (proven bytes, or deeper corruption); this state was \
                         persisted before the nullifier cache existed, and the migration cannot \
                         be resumed: the remaining balance must be re-planned"
                    )));
                }
                transaction.execute(
                    "UPDATE orchard_ironwood_migration_transactions
                        SET spend_nullifiers = :spend_nullifiers
                      WHERE migration_id = :migration_id AND transfer_id = :transfer_id",
                    named_params! {
                        ":spend_nullifiers": spend_nullifiers,
                        ":migration_id": migration_id,
                        ":transfer_id": transfer_id,
                    },
                )?;
            }
        }

        backfill_mined_txids(transaction)?;

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

    /// The pool-migration tables exactly as the released `orchard_ironwood_migration_tables`
    /// creates them, which is the state a freshly created database reaches this migration in. (One
    /// created before the columns repaired below existed has the shape `create_pre_fix_table`
    /// builds instead; both name the transfer ordinal `tx_id`.)
    fn create_released_tables(conn: &Connection) {
        conn.execute_batch(super::super::orchard_ironwood_migration_tables::CREATE_TABLES_SQL)
            .unwrap();
    }

    /// Whether `orchard_ironwood_migration_transactions` names its transfer ordinal `column`.
    fn transactions_has_column(conn: &Connection, column: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migration_transactions')
                WHERE name = :column_name
             )",
            named_params![":column_name": column],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    }

    /// The pre-fix schema: `orchard_ironwood_migration_transactions` without `unsatisfiable_at`
    /// and `spend_nullifiers`, which is what a wallet built before this migration has on disk,
    /// beside the dependency table that has always accompanied it (unchanged since it was created,
    /// and the target of one of the renames).
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
            );
            CREATE TABLE orchard_ironwood_migration_transaction_deps (
                migration_id INTEGER NOT NULL,
                tx_id INTEGER NOT NULL,
                ordinal INTEGER NOT NULL,
                depends_on_tx_id INTEGER NOT NULL,
                PRIMARY KEY (migration_id, tx_id, ordinal),
                FOREIGN KEY (migration_id, tx_id)
                    REFERENCES orchard_ironwood_migration_transactions(migration_id, tx_id)
                    ON DELETE CASCADE
            )",
        )
        .unwrap();
    }

    fn has_columns(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT (
                SELECT COUNT(*) FROM pragma_table_info('orchard_ironwood_migration_transactions')
                WHERE name IN ('unsatisfiable_at', 'spend_nullifiers', 'unsatisfiable_kind',
                               'broadcast_failure_at')
             ) = 4",
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

    /// The fresh path: the tables the released creating migration builds already carry every
    /// column, so `up` must add none of them again (which would fail with "duplicate column
    /// name") — while still renaming, since that migration creates `tx_id` on every database it
    /// will ever run on.
    #[test]
    fn renames_but_adds_nothing_on_a_freshly_created_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_released_tables(&conn);
        assert!(has_columns(&conn));
        assert!(has_replan_threshold_column(&conn));
        assert!(transactions_has_column(&conn, "tx_id"));

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_columns(&conn));
        assert!(has_replan_threshold_column(&conn));
        assert!(transactions_has_column(&conn, "transfer_id"));
        assert!(!transactions_has_column(&conn, "tx_id"));
    }

    /// A dependency edge is still removed with the transfer it hangs off, after the rename has
    /// rewritten the foreign key that enforces it: the constraint is the same one under new column
    /// names, and nothing about the rows changed.
    #[test]
    fn the_dependency_cascade_survives_the_rename() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE accounts (id INTEGER PRIMARY KEY);")
            .unwrap();
        create_released_tables(&conn);
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (id) VALUES (1);
             INSERT INTO orchard_ironwood_migrations (
                id, account_id, status, note_split_fee_buffer, note_split_prep_fees,
                note_split_total_input, note_split_total_migratable
             )
             VALUES (1, 1, 'committed', 0, 0, 0, 0);
             INSERT INTO orchard_ironwood_migration_transactions (
                migration_id, tx_id, kind, kind_crossing, pczt, scheduled_height, expiry_height,
                state
             )
             VALUES (1, 0, 'transfer', 0, X'00', 200, 240, 'signed'),
                    (1, 1, 'transfer', 1, X'00', 200, 240, 'signed');
             INSERT INTO orchard_ironwood_migration_transaction_deps (
                migration_id, tx_id, ordinal, depends_on_tx_id
             )
             VALUES (1, 1, 0, 0);",
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        conn.execute(
            "DELETE FROM orchard_ironwood_migration_transactions WHERE transfer_id = 1",
            [],
        )
        .unwrap();
        let remaining: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM orchard_ironwood_migration_transaction_deps",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "the edge cascaded with the transfer it names");
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
    /// get their columns added and the transfer ordinal renamed, and nothing needs backfilling.
    #[test]
    fn adds_columns_to_empty_pre_fix_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        create_pre_fix_migrations_table(&conn);
        assert!(!has_columns(&conn));
        assert!(!has_replan_threshold_column(&conn));
        assert!(transactions_has_column(&conn, "tx_id"));

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_columns(&conn));
        assert!(has_replan_threshold_column(&conn));
        assert!(transactions_has_column(&conn, "transfer_id"));
        assert!(!transactions_has_column(&conn, "tx_id"));
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
    /// (which carries its own witness) contributes nothing — and `unsatisfiable_at`,
    /// `unsatisfiable_kind`, and `broadcast_failure_at` all start out `NULL`: a database that had
    /// none of these columns carried neither an unsatisfiability observation nor a
    /// broadcast-failure report, so there is nothing for them to say. The row's transfer ordinal
    /// arrives under its new name, with nothing left answering to the old one.
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

        assert!(transactions_has_column(&conn, "transfer_id"));
        assert!(!transactions_has_column(&conn, "tx_id"));

        let (unsatisfiable_at, spend_nullifiers, unsatisfiable_kind, broadcast_failure_at) = conn
            .query_row(
                "SELECT unsatisfiable_at, spend_nullifiers, unsatisfiable_kind,
                        broadcast_failure_at
                   FROM orchard_ironwood_migration_transactions
                  WHERE transfer_id = 0",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<u32>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<u32>>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(unsatisfiable_at, None);
        assert_eq!(unsatisfiable_kind, None);
        assert_eq!(broadcast_failure_at, None);
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

    /// The wallet-owned tables the txid recovery reads, plus the `accounts` row a pool-migration
    /// store is scoped by: a minimal stand-in for the wallet schema these unit fixtures build
    /// their pre-fix pool-migration tables beside.
    #[cfg(feature = "orchard")]
    fn create_wallet_tables(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE accounts (
                id INTEGER PRIMARY KEY,
                uuid BLOB NOT NULL
             );
             CREATE TABLE transactions (
                id_tx INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                mined_height INTEGER
             );
             CREATE TABLE orchard_received_notes (
                id INTEGER PRIMARY KEY,
                nf BLOB
             );
             CREATE TABLE orchard_received_note_spends (
                orchard_received_note_id INTEGER NOT NULL,
                transaction_id INTEGER NOT NULL
             );",
        )
        .unwrap();
    }

    /// Record the wallet's own view of a mined transaction `txid` at `mined_height` spending the
    /// note whose nullifier is `nf` — exactly the evidence the txid recovery reads back.
    #[cfg(feature = "orchard")]
    fn record_wallet_spend(conn: &Connection, txid: [u8; 32], mined_height: u32, nf: [u8; 32]) {
        conn.execute(
            "INSERT INTO transactions (txid, mined_height) VALUES (:txid, :mined_height)",
            named_params![":txid": txid.as_slice(), ":mined_height": mined_height],
        )
        .unwrap();
        let tx_ref = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO orchard_received_notes (nf) VALUES (:nf)",
            named_params![":nf": nf.as_slice()],
        )
        .unwrap();
        let note_ref = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
             VALUES (:note_ref, :tx_ref)",
            named_params![":note_ref": note_ref, ":tx_ref": tx_ref],
        )
        .unwrap();
    }

    /// The same proven bytes on a `mined` row are exempt from the nullifier-cache reconstruction:
    /// the transaction is terminal, so no satisfiability question remains for the cache to answer,
    /// and the row keeps the empty cache.
    ///
    /// Its erased `txid` is a different matter, and is repaired: a published release nulled the
    /// column on the way to `mined`, and the reconstructing reader requires it, so this asserts the
    /// whole round trip — the migration recovers the txid from the wallet's own record of the
    /// spend, and `get_migration()` reads the row back as a `Mined` state carrying it. Without the
    /// repair this read fails permanently, which is the condition the backfill exists to prevent.
    #[cfg(feature = "orchard")]
    #[test]
    fn a_mined_row_keeps_its_empty_cache_and_regains_its_txid() {
        use uuid::Uuid;
        use zcash_pool_migration::engine::{MigrationTxState, PoolMigrationRead};
        use zcash_protocol::TxId;
        use zcash_protocol::consensus::BlockHeight;

        use crate::AccountUuid;
        use crate::pool_migration::orchard_ironwood::PoolMigrations;

        const MINED_TXID: [u8; 32] = [0x3C; 32];
        const MINED_HEIGHT: u32 = 220;

        let (pczt_bytes, nullifier) = built_transfer_pczt();
        let proven = proven_shaped(&pczt_bytes);

        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        create_pre_fix_migrations_table(&conn);
        create_wallet_tables(&conn);
        // The remaining pool-migration child tables, which the reader queries, as the released
        // creating migration builds them; the two pre-fix tables above already exist, so this
        // leaves them alone.
        create_released_tables(&conn);

        let account = Uuid::from_u128(0x5A);
        conn.execute(
            "INSERT INTO accounts (id, uuid) VALUES (1, :uuid)",
            named_params![":uuid": account.as_bytes().as_slice()],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations (
                id, account_id, status, note_split_fee_buffer, note_split_prep_fees,
                note_split_total_input, note_split_total_migratable
             )
             VALUES (1, 1, 'complete', 0, 0, 0, 0)",
        )
        .unwrap();
        insert_pre_fix_row(&conn, 0, &proven, "mined");
        conn.execute(
            "UPDATE orchard_ironwood_migration_transactions SET mined_height = :mined_height",
            named_params![":mined_height": MINED_HEIGHT],
        )
        .unwrap();
        // The wallet scanned the transaction that spent the migration's funding note, which is
        // the only surviving record of the txid it was mined under.
        record_wallet_spend(&conn, MINED_TXID, MINED_HEIGHT, nullifier);

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

        let store = PoolMigrations::for_account(&conn, AccountUuid::from_uuid(account))
            .expect("the account exists");
        let state = store
            .get_migration()
            .expect("the repaired store reads back")
            .expect("the migration is present");
        assert_eq!(
            state.transactions()[0].state(),
            MigrationTxState::Mined {
                txid: TxId::from_bytes(MINED_TXID),
                height: BlockHeight::from_u32(MINED_HEIGHT),
            },
            "the mined row reconstructs with the txid recovered from the wallet's spend record",
        );
    }

    /// A `mined` row whose txid was erased and whose spends this wallet has no mined-spend record
    /// for cannot be repaired, and fails the migration naming the row rather than leaving a store
    /// that reads back as corrupt ever after.
    #[cfg(feature = "orchard")]
    #[test]
    fn an_unrecoverable_mined_txid_fails_the_migration() {
        let (pczt_bytes, _) = built_transfer_pczt();
        let proven = proven_shaped(&pczt_bytes);

        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        create_pre_fix_migrations_table(&conn);
        create_wallet_tables(&conn);
        insert_pre_fix_row(&conn, 0, &proven, "mined");

        let tx = conn.transaction().unwrap();
        assert!(matches!(
            RusqliteMigration::up(&Migration, &tx),
            Err(WalletMigrationError::CorruptedData(_)),
        ));
    }
}
