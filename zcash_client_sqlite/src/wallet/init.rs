//! Functions for initializing the various databases.

use std::fmt;

use rusqlite::{self};
use schemer::{Migrator, MigratorError};
use schemer_rusqlite::RusqliteAdapter;
use secrecy::SecretVec;
use shardtree::error::ShardTreeError;
use uuid::Uuid;

use zcash_primitives::{
    consensus::{self},
    transaction::components::amount::BalanceError,
};

use crate::WalletDb;

use super::commitment_tree::{self};

mod migrations;

#[derive(Debug)]
pub enum WalletMigrationError {
    /// The seed is required for the migration.
    SeedRequired,

    /// Decoding of an existing value from its serialized form has failed.
    CorruptedData(String),

    /// Wrapper for rusqlite errors.
    DbError(rusqlite::Error),

    /// Wrapper for amount balance violations
    BalanceError(BalanceError),

    /// Wrapper for commitment tree invariant violations
    CommitmentTree(ShardTreeError<commitment_tree::Error>),
}

impl From<rusqlite::Error> for WalletMigrationError {
    fn from(e: rusqlite::Error) -> Self {
        WalletMigrationError::DbError(e)
    }
}

impl From<BalanceError> for WalletMigrationError {
    fn from(e: BalanceError) -> Self {
        WalletMigrationError::BalanceError(e)
    }
}

impl From<ShardTreeError<commitment_tree::Error>> for WalletMigrationError {
    fn from(e: ShardTreeError<commitment_tree::Error>) -> Self {
        WalletMigrationError::CommitmentTree(e)
    }
}

impl fmt::Display for WalletMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            WalletMigrationError::SeedRequired => {
                write!(
                    f,
                    "The wallet seed is required in order to update the database."
                )
            }
            WalletMigrationError::CorruptedData(reason) => {
                write!(f, "Wallet database is corrupted: {}", reason)
            }
            WalletMigrationError::DbError(e) => write!(f, "{}", e),
            WalletMigrationError::BalanceError(e) => write!(f, "Balance error: {:?}", e),
            WalletMigrationError::CommitmentTree(e) => write!(f, "Commitment tree error: {:?}", e),
        }
    }
}

impl std::error::Error for WalletMigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            WalletMigrationError::DbError(e) => Some(e),
            _ => None,
        }
    }
}

/// Sets up the internal structure of the data database.
///
/// This procedure will automatically perform migration operations to update the wallet database to
/// the database structure required by the current version of this library, and should be invoked
/// at least once any time a client program upgrades to a new version of this library.  The
/// operation of this procedure is idempotent, so it is safe (though not required) to invoke this
/// operation every time the wallet is opened.
///
/// It is safe to use a wallet database previously created without the ability to create
/// transparent spends with a build that enables transparent spends (via use of the
/// `transparent-inputs` feature flag.) The reverse is unsafe, as wallet balance calculations would
/// ignore the transparent UTXOs already controlled by the wallet.
///
///
/// # Examples
///
/// ```
/// use secrecy::Secret;
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::init::init_wallet_db,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let mut db = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
/// init_wallet_db(&mut db, Some(Secret::new(vec![]))).unwrap();
/// ```
// TODO: It would be possible to make the transition from providing transparent support to no
// longer providing transparent support safe, by including a migration that verifies that no
// unspent transparent outputs exist in the wallet at the time of upgrading to a version of
// the library that does not support transparent use. It might be a good idea to add an explicit
// check for unspent transparent outputs whenever running initialization with a version of the
// library *not* compiled with the `transparent-inputs` feature flag, and fail if any are present.
pub fn init_wallet_db<P: consensus::Parameters + 'static>(
    wdb: &mut WalletDb<rusqlite::Connection, P>,
    seed: Option<SecretVec<u8>>,
) -> Result<(), MigratorError<WalletMigrationError>> {
    init_wallet_db_internal(wdb, seed, &[])
}

fn init_wallet_db_internal<P: consensus::Parameters + 'static>(
    wdb: &mut WalletDb<rusqlite::Connection, P>,
    seed: Option<SecretVec<u8>>,
    target_migrations: &[Uuid],
) -> Result<(), MigratorError<WalletMigrationError>> {
    // Turn off foreign keys, and ensure that table replacement/modification
    // does not break views
    wdb.conn
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             PRAGMA legacy_alter_table = TRUE;",
        )
        .map_err(|e| MigratorError::Adapter(WalletMigrationError::from(e)))?;
    let adapter = RusqliteAdapter::new(&mut wdb.conn, Some("schemer_migrations".to_string()));
    adapter.init().expect("Migrations table setup succeeds.");

    let mut migrator = Migrator::new(adapter);
    migrator
        .register_multiple(migrations::all_migrations(&wdb.params, seed))
        .expect("Wallet migration registration should have been successful.");
    if target_migrations.is_empty() {
        migrator.up(None)?;
    } else {
        for target_migration in target_migrations {
            migrator.up(Some(*target_migration))?;
        }
    }
    wdb.conn
        .execute("PRAGMA foreign_keys = ON", [])
        .map_err(|e| MigratorError::Adapter(WalletMigrationError::from(e)))?;
    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use rusqlite::{self, named_params, ToSql};
    use secrecy::Secret;

    use tempfile::NamedTempFile;

    use zcash_client_backend::{
        address::RecipientAddress,
        data_api::scanning::ScanPriority,
        encoding::{encode_extended_full_viewing_key, encode_payment_address},
        keys::{sapling, UnifiedFullViewingKey, UnifiedSpendingKey},
    };

    use zcash_primitives::{
        consensus::{self, BlockHeight, BranchId, Network, NetworkUpgrade, Parameters},
        transaction::{TransactionData, TxVersion},
        zip32::{sapling::ExtendedFullViewingKey, AccountId},
    };

    use crate::{testing::TestBuilder, wallet::scanning::priority_code, WalletDb};

    use super::init_wallet_db;

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::wallet::{self, pool_code, PoolType},
        zcash_address::test_vectors,
        zcash_client_backend::data_api::WalletWrite,
        zcash_primitives::zip32::DiversifierIndex,
    };

    #[test]
    fn verify_schema() {
        let st = TestBuilder::new().build();

        use regex::Regex;
        let re = Regex::new(r"\s+").unwrap();

        let expected_tables = vec![
            "CREATE TABLE \"accounts\" (
                account INTEGER PRIMARY KEY,
                ufvk TEXT NOT NULL,
                birthday_height INTEGER NOT NULL,
                recover_until_height INTEGER )",
            "CREATE TABLE addresses (
                account INTEGER NOT NULL,
                diversifier_index_be BLOB NOT NULL,
                address TEXT NOT NULL,
                cached_transparent_receiver_address TEXT,
                FOREIGN KEY (account) REFERENCES accounts(account),
                CONSTRAINT diversification UNIQUE (account, diversifier_index_be)
            )",
            "CREATE TABLE blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL,
                time INTEGER NOT NULL,
                sapling_tree BLOB NOT NULL ,
                sapling_commitment_tree_size INTEGER,
                orchard_commitment_tree_size INTEGER,
                sapling_output_count INTEGER,
                orchard_action_count INTEGER)",
            "CREATE TABLE nullifier_map (
                spend_pool INTEGER NOT NULL,
                nf BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                CONSTRAINT tx_locator
                    FOREIGN KEY (block_height, tx_index)
                    REFERENCES tx_locator_map(block_height, tx_index)
                    ON DELETE CASCADE
                    ON UPDATE RESTRICT,
                CONSTRAINT nf_uniq UNIQUE (spend_pool, nf)
            )",
            "CREATE TABLE sapling_received_notes (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                account INTEGER NOT NULL,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rcm BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                spent INTEGER,
                commitment_tree_position INTEGER,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (account) REFERENCES accounts(account),
                FOREIGN KEY (spent) REFERENCES transactions(id_tx),
                CONSTRAINT tx_output UNIQUE (tx, output_index)
            )",
            "CREATE TABLE sapling_tree_cap (
                -- cap_id exists only to be able to take advantage of `ON CONFLICT`
                -- upsert functionality; the table will only ever contain one row
                cap_id INTEGER PRIMARY KEY,
                cap_data BLOB NOT NULL
            )",
            "CREATE TABLE sapling_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES sapling_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE,
                CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
            )",
            "CREATE TABLE sapling_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            )",
            "CREATE TABLE sapling_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB,
                contains_marked INTEGER,
                CONSTRAINT root_unique UNIQUE (root_hash)
            )",
            "CREATE TABLE sapling_witnesses (
                id_witness INTEGER PRIMARY KEY,
                note INTEGER NOT NULL,
                block INTEGER NOT NULL,
                witness BLOB NOT NULL,
                FOREIGN KEY (note) REFERENCES sapling_received_notes(id_note),
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT witness_height UNIQUE (note, block)
            )",
            "CREATE TABLE scan_queue (
                block_range_start INTEGER NOT NULL,
                block_range_end INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                CONSTRAINT range_start_uniq UNIQUE (block_range_start),
                CONSTRAINT range_end_uniq UNIQUE (block_range_end),
                CONSTRAINT range_bounds_order CHECK (
                    block_range_start < block_range_end
                )
            )",
            "CREATE TABLE schemer_migrations (
                id blob PRIMARY KEY
            )",
            "CREATE TABLE \"sent_notes\" (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                to_address TEXT,
                to_account INTEGER,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(account),
                FOREIGN KEY (to_account) REFERENCES accounts(account),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index),
                CONSTRAINT note_recipient CHECK (
                    (to_address IS NOT NULL) != (to_account IS NOT NULL)
                )
            )",
            "CREATE TABLE transactions (
                id_tx INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                created TEXT,
                block INTEGER,
                tx_index INTEGER,
                expiry_height INTEGER,
                raw BLOB,
                fee INTEGER,
                FOREIGN KEY (block) REFERENCES blocks(height)
            )",
            "CREATE TABLE tx_locator_map (
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                txid BLOB NOT NULL UNIQUE,
                PRIMARY KEY (block_height, tx_index)
            )",
            "CREATE TABLE \"utxos\" (
                id_utxo INTEGER PRIMARY KEY,
                received_by_account INTEGER NOT NULL,
                address TEXT NOT NULL,
                prevout_txid BLOB NOT NULL,
                prevout_idx INTEGER NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                height INTEGER NOT NULL,
                spent_in_tx INTEGER,
                FOREIGN KEY (received_by_account) REFERENCES accounts(account),
                FOREIGN KEY (spent_in_tx) REFERENCES transactions(id_tx),
                CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
            )",
        ];

        let mut tables_query = st
            .wallet()
            .conn
            .prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' ORDER BY tbl_name")
            .unwrap();
        let mut rows = tables_query.query([]).unwrap();
        let mut expected_idx = 0;
        while let Some(row) = rows.next().unwrap() {
            let sql: String = row.get(0).unwrap();
            assert_eq!(
                re.replace_all(&sql, " "),
                re.replace_all(expected_tables[expected_idx], " ")
            );
            expected_idx += 1;
        }

        let expected_views = vec![
            // v_sapling_shard_scan_ranges
            format!(
                "CREATE VIEW v_sapling_shard_scan_ranges AS
                SELECT
                    shard.shard_index,
                    shard.shard_index << 16 AS start_position,
                    (shard.shard_index + 1) << 16 AS end_position_exclusive,
                    IFNULL(prev_shard.subtree_end_height, {}) AS subtree_start_height,
                    shard.subtree_end_height,
                    shard.contains_marked,
                    scan_queue.block_range_start,
                    scan_queue.block_range_end,
                    scan_queue.priority
                FROM sapling_tree_shards shard
                LEFT OUTER JOIN sapling_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                -- Join with scan ranges that overlap with the subtree's involved blocks.
                INNER JOIN scan_queue ON (
                    subtree_start_height < scan_queue.block_range_end AND
                    (
                        scan_queue.block_range_start <= shard.subtree_end_height OR
                        shard.subtree_end_height IS NULL
                    )
                )",
                u32::from(st.network().activation_height(NetworkUpgrade::Sapling).unwrap()),
            ),
            // v_sapling_shard_unscanned_ranges
            format!(
                "CREATE VIEW v_sapling_shard_unscanned_ranges AS
                WITH wallet_birthday AS (SELECT MIN(birthday_height) AS height FROM accounts)
                SELECT
                    shard_index,
                    start_position,
                    end_position_exclusive,
                    subtree_start_height,
                    subtree_end_height,
                    contains_marked,
                    block_range_start,
                    block_range_end,
                    priority
                FROM v_sapling_shard_scan_ranges
                INNER JOIN wallet_birthday
                WHERE priority > {}
                AND block_range_end > wallet_birthday.height",
                priority_code(&ScanPriority::Scanned)
            ),
            // v_sapling_shards_scan_state
            "CREATE VIEW v_sapling_shards_scan_state AS
            SELECT
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked,
                MAX(priority) AS max_priority
            FROM v_sapling_shard_scan_ranges
            GROUP BY
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked".to_owned(),
            // v_transactions
            "CREATE VIEW v_transactions AS
            WITH
            notes AS (
                SELECT sapling_received_notes.account        AS account_id,
                       sapling_received_notes.tx             AS id_tx,
                       2                             AS pool,
                       sapling_received_notes.value          AS value,
                       CASE
                            WHEN sapling_received_notes.is_change THEN 1
                            ELSE 0
                       END AS is_change,
                       CASE
                            WHEN sapling_received_notes.is_change THEN 0
                            ELSE 1
                       END AS received_count,
                       CASE
                         WHEN (sapling_received_notes.memo IS NULL OR sapling_received_notes.memo = X'F6')
                           THEN 0
                         ELSE 1
                       END AS memo_present
                FROM   sapling_received_notes
                UNION
                SELECT utxos.received_by_account     AS account_id,
                       transactions.id_tx            AS id_tx,
                       0                             AS pool,
                       utxos.value_zat               AS value,
                       0                             AS is_change,
                       1                             AS received_count,
                       0                             AS memo_present
                FROM utxos
                JOIN transactions
                     ON transactions.txid = utxos.prevout_txid
                UNION
                SELECT sapling_received_notes.account        AS account_id,
                       sapling_received_notes.spent          AS id_tx,
                       2                             AS pool,
                       -sapling_received_notes.value         AS value,
                       0                             AS is_change,
                       0                             AS received_count,
                       0                             AS memo_present
                FROM   sapling_received_notes
                WHERE  sapling_received_notes.spent IS NOT NULL
            ),
            sent_note_counts AS (
                SELECT sent_notes.from_account AS account_id,
                       sent_notes.tx AS id_tx,
                       COUNT(DISTINCT sent_notes.id_note) as sent_notes,
                       SUM(
                         CASE
                           WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6')
                             THEN 0
                           ELSE 1
                         END
                       ) AS memo_count
                FROM sent_notes
                LEFT JOIN sapling_received_notes
                          ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                             (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
                WHERE  sapling_received_notes.is_change IS NULL
                   OR  sapling_received_notes.is_change = 0
                GROUP BY account_id, id_tx
            ),
            blocks_max_height AS (
                SELECT MAX(blocks.height) as max_height FROM blocks
            )
            SELECT notes.account_id                  AS account_id,
                   transactions.id_tx                AS id_tx,
                   transactions.block                AS mined_height,
                   transactions.tx_index             AS tx_index,
                   transactions.txid                 AS txid,
                   transactions.expiry_height        AS expiry_height,
                   transactions.raw                  AS raw,
                   SUM(notes.value)                  AS account_balance_delta,
                   transactions.fee                  AS fee_paid,
                   SUM(notes.is_change) > 0          AS has_change,
                   MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
                   SUM(notes.received_count)         AS received_note_count,
                   SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
                   blocks.time                       AS block_time,
                   (
                        blocks.height IS NULL
                        AND transactions.expiry_height <= blocks_max_height.max_height
                   ) AS expired_unmined
            FROM transactions
            JOIN notes ON notes.id_tx = transactions.id_tx
            JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = transactions.block
            LEFT JOIN sent_note_counts
                      ON sent_note_counts.account_id = notes.account_id
                      AND sent_note_counts.id_tx = notes.id_tx
            GROUP BY notes.account_id, transactions.id_tx".to_owned(),
            // v_tx_outputs
            "CREATE VIEW v_tx_outputs AS
            SELECT sapling_received_notes.tx           AS id_tx,
                   2                                   AS output_pool,
                   sapling_received_notes.output_index AS output_index,
                   sent_notes.from_account             AS from_account,
                   sapling_received_notes.account      AS to_account,
                   NULL                                AS to_address,
                   sapling_received_notes.value        AS value,
                   sapling_received_notes.is_change    AS is_change,
                   sapling_received_notes.memo         AS memo
            FROM sapling_received_notes
            LEFT JOIN sent_notes
                      ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                         (sapling_received_notes.tx, 2, sent_notes.output_index)
            UNION
            SELECT transactions.id_tx          AS id_tx,
                   0                           AS output_pool,
                   utxos.prevout_idx           AS output_index,
                   NULL                        AS from_account,
                   utxos.received_by_account   AS to_account,
                   utxos.address               AS to_address,
                   utxos.value_zat             AS value,
                   false                       AS is_change,
                   NULL                        AS memo
            FROM utxos
            JOIN transactions
                 ON transactions.txid = utxos.prevout_txid
            UNION
            SELECT sent_notes.tx                  AS id_tx,
                   sent_notes.output_pool         AS output_pool,
                   sent_notes.output_index        AS output_index,
                   sent_notes.from_account        AS from_account,
                   sapling_received_notes.account AS to_account,
                   sent_notes.to_address          AS to_address,
                   sent_notes.value               AS value,
                   false                          AS is_change,
                   sent_notes.memo                AS memo
            FROM sent_notes
            LEFT JOIN sapling_received_notes
                      ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                         (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
            WHERE  sapling_received_notes.is_change IS NULL
               OR  sapling_received_notes.is_change = 0".to_owned(),
        ];

        let mut views_query = st
            .wallet()
            .conn
            .prepare("SELECT sql FROM sqlite_schema WHERE type = 'view' ORDER BY tbl_name")
            .unwrap();
        let mut rows = views_query.query([]).unwrap();
        let mut expected_idx = 0;
        while let Some(row) = rows.next().unwrap() {
            let sql: String = row.get(0).unwrap();
            assert_eq!(
                re.replace_all(&sql, " "),
                re.replace_all(&expected_views[expected_idx], " ")
            );
            expected_idx += 1;
        }
    }

    #[test]
    fn init_migrate_from_0_3_0() {
        fn init_0_3_0<P: consensus::Parameters>(
            wdb: &mut WalletDb<rusqlite::Connection, P>,
            extfvk: &ExtendedFullViewingKey,
            account: AccountId,
        ) -> Result<(), rusqlite::Error> {
            wdb.conn.execute(
                "CREATE TABLE accounts (
                    account INTEGER PRIMARY KEY,
                    extfvk TEXT NOT NULL,
                    address TEXT NOT NULL
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE blocks (
                    height INTEGER PRIMARY KEY,
                    hash BLOB NOT NULL,
                    time INTEGER NOT NULL,
                    sapling_tree BLOB NOT NULL
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE transactions (
                    id_tx INTEGER PRIMARY KEY,
                    txid BLOB NOT NULL UNIQUE,
                    created TEXT,
                    block INTEGER,
                    tx_index INTEGER,
                    expiry_height INTEGER,
                    raw BLOB,
                    FOREIGN KEY (block) REFERENCES blocks(height)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE received_notes (
                    id_note INTEGER PRIMARY KEY,
                    tx INTEGER NOT NULL,
                    output_index INTEGER NOT NULL,
                    account INTEGER NOT NULL,
                    diversifier BLOB NOT NULL,
                    value INTEGER NOT NULL,
                    rcm BLOB NOT NULL,
                    nf BLOB NOT NULL UNIQUE,
                    is_change INTEGER NOT NULL,
                    memo BLOB,
                    spent INTEGER,
                    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                    FOREIGN KEY (account) REFERENCES accounts(account),
                    FOREIGN KEY (spent) REFERENCES transactions(id_tx),
                    CONSTRAINT tx_output UNIQUE (tx, output_index)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE sapling_witnesses (
                    id_witness INTEGER PRIMARY KEY,
                    note INTEGER NOT NULL,
                    block INTEGER NOT NULL,
                    witness BLOB NOT NULL,
                    FOREIGN KEY (note) REFERENCES received_notes(id_note),
                    FOREIGN KEY (block) REFERENCES blocks(height),
                    CONSTRAINT witness_height UNIQUE (note, block)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE sent_notes (
                    id_note INTEGER PRIMARY KEY,
                    tx INTEGER NOT NULL,
                    output_index INTEGER NOT NULL,
                    from_account INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    value INTEGER NOT NULL,
                    memo BLOB,
                    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                    FOREIGN KEY (from_account) REFERENCES accounts(account),
                    CONSTRAINT tx_output UNIQUE (tx, output_index)
                )",
                [],
            )?;

            let address = encode_payment_address(
                wdb.params.hrp_sapling_payment_address(),
                &extfvk.default_address().1,
            );
            let extfvk = encode_extended_full_viewing_key(
                wdb.params.hrp_sapling_extended_full_viewing_key(),
                extfvk,
            );
            wdb.conn.execute(
                "INSERT INTO accounts (account, extfvk, address)
                VALUES (?, ?, ?)",
                [
                    u32::from(account).to_sql()?,
                    extfvk.to_sql()?,
                    address.to_sql()?,
                ],
            )?;

            Ok(())
        }

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();

        let seed = [0xab; 32];
        let account = AccountId::from(0);
        let secret_key = sapling::spending_key(&seed, db_data.params.coin_type(), account);
        let extfvk = secret_key.to_extended_full_viewing_key();

        init_0_3_0(&mut db_data, &extfvk, account).unwrap();
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))),
            Ok(_)
        );
    }

    #[test]
    fn init_migrate_from_autoshielding_poc() {
        fn init_autoshielding<P: consensus::Parameters>(
            wdb: &mut WalletDb<rusqlite::Connection, P>,
            extfvk: &ExtendedFullViewingKey,
            account: AccountId,
        ) -> Result<(), rusqlite::Error> {
            wdb.conn.execute(
                "CREATE TABLE accounts (
                    account INTEGER PRIMARY KEY,
                    extfvk TEXT NOT NULL,
                    address TEXT NOT NULL,
                    transparent_address TEXT NOT NULL
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE blocks (
                    height INTEGER PRIMARY KEY,
                    hash BLOB NOT NULL,
                    time INTEGER NOT NULL,
                    sapling_tree BLOB NOT NULL
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE transactions (
                    id_tx INTEGER PRIMARY KEY,
                    txid BLOB NOT NULL UNIQUE,
                    created TEXT,
                    block INTEGER,
                    tx_index INTEGER,
                    expiry_height INTEGER,
                    raw BLOB,
                    FOREIGN KEY (block) REFERENCES blocks(height)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE received_notes (
                    id_note INTEGER PRIMARY KEY,
                    tx INTEGER NOT NULL,
                    output_index INTEGER NOT NULL,
                    account INTEGER NOT NULL,
                    diversifier BLOB NOT NULL,
                    value INTEGER NOT NULL,
                    rcm BLOB NOT NULL,
                    nf BLOB NOT NULL UNIQUE,
                    is_change INTEGER NOT NULL,
                    memo BLOB,
                    spent INTEGER,
                    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                    FOREIGN KEY (account) REFERENCES accounts(account),
                    FOREIGN KEY (spent) REFERENCES transactions(id_tx),
                    CONSTRAINT tx_output UNIQUE (tx, output_index)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE sapling_witnesses (
                    id_witness INTEGER PRIMARY KEY,
                    note INTEGER NOT NULL,
                    block INTEGER NOT NULL,
                    witness BLOB NOT NULL,
                    FOREIGN KEY (note) REFERENCES received_notes(id_note),
                    FOREIGN KEY (block) REFERENCES blocks(height),
                    CONSTRAINT witness_height UNIQUE (note, block)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE sent_notes (
                    id_note INTEGER PRIMARY KEY,
                    tx INTEGER NOT NULL,
                    output_index INTEGER NOT NULL,
                    from_account INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    value INTEGER NOT NULL,
                    memo BLOB,
                    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                    FOREIGN KEY (from_account) REFERENCES accounts(account),
                    CONSTRAINT tx_output UNIQUE (tx, output_index)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE utxos (
                    id_utxo INTEGER PRIMARY KEY,
                    address TEXT NOT NULL,
                    prevout_txid BLOB NOT NULL,
                    prevout_idx INTEGER NOT NULL,
                    script BLOB NOT NULL,
                    value_zat INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    spent_in_tx INTEGER,
                    FOREIGN KEY (spent_in_tx) REFERENCES transactions(id_tx),
                    CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
                )",
                [],
            )?;

            let address = encode_payment_address(
                wdb.params.hrp_sapling_payment_address(),
                &extfvk.default_address().1,
            );
            let extfvk = encode_extended_full_viewing_key(
                wdb.params.hrp_sapling_extended_full_viewing_key(),
                extfvk,
            );
            wdb.conn.execute(
                "INSERT INTO accounts (account, extfvk, address, transparent_address)
                VALUES (?, ?, ?, '')",
                [
                    u32::from(account).to_sql()?,
                    extfvk.to_sql()?,
                    address.to_sql()?,
                ],
            )?;

            // add a sapling sent note
            wdb.conn.execute(
                "INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, x'000000')",
                [],
            )?;

            let tx = TransactionData::from_parts(
                TxVersion::Sapling,
                BranchId::Canopy,
                0,
                BlockHeight::from(0),
                None,
                None,
                None,
                None,
            )
            .freeze()
            .unwrap();

            let mut tx_bytes = vec![];
            tx.write(&mut tx_bytes).unwrap();
            wdb.conn.execute(
                "INSERT INTO transactions (block, id_tx, txid, raw) VALUES (0, 0, :txid, :tx_bytes)",
                named_params![
                    ":txid": tx.txid().as_ref(),
                    ":tx_bytes": &tx_bytes[..]
                ],
            )?;
            wdb.conn.execute(
                "INSERT INTO sent_notes (tx, output_index, from_account, address, value)
                VALUES (0, 0, ?, ?, 0)",
                [u32::from(account).to_sql()?, address.to_sql()?],
            )?;

            Ok(())
        }

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();

        let seed = [0xab; 32];
        let account = AccountId::from(0);
        let secret_key = sapling::spending_key(&seed, db_data.params.coin_type(), account);
        let extfvk = secret_key.to_extended_full_viewing_key();

        init_autoshielding(&mut db_data, &extfvk, account).unwrap();
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))),
            Ok(_)
        );
    }

    #[test]
    fn init_migrate_from_main_pre_migrations() {
        fn init_main<P: consensus::Parameters>(
            wdb: &mut WalletDb<rusqlite::Connection, P>,
            ufvk: &UnifiedFullViewingKey,
            account: AccountId,
        ) -> Result<(), rusqlite::Error> {
            wdb.conn.execute(
                "CREATE TABLE accounts (
                    account INTEGER PRIMARY KEY,
                    ufvk TEXT,
                    address TEXT,
                    transparent_address TEXT
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE blocks (
                    height INTEGER PRIMARY KEY,
                    hash BLOB NOT NULL,
                    time INTEGER NOT NULL,
                    sapling_tree BLOB NOT NULL
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE transactions (
                    id_tx INTEGER PRIMARY KEY,
                    txid BLOB NOT NULL UNIQUE,
                    created TEXT,
                    block INTEGER,
                    tx_index INTEGER,
                    expiry_height INTEGER,
                    raw BLOB,
                    FOREIGN KEY (block) REFERENCES blocks(height)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE received_notes (
                    id_note INTEGER PRIMARY KEY,
                    tx INTEGER NOT NULL,
                    output_index INTEGER NOT NULL,
                    account INTEGER NOT NULL,
                    diversifier BLOB NOT NULL,
                    value INTEGER NOT NULL,
                    rcm BLOB NOT NULL,
                    nf BLOB NOT NULL UNIQUE,
                    is_change INTEGER NOT NULL,
                    memo BLOB,
                    spent INTEGER,
                    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                    FOREIGN KEY (account) REFERENCES accounts(account),
                    FOREIGN KEY (spent) REFERENCES transactions(id_tx),
                    CONSTRAINT tx_output UNIQUE (tx, output_index)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE sapling_witnesses (
                    id_witness INTEGER PRIMARY KEY,
                    note INTEGER NOT NULL,
                    block INTEGER NOT NULL,
                    witness BLOB NOT NULL,
                    FOREIGN KEY (note) REFERENCES received_notes(id_note),
                    FOREIGN KEY (block) REFERENCES blocks(height),
                    CONSTRAINT witness_height UNIQUE (note, block)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE sent_notes (
                    id_note INTEGER PRIMARY KEY,
                    tx INTEGER NOT NULL,
                    output_pool INTEGER NOT NULL,
                    output_index INTEGER NOT NULL,
                    from_account INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    value INTEGER NOT NULL,
                    memo BLOB,
                    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                    FOREIGN KEY (from_account) REFERENCES accounts(account),
                    CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index)
                )",
                [],
            )?;
            wdb.conn.execute(
                "CREATE TABLE utxos (
                    id_utxo INTEGER PRIMARY KEY,
                    address TEXT NOT NULL,
                    prevout_txid BLOB NOT NULL,
                    prevout_idx INTEGER NOT NULL,
                    script BLOB NOT NULL,
                    value_zat INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    spent_in_tx INTEGER,
                    FOREIGN KEY (spent_in_tx) REFERENCES transactions(id_tx),
                    CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
                )",
                [],
            )?;

            let ufvk_str = ufvk.encode(&wdb.params);
            let address_str =
                RecipientAddress::Unified(ufvk.default_address().0).encode(&wdb.params);
            wdb.conn.execute(
                "INSERT INTO accounts (account, ufvk, address, transparent_address)
                VALUES (?, ?, ?, '')",
                [
                    u32::from(account).to_sql()?,
                    ufvk_str.to_sql()?,
                    address_str.to_sql()?,
                ],
            )?;

            // add a transparent "sent note"
            #[cfg(feature = "transparent-inputs")]
            {
                let taddr =
                    RecipientAddress::Transparent(*ufvk.default_address().0.transparent().unwrap())
                        .encode(&wdb.params);
                wdb.conn.execute(
                    "INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, x'000000')",
                    [],
                )?;
                wdb.conn.execute(
                    "INSERT INTO transactions (block, id_tx, txid) VALUES (0, 0, '')",
                    [],
                )?;
                wdb.conn.execute(
                    "INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value)
                    VALUES (0, ?, 0, ?, ?, 0)",
                    [pool_code(PoolType::Transparent).to_sql()?, u32::from(account).to_sql()?, taddr.to_sql()?])?;
            }

            Ok(())
        }

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();

        let seed = [0xab; 32];
        let account = AccountId::from(0);
        let secret_key = UnifiedSpendingKey::from_seed(&db_data.params, &seed, account).unwrap();

        init_main(
            &mut db_data,
            &secret_key.to_unified_full_viewing_key(),
            account,
        )
        .unwrap();
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))),
            Ok(_)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn account_produces_expected_ua_sequence() {
        use zcash_client_backend::data_api::AccountBirthday;

        let network = Network::MainNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), network).unwrap();
        let seed = test_vectors::UNIFIED[0].root_seed;
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))),
            Ok(_)
        );

        let birthday = AccountBirthday::from_sapling_activation(&network);
        let (account, _usk) = db_data
            .create_account(&Secret::new(seed.to_vec()), birthday)
            .unwrap();
        assert_eq!(account, AccountId::from(0u32));

        for tv in &test_vectors::UNIFIED[..3] {
            if let Some(RecipientAddress::Unified(tvua)) =
                RecipientAddress::decode(&Network::MainNetwork, tv.unified_addr)
            {
                let (ua, di) = wallet::get_current_address(&db_data.conn, &db_data.params, account)
                    .unwrap()
                    .expect("create_account generated the first address");
                assert_eq!(DiversifierIndex::from(tv.diversifier_index), di);
                assert_eq!(tvua.transparent(), ua.transparent());
                assert_eq!(tvua.sapling(), ua.sapling());
                assert_eq!(tv.unified_addr, ua.encode(&Network::MainNetwork));

                db_data
                    .get_next_available_address(account)
                    .unwrap()
                    .expect("get_next_available_address generated an address");
            } else {
                panic!(
                    "{} did not decode to a valid unified address",
                    tv.unified_addr
                );
            }
        }
    }
}
