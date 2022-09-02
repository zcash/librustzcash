//! Functions for initializing the various databases.
use rusqlite::{self, params, types::ToSql, Connection, NO_PARAMS};
use schemer::{migration, Migration, Migrator, MigratorError};
use schemer_rusqlite::{RusqliteAdapter, RusqliteMigration};
use secrecy::{ExposeSecret, SecretVec};
use std::collections::{HashMap, HashSet};
use std::fmt;
use uuid::Uuid;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, BranchId},
    transaction::{
        components::amount::{Amount, BalanceError},
        Transaction,
    },
    zip32::AccountId,
};

use zcash_client_backend::{
    address::RecipientAddress,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
};

use crate::{error::SqliteClientError, wallet::PoolType, WalletDb};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::encoding::AddressCodec,
    zcash_primitives::legacy::keys::IncomingViewingKey,
};

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

struct WalletMigration0;

migration!(
    WalletMigration0,
    "bc4f5e57-d600-4b6c-990f-b3538f0bfce1",
    [],
    "Initialize the wallet database."
);

impl RusqliteMigration for WalletMigration0 {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            // We set the user_version field of the database to a constant value of 8 to allow
            // correct integration with the Android SDK with versions of the database that were
            // created prior to the introduction of migrations in this crate.  This constant should
            // remain fixed going forward, and should not be altered by migrations; migration
            // status is maintained exclusively by the schemer_migrations table.
            "PRAGMA user_version = 8;
            CREATE TABLE IF NOT EXISTS accounts (
                account INTEGER PRIMARY KEY,
                extfvk TEXT NOT NULL,
                address TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL,
                time INTEGER NOT NULL,
                sapling_tree BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id_tx INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                created TEXT,
                block INTEGER,
                tx_index INTEGER,
                expiry_height INTEGER,
                raw BLOB,
                FOREIGN KEY (block) REFERENCES blocks(height)
            );
            CREATE TABLE IF NOT EXISTS received_notes (
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
            );
            CREATE TABLE IF NOT EXISTS sapling_witnesses (
                id_witness INTEGER PRIMARY KEY,
                note INTEGER NOT NULL,
                block INTEGER NOT NULL,
                witness BLOB NOT NULL,
                FOREIGN KEY (note) REFERENCES received_notes(id_note),
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT witness_height UNIQUE (note, block)
            );
            CREATE TABLE IF NOT EXISTS sent_notes (
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
            );",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // We should never down-migrate the first migration, as that can irreversibly
        // destroy data.
        panic!("Cannot revert the initial migration.");
    }
}

struct WalletMigration1;

migration!(
    WalletMigration1,
    "a2e0ed2e-8852-475e-b0a4-f154b15b9dbe",
    ["bc4f5e57-d600-4b6c-990f-b3538f0bfce1"],
    "Add support for receiving transparent UTXOs."
);

impl RusqliteMigration for WalletMigration1 {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS utxos (
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
            );",
        )?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("DROP TABLE utxos;")?;
        Ok(())
    }
}

struct WalletMigration2<P> {
    params: P,
    seed: Option<SecretVec<u8>>,
}

impl<P> Migration for WalletMigration2<P> {
    fn id(&self) -> Uuid {
        ::uuid::Uuid::parse_str("be57ef3b-388e-42ea-97e2-678dafcf9754").unwrap()
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        ["a2e0ed2e-8852-475e-b0a4-f154b15b9dbe"]
            .iter()
            .map(|uuidstr| ::uuid::Uuid::parse_str(uuidstr).unwrap())
            .collect()
    }

    fn description(&self) -> &'static str {
        "Add support for unified full viewing keys"
    }
}

impl<P: consensus::Parameters> RusqliteMigration for WalletMigration2<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        //
        // Update the accounts table to store ufvks rather than extfvks
        //

        transaction.execute_batch(
            "CREATE TABLE accounts_new (
                account INTEGER PRIMARY KEY,
                ufvk TEXT NOT NULL,
                address TEXT,
                transparent_address TEXT
            );",
        )?;

        let mut stmt_fetch_accounts =
            transaction.prepare("SELECT account, address FROM accounts")?;

        let mut rows = stmt_fetch_accounts.query(NO_PARAMS)?;
        while let Some(row) = rows.next()? {
            // We only need to check for the presence of the seed if we have keys that
            // need to be migrated; otherwise, it's fine to not supply the seed if this
            // migration is being used to initialize an empty database.
            if let Some(seed) = &self.seed {
                let account: u32 = row.get(0)?;
                let account = AccountId::from(account);
                let usk =
                    UnifiedSpendingKey::from_seed(&self.params, seed.expose_secret(), account)
                        .unwrap();
                let ufvk = usk.to_unified_full_viewing_key();

                let address: String = row.get(1)?;
                let decoded =
                    RecipientAddress::decode(&self.params, &address).ok_or_else(|| {
                        WalletMigrationError::CorruptedData(format!(
                            "Could not decode {} as a valid Zcash address.",
                            address
                        ))
                    })?;
                match decoded {
                    RecipientAddress::Shielded(decoded_address) => {
                        let dfvk = ufvk.sapling().expect(
                            "Derivation should have produced a UFVK containing a Sapling component.",
                        );
                        let (idx, expected_address) = dfvk.default_address();
                        if decoded_address != expected_address {
                            return Err(WalletMigrationError::CorruptedData(
                                format!("Decoded Sapling address {} does not match the ufvk's Sapling address {} at {:?}.",
                                    address,
                                    RecipientAddress::Shielded(expected_address).encode(&self.params),
                                    idx)));
                        }
                    }
                    RecipientAddress::Transparent(_) => {
                        return Err(WalletMigrationError::CorruptedData(
                            "Address field value decoded to a transparent address; should have been Sapling or unified.".to_string()));
                    }
                    RecipientAddress::Unified(decoded_address) => {
                        let (expected_address, idx) = ufvk.default_address();
                        if decoded_address != expected_address {
                            return Err(WalletMigrationError::CorruptedData(
                                format!("Decoded unified address {} does not match the ufvk's default address {} at {:?}.",
                                    address,
                                    RecipientAddress::Unified(expected_address).encode(&self.params),
                                    idx)));
                        }
                    }
                }

                let ufvk_str: String = ufvk.encode(&self.params);
                let address_str: String = ufvk.default_address().0.encode(&self.params);

                // This migration, and the wallet behaviour before it, stored the default
                // transparent address in the `accounts` table. This does not necessarily
                // match the transparent receiver in the default Unified Address. Starting
                // from `AddressesTableMigration` below, we no longer store transparent
                // addresses directly, but instead extract them from the Unified Address
                // (or from the UFVK if the UA was derived without a transparent receiver,
                // which is not the case for UAs generated by this crate).
                #[cfg(feature = "transparent-inputs")]
                let taddress_str: Option<String> = ufvk.transparent().and_then(|k| {
                    k.derive_external_ivk()
                        .ok()
                        .map(|k| k.default_address().0.encode(&self.params))
                });
                #[cfg(not(feature = "transparent-inputs"))]
                let taddress_str: Option<String> = None;

                transaction.execute_named(
                    "INSERT INTO accounts_new (account, ufvk, address, transparent_address)
                    VALUES (:account, :ufvk, :address, :transparent_address)",
                    &[
                        (":account", &<u32>::from(account)),
                        (":ufvk", &ufvk_str),
                        (":address", &address_str),
                        (":transparent_address", &taddress_str),
                    ],
                )?;
            } else {
                return Err(WalletMigrationError::SeedRequired);
            }
        }

        transaction.execute_batch(
            "DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;",
        )?;

        //
        // Update the sent_notes table to inclue an output_pool column that
        // is respected by the uniqueness constraint
        //

        transaction.execute_batch(
            "CREATE TABLE sent_notes_new (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL ,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                address TEXT NOT NULL,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(account),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index)
            );",
        )?;

        // we query in a nested scope so that the col_names iterator is correctly
        // dropped and doesn't maintain a lock on the table.
        let has_output_pool = {
            let mut stmt_fetch_columns = transaction.prepare("PRAGMA TABLE_INFO('sent_notes')")?;
            let mut col_names = stmt_fetch_columns.query_map(NO_PARAMS, |row| {
                let col_name: String = row.get(1)?;
                Ok(col_name)
            })?;

            col_names.any(|cname| cname == Ok("output_pool".to_string()))
        };

        if has_output_pool {
            transaction.execute_batch(
                "INSERT INTO sent_notes_new
                    (id_note, tx, output_pool, output_index, from_account, address, value, memo)
                    SELECT id_note, tx, output_pool, output_index, from_account, address, value, memo
                    FROM sent_notes;"
            )?;
        } else {
            let mut stmt_fetch_sent_notes = transaction.prepare(
                "SELECT id_note, tx, output_index, from_account, address, value, memo
                    FROM sent_notes",
            )?;

            let mut stmt_insert_sent_note = transaction.prepare(
                "INSERT INTO sent_notes_new
                    (id_note, tx, output_pool, output_index, from_account, address, value, memo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )?;

            let mut rows = stmt_fetch_sent_notes.query(NO_PARAMS)?;
            while let Some(row) = rows.next()? {
                let id_note: i64 = row.get(0)?;
                let tx_ref: i64 = row.get(1)?;
                let output_index: i64 = row.get(2)?;
                let account_id: u32 = row.get(3)?;
                let address: String = row.get(4)?;
                let value: i64 = row.get(5)?;
                let memo: Option<Vec<u8>> = row.get(6)?;

                let decoded_address =
                    RecipientAddress::decode(&self.params, &address).ok_or_else(|| {
                        WalletMigrationError::CorruptedData(format!(
                            "Could not decode {} as a valid Zcash address.",
                            address
                        ))
                    })?;
                let output_pool = match decoded_address {
                    RecipientAddress::Shielded(_) => Ok(PoolType::Sapling.typecode()),
                    RecipientAddress::Transparent(_) => Ok(PoolType::Transparent.typecode()),
                    RecipientAddress::Unified(_) => Err(WalletMigrationError::CorruptedData(
                        "Unified addresses should not yet appear in the sent_notes table."
                            .to_string(),
                    )),
                }?;

                stmt_insert_sent_note.execute(params![
                    id_note,
                    tx_ref,
                    output_pool,
                    output_index,
                    account_id,
                    address,
                    value,
                    memo
                ])?;
            }
        }

        transaction.execute_batch(
            "DROP TABLE sent_notes;
            ALTER TABLE sent_notes_new RENAME TO sent_notes;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}

struct WalletMigrationAddTxViews<P> {
    params: P,
}

impl<P> Migration for WalletMigrationAddTxViews<P> {
    fn id(&self) -> Uuid {
        ::uuid::Uuid::parse_str("282fad2e-8372-4ca0-8bed-71821320909f").unwrap()
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        ["be57ef3b-388e-42ea-97e2-678dafcf9754"]
            .iter()
            .map(|uuidstr| ::uuid::Uuid::parse_str(uuidstr).unwrap())
            .collect()
    }

    fn description(&self) -> &'static str {
        "Add transaction summary views & add fee information to transactions."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for WalletMigrationAddTxViews<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("ALTER TABLE transactions ADD COLUMN fee INTEGER;")?;

        let mut stmt_list_txs =
            transaction.prepare("SELECT id_tx, raw, block FROM transactions")?;

        let mut stmt_set_fee =
            transaction.prepare("UPDATE transactions SET fee = ? WHERE id_tx = ?")?;

        let mut stmt_find_utxo_value = transaction
            .prepare("SELECT value_zat FROM utxos WHERE prevout_txid = ? AND prevout_idx = ?")?;

        let mut tx_rows = stmt_list_txs.query(NO_PARAMS)?;
        while let Some(row) = tx_rows.next()? {
            let id_tx: i64 = row.get(0)?;
            let tx_bytes: Vec<u8> = row.get(1)?;
            let h: u32 = row.get(2)?;
            let block_height = BlockHeight::from(h);

            let tx = Transaction::read(
                &tx_bytes[..],
                BranchId::for_height(&self.params, block_height),
            )
            .map_err(|e| {
                WalletMigrationError::CorruptedData(format!(
                    "Parsing failed for transaction {:?}: {:?}",
                    id_tx, e
                ))
            })?;

            let fee_paid = tx.fee_paid(|op| {
                stmt_find_utxo_value
                    .query_row(&[op.hash().to_sql()?, op.n().to_sql()?], |row| {
                        row.get(0).map(|i| Amount::from_i64(i).unwrap())
                    })
                    .map_err(WalletMigrationError::DbError)
            })?;

            stmt_set_fee.execute(&[i64::from(fee_paid), id_tx])?;
        }

        transaction.execute_batch(
            "CREATE VIEW v_tx_sent AS
            SELECT transactions.id_tx         AS id_tx,
                   transactions.block         AS mined_height,
                   transactions.tx_index      AS tx_index,
                   transactions.txid          AS txid,
                   transactions.expiry_height AS expiry_height,
                   transactions.raw           AS raw,
                   SUM(sent_notes.value)      AS sent_total,
                   COUNT(sent_notes.id_note)  AS sent_note_count,
                   SUM(CASE WHEN sent_notes.memo IS NULL OR sent_notes.memo = '' THEN 0 ELSE 1 END) AS memo_count,
                   blocks.time                AS block_time
            FROM   transactions
                   JOIN sent_notes
                          ON transactions.id_tx = sent_notes.tx
                   LEFT JOIN blocks
                          ON transactions.block = blocks.height
            GROUP BY sent_notes.tx;
            CREATE VIEW v_tx_received AS
            SELECT transactions.id_tx            AS id_tx,
                   transactions.block            AS mined_height,
                   transactions.tx_index         AS tx_index,
                   transactions.txid             AS txid,
                   SUM(received_notes.value)     AS received_total,
                   COUNT(received_notes.id_note) AS received_note_count,
                   SUM(CASE WHEN received_notes.memo IS NULL OR received_notes.memo = '' THEN 0 ELSE 1 END) AS memo_count,
                   blocks.time                   AS block_time
            FROM   transactions
                   JOIN received_notes
                          ON transactions.id_tx = received_notes.tx
                   LEFT JOIN blocks
                          ON transactions.block = blocks.height
            GROUP BY received_notes.tx;
            CREATE VIEW v_transactions AS
            SELECT id_tx,
                   mined_height,
                   tx_index,
                   txid,
                   expiry_height,
                   raw,
                   SUM(value) + MAX(fee) AS net_value,
                   SUM(is_change) > 0 AS has_change,
                   SUM(memo_present) AS memo_count
            FROM (
                SELECT transactions.id_tx            AS id_tx,
                       transactions.block            AS mined_height,
                       transactions.tx_index         AS tx_index,
                       transactions.txid             AS txid,
                       transactions.expiry_height    AS expiry_height,
                       transactions.raw              AS raw,
                       transactions.fee              AS fee,
                       CASE
                            WHEN received_notes.is_change THEN 0
                            ELSE value
                       END AS value,
                       received_notes.is_change      AS is_change,
                       CASE WHEN received_notes.memo IS NULL OR received_notes.memo = '' THEN 0 ELSE 1 END AS memo_present
                FROM   transactions
                       JOIN received_notes ON transactions.id_tx = received_notes.tx
                UNION
                SELECT transactions.id_tx            AS id_tx,
                       transactions.block            AS mined_height,
                       transactions.tx_index         AS tx_index,
                       transactions.txid             AS txid,
                       transactions.expiry_height    AS expiry_height,
                       transactions.raw              AS raw,
                       0                             AS fee,
                       -sent_notes.value             AS value,
                       false                         AS is_change,
                       CASE WHEN sent_notes.memo IS NULL OR sent_notes.memo = '' THEN 0 ELSE 1 END AS memo_present
                FROM   transactions
                       JOIN sent_notes ON transactions.id_tx = sent_notes.tx
            )
            GROUP BY id_tx;",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "DROP VIEW v_tx_sent_notes;
            DROP VIEW v_tx_received_notes;
            DROP VIEW v_tx_notes;",
        )?;
        Ok(())
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
    wdb: &mut WalletDb<P>,
    seed: Option<SecretVec<u8>>,
) -> Result<(), MigratorError<WalletMigrationError>> {
    wdb.conn
        .execute("PRAGMA foreign_keys = OFF", NO_PARAMS)
        .map_err(|e| MigratorError::Adapter(WalletMigrationError::from(e)))?;
    let adapter = RusqliteAdapter::new(&mut wdb.conn, Some("schemer_migrations".to_string()));
    adapter.init().expect("Migrations table setup succeeds.");

    let mut migrator = Migrator::new(adapter);
    let migration0 = Box::new(WalletMigration0 {});
    let migration1 = Box::new(WalletMigration1 {});
    let migration2 = Box::new(WalletMigration2 {
        params: wdb.params.clone(),
        seed,
    });
    let migration3 = Box::new(WalletMigrationAddTxViews {
        params: wdb.params.clone(),
    });
    let migration4 = Box::new(migrations::AddressesTableMigration {
        params: wdb.params.clone(),
    });

    migrator
        .register_multiple(vec![
            migration0, migration1, migration2, migration3, migration4,
        ])
        .expect("Wallet migration registration should have been successful.");
    migrator.up(None)?;
    wdb.conn
        .execute("PRAGMA foreign_keys = ON", NO_PARAMS)
        .map_err(|e| MigratorError::Adapter(WalletMigrationError::from(e)))?;
    Ok(())
}

/// Initialises the data database with the given [`UnifiedFullViewingKey`]s.
///
/// The [`UnifiedFullViewingKey`]s are stored internally and used by other APIs such as
/// [`get_address`], [`scan_cached_blocks`], and [`create_spend_to_address`]. `extfvks` **MUST**
/// be arranged in account-order; that is, the [`UnifiedFullViewingKey`] for ZIP 32
/// account `i` **MUST** be at `extfvks[i]`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "transparent-inputs")]
/// # {
/// use tempfile::NamedTempFile;
/// use secrecy::Secret;
/// use std::collections::HashMap;
///
/// use zcash_primitives::{
///     consensus::{Network, Parameters},
///     zip32::{AccountId, ExtendedFullViewingKey, ExtendedSpendingKey}
/// };
///
/// use zcash_client_backend::{
///     keys::{
///         sapling,
///         UnifiedFullViewingKey
///     },
/// };
///
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::init::{init_accounts_table, init_wallet_db}
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
/// init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();
///
/// let seed = [0u8; 32]; // insecure; replace with a strong random seed
/// let account = AccountId::from(0);
/// let extsk = sapling::spending_key(&seed, Network::TestNetwork.coin_type(), account);
/// let dfvk = ExtendedFullViewingKey::from(&extsk).into();
/// let ufvk = UnifiedFullViewingKey::new(None, Some(dfvk), None).unwrap();
/// let ufvks = HashMap::from([(account, ufvk)]);
/// init_accounts_table(&db_data, &ufvks).unwrap();
/// # }
/// ```
///
/// [`get_address`]: crate::wallet::get_address
/// [`scan_cached_blocks`]: zcash_client_backend::data_api::chain::scan_cached_blocks
/// [`create_spend_to_address`]: zcash_client_backend::data_api::wallet::create_spend_to_address
pub fn init_accounts_table<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    keys: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> Result<(), SqliteClientError> {
    let mut empty_check = wdb.conn.prepare("SELECT * FROM accounts LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(SqliteClientError::TableNotEmpty);
    }

    // Insert accounts atomically
    wdb.conn.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
    for (account, key) in keys.iter() {
        add_account_internal::<P, SqliteClientError>(
            &wdb.params,
            &wdb.conn,
            "accounts",
            *account,
            key,
        )?;
    }
    wdb.conn.execute("COMMIT", NO_PARAMS)?;

    Ok(())
}

fn add_account_internal<P: consensus::Parameters, E: From<rusqlite::Error>>(
    network: &P,
    conn: &Connection,
    accounts_table: &'static str,
    account: AccountId,
    key: &UnifiedFullViewingKey,
) -> Result<(), E> {
    let ufvk_str: String = key.encode(network);
    conn.execute_named(
        &format!(
            "INSERT INTO {} (account, ufvk) VALUES (:account, :ufvk)",
            accounts_table
        ),
        &[(":account", &<u32>::from(account)), (":ufvk", &ufvk_str)],
    )?;

    // Always derive the default Unified Address for the account.
    let (address, idx) = key.default_address();
    let address_str: String = address.encode(network);
    conn.execute_named(
        "INSERT INTO addresses (account, diversifier_index, address)
        VALUES (:account, :diversifier_index, :address)",
        &[
            (":account", &<u32>::from(account)),
            (":diversifier_index", &&idx.0[..]),
            (":address", &address_str),
        ],
    )?;

    Ok(())
}

/// Initialises the data database with the given block.
///
/// This enables a newly-created database to be immediately-usable, without needing to
/// synchronise historic blocks.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     block::BlockHash,
///     consensus::{BlockHeight, Network},
/// };
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::init::init_blocks_table,
/// };
///
/// // The block height.
/// let height = BlockHeight::from_u32(500_000);
/// // The hash of the block header.
/// let hash = BlockHash([0; 32]);
/// // The nTime field from the block header.
/// let time = 12_3456_7890;
/// // The serialized Sapling commitment tree as of this block.
/// // Pre-compute and hard-code, or obtain from a service.
/// let sapling_tree = &[];
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
/// init_blocks_table(&db, height, hash, time, sapling_tree);
/// ```
pub fn init_blocks_table<P>(
    wdb: &WalletDb<P>,
    height: BlockHeight,
    hash: BlockHash,
    time: u32,
    sapling_tree: &[u8],
) -> Result<(), SqliteClientError> {
    let mut empty_check = wdb.conn.prepare("SELECT * FROM blocks LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(SqliteClientError::TableNotEmpty);
    }

    wdb.conn.execute(
        "INSERT INTO blocks (height, hash, time, sapling_tree)
        VALUES (?, ?, ?, ?)",
        &[
            u32::from(height).to_sql()?,
            hash.0.to_sql()?,
            time.to_sql()?,
            sapling_tree.to_sql()?,
        ],
    )?;

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use rusqlite::{self, ToSql, NO_PARAMS};
    use secrecy::Secret;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    use zcash_client_backend::{
        address::RecipientAddress,
        encoding::{encode_extended_full_viewing_key, encode_payment_address},
        keys::{sapling, UnifiedFullViewingKey, UnifiedSpendingKey},
    };

    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, BranchId, Parameters},
        sapling::keys::DiversifiableFullViewingKey,
        transaction::{TransactionData, TxVersion},
        zip32::ExtendedFullViewingKey,
    };

    use crate::{
        tests::{self, network},
        wallet::get_address,
        AccountId, WalletDb,
    };

    use super::{init_accounts_table, init_blocks_table, init_wallet_db};

    #[cfg(feature = "transparent-inputs")]
    use {crate::wallet::PoolType, zcash_primitives::legacy::keys as transparent};

    #[test]
    fn verify_schema() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        use regex::Regex;
        let re = Regex::new(r"\s+").unwrap();

        let expected_tables = vec![
            "CREATE TABLE \"accounts\" (
                account INTEGER PRIMARY KEY,
                ufvk TEXT NOT NULL
            )",
            "CREATE TABLE addresses (
                account INTEGER NOT NULL,
                diversifier_index BLOB NOT NULL,
                address TEXT NOT NULL,
                FOREIGN KEY (account) REFERENCES accounts(account),
                CONSTRAINT diversification UNIQUE (account, diversifier_index)
            )",
            "CREATE TABLE blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL,
                time INTEGER NOT NULL,
                sapling_tree BLOB NOT NULL
            )",
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
            "CREATE TABLE sapling_witnesses (
                id_witness INTEGER PRIMARY KEY,
                note INTEGER NOT NULL,
                block INTEGER NOT NULL,
                witness BLOB NOT NULL,
                FOREIGN KEY (note) REFERENCES received_notes(id_note),
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT witness_height UNIQUE (note, block)
            )",
            "CREATE TABLE schemer_migrations (
                id blob PRIMARY KEY
            )",
            "CREATE TABLE \"sent_notes\" (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL ,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                address TEXT NOT NULL,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(account),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index)
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
        ];

        let mut tables_query = db_data
            .conn
            .prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' ORDER BY tbl_name")
            .unwrap();
        let mut rows = tables_query.query(NO_PARAMS).unwrap();
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
            "CREATE VIEW v_transactions AS
            SELECT id_tx,
                   mined_height,
                   tx_index,
                   txid,
                   expiry_height,
                   raw,
                   SUM(value) + MAX(fee) AS net_value,
                   SUM(is_change) > 0 AS has_change,
                   SUM(memo_present) AS memo_count
            FROM (
                SELECT transactions.id_tx            AS id_tx,
                       transactions.block            AS mined_height,
                       transactions.tx_index         AS tx_index,
                       transactions.txid             AS txid,
                       transactions.expiry_height    AS expiry_height,
                       transactions.raw              AS raw,
                       transactions.fee              AS fee,
                       CASE
                            WHEN received_notes.is_change THEN 0
                            ELSE value
                       END AS value,
                       received_notes.is_change      AS is_change,
                       CASE WHEN received_notes.memo IS NULL OR received_notes.memo = '' THEN 0 ELSE 1 END AS memo_present
                FROM   transactions
                       JOIN received_notes ON transactions.id_tx = received_notes.tx
                UNION
                SELECT transactions.id_tx            AS id_tx,
                       transactions.block            AS mined_height,
                       transactions.tx_index         AS tx_index,
                       transactions.txid             AS txid,
                       transactions.expiry_height    AS expiry_height,
                       transactions.raw              AS raw,
                       0                             AS fee,
                       -sent_notes.value             AS value,
                       false                         AS is_change,
                       CASE WHEN sent_notes.memo IS NULL OR sent_notes.memo = '' THEN 0 ELSE 1 END AS memo_present
                FROM   transactions
                       JOIN sent_notes ON transactions.id_tx = sent_notes.tx
            )
            GROUP BY id_tx",
            "CREATE VIEW v_tx_received AS
            SELECT transactions.id_tx            AS id_tx,
                   transactions.block            AS mined_height,
                   transactions.tx_index         AS tx_index,
                   transactions.txid             AS txid,
                   SUM(received_notes.value)     AS received_total,
                   COUNT(received_notes.id_note) AS received_note_count,
                   SUM(CASE WHEN received_notes.memo IS NULL OR received_notes.memo = '' THEN 0 ELSE 1 END) AS memo_count,
                   blocks.time                   AS block_time
            FROM   transactions
                   JOIN received_notes
                          ON transactions.id_tx = received_notes.tx
                   LEFT JOIN blocks
                          ON transactions.block = blocks.height
            GROUP BY received_notes.tx",
            "CREATE VIEW v_tx_sent AS
            SELECT transactions.id_tx         AS id_tx,
                   transactions.block         AS mined_height,
                   transactions.tx_index      AS tx_index,
                   transactions.txid          AS txid,
                   transactions.expiry_height AS expiry_height,
                   transactions.raw           AS raw,
                   SUM(sent_notes.value)      AS sent_total,
                   COUNT(sent_notes.id_note)  AS sent_note_count,
                   SUM(CASE WHEN sent_notes.memo IS NULL OR sent_notes.memo = '' THEN 0 ELSE 1 END) AS memo_count,
                   blocks.time                AS block_time
            FROM   transactions
                   JOIN sent_notes
                          ON transactions.id_tx = sent_notes.tx
                   LEFT JOIN blocks
                          ON transactions.block = blocks.height
            GROUP BY sent_notes.tx",
        ];

        let mut views_query = db_data
            .conn
            .prepare("SELECT sql FROM sqlite_schema WHERE type = 'view' ORDER BY tbl_name")
            .unwrap();
        let mut rows = views_query.query(NO_PARAMS).unwrap();
        let mut expected_idx = 0;
        while let Some(row) = rows.next().unwrap() {
            let sql: String = row.get(0).unwrap();
            assert_eq!(
                re.replace_all(&sql, " "),
                re.replace_all(expected_views[expected_idx], " ")
            );
            expected_idx += 1;
        }
    }

    #[test]
    fn init_migrate_from_0_3_0() {
        fn init_0_3_0<P>(
            wdb: &mut WalletDb<P>,
            extfvk: &ExtendedFullViewingKey,
            account: AccountId,
        ) -> Result<(), rusqlite::Error> {
            wdb.conn.execute(
                "CREATE TABLE accounts (
                    account INTEGER PRIMARY KEY,
                    extfvk TEXT NOT NULL,
                    address TEXT NOT NULL
                )",
                NO_PARAMS,
            )?;
            wdb.conn.execute(
                "CREATE TABLE blocks (
                    height INTEGER PRIMARY KEY,
                    hash BLOB NOT NULL,
                    time INTEGER NOT NULL,
                    sapling_tree BLOB NOT NULL
                )",
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
            )?;

            let address = encode_payment_address(
                tests::network().hrp_sapling_payment_address(),
                &extfvk.default_address().1,
            );
            let extfvk = encode_extended_full_viewing_key(
                tests::network().hrp_sapling_extended_full_viewing_key(),
                extfvk,
            );
            wdb.conn.execute(
                "INSERT INTO accounts (account, extfvk, address)
                VALUES (?, ?, ?)",
                &[
                    u32::from(account).to_sql()?,
                    extfvk.to_sql()?,
                    address.to_sql()?,
                ],
            )?;

            Ok(())
        }

        let seed = [0xab; 32];
        let account = AccountId::from(0);
        let secret_key = sapling::spending_key(&seed, tests::network().coin_type(), account);
        let extfvk = ExtendedFullViewingKey::from(&secret_key);
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_0_3_0(&mut db_data, &extfvk, account).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))).unwrap();
    }

    #[test]
    fn init_migrate_from_autoshielding_poc() {
        fn init_autoshielding<P>(
            wdb: &WalletDb<P>,
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
                NO_PARAMS,
            )?;
            wdb.conn.execute(
                "CREATE TABLE blocks (
                    height INTEGER PRIMARY KEY,
                    hash BLOB NOT NULL,
                    time INTEGER NOT NULL,
                    sapling_tree BLOB NOT NULL
                )",
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
            )?;

            let address = encode_payment_address(
                tests::network().hrp_sapling_payment_address(),
                &extfvk.default_address().1,
            );
            let extfvk = encode_extended_full_viewing_key(
                tests::network().hrp_sapling_extended_full_viewing_key(),
                extfvk,
            );
            wdb.conn.execute(
                "INSERT INTO accounts (account, extfvk, address, transparent_address)
                VALUES (?, ?, ?, '')",
                &[
                    u32::from(account).to_sql()?,
                    extfvk.to_sql()?,
                    address.to_sql()?,
                ],
            )?;

            // add a sapling sent note
            wdb.conn.execute(
                "INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, '')",
                NO_PARAMS,
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
                "INSERT INTO transactions (block, id_tx, txid, raw) VALUES (0, 0, '', ?)",
                &[&tx_bytes[..]],
            )?;
            wdb.conn.execute(
                "INSERT INTO sent_notes (tx, output_index, from_account, address, value)
                VALUES (0, 0, ?, ?, 0)",
                &[u32::from(account).to_sql()?, address.to_sql()?],
            )?;

            Ok(())
        }

        let seed = [0xab; 32];
        let account = AccountId::from(0);
        let secret_key = sapling::spending_key(&seed, tests::network().coin_type(), account);
        let extfvk = ExtendedFullViewingKey::from(&secret_key);
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_autoshielding(&db_data, &extfvk, account).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))).unwrap();
    }

    #[test]
    fn init_migrate_from_main_pre_migrations() {
        fn init_main<P>(
            wdb: &WalletDb<P>,
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
                NO_PARAMS,
            )?;
            wdb.conn.execute(
                "CREATE TABLE blocks (
                    height INTEGER PRIMARY KEY,
                    hash BLOB NOT NULL,
                    time INTEGER NOT NULL,
                    sapling_tree BLOB NOT NULL
                )",
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
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
                NO_PARAMS,
            )?;

            let ufvk_str = ufvk.encode(&tests::network());
            let address_str =
                RecipientAddress::Unified(ufvk.default_address().0).encode(&tests::network());
            wdb.conn.execute(
                "INSERT INTO accounts (account, ufvk, address, transparent_address)
                VALUES (?, ?, ?, '')",
                &[
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
                        .encode(&tests::network());
                wdb.conn.execute(
                    "INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, '')",
                    NO_PARAMS,
                )?;
                wdb.conn.execute(
                    "INSERT INTO transactions (block, id_tx, txid) VALUES (0, 0, '')",
                    NO_PARAMS,
                )?;
                wdb.conn.execute(
                    "INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value)
                    VALUES (0, ?, 0, ?, ?, 0)",
                    &[PoolType::Transparent.typecode().to_sql()?, u32::from(account).to_sql()?, taddr.to_sql()?])?;
            }

            Ok(())
        }

        let seed = [0xab; 32];
        let account = AccountId::from(0);
        let secret_key = UnifiedSpendingKey::from_seed(&tests::network(), &seed, account).unwrap();
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_main(&db_data, &secret_key.to_unified_full_viewing_key(), account).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))).unwrap();
    }

    #[test]
    fn transaction_views() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        db_data.conn.execute_batch(
            "INSERT INTO accounts (account, ufvk) VALUES (0, '');
            INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (0, 0, 0, '');
            INSERT INTO transactions (block, id_tx, txid) VALUES (0, 0, '');

            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value)
            VALUES (0, 2, 0, 0, '', 2);
            INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value, memo)
            VALUES (0, 2, 1, 0, '', 3, 'a');

            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change, memo)
            VALUES (0, 0, 0, '', 5, '', 'a', false, 'b');
            INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change, memo)
            VALUES (0, 1, 0, '', 7, '', 'b', true, 'c');",
        ).unwrap();

        let mut q = db_data
            .conn
            .prepare("SELECT received_total, received_note_count, memo_count FROM v_tx_received")
            .unwrap();
        let mut rows = q.query(NO_PARAMS).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let total: i64 = row.get(0).unwrap();
            let count: i64 = row.get(1).unwrap();
            let memo_count: i64 = row.get(2).unwrap();
            assert_eq!(total, 12);
            assert_eq!(count, 2);
            assert_eq!(memo_count, 2);
        }
        assert_eq!(row_count, 1);

        let mut q = db_data
            .conn
            .prepare("SELECT sent_total, sent_note_count, memo_count FROM v_tx_sent")
            .unwrap();
        let mut rows = q.query(NO_PARAMS).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let total: i64 = row.get(0).unwrap();
            let count: i64 = row.get(1).unwrap();
            let memo_count: i64 = row.get(2).unwrap();
            assert_eq!(total, 5);
            assert_eq!(count, 2);
            assert_eq!(memo_count, 1);
        }
        assert_eq!(row_count, 1);

        let mut q = db_data
            .conn
            .prepare("SELECT net_value, has_change, memo_count FROM v_transactions")
            .unwrap();
        let mut rows = q.query(NO_PARAMS).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let net_value: i64 = row.get(0).unwrap();
            let has_change: bool = row.get(1).unwrap();
            let memo_count: i64 = row.get(2).unwrap();
            assert_eq!(net_value, 0);
            assert!(has_change);
            assert_eq!(memo_count, 3);
        }
        assert_eq!(row_count, 1);
    }

    #[test]
    fn init_accounts_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // We can call the function as many times as we want with no data
        init_accounts_table(&db_data, &HashMap::new()).unwrap();
        init_accounts_table(&db_data, &HashMap::new()).unwrap();

        let seed = [0u8; 32];
        let account = AccountId::from(0);

        // First call with data should initialise the accounts table
        let extsk = sapling::spending_key(&seed, network().coin_type(), account);
        let dfvk = DiversifiableFullViewingKey::from(ExtendedFullViewingKey::from(&extsk));

        #[cfg(feature = "transparent-inputs")]
        let ufvk = UnifiedFullViewingKey::new(
            Some(
                transparent::AccountPrivKey::from_seed(&network(), &seed, account)
                    .unwrap()
                    .to_account_pubkey(),
            ),
            Some(dfvk),
            None,
        )
        .unwrap();

        #[cfg(not(feature = "transparent-inputs"))]
        let ufvk = UnifiedFullViewingKey::new(Some(dfvk), None).unwrap();
        let ufvks = HashMap::from([(account, ufvk)]);

        init_accounts_table(&db_data, &ufvks).unwrap();

        // Subsequent calls should return an error
        init_accounts_table(&db_data, &HashMap::new()).unwrap_err();
        init_accounts_table(&db_data, &ufvks).unwrap_err();
    }

    #[test]
    fn init_blocks_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // First call with data should initialise the blocks table
        init_blocks_table(
            &db_data,
            BlockHeight::from(1u32),
            BlockHash([1; 32]),
            1,
            &[],
        )
        .unwrap();

        // Subsequent calls should return an error
        init_blocks_table(
            &db_data,
            BlockHeight::from(2u32),
            BlockHash([2; 32]),
            2,
            &[],
        )
        .unwrap_err();
    }

    #[test]
    fn init_accounts_table_stores_correct_address() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        let seed = [0u8; 32];

        // Add an account to the wallet
        let account_id = AccountId::from(0);
        let usk = UnifiedSpendingKey::from_seed(&tests::network(), &seed, account_id).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let expected_address = ufvk.sapling().unwrap().default_address().1;
        let ufvks = HashMap::from([(account_id, ufvk)]);
        init_accounts_table(&db_data, &ufvks).unwrap();

        // The account's address should be in the data DB
        let pa = get_address(&db_data, AccountId::from(0)).unwrap();
        assert_eq!(pa.unwrap(), expected_address);
    }
}
