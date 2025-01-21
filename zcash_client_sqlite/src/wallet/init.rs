//! Functions for initializing the various databases.

use std::fmt;
use std::rc::Rc;

use regex::Regex;
use schemerz::{Migrator, MigratorError};
use schemerz_rusqlite::RusqliteAdapter;
use secrecy::SecretVec;
use shardtree::error::ShardTreeError;
use uuid::Uuid;

use zcash_client_backend::data_api::{SeedRelevance, WalletRead};
use zcash_keys::keys::AddressGenerationError;
use zcash_protocol::{consensus, value::BalanceError};

use self::migrations::verify_network_compatibility;

use super::commitment_tree;
use crate::{error::SqliteClientError, WalletDb};

mod migrations;

const SQLITE_MAJOR_VERSION: u32 = 3;
const MIN_SQLITE_MINOR_VERSION: u32 = 35;

const MIGRATIONS_TABLE: &str = "schemer_migrations";

#[derive(Debug)]
pub enum WalletMigrationError {
    /// A feature required by the wallet database is not supported by the version of
    /// SQLite that the migration is running against.
    DatabaseNotSupported(String),

    /// The seed is required for the migration.
    SeedRequired,

    /// A seed was provided that is not relevant to any of the accounts within the wallet.
    ///
    /// Specifically, it is not relevant to any account for which [`Account::source`] is
    /// [`AccountSource::Derived`]. We do not check whether the seed is relevant to any
    /// imported account, because that would require brute-forcing the ZIP 32 account
    /// index space.
    ///
    /// [`Account::source`]: zcash_client_backend::data_api::Account::source
    /// [`AccountSource::Derived`]: zcash_client_backend::data_api::AccountSource::Derived
    SeedNotRelevant,

    /// Decoding of an existing value from its serialized form has failed.
    CorruptedData(String),

    /// An error occurred in migrating a Zcash address or key.
    AddressGeneration(AddressGenerationError),

    /// Wrapper for rusqlite errors.
    DbError(rusqlite::Error),

    /// Wrapper for amount balance violations
    BalanceError(BalanceError),

    /// Wrapper for commitment tree invariant violations
    CommitmentTree(ShardTreeError<commitment_tree::Error>),

    /// Reverting the specified migration is not supported.
    CannotRevert(Uuid),

    /// Some other unexpected violation of database business rules occurred
    Other(SqliteClientError),
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

impl From<AddressGenerationError> for WalletMigrationError {
    fn from(e: AddressGenerationError) -> Self {
        WalletMigrationError::AddressGeneration(e)
    }
}

impl From<SqliteClientError> for WalletMigrationError {
    fn from(value: SqliteClientError) -> Self {
        match value {
            SqliteClientError::CorruptedData(err) => WalletMigrationError::CorruptedData(err),
            SqliteClientError::DbError(err) => WalletMigrationError::DbError(err),
            SqliteClientError::CommitmentTree(err) => WalletMigrationError::CommitmentTree(err),
            SqliteClientError::BalanceError(err) => WalletMigrationError::BalanceError(err),
            SqliteClientError::AddressGeneration(err) => {
                WalletMigrationError::AddressGeneration(err)
            }
            other => WalletMigrationError::Other(other),
        }
    }
}

impl fmt::Display for WalletMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            WalletMigrationError::DatabaseNotSupported(version) => {
                write!(
                    f,
                    "The installed SQLite version {} does not support operations required by the wallet.",
                    version
                )
            }
            WalletMigrationError::SeedRequired => {
                write!(
                    f,
                    "The wallet seed is required in order to update the database."
                )
            }
            WalletMigrationError::SeedNotRelevant => {
                write!(
                    f,
                    "The provided seed is not relevant to any derived accounts in the database."
                )
            }
            WalletMigrationError::CorruptedData(reason) => {
                write!(f, "Wallet database is corrupted: {}", reason)
            }
            WalletMigrationError::DbError(e) => write!(f, "{}", e),
            WalletMigrationError::BalanceError(e) => write!(f, "Balance error: {:?}", e),
            WalletMigrationError::CommitmentTree(e) => write!(f, "Commitment tree error: {:?}", e),
            WalletMigrationError::AddressGeneration(e) => {
                write!(f, "Address generation error: {:?}", e)
            }
            WalletMigrationError::CannotRevert(uuid) => {
                write!(f, "Reverting migration {} is not supported", uuid)
            }
            WalletMigrationError::Other(err) => {
                write!(
                    f,
                    "Unexpected violation of database business rules: {}",
                    err
                )
            }
        }
    }
}

impl std::error::Error for WalletMigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            WalletMigrationError::DbError(e) => Some(e),
            WalletMigrationError::BalanceError(e) => Some(e),
            WalletMigrationError::CommitmentTree(e) => Some(e),
            WalletMigrationError::AddressGeneration(e) => Some(e),
            WalletMigrationError::Other(e) => Some(e),
            _ => None,
        }
    }
}

/// Helper to enable calling regular `WalletDb` methods inside the migration code.
///
/// In this context we can know the full set of errors that are generated by any call we
/// make, so we mark errors as unreachable instead of adding new `WalletMigrationError`
/// variants.
fn sqlite_client_error_to_wallet_migration_error(e: SqliteClientError) -> WalletMigrationError {
    match e {
        SqliteClientError::CorruptedData(e) => WalletMigrationError::CorruptedData(e),
        SqliteClientError::Protobuf(e) => WalletMigrationError::CorruptedData(e.to_string()),
        SqliteClientError::InvalidNote => {
            WalletMigrationError::CorruptedData("invalid note".into())
        }
        SqliteClientError::DecodingError(e) => WalletMigrationError::CorruptedData(e.to_string()),
        #[cfg(feature = "transparent-inputs")]
        SqliteClientError::TransparentDerivation(e) => {
            WalletMigrationError::CorruptedData(e.to_string())
        }
        #[cfg(feature = "transparent-inputs")]
        SqliteClientError::TransparentAddress(e) => {
            WalletMigrationError::CorruptedData(e.to_string())
        }
        SqliteClientError::DbError(e) => WalletMigrationError::DbError(e),
        SqliteClientError::Io(e) => WalletMigrationError::CorruptedData(e.to_string()),
        SqliteClientError::InvalidMemo(e) => WalletMigrationError::CorruptedData(e.to_string()),
        SqliteClientError::AddressGeneration(e) => WalletMigrationError::AddressGeneration(e),
        SqliteClientError::BadAccountData(e) => WalletMigrationError::CorruptedData(e),
        SqliteClientError::CommitmentTree(e) => WalletMigrationError::CommitmentTree(e),
        SqliteClientError::UnsupportedPoolType(pool) => WalletMigrationError::CorruptedData(
            format!("Wallet DB contains unsupported pool type {}", pool),
        ),
        SqliteClientError::BalanceError(e) => WalletMigrationError::BalanceError(e),
        SqliteClientError::TableNotEmpty => unreachable!("wallet already initialized"),
        SqliteClientError::BlockConflict(_)
        | SqliteClientError::NonSequentialBlocks
        | SqliteClientError::RequestedRewindInvalid { .. }
        | SqliteClientError::KeyDerivationError(_)
        | SqliteClientError::Zip32AccountIndexOutOfRange
        | SqliteClientError::AccountCollision(_)
        | SqliteClientError::CacheMiss(_) => {
            unreachable!("we only call WalletRead methods; mutations can't occur")
        }
        #[cfg(feature = "transparent-inputs")]
        SqliteClientError::AddressNotRecognized(_) => {
            unreachable!("we only call WalletRead methods; mutations can't occur")
        }
        SqliteClientError::AccountUnknown => {
            unreachable!("all accounts are known in migration context")
        }
        SqliteClientError::UnknownZip32Derivation => {
            unreachable!("we don't call methods that require operating on imported accounts")
        }
        SqliteClientError::ChainHeightUnknown => {
            unreachable!("we don't call methods that require a known chain height")
        }
        #[cfg(feature = "transparent-inputs")]
        SqliteClientError::ReachedGapLimit(_, _) => {
            unreachable!("we don't do ephemeral address tracking")
        }
        #[cfg(feature = "transparent-inputs")]
        SqliteClientError::EphemeralAddressReuse(_, _) => {
            unreachable!("we don't do ephemeral address tracking")
        }
        SqliteClientError::NoteFilterInvalid(_) => {
            unreachable!("we don't do note selection in migrations")
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
/// In order to correctly apply migrations to accounts derived from a seed, sometimes the
/// optional `seed` argument is required. This function should first be invoked with
/// `seed` set to `None`; if a pending migration requires the seed, the function returns
/// `Err(schemerz::MigratorError::Migration { error: WalletMigrationError::SeedRequired, .. })`.
/// The caller can then re-call this function with the necessary seed.
///
/// > Note that currently only one seed can be provided; as such, wallets containing
/// > accounts derived from several different seeds are unsupported, and will result in an
/// > error. Support for multi-seed wallets is being tracked in [zcash/librustzcash#1284].
///
/// When the `seed` argument is provided, the seed is checked against the database for
/// _relevance_: if any account in the wallet for which [`Account::source`] is
/// [`AccountSource::Derived`] can be derived from the given seed, the seed is relevant to
/// the wallet. If the given seed is not relevant, the function returns
/// `Err(schemerz::MigratorError::Migration { error: WalletMigrationError::SeedNotRelevant, .. })`
/// or `Err(schemerz::MigratorError::Adapter(WalletMigrationError::SeedNotRelevant))`.
///
/// We do not check whether the seed is relevant to any imported account, because that
/// would require brute-forcing the ZIP 32 account index space. Consequentially, imported
/// accounts are not migrated.
///
/// It is safe to use a wallet database previously created without the ability to create
/// transparent spends with a build that enables transparent spends (via use of the
/// `transparent-inputs` feature flag.) The reverse is unsafe, as wallet balance calculations would
/// ignore the transparent UTXOs already controlled by the wallet.
///
/// [zcash/librustzcash#1284]: https://github.com/zcash/librustzcash/issues/1284
/// [`Account::source`]: zcash_client_backend::data_api::Account::source
/// [`AccountSource::Derived`]: zcash_client_backend::data_api::AccountSource::Derived
///
/// # Examples
///
/// ```
/// # use std::error::Error;
/// # use secrecy::SecretVec;
/// # use tempfile::NamedTempFile;
/// use zcash_protocol::consensus::Network;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::init::{WalletMigrationError, init_wallet_db},
/// };
///
/// # fn main() -> Result<(), Box<dyn Error>> {
/// # let data_file = NamedTempFile::new().unwrap();
/// # let get_data_db_path = || data_file.path();
/// # let load_seed = || -> Result<_, String> { Ok(SecretVec::new(vec![])) };
/// let mut db = WalletDb::for_path(get_data_db_path(), Network::TestNetwork)?;
/// match init_wallet_db(&mut db, None) {
///     Err(e)
///         if matches!(
///             e.source().and_then(|e| e.downcast_ref()),
///             Some(&WalletMigrationError::SeedRequired)
///         ) =>
///     {
///         let seed = load_seed()?;
///         init_wallet_db(&mut db, Some(seed))
///     }
///     res => res,
/// }?;
/// # Ok(())
/// # }
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
) -> Result<(), MigratorError<Uuid, WalletMigrationError>> {
    init_wallet_db_internal(wdb, seed, &[], true)
}

pub(crate) fn init_wallet_db_internal<P: consensus::Parameters + 'static>(
    wdb: &mut WalletDb<rusqlite::Connection, P>,
    seed: Option<SecretVec<u8>>,
    target_migrations: &[Uuid],
    verify_seed_relevance: bool,
) -> Result<(), MigratorError<Uuid, WalletMigrationError>> {
    let seed = seed.map(Rc::new);

    verify_sqlite_version_compatibility(&wdb.conn).map_err(MigratorError::Adapter)?;

    // Turn off foreign key enforcement, to ensure that table replacement does not break foreign
    // key references in table definitions.
    //
    // It is necessary to perform this operation globally using the outer connection because this
    // pragma has no effect when set or unset within a transaction.
    wdb.conn
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(|e| MigratorError::Adapter(WalletMigrationError::from(e)))?;

    // Temporarily take ownership of the connection in a wrapper to perform the initial migration
    // table setup. This extra adapter creation could be omitted if `RusqliteAdapter` provided an
    // accessor for the connection that it wraps, or if it provided a mechanism to query to
    // determine whether a given migration has been applied. (see
    // https://github.com/zcash/schemerz/issues/6)
    {
        let adapter = RusqliteAdapter::<'_, WalletMigrationError>::new(
            &mut wdb.conn,
            Some(MIGRATIONS_TABLE.to_string()),
        );
        adapter.init().expect("Migrations table setup succeeds.");
    }

    // Now that we are certain that the migrations table exists, verify that if the database
    // already contains account data, any stored UFVKs correspond to the same network that the
    // migrations are being run for.
    verify_network_compatibility(&wdb.conn, &wdb.params).map_err(MigratorError::Adapter)?;

    // Now create the adapter that we're actually going to use to perform the migrations, and
    // proceed.
    let adapter = RusqliteAdapter::new(&mut wdb.conn, Some(MIGRATIONS_TABLE.to_string()));
    let mut migrator = Migrator::new(adapter);
    migrator
        .register_multiple(migrations::all_migrations(&wdb.params, seed.clone()).into_iter())
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

    // Now that the migration succeeded, check whether the seed is relevant to the wallet.
    // We can only check this if we have migrated as far as `full_account_ids::MIGRATION_ID`,
    // but unfortunately `schemer` does not currently expose its DAG of migrations. As a
    // consequence, the caller has to choose whether or not this check should be performed
    // based upon which migrations they're asking to apply.
    if verify_seed_relevance {
        if let Some(seed) = seed {
            match wdb
                .seed_relevance_to_derived_accounts(&seed)
                .map_err(sqlite_client_error_to_wallet_migration_error)?
            {
                SeedRelevance::Relevant { .. } => (),
                // Every seed is relevant to a wallet with no accounts; this is most likely a
                // new wallet database being initialized for the first time.
                SeedRelevance::NoAccounts => (),
                // No seed is relevant to a wallet that only has imported accounts.
                SeedRelevance::NotRelevant | SeedRelevance::NoDerivedAccounts => {
                    return Err(WalletMigrationError::SeedNotRelevant.into())
                }
            }
        }
    }

    Ok(())
}

/// Verify that the sqlite version in use supports the features required by this library.
/// Note that the version of sqlite available to the database backend may be different
/// from what is used to query the views that are part of the public API.
fn verify_sqlite_version_compatibility(
    conn: &rusqlite::Connection,
) -> Result<(), WalletMigrationError> {
    let sqlite_version =
        conn.query_row("SELECT sqlite_version()", [], |row| row.get::<_, String>(0))?;

    let version_re = Regex::new(r"^(?<major>[0-9]+)\.(?<minor>[0-9]+).*$").unwrap();
    let captures =
        version_re
            .captures(&sqlite_version)
            .ok_or(WalletMigrationError::DatabaseNotSupported(
                "Unknown".to_owned(),
            ))?;
    let parse_version_part = |part: &str| {
        captures[part].parse::<u32>().map_err(|_| {
            WalletMigrationError::CorruptedData(format!(
                "Cannot decode SQLite {} version component {}",
                part, &captures[part]
            ))
        })
    };
    let major = parse_version_part("major")?;
    let minor = parse_version_part("minor")?;

    if major != SQLITE_MAJOR_VERSION || minor < MIN_SQLITE_MINOR_VERSION {
        Err(WalletMigrationError::DatabaseNotSupported(sqlite_version))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{self, named_params, Connection, ToSql};
    use secrecy::Secret;

    use tempfile::NamedTempFile;

    use ::sapling::zip32::ExtendedFullViewingKey;
    use zcash_client_backend::data_api::testing::TestBuilder;
    use zcash_keys::{
        address::Address,
        encoding::{encode_extended_full_viewing_key, encode_payment_address},
        keys::{
            sapling, ReceiverRequirement::*, UnifiedAddressRequest, UnifiedFullViewingKey,
            UnifiedSpendingKey,
        },
    };
    use zcash_primitives::transaction::{TransactionData, TxVersion};
    use zcash_protocol::consensus::{self, BlockHeight, BranchId, Network, NetworkConstants};
    use zip32::AccountId;

    use crate::{testing::db::TestDbFactory, wallet::db, WalletDb, UA_TRANSPARENT};

    use super::init_wallet_db;

    #[cfg(feature = "transparent-inputs")]
    use {
        super::WalletMigrationError,
        crate::wallet::{self, pool_code, PoolType},
        zcash_address::test_vectors,
        zcash_client_backend::data_api::WalletWrite,
        zip32::DiversifierIndex,
    };

    pub(crate) fn describe_tables(conn: &Connection) -> Result<Vec<String>, rusqlite::Error> {
        let result = conn
            .prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' ORDER BY tbl_name")?
            .query_and_then([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(result)
    }

    #[test]
    fn verify_schema() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .build();

        use regex::Regex;
        let re = Regex::new(r"\s+").unwrap();

        let expected_tables = vec![
            db::TABLE_ACCOUNTS,
            db::TABLE_ADDRESSES,
            db::TABLE_BLOCKS,
            db::TABLE_EPHEMERAL_ADDRESSES,
            db::TABLE_NULLIFIER_MAP,
            db::TABLE_ORCHARD_RECEIVED_NOTE_SPENDS,
            db::TABLE_ORCHARD_RECEIVED_NOTES,
            db::TABLE_ORCHARD_TREE_CAP,
            db::TABLE_ORCHARD_TREE_CHECKPOINT_MARKS_REMOVED,
            db::TABLE_ORCHARD_TREE_CHECKPOINTS,
            db::TABLE_ORCHARD_TREE_SHARDS,
            db::TABLE_SAPLING_RECEIVED_NOTE_SPENDS,
            db::TABLE_SAPLING_RECEIVED_NOTES,
            db::TABLE_SAPLING_TREE_CAP,
            db::TABLE_SAPLING_TREE_CHECKPOINT_MARKS_REMOVED,
            db::TABLE_SAPLING_TREE_CHECKPOINTS,
            db::TABLE_SAPLING_TREE_SHARDS,
            db::TABLE_SCAN_QUEUE,
            db::TABLE_SCHEMERZ_MIGRATIONS,
            db::TABLE_SENT_NOTES,
            db::TABLE_SQLITE_SEQUENCE,
            db::TABLE_TRANSACTIONS,
            db::TABLE_TRANSPARENT_RECEIVED_OUTPUT_SPENDS,
            db::TABLE_TRANSPARENT_RECEIVED_OUTPUTS,
            db::TABLE_TRANSPARENT_SPEND_MAP,
            db::TABLE_TRANSPARENT_SPEND_SEARCH_QUEUE,
            db::TABLE_TX_LOCATOR_MAP,
            db::TABLE_TX_RETRIEVAL_QUEUE,
        ];

        let rows = describe_tables(&st.wallet().db().conn).unwrap();
        assert_eq!(rows.len(), expected_tables.len());
        for (actual, expected) in rows.iter().zip(expected_tables.iter()) {
            assert_eq!(
                re.replace_all(actual, " "),
                re.replace_all(expected, " ").trim(),
            );
        }

        let expected_indices = vec![
            db::INDEX_ACCOUNTS_UFVK,
            db::INDEX_ACCOUNTS_UIVK,
            db::INDEX_ACCOUNTS_UUID,
            db::INDEX_HD_ACCOUNT,
            db::INDEX_ADDRESSES_ACCOUNTS,
            db::INDEX_NF_MAP_LOCATOR_IDX,
            db::INDEX_ORCHARD_RECEIVED_NOTES_ACCOUNT,
            db::INDEX_ORCHARD_RECEIVED_NOTES_TX,
            db::INDEX_SAPLING_RECEIVED_NOTES_ACCOUNT,
            db::INDEX_SAPLING_RECEIVED_NOTES_TX,
            db::INDEX_SENT_NOTES_FROM_ACCOUNT,
            db::INDEX_SENT_NOTES_TO_ACCOUNT,
            db::INDEX_SENT_NOTES_TX,
            db::INDEX_TRANSPARENT_RECEIVED_OUTPUTS_ACCOUNT_ID,
        ];
        let mut indices_query = st
            .wallet()
            .db()
            .conn
            .prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND sql != '' ORDER BY tbl_name, name")
            .unwrap();
        let mut rows = indices_query.query([]).unwrap();
        let mut expected_idx = 0;
        while let Some(row) = rows.next().unwrap() {
            let sql: String = row.get(0).unwrap();
            assert_eq!(
                re.replace_all(&sql, " "),
                re.replace_all(expected_indices[expected_idx], " ").trim(),
            );
            expected_idx += 1;
        }

        let expected_views = vec![
            db::view_orchard_shard_scan_ranges(st.network()),
            db::view_orchard_shard_unscanned_ranges(),
            db::VIEW_ORCHARD_SHARDS_SCAN_STATE.to_owned(),
            db::VIEW_RECEIVED_OUTPUT_SPENDS.to_owned(),
            db::VIEW_RECEIVED_OUTPUTS.to_owned(),
            db::view_sapling_shard_scan_ranges(st.network()),
            db::view_sapling_shard_unscanned_ranges(),
            db::VIEW_SAPLING_SHARDS_SCAN_STATE.to_owned(),
            db::VIEW_TRANSACTIONS.to_owned(),
            db::VIEW_TX_OUTPUTS.to_owned(),
        ];

        let mut views_query = st
            .wallet()
            .db()
            .conn
            .prepare("SELECT sql FROM sqlite_schema WHERE type = 'view' ORDER BY tbl_name")
            .unwrap();
        let mut rows = views_query.query([]).unwrap();
        let mut expected_idx = 0;
        while let Some(row) = rows.next().unwrap() {
            let sql: String = row.get(0).unwrap();
            assert_eq!(
                re.replace_all(&sql, " "),
                re.replace_all(&expected_views[expected_idx], " ").trim(),
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
        let account = AccountId::ZERO;
        let secret_key = sapling::spending_key(&seed, db_data.params.coin_type(), account);
        #[allow(deprecated)]
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
        let account = AccountId::ZERO;
        let secret_key = sapling::spending_key(&seed, db_data.params.coin_type(), account);
        #[allow(deprecated)]
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

            // Unified addresses at the time of the addition of migrations did not contain an
            // Orchard component.
            let ua_request =
                UnifiedAddressRequest::unsafe_new_without_expiry(Omit, Require, UA_TRANSPARENT);
            let address_str = Address::from(
                ufvk.default_address(Some(ua_request))
                    .expect("A valid default address exists for the UFVK")
                    .0,
            )
            .encode(&wdb.params);
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
                let taddr = Address::from(
                    *ufvk
                        .default_address(Some(ua_request))
                        .expect("A valid default address exists for the UFVK")
                        .0
                        .transparent()
                        .unwrap(),
                )
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
                    [pool_code(PoolType::TRANSPARENT).to_sql()?, u32::from(account).to_sql()?, taddr.to_sql()?])?;
            }

            Ok(())
        }

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();

        let seed = [0xab; 32];
        let account = AccountId::ZERO;
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
        use zcash_client_backend::data_api::{AccountBirthday, AccountSource, WalletRead};
        use zcash_primitives::block::BlockHash;

        let network = Network::MainNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), network).unwrap();
        assert_matches!(init_wallet_db(&mut db_data, None), Ok(_));

        // Prior to adding any accounts, every seed phrase is relevant to the wallet.
        let seed = test_vectors::UNIFIED[0].root_seed;
        let other_seed = [7; 32];
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))),
            Ok(())
        );
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(other_seed.to_vec()))),
            Ok(())
        );

        let birthday = AccountBirthday::from_sapling_activation(&network, BlockHash([0; 32]));
        let (account_id, _usk) = db_data
            .create_account("", &Secret::new(seed.to_vec()), &birthday, None)
            .unwrap();
        assert_matches!(
            db_data.get_account(account_id),
            Ok(Some(account)) if matches!(
                &account.kind,
                AccountSource::Derived{derivation, ..} if derivation.account_index() == zip32::AccountId::ZERO,
            )
        );

        // After adding an account, only the real seed phrase is relevant to the wallet.
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(seed.to_vec()))),
            Ok(())
        );
        assert_matches!(
            init_wallet_db(&mut db_data, Some(Secret::new(other_seed.to_vec()))),
            Err(schemerz::MigratorError::Adapter(
                WalletMigrationError::SeedNotRelevant
            ))
        );

        for tv in &test_vectors::UNIFIED[..3] {
            if let Some(Address::Unified(tvua)) =
                Address::decode(&Network::MainNetwork, tv.unified_addr)
            {
                let (ua, di) =
                    wallet::get_current_address(&db_data.conn, &db_data.params, account_id)
                        .unwrap()
                        .expect("create_account generated the first address");
                assert_eq!(DiversifierIndex::from(tv.diversifier_index), di);
                assert_eq!(tvua.transparent(), ua.transparent());
                assert_eq!(tvua.sapling(), ua.sapling());
                #[cfg(not(feature = "orchard"))]
                assert_eq!(tv.unified_addr, ua.encode(&Network::MainNetwork));

                // hardcoded with knowledge of what's coming next
                let ua_request =
                    UnifiedAddressRequest::unsafe_new_without_expiry(Omit, Require, Require);
                db_data
                    .get_next_available_address(account_id, Some(ua_request))
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
