//! Functions for initializing the various databases.

use rusqlite::{types::ToSql, NO_PARAMS};

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    zip32::ExtendedFullViewingKey,
};

use zcash_client_backend::{data_api::error::Error, encoding::encode_extended_full_viewing_key};

use crate::{address_from_extfvk, error::SqliteClientError, CacheConnection, DataConnection};

/// Sets up the internal structure of the cache database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     CacheConnection,
///     init::init_cache_database,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let db = CacheConnection::for_path(cache_file.path()).unwrap();
/// init_cache_database(&db).unwrap();
/// ```
pub fn init_cache_database(db_cache: &CacheConnection) -> Result<(), rusqlite::Error> {
    db_cache.0.execute(
        "CREATE TABLE IF NOT EXISTS compactblocks (
            height INTEGER PRIMARY KEY,
            data BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    Ok(())
}

/// Sets up the internal structure of the data database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     DataConnection,
///     init::init_data_database,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file.path()).unwrap();
/// init_data_database(&db).unwrap();
/// ```
pub fn init_data_database(db_data: &DataConnection) -> Result<(), rusqlite::Error> {
    db_data.0.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            account INTEGER PRIMARY KEY,
            extfvk TEXT NOT NULL,
            address TEXT NOT NULL
        )",
        NO_PARAMS,
    )?;
    db_data.0.execute(
        "CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            hash BLOB NOT NULL,
            time INTEGER NOT NULL,
            sapling_tree BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    db_data.0.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
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
    db_data.0.execute(
        "CREATE TABLE IF NOT EXISTS received_notes (
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
    db_data.0.execute(
        "CREATE TABLE IF NOT EXISTS sapling_witnesses (
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
    db_data.0.execute(
        "CREATE TABLE IF NOT EXISTS sent_notes (
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
    Ok(())
}

/// Initialises the data database with the given [`ExtendedFullViewingKey`]s.
///
/// The [`ExtendedFullViewingKey`]s are stored internally and used by other APIs such as
/// [`get_address`], [`scan_cached_blocks`], and [`create_to_address`]. `extfvks` **MUST**
/// be arranged in account-order; that is, the [`ExtendedFullViewingKey`] for ZIP 32
/// account `i` **MUST** be at `extfvks[i]`.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
///
/// use zcash_primitives::{
///     consensus::Network,
///     zip32::{ExtendedFullViewingKey, ExtendedSpendingKey}
/// };
///
/// use zcash_client_sqlite::{
///     DataConnection,
///     init::{init_accounts_table, init_data_database}
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_data = DataConnection::for_path(data_file.path()).unwrap();
/// init_data_database(&db_data).unwrap();
///
/// let extsk = ExtendedSpendingKey::master(&[]);
/// let extfvks = [ExtendedFullViewingKey::from(&extsk)];
/// init_accounts_table(&db_data, &Network::TestNetwork, &extfvks).unwrap();
/// ```
///
/// [`get_address`]: crate::query::get_address
/// [`scan_cached_blocks`]: crate::scan::scan_cached_blocks
/// [`create_to_address`]: crate::transact::create_to_address
pub fn init_accounts_table<P: consensus::Parameters>(
    data: &DataConnection,
    params: &P,
    extfvks: &[ExtendedFullViewingKey],
) -> Result<(), SqliteClientError> {
    let mut empty_check = data.0.prepare("SELECT * FROM accounts LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(SqliteClientError(Error::TableNotEmpty));
    }

    // Insert accounts atomically
    data.0.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
    for (account, extfvk) in extfvks.iter().enumerate() {
        let extfvk_str = encode_extended_full_viewing_key(
            params.hrp_sapling_extended_full_viewing_key(),
            extfvk,
        );

        let address_str = address_from_extfvk(params, extfvk);

        data.0.execute(
            "INSERT INTO accounts (account, extfvk, address)
            VALUES (?, ?, ?)",
            &[
                (account as u32).to_sql()?,
                extfvk_str.to_sql()?,
                address_str.to_sql()?,
            ],
        )?;
    }
    data.0.execute("COMMIT", NO_PARAMS)?;

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
///     consensus::BlockHeight,
/// };
/// use zcash_client_sqlite::{
///     DataConnection,
///     init::init_blocks_table,
/// };
///
/// // The block height.
/// let height = BlockHeight(500_000);
/// // The hash of the block header.
/// let hash = BlockHash([0; 32]);
/// // The nTime field from the block header.
/// let time = 12_3456_7890;
/// // The serialized Sapling commitment tree as of this block.
/// // Pre-compute and hard-code, or obtain from a service.
/// let sapling_tree = &[];
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file.path()).unwrap();
/// init_blocks_table(&db, height, hash, time, sapling_tree);
/// ```
pub fn init_blocks_table(
    data: &DataConnection,
    height: BlockHeight,
    hash: BlockHash,
    time: u32,
    sapling_tree: &[u8],
) -> Result<(), SqliteClientError> {
    let mut empty_check = data.0.prepare("SELECT * FROM blocks LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(SqliteClientError(Error::TableNotEmpty));
    }

    data.0.execute(
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
mod tests {
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    use zcash_primitives::{
        block::BlockHash,
        consensus::BlockHeight,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use crate::{query::get_address, tests, Account, DataConnection};

    use super::{init_accounts_table, init_blocks_table, init_data_database};

    #[test]
    fn init_accounts_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // We can call the function as many times as we want with no data
        init_accounts_table(&db_data, &tests::network(), &[]).unwrap();
        init_accounts_table(&db_data, &tests::network(), &[]).unwrap();

        // First call with data should initialise the accounts table
        let extfvks = [ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(
            &[],
        ))];
        init_accounts_table(&db_data, &tests::network(), &extfvks).unwrap();

        // Subsequent calls should return an error
        init_accounts_table(&db_data, &tests::network(), &[]).unwrap_err();
        init_accounts_table(&db_data, &tests::network(), &extfvks).unwrap_err();
    }

    #[test]
    fn init_blocks_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

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
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &tests::network(), &extfvks).unwrap();

        // The account's address should be in the data DB
        let pa = get_address(&db_data, &tests::network(), Account(0)).unwrap();
        assert_eq!(pa.unwrap(), extsk.default_address().unwrap().1);
    }
}
