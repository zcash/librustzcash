//! Functions for initializing the various databases.

use rusqlite::{types::ToSql, Connection, NO_PARAMS};
use std::path::Path;
use zcash_client_backend::encoding::encode_extended_full_viewing_key;

use zcash_primitives::{
    block::BlockHash,
    consensus,
    zip32::ExtendedFullViewingKey,
};

use crate::{
    address_from_extfvk,
    error::{Error, ErrorKind},
};

/// Sets up the internal structure of the cache database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::init::init_cache_database;
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_cache = data_file.path();
/// init_cache_database(&db_cache).unwrap();
/// ```
pub fn init_cache_database<P: AsRef<Path>>(db_cache: P) -> Result<(), Error> {
    let cache = Connection::open(db_cache)?;
    cache.execute(
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
/// use zcash_client_sqlite::init::init_data_database;
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_data = data_file.path();
/// init_data_database(&db_data).unwrap();
/// ```
pub fn init_data_database<P: AsRef<Path>>(db_data: P) -> Result<(), Error> {
    let data = Connection::open(db_data)?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            account INTEGER PRIMARY KEY,
            extfvk TEXT NOT NULL,
            address TEXT NOT NULL
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            hash BLOB NOT NULL,
            time INTEGER NOT NULL,
            sapling_tree BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    data.execute(
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
    data.execute(
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
    data.execute(
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
    data.execute(
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
/// use zcash_client_sqlite::init::{init_accounts_table, init_data_database};
/// use zcash_primitives::{
///     consensus::Network,
///     zip32::{ExtendedFullViewingKey, ExtendedSpendingKey}
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_data = data_file.path();
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
pub fn init_accounts_table<D: AsRef<Path>, P: consensus::Parameters>(
    db_data: D,
    params: &P,
    extfvks: &[ExtendedFullViewingKey],
) -> Result<(), Error> {
    let data = Connection::open(db_data)?;

    let mut empty_check = data.prepare("SELECT * FROM accounts LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(Error(ErrorKind::TableNotEmpty));
    }

    // Insert accounts atomically
    data.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
    for (account, extfvk) in extfvks.iter().enumerate() {
        let address = address_from_extfvk(params, extfvk);
        let extfvk = encode_extended_full_viewing_key(
            params.hrp_sapling_extended_full_viewing_key(),
            extfvk,
        );
        data.execute(
            "INSERT INTO accounts (account, extfvk, address)
            VALUES (?, ?, ?)",
            &[
                (account as u32).to_sql()?,
                extfvk.to_sql()?,
                address.to_sql()?,
            ],
        )?;
    }
    data.execute("COMMIT", NO_PARAMS)?;

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
/// use zcash_client_sqlite::init::init_blocks_table;
/// use zcash_primitives::block::BlockHash;
///
/// // The block height.
/// let height = 500_000;
/// // The hash of the block header.
/// let hash = BlockHash([0; 32]);
/// // The nTime field from the block header.
/// let time = 12_3456_7890;
/// // The serialized Sapling commitment tree as of this block.
/// // Pre-compute and hard-code, or obtain from a service.
/// let sapling_tree = &[];
///
/// init_blocks_table("/path/to/data.db", height, hash, time, sapling_tree);
/// ```
pub fn init_blocks_table<P: AsRef<Path>>(
    db_data: P,
    height: i32,
    hash: BlockHash,
    time: u32,
    sapling_tree: &[u8],
) -> Result<(), Error> {
    let data = Connection::open(db_data)?;

    let mut empty_check = data.prepare("SELECT * FROM blocks LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(Error(ErrorKind::TableNotEmpty));
    }

    data.execute(
        "INSERT INTO blocks (height, hash, time, sapling_tree)
        VALUES (?, ?, ?, ?)",
        &[
            height.to_sql()?,
            hash.0.to_sql()?,
            time.to_sql()?,
            sapling_tree.to_sql()?,
        ],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zcash_client_backend::encoding::decode_payment_address;
    use zcash_primitives::{
        block::BlockHash,
        consensus::Parameters,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use super::{init_accounts_table, init_blocks_table, init_data_database};
    use crate::{
        query::get_address,
        tests,
    };

    #[test]
    fn init_accounts_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
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
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // First call with data should initialise the blocks table
        init_blocks_table(&db_data, 1, BlockHash([1; 32]), 1, &[]).unwrap();

        // Subsequent calls should return an error
        init_blocks_table(&db_data, 2, BlockHash([2; 32]), 2, &[]).unwrap_err();
    }

    #[test]
    fn init_accounts_table_stores_correct_address() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &tests::network(), &extfvks).unwrap();

        // The account's address should be in the data DB
        let addr = get_address(&db_data, 0).unwrap();
        let pa =
            decode_payment_address(tests::network().hrp_sapling_payment_address(), &addr).unwrap();
        assert_eq!(pa.unwrap(), extsk.default_address().unwrap().1);
    }
}
