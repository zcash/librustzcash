//! Functions for initializing the various databases.

use rusqlite::{types::ToSql, NO_PARAMS};

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    legacy::TransparentAddress,
    zip32::ExtendedFullViewingKey,
};

use zcash_client_backend::encoding::{encode_extended_full_viewing_key, AddressCodec};

use crate::{address_from_extfvk, error::SqliteClientError, WalletDb};

/// Sets up the internal structure of the data database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::init::init_wallet_db,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
/// init_wallet_db(&db).unwrap();
/// ```
pub fn init_wallet_db<P>(wdb: &WalletDb<P>) -> Result<(), rusqlite::Error> {
    wdb.conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            account INTEGER PRIMARY KEY,
            extfvk TEXT NOT NULL,
            address TEXT NOT NULL,
            transparent_address TEXT NOT NULL
        )",
        NO_PARAMS,
    )?;
    wdb.conn.execute(
        "CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            hash BLOB NOT NULL,
            time INTEGER NOT NULL,
            sapling_tree BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    wdb.conn.execute(
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
    wdb.conn.execute(
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
    wdb.conn.execute(
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
    wdb.conn.execute(
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
    wdb.conn.execute(
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
        )",
        NO_PARAMS,
    )?;
    Ok(())
}

/// Initialises the data database with the given [`ExtendedFullViewingKey`]s.
///
/// The [`ExtendedFullViewingKey`]s are stored internally and used by other APIs such as
/// [`get_address`], [`scan_cached_blocks`], and [`create_spend_to_address`]. `extfvks` **MUST**
/// be arranged in account-order; that is, the [`ExtendedFullViewingKey`] for ZIP 32
/// account `i` **MUST** be at `extfvks[i]`.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
///
/// use zcash_primitives::{
///     consensus::{Network, Parameters},
///     zip32::{ExtendedFullViewingKey, ExtendedSpendingKey}
/// };
///
/// use zcash_client_backend::{
///     keys::{spending_key, derive_transparent_address_from_secret_key, derive_secret_key_from_seed},
///     wallet::AccountId,
/// };
///
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::init::{init_accounts_table, init_wallet_db}
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
/// init_wallet_db(&db_data).unwrap();
///
/// let seed = [0u8; 32];
/// let account = AccountId(0);
/// let extsk = spending_key(&seed, Network::TestNetwork.coin_type(), account);
/// let tsk = derive_secret_key_from_seed(&Network::TestNetwork, &seed, account, 0).unwrap();
/// let extfvk = ExtendedFullViewingKey::from(&extsk);
/// let taddr = derive_transparent_address_from_secret_key(&tsk);
/// init_accounts_table(&db_data, &[extfvk], &[taddr]).unwrap();
/// ```
///
/// [`get_address`]: crate::wallet::get_address
/// [`scan_cached_blocks`]: zcash_client_backend::data_api::chain::scan_cached_blocks
/// [`create_spend_to_address`]: zcash_client_backend::data_api::wallet::create_spend_to_address
pub fn init_accounts_table<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    extfvks: &[ExtendedFullViewingKey],
    taddrs: &[TransparentAddress],
) -> Result<(), SqliteClientError> {
    //TODO: make this a proper error?
    assert!(extfvks.len() == taddrs.len());

    let mut empty_check = wdb.conn.prepare("SELECT * FROM accounts LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(SqliteClientError::TableNotEmpty);
    }

    // Insert accounts atomically
    wdb.conn.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
    for (account, (extfvk, taddr)) in extfvks.iter().zip(taddrs.iter()).enumerate() {
        let extfvk_str = encode_extended_full_viewing_key(
            wdb.params.hrp_sapling_extended_full_viewing_key(),
            extfvk,
        );

        let address_str = address_from_extfvk(&wdb.params, extfvk);
        let taddress_str: String = taddr.encode(&wdb.params);

        wdb.conn.execute(
            "INSERT INTO accounts (account, extfvk, address, transparent_address)
            VALUES (?, ?, ?, ?)",
            &[
                (account as u32).to_sql()?,
                extfvk_str.to_sql()?,
                address_str.to_sql()?,
                taddress_str.to_sql()?,
            ],
        )?;
    }
    wdb.conn.execute("COMMIT", NO_PARAMS)?;

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
mod tests {
    use tempfile::NamedTempFile;

    use zcash_client_backend::keys::derive_transparent_address_from_secret_key;

    use zcash_primitives::{
        block::BlockHash, consensus::BlockHeight, zip32::ExtendedFullViewingKey,
    };

    use crate::{tests, wallet::get_address, AccountId, WalletDb};

    use super::{init_accounts_table, init_blocks_table, init_wallet_db};

    #[test]
    fn init_accounts_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // We can call the function as many times as we want with no data
        init_accounts_table(&db_data, &[], &[]).unwrap();
        init_accounts_table(&db_data, &[], &[]).unwrap();

        // First call with data should initialise the accounts table
        let (extsk, tsk) = tests::derive_test_keys_from_seed(&[0u8; 32], AccountId(0));
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let taddr = derive_transparent_address_from_secret_key(&tsk);
        init_accounts_table(&db_data, &[extfvk.clone()], &[taddr.clone()]).unwrap();

        // Subsequent calls should return an error
        init_accounts_table(&db_data, &[], &[]).unwrap_err();
        init_accounts_table(&db_data, &[extfvk], &[taddr]).unwrap_err();
    }

    #[test]
    fn init_blocks_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

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
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add an account to the wallet
        let (extsk, tsk) = tests::derive_test_keys_from_seed(&[0u8; 32], AccountId(0));
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let taddr = derive_transparent_address_from_secret_key(&tsk);
        init_accounts_table(&db_data, &[extfvk], &[taddr]).unwrap();

        // The account's address should be in the data DB
        let pa = get_address(&db_data, AccountId(0)).unwrap();
        assert_eq!(pa.unwrap(), extsk.default_address().unwrap().1);
    }
}
