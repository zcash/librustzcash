//! Functions for initializing the various databases.

use rusqlite::{params, types::ToSql, NO_PARAMS};

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
};

use zcash_client_backend::{
    encoding::encode_extended_full_viewing_key, keys::UnifiedFullViewingKey,
};

use crate::{address_from_extfvk, error::SqliteClientError, WalletDb};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::encoding::AddressCodec,
    zcash_primitives::legacy::keys::IncomingViewingKey,
};

/// Sets up the internal structure of the data database.
///
/// The database structure is the same irrespective of whether or
/// not transparent spends are enabled, and it is safe to use a
/// wallet database created without the ability to create transparent
/// spends with a build that enables transparent spends (though not
/// the reverse, as wallet balance calculations would ignore the
/// prior transparent inputs controlled by the wallet).
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
            extfvk TEXT,
            address TEXT,
            transparent_address TEXT
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
/// let db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
/// init_wallet_db(&db_data).unwrap();
///
/// let seed = [0u8; 32]; // insecure; replace with a strong random seed
/// let account = AccountId(0);
/// let extsk = sapling::spending_key(&seed, Network::TestNetwork.coin_type(), account);
/// let extfvk = ExtendedFullViewingKey::from(&extsk);
/// let ufvk = UnifiedFullViewingKey::new(account, None, Some(extfvk)).unwrap();
/// init_accounts_table(&db_data, &[ufvk]).unwrap();
/// # }
/// ```
///
/// [`get_address`]: crate::wallet::get_address
/// [`scan_cached_blocks`]: zcash_client_backend::data_api::chain::scan_cached_blocks
/// [`create_spend_to_address`]: zcash_client_backend::data_api::wallet::create_spend_to_address
pub fn init_accounts_table<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    keys: &[UnifiedFullViewingKey],
) -> Result<(), SqliteClientError> {
    let mut empty_check = wdb.conn.prepare("SELECT * FROM accounts LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(SqliteClientError::TableNotEmpty);
    }

    // Insert accounts atomically
    wdb.conn.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
    for key in keys.iter() {
        let extfvk_str: Option<String> = key.sapling().map(|extfvk| {
            encode_extended_full_viewing_key(
                wdb.params.hrp_sapling_extended_full_viewing_key(),
                extfvk,
            )
        });

        let address_str: Option<String> = key
            .sapling()
            .map(|extfvk| address_from_extfvk(&wdb.params, extfvk));
        #[cfg(feature = "transparent-inputs")]
        let taddress_str: Option<String> = key.transparent().and_then(|k| {
            k.derive_external_ivk()
                .ok()
                .map(|k| k.default_address().0.encode(&wdb.params))
        });
        #[cfg(not(feature = "transparent-inputs"))]
        let taddress_str: Option<String> = None;

        wdb.conn.execute(
            "INSERT INTO accounts (account, extfvk, address, transparent_address)
            VALUES (?, ?, ?, ?)",
            params![key.account().0, extfvk_str, address_str, taddress_str,],
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
#[allow(deprecated)]
mod tests {
    use tempfile::NamedTempFile;

    use zcash_client_backend::keys::{sapling, UnifiedFullViewingKey, UnifiedSpendingKey};

    #[cfg(feature = "transparent-inputs")]
    use zcash_primitives::legacy::keys as transparent;

    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, Parameters},
        zip32::ExtendedFullViewingKey,
    };

    use crate::{
        tests::{self, network},
        wallet::get_address,
        AccountId, WalletDb,
    };

    use super::{init_accounts_table, init_blocks_table, init_wallet_db};

    #[test]
    fn init_accounts_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // We can call the function as many times as we want with no data
        init_accounts_table(&db_data, &[]).unwrap();
        init_accounts_table(&db_data, &[]).unwrap();

        let seed = [0u8; 32];
        let account = AccountId(0);

        // First call with data should initialise the accounts table
        let extsk = sapling::spending_key(&seed, network().coin_type(), account);
        let extfvk = ExtendedFullViewingKey::from(&extsk);

        #[cfg(feature = "transparent-inputs")]
        let ufvk = UnifiedFullViewingKey::new(
            account,
            Some(
                transparent::AccountPrivKey::from_seed(&network(), &seed, account)
                    .unwrap()
                    .to_account_pubkey(),
            ),
            Some(extfvk),
        )
        .unwrap();

        #[cfg(not(feature = "transparent-inputs"))]
        let ufvk = UnifiedFullViewingKey::new(account, Some(extfvk)).unwrap();

        init_accounts_table(&db_data, &[ufvk.clone()]).unwrap();

        // Subsequent calls should return an error
        init_accounts_table(&db_data, &[]).unwrap_err();
        init_accounts_table(&db_data, &[ufvk]).unwrap_err();
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

        let seed = [0u8; 32];

        // Add an account to the wallet
        let account_id = AccountId(0);
        let usk = UnifiedSpendingKey::from_seed(&tests::network(), &seed, account_id).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let expected_address = ufvk.sapling().unwrap().default_address().1;
        init_accounts_table(&db_data, &[ufvk]).unwrap();

        // The account's address should be in the data DB
        let pa = get_address(&db_data, AccountId(0)).unwrap();
        assert_eq!(pa.unwrap(), expected_address);
    }
}
