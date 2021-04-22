//! Functions for querying information in the wdb database.
//!
//! These functions should generally not be used directly; instead,
//! their functionality is available via the [`WalletRead`] and
//! [`WalletWrite`] traits.
//!
//! [`WalletRead`]: zcash_client_backend::data_api::WalletRead
//! [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite

use ff::PrimeField;
use rusqlite::{params, OptionalExtension, ToSql, NO_PARAMS};
use std::collections::HashMap;
use std::convert::TryFrom;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::{Memo, MemoBytes},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::{Node, Note, Nullifier, PaymentAddress},
    transaction::{
        components::{Amount, OutPoint},
        Transaction, TxId,
    },
    zip32::ExtendedFullViewingKey,
};

use zcash_client_backend::{
    data_api::error::Error,
    encoding::{
        decode_extended_full_viewing_key, decode_payment_address, encode_extended_full_viewing_key,
        encode_payment_address_p, encode_transparent_address_p,
    },
    wallet::{AccountId, WalletShieldedOutput, WalletTx},
    DecryptedOutput,
};

use crate::{error::SqliteClientError, DataConnStmtCache, NoteId, WalletDb, PRUNING_HEIGHT};

use {
    crate::UtxoId,
    zcash_client_backend::{encoding::AddressCodec, wallet::WalletTransparentOutput},
    zcash_primitives::legacy::TransparentAddress,
};

pub mod init;
pub mod transact;

/// This trait provides a generalization over shielded output representations.
pub trait ShieldedOutput {
    fn index(&self) -> usize;
    fn account(&self) -> AccountId;
    fn to(&self) -> &PaymentAddress;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> Option<bool>;
    fn nullifier(&self) -> Option<Nullifier>;
}

impl ShieldedOutput for WalletShieldedOutput<Nullifier> {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        self.account
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> Option<bool> {
        Some(self.is_change)
    }

    fn nullifier(&self) -> Option<Nullifier> {
        Some(self.nf)
    }
}

impl ShieldedOutput for DecryptedOutput {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        self.account
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(&self.memo)
    }
    fn is_change(&self) -> Option<bool> {
        None
    }
    fn nullifier(&self) -> Option<Nullifier> {
        None
    }
}

/// Returns the address for the account.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     consensus::{self, Network},
/// };
/// use zcash_client_backend::wallet::AccountId;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_address,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let addr = get_address(&db, AccountId(0));
/// ```
pub fn get_address<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    account: AccountId,
) -> Result<Option<PaymentAddress>, SqliteClientError> {
    let addr: String = wdb.conn.query_row(
        "SELECT address FROM accounts
        WHERE account = ?",
        &[account.0],
        |row| row.get(0),
    )?;

    decode_payment_address(wdb.params.hrp_sapling_payment_address(), &addr)
        .map_err(SqliteClientError::Bech32)
}

/// Returns the [`ExtendedFullViewingKey`]s for the wallet.
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
pub fn get_extended_full_viewing_keys<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
) -> Result<HashMap<AccountId, ExtendedFullViewingKey>, SqliteClientError> {
    // Fetch the ExtendedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts = wdb
        .conn
        .prepare("SELECT account, extfvk FROM accounts ORDER BY account ASC")?;

    let rows = stmt_fetch_accounts
        .query_map(NO_PARAMS, |row| {
            let acct = row.get(0).map(AccountId)?;
            let extfvk = row.get(1).map(|extfvk: String| {
                decode_extended_full_viewing_key(
                    wdb.params.hrp_sapling_extended_full_viewing_key(),
                    &extfvk,
                )
                .map_err(SqliteClientError::Bech32)
                .and_then(|k| k.ok_or(SqliteClientError::IncorrectHrpExtFvk))
            })?;

            Ok((acct, extfvk))
        })
        .map_err(SqliteClientError::from)?;

    let mut res: HashMap<AccountId, ExtendedFullViewingKey> = HashMap::new();
    for row in rows {
        let (account_id, efvkr) = row?;
        res.insert(account_id, efvkr?);
    }

    Ok(res)
}

/// Checks whether the specified [`ExtendedFullViewingKey`] is valid and corresponds to the
/// specified account.
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
pub fn is_valid_account_extfvk<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    account: AccountId,
    extfvk: &ExtendedFullViewingKey,
) -> Result<bool, SqliteClientError> {
    wdb.conn
        .prepare("SELECT * FROM accounts WHERE account = ? AND extfvk = ?")?
        .exists(&[
            account.0.to_sql()?,
            encode_extended_full_viewing_key(
                wdb.params.hrp_sapling_extended_full_viewing_key(),
                extfvk,
            )
            .to_sql()?,
        ])
        .map_err(SqliteClientError::from)
}

/// Returns the balance for the account, including all mined unspent notes that we know
/// about.
///
/// WARNING: This balance is potentially unreliable, as mined notes may become unmined due
/// to chain reorgs. You should generally not show this balance to users without some
/// caveat. Use [`get_balance_at`] where you need a more reliable indication of the
/// wallet balance.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_backend::wallet::AccountId;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_balance,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let addr = get_balance(&db, AccountId(0));
/// ```
pub fn get_balance<P>(wdb: &WalletDb<P>, account: AccountId) -> Result<Amount, SqliteClientError> {
    let balance = wdb.conn.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block IS NOT NULL",
        &[account.0],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError::CorruptedData(
            "Sum of values in received_notes is out of range".to_string(),
        )),
    }
}

/// Returns the verified balance for the account at the specified height,
/// This may be used to obtain a balance that ignores notes that have been
/// received so recently that they are not yet deemed spendable.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{BlockHeight, Network};
/// use zcash_client_backend::wallet::AccountId;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_balance_at,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let addr = get_balance_at(&db, AccountId(0), BlockHeight::from_u32(0));
/// ```
pub fn get_balance_at<P>(
    wdb: &WalletDb<P>,
    account: AccountId,
    anchor_height: BlockHeight,
) -> Result<Amount, SqliteClientError> {
    let balance = wdb.conn.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block <= ?",
        &[account.0, u32::from(anchor_height)],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError::CorruptedData(
            "Sum of values in received_notes is out of range".to_string(),
        )),
    }
}

/// Returns the memo for a received note.
///
/// The note is identified by its row index in the `received_notes` table within the wdb
/// database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     NoteId,
///     WalletDb,
///     wallet::get_received_memo,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let memo = get_received_memo(&db, 27);
/// ```
pub fn get_received_memo<P>(wdb: &WalletDb<P>, id_note: i64) -> Result<Memo, SqliteClientError> {
    let memo_bytes: Vec<_> = wdb.conn.query_row(
        "SELECT memo FROM received_notes
        WHERE id_note = ?",
        &[id_note],
        |row| row.get(0),
    )?;

    MemoBytes::from_bytes(&memo_bytes)
        .and_then(Memo::try_from)
        .map_err(SqliteClientError::from)
}

pub fn get_transaction<P>(wdb: &WalletDb<P>, id_tx: i64) -> Result<Transaction, SqliteClientError> {
    let tx_bytes: Vec<_> = wdb.conn.query_row(
        "SELECT raw FROM transactions
        WHERE id_tx = ?",
        &[id_tx],
        |row| row.get(0),
    )?;

    Transaction::read(&tx_bytes[..]).map_err(SqliteClientError::from)
}

/// Returns the memo for a sent note.
///
/// The note is identified by its row index in the `sent_notes` table within the wdb
/// database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     NoteId,
///     WalletDb,
///     wallet::get_sent_memo,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let memo = get_sent_memo(&db, 12);
/// ```
pub fn get_sent_memo<P>(wdb: &WalletDb<P>, id_note: i64) -> Result<Memo, SqliteClientError> {
    let memo_bytes: Vec<_> = wdb.conn.query_row(
        "SELECT memo FROM sent_notes
        WHERE id_note = ?",
        &[id_note],
        |row| row.get(0),
    )?;

    MemoBytes::from_bytes(&memo_bytes)
        .and_then(Memo::try_from)
        .map_err(SqliteClientError::from)
}

/// Returns the minimum and maximum heights for blocks stored in the wallet database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::block_height_extrema,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let bounds = block_height_extrema(&db);
/// ```
pub fn block_height_extrema<P>(
    wdb: &WalletDb<P>,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    wdb.conn
        .query_row(
            "SELECT MIN(height), MAX(height) FROM blocks",
            NO_PARAMS,
            |row| {
                let min_height: u32 = row.get(0)?;
                let max_height: u32 = row.get(1)?;
                Ok(Some((
                    BlockHeight::from(min_height),
                    BlockHeight::from(max_height),
                )))
            },
        )
        //.optional() doesn't work here because a failed aggregate function
        //produces a runtime error, not an empty set of rows.
        .or(Ok(None))
}

/// Returns the block height at which the specified transaction was mined,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_primitives::transaction::TxId;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_tx_height,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let height = get_tx_height(&db, TxId([0u8; 32]));
/// ```
pub fn get_tx_height<P>(
    wdb: &WalletDb<P>,
    txid: TxId,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    wdb.conn
        .query_row(
            "SELECT block FROM transactions WHERE txid = ?",
            &[txid.0.to_vec()],
            |row| row.get(0).map(u32::into),
        )
        .optional()
}

/// Returns the block hash for the block at the specified height,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{H0, Network};
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_block_hash,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let hash = get_block_hash(&db, H0);
/// ```
pub fn get_block_hash<P>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<Option<BlockHash>, rusqlite::Error> {
    wdb.conn
        .query_row(
            "SELECT hash FROM blocks WHERE height = ?",
            &[u32::from(block_height)],
            |row| {
                let row_data = row.get::<_, Vec<_>>(0)?;
                Ok(BlockHash::from_slice(&row_data))
            },
        )
        .optional()
}

/// Gets the height to which the database must be rewound if any rewind greater than the pruning
/// height is attempted.
pub fn get_rewind_height<P>(wdb: &WalletDb<P>) -> Result<Option<BlockHeight>, SqliteClientError> {
    wdb.conn
        .query_row(
            "SELECT MIN(tx.block) 
             FROM received_notes n
             JOIN transactions tx ON tx.id_tx = n.tx
             WHERE n.spent IS NULL",
            NO_PARAMS,
            |row| {
                row.get(0)
                    .map(|maybe_height: Option<u32>| maybe_height.map(|height| height.into()))
            },
        )
        .map_err(SqliteClientError::from)
}

/// Rewinds the database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
///
/// This should only be executed inside a transactional context.
pub fn rewind_to_height<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let sapling_activation_height = wdb
        .params
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(SqliteClientError::BackendError(Error::SaplingNotActive))?;

    // Recall where we synced up to previously.
    let last_scanned_height =
        wdb.conn
            .query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
                row.get(0)
                    .map(|h: u32| h.into())
                    .or(Ok(sapling_activation_height - 1))
            })?;

    let rewind_height = if block_height >= (last_scanned_height - PRUNING_HEIGHT) {
        Some(block_height)
    } else {
        match get_rewind_height(&wdb)? {
            Some(h) => {
                if block_height > h {
                    return Err(SqliteClientError::RequestedRewindInvalid(h));
                } else {
                    Some(block_height)
                }
            }
            None => Some(block_height),
        }
    };

    // nothing to do if we're deleting back down to the max height

    if let Some(block_height) = rewind_height {
        if block_height < last_scanned_height {
            // Decrement witnesses.
            wdb.conn.execute(
                "DELETE FROM sapling_witnesses WHERE block > ?",
                &[u32::from(block_height)],
            )?;

            // Un-mine transactions.
            wdb.conn.execute(
                "UPDATE transactions SET block = NULL, tx_index = NULL WHERE block > ?",
                &[u32::from(block_height)],
            )?;

            // Now that they aren't depended on, delete scanned blocks.
            wdb.conn.execute(
                "DELETE FROM blocks WHERE height > ?",
                &[u32::from(block_height)],
            )?;

            // Rewind received notes
            wdb.conn.execute(
                "DELETE FROM received_notes
                    WHERE id_note IN (
                        SELECT rn.id_note
                        FROM received_notes rn
                        LEFT OUTER JOIN transactions tx
                        ON tx.id_tx = rn.tx
                        WHERE tx.block > ?
                    );",
                &[u32::from(block_height)],
            )?;

            // Rewind sent notes
            wdb.conn.execute(
                "DELETE FROM sent_notes
                    WHERE id_note IN (
                        SELECT sn.id_note
                        FROM sent_notes sn
                        LEFT OUTER JOIN transactions tx
                        ON tx.id_tx = sn.tx
                        WHERE tx.block > ?
                    );",
                &[u32::from(block_height)],
            )?;

            // Rewind utxos
            wdb.conn.execute(
                "DELETE FROM utxos WHERE height > ?",
                &[u32::from(block_height)],
            )?;
        }
    }

    Ok(())
}

/// Returns the commitment tree for the block at the specified height,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{Network, H0};
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_commitment_tree,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let tree = get_commitment_tree(&db, H0);
/// ```
pub fn get_commitment_tree<P>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<Option<CommitmentTree<Node>>, SqliteClientError> {
    wdb.conn
        .query_row_and_then(
            "SELECT sapling_tree FROM blocks WHERE height = ?",
            &[u32::from(block_height)],
            |row| {
                let row_data: Vec<u8> = row.get(0)?;
                CommitmentTree::read(&row_data[..]).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        row_data.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })
            },
        )
        .optional()
        .map_err(SqliteClientError::from)
}

/// Returns the incremental witnesses for the block at the specified height,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{Network, H0};
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_witnesses,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let witnesses = get_witnesses(&db, H0);
/// ```
pub fn get_witnesses<P>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<Vec<(NoteId, IncrementalWitness<Node>)>, SqliteClientError> {
    let mut stmt_fetch_witnesses = wdb
        .conn
        .prepare("SELECT note, witness FROM sapling_witnesses WHERE block = ?")?;
    let witnesses = stmt_fetch_witnesses
        .query_map(&[u32::from(block_height)], |row| {
            let id_note = NoteId::ReceivedNoteId(row.get(0)?);
            let wdb: Vec<u8> = row.get(1)?;
            Ok(IncrementalWitness::read(&wdb[..]).map(|witness| (id_note, witness)))
        })
        .map_err(SqliteClientError::from)?;

    // unwrap database error & IO error from IncrementalWitness::read
    let res: Vec<_> = witnesses.collect::<Result<Result<_, _>, _>>()??;
    Ok(res)
}

/// Retrieve the nullifiers for notes that the wallet is tracking
/// that have not yet been confirmed as a consequence of the spending
/// transaction being included in a block.
pub fn get_nullifiers<P>(
    wdb: &WalletDb<P>,
) -> Result<Vec<(AccountId, Nullifier)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = wdb.conn.prepare(
        "SELECT rn.id_note, rn.account, rn.nf, tx.block as block
            FROM received_notes rn
            LEFT OUTER JOIN transactions tx
            ON tx.id_tx = rn.spent
            WHERE block IS NULL",
    )?;
    let nullifiers = stmt_fetch_nullifiers.query_map(NO_PARAMS, |row| {
        let account = AccountId(row.get(1)?);
        let nf_bytes: Vec<u8> = row.get(2)?;
        Ok((account, Nullifier::from_slice(&nf_bytes).unwrap()))
    })?;

    let res: Vec<_> = nullifiers.collect::<Result<_, _>>()?;
    Ok(res)
}

pub fn get_all_nullifiers<P>(
    wdb: &WalletDb<P>,
) -> Result<Vec<(AccountId, Nullifier)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = wdb.conn.prepare(
        "SELECT rn.id_note, rn.account, rn.nf
            FROM received_notes rn",
    )?;
    let nullifiers = stmt_fetch_nullifiers.query_map(NO_PARAMS, |row| {
        let account = AccountId(row.get(1)?);
        let nf_bytes: Vec<u8> = row.get(2)?;
        Ok((account, Nullifier::from_slice(&nf_bytes).unwrap()))
    })?;

    let res: Vec<_> = nullifiers.collect::<Result<_, _>>()?;
    Ok(res)
}

pub fn get_unspent_transparent_utxos<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    address: &TransparentAddress,
    anchor_height: BlockHeight,
) -> Result<Vec<WalletTransparentOutput>, SqliteClientError> {
    let mut stmt_blocks = wdb.conn.prepare(
        "SELECT u.address, u.prevout_txid, u.prevout_idx, u.script, u.value_zat, u.height, tx.block as block
         FROM utxos u
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = u.spent_in_tx
         WHERE u.address = ?
         AND u.height <= ?
         AND block IS NULL",
    )?;

    let addr_str = address.encode(&wdb.params);

    let rows = stmt_blocks.query_map(params![addr_str, u32::from(anchor_height)], |row| {
        let addr: String = row.get(0)?;
        let address = TransparentAddress::decode(&wdb.params, &addr).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                addr.len(),
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })?;

        let id: Vec<u8> = row.get(1)?;

        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&id);
        let index: i32 = row.get(2)?;
        let script: Vec<u8> = row.get(3)?;
        let value: i64 = row.get(4)?;
        let height: u32 = row.get(5)?;

        Ok(WalletTransparentOutput {
            address,
            outpoint: OutPoint::new(txid_bytes, index as u32),
            script,
            value: Amount::from_i64(value).unwrap(),
            height: BlockHeight::from(height),
        })
    })?;

    let mut utxos = Vec::<WalletTransparentOutput>::new();

    for utxo in rows {
        utxos.push(utxo.unwrap())
    }
    Ok(utxos)
}

/// Inserts information about a scanned block into the database.
pub fn insert_block<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    block_height: BlockHeight,
    block_hash: BlockHash,
    block_time: u32,
    commitment_tree: &CommitmentTree<Node>,
) -> Result<(), SqliteClientError> {
    let mut encoded_tree = Vec::new();
    commitment_tree.write(&mut encoded_tree).unwrap();

    stmts.stmt_insert_block.execute(params![
        u32::from(block_height),
        &block_hash.0[..],
        block_time,
        encoded_tree
    ])?;

    Ok(())
}

/// Inserts information about a mined transaction that was observed to
/// contain a note related to this wallet into the database.
pub fn put_tx_meta<'a, P, N>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx: &WalletTx<N>,
    height: BlockHeight,
) -> Result<i64, SqliteClientError> {
    let txid = tx.txid.0.to_vec();
    if stmts
        .stmt_update_tx_meta
        .execute(params![u32::from(height), (tx.index as i64), txid])?
        == 0
    {
        // It isn't there, so insert our transaction into the database.
        stmts
            .stmt_insert_tx_meta
            .execute(params![txid, u32::from(height), (tx.index as i64),])?;

        Ok(stmts.wallet_db.conn.last_insert_rowid())
    } else {
        // It was there, so grab its row number.
        stmts
            .stmt_select_tx_ref
            .query_row(&[txid], |row| row.get(0))
            .map_err(SqliteClientError::from)
    }
}

/// Inserts full transaction data into the database.
pub fn put_tx_data<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx: &Transaction,
    created_at: Option<time::OffsetDateTime>,
) -> Result<i64, SqliteClientError> {
    let txid = tx.txid().0.to_vec();

    let mut raw_tx = vec![];
    tx.write(&mut raw_tx)?;

    if stmts
        .stmt_update_tx_data
        .execute(params![u32::from(tx.expiry_height), raw_tx, txid,])?
        == 0
    {
        // It isn't there, so insert our transaction into the database.
        stmts.stmt_insert_tx_data.execute(params![
            txid,
            created_at,
            u32::from(tx.expiry_height),
            raw_tx
        ])?;

        Ok(stmts.wallet_db.conn.last_insert_rowid())
    } else {
        // It was there, so grab its row number.
        stmts
            .stmt_select_tx_ref
            .query_row(&[txid], |row| row.get(0))
            .map_err(SqliteClientError::from)
    }
}

/// Marks a given nullifier as having been revealed in the construction
/// of the specified transaction.
///
/// Marking a note spent in this fashion does NOT imply that the
/// spending transaction has been mined.
pub fn mark_sapling_note_spent<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    nf: &Nullifier,
) -> Result<(), SqliteClientError> {
    stmts
        .stmt_mark_sapling_note_spent
        .execute(&[tx_ref.to_sql()?, nf.0.to_sql()?])?;
    Ok(())
}

/// Records the specified shielded output as having been received.
pub fn mark_transparent_utxo_spent<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    outpoint: &OutPoint,
) -> Result<(), SqliteClientError> {
    let sql_args: &[(&str, &dyn ToSql)] = &[
        (&":spent_in_tx", &tx_ref),
        (&":prevout_txid", &outpoint.hash().to_vec()),
        (&":prevout_idx", &outpoint.n()),
    ];

    stmts
        .stmt_mark_transparent_utxo_spent
        .execute_named(&sql_args)?;

    Ok(())
}

pub fn put_received_transparent_utxo<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    output: &WalletTransparentOutput,
) -> Result<UtxoId, SqliteClientError> {
    let sql_args: &[(&str, &dyn ToSql)] = &[
        (&":address", &output.address.encode(&stmts.wallet_db.params)),
        (&":prevout_txid", &output.outpoint.hash().to_vec()),
        (&":prevout_idx", &output.outpoint.n()),
        (&":script", &output.script),
        (&":value_zat", &i64::from(output.value)),
        (&":height", &u32::from(output.height)),
    ];

    stmts
        .stmt_insert_received_transparent_utxo
        .execute_named(&sql_args)?;

    Ok(UtxoId(stmts.wallet_db.conn.last_insert_rowid()))
}

pub fn delete_utxos_above<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    taddr: &TransparentAddress,
    height: BlockHeight,
) -> Result<usize, SqliteClientError> {
    let sql_args: &[(&str, &dyn ToSql)] = &[
        (&":address", &taddr.encode(&stmts.wallet_db.params)),
        (&":above_height", &u32::from(height)),
    ];

    let rows = stmts.stmt_delete_utxos.execute_named(&sql_args)?;

    Ok(rows)
}

// Assumptions:
// - A transaction will not contain more than 2^63 shielded outputs.
// - A note value will never exceed 2^63 zatoshis.
pub fn put_received_note<'a, P, T: ShieldedOutput>(
    stmts: &mut DataConnStmtCache<'a, P>,
    output: &T,
    tx_ref: i64,
) -> Result<NoteId, SqliteClientError> {
    let rcm = output.note().rcm().to_repr();
    let account = output.account().0 as i64;
    let diversifier = output.to().diversifier().0.to_vec();
    let value = output.note().value as i64;
    let rcm = rcm.as_ref();
    let memo = output.memo().map(|m| m.as_slice());
    let is_change = output.is_change();
    let tx = tx_ref;
    let output_index = output.index() as i64;
    let nf_bytes = output.nullifier().map(|nf| nf.0.to_vec());

    let sql_args: &[(&str, &dyn ToSql)] = &[
        (&":account", &account),
        (&":diversifier", &diversifier),
        (&":value", &value),
        (&":rcm", &rcm),
        (&":nf", &nf_bytes),
        (&":memo", &memo),
        (&":is_change", &is_change),
        (&":tx", &tx),
        (&":output_index", &output_index),
    ];

    // First try updating an existing received note into the database.
    if stmts.stmt_update_received_note.execute_named(&sql_args)? == 0 {
        // It isn't there, so insert our note into the database.
        stmts.stmt_insert_received_note.execute_named(&sql_args)?;

        Ok(NoteId::ReceivedNoteId(
            stmts.wallet_db.conn.last_insert_rowid(),
        ))
    } else {
        // It was there, so grab its row number.
        stmts
            .stmt_select_received_note
            .query_row(params![tx_ref, (output.index() as i64)], |row| {
                row.get(0).map(NoteId::ReceivedNoteId)
            })
            .map_err(SqliteClientError::from)
    }
}

/// Records the incremental witness for the specified note,
/// as of the given block height.
pub fn insert_witness<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    note_id: i64,
    witness: &IncrementalWitness<Node>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let mut encoded = Vec::new();
    witness.write(&mut encoded).unwrap();

    stmts
        .stmt_insert_witness
        .execute(params![note_id, u32::from(height), encoded])?;

    Ok(())
}

/// Removes old incremental witnesses up to the given block height.
pub fn prune_witnesses<P>(
    stmts: &mut DataConnStmtCache<'_, P>,
    below_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    stmts
        .stmt_prune_witnesses
        .execute(&[u32::from(below_height)])?;
    Ok(())
}

/// Marks notes that have not been mined in transactions
/// as expired, up to the given block height.
pub fn update_expired_notes<P>(
    stmts: &mut DataConnStmtCache<'_, P>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    stmts.stmt_update_expired.execute(&[u32::from(height)])?;
    Ok(())
}

/// Records information about a note that your wallet created.
pub fn put_sent_note<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &PaymentAddress,
    value: Amount,
    memo: Option<&MemoBytes>,
) -> Result<(), SqliteClientError> {
    let ivalue: i64 = value.into();
    // Try updating an existing sent note.
    if stmts.stmt_update_sent_note.execute(params![
        account.0 as i64,
        encode_payment_address_p(&stmts.wallet_db.params, &to),
        ivalue,
        &memo.map(|m| m.as_slice()),
        tx_ref,
        output_index as i64
    ])? == 0
    {
        // It isn't there, so insert.
        insert_sent_note(stmts, tx_ref, output_index, account, &to, value, memo)?
    }

    Ok(())
}

pub fn put_sent_utxo<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &TransparentAddress,
    value: Amount,
) -> Result<(), SqliteClientError> {
    let ivalue: i64 = value.into();
    // Try updating an existing sent note.
    if stmts.stmt_update_sent_note.execute(params![
        account.0 as i64,
        encode_transparent_address_p(&stmts.wallet_db.params, &to),
        ivalue,
        (None::<&[u8]>),
        tx_ref,
        output_index as i64
    ])? == 0
    {
        // It isn't there, so insert.
        insert_sent_utxo(stmts, tx_ref, output_index, account, &to, value)?
    }

    Ok(())
}

/// Inserts a sent note into the wallet database.
///
/// `output_index` is the index within the transaction that contains the recipient output:
///
/// - If `to` is a Sapling address, this is an index into the Sapling outputs of the
///   transaction.
/// - If `to` is a transparent address, this is an index into the transparent outputs of
///   the transaction.
pub fn insert_sent_note<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &PaymentAddress,
    value: Amount,
    memo: Option<&MemoBytes>,
) -> Result<(), SqliteClientError> {
    let to_str = encode_payment_address_p(&stmts.wallet_db.params, to);
    let ivalue: i64 = value.into();
    stmts.stmt_insert_sent_note.execute(params![
        tx_ref,
        (output_index as i64),
        account.0,
        to_str,
        ivalue,
        memo.map(|m| m.as_slice().to_vec()),
    ])?;

    Ok(())
}

pub fn insert_sent_utxo<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &TransparentAddress,
    value: Amount,
) -> Result<(), SqliteClientError> {
    let to_str = encode_transparent_address_p(&stmts.wallet_db.params, to);
    let ivalue: i64 = value.into();
    stmts.stmt_insert_sent_note.execute(params![
        tx_ref,
        (output_index as i64),
        account.0,
        to_str,
        ivalue,
        (None::<&[u8]>)
    ])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use zcash_primitives::transaction::components::Amount;

    use zcash_client_backend::data_api::WalletRead;

    use crate::{tests, wallet::init::init_wallet_db, AccountId, WalletDb};

    use super::{get_address, get_balance};

    #[test]
    fn empty_database_has_no_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add an account to the wallet
        tests::init_test_accounts_table(&db_data);

        // The account should be empty
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // We can't get an anchor height, as we have not scanned any blocks.
        assert_eq!((&db_data).get_target_and_anchor_heights().unwrap(), None);

        // An invalid account has zero balance
        assert!(get_address(&db_data, AccountId(1)).is_err());
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());
    }
}
