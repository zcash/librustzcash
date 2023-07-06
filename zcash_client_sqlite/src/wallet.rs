//! Functions for querying information in the wallet database.
//!
//! These functions should generally not be used directly; instead,
//! their functionality is available via the [`WalletRead`] and
//! [`WalletWrite`] traits.
//!
//! [`WalletRead`]: zcash_client_backend::data_api::WalletRead
//! [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite
//!
//! # Views
//!
//! The wallet database exposes the following views as part of its public API:
//!
//! ## `v_transactions`
//!
//! This view exposes the history of transactions that affect the balance of each account in the
//! wallet. A transaction may be represented by multiple rows in this view, one for each account in
//! the wallet that contributes funds to or receives funds from the transaction in question. Each
//! row of the view contains:
//! - `account_balance_delta`: the net effect of the transaction on the associated account's
//!   balance. This value is positive when funds are received by the account, and negative when the
//!   balance of the account decreases due to a spend.
//! - `fee_paid`: the total fee paid to send the transaction, as a positive value. This fee is
//!   associated with the transaction (similar to e.g. `txid` or `mined_height`), and not with any
//!   specific account involved with that transaction. ` If multiple rows exist for a single
//!   transaction, this fee amount will be repeated for each such row. Therefore, if more than one
//!   of the wallet's accounts is involved with the transaction, this fee should be considered only
//!   once in determining the total value sent from the wallet as a whole.
//!
//! ### Seed Phrase with Single Account
//!
//! In the case that the seed phrase for in this wallet has only been used to create a single
//! account, this view will contain one row per transaction, in the case that
//! `account_balance_delta` is negative, it is usually safe to add `fee_paid` back to the
//! `account_balance_delta` value to determine the amount sent to addresses outside the wallet.
//!
//! ### Seed Phrase with Multiple Accounts
//!
//! In the case that the seed phrase for in this wallet has been used to create multiple accounts,
//! this view may contain multiple rows per transaction, one for each account involved. In this
//! case, the total amount sent to addresses outside the wallet can usually be calculated by
//! grouping rows by `id_tx` and then using `SUM(account_balance_delta) + MAX(fee_paid)`.
//!
//! ### Imported Seed Phrases
//!
//! If a seed phrase is imported, and not every account associated with it is loaded into the
//! wallet, this view may show partial information about some transactions. In particular, any
//! computation that involves both `account_balance_delta` and `fee_paid` is likely to be
//! inaccurate.
//!
//! ## `v_tx_outputs`
//!
//! This view exposes the history of transaction outputs received by and sent from the wallet,
//! keyed by transaction ID, pool type, and output index. The contents of this view are useful for
//! producing a detailed report of the effects of a transaction. Each row of this view contains:
//! - `from_account` for sent outputs, the account from which the value was sent.
//! - `to_account` in the case that the output was received by an account in the wallet, the
//!   identifier for the account receiving the funds.
//! - `to_address` the address to which an output was sent, or the address at which value was
//!   received in the case of received transparent funds.
//! - `value` the value of the output. This is always a positive number, for both sent and received
//!   outputs.
//! - `is_change` a boolean flag indicating whether this is a change output belonging to the
//!   wallet.
//! - `memo` the shielded memo associated with the output, if any.

use rusqlite::{self, named_params, OptionalExtension, ToSql};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{self, Cursor};
use zcash_client_backend::data_api::ShieldedProtocol;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, BranchId, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
    merkle_tree::read_commitment_tree,
    transaction::{components::Amount, Transaction, TxId},
    zip32::{
        sapling::{DiversifiableFullViewingKey, ExtendedFullViewingKey},
        AccountId, DiversifierIndex,
    },
};

use zcash_client_backend::{
    address::{RecipientAddress, UnifiedAddress},
    data_api::{BlockMetadata, PoolType, Recipient, SentTransactionOutput},
    encoding::AddressCodec,
    keys::UnifiedFullViewingKey,
    wallet::WalletTx,
};

use crate::{
    error::SqliteClientError, SqlTransaction, WalletCommitmentTrees, WalletDb, PRUNING_DEPTH,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::UtxoId,
    std::collections::BTreeSet,
    zcash_client_backend::{address::AddressMetadata, wallet::WalletTransparentOutput},
    zcash_primitives::{
        legacy::{keys::IncomingViewingKey, Script, TransparentAddress},
        transaction::components::{OutPoint, TxOut},
    },
};

pub(crate) mod commitment_tree;
pub mod init;
pub(crate) mod sapling;

pub(crate) const BLOCK_SAPLING_FRONTIER_ABSENT: &[u8] = &[0x0];

pub(crate) fn pool_code(pool_type: PoolType) -> i64 {
    // These constants are *incidentally* shared with the typecodes
    // for unified addresses, but this is exclusively an internal
    // implementation detail.
    match pool_type {
        PoolType::Transparent => 0i64,
        PoolType::Shielded(ShieldedProtocol::Sapling) => 2i64,
    }
}

pub(crate) fn memo_repr(memo: Option<&MemoBytes>) -> Option<&[u8]> {
    memo.filter(|m| *m != &MemoBytes::empty())
        .map(|m| m.as_slice())
}

pub(crate) fn get_max_account_id(
    conn: &rusqlite::Connection,
) -> Result<Option<AccountId>, SqliteClientError> {
    // This returns the most recently generated address.
    conn.query_row("SELECT MAX(account) FROM accounts", [], |row| {
        let account_id: Option<u32> = row.get(0)?;
        Ok(account_id.map(AccountId::from))
    })
    .map_err(SqliteClientError::from)
}

pub(crate) fn add_account<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account: AccountId,
    key: &UnifiedFullViewingKey,
) -> Result<(), SqliteClientError> {
    add_account_internal(conn, params, "accounts", account, key)
}

pub(crate) fn add_account_internal<P: consensus::Parameters, E: From<rusqlite::Error>>(
    conn: &rusqlite::Transaction,
    network: &P,
    accounts_table: &'static str,
    account: AccountId,
    key: &UnifiedFullViewingKey,
) -> Result<(), E> {
    let ufvk_str: String = key.encode(network);
    conn.execute(
        &format!(
            "INSERT INTO {} (account, ufvk) VALUES (:account, :ufvk)",
            accounts_table
        ),
        named_params![":account": &<u32>::from(account), ":ufvk": &ufvk_str],
    )?;

    // Always derive the default Unified Address for the account.
    let (address, d_idx) = key.default_address();
    insert_address(conn, network, account, d_idx, &address)?;

    Ok(())
}

pub(crate) fn get_current_address<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqliteClientError> {
    // This returns the most recently generated address.
    let addr: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT address, diversifier_index_be
            FROM addresses WHERE account = :account
            ORDER BY diversifier_index_be DESC
            LIMIT 1",
            named_params![":account": &u32::from(account)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    addr.map(|(addr_str, di_vec)| {
        let mut di_be: [u8; 11] = di_vec.try_into().map_err(|_| {
            SqliteClientError::CorruptedData("Diversifier index is not an 11-byte value".to_owned())
        })?;
        di_be.reverse();

        RecipientAddress::decode(params, &addr_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                RecipientAddress::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    addr_str,
                ))),
            })
            .map(|addr| (addr, DiversifierIndex(di_be)))
    })
    .transpose()
}

/// Adds the given address and diversifier index to the addresses table.
///
/// Returns the database row for the newly-inserted address.
pub(crate) fn insert_address<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
    mut diversifier_index: DiversifierIndex,
    address: &UnifiedAddress,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO addresses (
                    account,
                    diversifier_index_be,
                    address,
                    cached_transparent_receiver_address
                )
                VALUES (
                    :account,
                    :diversifier_index_be,
                    :address,
                    :cached_transparent_receiver_address
                )",
    )?;

    // the diversifier index is stored in big-endian order to allow sorting
    diversifier_index.0.reverse();
    stmt.execute(named_params![
        ":account": &u32::from(account),
        ":diversifier_index_be": &&diversifier_index.0[..],
        ":address": &address.encode(params),
        ":cached_transparent_receiver_address": &address.transparent().map(|r| r.encode(params)),
    ])?;

    Ok(())
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_transparent_receivers<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
) -> Result<HashMap<TransparentAddress, AddressMetadata>, SqliteClientError> {
    let mut ret = HashMap::new();

    // Get all UAs derived
    let mut ua_query = conn
        .prepare("SELECT address, diversifier_index_be FROM addresses WHERE account = :account")?;
    let mut rows = ua_query.query(named_params![":account": &u32::from(account)])?;

    while let Some(row) = rows.next()? {
        let ua_str: String = row.get(0)?;
        let di_vec: Vec<u8> = row.get(1)?;
        let mut di_be: [u8; 11] = di_vec.try_into().map_err(|_| {
            SqliteClientError::CorruptedData(
                "Diverisifier index is not an 11-byte value".to_owned(),
            )
        })?;
        di_be.reverse();

        let ua = RecipientAddress::decode(params, &ua_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                RecipientAddress::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    ua_str,
                ))),
            })?;

        if let Some(taddr) = ua.transparent() {
            ret.insert(
                *taddr,
                AddressMetadata::new(account, DiversifierIndex(di_be)),
            );
        }
    }

    if let Some((taddr, diversifier_index)) = get_legacy_transparent_address(params, conn, account)?
    {
        ret.insert(taddr, AddressMetadata::new(account, diversifier_index));
    }

    Ok(ret)
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    conn: &rusqlite::Connection,
    account: AccountId,
) -> Result<Option<(TransparentAddress, DiversifierIndex)>, SqliteClientError> {
    // Get the UFVK for the account.
    let ufvk_str: Option<String> = conn
        .query_row(
            "SELECT ufvk FROM accounts WHERE account = :account",
            [u32::from(account)],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(ufvk_str) = ufvk_str {
        let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
            .map_err(SqliteClientError::CorruptedData)?;

        // Derive the default transparent address (if it wasn't already part of a derived UA).
        ufvk.transparent()
            .map(|tfvk| {
                tfvk.derive_external_ivk()
                    .map(|tivk| {
                        let (taddr, child_index) = tivk.default_address();
                        (taddr, DiversifierIndex::from(child_index))
                    })
                    .map_err(SqliteClientError::HdwalletError)
            })
            .transpose()
    } else {
        Ok(None)
    }
}

/// Returns the [`UnifiedFullViewingKey`]s for the wallet.
pub(crate) fn get_unified_full_viewing_keys<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, SqliteClientError> {
    // Fetch the UnifiedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts =
        conn.prepare("SELECT account, ufvk FROM accounts ORDER BY account ASC")?;

    let rows = stmt_fetch_accounts.query_map([], |row| {
        let acct: u32 = row.get(0)?;
        let account = AccountId::from(acct);
        let ufvk_str: String = row.get(1)?;
        let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
            .map_err(SqliteClientError::CorruptedData);

        Ok((account, ufvk))
    })?;

    let mut res: HashMap<AccountId, UnifiedFullViewingKey> = HashMap::new();
    for row in rows {
        let (account_id, ufvkr) = row?;
        res.insert(account_id, ufvkr?);
    }

    Ok(res)
}

/// Returns the account id corresponding to a given [`UnifiedFullViewingKey`],
/// if any.
pub(crate) fn get_account_for_ufvk<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    ufvk: &UnifiedFullViewingKey,
) -> Result<Option<AccountId>, SqliteClientError> {
    conn.query_row(
        "SELECT account FROM accounts WHERE ufvk = ?",
        [&ufvk.encode(params)],
        |row| {
            let acct: u32 = row.get(0)?;
            Ok(AccountId::from(acct))
        },
    )
    .optional()
    .map_err(SqliteClientError::from)
}

/// Checks whether the specified [`ExtendedFullViewingKey`] is valid and corresponds to the
/// specified account.
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
pub(crate) fn is_valid_account_extfvk<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
    extfvk: &ExtendedFullViewingKey,
) -> Result<bool, SqliteClientError> {
    conn.prepare("SELECT ufvk FROM accounts WHERE account = ?")?
        .query_row([u32::from(account).to_sql()?], |row| {
            row.get(0).map(|ufvk_str: String| {
                UnifiedFullViewingKey::decode(params, &ufvk_str)
                    .map_err(SqliteClientError::CorruptedData)
            })
        })
        .optional()
        .map_err(SqliteClientError::from)
        .and_then(|row| {
            if let Some(ufvk) = row {
                ufvk.map(|ufvk| {
                    ufvk.sapling().map(|dfvk| dfvk.to_bytes())
                        == Some(DiversifiableFullViewingKey::from(extfvk.clone()).to_bytes())
                })
            } else {
                Ok(false)
            }
        })
}

/// Returns the balance for the account, including all mined unspent notes that we know
/// about.
///
/// WARNING: This balance is potentially unreliable, as mined notes may become unmined due
/// to chain reorgs. You should generally not show this balance to users without some
/// caveat. Use [`get_balance_at`] where you need a more reliable indication of the
/// wallet balance.
#[cfg(test)]
pub(crate) fn get_balance(
    conn: &rusqlite::Connection,
    account: AccountId,
) -> Result<Amount, SqliteClientError> {
    let balance = conn.query_row(
        "SELECT SUM(value) FROM sapling_received_notes
        INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block IS NOT NULL",
        [u32::from(account)],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError::CorruptedData(
            "Sum of values in sapling_received_notes is out of range".to_string(),
        )),
    }
}

/// Returns the verified balance for the account at the specified height,
/// This may be used to obtain a balance that ignores notes that have been
/// received so recently that they are not yet deemed spendable.
pub(crate) fn get_balance_at(
    conn: &rusqlite::Connection,
    account: AccountId,
    anchor_height: BlockHeight,
) -> Result<Amount, SqliteClientError> {
    let balance = conn.query_row(
        "SELECT SUM(value) FROM sapling_received_notes
        INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block <= ?",
        [u32::from(account), u32::from(anchor_height)],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError::CorruptedData(
            "Sum of values in sapling_received_notes is out of range".to_string(),
        )),
    }
}

/// Returns the memo for a received note.
///
/// The note is identified by its row index in the `sapling_received_notes` table within the wdb
/// database.
pub(crate) fn get_received_memo(
    conn: &rusqlite::Connection,
    id_note: i64,
) -> Result<Option<Memo>, SqliteClientError> {
    let memo_bytes: Option<Vec<_>> = conn.query_row(
        "SELECT memo FROM sapling_received_notes
        WHERE id_note = ?",
        [id_note],
        |row| row.get(0),
    )?;

    memo_bytes
        .map(|b| {
            MemoBytes::from_bytes(&b)
                .and_then(Memo::try_from)
                .map_err(SqliteClientError::from)
        })
        .transpose()
}

/// Looks up a transaction by its internal database identifier.
pub(crate) fn get_transaction<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    id_tx: i64,
) -> Result<Transaction, SqliteClientError> {
    let (tx_bytes, block_height): (Vec<_>, BlockHeight) = conn.query_row(
        "SELECT raw, block FROM transactions
        WHERE id_tx = ?",
        [id_tx],
        |row| {
            let h: u32 = row.get(1)?;
            Ok((row.get(0)?, BlockHeight::from(h)))
        },
    )?;

    Transaction::read(&tx_bytes[..], BranchId::for_height(params, block_height))
        .map_err(SqliteClientError::from)
}

/// Returns the memo for a sent note.
///
/// The note is identified by its row index in the `sent_notes` table within the wdb
/// database.
pub(crate) fn get_sent_memo(
    conn: &rusqlite::Connection,
    id_note: i64,
) -> Result<Option<Memo>, SqliteClientError> {
    let memo_bytes: Option<Vec<_>> = conn.query_row(
        "SELECT memo FROM sent_notes
        WHERE id_note = ?",
        [id_note],
        |row| row.get(0),
    )?;

    memo_bytes
        .map(|b| {
            MemoBytes::from_bytes(&b)
                .and_then(Memo::try_from)
                .map_err(SqliteClientError::from)
        })
        .transpose()
}

pub(crate) fn chain_tip(
    conn: &rusqlite::Connection,
    depth: usize,
) -> Result<Vec<BlockMetadata>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT height, hash, sapling_commitment_tree_size, sapling_tree
        FROM blocks
        ORDER BY height DESC
        LIMIT :depth",
    )?;

    let rows = stmt.query(named_params![":depth": depth])?;
    rows.mapped(|row| {
        let height: u32 = row.get(0)?;
        let block_hash: Vec<u8> = row.get(1)?;
        let sapling_tree_size: Option<u32> = row.get(2)?;
        let sapling_tree: Vec<u8> = row.get(3)?;
        Ok((
            BlockHeight::from(height),
            block_hash,
            sapling_tree_size,
            sapling_tree,
        ))
    })
    .map(|row| {
        row.map_err(SqliteClientError::from)
            .and_then(parse_block_metadata)
    })
    .scan(None, |prev: &mut Option<BlockMetadata>, res| {
        if let Some(successor) = prev {
            // we need to avoid swallowing parse errors, so we continue the scan if we hit one, and
            // only stop if we successfully find a discontinuity
            match res {
                Ok(m) => {
                    if m.block_height() + 1 == successor.block_height() {
                        *prev = Some(m);
                        Some(res)
                    } else {
                        // terminate if we hit a gap in the range
                        None
                    }
                }
                err => Some(err),
            }
        } else {
            Some(res)
        }
    })
    .collect::<Result<Vec<BlockMetadata>, _>>()
    .map(|mut chain_tip| {
        // return in increasing block height order
        chain_tip.reverse();
        chain_tip
    })
}

/// Returns the minimum and maximum heights for blocks stored in the wallet database.
pub(crate) fn block_height_extrema(
    conn: &rusqlite::Connection,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    conn.query_row("SELECT MIN(height), MAX(height) FROM blocks", [], |row| {
        let min_height: Option<u32> = row.get(0)?;
        let max_height: Option<u32> = row.get(1)?;
        Ok(min_height
            .map(BlockHeight::from)
            .zip(max_height.map(BlockHeight::from)))
    })
}

fn parse_block_metadata(
    row: (BlockHeight, Vec<u8>, Option<u32>, Vec<u8>),
) -> Result<BlockMetadata, SqliteClientError> {
    let (block_height, hash_data, sapling_tree_size_opt, sapling_tree) = row;
    let sapling_tree_size = sapling_tree_size_opt.map_or_else(|| {
        if sapling_tree == BLOCK_SAPLING_FRONTIER_ABSENT {
            Err(SqliteClientError::CorruptedData("One of either the Sapling tree size or the legacy Sapling commitment tree must be present.".to_owned()))
        } else {
            // parse the legacy commitment tree data
            read_commitment_tree::<
                zcash_primitives::sapling::Node,
                _,
                { zcash_primitives::sapling::NOTE_COMMITMENT_TREE_DEPTH },
            >(Cursor::new(sapling_tree))
            .map(|tree| tree.size().try_into().unwrap())
            .map_err(SqliteClientError::from)
        }
    }, Ok)?;

    let block_hash = BlockHash::try_from_slice(&hash_data).ok_or_else(|| {
        SqliteClientError::from(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid block hash length: {}", hash_data.len()),
        ))
    })?;

    Ok(BlockMetadata::from_parts(
        block_height,
        block_hash,
        sapling_tree_size,
    ))
}

pub(crate) fn block_metadata(
    conn: &rusqlite::Connection,
    block_height: BlockHeight,
) -> Result<Option<BlockMetadata>, SqliteClientError> {
    conn.query_row(
        "SELECT height, hash, sapling_commitment_tree_size, sapling_tree
        FROM blocks
        WHERE height = :block_height",
        named_params![":block_height": u32::from(block_height)],
        |row| {
            let height: u32 = row.get(0)?;
            let block_hash: Vec<u8> = row.get(1)?;
            let sapling_tree_size: Option<u32> = row.get(2)?;
            let sapling_tree: Vec<u8> = row.get(3)?;
            Ok((
                BlockHeight::from(height),
                block_hash,
                sapling_tree_size,
                sapling_tree,
            ))
        },
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|meta_row| meta_row.map(parse_block_metadata).transpose())
}

pub(crate) fn block_fully_scanned(
    conn: &rusqlite::Connection,
) -> Result<Option<BlockMetadata>, SqliteClientError> {
    // FIXME: this will need to be rewritten once out-of-order scan range suggestion
    // is implemented.
    conn.query_row(
        "SELECT height, hash, sapling_commitment_tree_size, sapling_tree
            FROM blocks
            ORDER BY height DESC
            LIMIT 1",
        [],
        |row| {
            let height: u32 = row.get(0)?;
            let block_hash: Vec<u8> = row.get(1)?;
            let sapling_tree_size: Option<u32> = row.get(2)?;
            let sapling_tree: Vec<u8> = row.get(3)?;
            Ok((
                BlockHeight::from(height),
                block_hash,
                sapling_tree_size,
                sapling_tree,
            ))
        },
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|meta_row| meta_row.map(parse_block_metadata).transpose())
}

/// Returns the block height at which the specified transaction was mined,
/// if any.
pub(crate) fn get_tx_height(
    conn: &rusqlite::Connection,
    txid: TxId,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.query_row(
        "SELECT block FROM transactions WHERE txid = ?",
        [txid.as_ref().to_vec()],
        |row| row.get(0).map(u32::into),
    )
    .optional()
}

/// Returns the block hash for the block at the specified height,
/// if any.
pub(crate) fn get_block_hash(
    conn: &rusqlite::Connection,
    block_height: BlockHeight,
) -> Result<Option<BlockHash>, rusqlite::Error> {
    conn.query_row(
        "SELECT hash FROM blocks WHERE height = ?",
        [u32::from(block_height)],
        |row| {
            let row_data = row.get::<_, Vec<_>>(0)?;
            Ok(BlockHash::from_slice(&row_data))
        },
    )
    .optional()
}

/// Gets the height to which the database must be truncated if any truncation that would remove a
/// number of blocks greater than the pruning height is attempted.
pub(crate) fn get_min_unspent_height(
    conn: &rusqlite::Connection,
) -> Result<Option<BlockHeight>, SqliteClientError> {
    conn.query_row(
        "SELECT MIN(tx.block)
             FROM sapling_received_notes n
             JOIN transactions tx ON tx.id_tx = n.tx
             WHERE n.spent IS NULL",
        [],
        |row| {
            row.get(0)
                .map(|maybe_height: Option<u32>| maybe_height.map(|height| height.into()))
        },
    )
    .map_err(SqliteClientError::from)
}

/// Truncates the database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
///
/// This should only be executed inside a transactional context.
pub(crate) fn truncate_to_height<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    block_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let sapling_activation_height = params
        .activation_height(NetworkUpgrade::Sapling)
        .expect("Sapling activation height mutst be available.");

    // Recall where we synced up to previously.
    let last_scanned_height = conn.query_row("SELECT MAX(height) FROM blocks", [], |row| {
        row.get::<_, Option<u32>>(0)
            .map(|opt| opt.map_or_else(|| sapling_activation_height - 1, BlockHeight::from))
    })?;

    if block_height < last_scanned_height - PRUNING_DEPTH {
        if let Some(h) = get_min_unspent_height(conn)? {
            if block_height > h {
                return Err(SqliteClientError::RequestedRewindInvalid(h, block_height));
            }
        }
    }

    // nothing to do if we're deleting back down to the max height
    if block_height < last_scanned_height {
        // Truncate the note commitment trees
        let mut wdb = WalletDb {
            conn: SqlTransaction(conn),
            params: params.clone(),
        };
        wdb.with_sapling_tree_mut(|tree| {
            tree.truncate_removing_checkpoint(&block_height).map(|_| ())
        })?;

        // Remove any legacy Sapling witnesses
        conn.execute(
            "DELETE FROM sapling_witnesses WHERE block > ?",
            [u32::from(block_height)],
        )?;

        // Rewind received notes
        conn.execute(
            "DELETE FROM sapling_received_notes
            WHERE id_note IN (
                SELECT rn.id_note
                FROM sapling_received_notes rn
                LEFT OUTER JOIN transactions tx
                ON tx.id_tx = rn.tx
                WHERE tx.block IS NOT NULL AND tx.block > ?
            );",
            [u32::from(block_height)],
        )?;

        // Do not delete sent notes; this can contain data that is not recoverable
        // from the chain. Wallets must continue to operate correctly in the
        // presence of stale sent notes that link to unmined transactions.

        // Rewind utxos
        conn.execute(
            "DELETE FROM utxos WHERE height > ?",
            [u32::from(block_height)],
        )?;

        // Un-mine transactions.
        conn.execute(
            "UPDATE transactions SET block = NULL, tx_index = NULL WHERE block IS NOT NULL AND block > ?",
            [u32::from(block_height)],
        )?;

        // Now that they aren't depended on, delete scanned blocks.
        conn.execute(
            "DELETE FROM blocks WHERE height > ?",
            [u32::from(block_height)],
        )?;
    }

    Ok(())
}

/// Returns unspent transparent outputs that have been received by this wallet at the given
/// transparent address, such that the block that included the transaction was mined at a
/// height less than or equal to the provided `max_height`.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_unspent_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
    max_height: BlockHeight,
    exclude: &[OutPoint],
) -> Result<Vec<WalletTransparentOutput>, SqliteClientError> {
    let mut stmt_blocks = conn.prepare(
        "SELECT u.prevout_txid, u.prevout_idx, u.script,
                u.value_zat, u.height, tx.block as block
         FROM utxos u
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = u.spent_in_tx
         WHERE u.address = :address
         AND u.height <= :max_height
         AND tx.block IS NULL",
    )?;

    let addr_str = address.encode(params);

    let mut utxos = Vec::<WalletTransparentOutput>::new();
    let mut rows = stmt_blocks.query(named_params![
        ":address": addr_str,
        ":max_height": u32::from(max_height)
    ])?;
    let excluded: BTreeSet<OutPoint> = exclude.iter().cloned().collect();
    while let Some(row) = rows.next()? {
        let txid: Vec<u8> = row.get(0)?;
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&txid);

        let index: u32 = row.get(1)?;
        let script_pubkey = Script(row.get(2)?);
        let value = Amount::from_i64(row.get(3)?).unwrap();
        let height: u32 = row.get(4)?;

        let outpoint = OutPoint::new(txid_bytes, index);
        if excluded.contains(&outpoint) {
            continue;
        }

        let output = WalletTransparentOutput::from_parts(
            outpoint,
            TxOut {
                value,
                script_pubkey,
            },
            BlockHeight::from(height),
        )
        .ok_or_else(|| {
            SqliteClientError::CorruptedData(
                "Txout script_pubkey value did not correspond to a P2PKH or P2SH address"
                    .to_string(),
            )
        })?;

        utxos.push(output);
    }

    Ok(utxos)
}

/// Returns the unspent balance for each transparent address associated with the specified account,
/// such that the block that included the transaction was mined at a height less than or equal to
/// the provided `max_height`.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_transparent_balances<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
    max_height: BlockHeight,
) -> Result<HashMap<TransparentAddress, Amount>, SqliteClientError> {
    let mut stmt_blocks = conn.prepare(
        "SELECT u.address, SUM(u.value_zat)
         FROM utxos u
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = u.spent_in_tx
         WHERE u.received_by_account = :account_id
         AND u.height <= :max_height
         AND tx.block IS NULL
         GROUP BY u.address",
    )?;

    let mut res = HashMap::new();
    let mut rows = stmt_blocks.query(named_params![
        ":account_id": u32::from(account),
        ":max_height": u32::from(max_height)
    ])?;
    while let Some(row) = rows.next()? {
        let taddr_str: String = row.get(0)?;
        let taddr = TransparentAddress::decode(params, &taddr_str)?;
        let value = Amount::from_i64(row.get(1)?).unwrap();

        res.insert(taddr, value);
    }

    Ok(res)
}

/// Inserts information about a scanned block into the database.
pub(crate) fn put_block(
    conn: &rusqlite::Transaction<'_>,
    block_height: BlockHeight,
    block_hash: BlockHash,
    block_time: u32,
    sapling_commitment_tree_size: u32,
) -> Result<(), SqliteClientError> {
    let block_hash_data = conn
        .query_row(
            "SELECT hash FROM blocks WHERE height = ?",
            [u32::from(block_height)],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;

    // Ensure that in the case of an upsert, we don't overwrite block data
    // with information for a block with a different hash.
    if let Some(bytes) = block_hash_data {
        let expected_hash = BlockHash::try_from_slice(&bytes).ok_or_else(|| {
            SqliteClientError::CorruptedData(format!(
                "Invalid block hash at height {}",
                u32::from(block_height)
            ))
        })?;
        if expected_hash != block_hash {
            return Err(SqliteClientError::BlockConflict(block_height));
        }
    }

    let mut stmt_upsert_block = conn.prepare_cached(
        "INSERT INTO blocks (
            height,
            hash,
            time,
            sapling_commitment_tree_size,
            sapling_tree
        )
        VALUES (
            :height,
            :hash,
            :block_time,
            :sapling_commitment_tree_size,
            x'00'
        )
        ON CONFLICT (height) DO UPDATE
        SET hash = :hash,
            time = :block_time,
            sapling_commitment_tree_size = :sapling_commitment_tree_size",
    )?;

    stmt_upsert_block.execute(named_params![
        ":height": u32::from(block_height),
        ":hash": &block_hash.0[..],
        ":block_time": block_time,
        ":sapling_commitment_tree_size": sapling_commitment_tree_size
    ])?;

    Ok(())
}

/// Inserts information about a mined transaction that was observed to
/// contain a note related to this wallet into the database.
pub(crate) fn put_tx_meta<N>(
    conn: &rusqlite::Connection,
    tx: &WalletTx<N>,
    height: BlockHeight,
) -> Result<i64, SqliteClientError> {
    // It isn't there, so insert our transaction into the database.
    let mut stmt_upsert_tx_meta = conn.prepare_cached(
        "INSERT INTO transactions (txid, block, tx_index)
        VALUES (:txid, :block, :tx_index)
        ON CONFLICT (txid) DO UPDATE
        SET block = :block,
            tx_index = :tx_index
        RETURNING id_tx",
    )?;

    let tx_params = named_params![
        ":txid": &tx.txid.as_ref()[..],
        ":block": u32::from(height),
        ":tx_index": i64::try_from(tx.index).expect("transaction indices are representable as i64"),
    ];

    stmt_upsert_tx_meta
        .query_row(tx_params, |row| row.get::<_, i64>(0))
        .map_err(SqliteClientError::from)
}

/// Inserts full transaction data into the database.
pub(crate) fn put_tx_data(
    conn: &rusqlite::Connection,
    tx: &Transaction,
    fee: Option<Amount>,
    created_at: Option<time::OffsetDateTime>,
) -> Result<i64, SqliteClientError> {
    let mut stmt_upsert_tx_data = conn.prepare_cached(
        "INSERT INTO transactions (txid, created, expiry_height, raw, fee)
        VALUES (:txid, :created_at, :expiry_height, :raw, :fee)
        ON CONFLICT (txid) DO UPDATE
        SET expiry_height = :expiry_height,
            raw = :raw,
            fee = IFNULL(:fee, fee)
        RETURNING id_tx",
    )?;

    let txid = tx.txid();
    let mut raw_tx = vec![];
    tx.write(&mut raw_tx)?;

    let tx_params = named_params![
        ":txid": &txid.as_ref()[..],
        ":created_at": created_at,
        ":expiry_height": u32::from(tx.expiry_height()),
        ":raw": raw_tx,
        ":fee": fee.map(i64::from),
    ];

    stmt_upsert_tx_data
        .query_row(tx_params, |row| row.get::<_, i64>(0))
        .map_err(SqliteClientError::from)
}

/// Marks the given UTXO as having been spent.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn mark_transparent_utxo_spent(
    conn: &rusqlite::Connection,
    tx_ref: i64,
    outpoint: &OutPoint,
) -> Result<(), SqliteClientError> {
    let mut stmt_mark_transparent_utxo_spent = conn.prepare_cached(
        "UPDATE utxos SET spent_in_tx = :spent_in_tx
        WHERE prevout_txid = :prevout_txid
        AND prevout_idx = :prevout_idx",
    )?;

    let sql_args = named_params![
        ":spent_in_tx": &tx_ref,
        ":prevout_txid": &outpoint.hash().to_vec(),
        ":prevout_idx": &outpoint.n(),
    ];

    stmt_mark_transparent_utxo_spent.execute(sql_args)?;
    Ok(())
}

/// Adds the given received UTXO to the datastore.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn put_received_transparent_utxo<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    output: &WalletTransparentOutput,
) -> Result<UtxoId, SqliteClientError> {
    let address_str = output.recipient_address().encode(params);
    let account_id = conn
        .query_row(
            "SELECT account FROM addresses WHERE cached_transparent_receiver_address = :address",
            named_params![":address": &address_str],
            |row| row.get::<_, u32>(0).map(AccountId::from),
        )
        .optional()?;

    let utxoid = if let Some(account) = account_id {
        put_legacy_transparent_utxo(conn, params, output, account)?
    } else {
        // If the UTXO is received at the legacy transparent address, there may be no entry in the
        // addresses table that can be used to tie the address to a particular account. In this
        // case, we should look up the legacy address for account 0 and check whether it matches
        // the address for the received UTXO, and if so then insert/update it directly.
        let account = AccountId::from(0u32);
        get_legacy_transparent_address(params, conn, account).and_then(|legacy_taddr| {
            if legacy_taddr
                .iter()
                .any(|(taddr, _)| taddr == output.recipient_address())
            {
                put_legacy_transparent_utxo(conn, params, output, account)
                    .map_err(SqliteClientError::from)
            } else {
                Err(SqliteClientError::AddressNotRecognized(
                    *output.recipient_address(),
                ))
            }
        })?
    };

    Ok(utxoid)
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn put_legacy_transparent_utxo<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    output: &WalletTransparentOutput,
    received_by_account: AccountId,
) -> Result<UtxoId, rusqlite::Error> {
    #[cfg(feature = "transparent-inputs")]
    let mut stmt_upsert_legacy_transparent_utxo = conn.prepare_cached(
        "INSERT INTO utxos (
            prevout_txid, prevout_idx,
            received_by_account, address, script,
            value_zat, height)
        VALUES
            (:prevout_txid, :prevout_idx,
            :received_by_account, :address, :script,
            :value_zat, :height)
        ON CONFLICT (prevout_txid, prevout_idx) DO UPDATE
        SET received_by_account = :received_by_account,
            height = :height,
            address = :address,
            script = :script,
            value_zat = :value_zat
        RETURNING id_utxo",
    )?;

    let sql_args = named_params![
        ":prevout_txid": &output.outpoint().hash().to_vec(),
        ":prevout_idx": &output.outpoint().n(),
        ":received_by_account": &u32::from(received_by_account),
        ":address": &output.recipient_address().encode(params),
        ":script": &output.txout().script_pubkey.0,
        ":value_zat": &i64::from(output.txout().value),
        ":height": &u32::from(output.height()),
    ];

    stmt_upsert_legacy_transparent_utxo.query_row(sql_args, |row| row.get::<_, i64>(0).map(UtxoId))
}

/// Marks notes that have not been mined in transactions
/// as expired, up to the given block height.
pub(crate) fn update_expired_notes(
    conn: &rusqlite::Connection,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let mut stmt_update_expired = conn.prepare_cached(
        "UPDATE sapling_received_notes SET spent = NULL WHERE EXISTS (
            SELECT id_tx FROM transactions
            WHERE id_tx = sapling_received_notes.spent AND block IS NULL AND expiry_height < ?
        )",
    )?;
    stmt_update_expired.execute([u32::from(height)])?;
    Ok(())
}

// A utility function for creation of parameters for use in `insert_sent_output`
// and `put_sent_output`
fn recipient_params<P: consensus::Parameters>(
    params: &P,
    to: &Recipient,
) -> (Option<String>, Option<u32>, PoolType) {
    match to {
        Recipient::Transparent(addr) => (Some(addr.encode(params)), None, PoolType::Transparent),
        Recipient::Sapling(addr) => (
            Some(addr.encode(params)),
            None,
            PoolType::Shielded(ShieldedProtocol::Sapling),
        ),
        Recipient::Unified(addr, pool) => (Some(addr.encode(params)), None, *pool),
        Recipient::InternalAccount(id, pool) => (None, Some(u32::from(*id)), *pool),
    }
}

/// Records information about a transaction output that your wallet created.
pub(crate) fn insert_sent_output<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    tx_ref: i64,
    from_account: AccountId,
    output: &SentTransactionOutput,
) -> Result<(), SqliteClientError> {
    let mut stmt_insert_sent_output = conn.prepare_cached(
        "INSERT INTO sent_notes (
            tx, output_pool, output_index, from_account,
            to_address, to_account, value, memo)
        VALUES (
            :tx, :output_pool, :output_index, :from_account,
            :to_address, :to_account, :value, :memo)",
    )?;

    let (to_address, to_account, pool_type) = recipient_params(params, output.recipient());
    let sql_args = named_params![
        ":tx": &tx_ref,
        ":output_pool": &pool_code(pool_type),
        ":output_index": &i64::try_from(output.output_index()).unwrap(),
        ":from_account": &u32::from(from_account),
        ":to_address": &to_address,
        ":to_account": &to_account,
        ":value": &i64::from(output.value()),
        ":memo": output.memo().filter(|m| *m != &MemoBytes::empty()).map(|m| m.as_slice()),
    ];

    stmt_insert_sent_output.execute(sql_args)?;

    Ok(())
}

/// Records information about a transaction output that your wallet created, from the constituent
/// properties of that output.
///
/// - If `recipient` is a Unified address, `output_index` is an index into the outputs of the
///   transaction within the bundle associated with the recipient's output pool.
/// - If `recipient` is a Sapling address, `output_index` is an index into the Sapling outputs of
///   the transaction.
/// - If `recipient` is a transparent address, `output_index` is an index into the transparent
///   outputs of the transaction.
/// - If `recipient` is an internal account, `output_index` is an index into the Sapling outputs of
///   the transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn put_sent_output<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    from_account: AccountId,
    tx_ref: i64,
    output_index: usize,
    recipient: &Recipient,
    value: Amount,
    memo: Option<&MemoBytes>,
) -> Result<(), SqliteClientError> {
    let mut stmt_upsert_sent_output = conn.prepare_cached(
        "INSERT INTO sent_notes (
            tx, output_pool, output_index, from_account,
            to_address, to_account, value, memo)
        VALUES (
            :tx, :output_pool, :output_index, :from_account,
            :to_address, :to_account, :value, :memo)
        ON CONFLICT (tx, output_pool, output_index) DO UPDATE
        SET from_account = :from_account,
            to_address = :to_address,
            to_account = :to_account,
            value = :value,
            memo = IFNULL(:memo, memo)",
    )?;

    let (to_address, to_account, pool_type) = recipient_params(params, recipient);
    let sql_args = named_params![
        ":tx": &tx_ref,
        ":output_pool": &pool_code(pool_type),
        ":output_index": &i64::try_from(output_index).unwrap(),
        ":from_account": &u32::from(from_account),
        ":to_address": &to_address,
        ":to_account": &to_account,
        ":value": &i64::from(value),
        ":memo": memo_repr(memo)
    ];

    stmt_upsert_sent_output.execute(sql_args)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use zcash_primitives::transaction::components::Amount;

    use zcash_client_backend::data_api::WalletRead;

    use crate::{
        tests,
        wallet::{get_current_address, init::init_wallet_db},
        AccountId, WalletDb,
    };

    use super::get_balance;

    #[cfg(feature = "transparent-inputs")]
    use {
        zcash_client_backend::{
            data_api::WalletWrite, encoding::AddressCodec, wallet::WalletTransparentOutput,
        },
        zcash_primitives::{
            consensus::BlockHeight,
            transaction::components::{OutPoint, TxOut},
        },
    };

    #[test]
    fn empty_database_has_no_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        tests::init_test_accounts_table(&mut db_data);

        // The account should be empty
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            Amount::zero()
        );

        // We can't get an anchor height, as we have not scanned any blocks.
        assert_eq!(
            db_data
                .get_target_and_anchor_heights(NonZeroU32::new(10).unwrap())
                .unwrap(),
            None
        );

        // An invalid account has zero balance
        assert_matches!(
            get_current_address(&db_data.conn, &db_data.params, AccountId::from(1)),
            Ok(None)
        );
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            Amount::zero()
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn put_received_transparent_utxo() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let seed = Secret::new([0u8; 32].to_vec());
        let (account_id, _usk) = db_data.create_account(&seed).unwrap();
        let uaddr = db_data.get_current_address(account_id).unwrap().unwrap();
        let taddr = uaddr.transparent().unwrap();

        let bal_absent = db_data
            .get_transparent_balances(account_id, BlockHeight::from_u32(12345))
            .unwrap();
        assert!(bal_absent.is_empty());

        let utxo = WalletTransparentOutput::from_parts(
            OutPoint::new([1u8; 32], 1),
            TxOut {
                value: Amount::from_u64(100000).unwrap(),
                script_pubkey: taddr.script(),
            },
            BlockHeight::from_u32(12345),
        )
        .unwrap();

        let res0 = super::put_received_transparent_utxo(&db_data.conn, &db_data.params, &utxo);
        assert_matches!(res0, Ok(_));

        // Change the mined height of the UTXO and upsert; we should get back
        // the same utxoid
        let utxo2 = WalletTransparentOutput::from_parts(
            OutPoint::new([1u8; 32], 1),
            TxOut {
                value: Amount::from_u64(100000).unwrap(),
                script_pubkey: taddr.script(),
            },
            BlockHeight::from_u32(34567),
        )
        .unwrap();
        let res1 = super::put_received_transparent_utxo(&db_data.conn, &db_data.params, &utxo2);
        assert_matches!(res1, Ok(id) if id == res0.unwrap());

        assert_matches!(
            super::get_unspent_transparent_outputs(
                &db_data.conn,
                &db_data.params,
                taddr,
                BlockHeight::from_u32(12345),
                &[]
            ),
            Ok(utxos) if utxos.is_empty()
        );

        assert_matches!(
            super::get_unspent_transparent_outputs(
                &db_data.conn,
                &db_data.params,
                taddr,
                BlockHeight::from_u32(34567),
                &[]
            ),
            Ok(utxos) if {
                utxos.len() == 1 &&
                utxos.iter().any(|rutxo| rutxo.height() == utxo2.height())
            }
        );

        assert_matches!(
            db_data.get_transparent_balances(account_id, BlockHeight::from_u32(34567)),
            Ok(h) if h.get(taddr) == Amount::from_u64(100000).ok().as_ref()
        );

        // Artificially delete the address from the addresses table so that
        // we can ensure the update fails if the join doesn't work.
        db_data
            .conn
            .execute(
                "DELETE FROM addresses WHERE cached_transparent_receiver_address = ?",
                [Some(taddr.encode(&db_data.params))],
            )
            .unwrap();

        let res2 = super::put_received_transparent_utxo(&db_data.conn, &db_data.params, &utxo2);
        assert_matches!(res2, Err(_));
    }
}
