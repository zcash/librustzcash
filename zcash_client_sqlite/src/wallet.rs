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

use incrementalmerkletree::Retention;
use rusqlite::{self, named_params, OptionalExtension, ToSql};
use shardtree::ShardTree;
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::io::{self, Cursor};
use std::num::NonZeroU32;
use tracing::debug;
use zcash_client_backend::data_api::{AccountBalance, Ratio, WalletSummary};
use zcash_primitives::transaction::components::amount::NonNegativeAmount;

use zcash_client_backend::data_api::{
    scanning::{ScanPriority, ScanRange},
    AccountBirthday, NoteId, ShieldedProtocol, SAPLING_SHARD_HEIGHT,
};
use zcash_primitives::transaction::TransactionData;

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

use crate::wallet::commitment_tree::SqliteShardStore;
use crate::{
    error::SqliteClientError, SqlTransaction, WalletCommitmentTrees, WalletDb, PRUNING_DEPTH,
};
use crate::{SAPLING_TABLES_PREFIX, VERIFY_LOOKAHEAD};

use self::scanning::{parse_priority_code, replace_queue_entries};

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

pub mod commitment_tree;
pub mod init;
pub(crate) mod sapling;
pub(crate) mod scanning;

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
    memo.map(|m| {
        if m == &MemoBytes::empty() {
            // we store the empty memo as a single 0xf6 byte
            &[0xf6]
        } else {
            m.as_slice()
        }
    })
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
    birthday: AccountBirthday,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO accounts (account, ufvk, birthday_height, recover_until_height)
        VALUES (:account, :ufvk, :birthday_height, :recover_until_height)",
        named_params![
            ":account": u32::from(account),
            ":ufvk": &key.encode(params),
            ":birthday_height": u32::from(birthday.height()),
            ":recover_until_height": birthday.recover_until().map(u32::from)
        ],
    )?;

    // If a birthday frontier is available, insert it into the note commitment tree. If the
    // birthday frontier is the empty frontier, we don't need to do anything.
    if let Some(frontier) = birthday.sapling_frontier().value() {
        debug!("Inserting frontier into ShardTree: {:?}", frontier);
        let shard_store = SqliteShardStore::<
            _,
            zcash_primitives::sapling::Node,
            SAPLING_SHARD_HEIGHT,
        >::from_connection(conn, SAPLING_TABLES_PREFIX)?;
        let mut shard_tree: ShardTree<
            _,
            { zcash_primitives::sapling::NOTE_COMMITMENT_TREE_DEPTH },
            SAPLING_SHARD_HEIGHT,
        > = ShardTree::new(shard_store, PRUNING_DEPTH.try_into().unwrap());
        shard_tree.insert_frontier_nodes(
            frontier.clone(),
            Retention::Checkpoint {
                // This subtraction is safe, because all leaves in the tree appear in blocks, and
                // the invariant that birthday.height() always corresponds to the block for which
                // `frontier` is the tree state at the start of the block. Together, this means
                // there exists a prior block for which frontier is the tree state at the end of
                // the block.
                id: birthday.height() - 1,
                is_marked: false,
            },
        )?;
    }

    let sapling_activation_height = params
        .activation_height(NetworkUpgrade::Sapling)
        .expect("Sapling activation height must be available.");

    // Add the ignored range up to the birthday height.
    if sapling_activation_height < birthday.height() {
        let ignored_range = sapling_activation_height..birthday.height();

        replace_queue_entries::<SqliteClientError>(
            conn,
            &ignored_range,
            Some(ScanRange::from_parts(
                ignored_range.clone(),
                ScanPriority::Ignored,
            ))
            .into_iter(),
            false,
        )?;
    };

    // Rewrite the scan ranges from the birthday height up to the chain tip so that we'll ensure we
    // re-scan to find any notes that might belong to the newly added account.
    if let Some(t) = scan_queue_extrema(conn)?.map(|(_, max)| max) {
        let rescan_range = birthday.height()..(t + 1);

        replace_queue_entries::<SqliteClientError>(
            conn,
            &rescan_range,
            Some(ScanRange::from_parts(
                rescan_range.clone(),
                ScanPriority::Historic,
            ))
            .into_iter(),
            true, // force rescan
        )?;
    }

    // Always derive the default Unified Address for the account.
    let (address, d_idx) = key.default_address();
    insert_address(conn, params, account, d_idx, &address)?;

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

pub(crate) trait ScanProgress {
    fn sapling_scan_progress(
        &self,
        conn: &rusqlite::Connection,
        birthday_height: BlockHeight,
        fully_scanned_height: BlockHeight,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Ratio<u64>>, SqliteClientError>;
}

pub(crate) struct SubtreeScanProgress;

impl ScanProgress for SubtreeScanProgress {
    fn sapling_scan_progress(
        &self,
        conn: &rusqlite::Connection,
        birthday_height: BlockHeight,
        fully_scanned_height: BlockHeight,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Ratio<u64>>, SqliteClientError> {
        if fully_scanned_height == chain_tip_height {
            // Compute the total blocks scanned since the wallet birthday
            conn.query_row(
                "SELECT SUM(sapling_output_count)
                 FROM blocks
                 WHERE height >= :birthday_height",
                named_params![":birthday_height": u32::from(birthday_height)],
                |row| {
                    let scanned = row.get::<_, Option<u64>>(0)?;
                    Ok(scanned.map(|n| Ratio::new(n, n)))
                },
            )
            .map_err(SqliteClientError::from)
        } else {
            let start_height = birthday_height;
            // Compute the starting number of notes directly from the blocks table
            let start_size = conn.query_row(
                "SELECT MAX(sapling_commitment_tree_size)
                 FROM blocks
                 WHERE height <= :start_height",
                named_params![":start_height": u32::from(start_height)],
                |row| row.get::<_, Option<u64>>(0),
            )?;

            // Compute the total blocks scanned so far above the starting height
            let scanned_count = conn.query_row(
                "SELECT SUM(sapling_output_count)
                 FROM blocks
                 WHERE height > :start_height",
                named_params![":start_height": u32::from(start_height)],
                |row| row.get::<_, Option<u64>>(0),
            )?;

            // We don't have complete information on how many outputs will exist in the shard at
            // the chain tip without having scanned the chain tip block, so we overestimate by
            // computing the maximum possible number of notes directly from the shard indices.
            //
            // TODO: it would be nice to be able to reliably have the size of the commitment tree
            // at the chain tip without having to have scanned that block.
            Ok(conn
                .query_row(
                    "SELECT MIN(shard_index), MAX(shard_index)
                     FROM sapling_tree_shards
                     WHERE subtree_end_height > :start_height
                     OR subtree_end_height IS NULL",
                    named_params![":start_height": u32::from(start_height)],
                    |row| {
                        let min_tree_size = row
                            .get::<_, Option<u64>>(0)?
                            .map(|min| min << SAPLING_SHARD_HEIGHT);
                        let max_idx = row.get::<_, Option<u64>>(1)?;
                        Ok(start_size
                            .or(min_tree_size)
                            .zip(max_idx)
                            .map(|(min_tree_size, max)| {
                                let max_tree_size = (max + 1) << SAPLING_SHARD_HEIGHT;
                                Ratio::new(
                                    scanned_count.unwrap_or(0),
                                    max_tree_size - min_tree_size,
                                )
                            }))
                    },
                )
                .optional()?
                .flatten())
        }
    }
}

/// Returns the spendable balance for the account at the specified height.
///
/// This may be used to obtain a balance that ignores notes that have been detected so recently
/// that they are not yet spendable, or for which it is not yet possible to construct witnesses.
///
/// `min_confirmations` can be 0, but that case is currently treated identically to
/// `min_confirmations == 1` for shielded notes. This behaviour may change in the future.
pub(crate) fn get_wallet_summary(
    conn: &rusqlite::Connection,
    min_confirmations: u32,
    progress: &impl ScanProgress,
) -> Result<Option<WalletSummary>, SqliteClientError> {
    let chain_tip_height = match scan_queue_extrema(conn)? {
        Some((_, max)) => max,
        None => {
            return Ok(None);
        }
    };

    let birthday_height =
        wallet_birthday(conn)?.expect("If a scan range exists, we know the wallet birthday.");

    let fully_scanned_height =
        block_fully_scanned(conn)?.map_or(birthday_height - 1, |m| m.block_height());
    let summary_height = (chain_tip_height + 1).saturating_sub(std::cmp::max(min_confirmations, 1));

    let sapling_scan_progress = progress.sapling_scan_progress(
        conn,
        birthday_height,
        fully_scanned_height,
        chain_tip_height,
    )?;

    // If the shard containing the summary height contains any unscanned ranges that start below or
    // including that height, none of our balance is currently spendable.
    let any_spendable = conn.query_row(
        "SELECT NOT EXISTS(
             SELECT 1 FROM v_sapling_shard_unscanned_ranges
             WHERE :summary_height
                BETWEEN subtree_start_height
                AND IFNULL(subtree_end_height, :summary_height)
             AND block_range_start <= :summary_height
         )",
        named_params![":summary_height": u32::from(summary_height)],
        |row| row.get::<_, bool>(0),
    )?;

    let mut stmt_accounts = conn.prepare_cached("SELECT account FROM accounts")?;
    let mut account_balances = stmt_accounts
        .query([])?
        .mapped(|row| {
            row.get::<_, u32>(0)
                .map(|a| (AccountId::from(a), AccountBalance::ZERO))
        })
        .collect::<Result<BTreeMap<AccountId, AccountBalance>, _>>()?;

    let mut stmt_select_notes = conn.prepare_cached(
        "SELECT n.account, n.value, n.is_change, scan_state.max_priority, t.block
         FROM sapling_received_notes n
         JOIN transactions t ON t.id_tx = n.tx
         LEFT OUTER JOIN v_sapling_shards_scan_state scan_state
            ON n.commitment_tree_position >= scan_state.start_position
            AND n.commitment_tree_position < scan_state.end_position_exclusive
         WHERE n.spent IS NULL
         AND (
             t.expiry_height IS NULL
             OR t.block IS NOT NULL
             OR t.expiry_height >= :summary_height
         )",
    )?;

    let mut rows =
        stmt_select_notes.query(named_params![":summary_height": u32::from(summary_height)])?;
    while let Some(row) = rows.next()? {
        let account = row.get::<_, u32>(0).map(AccountId::from)?;

        let value_raw = row.get::<_, i64>(1)?;
        let value = NonNegativeAmount::from_nonnegative_i64(value_raw).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative received note value: {}", value_raw))
        })?;

        let is_change = row.get::<_, bool>(2)?;

        // If `max_priority` is null, this means that the note is not positioned; the note
        // will not be spendable, so we assign the scan priority to `ChainTip` as a priority
        // that is greater than `Scanned`
        let max_priority_raw = row.get::<_, Option<i64>>(3)?;
        let max_priority = max_priority_raw.map_or_else(
            || Ok(ScanPriority::ChainTip),
            |raw| {
                parse_priority_code(raw).ok_or_else(|| {
                    SqliteClientError::CorruptedData(format!(
                        "Priority code {} not recognized.",
                        raw
                    ))
                })
            },
        )?;

        let received_height = row.get::<_, Option<u32>>(4)?.map(BlockHeight::from);

        let is_spendable = any_spendable
            && received_height.iter().any(|h| h <= &summary_height)
            && max_priority <= ScanPriority::Scanned;

        let is_pending_change = is_change && received_height.iter().all(|h| h > &summary_height);

        let (spendable_value, change_pending_confirmation, value_pending_spendability) = {
            let zero = NonNegativeAmount::ZERO;
            if is_spendable {
                (value, zero, zero)
            } else if is_pending_change {
                (zero, value, zero)
            } else {
                (zero, zero, value)
            }
        };

        account_balances.entry(account).and_modify(|bal| {
            bal.sapling_balance.spendable_value = (bal.sapling_balance.spendable_value
                + spendable_value)
                .expect("Spendable value cannot overflow");
            bal.sapling_balance.change_pending_confirmation =
                (bal.sapling_balance.change_pending_confirmation + change_pending_confirmation)
                    .expect("Pending change value cannot overflow");
            bal.sapling_balance.value_pending_spendability =
                (bal.sapling_balance.value_pending_spendability + value_pending_spendability)
                    .expect("Value pending spendability cannot overflow");
        });
    }

    #[cfg(feature = "transparent-inputs")]
    {
        let zero_conf_height = (chain_tip_height + 1).saturating_sub(min_confirmations);
        let mut stmt_transparent_balances = conn.prepare(
            "SELECT u.received_by_account, SUM(u.value_zat)
             FROM utxos u
             LEFT OUTER JOIN transactions tx
             ON tx.id_tx = u.spent_in_tx
             WHERE u.height <= :max_height
             AND tx.block IS NULL
             GROUP BY u.received_by_account",
        )?;
        let mut rows = stmt_transparent_balances
            .query(named_params![":max_height": u32::from(zero_conf_height)])?;

        while let Some(row) = rows.next()? {
            let account = AccountId::from(row.get::<_, u32>(0)?);
            let raw_value = row.get(1)?;
            let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
                SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
            })?;

            account_balances.entry(account).and_modify(|bal| {
                bal.unshielded = (bal.unshielded + value).expect("Unshielded value cannot overflow")
            });
        }
    }

    let summary = WalletSummary::new(
        account_balances,
        chain_tip_height,
        fully_scanned_height,
        sapling_scan_progress,
    );

    Ok(Some(summary))
}

/// Returns the memo for a received note, if the note is known to the wallet.
pub(crate) fn get_received_memo(
    conn: &rusqlite::Connection,
    note_id: NoteId,
) -> Result<Option<Memo>, SqliteClientError> {
    let memo_bytes: Option<Vec<_>> = match note_id.protocol() {
        ShieldedProtocol::Sapling => conn
            .query_row(
                "SELECT memo FROM sapling_received_notes
                JOIN transactions ON sapling_received_notes.tx = transactions.id_tx
                WHERE transactions.txid = :txid
                AND sapling_received_notes.output_index = :output_index",
                named_params![
                    ":txid": note_id.txid().as_ref(),
                    ":output_index": note_id.output_index()
                ],
                |row| row.get(0),
            )
            .optional()?
            .flatten(),
    };

    memo_bytes
        .map(|b| {
            MemoBytes::from_bytes(&b)
                .and_then(Memo::try_from)
                .map_err(SqliteClientError::from)
        })
        .transpose()
}

/// Looks up a transaction by its [`TxId`].
///
/// Returns the decoded transaction, along with the block height that was used in its decoding.
/// This is either the block height at which the transaction was mined, or the expiry height if the
/// wallet created the transaction but the transaction has not yet been mined from the perspective
/// of the wallet.
pub(crate) fn get_transaction<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    txid: TxId,
) -> Result<(BlockHeight, Transaction), SqliteClientError> {
    let (tx_bytes, block_height, expiry_height): (
        Vec<_>,
        Option<BlockHeight>,
        Option<BlockHeight>,
    ) = conn.query_row(
        "SELECT raw, block, expiry_height FROM transactions
        WHERE txid = ?",
        [txid.as_ref()],
        |row| {
            let h: Option<u32> = row.get(1)?;
            let expiry: Option<u32> = row.get(2)?;
            Ok((
                row.get(0)?,
                h.map(BlockHeight::from),
                expiry.map(BlockHeight::from),
            ))
        },
    )?;

    // We need to provide a consensus branch ID so that pre-v5 `Transaction` structs
    // (which don't commit directly to one) can store it internally.
    // - If the transaction is mined, we use the block height to get the correct one.
    // - If the transaction is unmined and has a cached non-zero expiry height, we use
    //   that (relying on the invariant that a transaction can't be mined across a network
    //   upgrade boundary, so the expiry height must be in the same epoch).
    // - Otherwise, we use a placeholder for the initial transaction parse (as the
    //   consensus branch ID is not used there), and then either use its non-zero expiry
    //   height or return an error.
    if let Some(height) =
        block_height.or_else(|| expiry_height.filter(|h| h > &BlockHeight::from(0)))
    {
        Transaction::read(&tx_bytes[..], BranchId::for_height(params, height))
            .map(|t| (height, t))
            .map_err(SqliteClientError::from)
    } else {
        let tx_data = Transaction::read(&tx_bytes[..], BranchId::Sprout)
            .map_err(SqliteClientError::from)?
            .into_data();

        let expiry_height = tx_data.expiry_height();
        if expiry_height > BlockHeight::from(0) {
            TransactionData::from_parts(
                tx_data.version(),
                BranchId::for_height(params, expiry_height),
                tx_data.lock_time(),
                expiry_height,
                tx_data.transparent_bundle().cloned(),
                tx_data.sprout_bundle().cloned(),
                tx_data.sapling_bundle().cloned(),
                tx_data.orchard_bundle().cloned(),
            )
            .freeze()
            .map(|t| (expiry_height, t))
            .map_err(SqliteClientError::from)
        } else {
            Err(SqliteClientError::CorruptedData(
                "Consensus branch ID not known, cannot parse this transaction until it is mined"
                    .to_string(),
            ))
        }
    }
}

/// Returns the memo for a sent note, if the sent note is known to the wallet.
pub(crate) fn get_sent_memo(
    conn: &rusqlite::Connection,
    note_id: NoteId,
) -> Result<Option<Memo>, SqliteClientError> {
    let memo_bytes: Option<Vec<_>> = conn
        .query_row(
            "SELECT memo FROM sent_notes
            JOIN transactions ON sent_notes.tx = transactions.id_tx
            WHERE transactions.txid = :txid
            AND sent_notes.output_pool = :pool_code
            AND sent_notes.output_index = :output_index",
            named_params![
                ":txid": note_id.txid().as_ref(),
                ":pool_code": pool_code(PoolType::Shielded(note_id.protocol())),
                ":output_index": note_id.output_index()
            ],
            |row| row.get(0),
        )
        .optional()?
        .flatten();

    memo_bytes
        .map(|b| {
            MemoBytes::from_bytes(&b)
                .and_then(Memo::try_from)
                .map_err(SqliteClientError::from)
        })
        .transpose()
}

/// Returns the minimum birthday height for accounts in the wallet.
//
// TODO ORCHARD: we should consider whether we want to permit protocol-restricted accounts; if so,
// we would then want this method to take a protocol identifier to be able to learn the wallet's
// "Orchard birthday" which might be different from the overall wallet birthday.
pub(crate) fn wallet_birthday(
    conn: &rusqlite::Connection,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.query_row(
        "SELECT MIN(birthday_height) AS wallet_birthday FROM accounts",
        [],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
}

pub(crate) fn account_birthday(
    conn: &rusqlite::Connection,
    account: AccountId,
) -> Result<BlockHeight, SqliteClientError> {
    conn.query_row(
        "SELECT birthday_height
         FROM accounts
         WHERE account = :account_id",
        named_params![":account_id": u32::from(account)],
        |row| row.get::<_, u32>(0).map(BlockHeight::from),
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|opt| opt.ok_or(SqliteClientError::AccountUnknown(account)))
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

/// Returns the minimum and maximum heights of blocks in the chain which may be scanned.
pub(crate) fn scan_queue_extrema(
    conn: &rusqlite::Connection,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    conn.query_row(
        "SELECT MIN(block_range_start), MAX(block_range_end) FROM scan_queue",
        [],
        |row| {
            let min_height: Option<u32> = row.get(0)?;
            let max_height: Option<u32> = row.get(1)?;

            // Scan ranges are end-exclusive, so we subtract 1 from `max_height` to obtain the
            // height of the last known chain tip;
            Ok(min_height
                .map(BlockHeight::from)
                .zip(max_height.map(|h| BlockHeight::from(h.saturating_sub(1)))))
        },
    )
}

pub(crate) fn get_target_and_anchor_heights(
    conn: &rusqlite::Connection,
    min_confirmations: NonZeroU32,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    scan_queue_extrema(conn).map(|heights| {
        heights.map(|(min_height, max_height)| {
            let target_height = max_height + 1;
            // Select an anchor min_confirmations back from the target block,
            // unless that would be before the earliest block we have.
            let anchor_height = BlockHeight::from(cmp::max(
                u32::from(target_height).saturating_sub(min_confirmations.into()),
                u32::from(min_height),
            ));

            (target_height, anchor_height)
        })
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
    if let Some(birthday_height) = wallet_birthday(conn)? {
        // We assume that the only way we get a contiguous range of block heights in the `blocks` table
        // starting with the birthday block, is if all scanning operations have been performed on those
        // blocks. This holds because the `blocks` table is only altered by `WalletDb::put_blocks` via
        // `put_block`, and the effective combination of intra-range linear scanning and the nullifier
        // map ensures that we discover all wallet-related information within the contiguous range.
        //
        // The fully-scanned height is therefore the greatest height in the first contiguous range of
        // block rows, which is a combined case of the "gaps and islands" and "greatest N per group"
        // SQL query problems.
        conn.query_row(
            "SELECT height, hash, sapling_commitment_tree_size, sapling_tree
            FROM blocks
            INNER JOIN (
                WITH contiguous AS (
                    SELECT height, ROW_NUMBER() OVER (ORDER BY height) - height AS grp
                    FROM blocks
                )
                SELECT MIN(height) AS group_min_height, MAX(height) AS group_max_height
                FROM contiguous
                GROUP BY grp
                HAVING :birthday_height BETWEEN group_min_height AND group_max_height
            )
            ON height = group_max_height",
            named_params![":birthday_height": u32::from(birthday_height)],
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
    } else {
        Ok(None)
    }
}

pub(crate) fn block_max_scanned(
    conn: &rusqlite::Connection,
) -> Result<Option<BlockMetadata>, SqliteClientError> {
    conn.query_row(
        "SELECT blocks.height, hash, sapling_commitment_tree_size, sapling_tree
         FROM blocks
         JOIN (SELECT MAX(height) AS height FROM blocks) blocks_max
         ON blocks.height = blocks_max.height",
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

pub(crate) fn get_max_height_hash(
    conn: &rusqlite::Connection,
) -> Result<Option<(BlockHeight, BlockHash)>, rusqlite::Error> {
    conn.query_row(
        "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
        [],
        |row| {
            let height = row.get::<_, u32>(0).map(BlockHeight::from)?;
            let row_data = row.get::<_, Vec<_>>(1)?;
            Ok((height, BlockHash::from_slice(&row_data)))
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
        .expect("Sapling activation height must be available.");

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
            "UPDATE transactions SET block = NULL, tx_index = NULL
            WHERE block IS NOT NULL AND block > ?",
            [u32::from(block_height)],
        )?;

        // Now that they aren't depended on, delete scanned blocks.
        conn.execute(
            "DELETE FROM blocks WHERE height > ?",
            [u32::from(block_height)],
        )?;

        // Delete from the nullifier map any entries with a locator referencing a block
        // height greater than the truncation height.
        conn.execute(
            "DELETE FROM tx_locator_map
            WHERE block_height > :block_height",
            named_params![":block_height": u32::from(block_height)],
        )?;

        // Delete from the scanning queue any range with a start height greater than the
        // truncation height, and then truncate any remaining range by setting the end
        // equal to the truncation height + 1.
        conn.execute(
            "DELETE FROM scan_queue
            WHERE block_range_start > :block_height",
            named_params![":block_height": u32::from(block_height)],
        )?;

        conn.execute(
            "UPDATE scan_queue
            SET block_range_end = :end_height
            WHERE block_range_end > :end_height",
            named_params![":end_height": u32::from(block_height + 1)],
        )?;

        // Prioritize the range starting at the height we just rewound to for verification
        let query_range = block_height..(block_height + VERIFY_LOOKAHEAD);
        let scan_range = ScanRange::from_parts(query_range.clone(), ScanPriority::Verify);
        replace_queue_entries::<SqliteClientError>(
            conn,
            &query_range,
            Some(scan_range).into_iter(),
            false,
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
    sapling_output_count: u32,
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
            sapling_output_count,
            sapling_tree
        )
        VALUES (
            :height,
            :hash,
            :block_time,
            :sapling_commitment_tree_size,
            :sapling_output_count,
            x'00'
        )
        ON CONFLICT (height) DO UPDATE
        SET hash = :hash,
            time = :block_time,
            sapling_commitment_tree_size = :sapling_commitment_tree_size,
            sapling_output_count = :sapling_output_count",
    )?;

    stmt_upsert_block.execute(named_params![
        ":height": u32::from(block_height),
        ":hash": &block_hash.0[..],
        ":block_time": block_time,
        ":sapling_commitment_tree_size": sapling_commitment_tree_size,
        ":sapling_output_count": sapling_output_count,
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
    expiry_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let mut stmt_update_expired = conn.prepare_cached(
        "UPDATE sapling_received_notes SET spent = NULL WHERE EXISTS (
            SELECT id_tx FROM transactions
            WHERE id_tx = sapling_received_notes.spent AND block IS NULL AND expiry_height < ?
        )",
    )?;
    stmt_update_expired.execute([u32::from(expiry_height)])?;
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
        ":memo": memo_repr(output.memo())
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

/// Inserts the given entries into the nullifier map.
///
/// Returns an error if the new entries conflict with existing ones. This indicates either
/// corrupted data, or that a reorg has occurred and the caller needs to repair the wallet
/// state with [`truncate_to_height`].
pub(crate) fn insert_nullifier_map<N: AsRef<[u8]>>(
    conn: &rusqlite::Transaction<'_>,
    block_height: BlockHeight,
    spend_pool: ShieldedProtocol,
    new_entries: &[(TxId, u16, Vec<N>)],
) -> Result<(), SqliteClientError> {
    let mut stmt_select_tx_locators = conn.prepare_cached(
        "SELECT block_height, tx_index, txid
        FROM tx_locator_map
        WHERE (block_height = :block_height AND tx_index = :tx_index) OR txid = :txid",
    )?;
    let mut stmt_insert_tx_locator = conn.prepare_cached(
        "INSERT INTO tx_locator_map
        (block_height, tx_index, txid)
        VALUES (:block_height, :tx_index, :txid)",
    )?;
    let mut stmt_insert_nullifier_mapping = conn.prepare_cached(
        "INSERT INTO nullifier_map
        (spend_pool, nf, block_height, tx_index)
        VALUES (:spend_pool, :nf, :block_height, :tx_index)
        ON CONFLICT (spend_pool, nf) DO UPDATE
        SET block_height = :block_height,
            tx_index = :tx_index",
    )?;

    for (txid, tx_index, nullifiers) in new_entries {
        let tx_args = named_params![
            ":block_height": u32::from(block_height),
            ":tx_index": tx_index,
            ":txid": txid.as_ref(),
        ];

        // We cannot use an upsert here, because we use the tx locator as the foreign key
        // in `nullifier_map` instead of `txid` for database size efficiency. If an insert
        // into `tx_locator_map` were to conflict, we would need the resulting update to
        // cascade into `nullifier_map` as either:
        // - an update (if a transaction moved within a block), or
        // - a deletion (if the locator now points to a different transaction).
        //
        // `ON UPDATE` has `CASCADE` to always update, but has no deletion option. So we
        // instead set `ON UPDATE RESTRICT` on the foreign key relation, and require the
        // caller to manually rewind the database in this situation.
        let locator = stmt_select_tx_locators
            .query_map(tx_args, |row| {
                Ok((
                    BlockHeight::from_u32(row.get(0)?),
                    row.get::<_, u16>(1)?,
                    TxId::from_bytes(row.get(2)?),
                ))
            })?
            .fold(Ok(None), |acc: Result<_, SqliteClientError>, row| {
                match (acc?, row?) {
                    (None, rhs) => Ok(Some(Some(rhs))),
                    // If there was more than one row, then due to the uniqueness
                    // constraints on the `tx_locator_map` table, all of the rows conflict
                    // with the locator being inserted.
                    (Some(_), _) => Ok(Some(None)),
                }
            })?;

        match locator {
            // If the locator in the table matches the one being inserted, do nothing.
            Some(Some(loc)) if loc == (block_height, *tx_index, *txid) => (),
            // If the locator being inserted would conflict, report it.
            Some(_) => Err(SqliteClientError::DbError(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                Some("UNIQUE constraint failed: tx_locator_map.block_height, tx_locator_map.tx_index".into()),
            )))?,
            // If the locator doesn't exist, insert it.
            None => stmt_insert_tx_locator.execute(tx_args).map(|_| ())?,
        }

        for nf in nullifiers {
            // Here it is okay to use an upsert, because per above we've confirmed that
            // the locator points to the same transaction.
            let nf_args = named_params![
                ":spend_pool": pool_code(PoolType::Shielded(spend_pool)),
                ":nf": nf.as_ref(),
                ":block_height": u32::from(block_height),
                ":tx_index": tx_index,
            ];
            stmt_insert_nullifier_mapping.execute(nf_args)?;
        }
    }

    Ok(())
}

/// Returns the row of the `transactions` table corresponding to the transaction in which
/// this nullifier is revealed, if any.
pub(crate) fn query_nullifier_map<N: AsRef<[u8]>>(
    conn: &rusqlite::Transaction<'_>,
    spend_pool: ShieldedProtocol,
    nf: &N,
) -> Result<Option<i64>, SqliteClientError> {
    let mut stmt_select_locator = conn.prepare_cached(
        "SELECT block_height, tx_index, txid
        FROM nullifier_map
        LEFT JOIN tx_locator_map USING (block_height, tx_index)
        WHERE spend_pool = :spend_pool AND nf = :nf",
    )?;

    let sql_args = named_params![
        ":spend_pool": pool_code(PoolType::Shielded(spend_pool)),
        ":nf": nf.as_ref(),
    ];

    // Find the locator corresponding to this nullifier, if any.
    let locator = stmt_select_locator
        .query_row(sql_args, |row| {
            Ok((
                BlockHeight::from_u32(row.get(0)?),
                row.get(1)?,
                TxId::from_bytes(row.get(2)?),
            ))
        })
        .optional()?;
    let (height, index, txid) = match locator {
        Some(res) => res,
        None => return Ok(None),
    };

    // Find or create a corresponding row in the `transactions` table. Usually a row will
    // have been created during the same scan that the locator was added to the nullifier
    // map, but it would not happen if the transaction in question spent the note with no
    // change or explicit in-wallet recipient.
    put_tx_meta(
        conn,
        &WalletTx::<N> {
            txid,
            index,
            sapling_spends: vec![],
            sapling_outputs: vec![],
        },
        height,
    )
    .map(Some)
}

/// Deletes from the nullifier map any entries with a locator referencing a block height
/// lower than the pruning height.
pub(crate) fn prune_nullifier_map(
    conn: &rusqlite::Transaction<'_>,
    block_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let mut stmt_delete_locators = conn.prepare_cached(
        "DELETE FROM tx_locator_map
        WHERE block_height < :block_height",
    )?;

    stmt_delete_locators.execute(named_params![":block_height": u32::from(block_height)])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use zcash_client_backend::data_api::{AccountBirthday, WalletRead};

    use crate::{testing::TestBuilder, AccountId};

    #[cfg(feature = "transparent-inputs")]
    use {
        secrecy::Secret,
        zcash_client_backend::{
            data_api::WalletWrite, encoding::AddressCodec, wallet::WalletTransparentOutput,
        },
        zcash_primitives::{
            consensus::BlockHeight,
            transaction::components::{Amount, OutPoint, TxOut},
        },
    };

    #[test]
    fn empty_database_has_no_balance() {
        let st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        // The account should have no summary information
        assert_eq!(st.get_wallet_summary(0), None);

        // We can't get an anchor height, as we have not scanned any blocks.
        assert_eq!(
            st.wallet()
                .get_target_and_anchor_heights(NonZeroU32::new(10).unwrap())
                .unwrap(),
            None
        );

        // The default address is set for the test account
        assert_matches!(
            st.wallet().get_current_address(AccountId::from(0)),
            Ok(Some(_))
        );

        // No default address is set for an un-initialized account
        assert_matches!(
            st.wallet().get_current_address(AccountId::from(1)),
            Ok(None)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn put_received_transparent_utxo() {
        use crate::testing::TestBuilder;

        let mut st = TestBuilder::new().build();

        // Add an account to the wallet
        let seed = Secret::new([0u8; 32].to_vec());
        let birthday = AccountBirthday::from_sapling_activation(&st.network());
        let (account_id, _usk) = st.wallet_mut().create_account(&seed, birthday).unwrap();
        let uaddr = st
            .wallet()
            .get_current_address(account_id)
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        let bal_absent = st
            .wallet()
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

        let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
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
        let res1 = st.wallet_mut().put_received_transparent_utxo(&utxo2);
        assert_matches!(res1, Ok(id) if id == res0.unwrap());

        assert_matches!(
            st.wallet().get_unspent_transparent_outputs(
                taddr,
                BlockHeight::from_u32(12345),
                &[]
            ),
            Ok(utxos) if utxos.is_empty()
        );

        assert_matches!(
            st.wallet().get_unspent_transparent_outputs(
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
            st.wallet().get_transparent_balances(account_id, BlockHeight::from_u32(34567)),
            Ok(h) if h.get(taddr) == Amount::from_u64(100000).ok().as_ref()
        );

        // Artificially delete the address from the addresses table so that
        // we can ensure the update fails if the join doesn't work.
        st.wallet()
            .conn
            .execute(
                "DELETE FROM addresses WHERE cached_transparent_receiver_address = ?",
                [Some(taddr.encode(&st.wallet().params))],
            )
            .unwrap();

        let res2 = st.wallet_mut().put_received_transparent_utxo(&utxo2);
        assert_matches!(res2, Err(_));
    }
}
