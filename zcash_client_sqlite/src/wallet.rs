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
//! - `from_account_id` for sent outputs, the account from which the value was sent.
//! - `to_account_id` in the case that the output was received by an account in the wallet, the
//!   identifier for the account receiving the funds.
//! - `to_address` the address to which an output was sent, or the address at which value was
//!   received in the case of received transparent funds.
//! - `value` the value of the output. This is always a positive number, for both sent and received
//!   outputs.
//! - `is_change` a boolean flag indicating whether this is a change output belonging to the
//!   wallet.
//! - `memo` the shielded memo associated with the output, if any.

use incrementalmerkletree::Retention;
use rusqlite::{self, named_params, params, OptionalExtension};
use shardtree::{error::ShardTreeError, store::ShardStore, ShardTree};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{self, Cursor};
use std::num::NonZeroU32;
use std::ops::RangeInclusive;
use tracing::debug;
use zcash_address::unified::{Encoding, Ivk, Uivk};
use zcash_keys::keys::{AddressGenerationError, HdSeedFingerprint, UnifiedAddressRequest};

use zcash_client_backend::{
    address::{Address, UnifiedAddress},
    data_api::{
        scanning::{ScanPriority, ScanRange},
        AccountBalance, AccountBirthday, BlockMetadata, Ratio, SentTransactionOutput,
        WalletSummary, SAPLING_SHARD_HEIGHT,
    },
    encoding::AddressCodec,
    keys::UnifiedFullViewingKey,
    wallet::{Note, NoteId, Recipient, WalletTx},
    PoolType, ShieldedProtocol,
};
use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, BranchId, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
    merkle_tree::read_commitment_tree,
    transaction::{
        components::{amount::NonNegativeAmount, Amount},
        Transaction, TransactionData, TxId,
    },
    zip32::{self, DiversifierIndex, Scope},
};

use crate::{
    error::SqliteClientError,
    wallet::commitment_tree::{get_max_checkpointed_height, SqliteShardStore},
    AccountId, SqlTransaction, WalletCommitmentTrees, WalletDb, DEFAULT_UA_REQUEST, PRUNING_DEPTH,
    SAPLING_TABLES_PREFIX,
};

use self::scanning::{parse_priority_code, priority_code, replace_queue_entries};

#[cfg(feature = "transparent-inputs")]
use {
    crate::UtxoId,
    rusqlite::Row,
    std::collections::BTreeSet,
    zcash_client_backend::wallet::{TransparentAddressMetadata, WalletTransparentOutput},
    zcash_primitives::{
        legacy::{
            keys::{IncomingViewingKey, NonHardenedChildIndex},
            Script, TransparentAddress,
        },
        transaction::components::{OutPoint, TxOut},
    },
};

pub mod commitment_tree;
pub mod init;
pub(crate) mod sapling;
pub(crate) mod scanning;

pub(crate) const BLOCK_SAPLING_FRONTIER_ABSENT: &[u8] = &[0x0];

/// This tracks the allowed values of the `account_type` column of the `accounts` table
/// and should not be made public.
enum AccountType {
    Zip32,
    Imported,
}

impl TryFrom<u32> for AccountType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AccountType::Zip32),
            1 => Ok(AccountType::Imported),
            _ => Err(()),
        }
    }
}

impl From<AccountType> for u32 {
    fn from(value: AccountType) -> Self {
        match value {
            AccountType::Zip32 => 0,
            AccountType::Imported => 1,
        }
    }
}

/// Describes the key inputs and UFVK for an account that was derived from a ZIP-32 HD seed and account index.
#[derive(Debug, Clone)]
pub(crate) struct HdSeedAccount(
    HdSeedFingerprint,
    zip32::AccountId,
    Box<UnifiedFullViewingKey>,
);

impl HdSeedAccount {
    pub fn new(
        hd_seed_fingerprint: HdSeedFingerprint,
        account_index: zip32::AccountId,
        ufvk: UnifiedFullViewingKey,
    ) -> Self {
        Self(hd_seed_fingerprint, account_index, Box::new(ufvk))
    }

    /// Returns the HD seed fingerprint for this account.
    pub fn hd_seed_fingerprint(&self) -> &HdSeedFingerprint {
        &self.0
    }

    /// Returns the ZIP-32 account index for this account.
    pub fn account_index(&self) -> zip32::AccountId {
        self.1
    }

    /// Returns the Unified Full Viewing Key for this account.
    pub fn ufvk(&self) -> &UnifiedFullViewingKey {
        &self.2
    }
}

/// Represents an arbitrary account for which the seed and ZIP-32 account ID are not known
/// and may not have been involved in creating this account.
#[derive(Debug, Clone)]
pub(crate) enum ImportedAccount {
    /// An account that was imported via its full viewing key.
    Full(Box<UnifiedFullViewingKey>),
    /// An account that was imported via its incoming viewing key.
    Incoming(Uivk),
}

/// Describes an account in terms of its UVK or ZIP-32 origins.
#[derive(Debug, Clone)]
pub(crate) enum Account {
    /// Inputs for a ZIP-32 HD account.
    Zip32(HdSeedAccount),
    /// Inputs for an imported account.
    Imported(ImportedAccount),
}

impl Account {
    /// Returns the default Unified Address for the account,
    /// along with the diversifier index that generated it.
    ///
    /// The diversifier index may be non-zero if the Unified Address includes a Sapling
    /// receiver, and there was no valid Sapling receiver at diversifier index zero.
    pub fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        match self {
            Account::Zip32(HdSeedAccount(_, _, ufvk)) => ufvk.default_address(request),
            Account::Imported(ImportedAccount::Full(ufvk)) => ufvk.default_address(request),
            Account::Imported(ImportedAccount::Incoming(_uivk)) => todo!(),
        }
    }
}

pub(crate) fn pool_code(pool_type: PoolType) -> i64 {
    // These constants are *incidentally* shared with the typecodes
    // for unified addresses, but this is exclusively an internal
    // implementation detail.
    match pool_type {
        PoolType::Transparent => 0i64,
        PoolType::Shielded(ShieldedProtocol::Sapling) => 2i64,
        PoolType::Shielded(ShieldedProtocol::Orchard) => 3i64,
    }
}

pub(crate) fn scope_code(scope: Scope) -> i64 {
    match scope {
        Scope::External => 0i64,
        Scope::Internal => 1i64,
    }
}

pub(crate) fn parse_scope(code: i64) -> Option<Scope> {
    match code {
        0i64 => Some(Scope::External),
        1i64 => Some(Scope::Internal),
        _ => None,
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

// Returns the highest used account index for a given seed.
pub(crate) fn max_zip32_account_index(
    conn: &rusqlite::Connection,
    seed_id: &HdSeedFingerprint,
) -> Result<Option<zip32::AccountId>, SqliteClientError> {
    conn.query_row_and_then(
        "SELECT MAX(hd_account_index) FROM accounts WHERE hd_seed_fingerprint = :hd_seed",
        [seed_id.as_bytes()],
        |row| {
            let account_id: Option<u32> = row.get(0)?;
            account_id
                .map(zip32::AccountId::try_from)
                .transpose()
                .map_err(|_| SqliteClientError::AccountIdOutOfRange)
        },
    )
}

struct AccountSqlValues<'a> {
    account_type: u32,
    hd_seed_fingerprint: Option<&'a [u8]>,
    hd_account_index: Option<u32>,
    ufvk: Option<&'a UnifiedFullViewingKey>,
    uivk: String,
}

/// Returns (account_type, hd_seed_fingerprint, hd_account_index, ufvk, uivk) for a given account.
fn get_sql_values_for_account_parameters<'a, P: consensus::Parameters>(
    account: &'a Account,
    params: &P,
) -> Result<AccountSqlValues<'a>, SqliteClientError> {
    Ok(match account {
        Account::Zip32(hdaccount) => AccountSqlValues {
            account_type: AccountType::Zip32.into(),
            hd_seed_fingerprint: Some(hdaccount.hd_seed_fingerprint().as_bytes()),
            hd_account_index: Some(hdaccount.account_index().into()),
            ufvk: Some(hdaccount.ufvk()),
            uivk: ufvk_to_uivk(hdaccount.ufvk(), params)?,
        },
        Account::Imported(ImportedAccount::Full(ufvk)) => AccountSqlValues {
            account_type: AccountType::Imported.into(),
            hd_seed_fingerprint: None,
            hd_account_index: None,
            ufvk: Some(ufvk),
            uivk: ufvk_to_uivk(ufvk, params)?,
        },
        Account::Imported(ImportedAccount::Incoming(uivk)) => AccountSqlValues {
            account_type: AccountType::Imported.into(),
            hd_seed_fingerprint: None,
            hd_account_index: None,
            ufvk: None,
            uivk: uivk.encode(&params.network_type()),
        },
    })
}

pub(crate) fn ufvk_to_uivk<P: consensus::Parameters>(
    ufvk: &UnifiedFullViewingKey,
    params: &P,
) -> Result<String, SqliteClientError> {
    let mut ivks: Vec<Ivk> = Vec::new();
    if let Some(orchard) = ufvk.orchard() {
        ivks.push(Ivk::Orchard(orchard.to_ivk(Scope::External).to_bytes()));
    }
    if let Some(sapling) = ufvk.sapling() {
        let ivk = sapling.to_external_ivk();
        ivks.push(Ivk::Sapling(ivk.to_bytes()));
    }
    #[cfg(feature = "transparent-inputs")]
    if let Some(tfvk) = ufvk.transparent() {
        let tivk = tfvk.derive_external_ivk()?;
        ivks.push(Ivk::P2pkh(tivk.serialize().try_into().map_err(|_| {
            SqliteClientError::BadAccountData("Unable to serialize transparent IVK.".to_string())
        })?));
    }

    let uivk = zcash_address::unified::Uivk::try_from_items(ivks)
        .map_err(|e| SqliteClientError::BadAccountData(format!("Unable to derive UIVK: {}", e)))?;
    Ok(uivk.encode(&params.network_type()))
}

pub(crate) fn add_account<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account: Account,
    birthday: AccountBirthday,
) -> Result<AccountId, SqliteClientError> {
    let args = get_sql_values_for_account_parameters(&account, params)?;

    let orchard_item = args
        .ufvk
        .and_then(|ufvk| ufvk.orchard().map(|k| k.to_bytes()));
    let sapling_item = args
        .ufvk
        .and_then(|ufvk| ufvk.sapling().map(|k| k.to_bytes()));
    #[cfg(feature = "transparent-inputs")]
    let transparent_item = args
        .ufvk
        .and_then(|ufvk| ufvk.transparent().map(|k| k.serialize()));
    #[cfg(not(feature = "transparent-inputs"))]
    let transparent_item: Option<Vec<u8>> = None;

    let account_id: AccountId = conn.query_row(
        r#"
        INSERT INTO accounts (
            account_type, hd_seed_fingerprint, hd_account_index,
            ufvk, uivk,
            orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
            birthday_height, recover_until_height
        )
        VALUES (
            :account_type, :hd_seed_fingerprint, :hd_account_index,
            :ufvk, :uivk,
            :orchard_fvk_item_cache, :sapling_fvk_item_cache, :p2pkh_fvk_item_cache,
            :birthday_height, :recover_until_height
        )
        RETURNING id;
        "#,
        named_params![
            ":account_type": args.account_type,
            ":hd_seed_fingerprint": args.hd_seed_fingerprint,
            ":hd_account_index": args.hd_account_index,
            ":ufvk": args.ufvk.map(|ufvk| ufvk.encode(params)),
            ":uivk": args.uivk,
            ":orchard_fvk_item_cache": orchard_item,
            ":sapling_fvk_item_cache": sapling_item,
            ":p2pkh_fvk_item_cache": transparent_item,
            ":birthday_height": u32::from(birthday.height()),
            ":recover_until_height": birthday.recover_until().map(u32::from)
        ],
        |row| Ok(AccountId(row.get(0)?)),
    )?;

    // If a birthday frontier is available, insert it into the note commitment tree. If the
    // birthday frontier is the empty frontier, we don't need to do anything.
    if let Some(frontier) = birthday.sapling_frontier().value() {
        debug!("Inserting frontier into ShardTree: {:?}", frontier);
        let shard_store =
            SqliteShardStore::<_, ::sapling::Node, SAPLING_SHARD_HEIGHT>::from_connection(
                conn,
                SAPLING_TABLES_PREFIX,
            )?;
        let mut shard_tree: ShardTree<
            _,
            { ::sapling::NOTE_COMMITMENT_TREE_DEPTH },
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
    if let Some(t) = scan_queue_extrema(conn)?.map(|range| *range.end()) {
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
    let (address, d_idx) = account.default_address(DEFAULT_UA_REQUEST)?;
    insert_address(conn, params, account_id, d_idx, &address)?;

    Ok(account_id)
}

pub(crate) fn get_current_address<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountId,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqliteClientError> {
    // This returns the most recently generated address.
    let addr: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT address, diversifier_index_be
            FROM addresses WHERE account_id = :account_id
            ORDER BY diversifier_index_be DESC
            LIMIT 1",
            named_params![":account_id": account_id.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    addr.map(|(addr_str, di_vec)| {
        let mut di_be: [u8; 11] = di_vec.try_into().map_err(|_| {
            SqliteClientError::CorruptedData("Diversifier index is not an 11-byte value".to_owned())
        })?;
        di_be.reverse();

        Address::decode(params, &addr_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                Address::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    addr_str,
                ))),
            })
            .map(|addr| (addr, DiversifierIndex::from(di_be)))
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
    diversifier_index: DiversifierIndex,
    address: &UnifiedAddress,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO addresses (
            account_id,
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
    let mut di_be = *diversifier_index.as_bytes();
    di_be.reverse();
    stmt.execute(named_params![
        ":account": account.0,
        ":diversifier_index_be": &di_be[..],
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
) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, SqliteClientError> {
    let mut ret: HashMap<TransparentAddress, Option<TransparentAddressMetadata>> = HashMap::new();

    // Get all UAs derived
    let mut ua_query = conn.prepare(
        "SELECT address, diversifier_index_be FROM addresses WHERE account_id = :account",
    )?;
    let mut rows = ua_query.query(named_params![":account": account.0])?;

    while let Some(row) = rows.next()? {
        let ua_str: String = row.get(0)?;
        let di_vec: Vec<u8> = row.get(1)?;
        let mut di: [u8; 11] = di_vec.try_into().map_err(|_| {
            SqliteClientError::CorruptedData(
                "Diverisifier index is not an 11-byte value".to_owned(),
            )
        })?;
        di.reverse(); // BE -> LE conversion

        let ua = Address::decode(params, &ua_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                Address::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    ua_str,
                ))),
            })?;

        if let Some(taddr) = ua.transparent() {
            let index = NonHardenedChildIndex::from_index(
                DiversifierIndex::from(di).try_into().map_err(|_| {
                    SqliteClientError::CorruptedData(
                        "Unable to get diversifier for transparent address.".to_string(),
                    )
                })?,
            )
            .ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "Unexpected hardened index for transparent address.".to_string(),
                )
            })?;

            ret.insert(
                *taddr,
                Some(TransparentAddressMetadata::new(
                    Scope::External.into(),
                    index,
                )),
            );
        }
    }

    if let Some((taddr, child_index)) = get_legacy_transparent_address(params, conn, account)? {
        ret.insert(
            taddr,
            Some(TransparentAddressMetadata::new(
                Scope::External.into(),
                child_index,
            )),
        );
    }

    Ok(ret)
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    conn: &rusqlite::Connection,
    account_id: AccountId,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    use zcash_address::unified::Container;
    use zcash_primitives::legacy::keys::ExternalIvk;

    // Get the UIVK for the account.
    let uivk_str: Option<String> = conn
        .query_row(
            "SELECT uivk FROM accounts WHERE id = :account",
            [account_id.0],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(uivk_str) = uivk_str {
        let (network, uivk) = Uivk::decode(&uivk_str)
            .map_err(|e| SqliteClientError::CorruptedData(format!("Unable to parse UIVK: {e}")))?;
        if params.network_type() != network {
            return Err(SqliteClientError::CorruptedData(
                "Network type mismatch".to_owned(),
            ));
        }

        // Derive the default transparent address (if it wasn't already part of a derived UA).
        for item in uivk.items() {
            if let Ivk::P2pkh(tivk_bytes) = item {
                let tivk = ExternalIvk::deserialize(&tivk_bytes)?;
                return Ok(Some(tivk.default_address()));
            }
        }
    }

    Ok(None)
}

/// Returns the [`UnifiedFullViewingKey`]s for the wallet.
pub(crate) fn get_unified_full_viewing_keys<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, SqliteClientError> {
    // Fetch the UnifiedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts = conn.prepare("SELECT id, ufvk FROM accounts")?;

    let rows = stmt_fetch_accounts.query_map([], |row| {
        let acct: u32 = row.get(0)?;
        let ufvk_str: Option<String> = row.get(1)?;
        if let Some(ufvk_str) = ufvk_str {
            let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
                .map_err(SqliteClientError::CorruptedData);
            Ok(Some((AccountId(acct), ufvk)))
        } else {
            Ok(None)
        }
    })?;

    let mut res: HashMap<AccountId, UnifiedFullViewingKey> = HashMap::new();
    for row in rows {
        if let Some((account_id, ufvkr)) = row? {
            res.insert(account_id, ufvkr?);
        }
    }

    Ok(res)
}

/// Returns the account id corresponding to a given [`UnifiedFullViewingKey`],
/// if any.
pub(crate) fn get_account_for_ufvk(
    conn: &rusqlite::Connection,
    ufvk: &UnifiedFullViewingKey,
) -> Result<Option<AccountId>, SqliteClientError> {
    #[cfg(feature = "transparent-inputs")]
    let transparent_item = ufvk.transparent().map(|k| k.serialize());
    #[cfg(not(feature = "transparent-inputs"))]
    let transparent_item: Option<Vec<u8>> = None;

    let mut stmt = conn.prepare(
        "SELECT id
        FROM accounts
        WHERE orchard_fvk_item_cache = :orchard_fvk_item_cache
           OR sapling_fvk_item_cache = :sapling_fvk_item_cache
           OR p2pkh_fvk_item_cache = :p2pkh_fvk_item_cache",
    )?;

    let accounts = stmt
        .query_and_then::<_, rusqlite::Error, _, _>(
            named_params![
                ":orchard_fvk_item_cache": ufvk.orchard().map(|k| k.to_bytes()),
                ":sapling_fvk_item_cache": ufvk.sapling().map(|k| k.to_bytes()),
                ":p2pkh_fvk_item_cache": transparent_item,
            ],
            |row| row.get::<_, u32>(0).map(AccountId),
        )?
        .collect::<Result<Vec<_>, _>>()?;

    if accounts.len() > 1 {
        Err(SqliteClientError::CorruptedData(
            "Mutiple account records correspond to a single UFVK".to_owned(),
        ))
    } else {
        Ok(accounts.first().copied())
    }
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

#[derive(Debug)]
pub(crate) struct SubtreeScanProgress;

impl ScanProgress for SubtreeScanProgress {
    #[tracing::instrument(skip(conn))]
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
#[tracing::instrument(skip(tx, params, progress))]
pub(crate) fn get_wallet_summary<P: consensus::Parameters>(
    tx: &rusqlite::Transaction,
    params: &P,
    min_confirmations: u32,
    progress: &impl ScanProgress,
) -> Result<Option<WalletSummary<AccountId>>, SqliteClientError> {
    let chain_tip_height = match scan_queue_extrema(tx)? {
        Some(range) => *range.end(),
        None => {
            return Ok(None);
        }
    };

    let birthday_height =
        wallet_birthday(tx)?.expect("If a scan range exists, we know the wallet birthday.");

    let fully_scanned_height =
        block_fully_scanned(tx, params)?.map_or(birthday_height - 1, |m| m.block_height());
    let summary_height = (chain_tip_height + 1).saturating_sub(std::cmp::max(min_confirmations, 1));

    let sapling_scan_progress = progress.sapling_scan_progress(
        tx,
        birthday_height,
        fully_scanned_height,
        chain_tip_height,
    )?;

    // If the shard containing the summary height contains any unscanned ranges that start below or
    // including that height, none of our balance is currently spendable.
    #[tracing::instrument(skip_all)]
    fn is_any_spendable(
        conn: &rusqlite::Connection,
        summary_height: BlockHeight,
    ) -> Result<bool, SqliteClientError> {
        conn.query_row(
            "SELECT NOT EXISTS(
                 SELECT 1 FROM v_sapling_shard_unscanned_ranges
                 WHERE :summary_height
                    BETWEEN subtree_start_height
                    AND IFNULL(subtree_end_height, :summary_height)
                 AND block_range_start <= :summary_height
             )",
            named_params![":summary_height": u32::from(summary_height)],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|e| e.into())
    }
    let any_spendable = is_any_spendable(tx, summary_height)?;

    let mut stmt_accounts = tx.prepare_cached("SELECT id FROM accounts")?;
    let mut account_balances = stmt_accounts
        .query([])?
        .and_then(|row| {
            Ok::<_, SqliteClientError>((AccountId(row.get::<_, u32>(0)?), AccountBalance::ZERO))
        })
        .collect::<Result<HashMap<AccountId, AccountBalance>, _>>()?;

    let sapling_trace = tracing::info_span!("stmt_select_notes").entered();
    let mut stmt_select_notes = tx.prepare_cached(
        "SELECT n.account_id, n.value, n.is_change, scan_state.max_priority, t.block
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
        let account = AccountId(row.get::<_, u32>(0)?);

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

        if let Some(balances) = account_balances.get_mut(&account) {
            balances.with_sapling_balance_mut::<_, SqliteClientError>(|bal| {
                bal.add_spendable_value(spendable_value)?;
                bal.add_pending_change_value(change_pending_confirmation)?;
                bal.add_pending_spendable_value(value_pending_spendability)?;
                Ok(())
            })?;
        }
    }
    drop(sapling_trace);

    #[cfg(feature = "transparent-inputs")]
    {
        let transparent_trace = tracing::info_span!("stmt_transparent_balances").entered();
        let zero_conf_height = (chain_tip_height + 1).saturating_sub(min_confirmations);
        let stable_height = chain_tip_height.saturating_sub(PRUNING_DEPTH);

        let mut stmt_transparent_balances = tx.prepare(
            "SELECT u.received_by_account_id, SUM(u.value_zat)
             FROM utxos u
             LEFT OUTER JOIN transactions tx
             ON tx.id_tx = u.spent_in_tx
             WHERE u.height <= :max_height
             AND (u.spent_in_tx IS NULL OR (tx.block IS NULL AND tx.expiry_height <= :stable_height))
             GROUP BY u.received_by_account_id",
        )?;
        let mut rows = stmt_transparent_balances.query(named_params![
            ":max_height": u32::from(zero_conf_height),
            ":stable_height": u32::from(stable_height)
        ])?;

        while let Some(row) = rows.next()? {
            let account = AccountId(row.get(0)?);
            let raw_value = row.get(1)?;
            let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
                SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
            })?;

            if let Some(balances) = account_balances.get_mut(&account) {
                balances.add_unshielded_value(value)?;
            }
        }
        drop(transparent_trace);
    }

    let next_sapling_subtree_index = {
        let shard_store =
            SqliteShardStore::<_, ::sapling::Node, SAPLING_SHARD_HEIGHT>::from_connection(
                tx,
                SAPLING_TABLES_PREFIX,
            )?;

        // The last shard will be incomplete, and we want the next range to overlap with
        // the last complete shard, so return the index of the second-to-last shard root.
        shard_store
            .get_shard_roots()
            .map_err(ShardTreeError::Storage)?
            .iter()
            .rev()
            .nth(1)
            .map(|addr| addr.index())
            .unwrap_or(0)
    };

    let summary = WalletSummary::new(
        account_balances,
        chain_tip_height,
        fully_scanned_height,
        sapling_scan_progress,
        next_sapling_subtree_index,
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
        _ => {
            return Err(SqliteClientError::UnsupportedPoolType(PoolType::Shielded(
                note_id.protocol(),
            )))
        }
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
        named_params![":account_id": account.0],
        |row| row.get::<_, u32>(0).map(BlockHeight::from),
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|opt| opt.ok_or(SqliteClientError::AccountUnknown))
}

/// Returns the minimum and maximum heights for blocks stored in the wallet database.
pub(crate) fn block_height_extrema(
    conn: &rusqlite::Connection,
) -> Result<Option<RangeInclusive<BlockHeight>>, rusqlite::Error> {
    conn.query_row("SELECT MIN(height), MAX(height) FROM blocks", [], |row| {
        let min_height: Option<u32> = row.get(0)?;
        let max_height: Option<u32> = row.get(1)?;
        Ok(min_height
            .zip(max_height)
            .map(|(min, max)| RangeInclusive::new(min.into(), max.into())))
    })
}

pub(crate) fn get_account<C: Borrow<rusqlite::Connection>, P: Parameters>(
    db: &WalletDb<C, P>,
    account_id: AccountId,
) -> Result<Option<Account>, SqliteClientError> {
    let mut sql = db.conn.borrow().prepare_cached(
        r#"
        SELECT account_type, ufvk, uivk, hd_seed_fingerprint, hd_account_index
        FROM accounts
        WHERE id = :account_id
    "#,
    )?;

    let mut result = sql.query(params![account_id.0])?;
    let row = result.next()?;
    match row {
        Some(row) => {
            let account_type: AccountType =
                row.get::<_, u32>("account_type")?.try_into().map_err(|_| {
                    SqliteClientError::CorruptedData("Unrecognized account_type".to_string())
                })?;
            let ufvk_str: Option<String> = row.get("ufvk")?;
            let ufvk = if let Some(ufvk_str) = ufvk_str {
                Some(
                    UnifiedFullViewingKey::decode(&db.params, &ufvk_str[..])
                        .map_err(SqliteClientError::BadAccountData)?,
                )
            } else {
                None
            };
            let uivk_str: String = row.get("uivk")?;
            let (network, uivk) = Uivk::decode(&uivk_str).map_err(|e| {
                SqliteClientError::CorruptedData(format!("Failure to decode UIVK: {e}"))
            })?;
            if network != db.params.network_type() {
                return Err(SqliteClientError::CorruptedData(
                    "UIVK network type does not match wallet network type".to_string(),
                ));
            }

            match account_type {
                AccountType::Zip32 => Ok(Some(Account::Zip32(HdSeedAccount::new(
                    HdSeedFingerprint::from_bytes(row.get("hd_seed_fingerprint")?),
                    zip32::AccountId::try_from(row.get::<_, u32>("hd_account_index")?).map_err(
                        |_| {
                            SqliteClientError::CorruptedData(
                                "ZIP-32 account ID from db is out of range.".to_string(),
                            )
                        },
                    )?,
                    ufvk.ok_or_else(|| {
                        SqliteClientError::CorruptedData(
                            "ZIP-32 account is missing a full viewing key".to_string(),
                        )
                    })?,
                )))),
                AccountType::Imported => Ok(Some(Account::Imported(if let Some(ufvk) = ufvk {
                    ImportedAccount::Full(Box::new(ufvk))
                } else {
                    ImportedAccount::Incoming(uivk)
                }))),
            }
        }
        None => Ok(None),
    }
}

/// Returns the minimum and maximum heights of blocks in the chain which may be scanned.
pub(crate) fn scan_queue_extrema(
    conn: &rusqlite::Connection,
) -> Result<Option<RangeInclusive<BlockHeight>>, rusqlite::Error> {
    conn.query_row(
        "SELECT MIN(block_range_start), MAX(block_range_end) FROM scan_queue",
        [],
        |row| {
            let min_height: Option<u32> = row.get(0)?;
            let max_height: Option<u32> = row.get(1)?;

            // Scan ranges are end-exclusive, so we subtract 1 from `max_height` to obtain the
            // height of the last known chain tip;
            Ok(min_height
                .zip(max_height.map(|h| h.saturating_sub(1)))
                .map(|(min, max)| RangeInclusive::new(min.into(), max.into())))
        },
    )
}

pub(crate) fn get_target_and_anchor_heights(
    conn: &rusqlite::Connection,
    min_confirmations: NonZeroU32,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    match scan_queue_extrema(conn)?.map(|range| *range.end()) {
        Some(chain_tip_height) => {
            let sapling_anchor_height = get_max_checkpointed_height(
                conn,
                SAPLING_TABLES_PREFIX,
                chain_tip_height,
                min_confirmations,
            )?;

            Ok(sapling_anchor_height.map(|h| (chain_tip_height + 1, h)))
        }
        None => Ok(None),
    }
}

fn parse_block_metadata<P: consensus::Parameters>(
    _params: &P,
    row: (BlockHeight, Vec<u8>, Option<u32>, Vec<u8>, Option<u32>),
) -> Result<BlockMetadata, SqliteClientError> {
    let (block_height, hash_data, sapling_tree_size_opt, sapling_tree, _orchard_tree_size_opt) =
        row;
    let sapling_tree_size = sapling_tree_size_opt.map_or_else(|| {
        if sapling_tree == BLOCK_SAPLING_FRONTIER_ABSENT {
            Err(SqliteClientError::CorruptedData("One of either the Sapling tree size or the legacy Sapling commitment tree must be present.".to_owned()))
        } else {
            // parse the legacy commitment tree data
            read_commitment_tree::<
                ::sapling::Node,
                _,
                { ::sapling::NOTE_COMMITMENT_TREE_DEPTH },
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
        Some(sapling_tree_size),
        #[cfg(feature = "orchard")]
        if _params
            .activation_height(NetworkUpgrade::Nu5)
            .iter()
            .any(|nu5_activation| &block_height >= nu5_activation)
        {
            _orchard_tree_size_opt
        } else {
            Some(0)
        },
    ))
}

#[tracing::instrument(skip(conn, params))]
pub(crate) fn block_metadata<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    block_height: BlockHeight,
) -> Result<Option<BlockMetadata>, SqliteClientError> {
    conn.query_row(
        "SELECT height, hash, sapling_commitment_tree_size, sapling_tree, orchard_commitment_tree_size
        FROM blocks
        WHERE height = :block_height",
        named_params![":block_height": u32::from(block_height)],
        |row| {
            let height: u32 = row.get(0)?;
            let block_hash: Vec<u8> = row.get(1)?;
            let sapling_tree_size: Option<u32> = row.get(2)?;
            let sapling_tree: Vec<u8> = row.get(3)?;
            let orchard_tree_size: Option<u32> = row.get(4)?;
            Ok((
                BlockHeight::from(height),
                block_hash,
                sapling_tree_size,
                sapling_tree,
                orchard_tree_size,
            ))
        },
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|meta_row| meta_row.map(|r| parse_block_metadata(params, r)).transpose())
}

#[tracing::instrument(skip_all)]
pub(crate) fn block_fully_scanned<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<Option<BlockMetadata>, SqliteClientError> {
    if let Some(birthday_height) = wallet_birthday(conn)? {
        // We assume that the only way we get a contiguous range of block heights in the `blocks` table
        // starting with the birthday block, is if all scanning operations have been performed on those
        // blocks. This holds because the `blocks` table is only altered by `WalletDb::put_blocks` via
        // `put_block`, and the effective combination of intra-range linear scanning and the nullifier
        // map ensures that we discover all wallet-related information within the contiguous range.
        //
        // We also assume that every contiguous range of block heights in the `blocks` table has a
        // single matching entry in the `scan_queue` table with priority "Scanned". This requires no
        // bugs in the scan queue update logic, which we have had before. However, a bug here would
        // mean that we return a more conservative fully-scanned height, which likely just causes a
        // performance regression.
        //
        // The fully-scanned height is therefore the last height that falls within the first range in
        // the scan queue with priority "Scanned".
        // SQL query problems.
        let fully_scanned_height = match conn
            .query_row(
                "SELECT block_range_start, block_range_end
                FROM scan_queue
                WHERE priority = :priority
                ORDER BY block_range_start ASC
                LIMIT 1",
                named_params![":priority": priority_code(&ScanPriority::Scanned)],
                |row| {
                    let block_range_start = BlockHeight::from_u32(row.get(0)?);
                    let block_range_end = BlockHeight::from_u32(row.get(1)?);

                    // If the start of the earliest scanned range is greater than
                    // the birthday height, then there is an unscanned range between
                    // the wallet birthday and that range, so there is no fully
                    // scanned height.
                    Ok(if block_range_start <= birthday_height {
                        // Scan ranges are end-exclusive.
                        Some(block_range_end - 1)
                    } else {
                        None
                    })
                },
            )
            .optional()?
        {
            Some(Some(h)) => h,
            _ => return Ok(None),
        };

        block_metadata(conn, params, fully_scanned_height)
    } else {
        Ok(None)
    }
}

pub(crate) fn block_max_scanned<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<Option<BlockMetadata>, SqliteClientError> {
    conn.query_row(
        "SELECT blocks.height, hash, sapling_commitment_tree_size, sapling_tree, orchard_commitment_tree_size
         FROM blocks
         JOIN (SELECT MAX(height) AS height FROM blocks) blocks_max
         ON blocks.height = blocks_max.height",
        [],
        |row| {
            let height: u32 = row.get(0)?;
            let block_hash: Vec<u8> = row.get(1)?;
            let sapling_tree_size: Option<u32> = row.get(2)?;
            let sapling_tree: Vec<u8> = row.get(3)?;
            let orchard_tree_size: Option<u32> = row.get(4)?;
            Ok((
                BlockHeight::from(height),
                block_hash,
                sapling_tree_size,
                sapling_tree,
                orchard_tree_size
            ))
        },
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|meta_row| meta_row.map(|r| parse_block_metadata(params, r)).transpose())
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

        // Rewind received notes
        conn.execute(
            "DELETE FROM sapling_received_notes
            WHERE id IN (
                SELECT rn.id
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

        // Prioritize the height we just rewound to for verification.
        let query_range = block_height..(block_height + 1);
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

#[cfg(feature = "transparent-inputs")]
fn to_unspent_transparent_output(row: &Row) -> Result<WalletTransparentOutput, SqliteClientError> {
    let txid: Vec<u8> = row.get(0)?;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&txid);

    let index: u32 = row.get(1)?;
    let script_pubkey = Script(row.get(2)?);
    let raw_value: i64 = row.get(3)?;
    let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
        SqliteClientError::CorruptedData(format!("Invalid UTXO value: {}", raw_value))
    })?;
    let height: u32 = row.get(4)?;

    let outpoint = OutPoint::new(txid_bytes, index);
    WalletTransparentOutput::from_parts(
        outpoint,
        TxOut {
            value,
            script_pubkey,
        },
        BlockHeight::from(height),
    )
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Txout script_pubkey value did not correspond to a P2PKH or P2SH address".to_string(),
        )
    })
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_unspent_transparent_output(
    conn: &rusqlite::Connection,
    outpoint: &OutPoint,
) -> Result<Option<WalletTransparentOutput>, SqliteClientError> {
    let mut stmt_select_utxo = conn.prepare_cached(
        "SELECT u.prevout_txid, u.prevout_idx, u.script, u.value_zat, u.height
         FROM utxos u
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = u.spent_in_tx
         WHERE u.prevout_txid = :txid
         AND u.prevout_idx = :output_index
         AND tx.block IS NULL",
    )?;

    let result: Result<Option<WalletTransparentOutput>, SqliteClientError> = stmt_select_utxo
        .query_and_then(
            named_params![
                ":txid": outpoint.hash(),
                ":output_index": outpoint.n()
            ],
            to_unspent_transparent_output,
        )?
        .next()
        .transpose();

    result
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
    let chain_tip_height = scan_queue_extrema(conn)?.map(|range| *range.end());
    let stable_height = chain_tip_height
        .unwrap_or(max_height)
        .saturating_sub(PRUNING_DEPTH);

    let mut stmt_utxos = conn.prepare(
        "SELECT u.prevout_txid, u.prevout_idx, u.script,
                u.value_zat, u.height
         FROM utxos u
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = u.spent_in_tx
         WHERE u.address = :address
         AND u.height <= :max_height
         AND (u.spent_in_tx IS NULL OR (tx.block IS NULL AND tx.expiry_height <= :stable_height))",
    )?;

    let addr_str = address.encode(params);

    let mut utxos = Vec::<WalletTransparentOutput>::new();
    let mut rows = stmt_utxos.query(named_params![
        ":address": addr_str,
        ":max_height": u32::from(max_height),
        ":stable_height": u32::from(stable_height),
    ])?;
    let excluded: BTreeSet<OutPoint> = exclude.iter().cloned().collect();
    while let Some(row) = rows.next()? {
        let output = to_unspent_transparent_output(row)?;
        if excluded.contains(output.outpoint()) {
            continue;
        }

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
) -> Result<HashMap<TransparentAddress, NonNegativeAmount>, SqliteClientError> {
    let chain_tip_height = scan_queue_extrema(conn)?.map(|range| *range.end());
    let stable_height = chain_tip_height
        .unwrap_or(max_height)
        .saturating_sub(PRUNING_DEPTH);

    let mut stmt_blocks = conn.prepare(
        "SELECT u.address, SUM(u.value_zat)
         FROM utxos u
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = u.spent_in_tx
         WHERE u.received_by_account_id = :account_id
         AND u.height <= :max_height
         AND (u.spent_in_tx IS NULL OR (tx.block IS NULL AND tx.expiry_height <= :stable_height))
         GROUP BY u.address",
    )?;

    let mut res = HashMap::new();
    let mut rows = stmt_blocks.query(named_params![
        ":account_id": account.0,
        ":max_height": u32::from(max_height),
        ":stable_height": u32::from(stable_height),
    ])?;
    while let Some(row) = rows.next()? {
        let taddr_str: String = row.get(0)?;
        let taddr = TransparentAddress::decode(params, &taddr_str)?;
        let value = NonNegativeAmount::from_nonnegative_i64(row.get(1)?)?;

        res.insert(taddr, value);
    }

    Ok(res)
}

/// Returns a vector with the IDs of all accounts known to this wallet.
pub(crate) fn get_account_ids(
    conn: &rusqlite::Connection,
) -> Result<Vec<AccountId>, SqliteClientError> {
    let mut stmt = conn.prepare("SELECT id FROM accounts")?;
    let mut rows = stmt.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let id = AccountId(row.get(0)?);
        result.push(id);
    }
    Ok(result)
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
pub(crate) fn put_tx_meta(
    conn: &rusqlite::Connection,
    tx: &WalletTx<AccountId>,
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

    let txid_bytes = tx.txid();
    let tx_params = named_params![
        ":txid": &txid_bytes.as_ref()[..],
        ":block": u32::from(height),
        ":tx_index": i64::try_from(tx.block_index()).expect("transaction indices are representable as i64"),
    ];

    stmt_upsert_tx_meta
        .query_row(tx_params, |row| row.get::<_, i64>(0))
        .map_err(SqliteClientError::from)
}

/// Inserts full transaction data into the database.
pub(crate) fn put_tx_data(
    conn: &rusqlite::Connection,
    tx: &Transaction,
    fee: Option<NonNegativeAmount>,
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
        ":fee": fee.map(u64::from),
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
            "SELECT account_id FROM addresses WHERE cached_transparent_receiver_address = :address",
            named_params![":address": &address_str],
            |row| Ok(AccountId(row.get(0)?)),
        )
        .optional()?;

    if let Some(account) = account_id {
        Ok(put_legacy_transparent_utxo(conn, params, output, account)?)
    } else {
        // If the UTXO is received at the legacy transparent address (at BIP 44 address
        // index 0 within its particular account, which we specifically ensure is returned
        // from `get_transparent_receivers`), there may be no entry in the addresses table
        // that can be used to tie the address to a particular account. In this case, we
        // look up the legacy address for each account in the wallet, and check whether it
        // matches the address for the received UTXO; if so, insert/update it directly.
        get_account_ids(conn)?
            .into_iter()
            .find_map(
                |account| match get_legacy_transparent_address(params, conn, account) {
                    Ok(Some((legacy_taddr, _))) if &legacy_taddr == output.recipient_address() => {
                        Some(
                            put_legacy_transparent_utxo(conn, params, output, account)
                                .map_err(SqliteClientError::from),
                        )
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                },
            )
            // The UTXO was not for any of the legacy transparent addresses.
            .unwrap_or_else(|| {
                Err(SqliteClientError::AddressNotRecognized(
                    *output.recipient_address(),
                ))
            })
    }
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
            received_by_account_id, address, script,
            value_zat, height)
        VALUES
            (:prevout_txid, :prevout_idx,
            :received_by_account_id, :address, :script,
            :value_zat, :height)
        ON CONFLICT (prevout_txid, prevout_idx) DO UPDATE
        SET received_by_account_id = :received_by_account_id,
            height = :height,
            address = :address,
            script = :script,
            value_zat = :value_zat
        RETURNING id",
    )?;

    let sql_args = named_params![
        ":prevout_txid": &output.outpoint().hash().to_vec(),
        ":prevout_idx": &output.outpoint().n(),
        ":received_by_account_id": received_by_account.0,
        ":address": &output.recipient_address().encode(params),
        ":script": &output.txout().script_pubkey.0,
        ":value_zat": &i64::from(Amount::from(output.txout().value)),
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
    to: &Recipient<AccountId, Note>,
) -> (Option<String>, Option<AccountId>, PoolType) {
    match to {
        Recipient::Transparent(addr) => (Some(addr.encode(params)), None, PoolType::Transparent),
        Recipient::Sapling(addr) => (
            Some(addr.encode(params)),
            None,
            PoolType::Shielded(ShieldedProtocol::Sapling),
        ),
        Recipient::Unified(addr, pool) => (Some(addr.encode(params)), None, *pool),
        Recipient::InternalAccount(id, note) => (
            None,
            Some(id.to_owned()),
            PoolType::Shielded(note.protocol()),
        ),
    }
}

/// Records information about a transaction output that your wallet created.
pub(crate) fn insert_sent_output<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    tx_ref: i64,
    from_account: AccountId,
    output: &SentTransactionOutput<AccountId>,
) -> Result<(), SqliteClientError> {
    let mut stmt_insert_sent_output = conn.prepare_cached(
        "INSERT INTO sent_notes (
            tx, output_pool, output_index, from_account_id,
            to_address, to_account_id, value, memo)
        VALUES (
            :tx, :output_pool, :output_index, :from_account_id,
            :to_address, :to_account_id, :value, :memo)",
    )?;

    let (to_address, to_account_id, pool_type) = recipient_params(params, output.recipient());
    let sql_args = named_params![
        ":tx": &tx_ref,
        ":output_pool": &pool_code(pool_type),
        ":output_index": &i64::try_from(output.output_index()).unwrap(),
        ":from_account_id": from_account.0,
        ":to_address": &to_address,
        ":to_account_id": to_account_id.map(|a| a.0),
        ":value": &i64::from(Amount::from(output.value())),
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
    recipient: &Recipient<AccountId, Note>,
    value: NonNegativeAmount,
    memo: Option<&MemoBytes>,
) -> Result<(), SqliteClientError> {
    let mut stmt_upsert_sent_output = conn.prepare_cached(
        "INSERT INTO sent_notes (
            tx, output_pool, output_index, from_account_id,
            to_address, to_account_id, value, memo)
        VALUES (
            :tx, :output_pool, :output_index, :from_account_id,
            :to_address, :to_account_id, :value, :memo)
        ON CONFLICT (tx, output_pool, output_index) DO UPDATE
        SET from_account_id = :from_account_id,
            to_address = :to_address,
            to_account_id = :to_account_id,
            value = :value,
            memo = IFNULL(:memo, memo)",
    )?;

    let (to_address, to_account_id, pool_type) = recipient_params(params, recipient);
    let sql_args = named_params![
        ":tx": &tx_ref,
        ":output_pool": &pool_code(pool_type),
        ":output_index": &i64::try_from(output_index).unwrap(),
        ":from_account_id": from_account.0,
        ":to_address": &to_address,
        ":to_account_id": &to_account_id.map(|a| a.0),
        ":value": &i64::from(Amount::from(value)),
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
pub(crate) fn query_nullifier_map<N: AsRef<[u8]>, S>(
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
        &WalletTx::new(
            txid,
            index,
            vec![],
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
        ),
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

    use sapling::zip32::ExtendedSpendingKey;
    use zcash_client_backend::data_api::{AccountBirthday, WalletRead};
    use zcash_primitives::{block::BlockHash, transaction::components::amount::NonNegativeAmount};

    use crate::{
        testing::{AddressType, BlockCache, TestBuilder, TestState},
        wallet::{get_account, Account},
        AccountId,
    };

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::PRUNING_DEPTH,
        zcash_client_backend::{
            data_api::{wallet::input_selection::GreedyInputSelector, InputSource, WalletWrite},
            encoding::AddressCodec,
            fees::{fixed, DustOutputPolicy},
            wallet::WalletTransparentOutput,
        },
        zcash_primitives::{
            consensus::BlockHeight,
            transaction::{
                components::{OutPoint, TxOut},
                fees::fixed::FeeRule as FixedFeeRule,
            },
        },
    };

    #[test]
    fn empty_database_has_no_balance() {
        let st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();
        let account = st.test_account().unwrap();

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
        assert_matches!(st.wallet().get_current_address(account.0), Ok(Some(_)));

        // No default address is set for an un-initialized account
        assert_matches!(
            st.wallet().get_current_address(AccountId(account.0 .0 + 1)),
            Ok(None)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn put_received_transparent_utxo() {
        use crate::testing::TestBuilder;

        let mut st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account_id, _, _) = st.test_account().unwrap();
        let uaddr = st
            .wallet()
            .get_current_address(account_id)
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        let height_1 = BlockHeight::from_u32(12345);
        let bal_absent = st
            .wallet()
            .get_transparent_balances(account_id, height_1)
            .unwrap();
        assert!(bal_absent.is_empty());

        // Create a fake transparent output.
        let value = NonNegativeAmount::const_from_u64(100000);
        let outpoint = OutPoint::new([1u8; 32], 1);
        let txout = TxOut {
            value,
            script_pubkey: taddr.script(),
        };

        // Pretend the output's transaction was mined at `height_1`.
        let utxo =
            WalletTransparentOutput::from_parts(outpoint.clone(), txout.clone(), height_1).unwrap();
        let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
        assert_matches!(res0, Ok(_));

        // Confirm that we see the output unspent as of `height_1`.
        assert_matches!(
            st.wallet().get_unspent_transparent_outputs(
                taddr,
                height_1,
                &[]
            ).as_deref(),
            Ok(&[ref ret]) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_1)
        );

        // Change the mined height of the UTXO and upsert; we should get back
        // the same `UtxoId`.
        let height_2 = BlockHeight::from_u32(34567);
        let utxo2 = WalletTransparentOutput::from_parts(outpoint, txout, height_2).unwrap();
        let res1 = st.wallet_mut().put_received_transparent_utxo(&utxo2);
        assert_matches!(res1, Ok(id) if id == res0.unwrap());

        // Confirm that we no longer see any unspent outputs as of `height_1`.
        assert_matches!(
            st.wallet()
                .get_unspent_transparent_outputs(taddr, height_1, &[])
                .as_deref(),
            Ok(&[])
        );

        // If we include `height_2` then the output is returned.
        assert_matches!(
            st.wallet()
                .get_unspent_transparent_outputs(taddr, height_2, &[])
                .as_deref(),
            Ok(&[ref ret]) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_2)
        );

        assert_matches!(
            st.wallet().get_transparent_balances(account_id, height_2),
            Ok(h) if h.get(taddr) == Some(&value)
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

    #[test]
    fn get_default_account_index() {
        use crate::testing::TestBuilder;

        let st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();
        let account_id = st.test_account().unwrap().0;
        let account_parameters = get_account(st.wallet(), account_id).unwrap().unwrap();

        let expected_account_index = zip32::AccountId::try_from(0).unwrap();
        assert_matches!(
            account_parameters,
            Account::Zip32(hdaccount) if hdaccount.account_index() == expected_account_index
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_balance_across_shielding() {
        use zcash_client_backend::ShieldedProtocol;

        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account_id, usk, _) = st.test_account().unwrap();
        let uaddr = st
            .wallet()
            .get_current_address(account_id)
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        // Initialize the wallet with chain data that has no shielded notes for us.
        let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
        let not_our_value = NonNegativeAmount::const_from_u64(10000);
        let (start_height, _, _) =
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        for _ in 1..10 {
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        }
        st.scan_cached_blocks(start_height, 10);

        let check_balance = |st: &TestState<_>, min_confirmations: u32, expected| {
            // Check the wallet summary returns the expected transparent balance.
            let summary = st
                .wallet()
                .get_wallet_summary(min_confirmations)
                .unwrap()
                .unwrap();
            let balance = summary.account_balances().get(&account_id).unwrap();
            assert_eq!(balance.unshielded(), expected);

            // Check the older APIs for consistency.
            let max_height = st.wallet().chain_height().unwrap().unwrap() + 1 - min_confirmations;
            assert_eq!(
                st.wallet()
                    .get_transparent_balances(account_id, max_height)
                    .unwrap()
                    .get(taddr)
                    .cloned()
                    .unwrap_or(NonNegativeAmount::ZERO),
                expected,
            );
            assert_eq!(
                st.wallet()
                    .get_unspent_transparent_outputs(taddr, max_height, &[])
                    .unwrap()
                    .into_iter()
                    .map(|utxo| utxo.value())
                    .sum::<Option<NonNegativeAmount>>(),
                Some(expected),
            );
        };

        // The wallet starts out with zero balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);

        // Create a fake transparent output.
        let value = NonNegativeAmount::from_u64(100000).unwrap();
        let outpoint = OutPoint::new([1u8; 32], 1);
        let txout = TxOut {
            value,
            script_pubkey: taddr.script(),
        };

        // Pretend the output was received in the chain tip.
        let height = st.wallet().chain_height().unwrap().unwrap();
        let utxo = WalletTransparentOutput::from_parts(outpoint, txout, height).unwrap();
        st.wallet_mut()
            .put_received_transparent_utxo(&utxo)
            .unwrap();

        // The wallet should detect the balance as having 1 confirmation.
        check_balance(&st, 0, value);
        check_balance(&st, 1, value);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Shield the output.
        let input_selector = GreedyInputSelector::new(
            fixed::SingleOutputChangeStrategy::new(
                FixedFeeRule::non_standard(NonNegativeAmount::ZERO),
                None,
                ShieldedProtocol::Sapling,
            ),
            DustOutputPolicy::default(),
        );
        let txid = st
            .shield_transparent_funds(&input_selector, value, &usk, &[*taddr], 1)
            .unwrap()[0];

        // The wallet should have zero transparent balance, because the shielding
        // transaction can be mined.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Mine the shielding transaction.
        let (mined_height, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(mined_height, 1);

        // The wallet should still have zero transparent balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Unmine the shielding transaction via a reorg.
        st.wallet_mut()
            .truncate_to_height(mined_height - 1)
            .unwrap();
        assert_eq!(st.wallet().chain_height().unwrap(), Some(mined_height - 1));

        // The wallet should still have zero transparent balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Expire the shielding transaction.
        let expiry_height = st.wallet().get_transaction(txid).unwrap().expiry_height();
        st.wallet_mut().update_chain_tip(expiry_height).unwrap();

        // TODO: Making the transparent output spendable in this situation requires
        // changes to the transparent data model, so for now the wallet should still have
        // zero transparent balance. https://github.com/zcash/librustzcash/issues/986
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Roll forward the chain tip until the transaction's expiry height is in the
        // stable block range (so a reorg won't make it spendable again).
        st.wallet_mut()
            .update_chain_tip(expiry_height + PRUNING_DEPTH)
            .unwrap();

        // The transparent output should be spendable again, with more confirmations.
        check_balance(&st, 0, value);
        check_balance(&st, 1, value);
        check_balance(&st, 2, value);
    }

    #[test]
    fn block_fully_scanned() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let block_fully_scanned = |st: &TestState<BlockCache>| {
            st.wallet()
                .block_fully_scanned()
                .unwrap()
                .map(|meta| meta.block_height())
        };

        // A fresh wallet should have no fully-scanned block.
        assert_eq!(block_fully_scanned(&st), None);

        // Scan a block above the wallet's birthday height.
        let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
        let not_our_value = NonNegativeAmount::const_from_u64(10000);
        let end_height = st.sapling_activation_height() + 2;
        let _ = st.generate_block_at(
            end_height,
            BlockHash([37; 32]),
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
            17,
            17,
        );
        st.scan_cached_blocks(end_height, 1);

        // The wallet should still have no fully-scanned block, as no scanned block range
        // overlaps the wallet's birthday.
        assert_eq!(block_fully_scanned(&st), None);

        // Scan the block at the wallet's birthday height.
        let start_height = st.sapling_activation_height();
        let _ = st.generate_block_at(
            start_height,
            BlockHash([0; 32]),
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
            0,
            0,
        );
        st.scan_cached_blocks(start_height, 1);

        // The fully-scanned height should now be that of the scanned block.
        assert_eq!(block_fully_scanned(&st), Some(start_height));

        // Scan the block in between the two previous blocks.
        let (h, _, _) =
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        st.scan_cached_blocks(h, 1);

        // The fully-scanned height should now be the latest block, as the two disjoint
        // ranges have been connected.
        assert_eq!(block_fully_scanned(&st), Some(end_height));
    }
}
