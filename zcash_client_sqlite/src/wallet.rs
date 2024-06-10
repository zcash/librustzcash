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
use rusqlite::{self, named_params, OptionalExtension};
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::ShardStore, ShardTree};
use zip32::fingerprint::SeedFingerprint;

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::io::{self, Cursor};
use std::num::NonZeroU32;
use std::ops::RangeInclusive;
use tracing::debug;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        scanning::{ScanPriority, ScanRange},
        AccountBalance, AccountBirthday, AccountSource, BlockMetadata, Ratio,
        SentTransactionOutput, WalletSummary, SAPLING_SHARD_HEIGHT,
    },
    encoding::AddressCodec,
    keys::UnifiedFullViewingKey,
    wallet::{Note, NoteId, Recipient, WalletTx},
    PoolType, ShieldedProtocol,
};
use zcash_keys::{
    address::{Address, Receiver, UnifiedAddress},
    keys::{
        AddressGenerationError, UnifiedAddressRequest, UnifiedIncomingViewingKey,
        UnifiedSpendingKey,
    },
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
};
use zip32::{self, DiversifierIndex, Scope};

use crate::{
    error::SqliteClientError,
    wallet::commitment_tree::{get_max_checkpointed_height, SqliteShardStore},
    AccountId, SqlTransaction, WalletCommitmentTrees, WalletDb, DEFAULT_UA_REQUEST, PRUNING_DEPTH,
    SAPLING_TABLES_PREFIX,
};

use self::scanning::{parse_priority_code, priority_code, replace_queue_entries};

#[cfg(feature = "orchard")]
use {crate::ORCHARD_TABLES_PREFIX, zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT};

#[cfg(feature = "transparent-inputs")]
use {
    crate::UtxoId,
    rusqlite::Row,
    std::collections::BTreeSet,
    zcash_address::unified::{Encoding, Ivk, Uivk},
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
pub(crate) mod common;
pub mod init;
#[cfg(feature = "orchard")]
pub(crate) mod orchard;
pub(crate) mod sapling;
pub(crate) mod scanning;
#[cfg(feature = "transparent-inputs")]
pub(crate) mod transparent;

pub(crate) const BLOCK_SAPLING_FRONTIER_ABSENT: &[u8] = &[0x0];

fn parse_account_source(
    account_kind: u32,
    hd_seed_fingerprint: Option<[u8; 32]>,
    hd_account_index: Option<u32>,
) -> Result<AccountSource, SqliteClientError> {
    match (account_kind, hd_seed_fingerprint, hd_account_index) {
        (0, Some(seed_fp), Some(account_index)) => Ok(AccountSource::Derived {
            seed_fingerprint: SeedFingerprint::from_bytes(seed_fp),
            account_index: zip32::AccountId::try_from(account_index).map_err(|_| {
                SqliteClientError::CorruptedData(
                    "ZIP-32 account ID from wallet DB is out of range.".to_string(),
                )
            })?,
        }),
        (1, None, None) => Ok(AccountSource::Imported),
        (0, None, None) | (1, Some(_), Some(_)) => Err(SqliteClientError::CorruptedData(
            "Wallet DB account_kind constraint violated".to_string(),
        )),
        (_, _, _) => Err(SqliteClientError::CorruptedData(
            "Unrecognized account_kind".to_string(),
        )),
    }
}

fn account_kind_code(value: AccountSource) -> u32 {
    match value {
        AccountSource::Derived { .. } => 0,
        AccountSource::Imported => 1,
    }
}

/// The viewing key that an [`Account`] has available to it.
#[derive(Debug, Clone)]
pub(crate) enum ViewingKey {
    /// A full viewing key.
    ///
    /// This is available to derived accounts, as well as accounts directly imported as
    /// full viewing keys.
    Full(Box<UnifiedFullViewingKey>),

    /// An incoming viewing key.
    ///
    /// Accounts that have this kind of viewing key cannot be used in wallet contexts,
    /// because they are unable to maintain an accurate balance.
    Incoming(Box<UnifiedIncomingViewingKey>),
}

/// An account stored in a `zcash_client_sqlite` database.
#[derive(Debug, Clone)]
pub struct Account {
    account_id: AccountId,
    kind: AccountSource,
    viewing_key: ViewingKey,
}

impl Account {
    /// Returns the default Unified Address for the account,
    /// along with the diversifier index that generated it.
    ///
    /// The diversifier index may be non-zero if the Unified Address includes a Sapling
    /// receiver, and there was no valid Sapling receiver at diversifier index zero.
    pub(crate) fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        match &self.viewing_key {
            ViewingKey::Full(ufvk) => ufvk.default_address(request),
            ViewingKey::Incoming(uivk) => uivk.default_address(request),
        }
    }
}

impl zcash_client_backend::data_api::Account<AccountId> for Account {
    fn id(&self) -> AccountId {
        self.account_id
    }

    fn source(&self) -> AccountSource {
        self.kind
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        self.viewing_key.ufvk()
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.viewing_key.uivk()
    }
}

impl ViewingKey {
    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        match self {
            ViewingKey::Full(ufvk) => Some(ufvk),
            ViewingKey::Incoming(_) => None,
        }
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        match self {
            ViewingKey::Full(ufvk) => ufvk.as_ref().to_unified_incoming_viewing_key(),
            ViewingKey::Incoming(uivk) => uivk.as_ref().clone(),
        }
    }
}

pub(crate) fn seed_matches_derived_account<P: consensus::Parameters>(
    params: &P,
    seed: &SecretVec<u8>,
    seed_fingerprint: &SeedFingerprint,
    account_index: zip32::AccountId,
    uivk: &UnifiedIncomingViewingKey,
) -> Result<bool, SqliteClientError> {
    let seed_fingerprint_match =
        &SeedFingerprint::from_seed(seed.expose_secret()).ok_or_else(|| {
            SqliteClientError::BadAccountData(
                "Seed must be between 32 and 252 bytes in length.".to_owned(),
            )
        })? == seed_fingerprint;

    // Keys are not comparable with `Eq`, but addresses are, so we derive what should
    // be equivalent addresses for each key and use those to check for key equality.
    let uivk_match =
        match UnifiedSpendingKey::from_seed(params, &seed.expose_secret()[..], account_index) {
            // If we can't derive a USK from the given seed with the account's ZIP 32
            // account index, then we immediately know the UIVK won't match because wallet
            // accounts are required to have a known UIVK.
            Err(_) => false,
            Ok(usk) => UnifiedAddressRequest::all().map_or(
                Ok::<_, SqliteClientError>(false),
                |ua_request| {
                    Ok(usk
                        .to_unified_full_viewing_key()
                        .default_address(ua_request)?
                        == uivk.default_address(ua_request)?)
                },
            )?,
        };

    if seed_fingerprint_match != uivk_match {
        // If these mismatch, it suggests database corruption.
        Err(SqliteClientError::CorruptedData(format!(
            "Seed fingerprint match: {seed_fingerprint_match}, uivk match: {uivk_match}"
        )))
    } else {
        Ok(seed_fingerprint_match && uivk_match)
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
    seed_id: &SeedFingerprint,
) -> Result<Option<zip32::AccountId>, SqliteClientError> {
    conn.query_row_and_then(
        "SELECT MAX(hd_account_index) FROM accounts WHERE hd_seed_fingerprint = :hd_seed",
        [seed_id.to_bytes()],
        |row| {
            let account_id: Option<u32> = row.get(0)?;
            account_id
                .map(zip32::AccountId::try_from)
                .transpose()
                .map_err(|_| SqliteClientError::AccountIdOutOfRange)
        },
    )
}

pub(crate) fn add_account<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    kind: AccountSource,
    viewing_key: ViewingKey,
    birthday: &AccountBirthday,
) -> Result<AccountId, SqliteClientError> {
    let (hd_seed_fingerprint, hd_account_index) = match kind {
        AccountSource::Derived {
            seed_fingerprint,
            account_index,
        } => (Some(seed_fingerprint), Some(account_index)),
        AccountSource::Imported => (None, None),
    };

    let orchard_item = viewing_key
        .ufvk()
        .and_then(|ufvk| ufvk.orchard().map(|k| k.to_bytes()));
    let sapling_item = viewing_key
        .ufvk()
        .and_then(|ufvk| ufvk.sapling().map(|k| k.to_bytes()));
    #[cfg(feature = "transparent-inputs")]
    let transparent_item = viewing_key
        .ufvk()
        .and_then(|ufvk| ufvk.transparent().map(|k| k.serialize()));
    #[cfg(not(feature = "transparent-inputs"))]
    let transparent_item: Option<Vec<u8>> = None;

    let birthday_sapling_tree_size = Some(birthday.sapling_frontier().tree_size());
    #[cfg(feature = "orchard")]
    let birthday_orchard_tree_size = Some(birthday.orchard_frontier().tree_size());
    #[cfg(not(feature = "orchard"))]
    let birthday_orchard_tree_size: Option<u64> = None;

    let account_id: AccountId = conn.query_row(
        r#"
        INSERT INTO accounts (
            account_kind, hd_seed_fingerprint, hd_account_index,
            ufvk, uivk,
            orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
            birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
            recover_until_height
        )
        VALUES (
            :account_kind, :hd_seed_fingerprint, :hd_account_index,
            :ufvk, :uivk,
            :orchard_fvk_item_cache, :sapling_fvk_item_cache, :p2pkh_fvk_item_cache,
            :birthday_height, :birthday_sapling_tree_size, :birthday_orchard_tree_size,
            :recover_until_height
        )
        RETURNING id;
        "#,
        named_params![
            ":account_kind": account_kind_code(kind),
            ":hd_seed_fingerprint": hd_seed_fingerprint.as_ref().map(|fp| fp.to_bytes()),
            ":hd_account_index": hd_account_index.map(u32::from),
            ":ufvk": viewing_key.ufvk().map(|ufvk| ufvk.encode(params)),
            ":uivk": viewing_key.uivk().encode(params),
            ":orchard_fvk_item_cache": orchard_item,
            ":sapling_fvk_item_cache": sapling_item,
            ":p2pkh_fvk_item_cache": transparent_item,
            ":birthday_height": u32::from(birthday.height()),
            ":birthday_sapling_tree_size": birthday_sapling_tree_size,
            ":birthday_orchard_tree_size": birthday_orchard_tree_size,
            ":recover_until_height": birthday.recover_until().map(u32::from)
        ],
        |row| Ok(AccountId(row.get(0)?)),
    )?;

    let account = Account {
        account_id,
        kind,
        viewing_key,
    };

    // If a birthday frontier is available, insert it into the note commitment tree. If the
    // birthday frontier is the empty frontier, we don't need to do anything.
    if let Some(frontier) = birthday.sapling_frontier().value() {
        debug!("Inserting Sapling frontier into ShardTree: {:?}", frontier);
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

    #[cfg(feature = "orchard")]
    if let Some(frontier) = birthday.orchard_frontier().value() {
        debug!("Inserting Orchard frontier into ShardTree: {:?}", frontier);
        let shard_store = SqliteShardStore::<
            _,
            ::orchard::tree::MerkleHashOrchard,
            ORCHARD_SHARD_HEIGHT,
        >::from_connection(conn, ORCHARD_TABLES_PREFIX)?;
        let mut shard_tree: ShardTree<
            _,
            { ::orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            ORCHARD_SHARD_HEIGHT,
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

    // The ignored range always starts at Sapling activation
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
pub(crate) fn get_account_for_ufvk<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    ufvk: &UnifiedFullViewingKey,
) -> Result<Option<Account>, SqliteClientError> {
    #[cfg(feature = "transparent-inputs")]
    let transparent_item = ufvk.transparent().map(|k| k.serialize());
    #[cfg(not(feature = "transparent-inputs"))]
    let transparent_item: Option<Vec<u8>> = None;

    let mut stmt = conn.prepare(
        "SELECT id, account_kind, hd_seed_fingerprint, hd_account_index, ufvk
        FROM accounts
        WHERE orchard_fvk_item_cache = :orchard_fvk_item_cache
           OR sapling_fvk_item_cache = :sapling_fvk_item_cache
           OR p2pkh_fvk_item_cache = :p2pkh_fvk_item_cache",
    )?;

    let accounts = stmt
        .query_and_then::<_, SqliteClientError, _, _>(
            named_params![
                ":orchard_fvk_item_cache": ufvk.orchard().map(|k| k.to_bytes()),
                ":sapling_fvk_item_cache": ufvk.sapling().map(|k| k.to_bytes()),
                ":p2pkh_fvk_item_cache": transparent_item,
            ],
            |row| {
                let account_id = row.get::<_, u32>(0).map(AccountId)?;
                let kind = parse_account_source(row.get(1)?, row.get(2)?, row.get(3)?)?;

                // We looked up the account by FVK components, so the UFVK column must be
                // non-null.
                let ufvk_str: String = row.get(4)?;
                let viewing_key = ViewingKey::Full(Box::new(
                    UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                        SqliteClientError::CorruptedData(format!(
                            "Could not decode unified full viewing key for account {:?}: {}",
                            account_id, e
                        ))
                    })?,
                ));

                Ok(Account {
                    account_id,
                    kind,
                    viewing_key,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    if accounts.len() > 1 {
        Err(SqliteClientError::CorruptedData(
            "Mutiple account records matched the provided UFVK".to_owned(),
        ))
    } else {
        Ok(accounts.into_iter().next())
    }
}

/// Returns the account id corresponding to a given [`SeedFingerprint`]
/// and [`zip32::AccountId`], if any.
pub(crate) fn get_derived_account<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    seed: &SeedFingerprint,
    account_index: zip32::AccountId,
) -> Result<Option<Account>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT id, ufvk
        FROM accounts
        WHERE hd_seed_fingerprint = :hd_seed_fingerprint
          AND hd_account_index = :account_id",
    )?;

    let mut accounts = stmt.query_and_then::<_, SqliteClientError, _, _>(
        named_params![
            ":hd_seed_fingerprint": seed.to_bytes(),
            ":hd_account_index": u32::from(account_index),
        ],
        |row| {
            let account_id = row.get::<_, u32>(0).map(AccountId)?;
            let ufvk = match row.get::<_, Option<String>>(1)? {
                None => Err(SqliteClientError::CorruptedData(format!(
                    "Missing unified full viewing key for derived account {:?}",
                    account_id,
                ))),
                Some(ufvk_str) => UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                    SqliteClientError::CorruptedData(format!(
                        "Could not decode unified full viewing key for account {:?}: {}",
                        account_id, e
                    ))
                }),
            }?;
            Ok(Account {
                account_id,
                kind: AccountSource::Derived {
                    seed_fingerprint: *seed,
                    account_index,
                },
                viewing_key: ViewingKey::Full(Box::new(ufvk)),
            })
        },
    )?;

    accounts.next().transpose()
}

pub(crate) trait ScanProgress {
    fn sapling_scan_progress(
        &self,
        conn: &rusqlite::Connection,
        birthday_height: BlockHeight,
        fully_scanned_height: BlockHeight,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Ratio<u64>>, SqliteClientError>;

    #[cfg(feature = "orchard")]
    fn orchard_scan_progress(
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
            // Get the starting note commitment tree size from the wallet birthday, or failing that
            // from the blocks table.
            let start_size = conn
                .query_row(
                    "SELECT birthday_sapling_tree_size
                     FROM accounts
                     WHERE birthday_height = :birthday_height",
                    named_params![":birthday_height": u32::from(birthday_height)],
                    |row| row.get::<_, Option<u64>>(0),
                )
                .optional()?
                .flatten()
                .map(Ok)
                .or_else(|| {
                    conn.query_row(
                        "SELECT MAX(sapling_commitment_tree_size - sapling_output_count)
                         FROM blocks
                         WHERE height <= :start_height",
                        named_params![":start_height": u32::from(birthday_height)],
                        |row| row.get::<_, Option<u64>>(0),
                    )
                    .optional()
                    .map(|opt| opt.flatten())
                    .transpose()
                })
                .transpose()?;

            // Compute the total blocks scanned so far above the starting height
            let scanned_count = conn.query_row(
                "SELECT SUM(sapling_output_count)
                 FROM blocks
                 WHERE height > :start_height",
                named_params![":start_height": u32::from(birthday_height)],
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
                    named_params![":start_height": u32::from(birthday_height)],
                    |row| {
                        let min_tree_size = row
                            .get::<_, Option<u64>>(0)?
                            .map(|min_idx| min_idx << SAPLING_SHARD_HEIGHT);
                        let max_tree_size = row
                            .get::<_, Option<u64>>(1)?
                            .map(|max_idx| (max_idx + 1) << SAPLING_SHARD_HEIGHT);
                        Ok(start_size.or(min_tree_size).zip(max_tree_size).map(
                            |(min_tree_size, max_tree_size)| {
                                Ratio::new(
                                    scanned_count.unwrap_or(0),
                                    max_tree_size - min_tree_size,
                                )
                            },
                        ))
                    },
                )
                .optional()?
                .flatten())
        }
    }

    #[cfg(feature = "orchard")]
    #[tracing::instrument(skip(conn))]
    fn orchard_scan_progress(
        &self,
        conn: &rusqlite::Connection,
        birthday_height: BlockHeight,
        fully_scanned_height: BlockHeight,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Ratio<u64>>, SqliteClientError> {
        if fully_scanned_height == chain_tip_height {
            // Compute the total blocks scanned since the wallet birthday
            conn.query_row(
                "SELECT SUM(orchard_action_count)
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
            // Compute the starting number of notes directly from the blocks table
            let start_size = conn
                .query_row(
                    "SELECT birthday_orchard_tree_size
                     FROM accounts
                     WHERE birthday_height = :birthday_height",
                    named_params![":birthday_height": u32::from(birthday_height)],
                    |row| row.get::<_, Option<u64>>(0),
                )
                .optional()?
                .flatten()
                .map(Ok)
                .or_else(|| {
                    conn.query_row(
                        "SELECT MAX(orchard_commitment_tree_size - orchard_action_count)
                         FROM blocks
                         WHERE height <= :start_height",
                        named_params![":start_height": u32::from(birthday_height)],
                        |row| row.get::<_, Option<u64>>(0),
                    )
                    .optional()
                    .map(|opt| opt.flatten())
                    .transpose()
                })
                .transpose()?;

            // Compute the total blocks scanned so far above the starting height
            let scanned_count = conn.query_row(
                "SELECT SUM(orchard_action_count)
                 FROM blocks
                 WHERE height > :start_height",
                named_params![":start_height": u32::from(birthday_height)],
                |row| row.get::<_, Option<u64>>(0),
            )?;

            // We don't have complete information on how many actions will exist in the shard at
            // the chain tip without having scanned the chain tip block, so we overestimate by
            // computing the maximum possible number of notes directly from the shard indices.
            //
            // TODO: it would be nice to be able to reliably have the size of the commitment tree
            // at the chain tip without having to have scanned that block.
            Ok(conn
                .query_row(
                    "SELECT MIN(shard_index), MAX(shard_index)
                     FROM orchard_tree_shards
                     WHERE subtree_end_height > :start_height
                     OR subtree_end_height IS NULL",
                    named_params![":start_height": u32::from(birthday_height)],
                    |row| {
                        let min_tree_size = row
                            .get::<_, Option<u64>>(0)?
                            .map(|min_idx| min_idx << ORCHARD_SHARD_HEIGHT);
                        let max_tree_size = row
                            .get::<_, Option<u64>>(1)?
                            .map(|max_idx| (max_idx + 1) << ORCHARD_SHARD_HEIGHT);
                        Ok(start_size.or(min_tree_size).zip(max_tree_size).map(
                            |(min_tree_size, max_tree_size)| {
                                Ratio::new(
                                    scanned_count.unwrap_or(0),
                                    max_tree_size - min_tree_size,
                                )
                            },
                        ))
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

    #[cfg(feature = "orchard")]
    let orchard_scan_progress = progress.orchard_scan_progress(
        tx,
        birthday_height,
        fully_scanned_height,
        chain_tip_height,
    )?;
    #[cfg(not(feature = "orchard"))]
    let orchard_scan_progress: Option<Ratio<u64>> = None;

    // Treat Sapling and Orchard outputs as having the same cost to scan.
    let scan_progress = sapling_scan_progress
        .zip(orchard_scan_progress)
        .map(|(s, o)| {
            Ratio::new(
                s.numerator() + o.numerator(),
                s.denominator() + o.denominator(),
            )
        })
        .or(sapling_scan_progress)
        .or(orchard_scan_progress);

    let mut stmt_accounts = tx.prepare_cached("SELECT id FROM accounts")?;
    let mut account_balances = stmt_accounts
        .query([])?
        .and_then(|row| {
            Ok::<_, SqliteClientError>((AccountId(row.get::<_, u32>(0)?), AccountBalance::ZERO))
        })
        .collect::<Result<HashMap<AccountId, AccountBalance>, _>>()?;

    fn count_notes<F>(
        tx: &rusqlite::Transaction,
        summary_height: BlockHeight,
        account_balances: &mut HashMap<AccountId, AccountBalance>,
        table_prefix: &'static str,
        with_pool_balance: F,
    ) -> Result<(), SqliteClientError>
    where
        F: Fn(
            &mut AccountBalance,
            NonNegativeAmount,
            NonNegativeAmount,
            NonNegativeAmount,
        ) -> Result<(), SqliteClientError>,
    {
        // If the shard containing the summary height contains any unscanned ranges that start below or
        // including that height, none of our balance is currently spendable.
        #[tracing::instrument(skip_all)]
        fn is_any_spendable(
            conn: &rusqlite::Connection,
            summary_height: BlockHeight,
            table_prefix: &'static str,
        ) -> Result<bool, SqliteClientError> {
            conn.query_row(
                &format!(
                    "SELECT NOT EXISTS(
                         SELECT 1 FROM v_{table_prefix}_shard_unscanned_ranges
                         WHERE :summary_height
                            BETWEEN subtree_start_height
                            AND IFNULL(subtree_end_height, :summary_height)
                         AND block_range_start <= :summary_height
                     )"
                ),
                named_params![":summary_height": u32::from(summary_height)],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|e| e.into())
        }

        let any_spendable = is_any_spendable(tx, summary_height, table_prefix)?;
        let mut stmt_select_notes = tx.prepare_cached(&format!(
            "SELECT n.account_id, n.value, n.is_change, scan_state.max_priority, t.block
             FROM {table_prefix}_received_notes n
             JOIN transactions t ON t.id_tx = n.tx
             LEFT OUTER JOIN v_{table_prefix}_shards_scan_state scan_state
                ON n.commitment_tree_position >= scan_state.start_position
                AND n.commitment_tree_position < scan_state.end_position_exclusive
             WHERE (
                t.block IS NOT NULL -- the receiving tx is mined
                OR t.expiry_height IS NULL -- the receiving tx will not expire
                OR t.expiry_height >= :summary_height -- the receiving tx is unexpired
             )
             -- and the received note is unspent
             AND n.id NOT IN (
               SELECT {table_prefix}_received_note_id
               FROM {table_prefix}_received_note_spends
               JOIN transactions t ON t.id_tx = transaction_id
               WHERE t.block IS NOT NULL -- the spending transaction is mined
               OR t.expiry_height IS NULL -- the spending tx will not expire
               OR t.expiry_height > :summary_height -- the spending tx is unexpired
             )"
        ))?;

        let mut rows =
            stmt_select_notes.query(named_params![":summary_height": u32::from(summary_height)])?;
        while let Some(row) = rows.next()? {
            let account = AccountId(row.get::<_, u32>(0)?);

            let value_raw = row.get::<_, i64>(1)?;
            let value = NonNegativeAmount::from_nonnegative_i64(value_raw).map_err(|_| {
                SqliteClientError::CorruptedData(format!(
                    "Negative received note value: {}",
                    value_raw
                ))
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

            let is_pending_change =
                is_change && received_height.iter().all(|h| h > &summary_height);

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
                with_pool_balance(
                    balances,
                    spendable_value,
                    change_pending_confirmation,
                    value_pending_spendability,
                )?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "orchard")]
    {
        let orchard_trace = tracing::info_span!("orchard_balances").entered();
        count_notes(
            tx,
            summary_height,
            &mut account_balances,
            ORCHARD_TABLES_PREFIX,
            |balances, spendable_value, change_pending_confirmation, value_pending_spendability| {
                balances.with_orchard_balance_mut::<_, SqliteClientError>(|bal| {
                    bal.add_spendable_value(spendable_value)?;
                    bal.add_pending_change_value(change_pending_confirmation)?;
                    bal.add_pending_spendable_value(value_pending_spendability)?;
                    Ok(())
                })
            },
        )?;
        drop(orchard_trace);
    }

    let sapling_trace = tracing::info_span!("sapling_balances").entered();
    count_notes(
        tx,
        summary_height,
        &mut account_balances,
        SAPLING_TABLES_PREFIX,
        |balances, spendable_value, change_pending_confirmation, value_pending_spendability| {
            balances.with_sapling_balance_mut::<_, SqliteClientError>(|bal| {
                bal.add_spendable_value(spendable_value)?;
                bal.add_pending_change_value(change_pending_confirmation)?;
                bal.add_pending_spendable_value(value_pending_spendability)?;
                Ok(())
            })
        },
    )?;
    drop(sapling_trace);

    #[cfg(feature = "transparent-inputs")]
    {
        let transparent_trace = tracing::info_span!("stmt_transparent_balances").entered();
        let zero_conf_height = (chain_tip_height + 1).saturating_sub(min_confirmations);
        let stable_height = chain_tip_height.saturating_sub(PRUNING_DEPTH);

        let mut stmt_transparent_balances = tx.prepare(
            "SELECT u.received_by_account_id, SUM(u.value_zat)
             FROM utxos u
             WHERE u.height <= :max_height
             -- and the received txo is unspent
             AND u.id NOT IN (
               SELECT transparent_received_output_id
               FROM transparent_received_output_spends txo_spends
               JOIN transactions tx
                 ON tx.id_tx = txo_spends.transaction_id
               WHERE tx.block IS NOT NULL -- the spending tx is mined
               OR tx.expiry_height IS NULL -- the spending tx will not expire
               OR tx.expiry_height > :stable_height -- the spending tx is unexpired
             )
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

    // The approach used here for Sapling and Orchard subtree indexing was a quick hack
    // that has not yet been replaced. TODO: Make less hacky.
    // https://github.com/zcash/librustzcash/issues/1249
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

    #[cfg(feature = "orchard")]
    let next_orchard_subtree_index = {
        let shard_store = SqliteShardStore::<
            _,
            ::orchard::tree::MerkleHashOrchard,
            ORCHARD_SHARD_HEIGHT,
        >::from_connection(tx, ORCHARD_TABLES_PREFIX)?;

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
        scan_progress,
        next_sapling_subtree_index,
        #[cfg(feature = "orchard")]
        next_orchard_subtree_index,
    );

    Ok(Some(summary))
}

/// Returns the memo for a received note, if the note is known to the wallet.
pub(crate) fn get_received_memo(
    conn: &rusqlite::Connection,
    note_id: NoteId,
) -> Result<Option<Memo>, SqliteClientError> {
    let fetch_memo = |table_prefix: &'static str, output_col: &'static str| {
        conn.query_row(
            &format!(
                "SELECT memo FROM {table_prefix}_received_notes
                JOIN transactions ON {table_prefix}_received_notes.tx = transactions.id_tx
                WHERE transactions.txid = :txid
                AND {table_prefix}_received_notes.{output_col} = :output_index"
            ),
            named_params![
                ":txid": note_id.txid().as_ref(),
                ":output_index": note_id.output_index()
            ],
            |row| row.get(0),
        )
        .optional()
    };

    let memo_bytes: Option<Vec<_>> = match note_id.protocol() {
        ShieldedProtocol::Sapling => fetch_memo(SAPLING_TABLES_PREFIX, "output_index")?.flatten(),
        #[cfg(feature = "orchard")]
        ShieldedProtocol::Orchard => fetch_memo(ORCHARD_TABLES_PREFIX, "action_index")?.flatten(),
        #[cfg(not(feature = "orchard"))]
        ShieldedProtocol::Orchard => {
            return Err(SqliteClientError::UnsupportedPoolType(PoolType::Shielded(
                ShieldedProtocol::Orchard,
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
) -> Result<Option<(BlockHeight, Transaction)>, SqliteClientError> {
    conn.query_row(
        "SELECT raw, block, expiry_height FROM transactions
        WHERE txid = ?",
        [txid.as_ref()],
        |row| {
            let h: Option<u32> = row.get(1)?;
            let expiry: Option<u32> = row.get(2)?;
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                h.map(BlockHeight::from),
                expiry.map(BlockHeight::from),
            ))
        },
    )
    .optional()?
    .map(|(tx_bytes, block_height, expiry_height)| {
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
                    #[cfg(zcash_unstable = "nu7")]
                    tx_data.orchard_zsa_bundle().cloned(),
                    #[cfg(zcash_unstable = "nu7")]
                    tx_data.issue_bundle().cloned(),
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
    })
    .transpose()
}

pub(crate) fn get_funding_accounts(
    conn: &rusqlite::Connection,
    tx: &Transaction,
) -> Result<HashSet<AccountId>, rusqlite::Error> {
    let mut funding_accounts = HashSet::new();
    #[cfg(feature = "transparent-inputs")]
    funding_accounts.extend(transparent::detect_spending_accounts(
        conn,
        tx.transparent_bundle()
            .iter()
            .flat_map(|bundle| bundle.vin.iter().map(|txin| &txin.prevout)),
    )?);

    funding_accounts.extend(sapling::detect_spending_accounts(
        conn,
        tx.sapling_bundle().iter().flat_map(|bundle| {
            bundle
                .shielded_spends()
                .iter()
                .map(|spend| spend.nullifier())
        }),
    )?);

    #[cfg(feature = "orchard")]
    funding_accounts.extend(orchard::detect_spending_accounts(
        conn,
        tx.orchard_bundle()
            .iter()
            .flat_map(|bundle| bundle.actions().iter().map(|action| action.nullifier())),
    )?);

    Ok(funding_accounts)
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
         WHERE id = :account_id",
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

pub(crate) fn get_account<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountId,
) -> Result<Option<Account>, SqliteClientError> {
    let mut sql = conn.prepare_cached(
        r#"
        SELECT account_kind, hd_seed_fingerprint, hd_account_index, ufvk, uivk
        FROM accounts
        WHERE id = :account_id
        "#,
    )?;

    let mut result = sql.query(named_params![":account_id": account_id.0])?;
    let row = result.next()?;
    match row {
        Some(row) => {
            let kind = parse_account_source(
                row.get("account_kind")?,
                row.get("hd_seed_fingerprint")?,
                row.get("hd_account_index")?,
            )?;

            let ufvk_str: Option<String> = row.get("ufvk")?;
            let viewing_key = if let Some(ufvk_str) = ufvk_str {
                ViewingKey::Full(Box::new(
                    UnifiedFullViewingKey::decode(params, &ufvk_str[..])
                        .map_err(SqliteClientError::BadAccountData)?,
                ))
            } else {
                let uivk_str: String = row.get("uivk")?;
                ViewingKey::Incoming(Box::new(
                    UnifiedIncomingViewingKey::decode(params, &uivk_str[..])
                        .map_err(SqliteClientError::BadAccountData)?,
                ))
            };

            Ok(Some(Account {
                account_id,
                kind,
                viewing_key,
            }))
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

            #[cfg(feature = "orchard")]
            let orchard_anchor_height = get_max_checkpointed_height(
                conn,
                ORCHARD_TABLES_PREFIX,
                chain_tip_height,
                min_confirmations,
            )?;

            #[cfg(not(feature = "orchard"))]
            let orchard_anchor_height: Option<BlockHeight> = None;

            let anchor_height = sapling_anchor_height
                .zip(orchard_anchor_height)
                .map(|(s, o)| std::cmp::min(s, o))
                .or(sapling_anchor_height)
                .or(orchard_anchor_height);

            Ok(anchor_height.map(|h| (chain_tip_height + 1, h)))
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
        |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
    )
    .optional()
    .map(|opt| opt.flatten())
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
    let min_sapling: Option<BlockHeight> = conn.query_row(
        "SELECT MIN(tx.block)
         FROM sapling_received_notes n
         JOIN transactions tx ON tx.id_tx = n.tx
         WHERE n.id NOT IN (
            SELECT sapling_received_note_id
            FROM sapling_received_note_spends
            JOIN transactions tx ON tx.id_tx = transaction_id
            WHERE tx.block IS NOT NULL
         )",
        [],
        |row| {
            row.get(0)
                .map(|maybe_height: Option<u32>| maybe_height.map(|height| height.into()))
        },
    )?;
    #[cfg(feature = "orchard")]
    let min_orchard: Option<BlockHeight> = conn.query_row(
        "SELECT MIN(tx.block)
         FROM orchard_received_notes n
         JOIN transactions tx ON tx.id_tx = n.tx
         WHERE n.id NOT IN (
            SELECT orchard_received_note_id
            FROM orchard_received_note_spends
            JOIN transactions tx ON tx.id_tx = transaction_id
            WHERE tx.block IS NOT NULL
         )",
        [],
        |row| {
            row.get(0)
                .map(|maybe_height: Option<u32>| maybe_height.map(|height| height.into()))
        },
    )?;
    #[cfg(not(feature = "orchard"))]
    let min_orchard = None;

    Ok(min_sapling
        .zip(min_orchard)
        .map(|(s, o)| s.min(o))
        .or(min_sapling)
        .or(min_orchard))
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

    // Delete from the scanning queue any range with a start height greater than the
    // truncation height, and then truncate any remaining range by setting the end
    // equal to the truncation height + 1. This sets our view of the chain tip back
    // to the retained height.
    conn.execute(
        "DELETE FROM scan_queue
        WHERE block_range_start >= :new_end_height",
        named_params![":new_end_height": u32::from(block_height + 1)],
    )?;
    conn.execute(
        "UPDATE scan_queue
        SET block_range_end = :new_end_height
        WHERE block_range_end > :new_end_height",
        named_params![":new_end_height": u32::from(block_height + 1)],
    )?;

    // If we're removing scanned blocks, we need to truncate the note commitment tree, un-mine
    // transactions, and remove received transparent outputs and affected block records from the
    // database.
    if block_height < last_scanned_height {
        // Truncate the note commitment trees
        let mut wdb = WalletDb {
            conn: SqlTransaction(conn),
            params: params.clone(),
        };
        wdb.with_sapling_tree_mut(|tree| {
            tree.truncate_removing_checkpoint(&block_height).map(|_| ())
        })?;
        #[cfg(feature = "orchard")]
        wdb.with_orchard_tree_mut(|tree| {
            tree.truncate_removing_checkpoint(&block_height).map(|_| ())
        })?;

        // Do not delete sent notes; this can contain data that is not recoverable
        // from the chain. Wallets must continue to operate correctly in the
        // presence of stale sent notes that link to unmined transactions.
        // Also, do not delete received notes; they may contain memo data that is
        // not recoverable; balance APIs must ensure that un-mined received notes
        // do not count towards spendability or transaction balalnce.

        // Rewind utxos. It is currently necessary to delete these because we do
        // not have the full transaction data for the received output.
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

        // Now that they aren't depended on, delete un-mined blocks.
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
    }

    Ok(())
}

#[cfg(feature = "transparent-inputs")]
fn to_unspent_transparent_output(row: &Row) -> Result<WalletTransparentOutput, SqliteClientError> {
    let txid: Vec<u8> = row.get("prevout_txid")?;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&txid);

    let index: u32 = row.get("prevout_idx")?;
    let script_pubkey = Script(row.get("script")?);
    let raw_value: i64 = row.get("value_zat")?;
    let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
        SqliteClientError::CorruptedData(format!("Invalid UTXO value: {}", raw_value))
    })?;
    let height: u32 = row.get("height")?;

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
         WHERE u.prevout_txid = :txid
         AND u.prevout_idx = :output_index
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE tx.block IS NOT NULL  -- the spending tx is mined
            OR tx.expiry_height IS NULL -- the spending tx will not expire
         )",
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
         WHERE u.address = :address
         AND u.height <= :max_height
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE
              tx.block IS NOT NULL -- the spending tx is mined
              OR tx.expiry_height IS NULL -- the spending tx will not expire
              OR tx.expiry_height > :stable_height -- the spending tx is unexpired
         )",
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
         WHERE u.received_by_account_id = :account_id
         AND u.height <= :max_height
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE
              tx.block IS NOT NULL -- the spending tx is mined
              OR tx.expiry_height IS NULL -- the spending tx will not expire
              OR tx.expiry_height > :stable_height -- the spending tx is unexpired
         )
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn put_block(
    conn: &rusqlite::Transaction<'_>,
    block_height: BlockHeight,
    block_hash: BlockHash,
    block_time: u32,
    sapling_commitment_tree_size: u32,
    sapling_output_count: u32,
    #[cfg(feature = "orchard")] orchard_commitment_tree_size: u32,
    #[cfg(feature = "orchard")] orchard_action_count: u32,
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
            sapling_tree,
            orchard_commitment_tree_size,
            orchard_action_count
        )
        VALUES (
            :height,
            :hash,
            :block_time,
            :sapling_commitment_tree_size,
            :sapling_output_count,
            x'00',
            :orchard_commitment_tree_size,
            :orchard_action_count
        )
        ON CONFLICT (height) DO UPDATE
        SET hash = :hash,
            time = :block_time,
            sapling_commitment_tree_size = :sapling_commitment_tree_size,
            sapling_output_count = :sapling_output_count,
            orchard_commitment_tree_size = :orchard_commitment_tree_size,
            orchard_action_count = :orchard_action_count",
    )?;

    #[cfg(not(feature = "orchard"))]
    let orchard_commitment_tree_size: Option<u32> = None;
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count: Option<u32> = None;

    stmt_upsert_block.execute(named_params![
        ":height": u32::from(block_height),
        ":hash": &block_hash.0[..],
        ":block_time": block_time,
        ":sapling_commitment_tree_size": sapling_commitment_tree_size,
        ":sapling_output_count": sapling_output_count,
        ":orchard_commitment_tree_size": orchard_commitment_tree_size,
        ":orchard_action_count": orchard_action_count,
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

/// Returns the most likely wallet address that corresponds to the protocol-level receiver of a
/// note or UTXO.
pub(crate) fn select_receiving_address<P: consensus::Parameters>(
    _params: &P,
    conn: &rusqlite::Connection,
    account: AccountId,
    receiver: &Receiver,
) -> Result<Option<ZcashAddress>, SqliteClientError> {
    match receiver {
        #[cfg(feature = "transparent-inputs")]
        Receiver::Transparent(taddr) => conn
            .query_row(
                "SELECT address
                 FROM addresses
                 WHERE cached_transparent_receiver_address = :taddr",
                named_params! {
                    ":taddr": Address::Transparent(*taddr).encode(_params)
                },
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|addr_str| addr_str.parse::<ZcashAddress>())
            .transpose()
            .map_err(SqliteClientError::from),
        receiver => {
            let mut stmt =
                conn.prepare_cached("SELECT address FROM addresses WHERE account_id = :account")?;

            let mut result = stmt.query(named_params! { ":account": account.0 })?;
            while let Some(row) = result.next()? {
                let addr_str = row.get::<_, String>(0)?;
                let decoded = addr_str.parse::<ZcashAddress>()?;
                if receiver.corresponds(&decoded) {
                    return Ok(Some(decoded));
                }
            }

            Ok(None)
        }
    }
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
        "INSERT INTO transparent_received_output_spends (transparent_received_output_id, transaction_id)
         SELECT txo.id, :spent_in_tx
         FROM utxos txo
         WHERE txo.prevout_txid = :prevout_txid
         AND txo.prevout_idx = :prevout_idx
         ON CONFLICT (transparent_received_output_id, transaction_id) DO NOTHING",
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

// A utility function for creation of parameters for use in `insert_sent_output`
// and `put_sent_output`
fn recipient_params(
    to: &Recipient<AccountId, Note>,
) -> (Option<String>, Option<AccountId>, PoolType) {
    match to {
        Recipient::External(addr, pool) => (Some(addr.encode()), None, *pool),
        Recipient::InternalAccount {
            receiving_account,
            external_address,
            note,
        } => (
            external_address.as_ref().map(|a| a.encode()),
            Some(*receiving_account),
            PoolType::Shielded(note.protocol()),
        ),
    }
}

/// Records information about a transaction output that your wallet created.
pub(crate) fn insert_sent_output(
    conn: &rusqlite::Connection,
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

    let (to_address, to_account_id, pool_type) = recipient_params(output.recipient());
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
pub(crate) fn put_sent_output(
    conn: &rusqlite::Connection,
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
            to_account_id = IFNULL(to_account_id, :to_account_id),
            value = :value,
            memo = IFNULL(:memo, memo)",
    )?;

    let (to_address, to_account_id, pool_type) = recipient_params(recipient);
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
    use secrecy::{ExposeSecret, SecretVec};
    use zcash_client_backend::data_api::{AccountSource, WalletRead};
    use zcash_primitives::{block::BlockHash, transaction::components::amount::NonNegativeAmount};

    use crate::{
        testing::{AddressType, BlockCache, TestBuilder, TestState},
        AccountId,
    };

    use super::account_birthday;

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
            .with_account_from_sapling_activation(BlockHash([0; 32]))
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
        assert_matches!(
            st.wallet().get_current_address(account.account_id()),
            Ok(Some(_))
        );

        // No default address is set for an un-initialized account
        assert_matches!(
            st.wallet()
                .get_current_address(AccountId(account.account_id().0 + 1)),
            Ok(None)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn put_received_transparent_utxo() {
        use crate::testing::TestBuilder;

        let mut st = TestBuilder::new()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_id = st.test_account().unwrap().account_id();
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
        assert_matches!(
            st.wallet().get_unspent_transparent_output(utxo.outpoint()),
            Ok(Some(ret)) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_1)
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

        // We can still look up the specific output, and it has the expected height.
        assert_matches!(
            st.wallet().get_unspent_transparent_output(utxo2.outpoint()),
            Ok(Some(ret)) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo2.outpoint(), utxo2.txout(), height_2)
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
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account_id = st.test_account().unwrap().account_id();
        let account_parameters = st.wallet().get_account(account_id).unwrap().unwrap();

        let expected_account_index = zip32::AccountId::try_from(0).unwrap();
        assert_matches!(
            account_parameters.kind,
            AccountSource::Derived{account_index, ..} if account_index == expected_account_index
        );
    }

    #[test]
    fn get_account_ids() {
        use crate::testing::TestBuilder;
        use zcash_client_backend::data_api::WalletWrite;

        let mut st = TestBuilder::new()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
        let birthday = st.test_account().unwrap().birthday().clone();

        st.wallet_mut().create_account(&seed, &birthday).unwrap();

        for acct_id in st.wallet().get_account_ids().unwrap() {
            assert_matches!(st.wallet().get_account(acct_id), Ok(Some(_)))
        }
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_balance_across_shielding() {
        use zcash_client_backend::ShieldedProtocol;

        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let uaddr = st
            .wallet()
            .get_current_address(account.account_id())
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
            let balance = summary
                .account_balances()
                .get(&account.account_id())
                .unwrap();
            assert_eq!(balance.unshielded(), expected);

            // Check the older APIs for consistency.
            let max_height = st.wallet().chain_height().unwrap().unwrap() + 1 - min_confirmations;
            assert_eq!(
                st.wallet()
                    .get_transparent_balances(account.account_id(), max_height)
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
            .shield_transparent_funds(&input_selector, value, account.usk(), &[*taddr], 1)
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
        let expiry_height = st
            .wallet()
            .get_transaction(txid)
            .unwrap()
            .expect("Transaction exists in the wallet.")
            .expiry_height();
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
            .with_account_from_sapling_activation(BlockHash([0; 32]))
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
        let start_height = st.sapling_activation_height();
        let _ = st.generate_block_at(
            start_height,
            BlockHash([0; 32]),
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
            0,
            0,
            false,
        );
        let (mid_height, _, _) =
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        let (end_height, _, _) =
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);

        // Scan the last block first
        st.scan_cached_blocks(end_height, 1);

        // The wallet should still have no fully-scanned block, as no scanned block range
        // overlaps the wallet's birthday.
        assert_eq!(block_fully_scanned(&st), None);

        // Scan the block at the wallet's birthday height.
        st.scan_cached_blocks(start_height, 1);

        // The fully-scanned height should now be that of the scanned block.
        assert_eq!(block_fully_scanned(&st), Some(start_height));

        // Scan the block in between the two previous blocks.
        st.scan_cached_blocks(mid_height, 1);

        // The fully-scanned height should now be the latest block, as the two disjoint
        // ranges have been connected.
        assert_eq!(block_fully_scanned(&st), Some(end_height));
    }

    #[test]
    fn test_account_birthday() {
        let st = TestBuilder::new()
            .with_block_cache()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_id = st.test_account().unwrap().account_id();
        assert_matches!(
            account_birthday(&st.wallet().conn, account_id),
            Ok(birthday) if birthday == st.sapling_activation_height()
        )
    }
}
