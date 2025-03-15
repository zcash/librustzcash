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

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    io::{self, Cursor},
    num::NonZeroU32,
    ops::{Range, RangeInclusive},
    time::SystemTime,
};

use encoding::{
    account_kind_code, decode_diversifier_index_be, encode_diversifier_index_be, memo_repr,
    pool_code, KeyScope, ReceiverFlags,
};
use incrementalmerkletree::{Marking, Retention};
use rusqlite::{self, named_params, params, Connection, OptionalExtension};
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::ShardStore, ShardTree};
use tracing::{debug, warn};
use uuid::Uuid;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        scanning::{ScanPriority, ScanRange},
        Account as _, AccountBalance, AccountBirthday, AccountPurpose, AccountSource, AddressInfo,
        BlockMetadata, DecryptedTransaction, Progress, Ratio, SentTransaction,
        SentTransactionOutput, TransactionDataRequest, TransactionStatus, WalletSummary,
        Zip32Derivation, SAPLING_SHARD_HEIGHT,
    },
    wallet::{Note, NoteId, Recipient, WalletTx},
    DecryptedOutput,
};
use zcash_keys::{
    address::{Address, Receiver, UnifiedAddress},
    encoding::AddressCodec,
    keys::{
        AddressGenerationError, ReceiverRequirement, UnifiedAddressRequest, UnifiedFullViewingKey,
        UnifiedIncomingViewingKey, UnifiedSpendingKey,
    },
};
use zcash_primitives::{
    block::BlockHash,
    merkle_tree::read_commitment_tree,
    transaction::{Transaction, TransactionData},
};
use zcash_protocol::{
    consensus::{self, BlockHeight, BranchId, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
    value::{ZatBalance, Zatoshis},
    PoolType, ShieldedProtocol, TxId,
};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex};

use self::scanning::{parse_priority_code, priority_code, replace_queue_entries};
use crate::{
    error::SqliteClientError,
    util::Clock,
    wallet::commitment_tree::{get_max_checkpointed_height, SqliteShardStore},
    AccountRef, AccountUuid, AddressRef, SqlTransaction, TransferType, TxRef,
    WalletCommitmentTrees, WalletDb, PRUNING_DEPTH, SAPLING_TABLES_PREFIX, VERIFY_LOOKAHEAD,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::GapLimits,
    ::transparent::{
        bundle::{OutPoint, TxOut},
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    },
    std::collections::BTreeMap,
};

#[cfg(feature = "orchard")]
use {crate::ORCHARD_TABLES_PREFIX, zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT};

pub mod commitment_tree;
pub(crate) mod common;
mod db;
pub(crate) mod encoding;
pub mod init;
#[cfg(feature = "orchard")]
pub(crate) mod orchard;
pub(crate) mod sapling;
pub(crate) mod scanning;
#[cfg(feature = "transparent-inputs")]
pub(crate) mod transparent;

pub(crate) const BLOCK_SAPLING_FRONTIER_ABSENT: &[u8] = &[0x0];

/// A constant for use in converting Unix timestamps to shielded-only diversifier indices. The
/// value here is intended to be added to the current time, in seconds since the epoch, to obtain
/// an index that is greater than or equal to 2^32. While it would be possible to use indices in
/// the range 2^31..2^32, we wish to avoid any confusion with indices in the BIP 32 child
/// index derivation space.
///
/// 2^32 - (date --date "Oct 28, 2016 07:56 UTC" +%s)
pub(crate) const MIN_SHIELDED_DIVERSIFIER_OFFSET: u64 = 2817325936;

fn parse_account_source(
    account_kind: u32,
    hd_seed_fingerprint: Option<[u8; 32]>,
    hd_account_index: Option<u32>,
    spending_key_available: bool,
    key_source: Option<String>,
) -> Result<AccountSource, SqliteClientError> {
    let derivation = hd_seed_fingerprint
        .zip(hd_account_index)
        .map(|(seed_fp, idx)| {
            zip32::AccountId::try_from(idx)
                .map_err(|_| {
                    SqliteClientError::CorruptedData(
                        "ZIP-32 account ID from wallet DB is out of range.".to_string(),
                    )
                })
                .map(|idx| Zip32Derivation::new(SeedFingerprint::from_bytes(seed_fp), idx))
        })
        .transpose()?;

    match (account_kind, derivation) {
        (0, Some(derivation)) => Ok(AccountSource::Derived {
            derivation,
            key_source,
        }),
        (1, derivation) => Ok(AccountSource::Imported {
            purpose: if spending_key_available {
                AccountPurpose::Spending { derivation }
            } else {
                AccountPurpose::ViewOnly
            },
            key_source,
        }),
        (0, None) => Err(SqliteClientError::CorruptedData(
            "Wallet DB account_kind constraint violated".to_string(),
        )),
        (_, _) => Err(SqliteClientError::CorruptedData(
            "Unrecognized account_kind".to_string(),
        )),
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
    id: AccountRef,
    uuid: AccountUuid,
    name: Option<String>,
    kind: AccountSource,
    viewing_key: ViewingKey,
    birthday: BlockHeight,
}

impl Account {
    /// Returns the default Unified Address for the account, along with the diversifier index that
    /// generated it.
    ///
    /// The diversifier index may be non-zero if the Unified Address includes a Sapling
    /// receiver, and there was no valid Sapling receiver at diversifier index zero.
    pub(crate) fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.uivk().default_address(request)
    }

    pub(crate) fn internal_id(&self) -> AccountRef {
        self.id
    }

    pub(crate) fn birthday(&self) -> BlockHeight {
        self.birthday
    }
}

impl zcash_client_backend::data_api::Account for Account {
    type AccountId = AccountUuid;

    fn id(&self) -> AccountUuid {
        self.uuid
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn source(&self) -> &AccountSource {
        &self.kind
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

    // `UnifiedIncomingViewingKey`s are not comparable with `Eq`, but Unified Address
    // components are, so we derive corresponding addresses for each key and use
    // those to check whether any components match.
    let uivk_match = {
        let usk = UnifiedSpendingKey::from_seed(params, &seed.expose_secret()[..], account_index)
            .map_err(|_| SqliteClientError::KeyDerivationError(account_index))?;

        let (seed_addr, _) = usk
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)?;
        let (uivk_addr, _) = uivk.default_address(UnifiedAddressRequest::AllAvailableKeys)?;

        #[cfg(not(feature = "orchard"))]
        let orchard_match = false;
        #[cfg(feature = "orchard")]
        let orchard_match = seed_addr
            .orchard()
            .zip(uivk_addr.orchard())
            .map(|(a, b)| a == b)
            == Some(true);

        let sapling_match = seed_addr
            .sapling()
            .zip(uivk_addr.sapling())
            .map(|(a, b)| a == b)
            == Some(true);

        let p2pkh_match = seed_addr
            .transparent()
            .zip(uivk_addr.transparent())
            .map(|(a, b)| a == b)
            == Some(true);

        orchard_match || sapling_match || p2pkh_match
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

// Returns the highest used account index for a given seed.
pub(crate) fn max_zip32_account_index(
    conn: &rusqlite::Connection,
    seed_id: &SeedFingerprint,
) -> Result<Option<zip32::AccountId>, SqliteClientError> {
    conn.query_row_and_then(
        "SELECT MAX(hd_account_index) FROM accounts WHERE hd_seed_fingerprint = :hd_seed",
        [seed_id.to_bytes()],
        |row| {
            row.get::<_, Option<u32>>(0)?
                .map(zip32::AccountId::try_from)
                .transpose()
                .map_err(|_| SqliteClientError::Zip32AccountIndexOutOfRange)
        },
    )
}

pub(crate) fn add_account<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_name: &str,
    kind: &AccountSource,
    viewing_key: ViewingKey,
    birthday: &AccountBirthday,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
) -> Result<Account, SqliteClientError> {
    if let Some(ufvk) = viewing_key.ufvk() {
        // Check whether any component of this UFVK collides with an existing imported or derived FVK.
        if let Some(existing_account) = get_account_for_ufvk(conn, params, ufvk)? {
            return Err(SqliteClientError::AccountCollision(existing_account.id()));
        }
    }
    // TODO(#1490): check for IVK collisions.

    let account_uuid = AccountUuid(Uuid::new_v4());

    let (derivation, spending_key_available, key_source) = match kind {
        AccountSource::Derived {
            derivation,
            key_source,
        } => (Some(derivation), true, key_source),
        AccountSource::Imported {
            purpose: AccountPurpose::Spending { derivation },
            key_source,
        } => (derivation.as_ref(), true, key_source),
        AccountSource::Imported {
            purpose: AccountPurpose::ViewOnly,
            key_source,
        } => (None, false, key_source),
    };

    #[cfg(feature = "orchard")]
    let orchard_item = viewing_key
        .ufvk()
        .and_then(|ufvk| ufvk.orchard().map(|k| k.to_bytes()));
    #[cfg(not(feature = "orchard"))]
    let orchard_item: Option<Vec<u8>> = None;

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

    let ufvk_encoded = viewing_key.ufvk().map(|ufvk| ufvk.encode(params));
    let account_id = conn
        .query_row(
            r#"
            INSERT INTO accounts (
                name,
                uuid,
                account_kind, hd_seed_fingerprint, hd_account_index, key_source,
                ufvk, uivk,
                orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
                birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                recover_until_height,
                has_spend_key
            )
            VALUES (
                :account_name,
                :uuid,
                :account_kind, :hd_seed_fingerprint, :hd_account_index, :key_source,
                :ufvk, :uivk,
                :orchard_fvk_item_cache, :sapling_fvk_item_cache, :p2pkh_fvk_item_cache,
                :birthday_height, :birthday_sapling_tree_size, :birthday_orchard_tree_size,
                :recover_until_height,
                :has_spend_key
            )
            RETURNING id
            "#,
            named_params![
                ":account_name": account_name,
                ":uuid": account_uuid.0,
                ":account_kind": account_kind_code(kind),
                ":hd_seed_fingerprint": derivation.map(|d| d.seed_fingerprint().to_bytes()),
                ":hd_account_index": derivation.map(|d| u32::from(d.account_index())),
                ":key_source": key_source,
                ":ufvk": ufvk_encoded,
                ":uivk": viewing_key.uivk().encode(params),
                ":orchard_fvk_item_cache": orchard_item,
                ":sapling_fvk_item_cache": sapling_item,
                ":p2pkh_fvk_item_cache": transparent_item,
                ":birthday_height": u32::from(birthday.height()),
                ":birthday_sapling_tree_size": birthday_sapling_tree_size,
                ":birthday_orchard_tree_size": birthday_orchard_tree_size,
                ":recover_until_height": birthday.recover_until().map(u32::from),
                ":has_spend_key": spending_key_available as i64,
            ],
            |row| row.get(0).map(AccountRef),
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, s)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                // An account conflict occurred. This should already have been caught by
                // the check using `get_account_for_ufvk` above, but in case it wasn't,
                // make a best effort to determine the AccountRef of the pre-existing row
                // and provide that to our caller.
                if let Ok(colliding_uuid) = conn.query_row(
                    "SELECT uuid FROM accounts WHERE ufvk = ?",
                    params![ufvk_encoded],
                    |row| Ok(AccountUuid(row.get(0)?)),
                ) {
                    return SqliteClientError::AccountCollision(colliding_uuid);
                }

                SqliteClientError::from(rusqlite::Error::SqliteFailure(f, s))
            }
            _ => SqliteClientError::from(e),
        })?;

    let account = Account {
        id: account_id,
        name: Some(account_name.to_owned()),
        uuid: account_uuid,
        kind: kind.clone(),
        viewing_key,
        birthday: birthday.height(),
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
                marking: Marking::Reference,
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
                marking: Marking::Reference,
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
    if let Some(t) = chain_tip_height(conn)? {
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

    // Always derive the default Unified Address for the account. If the account's viewing
    // key has fewer components than the wallet supports (most likely due to this being an
    // imported viewing key), derive an address containing the common subset of receivers.
    let (address, d_idx) = account.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
    upsert_address(
        conn,
        params,
        account_id,
        d_idx,
        &address,
        Some(birthday.height()),
        false,
    )?;

    // Pre-generate transparent addresses up to the gap limits for the external, internal,
    // and ephemeral key scopes.
    #[cfg(feature = "transparent-inputs")]
    for key_scope in [KeyScope::EXTERNAL, KeyScope::INTERNAL, KeyScope::Ephemeral] {
        use ReceiverRequirement::*;
        transparent::generate_gap_addresses(
            conn,
            params,
            account_id,
            key_scope,
            gap_limits,
            UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
            false,
        )?;
    }

    Ok(account)
}

pub(crate) fn get_next_available_address<P: consensus::Parameters, C: Clock>(
    conn: &rusqlite::Transaction,
    params: &P,
    clock: &C,
    account_uuid: AccountUuid,
    request: UnifiedAddressRequest,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqliteClientError> {
    let account: Account = match get_account(conn, params, account_uuid)? {
        Some(account) => account,
        None => {
            return Ok(None);
        }
    };

    // This will also ensure that the provided request can be satisfied by the account's UIVK
    let requirements = account.uivk().receiver_requirements(request)?;

    let (addr, diversifier_index) = if requirements.p2pkh() == ReceiverRequirement::Require {
        #[cfg(not(feature = "transparent-inputs"))]
        {
            return Err(SqliteClientError::AddressGeneration(
                AddressGenerationError::ReceiverTypeNotSupported(
                    zcash_address::unified::Typecode::P2pkh,
                ),
            ));
        }

        // If a p2pkh receiver is required, return the first un-exposed address from within the
        // transparent gap limit.
        #[cfg(feature = "transparent-inputs")]
        {
            use ReceiverRequirement::*;
            // First, ensure that we have pre-generated as many addresses as we can.
            transparent::generate_gap_addresses(
                conn,
                params,
                account.internal_id(),
                KeyScope::EXTERNAL,
                gap_limits,
                UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                true,
            )?;

            // Select indices from the transparent gap limit that are available for use as
            // diversifier indices.
            let (gap_start, addrs) = transparent::select_addrs_to_reserve(
                conn,
                params,
                account.internal_id(),
                KeyScope::EXTERNAL,
                gap_limits.external(),
                gap_limits
                    .external()
                    .try_into()
                    .expect("gap limit fits in usize"),
            )?;

            // Find the first index that generates an address conforming to the request.
            addrs
                .iter()
                .find_map(|(_, _, meta)| {
                    let j = DiversifierIndex::from(meta.address_index());
                    account.uivk().address(j, request).ok().map(|ua| (ua, j))
                })
                .ok_or(SqliteClientError::ReachedGapLimit(
                    TransparentKeyScope::EXTERNAL,
                    gap_start.index() + gap_limits.external(),
                ))?
        }
    } else {
        // compute a base diversifier index from the timestamp
        let mut j = DiversifierIndex::from(
            clock
                .now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time is valid")
                .as_secs()
                .saturating_add(MIN_SHIELDED_DIVERSIFIER_OFFSET),
        );

        let mut find_collision = conn.prepare(
            "SELECT exposed_at_height
             FROM addresses
             WHERE account_id = :account_id
             AND key_scope = :key_scope
             AND diversifier_index_be = :diversifier_index_be",
        )?;

        // search the diversifier space for a diversifier index that creates a valid address
        // satisfying the request and is currently not used in an exposed address
        loop {
            let found_addr = account.uivk().find_address(j, request)?;
            let collision = find_collision
                .query_row(
                    named_params! {
                        ":account_id": account.internal_id().0,
                        ":key_scope": KeyScope::EXTERNAL.encode(),
                        ":diversifier_index_be": &encode_diversifier_index_be(found_addr.1)
                    },
                    |row| row.get::<_, Option<u32>>(0),
                )
                .optional()?
                .flatten();

            if collision.is_none() {
                break found_addr;
            } else {
                j.increment().map_err(|_| {
                    SqliteClientError::AddressGeneration(
                        AddressGenerationError::DiversifierSpaceExhausted,
                    )
                })?;
            }
        }
    };

    let chain_tip_height = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;
    upsert_address(
        conn,
        params,
        account.internal_id(),
        diversifier_index,
        &addr,
        Some(chain_tip_height),
        true,
    )?;

    Ok(Some((addr, diversifier_index)))
}

pub(crate) fn list_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
) -> Result<Vec<AddressInfo>, SqliteClientError> {
    let mut addrs = vec![];

    let mut stmt_addrs = conn.prepare(
        "SELECT address, diversifier_index_be, key_scope
         FROM addresses
         JOIN accounts ON accounts.id = addresses.account_id
         WHERE accounts.uuid = :account_uuid
         AND exposed_at_height IS NOT NULL
         ORDER BY exposed_at_height ASC, diversifier_index_be ASC",
    )?;

    let mut rows = stmt_addrs.query(named_params![
        ":account_uuid": account_uuid.0,
    ])?;

    while let Some(row) = rows.next()? {
        let addr_str: String = row.get(0)?;
        let di_vec: Vec<u8> = row.get(1)?;
        let _scope = KeyScope::decode(row.get(2)?)?;

        let addr = Address::decode(params, &addr_str).ok_or_else(|| {
            SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
        })?;
        let diversifier_index = decode_diversifier_index_be(&di_vec)?;
        // Sapling and Unified addresses always have external scope.
        #[cfg(feature = "transparent-inputs")]
        let transparent_scope =
            matches!(addr, Address::Transparent(_) | Address::Tex(_)).then(|| _scope.into());

        addrs.push(
            AddressInfo::from_parts(
                addr,
                diversifier_index,
                #[cfg(feature = "transparent-inputs")]
                transparent_scope,
            )
            .expect("valid"),
        );
    }

    Ok(addrs)
}

pub(crate) fn get_last_generated_address_matching<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
    address_filter: UnifiedAddressRequest,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqliteClientError> {
    let account: Account =
        get_account(conn, params, account_uuid)?.ok_or(SqliteClientError::AccountUnknown)?;

    let requirements = account
        .uivk()
        .receiver_requirements(address_filter)
        .map_err(|_| {
            SqliteClientError::BadAccountData(
                "Could not generate UnifiedAddressRequest for UIVK".to_string(),
            )
        })?;
    let require_flags = ReceiverFlags::required(requirements);
    let omit_flags = ReceiverFlags::omitted(requirements);
    // This returns the most recently exposed external-scope address (the address that was exposed
    // at the greatest block height, using the largest diversifier index to break ties)
    // that conforms to the specified requirements.
    let addr: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT address, diversifier_index_be
             FROM addresses
             WHERE account_id = :account_id
             AND key_scope = :key_scope
             AND (receiver_flags & :require_flags) = :require_flags
             AND (receiver_flags & :omit_flags) = 0
             AND exposed_at_height IS NOT NULL
             ORDER BY exposed_at_height DESC, diversifier_index_be DESC
             LIMIT 1",
            named_params![
                ":account_id": account.internal_id().0,
                ":key_scope": KeyScope::EXTERNAL.encode(),
                ":require_flags": require_flags.bits(),
                ":omit_flags": omit_flags.bits(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    addr.map(|(addr_str, di_vec)| {
        let diversifier_index = decode_diversifier_index_be(&di_vec)?;
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
            .map(|addr| (addr, diversifier_index))
    })
    .transpose()
}

/// Adds the given external address and diversifier index to the addresses table.
///
/// Returns the primary key identifier for the newly-inserted address.
///
/// ## Parameters
/// - `account_id`: The account that the address was generated for.
/// - `diversifier_index`: The diversifier index used to generate the address.
/// - `address`: The unified address itself.
/// - `exposed_at_height`: The block height at the earliest time that the address may have been
///   exposed to a user, assuming a single generator of addresses.
/// - `force_update_address`: If this argument is set to `true`, an address has already been
///   inserted for the given account and diversifier index, and the `exposed_at_height` column
///   is currently `NULL` (i.e. the address at this diversifier index has not yet been exposed)
///   then the value of the `address` column will be replaced with the provided address.
pub(crate) fn upsert_address<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountRef,
    diversifier_index: DiversifierIndex,
    address: &UnifiedAddress,
    exposed_at_height: Option<BlockHeight>,
    force_update_address: bool,
) -> Result<AddressRef, SqliteClientError> {
    // the diversifier index is stored in big-endian order to allow sorting
    let di_be = encode_diversifier_index_be(diversifier_index);

    // If a force-update was requested, check whether an address has previously been exposed for
    // this diversifier index. If so, and if that address differs from the given address, return an
    // error.
    if force_update_address {
        let previously_exposed_as = conn
            .query_row(
                "SELECT address, exposed_at_height
                 FROM addresses
                 WHERE account_id = :account_id
                 AND diversifier_index_be = :diversifier_index_be
                 AND key_scope = :key_scope",
                named_params![
                    ":account_id": account_id.0,
                    ":diversifier_index_be": di_be,
                    ":key_scope": KeyScope::EXTERNAL.encode(),
                ],
                |row| {
                    let address = row.get::<_, String>("address")?;
                    let exposed_at = row.get::<_, Option<u32>>("exposed_at_height")?;
                    Ok(exposed_at.map(|_| address))
                },
            )
            .optional()?
            .flatten()
            .map(|addr_str| UnifiedAddress::decode(params, &addr_str))
            .transpose()
            .map_err(SqliteClientError::CorruptedData)?;

        match previously_exposed_as {
            Some(addr) if &addr != address => {
                return Err(SqliteClientError::DiversifierIndexReuse(
                    diversifier_index,
                    Box::new(addr),
                ));
            }
            _ => (),
        }
    }

    let mut stmt = conn.prepare_cached(
        "INSERT INTO addresses (
            account_id,
            diversifier_index_be,
            key_scope,
            address,
            transparent_child_index,
            cached_transparent_receiver_address,
            exposed_at_height,
            receiver_flags
        )
        VALUES (
            :account_id,
            :diversifier_index_be,
            :key_scope,
            :address,
            :transparent_child_index,
            :cached_transparent_receiver_address,
            :exposed_at_height,
            :receiver_flags
        )
        ON CONFLICT (account_id, diversifier_index_be, key_scope) DO UPDATE
        SET exposed_at_height = COALESCE(
                MIN(exposed_at_height, :exposed_at_height),
                exposed_at_height,
                :exposed_at_height
            ),
            address = IIF(
                exposed_at_height IS NULL AND :force_update_address,
                :address,
                address
            ),
            receiver_flags = IIF(
                exposed_at_height IS NULL AND :force_update_address,
                :receiver_flags,
                receiver_flags
            )
        RETURNING id",
    )?;

    #[cfg(feature = "transparent-inputs")]
    let (transparent_child_index, cached_taddr) = {
        let idx = NonHardenedChildIndex::try_from(diversifier_index)
            .ok()
            .map(|i| i.index());

        // This upholds the `transparent_index_consistency` check on the `addresses` table.
        match (idx, address.transparent()) {
            (Some(idx), Some(r)) => Ok((Some(idx), Some(r.encode(params)))),
            (_, None) => Ok((None, None)),
            (None, Some(addr)) => Err(SqliteClientError::AddressNotRecognized(*addr)),
        }
    }?;

    #[cfg(not(feature = "transparent-inputs"))]
    let (transparent_child_index, cached_taddr): (Option<u32>, Option<String>) = (None, None);

    stmt.query_row(
        named_params![
            ":account_id": account_id.0,
            // the diversifier index is stored in big-endian order to allow sorting
            ":diversifier_index_be": &di_be,
            ":key_scope": KeyScope::EXTERNAL.encode(),
            ":address": &address.encode(params),
            ":transparent_child_index": transparent_child_index,
            ":cached_transparent_receiver_address": &cached_taddr,
            ":exposed_at_height": exposed_at_height.map(u32::from),
            ":force_update_address": force_update_address,
            ":receiver_flags": ReceiverFlags::from(address).bits()
        ],
        |row| row.get(0).map(AddressRef),
    )
    .map_err(SqliteClientError::from)
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn involved_accounts(
    conn: &rusqlite::Connection,
    tx_refs: impl IntoIterator<Item = TxRef>,
) -> Result<Vec<(AccountRef, KeyScope)>, SqliteClientError> {
    use rusqlite::types::Value;
    use std::rc::Rc;

    let mut stmt = conn.prepare_cached(
        "SELECT account_id, key_scope
         FROM v_address_uses
         WHERE transaction_id IN rarray(:tx_refs_ptr)",
    )?;

    let tx_refs_values: Vec<Value> = tx_refs.into_iter().map(|r| Value::Integer(r.0)).collect();
    let tx_refs_ptr = Rc::new(tx_refs_values);
    let result = stmt
        .query_and_then(
            named_params! {
                ":tx_refs_ptr": &tx_refs_ptr
            },
            |row| {
                Ok::<_, SqliteClientError>((
                    row.get(0).map(AccountRef)?,
                    KeyScope::decode(row.get(1)?)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(result)
}

/// Returns the [`UnifiedFullViewingKey`]s for the wallet.
pub(crate) fn get_unified_full_viewing_keys<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<HashMap<AccountUuid, UnifiedFullViewingKey>, SqliteClientError> {
    // Fetch the UnifiedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts = conn.prepare("SELECT uuid, ufvk FROM accounts")?;

    let rows = stmt_fetch_accounts.query_map([], |row| {
        let ufvk_str: Option<String> = row.get(1)?;
        if let Some(ufvk_str) = ufvk_str {
            let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
                .map_err(SqliteClientError::CorruptedData);
            Ok(Some((AccountUuid(row.get(0)?), ufvk)))
        } else {
            Ok(None)
        }
    })?;

    let mut res: HashMap<AccountUuid, UnifiedFullViewingKey> = HashMap::new();
    for row in rows {
        if let Some((account_id, ufvkr)) = row? {
            res.insert(account_id, ufvkr?);
        }
    }

    Ok(res)
}

fn parse_account_row<P: consensus::Parameters>(
    row: &rusqlite::Row<'_>,
    params: &P,
) -> Result<Account, SqliteClientError> {
    let account_id = AccountRef(row.get("id")?);
    let account_name = row.get("name")?;
    let account_uuid = AccountUuid(row.get("uuid")?);
    let kind = parse_account_source(
        row.get("account_kind")?,
        row.get("hd_seed_fingerprint")?,
        row.get("hd_account_index")?,
        row.get("has_spend_key")?,
        row.get("key_source")?,
    )?;

    let ufvk_str: Option<String> = row.get("ufvk")?;
    let viewing_key = if let Some(ufvk_str) = ufvk_str {
        ViewingKey::Full(Box::new(
            UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                SqliteClientError::CorruptedData(format!(
                    "Could not decode unified full viewing key for account {}: {}",
                    account_uuid.0, e
                ))
            })?,
        ))
    } else {
        let uivk_str: String = row.get("uivk")?;
        ViewingKey::Incoming(Box::new(
            UnifiedIncomingViewingKey::decode(params, &uivk_str).map_err(|e| {
                SqliteClientError::CorruptedData(format!(
                    "Could not decode unified incoming viewing key for account {}: {}",
                    account_uuid.0, e
                ))
            })?,
        ))
    };

    let birthday = BlockHeight::from(row.get::<_, u32>("birthday_height")?);

    Ok(Account {
        id: account_id,
        name: account_name,
        uuid: account_uuid,
        kind,
        viewing_key,
        birthday,
    })
}

pub(crate) fn get_account<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
) -> Result<Option<Account>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, name, uuid, account_kind,
               hd_seed_fingerprint, hd_account_index, key_source,
               ufvk, uivk, has_spend_key, birthday_height
        FROM accounts
        WHERE uuid = :account_uuid
        "#,
    )?;

    let mut rows = stmt.query_and_then::<_, SqliteClientError, _, _>(
        named_params![":account_uuid": account_uuid.0],
        |row| parse_account_row(row, params),
    )?;

    rows.next().transpose()
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_account_internal<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountRef,
) -> Result<Option<Account>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, name, uuid, account_kind,
               hd_seed_fingerprint, hd_account_index, key_source,
               ufvk, uivk, has_spend_key, birthday_height
        FROM accounts
        WHERE id = :account_id
        "#,
    )?;

    let mut rows = stmt.query_and_then::<_, SqliteClientError, _, _>(
        named_params![":account_id": account_id.0],
        |row| parse_account_row(row, params),
    )?;

    rows.next().transpose()
}

/// Returns the account id corresponding to a given [`UnifiedFullViewingKey`],
/// if any.
pub(crate) fn get_account_for_ufvk<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    ufvk: &UnifiedFullViewingKey,
) -> Result<Option<Account>, SqliteClientError> {
    #[cfg(feature = "orchard")]
    let orchard_item = ufvk.orchard().map(|k| k.to_bytes());
    #[cfg(not(feature = "orchard"))]
    let orchard_item: Option<Vec<u8>> = None;

    let sapling_item = ufvk.sapling().map(|k| k.to_bytes());

    #[cfg(feature = "transparent-inputs")]
    let transparent_item = ufvk.transparent().map(|k| k.serialize());
    #[cfg(not(feature = "transparent-inputs"))]
    let transparent_item: Option<Vec<u8>> = None;

    let mut stmt = conn.prepare(
        "SELECT id, name, uuid, account_kind,
                hd_seed_fingerprint, hd_account_index, key_source,
                ufvk, uivk, has_spend_key, birthday_height
         FROM accounts
         WHERE orchard_fvk_item_cache = :orchard_fvk_item_cache
            OR sapling_fvk_item_cache = :sapling_fvk_item_cache
            OR p2pkh_fvk_item_cache = :p2pkh_fvk_item_cache",
    )?;

    let accounts = stmt
        .query_and_then::<_, SqliteClientError, _, _>(
            named_params![
                ":orchard_fvk_item_cache": orchard_item,
                ":sapling_fvk_item_cache": sapling_item,
                ":p2pkh_fvk_item_cache": transparent_item,
            ],
            |row| parse_account_row(row, params),
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
    seed_fp: &SeedFingerprint,
    account_index: zip32::AccountId,
) -> Result<Option<Account>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, key_source, uuid, ufvk, birthday_height
         FROM accounts
         WHERE hd_seed_fingerprint = :hd_seed_fingerprint
         AND hd_account_index = :hd_account_index",
    )?;

    let mut accounts = stmt.query_and_then::<_, SqliteClientError, _, _>(
        named_params![
            ":hd_seed_fingerprint": seed_fp.to_bytes(),
            ":hd_account_index": u32::from(account_index),
        ],
        |row| {
            let account_id = AccountRef(row.get("id")?);
            let account_name = row.get("name")?;
            let key_source = row.get("key_source")?;
            let account_uuid = AccountUuid(row.get("uuid")?);
            let ufvk = match row.get::<_, Option<String>>("ufvk")? {
                None => Err(SqliteClientError::CorruptedData(format!(
                    "Missing unified full viewing key for derived account {}",
                    account_uuid.0,
                ))),
                Some(ufvk_str) => UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                    SqliteClientError::CorruptedData(format!(
                        "Could not decode unified full viewing key for account {}: {}",
                        account_uuid.0, e
                    ))
                }),
            }?;
            let birthday = BlockHeight::from(row.get::<_, u32>("birthday_height")?);

            Ok(Account {
                id: account_id,
                name: account_name,
                uuid: account_uuid,
                kind: AccountSource::Derived {
                    derivation: Zip32Derivation::new(*seed_fp, account_index),
                    key_source,
                },
                viewing_key: ViewingKey::Full(Box::new(ufvk)),
                birthday,
            })
        },
    )?;

    accounts.next().transpose()
}

pub(crate) trait ProgressEstimator {
    fn sapling_scan_progress<P: consensus::Parameters>(
        &self,
        conn: &rusqlite::Connection,
        params: &P,
        birthday_height: BlockHeight,
        recover_until_height: Option<BlockHeight>,
        fully_scanned_height: Option<BlockHeight>,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Progress>, SqliteClientError>;

    #[cfg(feature = "orchard")]
    fn orchard_scan_progress<P: consensus::Parameters>(
        &self,
        conn: &rusqlite::Connection,
        params: &P,
        birthday_height: BlockHeight,
        recover_until_height: Option<BlockHeight>,
        fully_scanned_height: Option<BlockHeight>,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Progress>, SqliteClientError>;
}

#[derive(Debug)]
pub(crate) struct SubtreeProgressEstimator;

fn table_constants(
    shielded_protocol: ShieldedProtocol,
) -> Result<(&'static str, &'static str, u8), SqliteClientError> {
    match shielded_protocol {
        ShieldedProtocol::Sapling => Ok((
            SAPLING_TABLES_PREFIX,
            "sapling_output_count",
            SAPLING_SHARD_HEIGHT,
        )),
        #[cfg(feature = "orchard")]
        ShieldedProtocol::Orchard => Ok((
            ORCHARD_TABLES_PREFIX,
            "orchard_action_count",
            ORCHARD_SHARD_HEIGHT,
        )),
        #[cfg(not(feature = "orchard"))]
        ShieldedProtocol::Orchard => Err(SqliteClientError::UnsupportedPoolType(PoolType::ORCHARD)),
    }
}

fn estimate_tree_size<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    shielded_protocol: ShieldedProtocol,
    pool_activation_height: BlockHeight,
    chain_tip_height: BlockHeight,
) -> Result<Option<u64>, SqliteClientError> {
    let (table_prefix, _, shard_height) = table_constants(shielded_protocol)?;

    // Estimate the size of the tree by linear extrapolation from available
    // data closest to the chain tip.
    //
    // - If we have scanned blocks within the incomplete subtree, and we know
    //   the tree size for the end of the most recent scanned range, then we
    //   extrapolate from the start of the incomplete subtree:
    //
    //         subtree
    //         /     \
    //       /         \
    //     /             \
    //   /                 \
    //   |<--------->|  |
    //     | scanned |  tip
    //           last_scanned
    //
    //
    //             subtree
    //             /     \
    //           /         \
    //         /             \
    //       /                 \
    //       |<------->|    |
    //   |   scanned   |    tip
    //             last_scanned
    //
    // - If we don't have scanned blocks within the incomplete subtree, or we
    //   don't know the tree size, then we extrapolate from the block-width of
    //   the last complete subtree.
    //
    // This avoids having a sharp discontinuity in the progress percentages
    // shown to users, and gets more accurate the closer to the chain tip we
    // have scanned.
    //
    // TODO: it would be nice to be able to reliably have the size of the
    // commitment tree at the chain tip without having to have scanned that
    // block.

    // Get the tree size at the last scanned height, if known.
    let last_scanned = block_max_scanned(conn, params)?.and_then(|last_scanned| {
        match shielded_protocol {
            ShieldedProtocol::Sapling => last_scanned.sapling_tree_size(),
            #[cfg(feature = "orchard")]
            ShieldedProtocol::Orchard => last_scanned.orchard_tree_size(),
            #[cfg(not(feature = "orchard"))]
            ShieldedProtocol::Orchard => None,
        }
        .map(|tree_size| (last_scanned.block_height(), u64::from(tree_size)))
    });

    // Get the last completed subtree.
    let last_completed_subtree = conn
        .query_row(
            &format!(
                "SELECT shard_index, subtree_end_height
                 FROM {table_prefix}_tree_shards
                 WHERE subtree_end_height IS NOT NULL
                 ORDER BY shard_index DESC
                 LIMIT 1"
            ),
            [],
            |row| {
                Ok((
                    incrementalmerkletree::Address::from_parts(
                        incrementalmerkletree::Level::new(shard_height),
                        row.get(0)?,
                    ),
                    BlockHeight::from_u32(row.get(1)?),
                ))
            },
        )
        // `None` if we have no subtree roots yet.
        .optional()?;

    let result = if let Some((last_completed_subtree, last_completed_subtree_end)) =
        last_completed_subtree
    {
        // If we know the tree size at the last scanned height, and that
        // height is within the incomplete subtree, extrapolate.
        let tip_tree_size = last_scanned.and_then(|(last_scanned, last_scanned_tree_size)| {
            (last_scanned > last_completed_subtree_end)
                .then(|| {
                    let scanned_notes = last_scanned_tree_size
                        - u64::from(last_completed_subtree.position_range_end());
                    let scanned_range = u64::from(last_scanned - last_completed_subtree_end);
                    let unscanned_range = u64::from(chain_tip_height - last_scanned);

                    (scanned_notes * unscanned_range)
                        .checked_div(scanned_range)
                        .map(|extrapolated_unscanned_notes| {
                            last_scanned_tree_size + extrapolated_unscanned_notes
                        })
                })
                .flatten()
        });

        if let Some(tree_size) = tip_tree_size {
            Some(tree_size)
        } else if let Some(second_to_last_completed_subtree_end) = last_completed_subtree
            .index()
            .checked_sub(1)
            .and_then(|subtree_index| {
                conn.query_row(
                    &format!(
                        "SELECT subtree_end_height
                         FROM {table_prefix}_tree_shards
                         WHERE shard_index = :shard_index"
                    ),
                    named_params! {":shard_index": subtree_index},
                    |row| Ok(row.get::<_, Option<_>>(0)?.map(BlockHeight::from_u32)),
                )
                .transpose()
            })
            .transpose()?
        {
            let notes_in_complete_subtrees = u64::from(last_completed_subtree.position_range_end());

            let subtree_notes = 1 << shard_height;
            let subtree_range =
                u64::from(last_completed_subtree_end - second_to_last_completed_subtree_end);
            let unscanned_range = u64::from(chain_tip_height - last_completed_subtree_end);

            (subtree_notes * unscanned_range)
                .checked_div(subtree_range)
                .map(|extrapolated_incomplete_subtree_notes| {
                    notes_in_complete_subtrees + extrapolated_incomplete_subtree_notes
                })
        } else {
            // There's only one completed subtree; its start height must
            // be the activation height for this shielded protocol.
            let subtree_notes = 1 << shard_height;

            let subtree_range = u64::from(last_completed_subtree_end - pool_activation_height);
            let unscanned_range = u64::from(chain_tip_height - last_completed_subtree_end);

            (subtree_notes * unscanned_range)
                .checked_div(subtree_range)
                .map(|extrapolated_incomplete_subtree_notes| {
                    subtree_notes + extrapolated_incomplete_subtree_notes
                })
        }
    } else {
        // If there are no completed subtrees, but we have scanned some blocks, we can still
        // interpolate based upon the tree size as of the last scanned block. Here, since we
        // don't have any subtree data to draw on, we will interpolate based on the number of
        // blocks since the pool activation height
        last_scanned.and_then(|(last_scanned_height, last_scanned_tree_size)| {
            let subtree_range = u64::from(last_scanned_height - pool_activation_height);
            let unscanned_range = u64::from(chain_tip_height - last_scanned_height);

            (last_scanned_tree_size * unscanned_range)
                .checked_div(subtree_range)
                .map(|extrapolated_incomplete_subtree_notes| {
                    last_scanned_tree_size + extrapolated_incomplete_subtree_notes
                })
        })
    };

    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn subtree_scan_progress<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    shielded_protocol: ShieldedProtocol,
    pool_activation_height: BlockHeight,
    birthday_height: BlockHeight,
    recover_until_height: Option<BlockHeight>,
    fully_scanned_height: Option<BlockHeight>,
    chain_tip_height: BlockHeight,
) -> Result<Option<Progress>, SqliteClientError> {
    let (table_prefix, output_count_col, shard_height) = table_constants(shielded_protocol)?;

    let mut stmt_scanned_count_until = conn.prepare_cached(&format!(
        "SELECT SUM({output_count_col})
        FROM blocks
        WHERE :start_height <= height AND height < :end_height",
    ))?;
    let mut stmt_scanned_count_from = conn.prepare_cached(&format!(
        "SELECT SUM({output_count_col})
        FROM blocks
        WHERE :start_height <= height",
    ))?;
    let mut stmt_start_tree_size = conn.prepare_cached(&format!(
        "SELECT MAX({table_prefix}_commitment_tree_size - {output_count_col})
        FROM blocks
        WHERE height <= :start_height",
    ))?;
    let mut stmt_end_tree_size_at = conn.prepare_cached(&format!(
        "SELECT {table_prefix}_commitment_tree_size
        FROM blocks
        WHERE height = :height",
    ))?;

    if fully_scanned_height == Some(chain_tip_height) {
        // Compute the total blocks scanned since the wallet birthday on either side of
        // the recover-until height.
        let recover = match recover_until_height {
            Some(end_height) => stmt_scanned_count_until.query_row(
                named_params! {
                    ":start_height": u32::from(birthday_height),
                    ":end_height": u32::from(end_height),
                },
                |row| {
                    let recovered = row.get::<_, Option<u64>>(0)?;
                    Ok(recovered.map(|n| Ratio::new(n, n)))
                },
            )?,
            None => {
                // If none of the wallet's accounts have a recover-until height, then there
                // is no recovery phase for the wallet, and therefore the denominator in the
                // resulting ratio (the number of notes in the recovery range) is zero.
                Some(Ratio::new(0, 0))
            }
        };

        let scan = stmt_scanned_count_from.query_row(
            named_params! {
                ":start_height": u32::from(
                    recover_until_height.unwrap_or(birthday_height)
                ),
            },
            |row| {
                let scanned = row.get::<_, Option<u64>>(0)?;
                Ok(scanned.map(|n| Ratio::new(n, n)))
            },
        )?;

        Ok(scan.map(|scan| Progress::new(scan, recover)))
    } else {
        // In case we didn't have information about the tree size at the recover-until
        // height, get the tree size from a nearby subtree. It's fine for this to be
        // approximate; it just shifts the boundary between scan and recover progress.
        let mut get_tree_size_near = |as_of: BlockHeight| {
            let size_from_blocks = stmt_start_tree_size
                .query_row(named_params![":start_height": u32::from(as_of)], |row| {
                    row.get::<_, Option<u64>>(0)
                })
                .optional()?
                .flatten();

            let size_from_subtree_roots = || {
                conn.query_row(
                    &format!(
                        "SELECT MIN(shard_index)
                             FROM {table_prefix}_tree_shards
                             WHERE subtree_end_height >= :start_height
                             OR subtree_end_height IS NULL",
                    ),
                    named_params! {
                        ":start_height": u32::from(as_of),
                    },
                    |row| {
                        let min_tree_size = row
                            .get::<_, Option<u64>>(0)?
                            .map(|min_idx| min_idx << shard_height);
                        Ok(min_tree_size)
                    },
                )
                .optional()
                .map(|opt| opt.flatten())
            };

            match size_from_blocks {
                Some(size) => Ok(Some(size)),
                None => size_from_subtree_roots(),
            }
        };

        // Get the starting note commitment tree size from the wallet birthday, or failing that
        // from the blocks table.
        let birthday_size = match conn
            .query_row(
                &format!(
                    "SELECT birthday_{table_prefix}_tree_size
                     FROM accounts
                     WHERE birthday_height = :birthday_height",
                ),
                named_params![":birthday_height": u32::from(birthday_height)],
                |row| row.get::<_, Option<u64>>(0),
            )
            .optional()?
            .flatten()
        {
            Some(tree_size) => Some(tree_size),
            // If we don't have an explicit birthday tree size, find something nearby.
            None => get_tree_size_near(birthday_height)?,
        };

        // Get the note commitment tree size as of the start of the recover-until height.
        // The outer option indicates whether or not we have recover-until height information;
        // the inner option indicates whether or not we were able to obtain a tree size given
        // the recover-until height.
        let recover_until_size: Option<Option<u64>> = recover_until_height
            // Find a tree size near to the recover-until height
            .map(get_tree_size_near)
            .transpose()?;

        // Count the total outputs scanned so far on the birthday side of the recover-until height.
        let recovered_count = recover_until_height
            .map(|end_height| {
                stmt_scanned_count_until.query_row(
                    named_params! {
                        ":start_height": u32::from(birthday_height),
                        ":end_height": u32::from(end_height),
                    },
                    |row| row.get::<_, Option<u64>>(0),
                )
            })
            .transpose()?;

        // If we've scanned the block at the chain tip, we know how many notes are currently in the
        // tree.
        let tip_tree_size = match stmt_end_tree_size_at
            .query_row(
                named_params! {":height": u32::from(chain_tip_height)},
                |row| row.get::<_, Option<u64>>(0),
            )
            .optional()?
            .flatten()
        {
            Some(tree_size) => Some(tree_size),
            None => estimate_tree_size(
                conn,
                params,
                shielded_protocol,
                pool_activation_height,
                chain_tip_height,
            )?,
        };

        let recover = recovered_count
            .zip(recover_until_size)
            .map(|(recovered, end_size)| {
                birthday_size.zip(end_size).map(|(start_size, end_size)| {
                    Ratio::new(recovered.unwrap_or(0), end_size - start_size)
                })
            })
            // If none of the wallet's accounts have a recover-until height, then there
            // is no recovery phase for the wallet, and therefore the denominator in the
            // resulting ratio (the number of notes in the recovery range) is zero.
            .unwrap_or_else(|| Some(Ratio::new(0, 0)));

        let scan = {
            // Count the total outputs scanned so far on the chain tip side of the
            // recover-until height.
            let scanned_count = stmt_scanned_count_from.query_row(
                named_params![":start_height": u32::from(recover_until_height.unwrap_or(birthday_height))],
                |row| row.get::<_, Option<u64>>(0),
            )?;

            recover_until_size
                .unwrap_or(birthday_size)
                .zip(tip_tree_size)
                .map(|(start_size, tip_tree_size)| {
                    Ratio::new(scanned_count.unwrap_or(0), tip_tree_size - start_size)
                })
        };

        Ok(scan.map(|scan| Progress::new(scan, recover)))
    }
}

impl ProgressEstimator for SubtreeProgressEstimator {
    #[tracing::instrument(skip(conn, params))]
    fn sapling_scan_progress<P: consensus::Parameters>(
        &self,
        conn: &rusqlite::Connection,
        params: &P,
        birthday_height: BlockHeight,
        recover_until_height: Option<BlockHeight>,
        fully_scanned_height: Option<BlockHeight>,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Progress>, SqliteClientError> {
        subtree_scan_progress(
            conn,
            params,
            ShieldedProtocol::Sapling,
            params
                .activation_height(NetworkUpgrade::Sapling)
                .expect("Sapling activation height must be available."),
            birthday_height,
            recover_until_height,
            fully_scanned_height,
            chain_tip_height,
        )
    }

    #[cfg(feature = "orchard")]
    #[tracing::instrument(skip(conn, params))]
    fn orchard_scan_progress<P: consensus::Parameters>(
        &self,
        conn: &rusqlite::Connection,
        params: &P,
        birthday_height: BlockHeight,
        recover_until_height: Option<BlockHeight>,
        fully_scanned_height: Option<BlockHeight>,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Progress>, SqliteClientError> {
        subtree_scan_progress(
            conn,
            params,
            ShieldedProtocol::Orchard,
            params
                .activation_height(NetworkUpgrade::Nu5)
                .expect("NU5 activation height must be available."),
            birthday_height,
            recover_until_height,
            fully_scanned_height,
            chain_tip_height,
        )
    }
}

/// Returns the spendable balance for the account at the specified height.
///
/// This may be used to obtain a balance that ignores notes that have been detected so recently
/// that they are not yet spendable, or for which it is not yet possible to construct witnesses.
///
/// `min_confirmations` can be 0, but that case is currently treated identically to
/// `min_confirmations == 1` for both shielded and transparent TXOs. This behaviour
/// may change in the future.
#[tracing::instrument(skip(tx, params, progress))]
pub(crate) fn get_wallet_summary<P: consensus::Parameters>(
    tx: &rusqlite::Transaction,
    params: &P,
    min_confirmations: u32,
    progress: &impl ProgressEstimator,
) -> Result<Option<WalletSummary<AccountUuid>>, SqliteClientError> {
    let chain_tip_height = match chain_tip_height(tx)? {
        Some(h) => h,
        None => {
            return Ok(None);
        }
    };

    let birthday_height = match wallet_birthday(tx)? {
        Some(h) => h,
        None => {
            return Ok(None);
        }
    };

    let recover_until_height = recover_until_height(tx)?;

    let fully_scanned_height = block_fully_scanned(tx, params)?.map(|m| m.block_height());
    let summary_height = (chain_tip_height + 1).saturating_sub(std::cmp::max(min_confirmations, 1));

    let sapling_progress = progress.sapling_scan_progress(
        tx,
        params,
        birthday_height,
        recover_until_height,
        fully_scanned_height,
        chain_tip_height,
    )?;

    #[cfg(feature = "orchard")]
    let orchard_progress = progress.orchard_scan_progress(
        tx,
        params,
        birthday_height,
        recover_until_height,
        fully_scanned_height,
        chain_tip_height,
    )?;
    #[cfg(not(feature = "orchard"))]
    let orchard_progress: Option<Progress> = None;

    // Treat Sapling and Orchard outputs as having the same cost to scan.
    let progress = sapling_progress
        .as_ref()
        .zip(orchard_progress.as_ref())
        .map(|(s, o)| {
            Progress::new(
                Ratio::new(
                    s.scan().numerator() + o.scan().numerator(),
                    s.scan().denominator() + o.scan().denominator(),
                ),
                s.recovery()
                    .zip(o.recovery())
                    .map(|(s, o)| {
                        Ratio::new(
                            s.numerator() + o.numerator(),
                            s.denominator() + o.denominator(),
                        )
                    })
                    .or_else(|| s.recovery())
                    .or_else(|| o.recovery()),
            )
        })
        .or(sapling_progress)
        .or(orchard_progress);

    let progress = match progress {
        Some(p) => p,
        None => return Ok(None),
    };

    let mut stmt_accounts = tx.prepare_cached("SELECT uuid FROM accounts")?;
    let mut account_balances = stmt_accounts
        .query([])?
        .and_then(|row| {
            Ok::<_, SqliteClientError>((AccountUuid(row.get::<_, Uuid>(0)?), AccountBalance::ZERO))
        })
        .collect::<Result<HashMap<AccountUuid, AccountBalance>, _>>()?;

    fn count_notes<F>(
        tx: &rusqlite::Transaction,
        summary_height: BlockHeight,
        account_balances: &mut HashMap<AccountUuid, AccountBalance>,
        table_prefix: &'static str,
        with_pool_balance: F,
    ) -> Result<(), SqliteClientError>
    where
        F: Fn(&mut AccountBalance, Zatoshis, Zatoshis, Zatoshis) -> Result<(), SqliteClientError>,
    {
        // If the shard containing the summary height contains any unscanned ranges that start below or
        // including that height, none of our shielded balance is currently spendable.
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
            "SELECT a.uuid, n.value, n.is_change, scan_state.max_priority, t.block
             FROM {table_prefix}_received_notes n
             JOIN accounts a ON a.id = n.account_id
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
            let account = AccountUuid(row.get::<_, Uuid>(0)?);

            let value_raw = row.get::<_, i64>(1)?;
            let value = Zatoshis::from_nonnegative_i64(value_raw).map_err(|_| {
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
                let zero = Zatoshis::ZERO;
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
    transparent::add_transparent_account_balances(
        tx,
        chain_tip_height + 1,
        min_confirmations,
        &mut account_balances,
    )?;

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
        fully_scanned_height.unwrap_or(birthday_height - 1),
        progress,
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
            return Err(SqliteClientError::UnsupportedPoolType(PoolType::ORCHARD))
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
) -> Result<HashSet<AccountUuid>, rusqlite::Error> {
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
    account_uuid: AccountUuid,
) -> Result<BlockHeight, SqliteClientError> {
    conn.query_row(
        "SELECT birthday_height
         FROM accounts
         WHERE uuid = :account_uuid",
        named_params![":account_uuid": account_uuid.0],
        |row| row.get::<_, u32>(0).map(BlockHeight::from),
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|opt| opt.ok_or(SqliteClientError::AccountUnknown))
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn account_birthday_internal(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<BlockHeight, SqliteClientError> {
    conn.query_row(
        "SELECT birthday_height
         FROM accounts
         WHERE id = :account_ref",
        named_params![":account_ref": account_ref.0],
        |row| row.get::<_, u32>(0).map(BlockHeight::from),
    )
    .optional()
    .map_err(SqliteClientError::from)
    .and_then(|opt| opt.ok_or(SqliteClientError::AccountUnknown))
}

/// Returns the maximum recover-until height for accounts in the wallet.
pub(crate) fn recover_until_height(
    conn: &rusqlite::Connection,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.query_row(
        "SELECT MAX(recover_until_height) FROM accounts",
        [],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
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

pub(crate) fn get_account_ref(
    conn: &rusqlite::Connection,
    account_uuid: AccountUuid,
) -> Result<AccountRef, SqliteClientError> {
    conn.query_row(
        "SELECT id FROM accounts WHERE uuid = :account_uuid",
        named_params! {":account_uuid": account_uuid.0},
        |row| row.get("id").map(AccountRef),
    )
    .optional()?
    .ok_or(SqliteClientError::AccountUnknown)
}

/// Returns the minimum and maximum heights of blocks in the chain which may be scanned.
pub(crate) fn chain_tip_height(
    conn: &rusqlite::Connection,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.query_row("SELECT MAX(block_range_end) FROM scan_queue", [], |row| {
        let max_height: Option<u32> = row.get(0)?;

        // Scan ranges are end-exclusive, so we subtract 1 from `max_height` to obtain the
        // height of the last known chain tip;
        Ok(max_height.map(|h| BlockHeight::from(h.saturating_sub(1))))
    })
}

pub(crate) fn get_target_and_anchor_heights(
    conn: &rusqlite::Connection,
    min_confirmations: NonZeroU32,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    match chain_tip_height(conn)? {
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
        let calc_fully_scanned_height = |row: &rusqlite::Row| {
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
        };
        let fully_scanned_height = match conn
            .query_row(
                "SELECT block_range_start, block_range_end
                FROM scan_queue
                WHERE priority = :priority
                ORDER BY block_range_start ASC
                LIMIT 1",
                named_params![":priority": priority_code(&ScanPriority::Scanned)],
                calc_fully_scanned_height,
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
        [txid.as_ref()],
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

pub(crate) fn store_transaction_to_be_sent<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    sent_tx: &SentTransaction<AccountUuid>,
) -> Result<(), SqliteClientError> {
    let tx_ref = put_tx_data(
        conn,
        sent_tx.tx(),
        Some(sent_tx.fee_amount()),
        Some(sent_tx.created()),
        Some(sent_tx.target_height()),
    )?;

    let mut detectable_via_scanning = false;

    // Mark notes as spent.
    //
    // This locks the notes so they aren't selected again by a subsequent call to
    // create_spend_to_address() before this transaction has been mined (at which point the notes
    // get re-marked as spent).
    //
    // Assumes that create_spend_to_address() will never be called in parallel, which is a
    // reasonable assumption for a light client such as a mobile phone.
    if let Some(bundle) = sent_tx.tx().sapling_bundle() {
        detectable_via_scanning = true;
        for spend in bundle.shielded_spends() {
            sapling::mark_sapling_note_spent(conn, tx_ref, spend.nullifier())?;
        }
    }
    if let Some(_bundle) = sent_tx.tx().orchard_bundle() {
        #[cfg(feature = "orchard")]
        {
            detectable_via_scanning = true;
            for action in _bundle.actions() {
                orchard::mark_orchard_note_spent(conn, tx_ref, action.nullifier())?;
            }
        }

        #[cfg(not(feature = "orchard"))]
        panic!("Sent a transaction with Orchard Actions without `orchard` enabled?");
    }

    #[cfg(feature = "transparent-inputs")]
    for utxo_outpoint in sent_tx.utxos_spent() {
        transparent::mark_transparent_utxo_spent(conn, tx_ref, utxo_outpoint)?;
    }

    for output in sent_tx.outputs() {
        insert_sent_output(conn, params, tx_ref, *sent_tx.account_id(), output)?;

        match output.recipient() {
            Recipient::External {
                recipient_address: _addr,
                output_pool: _pool,
                ..
            } => {
                // Nothing to do for external recipients.
            }
            Recipient::InternalAccount {
                receiving_account,
                note,
                ..
            } => match note.as_ref() {
                Note::Sapling(note) => {
                    sapling::put_received_note(
                        conn,
                        params,
                        &DecryptedOutput::new(
                            output.output_index(),
                            note.clone(),
                            *receiving_account,
                            output
                                .memo()
                                .map_or_else(MemoBytes::empty, |memo| memo.clone()),
                            TransferType::WalletInternal,
                        ),
                        tx_ref,
                        Some(sent_tx.target_height()),
                        None,
                    )?;
                }
                #[cfg(feature = "orchard")]
                Note::Orchard(note) => {
                    orchard::put_received_note(
                        conn,
                        params,
                        &DecryptedOutput::new(
                            output.output_index(),
                            *note,
                            *receiving_account,
                            output
                                .memo()
                                .map_or_else(MemoBytes::empty, |memo| memo.clone()),
                            TransferType::WalletInternal,
                        ),
                        tx_ref,
                        Some(sent_tx.target_height()),
                        None,
                    )?;
                }
            },
            #[cfg(feature = "transparent-inputs")]
            Recipient::EphemeralTransparent {
                ephemeral_address,
                outpoint,
                ..
            } => {
                // First check to verify that creation of this output does not result in reuse of
                // an ephemeral address.
                transparent::check_ephemeral_address_reuse(conn, params, ephemeral_address)?;

                transparent::put_transparent_output(
                    conn,
                    &params,
                    outpoint,
                    &TxOut {
                        value: output.value(),
                        script_pubkey: ephemeral_address.script(),
                    },
                    None,
                    ephemeral_address,
                    true,
                )?;
            }
        }
    }

    // Add the transaction to the set to be queried for transaction status. This is only necessary
    // at present for fully transparent transactions, because any transaction with a shielded
    // component will be detected via ordinary chain scanning and/or nullifier checking.
    if !detectable_via_scanning {
        queue_tx_retrieval(conn, std::iter::once(sent_tx.tx().txid()), None)?;
    }

    Ok(())
}

pub(crate) fn set_transaction_status(
    conn: &rusqlite::Transaction,
    txid: TxId,
    status: TransactionStatus,
) -> Result<(), SqliteClientError> {
    // It is safe to unconditionally delete the request from `tx_retrieval_queue` below (both in
    // the expired case and the case where it has been mined), because we already have all the data
    // we need about this transaction:
    // * if the status is being set in response to a `GetStatus` request, we know that we already
    //   have the transaction data (`GetStatus` requests are only generated if we already have that
    //   data)
    // * if it is being set in response to an `Enhancement` request, we know that the status must
    //   be `TxidNotRecognized` because otherwise the transaction data should have been provided to
    //   the backend directly instead of calling `set_transaction_status`
    //
    // In general `Enhancement` requests are only generated in response to situations where a
    // transaction has already been mined - either the transaction was detected by scanning the
    // chain of `CompactBlock` values, or was discovered by walking backward from the inputs of a
    // transparent transaction; in the case that a transaction was read from the mempool, complete
    // transaction data will have been available and the only question that we are concerned with
    // is whether that transaction ends up being mined or expires.
    match status {
        TransactionStatus::TxidNotRecognized | TransactionStatus::NotInMainChain => {
            // If the transaction is now expired, remove it from the retrieval queue.
            if let Some(chain_tip) = chain_tip_height(conn)? {
                conn.execute(
                    "DELETE FROM tx_retrieval_queue WHERE txid IN (
                        SELECT txid FROM transactions
                        WHERE txid = :txid AND expiry_height < :chain_tip_minus_lookahead
                    )",
                    named_params![
                        ":txid": txid.as_ref(),
                        ":chain_tip_minus_lookahead": u32::from(chain_tip).saturating_sub(VERIFY_LOOKAHEAD)
                    ],
                )?;
            }
        }
        TransactionStatus::Mined(height) => {
            // The transaction has been mined, so we can set its mined height, associate it with
            // the appropriate block, and remove it from the retrieval queue.
            let sql_args = named_params![
                ":txid": txid.as_ref(),
                ":height": u32::from(height)
            ];

            conn.execute(
                "UPDATE transactions
                 SET mined_height = :height
                 WHERE txid = :txid",
                sql_args,
            )?;

            conn.execute(
                "UPDATE transactions
                 SET block = blocks.height
                 FROM blocks
                 WHERE txid = :txid
                 AND blocks.height = :height",
                sql_args,
            )?;

            notify_tx_retrieved(conn, txid)?;
        }
    }

    Ok(())
}

/// Truncates the database to at most the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
///
/// This should only be executed inside a transactional context.
///
/// Returns the block height to which the database was truncated.
pub(crate) fn truncate_to_height<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
    max_height: BlockHeight,
) -> Result<BlockHeight, SqliteClientError> {
    // Determine a checkpoint to which we can rewind, if any.
    #[cfg(not(feature = "orchard"))]
    let truncation_height_query = r#"
        SELECT MAX(height) FROM blocks
        JOIN sapling_tree_checkpoints ON checkpoint_id = blocks.height
        WHERE blocks.height <= :block_height
    "#;

    #[cfg(feature = "orchard")]
    let truncation_height_query = r#"
        SELECT MAX(height) FROM blocks
        JOIN sapling_tree_checkpoints sc ON sc.checkpoint_id = blocks.height
        JOIN orchard_tree_checkpoints oc ON oc.checkpoint_id = blocks.height
        WHERE blocks.height <= :block_height
    "#;

    let truncation_height = conn
        .query_row(
            truncation_height_query,
            named_params! {":block_height": u32::from(max_height)},
            |row| row.get::<_, Option<u32>>(0),
        )
        .optional()?
        .flatten()
        .map_or_else(
            || {
                // If we don't have a checkpoint at a height less than or equal to the requested
                // truncation height, query for the minimum height to which it's possible for us to
                // truncate so that we can report it to the caller.
                #[cfg(not(feature = "orchard"))]
                let min_checkpoint_height_query =
                    "SELECT MIN(checkpoint_id) FROM sapling_tree_checkpoints";
                #[cfg(feature = "orchard")]
                let min_checkpoint_height_query = "SELECT MIN(sc.checkpoint_id)
                     FROM sapling_tree_checkpoints sc
                     JOIN orchard_tree_checkpoints oc
                     ON oc.checkpoint_id = sc.checkpoint_id";

                let min_truncation_height = conn
                    .query_row(min_checkpoint_height_query, [], |row| {
                        row.get::<_, Option<u32>>(0)
                    })
                    .optional()?
                    .flatten()
                    .map(BlockHeight::from);

                Err(SqliteClientError::RequestedRewindInvalid {
                    safe_rewind_height: min_truncation_height,
                    requested_height: max_height,
                })
            },
            |h| Ok(BlockHeight::from(h)),
        )?;

    let last_scanned_height = conn.query_row("SELECT MAX(height) FROM blocks", [], |row| {
        let h = row.get::<_, Option<u32>>(0)?;

        Ok(h.map_or_else(
            || {
                params
                    .activation_height(NetworkUpgrade::Sapling)
                    .expect("Sapling activation height must be available.")
                    - 1
            },
            BlockHeight::from,
        ))
    })?;

    // Delete from the scanning queue any range with a start height greater than the
    // truncation height, and then truncate any remaining range by setting the end
    // equal to the truncation height + 1. This sets our view of the chain tip back
    // to the retained height.
    conn.execute(
        "DELETE FROM scan_queue
        WHERE block_range_start >= :new_end_height",
        named_params![":new_end_height": u32::from(truncation_height + 1)],
    )?;
    conn.execute(
        "UPDATE scan_queue
        SET block_range_end = :new_end_height
        WHERE block_range_end > :new_end_height",
        named_params![":new_end_height": u32::from(truncation_height + 1)],
    )?;

    // Mark transparent utxos as un-mined. Since the TXO is now not mined, it would ideally be
    // considered to have been returned to the mempool; it _might_ be spendable in this state, but
    // we must also set its max_observed_unspent_height field to NULL because the transaction may
    // be rendered entirely invalid by a reorg that alters anchor(s) used in constructing shielded
    // spends in the transaction.
    conn.execute(
        "UPDATE transparent_received_outputs
         SET max_observed_unspent_height = CASE WHEN tx.mined_height <= :height THEN :height ELSE NULL END
         FROM transactions tx
         WHERE tx.id_tx = transaction_id
         AND max_observed_unspent_height > :height",
        named_params![":height": u32::from(truncation_height)],
    )?;

    // Un-mine transactions. This must be done outside of the last_scanned_height check because
    // transaction entries may be created as a consequence of receiving transparent TXOs.
    conn.execute(
        "UPDATE transactions
         SET block = NULL, mined_height = NULL, tx_index = NULL
         WHERE mined_height > :height",
        named_params![":height": u32::from(truncation_height)],
    )?;

    // If we're removing scanned blocks, we need to truncate the note commitment tree and remove
    // affected block records from the database.
    if truncation_height < last_scanned_height {
        // Truncate the note commitment trees
        let mut wdb = WalletDb {
            conn: SqlTransaction(conn),
            params: params.clone(),
            clock: (),
            rng: (),
            #[cfg(feature = "transparent-inputs")]
            gap_limits: *gap_limits,
        };
        wdb.with_sapling_tree_mut(|tree| {
            tree.truncate_to_checkpoint(&truncation_height)?;
            Ok::<_, SqliteClientError>(())
        })?;
        #[cfg(feature = "orchard")]
        wdb.with_orchard_tree_mut(|tree| {
            tree.truncate_to_checkpoint(&truncation_height)?;
            Ok::<_, SqliteClientError>(())
        })?;

        // Do not delete sent notes; this can contain data that is not recoverable
        // from the chain. Wallets must continue to operate correctly in the
        // presence of stale sent notes that link to unmined transactions.
        // Also, do not delete received notes; they may contain memo data that is
        // not recoverable; balance APIs must ensure that un-mined received notes
        // do not count towards spendability or transaction balalnce.

        // Now that they aren't depended on, delete un-mined blocks.
        conn.execute(
            "DELETE FROM blocks WHERE height > ?",
            [u32::from(truncation_height)],
        )?;

        // Delete from the nullifier map any entries with a locator referencing a block
        // height greater than the truncation height.
        conn.execute(
            "DELETE FROM tx_locator_map
            WHERE block_height > :block_height",
            named_params![":block_height": u32::from(truncation_height)],
        )?;
    }

    Ok(truncation_height)
}

/// Returns a vector with the IDs of all accounts known to this wallet.
///
/// Note that this is called from db migration code.
pub(crate) fn get_account_ids(
    conn: &rusqlite::Connection,
) -> Result<Vec<AccountUuid>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT uuid FROM accounts")?;
    let mut rows = stmt.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let id = AccountUuid(row.get(0)?);
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

    // If we now have a block corresponding to a received transparent output that had not been
    // scanned at the time the UTXO was discovered, update the associated transaction record to
    // refer to that block.
    //
    // NOTE: There's a small data corruption hazard here, in that we're relying exclusively upon
    // the block height to associate the transaction to the block. This is because CompactBlock
    // values only contain CompactTx entries for transactions that contain shielded inputs or
    // outputs, and the GetAddressUtxosReply data does not contain the block hash. As such, it's
    // necessary to ensure that any chain rollback to below the received height causes that height
    // to be set to NULL.
    let mut stmt_update_transaction_block_reference = conn.prepare_cached(
        "UPDATE transactions
         SET block = :height
         WHERE mined_height = :height",
    )?;

    stmt_update_transaction_block_reference
        .execute(named_params![":height": u32::from(block_height),])?;

    Ok(())
}

pub(crate) fn store_decrypted_tx<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    d_tx: DecryptedTransaction<AccountUuid>,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
) -> Result<(), SqliteClientError> {
    let tx_ref = put_tx_data(conn, d_tx.tx(), None, None, None)?;
    if let Some(height) = d_tx.mined_height() {
        set_transaction_status(conn, d_tx.tx().txid(), TransactionStatus::Mined(height))?;
    }

    let funding_accounts = get_funding_accounts(conn, d_tx.tx())?;

    // TODO(#1305): Correctly track accounts that fund each transaction output.
    let funding_account = funding_accounts.iter().next().copied();
    if funding_accounts.len() > 1 {
        warn!(
            "More than one wallet account detected as funding transaction {:?}, selecting {:?}",
            d_tx.tx().txid(),
            funding_account.unwrap()
        )
    }

    // A flag used to determine whether it is necessary to query for transactions that
    // provided transparent inputs to this transaction, in order to be able to correctly
    // recover transparent transaction history.
    #[cfg(feature = "transparent-inputs")]
    let mut tx_has_wallet_outputs = false;

    #[cfg(feature = "transparent-inputs")]
    let mut receiving_accounts = BTreeMap::new();

    for output in d_tx.sapling_outputs() {
        #[cfg(feature = "transparent-inputs")]
        {
            tx_has_wallet_outputs = true;
        }
        match output.transfer_type() {
            TransferType::Outgoing => {
                let recipient = {
                    let receiver = Receiver::Sapling(output.note().recipient());
                    let recipient_address =
                        select_receiving_address(params, conn, *output.account(), &receiver)?
                            .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));

                    Recipient::External {
                        recipient_address,
                        output_pool: PoolType::SAPLING,
                    }
                };

                put_sent_output(
                    conn,
                    params,
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::WalletInternal => {
                sapling::put_received_note(
                    conn,
                    params,
                    output,
                    tx_ref,
                    d_tx.mined_height(),
                    None,
                )?;

                let recipient = Recipient::InternalAccount {
                    receiving_account: *output.account(),
                    external_address: None,
                    note: Box::new(Note::Sapling(output.note().clone())),
                };

                put_sent_output(
                    conn,
                    params,
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::Incoming => {
                let _account_id = sapling::put_received_note(
                    conn,
                    params,
                    output,
                    tx_ref,
                    d_tx.mined_height(),
                    None,
                )?;

                #[cfg(feature = "transparent-inputs")]
                receiving_accounts.insert(_account_id, KeyScope::EXTERNAL);

                if let Some(account_id) = funding_account {
                    let recipient = Recipient::InternalAccount {
                        receiving_account: *output.account(),
                        external_address: {
                            let receiver = Receiver::Sapling(output.note().recipient());
                            Some(
                                select_receiving_address(
                                    params,
                                    conn,
                                    *output.account(),
                                    &receiver,
                                )?
                                .unwrap_or_else(|| {
                                    receiver.to_zcash_address(params.network_type())
                                }),
                            )
                        },
                        note: Box::new(Note::Sapling(output.note().clone())),
                    };

                    put_sent_output(
                        conn,
                        params,
                        account_id,
                        tx_ref,
                        output.index(),
                        &recipient,
                        output.note_value(),
                        Some(output.memo()),
                    )?;
                }
            }
        }
    }

    #[cfg(feature = "orchard")]
    for output in d_tx.orchard_outputs() {
        #[cfg(feature = "transparent-inputs")]
        {
            tx_has_wallet_outputs = true;
        }
        match output.transfer_type() {
            TransferType::Outgoing => {
                let recipient = {
                    let receiver = Receiver::Orchard(output.note().recipient());
                    let recipient_address =
                        select_receiving_address(params, conn, *output.account(), &receiver)?
                            .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));

                    Recipient::External {
                        recipient_address,
                        output_pool: PoolType::ORCHARD,
                    }
                };

                put_sent_output(
                    conn,
                    params,
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::WalletInternal => {
                orchard::put_received_note(
                    conn,
                    params,
                    output,
                    tx_ref,
                    d_tx.mined_height(),
                    None,
                )?;

                let recipient = Recipient::InternalAccount {
                    receiving_account: *output.account(),
                    external_address: None,
                    note: Box::new(Note::Orchard(*output.note())),
                };

                put_sent_output(
                    conn,
                    params,
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::Incoming => {
                let _account_id = orchard::put_received_note(
                    conn,
                    params,
                    output,
                    tx_ref,
                    d_tx.mined_height(),
                    None,
                )?;

                #[cfg(feature = "transparent-inputs")]
                receiving_accounts.insert(_account_id, KeyScope::EXTERNAL);

                if let Some(account_id) = funding_account {
                    // Even if the recipient address is external, record the send as internal.
                    let recipient = Recipient::InternalAccount {
                        receiving_account: *output.account(),
                        external_address: {
                            let receiver = Receiver::Orchard(output.note().recipient());
                            Some(
                                select_receiving_address(
                                    params,
                                    conn,
                                    *output.account(),
                                    &receiver,
                                )?
                                .unwrap_or_else(|| {
                                    receiver.to_zcash_address(params.network_type())
                                }),
                            )
                        },
                        note: Box::new(Note::Orchard(*output.note())),
                    };

                    put_sent_output(
                        conn,
                        params,
                        account_id,
                        tx_ref,
                        output.index(),
                        &recipient,
                        output.note_value(),
                        Some(output.memo()),
                    )?;
                }
            }
        }
    }

    // If any of the utxos spent in the transaction are ours, mark them as spent.
    #[cfg(feature = "transparent-inputs")]
    for txin in d_tx
        .tx()
        .transparent_bundle()
        .iter()
        .flat_map(|b| b.vin.iter())
    {
        transparent::mark_transparent_utxo_spent(conn, tx_ref, &txin.prevout)?;
    }

    // This `if` is just an optimization for cases where we would do nothing in the loop.
    if funding_account.is_some() || cfg!(feature = "transparent-inputs") {
        for (output_index, txout) in d_tx
            .tx()
            .transparent_bundle()
            .iter()
            .flat_map(|b| b.vout.iter())
            .enumerate()
        {
            if let Some(address) = txout.recipient_address() {
                debug!(
                    "{:?} output {} has recipient {}",
                    d_tx.tx().txid(),
                    output_index,
                    address.encode(params)
                );

                // If the output belongs to the wallet, add it to `transparent_received_outputs`.
                #[cfg(feature = "transparent-inputs")]
                if let Some((account_uuid, key_scope)) =
                    transparent::find_account_uuid_for_transparent_address(conn, params, &address)?
                {
                    debug!(
                        "{:?} output {} belongs to account {:?}",
                        d_tx.tx().txid(),
                        output_index,
                        account_uuid
                    );
                    let (account_id, _, _) = transparent::put_transparent_output(
                        conn,
                        params,
                        &OutPoint::new(
                            d_tx.tx().txid().into(),
                            u32::try_from(output_index).unwrap(),
                        ),
                        txout,
                        d_tx.mined_height(),
                        &address,
                        false,
                    )?;

                    receiving_accounts.insert(account_id, key_scope);

                    // Since the wallet created the transparent output, we need to ensure
                    // that any transparent inputs belonging to the wallet will be
                    // discovered.
                    tx_has_wallet_outputs = true;

                    // When we receive transparent funds (particularly as ephemeral outputs
                    // in transaction pairs sending to a ZIP 320 address) it becomes
                    // possible that the spend of these outputs is not then later detected
                    // if the transaction that spends them is purely transparent. This is
                    // especially a problem in wallet recovery.
                    transparent::queue_transparent_spend_detection(
                        conn,
                        params,
                        address,
                        tx_ref,
                        output_index.try_into().unwrap(),
                    )?;
                } else {
                    debug!(
                        "Address {} is not recognized as belonging to any of our accounts.",
                        address.encode(params)
                    );
                }

                // If a transaction we observe contains spends from our wallet, we will
                // store its transparent outputs in the same way they would be stored by
                // create_spend_to_address.
                if let Some(account_uuid) = funding_account {
                    let receiver = Receiver::Transparent(address);

                    #[cfg(feature = "transparent-inputs")]
                    let recipient_address =
                        select_receiving_address(params, conn, account_uuid, &receiver)?
                            .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));

                    #[cfg(not(feature = "transparent-inputs"))]
                    let recipient_address = receiver.to_zcash_address(params.network_type());

                    let recipient = Recipient::External {
                        recipient_address,
                        output_pool: PoolType::TRANSPARENT,
                    };

                    put_sent_output(
                        conn,
                        params,
                        account_uuid,
                        tx_ref,
                        output_index,
                        &recipient,
                        txout.value,
                        None,
                    )?;

                    // Even though we know the funding account, we don't know that we have
                    // information for all of the transparent inputs to the transaction.
                    #[cfg(feature = "transparent-inputs")]
                    {
                        tx_has_wallet_outputs = true;
                    }
                }
            } else {
                warn!(
                    "Unable to determine recipient address for tx {:?} output {}",
                    d_tx.tx().txid(),
                    output_index
                );
            }
        }
    }

    #[cfg(feature = "transparent-inputs")]
    for (account_id, key_scope) in receiving_accounts {
        use ReceiverRequirement::*;
        transparent::generate_gap_addresses(
            conn,
            params,
            account_id,
            key_scope,
            gap_limits,
            UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
            false,
        )?;
    }

    // If the transaction has outputs that belong to the wallet as well as transparent
    // inputs, we may need to download the transactions corresponding to the transparent
    // prevout references to determine whether the transaction was created (at least in
    // part) by this wallet.
    #[cfg(feature = "transparent-inputs")]
    if tx_has_wallet_outputs {
        queue_transparent_input_retrieval(conn, tx_ref, &d_tx)?
    }

    notify_tx_retrieved(conn, d_tx.tx().txid())?;

    // If the decrypted transaction is unmined and has no shielded components, add it to
    // the queue for status retrieval.
    #[cfg(feature = "transparent-inputs")]
    queue_unmined_tx_retrieval(conn, &d_tx)?;

    Ok(())
}

/// Inserts information about a mined transaction that was observed to
/// contain a note related to this wallet into the database.
pub(crate) fn put_tx_meta(
    conn: &rusqlite::Connection,
    tx: &WalletTx<AccountUuid>,
    height: BlockHeight,
) -> Result<TxRef, SqliteClientError> {
    // It isn't there, so insert our transaction into the database.
    let mut stmt_upsert_tx_meta = conn.prepare_cached(
        "INSERT INTO transactions (txid, block, mined_height, tx_index)
        VALUES (:txid, :block, :block, :tx_index)
        ON CONFLICT (txid) DO UPDATE
        SET block = :block,
            mined_height = :block,
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
        .query_row(tx_params, |row| row.get::<_, i64>(0).map(TxRef))
        .map_err(SqliteClientError::from)
}

/// Returns the most likely wallet address that corresponds to the protocol-level receiver of a
/// note or UTXO.
pub(crate) fn select_receiving_address<P: consensus::Parameters>(
    _params: &P,
    conn: &rusqlite::Connection,
    account: AccountUuid,
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
            let mut stmt = conn.prepare_cached(
                "SELECT address
                 FROM addresses
                 JOIN accounts ON accounts.id = addresses.account_id
                 WHERE accounts.uuid = :account_uuid
                 AND key_scope = :key_scope",
            )?;

            let mut result = stmt.query(named_params! {
                ":account_uuid": account.0,
                ":key_scope": KeyScope::EXTERNAL.encode(),
            })?;
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
    fee: Option<Zatoshis>,
    created_at: Option<time::OffsetDateTime>,
    target_height: Option<BlockHeight>,
) -> Result<TxRef, SqliteClientError> {
    let mut stmt_upsert_tx_data = conn.prepare_cached(
        "INSERT INTO transactions (txid, created, expiry_height, raw, fee, target_height)
        VALUES (:txid, :created_at, :expiry_height, :raw, :fee, :target_height)
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
        ":target_height": target_height.map(u32::from),
    ];

    stmt_upsert_tx_data
        .query_row(tx_params, |row| row.get::<_, i64>(0).map(TxRef))
        .map_err(SqliteClientError::from)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxQueryType {
    Status,
    Enhancement,
}

impl TxQueryType {
    pub(crate) fn code(&self) -> i64 {
        match self {
            TxQueryType::Status => 0,
            TxQueryType::Enhancement => 1,
        }
    }

    pub(crate) fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(TxQueryType::Status),
            1 => Some(TxQueryType::Enhancement),
            _ => None,
        }
    }
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn queue_transparent_input_retrieval<AccountId>(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: TxRef,
    d_tx: &DecryptedTransaction<'_, AccountId>,
) -> Result<(), SqliteClientError> {
    if let Some(b) = d_tx.tx().transparent_bundle() {
        // queue the transparent inputs for enhancement
        queue_tx_retrieval(
            conn,
            b.vin.iter().map(|txin| *txin.prevout.txid()),
            Some(tx_ref),
        )?;
    }

    Ok(())
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn queue_unmined_tx_retrieval<AccountId>(
    conn: &rusqlite::Transaction<'_>,
    d_tx: &DecryptedTransaction<'_, AccountId>,
) -> Result<(), SqliteClientError> {
    let detectable_via_scanning = d_tx.tx().sapling_bundle().is_some();
    #[cfg(feature = "orchard")]
    let detectable_via_scanning = detectable_via_scanning | d_tx.tx().orchard_bundle().is_some();

    if d_tx.mined_height().is_none() && !detectable_via_scanning {
        queue_tx_retrieval(conn, std::iter::once(d_tx.tx().txid()), None)?
    }

    Ok(())
}

pub(crate) fn queue_tx_retrieval(
    conn: &rusqlite::Transaction<'_>,
    txids: impl Iterator<Item = TxId>,
    dependent_tx_ref: Option<TxRef>,
) -> Result<(), SqliteClientError> {
    // Add an entry to the transaction retrieval queue if it would not be redundant.
    let mut stmt_insert_tx = conn.prepare_cached(
        "INSERT INTO tx_retrieval_queue (txid, query_type, dependent_transaction_id)
            SELECT
            :txid,
            IIF(
                EXISTS (SELECT 1 FROM transactions WHERE txid = :txid AND raw IS NOT NULL),
                :status_type,
                :enhancement_type
            ),
            :dependent_transaction_id
        ON CONFLICT (txid) DO UPDATE
        SET query_type =
            IIF(
                EXISTS (SELECT 1 FROM transactions WHERE txid = :txid AND raw IS NOT NULL),
                :status_type,
                :enhancement_type
            ),
            dependent_transaction_id = IFNULL(:dependent_transaction_id, dependent_transaction_id)",
    )?;

    for txid in txids {
        stmt_insert_tx.execute(named_params! {
            ":txid": txid.as_ref(),
            ":status_type": TxQueryType::Status.code(),
            ":enhancement_type": TxQueryType::Enhancement.code(),
            ":dependent_transaction_id": dependent_tx_ref.map(|r| r.0),
        })?;
    }

    Ok(())
}

/// Returns the vector of [`TransactionDataRequest`]s that represents the information needed by the
/// wallet backend in order to be able to present a complete view of wallet history and memo data.
pub(crate) fn transaction_data_requests(
    conn: &rusqlite::Connection,
) -> Result<Vec<TransactionDataRequest>, SqliteClientError> {
    let mut tx_retrieval_stmt =
        conn.prepare_cached("SELECT txid, query_type FROM tx_retrieval_queue")?;

    let result = tx_retrieval_stmt
        .query_and_then([], |row| {
            let txid = row.get(0).map(TxId::from_bytes)?;
            let query_type = row.get(1).map(TxQueryType::from_code)?.ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "Unrecognized transaction data request type.".to_owned(),
                )
            })?;

            Ok::<TransactionDataRequest, SqliteClientError>(match query_type {
                TxQueryType::Status => TransactionDataRequest::GetStatus(txid),
                TxQueryType::Enhancement => TransactionDataRequest::Enhancement(txid),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(result)
}

pub(crate) fn notify_tx_retrieved(
    conn: &rusqlite::Transaction<'_>,
    txid: TxId,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "DELETE FROM tx_retrieval_queue WHERE txid = :txid",
        named_params![":txid": &txid.as_ref()[..]],
    )?;

    Ok(())
}

// A utility function for creation of parameters for use in `insert_sent_output`
// and `put_sent_output`
fn recipient_params<P: consensus::Parameters>(
    conn: &Connection,
    _params: &P,
    from: AccountUuid,
    to: &Recipient<AccountUuid>,
) -> Result<(AccountRef, Option<String>, Option<AccountRef>, PoolType), SqliteClientError> {
    let from_account_id = get_account_ref(conn, from)?;
    match to {
        Recipient::External {
            recipient_address,
            output_pool,
            ..
        } => Ok((
            from_account_id,
            Some(recipient_address.encode()),
            None,
            *output_pool,
        )),
        #[cfg(feature = "transparent-inputs")]
        Recipient::EphemeralTransparent {
            receiving_account,
            ephemeral_address,
            ..
        } => {
            let to_account = get_account_ref(conn, *receiving_account)?;
            Ok((
                from_account_id,
                Some(ephemeral_address.encode(_params)),
                Some(to_account),
                PoolType::TRANSPARENT,
            ))
        }
        Recipient::InternalAccount {
            receiving_account,
            external_address,
            note,
        } => {
            let to_account = get_account_ref(conn, *receiving_account)?;
            Ok((
                from_account_id,
                external_address.as_ref().map(|a| a.encode()),
                Some(to_account),
                PoolType::Shielded(note.protocol()),
            ))
        }
    }
}

fn flag_previously_received_change(
    conn: &rusqlite::Transaction,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    let flag_received_change = |table_prefix| {
        conn.execute(
            &format!(
                "UPDATE {table_prefix}_received_notes
                 SET is_change = 1
                 FROM sent_notes sn
                 WHERE sn.tx = {table_prefix}_received_notes.tx
                 AND sn.tx = :tx
                 AND sn.from_account_id = {table_prefix}_received_notes.account_id
                 AND {table_prefix}_received_notes.recipient_key_scope = :internal_scope"
            ),
            named_params! {
                ":tx": tx_ref.0,
                ":internal_scope": KeyScope::INTERNAL.encode()
            },
        )
    };

    flag_received_change(SAPLING_TABLES_PREFIX)?;
    #[cfg(feature = "orchard")]
    flag_received_change(ORCHARD_TABLES_PREFIX)?;

    Ok(())
}

/// Records information about a transaction output that your wallet created.
pub(crate) fn insert_sent_output<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    tx_ref: TxRef,
    from_account_uuid: AccountUuid,
    output: &SentTransactionOutput<AccountUuid>,
) -> Result<(), SqliteClientError> {
    let mut stmt_insert_sent_output = conn.prepare_cached(
        "INSERT INTO sent_notes (
            tx, output_pool, output_index, from_account_id,
            to_address, to_account_id, value, memo)
         VALUES (
            :tx, :output_pool, :output_index, :from_account_id,
            :to_address, :to_account_id, :value, :memo)",
    )?;

    let (from_account_id, to_address, to_account_id, pool_type) =
        recipient_params(conn, params, from_account_uuid, output.recipient())?;
    let sql_args = named_params![
        ":tx": tx_ref.0,
        ":output_pool": &pool_code(pool_type),
        ":output_index": &i64::try_from(output.output_index()).unwrap(),
        ":from_account_id": from_account_id.0,
        ":to_address": &to_address,
        ":to_account_id": to_account_id.map(|a| a.0),
        ":value": &i64::from(ZatBalance::from(output.value())),
        ":memo": memo_repr(output.memo())
    ];

    stmt_insert_sent_output.execute(sql_args)?;
    flag_previously_received_change(conn, tx_ref)?;

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
    conn: &rusqlite::Transaction,
    params: &P,
    from_account_uuid: AccountUuid,
    tx_ref: TxRef,
    output_index: usize,
    recipient: &Recipient<AccountUuid>,
    value: Zatoshis,
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
            to_address = IFNULL(to_address, :to_address),
            to_account_id = IFNULL(to_account_id, :to_account_id),
            value = :value,
            memo = IFNULL(:memo, memo)",
    )?;

    let (from_account_id, to_address, to_account_id, pool_type) =
        recipient_params(conn, params, from_account_uuid, recipient)?;
    let sql_args = named_params![
        ":tx": tx_ref.0,
        ":output_pool": &pool_code(pool_type),
        ":output_index": &i64::try_from(output_index).unwrap(),
        ":from_account_id": from_account_id.0,
        ":to_address": &to_address,
        ":to_account_id": &to_account_id.map(|a| a.0),
        ":value": &i64::from(ZatBalance::from(value)),
        ":memo": memo_repr(memo)
    ];

    stmt_upsert_sent_output.execute(sql_args)?;
    flag_previously_received_change(conn, tx_ref)?;

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
            .try_fold(None, |acc, row| -> Result<_, SqliteClientError> {
                match (acc, row?) {
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
) -> Result<Option<TxRef>, SqliteClientError> {
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

pub(crate) fn get_block_range(
    conn: &rusqlite::Connection,
    protocol: ShieldedProtocol,
    commitment_tree_address: incrementalmerkletree::Address,
) -> Result<Option<Range<BlockHeight>>, SqliteClientError> {
    let prefix = match protocol {
        ShieldedProtocol::Sapling => "sapling",
        ShieldedProtocol::Orchard => "orchard",
    };
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT MIN(height), MAX(height), MAX({prefix}_commitment_tree_size)
         FROM blocks
         WHERE {prefix}_commitment_tree_size BETWEEN :min_tree_size AND :max_tree_size"
    ))?;

    stmt.query_row(
        // BETWEEN is inclusive on both ends. However, we are comparing commitment tree sizes
        // to commitment tree positions, so we must add one to the start, and we do not subtract
        // one from the end.
        named_params! {
            ":min_tree_size": u64::from(commitment_tree_address.position_range_start()) + 1,
            ":max_tree_size": u64::from(commitment_tree_address.position_range_end()),
        },
        |row| {
            // The first block to be scanned is known to contain the start of the address range in
            // question because the tree size we compared against is measured as of the end of the
            // block.
            let min_height = row.get::<_, Option<u32>>(0)?.map(BlockHeight::from_u32);
            let max_height_inclusive = row.get::<_, Option<u32>>(1)?.map(BlockHeight::from_u32);
            let end_offset = row.get::<_, Option<u64>>(2)?.map(|max_height_tree_size| {
                // If the tree size at the end of the max-height block is less than the
                // end-exclusive maximum position of the address range, this means that the end of
                // the subtree referred to by that address is somewhere in the next block, so we
                // need to rescan an extra block to ensure that we have observed all of the note
                // commitments that aggregate up to that address.
                if max_height_tree_size < u64::from(commitment_tree_address.position_range_end()) {
                    1
                } else {
                    0
                }
            });

            Ok(min_height
                .zip(max_height_inclusive)
                .zip(end_offset)
                .map(|((min, max_inclusive), offset)| min..(max_inclusive + offset + 1)))
        },
    )
    .map_err(SqliteClientError::from)
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use incrementalmerkletree::Position;
    use zcash_client_backend::data_api::testing::TransactionSummary;
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::{
        consensus::BlockHeight,
        value::{ZatBalance, Zatoshis},
        ShieldedProtocol,
    };

    use crate::{error::SqliteClientError, AccountUuid, SAPLING_TABLES_PREFIX};

    #[cfg(feature = "orchard")]
    use crate::ORCHARD_TABLES_PREFIX;

    pub(crate) fn get_tx_history(
        conn: &rusqlite::Connection,
    ) -> Result<Vec<TransactionSummary<AccountUuid>>, SqliteClientError> {
        let mut stmt = conn.prepare_cached(
            "SELECT accounts.uuid as account_uuid, v_transactions.*
             FROM v_transactions
             JOIN accounts ON accounts.uuid = v_transactions.account_uuid
             ORDER BY mined_height DESC, tx_index DESC",
        )?;

        let results = stmt
            .query_and_then::<_, SqliteClientError, _, _>([], |row| {
                Ok(TransactionSummary::from_parts(
                    AccountUuid(row.get("account_uuid")?),
                    TxId::from_bytes(row.get("txid")?),
                    row.get::<_, Option<u32>>("expiry_height")?
                        .map(BlockHeight::from),
                    row.get::<_, Option<u32>>("mined_height")?
                        .map(BlockHeight::from),
                    ZatBalance::from_i64(row.get("account_balance_delta")?)?,
                    Zatoshis::from_nonnegative_i64(row.get("total_spent")?)?,
                    Zatoshis::from_nonnegative_i64(row.get("total_received")?)?,
                    row.get::<_, Option<i64>>("fee_paid")?
                        .map(Zatoshis::from_nonnegative_i64)
                        .transpose()?,
                    row.get("spent_note_count")?,
                    row.get("has_change")?,
                    row.get("sent_note_count")?,
                    row.get("received_note_count")?,
                    row.get("memo_count")?,
                    row.get("expired_unmined")?,
                    row.get("is_shielding")?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Returns a vector of transaction summaries
    #[allow(dead_code)] // used only for tests that are flagged off by default
    pub(crate) fn get_checkpoint_history(
        conn: &rusqlite::Connection,
        protocol: &ShieldedProtocol,
    ) -> Result<Vec<(BlockHeight, Option<Position>)>, SqliteClientError> {
        let table_prefix = match protocol {
            ShieldedProtocol::Sapling => SAPLING_TABLES_PREFIX,
            #[cfg(feature = "orchard")]
            ShieldedProtocol::Orchard => ORCHARD_TABLES_PREFIX,
            #[cfg(not(feature = "orchard"))]
            ShieldedProtocol::Orchard => {
                return Err(SqliteClientError::UnsupportedPoolType(
                    zcash_protocol::PoolType::ORCHARD,
                ));
            }
        };

        let mut stmt = conn.prepare_cached(&format!(
            "SELECT checkpoint_id, position FROM {}_tree_checkpoints
             ORDER BY checkpoint_id",
            table_prefix
        ))?;

        let results = stmt
            .query_and_then::<_, SqliteClientError, _, _>([], |row| {
                Ok((
                    BlockHeight::from(row.get::<_, u32>(0)?),
                    row.get::<_, Option<u64>>(1)?.map(Position::from),
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use sapling::zip32::ExtendedSpendingKey;
    use secrecy::{ExposeSecret, SecretVec};
    use uuid::Uuid;
    use zcash_client_backend::data_api::{
        testing::{AddressType, DataStoreFactory, FakeCompactOutput, TestBuilder, TestState},
        Account as _, AccountSource, WalletRead, WalletWrite,
    };
    use zcash_keys::keys::UnifiedAddressRequest;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::value::Zatoshis;

    use crate::{
        error::SqliteClientError,
        testing::{db::TestDbFactory, BlockCache},
        AccountUuid,
    };

    use super::account_birthday;

    #[test]
    fn empty_database_has_no_balance() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
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
            st.wallet().get_last_generated_address_matching(
                account.id(),
                UnifiedAddressRequest::AllAvailableKeys
            ),
            Ok(Some(_))
        );

        // No default address is set for an un-initialized account
        assert_matches!(
            st.wallet().get_last_generated_address_matching(
                AccountUuid(Uuid::nil()),
                UnifiedAddressRequest::AllAvailableKeys
            ),
            Err(SqliteClientError::AccountUnknown)
        );
    }

    #[test]
    fn get_default_account_index() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account_id = st.test_account().unwrap().id();
        let account_parameters = st.wallet().get_account(account_id).unwrap().unwrap();

        let expected_account_index = zip32::AccountId::try_from(0).unwrap();
        assert_matches!(
            account_parameters.kind,
            AccountSource::Derived{derivation, ..} if derivation.account_index() == expected_account_index
        );
    }

    #[test]
    fn get_account_ids() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
        let birthday = st.test_account().unwrap().birthday().clone();

        st.wallet_mut()
            .create_account("", &seed, &birthday, None)
            .unwrap();

        for acct_id in st.wallet().get_account_ids().unwrap() {
            assert_matches!(st.wallet().get_account(acct_id), Ok(Some(_)))
        }
    }

    #[test]
    fn block_fully_scanned() {
        check_block_fully_scanned(TestDbFactory::default())
    }

    fn check_block_fully_scanned<DsF: DataStoreFactory>(dsf: DsF) {
        let mut st = TestBuilder::new()
            .with_data_store_factory(dsf)
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let block_fully_scanned = |st: &TestState<_, DsF::DataStore, _>| {
            st.wallet()
                .block_fully_scanned()
                .unwrap()
                .map(|meta| meta.block_height())
        };

        // A fresh wallet should have no fully-scanned block.
        assert_eq!(block_fully_scanned(&st), None);

        // Scan a block above the wallet's birthday height.
        let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
        let not_our_value = Zatoshis::const_from_u64(10000);
        let start_height = st.sapling_activation_height();
        let _ = st.generate_block_at(
            start_height,
            BlockHash([0; 32]),
            &[FakeCompactOutput::new(
                &not_our_key,
                AddressType::DefaultExternal,
                not_our_value,
            )],
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
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_id = st.test_account().unwrap().id();
        assert_matches!(
            account_birthday(st.wallet().conn(), account_id),
            Ok(birthday) if birthday == st.sapling_activation_height()
        )
    }
}
