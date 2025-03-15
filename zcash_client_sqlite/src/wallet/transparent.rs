//! Functions for transparent input support in the wallet.
use std::collections::{HashMap, HashSet};
use std::num::TryFromIntError;
use std::ops::DerefMut;
use std::rc::Rc;
use std::time::{Duration, SystemTime, SystemTimeError};

use nonempty::NonEmpty;
use rand::RngCore;
use rand_distr::Distribution;
use rusqlite::types::Value;
use rusqlite::OptionalExtension;
use rusqlite::{named_params, Connection, Row};

use ::transparent::{
    address::{Script, TransparentAddress},
    bundle::{OutPoint, TxOut},
    keys::{IncomingViewingKey, NonHardenedChildIndex},
};
use zcash_address::unified::{Ivk, Typecode, Uivk};
use zcash_client_backend::{
    data_api::{
        Account, AccountBalance, OutputStatusFilter, TransactionDataRequest,
        TransactionStatusFilter,
    },
    wallet::{TransparentAddressMetadata, WalletTransparentOutput},
};
use zcash_keys::{
    address::Address,
    encoding::AddressCodec,
    keys::{AddressGenerationError, UnifiedAddressRequest},
};
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::{ZatBalance, Zatoshis},
    TxId,
};
use zip32::Scope;

use super::encoding::{decode_epoch_seconds, ReceiverFlags};
use super::{
    account_birthday_internal, chain_tip_height,
    encoding::{decode_diversifier_index_be, encode_diversifier_index_be},
    get_account_ids, get_account_internal, KeyScope,
};
use crate::{error::SqliteClientError, AccountUuid, TxRef, UtxoId};
use crate::{AccountRef, AddressRef, GapLimits};

pub(crate) mod ephemeral;

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    spent: impl Iterator<Item = &'a OutPoint>,
) -> Result<HashSet<AccountUuid>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT accounts.uuid
        FROM transparent_received_outputs o
        JOIN accounts ON accounts.id = o.account_id
        JOIN transactions t ON t.id_tx = o.transaction_id
        WHERE t.txid = :prevout_txid
        AND o.output_index = :prevout_idx",
    )?;

    let mut acc = HashSet::new();
    for prevout in spent {
        for account in account_q.query_and_then(
            named_params![
                ":prevout_txid": prevout.hash(),
                ":prevout_idx": prevout.n()
            ],
            |row| row.get(0).map(AccountUuid),
        )? {
            acc.insert(account?);
        }
    }

    Ok(acc)
}

/// Returns the `NonHardenedChildIndex` corresponding to a diversifier index
/// given as bytes in big-endian order (the reverse of the usual order).
fn address_index_from_diversifier_index_be(
    diversifier_index_be: &[u8],
) -> Result<NonHardenedChildIndex, SqliteClientError> {
    let di = decode_diversifier_index_be(diversifier_index_be)?;

    NonHardenedChildIndex::try_from(di).map_err(|_| {
        SqliteClientError::CorruptedData(
            "Unexpected hardened index for transparent address.".to_string(),
        )
    })
}

pub(crate) fn get_transparent_receivers<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
    scopes: &[KeyScope],
) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, SqliteClientError> {
    let mut ret: HashMap<TransparentAddress, Option<TransparentAddressMetadata>> = HashMap::new();

    // Get all addresses with the provided scopes.
    let mut addr_query = conn.prepare(
        "SELECT address, diversifier_index_be, key_scope
         FROM addresses
         JOIN accounts ON accounts.id = addresses.account_id
         WHERE accounts.uuid = :account_uuid
         AND key_scope IN rarray(:scopes_ptr)",
    )?;

    let scope_values: Vec<Value> = scopes.iter().map(|s| Value::Integer(s.encode())).collect();
    let scopes_ptr = Rc::new(scope_values);
    let mut rows = addr_query.query(named_params![
        ":account_uuid": account_uuid.0,
        ":scopes_ptr": &scopes_ptr
    ])?;

    while let Some(row) = rows.next()? {
        let ua_str: String = row.get(0)?;
        let di_vec: Vec<u8> = row.get(1)?;
        let scope = KeyScope::decode(row.get(2)?)?;

        let taddr = Address::decode(params, &ua_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })?
            .to_transparent_address();

        if let Some(taddr) = taddr {
            let address_index = address_index_from_diversifier_index_be(&di_vec)?;
            let metadata = TransparentAddressMetadata::new(scope.into(), address_index);
            ret.insert(taddr, Some(metadata));
        }
    }

    if let Some((taddr, address_index)) =
        get_legacy_transparent_address(params, conn, account_uuid)?
    {
        let metadata = TransparentAddressMetadata::new(KeyScope::EXTERNAL.into(), address_index);
        ret.insert(taddr, Some(metadata));
    }

    Ok(ret)
}

pub(crate) fn uivk_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    uivk_str: &str,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    use ::transparent::keys::ExternalIvk;
    use zcash_address::unified::{Container as _, Encoding as _};

    let (network, uivk) = Uivk::decode(uivk_str)
        .map_err(|e| SqliteClientError::CorruptedData(format!("Unable to parse UIVK: {e}")))?;

    if params.network_type() != network {
        let network_name = |n| match n {
            consensus::NetworkType::Main => "mainnet",
            consensus::NetworkType::Test => "testnet",
            consensus::NetworkType::Regtest => "regtest",
        };
        return Err(SqliteClientError::CorruptedData(format!(
            "Network type mismatch: account UIVK is for {} but a {} address was requested.",
            network_name(network),
            network_name(params.network_type())
        )));
    }

    // Derive the default transparent address (if it wasn't already part of a derived UA).
    for item in uivk.items() {
        if let Ivk::P2pkh(tivk_bytes) = item {
            let tivk = ExternalIvk::deserialize(&tivk_bytes)?;
            return Ok(Some(tivk.default_address()));
        }
    }

    Ok(None)
}

pub(crate) fn get_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    conn: &rusqlite::Connection,
    account_uuid: AccountUuid,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    // Get the UIVK for the account.
    let uivk_str: Option<String> = conn
        .query_row(
            "SELECT uivk FROM accounts WHERE uuid = :account_uuid",
            named_params![":account_uuid": account_uuid.0],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(uivk_str) = uivk_str {
        return uivk_legacy_transparent_address(params, &uivk_str);
    }

    Ok(None)
}

/// Returns the transparent address index at the start of the first gap of at least `gap_limit`
/// indices in the given account, considering only addresses derived for the specified key scope.
///
/// Returns `Ok(None)` if the gap would start at an index greater than the maximum valid
/// non-hardened transparent child index.
pub(crate) fn find_gap_start(
    conn: &rusqlite::Connection,
    account_id: AccountRef,
    key_scope: KeyScope,
    gap_limit: u32,
) -> Result<Option<NonHardenedChildIndex>, SqliteClientError> {
    match conn
        .query_row(
            r#"
            WITH offsets AS (
                SELECT
                    a.transparent_child_index,
                    LEAD(a.transparent_child_index)
                        OVER (ORDER BY a.transparent_child_index)
                        AS next_child_index
                FROM v_address_first_use a
                WHERE a.account_id = :account_id
                AND a.key_scope = :key_scope
                AND a.transparent_child_index IS NOT NULL
                AND a.first_use_height IS NOT NULL
            )
            SELECT
                transparent_child_index + 1,
                -- both next_child_index and transparent_child_index are used indices,
                -- so the gap between them is one less than their difference
                next_child_index - transparent_child_index - 1 AS gap_len
            FROM offsets
            -- if gap_len is at least the gap limit, then we have found a gap.
            -- if next_child_index is NULL, then we have reached the end of
            -- the allocated indices (the remainder of the index space is a gap).
            WHERE gap_len >= :gap_limit OR next_child_index IS NULL
            ORDER BY transparent_child_index
            LIMIT 1
            "#,
            named_params![
                ":account_id": account_id.0,
                ":key_scope": key_scope.encode(),
                ":gap_limit": gap_limit
            ],
            |row| row.get::<_, u32>(0),
        )
        .optional()?
    {
        Some(i) => Ok(NonHardenedChildIndex::from_index(i)),
        None => Ok(Some(NonHardenedChildIndex::ZERO)),
    }
}

pub(crate) fn decode_transparent_child_index(
    value: i64,
) -> Result<NonHardenedChildIndex, SqliteClientError> {
    u32::try_from(value)
        .ok()
        .and_then(NonHardenedChildIndex::from_index)
        .ok_or_else(|| {
            SqliteClientError::CorruptedData(format!("Illegal transparent child index {value}"))
        })
}

/// Returns the current gap start, along with a vector with at most the next `n` previously
/// unreserved transparent addresses for the given account. These addresses must have been
/// previously generated using `generate_gap_addresses`.
///
/// WARNING: the addresses returned by this method have not been marked as exposed; it is the
/// responsibility of the caller to correctly update the `exposed_at_height` value for each
/// returned address before such an address is exposed to a user.
///
/// # Errors
///
/// * `SqliteClientError::AccountUnknown`, if there is no account with the given id.
/// * `SqliteClientError::AddressGeneration(AddressGenerationError::DiversifierSpaceExhausted)`,
///   if the limit on transparent address indices has been reached.
#[allow(clippy::type_complexity)]
pub(crate) fn select_addrs_to_reserve<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    key_scope: KeyScope,
    gap_limit: u32,
    n: usize,
) -> Result<
    (
        NonHardenedChildIndex,
        Vec<(AddressRef, TransparentAddress, TransparentAddressMetadata)>,
    ),
    SqliteClientError,
> {
    let gap_start = find_gap_start(conn, account_id, key_scope, gap_limit)?.ok_or(
        SqliteClientError::AddressGeneration(AddressGenerationError::DiversifierSpaceExhausted),
    )?;

    let mut stmt_addrs_to_reserve = conn.prepare(
        "SELECT id, transparent_child_index, cached_transparent_receiver_address
         FROM addresses
         WHERE account_id = :account_id
         AND key_scope = :key_scope
         AND transparent_child_index >= :gap_start
         AND transparent_child_index < :gap_end
         AND exposed_at_height IS NULL
         ORDER BY transparent_child_index
         LIMIT :n",
    )?;

    let addresses_to_reserve = stmt_addrs_to_reserve
        .query_and_then(
            named_params! {
                ":account_id": account_id.0,
                ":key_scope": key_scope.encode(),
                ":gap_start": gap_start.index(),
                // NOTE: this approach means that the address at index 2^31 - 1 will never be
                // allocated. I think that's fine.
                ":gap_end": gap_start.saturating_add(gap_limit).index(),
                ":n": n
            },
            |row| {
                let address_id = row.get("id").map(AddressRef)?;
                let transparent_child_index = row
                    .get::<_, Option<i64>>("transparent_child_index")?
                    .map(decode_transparent_child_index)
                    .transpose()?;
                let address = row
                    .get::<_, Option<String>>("cached_transparent_receiver_address")?
                    .map(|addr_str| TransparentAddress::decode(params, &addr_str))
                    .transpose()?;

                Ok::<_, SqliteClientError>(transparent_child_index.zip(address).map(|(i, a)| {
                    (
                        address_id,
                        a,
                        TransparentAddressMetadata::new(key_scope.into(), i),
                    )
                }))
            },
        )?
        .filter_map(|r| r.transpose())
        .collect::<Result<Vec<_>, _>>()?;

    Ok((gap_start, addresses_to_reserve))
}

/// Returns a vector with the next `n` previously unreserved transparent addresses for the given
/// account, having marked each address as having been exposed at the current chain-tip height.
/// These addresses must have been previously generated using `generate_gap_addresses`.
///
/// # Errors
///
/// * [`SqliteClientError::AccountUnknown`], if there is no account with the given id.
/// * [`SqliteClientError::ReachedGapLimit`], if it is not possible to reserve `n` addresses
///   within the gap limit after the last address in this account that is known to have an
///   output in a mined transaction.
/// * [`SqliteClientError::AddressGeneration(AddressGenerationError::DiversifierSpaceExhausted)`]
///   if the limit on transparent address indices has been reached.
///
/// [`SqliteClientError::AddressGeneration(AddressGenerationError::DiversifierSpaceExhausted)`]:
/// SqliteClientError::AddressGeneration
pub(crate) fn reserve_next_n_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    key_scope: KeyScope,
    gap_limit: u32,
    n: usize,
) -> Result<Vec<(AddressRef, TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
    if n == 0 {
        return Ok(vec![]);
    }

    let (gap_start, addresses_to_reserve) =
        select_addrs_to_reserve(conn, params, account_id, key_scope, gap_limit, n)?;

    if addresses_to_reserve.len() < n {
        return Err(SqliteClientError::ReachedGapLimit(
            key_scope.into(),
            gap_start.index() + gap_limit,
        ));
    }

    let current_chain_tip = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;

    let reserve_id_values: Vec<Value> = addresses_to_reserve
        .iter()
        .map(|(id, _, _)| Value::Integer(id.0))
        .collect();
    let reserved_ptr = Rc::new(reserve_id_values);
    conn.execute(
        "UPDATE addresses
         SET exposed_at_height = :chain_tip_height
         WHERE id IN rarray(:reserved_ptr)",
        named_params! {
            ":chain_tip_height": u32::from(current_chain_tip),
            ":reserved_ptr": &reserved_ptr
        },
    )?;

    Ok(addresses_to_reserve)
}

/// Extend the range of preallocated addresses in an account to ensure that a full `gap_limit` of
/// transparent addresses is available from the first gap in existing indices of addresses at which
/// a received transaction has been observed on the chain, for each key scope.
///
/// The provided [`UnifiedAddressRequest`] is used to pre-generate unified addresses that correspond
/// to the transparent address index in question; such unified addresses need not internally
/// contain a transparent receiver, and may be overwritten when these addresses are exposed via the
/// [`WalletWrite::get_next_available_address`] or [`WalletWrite::get_address_for_index`] methods.
/// If no request is provided, each address so generated will contain a receiver for each possible
/// pool: i.e., a recevier for each data item in the account's UFVK or UIVK where the transparent
/// child index is valid.
///
/// [`WalletWrite::get_next_available_address`]: zcash_client_backend::data_api::WalletWrite::get_next_available_address
/// [`WalletWrite::get_address_for_index`]: zcash_client_backend::data_api::WalletWrite::get_address_for_index
pub(crate) fn generate_gap_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    key_scope: KeyScope,
    gap_limits: &GapLimits,
    request: UnifiedAddressRequest,
    require_key: bool,
) -> Result<(), SqliteClientError> {
    let account = get_account_internal(conn, params, account_id)?
        .ok_or_else(|| SqliteClientError::AccountUnknown)?;

    if !account.uivk().has_transparent() {
        if require_key {
            return Err(SqliteClientError::AddressGeneration(
                AddressGenerationError::KeyNotAvailable(Typecode::P2pkh),
            ));
        } else {
            return Ok(());
        }
    }

    let gen_addrs = |key_scope: KeyScope, index: NonHardenedChildIndex| {
        Ok::<_, SqliteClientError>(match key_scope {
            KeyScope::Zip32(zip32::Scope::External) => {
                let ua = account.uivk().address(index.into(), request);
                let transparent_address = account
                    .uivk()
                    .transparent()
                    .as_ref()
                    .expect("presence of transparent key was checked above.")
                    .derive_address(index)?;
                (
                    ua.map_or_else(
                        |e| {
                            if matches!(e, AddressGenerationError::ShieldedReceiverRequired) {
                                // fall back to the transparent-only address
                                Ok(Address::from(transparent_address).to_zcash_address(params))
                            } else {
                                // other address generation errors are allowed to propagate
                                Err(e)
                            }
                        },
                        |addr| Ok(Address::from(addr).to_zcash_address(params)),
                    )?,
                    transparent_address,
                )
            }
            KeyScope::Zip32(zip32::Scope::Internal) => {
                let internal_address = account
                    .ufvk()
                    .and_then(|k| k.transparent())
                    .expect("presence of transparent key was checked above.")
                    .derive_internal_ivk()?
                    .derive_address(index)?;
                (
                    Address::from(internal_address).to_zcash_address(params),
                    internal_address,
                )
            }
            KeyScope::Ephemeral => {
                let ephemeral_address = account
                    .ufvk()
                    .and_then(|k| k.transparent())
                    .expect("presence of transparent key was checked above.")
                    .derive_ephemeral_ivk()?
                    .derive_ephemeral_address(index)?;
                (
                    Address::from(ephemeral_address).to_zcash_address(params),
                    ephemeral_address,
                )
            }
        })
    };

    let gap_limit = match key_scope {
        KeyScope::Zip32(zip32::Scope::External) => gap_limits.external(),
        KeyScope::Zip32(zip32::Scope::Internal) => gap_limits.internal(),
        KeyScope::Ephemeral => gap_limits.ephemeral(),
    };

    if let Some(gap_start) = find_gap_start(conn, account_id, key_scope, gap_limit)? {
        let range_to_store = gap_start.index()..gap_start.saturating_add(gap_limit).index();
        if range_to_store.is_empty() {
            return Ok(());
        }
        // exposed_at_height is initially NULL
        let mut stmt_insert_address = conn.prepare_cached(
            "INSERT INTO addresses (
                account_id, diversifier_index_be, key_scope, address,
                transparent_child_index, cached_transparent_receiver_address,
                receiver_flags
             )
             VALUES (
                :account_id, :diversifier_index_be, :key_scope, :address,
                :transparent_child_index, :transparent_address,
                :receiver_flags
             )
             ON CONFLICT (account_id, diversifier_index_be, key_scope) DO NOTHING",
        )?;

        for raw_index in range_to_store {
            let transparent_child_index = NonHardenedChildIndex::from_index(raw_index)
                .expect("restricted to valid range above");
            let (zcash_address, transparent_address) =
                gen_addrs(key_scope, transparent_child_index)?;
            let receiver_flags: ReceiverFlags = zcash_address
                .clone()
                .convert::<ReceiverFlags>()
                .expect("address is valid");

            stmt_insert_address.execute(named_params![
                ":account_id": account_id.0,
                ":diversifier_index_be": encode_diversifier_index_be(transparent_child_index.into()),
                ":key_scope": key_scope.encode(),
                ":address": zcash_address.encode(),
                ":transparent_child_index": raw_index,
                ":transparent_address": transparent_address.encode(params),
                ":receiver_flags": receiver_flags.bits()
            ])?;
        }
    }

    Ok(())
}

/// Check whether `address` has previously been used as the recipient address for any previously
/// received output. This is intended primarily for use in ensuring that the wallet does not create
/// ZIP 320 transactions that reuse the same ephemeral address, although it is written in such a
/// way that it may be used for detection of transparent address reuse more generally.
///
/// If the address was already used in an output we received, this method will return
/// [`SqliteClientError::AddressReuse`].
pub(crate) fn check_ephemeral_address_reuse<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    address: &TransparentAddress,
) -> Result<(), SqliteClientError> {
    let taddr_str = address.encode(params);
    let mut stmt = conn.prepare_cached(
        "SELECT t.txid
         FROM transactions t
         JOIN v_received_outputs vro ON vro.transaction_id = t.id_tx
         JOIN addresses a ON a.id = vro.address_id
         WHERE a.cached_transparent_receiver_address = :transparent_address",
    )?;

    let txids = stmt
        .query_and_then(
            named_params![
                ":transparent_address": taddr_str,
            ],
            |row| Ok(TxId::from_bytes(row.get::<_, [u8; 32]>(0)?)),
        )?
        .collect::<Result<Vec<_>, SqliteClientError>>()?;

    if let Some(txids) = NonEmpty::from_vec(txids) {
        return Err(SqliteClientError::AddressReuse(taddr_str, txids));
    }

    Ok(())
}

/// Returns the block height at which we should start scanning for UTXOs.
///
/// We must start looking for UTXOs for addresses within the current gap limit as of the block
/// height at which they might have first been revealed. This would have occurred when the gap
/// advanced as a consequence of a transaction being mined. The address at the start of the current
/// gap was potentially first revealed after the address at index `gap_start - (gap_limit + 1)`
/// received an output in a mined transaction; therefore, we take that height to be where we should
/// start searching for UTXOs.
pub(crate) fn utxo_query_height(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
    gap_limits: &GapLimits,
) -> Result<BlockHeight, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT MIN(au.mined_height)
         FROM v_address_uses au
         JOIN addresses a ON a.id = au.address_id
         WHERE a.account_id = :account_id
         AND au.key_scope = :key_scope
         AND au.transparent_child_index >= :transparent_child_index",
    )?;

    let mut get_height = |key_scope: KeyScope, gap_limit: u32| {
        if let Some(gap_start) = find_gap_start(conn, account_ref, key_scope, gap_limit)? {
            stmt.query_row(
                named_params! {
                    ":account_id": account_ref.0,
                    ":key_scope": key_scope.encode(),
                    ":transparent_child_index": gap_start.index().saturating_sub(gap_limit + 1)
                },
                |row| {
                    row.get::<_, Option<u32>>(0)
                        .map(|opt| opt.map(BlockHeight::from))
                },
            )
            .optional()
            .map(|opt| opt.flatten())
            .map_err(SqliteClientError::from)
        } else {
            Ok(None)
        }
    };

    let h_external = get_height(KeyScope::EXTERNAL, gap_limits.external())?;
    let h_internal = get_height(KeyScope::INTERNAL, gap_limits.internal())?;

    match (h_external, h_internal) {
        (Some(ext), Some(int)) => Ok(std::cmp::min(ext, int)),
        (Some(h), None) | (None, Some(h)) => Ok(h),
        (None, None) => account_birthday_internal(conn, account_ref),
    }
}

fn to_unspent_transparent_output(row: &Row) -> Result<WalletTransparentOutput, SqliteClientError> {
    let txid: Vec<u8> = row.get("txid")?;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&txid);

    let index: u32 = row.get("output_index")?;
    let script_pubkey = Script(row.get("script")?);
    let raw_value: i64 = row.get("value_zat")?;
    let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
        SqliteClientError::CorruptedData(format!("Invalid UTXO value: {}", raw_value))
    })?;
    let height: Option<u32> = row.get("received_height")?;

    let outpoint = OutPoint::new(txid_bytes, index);
    WalletTransparentOutput::from_parts(
        outpoint,
        TxOut {
            value,
            script_pubkey,
        },
        height.map(BlockHeight::from),
    )
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Txout script_pubkey value did not correspond to a P2PKH or P2SH address".to_string(),
        )
    })
}

/// Select an output to fund a new transaction that is targeting at least `chain_tip_height + 1`.
pub(crate) fn get_wallet_transparent_output(
    conn: &rusqlite::Connection,
    outpoint: &OutPoint,
    allow_unspendable: bool,
) -> Result<Option<WalletTransparentOutput>, SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?;

    // This could return as unspent outputs that are actually not spendable, if they are the
    // outputs of deshielding transactions where the spend anchors have been invalidated by a
    // rewind or spent in a transaction that has not been observed by this wallet. There isn't a
    // way to detect the circumstance related to anchor invalidation at present, but it should be
    // vanishingly rare as the vast majority of rewinds are of a single block.
    let mut stmt_select_utxo = conn.prepare_cached(
        "SELECT t.txid, u.output_index, u.script,
                u.value_zat, t.mined_height AS received_height
         FROM transparent_received_outputs u
         JOIN transactions t ON t.id_tx = u.transaction_id
         WHERE t.txid = :txid
         AND u.output_index = :output_index
         -- the transaction that created the output is mined or is definitely unexpired
         AND (
             :allow_unspendable
             OR (
                 (
                    t.mined_height IS NOT NULL -- tx is mined
                    -- TODO: uncomment the following two lines in order to enable zero-conf spends
                    -- OR t.expiry_height = 0 -- tx will not expire
                    -- OR t.expiry_height >= :mempool_height -- tx has not yet expired
                 )
                 -- and the output is unspent
                 AND u.id NOT IN (
                    SELECT txo_spends.transparent_received_output_id
                    FROM transparent_received_output_spends txo_spends
                    JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
                    WHERE tx.mined_height IS NOT NULL  -- the spending tx is mined
                    OR tx.expiry_height = 0 -- the spending tx will not expire
                    OR tx.expiry_height >= :mempool_height -- the spending tx has not yet expired
                 )
             )
         )",
    )?;

    let result: Result<Option<WalletTransparentOutput>, SqliteClientError> = stmt_select_utxo
        .query_and_then(
            named_params![
                ":txid": outpoint.hash(),
                ":output_index": outpoint.n(),
                ":mempool_height": chain_tip_height.map(|h| u32::from(h) + 1),
                ":allow_unspendable": allow_unspendable
            ],
            to_unspent_transparent_output,
        )?
        .next()
        .transpose();

    result
}

/// Returns the list of spendable transparent outputs received by this wallet at `address`
/// such that, at height `target_height`:
/// * the transaction that produced the output had or will have at least `min_confirmations`
///   confirmations; and
/// * the output is unspent as of the current chain tip.
///
/// An output that is potentially spent by an unmined transaction in the mempool is excluded
/// iff the spending transaction will not be expired at `target_height`.
///
/// This could, in very rare circumstances, return as unspent outputs that are actually not
/// spendable, if they are the outputs of deshielding transactions where the spend anchors have
/// been invalidated by a rewind. There isn't a way to detect this circumstance at present, but
/// it should be vanishingly rare as the vast majority of rewinds are of a single block.
pub(crate) fn get_spendable_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
    target_height: BlockHeight,
    min_confirmations: u32,
) -> Result<Vec<WalletTransparentOutput>, SqliteClientError> {
    let confirmed_height = target_height - min_confirmations;

    let mut stmt_utxos = conn.prepare(
        "SELECT t.txid, u.output_index, u.script,
                u.value_zat, t.mined_height AS received_height
         FROM transparent_received_outputs u
         JOIN transactions t ON t.id_tx = u.transaction_id
         WHERE u.address = :address
         -- the transaction that created the output is mined or unexpired as of `confirmed_height`
         AND (
            t.mined_height <= :confirmed_height -- tx is mined
            -- TODO: uncomment the following lines in order to enable zero-conf spends
            -- OR (
            --     :min_confirmations = 0
            --     AND (
            --         t.expiry_height = 0 -- tx will not expire
            --         OR t.expiry_height >= :target_height
            --     )
            -- )
         )
         -- and the output is unspent
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE tx.mined_height IS NOT NULL -- the spending transaction is mined
            OR tx.expiry_height = 0 -- the spending tx will not expire
            OR tx.expiry_height >= :target_height -- the spending tx has not yet expired
            -- we are intentionally conservative and exclude outputs that are potentially spent
            -- as of the target height, even if they might actually be spendable due to expiry
            -- of the spending transaction as of the chain tip
         )",
    )?;

    let addr_str = address.encode(params);
    let mut rows = stmt_utxos.query(named_params![
        ":address": addr_str,
        ":confirmed_height": u32::from(confirmed_height),
        ":target_height": u32::from(target_height),
        //":min_confirmations": min_confirmations
    ])?;

    let mut utxos = Vec::<WalletTransparentOutput>::new();
    while let Some(row) = rows.next()? {
        let output = to_unspent_transparent_output(row)?;
        utxos.push(output);
    }

    Ok(utxos)
}

/// Returns a mapping from each transparent receiver associated with the specified account
/// to its not-yet-shielded UTXO balance, including only the effects of transactions mined
/// at a block height less than or equal to `summary_height`.
///
/// Only non-ephemeral transparent receivers with a non-zero balance at the summary height
/// will be included.
pub(crate) fn get_transparent_balances<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
    summary_height: BlockHeight,
) -> Result<HashMap<TransparentAddress, Zatoshis>, SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;

    let mut stmt_address_balances = conn.prepare(
        "SELECT u.address, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN accounts ON accounts.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         WHERE accounts.uuid = :account_uuid
         -- the transaction that created the output is mined or is definitely unexpired
         AND (
            t.mined_height <= :summary_height -- tx is mined
            OR ( -- or the caller has requested to include zero-conf funds that are not expired
                :summary_height > :chain_tip_height
                AND (
                    t.expiry_height = 0 -- tx will not expire
                    OR t.expiry_height >= :summary_height
                )
            )
         )
         -- and the output is unspent
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE tx.mined_height IS NOT NULL -- the spending tx is mined
            OR tx.expiry_height = 0 -- the spending tx will not expire
            OR tx.expiry_height >= :spend_expiry_height -- the spending tx is unexpired
         )
         GROUP BY u.address",
    )?;

    let mut res = HashMap::new();
    let mut rows = stmt_address_balances.query(named_params![
        ":account_uuid": account_uuid.0,
        ":summary_height": u32::from(summary_height),
        ":chain_tip_height": u32::from(chain_tip_height),
        ":spend_expiry_height": u32::from(std::cmp::min(summary_height, chain_tip_height + 1)),
    ])?;
    while let Some(row) = rows.next()? {
        let taddr_str: String = row.get(0)?;
        let taddr = TransparentAddress::decode(params, &taddr_str)?;
        let value = Zatoshis::from_nonnegative_i64(row.get(1)?)?;

        res.insert(taddr, value);
    }

    Ok(res)
}

#[tracing::instrument(skip(conn, account_balances))]
pub(crate) fn add_transparent_account_balances(
    conn: &rusqlite::Connection,
    mempool_height: BlockHeight,
    min_confirmations: u32,
    account_balances: &mut HashMap<AccountUuid, AccountBalance>,
) -> Result<(), SqliteClientError> {
    // TODO (#1592): Ability to distinguish between Transparent pending change and pending non-change
    let mut stmt_account_spendable_balances = conn.prepare(
        "SELECT a.uuid, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN accounts a ON a.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         -- the transaction that created the output is mined and with enough confirmations
         WHERE (
            t.mined_height < :mempool_height -- tx is mined
            AND :mempool_height - t.mined_height >= :min_confirmations -- has at least min_confirmations
         )
         -- and the received txo is unspent
         AND u.id NOT IN (
           SELECT transparent_received_output_id
           FROM transparent_received_output_spends txo_spends
           JOIN transactions tx
             ON tx.id_tx = txo_spends.transaction_id
           WHERE tx.mined_height IS NOT NULL -- the spending tx is mined
           OR tx.expiry_height = 0 -- the spending tx will not expire
           OR tx.expiry_height >= :mempool_height -- the spending tx is unexpired
         )
         GROUP BY a.uuid",
    )?;
    let mut rows = stmt_account_spendable_balances.query(named_params![
        ":mempool_height": u32::from(mempool_height),
        ":min_confirmations": min_confirmations,
    ])?;

    while let Some(row) = rows.next()? {
        let account = AccountUuid(row.get(0)?);
        let raw_value = row.get(1)?;
        let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
        })?;

        account_balances
            .entry(account)
            .or_insert(AccountBalance::ZERO)
            .with_unshielded_balance_mut(|bal| bal.add_spendable_value(value))?;
    }

    let mut stmt_account_unconfirmed_balances = conn.prepare(
        "SELECT a.uuid, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN accounts a ON a.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         -- the transaction that created the output is mined with not enough confirmations or is definitely unexpired
         WHERE (
            t.mined_height < :mempool_height
            AND :mempool_height - t.mined_height < :min_confirmations -- tx is mined but not confirmed
            OR t.expiry_height = 0 -- tx will not expire
            OR t.expiry_height >= :mempool_height
         )
         -- and the received txo is unspent
         AND u.id NOT IN (
           SELECT transparent_received_output_id
           FROM transparent_received_output_spends txo_spends
           JOIN transactions tx
             ON tx.id_tx = txo_spends.transaction_id
           WHERE tx.mined_height IS NOT NULL -- the spending tx is mined
           OR tx.expiry_height = 0 -- the spending tx will not expire
           OR tx.expiry_height >= :mempool_height -- the spending tx is unexpired
         )
         GROUP BY a.uuid",
    )?;

    let mut rows = stmt_account_unconfirmed_balances.query(named_params![
        ":mempool_height": u32::from(mempool_height),
        ":min_confirmations": min_confirmations,
    ])?;

    while let Some(row) = rows.next()? {
        let account = AccountUuid(row.get(0)?);
        let raw_value = row.get(1)?;
        let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
        })?;

        account_balances
            .entry(account)
            .or_insert(AccountBalance::ZERO)
            .with_unshielded_balance_mut(|bal| bal.add_pending_spendable_value(value))?;
    }
    Ok(())
}

/// Marks the given UTXO as having been spent.
///
/// Returns `true` if the UTXO was known to the wallet.
pub(crate) fn mark_transparent_utxo_spent(
    conn: &rusqlite::Connection,
    spent_in_tx: TxRef,
    outpoint: &OutPoint,
) -> Result<bool, SqliteClientError> {
    let spend_params = named_params![
        ":spent_in_tx": spent_in_tx.0,
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
    ];
    let mut stmt_mark_transparent_utxo_spent = conn.prepare_cached(
        "INSERT INTO transparent_received_output_spends (transparent_received_output_id, transaction_id)
         SELECT txo.id, :spent_in_tx
         FROM transparent_received_outputs txo
         JOIN transactions t ON t.id_tx = txo.transaction_id
         WHERE t.txid = :prevout_txid
         AND txo.output_index = :prevout_idx
         ON CONFLICT (transparent_received_output_id, transaction_id)
         -- The following UPDATE is effectively a no-op, but we perform it anyway so that the
         -- number of affected rows can be used to determine whether a record existed.
         DO UPDATE SET transaction_id = :spent_in_tx",
    )?;
    let affected_rows = stmt_mark_transparent_utxo_spent.execute(spend_params)?;

    // Since we know that the output is spent, we no longer need to search for
    // it to find out if it has been spent.
    let mut stmt_remove_spend_detection = conn.prepare_cached(
        "DELETE FROM transparent_spend_search_queue
         WHERE output_index = :prevout_idx
         AND transaction_id IN (
            SELECT id_tx FROM transactions WHERE txid = :prevout_txid
         )",
    )?;
    stmt_remove_spend_detection.execute(named_params![
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
    ])?;

    // If no rows were affected, we know that we don't actually have the output in
    // `transparent_received_outputs` yet, so we have to record the output as spent
    // so that when we eventually detect the output, we can create the spend record.
    if affected_rows == 0 {
        conn.execute(
            "INSERT INTO transparent_spend_map (
                spending_transaction_id,
                prevout_txid,
                prevout_output_index
            )
            VALUES (:spent_in_tx, :prevout_txid, :prevout_idx)
            ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index)
            DO NOTHING",
            spend_params,
        )?;
    }

    Ok(affected_rows > 0)
}

/// Adds the given received UTXO to the datastore.
pub(crate) fn put_received_transparent_utxo<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    output: &WalletTransparentOutput,
) -> Result<(AccountRef, KeyScope, UtxoId), SqliteClientError> {
    put_transparent_output(
        conn,
        params,
        output.outpoint(),
        output.txout(),
        output.mined_height(),
        output.recipient_address(),
        true,
    )
}

/// An enumeration of the types of errors that can occur when scheduling an event to happen at a
/// specific time.
#[derive(Debug, Clone)]
pub enum SchedulingError {
    /// An error occurred in sampling a time offset using an exponential distribution.
    Distribution(rand_distr::ExpError),
    /// The system attempted to generate an invalid timestamp.
    Time(SystemTimeError),
    /// A generated duration was out of the range of valid integer values for durations.
    OutOfRange(TryFromIntError),
}

impl std::fmt::Display for SchedulingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            SchedulingError::Distribution(e) => {
                write!(f, "Failure in sampling scheduling time: {}", e)
            }
            SchedulingError::Time(t) => write!(f, "Invalid system time: {}", t),
            SchedulingError::OutOfRange(t) => write!(f, "Not a valid timestamp or duration: {}", t),
        }
    }
}

impl std::error::Error for SchedulingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            SchedulingError::Distribution(_) => None,
            SchedulingError::Time(t) => Some(t),
            SchedulingError::OutOfRange(i) => Some(i),
        }
    }
}

impl From<rand_distr::ExpError> for SchedulingError {
    fn from(value: rand_distr::ExpError) -> Self {
        SchedulingError::Distribution(value)
    }
}

impl From<SystemTimeError> for SchedulingError {
    fn from(value: SystemTimeError) -> Self {
        SchedulingError::Time(value)
    }
}

impl From<TryFromIntError> for SchedulingError {
    fn from(value: TryFromIntError) -> Self {
        SchedulingError::OutOfRange(value)
    }
}

/// Sample a random timestamp from an exponential distribution such that the expected value of the
/// generated timestamp is `check_interval_seconds` after the provided `from_event` time.
pub(crate) fn next_check_time<R: RngCore, D: DerefMut<Target = R>>(
    mut rng: D,
    from_event: SystemTime,
    check_interval_seconds: u32,
) -> Result<SystemTime, SchedulingError> {
    // A λ parameter of 1/check_interval_seconds will result in a distribution with an expected
    // value of `check_interval_seconds`.
    let dist = rand_distr::Exp::new(1.0 / f64::from(check_interval_seconds))?;
    let event_delay = dist.sample(rng.deref_mut()).round() as u64;

    Ok(from_event + Duration::new(event_delay, 0))
}

/// Returns the vector of [`TransactionDataRequest`]s that represents the information needed by the
/// wallet backend in order to be able to present a complete view of wallet history and memo data.
pub(crate) fn transaction_data_requests<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<Vec<TransactionDataRequest>, SqliteClientError> {
    // `lightwalletd` will return an error for `GetTaddressTxids` requests having an end height
    // greater than the current chain tip height, so we take the chain tip height into account
    // here in order to make this pothole easier for clients of the API to avoid.
    let chain_tip_height =
        super::chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;

    // We cannot construct address-based transaction data requests for the case where we cannot
    // determine the height at which to begin, so we require that either the target height or mined
    // height be set.
    let mut spend_requests_stmt = conn.prepare_cached(
        "SELECT
            ssq.address,
            IFNULL(t.target_height, t.mined_height)
         FROM transparent_spend_search_queue ssq
         JOIN transactions t ON t.id_tx = ssq.transaction_id
         WHERE t.target_height IS NOT NULL
         OR t.mined_height IS NOT NULL",
    )?;

    let spend_search_rows = spend_requests_stmt.query_and_then([], |row| {
        let address = TransparentAddress::decode(params, &row.get::<_, String>(0)?)?;
        let block_range_start = BlockHeight::from(row.get::<_, u32>(1)?);
        let max_end_height = block_range_start + DEFAULT_TX_EXPIRY_DELTA + 1;
        Ok::<TransactionDataRequest, SqliteClientError>(
            TransactionDataRequest::TransactionsInvolvingAddress {
                address,
                block_range_start,
                block_range_end: Some(std::cmp::min(chain_tip_height + 1, max_end_height)),
                request_at: None,
                tx_status_filter: TransactionStatusFilter::Mined,
                output_status_filter: OutputStatusFilter::All,
            },
        )
    })?;

    // Since we don't want to interpret funds that are temporarily held by an ephemeral address in
    // the course of creating ZIP 320 transaction pair as belonging to the wallet, we will perform
    // ephemeral address checks only for addresses that do not have an unexpired transaction
    // associated with them in the database. If, for some reason, the second transaction in a ZIP
    // 320 pair fails to be mined after the first transaction in the pair succeeded, we will begin
    // including the associated ephemeral address in the set to be checked for funds only after
    // the transaction that spends from it has expired.
    let mut ephemeral_check_stmt = conn.prepare_cached(
        "SELECT
            cached_transparent_receiver_address,
            transparent_receiver_next_check_time
         FROM addresses
         WHERE key_scope = :ephemeral_key_scope
         AND NOT EXISTS (
            SELECT 'x'
            FROM transparent_received_outputs tro
            JOIN transactions t ON t.id_tx = tro.transaction_id
            WHERE tro.address_id = addresses.id
            AND t.expiry_height > :chain_tip_height
         )",
    )?;

    let ephemeral_check_rows = ephemeral_check_stmt.query_and_then(
        named_params! {
            ":ephemeral_key_scope": KeyScope::Ephemeral.encode(),
            ":chain_tip_height": u32::from(chain_tip_height)
        },
        |row| {
            let address = TransparentAddress::decode(params, &row.get::<_, String>(0)?)?;
            let request_at = row
                .get::<_, Option<i64>>(1)?
                .map(decode_epoch_seconds)
                .transpose()?;

            Ok::<TransactionDataRequest, SqliteClientError>(
                TransactionDataRequest::TransactionsInvolvingAddress {
                    address,
                    // We don't want these queries to leak anything about when the wallet created
                    // or exposed the address, so we just query for all UTXOs for the address.
                    block_range_start: BlockHeight::from(0),
                    block_range_end: None,
                    request_at,
                    tx_status_filter: TransactionStatusFilter::All,
                    output_status_filter: OutputStatusFilter::Unspent,
                },
            )
        },
    )?;

    spend_search_rows
        .chain(ephemeral_check_rows)
        .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn get_transparent_address_metadata<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
    address: &TransparentAddress,
) -> Result<Option<TransparentAddressMetadata>, SqliteClientError> {
    let address_str = address.encode(params);
    let addr_meta = conn
        .query_row(
            "SELECT diversifier_index_be, key_scope
             FROM addresses
             JOIN accounts ON addresses.account_id = accounts.id
             WHERE accounts.uuid = :account_uuid
             AND cached_transparent_receiver_address = :address",
            named_params![":account_uuid": account_uuid.0, ":address": &address_str],
            |row| {
                let di_be: Vec<u8> = row.get(0)?;
                let scope_code = row.get(1)?;
                Ok(KeyScope::decode(scope_code).and_then(|key_scope| {
                    address_index_from_diversifier_index_be(&di_be).map(|address_index| {
                        TransparentAddressMetadata::new(key_scope.into(), address_index)
                    })
                }))
            },
        )
        .optional()?
        .transpose()?;

    if addr_meta.is_some() {
        return Ok(addr_meta);
    }

    if let Some((legacy_taddr, address_index)) =
        get_legacy_transparent_address(params, conn, account_uuid)?
    {
        if &legacy_taddr == address {
            let metadata = TransparentAddressMetadata::new(Scope::External.into(), address_index);
            return Ok(Some(metadata));
        }
    }

    Ok(None)
}

/// Attempts to determine the account that received the given transparent output.
///
/// The following three locations in the wallet's key tree are searched:
/// - Transparent receivers that have been generated as part of a Unified Address.
/// - Transparent ephemeral addresses that have been reserved or are within
///   the gap limit from the last reserved address.
/// - "Legacy transparent addresses" (at BIP 44 address index 0 within an account).
///
/// Returns `Ok(None)` if the transparent output's recipient address is not in any of the
/// above locations. This means the wallet considers the output "not interesting".
pub(crate) fn find_account_uuid_for_transparent_address<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
) -> Result<Option<(AccountUuid, KeyScope)>, SqliteClientError> {
    let address_str = address.encode(params);

    if let Some((account_id, key_scope_code)) = conn
        .query_row(
            "SELECT accounts.uuid, addresses.key_scope
             FROM addresses
             JOIN accounts ON accounts.id = addresses.account_id
             WHERE cached_transparent_receiver_address = :address",
            named_params![":address": &address_str],
            |row| Ok((AccountUuid(row.get(0)?), row.get(1)?)),
        )
        .optional()?
    {
        return Ok(Some((account_id, KeyScope::decode(key_scope_code)?)));
    }

    let account_ids = get_account_ids(conn)?;

    // If the UTXO is received at the legacy transparent address (at BIP 44 address
    // index 0 within its particular account, which we specifically ensure is returned
    // from `get_transparent_receivers`), there may be no entry in the addresses table
    // that can be used to tie the address to a particular account. In this case, we
    // look up the legacy address for each account in the wallet, and check whether it
    // matches the address for the received UTXO.
    for &account_id in account_ids.iter() {
        if let Some((legacy_taddr, _)) = get_legacy_transparent_address(params, conn, account_id)? {
            if &legacy_taddr == address {
                return Ok(Some((account_id, KeyScope::EXTERNAL)));
            }
        }
    }

    Ok(None)
}

/// Add a transparent output relevant to this wallet to the database.
///
/// `output_height` may be None if this is an ephemeral output from a
/// transaction we created, that we do not yet know to have been mined.
#[allow(clippy::too_many_arguments)]
pub(crate) fn put_transparent_output<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    outpoint: &OutPoint,
    txout: &TxOut,
    output_height: Option<BlockHeight>,
    address: &TransparentAddress,
    known_unspent: bool,
) -> Result<(AccountRef, KeyScope, UtxoId), SqliteClientError> {
    let addr_str = address.encode(params);

    // Unlike the shielded pools, we only can receive transparent outputs on addresses for which we
    // have an `addresses` table entry, so we can just query for that here.
    let (address_id, account_id, key_scope_code) = conn
        .query_row(
            "SELECT id, account_id, key_scope
             FROM addresses
             WHERE cached_transparent_receiver_address = :transparent_address",
            named_params! {":transparent_address": addr_str},
            |row| {
                Ok((
                    row.get("id").map(AddressRef)?,
                    row.get("account_id").map(AccountRef)?,
                    row.get("key_scope")?,
                ))
            },
        )
        .optional()?
        .ok_or(SqliteClientError::AddressNotRecognized(*address))?;

    let key_scope = KeyScope::decode(key_scope_code)?;

    let output_height = output_height.map(u32::from);

    // Check whether we have an entry in the blocks table for the output height;
    // if not, the transaction will be updated with its mined height when the
    // associated block is scanned.
    let block = match output_height {
        Some(height) => conn
            .query_row(
                "SELECT height FROM blocks WHERE height = :height",
                named_params![":height": height],
                |row| row.get::<_, u32>(0),
            )
            .optional()?,
        None => None,
    };

    let id_tx = conn.query_row(
        "INSERT INTO transactions (txid, block, mined_height)
         VALUES (:txid, :block, :mined_height)
         ON CONFLICT (txid) DO UPDATE
         SET block = IFNULL(block, :block),
             mined_height = :mined_height
         RETURNING id_tx",
        named_params![
           ":txid": &outpoint.hash().to_vec(),
           ":block": block,
           ":mined_height": output_height
        ],
        |row| row.get::<_, i64>(0),
    )?;

    let spent_height = conn
        .query_row(
            "SELECT t.mined_height
             FROM transactions t
             JOIN transparent_received_output_spends ts ON ts.transaction_id = t.id_tx
             JOIN transparent_received_outputs tro ON tro.id = ts.transparent_received_output_id
             WHERE tro.transaction_id = :transaction_id
             AND tro.output_index = :output_index",
            named_params![
                ":transaction_id": id_tx,
                ":output_index": &outpoint.n(),
            ],
            |row| {
                row.get::<_, Option<u32>>(0)
                    .map(|o| o.map(BlockHeight::from))
            },
        )
        .optional()?
        .flatten();

    // The max observed unspent height is either the spending transaction's mined height - 1, or
    // the current chain tip height if the UTXO was received via a path that confirmed that it was
    // unspent, such as by querying the UTXO set of the network.
    let max_observed_unspent = match spent_height {
        Some(h) => Some(h - 1),
        None => {
            if known_unspent {
                chain_tip_height(conn)?
            } else {
                None
            }
        }
    };

    let mut stmt_upsert_transparent_output = conn.prepare_cached(
        "INSERT INTO transparent_received_outputs (
            transaction_id, output_index,
            account_id, address_id, address, script,
            value_zat, max_observed_unspent_height
        )
        VALUES (
            :transaction_id, :output_index,
            :account_id, :address_id, :address, :script,
            :value_zat, :max_observed_unspent_height
        )
        ON CONFLICT (transaction_id, output_index) DO UPDATE
        SET account_id = :account_id,
            address_id = :address_id,
            address = :address,
            script = :script,
            value_zat = :value_zat,
            max_observed_unspent_height = IFNULL(:max_observed_unspent_height, max_observed_unspent_height)
        RETURNING id",
    )?;

    let sql_args = named_params![
        ":transaction_id": id_tx,
        ":output_index": &outpoint.n(),
        ":account_id": account_id.0,
        ":address_id": address_id.0,
        ":address": &address.encode(params),
        ":script": &txout.script_pubkey.0,
        ":value_zat": &i64::from(ZatBalance::from(txout.value)),
        ":max_observed_unspent_height": max_observed_unspent.map(u32::from),
    ];

    let utxo_id = stmt_upsert_transparent_output
        .query_row(sql_args, |row| row.get::<_, i64>(0).map(UtxoId))?;

    // If we have a record of the output already having been spent, then mark it as spent using the
    // stored reference to the spending transaction.
    let spending_tx_ref = conn
        .query_row(
            "SELECT ts.spending_transaction_id
             FROM transparent_spend_map ts
             JOIN transactions t ON t.id_tx = ts.spending_transaction_id
             WHERE ts.prevout_txid = :prevout_txid
             AND ts.prevout_output_index = :prevout_idx
             ORDER BY t.block NULLS LAST LIMIT 1",
            named_params![
                ":prevout_txid": outpoint.txid().as_ref(),
                ":prevout_idx": outpoint.n()
            ],
            |row| row.get::<_, i64>(0).map(TxRef),
        )
        .optional()?;

    if let Some(spending_transaction_id) = spending_tx_ref {
        mark_transparent_utxo_spent(conn, spending_transaction_id, outpoint)?;
    }

    Ok((account_id, key_scope, utxo_id))
}

/// Adds a request to retrieve transactions involving the specified address to the transparent
/// spend search queue. Note that such requests are _not_ for data related to `tx_ref`, but instead
/// a request to find where the UTXO with the outpoint `(tx_ref, output_index)` is spent.
///
/// ### Parameters
/// - `receiving_address`: The address that received the UTXO.
/// - `tx_ref`: The transaction in which the UTXO was received.
/// - `output_index`: The index of the output within `vout` of the specified transaction.
pub(crate) fn queue_transparent_spend_detection<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    receiving_address: TransparentAddress,
    tx_ref: TxRef,
    output_index: u32,
) -> Result<(), SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO transparent_spend_search_queue
         (address, transaction_id, output_index)
         VALUES
         (:address, :transaction_id, :output_index)
         ON CONFLICT (transaction_id, output_index) DO NOTHING",
    )?;

    let addr_str = receiving_address.encode(params);
    stmt.execute(named_params! {
        ":address": addr_str,
        ":transaction_id": tx_ref.0,
        ":output_index": output_index
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use transparent::keys::NonHardenedChildIndex;
    use zcash_client_backend::{
        data_api::{testing::TestBuilder, Account as _, WalletWrite},
        wallet::TransparentAddressMetadata,
    };
    use zcash_primitives::block::BlockHash;

    use crate::{
        error::SqliteClientError,
        testing::{db::TestDbFactory, BlockCache},
        wallet::{
            get_account_ref,
            transparent::{ephemeral, find_gap_start, reserve_next_n_addresses},
            KeyScope,
        },
        GapLimits, WalletDb,
    };

    #[test]
    fn put_received_transparent_utxo() {
        zcash_client_backend::data_api::testing::transparent::put_received_transparent_utxo(
            TestDbFactory::default(),
        );
    }

    #[test]
    fn transparent_balance_across_shielding() {
        zcash_client_backend::data_api::testing::transparent::transparent_balance_across_shielding(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn transparent_balance_spendability() {
        zcash_client_backend::data_api::testing::transparent::transparent_balance_spendability(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn gap_limits() {
        zcash_client_backend::data_api::testing::transparent::gap_limits(
            TestDbFactory::default(),
            BlockCache::new(),
            GapLimits::default().into(),
        );
    }

    #[test]
    fn ephemeral_address_management() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let birthday = st.test_account().unwrap().birthday().clone();
        let account0_uuid = st.test_account().unwrap().account().id();
        let account0_id = get_account_ref(&st.wallet().db().conn, account0_uuid).unwrap();

        // The chain height must be known in order to reserve addresses, as we store the height at
        // which the address was considered to be exposed.
        st.wallet_mut()
            .db_mut()
            .update_chain_tip(birthday.height())
            .unwrap();

        let check = |db: &WalletDb<_, _, _, _>, account_id| {
            eprintln!("checking {account_id:?}");
            assert_matches!(
                find_gap_start(&db.conn, account_id, KeyScope::Ephemeral, db.gap_limits.ephemeral()), Ok(addr_index)
                    if addr_index == Some(NonHardenedChildIndex::ZERO)
            );
            //assert_matches!(ephemeral::first_unstored_index(&db.conn, account_id), Ok(addr_index) if addr_index == GAP_LIMIT);

            let known_addrs =
                ephemeral::get_known_ephemeral_addresses(&db.conn, &db.params, account_id, None)
                    .unwrap();

            let expected_metadata: Vec<TransparentAddressMetadata> = (0..db.gap_limits.ephemeral())
                .map(|i| ephemeral::metadata(NonHardenedChildIndex::from_index(i).unwrap()))
                .collect();
            let actual_metadata: Vec<TransparentAddressMetadata> =
                known_addrs.into_iter().map(|(_, meta)| meta).collect();
            assert_eq!(actual_metadata, expected_metadata);

            let transaction = &db.conn.unchecked_transaction().unwrap();
            // reserve half the addresses (rounding down)
            let reserved = reserve_next_n_addresses(
                transaction,
                &db.params,
                account_id,
                KeyScope::Ephemeral,
                db.gap_limits.ephemeral(),
                (db.gap_limits.ephemeral() / 2) as usize,
            )
            .unwrap();
            assert_eq!(reserved.len(), (db.gap_limits.ephemeral() / 2) as usize);

            // we have not yet used any of the addresses, so the maximum available address index
            // should not have increased, and therefore attempting to reserve a full gap limit
            // worth of addresses should fail.
            assert_matches!(
                reserve_next_n_addresses(
                    transaction,
                    &db.params,
                    account_id,
                    KeyScope::Ephemeral,
                    db.gap_limits.ephemeral(),
                    db.gap_limits.ephemeral() as usize
                ),
                Err(SqliteClientError::ReachedGapLimit(..))
            );
        };

        check(st.wallet().db(), account0_id);

        // Creating a new account should initialize `ephemeral_addresses` for that account.
        let seed1 = vec![0x01; 32];
        let (account1_uuid, _usk) = st
            .wallet_mut()
            .db_mut()
            .create_account("test1", &Secret::new(seed1), &birthday, None)
            .unwrap();
        let account1_id = get_account_ref(&st.wallet().db().conn, account1_uuid).unwrap();
        assert_ne!(account0_id, account1_id);
        check(st.wallet().db(), account1_id);
    }
}
