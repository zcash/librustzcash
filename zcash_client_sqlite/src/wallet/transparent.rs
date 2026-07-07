//! Functions for transparent input support in the wallet.
use core::ops::Range;
use std::collections::{HashMap, HashSet};
use std::num::TryFromIntError;
use std::ops::DerefMut;
use std::rc::Rc;
use std::time::{Duration, SystemTime, SystemTimeError};

use nonempty::NonEmpty;
use rand::RngCore;
use rand_distr::Distribution;
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use rusqlite::{Connection, Row, named_params};
use tracing::{debug, warn};

use transparent::{
    address::{Script, TransparentAddress},
    bundle::{OutPoint, TxOut},
    keys::{IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope},
};
use zcash_address::unified::{Ivk, Uivk};
use zcash_client_backend::{
    data_api::{
        Account, AccountBalance, Balance, CoinbaseFilter, OutputStatusFilter, TargetValue,
        TransactionDataRequest, TransactionStatusFilter, TransparentBalances,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    fees::StandardFeeRule,
    wallet::{
        Exposure, GapMetadata, TransparentAddressMetadata, TransparentAddressSource,
        WalletTransparentOutput,
    },
};
use zcash_keys::{
    address::Address,
    encoding::AddressCodec,
    keys::{
        AddressGenerationError, UnifiedAddressRequest, UnifiedFullViewingKey,
        UnifiedIncomingViewingKey,
        transparent::gap_limits::{GapLimits, generate_address_list},
    },
};
#[cfg(not(feature = "spend-index"))]
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_primitives::transaction::fees::{
    FeeRule,
    transparent::{InputSize, InputView},
    zip317,
};
use zcash_protocol::{
    TxId,
    consensus::{self, BlockHeight, COINBASE_MATURITY_BLOCKS},
    value::{ZatBalance, Zatoshis},
};
use zcash_script::script;
use zip32::Scope;

#[cfg(feature = "transparent-key-import")]
use bip32::{PublicKey, PublicKeyBytes};

use super::{
    KeyScope, account_birthday_internal, chain_tip_height,
    encoding::{
        ReceiverFlags, decode_diversifier_index_be, decode_epoch_seconds,
        encode_diversifier_index_be, epoch_seconds,
    },
    get_account_ids, get_account_internal,
};
use crate::{
    AccountRef, AccountUuid, AddressRef, TxRef, UtxoId,
    error::SqliteClientError,
    util::Clock,
    wallet::{common::tx_unexpired_condition, get_account, mempool_height},
};

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
    diversifier_index_be: Option<Vec<u8>>,
) -> Result<Option<NonHardenedChildIndex>, SqliteClientError> {
    decode_diversifier_index_be(diversifier_index_be)?
        .map(|di| {
            NonHardenedChildIndex::try_from(di).map_err(|_| {
                SqliteClientError::CorruptedData(
                    "Unexpected hardened index for transparent address.".to_string(),
                )
            })
        })
        .transpose()
}

pub(crate) fn get_transparent_receivers<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account_uuid: AccountUuid,
    scopes: &[KeyScope],
    exposure_depth: Option<u32>,
    exclude_used: bool,
) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, SqliteClientError> {
    let mut ret: HashMap<TransparentAddress, TransparentAddressMetadata> = HashMap::new();

    let min_exposure_height = exposure_depth
        .map(|d| {
            Ok::<_, SqliteClientError>(
                mempool_height(conn)?
                    .ok_or(SqliteClientError::ChainHeightUnknown)?
                    .saturating_sub(d),
            )
        })
        .transpose()?;

    let account_id = get_account(conn, params, account_uuid)?
        .ok_or(SqliteClientError::AccountUnknown)?
        .id;

    // A map from key scope to gap limit size for that scope and start index of the existing gap
    let gap_limit_starts = scopes
        .iter()
        .filter_map(|key_scope| {
            key_scope.as_transparent().and_then(|t_key_scope| {
                gap_limits.limit_for(t_key_scope).and_then(|limit| {
                    find_gap_start(conn, account_id, t_key_scope, limit)
                        .transpose()
                        .map(|res| res.map(|child_idx| (t_key_scope, (limit, child_idx))))
                })
            })
        })
        .collect::<Result<HashMap<TransparentKeyScope, (u32, NonHardenedChildIndex)>, SqliteClientError>>()?;

    // Get all addresses with the provided scopes.
    let mut addr_query = conn.prepare(
        "SELECT
            cached_transparent_receiver_address,
            key_scope,
            transparent_child_index,
            imported_transparent_receiver_pubkey,
            exposed_at_height,
            transparent_receiver_next_check_time,
            imported_transparent_receiver_script
         FROM addresses
         WHERE account_id = :account_id
         AND cached_transparent_receiver_address IS NOT NULL
         AND key_scope IN rarray(:scopes_ptr)
         AND (
             :min_exposure_height IS NULL
             OR exposed_at_height >= :min_exposure_height
         )
         AND (
             NOT(:exclude_used)
             -- if we're only retrieving unused addresses, do not return those for which we have
             -- observed an output.
             OR NOT EXISTS(
                 SELECT 1 FROM transparent_received_outputs tro
                 WHERE tro.address_id = addresses.id
             )
         )",
    )?;

    let scope_values: Vec<Value> = scopes.iter().map(|s| Value::Integer(s.encode())).collect();
    let scopes_ptr = Rc::new(scope_values);
    let mut rows = addr_query.query(named_params![
        ":account_id": account_id.0,
        ":scopes_ptr": &scopes_ptr,
        ":min_exposure_height": min_exposure_height.map(u32::from),
        ":exclude_used": exclude_used
    ])?;

    while let Some(row) = rows.next()? {
        let addr_str: String = row.get(0)?;
        let key_scope = KeyScope::decode(row.get(1)?)?;

        let taddr = Address::decode(params, &addr_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })?
            .to_transparent_address();

        let address_index_opt = row
            .get::<_, Option<u32>>("transparent_child_index")?
            .map(|address_index| {
                NonHardenedChildIndex::from_index(address_index).ok_or(
                    SqliteClientError::CorruptedData(format!(
                        "{} is not a valid transparent child index",
                        address_index
                    )),
                )
            })
            .transpose()?;

        let exposure =
            row.get::<_, Option<u32>>("exposed_at_height")?
                .map_or(Exposure::Unknown, |h| Exposure::Exposed {
                    at_height: BlockHeight::from(h),
                    gap_metadata: key_scope
                        .as_transparent()
                        .and_then(|t_key_scope| {
                            gap_limit_starts.get(&t_key_scope).zip(address_index_opt)
                        })
                        .map_or(
                            GapMetadata::DerivationUnknown,
                            |((gap_limit, start), idx)| {
                                if let Some(gap_position) = idx.index().checked_sub(start.index()) {
                                    GapMetadata::InGap {
                                        gap_position,
                                        gap_limit: *gap_limit,
                                    }
                                } else {
                                    GapMetadata::GapRecoverable {
                                        gap_limit: *gap_limit,
                                    }
                                }
                            },
                        ),
                });

        let next_check_time = row
            .get::<_, Option<i64>>("transparent_receiver_next_check_time")?
            .map(decode_epoch_seconds)
            .transpose()?;

        #[cfg(feature = "transparent-key-import")]
        let imported_transparent_receiver_script_bytes: Option<Vec<u8>> =
            row.get("imported_transparent_receiver_script")?;

        if let Some(taddr) = taddr {
            let p2pkh_metadata = || -> Result<TransparentAddressMetadata, SqliteClientError> {
                match key_scope {
                    #[cfg(feature = "transparent-key-import")]
                    KeyScope::Foreign => {
                        let pubkey_bytes = row
                                .get::<_, Option<Vec<u8>>>(3)?
                                .ok_or_else(|| {
                                    SqliteClientError::CorruptedData(
                                    "Pubkey bytes must be present for all imported transparent P2PKH addresses."
                                        .to_owned(),
                                )
                                })
                                .and_then(|b| {
                                    <[u8; 33]>::try_from(&b[..]).map_err(|_| {
                                        SqliteClientError::CorruptedData(format!(
                                            "Invalid public key byte length; must be 33 bytes, got {}.",
                                            b.len()
                                        ))
                                    })
                                })?;
                        let pubkey = PublicKey::from_bytes(pubkey_bytes).map_err(|e| {
                            SqliteClientError::CorruptedData(format!("Invalid public key: {}", e))
                        })?;
                        Ok(TransparentAddressMetadata::standalone_p2pkh(
                            pubkey,
                            exposure,
                            next_check_time,
                        ))
                    }
                    derived => {
                        let (scope, address_index) = derived
                            .as_transparent()
                            .zip(address_index_opt)
                            .ok_or_else(|| {
                                SqliteClientError::CorruptedData(
                                    "Derived addresses must have derivation metadata present."
                                        .to_owned(),
                                )
                            })?;

                        Ok(TransparentAddressMetadata::derived(
                            scope,
                            address_index,
                            exposure,
                            next_check_time,
                        ))
                    }
                }
            };

            #[cfg(feature = "transparent-key-import")]
            let p2sh_metadata =
                |rs_bytes: &Vec<u8>| -> Result<TransparentAddressMetadata, SqliteClientError> {
                    use zcash_script::script::{self, Code};

                    let imported_transparent_receiver_script =
                        script::Redeem::parse(&Code(rs_bytes.clone())).map_err(|e| {
                            SqliteClientError::CorruptedData(format!(
                                "Invalid redeem script: {:?}",
                                e
                            ))
                        })?;

                    if matches!(key_scope, KeyScope::Foreign) {
                        // Standalone P2SH import
                        Ok(TransparentAddressMetadata::standalone_script(
                            imported_transparent_receiver_script,
                            exposure,
                            next_check_time,
                        ))
                    } else {
                        Err(SqliteClientError::CorruptedData(
                            "non-foreign-scoped address is not supported.".to_owned(),
                        ))
                    }
                };

            #[cfg(feature = "transparent-key-import")]
            let metadata = if let Some(ref rs_bytes) = imported_transparent_receiver_script_bytes {
                p2sh_metadata(rs_bytes)?
            } else {
                p2pkh_metadata()?
            };

            #[cfg(not(feature = "transparent-key-import"))]
            let metadata = p2pkh_metadata()?;

            #[cfg(not(feature = "transparent-key-import"))]
            {
                if matches!(key_scope, KeyScope::Foreign) {
                    // Foreign-scoped addresses (standalone imports) require
                    // transparent-key-import. Skip gracefully for DB compatibility.
                    warn!(
                        "Skipping foreign-scoped address {}: \
                         transparent-key-import feature is not enabled",
                        taddr.encode(params),
                    );
                    continue;
                }
            }

            ret.insert(taddr, metadata);
        }
    }

    Ok(ret)
}

pub(crate) fn uivk_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    uivk_str: &str,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    use transparent::keys::ExternalIvk;
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
    key_scope: TransparentKeyScope,
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
                ":key_scope": KeyScope::try_from(key_scope)?.encode(),
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
/// previously generated using [`generate_gap_addresses`].
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
    key_scope: TransparentKeyScope,
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
                ":key_scope": KeyScope::try_from(key_scope)?.encode(),
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

                transparent_child_index
                    .zip(address)
                    .map(|(i, a)| {
                        Ok::<_, SqliteClientError>((
                            address_id,
                            a,
                            TransparentAddressMetadata::derived(
                                key_scope,
                                i,
                                Exposure::Unknown,
                                None,
                            ),
                        ))
                    })
                    .transpose()
            },
        )?
        .filter_map(|r| r.transpose())
        .collect::<Result<Vec<_>, _>>()?;

    Ok((gap_start, addresses_to_reserve))
}

/// Returns a vector with the next `n` previously unreserved transparent addresses for the given
/// account, having marked each address as having been exposed at the current chain-tip height.
/// These addresses must have been previously generated using [`generate_gap_addresses`].
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
    key_scope: TransparentKeyScope,
    gap_limit: u32,
    n: usize,
) -> Result<Vec<(AddressRef, TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
    if n == 0 {
        return Ok(vec![]);
    }

    let (gap_start, addresses_to_reserve) =
        select_addrs_to_reserve(conn, params, account_id, key_scope, gap_limit, n)?;

    let gap_end = gap_start.index() + gap_limit;
    if addresses_to_reserve.len() < n {
        return Err(SqliteClientError::ReachedGapLimit(
            <Option<TransparentKeyScope>>::from(key_scope)
                .expect("reservation relies on key derivation"),
            gap_end,
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

    // When `transparent-key-import` is disabled, `TransparentAddressSource` has only the
    // `Derived` variant, so the `if let` below is irrefutable; silence that conditional
    // lint rather than restructuring the match.
    #[cfg_attr(
        not(feature = "transparent-key-import"),
        allow(irrefutable_let_patterns)
    )]
    Ok(addresses_to_reserve
        .into_iter()
        .map(|(id, addr, meta)| {
            if let TransparentAddressSource::Derived { address_index, .. } = meta.source() {
                (
                    id,
                    addr,
                    meta.with_exposure_at(
                        current_chain_tip,
                        GapMetadata::InGap {
                            gap_position: address_index.index().saturating_sub(gap_start.index()),
                            gap_limit,
                        },
                    ),
                )
            } else {
                unreachable!("gap addresses are always produced by derivation");
            }
        })
        .collect())
}

/// Generates addresses to fill the specified non-hardened child index range.
///
/// The provided [`UnifiedAddressRequest`] is used to pre-generate unified addresses that correspond
/// to each transparent address index in question; such unified addresses need not internally
/// contain a transparent receiver, and may be overwritten when these addresses are exposed via the
/// [`WalletWrite::get_next_available_address`] or [`WalletWrite::get_address_for_index`] methods.
/// If no request is provided, each address so generated will contain a receiver for each possible
/// pool: i.e., a recevier for each data item in the account's UFVK or UIVK where the transparent
/// child index is valid.
///
/// [`WalletWrite::get_next_available_address`]: zcash_client_backend::data_api::WalletWrite::get_next_available_address
/// [`WalletWrite::get_address_for_index`]: zcash_client_backend::data_api::WalletWrite::get_address_for_index
pub(crate) fn generate_address_range<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    range_to_store: Range<NonHardenedChildIndex>,
    require_key: bool,
) -> Result<(), SqliteClientError> {
    let account = get_account_internal(conn, params, account_id)?
        .ok_or_else(|| SqliteClientError::AccountUnknown)?;
    generate_address_range_internal(
        conn,
        params,
        account_id,
        &account.uivk(),
        account.ufvk(),
        key_scope,
        request,
        range_to_store,
        require_key,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_address_range_internal<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    account_uivk: &UnifiedIncomingViewingKey,
    account_ufvk: Option<&UnifiedFullViewingKey>,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    range_to_store: Range<NonHardenedChildIndex>,
    require_key: bool,
) -> Result<(), SqliteClientError> {
    let address_list = generate_address_list(
        account_uivk,
        account_ufvk,
        key_scope,
        request,
        range_to_store,
        require_key,
    )?;
    store_address_range(conn, params, account_id, key_scope, address_list)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn store_address_range<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    key_scope: TransparentKeyScope,
    address_list: Vec<(Address, TransparentAddress, NonHardenedChildIndex)>,
) -> Result<(), SqliteClientError> {
    // If the address being derived was previously imported as a standalone (`Foreign`)
    // receiver, upgrade that row in place to its derived form rather than inserting a second row
    // for the same transparent receiver (which the UNIQUE index on
    // `cached_transparent_receiver_address` forbids). The row `id` is preserved, so any UTXOs,
    // exposure, and spend-search state already attached to the imported receiver carry over and
    // become spendable.
    //
    // The import may have been made under a *different* account: deriving the address is itself
    // proof that the deriving account owns it, so in that case the row's account attribution
    // (and that of any outputs received at the address) moves to the deriving account. The
    // receiver-uniqueness index guarantees at most one row per receiver, and the deriving
    // account cannot already hold a row at this (key scope, child index) — such a row would be
    // this same receiver — so retargeting the row cannot violate the address-tuple constraint.
    //
    // The lookup below reads only columns present at every schema version at which
    // `store_address_range` runs, so it is safe when this function is called from a migration.
    // The upgrade `UPDATE` clears the `imported_transparent_receiver_*` columns, so it is only
    // ever prepared and executed when a `Foreign` row exists — which cannot occur before those
    // columns have been added.
    let mut stmt_lookup_foreign = conn.prepare_cached(
        "SELECT id, account_id FROM addresses
         WHERE cached_transparent_receiver_address = :transparent_address
           AND key_scope = :foreign_scope",
    )?;

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

    for (address, transparent_address, transparent_child_index) in address_list {
        let zcash_address = address.to_zcash_address(params);
        let receiver_flags: ReceiverFlags = zcash_address
            .clone()
            .convert::<ReceiverFlags>()
            .expect("address is valid");

        let derived_scope = KeyScope::try_from(key_scope)?.encode();
        let diversifier_index_be = encode_diversifier_index_be(transparent_child_index.into());
        let transparent_address_enc = transparent_address.encode(params);
        let address_enc = zcash_address.encode();
        let child_index = transparent_child_index.index();
        let flags = receiver_flags.bits();

        let foreign_row: Option<(i64, i64)> = stmt_lookup_foreign
            .query_row(
                named_params![
                    ":transparent_address": transparent_address_enc,
                    ":foreign_scope": KeyScope::Foreign.encode(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((foreign_id, foreign_account)) = foreign_row {
            conn.execute(
                "UPDATE addresses
                 SET account_id = :account_id,
                     key_scope = :key_scope,
                     diversifier_index_be = :diversifier_index_be,
                     address = :address,
                     transparent_child_index = :transparent_child_index,
                     receiver_flags = :receiver_flags,
                     imported_transparent_receiver_pubkey = NULL,
                     imported_transparent_receiver_script = NULL
                 WHERE id = :id",
                named_params![
                    ":account_id": account_id.0,
                    ":key_scope": derived_scope,
                    ":diversifier_index_be": diversifier_index_be,
                    ":address": address_enc,
                    ":transparent_child_index": child_index,
                    ":receiver_flags": flags,
                    ":id": foreign_id,
                ],
            )?;

            // If the import was recorded under a different account, the outputs received at
            // the address follow the (derivation-proven) attribution to this account.
            if foreign_account != account_id.0 {
                for table in [
                    "transparent_received_outputs",
                    "sapling_received_notes",
                    "orchard_received_notes",
                ] {
                    conn.execute(
                        &format!(
                            "UPDATE {table} SET account_id = :account_id
                             WHERE address_id = :address_id"
                        ),
                        named_params![
                            ":account_id": account_id.0,
                            ":address_id": foreign_id,
                        ],
                    )?;
                }
            }
        } else {
            stmt_insert_address.execute(named_params![
                ":account_id": account_id.0,
                ":diversifier_index_be": diversifier_index_be,
                ":key_scope": derived_scope,
                ":address": address_enc,
                ":transparent_child_index": child_index,
                ":transparent_address": transparent_address_enc,
                ":receiver_flags": flags,
            ])?;
        }
    }
    Ok(())
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
    gap_limits: &GapLimits,
    account_id: AccountRef,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    require_key: bool,
) -> Result<(), SqliteClientError> {
    let gap_limit = gap_limits.limit_for(key_scope).ok_or(
        AddressGenerationError::UnsupportedTransparentKeyScope(key_scope),
    )?;

    if let Some(gap_start) = find_gap_start(conn, account_id, key_scope, gap_limit)? {
        generate_address_range(
            conn,
            params,
            account_id,
            key_scope,
            request,
            gap_start..gap_start.saturating_add(gap_limit),
            require_key,
        )?;
    }

    Ok(())
}

/// Finds the wallet addresses that are involved with the given transaction, and regenerates the gap
/// limit worth of addresses as appropriate for each key scope.
pub(crate) fn update_gap_limits<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    gap_limits: &GapLimits,
    txid: TxId,
    observation_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let mut scopes_query = conn.prepare_cached(
        "SELECT tro.address_id, a.account_id, a.key_scope
         FROM transparent_received_outputs tro
         JOIN addresses a ON a.id = tro.address_id
         JOIN transactions t ON t.id_tx = tro.transaction_id
         WHERE t.txid = :txid
         UNION
         SELECT tro.address_id, a.account_id, a.key_scope
         FROM transparent_received_output_spends tros
         JOIN transparent_received_outputs tro ON tro.id = tros.transparent_received_output_id
         JOIN addresses a ON a.id = tro.address_id
         JOIN transactions t ON t.id_tx = tros.transaction_id
         WHERE t.txid = :txid",
    )?;

    let mut rows = scopes_query.query(named_params! {":txid": txid.as_ref() })?;
    while let Some(row) = rows.next()? {
        let addr_id: i64 = row.get("address_id")?;
        let account_id = AccountRef(row.get("account_id")?);
        let key_scope = KeyScope::decode(row.get("key_scope")?)?;

        // Update the exposure height for the address, in case the transaction was mined at a lower
        // height than the existing exposure height due to a reorg.
        conn.execute(
            "UPDATE addresses
             SET exposed_at_height = MIN(
                IFNULL(exposed_at_height, :height),
                :height
             )
             WHERE id = :addr_id",
            named_params![
               ":height": u32::from(observation_height),
               ":addr_id": addr_id
            ],
        )?;

        if let Some(t_key_scope) = <Option<TransparentKeyScope>>::from(key_scope) {
            use zcash_keys::keys::ReceiverRequirement::*;
            generate_gap_addresses(
                conn,
                params,
                gap_limits,
                account_id,
                t_key_scope,
                UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                false,
            )?;
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
/// the [`SqliteClientError::AddressReuse`] error variant.
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

    let mut get_height = |key_scope: TransparentKeyScope, gap_limit: u32| {
        if let Some(gap_start) = find_gap_start(conn, account_ref, key_scope, gap_limit)? {
            stmt.query_row(
                named_params! {
                    ":account_id": account_ref.0,
                    ":key_scope": KeyScope::try_from(key_scope)?.encode(),
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

    let h_external = get_height(TransparentKeyScope::EXTERNAL, gap_limits.external())?;
    let h_internal = get_height(TransparentKeyScope::INTERNAL, gap_limits.internal())?;

    match (h_external, h_internal) {
        (Some(ext), Some(int)) => Ok(std::cmp::min(ext, int)),
        (Some(h), None) | (None, Some(h)) => Ok(h),
        (None, None) => account_birthday_internal(conn, account_ref),
    }
}

/// Returns the wallet accounts that contributed inputs to the transaction with the
/// given internal id, paired with the total value each account contributed. Results
/// are ordered by total contributed value descending; ties are broken in favor of
/// the account whose oldest contributed input has the lowest mined height (with
/// unmined inputs sorting last), then by `accounts.id`.
fn list_funding_accounts(
    conn: &rusqlite::Connection,
    creating_tx_id: i64,
) -> Result<Vec<(AccountUuid, Zatoshis)>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid, contribs.total_value
         FROM accounts a
         JOIN (
             SELECT account_id,
                    SUM(value) AS total_value,
                    MIN(IFNULL(mined_height, 0x7FFFFFFF)) AS oldest_mined
             FROM (
                 SELECT tro.account_id, tro.value_zat AS value, t.mined_height AS mined_height
                 FROM transparent_received_outputs tro
                 JOIN transparent_received_output_spends tros
                   ON tros.transparent_received_output_id = tro.id
                 JOIN transactions t ON t.id_tx = tro.transaction_id
                 WHERE tros.transaction_id = :creating_tx_id
                 UNION ALL
                 SELECT srn.account_id, srn.value, t.mined_height
                 FROM sapling_received_notes srn
                 JOIN sapling_received_note_spends srns
                   ON srns.sapling_received_note_id = srn.id
                 JOIN transactions t ON t.id_tx = srn.transaction_id
                 WHERE srns.transaction_id = :creating_tx_id
                 UNION ALL
                 SELECT orn.account_id, orn.value, t.mined_height
                 FROM orchard_received_notes orn
                 JOIN orchard_received_note_spends orns
                   ON orns.orchard_received_note_id = orn.id
                 JOIN transactions t ON t.id_tx = orn.transaction_id
                 WHERE orns.transaction_id = :creating_tx_id
             )
             GROUP BY account_id
         ) contribs ON contribs.account_id = a.id
         ORDER BY contribs.total_value DESC, contribs.oldest_mined ASC, a.id ASC",
    )?;

    stmt.query_and_then(
        named_params![":creating_tx_id": creating_tx_id],
        |row| -> Result<(AccountUuid, Zatoshis), SqliteClientError> {
            let account = AccountUuid(row.get(0)?);
            let raw_value: i64 = row.get(1)?;
            let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
                SqliteClientError::CorruptedData(format!(
                    "Invalid funding contribution value: {raw_value}"
                ))
            })?;
            Ok((account, value))
        },
    )?
    .collect()
}

fn to_unspent_transparent_output(
    conn: &rusqlite::Connection,
    row: &Row,
) -> Result<WalletTransparentOutput<AccountUuid>, SqliteClientError> {
    let txid: Vec<u8> = row.get("txid")?;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&txid);

    let index: u32 = row.get("output_index")?;
    let script_pubkey = Script(script::Code(row.get("script")?));
    let raw_value: i64 = row.get("value_zat")?;
    let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
        SqliteClientError::CorruptedData(format!("Invalid UTXO value: {raw_value}"))
    })?;
    let height: Option<u32> = row.get("received_height")?;
    let account_id = AccountUuid(row.get("account_uuid")?);
    let key_scope = KeyScope::decode(row.get("key_scope")?)?.as_transparent();
    let creating_tx_id: i64 = row.get("creating_tx_id")?;

    // `WalletTransparentOutput` records at most a single funding account; when
    // multiple wallet accounts contributed inputs to the creating transaction we
    // pick the largest contributor.
    let funding_account = list_funding_accounts(conn, creating_tx_id)?
        .into_iter()
        .next()
        .map(|(account, _)| account);

    let outpoint = OutPoint::new(txid_bytes, index);
    WalletTransparentOutput::from_parts(
        outpoint,
        TxOut::new(value, script_pubkey),
        height.map(BlockHeight::from),
        Some(account_id),
        key_scope,
        funding_account,
    )
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Txout script_pubkey value did not correspond to a P2PKH or P2SH address".to_string(),
        )
    })
}

// Generates a SQL expression that returns the identifiers of all spent UTXOS in the wallet.
///
/// # Usage requirements
/// - The parent must provide `:target_height` as a named argument.
/// - The parent is responsible for enclosing this condition in parentheses as appropriate.
pub(crate) fn spent_utxos_clause() -> String {
    format!(
        r#"
        SELECT txo_spends.transparent_received_output_id
        FROM transparent_received_output_spends txo_spends
        JOIN transactions stx ON stx.id_tx = txo_spends.transaction_id
        WHERE {}
        "#,
        super::common::tx_unexpired_condition("stx")
    )
}

/// Generates an SQL condition that a transaction is mined with at least a required number of
/// confirmations, or is unexpired if UTXOS are spendable with zero confirmations.
///
/// # Usage requirements
/// - `tx` must be set to the SQL variable name for the transaction in the parent.
/// - The parent must provide `:target_height` as a named argument.
/// - The parent must provide `:min_confirmations` as a named argument.
/// - The parent is responsible for enclosing this condition in parentheses as appropriate.
pub(crate) fn tx_unexpired_condition_minconf_0(tx: &str) -> String {
    format!(
        r#"
        -- tx is mined and has at least min_confirmations
        (
            {tx}.mined_height < :target_height -- tx is mined
            AND :target_height - {tx}.mined_height >= :min_confirmations
        )
        -- or outputs may be spent with zero confirmations and the transaction is unexpired
        OR (
            :min_confirmations = 0
            AND ({tx}.expiry_height = 0 OR {tx}.expiry_height >= :target_height)
        )
        "#
    )
}

/// Generates a SQL condition that checks that if a TXO was received at an ephemeral
/// address, it either had no inputs belonging to the wallet, or has been confirmed
/// to be unspent after the transaction that created it would have expired.
///
/// TODO: This fragment is very unwieldy; it really doesn't work well as a fragment. It would be
/// much better if it could be expressed as a view somehow; the problem is that views can't be
/// parameterized, and there are numerous interacting checks that need to be made against the
/// target height in the context where this fragment is being used.
///
/// # Usage requirements
/// - `transparent_received_outputs` must be set to the alias to the `transparent_received_outputs`
///   table in the enclosing scope.
/// - `addresses` must be set to alias for the `addresses` table in the enclosing scope such that
///   `addresses.id = transparent_received_outputs.address_id`.
/// - `tx` must be set to the alias for the `transactions` table in the enclosing scope such that
///   `tx.id_tx = transparent_received_outputs.transaction_id`.
/// - `accounts` must be set to the alias for the `accounts` table in the enclosing scope such that
///   `accounts.id = transparent_received_outputs.account_id`
/// - The parent is responsible for enclosing this condition in parentheses as appropriate.
/// - The parent is responsible for ensuring that this condition will only be checked for
///   outputs that have already otherwise been verified to be spendable, i.e. it must be
///   used as a strictly constricting clause on the set of outputs.
pub(crate) fn excluding_wallet_internal_ephemeral_outputs(
    transparent_received_outputs: &str,
    addresses: &str,
    tx: &str,
    accounts: &str,
) -> String {
    let ephemeral_key_scope = KeyScope::Ephemeral.encode();
    format!(
        r#"
        -- the receiving address is not an ephemeral address
        {addresses}.key_scope != {ephemeral_key_scope}
        -- or the transaction that generated the TXO has no inputs belonging to the wallet
        OR {tx}.id_tx NOT IN (
            SELECT transaction_id
            FROM v_received_output_spends
            WHERE v_received_output_spends.account_id = {accounts}.id
        )
        -- or the transaction that generated the TXO would be considered expired as of the TXOs
        -- max_observed_unspent_height; this operates under the assumption that the second
        -- transaction in a TEX chain has the same expiry as the transaction that generated the
        -- ephemeral output, and the output having been observed to be unspent above this height
        -- indicates that the subsequent spend failed and the spending transaction will have
        -- expired.
        OR {transparent_received_outputs}.max_observed_unspent_height > {tx}.expiry_height
        "#
    )
}

/// Generates a SQL condition that checks the coinbase maturity rule.
///
/// # Usage requirements
/// - `tx` must be set to the SQL variable name for the transaction in the parent.
/// - The parent is responsible for enclosing this condition in parentheses as appropriate.
/// - The parent is responsible for ensuring that this condition will only be checked for
///   outputs that have already otherwise been verified to be spendable, i.e. it must be
///   used as a strictly constricting clause on the set of outputs.
pub(crate) fn excluding_immature_coinbase_outputs(tx: &str) -> String {
    // FIXME: If a coinbase transaction is discovered via the get_compact_utxos RPC call
    // we won't have sufficient info to identify it as coinbase, so it may not be excluded
    // unless decrypt_and_store_transaction has been called on the transaction that produced it.
    //
    // To fix this we'll need to add the `tx_index` field to the GetAddressUtxosReply proto type.
    //
    // See the tracking ticket https://github.com/zcash/lightwallet-protocol/issues/17.
    format!(
        r#"
        NOT (
            -- the output is a coinbase output
            IFNULL({tx}.tx_index, 1) == 0
            -- the coinbase output is immature (< 100 confirmations)
            AND :target_height - {tx}.mined_height < {COINBASE_MATURITY_BLOCKS}
        )
        "#
    )
}
/// Get information about a transparent output controlled by the wallet.
///
/// # Parameters
/// - `outpoint`: The identifier for the output to be retrieved.
/// - `target_height`: The target height of a transaction under construction that will spend the
///   returned output. If this is `None`, no spendability checks are performed.
pub(crate) fn get_wallet_transparent_output(
    conn: &rusqlite::Connection,
    outpoint: &OutPoint,
    target_height: Option<TargetHeight>,
) -> Result<Option<WalletTransparentOutput<AccountUuid>>, SqliteClientError> {
    // This could return as unspent outputs that are actually not spendable, if they are the
    // outputs of deshielding transactions where the spend anchors have been invalidated by a
    // rewind or spent in a transaction that has not been observed by this wallet. There isn't a
    // way to detect the circumstance related to anchor invalidation at present, but it should be
    // vanishingly rare as the vast majority of rewinds are of a single block.
    let mut stmt_select_utxo = conn.prepare_cached(&format!(
        "SELECT t.txid, u.output_index, u.script,
                u.value_zat, addresses.key_scope,
                accounts.uuid AS account_uuid,
                u.transaction_id AS creating_tx_id,
                t.mined_height AS received_height
         FROM transparent_received_outputs u
         JOIN transactions t ON t.id_tx = u.transaction_id
         JOIN accounts ON accounts.id = u.account_id
         JOIN addresses ON addresses.id = u.address_id
         WHERE t.txid = :txid
         AND u.output_index = :output_index
         AND (
             :allow_unspendable
             OR (
                 -- the transaction that created the output is mined or is definitely unexpired
                 ({}) -- the transaction is unexpired
                 AND u.id NOT IN ({}) -- and the output is unspent
                 AND ({}) -- exclude likely-spent wallet-internal ephemeral outputs
             )
         )",
        tx_unexpired_condition("t"),
        spent_utxos_clause(),
        excluding_wallet_internal_ephemeral_outputs("u", "addresses", "t", "accounts")
    ))?;

    let result: Result<Option<WalletTransparentOutput<_>>, SqliteClientError> = stmt_select_utxo
        .query_and_then(
            named_params![
                ":txid": outpoint.hash(),
                ":output_index": outpoint.n(),
                ":target_height": target_height.map(u32::from),
                ":allow_unspendable": target_height.is_none(),
            ],
            |row| to_unspent_transparent_output(conn, row),
        )?
        .next()
        .transpose();

    result
}

/// Builds the SQL query body shared by `get_spendable_transparent_outputs[_for_addresses]`
/// and `select_spendable_transparent_outputs`.
///
/// The query body is parameterized over the address-predicate SQL fragment and the
/// `ORDER BY` fragment, so callers can match on a single address, a set of addresses, or
/// an account; and can order by address+index (per-address determinism) or by value
/// descending (value-bounded selection).
fn spendable_transparent_outputs_query(address_predicate_sql: &str, order_by_sql: &str) -> String {
    format!(
        "SELECT t.txid, u.output_index, u.script,
                u.value_zat, addresses.key_scope,
                accounts.uuid AS account_uuid,
                u.transaction_id AS creating_tx_id,
                addresses.imported_transparent_receiver_script,
                t.mined_height AS received_height
         FROM transparent_received_outputs u
         JOIN transactions t ON t.id_tx = u.transaction_id
         JOIN accounts ON accounts.id = u.account_id
         JOIN addresses ON addresses.id = u.address_id
         WHERE {address_predicate_sql}
         AND u.value_zat > :min_value
         AND ({}) -- the transaction is mined or unexpired with minconf 0
         AND u.id NOT IN ({}) -- and the output is unspent
         AND ({}) -- exclude likely-spent wallet-internal ephemeral outputs
         AND ({}) -- exclude immature coinbase outputs
         AND (
             :coinbase_filter == 0
             OR (:coinbase_filter == 1 AND IFNULL(t.tx_index, 1) == 0)
             OR (:coinbase_filter == 2 AND IFNULL(t.tx_index, 1) != 0)
         ) -- coinbase filter: 0 = all, 1 = coinbase-only, 2 = non-coinbase-only;
           -- unknown tx_index defaults to 1 (non-coinbase) to avoid false positives,
           -- so such outputs are excluded by CoinbaseOnly and included by NonCoinbaseOnly
         ORDER BY {order_by_sql}",
        tx_unexpired_condition_minconf_0("t"),
        spent_utxos_clause(),
        excluding_wallet_internal_ephemeral_outputs("u", "addresses", "t", "accounts"),
        excluding_immature_coinbase_outputs("t"),
    )
}

/// Encodes the common `CoinbaseFilter` encoding used by the transparent-output SQL queries:
/// 0 = all transparent outputs, 1 = coinbase outputs only, 2 = non-coinbase outputs only.
fn coinbase_filter_encoding(output_filter: CoinbaseFilter) -> i32 {
    match output_filter {
        CoinbaseFilter::AllTransparentOutputs => 0i32,
        CoinbaseFilter::CoinbaseOnly => 1i32,
        CoinbaseFilter::NonCoinbaseOnly => 2i32,
    }
}

/// Returns the list of spendable transparent outputs received by this wallet at `address`
/// such that, at height `target_height`:
/// * the transaction that produced the output had or will have at least the number of
///   confirmations required by the specified confirmations policy; and
/// * the output is unspent as of the current chain tip; and
/// * the output adheres to the coinbase maturity requirement, if it is a coinbase output.
///
/// An output that is potentially spent by an unmined transaction in the mempool is excluded
/// iff the spending transaction will not be expired at `target_height`.
///
/// This could, in very rare circumstances, return unspent outputs that are actually not
/// spendable, if they are the outputs of deshielding transactions where the spend anchors have
/// been invalidated by a rewind. There isn't a way to detect this circumstance at present, but
/// it should be vanishingly rare as the vast majority of rewinds are of a single block.
pub(crate) fn get_spendable_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    output_filter: CoinbaseFilter,
) -> Result<Vec<WalletTransparentOutput<AccountUuid>>, SqliteClientError> {
    // Defer to the batched query with a singleton address set, so that there is a single query
    // body to maintain. `transparent_received_outputs.address` is always equal to the
    // `cached_transparent_receiver_address` of the joined `addresses` row (both are written from
    // the same recipient address on insert, and the gap-limit migration backfilled this invariant
    // for pre-existing rows), so matching on the latter for a single address selects the same
    // outputs as the former.
    get_spendable_transparent_outputs_for_addresses(
        conn,
        params,
        core::slice::from_ref(address),
        target_height,
        confirmations_policy,
        output_filter,
    )
}

/// Returns the list of spendable transparent outputs received by this wallet at any of the
/// given `addresses`, under the same spendability conditions as
/// [`get_spendable_transparent_outputs`].
///
/// This is the batched equivalent of [`get_spendable_transparent_outputs`]: it issues a single
/// query over the entire set of provided addresses rather than one query per address, which avoids
/// a per-address database round-trip (and, for each empty address, a wasted query) when shielding
/// from a wallet that holds large numbers of transparent addresses. Each returned output
/// identifies its receiving address, so a caller that needs to group results by address can do so
/// from the returned values.
///
/// The query body mirrors that of [`get_spendable_transparent_outputs`], differing only in that
/// the receiving address is matched against a set via `rarray` rather than a single value.
pub(crate) fn get_spendable_transparent_outputs_for_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    addresses: &[TransparentAddress],
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    output_filter: CoinbaseFilter,
) -> Result<Vec<WalletTransparentOutput<AccountUuid>>, SqliteClientError> {
    if addresses.is_empty() {
        return Ok(vec![]);
    }

    let coinbase_filter = coinbase_filter_encoding(output_filter);

    let mut stmt_utxos = conn.prepare_cached(&spendable_transparent_outputs_query(
        "addresses.cached_transparent_receiver_address IN rarray(:addresses)",
        "addresses.cached_transparent_receiver_address, u.output_index",
    ))?;

    // We treat all transparent UTXOs as untrusted; however, if zero-conf shielding
    // is enabled, we set the minimum number of confirmations to zero.
    let min_confirmations = if confirmations_policy.allow_zero_conf_shielding() {
        0u32
    } else {
        u32::from(confirmations_policy.untrusted())
    };

    let address_values: Vec<Value> = addresses
        .iter()
        .map(|addr| Value::Text(addr.encode(params)))
        .collect();
    let addresses_ptr = Rc::new(address_values);

    let mut rows = stmt_utxos.query(named_params![
        ":addresses": &addresses_ptr,
        ":target_height": u32::from(target_height),
        ":min_confirmations": min_confirmations,
        ":min_value": u64::from(zip317::MARGINAL_FEE),
        ":coinbase_filter": coinbase_filter,
    ])?;

    let mut utxos = Vec::<WalletTransparentOutput<_>>::new();
    while let Some(row) = rows.next()? {
        let mut output = to_unspent_transparent_output(conn, row)?;
        // If the address has a redeem script, compute the known input size for fee
        // estimation so that the ZIP 317 fee calculator can handle P2SH inputs.
        if let Ok(Some(rs_bytes)) =
            row.get::<_, Option<Vec<u8>>>("imported_transparent_receiver_script")
        {
            if let Ok(from_chain) = script::FromChain::parse(&script::Code(rs_bytes)) {
                if let Some(input_size) =
                    transparent::builder::p2sh_input_serialized_len(&from_chain)
                {
                    output = output.with_known_input_size(input_size);
                }
            }
        }
        utxos.push(output);
    }

    Ok(utxos)
}

/// Returns the spendable transparent outputs received by the given `account` whose total
/// post-fee value (sum of values minus the cumulative marginal fee cost of the gathered
/// inputs themselves, per `fee_rule`) is at least `target_value`, or `max_inputs` outputs
/// (whichever is reached first).
///
/// The query is a single SQL statement that orders eligible UTXOs by descending value (using
/// the `idx_transparent_received_outputs_value_zat` index) and lets the Rust side accumulate
/// values until the post-fee bound (or the `max_inputs` cap) is met. This bounds the work
/// done in SQLite to the prefix of the table that can possibly satisfy the request, which is
/// important for wallets that hold large numbers of transparent UTXOs (e.g. a recovered
/// `zcashd` import).
///
/// The cumulative fee is recomputed via `fee_rule` at each step. To keep this loop linear in
/// the number of UTXOs examined (rather than quadratic), we maintain a running total of the
/// serialized transparent input sizes seen so far and pass that single collapsed total to
/// `FeeRule::fee_required` on each iteration, rather than re-summing the whole prefix each
/// time. This is valid for ZIP 317, whose transparent-input fee contribution depends only on
/// the sum of input sizes.
///
/// For `TargetValue::AllFunds`, no value bound is applied and the gather returns every
/// eligible output up to `max_inputs`.
///
/// When `address_allow_list` is `Some`, the eligible set is additionally restricted (within
/// the query, so that ineligible outputs do not consume the value bound) to outputs received
/// at one of the given transparent addresses.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn select_spendable_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountUuid,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    output_filter: CoinbaseFilter,
    address_allow_list: Option<&[TransparentAddress]>,
    target_value: TargetValue,
    max_inputs: usize,
    fee_rule: &StandardFeeRule,
) -> Result<Vec<WalletTransparentOutput<AccountUuid>>, SqliteClientError> {
    // The post-fee bound for `TargetValue::AtLeast`. `TargetValue::AllFunds` has no bound; we
    // return every eligible output in that case.
    let target_zat: Option<u64> = match target_value {
        TargetValue::AtLeast(z) => Some(u64::from(z)),
        TargetValue::AllFunds(_) => None,
    };

    let coinbase_filter = coinbase_filter_encoding(output_filter);

    // `:has_address_allow_list` and `:addresses` are always bound (the latter to an empty
    // array when there is no allow list), following the same always-bound-flag idiom as
    // `:coinbase_filter`, so that there is a single query text regardless of whether an
    // allow list is present.
    let mut stmt_utxos = conn.prepare_cached(&spendable_transparent_outputs_query(
        "accounts.uuid = :account_uuid
         AND (
             :has_address_allow_list = 0
             OR addresses.cached_transparent_receiver_address IN rarray(:addresses)
         )",
        "u.value_zat DESC, u.output_index",
    ))?;

    // We treat all transparent UTXOs as untrusted; however, if zero-conf shielding
    // is enabled, we set the minimum number of confirmations to zero.
    let min_confirmations = if confirmations_policy.allow_zero_conf_shielding() {
        0u32
    } else {
        u32::from(confirmations_policy.untrusted())
    };

    let address_values: Vec<Value> = address_allow_list
        .unwrap_or(&[])
        .iter()
        .map(|addr| Value::Text(addr.encode(params)))
        .collect();
    let addresses_ptr = Rc::new(address_values);

    let mut rows = stmt_utxos.query(named_params![
        ":account_uuid": account.0,
        ":target_height": u32::from(target_height),
        ":min_confirmations": min_confirmations,
        ":min_value": u64::from(zip317::MARGINAL_FEE),
        ":coinbase_filter": coinbase_filter,
        ":has_address_allow_list": address_allow_list.is_some(),
        ":addresses": &addresses_ptr,
    ])?;

    let mut utxos = Vec::<WalletTransparentOutput<_>>::new();
    let mut accumulated_value: u64 = 0;
    // Running total of the serialized size of the transparent inputs gathered so far.
    // Maintained incrementally so that the fee re-computation below is O(1) per candidate
    // UTXO rather than O(prefix length), keeping the overall gather linear.
    let mut cumulative_input_size: usize = 0;
    while let Some(row) = rows.next()? {
        // Stop once the cap on the number of transparent inputs is reached, regardless of
        // whether the value target has been met. This bounds the size of the resulting
        // transaction independent of `target_value`, since a wallet holding a very large
        // number of small (e.g. dust) UTXOs could otherwise require an unbounded number of
        // inputs to satisfy even a modest request.
        if utxos.len() >= max_inputs {
            break;
        }

        let output = to_unspent_transparent_output(conn, row)?;

        // If we have a target bound, stop once the post-fee accumulated value reaches it.
        if let Some(target) = target_zat {
            let cumulative_fee = fee_rule
                .fee_required(
                    params,
                    BlockHeight::from(target_height),
                    [InputSize::Known(cumulative_input_size)],
                    std::iter::empty::<usize>(),
                    0,
                    0,
                    0,
                    0,
                )
                .map_err(SqliteClientError::from)?;
            if accumulated_value.saturating_sub(u64::from(cumulative_fee)) >= target {
                break;
            }
        }

        let input_size = match output.serialized_size() {
            InputSize::Known(size) => size,
            // Fall back to the standard P2PKH size for inputs whose exact serialized size is
            // not known (e.g. a P2SH output with an unrecognized redeem script). This is an
            // estimate for the purposes of this gather only; the real fee is computed by the
            // caller's actual change strategy once the transaction is built.
            InputSize::Unknown(_) => zip317::P2PKH_STANDARD_INPUT_SIZE,
        };
        cumulative_input_size += input_size;
        accumulated_value = accumulated_value.saturating_add(u64::from(output.value()));
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
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<TransparentBalances, SqliteClientError> {
    // We treat all transparent UTXOs as untrusted; however, if zero-conf shielding
    // is enabled, we set the minimum number of confirmations to zero.
    let min_confirmations = if confirmations_policy.allow_zero_conf_shielding() {
        0u32
    } else {
        u32::from(confirmations_policy.untrusted())
    };

    let mut result = HashMap::new();

    let mut stmt_address_balances = conn.prepare(&format!(
        "SELECT u.address, u.value_zat, addresses.key_scope
         FROM transparent_received_outputs u
         JOIN accounts ON accounts.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         JOIN addresses ON addresses.id = u.address_id
         WHERE accounts.uuid = :account_uuid
         AND u.value_zat > 0
         AND ({}) -- the transaction is mined or unexpired with minconf 0
         AND u.id NOT IN ({}) -- and the output is unspent
         AND ({}) -- exclude likely-spent wallet-internal ephemeral outputs",
        tx_unexpired_condition_minconf_0("t"),
        spent_utxos_clause(),
        excluding_wallet_internal_ephemeral_outputs("u", "addresses", "t", "accounts")
    ))?;

    let mut rows = stmt_address_balances.query(named_params![
        ":account_uuid": account_uuid.0,
        ":target_height": u32::from(target_height),
        ":min_confirmations": min_confirmations,
    ])?;

    while let Some(row) = rows.next()? {
        let taddr_str: String = row.get("address")?;
        let taddr = TransparentAddress::decode(params, &taddr_str)?;
        let value = Zatoshis::from_nonnegative_i64(row.get("value_zat")?)?;
        let key_scope_code: i64 = row.get("key_scope")?;
        let key_origin = KeyScope::decode(key_scope_code)?.as_key_origin();

        let entry = result.entry(taddr).or_insert((key_origin, Balance::ZERO));
        if value <= zip317::MARGINAL_FEE {
            entry.1.add_uneconomic_value(value)?;
        } else {
            entry.1.add_spendable_value(value)?;
        }
    }

    // Pending spendable balance for transparent UTXOs is only relevant for min_confirmations > 0;
    // with min_confirmations == 0, zero-conf spends are allowed and therefore the value will
    // appear in the spendable balance and we don't want to double-count it.
    if min_confirmations > 0 {
        let mut stmt_address_balances = conn.prepare(&format!(
            "SELECT u.address, u.value_zat, addresses.key_scope
             FROM transparent_received_outputs u
             JOIN accounts ON accounts.id = u.account_id
             JOIN transactions t ON t.id_tx = u.transaction_id
             JOIN addresses ON addresses.id = u.address_id
             WHERE accounts.uuid = :account_uuid
             AND u.value_zat > 0
             -- the transaction that created the output is mined or is definitely unexpired
             AND (
                 -- the transaction that created the output is mined with not enough confirmations
                (
                    t.mined_height < :target_height
                    AND :target_height - t.mined_height < :min_confirmations
                )
                -- or the tx is unmined but definitely not expired
                OR (
                    t.mined_height IS NULL
                    AND (t.expiry_height = 0 OR t.expiry_height >= :target_height)
                )
             )
             AND u.id NOT IN ({}) -- and the output is unspent
             AND ({}) -- exclude likely-spent wallet-internal ephemeral outputs",
            spent_utxos_clause(),
            excluding_wallet_internal_ephemeral_outputs("u", "addresses", "t", "accounts")
        ))?;

        let mut rows = stmt_address_balances.query(named_params![
            ":account_uuid": account_uuid.0,
            ":target_height": u32::from(target_height),
            ":min_confirmations": min_confirmations
        ])?;

        while let Some(row) = rows.next()? {
            let taddr_str: String = row.get("address")?;
            let taddr = TransparentAddress::decode(params, &taddr_str)?;
            let value = Zatoshis::from_nonnegative_i64(row.get("value_zat")?)?;
            let key_scope_code: i64 = row.get("key_scope")?;
            let key_origin = KeyScope::decode(key_scope_code)?.as_key_origin();

            let entry = result.entry(taddr).or_insert((key_origin, Balance::ZERO));
            if value <= zip317::MARGINAL_FEE {
                entry.1.add_uneconomic_value(value)?;
            } else {
                entry.1.add_spendable_value(value)?;
            }
        }
    }

    Ok(result)
}

#[tracing::instrument(skip(conn, account_balances))]
pub(crate) fn add_transparent_account_balances(
    conn: &rusqlite::Connection,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    account_balances: &mut HashMap<AccountUuid, AccountBalance>,
) -> Result<(), SqliteClientError> {
    // We treat all transparent UTXOs as untrusted; however, if zero-conf shielding
    // is enabled, we set the minimum number of confirmations to zero.
    let min_confirmations = if confirmations_policy.allow_zero_conf_shielding() {
        0u32
    } else {
        u32::from(confirmations_policy.untrusted())
    };

    let mut stmt_account_spendable_balances = conn.prepare(&format!(
        "SELECT accounts.uuid, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN accounts ON accounts.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         JOIN addresses ON addresses.id = u.address_id
         WHERE ({}) -- the transaction is mined or unexpired with minconf 0
         AND u.id NOT IN ({}) -- and the received txo is unspent
         AND ({}) -- exclude likely-spent wallet-internal ephemeral outputs
         GROUP BY accounts.uuid",
        tx_unexpired_condition_minconf_0("t"),
        spent_utxos_clause(),
        excluding_wallet_internal_ephemeral_outputs("u", "addresses", "t", "accounts")
    ))?;

    let mut rows = stmt_account_spendable_balances.query(named_params![
        ":target_height": u32::from(target_height),
        ":min_confirmations": min_confirmations,
    ])?;

    while let Some(row) = rows.next()? {
        let account = AccountUuid(row.get(0)?);
        let raw_value = row.get(1)?;
        let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative UTXO value {raw_value:?}"))
        })?;

        account_balances
            .entry(account)
            .or_insert(AccountBalance::ZERO)
            .with_unshielded_balance_mut(|bal| {
                if value <= zip317::MARGINAL_FEE {
                    bal.add_uneconomic_value(value)
                } else {
                    bal.add_spendable_value(value)
                }
            })?;
    }

    // Pending spendable balance for transparent UTXOs is only relevant for min_confirmations > 0;
    // with min_confirmations == 0, zero-conf spends are allowed and therefore the value will
    // appear in the spendable balance and we don't want to double-count it.
    // TODO (#1592): Ability to distinguish between Transparent pending change and pending non-change
    if min_confirmations > 0 {
        let mut stmt_account_unconfirmed_balances = conn.prepare(&format!(
            "SELECT accounts.uuid, SUM(u.value_zat)
             FROM transparent_received_outputs u
             JOIN accounts ON accounts.id = u.account_id
             JOIN transactions t ON t.id_tx = u.transaction_id
             JOIN addresses ON addresses.id = u.address_id
             WHERE (
                 -- the transaction that created the output is mined with not enough confirmations
                (
                    t.mined_height < :target_height
                    AND :target_height - t.mined_height < :min_confirmations
                )
                -- or the tx is unmined but definitely not expired
                OR (
                    t.mined_height IS NULL
                    AND (t.expiry_height = 0 OR t.expiry_height >= :target_height)
                )
             )
             AND u.id NOT IN ({}) -- and the received txo is unspent
             AND ({}) -- exclude likely-spent wallet-internal ephemeral outputs
             GROUP BY accounts.uuid",
            spent_utxos_clause(),
            excluding_wallet_internal_ephemeral_outputs("u", "addresses", "t", "accounts")
        ))?;

        let mut rows = stmt_account_unconfirmed_balances.query(named_params![
            ":target_height": u32::from(target_height),
            ":min_confirmations": min_confirmations,
        ])?;

        while let Some(row) = rows.next()? {
            let account = AccountUuid(row.get(0)?);
            let raw_value = row.get(1)?;
            let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
                SqliteClientError::CorruptedData(format!("Negative UTXO value {raw_value:?}"))
            })?;

            account_balances
                .entry(account)
                .or_insert(AccountBalance::ZERO)
                .with_unshielded_balance_mut(|bal| {
                    if value <= zip317::MARGINAL_FEE {
                        bal.add_uneconomic_value(value)
                    } else {
                        bal.add_pending_spendable_value(value)
                    }
                })?;
        }
    }
    Ok(())
}

/// Marks the given UTXO as having been spent.
///
/// Returns `true` if the UTXO was known to the wallet.
pub(crate) fn mark_transparent_utxo_spent(
    conn: &rusqlite::Transaction,
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

/// Sets the max observed unspent height for all unspent transparent outputs received at the given
/// address to at least the given height (calling this method will not cause the max observed
/// unspent height to decrease).
pub(crate) fn update_observed_unspent_heights<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    address: TransparentAddress,
    checked_at: BlockHeight,
) -> Result<(), SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;
    let checked_at = std::cmp::min(checked_at, chain_tip_height);

    let addr_str = address.encode(params);
    debug!(
        "Setting max_observed_unspent_height to {} for address {}",
        checked_at, addr_str
    );

    let mut stmt_update_observed_unspent = conn.prepare(
        "UPDATE transparent_received_outputs AS tro
         SET max_observed_unspent_height = CASE
            WHEN max_observed_unspent_height IS NULL THEN :checked_at
            WHEN max_observed_unspent_height < :checked_at THEN :checked_at
            ELSE max_observed_unspent_height
         END
         WHERE address = :addr_str
         AND tro.id NOT IN (
             SELECT transparent_received_output_id
             FROM transparent_received_output_spends
         )",
    )?;

    stmt_update_observed_unspent.execute(named_params![
        ":addr_str": addr_str,
        ":checked_at": u32::from(checked_at)
    ])?;

    Ok(())
}

/// Sets the max observed unspent height for the unspent transparent output identified by the given
/// outpoint to at least the given height (will not cause the height to decrease). Used to record
/// the result of a [`TransactionDataRequest::GetSpendingTx`] check that found the
/// output unspent.
///
/// [`TransactionDataRequest::GetSpendingTx`]: zcash_client_backend::data_api::TransactionDataRequest::GetSpendingTx
#[cfg(feature = "spend-index")]
pub(crate) fn update_observed_unspent_height_for_outpoint(
    conn: &rusqlite::Transaction,
    outpoint: &OutPoint,
    checked_at: BlockHeight,
) -> Result<(), SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;
    let checked_at = std::cmp::min(checked_at, chain_tip_height);

    let mut stmt = conn.prepare(
        "UPDATE transparent_received_outputs AS tro
         SET max_observed_unspent_height = CASE
            WHEN max_observed_unspent_height IS NULL THEN :checked_at
            WHEN max_observed_unspent_height < :checked_at THEN :checked_at
            ELSE max_observed_unspent_height
         END
         FROM transactions t
         WHERE tro.transaction_id = t.id_tx
         AND t.txid = :txid
         AND tro.output_index = :output_index
         AND tro.id NOT IN (
             SELECT transparent_received_output_id
             FROM transparent_received_output_spends
         )",
    )?;

    stmt.execute(named_params![
        ":txid": outpoint.hash(),
        ":output_index": outpoint.n(),
        ":checked_at": u32::from(checked_at)
    ])?;

    Ok(())
}

/// Adds the given received UTXO to the datastore.
pub(crate) fn put_received_transparent_utxo<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    gap_limits: &GapLimits,
    output: &WalletTransparentOutput<AccountUuid>,
) -> Result<(AccountRef, AccountUuid, KeyScope, UtxoId), SqliteClientError> {
    let observed_height = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;
    put_transparent_output(conn, params, gap_limits, output, observed_height, true)
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
                write!(f, "Failure in sampling scheduling time: {e}")
            }
            SchedulingError::Time(t) => write!(f, "Invalid system time: {t}"),
            SchedulingError::OutOfRange(t) => write!(f, "Not a valid timestamp or duration: {t}"),
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

pub(crate) fn schedule_next_check<P: consensus::Parameters, C: Clock, R: RngCore>(
    conn: &rusqlite::Transaction,
    params: &P,
    clock: C,
    mut rng: R,
    address: &TransparentAddress,
    offset_seconds: u32,
) -> Result<Option<SystemTime>, SqliteClientError> {
    let addr_str = address.encode(params);
    let now = clock.now();
    let next_check = next_check_time(&mut rng, now, offset_seconds)?;
    let scheduled_next_check = conn
        .query_row(
            "UPDATE addresses
             SET transparent_receiver_next_check_time = CASE
                WHEN transparent_receiver_next_check_time < :current_time THEN :next_check
                WHEN :next_check <= IFNULL(transparent_receiver_next_check_time, :next_check) THEN :next_check
                ELSE IFNULL(transparent_receiver_next_check_time, :next_check)
             END
             WHERE cached_transparent_receiver_address = :addr_str
             RETURNING transparent_receiver_next_check_time",
            named_params! {
                ":current_time": epoch_seconds(now)?,
                ":addr_str": addr_str,
                ":next_check": epoch_seconds(next_check)?
            },
            |row| row.get::<_, i64>(0),
        )
        .optional()?;

    scheduled_next_check
        .map(decode_epoch_seconds)
        .transpose()
        .map_err(SqliteClientError::from)
}

/// Marks each of the given transparent addresses as having been exposed to an external party
/// at or before its paired block height. For any address whose wallet row already tracks an
/// earlier exposure, that earlier height is retained.
///
/// The operation is atomic: if any address in `exposures` does not match a wallet row, the
/// call returns [`SqliteClientError::AddressNotRecognized`] for the first such address and
/// relies on the enclosing transaction being rolled back by the caller.
pub(crate) fn mark_transparent_addresses_exposed<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    exposures: &[(TransparentAddress, BlockHeight)],
) -> Result<(), SqliteClientError> {
    if exposures.is_empty() {
        return Ok(());
    }

    let mut stmt = conn.prepare_cached(
        "UPDATE addresses
         SET exposed_at_height = MIN(
             IFNULL(exposed_at_height, :height),
             :height
         )
         WHERE cached_transparent_receiver_address = :addr_str",
    )?;

    for (address, exposure_height) in exposures {
        let updated = stmt.execute(named_params! {
            ":height": u32::from(*exposure_height),
            ":addr_str": address.encode(params),
        })?;

        if updated == 0 {
            return Err(SqliteClientError::AddressNotRecognized(*address));
        }
    }

    Ok(())
}

/// Returns the vector of [`TransactionDataRequest`]s that represents the information needed by the
/// wallet backend in order to be able to present a complete view of wallet history and memo data.
///
/// FIXME: the need for these requests will be obviated if transparent spend and output information
/// is added to compact block data.
///
/// `lightwalletd` will return an error for `GetTaddressTxids` requests having an end height
/// greater than the current chain tip height, so we take the chain tip height into account
/// here in order to make this pothole easier for clients of the API to avoid.
pub(crate) fn transaction_data_requests<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    chain_tip_height: BlockHeight,
) -> Result<Vec<TransactionDataRequest>, SqliteClientError> {
    debug!(
        "Generating transaction data requests as of chain tip height {}",
        chain_tip_height
    );

    // Create transaction data requests that can find spends of our received UTXOs.
    //
    // With the `spend-index` feature, the chain-data source can resolve the spend of an
    // individual outpoint directly, so we request spends per-outpoint. Otherwise we fall back to
    // address-based requests (which, so long as address-based transaction data requests are
    // required at all, are served by address-based lookups rather than by querying the spends of
    // the associated outpoints directly).
    #[cfg(feature = "spend-index")]
    let spend_search_requests = {
        // Per-outpoint spend resolution is privacy-preserving (it does not correlate the
        // wallet's addresses to an untrusted server), so unlike the address-based path below
        // there is no need to exclude ephemeral-address outpoints here.
        let mut spend_requests_stmt = conn.prepare_cached(
            "SELECT t.txid, ssq.output_index
             FROM transparent_spend_search_queue ssq
             JOIN transactions t ON t.id_tx = ssq.transaction_id
             JOIN transparent_received_outputs tro
                ON tro.transaction_id = ssq.transaction_id AND tro.output_index = ssq.output_index
             LEFT OUTER JOIN transparent_received_output_spends tros
                ON tros.transparent_received_output_id = tro.id
             WHERE tros.transaction_id IS NULL
             AND (
                 tro.max_observed_unspent_height IS NULL
                 OR tro.max_observed_unspent_height < :chain_tip_height
             )",
        )?;

        spend_requests_stmt
            .query_and_then(
                named_params! {
                    ":chain_tip_height": u32::from(chain_tip_height)
                },
                |row| {
                    let outpoint = OutPoint::new(row.get::<_, [u8; 32]>(0)?, row.get::<_, u32>(1)?);
                    Ok::<TransactionDataRequest, SqliteClientError>(
                        TransactionDataRequest::GetSpendingTx(outpoint),
                    )
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };

    #[cfg(not(feature = "spend-index"))]
    let spend_search_requests = {
        let mut spend_requests_stmt = conn.prepare_cached(
            "SELECT
                ssq.address,
                COALESCE(tro.max_observed_unspent_height + 1, t.mined_height) AS block_range_start
             FROM transparent_spend_search_queue ssq
             JOIN transactions t ON t.id_tx = ssq.transaction_id
             JOIN transparent_received_outputs tro ON tro.transaction_id = t.id_tx
             JOIN addresses ON addresses.id = tro.address_id
             LEFT OUTER JOIN transparent_received_output_spends tros
                ON tros.transparent_received_output_id = tro.id
             WHERE tros.transaction_id IS NULL
             AND addresses.key_scope != :ephemeral_key_scope
             AND (
                 tro.max_observed_unspent_height IS NULL
                 OR tro.max_observed_unspent_height < :chain_tip_height
             )
             AND (
                 block_range_start IS NOT NULL
                 OR t.expiry_height > :chain_tip_height
             )",
        )?;

        spend_requests_stmt
            .query_and_then(
                named_params! {
                    ":ephemeral_key_scope": KeyScope::Ephemeral.encode(),
                    ":chain_tip_height": u32::from(chain_tip_height)
                },
                |row| {
                    let address = TransparentAddress::decode(params, &row.get::<_, String>(0)?)?;
                    // If the transaction that creates this UTXO is unmined, then this must be a
                    // mempool transaction so we default to the chain tip for block_range_start
                    let block_range_start = row
                        .get::<_, Option<u32>>(1)?
                        .map(BlockHeight::from)
                        .unwrap_or(chain_tip_height);
                    let max_end_height = block_range_start + DEFAULT_TX_EXPIRY_DELTA + 1;
                    Ok::<TransactionDataRequest, SqliteClientError>(
                        TransactionDataRequest::transactions_involving_address(
                            address,
                            block_range_start,
                            Some(std::cmp::min(chain_tip_height + 1, max_end_height)),
                            None,
                            TransactionStatusFilter::Mined,
                            OutputStatusFilter::All,
                        ),
                    )
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };

    // Query for transactions that "return" funds to an ephemeral address. By including a block
    // range start equal to the mined height of the transaction, we make it harder to distinguish
    // these requests from the spend detection requests above.
    //
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
            MIN(COALESCE(tro.max_observed_unspent_height + 1, t.mined_height)),
            transparent_receiver_next_check_time
         FROM addresses
         LEFT OUTER JOIN transparent_received_outputs tro ON tro.address_id = addresses.id
         LEFT OUTER JOIN transactions t ON t.id_tx = tro.transaction_id
         WHERE addresses.key_scope = :ephemeral_key_scope
         -- ensure that there is not a pending transaction
         AND NOT EXISTS (
            SELECT 'x'
            FROM transparent_received_outputs tro
            JOIN transactions t ON t.id_tx = tro.transaction_id
            WHERE tro.address_id = addresses.id
            AND t.expiry_height > :chain_tip_height
         )
         GROUP BY addresses.id",
    )?;

    let ephemeral_check_rows = ephemeral_check_stmt.query_and_then(
        named_params! {
            ":ephemeral_key_scope": KeyScope::Ephemeral.encode(),
            ":chain_tip_height": u32::from(chain_tip_height)
        },
        |row| {
            let address = TransparentAddress::decode(params, &row.get::<_, String>(0)?)?;
            let block_range_start = BlockHeight::from(row.get::<_, Option<u32>>(1)?.unwrap_or(0));
            let request_at = row
                .get::<_, Option<i64>>(2)?
                .map(decode_epoch_seconds)
                .transpose()?;

            Ok::<TransactionDataRequest, SqliteClientError>(
                TransactionDataRequest::transactions_involving_address(
                    address,
                    block_range_start,
                    None,
                    request_at,
                    TransactionStatusFilter::All,
                    OutputStatusFilter::Unspent,
                ),
            )
        },
    )?;

    let mut requests = spend_search_requests;
    for request in ephemeral_check_rows {
        requests.push(request?);
    }
    Ok(requests)
}

pub(crate) fn get_transparent_address_metadata<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account_uuid: AccountUuid,
    address: &TransparentAddress,
) -> Result<Option<TransparentAddressMetadata>, SqliteClientError> {
    let address_str = address.encode(params);
    let addr_meta = conn
        .query_row(
            "SELECT
                account_id,
                diversifier_index_be,
                key_scope,
                imported_transparent_receiver_pubkey,
                exposed_at_height,
                transparent_receiver_next_check_time,
                imported_transparent_receiver_script
             FROM addresses
             JOIN accounts ON addresses.account_id = accounts.id
             WHERE accounts.uuid = :account_uuid
             AND cached_transparent_receiver_address = :address",
            named_params![":account_uuid": account_uuid.0, ":address": &address_str],
            |row| {
                let account_id = row.get("account_id").map(AccountRef)?;
                let scope_code = row.get("key_scope")?;

                let next_check_time = row
                    .get::<_, Option<i64>>("transparent_receiver_next_check_time")?
                    .map(decode_epoch_seconds)
                    .transpose()
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

                Ok(KeyScope::decode(scope_code).and_then(|key_scope| {
                    let address_index = address_index_from_diversifier_index_be(row.get("diversifier_index_be")?)?;
                    let exposed_at_height = row.get::<_, Option<u32>>("exposed_at_height")?.map(BlockHeight::from);

                    match key_scope.as_transparent().zip(address_index) {
                        Some((t_key_scope, address_index)) => {
                            let exposure = exposed_at_height.map_or(
                                Ok::<_, SqliteClientError>(Exposure::Unknown),
                                |at_height| {
                                    let gap_metadata = match gap_limits.limit_for(t_key_scope) {
                                        None => GapMetadata::DerivationUnknown,
                                        Some(gap_limit) => {
                                            find_gap_start(conn, account_id, t_key_scope, gap_limit)?.map_or(
                                                GapMetadata::GapRecoverable { gap_limit },
                                                |gap_start| {
                                                    if let Some(gap_position) = address_index.index().checked_sub(gap_start.index()) {
                                                        GapMetadata::InGap {
                                                            gap_position,
                                                            gap_limit,
                                                        }
                                                    } else {
                                                        GapMetadata::GapRecoverable { gap_limit }
                                                    }
                                                }
                                            )
                                        }
                                    };

                                    Ok(Exposure::Exposed {
                                        at_height,
                                        gap_metadata
                                    })
                                }
                            )?;

                            Ok(TransparentAddressMetadata::derived(
                                t_key_scope,
                                address_index,
                                exposure,
                                next_check_time
                            ))
                        }
                        None => {
                            let _imported_transparent_receiver_script_bytes: Option<Vec<u8>> = row.get("imported_transparent_receiver_script")?;
                            let _pubkey_bytes = row.get::<_, Option<Vec<u8>>>("imported_transparent_receiver_pubkey")?;

                            let _standalone_exposure = exposed_at_height.map_or(
                                Exposure::Unknown,
                                |at_height| Exposure::Exposed {
                                    at_height,
                                    gap_metadata: GapMetadata::DerivationUnknown
                                }
                            );

                            #[cfg(feature = "transparent-key-import")]
                            {
                                if let Some(ref rs_bytes) = _imported_transparent_receiver_script_bytes {
                                    use zcash_script::script::{self, Code};

                                    let imported_transparent_receiver_script =
                                        script::Redeem::parse(&Code(rs_bytes.clone())).map_err(|e| {
                                            SqliteClientError::CorruptedData(format!(
                                                "Invalid redeem script: {:?}",
                                                e
                                            ))
                                        })?;

                                    Ok(TransparentAddressMetadata::standalone_script(
                                        imported_transparent_receiver_script,
                                        _standalone_exposure,
                                        next_check_time,
                                    ))
                                } else if let Some(ref pubkey_bytes_vec) = _pubkey_bytes {
                                    let pubkey_bytes = PublicKeyBytes::try_from(pubkey_bytes_vec.clone()).map_err(|_| {
                                        SqliteClientError::CorruptedData(
                                            "imported_transparent_receiver_pubkey must be 33 bytes in length".to_string()
                                        )
                                    })?;
                                    let pubkey = secp256k1::PublicKey::from_bytes(pubkey_bytes)?;

                                    Ok(TransparentAddressMetadata::standalone_p2pkh(
                                        pubkey,
                                        _standalone_exposure,
                                        next_check_time,
                                    ))
                                } else {
                                    Err(SqliteClientError::CorruptedData(
                                        "imported_transparent_receiver_pubkey or imported_transparent_receiver_script must be set for \"standalone\" transparent addresses".to_string()
                                    ))
                                }
                            }

                            #[cfg(not(feature = "transparent-key-import"))]
                            {
                                if _pubkey_bytes.is_some() || _imported_transparent_receiver_script_bytes.is_some() {
                                    Err(SqliteClientError::CorruptedData(
                                        "standalone imported transparent addresses are not supported by this build of `zcash_client_sqlite`".to_string()
                                    ))
                                } else {
                                    Err(SqliteClientError::CorruptedData(
                                        "imported_transparent_receiver_pubkey or imported_transparent_receiver_script must be set for \"standalone\" transparent addresses".to_string()
                                    ))
                                }
                            }
                        }
                    }
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
            let metadata = TransparentAddressMetadata::derived(
                Scope::External.into(),
                address_index,
                Exposure::CannotKnow,
                None,
            );
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
    conn: &rusqlite::Transaction,
    params: &P,
    gap_limits: &GapLimits,
    output: &WalletTransparentOutput<AccountUuid>,
    observation_height: BlockHeight,
    known_unspent: bool,
) -> Result<(AccountRef, AccountUuid, KeyScope, UtxoId), SqliteClientError> {
    let addr_str = output.recipient_address().encode(params);

    // Unlike the shielded pools, we only can receive transparent outputs on addresses for which we
    // have an `addresses` table entry, so we can just query for that here.
    let (address_id, account_id, account_uuid, key_scope_code) = conn
        .query_row(
            "SELECT addresses.id, account_id, accounts.uuid, key_scope
             FROM addresses
             JOIN accounts ON accounts.id = addresses.account_id
             WHERE cached_transparent_receiver_address = :transparent_address",
            named_params! {":transparent_address": addr_str},
            |row| {
                Ok((
                    row.get("id").map(AddressRef)?,
                    row.get("account_id").map(AccountRef)?,
                    row.get("uuid").map(AccountUuid)?,
                    row.get("key_scope")?,
                ))
            },
        )
        .optional()?
        .ok_or(SqliteClientError::AddressNotRecognized(
            *output.recipient_address(),
        ))?;

    let key_scope = KeyScope::decode(key_scope_code)?;

    let output_height = output.mined_height().map(u32::from);

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
        "INSERT INTO transactions (txid, block, mined_height, min_observed_height)
         VALUES (:txid, :block, :mined_height, :observation_height)
         ON CONFLICT (txid) DO UPDATE
         SET block = IFNULL(block, :block),
             -- A NULL :mined_height means the height is unknown to the caller (e.g. the
             -- output was observed in the mempool), not that the transaction is unmined;
             -- it must not discard a previously-recorded mined height. Un-mining is the
             -- responsibility of `truncate_to_height`.
             mined_height = IFNULL(:mined_height, mined_height),
             min_observed_height = MIN(min_observed_height, :observation_height),
             confirmed_unmined_at_height = CASE
                WHEN :mined_height IS NOT NULL THEN NULL
                ELSE confirmed_unmined_at_height
             END
         RETURNING id_tx",
        named_params![
           ":txid": &output.outpoint().hash().to_vec(),
           ":block": block,
           ":mined_height": output_height,
           ":observation_height": output_height.map_or_else(
               || u32::from(observation_height),
               |h| std::cmp::min(h, u32::from(observation_height))
           )
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
                ":output_index": output.outpoint().n(),
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

    let addr_str = output.recipient_address().encode(params);
    let sql_args = named_params![
        ":transaction_id": id_tx,
        ":output_index": output.outpoint().n(),
        ":account_id": account_id.0,
        ":address_id": address_id.0,
        ":address": &addr_str,
        ":script": &output.txout().script_pubkey().0.0,
        ":value_zat": &i64::from(ZatBalance::from(output.txout().value())),
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
             ORDER BY t.mined_height NULLS LAST LIMIT 1",
            named_params![
                ":prevout_txid": output.outpoint().txid().as_ref(),
                ":prevout_idx": output.outpoint().n()
            ],
            |row| row.get::<_, i64>(0).map(TxRef),
        )
        .optional()?;

    if let Some(spending_transaction_id) = spending_tx_ref {
        mark_transparent_utxo_spent(conn, spending_transaction_id, output.outpoint())?;
    }

    #[cfg(feature = "transparent-inputs")]
    update_gap_limits(
        conn,
        params,
        gap_limits,
        *output.outpoint().txid(),
        output_height.map_or(observation_height, BlockHeight::from),
    )?;

    Ok((account_id, account_uuid, key_scope, utxo_id))
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
    use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
    use zcash_client_backend::{
        data_api::{Account as _, WalletWrite, testing::TestBuilder},
        wallet::{Exposure, TransparentAddressMetadata},
    };
    use zcash_primitives::block::BlockHash;

    use crate::{
        GapLimits, WalletDb,
        error::SqliteClientError,
        testing::{BlockCache, db::TestDbFactory},
        wallet::{
            get_account_ref,
            transparent::{ephemeral, find_gap_start, reserve_next_n_addresses},
        },
    };

    #[test]
    fn put_received_transparent_utxo() {
        zcash_client_backend::data_api::testing::transparent::put_received_transparent_utxo(
            TestDbFactory::default(),
        );
    }

    /// Re-storing a transparent output with an unknown mined height (`None`) must not discard
    /// the mined height already recorded for its transaction. A `None` height means "we do not
    /// yet know this to have been mined" — for example, an output re-observed via the mempool
    /// or a transaction fetched from a backend that could not locate it on the best chain — and
    /// carries no evidence that a previously-recorded height is wrong. (Genuine un-mining is the
    /// responsibility of `truncate_to_height`.)
    #[test]
    fn put_received_transparent_utxo_preserves_mined_height() {
        use transparent::bundle::{OutPoint, TxOut};
        use zcash_client_backend::{data_api::WalletRead as _, wallet::WalletTransparentOutput};
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_protocol::value::Zatoshis;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_id = st.test_account().unwrap().id();
        let birthday = st.test_account().unwrap().birthday().height();
        let taddr = *st
            .wallet()
            .get_last_generated_address_matching(
                account_id,
                UnifiedAddressRequest::AllAvailableKeys,
            )
            .unwrap()
            .unwrap()
            .transparent()
            .unwrap();

        let mined_at = birthday + 100;
        st.wallet_mut().update_chain_tip(mined_at + 10).unwrap();

        let outpoint = OutPoint::fake();
        let txout = TxOut::new(Zatoshis::const_from_u64(100_000), taddr.script().into());

        // Store the output as mined at `mined_at`.
        let mined_utxo = WalletTransparentOutput::from_parts(
            outpoint.clone(),
            txout.clone(),
            Some(mined_at),
            Some(account_id),
            Some(TransparentKeyScope::EXTERNAL),
            None,
        )
        .unwrap();
        st.wallet_mut()
            .put_received_transparent_utxo(&mined_utxo)
            .unwrap();

        let mined_height: Option<u32> = st
            .wallet()
            .db()
            .conn
            .query_row(
                "SELECT mined_height FROM transactions WHERE txid = :txid",
                rusqlite::named_params! { ":txid": outpoint.hash().to_vec() },
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mined_height, Some(u32::from(mined_at)));

        // Re-store the same output with an unknown mined height.
        let unknown_height_utxo = WalletTransparentOutput::from_parts(
            outpoint.clone(),
            txout,
            None,
            Some(account_id),
            Some(TransparentKeyScope::EXTERNAL),
            None,
        )
        .unwrap();
        st.wallet_mut()
            .put_received_transparent_utxo(&unknown_height_utxo)
            .unwrap();

        // The previously-recorded mined height must be preserved.
        let mined_height: Option<u32> = st
            .wallet()
            .db()
            .conn
            .query_row(
                "SELECT mined_height FROM transactions WHERE txid = :txid",
                rusqlite::named_params! { ":txid": outpoint.hash().to_vec() },
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mined_height, Some(u32::from(mined_at)));
    }

    #[test]
    fn transparent_balance_across_shielding() {
        zcash_client_backend::data_api::testing::transparent::transparent_balance_across_shielding(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn shielding_many_transparent_utxos() {
        zcash_client_backend::data_api::testing::transparent::shielding_many_transparent_utxos(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn get_spendable_transparent_outputs_for_addresses() {
        zcash_client_backend::data_api::testing::transparent::get_spendable_transparent_outputs_for_addresses(
            TestDbFactory::default(),
        );
    }

    #[test]
    fn shielding_transparent_input_cap() {
        zcash_client_backend::data_api::testing::transparent::shielding_transparent_input_cap(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn propose_t2t_shielded_only_is_insufficient() {
        zcash_client_backend::data_api::testing::transparent::propose_t2t_shielded_only_is_insufficient(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn propose_t2t_any_account_taddr() {
        zcash_client_backend::data_api::testing::transparent::propose_t2t_any_account_taddr(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn propose_t2t_from_addresses() {
        zcash_client_backend::data_api::testing::transparent::propose_t2t_from_addresses(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn reserve_next_n_internal_addresses_gap_limit() {
        zcash_client_backend::data_api::testing::transparent::reserve_next_n_internal_addresses_gap_limit(
            TestDbFactory::default(),
            BlockCache::new(),
            |e, _, expected_bad_index| {
                matches!(
                    e,
                    SqliteClientError::ReachedGapLimit(scope, bad_index)
                    if scope == &TransparentKeyScope::INTERNAL && bad_index == &expected_bad_index
                )
            },
        );
    }

    #[test]
    fn propose_t2t_with_transparent_change() {
        zcash_client_backend::data_api::testing::transparent::propose_t2t_with_transparent_change(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn propose_t2t_transparent_change_exact_match() {
        zcash_client_backend::data_api::testing::transparent::propose_t2t_transparent_change_exact_match(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn propose_t2shielded_requires_transparent_regather() {
        zcash_client_backend::data_api::testing::transparent::propose_t2shielded_requires_transparent_regather(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn propose_transfer_transparent_input_cap() {
        zcash_client_backend::data_api::testing::transparent::propose_transfer_transparent_input_cap(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn value_bounded_transparent_gather() {
        zcash_client_backend::data_api::testing::transparent::value_bounded_transparent_gather(
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
            GapLimits::default(),
        );
    }

    /// Deriving an address that already exists as a standalone (`Foreign`) import upgrades the
    /// existing row in place — same `id`, derived scope, import columns cleared — rather than
    /// inserting a duplicate row for the same transparent receiver, and any UTXO already
    /// attached to the imported row carries over.
    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn store_address_range_upgrades_imported_receiver() {
        use rusqlite::named_params;
        use transparent::address::TransparentAddress;
        use zcash_keys::{address::Address, encoding::AddressCodec};

        use crate::wallet::encoding::KeyScope;

        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_uuid = st.test_account().unwrap().id();
        let network = *st.network();

        // An address we pretend was imported standalone and is also derivable at child index 100
        // (beyond the default external gap of 10, so no real derived row occupies that index).
        let taddr = TransparentAddress::PublicKeyHash([0x11; 20]);
        let taddr_enc = taddr.encode(&network);
        let child_index = NonHardenedChildIndex::from_index(100).unwrap();

        let tx = st.wallet().db().conn.unchecked_transaction().unwrap();
        let account_id = get_account_ref(&tx, account_uuid).unwrap();

        // A standalone (`Foreign`) row for the receiver, exposed at height 55.
        tx.execute(
            "INSERT INTO addresses
                 (account_id, key_scope, address, cached_transparent_receiver_address,
                  imported_transparent_receiver_pubkey, receiver_flags, exposed_at_height)
             VALUES (:account_id, :foreign, :address, :taddr,
                  X'020000000000000000000000000000000000000000000000000000000000000001', 1, 55)",
            named_params! {
                ":account_id": account_id.0,
                ":foreign": KeyScope::Foreign.encode(),
                ":address": &taddr_enc,
                ":taddr": &taddr_enc,
            },
        )
        .unwrap();
        let foreign_id = tx.last_insert_rowid();

        // A UTXO attached to the imported row.
        tx.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height) VALUES (1, X'00', 1)",
            [],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO transparent_received_outputs
                 (transaction_id, output_index, account_id, address, script, value_zat, address_id)
             VALUES (1, 0, :account_id, :taddr, X'00', 100000, :addr_id)",
            named_params! { ":account_id": account_id.0, ":taddr": &taddr_enc, ":addr_id": foreign_id },
        )
        .unwrap();

        // Derive the same address at child index 100 via the gap-generation storage entry point.
        super::store_address_range(
            &tx,
            &network,
            account_id,
            TransparentKeyScope::EXTERNAL,
            vec![(Address::from(taddr), taddr, child_index)],
        )
        .unwrap();

        // Exactly one row remains for the receiver: the upgraded former-import row.
        let mut stmt = tx
            .prepare(
                "SELECT id, key_scope, transparent_child_index,
                        imported_transparent_receiver_pubkey IS NULL
                 FROM addresses WHERE cached_transparent_receiver_address = :taddr",
            )
            .unwrap();
        let rows: Vec<(i64, i64, Option<u32>, bool)> = stmt
            .query_map(named_params! { ":taddr": &taddr_enc }, |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(stmt);

        assert_eq!(rows.len(), 1);
        let (id, key_scope, child, pubkey_is_null) = rows[0];
        assert_eq!(id, foreign_id, "upgraded in place, same id");
        assert_eq!(key_scope, KeyScope::EXTERNAL.encode());
        assert_eq!(child, Some(100));
        assert!(pubkey_is_null, "standalone-import column cleared");

        // The UTXO still references the (now-derived) row.
        let utxo_addr_id: i64 = tx
            .query_row(
                "SELECT address_id FROM transparent_received_outputs
                 WHERE transaction_id = 1 AND output_index = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(utxo_addr_id, foreign_id);

        tx.commit().unwrap();
    }

    /// Deriving an address that was imported as a standalone (`Foreign`) receiver under a
    /// *different* account also upgrades the existing row in place: deriving the address is
    /// itself proof that the deriving account owns it, so the row's account attribution moves
    /// to the deriving account, along with the account attribution of any outputs received at
    /// the address. Without this, the derive would fail on the receiver-uniqueness index.
    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn store_address_range_upgrades_receiver_imported_under_other_account() {
        use rusqlite::named_params;
        use transparent::address::TransparentAddress;
        use zcash_client_backend::data_api::{AccountBirthday, chain::ChainState};
        use zcash_keys::{address::Address, encoding::AddressCodec};
        use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

        use crate::wallet::encoding::KeyScope;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_a_uuid = st.test_account().unwrap().id();
        let network = *st.network();

        // A second account, under which the address will be imported.
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(
                network.activation_height(NetworkUpgrade::Sapling).unwrap() - 1,
                BlockHash([0; 32]),
            ),
            None,
        );
        let seed_b = Secret::new(vec![42u8; 32]);
        let (account_b_uuid, _) = st
            .wallet_mut()
            .create_account("b", &seed_b, &birthday, None)
            .unwrap();

        // An address we pretend was imported standalone under account B, and is derivable by
        // account A at child index 100 (beyond the default external gap of 10).
        let taddr = TransparentAddress::PublicKeyHash([0x22; 20]);
        let taddr_enc = taddr.encode(&network);
        let child_index = NonHardenedChildIndex::from_index(100).unwrap();

        let tx = st.wallet().db().conn.unchecked_transaction().unwrap();
        let account_a = get_account_ref(&tx, account_a_uuid).unwrap();
        let account_b = get_account_ref(&tx, account_b_uuid).unwrap();

        // The standalone (`Foreign`) row under account B.
        tx.execute(
            "INSERT INTO addresses
                 (account_id, key_scope, address, cached_transparent_receiver_address,
                  imported_transparent_receiver_pubkey, receiver_flags, exposed_at_height)
             VALUES (:account_id, :foreign, :address, :taddr,
                  X'020000000000000000000000000000000000000000000000000000000000000004', 1, 55)",
            named_params! {
                ":account_id": account_b.0,
                ":foreign": KeyScope::Foreign.encode(),
                ":address": &taddr_enc,
                ":taddr": &taddr_enc,
            },
        )
        .unwrap();
        let foreign_id = tx.last_insert_rowid();

        // A UTXO attached to the imported row, attributed to account B.
        tx.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height) VALUES (1, X'00', 1)",
            [],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO transparent_received_outputs
                 (transaction_id, output_index, account_id, address, script, value_zat, address_id)
             VALUES (1, 0, :account_id, :taddr, X'00', 100000, :addr_id)",
            named_params! { ":account_id": account_b.0, ":taddr": &taddr_enc, ":addr_id": foreign_id },
        )
        .unwrap();

        // Account A derives the same address.
        super::store_address_range(
            &tx,
            &network,
            account_a,
            TransparentKeyScope::EXTERNAL,
            vec![(Address::from(taddr), taddr, child_index)],
        )
        .unwrap();

        // Exactly one row remains for the receiver: the upgraded former-import row, now
        // belonging to account A.
        let mut stmt = tx
            .prepare(
                "SELECT id, account_id, key_scope, transparent_child_index,
                        imported_transparent_receiver_pubkey IS NULL
                 FROM addresses WHERE cached_transparent_receiver_address = :taddr",
            )
            .unwrap();
        let rows: Vec<(i64, i64, i64, Option<u32>, bool)> = stmt
            .query_map(named_params! { ":taddr": &taddr_enc }, |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(stmt);

        assert_eq!(rows.len(), 1);
        let (id, account_id, key_scope, child, pubkey_is_null) = rows[0];
        assert_eq!(id, foreign_id, "upgraded in place, same id");
        assert_eq!(
            account_id, account_a.0,
            "attribution moved to the deriving account"
        );
        assert_eq!(key_scope, KeyScope::EXTERNAL.encode());
        assert_eq!(child, Some(100));
        assert!(pubkey_is_null, "standalone-import column cleared");

        // The UTXO followed the row, and its account attribution moved with it.
        let (utxo_addr_id, utxo_account_id): (i64, i64) = tx
            .query_row(
                "SELECT address_id, account_id FROM transparent_received_outputs
                 WHERE transaction_id = 1 AND output_index = 0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((utxo_addr_id, utxo_account_id), (foreign_id, account_a.0));

        tx.commit().unwrap();
    }

    /// Smoke test that the `spend-index` feature's SQL is valid: `transaction_data_requests`
    /// runs its per-outpoint spend-search query, and `update_observed_unspent_height_for_outpoint`
    /// runs its `UPDATE ... FROM`. Exercised on a minimal wallet so the queries execute (failing
    /// the test on any SQL error) without needing a populated spend-search queue.
    #[test]
    #[cfg(feature = "spend-index")]
    fn spend_index_queries_are_valid_sql() {
        use transparent::bundle::OutPoint;
        use zcash_client_backend::data_api::WalletRead;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let chain_tip = st.test_account().unwrap().birthday().height() + 100;
        st.wallet_mut().update_chain_tip(chain_tip).unwrap();

        // Exercises the `spend-index` SELECT in `transaction_data_requests`.
        st.wallet().transaction_data_requests().unwrap();

        // Exercises the `spend-index` `UPDATE ... FROM` in
        // `update_observed_unspent_height_for_outpoint` (the outpoint matches no rows).
        let tx = st.wallet().db().conn.unchecked_transaction().unwrap();
        super::update_observed_unspent_height_for_outpoint(
            &tx,
            &OutPoint::new([1u8; 32], 0),
            chain_tip,
        )
        .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_pubkey() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_pubkey(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_pubkey_idempotent() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_pubkey_idempotent(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_pubkey_conflict() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_pubkey_conflict(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_pubkey_balance() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_pubkey_balance(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_spend_from_standalone_pubkey() {
        zcash_client_backend::data_api::testing::transparent::spend_from_standalone_pubkey(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_p2sh() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_p2sh(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_p2sh_idempotent() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_p2sh_idempotent(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_p2sh_conflict() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_p2sh_conflict(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_import_standalone_transparent_p2sh_balance() {
        zcash_client_backend::data_api::testing::transparent::import_standalone_transparent_p2sh_balance(
            TestDbFactory::default(),
        );
    }

    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn test_spend_from_standalone_p2sh() {
        zcash_client_backend::data_api::testing::transparent::spend_from_standalone_p2sh(
            TestDbFactory::default(),
            BlockCache::new(),
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
            let gap_start = find_gap_start(
                &db.conn,
                account_id,
                TransparentKeyScope::EPHEMERAL,
                db.gap_limits.ephemeral(),
            );
            assert_matches!(
                gap_start, Ok(addr_index)
                    if addr_index == Some(NonHardenedChildIndex::ZERO)
            );
            //assert_matches!(ephemeral::first_unstored_index(&db.conn, account_id), Ok(addr_index) if addr_index == GAP_LIMIT);

            let known_addrs = ephemeral::get_known_ephemeral_addresses(
                &db.conn,
                &db.params,
                &db.gap_limits,
                account_id,
                None,
            )
            .unwrap();

            let expected_metadata: Vec<TransparentAddressMetadata> = (0..db.gap_limits.ephemeral())
                .map(|i| {
                    ephemeral::metadata(
                        NonHardenedChildIndex::from_index(i).unwrap(),
                        Exposure::Unknown,
                        None,
                    )
                })
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
                TransparentKeyScope::EPHEMERAL,
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
                    TransparentKeyScope::EPHEMERAL,
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

    #[test]
    fn mark_transparent_addresses_exposed() {
        zcash_client_backend::data_api::testing::transparent::mark_transparent_addresses_exposed(
            TestDbFactory::default(),
        );
    }

    #[test]
    fn mark_transparent_addresses_exposed_bulk() {
        zcash_client_backend::data_api::testing::transparent::mark_transparent_addresses_exposed_bulk(
            TestDbFactory::default(),
        );
    }

    #[test]
    fn mark_transparent_addresses_exposed_unknown_address() {
        zcash_client_backend::data_api::testing::transparent::mark_transparent_addresses_exposed_unknown_address(
            TestDbFactory::default(),
        );
    }
}
