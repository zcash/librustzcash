//! Functions for wallet support of ephemeral transparent addresses.
use std::cmp::max;
use std::collections::HashMap;
use std::ops::RangeInclusive;

use rusqlite::{named_params, OptionalExtension};

use zcash_client_backend::{data_api::Account, wallet::TransparentAddressMetadata};
use zcash_keys::{
    encoding::{encode_transparent_address_p, AddressCodec},
    keys::AddressGenerationError,
};
use zcash_primitives::{
    legacy::{
        keys::{EphemeralIvk, NonHardenedChildIndex, TransparentKeyScope},
        TransparentAddress,
    },
    transaction::TxId,
};
use zcash_protocol::consensus;

use crate::{error::SqliteClientError, wallet::get_account, AccountId, SqlTransaction, WalletDb};

/// The number of ephemeral addresses that can be safely reserved without observing any
/// of them to be mined. This is the same as the gap limit in Bitcoin.
pub(crate) const GAP_LIMIT: i32 = 20;

// The custom scope used for derivation of ephemeral addresses.
//
// This must match the constant used in
// `zcash_primitives::legacy::keys::AccountPubKey::derive_ephemeral_ivk`.
//
// TODO: consider moving this to `zcash_primitives::legacy::keys`, or else
// provide a way to derive `ivk`s for custom scopes in general there, so that
// the constant isn't duplicated.
const EPHEMERAL_SCOPE: TransparentKeyScope = match TransparentKeyScope::custom(2) {
    Some(s) => s,
    None => unreachable!(),
};

// Returns `TransparentAddressMetadata` in the ephemeral scope for the
// given address index.
pub(crate) fn metadata(address_index: NonHardenedChildIndex) -> TransparentAddressMetadata {
    TransparentAddressMetadata::new(EPHEMERAL_SCOPE, address_index)
}

/// Returns the last reserved ephemeral address index in the given account,
/// or -1 if the account has no reserved ephemeral addresses.
pub(crate) fn last_reserved_index(
    conn: &rusqlite::Connection,
    account_id: AccountId,
) -> Result<i32, SqliteClientError> {
    match conn
        .query_row(
            "SELECT address_index FROM ephemeral_addresses
             WHERE account_id = :account_id
             ORDER BY address_index DESC
             LIMIT 1",
            named_params![":account_id": account_id.0],
            |row| row.get::<_, i32>(0),
        )
        .optional()?
    {
        Some(i) if i < 0 => Err(SqliteClientError::CorruptedData(
            "negative index".to_owned(),
        )),
        Some(i) => Ok(i),
        None => Ok(-1),
    }
}

/// Returns the last ephemeral address index in the given account that
/// would not violate the gap invariant if used.
pub(crate) fn last_safe_index(
    conn: &rusqlite::Connection,
    account_id: AccountId,
) -> Result<u32, SqliteClientError> {
    // The inner join with `transactions` excludes addresses for which
    // `mined_in_tx` is NULL. The query also excludes addresses observed
    // to have been mined in a transaction that we currently see as unmined.
    // This is conservative in terms of avoiding violation of the gap
    // invariant: it can only cause us to get to the end of the gap sooner.
    let last_mined_index: i32 = match conn
        .query_row(
            "SELECT address_index FROM ephemeral_addresses
             JOIN transactions t ON t.id_tx = mined_in_tx
             WHERE account_id = :account_id AND t.mined_height IS NOT NULL
             ORDER BY address_index DESC
             LIMIT 1",
            named_params![":account_id": account_id.0],
            |row| row.get::<_, i32>(0),
        )
        .optional()?
    {
        Some(i) if i < 0 => Err(SqliteClientError::CorruptedData(
            "negative index".to_owned(),
        )),
        Some(i) => Ok(i),
        None => Ok(-1),
    }?;
    Ok(u32::try_from(last_mined_index.saturating_add(GAP_LIMIT)).unwrap())
}

/// Utility function to return an `InclusiveRange<u32>` that starts at `i + 1`
/// and is of length up to `n`. The range is truncated if necessary to end at
/// the maximum valid address index, `i32::MAX`.
///
/// Precondition: `i >= -1 and n > 0`
pub(crate) fn range_after(i: i32, n: i32) -> RangeInclusive<u32> {
    assert!(i >= -1);
    assert!(n > 0);
    let first = u32::try_from(i64::from(i) + 1).unwrap();
    let last = u32::try_from(i.saturating_add(n)).unwrap();
    first..=last
}

/// Returns the ephemeral transparent IVK for a given account ID.
pub(crate) fn get_ephemeral_ivk<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountId,
) -> Result<EphemeralIvk, SqliteClientError> {
    Ok(get_account(conn, params, account_id)?
        .ok_or(SqliteClientError::AccountUnknown)?
        .ufvk()
        .and_then(|ufvk| ufvk.transparent())
        .ok_or(SqliteClientError::UnknownZip32Derivation)?
        .derive_ephemeral_ivk()?)
}

/// Returns a vector with all ephemeral transparent addresses potentially belonging to this wallet.
/// If `for_detection` is true, this includes addresses for an additional GAP_LIMIT indices.
pub(crate) fn get_reserved_ephemeral_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountId,
    for_detection: bool,
) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT address, address_index FROM ephemeral_addresses WHERE account_id = :account ORDER BY address_index",
    )?;
    let mut rows = stmt.query(named_params! { ":account": account_id.0 })?;

    let mut result = HashMap::new();
    let mut first_unused_index: Option<i32> = Some(0);

    while let Some(row) = rows.next()? {
        let addr_str: String = row.get(0)?;
        let raw_index: u32 = row.get(1)?;
        first_unused_index = i32::try_from(raw_index)
            .map_err(|e| SqliteClientError::CorruptedData(e.to_string()))?
            .checked_add(1);
        let address_index = NonHardenedChildIndex::from_index(raw_index).unwrap();
        let address = TransparentAddress::decode(params, &addr_str)?;
        result.insert(address, Some(metadata(address_index)));
    }

    if for_detection {
        if let Some(first) = first_unused_index {
            let ephemeral_ivk = get_ephemeral_ivk(conn, params, account_id)?;

            for raw_index in range_after(first, GAP_LIMIT) {
                let address_index = NonHardenedChildIndex::from_index(raw_index).unwrap();
                let address = ephemeral_ivk.derive_ephemeral_address(address_index)?;
                result.insert(address, Some(metadata(address_index)));
            }
        }
    }
    Ok(result)
}

/// Returns a vector with the next `n` previously unreserved ephemeral addresses for
/// the given account.
///
/// Precondition: `n >= 0`
///
/// # Errors
///
/// * `SqliteClientError::AccountUnknown`, if there is no account with the given id.
/// * `SqliteClientError::UnknownZip32Derivation`, if the account is imported and
///   it is not possible to derive new addresses for it.
/// * `SqliteClientError::ReachedGapLimit`, if it is not possible to reserve `n` addresses
///   within the gap limit after the last address in this account that is known to have an
///   output in a mined transaction.
/// * `SqliteClientError::AddressGeneration(AddressGenerationError::DiversifierSpaceExhausted)`,
///   if the limit on transparent address indices has been reached.
pub(crate) fn reserve_next_n_ephemeral_addresses<P: consensus::Parameters>(
    wdb: &mut WalletDb<SqlTransaction<'_>, P>,
    account_id: AccountId,
    n: i32,
) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
    if n == 0 {
        return Ok(vec![]);
    }
    assert!(n > 0);

    let ephemeral_ivk = get_ephemeral_ivk(wdb.conn.0, &wdb.params, account_id)?;
    let last_reserved_index = last_reserved_index(wdb.conn.0, account_id)?;
    let last_safe_index = last_safe_index(wdb.conn.0, account_id)?;
    let allocation = range_after(last_reserved_index, n);

    if allocation.clone().count() < n.try_into().unwrap() {
        return Err(SqliteClientError::AddressGeneration(
            AddressGenerationError::DiversifierSpaceExhausted,
        ));
    }
    if *allocation.end() > last_safe_index {
        let unsafe_index = max(*allocation.start(), last_safe_index.saturating_add(1));
        return Err(SqliteClientError::ReachedGapLimit(account_id, unsafe_index));
    }

    // used_in_tx and mined_in_tx are initially NULL
    let mut stmt_insert_ephemeral_address = wdb.conn.0.prepare_cached(
        "INSERT INTO ephemeral_addresses (account_id, address_index, address)
         VALUES (:account_id, :address_index, :address)",
    )?;

    allocation
        .map(|raw_index| {
            let address_index = NonHardenedChildIndex::from_index(raw_index).unwrap();
            let address = ephemeral_ivk.derive_ephemeral_address(address_index)?;

            stmt_insert_ephemeral_address.execute(named_params![
                ":account_id": account_id.0,
                ":address_index": raw_index,
                ":address": encode_transparent_address_p(&wdb.params, &address)
            ])?;
            Ok((address, metadata(address_index)))
        })
        .collect()
}

/// Returns a `SqliteClientError::EphemeralAddressReuse` error if `address` is
/// an ephemeral transparent address.
pub(crate) fn check_address_is_not_ephemeral<P: consensus::Parameters>(
    wdb: &mut WalletDb<SqlTransaction<'_>, P>,
    address_str: &str,
) -> Result<(), SqliteClientError> {
    ephemeral_address_check_internal(wdb, address_str, true)
}

/// Returns a `SqliteClientError::EphemeralAddressReuse` error if the address was
/// already used. If `reject_all_ephemeral` is set, return an error if the address
/// is ephemeral at all, regardless of reuse.
fn ephemeral_address_check_internal<P: consensus::Parameters>(
    wdb: &mut WalletDb<SqlTransaction<'_>, P>,
    address_str: &str,
    reject_all_ephemeral: bool,
) -> Result<(), SqliteClientError> {
    // It is intentional that we don't require `t.mined_height` to be non-null.
    // That is, we conservatively treat an ephemeral address as potentially
    // reused even if we think that the transaction where we had evidence of
    // its use is at present unmined. This should never occur in supported
    // situations where only a single correctly operating wallet instance is
    // using a given seed, because such a wallet will not reuse an address that
    // it ever reserved.
    //
    // `COALESCE(used_in_tx, mined_in_tx)` can only differ from `used_in_tx`
    // if the address was reserved, an error occurred in transaction creation
    // before calling `mark_ephemeral_address_as_used`, and then we observed
    // the address to have been used in a mined transaction (presumably by
    // another wallet instance, or due to a bug) anyway.
    let res = wdb
        .conn
        .0
        .query_row(
            "SELECT t.txid FROM ephemeral_addresses
             LEFT OUTER JOIN transactions t
             ON t.id_tx = COALESCE(used_in_tx, mined_in_tx)
             WHERE address = :address",
            named_params![":address": address_str],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?;

    match res {
        Some(Some(txid_bytes)) => {
            let txid = TxId::from_bytes(
                txid_bytes
                    .try_into()
                    .map_err(|_| SqliteClientError::CorruptedData("invalid txid".to_owned()))?,
            );
            Err(SqliteClientError::EphemeralAddressReuse(
                address_str.to_owned(),
                Some(txid),
            ))
        }
        Some(None) if reject_all_ephemeral => Err(SqliteClientError::EphemeralAddressReuse(
            address_str.to_owned(),
            None,
        )),
        _ => Ok(()),
    }
}

/// If `address` is one of our ephemeral addresses, mark it as having an output
/// in a transaction that we have just created. This has no effect if `address` is
/// not one of our ephemeral addresses.
///
/// Returns a `SqliteClientError::EphemeralAddressReuse` error if the address was
/// already used.
pub(crate) fn mark_ephemeral_address_as_used<P: consensus::Parameters>(
    wdb: &mut WalletDb<SqlTransaction<'_>, P>,
    ephemeral_address: &TransparentAddress,
    tx_ref: i64,
) -> Result<(), SqliteClientError> {
    let address_str = encode_transparent_address_p(&wdb.params, ephemeral_address);
    ephemeral_address_check_internal(wdb, &address_str, false)?;

    wdb.conn.0.execute(
        "UPDATE ephemeral_addresses SET used_in_tx = :used_in_tx WHERE address = :address",
        named_params![":used_in_tx": &tx_ref, ":address": address_str],
    )?;
    Ok(())
}

/// If `address` is one of our ephemeral addresses, mark it as having an output
/// in the given mined transaction (which may or may not be a transaction we sent).
///
/// `tx_ref` must be a valid transaction reference. This call has no effect if
/// `address` is not one of our ephemeral addresses.
pub(crate) fn mark_ephemeral_address_as_mined<P: consensus::Parameters>(
    wdb: &mut WalletDb<SqlTransaction<'_>, P>,
    address: &TransparentAddress,
    tx_ref: i64,
) -> Result<(), SqliteClientError> {
    let address_str = encode_transparent_address_p(&wdb.params, address);

    // Figure out which transaction was mined earlier: `tx_ref`, or any existing
    // tx referenced by `mined_in_tx` for the given address. Prefer the existing
    // reference in case of a tie or if both transactions are unmined.
    // This slightly reduces the chance of unnecessarily reaching the gap limit
    // too early in some corner cases (because the earlier transaction is less
    // likely to be unmined).
    //
    // The query should always return a value if `tx_ref` is valid.
    let earlier_ref = wdb.conn.0.query_row(
        "SELECT id_tx FROM transactions
         LEFT OUTER JOIN ephemeral_addresses e
         ON id_tx = e.mined_in_tx
         WHERE id_tx = :tx_ref OR e.address = :address
         ORDER BY mined_height ASC NULLS LAST,
                  tx_index ASC NULLS LAST,
                  e.mined_in_tx ASC NULLS LAST
         LIMIT 1",
        named_params![":tx_ref": &tx_ref, ":address": address_str],
        |row| row.get::<_, i64>(0),
    )?;

    wdb.conn.0.execute(
        "UPDATE ephemeral_addresses SET mined_in_tx = :mined_in_tx WHERE address = :address",
        named_params![":mined_in_tx": &earlier_ref, ":address": address_str],
    )?;
    Ok(())
}
