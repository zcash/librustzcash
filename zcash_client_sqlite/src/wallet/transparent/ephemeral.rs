//! Functions for wallet support of ephemeral transparent addresses.
use std::cmp::{max, min};
use std::ops::Range;

use rusqlite::{named_params, OptionalExtension};

use ::transparent::{
    address::TransparentAddress,
    keys::{EphemeralIvk, NonHardenedChildIndex, TransparentKeyScope},
};
use zcash_client_backend::{data_api::GAP_LIMIT, wallet::TransparentAddressMetadata};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_keys::{encoding::AddressCodec, keys::AddressGenerationError};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus;

use crate::wallet::{self, get_account_ref};
use crate::AccountUuid;
use crate::{error::SqliteClientError, AccountRef, TxRef};

// Returns `TransparentAddressMetadata` in the ephemeral scope for the
// given address index.
pub(crate) fn metadata(address_index: NonHardenedChildIndex) -> TransparentAddressMetadata {
    TransparentAddressMetadata::new(TransparentKeyScope::EPHEMERAL, address_index)
}

/// Returns the first unstored ephemeral address index in the given account.
pub(crate) fn first_unstored_index(
    conn: &rusqlite::Connection,
    account_id: AccountRef,
) -> Result<u32, SqliteClientError> {
    match conn
        .query_row(
            "SELECT address_index FROM ephemeral_addresses
             WHERE account_id = :account_id
             ORDER BY address_index DESC
             LIMIT 1",
            named_params![":account_id": account_id.0],
            |row| row.get::<_, u32>(0),
        )
        .optional()?
    {
        Some(i) if i >= (1 << 31) + GAP_LIMIT => {
            unreachable!("violates constraint index_range_and_address_nullity")
        }
        Some(i) => Ok(i.checked_add(1).unwrap()),
        None => Ok(0),
    }
}

/// Returns the first unreserved ephemeral address index in the given account.
pub(crate) fn first_unreserved_index(
    conn: &rusqlite::Connection,
    account_id: AccountRef,
) -> Result<u32, SqliteClientError> {
    first_unstored_index(conn, account_id)?
        .checked_sub(GAP_LIMIT)
        .ok_or(SqliteClientError::CorruptedData(
            "ephemeral_addresses table has not been initialized".to_owned(),
        ))
}

/// Returns the first ephemeral address index in the given account that
/// would violate the gap invariant if used.
pub(crate) fn first_unsafe_index(
    conn: &rusqlite::Connection,
    account_id: AccountRef,
) -> Result<u32, SqliteClientError> {
    // The inner join with `transactions` excludes addresses for which
    // `seen_in_tx` is NULL. The query also excludes addresses observed
    // to have been mined in a transaction that we currently see as unmined.
    // This is conservative in terms of avoiding violation of the gap
    // invariant: it can only cause us to get to the end of the gap sooner.
    //
    // TODO: do we want to only consider transactions with a minimum number
    // of confirmations here?
    let first_unmined_index: u32 = match conn
        .query_row(
            "SELECT address_index FROM ephemeral_addresses
             JOIN transactions t ON t.id_tx = seen_in_tx
             WHERE account_id = :account_id AND t.mined_height IS NOT NULL
             ORDER BY address_index DESC
             LIMIT 1",
            named_params![":account_id": account_id.0],
            |row| row.get::<_, u32>(0),
        )
        .optional()?
    {
        Some(i) if i >= 1 << 31 => {
            unreachable!("violates constraint index_range_and_address_nullity")
        }
        Some(i) => i.checked_add(1).unwrap(),
        None => 0,
    };
    Ok(min(
        1 << 31,
        first_unmined_index.checked_add(GAP_LIMIT).unwrap(),
    ))
}

/// Utility function to return an `Range<u32>` that starts at `i`
/// and is of length up to `n`. The range is truncated if necessary
/// so that it contains no elements beyond the maximum valid address
/// index, `(1 << 31) - 1`.
pub(crate) fn range_from(i: u32, n: u32) -> Range<u32> {
    let first = min(1 << 31, i);
    let last = min(1 << 31, i.saturating_add(n));
    first..last
}

/// Returns the ephemeral transparent IVK for a given account ID.
pub(crate) fn get_ephemeral_ivk<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountRef,
) -> Result<Option<EphemeralIvk>, SqliteClientError> {
    let ufvk = conn
        .query_row(
            "SELECT ufvk FROM accounts WHERE id = :account_id",
            named_params![":account_id": account_id.0],
            |row| {
                let ufvk_str: Option<String> = row.get("ufvk")?;
                Ok(ufvk_str.map(|s| {
                    UnifiedFullViewingKey::decode(params, &s[..])
                        .map_err(SqliteClientError::BadAccountData)
                }))
            },
        )
        .optional()?
        .ok_or(SqliteClientError::AccountUnknown)?
        .transpose()?;

    let eivk = ufvk
        .as_ref()
        .and_then(|ufvk| ufvk.transparent())
        .map(|t| t.derive_ephemeral_ivk())
        .transpose()?;

    Ok(eivk)
}

/// Returns a vector of ephemeral transparent addresses associated with the given
/// account controlled by this wallet, along with their metadata. The result includes
/// reserved addresses, and addresses for `GAP_LIMIT` additional indices (capped to
/// the maximum index).
///
/// If `index_range` is some `Range`, it limits the result to addresses with indices
/// in that range.
pub(crate) fn get_known_ephemeral_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountRef,
    index_range: Option<Range<u32>>,
) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
    let index_range = index_range.unwrap_or(0..(1 << 31));

    let mut stmt = conn.prepare(
        "SELECT address, address_index 
         FROM ephemeral_addresses ea
         WHERE ea.account_id = :account_id
         AND address_index >= :start 
         AND address_index < :end
         ORDER BY address_index",
    )?;
    let mut rows = stmt.query(named_params![
        ":account_id": account_id.0,
        ":start": index_range.start,
        ":end": min(1 << 31, index_range.end),
    ])?;

    let mut result = vec![];

    while let Some(row) = rows.next()? {
        let addr_str: String = row.get(0)?;
        let raw_index: u32 = row.get(1)?;
        let address_index = NonHardenedChildIndex::from_index(raw_index)
            .expect("where clause ensures this is in range");
        let address = TransparentAddress::decode(params, &addr_str)?;
        result.push((address, metadata(address_index)));
    }
    Ok(result)
}

/// If this is a known ephemeral address in any account, return its account id.
pub(crate) fn find_account_for_ephemeral_address_str(
    conn: &rusqlite::Connection,
    address_str: &str,
) -> Result<Option<AccountUuid>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT accounts.uuid 
             FROM ephemeral_addresses ea
             JOIN accounts ON accounts.id = ea.account_id
             WHERE address = :address",
            named_params![":address": &address_str],
            |row| Ok(AccountUuid(row.get(0)?)),
        )
        .optional()?)
}

/// If this is a known ephemeral address in the given account, return its index.
pub(crate) fn find_index_for_ephemeral_address_str(
    conn: &rusqlite::Connection,
    account_uuid: AccountUuid,
    address_str: &str,
) -> Result<Option<NonHardenedChildIndex>, SqliteClientError> {
    let account_id = get_account_ref(conn, account_uuid)?;
    Ok(conn
        .query_row(
            "SELECT address_index FROM ephemeral_addresses
            WHERE account_id = :account_id AND address = :address",
            named_params![":account_id": account_id.0, ":address": &address_str],
            |row| row.get::<_, u32>(0),
        )
        .optional()?
        .map(|index| {
            NonHardenedChildIndex::from_index(index)
                .expect("valid by constraint index_range_and_address_nullity")
        }))
}

/// Returns a vector with the next `n` previously unreserved ephemeral addresses for
/// the given account.
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
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    n: usize,
) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
    if n == 0 {
        return Ok(vec![]);
    }

    let first_unreserved = first_unreserved_index(conn, account_id)?;
    let first_unsafe = first_unsafe_index(conn, account_id)?;
    let allocation = range_from(
        first_unreserved,
        u32::try_from(n).map_err(|_| AddressGenerationError::DiversifierSpaceExhausted)?,
    );

    if allocation.len() < n {
        return Err(AddressGenerationError::DiversifierSpaceExhausted.into());
    }
    if allocation.end > first_unsafe {
        let account_uuid = wallet::get_account_uuid(conn, account_id)?;
        return Err(SqliteClientError::ReachedGapLimit(
            account_uuid,
            max(first_unreserved, first_unsafe),
        ));
    }
    reserve_until(conn, params, account_id, allocation.end)?;
    get_known_ephemeral_addresses(conn, params, account_id, Some(allocation))
}

/// Initialize the `ephemeral_addresses` table. This must be called when
/// creating or migrating an account.
pub(crate) fn init_account<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
) -> Result<(), SqliteClientError> {
    reserve_until(conn, params, account_id, 0)
}

/// Extend the range of stored addresses in an account if necessary so that the index of the next
/// address to reserve will be *at least* `next_to_reserve`. If no transparent key exists for the
/// given account or it would already have been at least `next_to_reserve`, then do nothing.
///
/// Note that this is called from database migration code.
///
/// # Panics
///
/// Panics if the precondition `next_to_reserve <= (1 << 31)` does not hold.
fn reserve_until<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    next_to_reserve: u32,
) -> Result<(), SqliteClientError> {
    assert!(next_to_reserve <= 1 << 31);

    if let Some(ephemeral_ivk) = get_ephemeral_ivk(conn, params, account_id)? {
        let first_unstored = first_unstored_index(conn, account_id)?;
        let range_to_store = first_unstored..(next_to_reserve.checked_add(GAP_LIMIT).unwrap());
        if range_to_store.is_empty() {
            return Ok(());
        }

        // used_in_tx and seen_in_tx are initially NULL
        let mut stmt_insert_ephemeral_address = conn.prepare_cached(
            "INSERT INTO ephemeral_addresses (account_id, address_index, address)
             VALUES (:account_id, :address_index, :address)",
        )?;

        for raw_index in range_to_store {
            // The range to store may contain indicies that are out of the valid range of non hardened
            // child indices; we still store explicit rows in the ephemeral_addresses table for these
            // so that it's possible to find the first unused address using dead reckoning with the gap
            // limit.
            let address_str_opt = NonHardenedChildIndex::from_index(raw_index)
                .map(|address_index| {
                    ephemeral_ivk
                        .derive_ephemeral_address(address_index)
                        .map(|addr| addr.encode(params))
                })
                .transpose()?;

            stmt_insert_ephemeral_address.execute(named_params![
                ":account_id": account_id.0,
                ":address_index": raw_index,
                ":address": address_str_opt,
            ])?;
        }
    }

    Ok(())
}

/// Returns a `SqliteClientError::EphemeralAddressReuse` error if the address was
/// already used.
fn ephemeral_address_reuse_check(
    conn: &rusqlite::Transaction,
    address_str: &str,
) -> Result<(), SqliteClientError> {
    // It is intentional that we don't require `t.mined_height` to be non-null.
    // That is, we conservatively treat an ephemeral address as potentially
    // reused even if we think that the transaction where we had evidence of
    // its use is at present unmined. This should never occur in supported
    // situations where only a single correctly operating wallet instance is
    // using a given seed, because such a wallet will not reuse an address that
    // it ever reserved.
    //
    // `COALESCE(used_in_tx, seen_in_tx)` can only differ from `used_in_tx`
    // if the address was reserved, an error occurred in transaction creation
    // before calling `mark_ephemeral_address_as_used`, and then we saw the
    // address in another transaction (presumably created by another wallet
    // instance, or as a result of a bug) anyway.
    let res = conn
        .query_row(
            "SELECT t.txid FROM ephemeral_addresses
             LEFT OUTER JOIN transactions t
             ON t.id_tx = COALESCE(used_in_tx, seen_in_tx)
             WHERE address = :address",
            named_params![":address": address_str],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten();

    if let Some(txid_bytes) = res {
        let txid = TxId::from_bytes(
            txid_bytes
                .try_into()
                .map_err(|_| SqliteClientError::CorruptedData("invalid txid".to_owned()))?,
        );
        Err(SqliteClientError::EphemeralAddressReuse(
            address_str.to_owned(),
            txid,
        ))
    } else {
        Ok(())
    }
}

/// If `address` is one of our ephemeral addresses, mark it as having an output
/// in a transaction that we have just created. This has no effect if `address` is
/// not one of our ephemeral addresses.
///
/// Returns a `SqliteClientError::EphemeralAddressReuse` error if the address was
/// already used.
pub(crate) fn mark_ephemeral_address_as_used<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    ephemeral_address: &TransparentAddress,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    let address_str = ephemeral_address.encode(params);
    ephemeral_address_reuse_check(conn, &address_str)?;

    // We update both `used_in_tx` and `seen_in_tx` here, because a used address has
    // necessarily been seen in a transaction. We will not treat this as extending the
    // range of addresses that are safe to reserve unless and until the transaction is
    // observed as mined.
    let update_result = conn
        .query_row(
            "UPDATE ephemeral_addresses
             SET used_in_tx = :tx_ref, seen_in_tx = :tx_ref
             WHERE address = :address
             RETURNING account_id, address_index",
            named_params![":tx_ref": tx_ref.0, ":address": address_str],
            |row| Ok((AccountRef(row.get::<_, u32>(0)?), row.get::<_, u32>(1)?)),
        )
        .optional()?;

    // Maintain the invariant that the last `GAP_LIMIT` addresses are unused and unseen.
    if let Some((account_id, address_index)) = update_result {
        let next_to_reserve = address_index.checked_add(1).expect("ensured by constraint");
        reserve_until(conn, params, account_id, next_to_reserve)?;
    }
    Ok(())
}

/// If `address` is one of our ephemeral addresses, mark it as having an output
/// in the given mined transaction (which may or may not be a transaction we sent).
///
/// `tx_ref` must be a valid transaction reference. This call has no effect if
/// `address` is not one of our ephemeral addresses.
pub(crate) fn mark_ephemeral_address_as_seen<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    address: &TransparentAddress,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    let address_str = address.encode(params);

    // Figure out which transaction was mined earlier: `tx_ref`, or any existing
    // tx referenced by `seen_in_tx` for the given address. Prefer the existing
    // reference in case of a tie or if both transactions are unmined.
    // This slightly reduces the chance of unnecessarily reaching the gap limit
    // too early in some corner cases (because the earlier transaction is less
    // likely to be unmined).
    //
    // The query should always return a value if `tx_ref` is valid.
    let earlier_ref = conn.query_row(
        "SELECT id_tx FROM transactions
         LEFT OUTER JOIN ephemeral_addresses e
         ON id_tx = e.seen_in_tx
         WHERE id_tx = :tx_ref OR e.address = :address
         ORDER BY mined_height ASC NULLS LAST,
                  tx_index ASC NULLS LAST,
                  e.seen_in_tx ASC NULLS LAST
         LIMIT 1",
        named_params![":tx_ref": tx_ref.0, ":address": address_str],
        |row| row.get::<_, i64>(0),
    )?;

    let update_result = conn
        .query_row(
            "UPDATE ephemeral_addresses
             SET seen_in_tx = :seen_in_tx
             WHERE address = :address
             RETURNING account_id, address_index",
            named_params![":seen_in_tx": &earlier_ref, ":address": address_str],
            |row| Ok((AccountRef(row.get::<_, u32>(0)?), row.get::<_, u32>(1)?)),
        )
        .optional()?;

    // Maintain the invariant that the last `GAP_LIMIT` addresses are unused and unseen.
    if let Some((account_id, address_index)) = update_result {
        let next_to_reserve = address_index.checked_add(1).expect("ensured by constraint");
        reserve_until(conn, params, account_id, next_to_reserve)?;
    }
    Ok(())
}
