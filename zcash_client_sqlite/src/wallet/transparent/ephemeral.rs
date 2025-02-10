//! Functions for wallet support of ephemeral transparent addresses.
use std::ops::Range;

use rusqlite::{named_params, OptionalExtension};

use ::transparent::{
    address::TransparentAddress,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};
use zcash_client_backend::wallet::TransparentAddressMetadata;
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus;

use crate::{error::SqliteClientError, wallet::KeyScope, AccountRef, AccountUuid};

// Returns `TransparentAddressMetadata` in the ephemeral scope for the
// given address index.
pub(crate) fn metadata(address_index: NonHardenedChildIndex) -> TransparentAddressMetadata {
    TransparentAddressMetadata::new(TransparentKeyScope::EPHEMERAL, address_index)
}

/// Returns a vector of ephemeral transparent addresses associated with the given account
/// controlled by this wallet, along with their metadata. The result includes reserved addresses,
/// and addresses for the wallet's configured ephemeral address gap limit of additional indices
/// (capped to the maximum index).
///
/// If `index_range` is some `Range`, it limits the result to addresses with indices in that range.
pub(crate) fn get_known_ephemeral_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_id: AccountRef,
    index_range: Option<Range<NonHardenedChildIndex>>,
) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT cached_transparent_receiver_address, transparent_child_index 
         FROM addresses
         WHERE account_id = :account_id
         AND transparent_child_index >= :start 
         AND transparent_child_index < :end
         AND key_scope = :key_scope
         ORDER BY transparent_child_index",
    )?;

    let results = stmt
        .query_and_then(
            named_params![
                ":account_id": account_id.0,
                ":start": index_range.as_ref().map_or(NonHardenedChildIndex::ZERO, |i| i.start).index(),
                ":end": index_range.as_ref().map_or(NonHardenedChildIndex::MAX, |i| i.end).index(),
                ":key_scope": KeyScope::Ephemeral.encode()
            ],
            |row| {
                let addr_str: String = row.get(0)?;
                let raw_index: u32 = row.get(1)?;
                let address_index = NonHardenedChildIndex::from_index(raw_index)
                    .expect("where clause ensures this is in range");
                Ok::<_, SqliteClientError>((
                    TransparentAddress::decode(params, &addr_str)?,
                    metadata(address_index)
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// If this is a known ephemeral address in any account, return its account id.
pub(crate) fn find_account_for_ephemeral_address_str(
    conn: &rusqlite::Connection,
    address_str: &str,
) -> Result<Option<AccountUuid>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT accounts.uuid 
             FROM addresses
             JOIN accounts ON accounts.id = account_id
             WHERE cached_transparent_receiver_address = :address
             AND key_scope = :key_scope",
            named_params![
                ":address": &address_str,
                ":key_scope": KeyScope::Ephemeral.encode()
            ],
            |row| Ok(AccountUuid(row.get(0)?)),
        )
        .optional()?)
}
