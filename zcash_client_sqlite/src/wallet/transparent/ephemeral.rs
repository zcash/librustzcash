//! Functions for wallet support of ephemeral transparent addresses.
use std::ops::RangeInclusive;

use rusqlite::{named_params, OptionalExtension};

use zcash_client_backend::wallet::TransparentAddressMetadata;
use zcash_primitives::legacy::keys::{NonHardenedChildIndex, TransparentKeyScope};

use crate::{error::SqliteClientError, AccountId};

/// The number of ephemeral addresses that can be safely reserved without observing any
/// of them to be mined. This is the same as the gap limit in Bitcoin.
pub(crate) const GAP_LIMIT: i32 = 20;

// The custom scope used for derivation of ephemeral addresses.
// TODO: consider moving this to `zcash_primitives::legacy::keys`, or else
// provide a way to derive `ivk`s for custom scopes in general there, so that
// the constant isn't duplicated.
pub(crate) const EPHEMERAL_SCOPE: TransparentKeyScope = match TransparentKeyScope::custom(2) {
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
