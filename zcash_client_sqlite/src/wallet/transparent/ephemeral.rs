//! Functions for wallet support of ephemeral transparent addresses.
use std::{ops::Range, time::SystemTime};

use rand::{RngCore, seq::SliceRandom};
use rusqlite::{OptionalExtension, named_params};

use ::transparent::{
    address::TransparentAddress,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};
use zcash_client_backend::wallet::{Exposure, TransparentAddressMetadata};
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::{self, BlockHeight};

#[cfg(any(test, feature = "test-dependencies"))]
use crate::GapLimits;
use crate::{
    AccountRef, AccountUuid,
    error::SqliteClientError,
    util::Clock,
    wallet::{
        KeyScope,
        encoding::{decode_epoch_seconds, epoch_seconds},
    },
};

use super::next_check_time;

// Returns `TransparentAddressMetadata` in the ephemeral scope for the
// given address index.
pub(crate) fn metadata(
    address_index: NonHardenedChildIndex,
    exposure: Exposure,
    next_check_time: Option<SystemTime>,
) -> TransparentAddressMetadata {
    TransparentAddressMetadata::derived(
        TransparentKeyScope::EPHEMERAL,
        address_index,
        exposure,
        next_check_time,
    )
}

/// Returns a vector of ephemeral transparent addresses associated with the given account
/// controlled by this wallet, along with their metadata. The result includes reserved addresses,
/// and addresses for the wallet's configured ephemeral address gap limit of additional indices
/// (capped to the maximum index).
///
/// If `index_range` is some `Range`, it limits the result to addresses with indices in that range.
#[cfg(any(test, feature = "test-dependencies"))]
pub(crate) fn get_known_ephemeral_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account_id: AccountRef,
    index_range: Option<Range<NonHardenedChildIndex>>,
) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
    use crate::wallet::transparent::find_gap_start;

    let gap_start = find_gap_start(
        conn,
        account_id,
        TransparentKeyScope::EPHEMERAL,
        gap_limits.ephemeral(),
    )?;

    let mut stmt = conn.prepare(
        "SELECT
            cached_transparent_receiver_address,
            transparent_child_index,
            exposed_at_height,
            transparent_receiver_next_check_time
         FROM addresses
         WHERE account_id = :account_id
         AND transparent_child_index >= :start
         AND transparent_child_index < :end
         AND key_scope = :key_scope
         ORDER BY transparent_child_index",
    )?;

    let results = stmt
        .query_and_then(
            named_params! {
                ":account_id": account_id.0,
                ":start": index_range.as_ref().map_or(NonHardenedChildIndex::ZERO, |i| i.start).index(),
                ":end": index_range.as_ref().map_or(NonHardenedChildIndex::MAX, |i| i.end).index(),
                ":key_scope": KeyScope::Ephemeral.encode()
            },
            |row| {
                use zcash_client_backend::wallet::GapMetadata;

                let addr_str: String = row.get("cached_transparent_receiver_address")?;

                let raw_index: u32 = row.get("transparent_child_index")?;
                let address_index = NonHardenedChildIndex::from_index(raw_index)
                    .expect("where clause ensures this is in range");

                let exposure = row.get::<_, Option<u32>>("exposed_at_height")?.map_or(
                    Exposure::Unknown,
                    |h| Exposure::Exposed {
                        at_height: BlockHeight::from(h),
                        gap_metadata: gap_start.map_or(
                            GapMetadata::DerivationUnknown,
                            |gap_start| {
                                if let Some(gap_position) = address_index.index().checked_sub(gap_start.index()) {
                                    GapMetadata::InGap {
                                        gap_position,
                                        gap_limit: gap_limits.ephemeral(),
                                    }
                                } else {
                                    GapMetadata::GapRecoverable { gap_limit: gap_limits.ephemeral() }
                                }
                            }
                        )
                    }
                );

                let next_check_time = row
                    .get::<_, Option<i64>>("transparent_receiver_next_check_time")?
                    .map(decode_epoch_seconds)
                    .transpose()?;

                Ok::<_, SqliteClientError>((
                    TransparentAddress::decode(params, &addr_str)?,
                    metadata(address_index, exposure, next_check_time)
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

pub(crate) fn schedule_ephemeral_address_checks<C: Clock, R: RngCore>(
    conn: &rusqlite::Transaction,
    clock: C,
    mut rng: R,
) -> Result<(), SqliteClientError> {
    let mut addr_check_times = conn.prepare(
        "SELECT id, transparent_receiver_next_check_time
         FROM addresses
         WHERE key_scope = :ephemeral_key_scope
         ORDER BY transparent_receiver_next_check_time NULLS FIRST",
    )?;
    let mut rows = addr_check_times
        .query_and_then(
            named_params! {
                ":ephemeral_key_scope": KeyScope::Ephemeral.encode()
            },
            |row| {
                let id: i64 = row.get("id")?;
                let next_check = row
                    .get::<_, Option<i64>>("transparent_receiver_next_check_time")?
                    .map(decode_epoch_seconds)
                    .transpose()?;
                Ok::<_, SqliteClientError>((id, next_check))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    if let Some((_, max_check_time)) = rows.last().as_ref() {
        // Updating the next check time should not result in an already-scheduled check being
        // further deferred.
        let mut set_check_time = conn.prepare(
            "UPDATE addresses
             SET transparent_receiver_next_check_time = CASE
                WHEN transparent_receiver_next_check_time < :current_time THEN :next_check
                WHEN :next_check <= IFNULL(transparent_receiver_next_check_time, :next_check) THEN :next_check
                ELSE IFNULL(transparent_receiver_next_check_time, :next_check)
             END
             WHERE id = :address_id",
        )?;

        // Set the expected value of the check time such that each ephemeral address will be
        // checked once per day.
        let check_interval =
            (24 * 60 * 60) / u32::try_from(rows.len()).expect("number of addresses fits in a u32");
        let now = clock.now();
        let mut check_time = max_check_time.map_or(now, |t| std::cmp::max(t, now));

        // Shuffle the addresses so that we don't always check them in the same order.
        rows.shuffle(&mut rng);
        for (address_id, addr_check_time) in rows {
            // if the check time for this address is absent or in the past, schedule a check.
            if addr_check_time.iter().all(|t| *t < now) {
                check_time = next_check_time(&mut rng, check_time, check_interval)?;
                set_check_time.execute(named_params! {
                    ":current_time": epoch_seconds(now)?,
                    ":next_check": epoch_seconds(check_time)?,
                    ":address_id": address_id
                })?;
            }
        }
    }

    Ok(())
}
