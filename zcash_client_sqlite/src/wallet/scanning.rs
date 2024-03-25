use incrementalmerkletree::{Address, Position};
use rusqlite::{self, named_params, types::Value, OptionalExtension};
use shardtree::error::ShardTreeError;
use std::cmp::{max, min};
use std::collections::BTreeSet;
use std::ops::Range;
use std::rc::Rc;
use tracing::{debug, trace};

use zcash_client_backend::{
    data_api::{
        scanning::{spanning_tree::SpanningTree, ScanPriority, ScanRange},
        SAPLING_SHARD_HEIGHT,
    },
    ShieldedProtocol,
};
use zcash_primitives::consensus::{self, BlockHeight, NetworkUpgrade};

use crate::{
    error::SqliteClientError,
    wallet::{block_height_extrema, commitment_tree, init::WalletMigrationError},
    PRUNING_DEPTH, SAPLING_TABLES_PREFIX, VERIFY_LOOKAHEAD,
};

use super::wallet_birthday;

#[cfg(feature = "orchard")]
use {crate::ORCHARD_TABLES_PREFIX, zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT};

#[cfg(not(feature = "orchard"))]
use zcash_client_backend::PoolType;

pub(crate) fn priority_code(priority: &ScanPriority) -> i64 {
    use ScanPriority::*;
    match priority {
        Ignored => 0,
        Scanned => 10,
        Historic => 20,
        OpenAdjacent => 30,
        FoundNote => 40,
        ChainTip => 50,
        Verify => 60,
    }
}

pub(crate) fn parse_priority_code(code: i64) -> Option<ScanPriority> {
    use ScanPriority::*;
    match code {
        0 => Some(Ignored),
        10 => Some(Scanned),
        20 => Some(Historic),
        30 => Some(OpenAdjacent),
        40 => Some(FoundNote),
        50 => Some(ChainTip),
        60 => Some(Verify),
        _ => None,
    }
}

pub(crate) fn suggest_scan_ranges(
    conn: &rusqlite::Connection,
    min_priority: ScanPriority,
) -> Result<Vec<ScanRange>, SqliteClientError> {
    let mut stmt_scan_ranges = conn.prepare_cached(
        "SELECT block_range_start, block_range_end, priority
         FROM scan_queue
         WHERE priority >= :min_priority
         ORDER BY priority DESC, block_range_end DESC",
    )?;

    let mut rows =
        stmt_scan_ranges.query(named_params![":min_priority": priority_code(&min_priority)])?;

    let mut result = vec![];
    while let Some(row) = rows.next()? {
        let range = Range {
            start: row.get::<_, u32>(0).map(BlockHeight::from)?,
            end: row.get::<_, u32>(1).map(BlockHeight::from)?,
        };
        let code = row.get::<_, i64>(2)?;
        let priority = parse_priority_code(code).ok_or_else(|| {
            SqliteClientError::CorruptedData(format!("scan priority not recognized: {}", code))
        })?;

        result.push(ScanRange::from_parts(range, priority));
    }

    Ok(result)
}

pub(crate) fn insert_queue_entries<'a>(
    conn: &rusqlite::Connection,
    entries: impl Iterator<Item = &'a ScanRange>,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
        VALUES (:block_range_start, :block_range_end, :priority)",
    )?;

    for entry in entries {
        trace!("Inserting queue entry {}", entry);
        if !entry.is_empty() {
            stmt.execute(named_params![
                ":block_range_start": u32::from(entry.block_range().start),
                ":block_range_end": u32::from(entry.block_range().end),
                ":priority": priority_code(&entry.priority())
            ])?;
        }
    }

    Ok(())
}

/// A trait that abstracts over the construction of wallet errors.
///
/// In order to make it possible to use [`replace_queue_entries`] in database migrations as well as
/// in code that returns `SqliteClientError`, it is necessary for that method to be polymorphic in
/// the error type.
pub(crate) trait WalletError {
    fn db_error(err: rusqlite::Error) -> Self;
    fn corrupt(message: String) -> Self;
    fn chain_height_unknown() -> Self;
    fn commitment_tree(err: ShardTreeError<commitment_tree::Error>) -> Self;
}

impl WalletError for SqliteClientError {
    fn db_error(err: rusqlite::Error) -> Self {
        SqliteClientError::DbError(err)
    }

    fn corrupt(message: String) -> Self {
        SqliteClientError::CorruptedData(message)
    }

    fn chain_height_unknown() -> Self {
        SqliteClientError::ChainHeightUnknown
    }

    fn commitment_tree(err: ShardTreeError<commitment_tree::Error>) -> Self {
        SqliteClientError::CommitmentTree(err)
    }
}

impl WalletError for WalletMigrationError {
    fn db_error(err: rusqlite::Error) -> Self {
        WalletMigrationError::DbError(err)
    }

    fn corrupt(message: String) -> Self {
        WalletMigrationError::CorruptedData(message)
    }

    fn chain_height_unknown() -> Self {
        WalletMigrationError::CorruptedData(
            "Wallet migration requires a valid account birthday.".to_owned(),
        )
    }

    fn commitment_tree(err: ShardTreeError<commitment_tree::Error>) -> Self {
        WalletMigrationError::CommitmentTree(err)
    }
}

pub(crate) fn replace_queue_entries<E: WalletError>(
    conn: &rusqlite::Transaction<'_>,
    query_range: &Range<BlockHeight>,
    entries: impl Iterator<Item = ScanRange>,
    force_rescans: bool,
) -> Result<(), E> {
    let (to_create, to_delete_ends) = {
        let mut suggested_stmt = conn
            .prepare_cached(
                "SELECT block_range_start, block_range_end, priority
                 FROM scan_queue
                 -- Ignore ranges that do not overlap and are not adjacent to the query range.
                 WHERE NOT (block_range_start > :end OR :start > block_range_end)
                 ORDER BY block_range_end",
            )
            .map_err(E::db_error)?;

        let mut rows = suggested_stmt
            .query(named_params![
                ":start": u32::from(query_range.start),
                ":end": u32::from(query_range.end),
            ])
            .map_err(E::db_error)?;

        // Iterate over the ranges in the scan queue that overlap the range that we have
        // identified as needing to be fully scanned. For each such range add it to the
        // spanning tree (these should all be nonoverlapping ranges, but we might coalesce
        // some in the process).
        let mut to_create: Option<SpanningTree> = None;
        let mut to_delete_ends: Vec<Value> = vec![];
        while let Some(row) = rows.next().map_err(E::db_error)? {
            let entry = ScanRange::from_parts(
                Range {
                    start: BlockHeight::from(row.get::<_, u32>(0).map_err(E::db_error)?),
                    end: BlockHeight::from(row.get::<_, u32>(1).map_err(E::db_error)?),
                },
                {
                    let code = row.get::<_, i64>(2).map_err(E::db_error)?;
                    parse_priority_code(code).ok_or_else(|| {
                        E::corrupt(format!("scan priority not recognized: {}", code))
                    })?
                },
            );
            to_delete_ends.push(Value::from(u32::from(entry.block_range().end)));
            to_create = if let Some(cur) = to_create {
                Some(cur.insert(entry, force_rescans))
            } else {
                Some(SpanningTree::Leaf(entry))
            };
        }

        // Update the tree that we read from the database, or if we didn't find any ranges
        // start with the scanned range.
        for entry in entries {
            to_create = if let Some(cur) = to_create {
                Some(cur.insert(entry, force_rescans))
            } else {
                Some(SpanningTree::Leaf(entry))
            };
        }

        (to_create, to_delete_ends)
    };

    if let Some(tree) = to_create {
        let ends_ptr = Rc::new(to_delete_ends);
        conn.execute(
            "DELETE FROM scan_queue WHERE block_range_end IN rarray(:ends)",
            named_params![":ends": ends_ptr],
        )
        .map_err(E::db_error)?;

        let scan_ranges = tree.into_vec();
        insert_queue_entries(conn, scan_ranges.iter()).map_err(E::db_error)?;
    }

    Ok(())
}

fn extend_range(
    conn: &rusqlite::Transaction<'_>,
    range: &Range<BlockHeight>,
    required_subtree_indices: BTreeSet<u64>,
    table_prefix: &'static str,
    fallback_start_height: Option<BlockHeight>,
    birthday_height: Option<BlockHeight>,
) -> Result<Option<Range<BlockHeight>>, SqliteClientError> {
    // we'll either have both min and max bounds, or we'll have neither
    let subtree_index_bounds = required_subtree_indices
        .iter()
        .min()
        .zip(required_subtree_indices.iter().max());

    let mut shard_end_stmt = conn.prepare_cached(&format!(
        "SELECT subtree_end_height
                FROM {}_tree_shards
                WHERE shard_index = :shard_index",
        table_prefix
    ))?;

    let mut shard_end = |index: u64| -> Result<Option<BlockHeight>, rusqlite::Error> {
        Ok(shard_end_stmt
            .query_row(named_params![":shard_index": index], |row| {
                row.get::<_, Option<u32>>(0)
                    .map(|opt| opt.map(BlockHeight::from))
            })
            .optional()?
            .flatten())
    };

    // If no notes belonging to the wallet were found, we don't need to extend the scanning
    // range suggestions to include the associated subtrees, and our bounds are just the
    // scanned range. Otherwise, ensure that all shard ranges starting from the wallet
    // birthday are included.
    subtree_index_bounds
        .map(|(min_idx, max_idx)| {
            let range_min = if *min_idx > 0 {
                // get the block height of the end of the previous shard
                shard_end(*min_idx - 1)?
            } else {
                // our lower bound is going to be the fallback height
                fallback_start_height
            };

            // bound the minimum to the wallet birthday
            let range_min = range_min.map(|h| birthday_height.map_or(h, |b| std::cmp::max(b, h)));

            // Get the block height for the end of the current shard, and make it an
            // exclusive end bound.
            let range_max = shard_end(*max_idx)?.map(|end| end + 1);

            Ok::<Range<BlockHeight>, rusqlite::Error>(Range {
                start: range.start.min(range_min.unwrap_or(range.start)),
                end: range.end.max(range_max.unwrap_or(range.end)),
            })
        })
        .transpose()
        .map_err(SqliteClientError::from)
}

pub(crate) fn scan_complete<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    range: Range<BlockHeight>,
    wallet_note_positions: &[(ShieldedProtocol, Position)],
) -> Result<(), SqliteClientError> {
    // Read the wallet birthday (if known).
    // TODO: use per-pool birthdays?
    let wallet_birthday = wallet_birthday(conn)?;

    // Determine the range of block heights for which we will be updating the scan queue.
    let extended_range = {
        // If notes have been detected in the scan, we need to extend any adjacent un-scanned
        // ranges starting from the wallet birthday to include the blocks needed to complete
        // the note commitment tree subtrees containing the positions of the discovered notes.
        // We will query by subtree index to find these bounds.
        let mut required_sapling_subtrees = BTreeSet::new();
        #[cfg(feature = "orchard")]
        let mut required_orchard_subtrees = BTreeSet::new();
        for (protocol, position) in wallet_note_positions {
            match protocol {
                ShieldedProtocol::Sapling => {
                    required_sapling_subtrees.insert(
                        Address::above_position(SAPLING_SHARD_HEIGHT.into(), *position).index(),
                    );
                }
                ShieldedProtocol::Orchard => {
                    #[cfg(feature = "orchard")]
                    required_orchard_subtrees.insert(
                        Address::above_position(ORCHARD_SHARD_HEIGHT.into(), *position).index(),
                    );

                    #[cfg(not(feature = "orchard"))]
                    return Err(SqliteClientError::UnsupportedPoolType(PoolType::Shielded(
                        *protocol,
                    )));
                }
            }
        }

        let extended_range = extend_range(
            conn,
            &range,
            required_sapling_subtrees,
            SAPLING_TABLES_PREFIX,
            params.activation_height(NetworkUpgrade::Sapling),
            wallet_birthday,
        )?;

        #[cfg(feature = "orchard")]
        let extended_range = extend_range(
            conn,
            extended_range.as_ref().unwrap_or(&range),
            required_orchard_subtrees,
            ORCHARD_TABLES_PREFIX,
            params.activation_height(NetworkUpgrade::Nu5),
            wallet_birthday,
        )?
        .or(extended_range);

        #[allow(clippy::let_and_return)]
        extended_range
    };

    let query_range = extended_range.clone().unwrap_or_else(|| range.clone());

    let scanned = ScanRange::from_parts(range.clone(), ScanPriority::Scanned);

    // If any of the extended range actually extends beyond the scanned range, we need to
    // scan that extension in order to make the found note(s) spendable. We need to avoid
    // creating empty ranges here, as that acts as an optimization barrier preventing
    // `SpanningTree` from merging non-empty scanned ranges on either side.
    let extended_before = extended_range
        .as_ref()
        .map(|extended| ScanRange::from_parts(extended.start..range.start, ScanPriority::FoundNote))
        .filter(|range| !range.is_empty());
    let extended_after = extended_range
        .map(|extended| ScanRange::from_parts(range.end..extended.end, ScanPriority::FoundNote))
        .filter(|range| !range.is_empty());

    let replacement = Some(scanned)
        .into_iter()
        .chain(extended_before)
        .chain(extended_after);

    replace_queue_entries::<SqliteClientError>(conn, &query_range, replacement, false)?;

    Ok(())
}

fn tip_shard_end_height(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.query_row(
        &format!(
            "SELECT MAX(subtree_end_height) FROM {}_tree_shards",
            table_prefix
        ),
        [],
        |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
    )
}

pub(crate) fn update_chain_tip<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    new_tip: BlockHeight,
) -> Result<(), SqliteClientError> {
    // If the caller provided a chain tip that is before Sapling activation, do nothing.
    let sapling_activation = match params.activation_height(NetworkUpgrade::Sapling) {
        Some(h) if h <= new_tip => h,
        _ => return Ok(()),
    };

    // Read the previous max scanned height from the blocks table
    let max_scanned = block_height_extrema(conn)?.map(|range| *range.end());

    // Read the wallet birthday (if known).
    let wallet_birthday = wallet_birthday(conn)?;

    // If the chain tip is below the prior max scanned height, then the caller has caught
    // the chain in the middle of a reorg. Do nothing; the caller will continue using the
    // old scan ranges and either:
    // - encounter an error trying to fetch the blocks (and thus trigger the same handling
    //   logic as if this happened with the old linear scanning code); or
    // - encounter a discontinuity error in `scan_cached_blocks`, at which point they will
    //   call `WalletDb::truncate_to_height` as part of their reorg handling which will
    //   resolve the problem.
    //
    // We don't check the shard height, as normal usage would have the caller update the
    // shard state prior to this call, so it is possible and expected to be in a situation
    // where we should update the tip-related scan ranges but not the shard-related ones.
    match max_scanned {
        Some(h) if new_tip < h => return Ok(()),
        _ => (),
    };

    // `ScanRange` uses an exclusive upper bound.
    let chain_end = new_tip + 1;

    // Read the maximum height from each of the shards tables. The minimum of the two
    // gives the start of a height range that covers the last incomplete shard of both the
    // Sapling and Orchard pools.
    let sapling_shard_tip = tip_shard_end_height(conn, SAPLING_TABLES_PREFIX)?;
    #[cfg(feature = "orchard")]
    let orchard_shard_tip = tip_shard_end_height(conn, ORCHARD_TABLES_PREFIX)?;

    #[cfg(feature = "orchard")]
    let min_shard_tip = match (sapling_shard_tip, orchard_shard_tip) {
        (None, None) => None,
        (None, Some(o)) => Some(o),
        (Some(s), None) => Some(s),
        (Some(s), Some(o)) => Some(std::cmp::min(s, o)),
    };
    #[cfg(not(feature = "orchard"))]
    let min_shard_tip = sapling_shard_tip;

    // Create a scanning range for the fragment of the last shard leading up to new tip.
    // We set a lower bound at the wallet birthday (if known), because account creation
    // requires specifying a tree frontier that ensures we don't need tree information
    // prior to the birthday.
    let tip_shard_entry = min_shard_tip.filter(|h| h < &chain_end).map(|h| {
        let min_to_scan = wallet_birthday.filter(|b| b > &h).unwrap_or(h);
        ScanRange::from_parts(min_to_scan..chain_end, ScanPriority::ChainTip)
    });

    // Create scan ranges to either validate potentially invalid blocks at the wallet's
    // view of the chain tip, or connect the prior tip to the new tip.
    let tip_entry = max_scanned.map_or_else(
        || {
            // No blocks have been scanned, so we need to anchor the start of the new scan
            // range to something else.
            wallet_birthday.map_or_else(
                // We don't have a wallet birthday, which means we have no accounts yet.
                // We can therefore ignore all blocks up to the chain tip.
                || ScanRange::from_parts(sapling_activation..chain_end, ScanPriority::Ignored),
                // We have a wallet birthday, so mark all blocks between that and the
                // chain tip as `Historic` (performing wallet recovery).
                |wallet_birthday| {
                    ScanRange::from_parts(wallet_birthday..chain_end, ScanPriority::Historic)
                },
            )
        },
        |max_scanned| {
            // The scan range starts at the block after the max scanned height. Since
            // `scan_cached_blocks` retrieves the metadata for the block being connected to
            // (if it exists), the connectivity of the scan range to the max scanned block
            // will always be checked if relevant.
            let min_unscanned = max_scanned + 1;

            // If we don't have shard metadata, this means we're doing linear scanning, so
            // create a scan range from the prior tip to the current tip with `Historic`
            // priority.
            if tip_shard_entry.is_none() {
                ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::Historic)
            } else {
                // Determine the height to which we expect new blocks retrieved from the
                // block source to be stable and not subject to being reorg'ed.
                let stable_height = new_tip.saturating_sub(PRUNING_DEPTH);

                // If the wallet's max scanned height is above the stable height,
                // prioritize the range between it and the new tip as `ChainTip`.
                if max_scanned > stable_height {
                    // We are in the steady-state case, where a wallet is close to the
                    // chain tip and just needs to catch up.
                    //
                    // This overlaps the `tip_shard_entry` range and so will be coalesced
                    // with it.
                    ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::ChainTip)
                } else {
                    // In this case, the max scanned height is considered stable relative
                    // to the chain tip. However, it may be stable or unstable relative to
                    // the prior chain tip, which we could determine by looking up the
                    // prior chain tip height from the scan queue. For simplicity we merge
                    // these two cases together, and proceed as though the max scanned
                    // block is unstable relative to the prior chain tip.
                    //
                    // To confirm its stability, prioritize the `VERIFY_LOOKAHEAD` blocks
                    // above the max scanned height as `Verify`:
                    //
                    // - We use `Verify` to ensure that a connectivity check is performed,
                    //   along with any required rewinds, before any `ChainTip` ranges
                    //   (from this or any prior `update_chain_tip` call) are scanned.
                    //
                    // - We prioritize `VERIFY_LOOKAHEAD` blocks because this is expected
                    //   to be 12.5 minutes, within which it is reasonable for a user to
                    //   have potentially received a transaction (if they opened their
                    //   wallet to provide an address to someone else, or spent their own
                    //   funds creating a change output), without necessarily having left
                    //   their wallet open long enough for the transaction to be mined and
                    //   the corresponding block to be scanned.
                    //
                    // - We limit the range to at most the stable region, to prevent any
                    //   `Verify` ranges from being susceptible to reorgs, and potentially
                    //   interfering with subsequent `Verify` ranges defined by future
                    //   calls to `update_chain_tip`. Any gap between `stable_height` and
                    //   `shard_start_height` will be filled by the scan range merging
                    //   logic with a `Historic` range.
                    //
                    // If `max_scanned == stable_height` then this is a zero-length range.
                    // In this case, any non-empty `(stable_height+1)..shard_start_height`
                    // will be marked `Historic`, minimising the prioritised blocks at the
                    // chain tip and allowing for other ranges (for example, `FoundNote`)
                    // to take priority.
                    ScanRange::from_parts(
                        min_unscanned..min(stable_height + 1, min_unscanned + VERIFY_LOOKAHEAD),
                        ScanPriority::Verify,
                    )
                }
            }
        },
    );
    if let Some(entry) = &tip_shard_entry {
        debug!("{} will update latest shard", entry);
    }
    debug!("{} will connect prior scanned state to new tip", tip_entry);

    let query_range = match tip_shard_entry.as_ref() {
        Some(se) => Range {
            start: min(se.block_range().start, tip_entry.block_range().start),
            end: max(se.block_range().end, tip_entry.block_range().end),
        },
        None => tip_entry.block_range().clone(),
    };

    replace_queue_entries::<SqliteClientError>(
        conn,
        &query_range,
        tip_shard_entry.into_iter().chain(Some(tip_entry)),
        false,
    )?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::num::NonZeroU8;

    use incrementalmerkletree::{frontier::Frontier, Hashable, Position};

    use secrecy::SecretVec;
    use zcash_client_backend::data_api::{
        chain::{ChainState, CommitmentTreeRoot},
        scanning::{spanning_tree::testing::scan_range, ScanPriority},
        AccountBirthday, Ratio, WalletRead, WalletWrite, SAPLING_SHARD_HEIGHT,
    };
    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, NetworkUpgrade, Parameters},
        transaction::components::amount::NonNegativeAmount,
    };

    use crate::{
        error::SqliteClientError,
        testing::{
            pool::ShieldedPoolTester, AddressType, BlockCache, InitialChainState, TestBuilder,
            TestState,
        },
        wallet::{
            sapling::tests::SaplingPoolTester,
            scanning::{insert_queue_entries, replace_queue_entries, suggest_scan_ranges},
        },
        VERIFY_LOOKAHEAD,
    };

    #[cfg(feature = "orchard")]
    use {crate::wallet::orchard::tests::OrchardPoolTester, orchard::tree::MerkleHashOrchard};

    #[test]
    fn sapling_scan_complete() {
        scan_complete::<SaplingPoolTester>();
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn orchard_scan_complete() {
        scan_complete::<OrchardPoolTester>();
    }

    fn scan_complete<T: ShieldedPoolTester>() {
        use ScanPriority::*;

        // We'll start inserting leaf notes 5 notes after the end of the third subtree, with a gap
        // of 10 blocks. After `scan_cached_blocks`, the scan queue should have a requested scan
        // range of 300..310 with `FoundNote` priority, 310..320 with `Scanned` priority.
        // We set both Sapling and Orchard to the same initial tree size for simplicity.
        let prior_block_hash = BlockHash([0; 32]);
        let initial_sapling_tree_size: u32 = (0x1 << 16) * 3 + 5;
        let initial_orchard_tree_size: u32 = (0x1 << 16) * 3 + 5;
        let initial_height_offset = 310;

        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_initial_chain_state(|rng, network| {
                let sapling_activation_height =
                    network.activation_height(NetworkUpgrade::Sapling).unwrap();
                // Construct a fake chain state for the end of block 300
                let (prior_sapling_roots, sapling_initial_tree) =
                    Frontier::random_with_prior_subtree_roots(
                        rng,
                        initial_sapling_tree_size.into(),
                        NonZeroU8::new(16).unwrap(),
                    );
                let prior_sapling_roots = prior_sapling_roots
                    .into_iter()
                    .zip(1u32..)
                    .map(|(root, i)| {
                        CommitmentTreeRoot::from_parts(sapling_activation_height + (100 * i), root)
                    })
                    .collect::<Vec<_>>();

                #[cfg(feature = "orchard")]
                let (prior_orchard_roots, orchard_initial_tree) =
                    Frontier::random_with_prior_subtree_roots(
                        rng,
                        initial_orchard_tree_size.into(),
                        NonZeroU8::new(16).unwrap(),
                    );
                #[cfg(feature = "orchard")]
                let prior_orchard_roots = prior_orchard_roots
                    .into_iter()
                    .zip(1u32..)
                    .map(|(root, i)| {
                        CommitmentTreeRoot::from_parts(sapling_activation_height + (100 * i), root)
                    })
                    .collect::<Vec<_>>();

                InitialChainState {
                    chain_state: ChainState::new(
                        sapling_activation_height + initial_height_offset - 1,
                        prior_block_hash,
                        sapling_initial_tree,
                        #[cfg(feature = "orchard")]
                        orchard_initial_tree,
                    ),
                    prior_sapling_roots,
                    #[cfg(feature = "orchard")]
                    prior_orchard_roots,
                }
            })
            .with_account_from_sapling_activation(BlockHash([3; 32]))
            .build();

        let sapling_activation_height = st.sapling_activation_height();

        let dfvk = T::test_account_fvk(&st);
        let value = NonNegativeAmount::const_from_u64(50000);
        let initial_height = sapling_activation_height + initial_height_offset;
        st.generate_block_at(
            initial_height,
            prior_block_hash,
            &dfvk,
            AddressType::DefaultExternal,
            value,
            initial_sapling_tree_size,
            initial_orchard_tree_size,
            false,
        );

        for _ in 1..=10 {
            st.generate_next_block(
                &dfvk,
                AddressType::DefaultExternal,
                NonNegativeAmount::const_from_u64(10000),
            );
        }

        st.scan_cached_blocks(initial_height, 10);

        // Verify the that adjacent range needed to make the note spendable has been prioritized.
        let sap_active = u32::from(sapling_activation_height);
        assert_matches!(
            st.wallet().suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 300)..(sap_active + 310), FoundNote)
            ]
        );

        // Check that the scanned range has been properly persisted.
        assert_matches!(
            suggest_scan_ranges(&st.wallet().conn, Scanned),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 300)..(sap_active + 310), FoundNote),
                scan_range((sap_active + 310)..(sap_active + 320), Scanned)
            ]
        );

        // Simulate the wallet going offline for a bit, update the chain tip to 20 blocks in the
        // future.
        assert_matches!(
            st.wallet_mut()
                .update_chain_tip(sapling_activation_height + 340),
            Ok(())
        );

        // Check the scan range again, we should see a `ChainTip` range for the period we've been
        // offline.
        assert_matches!(
            st.wallet().suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 320)..(sap_active + 341), ChainTip),
                scan_range((sap_active + 300)..(sap_active + 310), ChainTip)
            ]
        );

        // Now simulate a jump ahead more than 100 blocks.
        assert_matches!(
            st.wallet_mut()
                .update_chain_tip(sapling_activation_height + 450),
            Ok(())
        );

        // Check the scan range again, we should see a `Validate` range for the previous wallet
        // tip, and then a `ChainTip` for the remaining range.
        assert_matches!(
            st.wallet().suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 320)..(sap_active + 330), Verify),
                scan_range((sap_active + 330)..(sap_active + 451), ChainTip),
                scan_range((sap_active + 300)..(sap_active + 310), ChainTip)
            ]
        );

        // The wallet summary should be requesting the second-to-last root, as the last
        // shard is incomplete.
        assert_eq!(
            st.wallet()
                .get_wallet_summary(0)
                .unwrap()
                .map(|s| T::next_subtree_index(&s)),
            Some(2),
        );
    }

    pub(crate) fn test_with_nu5_birthday_offset<T: ShieldedPoolTester>(
        birthday_offset: u32,
        prior_block_hash: BlockHash,
    ) -> (TestState<BlockCache>, T::Fvk, AccountBirthday, u32) {
        let st = TestBuilder::new()
            .with_block_cache()
            .with_account_birthday(|rng, network, initial_chain_state| {
                // We're constructing the birthday without adding any chain data.
                assert!(initial_chain_state.is_none());

                // We set the Sapling and Orchard frontiers at the birthday height to be
                // 1234 notes into the second shard.
                let frontier_position = Position::from((0x1 << 16) + 1234);
                let birthday_height =
                    network.activation_height(NetworkUpgrade::Nu5).unwrap() + birthday_offset;

                // Construct a fake chain state for the end of the block with the given
                // birthday_offset from the Nu5 birthday.
                let (_, sapling_initial_tree) = Frontier::random_with_prior_subtree_roots(
                    rng,
                    (frontier_position + 1).into(),
                    NonZeroU8::new(16).unwrap(),
                );
                #[cfg(feature = "orchard")]
                let (_, orchard_initial_tree) = Frontier::random_with_prior_subtree_roots(
                    rng,
                    (frontier_position + 1).into(),
                    NonZeroU8::new(16).unwrap(),
                );

                AccountBirthday::from_parts(
                    ChainState::new(
                        birthday_height,
                        prior_block_hash,
                        sapling_initial_tree,
                        #[cfg(feature = "orchard")]
                        orchard_initial_tree,
                    ),
                    None,
                )
            })
            .build();

        let birthday = st.test_account().unwrap().birthday().clone();
        let dfvk = T::test_account_fvk(&st);
        let sap_active = st.sapling_activation_height();

        (st, dfvk, birthday, sap_active.into())
    }

    #[test]
    fn sapling_create_account_creates_ignored_range() {
        create_account_creates_ignored_range::<SaplingPoolTester>();
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn orchard_create_account_creates_ignored_range() {
        create_account_creates_ignored_range::<OrchardPoolTester>();
    }

    fn create_account_creates_ignored_range<T: ShieldedPoolTester>() {
        use ScanPriority::*;

        // Use a non-zero birthday offset because Sapling and NU5 are activated at the same height.
        let (st, _, birthday, sap_active) =
            test_with_nu5_birthday_offset::<T>(76, BlockHash([0; 32]));
        let birthday_height = birthday.height().into();

        let expected = vec![
            // The range up to the wallet's birthday height is ignored.
            scan_range(sap_active..birthday_height, Ignored),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn update_chain_tip_before_create_account() {
        use ScanPriority::*;

        let mut st = TestBuilder::new().with_block_cache().build();
        let sap_active = st.sapling_activation_height();

        // Update the chain tip.
        let new_tip = sap_active + 1000;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();
        let chain_end = u32::from(new_tip + 1);

        let expected = vec![
            // The range up to the chain end is ignored.
            scan_range(sap_active.into()..chain_end, Ignored),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Now add an account.
        let wallet_birthday = sap_active + 500;
        st.wallet_mut()
            .create_account(
                &SecretVec::new(vec![0; 32]),
                &AccountBirthday::from_parts(
                    ChainState::empty(wallet_birthday - 1, BlockHash([0; 32])),
                    None,
                ),
            )
            .unwrap();

        let expected = vec![
            // The account's birthday onward is marked for recovery.
            scan_range(wallet_birthday.into()..chain_end, Historic),
            // The range up to the wallet's birthday height is ignored.
            scan_range(sap_active.into()..wallet_birthday.into(), Ignored),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn sapling_update_chain_tip_with_no_subtree_roots() {
        update_chain_tip_with_no_subtree_roots::<SaplingPoolTester>();
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn orchard_update_chain_tip_with_no_subtree_roots() {
        update_chain_tip_with_no_subtree_roots::<OrchardPoolTester>();
    }

    fn update_chain_tip_with_no_subtree_roots<T: ShieldedPoolTester>() {
        use ScanPriority::*;

        // Use a non-zero birthday offset because Sapling and NU5 are activated at the same height.
        let (mut st, _, birthday, sap_active) =
            test_with_nu5_birthday_offset::<T>(76, BlockHash([0; 32]));

        // Set up the following situation:
        //
        //   prior_tip      new_tip
        //       |<--- 500 --->|
        // wallet_birthday
        let prior_tip = birthday.height();
        let wallet_birthday = birthday.height().into();

        // Update the chain tip.
        let new_tip = prior_tip + 500;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();
        let chain_end = u32::from(new_tip + 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            // The wallet's birthday onward is marked for recovery. Because we don't
            // yet have any chain state, it is marked with `Historic` priority rather
            // than `ChainTip`.
            scan_range(wallet_birthday..chain_end, Historic),
            // The range below the wallet's birthday height is ignored.
            scan_range(sap_active..wallet_birthday, Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn sapling_update_chain_tip_when_never_scanned() {
        update_chain_tip_when_never_scanned::<SaplingPoolTester>();
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn orchard_update_chain_tip_when_never_scanned() {
        update_chain_tip_when_never_scanned::<OrchardPoolTester>();
    }

    fn update_chain_tip_when_never_scanned<T: ShieldedPoolTester>() {
        use ScanPriority::*;

        // Use a non-zero birthday offset because Sapling and NU5 are activated at the same height.
        let (mut st, _, birthday, sap_active) =
            test_with_nu5_birthday_offset::<T>(76, BlockHash([0; 32]));

        // Set up the following situation:
        //
        // last_shard_start      prior_tip      new_tip
        //        |<----- 1000 ----->|<--- 500 --->|
        //                    wallet_birthday
        let prior_tip_height = birthday.height();

        // Set up some shard root history before the wallet birthday.
        let last_shard_start = birthday.height() - 1000;
        T::put_subtree_roots(
            &mut st,
            0,
            &[CommitmentTreeRoot::from_parts(
                last_shard_start,
                // fake a hash, the value doesn't matter
                T::empty_tree_leaf(),
            )],
        )
        .unwrap();

        // Update the chain tip.
        let tip_height = prior_tip_height + 500;
        st.wallet_mut().update_chain_tip(tip_height).unwrap();
        let chain_end = u32::from(tip_height + 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            // The last (incomplete) shard's range starting from the wallet birthday is
            // marked for catching up to the chain tip, to ensure that if any notes are
            // discovered after the wallet's birthday, they will be spendable.
            scan_range(birthday.height().into()..chain_end, ChainTip),
            // The range below the birthday height is ignored.
            scan_range(sap_active..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn sapling_update_chain_tip_unstable_max_scanned() {
        update_chain_tip_unstable_max_scanned::<SaplingPoolTester>();
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn orchard_update_chain_tip_unstable_max_scanned() {
        update_chain_tip_unstable_max_scanned::<OrchardPoolTester>();
    }

    fn update_chain_tip_unstable_max_scanned<T: ShieldedPoolTester>() {
        use ScanPriority::*;
        // Set up the following situation:
        //
        //                                                prior_tip           new_tip
        //        |<------- 10 ------->|<--- 500 --->|<- 40 ->|<-- 70 -->|<- 20 ->|
        // initial_shard_end    wallet_birthday  max_scanned     last_shard_start
        //
        let birthday_offset = 76;
        let birthday_prior_block_hash = BlockHash([0; 32]);
        // We set the Sapling and Orchard frontiers at the birthday block initial state to 1234
        // notes beyond the end of the first shard.
        let frontier_tree_size: u32 = (0x1 << 16) + 1234;
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_initial_chain_state(|rng, network| {
                let birthday_height =
                    network.activation_height(NetworkUpgrade::Nu5).unwrap() + birthday_offset;

                // Construct a fake chain state for the end of the block with the given
                // birthday_offset from the Nu5 birthday.
                let (prior_sapling_roots, sapling_initial_tree) =
                    Frontier::random_with_prior_subtree_roots(
                        rng,
                        frontier_tree_size.into(),
                        NonZeroU8::new(16).unwrap(),
                    );
                // There will only be one prior root
                let prior_sapling_roots = prior_sapling_roots
                    .into_iter()
                    .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 10, root))
                    .collect::<Vec<_>>();

                #[cfg(feature = "orchard")]
                let (prior_orchard_roots, orchard_initial_tree) =
                    Frontier::random_with_prior_subtree_roots(
                        rng,
                        frontier_tree_size.into(),
                        NonZeroU8::new(16).unwrap(),
                    );
                // There will only be one prior root
                #[cfg(feature = "orchard")]
                let prior_orchard_roots = prior_orchard_roots
                    .into_iter()
                    .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 10, root))
                    .collect::<Vec<_>>();

                InitialChainState {
                    chain_state: ChainState::new(
                        birthday_height - 1,
                        birthday_prior_block_hash,
                        sapling_initial_tree,
                        #[cfg(feature = "orchard")]
                        orchard_initial_tree,
                    ),
                    prior_sapling_roots,
                    #[cfg(feature = "orchard")]
                    prior_orchard_roots,
                }
            })
            .with_account_having_current_birthday()
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = T::test_account_fvk(&st);
        let sap_active = st.sapling_activation_height();
        let max_scanned = account.birthday().height() + 500;

        // Set up prior chain state. This simulates us having imported a wallet
        // with a birthday 520 blocks below the chain tip.
        let prior_tip = max_scanned + 40;
        st.wallet_mut().update_chain_tip(prior_tip).unwrap();

        let pre_birthday_range = scan_range(
            sap_active.into()..account.birthday().height().into(),
            Ignored,
        );

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            scan_range(
                account.birthday().height().into()..(prior_tip + 1).into(),
                ChainTip,
            ),
            pre_birthday_range.clone(),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Simulate that in the blocks between the wallet birthday and the max_scanned height,
        // there are 10 Sapling notes and 10 Orchard notes created on the chain.
        st.generate_block_at(
            max_scanned,
            BlockHash([1u8; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            // 1235 notes into into the second shard
            NonNegativeAmount::const_from_u64(10000),
            frontier_tree_size + 10,
            frontier_tree_size + 10,
            false,
        );
        st.scan_cached_blocks(max_scanned, 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            scan_range((max_scanned + 1).into()..(prior_tip + 1).into(), ChainTip),
            scan_range(
                account.birthday().height().into()..max_scanned.into(),
                ChainTip,
            ),
            scan_range(max_scanned.into()..(max_scanned + 1).into(), Scanned),
            pre_birthday_range.clone(),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Now simulate shutting down, and then restarting 90 blocks later, after a shard
        // has been completed. We have to update both trees, because otherwise we will pick the
        // lesser of the tip shard start heights as where we must scan from.
        let last_shard_start = prior_tip + 70;
        st.put_subtree_roots(
            1,
            &[CommitmentTreeRoot::from_parts(
                last_shard_start,
                // fake a hash, the value doesn't matter
                sapling::Node::empty_leaf(),
            )],
            #[cfg(feature = "orchard")]
            1,
            #[cfg(feature = "orchard")]
            &[CommitmentTreeRoot::from_parts(
                last_shard_start,
                // fake a hash, the value doesn't matter
                MerkleHashOrchard::empty_leaf(),
            )],
        )
        .unwrap();

        // Just inserting the subtree roots doesn't affect the scan ranges.
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        let new_tip = last_shard_start + 20;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();

        // Verify that the suggested scan ranges match what is expected
        let expected = vec![
            // The max scanned block's connectivity is verified by scanning the next 10 blocks.
            scan_range(
                (max_scanned + 1).into()..(max_scanned + 1 + VERIFY_LOOKAHEAD).into(),
                Verify,
            ),
            // The last shard needs to catch up to the chain tip in order to make notes spendable.
            scan_range(last_shard_start.into()..u32::from(new_tip + 1), ChainTip),
            // The range between the verification blocks and the prior tip is still in the queue.
            scan_range(
                (max_scanned + 1 + VERIFY_LOOKAHEAD).into()..(prior_tip + 1).into(),
                ChainTip,
            ),
            // The remainder of the second-to-last shard's range is still in the queue.
            scan_range(
                account.birthday().height().into()..max_scanned.into(),
                ChainTip,
            ),
            // The gap between the prior tip and the last shard is deferred as low priority.
            scan_range((prior_tip + 1).into()..last_shard_start.into(), Historic),
            // The max scanned block itself is left as-is.
            scan_range(max_scanned.into()..(max_scanned + 1).into(), Scanned),
            // The range below the second-to-last shard is ignored.
            pre_birthday_range,
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn sapling_update_chain_tip_stable_max_scanned() {
        update_chain_tip_stable_max_scanned::<SaplingPoolTester>();
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn orchard_update_chain_tip_stable_max_scanned() {
        update_chain_tip_stable_max_scanned::<OrchardPoolTester>();
    }

    fn update_chain_tip_stable_max_scanned<T: ShieldedPoolTester>() {
        use ScanPriority::*;

        // Set up the following situation:
        //
        //                            prior_tip           new_tip
        //        |<--- 500 --->|<- 20 ->|<-- 50 -->|<- 20 ->|
        // wallet_birthday  max_scanned     last_shard_start
        //
        let birthday_offset = 76;
        let birthday_prior_block_hash = BlockHash([0; 32]);
        // We set the Sapling and Orchard frontiers at the birthday block initial state to 1234
        // notes beyond the end of the first shard.
        let frontier_tree_size: u32 = (0x1 << 16) + 1234;
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_initial_chain_state(|rng, network| {
                let birthday_height =
                    network.activation_height(NetworkUpgrade::Nu5).unwrap() + birthday_offset;

                // Construct a fake chain state for the end of the block with the given
                // birthday_offset from the Nu5 birthday.
                let (prior_sapling_roots, sapling_initial_tree) =
                    Frontier::random_with_prior_subtree_roots(
                        rng,
                        frontier_tree_size.into(),
                        NonZeroU8::new(16).unwrap(),
                    );
                // There will only be one prior root
                let prior_sapling_roots = prior_sapling_roots
                    .into_iter()
                    .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 10, root))
                    .collect::<Vec<_>>();

                #[cfg(feature = "orchard")]
                let (prior_orchard_roots, orchard_initial_tree) =
                    Frontier::random_with_prior_subtree_roots(
                        rng,
                        frontier_tree_size.into(),
                        NonZeroU8::new(16).unwrap(),
                    );
                // There will only be one prior root
                #[cfg(feature = "orchard")]
                let prior_orchard_roots = prior_orchard_roots
                    .into_iter()
                    .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 10, root))
                    .collect::<Vec<_>>();

                InitialChainState {
                    chain_state: ChainState::new(
                        birthday_height - 1,
                        birthday_prior_block_hash,
                        sapling_initial_tree,
                        #[cfg(feature = "orchard")]
                        orchard_initial_tree,
                    ),
                    prior_sapling_roots,
                    #[cfg(feature = "orchard")]
                    prior_orchard_roots,
                }
            })
            .with_account_having_current_birthday()
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = T::test_account_fvk(&st);
        let birthday = account.birthday();
        let sap_active = st.sapling_activation_height();

        // We have scan ranges and a subtree, but have scanned no blocks.
        let summary = st.get_wallet_summary(1);
        assert_eq!(summary.and_then(|s| s.scan_progress()), None);

        // Set up prior chain state. This simulates us having imported a wallet
        // with a birthday 520 blocks below the chain tip.
        let max_scanned = birthday.height() + 500;
        let prior_tip = max_scanned + 20;
        st.wallet_mut().update_chain_tip(prior_tip).unwrap();

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            scan_range(birthday.height().into()..(prior_tip + 1).into(), ChainTip),
            scan_range(sap_active.into()..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Simulate that in the blocks between the wallet birthday and the max_scanned height,
        // there are 10 Sapling notes and 10 Orchard notes created on the chain.
        st.generate_block_at(
            max_scanned,
            BlockHash([1; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            NonNegativeAmount::const_from_u64(10000),
            frontier_tree_size + 10,
            frontier_tree_size + 10,
            false,
        );
        st.scan_cached_blocks(max_scanned, 1);

        // We have scanned a block, so we now have a starting tree position, 500 blocks above the
        // wallet birthday but before the end of the shard.
        let summary = st.get_wallet_summary(1);
        assert_eq!(summary.as_ref().map(|s| T::next_subtree_index(s)), Some(0));

        // Progress denominator depends on which pools are enabled (which changes the
        // initial tree states). Here we compute the denominator based upon the fact that
        // the trees are the same size at present.
        let expected_denom = (1 << SAPLING_SHARD_HEIGHT) * 2 - frontier_tree_size;
        #[cfg(feature = "orchard")]
        let expected_denom = expected_denom * 2;
        assert_eq!(
            summary.and_then(|s| s.scan_progress()),
            Some(Ratio::new(1, u64::from(expected_denom)))
        );

        // Now simulate shutting down, and then restarting 70 blocks later, after a shard
        // has been completed in one pool. This shard will have index 2, as our birthday
        // was in shard 1.
        let last_shard_start = prior_tip + 50;
        T::put_subtree_roots(
            &mut st,
            2,
            &[CommitmentTreeRoot::from_parts(
                last_shard_start,
                // fake a hash, the value doesn't matter
                T::empty_tree_leaf(),
            )],
        )
        .unwrap();

        {
            let mut shard_stmt = st
                .wallet_mut()
                .conn
                .prepare("SELECT shard_index, subtree_end_height FROM sapling_tree_shards")
                .unwrap();
            (shard_stmt
                .query_and_then::<_, rusqlite::Error, _, _>([], |row| {
                    Ok((row.get::<_, u32>(0)?, row.get::<_, Option<u32>>(1)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>())
            .unwrap();
        }

        {
            let mut shard_stmt = st
                .wallet_mut()
                .conn
                .prepare("SELECT shard_index, subtree_end_height FROM orchard_tree_shards")
                .unwrap();
            (shard_stmt
                .query_and_then::<_, rusqlite::Error, _, _>([], |row| {
                    Ok((row.get::<_, u32>(0)?, row.get::<_, Option<u32>>(1)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>())
            .unwrap();
        }

        let new_tip = last_shard_start + 20;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();
        let chain_end = u32::from(new_tip + 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            // The blocks after the max scanned block up to the chain tip are prioritised.
            scan_range((max_scanned + 1).into()..chain_end, ChainTip),
            // The remainder of the second-to-last shard's range is still in the queue.
            scan_range(birthday.height().into()..max_scanned.into(), ChainTip),
            // The max scanned block itself is left as-is.
            scan_range(max_scanned.into()..(max_scanned + 1).into(), Scanned),
            // The range below the second-to-last shard is ignored.
            scan_range(sap_active.into()..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // We've crossed a subtree boundary, but only in one pool. We still only have one scanned
        // note but in the pool where we crossed the subtree boundary we have two shards worth of
        // notes to scan.
        let expected_denom = expected_denom + (1 << 16);
        let summary = st.get_wallet_summary(1);
        assert_eq!(
            summary.and_then(|s| s.scan_progress()),
            Some(Ratio::new(1, u64::from(expected_denom)))
        );
    }

    #[test]
    fn replace_queue_entries_merges_previous_range() {
        use ScanPriority::*;

        let mut st = TestBuilder::new().build();

        let ranges = vec![
            scan_range(150..200, ChainTip),
            scan_range(100..150, Scanned),
            scan_range(0..100, Ignored),
        ];

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            insert_queue_entries(&tx, ranges.iter()).unwrap();
            tx.commit().unwrap();
        }

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, ranges);

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            replace_queue_entries::<SqliteClientError>(
                &tx,
                &(BlockHeight::from(150)..BlockHeight::from(160)),
                vec![scan_range(150..160, Scanned)].into_iter(),
                false,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let expected = vec![
            scan_range(160..200, ChainTip),
            scan_range(100..160, Scanned),
            scan_range(0..100, Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn replace_queue_entries_merges_subsequent_range() {
        use ScanPriority::*;

        let mut st = TestBuilder::new().build();

        let ranges = vec![
            scan_range(150..200, ChainTip),
            scan_range(100..150, Scanned),
            scan_range(0..100, Ignored),
        ];

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            insert_queue_entries(&tx, ranges.iter()).unwrap();
            tx.commit().unwrap();
        }

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, ranges);

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            replace_queue_entries::<SqliteClientError>(
                &tx,
                &(BlockHeight::from(90)..BlockHeight::from(100)),
                vec![scan_range(90..100, Scanned)].into_iter(),
                false,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let expected = vec![
            scan_range(150..200, ChainTip),
            scan_range(90..150, Scanned),
            scan_range(0..90, Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }
}
