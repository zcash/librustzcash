use std::cmp;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, NetworkUpgrade},
    merkle_tree::CommitmentTree,
};

use crate::{
    data_api::{
        error::{ChainInvalid, Error},
        CacheOps, DBOps, DBUpdate,
    },
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, WalletTx},
    welding_rig::scan_block,
};

pub const ANCHOR_OFFSET: u32 = 10;

/// Checks that the scanned blocks in the data database, when combined with the recent
/// `CompactBlock`s in the cache database, form a valid chain.
///
/// This function is built on the core assumption that the information provided in the
/// cache database is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// Returns:
/// - `Ok(())` if the combined chain is valid.
/// - `Err(ErrorKind::InvalidChain(upper_bound, cause))` if the combined chain is invalid.
///   `upper_bound` is the height of the highest invalid block (on the assumption that the
///   highest block in the cache database is correct).
/// - `Err(e)` if there was an error during validation unrelated to chain validity.
///
/// This function does not mutate either of the databases.
pub fn validate_combined_chain<'db, E0, N, E, P, C, D>(
    parameters: &P,
    cache: &C,
    data: &'db D,
) -> Result<(), E>
where
    E: From<Error<E0, N>>,
    P: consensus::Parameters,
    C: CacheOps<Error = E>,
    &'db D: DBOps<Error = E>,
{
    let sapling_activation_height = parameters
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(Error::SaplingNotActive)?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height to select all cached CompactBlocks.
    let data_max_height = data.block_height_extrema()?.map(|(_, max)| max);

    // The cache will contain blocks above the maximum height of data in the database;
    // validate from that maximum height up to the chain tip, returning the
    // hash of the block at data_max_height
    let from_height = data_max_height.unwrap_or(sapling_activation_height - 1);
    let cached_hash_opt = cache.validate_chain(from_height, |top_block, next_block| {
        if next_block.height() != top_block.height() - 1 {
            Err(
                ChainInvalid::block_height_mismatch(top_block.height() - 1, next_block.height())
                    .into(),
            )
        } else if next_block.hash() != top_block.prev_hash() {
            Err(ChainInvalid::prev_hash_mismatch(next_block.height()).into())
        } else {
            Ok(())
        }
    })?;

    match (cached_hash_opt, data_max_height) {
        (Some(cached_hash), Some(h)) => match data.get_block_hash(h)? {
            Some(data_scan_max_hash) => {
                if cached_hash == data_scan_max_hash {
                    Ok(())
                } else {
                    Err(ChainInvalid::prev_hash_mismatch(h).into())
                }
            }
            None => Err(Error::CorruptedData(
                "No block hash available for block at maximum chain height.",
            )
            .into()),
        },
        _ => {
            // No cached blocks are present, or the max data height is absent, this is fine.
            Ok(())
        }
    }
}

/// Determines the target height for a transaction, and the height from which to
/// select anchors, based on the current synchronised block chain.
pub fn get_target_and_anchor_heights<'db, E0, N, E, D>(
    data: &'db D,
) -> Result<(BlockHeight, BlockHeight), E>
where
    E: From<Error<E0, N>>,
    &'db D: DBOps<Error = E>,
{
    data.block_height_extrema().and_then(|heights| {
        match heights {
            Some((min_height, max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = BlockHeight::from(cmp::max(
                    u32::from(target_height).saturating_sub(ANCHOR_OFFSET),
                    u32::from(min_height),
                ));

                Ok((target_height, anchor_height))
            }
            None => Err(Error::ScanRequired.into()),
        }
    })
}

/// Scans at most `limit` new blocks added to the cache for any transactions received by
/// the tracked accounts.
///
/// This function will return without error after scanning at most `limit` new blocks, to
/// enable the caller to update their UI with scanning progress. Repeatedly calling this
/// function will process sequential ranges of blocks, and is equivalent to calling
/// `scan_cached_blocks` and passing `None` for the optional `limit` value.
///
/// This function pays attention only to cached blocks with heights greater than the
/// highest scanned block in `db_data`. Cached blocks with lower heights are not verified
/// against previously-scanned blocks. In particular, this function **assumes** that the
/// caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be returned with kind [`ChainInvalid::HeightMismatch`].
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{
///     Network,
///     Parameters,
/// };
/// use zcash_client_backend::{
///     data_api::chain::scan_cached_blocks,
/// };
/// use zcash_client_sqlite::{
///     CacheConnection,
///     DataConnection,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let cache = CacheConnection::for_path(cache_file).unwrap();
/// let data_file = NamedTempFile::new().unwrap();
/// let data = DataConnection::for_path(data_file).unwrap();
/// scan_cached_blocks(&Network::TestNetwork, &cache, &data, None);
/// ```
///
/// [`init_blocks_table`]: crate::init::init_blocks_table
pub fn scan_cached_blocks<'db, E, E0, N, P, C, D>(
    params: &P,
    cache: &C,
    data: &'db D,
    limit: Option<u32>,
) -> Result<(), E>
where
    P: consensus::Parameters,
    C: CacheOps<Error = E>,
    &'db D: DBOps<Error = E, NoteRef = N>,
    N: Copy,
    E: From<Error<E0, N>>,
{
    let sapling_activation_height = params
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(Error::SaplingNotActive)?;

    // Recall where we synced up to previously.
    // If we have never synced, use sapling activation height to select all cached CompactBlocks.
    let mut last_height = data.block_height_extrema().map(|opt| {
        opt.map(|(_, max)| max)
            .unwrap_or(sapling_activation_height - 1)
    })?;

    // Raise SQL errors from the query, IO errors from parsing, and incorrect HRP errors.
    let extfvks = data.get_extended_full_viewing_keys(params)?;

    // Get the most recent CommitmentTree
    let mut tree = data
        .get_commitment_tree(last_height)
        .map(|t| t.unwrap_or(CommitmentTree::new()))?;

    // Get most recent incremental witnesses for the notes we are tracking
    let mut witnesses = data.get_witnesses(last_height)?;

    // Get the nullifiers for the notes we are tracking
    let mut nullifiers = data.get_nullifiers()?;

    cache.with_cached_blocks(
        last_height,
        limit,
        |height: BlockHeight, block: CompactBlock| {
            // Scanned blocks MUST be height-sequential.
            if height != (last_height + 1) {
                return Err(ChainInvalid::block_height_mismatch(last_height + 1, height).into());
            }
            last_height = height;

            let block_hash = BlockHash::from_slice(&block.hash);
            let block_time = block.time;

            let txs: Vec<WalletTx> = {
                let nf_refs: Vec<_> = nullifiers
                    .iter()
                    .map(|(nf, acc)| (&nf[..], acc.0 as usize))
                    .collect();
                let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.1).collect();
                scan_block(
                    params,
                    block,
                    &extfvks[..],
                    &nf_refs,
                    &mut tree,
                    &mut witness_refs[..],
                )
            };

            // Enforce that all roots match. This is slow, so only include in debug builds.
            #[cfg(debug_assertions)]
            {
                let cur_root = tree.root();
                for row in &witnesses {
                    if row.1.root() != cur_root {
                        return Err(Error::InvalidWitnessAnchor(row.0, last_height).into());
                    }
                }
                for tx in &txs {
                    for output in tx.shielded_outputs.iter() {
                        if output.witness.root() != cur_root {
                            return Err(Error::InvalidNewWitnessAnchor(
                                output.index,
                                tx.txid,
                                last_height,
                                output.witness.root(),
                            )
                            .into());
                        }
                    }
                }
            }

            // database updates for each block are transactional
            data.transactionally(&mut data.get_update_ops()?, |db_update| {
                // Insert the block into the database.
                db_update.insert_block(height, block_hash, block_time, &tree)?;

                for tx in txs {
                    let tx_row = db_update.put_tx_meta(&tx, height)?;

                    // Mark notes as spent and remove them from the scanning cache
                    for spend in &tx.shielded_spends {
                        db_update.mark_spent(tx_row, &spend.nf)?;
                    }

                    nullifiers.retain(|(nf, _acc)| {
                        tx.shielded_spends
                            .iter()
                            .find(|spend| &spend.nf == nf)
                            .is_none()
                    });

                    for output in tx.shielded_outputs {
                        let nf = output.note.nf(
                            &extfvks[output.account].fvk.vk,
                            output.witness.position() as u64,
                        );

                        let note_id = db_update.put_received_note(&output, Some(&nf), tx_row)?;

                        // Save witness for note.
                        witnesses.push((note_id, output.witness));

                        // Cache nullifier for note (to detect subsequent spends in this scan).
                        nullifiers.push((nf, AccountId(output.account as u32)));
                    }
                }

                // Insert current witnesses into the database.
                for (note_id, witness) in witnesses.iter() {
                    db_update.insert_witness(*note_id, witness, last_height)?;
                }

                // Prune the stored witnesses (we only expect rollbacks of at most 100 blocks).
                db_update.prune_witnesses(last_height - 100)?;

                // Update now-expired transactions that didn't get mined.
                db_update.update_expired_notes(last_height)?;

                Ok(())
            })
        },
    )?;

    Ok(())
}
