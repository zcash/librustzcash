//! Helpers for fabricating shard-tree internal structure in tests.
//!
//! Real shards in shielded pools may contain on the order of 2^16 leaves, far
//! more than is practical to construct in test fixtures. This module provides
//! a "fake-advance" operation that advances the wallet's note commitment tree
//! to a target leaf position by inserting fake subtree roots and a synthetic
//! frontier — modeling the on-chain state that would arise after pruning had
//! discarded most of a shard's interior.
//!
//! The high-level operation is [`fake_advance_to`], which inserts the stubs
//! and frontier into the wallet's tree and returns the resulting frontier.
//! The caller uses this frontier as the chain-state frontier for a subsequent
//! `scan_cached_blocks` call; the next real block's outputs land at the target
//! position and beyond.
//!
//! The pure decomposition primitive [`level_index_decomposition`] is exposed
//! independently for tests that want to manipulate stubs directly.
//!
//! [`incrementalmerkletree::frontier::Frontier::random_with_prior_subtree_roots`]
//! is the special case of [`fake_advance_to`] in which the starting state is
//! empty.

use std::collections::BTreeMap;

use incrementalmerkletree::{
    Address, Hashable, Level, Marking, Position, Retention,
    frontier::{Frontier, NonEmptyFrontier},
};
use rand::RngCore;
use shardtree::error::{InsertionError, QueryError, ShardTreeError};

use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{self, BlockHeight};

use crate::data_api::{
    WalletCommitmentTrees, WalletTest, WalletWrite,
    chain::{BlockSource, ChainState, CommitmentTreeRoot},
};

use super::{CachedBlock, TestCache, TestState, pool::ShieldedPoolTester};

/// The fixed Merkle tree depth used by both Sapling and Orchard note
/// commitment trees.
pub const NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;

/// Decomposes the half-open range `[start, end)` of leaf positions into the
/// minimal set of aligned subtree addresses that exactly cover the range,
/// capping each subtree at level `max_level`.
///
/// Each returned [`Address`] identifies a subtree at some
/// `0 <= level <= max_level` whose leaf range is contained in `[start, end)`.
/// Returned addresses are disjoint and together cover `[start, end)` exactly.
///
/// Returns an empty vector when `start >= end`.
pub fn level_index_decomposition(start: u64, end: u64, max_level: u8) -> Vec<Address> {
    let mut result = Vec::new();
    let mut pos = start;
    while pos < end {
        let alignment_level: u32 = if pos == 0 {
            u64::BITS
        } else {
            pos.trailing_zeros()
        };
        let size_level: u32 = (u64::BITS - 1) - (end - pos).leading_zeros();
        let level = alignment_level.min(size_level).min(u32::from(max_level));
        let level_u8: u8 = level as u8;
        let index = pos >> level;
        result.push(Address::from_parts(Level::from(level_u8), index));
        pos += 1u64 << level;
    }
    result
}

/// Advances the wallet's note commitment tree for pool `T` to `target_position`
/// by inserting fake subtree roots and a synthetic frontier, then registers a
/// synthetic [`CachedBlock`] at `advance_height` so the test framework's chain
/// state tracking reflects the advance.
///
/// The current chain state is read from `st.latest_cached_block()` (or treated
/// as empty if no cached block exists). The empty-state case subsumes the
/// behavior of
/// [`incrementalmerkletree::frontier::Frontier::random_with_prior_subtree_roots`].
///
/// On return, the wallet's tree has been advanced so that:
/// - The interior of the gap `[next_real_pos, target_position - 1)` is filled
///   with random stubs at the minimal aligned-subtree decomposition, with
///   shard-root-level stubs installed via `put_subtree_roots` (recording
///   `subtree_end_height = advance_height`) and lower-level stubs installed
///   directly into the shardtree.
/// - A synthetic frontier at `target_position - 1` (with a random leaf and
///   ommers consistent with the existing tree state plus the new stubs) has
///   been installed via the shardtree's frontier-insertion path.
/// - A [`CachedBlock`] at `advance_height` whose chain state holds the new
///   frontier (and the unchanged frontier of the other shielded pool) has
///   been recorded in the test framework's cache; the next
///   `generate_next_block_*` call will produce a block at
///   `advance_height + 1` whose first output lands at `target_position`.
///
/// The returned frontier is the pool-`T` frontier installed at
/// `advance_height`, suitable for direct use in test assertions.
///
/// # Errors
///
/// Returns an error if `target_position` is at or before the current frontier,
/// or if any of the underlying shardtree operations fail.
pub fn fake_advance_to<T, Cache, DbT, P>(
    st: &mut TestState<Cache, DbT, P>,
    advance_height: BlockHeight,
    advance_block_hash: BlockHash,
    target_position: u64,
    rng: &mut impl RngCore,
) -> Result<
    Frontier<T::MerkleTreeHash, NOTE_COMMITMENT_TREE_DEPTH>,
    ShardTreeError<<DbT as WalletCommitmentTrees>::Error>,
>
where
    T: ShieldedPoolTester,
    Cache: TestCache,
    <Cache::BlockSource as BlockSource>::Error: std::fmt::Debug,
    DbT: WalletTest + WalletWrite + WalletCommitmentTrees,
    P: consensus::Parameters,
    T::MerkleTreeHash: Hashable + Clone,
{
    let prior_chain_state: ChainState = st
        .latest_cached_block()
        .map(|b| b.chain_state().clone())
        .unwrap_or_else(|| ChainState::empty(advance_height - 1, BlockHash([0; 32])));

    let current_frontier = T::pool_frontier_in_chain_state(&prior_chain_state);

    let next_real_pos: u64 = current_frontier
        .value()
        .map(|f| u64::from(f.position()) + 1)
        .unwrap_or(0);

    if target_position < next_real_pos.saturating_add(1) {
        return Err(ShardTreeError::Query(QueryError::NotContained(
            Address::from_parts(Level::ZERO, target_position),
        )));
    }

    let new_frontier_pos = target_position - 1;
    let shard_height = T::SHARD_HEIGHT;

    // Decompose the gap between the current frontier and the new frontier's
    // leaf into aligned subtree stubs. Capping at the shard root level keeps
    // multi-shard stubs out of the cap (each whole-shard stub becomes its own
    // `put_subtree_roots` entry with proper `subtree_end_height` accounting).
    let stub_addrs = level_index_decomposition(next_real_pos, new_frontier_pos, shard_height);

    let mut shard_stubs: BTreeMap<u64, T::MerkleTreeHash> = BTreeMap::new();
    let mut internal_stubs: Vec<(Address, T::MerkleTreeHash)> = Vec::new();
    for addr in stub_addrs {
        let hash = T::random_subtree_hash(&mut *rng);
        if u8::from(addr.level()) == shard_height {
            shard_stubs.insert(addr.index(), hash);
        } else {
            internal_stubs.push((addr, hash));
        }
    }

    for (addr, hash) in &internal_stubs {
        T::insert_subtree_stub(st, *addr, hash.clone())?;
    }

    if !shard_stubs.is_empty() {
        let entries: Vec<(u64, T::MerkleTreeHash)> = shard_stubs.into_iter().collect();
        let mut start_index = entries[0].0;
        let mut roots: Vec<CommitmentTreeRoot<T::MerkleTreeHash>> =
            vec![CommitmentTreeRoot::from_parts(
                advance_height,
                entries[0].1.clone(),
            )];
        for (idx, hash) in &entries[1..] {
            if *idx == start_index + roots.len() as u64 {
                roots.push(CommitmentTreeRoot::from_parts(advance_height, hash.clone()));
            } else {
                T::put_subtree_roots(st, start_index, &roots)?;
                start_index = *idx;
                roots = vec![CommitmentTreeRoot::from_parts(advance_height, hash.clone())];
            }
        }
        T::put_subtree_roots(st, start_index, &roots)?;
    }

    // The new frontier's ommers are the LEFT siblings on the path from the
    // leaf to the root: at level `k`, an ommer exists exactly when bit `k` of
    // `new_frontier_pos` is set, and it covers leaf positions
    // `[(idx-1) << k, idx << k)` where `idx = new_frontier_pos >> k`. Each
    // ommer's range is now fully populated in the tree (real leaves below
    // `next_real_pos`, stubs above), so reading via `tree.root` yields a value
    // consistent with what's there.
    let mut ommers: Vec<T::MerkleTreeHash> = Vec::new();
    for level in 0..NOTE_COMMITMENT_TREE_DEPTH {
        if (new_frontier_pos >> level) & 1 == 1 {
            let sibling_index = (new_frontier_pos >> level) - 1;
            let ommer_addr = Address::from_parts(Level::from(level), sibling_index);
            let ommer_end = (sibling_index + 1) << level;
            let ommer_value = T::read_tree_root(st, ommer_addr, Position::from(ommer_end))?;
            ommers.push(ommer_value);
        }
    }

    let leaf = T::random_subtree_hash(&mut *rng);
    let nonempty = NonEmptyFrontier::from_parts(Position::from(new_frontier_pos), leaf, ommers)
        .map_err(|_| ShardTreeError::Insert(InsertionError::TreeFull))?;

    T::insert_frontier_into_tree(
        st,
        nonempty.clone(),
        Retention::Checkpoint {
            id: advance_height,
            marking: Marking::None,
        },
    )?;

    let new_frontier = Frontier::try_from(nonempty)
        .map_err(|_| ShardTreeError::Insert(InsertionError::TreeFull))?;

    let new_chain_state = T::build_chain_state_with_pool_frontier(
        advance_height,
        advance_block_hash,
        new_frontier.clone(),
        &prior_chain_state,
    );
    let sapling_end_size = new_chain_state.final_sapling_tree().tree_size() as u32;
    #[cfg(feature = "orchard")]
    let orchard_end_size = new_chain_state.final_orchard_tree().tree_size() as u32;
    #[cfg(not(feature = "orchard"))]
    let orchard_end_size = 0;
    #[cfg(feature = "orchard")]
    let ironwood_end_size = new_chain_state.final_ironwood_tree().tree_size() as u32;
    #[cfg(not(feature = "orchard"))]
    let ironwood_end_size = 0;
    let cached_block = CachedBlock::at(
        new_chain_state,
        sapling_end_size,
        orchard_end_size,
        ironwood_end_size,
    );
    st.insert_synthetic_cached_block(advance_height, cached_block);

    Ok(new_frontier)
}

#[cfg(test)]
mod tests {
    use super::level_index_decomposition;
    use incrementalmerkletree::{Address, Level};

    fn addrs(pairs: &[(u8, u64)]) -> Vec<Address> {
        pairs
            .iter()
            .map(|&(l, i)| Address::from_parts(Level::from(l), i))
            .collect()
    }

    #[test]
    fn empty_range_yields_no_addresses() {
        assert_eq!(
            level_index_decomposition(0, 0, u8::MAX),
            Vec::<Address>::new()
        );
        assert_eq!(
            level_index_decomposition(7, 7, u8::MAX),
            Vec::<Address>::new()
        );
        assert_eq!(
            level_index_decomposition(10, 5, u8::MAX),
            Vec::<Address>::new()
        );
    }

    #[test]
    fn single_leaf_yields_level_zero() {
        assert_eq!(level_index_decomposition(0, 1, u8::MAX), addrs(&[(0, 0)]));
        assert_eq!(level_index_decomposition(5, 6, u8::MAX), addrs(&[(0, 5)]));
    }

    #[test]
    fn aligned_power_of_two_collapses_to_single_address() {
        assert_eq!(level_index_decomposition(0, 8, u8::MAX), addrs(&[(3, 0)]));
        assert_eq!(level_index_decomposition(0, 16, u8::MAX), addrs(&[(4, 0)]));
        assert_eq!(level_index_decomposition(8, 16, u8::MAX), addrs(&[(3, 1)]));
    }

    #[test]
    fn aligned_start_with_non_power_of_two_size() {
        assert_eq!(
            level_index_decomposition(0, 12, u8::MAX),
            addrs(&[(3, 0), (2, 2)])
        );
    }

    #[test]
    fn unaligned_start() {
        assert_eq!(
            level_index_decomposition(2, 8, u8::MAX),
            addrs(&[(1, 1), (2, 1)])
        );
    }

    #[test]
    fn unaligned_start_and_end() {
        assert_eq!(
            level_index_decomposition(5, 16, u8::MAX),
            addrs(&[(0, 5), (1, 3), (3, 1)])
        );
    }

    #[test]
    fn max_level_caps_decomposition() {
        // Without a cap, [0, 16) collapses to a single (4, 0).
        assert_eq!(level_index_decomposition(0, 16, 4), addrs(&[(4, 0)]));
        // Capping at level 3 forces two level-3 subtrees.
        assert_eq!(
            level_index_decomposition(0, 16, 3),
            addrs(&[(3, 0), (3, 1)])
        );
        // Capping at level 2 forces four level-2 subtrees.
        assert_eq!(
            level_index_decomposition(0, 16, 2),
            addrs(&[(2, 0), (2, 1), (2, 2), (2, 3)])
        );
        // Capping at level 0 forces all leaves.
        assert_eq!(
            level_index_decomposition(0, 4, 0),
            addrs(&[(0, 0), (0, 1), (0, 2), (0, 3)])
        );
    }

    #[test]
    fn decomposition_covers_range_exactly() {
        for max_level in [0, 2, 4, u8::MAX] {
            for start in 0u64..20 {
                for end in start..40 {
                    let decomp = level_index_decomposition(start, end, max_level);
                    let total: u64 = decomp
                        .iter()
                        .map(|addr| 1u64 << u8::from(addr.level()))
                        .sum();
                    assert_eq!(
                        total,
                        end - start,
                        "[{start}, {end}) at max_level={max_level}"
                    );

                    let mut pos = start;
                    for addr in &decomp {
                        let level = u8::from(addr.level());
                        assert!(level <= max_level, "level cap violated");
                        let span = 1u64 << level;
                        assert_eq!(addr.index(), pos >> level);
                        assert_eq!(pos & (span - 1), 0);
                        pos += span;
                    }
                    assert_eq!(pos, end);
                }
            }
        }
    }
}
