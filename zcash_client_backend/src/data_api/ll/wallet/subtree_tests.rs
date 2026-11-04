use std::collections::BTreeMap;

use incrementalmerkletree::{Hashable, Marking, Position, Retention};
use proptest::prelude::*;
use shardtree::{
    ShardTree,
    store::{ShardStore, memory::MemoryShardStore},
    testing::arb_leaves_sized,
};
use zcash_protocol::consensus::BlockHeight;

use super::build_subtrees;

/// Small trees exercise shard boundaries without expensive production-sized fixtures.
const TREE_DEPTH: u8 = 8;
const SHARD_HEIGHT: u8 = 4;
/// Keep pruning active while retaining the first checkpoint independently.
const MAX_CHECKPOINTS: usize = 4;
/// Full chunks are smaller than a shard, as in the scanning path.
const CHUNK_SIZE: usize = 8;

type TestTree<H> = ShardTree<MemoryShardStore<H, BlockHeight>, TREE_DEPTH, SHARD_HEIGHT>;

fn checkpoints<H: Hashable + Clone + PartialEq>(
    tree: &TestTree<H>,
) -> BTreeMap<BlockHeight, Position> {
    let mut checkpoints = BTreeMap::new();
    tree.store()
        .for_each_checkpoint(usize::MAX, |id, checkpoint| {
            checkpoints.insert(*id, checkpoint.position().unwrap());
            Ok(())
        })
        .unwrap();
    checkpoints
}

fn assert_trees_match<H: Hashable + Clone + PartialEq>(
    actual: &TestTree<H>,
    expected: &TestTree<H>,
) {
    let checkpoints = checkpoints(expected);
    assert_eq!(self::checkpoints(actual), checkpoints);
    let marked = expected.marked_positions().unwrap();
    assert_eq!(actual.marked_positions().unwrap(), marked);
    assert_eq!(
        actual.max_leaf_position(None).unwrap(),
        expected.max_leaf_position(None).unwrap()
    );
    for (id, end) in checkpoints {
        let root = expected.root_at_checkpoint_id(&id).unwrap().unwrap();
        assert_eq!(actual.root_at_checkpoint_id(&id).unwrap().unwrap(), root);
        for position in marked.iter().copied().filter(|position| *position <= end) {
            let leaf = expected.get_marked_leaf(position).unwrap().unwrap();
            assert_eq!(actual.get_marked_leaf(position).unwrap().unwrap(), leaf);
            let witness = actual
                .witness_at_checkpoint_id(position, &id)
                .unwrap()
                .unwrap();
            let expected_witness = expected
                .witness_at_checkpoint_id(position, &id)
                .unwrap()
                .unwrap();
            assert_eq!(witness.path_elems(), expected_witness.path_elems());
            assert_eq!(witness.root(leaf), root);
        }
    }
}

fn check_insertion<H: Hashable + Clone + PartialEq + Send + Sync>(
    leaves: Vec<(H, Retention<BlockHeight>)>,
    start: usize,
    chunk_size: usize,
) {
    let mut expected = TestTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    let mut actual = TestTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    let prefix = vec![(H::empty_leaf(), Retention::Marked); start];
    for tree in [&mut actual, &mut expected] {
        tree.batch_insert(Position::from(0), prefix.clone().into_iter())
            .unwrap();
        if let Some(id) = leaves.iter().find_map(|(_, retention)| match retention {
            Retention::Checkpoint { id, .. } => Some(*id),
            _ => None,
        }) {
            tree.ensure_retained(id).unwrap();
        }
    }
    let from = Position::from(start as u64);
    expected
        .batch_insert(from, leaves.clone().into_iter())
        .unwrap();
    let mut commitments = leaves.iter().cloned().map(Some).collect::<Vec<_>>();
    for (subtree, checkpoints) in
        build_subtrees::<_, SHARD_HEIGHT>(from, &mut commitments, chunk_size)
    {
        actual.insert_tree(subtree, checkpoints).unwrap();
    }
    assert!(commitments.iter().all(Option::is_none));
    assert_trees_match(&actual, &expected);

    // Rewind to the preceding checkpoint and replay its suffix with the same chunk size.
    let checkpoints = checkpoints(&expected);
    if let Some((id, position)) = checkpoints.iter().rev().nth(1) {
        assert!(actual.truncate_to_checkpoint(id).unwrap());
        assert!(expected.truncate_to_checkpoint(id).unwrap());
        assert_trees_match(&actual, &expected);
        let next = u64::from(*position) + 1;
        let suffix = &leaves[(next as usize - start)..];
        expected
            .batch_insert(Position::from(next), suffix.iter().cloned())
            .unwrap();
        let mut commitments = suffix.iter().cloned().map(Some).collect::<Vec<_>>();
        for (subtree, checkpoints) in
            build_subtrees::<_, SHARD_HEIGHT>(Position::from(next), &mut commitments, chunk_size)
        {
            actual.insert_tree(subtree, checkpoints).unwrap();
        }
        assert_trees_match(&actual, &expected);
    }
}

#[test]
fn subtree_chunks_align_and_cache_complete_roots() {
    const START: u64 = 3;
    const LEAF_COUNT: usize = 18;
    let mut commitments = vec![Some(("a".to_string(), Retention::Marked)); LEAF_COUNT];
    let subtrees =
        build_subtrees::<_, SHARD_HEIGHT>(Position::from(START), &mut commitments, CHUNK_SIZE);
    assert_eq!(subtrees.len(), 3);
    let complete = &subtrees[1].0;
    assert_eq!(
        u64::from(complete.root_addr().position_range_start()),
        CHUNK_SIZE as u64
    );
    assert_eq!(
        u64::from(complete.root_addr().position_range_end()),
        2 * CHUNK_SIZE as u64
    );
    let root = complete
        .root_hash(complete.root_addr().position_range_end())
        .unwrap();
    assert_eq!(complete.root().node_value(), Some(&root));
    for index in [0, 2] {
        let partial = &subtrees[index].0;
        assert!(
            partial
                .root_hash(partial.root_addr().position_range_end())
                .is_err()
        );
        assert!(partial.root().node_value().is_none());
    }
    assert!(commitments.iter().all(Option::is_none));
}

#[test]
fn subtree_chunks_preserve_all_retention_kinds() {
    const LEAF_COUNT: u32 = 80;
    let leaves = (0..LEAF_COUNT)
        .map(|position| {
            let retention = match position % CHUNK_SIZE as u32 {
                0 => Retention::Marked,
                1 => Retention::Reference,
                2 => Retention::Checkpoint {
                    id: BlockHeight::from_u32(position + 1),
                    marking: Marking::Reference,
                },
                3 => Retention::Checkpoint {
                    id: BlockHeight::from_u32(position + 1),
                    marking: Marking::Marked,
                },
                7 => Retention::Checkpoint {
                    id: BlockHeight::from_u32(position + 1),
                    marking: Marking::None,
                },
                _ => Retention::Ephemeral,
            };
            (
                char::from(b'a' + (position % 26) as u8).to_string(),
                retention,
            )
        })
        .collect::<Vec<_>>();
    for start in 0..CHUNK_SIZE {
        check_insertion(leaves.clone(), start, CHUNK_SIZE);
    }
}

proptest! {
    #[test]
    fn subtree_chunks_match_sequential_insertion(
        start in 0usize..32,
        chunk_size in 1usize..33,
        leaves in arb_leaves_sized(proptest::char::range('a', 'z').prop_map(|c| c.to_string()), 160),
    ) {
        let leaves = leaves.into_iter().map(|(leaf, retention)| {
            (leaf, retention.map(|id| BlockHeight::from_u32(u32::try_from(*id).unwrap() + 1)))
        }).collect();
        check_insertion(leaves, start, chunk_size);
    }
}

#[test]
fn subtree_chunks_match_sapling_hashes() {
    const LEAF_COUNT: u64 = 40;
    let leaves = (0..LEAF_COUNT)
        .map(|position| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&position.to_le_bytes());
            let leaf = sapling::Node::from_bytes(bytes).unwrap();
            (
                leaf,
                Retention::Checkpoint {
                    id: BlockHeight::from_u32(u32::try_from(position).unwrap() + 1),
                    marking: Marking::Marked,
                },
            )
        })
        .collect();
    check_insertion(leaves, 3, CHUNK_SIZE);
}

#[cfg(feature = "orchard")]
#[test]
fn subtree_chunks_match_orchard_hashes() {
    const LEAF_COUNT: u64 = 40;
    let leaves = (0..LEAF_COUNT)
        .map(|position| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&position.to_le_bytes());
            let leaf = orchard::tree::MerkleHashOrchard::from_bytes(&bytes).unwrap();
            (
                leaf,
                Retention::Checkpoint {
                    id: BlockHeight::from_u32(u32::try_from(position).unwrap() + 1),
                    marking: Marking::Marked,
                },
            )
        })
        .collect();
    check_insertion(leaves, 3, CHUNK_SIZE);
}
