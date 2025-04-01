use std::collections::HashMap;

use crate::{Entry, EntryKind, EntryLink, Error, Version};

/// Represents partially loaded tree.
///
/// Some kind of "view" into the array representation of the MMR tree.
/// With only some of the leaves/nodes pre-loaded / pre-generated.
/// Exact amount of the loaded data can be calculated by the constructing party,
/// depending on the length of the tree and maximum amount of operations that are going
/// to happen after construction. `Tree` should not be used as self-contained data structure,
/// since it's internal state can grow indefinitely after serial operations.
/// Intended use of this `Tree` is to instantiate it based on partially loaded data (see example
/// how to pick right nodes from the array representation of MMR Tree), perform several operations
/// (append-s/delete-s) and then drop it.
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(
    feature = "serde_serialization",
    serde(bound(
        serialize = "V: serde::Serialize,
                     V::NodeData: serde::Serialize,
                     Entry<V>: serde::Serialize,
                     std::collections::HashMap<u32, Entry<V>>: serde::Serialize,
                     Vec<Entry<V>>: serde::Serialize,
                     V::EntryLink: serde::Serialize",
        deserialize = "V: serde::de::DeserializeOwned,
                       V::NodeData: serde::de::DeserializeOwned,
                       Entry<V>: serde::de::DeserializeOwned,
                       std::collections::HashMap<u32, Entry<V>>: serde::de::DeserializeOwned,
                       Vec<Entry<V>>: serde::de::DeserializeOwned,
                       V::EntryLink: serde::de::DeserializeOwned",
    ))
)]
pub struct Tree<V: Version> {
    stored: HashMap<u32, Entry<V>>,

    // This can grow indefinitely if `Tree` is misused as a self-contained data structure
    generated: Vec<Entry<V>>,

    // number of persistent(!) tree entries
    stored_count: u32,

    root: V::EntryLink,
}

impl<V> Tree<V>
where
    V: Version,
    V::EntryLink: From<EntryLink> + Copy,
    V::EntryKind: From<EntryKind>,
    EntryLink: From<V::EntryLink>,
{
    /// Resolve link originated from this tree
    pub fn resolve_link(&self, link: V::EntryLink) -> Result<IndexedNode<V>, Error> {
        match EntryLink::from(link) {
            EntryLink::Generated(index) => self.generated.get(index as usize),
            EntryLink::Stored(index) => self.stored.get(&index),
        }
        .map(|node| IndexedNode { node, link })
        .ok_or(Error::ExpectedInMemory(EntryLink::from(link)))
    }

    fn push(&mut self, data: Entry<V>) -> V::EntryLink {
        let idx = self.stored_count;
        self.stored_count += 1;
        self.stored.insert(idx, data);
        V::make_stored(idx)
    }

    fn push_generated(&mut self, data: Entry<V>) -> V::EntryLink {
        self.generated.push(data);
        V::make_generated(self.generated.len() as u32 - 1)
    }

    /// Populate tree with plain list of the leaves/nodes. For now, only for tests,
    /// since this `Tree` structure is for partially loaded tree (but it might change)
    #[cfg(test)]
    pub fn populate(loaded: Vec<Entry<V>>, root: V::EntryLink) -> Self {
        let mut result = Tree::invalid();
        result.stored_count = loaded.len() as u32;
        for (idx, item) in loaded.into_iter().enumerate() {
            result.stored.insert(idx as u32, item);
        }
        result.root = root;

        result
    }

    // Empty tree with invalid root
    fn invalid() -> Self {
        Tree {
            root: V::make_generated(0),
            generated: Default::default(),
            stored: Default::default(),
            stored_count: 0,
        }
    }

    /// New view into the tree array representation
    ///
    /// `length` is total length of the array representation (is generally not a sum of
    ///     peaks.len + extra.len)
    /// `peaks` is peaks of the mmr tree
    /// `extra` is some extra nodes that calculated to be required during next one or more
    /// operations on the tree.
    ///
    /// # Panics
    ///
    /// Will panic if `peaks` is empty.
    pub fn new(length: u32, peaks: Vec<(u32, Entry<V>)>, extra: Vec<(u32, Entry<V>)>) -> Self {
        assert!(!peaks.is_empty());

        let mut result = Tree::invalid();

        result.stored_count = length;

        let mut root = V::make_stored(peaks[0].0);
        for (gen, (idx, node)) in peaks.into_iter().enumerate() {
            result.stored.insert(idx, node);
            if gen != 0 {
                let next_generated = combine_nodes(
                    result
                        .resolve_link(root)
                        .expect("Inserted before, cannot fail; qed"),
                    result
                        .resolve_link(V::make_stored(idx))
                        .expect("Inserted before, cannot fail; qed"),
                );
                root = result.push_generated(next_generated);
            }
        }

        for (idx, node) in extra {
            result.stored.insert(idx, node);
        }

        result.root = root;

        result
    }

    fn get_peaks(&self, root: V::EntryLink, target: &mut Vec<V::EntryLink>) -> Result<(), Error> {
        let (left_child_link, right_child_link) = {
            let root = self.resolve_link(root)?;
            if root.node.complete() {
                target.push(root.link);
                return Ok(());
            }
            (root.left()?, root.right()?)
        };

        self.get_peaks(left_child_link, target)?;
        self.get_peaks(right_child_link, target)?;
        Ok(())
    }

    /// Append one leaf to the tree.
    ///
    /// Returns links to actual nodes that has to be persisted as the result of the append.
    /// If completed without error, at least one link to the appended
    /// node (with metadata provided in `new_leaf`) will be returned.
    pub fn append_leaf(&mut self, new_leaf: V::NodeData) -> Result<Vec<V::EntryLink>, Error> {
        let root = self.root;
        let new_leaf_link = self.push(Entry::new_leaf(new_leaf));
        let mut appended = vec![new_leaf_link];

        let mut peaks = Vec::new();
        self.get_peaks(root, &mut peaks)?;

        let mut merge_stack = vec![new_leaf_link];

        // Scan the peaks right-to-left, merging together equal-sized adjacent
        // complete subtrees. After this, merge_stack only contains peaks of
        // unequal-sized subtrees.
        while let Some(next_peak) = peaks.pop() {
            let next_merge = merge_stack
                .pop()
                .expect("there should be at least one, initial or re-pushed");

            if let Some(stored) = {
                let peak = self.resolve_link(next_peak)?;
                let m = self.resolve_link(next_merge)?;
                if peak.node.leaf_count() == m.node.leaf_count() {
                    Some(combine_nodes(peak, m))
                } else {
                    None
                }
            } {
                let link = self.push(stored);
                merge_stack.push(link);
                appended.push(link);
                continue;
            } else {
                merge_stack.push(next_merge);
                merge_stack.push(next_peak);
            }
        }

        let mut new_root = merge_stack
            .pop()
            .expect("Loop above cannot reduce the merge_stack");
        // Scan the peaks left-to-right, producing new generated nodes that
        // connect the subtrees
        while let Some(next_child) = merge_stack.pop() {
            new_root = self.push_generated(combine_nodes(
                self.resolve_link(new_root)?,
                self.resolve_link(next_child)?,
            ))
        }

        self.root = new_root;

        Ok(appended)
    }

    #[cfg(test)]
    fn for_children<F: Fn(V::EntryLink, V::EntryLink)>(&self, node: V::EntryLink, f: F) {
        let (left, right) = {
            let link = self
                .resolve_link(node)
                .expect("Failed to resolve link in test");
            (
                link.left().expect("Failed to find node in test"),
                link.right().expect("Failed to find node in test"),
            )
        };
        f(left, right);
    }

    fn pop(&mut self) {
        self.stored.remove(&(self.stored_count - 1));
        self.stored_count -= 1;
    }

    /// Truncate one leaf from the end of the tree.
    ///
    /// Returns actual number of nodes that should be removed by the caller
    /// from the end of the array representation.
    pub fn truncate_leaf(&mut self) -> Result<u32, Error> {
        let root = {
            let (leaves, root_left_child) = {
                let n = self.resolve_link(self.root)?;
                (n.node.leaf_count(), n.node.left()?)
            };
            if leaves & 1 != 0 {
                self.pop();
                self.root = root_left_child;
                return Ok(1);
            } else {
                self.resolve_link(self.root)?
            }
        };

        let mut peaks = vec![root.left()?];
        let mut subtree_root_link = root.right()?;
        let mut truncated = 1;

        loop {
            let left_link = self.resolve_link(subtree_root_link)?.node;
            if let (Some(left), Some(right)) =
                (V::get_left(&left_link.kind), V::get_right(&left_link.kind))
            {
                peaks.push(left);
                subtree_root_link = right;
                truncated += 1;
            } else {
                if root.node.complete() {
                    truncated += 1;
                }
                break;
            }
        }

        let mut new_root = *peaks.first().expect("At lest 1 elements in peaks");

        for next_peak in peaks.into_iter().skip(1) {
            new_root = self.push_generated(combine_nodes(
                self.resolve_link(new_root)?,
                self.resolve_link(next_peak)?,
            ));
        }

        for _ in 0..truncated {
            self.pop();
        }

        self.root = new_root;

        Ok(truncated)
    }

    /// Length of array representation of the tree.
    pub fn len(&self) -> u32 {
        self.stored_count
    }

    /// Link to the root node
    pub fn root(&self) -> V::EntryLink {
        self.root
    }

    /// Reference to the root node.
    pub fn root_node(&self) -> Result<IndexedNode<V>, Error> {
        self.resolve_link(self.root)
    }

    /// If this tree is empty.
    pub fn is_empty(&self) -> bool {
        self.stored_count == 0
    }
}

/// Reference to the node with link attached.
#[derive(Debug)]
pub struct IndexedNode<'a, V: Version> {
    node: &'a Entry<V>,
    link: V::EntryLink,
}

impl<V> IndexedNode<'_, V>
where
    V: Version,
    V::EntryLink: From<EntryLink> + Copy,
    V::EntryKind: From<EntryKind>,
    EntryLink: From<V::EntryLink>,
{
    fn left(&self) -> Result<V::EntryLink, Error> {
        self.node
            .left()
            .map_err(|e| e.augment(EntryLink::from(self.link)))
    }

    fn right(&self) -> Result<V::EntryLink, Error> {
        self.node
            .right()
            .map_err(|e| e.augment(EntryLink::from(self.link)))
    }

    /// Reference to the entry struct.
    pub fn node(&self) -> &Entry<V> {
        self.node
    }

    /// Reference to the entry metadata.
    pub fn data(&self) -> &V::NodeData {
        &self.node.data
    }

    /// Actual link by what this node was resolved.
    pub fn link(&self) -> V::EntryLink {
        self.link
    }
}

fn combine_nodes<'a, V: Version>(left: IndexedNode<'a, V>, right: IndexedNode<'a, V>) -> Entry<V> {
    Entry {
        kind: V::make_node(left.link, right.link),
        data: V::combine(&left.node.data, &right.node.data),
    }
}

#[cfg(test)]
mod tests {
    use super::{Entry, EntryKind, EntryLink, Tree};
    use crate::{node_data, NodeData, Version, V2};

    use assert_matches::assert_matches;
    use proptest::prelude::*;

    fn leaf(height: u32) -> node_data::V2 {
        node_data::V2 {
            v1: NodeData {
                consensus_branch_id: 1,
                subtree_commitment: [0u8; 32],
                start_time: 0,
                end_time: 0,
                start_target: 0,
                end_target: 0,
                start_sapling_root: [0u8; 32],
                end_sapling_root: [0u8; 32],
                subtree_total_work: 0.into(),
                start_height: height as u64,
                end_height: height as u64,
                sapling_tx: 7,
            },
            start_orchard_root: [0u8; 32],
            end_orchard_root: [0u8; 32],
            orchard_tx: 42,
        }
    }

    fn initial() -> Tree<V2> {
        let node1 = Entry::new_leaf(leaf(1));
        let node2 = Entry::new_leaf(leaf(2));

        let node3 = Entry {
            data: V2::combine(&node1.data, &node2.data),
            kind: EntryKind::Leaf,
        };

        Tree::populate(vec![node1, node2, node3], EntryLink::Stored(2))
    }

    // returns tree with specified number of leafs and it's root
    fn generated(length: u32) -> Tree<V2> {
        assert!(length >= 3);
        let mut tree = initial();
        for i in 2..length {
            tree.append_leaf(leaf(i + 1)).expect("Failed to append");
        }

        tree
    }

    #[test]
    fn discrete_append() {
        let mut tree = initial();

        // ** APPEND 3 **
        let appended = tree.append_leaf(leaf(3)).expect("Failed to append");
        let new_root = tree.root_node().expect("Failed to resolve root").node;

        // initial tree:  (2)
        //               /   \
        //             (0)   (1)
        //
        // new tree:
        //                (4g)
        //               /   \
        //             (2)    \
        //             /  \    \
        //           (0)  (1)  (3)
        //
        // so only (3) is added as real leaf
        // while new root, (4g) is generated one
        assert_eq!(new_root.data.v1.end_height, 3);
        assert_eq!(appended.len(), 1);

        // ** APPEND 4 **
        let appended = tree.append_leaf(leaf(4)).expect("Failed to append");

        let new_root = tree.root_node().expect("Failed to resolve root").node;

        // intermediate tree:
        //                (4g)
        //               /   \
        //             (2)    \
        //             /  \    \
        //           (0)  (1)  (3)
        //
        // new tree:
        //                 ( 6 )
        //                /     \
        //             (2)       (5)
        //             /  \     /   \
        //           (0)  (1) (3)   (4)
        //
        // so (4), (5), (6) are added as real leaves
        // and new root, (6) is stored one
        assert_eq!(new_root.data.v1.end_height, 4);
        assert_eq!(appended.len(), 3);
        assert_matches!(tree.root(), EntryLink::Stored(6));

        // ** APPEND 5 **

        let appended = tree.append_leaf(leaf(5)).expect("Failed to append");
        let new_root = tree.root_node().expect("Failed to resolve root").node;

        // intermediate tree:
        //                 ( 6 )
        //                /     \
        //             (2)       (5)
        //             /  \     /   \
        //           (0)  (1) (3)   (4)
        //
        // new tree:
        //                     ( 8g )
        //                    /      \
        //                 ( 6 )      \
        //                /     \      \
        //             (2)       (5)    \
        //             /  \     /   \    \
        //           (0)  (1) (3)   (4)  (7)
        //
        // so (7) is added as real leaf
        // and new root, (8g) is generated one
        assert_eq!(new_root.data.v1.end_height, 5);
        assert_eq!(appended.len(), 1);
        assert_matches!(tree.root(), EntryLink::Generated(_));
        tree.for_children(tree.root(), |l, r| {
            assert_matches!(l, EntryLink::Stored(6));
            assert_matches!(r, EntryLink::Stored(7));
        });

        // *** APPEND #6 ***
        let appended = tree.append_leaf(leaf(6)).expect("Failed to append");
        let new_root = tree.root_node().expect("Failed to resolve root").node;

        // intermediate tree:
        //                     ( 8g )
        //                    /      \
        //                 ( 6 )      \
        //                /     \      \
        //             (2)       (5)    \
        //             /  \     /   \    \
        //           (0)  (1) (3)   (4)  (7)
        //
        // new tree:
        //                     (---10g--)
        //                    /          \
        //                 ( 6 )          \
        //                /     \          \
        //             (2)       (5)       (9)
        //             /  \     /   \     /   \
        //           (0)  (1) (3)   (4)  (7)  (8)
        //
        // so (7) is added as real leaf
        // and new root, (10g) is generated one
        assert_eq!(new_root.data.v1.end_height, 6);
        assert_eq!(appended.len(), 2);
        assert_matches!(tree.root(), EntryLink::Generated(_));
        tree.for_children(tree.root(), |l, r| {
            assert_matches!(l, EntryLink::Stored(6));
            assert_matches!(r, EntryLink::Stored(9));
        });

        // *** APPEND #7 ***

        let appended = tree.append_leaf(leaf(7)).expect("Failed to append");
        let new_root = tree.root_node().expect("Failed to resolve root").node;

        // intermediate tree:
        //                     (---8g---)
        //                    /          \
        //                 ( 6 )          \
        //                /     \          \
        //             (2)       (5)       (9)
        //             /  \     /   \     /   \
        //           (0)  (1) (3)   (4)  (7)  (8)
        //
        // new tree:
        //                          (---12g--)
        //                         /          \
        //                    (---11g---)      \
        //                   /           \      \
        //                 ( 6 )          \      \
        //                /     \          \      \
        //             (2)       (5)       (9)     \
        //             /  \     /   \     /   \     \
        //           (0)  (1) (3)   (4) (7)   (8)  (10)
        //
        // so (10) is added as real leaf
        // and new root, (12g) is generated one
        assert_eq!(new_root.data.v1.end_height, 7);
        assert_eq!(appended.len(), 1);
        assert_matches!(tree.root(), EntryLink::Generated(_));
        tree.for_children(tree.root(), |l, r| {
            assert_matches!(l, EntryLink::Generated(_));
            tree.for_children(l, |l, r| {
                assert_matches!((l, r), (EntryLink::Stored(6), EntryLink::Stored(9)))
            });
            assert_matches!(r, EntryLink::Stored(10));
        });
    }

    #[test]
    fn truncate_simple() {
        let mut tree = generated(9);
        let total_truncated = tree.truncate_leaf().expect("Failed to truncate");

        // initial tree:
        //
        //                               (-------16g------)
        //                              /                  \
        //                    (--------14-------)           \
        //                   /                   \           \
        //                 ( 6 )              (  13  )        \
        //                /     \            /        \        \
        //             (2)       (5)       (9)        (12)      \
        //             /  \     /   \     /   \      /    \      \
        //           (0)  (1) (3)   (4) (7)   (8)  (10)  (11)    (15)
        //
        // new tree:
        //                    (--------14-------)
        //                   /                   \
        //                 ( 6 )              (  13  )
        //                /     \            /        \
        //             (2)       (5)       (9)        (12)
        //             /  \     /   \     /   \      /    \
        //           (0)  (1) (3)   (4) (7)   (8)  (10)  (11)
        //
        // so (15) is truncated
        // and new root, (14) is a stored one now

        assert_matches!(tree.root(), EntryLink::Stored(14));
        assert_eq!(total_truncated, 1);
        assert_eq!(tree.len(), 15);
    }

    #[test]
    fn truncate_generated() {
        let mut tree = generated(10);
        let deleted = tree.truncate_leaf().expect("Failed to truncate");

        // initial tree:
        //
        //                               (--------18g--------)
        //                              /                     \
        //                    (--------14-------)              \
        //                   /                   \              \
        //                 ( 6 )              (  13  )           \
        //                /     \            /        \           \
        //             (2)       (5)       (9)        (12)        (17)
        //             /  \     /   \     /   \      /    \      /    \
        //           (0)  (1) (3)   (4) (7)   (8)  (10)  (11)  (15)  (16)
        //
        // new tree:
        //                               (-------16g------)
        //                              /                  \
        //                    (--------14-------)           \
        //                   /                   \           \
        //                 ( 6 )              (  13  )        \
        //                /     \            /        \        \
        //             (2)       (5)       (9)        (12)      \
        //             /  \     /   \     /   \      /    \      \
        //           (0)  (1) (3)   (4) (7)   (8)  (10)  (11)    (15)

        // new root is generated

        assert_matches!(tree.root(), EntryLink::Generated(_));

        tree.for_children(tree.root(), |left, right| {
            assert_matches!(
                (left, right),
                (EntryLink::Stored(14), EntryLink::Stored(15))
            )
        });

        // two stored nodes should leave us (leaf 16 and no longer needed node 17)
        assert_eq!(deleted, 2);
        assert_eq!(tree.len(), 16);
    }

    #[test]
    fn tree_len() {
        let mut tree = initial();

        assert_eq!(tree.len(), 3);

        for i in 0..2 {
            tree.append_leaf(leaf(i + 3)).expect("Failed to append");
        }
        assert_eq!(tree.len(), 7);

        tree.truncate_leaf().expect("Failed to truncate");

        assert_eq!(tree.len(), 4);
    }

    #[test]
    fn tree_len_long() {
        let mut tree = initial();

        assert_eq!(tree.len(), 3);

        for i in 0..4094 {
            tree.append_leaf(leaf(i + 3)).expect("Failed to append");
        }
        assert_eq!(tree.len(), 8191); // 4096*2-1 (full tree)

        for _ in 0..2049 {
            tree.truncate_leaf().expect("Failed to truncate");
        }

        assert_eq!(tree.len(), 4083); // 4095 - log2(4096)
    }

    proptest! {
        #[test]
        fn prop_there_and_back(number in 0u32..=1024) {
            let mut tree = initial();
            for i in 0..number {
                tree.append_leaf(leaf(i+3)).expect("Failed to append");
            }
            for _ in 0..number {
                tree.truncate_leaf().expect("Failed to truncate");
            }

            assert_matches!(tree.root(), EntryLink::Stored(2));
        }

        #[test]
        fn prop_leaf_count(number in 3u32..=1024) {
            let mut tree = initial();
            for i in 1..(number-1) {
                tree.append_leaf(leaf(i+2)).expect("Failed to append");
            }

            assert_eq!(tree.root_node().expect("no root").node.leaf_count(), number as u64);
        }

        #[test]
        fn prop_parity(number in 3u32..=2048) {
            let mut tree = initial();
            for i in 1..(number-1) {
                tree.append_leaf(leaf(i+2)).expect("Failed to append");
            }

            if number & (number - 1) == 0 {
                assert_matches!(tree.root(), EntryLink::Stored(_));
            } else {
                assert_matches!(tree.root(), EntryLink::Generated(_));
            }
        }

        #[test]
        fn prop_parity_with_truncate(
            add_and_delete in (0u32..=2048).prop_flat_map(
                |add| (Just(add), 0..=add)
            )
        ) {
            let (add, delete) = add_and_delete;
            // First we add `add` number of leaves, then delete `delete` number of leaves
            // What is left should be consistent with generated-stored structure
            let mut tree = initial();
            for i in 0..add {
                tree.append_leaf(leaf(i+3)).expect("Failed to append");
            }
            for _ in 0..delete {
                tree.truncate_leaf().expect("Failed to truncate");
            }

            let total = add - delete + 2;

            if total & (total - 1) == 0 {
                assert_matches!(tree.root(), EntryLink::Stored(_));
            } else {
                assert_matches!(tree.root(), EntryLink::Generated(_));
            }
        }

        #[test]
        fn prop_stored_length(
            add_and_delete in (0u32..=2048).prop_flat_map(
                |add| (Just(add), 0..=add)
            )
        ) {
            let (add, delete) = add_and_delete;
            let mut tree = initial();
            for i in 0..add {
                tree.append_leaf(leaf(i+3)).expect("Failed to append");
            }
            for _ in 0..delete {
                tree.truncate_leaf().expect("Failed to truncate");
            }

            let total = add - delete + 2;

            assert!(total * total > tree.len())
        }
    }
}
