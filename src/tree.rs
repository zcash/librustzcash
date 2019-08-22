use std::collections::HashMap;

use crate::{MMRNode, NodeLink, NodeData};

/// Represents partially loaded tree.
///
/// Some kind of "view" into the array representation of the MMR tree.
/// With only some of the leaves/nodes pre-loaded / pre-generated.
/// Exact amount of the loaded data can be calculated by the constructing party,
/// depending on the length of the tree and maximum amount of operations that are going
/// to happen after construction.
#[derive(Default)]
pub struct Tree {
    stored: HashMap<u32, MMRNode>,

    generated: HashMap<u32, MMRNode>,

    // number of persistent(!) tree entries
    stored_count: u32,

    // number of virtual nodes generated
    generated_count: u32,
}

/// Result of appending one or several leaves.
pub struct AppendTransaction {
    /// Plain list of nodes that has to be appended to the end of the array representation
    /// of the tree as the result of append operation.
    pub appended: Vec<NodeLink>,

    /// New root as a result of the operation (can be generated one).
    pub new_root: NodeLink,
}

/// Result of truncating one or severl leaves.
pub struct DeleteTransaction {
    /// Number of leaves that should be dropped from the end of the list.
    pub truncated: u32,
    /// New root as the result of the operation (can be generated one).
    pub new_root: NodeLink,
}

impl Tree {
    fn resolve_link(&self, link: NodeLink) -> IndexedNode {
        match link {
            NodeLink::Generated(index) => {
                // TODO: maybe graceful error?
                let node = self.generated.get(&index).expect("caller should ensure id generated");
                IndexedNode {
                    node,
                    link,
                }
            },
            NodeLink::Stored(index) => {
                // TODO: maybe graceful error?
                let node = self.stored.get(&index).expect("caller should ensure id stored");
                IndexedNode {
                    node,
                    link,
                }
            },
        }
    }

    fn push(&mut self, data: MMRNode) -> NodeLink {
        let idx = self.stored_count;
        self.stored_count = self.stored_count + 1;
        self.stored.insert(idx, data);
        NodeLink::Stored(idx)
    }

    fn push_generated(&mut self, data: MMRNode) -> NodeLink {
        let idx = self.generated_count;
        self.generated_count = self.generated_count + 1;
        self.generated.insert(idx, data);
        NodeLink::Generated(idx)
    }

    /// Populate tree with plain list of the leaves/nodes. Mostly for tests,
    /// since this `Tree` structure is for partially loaded tree.
    pub fn populate(loaded: Vec<MMRNode>) -> Self {
        let mut result = Tree::default();
        result.stored_count = loaded.len() as u32;
        for (idx, item) in loaded.into_iter().enumerate() {
            result.stored.insert(idx as u32, item);
        }

        result
    }

    pub fn new(
        length: u32,
        stored: Vec<(u32, MMRNode)>,
        generated: Vec<MMRNode>,
    ) -> Self {
        let mut result = Tree::default();
        result.stored_count = length;

        for (idx, node) in stored.into_iter() {
            result.stored.insert(idx, node);
        }

        result.generated_count = generated.len() as u32;

        for (idx, node) in generated.into_iter().enumerate() {
            result.generated.insert(idx as u32, node);
        }

        result
    }

    /// Append one leaf to the tree.
    pub fn append_leaf(&mut self, root: NodeLink, new_leaf: NodeData) -> AppendTransaction {

        let is_complete= self.resolve_link(root).node.complete();

        let (new_root_node, mut appended) = if is_complete {
            let new_leaf_link = self.push(new_leaf.into());

            let mut appended = Vec::new();
            appended.push(new_leaf_link);

            // since we dethrone stored root, new one is always generated
            let new_root_node = combine_nodes(
                self.resolve_link(root),
                self.resolve_link(new_leaf_link),
            );

            (new_root_node, appended)
        } else {
            let (root_left_child, root_right_child) = {
                let root = self.resolve_link(root).node;
                (
                    root.left.expect("Root should always have left child"),
                    root.right.expect("Root should always have right child"),
                )
            };

            let nested_append = self.append_leaf(root_right_child, new_leaf);
            let appended = nested_append.appended;
            let subtree_root = nested_append.new_root;

            let new_root_node = combine_nodes(
                self.resolve_link(root_left_child),
                self.resolve_link(subtree_root),
            );

            (new_root_node, appended)
        };

        let new_root = if new_root_node.complete() {
            let new_root= self.push(new_root_node);
            appended.push(new_root);
            new_root
        } else {
            self.push_generated(new_root_node)
        };

        AppendTransaction {
            new_root,
            appended,
        }
    }

    fn pop(&mut self) {
        self.stored.remove(&(self.stored_count-1));
        self.stored_count = self.stored_count - 1;
    }

    /// Truncate one leaf from the end of the tree.
    pub fn truncate_leaf(&mut self, root: NodeLink) -> DeleteTransaction {
        let root = {
            let (leaves, root_left_child) = {
                let n = self.resolve_link(root);
                (
                    n.node.data.end_height - n.node.data.start_height + 1,
                    n.node.left.expect("Root should have left child while deleting")
                )
            };
            if leaves & 1 != 0 {
                self.pop();
                return DeleteTransaction {
                    truncated: 1,
                    new_root: root_left_child,
                }
            } else {
                self.resolve_link(root)
            }
        };

        let mut peaks = vec![root.node.left.expect("Root should have left child")];
        let mut subtree_root_link = root.node.right.expect("Root should have right child");
        let mut truncated = 1;

        loop {
            let left_link = self.resolve_link(subtree_root_link).node.left;
            if let Some(left_link) = left_link {
                peaks.push(left_link);
                subtree_root_link = self
                    .resolve_link(subtree_root_link).node.right
                    .expect("If left exists, right should exist as well");
                truncated += 1;
            } else {
                break;
            }
        }

        let root = peaks.drain(0..1).nth(0).expect("At lest 2 elements in peaks");
        let new_root = peaks.into_iter().fold(
            root,
            |root, next_peak|
                self.push_generated(
                    combine_nodes(
                        self.resolve_link(root),
                        self.resolve_link(next_peak)
                    )
                )
        );

        for _ in 0..truncated { self.pop(); }

        DeleteTransaction {
            new_root,
            truncated,
        }
    }

    /// Length of array representation of the tree.
    pub fn len(&self) -> u32 {
        self.stored_count
    }
}


struct IndexedNode<'a> {
    node: &'a MMRNode,
    link: NodeLink,
}

fn combine_data(left: &NodeData, right: &NodeData) -> NodeData {
    NodeData {
        // TODO: hash children
        subtree_commitment: [0u8; 32],
        start_time: left.start_time,
        end_time: right.end_time,
        start_target: left.start_target,
        end_target: right.end_target,
        start_sapling_root: left.start_sapling_root,
        end_sapling_root: right.end_sapling_root,

        // TODO: sum work?
        subtree_total_work: 0,
        start_height: left.start_height,
        end_height: right.end_height,
        shielded_tx: left.shielded_tx + right.shielded_tx,
    }
}

fn combine_nodes<'a>(left: IndexedNode<'a>, right: IndexedNode<'a>) -> MMRNode {
    MMRNode {
        left: Some(left.link),
        right: Some(right.link),
        data: combine_data(&left.node.data, &right.node.data),
    }
}

#[cfg(test)]
mod tests {

    use super::{MMRNode, NodeData, Tree, NodeLink};

    fn leaf(height: u32) -> NodeData {
        NodeData {
            subtree_commitment: [0u8; 32],
            start_time: 0,
            end_time: 0,
            start_target: 0,
            end_target: 0,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: 0,
            start_height: height,
            end_height: height,
            shielded_tx: 7,
        }
    }

    fn node(start_height: u32, end_height: u32) -> NodeData {
        NodeData {
            subtree_commitment: [0u8; 32],
            start_time: 0,
            end_time: 0,
            start_target: 0,
            end_target: 0,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: 0,
            start_height: start_height,
            end_height: end_height,
            shielded_tx: 7,
        }
    }

    fn initial() -> Tree {
        let node1: MMRNode = leaf(1).into();
        let node2: MMRNode = leaf(2).into();

        let node3 = MMRNode {
            data: node(1, 2),
            left: Some(NodeLink::Stored(0)),
            right: Some(NodeLink::Stored(1)),
        };

        Tree::populate(vec![node1, node2, node3])
    }

    // returns tree with specified number of leafs and it's root
    fn generated(length: u32) -> (Tree, NodeLink) {
        assert!(length > 3);
        let mut tree = initial();
        let mut root = NodeLink::Stored(2);

        for i in 2..length {
            root = tree.append_leaf(root, leaf(i+1).into()).new_root;
        }

        (tree, root)
    }

    #[test]
    fn discrete_append() {
        let mut tree = initial();
        let append_tx = tree.append_leaf(NodeLink::Stored(2), leaf(3));
        let new_root_link = append_tx.new_root;
        let new_root = tree.resolve_link(new_root_link).node;

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
        assert_eq!(new_root.data.end_height, 3);
        assert_eq!(append_tx.appended.len(), 1);

        let append_tx = tree.append_leaf(new_root_link, leaf(4));
        let new_root_link = append_tx.new_root;
        let new_root = tree.resolve_link(new_root_link).node;

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
        assert_eq!(new_root.data.end_height, 4);
        assert_eq!(append_tx.appended.len(), 3);

        let append_tx = tree.append_leaf(new_root_link, leaf(5));
        let new_root_link = append_tx.new_root;
        let new_root = tree.resolve_link(new_root_link).node;

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
        assert_eq!(new_root.data.end_height, 5);
        assert_eq!(append_tx.appended.len(), 1);
    }

    #[test]
    fn truncate_simple() {
        let (mut tree, root) = generated(9);
        let delete_tx = tree.truncate_leaf(root);

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

        assert_matches!(delete_tx.new_root, NodeLink::Stored(14));
        assert_eq!(tree.len(), 15);
    }

    #[test]
    fn truncate_generated() {
        let (mut tree, root) = generated(10);
        let delete_tx = tree.truncate_leaf(root);

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

        assert_matches!(delete_tx.new_root, NodeLink::Generated(_));

        // left is 14 and right is 15
        let (left_root_child, right_root_child) = {
            let root = tree.resolve_link(delete_tx.new_root);

            (
                root.node.left.expect("there should be left child for root"),
                root.node.right.expect("there should be right child for root"),
            )
        };

        assert_matches!(
            (left_root_child, right_root_child),
            (NodeLink::Stored(14), NodeLink::Stored(15))
        );

        // two stored nodes should leave us (leaf 16 and no longer needed node 17)
        assert_eq!(delete_tx.truncated, 2);
        assert_eq!(tree.len(), 16);
    }
}