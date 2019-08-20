use std::collections::HashMap;

use crate::{MMRNode, NodeLink, NodeData};

#[derive(Default)]
struct Tree {
    stored: HashMap<u32, MMRNode>,

    generated: HashMap<u32, MMRNode>,

    // number of persistent(!) tree entries
    stored_count: u32,

    // number of virtual nodes generated
    generated_count: u32,
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

    pub fn populate(loaded: Vec<MMRNode>) -> Self {
        let mut result = Tree::default();
        result.stored_count = loaded.len() as u32;
        for (idx, item) in loaded.into_iter().enumerate() {
            result.stored.insert(idx as u32, item);
        }

        result
    }
}

/// plain list of nodes that has to be appended to the end of the tree as the result of append operation
/// along with new root
pub struct AppendTransaction {
    pub appended: Vec<NodeLink>,
    pub new_root: NodeLink,
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

fn append(tree: &mut Tree, root: NodeLink, new_leaf: NodeData) -> AppendTransaction {

    let is_complete= tree.resolve_link(root).node.complete();

    let (new_root_node, mut appended) = if is_complete {
        let new_leaf_link = tree.push(new_leaf.into());

        let mut appended = Vec::new();
        appended.push(new_leaf_link);

        // since we dethrone stored root, new one is always generated
        let new_root_node = combine_nodes(
            tree.resolve_link(root),
            tree.resolve_link(new_leaf_link),
        );

        (new_root_node, appended)


    } else {
        let (root_left_child, root_right_child) = {
            let root = tree.resolve_link(root).node;
            (
                root.left.expect("Root should always have left child"),
                root.right.expect("Root should always have right child"),
            )
        };

        let nested_append = append(tree, root_right_child, new_leaf);
        let mut appended = nested_append.appended;
        let subtree_root = nested_append.new_root;

        let new_root_node = combine_nodes(
            tree.resolve_link(root_left_child),
            tree.resolve_link(subtree_root),
        );

        (new_root_node, appended)
    };

    let new_root = if new_root_node.complete() {
        let new_root= tree.push(new_root_node);
        appended.push(new_root);
        new_root
    } else {
        tree.push_generated(new_root_node)
    };

    AppendTransaction {
        new_root,
        appended,
    }
}

#[cfg(test)]
mod tests {

    use super::{MMRNode, NodeData, Tree, append, NodeLink};

    fn leaf(height: u32) -> NodeData {
        NodeData {
            // TODO: hash children
            subtree_commitment: [0u8; 32],
            start_time: 0,
            end_time: 0,
            start_target: 0,
            end_target: 0,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],

            // TODO: sum work?
            subtree_total_work: 0,
            start_height: height,
            end_height: height,
            shielded_tx: 7,
        }
    }

    fn node(start_height: u32, end_height: u32) -> NodeData {
        NodeData {
            // TODO: hash children
            subtree_commitment: [0u8; 32],
            start_time: 0,
            end_time: 0,
            start_target: 0,
            end_target: 0,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],

            // TODO: sum work?
            subtree_total_work: 0,
            start_height: start_height,
            end_height: end_height,
            shielded_tx: 7,
        }
    }

    // size should be power of 2-1
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

    #[test]
    fn discrete_append() {
        let mut tree = initial();
        let append_tx = append(
            &mut tree, NodeLink::Stored(2),
            leaf(3)
        );
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

        let append_tx = append(&mut tree, new_root_link, leaf(4));
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

        let append_tx = append(&mut tree, new_root_link, leaf(5));
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

}