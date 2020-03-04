use zcash_history::{Entry, EntryLink, NodeData, Tree};

pub struct NodeDataIterator {
    return_stack: Vec<NodeData>,
    tree: Tree,
    cursor: usize,
    leaf_cursor: usize,
}

impl Iterator for NodeDataIterator {
    type Item = NodeData;

    fn next(&mut self) -> Option<NodeData> {
        let result = if self.cursor == 1 {
            self.leaf_cursor = 2;
            Some(leaf(1))
        } else if self.cursor == 2 {
            self.leaf_cursor = 3;
            Some(leaf(2))
        } else if self.cursor == 3 {
            Some(self.tree.root_node().expect("always exists").data().clone())
        } else if self.return_stack.len() > 0 {
            self.return_stack.pop()
        } else {
            for n_append in self
                .tree
                .append_leaf(leaf(self.leaf_cursor as u32))
                .expect("full tree cannot fail")
                .into_iter()
                .rev()
            {
                self.return_stack.push(
                    self.tree
                        .resolve_link(n_append)
                        .expect("just pushed")
                        .data()
                        .clone(),
                )
            }
            self.leaf_cursor += 1;
            self.return_stack.pop()
        };

        self.cursor += 1;
        result
    }
}

impl NodeDataIterator {
    pub fn new() -> Self {
        let root = Entry::new(
            NodeData::combine(&leaf(1), &leaf(2)),
            EntryLink::Stored(0),
            EntryLink::Stored(1),
        );
        let tree = Tree::new(
            3,
            vec![(2, root)],
            vec![(0, leaf(1).into()), (1, leaf(2).into())],
        );

        NodeDataIterator {
            return_stack: Vec::new(),
            tree,
            cursor: 1,
            leaf_cursor: 1,
        }
    }
}

fn leaf(height: u32) -> NodeData {
    NodeData {
        consensus_branch_id: 0,
        subtree_commitment: [0u8; 32],
        start_time: height * 10 + 1,
        end_time: (height + 1) * 10,
        start_target: 100 + height * 10,
        end_target: 100 + (height + 1) * 10,
        start_sapling_root: [0u8; 32],
        end_sapling_root: [0u8; 32],
        subtree_total_work: 0.into(),
        start_height: height as u64,
        end_height: height as u64,
        sapling_tx: 5 + height as u64,
    }
}
