//! MMR library for Zcash
//!
//! To be used in zebra and via FFI bindings in zcashd

#[cfg(test)] #[macro_use] extern crate assert_matches;
#[cfg(test)] #[macro_use] extern crate quickcheck;
extern crate derive_more;


mod tree;

pub use tree::Tree;

/// Node metadata.
#[repr(C)]
#[derive(Debug)]
pub struct NodeData {
    subtree_commitment: [u8; 32],
    start_time: u32,
    end_time: u32,
    start_target: u32,
    end_target: u32,
    start_sapling_root: [u8; 32],
    end_sapling_root: [u8; 32],
    subtree_total_work: u64,
    start_height: u32,
    end_height: u32,
    shielded_tx: u64,
}

#[derive(Debug, derive_more::Display)]
pub enum Error {
    #[display(fmt="Node/leaf expected to be in memory: {}", _0)]
    ExpectedInMemory(EntryLink),
    #[display(fmt="Node expected")]
    ExpectedNode,
    #[display(fmt="Node expected, not leaf: {}", _0)]
    ExpectedNodeForLink(EntryLink),
}

/// Reference to to the tree node.
#[repr(C)]
#[derive(Clone, Copy, Debug, derive_more::Display)]
pub enum EntryLink {
    /// Reference to the stored (in the array representation) leaf/node.
    #[display(fmt="stored(@{})", _0)]
    Stored(u32),
    /// Reference to the generated leaf/node.
    #[display(fmt="generated(@{})", _0)]
    Generated(u32),
}

/// MMR Node. It is leaf when `left`, `right` are `None` and node when they are not.
#[repr(C)]
#[derive(Debug)]
pub enum EntryKind {
    Leaf,
    Node(EntryLink, EntryLink),
}

pub struct Entry {
    kind: EntryKind,
    data: NodeData,
}

impl Entry {
    pub fn complete(&self) -> bool {
        let leaves = self.leaf_count();
        leaves & (leaves - 1) == 0
    }

    pub fn leaf_count(&self) -> u32 {
        self.data.end_height - self.data.start_height + 1
    }

    pub fn is_leaf(&self) -> bool {
        if let EntryKind::Leaf = self.kind { true } else { false }
    }

    pub fn left(&self) -> Result<EntryLink, Error> {
        match self.kind {
            EntryKind::Leaf => { Err(Error::ExpectedNode) }
            EntryKind::Node(left, _) => Ok(left)
        }
    }

    pub fn right(&self) -> Result<EntryLink, Error> {
        match self.kind {
            EntryKind::Leaf => { Err(Error::ExpectedNode) }
            EntryKind::Node(_, right) => Ok(right)
        }
    }
}

impl From<NodeData> for Entry {
    fn from(s: NodeData) -> Self {
        Entry { kind: EntryKind::Leaf, data: s }
    }
}

impl Error {
    pub (crate) fn augment(self, link: EntryLink) -> Self {
        match self {
            Error::ExpectedNode => Error::ExpectedNodeForLink(link),
            val => val
        }
    }
}

