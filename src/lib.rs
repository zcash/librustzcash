//! MMR library for Zcash
//!
//! To be used in zebra and via FFI bindings in zcashd

mod tree;
mod node_data;
mod entry;

pub use tree::Tree;
pub use node_data::NodeData;
pub use entry::Entry;

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

impl Error {
    pub (crate) fn augment(self, link: EntryLink) -> Self {
        match self {
            Error::ExpectedNode => Error::ExpectedNodeForLink(link),
            val => val
        }
    }
}

