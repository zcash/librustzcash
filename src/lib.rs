//! MMR library for Zcash
//!
//! To be used in zebra and via FFI bindings in zcashd
#![warn(missing_docs)]

mod tree;
mod node_data;
mod entry;


pub use tree::Tree;
pub use node_data::{NodeData, MAX_NODE_DATA_SIZE};
pub use entry::{Entry, MAX_ENTRY_SIZE};

/// Crate-level error type
#[derive(Debug)]
pub enum Error {
    /// Entry expected to be presented in the tree view while it was not.
    ExpectedInMemory(EntryLink),
    /// Entry expected to be a node.
    ExpectedNode,
    /// Entry expected to be a node (specifying for which link this is not true).
    ExpectedNodeForLink(EntryLink),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ExpectedInMemory(l) => write!(f, "Node/leaf expected to be in memory: {}", l),
            Self::ExpectedNode => write!(f, "Node expected"),
            Self::ExpectedNodeForLink(l) => write!(f, "Node expected, not leaf: {}", l),
        }
    }
}

/// Reference to to the tree node.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum EntryLink {
    /// Reference to the stored (in the array representation) leaf/node.
    Stored(u32),
    /// Reference to the generated leaf/node.
    Generated(u32),
}

impl std::fmt::Display for EntryLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Stored(v) => write!(f, "stored({})", v),
            Self::Generated(v) => write!(f, "generated({})", v),
        }
    }
}

/// MMR Node. It is leaf when `left`, `right` are `None` and node when they are not.
#[repr(C)]
#[derive(Debug)]
pub enum EntryKind {
    /// Leaf entry.
    Leaf,
    /// Node entry with children links.
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

