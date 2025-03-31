//! Chain history library for Zcash
//!
//! To be used in zebra and via FFI bindings in zcashd

// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

mod entry;
mod node_data;
mod tree;
mod version;

pub use entry::{Entry, MAX_ENTRY_SIZE};
pub use node_data::{NodeData, MAX_NODE_DATA_SIZE};
pub use tree::Tree;
pub use version::{Version, V1, V2};

/// Crate-level error type
#[derive(Debug)]
pub enum Error {
    /// Entry expected to be presented in the tree view while it was not.
    ExpectedInMemory(EntryLink),
    /// Entry expected to be a node (specifying for which link this is not true).
    ExpectedNode(Option<EntryLink>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ExpectedInMemory(l) => write!(f, "Node/leaf expected to be in memory: {}", l),
            Self::ExpectedNode(None) => write!(f, "Node expected"),
            Self::ExpectedNode(Some(l)) => write!(f, "Node expected, not leaf: {}", l),
        }
    }
}

/// Reference to the tree node.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "remote_read_state_service",
    derive(serde::Serialize, serde::Deserialize)
)]
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

impl EntryLink {
    /// Writes an EntryLink to the provided writer.
    pub fn write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};
        match *self {
            EntryLink::Stored(v) => {
                w.write_u8(0)?; // Tag 0 for Stored.
                w.write_u32::<LittleEndian>(v)?;
            }
            EntryLink::Generated(v) => {
                w.write_u8(1)?; // Tag 1 for Generated.
                w.write_u32::<LittleEndian>(v)?;
            }
        }
        Ok(())
    }

    /// Reads an EntryLink from the provided reader.
    pub fn read<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        use byteorder::{LittleEndian, ReadBytesExt};
        let tag = r.read_u8()?;
        let v = r.read_u32::<LittleEndian>()?;
        match tag {
            0 => Ok(EntryLink::Stored(v)),
            1 => Ok(EntryLink::Generated(v)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid entry link tag",
            )),
        }
    }
}

/// MMR Node. It is leaf when `left`, `right` are `None` and node when they are not.
#[repr(C)]
#[derive(Debug)]
#[cfg_attr(
    feature = "remote_read_state_service",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum EntryKind {
    /// Leaf entry.
    Leaf,
    /// Node entry with children links.
    Node(EntryLink, EntryLink),
}

impl std::fmt::Display for EntryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryKind::Leaf => write!(f, "leaf"),
            EntryKind::Node(left, right) => write!(f, "node({}, {})", left, right),
        }
    }
}

impl EntryKind {
    /// Writes an EntryKind to the provided writer.
    pub fn write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        use byteorder::WriteBytesExt;
        match self {
            EntryKind::Node(left, right) => {
                w.write_u8(0)?; // Tag 0 for Node.
                left.write(w)?; // Use the EntryLink write method.
                right.write(w)?;
            }
            EntryKind::Leaf => {
                w.write_u8(1)?; // Tag 1 for Leaf.
            }
        }
        Ok(())
    }

    /// Reads an EntryKind from the provided reader.
    pub fn read<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        use byteorder::ReadBytesExt;
        let tag = r.read_u8()?;
        match tag {
            0 => {
                let left = EntryLink::read(r)?; // **CHANGE:** Use the EntryLink read method.
                let right = EntryLink::read(r)?;
                Ok(EntryKind::Node(left, right))
            }
            1 => Ok(EntryKind::Leaf),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid entry kind tag",
            )),
        }
    }
}

impl Error {
    /// Entry expected to be a node (specifying for which link this is not true).
    pub fn link_node_expected(link: EntryLink) -> Self {
        Self::ExpectedNode(Some(link))
    }

    /// Some entry is expected to be node
    pub fn node_expected() -> Self {
        Self::ExpectedNode(None)
    }

    pub(crate) fn augment(self, link: EntryLink) -> Self {
        match self {
            Error::ExpectedNode(_) => Error::ExpectedNode(Some(link)),
            val => val,
        }
    }
}
