use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::{EntryKind, EntryLink, Error, MAX_NODE_DATA_SIZE, Version};

/// Max serialized length of entry data.
pub const MAX_ENTRY_SIZE: usize = MAX_NODE_DATA_SIZE + 9;

/// MMR Entry.
#[derive(Debug)]
pub struct Entry<V: Version> {
    pub(crate) kind: EntryKind,
    pub(crate) data: V::NodeData,
}

impl<V: Version> Entry<V> {
    /// New entry of type node.
    pub fn new(data: V::NodeData, left: EntryLink, right: EntryLink) -> Self {
        Entry {
            kind: EntryKind::Node(left, right),
            data,
        }
    }

    /// Returns the data associated with this node.
    pub fn data(&self) -> &V::NodeData {
        &self.data
    }

    /// Creates a new leaf.
    pub fn new_leaf(data: V::NodeData) -> Self {
        Entry {
            kind: EntryKind::Leaf,
            data,
        }
    }

    /// Returns if is this node complete (has total of 2^N leaves)
    pub fn complete(&self) -> bool {
        self.leaf_count().is_power_of_two()
    }

    /// Number of leaves under this node.
    pub fn leaf_count(&self) -> u64 {
        V::end_height(&self.data) - (V::start_height(&self.data) - 1)
    }

    /// Is this node a leaf.
    pub fn leaf(&self) -> bool {
        matches!(self.kind, EntryKind::Leaf)
    }

    /// Left child
    pub fn left(&self) -> Result<EntryLink, Error> {
        match self.kind {
            EntryKind::Leaf => Err(Error::node_expected()),
            EntryKind::Node(left, _) => Ok(left),
        }
    }

    /// Right child.
    pub fn right(&self) -> Result<EntryLink, Error> {
        match self.kind {
            EntryKind::Leaf => Err(Error::node_expected()),
            EntryKind::Node(_, right) => Ok(right),
        }
    }

    /// Read from byte representation.
    pub fn read<R: std::io::Read>(consensus_branch_id: u32, r: &mut R) -> std::io::Result<Self> {
        let kind = {
            match r.read_u8()? {
                0 => {
                    let left = r.read_u32::<LittleEndian>()?;
                    let right = r.read_u32::<LittleEndian>()?;
                    EntryKind::Node(EntryLink::Stored(left), EntryLink::Stored(right))
                }
                1 => EntryKind::Leaf,
                _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
            }
        };

        let data = V::read(consensus_branch_id, r)?;

        Ok(Entry { kind, data })
    }

    /// Write to byte representation.
    pub fn write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        match self.kind {
            EntryKind::Node(EntryLink::Stored(left), EntryLink::Stored(right)) => {
                w.write_u8(0)?;
                w.write_u32::<LittleEndian>(left)?;
                w.write_u32::<LittleEndian>(right)?;
            }
            EntryKind::Leaf => {
                w.write_u8(1)?;
            }
            _ => {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
        }

        V::write(&self.data, w)?;

        Ok(())
    }

    /// Convert from byte representation.
    pub fn from_bytes<T: AsRef<[u8]>>(consensus_branch_id: u32, buf: T) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(buf);
        Self::read(consensus_branch_id, &mut cursor)
    }
}

impl<V: Version> std::fmt::Display for Entry<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            EntryKind::Node(l, r) => write!(f, "node({l}, {r}, ..)"),
            EntryKind::Leaf => write!(f, "leaf(..)"),
        }
    }
}
