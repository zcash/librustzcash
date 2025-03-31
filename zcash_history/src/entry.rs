use crate::{Error, Version, MAX_NODE_DATA_SIZE};

/// Max serialized length of entry data.
pub const MAX_ENTRY_SIZE: usize = MAX_NODE_DATA_SIZE + 9;

/// MMR Entry.
#[derive(Debug)]
#[cfg_attr(
    feature = "remote_read_state_service",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(
    feature = "remote_read_state_service",
    serde(bound(
        serialize = "V::NodeData: serde::Serialize, V::EntryKind: serde::Serialize",
        deserialize = "V::NodeData: serde::de::DeserializeOwned, V::EntryKind: serde::de::DeserializeOwned"
    ))
)]
pub struct Entry<V: Version> {
    pub(crate) kind: V::EntryKind,
    pub(crate) data: V::NodeData,
}

impl<V: Version> Entry<V> {
    /// New entry of type node.
    pub fn new(data: V::NodeData, left: V::EntryLink, right: V::EntryLink) -> Self {
        Entry {
            kind: V::make_node(left, right),
            data,
        }
    }

    /// Creates a new leaf.
    pub fn new_leaf(data: V::NodeData) -> Self {
        Entry {
            kind: V::make_leaf(),
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
        V::is_leaf(&self.kind)
    }

    /// Left child.
    pub fn left(&self) -> Result<V::EntryLink, Error> {
        match V::get_left(&self.kind) {
            Some(link) => Ok(link),
            None => Err(Error::node_expected()),
        }
    }

    /// Right child.
    pub fn right(&self) -> Result<V::EntryLink, Error> {
        match V::get_right(&self.kind) {
            Some(link) => Ok(link),
            None => Err(Error::node_expected()),
        }
    }

    /// Read from byte representation.
    pub fn read<R: std::io::Read>(consensus_branch_id: u32, r: &mut R) -> std::io::Result<Self> {
        let kind = V::read_entry_kind(r)?;
        let data = V::read(consensus_branch_id, r)?;
        Ok(Entry { kind, data })
    }

    /// Write to byte representation.
    pub fn write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        V::write_entry_kind(&self.kind, w)?;
        V::write(&self.data, w)?;
        Ok(())
    }

    /// Convert from byte representation.
    pub fn from_bytes<T: AsRef<[u8]>>(consensus_branch_id: u32, buf: T) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(buf);
        Self::read(consensus_branch_id, &mut cursor)
    }
}

impl<V: Version> std::fmt::Display for Entry<V>
where
    V::EntryKind: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Entry(kind: {}, ...)", self.kind)
    }
}
