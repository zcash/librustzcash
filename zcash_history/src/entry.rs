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
    ///
    /// # Panics
    ///
    /// Panics if this entry was constructed with a descending height range or
    /// a range containing more leaves than can be represented by a `u64`.
    /// Entries produced by [`Self::read`] are validated against these cases.
    pub fn leaf_count(&self) -> u64 {
        V::end_height(&self.data)
            .checked_sub(V::start_height(&self.data))
            .and_then(|height_diff| height_diff.checked_add(1))
            .expect("entry height range must contain a representable number of leaves")
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
    pub fn read<R: corez::io::Read>(consensus_branch_id: u32, r: &mut R) -> corez::io::Result<Self> {
        let kind = {
            let mut byte = [0u8; 1];
            r.read_exact(&mut byte)?;
            match byte[0] {
                0 => {
                    let mut buf = [0u8; 4];
                    r.read_exact(&mut buf)?;
                    let left = u32::from_le_bytes(buf);
                    r.read_exact(&mut buf)?;
                    let right = u32::from_le_bytes(buf);
                    EntryKind::Node(EntryLink::Stored(left), EntryLink::Stored(right))
                }
                1 => EntryKind::Leaf,
                _ => return Err(corez::io::Error::from(corez::io::ErrorKind::InvalidData)),
            }
        };

        let data = V::read(consensus_branch_id, r)?;

        Ok(Entry { kind, data })
    }

    /// Write to byte representation.
    pub fn write<W: corez::io::Write>(&self, w: &mut W) -> corez::io::Result<()> {
        match self.kind {
            EntryKind::Node(EntryLink::Stored(left), EntryLink::Stored(right)) => {
                w.write_all(&[0])?;
                w.write_all(&left.to_le_bytes())?;
                w.write_all(&right.to_le_bytes())?;
            }
            EntryKind::Leaf => {
                w.write_all(&[1])?;
            }
            _ => {
                return Err(corez::io::Error::from(corez::io::ErrorKind::InvalidData));
            }
        }

        V::write(&self.data, w)?;

        Ok(())
    }

    /// Convert from byte representation.
    pub fn from_bytes<T: AsRef<[u8]>>(consensus_branch_id: u32, buf: T) -> corez::io::Result<Self> {
        let mut cursor = corez::io::Cursor::new(buf);
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
