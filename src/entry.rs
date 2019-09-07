use byteorder::{LittleEndian, ReadBytesExt};

use crate::{EntryKind, NodeData, Error, EntryLink, MAX_NODE_DATA_SIZE};

pub const MAX_ENTRY_SIZE: usize = MAX_NODE_DATA_SIZE + 9;

#[derive(Debug)]
pub struct Entry {
    pub(crate) kind: EntryKind,
    pub(crate) data: NodeData,
}

impl Entry {
    pub fn update_siblings(&mut self, left: EntryLink, right: EntryLink) {
        self.kind = EntryKind::Node(left, right);
    }

    pub fn complete(&self) -> bool {
        let leaves = self.leaf_count();
        leaves & (leaves - 1) == 0
    }

    pub fn leaf_count(&self) -> u64 {
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

    pub fn read<R: std::io::Read>(consensus_branch_id: u32, r: &mut R) -> std::io::Result<Self> {
        let kind = {
            match r.read_u8()? {
                0 => {
                    let left = r.read_u32::<LittleEndian>()?;
                    let right = r.read_u32::<LittleEndian>()?;
                    EntryKind::Node(EntryLink::Stored(left), EntryLink::Stored(right))
                },
                1 => {
                    EntryKind::Leaf
                },
                _ => {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
                },
            }
        };

        let data = NodeData::read(consensus_branch_id, r)?;

        Ok(Entry {
            kind,
            data,
        })
    }

    pub fn from_bytes(consensus_branch_id: u32, buf: &[u8]) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(buf);
        Self::read(consensus_branch_id, &mut cursor)
    }
}

impl From<NodeData> for Entry {
    fn from(s: NodeData) -> Self {
        Entry { kind: EntryKind::Leaf, data: s }
    }
}
