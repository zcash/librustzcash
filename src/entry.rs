use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt, ByteOrder};

use crate::{EntryKind, NodeData, Error, EntryLink};

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
}

impl From<NodeData> for Entry {
    fn from(s: NodeData) -> Self {
        Entry { kind: EntryKind::Leaf, data: s }
    }
}
