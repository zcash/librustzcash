use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use primitive_types::U256;

use crate::Version;

/// Maximum serialized size of the node metadata.
pub const MAX_NODE_DATA_SIZE: usize = 32 + // subtree commitment
    4 +  // start time
    4 +  // end time
    4 +  // start target
    4 +  // end target
    32 + // start sapling tree root
    32 + // end sapling tree root
    32 + // subtree total work
    9 +  // start height (compact uint)
    9 +  // end height (compact uint)
    9 + // Sapling tx count (compact uint)
    32 + // start Orchard tree root
    32 + // end Orchard tree root
    9; // Orchard tx count (compact uint)
       // = total of 244

/// V1 node metadata.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct NodeData {
    /// Consensus branch id, should be provided by deserializing node.
    pub consensus_branch_id: u32,
    /// Subtree commitment - either block hash for leaves or hashsum of children for nodes.
    pub subtree_commitment: [u8; 32],
    /// Start time.
    pub start_time: u32,
    /// End time.
    pub end_time: u32,
    /// Start target.
    pub start_target: u32,
    /// End target.
    pub end_target: u32,
    /// Start sapling tree root.
    pub start_sapling_root: [u8; 32],
    /// End sapling tree root.
    pub end_sapling_root: [u8; 32],
    /// Part of tree total work.
    pub subtree_total_work: U256,
    /// Start height.
    pub start_height: u64,
    /// End height
    pub end_height: u64,
    /// Number of Sapling transactions.
    pub sapling_tx: u64,
}

impl NodeData {
    /// Combine two nodes metadata.
    pub fn combine(left: &NodeData, right: &NodeData) -> NodeData {
        crate::V1::combine(left, right)
    }

    pub(crate) fn combine_inner(
        subtree_commitment: [u8; 32],
        left: &NodeData,
        right: &NodeData,
    ) -> NodeData {
        NodeData {
            consensus_branch_id: left.consensus_branch_id,
            subtree_commitment,
            start_time: left.start_time,
            end_time: right.end_time,
            start_target: left.start_target,
            end_target: right.end_target,
            start_sapling_root: left.start_sapling_root,
            end_sapling_root: right.end_sapling_root,
            subtree_total_work: left.subtree_total_work + right.subtree_total_work,
            start_height: left.start_height,
            end_height: right.end_height,
            sapling_tx: left.sapling_tx + right.sapling_tx,
        }
    }

    fn write_compact<W: std::io::Write>(w: &mut W, compact: u64) -> std::io::Result<()> {
        match compact {
            0..=0xfc => w.write_all(&[compact as u8])?,
            0xfd..=0xffff => {
                w.write_all(&[0xfd])?;
                w.write_u16::<LittleEndian>(compact as u16)?;
            }
            0x10000..=0xffff_ffff => {
                w.write_all(&[0xfe])?;
                w.write_u32::<LittleEndian>(compact as u32)?;
            }
            _ => {
                w.write_all(&[0xff])?;
                w.write_u64::<LittleEndian>(compact)?;
            }
        }
        Ok(())
    }

    fn read_compact<R: std::io::Read>(reader: &mut R) -> std::io::Result<u64> {
        let result = match reader.read_u8()? {
            i @ 0..=0xfc => i.into(),
            0xfd => reader.read_u16::<LittleEndian>()?.into(),
            0xfe => reader.read_u32::<LittleEndian>()?.into(),
            _ => reader.read_u64::<LittleEndian>()?,
        };

        Ok(result)
    }

    /// Write to the byte representation.
    pub fn write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.subtree_commitment)?;
        w.write_u32::<LittleEndian>(self.start_time)?;
        w.write_u32::<LittleEndian>(self.end_time)?;
        w.write_u32::<LittleEndian>(self.start_target)?;
        w.write_u32::<LittleEndian>(self.end_target)?;
        w.write_all(&self.start_sapling_root)?;
        w.write_all(&self.end_sapling_root)?;

        let mut work_buf = [0u8; 32];
        self.subtree_total_work.to_little_endian(&mut work_buf[..]);
        w.write_all(&work_buf)?;

        Self::write_compact(w, self.start_height)?;
        Self::write_compact(w, self.end_height)?;
        Self::write_compact(w, self.sapling_tx)?;
        Ok(())
    }

    /// Read from the byte representation.
    pub fn read<R: std::io::Read>(consensus_branch_id: u32, r: &mut R) -> std::io::Result<Self> {
        let mut data = NodeData {
            consensus_branch_id,
            ..Default::default()
        };
        r.read_exact(&mut data.subtree_commitment)?;
        data.start_time = r.read_u32::<LittleEndian>()?;
        data.end_time = r.read_u32::<LittleEndian>()?;
        data.start_target = r.read_u32::<LittleEndian>()?;
        data.end_target = r.read_u32::<LittleEndian>()?;
        r.read_exact(&mut data.start_sapling_root)?;
        r.read_exact(&mut data.end_sapling_root)?;

        let mut work_buf = [0u8; 32];
        r.read_exact(&mut work_buf)?;
        data.subtree_total_work = U256::from_little_endian(&work_buf);

        data.start_height = Self::read_compact(r)?;
        data.end_height = Self::read_compact(r)?;
        data.sapling_tx = Self::read_compact(r)?;

        Ok(data)
    }

    /// Convert to byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::V1::to_bytes(self)
    }

    /// Convert from byte representation.
    pub fn from_bytes<T: AsRef<[u8]>>(consensus_branch_id: u32, buf: T) -> std::io::Result<Self> {
        crate::V1::from_bytes(consensus_branch_id, buf)
    }

    /// Hash node metadata
    pub fn hash(&self) -> [u8; 32] {
        crate::V1::hash(self)
    }
}

/// V2 node metadata.
#[derive(Debug, Clone, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct V2 {
    /// The V1 node data retained in V2.
    pub v1: NodeData,
    /// Start Orchard tree root.
    pub start_orchard_root: [u8; 32],
    /// End Orchard tree root.
    pub end_orchard_root: [u8; 32],
    /// Number of Orchard transactions.
    pub orchard_tx: u64,
}

impl V2 {
    pub(crate) fn combine_inner(subtree_commitment: [u8; 32], left: &V2, right: &V2) -> V2 {
        V2 {
            v1: NodeData::combine_inner(subtree_commitment, &left.v1, &right.v1),
            start_orchard_root: left.start_orchard_root,
            end_orchard_root: right.end_orchard_root,
            orchard_tx: left.orchard_tx + right.orchard_tx,
        }
    }

    /// Write to the byte representation.
    pub fn write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        self.v1.write(w)?;
        w.write_all(&self.start_orchard_root)?;
        w.write_all(&self.end_orchard_root)?;
        NodeData::write_compact(w, self.orchard_tx)?;
        Ok(())
    }

    /// Read from the byte representation.
    pub fn read<R: std::io::Read>(consensus_branch_id: u32, r: &mut R) -> std::io::Result<Self> {
        let mut data = V2 {
            v1: NodeData::read(consensus_branch_id, r)?,
            ..Default::default()
        };
        r.read_exact(&mut data.start_orchard_root)?;
        r.read_exact(&mut data.end_orchard_root)?;
        data.orchard_tx = NodeData::read_compact(r)?;

        Ok(data)
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for NodeData {
    fn arbitrary<G: quickcheck::Gen>(gen: &mut G) -> Self {
        let mut node_data = NodeData {
            consensus_branch_id: 0,
            ..Default::default()
        };
        gen.fill_bytes(&mut node_data.subtree_commitment[..]);
        node_data.start_time = gen.next_u32();
        node_data.end_time = gen.next_u32();
        node_data.start_target = gen.next_u32();
        node_data.end_target = gen.next_u32();
        gen.fill_bytes(&mut node_data.start_sapling_root[..]);
        gen.fill_bytes(&mut node_data.end_sapling_root[..]);
        let mut number = [0u8; 32];
        gen.fill_bytes(&mut number[..]);
        node_data.subtree_total_work = U256::from_little_endian(&number[..]);
        node_data.start_height = gen.next_u64();
        node_data.end_height = gen.next_u64();
        node_data.sapling_tx = gen.next_u64();

        node_data
    }
}

#[cfg(test)]
mod tests {
    use super::NodeData;
    use quickcheck::{quickcheck, TestResult};

    quickcheck! {
        fn serialization_round_trip(node_data: NodeData) -> TestResult {
            TestResult::from_bool(NodeData::from_bytes(0, node_data.to_bytes()).unwrap() == node_data)
        }
    }
}
