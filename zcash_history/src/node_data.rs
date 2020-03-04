use bigint::U256;
use blake2::Params as Blake2Params;
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};

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
    9; // Sapling tx count (compact uint)
       // = total of 171

/// Node metadata.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[cfg_attr(test, derive(PartialEq))]
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

fn blake2b_personal(personalization: &[u8], input: &[u8]) -> [u8; 32] {
    let hash_result = Blake2Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state()
        .update(input)
        .finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash_result.as_bytes());
    result
}

fn personalization(branch_id: u32) -> [u8; 16] {
    let mut result = [0u8; 16];
    result[..12].copy_from_slice(b"ZcashHistory");
    LittleEndian::write_u32(&mut result[12..], branch_id);
    result
}

impl NodeData {
    /// Combine two nodes metadata.
    pub fn combine(left: &NodeData, right: &NodeData) -> NodeData {
        assert_eq!(left.consensus_branch_id, right.consensus_branch_id);

        let mut hash_buf = [0u8; MAX_NODE_DATA_SIZE * 2];
        let size = {
            let mut cursor = ::std::io::Cursor::new(&mut hash_buf[..]);
            left.write(&mut cursor)
                .expect("Writing to memory buf with enough length cannot fail; qed");
            right
                .write(&mut cursor)
                .expect("Writing to memory buf with enough length cannot fail; qed");
            cursor.position() as usize
        };

        let hash = blake2b_personal(
            &personalization(left.consensus_branch_id),
            &hash_buf[..size],
        );

        NodeData {
            consensus_branch_id: left.consensus_branch_id,
            subtree_commitment: hash,
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
        let mut data = Self::default();
        data.consensus_branch_id = consensus_branch_id;
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
        let mut buf = [0u8; MAX_NODE_DATA_SIZE];
        let pos = {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            self.write(&mut cursor).expect("Cursor cannot fail");
            cursor.position() as usize
        };

        buf[0..pos].to_vec()
    }

    /// Convert from byte representation.
    pub fn from_bytes<T: AsRef<[u8]>>(consensus_branch_id: u32, buf: T) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(buf);
        Self::read(consensus_branch_id, &mut cursor)
    }

    /// Hash node metadata
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();

        blake2b_personal(&personalization(self.consensus_branch_id), &bytes)
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for NodeData {
    fn arbitrary<G: quickcheck::Gen>(gen: &mut G) -> Self {
        let mut node_data = NodeData::default();
        node_data.consensus_branch_id = 0;
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
            TestResult::from_bool(NodeData::from_bytes(0, &node_data.to_bytes()).unwrap() == node_data)
        }
    }
}
