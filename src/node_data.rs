use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt, ByteOrder};
use bigint::U256;
use blake2::blake2b::Blake2b;

/// Node metadata.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct NodeData {
    pub consensus_branch_id: u32,
    pub subtree_commitment: [u8; 32],
    pub start_time: u32,
    pub end_time: u32,
    pub start_target: u32,
    pub end_target: u32,
    pub start_sapling_root: [u8; 32],
    pub end_sapling_root: [u8; 32],
    pub subtree_total_work: U256,
    pub start_height: u64,
    pub end_height: u64,
    pub shielded_tx: u64,
}

fn blake2b_personal(personalization: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::with_params(32, &[], &[], personalization);
    hasher.update(input);
    let mut result = [0u8; 32];
    result.copy_from_slice(hasher.finalize().as_bytes());
    result
}

fn personalization(branch_id: u32) -> [u8; 16] {
    let mut result = [0u8; 16];
    result[..12].copy_from_slice(b"ZcashHistory");
    LittleEndian::write_u32(&mut result[12..], branch_id);
    result
}

impl NodeData {
    pub const MAX_SERIALIZED_SIZE: usize = 32 + 4 + 4 + 4 + 4 + 32 + 32 + 32 + 9 + 9 + 9; // =171;

    pub fn combine(left: &NodeData, right: &NodeData) -> NodeData {
        assert_eq!(left.consensus_branch_id, right.consensus_branch_id);

        let mut hash_buf = [0u8; Self::MAX_SERIALIZED_SIZE * 2];
        let size = {
            let mut cursor = ::std::io::Cursor::new(&mut hash_buf[..]);
            left.write(&mut cursor).expect("Writing to memory buf with enough length cannot fail; qed");
            right.write(&mut cursor).expect("Writing to memory buf with enough length cannot fail; qed");
            cursor.position() as usize
        };

        let hash = blake2b_personal(
            &personalization(left.consensus_branch_id),
            &hash_buf[..size]
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
            shielded_tx: left.shielded_tx + right.shielded_tx,
        }
    }

    fn write_compact<W: std::io::Write>(w: &mut W, compact: u64) -> std::io::Result<()> {
        match compact {
            0..=0xfc => {
                w.write_all(&[compact as u8])?
            },
            0xfd..=0xffff => {
                w.write_all(&[0xfd])?;
                w.write_u16::<LittleEndian>(compact as u16)?;
            },
            0x10000..=0xffff_ffff => {
                w.write_all(&[0xfe])?;
                w.write_u32::<LittleEndian>(compact as u32)?;
            },
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
            _ => reader.read_u64::<LittleEndian>()?.into(),
        };

        Ok(result)
    }

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
        Self::write_compact(w, self.shielded_tx)?;
        Ok(())
    }

    pub fn read<R: std::io::Read>(consensus_branch_id: u32, r: &mut R) -> std::io::Result<Self> {
        let mut data = Self::default();
        data.consensus_branch_id = consensus_branch_id;
        r.read_exact(&mut data.subtree_commitment)?;
        data.start_time = r.read_u32::<LittleEndian>()?;
        data.end_time = r.read_u32::<LittleEndian>()?;
        data.start_target= r.read_u32::<LittleEndian>()?;
        data.end_target= r.read_u32::<LittleEndian>()?;
        r.read_exact(&mut data.start_sapling_root)?;
        r.read_exact(&mut data.end_sapling_root)?;

        let mut work_buf = [0u8; 32];
        r.read_exact(&mut work_buf)?;
        data.subtree_total_work = U256::from_little_endian(&work_buf);

        data.start_height = Self::read_compact(r)?;
        data.end_height = Self::read_compact(r)?;
        data.shielded_tx = Self::read_compact(r)?;

        Ok(data)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; Self::MAX_SERIALIZED_SIZE];
        let pos = {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            self.write(&mut cursor).expect("Cursor cannot fail");
            cursor.position() as usize
        };

        buf[0..pos].to_vec()
    }
}