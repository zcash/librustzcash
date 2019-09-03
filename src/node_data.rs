use byteorder::{LittleEndian, WriteBytesExt};

use bigint::U256;

/// Node metadata.
#[repr(C)]
#[derive(Debug)]
pub struct NodeData {
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

impl NodeData {
    pub const MAX_SERIALIZED_SIZE: usize = 32 + 4 + 4 + 4 + 4 + 32 + 32 + 32 + 9 + 9 + 9; // =171;

    pub fn combine(left: &NodeData, right: &NodeData) -> NodeData {
        NodeData {
            // TODO: hash children
            subtree_commitment: [0u8; 32],
            start_time: left.start_time,
            end_time: right.end_time,
            start_target: left.start_target,
            end_target: right.end_target,
            start_sapling_root: left.start_sapling_root,
            end_sapling_root: right.end_sapling_root,

            // TODO: sum work?
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