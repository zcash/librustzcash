use hex;
use std::fmt;
use std::ops::Deref;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHash(pub [u8; 32]);

impl fmt::Display for BlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut data = self.0.to_vec();
        data.reverse();
        formatter.write_str(&hex::encode(data))
    }
}

/// A Zcash block header.
pub struct BlockHeader(BlockHeaderData);

impl Deref for BlockHeader {
    type Target = BlockHeaderData;

    fn deref(&self) -> &BlockHeaderData {
        &self.0
    }
}

pub struct BlockHeaderData {
    pub version: i32,
    pub prev_block: BlockHash,
    pub merkle_root: [u8; 32],
    pub final_sapling_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: [u8; 32],
    pub solution: Vec<u8>,
}

impl BlockHeaderData {
    pub fn freeze(self) -> BlockHeader {
        BlockHeader(self)
    }
}
