use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use zcash_primitives::{block::BlockHash, consensus::BlockHeight, transaction::TxId};
use zcash_protocol::memo::MemoBytes;

use zcash_client_backend::wallet::NoteId;

/// Internal wallet representation of a Block.
pub(crate) struct MemoryWalletBlock {
    pub(crate) height: BlockHeight,
    pub(crate) hash: BlockHash,
    pub(crate) block_time: u32,
    // Just the transactions that involve an account in this wallet
    pub(crate) _transactions: HashSet<TxId>,
    pub(crate) _memos: HashMap<NoteId, MemoBytes>,
    pub(crate) sapling_commitment_tree_size: Option<u32>,
    pub(crate) _sapling_output_count: Option<u32>,
    #[cfg(feature = "orchard")]
    pub(crate) orchard_commitment_tree_size: Option<u32>,
    #[cfg(feature = "orchard")]
    pub(crate) _orchard_action_count: Option<u32>,
}

impl PartialEq for MemoryWalletBlock {
    fn eq(&self, other: &Self) -> bool {
        (self.height, self.block_time) == (other.height, other.block_time)
    }
}

impl Eq for MemoryWalletBlock {}

impl PartialOrd for MemoryWalletBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some((self.height, self.block_time).cmp(&(other.height, other.block_time)))
    }
}

impl Ord for MemoryWalletBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.height, self.block_time).cmp(&(other.height, other.block_time))
    }
}
