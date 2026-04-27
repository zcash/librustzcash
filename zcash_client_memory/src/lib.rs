mod block_source;
mod error;
mod input_source;
pub mod proto;
mod types;
mod wallet_commitment_trees;
mod wallet_read;
mod wallet_write;

#[cfg(test)]
pub mod testing;
pub use block_source::*;
pub use error::Error;
pub use types::MemoryWalletDb;
// Re-export types needed for transaction history feature
pub(crate) use types::*;
pub use types::{
    ReceivedNote, ReceivedNoteTable, SentNote, SentNoteTable, TransactionEntry, TransactionTable,
};

/// The maximum number of blocks the wallet is allowed to rewind. This is
/// consistent with the bound in zcashd, and allows block data deeper than
/// this delta from the chain tip to be pruned.
pub(crate) const PRUNING_DEPTH: u32 = 100;

/// The number of blocks to verify ahead when the chain tip is updated.
pub(crate) const VERIFY_LOOKAHEAD: u32 = 10;
