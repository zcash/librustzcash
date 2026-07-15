//! An engine for migrating Zcash wallet funds from the Orchard value pool to the Ironwood value
//! pool.
//!
//! The engine plans a note split into self-funding `{1, 2, 5} * 10^k` denominations, builds and
//! signs
//! migration transactions as PCZTs, schedules them by block height, and persists its state in the
//! wallet database; the consuming application broadcasts the transactions and reports results
//! back.
//!
//! Inspired by an original implementation by Adam Tucker from ValarGroup, originally made
//! available in [Vizor Wallet](https://github.com/chainapsis/vizor-wallet).

#![deny(rustdoc::broken_intra_doc_links)]

pub mod types;

pub use types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, Signed, SignedTransferPczt, TransferId, TransferPczt, TransferProposal,
    TransferResult, Unsigned, UnsignedTransferPczt,
};
