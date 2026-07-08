//! An engine for migrating Zcash wallet funds from the Orchard value pool to the
//! Ironwood value pool.
//!
//! [Full crate docs are completed in Task 14; keep this header + the module wiring.]

#![deny(rustdoc::broken_intra_doc_links)]

mod denominations;
mod reserved_source;
mod scheduling;
mod split;
mod state;
mod store;

pub mod error;
pub mod types;

pub use error::{InvalidStateError, MigrationError};
pub use types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, SignedTransferPczt, TransferId, TransferProposal, TransferResult,
    UnsignedTransferPczt,
};
