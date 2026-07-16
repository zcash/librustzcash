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

// Internal note-split planner, consumed by the context module.
mod note_splitting;
// Internal transfer scheduler, consumed by the context module.
mod scheduling;
// The pure PCZT pipeline, consumed by the context module.
mod pipeline;

// Pure PCZT construction from plain-data ingredients; consumed by a wallet backend once it supplies
// the notes, witnesses, anchor, and recipient (see the module docs).
pub mod build;
pub mod context;
pub mod error;
pub mod state;
pub mod store;
pub mod types;
pub mod wallet;

pub use context::MigrationContext;
pub use error::{InvalidStateError, MigrationError};
pub use state::Phase;
pub use store::{
    MigrationStore, NewRun, NoteSplitTxRow, PreparedNote, RunRow, ScheduledTransferRow, StagedKind,
    StagedPczt, TransferTotals,
};
pub use types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, Signed, SignedTransferPczt, TransferId, TransferPczt, TransferProposal,
    TransferResult, Unsigned, UnsignedTransferPczt,
};
pub use wallet::{
    NoteRef, PoolBalances, SpentNote, SplitOutputs, TransferBuild, WalletMigrationBackend,
};
