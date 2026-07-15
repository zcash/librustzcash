//! An engine for migrating Zcash wallet funds from the Orchard value pool to the Ironwood value
//! pool.
//!
//! The engine plans a note split into self-funding power-of-ten denominations, builds and signs
//! migration transactions as PCZTs, schedules them by block height, and persists its state in the
//! wallet database; the consuming application broadcasts the transactions and reports results
//! back.
//!
//! See [`types`] for the public data types the engine exchanges with the platform: they have
//! private fields with `from_parts`-style constructors and accessor methods, derive no `serde`,
//! and — where a value has a signing lifecycle — encode that lifecycle in the type system (see
//! [`types::TransferPczt`]).

#![deny(rustdoc::broken_intra_doc_links)]

pub mod types;

pub use types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, Signed, SignedTransferPczt, TransferId, TransferPczt, TransferProposal,
    TransferResult, Unsigned, UnsignedTransferPczt,
};
