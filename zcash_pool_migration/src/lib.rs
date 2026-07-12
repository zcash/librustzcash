//! An engine for migrating Zcash wallet funds from the Orchard value pool to the Ironwood value
//! pool.
//!
//! This crate is under construction. Its public surface will be the `MigrationContext` facade;
//! for now it exposes the foundational [`error`] and [`types`] modules that the rest of the
//! engine is built on. See [`types`] for the public data-type catalogue (private fields,
//! `from_parts` constructors, and accessor methods throughout — no `serde` anywhere in this
//! crate) and [`error`] for the error types.

#![deny(rustdoc::broken_intra_doc_links)]
// The engine is being landed module by module: the constructors and accessors below are exercised
// by the wallet-facing layers (`store`, `backend`, `context`) that land in later commits. Allow
// dead code until then; the allowance is removed in the commit that wires up `MigrationContext`.
#![allow(dead_code)]

pub mod error;
pub mod types;

pub use error::{InvalidStateError, MigrationError};
pub use types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, SignedTransferPczt, TransferId, TransferProposal, TransferResult,
    UnsignedTransferPczt,
};
