//! An engine for migrating Zcash wallet funds from the Orchard value pool to the
//! Ironwood value pool.
//!
//! [Full crate docs are completed in Task 14; keep this header + the module wiring.]

#![deny(rustdoc::broken_intra_doc_links)]

pub mod error;

pub use error::{InvalidStateError, MigrationError};
