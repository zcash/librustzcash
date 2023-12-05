//! *A crate for implementing Zcash light clients.*
//!
//! `zcash_client_backend` contains Rust structs and traits for creating shielded Zcash
//! light clients.

// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

pub mod address;
pub mod data_api;
mod decrypt;
pub mod encoding;
pub mod fees;
pub mod keys;
pub mod proto;
pub mod scan;
pub mod scanning;
pub mod wallet;
pub mod zip321;

#[cfg(feature = "unstable-serialization")]
pub mod serialization;

use std::fmt;

pub use decrypt::{decrypt_transaction, DecryptedOutput, TransferType};

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

/// A shielded transfer protocol supported by the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShieldedProtocol {
    /// The Sapling protocol
    Sapling,
    /// The Orchard protocol
    Orchard,
}

/// A value pool to which the wallet supports sending transaction outputs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PoolType {
    /// The transparent value pool
    Transparent,
    /// A shielded value pool.
    Shielded(ShieldedProtocol),
}

impl fmt::Display for PoolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolType::Transparent => f.write_str("Transparent"),
            PoolType::Shielded(ShieldedProtocol::Sapling) => f.write_str("Sapling"),
            PoolType::Shielded(ShieldedProtocol::Orchard) => f.write_str("Orchard"),
        }
    }
}
