//! *A crate for Zcash protocol constants and value types.*
//!
//! `zcash_protocol` contains Rust structs, traits and functions that provide the network constants
//! for the Zcash main and test networks, as well types for representing ZEC amounts and value
//! balances.
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

#[cfg_attr(any(test, feature = "test-dependencies"), macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

pub mod consensus;
pub mod constants;
#[cfg(feature = "local-consensus")]
pub mod local_consensus;
pub mod memo;
pub mod value;

mod txid;
pub use txid::TxId;

/// A Zcash shielded transfer protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShieldedProtocol {
    /// The Sapling protocol
    Sapling,
    /// The Orchard protocol
    Orchard,
}

/// A value pool in the Zcash protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PoolType {
    /// The transparent value pool
    Transparent,
    /// A shielded value pool.
    Shielded(ShieldedProtocol),
}

impl PoolType {
    pub const TRANSPARENT: PoolType = PoolType::Transparent;
    pub const SAPLING: PoolType = PoolType::Shielded(ShieldedProtocol::Sapling);
    pub const ORCHARD: PoolType = PoolType::Shielded(ShieldedProtocol::Orchard);
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
