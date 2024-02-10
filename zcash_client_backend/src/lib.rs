//! *A crate for implementing Zcash light clients.*
//!
//! `zcash_client_backend` contains Rust structs and traits for creating shielded Zcash
//! light clients.
//!
//! # Design
//!
//! ## Wallet sync
//!
//! The APIs in the [`data_api::chain`] module can be used to implement the following
//! synchronization flow:
//!
//! ```text
//!                          ┌─────────────┐  ┌─────────────┐
//!                          │Get required │  │   Update    │
//!                          │subtree root │─▶│subtree roots│
//!                          │    range    │  └─────────────┘
//!                          └─────────────┘         │
//!                                                  ▼
//!                                             ┌─────────┐
//!                                             │ Update  │
//!           ┌────────────────────────────────▶│chain tip│◀──────┐
//!           │                                 └─────────┘       │
//!           │                                      │            │
//!           │                                      ▼            │
//!    ┌─────────────┐        ┌────────────┐  ┌─────────────┐     │
//!    │  Truncate   │        │Split range │  │Get suggested│     │
//!    │  wallet to  │        │into batches│◀─│ scan ranges │     │
//!    │rewind height│        └────────────┘  └─────────────┘     │
//!    └─────────────┘               │                            │
//!           ▲                     ╱│╲                           │
//!           │      ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─              │
//!      ┌────────┐         ┌───────────────┐       │             │
//!      │ Choose │  │      │Download blocks│                     │
//!      │ rewind │         │   to cache    │       │             │
//!      │ height │  │      └───────────────┘           .───────────────────.
//!      └────────┘                 │               │  ( Scan ranges updated )
//!           ▲      │              ▼                   `───────────────────'
//!           │               ┌───────────┐         │             ▲
//!  .───────────────┴─.      │Scan cached│    .─────────.        │
//! ( Continuity error  )◀────│  blocks   │──▶(  Success  )───────┤
//!  `───────────────┬─'      └───────────┘    `─────────'        │
//!                                 │               │             │
//!                  │       ┌──────┴───────┐                     │
//!                          ▼              ▼       │             ▼
//!                  │┌─────────────┐┌─────────────┐  ┌──────────────────────┐
//!                   │Delete blocks││   Enhance   ││ │Update wallet balance │
//!                  ││ from cache  ││transactions │  │  and sync progress   │
//!                   └─────────────┘└─────────────┘│ └──────────────────────┘
//!                  └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
//! ```
//!
//! ## Feature flags
#![doc = document_features::document_features!()]
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

pub use zcash_keys::address;
pub mod data_api;
mod decrypt;
pub use zcash_keys::encoding;
pub mod fees;
pub use zcash_keys::keys;
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

#[cfg(all(feature = "orchard", not(zcash_unstable = "orchard")))]
core::compile_error!(
    "The `orchard` feature flag requires the `zcash_unstable=\"orchard\"` RUSTFLAG."
);

/// A shielded transfer protocol known to the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShieldedProtocol {
    /// The Sapling protocol
    Sapling,
    /// The Orchard protocol
    #[cfg(zcash_unstable = "orchard")]
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
            #[cfg(zcash_unstable = "orchard")]
            PoolType::Shielded(ShieldedProtocol::Orchard) => f.write_str("Orchard"),
        }
    }
}
