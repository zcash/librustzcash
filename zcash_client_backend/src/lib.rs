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
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

pub mod data_api;
mod decrypt;
pub mod fees;
pub mod proposal;
pub mod proto;
pub mod scan;
pub mod scanning;
pub mod wallet;

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(feature = "unstable-serialization")]
pub mod serialization;

#[cfg(feature = "tor")]
pub mod tor;

pub use decrypt::{DecryptedOutput, TransferType, decrypt_transaction};

#[cfg(zcash_unstable = "nu7")]
use orchard::note::AssetBase;

#[deprecated(note = "This module is deprecated; use `::zcash_keys::address` instead.")]
pub mod address {
    pub use zcash_keys::address::*;
}
#[deprecated(note = "This module is deprecated; use `::zcash_keys::encoding` instead.")]
pub mod encoding {
    pub use zcash_keys::encoding::*;
}
#[deprecated(note = "This module is deprecated; use `::zcash_keys::keys` instead.")]
pub mod keys {
    pub use zcash_keys::keys::*;
}
#[deprecated(note = "use ::zcash_protocol::PoolType instead")]
pub type PoolType = zcash_protocol::PoolType;
#[deprecated(note = "use ::zcash_protocol::ShieldedProtocol instead")]
pub type ShieldedProtocol = zcash_protocol::ShieldedProtocol;
#[deprecated(note = "This module is deprecated; use the `zip321` crate instead.")]
pub mod zip321 {
    pub use zip321::*;
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

/// This is a helper function that indicates no assets are newly created.
#[cfg(zcash_unstable = "nu7")]
fn no_new_assets(_: &AssetBase) -> bool {
    false
}
