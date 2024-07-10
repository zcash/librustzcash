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
pub mod proposal;
pub mod proto;
pub mod scan;
pub mod scanning;
pub mod wallet;
pub use zip321;

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(feature = "unstable-serialization")]
pub mod serialization;

pub use decrypt::{decrypt_transaction, DecryptedOutput, TransferType};
pub use zcash_protocol::{PoolType, ShieldedProtocol};

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
