//! *A crate for Zcash protocol constants and value types.*
//!
//! `zcash_protocol` contains Rust structs, traits and functions that provide the network constants
//! for the Zcash main and test networks, as well types for representing ZEC amounts and value
//! balances.
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

pub mod consensus;
pub mod constants;
