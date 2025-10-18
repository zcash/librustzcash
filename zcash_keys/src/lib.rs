//! *A crate for Zcash key and address management.*
//!
//! `zcash_keys` contains Rust structs, traits and functions for creating Zcash spending
//! and viewing keys and addresses.
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod address;
pub mod encoding;

#[cfg(any(
    feature = "orchard",
    feature = "sapling",
    feature = "transparent-inputs"
))]
pub mod keys;
