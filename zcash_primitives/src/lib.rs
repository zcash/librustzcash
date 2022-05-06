//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

pub mod block;
pub mod consensus;
pub mod constants;
pub mod keys;
pub mod legacy;
pub mod memo;
pub mod merkle_tree;
pub mod sapling;
pub mod transaction;
pub mod zip32;
pub mod zip339;

#[cfg(feature = "zfuture")]
pub mod extensions;

#[cfg(test)]
mod test_vectors;
