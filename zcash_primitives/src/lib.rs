//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.
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
// Present to reduce refactoring noise from changing all the imports inside this crate for
// the `sapling` crate extraction.
#![allow(clippy::single_component_path_imports)]

pub mod block;
pub mod consensus;
pub mod constants;
pub mod legacy;
pub mod memo;
pub mod merkle_tree;
use sapling;
pub mod transaction;
pub use zip32;
pub mod zip339;

#[cfg(feature = "zfuture")]
pub mod extensions;
