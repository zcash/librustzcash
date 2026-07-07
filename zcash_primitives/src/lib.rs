//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.
//!
//! ## Feature flags
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Present to reduce refactoring noise from changing all the imports inside this crate for
// the `sapling` crate extraction.
#![allow(clippy::single_component_path_imports)]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate alloc;

pub mod block;
pub(crate) mod encoding;
pub mod merkle_tree;
pub mod transaction;

/// Re-export of the `orchard` crate, whose types appear in this crate's public API
/// (such as the bundle type carried by `BuildConfig::Standard`). This lets downstream
/// crates that treat their own `orchard` dependency as optional still name those types.
pub use orchard;
