//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.
//!
//! ## Feature flags
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!
//! ## Protocol domains and the byte layer
//!
//! The `sapling` and `orchard` features select which shielded protocol domain
//! types this crate constructs. The byte layer
//! ([`transaction::bytes`], [`transaction::zip248`], and the byte-level
//! [`transaction::txid`] digest functions) is always available and does not
//! depend on either protocol crate, so a wallet that handles only one shielded
//! protocol can parse every wire format without linking the other.
//!
//! The typed transaction API exposes each shielded protocol's fields,
//! accessors, conversions, and digests under its corresponding feature. Typed
//! reading rejects a bundle whose protocol is disabled instead of discarding
//! it. The builder, `block::Block`, and full ZIP 248 validation require both
//! protocol features. PCZT construction does not require `circuits`; proof
//! creation does. Block hashes and headers are available independently of the
//! protocol features.
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Present to reduce refactoring noise from changing all the imports inside this crate for
// the `sapling` crate extraction.
#![allow(clippy::single_component_path_imports)]
#![no_std]

#[cfg(any(feature = "std", test))]
extern crate std;

#[macro_use]
extern crate alloc;

pub mod block;
pub(crate) mod encoding;
pub mod merkle_tree;
pub mod transaction;
