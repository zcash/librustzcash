//! *Zcash Rust APIs.*
//!
//! ## Feature flags
#![doc = document_features::document_features!()]
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use zcash_primitives as primitives;
