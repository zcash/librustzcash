//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.
//!
//! ## Feature flags
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
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
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate alloc;

pub mod block;
pub(crate) mod encoding;
#[cfg(zcash_unstable = "zfuture")]
pub mod extensions;
pub mod merkle_tree;
pub mod transaction;

#[deprecated(note = "This module is deprecated; use `::zcash_protocol::consensus` instead.")]
pub mod consensus {
    pub use zcash_protocol::consensus::*;
}
#[deprecated(note = "This module is deprecated; use `::zcash_protocol::constants` instead.")]
pub mod constants {
    pub use zcash_protocol::constants::*;
}
#[deprecated(note = "This module is deprecated; use `::zcash_protocol::memo` instead.")]
pub mod memo {
    pub use zcash_protocol::memo::*;
}
#[deprecated(note = "This module is deprecated; use the `zip32` crate instead.")]
pub mod zip32 {
    pub use zip32::*;
}
#[deprecated(note = "This module is deprecated; use the `zcash_transparent` crate instead.")]
pub mod legacy {
    pub use transparent::address::*;
    #[cfg(feature = "transparent-inputs")]
    #[deprecated(note = "This module is deprecated; use `::zcash_transparent::keys` instead.")]
    pub mod keys {
        pub use transparent::keys::*;
    }
}
