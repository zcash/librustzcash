//! # Zcash transparent protocol
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]

pub mod address;
pub mod builder;
pub mod bundle;
pub mod keys;
pub mod pczt;
pub mod sighash;
#[cfg(feature = "transparent-inputs")]
pub mod zip48;

#[cfg(test)]
mod test_vectors;

#[macro_use]
extern crate alloc;
