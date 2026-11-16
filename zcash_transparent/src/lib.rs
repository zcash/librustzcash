//! # Zcash transparent protocol
//!
//! The value of a transparent output has a type `V` that the caller chooses; see
//! [`bundle::TxOut`].
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod address;
pub mod builder;
pub mod bundle;
pub mod pczt;
pub mod sighash;
pub mod util;

#[macro_use]
extern crate alloc;
