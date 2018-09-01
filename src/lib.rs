// This crate is `no_std` unless test mode is enabled.
#![cfg_attr(not(test), no_std)]

// Import `core` explicitly (it is imported implicitly
// when `no_std` is enabled, but this does not occur
// during testing)
#[cfg(test)]
extern crate core;

extern crate byteorder;
extern crate subtle;

mod fq;
pub use fq::*;
