//! # `bls12_381`
//!
//! This crate provides an implementation of the BLS12-381 pairing-friendly elliptic
//! curve construction.
//!
//! * **This implementation has not been reviewed or audited. Use at your own risk.**
//! * This implementation targets Rust `1.36` or later.
//! * This implementation does not require the Rust standard library.
//! * All operations are constant time unless explicitly noted.

#![no_std]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg(feature = "pairings")]
extern crate alloc;

#[cfg(test)]
extern crate std;
