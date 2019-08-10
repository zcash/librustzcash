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
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]

#[cfg(feature = "pairings")]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[macro_use]
mod util;

mod scalar;

pub use scalar::Scalar;
