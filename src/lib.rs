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

/// Notes about how the BLS12-381 elliptic curve is designed, specified
/// and implemented by this library.
pub mod notes {
    pub mod design;
}

mod scalar;

pub use scalar::Scalar;

#[cfg(feature = "groups")]
mod fp;
#[cfg(feature = "groups")]
mod fp2;
#[cfg(feature = "groups")]
mod g1;
#[cfg(feature = "groups")]
mod g2;

#[cfg(feature = "groups")]
pub use g1::{G1Affine, G1Projective};
#[cfg(feature = "groups")]
pub use g2::{G2Affine, G2Projective};

// TODO: This should be upstreamed to subtle.
// See https://github.com/dalek-cryptography/subtle/pull/48
trait CtOptionExt<T> {
    /// Calls f() and either returns self if it contains a value,
    /// or returns the output of f() otherwise.
    fn or_else<F: FnOnce() -> subtle::CtOption<T>>(self, f: F) -> subtle::CtOption<T>;
}

impl<T: subtle::ConditionallySelectable> CtOptionExt<T> for subtle::CtOption<T> {
    fn or_else<F: FnOnce() -> subtle::CtOption<T>>(self, f: F) -> subtle::CtOption<T> {
        let is_none = self.is_none();
        let f = f();

        subtle::ConditionallySelectable::conditional_select(&self, &f, is_none)
    }
}
