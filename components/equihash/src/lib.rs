//! Equihash is a Proof-of-Work algorithm, based on a generalization of the Birthday
//! problem which finds colliding hash values. It was designed to be memory-hard; more
//! specifically, the bottle-neck for parallel implementations of Equihash solvers would
//! be memory bandwidth.
//!
//! This crate implements Equihash as specified for the Zcash consensus rules. It can
//! verify solutions for any valid `(n, k)` parameters, as long as the row indices are no
//! larger than 32 bits (that is, `ceiling(((n / (k + 1)) + 1) / 8) <= 4`).
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!
//! References
//! ==========
//! - [Section 7.6.1: Equihash.] Zcash Protocol Specification, version 2020.1.10 or later.
//! - Alex Biryukov and Dmitry Khovratovich.
//!   [*Equihash: Asymmetric Proof-of-Work Based on the Generalized Birthday Problem.*][BK16]
//!   NDSS ’16.
//!
//! [Section 7.6.1: Equihash.]: https://zips.z.cash/protocol/protocol.pdf#equihash
//! [BK16]: https://www.internetsociety.org/sites/default/files/blogs-media/equihash-asymmetric-proof-of-work-based-generalized-birthday-problem.pdf

// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate alloc;

mod minimal;
mod params;
mod verify;

#[cfg(test)]
mod test_vectors;

pub use verify::{is_valid_solution, Error};

#[cfg(feature = "solver")]
mod blake2b;
#[cfg(feature = "solver")]
pub mod tromp;
