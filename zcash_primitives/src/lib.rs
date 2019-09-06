//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

pub mod block;
pub mod constants;
pub mod group_hash;
pub mod jubjub;
pub mod keys;
pub mod legacy;
pub mod merkle_tree;
pub mod note_encryption;
pub mod pedersen_hash;
pub mod primitives;
pub mod prover;
pub mod redjubjub;
pub mod sapling;
pub mod serialize;
pub mod transaction;
mod util;
pub mod zip32;

#[cfg(test)]
mod test_vectors;

use crate::jubjub::JubjubBls12;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
