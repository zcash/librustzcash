#[macro_use]
extern crate lazy_static;

extern crate aes;
extern crate blake2b_simd;
extern crate byteorder;
extern crate crypto_api_chachapoly;
extern crate ff;
extern crate fpe;
extern crate hex;
extern crate pairing;
extern crate rand;
extern crate rand_core;
extern crate rand_os;
extern crate sapling_crypto;
extern crate sha2;

#[cfg(test)]
extern crate rand_xorshift;

use sapling_crypto::jubjub::JubjubBls12;

pub mod block;
pub mod keys;
pub mod legacy;
pub mod merkle_tree;
pub mod note_encryption;
pub mod prover;
pub mod redjubjub;
pub mod sapling;
mod serialize;
pub mod transaction;
mod util;
pub mod zip32;

#[cfg(test)]
mod test_vectors;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
