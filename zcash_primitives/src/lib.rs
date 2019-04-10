#[macro_use]
extern crate lazy_static;

extern crate aes;
extern crate blake2_rfc;
extern crate byteorder;
extern crate crypto_api_chachapoly;
extern crate ff;
extern crate fpe;
extern crate hex;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sha2;

use sapling_crypto::jubjub::JubjubBls12;

pub mod block;
pub mod keys;
pub mod note_encryption;
pub mod sapling;
mod serialize;
pub mod transaction;
pub mod zip32;

#[cfg(test)]
mod test_vectors;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
