#[macro_use]
extern crate lazy_static;

extern crate blake2_rfc;
extern crate byteorder;
extern crate ff;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;

use sapling_crypto::jubjub::JubjubBls12;

pub mod sapling;
mod serialize;
pub mod transaction;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
