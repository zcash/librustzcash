extern crate blake2_rfc;
extern crate byteorder;
#[macro_use]
extern crate lazy_static;
extern crate pairing;
extern crate sapling_crypto;

use sapling_crypto::jubjub::JubjubBls12;

mod serialize;
pub mod transaction;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
