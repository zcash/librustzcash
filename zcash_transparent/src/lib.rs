//! # Zcash transparent protocol
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub mod address;
pub mod builder;
pub mod bundle;
pub mod keys;
pub mod pczt;
pub mod sighash;

#[cfg(test)]
mod test_vectors;

#[macro_use]
extern crate alloc;

/// `RIPEMD160(SHA256(data))`: the hash by which a P2PKH `script_pubkey` commits to its
/// pubkey, and a P2SH `script_pubkey` to its redeem script.
pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    *Ripemd160::digest(Sha256::digest(data)).as_ref()
}
