extern crate pairing;
extern crate bellman;
extern crate blake2_rfc;
extern crate digest;
extern crate rand;

extern crate byteorder;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

pub mod jubjub;
pub mod circuit;
pub mod group_hash;
pub mod pedersen_hash;
pub mod primitives;

// BLAKE2s personalizations
pub const CRH_IVK_PERSONALIZATION: &'static [u8; 8] = b"Zcashivk";
pub const PRF_NR_PERSONALIZATION: &'static [u8; 8]  = b"WhatTheH";
pub const PEDERSEN_HASH_GENERATORS_PERSONALIZATION: &'static [u8; 8] = b"PEDERSEN";

// TODO: Expand the personalizations to the specific generators
pub const OTHER_PERSONALIZATION: &'static [u8; 8] = b"GOTOFAIL";
