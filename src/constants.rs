// BLAKE2s invocation personalizations
/// BLAKE2s Personalization for CRH^ivk = BLAKE2s(ak | rk)
pub const CRH_IVK_PERSONALIZATION: &'static [u8; 8] = b"Zcashivk";
/// BLAKE2s Personalization for PRF^nr = BLAKE2s(rk | cm + position)
pub const PRF_NR_PERSONALIZATION: &'static [u8; 8]  = b"WhatTheH";

// Group hash personalizations
/// BLAKE2s Personalization for Pedersen hash generators.
pub const PEDERSEN_HASH_GENERATORS_PERSONALIZATION: &'static [u8; 8] = b"PEDERSEN";
/// BLAKE2s Personalization for the group hash for key diversification
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &'static [u8; 8] = b"Zcash_gh";
/// BLAKE2s Personalization for the proof generation key base point
pub const PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION: &'static [u8; 8] = b"12345678";
/// BLAKE2s Personalization for the note commitment randomness generator
pub const NOTE_COMMITMENT_RANDOMNESS_GENERATOR_PERSONALIZATION: &'static [u8; 8] = b"abcdefgh";
/// BLAKE2s Personalization for the nullifier position generator (for PRF^nr)
pub const NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION: &'static [u8; 8] = b"nfnfnfnf";
/// BLAKE2s Personalization for the value commitment generator for the value
pub const VALUE_COMMITMENT_VALUE_GENERATOR_PERSONALIZATION: &'static [u8; 8]     = b"45u8gh45";
/// BLAKE2s Personalization for the value commitment randomness generator
pub const VALUE_COMMITMENT_RANDOMNESS_GENERATOR_PERSONALIZATION: &'static [u8; 8] = b"11111111";
/// BLAKE2s Personalization for the spending key base point
pub const SPENDING_KEY_GENERATOR_PERSONALIZATION: &'static [u8; 8] = b"sksksksk";
