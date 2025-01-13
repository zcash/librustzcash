//! The Partially Created Zcash Transaction (PCZT) format.
//!
//! Goal is to split up the parts of creating a transaction across distinct entities.
//! The entity roles roughly match BIP 174: Partially Signed Bitcoin Transaction Format.
//! - Creator (single entity)
//!   - Creates the base PCZT with no information about spends or outputs.
//! - Constructor (anyone can contribute)
//!   - Adds spends and outputs to the PCZT.
//!   - Before any input or output may be added, the constructor must check the
//!     `Global.tx_modifiable` field. Inputs may only be added if the Inputs Modifiable
//!     flag is True. Outputs may only be added if the Outputs Modifiable flag is True.
//!   - A single entity is likely to be both a Creator and Constructor.
//! - IO Finalizer (anyone can execute)
//!   - Sets the appropriate bits in `Global.tx_modifiable` to 0.
//!   - Updates the various bsk values using the rcv information from spends and outputs.
//! - Updater (anyone can contribute)
//!   - Adds information necessary for subsequent entities to proceed, such as key paths
//!     for signing spends.
//! - Redactor (anyone can execute)
//!   - Removes information that is unnecessary for subsequent entities to proceed.
//!   - This can be useful e.g. when creating a transaction that has inputs from multiple
//!     independent Signers; each can receive a PCZT with just the information they need
//!     to sign, but (e.g.) not the `alpha` values for other Signers.
//! - Prover (capability holders can contribute)
//!   - Needs all private information for a single spend or output.
//!   - In practice, the Updater that adds a given spend or output will either act as
//!     the Prover themselves, or add the necessary data, offload to the Prover, and
//!     then receive back the PCZT with private data stripped and proof added.
//! - Signer (capability holders can contribute)
//!   - Needs the spend authorization randomizers to create signatures.
//!   - Needs sufficient information to verify that the proof is over the correct data,
//!     without needing to verify the proof itself.
//!   - A Signer should only need to implement:
//!     - Pedersen commitments using Jubjub / Pallas arithmetic (for note and value
//!       commitments)
//!     - BLAKE2b and BLAKE2s (and the various PRFs / CRHs they are used in)
//!     - Nullifier check (using Jubjub / Pallas arithmetic)
//!     - KDF plus note decryption (AEAD_CHACHA20_POLY1305)
//!     - SignatureHash algorithm
//!     - Signatures (RedJubjub / RedPallas)
//!     - A source of randomness.
//! - Combiner (anyone can execute)
//!   - Combines several PCZTs that represent the same transaction into a single PCZT.
//! - Spend Finalizer (anyone can execute)
//!   - Combines partial transparent signatures into `script_sig`s.
//! - Transaction Extractor (anyone can execute)
//!   - Creates bindingSig and extracts the final transaction.

#![no_std]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

use getset::Getters;
use serde::{Deserialize, Serialize};

#[cfg(feature = "signer")]
use {roles::signer::EffectsOnly, zcash_primitives::transaction::TransactionData};

pub mod roles;

pub mod common;
pub mod orchard;
pub mod sapling;
pub mod transparent;

const MAGIC_BYTES: &[u8] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;

#[cfg(feature = "zcp-builder")]
const SAPLING_TX_VERSION: u32 = 4;
const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// A partially-created Zcash transaction.
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Pczt {
    /// Global fields that are relevant to the transaction as a whole.
    #[getset(get = "pub")]
    global: common::Global,

    //
    // Protocol-specific fields.
    //
    // Unlike the `TransactionData` type in `zcash_primitives`, these are not optional.
    // This is because a PCZT does not always contain a semantically-valid transaction,
    // and there may be phases where we need to store protocol-specific metadata before
    // it has been determined whether there are protocol-specific inputs or outputs.
    //
    #[getset(get = "pub")]
    transparent: transparent::Bundle,
    #[getset(get = "pub")]
    sapling: sapling::Bundle,
    #[getset(get = "pub")]
    orchard: orchard::Bundle,
}

impl Pczt {
    /// Parses a PCZT from its encoding.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::TooShort);
        }
        if &bytes[..4] != MAGIC_BYTES {
            return Err(ParseError::NotPczt);
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != PCZT_VERSION_1 {
            return Err(ParseError::UnknownVersion(version));
        }

        // This is a v1 PCZT.
        postcard::from_bytes(&bytes[8..]).map_err(ParseError::Invalid)
    }

    /// Serializes this PCZT.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(MAGIC_BYTES);
        bytes.extend_from_slice(&PCZT_VERSION_1.to_le_bytes());
        postcard::to_extend(self, bytes).expect("can serialize into memory")
    }

    /// Gets the effects of this transaction.
    #[cfg(feature = "signer")]
    pub fn into_effects(self) -> Option<TransactionData<EffectsOnly>> {
        let Self {
            global,
            transparent,
            sapling,
            orchard,
        } = self;

        let transparent = transparent.into_parsed().ok()?;
        let sapling = sapling.into_parsed().ok()?;
        let orchard = orchard.into_parsed().ok()?;

        roles::signer::pczt_to_tx_data(&global, &transparent, &sapling, &orchard).ok()
    }
}

/// Errors that can occur while parsing a PCZT.
#[derive(Debug)]
pub enum ParseError {
    /// The bytes do not contain a PCZT.
    NotPczt,
    /// The PCZT encoding was invalid.
    Invalid(postcard::Error),
    /// The bytes are too short to contain a PCZT.
    TooShort,
    /// The PCZT has an unknown version.
    UnknownVersion(u32),
}
