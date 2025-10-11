//! The Partially Created Zcash Transaction (PCZT) format.
//!
//! This format enables splitting up the logical steps of creating a Zcash transaction
//! across distinct entities. The entity roles roughly match those specified in
//! [BIP 174: Partially Signed Bitcoin Transaction Format] and [BIP 370: PSBT Version 2],
//! with additional Zcash-specific roles.
//!
//! The PCZT format supports all three Zcash shielded protocols:
//! - **Transparent**: Bitcoin-compatible UTXO-based transactions ([BIP 16], [BIP 143])
//! - **Sapling**: First-generation shielded protocol ([ZIP 212])
//! - **Orchard**: Next-generation shielded protocol ([ZIP 224])
//!
//! [BIP 16]: https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
//! [BIP 143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//! [BIP 174]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! [BIP 370]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
//! [ZIP 212]: https://zips.z.cash/zip-0212
//! [ZIP 224]: https://zips.z.cash/zip-0224
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

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

/// A partially-created Zcash transaction.
///
/// The PCZT format extends the PSBT format ([BIP 174], [BIP 370]) to support Zcash's
/// shielded protocols (Sapling and Orchard) while maintaining compatibility with
/// Bitcoin's transparent transaction model.
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
    ///
    /// The PCZT serialization format follows a binary encoding with magic bytes
    /// "PCZT" followed by the version number and postcard-encoded data.
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
