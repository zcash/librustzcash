//! The Partially Created Zcash Transaction (PCZT) format.
//!
//! This format enables splitting up the logical steps of creating a Zcash transaction
//! across distinct entities. The entity roles roughly match those specified in
//! [BIP 174: Partially Signed Bitcoin Transaction Format] and [BIP 370: PSBT Version 2],
//! with additional Zcash-specific roles.
//!
//! [BIP 174: Partially Signed Bitcoin Transaction Format]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! [BIP 370: PSBT Version 2]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

use getset::Getters;
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
use {roles::tx_data::EffectsOnly, zcash_primitives::transaction::TransactionData};

pub mod roles;

pub mod common;
pub mod orchard;
pub mod sapling;
pub mod transparent;

const MAGIC_BYTES: &[u8] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;

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
    #[cfg(any(feature = "io-finalizer", feature = "signer"))]
    pub fn into_effects(self) -> Result<TransactionData<EffectsOnly>, ExtractError> {
        roles::tx_data::pczt_to_tx_data(
            self,
            |t| {
                t.extract_effects()
                    .map_err(ExtractError::TransparentExtract)
            },
            |s| s.extract_effects().map_err(ExtractError::SaplingExtract),
            |o| o.extract_effects().map_err(ExtractError::OrchardExtract),
        )
        .map(|parsed| parsed.tx_data)
    }
}

/// Errors that can occur while extracting effects-only transaction data from a PCZT.
#[cfg(any(feature = "io-finalizer", feature = "signer"))]
#[derive(Debug)]
pub enum ExtractError {
    OrchardExtract(::orchard::pczt::TxExtractorError),
    OrchardParse(::orchard::pczt::ParseError),
    SaplingExtract(::sapling::pczt::TxExtractorError),
    SaplingParse(::sapling::pczt::ParseError),
    TransparentExtract(::transparent::pczt::TxExtractorError),
    TransparentParse(::transparent::pczt::ParseError),
    TxData(roles::tx_data::Error),
}

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
impl From<roles::tx_data::Error> for ExtractError {
    fn from(e: roles::tx_data::Error) -> Self {
        match e {
            roles::tx_data::Error::TransparentParse(e) => ExtractError::TransparentParse(e),
            roles::tx_data::Error::SaplingParse(e) => ExtractError::SaplingParse(e),
            roles::tx_data::Error::OrchardParse(e) => ExtractError::OrchardParse(e),
            other @ (roles::tx_data::Error::IncompatibleLockTimes
            | roles::tx_data::Error::UnknownConsensusBranchId
            | roles::tx_data::Error::UnsupportedTxVersion { .. }) => ExtractError::TxData(other),
        }
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
