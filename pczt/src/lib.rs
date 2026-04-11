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

#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
use {
    common::{Global, determine_lock_time},
    zcash_primitives::transaction::{Authorization, TransactionData, TxVersion, zip248},
    zcash_protocol::consensus::BranchId,
    zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID},
};

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
use {
    blake2b_simd::Hash as Blake2bHash,
    zcash_primitives::transaction::{
        TxDigests, sighash::SignableInput, sighash_v5::v5_signature_hash,
    },
};

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

    /// Parses this PCZT's bundles and constructs a `TransactionData` using caller-provided
    /// bundle extraction closures.
    ///
    /// This handles bundle parsing, version validation, consensus branch ID parsing,
    /// lock time computation, and final assembly, delegating bundle extraction to the
    /// caller via closures that receive references to the parsed bundles.
    #[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
    pub(crate) fn extract_tx_data<A, E>(
        self,
        extract_transparent: impl FnOnce(
            &::transparent::pczt::Bundle,
        ) -> Result<
            Option<::transparent::bundle::Bundle<A::TransparentAuth>>,
            E,
        >,
        extract_sapling: impl FnOnce(
            &::sapling::pczt::Bundle,
        ) -> Result<
            Option<::sapling::Bundle<A::SaplingAuth, zcash_protocol::value::ZatBalance>>,
            E,
        >,
        extract_orchard: impl FnOnce(
            &::orchard::pczt::Bundle,
        ) -> Result<
            Option<::orchard::Bundle<A::OrchardAuth, zcash_protocol::value::ZatBalance>>,
            E,
        >,
    ) -> Result<ParsedPczt<A>, E>
    where
        A: Authorization,
        E: From<ExtractError>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self;

        let transparent = transparent
            .into_parsed()
            .map_err(ExtractError::TransparentParse)?;
        let sapling = sapling.into_parsed().map_err(ExtractError::SaplingParse)?;
        let orchard = orchard.into_parsed().map_err(ExtractError::OrchardParse)?;

        let version = match (global.tx_version, global.version_group_id) {
            (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::V5),
            (version, version_group_id) => Err(ExtractError::UnsupportedTxVersion {
                version,
                version_group_id,
            }),
        }?;

        let consensus_branch_id = BranchId::try_from(global.consensus_branch_id)
            .map_err(|_| ExtractError::UnknownConsensusBranchId)?;

        let lock_time = determine_lock_time(&global, transparent.inputs())
            .ok_or(ExtractError::IncompatibleLockTimes)?;

        let transparent_bundle = extract_transparent(&transparent)?;
        let sapling_bundle = extract_sapling(&sapling)?;
        let orchard_bundle = extract_orchard(&orchard)?;

        let tx_data = TransactionData::from_parts(
            version,
            consensus_branch_id,
            lock_time,
            global.expiry_height.into(),
            zip248::ValuePoolDeltas::default(),
            transparent_bundle,
            None,
            sapling_bundle,
            orchard_bundle,
        );

        Ok(ParsedPczt {
            global,
            transparent,
            sapling,
            orchard,
            tx_data,
        })
    }

    /// Gets the effects of this transaction.
    #[cfg(any(feature = "io-finalizer", feature = "signer"))]
    pub fn into_effects(self) -> Result<TransactionData<EffectsOnly>, ExtractError> {
        self.extract_tx_data(
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

/// The result of parsing a PCZT and constructing its `TransactionData`.
#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
#[cfg_attr(
    not(any(feature = "io-finalizer", feature = "signer")),
    allow(dead_code)
)]
pub(crate) struct ParsedPczt<A: Authorization> {
    pub(crate) global: Global,
    pub(crate) transparent: ::transparent::pczt::Bundle,
    pub(crate) sapling: ::sapling::pczt::Bundle,
    pub(crate) orchard: ::orchard::pczt::Bundle,
    pub(crate) tx_data: TransactionData<A>,
}

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub struct EffectsOnly;

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
impl Authorization for EffectsOnly {
    type TransparentAuth = ::transparent::bundle::EffectsOnly;
    type SaplingAuth = ::sapling::bundle::EffectsOnly;
    type OrchardAuth = ::orchard::bundle::EffectsOnly;
    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = core::convert::Infallible;
}

/// Helper to produce the correct sighash for a PCZT.
///
/// At present, only V5 transaction signature hashes are supported, and a version check *MUST* be
/// performed prior to invoking this function. It is intended for use exclusively for use in the
/// context of a callback to the `extract_tx_data` function, which performs this check.
#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub(crate) fn sighash(
    tx_data: &TransactionData<EffectsOnly>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> [u8; 32] {
    // TODO: Pick sighash based on tx version
    v5_signature_hash(tx_data, signable_input, txid_parts)
        .as_ref()
        .try_into()
        .expect("correct length")
}

/// Errors that can occur while parsing PCZT bundles and extracting transaction data.
#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
#[derive(Debug)]
#[non_exhaustive]
pub enum ExtractError {
    /// The PCZT's transparent inputs have incompatible lock time requirements.
    IncompatibleLockTimes,
    /// An error occurred extracting the Orchard protocol bundle from the Orchard PCZT bundle.
    OrchardExtract(::orchard::pczt::TxExtractorError),
    /// An error occurred parsing the Orchard PCZT bundle from the PCZT data.
    OrchardParse(::orchard::pczt::ParseError),
    /// An error occurred extracting the Sapling protocol bundle from the Sapling PCZT bundle.
    SaplingExtract(::sapling::pczt::TxExtractorError),
    /// An error occurred parsing the Sapling PCZT bundle from the PCZT data.
    SaplingParse(::sapling::pczt::ParseError),
    /// An error occurred extracting the transparent protocol bundle from the transparent PCZT bundle.
    TransparentExtract(::transparent::pczt::TxExtractorError),
    /// An error occurred parsing the transparent PCZT bundle from the PCZT data.
    TransparentParse(::transparent::pczt::ParseError),
    /// The consensus branch ID requested by the PCZT does not correspond to a known network upgrade.
    UnknownConsensusBranchId,
    /// The PCZT specifies an unsupported transaction version.
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
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
