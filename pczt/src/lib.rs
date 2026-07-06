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

#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};
#[cfg(all(
    any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"),
    zcash_unstable = "nu7",
    feature = "zip-233",
))]
use zcash_protocol::value::Zatoshis;
#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
use {
    common::{Global, determine_lock_time},
    zcash_primitives::transaction::{Authorization, TransactionData, TxVersion},
    zcash_protocol::{
        consensus::{BranchId, OrchardProtocolRevision},
        constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID},
    },
};

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
use zcash_primitives::transaction::sighash_v6::v6_signature_hash;
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

pub(crate) const MAGIC_BYTES: &[u8] = b"PCZT";
pub(crate) const PCZT_VERSION_1: u32 = 1;
pub(crate) const PCZT_VERSION_2: u32 = 2;

/// Parses a PCZT from its encoding.
pub fn parse(bytes: &[u8]) -> Result<Pczt, ParseError> {
    Pczt::parse(bytes)
}

/// A partially-created Zcash transaction.
#[derive(Clone, Debug, Getters)]
pub struct Pczt {
    /// Global fields that are relevant to the transaction as a whole.
    #[getset(get = "pub")]
    pub(crate) global: common::Global,

    //
    // Protocol-specific fields.
    //
    // Unlike the `TransactionData` type in `zcash_primitives`, these are not optional.
    // This is because a PCZT does not always contain a semantically-valid transaction,
    // and there may be phases where we need to store protocol-specific metadata before
    // it has been determined whether there are protocol-specific inputs or outputs.
    //
    #[getset(get = "pub")]
    pub(crate) transparent: transparent::Bundle,
    #[getset(get = "pub")]
    pub(crate) sapling: sapling::Bundle,
    #[getset(get = "pub")]
    pub(crate) orchard: orchard::Bundle,
    #[getset(get = "pub")]
    pub(crate) ironwood: orchard::Bundle,
}

/// Types and operations for the v1 Pczt encoding.
pub mod v1 {
    use alloc::vec::Vec;
    use serde::{Deserialize, Serialize};

    use crate::{common, orchard, sapling, transparent};

    /// The in-memory type used for derived serialization of the v1 Pczt encoding.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Pczt {
        global: common::Global,
        transparent: transparent::Bundle,
        sapling: sapling::Bundle,
        orchard: orchard::v1::Bundle,
    }

    impl Pczt {
        pub fn serialize(&self) -> Vec<u8> {
            let mut bytes = vec![];
            bytes.extend_from_slice(crate::MAGIC_BYTES);
            bytes.extend_from_slice(&crate::PCZT_VERSION_1.to_le_bytes());
            postcard::to_extend(&self, bytes).expect("can serialize into memory")
        }
    }

    /// Encodes the in-memory [`super::Pczt`] into the v1 serialization type [`Pczt`].
    impl TryFrom<super::Pczt> for Pczt {
        type Error = super::EncodingError;

        fn try_from(pczt: super::Pczt) -> Result<Self, Self::Error> {
            // The v1 format predates the v6 transaction format; a parser of the v1
            // encoding could parse a v6 PCZT but never extract a transaction from it.
            if pczt.global.tx_version == zcash_protocol::constants::V6_TX_VERSION {
                return Err(super::EncodingError::UnsupportedTxVersion);
            }

            // The v1 format cannot represent an Ironwood bundle in any state other
            // than the canonical empty one; a parser of the v1 encoding will
            // reconstruct exactly that value.
            if pczt.ironwood != orchard::EMPTY_IRONWOOD {
                return Err(super::EncodingError::UnsupportedTxVersion);
            }

            Ok(Self {
                global: pczt.global,
                transparent: pczt.transparent,
                sapling: pczt.sapling,
                orchard: orchard::v1::Bundle::try_from(pczt.orchard)?,
            })
        }
    }

    impl From<Pczt> for super::Pczt {
        fn from(pczt: Pczt) -> Self {
            Self {
                global: pczt.global,
                transparent: pczt.transparent,
                sapling: pczt.sapling,
                orchard: pczt.orchard.into(),
                ironwood: orchard::EMPTY_IRONWOOD,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use zcash_protocol::consensus::BranchId;

        use crate::roles::creator::Creator;

        #[test]
        fn v1_refuses_v6_pczts_and_non_canonical_ironwood_bundles() {
            // A v6 tx cannot be encoded as a v1 PCZT, even when its Ironwood bundle is
            // canonically empty.
            let pczt = Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], [0; 32])
                .unwrap()
                .build();
            assert!(matches!(
                super::Pczt::try_from(pczt),
                Err(crate::EncodingError::UnsupportedTxVersion)
            ));

            // A v5 tx carrying non-canonical Ironwood bundle data cannot be encoded
            // as a v1 PCZT, because the data would be dropped.
            let mut pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
                .unwrap()
                .build();
            pczt.ironwood.bsk = Some([1; 32]);
            assert!(matches!(
                super::Pczt::try_from(pczt),
                Err(crate::EncodingError::UnsupportedTxVersion)
            ));
        }
    }
}

/// Types and operations for the v2 Pczt encoding.
///
/// In the Orchard-shaped bundles of this encoding the derived fields (`cv_net`,
/// `nullifier`, `rk`, `cmx`, `ephemeral_key`, `enc_ciphertext`) and the bundle
/// `anchor` are optional, and each output carries an optional
/// [`MemoKind`](crate::orchard::MemoKind) tag. A producer elides those fields with the
/// Redactor to shrink the encoding, and the receiver recomputes them with
/// `Pczt::fill_derived_fields` (which requires the `orchard` feature; parsing the
/// bundles also performs the fill implicitly).
pub mod v2 {
    use alloc::vec::Vec;
    use serde::{Deserialize, Serialize};

    use crate::{common, orchard, sapling, transparent};

    /// The in-memory type used for derived serialization of the v2 Pczt encoding.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Pczt {
        global: common::Global,
        // This value is set to `None` if the transparent bundle is empty,
        // meaning inputs and outputs are empty.
        transparent: Option<transparent::Bundle>,
        // This value is set to `None` if the Sapling bundle is empty,
        // meaning every field has its empty/default value.
        sapling: Option<sapling::Bundle>,
        // This value is set to `None` if the Orchard bundle is empty,
        // meaning actions, value sum, anchor, zkproof, and bsk are all
        // empty. Flags and note version are not checked, as values can be
        // defaulted there.
        orchard: Option<orchard::v2::Bundle>,
        ironwood: Option<orchard::v2::Bundle>,
    }

    impl Pczt {
        pub fn serialize(&self) -> Vec<u8> {
            let mut bytes = vec![];
            bytes.extend_from_slice(crate::MAGIC_BYTES);
            bytes.extend_from_slice(&crate::PCZT_VERSION_2.to_le_bytes());
            postcard::to_extend(&self, bytes).expect("can serialize into memory")
        }
    }

    /// Encodes the in-memory [`super::Pczt`] into the v2 serialization type [`Pczt`],
    /// omitting empty Transparent, Sapling, and Orchard bundles. Infallible: the v2
    /// encoding can represent every in-memory PCZT.
    impl From<super::Pczt> for Pczt {
        fn from(pczt: super::Pczt) -> Self {
            Self {
                global: pczt.global,
                transparent: (pczt.transparent != transparent::EMPTY_BUNDLE)
                    .then_some(pczt.transparent),
                sapling: (pczt.sapling != sapling::EMPTY_BUNDLE).then_some(pczt.sapling),
                orchard: orchard::v2::encode(pczt.orchard, &orchard::EMPTY_ORCHARD),
                ironwood: orchard::v2::encode(pczt.ironwood, &orchard::EMPTY_IRONWOOD),
            }
        }
    }

    impl From<Pczt> for super::Pczt {
        fn from(pczt: Pczt) -> Self {
            Self {
                global: pczt.global,
                transparent: pczt.transparent.unwrap_or(transparent::EMPTY_BUNDLE),
                sapling: pczt.sapling.unwrap_or(sapling::EMPTY_BUNDLE),
                orchard: pczt
                    .orchard
                    .map(orchard::Bundle::from)
                    .unwrap_or(orchard::EMPTY_ORCHARD),
                ironwood: pczt
                    .ironwood
                    .map(orchard::Bundle::from)
                    .unwrap_or(orchard::EMPTY_IRONWOOD),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use zcash_protocol::consensus::BranchId;

        use super::Pczt;
        use crate::{orchard::NoteVersion, roles::creator::Creator};

        #[test]
        fn empty_bundles_encode_as_none_and_decode_as_empty() {
            // Zero anchors: the shielded bundles carry no anchor and no
            // spends/actions, so they are fully empty and omitted.
            let pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
                .unwrap()
                .build();

            let encoded = Pczt::from(pczt);

            assert!(encoded.transparent.is_none());
            assert!(encoded.sapling.is_none());
            assert!(encoded.orchard.is_none());
            assert!(encoded.ironwood.is_none());

            let decoded = crate::parse(&encoded.serialize()).unwrap();

            assert!(decoded.transparent.inputs.is_empty());
            assert!(decoded.transparent.outputs.is_empty());
            assert!(decoded.sapling.spends.is_empty());
            assert!(decoded.sapling.outputs.is_empty());
            assert!(decoded.orchard.actions.is_empty());
            assert_eq!(decoded.orchard.note_version, NoteVersion::V2);
            {
                assert!(decoded.ironwood.actions.is_empty());
                assert_eq!(decoded.ironwood.note_version, NoteVersion::V3);
            }
        }

        #[test]
        fn anchored_bundles_are_preserved() {
            // A Sapling/Orchard bundle with a non-empty anchor differs from its
            // empty form, so it must not be omitted even with no spends/actions,
            // and the anchor must survive the v2 round-trip.
            let pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [1; 32], [2; 32])
                .unwrap()
                .build();

            let encoded = Pczt::from(pczt);

            assert!(encoded.transparent.is_none());
            assert!(encoded.sapling.is_some());
            assert!(encoded.orchard.is_some());

            let decoded = crate::parse(&encoded.serialize()).unwrap();

            assert_eq!(decoded.sapling.anchor, [1; 32]);
            assert_eq!(decoded.orchard.anchor, Some([2; 32]));
        }

        #[test]
        fn non_canonical_orchard_flags_and_note_version_prevent_omission() {
            let mut pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
                .unwrap()
                .build();
            pczt.orchard.flags = 0;
            pczt.orchard.note_version = NoteVersion::V3;

            // A bundle whose flags or note version differ from the canonical empty
            // bundle is not omitted, so that those fields round-trip losslessly.
            let encoded = Pczt::from(pczt.clone());
            assert!(encoded.orchard.is_some());

            let decoded = crate::Pczt::from(encoded);
            assert_eq!(decoded.orchard, pczt.orchard);
            assert_eq!(decoded.orchard.flags, 0);
            assert_eq!(decoded.orchard.note_version, NoteVersion::V3);
        }
    }
}

/// Errors that can occur while serializing a PCZT.
#[derive(Debug)]
#[non_exhaustive]
pub enum EncodingError {
    /// The requested transaction version cannot be represented in this PCZT
    /// encoding.
    UnsupportedTxVersion,
    /// The v1 PCZT encoding does not support this Orchard note plaintext version.
    UnsupportedOrchardNoteVersion,
    /// The PCZT elides fields this encoding cannot represent (an elided derived
    /// Orchard-shaped field, an elided bundle anchor, or a memo-kind tag). Encode it
    /// with [`v2`] instead.
    RequiresV2,
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
        match version {
            PCZT_VERSION_1 => postcard::from_bytes::<v1::Pczt>(&bytes[8..])
                .map(Pczt::from)
                .map_err(ParseError::Invalid),
            PCZT_VERSION_2 => postcard::from_bytes::<v2::Pczt>(&bytes[8..])
                .map(Pczt::from)
                .map_err(ParseError::Invalid),
            _ => Err(ParseError::UnknownVersion(version)),
        }
    }

    /// Serializes this PCZT as the latest PCZT version.
    ///
    /// To serialize a specific PCZT version, e.g. v1, use [`v1::Pczt::serialize`].
    pub fn serialize(self) -> Result<Vec<u8>, EncodingError> {
        Ok(v2::Pczt::from(self).serialize())
    }

    /// Recomputes and fills, in place, every elided derived field across the PCZT's
    /// Orchard and Ironwood bundles; see
    /// [`orchard::Bundle::fill_derived_fields`](crate::orchard::Bundle::fill_derived_fields)
    /// for the per-bundle contract. On error the PCZT may be left partially filled.
    #[cfg(feature = "orchard")]
    pub fn fill_derived_fields(&mut self) -> Result<(), crate::orchard::FillError> {
        self.orchard.fill_derived_fields()?;
        self.ironwood.fill_derived_fields()
    }

    /// Fills missing Orchard and Ironwood spend FVK bytes for actions whose ZIP 32
    /// derivation matches the supplied seed fingerprint and account path.
    ///
    /// This prepares a PCZT whose wire encoding omitted account FVKs for
    /// [`Self::fill_derived_fields`], allowing `nullifier` and `rk` to be
    /// recomputed from a locally derived FVK.
    #[cfg(feature = "orchard")]
    pub fn fill_missing_spend_fvks_for_zip32_path(
        &mut self,
        seed_fingerprint: &[u8; 32],
        derivation_path: &[u32],
        fvk: [u8; 96],
    ) -> usize {
        self.orchard
            .fill_missing_spend_fvks_for_zip32_path(seed_fingerprint, derivation_path, fvk)
            + self.ironwood.fill_missing_spend_fvks_for_zip32_path(
                seed_fingerprint,
                derivation_path,
                fvk,
            )
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
        extract_ironwood: impl FnOnce(
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
            ironwood,
        } = self;

        let consensus_branch_id = BranchId::try_from(global.consensus_branch_id)
            .map_err(|_| ExtractError::UnknownConsensusBranchId)?;
        let orchard_protocol_revision = consensus_branch_id
            .orchard_protocol_revision()
            // The v5 and v6 transaction formats do not exist prior to NU5, so no
            // transaction could be extracted under such a branch in any case.
            .ok_or(ExtractError::UnsupportedConsensusBranchId)?;

        let version = match (global.tx_version, global.version_group_id) {
            (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::V5),
            (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(TxVersion::V6),
            (version, version_group_id) => Err(ExtractError::UnsupportedTxVersion {
                version,
                version_group_id,
            }),
        }?;

        match version {
            // Only the v6 transaction format carries an Ironwood bundle.
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
                if ironwood != crate::orchard::EMPTY_IRONWOOD {
                    return Err(ExtractError::IronwoodNotSupported.into());
                }
            }
            // The v6 transaction format does not exist prior to NU6.3 (the first
            // upgrade under which the Orchard protocol is at revision V3).
            TxVersion::V6 => {
                if orchard_protocol_revision < OrchardProtocolRevision::V3 {
                    return Err(ExtractError::UnsupportedConsensusBranchId.into());
                }
            }
        }

        let transparent = transparent
            .into_parsed()
            .map_err(ExtractError::TransparentParse)?;
        let sapling = sapling.into_parsed().map_err(ExtractError::SaplingParse)?;
        let orchard = orchard
            .into_parsed_with_version(
                crate::orchard::bundle_version_for_revision(
                    orchard_protocol_revision,
                    ::orchard::ValuePool::Orchard,
                )
                .expect("the Orchard pool is supported under every protocol revision"),
            )
            .map_err(ExtractError::OrchardParse)?;
        let ironwood = ironwood
            .into_ironwood_parsed()
            .map_err(ExtractError::IronwoodParse)?;

        let lock_time = determine_lock_time(&global, transparent.inputs())
            .ok_or(ExtractError::IncompatibleLockTimes)?;

        let transparent_bundle = extract_transparent(&transparent)?;
        let sapling_bundle = extract_sapling(&sapling)?;
        let orchard_bundle = extract_orchard(&orchard)?;
        let ironwood_bundle = extract_ironwood(&ironwood)?;

        let tx_data = match version {
            TxVersion::V6 => TransactionData::from_parts_v6(
                consensus_branch_id,
                lock_time,
                global.expiry_height.into(),
                #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
                Zatoshis::ZERO,
                transparent_bundle,
                sapling_bundle,
                orchard_bundle,
                ironwood_bundle,
            ),
            _ => TransactionData::from_parts(
                version,
                consensus_branch_id,
                lock_time,
                global.expiry_height.into(),
                #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
                Zatoshis::ZERO,
                transparent_bundle,
                None,
                sapling_bundle,
                orchard_bundle,
            ),
        };

        Ok(ParsedPczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
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
            |i| i.extract_effects().map_err(ExtractError::IronwoodExtract),
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
    pub(crate) ironwood: ::orchard::pczt::Bundle,
    pub(crate) tx_data: TransactionData<A>,
}

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub struct EffectsOnly;

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
impl Authorization for EffectsOnly {
    type TransparentAuth = ::transparent::bundle::EffectsOnly;
    type SaplingAuth = ::sapling::bundle::EffectsOnly;
    type OrchardAuth = ::orchard::bundle::EffectsOnly;
}

/// Helper to produce the correct sighash for a PCZT.
#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub(crate) fn sighash(
    tx_data: &TransactionData<EffectsOnly>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> [u8; 32] {
    match tx_data.version() {
        TxVersion::V5 => v5_signature_hash(tx_data, signable_input, txid_parts),
        TxVersion::V6 => v6_signature_hash(tx_data, signable_input, txid_parts),
        _ => unreachable!("PCZT only supports v5 and v6 transaction data"),
    }
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
    /// An error occurred extracting the Ironwood protocol bundle from the Ironwood PCZT bundle.
    IronwoodExtract(::orchard::pczt::TxExtractorError),
    /// The PCZT carries Ironwood bundle data, but its transaction version does not
    /// support an Ironwood bundle.
    IronwoodNotSupported,
    /// An error occurred parsing the Ironwood PCZT bundle from the PCZT data.
    IronwoodParse(::orchard::pczt::ParseError),
    /// An error occurred extracting the Orchard protocol bundle from the Orchard PCZT bundle.
    OrchardExtract(::orchard::pczt::TxExtractorError),
    /// An error occurred parsing the Orchard PCZT bundle from the PCZT data.
    OrchardParse(::orchard::pczt::ParseError),
    /// An error occurred extracting the Sapling protocol bundle from the Sapling PCZT bundle.
    SaplingExtract(::sapling::pczt::TxExtractorError),
    /// An error occurred parsing the Sapling PCZT bundle from the PCZT data.
    SaplingParse(::sapling::pczt::ParseError),
    /// An error occurred extracting the transparent protocol bundle from the
    /// transparent PCZT bundle.
    TransparentExtract(::transparent::pczt::TxExtractorError),
    /// An error occurred parsing the transparent PCZT bundle from the PCZT data.
    TransparentParse(::transparent::pczt::ParseError),
    /// The consensus branch ID requested by the PCZT does not correspond to a
    /// known network upgrade.
    UnknownConsensusBranchId,
    /// The network upgrade for the PCZT's consensus branch ID predates the v5
    /// transaction format, so no transaction can be extracted from it.
    UnsupportedConsensusBranchId,
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

#[cfg(all(test, any(feature = "io-finalizer", feature = "signer")))]
mod extraction_tests {
    use zcash_protocol::consensus::BranchId;

    use crate::{ExtractError, roles::creator::Creator};

    #[test]
    fn v5_pczt_with_ironwood_data_does_not_extract() {
        let mut pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
            .unwrap()
            .build();
        pczt.ironwood.bsk = Some([1; 32]);
        assert!(matches!(
            pczt.into_effects(),
            Err(ExtractError::IronwoodNotSupported)
        ));
    }

    #[test]
    fn v6_pczt_with_pre_nu6_3_branch_does_not_extract() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], [0; 32])
            .unwrap()
            .build();
        pczt.global.consensus_branch_id = BranchId::Nu6_2.into();
        assert!(matches!(
            pczt.into_effects(),
            Err(ExtractError::UnsupportedConsensusBranchId)
        ));
    }
}
