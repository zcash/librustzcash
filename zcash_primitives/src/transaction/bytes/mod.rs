//! Byte-oriented representation of Zcash transactions.
//!
//! The types in this module parse and serialize the wire encoding of a
//! transaction without constructing any protocol domain values. A transaction
//! can therefore be read, inspected, and re-serialized even when it carries
//! bundle types or variants that this implementation does not understand.
//!
//! The representation is split by transaction format family:
//!
//! - [`LegacyTransactionBodyBytes`] covers versions 1 through 4, whose
//!   transparent, Sprout, and Sapling components are interleaved with the
//!   header fields.
//! - [`V5TransactionBodyBytes`] and [`V6TransactionBodyBytes`] cover the
//!   contiguous bundle layouts of [ZIP 225] and [ZIP 229].
//! - `V7TransactionBodyBytes` covers the [ZIP 248] extensible format, whose
//!   value pool deltas and effect/auth bundle maps are retained separately.
//!
//! # Rules enforced at this layer
//!
//! The byte layer enforces the structural rules that make a transaction
//! well-formed: canonical map ordering, uniqueness, nonzero value pool deltas,
//! asset-class encoding, cross-map variant consistency, auth-implies-effect,
//! exact payload consumption for recognized bundles, and sequence-length
//! correspondence. It deliberately does not enforce registry rules that depend
//! on which bundle types are permitted in which map (for example, that the fee
//! and ZIP 233 NSM bundles are value-only, or that the coinbase bundle has no
//! authorizing data). Such entries are retained as `V7BundleBytes::KnownOpaque`
//! or `V7BundleBytes::CoinbaseWithAuth` so that they round-trip;
//! `TransactionBytes::validate_v7` enforces the registry and consensus rules.
//! Cryptographic field validity (curve points, proof sizes, sighash versions)
//! is likewise not checked here; typed conversion and
//! `TransactionBytes::validate_v7` check it.
//!
//! The version 7 types also expose the [ZIP 248] digest tree, computed from the
//! byte-layer fields. A bundle whose type or variant this layer does not
//! interpret takes its canonical digest from a `BundleDigestProvider`; parsing
//! never requires one.
//!
//! [ZIP 225]: https://zips.z.cash/zip-0225
//! [ZIP 229]: https://zips.z.cash/zip-0229
//! [ZIP 248]: https://zips.z.cash/zip-0248

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::CompactSize;
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::encoding::{ReadBytesExt, WriteBytesExt};

use super::TxVersion;

#[cfg(zcash_unstable = "nu8")]
use {
    super::{
        TxId, Zip244Digests,
        zip248::{BundleDigestProvider, V7DigestError},
    },
    blake2b_simd::Hash as Blake2bHash,
};

#[cfg(zcash_unstable = "nu8")]
mod coinbase;
mod orchard;
mod sapling;
mod sprout;
pub mod transparent;
#[cfg(zcash_unstable = "nu8")]
mod v7;
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
mod validate;

#[cfg(zcash_unstable = "nu8")]
pub use self::{
    coinbase::CoinbaseBundleBytes,
    orchard::{OrchardSignatureBytes, V7OrchardBundleBytes},
    sapling::{SaplingSignatureBytes, SighashInfoBytes, V7SaplingBundleBytes},
    transparent::{
        TransparentAuthBytes, TransparentBundleBytes, TransparentEffectsBytes,
        TransparentInputAuthBytes, TransparentInputEffectingBytes, TransparentSighashInfoBytes,
    },
    v7::{
        AssetClass, OpaqueBundleBytes, V7BundleBytes, V7TransactionBodyBytes, ValuePoolDeltaBytes,
    },
};
pub use self::{
    orchard::{IronwoodBundleBytes, OrchardActionBytes, OrchardBundleBytes},
    sapling::{
        SaplingBundleBytes, SaplingOutputBytes, SaplingOutputV4Bytes, SaplingSpendBytes,
        SaplingSpendV4Bytes, V4SaplingBundleBytes,
    },
    sprout::{SproutBundleBytes, SproutJoinSplitBytes, SproutProofBytes},
    transparent::{
        LegacyTransparentBundleBytes, LegacyTransparentInputBytes, TransparentOutPointBytes,
        TransparentOutputBytes, TransparentOutputValueBytes, TransparentScriptBytes,
    },
};
#[cfg(zcash_unstable = "nu8")]
pub use crate::transaction::zip248::{BundleType, BundleVariant};

#[cfg(test)]
mod tests;

/// Reads `count` elements, growing the result as elements are decoded.
///
/// The count comes from the wire, so it must not be used to reserve capacity up
/// front: a claimed count that the remaining bytes cannot satisfy fails on the
/// first missing element without allocating for the whole claim.
pub(crate) fn read_array<R: Read, E, F>(
    reader: &mut R,
    count: usize,
    mut func: F,
) -> io::Result<Vec<E>>
where
    F: FnMut(&mut R) -> io::Result<E>,
{
    let mut items = Vec::new();
    for _ in 0..count {
        items.push(func(reader)?);
    }
    Ok(items)
}

/// Reads a CompactSize-prefixed vector, growing the result as elements are
/// decoded.
pub(crate) fn read_vector<R: Read, E, F>(reader: &mut R, func: F) -> io::Result<Vec<E>>
where
    F: FnMut(&mut R) -> io::Result<E>,
{
    let count = CompactSize::read_t::<_, usize>(&mut *reader)?;
    read_array(reader, count, func)
}

/// Reads a fixed-size byte array.
pub(crate) fn read_fixed<const N: usize, R: Read>(mut reader: R) -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// A whole transaction in its wire representation.
///
/// The header fields are common to every format family. For versions 1 through
/// 4 the consensus branch ID is not encoded, so [`Self::raw_consensus_branch_id`]
/// returns `None`; for version 5 and later it is read from the wire.
///
/// The wire format defines `nConsensusBranchId` as a `uint32`, so these types
/// retain its raw value rather than interpreting it as a [`BranchId`]. Parsing
/// and serialization therefore round-trip a branch ID this implementation does
/// not recognize. [`Self::consensus_branch_id`] and
/// [`Self::try_consensus_branch_id`] expose the typed value; the latter reports
/// an unrecognized ID as an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionBytes {
    version: TxVersion,
    consensus_branch_id: Option<u32>,
    lock_time: u32,
    expiry_height: BlockHeight,
    body: TransactionBodyBytes,
}

impl TransactionBytes {
    /// Constructs a transaction from its header fields and body.
    ///
    /// Returns an error if the body does not match the version, if the
    /// consensus branch ID is present for a version that does not encode it or
    /// absent for a version that does, or if a legacy body's Sapling, Sprout,
    /// or expiry fields are inconsistent with the version.
    pub fn from_parts(
        version: TxVersion,
        consensus_branch_id: Option<BranchId>,
        lock_time: u32,
        expiry_height: BlockHeight,
        body: TransactionBodyBytes,
    ) -> io::Result<Self> {
        let legacy = matches!(
            version,
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4
        );
        if legacy {
            if consensus_branch_id.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "legacy transaction versions do not encode a consensus branch ID",
                ));
            }
            let TransactionBodyBytes::Legacy(legacy_body) = &body else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "legacy transaction version requires a legacy body",
                ));
            };
            if version.has_sapling() != legacy_body.sapling.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the Sapling bundle is present exactly when the version supports Sapling",
                ));
            }
            if !version.has_sprout() && legacy_body.sprout.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the Sprout bundle is absent when the version does not support Sprout",
                ));
            }
            if let Some(sprout) = &legacy_body.sprout {
                let expected_groth = version.has_sapling();
                for joinsplit in sprout.joinsplits() {
                    let is_groth = matches!(joinsplit.proof(), SproutProofBytes::Groth(_));
                    if is_groth != expected_groth {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Sprout JoinSplit proof type does not match the transaction version",
                        ));
                    }
                }
            }
            if !version.has_overwinter() && expiry_height != BlockHeight::from(0u32) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a transaction without Overwinter has no expiry height",
                ));
            }
        } else {
            if consensus_branch_id.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "transaction version 5 and later require a consensus branch ID",
                ));
            }
            let matches_version = match (&version, &body) {
                (TxVersion::V5, TransactionBodyBytes::V5(_)) => true,
                (TxVersion::V6, TransactionBodyBytes::V6(_)) => true,
                #[cfg(zcash_unstable = "nu8")]
                (TxVersion::V7, TransactionBodyBytes::V7(_)) => true,
                _ => false,
            };
            if !matches_version {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "transaction body does not match the transaction version",
                ));
            }
        }

        Ok(Self {
            version,
            consensus_branch_id: consensus_branch_id.map(u32::from),
            lock_time,
            expiry_height,
            body,
        })
    }

    /// Constructs a transaction without checking consistency between its
    /// version, header, and body.
    ///
    /// Version-specific typed writers use this when the requested body format
    /// intentionally differs from the transaction's version field.
    #[cfg(all(feature = "sapling", feature = "orchard"))]
    pub(crate) fn from_parts_unchecked(
        version: TxVersion,
        consensus_branch_id: Option<u32>,
        lock_time: u32,
        expiry_height: BlockHeight,
        body: TransactionBodyBytes,
    ) -> Self {
        Self {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            body,
        }
    }

    /// Returns the transaction format version.
    pub fn version(&self) -> TxVersion {
        self.version
    }

    /// Returns the raw `nConsensusBranchId` field, if the format encodes one.
    ///
    /// Versions 1 through 4 do not encode the field and return `None`. The
    /// value is returned verbatim, including IDs that [`BranchId`] does not
    /// recognize.
    pub fn raw_consensus_branch_id(&self) -> Option<u32> {
        self.consensus_branch_id
    }

    /// Returns the consensus branch ID, if the format encodes one and this
    /// implementation recognizes it.
    ///
    /// An encoded ID that this implementation does not recognize also yields
    /// `None`; use [`Self::try_consensus_branch_id`] to distinguish it from a
    /// format that does not encode the field.
    pub fn consensus_branch_id(&self) -> Option<BranchId> {
        self.consensus_branch_id
            .and_then(|raw| BranchId::try_from(raw).ok())
    }

    /// Returns the consensus branch ID, if the format encodes one, or an error
    /// if the encoded value is not a recognized [`BranchId`].
    ///
    /// Versions 1 through 4 return `Ok(None)`.
    pub fn try_consensus_branch_id(&self) -> io::Result<Option<BranchId>> {
        match self.consensus_branch_id {
            Some(raw) => BranchId::try_from(raw).map(Some).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    alloc::format!("unrecognized consensus branch ID {raw:#010x}"),
                )
            }),
            None => Ok(None),
        }
    }

    /// Returns the transaction's lock time.
    pub fn lock_time(&self) -> u32 {
        self.lock_time
    }

    /// Returns the transaction's expiry height, or zero if it has none.
    pub fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }

    /// Returns the transaction body.
    pub fn body(&self) -> &TransactionBodyBytes {
        &self.body
    }

    /// Consumes this transaction, returning its body.
    pub fn into_body(self) -> TransactionBodyBytes {
        self.body
    }

    /// Reads a transaction from its wire encoding.
    ///
    /// The reader is consumed exactly as far as the transaction's encoding
    /// extends; any following bytes are left unread.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = TxVersion::read(&mut reader)?;
        match version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                let transparent = LegacyTransparentBundleBytes::read(&mut reader)?;
                let lock_time = reader.read_u32_le()?;
                let expiry_height = if version.has_overwinter() {
                    reader.read_u32_le()?.into()
                } else {
                    0u32.into()
                };

                let sapling = if version.has_sapling() {
                    Some(V4SaplingBundleBytes::read(&mut reader)?)
                } else {
                    None
                };

                let sprout = if version.has_sprout() {
                    SproutBundleBytes::read(&mut reader, version.has_sapling())?
                } else {
                    None
                };

                let sapling_binding_sig = match &sapling {
                    Some(sapling) if !sapling.is_empty() => Some(read_fixed::<64, _>(&mut reader)?),
                    _ => None,
                };

                Ok(Self {
                    version,
                    consensus_branch_id: None,
                    lock_time,
                    expiry_height,
                    body: TransactionBodyBytes::Legacy(LegacyTransactionBodyBytes {
                        transparent,
                        sapling,
                        sprout,
                        sapling_binding_sig,
                    }),
                })
            }
            TxVersion::V5 => {
                let (consensus_branch_id, lock_time, expiry_height) =
                    read_header_fragment(&mut reader)?;
                Ok(Self {
                    version,
                    consensus_branch_id: Some(consensus_branch_id),
                    lock_time,
                    expiry_height,
                    body: TransactionBodyBytes::V5(V5TransactionBodyBytes::read(&mut reader)?),
                })
            }
            TxVersion::V6 => {
                let (consensus_branch_id, lock_time, expiry_height) =
                    read_header_fragment(&mut reader)?;
                Ok(Self {
                    version,
                    consensus_branch_id: Some(consensus_branch_id),
                    lock_time,
                    expiry_height,
                    body: TransactionBodyBytes::V6(V6TransactionBodyBytes::read(&mut reader)?),
                })
            }
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => {
                let (consensus_branch_id, lock_time, expiry_height) =
                    read_header_fragment(&mut reader)?;
                Ok(Self {
                    version,
                    consensus_branch_id: Some(consensus_branch_id),
                    lock_time,
                    expiry_height,
                    body: TransactionBodyBytes::V7(V7TransactionBodyBytes::read(&mut reader)?),
                })
            }
        }
    }

    /// Writes this transaction in its wire encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        match &self.body {
            TransactionBodyBytes::Legacy(body) => {
                body.transparent.write(&mut writer)?;
                writer.write_u32_le(self.lock_time)?;
                if self.version.has_overwinter() {
                    writer.write_u32_le(u32::from(self.expiry_height))?;
                }
                if let Some(sapling) = &body.sapling {
                    sapling.write(&mut writer)?;
                }
                if self.version.has_sprout() {
                    SproutBundleBytes::write_opt(&mut writer, body.sprout.as_ref())?;
                }
                if let Some(sig) = &body.sapling_binding_sig {
                    writer.write_all(sig)?;
                }
            }
            TransactionBodyBytes::V5(body) => {
                write_header_fragment(
                    &mut writer,
                    self.consensus_branch_id,
                    self.lock_time,
                    self.expiry_height,
                )?;
                body.write(&mut writer)?;
            }
            TransactionBodyBytes::V6(body) => {
                write_header_fragment(
                    &mut writer,
                    self.consensus_branch_id,
                    self.lock_time,
                    self.expiry_height,
                )?;
                body.write(&mut writer)?;
            }
            #[cfg(zcash_unstable = "nu8")]
            TransactionBodyBytes::V7(body) => {
                write_header_fragment(
                    &mut writer,
                    self.consensus_branch_id,
                    self.lock_time,
                    self.expiry_height,
                )?;
                body.write(&mut writer)?;
            }
        }
        Ok(())
    }

    /// Computes the [ZIP 248](https://zips.z.cash/zip-0248) transaction digest
    /// tree for a version 7 transaction.
    ///
    /// Known bundle types are digested from their byte-layer fields. A bundle
    /// whose type or variant this implementation does not interpret has no
    /// defined digest here, so its canonical digest is taken from `provider`.
    /// Parsing never requires a provider; only digest resolution does.
    ///
    /// The supplied digests are trusted: the byte layer cannot verify a digest
    /// for a bundle it does not interpret, so the resulting identifier is only
    /// as trustworthy as the provider.
    ///
    /// # Errors
    ///
    /// Returns [`V7DigestError::NotV7`] if this is not a version 7 transaction,
    /// [`V7DigestError::UnrecognizedBranchId`] if the encoded consensus branch
    /// ID is not a recognized [`BranchId`],
    /// [`V7DigestError::MissingEffectsDigest`] if `provider` does not supply a
    /// digest for an opaque bundle, or
    /// [`V7DigestError::MissingSaplingAnchor`] if a Sapling bundle has spends
    /// but no anchor.
    #[cfg(zcash_unstable = "nu8")]
    pub fn v7_txid_digests(
        &self,
        provider: &impl BundleDigestProvider,
    ) -> Result<Zip244Digests<Blake2bHash>, V7DigestError> {
        use super::txid;

        let body = self.body.as_v7().ok_or(V7DigestError::NotV7)?;
        let consensus_branch_id = self.v7_branch_id()?;

        let mut transparent_digests = None;
        let mut coinbase_digest = None;
        let mut sapling_digest = None;
        let mut orchard_digest = None;
        let mut ironwood_digest = None;
        let mut unknown_effect_digests = Vec::new();

        for bundle in body.bundles() {
            match bundle {
                V7BundleBytes::Transparent(bundle) => {
                    transparent_digests = Some(txid::transparent_digests_bytes(bundle));
                }
                V7BundleBytes::Coinbase(_) | V7BundleBytes::CoinbaseWithAuth(..) => {
                    coinbase_digest = Some(bundle.effects_digest(provider)?);
                }
                V7BundleBytes::Sapling(_) => {
                    sapling_digest = Some(bundle.effects_digest(provider)?);
                }
                V7BundleBytes::Orchard(_) => {
                    orchard_digest = Some(bundle.effects_digest(provider)?);
                }
                V7BundleBytes::Ironwood(_) => {
                    ironwood_digest = Some(bundle.effects_digest(provider)?);
                }
                V7BundleBytes::KnownOpaque(_)
                | V7BundleBytes::KnownTypeUnknownVariant(_)
                | V7BundleBytes::Unknown(_) => {
                    unknown_effect_digests
                        .push((bundle.digest_key(), bundle.effects_digest(provider)?));
                }
            }
        }

        Ok(Zip244Digests {
            header_digest: txid::hash_v7_header(
                self.version,
                consensus_branch_id,
                self.lock_time,
                self.expiry_height,
            ),
            transparent_digests,
            sapling_digest,
            orchard_digest,
            ironwood_digest,
            coinbase_digest,
            value_pool_deltas_digest: Some(body.value_pool_deltas_digest()),
            unknown_effect_digests,
        })
    }

    /// Computes the [ZIP 248](https://zips.z.cash/zip-0248) transaction
    /// identifier for a version 7 transaction.
    ///
    /// The supplied digests are trusted: see [`Self::v7_txid_digests`].
    ///
    /// # Errors
    ///
    /// Returns [`V7DigestError::NotV7`] if this is not a version 7 transaction,
    /// [`V7DigestError::UnrecognizedBranchId`] if the encoded consensus branch
    /// ID is not a recognized [`BranchId`],
    /// [`V7DigestError::MissingEffectsDigest`] if `provider` does not supply a
    /// digest for an opaque bundle, or
    /// [`V7DigestError::MissingSaplingAnchor`] if a Sapling bundle has spends
    /// but no anchor.
    #[cfg(zcash_unstable = "nu8")]
    pub fn v7_txid(&self, provider: &impl BundleDigestProvider) -> Result<TxId, V7DigestError> {
        let digests = self.v7_txid_digests(provider)?;
        let consensus_branch_id = self.v7_branch_id()?;
        Ok(super::txid::to_txid_v7(consensus_branch_id, &digests))
    }

    /// Computes the [ZIP 248 §A.1](https://zips.z.cash/zip-0248#a-1-auth_bundles_digest)
    /// authorizing-data commitment for a version 7 transaction.
    ///
    /// The supplied digests are trusted: see [`Self::v7_txid_digests`].
    ///
    /// # Errors
    ///
    /// Returns [`V7DigestError::NotV7`] if this is not a version 7 transaction,
    /// [`V7DigestError::UnrecognizedBranchId`] if the encoded consensus branch
    /// ID is not a recognized [`BranchId`], or
    /// [`V7DigestError::MissingAuthDigest`] if `provider` does not supply a
    /// digest for an opaque bundle, or for a coinbase bundle with a prohibited
    /// authorizing payload, that has authorizing data.
    #[cfg(zcash_unstable = "nu8")]
    pub fn v7_auth_commitment(
        &self,
        provider: &impl BundleDigestProvider,
    ) -> Result<Blake2bHash, V7DigestError> {
        use super::txid;

        let body = self.body.as_v7().ok_or(V7DigestError::NotV7)?;
        let consensus_branch_id = self.v7_branch_id()?;
        let auth_bundles_digest = body.auth_bundles_digest(provider)?;

        let mut personal = [0; 16];
        personal[..12].copy_from_slice(txid::ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32_le(u32::from(consensus_branch_id))
            .expect("writing to a fixed-size buffer is infallible");

        let mut h = txid::hasher(&personal);
        h.write_all(auth_bundles_digest.as_bytes())
            .expect("writing to a hasher is infallible");
        Ok(h.finalize())
    }

    /// Returns the typed consensus branch ID required by the version 7 digest
    /// and authorizing-data commitment computations.
    ///
    /// Returns [`V7DigestError::NotV7`] if the format does not encode a branch
    /// ID, or [`V7DigestError::UnrecognizedBranchId`] if the encoded value is
    /// not a recognized [`BranchId`].
    #[cfg(zcash_unstable = "nu8")]
    fn v7_branch_id(&self) -> Result<BranchId, V7DigestError> {
        let raw = self.consensus_branch_id.ok_or(V7DigestError::NotV7)?;
        BranchId::try_from(raw).map_err(|_| V7DigestError::UnrecognizedBranchId { branch_id: raw })
    }
}

/// A whole transaction in its wire representation.
///
/// This is the ZIP 248 byte-layer name for [`TransactionBytes`]; the two are
/// the same type. It carries the common header fields and the
/// version-specific [`TransactionBodyBytes`].
pub type TransactionDataBytes = TransactionBytes;

/// The body of a transaction, in the layout of its format family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionBodyBytes {
    /// Versions 1 through 4.
    Legacy(LegacyTransactionBodyBytes),
    /// Version 5 ([ZIP 225]).
    ///
    /// [ZIP 225]: https://zips.z.cash/zip-0225
    V5(V5TransactionBodyBytes),
    /// Version 6 ([ZIP 229]).
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    V6(V6TransactionBodyBytes),
    /// Version 7 ([ZIP 248]).
    ///
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    #[cfg(zcash_unstable = "nu8")]
    V7(V7TransactionBodyBytes),
}

impl TransactionBodyBytes {
    /// Returns the legacy body, if this is a version 1 through 4 transaction.
    pub fn as_legacy(&self) -> Option<&LegacyTransactionBodyBytes> {
        match self {
            Self::Legacy(body) => Some(body),
            _ => None,
        }
    }

    /// Returns the version 5 body, if this is a version 5 transaction.
    pub fn as_v5(&self) -> Option<&V5TransactionBodyBytes> {
        match self {
            Self::V5(body) => Some(body),
            _ => None,
        }
    }

    /// Returns the version 6 body, if this is a version 6 transaction.
    pub fn as_v6(&self) -> Option<&V6TransactionBodyBytes> {
        match self {
            Self::V6(body) => Some(body),
            _ => None,
        }
    }

    /// Returns the version 7 body, if this is a version 7 transaction.
    #[cfg(zcash_unstable = "nu8")]
    pub fn as_v7(&self) -> Option<&V7TransactionBodyBytes> {
        match self {
            Self::V7(body) => Some(body),
            _ => None,
        }
    }
}

/// The body of a version 1 through 4 transaction.
///
/// The wire layout interleaves the transparent bundle with the header fields:
/// `transparent || lock_time || expiry_height? || sapling? || sprout? ||
/// binding_sig?`. The fields are stored in that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyTransactionBodyBytes {
    transparent: LegacyTransparentBundleBytes,
    sapling: Option<V4SaplingBundleBytes>,
    sprout: Option<SproutBundleBytes>,
    sapling_binding_sig: Option<[u8; 64]>,
}

impl LegacyTransactionBodyBytes {
    /// Constructs a legacy body from its wire fields.
    ///
    /// Returns an error if a Sapling binding signature is present without a
    /// non-empty Sapling bundle, or absent from one.
    pub fn from_parts(
        transparent: LegacyTransparentBundleBytes,
        sapling: Option<V4SaplingBundleBytes>,
        sprout: Option<SproutBundleBytes>,
        sapling_binding_sig: Option<[u8; 64]>,
    ) -> io::Result<Self> {
        let sapling_nonempty = sapling.as_ref().is_some_and(|s| !s.is_empty());
        if sapling_nonempty != sapling_binding_sig.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a Sapling binding signature is present exactly when the Sapling bundle is non-empty",
            ));
        }
        Ok(Self {
            transparent,
            sapling,
            sprout,
            sapling_binding_sig,
        })
    }

    /// Returns the transparent bundle.
    pub fn transparent(&self) -> &LegacyTransparentBundleBytes {
        &self.transparent
    }

    /// Returns the version 4 Sapling bundle, if present.
    pub fn sapling(&self) -> Option<&V4SaplingBundleBytes> {
        self.sapling.as_ref()
    }

    /// Returns the Sprout bundle, if present.
    pub fn sprout(&self) -> Option<&SproutBundleBytes> {
        self.sprout.as_ref()
    }

    /// Returns the Sapling binding signature, if present.
    pub fn sapling_binding_sig(&self) -> Option<&[u8; 64]> {
        self.sapling_binding_sig.as_ref()
    }
}

/// The body of a version 5 transaction.
///
/// The wire layout is `transparent || sapling || orchard`, with each bundle
/// encoded in its [ZIP 225] form.
///
/// [ZIP 225]: https://zips.z.cash/zip-0225
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V5TransactionBodyBytes {
    transparent: LegacyTransparentBundleBytes,
    sapling: Option<SaplingBundleBytes>,
    orchard: Option<OrchardBundleBytes>,
}

impl V5TransactionBodyBytes {
    /// Constructs a version 5 body from its wire fields.
    pub fn from_parts(
        transparent: LegacyTransparentBundleBytes,
        sapling: Option<SaplingBundleBytes>,
        orchard: Option<OrchardBundleBytes>,
    ) -> Self {
        Self {
            transparent,
            sapling,
            orchard,
        }
    }

    /// Returns the transparent bundle.
    pub fn transparent(&self) -> &LegacyTransparentBundleBytes {
        &self.transparent
    }

    /// Returns the Sapling bundle, if present.
    pub fn sapling(&self) -> Option<&SaplingBundleBytes> {
        self.sapling.as_ref()
    }

    /// Returns the Orchard bundle, if present.
    pub fn orchard(&self) -> Option<&OrchardBundleBytes> {
        self.orchard.as_ref()
    }

    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let transparent = LegacyTransparentBundleBytes::read(&mut reader)?;
        let sapling = SaplingBundleBytes::read(&mut reader)?;
        let orchard = OrchardBundleBytes::read(&mut reader)?;
        Ok(Self {
            transparent,
            sapling,
            orchard,
        })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.transparent.write(&mut writer)?;
        SaplingBundleBytes::write_opt(&mut writer, self.sapling.as_ref())?;
        OrchardBundleBytes::write_opt(&mut writer, self.orchard.as_ref())
    }
}

/// The body of a version 6 transaction.
///
/// The wire layout is `transparent || sapling || orchard || ironwood`, with
/// each bundle encoded in its [ZIP 229] form.
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V6TransactionBodyBytes {
    transparent: LegacyTransparentBundleBytes,
    sapling: Option<SaplingBundleBytes>,
    orchard: Option<OrchardBundleBytes>,
    ironwood: Option<IronwoodBundleBytes>,
}

impl V6TransactionBodyBytes {
    /// Constructs a version 6 body from its wire fields.
    pub fn from_parts(
        transparent: LegacyTransparentBundleBytes,
        sapling: Option<SaplingBundleBytes>,
        orchard: Option<OrchardBundleBytes>,
        ironwood: Option<IronwoodBundleBytes>,
    ) -> Self {
        Self {
            transparent,
            sapling,
            orchard,
            ironwood,
        }
    }

    /// Returns the transparent bundle.
    pub fn transparent(&self) -> &LegacyTransparentBundleBytes {
        &self.transparent
    }

    /// Returns the Sapling bundle, if present.
    pub fn sapling(&self) -> Option<&SaplingBundleBytes> {
        self.sapling.as_ref()
    }

    /// Returns the Orchard bundle, if present.
    pub fn orchard(&self) -> Option<&OrchardBundleBytes> {
        self.orchard.as_ref()
    }

    /// Returns the Ironwood bundle, if present.
    pub fn ironwood(&self) -> Option<&IronwoodBundleBytes> {
        self.ironwood.as_ref()
    }

    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let transparent = LegacyTransparentBundleBytes::read(&mut reader)?;
        let sapling = SaplingBundleBytes::read(&mut reader)?;
        let orchard = OrchardBundleBytes::read(&mut reader)?;
        let ironwood = OrchardBundleBytes::read(&mut reader)?;
        Ok(Self {
            transparent,
            sapling,
            orchard,
            ironwood,
        })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.transparent.write(&mut writer)?;
        SaplingBundleBytes::write_opt(&mut writer, self.sapling.as_ref())?;
        OrchardBundleBytes::write_opt(&mut writer, self.orchard.as_ref())?;
        OrchardBundleBytes::write_opt(&mut writer, self.ironwood.as_ref())
    }
}

/// Reads the header fields common to version 5 and later transactions.
///
/// `nConsensusBranchId` is a `uint32` on the wire, so it is returned raw.
fn read_header_fragment<R: Read>(mut reader: R) -> io::Result<(u32, u32, BlockHeight)> {
    let consensus_branch_id = reader.read_u32_le()?;
    let lock_time = reader.read_u32_le()?;
    let expiry_height: BlockHeight = reader.read_u32_le()?.into();
    Ok((consensus_branch_id, lock_time, expiry_height))
}

/// Writes the header fields common to version 5 and later transactions.
pub(crate) fn write_header_fragment<W: Write>(
    mut writer: W,
    consensus_branch_id: Option<u32>,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> io::Result<()> {
    let consensus_branch_id = consensus_branch_id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "transaction version 5 and later require a consensus branch ID",
        )
    })?;
    writer.write_u32_le(consensus_branch_id)?;
    writer.write_u32_le(lock_time)?;
    writer.write_u32_le(u32::from(expiry_height))
}
