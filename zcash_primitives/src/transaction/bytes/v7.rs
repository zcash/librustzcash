//! Byte-level representation of the version 7 (ZIP 248) transaction body.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{CompactSize, MAX_COMPACT_SIZE};
use zcash_protocol::{constants::MAX_BLOCK_BYTES, value::ZatBalance};

use super::{
    CoinbaseBundleBytes, TransparentBundleBytes, V7OrchardBundleBytes, V7SaplingBundleBytes,
    read_fixed,
};
use crate::transaction::zip248::{self, BundleType, BundleVariant};

/// The size in bytes of an asset UUID.
const ASSET_UUID_SIZE: usize = 64;
/// The size in bytes of a value pool delta.
const VALUE_SIZE: usize = 8;

/// The asset class of a value pool delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssetClass {
    /// The ZEC asset (`assetClass = 0`).
    Zec,
    /// A non-ZEC asset (`assetClass = 1`), identified by its 64-byte UUID.
    Other([u8; ASSET_UUID_SIZE]),
}

impl AssetClass {
    /// Returns the asset UUID, or `None` for ZEC.
    pub fn asset_uuid(&self) -> Option<&[u8; ASSET_UUID_SIZE]> {
        match self {
            Self::Zec => None,
            Self::Other(uuid) => Some(uuid),
        }
    }

    /// Returns `true` if this is the ZEC asset.
    pub fn is_zec(&self) -> bool {
        matches!(self, Self::Zec)
    }

    /// Reads an asset class and its optional UUID.
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut class = [0u8; 1];
        reader.read_exact(&mut class)?;
        match class[0] {
            0 => Ok(Self::Zec),
            1 => Ok(Self::Other(read_fixed::<ASSET_UUID_SIZE, _>(&mut reader)?)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                alloc::format!("assetClass must be 0 or 1, got {other:#x}"),
            )),
        }
    }

    /// Writes an asset class and its optional UUID.
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match self {
            Self::Zec => writer.write_all(&[0]),
            Self::Other(uuid) => {
                writer.write_all(&[1])?;
                writer.write_all(uuid)
            }
        }
    }
}

/// A single value pool delta entry in its wire representation.
///
/// The value is retained as the raw signed 64-bit integer from the wire. The
/// byte layer enforces only the nonzero rule; narrowing to [`ZatBalance`]
/// happens when the entry is converted to its typed representation.
///
/// [ZIP 248 §ValuePoolDelta](https://zips.z.cash/zip-0248#valuepooldelta)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValuePoolDeltaBytes {
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    asset_class: AssetClass,
    value: i64,
}

impl ValuePoolDeltaBytes {
    /// Constructs a value pool delta from its wire fields.
    ///
    /// Returns an error if the value is zero, since a zero-valued entry must be
    /// elided from the encoding, or if a raw identifier has no `compactSize`
    /// encoding.
    pub fn from_parts(
        bundle_type: BundleType,
        bundle_variant: BundleVariant,
        asset_class: AssetClass,
        value: i64,
    ) -> io::Result<Self> {
        check_raw_key(bundle_type, bundle_variant)?;
        if value == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a zero-valued value pool delta must be elided",
            ));
        }
        Ok(Self {
            bundle_type,
            bundle_variant,
            asset_class,
            value,
        })
    }

    /// Returns the raw bundle type.
    pub fn bundle_type(&self) -> BundleType {
        self.bundle_type
    }

    /// Returns the raw bundle variant.
    pub fn bundle_variant(&self) -> BundleVariant {
        self.bundle_variant
    }

    /// Returns the asset class.
    pub fn asset_class(&self) -> &AssetClass {
        &self.asset_class
    }

    /// Returns the signed value pool delta as the raw wire integer.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Returns `true` if this entry belongs to a value-only bundle type.
    ///
    /// The fee and ZIP 233 NSM bundle types carry only a value pool delta and
    /// have no effecting or authorizing data.
    pub fn is_value_only(&self) -> bool {
        matches!(self.bundle_type, BundleType::FEE | BundleType::ZIP233_NSM)
    }

    /// Reads a value pool delta entry.
    ///
    /// The value is retained as the raw signed 64-bit integer from the wire and
    /// is not narrowed to the monetary domain.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let bundle_type = BundleType::from_u64(CompactSize::read(&mut reader)?);
        let bundle_variant = BundleVariant::from_u64(CompactSize::read(&mut reader)?);
        let asset_class = AssetClass::read(&mut reader)?;
        let mut value = [0u8; VALUE_SIZE];
        reader.read_exact(&mut value)?;
        let value = i64::from_le_bytes(value);
        Self::from_parts(bundle_type, bundle_variant, asset_class, value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "value pool delta is zero"))
    }

    /// Writes a value pool delta entry.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type.to_u64() as usize)?;
        CompactSize::write(&mut writer, self.bundle_variant.to_u64() as usize)?;
        self.asset_class.write(&mut writer)?;
        writer.write_all(&self.value.to_le_bytes())
    }
}

#[cfg(zcash_unstable = "nu8")]
impl TryFrom<&zip248::ValuePoolDeltaEntry> for ValuePoolDeltaBytes {
    type Error = io::Error;

    fn try_from(entry: &zip248::ValuePoolDeltaEntry) -> io::Result<Self> {
        let asset_class = match entry.asset_uuid() {
            Some(uuid) => AssetClass::Other(*uuid),
            None => AssetClass::Zec,
        };
        Self::from_parts(
            entry.bundle_type(),
            entry.bundle_variant(),
            asset_class,
            i64::from(entry.value()),
        )
    }
}

/// An opaque bundle payload retained without interpretation.
///
/// This is used for bundle types or variants the byte layer does not parse,
/// and for recognized types whose payload is not interpreted at this layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueBundleBytes {
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    effects: Vec<u8>,
    auth: Option<Vec<u8>>,
}

impl OpaqueBundleBytes {
    /// Constructs an opaque bundle from its raw payloads.
    ///
    /// Returns an error if a raw identifier has no `compactSize` encoding, or
    /// if either payload exceeds [`MAX_BLOCK_BYTES`], which the wire encoding
    /// cannot represent.
    pub fn from_parts(
        bundle_type: BundleType,
        bundle_variant: BundleVariant,
        effects: Vec<u8>,
        auth: Option<Vec<u8>>,
    ) -> io::Result<Self> {
        check_raw_key(bundle_type, bundle_variant)?;
        if effects.len() > MAX_BLOCK_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bundle effecting data exceeds the maximum block size",
            ));
        }
        if let Some(auth) = &auth
            && auth.len() > MAX_BLOCK_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bundle authorizing data exceeds the maximum block size",
            ));
        }
        Ok(Self {
            bundle_type,
            bundle_variant,
            effects,
            auth,
        })
    }

    /// Returns the raw bundle type.
    pub fn bundle_type(&self) -> BundleType {
        self.bundle_type
    }

    /// Returns the raw bundle variant.
    pub fn bundle_variant(&self) -> BundleVariant {
        self.bundle_variant
    }

    /// Returns the raw effecting data.
    pub fn effects(&self) -> &[u8] {
        &self.effects
    }

    /// Returns the raw authorizing data, if present.
    pub fn auth(&self) -> Option<&[u8]> {
        self.auth.as_deref()
    }
}

/// A version 7 bundle, either parsed into its protocol-specific byte
/// representation or retained opaquely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V7BundleBytes {
    /// A transparent bundle.
    Transparent(TransparentBundleBytes),
    /// A coinbase bundle.
    Coinbase(CoinbaseBundleBytes),
    /// A coinbase bundle with an authorizing payload.
    ///
    /// The registry prohibits the coinbase authorizing column, so the payload
    /// is retained without interpretation. Keeping it lets the transaction
    /// round-trip; [`TransactionBytes::validate_v7`] rejects the entry.
    ///
    /// [`TransactionBytes::validate_v7`]: super::TransactionBytes::validate_v7
    CoinbaseWithAuth(CoinbaseBundleBytes, Vec<u8>),
    /// A Sapling bundle.
    Sapling(V7SaplingBundleBytes),
    /// An Orchard bundle.
    Orchard(V7OrchardBundleBytes),
    /// An Ironwood bundle.
    Ironwood(V7OrchardBundleBytes),
    /// A bundle whose type and variant are recognized, but whose payload is
    /// not interpreted at this layer.
    KnownOpaque(OpaqueBundleBytes),
    /// A bundle whose type is recognized but whose variant is not.
    KnownTypeUnknownVariant(OpaqueBundleBytes),
    /// A bundle whose type is not recognized.
    Unknown(OpaqueBundleBytes),
}

impl V7BundleBytes {
    /// Returns the raw bundle type.
    pub fn bundle_type(&self) -> BundleType {
        match self {
            Self::Transparent(_) => BundleType::TRANSPARENT,
            Self::Coinbase(_) | Self::CoinbaseWithAuth(..) => BundleType::COINBASE,
            Self::Sapling(_) => BundleType::SAPLING,
            Self::Orchard(_) => BundleType::ORCHARD,
            Self::Ironwood(_) => BundleType::IRONWOOD,
            Self::KnownOpaque(bundle)
            | Self::KnownTypeUnknownVariant(bundle)
            | Self::Unknown(bundle) => bundle.bundle_type,
        }
    }

    /// Returns the raw bundle variant.
    pub fn bundle_variant(&self) -> BundleVariant {
        match self {
            Self::Transparent(_)
            | Self::Coinbase(_)
            | Self::CoinbaseWithAuth(..)
            | Self::Sapling(_)
            | Self::Orchard(_)
            | Self::Ironwood(_) => BundleVariant::DEFAULT,
            Self::KnownOpaque(bundle)
            | Self::KnownTypeUnknownVariant(bundle)
            | Self::Unknown(bundle) => bundle.bundle_variant,
        }
    }

    /// Returns `true` if this bundle has authorizing data.
    pub fn has_auth(&self) -> bool {
        match self {
            Self::Transparent(bundle) => bundle.auth().is_some(),
            Self::Coinbase(_) => false,
            Self::CoinbaseWithAuth(..) => true,
            Self::Sapling(bundle) => bundle.has_auth(),
            Self::Orchard(bundle) | Self::Ironwood(bundle) => bundle.has_auth(),
            Self::KnownOpaque(bundle)
            | Self::KnownTypeUnknownVariant(bundle)
            | Self::Unknown(bundle) => bundle.auth.is_some(),
        }
    }

    /// Returns the transparent bundle, if this is one.
    pub fn as_transparent(&self) -> Option<&TransparentBundleBytes> {
        match self {
            Self::Transparent(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Returns the coinbase bundle, if this is one.
    pub fn as_coinbase(&self) -> Option<&CoinbaseBundleBytes> {
        match self {
            Self::Coinbase(bundle) | Self::CoinbaseWithAuth(bundle, _) => Some(bundle),
            _ => None,
        }
    }

    /// Returns the retained coinbase authorizing payload, if present.
    ///
    /// The registry prohibits the coinbase authorizing column, so this payload
    /// is never interpreted.
    pub fn coinbase_auth(&self) -> Option<&[u8]> {
        match self {
            Self::CoinbaseWithAuth(_, auth) => Some(auth),
            _ => None,
        }
    }

    /// Returns the Sapling bundle, if this is one.
    pub fn as_sapling(&self) -> Option<&V7SaplingBundleBytes> {
        match self {
            Self::Sapling(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Returns the Orchard bundle, if this is one.
    pub fn as_orchard(&self) -> Option<&V7OrchardBundleBytes> {
        match self {
            Self::Orchard(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Returns the Ironwood bundle, if this is one.
    pub fn as_ironwood(&self) -> Option<&V7OrchardBundleBytes> {
        match self {
            Self::Ironwood(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Returns the opaque payload, if this bundle was not parsed.
    pub fn as_opaque(&self) -> Option<&OpaqueBundleBytes> {
        match self {
            Self::KnownOpaque(bundle)
            | Self::KnownTypeUnknownVariant(bundle)
            | Self::Unknown(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Returns the exact raw digest key of this bundle.
    pub fn digest_key(&self) -> zip248::BundleId {
        zip248::BundleId::new(self.bundle_type(), self.bundle_variant())
    }

    /// Computes this bundle's effecting-data digest.
    ///
    /// Known bundle types are digested from their byte-layer fields. A bundle
    /// whose type or variant this implementation does not interpret has no
    /// defined digest here, so its canonical digest is taken from `provider`.
    ///
    /// # Errors
    ///
    /// Returns [`zip248::V7DigestError::MissingEffectsDigest`] if `provider`
    /// does not supply a digest for an opaque bundle, or
    /// [`zip248::V7DigestError::MissingSaplingAnchor`] if a Sapling bundle has
    /// spends but no anchor.
    pub fn effects_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<blake2b_simd::Hash, zip248::V7DigestError> {
        use super::super::txid;

        match self {
            Self::Transparent(bundle) => Ok(txid::hash_v7_transparent_effects_bytes(bundle)),
            Self::Coinbase(bundle) | Self::CoinbaseWithAuth(bundle, _) => {
                Ok(txid::hash_v7_coinbase_effects_bytes(bundle))
            }
            Self::Sapling(bundle) => txid::hash_v7_sapling_effects_bytes(bundle),
            Self::Orchard(bundle) => Ok(txid::hash_v7_orchard_effects_bytes(bundle)),
            Self::Ironwood(bundle) => Ok(txid::hash_v7_ironwood_effects_bytes(bundle)),
            Self::KnownOpaque(_) | Self::KnownTypeUnknownVariant(_) | Self::Unknown(_) => {
                let key = self.digest_key();
                provider
                    .effects_digest(key)
                    .ok_or(zip248::V7DigestError::MissingEffectsDigest { key })
            }
        }
    }

    /// Computes this bundle's authorizing-data digest, if it has authorizing
    /// data.
    ///
    /// Known bundle types are digested from their byte-layer fields. A bundle
    /// whose type or variant this implementation does not interpret has no
    /// defined digest here, so its canonical digest is taken from `provider`.
    ///
    /// # Errors
    ///
    /// Returns [`zip248::V7DigestError::MissingAuthDigest`] if `provider` does
    /// not supply a digest for an opaque bundle, or for a coinbase bundle with
    /// a prohibited authorizing payload, that has authorizing data.
    pub fn auth_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<Option<blake2b_simd::Hash>, zip248::V7DigestError> {
        use super::super::txid;

        if !self.has_auth() {
            return Ok(None);
        }
        match self {
            Self::Transparent(bundle) => Ok(Some(txid::hash_v7_transparent_auth_bytes(bundle))),
            Self::Coinbase(_) => Ok(None),
            Self::CoinbaseWithAuth(_, _) => {
                // The registry prohibits this payload, so its canonical digest
                // is not defined here and must be supplied.
                let key = self.digest_key();
                provider
                    .auth_digest(key)
                    .map(Some)
                    .ok_or(zip248::V7DigestError::MissingAuthDigest { key })
            }
            Self::Sapling(bundle) => Ok(Some(txid::hash_v7_sapling_auth_bytes(bundle))),
            Self::Orchard(bundle) => Ok(Some(txid::hash_v7_orchard_auth_bytes(bundle))),
            Self::Ironwood(bundle) => Ok(Some(txid::hash_v7_ironwood_auth_bytes(bundle))),
            Self::KnownOpaque(_) | Self::KnownTypeUnknownVariant(_) | Self::Unknown(_) => {
                let key = self.digest_key();
                provider
                    .auth_digest(key)
                    .map(Some)
                    .ok_or(zip248::V7DigestError::MissingAuthDigest { key })
            }
        }
    }

    /// Writes this bundle's effecting data.
    pub fn write_effects<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match self {
            Self::Transparent(bundle) => bundle.write_effects(&mut writer),
            Self::Coinbase(bundle) => bundle.write(&mut writer),
            Self::CoinbaseWithAuth(bundle, _) => bundle.write(&mut writer),
            Self::Sapling(bundle) => bundle.write_effects(&mut writer),
            Self::Orchard(bundle) | Self::Ironwood(bundle) => bundle.write_effects(&mut writer),
            Self::KnownOpaque(bundle)
            | Self::KnownTypeUnknownVariant(bundle)
            | Self::Unknown(bundle) => writer.write_all(&bundle.effects),
        }
    }

    /// Writes this bundle's authorizing data, if it has any.
    pub fn write_auth<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match self {
            Self::Transparent(bundle) => bundle.write_auth(&mut writer),
            Self::Coinbase(_) => Ok(()),
            Self::CoinbaseWithAuth(_, auth) => writer.write_all(auth),
            Self::Sapling(bundle) => bundle.write_auth(&mut writer),
            Self::Orchard(bundle) | Self::Ironwood(bundle) => bundle.write_auth(&mut writer),
            Self::KnownOpaque(bundle)
            | Self::KnownTypeUnknownVariant(bundle)
            | Self::Unknown(bundle) => match &bundle.auth {
                Some(auth) => writer.write_all(auth),
                None => Ok(()),
            },
        }
    }
}

/// The body of a version 7 transaction.
///
/// [ZIP 248 §Transaction Format](https://zips.z.cash/zip-0248#transaction-format)
///
/// The value pool deltas and the effect/auth bundle maps are retained
/// separately. Known bundle types are parsed into their protocol-specific byte
/// representations; unknown types and variants are retained opaquely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7TransactionBodyBytes {
    value_pool_deltas: Vec<ValuePoolDeltaBytes>,
    bundles: Vec<V7BundleBytes>,
}

impl V7TransactionBodyBytes {
    /// Constructs a version 7 body from its value pool deltas and bundles.
    ///
    /// Returns an error if the value pool deltas are not in strictly
    /// increasing `(bundleType, assetClass, assetUuid)` order, if the bundles
    /// are not in strictly increasing `bundleType` order, if a bundle type
    /// appears with more than one variant across the maps, if a raw identifier
    /// has no `compactSize` encoding, or if a bundle's encoded effecting or
    /// authorizing payload exceeds [`MAX_BLOCK_BYTES`].
    pub fn from_parts(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        bundles: Vec<V7BundleBytes>,
    ) -> io::Result<Self> {
        let body = Self {
            value_pool_deltas,
            bundles,
        };
        body.validate()?;
        body.validate_payload_sizes()?;
        Ok(body)
    }

    /// Constructs a body from payloads that were already bounded by the wire
    /// reader.
    fn from_parts_read(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        bundles: Vec<V7BundleBytes>,
    ) -> io::Result<Self> {
        let body = Self {
            value_pool_deltas,
            bundles,
        };
        body.validate()?;
        Ok(body)
    }

    /// Returns the value pool delta entries in canonical order.
    pub fn value_pool_deltas(&self) -> &[ValuePoolDeltaBytes] {
        &self.value_pool_deltas
    }

    /// Interprets the value pool delta entries as a typed
    /// [`zip248::ValuePoolDeltas`] map.
    ///
    /// Entries for recognized bundle types and variants are stored in the
    /// typed map; entries for unrecognized types or variants are retained in
    /// its opaque map so that the transaction can be re-serialized.
    ///
    /// # Errors
    ///
    /// Returns an error if a raw delta is outside the [`ZatBalance`] monetary
    /// domain.
    pub fn to_value_pool_deltas(&self) -> io::Result<zip248::ValuePoolDeltas> {
        let mut deltas = zip248::ValuePoolDeltas::empty();
        for entry in &self.value_pool_deltas {
            let value = ZatBalance::from_i64(entry.value()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "value pool delta out of valid monetary range",
                )
            })?;
            let asset_class = match entry.asset_class() {
                AssetClass::Zec => zip248::ASSET_CLASS_ZEC,
                AssetClass::Other(_) => zip248::ASSET_CLASS_OTHER,
            };
            let asset_uuid = entry
                .asset_class()
                .asset_uuid()
                .copied()
                .unwrap_or([0u8; 64]);
            let key =
                zip248::ValuePoolDeltaKey::from_parts(entry.bundle_type(), asset_class, asset_uuid)
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, alloc::format!("{e}"))
                    })?;
            deltas
                .insert(key, entry.bundle_variant(), value)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, alloc::format!("{e}")))?;
        }
        Ok(deltas)
    }

    /// Returns the bundles in bundle-type order.
    pub fn bundles(&self) -> &[V7BundleBytes] {
        &self.bundles
    }

    /// Returns the transparent bundle, if present.
    pub fn transparent(&self) -> Option<&TransparentBundleBytes> {
        self.bundles.iter().find_map(V7BundleBytes::as_transparent)
    }

    /// Returns the coinbase bundle, if present.
    pub fn coinbase(&self) -> Option<&CoinbaseBundleBytes> {
        self.bundles.iter().find_map(V7BundleBytes::as_coinbase)
    }

    /// Returns the Sapling bundle, if present.
    pub fn sapling(&self) -> Option<&V7SaplingBundleBytes> {
        self.bundles.iter().find_map(V7BundleBytes::as_sapling)
    }

    /// Returns the Orchard bundle, if present.
    pub fn orchard(&self) -> Option<&V7OrchardBundleBytes> {
        self.bundles.iter().find_map(V7BundleBytes::as_orchard)
    }

    /// Returns the Ironwood bundle, if present.
    pub fn ironwood(&self) -> Option<&V7OrchardBundleBytes> {
        self.bundles.iter().find_map(V7BundleBytes::as_ironwood)
    }

    /// Returns an iterator over the bundles that were not parsed.
    pub fn opaque_bundles(&self) -> impl Iterator<Item = &OpaqueBundleBytes> {
        self.bundles.iter().filter_map(V7BundleBytes::as_opaque)
    }

    /// Returns the raw ZEC value pool delta for the given bundle type, if
    /// present.
    pub fn zec_value_pool_delta(&self, bundle_type: BundleType) -> Option<i64> {
        self.value_pool_deltas
            .iter()
            .find(|entry| entry.bundle_type() == bundle_type && entry.asset_class().is_zec())
            .map(ValuePoolDeltaBytes::value)
    }

    /// Computes the [ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest)
    /// digest of this body's value pool deltas.
    pub fn value_pool_deltas_digest(&self) -> blake2b_simd::Hash {
        super::super::txid::hash_v7_value_pool_deltas_bytes(&self.value_pool_deltas)
    }

    /// Computes the [ZIP 248 §T.3](https://zips.z.cash/zip-0248#t-3-effects_bundles_digest)
    /// digest of this body's effecting bundles.
    ///
    /// # Errors
    ///
    /// Returns [`zip248::V7DigestError::MissingEffectsDigest`] if `provider`
    /// does not supply a digest for an opaque bundle.
    pub fn effects_bundles_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<blake2b_simd::Hash, zip248::V7DigestError> {
        let mut entries = Vec::with_capacity(self.bundles.len());
        for bundle in &self.bundles {
            entries.push((
                bundle.digest_key().wire_key(),
                bundle.effects_digest(provider)?,
            ));
        }
        Ok(super::super::txid::hash_v7_effects_bundles(
            entries.iter().map(|(key, digest)| (*key, digest)),
        ))
    }

    /// Computes the [ZIP 248 §A.1](https://zips.z.cash/zip-0248#a-1-auth_bundles_digest)
    /// digest of this body's authorizing bundles.
    ///
    /// # Errors
    ///
    /// Returns [`zip248::V7DigestError::MissingAuthDigest`] if `provider` does
    /// not supply a digest for an opaque bundle, or for a coinbase bundle with
    /// a prohibited authorizing payload, that has authorizing data.
    pub fn auth_bundles_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<blake2b_simd::Hash, zip248::V7DigestError> {
        let mut entries = Vec::new();
        for bundle in &self.bundles {
            if let Some(digest) = bundle.auth_digest(provider)? {
                entries.push((bundle.digest_key().wire_key(), digest));
            }
        }
        Ok(super::super::txid::hash_v7_auth_bundles(
            entries.iter().map(|(key, digest)| (*key, digest)),
        ))
    }

    /// Reads a version 7 body from its wire encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let (entries, _) = zip248::read_value_pool_delta_entries(&mut reader)?;
        let value_pool_deltas = entries
            .into_iter()
            .map(|entry| {
                let asset_class = match entry.asset_class() {
                    0 => AssetClass::Zec,
                    1 => AssetClass::Other(
                        entry
                            .asset_uuid()
                            .copied()
                            .unwrap_or([0u8; ASSET_UUID_SIZE]),
                    ),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "assetClass must be 0 or 1",
                        ));
                    }
                };
                ValuePoolDeltaBytes::from_parts(
                    entry.bundle_type(),
                    entry.bundle_variant(),
                    asset_class,
                    entry.value(),
                )
            })
            .collect::<io::Result<Vec<_>>>()?;
        let effect_bundles = zip248::read_bundle_data_map(&mut reader, "mEffectBundles")?;
        let auth_bundles = zip248::read_bundle_data_map(&mut reader, "mAuthBundles")?;
        Self::from_maps(value_pool_deltas, effect_bundles, auth_bundles)
    }

    /// Writes a version 7 body in its wire encoding.
    ///
    /// Returns an error before writing anything if a bundle's encoded
    /// effecting or authorizing payload exceeds [`MAX_BLOCK_BYTES`].
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.validate()?;

        CompactSize::write(&mut writer, self.value_pool_deltas.len())?;
        for entry in &self.value_pool_deltas {
            entry.write(&mut writer)?;
        }

        let effect_bundles = self
            .bundles
            .iter()
            .map(|bundle| {
                let mut data = Vec::new();
                bundle.write_effects(&mut data)?;
                Ok((
                    bundle.bundle_type().to_u64(),
                    bundle.bundle_variant().to_u64(),
                    data,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        zip248::write_bundle_data_map(&mut writer, effect_bundles)?;

        let auth_bundles = self
            .bundles
            .iter()
            .filter(|bundle| bundle.has_auth())
            .map(|bundle| {
                let mut data = Vec::new();
                bundle.write_auth(&mut data)?;
                Ok((
                    bundle.bundle_type().to_u64(),
                    bundle.bundle_variant().to_u64(),
                    data,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        zip248::write_bundle_data_map(&mut writer, auth_bundles)
    }

    /// Checks the canonical ordering and cross-map variant consistency of this
    /// body.
    fn validate(&self) -> io::Result<()> {
        let mut last_key: Option<(BundleType, AssetClass)> = None;
        for entry in &self.value_pool_deltas {
            let key = (entry.bundle_type(), *entry.asset_class());
            if let Some(previous) = &last_key
                && &key <= previous
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "value pool deltas are not in strictly increasing \
                     (bundleType, assetClass, assetUuid) order",
                ));
            }
            last_key = Some(key);
        }

        let mut last_type: Option<BundleType> = None;
        for bundle in &self.bundles {
            let bundle_type = bundle.bundle_type();
            if let Some(previous) = last_type
                && bundle_type <= previous
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bundles are not in strictly increasing bundleType order",
                ));
            }
            last_type = Some(bundle_type);
            check_raw_key(bundle_type, bundle.bundle_variant())?;
            match bundle {
                V7BundleBytes::KnownOpaque(opaque)
                    if !opaque.bundle_type.is_known() || !opaque.bundle_variant.is_known() =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a KnownOpaque bundle must have a recognized type and variant",
                    ));
                }
                V7BundleBytes::KnownOpaque(opaque) => match opaque.bundle_type {
                    BundleType::TRANSPARENT
                    | BundleType::COINBASE
                    | BundleType::SAPLING
                    | BundleType::ORCHARD
                    | BundleType::IRONWOOD => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "a bundle type with a parsed representation must use it",
                        ));
                    }
                    _ => {}
                },
                V7BundleBytes::KnownTypeUnknownVariant(opaque)
                    if !opaque.bundle_type.is_known() || opaque.bundle_variant.is_known() =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a KnownTypeUnknownVariant bundle must have a recognized type \
                         and an unrecognized variant",
                    ));
                }
                V7BundleBytes::Unknown(opaque) if opaque.bundle_type.is_known() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "an Unknown bundle must have an unrecognized type",
                    ));
                }
                _ => {}
            }
        }

        let mut variants: BTreeMap<BundleType, BundleVariant> = BTreeMap::new();
        for entry in &self.value_pool_deltas {
            match variants.get(&entry.bundle_type()) {
                Some(&existing) if existing != entry.bundle_variant() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a bundle type appears with more than one bundleVariant",
                    ));
                }
                _ => {
                    variants.insert(entry.bundle_type(), entry.bundle_variant());
                }
            }
        }
        for bundle in &self.bundles {
            let bundle_type = bundle.bundle_type();
            let bundle_variant = bundle.bundle_variant();
            match variants.get(&bundle_type) {
                Some(&existing) if existing != bundle_variant => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a bundle type appears with more than one bundleVariant",
                    ));
                }
                _ => {
                    variants.insert(bundle_type, bundle_variant);
                }
            }
        }

        Ok(())
    }

    /// Checks that every bundle's encoded effecting and authorizing payload
    /// fits within [`MAX_BLOCK_BYTES`].
    ///
    /// The wire reader bounds each `vBundleData` payload by the maximum block
    /// size, so a body whose recognized bundle re-serializes to a larger
    /// payload could be written but not read back.
    fn validate_payload_sizes(&self) -> io::Result<()> {
        for bundle in &self.bundles {
            let mut effects = Vec::new();
            bundle.write_effects(&mut effects)?;
            if effects.len() > MAX_BLOCK_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bundle effecting data exceeds the maximum block size",
                ));
            }
            if bundle.has_auth() {
                let mut auth = Vec::new();
                bundle.write_auth(&mut auth)?;
                if auth.len() > MAX_BLOCK_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "bundle authorizing data exceeds the maximum block size",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Builds a body from the raw maps read from the wire.
    fn from_maps(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        effect_bundles: BTreeMap<BundleType, (BundleVariant, Vec<u8>)>,
        auth_bundles: BTreeMap<BundleType, (BundleVariant, Vec<u8>)>,
    ) -> io::Result<Self> {
        // Cross-map variant consistency: every entry for a bundle type across
        // all three maps must encode the same variant.
        let mut variants: BTreeMap<BundleType, BundleVariant> = BTreeMap::new();
        for entry in &value_pool_deltas {
            match variants.get(&entry.bundle_type()) {
                Some(&existing) if existing != entry.bundle_variant() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v7 mValuePoolDeltas has multiple bundleVariants for the same bundleType",
                    ));
                }
                _ => {
                    variants.insert(entry.bundle_type(), entry.bundle_variant());
                }
            }
        }
        for (&bundle_type, &(bundle_variant, _)) in &effect_bundles {
            match variants.get(&bundle_type) {
                Some(&existing) if existing != bundle_variant => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v7 mEffectBundles has multiple bundleVariants for the same bundleType",
                    ));
                }
                _ => {
                    variants.insert(bundle_type, bundle_variant);
                }
            }
        }
        for (&bundle_type, &(bundle_variant, _)) in &auth_bundles {
            match variants.get(&bundle_type) {
                Some(&existing) if existing != bundle_variant => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v7 mAuthBundles has multiple bundleVariants for the same bundleType",
                    ));
                }
                _ => {
                    variants.insert(bundle_type, bundle_variant);
                }
            }
        }

        // Auth-implies-effect: an authorizing entry must have a corresponding
        // effecting entry with the same variant.
        for (&bundle_type, &(auth_variant, _)) in &auth_bundles {
            match effect_bundles.get(&bundle_type) {
                Some(&(effect_variant, _)) if effect_variant == auth_variant => {}
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v7 mAuthBundles entry has a bundleVariant that does not match \
                         the corresponding mEffectBundles entry",
                    ));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v7 mAuthBundles entry has no matching mEffectBundles entry",
                    ));
                }
            }
        }

        let mut auth_by_type = auth_bundles;
        let mut bundles = Vec::new();
        for (bundle_type, (bundle_variant, effects)) in effect_bundles {
            let auth = auth_by_type.remove(&bundle_type).map(|(_, data)| data);
            bundles.push(parse_bundle(
                bundle_type,
                bundle_variant,
                &effects,
                auth.as_deref(),
            )?);
        }

        Self::from_parts_read(value_pool_deltas, bundles)
    }
}

/// Parses one effect/auth pair into a [`V7BundleBytes`].
fn parse_bundle(
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    effects: &[u8],
    auth: Option<&[u8]>,
) -> io::Result<V7BundleBytes> {
    let opaque = || {
        Ok(V7BundleBytes::KnownOpaque(OpaqueBundleBytes::from_parts(
            bundle_type,
            bundle_variant,
            effects.to_vec(),
            auth.map(|data| data.to_vec()),
        )?))
    };

    match (bundle_type, bundle_variant) {
        (BundleType::TRANSPARENT, BundleVariant::DEFAULT) => Ok(V7BundleBytes::Transparent(
            TransparentBundleBytes::read(effects, auth)?,
        )),
        (BundleType::COINBASE, BundleVariant::DEFAULT) => {
            // The registry prohibits the coinbase authorizing column, but that
            // is a consensus rule rather than a structural one. Parse the
            // effecting data regardless, and retain any authorizing payload so
            // that it round-trips and validation can reject it.
            let mut reader = effects;
            let bundle = CoinbaseBundleBytes::read(&mut reader)?;
            if !reader.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trailing bytes in v7 coinbase effecting data",
                ));
            }
            match auth {
                Some(auth) => Ok(V7BundleBytes::CoinbaseWithAuth(bundle, auth.to_vec())),
                None => Ok(V7BundleBytes::Coinbase(bundle)),
            }
        }
        (BundleType::SAPLING, BundleVariant::DEFAULT) => Ok(V7BundleBytes::Sapling(
            V7SaplingBundleBytes::read(effects, auth)?,
        )),
        (BundleType::ORCHARD, BundleVariant::DEFAULT) => Ok(V7BundleBytes::Orchard(
            V7OrchardBundleBytes::read(effects, auth)?,
        )),
        (BundleType::IRONWOOD, BundleVariant::DEFAULT) => Ok(V7BundleBytes::Ironwood(
            V7OrchardBundleBytes::read(effects, auth)?,
        )),
        (BundleType::FEE | BundleType::ZIP233_NSM, BundleVariant::DEFAULT) => {
            // The registry marks these bundle types as value-only. That is a
            // registry rule, not a structural one, so the byte layer retains
            // any effect/auth payload opaquely.
            opaque()
        }
        (bundle_type, bundle_variant) if bundle_type.is_known() && bundle_variant.is_known() => {
            opaque()
        }
        (bundle_type, _) if bundle_type.is_known() => Ok(V7BundleBytes::KnownTypeUnknownVariant(
            OpaqueBundleBytes::from_parts(
                bundle_type,
                bundle_variant,
                effects.to_vec(),
                auth.map(|data| data.to_vec()),
            )?,
        )),
        _ => Ok(V7BundleBytes::Unknown(OpaqueBundleBytes::from_parts(
            bundle_type,
            bundle_variant,
            effects.to_vec(),
            auth.map(|data| data.to_vec()),
        )?)),
    }
}

/// Checks that a raw wire key can be `compactSize`-encoded.
fn check_raw_key(bundle_type: BundleType, bundle_variant: BundleVariant) -> io::Result<()> {
    if bundle_type.to_u64() > u64::from(MAX_COMPACT_SIZE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundleType exceeds the maximum compactSize value",
        ));
    }
    if bundle_variant.to_u64() > u64::from(MAX_COMPACT_SIZE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundleVariant exceeds the maximum compactSize value",
        ));
    }
    Ok(())
}
