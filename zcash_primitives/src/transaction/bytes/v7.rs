//! Byte-level representation of the version 7 (ZIP 248) transaction body.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{CompactSize, MAX_COMPACT_SIZE};
use zcash_protocol::{constants::MAX_BLOCK_BYTES, value::ZatBalance};

use super::orchard::expected_proof_size;
use super::{
    CoinbaseBundleBytes, TransparentAuthBytes, TransparentEffectsBytes, V7OrchardAuthBytes,
    V7OrchardBundleBytes, V7SaplingAuthBytes, V7SaplingBundleBytes,
};
use crate::transaction::zip248::{self, BundleId, BundleType, BundleVariant};

/// The size in bytes of a value pool delta.
const VALUE_SIZE: usize = 8;

/// A single value pool delta entry in its wire representation.
///
/// The value is retained as the raw signed 64-bit integer from the wire. The
/// byte layer enforces only the nonzero rule; narrowing to [`ZatBalance`]
/// happens when the entry is converted to its typed representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValuePoolDeltaBytes {
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    value: i64,
}

impl ValuePoolDeltaBytes {
    /// Constructs a value pool delta from its wire fields.
    pub fn from_parts(
        bundle_type: BundleType,
        bundle_variant: BundleVariant,
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

    /// Returns the signed value pool delta as the raw wire integer.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Returns `true` if this entry belongs to a value-only bundle type.
    pub fn is_value_only(&self) -> bool {
        matches!(self.bundle_type, BundleType::FEE | BundleType::ZIP233_NSM)
    }

    /// Reads a value pool delta entry.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let bundle_type = BundleType::from_u64(CompactSize::read(&mut reader)?);
        let bundle_variant = BundleVariant::from_u64(CompactSize::read(&mut reader)?);
        let mut value = [0u8; VALUE_SIZE];
        reader.read_exact(&mut value)?;
        let value = i64::from_le_bytes(value);
        Self::from_parts(bundle_type, bundle_variant, value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "value pool delta is zero"))
    }

    /// Writes a value pool delta entry.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type.to_u64() as usize)?;
        CompactSize::write(&mut writer, self.bundle_variant.to_u64() as usize)?;
        writer.write_all(&self.value.to_le_bytes())
    }
}

/// Reads the `mValuePoolDeltas` map.
///
/// Entries are returned in wire order and must be strictly increasing by
/// `bundleType`. The nonzero-value rule is enforced by
/// [`ValuePoolDeltaBytes::read`].
fn read_value_pool_deltas<R: Read>(mut reader: R) -> io::Result<Vec<ValuePoolDeltaBytes>> {
    let count = CompactSize::read_t::<_, usize>(&mut reader)?;
    let mut entries = Vec::new();
    let mut last_type: Option<BundleType> = None;
    for _ in 0..count {
        let entry = ValuePoolDeltaBytes::read(&mut reader)?;
        let bundle_type = entry.bundle_type();
        if last_type.is_some_and(|previous| bundle_type <= previous) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v7 mValuePoolDeltas is not in strictly increasing bundleType order",
            ));
        }
        last_type = Some(bundle_type);
        entries.push(entry);
    }
    Ok(entries)
}

/// Reads the TLV framing of one bundle data map entry.
pub(crate) fn read_bundle_data_framing<R: Read>(mut reader: R) -> io::Result<(BundleId, Vec<u8>)> {
    let bundle_type = BundleType::from_u64(CompactSize::read(&mut reader)?);
    let bundle_variant = BundleVariant::from_u64(CompactSize::read(&mut reader)?);
    let data_len = CompactSize::read_t::<_, usize>(&mut reader)?;
    // The payload is allocated before it is read, so bound the claimed length
    // by something a transaction could actually contain: no bundle can exceed
    // the maximum block size.
    if data_len > MAX_BLOCK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "v7 bundle data length exceeds the maximum block size",
        ));
    }
    let mut data = alloc::vec![0u8; data_len];
    reader.read_exact(&mut data)?;
    Ok((BundleId::new(bundle_type, bundle_variant), data))
}

/// Writes the TLV framing of one bundle data map entry.
#[cfg(test)]
pub(crate) fn write_bundle_data_framing<W: Write>(
    mut writer: W,
    id: BundleId,
    data: &[u8],
) -> io::Result<()> {
    write_bundle_data_header(&mut writer, id, data.len())?;
    writer.write_all(data)
}

/// Reads one of the v7 bundle data maps (`mEffectBundles`, `mAuthBundles`).
///
/// Each entry is a TLV of `(bundleType, bundleVariant, compactSize-length,
/// data)`, and entries appear in strictly increasing `bundleType` order.
fn read_bundle_data_map<R: Read>(
    mut reader: R,
    map_name: &str,
) -> io::Result<BTreeMap<BundleType, (BundleVariant, Vec<u8>)>> {
    let count = CompactSize::read_t::<_, usize>(&mut reader)?;
    let mut data_by_type: BTreeMap<BundleType, (BundleVariant, Vec<u8>)> = BTreeMap::new();
    let mut last_type: Option<BundleType> = None;
    for _ in 0..count {
        let (id, data) = read_bundle_data_framing(&mut reader)?;
        let bundle_type = id.bundle_type();
        let bundle_variant = id.bundle_variant();
        if let Some(previous) = last_type
            && bundle_type <= previous
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                alloc::format!("v7 {map_name} is not in strictly increasing bundleType order"),
            ));
        }
        last_type = Some(bundle_type);
        data_by_type.insert(bundle_type, (bundle_variant, data));
    }
    Ok(data_by_type)
}

/// Writes one of the v7 bundle data maps, in canonical `bundleType` order.
///
/// Returns an error before writing anything if any payload exceeds
/// [`MAX_BLOCK_BYTES`], which the wire reader would reject.
#[cfg(test)]
pub(crate) fn write_bundle_data_map<W: Write>(
    mut writer: W,
    mut bundles: Vec<(BundleId, Vec<u8>)>,
) -> io::Result<()> {
    for (_, data) in &bundles {
        check_payload_size(data)?;
    }
    bundles.sort_by_key(|(id, _)| id.bundle_type());
    CompactSize::write(&mut writer, bundles.len())?;
    for (id, data) in &bundles {
        write_bundle_data_framing(&mut writer, *id, data)?;
    }
    Ok(())
}

/// An uninterpreted effecting-data map entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueEffectBundleBytes {
    id: BundleId,
    payload: Vec<u8>,
}

/// Returns `true` if `(bundle_type, bundle_variant)` has an effecting-data
/// codec that [`parse_effect`] recognizes.
///
/// An opaque effect for such an identifier would be read back as its typed
/// form, so its payload must be the codec's canonical encoding. Known types
/// with unknown variants, unknown types, and value-only or authorizing-only
/// registered entries have no effecting codec and remain opaque.
pub(crate) fn has_recognized_effect_codec(
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
) -> bool {
    bundle_variant == BundleVariant::DEFAULT
        && matches!(
            bundle_type,
            BundleType::TRANSPARENT
                | BundleType::COINBASE
                | BundleType::SAPLING
                | BundleType::ORCHARD
                | BundleType::IRONWOOD
        )
}

impl OpaqueEffectBundleBytes {
    /// Constructs an opaque effecting-data entry.
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the identifier has a
    /// recognized effecting codec, in which case the payload must use it, or if
    /// the payload exceeds the maximum block size.
    pub fn from_parts(id: BundleId, payload: Vec<u8>) -> io::Result<Self> {
        check_raw_key(id.bundle_type(), id.bundle_variant())?;
        if has_recognized_effect_codec(id.bundle_type(), id.bundle_variant()) {
            return Err(invalid_input(
                "bundle has a recognized effecting codec; construct its interpreted form",
            ));
        }
        check_payload_size(&payload)?;
        Ok(Self { id, payload })
    }

    /// Returns the bundle identifier.
    pub fn id(&self) -> BundleId {
        self.id
    }

    /// Returns the raw effecting payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// An uninterpreted authorizing-data map entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueAuthBundleBytes {
    id: BundleId,
    payload: Vec<u8>,
}

impl OpaqueAuthBundleBytes {
    /// Constructs an opaque authorizing-data entry.
    pub fn from_parts(id: BundleId, payload: Vec<u8>) -> io::Result<Self> {
        check_raw_key(id.bundle_type(), id.bundle_variant())?;
        check_payload_size(&payload)?;
        Ok(Self { id, payload })
    }

    /// Returns the bundle identifier.
    pub fn id(&self) -> BundleId {
        self.id
    }

    /// Returns the raw authorizing payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A version 7 effecting-data map entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V7EffectBundleBytes {
    /// Transparent effecting data.
    Transparent(TransparentEffectsBytes),
    /// Coinbase effecting data.
    Coinbase(CoinbaseBundleBytes),
    /// Sapling effecting data.
    Sapling(V7SaplingBundleBytes),
    /// Orchard effecting data.
    Orchard(V7OrchardBundleBytes),
    /// Ironwood effecting data.
    Ironwood(V7OrchardBundleBytes),
    /// An entry whose payload is not interpreted in this map.
    Opaque(OpaqueEffectBundleBytes),
}

impl V7EffectBundleBytes {
    /// Returns the exact raw digest key of this entry.
    pub fn digest_key(&self) -> BundleId {
        match self {
            Self::Transparent(_) => BundleId::new(BundleType::TRANSPARENT, BundleVariant::DEFAULT),
            Self::Coinbase(_) => BundleId::new(BundleType::COINBASE, BundleVariant::DEFAULT),
            Self::Sapling(_) => BundleId::new(BundleType::SAPLING, BundleVariant::DEFAULT),
            Self::Orchard(_) => BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT),
            Self::Ironwood(_) => BundleId::new(BundleType::IRONWOOD, BundleVariant::DEFAULT),
            Self::Opaque(bundle) => bundle.id,
        }
    }

    /// Returns this entry's bundle type.
    pub fn bundle_type(&self) -> BundleType {
        self.digest_key().bundle_type()
    }

    /// Returns this entry's bundle variant.
    pub fn bundle_variant(&self) -> BundleVariant {
        self.digest_key().bundle_variant()
    }

    /// Returns the opaque payload, if this entry was not interpreted.
    pub fn as_opaque(&self) -> Option<&OpaqueEffectBundleBytes> {
        match self {
            Self::Opaque(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Writes this entry's effecting payload.
    pub fn write_effects<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match self {
            Self::Transparent(bundle) => bundle.write(&mut writer),
            Self::Coinbase(bundle) => bundle.write(&mut writer),
            Self::Sapling(bundle) => bundle.write_effects(&mut writer),
            Self::Orchard(bundle) | Self::Ironwood(bundle) => bundle.write_effects(&mut writer),
            Self::Opaque(bundle) => writer.write_all(&bundle.payload),
        }
    }

    /// Computes this entry's effecting-data digest.
    pub fn effects_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<blake2b_simd::Hash, zip248::V7DigestError> {
        use super::super::txid;

        match self {
            Self::Transparent(bundle) => Ok(txid::hash_v7_transparent_effects_bytes(bundle)),
            Self::Coinbase(bundle) => Ok(txid::hash_v7_coinbase_effects_bytes(bundle)),
            Self::Sapling(bundle) => Ok(txid::hash_v7_sapling_effects_bytes(bundle)),
            Self::Orchard(bundle) => Ok(txid::hash_v7_orchard_effects_bytes(bundle)),
            Self::Ironwood(bundle) => Ok(txid::hash_v7_ironwood_effects_bytes(bundle)),
            Self::Opaque(bundle) => provider
                .effects_digest(bundle.id)
                .ok_or(zip248::V7DigestError::MissingEffectsDigest { key: bundle.id }),
        }
    }
}

/// A version 7 authorizing-data map entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V7AuthBundleBytes {
    /// Transparent authorizing data.
    Transparent(TransparentAuthBytes),
    /// Sapling authorizing data.
    Sapling(V7SaplingAuthBytes),
    /// Orchard authorizing data.
    Orchard(V7OrchardAuthBytes),
    /// Ironwood authorizing data.
    Ironwood(V7OrchardAuthBytes),
    /// An entry whose payload is not interpreted in this map.
    Opaque(OpaqueAuthBundleBytes),
}

impl V7AuthBundleBytes {
    /// Checks that authorizing fields correspond to the effecting entry.
    pub(in crate::transaction) fn validate_for_effect(
        &self,
        effect: &V7EffectBundleBytes,
    ) -> io::Result<()> {
        validate_auth_correspondence(effect, self)
    }

    /// Returns the exact raw digest key of this entry.
    pub fn digest_key(&self) -> BundleId {
        match self {
            Self::Transparent(_) => BundleId::new(BundleType::TRANSPARENT, BundleVariant::DEFAULT),
            Self::Sapling(_) => BundleId::new(BundleType::SAPLING, BundleVariant::DEFAULT),
            Self::Orchard(_) => BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT),
            Self::Ironwood(_) => BundleId::new(BundleType::IRONWOOD, BundleVariant::DEFAULT),
            Self::Opaque(bundle) => bundle.id,
        }
    }

    /// Returns this entry's bundle type.
    pub fn bundle_type(&self) -> BundleType {
        self.digest_key().bundle_type()
    }

    /// Returns this entry's bundle variant.
    pub fn bundle_variant(&self) -> BundleVariant {
        self.digest_key().bundle_variant()
    }

    /// Returns the opaque payload, if this entry was not interpreted.
    pub fn as_opaque(&self) -> Option<&OpaqueAuthBundleBytes> {
        match self {
            Self::Opaque(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Writes this entry's authorizing payload.
    pub fn write_auth<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match self {
            Self::Transparent(bundle) => bundle.write(&mut writer),
            Self::Sapling(bundle) => bundle.write_auth(&mut writer),
            Self::Orchard(bundle) | Self::Ironwood(bundle) => bundle.write_auth(&mut writer),
            Self::Opaque(bundle) => writer.write_all(&bundle.payload),
        }
    }

    /// Computes this entry's authorizing-data digest.
    pub fn auth_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<blake2b_simd::Hash, zip248::V7DigestError> {
        use super::super::txid;

        match self {
            Self::Transparent(bundle) => Ok(txid::hash_v7_transparent_auth_bytes(bundle)),
            Self::Sapling(bundle) => Ok(txid::hash_v7_sapling_auth_bytes(bundle)),
            Self::Orchard(bundle) => Ok(txid::hash_v7_orchard_auth_bytes(bundle)),
            Self::Ironwood(bundle) => Ok(txid::hash_v7_ironwood_auth_bytes(bundle)),
            Self::Opaque(bundle) => provider
                .auth_digest(bundle.id)
                .ok_or(zip248::V7DigestError::MissingAuthDigest { key: bundle.id }),
        }
    }
}

/// The body of a version 7 transaction.
///
/// The three wire maps remain separate in memory. Known entries use their
/// protocol-specific byte representations; all other payloads remain opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7TransactionBodyBytes {
    value_pool_deltas: Vec<ValuePoolDeltaBytes>,
    effect_bundles: Vec<V7EffectBundleBytes>,
    auth_bundles: Vec<V7AuthBundleBytes>,
}

impl V7TransactionBodyBytes {
    /// Constructs a version 7 body from its three maps.
    ///
    /// Returns an error for noncanonical ordering, inconsistent identifiers,
    /// invalid recognized payloads, or authorizing data without corresponding
    /// effects. Empty recognized effects and transparent authorizing data with
    /// no inputs must be omitted.
    pub fn from_parts(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        effect_bundles: Vec<V7EffectBundleBytes>,
        auth_bundles: Vec<V7AuthBundleBytes>,
    ) -> io::Result<Self> {
        let body = Self {
            value_pool_deltas,
            effect_bundles,
            auth_bundles,
        };
        body.validate()?;
        body.validate_payload_sizes()?;
        Ok(body)
    }

    /// Constructs a body whose payload sizes were bounded by the wire reader.
    fn from_parts_read(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        effect_bundles: Vec<V7EffectBundleBytes>,
        auth_bundles: Vec<V7AuthBundleBytes>,
    ) -> io::Result<Self> {
        let body = Self {
            value_pool_deltas,
            effect_bundles,
            auth_bundles,
        };
        body.validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(body)
    }

    /// Returns the value pool delta entries in canonical order.
    pub fn value_pool_deltas(&self) -> &[ValuePoolDeltaBytes] {
        &self.value_pool_deltas
    }

    /// Interprets the value pool delta entries as a typed map.
    pub fn to_value_pool_deltas(&self) -> io::Result<zip248::ValuePoolDeltas> {
        zip248::ValuePoolDeltas::from_wire_entries(self.value_pool_deltas.iter().map(|entry| {
            let value = ZatBalance::from_i64(entry.value()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "value pool delta out of valid monetary range",
                )
            })?;
            Ok((entry.bundle_type(), entry.bundle_variant(), value))
        }))
    }

    /// Returns the effecting-data entries in canonical order.
    pub fn effect_bundles(&self) -> &[V7EffectBundleBytes] {
        &self.effect_bundles
    }

    /// Returns the authorizing-data entries in canonical order.
    pub fn auth_bundles(&self) -> &[V7AuthBundleBytes] {
        &self.auth_bundles
    }

    /// Returns an effecting entry by bundle type.
    ///
    /// The effecting entries are kept in canonical `bundleType` order, so this
    /// is a binary search.
    pub fn effect_bundle(&self, bundle_type: BundleType) -> Option<&V7EffectBundleBytes> {
        self.effect_bundles
            .binary_search_by_key(&bundle_type, V7EffectBundleBytes::bundle_type)
            .ok()
            .map(|index| &self.effect_bundles[index])
    }

    /// Returns an authorizing entry by bundle type.
    ///
    /// The authorizing entries are kept in canonical `bundleType` order, so
    /// this is a binary search.
    pub fn auth_bundle(&self, bundle_type: BundleType) -> Option<&V7AuthBundleBytes> {
        self.auth_bundles
            .binary_search_by_key(&bundle_type, V7AuthBundleBytes::bundle_type)
            .ok()
            .map(|index| &self.auth_bundles[index])
    }

    /// Removes an effecting entry, preserving the order of the remaining entries.
    pub(crate) fn take_effect_bundle(
        &mut self,
        bundle_type: BundleType,
    ) -> Option<V7EffectBundleBytes> {
        self.effect_bundles
            .binary_search_by_key(&bundle_type, V7EffectBundleBytes::bundle_type)
            .ok()
            .map(|index| self.effect_bundles.remove(index))
    }

    /// Removes an authorizing entry, preserving the order of the remaining entries.
    pub(crate) fn take_auth_bundle(
        &mut self,
        bundle_type: BundleType,
    ) -> Option<V7AuthBundleBytes> {
        self.auth_bundles
            .binary_search_by_key(&bundle_type, V7AuthBundleBytes::bundle_type)
            .ok()
            .map(|index| self.auth_bundles.remove(index))
    }

    /// Returns transparent effecting data, if present.
    pub fn transparent(&self) -> Option<&TransparentEffectsBytes> {
        match self.effect_bundle(BundleType::TRANSPARENT) {
            Some(V7EffectBundleBytes::Transparent(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns transparent authorizing data, if present.
    pub fn transparent_auth(&self) -> Option<&TransparentAuthBytes> {
        match self.auth_bundle(BundleType::TRANSPARENT) {
            Some(V7AuthBundleBytes::Transparent(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns coinbase effecting data, if present.
    pub fn coinbase(&self) -> Option<&CoinbaseBundleBytes> {
        match self.effect_bundle(BundleType::COINBASE) {
            Some(V7EffectBundleBytes::Coinbase(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns Sapling effecting data, if present.
    pub fn sapling(&self) -> Option<&V7SaplingBundleBytes> {
        match self.effect_bundle(BundleType::SAPLING) {
            Some(V7EffectBundleBytes::Sapling(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns Sapling authorizing data, if present.
    pub fn sapling_auth(&self) -> Option<&V7SaplingAuthBytes> {
        match self.auth_bundle(BundleType::SAPLING) {
            Some(V7AuthBundleBytes::Sapling(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns Orchard effecting data, if present.
    pub fn orchard(&self) -> Option<&V7OrchardBundleBytes> {
        match self.effect_bundle(BundleType::ORCHARD) {
            Some(V7EffectBundleBytes::Orchard(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns Orchard authorizing data, if present.
    pub fn orchard_auth(&self) -> Option<&V7OrchardAuthBytes> {
        match self.auth_bundle(BundleType::ORCHARD) {
            Some(V7AuthBundleBytes::Orchard(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns Ironwood effecting data, if present.
    pub fn ironwood(&self) -> Option<&V7OrchardBundleBytes> {
        match self.effect_bundle(BundleType::IRONWOOD) {
            Some(V7EffectBundleBytes::Ironwood(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns Ironwood authorizing data, if present.
    pub fn ironwood_auth(&self) -> Option<&V7OrchardAuthBytes> {
        match self.auth_bundle(BundleType::IRONWOOD) {
            Some(V7AuthBundleBytes::Ironwood(bundle)) => Some(bundle),
            _ => None,
        }
    }

    /// Returns the opaque effecting entries.
    pub fn opaque_effect_bundles(&self) -> impl Iterator<Item = &OpaqueEffectBundleBytes> {
        self.effect_bundles
            .iter()
            .filter_map(V7EffectBundleBytes::as_opaque)
    }

    /// Returns the opaque authorizing entries.
    pub fn opaque_auth_bundles(&self) -> impl Iterator<Item = &OpaqueAuthBundleBytes> {
        self.auth_bundles
            .iter()
            .filter_map(V7AuthBundleBytes::as_opaque)
    }

    /// Returns the raw value pool delta for the given bundle type.
    pub fn zec_value_pool_delta(&self, bundle_type: BundleType) -> Option<i64> {
        self.value_pool_deltas
            .iter()
            .find(|entry| entry.bundle_type() == bundle_type)
            .map(ValuePoolDeltaBytes::value)
    }

    /// Computes the digest of this body's value pool deltas.
    pub fn value_pool_deltas_digest(&self) -> blake2b_simd::Hash {
        super::super::txid::hash_v7_value_pool_deltas_bytes(&self.value_pool_deltas)
    }

    /// Computes the digest of this body's effecting map.
    pub fn effects_bundles_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<blake2b_simd::Hash, zip248::V7DigestError> {
        let mut entries = Vec::with_capacity(self.effect_bundles.len());
        for bundle in &self.effect_bundles {
            entries.push((
                bundle.digest_key().wire_key(),
                bundle.effects_digest(provider)?,
            ));
        }
        Ok(super::super::txid::hash_v7_effects_bundles(
            entries.iter().map(|(key, digest)| (*key, digest)),
        ))
    }

    /// Computes the digest of this body's authorizing map.
    pub fn auth_bundles_digest(
        &self,
        provider: &impl zip248::BundleDigestProvider,
    ) -> Result<blake2b_simd::Hash, zip248::V7DigestError> {
        let mut entries = Vec::with_capacity(self.auth_bundles.len());
        for bundle in &self.auth_bundles {
            entries.push((
                bundle.digest_key().wire_key(),
                bundle.auth_digest(provider)?,
            ));
        }
        Ok(super::super::txid::hash_v7_auth_bundles(
            entries.iter().map(|(key, digest)| (*key, digest)),
        ))
    }

    /// Reads a version 7 body from its wire encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let value_pool_deltas = read_value_pool_deltas(&mut reader)?;
        let effect_bundles = read_bundle_data_map(&mut reader, "mEffectBundles")?;
        let auth_bundles = read_bundle_data_map(&mut reader, "mAuthBundles")?;
        Self::from_maps(value_pool_deltas, effect_bundles, auth_bundles)
    }

    /// Writes a version 7 body in its wire encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.validate()?;

        CompactSize::write(&mut writer, self.value_pool_deltas.len())?;
        for entry in &self.value_pool_deltas {
            entry.write(&mut writer)?;
        }

        let effect_lengths = self
            .effect_bundles
            .iter()
            .map(|bundle| payload_len(|writer| bundle.write_effects(writer)))
            .collect::<io::Result<Vec<_>>>()?;
        CompactSize::write(&mut writer, self.effect_bundles.len())?;
        for (bundle, len) in self.effect_bundles.iter().zip(effect_lengths) {
            write_bundle_data_header(&mut writer, bundle.digest_key(), len)?;
            bundle.write_effects(&mut writer)?;
        }

        let auth_lengths = self
            .auth_bundles
            .iter()
            .map(|bundle| payload_len(|writer| bundle.write_auth(writer)))
            .collect::<io::Result<Vec<_>>>()?;
        CompactSize::write(&mut writer, self.auth_bundles.len())?;
        for (bundle, len) in self.auth_bundles.iter().zip(auth_lengths) {
            write_bundle_data_header(&mut writer, bundle.digest_key(), len)?;
            bundle.write_auth(&mut writer)?;
        }
        Ok(())
    }

    /// Checks canonical ordering and all cross-map structural invariants.
    fn validate(&self) -> io::Result<()> {
        let mut last_type: Option<BundleType> = None;
        for entry in &self.value_pool_deltas {
            let bundle_type = entry.bundle_type();
            if last_type.is_some_and(|previous| bundle_type <= previous) {
                return Err(invalid_input(
                    "value pool deltas are not in canonical order",
                ));
            }
            last_type = Some(bundle_type);
        }

        validate_order(
            self.effect_bundles
                .iter()
                .map(V7EffectBundleBytes::bundle_type),
        )?;
        validate_order(self.auth_bundles.iter().map(V7AuthBundleBytes::bundle_type))?;

        let mut variants = BTreeMap::new();
        for entry in &self.value_pool_deltas {
            insert_variant(&mut variants, entry.bundle_type(), entry.bundle_variant())?;
        }
        for bundle in &self.effect_bundles {
            check_raw_key(bundle.bundle_type(), bundle.bundle_variant())?;
            match bundle {
                V7EffectBundleBytes::Transparent(effects) => effects.validate()?,
                V7EffectBundleBytes::Sapling(effects) => effects.validate()?,
                V7EffectBundleBytes::Orchard(effects) | V7EffectBundleBytes::Ironwood(effects) => {
                    effects.validate()?
                }
                V7EffectBundleBytes::Coinbase(_) | V7EffectBundleBytes::Opaque(_) => {}
            }
            insert_variant(&mut variants, bundle.bundle_type(), bundle.bundle_variant())?;
        }
        for bundle in &self.auth_bundles {
            check_raw_key(bundle.bundle_type(), bundle.bundle_variant())?;
            insert_variant(&mut variants, bundle.bundle_type(), bundle.bundle_variant())?;
            let Some(effect) = self.effect_bundle(bundle.bundle_type()) else {
                return Err(invalid_input(
                    "an authorizing entry has no corresponding effecting entry",
                ));
            };
            if effect.bundle_variant() != bundle.bundle_variant() {
                return Err(invalid_input(
                    "effecting and authorizing bundle variants differ",
                ));
            }
            validate_auth_correspondence(effect, bundle)?;
        }

        Ok(())
    }

    /// Checks each encoded payload's size bound.
    fn validate_payload_sizes(&self) -> io::Result<()> {
        for bundle in &self.effect_bundles {
            payload_len(|writer| bundle.write_effects(writer))?;
        }
        for bundle in &self.auth_bundles {
            payload_len(|writer| bundle.write_auth(writer))?;
        }
        Ok(())
    }

    /// Builds a body from the raw maps read from the wire.
    fn from_maps(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        raw_effects: BTreeMap<BundleType, (BundleVariant, Vec<u8>)>,
        raw_auth: BTreeMap<BundleType, (BundleVariant, Vec<u8>)>,
    ) -> io::Result<Self> {
        let mut variants = BTreeMap::new();
        for entry in &value_pool_deltas {
            insert_variant(&mut variants, entry.bundle_type(), entry.bundle_variant())?;
        }
        for (&bundle_type, &(bundle_variant, _)) in &raw_effects {
            insert_variant(&mut variants, bundle_type, bundle_variant)?;
        }
        for (&bundle_type, &(bundle_variant, _)) in &raw_auth {
            insert_variant(&mut variants, bundle_type, bundle_variant)?;
            match raw_effects.get(&bundle_type) {
                Some(&(effect_variant, _)) if effect_variant == bundle_variant => {}
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "authorizing and effecting variants differ",
                    ));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "authorizing entry has no corresponding effecting entry",
                    ));
                }
            }
        }

        let mut effect_bundles = Vec::with_capacity(raw_effects.len());
        for (bundle_type, (bundle_variant, effects)) in raw_effects {
            effect_bundles.push(parse_effect(bundle_type, bundle_variant, &effects)?);
        }

        // Both maps are ordered by bundle type, and every authorizing entry has
        // a corresponding effecting entry (checked above), so walking the
        // effecting entries in step with the authorizing ones pairs them in a
        // single pass.
        let mut auth_bundles = Vec::with_capacity(raw_auth.len());
        let mut effects_iter = effect_bundles.iter();
        for (bundle_type, (bundle_variant, auth)) in raw_auth {
            let effect = effects_iter
                .by_ref()
                .find(|bundle| bundle.bundle_type() == bundle_type)
                .expect("auth-implies-effect was checked above");
            auth_bundles.push(parse_auth(bundle_type, bundle_variant, &auth, effect)?);
        }

        Self::from_parts_read(value_pool_deltas, effect_bundles, auth_bundles)
    }
}

/// Parses one effecting-data map entry.
fn parse_effect(
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    payload: &[u8],
) -> io::Result<V7EffectBundleBytes> {
    let opaque = || {
        Ok(V7EffectBundleBytes::Opaque(
            OpaqueEffectBundleBytes::from_parts(
                BundleId::new(bundle_type, bundle_variant),
                payload.to_vec(),
            )?,
        ))
    };

    if !has_recognized_effect_codec(bundle_type, bundle_variant) {
        return opaque();
    }

    match (bundle_type, bundle_variant) {
        (BundleType::TRANSPARENT, BundleVariant::DEFAULT) => {
            let mut reader = payload;
            let effects = TransparentEffectsBytes::read(&mut reader)?;
            require_empty(reader, "transparent effecting data")?;
            Ok(V7EffectBundleBytes::Transparent(effects))
        }
        (BundleType::COINBASE, BundleVariant::DEFAULT) => {
            let mut reader = payload;
            let bundle = CoinbaseBundleBytes::read(&mut reader)?;
            require_empty(reader, "coinbase effecting data")?;
            Ok(V7EffectBundleBytes::Coinbase(bundle))
        }
        (BundleType::SAPLING, BundleVariant::DEFAULT) => Ok(V7EffectBundleBytes::Sapling(
            V7SaplingBundleBytes::read(payload)?,
        )),
        (BundleType::ORCHARD, BundleVariant::DEFAULT) => Ok(V7EffectBundleBytes::Orchard(
            V7OrchardBundleBytes::read(payload)?,
        )),
        (BundleType::IRONWOOD, BundleVariant::DEFAULT) => Ok(V7EffectBundleBytes::Ironwood(
            V7OrchardBundleBytes::read(payload)?,
        )),
        _ => opaque(),
    }
}

/// Parses one authorizing-data map entry using its corresponding effects.
fn parse_auth(
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    payload: &[u8],
    effect: &V7EffectBundleBytes,
) -> io::Result<V7AuthBundleBytes> {
    let opaque = || {
        Ok(V7AuthBundleBytes::Opaque(
            OpaqueAuthBundleBytes::from_parts(
                BundleId::new(bundle_type, bundle_variant),
                payload.to_vec(),
            )?,
        ))
    };

    match (bundle_type, bundle_variant, effect) {
        (
            BundleType::TRANSPARENT,
            BundleVariant::DEFAULT,
            V7EffectBundleBytes::Transparent(effects),
        ) => {
            let mut reader = payload;
            let auth = TransparentAuthBytes::read(&mut reader, effects.inputs().len())?;
            require_empty(reader, "transparent authorizing data")?;
            Ok(V7AuthBundleBytes::Transparent(auth))
        }
        (BundleType::SAPLING, BundleVariant::DEFAULT, V7EffectBundleBytes::Sapling(effects)) => {
            Ok(V7AuthBundleBytes::Sapling(V7SaplingAuthBytes::read(
                payload,
                effects.spends().len(),
                effects.outputs().len(),
            )?))
        }
        (BundleType::ORCHARD, BundleVariant::DEFAULT, V7EffectBundleBytes::Orchard(effects)) => Ok(
            V7AuthBundleBytes::Orchard(V7OrchardAuthBytes::read(payload, effects.actions().len())?),
        ),
        (BundleType::IRONWOOD, BundleVariant::DEFAULT, V7EffectBundleBytes::Ironwood(effects)) => {
            Ok(V7AuthBundleBytes::Ironwood(V7OrchardAuthBytes::read(
                payload,
                effects.actions().len(),
            )?))
        }
        _ => opaque(),
    }
}

/// Checks the per-element correspondence between an effect/auth pair.
///
/// Recognized entries must pair with their own kind: a recognized effecting
/// entry with an opaque authorizing payload for the same identifier would
/// serialize bytes that the reader interprets, so it is rejected rather than
/// left to the reader. The deliberate exceptions are the coinbase bundle,
/// which has no authorizing data type, and entries opaque on both sides.
fn validate_auth_correspondence(
    effect: &V7EffectBundleBytes,
    auth: &V7AuthBundleBytes,
) -> io::Result<()> {
    match (effect, auth) {
        (V7EffectBundleBytes::Transparent(effects), V7AuthBundleBytes::Transparent(auth)) => {
            auth.validate_for(effects)?;
        }
        (V7EffectBundleBytes::Sapling(effects), V7AuthBundleBytes::Sapling(auth)) => {
            if effects.spends().is_empty() != auth.anchor().is_none()
                || auth.spend_proofs().len() != effects.spends().len()
                || auth.spend_auth_sigs().len() != effects.spends().len()
                || auth.output_proofs().len() != effects.outputs().len()
                || auth.binding_sig().is_none()
            {
                return Err(invalid_input(
                    "Sapling authorizing fields do not correspond to effecting fields",
                ));
            }
        }
        (V7EffectBundleBytes::Orchard(effects), V7AuthBundleBytes::Orchard(auth))
        | (V7EffectBundleBytes::Ironwood(effects), V7AuthBundleBytes::Ironwood(auth)) => {
            if auth.anchor().is_none()
                || auth.binding_sig().is_none()
                || auth.spend_auth_sigs().len() != effects.actions().len()
                || auth.proof().len()
                    != expected_proof_size(effects.actions().len()).ok_or_else(|| {
                        invalid_input("Orchard proof size overflows the address space")
                    })?
            {
                return Err(invalid_input(
                    "Orchard authorizing fields do not correspond to effecting fields",
                ));
            }
        }
        (V7EffectBundleBytes::Coinbase(_), V7AuthBundleBytes::Opaque(_))
        | (V7EffectBundleBytes::Opaque(_), V7AuthBundleBytes::Opaque(_)) => {}
        _ => {
            return Err(invalid_input(
                "effecting and authorizing entries denote different bundle kinds",
            ));
        }
    }
    Ok(())
}

/// Checks that bundle types occur in strictly increasing order.
fn validate_order(types: impl Iterator<Item = BundleType>) -> io::Result<()> {
    let mut previous = None;
    for bundle_type in types {
        if previous.is_some_and(|previous| bundle_type <= previous) {
            return Err(invalid_input("bundles are not in canonical order"));
        }
        previous = Some(bundle_type);
    }
    Ok(())
}

/// Records a bundle variant, rejecting conflicts for one bundle type.
fn insert_variant(
    variants: &mut BTreeMap<BundleType, BundleVariant>,
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
) -> io::Result<()> {
    match variants.get(&bundle_type) {
        Some(&existing) if existing != bundle_variant => Err(invalid_input(
            "a bundle type appears with more than one variant",
        )),
        _ => {
            variants.insert(bundle_type, bundle_variant);
            Ok(())
        }
    }
}

/// Rejects bytes remaining after a recognized payload.
fn require_empty(reader: &[u8], field: &str) -> io::Result<()> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            alloc::format!("trailing bytes in v7 {field}"),
        ))
    }
}

/// Checks a raw wire key's CompactSize representability.
fn check_raw_key(bundle_type: BundleType, bundle_variant: BundleVariant) -> io::Result<()> {
    if bundle_type.to_u64() > u64::from(MAX_COMPACT_SIZE)
        || bundle_variant.to_u64() > u64::from(MAX_COMPACT_SIZE)
    {
        Err(invalid_input("bundle identifier exceeds CompactSize range"))
    } else {
        Ok(())
    }
}

/// Checks an individual bundle payload's wire size bound.
fn check_payload_size(payload: &[u8]) -> io::Result<()> {
    check_payload_len(payload.len())
}

/// Checks an individual bundle payload's wire size bound.
fn check_payload_len(len: usize) -> io::Result<()> {
    if len > MAX_BLOCK_BYTES {
        Err(invalid_input(
            "bundle payload exceeds the maximum block size",
        ))
    } else {
        Ok(())
    }
}

/// A writer that counts encoded bytes without retaining them.
#[derive(Default)]
struct PayloadCounter(usize);

impl Write for PayloadCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| invalid_input("bundle payload exceeds the maximum block size"))?;
        check_payload_len(len)?;
        self.0 = len;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Measures and bounds a payload using its canonical encoder.
fn payload_len(write: impl FnOnce(&mut PayloadCounter) -> io::Result<()>) -> io::Result<usize> {
    let mut counter = PayloadCounter::default();
    write(&mut counter)?;
    check_payload_len(counter.0)?;
    Ok(counter.0)
}

/// Writes a bundle entry's key and encoded payload length.
fn write_bundle_data_header<W: Write>(mut writer: W, id: BundleId, len: usize) -> io::Result<()> {
    check_raw_key(id.bundle_type(), id.bundle_variant())?;
    CompactSize::write(&mut writer, id.bundle_type().to_u64() as usize)?;
    CompactSize::write(&mut writer, id.bundle_variant().to_u64() as usize)?;
    CompactSize::write(&mut writer, len)
}

/// Constructs an invalid-input error for an in-memory structural violation.
fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
