//! ZIP 248: Extensible Transaction Format types.
//!
//! This module defines the core types for the ZIP 248 transaction format:
//! - [`BundleId`]: A `(bundleType, bundleVariant)` pair identifying a protocol bundle.
//! - [`TypedBundle`]: An enum over known typed bundles and opaque unknown bundles.
//! - [`BundleMap`]: An ordered map of bundles keyed by [`BundleId`].
//! - [`ValuePoolDeltas`]: The value pool delta map recording per-bundle value contributions.
//! - [`UnknownBundle`]: An opaque bundle with unparsed effect and auth data.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core2::io::{self, Read, Write};

use ::transparent::bundle::{self as transparent};
use orchard::bundle::{self as orchard};
use sapling::bundle::{self as sapling};
use zcash_encoding::CompactSize;
use zcash_protocol::value::{ZatBalance, Zatoshis};

use super::components::sprout;

#[cfg(zcash_unstable = "zfuture")]
use super::components::tze;

use super::Authorization;

// ---------------------------------------------------------------------------
// Bundle type constants (ZIP 248 registry for v6 transactions)
// ---------------------------------------------------------------------------

/// Transparent bundle type.
pub const BUNDLE_TYPE_TRANSPARENT: u64 = 0;
// 1 is reserved.
/// Sapling bundle type.
pub const BUNDLE_TYPE_SAPLING: u64 = 2;
/// Orchard bundle type.
pub const BUNDLE_TYPE_ORCHARD: u64 = 3;
/// Transaction fee bundle type (ZIP 2002). Value-only, no effect/auth data.
pub const BUNDLE_TYPE_FEE: u64 = 4;
/// ZIP 233 NSM field bundle type. Value-only, no effect/auth data.
pub const BUNDLE_TYPE_ZIP233_NSM: u64 = 5;

/// Default bundle variant for all currently-defined bundle types.
pub const BUNDLE_VARIANT_DEFAULT: u64 = 0;

/// Asset class byte for ZEC.
pub const ASSET_CLASS_ZEC: u8 = 0x00;
/// Asset class byte for non-ZEC assets.
pub const ASSET_CLASS_OTHER: u8 = 0x01;

// ---------------------------------------------------------------------------
// BundleId
// ---------------------------------------------------------------------------

/// A `(bundleType, bundleVariant)` pair identifying a protocol bundle.
///
/// Within the period that a given transaction format version is used on the
/// Zcash network, the semantics of the bundle associated with a given
/// `(bundleType, bundleVariant)` pair are fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BundleId {
    pub bundle_type: u64,
    pub bundle_variant: u64,
}

impl BundleId {
    pub const fn new(bundle_type: u64, bundle_variant: u64) -> Self {
        Self {
            bundle_type,
            bundle_variant,
        }
    }

    pub const TRANSPARENT: Self = Self::new(BUNDLE_TYPE_TRANSPARENT, BUNDLE_VARIANT_DEFAULT);
    pub const SAPLING: Self = Self::new(BUNDLE_TYPE_SAPLING, BUNDLE_VARIANT_DEFAULT);
    pub const ORCHARD: Self = Self::new(BUNDLE_TYPE_ORCHARD, BUNDLE_VARIANT_DEFAULT);
    pub const FEE: Self = Self::new(BUNDLE_TYPE_FEE, BUNDLE_VARIANT_DEFAULT);
    pub const ZIP233_NSM: Self = Self::new(BUNDLE_TYPE_ZIP233_NSM, BUNDLE_VARIANT_DEFAULT);
}

// ---------------------------------------------------------------------------
// UnknownBundle
// ---------------------------------------------------------------------------

/// An opaque bundle whose type is not recognized by this implementation.
///
/// The effect and auth data are stored as unparsed byte vectors so that
/// the transaction can still be serialized. To compute the v6 transaction
/// identifier (and the authorizing data commitment) over a transaction
/// containing an unknown bundle, the caller must also supply the
/// `bundle_effects_digest` (and, when `auth_data` is present, the
/// `bundle_auth_digest`) computed by whatever algorithm the defining ZIP
/// for the bundle type specifies. ZIP 248 §"Implications for Wallets"
/// expects these to be supplied externally; they cannot be derived from
/// the opaque bytes alone.
#[derive(Clone, Debug)]
pub struct UnknownBundle {
    pub effect_data: Vec<u8>,
    pub effect_digest: blake2b_simd::Hash,
    pub auth_data: Option<Vec<u8>>,
    /// Required to be `Some(_)` if and only if `auth_data` is `Some(_)`.
    pub auth_digest: Option<blake2b_simd::Hash>,
}

// ---------------------------------------------------------------------------
// TypedBundle
// ---------------------------------------------------------------------------

/// A bundle stored in the transaction's [`BundleMap`] — either a known typed
/// bundle or an opaque unknown bundle.
#[derive(Debug)]
pub enum TypedBundle<A: Authorization> {
    Transparent(transparent::Bundle<A::TransparentAuth>),
    Sprout(sprout::Bundle),
    Sapling(sapling::Bundle<A::SaplingAuth, ZatBalance>),
    Orchard(orchard::Bundle<A::OrchardAuth, ZatBalance>),
    #[cfg(zcash_unstable = "zfuture")]
    Tze(tze::Bundle<A::TzeAuth>),
    Unknown(UnknownBundle),
}

// ---------------------------------------------------------------------------
// BundleMap
// ---------------------------------------------------------------------------

/// An ordered map of protocol bundles keyed by [`BundleId`].
///
/// This reflects the ZIP 248 transaction structure where bundles are
/// self-describing entries in an ordered map. The map enforces that at most
/// one bundle exists per `bundleType` (variants of the same type are
/// mutually exclusive).
#[derive(Debug)]
pub struct BundleMap<A: Authorization> {
    inner: BTreeMap<BundleId, TypedBundle<A>>,
}

impl<A: Authorization> BundleMap<A> {
    /// Creates an empty bundle map.
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    /// Returns an iterator over all bundles in bundle-type order.
    pub fn iter(&self) -> impl Iterator<Item = (&BundleId, &TypedBundle<A>)> {
        self.inner.iter()
    }

    /// Returns true if the map contains no bundles.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    // -- Typed accessors --

    pub fn transparent(&self) -> Option<&transparent::Bundle<A::TransparentAuth>> {
        self.inner.get(&BundleId::TRANSPARENT).and_then(|b| match b {
            TypedBundle::Transparent(bundle) => Some(bundle),
            _ => None,
        })
    }

    pub fn sprout(&self) -> Option<&sprout::Bundle> {
        // Sprout uses synthetic BundleId(1, 0) — see `insert_sprout`.
        self.inner.get(&BundleId::new(1, 0)).and_then(|b| match b {
            TypedBundle::Sprout(bundle) => Some(bundle),
            _ => None,
        })
    }

    pub fn sapling(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.inner.get(&BundleId::SAPLING).and_then(|b| match b {
            TypedBundle::Sapling(bundle) => Some(bundle),
            _ => None,
        })
    }

    pub fn orchard(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.inner.get(&BundleId::ORCHARD).and_then(|b| match b {
            TypedBundle::Orchard(bundle) => Some(bundle),
            _ => None,
        })
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn tze(&self) -> Option<&tze::Bundle<A::TzeAuth>> {
        // TZE uses synthetic BundleId(0xFFFF, 0) — see `insert_tze`.
        self.inner
            .get(&BundleId::new(0xFFFF, 0))
            .and_then(|b| match b {
                TypedBundle::Tze(bundle) => Some(bundle),
                _ => None,
            })
    }

    /// Returns an iterator over unknown (opaque) bundles.
    pub fn unknown_bundles(&self) -> impl Iterator<Item = (&BundleId, &UnknownBundle)> {
        self.inner.iter().filter_map(|(id, b)| match b {
            TypedBundle::Unknown(ub) => Some((id, ub)),
            _ => None,
        })
    }

    // -- Insertion --

    pub fn insert_transparent(&mut self, bundle: transparent::Bundle<A::TransparentAuth>) {
        self.inner
            .insert(BundleId::TRANSPARENT, TypedBundle::Transparent(bundle));
    }

    /// Insert a sprout bundle. Sprout doesn't have a ZIP 248 bundle type;
    /// we use a synthetic BundleId with type 1 (reserved) and variant 0.
    pub fn insert_sprout(&mut self, bundle: sprout::Bundle) {
        self.inner
            .insert(BundleId::new(1, 0), TypedBundle::Sprout(bundle));
    }

    pub fn insert_sapling(&mut self, bundle: sapling::Bundle<A::SaplingAuth, ZatBalance>) {
        self.inner
            .insert(BundleId::SAPLING, TypedBundle::Sapling(bundle));
    }

    pub fn insert_orchard(&mut self, bundle: orchard::Bundle<A::OrchardAuth, ZatBalance>) {
        self.inner
            .insert(BundleId::ORCHARD, TypedBundle::Orchard(bundle));
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn insert_tze(&mut self, bundle: tze::Bundle<A::TzeAuth>) {
        // Use a high synthetic type for TZE since it doesn't have an assigned type yet.
        self.inner
            .insert(BundleId::new(0xFFFF, 0), TypedBundle::Tze(bundle));
    }

    pub fn insert_unknown(&mut self, id: BundleId, bundle: UnknownBundle) {
        self.inner.insert(id, TypedBundle::Unknown(bundle));
    }

    /// Returns a mutable reference to an unknown bundle, if present.
    pub fn get_unknown_mut(&mut self, id: &BundleId) -> Option<&mut UnknownBundle> {
        self.inner.get_mut(id).and_then(|b| match b {
            TypedBundle::Unknown(ub) => Some(ub),
            _ => None,
        })
    }

    // -- Authorization mapping --

    pub fn map_authorization<B: Authorization>(
        self,
        f_transparent: impl FnOnce(
            Option<transparent::Bundle<A::TransparentAuth>>,
        ) -> Option<transparent::Bundle<B::TransparentAuth>>,
        f_sapling: impl FnOnce(
            Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        ) -> Option<sapling::Bundle<B::SaplingAuth, ZatBalance>>,
        f_orchard: impl FnOnce(
            Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ) -> Option<orchard::Bundle<B::OrchardAuth, ZatBalance>>,
        #[cfg(zcash_unstable = "zfuture")] f_tze: impl FnOnce(
            Option<tze::Bundle<A::TzeAuth>>,
        ) -> Option<tze::Bundle<B::TzeAuth>>,
    ) -> BundleMap<B> {
        // Delegate to try_map_authorization with infallible closures.
        self.try_map_authorization::<B, core::convert::Infallible>(
            |b| Ok(f_transparent(b)),
            |b| Ok(f_sapling(b)),
            |b| Ok(f_orchard(b)),
            #[cfg(zcash_unstable = "zfuture")]
            |b| Ok(f_tze(b)),
        )
        // Safety: Infallible cannot be constructed, so this never panics.
        .unwrap()
    }

    /// Like [`map_authorization`] but with fallible closures.
    pub fn try_map_authorization<B: Authorization, E>(
        self,
        f_transparent: impl FnOnce(
            Option<transparent::Bundle<A::TransparentAuth>>,
        )
            -> Result<Option<transparent::Bundle<B::TransparentAuth>>, E>,
        f_sapling: impl FnOnce(
            Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        )
            -> Result<Option<sapling::Bundle<B::SaplingAuth, ZatBalance>>, E>,
        f_orchard: impl FnOnce(
            Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        )
            -> Result<Option<orchard::Bundle<B::OrchardAuth, ZatBalance>>, E>,
        #[cfg(zcash_unstable = "zfuture")] f_tze: impl FnOnce(
            Option<tze::Bundle<A::TzeAuth>>,
        ) -> Result<
            Option<tze::Bundle<B::TzeAuth>>,
            E,
        >,
    ) -> Result<BundleMap<B>, E> {
        let mut transparent_bundle = None;
        let mut sprout_bundle = None;
        let mut sapling_bundle = None;
        let mut orchard_bundle = None;
        #[cfg(zcash_unstable = "zfuture")]
        let mut tze_bundle = None;
        let mut result = BundleMap::new();

        for (id, bundle) in self.inner {
            match bundle {
                TypedBundle::Transparent(b) => transparent_bundle = Some(b),
                TypedBundle::Sprout(b) => sprout_bundle = Some((id, b)),
                TypedBundle::Sapling(b) => sapling_bundle = Some(b),
                TypedBundle::Orchard(b) => orchard_bundle = Some(b),
                #[cfg(zcash_unstable = "zfuture")]
                TypedBundle::Tze(b) => tze_bundle = Some(b),
                TypedBundle::Unknown(ub) => {
                    result.inner.insert(id, TypedBundle::Unknown(ub));
                }
            }
        }

        if let Some(b) = f_transparent(transparent_bundle)? {
            result.insert_transparent(b);
        }
        if let Some((id, b)) = sprout_bundle {
            result.inner.insert(id, TypedBundle::Sprout(b));
        }
        if let Some(b) = f_sapling(sapling_bundle)? {
            result.insert_sapling(b);
        }
        if let Some(b) = f_orchard(orchard_bundle)? {
            result.insert_orchard(b);
        }
        #[cfg(zcash_unstable = "zfuture")]
        if let Some(b) = f_tze(tze_bundle)? {
            result.insert_tze(b);
        }

        Ok(result)
    }
}

impl<A: Authorization> Default for BundleMap<A> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ValuePoolDeltas
// ---------------------------------------------------------------------------

/// Key for value pool delta entries, ordered by `(bundle_type, asset_class, asset_uuid)`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ValuePoolDeltaKey {
    pub bundle_type: u64,
    pub asset_class: u8,
    /// For ZEC (asset_class == 0), this is all zeros. For other assets, a 64-byte UUID.
    pub asset_uuid: [u8; 64],
}

impl ValuePoolDeltaKey {
    /// Creates a key for a ZEC delta of the given bundle type.
    pub fn zec(bundle_type: u64) -> Self {
        Self {
            bundle_type,
            asset_class: ASSET_CLASS_ZEC,
            asset_uuid: [0u8; 64],
        }
    }
}

/// The value pool delta map from ZIP 248.
///
/// Records per-bundle net contributions to the transparent transaction value pool.
/// For v6 transactions this is the authoritative source of value balance information.
/// For V1-V5 transactions it is derived from per-bundle value_balance fields.
#[derive(Clone, Debug, Default)]
pub struct ValuePoolDeltas {
    entries: BTreeMap<ValuePoolDeltaKey, i64>,
    /// Tracks the bundle variant for each bundle type present in the deltas.
    bundle_variants: BTreeMap<u64, u64>,
}

impl ValuePoolDeltas {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over all entries in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValuePoolDeltaKey, &i64)> {
        self.entries.iter()
    }

    /// Returns the bundle variant for a given bundle type, if present.
    pub fn bundle_variant(&self, bundle_type: u64) -> Option<u64> {
        self.bundle_variants.get(&bundle_type).copied()
    }

    // -- ZEC convenience accessors for known bundle types --

    fn get_zec(&self, bundle_type: u64) -> Option<i64> {
        self.entries.get(&ValuePoolDeltaKey::zec(bundle_type)).copied()
    }

    fn set_zec(&mut self, bundle_type: u64, variant: u64, value: i64) {
        if value != 0 {
            self.entries
                .insert(ValuePoolDeltaKey::zec(bundle_type), value);
        } else {
            self.entries.remove(&ValuePoolDeltaKey::zec(bundle_type));
        }
        self.bundle_variants.insert(bundle_type, variant);
    }

    pub fn transparent_value(&self) -> Option<ZatBalance> {
        self.get_zec(BUNDLE_TYPE_TRANSPARENT)
            .and_then(|v| ZatBalance::from_i64(v).ok())
    }

    pub fn set_transparent(&mut self, value: ZatBalance) {
        self.set_zec(
            BUNDLE_TYPE_TRANSPARENT,
            BUNDLE_VARIANT_DEFAULT,
            i64::from(value),
        );
    }

    pub fn sapling_value(&self) -> Option<ZatBalance> {
        self.get_zec(BUNDLE_TYPE_SAPLING)
            .and_then(|v| ZatBalance::from_i64(v).ok())
    }

    pub fn set_sapling(&mut self, value: ZatBalance) {
        self.set_zec(BUNDLE_TYPE_SAPLING, BUNDLE_VARIANT_DEFAULT, i64::from(value));
    }

    pub fn orchard_value(&self) -> Option<ZatBalance> {
        self.get_zec(BUNDLE_TYPE_ORCHARD)
            .and_then(|v| ZatBalance::from_i64(v).ok())
    }

    pub fn set_orchard(&mut self, value: ZatBalance) {
        self.set_zec(BUNDLE_TYPE_ORCHARD, BUNDLE_VARIANT_DEFAULT, i64::from(value));
    }

    pub fn fee(&self) -> Option<Zatoshis> {
        self.get_zec(BUNDLE_TYPE_FEE).and_then(|v| {
            // Fee VP delta is negative (value removed from pool).
            let abs = v.checked_neg().and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    pub fn set_fee(&mut self, value: Zatoshis) {
        // Fee is stored as a negative VP delta (value removed from pool).
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        self.set_zec(BUNDLE_TYPE_FEE, BUNDLE_VARIANT_DEFAULT, -pos);
    }

    pub fn zip233_amount(&self) -> Option<Zatoshis> {
        self.get_zec(BUNDLE_TYPE_ZIP233_NSM).and_then(|v| {
            // ZIP 233 NSM is a negative VP delta.
            let abs = v.checked_neg().and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    pub fn set_zip233(&mut self, value: Zatoshis) {
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        self.set_zec(BUNDLE_TYPE_ZIP233_NSM, BUNDLE_VARIANT_DEFAULT, -pos);
    }

    /// Insert a raw entry. Used during v6 deserialization.
    pub fn insert_raw(
        &mut self,
        key: ValuePoolDeltaKey,
        variant: u64,
        value: i64,
    ) {
        let bundle_type = key.bundle_type;
        self.entries.insert(key, value);
        self.bundle_variants.insert(bundle_type, variant);
    }
}

// ---------------------------------------------------------------------------
// v6 wire format helpers
// ---------------------------------------------------------------------------

/// A single value pool delta entry as it appears on the wire.
#[derive(Clone, Debug)]
pub struct ValuePoolDeltaEntry {
    pub bundle_type: u64,
    pub bundle_variant: u64,
    pub asset_class: u8,
    pub asset_uuid: Option<[u8; 64]>,
    pub value: i64,
}

impl ValuePoolDeltaEntry {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let bundle_type = CompactSize::read(&mut reader)?;
        let bundle_variant = CompactSize::read(&mut reader)?;
        let mut asset_class_buf = [0u8; 1];
        reader.read_exact(&mut asset_class_buf)?;
        let asset_class = asset_class_buf[0];
        let asset_uuid = match asset_class {
            ASSET_CLASS_ZEC => None,
            ASSET_CLASS_OTHER => {
                let mut uuid = [0u8; 64];
                reader.read_exact(&mut uuid)?;
                Some(uuid)
            }
            _other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    #[cfg(not(feature = "std"))]
                    "ValuePoolDelta assetClass must be 0 or 1",
                    #[cfg(feature = "std")]
                    alloc::format!(
                        "ValuePoolDelta assetClass must be 0 or 1, got {:#x}",
                        _other,
                    ),
                ));
            }
        };
        let mut value_buf = [0u8; 8];
        reader.read_exact(&mut value_buf)?;
        let value = i64::from_le_bytes(value_buf);
        if value == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ValuePoolDelta value must be nonzero",
            ));
        }
        Ok(Self {
            bundle_type,
            bundle_variant,
            asset_class,
            asset_uuid,
            value,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type as usize)?;
        CompactSize::write(&mut writer, self.bundle_variant as usize)?;
        writer.write_all(&[self.asset_class])?;
        if let Some(ref uuid) = self.asset_uuid {
            writer.write_all(uuid)?;
        }
        writer.write_all(&self.value.to_le_bytes())?;
        Ok(())
    }
}

/// Read the TLV framing for a bundle data entry: (bundleType, bundleVariant, dataLen, data).
pub fn read_bundle_data_framing<R: Read>(mut reader: R) -> io::Result<(BundleId, Vec<u8>)> {
    let bundle_type = CompactSize::read(&mut reader)?;
    let bundle_variant = CompactSize::read(&mut reader)?;
    let data_len = CompactSize::read(&mut reader)? as usize;
    let mut data = vec![0u8; data_len];
    reader.read_exact(&mut data)?;
    Ok((BundleId::new(bundle_type, bundle_variant), data))
}

/// Write the TLV framing for a bundle data entry.
pub fn write_bundle_data_framing<W: Write>(
    mut writer: W,
    id: &BundleId,
    data: &[u8],
) -> io::Result<()> {
    CompactSize::write(&mut writer, id.bundle_type as usize)?;
    CompactSize::write(&mut writer, id.bundle_variant as usize)?;
    CompactSize::write(&mut writer, data.len())?;
    writer.write_all(data)?;
    Ok(())
}

/// Reads and validates a sighash version 0 `sighashInfo` prefix
/// (`compactSize(1) || 0x00`) per ZIP 248 §"Sighash Versioning". Sighash
/// version 0 is currently the only defined version.
#[cfg(zcash_v6)]
pub(crate) fn consume_v6_sighash_v0_info<R: Read>(
    reader: &mut R,
    _context: &'static str,
) -> io::Result<()> {
    let info_len = CompactSize::read_t::<_, usize>(&mut *reader)?;
    if info_len != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            #[cfg(not(feature = "std"))]
            "unexpected sighashInfo length; only sighash version 0 is supported",
            #[cfg(feature = "std")]
            alloc::format!(
                "unexpected sighashInfo length {} for {}; only sighash version 0 is supported",
                info_len, _context,
            ),
        ));
    }
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            #[cfg(not(feature = "std"))]
            "unsupported sighash version",
            #[cfg(feature = "std")]
            alloc::format!(
                "unsupported sighash version {:#x} for {}",
                version[0], _context,
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transparent v6 effect/auth helpers
// ---------------------------------------------------------------------------

/// Writes transparent effecting data in v6 format.
/// Layout: tx_in_count, TransparentInputEffecting[tx_in_count] (prevout 36 + nSequence 4),
///         tx_out_count, TransparentOutput[tx_out_count] (value 8 + scriptPubKey).
pub fn write_v6_transparent_effects<W: Write>(
    mut writer: W,
    bundle: &transparent::Bundle<transparent::Authorized>,
) -> io::Result<()> {
    // tx_in_count + TransparentInputEffecting (prevout_hash + prevout_index + nSequence)
    CompactSize::write(&mut writer, bundle.vin.len())?;
    for txin in &bundle.vin {
        txin.prevout().write(&mut writer)?;
        writer.write_all(&txin.sequence().to_le_bytes())?;
    }

    // tx_out_count + TransparentOutput (value + scriptPubKey)
    CompactSize::write(&mut writer, bundle.vout.len())?;
    for txout in &bundle.vout {
        txout.write(&mut writer)?;
    }

    Ok(())
}

/// Writes transparent authorizing data in v6 format.
/// Layout: per-input TransparentInputAuth (sighashInfo + scriptSig).
pub fn write_v6_transparent_auth<W: Write>(
    mut writer: W,
    bundle: &transparent::Bundle<transparent::Authorized>,
) -> io::Result<()> {
    for txin in &bundle.vin {
        // TransparentSighashInfo: compactSize-prefixed byte array
        // For sighash version 0: single byte 0x00
        CompactSize::write(&mut writer, 1)?;
        writer.write_all(&[0x00])?;
        // scriptSig with compactSize length prefix
        txin.script_sig().write(&mut writer)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_id_ordering() {
        assert!(BundleId::TRANSPARENT < BundleId::SAPLING);
        assert!(BundleId::SAPLING < BundleId::ORCHARD);
        assert!(BundleId::ORCHARD < BundleId::FEE);
        assert!(BundleId::FEE < BundleId::ZIP233_NSM);
    }

    #[test]
    fn value_pool_deltas_basic() {
        let mut vp = ValuePoolDeltas::empty();
        assert!(vp.is_empty());
        assert_eq!(vp.fee(), None);
        assert_eq!(vp.zip233_amount(), None);

        // Set fee
        vp.set_fee(Zatoshis::from_u64(1000).unwrap());
        assert!(!vp.is_empty());
        assert_eq!(vp.fee(), Some(Zatoshis::from_u64(1000).unwrap()));

        // Set zip233
        vp.set_zip233(Zatoshis::from_u64(5000).unwrap());
        assert_eq!(vp.zip233_amount(), Some(Zatoshis::from_u64(5000).unwrap()));

        // Set sapling value balance
        let sap_vb = ZatBalance::from_i64(100_000).unwrap();
        vp.set_sapling(sap_vb);
        assert_eq!(vp.sapling_value(), Some(sap_vb));

        // Iteration order should be by bundle type
        let types: Vec<u64> = vp.iter().map(|(k, _)| k.bundle_type).collect();
        assert_eq!(types, vec![
            BUNDLE_TYPE_SAPLING,
            BUNDLE_TYPE_FEE,
            BUNDLE_TYPE_ZIP233_NSM,
        ]);
    }

    #[test]
    fn value_pool_deltas_zero_omitted() {
        let mut vp = ValuePoolDeltas::empty();
        vp.set_sapling(ZatBalance::from_i64(0).unwrap());
        // Zero values should not be stored
        assert!(vp.is_empty());
        assert_eq!(vp.sapling_value(), None);
    }

    #[test]
    fn value_pool_delta_entry_roundtrip() {
        let entry = ValuePoolDeltaEntry {
            bundle_type: BUNDLE_TYPE_SAPLING,
            bundle_variant: BUNDLE_VARIANT_DEFAULT,
            asset_class: ASSET_CLASS_ZEC,
            asset_uuid: None,
            value: -50000,
        };

        let mut buf = Vec::new();
        entry.write(&mut buf).unwrap();

        let parsed = ValuePoolDeltaEntry::read(&buf[..]).unwrap();
        assert_eq!(parsed.bundle_type, entry.bundle_type);
        assert_eq!(parsed.bundle_variant, entry.bundle_variant);
        assert_eq!(parsed.asset_class, entry.asset_class);
        assert_eq!(parsed.asset_uuid, entry.asset_uuid);
        assert_eq!(parsed.value, entry.value);
    }

    #[test]
    fn value_pool_delta_entry_rejects_zero() {
        let entry = ValuePoolDeltaEntry {
            bundle_type: 0,
            bundle_variant: 0,
            asset_class: ASSET_CLASS_ZEC,
            asset_uuid: None,
            value: 0,
        };
        let mut buf = Vec::new();
        // Write manually since write doesn't check for zero
        CompactSize::write(&mut buf, 0).unwrap();
        CompactSize::write(&mut buf, 0).unwrap();
        buf.push(ASSET_CLASS_ZEC);
        buf.extend_from_slice(&0i64.to_le_bytes());

        let result = ValuePoolDeltaEntry::read(&buf[..]);
        assert!(result.is_err());
    }

    #[test]
    fn bundle_data_framing_roundtrip() {
        let id = BundleId::new(3, 0);
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let mut buf = Vec::new();
        write_bundle_data_framing(&mut buf, &id, &data).unwrap();

        let (parsed_id, parsed_data) = read_bundle_data_framing(&buf[..]).unwrap();
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn bundle_map_typed_accessors() {
        use super::super::Authorized;

        let map: BundleMap<Authorized> = BundleMap::new();
        assert!(map.transparent().is_none());
        assert!(map.sapling().is_none());
        assert!(map.orchard().is_none());
        assert!(map.sprout().is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn bundle_map_unknown_bundles() {
        use super::super::Authorized;

        let mut map: BundleMap<Authorized> = BundleMap::new();
        let id = BundleId::new(99, 0);
        map.insert_unknown(id, UnknownBundle {
            effect_data: vec![1, 2, 3],
            effect_digest: blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"test_unknown_efx")
                .hash(&[1, 2, 3]),
            auth_data: Some(vec![4, 5, 6]),
            auth_digest: Some(
                blake2b_simd::Params::new()
                    .hash_length(32)
                    .personal(b"test_unknown_aut")
                    .hash(&[4, 5, 6]),
            ),
        });

        assert!(!map.is_empty());
        let unknowns: Vec<_> = map.unknown_bundles().collect();
        assert_eq!(unknowns.len(), 1);
        assert_eq!(unknowns[0].0, &id);
        assert_eq!(unknowns[0].1.effect_data, vec![1, 2, 3]);
    }
}
