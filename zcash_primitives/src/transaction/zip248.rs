//! ZIP 248: Extensible Transaction Format types.
//!
//! This module defines the core types for the ZIP 248 transaction format:
//! - [`BundleId`]: A `(bundleType, bundleVariant)` pair identifying a protocol bundle.
//! - [`TypedBundle`]: An enum over known ZIP 248 bundle types.
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
// Bundle type and variant enums (ZIP 248 registry for v6 transactions)
// ---------------------------------------------------------------------------

/// Bundle type identifiers from the V6 Transaction Bundle Type Registry
/// defined in ZIP 248.
///
/// Each variant corresponds to a protocol or value pool. New bundle types
/// may be added by future ZIPs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum BundleType {
    /// Sprout JoinSplit descriptions (v1–v4 transactions only).
    ///
    /// In-memory only — no wire encoding, not in the ZIP 248 registry.
    Sprout,
    /// Transparent Zcash Extensions (speculative, `zcash_unstable = "zfuture"` only).
    ///
    /// In-memory only — not yet assigned a bundle type in ZIP 248.
    Tze,
    /// Transparent inputs and outputs (bundleType 0).
    Transparent,
    /// Reserved (bundleType 1). MUST NOT appear in any map.
    Reserved,
    /// Sapling spends and outputs (bundleType 2).
    Sapling,
    /// Orchard actions (bundleType 3).
    Orchard,
    /// Transaction fee, value-only (bundleType 4, ZIP 2002).
    Fee,
    /// ZIP 233 NSM field, value-only (bundleType 5).
    Zip233Nsm,
    /// Key rotation (bundleType 6, ZIP 270). No VP deltas.
    KeyRotation,
    /// Lockbox disbursement (bundleType 7, TBD).
    LockboxDisbursement,
}

impl BundleType {
    /// Try to decode a wire value. Returns `None` for unrecognized types.
    ///
    /// [`BundleType::Sprout`] and [`BundleType::Tze`] are never returned —
    /// they have no wire encoding.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Transparent),
            1 => Some(Self::Reserved),
            2 => Some(Self::Sapling),
            3 => Some(Self::Orchard),
            4 => Some(Self::Fee),
            5 => Some(Self::Zip233Nsm),
            6 => Some(Self::KeyRotation),
            7 => Some(Self::LockboxDisbursement),
            _ => None,
        }
    }

    /// Encode as a `u64` for `compactSize` serialization.
    ///
    /// # Panics
    ///
    /// Panics if called on [`BundleType::Sprout`] or [`BundleType::Tze`],
    /// which have no wire encoding.
    pub fn to_u64(self) -> u64 {
        match self {
            Self::Sprout | Self::Tze => panic!("in-memory-only bundle type has no wire encoding"),
            Self::Transparent => 0,
            Self::Reserved => 1,
            Self::Sapling => 2,
            Self::Orchard => 3,
            Self::Fee => 4,
            Self::Zip233Nsm => 5,
            Self::KeyRotation => 6,
            Self::LockboxDisbursement => 7,
        }
    }
}

/// Bundle variant identifiers from the V6 Transaction Bundle Type Registry
/// defined in ZIP 248.
///
/// Within a given bundle type, variants allow protocol evolution while
/// preserving the association with the same value pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum BundleVariant {
    /// The default (and currently only assigned) variant for all bundle
    /// types (bundleVariant 0).
    Default,
}

impl BundleVariant {
    /// Try to decode a wire value. Returns `None` for unrecognized variants.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Default),
            _ => None,
        }
    }

    /// Encode as a `u64` for `compactSize` serialization.
    pub fn to_u64(self) -> u64 {
        match self {
            Self::Default => 0,
        }
    }
}

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
    pub bundle_type: BundleType,
    pub bundle_variant: BundleVariant,
}

impl BundleId {
    pub const fn new(bundle_type: BundleType, bundle_variant: BundleVariant) -> Self {
        Self {
            bundle_type,
            bundle_variant,
        }
    }

    pub const SPROUT: Self = Self::new(BundleType::Sprout, BundleVariant::Default);
    pub const TZE: Self = Self::new(BundleType::Tze, BundleVariant::Default);
    pub const TRANSPARENT: Self = Self::new(BundleType::Transparent, BundleVariant::Default);
    pub const SAPLING: Self = Self::new(BundleType::Sapling, BundleVariant::Default);
    pub const ORCHARD: Self = Self::new(BundleType::Orchard, BundleVariant::Default);
    pub const FEE: Self = Self::new(BundleType::Fee, BundleVariant::Default);
    pub const ZIP233_NSM: Self = Self::new(BundleType::Zip233Nsm, BundleVariant::Default);
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

/// A typed bundle stored in the [`BundleMap`]'s `known` map.
///
/// Unknown bundle types are stored separately as [`UnknownBundle`].
#[derive(Debug)]
pub enum TypedBundle<A: Authorization> {
    Transparent(transparent::Bundle<A::TransparentAuth>),
    Sprout(sprout::Bundle),
    Sapling(sapling::Bundle<A::SaplingAuth, ZatBalance>),
    Orchard(orchard::Bundle<A::OrchardAuth, ZatBalance>),
    #[cfg(zcash_unstable = "zfuture")]
    Tze(tze::Bundle<A::TzeAuth>),
}

// ---------------------------------------------------------------------------
// BundleMap
// ---------------------------------------------------------------------------

/// An ordered map of protocol bundles keyed by [`BundleId`].
///
/// Known bundle types are stored in a typed map keyed by [`BundleId`].
/// Unknown bundle types (those whose wire value doesn't map to a
/// [`BundleType`] variant) are stored separately as opaque byte blobs
/// keyed by the raw `(bundleType, bundleVariant)` pair so that the
/// transaction can be re-serialized without understanding their contents.
#[derive(Debug)]
pub struct BundleMap<A: Authorization> {
    known: BTreeMap<BundleId, TypedBundle<A>>,
    /// Opaque bundles whose type is not recognized by this implementation,
    /// keyed by raw `(bundleType, bundleVariant)` wire values.
    unknown: BTreeMap<(u64, u64), UnknownBundle>,
}

impl<A: Authorization> BundleMap<A> {
    /// Creates an empty bundle map.
    pub fn new() -> Self {
        Self {
            known: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    /// Returns an iterator over known-type bundles in bundle-type order.
    pub fn iter(&self) -> impl Iterator<Item = (&BundleId, &TypedBundle<A>)> {
        self.known.iter()
    }

    /// Returns true if the map contains no bundles (known or unknown).
    pub fn is_empty(&self) -> bool {
        self.known.is_empty() && self.unknown.is_empty()
    }

    // -- Typed accessors --

    pub fn transparent(&self) -> Option<&transparent::Bundle<A::TransparentAuth>> {
        self.known.get(&BundleId::TRANSPARENT).and_then(|b| match b {
            TypedBundle::Transparent(bundle) => Some(bundle),
            _ => None,
        })
    }

    pub fn sprout(&self) -> Option<&sprout::Bundle> {
        self.known.get(&BundleId::SPROUT).and_then(|b| match b {
            TypedBundle::Sprout(bundle) => Some(bundle),
            _ => None,
        })
    }

    pub fn sapling(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.known.get(&BundleId::SAPLING).and_then(|b| match b {
            TypedBundle::Sapling(bundle) => Some(bundle),
            _ => None,
        })
    }

    pub fn orchard(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.known.get(&BundleId::ORCHARD).and_then(|b| match b {
            TypedBundle::Orchard(bundle) => Some(bundle),
            _ => None,
        })
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn tze(&self) -> Option<&tze::Bundle<A::TzeAuth>> {
        self.known.get(&BundleId::TZE).and_then(|b| match b {
            TypedBundle::Tze(bundle) => Some(bundle),
            _ => None,
        })
    }

    /// Returns an iterator over unknown (opaque) bundles, keyed by their
    /// raw `(bundleType, bundleVariant)` wire values.
    pub fn unknown_bundles(&self) -> impl Iterator<Item = (&(u64, u64), &UnknownBundle)> {
        self.unknown.iter()
    }

    // -- Insertion --

    pub fn insert_transparent(&mut self, bundle: transparent::Bundle<A::TransparentAuth>) {
        self.known
            .insert(BundleId::TRANSPARENT, TypedBundle::Transparent(bundle));
    }

    /// Insert a Sprout bundle. Uses the in-memory-only [`BundleType::Sprout`].
    pub fn insert_sprout(&mut self, bundle: sprout::Bundle) {
        self.known.insert(BundleId::SPROUT, TypedBundle::Sprout(bundle));
    }

    pub fn insert_sapling(&mut self, bundle: sapling::Bundle<A::SaplingAuth, ZatBalance>) {
        self.known
            .insert(BundleId::SAPLING, TypedBundle::Sapling(bundle));
    }

    pub fn insert_orchard(&mut self, bundle: orchard::Bundle<A::OrchardAuth, ZatBalance>) {
        self.known
            .insert(BundleId::ORCHARD, TypedBundle::Orchard(bundle));
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn insert_tze(&mut self, bundle: tze::Bundle<A::TzeAuth>) {
        self.known.insert(BundleId::TZE, TypedBundle::Tze(bundle));
    }

    /// Insert an opaque bundle whose type is not recognized.
    pub fn insert_unknown(&mut self, raw_type: u64, raw_variant: u64, bundle: UnknownBundle) {
        self.unknown.insert((raw_type, raw_variant), bundle);
    }

    /// Returns a mutable reference to an unknown bundle, if present.
    pub fn get_unknown_mut(&mut self, raw_type: u64, raw_variant: u64) -> Option<&mut UnknownBundle> {
        self.unknown.get_mut(&(raw_type, raw_variant))
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

        for (_id, bundle) in self.known {
            match bundle {
                TypedBundle::Transparent(b) => transparent_bundle = Some(b),
                TypedBundle::Sprout(b) => sprout_bundle = Some(b),
                TypedBundle::Sapling(b) => sapling_bundle = Some(b),
                TypedBundle::Orchard(b) => orchard_bundle = Some(b),
                #[cfg(zcash_unstable = "zfuture")]
                TypedBundle::Tze(b) => tze_bundle = Some(b),
            }
        }
        result.unknown = self.unknown;

        if let Some(b) = f_transparent(transparent_bundle)? {
            result.insert_transparent(b);
        }
        // Sprout bundles pass through unchanged (no authorization to map).
        if let Some(b) = sprout_bundle {
            result.insert_sprout(b);
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

/// Key for value pool delta entries for known bundle types.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ValuePoolDeltaKey {
    pub bundle_type: BundleType,
    pub asset_class: u8,
    /// For ZEC (asset_class == 0), this is all zeros. For other assets, a 64-byte UUID.
    pub asset_uuid: [u8; 64],
}

impl ValuePoolDeltaKey {
    pub fn zec(bundle_type: BundleType) -> Self {
        Self {
            bundle_type,
            asset_class: ASSET_CLASS_ZEC,
            asset_uuid: [0u8; 64],
        }
    }
}

/// `(bundle_variant, value)` for a known-type VP delta entry.
pub type VPDeltaValue = (BundleVariant, i64);

/// Key for value pool delta entries for unknown bundle types.
/// `(bundleType, assetClass, assetUuid)` — all raw wire values.
pub type UnknownVPDeltaKey = (u64, u8, [u8; 64]);
/// `(bundleVariant, value)` — raw wire values.
pub type UnknownVPDeltaValue = (u64, i64);

/// The value pool delta map from ZIP 248.
///
/// Known bundle types are stored in `entries` keyed by [`ValuePoolDeltaKey`].
/// Unrecognized bundle types are stored separately in `unknown` so that
/// the transaction can be re-serialized without understanding their contents.
#[derive(Clone, Debug, Default)]
pub struct ValuePoolDeltas {
    known: BTreeMap<ValuePoolDeltaKey, VPDeltaValue>,
    unknown: BTreeMap<UnknownVPDeltaKey, UnknownVPDeltaValue>,
}

impl ValuePoolDeltas {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty() && self.unknown.is_empty()
    }

    /// Returns an iterator over known-type entries in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValuePoolDeltaKey, &VPDeltaValue)> {
        self.known.iter()
    }

    /// Returns an iterator over unknown-type entries in canonical order.
    pub fn unknown_iter(&self) -> impl Iterator<Item = (&UnknownVPDeltaKey, &UnknownVPDeltaValue)> {
        self.unknown.iter()
    }

    /// Returns the bundle variant for a given known bundle type, if present.
    pub fn bundle_variant(&self, bundle_type: BundleType) -> Option<BundleVariant> {
        self.known
            .range(ValuePoolDeltaKey::zec(bundle_type)..)
            .find(|(k, _)| k.bundle_type == bundle_type)
            .map(|(_, &(variant, _))| variant)
    }

    // -- ZEC convenience accessors for known bundle types --

    fn get_zec(&self, bundle_type: BundleType) -> Option<i64> {
        self.known
            .get(&ValuePoolDeltaKey::zec(bundle_type))
            .map(|&(_, v)| v)
    }

    fn set_zec(&mut self, bundle_type: BundleType, variant: BundleVariant, value: i64) {
        if value != 0 {
            self.known
                .insert(ValuePoolDeltaKey::zec(bundle_type), (variant, value));
        } else {
            self.known.remove(&ValuePoolDeltaKey::zec(bundle_type));
        }
    }

    pub fn transparent_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::Transparent)
            .and_then(|v| ZatBalance::from_i64(v).ok())
    }

    pub fn set_transparent(&mut self, value: ZatBalance) {
        self.set_zec(BundleType::Transparent, BundleVariant::Default, i64::from(value));
    }

    pub fn sapling_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::Sapling)
            .and_then(|v| ZatBalance::from_i64(v).ok())
    }

    pub fn set_sapling(&mut self, value: ZatBalance) {
        self.set_zec(BundleType::Sapling, BundleVariant::Default, i64::from(value));
    }

    pub fn orchard_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::Orchard)
            .and_then(|v| ZatBalance::from_i64(v).ok())
    }

    pub fn set_orchard(&mut self, value: ZatBalance) {
        self.set_zec(BundleType::Orchard, BundleVariant::Default, i64::from(value));
    }

    pub fn fee(&self) -> Option<Zatoshis> {
        self.get_zec(BundleType::Fee).and_then(|v| {
            let abs = v.checked_neg().and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    pub fn set_fee(&mut self, value: Zatoshis) {
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        self.set_zec(BundleType::Fee, BundleVariant::Default, -pos);
    }

    pub fn zip233_amount(&self) -> Option<Zatoshis> {
        self.get_zec(BundleType::Zip233Nsm).and_then(|v| {
            let abs = v.checked_neg().and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    pub fn set_zip233(&mut self, value: Zatoshis) {
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        self.set_zec(BundleType::Zip233Nsm, BundleVariant::Default, -pos);
    }

    /// Insert a known-type entry. Used during v6 deserialization.
    pub fn insert_known(&mut self, key: ValuePoolDeltaKey, variant: BundleVariant, value: i64) {
        self.known.insert(key, (variant, value));
    }

    /// Insert an unknown-type entry. Used during v6 deserialization.
    pub fn insert_unknown(&mut self, bundle_type: u64, asset_class: u8, asset_uuid: [u8; 64], variant: u64, value: i64) {
        self.unknown.insert((bundle_type, asset_class, asset_uuid), (variant, value));
    }

    /// Produce all VP delta entries (known and unknown) in canonical wire
    /// order, sorted by `(bundleType, assetClass, assetUuid)`.
    pub fn to_wire_entries(&self) -> Vec<ValuePoolDeltaEntry> {
        let known = self.known.iter().map(|(k, &(variant, v))| ValuePoolDeltaEntry {
            bundle_type: k.bundle_type.to_u64(),
            bundle_variant: variant.to_u64(),
            asset_class: k.asset_class,
            asset_uuid: if k.asset_class == ASSET_CLASS_ZEC { None } else { Some(k.asset_uuid) },
            value: v,
        });
        let unknown = self.unknown.iter().map(|(&(bt, ac, uuid), &(bv, v))| ValuePoolDeltaEntry {
            bundle_type: bt,
            bundle_variant: bv,
            asset_class: ac,
            asset_uuid: if ac == ASSET_CLASS_ZEC { None } else { Some(uuid) },
            value: v,
        });
        let mut all: Vec<_> = known.chain(unknown).collect();
        all.sort_by(|a, b| {
            (a.bundle_type, a.asset_class, a.asset_uuid.unwrap_or([0u8; 64]))
                .cmp(&(b.bundle_type, b.asset_class, b.asset_uuid.unwrap_or([0u8; 64])))
        });
        all
    }
}

// ---------------------------------------------------------------------------
// v6 wire format helpers
// ---------------------------------------------------------------------------

/// A single value pool delta entry as it appears on the wire.
///
/// Uses raw `u64` for type/variant since the wire may contain values for
/// bundle types not recognized by this implementation.
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
///
/// Returns raw `(u64, u64)` for the type/variant since the wire may carry
/// unrecognized bundle types.
pub fn read_bundle_data_framing<R: Read>(mut reader: R) -> io::Result<((u64, u64), Vec<u8>)> {
    let bundle_type = CompactSize::read(&mut reader)?;
    let bundle_variant = CompactSize::read(&mut reader)?;
    let data_len = CompactSize::read(&mut reader)? as usize;
    let mut data = vec![0u8; data_len];
    reader.read_exact(&mut data)?;
    Ok(((bundle_type, bundle_variant), data))
}

/// Write the TLV framing for a bundle data entry.
pub fn write_bundle_data_framing<W: Write>(
    mut writer: W,
    bundle_type: u64,
    bundle_variant: u64,
    data: &[u8],
) -> io::Result<()> {
    CompactSize::write(&mut writer, bundle_type as usize)?;
    CompactSize::write(&mut writer, bundle_variant as usize)?;
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
        let types: Vec<BundleType> = vp.iter().map(|(k, _)| k.bundle_type).collect();
        assert_eq!(types, vec![
            BundleType::Sapling,
            BundleType::Fee,
            BundleType::Zip233Nsm,
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
            bundle_type: BundleType::Sapling.to_u64(),
            bundle_variant: BundleVariant::Default.to_u64(),
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
        let mut buf = Vec::new();
        CompactSize::write(&mut buf, 0).unwrap();
        CompactSize::write(&mut buf, 0).unwrap();
        buf.push(ASSET_CLASS_ZEC);
        buf.extend_from_slice(&0i64.to_le_bytes());

        let result = ValuePoolDeltaEntry::read(&buf[..]);
        assert!(result.is_err());
    }

    #[test]
    fn bundle_data_framing_roundtrip() {
        let bt = BundleType::Orchard.to_u64();
        let bv = BundleVariant::Default.to_u64();
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let mut buf = Vec::new();
        write_bundle_data_framing(&mut buf, bt, bv, &data).unwrap();

        let ((parsed_bt, parsed_bv), parsed_data) = read_bundle_data_framing(&buf[..]).unwrap();
        assert_eq!(parsed_bt, bt);
        assert_eq!(parsed_bv, bv);
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
        map.insert_unknown(99, 0, UnknownBundle {
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
        assert_eq!(unknowns[0].0, &(99u64, 0u64));
        assert_eq!(unknowns[0].1.effect_data, vec![1, 2, 3]);
    }
}
