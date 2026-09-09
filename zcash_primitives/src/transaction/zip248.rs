//! ZIP 248: Extensible Transaction Format types.
//!
//! This module defines the core types for the ZIP 248 transaction format:
//! - [`BundleId`]: A `(bundleType, bundleVariant)` pair identifying a protocol bundle.
//! - [`TypedBundle`]: An enum over known ZIP 248 bundle types.
//! - [`BundleMap`]: An ordered map of bundles keyed by [`BundleId`].
//! - [`ValuePoolDeltas`]: The value pool delta map recording per-bundle value contributions.
//! - [`UnknownBundle`]: An opaque bundle with unparsed effect and auth data.

use alloc::boxed::Box;
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
// Bundle type and variant enums (ZIP 248 registry for v7 transactions)
// ---------------------------------------------------------------------------

/// Bundle type identifiers from the V7 Transaction Bundle Type Registry
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
    /// Coinbase issuance and metadata (bundleType 1). No authorizing data.
    Coinbase,
    /// Sapling spends and outputs (bundleType 2).
    Sapling,
    /// Orchard actions acting on the *Orchard pool* (bundleType 3).
    Orchard,
    /// Orchard actions acting on the *Ironwood pool* (bundleType 4).
    ///
    /// Uses the same encoding as [`BundleType::Orchard`]; the two differ in
    /// the pool they act on, and so in their digest personalizations.
    Ironwood,
    /// Transaction fee, value-only (bundleType 5, ZIP 2002).
    Fee,
    /// ZIP 233 NSM field, value-only (bundleType 6, ZIP 233).
    Zip233Nsm,
}

impl BundleType {
    /// Try to decode a wire value. Returns `None` for unrecognized types.
    ///
    /// [`BundleType::Sprout`] and [`BundleType::Tze`] are never returned —
    /// they have no wire encoding.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Transparent),
            1 => Some(Self::Coinbase),
            2 => Some(Self::Sapling),
            3 => Some(Self::Orchard),
            4 => Some(Self::Ironwood),
            5 => Some(Self::Fee),
            6 => Some(Self::Zip233Nsm),
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
            Self::Coinbase => 1,
            Self::Sapling => 2,
            Self::Orchard => 3,
            Self::Ironwood => 4,
            Self::Fee => 5,
            Self::Zip233Nsm => 6,
        }
    }
}

/// Bundle variant identifiers from the V7 Transaction Bundle Type Registry
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
    /// The protocol-level bundle type (e.g. Transparent, Sapling, Orchard).
    pub bundle_type: BundleType,
    /// The variant within the bundle type.
    pub bundle_variant: BundleVariant,
}

impl BundleId {
    /// Constructs a BundleId from its type and variant.
    pub const fn new(bundle_type: BundleType, bundle_variant: BundleVariant) -> Self {
        Self {
            bundle_type,
            bundle_variant,
        }
    }

    /// Returns `(bundleType, bundleVariant)` as raw `u64` values for wire encoding.
    ///
    /// # Panics
    ///
    /// Panics if the bundle type has no wire encoding (e.g. [`BundleType::Sprout`]).
    pub fn wire_key(&self) -> (u64, u64) {
        (self.bundle_type.to_u64(), self.bundle_variant.to_u64())
    }

    /// Sprout bundle (in-memory only, no wire encoding).
    pub const SPROUT: Self = Self::new(BundleType::Sprout, BundleVariant::Default);
    /// TZE bundle (in-memory only, no wire encoding).
    pub const TZE: Self = Self::new(BundleType::Tze, BundleVariant::Default);
    /// Transparent bundle (bundleType 0, variant 0).
    pub const TRANSPARENT: Self = Self::new(BundleType::Transparent, BundleVariant::Default);
    /// Coinbase bundle (bundleType 1, variant 0).
    pub const COINBASE: Self = Self::new(BundleType::Coinbase, BundleVariant::Default);
    /// Sapling bundle (bundleType 2, variant 0).
    pub const SAPLING: Self = Self::new(BundleType::Sapling, BundleVariant::Default);
    /// Orchard bundle (bundleType 3, variant 0).
    pub const ORCHARD: Self = Self::new(BundleType::Orchard, BundleVariant::Default);
    /// Ironwood bundle (bundleType 4, variant 0).
    pub const IRONWOOD: Self = Self::new(BundleType::Ironwood, BundleVariant::Default);
    /// Transaction fee (bundleType 5, variant 0, value-only).
    pub const FEE: Self = Self::new(BundleType::Fee, BundleVariant::Default);
    /// ZIP 233 NSM field (bundleType 6, variant 0, value-only).
    pub const ZIP233_NSM: Self = Self::new(BundleType::Zip233Nsm, BundleVariant::Default);
}

// ---------------------------------------------------------------------------
// UnknownBundle
// ---------------------------------------------------------------------------

/// An opaque bundle whose type is not recognized by this implementation.
///
/// The effect and auth data are stored as unparsed byte vectors so that
/// the transaction can still be serialized. The `effect_digest` is
/// computed using the opaque effects personalization defined in ZIP 248,
/// allowing any wallet to derive the txid. The `auth_digest` cannot be
/// computed without understanding the bundle type, so it is left as `None`
/// when parsed from the wire.
#[derive(Clone, Debug)]
pub struct UnknownBundle {
    /// Raw effecting-data bytes from the wire.
    pub effect_data: Vec<u8>,
    /// Digest of the effecting data for the txid computation, using the
    /// opaque effects personalization from ZIP 248 §T.3.
    pub effect_digest: blake2b_simd::Hash,
    /// Raw authorizing-data bytes from the wire, if present.
    pub auth_data: Option<Vec<u8>>,
    /// Digest of the authorizing data. `None` when parsed from the wire;
    /// set via [`BundleMap::get_unknown_mut`] before computing the auth commitment.
    pub auth_digest: Option<blake2b_simd::Hash>,
}

// ---------------------------------------------------------------------------
// CoinbaseBundle
// ---------------------------------------------------------------------------

/// The maximum length of the coinbase bundle's `coinbaseData` field.
///
/// A coinbase `scriptSig` was limited to 100 bytes, of which the leading push
/// of the block height took 5; of the 95 bytes that remained, the
/// `compactSize` length prefix of `coinbaseData` now takes one.
pub const MAX_COINBASE_DATA_LEN: usize = 94;

/// The largest block height that may appear in a coinbase bundle,
/// matching the range that ZIP 203 allows for `nExpiryHeight`.
const MAX_COINBASE_BLOCK_HEIGHT: u32 = 499_999_999;

/// The effecting data of the ZIP 248 coinbase bundle (`bundleType = 1`).
/// [ZIP 248 §Coinbase Bundle](https://zips.z.cash/zip-0248#coinbase-bundle)
///
/// A transaction is a coinbase transaction if and only if it has a coinbase
/// bundle. The bundle replaces the otherwise-unspendable transparent input
/// that identified a coinbase transaction in previous transaction versions,
/// and carries the block height that that input was required to encode.
///
/// `block_subsidy` is the whole of the new issuance for the block, and
/// `lockbox_value` is the part of it that the funding streams deposit into
/// the deferred pool. Only the difference is paid out by the transaction, so
/// that difference — not the subsidy — is the bundle's value pool delta.
///
/// The coinbase bundle has no authorizing data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseBundle {
    block_height: u32,
    block_subsidy: Zatoshis,
    lockbox_value: Zatoshis,
    coinbase_data: Vec<u8>,
}

impl CoinbaseBundle {
    /// Constructs a coinbase bundle, returning `None` if any of the field
    /// constraints in ZIP 248 §"Coinbase Effecting Data" is violated.
    pub fn from_parts(
        block_height: u32,
        block_subsidy: Zatoshis,
        lockbox_value: Zatoshis,
        coinbase_data: Vec<u8>,
    ) -> Option<Self> {
        if block_height == 0
            || block_height > MAX_COINBASE_BLOCK_HEIGHT
            || lockbox_value > block_subsidy
            || coinbase_data.len() > MAX_COINBASE_DATA_LEN
        {
            return None;
        }
        Some(Self {
            block_height,
            block_subsidy,
            lockbox_value,
            coinbase_data,
        })
    }

    /// Returns the height of the block in which the transaction is mined.
    pub fn block_height(&self) -> u32 {
        self.block_height
    }

    /// Returns the block subsidy for that block.
    pub fn block_subsidy(&self) -> Zatoshis {
        self.block_subsidy
    }

    /// Returns the part of the block subsidy deposited into the lockbox.
    pub fn lockbox_value(&self) -> Zatoshis {
        self.lockbox_value
    }

    /// Returns the miner-chosen data. Consensus assigns no meaning to it.
    pub fn coinbase_data(&self) -> &[u8] {
        &self.coinbase_data
    }

    /// Returns the value that this bundle contributes to the transparent
    /// transaction value pool: the block subsidy less the lockbox deposit.
    ///
    /// This is the value that
    /// $\mathsf{mValuePoolDeltas}[(\mathsf{CoinbaseBundleId}, \mathsf{Zec})]$
    /// is required to equal.
    pub fn value_pool_delta(&self) -> ZatBalance {
        // `from_parts` and `read` both reject a lockbox value larger than the
        // subsidy, so the difference of two in-range amounts is in range.
        let subsidy = i64::try_from(u64::from(self.block_subsidy)).expect("MAX_MONEY fits in i64");
        let lockbox = i64::try_from(u64::from(self.lockbox_value)).expect("MAX_MONEY fits in i64");
        ZatBalance::from_i64(subsidy - lockbox).expect("lockboxValue <= blockSubsidy <= MAX_MONEY")
    }

    /// Deserializes the coinbase bundle's effecting data.
    /// [ZIP 248 §Coinbase Effecting Data](https://zips.z.cash/zip-0248#coinbase-effecting-data)
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut u32_buf = [0u8; 4];
        reader.read_exact(&mut u32_buf)?;
        let block_height = u32::from_le_bytes(u32_buf);

        let mut u64_buf = [0u8; 8];
        reader.read_exact(&mut u64_buf)?;
        let block_subsidy = Zatoshis::from_u64(u64::from_le_bytes(u64_buf)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "coinbase blockSubsidy out of valid monetary range",
            )
        })?;

        reader.read_exact(&mut u64_buf)?;
        let lockbox_value = Zatoshis::from_u64(u64::from_le_bytes(u64_buf)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "coinbase lockboxValue out of valid monetary range",
            )
        })?;

        let data_len = CompactSize::read_t::<_, usize>(&mut reader)?;
        // Bound the allocation before reading: `coinbaseDataLen` comes from
        // the wire and is capped by ZIP 248 at `MAX_COINBASE_DATA_LEN`.
        if data_len > MAX_COINBASE_DATA_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "coinbase coinbaseDataLen exceeds the ZIP 248 limit of 94 bytes",
            ));
        }
        let mut coinbase_data = vec![0u8; data_len];
        reader.read_exact(&mut coinbase_data)?;

        Self::from_parts(block_height, block_subsidy, lockbox_value, coinbase_data).ok_or_else(
            || {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "coinbase bundle violates a ZIP 248 field constraint \
                     (blockHeight range, or lockboxValue > blockSubsidy)",
                )
            },
        )
    }

    /// Serializes the coinbase bundle's effecting data.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.block_height.to_le_bytes())?;
        writer.write_all(&u64::from(self.block_subsidy).to_le_bytes())?;
        writer.write_all(&u64::from(self.lockbox_value).to_le_bytes())?;
        CompactSize::write(&mut writer, self.coinbase_data.len())?;
        writer.write_all(&self.coinbase_data)?;
        Ok(())
    }
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
    Coinbase(CoinbaseBundle),
    Sprout(sprout::Bundle),
    Sapling(sapling::Bundle<A::SaplingAuth, ZatBalance>),
    Orchard(Box<orchard::Bundle<A::OrchardAuth, ZatBalance>>),
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

    /// Returns the transparent bundle, if present.
    pub fn transparent(&self) -> Option<&transparent::Bundle<A::TransparentAuth>> {
        self.known
            .get(&BundleId::TRANSPARENT)
            .and_then(|b| match b {
                TypedBundle::Transparent(bundle) => Some(bundle),
                _ => None,
            })
    }

    /// Returns the coinbase bundle, if present. A transaction is a coinbase
    /// transaction if and only if this returns `Some`.
    pub fn coinbase(&self) -> Option<&CoinbaseBundle> {
        self.known.get(&BundleId::COINBASE).and_then(|b| match b {
            TypedBundle::Coinbase(bundle) => Some(bundle),
            _ => None,
        })
    }

    /// Returns the sprout bundle, if present.
    pub fn sprout(&self) -> Option<&sprout::Bundle> {
        self.known.get(&BundleId::SPROUT).and_then(|b| match b {
            TypedBundle::Sprout(bundle) => Some(bundle),
            _ => None,
        })
    }

    /// Returns the sapling bundle, if present.
    pub fn sapling(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.known.get(&BundleId::SAPLING).and_then(|b| match b {
            TypedBundle::Sapling(bundle) => Some(bundle),
            _ => None,
        })
    }

    /// Returns the orchard bundle, if present.
    pub fn orchard(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.known.get(&BundleId::ORCHARD).and_then(|b| match b {
            TypedBundle::Orchard(bundle) => Some(bundle.as_ref()),
            _ => None,
        })
    }

    /// Returns the tze bundle, if present.
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

    /// Inserts the transparent bundle.
    pub fn insert_transparent(&mut self, bundle: transparent::Bundle<A::TransparentAuth>) {
        self.known
            .insert(BundleId::TRANSPARENT, TypedBundle::Transparent(bundle));
    }

    /// Inserts the coinbase bundle.
    pub fn insert_coinbase(&mut self, bundle: CoinbaseBundle) {
        self.known
            .insert(BundleId::COINBASE, TypedBundle::Coinbase(bundle));
    }

    /// Insert a Sprout bundle. Uses the in-memory-only [`BundleType::Sprout`].
    pub fn insert_sprout(&mut self, bundle: sprout::Bundle) {
        self.known
            .insert(BundleId::SPROUT, TypedBundle::Sprout(bundle));
    }

    /// Inserts the sapling bundle.
    pub fn insert_sapling(&mut self, bundle: sapling::Bundle<A::SaplingAuth, ZatBalance>) {
        self.known
            .insert(BundleId::SAPLING, TypedBundle::Sapling(bundle));
    }

    /// Inserts the orchard bundle.
    pub fn insert_orchard(&mut self, bundle: orchard::Bundle<A::OrchardAuth, ZatBalance>) {
        self.known
            .insert(BundleId::ORCHARD, TypedBundle::Orchard(Box::new(bundle)));
    }

    /// Inserts the tze bundle.
    #[cfg(zcash_unstable = "zfuture")]
    pub fn insert_tze(&mut self, bundle: tze::Bundle<A::TzeAuth>) {
        self.known.insert(BundleId::TZE, TypedBundle::Tze(bundle));
    }

    /// Insert an opaque bundle whose type is not recognized.
    pub fn insert_unknown(&mut self, raw_type: u64, raw_variant: u64, bundle: UnknownBundle) {
        self.unknown.insert((raw_type, raw_variant), bundle);
    }

    /// Returns a mutable reference to an unknown bundle, if present.
    pub fn get_unknown_mut(
        &mut self,
        raw_type: u64,
        raw_variant: u64,
    ) -> Option<&mut UnknownBundle> {
        self.unknown.get_mut(&(raw_type, raw_variant))
    }

    // -- Authorization mapping --

    /// Transforms bundle authorization types using the given per-protocol closures.
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
        )
            -> Option<tze::Bundle<B::TzeAuth>>,
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
        let mut coinbase_bundle = None;
        let mut sprout_bundle = None;
        let mut sapling_bundle = None;
        let mut orchard_bundle = None;
        #[cfg(zcash_unstable = "zfuture")]
        let mut tze_bundle = None;
        let mut result = BundleMap::new();

        for (_id, bundle) in self.known {
            match bundle {
                TypedBundle::Transparent(b) => transparent_bundle = Some(b),
                TypedBundle::Coinbase(b) => coinbase_bundle = Some(b),
                TypedBundle::Sprout(b) => sprout_bundle = Some(b),
                TypedBundle::Sapling(b) => sapling_bundle = Some(b),
                TypedBundle::Orchard(b) => orchard_bundle = Some(*b),
                #[cfg(zcash_unstable = "zfuture")]
                TypedBundle::Tze(b) => tze_bundle = Some(b),
            }
        }
        result.unknown = self.unknown;

        if let Some(b) = f_transparent(transparent_bundle)? {
            result.insert_transparent(b);
        }
        // The coinbase bundle has no authorizing data, so it passes through
        // unchanged.
        if let Some(b) = coinbase_bundle {
            result.insert_coinbase(b);
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
    /// The bundle type this delta belongs to.
    pub bundle_type: BundleType,
    /// Asset class: 0 for ZEC, 1 for other assets.
    pub asset_class: u8,
    /// For ZEC (asset_class == 0), this is all zeros. For other assets, a 64-byte UUID.
    pub asset_uuid: [u8; 64],
}

impl ValuePoolDeltaKey {
    /// Creates a key for a ZEC delta of the given bundle type.
    pub fn zec(bundle_type: BundleType) -> Self {
        Self {
            bundle_type,
            asset_class: ASSET_CLASS_ZEC,
            asset_uuid: [0u8; 64],
        }
    }
}

/// `(bundle_variant, value)` for a known-type VP delta entry.
pub type VPDeltaValue = (BundleVariant, ZatBalance);

/// Key for value pool delta entries for unknown bundle types.
/// `(bundleType, assetClass, assetUuid)` — all raw wire values.
pub type UnknownVPDeltaKey = (u64, u8, [u8; 64]);
/// `(bundleVariant, value)` — raw wire values.
pub type UnknownVPDeltaValue = (u64, ZatBalance);

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
    /// Returns an empty value pool delta map.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns true if there are no entries.
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

    fn get_zec(&self, bundle_type: BundleType) -> Option<ZatBalance> {
        self.known
            .get(&ValuePoolDeltaKey::zec(bundle_type))
            .map(|&(_, v)| v)
    }

    fn set_zec(&mut self, bundle_type: BundleType, variant: BundleVariant, value: ZatBalance) {
        if value != ZatBalance::zero() {
            self.known
                .insert(ValuePoolDeltaKey::zec(bundle_type), (variant, value));
        } else {
            self.known.remove(&ValuePoolDeltaKey::zec(bundle_type));
        }
    }

    /// Returns the transparent bundle's ZEC value pool delta.
    pub fn transparent_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::Transparent)
    }

    /// Sets the transparent bundle's ZEC value pool delta.
    pub fn set_transparent(&mut self, value: ZatBalance) {
        self.set_zec(BundleType::Transparent, BundleVariant::Default, value);
    }

    /// Returns the coinbase bundle's ZEC value pool delta: the block subsidy
    /// less the part of it deposited into the lockbox.
    pub fn coinbase_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::Coinbase)
    }

    /// Sets the coinbase bundle's ZEC value pool delta.
    pub fn set_coinbase(&mut self, value: ZatBalance) {
        self.set_zec(BundleType::Coinbase, BundleVariant::Default, value);
    }

    /// Returns the Sapling bundle's ZEC value pool delta.
    pub fn sapling_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::Sapling)
    }

    /// Sets the Sapling bundle's ZEC value pool delta.
    pub fn set_sapling(&mut self, value: ZatBalance) {
        self.set_zec(BundleType::Sapling, BundleVariant::Default, value);
    }

    /// Returns the Orchard bundle's ZEC value pool delta.
    pub fn orchard_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::Orchard)
    }

    /// Sets the Orchard bundle's ZEC value pool delta.
    pub fn set_orchard(&mut self, value: ZatBalance) {
        self.set_zec(BundleType::Orchard, BundleVariant::Default, value);
    }

    /// Returns the transaction fee as a non-negative amount.
    pub fn fee(&self) -> Option<Zatoshis> {
        self.get_zec(BundleType::Fee).and_then(|v| {
            let abs = i64::from(v)
                .checked_neg()
                .and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    /// Sets the transaction fee (stored as a negative delta).
    pub fn set_fee(&mut self, value: Zatoshis) {
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        let bal = ZatBalance::from_i64(-pos).expect("negated fee is valid ZatBalance");
        self.set_zec(BundleType::Fee, BundleVariant::Default, bal);
    }

    /// Returns the ZIP 233 NSM amount as a non-negative value.
    pub fn zip233_amount(&self) -> Option<Zatoshis> {
        self.get_zec(BundleType::Zip233Nsm).and_then(|v| {
            let abs = i64::from(v)
                .checked_neg()
                .and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    /// Sets the ZIP 233 NSM delta (stored as a negative value).
    pub fn set_zip233(&mut self, value: Zatoshis) {
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        let bal = ZatBalance::from_i64(-pos).expect("negated ZIP 233 amount is valid ZatBalance");
        self.set_zec(BundleType::Zip233Nsm, BundleVariant::Default, bal);
    }

    /// Insert a known-type entry. Used during v7 deserialization.
    pub fn insert_known(
        &mut self,
        key: ValuePoolDeltaKey,
        variant: BundleVariant,
        value: ZatBalance,
    ) {
        self.known.insert(key, (variant, value));
    }

    /// Insert an unknown-type entry. Used during v7 deserialization.
    pub fn insert_unknown(
        &mut self,
        bundle_type: u64,
        asset_class: u8,
        asset_uuid: [u8; 64],
        variant: u64,
        value: ZatBalance,
    ) {
        self.unknown
            .insert((bundle_type, asset_class, asset_uuid), (variant, value));
    }

    /// Produce all VP delta entries (known and unknown) in canonical wire
    /// order, sorted by `(bundleType, assetClass, assetUuid)`.
    pub fn to_wire_entries(&self) -> Vec<ValuePoolDeltaEntry> {
        let known = self
            .known
            .iter()
            .map(|(k, &(variant, v))| ValuePoolDeltaEntry {
                bundle_type: k.bundle_type.to_u64(),
                bundle_variant: variant.to_u64(),
                asset_class: k.asset_class,
                asset_uuid: if k.asset_class == ASSET_CLASS_ZEC {
                    None
                } else {
                    Some(k.asset_uuid)
                },
                value: v,
            });
        let unknown = self
            .unknown
            .iter()
            .map(|(&(bt, ac, uuid), &(bv, v))| ValuePoolDeltaEntry {
                bundle_type: bt,
                bundle_variant: bv,
                asset_class: ac,
                asset_uuid: if ac == ASSET_CLASS_ZEC {
                    None
                } else {
                    Some(uuid)
                },
                value: v,
            });
        let mut all: Vec<_> = known.chain(unknown).collect();
        all.sort_by(|a, b| {
            (
                a.bundle_type,
                a.asset_class,
                a.asset_uuid.unwrap_or([0u8; 64]),
            )
                .cmp(&(
                    b.bundle_type,
                    b.asset_class,
                    b.asset_uuid.unwrap_or([0u8; 64]),
                ))
        });
        all
    }
}

// ---------------------------------------------------------------------------
// v7 wire format helpers
// ---------------------------------------------------------------------------

/// A single value pool delta entry as it appears on the wire.
///
/// Uses raw `u64` for type/variant since the wire may contain values for
/// bundle types not recognized by this implementation.
#[derive(Clone, Debug)]
pub struct ValuePoolDeltaEntry {
    /// Bundle type as a raw wire value (may be unrecognized).
    pub bundle_type: u64,
    /// Bundle variant as a raw wire value.
    pub bundle_variant: u64,
    /// Asset class: 0 for ZEC, 1 for other assets.
    pub asset_class: u8,
    /// 64-byte asset UUID, present only when `asset_class != 0`.
    pub asset_uuid: Option<[u8; 64]>,
    /// The signed value-pool delta for this entry.
    pub value: ZatBalance,
}

impl ValuePoolDeltaEntry {
    /// Deserializes a value pool delta entry from the wire format.
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
        let raw = i64::from_le_bytes(value_buf);
        if raw == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ValuePoolDelta value must be nonzero",
            ));
        }
        let value = ZatBalance::from_i64(raw).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ValuePoolDelta value out of valid monetary range",
            )
        })?;
        Ok(Self {
            bundle_type,
            bundle_variant,
            asset_class,
            asset_uuid,
            value,
        })
    }

    /// Serializes this entry in the wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type as usize)?;
        CompactSize::write(&mut writer, self.bundle_variant as usize)?;
        writer.write_all(&[self.asset_class])?;
        if let Some(ref uuid) = self.asset_uuid {
            writer.write_all(uuid)?;
        }
        writer.write_all(&i64::from(self.value).to_le_bytes())?;
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

/// Returns the 16-byte BLAKE2b personalization for the opaque effects digest
/// of a bundle with the given type and variant.
/// [ZIP 248 §T.3](https://zips.z.cash/zip-0248#t-3-effects-bundles-digest)
///
/// Layout: `"ZTxIdT" (6) | bundleType (4-byte LE) | 0x56 (1) | bundleVariant (1) | "Hash" (4)`
///
/// This is used for bundle types not understood by the wallet, allowing the
/// txid to be computed by flat-hashing the raw `vBundleData` bytes.
pub fn opaque_effects_personalization(bundle_type: u64, bundle_variant: u64) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..6].copy_from_slice(b"ZTxIdT");
    p[6..10].copy_from_slice(&(bundle_type as u32).to_le_bytes());
    p[10] = b'V';
    p[11] = bundle_variant as u8;
    p[12..16].copy_from_slice(b"Hash");
    p
}

/// Reads and validates a sighash version 0 `sighashInfo` prefix.
/// [ZIP 248 §Sighash Versioning](https://zips.z.cash/zip-0248#sighash-versioning)
///
/// Sighash version 0 encodes as `[0x01, 0x00]` on the wire: compactSize(1) for the
/// info length, then `0x00` for the version byte. This is the only defined version.
#[cfg(zcash_v7)]
pub(crate) fn consume_v7_sighash_v0_info<R: Read>(
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
                info_len,
                _context,
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
                version[0],
                _context,
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transparent v7 effect/auth helpers
// ---------------------------------------------------------------------------

/// Writes transparent effecting data in v7 format.
/// [ZIP 248 §Transparent Effecting Data](https://zips.z.cash/zip-0248#transparent-effecting-data)
///
/// Layout: tx_in_count, TransparentInputEffecting[tx_in_count] (prevout 36 + nSequence 4),
///         tx_out_count, TransparentOutput[tx_out_count] (value 8 + scriptPubKey).
pub fn write_v7_transparent_effects<W: Write>(
    mut writer: W,
    bundle: &transparent::Bundle<transparent::Authorized>,
) -> io::Result<()> {
    CompactSize::write(&mut writer, bundle.vin.len())?;
    for txin in &bundle.vin {
        txin.prevout().write(&mut writer)?;
        writer.write_all(&txin.sequence().to_le_bytes())?;
    }

    CompactSize::write(&mut writer, bundle.vout.len())?;
    for txout in &bundle.vout {
        txout.write(&mut writer)?;
    }

    Ok(())
}

/// Writes transparent authorizing data in v7 format.
/// [ZIP 248 §Transparent Authorizing Data](https://zips.z.cash/zip-0248#transparent-authorizing-data)
///
/// Layout: per-input TransparentInputAuth (sighashInfo + scriptSig).
pub fn write_v7_transparent_auth<W: Write>(
    mut writer: W,
    bundle: &transparent::Bundle<transparent::Authorized>,
) -> io::Result<()> {
    for txin in &bundle.vin {
        // sighashInfo: version 0
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

        vp.set_fee(Zatoshis::from_u64(1000).unwrap());
        assert!(!vp.is_empty());
        assert_eq!(vp.fee(), Some(Zatoshis::from_u64(1000).unwrap()));

        vp.set_zip233(Zatoshis::from_u64(5000).unwrap());
        assert_eq!(vp.zip233_amount(), Some(Zatoshis::from_u64(5000).unwrap()));

        let sap_vb = ZatBalance::from_i64(100_000).unwrap();
        vp.set_sapling(sap_vb);
        assert_eq!(vp.sapling_value(), Some(sap_vb));

        // Iteration order should be by bundle type
        let types: Vec<BundleType> = vp.iter().map(|(k, _)| k.bundle_type).collect();
        assert_eq!(
            types,
            vec![BundleType::Sapling, BundleType::Fee, BundleType::Zip233Nsm,]
        );
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
            value: ZatBalance::from_i64(-50000).unwrap(),
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
        map.insert_unknown(
            99,
            0,
            UnknownBundle {
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
            },
        );

        assert!(!map.is_empty());
        let unknowns: Vec<_> = map.unknown_bundles().collect();
        assert_eq!(unknowns.len(), 1);
        assert_eq!(unknowns[0].0, &(99u64, 0u64));
        assert_eq!(unknowns[0].1.effect_data, vec![1, 2, 3]);
    }
}
