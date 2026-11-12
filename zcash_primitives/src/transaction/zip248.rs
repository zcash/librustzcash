//! ZIP 248: Extensible Transaction Format types.
//!
//! Typed transactions hold each protocol bundle in its own field; there is no
//! all-typed bundle map. A bundle whose type or variant this implementation
//! does not interpret has no typed representation and is handled by the byte
//! layer.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use corez::io::{self, Read, Write};

#[cfg(zcash_unstable = "nu8")]
use ::transparent::bundle as transparent;
use zcash_encoding::{CompactSize, MAX_COMPACT_SIZE};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::constants::MAX_BLOCK_BYTES;
use zcash_protocol::value::{ZatBalance, Zatoshis};

// ---------------------------------------------------------------------------
// Bundle type and variant identifiers
// ---------------------------------------------------------------------------

/// A bundle type identifier from the V7 Transaction Bundle Type Registry.
///
/// The registry is open: future ZIPs may assign identifiers this implementation
/// does not understand. The raw wire value is therefore retained rather than
/// represented by a closed enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BundleType(u64);

impl From<u64> for BundleType {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl BundleType {
    /// Transparent inputs and outputs (bundleType 0).
    pub const TRANSPARENT: Self = Self(0);
    /// Coinbase issuance and metadata (bundleType 1). No authorizing data.
    pub const COINBASE: Self = Self(1);
    /// Sapling spends and outputs (bundleType 2).
    pub const SAPLING: Self = Self(2);
    /// Orchard actions acting on the *Orchard pool* (bundleType 3).
    pub const ORCHARD: Self = Self(3);
    /// Orchard actions acting on the *Ironwood pool* (bundleType 4).
    pub const IRONWOOD: Self = Self(4);
    /// Transaction fee, value-only (bundleType 5, ZIP 2002).
    pub const FEE: Self = Self(5);
    /// ZIP 233 NSM field, value-only (bundleType 6, ZIP 233).
    pub const ZIP233_NSM: Self = Self(6);

    /// Constructs a bundle type from its raw wire value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw wire value.
    pub const fn to_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` if this implementation recognizes the bundle type.
    pub const fn is_known(self) -> bool {
        self.0 <= Self::ZIP233_NSM.0
    }
}

/// A bundle variant identifier from the V7 Transaction Bundle Type Registry.
///
/// The registry is open: future ZIPs may assign variants this implementation
/// does not understand. The raw wire value is therefore retained rather than
/// represented by a closed enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BundleVariant(u64);

impl From<u64> for BundleVariant {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl BundleVariant {
    /// The default (and currently only assigned) variant for all bundle types.
    pub const DEFAULT: Self = Self(0);

    /// Constructs a bundle variant from its raw wire value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw wire value.
    pub const fn to_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` if this implementation recognizes the bundle variant.
    pub const fn is_known(self) -> bool {
        self.0 == Self::DEFAULT.0
    }
}

/// Asset class byte for ZEC.
pub const ASSET_CLASS_ZEC: u8 = 0x00;
/// Asset class byte for non-ZEC assets.
pub const ASSET_CLASS_OTHER: u8 = 0x01;

/// The registry columns for a registered V7 bundle type.
///
/// Each column records whether an entry for the bundle type may appear in the
/// corresponding transaction map. A `reserved` row may not appear in any map.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BundleRegistryRow {
    pub(crate) value_pool_deltas: bool,
    pub(crate) effect_bundles: bool,
    pub(crate) auth_bundles: bool,
    pub(crate) reserved: bool,
}

/// Returns the V7 registry row for `bundle_type`, or `None` if the type is not
/// registered for V7.
///
/// No row in the registry is marked Reserved at this revision.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn bundle_registry_row(bundle_type: BundleType) -> Option<BundleRegistryRow> {
    let row = |value_pool_deltas, effect_bundles, auth_bundles| BundleRegistryRow {
        value_pool_deltas,
        effect_bundles,
        auth_bundles,
        reserved: false,
    };
    match bundle_type {
        BundleType::TRANSPARENT => Some(row(true, true, true)),
        BundleType::COINBASE => Some(row(true, true, false)),
        BundleType::SAPLING => Some(row(true, true, true)),
        BundleType::ORCHARD => Some(row(true, true, true)),
        BundleType::IRONWOOD => Some(row(true, true, true)),
        BundleType::FEE => Some(row(true, false, false)),
        BundleType::ZIP233_NSM => Some(row(true, false, false)),
        _ => None,
    }
}

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
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
}

impl BundleId {
    /// Constructs a BundleId from its type and variant.
    pub const fn new(bundle_type: BundleType, bundle_variant: BundleVariant) -> Self {
        Self {
            bundle_type,
            bundle_variant,
        }
    }

    /// Returns the protocol-level bundle type.
    pub const fn bundle_type(&self) -> BundleType {
        self.bundle_type
    }

    /// Returns the variant within the bundle type.
    pub const fn bundle_variant(&self) -> BundleVariant {
        self.bundle_variant
    }

    /// Returns `(bundleType, bundleVariant)` as raw `u64` values for wire encoding.
    pub const fn wire_key(&self) -> (u64, u64) {
        (self.bundle_type.to_u64(), self.bundle_variant.to_u64())
    }
}

// ---------------------------------------------------------------------------
// Bundle digest resolution
// ---------------------------------------------------------------------------

/// A source of canonical per-bundle digests for bundles the byte layer does not
/// interpret.
///
/// Effecting and authorizing digests are resolved independently: a bundle may
/// have an effecting digest without authorizing data, and a caller may know one
/// digest without the other. The provider is consulted only for bundles whose
/// payload the byte layer cannot digest itself.
///
/// The provider is trusted. The byte layer cannot verify a digest for a bundle
/// it does not interpret, so a transaction identifier computed from supplied
/// digests is only as trustworthy as the source that supplied them. A caller
/// that accepts such a transaction must obtain the digests from a source it
/// trusts, or verify the bundle independently.
#[cfg(zcash_unstable = "nu8")]
pub trait BundleDigestProvider {
    /// Returns the canonical effecting-data digest for `key`, if supplied.
    fn effects_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash>;

    /// Returns the canonical authorizing-data digest for `key`, if supplied.
    fn auth_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash>;
}

/// A [`BundleDigestProvider`] backed by explicit per-key digests.
///
/// Insertion rejects a second digest for the same key, and rejects a digest
/// that conflicts with one already present. A digest supplied for a key that
/// the transaction does not need is not an error at insertion time; use
/// [`Self::validate_for`] to reject such keys.
///
/// The supplied digests are trusted: see [`BundleDigestProvider`].
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, Default)]
pub struct SuppliedBundleDigests {
    effects: BTreeMap<BundleId, blake2b_simd::Hash>,
    auth: BTreeMap<BundleId, blake2b_simd::Hash>,
}

#[cfg(zcash_unstable = "nu8")]
impl SuppliedBundleDigests {
    /// Constructs an empty set of supplied digests.
    pub fn new() -> Self {
        Self::default()
    }

    /// Supplies the effecting-data digest for `key`.
    ///
    /// Returns [`V7DigestError::DuplicateEffectsDigest`] if a digest for `key`
    /// is already present, or [`V7DigestError::ConflictingEffectsDigest`] if it
    /// differs from the one already present.
    pub fn insert_effects(
        &mut self,
        key: BundleId,
        digest: blake2b_simd::Hash,
    ) -> Result<(), V7DigestError> {
        match self.effects.get(&key) {
            Some(existing) if existing == &digest => {
                Err(V7DigestError::DuplicateEffectsDigest { key })
            }
            Some(_) => Err(V7DigestError::ConflictingEffectsDigest { key }),
            None => {
                self.effects.insert(key, digest);
                Ok(())
            }
        }
    }

    /// Supplies the authorizing-data digest for `key`.
    ///
    /// Returns [`V7DigestError::DuplicateAuthDigest`] if a digest for `key` is
    /// already present, or [`V7DigestError::ConflictingAuthDigest`] if it
    /// differs from the one already present.
    pub fn insert_auth(
        &mut self,
        key: BundleId,
        digest: blake2b_simd::Hash,
    ) -> Result<(), V7DigestError> {
        match self.auth.get(&key) {
            Some(existing) if existing == &digest => {
                Err(V7DigestError::DuplicateAuthDigest { key })
            }
            Some(_) => Err(V7DigestError::ConflictingAuthDigest { key }),
            None => {
                self.auth.insert(key, digest);
                Ok(())
            }
        }
    }

    /// Returns the supplied effecting-data digest for `key`, if any.
    pub fn get_effects(&self, key: BundleId) -> Option<&blake2b_simd::Hash> {
        self.effects.get(&key)
    }

    /// Returns the supplied authorizing-data digest for `key`, if any.
    pub fn get_auth(&self, key: BundleId) -> Option<&blake2b_simd::Hash> {
        self.auth.get(&key)
    }

    /// Checks that the supplied digests exactly cover the required keys.
    ///
    /// `needed_effects` and `needed_auth` are the keys for which the caller
    /// requires a digest. Every supplied digest must be required, and every
    /// required key must have a supplied digest.
    pub fn validate_for<'a>(
        &self,
        needed_effects: impl IntoIterator<Item = &'a BundleId>,
        needed_auth: impl IntoIterator<Item = &'a BundleId>,
    ) -> Result<(), V7DigestError> {
        let needed_effects: alloc::collections::BTreeSet<BundleId> =
            needed_effects.into_iter().copied().collect();
        let needed_auth: alloc::collections::BTreeSet<BundleId> =
            needed_auth.into_iter().copied().collect();

        for &key in self.effects.keys() {
            if !needed_effects.contains(&key) {
                return Err(V7DigestError::UnexpectedEffectsDigest { key });
            }
        }
        for &key in self.auth.keys() {
            if !needed_auth.contains(&key) {
                return Err(V7DigestError::UnexpectedAuthDigest { key });
            }
        }
        for &key in &needed_effects {
            if !self.effects.contains_key(&key) {
                return Err(V7DigestError::MissingEffectsDigest { key });
            }
        }
        for &key in &needed_auth {
            if !self.auth.contains_key(&key) {
                return Err(V7DigestError::MissingAuthDigest { key });
            }
        }
        Ok(())
    }
}

#[cfg(zcash_unstable = "nu8")]
impl BundleDigestProvider for SuppliedBundleDigests {
    fn effects_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash> {
        self.effects.get(&key).cloned()
    }

    fn auth_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash> {
        self.auth.get(&key).cloned()
    }
}

/// An error resolving the per-bundle digests of a version 7 transaction.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V7DigestError {
    /// The transaction is not a version 7 transaction.
    NotV7,
    /// The encoded consensus branch ID is not a recognized [`BranchId`].
    ///
    /// [`BranchId`]: zcash_protocol::consensus::BranchId
    UnrecognizedBranchId {
        /// The raw `nConsensusBranchId` value.
        branch_id: u32,
    },
    /// No effecting-data digest was supplied for an unsupported bundle.
    MissingEffectsDigest {
        /// The bundle whose digest is missing.
        key: BundleId,
    },
    /// No authorizing-data digest was supplied for an unsupported bundle that
    /// has authorizing data.
    MissingAuthDigest {
        /// The bundle whose digest is missing.
        key: BundleId,
    },
    /// A Sapling bundle has spends but no anchor, so its effecting-data digest
    /// cannot be computed.
    ///
    /// An effects-only bundle parsed without its authorizing data omits the
    /// anchor, but the non-compact Sapling spends digest must hash the anchor
    /// once per spend.
    MissingSaplingAnchor,
    /// An effecting-data digest was supplied more than once for the same key.
    DuplicateEffectsDigest {
        /// The duplicated key.
        key: BundleId,
    },
    /// An authorizing-data digest was supplied more than once for the same key.
    DuplicateAuthDigest {
        /// The duplicated key.
        key: BundleId,
    },
    /// Two different effecting-data digests were supplied for the same key.
    ConflictingEffectsDigest {
        /// The conflicting key.
        key: BundleId,
    },
    /// Two different authorizing-data digests were supplied for the same key.
    ConflictingAuthDigest {
        /// The conflicting key.
        key: BundleId,
    },
    /// An effecting-data digest was supplied for a key the transaction does not
    /// need.
    UnexpectedEffectsDigest {
        /// The unexpected key.
        key: BundleId,
    },
    /// An authorizing-data digest was supplied for a key the transaction does
    /// not need.
    UnexpectedAuthDigest {
        /// The unexpected key.
        key: BundleId,
    },
}

#[cfg(zcash_unstable = "nu8")]
impl fmt::Display for V7DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotV7 => f.write_str("transaction is not a version 7 transaction"),
            Self::UnrecognizedBranchId { branch_id } => {
                write!(f, "unrecognized consensus branch ID {branch_id:#010x}")
            }
            Self::MissingEffectsDigest { key } => write!(
                f,
                "no effecting-data digest supplied for bundle ({}, {})",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
            Self::MissingAuthDigest { key } => write!(
                f,
                "no authorizing-data digest supplied for bundle ({}, {})",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
            Self::MissingSaplingAnchor => f.write_str("Sapling bundle with spends has no anchor"),
            Self::DuplicateEffectsDigest { key } => write!(
                f,
                "duplicate effecting-data digest for bundle ({}, {})",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
            Self::DuplicateAuthDigest { key } => write!(
                f,
                "duplicate authorizing-data digest for bundle ({}, {})",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
            Self::ConflictingEffectsDigest { key } => write!(
                f,
                "conflicting effecting-data digests for bundle ({}, {})",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
            Self::ConflictingAuthDigest { key } => write!(
                f,
                "conflicting authorizing-data digests for bundle ({}, {})",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
            Self::UnexpectedEffectsDigest { key } => write!(
                f,
                "effecting-data digest supplied for bundle ({}, {}), which the transaction does not need",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
            Self::UnexpectedAuthDigest { key } => write!(
                f,
                "authorizing-data digest supplied for bundle ({}, {}), which the transaction does not need",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
        }
    }
}

#[cfg(all(feature = "std", zcash_unstable = "nu8"))]
impl std::error::Error for V7DigestError {}

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
pub(crate) const MAX_COINBASE_BLOCK_HEIGHT: u32 = 499_999_999;

/// The largest permitted `nExpiryHeight` value.
#[cfg(zcash_unstable = "nu8")]
pub(crate) const MAX_EXPIRY_HEIGHT: u32 = 499_999_999;

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
    block_height: BlockHeight,
    block_subsidy: Zatoshis,
    lockbox_value: Zatoshis,
    coinbase_data: Vec<u8>,
}

impl CoinbaseBundle {
    /// Constructs a coinbase bundle, returning `None` if any of the field
    /// constraints in ZIP 248 §"Coinbase Effecting Data" is violated.
    pub fn from_parts(
        block_height: BlockHeight,
        block_subsidy: Zatoshis,
        lockbox_value: Zatoshis,
        coinbase_data: Vec<u8>,
    ) -> Option<Self> {
        let height = u32::from(block_height);
        if height == 0
            || height > MAX_COINBASE_BLOCK_HEIGHT
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
    pub fn block_height(&self) -> BlockHeight {
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
        let block_height = BlockHeight::from(u32::from_le_bytes(u32_buf));

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
        writer.write_all(&u32::from(self.block_height).to_le_bytes())?;
        writer.write_all(&u64::from(self.block_subsidy).to_le_bytes())?;
        writer.write_all(&u64::from(self.lockbox_value).to_le_bytes())?;
        CompactSize::write(&mut writer, self.coinbase_data.len())?;
        writer.write_all(&self.coinbase_data)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ValuePoolDeltas
// ---------------------------------------------------------------------------

/// An error constructing or inserting a value pool delta entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValuePoolDeltaError {
    /// `assetClass` is not `0` (ZEC) or `1` (other).
    InvalidAssetClass(u8),
    /// A ZEC entry has a nonzero asset UUID, or a non-ZEC entry has no UUID.
    AssetUuidMismatch {
        /// The offending asset class.
        asset_class: u8,
    },
    /// A value pool delta must be nonzero.
    ZeroValue,
    /// A raw `bundleType` or `bundleVariant` has no `compactSize` encoding.
    WireKey(WireKeyError),
    /// The entry duplicates an existing wire key.
    DuplicateEntry,
    /// The bundle type already has an entry with a different variant.
    VariantMismatch {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
}

impl fmt::Display for ValuePoolDeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAssetClass(asset_class) => {
                write!(f, "assetClass must be 0 or 1, got {asset_class:#x}")
            }
            Self::AssetUuidMismatch { asset_class } => write!(
                f,
                "asset UUID is inconsistent with assetClass {asset_class:#x}"
            ),
            Self::ZeroValue => f.write_str("a value pool delta must be nonzero"),
            Self::WireKey(error) => write!(f, "{error}"),
            Self::DuplicateEntry => f.write_str("duplicate value pool delta entry"),
            Self::VariantMismatch { bundle_type } => write!(
                f,
                "bundleType {bundle_type} has entries with different bundleVariants"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValuePoolDeltaError {}

/// Key for value pool delta entries.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ValuePoolDeltaKey {
    bundle_type: BundleType,
    asset_class: u8,
    asset_uuid: [u8; 64],
}

impl ValuePoolDeltaKey {
    /// Constructs a key from its bundle type and asset.
    ///
    /// `asset_class` is `0` for ZEC, in which case `asset_uuid` must be all
    /// zeros, or `1` for another asset, identified by its 64-byte UUID.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::InvalidAssetClass`] for an asset class
    /// other than 0 or 1, or [`ValuePoolDeltaError::AssetUuidMismatch`] if a
    /// ZEC key has a nonzero UUID.
    pub fn from_parts(
        bundle_type: BundleType,
        asset_class: u8,
        asset_uuid: [u8; 64],
    ) -> Result<Self, ValuePoolDeltaError> {
        match asset_class {
            ASSET_CLASS_ZEC if asset_uuid != [0u8; 64] => {
                Err(ValuePoolDeltaError::AssetUuidMismatch { asset_class })
            }
            ASSET_CLASS_ZEC | ASSET_CLASS_OTHER => Ok(Self {
                bundle_type,
                asset_class,
                asset_uuid,
            }),
            other => Err(ValuePoolDeltaError::InvalidAssetClass(other)),
        }
    }

    /// Creates a key for a ZEC delta of the given bundle type.
    pub const fn zec(bundle_type: BundleType) -> Self {
        Self {
            bundle_type,
            asset_class: ASSET_CLASS_ZEC,
            asset_uuid: [0u8; 64],
        }
    }

    /// Returns the bundle type this delta belongs to.
    pub const fn bundle_type(&self) -> BundleType {
        self.bundle_type
    }

    /// Returns the asset class: `0` for ZEC, `1` for another asset.
    pub const fn asset_class(&self) -> u8 {
        self.asset_class
    }

    /// Returns the 64-byte asset UUID, or all zeros for ZEC.
    pub const fn asset_uuid(&self) -> &[u8; 64] {
        &self.asset_uuid
    }
}

/// `(bundle_variant, value)` for a value pool delta entry.
pub type VPDeltaValue = (BundleVariant, ZatBalance);

/// The value pool delta map from ZIP 248.
///
/// The map is keyed by the raw bundle type and asset identifier, so entries for
/// bundle types or variants this implementation does not understand are
/// retained without a separate opaque map.
#[derive(Clone, Debug, Default)]
pub struct ValuePoolDeltas {
    entries: BTreeMap<ValuePoolDeltaKey, VPDeltaValue>,
}

impl ValuePoolDeltas {
    /// Returns an empty value pool delta map.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns true if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over entries in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValuePoolDeltaKey, &VPDeltaValue)> {
        self.entries.iter()
    }

    /// Returns the bundle variant for a given bundle type, if present.
    pub fn bundle_variant(&self, bundle_type: BundleType) -> Option<BundleVariant> {
        self.entries
            .iter()
            .find(|(key, _)| key.bundle_type() == bundle_type)
            .map(|(_, &(variant, _))| variant)
    }

    fn get_zec(&self, bundle_type: BundleType) -> Option<ZatBalance> {
        self.entries
            .get(&ValuePoolDeltaKey::zec(bundle_type))
            .map(|&(_, value)| value)
    }

    /// Replaces the ZEC entry for `bundle_type`, rejecting a variant conflict
    /// with any existing entry for that bundle type before mutating the map.
    fn set_zec(
        &mut self,
        bundle_type: BundleType,
        value: ZatBalance,
    ) -> Result<(), ValuePoolDeltaError> {
        self.check_variant(bundle_type, BundleVariant::DEFAULT)?;
        let key = ValuePoolDeltaKey::zec(bundle_type);
        if value == ZatBalance::zero() {
            self.entries.remove(&key);
        } else {
            self.entries.insert(key, (BundleVariant::DEFAULT, value));
        }
        Ok(())
    }

    /// Returns the transparent bundle's ZEC value pool delta.
    pub fn transparent_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::TRANSPARENT)
    }

    /// Sets the transparent bundle's ZEC value pool delta.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::VariantMismatch`] if the map already has
    /// an entry for the transparent bundle type with a different variant. The
    /// map is unchanged in that case.
    pub fn set_transparent(&mut self, value: ZatBalance) -> Result<(), ValuePoolDeltaError> {
        self.set_zec(BundleType::TRANSPARENT, value)
    }

    /// Returns the coinbase bundle's ZEC value pool delta: the block subsidy
    /// less the part of it deposited into the lockbox.
    pub fn coinbase_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::COINBASE)
    }

    /// Sets the coinbase bundle's ZEC value pool delta.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::VariantMismatch`] if the map already has
    /// an entry for the coinbase bundle type with a different variant. The map
    /// is unchanged in that case.
    pub fn set_coinbase(&mut self, value: ZatBalance) -> Result<(), ValuePoolDeltaError> {
        self.set_zec(BundleType::COINBASE, value)
    }

    /// Returns the Sapling bundle's ZEC value pool delta.
    pub fn sapling_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::SAPLING)
    }

    /// Sets the Sapling bundle's ZEC value pool delta.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::VariantMismatch`] if the map already has
    /// an entry for the Sapling bundle type with a different variant. The map
    /// is unchanged in that case.
    pub fn set_sapling(&mut self, value: ZatBalance) -> Result<(), ValuePoolDeltaError> {
        self.set_zec(BundleType::SAPLING, value)
    }

    /// Returns the Orchard bundle's ZEC value pool delta.
    pub fn orchard_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::ORCHARD)
    }

    /// Sets the Orchard bundle's ZEC value pool delta.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::VariantMismatch`] if the map already has
    /// an entry for the Orchard bundle type with a different variant. The map
    /// is unchanged in that case.
    pub fn set_orchard(&mut self, value: ZatBalance) -> Result<(), ValuePoolDeltaError> {
        self.set_zec(BundleType::ORCHARD, value)
    }

    /// Returns the Ironwood bundle's ZEC value pool delta.
    pub fn ironwood_value(&self) -> Option<ZatBalance> {
        self.get_zec(BundleType::IRONWOOD)
    }

    /// Sets the Ironwood bundle's ZEC value pool delta.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::VariantMismatch`] if the map already has
    /// an entry for the Ironwood bundle type with a different variant. The map
    /// is unchanged in that case.
    pub fn set_ironwood(&mut self, value: ZatBalance) -> Result<(), ValuePoolDeltaError> {
        self.set_zec(BundleType::IRONWOOD, value)
    }

    /// Returns the transaction fee as a non-negative amount.
    pub fn fee(&self) -> Option<Zatoshis> {
        self.get_zec(BundleType::FEE).and_then(|value| {
            let abs = i64::from(value)
                .checked_neg()
                .and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    /// Sets the transaction fee (stored as a negative delta).
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::VariantMismatch`] if the map already has
    /// an entry for the fee bundle type with a different variant. The map is
    /// unchanged in that case.
    pub fn set_fee(&mut self, value: Zatoshis) -> Result<(), ValuePoolDeltaError> {
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        let bal = ZatBalance::from_i64(-pos).expect("negated fee is valid ZatBalance");
        self.set_zec(BundleType::FEE, bal)
    }

    /// Returns the ZIP 233 NSM amount as a non-negative value.
    pub fn zip233_amount(&self) -> Option<Zatoshis> {
        self.get_zec(BundleType::ZIP233_NSM).and_then(|value| {
            let abs = i64::from(value)
                .checked_neg()
                .and_then(|n| u64::try_from(n).ok())?;
            Zatoshis::from_u64(abs).ok()
        })
    }

    /// Sets the ZIP 233 NSM delta (stored as a negative value).
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::VariantMismatch`] if the map already has
    /// an entry for the ZIP 233 NSM bundle type with a different variant. The
    /// map is unchanged in that case.
    pub fn set_zip233(&mut self, value: Zatoshis) -> Result<(), ValuePoolDeltaError> {
        let pos = i64::try_from(u64::from(value)).expect("MAX_MONEY fits in i64");
        let bal = ZatBalance::from_i64(-pos).expect("negated ZIP 233 amount is valid ZatBalance");
        self.set_zec(BundleType::ZIP233_NSM, bal)
    }

    /// Inserts a value pool delta entry.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::ZeroValue`] for a zero value,
    /// [`ValuePoolDeltaError::DuplicateEntry`] if the wire key is already
    /// present, or [`ValuePoolDeltaError::VariantMismatch`] if the bundle type
    /// already has an entry with a different variant.
    pub fn insert(
        &mut self,
        key: ValuePoolDeltaKey,
        variant: BundleVariant,
        value: ZatBalance,
    ) -> Result<(), ValuePoolDeltaError> {
        if value == ZatBalance::zero() {
            return Err(ValuePoolDeltaError::ZeroValue);
        }
        if self.entries.contains_key(&key) {
            return Err(ValuePoolDeltaError::DuplicateEntry);
        }
        self.check_variant(key.bundle_type(), variant)?;
        self.entries.insert(key, (variant, value));
        Ok(())
    }

    /// Checks that `bundle_type` has no entry with a different variant.
    fn check_variant(
        &self,
        bundle_type: BundleType,
        variant: BundleVariant,
    ) -> Result<(), ValuePoolDeltaError> {
        for (key, &(existing, _)) in &self.entries {
            if key.bundle_type() == bundle_type && existing != variant {
                return Err(ValuePoolDeltaError::VariantMismatch {
                    bundle_type: bundle_type.to_u64(),
                });
            }
        }
        Ok(())
    }

    /// Produces all value pool delta entries in canonical wire order, sorted by
    /// `(bundleType, assetClass, assetUuid)`.
    pub fn to_wire_entries(&self) -> Vec<ValuePoolDeltaEntry> {
        self.entries
            .iter()
            .map(|(key, &(variant, value))| {
                ValuePoolDeltaEntry::from_parts(
                    key.bundle_type(),
                    variant,
                    key.asset_class(),
                    if key.asset_class() == ASSET_CLASS_ZEC {
                        None
                    } else {
                        Some(*key.asset_uuid())
                    },
                    value,
                )
                .expect("value pool delta map invariants hold")
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// v7 wire format helpers
// ---------------------------------------------------------------------------

/// A single value pool delta entry as it appears on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValuePoolDeltaEntry {
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    asset_class: u8,
    asset_uuid: Option<[u8; 64]>,
    value: ZatBalance,
}

impl ValuePoolDeltaEntry {
    /// Constructs a value pool delta entry from its wire fields.
    ///
    /// `asset_uuid` must be present exactly when `asset_class` is
    /// [`ASSET_CLASS_OTHER`], and the value must be nonzero.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::WireKey`] if a raw identifier has no
    /// `compactSize` encoding, [`ValuePoolDeltaError::InvalidAssetClass`] for
    /// an asset class other than 0 or 1,
    /// [`ValuePoolDeltaError::AssetUuidMismatch`] if the UUID presence does
    /// not match the asset class, or [`ValuePoolDeltaError::ZeroValue`] for a
    /// zero value.
    pub fn from_parts(
        bundle_type: BundleType,
        bundle_variant: BundleVariant,
        asset_class: u8,
        asset_uuid: Option<[u8; 64]>,
        value: ZatBalance,
    ) -> Result<Self, ValuePoolDeltaError> {
        check_wire_key(bundle_type, bundle_variant).map_err(ValuePoolDeltaError::WireKey)?;
        if value == ZatBalance::zero() {
            return Err(ValuePoolDeltaError::ZeroValue);
        }
        match (asset_class, asset_uuid) {
            (ASSET_CLASS_ZEC, None) | (ASSET_CLASS_OTHER, Some(_)) => {}
            (ASSET_CLASS_ZEC | ASSET_CLASS_OTHER, _) => {
                return Err(ValuePoolDeltaError::AssetUuidMismatch { asset_class });
            }
            (other, _) => return Err(ValuePoolDeltaError::InvalidAssetClass(other)),
        }
        Ok(Self {
            bundle_type,
            bundle_variant,
            asset_class,
            asset_uuid,
            value,
        })
    }

    /// Returns the raw `bundleType`.
    pub const fn bundle_type(&self) -> BundleType {
        self.bundle_type
    }

    /// Returns the raw `bundleVariant`.
    pub const fn bundle_variant(&self) -> BundleVariant {
        self.bundle_variant
    }

    /// Returns the asset class: `0` for ZEC, `1` for another asset.
    pub const fn asset_class(&self) -> u8 {
        self.asset_class
    }

    /// Returns the 64-byte asset UUID, present only for a non-ZEC asset.
    pub const fn asset_uuid(&self) -> Option<&[u8; 64]> {
        self.asset_uuid.as_ref()
    }

    /// Returns the signed value-pool delta.
    pub const fn value(&self) -> ZatBalance {
        self.value
    }

    /// Deserializes a value pool delta entry from the wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let bundle_type = BundleType::from_u64(CompactSize::read(&mut reader)?);
        let bundle_variant = BundleVariant::from_u64(CompactSize::read(&mut reader)?);
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
                    alloc::format!("ValuePoolDelta assetClass must be 0 or 1, got {_other:#x}"),
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
        Self::from_parts(bundle_type, bundle_variant, asset_class, asset_uuid, value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, alloc::format!("{error}")))
    }

    /// Serializes this entry in the wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type.to_u64() as usize)?;
        CompactSize::write(&mut writer, self.bundle_variant.to_u64() as usize)?;
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
    // The payload is allocated before it is read, so bound the claimed length
    // by something a transaction could actually contain: no bundle can exceed
    // the maximum block size.
    if data_len > MAX_BLOCK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "v7 bundle data length exceeds the maximum block size",
        ));
    }
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

/// A value pool delta entry read from the wire without narrowing its value to
/// the monetary domain.
///
/// The byte layer retains the raw signed 64-bit value so that out-of-domain
/// entries can be inspected and re-serialized; conversion to [`ZatBalance`]
/// happens only in the typed path.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawValuePoolDeltaEntry {
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    asset_class: u8,
    asset_uuid: Option<[u8; 64]>,
    value: i64,
}

#[cfg(zcash_unstable = "nu8")]
impl RawValuePoolDeltaEntry {
    /// Returns the raw `bundleType`.
    pub(crate) const fn bundle_type(&self) -> BundleType {
        self.bundle_type
    }

    /// Returns the raw `bundleVariant`.
    pub(crate) const fn bundle_variant(&self) -> BundleVariant {
        self.bundle_variant
    }

    /// Returns the asset class: `0` for ZEC, `1` for another asset.
    pub(crate) const fn asset_class(&self) -> u8 {
        self.asset_class
    }

    /// Returns the 64-byte asset UUID, present only for a non-ZEC asset.
    pub(crate) const fn asset_uuid(&self) -> Option<&[u8; 64]> {
        self.asset_uuid.as_ref()
    }

    /// Returns the signed value-pool delta as the raw wire integer.
    pub(crate) const fn value(&self) -> i64 {
        self.value
    }

    /// Deserializes a value pool delta entry without narrowing its value.
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let bundle_type = BundleType::from_u64(CompactSize::read(&mut reader)?);
        let bundle_variant = BundleVariant::from_u64(CompactSize::read(&mut reader)?);
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
                    alloc::format!("ValuePoolDelta assetClass must be 0 or 1, got {_other:#x}"),
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
}

/// Reads the `mValuePoolDeltas` map, enforcing canonical order and
/// per-bundle-type variant consistency.
///
/// Returns the entries in wire order and the variant observed for each bundle
/// type, so that callers can check cross-map consistency. Values are retained
/// as raw signed 64-bit integers.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn read_value_pool_delta_entries<R: Read>(
    mut reader: R,
) -> io::Result<(
    Vec<RawValuePoolDeltaEntry>,
    BTreeMap<BundleType, BundleVariant>,
)> {
    let count = CompactSize::read_t::<_, usize>(&mut reader)?;
    let mut entries = Vec::new();
    let mut last_raw: Option<(BundleType, u8, [u8; 64])> = None;
    let mut variants_by_type: BTreeMap<BundleType, BundleVariant> = BTreeMap::new();
    for _ in 0..count {
        let entry = RawValuePoolDeltaEntry::read(&mut reader)?;
        let raw_key = (
            entry.bundle_type,
            entry.asset_class,
            entry.asset_uuid.unwrap_or([0u8; 64]),
        );
        if let Some(previous) = &last_raw
            && &raw_key <= previous
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v7 mValuePoolDeltas is not in strictly increasing \
                 (bundleType, assetClass, assetUuid) order",
            ));
        }
        last_raw = Some(raw_key);
        match variants_by_type.get(&entry.bundle_type) {
            Some(&existing) if existing != entry.bundle_variant => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "v7 mValuePoolDeltas has multiple bundleVariants for the same bundleType",
                ));
            }
            _ => {
                variants_by_type.insert(entry.bundle_type, entry.bundle_variant);
            }
        }
        entries.push(entry);
    }
    Ok((entries, variants_by_type))
}

/// Reads one of the v7 bundle data maps (`mEffectBundles`, `mAuthBundles`).
///
/// Each entry is a TLV of `(bundleType, bundleVariant, compactSize-length,
/// data)`, and entries appear in strictly increasing `bundleType` order.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn read_bundle_data_map<R: Read>(
    mut reader: R,
    map_name: &str,
) -> io::Result<BTreeMap<BundleType, (BundleVariant, Vec<u8>)>> {
    let count = CompactSize::read_t::<_, usize>(&mut reader)?;
    let mut data_by_type: BTreeMap<BundleType, (BundleVariant, Vec<u8>)> = BTreeMap::new();
    let mut last_type: Option<BundleType> = None;
    for _ in 0..count {
        let ((bundle_type, bundle_variant), data) = read_bundle_data_framing(&mut reader)?;
        let bundle_type = BundleType::from_u64(bundle_type);
        let bundle_variant = BundleVariant::from_u64(bundle_variant);
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
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn write_bundle_data_map<W: Write>(
    mut writer: W,
    mut bundles: Vec<(u64, u64, Vec<u8>)>,
) -> io::Result<()> {
    for (_, _, data) in &bundles {
        if data.len() > MAX_BLOCK_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bundle data exceeds the maximum block size",
            ));
        }
    }
    bundles.sort_by_key(|(bundle_type, _, _)| *bundle_type);
    CompactSize::write(&mut writer, bundles.len())?;
    for (bundle_type, bundle_variant, data) in &bundles {
        write_bundle_data_framing(&mut writer, *bundle_type, *bundle_variant, data)?;
    }
    Ok(())
}

/// A raw `(bundleType, bundleVariant)` pair with no `compactSize` encoding.
///
/// Both are `compactSize`-encoded on the wire and in the v7 bundle digests, so
/// a value above [`MAX_COMPACT_SIZE`] could be neither serialized nor
/// committed to. Parsed transactions cannot carry one, because `compactSize`
/// decoding enforces the same bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireKeyError {
    /// The raw `bundleType` is out of range.
    BundleType(u64),
    /// The raw `bundleVariant` is out of range.
    BundleVariant(u64),
}

impl fmt::Display for WireKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireKeyError::BundleType(value) => write!(
                f,
                "bundleType {value} exceeds the maximum compactSize value {MAX_COMPACT_SIZE}"
            ),
            WireKeyError::BundleVariant(value) => write!(
                f,
                "bundleVariant {value} exceeds the maximum compactSize value {MAX_COMPACT_SIZE}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WireKeyError {}

/// Checks that a raw wire key can be `compactSize`-encoded.
fn check_wire_key(
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
) -> Result<(), WireKeyError> {
    if bundle_type.to_u64() > u64::from(MAX_COMPACT_SIZE) {
        return Err(WireKeyError::BundleType(bundle_type.to_u64()));
    }
    if bundle_variant.to_u64() > u64::from(MAX_COMPACT_SIZE) {
        return Err(WireKeyError::BundleVariant(bundle_variant.to_u64()));
    }
    Ok(())
}

/// The wire encoding of a sighash version 0 `sighashInfo` prefix, shared by
/// `TransparentSighashInfo`, `SaplingSignature` and `OrchardSignature`.
///
/// Per [ZIP 248 §Sighash Versioning](https://zips.z.cash/zip-0248#sighash-versioning),
/// sighash version 0 has empty `associatedData` for every bundle type, so
/// `sighashInfo = [0x00]` and the wire encoding is `compactSize(1) || [0x00]`.
/// Version 0 is the only defined version.
#[cfg(zcash_unstable = "nu8")]
pub(crate) const V7_SIGHASH_V0_INFO_WIRE: &[u8; 2] = &[0x01, 0x00];

/// Reads and validates a sighash version 0 `sighashInfo` prefix.
/// [ZIP 248 §Sighash Versioning](https://zips.z.cash/zip-0248#sighash-versioning)
///
/// Sighash version 0 encodes as `[0x01, 0x00]` on the wire: compactSize(1) for the
/// info length, then `0x00` for the version byte. This is the only defined version.
#[cfg(all(zcash_unstable = "nu8", test, feature = "sapling", feature = "orchard"))]
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
/// Layout: `tx_in_count`, `TransparentInputEffecting[tx_in_count]` (prevout 36 + nSequence 4),
///         `tx_out_count`, `TransparentOutput[tx_out_count]` (value 8 + scriptPubKey).
#[cfg(zcash_unstable = "nu8")]
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
#[cfg(zcash_unstable = "nu8")]
pub fn write_v7_transparent_auth<W: Write>(
    mut writer: W,
    bundle: &transparent::Bundle<transparent::Authorized>,
) -> io::Result<()> {
    for txin in &bundle.vin {
        writer.write_all(V7_SIGHASH_V0_INFO_WIRE)?;
        // scriptSig with compactSize length prefix
        txin.script_sig().write(&mut writer)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
    #[test]
    fn registry_columns_match_zip248() {
        let row = |bundle_type| bundle_registry_row(bundle_type).unwrap();

        for bundle_type in [
            BundleType::TRANSPARENT,
            BundleType::COINBASE,
            BundleType::SAPLING,
            BundleType::ORCHARD,
            BundleType::IRONWOOD,
            BundleType::FEE,
            BundleType::ZIP233_NSM,
        ] {
            assert!(row(bundle_type).value_pool_deltas);
            assert!(!row(bundle_type).reserved);
        }

        assert!(row(BundleType::TRANSPARENT).effect_bundles);
        assert!(row(BundleType::TRANSPARENT).auth_bundles);
        assert!(row(BundleType::COINBASE).effect_bundles);
        assert!(!row(BundleType::COINBASE).auth_bundles);
        assert!(row(BundleType::SAPLING).effect_bundles);
        assert!(row(BundleType::SAPLING).auth_bundles);
        assert!(row(BundleType::ORCHARD).effect_bundles);
        assert!(row(BundleType::ORCHARD).auth_bundles);
        assert!(row(BundleType::IRONWOOD).effect_bundles);
        assert!(row(BundleType::IRONWOOD).auth_bundles);
        assert!(!row(BundleType::FEE).effect_bundles);
        assert!(!row(BundleType::FEE).auth_bundles);
        assert!(!row(BundleType::ZIP233_NSM).effect_bundles);
        assert!(!row(BundleType::ZIP233_NSM).auth_bundles);
    }

    #[test]
    fn bundle_id_ordering() {
        assert!(
            BundleId::new(BundleType::TRANSPARENT, BundleVariant::DEFAULT)
                < BundleId::new(BundleType::SAPLING, BundleVariant::DEFAULT)
        );
        assert!(
            BundleId::new(BundleType::SAPLING, BundleVariant::DEFAULT)
                < BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT)
        );
        assert!(
            BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT)
                < BundleId::new(BundleType::FEE, BundleVariant::DEFAULT)
        );
        assert!(
            BundleId::new(BundleType::FEE, BundleVariant::DEFAULT)
                < BundleId::new(BundleType::ZIP233_NSM, BundleVariant::DEFAULT)
        );
    }

    #[test]
    fn value_pool_deltas_basic() {
        let mut vp = ValuePoolDeltas::empty();
        assert!(vp.is_empty());
        assert_eq!(vp.fee(), None);
        assert_eq!(vp.zip233_amount(), None);

        vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();
        assert!(!vp.is_empty());
        assert_eq!(vp.fee(), Some(Zatoshis::from_u64(1000).unwrap()));

        vp.set_zip233(Zatoshis::from_u64(5000).unwrap()).unwrap();
        assert_eq!(vp.zip233_amount(), Some(Zatoshis::from_u64(5000).unwrap()));

        let sap_vb = ZatBalance::from_i64(100_000).unwrap();
        vp.set_sapling(sap_vb).unwrap();
        assert_eq!(vp.sapling_value(), Some(sap_vb));

        // Iteration order should be by bundle type
        let types: Vec<BundleType> = vp.iter().map(|(k, _)| k.bundle_type()).collect();
        assert_eq!(
            types,
            vec![BundleType::SAPLING, BundleType::FEE, BundleType::ZIP233_NSM,]
        );
    }

    #[test]
    fn value_pool_deltas_zero_omitted() {
        let mut vp = ValuePoolDeltas::empty();
        vp.set_sapling(ZatBalance::from_i64(0).unwrap()).unwrap();
        // Zero values should not be stored
        assert!(vp.is_empty());
        assert_eq!(vp.sapling_value(), None);
    }

    #[test]
    fn value_pool_delta_entry_roundtrip() {
        let entry = ValuePoolDeltaEntry::from_parts(
            BundleType::SAPLING,
            BundleVariant::DEFAULT,
            ASSET_CLASS_ZEC,
            None,
            ZatBalance::from_i64(-50000).unwrap(),
        )
        .unwrap();

        let mut buf = Vec::new();
        entry.write(&mut buf).unwrap();

        let parsed = ValuePoolDeltaEntry::read(&buf[..]).unwrap();
        assert_eq!(parsed.bundle_type(), entry.bundle_type());
        assert_eq!(parsed.bundle_variant(), entry.bundle_variant());
        assert_eq!(parsed.asset_class(), entry.asset_class());
        assert_eq!(parsed.asset_uuid(), entry.asset_uuid());
        assert_eq!(parsed.value(), entry.value());
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
    fn value_pool_delta_entry_rejects_invalid_asset_class() {
        assert_eq!(
            ValuePoolDeltaEntry::from_parts(
                BundleType::from_u64(2),
                BundleVariant::from_u64(0),
                2,
                None,
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::InvalidAssetClass(2))
        );
    }

    #[test]
    fn value_pool_delta_entry_rejects_uuid_mismatch() {
        assert_eq!(
            ValuePoolDeltaEntry::from_parts(
                BundleType::from_u64(2),
                BundleVariant::from_u64(0),
                ASSET_CLASS_ZEC,
                Some([1u8; 64]),
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::AssetUuidMismatch {
                asset_class: ASSET_CLASS_ZEC
            })
        );
        assert_eq!(
            ValuePoolDeltaEntry::from_parts(
                BundleType::from_u64(2),
                BundleVariant::from_u64(0),
                ASSET_CLASS_OTHER,
                None,
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::AssetUuidMismatch {
                asset_class: ASSET_CLASS_OTHER
            })
        );
    }

    #[test]
    fn value_pool_delta_entry_rejects_zero_value() {
        assert_eq!(
            ValuePoolDeltaEntry::from_parts(
                BundleType::from_u64(2),
                BundleVariant::from_u64(0),
                ASSET_CLASS_ZEC,
                None,
                ZatBalance::zero(),
            ),
            Err(ValuePoolDeltaError::ZeroValue)
        );
    }

    #[test]
    fn value_pool_delta_entry_rejects_out_of_range_raw_ids() {
        let too_large = u64::from(MAX_COMPACT_SIZE) + 1;
        assert_eq!(
            ValuePoolDeltaEntry::from_parts(
                BundleType::from_u64(too_large),
                BundleVariant::from_u64(0),
                ASSET_CLASS_ZEC,
                None,
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::WireKey(WireKeyError::BundleType(
                too_large
            )))
        );
        assert_eq!(
            ValuePoolDeltaEntry::from_parts(
                BundleType::from_u64(2),
                BundleVariant::from_u64(too_large),
                ASSET_CLASS_ZEC,
                None,
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::WireKey(WireKeyError::BundleVariant(
                too_large
            )))
        );
    }

    #[test]
    fn value_pool_delta_key_rejects_invalid_assets() {
        assert_eq!(
            ValuePoolDeltaKey::from_parts(BundleType::SAPLING, 2, [0u8; 64]),
            Err(ValuePoolDeltaError::InvalidAssetClass(2))
        );
        assert_eq!(
            ValuePoolDeltaKey::from_parts(BundleType::SAPLING, ASSET_CLASS_ZEC, [1u8; 64]),
            Err(ValuePoolDeltaError::AssetUuidMismatch {
                asset_class: ASSET_CLASS_ZEC
            })
        );
    }

    #[test]
    fn value_pool_deltas_reject_duplicate_and_collapsing_keys() {
        let mut vp = ValuePoolDeltas::empty();
        let key = ValuePoolDeltaKey::zec(BundleType::SAPLING);
        vp.insert(
            key.clone(),
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            vp.insert(
                key,
                BundleVariant::DEFAULT,
                ZatBalance::from_i64(2).unwrap()
            ),
            Err(ValuePoolDeltaError::DuplicateEntry)
        );

        // A known ZEC key and an unknown ZEC key with the same wire key must
        // not both be present.
        assert_eq!(
            vp.insert(
                ValuePoolDeltaKey::from_parts(BundleType::SAPLING, ASSET_CLASS_ZEC, [0u8; 64])
                    .unwrap(),
                BundleVariant::from_u64(1),
                ZatBalance::from_i64(3).unwrap()
            ),
            Err(ValuePoolDeltaError::DuplicateEntry)
        );

        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::from_u64(8), ASSET_CLASS_ZEC, [0u8; 64])
                .unwrap(),
            BundleVariant::from_u64(0),
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            vp.insert(
                ValuePoolDeltaKey::from_parts(BundleType::from_u64(8), ASSET_CLASS_ZEC, [0u8; 64])
                    .unwrap(),
                BundleVariant::from_u64(0),
                ZatBalance::from_i64(2).unwrap()
            ),
            Err(ValuePoolDeltaError::DuplicateEntry)
        );
    }

    #[test]
    fn value_pool_deltas_setter_rejects_opaque_zec_variant_conflict() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::SAPLING, ASSET_CLASS_ZEC, [0u8; 64]).unwrap(),
            BundleVariant::from_u64(1),
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        let before = vp.to_wire_entries();

        let expected = Err(ValuePoolDeltaError::VariantMismatch {
            bundle_type: BundleType::SAPLING.to_u64(),
        });
        assert_eq!(vp.set_sapling(ZatBalance::from_i64(2).unwrap()), expected);
        assert_eq!(vp.to_wire_entries(), before);
        assert_eq!(vp.set_sapling(ZatBalance::zero()), expected);
        assert_eq!(vp.to_wire_entries(), before);
    }

    #[test]
    fn value_pool_deltas_setter_rejects_opaque_non_zec_variant_conflict() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::SAPLING, ASSET_CLASS_OTHER, [7u8; 64])
                .unwrap(),
            BundleVariant::from_u64(1),
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        let before = vp.to_wire_entries();

        let expected = Err(ValuePoolDeltaError::VariantMismatch {
            bundle_type: BundleType::SAPLING.to_u64(),
        });
        assert_eq!(vp.set_sapling(ZatBalance::from_i64(2).unwrap()), expected);
        assert_eq!(vp.to_wire_entries(), before);
        assert_eq!(vp.set_sapling(ZatBalance::zero()), expected);
        assert_eq!(vp.to_wire_entries(), before);
    }

    #[test]
    fn value_pool_deltas_setter_rejects_conflict_across_assets() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::SAPLING, ASSET_CLASS_ZEC, [0u8; 64]).unwrap(),
            BundleVariant::from_u64(1),
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::SAPLING, ASSET_CLASS_OTHER, [7u8; 64])
                .unwrap(),
            BundleVariant::from_u64(1),
            ZatBalance::from_i64(2).unwrap(),
        )
        .unwrap();
        let before = vp.to_wire_entries();

        assert_eq!(
            vp.set_sapling(ZatBalance::from_i64(3).unwrap()),
            Err(ValuePoolDeltaError::VariantMismatch {
                bundle_type: BundleType::SAPLING.to_u64(),
            })
        );
        assert_eq!(vp.to_wire_entries(), before);
    }

    #[test]
    fn value_pool_deltas_setter_allows_same_variant_cross_asset() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::SAPLING, ASSET_CLASS_OTHER, [7u8; 64])
                .unwrap(),
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        vp.set_sapling(ZatBalance::from_i64(2).unwrap()).unwrap();

        let entries = vp.to_wire_entries();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| {
            entry.bundle_type() == BundleType::SAPLING
                && entry.bundle_variant() == BundleVariant::DEFAULT
        }));
        assert_eq!(entries[0].asset_class(), ASSET_CLASS_ZEC);
        assert_eq!(entries[1].asset_class(), ASSET_CLASS_OTHER);
    }

    #[test]
    fn value_pool_deltas_accept_zec_and_other_assets() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            ValuePoolDeltaKey::zec(BundleType::SAPLING),
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::ORCHARD, ASSET_CLASS_OTHER, [7u8; 64])
                .unwrap(),
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(2).unwrap(),
        )
        .unwrap();
        vp.insert(
            ValuePoolDeltaKey::from_parts(BundleType::from_u64(8), ASSET_CLASS_OTHER, [9u8; 64])
                .unwrap(),
            BundleVariant::from_u64(0),
            ZatBalance::from_i64(3).unwrap(),
        )
        .unwrap();

        let entries = vp.to_wire_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].bundle_type(), BundleType::SAPLING);
        assert_eq!(entries[0].asset_class(), ASSET_CLASS_ZEC);
        assert_eq!(entries[0].asset_uuid(), None);
        assert_eq!(entries[1].bundle_type(), BundleType::ORCHARD);
        assert_eq!(entries[1].asset_class(), ASSET_CLASS_OTHER);
        assert_eq!(entries[1].asset_uuid(), Some(&[7u8; 64]));
        assert_eq!(entries[2].bundle_type(), BundleType::from_u64(8));
        assert_eq!(entries[2].asset_class(), ASSET_CLASS_OTHER);
        assert_eq!(entries[2].asset_uuid(), Some(&[9u8; 64]));
    }

    #[test]
    fn bundle_data_framing_roundtrip() {
        let bt = BundleType::ORCHARD;
        let bv = BundleVariant::DEFAULT;
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let mut buf = Vec::new();
        write_bundle_data_framing(&mut buf, bt.to_u64(), bv.to_u64(), &data).unwrap();

        let ((parsed_bt, parsed_bv), parsed_data) = read_bundle_data_framing(&buf[..]).unwrap();
        assert_eq!(parsed_bt, bt.to_u64());
        assert_eq!(parsed_bv, bv.to_u64());
        assert_eq!(parsed_data, data);
    }
}
