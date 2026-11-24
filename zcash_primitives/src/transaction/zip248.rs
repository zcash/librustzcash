//! ZIP 248: Extensible Transaction Format types.
//!
//! Typed transactions hold each protocol bundle in its own field; there is no
//! all-typed bundle map. An effecting or authorizing payload whose bundle type
//! or variant this implementation does not interpret is retained in a separate
//! byte map. Value pool delta entries carry no payload, so they remain representable
//! in [`ValuePoolDeltas`] under their open identifiers, subject only to the
//! typed monetary range.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

#[cfg(zcash_unstable = "nu8")]
use crate::transaction::bytes::ValuePoolDeltaBytes;
#[cfg(test)]
use alloc::vec;
#[cfg(zcash_unstable = "nu8")]
use corez::io;
#[cfg(all(test, feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
use corez::io::Read;
#[cfg(all(test, zcash_unstable = "nu8"))]
use zcash_encoding::CompactSize;
use zcash_encoding::MAX_COMPACT_SIZE;
use zcash_protocol::consensus::BlockHeight;
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

/// The registry columns for a registered V7 bundle type.
///
/// Each column records whether an entry for the bundle type may appear in the
/// corresponding transaction map. A `reserved` row may not appear in any map.
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
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
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
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

/// Returns whether a registered version 7 bundle type is activated by any
/// implemented consensus branch.
///
/// Registration and activation are separate: a registered entry must still be
/// rejected while its ZIP is undeployed, even though the type and its registry
/// columns are known. [ZIP 233](https://zips.z.cash/zip-0233) registers
/// `bundleType` 6 but is not deployed by any implemented branch, including NU8.
pub(crate) fn bundle_activated(bundle_type: BundleType) -> bool {
    !matches!(bundle_type, BundleType::ZIP233_NSM)
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
/// The unit value `()` supplies no digests.
///
/// The provider is trusted. The byte layer cannot verify a digest for a bundle
/// it does not interpret, so a transaction identifier computed from supplied
/// digests is only as trustworthy as the source that supplied them. A caller
/// that accepts such a transaction must obtain the digests from a source it
/// trusts, or verify the bundle independently.
pub trait BundleDigestProvider {
    /// Returns the canonical effecting-data digest for `key`, if supplied.
    fn effects_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash>;

    /// Returns the canonical authorizing-data digest for `key`, if supplied.
    fn auth_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash>;
}

impl BundleDigestProvider for () {
    fn effects_digest(&self, _key: BundleId) -> Option<blake2b_simd::Hash> {
        None
    }

    fn auth_digest(&self, _key: BundleId) -> Option<blake2b_simd::Hash> {
        None
    }
}

/// A [`BundleDigestProvider`] backed by explicit per-key digests.
///
/// Insertion rejects a second digest for the same key, and rejects a digest
/// that conflicts with one already present. A digest supplied for a key that
/// the transaction does not need is not an error at insertion time; use
/// [`Self::validate_for`] to reject such keys.
///
/// The supplied digests are trusted: see [`BundleDigestProvider`].
#[derive(Clone, Debug, Default)]
pub struct SuppliedBundleDigests {
    effects: BTreeMap<BundleId, blake2b_simd::Hash>,
    auth: BTreeMap<BundleId, blake2b_simd::Hash>,
}

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

impl BundleDigestProvider for SuppliedBundleDigests {
    fn effects_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash> {
        self.effects.get(&key).cloned()
    }

    fn auth_digest(&self, key: BundleId) -> Option<blake2b_simd::Hash> {
        self.auth.get(&key).cloned()
    }
}

/// An error resolving the per-bundle digests of a version 7 transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V7DigestError {
    /// A previous-output identifier is missing, extra, or differs from its input.
    MismatchedTransparentInputContext {
        /// The first context position without a matching transaction input.
        index: usize,
    },
    /// The selected legacy format commits to an anchor that is absent.
    MissingEffectingAnchor,
    /// The transaction is not a version 7 transaction.
    NotV7,
    /// The bundle is not supported by the selected transaction format.
    EffectsVersionMismatch,
    /// Signature hashing requires one genuine previous output per transparent input.
    MissingTransparentInputContext {
        /// The number of transparent inputs.
        expected: usize,
        /// The number of supplied amounts.
        amounts: usize,
        /// The number of supplied scripts.
        scripts: usize,
    },
    /// A retained entry duplicates a typed bundle slot.
    DuplicateBundleType {
        /// The retained entry that conflicts with the typed bundle.
        key: BundleId,
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

impl fmt::Display for V7DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MismatchedTransparentInputContext { index } => {
                write!(f, "previous output differs at input {index}")
            }
            Self::MissingEffectingAnchor => f.write_str("legacy effects require a real anchor"),
            Self::NotV7 => f.write_str("transaction is not a version 7 transaction"),
            Self::EffectsVersionMismatch => {
                f.write_str("bundle is not supported by this transaction format")
            }
            Self::MissingTransparentInputContext {
                expected,
                amounts,
                scripts,
            } => {
                write!(
                    f,
                    "signature hashing needs {expected} previous outputs, but has {amounts} amounts and {scripts} scripts"
                )
            }
            Self::DuplicateBundleType { key } => write!(
                f,
                "retained bundle ({}, {}) duplicates a typed bundle slot",
                key.bundle_type().to_u64(),
                key.bundle_variant().to_u64()
            ),
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

#[cfg(feature = "std")]
impl std::error::Error for V7DigestError {}

// CoinbaseBundle
// ---------------------------------------------------------------------------

/// The maximum length of the coinbase bundle's `coinbaseData` field.
///
/// A coinbase `scriptSig` was limited to 100 bytes, of which the leading push
/// of the block height took 5; of the 95 bytes that remained, the
/// `compactSize` length prefix of `coinbaseData` now takes one.
pub const MAX_COINBASE_DATA_LEN: usize = 94;

/// The maximum number of miner signal entries in a coinbase bundle.
///
/// Signal codes are one byte each and must strictly ascend, so there can be at
/// most one entry per possible code.
pub const MAX_MINER_SIGNALS: usize = 256;

/// The size in bytes of a poll digest.
pub const POLL_DIGEST_SIZE: usize = 16;

/// A signal code identifying the subject of a [`MinerSignal`].
///
/// The code space is allocated outside consensus; see
/// [ZIP 248 §MinerSignal](https://zips.z.cash/zip-0248#minersignal).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SignalCode(u8);

impl SignalCode {
    /// Constructs a signal code from its wire value.
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the wire value.
    pub const fn to_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for SignalCode {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

/// A miner's level of support for a [`MinerSignal`]'s subject.
///
/// The scale is allocated outside consensus; see
/// [ZIP 248 §MinerSignal](https://zips.z.cash/zip-0248#minersignal).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LevelOfSupport(u8);

impl LevelOfSupport {
    /// Constructs a level of support from its wire value.
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the wire value.
    pub const fn to_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for LevelOfSupport {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

/// One miner signal: a code identifying a subject and a level of support for
/// it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinerSignal {
    signal_code: SignalCode,
    level_of_support: LevelOfSupport,
}

impl MinerSignal {
    /// Constructs a miner signal from its code and level of support.
    pub const fn from_parts(signal_code: SignalCode, level_of_support: LevelOfSupport) -> Self {
        Self {
            signal_code,
            level_of_support,
        }
    }

    /// Returns the signal code.
    pub const fn signal_code(&self) -> SignalCode {
        self.signal_code
    }

    /// Returns the level of support.
    pub const fn level_of_support(&self) -> LevelOfSupport {
        self.level_of_support
    }
}

/// A digest identifying the poll that a coinbase bundle's miner signals respond
/// to.
///
/// Consensus assigns no structure to the digest; see
/// [ZIP 248 §Coinbase Effecting Data](https://zips.z.cash/zip-0248#coinbase-effecting-data).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PollDigest([u8; POLL_DIGEST_SIZE]);

impl PollDigest {
    /// Constructs a poll digest from its wire bytes.
    pub const fn new(bytes: [u8; POLL_DIGEST_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the wire bytes.
    pub const fn to_bytes(self) -> [u8; POLL_DIGEST_SIZE] {
        self.0
    }

    /// Returns a reference to the wire bytes.
    pub const fn as_bytes(&self) -> &[u8; POLL_DIGEST_SIZE] {
        &self.0
    }
}

impl From<[u8; POLL_DIGEST_SIZE]> for PollDigest {
    fn from(bytes: [u8; POLL_DIGEST_SIZE]) -> Self {
        Self::new(bytes)
    }
}

/// The largest block height that may appear in a coinbase bundle,
/// matching the range that ZIP 203 allows for `nExpiryHeight`.
pub(crate) const MAX_COINBASE_BLOCK_HEIGHT: u32 = 499_999_999;

/// The largest permitted `nExpiryHeight` value.
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) const MAX_EXPIRY_HEIGHT: u32 = 499_999_999;

/// The numerator of the fraction of transaction fees that ZIP 235 removes from
/// circulation as the NSM fee contribution.
pub(crate) const NSM_FEE_CONTRIBUTION_NUMERATOR: u64 = 6;

/// The denominator of the fraction of transaction fees that ZIP 235 removes
/// from circulation as the NSM fee contribution.
pub(crate) const NSM_FEE_CONTRIBUTION_DENOMINATOR: u64 = 10;

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
/// the deferred pool. The bundle's value pool delta is the subsidy less that
/// deposit and less the ZIP 235 NSM fee contribution; see
/// [`Self::value_pool_delta`].
///
/// The coinbase bundle has no authorizing data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseBundle {
    block_height: BlockHeight,
    block_subsidy: Zatoshis,
    lockbox_value: Zatoshis,
    coinbase_data: Vec<u8>,
    miner_signals: Vec<MinerSignal>,
    poll_digest: Option<PollDigest>,
}

impl CoinbaseBundle {
    /// Constructs a coinbase bundle, returning `None` if any of the field
    /// constraints in ZIP 248 §"Coinbase Effecting Data" is violated.
    ///
    /// This includes the miner-signal rules: at most [`MAX_MINER_SIGNALS`]
    /// entries, strictly ascending signal codes, and a poll digest present
    /// exactly when the signal list is nonempty.
    pub fn from_parts(
        block_height: BlockHeight,
        block_subsidy: Zatoshis,
        lockbox_value: Zatoshis,
        coinbase_data: Vec<u8>,
        miner_signals: Vec<MinerSignal>,
        poll_digest: Option<PollDigest>,
    ) -> Option<Self> {
        let height = u32::from(block_height);
        if height == 0
            || height > MAX_COINBASE_BLOCK_HEIGHT
            || lockbox_value > block_subsidy
            || coinbase_data.len() > MAX_COINBASE_DATA_LEN
            || miner_signals.len() > MAX_MINER_SIGNALS
            || miner_signals
                .windows(2)
                .any(|pair| pair[0].signal_code >= pair[1].signal_code)
            // The digest is present exactly when there are signals.
            || poll_digest.is_some() == miner_signals.is_empty()
        {
            return None;
        }
        Some(Self {
            block_height,
            block_subsidy,
            lockbox_value,
            coinbase_data,
            miner_signals,
            poll_digest,
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

    /// Returns the miner signals, in strictly ascending signal-code order.
    pub fn miner_signals(&self) -> &[MinerSignal] {
        &self.miner_signals
    }

    /// Returns the poll digest, if the bundle has miner signals.
    pub fn poll_digest(&self) -> Option<&PollDigest> {
        self.poll_digest.as_ref()
    }

    /// Returns the value that this bundle contributes to the transparent
    /// transaction value pool, given the block's gross transaction fees: the
    /// block subsidy, less the lockbox deposit and less the
    /// [ZIP 235 §Consensus rule changes](https://zips.z.cash/zip-0235#consensusrulechanges)
    /// NSM fee contribution
    /// `floor(6 * transaction_fees / 10)`.
    ///
    /// This is the value that
    /// $\mathsf{mValuePoolDeltas}[\mathsf{CoinbaseBundleId}]$
    /// is required to equal. It can be negative. Deriving the contribution
    /// here does not check that `transaction_fees` equals the block's total
    /// fees; that requires block context and is the consumer's responsibility.
    pub fn value_pool_delta(&self, transaction_fees: Zatoshis) -> ZatBalance {
        let subsidy = i128::from(u64::from(self.block_subsidy));
        let lockbox = i128::from(u64::from(self.lockbox_value));
        let contribution = (i128::from(u64::from(transaction_fees))
            * i128::from(NSM_FEE_CONTRIBUTION_NUMERATOR))
            / i128::from(NSM_FEE_CONTRIBUTION_DENOMINATOR);
        // Both amounts are at most MAX_MONEY and the contribution is at most
        // 6/10 of MAX_MONEY, so the widened difference fits comfortably in an
        // i64.
        let delta = i64::try_from(subsidy - lockbox - contribution)
            .expect("subsidy, lockbox and fee contribution are at most MAX_MONEY");
        ZatBalance::from_i64(delta).expect("delta is within the ZatBalance range")
    }
}

// ---------------------------------------------------------------------------
// ValuePoolDeltas
// ---------------------------------------------------------------------------

/// An error constructing or inserting a value pool delta entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValuePoolDeltaError {
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

/// `(bundle_variant, value)` for a value pool delta entry.
pub type VPDeltaValue = (BundleVariant, ZatBalance);

/// The value pool delta map from ZIP 248.
///
/// The map is keyed by the raw bundle type, so entries for bundle types or
/// variants this implementation does not understand are retained without a
/// separate opaque map. Retention is an inspection capability, not
/// recognition: an unknown entry's bundle is not thereby registered, activated,
/// understood, or safe to construct or sign, and consensus validation is a
/// separate step.
#[derive(Clone, Debug, Default)]
pub struct ValuePoolDeltas {
    entries: BTreeMap<BundleType, VPDeltaValue>,
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
    pub fn iter(&self) -> impl Iterator<Item = (&BundleType, &VPDeltaValue)> {
        self.entries.iter()
    }

    /// Returns the bundle variant for a given bundle type, if present.
    pub fn bundle_variant(&self, bundle_type: BundleType) -> Option<BundleVariant> {
        self.entries.get(&bundle_type).map(|&(variant, _)| variant)
    }

    /// Returns a bundle type's value pool delta.
    pub fn zec_value(&self, bundle_type: BundleType) -> Option<ZatBalance> {
        self.entries.get(&bundle_type).map(|&(_, value)| value)
    }

    /// Replaces a bundle's value pool delta, rejecting a variant conflict with
    /// any existing entry for that bundle type before mutating the map.
    ///
    /// # Errors
    ///
    /// Returns [`ValuePoolDeltaError::WireKey`] if an identifier has no
    /// `compactSize` encoding, or [`ValuePoolDeltaError::VariantMismatch`] if
    /// the map already has an entry for the bundle type with a different
    /// variant. The map is unchanged in either case.
    pub fn set_zec_value(
        &mut self,
        bundle_id: BundleId,
        value: ZatBalance,
    ) -> Result<(), ValuePoolDeltaError> {
        let bundle_type = bundle_id.bundle_type();
        let bundle_variant = bundle_id.bundle_variant();
        check_wire_key(bundle_type, bundle_variant).map_err(ValuePoolDeltaError::WireKey)?;
        self.check_variant(bundle_type, bundle_variant)?;
        if value == ZatBalance::zero() {
            self.entries.remove(&bundle_type);
        } else {
            self.entries.insert(bundle_type, (bundle_variant, value));
        }
        Ok(())
    }

    fn get_zec(&self, bundle_type: BundleType) -> Option<ZatBalance> {
        self.zec_value(bundle_type)
    }

    fn set_zec(
        &mut self,
        bundle_type: BundleType,
        value: ZatBalance,
    ) -> Result<(), ValuePoolDeltaError> {
        self.set_zec_value(BundleId::new(bundle_type, BundleVariant::DEFAULT), value)
    }

    /// Builds a map from canonically ordered wire entries in one pass.
    #[cfg(zcash_unstable = "nu8")]
    pub(crate) fn from_wire_entries<I>(entries: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = io::Result<(BundleType, BundleVariant, ZatBalance)>>,
    {
        let mut result = Self::empty();
        let mut previous_type = None;
        for entry in entries {
            let (bundle_type, variant, value) = entry?;
            if value == ZatBalance::zero() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a zero-valued value pool delta must be elided",
                ));
            }
            if previous_type.is_some_and(|previous| bundle_type <= previous) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "value pool deltas are not in canonical order",
                ));
            }
            if result
                .entries
                .insert(bundle_type, (variant, value))
                .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a bundle type appears more than once",
                ));
            }
            previous_type = Some(bundle_type);
        }
        Ok(result)
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

    /// Returns the coinbase bundle's ZEC value pool delta: the block subsidy,
    /// less the part of it deposited into the lockbox and less the ZIP 235 NSM
    /// fee contribution.
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
    /// Returns [`ValuePoolDeltaError::WireKey`] if an identifier has no
    /// `compactSize` encoding, [`ValuePoolDeltaError::ZeroValue`] for a zero
    /// value, [`ValuePoolDeltaError::DuplicateEntry`] if the bundle type is
    /// already present, or [`ValuePoolDeltaError::VariantMismatch`] if the
    /// bundle type already has an entry with a different variant.
    pub fn insert(
        &mut self,
        bundle_type: BundleType,
        variant: BundleVariant,
        value: ZatBalance,
    ) -> Result<(), ValuePoolDeltaError> {
        check_wire_key(bundle_type, variant).map_err(ValuePoolDeltaError::WireKey)?;
        if value == ZatBalance::zero() {
            return Err(ValuePoolDeltaError::ZeroValue);
        }
        if self.entries.contains_key(&bundle_type) {
            return Err(ValuePoolDeltaError::DuplicateEntry);
        }
        self.check_variant(bundle_type, variant)?;
        self.entries.insert(bundle_type, (variant, value));
        Ok(())
    }

    /// Checks that `bundle_type` has no entry with a different variant.
    fn check_variant(
        &self,
        bundle_type: BundleType,
        variant: BundleVariant,
    ) -> Result<(), ValuePoolDeltaError> {
        if let Some(&(existing, _)) = self.entries.get(&bundle_type)
            && existing != variant
        {
            return Err(ValuePoolDeltaError::VariantMismatch {
                bundle_type: bundle_type.to_u64(),
            });
        }
        Ok(())
    }

    /// Produces all value pool delta entries in canonical wire order, sorted by
    /// `bundleType`.
    #[cfg(zcash_unstable = "nu8")]
    pub fn to_wire_entries(&self) -> Vec<ValuePoolDeltaBytes> {
        self.entries
            .iter()
            .map(|(&bundle_type, &(variant, value))| {
                ValuePoolDeltaBytes::from_parts(bundle_type, variant, i64::from(value))
                    .expect("value pool delta map construction enforces wire invariants")
            })
            .collect()
    }
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

/// The wire encoding of a sighash variant 0 `sighashInfo` prefix, shared by
/// `TransparentSighashInfo`, `SaplingSignature` and `OrchardSignature`.
///
/// Per [ZIP 248 §Sighash Variants](https://zips.z.cash/zip-0248#sighash-variants),
/// sighash variant 0 has empty `associatedData` for every bundle type, so
/// `sighashInfo = [0x00]` and the wire encoding is `compactSize(1) || [0x00]`.
/// Variant 0 is the only defined variant.
#[cfg(zcash_unstable = "nu8")]
pub(crate) const V7_SIGHASH_V0_INFO_WIRE: &[u8; 2] = &[0x01, 0x00];

/// Reads and validates a sighash variant 0 `sighashInfo` prefix.
/// [ZIP 248 §Sighash Variants](https://zips.z.cash/zip-0248#sighash-variants)
///
/// Sighash variant 0 encodes as `[0x01, 0x00]` on the wire: compactSize(1) for the
/// info length, then `0x00` for the variant byte. This is the only defined variant.
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
            "unexpected sighashInfo length; only sighash variant 0 is supported",
            #[cfg(feature = "std")]
            alloc::format!(
                "unexpected sighashInfo length {} for {}; only sighash variant 0 is supported",
                info_len,
                _context,
            ),
        ));
    }
    let mut variant = [0u8; 1];
    reader.read_exact(&mut variant)?;
    if variant[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            #[cfg(not(feature = "std"))]
            "unsupported sighash variant",
            #[cfg(feature = "std")]
            alloc::format!(
                "unsupported sighash variant {:#x} for {}",
                variant[0],
                _context,
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbase_value_pool_delta_floors_nsm_fee_contribution() {
        /// Subsidy and lockbox leave 80 zatoshis before the fee contribution.
        const SUBSIDY: Zatoshis = Zatoshis::const_from_u64(100);
        const LOCKBOX: Zatoshis = Zatoshis::const_from_u64(20);
        /// ZIP 235 defines floor(6 * aggregate block fees / 10); 11 fees
        /// contribute 6, not the 7 that rounding to nearest would produce.
        const BLOCK_FEES: Zatoshis = Zatoshis::const_from_u64(11);
        const EXPECTED_DELTA: i64 = 74;
        let bundle = CoinbaseBundle::from_parts(
            BlockHeight::from_u32(1),
            SUBSIDY,
            LOCKBOX,
            vec![],
            vec![],
            None,
        )
        .unwrap();
        assert_eq!(
            bundle.value_pool_delta(BLOCK_FEES),
            ZatBalance::from_i64(EXPECTED_DELTA).unwrap(),
        );
    }

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
        let types: Vec<BundleType> = vp.iter().map(|(bundle_type, _)| *bundle_type).collect();
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

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn value_pool_delta_bytes_roundtrip() {
        let entry =
            ValuePoolDeltaBytes::from_parts(BundleType::SAPLING, BundleVariant::DEFAULT, -50_000)
                .unwrap();

        let mut buf = Vec::new();
        entry.write(&mut buf).unwrap();

        let parsed = ValuePoolDeltaBytes::read(&buf[..]).unwrap();
        assert_eq!(parsed, entry);
    }

    /// The wire form is exactly two one-byte compact sizes followed by the
    /// eight value bytes, with no asset discriminant between them.
    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn value_pool_delta_bytes_wire_is_type_variant_value() {
        let entry =
            ValuePoolDeltaBytes::from_parts(BundleType::SAPLING, BundleVariant::DEFAULT, -50_000)
                .unwrap();

        let mut buf = Vec::new();
        entry.write(&mut buf).unwrap();

        let mut expected = vec![BundleType::SAPLING.to_u64() as u8, 0];
        expected.extend_from_slice(&(-50_000i64).to_le_bytes());
        assert_eq!(buf, expected);
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn value_pool_delta_bytes_rejects_zero() {
        let mut buf = Vec::new();
        CompactSize::write(&mut buf, 0).unwrap();
        CompactSize::write(&mut buf, 0).unwrap();
        buf.extend_from_slice(&0i64.to_le_bytes());

        assert!(ValuePoolDeltaBytes::read(&buf[..]).is_err());
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn value_pool_delta_bytes_rejects_zero_value() {
        assert!(
            ValuePoolDeltaBytes::from_parts(BundleType::from_u64(2), BundleVariant::DEFAULT, 0)
                .is_err()
        );
    }

    #[test]
    fn value_pool_deltas_reject_out_of_range_wire_keys() {
        let too_large = u64::from(MAX_COMPACT_SIZE) + 1;
        let mut vp = ValuePoolDeltas::empty();
        assert_eq!(
            vp.insert(
                BundleType::from_u64(too_large),
                BundleVariant::DEFAULT,
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::WireKey(WireKeyError::BundleType(
                too_large
            )))
        );
        assert_eq!(
            vp.insert(
                BundleType::SAPLING,
                BundleVariant::from_u64(too_large),
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::WireKey(WireKeyError::BundleVariant(
                too_large
            )))
        );
        assert_eq!(
            vp.set_zec_value(
                BundleId::new(BundleType::SAPLING, BundleVariant::from_u64(too_large)),
                ZatBalance::from_i64(1).unwrap(),
            ),
            Err(ValuePoolDeltaError::WireKey(WireKeyError::BundleVariant(
                too_large
            )))
        );
        assert!(vp.is_empty());
    }

    #[test]
    fn value_pool_deltas_reject_duplicate_entry() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            BundleType::SAPLING,
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            vp.insert(
                BundleType::SAPLING,
                BundleVariant::DEFAULT,
                ZatBalance::from_i64(2).unwrap()
            ),
            Err(ValuePoolDeltaError::DuplicateEntry)
        );
    }

    /// A duplicate bundle type is rejected even when its variant differs.
    #[test]
    fn value_pool_deltas_reject_duplicate_type_with_different_variant() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            BundleType::SAPLING,
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            vp.insert(
                BundleType::SAPLING,
                BundleVariant::from_u64(1),
                ZatBalance::from_i64(3).unwrap()
            ),
            Err(ValuePoolDeltaError::DuplicateEntry)
        );

        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            BundleType::from_u64(8),
            BundleVariant::from_u64(0),
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            vp.insert(
                BundleType::from_u64(8),
                BundleVariant::from_u64(0),
                ZatBalance::from_i64(2).unwrap()
            ),
            Err(ValuePoolDeltaError::DuplicateEntry)
        );
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn value_pool_deltas_setter_rejects_opaque_variant_conflict() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            BundleType::SAPLING,
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

    /// The map is keyed and emitted purely by bundle type, including for
    /// unknown types and non-default variants.
    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn value_pool_deltas_emit_by_bundle_type() {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            BundleType::SAPLING,
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(1).unwrap(),
        )
        .unwrap();
        vp.insert(
            BundleType::ORCHARD,
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(2).unwrap(),
        )
        .unwrap();
        vp.insert(
            BundleType::from_u64(8),
            BundleVariant::from_u64(3),
            ZatBalance::from_i64(3).unwrap(),
        )
        .unwrap();

        let entries = vp.to_wire_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].bundle_type(), BundleType::SAPLING);
        assert_eq!(entries[1].bundle_type(), BundleType::ORCHARD);
        assert_eq!(entries[2].bundle_type(), BundleType::from_u64(8));
        assert_eq!(entries[2].bundle_variant(), BundleVariant::from_u64(3));
    }
}

#[cfg(test)]
mod miner_signal_tests {
    use super::*;

    fn signal(code: u8, level: u8) -> MinerSignal {
        MinerSignal::from_parts(SignalCode::new(code), LevelOfSupport::new(level))
    }

    fn bundle(
        signals: Vec<MinerSignal>,
        poll_digest: Option<PollDigest>,
    ) -> Option<CoinbaseBundle> {
        CoinbaseBundle::from_parts(
            BlockHeight::from(100u32),
            Zatoshis::from_u64(1_000_000).unwrap(),
            Zatoshis::ZERO,
            vec![],
            signals,
            poll_digest,
        )
    }

    fn digest() -> PollDigest {
        PollDigest::new([0x11; POLL_DIGEST_SIZE])
    }

    #[test]
    fn accessors_round_trip() {
        let signals = vec![signal(1, 0x10), signal(9, 0x90)];
        let bundle = bundle(signals.clone(), Some(digest())).unwrap();
        assert_eq!(bundle.miner_signals(), signals.as_slice());
        assert_eq!(bundle.miner_signals()[1].signal_code().to_u8(), 9);
        assert_eq!(bundle.miner_signals()[1].level_of_support().to_u8(), 0x90);
        assert_eq!(bundle.poll_digest(), Some(&digest()));
    }

    #[test]
    fn empty_signals_have_no_digest() {
        let bundle = bundle(vec![], None).unwrap();
        assert!(bundle.miner_signals().is_empty());
        assert_eq!(bundle.poll_digest(), None);
    }

    #[test]
    fn signal_codes_must_strictly_ascend() {
        assert!(bundle(vec![signal(1, 0), signal(1, 0)], Some(digest())).is_none());
        assert!(bundle(vec![signal(2, 0), signal(1, 0)], Some(digest())).is_none());
        assert!(bundle(vec![signal(1, 0), signal(2, 0)], Some(digest())).is_some());
    }

    #[test]
    fn signal_count_is_at_most_all_codes() {
        let all: Vec<_> = (0u8..=255).map(|code| signal(code, 0)).collect();
        assert_eq!(all.len(), MAX_MINER_SIGNALS);
        assert!(bundle(all.clone(), Some(digest())).is_some());

        let mut over = all;
        over.push(signal(0, 0));
        assert_eq!(over.len(), MAX_MINER_SIGNALS + 1);
        assert!(bundle(over, Some(digest())).is_none());
    }

    #[test]
    fn digest_presence_must_match_signals() {
        assert!(bundle(vec![signal(1, 0)], None).is_none());
        assert!(bundle(vec![], Some(digest())).is_none());
    }
}
