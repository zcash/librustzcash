//! Helper functions for managing light client key material.
use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{self, Display};

use zcash_address::unified::{self, Container, Encoding, Item, MetadataItem, Typecode};
use zcash_protocol::{
    address::Revision,
    consensus::{self, BlockHeight},
};
use zip32::{AccountId, DiversifierIndex};

use crate::address::UnifiedAddress;

#[cfg(any(feature = "sapling", feature = "orchard"))]
use zcash_protocol::consensus::NetworkConstants;

#[cfg(feature = "transparent-inputs")]
use {
    core::convert::TryInto,
    transparent::keys::{IncomingViewingKey, NonHardenedChildIndex},
};

#[cfg(all(
    feature = "transparent-inputs",
    any(test, feature = "test-dependencies")
))]
use transparent::address::TransparentAddress;

#[cfg(feature = "unstable")]
use {
    byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt},
    core::convert::TryFrom,
    core2::io::{Read, Write},
    zcash_encoding::CompactSize,
    zcash_protocol::consensus::BranchId,
};

#[cfg(feature = "orchard")]
use orchard::{self, keys::Scope};

#[cfg(all(feature = "sapling", feature = "unstable"))]
use ::sapling::zip32::ExtendedFullViewingKey;

#[cfg(feature = "sapling")]
pub mod sapling {
    pub use sapling::zip32::{
        DiversifiableFullViewingKey, ExtendedFullViewingKey, ExtendedSpendingKey,
    };
    use zip32::{AccountId, ChildIndex};

    /// Derives the ZIP 32 [`ExtendedSpendingKey`] for a given coin type and account from the
    /// given seed.
    ///
    /// # Panics
    ///
    /// Panics if `seed` is shorter than 32 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use zcash_protocol::constants::testnet::COIN_TYPE;
    /// use zcash_keys::keys::sapling;
    /// use zip32::AccountId;
    ///
    /// let extsk = sapling::spending_key(&[0; 32][..], COIN_TYPE, AccountId::ZERO);
    /// ```
    /// [`ExtendedSpendingKey`]: sapling::zip32::ExtendedSpendingKey
    pub fn spending_key(seed: &[u8], coin_type: u32, account: AccountId) -> ExtendedSpendingKey {
        if seed.len() < 32 {
            panic!("ZIP 32 seeds MUST be at least 32 bytes");
        }

        ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(seed),
            &[
                ChildIndex::hardened(32),
                ChildIndex::hardened(coin_type),
                account.into(),
            ],
        )
    }
}

#[cfg(feature = "transparent-inputs")]
fn to_transparent_child_index(j: DiversifierIndex) -> Option<NonHardenedChildIndex> {
    let (low_4_bytes, rest) = j.as_bytes().split_at(4);
    let transparent_j = u32::from_le_bytes(low_4_bytes.try_into().unwrap());
    if rest.iter().any(|b| b != &0) {
        None
    } else {
        NonHardenedChildIndex::from_index(transparent_j)
    }
}

/// Errors that can occur in the generation of Unified Spending Keys, Unified Viewing Keys, or
/// Unified Addresses.
#[derive(Debug)]
pub enum UnifiedKeyError {
    /// A data item (Orchard, Sapling, or P2pkh key or receiver, or some other unknown data item)
    /// must be present in order for a key or address to be valid.
    DataItemRequired,
    /// An error occurred in Orchard key or receiver derivation.
    #[cfg(feature = "orchard")]
    Orchard(orchard::zip32::Error),
    /// An error occurred in P2pkh key or receiver derivation.
    #[cfg(feature = "transparent-inputs")]
    Transparent(bip32::Error),
}

impl Display for UnifiedKeyError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnifiedKeyError::DataItemRequired => write!(
                _f,
                "Unified keys must contain at least one non-metadata item."
            ),
            #[cfg(feature = "orchard")]
            UnifiedKeyError::Orchard(e) => write!(_f, "Orchard key derivation error: {}", e),
            #[cfg(feature = "transparent-inputs")]
            UnifiedKeyError::Transparent(e) => {
                write!(_f, "Transparent key derivation error: {}", e)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnifiedKeyError {}

/// A version identifier for the encoding of unified spending keys.
///
/// Each era corresponds to a range of block heights. During an era, the unified spending key
/// parsed from an encoded form tagged with that era's identifier is expected to provide
/// sufficient spending authority to spend any non-Sprout shielded note created in a transaction
/// within the era's block range.
#[cfg(feature = "unstable")]
#[derive(Debug, PartialEq, Eq)]
pub enum Era {
    /// The Orchard era begins at Orchard activation, and will end if a new pool that requires a
    /// change to unified spending keys is introduced.
    Orchard,
}

/// A type for errors that can occur when decoding keys from their serialized representations.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodingError {
    #[cfg(feature = "unstable")]
    ReadError(&'static str),
    #[cfg(feature = "unstable")]
    EraInvalid,
    #[cfg(feature = "unstable")]
    EraMismatch(Era),
    #[cfg(feature = "unstable")]
    TypecodeInvalid,
    #[cfg(feature = "unstable")]
    LengthInvalid,
    #[cfg(feature = "unstable")]
    LengthMismatch(Typecode, u32),
    #[cfg(feature = "unstable")]
    InsufficientData(Typecode),
    /// The key data for the given key type could not be decoded from its string representation to
    /// a valid key.
    KeyDataInvalid(Typecode),
    /// Decoding resulted in a value that would violate validity constraints.
    ConstraintViolation(String),
}

impl core::fmt::Display for DecodingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "unstable")]
            DecodingError::ReadError(s) => write!(f, "Read error: {}", s),
            #[cfg(feature = "unstable")]
            DecodingError::EraInvalid => write!(f, "Invalid era"),
            #[cfg(feature = "unstable")]
            DecodingError::EraMismatch(e) => write!(f, "Era mismatch: actual {:?}", e),
            #[cfg(feature = "unstable")]
            DecodingError::TypecodeInvalid => write!(f, "Invalid typecode"),
            #[cfg(feature = "unstable")]
            DecodingError::LengthInvalid => write!(f, "Invalid length"),
            #[cfg(feature = "unstable")]
            DecodingError::LengthMismatch(t, l) => {
                write!(
                    f,
                    "Length mismatch: received {} bytes for typecode {:?}",
                    l, t
                )
            }
            #[cfg(feature = "unstable")]
            DecodingError::InsufficientData(t) => {
                write!(f, "Insufficient data for typecode {:?}", t)
            }
            DecodingError::KeyDataInvalid(t) => write!(f, "Invalid key data for key type {:?}", t),
            DecodingError::ConstraintViolation(s) => {
                write!(f, "Decoding produced an invalid value: {}", s)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodingError {}

impl From<UnifiedKeyError> for DecodingError {
    fn from(value: UnifiedKeyError) -> Self {
        match value {
            UnifiedKeyError::DataItemRequired => {
                Self::ConstraintViolation("At least one Data Item must be present.".to_owned())
            }
            #[cfg(feature = "orchard")]
            UnifiedKeyError::Orchard(_) => {
                Self::KeyDataInvalid(Typecode::Data(unified::DataTypecode::Orchard))
            }
            #[cfg(feature = "transparent-inputs")]
            UnifiedKeyError::Transparent(_) => {
                Self::KeyDataInvalid(Typecode::Data(unified::DataTypecode::P2pkh))
            }
        }
    }
}

#[cfg(feature = "unstable")]
impl Era {
    /// Returns the unique identifier for the era.
    fn id(&self) -> u32 {
        // We use the consensus branch id of the network upgrade that introduced a
        // new USK format as the identifier for the era.
        match self {
            Era::Orchard => u32::from(BranchId::Nu5),
        }
    }

    fn try_from_id(id: u32) -> Option<Self> {
        BranchId::try_from(id).ok().and_then(|b| match b {
            BranchId::Nu5 => Some(Era::Orchard),
            _ => None,
        })
    }
}

/// A set of spending keys that are all associated with a single ZIP-0032 account identifier.
#[derive(Clone, Debug)]
pub struct UnifiedSpendingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: transparent::keys::AccountPrivKey,
    #[cfg(feature = "sapling")]
    sapling: sapling::ExtendedSpendingKey,
    #[cfg(feature = "orchard")]
    orchard: orchard::keys::SpendingKey,
}

impl UnifiedSpendingKey {
    pub fn from_seed<P: consensus::Parameters>(
        _params: &P,
        seed: &[u8],
        _account: AccountId,
    ) -> Result<UnifiedSpendingKey, UnifiedKeyError> {
        if seed.len() < 32 {
            panic!("ZIP 32 seeds MUST be at least 32 bytes");
        }

        UnifiedSpendingKey::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            transparent::keys::AccountPrivKey::from_seed(_params, seed, _account)
                .map_err(UnifiedKeyError::Transparent)?,
            #[cfg(feature = "sapling")]
            sapling::spending_key(seed, _params.coin_type(), _account),
            #[cfg(feature = "orchard")]
            orchard::keys::SpendingKey::from_zip32_seed(seed, _params.coin_type(), _account)
                .map_err(UnifiedKeyError::Orchard)?,
        )
    }

    /// Construct a USK from its constituent parts, after verifying that UIVK derivation can
    /// succeed.
    fn from_checked_parts(
        #[cfg(feature = "transparent-inputs")] transparent: transparent::keys::AccountPrivKey,
        #[cfg(feature = "sapling")] sapling: sapling::ExtendedSpendingKey,
        #[cfg(feature = "orchard")] orchard: orchard::keys::SpendingKey,
    ) -> Result<UnifiedSpendingKey, UnifiedKeyError> {
        // Verify that FVK and IVK derivation succeed; we don't want to construct a USK
        // that can't derive transparent addresses.
        #[cfg(feature = "transparent-inputs")]
        let _ = transparent.to_account_pubkey().derive_external_ivk()?;

        Ok(UnifiedSpendingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
        })
    }

    pub fn to_unified_full_viewing_key(&self) -> UnifiedFullViewingKey {
        UnifiedFullViewingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent: Some(self.transparent.to_account_pubkey()),
            #[cfg(feature = "sapling")]
            sapling: Some(self.sapling.to_diversifiable_full_viewing_key()),
            #[cfg(feature = "orchard")]
            orchard: Some((&self.orchard).into()),
            unknown_data: vec![],
            expiry_height: None,
            expiry_time: None,
            unknown_metadata: vec![],
        }
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &transparent::keys::AccountPrivKey {
        &self.transparent
    }

    /// Returns the Sapling extended spending key component of this unified spending key.
    #[cfg(feature = "sapling")]
    pub fn sapling(&self) -> &sapling::ExtendedSpendingKey {
        &self.sapling
    }

    /// Returns the Orchard spending key component of this unified spending key.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> &orchard::keys::SpendingKey {
        &self.orchard
    }

    /// Returns a binary encoding of this key suitable for decoding with [`Self::from_bytes`].
    ///
    /// The encoded form of a unified spending key is only intended for use
    /// within wallets when required for storage and/or crossing FFI boundaries;
    /// unified spending keys should not be exposed to users, and consequently
    /// no string-based encoding is defined. This encoding does not include any
    /// internal validation metadata (such as checksums) as keys decoded from
    /// this form will necessarily be validated when the attempt is made to
    /// spend a note that they have authority for.
    #[cfg(feature = "unstable")]
    pub fn to_bytes(&self, era: Era) -> Vec<u8> {
        let mut result = vec![];
        result.write_u32::<LittleEndian>(era.id()).unwrap();

        #[cfg(feature = "orchard")]
        {
            let orchard_key = self.orchard();
            CompactSize::write(&mut result, usize::try_from(Typecode::ORCHARD).unwrap()).unwrap();

            let orchard_key_bytes = orchard_key.to_bytes();
            CompactSize::write(&mut result, orchard_key_bytes.len()).unwrap();
            result.write_all(orchard_key_bytes).unwrap();
        }

        #[cfg(feature = "sapling")]
        {
            let sapling_key = self.sapling();
            CompactSize::write(&mut result, usize::try_from(Typecode::SAPLING).unwrap()).unwrap();

            let sapling_key_bytes = sapling_key.to_bytes();
            CompactSize::write(&mut result, sapling_key_bytes.len()).unwrap();
            result.write_all(&sapling_key_bytes).unwrap();
        }

        #[cfg(feature = "transparent-inputs")]
        {
            let account_tkey = self.transparent();
            CompactSize::write(&mut result, usize::try_from(Typecode::P2PKH).unwrap()).unwrap();

            let account_tkey_bytes = account_tkey.to_bytes();
            CompactSize::write(&mut result, account_tkey_bytes.len()).unwrap();
            result.write_all(&account_tkey_bytes).unwrap();
        }

        result
    }

    /// Decodes a [`UnifiedSpendingKey`] value from its serialized representation.
    ///
    /// See [`Self::to_bytes`] for additional detail about the encoded form.
    #[allow(clippy::unnecessary_unwrap)]
    #[cfg(feature = "unstable")]
    pub fn from_bytes(era: Era, encoded: &[u8]) -> Result<Self, DecodingError> {
        use zcash_address::unified::DataTypecode;
        let mut source = core2::io::Cursor::new(encoded);
        let decoded_era = source
            .read_u32::<LittleEndian>()
            .map_err(|_| DecodingError::ReadError("era"))
            .and_then(|id| Era::try_from_id(id).ok_or(DecodingError::EraInvalid))?;

        if decoded_era != era {
            return Err(DecodingError::EraMismatch(decoded_era));
        }

        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        loop {
            let tc = CompactSize::read_t::<_, u32>(&mut source)
                .map_err(|_| DecodingError::ReadError("typecode"))
                .and_then(|v| {
                    DataTypecode::try_from(v).map_err(|_| DecodingError::TypecodeInvalid)
                })?;

            let len = CompactSize::read_t::<_, u32>(&mut source)
                .map_err(|_| DecodingError::ReadError("key length"))?;

            match tc {
                DataTypecode::Orchard => {
                    if len != 32 {
                        return Err(DecodingError::LengthMismatch(Typecode::ORCHARD, len));
                    }

                    let mut key = [0u8; 32];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::ORCHARD))?;

                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::<orchard::keys::SpendingKey>::from(
                                orchard::keys::SpendingKey::from_bytes(key),
                            )
                            .ok_or(DecodingError::KeyDataInvalid(Typecode::ORCHARD))?,
                        );
                    }
                }
                DataTypecode::Sapling => {
                    if len != 169 {
                        return Err(DecodingError::LengthMismatch(Typecode::SAPLING, len));
                    }

                    let mut key = [0u8; 169];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::SAPLING))?;

                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            sapling::ExtendedSpendingKey::from_bytes(&key)
                                .map_err(|_| DecodingError::KeyDataInvalid(Typecode::SAPLING))?,
                        );
                    }
                }
                DataTypecode::P2pkh => {
                    if len != 74 {
                        return Err(DecodingError::LengthMismatch(Typecode::P2PKH, len));
                    }

                    let mut key = [0u8; 74];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::P2PKH))?;

                    #[cfg(feature = "transparent-inputs")]
                    {
                        transparent = Some(
                            transparent::keys::AccountPrivKey::from_bytes(&key)
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::P2PKH))?,
                        );
                    }
                }
                _ => {
                    return Err(DecodingError::TypecodeInvalid);
                }
            }

            #[cfg(feature = "orchard")]
            let has_orchard = orchard.is_some();
            #[cfg(not(feature = "orchard"))]
            let has_orchard = true;

            #[cfg(feature = "sapling")]
            let has_sapling = sapling.is_some();
            #[cfg(not(feature = "sapling"))]
            let has_sapling = true;

            #[cfg(feature = "transparent-inputs")]
            let has_transparent = transparent.is_some();
            #[cfg(not(feature = "transparent-inputs"))]
            let has_transparent = true;

            if has_orchard && has_sapling && has_transparent {
                return UnifiedSpendingKey::from_checked_parts(
                    #[cfg(feature = "transparent-inputs")]
                    transparent.unwrap(),
                    #[cfg(feature = "sapling")]
                    sapling.unwrap(),
                    #[cfg(feature = "orchard")]
                    orchard.unwrap(),
                )
                .map_err(DecodingError::from);
            }
        }
    }

    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn default_address(
        &self,
        request: Option<UnifiedAddressRequest>,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.to_unified_full_viewing_key().default_address(request)
    }

    #[cfg(all(
        feature = "transparent-inputs",
        any(test, feature = "test-dependencies")
    ))]
    pub fn default_transparent_address(&self) -> (TransparentAddress, NonHardenedChildIndex) {
        self.transparent()
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap()
            .default_address()
    }
}

/// Errors that can occur in the generation of unified addresses.
#[derive(Clone, Debug)]
pub enum AddressGenerationError {
    /// The requested diversifier index was outside the range of valid transparent
    /// child address indices.
    #[cfg(feature = "transparent-inputs")]
    InvalidTransparentChildIndex(DiversifierIndex),
    /// The diversifier index could not be mapped to a valid Sapling diversifier.
    #[cfg(feature = "sapling")]
    InvalidSaplingDiversifierIndex(DiversifierIndex),
    /// The space of available diversifier indices has been exhausted.
    DiversifierSpaceExhausted,
    /// A requested address typecode was not recognized, so we are unable to generate the address
    /// as requested.
    ReceiverTypeNotSupported(Typecode),
    /// A requested address typecode was recognized, but the unified key being used to generate the
    /// address lacks an item of the requested type.
    KeyNotAvailable(Typecode),
    /// A Unified address cannot be generated without at least one shielded receiver being
    /// included.
    ShieldedReceiverRequired,
}

impl fmt::Display for AddressGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            #[cfg(feature = "transparent-inputs")]
            AddressGenerationError::InvalidTransparentChildIndex(i) => {
                write!(
                    f,
                    "Child index {:?} does not generate a valid transparent receiver",
                    i
                )
            }
            #[cfg(feature = "sapling")]
            AddressGenerationError::InvalidSaplingDiversifierIndex(i) => {
                write!(
                    f,
                    "Child index {:?} does not generate a valid Sapling receiver",
                    i
                )
            }
            AddressGenerationError::DiversifierSpaceExhausted => {
                write!(
                    f,
                    "Exhausted the space of diversifier indices without finding an address."
                )
            }
            AddressGenerationError::ReceiverTypeNotSupported(t) => {
                write!(
                    f,
                    "Unified Address generation does not yet support receivers of type {:?}.",
                    t
                )
            }
            AddressGenerationError::KeyNotAvailable(t) => {
                write!(
                    f,
                    "The Unified Viewing Key does not contain a key for typecode {:?}.",
                    t
                )
            }
            AddressGenerationError::ShieldedReceiverRequired => {
                write!(f, "A Unified Address requires at least one shielded (Sapling or Orchard) receiver.")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddressGenerationError {}

/// An enumeration of the ways in which a receiver may be requested to be present in a generated
/// [`UnifiedAddress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverRequirement {
    /// A receiver of the associated type is required to be present in the generated
    /// `[UnifiedAddress`], and if it is not possible to generate a receiver of this type, the
    /// address generation method should return an error. When calling [`Self::intersect`], this
    /// variant will be preferred over [`ReceiverRequirement::Allow`].
    Require,
    /// The associated receiver should be included, if a corresponding item exists in the IVK from
    /// which the address is being derived and derivation of the receiver succeeds at the given
    /// diversifier index.
    Allow,
    /// No receiver of the associated type may be included in the generated [`UnifiedAddress`]
    /// under any circumstances. When calling [`Self::intersect`], this variant will be preferred
    /// over [`ReceiverRequirement::Allow`].
    Omit,
}

impl ReceiverRequirement {
    /// Return the intersection of two requirements that chooses the stronger requirement, if one
    /// exists. [`ReceiverRequirement::Require`] and [`ReceiverRequirement::Omit`] are
    /// incompatible; attempting an intersection between these will return an error.
    pub fn intersect(self, other: Self) -> Result<Self, ()> {
        use ReceiverRequirement::*;
        match (self, other) {
            (Require, Omit) => Err(()),
            (Require, Require) => Ok(Require),
            (Require, Allow) => Ok(Require),
            (Allow, Require) => Ok(Require),
            (Allow, Allow) => Ok(Allow),
            (Allow, Omit) => Ok(Omit),
            (Omit, Require) => Err(()),
            (Omit, Allow) => Ok(Omit),
            (Omit, Omit) => Ok(Omit),
        }
    }
}

/// Specification for how a unified address should be generated from a unified viewing key.
#[derive(Clone, Copy, Debug)]
pub struct UnifiedAddressRequest {
    orchard: ReceiverRequirement,
    sapling: ReceiverRequirement,
    p2pkh: ReceiverRequirement,
    expiry_height: Option<BlockHeight>,
    expiry_time: Option<u64>,
}

impl UnifiedAddressRequest {
    /// Construct a new unified address request from its constituent parts.
    ///
    /// Returns `Err(())` if the resulting unified address would not include at least one shielded receiver.
    pub fn new(
        orchard: ReceiverRequirement,
        sapling: ReceiverRequirement,
        p2pkh: ReceiverRequirement,
        expiry_height: Option<BlockHeight>,
        expiry_time: Option<u64>,
    ) -> Result<Self, ()> {
        use ReceiverRequirement::*;
        if orchard == Omit && sapling == Omit && p2pkh == Omit {
            Err(())
        } else {
            Ok(Self {
                orchard,
                sapling,
                p2pkh,
                expiry_height,
                expiry_time,
            })
        }
    }

    /// Constructs a new unified address request that allows a receiver of each type.
    pub const ALLOW_ALL: UnifiedAddressRequest = {
        use ReceiverRequirement::*;
        Self::unsafe_new_without_expiry(Allow, Allow, Allow)
    };

    /// Constructs a new unified address request that includes only the receivers that are allowed
    /// both in itself and a given other request. Returns [`None`] if requirements are incompatible
    /// or if no shielded receiver type is allowed.
    pub fn intersect(&self, other: &UnifiedAddressRequest) -> Result<UnifiedAddressRequest, ()> {
        let orchard = self.orchard.intersect(other.orchard)?;
        let sapling = self.sapling.intersect(other.sapling)?;
        let p2pkh = self.p2pkh.intersect(other.p2pkh)?;
        Self::new(
            orchard,
            sapling,
            p2pkh,
            self.expiry_height
                .zip(other.expiry_height)
                .map(|(s, o)| std::cmp::min(s, o))
                .or(self.expiry_height)
                .or(other.expiry_height),
            self.expiry_time
                .zip(other.expiry_time)
                .map(|(s, o)| std::cmp::min(s, o))
                .or(self.expiry_time)
                .or(other.expiry_time),
        )
    }

    /// Construct a new unified address request from its constituent parts.
    ///
    /// Panics: at least one of `orchard` or `sapling` must be allowed.
    pub const fn unsafe_new_without_expiry(
        orchard: ReceiverRequirement,
        sapling: ReceiverRequirement,
        p2pkh: ReceiverRequirement,
    ) -> Self {
        use ReceiverRequirement::*;
        if matches!(orchard, Omit) && matches!(sapling, Omit) && matches!(p2pkh, Omit) {
            panic!("At least one receiver type must be allowed.")
        }

        Self {
            orchard,
            sapling,
            p2pkh,
            expiry_height: None,
            expiry_time: None,
        }
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<bip32::Error> for UnifiedKeyError {
    fn from(e: bip32::Error) -> Self {
        UnifiedKeyError::Transparent(e)
    }
}

/// A [ZIP 316](https://zips.z.cash/zip-0316) unified full viewing key.
#[derive(Clone, Debug)]
pub struct UnifiedFullViewingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<transparent::keys::AccountPubKey>,
    #[cfg(feature = "sapling")]
    sapling: Option<sapling::DiversifiableFullViewingKey>,
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::keys::FullViewingKey>,
    unknown_data: Vec<(u32, Vec<u8>)>,
    expiry_height: Option<BlockHeight>,
    expiry_time: Option<u64>,
    unknown_metadata: Vec<(u32, Vec<u8>)>,
}

impl UnifiedFullViewingKey {
    /// Construct a new unified full viewing key.
    ///
    /// This method is only available when the `test-dependencies` feature is enabled,
    /// as derivation from the USK or deserialization from the serialized form should
    /// be used instead.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn new(
        #[cfg(feature = "transparent-inputs")] transparent: Option<
            transparent::keys::AccountPubKey,
        >,
        #[cfg(feature = "sapling")] sapling: Option<sapling::DiversifiableFullViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::FullViewingKey>,
        unknown_data: Vec<(u32, Vec<u8>)>,
        expiry_height: Option<BlockHeight>,
        expiry_time: Option<u64>,
        unknown_metadata: Vec<(u32, Vec<u8>)>,
    ) -> Result<UnifiedFullViewingKey, UnifiedKeyError> {
        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown_data,
            expiry_height,
            expiry_time,
            unknown_metadata,
        )
    }

    #[cfg(feature = "unstable-frost")]
    pub fn from_orchard_fvk(
        orchard: orchard::keys::FullViewingKey,
    ) -> Result<UnifiedFullViewingKey, UnifiedKeyError> {
        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            None,
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            Some(orchard),
            // We don't currently allow constructing new UFVKs with unknown items, but we store
            // this to allow parsing such UFVKs.
            vec![],
            None,
            None,
            vec![],
        )
    }

    #[cfg(all(feature = "sapling", feature = "unstable"))]
    pub fn from_sapling_extended_full_viewing_key(
        sapling: ExtendedFullViewingKey,
    ) -> Result<UnifiedFullViewingKey, UnifiedKeyError> {
        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            None,
            #[cfg(feature = "sapling")]
            Some(sapling.to_diversifiable_full_viewing_key()),
            #[cfg(feature = "orchard")]
            None,
            // We don't currently allow constructing new UFVKs with unknown items, but we store
            // this to allow parsing such UFVKs.
            vec![],
            None,
            None,
            vec![],
        )
    }

    /// Construct a UFVK from its constituent parts, after verifying that UIVK derivation can
    /// succeed.
    fn from_checked_parts(
        #[cfg(feature = "transparent-inputs")] transparent: Option<
            transparent::keys::AccountPubKey,
        >,
        #[cfg(feature = "sapling")] sapling: Option<sapling::DiversifiableFullViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::FullViewingKey>,
        unknown_data: Vec<(u32, Vec<u8>)>,
        expiry_height: Option<BlockHeight>,
        expiry_time: Option<u64>,
        unknown_metadata: Vec<(u32, Vec<u8>)>,
    ) -> Result<UnifiedFullViewingKey, UnifiedKeyError> {
        // Verify that IVK derivation succeeds; we don't want to construct a UFVK
        // that can't derive transparent addresses.
        #[cfg(feature = "transparent-inputs")]
        let _ = transparent
            .as_ref()
            .map(|t| t.derive_external_ivk())
            .transpose()?;

        #[allow(unused_mut)]
        let mut has_data = !unknown_data.is_empty();
        #[cfg(feature = "transparent-inputs")]
        {
            has_data = has_data || transparent.is_some();
        }
        #[cfg(feature = "sapling")]
        {
            has_data = has_data || sapling.is_some();
        }
        #[cfg(feature = "orchard")]
        {
            has_data = has_data || orchard.is_some();
        }

        if has_data {
            Ok(Self {
                #[cfg(feature = "transparent-inputs")]
                transparent,
                #[cfg(feature = "sapling")]
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                unknown_data,
                expiry_height,
                expiry_time,
                unknown_metadata,
            })
        } else {
            Err(UnifiedKeyError::DataItemRequired)
        }
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn decode<P: consensus::Parameters>(params: &P, encoding: &str) -> Result<Self, String> {
        let (net, ufvk) =
            zcash_address::unified::Ufvk::decode(encoding).map_err(|e| e.to_string())?;
        let expected_net = params.network_type();
        if net != expected_net {
            return Err(format!(
                "UFVK is for network {:?} but we expected {:?}",
                net, expected_net,
            ));
        }

        Self::parse(&ufvk).map_err(|e| e.to_string())
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn parse(ufvk: &zcash_address::unified::Ufvk) -> Result<Self, DecodingError> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        let mut unknown_data = vec![];
        let mut expiry_height = None;
        let mut expiry_time = None;
        let mut unknown_metadata = vec![];

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        for item in ufvk.items_as_parsed() {
            match item {
                Item::Data(unified::Fvk::Orchard(data)) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            orchard::keys::FullViewingKey::from_bytes(data)
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::ORCHARD))?,
                        );
                    }

                    #[cfg(not(feature = "orchard"))]
                    unknown_data.push((unified::DataTypecode::Orchard.into(), data.to_vec()));
                }
                Item::Data(unified::Fvk::Sapling(data)) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            sapling::DiversifiableFullViewingKey::from_bytes(data)
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::SAPLING))?,
                        );
                    }
                    #[cfg(not(feature = "sapling"))]
                    unknown_data.push((unified::Typecode::SAPLING.into(), data.to_vec()));
                }
                Item::Data(unified::Fvk::P2pkh(data)) => {
                    #[cfg(feature = "transparent-inputs")]
                    {
                        transparent = Some(
                            transparent::keys::AccountPubKey::deserialize(data)
                                .map_err(|_| DecodingError::KeyDataInvalid(Typecode::P2PKH))?,
                        );
                    }

                    #[cfg(not(feature = "transparent-inputs"))]
                    unknown_data.push((unified::DataTypecode::P2pkh.into(), data.to_vec()));
                }
                Item::Data(unified::Fvk::Unknown { typecode, data }) => {
                    unknown_data.push((*typecode, data.clone()));
                }
                Item::Metadata(MetadataItem::ExpiryHeight(h)) => {
                    expiry_height = Some(BlockHeight::from(*h));
                }
                Item::Metadata(MetadataItem::ExpiryTime(t)) => {
                    expiry_time = Some(*t);
                }
                Item::Metadata(MetadataItem::Unknown { typecode, data }) => {
                    unknown_metadata.push((*typecode, data.clone()));
                }
            }
        }

        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown_data,
            expiry_height,
            expiry_time,
            unknown_metadata,
        )
        .map_err(|_| DecodingError::KeyDataInvalid(Typecode::P2PKH))
    }

    /// Returns the string encoding of this `UnifiedFullViewingKey` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_ufvk().encode(&params.network_type())
    }

    /// Returns the string encoding of this `UnifiedFullViewingKey` for the given network.
    fn to_ufvk(&self) -> zcash_address::unified::Ufvk {
        let data_items =
            std::iter::empty().chain(self.unknown_data.iter().map(|(typecode, data)| {
                unified::Fvk::Unknown {
                    typecode: *typecode,
                    data: data.clone(),
                }
            }));
        #[cfg(feature = "orchard")]
        let data_items = data_items.chain(
            self.orchard
                .as_ref()
                .map(|fvk| fvk.to_bytes())
                .map(unified::Fvk::Orchard),
        );
        #[cfg(feature = "sapling")]
        let data_items = data_items.chain(
            self.sapling
                .as_ref()
                .map(|dfvk| dfvk.to_bytes())
                .map(unified::Fvk::Sapling),
        );
        #[cfg(feature = "transparent-inputs")]
        let data_items = data_items.chain(
            self.transparent
                .as_ref()
                .map(|tfvk| tfvk.serialize().try_into().unwrap())
                .map(unified::Fvk::P2pkh),
        );

        let meta_items = std::iter::empty()
            .chain(self.unknown_metadata.iter().map(|(typecode, data)| {
                unified::MetadataItem::Unknown {
                    typecode: *typecode,
                    data: data.clone(),
                }
            }))
            .chain(
                self.expiry_height
                    .map(|h| unified::MetadataItem::ExpiryHeight(u32::from(h))),
            )
            .chain(self.expiry_time.map(unified::MetadataItem::ExpiryTime));

        zcash_address::unified::Ufvk::try_from_items(
            if self.expiry_height().is_some()
                || self.expiry_time().is_some()
                || !(self.has_sapling() || self.has_orchard())
            {
                Revision::R1
            } else {
                Revision::R0
            },
            data_items
                .map(Item::Data)
                .chain(meta_items.map(Item::Metadata))
                .collect(),
        )
        .expect("UnifiedFullViewingKey should only be constructed safely")
    }

    /// Derives a Unified Incoming Viewing Key from this Unified Full Viewing Key.
    pub fn to_unified_incoming_viewing_key(&self) -> UnifiedIncomingViewingKey {
        UnifiedIncomingViewingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent: self.transparent.as_ref().map(|t| {
                t.derive_external_ivk()
                    .expect("Transparent IVK derivation was checked at construction.")
            }),
            #[cfg(feature = "sapling")]
            sapling: self.sapling.as_ref().map(|s| s.to_external_ivk()),
            #[cfg(feature = "orchard")]
            orchard: self.orchard.as_ref().map(|o| o.to_ivk(Scope::External)),
            expiry_height: self.expiry_height,
            expiry_time: self.expiry_time,
            // We cannot translate unknown data or metadata items, as they may not be relevant to the IVK
            unknown_data: vec![],
            unknown_metadata: vec![],
        }
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> Option<&transparent::keys::AccountPubKey> {
        self.transparent.as_ref()
    }

    /// Returns the Sapling diversifiable full viewing key component of this unified key.
    #[cfg(feature = "sapling")]
    pub fn sapling(&self) -> Option<&sapling::DiversifiableFullViewingKey> {
        self.sapling.as_ref()
    }

    /// Returns whether this UFVK contains a Sapling item.
    pub fn has_sapling(&self) -> bool {
        #[cfg(feature = "sapling")]
        return self.sapling.is_some();
        #[cfg(not(feature = "sapling"))]
        return false;
    }

    /// Returns the Orchard full viewing key component of this unified key.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> Option<&orchard::keys::FullViewingKey> {
        self.orchard.as_ref()
    }

    /// Returns whether this UFVK contains an Orchard item.
    pub fn has_orchard(&self) -> bool {
        #[cfg(feature = "orchard")]
        return self.orchard.is_some();
        #[cfg(not(feature = "orchard"))]
        return false;
    }

    /// Returns any unknown data items parsed from the encoded form of the key.
    pub fn unknown_data(&self) -> &[(u32, Vec<u8>)] {
        self.unknown_data.as_ref()
    }

    /// Returns the expiration height that will be used in addresses derived from this key.
    pub fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }

    /// Sets the expiration height that will be used in addresses derived from this key.
    pub fn set_expiry_height(&mut self, height: BlockHeight) {
        self.expiry_height = Some(height);
    }

    /// Removes the expiration height from this key.
    pub fn unset_expiry_height(&mut self) {
        self.expiry_height = None;
    }

    /// Returns the expiration time that will be used in addresses derived from this key.
    ///
    /// The returned value is an integer representing a UTC time in seconds relative to the Unix
    /// Epoch of 1970-01-01T00:00:00Z.
    pub fn expiry_time(&self) -> Option<u64> {
        self.expiry_time
    }

    /// Sets the expiration time that will be used in addresses derived from this key.
    ///
    /// The argument should be an integer representing a UTC time in seconds relative to the Unix
    /// Epoch of 1970-01-01T00:00:00Z.
    pub fn set_expiry_time(&mut self, time: u64) {
        self.expiry_time = Some(time);
    }

    /// Removes the expiration time from this key.
    pub fn unset_expiry_time(&mut self) {
        self.expiry_time = None;
    }

    /// Returns any unknown metadata items parsed from the encoded form of the key.
    pub fn unknown_metadata(&self) -> &[(u32, Vec<u8>)] {
        self.unknown_metadata.as_ref()
    }

    /// Attempts to derive the Unified Address for the given diversifier index and receiver types.
    /// If `request` is None, the address should be derived to contain a receiver for each item in
    /// this UFVK.
    ///
    /// Returns `None` if the specified index does not produce a valid diversifier.
    pub fn address(
        &self,
        j: DiversifierIndex,
        request: Option<UnifiedAddressRequest>,
    ) -> Result<UnifiedAddress, AddressGenerationError> {
        self.to_unified_incoming_viewing_key().address(j, request)
    }

    /// Searches the diversifier space starting at diversifier index `j` for one which will produce
    /// a valid diversifier, and return the Unified Address constructed using that diversifier
    /// along with the index at which the valid diversifier was found. If `request` is None, the
    /// address should be derived to contain a receiver for each item in this UFVK.
    ///
    /// Returns an `Err(AddressGenerationError)` if no valid diversifier exists or if the features
    /// required to satisfy the unified address request are not properly enabled.
    pub fn find_address(
        &self,
        j: DiversifierIndex,
        request: Option<UnifiedAddressRequest>,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.to_unified_incoming_viewing_key()
            .find_address(j, request)
    }

    /// Find the Unified Address corresponding to the smallest valid diversifier index, along with
    /// that index. If `request` is None, the address should be derived to contain a receiver for
    /// each item in this UFVK.
    ///
    /// Returns an `Err(AddressGenerationError)` if no valid diversifier exists or if the features
    /// required to satisfy the unified address request are not properly enabled.
    pub fn default_address(
        &self,
        request: Option<UnifiedAddressRequest>,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.find_address(DiversifierIndex::new(), request)
    }
}

/// A [ZIP 316](https://zips.z.cash/zip-0316) unified incoming viewing key.
#[derive(Clone, Debug)]
pub struct UnifiedIncomingViewingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<transparent::keys::ExternalIvk>,
    #[cfg(feature = "sapling")]
    sapling: Option<::sapling::zip32::IncomingViewingKey>,
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::keys::IncomingViewingKey>,
    unknown_data: Vec<(u32, Vec<u8>)>,
    expiry_height: Option<BlockHeight>,
    expiry_time: Option<u64>,
    unknown_metadata: Vec<(u32, Vec<u8>)>,
}

impl UnifiedIncomingViewingKey {
    /// Construct a new unified incoming viewing key.
    ///
    /// This method is only available when the `test-dependencies` feature is enabled,
    /// as derivation from the UFVK or deserialization from the serialized form should
    /// be used instead.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn new(
        #[cfg(feature = "transparent-inputs")] transparent: Option<transparent::keys::ExternalIvk>,
        #[cfg(feature = "sapling")] sapling: Option<::sapling::zip32::IncomingViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::IncomingViewingKey>,
        unknown_data: Vec<(u32, Vec<u8>)>,
        expiry_height: Option<BlockHeight>,
        expiry_time: Option<u64>,
        unknown_metadata: Vec<(u32, Vec<u8>)>,
    ) -> Result<UnifiedIncomingViewingKey, UnifiedKeyError> {
        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown_data,
            expiry_height,
            expiry_time,
            unknown_metadata,
        )
    }

    fn from_checked_parts(
        #[cfg(feature = "transparent-inputs")] transparent: Option<transparent::keys::ExternalIvk>,
        #[cfg(feature = "sapling")] sapling: Option<::sapling::zip32::IncomingViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::IncomingViewingKey>,
        unknown_data: Vec<(u32, Vec<u8>)>,
        expiry_height: Option<BlockHeight>,
        expiry_time: Option<u64>,
        unknown_metadata: Vec<(u32, Vec<u8>)>,
    ) -> Result<Self, UnifiedKeyError> {
        #[allow(unused_mut)]
        let mut has_data = !unknown_data.is_empty();
        #[cfg(feature = "transparent-inputs")]
        {
            has_data = has_data || transparent.is_some();
        }
        #[cfg(feature = "sapling")]
        {
            has_data = has_data || sapling.is_some();
        }
        #[cfg(feature = "orchard")]
        {
            has_data = has_data || orchard.is_some();
        }

        if has_data {
            Ok(Self {
                #[cfg(feature = "transparent-inputs")]
                transparent,
                #[cfg(feature = "sapling")]
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                unknown_data,
                expiry_height,
                expiry_time,
                unknown_metadata,
            })
        } else {
            Err(UnifiedKeyError::DataItemRequired)
        }
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn decode<P: consensus::Parameters>(params: &P, encoding: &str) -> Result<Self, String> {
        let (net, uivk) = unified::Uivk::decode(encoding).map_err(|e| e.to_string())?;
        let expected_net = params.network_type();
        if net != expected_net {
            return Err(format!(
                "UIVK is for network {:?} but we expected {:?}",
                net, expected_net,
            ));
        }

        Self::parse(&uivk).map_err(|e| e.to_string())
    }

    /// Constructs a unified incoming viewing key from a parsed unified encoding.
    fn parse(uivk: &zcash_address::unified::Uivk) -> Result<Self, DecodingError> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        let mut unknown_data = vec![];
        let mut expiry_height = None;
        let mut expiry_time = None;
        let mut unknown_metadata = vec![];

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        for receiver in uivk.items_as_parsed() {
            match receiver {
                Item::Data(unified::Ivk::Orchard(data)) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::from(orchard::keys::IncomingViewingKey::from_bytes(data))
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::ORCHARD))?,
                        );
                    }

                    #[cfg(not(feature = "orchard"))]
                    unknown_data.push((u32::from(unified::Typecode::ORCHARD), data.to_vec()));
                }
                Item::Data(unified::Ivk::Sapling(data)) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            Option::from(::sapling::zip32::IncomingViewingKey::from_bytes(data))
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::SAPLING))?,
                        );
                    }

                    #[cfg(not(feature = "sapling"))]
                    unknown_data.push((u32::from(unified::Typecode::SAPLING), data.to_vec()));
                }
                Item::Data(unified::Ivk::P2pkh(data)) => {
                    #[cfg(feature = "transparent-inputs")]
                    {
                        transparent = Some(
                            transparent::keys::ExternalIvk::deserialize(data)
                                .map_err(|_| DecodingError::KeyDataInvalid(Typecode::P2PKH))?,
                        );
                    }

                    #[cfg(not(feature = "transparent-inputs"))]
                    unknown_data.push((u32::from(unified::Typecode::P2PKH), data.to_vec()));
                }
                Item::Data(unified::Ivk::Unknown { typecode, data }) => {
                    unknown_data.push((*typecode, data.clone()));
                }
                Item::Metadata(MetadataItem::ExpiryHeight(h)) => {
                    expiry_height = Some(BlockHeight::from(*h));
                }
                Item::Metadata(MetadataItem::ExpiryTime(t)) => {
                    expiry_time = Some(*t);
                }
                Item::Metadata(MetadataItem::Unknown { typecode, data }) => {
                    unknown_metadata.push((*typecode, data.clone()));
                }
            }
        }

        Ok(Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown_data,
            expiry_height,
            expiry_time,
            unknown_metadata,
        )?)
    }

    /// Returns the string encoding of this `UnifiedFullViewingKey` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.render().encode(&params.network_type())
    }

    /// Converts this unified incoming viewing key to a unified encoding.
    fn render(&self) -> zcash_address::unified::Uivk {
        let data_items =
            std::iter::empty().chain(self.unknown_data.iter().map(|(typecode, data)| {
                unified::Ivk::Unknown {
                    typecode: *typecode,
                    data: data.clone(),
                }
            }));
        #[cfg(feature = "orchard")]
        let data_items = data_items.chain(
            self.orchard
                .as_ref()
                .map(|ivk| ivk.to_bytes())
                .map(unified::Ivk::Orchard),
        );
        #[cfg(feature = "sapling")]
        let data_items = data_items.chain(
            self.sapling
                .as_ref()
                .map(|divk| divk.to_bytes())
                .map(unified::Ivk::Sapling),
        );
        #[cfg(feature = "transparent-inputs")]
        let data_items = data_items.chain(
            self.transparent
                .as_ref()
                .map(|tivk| tivk.serialize().try_into().unwrap())
                .map(unified::Ivk::P2pkh),
        );

        let meta_items = std::iter::empty()
            .chain(self.unknown_metadata.iter().map(|(typecode, data)| {
                unified::MetadataItem::Unknown {
                    typecode: *typecode,
                    data: data.clone(),
                }
            }))
            .chain(
                self.expiry_height
                    .map(|h| unified::MetadataItem::ExpiryHeight(u32::from(h))),
            )
            .chain(self.expiry_time.map(unified::MetadataItem::ExpiryTime));

        zcash_address::unified::Uivk::try_from_items(
            if self.expiry_height.is_some() || self.expiry_time.is_some() {
                Revision::R1
            } else {
                Revision::R0
            },
            data_items
                .map(Item::Data)
                .chain(meta_items.map(Item::Metadata))
                .collect(),
        )
        .expect("UnifiedIncomingViewingKey should only be constructed safely.")
    }

    /// Returns the Transparent external IVK, if present.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &Option<transparent::keys::ExternalIvk> {
        &self.transparent
    }

    /// Returns the Sapling IVK, if present.
    #[cfg(feature = "sapling")]
    pub fn sapling(&self) -> &Option<::sapling::zip32::IncomingViewingKey> {
        &self.sapling
    }

    /// Returns the Orchard IVK, if present.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> &Option<orchard::keys::IncomingViewingKey> {
        &self.orchard
    }

    /// Returns any unknown data items parsed from the encoded form of the key.
    pub fn unknown_data(&self) -> &[(u32, Vec<u8>)] {
        self.unknown_data.as_ref()
    }

    /// Returns the expiration height that will be used in addresses derived from this key.
    pub fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }

    /// Sets the expiration height that will be used in addresses derived from this key.
    pub fn set_expiry_height(&mut self, height: BlockHeight) {
        self.expiry_height = Some(height);
    }

    /// Removes the expiration height from this key.
    pub fn unset_expiry_height(&mut self) {
        self.expiry_height = None;
    }

    /// Returns the expiration time that will be used in addresses derived from this key.
    ///
    /// The returned value is an integer representing a UTC time in seconds relative to the Unix
    /// Epoch of 1970-01-01T00:00:00Z.
    pub fn expiry_time(&self) -> Option<u64> {
        self.expiry_time
    }

    /// Sets the expiration time that will be used in addresses derived from this key.
    ///
    /// The argument should be an integer representing a UTC time in seconds relative to the Unix
    /// Epoch of 1970-01-01T00:00:00Z.
    pub fn set_expiry_time(&mut self, time: u64) {
        self.expiry_time = Some(time);
    }

    /// Removes the expiration time from this key.
    pub fn unset_expiry_time(&mut self) {
        self.expiry_time = None;
    }

    /// Returns any unknown metadata items parsed from the encoded form of the key.
    pub fn unknown_metadata(&self) -> &[(u32, Vec<u8>)] {
        self.unknown_metadata.as_ref()
    }

    /// Attempts to derive the Unified Address for the given diversifier index and receiver types.
    /// If `request` is None, the address will be derived to contain a receiver for each item in
    /// this UFVK.
    ///
    /// Returns an error if the this key does not produce a valid receiver for a required receiver
    /// type at the given diversifier index.
    pub fn address(
        &self,
        _j: DiversifierIndex,
        request: Option<UnifiedAddressRequest>,
    ) -> Result<UnifiedAddress, AddressGenerationError> {
        use ReceiverRequirement::*;

        let request = request
            .or(self.to_address_request().ok())
            .ok_or(AddressGenerationError::ShieldedReceiverRequired)?;

        #[cfg(feature = "orchard")]
        let mut orchard = None;
        if request.orchard != Omit {
            #[cfg(not(feature = "orchard"))]
            if request.orchard == Require {
                return Err(AddressGenerationError::ReceiverTypeNotSupported(
                    Typecode::ORCHARD,
                ));
            }

            #[cfg(feature = "orchard")]
            if let Some(oivk) = &self.orchard {
                let orchard_j = orchard::keys::DiversifierIndex::from(*_j.as_bytes());
                orchard = Some(oivk.address_at(orchard_j))
            } else if request.orchard == Require {
                return Err(AddressGenerationError::KeyNotAvailable(Typecode::ORCHARD));
            }
        }

        #[cfg(feature = "sapling")]
        let mut sapling = None;
        if request.sapling != Omit {
            #[cfg(not(feature = "sapling"))]
            if request.sapling == Require {
                return Err(AddressGenerationError::ReceiverTypeNotSupported(
                    Typecode::SAPLING,
                ));
            }

            #[cfg(feature = "sapling")]
            if let Some(divk) = &self.sapling {
                // If a Sapling receiver type is requested, we must be able to construct an
                // address; if we're unable to do so, then no Unified Address exists at this
                // diversifier and we use `?` to early-return from this method.
                sapling = match (request.sapling, divk.address_at(_j)) {
                    (Require | Allow, Some(addr)) => Ok(Some(addr)),
                    (Require, None) => {
                        Err(AddressGenerationError::InvalidSaplingDiversifierIndex(_j))
                    }
                    _ => Ok(None),
                }?;
            } else if request.sapling == Require {
                return Err(AddressGenerationError::KeyNotAvailable(Typecode::SAPLING));
            }
        }

        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        if request.p2pkh != Omit {
            #[cfg(not(feature = "transparent-inputs"))]
            if request.p2pkh == Require {
                return Err(AddressGenerationError::ReceiverTypeNotSupported(
                    Typecode::P2PKH,
                ));
            }

            #[cfg(feature = "transparent-inputs")]
            if let Some(tivk) = self.transparent.as_ref() {
                // If a transparent receiver type is requested, we must be able to construct an
                // address; if we're unable to do so, then no Unified Address exists at this
                // diversifier.
                let j = to_transparent_child_index(_j);

                transparent = match (request.p2pkh, j.and_then(|j| tivk.derive_address(j).ok())) {
                    (Require | Allow, Some(addr)) => Ok(Some(addr)),
                    (Require, None) => {
                        Err(AddressGenerationError::InvalidTransparentChildIndex(_j))
                    }
                    _ => Ok(None),
                }?;
            } else if request.p2pkh == Require {
                return Err(AddressGenerationError::KeyNotAvailable(Typecode::P2PKH));
            }
        }
        #[cfg(not(feature = "transparent-inputs"))]
        let transparent = None;

        Ok(UnifiedAddress::from_checked_parts(
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "sapling")]
            sapling,
            transparent,
            self.unknown_data.clone(),
            self.expiry_height
                .zip(request.expiry_height)
                .map(|(l, r)| std::cmp::min(l, r))
                .or(self.expiry_height)
                .or(request.expiry_height),
            self.expiry_time
                .zip(request.expiry_time)
                .map(|(l, r)| std::cmp::min(l, r))
                .or(self.expiry_time)
                .or(request.expiry_time),
            self.unknown_metadata.clone(),
        )
        .expect("UIVK validity constraints are checked at construction."))
    }

    /// Searches the diversifier space starting at diversifier index `j` for one which will produce
    /// a valid address that conforms to the provided request, and returns that Unified Address
    /// along with the index at which the valid diversifier was found.
    ///
    /// If [`None`] is specified for the `request` parameter, a default request that [`Require`]s a
    /// receiver be present for each key item enabled by the feature flags in use will be used to
    /// search the diversifier space.
    ///
    /// Returns an `Err(AddressGenerationError)` if no valid diversifier exists or if the features
    /// required to satisfy the unified address request are not enabled.
    ///
    /// [`Require`]: ReceiverRequirement::Require
    #[allow(unused_mut)]
    pub fn find_address(
        &self,
        mut j: DiversifierIndex,
        request: Option<UnifiedAddressRequest>,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        let request = request
            .or_else(|| self.to_address_request().ok())
            .ok_or(AddressGenerationError::ShieldedReceiverRequired)?;

        // If we need to generate a transparent receiver, check that the user has not
        // specified an invalid transparent child index, from which we can never search to
        // find a valid index.
        #[cfg(feature = "transparent-inputs")]
        if request.p2pkh == ReceiverRequirement::Require
            && self.transparent.is_some()
            && to_transparent_child_index(j).is_none()
        {
            return Err(AddressGenerationError::InvalidTransparentChildIndex(j));
        }

        // Find a working diversifier and construct the associated address.
        loop {
            let res = self.address(j, Some(request));
            match res {
                Ok(ua) => {
                    return Ok((ua, j));
                }
                #[cfg(feature = "sapling")]
                Err(AddressGenerationError::InvalidSaplingDiversifierIndex(_)) => {
                    if j.increment().is_err() {
                        return Err(AddressGenerationError::DiversifierSpaceExhausted);
                    } else {
                        continue;
                    }
                }
                Err(other) => {
                    return Err(other);
                }
            }
        }
    }

    /// Find the Unified Address corresponding to the smallest valid diversifier index, along with
    /// that index. If `request` is None, the address will be derived to contain a receiver for
    /// each data item in this UFVK.
    ///
    /// Returns an error if the this key does not produce a valid receiver for a required receiver
    /// type at any diversifier index.
    pub fn default_address(
        &self,
        request: Option<UnifiedAddressRequest>,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.find_address(DiversifierIndex::new(), request)
    }

    /// Constructs a [`UnifiedAddressRequest`] that requires a receiver for each data item of this UIVK.
    ///
    /// Returns [`Err`] if the resulting request would not include a shielded receiver.
    #[allow(unused_mut)]
    pub fn to_address_request(&self) -> Result<UnifiedAddressRequest, ()> {
        use ReceiverRequirement::*;

        let mut orchard = Omit;
        #[cfg(feature = "orchard")]
        if self.orchard.is_some() {
            orchard = Require;
        }

        let mut sapling = Omit;
        #[cfg(feature = "sapling")]
        if self.sapling.is_some() {
            sapling = Require;
        }

        let mut p2pkh = Omit;
        #[cfg(feature = "transparent-inputs")]
        if self.transparent.is_some() {
            p2pkh = Require;
        }

        UnifiedAddressRequest::new(
            orchard,
            sapling,
            p2pkh,
            self.expiry_height,
            self.expiry_time,
        )
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use super::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;
    use zip32::AccountId;

    pub fn arb_unified_spending_key(params: Network) -> impl Strategy<Value = UnifiedSpendingKey> {
        prop::array::uniform32(prop::num::u8::ANY).prop_flat_map(move |seed| {
            prop::num::u32::ANY
                .prop_map(move |account| {
                    UnifiedSpendingKey::from_seed(
                        &params,
                        &seed,
                        AccountId::try_from(account & ((1 << 31) - 1)).unwrap(),
                    )
                })
                .prop_filter("seeds must generate valid USKs", |v| v.is_ok())
                .prop_map(|v| v.unwrap())
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::proptest;

    use zcash_protocol::consensus::MAIN_NETWORK;
    use zip32::AccountId;

    #[cfg(any(feature = "sapling", feature = "orchard"))]
    use {
        super::{UnifiedFullViewingKey, UnifiedIncomingViewingKey},
        zcash_address::unified::Encoding,
    };

    #[cfg(feature = "orchard")]
    use zip32::Scope;

    #[cfg(feature = "sapling")]
    use super::sapling;

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::encoding::AddressCodec,
        alloc::string::ToString,
        alloc::vec::Vec,
        transparent::keys::{AccountPrivKey, IncomingViewingKey},
    };

    #[cfg(all(feature = "unstable", any(feature = "sapling", feature = "orchard")))]
    use super::{testing::arb_unified_spending_key, Era, UnifiedSpendingKey};

    #[cfg(all(feature = "orchard", feature = "unstable"))]
    use subtle::ConstantTimeEq;

    #[cfg(feature = "transparent-inputs")]
    fn seed() -> Vec<u8> {
        let seed_hex = "6ef5f84def6f4b9d38f466586a8380a38593bd47c8cda77f091856176da47f26b5bd1c8d097486e5635df5a66e820d28e1d73346f499801c86228d43f390304f";
        hex::decode(seed_hex).unwrap()
    }

    #[test]
    #[should_panic]
    #[cfg(feature = "sapling")]
    fn spending_key_panics_on_short_seed() {
        let _ = sapling::spending_key(&[0; 31][..], 0, AccountId::ZERO);
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn pk_to_taddr() {
        use transparent::keys::NonHardenedChildIndex;

        let taddr = AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId::ZERO)
            .unwrap()
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap()
            .derive_address(NonHardenedChildIndex::ZERO)
            .unwrap()
            .encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }

    #[test]
    #[cfg(any(feature = "orchard", feature = "sapling"))]
    fn ufvk_round_trip() {
        #[cfg(feature = "orchard")]
        let orchard = {
            let sk =
                orchard::keys::SpendingKey::from_zip32_seed(&[0; 32], 0, AccountId::ZERO).unwrap();
            Some(orchard::keys::FullViewingKey::from(&sk))
        };

        #[cfg(feature = "sapling")]
        let sapling = {
            let extsk = sapling::spending_key(&[0; 32], 0, AccountId::ZERO);
            Some(extsk.to_diversifiable_full_viewing_key())
        };

        #[cfg(feature = "transparent-inputs")]
        let transparent = {
            let privkey =
                AccountPrivKey::from_seed(&MAIN_NETWORK, &[0; 32], AccountId::ZERO).unwrap();
            Some(privkey.to_account_pubkey())
        };

        let ufvk = UnifiedFullViewingKey::new(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            vec![],
            None,
            None,
            vec![],
        );

        let ufvk = ufvk.expect("Orchard or Sapling fvk is present.");
        let encoded = ufvk.encode(&MAIN_NETWORK);

        // Test encoded form against known values; these test vectors contain Orchard receivers
        // that will be treated as unknown if the `orchard` feature is not enabled.
        let encoded_with_t = "uview1tg6rpjgju2s2j37gkgjq79qrh5lvzr6e0ed3n4sf4hu5qd35vmsh7avl80xa6mx7ryqce9hztwaqwrdthetpy4pc0kce25x453hwcmax02p80pg5savlg865sft9reat07c5vlactr6l2pxtlqtqunt2j9gmvr8spcuzf07af80h5qmut38h0gvcfa9k4rwujacwwca9vu8jev7wq6c725huv8qjmhss3hdj2vh8cfxhpqcm2qzc34msyrfxk5u6dqttt4vv2mr0aajreww5yufpk0gn4xkfm888467k7v6fmw7syqq6cceu078yw8xja502jxr0jgum43lhvpzmf7eu5dmnn6cr6f7p43yw8znzgxg598mllewnx076hljlvynhzwn5es94yrv65tdg3utuz2u3sras0wfcq4adxwdvlk387d22g3q98t5z74quw2fa4wed32escx8dwh4mw35t4jwf35xyfxnu83mk5s4kw2glkgsshmxk";
        let _encoded_no_t = "uview12z384wdq76ceewlsu0esk7d97qnd23v2qnvhujxtcf2lsq8g4hwzpx44fwxssnm5tg8skyh4tnc8gydwxefnnm0hd0a6c6etmj0pp9jqkdsllkr70u8gpf7ndsfqcjlqn6dec3faumzqlqcmtjf8vp92h7kj38ph2786zx30hq2wru8ae3excdwc8w0z3t9fuw7mt7xy5sn6s4e45kwm0cjp70wytnensgdnev286t3vew3yuwt2hcz865y037k30e428dvgne37xvyeal2vu8yjnznphf9t2rw3gdp0hk5zwq00ws8f3l3j5n3qkqgsyzrwx4qzmgq0xwwk4vz2r6vtsykgz089jncvycmem3535zjwvvtvjw8v98y0d5ydwte575gjm7a7k";

        // We test the full roundtrip only with the `sapling` and `orchard` features enabled,
        // because we will not generate these parts of the encoding if the UFVK does not have an
        // these parts.
        #[cfg(all(feature = "sapling", feature = "orchard"))]
        {
            #[cfg(feature = "transparent-inputs")]
            assert_eq!(encoded, encoded_with_t);
            #[cfg(not(feature = "transparent-inputs"))]
            assert_eq!(encoded, _encoded_no_t);
        }

        let decoded = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &encoded).unwrap();
        let reencoded = decoded.encode(&MAIN_NETWORK);
        assert_eq!(encoded, reencoded);

        #[cfg(feature = "transparent-inputs")]
        assert_eq!(
            decoded.transparent.map(|t| t.serialize()),
            ufvk.transparent.as_ref().map(|t| t.serialize()),
        );
        #[cfg(feature = "sapling")]
        assert_eq!(
            decoded.sapling.map(|s| s.to_bytes()),
            ufvk.sapling.map(|s| s.to_bytes()),
        );
        #[cfg(feature = "orchard")]
        assert_eq!(
            decoded.orchard.map(|o| o.to_bytes()),
            ufvk.orchard.map(|o| o.to_bytes()),
        );

        let decoded_with_t = UnifiedFullViewingKey::decode(&MAIN_NETWORK, encoded_with_t).unwrap();
        #[cfg(feature = "transparent-inputs")]
        assert_eq!(
            decoded_with_t.transparent.map(|t| t.serialize()),
            ufvk.transparent.as_ref().map(|t| t.serialize()),
        );

        // Both Orchard and Sapling enabled
        #[cfg(all(
            feature = "orchard",
            feature = "sapling",
            feature = "transparent-inputs"
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 0);
        #[cfg(all(
            feature = "orchard",
            feature = "sapling",
            not(feature = "transparent-inputs")
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 1);

        // Orchard enabled
        #[cfg(all(
            feature = "orchard",
            not(feature = "sapling"),
            feature = "transparent-inputs"
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 1);
        #[cfg(all(
            feature = "orchard",
            not(feature = "sapling"),
            not(feature = "transparent-inputs")
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 2);

        // Sapling enabled
        #[cfg(all(
            not(feature = "orchard"),
            feature = "sapling",
            feature = "transparent-inputs"
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 1);
        #[cfg(all(
            not(feature = "orchard"),
            feature = "sapling",
            not(feature = "transparent-inputs")
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 2);
    }

    #[test]
    #[cfg(all(
        feature = "transparent-inputs",
        any(feature = "orchard", feature = "sapling")
    ))]
    fn ufvk_derivation() {
        use crate::{address::Address, keys::UnifiedAddressRequest};
        use zcash_address::test_vectors;
        use zip32::DiversifierIndex;

        use super::{ReceiverRequirement::*, UnifiedSpendingKey};

        for tv in test_vectors::UNIFIED {
            let usk = UnifiedSpendingKey::from_seed(
                &MAIN_NETWORK,
                &tv.root_seed,
                AccountId::try_from(tv.account).unwrap(),
            )
            .expect("seed produced a valid unified spending key");

            let d_idx = DiversifierIndex::from(tv.diversifier_index);
            let ufvk = usk.to_unified_full_viewing_key();

            // The test vectors contain some diversifier indices that do not generate
            // valid Sapling addresses, so skip those.
            #[cfg(feature = "sapling")]
            if ufvk.sapling().unwrap().address(d_idx).is_none() {
                continue;
            }

            let ua = ufvk
                .address(
                    d_idx,
                    Some(UnifiedAddressRequest::unsafe_new_without_expiry(
                        Omit, Require, Require,
                    )),
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "unified address generation failed for account {}: {:?}",
                        tv.account, err
                    )
                });

            match Address::decode(&MAIN_NETWORK, tv.unified_addr) {
                Some(Address::Unified(tvua)) => {
                    // We always derive transparent and Sapling receivers, but not
                    // every value in the test vectors has these present.
                    if tvua.has_transparent() {
                        assert_eq!(tvua.transparent(), ua.transparent());
                    }
                    #[cfg(feature = "sapling")]
                    if tvua.has_sapling() {
                        assert_eq!(tvua.sapling(), ua.sapling());
                    }
                }
                _other => {
                    panic!(
                        "{} did not decode to a valid unified address",
                        tv.unified_addr
                    );
                }
            }
        }
    }

    #[test]
    #[cfg(any(feature = "orchard", feature = "sapling"))]
    fn uivk_round_trip() {
        use zcash_protocol::consensus::NetworkType;

        #[cfg(feature = "orchard")]
        let orchard = {
            let sk =
                orchard::keys::SpendingKey::from_zip32_seed(&[0; 32], 0, AccountId::ZERO).unwrap();
            Some(orchard::keys::FullViewingKey::from(&sk).to_ivk(Scope::External))
        };

        #[cfg(feature = "sapling")]
        let sapling = {
            let extsk = sapling::spending_key(&[0; 32], 0, AccountId::ZERO);
            Some(extsk.to_diversifiable_full_viewing_key().to_external_ivk())
        };

        #[cfg(feature = "transparent-inputs")]
        let transparent = {
            let privkey =
                AccountPrivKey::from_seed(&MAIN_NETWORK, &[0; 32], AccountId::ZERO).unwrap();
            Some(privkey.to_account_pubkey().derive_external_ivk().unwrap())
        };

        let uivk = UnifiedIncomingViewingKey::new(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            vec![],
            None,
            None,
            vec![],
        )
        .unwrap();

        let encoded = uivk.render().encode(&NetworkType::Main);

        // Test encoded form against known values; these test vectors contain Orchard receivers
        // that will be treated as unknown if the `orchard` feature is not enabled.
        let encoded_with_t = "uivk1z28yg638vjwusmf0zc9ad2j0mpv6s42wc5kqt004aaqfu5xxxgu7mdcydn9qf723fnryt34s6jyxyw0jt7spq04c3v9ze6qe9gjjc5aglz8zv5pqtw58czd0actynww5n85z3052kzgy6cu0fyjafyp4sr4kppyrrwhwev2rr0awq6m8d66esvk6fgacggqnswg5g9gkv6t6fj9ajhyd0gmel4yzscprpzduncc0e2lywufup6fvzf6y8cefez2r99pgge5yyfuus0r60khgu895pln5e7nn77q6s9kh2uwf6lrfu06ma2kd7r05jjvl4hn6nupge8fajh0cazd7mkmz23t79w";
        let _encoded_no_t = "uivk1020vq9j5zeqxh303sxa0zv2hn9wm9fev8x0p8yqxdwyzde9r4c90fcglc63usj0ycl2scy8zxuhtser0qrq356xfy8x3vyuxu7f6gas75svl9v9m3ctuazsu0ar8e8crtx7x6zgh4kw8xm3q4rlkpm9er2wefxhhf9pn547gpuz9vw27gsdp6c03nwlrxgzhr2g6xek0x8l5avrx9ue9lf032tr7kmhqf3nfdxg7ldfgx6yf09g";

        // We test the full roundtrip only with the `sapling` and `orchard` features enabled,
        // because we will not generate these parts of the encoding if the UIVK does not have an
        // these parts.
        #[cfg(all(feature = "sapling", feature = "orchard"))]
        {
            #[cfg(feature = "transparent-inputs")]
            assert_eq!(encoded, encoded_with_t);
            #[cfg(not(feature = "transparent-inputs"))]
            assert_eq!(encoded, _encoded_no_t);
        }

        let decoded = UnifiedIncomingViewingKey::decode(&MAIN_NETWORK, &encoded).unwrap();
        let reencoded = decoded.render().encode(&NetworkType::Main);
        assert_eq!(encoded, reencoded);

        #[cfg(feature = "transparent-inputs")]
        assert_eq!(
            decoded.transparent.map(|t| t.serialize()),
            uivk.transparent.as_ref().map(|t| t.serialize()),
        );
        #[cfg(feature = "sapling")]
        assert_eq!(
            decoded.sapling.map(|s| s.to_bytes()),
            uivk.sapling.map(|s| s.to_bytes()),
        );
        #[cfg(feature = "orchard")]
        assert_eq!(
            decoded.orchard.map(|o| o.to_bytes()),
            uivk.orchard.map(|o| o.to_bytes()),
        );

        let decoded_with_t =
            UnifiedIncomingViewingKey::decode(&MAIN_NETWORK, encoded_with_t).unwrap();
        #[cfg(feature = "transparent-inputs")]
        assert_eq!(
            decoded_with_t.transparent.map(|t| t.serialize()),
            uivk.transparent.as_ref().map(|t| t.serialize()),
        );

        // Both Orchard and Sapling enabled
        #[cfg(all(
            feature = "orchard",
            feature = "sapling",
            feature = "transparent-inputs"
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 0);
        #[cfg(all(
            feature = "orchard",
            feature = "sapling",
            not(feature = "transparent-inputs")
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 1);

        // Orchard enabled
        #[cfg(all(
            feature = "orchard",
            not(feature = "sapling"),
            feature = "transparent-inputs"
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 1);
        #[cfg(all(
            feature = "orchard",
            not(feature = "sapling"),
            not(feature = "transparent-inputs")
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 2);

        // Sapling enabled
        #[cfg(all(
            not(feature = "orchard"),
            feature = "sapling",
            feature = "transparent-inputs"
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 1);
        #[cfg(all(
            not(feature = "orchard"),
            feature = "sapling",
            not(feature = "transparent-inputs")
        ))]
        assert_eq!(decoded_with_t.unknown_data.len(), 2);
    }

    #[test]
    #[cfg(all(
        feature = "transparent-inputs",
        any(feature = "sapling", feature = "orchard")
    ))]
    fn uivk_derivation() {
        use crate::{address::Address, keys::UnifiedAddressRequest};
        use zcash_address::test_vectors;
        use zip32::DiversifierIndex;

        use super::{ReceiverRequirement::*, UnifiedSpendingKey};

        for tv in test_vectors::UNIFIED {
            let usk = UnifiedSpendingKey::from_seed(
                &MAIN_NETWORK,
                &tv.root_seed,
                AccountId::try_from(tv.account).unwrap(),
            )
            .expect("seed produced a valid unified spending key");

            let d_idx = DiversifierIndex::from(tv.diversifier_index);
            let uivk = usk
                .to_unified_full_viewing_key()
                .to_unified_incoming_viewing_key();

            // The test vectors contain some diversifier indices that do not generate
            // valid Sapling addresses, so skip those.
            #[cfg(feature = "sapling")]
            if uivk.sapling().as_ref().unwrap().address_at(d_idx).is_none() {
                continue;
            }

            let ua = uivk
                .address(
                    d_idx,
                    Some(UnifiedAddressRequest::unsafe_new_without_expiry(
                        Omit, Require, Require,
                    )),
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "unified address generation failed for account {}: {:?}",
                        tv.account, err
                    )
                });

            match Address::decode(&MAIN_NETWORK, tv.unified_addr) {
                Some(Address::Unified(tvua)) => {
                    // We always derive transparent and Sapling receivers, but not
                    // every value in the test vectors has these present.
                    if tvua.has_transparent() {
                        assert_eq!(tvua.transparent(), ua.transparent());
                    }
                    #[cfg(feature = "sapling")]
                    if tvua.has_sapling() {
                        assert_eq!(tvua.sapling(), ua.sapling());
                    }
                }
                _other => {
                    panic!(
                        "{} did not decode to a valid unified address",
                        tv.unified_addr
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        #[cfg(all(feature = "unstable", any(feature = "orchard", feature = "sapling")))]
        fn prop_usk_roundtrip(usk in arb_unified_spending_key(zcash_protocol::consensus::Network::MainNetwork)) {
            let encoded = usk.to_bytes(Era::Orchard);

            #[allow(clippy::let_and_return)]
            let encoded_len = {
                let len = 4;

                #[cfg(feature = "orchard")]
                let len = len + 2 + 32;

                let len = len + 2 + 169;

                // Transparent part is an `xprv` transparent extended key deserialized
                // into bytes from Base58, minus the 4 prefix bytes.
                #[cfg(feature = "transparent-inputs")]
                let len = len + 2 + 74;

                #[allow(clippy::let_and_return)]
                len
            };
            assert_eq!(encoded.len(), encoded_len);

            let decoded = UnifiedSpendingKey::from_bytes(Era::Orchard, &encoded);
            let decoded = decoded.unwrap_or_else(|e| panic!("Error decoding USK: {:?}", e));

            #[cfg(feature = "orchard")]
            assert!(bool::from(decoded.orchard().ct_eq(usk.orchard())));

            #[cfg(feature = "sapling")]
            assert_eq!(decoded.sapling(), usk.sapling());

            #[cfg(feature = "transparent-inputs")]
            assert_eq!(decoded.transparent().to_bytes(), usk.transparent().to_bytes());
        }
    }
}
