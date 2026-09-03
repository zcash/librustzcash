//! Helper functions for managing light client key material.
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};
use nonempty::NonEmpty;
#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::keys::{IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope},
    core::convert::TryInto,
};

use zcash_address::unified::{self, Container, Encoding, MetadataItem, Typecode, Uitem};
use zcash_protocol::{PoolType, consensus};
use zip32::{AccountId, DiversifierIndex};

use crate::address::UnifiedAddress;

// The requirement combinators and the `ReceiverRequirements` constants below name these
// variants bare.
use ReceiverRequirement::*;

#[cfg(any(feature = "sapling", feature = "orchard"))]
use zcash_protocol::consensus::NetworkConstants;

#[cfg(all(
    feature = "transparent-inputs",
    any(test, feature = "test-dependencies")
))]
use ::transparent::address::TransparentAddress;

#[cfg(feature = "unstable")]
use {
    byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt},
    core::convert::TryFrom,
    corez::io::{Read, Write},
    zcash_encoding::CompactSize,
    zcash_protocol::consensus::BranchId,
};

#[cfg(feature = "orchard")]
use orchard::{self, keys::Scope};

#[cfg(all(feature = "sapling", feature = "unstable"))]
use ::sapling::zip32::ExtendedFullViewingKey;

#[cfg(test)]
pub(crate) mod test_vectors {
    pub(crate) mod unified_viewing_keys_r2;
}

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

#[cfg(any(feature = "transparent-key-encoding", feature = "transparent-inputs"))]
pub mod transparent;

#[cfg(feature = "zcashd-compat")]
pub mod zcashd;

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

#[derive(Debug)]
pub enum DerivationError {
    #[cfg(feature = "orchard")]
    Orchard(orchard::zip32::Error),
    #[cfg(feature = "transparent-inputs")]
    Transparent(bip32::Error),
}

impl Display for DerivationError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "orchard")]
            DerivationError::Orchard(e) => write!(_f, "Orchard error: {e}"),
            #[cfg(feature = "transparent-inputs")]
            DerivationError::Transparent(e) => write!(_f, "Transparent error: {e}"),
            #[cfg(not(any(feature = "orchard", feature = "transparent-inputs")))]
            other => {
                unreachable!("Unhandled DerivationError variant {:?}", other)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DerivationError {}

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
    /// The key data could not be decoded from its string representation to a valid key.
    KeyDataInvalid(Typecode),
}

impl core::fmt::Display for DecodingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "unstable")]
            DecodingError::ReadError(s) => write!(f, "Read error: {s}"),
            #[cfg(feature = "unstable")]
            DecodingError::EraInvalid => write!(f, "Invalid era"),
            #[cfg(feature = "unstable")]
            DecodingError::EraMismatch(e) => write!(f, "Era mismatch: actual {e:?}"),
            #[cfg(feature = "unstable")]
            DecodingError::TypecodeInvalid => write!(f, "Invalid typecode"),
            #[cfg(feature = "unstable")]
            DecodingError::LengthInvalid => write!(f, "Invalid length"),
            #[cfg(feature = "unstable")]
            DecodingError::LengthMismatch(t, l) => {
                write!(f, "Length mismatch: received {l} bytes for typecode {t:?}")
            }
            #[cfg(feature = "unstable")]
            DecodingError::InsufficientData(t) => {
                write!(f, "Insufficient data for typecode {t:?}")
            }
            DecodingError::KeyDataInvalid(t) => write!(f, "Invalid key data for key type {t:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodingError {}

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
#[derive(Clone)]
pub struct UnifiedSpendingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: ::transparent::keys::AccountPrivKey,
    #[cfg(feature = "sapling")]
    sapling: sapling::ExtendedSpendingKey,
    #[cfg(feature = "orchard")]
    orchard: orchard::keys::SpendingKey,
}

impl core::fmt::Debug for UnifiedSpendingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("UnifiedSpendingKey");
        #[cfg(feature = "transparent-inputs")]
        d.field("transparent", &"...");
        #[cfg(feature = "sapling")]
        d.field("sapling", &"...");
        #[cfg(feature = "orchard")]
        d.field("orchard", &"...");
        d.finish()
    }
}

impl UnifiedSpendingKey {
    pub fn from_seed<P: consensus::Parameters>(
        _params: &P,
        seed: &[u8],
        _account: AccountId,
    ) -> Result<UnifiedSpendingKey, DerivationError> {
        if seed.len() < 32 {
            panic!("ZIP 32 seeds MUST be at least 32 bytes");
        }

        UnifiedSpendingKey::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            ::transparent::keys::AccountPrivKey::from_seed(_params, seed, _account)
                .map_err(DerivationError::Transparent)?,
            #[cfg(feature = "sapling")]
            sapling::spending_key(seed, _params.coin_type(), _account),
            #[cfg(feature = "orchard")]
            orchard::keys::SpendingKey::from_zip32_seed(seed, _params.coin_type(), _account)
                .map_err(DerivationError::Orchard)?,
        )
    }

    /// Construct a USK from its constituent parts, after verifying that UIVK derivation can
    /// succeed.
    fn from_checked_parts(
        #[cfg(feature = "transparent-inputs")] transparent: ::transparent::keys::AccountPrivKey,
        #[cfg(feature = "sapling")] sapling: sapling::ExtendedSpendingKey,
        #[cfg(feature = "orchard")] orchard: orchard::keys::SpendingKey,
    ) -> Result<UnifiedSpendingKey, DerivationError> {
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
            p2sh: None,
            #[cfg(feature = "sapling")]
            sapling: Some(self.sapling.to_diversifiable_full_viewing_key()),
            #[cfg(feature = "orchard")]
            orchard: Some((&self.orchard).into()),
            unknown: vec![],
            expiry_height: None,
            expiry_time: None,
            unknown_metadata: vec![],
        }
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &::transparent::keys::AccountPrivKey {
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
        let mut source = corez::io::Cursor::new(encoded);
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
                .and_then(|v| Typecode::try_from(v).map_err(|_| DecodingError::TypecodeInvalid))?;

            let len = CompactSize::read_t::<_, u32>(&mut source)
                .map_err(|_| DecodingError::ReadError("key length"))?;

            match tc {
                Typecode::ORCHARD => {
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
                Typecode::SAPLING => {
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
                Typecode::P2PKH => {
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
                            ::transparent::keys::AccountPrivKey::from_bytes(&key)
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
                .map_err(|_| DecodingError::KeyDataInvalid(Typecode::P2PKH));
            }
        }
    }

    /// Returns the unified address corresponding to the smallest valid diversifier index,
    /// along with that diversifier index.
    ///
    /// See [`UnifiedFullViewingKey::default_address`] for additional details.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> (UnifiedAddress, DiversifierIndex) {
        self.to_unified_full_viewing_key()
            .default_address(request)
            .unwrap()
    }

    /// Returns the default external transparent address using the transparent account pubkey.
    ///
    /// See [`ExternalIvk::default_address`] for more information.
    ///
    /// [`ExternalIvk::default_address`]: ::transparent::keys::ExternalIvk::default_address
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
    /// The requested key scope is not supported for address derivation.
    #[cfg(feature = "transparent-inputs")]
    UnsupportedTransparentKeyScope(TransparentKeyScope),
    /// An error occurred in [`bip32`] derivation of a transparent address.
    #[cfg(feature = "transparent-inputs")]
    Bip32DerivationError(bip32::Error),
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
    /// The address request permits no receiver that the unified key being used to generate the
    /// address can provide.
    ///
    /// Omitting both shielded receiver types is permitted only for a key that has no shielded
    /// item; see [`ReceiverRequirements::TRANSPARENT_ONLY`].
    NoSatisfiableReceiver,
}

impl fmt::Display for AddressGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            #[cfg(feature = "transparent-inputs")]
            AddressGenerationError::InvalidTransparentChildIndex(i) => {
                write!(
                    f,
                    "Child index {i:?} does not generate a valid transparent receiver"
                )
            }
            #[cfg(feature = "transparent-inputs")]
            AddressGenerationError::UnsupportedTransparentKeyScope(i) => {
                write!(f, "Key scope {i:?} is not supported for key derivation")
            }
            #[cfg(feature = "transparent-inputs")]
            AddressGenerationError::Bip32DerivationError(e) => {
                write!(f, "{e}")
            }
            #[cfg(feature = "sapling")]
            AddressGenerationError::InvalidSaplingDiversifierIndex(i) => {
                write!(
                    f,
                    "Child index {i:?} does not generate a valid Sapling receiver"
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
                    "Unified Address generation does not yet support receivers of type {t:?}."
                )
            }
            AddressGenerationError::KeyNotAvailable(t) => {
                write!(
                    f,
                    "The Unified Viewing Key does not contain a key for typecode {t:?}."
                )
            }
            AddressGenerationError::NoSatisfiableReceiver => {
                write!(
                    f,
                    "The address request permits no receiver that this Unified Viewing Key can provide."
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddressGenerationError {}

#[cfg(feature = "transparent-inputs")]
impl From<bip32::Error> for AddressGenerationError {
    fn from(value: bip32::Error) -> Self {
        AddressGenerationError::Bip32DerivationError(value)
    }
}

/// An error type for failures in combining [`ReceiverRequirement`] values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverRequirementError {
    /// The two requirements are incompatible: one requires inclusion and the other requires
    /// omission.
    Conflict,
    /// A set of receiver requirements would not include any shielded receiver.
    ///
    /// See [`ReceiverRequirements::TRANSPARENT_ONLY`] for the one set of requirements that
    /// permits no shielded receiver.
    NoShieldedReceiver,
}

impl Display for ReceiverRequirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiverRequirementError::Conflict => {
                write!(f, "Require and Omit receiver requirements are incompatible")
            }
            ReceiverRequirementError::NoShieldedReceiver => {
                write!(
                    f,
                    "These receiver requirements must permit at least one shielded receiver"
                )
            }
        }
    }
}

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
    pub fn intersect(self, other: Self) -> Result<Self, ReceiverRequirementError> {
        match (self, other) {
            (Require, Omit) | (Omit, Require) => Err(ReceiverRequirementError::Conflict),
            (Require, Require) | (Require, Allow) | (Allow, Require) => Ok(Require),
            (Allow, Allow) => Ok(Allow),
            (Allow, Omit) | (Omit, Allow) | (Omit, Omit) => Ok(Omit),
        }
    }
}

/// Specification for how a unified address should be generated from a unified viewing key.
#[derive(Clone, Copy, Debug)]
pub enum UnifiedAddressRequest {
    AllAvailableKeys,
    Custom(ReceiverRequirements),
}

impl UnifiedAddressRequest {
    /// Constructs a new unified address request that allows a receiver of each type.
    pub const ALLOW_ALL: Self = Self::Custom(ReceiverRequirements::ALLOW_ALL);

    /// Constructs a new unified address request that allows only shielded receivers.
    pub const SHIELDED: Self = Self::Custom(ReceiverRequirements::SHIELDED);

    /// Constructs a new unified address request that requires an Orchard receiver and no others.
    pub const ORCHARD: Self = Self::Custom(ReceiverRequirements::ORCHARD);

    /// Constructs a new unified address request that requires a transparent P2PKH receiver and
    /// no others.
    ///
    /// See [`ReceiverRequirements::TRANSPARENT_ONLY`] for the constraints on the resulting
    /// address.
    pub const TRANSPARENT_ONLY: Self = Self::Custom(ReceiverRequirements::TRANSPARENT_ONLY);

    pub fn custom(
        orchard: ReceiverRequirement,
        sapling: ReceiverRequirement,
        p2pkh: ReceiverRequirement,
    ) -> Result<Self, ReceiverRequirementError> {
        ReceiverRequirements::new(orchard, sapling, p2pkh).map(UnifiedAddressRequest::Custom)
    }

    pub const fn unsafe_custom(
        orchard: ReceiverRequirement,
        sapling: ReceiverRequirement,
        p2pkh: ReceiverRequirement,
    ) -> Self {
        UnifiedAddressRequest::Custom(ReceiverRequirements::unsafe_new(orchard, sapling, p2pkh))
    }
}

/// Specification for how a unified address should be generated from a unified viewing key.
#[derive(Clone, Copy, Debug)]
pub struct ReceiverRequirements {
    orchard: ReceiverRequirement,
    sapling: ReceiverRequirement,
    p2pkh: ReceiverRequirement,
}

impl ReceiverRequirements {
    /// Construct a new unified address request from its constituent parts.
    ///
    /// Returns an error if the resulting unified address would not include at least one shielded
    /// receiver. A unified address containing only a transparent receiver cannot be requested
    /// this way; use [`Self::TRANSPARENT_ONLY`], which is applicable only to keys that have no
    /// shielded item at all.
    pub fn new(
        orchard: ReceiverRequirement,
        sapling: ReceiverRequirement,
        p2pkh: ReceiverRequirement,
    ) -> Result<Self, ReceiverRequirementError> {
        if orchard == Omit && sapling == Omit {
            Err(ReceiverRequirementError::NoShieldedReceiver)
        } else {
            Ok(Self {
                orchard,
                sapling,
                p2pkh,
            })
        }
    }

    /// Constructs a new unified address request that allows a receiver of each type.
    pub const ALLOW_ALL: ReceiverRequirements = { Self::unsafe_new(Allow, Allow, Allow) };

    /// Constructs a new unified address request that allows only shielded receivers.
    pub const SHIELDED: ReceiverRequirements = { Self::unsafe_new(Allow, Allow, Omit) };

    /// Constructs a new unified address request that requires an Orchard receiver, and no others.
    pub const ORCHARD: ReceiverRequirements = { Self::unsafe_new(Require, Omit, Omit) };

    /// Constructs a new unified address request that requires a transparent P2PKH receiver, and
    /// no others.
    ///
    /// An address satisfying these requirements has no shielded receiver, and so is
    /// representable only as a [ZIP 316] Revision 2 transparent-including (`tu`) unified
    /// address. Consequently this is the appropriate request only for a key that has no
    /// shielded item; requesting it from a key that has one produces an address that
    /// needlessly discards the recipient's shielded receiving capability. It is not reachable
    /// via [`Self::new`] or [`Self::unsafe_new`] for that reason.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const TRANSPARENT_ONLY: ReceiverRequirements = Self {
        orchard: Omit,
        sapling: Omit,
        p2pkh: Require,
    };

    /// Constructs a new unified address request that includes only the receivers that are allowed
    /// both in itself and a given other request. Returns an error if requirements are incompatible
    /// or if no shielded receiver type is allowed.
    ///
    /// Intersection preserves [`Omit`], so its result permits no shielded receiver only if at
    /// least one of the operands already permitted none. In that case the result is no less
    /// honest than the operand it came from and is returned; otherwise the shielded-receiver
    /// requirement of [`Self::new`] applies.
    ///
    /// This operation is commutative and idempotent, but it is not associative. The rule above
    /// inspects the operands and not only the meet, so an intermediate result that permits no
    /// shielded receiver can be rejected under one bracketing and admitted under another.
    ///
    /// [`Omit`]: ReceiverRequirement::Omit
    pub fn intersect(
        &self,
        other: &ReceiverRequirements,
    ) -> Result<ReceiverRequirements, ReceiverRequirementError> {
        let orchard = self.orchard.intersect(other.orchard)?;
        let sapling = self.sapling.intersect(other.sapling)?;
        let p2pkh = self.p2pkh.intersect(other.p2pkh)?;
        match (orchard, sapling, p2pkh) {
            (Omit, Omit, Require) if self.is_transparent_only() || other.is_transparent_only() => {
                Ok(Self::TRANSPARENT_ONLY)
            }
            _ => Self::new(orchard, sapling, p2pkh),
        }
    }

    /// Construct a new unified address request from its constituent parts.
    ///
    /// Panics: at least one of `orchard` or `sapling` must be allowed. Use
    /// [`Self::TRANSPARENT_ONLY`] to describe a key that has no shielded item.
    pub const fn unsafe_new(
        orchard: ReceiverRequirement,
        sapling: ReceiverRequirement,
        p2pkh: ReceiverRequirement,
    ) -> Self {
        if matches!(orchard, Omit) && matches!(sapling, Omit) {
            panic!("At least one shielded receiver must be allowed.")
        }

        Self {
            orchard,
            sapling,
            p2pkh,
        }
    }

    /// Returns whether these requirements permit no shielded receiver.
    fn is_transparent_only(&self) -> bool {
        self.orchard == Omit && self.sapling == Omit
    }

    /// Returns the [`ReceiverRequirement`] for inclusion of an Orchard receiver.
    pub fn orchard(&self) -> ReceiverRequirement {
        self.orchard
    }

    /// Returns the [`ReceiverRequirement`] for inclusion of a Sapling receiver.
    pub fn sapling(&self) -> ReceiverRequirement {
        self.sapling
    }

    /// Returns the [`ReceiverRequirement`] for inclusion of a P2PKH receiver.
    pub fn p2pkh(&self) -> ReceiverRequirement {
        self.p2pkh
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<bip32::Error> for DerivationError {
    fn from(e: bip32::Error) -> Self {
        DerivationError::Transparent(e)
    }
}

/// A key that provides the capability to recover outgoing transaction information from
/// the block chain.
#[derive(Clone, Copy)]
pub struct OutgoingViewingKey([u8; 32]);

impl core::fmt::Debug for OutgoingViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("OutgoingViewingKey").field(&"...").finish()
    }
}

impl From<[u8; 32]> for OutgoingViewingKey {
    fn from(ovk: [u8; 32]) -> Self {
        OutgoingViewingKey(ovk)
    }
}

#[cfg(feature = "sapling")]
impl From<OutgoingViewingKey> for ::sapling::keys::OutgoingViewingKey {
    fn from(value: OutgoingViewingKey) -> Self {
        ::sapling::keys::OutgoingViewingKey(value.0)
    }
}

#[cfg(feature = "sapling")]
impl From<::sapling::keys::OutgoingViewingKey> for OutgoingViewingKey {
    fn from(value: ::sapling::keys::OutgoingViewingKey) -> Self {
        OutgoingViewingKey(value.0)
    }
}

#[cfg(feature = "orchard")]
impl From<OutgoingViewingKey> for ::orchard::keys::OutgoingViewingKey {
    fn from(value: OutgoingViewingKey) -> Self {
        ::orchard::keys::OutgoingViewingKey::from(value.0)
    }
}

#[cfg(feature = "orchard")]
impl From<::orchard::keys::OutgoingViewingKey> for OutgoingViewingKey {
    fn from(value: ::orchard::keys::OutgoingViewingKey) -> Self {
        OutgoingViewingKey(*value.as_ref())
    }
}

impl AsRef<[u8; 32]> for OutgoingViewingKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A [ZIP 316](https://zips.z.cash/zip-0316) unified full viewing key.
#[derive(Clone)]
pub struct UnifiedFullViewingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<::transparent::keys::AccountPubKey>,
    p2sh: Option<P2shPolicy>,
    #[cfg(feature = "sapling")]
    sapling: Option<sapling::DiversifiableFullViewingKey>,
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::keys::FullViewingKey>,
    unknown: Vec<(u32, Vec<u8>)>,
    expiry_height: Option<consensus::BlockHeight>,
    expiry_time: Option<u64>,
    unknown_metadata: Vec<(u32, Vec<u8>)>,
}

/// The payload of a [ZIP 316] Revision 2 P2SH viewing key item: the canonical encoding
/// of a [BIP 388] wallet policy (a descriptor template and key information vector).
///
/// The payload is structurally validated when the containing unified viewing key is
/// parsed; the policy is not otherwise interpreted, and cannot yet be used for address
/// generation.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
/// [BIP 388]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki
#[derive(Clone, PartialEq, Eq)]
pub struct P2shPolicy(Vec<u8>);

impl P2shPolicy {
    /// Returns the canonical item encoding of this wallet policy.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for P2shPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("P2shPolicy").field(&"...").finish()
    }
}

/// Derives the UIVK form of a P2SH viewing key item from its UFVK form, rewriting the
/// descriptor template's `/**` multipath notation to `/*` and replacing each key
/// information entry with its external (index 0) non-hardened child, as specified in
/// [ZIP 316] Revision 2.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
#[cfg(feature = "transparent-inputs")]
fn derive_p2sh_ivk_policy(fvk_policy: &[u8]) -> Result<P2shPolicy, DerivationError> {
    /// The length of one key information entry: a 32-byte BIP 32 chain code followed by
    /// a 33-byte SEC1 compressed public key.
    const KEY_INFO_LEN: usize = 65;

    // The container framing was validated when the item was parsed, so framing reads
    // cannot fail here.
    let mut cursor = corez::io::Cursor::new(fvk_policy);
    let template_len = usize::try_from(
        zcash_encoding::CompactSize::read(&mut cursor)
            .expect("P2SH policy framing was validated at parse time"),
    )
    .expect("validated template length fits in usize");
    let template_start = usize::try_from(cursor.position()).expect("cursor fits in usize");
    let template = &fvk_policy[template_start..template_start + template_len];
    cursor.set_position((template_start + template_len) as u64);
    let n_keys = usize::try_from(
        zcash_encoding::CompactSize::read(&mut cursor)
            .expect("P2SH policy framing was validated at parse time"),
    )
    .expect("validated key count fits in usize");
    let keys_start = usize::try_from(cursor.position()).expect("cursor fits in usize");

    // In a structurally valid UFVK template, `/**` occurs exactly as the multipath
    // suffix of each key placeholder.
    let ivk_template = core::str::from_utf8(template)
        .expect("template was validated as US-ASCII at parse time")
        .replace("/**", "/*");

    // ZIP 316 requires the key information vector to be encoded in a deterministic
    // order; for ZIP 48 keys this is lexicographic by chain code and pubkey, so the
    // derived entries must be re-sorted rather than kept in the UFVK's order.
    let mut entries = Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        let entry: &[u8; KEY_INFO_LEN] = fvk_policy
            [keys_start + i * KEY_INFO_LEN..keys_start + (i + 1) * KEY_INFO_LEN]
            .try_into()
            .expect("P2SH policy framing was validated at parse time");
        let child = ::transparent::keys::AccountPubKey::deserialize(entry)
            .map_err(DerivationError::Transparent)?
            .derive_external_ivk()
            .map_err(DerivationError::Transparent)?;
        entries.push(child.serialize());
    }
    entries.sort_unstable();

    let mut result = vec![];
    zcash_encoding::CompactSize::write(&mut result, ivk_template.len())
        .expect("writing to a Vec cannot fail");
    result.extend_from_slice(ivk_template.as_bytes());
    zcash_encoding::CompactSize::write(&mut result, n_keys).expect("writing to a Vec cannot fail");
    for entry in entries {
        result.extend_from_slice(&entry);
    }

    Ok(P2shPolicy(result))
}

impl core::fmt::Debug for UnifiedFullViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("UnifiedFullViewingKey");
        #[cfg(feature = "transparent-inputs")]
        d.field("transparent", &self.transparent.as_ref().map(|_| "..."));
        d.field("p2sh", &self.p2sh);
        #[cfg(feature = "sapling")]
        d.field("sapling", &self.sapling.as_ref().map(|_| "..."));
        #[cfg(feature = "orchard")]
        d.field("orchard", &self.orchard.as_ref().map(|_| "..."));
        d.field(
            "unknown_typecodes",
            &self
                .unknown
                .iter()
                .map(|(typecode, _)| *typecode)
                .collect::<Vec<_>>(),
        )
        .field("expiry_height", &self.expiry_height)
        .field("expiry_time", &self.expiry_time)
        .field(
            "unknown_metadata_typecodes",
            &self
                .unknown_metadata
                .iter()
                .map(|(typecode, _)| *typecode)
                .collect::<Vec<_>>(),
        )
        .finish()
    }
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
            ::transparent::keys::AccountPubKey,
        >,
        #[cfg(feature = "sapling")] sapling: Option<sapling::DiversifiableFullViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::FullViewingKey>,
        // TODO: Implement construction of UFVKs with metadata items.
    ) -> Result<UnifiedFullViewingKey, DerivationError> {
        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            None,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            vec![],
            None,
            None,
            vec![],
        )
    }

    #[cfg(feature = "unstable-frost")]
    pub fn from_orchard_fvk(
        orchard: orchard::keys::FullViewingKey,
    ) -> Result<UnifiedFullViewingKey, DerivationError> {
        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            None,
            None,
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            Some(orchard),
            vec![],
            None,
            None,
            vec![],
        )
    }

    #[cfg(all(feature = "sapling", feature = "unstable"))]
    pub fn from_sapling_extended_full_viewing_key(
        sapling: ExtendedFullViewingKey,
    ) -> Result<UnifiedFullViewingKey, DerivationError> {
        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            None,
            None,
            #[cfg(feature = "sapling")]
            Some(sapling.to_diversifiable_full_viewing_key()),
            #[cfg(feature = "orchard")]
            None,
            vec![],
            None,
            None,
            vec![],
        )
    }

    /// Construct a UFVK from its constituent parts, after verifying that UIVK derivation can
    /// succeed.
    #[allow(clippy::too_many_arguments)]
    fn from_checked_parts(
        #[cfg(feature = "transparent-inputs")] transparent: Option<
            ::transparent::keys::AccountPubKey,
        >,
        p2sh: Option<P2shPolicy>,
        #[cfg(feature = "sapling")] sapling: Option<sapling::DiversifiableFullViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::FullViewingKey>,
        unknown: Vec<(u32, Vec<u8>)>,
        expiry_height: Option<consensus::BlockHeight>,
        expiry_time: Option<u64>,
        unknown_metadata: Vec<(u32, Vec<u8>)>,
    ) -> Result<UnifiedFullViewingKey, DerivationError> {
        // Verify that IVK derivation succeeds; we don't want to construct a UFVK
        // that can't derive transparent addresses.
        #[cfg(feature = "transparent-inputs")]
        let _ = transparent
            .as_ref()
            .map(|t| t.derive_external_ivk())
            .transpose()?;

        // Likewise verify that the UIVK form of the P2SH policy is derivable.
        #[cfg(feature = "transparent-inputs")]
        let _ = p2sh
            .as_ref()
            .map(|p| derive_p2sh_ivk_policy(p.as_bytes()))
            .transpose()?;

        Ok(UnifiedFullViewingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            p2sh,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown,
            expiry_height,
            expiry_time,
            unknown_metadata,
        })
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn decode<P: consensus::Parameters>(params: &P, encoding: &str) -> Result<Self, String> {
        let (net, _revision, ufvk) = unified::Ufvk::decode(encoding).map_err(|e| e.to_string())?;
        let expected_net = params.network_type();
        if net != expected_net {
            return Err(format!(
                "UFVK is for network {net:?} but we expected {expected_net:?}",
            ));
        }

        Self::parse(&ufvk).map_err(|e| e.to_string())
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn parse(ufvk: &unified::Ufvk) -> Result<Self, DecodingError> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        let mut p2sh = None;
        let mut unknown = vec![];
        let mut expiry_height = None;
        let mut expiry_time = None;
        let mut unknown_metadata = vec![];

        for item in ufvk.items_as_parsed() {
            match item {
                Uitem::Data(unified::Fvk::Orchard(data)) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            orchard::keys::FullViewingKey::from_bytes(data)
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::ORCHARD))?,
                        );
                    }
                    #[cfg(not(feature = "orchard"))]
                    unknown.push((u32::from(unified::Typecode::ORCHARD), data.to_vec()));
                }
                Uitem::Data(unified::Fvk::Sapling(data)) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            sapling::DiversifiableFullViewingKey::from_bytes(data)
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::SAPLING))?,
                        );
                    }
                    #[cfg(not(feature = "sapling"))]
                    unknown.push((u32::from(unified::Typecode::SAPLING), data.to_vec()));
                }
                Uitem::Data(unified::Fvk::P2pkh(data)) => {
                    #[cfg(feature = "transparent-inputs")]
                    {
                        transparent = Some(
                            ::transparent::keys::AccountPubKey::deserialize(data)
                                .map_err(|_| DecodingError::KeyDataInvalid(Typecode::P2PKH))?,
                        );
                    }
                    #[cfg(not(feature = "transparent-inputs"))]
                    unknown.push((u32::from(unified::Typecode::P2PKH), data.to_vec()));
                }
                Uitem::Data(unified::Fvk::P2sh(data)) => {
                    p2sh = Some(P2shPolicy(data.clone()));
                }
                Uitem::Data(unified::Fvk::Unknown { typecode, data }) => {
                    unknown.push((*typecode, data.clone()));
                }
                Uitem::Metadata(MetadataItem::ExpiryHeight(h)) => {
                    expiry_height = Some(consensus::BlockHeight::from_u32(*h));
                }
                Uitem::Metadata(MetadataItem::ExpiryTime(t)) => {
                    expiry_time = Some(*t);
                }
                Uitem::Metadata(MetadataItem::Unknown { typecode, data }) => {
                    unknown_metadata.push((*typecode, data.clone()));
                }
            }
        }

        Self::from_checked_parts(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            p2sh,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown,
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
    fn to_ufvk(&self) -> unified::Ufvk {
        // ZIP 316 recommends that producers upgrade to Revision 2 as soon as
        // possible. We use R2 unconditionally here.
        let revision = unified::Revision::R2;

        let data_items = core::iter::empty().chain(self.unknown.iter().map(|(typecode, data)| {
            unified::Fvk::Unknown {
                typecode: *typecode,
                data: data.clone(),
            }
        }));
        let data_items = data_items.chain(
            self.p2sh
                .as_ref()
                .map(|p| unified::Fvk::P2sh(p.as_bytes().to_vec())),
        );
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

        let meta_items = core::iter::empty()
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

        unified::Ufvk::try_from_items(
            revision,
            data_items
                .map(Uitem::Data)
                .chain(meta_items.map(Uitem::Metadata))
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
            p2sh: {
                #[cfg(feature = "transparent-inputs")]
                {
                    self.p2sh.as_ref().map(|p| {
                        derive_p2sh_ivk_policy(p.as_bytes())
                            .expect("P2SH IVK derivation was checked at construction.")
                    })
                }
                // Deriving the UIVK form of a P2SH item requires the transparent key
                // machinery; without it the item cannot be carried over.
                #[cfg(not(feature = "transparent-inputs"))]
                None
            },
            #[cfg(feature = "sapling")]
            sapling: self.sapling.as_ref().map(|s| s.to_external_ivk()),
            #[cfg(feature = "orchard")]
            orchard: self.orchard.as_ref().map(|o| o.to_ivk(Scope::External)),
            expiry_height: self.expiry_height,
            expiry_time: self.expiry_time,
            // An item that this build cannot interpret has no derivable incoming viewing key
            // form, so it cannot be carried over. Record its typecode: the derived key is a
            // lossy description of the account, and callers that describe the account from it
            // must not present it as complete.
            unknown: Vec::new(),
            unconverted_typecodes: self.unknown.iter().map(|(typecode, _)| *typecode).collect(),
            unknown_metadata: vec![],
        }
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> Option<&::transparent::keys::AccountPubKey> {
        self.transparent.as_ref()
    }

    /// Returns the P2SH viewing key item of this unified key, if present.
    pub fn p2sh(&self) -> Option<&P2shPolicy> {
        self.p2sh.as_ref()
    }

    /// Returns the Sapling diversifiable full viewing key component of this unified key.
    #[cfg(feature = "sapling")]
    pub fn sapling(&self) -> Option<&sapling::DiversifiableFullViewingKey> {
        self.sapling.as_ref()
    }

    /// Returns the Orchard full viewing key component of this unified key.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> Option<&orchard::keys::FullViewingKey> {
        self.orchard.as_ref()
    }

    /// Returns whether this key has a Sapling component.
    pub fn has_sapling(&self) -> bool {
        #[cfg(feature = "sapling")]
        return self.sapling.is_some();
        #[cfg(not(feature = "sapling"))]
        return false;
    }

    /// Returns whether this key has an Orchard component.
    pub fn has_orchard(&self) -> bool {
        #[cfg(feature = "orchard")]
        return self.orchard.is_some();
        #[cfg(not(feature = "orchard"))]
        return false;
    }

    /// Returns the expiry height metadata for this key, if present.
    pub fn expiry_height(&self) -> Option<consensus::BlockHeight> {
        self.expiry_height
    }

    /// Returns the expiry time metadata for this key, if present.
    pub fn expiry_time(&self) -> Option<u64> {
        self.expiry_time
    }

    /// Returns `true` if this UFVK subsumes the given UIVK: every IVK item present in
    /// `other` has a matching item derivable from `self`. The UFVK may have additional
    /// items representing capabilities not present in the UIVK.
    pub fn subsumes_uivk(&self, other: &UnifiedIncomingViewingKey) -> bool {
        self.to_unified_incoming_viewing_key().subsumes(other)
    }

    /// Returns `true` if this UFVK subsumes `other`: every FVK item in `other` has a
    /// matching item in `self`, including both incoming and outgoing viewing capability.
    ///
    /// For unknown items, exact equality of (typecode, data) is required.
    pub fn subsumes_ufvk(&self, other: &UnifiedFullViewingKey) -> bool {
        #[cfg(feature = "orchard")]
        match (&other.orchard, &self.orchard) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        #[cfg(feature = "sapling")]
        match (&other.sapling, &self.sapling) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        #[cfg(feature = "transparent-inputs")]
        match (&other.transparent, &self.transparent) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        match (&other.p2sh, &self.p2sh) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        // Every unknown item in `other` must have an identical entry in `self`.
        for item in &other.unknown {
            if !self.unknown.contains(item) {
                return false;
            }
        }

        true
    }

    /// Attempts to derive the Unified Address for the given diversifier index and receiver types.
    ///
    /// Returns `None` if the specified index does not produce a valid diversifier.
    pub fn address(
        &self,
        j: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<UnifiedAddress, AddressGenerationError> {
        self.to_unified_incoming_viewing_key().address(j, request)
    }

    /// Searches the diversifier space starting at diversifier index `j` for one which will produce
    /// a valid diversifier, and return the Unified Address constructed using that diversifier
    /// along with the index at which the valid diversifier was found.
    ///
    /// Returns an `Err(AddressGenerationError)` if no valid diversifier exists or if the features
    /// required to satisfy the unified address request are not properly enabled.
    pub fn find_address(
        &self,
        j: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.to_unified_incoming_viewing_key()
            .find_address(j, request)
    }

    /// Find the Unified Address corresponding to the smallest valid diversifier index, along with
    /// that index.
    ///
    /// Returns an `Err(AddressGenerationError)` if no valid diversifier exists or if the features
    /// required to satisfy the unified address request are not properly enabled.
    pub fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.find_address(DiversifierIndex::new(), request)
    }

    /// Returns the default external transparent address using the transparent account pubkey.
    ///
    /// See [`ExternalIvk::default_address`] for more information.
    ///
    /// [`ExternalIvk::default_address`]: ::transparent::keys::ExternalIvk::default_address
    #[cfg(all(
        feature = "transparent-inputs",
        any(test, feature = "test-dependencies")
    ))]
    pub fn default_transparent_address(
        &self,
    ) -> Option<(TransparentAddress, NonHardenedChildIndex)> {
        self.transparent().map(|k| {
            k.derive_external_ivk()
                .expect("ability to derive the external IVK was checked at construction")
                .default_address()
        })
    }

    /// Selects an outgoing viewing key for a transaction's outputs based upon the type(s) of
    /// inputs spent in the transaction.
    ///
    /// This method selects the OVK of the highest-preference item in [ZIP 316] preference order
    /// from among the item types represented by the provided input types. It will return `None` in
    /// the case that this FVK does not contain any items corresponding to the provided input
    /// sources; this should ordinarily never occur because in order to spend an input, a spending
    /// key of the appropriate type must be available and that spending key should be represented
    /// among this UFVK's items.
    pub fn select_ovk(
        &self,
        scope: zip32::Scope,
        input_sources: &NonEmpty<PoolType>,
    ) -> Option<OutgoingViewingKey> {
        #[cfg(feature = "orchard")]
        if let Some(ovk) = input_sources
            .contains(&PoolType::ORCHARD)
            .then(|| {
                self.orchard()
                    .map(|k| OutgoingViewingKey::from(k.to_ovk(scope)))
            })
            .flatten()
        {
            return Some(ovk);
        };

        #[cfg(feature = "sapling")]
        if let Some(ovk) = input_sources
            .contains(&PoolType::SAPLING)
            .then(|| {
                self.sapling()
                    .map(|k| OutgoingViewingKey::from(k.to_ovk(scope)))
            })
            .flatten()
        {
            return Some(ovk);
        }

        #[cfg(feature = "transparent-inputs")]
        if let Some(ovk) = input_sources
            .contains(&PoolType::Transparent)
            .then(|| {
                self.transparent().map(|k| {
                    OutgoingViewingKey(match scope {
                        zip32::Scope::External => k.external_ovk().as_bytes(),
                        zip32::Scope::Internal => k.internal_ovk().as_bytes(),
                    })
                })
            })
            .flatten()
        {
            return Some(ovk);
        }

        None
    }
}

/// A [ZIP 316](https://zips.z.cash/zip-0316) unified incoming viewing key.
#[derive(Clone)]
pub struct UnifiedIncomingViewingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<::transparent::keys::ExternalIvk>,
    p2sh: Option<P2shPolicy>,
    #[cfg(feature = "sapling")]
    sapling: Option<::sapling::zip32::IncomingViewingKey>,
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::keys::IncomingViewingKey>,
    unknown: Vec<(u32, Vec<u8>)>,
    /// The typecodes of the data items of the full viewing key that this key was derived from
    /// that could not be carried over, because this build cannot interpret them.
    ///
    /// These items are not part of this key's encoding, and take no part in equality or
    /// subsumption. They record only that the account has receiving capability that this key
    /// does not describe.
    unconverted_typecodes: Vec<u32>,
    expiry_height: Option<consensus::BlockHeight>,
    expiry_time: Option<u64>,
    unknown_metadata: Vec<(u32, Vec<u8>)>,
}

impl core::fmt::Debug for UnifiedIncomingViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("UnifiedIncomingViewingKey");
        #[cfg(feature = "transparent-inputs")]
        d.field("transparent", &self.transparent);
        d.field("p2sh", &self.p2sh);
        #[cfg(feature = "sapling")]
        d.field("sapling", &self.sapling.as_ref().map(|_| "..."));
        #[cfg(feature = "orchard")]
        d.field("orchard", &self.orchard.as_ref().map(|_| "..."));
        d.field(
            "unknown_typecodes",
            &self
                .unknown
                .iter()
                .map(|(typecode, _)| *typecode)
                .collect::<Vec<_>>(),
        )
        .field("unconverted_typecodes", &self.unconverted_typecodes)
        .field("expiry_height", &self.expiry_height)
        .field("expiry_time", &self.expiry_time)
        .field(
            "unknown_metadata_typecodes",
            &self
                .unknown_metadata
                .iter()
                .map(|(typecode, _)| *typecode)
                .collect::<Vec<_>>(),
        )
        .finish()
    }
}

impl PartialEq for UnifiedIncomingViewingKey {
    fn eq(&self, other: &Self) -> bool {
        self.subsumes(other) && other.subsumes(self)
    }
}

impl Eq for UnifiedIncomingViewingKey {}

impl UnifiedIncomingViewingKey {
    /// Construct a new unified incoming viewing key.
    ///
    /// This method is only available when the `test-dependencies` feature is enabled,
    /// as derivation from the UFVK or deserialization from the serialized form should
    /// be used instead.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn new(
        #[cfg(feature = "transparent-inputs")] transparent: Option<
            ::transparent::keys::ExternalIvk,
        >,
        #[cfg(feature = "sapling")] sapling: Option<::sapling::zip32::IncomingViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::IncomingViewingKey>,
        unknown: Vec<(u32, Vec<u8>)>,
        expiry_height: Option<consensus::BlockHeight>,
        expiry_time: Option<u64>,
        unknown_metadata: Vec<(u32, Vec<u8>)>,
    ) -> UnifiedIncomingViewingKey {
        UnifiedIncomingViewingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            p2sh: None,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown,
            unconverted_typecodes: vec![],
            expiry_height,
            expiry_time,
            unknown_metadata,
        }
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn decode<P: consensus::Parameters>(params: &P, encoding: &str) -> Result<Self, String> {
        let (net, _revision, uivk) = unified::Uivk::decode(encoding).map_err(|e| e.to_string())?;
        let expected_net = params.network_type();
        if net != expected_net {
            return Err(format!(
                "UIVK is for network {net:?} but we expected {expected_net:?}",
            ));
        }

        Self::parse(&uivk).map_err(|e| e.to_string())
    }

    /// Constructs a unified incoming viewing key from a parsed unified encoding.
    fn parse(uivk: &unified::Uivk) -> Result<Self, DecodingError> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        let mut p2sh = None;
        let mut unknown = vec![];
        let mut expiry_height = None;
        let mut expiry_time = None;
        let mut unknown_metadata = vec![];

        for item in uivk.items_as_parsed() {
            match item {
                Uitem::Data(unified::Ivk::Orchard(data)) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::from(orchard::keys::IncomingViewingKey::from_bytes(data))
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::ORCHARD))?,
                        );
                    }
                    #[cfg(not(feature = "orchard"))]
                    unknown.push((u32::from(unified::Typecode::ORCHARD), data.to_vec()));
                }
                Uitem::Data(unified::Ivk::Sapling(data)) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            Option::from(::sapling::zip32::IncomingViewingKey::from_bytes(data))
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::SAPLING))?,
                        );
                    }
                    #[cfg(not(feature = "sapling"))]
                    unknown.push((u32::from(unified::Typecode::SAPLING), data.to_vec()));
                }
                Uitem::Data(unified::Ivk::P2pkh(data)) => {
                    #[cfg(feature = "transparent-inputs")]
                    {
                        transparent = Some(
                            ::transparent::keys::ExternalIvk::deserialize(data)
                                .map_err(|_| DecodingError::KeyDataInvalid(Typecode::P2PKH))?,
                        );
                    }
                    #[cfg(not(feature = "transparent-inputs"))]
                    unknown.push((u32::from(unified::Typecode::P2PKH), data.to_vec()));
                }
                Uitem::Data(unified::Ivk::P2sh(data)) => {
                    p2sh = Some(P2shPolicy(data.clone()));
                }
                Uitem::Data(unified::Ivk::Unknown { typecode, data }) => {
                    unknown.push((*typecode, data.clone()));
                }
                Uitem::Metadata(MetadataItem::ExpiryHeight(h)) => {
                    expiry_height = Some(consensus::BlockHeight::from_u32(*h));
                }
                Uitem::Metadata(MetadataItem::ExpiryTime(t)) => {
                    expiry_time = Some(*t);
                }
                Uitem::Metadata(MetadataItem::Unknown { typecode, data }) => {
                    unknown_metadata.push((*typecode, data.clone()));
                }
            }
        }

        Ok(Self {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            p2sh,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown,
            // A parsed key keeps every item that it cannot interpret in `unknown`, and so
            // describes itself completely.
            unconverted_typecodes: vec![],
            expiry_height,
            expiry_time,
            unknown_metadata,
        })
    }

    /// Returns the string encoding of this `UnifiedIncomingViewingKey` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.render().encode(&params.network_type())
    }

    /// Converts this unified incoming viewing key to a unified encoding.
    fn render(&self) -> unified::Uivk {
        // ZIP 316 recommends that producers upgrade to Revision 2 as soon as
        // possible. We use R2 unconditionally here.
        let revision = unified::Revision::R2;

        let data_items = core::iter::empty().chain(self.unknown.iter().map(|(typecode, data)| {
            unified::Ivk::Unknown {
                typecode: *typecode,
                data: data.clone(),
            }
        }));
        let data_items = data_items.chain(
            self.p2sh
                .as_ref()
                .map(|p| unified::Ivk::P2sh(p.as_bytes().to_vec())),
        );
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

        let meta_items = core::iter::empty()
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

        unified::Uivk::try_from_items(
            revision,
            data_items
                .map(Uitem::Data)
                .chain(meta_items.map(Uitem::Metadata))
                .collect(),
        )
        .expect("UnifiedIncomingViewingKey should only be constructed safely.")
    }

    /// Returns whether this uivk has a transparent key item.
    ///
    /// This method is available irrespective of whether the `transparent-inputs` feature flag is enabled.
    pub fn has_transparent(&self) -> bool {
        #[cfg(not(feature = "transparent-inputs"))]
        return false;
        #[cfg(feature = "transparent-inputs")]
        return self.transparent.is_some();
    }

    /// Returns the Transparent external IVK, if present.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &Option<::transparent::keys::ExternalIvk> {
        &self.transparent
    }

    /// Returns the P2SH viewing key item of this key, if present.
    pub fn p2sh(&self) -> Option<&P2shPolicy> {
        self.p2sh.as_ref()
    }

    /// Returns whether this uivk has a Sapling key item.
    ///
    /// This method is available irrespective of whether the `sapling` feature flag is enabled.
    pub fn has_sapling(&self) -> bool {
        #[cfg(not(feature = "sapling"))]
        return false;
        #[cfg(feature = "sapling")]
        return self.sapling.is_some();
    }

    /// Returns the Sapling IVK, if present.
    #[cfg(feature = "sapling")]
    pub fn sapling(&self) -> &Option<::sapling::zip32::IncomingViewingKey> {
        &self.sapling
    }

    /// Returns whether this uivk has an Orchard key item.
    ///
    /// This method is available irrespective of whether the `orchard` feature flag is enabled.
    pub fn has_orchard(&self) -> bool {
        #[cfg(not(feature = "orchard"))]
        return false;
        #[cfg(feature = "orchard")]
        return self.orchard.is_some();
    }

    /// Returns the Orchard IVK, if present.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> &Option<orchard::keys::IncomingViewingKey> {
        &self.orchard
    }

    /// Returns the expiry height metadata for this key, if present.
    pub fn expiry_height(&self) -> Option<consensus::BlockHeight> {
        self.expiry_height
    }

    /// Returns the expiry time metadata for this key, if present.
    pub fn expiry_time(&self) -> Option<u64> {
        self.expiry_time
    }

    /// Returns `true` if this UIVK subsumes `other`: every IVK item present in `other`
    /// has a matching item in `self`. This key may have additional items representing
    /// capabilities not present in `other`.
    ///
    /// For unknown items, exact equality of (typecode, data) is required. Future
    /// revisions may apply more specific semantics for known metadata typecodes.
    pub fn subsumes(&self, other: &UnifiedIncomingViewingKey) -> bool {
        #[cfg(feature = "orchard")]
        match (other.orchard(), &self.orchard) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        #[cfg(feature = "sapling")]
        match (other.sapling(), &self.sapling) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        #[cfg(feature = "transparent-inputs")]
        match (other.transparent(), &self.transparent) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        match (&other.p2sh, &self.p2sh) {
            (Some(e), Some(n)) if e != n => {
                return false;
            }
            (Some(_), None) => return false,
            _ => {}
        }

        // Every unknown item in `other` must have an identical entry in `self`.
        for item in &other.unknown {
            if !self.unknown.contains(item) {
                return false;
            }
        }

        true
    }

    /// Attempts to derive the Unified Address for the given diversifier index and receiver types.
    ///
    /// Returns an error if the this key does not produce a valid receiver for a required receiver
    /// type at the given diversifier index.
    pub fn address(
        &self,
        _j: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<UnifiedAddress, AddressGenerationError> {
        let request = self
            .receiver_requirements(request)
            .map_err(|_| AddressGenerationError::NoSatisfiableReceiver)?;

        // If we need to generate a transparent receiver, check that the user has not
        // specified an invalid transparent child index, from which we can never search to
        // find a valid index.
        #[cfg(feature = "transparent-inputs")]
        if request.p2pkh == ReceiverRequirement::Require
            && self.transparent.is_some()
            && to_transparent_child_index(_j).is_none()
        {
            return Err(AddressGenerationError::InvalidTransparentChildIndex(_j));
        }

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

        UnifiedAddress::from_receivers(
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "sapling")]
            sapling,
            transparent,
            self.expiry_height,
            self.expiry_time,
        )
        .ok_or(AddressGenerationError::NoSatisfiableReceiver)
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
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        // Only a Sapling receiver can reject a diversifier index, so only that configuration
        // has to search.
        #[cfg(feature = "sapling")]
        loop {
            match self.address(j, request) {
                Ok(ua) => return Ok((ua, j)),
                Err(AddressGenerationError::InvalidSaplingDiversifierIndex(_)) => {
                    if j.increment().is_err() {
                        return Err(AddressGenerationError::DiversifierSpaceExhausted);
                    }
                }
                Err(other) => return Err(other),
            }
        }

        #[cfg(not(feature = "sapling"))]
        self.address(j, request).map(|ua| (ua, j))
    }

    /// Find the Unified Address corresponding to the smallest valid diversifier index, along with
    /// that index.
    ///
    /// Returns an error if the this key does not produce a valid receiver for a required receiver
    /// type at any diversifier index.
    pub fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.find_address(DiversifierIndex::new(), request)
    }

    /// Attempts to recover a diversifier index for each of the receivers of the given
    /// [`UnifiedAddress`].
    ///
    /// Returns the empty set if no shielded receiver of `ua` can be attributed to this key.
    /// Transparent receivers are not considered here, as recovering a diversifier index from a
    /// transparent receiver alone is not possible without additional context.
    pub fn decrypt_diversifiers(&self, ua: &UnifiedAddress) -> BTreeSet<DiversifierIndex> {
        #[cfg(not(any(feature = "sapling", feature = "orchard")))]
        let _ = ua;

        #[cfg(not(feature = "sapling"))]
        let sapling_di: Option<DiversifierIndex> = None;

        #[cfg(feature = "sapling")]
        let sapling_di = ua
            .sapling()
            .zip(self.sapling().as_ref())
            .and_then(|(receiver, ivk)| ivk.decrypt_diversifier(receiver));

        #[cfg(not(feature = "orchard"))]
        let orchard_di: Option<DiversifierIndex> = None;

        #[cfg(feature = "orchard")]
        let orchard_di = ua
            .orchard()
            .zip(self.orchard().as_ref())
            .and_then(|(receiver, ivk)| ivk.diversifier_index(receiver));

        sapling_di.into_iter().chain(orchard_di).collect()
    }

    /// Convenience method for choosing a set of receiver requirements based upon the given unified
    /// address request and the available items of this key.
    ///
    /// Returns an error if the provided request cannot be satisfied in address generation using
    /// this key.
    pub fn receiver_requirements(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<ReceiverRequirements, AddressGenerationError> {
        match request {
            UnifiedAddressRequest::AllAvailableKeys => self
                .to_receiver_requirements()
                .map_err(|_| AddressGenerationError::NoSatisfiableReceiver),
            UnifiedAddressRequest::Custom(req) => {
                if req.orchard() == Require && !self.has_orchard() {
                    return Err(AddressGenerationError::ReceiverTypeNotSupported(
                        Typecode::ORCHARD,
                    ));
                }

                if req.sapling() == Require && !self.has_sapling() {
                    return Err(AddressGenerationError::ReceiverTypeNotSupported(
                        Typecode::SAPLING,
                    ));
                }

                if req.p2pkh() == Require && !self.has_transparent() {
                    return Err(AddressGenerationError::ReceiverTypeNotSupported(
                        Typecode::P2PKH,
                    ));
                }

                Ok(req)
            }
        }
    }

    /// Returns whether this key has a data item that this build cannot interpret.
    ///
    /// An item of a pool whose feature is disabled and an item of a pool that postdates this
    /// crate are both uninterpretable, and either may be a shielded receiver.
    fn has_uninterpretable_data_item(&self) -> bool {
        !self.unknown.is_empty() || !self.unconverted_typecodes.is_empty()
    }

    /// Constructs the [`ReceiverRequirements`] that requires a receiver for each data item of this UIVK.
    ///
    /// A key that has nothing but a transparent item describes a transparent-only account, and
    /// yields [`ReceiverRequirements::TRANSPARENT_ONLY`]; addresses generated from it are
    /// representable as [ZIP 316] Revision 2 transparent-including (`tu`) unified addresses.
    ///
    /// Returns an error if this key has no item for which a receiver can be derived, and also
    /// if the only receiver it can derive is transparent but the key has a data item that this
    /// build cannot interpret. A metadata item never prevents address generation.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn to_receiver_requirements(
        &self,
    ) -> Result<ReceiverRequirements, ReceiverRequirementError> {
        let orchard = if self.has_orchard() { Require } else { Omit };
        let sapling = if self.has_sapling() { Require } else { Omit };
        let p2pkh = if self.has_transparent() {
            Require
        } else {
            Omit
        };

        match (orchard, sapling, p2pkh) {
            // Omitting the shielded receivers is the honest description of a key that has
            // nothing but a transparent item, so `ReceiverRequirements::new`'s
            // shielded-receiver requirement, which guards against callers discarding a key's
            // shielded capability, does not apply here.
            //
            // `TRANSPARENT_ONLY` silently omits receivers, so it is sound only for a key that
            // provably has nothing but transparent. A data item that this build cannot
            // interpret defeats that proof: the item may be a shielded receiver, and a
            // transparent-only address would discard the recipient's shielded receiving
            // capability. Fall through instead, and let the ordinary error surface.
            (Omit, Omit, Require) if !self.has_uninterpretable_data_item() => {
                Ok(ReceiverRequirements::TRANSPARENT_ONLY)
            }
            _ => ReceiverRequirements::new(orchard, sapling, p2pkh),
        }
    }

    /// Returns the default external transparent address using the transparent account pubkey.
    ///
    /// See [`ExternalIvk::default_address`] for more information.
    ///
    /// [`ExternalIvk::default_address`]: ::transparent::keys::ExternalIvk::default_address
    #[cfg(all(
        feature = "transparent-inputs",
        any(test, feature = "test-dependencies")
    ))]
    pub fn default_transparent_address(
        &self,
    ) -> Option<(TransparentAddress, NonHardenedChildIndex)> {
        self.transparent.as_ref().map(|k| k.default_address())
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

    #[cfg(all(
        feature = "transparent-inputs",
        any(feature = "orchard", feature = "sapling")
    ))]
    use {
        super::ReceiverRequirement::*,
        crate::{address::Address, keys::UnifiedAddressRequest},
        zcash_address::test_vectors,
        zip32::DiversifierIndex,
    };

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::encoding::AddressCodec,
        ::transparent::keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex},
        alloc::{string::ToString, vec::Vec},
    };

    use zcash_protocol::consensus::MAIN_NETWORK;
    use zip32::AccountId;

    #[cfg(any(feature = "sapling", feature = "orchard"))]
    use super::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};

    #[cfg(all(
        feature = "orchard",
        feature = "sapling",
        feature = "transparent-inputs"
    ))]
    use {
        crate::address::UnifiedAddress,
        zcash_address::unified::{self, Encoding},
    };

    #[cfg(feature = "orchard")]
    use zip32::Scope;

    #[cfg(feature = "sapling")]
    use super::sapling;

    // `UnifiedSpendingKey` is used both by the `unstable` serialization tests and by the
    // derivation tests, which are enabled by a different set of features.
    #[cfg(any(
        feature = "unstable",
        all(
            feature = "transparent-inputs",
            any(feature = "orchard", feature = "sapling")
        )
    ))]
    use super::UnifiedSpendingKey;

    #[cfg(feature = "unstable")]
    use super::{Era, testing::arb_unified_spending_key};

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

    /// Tests UFVK encoding round-trip and verification against R2 test vectors from
    /// https://github.com/zcash/zcash-test-vectors/blob/667c92954acd7defc6e60e25b022fedf8831dfb3/test-vectors/rust/unified_viewing_keys_r2.rs
    #[test]
    #[cfg(all(
        feature = "orchard",
        feature = "sapling",
        feature = "transparent-inputs"
    ))]
    fn ufvk_round_trip() {
        use super::test_vectors::unified_viewing_keys_r2::TEST_VECTORS;

        for tv in TEST_VECTORS {
            let ufvk =
                UnifiedFullViewingKey::decode(&MAIN_NETWORK, tv.unified_fvk).unwrap_or_else(|e| {
                    panic!("Failed to decode UFVK for account {}: {e}", tv.account)
                });

            let reencoded = ufvk.encode(&MAIN_NETWORK);
            assert_eq!(
                reencoded, tv.unified_fvk,
                "UFVK round-trip failed for account {}",
                tv.account
            );

            assert_eq!(
                ufvk.expiry_height(),
                tv.expiry_height
                    .map(zcash_protocol::consensus::BlockHeight::from_u32),
                "expiry height mismatch for account {}",
                tv.account
            );
            assert_eq!(
                ufvk.expiry_time(),
                tv.expiry_time,
                "expiry time mismatch for account {}",
                tv.account
            );

            // Verify key data matches the test vector bytes.
            if let Some(ref expected) = tv.t_p2pkh_fvk_bytes {
                let actual = ufvk
                    .transparent()
                    .expect("transparent key present in test vector")
                    .serialize();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "transparent FVK mismatch for account {}",
                    tv.account
                );
            }

            if let Some(ref expected) = tv.sapling_fvk_bytes {
                let actual = ufvk
                    .sapling()
                    .expect("sapling key present in test vector")
                    .to_bytes();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "sapling FVK mismatch for account {}",
                    tv.account
                );
            }

            if let Some(ref expected) = tv.orchard_fvk_bytes {
                let actual = ufvk
                    .orchard()
                    .expect("orchard key present in test vector")
                    .to_bytes();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "orchard FVK mismatch for account {}",
                    tv.account
                );
            }

            assert_eq!(
                ufvk.p2sh().map(|p| p.as_bytes()),
                tv.p2sh_fvk_bytes,
                "P2SH FVK item mismatch for account {}",
                tv.account
            );

            // The UIVK form of the P2SH item derived from the UFVK must match the
            // vector's UIVK item.
            let derived_uivk = ufvk.to_unified_incoming_viewing_key();
            assert_eq!(
                derived_uivk.p2sh().map(|p| p.as_bytes()),
                tv.p2sh_ivk_bytes,
                "derived P2SH IVK item mismatch for account {}",
                tv.account
            );
        }
    }

    #[test]
    #[cfg(all(
        feature = "transparent-inputs",
        any(feature = "orchard", feature = "sapling")
    ))]
    fn ufvk_derivation() {
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
                    UnifiedAddressRequest::unsafe_custom(Omit, Require, Require),
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

    /// Tests UIVK encoding round-trip and verification against R2 test vectors from
    /// https://github.com/zcash/zcash-test-vectors/blob/667c92954acd7defc6e60e25b022fedf8831dfb3/test-vectors/rust/unified_viewing_keys_r2.rs
    #[test]
    #[cfg(all(
        feature = "orchard",
        feature = "sapling",
        feature = "transparent-inputs"
    ))]
    fn uivk_round_trip() {
        use super::test_vectors::unified_viewing_keys_r2::TEST_VECTORS;
        use zcash_protocol::consensus::NetworkType;

        for tv in TEST_VECTORS {
            let decoded =
                UnifiedIncomingViewingKey::parse(&unified::Uivk::decode(tv.unified_ivk).unwrap().2)
                    .unwrap_or_else(|e| {
                        panic!("Failed to decode UIVK for account {}: {e}", tv.account)
                    });

            let reencoded = decoded.render().encode(&NetworkType::Main);
            assert_eq!(
                reencoded, tv.unified_ivk,
                "UIVK round-trip failed for account {}",
                tv.account
            );

            // ZIP 316 requires the source UFVK's expiry metadata to be retained
            // unmodified in the derived UIVK.
            assert_eq!(
                decoded.expiry_height(),
                tv.expiry_height
                    .map(zcash_protocol::consensus::BlockHeight::from_u32),
                "expiry height mismatch for account {}",
                tv.account
            );
            assert_eq!(
                decoded.expiry_time(),
                tv.expiry_time,
                "expiry time mismatch for account {}",
                tv.account
            );

            // The Unified Address derived from the decoded UIVK must match the vector.
            // Deriving the transparent receiver of a P2SH viewing key item requires
            // evaluating its BIP 388 wallet policy, which this crate does not yet do, so
            // the addresses of such keys cannot yet be checked against the vectors.
            // TODO: assert these vectors too, once P2SH receiver derivation is supported.
            if tv.p2sh_ivk_bytes.is_none() {
                let ua = decoded
                    .address(
                        DiversifierIndex::from(tv.diversifier_index),
                        UnifiedAddressRequest::AllAvailableKeys,
                    )
                    .unwrap_or_else(|e| {
                        panic!("UA derivation failed for account {}: {e:?}", tv.account)
                    });
                assert_eq!(
                    ua.encode_receiver_preserving(&MAIN_NETWORK),
                    tv.derived_ua,
                    "derived UA mismatch for account {}",
                    tv.account
                );
            }

            // Verify key data matches the test vector bytes.
            if let Some(ref expected) = tv.t_p2pkh_ivk_bytes {
                let actual = decoded
                    .transparent
                    .as_ref()
                    .expect("transparent key present in test vector")
                    .serialize();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "transparent IVK mismatch for account {}",
                    tv.account
                );
            }

            if let Some(ref expected) = tv.sapling_ivk_bytes {
                let actual = decoded
                    .sapling
                    .as_ref()
                    .expect("sapling key present in test vector")
                    .to_bytes();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "sapling IVK mismatch for account {}",
                    tv.account
                );
            }

            if let Some(ref expected) = tv.orchard_ivk_bytes {
                let actual = decoded
                    .orchard
                    .as_ref()
                    .expect("orchard key present in test vector")
                    .to_bytes();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "orchard IVK mismatch for account {}",
                    tv.account
                );
            }

            assert_eq!(
                decoded.p2sh().map(|p| p.as_bytes()),
                tv.p2sh_ivk_bytes,
                "P2SH IVK item mismatch for account {}",
                tv.account
            );
        }
    }

    #[test]
    #[cfg(all(
        feature = "transparent-inputs",
        any(feature = "orchard", feature = "sapling")
    ))]
    fn uivk_derivation() {
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
                    UnifiedAddressRequest::unsafe_custom(Omit, Require, Require),
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
        #[cfg(feature = "unstable")]
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

            assert_eq!(decoded.sapling(), usk.sapling());

            #[cfg(feature = "transparent-inputs")]
            assert_eq!(decoded.transparent().to_bytes(), usk.transparent().to_bytes());
        }
    }

    #[test]
    #[cfg(all(
        feature = "sapling",
        feature = "orchard",
        feature = "transparent-inputs"
    ))]
    fn uivk_decrypt_diversifier_matches_own_ua_and_rejects_foreign() {
        let ufvk_a = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &[1u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        let ufvk_b = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &[2u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();

        let (ua_a, mut di_a) = ufvk_a
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();

        // The UIVK for A recovers the diversifier index used to derive A's own UA.
        let uivk_a = ufvk_a.to_unified_incoming_viewing_key();
        let ua_a_dis = uivk_a.decrypt_diversifiers(&ua_a);
        assert_eq!(ua_a_dis.len(), 1);
        assert_eq!(ua_a_dis.first(), Some(di_a).as_ref());

        // The UIVK for B, which did not derive A's UA, returns None.
        let uivk_b = ufvk_b.to_unified_incoming_viewing_key();
        assert_eq!(uivk_b.decrypt_diversifiers(&ua_a).len(), 0);

        // A frankenstein UA combining A's Sapling receiver with B's Orchard receiver is
        // attributed to A (matched via Sapling, tried first).
        let (ua_b, di_b) = ufvk_b
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        let franken = UnifiedAddress::from_receivers(
            Some(*ua_b.orchard().unwrap()),
            Some(*ua_a.sapling().unwrap()),
            None,
            None,
            None,
        )
        .unwrap();

        let franken_dis_a = uivk_a.decrypt_diversifiers(&franken);
        assert_eq!(franken_dis_a.len(), 1);
        assert_eq!(franken_dis_a.first(), Some(di_a).as_ref());

        let franken_dis_b = uivk_b.decrypt_diversifiers(&franken);
        assert_eq!(franken_dis_b.len(), 1);
        assert_eq!(franken_dis_b.first(), Some(di_b).as_ref());

        di_a.increment()
            .expect("diversifier space is not exhausted");
        let (next_ua_a, _) = ufvk_a
            .find_address(di_a, UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        let mixed_ua = UnifiedAddress::from_receivers(
            Some(*ua_a.orchard().unwrap()),
            Some(*next_ua_a.sapling().unwrap()),
            None,
            None,
            None,
        )
        .unwrap();
        let mixed_dis_a = uivk_a.decrypt_diversifiers(&mixed_ua);
        assert_eq!(mixed_dis_a.len(), 2);
    }

    /// A key with no shielded item describes a transparent-only account, and generates
    /// transparent-only ZIP 316 Revision 2 (`tu`) Unified Addresses.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_only_key_generates_tu_address() {
        use super::{
            ReceiverRequirement::{Omit, Require},
            UnifiedAddressRequest,
        };
        use crate::address::UnifiedAddress;
        use zcash_protocol::consensus::NetworkConstants;

        let account_pubkey = AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId::ZERO)
            .unwrap()
            .to_account_pubkey();
        let ufvk = super::UnifiedFullViewingKey::new(
            Some(account_pubkey),
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
        )
        .unwrap();
        let uivk = ufvk.to_unified_incoming_viewing_key();

        let requirements = uivk
            .to_receiver_requirements()
            .expect("a transparent item is a receiver requirement");
        assert_eq!(requirements.orchard(), Omit);
        assert_eq!(requirements.sapling(), Omit);
        assert_eq!(requirements.p2pkh(), Require);

        let (ufvk_addr, _) = ufvk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .expect("a transparent-only key has a default address");
        let (uivk_addr, _) = uivk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .expect("a transparent-only key has a default address");
        assert_eq!(ufvk_addr, uivk_addr);

        assert!(ufvk_addr.has_transparent());
        assert!(!ufvk_addr.has_sapling());
        assert!(!ufvk_addr.has_orchard());
        assert_eq!(
            ufvk_addr.transparent(),
            ufvk.default_transparent_address()
                .map(|(addr, _)| addr)
                .as_ref()
        );

        // The address is encoded using the Revision 2 transparent-including HRP, and
        // round-trips through that encoding.
        let encoded = ufvk_addr.encode(&MAIN_NETWORK);
        assert!(
            encoded.starts_with(MAIN_NETWORK.hrp_unified_address_r2_ti()),
            "{encoded} is not a transparent-including Revision 2 Unified Address",
        );
        assert_eq!(
            UnifiedAddress::decode(&MAIN_NETWORK, &encoded).as_ref(),
            Ok(&ufvk_addr)
        );
    }

    /// A key that has a transparent item and a data item that this build cannot interpret is
    /// not transparent-only: the uninterpretable item may be a shielded receiver, so no
    /// address can be generated for all of the key's items.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn key_with_uninterpretable_data_item_is_not_transparent_only() {
        use super::{
            AddressGenerationError,
            ReceiverRequirement::{Omit, Require},
            ReceiverRequirementError, UnifiedAddressRequest,
        };
        use zcash_protocol::consensus::BlockHeight;

        // A data typecode that this crate does not know. Metadata typecodes start at 0xC0, so
        // this is a data item: a pool that postdates this crate.
        const FUTURE_POOL_TYPECODE: u32 = 0x04;

        let account_privkey =
            AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId::ZERO).unwrap();
        let account_pubkey = account_privkey.to_account_pubkey();
        let transparent_ivk = account_pubkey.derive_external_ivk().unwrap();

        // The incoming viewing key form, which keeps an uninterpretable item in `unknown`.
        let uivk = super::UnifiedIncomingViewingKey::new(
            Some(transparent_ivk.clone()),
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
            vec![(FUTURE_POOL_TYPECODE, vec![0u8; 32])],
            None,
            None,
            vec![],
        );

        assert_eq!(
            uivk.to_receiver_requirements().err(),
            Some(ReceiverRequirementError::NoShieldedReceiver)
        );
        assert!(matches!(
            uivk.default_address(UnifiedAddressRequest::AllAvailableKeys),
            Err(AddressGenerationError::NoSatisfiableReceiver)
        ));

        // The full viewing key form. Deriving its incoming viewing key cannot carry the
        // uninterpretable item over, so the derived key must record that it is incomplete;
        // otherwise every consumer that describes an account through that derivation, as
        // wallet backends do, sees a transparent-only key.
        let ufvk = super::UnifiedFullViewingKey::from_checked_parts(
            Some(account_pubkey),
            None,
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
            vec![(FUTURE_POOL_TYPECODE, vec![0u8; 32])],
            None,
            None,
            vec![],
        )
        .unwrap();

        assert_eq!(
            ufvk.to_unified_incoming_viewing_key()
                .to_receiver_requirements()
                .err(),
            Some(ReceiverRequirementError::NoShieldedReceiver)
        );
        assert!(matches!(
            ufvk.default_address(UnifiedAddressRequest::AllAvailableKeys),
            Err(AddressGenerationError::NoSatisfiableReceiver)
        ));

        // Metadata items are not receivers, so they never prevent address generation.
        let with_metadata = super::UnifiedIncomingViewingKey::new(
            Some(transparent_ivk),
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
            vec![],
            Some(BlockHeight::from_u32(1_000_000)),
            Some(1730506496),
            vec![(0xC5, vec![0u8; 4])],
        );

        let requirements = with_metadata
            .to_receiver_requirements()
            .expect("metadata items do not prevent address generation");
        assert_eq!(requirements.orchard(), Omit);
        assert_eq!(requirements.sapling(), Omit);
        assert_eq!(requirements.p2pkh(), Require);
    }

    /// Decoding a genuine Orchard-and-transparent UFVK in a build that cannot interpret Orchard
    /// keeps the Orchard item, and so must not describe the key as transparent-only.
    #[test]
    #[cfg(all(
        feature = "sapling",
        feature = "transparent-inputs",
        not(feature = "orchard")
    ))]
    fn orchard_and_transparent_ufvk_is_not_transparent_only_without_orchard() {
        use super::test_vectors::unified_viewing_keys_r2::TEST_VECTORS;
        use super::{AddressGenerationError, UnifiedAddressRequest};

        let mut checked = 0;
        for tv in TEST_VECTORS {
            if tv.orchard_fvk_bytes.is_none()
                || tv.sapling_fvk_bytes.is_some()
                || tv.t_p2pkh_fvk_bytes.is_none()
            {
                continue;
            }
            checked += 1;

            let ufvk =
                UnifiedFullViewingKey::decode(&MAIN_NETWORK, tv.unified_fvk).unwrap_or_else(|e| {
                    panic!("Failed to decode UFVK for account {}: {e}", tv.account)
                });

            // The Orchard item is still part of the key: it re-encodes byte-identically.
            assert_eq!(
                ufvk.encode(&MAIN_NETWORK),
                tv.unified_fvk,
                "UFVK round-trip failed for account {}",
                tv.account
            );

            assert!(
                matches!(
                    ufvk.default_address(UnifiedAddressRequest::AllAvailableKeys),
                    Err(AddressGenerationError::NoSatisfiableReceiver)
                ),
                "account {} produced an address that discards its Orchard receiver",
                tv.account
            );
        }

        assert!(
            checked > 0,
            "no test vector has an Orchard item, a transparent item, and no Sapling item"
        );
    }

    /// Requirements that permit no shielded receiver cannot arise from constructing a request
    /// or from intersecting two requests; [`ReceiverRequirements::TRANSPARENT_ONLY`] is the
    /// only way to name them.
    #[test]
    #[cfg(all(feature = "transparent-inputs", feature = "sapling"))]
    fn shielded_less_requirements_unreachable_by_construction_or_intersection() {
        use super::{
            ReceiverRequirement::{Allow, Omit, Require},
            ReceiverRequirementError, ReceiverRequirements, UnifiedAddressRequest,
        };

        let account_pubkey = AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId::ZERO)
            .unwrap()
            .to_account_pubkey();
        let ufvk = super::UnifiedFullViewingKey::new(
            Some(account_pubkey),
            Some(
                sapling::spending_key(&seed(), 1, AccountId::ZERO)
                    .to_diversifiable_full_viewing_key(),
            ),
            #[cfg(feature = "orchard")]
            None,
        )
        .unwrap();
        let uivk = ufvk.to_unified_incoming_viewing_key();

        // The requirements derived from the key require its Sapling receiver.
        let requirements = uivk.to_receiver_requirements().unwrap();
        assert_eq!(requirements.sapling(), Require);

        // A shielded-less request cannot be constructed through the ordinary request path.
        assert_eq!(
            UnifiedAddressRequest::custom(Omit, Omit, Require).err(),
            Some(ReceiverRequirementError::NoShieldedReceiver)
        );
        assert_eq!(
            ReceiverRequirements::new(Omit, Omit, Require).err(),
            Some(ReceiverRequirementError::NoShieldedReceiver)
        );

        // Nor can it be reached by intersection with the key's own requirements.
        assert_eq!(
            requirements
                .intersect(&ReceiverRequirements::TRANSPARENT_ONLY)
                .err(),
            Some(ReceiverRequirementError::Conflict)
        );

        // Intersection does not introduce a shielded-less requirement from two operands that
        // each permit a shielded receiver ...
        assert_eq!(
            ReceiverRequirements::unsafe_new(Omit, Allow, Allow)
                .intersect(&ReceiverRequirements::unsafe_new(Allow, Omit, Allow))
                .err(),
            Some(ReceiverRequirementError::NoShieldedReceiver)
        );

        // ... but preserves it when an operand is already transparent-only.
        let intersected = ReceiverRequirements::TRANSPARENT_ONLY
            .intersect(&ReceiverRequirements::ALLOW_ALL)
            .expect("a transparent-only operand keeps the intersection transparent-only");
        assert_eq!(intersected.orchard(), Omit);
        assert_eq!(intersected.sapling(), Omit);
        assert_eq!(intersected.p2pkh(), Require);

        // The address generated for all of the key's available items retains the Sapling
        // receiver.
        let (addr, _) = ufvk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        assert!(addr.has_sapling());
        assert!(addr.has_transparent());

        // `TRANSPARENT_ONLY` is a deliberate escape hatch: requesting it against a key that
        // has a shielded item is documented misuse, not a rejected request.
        let (addr, _) = ufvk
            .default_address(UnifiedAddressRequest::TRANSPARENT_ONLY)
            .unwrap();
        assert!(!addr.has_sapling());
        assert!(addr.has_transparent());
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn usk_debug_redaction() {
        let seed = [0u8; 64];
        let usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, AccountId::ZERO).unwrap();
        assert!(format!("{usk:?}").contains("\"...\""));
    }

    #[test]
    #[cfg(any(feature = "orchard", feature = "sapling"))]
    fn ufvk_debug_redaction() {
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
        )
        .unwrap();

        let debug_str = format!("{ufvk:?}");
        #[cfg(feature = "transparent-inputs")]
        assert!(debug_str.contains("transparent: Some(\"...\")"));
        #[cfg(feature = "sapling")]
        assert!(debug_str.contains("sapling: Some(\"...\")"));
        #[cfg(feature = "orchard")]
        assert!(debug_str.contains("orchard: Some(\"...\")"));
    }

    #[test]
    #[cfg(any(feature = "orchard", feature = "sapling"))]
    fn uivk_debug_redaction() {
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
        );

        let debug_str = format!("{uivk:?}");
        #[cfg(feature = "sapling")]
        assert!(debug_str.contains("sapling: Some(\"...\")"));
        #[cfg(feature = "orchard")]
        assert!(debug_str.contains("orchard: Some(\"...\")"));
    }

    #[test]
    fn ovk_debug_redaction() {
        assert_eq!(
            format!("{:?}", super::OutgoingViewingKey::from([0u8; 32])),
            "OutgoingViewingKey(\"...\")"
        );
    }

    #[cfg(any(feature = "sapling", feature = "orchard"))]
    #[test]
    fn subsumes_ufvk_same_key() {
        let seed = vec![0u8; 32];
        let usk =
            super::UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        // A UFVK subsumes itself.
        assert!(ufvk.subsumes_ufvk(&ufvk));
    }

    #[cfg(any(feature = "sapling", feature = "orchard"))]
    #[test]
    fn subsumes_uivk_from_same_ufvk() {
        let seed = vec![0u8; 32];
        let usk =
            super::UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let uivk = ufvk.to_unified_incoming_viewing_key();

        // A UFVK subsumes the UIVK derived from it.
        assert!(ufvk.subsumes_uivk(&uivk));
    }

    #[cfg(all(feature = "sapling", feature = "orchard"))]
    #[test]
    fn subsumes_ufvk_subset() {
        let seed = vec![0u8; 32];
        let usk =
            super::UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        // A UFVK with all components subsumes one with fewer components.
        let subset_ufvk = UnifiedFullViewingKey::new(
            #[cfg(feature = "transparent-inputs")]
            None,
            ufvk.sapling().cloned(),
            None, // no Orchard
        )
        .unwrap();
        assert!(ufvk.subsumes_ufvk(&subset_ufvk));
        // The subset does not subsume the full key.
        assert!(!subset_ufvk.subsumes_ufvk(&ufvk));
    }

    #[cfg(any(feature = "sapling", feature = "orchard"))]
    #[test]
    fn subsumes_ufvk_different_keys() {
        let seed0 = vec![0u8; 32];
        let seed1 = vec![1u8; 32];
        let usk0 =
            super::UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed0, AccountId::ZERO).unwrap();
        let usk1 =
            super::UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed1, AccountId::ZERO).unwrap();
        let ufvk0 = usk0.to_unified_full_viewing_key();
        let ufvk1 = usk1.to_unified_full_viewing_key();

        // UFVKs from different seeds do not subsume each other.
        assert!(!ufvk0.subsumes_ufvk(&ufvk1));
        assert!(!ufvk1.subsumes_ufvk(&ufvk0));
    }
}
