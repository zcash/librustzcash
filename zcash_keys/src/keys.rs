//! Helper functions for managing light client key material.
use blake2b_simd::Params as blake2bParams;
use secrecy::{ExposeSecret, SecretVec};
use std::{
    error,
    fmt::{self, Display},
};

use zcash_address::unified::{self, Container, Encoding, Typecode, Ufvk, Uivk};
use zcash_protocol::{consensus, ShieldedProtocol};
use zip32::{AccountId, DiversifierIndex};

use crate::address::UnifiedAddress;

#[cfg(feature = "transparent-inputs")]
use {
    std::convert::TryInto,
    zcash_primitives::legacy::keys::{self as legacy, IncomingViewingKey, NonHardenedChildIndex},
};

#[cfg(any(feature = "sapling", feature = "orchard"))]
// Your code here
use zcash_protocol::consensus::NetworkConstants;

#[cfg(all(
    feature = "transparent-inputs",
    any(test, feature = "test-dependencies")
))]
use zcash_primitives::legacy::TransparentAddress;

#[cfg(feature = "unstable")]
use {
    byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt},
    std::convert::TryFrom,
    std::io::{Read, Write},
    zcash_encoding::CompactSize,
    zcash_primitives::consensus::BranchId,
};

#[cfg(feature = "orchard")]
use orchard::{self, keys::Scope};

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
    /// use zcash_primitives::constants::testnet::COIN_TYPE;
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

/// A [ZIP 32 seed fingerprint] of a seed used for an HD account.
///
/// For wallets that use [BIP 39] mnemonic phrases, this is the fingerprint of the binary
/// seed [produced from the mnemonic].
///
/// [ZIP 32 seed fingerprint]: https://zips.z.cash/zip-0032#seed-fingerprints
/// [BIP 39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
/// [produced from the mnemonic]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HdSeedFingerprint([u8; 32]);

impl HdSeedFingerprint {
    /// Generates the fingerprint from a given seed.
    ///
    /// Panics if the length of the seed is not between 32 and 252 bytes inclusive.
    pub fn from_seed(seed: &SecretVec<u8>) -> Self {
        let len = seed.expose_secret().len();
        let len = match len {
            32..=252 => [u8::try_from(len).unwrap()],
            _ => panic!("ZIP 32 seeds MUST be at least 32 bytes and at most 252 bytes"),
        };
        const PERSONALIZATION: &[u8] = b"Zcash_HD_Seed_FP";
        let hash = blake2bParams::new()
            .hash_length(32)
            .personal(PERSONALIZATION)
            .to_state()
            .update(&len)
            .update(seed.expose_secret())
            .finalize();
        Self(
            hash.as_bytes()
                .try_into()
                .expect("BLAKE2b-256 hash length is 32 bytes"),
        )
    }

    /// Instantiates the fingerprint from a buffer containing a previously computed fingerprint.
    pub fn from_bytes(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Returns the bytes of the fingerprint.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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

#[derive(Debug)]
#[doc(hidden)]
pub enum DerivationError {
    InvalidShieldedKey(ShieldedProtocol),
    #[cfg(feature = "orchard")]
    Orchard(orchard::zip32::Error),
    #[cfg(feature = "transparent-inputs")]
    Transparent(hdwallet::error::Error),
}

impl Display for DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerivationError::InvalidShieldedKey(protocol) => {
                write!(f, "Invalid shielded key for protocol {:?}", protocol)
            }
            #[cfg(feature = "orchard")]
            DerivationError::Orchard(e) => write!(f, "Orchard error: {}", e),
            #[cfg(feature = "transparent-inputs")]
            DerivationError::Transparent(e) => write!(f, "Transparent error: {}", e),
        }
    }
}

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
#[cfg(feature = "unstable")]
#[derive(Debug, PartialEq, Eq)]
pub enum DecodingError {
    ReadError(&'static str),
    EraInvalid,
    EraMismatch(Era),
    TypecodeInvalid,
    LengthInvalid,
    LengthMismatch(Typecode, u32),
    InsufficientData(Typecode),
    KeyDataInvalid(Typecode),
}

#[cfg(feature = "unstable")]
impl std::fmt::Display for DecodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodingError::ReadError(s) => write!(f, "Read error: {}", s),
            DecodingError::EraInvalid => write!(f, "Invalid era"),
            DecodingError::EraMismatch(e) => write!(f, "Era mismatch: actual {:?}", e),
            DecodingError::TypecodeInvalid => write!(f, "Invalid typecode"),
            DecodingError::LengthInvalid => write!(f, "Invalid length"),
            DecodingError::LengthMismatch(t, l) => {
                write!(
                    f,
                    "Length mismatch: received {} bytes for typecode {:?}",
                    l, t
                )
            }
            DecodingError::InsufficientData(t) => {
                write!(f, "Insufficient data for typecode {:?}", t)
            }
            DecodingError::KeyDataInvalid(t) => write!(f, "Invalid key data for typecode {:?}", t),
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
#[doc(hidden)]
pub struct UnifiedSpendingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: legacy::AccountPrivKey,
    #[cfg(feature = "sapling")]
    sapling: sapling::ExtendedSpendingKey,
    #[cfg(feature = "orchard")]
    orchard: orchard::keys::SpendingKey,
}

#[doc(hidden)]
impl UnifiedSpendingKey {
    pub fn from_seed<P: consensus::Parameters>(
        _params: &P,
        seed: &[u8],
        _account: AccountId,
    ) -> Result<UnifiedSpendingKey, DerivationError> {
        if seed.len() < 32 {
            panic!("ZIP 32 seeds MUST be at least 32 bytes");
        }

        Ok(UnifiedSpendingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent: legacy::AccountPrivKey::from_seed(_params, seed, _account)
                .map_err(DerivationError::Transparent)?,
            #[cfg(feature = "sapling")]
            sapling: sapling::spending_key(seed, _params.coin_type(), _account),
            #[cfg(feature = "orchard")]
            orchard: orchard::keys::SpendingKey::from_zip32_seed(
                seed,
                _params.coin_type(),
                _account,
            )
            .map_err(DerivationError::Orchard)?,
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
            unknown: vec![],
        }
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &legacy::AccountPrivKey {
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

    /// Returns a binary encoding of this key suitable for decoding with [`decode`].
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
            CompactSize::write(&mut result, usize::try_from(Typecode::Orchard).unwrap()).unwrap();

            let orchard_key_bytes = orchard_key.to_bytes();
            CompactSize::write(&mut result, orchard_key_bytes.len()).unwrap();
            result.write_all(orchard_key_bytes).unwrap();
        }

        #[cfg(feature = "sapling")]
        {
            let sapling_key = self.sapling();
            CompactSize::write(&mut result, usize::try_from(Typecode::Sapling).unwrap()).unwrap();

            let sapling_key_bytes = sapling_key.to_bytes();
            CompactSize::write(&mut result, sapling_key_bytes.len()).unwrap();
            result.write_all(&sapling_key_bytes).unwrap();
        }

        #[cfg(feature = "transparent-inputs")]
        {
            let account_tkey = self.transparent();
            CompactSize::write(&mut result, usize::try_from(Typecode::P2pkh).unwrap()).unwrap();

            let account_tkey_bytes = account_tkey.to_bytes();
            CompactSize::write(&mut result, account_tkey_bytes.len()).unwrap();
            result.write_all(&account_tkey_bytes).unwrap();
        }

        result
    }

    /// Decodes a [`UnifiedSpendingKey`] value from its serialized representation.
    ///
    /// See [`to_bytes`] for additional detail about the encoded form.
    #[allow(clippy::unnecessary_unwrap)]
    #[cfg(feature = "unstable")]
    pub fn from_bytes(era: Era, encoded: &[u8]) -> Result<Self, DecodingError> {
        let mut source = std::io::Cursor::new(encoded);
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
                Typecode::Orchard => {
                    if len != 32 {
                        return Err(DecodingError::LengthMismatch(Typecode::Orchard, len));
                    }

                    let mut key = [0u8; 32];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::Orchard))?;

                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::<orchard::keys::SpendingKey>::from(
                                orchard::keys::SpendingKey::from_bytes(key),
                            )
                            .ok_or(DecodingError::KeyDataInvalid(Typecode::Orchard))?,
                        );
                    }
                }
                Typecode::Sapling => {
                    if len != 169 {
                        return Err(DecodingError::LengthMismatch(Typecode::Sapling, len));
                    }

                    let mut key = [0u8; 169];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::Sapling))?;

                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            sapling::ExtendedSpendingKey::from_bytes(&key)
                                .map_err(|_| DecodingError::KeyDataInvalid(Typecode::Sapling))?,
                        );
                    }
                }
                Typecode::P2pkh => {
                    if len != 64 {
                        return Err(DecodingError::LengthMismatch(Typecode::P2pkh, len));
                    }

                    let mut key = [0u8; 64];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::P2pkh))?;

                    #[cfg(feature = "transparent-inputs")]
                    {
                        transparent = Some(
                            legacy::AccountPrivKey::from_bytes(&key)
                                .ok_or(DecodingError::KeyDataInvalid(Typecode::P2pkh))?,
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
                return Ok(UnifiedSpendingKey {
                    #[cfg(feature = "orchard")]
                    orchard: orchard.unwrap(),
                    #[cfg(feature = "sapling")]
                    sapling: sapling.unwrap(),
                    #[cfg(feature = "transparent-inputs")]
                    transparent: transparent.unwrap(),
                });
            }
        }
    }

    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> (UnifiedAddress, DiversifierIndex) {
        self.to_unified_full_viewing_key()
            .default_address(request)
            .unwrap()
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
#[derive(Debug)]
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
    // An error occurred while deriving a key or address from an HD wallet.
    Derivation(DerivationError),
}

#[cfg(feature = "transparent-inputs")]
impl From<hdwallet::error::Error> for AddressGenerationError {
    fn from(e: hdwallet::error::Error) -> Self {
        AddressGenerationError::Derivation(DerivationError::Transparent(e))
    }
}

impl From<DerivationError> for AddressGenerationError {
    fn from(e: DerivationError) -> Self {
        AddressGenerationError::Derivation(e)
    }
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
            AddressGenerationError::Derivation(e) => write!(f, "Error deriving address: {}", e),
        }
    }
}

impl error::Error for AddressGenerationError {}

/// Specification for how a unified address should be generated from a unified viewing key.
#[derive(Clone, Copy, Debug)]
pub struct UnifiedAddressRequest {
    has_orchard: bool,
    has_sapling: bool,
    has_p2pkh: bool,
}

impl UnifiedAddressRequest {
    /// Construct a new unified address request from its constituent parts.
    ///
    /// Returns `None` if the resulting unified address would not include at least one shielded receiver.
    pub fn new(has_orchard: bool, has_sapling: bool, has_p2pkh: bool) -> Option<Self> {
        let has_shielded_receiver = has_orchard || has_sapling;

        if !has_shielded_receiver {
            None
        } else {
            Some(Self {
                has_orchard,
                has_sapling,
                has_p2pkh,
            })
        }
    }

    /// Constructs a new unified address request that includes a request for a receiver of each
    /// type that is supported given the active feature flags.
    pub fn all() -> Option<Self> {
        let _has_orchard = false;
        #[cfg(feature = "orchard")]
        let _has_orchard = true;

        let _has_sapling = false;
        #[cfg(feature = "sapling")]
        let _has_sapling = true;

        let _has_p2pkh = false;
        #[cfg(feature = "transparent-inputs")]
        let _has_p2pkh = true;

        Self::new(_has_orchard, _has_sapling, _has_p2pkh)
    }

    /// Construct a new unified address request from its constituent parts.
    ///
    /// Panics: at least one of `has_orchard` or `has_sapling` must be `true`.
    pub const fn unsafe_new(has_orchard: bool, has_sapling: bool, has_p2pkh: bool) -> Self {
        if !(has_orchard || has_sapling) {
            panic!("At least one shielded receiver must be requested.")
        }

        Self {
            has_orchard,
            has_sapling,
            has_p2pkh,
        }
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<hdwallet::error::Error> for DerivationError {
    fn from(e: hdwallet::error::Error) -> Self {
        DerivationError::Transparent(e)
    }
}

/// A [ZIP 316](https://zips.z.cash/zip-0316) unified full viewing key.
#[derive(Clone, Debug)]
pub struct UnifiedFullViewingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<legacy::AccountPubKey>,
    #[cfg(feature = "sapling")]
    sapling: Option<sapling::DiversifiableFullViewingKey>,
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::keys::FullViewingKey>,
    unknown: Vec<(u32, Vec<u8>)>,
}

#[doc(hidden)]
impl UnifiedFullViewingKey {
    /// Construct a new unified full viewing key, if the required components are present.
    pub fn new(
        #[cfg(feature = "transparent-inputs")] transparent: Option<legacy::AccountPubKey>,
        #[cfg(feature = "sapling")] sapling: Option<sapling::DiversifiableFullViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::FullViewingKey>,
        // TODO: Implement construction of UFVKs with metadata items.
    ) -> Option<UnifiedFullViewingKey> {
        #[cfg(feature = "orchard")]
        let has_orchard = orchard.is_some();
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;
        #[cfg(feature = "sapling")]
        let has_sapling = sapling.is_some();
        #[cfg(not(feature = "sapling"))]
        let has_sapling = false;

        if has_orchard || has_sapling {
            Some(UnifiedFullViewingKey {
                #[cfg(feature = "transparent-inputs")]
                transparent,
                #[cfg(feature = "sapling")]
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                // We don't allow constructing new UFVKs with unknown items, but we store
                // this to allow parsing such UFVKs.
                unknown: vec![],
            })
        } else {
            None
        }
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn decode<P: consensus::Parameters>(params: &P, encoding: &str) -> Result<Self, String> {
        let (net, ufvk) = unified::Ufvk::decode(encoding).map_err(|e| e.to_string())?;
        let expected_net = params.network_type();
        if net != expected_net {
            return Err(format!(
                "UFVK is for network {:?} but we expected {:?}",
                net, expected_net,
            ));
        }

        Self::from_ufvk(&ufvk).map_err(|e| e.to_string())
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn from_ufvk(ufvk: &Ufvk) -> Result<Self, DerivationError> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        let unknown = ufvk
            .items_as_parsed()
            .iter()
            .filter_map(|receiver| match receiver {
                #[cfg(feature = "orchard")]
                unified::Fvk::Orchard(data) => orchard::keys::FullViewingKey::from_bytes(data)
                    .ok_or(DerivationError::InvalidShieldedKey(
                        ShieldedProtocol::Orchard,
                    ))
                    .map(|addr| {
                        orchard = Some(addr);
                        None
                    })
                    .transpose(),
                #[cfg(not(feature = "orchard"))]
                unified::Fvk::Orchard(data) => Some(Ok::<_, DerivationError>((
                    u32::from(unified::Typecode::Orchard),
                    data.to_vec(),
                ))),
                #[cfg(feature = "sapling")]
                unified::Fvk::Sapling(data) => {
                    sapling::DiversifiableFullViewingKey::from_bytes(data)
                        .ok_or(DerivationError::InvalidShieldedKey(
                            ShieldedProtocol::Sapling,
                        ))
                        .map(|pa| {
                            sapling = Some(pa);
                            None
                        })
                        .transpose()
                }
                #[cfg(not(feature = "sapling"))]
                unified::Fvk::Sapling(data) => Some(Ok::<_, DerivationError>((
                    u32::from(unified::Typecode::Sapling),
                    data.to_vec(),
                ))),
                #[cfg(feature = "transparent-inputs")]
                unified::Fvk::P2pkh(data) => legacy::AccountPubKey::deserialize(data)
                    .map_err(DerivationError::Transparent)
                    .map(|tfvk| {
                        transparent = Some(tfvk);
                        None
                    })
                    .transpose(),
                #[cfg(not(feature = "transparent-inputs"))]
                unified::Fvk::P2pkh(data) => Some(Ok::<_, DerivationError>((
                    u32::from(unified::Typecode::P2pkh),
                    data.to_vec(),
                ))),
                unified::Fvk::Unknown { typecode, data } => Some(Ok((*typecode, data.clone()))),
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown,
        })
    }

    /// Returns the string encoding of this `UnifiedFullViewingKey` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_ufvk().encode(&params.network_type())
    }

    /// Returns the string encoding of this `UnifiedFullViewingKey` for the given network.
    pub fn to_ufvk(&self) -> Ufvk {
        let items = std::iter::empty().chain(self.unknown.iter().map(|(typecode, data)| {
            unified::Fvk::Unknown {
                typecode: *typecode,
                data: data.clone(),
            }
        }));
        #[cfg(feature = "orchard")]
        let items = items.chain(
            self.orchard
                .as_ref()
                .map(|fvk| fvk.to_bytes())
                .map(unified::Fvk::Orchard),
        );
        #[cfg(feature = "sapling")]
        let items = items.chain(
            self.sapling
                .as_ref()
                .map(|dfvk| dfvk.to_bytes())
                .map(unified::Fvk::Sapling),
        );
        #[cfg(feature = "transparent-inputs")]
        let items = items.chain(
            self.transparent
                .as_ref()
                .map(|tfvk| tfvk.serialize().try_into().unwrap())
                .map(unified::Fvk::P2pkh),
        );

        unified::Ufvk::try_from_items(items.collect())
            .expect("UnifiedFullViewingKey should only be constructed safely")
    }

    /// Derives a Unified Incoming Viewing Key from this Unified Full Viewing Key.
    pub fn to_unified_incoming_viewing_key(
        &self,
    ) -> Result<UnifiedIncomingViewingKey, DerivationError> {
        Ok(UnifiedIncomingViewingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent: self
                .transparent
                .as_ref()
                .map(|t| t.derive_external_ivk())
                .transpose()?,
            #[cfg(feature = "sapling")]
            sapling: self.sapling.as_ref().map(|s| s.to_external_ivk()),
            #[cfg(feature = "orchard")]
            orchard: self.orchard.as_ref().map(|o| o.to_ivk(Scope::External)),
            unknown: Vec::new(),
        })
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> Option<&legacy::AccountPubKey> {
        self.transparent.as_ref()
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

    /// Attempts to derive the Unified Address for the given diversifier index and
    /// receiver types.
    ///
    /// Returns `None` if the specified index does not produce a valid diversifier.
    pub fn address(
        &self,
        j: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<UnifiedAddress, AddressGenerationError> {
        self.to_unified_incoming_viewing_key()?.address(j, request)
    }

    /// Searches the diversifier space starting at diversifier index `j` for one which will
    /// produce a valid diversifier, and return the Unified Address constructed using that
    /// diversifier along with the index at which the valid diversifier was found.
    ///
    /// Returns an `Err(AddressGenerationError)` if no valid diversifier exists or if the features
    /// required to satisfy the unified address request are not properly enabled.
    #[allow(unused_mut)]
    pub fn find_address(
        &self,
        mut j: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.to_unified_incoming_viewing_key()?
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
}

/// A [ZIP 316](https://zips.z.cash/zip-0316) unified incoming viewing key.
#[derive(Clone, Debug)]
pub struct UnifiedIncomingViewingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<zcash_primitives::legacy::keys::ExternalIvk>,
    #[cfg(feature = "sapling")]
    sapling: Option<::sapling::zip32::IncomingViewingKey>,
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::keys::IncomingViewingKey>,
    /// Stores the unrecognized elements of the unified encoding.
    unknown: Vec<(u32, Vec<u8>)>,
}

impl UnifiedIncomingViewingKey {
    /// Construct a new unified incoming viewing key, if the required components are present.
    pub fn new(
        #[cfg(feature = "transparent-inputs")] transparent: Option<
            zcash_primitives::legacy::keys::ExternalIvk,
        >,
        #[cfg(feature = "sapling")] sapling: Option<::sapling::zip32::IncomingViewingKey>,
        #[cfg(feature = "orchard")] orchard: Option<orchard::keys::IncomingViewingKey>,
        // TODO: Implement construction of UIVKs with metadata items.
    ) -> Option<UnifiedIncomingViewingKey> {
        #[cfg(feature = "orchard")]
        let has_orchard = orchard.is_some();
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;
        #[cfg(feature = "sapling")]
        let has_sapling = sapling.is_some();
        #[cfg(not(feature = "sapling"))]
        let has_sapling = false;

        if has_orchard || has_sapling {
            Some(UnifiedIncomingViewingKey {
                #[cfg(feature = "transparent-inputs")]
                transparent,
                #[cfg(feature = "sapling")]
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                // We don't allow constructing new UFVKs with unknown items, but we store
                // this to allow parsing such UFVKs.
                unknown: vec![],
            })
        } else {
            None
        }
    }

    /// Constructs a unified incoming viewing key from a parsed unified encoding.
    pub fn from_uivk(uivk: &Uivk) -> Result<Self, DerivationError> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;

        let mut unknown = vec![];

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        for receiver in uivk.items_as_parsed() {
            match receiver {
                unified::Ivk::Orchard(data) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::from(orchard::keys::IncomingViewingKey::from_bytes(data))
                                .ok_or(DerivationError::InvalidShieldedKey(
                                    ShieldedProtocol::Orchard,
                                ))?,
                        );
                    }

                    #[cfg(not(feature = "orchard"))]
                    unknown.push((u32::from(unified::Typecode::Orchard), data.to_vec()));
                }
                unified::Ivk::Sapling(data) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            Option::from(::sapling::zip32::IncomingViewingKey::from_bytes(data))
                                .ok_or(DerivationError::InvalidShieldedKey(
                                    ShieldedProtocol::Sapling,
                                ))?,
                        );
                    }

                    #[cfg(not(feature = "sapling"))]
                    unknown.push((u32::from(unified::Typecode::Sapling), data.to_vec()));
                }
                unified::Ivk::P2pkh(data) => {
                    #[cfg(feature = "transparent-inputs")]
                    {
                        transparent = Some(legacy::ExternalIvk::deserialize(data)?);
                    }

                    #[cfg(not(feature = "transparent-inputs"))]
                    unknown.push((u32::from(unified::Typecode::P2pkh), data.to_vec()));
                }
                unified::Ivk::Unknown { typecode, data } => {
                    unknown.push((*typecode, data.clone()));
                }
            }
        }

        Ok(Self {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            #[cfg(feature = "sapling")]
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            unknown,
        })
    }

    /// Converts this unified incoming viewing key to a unified encoding.
    pub fn to_uivk(&self) -> Uivk {
        let items = std::iter::empty().chain(self.unknown.iter().map(|(typecode, data)| {
            unified::Ivk::Unknown {
                typecode: *typecode,
                data: data.clone(),
            }
        }));
        #[cfg(feature = "orchard")]
        let items = items.chain(
            self.orchard
                .as_ref()
                .map(|ivk| ivk.to_bytes())
                .map(unified::Ivk::Orchard),
        );
        #[cfg(feature = "sapling")]
        let items = items.chain(
            self.sapling
                .as_ref()
                .map(|divk| divk.to_bytes())
                .map(unified::Ivk::Sapling),
        );
        #[cfg(feature = "transparent-inputs")]
        let items = items.chain(
            self.transparent
                .as_ref()
                .map(|tivk| tivk.serialize().try_into().unwrap())
                .map(unified::Ivk::P2pkh),
        );

        unified::Uivk::try_from_items(items.collect())
            .expect("UnifiedIncomingViewingKey should only be constructed safely.")
    }

    /// Returns the Transparent external IVK, if present.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &Option<zcash_primitives::legacy::keys::ExternalIvk> {
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

    /// Attempts to derive the Unified Address for the given diversifier index and
    /// receiver types.
    ///
    /// Returns `None` if the specified index does not produce a valid diversifier.
    pub fn address(
        &self,
        _j: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<UnifiedAddress, AddressGenerationError> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        if request.has_orchard {
            #[cfg(not(feature = "orchard"))]
            return Err(AddressGenerationError::ReceiverTypeNotSupported(
                Typecode::Orchard,
            ));

            #[cfg(feature = "orchard")]
            if let Some(oivk) = &self.orchard {
                let orchard_j = orchard::keys::DiversifierIndex::from(*_j.as_bytes());
                orchard = Some(oivk.address_at(orchard_j))
            } else {
                return Err(AddressGenerationError::KeyNotAvailable(Typecode::Orchard));
            }
        }

        #[cfg(feature = "sapling")]
        let mut sapling = None;
        if request.has_sapling {
            #[cfg(not(feature = "sapling"))]
            return Err(AddressGenerationError::ReceiverTypeNotSupported(
                Typecode::Sapling,
            ));

            #[cfg(feature = "sapling")]
            if let Some(divk) = &self.sapling {
                // If a Sapling receiver type is requested, we must be able to construct an
                // address; if we're unable to do so, then no Unified Address exists at this
                // diversifier and we use `?` to early-return from this method.
                sapling = Some(
                    divk.address_at(_j)
                        .ok_or(AddressGenerationError::InvalidSaplingDiversifierIndex(_j))?,
                );
            } else {
                return Err(AddressGenerationError::KeyNotAvailable(Typecode::Sapling));
            }
        }

        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        if request.has_p2pkh {
            #[cfg(not(feature = "transparent-inputs"))]
            return Err(AddressGenerationError::ReceiverTypeNotSupported(
                Typecode::P2pkh,
            ));

            #[cfg(feature = "transparent-inputs")]
            if let Some(tivk) = self.transparent.as_ref() {
                // If a transparent receiver type is requested, we must be able to construct an
                // address; if we're unable to do so, then no Unified Address exists at this
                // diversifier.
                let transparent_j = to_transparent_child_index(_j)
                    .ok_or(AddressGenerationError::InvalidTransparentChildIndex(_j))?;

                transparent = Some(
                    tivk.derive_address(transparent_j)
                        .map_err(|_| AddressGenerationError::InvalidTransparentChildIndex(_j))?,
                );
            } else {
                return Err(AddressGenerationError::KeyNotAvailable(Typecode::P2pkh));
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
        )
        .ok_or(AddressGenerationError::ShieldedReceiverRequired)
    }

    /// Searches the diversifier space starting at diversifier index `j` for one which will
    /// produce a valid diversifier, and return the Unified Address constructed using that
    /// diversifier along with the index at which the valid diversifier was found.
    ///
    /// Returns an `Err(AddressGenerationError)` if no valid diversifier exists or if the features
    /// required to satisfy the unified address request are not properly enabled.
    #[allow(unused_mut)]
    pub fn find_address(
        &self,
        mut j: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        // If we need to generate a transparent receiver, check that the user has not
        // specified an invalid transparent child index, from which we can never search to
        // find a valid index.
        #[cfg(feature = "transparent-inputs")]
        if request.has_p2pkh
            && self.transparent.is_some()
            && to_transparent_child_index(j).is_none()
        {
            return Err(AddressGenerationError::InvalidTransparentChildIndex(j));
        }

        // Find a working diversifier and construct the associated address.
        loop {
            let res = self.address(j, request);
            match res {
                Ok(ua) => {
                    return Ok((ua, j));
                }
                #[cfg(feature = "sapling")]
                Err(AddressGenerationError::InvalidSaplingDiversifierIndex(_)) => {
                    if j.increment().is_err() {
                        return Err(AddressGenerationError::DiversifierSpaceExhausted);
                    }
                }
                Err(other) => {
                    return Err(other);
                }
            }
        }
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
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use super::UnifiedSpendingKey;
    use zcash_primitives::{consensus::Network, zip32::AccountId};

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
    use crate::keys::UnifiedIncomingViewingKey;

    use super::UnifiedFullViewingKey;
    use proptest::prelude::proptest;
    use zcash_address::unified::{Encoding, Uivk};
    #[cfg(feature = "orchard")]
    use zip32::Scope;

    #[cfg(any(
        feature = "orchard",
        feature = "sapling",
        feature = "transparent-inputs"
    ))]
    use {zcash_primitives::consensus::MAIN_NETWORK, zip32::AccountId};

    #[cfg(feature = "sapling")]
    use super::sapling;

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::{address::Address, encoding::AddressCodec},
        zcash_address::test_vectors,
        zcash_primitives::legacy::{
            self,
            keys::{AccountPrivKey, IncomingViewingKey},
        },
        zip32::DiversifierIndex,
    };

    #[cfg(feature = "unstable")]
    use {
        super::{testing::arb_unified_spending_key, Era, UnifiedSpendingKey},
        zcash_primitives::consensus::Network,
    };

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
        use zcash_primitives::legacy::keys::NonHardenedChildIndex;

        let taddr =
            legacy::keys::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId::ZERO)
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
        );

        #[cfg(not(any(feature = "orchard", feature = "sapling")))]
        assert!(ufvk.is_none());

        #[cfg(any(feature = "orchard", feature = "sapling"))]
        {
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

            let decoded_with_t =
                UnifiedFullViewingKey::decode(&MAIN_NETWORK, encoded_with_t).unwrap();
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
            assert_eq!(decoded_with_t.unknown.len(), 0);
            #[cfg(all(
                feature = "orchard",
                feature = "sapling",
                not(feature = "transparent-inputs")
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 1);

            // Orchard enabled
            #[cfg(all(
                feature = "orchard",
                not(feature = "sapling"),
                feature = "transparent-inputs"
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 1);
            #[cfg(all(
                feature = "orchard",
                not(feature = "sapling"),
                not(feature = "transparent-inputs")
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 2);

            // Sapling enabled
            #[cfg(all(
                not(feature = "orchard"),
                feature = "sapling",
                feature = "transparent-inputs"
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 1);
            #[cfg(all(
                not(feature = "orchard"),
                feature = "sapling",
                not(feature = "transparent-inputs")
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 2);
        }
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn ufvk_derivation() {
        use crate::keys::UnifiedAddressRequest;

        use super::UnifiedSpendingKey;

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
                .address(d_idx, UnifiedAddressRequest::unsafe_new(false, true, true))
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
                    if tvua.transparent().is_some() {
                        assert_eq!(tvua.transparent(), ua.transparent());
                    }
                    #[cfg(feature = "sapling")]
                    if tvua.sapling().is_some() {
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
    fn uivk_round_trip() {
        use zcash_primitives::consensus::NetworkType;

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
        );

        #[cfg(not(any(feature = "orchard", feature = "sapling")))]
        assert!(uivk.is_none());

        #[cfg(any(feature = "orchard", feature = "sapling"))]
        {
            let uivk = uivk.expect("Orchard or Sapling ivk is present.");
            let encoded = uivk.to_uivk().encode(&NetworkType::Main);

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

            let decoded =
                UnifiedIncomingViewingKey::from_uivk(&Uivk::decode(&encoded).unwrap().1).unwrap();
            let reencoded = decoded.to_uivk().encode(&Network::Main);
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
                UnifiedIncomingViewingKey::from_uivk(&Uivk::decode(encoded_with_t).unwrap().1)
                    .unwrap();
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
            assert_eq!(decoded_with_t.unknown.len(), 0);
            #[cfg(all(
                feature = "orchard",
                feature = "sapling",
                not(feature = "transparent-inputs")
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 1);

            // Orchard enabled
            #[cfg(all(
                feature = "orchard",
                not(feature = "sapling"),
                feature = "transparent-inputs"
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 1);
            #[cfg(all(
                feature = "orchard",
                not(feature = "sapling"),
                not(feature = "transparent-inputs")
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 2);

            // Sapling enabled
            #[cfg(all(
                not(feature = "orchard"),
                feature = "sapling",
                feature = "transparent-inputs"
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 1);
            #[cfg(all(
                not(feature = "orchard"),
                feature = "sapling",
                not(feature = "transparent-inputs")
            ))]
            assert_eq!(decoded_with_t.unknown.len(), 2);
        }
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn uivk_derivation() {
        use crate::keys::UnifiedAddressRequest;

        use super::UnifiedSpendingKey;

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
                .to_unified_incoming_viewing_key()
                .unwrap();

            // The test vectors contain some diversifier indices that do not generate
            // valid Sapling addresses, so skip those.
            #[cfg(feature = "sapling")]
            if uivk.sapling().as_ref().unwrap().address_at(d_idx).is_none() {
                continue;
            }

            let ua = uivk
                .address(d_idx, UnifiedAddressRequest::unsafe_new(false, true, true))
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
                    if tvua.transparent().is_some() {
                        assert_eq!(tvua.transparent(), ua.transparent());
                    }
                    #[cfg(feature = "sapling")]
                    if tvua.sapling().is_some() {
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

            let encoded_len = {
                let len = 4;

                #[cfg(feature = "orchard")]
                let len = len + 2 + 32;

                let len = len + 2 + 169;

                #[cfg(feature = "transparent-inputs")]
                let len = len + 2 + 64;

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
}
