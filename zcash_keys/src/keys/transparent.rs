//! Transparent key components: BIP 44 account keys with their incoming and outgoing
//! viewing keys, derivation-path index types, functions that read BIP 44 and ZIP 48
//! derivation paths from PCZT metadata, and zcashd-compatible encodings of standalone
//! transparent spending keys.

use core::fmt;

use ::transparent::pczt::Bip32Derivation;
use bip32::ChildNumber;
use subtle::{Choice, ConstantTimeEq};
use zip32::DiversifierIndex;

#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::address::TransparentAddress,
    alloc::{string::ToString, vec::Vec},
    bip32::{ExtendedKey, ExtendedKeyAttrs, ExtendedPrivateKey, ExtendedPublicKey, Prefix},
    zcash_protocol::consensus::{self, NetworkConstants},
    zcash_spec::PrfExpand,
    zip32::AccountId,
};

#[cfg(feature = "transparent-key-encoding")]
use {
    bip32::{PrivateKey, PrivateKeyBytes},
    core::array::TryFromSliceError,
    secp256k1::SecretKey,
    secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize, zeroize::ZeroizeOnDrop},
    zcash_protocol::consensus::NetworkType,
};

#[cfg(any(feature = "transparent-inputs", feature = "transparent-key-encoding"))]
use secp256k1::PublicKey;

#[cfg(feature = "transparent-inputs")]
pub mod gap_limits;

#[cfg(feature = "transparent-inputs")]
pub mod zip48;

/// An error indicating that a DER-encoded secret key could not be decoded.
#[cfg(feature = "transparent-key-encoding")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerDecodeError;

#[cfg(feature = "transparent-key-encoding")]
impl core::fmt::Display for DerDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Invalid DER encoding for transparent secret key")
    }
}

/// Errors that can occur in the parsing of Bitcoin-style base58-encoded secret key material
#[cfg(feature = "transparent-key-encoding")]
#[derive(Debug)]
pub enum ParseError {
    /// The data being decoded had an incorrect length, an incorrect prefix, or has the correct
    /// length for a compressed encoding but has its final byte not equal to `1`.
    InvalidEncoding,
    /// Errors that occur in base58 decoding.
    Base58(bs58::decode::Error),
    /// Errors that occur when a decoded binary value does not correspond to a valid secp256k1 secret key.
    Bip32(bip32::Error),
}

#[cfg(feature = "transparent-key-encoding")]
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Key")
            .field("secret", &"...")
            .field("compressed", &self.compressed)
            .finish()
    }
}

#[cfg(feature = "transparent-key-encoding")]
impl From<bs58::decode::Error> for ParseError {
    fn from(value: bs58::decode::Error) -> Self {
        ParseError::Base58(value)
    }
}

#[cfg(feature = "transparent-key-encoding")]
impl From<TryFromSliceError> for ParseError {
    fn from(_: TryFromSliceError) -> Self {
        ParseError::InvalidEncoding
    }
}

#[cfg(feature = "transparent-key-encoding")]
impl From<bip32::Error> for ParseError {
    fn from(value: bip32::Error) -> Self {
        ParseError::Bip32(value)
    }
}

/// A secp256k1 secret key, along with a flag indicating whether a compressed encoding should be
/// used when performing DER serialization.
#[cfg(feature = "transparent-key-encoding")]
pub struct Key {
    secret: SecretKey,
    compressed: bool,
}

#[cfg(feature = "transparent-key-encoding")]
impl Key {
    /// Constructs a new key value from a secret key and a flag indicating whether
    /// the compressed encoding should be used when performing DER serialization.
    pub fn new(secret: SecretKey, compressed: bool) -> Self {
        Self { secret, compressed }
    }

    /// Decodes a base58-encoded secret key.
    ///
    /// This corresponds to <https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L282>
    pub fn decode_base58(network: NetworkType, encoded: &SecretString) -> Result<Self, ParseError> {
        let decoded = SecretVec::new(
            bs58::decode(encoded.expose_secret())
                .with_check(None)
                .into_vec()?,
        );
        let prefix = crate::constants::b58_secret_key_prefix(network);
        let decoded_len = decoded.expose_secret().len();
        let compressed =
            decoded_len == (33 + prefix.len()) && decoded.expose_secret().last() == Some(&1);
        if (decoded_len == 32 + prefix.len() || compressed)
            && decoded.expose_secret()[0..prefix.len()] == prefix
        {
            let key_end = decoded_len - if compressed { 1 } else { 0 };
            let bytes = PrivateKeyBytes::try_from(&decoded.expose_secret()[prefix.len()..key_end])?;
            Ok(Self {
                secret: SecretKey::from_bytes(&bytes)?,
                compressed,
            })
        } else {
            Err(ParseError::InvalidEncoding)
        }
    }

    /// Encodes a base58-encoded secret key.
    ///
    /// This corresponds to <https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L298>
    pub fn encode_base58(&self, network: NetworkType) -> SecretString {
        let input = SecretVec::new(
            crate::constants::b58_secret_key_prefix(network)
                .iter()
                .chain(self.secret.to_secret_bytes().iter())
                .chain(self.compressed.then_some(&1))
                .copied()
                .collect(),
        );

        SecretString::new(
            bs58::encode(input.expose_secret())
                .with_check()
                .into_string(),
        )
    }

    /// Returns the wrapped secp256k1 secret key.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Returns the value of the compressed flag.
    pub fn compressed(&self) -> bool {
        self.compressed
    }

    /// Derives the secp256k1 public key corresponding to the secret key.
    pub fn pubkey(&self) -> PublicKey {
        self.secret.public_key()
    }

    /// Generates the "openssh-inspired" DER encoding of the secret key used by zcashd.
    pub fn der_encode(&self) -> SecretVec<u8> {
        // Ported from https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key.cpp#L93
        // The original c++ code is retained as comments.

        //    secp256k1_pubkey pubkey;
        //    size_t pubkeylen = 0;
        //    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        //        *seckeylen = 0;
        //        return 0;
        //    }
        let keypair = self.secret().keypair();

        if self.compressed {
            let begin = [0x30, 0x81, 0xD3, 0x02, 0x01, 0x01, 0x04, 0x20];
            let middle = [
                0xA0, 0x81, 0x85, 0x30, 0x81, 0x82, 0x02, 0x01, 0x01, 0x30, 0x2C, 0x06, 0x07, 0x2A,
                0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F, 0x30,
                0x06, 0x04, 0x01, 0x00, 0x04, 0x01, 0x07, 0x04, 0x21, 0x02, 0x79, 0xBE, 0x66, 0x7E,
                0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B,
                0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
                0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF,
                0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41, 0x02, 0x01, 0x01, 0xA1, 0x24, 0x03, 0x22,
                0x00,
            ];
            //        unsigned char *ptr = seckey;
            //        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
            //        memcpy(ptr, key32, 32); ptr += 32;
            //        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
            //        pubkeylen = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE;
            //        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
            //        ptr += pubkeylen;
            //        *seckeylen = ptr - seckey;
            //        assert(*seckeylen == CKey::COMPRESSED_PRIVATE_KEY_SIZE);
            SecretVec::new(
                begin
                    .iter()
                    .chain(keypair.to_secret_bytes().iter())
                    .chain(middle.iter())
                    .chain(keypair.public_key().serialize().iter())
                    .copied()
                    .collect(),
            )
        } else {
            let begin = [0x30, 0x82, 0x01, 0x13, 0x02, 0x01, 0x01, 0x04, 0x20];
            let middle = [
                0xA0, 0x81, 0xA5, 0x30, 0x81, 0xA2, 0x02, 0x01, 0x01, 0x30, 0x2C, 0x06, 0x07, 0x2A,
                0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F, 0x30,
                0x06, 0x04, 0x01, 0x00, 0x04, 0x01, 0x07, 0x04, 0x41, 0x04, 0x79, 0xBE, 0x66, 0x7E,
                0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B,
                0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
                0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
                0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
                0xFB, 0x10, 0xD4, 0xB8, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF,
                0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41, 0x02, 0x01, 0x01,
                0xA1, 0x44, 0x03, 0x42, 0x00,
            ];
            //        unsigned char *ptr = seckey;
            //        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
            //        memcpy(ptr, key32, 32); ptr += 32;
            //        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
            //        pubkeylen = CPubKey::PUBLIC_KEY_SIZE;
            //        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
            //        ptr += pubkeylen;
            //        *seckeylen = ptr - seckey;
            //        assert(*seckeylen == CKey::PRIVATE_KEY_SIZE);
            SecretVec::new(
                begin
                    .iter()
                    .chain(keypair.to_secret_bytes().iter())
                    .chain(middle.iter())
                    .chain(keypair.public_key().serialize_uncompressed().iter())
                    .copied()
                    .collect(),
            )
        }
    }

    // Decodes a secret key from the "openssl-inspired" DER encoding used by zcashd.
    pub fn der_decode(encoded: &SecretVec<u8>, compressed: bool) -> Result<Self, DerDecodeError> {
        // Ported from https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key.cpp#L36
        // The original c++ code is retained as comments.

        let seckey = encoded.expose_secret();

        //    /* sequence header */
        //    if (end - seckey < 1 || *seckey != 0x30u) {
        //        return 0;
        //    }
        //    seckey++;
        let seckey = match seckey.split_first() {
            Some((&0x30, rest)) => Ok(rest),
            _ => Err(DerDecodeError),
        }?;

        //    /* sequence length constructor */
        //    if (end - seckey < 1 || !(*seckey & 0x80u)) {
        //        return 0;
        //    }
        //    size_t lenb = *seckey & ~0x80u; seckey++;
        //    if (lenb < 1 || lenb > 2) {
        //        return 0;
        //    }
        //    if (end - seckey < lenb) {
        //        return 0;
        //    }
        let (lenb, seckey) = match seckey.split_first() {
            Some((lenb, seckey)) if lenb & 0x80 != 0 => Ok((usize::from(lenb & !0x80), seckey)),
            _ => Err(DerDecodeError),
        }?;
        if !(1..=2).contains(&lenb) {
            return Err(DerDecodeError);
        }
        if seckey.len() < lenb {
            return Err(DerDecodeError);
        }

        //    /* sequence length */
        //    size_t len = seckey[lenb-1] | (lenb > 1 ? seckey[lenb-2] << 8 : 0u);
        //    seckey += lenb;
        //    if (end - seckey < len) {
        //        return 0;
        //    }
        let len_low_bits = usize::from(seckey[lenb - 1]);
        let len_high_bits = if lenb > 1 {
            usize::from(seckey[lenb - 2]) << 8
        } else {
            0
        };
        let len = len_low_bits | len_high_bits;
        let seckey = &seckey[lenb..];
        if seckey.len() < len {
            return Err(DerDecodeError);
        }

        //    /* sequence element 0: version number (=1) */
        //    if (end - seckey < 3 || seckey[0] != 0x02u || seckey[1] != 0x01u || seckey[2] != 0x01u) {
        //        return 0;
        //    }
        //    seckey += 3;
        let seckey = match seckey.split_at(3) {
            (&[0x02, 0x01, 0x01], rest) => Ok(rest),
            _ => Err(DerDecodeError),
        }?;

        //    /* sequence element 1: octet string, up to 32 bytes */
        //    if (end - seckey < 2 || seckey[0] != 0x04u) {
        //        return 0;
        //    }
        //    size_t oslen = seckey[1];
        //    seckey += 2;
        //    if (oslen > 32 || end - seckey < oslen) {
        //        return 0;
        //    }
        //    memcpy(out32 + (32 - oslen), seckey, oslen);
        //    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        //        memset(out32, 0, 32);
        //        return 0;
        //    }
        //    return 1;
        //}
        if seckey.len() < 2 || seckey[0] != 0x04 {
            return Err(DerDecodeError);
        }
        let oslen = usize::from(seckey[1]);
        let seckey = &seckey[2..];
        if oslen > 32 || seckey.len() < oslen {
            return Err(DerDecodeError);
        }
        let mut secret_buf = [0u8; 32];
        secret_buf[(32 - oslen)..].copy_from_slice(&seckey[..oslen]);
        let secret_key = SecretKey::from_bytes(&secret_buf);
        secret_buf.zeroize();

        secret_key
            .map(|secret| Self { secret, compressed })
            .map_err(|_| DerDecodeError)
    }
}

#[cfg(feature = "transparent-key-encoding")]
impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.secret.non_secure_erase();
    }
}

#[cfg(feature = "transparent-key-encoding")]
impl ZeroizeOnDrop for Key {}

/// The scope of a transparent key.
///
/// This type can represent [`zip32`] internal and external scopes, as well as custom scopes that
/// may be used in non-hardened derivation at the `change` level of the BIP 44 key path.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransparentKeyScope(u32);

impl TransparentKeyScope {
    /// Returns an arbitrary custom `TransparentKeyScope`.
    ///
    /// This should be used with care: funds associated with keys derived under a custom
    /// scope may not be recoverable if the wallet seed is restored in another wallet. It
    /// is usually preferable to use standardized key scopes.
    pub const fn custom(i: u32) -> Option<Self> {
        if i < (1 << 31) {
            Some(TransparentKeyScope(i))
        } else {
            None
        }
    }

    /// The scope used to derive keys for external transparent addresses,
    /// intended to be used to send funds to this wallet.
    pub const EXTERNAL: Self = TransparentKeyScope(0);

    /// The scope used to derive keys for internal wallet operations, e.g.
    /// change or UTXO management.
    pub const INTERNAL: Self = TransparentKeyScope(1);

    /// The scope used to derive keys for ephemeral transparent addresses.
    pub const EPHEMERAL: Self = TransparentKeyScope(2);
}

impl fmt::Debug for TransparentKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::EXTERNAL => f.write_str("TransparentKeyScope::EXTERNAL"),
            Self::INTERNAL => f.write_str("TransparentKeyScope::INTERNAL"),
            Self::EPHEMERAL => f.write_str("TransparentKeyScope::EPHEMERAL"),
            TransparentKeyScope(other) => f.write_str(&format!("TransparentKeyScope({other})")),
        }
    }
}

impl From<zip32::Scope> for TransparentKeyScope {
    fn from(value: zip32::Scope) -> Self {
        match value {
            zip32::Scope::External => TransparentKeyScope::EXTERNAL,
            zip32::Scope::Internal => TransparentKeyScope::INTERNAL,
        }
    }
}

impl From<TransparentKeyScope> for ChildNumber {
    fn from(value: TransparentKeyScope) -> Self {
        ChildNumber::new(value.0, false).expect("TransparentKeyScope is correct by construction")
    }
}

/// A child index for a derived transparent address.
///
/// Only NON-hardened derivation is supported.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonHardenedChildIndex(u32);

impl core::fmt::Debug for NonHardenedChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("NonHardenedChildIndex({})", self.0))
    }
}

impl ConstantTimeEq for NonHardenedChildIndex {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl NonHardenedChildIndex {
    /// The minimum valid non-hardened child index.
    pub const ZERO: NonHardenedChildIndex = NonHardenedChildIndex(0);

    /// The maximum valid non-hardened child index.
    pub const MAX: NonHardenedChildIndex = NonHardenedChildIndex((1 << 31) - 1);

    /// Parses the given ZIP 32 child index.
    ///
    /// Returns `None` if the hardened bit is set.
    pub const fn from_index(i: u32) -> Option<Self> {
        if i <= Self::MAX.0 {
            Some(NonHardenedChildIndex(i))
        } else {
            None
        }
    }

    /// Constructs a [`NonHardenedChildIndex`] from a ZIP 32 child index.
    ///
    /// Panics: if the hardened bit is set.
    pub const fn const_from_index(i: u32) -> Self {
        assert!(i <= Self::MAX.0);
        NonHardenedChildIndex(i)
    }

    /// Returns the index as a 32-bit integer.
    pub const fn index(&self) -> u32 {
        self.0
    }

    /// Returns the successor to this index.
    pub const fn next(&self) -> Option<Self> {
        // overflow cannot happen because self.0 is 31 bits, and the next index is at most 32 bits
        // which in that case would lead from_index to return None.
        Self::from_index(self.0 + 1)
    }

    /// Subtracts the given delta from this index.
    pub const fn saturating_sub(&self, delta: u32) -> Self {
        NonHardenedChildIndex(self.0.saturating_sub(delta))
    }

    /// Adds the given delta to this index, returning a maximum possible value of
    /// [`NonHardenedChildIndex::MAX`].
    pub const fn saturating_add(&self, delta: u32) -> Self {
        let idx = self.0.saturating_add(delta);
        if idx > Self::MAX.0 {
            Self::MAX
        } else {
            NonHardenedChildIndex(idx)
        }
    }
}

impl TryFrom<ChildNumber> for NonHardenedChildIndex {
    type Error = ();

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        if value.is_hardened() {
            Err(())
        } else {
            NonHardenedChildIndex::from_index(value.index()).ok_or(())
        }
    }
}

impl From<NonHardenedChildIndex> for ChildNumber {
    fn from(value: NonHardenedChildIndex) -> Self {
        Self::new(value.index(), false).expect("NonHardenedChildIndex is correct by construction")
    }
}

impl TryFrom<DiversifierIndex> for NonHardenedChildIndex {
    type Error = ();

    fn try_from(value: DiversifierIndex) -> Result<Self, Self::Error> {
        let idx = u32::try_from(value).map_err(|_| ())?;
        NonHardenedChildIndex::from_index(idx).ok_or(())
    }
}

impl From<NonHardenedChildIndex> for DiversifierIndex {
    fn from(value: NonHardenedChildIndex) -> Self {
        DiversifierIndex::from(value.0)
    }
}

/// An end-exclusive iterator over a range of non-hardened child indexes.
pub struct NonHardenedChildIter {
    next: Option<NonHardenedChildIndex>,
    end: NonHardenedChildIndex,
}

impl Iterator for NonHardenedChildIter {
    type Item = NonHardenedChildIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        self.next = self
            .next
            .and_then(|i| i.next())
            .filter(|succ| succ < &self.end);
        cur
    }
}

/// An end-exclusive range of non-hardened child indexes.
pub struct NonHardenedChildRange(core::ops::Range<NonHardenedChildIndex>);

impl From<core::ops::Range<NonHardenedChildIndex>> for NonHardenedChildRange {
    fn from(value: core::ops::Range<NonHardenedChildIndex>) -> Self {
        Self(value)
    }
}

impl IntoIterator for NonHardenedChildRange {
    type Item = NonHardenedChildIndex;
    type IntoIter = NonHardenedChildIter;

    fn into_iter(self) -> Self::IntoIter {
        NonHardenedChildIter {
            next: (self.0.start < self.0.end).then_some(self.0.start),
            end: self.0.end,
        }
    }
}

/// The hardened BIP 43 purpose index of a BIP 44 derivation path.
const BIP_44_PURPOSE: ChildNumber = ChildNumber(44 | ChildNumber::HARDENED_FLAG);

/// The hardened BIP 43 purpose index of a ZIP 48 derivation path.
const ZIP_48_PURPOSE: ChildNumber = ChildNumber(48 | ChildNumber::HARDENED_FLAG);

/// The hardened ZIP 48 script type index for P2SH.
const ZIP_48_P2SH_SCRIPT_TYPE: ChildNumber = ChildNumber(133000 | ChildNumber::HARDENED_FLAG);

/// Extracts the BIP 44 account index, scope, and address index from a PCZT derivation
/// path.
///
/// `expected_coin_type` is the hardened coin type index of the network.
///
/// Returns `None` if the seed fingerprints don't match, or if this is not a BIP 44
/// derivation path for `expected_coin_type`.
pub fn extract_bip_44_fields(
    derivation: &Bip32Derivation,
    seed_fp: &zip32::fingerprint::SeedFingerprint,
    expected_coin_type: ChildNumber,
) -> Option<(zip32::AccountId, TransparentKeyScope, NonHardenedChildIndex)> {
    if *derivation.seed_fingerprint() == seed_fp.to_bytes() {
        match &derivation.derivation_path()[..] {
            [purpose, coin_type, account_index, scope, address_index]
                if purpose == &BIP_44_PURPOSE
                    && coin_type.is_hardened()
                    && coin_type == &expected_coin_type
                    && account_index.is_hardened()
                    && !scope.is_hardened()
                    && !address_index.is_hardened() =>
            {
                let account_index = zip32::AccountId::try_from(account_index.index())
                    .expect("account_index is hardened");

                let scope =
                    TransparentKeyScope::custom(scope.index()).expect("scope is not hardened");

                let address_index = NonHardenedChildIndex::from_index(address_index.index())
                    .expect("address_index is not hardened");

                Some((account_index, scope, address_index))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Extracts the ZIP 48 account index, scope, and address index from a PCZT derivation
/// path.
///
/// `expected_coin_type` is the hardened coin type index of the network.
///
/// Returns `None` if the seed fingerprints don't match, if this is not a ZIP 48
/// derivation path for `expected_coin_type`, or if its scope is neither external (0)
/// nor internal (1).
pub fn extract_zip_48_fields(
    derivation: &Bip32Derivation,
    seed_fp: &zip32::fingerprint::SeedFingerprint,
    expected_coin_type: ChildNumber,
) -> Option<(zip32::AccountId, zip32::Scope, NonHardenedChildIndex)> {
    if *derivation.seed_fingerprint() == seed_fp.to_bytes() {
        match &derivation.derivation_path()[..] {
            [
                purpose,
                coin_type,
                account_index,
                script_type,
                scope,
                address_index,
            ] if purpose == &ZIP_48_PURPOSE
                && coin_type.is_hardened()
                && coin_type == &expected_coin_type
                && account_index.is_hardened()
                && script_type == &ZIP_48_P2SH_SCRIPT_TYPE
                && !scope.is_hardened()
                && !address_index.is_hardened() =>
            {
                let account_index = zip32::AccountId::try_from(account_index.index())
                    .expect("account_index is hardened");

                let scope = match scope.index() {
                    0 => Some(zip32::Scope::External),
                    1 => Some(zip32::Scope::Internal),
                    _ => None,
                };

                let address_index = NonHardenedChildIndex::from_index(address_index.index())
                    .expect("address_index is not hardened");

                scope.map(|scope| (account_index, scope, address_index))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// A [BIP44] private key at the account path level `m/44'/<coin_type>'/<account>'`.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[derive(Clone)]
#[cfg(feature = "transparent-inputs")]
pub struct AccountPrivKey(ExtendedPrivateKey<secp256k1::SecretKey>);

#[cfg(feature = "transparent-inputs")]
impl core::fmt::Debug for AccountPrivKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AccountPrivKey").field(&"...").finish()
    }
}

#[cfg(feature = "transparent-inputs")]
impl AccountPrivKey {
    /// Performs derivation of the extended private key for the BIP44 path:
    /// `m/44'/<coin_type>'/<account>'`.
    ///
    /// This produces the root of the derivation tree for transparent
    /// viewing keys and addresses for the provided account.
    pub fn from_seed<P: consensus::Parameters>(
        params: &P,
        seed: &[u8],
        account: AccountId,
    ) -> Result<AccountPrivKey, bip32::Error> {
        ExtendedPrivateKey::new(seed)?
            .derive_child(BIP_44_PURPOSE)?
            .derive_child(ChildNumber::new(params.coin_type(), true)?)?
            .derive_child(ChildNumber::new(account.into(), true)?)
            .map(AccountPrivKey)
    }

    pub fn from_extended_privkey(extprivkey: ExtendedPrivateKey<secp256k1::SecretKey>) -> Self {
        AccountPrivKey(extprivkey)
    }

    pub fn to_account_pubkey(&self) -> AccountPubKey {
        AccountPubKey(ExtendedPublicKey::from(&self.0))
    }

    /// Derives the BIP44 private spending key for the child path
    /// `m/44'/<coin_type>'/<account>'/<scope>/<address_index>`.
    pub fn derive_secret_key(
        &self,
        scope: TransparentKeyScope,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::SecretKey, bip32::Error> {
        self.0
            .derive_child(scope.into())?
            .derive_child(address_index.into())
            .map(|k| *k.private_key())
    }

    /// Derives the BIP44 private spending key for the external (incoming payment) child path
    /// `m/44'/<coin_type>'/<account>'/0/<address_index>`.
    pub fn derive_external_secret_key(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::SecretKey, bip32::Error> {
        self.derive_secret_key(zip32::Scope::External.into(), address_index)
    }

    /// Derives the BIP44 private spending key for the internal (change) child path
    /// `m/44'/<coin_type>'/<account>'/1/<address_index>`.
    pub fn derive_internal_secret_key(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::SecretKey, bip32::Error> {
        self.derive_secret_key(zip32::Scope::Internal.into(), address_index)
    }

    /// Returns the `AccountPrivKey` serialized using the encoding for a
    /// [BIP 32](https://en.bitcoin.it/wiki/BIP_0032) ExtendedPrivateKey, excluding the
    /// 4 prefix bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Convert to `xprv` encoding.
        let xprv_encoded = self.0.to_extended_key(Prefix::XPRV).to_string();

        // Now decode it and return the bytes we want.
        bs58::decode(xprv_encoded)
            .with_check(None)
            .into_vec()
            .expect("correct")
            .split_off(Prefix::LENGTH)
    }

    /// Decodes the `AccountPrivKey` from the encoding specified for a
    /// [BIP 32](https://en.bitcoin.it/wiki/BIP_0032) ExtendedPrivateKey, excluding the
    /// 4 prefix bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        // Convert to `xprv` encoding.
        let mut bytes = Prefix::XPRV.to_bytes().to_vec();
        bytes.extend_from_slice(b);
        let xprv_encoded = bs58::encode(bytes).with_check().into_string();

        // Now we can parse it.
        xprv_encoded
            .parse::<ExtendedKey>()
            .ok()
            .and_then(|k| ExtendedPrivateKey::try_from(k).ok())
            .map(AccountPrivKey::from_extended_privkey)
    }
}

/// A [BIP44] public key at the account path level `m/44'/<coin_type>'/<account>'`.
///
/// This provides the necessary derivation capability for the transparent component of a unified
/// full viewing key.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
#[derive(Clone)]
pub struct AccountPubKey(ExtendedPublicKey<PublicKey>);

/// Compares only the chain code and public key, ignoring BIP 32 derivation
/// metadata (depth, parent fingerprint, child number) which are not preserved
/// by the UFVK encoding.
#[cfg(feature = "transparent-inputs")]
impl PartialEq for AccountPubKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.attrs().chain_code == other.0.attrs().chain_code
            && self.0.public_key() == other.0.public_key()
    }
}

#[cfg(feature = "transparent-inputs")]
impl Eq for AccountPubKey {}

#[cfg(feature = "transparent-inputs")]
impl core::fmt::Debug for AccountPubKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AccountPubKey").field(&"...").finish()
    }
}

#[cfg(feature = "transparent-inputs")]
impl AccountPubKey {
    /// Derives the BIP44 public key at the external "change level" path
    /// `m/44'/<coin_type>'/<account>'/0`.
    pub fn derive_external_ivk(&self) -> Result<ExternalIvk, bip32::Error> {
        self.0
            .derive_child(ChildNumber::new(0, false)?)
            .map(ExternalIvk)
    }

    /// Derives the BIP44 public key at the internal "change level" path
    /// `m/44'/<coin_type>'/<account>'/1`.
    pub fn derive_internal_ivk(&self) -> Result<InternalIvk, bip32::Error> {
        self.0
            .derive_child(ChildNumber::new(1, false)?)
            .map(InternalIvk)
    }

    /// Derives the public key at the "ephemeral" path
    /// `m/44'/<coin_type>'/<account>'/2`.
    pub fn derive_ephemeral_ivk(&self) -> Result<EphemeralIvk, bip32::Error> {
        self.0
            .derive_child(ChildNumber::new(2, false)?)
            .map(EphemeralIvk)
    }

    /// Derives the BIP44 public key at the "address level" path corresponding to the given scope
    /// and address index.
    pub fn derive_address_pubkey(
        &self,
        scope: TransparentKeyScope,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::PublicKey, bip32::Error> {
        Ok(*self
            .0
            .derive_child(scope.into())?
            .derive_child(address_index.into())?
            .public_key())
    }

    /// Derives the public key corresponding to the given full BIP 32 path.
    ///
    /// This enforces that the path has a prefix that could have been used to derive this
    /// `AccountPubKey`.
    pub fn derive_pubkey_at_bip32_path<P: consensus::Parameters>(
        &self,
        params: &P,
        expected_account_index: AccountId,
        path: &[ChildNumber],
    ) -> Result<secp256k1::PublicKey, bip32::Error> {
        if path.len() < 3 {
            Err(bip32::Error::ChildNumber)
        } else {
            match path.split_at(3) {
                ([purpose, coin_type, account_index], sub_path)
                    if purpose.is_hardened()
                        && purpose.index() == 44
                        && coin_type.is_hardened()
                        && coin_type.index() == params.network_type().coin_type()
                        && account_index.is_hardened()
                        && account_index.index() == expected_account_index.into() =>
                {
                    sub_path
                        .iter()
                        .try_fold(self.0.clone(), |acc, child_index| {
                            acc.derive_child(*child_index)
                        })
                        .map(|k| *k.public_key())
                }
                _ => Err(bip32::Error::ChildNumber),
            }
        }
    }

    /// Derives the internal ovk and external ovk corresponding to this
    /// transparent fvk. As specified in [ZIP 316][transparent-ovk].
    ///
    /// A wallet uses these both to encrypt the outgoing ciphertexts of a transaction that spends
    /// transparent funds, and to recover the outgoing ciphertexts of such a transaction.
    ///
    /// [transparent-ovk]: https://zips.z.cash/zip-0316#deriving-internal-keys
    pub fn ovks_for_shielding(&self) -> ShieldingOvks {
        let i_ovk = PrfExpand::TRANSPARENT_ZIP316_OVK
            .with(&self.0.attrs().chain_code, &self.0.public_key().serialize());
        let ovk_external = ExternalOvk(i_ovk[..32].try_into().unwrap());
        let ovk_internal = InternalOvk(i_ovk[32..].try_into().unwrap());

        ShieldingOvks::new(ovk_internal, ovk_external)
    }

    /// Derives the internal ovk corresponding to this transparent fvk.
    pub fn internal_ovk(&self) -> InternalOvk {
        self.ovks_for_shielding().internal
    }

    /// Derives the external ovk corresponding to this transparent fvk.
    pub fn external_ovk(&self) -> ExternalOvk {
        self.ovks_for_shielding().external
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.0.attrs().chain_code.to_vec();
        buf.extend_from_slice(&self.0.public_key().serialize());
        buf
    }

    pub fn deserialize(data: &[u8; 65]) -> Result<Self, bip32::Error> {
        let chain_code = data[..32].try_into().expect("correct length");
        let public_key = PublicKey::from_slice(&data[32..])?;
        Ok(AccountPubKey(ExtendedPublicKey::new(
            public_key,
            ExtendedKeyAttrs {
                depth: 3,
                // We do not expose the inner `ExtendedPublicKey`, so we can use dummy
                // values for the fields that are not encoded in an `AccountPubKey`.
                parent_fingerprint: [0xff, 0xff, 0xff, 0xff],
                child_number: ChildNumber::new(0, true).expect("correct"),
                chain_code,
            },
        )))
    }
}

#[cfg(feature = "transparent-inputs")]
pub(crate) mod private {
    use super::TransparentKeyScope;
    use bip32::ExtendedPublicKey;
    use secp256k1::PublicKey;
    pub trait SealedChangeLevelKey {
        const SCOPE: TransparentKeyScope;
        fn extended_pubkey(&self) -> &ExtendedPublicKey<PublicKey>;
        fn from_extended_pubkey(key: ExtendedPublicKey<PublicKey>) -> Self;
    }
}

/// Trait representing a transparent "incoming viewing key".
///
/// Unlike the Sapling and Orchard shielded protocols (which have viewing keys built into
/// their key trees and bound to specific spending keys), the transparent protocol has no
/// "viewing key" concept. Transparent viewing keys are instead emulated by making two
/// observations:
///
/// - [BIP32] hierarchical derivation is structured as a tree.
/// - The [BIP44] key paths use non-hardened derivation below the account level.
///
/// A transparent viewing key for an account is thus defined as the root of a specific
/// non-hardened subtree underneath the account's path.
///
/// [BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
pub trait IncomingViewingKey: private::SealedChangeLevelKey + core::marker::Sized {
    /// Derives a transparent address at the provided child index.
    #[allow(deprecated)]
    fn derive_address(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<TransparentAddress, bip32::Error> {
        Ok(TransparentAddress::from_pubkey(
            &self.derive_pubkey(address_index)?,
        ))
    }

    /// Derives the public key at the provided child index.
    ///
    /// This is the key material [`derive_address`](Self::derive_address) hashes, which a
    /// caller needs directly when the address is determined by a script over several keys
    /// rather than by a single key hash.
    fn derive_pubkey(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<PublicKey, bip32::Error> {
        Ok(*self
            .extended_pubkey()
            .derive_child(address_index.into())?
            .public_key())
    }

    /// Searches the space of child indexes for an index that will
    /// generate a valid transparent address, and returns the resulting
    /// address and the index at which it was generated.
    fn default_address(&self) -> (TransparentAddress, NonHardenedChildIndex) {
        let mut address_index = NonHardenedChildIndex::ZERO;
        loop {
            match self.derive_address(address_index) {
                Ok(addr) => {
                    return (addr, address_index);
                }
                Err(_) => {
                    address_index = address_index.next().unwrap_or_else(|| {
                        panic!("Exhausted child index space attempting to find a default address.");
                    });
                }
            }
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let extpubkey = self.extended_pubkey();
        let mut buf = extpubkey.attrs().chain_code.to_vec();
        buf.extend_from_slice(&extpubkey.public_key().serialize());
        buf
    }

    fn deserialize(data: &[u8; 65]) -> Result<Self, bip32::Error> {
        let chain_code = data[..32].try_into().expect("correct length");
        let public_key = PublicKey::from_slice(&data[32..])?;
        Ok(Self::from_extended_pubkey(ExtendedPublicKey::new(
            public_key,
            ExtendedKeyAttrs {
                depth: 4,
                // We do not expose the inner `ExtendedPublicKey`, so we can use a dummy
                // value for the `parent_fingerprint` that is not encoded in an
                // `IncomingViewingKey`.
                parent_fingerprint: [0xff, 0xff, 0xff, 0xff],
                child_number: Self::SCOPE.into(),
                chain_code,
            },
        )))
    }
}

/// An incoming viewing key at the [BIP44] "external" path
/// `m/44'/<coin_type>'/<account>'/0`.
///
/// This allows derivation of child addresses that may be provided to external parties.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalIvk(ExtendedPublicKey<PublicKey>);

#[cfg(feature = "transparent-inputs")]
impl core::fmt::Debug for ExternalIvk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ExternalIvk").field(&"...").finish()
    }
}

#[cfg(feature = "transparent-inputs")]
impl private::SealedChangeLevelKey for ExternalIvk {
    const SCOPE: TransparentKeyScope = TransparentKeyScope(0);

    fn extended_pubkey(&self) -> &ExtendedPublicKey<PublicKey> {
        &self.0
    }

    fn from_extended_pubkey(key: ExtendedPublicKey<PublicKey>) -> Self {
        ExternalIvk(key)
    }
}

#[cfg(feature = "transparent-inputs")]
impl IncomingViewingKey for ExternalIvk {}

/// An incoming viewing key at the [BIP44] "internal" path
/// `m/44'/<coin_type>'/<account>'/1`.
///
/// This allows derivation of change addresses for use within the wallet, but which should
/// not be shared with external parties.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
#[derive(Clone)]
pub struct InternalIvk(ExtendedPublicKey<PublicKey>);

#[cfg(feature = "transparent-inputs")]
impl core::fmt::Debug for InternalIvk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("InternalIvk").field(&"...").finish()
    }
}

#[cfg(feature = "transparent-inputs")]
impl private::SealedChangeLevelKey for InternalIvk {
    const SCOPE: TransparentKeyScope = TransparentKeyScope(1);

    fn extended_pubkey(&self) -> &ExtendedPublicKey<PublicKey> {
        &self.0
    }

    fn from_extended_pubkey(key: ExtendedPublicKey<PublicKey>) -> Self {
        InternalIvk(key)
    }
}

#[cfg(feature = "transparent-inputs")]
impl IncomingViewingKey for InternalIvk {}

/// An incoming viewing key at the "ephemeral" path
/// `m/44'/<coin_type>'/<account>'/2`.
///
/// This allows derivation of ephemeral addresses for use within the wallet.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone)]
pub struct EphemeralIvk(ExtendedPublicKey<PublicKey>);

#[cfg(feature = "transparent-inputs")]
impl core::fmt::Debug for EphemeralIvk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EphemeralIvk").field(&"...").finish()
    }
}

#[cfg(feature = "transparent-inputs")]
impl EphemeralIvk {
    /// Derives a transparent address at the provided child index.
    pub fn derive_ephemeral_address(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<TransparentAddress, bip32::Error> {
        let child_key = self.0.derive_child(address_index.into())?;
        #[allow(deprecated)]
        Ok(TransparentAddress::from_pubkey(child_key.public_key()))
    }
}

/// Internal outgoing viewing key used for autoshielding.
pub struct InternalOvk([u8; 32]);

impl core::fmt::Debug for InternalOvk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("InternalOvk").field(&"...").finish()
    }
}

impl InternalOvk {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// External outgoing viewing key used by `zcashd` for transparent-to-shielded spends to
/// external receivers.
pub struct ExternalOvk([u8; 32]);

impl core::fmt::Debug for ExternalOvk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ExternalOvk").field(&"...").finish()
    }
}

impl ExternalOvk {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// The pair of outgoing viewing keys derived from a transparent full viewing key, as specified in
/// [ZIP 316][transparent-ovk].
///
/// The two keys are distinct types, but a consumer reaches [`InternalOvk::as_bytes`] or
/// [`ExternalOvk::as_bytes`] almost immediately, and past that point the scope of a key is carried
/// only by the position it was read from. [`Self::internal`] and [`Self::external`] name the scope
/// at that boundary, so that binding a key to the wrong scope is a visible mistake rather than a
/// transposition.
///
/// [transparent-ovk]: https://zips.z.cash/zip-0316#deriving-internal-keys
#[derive(Debug)]
pub struct ShieldingOvks {
    internal: InternalOvk,
    external: ExternalOvk,
}

impl ShieldingOvks {
    /// Constructs the pair from its two scopes.
    pub fn new(internal: InternalOvk, external: ExternalOvk) -> Self {
        Self { internal, external }
    }

    /// Returns the outgoing viewing key for the internal scope, which a wallet uses for the
    /// outputs it sends to itself.
    pub fn internal(&self) -> &InternalOvk {
        &self.internal
    }

    /// Returns the outgoing viewing key for the external scope, which a wallet uses for the
    /// outputs it sends to other recipients.
    pub fn external(&self) -> &ExternalOvk {
        &self.external
    }
}

#[cfg(all(
    feature = "transparent-key-encoding",
    any(test, feature = "test-dependencies")
))]
pub mod test_vectors;

#[cfg(all(test, feature = "transparent-inputs"))]
mod derivation_test_vectors;

#[cfg(all(test, feature = "transparent-key-encoding"))]
mod tests {
    use rand::{Rng, RngExt, SeedableRng as _};
    use rand_chacha::ChaChaRng;
    use secp256k1::SecretKey;
    use secrecy::SecretString;
    use zcash_protocol::consensus::NetworkType;
    use zcash_script::script::Evaluable;

    use super::{
        Key,
        test_vectors::{INVALID, VALID, VectorKind},
    };
    use crate::address::Address;

    /// Generates a uniformly random secp256k1 secret key.
    fn random_secret_key(rng: &mut impl Rng) -> SecretKey {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            if let Ok(secret) = SecretKey::from_secret_bytes(bytes) {
                return secret;
            }
        }
    }

    #[test]
    #[cfg(feature = "transparent-key-encoding")]
    fn der_encoding_roundtrip() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        for _ in 0..100 {
            let secret = random_secret_key(&mut rng);
            let compressed = rng.random_bool(0.5);
            let key = Key { secret, compressed };

            let encoded = key.der_encode();
            let decoded = Key::der_decode(&encoded, compressed).unwrap();

            assert_eq!(key.secret(), decoded.secret());
        }
    }

    /// Checks that parsed keys match test payload.
    #[test]
    fn base58_keys_valid_parse() {
        for v in VALID {
            match v.kind {
                VectorKind::Privkey { is_compressed } => {
                    // Must be valid private key
                    let secret = &SecretString::new(v.base58_encoding.into());
                    let privkey = Key::decode_base58(v.network, secret).unwrap();
                    assert_eq!(privkey.compressed, is_compressed);
                    assert_eq!(
                        hex::encode(privkey.secret.to_secret_bytes()),
                        v.raw_bytes_hex
                    );

                    // Private key must be invalid public key
                    assert_eq!(
                        zcash_address::ZcashAddress::try_from_encoded(v.base58_encoding),
                        Err(zcash_address::ParseError::NotZcash),
                    );
                }
                VectorKind::Pubkey => {
                    // Must be valid public key
                    let destination =
                        match zcash_address::ZcashAddress::try_from_encoded(v.base58_encoding)
                            .unwrap()
                            .convert_if_network::<Address>(v.network)
                            .unwrap()
                        {
                            Address::Transparent(addr) => addr,
                            _ => panic!("{} is not a transparent address", v.base58_encoding),
                        };
                    let script = destination.script();
                    assert_eq!(hex::encode(script.to_bytes()), v.raw_bytes_hex);

                    // Public key must be invalid private key
                    assert!(
                        Key::decode_base58(v.network, &SecretString::new(v.base58_encoding.into()))
                            .is_err()
                    );
                }
            }
        }
    }

    /// Checks that Base58 key parsing code is robust against a variety of corrupted data.
    #[test]
    fn base58_keys_invalid() {
        for &encoded in INVALID {
            assert!(
                Key::decode_base58(NetworkType::Main, &SecretString::new(encoded.into())).is_err()
            );
            assert_eq!(
                zcash_address::ZcashAddress::try_from_encoded(encoded),
                Err(zcash_address::ParseError::NotZcash),
            );
        }
    }

    #[test]
    #[cfg(feature = "transparent-key-encoding")]
    fn key_debug_redaction() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let secret = random_secret_key(&mut rng);
        let key = Key {
            secret,
            compressed: true,
        };
        let debug_str = format!("{key:?}");
        assert!(debug_str.contains("secret: \"...\""));
        assert!(debug_str.contains("compressed: true"));
    }
}

#[cfg(test)]
mod derivation_path_tests {
    use bip32::ChildNumber;
    use zcash_protocol::consensus::{MAIN_NETWORK, NetworkConstants};
    use zip32::{AccountId, fingerprint::SeedFingerprint};

    use ::transparent::pczt::Bip32Derivation;

    use super::{
        BIP_44_PURPOSE, NonHardenedChildIndex, TransparentKeyScope, ZIP_48_P2SH_SCRIPT_TYPE,
        ZIP_48_PURPOSE, extract_bip_44_fields, extract_zip_48_fields,
    };

    const HARDENED: u32 = ChildNumber::HARDENED_FLAG;

    /// The account index used by every path below.
    const ACCOUNT: u32 = 3;

    /// The address index used by every path below.
    const ADDRESS_INDEX: u32 = 5;

    fn seed_fingerprint() -> SeedFingerprint {
        SeedFingerprint::from_seed(&[0u8; 32]).unwrap()
    }

    fn coin_type() -> ChildNumber {
        ChildNumber(MAIN_NETWORK.coin_type() | HARDENED)
    }

    fn derivation(path: &[u32]) -> Bip32Derivation {
        Bip32Derivation::parse(seed_fingerprint().to_bytes(), path.to_vec()).unwrap()
    }

    fn bip_44_path() -> [u32; 5] {
        [
            BIP_44_PURPOSE.0,
            MAIN_NETWORK.coin_type() | HARDENED,
            ACCOUNT | HARDENED,
            TransparentKeyScope::INTERNAL.0,
            ADDRESS_INDEX,
        ]
    }

    fn zip_48_path() -> [u32; 6] {
        [
            ZIP_48_PURPOSE.0,
            MAIN_NETWORK.coin_type() | HARDENED,
            ACCOUNT | HARDENED,
            ZIP_48_P2SH_SCRIPT_TYPE.0,
            TransparentKeyScope::EXTERNAL.0,
            ADDRESS_INDEX,
        ]
    }

    #[test]
    fn extract_bip_44_fields_reads_a_bip_44_path() {
        assert_eq!(
            extract_bip_44_fields(
                &derivation(&bip_44_path()),
                &seed_fingerprint(),
                coin_type()
            ),
            Some((
                AccountId::try_from(ACCOUNT).unwrap(),
                TransparentKeyScope::INTERNAL,
                NonHardenedChildIndex::from_index(ADDRESS_INDEX).unwrap(),
            ))
        );
    }

    #[test]
    fn extract_bip_44_fields_rejects_other_paths() {
        // A ZIP 48 path is not a BIP 44 path.
        assert_eq!(
            extract_bip_44_fields(
                &derivation(&zip_48_path()),
                &seed_fingerprint(),
                coin_type()
            ),
            None
        );
        // A different seed.
        let other_seed = SeedFingerprint::from_seed(&[1u8; 32]).unwrap();
        assert_eq!(
            extract_bip_44_fields(&derivation(&bip_44_path()), &other_seed, coin_type()),
            None
        );
    }

    #[test]
    fn extract_zip_48_fields_reads_a_zip_48_path() {
        assert_eq!(
            extract_zip_48_fields(
                &derivation(&zip_48_path()),
                &seed_fingerprint(),
                coin_type()
            ),
            Some((
                AccountId::try_from(ACCOUNT).unwrap(),
                zip32::Scope::External,
                NonHardenedChildIndex::from_index(ADDRESS_INDEX).unwrap(),
            ))
        );
    }

    #[test]
    fn extract_zip_48_fields_rejects_other_paths() {
        assert_eq!(
            extract_zip_48_fields(
                &derivation(&bip_44_path()),
                &seed_fingerprint(),
                coin_type()
            ),
            None
        );
    }
}

#[cfg(test)]
mod derivation_tests {
    use alloc::vec::Vec;
    use core::ops::Range;

    use bip32::ChildNumber;
    use subtle::ConstantTimeEq;

    use super::{NonHardenedChildIndex, NonHardenedChildRange};

    #[cfg(feature = "transparent-inputs")]
    use {
        super::{
            AccountPrivKey, AccountPubKey, IncomingViewingKey, TransparentKeyScope,
            derivation_test_vectors as test_vectors,
        },
        ::transparent::address::TransparentAddress,
        zcash_protocol::consensus::{MAIN_NETWORK, NetworkConstants},
    };

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn address_derivation() {
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        for account_index in 0..5 {
            let account_index = zip32::AccountId::try_from(account_index).unwrap();
            let account_sk =
                AccountPrivKey::from_seed(&MAIN_NETWORK, &seed, account_index).unwrap();
            let account_pubkey = account_sk.to_account_pubkey();

            let external_ivk = account_pubkey.derive_external_ivk().unwrap();
            let (address, address_index) = external_ivk.default_address();

            let address_pubkey = account_pubkey
                .derive_address_pubkey(TransparentKeyScope::EXTERNAL, address_index)
                .unwrap();
            assert_eq!(TransparentAddress::from_pubkey(&address_pubkey), address);

            let expected_path = [
                ChildNumber::new(44, true).unwrap(),
                ChildNumber::new(MAIN_NETWORK.coin_type(), true).unwrap(),
                ChildNumber::new(account_index.into(), true).unwrap(),
                TransparentKeyScope::EXTERNAL.into(),
                address_index.into(),
            ];

            // For short paths, we get an error.
            for i in 0..3 {
                assert_eq!(
                    account_pubkey.derive_pubkey_at_bip32_path(
                        &MAIN_NETWORK,
                        account_index,
                        &expected_path[..i]
                    ),
                    Err(bip32::Error::ChildNumber),
                );
            }

            // The truncated-by-one path gives the external IVK.
            assert_eq!(
                account_pubkey.derive_pubkey_at_bip32_path(
                    &MAIN_NETWORK,
                    account_index,
                    &expected_path[..4],
                ),
                Ok(*external_ivk.0.public_key()),
            );

            // The full path gives the correct pubkey.
            assert_eq!(
                account_pubkey.derive_pubkey_at_bip32_path(
                    &MAIN_NETWORK,
                    account_index,
                    &expected_path,
                ),
                Ok(address_pubkey),
            );
        }
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn bip_32_test_vectors() {
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        for tv in test_vectors::bip_32() {
            let account_sk = AccountPrivKey::from_seed(
                &MAIN_NETWORK,
                &seed,
                zip32::AccountId::try_from(tv.account).unwrap(),
            )
            .unwrap();
            let account_pubkey = account_sk.to_account_pubkey();

            let mut key_bytes = [0u8; 65];
            key_bytes[..32].copy_from_slice(&tv.c);
            key_bytes[32..].copy_from_slice(&tv.pk);
            assert_eq!(account_pubkey.serialize(), key_bytes);

            let shielding_ovks = account_pubkey.ovks_for_shielding();
            assert_eq!(shielding_ovks.internal().as_bytes(), tv.internal_ovk);
            assert_eq!(shielding_ovks.external().as_bytes(), tv.external_ovk);

            // The test vectors are broken here: they should be deriving an address at the
            // address level, but instead use the account pubkey as an address.
            let address = TransparentAddress::PublicKeyHash(tv.address);

            #[cfg(feature = "transparent-inputs")]
            assert_eq!(
                TransparentAddress::from_pubkey(account_pubkey.0.public_key()),
                address
            );
        }
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn check_ovk_test_vectors() {
        for tv in test_vectors::transparent_ovk() {
            let mut key_bytes = [0u8; 65];
            key_bytes[..32].copy_from_slice(&tv.c);
            key_bytes[32..].copy_from_slice(&tv.pk);
            let account_key = AccountPubKey::deserialize(&key_bytes).unwrap();

            let shielding_ovks = account_key.ovks_for_shielding();

            assert_eq!(tv.internal_ovk, shielding_ovks.internal().as_bytes());
            assert_eq!(tv.external_ovk, shielding_ovks.external().as_bytes());
        }
    }

    #[test]
    fn nonhardened_indexes_accepted() {
        assert_eq!(0, NonHardenedChildIndex::from_index(0).unwrap().index());
        assert_eq!(
            0x7fffffff,
            NonHardenedChildIndex::from_index(0x7fffffff)
                .unwrap()
                .index()
        );
    }

    #[test]
    fn hardened_indexes_rejected() {
        assert!(NonHardenedChildIndex::from_index(0x80000000).is_none());
        assert!(NonHardenedChildIndex::from_index(0xffffffff).is_none());
    }

    #[test]
    fn nonhardened_index_next() {
        assert_eq!(1, NonHardenedChildIndex::ZERO.next().unwrap().index());
        assert!(
            NonHardenedChildIndex::from_index(0x7fffffff)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn nonhardened_child_range() {
        let collect = |range: Range<NonHardenedChildIndex>| {
            NonHardenedChildRange::from(range)
                .into_iter()
                .collect::<Vec<_>>()
        };
        let zero = NonHardenedChildIndex::ZERO;
        let one = zero.next().unwrap();
        let two = one.next().unwrap();

        assert_eq!(collect(zero..two), [zero, one]);
        assert_eq!(collect(one..one), []);
        assert_eq!(collect(two..one), []);
    }

    #[test]
    fn nonhardened_index_ct_eq() {
        assert!(check(
            NonHardenedChildIndex::ZERO,
            NonHardenedChildIndex::ZERO
        ));
        assert!(!check(
            NonHardenedChildIndex::ZERO,
            NonHardenedChildIndex::ZERO.next().unwrap()
        ));

        fn check<T: ConstantTimeEq>(v1: T, v2: T) -> bool {
            v1.ct_eq(&v2).into()
        }
    }

    #[test]
    fn nonhardened_index_tryfrom_keyindex() {
        let nh: NonHardenedChildIndex = ChildNumber::new(0, false).unwrap().try_into().unwrap();
        assert_eq!(nh.index(), 0);

        assert!(NonHardenedChildIndex::try_from(ChildNumber::new(0, true).unwrap()).is_err());
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn account_priv_key_debug_redaction() {
        let sk =
            AccountPrivKey::from_seed(&MAIN_NETWORK, &[0u8; 64], zip32::AccountId::ZERO).unwrap();
        assert_eq!(format!("{sk:?}"), "AccountPrivKey(\"...\")");
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn viewing_key_debug_redaction() {
        let seed = [0u8; 32];
        let account_sk =
            AccountPrivKey::from_seed(&MAIN_NETWORK, &seed, zip32::AccountId::ZERO).unwrap();
        let account_pubkey = account_sk.to_account_pubkey();
        assert_eq!(format!("{account_pubkey:?}"), "AccountPubKey(\"...\")");

        let external_ivk = account_pubkey.derive_external_ivk().unwrap();
        assert_eq!(format!("{external_ivk:?}"), "ExternalIvk(\"...\")");

        let internal_ivk = account_pubkey.derive_internal_ivk().unwrap();
        assert_eq!(format!("{internal_ivk:?}"), "InternalIvk(\"...\")");

        let ephemeral_ivk = account_pubkey.derive_ephemeral_ivk().unwrap();
        assert_eq!(format!("{ephemeral_ivk:?}"), "EphemeralIvk(\"...\")");

        let shielding_ovks = account_pubkey.ovks_for_shielding();
        assert_eq!(
            format!("{shielding_ovks:?}"),
            "ShieldingOvks { internal: InternalOvk(\"...\"), external: ExternalOvk(\"...\") }"
        );
    }
}
