//! Implementation of [ZIP 316](https://zips.z.cash/zip-0316) Unified Addresses and Viewing Keys.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp;
use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::num::TryFromIntError;

#[cfg(feature = "std")]
use std::error::Error;

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Checksum, Hrp};

use zcash_protocol::consensus::NetworkType;

pub(crate) mod address;
pub(crate) mod fvk;
pub(crate) mod ivk;

pub use address::{Address, Receiver};
pub use fvk::{Fvk, Ufvk};
pub use ivk::{Ivk, Uivk};

const PADDING_LEN: usize = 16;

/// The known Receiver and Viewing Key types.
///
/// The typecodes `0xFFFA..=0xFFFF` reserved for experiments are currently not
/// distinguished from unknown values, and will be parsed as [`Typecode::Unknown`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    /// A transparent P2PKH address, FVK, or IVK encoding as specified in [ZIP 316](https://zips.z.cash/zip-0316).
    P2pkh,
    /// A transparent P2SH address.
    ///
    /// This typecode cannot occur in a [`Ufvk`] or [`Uivk`].
    P2sh,
    /// A Sapling raw address, FVK, or IVK encoding as specified in [ZIP 316](https://zips.z.cash/zip-0316).
    Sapling,
    /// An Orchard raw address, FVK, or IVK encoding as specified in [ZIP 316](https://zips.z.cash/zip-0316).
    Orchard,
    /// An unknown or experimental typecode.
    Unknown(u32),
}

impl Typecode {
    pub fn preference_order(a: &Self, b: &Self) -> cmp::Ordering {
        match (a, b) {
            // Trivial equality checks.
            (Self::Orchard, Self::Orchard)
            | (Self::Sapling, Self::Sapling)
            | (Self::P2sh, Self::P2sh)
            | (Self::P2pkh, Self::P2pkh) => cmp::Ordering::Equal,

            // We don't know for certain the preference order of unknown items, but it
            // is likely that the higher typecode has higher preference. The exact order
            // doesn't really matter, as unknown items have lower preference than
            // known items.
            (Self::Unknown(a), Self::Unknown(b)) => b.cmp(a),

            // For the remaining cases, we rely on `match` always choosing the first arm
            // with a matching pattern. Patterns below are listed in priority order:
            (Self::Orchard, _) => cmp::Ordering::Less,
            (_, Self::Orchard) => cmp::Ordering::Greater,

            (Self::Sapling, _) => cmp::Ordering::Less,
            (_, Self::Sapling) => cmp::Ordering::Greater,

            (Self::P2sh, _) => cmp::Ordering::Less,
            (_, Self::P2sh) => cmp::Ordering::Greater,

            (Self::P2pkh, _) => cmp::Ordering::Less,
            (_, Self::P2pkh) => cmp::Ordering::Greater,
        }
    }

    pub fn encoding_order(a: &Self, b: &Self) -> cmp::Ordering {
        u32::from(*a).cmp(&u32::from(*b))
    }
}

impl TryFrom<u32> for Typecode {
    type Error = ParseError;

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        match typecode {
            0x00 => Ok(Typecode::P2pkh),
            0x01 => Ok(Typecode::P2sh),
            0x02 => Ok(Typecode::Sapling),
            0x03 => Ok(Typecode::Orchard),
            0x04..=0x02000000 => Ok(Typecode::Unknown(typecode)),
            0x02000001..=u32::MAX => Err(ParseError::InvalidTypecodeValue(typecode as u64)),
        }
    }
}

impl From<Typecode> for u32 {
    fn from(t: Typecode) -> Self {
        match t {
            Typecode::P2pkh => 0x00,
            Typecode::P2sh => 0x01,
            Typecode::Sapling => 0x02,
            Typecode::Orchard => 0x03,
            Typecode::Unknown(typecode) => typecode,
        }
    }
}

impl TryFrom<Typecode> for usize {
    type Error = TryFromIntError;
    fn try_from(t: Typecode) -> Result<Self, Self::Error> {
        u32::from(t).try_into()
    }
}

impl Typecode {
    fn is_transparent(&self) -> bool {
        // Unknown typecodes are treated as not transparent for the purpose of disallowing
        // only-transparent UAs, which can be represented with existing address encodings.
        matches!(self, Typecode::P2pkh | Typecode::P2sh)
    }
}

/// An error while attempting to parse a string as a Zcash address.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The unified container contains both P2PKH and P2SH items.
    BothP2phkAndP2sh,
    /// The unified container contains a duplicated typecode.
    DuplicateTypecode(Typecode),
    /// The parsed typecode exceeds the maximum allowed CompactSize value.
    InvalidTypecodeValue(u64),
    /// The string is an invalid encoding.
    InvalidEncoding(String),
    /// The items in the unified container are not in typecode order.
    InvalidTypecodeOrder,
    /// The unified container only contains transparent items.
    OnlyTransparent,
    /// The string is not Bech32m encoded, and so cannot be a unified address.
    NotUnified,
    /// The Bech32m string has an unrecognized human-readable prefix.
    UnknownPrefix(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BothP2phkAndP2sh => write!(f, "UA contains both P2PKH and P2SH items"),
            ParseError::DuplicateTypecode(c) => write!(f, "Duplicate typecode {}", u32::from(*c)),
            ParseError::InvalidTypecodeValue(v) => write!(f, "Typecode value out of range {}", v),
            ParseError::InvalidEncoding(msg) => write!(f, "Invalid encoding: {}", msg),
            ParseError::InvalidTypecodeOrder => write!(f, "Items are out of order."),
            ParseError::OnlyTransparent => write!(f, "UA only contains transparent items"),
            ParseError::NotUnified => write!(f, "Address is not Bech32m encoded"),
            ParseError::UnknownPrefix(s) => {
                write!(f, "Unrecognized Bech32m human-readable prefix: {}", s)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for ParseError {}

pub(crate) mod private {
    use alloc::borrow::ToOwned;
    use alloc::vec::Vec;
    use core::cmp;
    use core::convert::{TryFrom, TryInto};
    use core2::io::Write;

    use super::{ParseError, Typecode, PADDING_LEN};
    use zcash_encoding::CompactSize;
    use zcash_protocol::consensus::NetworkType;

    /// A raw address or viewing key.
    pub trait SealedItem: for<'a> TryFrom<(u32, &'a [u8]), Error = ParseError> + Clone {
        fn typecode(&self) -> Typecode;
        fn data(&self) -> &[u8];

        fn preference_order(a: &Self, b: &Self) -> cmp::Ordering {
            match Typecode::preference_order(&a.typecode(), &b.typecode()) {
                cmp::Ordering::Equal => a.data().cmp(b.data()),
                res => res,
            }
        }

        fn encoding_order(a: &Self, b: &Self) -> cmp::Ordering {
            match Typecode::encoding_order(&a.typecode(), &b.typecode()) {
                cmp::Ordering::Equal => a.data().cmp(b.data()),
                res => res,
            }
        }

        fn write_raw_encoding<W: Write>(&self, mut writer: W) {
            let data = self.data();
            CompactSize::write(
                &mut writer,
                <u32>::from(self.typecode()).try_into().unwrap(),
            )
            .unwrap();
            CompactSize::write(&mut writer, data.len()).unwrap();
            writer.write_all(data).unwrap();
        }
    }

    /// A Unified Container containing addresses or viewing keys.
    pub trait SealedContainer: super::Container + core::marker::Sized {
        const MAINNET: &'static str;
        const TESTNET: &'static str;
        const REGTEST: &'static str;

        /// Implementations of this method should act as unchecked constructors
        /// of the container type; the caller is guaranteed to check the
        /// general invariants that apply to all unified containers.
        fn from_inner(items: Vec<Self::Item>) -> Self;

        fn network_hrp(network: &NetworkType) -> &'static str {
            match network {
                NetworkType::Main => Self::MAINNET,
                NetworkType::Test => Self::TESTNET,
                NetworkType::Regtest => Self::REGTEST,
            }
        }

        fn hrp_network(hrp: &str) -> Option<NetworkType> {
            if hrp == Self::MAINNET {
                Some(NetworkType::Main)
            } else if hrp == Self::TESTNET {
                Some(NetworkType::Test)
            } else if hrp == Self::REGTEST {
                Some(NetworkType::Regtest)
            } else {
                None
            }
        }

        fn write_raw_encoding<W: Write>(&self, mut writer: W) {
            for item in self.items_as_parsed() {
                item.write_raw_encoding(&mut writer);
            }
        }

        /// Returns the jumbled padded raw encoding of this Unified Address or viewing key.
        fn to_jumbled_bytes(&self, hrp: &str) -> Vec<u8> {
            assert!(hrp.len() <= PADDING_LEN);

            let mut padded = Vec::new();
            self.write_raw_encoding(&mut padded);

            let mut padding = [0u8; PADDING_LEN];
            padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
            padded.write_all(&padding).unwrap();

            f4jumble::f4jumble(&padded)
                .unwrap_or_else(|e| panic!("f4jumble failed on {:?}: {}", padded, e))
        }

        /// Parse the items of the unified container.
        fn parse_items<T: Into<Vec<u8>>>(hrp: &str, buf: T) -> Result<Vec<Self::Item>, ParseError> {
            fn read_receiver<R: SealedItem>(
                mut cursor: &mut core2::io::Cursor<&[u8]>,
            ) -> Result<R, ParseError> {
                let typecode = CompactSize::read(&mut cursor)
                    .map(|v| u32::try_from(v).expect("CompactSize::read enforces MAX_SIZE limit"))
                    .map_err(|e| {
                        ParseError::InvalidEncoding(format!(
                            "Failed to deserialize CompactSize-encoded typecode {}",
                            e
                        ))
                    })?;
                let length = CompactSize::read(&mut cursor).map_err(|e| {
                    ParseError::InvalidEncoding(format!(
                        "Failed to deserialize CompactSize-encoded length {}",
                        e
                    ))
                })?;
                let addr_end = cursor.position().checked_add(length).ok_or_else(|| {
                    ParseError::InvalidEncoding(format!(
                        "Length value {} caused an overflow error",
                        length
                    ))
                })?;
                let buf = cursor.get_ref();
                if (buf.len() as u64) < addr_end {
                    return Err(ParseError::InvalidEncoding(format!(
                        "Truncated: unable to read {} bytes of item data",
                        length
                    )));
                }
                let result = R::try_from((
                    typecode,
                    &buf[cursor.position() as usize..addr_end as usize],
                ));
                cursor.set_position(addr_end);
                result
            }

            // Here we allocate if necessary to get a mutable Vec<u8> to unjumble.
            let mut encoded = buf.into();
            f4jumble::f4jumble_inv_mut(&mut encoded[..]).map_err(|e| {
                ParseError::InvalidEncoding(format!("F4Jumble decoding failed: {}", e))
            })?;

            // Validate and strip trailing padding bytes.
            if hrp.len() > 16 {
                return Err(ParseError::InvalidEncoding(
                    "Invalid human-readable part".to_owned(),
                ));
            }
            let mut expected_padding = [0; PADDING_LEN];
            expected_padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
            let encoded = match encoded.split_at(encoded.len() - PADDING_LEN) {
                (encoded, tail) if tail == expected_padding => Ok(encoded),
                _ => Err(ParseError::InvalidEncoding(
                    "Invalid padding bytes".to_owned(),
                )),
            }?;

            let mut cursor = core2::io::Cursor::new(encoded);
            let mut result = vec![];
            while cursor.position() < encoded.len().try_into().unwrap() {
                result.push(read_receiver(&mut cursor)?);
            }
            assert_eq!(cursor.position(), encoded.len().try_into().unwrap());

            Ok(result)
        }

        /// A private function that constructs a unified container with the
        /// specified items, which must be in ascending typecode order.
        fn try_from_items_internal(items: Vec<Self::Item>) -> Result<Self, ParseError> {
            assert!(u32::from(Typecode::P2sh) == u32::from(Typecode::P2pkh) + 1);

            let mut only_transparent = true;
            let mut prev_code = None; // less than any Some
            for item in &items {
                let t = item.typecode();
                let t_code = Some(u32::from(t));
                if t_code < prev_code {
                    return Err(ParseError::InvalidTypecodeOrder);
                } else if t_code == prev_code {
                    return Err(ParseError::DuplicateTypecode(t));
                } else if t == Typecode::P2sh && prev_code == Some(u32::from(Typecode::P2pkh)) {
                    // P2pkh and P2sh can only be in that order and next to each other,
                    // otherwise we would detect an out-of-order or duplicate typecode.
                    return Err(ParseError::BothP2phkAndP2sh);
                } else {
                    prev_code = t_code;
                    only_transparent = only_transparent && t.is_transparent();
                }
            }

            if only_transparent {
                Err(ParseError::OnlyTransparent)
            } else {
                // All checks pass!
                Ok(Self::from_inner(items))
            }
        }

        fn parse_internal<T: Into<Vec<u8>>>(hrp: &str, buf: T) -> Result<Self, ParseError> {
            Self::parse_items(hrp, buf).and_then(Self::try_from_items_internal)
        }
    }
}

use private::SealedItem;

/// The bech32m checksum algorithm, defined in [BIP-350], extended to allow all lengths
/// supported by [ZIP 316].
///
/// [BIP-350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
/// [ZIP 316]: https://zips.z.cash/zip-0316#solution
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bech32mZip316 {}
impl Checksum for Bech32mZip316 {
    type MidstateRepr = <Bech32m as Checksum>::MidstateRepr;
    // l^MAX from ZIP 316.
    const CODE_LENGTH: usize = 4194368;
    const CHECKSUM_LENGTH: usize = Bech32m::CHECKSUM_LENGTH;
    const GENERATOR_SH: [u32; 5] = Bech32m::GENERATOR_SH;
    const TARGET_RESIDUE: u32 = Bech32m::TARGET_RESIDUE;
}

/// Trait providing common encoding and decoding logic for Unified containers.
pub trait Encoding: private::SealedContainer {
    /// Constructs a value of a unified container type from a vector
    /// of container items, sorted according to typecode as specified
    /// in ZIP 316.
    ///
    /// This function will return an error in the case that the following ZIP 316
    /// invariants concerning the composition of a unified container are
    /// violated:
    /// * the item list may not contain two items having the same typecode
    /// * the item list may not contain only transparent items (or no items)
    /// * the item list may not contain both P2PKH and P2SH items.
    fn try_from_items(mut items: Vec<Self::Item>) -> Result<Self, ParseError> {
        items.sort_unstable_by(Self::Item::encoding_order);
        Self::try_from_items_internal(items)
    }

    /// Decodes a unified container from its string representation, preserving
    /// the order of its components so that it correctly obeys round-trip
    /// serialization invariants.
    fn decode(s: &str) -> Result<(NetworkType, Self), ParseError> {
        if let Ok(parsed) = CheckedHrpstring::new::<Bech32mZip316>(s) {
            let hrp = parsed.hrp();
            let hrp = hrp.as_str();
            // validate that the HRP corresponds to a known network.
            let net =
                Self::hrp_network(hrp).ok_or_else(|| ParseError::UnknownPrefix(hrp.to_string()))?;

            let data = parsed.byte_iter().collect::<Vec<_>>();

            Self::parse_internal(hrp, data).map(|value| (net, value))
        } else {
            Err(ParseError::NotUnified)
        }
    }

    /// Encodes the contents of the unified container to its string representation
    /// using the correct constants for the specified network, preserving the
    /// ordering of the contained items such that it correctly obeys round-trip
    /// serialization invariants.
    fn encode(&self, network: &NetworkType) -> String {
        let hrp = Self::network_hrp(network);
        bech32::encode::<Bech32mZip316>(Hrp::parse_unchecked(hrp), &self.to_jumbled_bytes(hrp))
            .expect("F4Jumble ensures length is short enough by construction")
    }
}

/// Trait for Unified containers, that exposes the items within them.
pub trait Container {
    /// The type of item in this unified container.
    type Item: Item;

    /// Returns the items contained within this container, sorted in preference order.
    fn items(&self) -> Vec<Self::Item> {
        let mut items = self.items_as_parsed().to_vec();
        // Unstable sorting is fine, because all items are guaranteed by construction
        // to have distinct typecodes.
        items.sort_unstable_by(Self::Item::preference_order);
        items
    }

    /// Returns the items in the order they were parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Self::items`.
    fn items_as_parsed(&self) -> &[Self::Item];
}

/// Trait for unified items, exposing specific methods on them.
pub trait Item: SealedItem {
    /// Returns the opaque typed encoding of this item.
    ///
    /// This is the same encoding used internally by [`Encoding::encode`].
    /// This API is for advanced usage; in most cases you should not depend
    /// on the typed encoding of items.
    fn typed_encoding(&self) -> Vec<u8> {
        let mut ret = vec![];
        self.write_raw_encoding(&mut ret);
        ret
    }
}

impl<T: SealedItem> Item for T {}
