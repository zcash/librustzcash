//! Implementation of [ZIP 316](https://zips.z.cash/zip-0316) Unified Addresses and Viewing Keys.

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};
use core::cmp;
use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::num::TryFromIntError;
use static_assertions::const_assert_eq;

#[cfg(feature = "std")]
use std::error::Error;

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Checksum, Hrp};
use zcash_encoding::MAX_COMPACT_SIZE;

use zcash_protocol::{address::Revision, consensus::NetworkType};

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
/// distinguished from unknown values, and will be parsed as [`DataTypecode::Unknown`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataTypecode {
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

impl DataTypecode {
    const fn into_u32(self) -> u32 {
        match self {
            DataTypecode::P2pkh => 0x00,
            DataTypecode::P2sh => 0x01,
            DataTypecode::Sapling => 0x02,
            DataTypecode::Orchard => 0x03,
            DataTypecode::Unknown(typecode) => typecode,
        }
    }
}

const_assert_eq!(
    DataTypecode::P2sh.into_u32(),
    DataTypecode::P2pkh.into_u32() + 1
);

impl TryFrom<u32> for DataTypecode {
    type Error = ();

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        match typecode {
            0x00 => Ok(DataTypecode::P2pkh),
            0x01 => Ok(DataTypecode::P2sh),
            0x02 => Ok(DataTypecode::Sapling),
            0x03 => Ok(DataTypecode::Orchard),
            0x04..=0xBF | 0xFD..=MAX_COMPACT_SIZE => Ok(DataTypecode::Unknown(typecode)),
            _ => Err(()),
        }
    }
}

impl From<DataTypecode> for u32 {
    fn from(t: DataTypecode) -> Self {
        DataTypecode::into_u32(t)
    }
}

impl DataTypecode {
    /// A total ordering over the data typecodes that can be used to sort
    /// receivers and/or key items in order of decreasing priority,
    /// as specified in [ZIP 316](https://zips.z.cash/zip-0316#encoding-of-unified-addresses)
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
}

/// The known Metadata Typecodes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetadataTypecode {
    /// Expiration height metadata as specified in [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    ExpiryHeight,
    /// Expiration time metadata as specified in [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    ExpiryTime,
    /// An unknown MUST-understand metadata item as specified in
    /// [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    ///
    /// A parser encountering this typecode MUST halt with an error.
    MustUnderstand(u32),
    /// An unknown metadata item as specified in [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    Unknown(u32),
}

impl TryFrom<u32> for MetadataTypecode {
    type Error = ();

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        match typecode {
            0xC0..=0xDF => Ok(MetadataTypecode::Unknown(typecode)),
            0xE0 => Ok(MetadataTypecode::ExpiryHeight),
            0xE1 => Ok(MetadataTypecode::ExpiryTime),
            0xE2..=0xFC => Ok(MetadataTypecode::MustUnderstand(typecode)),
            _ => Err(()),
        }
    }
}

impl From<MetadataTypecode> for u32 {
    fn from(t: MetadataTypecode) -> Self {
        match t {
            MetadataTypecode::ExpiryHeight => 0xE0,
            MetadataTypecode::ExpiryTime => 0xE1,
            MetadataTypecode::MustUnderstand(value) => value,
            MetadataTypecode::Unknown(value) => value,
        }
    }
}

/// An enumeration of the Unified Container Item Typecodes.
///
/// Unified Address Items are partitioned into two sets: data items, which include
/// receivers and viewing keys, and metadata items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    /// A data (receiver or viewing key) typecode.
    Data(DataTypecode),
    /// A metadata typecode.
    Metadata(MetadataTypecode),
}

impl Typecode {
    /// The typecode for p2pkh data items.
    pub const P2PKH: Typecode = Typecode::Data(DataTypecode::P2pkh);
    /// The typecode for p2sh data items.
    pub const P2SH: Typecode = Typecode::Data(DataTypecode::P2sh);
    /// The typecode for Sapling data items.
    pub const SAPLING: Typecode = Typecode::Data(DataTypecode::Sapling);
    /// The typecode for Orchard data items.
    pub const ORCHARD: Typecode = Typecode::Data(DataTypecode::Orchard);
}

impl TryFrom<u32> for Typecode {
    type Error = ParseError;

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        DataTypecode::try_from(typecode)
            .map_or_else(
                |()| MetadataTypecode::try_from(typecode).map(Typecode::Metadata),
                |t| Ok(Typecode::Data(t)),
            )
            .map_err(|()| ParseError::InvalidTypecodeValue(typecode))
    }
}

impl From<Typecode> for u32 {
    fn from(t: Typecode) -> Self {
        match t {
            Typecode::Data(tc) => tc.into(),
            Typecode::Metadata(tc) => tc.into(),
        }
    }
}

impl TryFrom<Typecode> for usize {
    type Error = TryFromIntError;

    fn try_from(t: Typecode) -> Result<Self, Self::Error> {
        u32::from(t).try_into()
    }
}

/// An enumeration of known Unified Metadata Item types.
///
/// Unknown MUST-understand metadata items are NOT represented using this type, as the presence of
/// an unrecognized metadata item with a typecode in the `MUST-understand` range will result in a
/// parse failure, instead of the construction of a metadata item.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MetadataItem {
    /// The expiry height for a Unified Address or Unified Viewing Key
    ExpiryHeight(u32),
    /// The expiry time for a Unified Address or Unified Viewing Key
    ExpiryTime(u64),
    /// A Metadata Item with an unrecognized Typecode. MUST-understand metadata items are NOT
    /// represented using this type, as the presence of an unrecognized metadata item with a
    /// typecode in the `MUST-understand` range will result in a parse failure.
    Unknown { typecode: u32, data: Vec<u8> },
}

impl MetadataItem {
    /// Parse a metadata item for the specified metadata typecode from the provided bytes.
    pub fn parse(
        revision: Revision,
        typecode: MetadataTypecode,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        use MetadataTypecode::*;
        use Revision::*;
        match (revision, typecode) {
            (R1, ExpiryHeight) => data
                .try_into()
                .map(u32::from_le_bytes)
                .map(MetadataItem::ExpiryHeight)
                .map_err(|_| {
                    ParseError::InvalidEncoding(
                        "Expiry height must be a 32-bit little-endian value.".to_string(),
                    )
                }),
            (R1, ExpiryTime) => data
                .try_into()
                .map(u64::from_le_bytes)
                .map(MetadataItem::ExpiryTime)
                .map_err(|_| {
                    ParseError::InvalidEncoding(
                        "Expiry time must be a 64-bit little-endian value.".to_string(),
                    )
                }),
            (R0, ExpiryHeight | ExpiryTime) => Err(ParseError::NotUnderstood(typecode.into())),
            (R0 | R1, MustUnderstand(tc)) => Err(ParseError::NotUnderstood(tc)),
            // This implementation treats the 0xC0..OxFD range as unknown metadata for both R0 and
            // R1, as no typecodes were specified in this range for R0 and were "reclaimed" as
            // metadata codes by ZIP 316 at the time R1 was introduced.
            (R0 | R1, Unknown(typecode)) => Ok(MetadataItem::Unknown {
                typecode,
                data: data.to_vec(),
            }),
        }
    }

    /// Returns the typecode for this metadata item.
    pub fn typecode(&self) -> MetadataTypecode {
        match self {
            MetadataItem::ExpiryHeight(_) => MetadataTypecode::ExpiryHeight,
            MetadataItem::ExpiryTime(_) => MetadataTypecode::ExpiryTime,
            MetadataItem::Unknown { typecode, .. } => MetadataTypecode::Unknown(*typecode),
        }
    }

    /// Returns the raw bytes of this metadata item.
    pub fn data(&self) -> Cow<'_, [u8]> {
        match self {
            MetadataItem::ExpiryHeight(h) => Cow::from(h.to_le_bytes().to_vec()),
            MetadataItem::ExpiryTime(t) => Cow::from(t.to_le_bytes().to_vec()),
            MetadataItem::Unknown { data, .. } => Cow::from(data),
        }
    }
}

/// A Unified Encoding Item.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Item<T> {
    /// A data item; either a receiver (for Unified Addresses) or a key (for Unified Viewing Keys)
    Data(T),
    /// A metadata item.
    Metadata(MetadataItem),
}

impl<T: private::SealedDataItem> Item<T> {
    /// Returns the typecode for this item.
    pub fn typecode(&self) -> Typecode {
        match self {
            Item::Data(d) => Typecode::Data(d.typecode()),
            Item::Metadata(m) => Typecode::Metadata(m.typecode()),
        }
    }

    /// The total ordering over items by their typecodes, used for encoding as specified
    /// in [ZIP 316](https://zips.z.cash/zip-0316#encoding-of-unified-addresses)
    pub fn encoding_order(a: &Self, b: &Self) -> cmp::Ordering {
        u32::from(a.typecode()).cmp(&u32::from(b.typecode()))
    }

    /// Returns the raw binary representation of the data for this item.
    pub fn data(&self) -> Cow<'_, [u8]> {
        match self {
            Item::Data(d) => Cow::from(d.data()),
            Item::Metadata(m) => m.data(),
        }
    }

    /// Returns whether this item is a transparent receiver or key.
    pub fn is_transparent_data_item(&self) -> bool {
        self.typecode() == Typecode::P2PKH || self.typecode() == Typecode::P2SH
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
    InvalidTypecodeValue(u32),
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
    /// A `MUST-understand` metadata item was not recognized.
    NotUnderstood(u32),
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
            ParseError::NotUnderstood(tc) => {
                write!(
                    f,
                    "MUST-understand metadata item with typecode {} was not recognized; please upgrade.",
                    tc
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for ParseError {}

pub(crate) mod private {
    use alloc::{borrow::ToOwned, string::ToString, vec::Vec};
    use core::convert::{TryFrom, TryInto};
    use core2::io::Write;

    use super::{DataTypecode, ParseError, Typecode, PADDING_LEN};
    use crate::unified::{Item, MetadataItem};
    use zcash_encoding::CompactSize;
    use zcash_protocol::{address::Revision, consensus::NetworkType};

    /// A raw address or viewing key.
    pub trait SealedDataItem: Clone {
        /// Parse a data item for the specified data typecode from the provided bytes.
        fn parse(tc: DataTypecode, value: &[u8]) -> Result<Self, ParseError>;

        /// Returns the typecode of this data item.
        fn typecode(&self) -> DataTypecode;

        /// Returns the raw bytes of this data item.
        fn data(&self) -> &[u8];
    }

    /// A Unified Container containing addresses or viewing keys.
    pub trait SealedContainer: super::Container + core::marker::Sized {
        const MAINNET_R0: &'static str;
        const TESTNET_R0: &'static str;
        const REGTEST_R0: &'static str;

        const MAINNET_R1: &'static str;
        const TESTNET_R1: &'static str;
        const REGTEST_R1: &'static str;

        /// Implementations of this method should act as unchecked constructors
        /// of the container type; the caller is guaranteed to check the
        /// general invariants that apply to all unified containers.
        fn from_inner(revision: Revision, items: Vec<Item<Self::DataItem>>) -> Self;

        fn network_hrp(revision: Revision, network: &NetworkType) -> &'static str {
            match (revision, network) {
                (Revision::R0, NetworkType::Main) => Self::MAINNET_R0,
                (Revision::R0, NetworkType::Test) => Self::TESTNET_R0,
                (Revision::R0, NetworkType::Regtest) => Self::REGTEST_R0,
                (Revision::R1, NetworkType::Main) => Self::MAINNET_R1,
                (Revision::R1, NetworkType::Test) => Self::TESTNET_R1,
                (Revision::R1, NetworkType::Regtest) => Self::REGTEST_R1,
            }
        }

        fn hrp_revision(hrp: &str) -> Option<Revision> {
            (hrp == Self::MAINNET_R0 || hrp == Self::TESTNET_R0 || hrp == Self::REGTEST_R0)
                .then_some(Revision::R0)
                .or_else(|| {
                    (hrp == Self::MAINNET_R1 || hrp == Self::TESTNET_R1 || hrp == Self::REGTEST_R1)
                        .then_some(Revision::R1)
                })
        }

        fn hrp_network(hrp: &str) -> Option<NetworkType> {
            (hrp == Self::MAINNET_R0 || hrp == Self::MAINNET_R1)
                .then_some(NetworkType::Main)
                .or_else(|| {
                    (hrp == Self::TESTNET_R0 || hrp == Self::TESTNET_R1)
                        .then_some(NetworkType::Test)
                })
                .or_else(|| {
                    (hrp == Self::REGTEST_R0 || hrp == Self::REGTEST_R1)
                        .then_some(NetworkType::Regtest)
                })
        }

        fn write_raw_encoding<W: Write>(&self, mut writer: W) {
            for item in self.items_as_parsed() {
                let data = item.data();
                CompactSize::write(
                    &mut writer,
                    <u32>::from(item.typecode()).try_into().unwrap(),
                )
                .unwrap();
                CompactSize::write(&mut writer, data.len()).unwrap();
                writer.write_all(&data).unwrap();
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
        #[allow(clippy::type_complexity)]
        fn parse_items<T: Into<Vec<u8>>>(
            hrp: &str,
            buf: T,
        ) -> Result<(Revision, Vec<Item<Self::DataItem>>), ParseError> {
            fn read_item<R: SealedDataItem>(
                revision: Revision,
                mut cursor: &mut core2::io::Cursor<&[u8]>,
            ) -> Result<Item<R>, ParseError> {
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
                // The "as usize" casts cannot change the values, because both
                // cursor.position() and addr_end are u64 values <= buf.len()
                // which is usize.
                let data = &buf[cursor.position() as usize..addr_end as usize];
                let result = match Typecode::try_from(typecode)? {
                    Typecode::Data(tc) => Item::Data(R::parse(tc, data)?),
                    Typecode::Metadata(tc) => {
                        Item::Metadata(MetadataItem::parse(revision, tc, data)?)
                    }
                };
                cursor.set_position(addr_end);
                Ok(result)
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

            let revision = Self::hrp_revision(hrp)
                .ok_or_else(|| ParseError::UnknownPrefix(hrp.to_string()))?;

            let mut cursor = core2::io::Cursor::new(encoded);
            let mut result = vec![];
            while cursor.position() < encoded.len().try_into().unwrap() {
                result.push(read_item(revision, &mut cursor)?);
            }
            assert_eq!(cursor.position(), encoded.len().try_into().unwrap());

            Ok((revision, result))
        }

        /// A private function that constructs a unified container with the
        /// specified items, which must be in ascending typecode order.
        fn try_from_items_internal(
            revision: Revision,
            items: Vec<Item<Self::DataItem>>,
        ) -> Result<Self, ParseError> {
            let mut prev_code = None; // less than any Some
            let mut only_transparent = true;
            for item in &items {
                let t = item.typecode();
                let t_code = Some(u32::from(t));
                if t_code < prev_code {
                    return Err(ParseError::InvalidTypecodeOrder);
                } else if t_code == prev_code {
                    return Err(ParseError::DuplicateTypecode(t));
                } else if t == Typecode::P2SH && prev_code == Some(u32::from(DataTypecode::P2pkh)) {
                    // P2pkh and P2sh can only be in that order and next to each other,
                    // otherwise we would detect an out-of-order or duplicate typecode.
                    return Err(ParseError::BothP2phkAndP2sh);
                } else {
                    prev_code = t_code;
                    only_transparent = only_transparent && item.is_transparent_data_item();
                }
            }

            if only_transparent {
                Err(ParseError::OnlyTransparent)
            } else {
                // All checks pass!
                Ok(Self::from_inner(revision, items))
            }
        }

        fn parse_internal<T: Into<Vec<u8>>>(hrp: &str, buf: T) -> Result<Self, ParseError> {
            Self::parse_items(hrp, buf)
                .and_then(|(revision, items)| Self::try_from_items_internal(revision, items))
        }
    }
}

use private::SealedDataItem;

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
    /// Constructs a value of a unified container type from a vector of container
    /// items. These items will be sorted according to typecode as specified in ZIP
    /// 316, so this method is not necessarily round-trip compatible with
    /// [`Container::items_as_parsed`].
    ///
    /// This function will return an error in the case that the following ZIP 316
    /// invariants concerning the composition of a unified container are
    /// violated:
    /// * the item list may not contain two items having the same typecode
    /// * the item list may not contain both P2PKH and P2SH items.
    fn try_from_items(
        revision: Revision,
        mut items: Vec<Item<Self::DataItem>>,
    ) -> Result<Self, ParseError> {
        items.sort_unstable_by(Item::encoding_order);
        Self::try_from_items_internal(revision, items)
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
        let hrp = Self::network_hrp(self.revision(), network);
        bech32::encode::<Bech32mZip316>(Hrp::parse_unchecked(hrp), &self.to_jumbled_bytes(hrp))
            .expect("F4Jumble ensures length is short enough by construction")
    }
}

/// Trait for Unified containers, that exposes the items within them.
pub trait Container {
    /// The type of data items in this unified container.
    type DataItem: SealedDataItem;

    /// Returns the items in encoding order.
    fn items_as_parsed(&self) -> &[Item<Self::DataItem>];

    /// Returns the revision of the ZIP 316 standard that this unified container
    /// conforms to.
    fn revision(&self) -> Revision;
}
