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
pub use zcash_protocol::address::Revision;

#[cfg(feature = "test-dependencies")]
pub use address::testing;

const PADDING_LEN: usize = 16;

/// Typecodes for data items (receivers / viewing keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataTypecode {
    /// A transparent P2PKH address, FVK, or IVK encoding.
    P2pkh,
    /// A transparent P2SH address.
    P2sh,
    /// A Sapling raw address, FVK, or IVK encoding.
    Sapling,
    /// An Orchard raw address, FVK, or IVK encoding.
    Orchard,
    /// An unknown data typecode.
    Unknown(u32),
}

impl DataTypecode {
    fn is_transparent(&self) -> bool {
        matches!(self, DataTypecode::P2pkh | DataTypecode::P2sh)
    }
}

impl From<DataTypecode> for u32 {
    fn from(t: DataTypecode) -> Self {
        match t {
            DataTypecode::P2pkh => 0x00,
            DataTypecode::P2sh => 0x01,
            DataTypecode::Sapling => 0x02,
            DataTypecode::Orchard => 0x03,
            DataTypecode::Unknown(tc) => tc,
        }
    }
}

/// Typecodes for metadata items (0xC0..=0xFC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetadataTypecode {
    /// Expiry height (typecode 0xE0). 4-byte little-endian block height.
    ExpiryHeight,
    /// Expiry time (typecode 0xE1). 8-byte little-endian Unix timestamp.
    ExpiryTime,
    /// An unknown metadata typecode.
    Unknown(u32),
}

impl From<MetadataTypecode> for u32 {
    fn from(t: MetadataTypecode) -> Self {
        match t {
            MetadataTypecode::ExpiryHeight => 0xE0,
            MetadataTypecode::ExpiryTime => 0xE1,
            MetadataTypecode::Unknown(tc) => tc,
        }
    }
}

/// The known Receiver and Viewing Key types.
///
/// This typecode covers both data items (receivers, viewing keys) and metadata items
/// as defined in [ZIP 316](https://zips.z.cash/zip-0316).
///
/// The typecodes `0xFFFA..=0xFFFF` reserved for experiments are currently not
/// distinguished from unknown values, and will be parsed as [`Typecode::Data`]`(`[`DataTypecode::Unknown`]`)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    /// A data item (receiver or viewing key).
    Data(DataTypecode),
    /// A metadata item.
    Metadata(MetadataTypecode),
}

// Convenience associated constants for backward compatibility.
impl Typecode {
    /// P2PKH data typecode.
    pub const P2PKH: Typecode = Typecode::Data(DataTypecode::P2pkh);
    /// P2SH data typecode.
    pub const P2SH: Typecode = Typecode::Data(DataTypecode::P2sh);
    /// Sapling data typecode.
    pub const SAPLING: Typecode = Typecode::Data(DataTypecode::Sapling);
    /// Orchard data typecode.
    pub const ORCHARD: Typecode = Typecode::Data(DataTypecode::Orchard);
}

impl From<DataTypecode> for Typecode {
    fn from(tc: DataTypecode) -> Self {
        Typecode::Data(tc)
    }
}

impl From<MetadataTypecode> for Typecode {
    fn from(tc: MetadataTypecode) -> Self {
        Typecode::Metadata(tc)
    }
}

/// Boundary between "SHOULD-understand" (unknown) metadata and "MUST-understand" metadata.
const MUST_UNDERSTAND_METADATA_MIN: u32 = 0xE0;
/// Maximum metadata typecode value. Values >= 0xFD are reserved.
const METADATA_TYPECODE_MAX: u32 = 0xFC;
/// Minimum metadata typecode value.
const METADATA_TYPECODE_MIN: u32 = 0xC0;

impl Typecode {
    /// Returns the numeric typecode value.
    pub fn typecode_value(&self) -> u32 {
        match self {
            Typecode::Data(tc) => u32::from(*tc),
            Typecode::Metadata(tc) => u32::from(*tc),
        }
    }

    pub fn preference_order(a: &Self, b: &Self) -> cmp::Ordering {
        use DataTypecode::*;
        match (a, b) {
            // Data items always have preference over metadata.
            (Typecode::Data(_), Typecode::Metadata(_)) => cmp::Ordering::Less,
            (Typecode::Metadata(_), Typecode::Data(_)) => cmp::Ordering::Greater,

            // Metadata items: order by typecode.
            (Typecode::Metadata(a), Typecode::Metadata(b)) => u32::from(*a).cmp(&u32::from(*b)),

            // Data items: known items in priority order.
            (Typecode::Data(a), Typecode::Data(b)) => match (a, b) {
                (Orchard, Orchard) | (Sapling, Sapling) | (P2sh, P2sh) | (P2pkh, P2pkh) => {
                    cmp::Ordering::Equal
                }

                (Unknown(a), Unknown(b)) => b.cmp(a),

                (Orchard, _) => cmp::Ordering::Less,
                (_, Orchard) => cmp::Ordering::Greater,

                (Sapling, _) => cmp::Ordering::Less,
                (_, Sapling) => cmp::Ordering::Greater,

                (P2sh, _) => cmp::Ordering::Less,
                (_, P2sh) => cmp::Ordering::Greater,

                (P2pkh, _) => cmp::Ordering::Less,
                (_, P2pkh) => cmp::Ordering::Greater,
            },
        }
    }

    pub fn encoding_order(a: &Self, b: &Self) -> cmp::Ordering {
        a.typecode_value().cmp(&b.typecode_value())
    }

    fn is_transparent(&self) -> bool {
        match self {
            Typecode::Data(tc) => tc.is_transparent(),
            Typecode::Metadata(_) => false,
        }
    }
}

impl TryFrom<u32> for Typecode {
    type Error = ParseError;

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        match typecode {
            0x00 => Ok(Typecode::Data(DataTypecode::P2pkh)),
            0x01 => Ok(Typecode::Data(DataTypecode::P2sh)),
            0x02 => Ok(Typecode::Data(DataTypecode::Sapling)),
            0x03 => Ok(Typecode::Data(DataTypecode::Orchard)),
            0x04..=0xBF => Ok(Typecode::Data(DataTypecode::Unknown(typecode))),
            tc @ METADATA_TYPECODE_MIN..=METADATA_TYPECODE_MAX => {
                match tc {
                    0xE0 => Ok(Typecode::Metadata(MetadataTypecode::ExpiryHeight)),
                    0xE1 => Ok(Typecode::Metadata(MetadataTypecode::ExpiryTime)),
                    // 0xC0..=0xDF: unknown SHOULD-understand metadata
                    // 0xE2..=0xFC: unknown MUST-understand metadata
                    _ => Ok(Typecode::Metadata(MetadataTypecode::Unknown(tc))),
                }
            }
            0xFD..=0x02000000 => Ok(Typecode::Data(DataTypecode::Unknown(typecode))),
            0x02000001..=u32::MAX => Err(ParseError::InvalidTypecodeValue(typecode as u64)),
        }
    }
}

impl From<Typecode> for u32 {
    fn from(t: Typecode) -> Self {
        t.typecode_value()
    }
}

impl TryFrom<Typecode> for usize {
    type Error = TryFromIntError;
    fn try_from(t: Typecode) -> Result<Self, Self::Error> {
        u32::from(t).try_into()
    }
}

/// A parsed metadata item.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MetadataItem {
    /// An expiry height, encoded as a 4-byte little-endian block height.
    ExpiryHeight(u32),
    /// An expiry time, encoded as an 8-byte little-endian Unix timestamp.
    ExpiryTime(u64),
    /// An unknown metadata item.
    Unknown { typecode: u32, data: Vec<u8> },
}

impl MetadataItem {
    /// Returns the typecode for this metadata item.
    pub fn typecode(&self) -> MetadataTypecode {
        match self {
            MetadataItem::ExpiryHeight(_) => MetadataTypecode::ExpiryHeight,
            MetadataItem::ExpiryTime(_) => MetadataTypecode::ExpiryTime,
            MetadataItem::Unknown { typecode, .. } => MetadataTypecode::Unknown(*typecode),
        }
    }

    /// Returns the raw data bytes for this metadata item.
    pub fn data(&self) -> Vec<u8> {
        match self {
            MetadataItem::ExpiryHeight(h) => h.to_le_bytes().to_vec(),
            MetadataItem::ExpiryTime(t) => t.to_le_bytes().to_vec(),
            MetadataItem::Unknown { data, .. } => data.clone(),
        }
    }

    /// Returns the combined typecode for this metadata item.
    pub fn combined_typecode(&self) -> Typecode {
        Typecode::Metadata(self.typecode())
    }
}

/// An item within a unified container, which can be either a data item or a metadata item.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Uitem<T> {
    /// A data item (receiver or viewing key).
    Data(T),
    /// A metadata item.
    Metadata(MetadataItem),
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
    /// A MUST-understand metadata typecode was encountered that this implementation
    /// does not recognize.
    NotUnderstood(u32),
    /// A transparent receiver was found in a Revision 2 Unified Address.
    TransparentReceiverInR2Address,
    /// The unified container has no data items.
    NoDataItems,
    /// A metadata item has an invalid length.
    InvalidMetadataLength {
        typecode: u32,
        expected: usize,
        actual: usize,
    },
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
                    "MUST-understand metadata typecode 0x{:02X} not recognized",
                    tc
                )
            }
            ParseError::TransparentReceiverInR2Address => {
                write!(
                    f,
                    "Transparent receivers are not permitted in Revision 2 Unified Addresses"
                )
            }
            ParseError::NoDataItems => {
                write!(f, "Unified container has no data items")
            }
            ParseError::InvalidMetadataLength {
                typecode,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Metadata typecode 0x{:02X} has invalid length: expected {}, got {}",
                    typecode, expected, actual
                )
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

    use super::{
        MetadataItem, ParseError, Typecode, Uitem, METADATA_TYPECODE_MAX, METADATA_TYPECODE_MIN,
        MUST_UNDERSTAND_METADATA_MIN, PADDING_LEN,
    };
    use zcash_encoding::CompactSize;
    use zcash_protocol::address::Revision;
    use zcash_protocol::consensus::NetworkType;

    /// A raw address or viewing key (data item).
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

    /// Write a metadata item's raw encoding.
    fn write_metadata_raw_encoding<W: Write>(item: &MetadataItem, mut writer: W) {
        let tc_val: u32 = item.typecode().into();
        let data = item.data();
        CompactSize::write(&mut writer, tc_val.try_into().unwrap()).unwrap();
        CompactSize::write(&mut writer, data.len()).unwrap();
        writer.write_all(&data).unwrap();
    }

    /// A Unified Container containing addresses or viewing keys.
    pub trait SealedContainer: super::Container + core::marker::Sized {
        const MAINNET: &'static str;
        const TESTNET: &'static str;
        const REGTEST: &'static str;

        const MAINNET_R2: &'static str;
        const TESTNET_R2: &'static str;
        const REGTEST_R2: &'static str;

        /// HRP constants for transparent-including R2 addresses.
        /// For non-address containers (UVKs), these are set to the same values as
        /// the R2 constants since the distinction does not apply.
        const MAINNET_R2_TI: &'static str;
        const TESTNET_R2_TI: &'static str;
        const REGTEST_R2_TI: &'static str;

        /// Whether this container type is an Address container (as opposed to a viewing key).
        const IS_ADDRESS: bool;

        /// Implementations of this method should act as unchecked constructors
        /// of the container type; the caller is guaranteed to check the
        /// general invariants that apply to all unified containers.
        fn from_inner(revision: Revision, items: Vec<Uitem<Self::Item>>) -> Self;

        fn network_hrp(
            network: &NetworkType,
            revision: Revision,
            has_transparent: bool,
        ) -> &'static str {
            match (network, revision) {
                (NetworkType::Main, Revision::R0) => Self::MAINNET,
                (NetworkType::Test, Revision::R0) => Self::TESTNET,
                (NetworkType::Regtest, Revision::R0) => Self::REGTEST,
                (NetworkType::Main, Revision::R2) => {
                    if Self::IS_ADDRESS && has_transparent {
                        Self::MAINNET_R2_TI
                    } else {
                        Self::MAINNET_R2
                    }
                }
                (NetworkType::Test, Revision::R2) => {
                    if Self::IS_ADDRESS && has_transparent {
                        Self::TESTNET_R2_TI
                    } else {
                        Self::TESTNET_R2
                    }
                }
                (NetworkType::Regtest, Revision::R2) => {
                    if Self::IS_ADDRESS && has_transparent {
                        Self::REGTEST_R2_TI
                    } else {
                        Self::REGTEST_R2
                    }
                }
            }
        }

        fn hrp_network(hrp: &str) -> Option<(NetworkType, Revision)> {
            if hrp == Self::MAINNET {
                Some((NetworkType::Main, Revision::R0))
            } else if hrp == Self::TESTNET {
                Some((NetworkType::Test, Revision::R0))
            } else if hrp == Self::REGTEST {
                Some((NetworkType::Regtest, Revision::R0))
            } else if hrp == Self::MAINNET_R2 {
                Some((NetworkType::Main, Revision::R2))
            } else if hrp == Self::TESTNET_R2 {
                Some((NetworkType::Test, Revision::R2))
            } else if hrp == Self::REGTEST_R2 {
                Some((NetworkType::Regtest, Revision::R2))
            } else if hrp == Self::MAINNET_R2_TI {
                Some((NetworkType::Main, Revision::R2))
            } else if hrp == Self::TESTNET_R2_TI {
                Some((NetworkType::Test, Revision::R2))
            } else if hrp == Self::REGTEST_R2_TI {
                Some((NetworkType::Regtest, Revision::R2))
            } else {
                None
            }
        }

        fn write_raw_encoding<W: Write>(&self, mut writer: W) {
            for item in self.items_as_parsed() {
                match item {
                    Uitem::Data(data_item) => data_item.write_raw_encoding(&mut writer),
                    Uitem::Metadata(meta_item) => {
                        write_metadata_raw_encoding(meta_item, &mut writer);
                    }
                }
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

        /// Parse the items of the unified container, returning both data and metadata items.
        fn parse_items<T: Into<Vec<u8>>>(
            hrp: &str,
            buf: T,
            revision: Revision,
        ) -> Result<Vec<Uitem<Self::Item>>, ParseError> {
            fn read_raw_item(
                mut cursor: &mut core2::io::Cursor<&[u8]>,
            ) -> Result<(u32, Vec<u8>), ParseError> {
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
                let data = buf[cursor.position() as usize..addr_end as usize].to_vec();
                cursor.set_position(addr_end);
                Ok((typecode, data))
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
                let (tc_val, data) = read_raw_item(&mut cursor)?;

                // Classify by typecode range.
                if (METADATA_TYPECODE_MIN..=METADATA_TYPECODE_MAX).contains(&tc_val) {
                    // Metadata typecode range (0xC0..=0xFC).
                    if tc_val >= MUST_UNDERSTAND_METADATA_MIN {
                        // MUST-understand metadata (0xE0..=0xFC).
                        match revision {
                            Revision::R0 => {
                                // R0 containers must not contain MUST-understand metadata.
                                return Err(ParseError::NotUnderstood(tc_val));
                            }
                            Revision::R2 => {
                                // Parse known MUST-understand typecodes.
                                let meta = parse_must_understand_metadata(tc_val, &data)?;
                                result.push(Uitem::Metadata(meta));
                            }
                        }
                    } else {
                        // SHOULD-understand (unknown) metadata: valid in both R0 and R2.
                        result.push(Uitem::Metadata(MetadataItem::Unknown {
                            typecode: tc_val,
                            data,
                        }));
                    }
                } else {
                    // Data typecode (0x00..=0xBF or 0xFD+).
                    let typecode = Typecode::try_from(tc_val)?;
                    match typecode {
                        Typecode::Data(_) => {
                            let data_item = Self::Item::try_from((tc_val, &data[..]))?;
                            result.push(Uitem::Data(data_item));
                        }
                        Typecode::Metadata(_) => {
                            unreachable!("metadata typecodes handled above")
                        }
                    }
                }
            }
            assert_eq!(cursor.position(), encoded.len().try_into().unwrap());

            Ok(result)
        }

        /// A private function that constructs a unified container with the
        /// specified items, which must be in ascending typecode order.
        fn try_from_items_internal(
            revision: Revision,
            items: Vec<Uitem<Self::Item>>,
        ) -> Result<Self, ParseError> {
            assert!(u32::from(Typecode::P2SH) == u32::from(Typecode::P2PKH) + 1);

            let mut has_data_item = false;
            let mut only_transparent = true;
            let mut prev_code: Option<u32> = None;
            for item in &items {
                let t = match item {
                    Uitem::Data(d) => d.typecode(),
                    Uitem::Metadata(m) => m.combined_typecode(),
                };
                let t_code = Some(t.typecode_value());

                if t_code < prev_code {
                    return Err(ParseError::InvalidTypecodeOrder);
                } else if t_code == prev_code {
                    return Err(ParseError::DuplicateTypecode(t));
                }

                if let Uitem::Data(d) = item {
                    has_data_item = true;
                    let dt = d.typecode();
                    if dt == Typecode::P2SH && prev_code == Some(u32::from(Typecode::P2PKH)) {
                        return Err(ParseError::BothP2phkAndP2sh);
                    }

                    if !dt.is_transparent() {
                        only_transparent = false;
                    }
                }

                prev_code = t_code;
            }

            match revision {
                Revision::R0 => {
                    // R0: Must contain at least one shielded item (for both UAs and UVKs).
                    if !has_data_item || only_transparent {
                        return Err(ParseError::OnlyTransparent);
                    }
                }
                Revision::R2 => {
                    // R2 containers (both addresses and UVKs) must have at least one
                    // data item. The zu/tu HRP-content consistency is enforced in
                    // parse_internal for decoding, and in encode for encoding.
                    if !has_data_item {
                        return Err(ParseError::NoDataItems);
                    }
                }
            }

            Ok(Self::from_inner(revision, items))
        }

        fn parse_internal<T: Into<Vec<u8>>>(
            hrp: &str,
            buf: T,
            revision: Revision,
        ) -> Result<Self, ParseError> {
            let result = Self::parse_items(hrp, buf, revision)
                .and_then(|items| Self::try_from_items_internal(revision, items))?;

            // Enforce HRP-content consistency for R2 addresses.
            if revision == Revision::R2 && Self::IS_ADDRESS {
                let is_ti_hrp = hrp == Self::MAINNET_R2_TI
                    || hrp == Self::TESTNET_R2_TI
                    || hrp == Self::REGTEST_R2_TI;

                let has_transparent = result
                    .items_as_parsed()
                    .iter()
                    .any(|item| matches!(item, Uitem::Data(d) if d.typecode().is_transparent()));

                if !is_ti_hrp {
                    // zu: must not have transparent receivers
                    if has_transparent {
                        return Err(ParseError::TransparentReceiverInR2Address);
                    }
                    // zu: must have at least one shielded receiver
                    let has_shielded = result.items_as_parsed().iter().any(|item| {
                        matches!(item, Uitem::Data(d) if matches!(d.typecode(),
                            Typecode::Data(super::DataTypecode::Sapling)
                            | Typecode::Data(super::DataTypecode::Orchard)))
                    });
                    if !has_shielded {
                        return Err(ParseError::OnlyTransparent);
                    }
                }
                // tu: no additional constraints beyond those in try_from_items_internal
            }

            Ok(result)
        }
    }

    /// Parse a MUST-understand metadata item (typecode 0xE0..=0xFC).
    fn parse_must_understand_metadata(tc: u32, data: &[u8]) -> Result<MetadataItem, ParseError> {
        match tc {
            0xE0 => {
                // ExpiryHeight: exactly 4 bytes, little-endian.
                if data.len() != 4 {
                    return Err(ParseError::InvalidMetadataLength {
                        typecode: tc,
                        expected: 4,
                        actual: data.len(),
                    });
                }
                let height = u32::from_le_bytes(data.try_into().unwrap());
                Ok(MetadataItem::ExpiryHeight(height))
            }
            0xE1 => {
                // ExpiryTime: exactly 8 bytes, little-endian.
                if data.len() != 8 {
                    return Err(ParseError::InvalidMetadataLength {
                        typecode: tc,
                        expected: 8,
                        actual: data.len(),
                    });
                }
                let time = u64::from_le_bytes(data.try_into().unwrap());
                Ok(MetadataItem::ExpiryTime(time))
            }
            _ => {
                // Unknown MUST-understand: reject.
                Err(ParseError::NotUnderstood(tc))
            }
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
    /// Constructs a value of a unified container type from a vector of items,
    /// sorted according to typecode as specified in ZIP 316.
    ///
    /// This function will return an error if ZIP 316 invariants are violated.
    fn try_from_items(
        revision: Revision,
        mut items: Vec<Uitem<Self::Item>>,
    ) -> Result<Self, ParseError> {
        items.sort_unstable_by(|a, b| {
            let tc_a = match a {
                Uitem::Data(d) => d.typecode().typecode_value(),
                Uitem::Metadata(m) => m.combined_typecode().typecode_value(),
            };
            let tc_b = match b {
                Uitem::Data(d) => d.typecode().typecode_value(),
                Uitem::Metadata(m) => m.combined_typecode().typecode_value(),
            };
            tc_a.cmp(&tc_b)
        });
        Self::try_from_items_internal(revision, items)
    }

    /// Decodes a unified container from its string representation, preserving
    /// the order of its components so that it correctly obeys round-trip
    /// serialization invariants.
    fn decode(s: &str) -> Result<(NetworkType, Revision, Self), ParseError> {
        if let Ok(parsed) = CheckedHrpstring::new::<Bech32mZip316>(s) {
            let hrp = parsed.hrp();
            let hrp = hrp.as_str();
            // validate that the HRP corresponds to a known network.
            let (net, revision) =
                Self::hrp_network(hrp).ok_or_else(|| ParseError::UnknownPrefix(hrp.to_string()))?;

            let data = parsed.byte_iter().collect::<Vec<_>>();

            Self::parse_internal(hrp, data, revision).map(|value| (net, revision, value))
        } else {
            Err(ParseError::NotUnified)
        }
    }

    /// Encodes the contents of the unified container to its string representation
    /// using the correct constants for the specified network, preserving the
    /// ordering of the contained items such that it correctly obeys round-trip
    /// serialization invariants.
    fn encode(&self, network: &NetworkType) -> String {
        let has_transparent = Self::IS_ADDRESS
            && self
                .items_as_parsed()
                .iter()
                .any(|item| matches!(item, Uitem::Data(d) if d.typecode().is_transparent()));
        let hrp = Self::network_hrp(network, self.revision(), has_transparent);
        bech32::encode::<Bech32mZip316>(Hrp::parse_unchecked(hrp), &self.to_jumbled_bytes(hrp))
            .expect("F4Jumble ensures length is short enough by construction")
    }
}

/// Trait for Unified containers, that exposes the items within them.
pub trait Container {
    /// The type of data item in this unified container.
    type Item: Item;

    /// Returns the revision of the unified encoding.
    fn revision(&self) -> Revision;

    /// Returns the data items contained within this container, sorted in preference order.
    fn items(&self) -> Vec<Self::Item> {
        let mut items: Vec<_> = self
            .items_as_parsed()
            .iter()
            .filter_map(|item| match item {
                Uitem::Data(d) => Some(d.clone()),
                Uitem::Metadata(_) => None,
            })
            .collect();
        items.sort_unstable_by(Self::Item::preference_order);
        items
    }

    /// Returns all items (data and metadata) in the order they were parsed from the
    /// string encoding.
    fn items_as_parsed(&self) -> &[Uitem<Self::Item>];

    /// Returns just the metadata items from this container.
    fn metadata_items(&self) -> Vec<&MetadataItem> {
        self.items_as_parsed()
            .iter()
            .filter_map(|item| match item {
                Uitem::Metadata(m) => Some(m),
                Uitem::Data(_) => None,
            })
            .collect()
    }
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
