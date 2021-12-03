use bech32::{self, FromBase32, ToBase32, Variant};
use std::cmp;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;

use crate::Network;

pub(crate) mod address;
pub(crate) mod fvk;
pub(crate) mod ivk;

pub use address::{Address, Receiver};
pub use fvk::{Fvk, Ufvk};
pub use ivk::{Ivk, Uivk};

const PADDING_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    P2pkh,
    P2sh,
    Sapling,
    Orchard,
    Unknown(u32),
}

impl Ord for Typecode {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
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

impl PartialOrd for Typecode {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
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

impl Typecode {
    fn is_transparent(&self) -> bool {
        // Unknown typecodes are treated as not transparent for the purpose of disallowing
        // only-transparent UAs, which can be represented with existing address encodings.
        matches!(self, Typecode::P2pkh | Typecode::P2sh)
    }
}

/// An error while attempting to parse a string as a Zcash address.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// The unified container contains both P2PKH and P2SH items.
    BothP2phkAndP2sh,
    /// The unified container contains a duplicated typecode.
    DuplicateTypecode(Typecode),
    /// The parsed typecode exceeds the maximum allowed CompactSize value.
    InvalidTypecodeValue(u64),
    /// The string is an invalid encoding.
    InvalidEncoding(String),
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
            ParseError::OnlyTransparent => write!(f, "UA only contains transparent items"),
            ParseError::NotUnified => write!(f, "Address is not Bech32m encoded"),
            ParseError::UnknownPrefix(s) => {
                write!(f, "Unrecognized Bech32m human-readable prefix: {}", s)
            }
        }
    }
}

impl Error for ParseError {}

pub(crate) mod private {
    use super::{ParseError, Typecode, PADDING_LEN};
    use crate::Network;
    use std::{
        cmp,
        convert::{TryFrom, TryInto},
        io::Write,
    };
    use zcash_encoding::CompactSize;

    /// A raw address or viewing key.
    pub trait SealedItem:
        for<'a> TryFrom<(u32, &'a [u8]), Error = ParseError> + cmp::Ord + cmp::PartialOrd + Clone
    {
        fn typecode(&self) -> Typecode;
        fn data(&self) -> &[u8];
    }

    /// A Unified Container containing addresses or viewing keys.
    pub trait SealedContainer: super::Container {
        const MAINNET: &'static str;
        const TESTNET: &'static str;
        const REGTEST: &'static str;

        /// Implementations of this method should act as unchecked constructors
        /// of the container type; the caller is guaranteed to check the
        /// general invariants that apply to all unified containers.
        fn from_inner(items: Vec<Self::Item>) -> Self;

        fn network_hrp(network: &Network) -> &'static str {
            match network {
                Network::Main => Self::MAINNET,
                Network::Test => Self::TESTNET,
                Network::Regtest => Self::REGTEST,
            }
        }

        fn hrp_network(hrp: &str) -> Option<Network> {
            if hrp == Self::MAINNET {
                Some(Network::Main)
            } else if hrp == Self::TESTNET {
                Some(Network::Test)
            } else if hrp == Self::REGTEST {
                Some(Network::Regtest)
            } else {
                None
            }
        }

        fn write_raw_encoding<W: Write>(&self, mut writer: W) {
            for item in &self.items() {
                let data = item.data();
                CompactSize::write(
                    &mut writer,
                    <u32>::from(item.typecode()).try_into().unwrap(),
                )
                .unwrap();
                CompactSize::write(&mut writer, data.len()).unwrap();
                writer.write_all(data).unwrap();
            }
        }

        /// Returns the jumbled padded raw encoding of this Unified Address or viewing key.
        fn to_jumbled_bytes(&self, hrp: &str) -> Vec<u8> {
            assert!(hrp.len() <= PADDING_LEN);

            let mut writer = std::io::Cursor::new(Vec::new());
            self.write_raw_encoding(&mut writer);

            let mut padding = [0u8; PADDING_LEN];
            padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
            writer.write_all(&padding).unwrap();

            f4jumble::f4jumble(&writer.into_inner()).unwrap()
        }

        /// Parse the items of the unified container.
        fn parse_items(hrp: &str, buf: &[u8]) -> Result<Vec<Self::Item>, ParseError> {
            fn read_receiver<R: SealedItem>(
                mut cursor: &mut std::io::Cursor<&[u8]>,
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

            let encoded = f4jumble::f4jumble_inv(buf).ok_or_else(|| {
                ParseError::InvalidEncoding("F4Jumble decoding failed".to_owned())
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

            let mut cursor = std::io::Cursor::new(encoded);
            let mut result = vec![];
            while cursor.position() < encoded.len().try_into().unwrap() {
                result.push(read_receiver(&mut cursor)?);
            }
            assert_eq!(cursor.position(), encoded.len().try_into().unwrap());

            Ok(result)
        }
    }
}

use private::SealedItem;

/// Trait providing common encoding and decoding logic for Unified containers.
pub trait Encoding: private::SealedContainer + std::marker::Sized {
    fn try_from_items(items: Vec<Self::Item>) -> Result<Self, ParseError> {
        let mut typecodes = HashSet::with_capacity(items.len());
        for item in &items {
            let t = item.typecode();
            if typecodes.contains(&t) {
                return Err(ParseError::DuplicateTypecode(t));
            } else if (t == Typecode::P2pkh && typecodes.contains(&Typecode::P2sh))
                || (t == Typecode::P2sh && typecodes.contains(&Typecode::P2pkh))
            {
                return Err(ParseError::BothP2phkAndP2sh);
            } else {
                typecodes.insert(t);
            }
        }

        if typecodes.iter().all(|t| t.is_transparent()) {
            Err(ParseError::OnlyTransparent)
        } else {
            // All checks pass!
            Ok(Self::from_inner(items))
        }
    }

    fn decode(s: &str) -> Result<(Network, Self), ParseError> {
        if let Ok((hrp, data, Variant::Bech32m)) = bech32::decode(s) {
            let hrp = hrp.as_str();
            // validate that the HRP corresponds to a known network.
            let net =
                Self::hrp_network(hrp).ok_or_else(|| ParseError::UnknownPrefix(hrp.to_string()))?;

            let data = Vec::<u8>::from_base32(&data)
                .map_err(|e| ParseError::InvalidEncoding(e.to_string()))?;

            Self::parse_items(hrp, &data[..])
                .and_then(Self::try_from_items)
                .map(|value| (net, value))
        } else {
            Err(ParseError::NotUnified)
        }
    }

    fn encode(&self, network: &Network) -> String {
        let hrp = Self::network_hrp(network);
        bech32::encode(
            hrp,
            self.to_jumbled_bytes(hrp).to_base32(),
            Variant::Bech32m,
        )
        .expect("hrp is invalid")
    }
}

/// Trait for for Unified containers, that exposes the items within them.
pub trait Container {
    /// The type of item in this unified container.
    type Item: SealedItem;

    /// Returns the items contained within this container, sorted in preference order.
    fn items(&self) -> Vec<Self::Item> {
        let mut items = self.items_as_parsed().to_vec();
        // Unstable sorting is fine, because all items are guaranteed by construction
        // to have distinct typecodes.
        items.sort_unstable_by_key(|r| r.typecode());
        items
    }

    /// Returns the items in the order they were parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Self::items`.
    fn items_as_parsed(&self) -> &[Self::Item];
}
