use std::cmp;
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt;
use std::io::Write;
use zcash_encoding::CompactSize;

pub(crate) mod address;

pub(crate) use address::Address;

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

            // We don't know for certain the preference order of unknown receivers, but it
            // is likely that the higher typecode has higher preference. The exact order
            // doesn't really matter, as unknown receivers have lower preference than
            // known receivers.
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
    /// The unified address contains both P2PKH and P2SH receivers.
    BothP2phkAndP2sh,
    /// The unified address contains a duplicated typecode.
    DuplicateTypecode(Typecode),
    /// The parsed typecode exceeds the maximum allowed CompactSize value.
    InvalidTypecodeValue(u64),
    /// The string is an invalid encoding.
    InvalidEncoding(String),
    /// The unified address only contains transparent receivers.
    OnlyTransparent,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BothP2phkAndP2sh => write!(f, "UA contains both P2PKH and P2SH receivers"),
            ParseError::DuplicateTypecode(c) => write!(f, "Duplicate typecode {}", u32::from(*c)),
            ParseError::InvalidTypecodeValue(v) => write!(f, "Typecode value out of range {}", v),
            ParseError::InvalidEncoding(msg) => write!(f, "Invalid encoding: {}", msg),
            ParseError::OnlyTransparent => write!(f, "UA only contains transparent receivers"),
        }
    }
}

impl Error for ParseError {}

pub(crate) mod private {
    use super::{ParseError, Typecode};
    use std::{cmp, convert::TryFrom};

    /// A raw address or viewing key.
    pub trait SealedReceiver:
        for<'a> TryFrom<(u32, &'a [u8]), Error = ParseError> + cmp::Ord + cmp::PartialOrd + Clone
    {
        fn typecode(&self) -> Typecode;
        fn data(&self) -> &[u8];
    }

    pub trait SealedContainer {
        const MAINNET: &'static str;
        const TESTNET: &'static str;
        const REGTEST: &'static str;

        type Receiver: SealedReceiver;

        fn from_inner(receivers: Vec<Self::Receiver>) -> Self;
    }
}

use private::SealedReceiver;

/// Trait providing common encoding logic for Unified containers.
pub trait Unified: private::SealedContainer + std::marker::Sized {
    fn try_from_bytes(hrp: &str, buf: &[u8]) -> Result<Self, ParseError> {
        fn read_receiver<R: SealedReceiver>(
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
                    "Truncated: unable to read {} bytes of address data",
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

        let encoded = f4jumble::f4jumble_inv(buf)
            .ok_or_else(|| ParseError::InvalidEncoding("F4Jumble decoding failed".to_owned()))?;

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
        Self::try_from_receivers(result)
    }

    fn try_from_receivers(receivers: Vec<Self::Receiver>) -> Result<Self, ParseError> {
        let mut typecodes = HashSet::with_capacity(receivers.len());
        for receiver in &receivers {
            let t = receiver.typecode();
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
            Ok(Self::from_inner(receivers))
        }
    }

    /// Returns the raw encoding of this Unified Address or viewing key.
    fn to_bytes(&self, hrp: &str) -> Vec<u8> {
        assert!(hrp.len() <= PADDING_LEN);

        let mut writer = std::io::Cursor::new(Vec::new());
        for receiver in &self.receivers() {
            let addr = receiver.data();
            CompactSize::write(
                &mut writer,
                <u32>::from(receiver.typecode()).try_into().unwrap(),
            )
            .unwrap();
            CompactSize::write(&mut writer, addr.len()).unwrap();
            writer.write_all(addr).unwrap();
        }

        let mut padding = [0u8; PADDING_LEN];
        padding[0..hrp.len()].copy_from_slice(&hrp.as_bytes());
        writer.write_all(&padding).unwrap();

        f4jumble::f4jumble(&writer.into_inner()).unwrap()
    }

    /// Returns the receivers contained within this address, sorted in preference order.
    fn receivers(&self) -> Vec<Self::Receiver> {
        let mut receivers = self.receivers_as_parsed().to_vec();
        // Unstable sorting is fine, because all receivers are guaranteed by construction
        // to have distinct typecodes.
        receivers.sort_unstable_by_key(|r| r.typecode());
        receivers
    }

    /// Returns the receivers in the order they were parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Self::receivers`.
    fn receivers_as_parsed(&self) -> &[Self::Receiver];
}
