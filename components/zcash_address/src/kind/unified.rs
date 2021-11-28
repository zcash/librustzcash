use std::cmp;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;
pub(crate) mod address;

pub(crate) use address::Address;

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
