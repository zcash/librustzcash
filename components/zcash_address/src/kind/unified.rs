use std::cmp;
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt;
use std::iter;

use crate::kind;

mod f4jumble;

/// The HRP for a Bech32m-encoded mainnet Unified Address.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub(crate) const MAINNET: &str = "u";

/// The HRP for a Bech32m-encoded testnet Unified Address.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub(crate) const TESTNET: &str = "utest";

/// The HRP for a Bech32m-encoded regtest Unified Address.
pub(crate) const REGTEST: &str = "uregtest";

const PADDING_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    P2pkh,
    P2sh,
    Sapling,
    Orchard,
    Unknown(u8),
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

impl From<u8> for Typecode {
    fn from(typecode: u8) -> Self {
        match typecode {
            0x00 => Typecode::P2pkh,
            0x01 => Typecode::P2sh,
            0x02 => Typecode::Sapling,
            0x03 => Typecode::Orchard,
            _ => Typecode::Unknown(typecode),
        }
    }
}

impl From<Typecode> for u8 {
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
    /// The string is an invalid encoding.
    InvalidEncoding,
    /// The unified address only contains transparent receivers.
    OnlyTransparent,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BothP2phkAndP2sh => write!(f, "UA contains both P2PKH and P2SH receivers"),
            ParseError::DuplicateTypecode(typecode) => {
                write!(f, "Duplicate typecode {}", u8::from(*typecode))
            }
            ParseError::InvalidEncoding => write!(f, "Invalid encoding"),
            ParseError::OnlyTransparent => write!(f, "UA only contains transparent receivers"),
        }
    }
}

impl Error for ParseError {}

/// The set of known Receivers for Unified Addresses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Receiver {
    Orchard([u8; 43]),
    Sapling(kind::sapling::Data),
    P2pkh(kind::p2pkh::Data),
    P2sh(kind::p2sh::Data),
    Unknown { typecode: u8, data: Vec<u8> },
}

impl cmp::Ord for Receiver {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.typecode().cmp(&other.typecode()) {
            cmp::Ordering::Equal => self.addr().cmp(other.addr()),
            res => res,
        }
    }
}

impl cmp::PartialOrd for Receiver {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<(u8, &[u8])> for Receiver {
    type Error = ParseError;

    fn try_from((typecode, addr): (u8, &[u8])) -> Result<Self, Self::Error> {
        match typecode.into() {
            Typecode::P2pkh => addr.try_into().map(Receiver::P2pkh),
            Typecode::P2sh => addr.try_into().map(Receiver::P2sh),
            Typecode::Sapling => addr.try_into().map(Receiver::Sapling),
            Typecode::Orchard => addr.try_into().map(Receiver::Orchard),
            Typecode::Unknown(_) => Ok(Receiver::Unknown {
                typecode,
                data: addr.to_vec(),
            }),
        }
        .map_err(|_| ParseError::InvalidEncoding)
    }
}

impl Receiver {
    fn typecode(&self) -> Typecode {
        match self {
            Receiver::P2pkh(_) => Typecode::P2pkh,
            Receiver::P2sh(_) => Typecode::P2sh,
            Receiver::Sapling(_) => Typecode::Sapling,
            Receiver::Orchard(_) => Typecode::Orchard,
            Receiver::Unknown { typecode, .. } => Typecode::Unknown(*typecode),
        }
    }

    fn addr(&self) -> &[u8] {
        match self {
            Receiver::P2pkh(data) => data,
            Receiver::P2sh(data) => data,
            Receiver::Sapling(data) => data,
            Receiver::Orchard(data) => data,
            Receiver::Unknown { data, .. } => data,
        }
    }
}

/// A Unified Address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address(pub(crate) Vec<Receiver>);

impl TryFrom<&[u8]> for Address {
    type Error = ParseError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let encoded = f4jumble::f4jumble_inv(buf).ok_or(ParseError::InvalidEncoding)?;

        // Validate and strip trailing zero bytes.
        let encoded = match encoded.split_at(encoded.len() - PADDING_LEN) {
            (encoded, tail) if tail == &[0; PADDING_LEN][..] => Ok(encoded),
            _ => Err(ParseError::InvalidEncoding),
        }?;

        iter::repeat(())
            .scan(encoded, |encoded, _| match encoded {
                // Base case: we've parsed the full encoding.
                [] => None,
                // The raw encoding of a Unified Address is a concatenation of:
                // - typecode: byte
                // - length: byte
                // - addr: byte[length]
                [typecode, length, data @ ..] if data.len() >= *length as usize => {
                    let (addr, rest) = data.split_at(*length as usize);
                    *encoded = rest;
                    Some(Receiver::try_from((*typecode, addr)))
                }
                // The encoding is truncated.
                _ => Some(Err(ParseError::InvalidEncoding)),
            })
            .collect::<Result<_, _>>()
            .and_then(|receivers: Vec<Receiver>| receivers.try_into())
    }
}

impl TryFrom<Vec<Receiver>> for Address {
    type Error = ParseError;

    fn try_from(receivers: Vec<Receiver>) -> Result<Self, Self::Error> {
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
            Ok(Address(receivers))
        }
    }
}

impl Address {
    /// Returns the raw encoding of this Unified Address.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let encoded: Vec<_> = self
            .0
            .iter()
            .flat_map(|receiver| {
                let addr = receiver.addr();
                // Holds by construction.
                assert!(addr.len() < 256);

                iter::empty()
                    .chain(Some(receiver.typecode().into()))
                    .chain(Some(addr.len() as u8))
                    .chain(addr.iter().cloned())
            })
            .chain(iter::repeat(0).take(PADDING_LEN))
            .collect();

        f4jumble::f4jumble(&encoded).unwrap()
    }

    /// Returns the receivers contained within this address, sorted in preference order.
    pub fn receivers(&self) -> Vec<Receiver> {
        let mut receivers = self.0.clone();
        // Unstable sorting is fine, because all receivers are guaranteed by construction
        // to have distinct typecodes.
        receivers.sort_unstable_by_key(|r| r.typecode());
        receivers
    }

    /// Returns the receivers contained within this address, in the order they were
    /// parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Address::receivers`.
    pub fn receivers_as_parsed(&self) -> &[Receiver] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use proptest::{
        array::{uniform11, uniform20, uniform32},
        prelude::*,
    };

    use super::{Address, ParseError, Receiver, Typecode};

    prop_compose! {
        fn uniform43()(a in uniform11(0u8..), b in uniform32(0u8..)) -> [u8; 43] {
            let mut c = [0; 43];
            c[..11].copy_from_slice(&a);
            c[11..].copy_from_slice(&b);
            c
        }
    }

    fn arb_shielded_receiver() -> BoxedStrategy<Receiver> {
        prop_oneof![
            uniform43().prop_map(Receiver::Sapling),
            uniform43().prop_map(Receiver::Orchard),
        ]
        .boxed()
    }

    fn arb_transparent_receiver() -> BoxedStrategy<Receiver> {
        prop_oneof![
            uniform20(0u8..).prop_map(Receiver::P2pkh),
            uniform20(0u8..).prop_map(Receiver::P2sh),
        ]
        .boxed()
    }

    prop_compose! {
        fn arb_unified_address()(
            shielded in prop::collection::hash_set(arb_shielded_receiver(), 1..2),
            transparent in prop::option::of(arb_transparent_receiver()),
        ) -> Address {
            Address(shielded.into_iter().chain(transparent).collect())
        }
    }

    proptest! {
        #[test]
        fn ua_roundtrip(ua in arb_unified_address()) {
            let bytes = ua.to_bytes();
            let decoded = Address::try_from(&bytes[..]);
            prop_assert_eq!(decoded, Ok(ua));
        }
    }

    #[test]
    fn padding() {
        // The test cases below use `Address(vec![Receiver::Orchard([1; 43])])` as base.

        // Invalid padding ([0xff; 16] instead of [0x00; 16])
        let invalid_padding = [
            0xe6, 0x59, 0xd1, 0xed, 0xf7, 0x4b, 0xe3, 0x5e, 0x5a, 0x54, 0x0e, 0x41, 0x5d, 0x2f,
            0x0c, 0x0d, 0x33, 0x42, 0xbd, 0xbe, 0x9f, 0x82, 0x62, 0x01, 0xc1, 0x1b, 0xd4, 0x1e,
            0x42, 0x47, 0x86, 0x23, 0x05, 0x4b, 0x98, 0xd7, 0x76, 0x86, 0xa5, 0xe3, 0x1b, 0xd3,
            0x03, 0xca, 0x24, 0x44, 0x8e, 0x72, 0xc1, 0x4a, 0xc6, 0xbf, 0x3f, 0x2b, 0xce, 0xa7,
            0x7b, 0x28, 0x69, 0xc9, 0x84,
        ];
        assert_eq!(
            Address::try_from(&invalid_padding[..]),
            Err(ParseError::InvalidEncoding)
        );

        // Truncated padding ([0x00; 15] instead of [0x00; 16])
        let truncated_padding = [
            0x20, 0x67, 0xa5, 0xec, 0x48, 0x5c, 0xdb, 0x25, 0xa1, 0x37, 0xf7, 0x73, 0xc3, 0xae,
            0x62, 0x9e, 0xa5, 0x0e, 0x90, 0x5f, 0xda, 0xea, 0x5a, 0xe7, 0x4c, 0xb1, 0xda, 0xd9,
            0x24, 0xab, 0x92, 0x2f, 0xe6, 0xa4, 0x77, 0xa0, 0xa6, 0xb5, 0xfc, 0x0c, 0x61, 0xf4,
            0xe1, 0x89, 0x1e, 0x88, 0xa0, 0x25, 0xd8, 0xc7, 0x39, 0xa4, 0x4a, 0xc9, 0xbf, 0x3c,
            0x3b, 0xe8, 0xfd, 0x0f,
        ];
        assert_eq!(
            Address::try_from(&truncated_padding[..]),
            Err(ParseError::InvalidEncoding)
        );
    }

    #[test]
    fn truncated() {
        // The test cases below start from an encoding of
        //     `Address(vec![Receiver::Orchard([1; 43]), Receiver::Sapling([2; 43])])`
        // with the receiver data truncated, but valid padding.

        // - Missing the last data byte of the Sapling receiver.
        let truncated_sapling_data = [
            0x7a, 0x1f, 0xfd, 0x14, 0x0d, 0x0c, 0x5b, 0x36, 0x35, 0x37, 0x13, 0x6f, 0xc8, 0xa7,
            0x69, 0x48, 0x8d, 0x49, 0x0c, 0x41, 0x4d, 0xdf, 0x16, 0xc1, 0x91, 0xeb, 0xc7, 0xcb,
            0x4f, 0xca, 0x20, 0xa5, 0xa6, 0x9c, 0xcb, 0x63, 0xc6, 0x81, 0xbe, 0x8f, 0xac, 0xb7,
            0x1b, 0x7a, 0x11, 0x3f, 0xda, 0x36, 0x73, 0x4e, 0x75, 0x0f, 0x0b, 0x1f, 0x62, 0x6f,
            0x83, 0xba, 0xe0, 0xf4, 0x02, 0x81, 0x63, 0x61, 0x83, 0xbc, 0x48, 0xd8, 0x7d, 0x29,
            0xdc, 0x4f, 0xf7, 0xfd, 0x85, 0x0f, 0xfd, 0xc9, 0x60, 0x54, 0x4a, 0x87, 0x84, 0xfd,
            0x49, 0xb4, 0x4f, 0x7d, 0x9a, 0x6f, 0x37, 0x65, 0x35, 0x7c, 0x18, 0xeb, 0xd7, 0x52,
            0xb7, 0xb5, 0x80, 0x53, 0x64, 0x8d, 0x71,
        ];
        assert_eq!(
            Address::try_from(&truncated_sapling_data[..]),
            Err(ParseError::InvalidEncoding)
        );

        // - Truncated after the typecode of the Sapling receiver.
        let truncated_after_sapling_typecode = [
            0xb3, 0x8f, 0xc3, 0xfd, 0xe9, 0xfa, 0x66, 0x51, 0x8a, 0xac, 0xcf, 0x31, 0x82, 0xcf,
            0xaa, 0x0b, 0xd9, 0x9e, 0xe5, 0x01, 0xbd, 0xc2, 0xdb, 0x8f, 0xb1, 0xea, 0x08, 0x3b,
            0x6e, 0xd7, 0x71, 0x22, 0x15, 0xfe, 0xe2, 0xcd, 0x2d, 0xda, 0xbd, 0x79, 0x6a, 0x92,
            0xd6, 0xb0, 0x69, 0x02, 0x0e, 0xae, 0x95, 0x58, 0xdf, 0x89, 0x80, 0xaa, 0x71, 0xb6,
            0x01, 0x56, 0x60, 0xb2, 0x61, 0xf1,
        ];
        assert_eq!(
            Address::try_from(&truncated_after_sapling_typecode[..]),
            Err(ParseError::InvalidEncoding)
        );
    }

    #[test]
    fn duplicate_typecode() {
        // Construct and serialize an invalid UA.
        let ua = Address(vec![Receiver::Sapling([1; 43]), Receiver::Sapling([2; 43])]);
        let encoded = ua.to_bytes();
        assert_eq!(
            Address::try_from(&encoded[..]),
            Err(ParseError::DuplicateTypecode(Typecode::Sapling))
        );
    }

    #[test]
    fn p2pkh_and_p2sh() {
        // Construct and serialize an invalid UA.
        let ua = Address(vec![Receiver::P2pkh([0; 20]), Receiver::P2sh([0; 20])]);
        let encoded = ua.to_bytes();
        assert_eq!(
            Address::try_from(&encoded[..]),
            Err(ParseError::BothP2phkAndP2sh)
        );
    }

    #[test]
    fn only_transparent() {
        // Encoding of `Address(vec![Receiver::P2pkh([0; 20])])`.
        let encoded = vec![
            0x3b, 0x3d, 0xe6, 0xb3, 0xed, 0xaa, 0x0a, 0x36, 0x12, 0xbc, 0x8d, 0x2b, 0x1a, 0xaa,
            0x27, 0x7e, 0x45, 0xc0, 0xc2, 0x0e, 0xf9, 0x6f, 0x24, 0x9b, 0x79, 0x0a, 0x68, 0x76,
            0xa8, 0x4c, 0x3f, 0xf0, 0x1f, 0x39, 0x97, 0xbd, 0x15, 0x0d,
        ];

        // We can't actually exercise this error, because at present the only transparent
        // receivers we can use are P2PKH and P2SH (which cannot be used together), and
        // with only one of them we don't have sufficient data for F4Jumble (so we hit a
        // different error).
        assert_eq!(
            Address::try_from(&encoded[..]),
            Err(ParseError::InvalidEncoding)
        );
    }

    #[test]
    fn receivers_are_sorted() {
        // Construct a UA with receivers in an unsorted order.
        let ua = Address(vec![
            Receiver::P2pkh([0; 20]),
            Receiver::Orchard([0; 43]),
            Receiver::Unknown {
                typecode: 0xff,
                data: vec![],
            },
            Receiver::Sapling([0; 43]),
        ]);

        // `Address::receivers` sorts the receivers in priority order.
        assert_eq!(
            ua.receivers(),
            vec![
                Receiver::Orchard([0; 43]),
                Receiver::Sapling([0; 43]),
                Receiver::P2pkh([0; 20]),
                Receiver::Unknown {
                    typecode: 0xff,
                    data: vec![],
                },
            ]
        )
    }
}
