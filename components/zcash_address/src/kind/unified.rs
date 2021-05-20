use std::convert::{TryFrom, TryInto};
use std::iter;

use crate::{kind, ParseError};

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

/// The set of known Receivers for Unified Addresses.
///
/// This enum is an internal-only type, and is maintained in preference order, so that the
/// derived [`PartialOrd`] will sort receivers correctly. From its documentation:
///
/// > When derived on enums, variants are ordered by their top-to-bottom discriminant
/// > order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Receiver {
    Orchard([u8; 43]),
    Sapling(kind::sapling::Data),
    P2pkh(kind::p2pkh::Data),
    P2sh(kind::p2sh::Data),
    Unknown { typecode: u8, data: Vec<u8> },
}

impl TryFrom<(u8, &[u8])> for Receiver {
    type Error = ParseError;

    fn try_from((typecode, addr): (u8, &[u8])) -> Result<Self, Self::Error> {
        match typecode {
            0x00 => addr.try_into().map(Receiver::P2pkh),
            0x01 => addr.try_into().map(Receiver::P2sh),
            0x02 => addr.try_into().map(Receiver::Sapling),
            0x03 => addr.try_into().map(Receiver::Orchard),
            _ => Ok(Receiver::Unknown {
                typecode,
                data: addr.to_vec(),
            }),
        }
        .map_err(|_| ParseError::InvalidEncoding)
    }
}

impl Receiver {
    fn typecode(&self) -> u8 {
        match self {
            Receiver::P2pkh(_) => 0x00,
            Receiver::P2sh(_) => 0x01,
            Receiver::Sapling(_) => 0x02,
            Receiver::Orchard(_) => 0x03,
            Receiver::Unknown { typecode, .. } => *typecode,
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
                    Some((*typecode, addr).try_into())
                }
                // The encoding is truncated.
                _ => Some(Err(ParseError::InvalidEncoding)),
            })
            .collect::<Result<_, _>>()
            .map(Address)
    }
}

impl Address {
    /// Returns the raw encoding of this Unified Address.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|receiver| {
                let addr = receiver.addr();
                // Holds by construction.
                assert!(addr.len() < 256);

                let encoded: Vec<_> = iter::empty()
                    .chain(Some(receiver.typecode()))
                    .chain(Some(addr.len() as u8))
                    .chain(addr.into_iter().cloned())
                    .chain(iter::repeat(0).take(PADDING_LEN))
                    .collect();

                f4jumble::f4jumble(&encoded).unwrap()
            })
            .collect()
    }
}
