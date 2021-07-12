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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    P2pkh,
    P2sh,
    Sapling,
    Orchard,
    Unknown(u8),
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
            .map(Address)
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
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use proptest::{
        array::{uniform11, uniform20, uniform32},
        prelude::*,
    };

    use super::{Address, Receiver};

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
}
