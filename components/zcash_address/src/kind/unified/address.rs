use zcash_protocol::{address::Revision, constants, PoolType};

use super::{private::SealedDataItem, DataTypecode, Item, ParseError};

use alloc::vec::Vec;
use core::{cmp, convert::TryInto};

/// The enumeration of Unified Address Receivers of known types.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Receiver {
    Orchard([u8; 43]),
    Sapling([u8; 43]),
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    Unknown { typecode: u32, data: Vec<u8> },
}

impl Receiver {
    fn preference_order(a: &Self, b: &Self) -> cmp::Ordering {
        DataTypecode::preference_order(&a.typecode(), &b.typecode())
    }
}

impl SealedDataItem for Receiver {
    fn parse(typecode: DataTypecode, data: &[u8]) -> Result<Self, ParseError> {
        match typecode {
            DataTypecode::P2pkh => data.try_into().map(Receiver::P2pkh),
            DataTypecode::P2sh => data.try_into().map(Receiver::P2sh),
            DataTypecode::Sapling => data.try_into().map(Receiver::Sapling),
            DataTypecode::Orchard => data.try_into().map(Receiver::Orchard),
            DataTypecode::Unknown(typecode) => Ok(Receiver::Unknown {
                typecode,
                data: data.to_vec(),
            }),
        }
        .map_err(|e| {
            ParseError::InvalidEncoding(format!(
                "Invalid address for typecode {:?}: {:?}",
                typecode, e
            ))
        })
    }

    fn typecode(&self) -> DataTypecode {
        match self {
            Receiver::P2pkh(_) => DataTypecode::P2pkh,
            Receiver::P2sh(_) => DataTypecode::P2sh,
            Receiver::Sapling(_) => DataTypecode::Sapling,
            Receiver::Orchard(_) => DataTypecode::Orchard,
            Receiver::Unknown { typecode, .. } => DataTypecode::Unknown(*typecode),
        }
    }

    fn data(&self) -> &[u8] {
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
///
/// # Examples
///
/// ```
/// # use core::convert::Infallible;
/// use zcash_address::{
///     unified::{self, Container, Encoding, Item},
///     ConversionError, TryFromRawAddress, ZcashAddress,
/// };
/// use zcash_protocol::address::Revision;
///
/// # #[cfg(not(feature = "std"))]
/// # fn main() {}
/// # #[cfg(feature = "std")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let address_from_user = || "u1pg2aaph7jp8rpf6yhsza25722sg5fcn3vaca6ze27hqjw7jvvhhuxkpcg0ge9xh6drsgdkda8qjq5chpehkcpxf87rnjryjqwymdheptpvnljqqrjqzjwkc2ma6hcq666kgwfytxwac8eyex6ndgr6ezte66706e3vaqrd25dzvzkc69kw0jgywtd0cmq52q5lkw6uh7hyvzjse8ksx";
/// let example_ua: &str = address_from_user();
///
/// // We can parse this directly as a `unified::Address`:
/// let (network, ua) = unified::Address::decode(example_ua)?;
///
/// // Or we can parse via `ZcashAddress` (which you should do):
/// struct MyUnifiedAddress(unified::Address);
/// impl TryFromRawAddress for MyUnifiedAddress {
///     // In this example we aren't checking the validity of the
///     // inner Unified Address, but your code should do so!
///     type Error = Infallible;
///
///     fn try_from_raw_unified(ua: unified::Address) -> Result<Self, ConversionError<Self::Error>> {
///         Ok(MyUnifiedAddress(ua))
///     }
/// }
/// let addr: ZcashAddress = example_ua.parse()?;
/// let parsed = addr.convert_if_network::<MyUnifiedAddress>(network)?;
/// assert_eq!(parsed.0, ua);
///
/// // We can obtain the receivers for the UA in preference order
/// // (the order in which wallets should prefer to use them):
/// let receivers: Vec<unified::Receiver> = ua.receivers();
///
/// // And we can create the UA from a list of receivers:
/// let new_ua = unified::Address::try_from_items(Revision::R0, receivers.into_iter().map(Item::Data).collect())?;
/// assert_eq!(new_ua, ua);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    pub(crate) revision: Revision,
    pub(crate) receivers: Vec<Item<Receiver>>,
}

impl Address {
    /// Returns the receiver items for this address, in order of decreasing preference.
    ///
    /// The receiver for a wallet to send to can safely be chosen by selecting the first receiver
    /// of a type that wallet supports from the result.
    pub fn receivers(&self) -> Vec<Receiver> {
        let mut result = self
            .receivers
            .iter()
            .filter_map(|item| match item {
                Item::Data(r) => Some(r.clone()),
                Item::Metadata(_) => None,
            })
            .collect::<Vec<Receiver>>();
        result.sort_unstable_by(Receiver::preference_order);
        result
    }
}

impl Address {
    /// Returns whether this address has the ability to receive transfers of the given pool type.
    pub fn has_receiver_of_type(&self, pool_type: PoolType) -> bool {
        self.receivers.iter().any(|item| match item {
            Item::Data(Receiver::Orchard(_)) => pool_type == PoolType::ORCHARD,
            Item::Data(Receiver::Sapling(_)) => pool_type == PoolType::SAPLING,
            Item::Data(Receiver::P2pkh(_)) | Item::Data(Receiver::P2sh(_)) => {
                pool_type == PoolType::TRANSPARENT
            }
            Item::Data(Receiver::Unknown { .. }) => false,
            Item::Metadata(_) => false,
        })
    }

    /// Returns whether this address contains the given receiver.
    pub fn contains_receiver(&self, receiver: &Receiver) -> bool {
        self.receivers
            .iter()
            .any(|item| matches!(item, Item::Data(r) if r == receiver))
    }

    /// Returns whether this address can receive a memo.
    pub fn can_receive_memo(&self) -> bool {
        self.receivers.iter().any(|r| {
            matches!(
                r,
                Item::Data(Receiver::Sapling(_)) | Item::Data(Receiver::Orchard(_))
            )
        })
    }
}

impl super::private::SealedContainer for Address {
    /// The HRP for a Bech32m-encoded mainnet Revision 0 Unified Address.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const MAINNET_R0: &'static str = constants::mainnet::HRP_UNIFIED_ADDRESS_R0;

    /// The HRP for a Bech32m-encoded testnet Revision 0 Unified Address.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const TESTNET_R0: &'static str = constants::testnet::HRP_UNIFIED_ADDRESS_R0;

    /// The HRP for a Bech32m-encoded regtest Unified Address.
    const REGTEST_R0: &'static str = constants::regtest::HRP_UNIFIED_ADDRESS_R0;

    /// The HRP for a Bech32m-encoded mainnet Revision 1 Unified Address.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const MAINNET_R1: &'static str = constants::mainnet::HRP_UNIFIED_ADDRESS_R1;

    /// The HRP for a Bech32m-encoded testnet Revision 1 Unified Address.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const TESTNET_R1: &'static str = constants::testnet::HRP_UNIFIED_ADDRESS_R1;

    /// The HRP for a Bech32m-encoded regtest Revision 1 Unified Address.
    const REGTEST_R1: &'static str = constants::regtest::HRP_UNIFIED_ADDRESS_R1;

    fn from_inner(revision: Revision, receivers: Vec<Item<Self::DataItem>>) -> Self {
        Self {
            revision,
            receivers,
        }
    }
}

impl super::Encoding for Address {}
impl super::Container for Address {
    type DataItem = Receiver;

    fn items_as_parsed(&self) -> &[Item<Receiver>] {
        &self.receivers
    }

    fn revision(&self) -> Revision {
        self.revision
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use alloc::vec::Vec;

    use proptest::{
        array::{uniform11, uniform20, uniform32},
        collection::vec,
        prelude::*,
        sample::select,
        strategy::Strategy,
    };

    use super::{Address, Receiver};
    use crate::unified::{DataTypecode, Item};
    use zcash_encoding::MAX_COMPACT_SIZE;
    use zcash_protocol::address::Revision;

    prop_compose! {
        fn uniform43()(a in uniform11(0u8..), b in uniform32(0u8..)) -> [u8; 43] {
            let mut c = [0; 43];
            c[..11].copy_from_slice(&a);
            c[11..].copy_from_slice(&b);
            c
        }
    }

    /// A strategy to generate an arbitrary transparent typecode.
    fn arb_transparent_typecode() -> impl Strategy<Value = DataTypecode> {
        select(vec![DataTypecode::P2pkh, DataTypecode::P2sh])
    }

    /// A strategy to generate an arbitrary transparent typecode.
    pub(crate) fn arb_revision() -> impl Strategy<Value = Revision> {
        select(vec![Revision::R0, Revision::R1])
    }

    /// A strategy to generate an arbitrary shielded (Sapling, Orchard, or unknown) typecode.
    fn arb_shielded_typecode() -> impl Strategy<Value = DataTypecode> {
        prop_oneof![
            Just(DataTypecode::Sapling),
            Just(DataTypecode::Orchard),
            ((<u32>::from(DataTypecode::Orchard) + 1)..MAX_COMPACT_SIZE)
                .prop_map(DataTypecode::Unknown)
        ]
    }

    /// A strategy to generate an arbitrary valid set of typecodes without
    /// duplication and containing only one of P2sh and P2pkh transparent
    /// typecodes.
    fn arb_typecodes() -> impl Strategy<Value = Vec<DataTypecode>> {
        prop::option::of(arb_transparent_typecode()).prop_flat_map(|transparent| {
            prop::collection::hash_set(arb_shielded_typecode(), 1..4)
                .prop_map(move |xs| xs.into_iter().chain(transparent).collect::<Vec<_>>())
        })
    }

    /// A strategy to generate a vector of unified address receivers containing random data. The
    /// resulting receivers may not be valid according to protocol rules; this generator is only
    /// intended for use in testing parsing and serialization.
    fn arb_unified_address_receivers(
        typecodes: Vec<DataTypecode>,
    ) -> impl Strategy<Value = Vec<Receiver>> {
        typecodes
            .into_iter()
            .map(|tc| match tc {
                DataTypecode::P2pkh => uniform20(0u8..).prop_map(Receiver::P2pkh).boxed(),
                DataTypecode::P2sh => uniform20(0u8..).prop_map(Receiver::P2sh).boxed(),
                DataTypecode::Sapling => uniform43().prop_map(Receiver::Sapling).boxed(),
                DataTypecode::Orchard => uniform43().prop_map(Receiver::Orchard).boxed(),
                DataTypecode::Unknown(typecode) => vec(any::<u8>(), 32..256)
                    .prop_map(move |data| Receiver::Unknown { typecode, data })
                    .boxed(),
            })
            .collect::<Vec<_>>()
    }

    /// A strategy to generate an arbitrary Unified Address containing only receivers, without
    /// additional metadata. The receivers in the resulting address  may not be valid according to
    /// protocol rules; this generator is only intended for use in testing parsing and
    /// serialization.
    pub fn arb_unified_address() -> impl Strategy<Value = Address> {
        (arb_typecodes(), arb_revision()).prop_flat_map(|(tc, revision)| {
            arb_unified_address_receivers(tc).prop_map(move |rs| {
                let mut receivers = rs.into_iter().map(Item::Data).collect::<Vec<_>>();
                receivers.sort_unstable_by(Item::encoding_order);
                Address {
                    revision,
                    receivers: receivers.clone(),
                }
            })
        })
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod test_vectors;

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;

    use assert_matches::assert_matches;
    use proptest::{prelude::*, sample::select};

    use zcash_protocol::consensus::NetworkType;

    use super::{Address, ParseError, Receiver};
    use crate::{
        kind::unified::{private::SealedContainer, Encoding as _},
        unified::{address::testing::arb_unified_address, Item, Revision, Typecode},
    };

    proptest! {
        #[test]
        fn ua_roundtrip(
            network in select(vec![NetworkType::Main, NetworkType::Test, NetworkType::Regtest]),
            ua in arb_unified_address(),
        ) {
            let encoded = ua.encode(&network);
            let decoded = Address::decode(&encoded);
            prop_assert_eq!(&decoded, &Ok((network, ua)));
            let reencoded = decoded.unwrap().1.encode(&network);
            prop_assert_eq!(reencoded, encoded);
        }
    }

    #[test]
    fn padding() {
        // The test cases below use `Address(vec![Receiver::Orchard([1; 43])])` as base.

        // Invalid padding ([0xff; 16] instead of [0x75, 0x00, 0x00, 0x00...])
        let invalid_padding = [
            0xe6, 0x59, 0xd1, 0xed, 0xf7, 0x4b, 0xe3, 0x5e, 0x5a, 0x54, 0x0e, 0x41, 0x5d, 0x2f,
            0x0c, 0x0d, 0x33, 0x42, 0xbd, 0xbe, 0x9f, 0x82, 0x62, 0x01, 0xc1, 0x1b, 0xd4, 0x1e,
            0x42, 0x47, 0x86, 0x23, 0x05, 0x4b, 0x98, 0xd7, 0x76, 0x86, 0xa5, 0xe3, 0x1b, 0xd3,
            0x03, 0xca, 0x24, 0x44, 0x8e, 0x72, 0xc1, 0x4a, 0xc6, 0xbf, 0x3f, 0x2b, 0xce, 0xa7,
            0x7b, 0x28, 0x69, 0xc9, 0x84,
        ];
        assert_eq!(
            Address::parse_internal(Address::MAINNET_R0, &invalid_padding[..]),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );

        // Short padding (padded to 15 bytes instead of 16)
        let truncated_padding = [
            0x9a, 0x56, 0x12, 0xa3, 0x43, 0x45, 0xe0, 0x82, 0x6c, 0xac, 0x24, 0x8b, 0x3b, 0x45,
            0x72, 0x9a, 0x53, 0xd5, 0xf8, 0xda, 0xec, 0x07, 0x7c, 0xba, 0x9f, 0xa8, 0xd2, 0x97,
            0x5b, 0xda, 0x73, 0x1b, 0xd2, 0xd1, 0x32, 0x6b, 0x7b, 0x36, 0xdd, 0x57, 0x84, 0x2a,
            0xa0, 0x21, 0x23, 0x89, 0x73, 0x85, 0xe1, 0x4b, 0x3e, 0x95, 0xb7, 0xd4, 0x67, 0xbc,
            0x4b, 0x31, 0xee, 0x5a,
        ];
        assert_eq!(
            Address::parse_internal(Address::MAINNET_R0, &truncated_padding[..]),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );
    }

    #[test]
    fn truncated() {
        // The test cases below start from an encoding of
        //     `Address(vec![Receiver::Orchard([1; 43]), Receiver::Sapling([2; 43])])`
        // with the receiver data truncated, but valid padding.

        // - Missing the last data byte of the Sapling receiver.
        let truncated_sapling_data = [
            0xaa, 0xb0, 0x6e, 0x7b, 0x26, 0x7a, 0x22, 0x17, 0x39, 0xfa, 0x07, 0x69, 0xe9, 0x32,
            0x2b, 0xac, 0x8c, 0x9e, 0x5e, 0x8a, 0xd9, 0x24, 0x06, 0x5a, 0x13, 0x79, 0x3a, 0x8d,
            0xb4, 0x52, 0xfa, 0x18, 0x4e, 0x33, 0x4d, 0x8c, 0x17, 0x77, 0x4d, 0x63, 0x69, 0x34,
            0x22, 0x70, 0x3a, 0xea, 0x30, 0x82, 0x5a, 0x6b, 0x37, 0xd1, 0x0d, 0xbe, 0x20, 0xab,
            0x82, 0x86, 0x98, 0x34, 0x6a, 0xd8, 0x45, 0x40, 0xd0, 0x25, 0x60, 0xbf, 0x1e, 0xb6,
            0xeb, 0x06, 0x85, 0x70, 0x4c, 0x42, 0xbc, 0x19, 0x14, 0xef, 0x7a, 0x05, 0xa0, 0x71,
            0xb2, 0x63, 0x80, 0xbb, 0xdc, 0x12, 0x08, 0x48, 0x28, 0x8f, 0x1c, 0x9e, 0xc3, 0x42,
            0xc6, 0x5e, 0x68, 0xa2, 0x78, 0x6c, 0x9e,
        ];
        assert_matches!(
            Address::parse_internal(Address::MAINNET_R0, &truncated_sapling_data[..]),
            Err(ParseError::InvalidEncoding(_))
        );

        // - Truncated after the typecode of the Sapling receiver.
        let truncated_after_sapling_typecode = [
            0x87, 0x7a, 0xdf, 0x79, 0x6b, 0xe3, 0xb3, 0x40, 0xef, 0xe4, 0x5d, 0xc2, 0x91, 0xa2,
            0x81, 0xfc, 0x7d, 0x76, 0xbb, 0xb0, 0x58, 0x98, 0x53, 0x59, 0xd3, 0x3f, 0xbc, 0x4b,
            0x86, 0x59, 0x66, 0x62, 0x75, 0x92, 0xba, 0xcc, 0x31, 0x1e, 0x60, 0x02, 0x3b, 0xd8,
            0x4c, 0xdf, 0x36, 0xa1, 0xac, 0x82, 0x57, 0xed, 0x0c, 0x98, 0x49, 0x8f, 0x49, 0x7e,
            0xe6, 0x70, 0x36, 0x5b, 0x7b, 0x9e,
        ];
        assert_matches!(
            Address::parse_internal(Address::MAINNET_R0, &truncated_after_sapling_typecode[..]),
            Err(ParseError::InvalidEncoding(_))
        );
    }

    #[test]
    fn duplicate_typecode() {
        // Construct and serialize an invalid UA. This must be done using private
        // methods, as the public API does not permit construction of such invalid values.
        let ua = Address {
            revision: Revision::R0,
            receivers: vec![
                Item::Data(Receiver::Sapling([1; 43])),
                Item::Data(Receiver::Sapling([2; 43])),
            ],
        };
        let encoded = ua.to_jumbled_bytes(Address::MAINNET_R0);
        assert_eq!(
            Address::parse_internal(Address::MAINNET_R0, &encoded[..]),
            Err(ParseError::DuplicateTypecode(Typecode::SAPLING))
        );
    }

    #[test]
    fn p2pkh_and_p2sh() {
        // Construct and serialize an invalid UA. This must be done using private
        // methods, as the public API does not permit construction of such invalid values.
        let ua = Address {
            revision: Revision::R0,
            receivers: vec![
                Item::Data(Receiver::P2pkh([0; 20])),
                Item::Data(Receiver::P2sh([0; 20])),
            ],
        };
        let encoded = ua.to_jumbled_bytes(Address::MAINNET_R0);
        // ensure that decoding catches the error
        assert_eq!(
            Address::parse_internal(Address::MAINNET_R0, &encoded[..]),
            Err(ParseError::BothP2phkAndP2sh)
        );
    }

    #[test]
    fn addresses_out_of_order() {
        // Construct and serialize an invalid UA. This must be done using private
        // methods, as the public API does not permit construction of such invalid values.
        let ua = Address {
            revision: Revision::R0,
            receivers: vec![
                Item::Data(Receiver::Sapling([0; 43])),
                Item::Data(Receiver::P2pkh([0; 20])),
            ],
        };
        let encoded = ua.to_jumbled_bytes(Address::MAINNET_R0);
        // ensure that decoding catches the error
        assert_eq!(
            Address::parse_internal(Address::MAINNET_R0, &encoded[..]),
            Err(ParseError::InvalidTypecodeOrder)
        );
    }

    #[test]
    fn only_transparent() {
        // Encoding of `Address(vec![Receiver::P2pkh([0; 20])])`.
        let encoded = [
            0xf0, 0x9e, 0x9d, 0x6e, 0xf5, 0xa6, 0xac, 0x16, 0x50, 0xf0, 0xdb, 0xe1, 0x2c, 0xa5,
            0x36, 0x22, 0xa2, 0x04, 0x89, 0x86, 0xe9, 0x6a, 0x9b, 0xf3, 0xff, 0x6d, 0x2f, 0xe6,
            0xea, 0xdb, 0xc5, 0x20, 0x62, 0xf9, 0x6f, 0xa9, 0x86, 0xcc,
        ];

        // We can't actually exercise this error, because at present the only transparent
        // receivers we can use are P2PKH and P2SH (which cannot be used together), and
        // with only one of them we don't have sufficient data for F4Jumble (so we hit a
        // different error).
        assert_matches!(
            Address::parse_internal(Address::MAINNET_R0, &encoded[..]),
            Err(ParseError::InvalidEncoding(_))
        );
    }

    #[test]
    fn receivers_are_sorted() {
        // Construct a UA with receivers in an unsorted order.
        let ua = Address {
            revision: Revision::R0,
            receivers: vec![
                Item::Data(Receiver::P2pkh([0; 20])),
                Item::Data(Receiver::Orchard([0; 43])),
                Item::Data(Receiver::Unknown {
                    typecode: 0xff,
                    data: vec![],
                }),
                Item::Data(Receiver::Sapling([0; 43])),
            ],
        };

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
