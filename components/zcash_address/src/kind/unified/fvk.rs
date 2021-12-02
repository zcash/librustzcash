use std::cmp;
use std::convert::{TryFrom, TryInto};

use super::{
    private::{SealedContainer, SealedItem},
    Container, Encoding, ParseError, Typecode,
};

/// The set of known FVKs for Unified FVKs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Fvk {
    /// The raw encoding of an Orchard Full Viewing Key.
    ///
    /// `(ak, nk, rivk)` each 32 bytes.
    Orchard([u8; 96]),

    /// Data contained within the Sapling component of a Unified Full Viewing Key
    ///
    /// `(ak, nk, ovk)` each 32 bytes.
    Sapling([u8; 96]),

    /// The extended public key for the BIP 44 account corresponding to the transparent
    /// address subtree from which transparent addresses are derived.
    ///
    /// Transparent addresses don't have "viewing keys" - the addresses themselves serve
    /// that purpose. However, we want the ability to derive diversified Unified Addresses
    /// from Unified Viewing Keys, and to not break the unlinkability property when they
    /// include transparent receivers. To achieve this, we treat the last hardened node in
    /// the BIP 44 derivation path as the "transparent viewing key"; all addresses derived
    /// from this node use non-hardened derivation, and can thus be derived just from this
    /// extended public key.
    P2pkh([u8; 78]),

    Unknown {
        typecode: u32,
        data: Vec<u8>,
    },
}

impl cmp::Ord for Fvk {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.typecode().cmp(&other.typecode()) {
            cmp::Ordering::Equal => self.data().cmp(other.data()),
            res => res,
        }
    }
}

impl cmp::PartialOrd for Fvk {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<(u32, &[u8])> for Fvk {
    type Error = ParseError;

    fn try_from((typecode, data): (u32, &[u8])) -> Result<Self, Self::Error> {
        let data = data.to_vec();
        match typecode.try_into()? {
            Typecode::P2pkh => data.try_into().map(Fvk::P2pkh),
            Typecode::P2sh => Err(data),
            Typecode::Sapling => data.try_into().map(Fvk::Sapling),
            Typecode::Orchard => data.try_into().map(Fvk::Orchard),
            Typecode::Unknown(_) => Ok(Fvk::Unknown { typecode, data }),
        }
        .map_err(|e| {
            ParseError::InvalidEncoding(format!("Invalid fvk for typecode {}: {:?}", typecode, e))
        })
    }
}

impl SealedItem for Fvk {
    fn typecode(&self) -> Typecode {
        match self {
            Fvk::P2pkh(_) => Typecode::P2pkh,
            Fvk::Sapling(_) => Typecode::Sapling,
            Fvk::Orchard(_) => Typecode::Orchard,
            Fvk::Unknown { typecode, .. } => Typecode::Unknown(*typecode),
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            Fvk::P2pkh(data) => data,
            Fvk::Sapling(data) => data,
            Fvk::Orchard(data) => data,
            Fvk::Unknown { data, .. } => data,
        }
    }
}

/// A Unified Full Viewing Key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ufvk(pub(crate) Vec<Fvk>);

impl Container for Ufvk {
    type Item = Fvk;

    /// Returns the FVKs contained within this UFVK, in the order they were
    /// parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Ufvk::receivers`.
    fn items_as_parsed(&self) -> &[Fvk] {
        &self.0
    }
}

impl Encoding for Ufvk {}

impl SealedContainer for Ufvk {
    /// The HRP for a Bech32m-encoded mainnet Unified FVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const MAINNET: &'static str = "uview";

    /// The HRP for a Bech32m-encoded testnet Unified FVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const TESTNET: &'static str = "uviewtest";

    /// The HRP for a Bech32m-encoded regtest Unified FVK.
    const REGTEST: &'static str = "uviewregtest";

    fn from_inner(fvks: Vec<Self::Item>) -> Self {
        Self(fvks)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use proptest::{array::uniform32, prelude::*, sample::select};

    use super::{Fvk, ParseError, Typecode, Ufvk};
    use crate::{
        kind::unified::{private::SealedContainer, Container, Encoding},
        Network,
    };

    prop_compose! {
        fn uniform96()(a in uniform32(0u8..), b in uniform32(0u8..), c in uniform32(0u8..)) -> [u8; 96] {
            let mut fvk = [0; 96];
            fvk[..32].copy_from_slice(&a);
            fvk[32..64].copy_from_slice(&b);
            fvk[64..].copy_from_slice(&c);
            fvk
        }
    }

    prop_compose! {
        fn uniform78()(a in uniform96()) -> [u8; 78] {
            let mut c = [0; 78];
            c[..78].copy_from_slice(&a[..78]);
            c
        }
    }

    fn arb_shielded_fvk() -> BoxedStrategy<Vec<Fvk>> {
        prop_oneof![
            vec![uniform96().prop_map(Fvk::Sapling)],
            vec![uniform96().prop_map(Fvk::Orchard)],
            vec![
                uniform96().prop_map(Fvk::Orchard as fn([u8; 96]) -> Fvk),
                uniform96().prop_map(Fvk::Sapling)
            ],
        ]
        .boxed()
    }

    fn arb_transparent_fvk() -> BoxedStrategy<Fvk> {
        uniform78().prop_map(Fvk::P2pkh).boxed()
    }

    prop_compose! {
        fn arb_unified_fvk()(
            shielded in arb_shielded_fvk(),
            transparent in prop::option::of(arb_transparent_fvk()),
        ) -> Ufvk {
            Ufvk(shielded.into_iter().chain(transparent).collect())
        }
    }

    proptest! {
        #[test]
        fn ufvk_roundtrip(
            network in select(vec![Network::Main, Network::Test, Network::Regtest]),
            ufvk in arb_unified_fvk(),
        ) {
            let encoded = ufvk.encode(&network);
            let decoded = Ufvk::decode(&encoded);
            prop_assert_eq!(decoded, Ok((network, ufvk)));
        }
    }

    #[test]
    fn padding() {
        // The test cases below use `Ufvk(vec![Fvk::Orchard([1; 96])])` as base.

        // Invalid padding ([0xff; 16] instead of [b'u', 0x00, 0x00, 0x00...])
        let invalid_padding = vec![
            0x6b, 0x32, 0x44, 0xf1, 0xb, 0x67, 0xe9, 0x8f, 0x6, 0x57, 0xe3, 0x5, 0x17, 0xa0, 0x7,
            0x5c, 0xb0, 0xc9, 0x23, 0xcc, 0xb7, 0x54, 0xac, 0x55, 0x6a, 0x65, 0x99, 0x95, 0x32,
            0x97, 0xd5, 0x34, 0xa7, 0xc8, 0x6f, 0xc, 0xd7, 0x3b, 0xe0, 0x88, 0x19, 0xf3, 0x3e,
            0x26, 0x19, 0xd6, 0x5f, 0x9a, 0x62, 0xc9, 0x6f, 0xad, 0x3b, 0xe5, 0xdd, 0xf1, 0xff,
            0x5b, 0x4a, 0x13, 0x61, 0xc0, 0xd5, 0xa5, 0x87, 0xc5, 0x69, 0x48, 0xdb, 0x7e, 0xc6,
            0x4e, 0xb0, 0x55, 0x41, 0x3f, 0xc0, 0x53, 0xbb, 0x79, 0x8b, 0x24, 0xa0, 0xfa, 0xd1,
            0x6e, 0xea, 0x9, 0xea, 0xb3, 0xaf, 0x0, 0x7d, 0x86, 0x47, 0xdb, 0x8b, 0x38, 0xdd, 0x7b,
            0xdf, 0x63, 0xe7, 0xef, 0x65, 0x6b, 0x18, 0x23, 0xf7, 0x3e, 0x35, 0x7c, 0xf3, 0xc4,
        ];
        assert_eq!(
            Ufvk::parse_items(&Ufvk::MAINNET, &invalid_padding[..]),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );

        // Short padding (padded to 15 bytes instead of 16)
        let truncated_padding = vec![
            0xdf, 0xea, 0x84, 0x55, 0xc3, 0x4a, 0x7c, 0x6e, 0x9f, 0x83, 0x3, 0x21, 0x14, 0xb0,
            0xcf, 0xb0, 0x60, 0x84, 0x75, 0x3a, 0xdc, 0xb9, 0x93, 0x16, 0xc0, 0x8f, 0x28, 0x5f,
            0x61, 0x5e, 0xf0, 0x8e, 0x44, 0xae, 0xa6, 0x74, 0xc5, 0x64, 0xad, 0xfa, 0xdc, 0x7d,
            0x64, 0x2a, 0x9, 0x47, 0x16, 0xf6, 0x5d, 0x8e, 0x46, 0xc4, 0xf0, 0x54, 0xfa, 0x5, 0x28,
            0x1e, 0x3d, 0x7d, 0x37, 0xa5, 0x9f, 0x8b, 0x62, 0x78, 0xf6, 0x50, 0x18, 0x63, 0xe4,
            0x51, 0x14, 0xae, 0x89, 0x41, 0x86, 0xd4, 0x9f, 0x10, 0x4b, 0x66, 0x2b, 0xf9, 0x46,
            0x9c, 0xeb, 0xe8, 0x90, 0x8, 0xad, 0xd9, 0x6c, 0x6a, 0xf1, 0xed, 0xeb, 0x72, 0x44,
            0x43, 0x8e, 0xc0, 0x3e, 0x9f, 0xf4, 0xf1, 0x80, 0x32, 0xcf, 0x2f, 0x7e, 0x7f, 0x91,
        ];
        assert_eq!(
            Ufvk::parse_items(&Ufvk::MAINNET, &truncated_padding[..]),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );
    }

    #[test]
    fn truncated() {
        // The test cases below start from an encoding of
        //     `Ufvk(vec![Fvk::Orchard([1; 96]), Fvk::Sapling([2; 96])])`
        // with the fvk data truncated, but valid padding.

        // - Missing the last data byte of the Sapling fvk.
        let truncated_sapling_data = vec![
            0x43, 0xbf, 0x17, 0xa2, 0xb7, 0x85, 0xe7, 0x8e, 0xa4, 0x6d, 0x36, 0xa5, 0xf1, 0x1d,
            0x74, 0xd1, 0x40, 0x6e, 0xed, 0xbd, 0x6b, 0x51, 0x6a, 0x36, 0x9c, 0xb3, 0x28, 0xd,
            0x90, 0xa1, 0x1e, 0x3a, 0x67, 0xa2, 0x15, 0xc5, 0xfb, 0x82, 0x96, 0xf4, 0x35, 0x57,
            0x71, 0x5d, 0xbb, 0xac, 0x30, 0x1d, 0x1, 0x6d, 0xdd, 0x2e, 0xf, 0x8, 0x4b, 0xcf, 0x5,
            0xfe, 0x86, 0xd7, 0xa0, 0x9d, 0x94, 0x9f, 0x16, 0x5e, 0xa0, 0x3, 0x58, 0x81, 0x71,
            0x40, 0xe4, 0xb8, 0xfc, 0x64, 0x75, 0x80, 0x46, 0x4f, 0x51, 0x2d, 0xb2, 0x51, 0xf,
            0x22, 0x49, 0x53, 0x95, 0xbd, 0x7b, 0x66, 0xd9, 0x17, 0xda, 0x15, 0x62, 0xe0, 0xc6,
            0xf8, 0x5c, 0xdf, 0x75, 0x6d, 0x7, 0xb, 0xf7, 0xab, 0xfc, 0x20, 0x61, 0xd0, 0xf4, 0x79,
            0xfa, 0x4, 0xd3, 0xac, 0x8b, 0xf, 0x3c, 0x30, 0x23, 0x32, 0x37, 0x51, 0xc5, 0xfc, 0x66,
            0x7e, 0xe1, 0x9c, 0xa8, 0xec, 0x52, 0x57, 0x7e, 0xc0, 0x31, 0x83, 0x1c, 0x31, 0x5,
            0x1b, 0xc3, 0x70, 0xd3, 0x44, 0x74, 0xd2, 0x8a, 0xda, 0x32, 0x4, 0x93, 0xd2, 0xbf,
            0xb4, 0xbb, 0xa, 0x9e, 0x8c, 0xe9, 0x8f, 0xe7, 0x8a, 0x95, 0xc8, 0x21, 0xfa, 0x12,
            0x41, 0x2e, 0x69, 0x54, 0xf0, 0x7a, 0x9e, 0x20, 0x94, 0xa3, 0xaa, 0xc3, 0x50, 0x43,
            0xc5, 0xe2, 0x32, 0x8b, 0x2e, 0x4f, 0xbb, 0xb4, 0xc0, 0x7f, 0x47, 0x35, 0xab, 0x89,
            0x8c, 0x7a, 0xbf, 0x7b, 0x9a, 0xdd, 0xee, 0x18, 0x2c, 0x2d, 0xc2, 0xfc,
        ];
        assert_matches!(
            Ufvk::parse_items(&Ufvk::MAINNET, &truncated_sapling_data[..]),
            Err(ParseError::InvalidEncoding(_))
        );

        // - Truncated after the typecode of the Sapling fvk.
        let truncated_after_sapling_typecode = vec![
            0xac, 0x26, 0x5b, 0x19, 0x8f, 0x88, 0xb0, 0x7, 0xb3, 0x0, 0x91, 0x19, 0x52, 0xe1, 0x73,
            0x48, 0xff, 0x66, 0x7a, 0xef, 0xcf, 0x57, 0x9c, 0x65, 0xe4, 0x6a, 0x7a, 0x1d, 0x19,
            0x75, 0x6b, 0x43, 0xdd, 0xcf, 0xb9, 0x9a, 0xf3, 0x7a, 0xf8, 0xb, 0x23, 0x96, 0x64,
            0x8c, 0x57, 0x56, 0x67, 0x9, 0x40, 0x35, 0xcb, 0xb1, 0xa4, 0x91, 0x4f, 0xdc, 0x39, 0x0,
            0x98, 0x56, 0xa8, 0xf7, 0x25, 0x1a, 0xc8, 0xbc, 0xd7, 0xb3, 0xb0, 0xfa, 0x78, 0x6,
            0xe8, 0x50, 0xfe, 0x92, 0xec, 0x5b, 0x1f, 0x74, 0xb9, 0xcf, 0x1f, 0x2e, 0x3b, 0x41,
            0x54, 0xd1, 0x9e, 0xec, 0x8b, 0xef, 0x35, 0xb8, 0x44, 0xdd, 0xab, 0x9a, 0x8d,
        ];
        assert_matches!(
            Ufvk::parse_items(&Ufvk::MAINNET, &truncated_after_sapling_typecode[..]),
            Err(ParseError::InvalidEncoding(_))
        );
    }

    #[test]
    fn duplicate_typecode() {
        // Construct and serialize an invalid Ufvk. This must be done using private
        // methods, as the public API does not permit construction of such invalid values.
        let ufvk = Ufvk(vec![Fvk::Sapling([1; 96]), Fvk::Sapling([2; 96])]);
        let encoded = ufvk.to_bytes(&Ufvk::MAINNET);
        assert_eq!(
            Ufvk::parse_items(&Ufvk::MAINNET, &encoded[..]).and_then(Ufvk::try_from_items),
            Err(ParseError::DuplicateTypecode(Typecode::Sapling))
        );
    }

    #[test]
    fn only_transparent() {
        // Raw encoding of `Ufvk(vec![Fvk::P2pkh([0; 78])])`.
        let encoded = vec![
            0xce, 0x3b, 0x36, 0xd9, 0x15, 0xf4, 0xc0, 0x78, 0x86, 0xf8, 0x21, 0xb6, 0x9a, 0xef,
            0x40, 0x6d, 0xe6, 0x4d, 0xbd, 0x17, 0x8c, 0x7a, 0xa5, 0x4b, 0xd7, 0x0, 0x8d, 0x64, 0x2,
            0x1a, 0x8, 0xd0, 0xbb, 0xcd, 0x65, 0xe2, 0x16, 0xba, 0x63, 0x7a, 0x3f, 0xf5, 0x7b,
            0xe2, 0xff, 0x80, 0x5d, 0x42, 0xf7, 0x1, 0x8b, 0x1c, 0xd8, 0x31, 0x3, 0x36, 0xe9, 0x30,
            0x9b, 0x46, 0xfd, 0x47, 0x9c, 0xce, 0x35, 0xdf, 0xb6, 0x24, 0xdc, 0x65, 0x25, 0x5b,
            0xc4, 0xc5, 0x22, 0xe9, 0x4, 0x24, 0xe9, 0x8, 0x71, 0x27, 0x8, 0xc3, 0xa5, 0xff, 0x84,
            0xf9, 0xfb, 0xf4, 0xa2, 0x8c, 0x27, 0xcc, 0x78, 0xcf,
        ];

        assert_eq!(
            Ufvk::parse_items(&Ufvk::MAINNET, &encoded[..]).and_then(Ufvk::try_from_items),
            Err(ParseError::OnlyTransparent)
        );
    }

    #[test]
    fn fvks_are_sorted() {
        // Construct a UFVK with fvks in an unsorted order.
        let ufvk = Ufvk(vec![
            Fvk::P2pkh([0; 78]),
            Fvk::Orchard([0; 96]),
            Fvk::Unknown {
                typecode: 0xff,
                data: vec![],
            },
            Fvk::Sapling([0; 96]),
        ]);

        // `Ufvk::items` sorts the fvks in priority order.
        assert_eq!(
            ufvk.items(),
            vec![
                Fvk::Orchard([0; 96]),
                Fvk::Sapling([0; 96]),
                Fvk::P2pkh([0; 78]),
                Fvk::Unknown {
                    typecode: 0xff,
                    data: vec![],
                },
            ]
        )
    }
}
