use std::cmp;
use std::convert::{TryFrom, TryInto};

use super::{
    private::{SealedContainer, SealedItem},
    Encoding, ParseError, Container, Typecode,
};

/// The set of known IVKs for Unified IVKs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ivk {
    /// The raw encoding of an Orchard Incoming Viewing Key.
    ///
    /// `(dk, ivk)` each 32 bytes.
    Orchard([u8; 64]),

    /// Data contained within the Sapling component of a Unified Incoming Viewing Key.
    ///
    /// In order to ensure that Unified Addresses can always be derived from UIVKs, we
    /// store more data here than was specified to be part of a Sapling IVK. Specifically,
    /// we store the same data here as we do for Orchard.
    ///
    /// `(dk, ivk)` each 32 bytes.
    Sapling([u8; 64]),

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

impl cmp::Ord for Ivk {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.typecode().cmp(&other.typecode()) {
            cmp::Ordering::Equal => self.data().cmp(other.data()),
            res => res,
        }
    }
}

impl cmp::PartialOrd for Ivk {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<(u32, &[u8])> for Ivk {
    type Error = ParseError;

    fn try_from((typecode, data): (u32, &[u8])) -> Result<Self, Self::Error> {
        let data = data.to_vec();
        match typecode.try_into()? {
            Typecode::P2pkh => data.try_into().map(Ivk::P2pkh),
            Typecode::P2sh => Err(data),
            Typecode::Sapling => data.try_into().map(Ivk::Sapling),
            Typecode::Orchard => data.try_into().map(Ivk::Orchard),
            Typecode::Unknown(_) => Ok(Ivk::Unknown { typecode, data }),
        }
        .map_err(|e| {
            ParseError::InvalidEncoding(format!("Invalid ivk for typecode {}: {:?}", typecode, e))
        })
    }
}

impl SealedItem for Ivk {
    fn typecode(&self) -> Typecode {
        match self {
            Ivk::P2pkh(_) => Typecode::P2pkh,
            Ivk::Sapling(_) => Typecode::Sapling,
            Ivk::Orchard(_) => Typecode::Orchard,
            Ivk::Unknown { typecode, .. } => Typecode::Unknown(*typecode),
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            Ivk::P2pkh(data) => data,
            Ivk::Sapling(data) => data,
            Ivk::Orchard(data) => data,
            Ivk::Unknown { data, .. } => data,
        }
    }
}

/// A Unified Incoming Viewing Key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Uivk(pub(crate) Vec<Ivk>);

impl Container for Uivk {
    type Item = Ivk;

    /// Returns the IVKs contained within this UIVK, in the order they were
    /// parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Uivk::items`.
    fn items_as_parsed(&self) -> &[Ivk] {
        &self.0
    }
}
impl Encoding for Uivk {}

impl SealedContainer for Uivk {
    /// The HRP for a Bech32m-encoded mainnet Unified IVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const MAINNET: &'static str = "uivk";

    /// The HRP for a Bech32m-encoded testnet Unified IVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const TESTNET: &'static str = "uivktest";

    /// The HRP for a Bech32m-encoded regtest Unified IVK.
    const REGTEST: &'static str = "uivkregtest";

    fn from_inner(ivks: Vec<Self::Item>) -> Self {
        Self(ivks)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use proptest::{
        array::{uniform14, uniform32},
        prelude::*,
    };

    use super::{Ivk, ParseError, Typecode, Uivk};
    use crate::kind::unified::{private::SealedContainer, Encoding, Container};

    prop_compose! {
        fn uniform64()(a in uniform32(0u8..), b in uniform32(0u8..)) -> [u8; 64] {
            let mut c = [0; 64];
            c[..32].copy_from_slice(&a);
            c[32..].copy_from_slice(&b);
            c
        }
    }

    prop_compose! {
        fn uniform78()(a in uniform14(0u8..), b in uniform64()) -> [u8; 78] {
            let mut c = [0; 78];
            c[..14].copy_from_slice(&a);
            c[14..].copy_from_slice(&b);
            c
        }
    }

    fn arb_shielded_ivk() -> BoxedStrategy<Vec<Ivk>> {
        prop_oneof![
            vec![uniform64().prop_map(Ivk::Sapling)],
            vec![uniform64().prop_map(Ivk::Orchard)],
            vec![
                uniform64().prop_map(Ivk::Orchard as fn([u8; 64]) -> Ivk),
                uniform64().prop_map(Ivk::Sapling)
            ],
        ]
        .boxed()
    }

    fn arb_transparent_ivk() -> BoxedStrategy<Ivk> {
        uniform78().prop_map(Ivk::P2pkh).boxed()
    }

    prop_compose! {
        fn arb_unified_ivk()(
            shielded in arb_shielded_ivk(),
            transparent in prop::option::of(arb_transparent_ivk()),
        ) -> Uivk {
            Uivk(shielded.into_iter().chain(transparent).collect())
        }
    }

    proptest! {
        #[test]
        fn uivk_roundtrip(
            hrp in prop_oneof![Uivk::MAINNET, Uivk::TESTNET, Uivk::REGTEST],
            uivk in arb_unified_ivk(),
        ) {
            let bytes = uivk.to_bytes(&hrp);
            let decoded = Uivk::try_from_bytes(hrp.as_str(), &bytes[..]);
            prop_assert_eq!(decoded, Ok(uivk));
        }
    }

    #[test]
    fn padding() {
        // The test cases below use `Uivk(vec![Ivk::Orchard([1; 64])])` as base.

        // Invalid padding ([0xff; 16] instead of [b'u', 0x00, 0x00, 0x00...])
        let invalid_padding = vec![
            0xba, 0xbc, 0xc0, 0x71, 0xcd, 0x3b, 0xfd, 0x9a, 0x32, 0x19, 0x7e, 0xeb, 0x8a, 0xa7,
            0x6e, 0xd4, 0xac, 0xcb, 0x59, 0xc2, 0x54, 0x26, 0xc6, 0xab, 0x71, 0xc7, 0xc3, 0x72,
            0xc, 0xa9, 0xad, 0xa4, 0xad, 0x8c, 0x9e, 0x35, 0x7b, 0x4c, 0x5d, 0xc7, 0x66, 0x12,
            0x8a, 0xc5, 0x42, 0x89, 0xc1, 0x77, 0x32, 0xdc, 0xe8, 0x4b, 0x51, 0x31, 0x30, 0x3,
            0x20, 0xe3, 0xb6, 0x8c, 0xbb, 0xab, 0xe8, 0x89, 0xf8, 0xed, 0xac, 0x6d, 0x8e, 0xb1,
            0x83, 0xe8, 0x92, 0x18, 0x28, 0x70, 0x1e, 0x81, 0x76, 0x56, 0xb6, 0x15,
        ];
        assert_eq!(
            Uivk::try_from_bytes(Uivk::MAINNET, &invalid_padding[..]),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );

        // Short padding (padded to 15 bytes instead of 16)
        let truncated_padding = vec![
            0x96, 0x73, 0x6a, 0x56, 0xbc, 0x44, 0x38, 0xe2, 0x47, 0x41, 0x1c, 0x70, 0xe4, 0x6,
            0x87, 0xbe, 0xb6, 0x90, 0xbd, 0xab, 0x1b, 0xd8, 0x27, 0x10, 0x0, 0x21, 0x30, 0x2, 0x77,
            0x87, 0x0, 0x25, 0x96, 0x94, 0x8f, 0x1e, 0x39, 0xd2, 0xd8, 0x65, 0xb4, 0x3c, 0x72,
            0xd8, 0xac, 0xec, 0x5b, 0xa2, 0x18, 0x62, 0x3f, 0xb, 0x88, 0xb4, 0x41, 0xf1, 0x55,
            0x39, 0x53, 0xbf, 0x2a, 0xd6, 0xcf, 0xdd, 0x46, 0xb7, 0xd8, 0xc1, 0x39, 0x34, 0x4d,
            0xf9, 0x65, 0x49, 0x14, 0xab, 0x7c, 0x55, 0x7b, 0x39, 0x47,
        ];
        assert_eq!(
            Uivk::try_from_bytes(Uivk::MAINNET, &truncated_padding[..]),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );
    }

    #[test]
    fn truncated() {
        // The test cases below start from an encoding of
        //     `Uivk(vec![Ivk::Orchard([1; 64]), Ivk::Sapling([2; 64])])`
        // with the ivk data truncated, but valid padding.

        // - Missing the last data byte of the Sapling ivk.
        let truncated_sapling_data = vec![
            0xce, 0xbc, 0xfe, 0xc5, 0xef, 0x2d, 0xe, 0x66, 0xc2, 0x8c, 0x34, 0xdc, 0x2e, 0x24,
            0xd2, 0xc7, 0x4b, 0xac, 0x36, 0xe0, 0x43, 0x72, 0xa7, 0x33, 0xa4, 0xe, 0xe0, 0x52,
            0x15, 0x64, 0x66, 0x92, 0x36, 0xa7, 0x60, 0x8e, 0x48, 0xe8, 0xb0, 0x30, 0x4d, 0xcb,
            0xd, 0x6f, 0x5, 0xd4, 0xb8, 0x72, 0x6a, 0xdc, 0x6c, 0x5c, 0xa, 0xf8, 0xdf, 0x95, 0x5a,
            0xba, 0xe1, 0xaa, 0x82, 0x51, 0xe2, 0x70, 0x8d, 0x13, 0x16, 0x88, 0x6a, 0xc0, 0xc1,
            0x99, 0x3c, 0xaf, 0x2c, 0x16, 0x54, 0x80, 0x7e, 0xb, 0xad, 0x31, 0x29, 0x26, 0xdd,
            0x7a, 0x55, 0x98, 0x1, 0x18, 0xb, 0x14, 0x94, 0xb2, 0x6b, 0x81, 0x67, 0x73, 0xa6, 0xd0,
            0x20, 0x94, 0x17, 0x3a, 0xf9, 0x98, 0x43, 0x58, 0xd6, 0x1, 0x10, 0x73, 0x32, 0xb4,
            0x99, 0xad, 0x6b, 0xfe, 0xc0, 0x97, 0xaf, 0xd2, 0xee, 0x8, 0xe5, 0x83, 0x6b, 0xb6,
            0xd9, 0x0, 0xef, 0x84, 0xff, 0xe8, 0x58, 0xba, 0xe8, 0x10, 0xea, 0x2d, 0xee, 0x72,
            0xf5, 0xd5, 0x8a, 0xb5, 0x1a,
        ];
        assert_matches!(
            Uivk::try_from_bytes(Uivk::MAINNET, &truncated_sapling_data[..]),
            Err(ParseError::InvalidEncoding(_))
        );

        // - Truncated after the typecode of the Sapling ivk.
        let truncated_after_sapling_typecode = vec![
            0xf7, 0x3, 0xd8, 0xbe, 0x6a, 0x27, 0xfa, 0xa1, 0xd3, 0x11, 0xea, 0x25, 0x94, 0xe2, 0xb,
            0xde, 0xed, 0x6a, 0xaa, 0x8, 0x46, 0x7d, 0xe4, 0xb1, 0xe, 0xf1, 0xde, 0x61, 0xd7, 0x95,
            0xf7, 0x82, 0x62, 0x32, 0x7a, 0x73, 0x8c, 0x55, 0x93, 0xa1, 0x63, 0x75, 0xe2, 0xca,
            0xcb, 0x73, 0xd5, 0xe5, 0xa3, 0xbd, 0xb3, 0xf2, 0x26, 0xfa, 0x1c, 0xa2, 0xad, 0xb6,
            0xd8, 0x21, 0x5e, 0x8, 0xa, 0x82, 0x95, 0x21, 0x74,
        ];
        assert_matches!(
            Uivk::try_from_bytes(Uivk::MAINNET, &truncated_after_sapling_typecode[..]),
            Err(ParseError::InvalidEncoding(_))
        );
    }

    #[test]
    fn duplicate_typecode() {
        // Construct and serialize an invalid UIVK.
        let uivk = Uivk(vec![Ivk::Sapling([1; 64]), Ivk::Sapling([2; 64])]);
        let encoded = uivk.to_bytes(Uivk::MAINNET);
        assert_eq!(
            Uivk::try_from_bytes(Uivk::MAINNET, &encoded[..]),
            Err(ParseError::DuplicateTypecode(Typecode::Sapling))
        );
    }

    #[test]
    fn only_transparent() {
        // Encoding of `Uivk(vec![Ivk::P2pkh([0; 78])])`.
        let encoded = vec![
            0xda, 0x41, 0xe7, 0x2b, 0xae, 0x1e, 0x95, 0x89, 0x0, 0xac, 0x28, 0x68, 0xb8, 0x50,
            0x71, 0x20, 0xa8, 0xfd, 0xdf, 0x29, 0x74, 0x3f, 0x34, 0x4f, 0xbc, 0x28, 0xe8, 0x29,
            0xe6, 0xee, 0x43, 0x74, 0xb, 0xea, 0x55, 0xd1, 0x58, 0xba, 0xb4, 0x71, 0x40, 0x6a,
            0x79, 0x91, 0xa4, 0x1e, 0x1e, 0x5f, 0xdf, 0x19, 0x42, 0xa3, 0xb0, 0x87, 0x8c, 0x3, 0x9,
            0xed, 0xc, 0x7a, 0x63, 0xa, 0x74, 0xbf, 0x30, 0xf5, 0xbb, 0xf2, 0x6f, 0xc, 0x89, 0xb2,
            0xf8, 0xda, 0xa1, 0xff, 0x84, 0xc2, 0xa, 0x89, 0x3, 0x8d, 0xf7, 0x0, 0x59, 0x63, 0xb1,
            0xfc, 0x13, 0x68, 0xc0, 0x32, 0x9a, 0x26, 0x10, 0x15,
        ];

        assert_eq!(
            Uivk::try_from_bytes(Uivk::MAINNET, &encoded[..]),
            Err(ParseError::OnlyTransparent)
        );
    }

    #[test]
    fn ivks_are_sorted() {
        // Construct a UIVK with ivks in an unsorted order.
        let uivk = Uivk(vec![
            Ivk::P2pkh([0; 78]),
            Ivk::Orchard([0; 64]),
            Ivk::Unknown {
                typecode: 0xff,
                data: vec![],
            },
            Ivk::Sapling([0; 64]),
        ]);

        // `Uivk::items` sorts the ivks in priority order.
        assert_eq!(
            uivk.items(),
            vec![
                Ivk::Orchard([0; 64]),
                Ivk::Sapling([0; 64]),
                Ivk::P2pkh([0; 78]),
                Ivk::Unknown {
                    typecode: 0xff,
                    data: vec![],
                },
            ]
        )
    }
}
