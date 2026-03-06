use alloc::vec::Vec;
use core::{
    convert::{TryFrom, TryInto},
    fmt,
};
use zcash_protocol::address::Revision;
use zcash_protocol::constants;

use super::{
    private::{SealedContainer, SealedItem},
    Container, DataTypecode, Encoding, ParseError, Typecode, Uitem,
};

/// The set of known FVKs for Unified FVKs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Fvk {
    /// The raw encoding of an Orchard Full Viewing Key.
    ///
    /// `(ak, nk, rivk)` each 32 bytes.
    Orchard([u8; 96]),

    /// Data contained within the Sapling component of a Unified Full Viewing Key
    ///
    /// `(ak, nk, ovk, dk)` each 32 bytes.
    Sapling([u8; 128]),

    /// A pruned version of the extended public key for the BIP 44 account corresponding to the
    /// transparent address subtree from which transparent addresses are derived. This
    /// includes just the chain code (32 bytes) and the compressed public key (33 bytes), and excludes
    /// the depth of in the derivation tree, the parent key fingerprint, and the child key
    /// number (which would reveal the wallet account number for which this UFVK was generated).
    ///
    /// Transparent addresses don't have "viewing keys" - the addresses themselves serve
    /// that purpose. However, we want the ability to derive diversified Unified Addresses
    /// from Unified Viewing Keys, and to not break the unlinkability property when they
    /// include transparent receivers. To achieve this, we treat the last hardened node in
    /// the BIP 44 derivation path as the "transparent viewing key"; all addresses derived
    /// from this node use non-hardened derivation, and can thus be derived just from this
    /// pruned extended public key.
    P2pkh([u8; 65]),

    Unknown {
        typecode: u32,
        data: Vec<u8>,
    },
}

impl fmt::Debug for Fvk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fvk::Orchard(_) => f.debug_tuple("Fvk::Orchard").field(&"...").finish(),
            Fvk::Sapling(_) => f.debug_tuple("Fvk::Sapling").field(&"...").finish(),
            Fvk::P2pkh(_) => f.debug_tuple("Fvk::P2pkh").field(&"...").finish(),
            Fvk::Unknown { typecode, .. } => f
                .debug_struct("Fvk::Unknown")
                .field("typecode", typecode)
                .field("data", &"...")
                .finish(),
        }
    }
}

impl TryFrom<(u32, &[u8])> for Fvk {
    type Error = ParseError;

    fn try_from((typecode, data): (u32, &[u8])) -> Result<Self, Self::Error> {
        let data = data.to_vec();
        match typecode.try_into()? {
            Typecode::Data(DataTypecode::P2pkh) => data.try_into().map(Fvk::P2pkh),
            Typecode::Data(DataTypecode::P2sh) => Err(data),
            Typecode::Data(DataTypecode::Sapling) => data.try_into().map(Fvk::Sapling),
            Typecode::Data(DataTypecode::Orchard) => data.try_into().map(Fvk::Orchard),
            Typecode::Data(DataTypecode::Unknown(_)) => Ok(Fvk::Unknown { typecode, data }),
            Typecode::Metadata(_) => {
                return Err(ParseError::InvalidEncoding(format!(
                    "Unexpected metadata typecode {} in data item position",
                    typecode
                )))
            }
        }
        .map_err(|e| {
            ParseError::InvalidEncoding(format!("Invalid fvk for typecode {}: {:?}", typecode, e))
        })
    }
}

impl SealedItem for Fvk {
    fn typecode(&self) -> Typecode {
        match self {
            Fvk::P2pkh(_) => Typecode::Data(DataTypecode::P2pkh),
            Fvk::Sapling(_) => Typecode::Data(DataTypecode::Sapling),
            Fvk::Orchard(_) => Typecode::Data(DataTypecode::Orchard),
            Fvk::Unknown { typecode, .. } => Typecode::Data(DataTypecode::Unknown(*typecode)),
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
///
/// # Examples
///
/// ```
/// use zcash_address::unified::{self, Container, Encoding, Uitem};
///
/// # #[cfg(not(feature = "std"))]
/// # fn main() {}
/// # #[cfg(feature = "std")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let ufvk_from_user = || "uview1cgrqnry478ckvpr0f580t6fsahp0a5mj2e9xl7hv2d2jd4ldzy449mwwk2l9yeuts85wjls6hjtghdsy5vhhvmjdw3jxl3cxhrg3vs296a3czazrycrr5cywjhwc5c3ztfyjdhmz0exvzzeyejamyp0cr9z8f9wj0953fzht0m4lenk94t70ruwgjxag2tvp63wn9ftzhtkh20gyre3w5s24f6wlgqxnjh40gd2lxe75sf3z8h5y2x0atpxcyf9t3em4h0evvsftluruqne6w4sm066sw0qe5y8qg423grple5fftxrqyy7xmqmatv7nzd7tcjadu8f7mqz4l83jsyxy4t8pkayytyk7nrp467ds85knekdkvnd7hqkfer8mnqd7pv";
/// let example_ufvk: &str = ufvk_from_user();
///
/// let (network, _revision, ufvk) = unified::Ufvk::decode(example_ufvk)?;
///
/// // We can obtain the pool-specific Full Viewing Keys for the UFVK in preference
/// // order (the order in which wallets should prefer to use their corresponding
/// // address receivers):
/// let fvks: Vec<unified::Fvk> = ufvk.items();
///
/// // And we can create the UFVK from a list of FVKs:
/// let new_ufvk = unified::Ufvk::try_from_items(
///     unified::Revision::R0,
///     fvks.into_iter().map(Uitem::Data).collect(),
/// )?;
/// assert_eq!(new_ufvk, ufvk);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ufvk {
    pub(crate) revision: Revision,
    pub(crate) items: Vec<Uitem<Fvk>>,
}

impl Container for Ufvk {
    type Item = Fvk;

    fn revision(&self) -> Revision {
        self.revision
    }

    fn items_as_parsed(&self) -> &[Uitem<Fvk>] {
        &self.items
    }
}

impl Encoding for Ufvk {}

impl SealedContainer for Ufvk {
    const MAINNET: &'static str = constants::mainnet::HRP_UNIFIED_FVK;
    const TESTNET: &'static str = constants::testnet::HRP_UNIFIED_FVK;
    const REGTEST: &'static str = constants::regtest::HRP_UNIFIED_FVK;

    const MAINNET_R2: &'static str = constants::mainnet::HRP_UNIFIED_FVK_R2;
    const TESTNET_R2: &'static str = constants::testnet::HRP_UNIFIED_FVK_R2;
    const REGTEST_R2: &'static str = constants::regtest::HRP_UNIFIED_FVK_R2;

    const MAINNET_R2_TI: &'static str = constants::mainnet::HRP_UNIFIED_FVK_R2;
    const TESTNET_R2_TI: &'static str = constants::testnet::HRP_UNIFIED_FVK_R2;
    const REGTEST_R2_TI: &'static str = constants::regtest::HRP_UNIFIED_FVK_R2;

    const IS_ADDRESS: bool = false;

    fn from_inner(revision: Revision, items: Vec<Uitem<Fvk>>) -> Self {
        Self { revision, items }
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::vec::Vec;

    use assert_matches::assert_matches;

    use proptest::{array::uniform1, array::uniform32, prelude::*, sample::select};

    use super::{Fvk, ParseError, Typecode, Ufvk};
    use crate::kind::unified::{
        private::{SealedContainer, SealedItem},
        Container, DataTypecode, Encoding, MetadataItem, Revision, Uitem,
    };
    use zcash_protocol::consensus::NetworkType;

    prop_compose! {
        fn uniform128()(a in uniform96(), b in uniform32(0u8..)) -> [u8; 128] {
            let mut fvk = [0; 128];
            fvk[..96].copy_from_slice(&a);
            fvk[96..].copy_from_slice(&b);
            fvk
        }
    }

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
        fn uniform65()(a in uniform32(0u8..), b in uniform32(0u8..), c in uniform1(0u8..)) -> [u8; 65] {
            let mut fvk = [0; 65];
            fvk[..32].copy_from_slice(&a);
            fvk[32..64].copy_from_slice(&b);
            fvk[64..].copy_from_slice(&c);
            fvk
        }
    }

    pub fn arb_orchard_fvk() -> impl Strategy<Value = Fvk> {
        uniform96().prop_map(Fvk::Orchard)
    }

    pub fn arb_sapling_fvk() -> impl Strategy<Value = Fvk> {
        uniform128().prop_map(Fvk::Sapling)
    }

    fn arb_shielded_fvk() -> impl Strategy<Value = Vec<Fvk>> {
        prop_oneof![
            vec![arb_sapling_fvk().boxed()],
            vec![arb_orchard_fvk().boxed()],
            vec![arb_sapling_fvk().boxed(), arb_orchard_fvk().boxed()],
        ]
    }

    fn arb_transparent_fvk() -> BoxedStrategy<Fvk> {
        uniform65().prop_map(Fvk::P2pkh).boxed()
    }

    prop_compose! {
        fn arb_unified_fvk()(
            shielded in arb_shielded_fvk(),
            transparent in prop::option::of(arb_transparent_fvk()),
        ) -> Ufvk {
            let mut items: Vec<Uitem<Fvk>> = transparent
                .into_iter()
                .chain(shielded)
                .map(Uitem::Data)
                .collect();
            items.sort_unstable_by(|a, b| {
                match (a, b) {
                    (Uitem::Data(a), Uitem::Data(b)) => Fvk::encoding_order(a, b),
                    _ => core::cmp::Ordering::Equal,
                }
            });
            Ufvk {
                revision: Revision::R0,
                items,
            }
        }
    }

    fn arb_metadata_items() -> impl Strategy<Value = Vec<Uitem<Fvk>>> {
        (
            prop::option::of(
                any::<u32>().prop_map(|h| Uitem::Metadata(MetadataItem::ExpiryHeight(h))),
            ),
            prop::option::of(
                any::<u64>().prop_map(|t| Uitem::Metadata(MetadataItem::ExpiryTime(t))),
            ),
        )
            .prop_map(|(h, t)| h.into_iter().chain(t).collect())
    }

    prop_compose! {
        fn arb_r2_unified_fvk()(
            shielded in arb_shielded_fvk(),
            transparent in prop::option::of(arb_transparent_fvk()),
            metadata in arb_metadata_items(),
        ) -> Ufvk {
            let mut items: Vec<Uitem<Fvk>> = transparent
                .into_iter()
                .chain(shielded)
                .map(Uitem::Data)
                .chain(metadata)
                .collect();
            items.sort_unstable_by(|a, b| {
                let tc_a = match a {
                    Uitem::Data(d) => u32::from(d.typecode()),
                    Uitem::Metadata(m) => m.combined_typecode().typecode_value(),
                };
                let tc_b = match b {
                    Uitem::Data(d) => u32::from(d.typecode()),
                    Uitem::Metadata(m) => m.combined_typecode().typecode_value(),
                };
                tc_a.cmp(&tc_b)
            });
            Ufvk {
                revision: Revision::R2,
                items,
            }
        }
    }

    // R2 allows transparent-only UFVKs.
    prop_compose! {
        fn arb_r2_transparent_only_fvk()(
            transparent in arb_transparent_fvk(),
            metadata in arb_metadata_items(),
        ) -> Ufvk {
            let mut items: Vec<Uitem<Fvk>> = core::iter::once(Uitem::Data(transparent))
                .chain(metadata)
                .collect();
            items.sort_unstable_by(|a, b| {
                let tc_a = match a {
                    Uitem::Data(d) => u32::from(d.typecode()),
                    Uitem::Metadata(m) => m.combined_typecode().typecode_value(),
                };
                let tc_b = match b {
                    Uitem::Data(d) => u32::from(d.typecode()),
                    Uitem::Metadata(m) => m.combined_typecode().typecode_value(),
                };
                tc_a.cmp(&tc_b)
            });
            Ufvk {
                revision: Revision::R2,
                items,
            }
        }
    }

    proptest! {
        #[test]
        fn ufvk_roundtrip(
            network in select(vec![NetworkType::Main, NetworkType::Test, NetworkType::Regtest]),
            ufvk in arb_unified_fvk(),
        ) {
            let encoded = ufvk.encode(&network);
            let decoded = Ufvk::decode(&encoded);
            let decoded = decoded.map(|(net, _rev, ufvk)| (net, ufvk));
            prop_assert_eq!(decoded, Ok((network, ufvk)));
        }

        #[test]
        fn r2_ufvk_roundtrip(
            network in select(vec![NetworkType::Main, NetworkType::Test, NetworkType::Regtest]),
            ufvk in arb_r2_unified_fvk(),
        ) {
            let encoded = ufvk.encode(&network);
            let decoded = Ufvk::decode(&encoded);
            let decoded = decoded.map(|(net, _rev, ufvk)| (net, ufvk));
            prop_assert_eq!(decoded, Ok((network, ufvk)));
        }

        #[test]
        fn r2_transparent_only_ufvk_roundtrip(
            network in select(vec![NetworkType::Main, NetworkType::Test, NetworkType::Regtest]),
            ufvk in arb_r2_transparent_only_fvk(),
        ) {
            let encoded = ufvk.encode(&network);
            let decoded = Ufvk::decode(&encoded);
            let decoded = decoded.map(|(net, _rev, ufvk)| (net, ufvk));
            prop_assert_eq!(decoded, Ok((network, ufvk)));
        }
    }

    #[test]
    fn padding() {
        // The test cases below use `Ufvk { revision: R0, items: vec![Uitem::Data(Fvk::Orchard([1; 96]))] }` as base.

        // Invalid padding ([0xff; 16] instead of [b'u', 0x00, 0x00, 0x00...])
        let invalid_padding = [
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
            Ufvk::parse_internal(Ufvk::MAINNET, &invalid_padding[..], Revision::R0),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );

        // Short padding (padded to 15 bytes instead of 16)
        let truncated_padding = [
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
            Ufvk::parse_internal(Ufvk::MAINNET, &truncated_padding[..], Revision::R0),
            Err(ParseError::InvalidEncoding(
                "Invalid padding bytes".to_owned()
            ))
        );
    }

    #[test]
    fn truncated() {
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
            Ufvk::parse_internal(Ufvk::MAINNET, &truncated_sapling_data[..], Revision::R0),
            Err(ParseError::InvalidEncoding(_))
        );

        // - Truncated after the typecode of the Sapling fvk.
        let truncated_after_sapling_typecode = [
            0xac, 0x26, 0x5b, 0x19, 0x8f, 0x88, 0xb0, 0x7, 0xb3, 0x0, 0x91, 0x19, 0x52, 0xe1, 0x73,
            0x48, 0xff, 0x66, 0x7a, 0xef, 0xcf, 0x57, 0x9c, 0x65, 0xe4, 0x6a, 0x7a, 0x1d, 0x19,
            0x75, 0x6b, 0x43, 0xdd, 0xcf, 0xb9, 0x9a, 0xf3, 0x7a, 0xf8, 0xb, 0x23, 0x96, 0x64,
            0x8c, 0x57, 0x56, 0x67, 0x9, 0x40, 0x35, 0xcb, 0xb1, 0xa4, 0x91, 0x4f, 0xdc, 0x39, 0x0,
            0x98, 0x56, 0xa8, 0xf7, 0x25, 0x1a, 0xc8, 0xbc, 0xd7, 0xb3, 0xb0, 0xfa, 0x78, 0x6,
            0xe8, 0x50, 0xfe, 0x92, 0xec, 0x5b, 0x1f, 0x74, 0xb9, 0xcf, 0x1f, 0x2e, 0x3b, 0x41,
            0x54, 0xd1, 0x9e, 0xec, 0x8b, 0xef, 0x35, 0xb8, 0x44, 0xdd, 0xab, 0x9a, 0x8d,
        ];
        assert_matches!(
            Ufvk::parse_internal(
                Ufvk::MAINNET,
                &truncated_after_sapling_typecode[..],
                Revision::R0
            ),
            Err(ParseError::InvalidEncoding(_))
        );
    }

    #[test]
    fn duplicate_typecode() {
        let ufvk = Ufvk {
            revision: Revision::R0,
            items: vec![
                Uitem::Data(Fvk::Sapling([1; 128])),
                Uitem::Data(Fvk::Sapling([2; 128])),
            ],
        };
        let encoded = ufvk.to_jumbled_bytes(Ufvk::MAINNET);
        assert_eq!(
            Ufvk::parse_internal(Ufvk::MAINNET, &encoded[..], Revision::R0),
            Err(ParseError::DuplicateTypecode(Typecode::Data(
                DataTypecode::Sapling
            )))
        );
    }

    #[test]
    fn only_transparent() {
        // Raw encoding of `Ufvk { items: vec![Uitem::Data(Fvk::P2pkh([0; 65]))] }`.
        let encoded = [
            0xc4, 0x70, 0xc8, 0x7a, 0xcc, 0xe6, 0x6b, 0x1a, 0x62, 0xc7, 0xcd, 0x5f, 0x76, 0xd8,
            0xcc, 0x9c, 0x50, 0xbd, 0xce, 0x85, 0x80, 0xd7, 0x78, 0x25, 0x3e, 0x47, 0x9, 0x57,
            0x7d, 0x6a, 0xdb, 0x10, 0xb4, 0x11, 0x80, 0x13, 0x4c, 0x83, 0x76, 0xb4, 0x6b, 0xbd,
            0xef, 0x83, 0x5c, 0xa7, 0x68, 0xe6, 0xba, 0x41, 0x12, 0xbd, 0x43, 0x24, 0xf5, 0xaa,
            0xa0, 0xf5, 0xf8, 0xe1, 0x59, 0xa0, 0x95, 0x85, 0x86, 0xf1, 0x9e, 0xcf, 0x8f, 0x94,
            0xf4, 0xf5, 0x16, 0xef, 0x5c, 0xe0, 0x26, 0xbc, 0x23, 0x73, 0x76, 0x3f, 0x4b,
        ];

        assert_eq!(
            Ufvk::parse_internal(Ufvk::MAINNET, &encoded[..], Revision::R0),
            Err(ParseError::OnlyTransparent)
        );
    }

    #[test]
    fn fvks_are_sorted() {
        let ufvk = Ufvk {
            revision: Revision::R0,
            items: vec![
                Uitem::Data(Fvk::P2pkh([0; 65])),
                Uitem::Data(Fvk::Orchard([0; 96])),
                Uitem::Data(Fvk::Unknown {
                    typecode: 0x50,
                    data: vec![],
                }),
                Uitem::Data(Fvk::Sapling([0; 128])),
            ],
        };

        assert_eq!(
            ufvk.items(),
            vec![
                Fvk::Orchard([0; 96]),
                Fvk::Sapling([0; 128]),
                Fvk::P2pkh([0; 65]),
                Fvk::Unknown {
                    typecode: 0x50,
                    data: vec![],
                },
            ]
        )
    }

    #[test]
    fn fvk_debug_redaction() {
        assert_eq!(
            format!("{:?}", Fvk::Orchard([0; 96])),
            "Fvk::Orchard(\"...\")"
        );
        assert_eq!(
            format!("{:?}", Fvk::Sapling([0; 128])),
            "Fvk::Sapling(\"...\")"
        );
        assert_eq!(format!("{:?}", Fvk::P2pkh([0; 65])), "Fvk::P2pkh(\"...\")");
        assert_eq!(
            format!(
                "{:?}",
                Fvk::Unknown {
                    typecode: 4242,
                    data: vec![1, 2, 3],
                }
            ),
            "Fvk::Unknown { typecode: 4242, data: \"...\" }"
        );
    }

    #[test]
    fn ufvk_debug_redaction() {
        let ufvk = Ufvk {
            revision: Revision::R0,
            items: vec![
                Uitem::Data(Fvk::P2pkh([0; 65])),
                Uitem::Data(Fvk::Unknown {
                    typecode: 7,
                    data: vec![9, 9, 9],
                }),
            ],
        };

        assert_eq!(
            format!("{:?}", ufvk),
            "Ufvk { revision: R0, items: [Data(Fvk::P2pkh(\"...\")), Data(Fvk::Unknown { typecode: 7, data: \"...\" })] }"
        );
    }

    #[test]
    fn r2_transparent_only_ufvk() {
        // R2 UVKs allow transparent-only.
        let items = vec![Uitem::Data(Fvk::P2pkh([1; 65]))];
        let ufvk = Ufvk::try_from_items(Revision::R2, items).unwrap();
        assert_eq!(ufvk.revision(), Revision::R2);

        // Round-trip.
        let encoded = ufvk.encode(&NetworkType::Main);
        assert!(encoded.starts_with("uvf"));
        let (net, rev, decoded) = Ufvk::decode(&encoded).unwrap();
        assert_eq!(net, NetworkType::Main);
        assert_eq!(rev, Revision::R2);
        assert_eq!(decoded, ufvk);
    }

    #[test]
    fn r2_ufvk_with_expiry() {
        let items = vec![
            Uitem::Data(Fvk::Orchard([2; 96])),
            Uitem::Metadata(MetadataItem::ExpiryHeight(500_000)),
            Uitem::Metadata(MetadataItem::ExpiryTime(1_700_000_000)),
        ];
        let ufvk = Ufvk::try_from_items(Revision::R2, items).unwrap();

        let encoded = ufvk.encode(&NetworkType::Test);
        let (net, rev, decoded) = Ufvk::decode(&encoded).unwrap();
        assert_eq!(net, NetworkType::Test);
        assert_eq!(rev, Revision::R2);
        assert_eq!(decoded, ufvk);

        let meta = decoded.metadata_items();
        assert_eq!(meta.len(), 2);
        assert_eq!(*meta[0], MetadataItem::ExpiryHeight(500_000));
        assert_eq!(*meta[1], MetadataItem::ExpiryTime(1_700_000_000));
    }
}
