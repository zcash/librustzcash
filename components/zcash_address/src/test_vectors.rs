/// Export test vectors for reuse by implementers of address parsing libraries.
#[cfg(feature = "test-dependencies")]
pub use crate::unified::address::test_vectors::TEST_VECTORS as UNIFIED;

#[cfg(test)]
use {
    crate::{
        unified::{
            self,
            address::{test_vectors::TEST_VECTORS, Receiver},
            Uitem,
        },
        ToAddress, ZcashAddress,
    },
    alloc::string::ToString,
    core::iter,
    zcash_protocol::{address::Revision, consensus::NetworkType},
};

#[test]
fn unified() {
    for tv in TEST_VECTORS {
        // Double-check test vectors match requirements:
        // - Only one of P2PKH and P2SH.
        assert!(tv.p2pkh_bytes.is_none() || tv.p2sh_bytes.is_none());
        // - At least one shielded receiver.
        assert!(tv.sapling_raw_addr.is_some() || tv.orchard_raw_addr.is_some());

        let unknown_tc = tv.unknown_typecode;
        let unknown_bytes = tv.unknown_bytes;
        let items = iter::empty()
            .chain(tv.p2pkh_bytes.map(|b| Uitem::Data(Receiver::P2pkh(b))))
            .chain(tv.p2sh_bytes.map(|b| Uitem::Data(Receiver::P2sh(b))))
            .chain(
                tv.sapling_raw_addr
                    .map(|b| Uitem::Data(Receiver::Sapling(b))),
            )
            .chain(
                tv.orchard_raw_addr
                    .map(|b| Uitem::Data(Receiver::Orchard(b))),
            )
            .chain(unknown_tc.and_then(|typecode| {
                unknown_bytes.map(move |data| {
                    Uitem::Data(Receiver::Unknown {
                        typecode,
                        data: data.to_vec(),
                    })
                })
            }))
            .collect();

        let expected_addr = ZcashAddress::from_unified(
            NetworkType::Main,
            unified::Address {
                revision: Revision::R0,
                items,
            },
        );

        // Test parsing
        let addr: ZcashAddress = tv.unified_addr.parse().unwrap();
        assert_eq!(addr, expected_addr);

        // Test serialization
        assert_eq!(expected_addr.to_string(), tv.unified_addr.to_string());
    }
}
