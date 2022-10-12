/// Export test vectors for reuse by implementers of address parsing libraries.
#[cfg(feature = "test-dependencies")]
pub use crate::unified::address::test_vectors::TEST_VECTORS as UNIFIED;

#[cfg(test)]
use {
    crate::{
        unified::{
            self,
            address::{test_vectors::TEST_VECTORS, Receiver},
        },
        Network, ToAddress, ZcashAddress,
    },
    std::iter,
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
        let receivers = iter::empty()
            .chain(tv.p2pkh_bytes.map(Receiver::P2pkh))
            .chain(tv.p2sh_bytes.map(Receiver::P2sh))
            .chain(tv.sapling_raw_addr.map(Receiver::Sapling))
            .chain(tv.orchard_raw_addr.map(Receiver::Orchard))
            .chain(unknown_tc.and_then(|typecode| {
                unknown_bytes.map(move |data| Receiver::Unknown {
                    typecode,
                    data: data.to_vec(),
                })
            }))
            .collect();

        let expected_addr = ZcashAddress::from_unified(Network::Main, unified::Address(receivers));

        // Test parsing
        let addr: ZcashAddress = tv.unified_addr.parse().unwrap();
        assert_eq!(addr, expected_addr);

        // Test serialization
        assert_eq!(expected_addr.to_string(), tv.unified_addr.to_string());
    }
}
