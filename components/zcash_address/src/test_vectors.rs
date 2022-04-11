use std::iter;

use crate::{
    unified::{
        self,
        address::{test_vectors::test_vectors, Receiver},
    },
    Network, ToAddress, ZcashAddress,
};

#[test]
fn unified() {
    for tv in test_vectors() {
        // Double-check test vectors match requirements:
        // - Only one of P2PKH and P2SH.
        assert!(tv.p2pkh_bytes.is_none() || tv.p2sh_bytes.is_none());
        // - At least one shielded receiver.
        assert!(tv.sapling_raw_addr.is_some() || tv.orchard_raw_addr.is_some());

        let addr_string = String::from_utf8(tv.unified_addr.to_vec()).unwrap();

        let unknown_tc = tv.unknown_typecode;
        let receivers = iter::empty()
            .chain(tv.p2pkh_bytes.map(Receiver::P2pkh))
            .chain(tv.p2sh_bytes.map(Receiver::P2sh))
            .chain(tv.sapling_raw_addr.map(Receiver::Sapling))
            .chain(tv.orchard_raw_addr.map(Receiver::Orchard))
            .chain(tv.unknown_bytes.map(|data| Receiver::Unknown {
                typecode: unknown_tc,
                data,
            }))
            .collect();

        let expected_addr = ZcashAddress::from_unified(Network::Main, unified::Address(receivers));

        // Test parsing
        let addr: ZcashAddress = addr_string.parse().unwrap();
        assert_eq!(addr, expected_addr);

        // Test serialization
        assert_eq!(expected_addr.to_string(), addr_string);
    }
}
