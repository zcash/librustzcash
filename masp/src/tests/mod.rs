use group::GroupEncoding;
use masp_primitives::asset_type::AssetType;
use masp_primitives::constants::{
    ASSET_IDENTIFIER_LENGTH, NOTE_COMMITMENT_RANDOMNESS_GENERATOR, NULLIFIER_POSITION_GENERATOR,
    PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
};

use crate::{libmasp_new_asset_identifier, libmasp_asset_from_name_and_nonce};
use libc::c_uchar;

mod key_agreement;
mod key_components;
mod notes;
mod signatures;

#[test]
fn sapling_generators() {
    struct SaplingGenerators {
        skb: [u8; 32],
        pkb: [u8; 32],
        npb: [u8; 32],
        wprb: [u8; 32],
        vcvb: [u8; 32],
        vcrb: [u8; 32],
    };

    // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_generators.py
    let sapling_generators = SaplingGenerators {
        skb: [
            0xb1, 0xb4, 0x86, 0xa1, 0x23, 0x26, 0xb6, 0x14, 0x52, 0xfd, 0x24, 0xf6, 0x31, 0xd0,
            0x12, 0x20, 0xf2, 0x9e, 0xf4, 0xf1, 0xcf, 0xfe, 0xde, 0x75, 0xab, 0xe0, 0x52, 0x1e,
            0x9f, 0x5f, 0xbc, 0x0c,
        ],
        pkb: [
            0xf8, 0xbf, 0x75, 0xc5, 0xbe, 0x96, 0x6f, 0xfe, 0x08, 0x07, 0xaf, 0xa2, 0x71, 0x9c,
            0xb4, 0x36, 0xe9, 0x4d, 0x00, 0x36, 0xdd, 0xdf, 0x54, 0xc6, 0x65, 0x63, 0x90, 0xd6,
            0x67, 0x0d, 0x93, 0x00,
        ],
        npb: [
            0xb3, 0x1e, 0x3a, 0xe1, 0x3e, 0x4e, 0x03, 0xed, 0x0a, 0xfe, 0x6d, 0xe9, 0xae, 0x45,
            0x69, 0x22, 0x9d, 0x79, 0xfe, 0x1a, 0xc3, 0x0d, 0xf7, 0xf3, 0x50, 0x40, 0x24, 0xf1,
            0x0b, 0x0f, 0x26, 0x83,
        ],
        wprb: [
            0xed, 0xae, 0x22, 0xee, 0xa0, 0xda, 0xb8, 0xc6, 0x64, 0x5c, 0xb8, 0x66, 0x5c, 0x29,
            0x0b, 0x69, 0xf0, 0xf8, 0x7a, 0xe9, 0x97, 0x71, 0x27, 0x6d, 0x73, 0xbc, 0xd3, 0x93,
            0x69, 0x92, 0xe2, 0x29,
        ],
        vcvb: [
            0x32, 0x06, 0xb9, 0x3a, 0xbd, 0xa8, 0x7c, 0x55, 0xb2, 0x6e, 0x4b, 0x9a, 0x76, 0x28,
            0xbc, 0x4a, 0xc6, 0xeb, 0xb0, 0x60, 0x0d, 0xd1, 0x37, 0x4b, 0x47, 0xd5, 0xab, 0x04,
            0xc1, 0xb8, 0x18, 0x3c,
        ],
        vcrb: [
            0xd0, 0x92, 0xe6, 0x9c, 0xe9, 0xfc, 0xe5, 0x28, 0xfe, 0x02, 0x03, 0x36, 0xaa, 0x2d,
            0x4c, 0xf9, 0x50, 0x11, 0xae, 0xb8, 0xd4, 0x0c, 0x90, 0xbc, 0x0b, 0xd5, 0x20, 0xb7,
            0xf9, 0x11, 0x5f, 0x55,
        ],
    };

    assert_eq!(&SPENDING_KEY_GENERATOR.to_bytes(), &sapling_generators.skb);
    assert_eq!(
        &PROOF_GENERATION_KEY_GENERATOR.to_bytes(),
        &sapling_generators.pkb
    );
    assert_eq!(
        &NULLIFIER_POSITION_GENERATOR.to_bytes(),
        &sapling_generators.npb
    );
    assert_eq!(
        &NOTE_COMMITMENT_RANDOMNESS_GENERATOR.to_bytes(),
        &sapling_generators.wprb
    );
    let asset_type = AssetType::from_identifier(
        b"sO\x0e\xc5os\x1e\x02\xccs~ki=\xb5+\x82\x1fonL\xd7\xfe<vCS\xf2cf\x9f\xbe", // b'default' under repeated hashing
    )
    .unwrap();
    assert_eq!(
        &asset_type.asset_generator().to_bytes(), // cofactor not cleared
        &sapling_generators.vcvb
    );
    assert_eq!(
        &VALUE_COMMITMENT_RANDOMNESS_GENERATOR.to_bytes(),
        &sapling_generators.vcrb
    );

    let asset_name: [c_uchar; 33] = *b"libmasp_new_asset_identifier test";
    let mut identifier_result: [c_uchar; ASSET_IDENTIFIER_LENGTH] = [0u8; ASSET_IDENTIFIER_LENGTH];
    let mut nonce_result = 0u8;

    assert!(libmasp_new_asset_identifier(
        asset_name.as_ptr(),
        33,
        &mut identifier_result,
        &mut nonce_result as *mut u8
    ));
    assert_eq!(
        identifier_result,
        [
            111, 168, 238, 116, 191, 118, 243, 110, 154, 73, 142, 75, 91, 203, 138, 114, 20, 66,
            249, 42, 15, 149, 115, 98, 99, 207, 81, 238, 2, 121, 163, 15,
        ]
    );
    assert_eq!(nonce_result, 3);

    let mut identifier_result_2: [c_uchar; ASSET_IDENTIFIER_LENGTH] =
        [0u8; ASSET_IDENTIFIER_LENGTH];

    assert!(libmasp_asset_from_name_and_nonce(
        asset_name.as_ptr(),
        33,
        nonce_result,
        &mut identifier_result_2
    ));

    assert_eq!(identifier_result, identifier_result_2);
}
