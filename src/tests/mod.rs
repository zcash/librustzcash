use super::*;

macro_rules! test_vectors {
    ($projective:ident, $affine:ident, $serialize:ident, $deserialize:ident, $expected:ident) => {
        let mut e = $projective::identity();

        let mut v = vec![];
        {
            let mut expected = $expected;
            for _ in 0..1000 {
                let e_affine = $affine::from(e);
                let encoded = e_affine.$serialize();
                v.extend_from_slice(&encoded[..]);

                let mut decoded = encoded;
                let len_of_encoding = decoded.len();
                (&mut decoded[..]).copy_from_slice(&expected[0..len_of_encoding]);
                expected = &expected[len_of_encoding..];
                let decoded = $affine::$deserialize(&decoded).unwrap();
                assert_eq!(e_affine, decoded);

                e = &e + &$projective::generator();
            }
        }

        assert_eq!(&v[..], $expected);
    };
}

#[test]
fn g1_uncompressed_valid_test_vectors() {
    let bytes: &'static [u8] = include_bytes!("g1_uncompressed_valid_test_vectors.dat");
    test_vectors!(
        G1Projective,
        G1Affine,
        to_uncompressed,
        from_uncompressed,
        bytes
    );
}

#[test]
fn g1_compressed_valid_test_vectors() {
    let bytes: &'static [u8] = include_bytes!("g1_compressed_valid_test_vectors.dat");
    test_vectors!(
        G1Projective,
        G1Affine,
        to_compressed,
        from_compressed,
        bytes
    );
}

#[test]
fn g2_uncompressed_valid_test_vectors() {
    let bytes: &'static [u8] = include_bytes!("g2_uncompressed_valid_test_vectors.dat");
    test_vectors!(
        G2Projective,
        G2Affine,
        to_uncompressed,
        from_uncompressed,
        bytes
    );
}

#[test]
fn g2_compressed_valid_test_vectors() {
    let bytes: &'static [u8] = include_bytes!("g2_compressed_valid_test_vectors.dat");
    test_vectors!(
        G2Projective,
        G2Affine,
        to_compressed,
        from_compressed,
        bytes
    );
}

#[test]
fn test_pairing_result_against_relic() {
    /*
    Sent to me from Diego Aranha (author of RELIC library):
    1250EBD871FC0A92 A7B2D83168D0D727 272D441BEFA15C50 3DD8E90CE98DB3E7 B6D194F60839C508 A84305AACA1789B6
    089A1C5B46E5110B 86750EC6A5323488 68A84045483C92B7 AF5AF689452EAFAB F1A8943E50439F1D 59882A98EAA0170F
    1368BB445C7C2D20 9703F239689CE34C 0378A68E72A6B3B2 16DA0E22A5031B54 DDFF57309396B38C 881C4C849EC23E87
    193502B86EDB8857 C273FA075A505129 37E0794E1E65A761 7C90D8BD66065B1F FFE51D7A579973B1 315021EC3C19934F
    01B2F522473D1713 91125BA84DC4007C FBF2F8DA752F7C74 185203FCCA589AC7 19C34DFFBBAAD843 1DAD1C1FB597AAA5
    018107154F25A764 BD3C79937A45B845 46DA634B8F6BE14A 8061E55CCEBA478B 23F7DACAA35C8CA7 8BEAE9624045B4B6
    19F26337D205FB46 9CD6BD15C3D5A04D C88784FBB3D0B2DB DEA54D43B2B73F2C BB12D58386A8703E 0F948226E47EE89D
    06FBA23EB7C5AF0D 9F80940CA771B6FF D5857BAAF222EB95 A7D2809D61BFE02E 1BFD1B68FF02F0B8 102AE1C2D5D5AB1A
    11B8B424CD48BF38 FCEF68083B0B0EC5 C81A93B330EE1A67 7D0D15FF7B984E89 78EF48881E32FAC9 1B93B47333E2BA57
    03350F55A7AEFCD3 C31B4FCB6CE5771C C6A0E9786AB59733 20C806AD36082910 7BA810C5A09FFDD9 BE2291A0C25A99A2
    04C581234D086A99 02249B64728FFD21 A189E87935A95405 1C7CDBA7B3872629 A4FAFC05066245CB 9108F0242D0FE3EF
    0F41E58663BF08CF 068672CBD01A7EC7 3BACA4D72CA93544 DEFF686BFD6DF543 D48EAA24AFE47E1E FDE449383B676631
    */

    let a = G1Affine::generator();
    let b = G2Affine::generator();

    use super::fp::Fp;
    use super::fp12::Fp12;
    use super::fp2::Fp2;
    use super::fp6::Fp6;

    let res = pairing(&a, &b);

    let prep = G2Prepared::from(b);

    assert_eq!(
        res,
        multi_miller_loop(&[(&a, &prep)]).final_exponentiation()
    );

    assert_eq!(
        res.0,
        Fp12 {
            c0: Fp6 {
                c0: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x1972e433a01f85c5,
                        0x97d32b76fd772538,
                        0xc8ce546fc96bcdf9,
                        0xcef63e7366d40614,
                        0xa611342781843780,
                        0x13f3448a3fc6d825
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xd26331b02e9d6995,
                        0x9d68a482f7797e7d,
                        0x9c9b29248d39ea92,
                        0xf4801ca2e13107aa,
                        0xa16c0732bdbcb066,
                        0x83ca4afba360478
                    ])
                },
                c1: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x59e261db0916b641,
                        0x2716b6f4b23e960d,
                        0xc8e55b10a0bd9c45,
                        0xbdb0bd99c4deda8,
                        0x8cf89ebf57fdaac5,
                        0x12d6b7929e777a5e
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x5fc85188b0e15f35,
                        0x34a06e3a8f096365,
                        0xdb3126a6e02ad62c,
                        0xfc6f5aa97d9a990b,
                        0xa12f55f5eb89c210,
                        0x1723703a926f8889
                    ])
                },
                c2: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x93588f2971828778,
                        0x43f65b8611ab7585,
                        0x3183aaf5ec279fdf,
                        0xfa73d7e18ac99df6,
                        0x64e176a6a64c99b0,
                        0x179fa78c58388f1f
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x672a0a11ca2aef12,
                        0xd11b9b52aa3f16b,
                        0xa44412d0699d056e,
                        0xc01d0177221a5ba5,
                        0x66e0cede6c735529,
                        0x5f5a71e9fddc339
                    ])
                }
            },
            c1: Fp6 {
                c0: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0xd30a88a1b062c679,
                        0x5ac56a5d35fc8304,
                        0xd0c834a6a81f290d,
                        0xcd5430c2da3707c7,
                        0xf0c27ff780500af0,
                        0x9245da6e2d72eae
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x9f2e0676791b5156,
                        0xe2d1c8234918fe13,
                        0x4c9e459f3c561bf4,
                        0xa3e85e53b9d3e3c1,
                        0x820a121e21a70020,
                        0x15af618341c59acc
                    ])
                },
                c1: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x7c95658c24993ab1,
                        0x73eb38721ca886b9,
                        0x5256d749477434bc,
                        0x8ba41902ea504a8b,
                        0x4a3d3f80c86ce6d,
                        0x18a64a87fb686eaa
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xbb83e71bb920cf26,
                        0x2a5277ac92a73945,
                        0xfc0ee59f94f046a0,
                        0x7158cdf3786058f7,
                        0x7cc1061b82f945f6,
                        0x3f847aa9fdbe567
                    ])
                },
                c2: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x8078dba56134e657,
                        0x1cd7ec9a43998a6e,
                        0xb1aa599a1a993766,
                        0xc9a0f62f0842ee44,
                        0x8e159be3b605dffa,
                        0xc86ba0d4af13fc2
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xe80ff2a06a52ffb1,
                        0x7694ca48721a906c,
                        0x7583183e03b08514,
                        0xf567afdd40cee4e2,
                        0x9a6d96d2e526a5fc,
                        0x197e9f49861f2242
                    ])
                }
            }
        }
    );
}
