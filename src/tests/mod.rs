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
