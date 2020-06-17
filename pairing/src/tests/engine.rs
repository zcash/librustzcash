use ff::{Endianness, Field, PrimeField};
use group::{cofactor::CofactorCurveAffine, Curve, Group};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::MulAssign;

use crate::{Engine, MillerLoopResult, MultiMillerLoop, PairingCurveAffine};

pub fn engine_tests<E: MultiMillerLoop>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..10 {
        let a = E::G1::random(&mut rng).to_affine();
        let b = E::G2::random(&mut rng).to_affine();

        assert!(a.pairing_with(&b) == b.pairing_with(&a));
        assert!(a.pairing_with(&b) == E::pairing(&a, &b));
    }

    for _ in 0..1000 {
        let z1 = E::G1Affine::identity();
        let z2 = E::G2Affine::identity().into();

        let a = E::G1::random(&mut rng).to_affine();
        let b = E::G2::random(&mut rng).to_affine().into();
        let c = E::G1::random(&mut rng).to_affine();
        let d = E::G2::random(&mut rng).to_affine().into();

        assert_eq!(
            E::Gt::one(),
            E::multi_miller_loop(&[(&z1, &b)]).final_exponentiation()
        );

        assert_eq!(
            E::Gt::one(),
            E::multi_miller_loop(&[(&a, &z2)]).final_exponentiation()
        );

        assert_eq!(
            E::multi_miller_loop(&[(&z1, &b), (&c, &d)]).final_exponentiation(),
            E::multi_miller_loop(&[(&a, &z2), (&c, &d)]).final_exponentiation()
        );

        assert_eq!(
            E::multi_miller_loop(&[(&a, &b), (&z1, &d)]).final_exponentiation(),
            E::multi_miller_loop(&[(&a, &b), (&c, &z2)]).final_exponentiation()
        );
    }

    random_bilinearity_tests::<E>();
    random_miller_loop_tests::<E>();
}

fn random_miller_loop_tests<E: MultiMillerLoop>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    // Exercise the miller loop for a reduced pairing
    for _ in 0..1000 {
        let a = E::G1::random(&mut rng).to_affine();
        let b = E::G2::random(&mut rng).to_affine();

        let p2 = E::pairing(&a, &b);

        let a = a;
        let b = b.into();

        let p1 = E::multi_miller_loop(&[(&a, &b)]).final_exponentiation();

        assert_eq!(p1, p2);
    }

    // Exercise a double miller loop
    for _ in 0..1000 {
        let a = E::G1::random(&mut rng).to_affine();
        let b = E::G2::random(&mut rng).to_affine();
        let c = E::G1::random(&mut rng).to_affine();
        let d = E::G2::random(&mut rng).to_affine();

        let ab = E::pairing(&a, &b);
        let cd = E::pairing(&c, &d);

        let mut abcd = ab;
        abcd.mul_assign(&cd);

        let a = a;
        let b = b.into();
        let c = c;
        let d = d.into();

        let abcd_with_double_loop =
            E::multi_miller_loop(&[(&a, &b), (&c, &d)]).final_exponentiation();

        assert_eq!(abcd, abcd_with_double_loop);
    }
}

fn random_bilinearity_tests<E: Engine>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let a = E::G1::random(&mut rng).to_affine();
        let b = E::G2::random(&mut rng).to_affine();

        let c = E::Fr::random(&mut rng);
        let d = E::Fr::random(&mut rng);

        let ac = (a * &c).to_affine();
        let ad = (a * &d).to_affine();
        let bc = (b * &c).to_affine();
        let bd = (b * &d).to_affine();

        let acbd = E::pairing(&ac, &bd);
        let adbc = E::pairing(&ad, &bc);

        let mut cd = (c * &d).to_repr();
        <E::Fr as PrimeField>::ReprEndianness::toggle_little_endian(&mut cd);

        use byteorder::ByteOrder;
        let mut cd_limbs = [0; 4];
        byteorder::LittleEndian::read_u64_into(cd.as_ref(), &mut cd_limbs);

        let abcd = E::pairing(&a, &b).pow_vartime(cd_limbs);

        assert_eq!(acbd, adbc);
        assert_eq!(acbd, abcd);
    }
}
