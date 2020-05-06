use group::{CurveAffine, CurveProjective};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::MulAssign;

use crate::{Engine, Field, PairingCurveAffine, PrimeField};

pub fn engine_tests<E: Engine>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..10 {
        let a = E::G1::random(&mut rng).into_affine();
        let b = E::G2::random(&mut rng).into_affine();

        assert!(a.pairing_with(&b) == b.pairing_with(&a));
        assert!(a.pairing_with(&b) == E::pairing(a, b));
    }

    for _ in 0..1000 {
        let z1 = E::G1Affine::zero().prepare();
        let z2 = E::G2Affine::zero().prepare();

        let a = E::G1::random(&mut rng).into_affine().prepare();
        let b = E::G2::random(&mut rng).into_affine().prepare();
        let c = E::G1::random(&mut rng).into_affine().prepare();
        let d = E::G2::random(&mut rng).into_affine().prepare();

        assert_eq!(
            E::Fqk::one(),
            E::final_exponentiation(&E::miller_loop(&[(&z1, &b)])).unwrap()
        );

        assert_eq!(
            E::Fqk::one(),
            E::final_exponentiation(&E::miller_loop(&[(&a, &z2)])).unwrap()
        );

        assert_eq!(
            E::final_exponentiation(&E::miller_loop(&[(&z1, &b), (&c, &d)])).unwrap(),
            E::final_exponentiation(&E::miller_loop(&[(&a, &z2), (&c, &d)])).unwrap()
        );

        assert_eq!(
            E::final_exponentiation(&E::miller_loop(&[(&a, &b), (&z1, &d)])).unwrap(),
            E::final_exponentiation(&E::miller_loop(&[(&a, &b), (&c, &z2)])).unwrap()
        );
    }

    random_bilinearity_tests::<E>();
    random_miller_loop_tests::<E>();
}

fn random_miller_loop_tests<E: Engine>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    // Exercise the miller loop for a reduced pairing
    for _ in 0..1000 {
        let a = E::G1::random(&mut rng);
        let b = E::G2::random(&mut rng);

        let p2 = E::pairing(a, b);

        let a = a.into_affine().prepare();
        let b = b.into_affine().prepare();

        let p1 = E::final_exponentiation(&E::miller_loop(&[(&a, &b)])).unwrap();

        assert_eq!(p1, p2);
    }

    // Exercise a double miller loop
    for _ in 0..1000 {
        let a = E::G1::random(&mut rng);
        let b = E::G2::random(&mut rng);
        let c = E::G1::random(&mut rng);
        let d = E::G2::random(&mut rng);

        let ab = E::pairing(a, b);
        let cd = E::pairing(c, d);

        let mut abcd = ab;
        abcd.mul_assign(&cd);

        let a = a.into_affine().prepare();
        let b = b.into_affine().prepare();
        let c = c.into_affine().prepare();
        let d = d.into_affine().prepare();

        let abcd_with_double_loop =
            E::final_exponentiation(&E::miller_loop(&[(&a, &b), (&c, &d)])).unwrap();

        assert_eq!(abcd, abcd_with_double_loop);
    }
}

fn random_bilinearity_tests<E: Engine>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let a = E::G1::random(&mut rng);
        let b = E::G2::random(&mut rng);

        let c = E::Fr::random(&mut rng);
        let d = E::Fr::random(&mut rng);

        let mut ac = a;
        ac.mul_assign(c);

        let mut ad = a;
        ad.mul_assign(d);

        let mut bc = b;
        bc.mul_assign(c);

        let mut bd = b;
        bd.mul_assign(d);

        let acbd = E::pairing(ac, bd);
        let adbc = E::pairing(ad, bc);

        let mut cd = c;
        cd.mul_assign(&d);

        let abcd = E::pairing(a, b).pow_vartime(cd.into_repr());

        assert_eq!(acbd, adbc);
        assert_eq!(acbd, abcd);
    }
}
