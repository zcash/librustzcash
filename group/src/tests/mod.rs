use ff::{Field, PrimeField};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::Neg;

use crate::{CurveAffine, CurveProjective, EncodedPoint};

pub fn curve_tests<G: CurveProjective>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    // Negation edge case with zero.
    {
        let z = G::zero().neg();
        assert!(z.is_zero());
    }

    // Doubling edge case with zero.
    {
        let mut z = G::zero();
        z.double();
        assert!(z.is_zero());
    }

    // Addition edge cases with zero
    {
        let mut r = G::random(&mut rng);
        let rcopy = r;
        r.add_assign(&G::zero());
        assert_eq!(r, rcopy);
        r.add_assign(&G::Affine::zero());
        assert_eq!(r, rcopy);

        let mut z = G::zero();
        z.add_assign(&G::zero());
        assert!(z.is_zero());
        z.add_assign(&G::Affine::zero());
        assert!(z.is_zero());

        let mut z2 = z;
        z2.add_assign(&r);

        z.add_assign(&r.into_affine());

        assert_eq!(z, z2);
        assert_eq!(z, r);
    }

    // Transformations
    {
        let a = G::random(&mut rng);
        let b = a.into_affine().into_projective();
        let c = a
            .into_affine()
            .into_projective()
            .into_affine()
            .into_projective();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    random_addition_tests::<G>();
    random_multiplication_tests::<G>();
    random_doubling_tests::<G>();
    random_negation_tests::<G>();
    random_transformation_tests::<G>();
    random_wnaf_tests::<G>();
    random_encoding_tests::<G>();
}

fn random_wnaf_tests<G: CurveProjective>() {
    use crate::wnaf::*;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    {
        let mut table = vec![];
        let mut wnaf = vec![];

        for w in 2..14 {
            for _ in 0..100 {
                let g = G::random(&mut rng);
                let s = G::Scalar::random(&mut rng).into_repr();
                let mut g1 = g;
                g1.mul_assign(s);

                wnaf_table(&mut table, g, w);
                wnaf_form(&mut wnaf, s, w);
                let g2 = wnaf_exp(&table, &wnaf);

                assert_eq!(g1, g2);
            }
        }
    }

    {
        fn only_compiles_if_send<S: Send>(_: &S) {}

        for _ in 0..100 {
            let g = G::random(&mut rng);
            let s = G::Scalar::random(&mut rng).into_repr();
            let mut g1 = g;
            g1.mul_assign(s);

            let g2 = {
                let mut wnaf = Wnaf::new();
                wnaf.base(g, 1).scalar(s)
            };
            let g3 = {
                let mut wnaf = Wnaf::new();
                wnaf.scalar(s).base(g)
            };
            let g4 = {
                let mut wnaf = Wnaf::new();
                let mut shared = wnaf.base(g, 1).shared();

                only_compiles_if_send(&shared);

                shared.scalar(s)
            };
            let g5 = {
                let mut wnaf = Wnaf::new();
                let mut shared = wnaf.scalar(s).shared();

                only_compiles_if_send(&shared);

                shared.base(g)
            };

            let g6 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                wnaf.base(g, 1).scalar(s)
            };
            let g7 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                wnaf.scalar(s).base(g)
            };
            let g8 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                let mut shared = wnaf.base(g, 1).shared();

                only_compiles_if_send(&shared);

                shared.scalar(s)
            };
            let g9 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                let mut shared = wnaf.scalar(s).shared();

                only_compiles_if_send(&shared);

                shared.base(g)
            };

            assert_eq!(g1, g2);
            assert_eq!(g1, g3);
            assert_eq!(g1, g4);
            assert_eq!(g1, g5);
            assert_eq!(g1, g6);
            assert_eq!(g1, g7);
            assert_eq!(g1, g8);
            assert_eq!(g1, g9);
        }
    }
}

fn random_negation_tests<G: CurveProjective>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let r = G::random(&mut rng);

        let s = G::Scalar::random(&mut rng);
        let sneg = s.neg();

        let mut t1 = r;
        t1.mul_assign(s);

        let mut t2 = r;
        t2.mul_assign(sneg);

        let mut t3 = t1;
        t3.add_assign(&t2);
        assert!(t3.is_zero());

        let mut t4 = t1;
        t4.add_assign(&t2.into_affine());
        assert!(t4.is_zero());

        assert_eq!(t1.neg(), t2);
    }
}

fn random_doubling_tests<G: CurveProjective>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let mut a = G::random(&mut rng);
        let mut b = G::random(&mut rng);

        // 2(a + b)
        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.double();

        // 2a + 2b
        a.double();
        b.double();

        let mut tmp2 = a;
        tmp2.add_assign(&b);

        let mut tmp3 = a;
        tmp3.add_assign(&b.into_affine());

        assert_eq!(tmp1, tmp2);
        assert_eq!(tmp1, tmp3);
    }
}

fn random_multiplication_tests<G: CurveProjective>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let mut a = G::random(&mut rng);
        let mut b = G::random(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();

        let s = G::Scalar::random(&mut rng);

        // s ( a + b )
        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.mul_assign(s);

        // sa + sb
        a.mul_assign(s);
        b.mul_assign(s);

        let mut tmp2 = a;
        tmp2.add_assign(&b);

        // Affine multiplication
        let mut tmp3 = a_affine.mul(s);
        tmp3.add_assign(&b_affine.mul(s));

        assert_eq!(tmp1, tmp2);
        assert_eq!(tmp1, tmp3);
    }
}

fn random_addition_tests<G: CurveProjective>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let a = G::random(&mut rng);
        let b = G::random(&mut rng);
        let c = G::random(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();
        let c_affine = c.into_affine();

        // a + a should equal the doubling
        {
            let mut aplusa = a;
            aplusa.add_assign(&a);

            let mut aplusamixed = a;
            aplusamixed.add_assign(&a.into_affine());

            let mut adouble = a;
            adouble.double();

            assert_eq!(aplusa, adouble);
            assert_eq!(aplusa, aplusamixed);
        }

        let mut tmp = vec![G::zero(); 6];

        // (a + b) + c
        tmp[0] = a;
        tmp[0].add_assign(&b);
        tmp[0].add_assign(&c);

        // a + (b + c)
        tmp[1] = b;
        tmp[1].add_assign(&c);
        tmp[1].add_assign(&a);

        // (a + c) + b
        tmp[2] = a;
        tmp[2].add_assign(&c);
        tmp[2].add_assign(&b);

        // Mixed addition

        // (a + b) + c
        tmp[3] = a_affine.into_projective();
        tmp[3].add_assign(&b_affine);
        tmp[3].add_assign(&c_affine);

        // a + (b + c)
        tmp[4] = b_affine.into_projective();
        tmp[4].add_assign(&c_affine);
        tmp[4].add_assign(&a_affine);

        // (a + c) + b
        tmp[5] = a_affine.into_projective();
        tmp[5].add_assign(&c_affine);
        tmp[5].add_assign(&b_affine);

        // Comparisons
        for i in 0..6 {
            for j in 0..6 {
                assert_eq!(tmp[i], tmp[j]);
                assert_eq!(tmp[i].into_affine(), tmp[j].into_affine());
            }

            assert!(tmp[i] != a);
            assert!(tmp[i] != b);
            assert!(tmp[i] != c);

            assert!(a != tmp[i]);
            assert!(b != tmp[i]);
            assert!(c != tmp[i]);
        }
    }
}

fn random_transformation_tests<G: CurveProjective>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let g = G::random(&mut rng);
        let g_affine = g.into_affine();
        let g_projective = g_affine.into_projective();
        assert_eq!(g, g_projective);
    }

    // Batch normalization
    for _ in 0..10 {
        let mut v = (0..1000).map(|_| G::random(&mut rng)).collect::<Vec<_>>();

        for i in &v {
            assert!(!i.is_normalized());
        }

        use rand::distributions::{Distribution, Uniform};
        let between = Uniform::new(0, 1000);
        // Sprinkle in some normalized points
        for _ in 0..5 {
            v[between.sample(&mut rng)] = G::zero();
        }
        for _ in 0..5 {
            let s = between.sample(&mut rng);
            v[s] = v[s].into_affine().into_projective();
        }

        let expected_v = v
            .iter()
            .map(|v| v.into_affine().into_projective())
            .collect::<Vec<_>>();
        G::batch_normalization(&mut v);

        for i in &v {
            assert!(i.is_normalized());
        }

        assert_eq!(v, expected_v);
    }
}

fn random_encoding_tests<G: CurveProjective>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    assert_eq!(
        G::Affine::zero().into_uncompressed().into_affine().unwrap(),
        G::Affine::zero()
    );

    assert_eq!(
        G::Affine::zero().into_compressed().into_affine().unwrap(),
        G::Affine::zero()
    );

    for _ in 0..1000 {
        let mut r = G::random(&mut rng).into_affine();

        let uncompressed = r.into_uncompressed();
        let de_uncompressed = uncompressed.into_affine().unwrap();
        assert_eq!(de_uncompressed, r);

        let compressed = r.into_compressed();
        let de_compressed = compressed.into_affine().unwrap();
        assert_eq!(de_compressed, r);

        r = r.neg();

        let compressed = r.into_compressed();
        let de_compressed = compressed.into_affine().unwrap();
        assert_eq!(de_compressed, r);
    }
}
