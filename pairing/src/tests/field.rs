use ff::{Field, PrimeField, SqrtField};
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

pub fn random_frobenius_tests<F: Field, C: AsRef<[u64]>>(characteristic: C, maxpower: usize) {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..100 {
        for i in 0..=maxpower {
            let mut a = F::random(&mut rng);
            let mut b = a;

            for _ in 0..i {
                a = a.pow_vartime(&characteristic);
            }
            b.frobenius_map(i);

            assert_eq!(a, b);
        }
    }
}

pub fn random_sqrt_tests<F: SqrtField>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..10000 {
        let a = F::random(&mut rng);
        let b = a.square();

        let b = b.sqrt().unwrap();
        let negb = b.neg();

        assert!(a == b || a == negb);
    }

    let mut c = F::one();
    for _ in 0..10000 {
        let mut b = c.square();

        b = b.sqrt().unwrap();

        if b != c {
            b = b.neg();
        }

        assert_eq!(b, c);

        c.add_assign(&F::one());
    }
}

pub fn random_field_tests<F: Field>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    random_multiplication_tests::<F, _>(&mut rng);
    random_addition_tests::<F, _>(&mut rng);
    random_subtraction_tests::<F, _>(&mut rng);
    random_negation_tests::<F, _>(&mut rng);
    random_doubling_tests::<F, _>(&mut rng);
    random_squaring_tests::<F, _>(&mut rng);
    random_inversion_tests::<F, _>(&mut rng);
    random_expansion_tests::<F, _>(&mut rng);

    assert!(F::zero().is_zero());
    {
        let z = F::zero().neg();
        assert!(z.is_zero());
    }

    assert!(bool::from(F::zero().invert().is_none()));

    // Multiplication by zero
    {
        let mut a = F::random(&mut rng);
        a.mul_assign(&F::zero());
        assert!(a.is_zero());
    }

    // Addition by zero
    {
        let mut a = F::random(&mut rng);
        let copy = a;
        a.add_assign(&F::zero());
        assert_eq!(a, copy);
    }
}

pub fn from_str_tests<F: PrimeField>() {
    {
        let a = "84395729384759238745923745892374598234705297301958723458712394587103249587213984572934750213947582345792304758273458972349582734958273495872304598234";
        let b = "38495729084572938457298347502349857029384609283450692834058293405982304598230458230495820394850293845098234059823049582309485203948502938452093482039";
        let c = "3248875134290623212325429203829831876024364170316860259933542844758450336418538569901990710701240661702808867062612075657861768196242274635305077449545396068598317421057721935408562373834079015873933065667961469731886739181625866970316226171512545167081793907058686908697431878454091011239990119126";

        let mut a = F::from_str(a).unwrap();
        let b = F::from_str(b).unwrap();
        let c = F::from_str(c).unwrap();

        a.mul_assign(&b);

        assert_eq!(a, c);
    }

    {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..1000 {
            let n = rng.next_u64();

            let a = F::from_str(&format!("{}", n)).unwrap();
            let b = F::from_repr(n.into()).unwrap();

            assert_eq!(a, b);
        }
    }

    assert!(F::from_str("").is_none());
    assert!(F::from_str("0").unwrap().is_zero());
    assert!(F::from_str("00").is_none());
    assert!(F::from_str("00000000000").is_none());
}

fn random_multiplication_tests<F: Field, R: RngCore>(rng: &mut R) {
    for _ in 0..10000 {
        let a = F::random(rng);
        let b = F::random(rng);
        let c = F::random(rng);

        let mut t0 = a; // (a * b) * c
        t0.mul_assign(&b);
        t0.mul_assign(&c);

        let mut t1 = a; // (a * c) * b
        t1.mul_assign(&c);
        t1.mul_assign(&b);

        let mut t2 = b; // (b * c) * a
        t2.mul_assign(&c);
        t2.mul_assign(&a);

        assert_eq!(t0, t1);
        assert_eq!(t1, t2);
    }
}

fn random_addition_tests<F: Field, R: RngCore>(rng: &mut R) {
    for _ in 0..10000 {
        let a = F::random(rng);
        let b = F::random(rng);
        let c = F::random(rng);

        let mut t0 = a; // (a + b) + c
        t0.add_assign(&b);
        t0.add_assign(&c);

        let mut t1 = a; // (a + c) + b
        t1.add_assign(&c);
        t1.add_assign(&b);

        let mut t2 = b; // (b + c) + a
        t2.add_assign(&c);
        t2.add_assign(&a);

        assert_eq!(t0, t1);
        assert_eq!(t1, t2);
    }
}

fn random_subtraction_tests<F: Field, R: RngCore>(rng: &mut R) {
    for _ in 0..10000 {
        let b = F::random(rng);
        let a = F::random(rng);

        let mut t0 = a; // (a - b)
        t0.sub_assign(&b);

        let mut t1 = b; // (b - a)
        t1.sub_assign(&a);

        let mut t2 = t0; // (a - b) + (b - a) = 0
        t2.add_assign(&t1);

        assert!(t2.is_zero());
    }
}

fn random_negation_tests<F: Field, R: RngCore>(rng: &mut R) {
    for _ in 0..10000 {
        let a = F::random(rng);
        let mut b = a.neg();
        b.add_assign(&a);

        assert!(b.is_zero());
    }
}

fn random_doubling_tests<F: Field, R: RngCore>(rng: &mut R) {
    for _ in 0..10000 {
        let a = F::random(rng);
        assert_eq!(a + a, a.double());
    }
}

fn random_squaring_tests<F: Field, R: RngCore>(rng: &mut R) {
    for _ in 0..10000 {
        let a = F::random(rng);
        assert_eq!(a * a, a.square());
    }
}

fn random_inversion_tests<F: Field, R: RngCore>(rng: &mut R) {
    assert!(bool::from(F::zero().invert().is_none()));

    for _ in 0..10000 {
        let mut a = F::random(rng);
        let b = a.invert().unwrap(); // probablistically nonzero
        a.mul_assign(&b);

        assert_eq!(a, F::one());
    }
}

fn random_expansion_tests<F: Field, R: RngCore>(rng: &mut R) {
    for _ in 0..10000 {
        // Compare (a + b)(c + d) and (a*c + b*c + a*d + b*d)

        let a = F::random(rng);
        let b = F::random(rng);
        let c = F::random(rng);
        let d = F::random(rng);

        let mut t0 = a;
        t0.add_assign(&b);
        let mut t1 = c;
        t1.add_assign(&d);
        t0.mul_assign(&t1);

        let mut t2 = a;
        t2.mul_assign(&c);
        let mut t3 = b;
        t3.mul_assign(&c);
        let mut t4 = a;
        t4.mul_assign(&d);
        let mut t5 = b;
        t5.mul_assign(&d);

        t2.add_assign(&t3);
        t2.add_assign(&t4);
        t2.add_assign(&t5);

        assert_eq!(t0, t2);
    }
}
