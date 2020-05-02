use ff::{Field, PrimeField};
use std::ops::{AddAssign, MulAssign, SubAssign};

#[derive(PrimeField)]
#[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Fr([u64; 4]);

#[cfg(test)]
use rand_core::SeedableRng;
#[cfg(test)]
use rand_xorshift::XorShiftRng;
#[cfg(test)]
use std::ops::Neg;

#[test]
fn test_fr_is_valid() {
    let mut a = MODULUS_LIMBS;
    assert!(!a.is_valid());
    a.sub_noborrow(&Fr([1, 0, 0, 0]));
    assert!(a.is_valid());
    assert!(Fr::from(0).is_valid());
    assert!(Fr([
        0xffffffff00000000,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48
    ])
    .is_valid());
    assert!(!Fr([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff
    ])
    .is_valid());

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let a = Fr::random(&mut rng);
        assert!(a.is_valid());
    }
}

#[test]
fn test_fr_add_assign() {
    {
        // Random number
        let mut tmp = Fr([
            0x437ce7616d580765,
            0xd42d1ccb29d1235b,
            0xed8f753821bd1423,
            0x4eede1c9c89528ca,
        ]);
        assert!(tmp.is_valid());
        // Test that adding zero has no effect.
        tmp.add_assign(&Fr([0, 0, 0, 0]));
        assert_eq!(
            tmp,
            Fr([
                0x437ce7616d580765,
                0xd42d1ccb29d1235b,
                0xed8f753821bd1423,
                0x4eede1c9c89528ca
            ])
        );
        // Add one and test for the result.
        tmp.add_assign(&Fr([1, 0, 0, 0]));
        assert_eq!(
            tmp,
            Fr([
                0x437ce7616d580766,
                0xd42d1ccb29d1235b,
                0xed8f753821bd1423,
                0x4eede1c9c89528ca
            ])
        );
        // Add another random number that exercises the reduction.
        tmp.add_assign(&Fr([
            0x946f435944f7dc79,
            0xb55e7ee6533a9b9b,
            0x1e43b84c2f6194ca,
            0x58717ab525463496,
        ]));
        assert_eq!(
            tmp,
            Fr([
                0xd7ec2abbb24fe3de,
                0x35cdf7ae7d0d62f7,
                0xd899557c477cd0e9,
                0x3371b52bc43de018
            ])
        );
        // Add one to (r - 1) and test for the result.
        tmp = Fr([
            0xffffffff00000000,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ]);
        tmp.add_assign(&Fr([1, 0, 0, 0]));
        assert!(tmp.is_zero());
        // Add a random number to another one such that the result is r - 1
        tmp = Fr([
            0xade5adacdccb6190,
            0xaa21ee0f27db3ccd,
            0x2550f4704ae39086,
            0x591d1902e7c5ba27,
        ]);
        tmp.add_assign(&Fr([
            0x521a525223349e70,
            0xa99bb5f3d8231f31,
            0xde8e397bebe477e,
            0x1ad08e5041d7c321,
        ]));
        assert_eq!(
            tmp,
            Fr([
                0xffffffff00000000,
                0x53bda402fffe5bfe,
                0x3339d80809a1d805,
                0x73eda753299d7d48
            ])
        );
        // Add one to the result and test for it.
        tmp.add_assign(&Fr([1, 0, 0, 0]));
        assert!(tmp.is_zero());
    }

    // Test associativity

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Generate a, b, c and ensure (a + b) + c == a + (b + c).
        let a = Fr::random(&mut rng);
        let b = Fr::random(&mut rng);
        let c = Fr::random(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);

        let mut tmp2 = b;
        tmp2.add_assign(&c);
        tmp2.add_assign(&a);

        assert!(tmp1.is_valid());
        assert!(tmp2.is_valid());
        assert_eq!(tmp1, tmp2);
    }
}

#[test]
fn test_fr_sub_assign() {
    {
        // Test arbitrary subtraction that tests reduction.
        let mut tmp = Fr([
            0x6a68c64b6f735a2b,
            0xd5f4d143fe0a1972,
            0x37c17f3829267c62,
            0xa2f37391f30915c,
        ]);
        tmp.sub_assign(&Fr([
            0xade5adacdccb6190,
            0xaa21ee0f27db3ccd,
            0x2550f4704ae39086,
            0x591d1902e7c5ba27,
        ]));
        assert_eq!(
            tmp,
            Fr([
                0xbc83189d92a7f89c,
                0x7f908737d62d38a3,
                0x45aa62cfe7e4c3e1,
                0x24ffc5896108547d
            ])
        );

        // Test the opposite subtraction which doesn't test reduction.
        tmp = Fr([
            0xade5adacdccb6190,
            0xaa21ee0f27db3ccd,
            0x2550f4704ae39086,
            0x591d1902e7c5ba27,
        ]);
        tmp.sub_assign(&Fr([
            0x6a68c64b6f735a2b,
            0xd5f4d143fe0a1972,
            0x37c17f3829267c62,
            0xa2f37391f30915c,
        ]));
        assert_eq!(
            tmp,
            Fr([
                0x437ce7616d580765,
                0xd42d1ccb29d1235b,
                0xed8f753821bd1423,
                0x4eede1c9c89528ca
            ])
        );

        // Test for sensible results with zero
        tmp = Fr::from(0);
        tmp.sub_assign(&Fr::from(0));
        assert!(tmp.is_zero());

        tmp = Fr([
            0x437ce7616d580765,
            0xd42d1ccb29d1235b,
            0xed8f753821bd1423,
            0x4eede1c9c89528ca,
        ]);
        tmp.sub_assign(&Fr::from(0));
        assert_eq!(
            tmp,
            Fr([
                0x437ce7616d580765,
                0xd42d1ccb29d1235b,
                0xed8f753821bd1423,
                0x4eede1c9c89528ca
            ])
        );
    }

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure that (a - b) + (b - a) = 0.
        let a = Fr::random(&mut rng);
        let b = Fr::random(&mut rng);

        let mut tmp1 = a;
        tmp1.sub_assign(&b);

        let mut tmp2 = b;
        tmp2.sub_assign(&a);

        tmp1.add_assign(&tmp2);
        assert!(tmp1.is_zero());
    }
}

#[test]
fn test_fr_mul_assign() {
    let mut tmp = Fr([
        0x6b7e9b8faeefc81a,
        0xe30a8463f348ba42,
        0xeff3cb67a8279c9c,
        0x3d303651bd7c774d,
    ]);
    tmp.mul_assign(&Fr([
        0x13ae28e3bc35ebeb,
        0xa10f4488075cae2c,
        0x8160e95a853c3b5d,
        0x5ae3f03b561a841d,
    ]));
    assert!(
        tmp == Fr([
            0x23717213ce710f71,
            0xdbee1fe53a16e1af,
            0xf565d3e1c2a48000,
            0x4426507ee75df9d7
        ])
    );

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000000 {
        // Ensure that (a * b) * c = a * (b * c)
        let a = Fr::random(&mut rng);
        let b = Fr::random(&mut rng);
        let c = Fr::random(&mut rng);

        let mut tmp1 = a;
        tmp1.mul_assign(&b);
        tmp1.mul_assign(&c);

        let mut tmp2 = b;
        tmp2.mul_assign(&c);
        tmp2.mul_assign(&a);

        assert_eq!(tmp1, tmp2);
    }

    for _ in 0..1000000 {
        // Ensure that r * (a + b + c) = r*a + r*b + r*c

        let r = Fr::random(&mut rng);
        let mut a = Fr::random(&mut rng);
        let mut b = Fr::random(&mut rng);
        let mut c = Fr::random(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);
        tmp1.mul_assign(&r);

        a.mul_assign(&r);
        b.mul_assign(&r);
        c.mul_assign(&r);

        a.add_assign(&b);
        a.add_assign(&c);

        assert_eq!(tmp1, a);
    }
}

#[test]
fn test_fr_squaring() {
    let a = Fr([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x73eda753299d7d47,
    ]);
    assert!(a.is_valid());
    assert_eq!(
        a.square(),
        Fr::from_repr(FrRepr([
            0xb8, 0x77, 0xe0, 0xbd, 0xe7, 0x98, 0xd6, 0xc0, 0xc2, 0x6e, 0xe7, 0x79, 0x05, 0x31,
            0x9a, 0xb7, 0x5f, 0x4e, 0xaf, 0xa9, 0xd0, 0xa8, 0x1d, 0xac, 0x97, 0x3e, 0xf2, 0x9b,
            0xc4, 0x29, 0xf6, 0x13,
        ]))
        .unwrap()
    );

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000000 {
        // Ensure that (a * a) = a^2
        let a = Fr::random(&mut rng);
        assert_eq!(a.square(), a * a);
    }
}

#[test]
fn test_fr_invert() {
    assert!(bool::from(Fr::zero().invert().is_none()));

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let one = Fr::one();

    for _ in 0..1000 {
        // Ensure that a * a^-1 = 1
        let mut a = Fr::random(&mut rng);
        let ainv = a.invert().unwrap();
        a.mul_assign(&ainv);
        assert_eq!(a, one);
    }
}

#[test]
fn test_fr_double() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure doubling a is equivalent to adding a to itself.
        let a = Fr::random(&mut rng);
        assert_eq!(a.double(), a + a);
    }
}

#[test]
fn test_fr_neg() {
    {
        let a = Fr::zero().neg();

        assert!(a.is_zero());
    }

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure (a - (-a)) = 0.
        let mut a = Fr::random(&mut rng);
        let b = a.neg();
        a.add_assign(&b);

        assert!(a.is_zero());
    }
}

#[test]
fn test_fr_pow() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for i in 0u64..1000 {
        // Exponentiate by various small numbers and ensure it consists with repeated
        // multiplication.
        let a = Fr::random(&mut rng);
        let target = a.pow_vartime(&[i]);
        let mut c = Fr::one();
        for _ in 0..i {
            c.mul_assign(&a);
        }
        assert_eq!(c, target);
    }

    use byteorder::ByteOrder;
    let mut char_limbs = [0; 4];
    byteorder::LittleEndian::read_u64_into(Fr::char().as_ref(), &mut char_limbs);

    for _ in 0..1000 {
        // Exponentiating by the modulus should have no effect in a prime field.
        let a = Fr::random(&mut rng);

        assert_eq!(a, a.pow_vartime(char_limbs));
    }
}

#[test]
fn test_fr_sqrt() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    assert_eq!(Fr::zero().sqrt().unwrap(), Fr::zero());

    for _ in 0..1000 {
        // Ensure sqrt(a^2) = a or -a
        let a = Fr::random(&mut rng);
        let nega = a.neg();
        let b = a.square();

        let b = b.sqrt().unwrap();

        assert!(a == b || nega == b);
    }

    for _ in 0..1000 {
        // Ensure sqrt(a)^2 = a for random a
        let a = Fr::random(&mut rng);

        let tmp = a.sqrt();
        if tmp.is_some().into() {
            assert_eq!(a, tmp.unwrap().square());
        }
    }
}

#[test]
fn test_fr_from_to_repr() {
    // r + 1 should not be in the field
    assert!(Fr::from_repr(FrRepr([
        0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd,
        0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7,
        0xed, 0x73,
    ]))
    .is_none());

    // r should not be in the field
    assert!(Fr::from_repr(Fr::char()).is_none());

    // Multiply some arbitrary representations to see if the result is as expected.
    let a = FrRepr([
        0x6a, 0x0c, 0x3c, 0xad, 0xa3, 0xe3, 0xeb, 0x25, 0x7c, 0x81, 0x2e, 0x09, 0x9d, 0xe3, 0x90,
        0x69, 0x8e, 0x65, 0xf5, 0x42, 0x0d, 0x90, 0x1f, 0x94, 0xe0, 0x71, 0x8a, 0xb3, 0x03, 0xa1,
        0xf8, 0x44,
    ]);
    let mut a_fr = Fr::from_repr(a).unwrap();
    let b = FrRepr([
        0x75, 0x24, 0x5e, 0x88, 0x54, 0x94, 0x4e, 0x26, 0x70, 0x83, 0x30, 0xb0, 0x6b, 0x74, 0xf7,
        0x46, 0xf9, 0x11, 0x74, 0x34, 0xf5, 0x3e, 0x68, 0x04, 0x92, 0x44, 0x8d, 0x20, 0x7f, 0x8d,
        0x83, 0x58,
    ]);
    let b_fr = Fr::from_repr(b).unwrap();
    let c = FrRepr([
        0x0d, 0x74, 0xfc, 0x3c, 0xb9, 0x9a, 0xa0, 0x48, 0x71, 0xa6, 0xc7, 0xbf, 0x0f, 0x60, 0xa6,
        0x03, 0x67, 0xd7, 0x01, 0x75, 0x01, 0x67, 0x85, 0x83, 0x12, 0x55, 0x74, 0x77, 0xda, 0xd6,
        0x61, 0x71,
    ]);
    a_fr.mul_assign(&b_fr);
    assert_eq!(a_fr.to_repr(), c);

    // Zero should be in the field.
    assert!(Fr::from_repr(FrRepr([0; 32])).unwrap().is_zero());

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Try to turn Fr elements into representations and back again, and compare.
        let a = Fr::random(&mut rng);
        let a_repr = a.to_repr();
        let b_repr = FrRepr::from(a);
        assert_eq!(a_repr, b_repr);
        let a_again = Fr::from_repr(a_repr).unwrap();

        assert_eq!(a, a_again);
    }
}

#[test]
fn test_fr_display() {
    assert_eq!(
        format!(
            "{}",
            Fr::from_repr(FrRepr([
                0xc7, 0xec, 0xb5, 0xa3, 0x46, 0xe7, 0xca, 0xc3, 0xee, 0x5a, 0x5b, 0x3f, 0xeb, 0xc8,
                0x5e, 0x18, 0x99, 0xdd, 0xb9, 0xe4, 0xff, 0x99, 0x44, 0x68, 0xaa, 0x8f, 0xb6, 0xaf,
                0xa7, 0xbb, 0xc9, 0x07,
            ]))
            .unwrap()
        ),
        "Fr(0x07c9bba7afb68faa684499ffe4b9dd99185ec8eb3f5b5aeec3cae746a3b5ecc7)".to_string()
    );
    assert_eq!(
        format!(
            "{}",
            Fr::from_repr(FrRepr([
                0x06, 0x81, 0x19, 0xff, 0x98, 0x12, 0xc7, 0x44, 0x6a, 0x9b, 0xf7, 0x7d, 0x81, 0x10,
                0xad, 0xb0, 0x2b, 0x13, 0x74, 0x2b, 0x0a, 0xa8, 0x34, 0xd0, 0x19, 0x07, 0xf5, 0x36,
                0x13, 0x9a, 0xcf, 0x41,
            ]))
            .unwrap()
        ),
        "Fr(0x41cf9a1336f50719d034a80a2b74132bb0ad10817df79b6a44c71298ff198106)".to_string()
    );
}

#[test]
fn test_fr_is_odd() {
    assert!(!Fr::from(0).is_odd());
    assert!(Fr::from(0).is_even());
    assert!(Fr::from(1).is_odd());
    assert!(!Fr::from(1).is_even());
    assert!(!Fr::from(324834872).is_odd());
    assert!(Fr::from(324834872).is_even());
    assert!(Fr::from(324834873).is_odd());
    assert!(!Fr::from(324834873).is_even());
}

#[test]
fn test_fr_num_bits() {
    assert_eq!(Fr::NUM_BITS, 255);
    assert_eq!(Fr::CAPACITY, 254);
}

#[test]
fn test_fr_root_of_unity() {
    assert_eq!(Fr::S, 32);
    assert_eq!(Fr::multiplicative_generator(), Fr::from(7));
    assert_eq!(
        Fr::multiplicative_generator().pow_vartime([
            0xfffe5bfeffffffffu64,
            0x9a1d80553bda402,
            0x299d7d483339d808,
            0x73eda753
        ]),
        Fr::root_of_unity()
    );
    assert_eq!(Fr::root_of_unity().pow_vartime([1u64 << Fr::S]), Fr::one());
    assert!(bool::from(Fr::multiplicative_generator().sqrt().is_none()));
}

#[test]
fn fr_field_tests() {
    crate::tests::field::random_field_tests::<Fr>();
    crate::tests::field::random_sqrt_tests::<Fr>();
    crate::tests::field::from_str_tests::<Fr>();
}

#[test]
fn fr_repr_tests() {
    crate::tests::repr::random_repr_tests::<Fr>();
}
