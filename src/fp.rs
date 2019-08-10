//! This module provides an implementation of the BLS12-381 base field `GF(p)`
//! where `p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// The internal representation of this type is six 64-bit unsigned
// integers in little-endian order. `Fp` values are always in
// Montgomery form; i.e., Scalar(a) = aR mod p, with R = 2^384.
#[derive(Copy, Clone, Debug)]
pub struct Fp([u64; 6]);

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
            & self.0[4].ct_eq(&other.0[4])
            & self.0[5].ct_eq(&other.0[5])
    }
}

impl Eq for Fp {}
impl PartialEq for Fp {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
            u64::conditional_select(&a.0[5], &b.0[5], choice),
        ])
    }
}

#[test]
fn test_conditional_selection() {
    let a = Fp([1, 2, 3, 4, 5, 6]);
    let b = Fp([7, 8, 9, 10, 11, 12]);

    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(0u8)),
        a
    );
    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(1u8)),
        b
    );
}

#[test]
fn test_equality() {
    fn is_equal(a: &Fp, b: &Fp) -> bool {
        let eq = a == b;
        let ct_eq = a.ct_eq(&b);

        assert_eq!(eq, ct_eq.unwrap_u8() == 1);

        eq
    }

    assert!(is_equal(&Fp([1, 2, 3, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));

    assert!(!is_equal(&Fp([7, 2, 3, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 7, 3, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 7, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 3, 7, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 3, 4, 7, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 3, 4, 5, 7]), &Fp([1, 2, 3, 4, 5, 6])));
}
