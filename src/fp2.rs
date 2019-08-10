//! This module implements arithmetic over the quadratic extension field Fp2.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::fp::Fp;

#[derive(Copy, Clone, Debug)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl ConstantTimeEq for Fp2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl Eq for Fp2 {}
impl PartialEq for Fp2 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConditionallySelectable for Fp2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp2 {
            c0: Fp::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

#[test]
fn test_conditional_selection() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
        c1: Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([13, 14, 15, 16, 17, 18]),
        c1: Fp::from_raw_unchecked([19, 20, 21, 22, 23, 24]),
    };

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
    fn is_equal(a: &Fp2, b: &Fp2) -> bool {
        let eq = a == b;
        let ct_eq = a.ct_eq(&b);

        assert_eq!(eq, ct_eq.unwrap_u8() == 1);

        eq
    }

    assert!(is_equal(
        &Fp2 {
            c0: Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
            c1: Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]),
        },
        &Fp2 {
            c0: Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
            c1: Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]),
        }
    ));

    assert!(!is_equal(
        &Fp2 {
            c0: Fp::from_raw_unchecked([2, 2, 3, 4, 5, 6]),
            c1: Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]),
        },
        &Fp2 {
            c0: Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
            c1: Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]),
        }
    ));

    assert!(!is_equal(
        &Fp2 {
            c0: Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
            c1: Fp::from_raw_unchecked([2, 8, 9, 10, 11, 12]),
        },
        &Fp2 {
            c0: Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
            c1: Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]),
        }
    ));
}
