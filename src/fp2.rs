//! This module implements arithmetic over the quadratic extension field Fp2.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::fp::Fp;

#[derive(Copy, Clone)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl fmt::Debug for Fp2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} + {:?}*u", self.c0, self.c1)
    }
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

impl<'a> Neg for &'a Fp2 {
    type Output = Fp2;

    #[inline]
    fn neg(self) -> Fp2 {
        self.neg()
    }
}

impl Neg for Fp2 {
    type Output = Fp2;

    #[inline]
    fn neg(self) -> Fp2 {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Fp2> for &'a Fp2 {
    type Output = Fp2;

    #[inline]
    fn sub(self, rhs: &'b Fp2) -> Fp2 {
        self.sub(rhs)
    }
}

impl<'a, 'b> Add<&'b Fp2> for &'a Fp2 {
    type Output = Fp2;

    #[inline]
    fn add(self, rhs: &'b Fp2) -> Fp2 {
        self.add(rhs)
    }
}

impl<'a, 'b> Mul<&'b Fp2> for &'a Fp2 {
    type Output = Fp2;

    #[inline]
    fn mul(self, rhs: &'b Fp2) -> Fp2 {
        self.mul(rhs)
    }
}

impl_binops_additive!(Fp2, Fp2);
impl_binops_multiplicative!(Fp2, Fp2);

impl Fp2 {
    pub const fn square(&self) -> Fp2 {
        // Complex squaring:
        //
        // v0  = c0 * c1
        // c0' = (c0 + c1) * (c0 + \beta*c1) - v0 - \beta * v0
        // c1' = 2 * v0
        //
        // In BLS12-381's F_{p^2}, our \beta is -1 so we
        // can modify this formula:
        //
        // c0' = (c0 + c1) * (c0 - c1)
        // c1' = 2 * c0 * c1

        let a = (&self.c0).add(&self.c1);
        let b = (&self.c0).sub(&self.c1);
        let c = (&self.c0).add(&self.c0);

        Fp2 {
            c0: (&a).mul(&b),
            c1: (&c).mul(&self.c1),
        }
    }

    pub const fn mul(&self, rhs: &Fp2) -> Fp2 {
        // Karatsuba multiplication:
        //
        // v0  = a0 * b0
        // v1  = a1 * b1
        // c0 = v0 + \beta * v1
        // c1 = (a0 + a1) * (b0 + b1) - v0 - v1
        //
        // In BLS12-381's F_{p^2}, our \beta is -1 so we
        // can modify this formula. (Also, since we always
        // subtract v1, we can compute v1 = -a1 * b1.)
        //
        // v0  = a0 * b0
        // v1  = (-a1) * b1
        // c0 = v0 + v1
        // c1 = (a0 + a1) * (b0 + b1) - v0 + v1

        let v0 = (&self.c0).mul(&rhs.c0);
        let v1 = (&(&self.c1).neg()).mul(&rhs.c1);
        let c0 = (&v0).add(&v1);
        let c1 = (&(&self.c0).add(&self.c1)).mul(&(&rhs.c0).add(&rhs.c1));
        let c1 = (&c1).sub(&v0);
        let c1 = (&c1).add(&v1);

        Fp2 { c0, c1 }
    }

    pub const fn add(&self, rhs: &Fp2) -> Fp2 {
        Fp2 {
            c0: (&self.c0).add(&rhs.c0),
            c1: (&self.c1).add(&rhs.c1),
        }
    }

    pub const fn sub(&self, rhs: &Fp2) -> Fp2 {
        Fp2 {
            c0: (&self.c0).sub(&rhs.c0),
            c1: (&self.c1).sub(&rhs.c1),
        }
    }

    pub const fn neg(&self) -> Fp2 {
        Fp2 {
            c0: (&self.c0).neg(),
            c1: (&self.c1).neg(),
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

#[test]
fn test_squaring() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xc9a2183163ee70d4,
            0xbc3770a7196b5c91,
            0xa247f8c1304c5f44,
            0xb01fc2a3726c80b5,
            0xe1d293e5bbd919c9,
            0x4b78e80020ef2ca,
        ]),
        c1: Fp::from_raw_unchecked([
            0x952ea4460462618f,
            0x238d5eddf025c62f,
            0xf6c94b012ea92e72,
            0x3ce24eac1c93808,
            0x55950f945da483c,
            0x10a768d0df4eabc,
        ]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa1e09175a4d2c1fe,
            0x8b33acfc204eff12,
            0xe24415a11b456e42,
            0x61d996b1b6ee1936,
            0x1164dbe8667c853c,
            0x788557acc7d9c79,
        ]),
        c1: Fp::from_raw_unchecked([
            0xda6a87cc6f48fa36,
            0xfc7b488277c1903,
            0x9445ac4adc448187,
            0x2616d5bc9099209,
            0xdbed46772db58d48,
            0x11b94d5076c7b7b1,
        ]),
    };

    assert_eq!(a.square(), b);
}

#[test]
fn test_multiplication() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xc9a2183163ee70d4,
            0xbc3770a7196b5c91,
            0xa247f8c1304c5f44,
            0xb01fc2a3726c80b5,
            0xe1d293e5bbd919c9,
            0x4b78e80020ef2ca,
        ]),
        c1: Fp::from_raw_unchecked([
            0x952ea4460462618f,
            0x238d5eddf025c62f,
            0xf6c94b012ea92e72,
            0x3ce24eac1c93808,
            0x55950f945da483c,
            0x10a768d0df4eabc,
        ]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa1e09175a4d2c1fe,
            0x8b33acfc204eff12,
            0xe24415a11b456e42,
            0x61d996b1b6ee1936,
            0x1164dbe8667c853c,
            0x788557acc7d9c79,
        ]),
        c1: Fp::from_raw_unchecked([
            0xda6a87cc6f48fa36,
            0xfc7b488277c1903,
            0x9445ac4adc448187,
            0x2616d5bc9099209,
            0xdbed46772db58d48,
            0x11b94d5076c7b7b1,
        ]),
    };
    let c = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xf597483e27b4e0f7,
            0x610fbadf811dae5f,
            0x8432af917714327a,
            0x6a9a9603cf88f09e,
            0xf05a7bf8bad0eb01,
            0x9549131c003ffae,
        ]),
        c1: Fp::from_raw_unchecked([
            0x963b02d0f93d37cd,
            0xc95ce1cdb30a73d4,
            0x308725fa3126f9b8,
            0x56da3c167fab0d50,
            0x6b5086b5f4b6d6af,
            0x9c39f062f18e9f2,
        ]),
    };

    assert_eq!(a * b, c);
}

#[test]
fn test_addition() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xc9a2183163ee70d4,
            0xbc3770a7196b5c91,
            0xa247f8c1304c5f44,
            0xb01fc2a3726c80b5,
            0xe1d293e5bbd919c9,
            0x4b78e80020ef2ca,
        ]),
        c1: Fp::from_raw_unchecked([
            0x952ea4460462618f,
            0x238d5eddf025c62f,
            0xf6c94b012ea92e72,
            0x3ce24eac1c93808,
            0x55950f945da483c,
            0x10a768d0df4eabc,
        ]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa1e09175a4d2c1fe,
            0x8b33acfc204eff12,
            0xe24415a11b456e42,
            0x61d996b1b6ee1936,
            0x1164dbe8667c853c,
            0x788557acc7d9c79,
        ]),
        c1: Fp::from_raw_unchecked([
            0xda6a87cc6f48fa36,
            0xfc7b488277c1903,
            0x9445ac4adc448187,
            0x2616d5bc9099209,
            0xdbed46772db58d48,
            0x11b94d5076c7b7b1,
        ]),
    };
    let c = Fp2 {
        c0: Fp::from_raw_unchecked([
            0x6b82a9a708c132d2,
            0x476b1da339ba5ba4,
            0x848c0e624b91cd87,
            0x11f95955295a99ec,
            0xf3376fce22559f06,
            0xc3fe3face8c8f43,
        ]),
        c1: Fp::from_raw_unchecked([
            0x6f992c1273ab5bc5,
            0x3355136617a1df33,
            0x8b0ef74c0aedaff9,
            0x62f92468ad2ca12,
            0xe1469770738fd584,
            0x12c3c3dd84bca26d,
        ]),
    };

    assert_eq!(a + b, c);
}

#[test]
fn test_subtraction() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xc9a2183163ee70d4,
            0xbc3770a7196b5c91,
            0xa247f8c1304c5f44,
            0xb01fc2a3726c80b5,
            0xe1d293e5bbd919c9,
            0x4b78e80020ef2ca,
        ]),
        c1: Fp::from_raw_unchecked([
            0x952ea4460462618f,
            0x238d5eddf025c62f,
            0xf6c94b012ea92e72,
            0x3ce24eac1c93808,
            0x55950f945da483c,
            0x10a768d0df4eabc,
        ]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa1e09175a4d2c1fe,
            0x8b33acfc204eff12,
            0xe24415a11b456e42,
            0x61d996b1b6ee1936,
            0x1164dbe8667c853c,
            0x788557acc7d9c79,
        ]),
        c1: Fp::from_raw_unchecked([
            0xda6a87cc6f48fa36,
            0xfc7b488277c1903,
            0x9445ac4adc448187,
            0x2616d5bc9099209,
            0xdbed46772db58d48,
            0x11b94d5076c7b7b1,
        ]),
    };
    let c = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xe1c086bbbf1b5981,
            0x4fafc3a9aa705d7e,
            0x2734b5c10bb7e726,
            0xb2bd7776af037a3e,
            0x1b895fb398a84164,
            0x17304aef6f113cec,
        ]),
        c1: Fp::from_raw_unchecked([
            0x74c31c7995191204,
            0x3271aa5479fdad2b,
            0xc9b471574915a30f,
            0x65e40313ec44b8be,
            0x7487b2385b7067cb,
            0x9523b26d0ad19a4,
        ]),
    };

    assert_eq!(a - b, c);
}

#[test]
fn test_negation() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xc9a2183163ee70d4,
            0xbc3770a7196b5c91,
            0xa247f8c1304c5f44,
            0xb01fc2a3726c80b5,
            0xe1d293e5bbd919c9,
            0x4b78e80020ef2ca,
        ]),
        c1: Fp::from_raw_unchecked([
            0x952ea4460462618f,
            0x238d5eddf025c62f,
            0xf6c94b012ea92e72,
            0x3ce24eac1c93808,
            0x55950f945da483c,
            0x10a768d0df4eabc,
        ]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xf05ce7ce9c1139d7,
            0x62748f5797e8a36d,
            0xc4e8d9dfc66496df,
            0xb45788e181189209,
            0x694913d08772930d,
            0x1549836a3770f3cf,
        ]),
        c1: Fp::from_raw_unchecked([
            0x24d05bb9fb9d491c,
            0xfb1ea120c12e39d0,
            0x7067879fc807c7b1,
            0x60a9269a31bbdab6,
            0x45c256bcfd71649b,
            0x18f69b5d2b8afbde,
        ]),
    };

    assert_eq!(-a, b);
}
