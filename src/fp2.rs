//! This module implements arithmetic over the quadratic extension field Fp2.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

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

impl Default for Fp2 {
    fn default() -> Self {
        Fp2::zero()
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
    #[inline]
    pub const fn zero() -> Fp2 {
        Fp2 {
            c0: Fp::zero(),
            c1: Fp::zero(),
        }
    }

    #[inline]
    pub const fn one() -> Fp2 {
        Fp2 {
            c0: Fp::one(),
            c1: Fp::zero(),
        }
    }

    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero()
    }

    /// Returns whether or not this element is strictly lexicographically
    /// larger than its negation.
    #[inline]
    pub fn lexicographically_largest(&self) -> Choice {
        // If this element's c1 coefficient is lexicographically largest
        // then it is lexicographically largest. Otherwise, in the event
        // the c1 coefficient is zero and the c0 coefficient is
        // lexicographically largest, then this element is lexicographically
        // largest.

        self.c1.lexicographically_largest()
            | (self.c1.is_zero() & self.c0.lexicographically_largest())
    }

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

    pub fn sqrt(&self) -> CtOption<Self> {
        use crate::CtOptionExt;

        // Algorithm 9, https://eprint.iacr.org/2012/685.pdf
        // with constant time modifications.

        CtOption::new(Fp2::zero(), self.is_zero()).or_else(|| {
            // a1 = self^((p - 3) / 4)
            let a1 = self.pow_vartime(&[
                0xee7fbfffffffeaaa,
                0x7aaffffac54ffff,
                0xd9cc34a83dac3d89,
                0xd91dd2e13ce144af,
                0x92c6e9ed90d2eb35,
                0x680447a8e5ff9a6,
            ]);

            // alpha = a1^2 * self = self^((p - 3) / 2 + 1) = self^((p - 1) / 2)
            let alpha = a1.square() * self;

            // x0 = self^((p + 1) / 4)
            let x0 = a1 * self;

            // In the event that alpha = -1, the element is order p - 1 and so
            // we're just trying to get the square of an element of the subfield
            // Fp. This is given by x0 * u, since u = sqrt(-1). Since the element
            // x0 = a + bu has b = 0, the solution is therefore au.
            CtOption::new(
                Fp2 {
                    c0: -x0.c1,
                    c1: x0.c0,
                },
                alpha.ct_eq(&(&Fp2::one()).neg()),
            )
            // Otherwise, the correct solution is (1 + alpha)^((q - 1) // 2) * x0
            .or_else(|| {
                CtOption::new(
                    (alpha + Fp2::one()).pow_vartime(&[
                        0xdcff7fffffffd555,
                        0xf55ffff58a9ffff,
                        0xb39869507b587b12,
                        0xb23ba5c279c2895f,
                        0x258dd3db21a5d66b,
                        0xd0088f51cbff34d,
                    ]) * x0,
                    Choice::from(1),
                )
            })
            // Only return the result if it's really the square root (and so
            // self is actually quadratic nonresidue)
            .and_then(|sqrt| CtOption::new(sqrt, sqrt.square().ct_eq(self)))
        })
    }

    /// Computes the multiplicative inverse of this field
    /// element, returning None in the case that this element
    /// is zero.
    pub fn invert(&self) -> CtOption<Self> {
        // We wish to find the multiplicative inverse of a nonzero
        // element a + bu in Fp2. We leverage an identity
        //
        // (a + bu)(a - bu) = a^2 + b^2
        //
        // which holds because u^2 = -1. This can be rewritten as
        //
        // (a + bu)(a - bu)/(a^2 + b^2) = 1
        //
        // because a^2 + b^2 = 0 has no nonzero solutions for (a, b).
        // This gives that (a - bu)/(a^2 + b^2) is the inverse
        // of (a + bu). Importantly, this can be computing using
        // only a single inversion in Fp.

        (self.c0.square() + self.c1.square()).invert().map(|t| Fp2 {
            c0: self.c0 * t,
            c1: self.c1 * -t,
        })
    }

    /// Although this is labeled "vartime", it is only
    /// variable time with respect to the exponent. It
    /// is also not exposed in the public API.
    pub fn pow_vartime(&self, by: &[u64; 6]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res *= self;
                }
            }
        }
        res
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

#[test]
fn test_sqrt() {
    // a = 1488924004771393321054797166853618474668089414631333405711627789629391903630694737978065425271543178763948256226639*u + 784063022264861764559335808165825052288770346101304131934508881646553551234697082295473567906267937225174620141295
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0x2beed14627d7f9e9,
            0xb6614e06660e5dce,
            0x6c4cc7c2f91d42c,
            0x996d78474b7a63cc,
            0xebaebc4c820d574e,
            0x18865e12d93fd845,
        ]),
        c1: Fp::from_raw_unchecked([
            0x7d828664baf4f566,
            0xd17e663996ec7339,
            0x679ead55cb4078d0,
            0xfe3b2260e001ec28,
            0x305993d043d91b68,
            0x626f03c0489b72d,
        ]),
    };

    assert_eq!(a.sqrt().unwrap().square(), a);

    // b = 5, which is a generator of the p - 1 order
    // multiplicative subgroup
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0x6631000000105545,
            0x211400400eec000d,
            0x3fa7af30c820e316,
            0xc52a8b8d6387695d,
            0x9fb4e61d1e83eac5,
            0x5cb922afe84dc7,
        ]),
        c1: Fp::zero(),
    };

    assert_eq!(b.sqrt().unwrap().square(), b);

    // c = 25, which is a generator of the (p - 1) / 2 order
    // multiplicative subgroup
    let c = Fp2 {
        c0: Fp::from_raw_unchecked([
            0x44f600000051ffae,
            0x86b8014199480043,
            0xd7159952f1f3794a,
            0x755d6e3dfe1ffc12,
            0xd36cd6db5547e905,
            0x2f8c8ecbf1867bb,
        ]),
        c1: Fp::zero(),
    };

    assert_eq!(c.sqrt().unwrap().square(), c);

    // 2155129644831861015726826462986972654175647013268275306775721078997042729172900466542651176384766902407257452753362*u + 2796889544896299244102912275102369318775038861758288697415827248356648685135290329705805931514906495247464901062529
    // is nonsquare.
    assert!(bool::from(
        Fp2 {
            c0: Fp::from_raw_unchecked([
                0xc5fa1bc8fd00d7f6,
                0x3830ca454606003b,
                0x2b287f1104b102da,
                0xa7fb30f28230f23e,
                0x339cdb9ee953dbf0,
                0xd78ec51d989fc57
            ]),
            c1: Fp::from_raw_unchecked([
                0x27ec4898cf87f613,
                0x9de1394e1abb05a5,
                0x947f85dc170fc14,
                0x586fbc696b6114b7,
                0x2b3475a4077d7169,
                0x13e1c895cc4b6c22
            ])
        }
        .sqrt()
        .is_none()
    ));
}

#[test]
fn test_inversion() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0x1128ecad67549455,
            0x9e7a1cff3a4ea1a8,
            0xeb208d51e08bcf27,
            0xe98ad40811f5fc2b,
            0x736c3a59232d511d,
            0x10acd42d29cfcbb6,
        ]),
        c1: Fp::from_raw_unchecked([
            0xd328e37cc2f58d41,
            0x948df0858a605869,
            0x6032f9d56f93a573,
            0x2be483ef3fffdc87,
            0x30ef61f88f483c2a,
            0x1333f55a35725be0,
        ]),
    };

    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0x581a1333d4f48a6,
            0x58242f6ef0748500,
            0x292c955349e6da5,
            0xba37721ddd95fcd0,
            0x70d167903aa5dfc5,
            0x11895e118b58a9d5,
        ]),
        c1: Fp::from_raw_unchecked([
            0xeda09d2d7a85d17,
            0x8808e137a7d1a2cf,
            0x43ae2625c1ff21db,
            0xf85ac9fdf7a74c64,
            0x8fccdda5b8da9738,
            0x8e84f0cb32cd17d,
        ]),
    };

    assert_eq!(a.invert().unwrap(), b);

    assert!(Fp2::zero().invert().is_none().unwrap_u8() == 1);
}

#[test]
fn test_lexicographic_largest() {
    assert!(!bool::from(Fp2::zero().lexicographically_largest()));
    assert!(!bool::from(Fp2::one().lexicographically_largest()));
    assert!(bool::from(
        Fp2 {
            c0: Fp::from_raw_unchecked([
                0x1128ecad67549455,
                0x9e7a1cff3a4ea1a8,
                0xeb208d51e08bcf27,
                0xe98ad40811f5fc2b,
                0x736c3a59232d511d,
                0x10acd42d29cfcbb6,
            ]),
            c1: Fp::from_raw_unchecked([
                0xd328e37cc2f58d41,
                0x948df0858a605869,
                0x6032f9d56f93a573,
                0x2be483ef3fffdc87,
                0x30ef61f88f483c2a,
                0x1333f55a35725be0,
            ]),
        }
        .lexicographically_largest()
    ));
    assert!(!bool::from(
        Fp2 {
            c0: -Fp::from_raw_unchecked([
                0x1128ecad67549455,
                0x9e7a1cff3a4ea1a8,
                0xeb208d51e08bcf27,
                0xe98ad40811f5fc2b,
                0x736c3a59232d511d,
                0x10acd42d29cfcbb6,
            ]),
            c1: -Fp::from_raw_unchecked([
                0xd328e37cc2f58d41,
                0x948df0858a605869,
                0x6032f9d56f93a573,
                0x2be483ef3fffdc87,
                0x30ef61f88f483c2a,
                0x1333f55a35725be0,
            ]),
        }
        .lexicographically_largest()
    ));
    assert!(!bool::from(
        Fp2 {
            c0: Fp::from_raw_unchecked([
                0x1128ecad67549455,
                0x9e7a1cff3a4ea1a8,
                0xeb208d51e08bcf27,
                0xe98ad40811f5fc2b,
                0x736c3a59232d511d,
                0x10acd42d29cfcbb6,
            ]),
            c1: Fp::zero(),
        }
        .lexicographically_largest()
    ));
    assert!(bool::from(
        Fp2 {
            c0: -Fp::from_raw_unchecked([
                0x1128ecad67549455,
                0x9e7a1cff3a4ea1a8,
                0xeb208d51e08bcf27,
                0xe98ad40811f5fc2b,
                0x736c3a59232d511d,
                0x10acd42d29cfcbb6,
            ]),
            c1: Fp::zero(),
        }
        .lexicographically_largest()
    ));
}
