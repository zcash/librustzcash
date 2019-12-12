use crate::fp::*;
use crate::fp2::*;

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// This represents an element $c_0 + c_1 v + c_2 v^2$ of $\mathbb{F}_{p^6} = \mathbb{F}_{p^2} / v^3 - u - 1$.
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

impl From<Fp> for Fp6 {
    fn from(f: Fp) -> Fp6 {
        Fp6 {
            c0: Fp2::from(f),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }
}

impl From<Fp2> for Fp6 {
    fn from(f: Fp2) -> Fp6 {
        Fp6 {
            c0: f,
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }
}

impl PartialEq for Fp6 {
    fn eq(&self, other: &Fp6) -> bool {
        self.ct_eq(other).into()
    }
}

impl Copy for Fp6 {}
impl Clone for Fp6 {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl Default for Fp6 {
    fn default() -> Self {
        Fp6::zero()
    }
}

impl fmt::Debug for Fp6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} + ({:?})*v + ({:?})*v^2", self.c0, self.c1, self.c2)
    }
}

impl ConditionallySelectable for Fp6 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp6 {
            c0: Fp2::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp2::conditional_select(&a.c1, &b.c1, choice),
            c2: Fp2::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

impl ConstantTimeEq for Fp6 {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1) & self.c2.ct_eq(&other.c2)
    }
}

impl Fp6 {
    #[inline]
    pub fn zero() -> Self {
        Fp6 {
            c0: Fp2::zero(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    #[inline]
    pub fn one() -> Self {
        Fp6 {
            c0: Fp2::one(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    pub fn mul_by_1(&self, c1: &Fp2) -> Fp6 {
        let b_b = self.c1 * c1;

        let t1 = (self.c1 + self.c2) * c1 - b_b;
        let t1 = t1.mul_by_nonresidue();

        let t2 = (self.c0 + self.c1) * c1 - b_b;

        Fp6 {
            c0: t1,
            c1: t2,
            c2: b_b,
        }
    }

    pub fn mul_by_01(&self, c0: &Fp2, c1: &Fp2) -> Fp6 {
        let a_a = self.c0 * c0;
        let b_b = self.c1 * c1;

        let t1 = (self.c1 + self.c2) * c1 - b_b;
        let t1 = t1.mul_by_nonresidue() + a_a;

        let t2 = (c0 + c1) * (self.c0 + self.c1) - a_a - b_b;

        let t3 = (self.c0 + self.c2) * c0 - a_a + b_b;

        Fp6 {
            c0: t1,
            c1: t2,
            c2: t3,
        }
    }

    /// Multiply by quadratic nonresidue v.
    pub fn mul_by_nonresidue(&self) -> Self {
        // Given a + bv + cv^2, this produces
        //     av + bv^2 + cv^3
        // but because v^3 = u + 1, we have
        //     c(u + 1) + av + v^2

        Fp6 {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// Raises this element to p.
    #[inline(always)]
    pub fn frobenius_map(&self) -> Self {
        let c0 = self.c0.frobenius_map();
        let c1 = self.c1.frobenius_map();
        let c2 = self.c2.frobenius_map();

        // c1 = c1 * (u + 1)^((p - 1) / 3)
        let c1 = c1
            * Fp2 {
                c0: Fp::zero(),
                c1: Fp::from_raw_unchecked([
                    0xcd03c9e48671f071,
                    0x5dab22461fcda5d2,
                    0x587042afd3851b95,
                    0x8eb60ebe01bacb9e,
                    0x3f97d6e83d050d2,
                    0x18f0206554638741,
                ]),
            };

        // c2 = c2 * (u + 1)^((2p - 2) / 3)
        let c2 = c2
            * Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x890dc9e4867545c3,
                    0x2af322533285a5d5,
                    0x50880866309b7e2c,
                    0xa20d1b8c7e881024,
                    0x14e4f04fe2db9068,
                    0x14e56d3f1564853a,
                ]),
                c1: Fp::zero(),
            };

        Fp6 { c0, c1, c2 }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero() & self.c2.is_zero()
    }

    #[inline]
    pub fn square(&self) -> Self {
        let s0 = self.c0.square();
        let ab = self.c0 * self.c1;
        let s1 = ab + ab;
        let s2 = (self.c0 - self.c1 + self.c2).square();
        let bc = self.c1 * self.c2;
        let s3 = bc + bc;
        let s4 = self.c2.square();

        Fp6 {
            c0: s3.mul_by_nonresidue() + s0,
            c1: s4.mul_by_nonresidue() + s1,
            c2: s1 + s2 + s3 - s0 - s4,
        }
    }

    #[inline]
    pub fn invert(&self) -> CtOption<Self> {
        let c0 = (self.c1 * self.c2).mul_by_nonresidue();
        let c0 = self.c0.square() - c0;

        let c1 = self.c2.square().mul_by_nonresidue();
        let c1 = c1 - (self.c0 * self.c1);

        let c2 = self.c1.square();
        let c2 = c2 - (self.c0 * self.c2);

        let tmp = ((self.c1 * c2) + (self.c2 * c1)).mul_by_nonresidue();
        let tmp = tmp + (self.c0 * c0);

        tmp.invert().map(|t| Fp6 {
            c0: t * c0,
            c1: t * c1,
            c2: t * c2,
        })
    }
}

impl<'a, 'b> Mul<&'b Fp6> for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn mul(self, other: &'b Fp6) -> Self::Output {
        let aa = self.c0 * other.c0;
        let bb = self.c1 * other.c1;
        let cc = self.c2 * other.c2;

        let t1 = other.c1 + other.c2;
        let tmp = self.c1 + self.c2;
        let t1 = t1 * tmp;
        let t1 = t1 - bb;
        let t1 = t1 - cc;
        let t1 = t1.mul_by_nonresidue();
        let t1 = t1 + aa;

        let t3 = other.c0 + other.c2;
        let tmp = self.c0 + self.c2;
        let t3 = t3 * tmp;
        let t3 = t3 - aa;
        let t3 = t3 + bb;
        let t3 = t3 - cc;

        let t2 = other.c0 + other.c1;
        let tmp = self.c0 + self.c1;
        let t2 = t2 * tmp;
        let t2 = t2 - aa;
        let t2 = t2 - bb;
        let cc = cc.mul_by_nonresidue();
        let t2 = t2 + cc;

        Fp6 {
            c0: t1,
            c1: t2,
            c2: t3,
        }
    }
}

impl<'a, 'b> Add<&'b Fp6> for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn add(self, rhs: &'b Fp6) -> Self::Output {
        Fp6 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl<'a> Neg for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn neg(self) -> Self::Output {
        Fp6 {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }
}

impl Neg for Fp6 {
    type Output = Fp6;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Fp6> for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn sub(self, rhs: &'b Fp6) -> Self::Output {
        Fp6 {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
            c2: self.c2 - rhs.c2,
        }
    }
}

impl_binops_additive!(Fp6, Fp6);
impl_binops_multiplicative!(Fp6, Fp6);

#[test]
fn test_arithmetic() {
    use crate::fp::*;

    let a = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x47f9cb98b1b82d58,
                0x5fe911eba3aa1d9d,
                0x96bf1b5f4dd81db3,
                0x8100d27cc9259f5b,
                0xafa20b9674640eab,
                0x9bbcea7d8d9497d,
            ]),
            c1: Fp::from_raw_unchecked([
                0x303cb98b1662daa,
                0xd93110aa0a621d5a,
                0xbfa9820c5be4a468,
                0xba3643ecb05a348,
                0xdc3534bb1f1c25a6,
                0x6c305bb19c0e1c1,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x46f9cb98b162d858,
                0xbe9109cf7aa1d57,
                0xc791bc55fece41d2,
                0xf84c57704e385ec2,
                0xcb49c1d9c010e60f,
                0xacdb8e158bfe3c8,
            ]),
            c1: Fp::from_raw_unchecked([
                0x8aefcb98b15f8306,
                0x3ea1108fe4f21d54,
                0xcf79f69fa1b7df3b,
                0xe4f54aa1d16b1a3c,
                0xba5e4ef86105a679,
                0xed86c0797bee5cf,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xcee5cb98b15c2db4,
                0x71591082d23a1d51,
                0xd76230e944a17ca4,
                0xd19e3dd3549dd5b6,
                0xa972dc1701fa66e3,
                0x12e31f2dd6bde7d6,
            ]),
            c1: Fp::from_raw_unchecked([
                0xad2acb98b1732d9d,
                0x2cfd10dd06961d64,
                0x7396b86c6ef24e8,
                0xbd76e2fdb1bfc820,
                0x6afea7f6de94d0d5,
                0x10994b0c5744c040,
            ]),
        },
    };

    let b = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xf120cb98b16fd84b,
                0x5fb510cff3de1d61,
                0xf21a5d069d8c251,
                0xaa1fd62f34f2839a,
                0x5a1335157f89913f,
                0x14a3fe329643c247,
            ]),
            c1: Fp::from_raw_unchecked([
                0x3516cb98b16c82f9,
                0x926d10c2e1261d5f,
                0x1709e01a0cc25fba,
                0x96c8c960b8253f14,
                0x4927c234207e51a9,
                0x18aeb158d542c44e,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xbf0dcb98b16982fc,
                0xa67910b71d1a1d5c,
                0xb7c147c2b8fb06ff,
                0x1efa710d47d2e7ce,
                0xed20a79c7e27653c,
                0x2b85294dac1dfba,
            ]),
            c1: Fp::from_raw_unchecked([
                0x9d52cb98b18082e5,
                0x621d111151761d6f,
                0xe79882603b48af43,
                0xad31637a4f4da37,
                0xaeac737c5ac1cf2e,
                0x6e7e735b48b824,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xe148cb98b17d2d93,
                0x94d511043ebe1d6c,
                0xef80bca9de324cac,
                0xf77c0969282795b1,
                0x9dc1009afbb68f97,
                0x47931999a47ba2b,
            ]),
            c1: Fp::from_raw_unchecked([
                0x253ecb98b179d841,
                0xc78d10f72c061d6a,
                0xf768f6f3811bea15,
                0xe424fc9aab5a512b,
                0x8cd58db99cab5001,
                0x883e4bfd946bc32,
            ]),
        },
    };

    let c = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x6934cb98b17682ef,
                0xfa4510ea194e1d67,
                0xff51313d2405877e,
                0xd0cdefcc2e8d0ca5,
                0x7bea1ad83da0106b,
                0xc8e97e61845be39,
            ]),
            c1: Fp::from_raw_unchecked([
                0x4779cb98b18d82d8,
                0xb5e911444daa1d7a,
                0x2f286bdaa6532fc2,
                0xbca694f68baeff0f,
                0x3d75e6b81a3a7a5d,
                0xa44c3c498cc96a3,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x8b6fcb98b18a2d86,
                0xe8a111373af21d77,
                0x3710a624493ccd2b,
                0xa94f88280ee1ba89,
                0x2c8a73d6bb2f3ac7,
                0xe4f76ead7cb98aa,
            ]),
            c1: Fp::from_raw_unchecked([
                0xcf65cb98b186d834,
                0x1b59112a283a1d74,
                0x3ef8e06dec266a95,
                0x95f87b5992147603,
                0x1b9f00f55c23fb31,
                0x125a2a1116ca9ab1,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x135bcb98b18382e2,
                0x4e11111d15821d72,
                0x46e11ab78f1007fe,
                0x82a16e8b1547317d,
                0xab38e13fd18bb9b,
                0x1664dd3755c99cb8,
            ]),
            c1: Fp::from_raw_unchecked([
                0xce65cb98b1318334,
                0xc7590fdb7c3a1d2e,
                0x6fcb81649d1c8eb3,
                0xd44004d1727356a,
                0x3746b738a7d0d296,
                0x136c144a96b134fc,
            ]),
        },
    };

    assert_eq!(a.square(), &a * &a);
    assert_eq!(b.square(), &b * &b);
    assert_eq!(c.square(), &c * &c);

    assert_eq!(
        (a + b) * c.square(),
        &(&(&c * &c) * &a) + &(&(&c * &c) * &b)
    );

    assert_eq!(
        &a.invert().unwrap() * &b.invert().unwrap(),
        (&a * &b).invert().unwrap()
    );
    assert_eq!(&a.invert().unwrap() * &a, Fp6::one());
}
