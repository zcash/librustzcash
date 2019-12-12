use crate::fp::*;
use crate::fp2::*;
use crate::fp6::*;

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// This represents an element $c_0 + c_1 w$ of $\mathbb{F}_{p^12} = \mathbb{F}_{p^6} / w^2 - v$.
pub struct Fp12 {
    pub c0: Fp6,
    pub c1: Fp6,
}

impl From<Fp> for Fp12 {
    fn from(f: Fp) -> Fp12 {
        Fp12 {
            c0: Fp6::from(f),
            c1: Fp6::zero(),
        }
    }
}

impl From<Fp2> for Fp12 {
    fn from(f: Fp2) -> Fp12 {
        Fp12 {
            c0: Fp6::from(f),
            c1: Fp6::zero(),
        }
    }
}

impl From<Fp6> for Fp12 {
    fn from(f: Fp6) -> Fp12 {
        Fp12 {
            c0: f,
            c1: Fp6::zero(),
        }
    }
}

impl PartialEq for Fp12 {
    fn eq(&self, other: &Fp12) -> bool {
        self.ct_eq(other).into()
    }
}

impl Copy for Fp12 {}
impl Clone for Fp12 {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl Default for Fp12 {
    fn default() -> Self {
        Fp12::zero()
    }
}

impl fmt::Debug for Fp12 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} + ({:?})*w", self.c0, self.c1)
    }
}

impl ConditionallySelectable for Fp12 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp12 {
            c0: Fp6::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp6::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

impl ConstantTimeEq for Fp12 {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl Fp12 {
    #[inline]
    pub fn zero() -> Self {
        Fp12 {
            c0: Fp6::zero(),
            c1: Fp6::zero(),
        }
    }

    #[inline]
    pub fn one() -> Self {
        Fp12 {
            c0: Fp6::one(),
            c1: Fp6::zero(),
        }
    }

    pub fn mul_by_014(&self, c0: &Fp2, c1: &Fp2, c4: &Fp2) -> Fp12 {
        let aa = self.c0.mul_by_01(c0, c1);
        let bb = self.c1.mul_by_1(c4);
        let o = c1 + c4;
        let c1 = self.c1 + self.c0;
        let c1 = c1.mul_by_01(c0, &o);
        let c1 = c1 - aa - bb;
        let c0 = bb;
        let c0 = c0.mul_by_nonresidue();
        let c0 = c0 + aa;

        Fp12 { c0, c1 }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero()
    }

    #[inline(always)]
    pub fn conjugate(&self) -> Self {
        Fp12 {
            c0: self.c0,
            c1: -self.c1,
        }
    }

    /// Raises this element to p.
    #[inline(always)]
    pub fn frobenius_map(&self) -> Self {
        let c0 = self.c0.frobenius_map();
        let c1 = self.c1.frobenius_map();

        // c1 = c1 * (u + 1)^((p - 1) / 6)
        let c1 = c1
            * Fp6::from(Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x7089552b319d465,
                    0xc6695f92b50a8313,
                    0x97e83cccd117228f,
                    0xa35baecab2dc29ee,
                    0x1ce393ea5daace4d,
                    0x8f2220fb0fb66eb,
                ]),
                c1: Fp::from_raw_unchecked([
                    0xb2f66aad4ce5d646,
                    0x5842a06bfc497cec,
                    0xcf4895d42599d394,
                    0xc11b9cba40a8e8d0,
                    0x2e3813cbe5a0de89,
                    0x110eefda88847faf,
                ]),
            });

        Fp12 { c0, c1 }
    }

    #[inline]
    pub fn square(&self) -> Self {
        let ab = self.c0 * self.c1;
        let c0c1 = self.c0 + self.c1;
        let c0 = self.c1.mul_by_nonresidue();
        let c0 = c0 + self.c0;
        let c0 = c0 * c0c1;
        let c0 = c0 - ab;
        let c1 = ab + ab;
        let c0 = c0 - ab.mul_by_nonresidue();

        Fp12 { c0, c1 }
    }

    pub fn invert(&self) -> CtOption<Self> {
        (self.c0.square() - self.c1.square().mul_by_nonresidue())
            .invert()
            .map(|t| Fp12 {
                c0: self.c0 * t,
                c1: self.c1 * -t,
            })
    }
}

impl<'a, 'b> Mul<&'b Fp12> for &'a Fp12 {
    type Output = Fp12;

    #[inline]
    fn mul(self, other: &'b Fp12) -> Self::Output {
        let aa = self.c0 * other.c0;
        let bb = self.c1 * other.c1;
        let o = other.c0 + other.c1;
        let c1 = self.c1 + self.c0;
        let c1 = c1 * o;
        let c1 = c1 - aa;
        let c1 = c1 - bb;
        let c0 = bb.mul_by_nonresidue();
        let c0 = c0 + aa;

        Fp12 { c0, c1 }
    }
}

impl<'a, 'b> Add<&'b Fp12> for &'a Fp12 {
    type Output = Fp12;

    #[inline]
    fn add(self, rhs: &'b Fp12) -> Self::Output {
        Fp12 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl<'a> Neg for &'a Fp12 {
    type Output = Fp12;

    #[inline]
    fn neg(self) -> Self::Output {
        Fp12 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

impl Neg for Fp12 {
    type Output = Fp12;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Fp12> for &'a Fp12 {
    type Output = Fp12;

    #[inline]
    fn sub(self, rhs: &'b Fp12) -> Self::Output {
        Fp12 {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}

impl_binops_additive!(Fp12, Fp12);
impl_binops_multiplicative!(Fp12, Fp12);

#[test]
fn test_arithmetic() {
    use crate::fp::*;
    use crate::fp2::*;

    let a = Fp12 {
        c0: Fp6 {
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
        },
        c1: Fp6 {
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
        },
    };

    let b = Fp12 {
        c0: Fp6 {
            c0: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x47f9cb98b1b82d58,
                    0x5fe911eba3aa1d9d,
                    0x96bf1b5f4dd81db3,
                    0x8100d272c9259f5b,
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
                    0xacdb8e158bfe348,
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
        },
        c1: Fp6 {
            c0: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x47f9cb98b1b82d58,
                    0x5fe911eba3aa1d9d,
                    0x96bf1b5f4dd21db3,
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
                    0xcf79f69fa117df3b,
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
        },
    };

    let c = Fp12 {
        c0: Fp6 {
            c0: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x47f9cb9871b82d58,
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
                    0x7791bc55fece41d2,
                    0xf84c57704e385ec2,
                    0xcb49c1d9c010e60f,
                    0xacdb8e158bfe3c8,
                ]),
                c1: Fp::from_raw_unchecked([
                    0x8aefcb98b15f8306,
                    0x3ea1108fe4f21d54,
                    0xcf79f69fa1b7df3b,
                    0xe4f54aa1d16b133c,
                    0xba5e4ef86105a679,
                    0xed86c0797bee5cf,
                ]),
            },
            c2: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xcee5cb98b15c2db4,
                    0x71591082d23a1d51,
                    0xd76240e944a17ca4,
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
                    0x10994b0c1744c040,
                ]),
            },
        },
        c1: Fp6 {
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
                    0xcb49c1d3c010e60f,
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
                    0x10994b0c57441040,
                ]),
            },
        },
    };

    // because a and b and c are similar to each other and
    // I was lazy, this is just some arbitrary way to make
    // them a little more different
    let a = &a.square().invert().unwrap().square() + &c;
    let b = &b.square().invert().unwrap().square() + &a;
    let c = &c.square().invert().unwrap().square() + &b;

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
    assert_eq!(&a.invert().unwrap() * &a, Fp12::one());

    assert!(a != a.frobenius_map());
    assert_eq!(
        a,
        a.frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
    );
}
