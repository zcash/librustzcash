//! This module provides an implementation of the $\mathbb{G}_2$ group of BLS12-381.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::fp::Fp;
use crate::fp2::Fp2;
use crate::Scalar;

/// This is an element of $\mathbb{G}_2$ represented in the affine coordinate space.
/// It is ideal to keep elements in this representation to reduce memory usage and
/// improve performance through the use of mixed curve model arithmetic.
///
/// Values of `G2Affine` are guaranteed to be in the $q$-order subgroup unless an
/// "unchecked" API was misused.
#[derive(Copy, Clone, Debug)]
pub struct G2Affine {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
    infinity: Choice,
}

impl Default for G2Affine {
    fn default() -> G2Affine {
        G2Affine::identity()
    }
}

impl<'a> From<&'a G2Projective> for G2Affine {
    fn from(p: &'a G2Projective) -> G2Affine {
        let zinv = p.z.invert().unwrap_or(Fp2::zero());
        let zinv2 = zinv.square();
        let x = p.x * zinv2;
        let zinv3 = zinv2 * zinv;
        let y = p.y * zinv3;

        let tmp = G2Affine {
            x,
            y,
            infinity: Choice::from(0u8),
        };

        G2Affine::conditional_select(&tmp, &G2Affine::identity(), zinv.is_zero())
    }
}

impl From<G2Projective> for G2Affine {
    fn from(p: G2Projective) -> G2Affine {
        G2Affine::from(&p)
    }
}

impl ConstantTimeEq for G2Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        // The only cases in which two points are equal are
        // 1. infinity is set on both
        // 2. infinity is not set on both, and their coordinates are equal

        (self.infinity & other.infinity)
            | ((!self.infinity)
                & (!other.infinity)
                & self.x.ct_eq(&other.x)
                & self.y.ct_eq(&other.y))
    }
}

impl ConditionallySelectable for G2Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G2Affine {
            x: Fp2::conditional_select(&a.x, &b.x, choice),
            y: Fp2::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl Eq for G2Affine {}
impl PartialEq for G2Affine {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G2Affine {
    type Output = G2Affine;

    #[inline]
    fn neg(self) -> G2Affine {
        G2Affine {
            x: self.x,
            y: Fp2::conditional_select(&-self.y, &Fp2::one(), self.infinity),
            infinity: self.infinity,
        }
    }
}

impl Neg for G2Affine {
    type Output = G2Affine;

    #[inline]
    fn neg(self) -> G2Affine {
        -&self
    }
}

impl<'a, 'b> Add<&'b G2Projective> for &'a G2Affine {
    type Output = G2Projective;

    #[inline]
    fn add(self, rhs: &'b G2Projective) -> G2Projective {
        rhs.add_mixed(self)
    }
}

impl<'a, 'b> Add<&'b G2Affine> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn add(self, rhs: &'b G2Affine) -> G2Projective {
        self.add_mixed(rhs)
    }
}

impl<'a, 'b> Sub<&'b G2Projective> for &'a G2Affine {
    type Output = G2Projective;

    #[inline]
    fn sub(self, rhs: &'b G2Projective) -> G2Projective {
        self + (-rhs)
    }
}

impl<'a, 'b> Sub<&'b G2Affine> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn sub(self, rhs: &'b G2Affine) -> G2Projective {
        self + (-rhs)
    }
}

impl_binops_additive!(G2Projective, G2Affine);
impl_binops_additive_specify_output!(G2Affine, G2Projective, G2Projective);

const B: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0xaa27_0000_000c_fff3,
        0x53cc_0032_fc34_000a,
        0x478f_e97a_6b0a_807f,
        0xb1d3_7ebe_e6ba_24d7,
        0x8ec9_733b_bf78_ab2f,
        0x09d6_4551_3d83_de7e,
    ]),
    c1: Fp::from_raw_unchecked([
        0xaa27_0000_000c_fff3,
        0x53cc_0032_fc34_000a,
        0x478f_e97a_6b0a_807f,
        0xb1d3_7ebe_e6ba_24d7,
        0x8ec9_733b_bf78_ab2f,
        0x09d6_4551_3d83_de7e,
    ]),
};

impl G2Affine {
    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> G2Affine {
        G2Affine {
            x: Fp2::zero(),
            y: Fp2::one(),
            infinity: Choice::from(1u8),
        }
    }

    /// Returns a fixed generator of the group. See [`notes::design`](notes/design/index.html#fixed-generators)
    /// for how this generator is chosen.
    pub fn generator() -> G2Affine {
        G2Affine {
            x: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xf5f2_8fa2_0294_0a10,
                    0xb3f5_fb26_87b4_961a,
                    0xa1a8_93b5_3e2a_e580,
                    0x9894_999d_1a3c_aee9,
                    0x6f67_b763_1863_366b,
                    0x0581_9192_4350_bcd7,
                ]),
                c1: Fp::from_raw_unchecked([
                    0xa5a9_c075_9e23_f606,
                    0xaaa0_c59d_bccd_60c3,
                    0x3bb1_7e18_e286_7806,
                    0x1b1a_b6cc_8541_b367,
                    0xc2b6_ed0e_f215_8547,
                    0x1192_2a09_7360_edf3,
                ]),
            },
            y: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x4c73_0af8_6049_4c4a,
                    0x597c_fa1f_5e36_9c5a,
                    0xe7e6_856c_aa0a_635a,
                    0xbbef_b5e9_6e0d_495f,
                    0x07d3_a975_f0ef_25a2,
                    0x0083_fd8e_7e80_dae5,
                ]),
                c1: Fp::from_raw_unchecked([
                    0xadc0_fc92_df64_b05d,
                    0x18aa_270a_2b14_61dc,
                    0x86ad_ac6a_3be4_eba0,
                    0x7949_5c4e_c93d_a33a,
                    0xe717_5850_a43c_caed,
                    0x0b2b_c2a1_63de_1bf2,
                ]),
            },
            infinity: Choice::from(0u8),
        }
    }

    /// Serializes this element into compressed form. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    pub fn to_compressed(&self) -> [u8; 96] {
        // Strictly speaking, self.x is zero already when self.infinity is true, but
        // to guard against implementation mistakes we do not assume this.
        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), self.infinity);

        let mut res = [0; 96];

        (&mut res[0..48]).copy_from_slice(&x.c1.to_bytes()[..]);
        (&mut res[48..96]).copy_from_slice(&x.c0.to_bytes()[..]);

        // This point is in compressed form, so we set the most significant bit.
        res[0] |= 1u8 << 7;

        // Is this point at infinity? If so, set the second-most significant bit.
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), self.infinity);

        // Is the y-coordinate the lexicographically largest of the two associated with the
        // x-coordinate? If so, set the third-most significant bit so long as this is not
        // the point at infinity.
        res[0] |= u8::conditional_select(
            &0u8,
            &(1u8 << 5),
            (!self.infinity) & self.y.lexicographically_largest(),
        );

        res
    }

    /// Serializes this element into uncompressed form. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    pub fn to_uncompressed(&self) -> [u8; 192] {
        let mut res = [0; 192];

        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), self.infinity);
        let y = Fp2::conditional_select(&self.y, &Fp2::zero(), self.infinity);

        res[0..48].copy_from_slice(&x.c1.to_bytes()[..]);
        res[48..96].copy_from_slice(&x.c0.to_bytes()[..]);
        res[96..144].copy_from_slice(&y.c1.to_bytes()[..]);
        res[144..192].copy_from_slice(&y.c0.to_bytes()[..]);

        // Is this point at infinity? If so, set the second-most significant bit.
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), self.infinity);

        res
    }

    /// Attempts to deserialize an uncompressed element. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    pub fn from_uncompressed(bytes: &[u8; 192]) -> CtOption<Self> {
        Self::from_uncompressed_unchecked(bytes)
            .and_then(|p| CtOption::new(p, p.is_on_curve() & p.is_torsion_free()))
    }

    /// Attempts to deserialize an uncompressed element, not checking if the
    /// element is on the curve and not checking if it is in the correct subgroup.
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using `from_uncompressed()` instead.
    pub fn from_uncompressed_unchecked(bytes: &[u8; 192]) -> CtOption<Self> {
        // Obtain the three flags from the start of the byte sequence
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);

        // Attempt to obtain the x-coordinate
        let xc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);

            // Mask away the flag bits
            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };
        let xc0 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[48..96]);

            Fp::from_bytes(&tmp)
        };

        // Attempt to obtain the y-coordinate
        let yc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[96..144]);

            Fp::from_bytes(&tmp)
        };
        let yc0 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[144..192]);

            Fp::from_bytes(&tmp)
        };

        xc1.and_then(|xc1| {
            xc0.and_then(|xc0| {
                yc1.and_then(|yc1| {
                    yc0.and_then(|yc0| {
                        let x = Fp2 {
                            c0: xc0,
                            c1: xc1
                        };
                        let y = Fp2 {
                            c0: yc0,
                            c1: yc1
                        };

                        // Create a point representing this value
                        let p = G2Affine::conditional_select(
                            &G2Affine {
                                x,
                                y,
                                infinity: infinity_flag_set,
                            },
                            &G2Affine::identity(),
                            infinity_flag_set,
                        );

                        CtOption::new(
                            p,
                            // If the infinity flag is set, the x and y coordinates should have been zero.
                            ((!infinity_flag_set) | (infinity_flag_set & x.is_zero() & y.is_zero())) &
                            // The compression flag should not have been set, as this is an uncompressed element
                            (!compression_flag_set) &
                            // The sort flag should not have been set, as this is an uncompressed element
                            (!sort_flag_set),
                        )
                    })
                })
            })
        })
    }

    /// Attempts to deserialize a compressed element. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    pub fn from_compressed(bytes: &[u8; 96]) -> CtOption<Self> {
        // We already know the point is on the curve because this is established
        // by the y-coordinate recovery procedure in from_compressed_unchecked().

        Self::from_compressed_unchecked(bytes).and_then(|p| CtOption::new(p, p.is_torsion_free()))
    }

    /// Attempts to deserialize an uncompressed element, not checking if the
    /// element is in the correct subgroup.
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using `from_compressed()` instead.
    pub fn from_compressed_unchecked(bytes: &[u8; 96]) -> CtOption<Self> {
        // Obtain the three flags from the start of the byte sequence
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);

        // Attempt to obtain the x-coordinate
        let xc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);

            // Mask away the flag bits
            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };
        let xc0 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[48..96]);

            Fp::from_bytes(&tmp)
        };

        xc1.and_then(|xc1| {
            xc0.and_then(|xc0| {
                let x = Fp2 { c0: xc0, c1: xc1 };

                // If the infinity flag is set, return the value assuming
                // the x-coordinate is zero and the sort bit is not set.
                //
                // Otherwise, return a recovered point (assuming the correct
                // y-coordinate can be found) so long as the infinity flag
                // was not set.
                CtOption::new(
                    G2Affine::identity(),
                    infinity_flag_set & // Infinity flag should be set
                    compression_flag_set & // Compression flag should be set
                    (!sort_flag_set) & // Sort flag should not be set
                    x.is_zero(), // The x-coordinate should be zero
                )
                .or_else(|| {
                    // Recover a y-coordinate given x by y = sqrt(x^3 + 4)
                    ((x.square() * x) + B).sqrt().and_then(|y| {
                        // Switch to the correct y-coordinate if necessary.
                        let y = Fp2::conditional_select(
                            &y,
                            &-y,
                            y.lexicographically_largest() ^ sort_flag_set,
                        );

                        CtOption::new(
                            G2Affine {
                                x,
                                y,
                                infinity: infinity_flag_set,
                            },
                            (!infinity_flag_set) & // Infinity flag should not be set
                            compression_flag_set, // Compression flag should be set
                        )
                    })
                })
            })
        })
    }

    /// Returns true if this element is the identity (the point at infinity).
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }

    /// Returns true if this point is free of an $h$-torsion component, and so it
    /// exists within the $q$-order subgroup $\mathbb{G}_2$. This should always return true
    /// unless an "unchecked" API was used.
    pub fn is_torsion_free(&self) -> Choice {
        const FQ_MODULUS_BYTES: [u8; 32] = [
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
        ];

        // Clear the r-torsion from the point and check if it is the identity
        G2Projective::from(*self)
            .multiply(&FQ_MODULUS_BYTES)
            .is_identity()
    }

    /// Returns true if this point is on the curve. This should always return
    /// true unless an "unchecked" API was used.
    pub fn is_on_curve(&self) -> Choice {
        // y^2 - x^3 ?= 4(u + 1)
        (self.y.square() - (self.x.square() * self.x)).ct_eq(&B) | self.infinity
    }
}

/// This is an element of $\mathbb{G}_2$ represented in the projective coordinate space.
#[derive(Copy, Clone, Debug)]
pub struct G2Projective {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
    pub(crate) z: Fp2,
}

impl<'a> From<&'a G2Affine> for G2Projective {
    fn from(p: &'a G2Affine) -> G2Projective {
        G2Projective {
            x: p.x,
            y: p.y,
            z: Fp2::conditional_select(&Fp2::one(), &Fp2::zero(), p.infinity),
        }
    }
}

impl From<G2Affine> for G2Projective {
    fn from(p: G2Affine) -> G2Projective {
        G2Projective::from(&p)
    }
}

impl ConstantTimeEq for G2Projective {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Is (xz^2, yz^3, z) equal to (x'z'^2, yz'^3, z') when converted to affine?

        let z = other.z.square();
        let x1 = self.x * z;
        let z = z * other.z;
        let y1 = self.y * z;
        let z = self.z.square();
        let x2 = other.x * z;
        let z = z * self.z;
        let y2 = other.y * z;

        let self_is_zero = self.z.is_zero();
        let other_is_zero = other.z.is_zero();

        (self_is_zero & other_is_zero) // Both point at infinity
            | ((!self_is_zero) & (!other_is_zero) & x1.ct_eq(&x2) & y1.ct_eq(&y2))
        // Neither point at infinity, coordinates are the same
    }
}

impl ConditionallySelectable for G2Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G2Projective {
            x: Fp2::conditional_select(&a.x, &b.x, choice),
            y: Fp2::conditional_select(&a.y, &b.y, choice),
            z: Fp2::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Eq for G2Projective {}
impl PartialEq for G2Projective {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn neg(self) -> G2Projective {
        G2Projective {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Neg for G2Projective {
    type Output = G2Projective;

    #[inline]
    fn neg(self) -> G2Projective {
        -&self
    }
}

impl<'a, 'b> Add<&'b G2Projective> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn add(self, rhs: &'b G2Projective) -> G2Projective {
        self.add(rhs)
    }
}

impl<'a, 'b> Sub<&'b G2Projective> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn sub(self, rhs: &'b G2Projective) -> G2Projective {
        self + (-rhs)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G2Projective {
    type Output = G2Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        self.multiply(&other.to_bytes())
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G2Affine {
    type Output = G2Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        G2Projective::from(self).multiply(&other.to_bytes())
    }
}

impl_binops_additive!(G2Projective, G2Projective);
impl_binops_multiplicative!(G2Projective, Scalar);
impl_binops_multiplicative_mixed!(G2Affine, Scalar, G2Projective);

impl G2Projective {
    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> G2Projective {
        G2Projective {
            x: Fp2::zero(),
            y: Fp2::one(),
            z: Fp2::zero(),
        }
    }

    /// Returns a fixed generator of the group. See [`notes::design`](notes/design/index.html#fixed-generators)
    /// for how this generator is chosen.
    pub fn generator() -> G2Projective {
        G2Projective {
            x: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xf5f2_8fa2_0294_0a10,
                    0xb3f5_fb26_87b4_961a,
                    0xa1a8_93b5_3e2a_e580,
                    0x9894_999d_1a3c_aee9,
                    0x6f67_b763_1863_366b,
                    0x0581_9192_4350_bcd7,
                ]),
                c1: Fp::from_raw_unchecked([
                    0xa5a9_c075_9e23_f606,
                    0xaaa0_c59d_bccd_60c3,
                    0x3bb1_7e18_e286_7806,
                    0x1b1a_b6cc_8541_b367,
                    0xc2b6_ed0e_f215_8547,
                    0x1192_2a09_7360_edf3,
                ]),
            },
            y: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x4c73_0af8_6049_4c4a,
                    0x597c_fa1f_5e36_9c5a,
                    0xe7e6_856c_aa0a_635a,
                    0xbbef_b5e9_6e0d_495f,
                    0x07d3_a975_f0ef_25a2,
                    0x0083_fd8e_7e80_dae5,
                ]),
                c1: Fp::from_raw_unchecked([
                    0xadc0_fc92_df64_b05d,
                    0x18aa_270a_2b14_61dc,
                    0x86ad_ac6a_3be4_eba0,
                    0x7949_5c4e_c93d_a33a,
                    0xe717_5850_a43c_caed,
                    0x0b2b_c2a1_63de_1bf2,
                ]),
            },
            z: Fp2::one(),
        }
    }

    /// Computes the doubling of this point.
    pub fn double(&self) -> G2Projective {
        // http://www.hyperelliptic.org/EFD/g2p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
        //
        // There are no points of order 2.

        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x + b;
        let d = d.square();
        let d = d - a - c;
        let d = d + d;
        let e = a + a + a;
        let f = e.square();
        let z3 = self.z * self.y;
        let z3 = z3 + z3;
        let x3 = f - (d + d);
        let c = c + c;
        let c = c + c;
        let c = c + c;
        let y3 = e * (d - x3) - c;

        let tmp = G2Projective {
            x: x3,
            y: y3,
            z: z3,
        };

        G2Projective::conditional_select(&tmp, &G2Projective::identity(), self.is_identity())
    }

    /// Adds this point to another point.
    pub fn add(&self, rhs: &G2Projective) -> G2Projective {
        // This Jacobian point addition technique is based on the implementation in libsecp256k1,
        // which assumes that rhs has z=1. Let's address the case of zero z-coordinates generally.

        // If self is the identity, return rhs. Otherwise, return self. The other cases will be
        // predicated on neither self nor rhs being the identity.
        let f1 = self.is_identity();
        let res = G2Projective::conditional_select(self, rhs, f1);
        let f2 = rhs.is_identity();

        // If neither are the identity but x1 = x2 and y1 != y2, then return the identity
        let z = rhs.z.square();
        let u1 = self.x * z;
        let z = z * rhs.z;
        let s1 = self.y * z;
        let z = self.z.square();
        let u2 = rhs.x * z;
        let z = z * self.z;
        let s2 = rhs.y * z;
        let f3 = u1.ct_eq(&u2) & (!s1.ct_eq(&s2));
        let res =
            G2Projective::conditional_select(&res, &G2Projective::identity(), (!f1) & (!f2) & f3);

        let t = u1 + u2;
        let m = s1 + s2;
        let rr = t.square();
        let m_alt = -u2;
        let tt = u1 * m_alt;
        let rr = rr + tt;

        // Correct for x1 != x2 but y1 = -y2, which can occur because p - 1 is divisible by 3.
        // libsecp256k1 does this by substituting in an alternative (defined) expression for lambda.
        let degenerate = m.is_zero() & rr.is_zero();
        let rr_alt = s1 + s1;
        let m_alt = m_alt + u1;
        let rr_alt = Fp2::conditional_select(&rr_alt, &rr, !degenerate);
        let m_alt = Fp2::conditional_select(&m_alt, &m, !degenerate);

        let n = m_alt.square();
        let q = n * t;

        let n = n.square();
        let n = Fp2::conditional_select(&n, &m, degenerate);
        let t = rr_alt.square();
        let z3 = m_alt * self.z * rhs.z; // We allow rhs.z != 1, so we must account for this.
        let z3 = z3 + z3;
        let q = -q;
        let t = t + q;
        let x3 = t;
        let t = t + t;
        let t = t + q;
        let t = t * rr_alt;
        let t = t + n;
        let y3 = -t;
        let x3 = x3 + x3;
        let x3 = x3 + x3;
        let y3 = y3 + y3;
        let y3 = y3 + y3;

        let tmp = G2Projective {
            x: x3,
            y: y3,
            z: z3,
        };

        G2Projective::conditional_select(&res, &tmp, (!f1) & (!f2) & (!f3))
    }

    /// Adds this point to another point in the affine model.
    pub fn add_mixed(&self, rhs: &G2Affine) -> G2Projective {
        // This Jacobian point addition technique is based on the implementation in libsecp256k1,
        // which assumes that rhs has z=1. Let's address the case of zero z-coordinates generally.

        // If self is the identity, return rhs. Otherwise, return self. The other cases will be
        // predicated on neither self nor rhs being the identity.
        let f1 = self.is_identity();
        let res = G2Projective::conditional_select(self, &G2Projective::from(rhs), f1);
        let f2 = rhs.is_identity();

        // If neither are the identity but x1 = x2 and y1 != y2, then return the identity
        let u1 = self.x;
        let s1 = self.y;
        let z = self.z.square();
        let u2 = rhs.x * z;
        let z = z * self.z;
        let s2 = rhs.y * z;
        let f3 = u1.ct_eq(&u2) & (!s1.ct_eq(&s2));
        let res =
            G2Projective::conditional_select(&res, &G2Projective::identity(), (!f1) & (!f2) & f3);

        let t = u1 + u2;
        let m = s1 + s2;
        let rr = t.square();
        let m_alt = -u2;
        let tt = u1 * m_alt;
        let rr = rr + tt;

        // Correct for x1 != x2 but y1 = -y2, which can occur because p - 1 is divisible by 3.
        // libsecp256k1 does this by substituting in an alternative (defined) expression for lambda.
        let degenerate = m.is_zero() & rr.is_zero();
        let rr_alt = s1 + s1;
        let m_alt = m_alt + u1;
        let rr_alt = Fp2::conditional_select(&rr_alt, &rr, !degenerate);
        let m_alt = Fp2::conditional_select(&m_alt, &m, !degenerate);

        let n = m_alt.square();
        let q = n * t;

        let n = n.square();
        let n = Fp2::conditional_select(&n, &m, degenerate);
        let t = rr_alt.square();
        let z3 = m_alt * self.z;
        let z3 = z3 + z3;
        let q = -q;
        let t = t + q;
        let x3 = t;
        let t = t + t;
        let t = t + q;
        let t = t * rr_alt;
        let t = t + n;
        let y3 = -t;
        let x3 = x3 + x3;
        let x3 = x3 + x3;
        let y3 = y3 + y3;
        let y3 = y3 + y3;

        let tmp = G2Projective {
            x: x3,
            y: y3,
            z: z3,
        };

        G2Projective::conditional_select(&res, &tmp, (!f1) & (!f2) & (!f3))
    }

    fn multiply(&self, by: &[u8; 32]) -> G2Projective {
        let mut acc = G2Projective::identity();

        // This is a simple double-and-add implementation of point
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading bit because it's always unset for Fq
        // elements.
        for bit in by
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8)))
            .skip(1)
        {
            acc = acc.double();
            acc = G2Projective::conditional_select(&acc, &(acc + self), bit);
        }

        acc
    }

    /// Converts a batch of `G2Projective` elements into `G2Affine` elements. This
    /// function will panic if `p.len() != q.len()`.
    pub fn batch_normalize(p: &[Self], q: &mut [G2Affine]) {
        assert_eq!(p.len(), q.len());

        let mut acc = Fp2::one();
        for (p, q) in p.iter().zip(q.iter_mut()) {
            // We use the `x` field of `G2Affine` to store the product
            // of previous z-coordinates seen.
            q.x = acc;

            // We will end up skipping all identities in p
            acc = Fp2::conditional_select(&(acc * p.z), &acc, p.is_identity());
        }

        // This is the inverse, as all z-coordinates are nonzero and the ones
        // that are not are skipped.
        acc = acc.invert().unwrap();

        for (p, q) in p.iter().rev().zip(q.iter_mut().rev()) {
            let skip = p.is_identity();

            // Compute tmp = 1/z
            let tmp = q.x * acc;

            // Cancel out z-coordinate in denominator of `acc`
            acc = Fp2::conditional_select(&(acc * p.z), &acc, skip);

            // Set the coordinates to the correct value
            let tmp2 = tmp.square();
            let tmp3 = tmp2 * tmp;

            q.x = p.x * tmp2;
            q.y = p.y * tmp3;
            q.infinity = Choice::from(0u8);

            *q = G2Affine::conditional_select(&q, &G2Affine::identity(), skip);
        }
    }

    /// Returns true if this element is the identity (the point at infinity).
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Returns true if this point is on the curve. This should always return
    /// true unless an "unchecked" API was used.
    pub fn is_on_curve(&self) -> Choice {
        // Y^2 - X^3 = 4(u + 1)(Z^6)

        (self.y.square() - (self.x.square() * self.x))
            .ct_eq(&((self.z.square() * self.z).square() * B))
            | self.z.is_zero()
    }
}

#[test]
fn test_is_on_curve() {
    assert!(bool::from(G2Affine::identity().is_on_curve()));
    assert!(bool::from(G2Affine::generator().is_on_curve()));
    assert!(bool::from(G2Projective::identity().is_on_curve()));
    assert!(bool::from(G2Projective::generator().is_on_curve()));

    let z = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xba7a_fa1f_9a6f_e250,
            0xfa0f_5b59_5eaf_e731,
            0x3bdc_4776_94c3_06e7,
            0x2149_be4b_3949_fa24,
            0x64aa_6e06_49b2_078c,
            0x12b1_08ac_3364_3c3e,
        ]),
        c1: Fp::from_raw_unchecked([
            0x1253_25df_3d35_b5a8,
            0xdc46_9ef5_555d_7fe3,
            0x02d7_16d2_4431_06a9,
            0x05a1_db59_a6ff_37d0,
            0x7cf7_784e_5300_bb8f,
            0x16a8_8922_c7a5_e844,
        ]),
    };

    let gen = G2Affine::generator();
    let mut test = G2Projective {
        x: gen.x * (z.square()),
        y: gen.y * (z.square() * z),
        z,
    };

    assert!(bool::from(test.is_on_curve()));

    test.x = z;
    assert!(!bool::from(test.is_on_curve()));
}

#[test]
#[allow(clippy::eq_op)]
fn test_affine_point_equality() {
    let a = G2Affine::generator();
    let b = G2Affine::identity();

    assert!(a == a);
    assert!(b == b);
    assert!(a != b);
    assert!(b != a);
}

#[test]
#[allow(clippy::eq_op)]
fn test_projective_point_equality() {
    let a = G2Projective::generator();
    let b = G2Projective::identity();

    assert!(a == a);
    assert!(b == b);
    assert!(a != b);
    assert!(b != a);

    let z = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xba7a_fa1f_9a6f_e250,
            0xfa0f_5b59_5eaf_e731,
            0x3bdc_4776_94c3_06e7,
            0x2149_be4b_3949_fa24,
            0x64aa_6e06_49b2_078c,
            0x12b1_08ac_3364_3c3e,
        ]),
        c1: Fp::from_raw_unchecked([
            0x1253_25df_3d35_b5a8,
            0xdc46_9ef5_555d_7fe3,
            0x02d7_16d2_4431_06a9,
            0x05a1_db59_a6ff_37d0,
            0x7cf7_784e_5300_bb8f,
            0x16a8_8922_c7a5_e844,
        ]),
    };

    let mut c = G2Projective {
        x: a.x * (z.square()),
        y: a.y * (z.square() * z),
        z,
    };
    assert!(bool::from(c.is_on_curve()));

    assert!(a == c);
    assert!(b != c);
    assert!(c == a);
    assert!(c != b);

    c.y = -c.y;
    assert!(bool::from(c.is_on_curve()));

    assert!(a != c);
    assert!(b != c);
    assert!(c != a);
    assert!(c != b);

    c.y = -c.y;
    c.x = z;
    assert!(!bool::from(c.is_on_curve()));
    assert!(a != b);
    assert!(a != c);
    assert!(b != c);
}

#[test]
fn test_conditionally_select_affine() {
    let a = G2Affine::generator();
    let b = G2Affine::identity();

    assert_eq!(G2Affine::conditional_select(&a, &b, Choice::from(0u8)), a);
    assert_eq!(G2Affine::conditional_select(&a, &b, Choice::from(1u8)), b);
}

#[test]
fn test_conditionally_select_projective() {
    let a = G2Projective::generator();
    let b = G2Projective::identity();

    assert_eq!(
        G2Projective::conditional_select(&a, &b, Choice::from(0u8)),
        a
    );
    assert_eq!(
        G2Projective::conditional_select(&a, &b, Choice::from(1u8)),
        b
    );
}

#[test]
fn test_projective_to_affine() {
    let a = G2Projective::generator();
    let b = G2Projective::identity();

    assert!(bool::from(G2Affine::from(a).is_on_curve()));
    assert!(!bool::from(G2Affine::from(a).is_identity()));
    assert!(bool::from(G2Affine::from(b).is_on_curve()));
    assert!(bool::from(G2Affine::from(b).is_identity()));

    let z = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xba7a_fa1f_9a6f_e250,
            0xfa0f_5b59_5eaf_e731,
            0x3bdc_4776_94c3_06e7,
            0x2149_be4b_3949_fa24,
            0x64aa_6e06_49b2_078c,
            0x12b1_08ac_3364_3c3e,
        ]),
        c1: Fp::from_raw_unchecked([
            0x1253_25df_3d35_b5a8,
            0xdc46_9ef5_555d_7fe3,
            0x02d7_16d2_4431_06a9,
            0x05a1_db59_a6ff_37d0,
            0x7cf7_784e_5300_bb8f,
            0x16a8_8922_c7a5_e844,
        ]),
    };

    let c = G2Projective {
        x: a.x * (z.square()),
        y: a.y * (z.square() * z),
        z,
    };

    assert_eq!(G2Affine::from(c), G2Affine::generator());
}

#[test]
fn test_affine_to_projective() {
    let a = G2Affine::generator();
    let b = G2Affine::identity();

    assert!(bool::from(G2Projective::from(a).is_on_curve()));
    assert!(!bool::from(G2Projective::from(a).is_identity()));
    assert!(bool::from(G2Projective::from(b).is_on_curve()));
    assert!(bool::from(G2Projective::from(b).is_identity()));
}

#[test]
fn test_doubling() {
    {
        let tmp = G2Projective::identity().double();
        assert!(bool::from(tmp.is_identity()));
        assert!(bool::from(tmp.is_on_curve()));
    }
    {
        let tmp = G2Projective::generator().double();
        assert!(!bool::from(tmp.is_identity()));
        assert!(bool::from(tmp.is_on_curve()));

        assert_eq!(
            G2Affine::from(tmp),
            G2Affine {
                x: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0xe9d9_e2da_9620_f98b,
                        0x54f1_1993_46b9_7f36,
                        0x3db3_b820_376b_ed27,
                        0xcfdb_31c9_b0b6_4f4c,
                        0x41d7_c127_8635_4493,
                        0x0571_0794_c255_c064,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xd6c1_d3ca_6ea0_d06e,
                        0xda0c_bd90_5595_489f,
                        0x4f53_52d4_3479_221d,
                        0x8ade_5d73_6f8c_97e0,
                        0x48cc_8433_925e_f70e,
                        0x08d7_ea71_ea91_ef81,
                    ]),
                },
                y: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x15ba_26eb_4b0d_186f,
                        0x0d08_6d64_b7e9_e01e,
                        0xc8b8_48dd_652f_4c78,
                        0xeecf_46a6_123b_ae4f,
                        0x255e_8dd8_b6dc_812a,
                        0x1641_42af_21dc_f93f,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xf9b4_a1a8_9598_4db4,
                        0xd417_b114_cccf_f748,
                        0x6856_301f_c89f_086e,
                        0x41c7_7787_8931_e3da,
                        0x3556_b155_066a_2105,
                        0x00ac_f7d3_25cb_89cf,
                    ]),
                },
                infinity: Choice::from(0u8)
            }
        );
    }
}

#[test]
fn test_projective_addition() {
    {
        let a = G2Projective::identity();
        let b = G2Projective::identity();
        let c = a + b;
        assert!(bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
    {
        let a = G2Projective::identity();
        let mut b = G2Projective::generator();
        {
            let z = Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xba7a_fa1f_9a6f_e250,
                    0xfa0f_5b59_5eaf_e731,
                    0x3bdc_4776_94c3_06e7,
                    0x2149_be4b_3949_fa24,
                    0x64aa_6e06_49b2_078c,
                    0x12b1_08ac_3364_3c3e,
                ]),
                c1: Fp::from_raw_unchecked([
                    0x1253_25df_3d35_b5a8,
                    0xdc46_9ef5_555d_7fe3,
                    0x02d7_16d2_4431_06a9,
                    0x05a1_db59_a6ff_37d0,
                    0x7cf7_784e_5300_bb8f,
                    0x16a8_8922_c7a5_e844,
                ]),
            };

            b = G2Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = a + b;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G2Projective::generator());
    }
    {
        let a = G2Projective::identity();
        let mut b = G2Projective::generator();
        {
            let z = Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xba7a_fa1f_9a6f_e250,
                    0xfa0f_5b59_5eaf_e731,
                    0x3bdc_4776_94c3_06e7,
                    0x2149_be4b_3949_fa24,
                    0x64aa_6e06_49b2_078c,
                    0x12b1_08ac_3364_3c3e,
                ]),
                c1: Fp::from_raw_unchecked([
                    0x1253_25df_3d35_b5a8,
                    0xdc46_9ef5_555d_7fe3,
                    0x02d7_16d2_4431_06a9,
                    0x05a1_db59_a6ff_37d0,
                    0x7cf7_784e_5300_bb8f,
                    0x16a8_8922_c7a5_e844,
                ]),
            };

            b = G2Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = b + a;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G2Projective::generator());
    }
    {
        let a = G2Projective::generator().double().double(); // 4P
        let b = G2Projective::generator().double(); // 2P
        let c = a + b;

        let mut d = G2Projective::generator();
        for _ in 0..5 {
            d += G2Projective::generator();
        }
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(!bool::from(d.is_identity()));
        assert!(bool::from(d.is_on_curve()));
        assert_eq!(c, d);
    }

    // Degenerate case
    {
        let beta = Fp2 {
            c0: Fp::from_raw_unchecked([
                0xcd03_c9e4_8671_f071,
                0x5dab_2246_1fcd_a5d2,
                0x5870_42af_d385_1b95,
                0x8eb6_0ebe_01ba_cb9e,
                0x03f9_7d6e_83d0_50d2,
                0x18f0_2065_5463_8741,
            ]),
            c1: Fp::zero(),
        };
        let beta = beta.square();
        let a = G2Projective::generator().double().double();
        let b = G2Projective {
            x: a.x * beta,
            y: -a.y,
            z: a.z,
        };
        assert!(bool::from(a.is_on_curve()));
        assert!(bool::from(b.is_on_curve()));

        let c = a + b;
        assert_eq!(
            G2Affine::from(c),
            G2Affine::from(G2Projective {
                x: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x705a_bc79_9ca7_73d3,
                        0xfe13_2292_c1d4_bf08,
                        0xf37e_ce3e_07b2_b466,
                        0x887e_1c43_f447_e301,
                        0x1e09_70d0_33bc_77e8,
                        0x1985_c81e_20a6_93f2,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x1d79_b25d_b36a_b924,
                        0x2394_8e4d_5296_39d3,
                        0x471b_a7fb_0d00_6297,
                        0x2c36_d4b4_465d_c4c0,
                        0x82bb_c3cf_ec67_f538,
                        0x051d_2728_b67b_f952,
                    ])
                },
                y: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x41b1_bbf6_576c_0abf,
                        0xb6cc_9371_3f7a_0f9a,
                        0x6b65_b43e_48f3_f01f,
                        0xfb7a_4cfc_af81_be4f,
                        0x3e32_dadc_6ec2_2cb6,
                        0x0bb0_fc49_d798_07e3,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x7d13_9778_8f5f_2ddf,
                        0xab29_0714_4ff0_d8e8,
                        0x5b75_73e0_cdb9_1f92,
                        0x4cb8_932d_d31d_af28,
                        0x62bb_fac6_db05_2a54,
                        0x11f9_5c16_d14c_3bbe,
                    ])
                },
                z: Fp2::one()
            })
        );
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
}

#[test]
fn test_mixed_addition() {
    {
        let a = G2Affine::identity();
        let b = G2Projective::identity();
        let c = a + b;
        assert!(bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
    {
        let a = G2Affine::identity();
        let mut b = G2Projective::generator();
        {
            let z = Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xba7a_fa1f_9a6f_e250,
                    0xfa0f_5b59_5eaf_e731,
                    0x3bdc_4776_94c3_06e7,
                    0x2149_be4b_3949_fa24,
                    0x64aa_6e06_49b2_078c,
                    0x12b1_08ac_3364_3c3e,
                ]),
                c1: Fp::from_raw_unchecked([
                    0x1253_25df_3d35_b5a8,
                    0xdc46_9ef5_555d_7fe3,
                    0x02d7_16d2_4431_06a9,
                    0x05a1_db59_a6ff_37d0,
                    0x7cf7_784e_5300_bb8f,
                    0x16a8_8922_c7a5_e844,
                ]),
            };

            b = G2Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = a + b;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G2Projective::generator());
    }
    {
        let a = G2Affine::identity();
        let mut b = G2Projective::generator();
        {
            let z = Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xba7a_fa1f_9a6f_e250,
                    0xfa0f_5b59_5eaf_e731,
                    0x3bdc_4776_94c3_06e7,
                    0x2149_be4b_3949_fa24,
                    0x64aa_6e06_49b2_078c,
                    0x12b1_08ac_3364_3c3e,
                ]),
                c1: Fp::from_raw_unchecked([
                    0x1253_25df_3d35_b5a8,
                    0xdc46_9ef5_555d_7fe3,
                    0x02d7_16d2_4431_06a9,
                    0x05a1_db59_a6ff_37d0,
                    0x7cf7_784e_5300_bb8f,
                    0x16a8_8922_c7a5_e844,
                ]),
            };

            b = G2Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = b + a;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G2Projective::generator());
    }
    {
        let a = G2Projective::generator().double().double(); // 4P
        let b = G2Projective::generator().double(); // 2P
        let c = a + b;

        let mut d = G2Projective::generator();
        for _ in 0..5 {
            d += G2Affine::generator();
        }
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(!bool::from(d.is_identity()));
        assert!(bool::from(d.is_on_curve()));
        assert_eq!(c, d);
    }

    // Degenerate case
    {
        let beta = Fp2 {
            c0: Fp::from_raw_unchecked([
                0xcd03_c9e4_8671_f071,
                0x5dab_2246_1fcd_a5d2,
                0x5870_42af_d385_1b95,
                0x8eb6_0ebe_01ba_cb9e,
                0x03f9_7d6e_83d0_50d2,
                0x18f0_2065_5463_8741,
            ]),
            c1: Fp::zero(),
        };
        let beta = beta.square();
        let a = G2Projective::generator().double().double();
        let b = G2Projective {
            x: a.x * beta,
            y: -a.y,
            z: a.z,
        };
        let a = G2Affine::from(a);
        assert!(bool::from(a.is_on_curve()));
        assert!(bool::from(b.is_on_curve()));

        let c = a + b;
        assert_eq!(
            G2Affine::from(c),
            G2Affine::from(G2Projective {
                x: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x705a_bc79_9ca7_73d3,
                        0xfe13_2292_c1d4_bf08,
                        0xf37e_ce3e_07b2_b466,
                        0x887e_1c43_f447_e301,
                        0x1e09_70d0_33bc_77e8,
                        0x1985_c81e_20a6_93f2,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x1d79_b25d_b36a_b924,
                        0x2394_8e4d_5296_39d3,
                        0x471b_a7fb_0d00_6297,
                        0x2c36_d4b4_465d_c4c0,
                        0x82bb_c3cf_ec67_f538,
                        0x051d_2728_b67b_f952,
                    ])
                },
                y: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x41b1_bbf6_576c_0abf,
                        0xb6cc_9371_3f7a_0f9a,
                        0x6b65_b43e_48f3_f01f,
                        0xfb7a_4cfc_af81_be4f,
                        0x3e32_dadc_6ec2_2cb6,
                        0x0bb0_fc49_d798_07e3,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x7d13_9778_8f5f_2ddf,
                        0xab29_0714_4ff0_d8e8,
                        0x5b75_73e0_cdb9_1f92,
                        0x4cb8_932d_d31d_af28,
                        0x62bb_fac6_db05_2a54,
                        0x11f9_5c16_d14c_3bbe,
                    ])
                },
                z: Fp2::one()
            })
        );
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
}

#[test]
#[allow(clippy::eq_op)]
fn test_projective_negation_and_subtraction() {
    let a = G2Projective::generator().double();
    assert_eq!(a + (-a), G2Projective::identity());
    assert_eq!(a + (-a), a - a);
}

#[test]
fn test_affine_negation_and_subtraction() {
    let a = G2Affine::generator();
    assert_eq!(G2Projective::from(a) + (-a), G2Projective::identity());
    assert_eq!(G2Projective::from(a) + (-a), G2Projective::from(a) - a);
}

#[test]
fn test_projective_scalar_multiplication() {
    let g = G2Projective::generator();
    let a = Scalar::from_raw([
        0x2b56_8297_a56d_a71c,
        0xd8c3_9ecb_0ef3_75d1,
        0x435c_38da_67bf_bf96,
        0x8088_a050_26b6_59b2,
    ]);
    let b = Scalar::from_raw([
        0x785f_dd9b_26ef_8b85,
        0xc997_f258_3769_5c18,
        0x4c8d_bc39_e7b7_56c1,
        0x70d9_b6cc_6d87_df20,
    ]);
    let c = a * b;

    assert_eq!((g * a) * b, g * c);
}

#[test]
fn test_affine_scalar_multiplication() {
    let g = G2Affine::generator();
    let a = Scalar::from_raw([
        0x2b56_8297_a56d_a71c,
        0xd8c3_9ecb_0ef3_75d1,
        0x435c_38da_67bf_bf96,
        0x8088_a050_26b6_59b2,
    ]);
    let b = Scalar::from_raw([
        0x785f_dd9b_26ef_8b85,
        0xc997_f258_3769_5c18,
        0x4c8d_bc39_e7b7_56c1,
        0x70d9_b6cc_6d87_df20,
    ]);
    let c = a * b;

    assert_eq!(G2Affine::from(g * a) * b, g * c);
}

#[test]
fn test_is_torsion_free() {
    let a = G2Affine {
        x: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x89f5_50c8_13db_6431,
                0xa50b_e8c4_56cd_8a1a,
                0xa45b_3741_14ca_e851,
                0xbb61_90f5_bf7f_ff63,
                0x970c_a02c_3ba8_0bc7,
                0x02b8_5d24_e840_fbac,
            ]),
            c1: Fp::from_raw_unchecked([
                0x6888_bc53_d707_16dc,
                0x3dea_6b41_1768_2d70,
                0xd8f5_f930_500c_a354,
                0x6b5e_cb65_56f5_c155,
                0xc96b_ef04_3477_8ab0,
                0x0508_1505_5150_06ad,
            ]),
        },
        y: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x3cf1_ea0d_434b_0f40,
                0x1a0d_c610_e603_e333,
                0x7f89_9561_60c7_2fa0,
                0x25ee_03de_cf64_31c5,
                0xeee8_e206_ec0f_e137,
                0x0975_92b2_26df_ef28,
            ]),
            c1: Fp::from_raw_unchecked([
                0x71e8_bb5f_2924_7367,
                0xa5fe_049e_2118_31ce,
                0x0ce6_b354_502a_3896,
                0x93b0_1200_0997_314e,
                0x6759_f3b6_aa5b_42ac,
                0x1569_44c4_dfe9_2bbb,
            ]),
        },
        infinity: Choice::from(0u8),
    };
    assert!(!bool::from(a.is_torsion_free()));

    assert!(bool::from(G2Affine::identity().is_torsion_free()));
    assert!(bool::from(G2Affine::generator().is_torsion_free()));
}

#[test]
fn test_batch_normalize() {
    let a = G2Projective::generator().double();
    let b = a.double();
    let c = b.double();

    for a_identity in (0..1).map(|n| n == 1) {
        for b_identity in (0..1).map(|n| n == 1) {
            for c_identity in (0..1).map(|n| n == 1) {
                let mut v = [a, b, c];
                if a_identity {
                    v[0] = G2Projective::identity()
                }
                if b_identity {
                    v[1] = G2Projective::identity()
                }
                if c_identity {
                    v[2] = G2Projective::identity()
                }

                let mut t = [
                    G2Affine::identity(),
                    G2Affine::identity(),
                    G2Affine::identity(),
                ];
                let expected = [
                    G2Affine::from(v[0]),
                    G2Affine::from(v[1]),
                    G2Affine::from(v[2]),
                ];

                G2Projective::batch_normalize(&v[..], &mut t[..]);

                assert_eq!(&t[..], &expected[..]);
            }
        }
    }
}
