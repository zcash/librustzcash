//! This module provides an implementation of the $\mathbb{G}_1$ group of BLS12-381.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::fp::Fp;
use crate::Scalar;

/// This is an element of $\mathbb{G}_1$ represented in the affine coordinate space.
/// It is ideal to keep elements in this representation to reduce memory usage and
/// improve performance through the use of mixed curve model arithmetic.
///
/// Values of `G1Affine` are guaranteed to be in the $q$-order subgroup unless an
/// "unchecked" API was misused.
#[derive(Copy, Clone, Debug)]
pub struct G1Affine {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    infinity: Choice,
}

impl Default for G1Affine {
    fn default() -> G1Affine {
        G1Affine::identity()
    }
}

impl<'a> From<&'a G1Projective> for G1Affine {
    fn from(p: &'a G1Projective) -> G1Affine {
        let zinv = p.z.invert().unwrap_or(Fp::zero());
        let zinv2 = zinv.square();
        let x = p.x * zinv2;
        let zinv3 = zinv2 * zinv;
        let y = p.y * zinv3;

        let tmp = G1Affine {
            x,
            y,
            infinity: Choice::from(0u8),
        };

        G1Affine::conditional_select(&tmp, &G1Affine::identity(), zinv.is_zero())
    }
}

impl From<G1Projective> for G1Affine {
    fn from(p: G1Projective) -> G1Affine {
        G1Affine::from(&p)
    }
}

impl ConstantTimeEq for G1Affine {
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

impl ConditionallySelectable for G1Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G1Affine {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl Eq for G1Affine {}
impl PartialEq for G1Affine {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G1Affine {
    type Output = G1Affine;

    #[inline]
    fn neg(self) -> G1Affine {
        G1Affine {
            x: self.x,
            y: Fp::conditional_select(&-self.y, &Fp::one(), self.infinity),
            infinity: self.infinity,
        }
    }
}

impl Neg for G1Affine {
    type Output = G1Affine;

    #[inline]
    fn neg(self) -> G1Affine {
        -&self
    }
}

impl<'a, 'b> Add<&'b G1Projective> for &'a G1Affine {
    type Output = G1Projective;

    #[inline]
    fn add(self, rhs: &'b G1Projective) -> G1Projective {
        rhs.add_mixed(self)
    }
}

impl<'a, 'b> Add<&'b G1Affine> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn add(self, rhs: &'b G1Affine) -> G1Projective {
        self.add_mixed(rhs)
    }
}

impl<'a, 'b> Sub<&'b G1Projective> for &'a G1Affine {
    type Output = G1Projective;

    #[inline]
    fn sub(self, rhs: &'b G1Projective) -> G1Projective {
        self + (-rhs)
    }
}

impl<'a, 'b> Sub<&'b G1Affine> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn sub(self, rhs: &'b G1Affine) -> G1Projective {
        self + (-rhs)
    }
}

impl_binops_additive!(G1Projective, G1Affine);
impl_binops_additive_specify_output!(G1Affine, G1Projective, G1Projective);

const B: Fp = Fp::from_raw_unchecked([
    0xaa27_0000_000c_fff3,
    0x53cc_0032_fc34_000a,
    0x478f_e97a_6b0a_807f,
    0xb1d3_7ebe_e6ba_24d7,
    0x8ec9_733b_bf78_ab2f,
    0x09d6_4551_3d83_de7e,
]);

impl G1Affine {
    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> G1Affine {
        G1Affine {
            x: Fp::zero(),
            y: Fp::one(),
            infinity: Choice::from(1u8),
        }
    }

    /// Returns a fixed generator of the group. See [`notes::design`](notes/design/index.html#fixed-generators)
    /// for how this generator is chosen.
    pub fn generator() -> G1Affine {
        G1Affine {
            x: Fp::from_raw_unchecked([
                0x5cb3_8790_fd53_0c16,
                0x7817_fc67_9976_fff5,
                0x154f_95c7_143b_a1c1,
                0xf0ae_6acd_f3d0_e747,
                0xedce_6ecc_21db_f440,
                0x1201_7741_9e0b_fb75,
            ]),
            y: Fp::from_raw_unchecked([
                0xbaac_93d5_0ce7_2271,
                0x8c22_631a_7918_fd8e,
                0xdd59_5f13_5707_25ce,
                0x51ac_5829_5040_5194,
                0x0e1c_8c3f_ad00_59c0,
                0x0bbc_3efc_5008_a26a,
            ]),
            infinity: Choice::from(0u8),
        }
    }

    /// Serializes this element into compressed form. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    pub fn to_compressed(&self) -> [u8; 48] {
        // Strictly speaking, self.x is zero already when self.infinity is true, but
        // to guard against implementation mistakes we do not assume this.
        let mut res = Fp::conditional_select(&self.x, &Fp::zero(), self.infinity).to_bytes();

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
    pub fn to_uncompressed(&self) -> [u8; 96] {
        let mut res = [0; 96];

        res[0..48].copy_from_slice(
            &Fp::conditional_select(&self.x, &Fp::zero(), self.infinity).to_bytes()[..],
        );
        res[48..96].copy_from_slice(
            &Fp::conditional_select(&self.y, &Fp::zero(), self.infinity).to_bytes()[..],
        );

        // Is this point at infinity? If so, set the second-most significant bit.
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), self.infinity);

        res
    }

    /// Attempts to deserialize an uncompressed element. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    pub fn from_uncompressed(bytes: &[u8; 96]) -> CtOption<Self> {
        Self::from_uncompressed_unchecked(bytes)
            .and_then(|p| CtOption::new(p, p.is_on_curve() & p.is_torsion_free()))
    }

    /// Attempts to deserialize an uncompressed element, not checking if the
    /// element is on the curve and not checking if it is in the correct subgroup.
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using `from_uncompressed()` instead.
    pub fn from_uncompressed_unchecked(bytes: &[u8; 96]) -> CtOption<Self> {
        // Obtain the three flags from the start of the byte sequence
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);

        // Attempt to obtain the x-coordinate
        let x = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);

            // Mask away the flag bits
            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };

        // Attempt to obtain the y-coordinate
        let y = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[48..96]);

            Fp::from_bytes(&tmp)
        };

        x.and_then(|x| {
            y.and_then(|y| {
                // Create a point representing this value
                let p = G1Affine::conditional_select(
                    &G1Affine {
                        x,
                        y,
                        infinity: infinity_flag_set,
                    },
                    &G1Affine::identity(),
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
    }

    /// Attempts to deserialize a compressed element. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    pub fn from_compressed(bytes: &[u8; 48]) -> CtOption<Self> {
        // We already know the point is on the curve because this is established
        // by the y-coordinate recovery procedure in from_compressed_unchecked().

        Self::from_compressed_unchecked(bytes).and_then(|p| CtOption::new(p, p.is_torsion_free()))
    }

    /// Attempts to deserialize an uncompressed element, not checking if the
    /// element is in the correct subgroup.
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using `from_compressed()` instead.
    pub fn from_compressed_unchecked(bytes: &[u8; 48]) -> CtOption<Self> {
        // Obtain the three flags from the start of the byte sequence
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);

        // Attempt to obtain the x-coordinate
        let x = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);

            // Mask away the flag bits
            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };

        x.and_then(|x| {
            // If the infinity flag is set, return the value assuming
            // the x-coordinate is zero and the sort bit is not set.
            //
            // Otherwise, return a recovered point (assuming the correct
            // y-coordinate can be found) so long as the infinity flag
            // was not set.
            CtOption::new(
                G1Affine::identity(),
                infinity_flag_set & // Infinity flag should be set
                compression_flag_set & // Compression flag should be set
                (!sort_flag_set) & // Sort flag should not be set
                x.is_zero(), // The x-coordinate should be zero
            )
            .or_else(|| {
                // Recover a y-coordinate given x by y = sqrt(x^3 + 4)
                ((x.square() * x) + B).sqrt().and_then(|y| {
                    // Switch to the correct y-coordinate if necessary.
                    let y = Fp::conditional_select(
                        &y,
                        &-y,
                        y.lexicographically_largest() ^ sort_flag_set,
                    );

                    CtOption::new(
                        G1Affine {
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
    }

    /// Returns true if this element is the identity (the point at infinity).
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }

    /// Returns true if this point is free of an $h$-torsion component, and so it
    /// exists within the $q$-order subgroup $\mathbb{G}_1$. This should always return true
    /// unless an "unchecked" API was used.
    pub fn is_torsion_free(&self) -> Choice {
        const FQ_MODULUS_BYTES: [u8; 32] = [
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
        ];

        // Clear the r-torsion from the point and check if it is the identity
        G1Projective::from(*self)
            .multiply(&FQ_MODULUS_BYTES)
            .is_identity()
    }

    /// Returns true if this point is on the curve. This should always return
    /// true unless an "unchecked" API was used.
    pub fn is_on_curve(&self) -> Choice {
        // y^2 - x^3 ?= 4
        (self.y.square() - (self.x.square() * self.x)).ct_eq(&B) | self.infinity
    }
}

/// This is an element of $\mathbb{G}_1$ represented in the projective coordinate space.
#[derive(Copy, Clone, Debug)]
pub struct G1Projective {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl<'a> From<&'a G1Affine> for G1Projective {
    fn from(p: &'a G1Affine) -> G1Projective {
        G1Projective {
            x: p.x,
            y: p.y,
            z: Fp::conditional_select(&Fp::one(), &Fp::zero(), p.infinity),
        }
    }
}

impl From<G1Affine> for G1Projective {
    fn from(p: G1Affine) -> G1Projective {
        G1Projective::from(&p)
    }
}

impl ConstantTimeEq for G1Projective {
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

impl ConditionallySelectable for G1Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G1Projective {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Eq for G1Projective {}
impl PartialEq for G1Projective {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn neg(self) -> G1Projective {
        G1Projective {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Neg for G1Projective {
    type Output = G1Projective;

    #[inline]
    fn neg(self) -> G1Projective {
        -&self
    }
}

impl<'a, 'b> Add<&'b G1Projective> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn add(self, rhs: &'b G1Projective) -> G1Projective {
        self.add(rhs)
    }
}

impl<'a, 'b> Sub<&'b G1Projective> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn sub(self, rhs: &'b G1Projective) -> G1Projective {
        self + (-rhs)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G1Projective {
    type Output = G1Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        self.multiply(&other.to_bytes())
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G1Affine {
    type Output = G1Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        G1Projective::from(self).multiply(&other.to_bytes())
    }
}

impl_binops_additive!(G1Projective, G1Projective);
impl_binops_multiplicative!(G1Projective, Scalar);
impl_binops_multiplicative_mixed!(G1Affine, Scalar, G1Projective);

impl G1Projective {
    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> G1Projective {
        G1Projective {
            x: Fp::zero(),
            y: Fp::one(),
            z: Fp::zero(),
        }
    }

    /// Returns a fixed generator of the group. See [`notes::design`](notes/design/index.html#fixed-generators)
    /// for how this generator is chosen.
    pub fn generator() -> G1Projective {
        G1Projective {
            x: Fp::from_raw_unchecked([
                0x5cb3_8790_fd53_0c16,
                0x7817_fc67_9976_fff5,
                0x154f_95c7_143b_a1c1,
                0xf0ae_6acd_f3d0_e747,
                0xedce_6ecc_21db_f440,
                0x1201_7741_9e0b_fb75,
            ]),
            y: Fp::from_raw_unchecked([
                0xbaac_93d5_0ce7_2271,
                0x8c22_631a_7918_fd8e,
                0xdd59_5f13_5707_25ce,
                0x51ac_5829_5040_5194,
                0x0e1c_8c3f_ad00_59c0,
                0x0bbc_3efc_5008_a26a,
            ]),
            z: Fp::one(),
        }
    }

    /// Computes the doubling of this point.
    pub fn double(&self) -> G1Projective {
        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
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

        let tmp = G1Projective {
            x: x3,
            y: y3,
            z: z3,
        };

        G1Projective::conditional_select(&tmp, &G1Projective::identity(), self.is_identity())
    }

    /// Adds this point to another point.
    pub fn add(&self, rhs: &G1Projective) -> G1Projective {
        // This Jacobian point addition technique is based on the implementation in libsecp256k1,
        // which assumes that rhs has z=1. Let's address the case of zero z-coordinates generally.

        // If self is the identity, return rhs. Otherwise, return self. The other cases will be
        // predicated on neither self nor rhs being the identity.
        let f1 = self.is_identity();
        let res = G1Projective::conditional_select(self, rhs, f1);
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
            G1Projective::conditional_select(&res, &G1Projective::identity(), (!f1) & (!f2) & f3);

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
        let rr_alt = Fp::conditional_select(&rr_alt, &rr, !degenerate);
        let m_alt = Fp::conditional_select(&m_alt, &m, !degenerate);

        let n = m_alt.square();
        let q = n * t;

        let n = n.square();
        let n = Fp::conditional_select(&n, &m, degenerate);
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

        let tmp = G1Projective {
            x: x3,
            y: y3,
            z: z3,
        };

        G1Projective::conditional_select(&res, &tmp, (!f1) & (!f2) & (!f3))
    }

    /// Adds this point to another point in the affine model.
    pub fn add_mixed(&self, rhs: &G1Affine) -> G1Projective {
        // This Jacobian point addition technique is based on the implementation in libsecp256k1,
        // which assumes that rhs has z=1. Let's address the case of zero z-coordinates generally.

        // If self is the identity, return rhs. Otherwise, return self. The other cases will be
        // predicated on neither self nor rhs being the identity.
        let f1 = self.is_identity();
        let res = G1Projective::conditional_select(self, &G1Projective::from(rhs), f1);
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
            G1Projective::conditional_select(&res, &G1Projective::identity(), (!f1) & (!f2) & f3);

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
        let rr_alt = Fp::conditional_select(&rr_alt, &rr, !degenerate);
        let m_alt = Fp::conditional_select(&m_alt, &m, !degenerate);

        let n = m_alt.square();
        let q = n * t;

        let n = n.square();
        let n = Fp::conditional_select(&n, &m, degenerate);
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

        let tmp = G1Projective {
            x: x3,
            y: y3,
            z: z3,
        };

        G1Projective::conditional_select(&res, &tmp, (!f1) & (!f2) & (!f3))
    }

    fn multiply(&self, by: &[u8; 32]) -> G1Projective {
        let mut acc = G1Projective::identity();

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
            acc = G1Projective::conditional_select(&acc, &(acc + self), bit);
        }

        acc
    }

    /// Converts a batch of `G1Projective` elements into `G1Affine` elements. This
    /// function will panic if `p.len() != q.len()`.
    pub fn batch_normalize(p: &[Self], q: &mut [G1Affine]) {
        assert_eq!(p.len(), q.len());

        let mut acc = Fp::one();
        for (p, q) in p.iter().zip(q.iter_mut()) {
            // We use the `x` field of `G1Affine` to store the product
            // of previous z-coordinates seen.
            q.x = acc;

            // We will end up skipping all identities in p
            acc = Fp::conditional_select(&(acc * p.z), &acc, p.is_identity());
        }

        // This is the inverse, as all z-coordinates are nonzero and the ones
        // that are not are skipped.
        acc = acc.invert().unwrap();

        for (p, q) in p.iter().rev().zip(q.iter_mut().rev()) {
            let skip = p.is_identity();

            // Compute tmp = 1/z
            let tmp = q.x * acc;

            // Cancel out z-coordinate in denominator of `acc`
            acc = Fp::conditional_select(&(acc * p.z), &acc, skip);

            // Set the coordinates to the correct value
            let tmp2 = tmp.square();
            let tmp3 = tmp2 * tmp;

            q.x = p.x * tmp2;
            q.y = p.y * tmp3;
            q.infinity = Choice::from(0u8);

            *q = G1Affine::conditional_select(&q, &G1Affine::identity(), skip);
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
        // Y^2 - X^3 = 4(Z^6)

        (self.y.square() - (self.x.square() * self.x))
            .ct_eq(&((self.z.square() * self.z).square() * B))
            | self.z.is_zero()
    }
}

#[test]
fn test_is_on_curve() {
    assert!(bool::from(G1Affine::identity().is_on_curve()));
    assert!(bool::from(G1Affine::generator().is_on_curve()));
    assert!(bool::from(G1Projective::identity().is_on_curve()));
    assert!(bool::from(G1Projective::generator().is_on_curve()));

    let z = Fp::from_raw_unchecked([
        0xba7a_fa1f_9a6f_e250,
        0xfa0f_5b59_5eaf_e731,
        0x3bdc_4776_94c3_06e7,
        0x2149_be4b_3949_fa24,
        0x64aa_6e06_49b2_078c,
        0x12b1_08ac_3364_3c3e,
    ]);

    let gen = G1Affine::generator();
    let mut test = G1Projective {
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
    let a = G1Affine::generator();
    let b = G1Affine::identity();

    assert!(a == a);
    assert!(b == b);
    assert!(a != b);
    assert!(b != a);
}

#[test]
#[allow(clippy::eq_op)]
fn test_projective_point_equality() {
    let a = G1Projective::generator();
    let b = G1Projective::identity();

    assert!(a == a);
    assert!(b == b);
    assert!(a != b);
    assert!(b != a);

    let z = Fp::from_raw_unchecked([
        0xba7a_fa1f_9a6f_e250,
        0xfa0f_5b59_5eaf_e731,
        0x3bdc_4776_94c3_06e7,
        0x2149_be4b_3949_fa24,
        0x64aa_6e06_49b2_078c,
        0x12b1_08ac_3364_3c3e,
    ]);

    let mut c = G1Projective {
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
    let a = G1Affine::generator();
    let b = G1Affine::identity();

    assert_eq!(G1Affine::conditional_select(&a, &b, Choice::from(0u8)), a);
    assert_eq!(G1Affine::conditional_select(&a, &b, Choice::from(1u8)), b);
}

#[test]
fn test_conditionally_select_projective() {
    let a = G1Projective::generator();
    let b = G1Projective::identity();

    assert_eq!(
        G1Projective::conditional_select(&a, &b, Choice::from(0u8)),
        a
    );
    assert_eq!(
        G1Projective::conditional_select(&a, &b, Choice::from(1u8)),
        b
    );
}

#[test]
fn test_projective_to_affine() {
    let a = G1Projective::generator();
    let b = G1Projective::identity();

    assert!(bool::from(G1Affine::from(a).is_on_curve()));
    assert!(!bool::from(G1Affine::from(a).is_identity()));
    assert!(bool::from(G1Affine::from(b).is_on_curve()));
    assert!(bool::from(G1Affine::from(b).is_identity()));

    let z = Fp::from_raw_unchecked([
        0xba7a_fa1f_9a6f_e250,
        0xfa0f_5b59_5eaf_e731,
        0x3bdc_4776_94c3_06e7,
        0x2149_be4b_3949_fa24,
        0x64aa_6e06_49b2_078c,
        0x12b1_08ac_3364_3c3e,
    ]);

    let c = G1Projective {
        x: a.x * (z.square()),
        y: a.y * (z.square() * z),
        z,
    };

    assert_eq!(G1Affine::from(c), G1Affine::generator());
}

#[test]
fn test_affine_to_projective() {
    let a = G1Affine::generator();
    let b = G1Affine::identity();

    assert!(bool::from(G1Projective::from(a).is_on_curve()));
    assert!(!bool::from(G1Projective::from(a).is_identity()));
    assert!(bool::from(G1Projective::from(b).is_on_curve()));
    assert!(bool::from(G1Projective::from(b).is_identity()));
}

#[test]
fn test_doubling() {
    {
        let tmp = G1Projective::identity().double();
        assert!(bool::from(tmp.is_identity()));
        assert!(bool::from(tmp.is_on_curve()));
    }
    {
        let tmp = G1Projective::generator().double();
        assert!(!bool::from(tmp.is_identity()));
        assert!(bool::from(tmp.is_on_curve()));

        assert_eq!(
            G1Affine::from(tmp),
            G1Affine {
                x: Fp::from_raw_unchecked([
                    0x53e9_78ce_58a9_ba3c,
                    0x3ea0_583c_4f3d_65f9,
                    0x4d20_bb47_f001_2960,
                    0xa54c_664a_e5b2_b5d9,
                    0x26b5_52a3_9d7e_b21f,
                    0x0008_895d_26e6_8785,
                ]),
                y: Fp::from_raw_unchecked([
                    0x7011_0b32_9829_3940,
                    0xda33_c539_3f1f_6afc,
                    0xb86e_dfd1_6a5a_a785,
                    0xaec6_d1c9_e7b1_c895,
                    0x25cf_c2b5_22d1_1720,
                    0x0636_1c83_f8d0_9b15,
                ]),
                infinity: Choice::from(0u8)
            }
        );
    }
}

#[test]
fn test_projective_addition() {
    {
        let a = G1Projective::identity();
        let b = G1Projective::identity();
        let c = a + b;
        assert!(bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
    {
        let a = G1Projective::identity();
        let mut b = G1Projective::generator();
        {
            let z = Fp::from_raw_unchecked([
                0xba7a_fa1f_9a6f_e250,
                0xfa0f_5b59_5eaf_e731,
                0x3bdc_4776_94c3_06e7,
                0x2149_be4b_3949_fa24,
                0x64aa_6e06_49b2_078c,
                0x12b1_08ac_3364_3c3e,
            ]);

            b = G1Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = a + b;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G1Projective::generator());
    }
    {
        let a = G1Projective::identity();
        let mut b = G1Projective::generator();
        {
            let z = Fp::from_raw_unchecked([
                0xba7a_fa1f_9a6f_e250,
                0xfa0f_5b59_5eaf_e731,
                0x3bdc_4776_94c3_06e7,
                0x2149_be4b_3949_fa24,
                0x64aa_6e06_49b2_078c,
                0x12b1_08ac_3364_3c3e,
            ]);

            b = G1Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = b + a;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G1Projective::generator());
    }
    {
        let a = G1Projective::generator().double().double(); // 4P
        let b = G1Projective::generator().double(); // 2P
        let c = a + b;

        let mut d = G1Projective::generator();
        for _ in 0..5 {
            d += G1Projective::generator();
        }
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(!bool::from(d.is_identity()));
        assert!(bool::from(d.is_on_curve()));
        assert_eq!(c, d);
    }

    // Degenerate case
    {
        let beta = Fp::from_raw_unchecked([
            0xcd03_c9e4_8671_f071,
            0x5dab_2246_1fcd_a5d2,
            0x5870_42af_d385_1b95,
            0x8eb6_0ebe_01ba_cb9e,
            0x03f9_7d6e_83d0_50d2,
            0x18f0_2065_5463_8741,
        ]);
        let beta = beta.square();
        let a = G1Projective::generator().double().double();
        let b = G1Projective {
            x: a.x * beta,
            y: -a.y,
            z: a.z,
        };
        assert!(bool::from(a.is_on_curve()));
        assert!(bool::from(b.is_on_curve()));

        let c = a + b;
        assert_eq!(
            G1Affine::from(c),
            G1Affine::from(G1Projective {
                x: Fp::from_raw_unchecked([
                    0x29e1_e987_ef68_f2d0,
                    0xc5f3_ec53_1db0_3233,
                    0xacd6_c4b6_ca19_730f,
                    0x18ad_9e82_7bc2_bab7,
                    0x46e3_b2c5_785c_c7a9,
                    0x07e5_71d4_2d22_ddd6,
                ]),
                y: Fp::from_raw_unchecked([
                    0x94d1_17a7_e5a5_39e7,
                    0x8e17_ef67_3d4b_5d22,
                    0x9d74_6aaf_508a_33ea,
                    0x8c6d_883d_2516_c9a2,
                    0x0bc3_b8d5_fb04_47f7,
                    0x07bf_a4c7_210f_4f44,
                ]),
                z: Fp::one()
            })
        );
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
}

#[test]
fn test_mixed_addition() {
    {
        let a = G1Affine::identity();
        let b = G1Projective::identity();
        let c = a + b;
        assert!(bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
    {
        let a = G1Affine::identity();
        let mut b = G1Projective::generator();
        {
            let z = Fp::from_raw_unchecked([
                0xba7a_fa1f_9a6f_e250,
                0xfa0f_5b59_5eaf_e731,
                0x3bdc_4776_94c3_06e7,
                0x2149_be4b_3949_fa24,
                0x64aa_6e06_49b2_078c,
                0x12b1_08ac_3364_3c3e,
            ]);

            b = G1Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = a + b;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G1Projective::generator());
    }
    {
        let a = G1Affine::identity();
        let mut b = G1Projective::generator();
        {
            let z = Fp::from_raw_unchecked([
                0xba7a_fa1f_9a6f_e250,
                0xfa0f_5b59_5eaf_e731,
                0x3bdc_4776_94c3_06e7,
                0x2149_be4b_3949_fa24,
                0x64aa_6e06_49b2_078c,
                0x12b1_08ac_3364_3c3e,
            ]);

            b = G1Projective {
                x: b.x * (z.square()),
                y: b.y * (z.square() * z),
                z,
            };
        }
        let c = b + a;
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(c == G1Projective::generator());
    }
    {
        let a = G1Projective::generator().double().double(); // 4P
        let b = G1Projective::generator().double(); // 2P
        let c = a + b;

        let mut d = G1Projective::generator();
        for _ in 0..5 {
            d += G1Affine::generator();
        }
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
        assert!(!bool::from(d.is_identity()));
        assert!(bool::from(d.is_on_curve()));
        assert_eq!(c, d);
    }

    // Degenerate case
    {
        let beta = Fp::from_raw_unchecked([
            0xcd03_c9e4_8671_f071,
            0x5dab_2246_1fcd_a5d2,
            0x5870_42af_d385_1b95,
            0x8eb6_0ebe_01ba_cb9e,
            0x03f9_7d6e_83d0_50d2,
            0x18f0_2065_5463_8741,
        ]);
        let beta = beta.square();
        let a = G1Projective::generator().double().double();
        let b = G1Projective {
            x: a.x * beta,
            y: -a.y,
            z: a.z,
        };
        let a = G1Affine::from(a);
        assert!(bool::from(a.is_on_curve()));
        assert!(bool::from(b.is_on_curve()));

        let c = a + b;
        assert_eq!(
            G1Affine::from(c),
            G1Affine::from(G1Projective {
                x: Fp::from_raw_unchecked([
                    0x29e1_e987_ef68_f2d0,
                    0xc5f3_ec53_1db0_3233,
                    0xacd6_c4b6_ca19_730f,
                    0x18ad_9e82_7bc2_bab7,
                    0x46e3_b2c5_785c_c7a9,
                    0x07e5_71d4_2d22_ddd6,
                ]),
                y: Fp::from_raw_unchecked([
                    0x94d1_17a7_e5a5_39e7,
                    0x8e17_ef67_3d4b_5d22,
                    0x9d74_6aaf_508a_33ea,
                    0x8c6d_883d_2516_c9a2,
                    0x0bc3_b8d5_fb04_47f7,
                    0x07bf_a4c7_210f_4f44,
                ]),
                z: Fp::one()
            })
        );
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_on_curve()));
    }
}

#[test]
#[allow(clippy::eq_op)]
fn test_projective_negation_and_subtraction() {
    let a = G1Projective::generator().double();
    assert_eq!(a + (-a), G1Projective::identity());
    assert_eq!(a + (-a), a - a);
}

#[test]
fn test_affine_negation_and_subtraction() {
    let a = G1Affine::generator();
    assert_eq!(G1Projective::from(a) + (-a), G1Projective::identity());
    assert_eq!(G1Projective::from(a) + (-a), G1Projective::from(a) - a);
}

#[test]
fn test_projective_scalar_multiplication() {
    let g = G1Projective::generator();
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
    let g = G1Affine::generator();
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

    assert_eq!(G1Affine::from(g * a) * b, g * c);
}

#[test]
fn test_is_torsion_free() {
    let a = G1Affine {
        x: Fp::from_raw_unchecked([
            0x0aba_f895_b97e_43c8,
            0xba4c_6432_eb9b_61b0,
            0x1250_6f52_adfe_307f,
            0x7502_8c34_3933_6b72,
            0x8474_4f05_b8e9_bd71,
            0x113d_554f_b095_54f7,
        ]),
        y: Fp::from_raw_unchecked([
            0x73e9_0e88_f5cf_01c0,
            0x3700_7b65_dd31_97e2,
            0x5cf9_a199_2f0d_7c78,
            0x4f83_c10b_9eb3_330d,
            0xf6a6_3f6f_07f6_0961,
            0x0c53_b5b9_7e63_4df3,
        ]),
        infinity: Choice::from(0u8),
    };
    assert!(!bool::from(a.is_torsion_free()));

    assert!(bool::from(G1Affine::identity().is_torsion_free()));
    assert!(bool::from(G1Affine::generator().is_torsion_free()));
}

#[test]
fn test_batch_normalize() {
    let a = G1Projective::generator().double();
    let b = a.double();
    let c = b.double();

    for a_identity in (0..1).map(|n| n == 1) {
        for b_identity in (0..1).map(|n| n == 1) {
            for c_identity in (0..1).map(|n| n == 1) {
                let mut v = [a, b, c];
                if a_identity {
                    v[0] = G1Projective::identity()
                }
                if b_identity {
                    v[1] = G1Projective::identity()
                }
                if c_identity {
                    v[2] = G1Projective::identity()
                }

                let mut t = [
                    G1Affine::identity(),
                    G1Affine::identity(),
                    G1Affine::identity(),
                ];
                let expected = [
                    G1Affine::from(v[0]),
                    G1Affine::from(v[1]),
                    G1Affine::from(v[2]),
                ];

                G1Projective::batch_normalize(&v[..], &mut t[..]);

                assert_eq!(&t[..], &expected[..]);
            }
        }
    }
}
