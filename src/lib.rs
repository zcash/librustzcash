#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
extern crate byteorder;
extern crate subtle;

use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign, MulAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[macro_use]
mod util;

mod fq;
mod fr;
pub use self::fq::*;
pub use self::fr::*;

/// This represents an affine point `(u, v)` on the
/// curve `-u^2 + v^2 = 1 + d.u^2.v^2` over `Fq` with
/// `d = -(10240/10241)`.
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    u: Fq,
    v: Fq,
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    #[inline]
    fn neg(self) -> AffinePoint {
        AffinePoint {
            u: -self.u,
            v: self.v,
        }
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.u.ct_eq(&other.u) & self.v.ct_eq(&other.v)
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        AffinePoint {
            u: Fq::conditional_select(&a.u, &b.u, choice),
            v: Fq::conditional_select(&a.v, &b.v, choice),
        }
    }
}

/// Represents the affine point `(u/z, v/z)` with
/// `z` nonzero and `t1 * t2 = uv/z`.
#[derive(Clone, Copy, Debug)]
pub struct ExtendedPoint {
    u: Fq,
    v: Fq,
    z: Fq,
    t1: Fq,
    t2: Fq,
}

impl ConstantTimeEq for ExtendedPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        // (u/z, v/z) = (u'/z', v'/z') implies
        //      (uz'z = u'z'z)
        //      (vz'z = v'z'z)

        (&self.u * &other.z).ct_eq(&(&other.u * &self.z))
            & (&self.v * &other.z).ct_eq(&(&other.v * &self.z))
    }
}

impl ConditionallySelectable for ExtendedPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedPoint {
            u: Fq::conditional_select(&a.u, &b.u, choice),
            v: Fq::conditional_select(&a.v, &b.v, choice),
            z: Fq::conditional_select(&a.z, &b.z, choice),
            t1: Fq::conditional_select(&a.t1, &b.t1, choice),
            t2: Fq::conditional_select(&a.t2, &b.t2, choice),
        }
    }
}

impl PartialEq for ExtendedPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl Neg for ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn neg(self) -> ExtendedPoint {
        ExtendedPoint {
            u: -self.u,
            v: self.v,
            z: self.z,
            t1: -self.t1,
            t2: self.t2,
        }
    }
}

impl From<AffinePoint> for ExtendedPoint {
    fn from(affine: AffinePoint) -> ExtendedPoint {
        ExtendedPoint {
            u: affine.u,
            v: affine.v,
            z: Fq::one(),
            t1: affine.u,
            t2: affine.v,
        }
    }
}

impl From<ExtendedPoint> for AffinePoint {
    fn from(extended: ExtendedPoint) -> AffinePoint {
        // Z coordinate is always nonzero, so this is
        // its inverse.
        let zinv = extended.z.invert_nonzero();

        AffinePoint {
            u: extended.u * &zinv,
            v: extended.v * &zinv,
        }
    }
}

#[derive(Clone, Copy)]
pub struct AffineNielsPoint {
    v_plus_u: Fq,
    v_minus_u: Fq,
    t2d: Fq,
}

impl AffineNielsPoint {
    pub fn identity() -> Self {
        AffineNielsPoint {
            v_plus_u: Fq::one(),
            v_minus_u: Fq::one(),
            t2d: Fq::zero(),
        }
    }
}

impl ConditionallySelectable for AffineNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        AffineNielsPoint {
            v_plus_u: Fq::conditional_select(&a.v_plus_u, &b.v_plus_u, choice),
            v_minus_u: Fq::conditional_select(&a.v_minus_u, &b.v_minus_u, choice),
            t2d: Fq::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

#[derive(Clone, Copy)]
pub struct ExtendedNielsPoint {
    v_plus_u: Fq,
    v_minus_u: Fq,
    z: Fq,
    t2d: Fq,
}

impl ConditionallySelectable for ExtendedNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedNielsPoint {
            v_plus_u: Fq::conditional_select(&a.v_plus_u, &b.v_plus_u, choice),
            v_minus_u: Fq::conditional_select(&a.v_minus_u, &b.v_minus_u, choice),
            z: Fq::conditional_select(&a.z, &b.z, choice),
            t2d: Fq::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

impl ExtendedNielsPoint {
    pub fn identity() -> Self {
        ExtendedNielsPoint {
            v_plus_u: Fq::one(),
            v_minus_u: Fq::one(),
            z: Fq::one(),
            t2d: Fq::zero(),
        }
    }
}

// `d = -(10240/10241)`
#[allow(dead_code)]
const EDWARDS_D: Fq = Fq([
    0x2a522455b974f6b0,
    0xfc6cc9ef0d9acab3,
    0x7a08fb94c27628d1,
    0x57f8f6a8fe0e262e,
]);

// `2*d`
#[allow(dead_code)]
const EDWARDS_D2: Fq = Fq([
    0x54a448ac72e9ed5f,
    0xa51befdb1b373967,
    0xc0d81f217b4a799e,
    0x3c0445fed27ecf14,
]);

impl AffinePoint {
    /// Returns the neutral element `(0, 1)`.
    pub fn identity() -> Self {
        AffinePoint {
            u: Fq::zero(),
            v: Fq::one(),
        }
    }

    /// Converts this element into its byte representation.
    pub fn into_bytes(&self) -> [u8; 32] {
        let mut tmp = self.v.into_bytes();
        let u = self.u.into_bytes();

        // Encode the sign of the u-coordinate in the most
        // significant bit.
        tmp[31] |= u[0] << 7;

        tmp
    }

    /// Attempts to interpret a byte representation of an
    /// affine point, failing if the element is not on
    /// the curve or non-canonical.
    ///
    /// **This operation is variable time.**
    pub fn from_bytes_vartime(mut b: [u8; 32]) -> Option<Self> {
        // Grab the sign bit from the representation
        let sign = b[31] >> 7;

        // Mask away the sign bit
        b[31] &= 0b01111_1111;

        // Interpret what remains as the v-coordinate
        match Fq::from_bytes_vartime(b) {
            Some(v) => {
                // -u^2 + v^2 = 1 + d.u^2.v^2
                // -u^2 = 1 + d.u^2.v^2 - v^2    (rearrange)
                // -u^2 - d.u^2.v^2 = 1 - v^2    (rearrange)
                // u^2 + d.u^2.v^2 = v^2 - 1     (flip signs)
                // u^2 (1 + d.v^2) = v^2 - 1     (factor)
                // u^2 = (v^2 - 1) / (1 + d.v^2) (isolate u^2)
                // We know that (1 + d.v^2) is nonzero for all v:
                //   (1 + d.v^2) = 0
                //   d.v^2 = -1
                //   v^2 = -(1 / d)   No solutions, as -(1 / d) is not a square

                let v2 = v.square();

                match ((v2 - Fq::one()) * (Fq::one() + EDWARDS_D * &v2).invert_nonzero())
                    .sqrt_vartime()
                {
                    Some(mut u) => {
                        // Fix the sign of `u` if necessary
                        if (u.into_bytes()[0] & 1) != sign {
                            u = -u;
                        }

                        Some(AffinePoint { u, v })
                    }
                    None => None,
                }
            }
            None => None,
        }
    }

    pub fn get_u(&self) -> Fq {
        self.u
    }

    pub fn get_v(&self) -> Fq {
        self.v
    }

    pub fn to_niels(&self) -> AffineNielsPoint {
        AffineNielsPoint {
            v_plus_u: &self.v + &self.u,
            v_minus_u: &self.v - &self.u,
            t2d: &self.u * &self.v * EDWARDS_D2,
        }
    }

    /// This is only for debugging purposes and not
    /// exposed in the public API. Checks that this
    /// point is on the curve.
    #[cfg(test)]
    fn is_on_curve_vartime(&self) -> bool {
        let u2 = self.u.square();
        let v2 = self.v.square();

        &v2 - &u2 == Fq::one() + &EDWARDS_D * &u2 * &v2
    }
}

impl ExtendedPoint {
    pub fn identity() -> Self {
        ExtendedPoint {
            u: Fq::zero(),
            v: Fq::one(),
            z: Fq::one(),
            t1: Fq::zero(),
            t2: Fq::zero(),
        }
    }

    pub fn mul_by_cofactor(&self) -> ExtendedPoint {
        self.double().double().double()
    }

    pub fn to_niels(&self) -> ExtendedNielsPoint {
        ExtendedNielsPoint {
            v_plus_u: &self.v + &self.u,
            v_minus_u: &self.v - &self.u,
            z: self.z,
            t2d: &self.t1 * &self.t2 * EDWARDS_D2,
        }
    }

    pub fn double(&self) -> ExtendedPoint {
        // Doubling is more efficient (three multiplications, four squarings)
        // when we work within the projective coordinate space (U:Z, V:Z). We
        // rely on the most efficient formula, "dbl-2008-bbjlp", as described
        // in Section 6 of "Twisted Edwards Curves" by Bernstein et al.
        //
        // See <https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp>
        // for more information.
        //
        // We differ from the literature in that we use (u, v) rather than
        // (x, y) coordinates. We also have the constant `a = -1` implied. Let
        // us rewrite the procedure of doubling (u, v, z) to produce (U, V, Z)
        // as follows:
        //
        // B = (u + v)^2
        // C = u^2
        // D = v^2
        // F = D - C
        // H = 2 * z^2
        // J = F - H
        // U = (B - C - D) * J
        // V = F * (- C - D)
        // Z = F * J
        //
        // If we compute K = D + C, we can rewrite this:
        //
        // B = (u + v)^2
        // C = u^2
        // D = v^2
        // F = D - C
        // K = D + C
        // H = 2 * z^2
        // J = F - H
        // U = (B - K) * J
        // V = F * (-K)
        // Z = F * J
        //
        // In order to avoid the unnecessary negation of K,
        // we will negate J, transforming the result into
        // an equivalent point with a negated z-coordinate.
        //
        // B = (u + v)^2
        // C = u^2
        // D = v^2
        // F = D - C
        // K = D + C
        // H = 2 * z^2
        // J = H - F
        // U = (B - K) * J
        // V = F * K
        // Z = F * J
        //
        // Let us rename some variables to simplify:
        //
        // UV2 = (u + v)^2
        // UU = u^2
        // VV = v^2
        // VVmUU = VV - UU
        // VVpUU = VV + UU
        // ZZ2 = 2 * z^2
        // J = ZZ2 - VVmUU
        // U = (UV2 - VVpUU) * J
        // V = VVmUU * VVpUU
        // Z = VVmUU * J
        //
        // We wish to obtain two factors of T = UV/Z.
        //
        // UV/Z = (UV2 - VVpUU) * (ZZ2 - VVmUU) * VVmUU * VVpUU / VVmUU / (ZZ2 - VVmUU)
        //      = (UV2 - VVpUU) * VVmUU * VVpUU / VVmUU
        //      = (UV2 - VVpUU) * VVpUU
        //
        // and so we have that T1 = (UV2 - VVpUU) and T2 = VVpUU.

        let uu = self.u.square();
        let vv = self.v.square();
        let zz2 = self.z.square().double();
        let uv2 = (&self.u + &self.v).square();
        let vv_plus_uu = &vv + &uu;
        let vv_minus_uu = &vv - &uu;

        // The remaining arithmetic is exactly the process of converting
        // from a completed point to an extended point.
        CompletedPoint {
            u: &uv2 - &vv_plus_uu,
            v: vv_plus_uu,
            z: vv_minus_uu,
            t: &zz2 - &vv_minus_uu,
        }.into_extended()
    }

    /// This is only for debugging purposes and not
    /// exposed in the public API. Checks that this
    /// point is on the curve.
    #[cfg(test)]
    fn is_on_curve_vartime(&self) -> bool {
        let affine = AffinePoint::from(*self);

        self.z != Fq::zero() &&
            affine.is_on_curve_vartime() &&
            (affine.u * affine.v * self.z == self.t1 * self.t2)
    }
}

// TODO: switch to Fr
impl<'a, 'b> Mul<&'b Fq> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn mul(self, other: &'b Fq) -> ExtendedPoint {
        let zero = ExtendedPoint::identity().to_niels();
        let base = self.to_niels();

        let mut acc = ExtendedPoint::identity();

        for bit in other
            .into_bytes()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8)))
            .skip(4)
        {
            acc = acc.double();
            acc = acc + ExtendedNielsPoint::conditional_select(&zero, &base, bit);
        }

        acc
    }
}

// TODO: change to Fr
impl_binops_multiplicative!(ExtendedPoint, Fq);

impl<'a, 'b> Add<&'b ExtendedNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn add(self, other: &'b ExtendedNielsPoint) -> ExtendedPoint {
        // We perform addition in the extended coordinates. Here we use
        // a formula presented by Hisil, Wong, Carter and Dawson in
        // "Twisted Edward Curves Revisited" which only requires 8M.
        //
        // A = (V1 - U1) * (V2 - U2)
        // B = (V1 + U1) * (V2 + U2)
        // C = 2d * T1 * T2
        // D = 2 * Z1 * Z2
        // E = B - A
        // F = D - C
        // G = D + C
        // H = B + A
        // U3 = E * F
        // Y3 = G * H
        // Z3 = F * G
        // T3 = E * H

        let a = (&self.v - &self.u) * &other.v_minus_u;
        let b = (&self.v + &self.u) * &other.v_plus_u;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = (&self.z * &other.z).double();

        // The remaining arithmetic is exactly the process of converting
        // from a completed point to an extended point.
        CompletedPoint {
            u: &b - &a,
            v: &b + &a,
            z: &d + &c,
            t: &d - &c,
        }.into_extended()
    }
}

impl<'a, 'b> Sub<&'b ExtendedNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn sub(self, other: &'b ExtendedNielsPoint) -> ExtendedPoint {
        let a = (&self.v - &self.u) * &other.v_plus_u;
        let b = (&self.v + &self.u) * &other.v_minus_u;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = (&self.z * &other.z).double();

        CompletedPoint {
            u: &b - &a,
            v: &b + &a,
            z: &d - &c,
            t: &d + &c,
        }.into_extended()
    }
}

impl_binops_additive!(ExtendedPoint, ExtendedNielsPoint);

impl<'a, 'b> Add<&'b AffineNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn add(self, other: &'b AffineNielsPoint) -> ExtendedPoint {
        // This is identical to the addition formula for `ExtendedNielsPoint`,
        // except we can assume that `other.z` is one, so that we perform
        // 7 multiplications.

        let a = (&self.v - &self.u) * &other.v_minus_u;
        let b = (&self.v + &self.u) * &other.v_plus_u;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = self.z.double();

        // The remaining arithmetic is exactly the process of converting
        // from a completed point to an extended point.
        CompletedPoint {
            u: &b - &a,
            v: &b + &a,
            z: &d + &c,
            t: &d - &c,
        }.into_extended()
    }
}

impl<'a, 'b> Sub<&'b AffineNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn sub(self, other: &'b AffineNielsPoint) -> ExtendedPoint {
        let a = (&self.v - &self.u) * &other.v_plus_u;
        let b = (&self.v + &self.u) * &other.v_minus_u;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = self.z.double();

        CompletedPoint {
            u: &b - &a,
            v: &b + &a,
            z: &d - &c,
            t: &d + &c,
        }.into_extended()
    }
}

impl_binops_additive!(ExtendedPoint, AffineNielsPoint);

impl<'a, 'b> Add<&'b ExtendedPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn add(self, other: &'b ExtendedPoint) -> ExtendedPoint {
        self + other.to_niels()
    }
}

impl<'a, 'b> Sub<&'b ExtendedPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn sub(self, other: &'b ExtendedPoint) -> ExtendedPoint {
        self - other.to_niels()
    }
}

impl_binops_additive!(ExtendedPoint, ExtendedPoint);

/// This is a "completed" point produced during a point doubling or
/// addition routine. These points exist in the `(U:Z, V:T)` model
/// of the curve.
struct CompletedPoint {
    u: Fq,
    v: Fq,
    z: Fq,
    t: Fq,
}

impl CompletedPoint {
    /// This converts a completed point into an extended point by
    /// homogenizing:
    ///
    /// (u/z, v/t) = (u/z * t/t, v/t * z/z) = (ut/zt, vz/zt)
    ///
    /// The resulting T coordinate is utvz/zt = uv, and so
    /// T1 = u, T2 = v, without loss of generality.
    fn into_extended(&self) -> ExtendedPoint {
        ExtendedPoint {
            u: &self.u * &self.t,
            v: &self.v * &self.z,
            z: &self.z * &self.t,
            t1: self.u,
            t2: self.v,
        }
    }
}

impl Default for AffinePoint {
    fn default() -> AffinePoint {
        AffinePoint::identity()
    }
}

pub fn batch_normalize<'a>(v: &'a mut [ExtendedPoint]) -> impl Iterator<Item = AffinePoint> + 'a {
    let mut acc = Fq::one();
    for p in v.iter_mut() {
        // We use the `t1` field of `ExtendedPoint` to store the product
        // of previous z-coordinates seen.
        p.t1 = acc;
        acc *= &p.z;
    }

    // This is the inverse, as all z-coordinates are nonzero.
    acc = acc.invert_nonzero();

    for p in v.iter_mut().rev() {
        let mut q = *p;

        // Compute tmp = 1/z
        let tmp = q.t1 * acc;

        // Cancel out z-coordinate in denominator of `acc`
        acc *= &q.z;

        // Set the coordinates to the correct value
        q.u *= &tmp; // Multiply by 1/z
        q.v *= &tmp; // Multiply by 1/z
        q.z = Fq::one(); // z-coordinate is now one
        q.t1 = q.u;
        q.t2 = q.v;

        *p = q;
    }

    // All extended points are now normalized, but the type
    // doesn't encode this fact. Let us offer affine points
    // to the caller.

    v.iter().map(|p| AffinePoint { u: p.u, v: p.v })
}

#[test]
fn test_is_on_curve_var() {
    assert!(AffinePoint::identity().is_on_curve_vartime());
}

#[test]
fn test_d_is_non_quadratic_residue() {
    assert!(EDWARDS_D.sqrt_vartime().is_none());
    assert!((-EDWARDS_D).sqrt_vartime().is_none());
    assert!((-EDWARDS_D).invert_nonzero().sqrt_vartime().is_none());
}

#[test]
fn test_affine_niels_point_identity() {
    assert_eq!(
        AffineNielsPoint::identity().v_plus_u,
        AffinePoint::identity().to_niels().v_plus_u
    );
    assert_eq!(
        AffineNielsPoint::identity().v_minus_u,
        AffinePoint::identity().to_niels().v_minus_u
    );
    assert_eq!(
        AffineNielsPoint::identity().t2d,
        AffinePoint::identity().to_niels().t2d
    );
}

#[test]
fn test_extended_niels_point_identity() {
    assert_eq!(
        ExtendedNielsPoint::identity().v_plus_u,
        ExtendedPoint::identity().to_niels().v_plus_u
    );
    assert_eq!(
        ExtendedNielsPoint::identity().v_minus_u,
        ExtendedPoint::identity().to_niels().v_minus_u
    );
    assert_eq!(
        ExtendedNielsPoint::identity().z,
        ExtendedPoint::identity().to_niels().z
    );
    assert_eq!(
        ExtendedNielsPoint::identity().t2d,
        ExtendedPoint::identity().to_niels().t2d
    );
}

#[test]
fn test_assoc() {
    let p = ExtendedPoint::from(AffinePoint {
        u: Fq([0xc0115cb656ae4839, 0x623dc3ff81d64c26, 0x5868e739b5794f2c, 0x23bd4fbb18d39c9c]),
        v: Fq([0x7588ee6d6dd40deb, 0x9d6d7a23ebdb7c4c, 0x46462e26d4edb8c7, 0x10b4c1517ca82e9b])
    }).mul_by_cofactor();
    assert!(p.is_on_curve_vartime());

    assert_eq!(
        (p * Fq::from(1000u64)) * Fq::from(3938u64),
        p * (Fq::from(1000u64) * Fq::from(3938u64)),
    );
}

#[cfg(feature = "std")]
#[test]
fn test_batch_normalize() {
    let mut p = ExtendedPoint::from(AffinePoint {
        u: Fq([0xc0115cb656ae4839, 0x623dc3ff81d64c26, 0x5868e739b5794f2c, 0x23bd4fbb18d39c9c]),
        v: Fq([0x7588ee6d6dd40deb, 0x9d6d7a23ebdb7c4c, 0x46462e26d4edb8c7, 0x10b4c1517ca82e9b])
    }).mul_by_cofactor();

    let mut v = vec![];
    for _ in 0..10 {
        v.push(p);
        p = p.double();
    }

    for p in &v {
        assert!(p.is_on_curve_vartime());
    }

    let expected: std::vec::Vec<_> = v.iter().map(|p| AffinePoint::from(*p)).collect();
    let result1: std::vec::Vec<_> = batch_normalize(&mut v).collect();
    for i in 0..10 {
        assert!(expected[i] == result1[i]);
        assert!(v[i].is_on_curve_vartime());
        assert!(AffinePoint::from(v[i]) == expected[i]);
    }
    let result2: std::vec::Vec<_> = batch_normalize(&mut v).collect();
    for i in 0..10 {
        assert!(expected[i] == result2[i]);
        assert!(v[i].is_on_curve_vartime());
        assert!(AffinePoint::from(v[i]) == expected[i]);
    }
}
