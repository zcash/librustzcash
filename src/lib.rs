//! This crate provides an implementation of the **Jubjub** elliptic curve and its associated
//! field arithmetic. See [`README.md`](https://github.com/zkcrypto/jubjub/blob/master/README.md) for more details about Jubjub.
//!
//! # API
//!
//! * `AffinePoint` / `ExtendedPoint` which are implementations of Jubjub group arithmetic
//! * `AffineNielsPoint` / `ExtendedNielsPoint` which are pre-processed Jubjub points
//! * `Fq`, which is the base field of Jubjub
//! * `Fr`, which is the scalar field of Jubjub
//! * `batch_normalize` for converting many `ExtendedPoint`s into `AffinePoint`s efficiently.
//!
//! # Constant Time
//!
//! All operations are constant time unless explicitly noted; these functions will contain
//! "vartime" in their name and they will be documented as variable time.
//!
//! This crate relies on the `subtle` crate for achieving constant time arithmetic. It is
//! recommended to enable the `nightly` feature on this crate (which enables the `nightly`
//! feature in the `subtle` crate) to defend against compiler optimizations that may
//! compromise constant time arithmetic. However, this requires use of the nightly version
//! of the Rust compiler.
//!
//! # Features
//!
//! * `nightly`: This enables `subtle/nightly` which attempts to prevent the compiler from
//! performing optimizations that could compromise constant time arithmetic. It is
//! recommended to enable this if you are able to use a nightly version of the Rust compiler.

#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[macro_use]
mod util;

pub mod maybe;
use maybe::Maybe;

mod fq;
mod fr;
pub use fq::*;
pub use fr::*;

/// This represents a Jubjub point in the affine `(u, v)`
/// coordinates.
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    u: Fq,
    v: Fq,
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    /// This computes the negation of a point `P = (u, v)`
    /// as `-P = (-u, v)`.
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

/// This represents an extended point `(U, V, Z, T1, T2)`
/// with `Z` nonzero, corresponding to the affine point
/// `(U/Z, V/Z)`. We always have `T1 * T2 = UV/Z`.
///
/// You can do the following things with a point in this
/// form:
///
/// * Convert it into a point in the affine form.
/// * Add it to an `ExtendedPoint`, `AffineNielsPoint` or `ExtendedNielsPoint`.
/// * Double it using `double()`.
/// * Compare it with another extended point using `PartialEq` or `ct_eq()`.
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
        // (u/z, v/z) = (u'/z', v'/z') is implied by
        //      (uz'z = u'z'z) and
        //      (vz'z = v'z'z)
        // as z and z' are always nonzero.

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

    /// Computes the negation of a point `P = (U, V, Z, T)`
    /// as `-P = (-U, V, Z, -T1, T2)`. The choice of `T1`
    /// is made without loss of generality.
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
    /// Constructs an extended point (with `Z = 1`) from
    /// an affine point using the map `(u, v) => (u, v, 1, u, v)`.
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
    /// Constructs an affine point from an extended point
    /// using the map `(U, V, Z, T1, T2) => (U/Z, V/Z)`
    /// as Z is always nonzero. **This requires a field inversion
    /// and so it is recommended to perform these in a batch
    /// using [`batch_normalize`](crate::batch_normalize) instead.**
    fn from(extended: ExtendedPoint) -> AffinePoint {
        // Z coordinate is always nonzero, so this is
        // its inverse.
        let zinv = extended.z.invert().unwrap();

        AffinePoint {
            u: extended.u * &zinv,
            v: extended.v * &zinv,
        }
    }
}

/// This is a pre-processed version of an affine point `(u, v)`
/// in the form `(v + u, v - u, u * v * 2d)`. This can be added to an
/// [`ExtendedPoint`](crate::ExtendedPoint).
#[derive(Clone, Copy)]
pub struct AffineNielsPoint {
    v_plus_u: Fq,
    v_minus_u: Fq,
    t2d: Fq,
}

impl AffineNielsPoint {
    /// Constructs this point from the neutral element `(0, 1)`.
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

/// This is a pre-processed version of an extended point `(U, V, Z, T1, T2)`
/// in the form `(V + U, V - U, Z, T1 * T2 * 2d)`.
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
    /// Constructs this point from the neutral element `(0, 1)`.
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
    /// Constructs the neutral element `(0, 1)`.
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
    pub fn from_bytes(mut b: [u8; 32]) -> Maybe<Self> {
        // Grab the sign bit from the representation
        let sign = b[31] >> 7;

        // Mask away the sign bit
        b[31] &= 0b01111_1111;

        // Interpret what remains as the v-coordinate
        Fq::from_bytes(b).and_then(|v| {
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

            ((v2 - Fq::one()) * (Fq::one() + EDWARDS_D * &v2).invert().unwrap())
            .sqrt().and_then(|u| {
                // Fix the sign of `u` if necessary
                let flip_sign = Choice::from((u.into_bytes()[0] ^ sign) & 1);
                let u_negated = -u;
                let final_u = Fq::conditional_select(&u, &u_negated, flip_sign);

                Maybe::new(AffinePoint { u: final_u, v }, Choice::from(1u8))
            })
        })
    }

    /// Returns the `u`-coordinate of this point.
    pub fn get_u(&self) -> Fq {
        self.u
    }

    /// Returns the `v`-coordinate of this point.
    pub fn get_v(&self) -> Fq {
        self.v
    }

    /// Performs a pre-processing step that produces an `AffineNielsPoint`
    /// for use in multiple additions.
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
    /// Constructs an extended point from the neutral element `(0, 1)`.
    pub fn identity() -> Self {
        ExtendedPoint {
            u: Fq::zero(),
            v: Fq::one(),
            z: Fq::one(),
            t1: Fq::zero(),
            t2: Fq::zero(),
        }
    }

    /// Multiplies this element by the cofactor `8`.
    pub fn mul_by_cofactor(&self) -> ExtendedPoint {
        self.double().double().double()
    }

    /// Performs a pre-processing step that produces an `ExtendedNielsPoint`
    /// for use in multiple additions.
    pub fn to_niels(&self) -> ExtendedNielsPoint {
        ExtendedNielsPoint {
            v_plus_u: &self.v + &self.u,
            v_minus_u: &self.v - &self.u,
            z: self.z,
            t2d: &self.t1 * &self.t2 * EDWARDS_D2,
        }
    }

    /// Computes the doubling of a point more efficiently than a point can
    /// be added to itself.
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

        self.z != Fq::zero()
            && affine.is_on_curve_vartime()
            && (affine.u * affine.v * self.z == self.t1 * self.t2)
    }
}

impl<'a, 'b> Mul<&'b Fr> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn mul(self, other: &'b Fr) -> ExtendedPoint {
        let zero = ExtendedPoint::identity().to_niels();
        let base = self.to_niels();

        let mut acc = ExtendedPoint::identity();

        // This is a simple double-and-add implementation of point
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading four bits because they're always
        // unset for Fr.
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

impl_binops_multiplicative!(ExtendedPoint, Fr);

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
/// of the curve. This is not exposed in the API because it is
/// an implementation detail.
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
    /// Returns the identity.
    fn default() -> AffinePoint {
        AffinePoint::identity()
    }
}

impl Default for ExtendedPoint {
    /// Returns the identity.
    fn default() -> ExtendedPoint {
        ExtendedPoint::identity()
    }
}

/// This takes a mutable slice of `ExtendedPoint`s and "normalizes" them using
/// only a single inversion for the entire batch. This normalization results in
/// all of the points having a Z-coordinate of one. Further, an iterator is
/// returned which can be used to obtain `AffinePoint`s for each element in the
/// slice.
///
/// This costs 5 multiplications per element, and a field inversion.
pub fn batch_normalize<'a>(v: &'a mut [ExtendedPoint]) -> impl Iterator<Item = AffinePoint> + 'a {
    let mut acc = Fq::one();
    for p in v.iter_mut() {
        // We use the `t1` field of `ExtendedPoint` to store the product
        // of previous z-coordinates seen.
        p.t1 = acc;
        acc *= &p.z;
    }

    // This is the inverse, as all z-coordinates are nonzero.
    acc = acc.invert().unwrap();

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
    assert!(EDWARDS_D.sqrt().is_none().unwrap_u8() == 1);
    assert!((-EDWARDS_D).sqrt().is_none().unwrap_u8() == 1);
    assert!((-EDWARDS_D).invert().unwrap().sqrt().is_none().unwrap_u8() == 1);
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
        u: Fq([
            0xc0115cb656ae4839,
            0x623dc3ff81d64c26,
            0x5868e739b5794f2c,
            0x23bd4fbb18d39c9c,
        ]),
        v: Fq([
            0x7588ee6d6dd40deb,
            0x9d6d7a23ebdb7c4c,
            0x46462e26d4edb8c7,
            0x10b4c1517ca82e9b,
        ]),
    }).mul_by_cofactor();
    assert!(p.is_on_curve_vartime());

    assert_eq!(
        (p * Fr::from(1000u64)) * Fr::from(3938u64),
        p * (Fr::from(1000u64) * Fr::from(3938u64)),
    );
}

#[cfg(feature = "std")]
#[test]
fn test_batch_normalize() {
    let mut p = ExtendedPoint::from(AffinePoint {
        u: Fq([
            0xc0115cb656ae4839,
            0x623dc3ff81d64c26,
            0x5868e739b5794f2c,
            0x23bd4fbb18d39c9c,
        ]),
        v: Fq([
            0x7588ee6d6dd40deb,
            0x9d6d7a23ebdb7c4c,
            0x46462e26d4edb8c7,
            0x10b4c1517ca82e9b,
        ]),
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

#[test]
fn test_mul_consistency() {
    let a = Fr([
        0x21e61211d9934f2e,
        0xa52c058a693c3e07,
        0x9ccb77bfb12d6360,
        0x07df2470ec94398e,
    ]);
    let b = Fr([
        0x03336d1cbe19dbe0,
        0x0153618f6156a536,
        0x2604c9e1fc3c6b15,
        0x04ae581ceb028720,
    ]);
    let c = Fr([
        0xd7abf5bb24683f4c,
        0x9d7712cc274b7c03,
        0x973293db9683789f,
        0x0b677e29380a97a7,
    ]);
    assert_eq!(a * b, c);
    let p = ExtendedPoint::from(AffinePoint {
        u: Fq([
            0xc0115cb656ae4839,
            0x623dc3ff81d64c26,
            0x5868e739b5794f2c,
            0x23bd4fbb18d39c9c,
        ]),
        v: Fq([
            0x7588ee6d6dd40deb,
            0x9d6d7a23ebdb7c4c,
            0x46462e26d4edb8c7,
            0x10b4c1517ca82e9b,
        ]),
    }).mul_by_cofactor();
    assert_eq!(p * c, (p * a) * b);
}
