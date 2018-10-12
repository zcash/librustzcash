#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

extern crate byteorder;
extern crate subtle;

use core::ops::{AddAssign, Neg};

#[macro_use]
mod util;

mod fq;
pub use fq::*;

// `d = -(10240/10241)`
#[allow(dead_code)]
const EDWARDS_D: Fq = Fq([
    0x2a522455b974f6b0,
    0xfc6cc9ef0d9acab3,
    0x7a08fb94c27628d1,
    0x57f8f6a8fe0e262e,
]);

/// This represents an affine point `(u, v)` on the
/// curve `-u^2 + v^2 = 1 + d.u^2.v^2` over `Fq` with
/// `d = -(10240/10241)`.
#[derive(Clone, Copy)]
pub struct AffinePoint {
    u: Fq,
    v: Fq,
}

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
    /// the curve or canonical.
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

                match ((v2 - Fq::one()) * (Fq::one() + EDWARDS_D * &v2).pow_q_minus_2())
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

impl Default for AffinePoint {
    fn default() -> AffinePoint {
        AffinePoint::identity()
    }
}

#[test]
fn test_is_on_curve_var() {
    assert!(AffinePoint::identity().is_on_curve_vartime());
}

#[test]
fn test_d_is_non_quadratic_residue() {
    assert!(EDWARDS_D.sqrt_vartime().is_none());
    assert!((-EDWARDS_D).sqrt_vartime().is_none());
    assert!((-EDWARDS_D).pow_q_minus_2().sqrt_vartime().is_none());
}

/*



// We're going to use the "extended twisted Edwards
// coordinates" from "Twisted Edwards Curves
// Revisited" by Hisil, Wong, Carter and Dawson.
//
// See https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
//
// We're going to use `u` and `v` to refer to what
// the paper calls `x` and `y`.
//
// In these coordinates, the affine point `(u, v)` is
// represented by `(U, V, T, Z)` where `U = u/Z`,
// `V = v/Z`, `T = uv/Z` for any nonzero `Z`.
#[derive(Clone, Copy)]
struct Point {
    // U = u/Z
    u: Fq,
    // V = v/Z
    v: Fq,
    // T = uv/Z
    t: Fq,
    z: Fq,
}

// `d = -(10240/10241)`
#[allow(dead_code)]
const EDWARDS_D: Fq = Fq([
    0x2a522455b974f6b0,
    0xfc6cc9ef0d9acab3,
    0x7a08fb94c27628d1,
    0x57f8f6a8fe0e262e,
]);

impl Point {
    pub fn identity() -> Point {
        // `(0, 1)` is the neutral element of the group;
        // the additive identity.

        Point {
            u: Fq::zero(),
            v: Fq::one(),
            t: Fq::zero(),
            z: Fq::one(),
        }
    }
}

impl<'a> Neg for &'a Point {
    type Output = Point;

    fn neg(self) -> Point {
        Point {
            u: -&self.u,
            v: self.v,
            t: -&self.t,
            z: self.z,
        }
    }
}

impl<'b> AddAssign<&'b Point> for Point {
    fn add_assign(&mut self, _rhs: &'b Point) {
        // See "Twisted Edwards Curves Revisited"
        //     Hisil, Wong, Carter, and Dawson
        //     3.1 Unified Addition in E^e

        unimplemented!()
    }
}
*/
