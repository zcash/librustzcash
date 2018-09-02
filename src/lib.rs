#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

extern crate byteorder;
extern crate subtle;

use core::ops::Neg;

mod fq;
pub use fq::*;

/// This represents a point on the Jubjub curve.
/// `-u^2 + v^2 = 1 + d.u^2.v^2` over `Fq` with
/// `d = -(10240/10241)`.

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

impl Point {
    pub fn zero() -> Point {
        // (0, 1) is the neutral element of the group.

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
