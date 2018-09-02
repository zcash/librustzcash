#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

extern crate byteorder;
extern crate subtle;

use core::ops::{AddAssign, Neg};

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

// `d = -(10240/10241)`
const EDWARDS_D: Fq = Fq([
    0x2a522455b974f6b0, 0xfc6cc9ef0d9acab3, 0x7a08fb94c27628d1, 0x57f8f6a8fe0e262e
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
    fn add_assign(&mut self, rhs: &'b Point) {
        // See "Twisted Edwards Curves Revisited"
        //     Hisil, Wong, Carter, and Dawson
        //     3.1 Unified Addition in E^e

        unimplemented!()
    }
}
