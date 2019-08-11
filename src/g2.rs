//! This module provides an implementation of the $\mathbb{G}_2$ group of BLS12-381.

use crate::fp2::Fp2;
use subtle::Choice;

/// This is an element of $\mathbb{G}_2$ represented in the affine coordinate space.
/// It is ideal to keep elements in this representation to reduce memory usage and
/// improve performance through the use of mixed curve model arithmetic.
///
/// Values of `G2Affine` are guaranteed to be in the $q$-order subgroup unless an
/// "unchecked" API was misused.
#[derive(Copy, Clone, Debug)]
pub struct G2Affine {
    x: Fp2,
    y: Fp2,
    infinity: Choice,
}

/// This is an element of $\mathbb{G}_2$ represented in the projective coordinate space.
#[derive(Copy, Clone, Debug)]
pub struct G2Projective {
    x: Fp2,
    y: Fp2,
    z: Fp2,
}
