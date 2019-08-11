//! This module provides an implementation of the $\mathbb{G}_1$ group of BLS12-381.

use crate::fp::Fp;
use subtle::Choice;

/// This is an element of $\mathbb{G}_1$ represented in the affine coordinate space.
/// It is ideal to keep elements in this representation to reduce memory usage and
/// improve performance through the use of mixed curve model arithmetic.
///
/// Values of `G1Affine` are guaranteed to be in the $q$-order subgroup unless an
/// "unchecked" API was misused.
#[derive(Copy, Clone, Debug)]
pub struct G1Affine {
    x: Fp,
    y: Fp,
    infinity: Choice,
}

/// This is an element of $\mathbb{G}_1$ represented in the projective coordinate space.
#[derive(Copy, Clone, Debug)]
pub struct G1Projective {
    x: Fp,
    y: Fp,
    z: Fp,
}
