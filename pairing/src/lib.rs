//! A library for working with pairing-friendly curves.

// `clippy` is a code linting tool for improving code quality by catching
// common mistakes or strange code patterns. If the `cargo-clippy` feature
// is provided, all compiler warnings are prohibited.
#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::inline_always))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::many_single_char_names))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::new_without_default))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::write_literal))]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
// Force public structures to implement Debug
#![deny(missing_debug_implementations)]

#[cfg(test)]
pub mod tests;

pub mod bls12_381;

use core::ops::Mul;
use ff::{Field, PrimeField, ScalarEngine};
use group::{CurveAffine, CurveProjective, GroupOps, GroupOpsOwned, ScalarMul, ScalarMulOwned};
use subtle::CtOption;

/// An "engine" is a collection of types (fields, elliptic curve groups, etc.)
/// with well-defined relationships. In particular, the G1/G2 curve groups are
/// of prime order `r`, and are equipped with a bilinear pairing function.
pub trait Engine: ScalarEngine {
    /// The projective representation of an element in G1.
    type G1: CurveProjective<Scalar = Self::Fr, Affine = Self::G1Affine>
        + From<Self::G1Affine>
        + GroupOps<Self::G1Affine>
        + GroupOpsOwned<Self::G1Affine>
        + ScalarMul<Self::Fr>
        + ScalarMulOwned<Self::Fr>;

    /// The affine representation of an element in G1.
    type G1Affine: PairingCurveAffine<
            Scalar = Self::Fr,
            Projective = Self::G1,
            Pair = Self::G2Affine,
            PairingResult = Self::Gt,
        > + From<Self::G1>
        + Mul<Self::Fr, Output = Self::G1>
        + for<'a> Mul<&'a Self::Fr, Output = Self::G1>;

    /// The projective representation of an element in G2.
    type G2: CurveProjective<Scalar = Self::Fr, Affine = Self::G2Affine>
        + From<Self::G2Affine>
        + GroupOps<Self::G2Affine>
        + GroupOpsOwned<Self::G2Affine>
        + ScalarMul<Self::Fr>
        + ScalarMulOwned<Self::Fr>;

    /// The affine representation of an element in G2.
    type G2Affine: PairingCurveAffine<
            Scalar = Self::Fr,
            Projective = Self::G2,
            Pair = Self::G1Affine,
            PairingResult = Self::Gt,
        > + From<Self::G2>
        + Mul<Self::Fr, Output = Self::G2>
        + for<'a> Mul<&'a Self::Fr, Output = Self::G2>;

    /// The type returned by `Engine::miller_loop`.
    type MillerLoopResult;

    /// The extension field that hosts the target group of the pairing.
    type Gt: Field;

    /// Perform a miller loop with some number of (G1, G2) pairs.
    fn miller_loop<'a, I>(i: I) -> Self::MillerLoopResult
    where
        I: IntoIterator<
            Item = &'a (
                &'a <Self::G1Affine as PairingCurveAffine>::Prepared,
                &'a <Self::G2Affine as PairingCurveAffine>::Prepared,
            ),
        >;

    /// Perform final exponentiation of the result of a miller loop.
    fn final_exponentiation(_: &Self::MillerLoopResult) -> CtOption<Self::Gt>;

    /// Performs a complete pairing operation `(p, q)`.
    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Gt
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        Self::final_exponentiation(&Self::miller_loop(
            [(&(p.into().prepare()), &(q.into().prepare()))].iter(),
        ))
        .unwrap()
    }
}

/// Affine representation of an elliptic curve point that can be used
/// to perform pairings.
pub trait PairingCurveAffine: CurveAffine {
    type Prepared: Clone + Send + Sync + 'static;
    type Pair: PairingCurveAffine<Pair = Self>;
    type PairingResult: Field;

    /// Prepares this element for pairing purposes.
    fn prepare(&self) -> Self::Prepared;

    /// Perform a pairing
    fn pairing_with(&self, other: &Self::Pair) -> Self::PairingResult;
}
