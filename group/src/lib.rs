// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

use ff::PrimeField;
use rand::RngCore;
use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, CtOption};

pub mod cofactor;
pub mod prime;
pub mod tests;

mod wnaf;
pub use self::wnaf::Wnaf;

/// A helper trait for types with a group operation.
pub trait GroupOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + AddAssign<Rhs> + SubAssign<Rhs>
{
}

impl<T, Rhs, Output> GroupOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + AddAssign<Rhs> + SubAssign<Rhs>
{
}

/// A helper trait for references with a group operation.
pub trait GroupOpsOwned<Rhs = Self, Output = Self>: for<'r> GroupOps<&'r Rhs, Output> {}
impl<T, Rhs, Output> GroupOpsOwned<Rhs, Output> for T where T: for<'r> GroupOps<&'r Rhs, Output> {}

/// A helper trait for types implementing group scalar multiplication.
pub trait ScalarMul<Rhs, Output = Self>: Mul<Rhs, Output = Output> + MulAssign<Rhs> {}

impl<T, Rhs, Output> ScalarMul<Rhs, Output> for T where T: Mul<Rhs, Output = Output> + MulAssign<Rhs>
{}

/// A helper trait for references implementing group scalar multiplication.
pub trait ScalarMulOwned<Rhs, Output = Self>: for<'r> ScalarMul<&'r Rhs, Output> {}
impl<T, Rhs, Output> ScalarMulOwned<Rhs, Output> for T where T: for<'r> ScalarMul<&'r Rhs, Output> {}

/// This trait represents an element of a cryptographic group.
pub trait Group:
    Clone
    + Copy
    + fmt::Debug
    + fmt::Display
    + Eq
    + Sized
    + Send
    + Sync
    + 'static
    + Sum
    + for<'a> Sum<&'a Self>
    + Neg<Output = Self>
    + GroupOps
    + GroupOpsOwned
    + ScalarMul<<Self as Group>::Scalar>
    + ScalarMulOwned<<Self as Group>::Scalar>
{
    /// Scalars modulo the order of this group's scalar field.
    type Scalar: PrimeField;

    /// Returns an element chosen uniformly at random using a user-provided RNG.
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self;

    /// Returns the additive identity, also known as the "neutral element".
    fn identity() -> Self;

    /// Returns a fixed generator of the prime-order subgroup.
    fn generator() -> Self;

    /// Determines if this point is the identity.
    fn is_identity(&self) -> Choice;

    /// Doubles this element.
    #[must_use]
    fn double(&self) -> Self;
}

/// Efficient representation of an elliptic curve point guaranteed.
pub trait Curve:
    Group + GroupOps<<Self as Curve>::AffineRepr> + GroupOpsOwned<<Self as Curve>::AffineRepr>
{
    /// The affine representation for this elliptic curve.
    type AffineRepr;

    /// Converts a batch of projective elements into affine elements. This function will
    /// panic if `p.len() != q.len()`.
    fn batch_normalize(p: &[Self], q: &mut [Self::AffineRepr]) {
        assert_eq!(p.len(), q.len());

        for (p, q) in p.iter().zip(q.iter_mut()) {
            *q = p.to_affine();
        }
    }

    /// Converts this element into its affine representation.
    fn to_affine(&self) -> Self::AffineRepr;

    /// Recommends a wNAF window table size given a scalar. Always returns a number
    /// between 2 and 22, inclusive.
    fn recommended_wnaf_for_scalar(scalar: &Self::Scalar) -> usize;

    /// Recommends a wNAF window size given the number of scalars you intend to multiply
    /// a base by. Always returns a number between 2 and 22, inclusive.
    fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize;
}

pub trait GroupEncoding: Sized {
    /// The encoding of group elements.
    type Repr: Default + AsRef<[u8]> + AsMut<[u8]>;

    /// Attempts to deserialize a group element from its encoding.
    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self>;

    /// Attempts to deserialize a group element, not checking if the element is valid.
    ///
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using
    /// [`GroupEncoding::from_bytes`] instead.
    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self>;

    /// Converts this element into its byte encoding. This may or may not support
    /// encoding the identity.
    // TODO: Figure out how to handle identity encoding generically.
    fn to_bytes(&self) -> Self::Repr;
}

/// Affine representation of a point on an elliptic curve that has a defined uncompressed
/// encoding.
pub trait UncompressedEncoding: Sized {
    type Uncompressed: Default + AsRef<[u8]> + AsMut<[u8]>;

    /// Attempts to deserialize an element from its uncompressed encoding.
    fn from_uncompressed(bytes: &Self::Uncompressed) -> CtOption<Self>;

    /// Attempts to deserialize an uncompressed element, not checking if the element is in
    /// the correct subgroup.
    ///
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using
    /// [`UncompressedEncoding::from_uncompressed`] instead.
    fn from_uncompressed_unchecked(bytes: &Self::Uncompressed) -> CtOption<Self>;

    /// Converts this element into its uncompressed encoding, so long as it's not
    /// the point at infinity.
    fn to_uncompressed(&self) -> Self::Uncompressed;
}
