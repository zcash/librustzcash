// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

use ff::{Field, PrimeField};
use rand::RngCore;
use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, CtOption};

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
    + GroupOps<<Self as Group>::Subgroup>
    + GroupOpsOwned<<Self as Group>::Subgroup>
    + ScalarMul<<Self as Group>::Scalar>
    + ScalarMulOwned<<Self as Group>::Scalar>
{
    /// The large prime-order subgroup in which cryptographic operations are performed.
    /// If `Self` implements `PrimeGroup`, then `Self::Subgroup` may be `Self`.
    type Subgroup: PrimeGroup;

    /// Scalars modulo the order of [`Group::Subgroup`].
    type Scalar: PrimeField;

    /// Returns an element chosen uniformly at random using a user-provided RNG.
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self;

    /// Returns the additive identity, also known as the "neutral element".
    fn identity() -> Self;

    /// Returns a fixed generator of the prime-order subgroup.
    fn generator() -> Self::Subgroup;

    /// Determines if this point is the identity.
    fn is_identity(&self) -> Choice;

    /// Doubles this element.
    #[must_use]
    fn double(&self) -> Self;
}

/// This trait represents an element of a prime-order cryptographic group.
pub trait PrimeGroup: Group {}

/// Projective representation of an elliptic curve point guaranteed to be
/// in the correct prime order subgroup.
pub trait CurveProjective:
    Group
    + GroupOps<<Self as CurveProjective>::Affine>
    + GroupOpsOwned<<Self as CurveProjective>::Affine>
{
    type Base: Field;
    type Affine: CurveAffine<Projective = Self, Scalar = Self::Scalar>
        + Mul<Self::Scalar, Output = Self>
        + for<'r> Mul<Self::Scalar, Output = Self>;

    /// Converts a batch of projective elements into affine elements. This function will
    /// panic if `p.len() != q.len()`.
    fn batch_normalize(p: &[Self], q: &mut [Self::Affine]);

    /// Converts this element into its affine representation.
    fn to_affine(&self) -> Self::Affine;

    /// Recommends a wNAF window table size given a scalar. Always returns a number
    /// between 2 and 22, inclusive.
    fn recommended_wnaf_for_scalar(scalar: &Self::Scalar) -> usize;

    /// Recommends a wNAF window size given the number of scalars you intend to multiply
    /// a base by. Always returns a number between 2 and 22, inclusive.
    fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize;
}

/// Affine representation of an elliptic curve point guaranteed to be
/// in the correct prime order subgroup.
pub trait CurveAffine:
    Copy
    + Clone
    + Sized
    + Send
    + Sync
    + fmt::Debug
    + fmt::Display
    + PartialEq
    + Eq
    + 'static
    + Neg<Output = Self>
    + Mul<<Self as CurveAffine>::Scalar, Output = <Self as CurveAffine>::Projective>
    + for<'r> Mul<<Self as CurveAffine>::Scalar, Output = <Self as CurveAffine>::Projective>
{
    type Scalar: PrimeField;
    type Base: Field;
    type Projective: CurveProjective<Affine = Self, Scalar = Self::Scalar>;
    type Uncompressed: Default + AsRef<[u8]> + AsMut<[u8]>;
    type Compressed: Default + AsRef<[u8]> + AsMut<[u8]>;

    /// Returns the additive identity.
    fn identity() -> Self;

    /// Returns a fixed generator of unknown exponent.
    fn generator() -> Self;

    /// Determines if this point represents the point at infinity; the
    /// additive identity.
    fn is_identity(&self) -> Choice;

    /// Converts this element into its affine representation.
    fn to_projective(&self) -> Self::Projective;

    /// Attempts to deserialize an element from its compressed encoding.
    fn from_compressed(bytes: &Self::Compressed) -> CtOption<Self>;

    /// Attempts to deserialize a compressed element, not checking if the element is in
    /// the correct subgroup.
    ///
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using
    /// [`CurveAffine::from_compressed`] instead.
    fn from_compressed_unchecked(bytes: &Self::Compressed) -> CtOption<Self>;

    /// Converts this element into its compressed encoding, so long as it's not
    /// the point at infinity.
    fn to_compressed(&self) -> Self::Compressed;

    /// Attempts to deserialize an element from its uncompressed encoding.
    fn from_uncompressed(bytes: &Self::Uncompressed) -> CtOption<Self>;

    /// Attempts to deserialize an uncompressed element, not checking if the element is in
    /// the correct subgroup.
    ///
    /// **This is dangerous to call unless you trust the bytes you are reading; otherwise,
    /// API invariants may be broken.** Please consider using
    /// [`CurveAffine::from_uncompressed`] instead.
    fn from_uncompressed_unchecked(bytes: &Self::Uncompressed) -> CtOption<Self>;

    /// Converts this element into its uncompressed encoding, so long as it's not
    /// the point at infinity.
    fn to_uncompressed(&self) -> Self::Uncompressed;
}
