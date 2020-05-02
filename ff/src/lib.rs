//! This crate provides traits for working with finite fields.

// Catch documentation errors caused by code changes.
#![no_std]
#![deny(intra_doc_link_resolution_failure)]
#![allow(unused_imports)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "derive")]
pub use ff_derive::*;

use byteorder::ByteOrder;
use core::convert::TryFrom;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, BitAnd, Mul, MulAssign, Neg, Shr, Sub, SubAssign};
use rand_core::RngCore;
#[cfg(feature = "std")]
use std::io::{self, Read, Write};
use subtle::{ConditionallySelectable, CtOption};

/// This trait represents an element of a field.
pub trait Field:
    Sized
    + Eq
    + Copy
    + Clone
    + Default
    + Send
    + Sync
    + fmt::Debug
    + fmt::Display
    + 'static
    + ConditionallySelectable
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + MulAssign
    + AddAssign
    + SubAssign
    + for<'a> MulAssign<&'a Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
{
    /// Returns an element chosen uniformly at random using a user-provided RNG.
    fn random<R: RngCore + ?std::marker::Sized>(rng: &mut R) -> Self;

    /// Returns the zero element of the field, the additive identity.
    fn zero() -> Self;

    /// Returns the one element of the field, the multiplicative identity.
    fn one() -> Self;

    /// Returns true iff this element is zero.
    fn is_zero(&self) -> bool;

    /// Squares this element.
    #[must_use]
    fn square(&self) -> Self;

    /// Doubles this element.
    #[must_use]
    fn double(&self) -> Self;

    /// Computes the multiplicative inverse of this element,
    /// failing if the element is zero.
    fn invert(&self) -> CtOption<Self>;

    /// Returns the square root of the field element, if it is
    /// quadratic residue.
    fn sqrt(&self) -> CtOption<Self>;

    /// Exponentiates `self` by `exp`, where `exp` is a little-endian order
    /// integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.** If the
    /// exponent is fixed, this operation is effectively constant time.
    fn pow_vartime<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        let mut res = Self::one();
        for e in exp.as_ref().iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res.mul_assign(self);
                }
            }
        }

        res
    }
}

/// Helper trait for converting the binary representation of a prime field element into a
/// specific endianness. This is useful when you need to act on the bit representation
/// of an element generically, as the native binary representation of a prime field is
/// field-dependent.
pub trait Endianness: ByteOrder {
    /// Converts the provided representation between native and little-endian.
    fn toggle_little_endian<T: AsMut<[u8]>>(t: &mut T);
}

impl Endianness for byteorder::BigEndian {
    fn toggle_little_endian<T: AsMut<[u8]>>(t: &mut T) {
        t.as_mut().reverse();
    }
}

impl Endianness for byteorder::LittleEndian {
    fn toggle_little_endian<T: AsMut<[u8]>>(_: &mut T) {
        // No-op
    }
}

/// This represents an element of a prime field.
pub trait PrimeField: Field + From<u64> {
    /// The prime field can be converted back and forth into this binary
    /// representation.
    type Repr: Default + AsRef<[u8]> + AsMut<[u8]> + From<Self> + for<'r> From<&'r Self>;

    /// This indicates the endianness of [`PrimeField::Repr`].
    type ReprEndianness: Endianness;

    /// Interpret a string of numbers as a (congruent) prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    fn from_str(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }

        if s == "0" {
            return Some(Self::zero());
        }

        let mut res = Self::zero();

        let ten = Self::from(10);

        let mut first_digit = true;

        for c in s.chars() {
            match c.to_digit(10) {
                Some(c) => {
                    if first_digit {
                        if c == 0 {
                            return None;
                        }

                        first_digit = false;
                    }

                    res.mul_assign(&ten);
                    res.add_assign(&Self::from(u64::from(c)));
                }
                None => {
                    return None;
                }
            }
        }

        Some(res)
    }

    /// Attempts to convert a byte representation of a field element into an element of
    /// this prime field, failing if the input is not canonical (is not smaller than the
    /// field's modulus).
    ///
    /// The byte representation is interpreted with the endianness defined by
    /// [`PrimeField::ReprEndianness`].
    fn from_repr(_: Self::Repr) -> Option<Self>;

    /// Converts an element of the prime field into the standard byte representation for
    /// this field.
    ///
    /// The endianness of the byte representation is defined by
    /// [`PrimeField::ReprEndianness`].
    fn to_repr(&self) -> Self::Repr;

    /// Returns true iff this element is odd.
    fn is_odd(&self) -> bool;

    /// Returns true iff this element is even.
    #[inline(always)]
    fn is_even(&self) -> bool {
        !self.is_odd()
    }

    /// Returns the field characteristic; the modulus.
    fn char() -> Self::Repr;

    /// How many bits are needed to represent an element of this field.
    const NUM_BITS: u32;

    /// How many bits of information can be reliably stored in the field element.
    const CAPACITY: u32;

    /// Returns the multiplicative generator of `char()` - 1 order. This element
    /// must also be quadratic nonresidue.
    fn multiplicative_generator() -> Self;

    /// 2^s * t = `char()` - 1 with t odd.
    const S: u32;

    /// Returns the 2^s root of unity computed by exponentiating the `multiplicative_generator()`
    /// by t.
    fn root_of_unity() -> Self;
}

/// An "engine" is a collection of types (fields, elliptic curve groups, etc.)
/// with well-defined relationships. Specific relationships (for example, a
/// pairing-friendly curve) can be defined in a subtrait.
pub trait ScalarEngine: Sized + 'static + Clone {
    /// This is the scalar field of the engine's groups.
    type Fr: PrimeField;
}

#[derive(Debug)]
pub struct BitIterator<T, E: AsRef<[T]>> {
    t: E,
    n: usize,
    _limb: PhantomData<T>,
}

impl<E: AsRef<[u64]>> BitIterator<u64, E> {
    pub fn new(t: E) -> Self {
        let n = t.as_ref().len() * 64;

        BitIterator {
            t,
            n,
            _limb: PhantomData::default(),
        }
    }
}

impl<E: AsRef<[u64]>> Iterator for BitIterator<u64, E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let part = self.n / 64;
            let bit = self.n - (64 * part);

            Some(self.t.as_ref()[part] & (1 << bit) > 0)
        }
    }
}

impl<E: AsRef<[u8]>> BitIterator<u8, E> {
    pub fn new(t: E) -> Self {
        let n = t.as_ref().len() * 8;

        BitIterator {
            t,
            n,
            _limb: PhantomData::default(),
        }
    }
}

impl<E: AsRef<[u8]>> Iterator for BitIterator<u8, E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let part = self.n / 8;
            let bit = self.n - (8 * part);

            Some(self.t.as_ref()[part] & (1 << bit) > 0)
        }
    }
}

#[test]
fn test_bit_iterator() {
    let mut a = BitIterator::<u64, _>::new([0xa953_d79b_83f6_ab59, 0x6dea_2059_e200_bd39]);
    let expected = "01101101111010100010000001011001111000100000000010111101001110011010100101010011110101111001101110000011111101101010101101011001";

    for e in expected.chars() {
        assert!(a.next().unwrap() == (e == '1'));
    }

    assert!(a.next().is_none());

    let expected = "1010010101111110101010000101101011101000011101110101001000011001100100100011011010001011011011010001011011101100110100111011010010110001000011110100110001100110011101101000101100011100100100100100001010011101010111110011101011000011101000111011011101011001";

    let mut a = BitIterator::<u64, _>::new([
        0x429d_5f3a_c3a3_b759,
        0xb10f_4c66_768b_1c92,
        0x9236_8b6d_16ec_d3b4,
        0xa57e_a85a_e877_5219,
    ]);

    for e in expected.chars() {
        assert!(a.next().unwrap() == (e == '1'));
    }

    assert!(a.next().is_none());
}

pub use self::arith_impl::*;

mod arith_impl {
    /// Calculate a - b - borrow, returning the result and modifying
    /// the borrow value.
    #[inline(always)]
    pub fn sbb(a: u64, b: u64, borrow: &mut u64) -> u64 {
        let tmp = (1u128 << 64) + u128::from(a) - u128::from(b) - u128::from(*borrow);

        *borrow = if tmp >> 64 == 0 { 1 } else { 0 };

        tmp as u64
    }

    /// Calculate a + b + carry, returning the sum and modifying the
    /// carry value.
    #[inline(always)]
    pub fn adc(a: u64, b: u64, carry: &mut u64) -> u64 {
        let tmp = u128::from(a) + u128::from(b) + u128::from(*carry);

        *carry = (tmp >> 64) as u64;

        tmp as u64
    }

    /// Calculate a + (b * c) + carry, returning the least significant digit
    /// and setting carry to the most significant digit.
    #[inline(always)]
    pub fn mac_with_carry(a: u64, b: u64, c: u64, carry: &mut u64) -> u64 {
        let tmp = (u128::from(a)) + u128::from(b) * u128::from(c) + u128::from(*carry);

        *carry = (tmp >> 64) as u64;

        tmp as u64
    }
}
