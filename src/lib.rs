#![feature(i128_type)]

extern crate rand;

//#[macro_use]
//extern crate ff_derive;

//pub use ff_derive::*;

use std::fmt;

/// This trait represents an element of a field.
pub trait Field: Sized +
                 Eq +
                 Copy +
                 Clone +
                 Send +
                 Sync +
                 fmt::Debug +
                 'static +
                 rand::Rand
{
    /// Returns the zero element of the field, the additive identity.
    fn zero() -> Self;

    /// Returns the one element of the field, the multiplicative identity.
    fn one() -> Self;

    /// Returns true iff this element is zero.
    fn is_zero(&self) -> bool;

    /// Squares this element.
    fn square(&mut self);

    /// Doubles this element.
    fn double(&mut self);

    /// Negates this element.
    fn negate(&mut self);

    /// Adds another element to this element.
    fn add_assign(&mut self, other: &Self);

    /// Subtracts another element from this element.
    fn sub_assign(&mut self, other: &Self);

    /// Multiplies another element by this element.
    fn mul_assign(&mut self, other: &Self);

    /// Computes the multiplicative inverse of this element, if nonzero.
    fn inverse(&self) -> Option<Self>;

    /// Exponentiates this element by a power of the modulus.
    fn frobenius_map(&mut self, power: usize);

    /// Exponentiates this element by a number represented with `u64` limbs,
    /// least significant digit first.
    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self
    {
        let mut res = Self::one();

        for i in BitIterator::new(exp) {
            res.square();
            if i {
                res.mul_assign(self);
            }
        }

        res
    }
}

/// This trait represents an element of a field that has a square root operation described for it.
pub trait SqrtField: Field
{
    /// Returns the square root of the field element, if it is
    /// quadratic residue.
    fn sqrt(&self) -> Option<Self>;
}

/// This trait represents a wrapper around a biginteger which can encode any element of a particular
/// prime field. It is a smart wrapper around a sequence of `u64` limbs, least-significant digit
/// first.
pub trait PrimeFieldRepr: Sized +
                          Copy +
                          Clone +
                          Eq +
                          Ord +
                          Send +
                          Sync +
                          fmt::Debug +
                          'static +
                          rand::Rand +
                          AsRef<[u64]> +
                          From<u64>
{
    /// Subtract another reprensetation from this one. Underflow is ignored.
    fn sub_noborrow(&mut self, other: &Self);

    /// Add another representation to this one. Overflow is ignored.
    fn add_nocarry(&mut self, other: &Self);

    /// Compute the number of bits needed to encode this number.
    fn num_bits(&self) -> usize;

    /// Returns true iff this number is zero.
    fn is_zero(&self) -> bool;

    /// Returns true iff this number is odd.
    fn is_odd(&self) -> bool;

    /// Returns true iff this number is even.
    fn is_even(&self) -> bool;

    /// Performs a rightwise bitshift of this number, effectively dividing
    /// it by 2.
    fn div2(&mut self);

    /// Performs a leftwise bitshift of this number, effectively multiplying
    /// it by 2. Overflow is ignored.
    fn mul2(&mut self);
}

/// This represents an element of a prime field.
pub trait PrimeField: SqrtField
{
    /// The prime field can be converted back and forth into this biginteger
    /// representation.
    type Repr: PrimeFieldRepr;

    /// Convert this prime field element into a biginteger representation.
    fn from_repr(Self::Repr) -> Result<Self, ()>;

    /// Convert a biginteger reprensentation into a prime field element, if
    /// the number is an element of the field.
    fn into_repr(&self) -> Self::Repr;

    /// Returns the field characteristic; the modulus.
    fn char() -> Self::Repr;

    /// Returns how many bits are needed to represent an element of this
    /// field.
    fn num_bits() -> usize;

    /// Returns how many bits of information can be reliably stored in the
    /// field element.
    fn capacity() -> usize;
}

pub struct BitIterator<E> {
    t: E,
    n: usize
}

impl<E: AsRef<[u64]>> BitIterator<E> {
    fn new(t: E) -> Self {
        let n = t.as_ref().len() * 64;

        BitIterator {
            t: t,
            n: n
        }
    }
}

impl<E: AsRef<[u64]>> Iterator for BitIterator<E> {
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

#[test]
fn test_bit_iterator() {
    let mut a = BitIterator::new([0xa953d79b83f6ab59, 0x6dea2059e200bd39]);
    let expected = "01101101111010100010000001011001111000100000000010111101001110011010100101010011110101111001101110000011111101101010101101011001";

    for e in expected.chars() {
        assert!(a.next().unwrap() == (e == '1'));
    }

    assert!(a.next().is_none());

    let expected = "1010010101111110101010000101101011101000011101110101001000011001100100100011011010001011011011010001011011101100110100111011010010110001000011110100110001100110011101101000101100011100100100100100001010011101010111110011101011000011101000111011011101011001";

    let mut a = BitIterator::new([0x429d5f3ac3a3b759, 0xb10f4c66768b1c92, 0x92368b6d16ecd3b4, 0xa57ea85ae8775219]);

    for e in expected.chars() {
        assert!(a.next().unwrap() == (e == '1'));
    }

    assert!(a.next().is_none());
}

/// Calculate a - b - borrow, returning the result and modifying
/// the borrow value.
#[inline(always)]
pub fn sbb(a: u64, b: u64, borrow: &mut u64) -> u64 {
    let tmp = (1u128 << 64) + (a as u128) - (b as u128) - (*borrow as u128);

    *borrow = if tmp >> 64 == 0 { 1 } else { 0 };

    tmp as u64
}

/// Calculate a + b + carry, returning the sum and modifying the
/// carry value.
#[inline(always)]
pub fn adc(a: u64, b: u64, carry: &mut u64) -> u64 {
    let tmp = (a as u128) + (b as u128) + (*carry as u128);

    *carry = (tmp >> 64) as u64;

    tmp as u64
}

/// Calculate a + (b * c) + carry, returning the least significant digit
/// and setting carry to the most significant digit.
#[inline(always)]
pub fn mac_with_carry(a: u64, b: u64, c: u64, carry: &mut u64) -> u64 {
    let tmp = (a as u128) + (b as u128) * (c as u128) + (*carry as u128);

    *carry = (tmp >> 64) as u64;

    tmp as u64
}
