use core::ops::{AddAssign, SubAssign, MulAssign, Neg};

use byteorder::{ByteOrder, LittleEndian};
use subtle::{Choice, ConditionallySelectable, ConditionallyAssignable};

/// Represents an element of `GF(q)`.
// The internal representation of this type is four 64-bit unsigned
// integers in little-endian order. Elements of Fq are always in
// Montgomery form; i.e., Fq(a) = aR mod q, with R = 2^256.
#[derive(Clone, Copy)]
pub struct Fq([u64; 4]);

impl ConditionallySelectable for Fq {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fq([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice)
        ])
    }
}

// Constant representing the modulus
// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const MODULUS: Fq = Fq([
    0xffffffff00000001, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48
]);

/// Compute a + b + carry, returning the result and setting carry to the
/// carry value.
#[inline(always)]
fn adc(a: u64, b: u64, carry: &mut u128) -> u64 {
    *carry = u128::from(a) + u128::from(b) + (*carry >> 64);
    *carry as u64
}

/// Compute a - (b + borrow), returning the result and setting borrow to
/// the borrow value.
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: &mut u128) -> u64 {
    *borrow = u128::from(a).wrapping_sub(u128::from(b) + (*borrow >> 127));
    *borrow as u64
}

/// Compute a + (b * c) + carry, returning the result and setting carry
/// to the carry value.
#[inline(always)]
fn mac_with_carry(a: u64, b: u64, c: u64, carry: &mut u128) -> u64 {
    *carry = u128::from(a) + (u128::from(b) * u128::from(c)) + (*carry >> 64);
    *carry as u64
}

impl Neg for Fq {
    type Output = Fq;

    fn neg(self) -> Fq {
        // Subtract `self` from `MODULUS` to negate.
        let mut tmp = MODULUS;
        tmp.sub_assign(&self);

        // `tmp` could be `MODULUS` if `self` was zero. Create a mask that is
        // zero if `self` was zero, and `u64::max_value()` if self was nonzero.
        let mask = u64::from((self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0).wrapping_sub(1);

        tmp.0[0] &= mask;
        tmp.0[1] &= mask;
        tmp.0[2] &= mask;
        tmp.0[3] &= mask;

        tmp
    }
}

impl<'b> SubAssign<&'b Fq> for Fq {
    fn sub_assign(&mut self, rhs: &'b Fq) {
        let mut borrow = 0;
        for i in 0..4 {
            self.0[i] = sbb(self.0[i], rhs.0[i], &mut borrow);
        }

        // If underflow occurred on the final limb, (borrow >> 64) = 0x111...111, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the modulus.
        let borrow_mask = (borrow >> 64) as u64;

        let mut carry = 0;
        for i in 0..4 {
            self.0[i] = adc(self.0[i], MODULUS.0[i] & borrow_mask, &mut carry);
        }
    }
}

impl<'b> AddAssign<&'b Fq> for Fq {
    fn add_assign(&mut self, rhs: &'b Fq) {
        let mut carry = 0;
        for i in 0..4 {
            self.0[i] = adc(self.0[i], rhs.0[i], &mut carry);
        }

        // Attempt to subtract the modulus, to ensure the value
        // is smaller than the modulus.
        self.sub_assign(&MODULUS);
    }
}

impl<'b> MulAssign<&'b Fq> for Fq {
    fn mul_assign(&mut self, rhs: &'b Fq) {
        // Schoolbook multiplication

        let mut carry = 0;
        let r0 = mac_with_carry(0, self.0[0], rhs.0[0], &mut carry);
        let r1 = mac_with_carry(0, self.0[0], rhs.0[1], &mut carry);
        let r2 = mac_with_carry(0, self.0[0], rhs.0[2], &mut carry);
        let r3 = mac_with_carry(0, self.0[0], rhs.0[3], &mut carry);
        let r4 = (carry >> 64) as u64;
        let mut carry = 0;
        let r1 = mac_with_carry(r1, self.0[1], rhs.0[0], &mut carry);
        let r2 = mac_with_carry(r2, self.0[1], rhs.0[1], &mut carry);
        let r3 = mac_with_carry(r3, self.0[1], rhs.0[2], &mut carry);
        let r4 = mac_with_carry(r4, self.0[1], rhs.0[3], &mut carry);
        let r5 = (carry >> 64) as u64;
        let mut carry = 0;
        let r2 = mac_with_carry(r2, self.0[2], rhs.0[0], &mut carry);
        let r3 = mac_with_carry(r3, self.0[2], rhs.0[1], &mut carry);
        let r4 = mac_with_carry(r4, self.0[2], rhs.0[2], &mut carry);
        let r5 = mac_with_carry(r5, self.0[2], rhs.0[3], &mut carry);
        let r6 = (carry >> 64) as u64;
        let mut carry = 0;
        let r3 = mac_with_carry(r3, self.0[3], rhs.0[0], &mut carry);
        let r4 = mac_with_carry(r4, self.0[3], rhs.0[1], &mut carry);
        let r5 = mac_with_carry(r5, self.0[3], rhs.0[2], &mut carry);
        let r6 = mac_with_carry(r6, self.0[3], rhs.0[3], &mut carry);
        let r7 = (carry >> 64) as u64;

        self.montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
    }
}

/// INV = -(q^{-1} mod 2^64) mod 2^64
const INV: u64 = 0xfffffffeffffffff;

/// R = 2^256 mod q
const R: Fq = Fq([
    0x00000001fffffffe, 0x5884b7fa00034802, 0x998c4fefecbc4ff5, 0x1824b159acc5056f
]);

/// R^2 = 2^512 mod q
const R2: Fq = Fq([
    0xc999e990f3f29c6d, 0x2b6cedcb87925c23, 0x05d314967254398f, 0x0748d9d99f59ff11
]);

impl Fq {
    pub fn zero() -> Fq {
        Fq([0, 0, 0, 0])
    }

    pub fn one() -> Fq {
        R
    }

    /// Attempts to convert a little-endian byte representation of
    /// a field element into an element of `Fq`, failing if the input
    /// is not canonical (is not smaller than q).
    ///
    /// **This operation is variable time.**
    pub fn from_bytes_var(bytes: [u8; 32]) -> Option<Fq> {
        let mut tmp = Fq([0, 0, 0, 0]);

        tmp.0[0] = LittleEndian::read_u64(&bytes[0..8]);
        tmp.0[1] = LittleEndian::read_u64(&bytes[8..16]);
        tmp.0[2] = LittleEndian::read_u64(&bytes[16..24]);
        tmp.0[3] = LittleEndian::read_u64(&bytes[24..32]);

        // Check if the value is in the field
        for i in (0..4).rev() {
            if tmp.0[i] < MODULUS.0[i] {
                // Convert to Montgomery form by computing
                // (a.R^{-1} * R^2) / R = a.R
                tmp.mul_assign(&R2);

                return Some(tmp)
            }

            if tmp.0[i] > MODULUS.0[i] {
                return None
            }
        }

        // Value is equal to the modulus
        None
    }

    /// Converts an element of `Fq` into a byte representation in
    /// little-endian byte order.
    pub fn into_bytes(&self) -> [u8; 32] {
        // Turn into canonical form by computing
        // (a.R * R) / R = a
        let mut tmp = *self;
        tmp.montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3],
            0, 0, 0, 0
        );

        let mut res = [0; 32];
        LittleEndian::write_u64(&mut res[0..8], tmp.0[0]);
        LittleEndian::write_u64(&mut res[8..16], tmp.0[1]);
        LittleEndian::write_u64(&mut res[16..24], tmp.0[2]);
        LittleEndian::write_u64(&mut res[24..32], tmp.0[3]);

        res
    }

    /// Squares this element.
    pub fn square_assign(&mut self) {
        let tmp = *self;
        self.mul_assign(&tmp);
    }

    /// Exponentiates `self` by `by`, where `by` is a
    /// little-endian order integer exponent.
    pub fn pow(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            res.square_assign();
            let mut e = *e;
            for i in (0..64).rev() {
                let mut tmp = res;
                tmp.mul_assign(self);
                res.conditional_assign(&tmp, (((e >> i) & 0x1) as u8).into());
            }
        }
        res
    }

    /// Exponentiates `self` by q - 2, which has the
    /// effect of inverting the element if it is
    /// nonzero.
    pub fn pow_q_minus_2(&self) -> Self {
        self.pow(&[0xfffffffeffffffff, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48])
    }

    #[inline(always)]
    fn montgomery_reduce(
        &mut self,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64
    )
    {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = r0.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r0, k, MODULUS.0[0], &mut carry);
        let r1 = mac_with_carry(r1, k, MODULUS.0[1], &mut carry);
        let r2 = mac_with_carry(r2, k, MODULUS.0[2], &mut carry);
        let r3 = mac_with_carry(r3, k, MODULUS.0[3], &mut carry);
        let r4 = adc(r4, 0, &mut carry);
        let carry2 = (carry >> 64) as u64;
        let k = r1.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r1, k, MODULUS.0[0], &mut carry);
        let r2 = mac_with_carry(r2, k, MODULUS.0[1], &mut carry);
        let r3 = mac_with_carry(r3, k, MODULUS.0[2], &mut carry);
        let r4 = mac_with_carry(r4, k, MODULUS.0[3], &mut carry);
        let r5 = adc(r5, carry2, &mut carry);
        let carry2 = (carry >> 64) as u64;
        let k = r2.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r2, k, MODULUS.0[0], &mut carry);
        let r3 = mac_with_carry(r3, k, MODULUS.0[1], &mut carry);
        let r4 = mac_with_carry(r4, k, MODULUS.0[2], &mut carry);
        let r5 = mac_with_carry(r5, k, MODULUS.0[3], &mut carry);
        let r6 = adc(r6, carry2, &mut carry);
        let carry2 = (carry >> 64) as u64;
        let k = r3.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r3, k, MODULUS.0[0], &mut carry);
        let r4 = mac_with_carry(r4, k, MODULUS.0[1], &mut carry);
        let r5 = mac_with_carry(r5, k, MODULUS.0[2], &mut carry);
        let r6 = mac_with_carry(r6, k, MODULUS.0[3], &mut carry);
        let r7 = adc(r7, carry2, &mut carry);

        self.0[0] = r4;
        self.0[1] = r5;
        self.0[2] = r6;
        self.0[3] = r7;

        // Result may be within MODULUS of the correct value
        self.sub_assign(&MODULUS);
    }
}

#[test]
fn test_inv() {
    // Compute -(q^{-1} mod 2^64) mod 2^64 by exponentiating
    // by totient(2**64) - 1

    let mut inv = 1u64;
    for _ in 0..63 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(MODULUS.0[0]);
    }
    inv = inv.wrapping_neg();

    assert_eq!(inv, INV);
}
