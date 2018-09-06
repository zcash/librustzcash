use core::fmt;
use core::ops::{AddAssign, MulAssign, Neg, SubAssign};

use byteorder::{ByteOrder, LittleEndian};
use subtle::{Choice, ConditionallyAssignable, ConditionallySelectable, ConstantTimeEq};

/// Represents an element of `GF(q)`.
// The internal representation of this type is four 64-bit unsigned
// integers in little-endian order. Elements of Fq are always in
// Montgomery form; i.e., Fq(a) = aR mod q, with R = 2^256.
#[derive(Clone, Copy)]
pub struct Fq(pub(crate) [u64; 4]);

impl fmt::Debug for Fq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = self.into_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter().rev() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl ConstantTimeEq for Fq {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl PartialEq for Fq {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConditionallySelectable for Fq {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fq([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

// Constant representing the modulus
// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const MODULUS: Fq = Fq([
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
]);

/// Compute a + b + carry, returning the result and setting carry to the
/// carry value.
#[inline(always)]
fn adc(a: u64, b: u64, carry: &mut u128) -> u64 {
    *carry = u128::from(a) + u128::from(b) + (*carry >> 64);
    *carry as u64
}

/// Compute a + b + carry, returning the result the new carry over.
#[inline(always)]
fn adc2(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let adc = u128::from(a) + u128::from(b) + u128::from(carry);
    (adc as u64, (adc >> 64) as u64)
}

/// Compute a + b, returning the result and the carry over.
#[inline(always)]
fn overflowing_add(a: u64, b: u64) -> (u64, u64) {
    let (sum, overflow) = a.overflowing_add(b);
    (sum, overflow as u64)
}

/// Compute a - (b + borrow), returning the result and setting borrow to
/// the borrow value.
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: &mut u128) -> u64 {
    *borrow = u128::from(a).wrapping_sub(u128::from(b) + (*borrow >> 127));
    *borrow as u64
}

/// Compute (b * c), returning the result and the carry over.
#[inline(always)]
fn overflowing_mul(b: u64, c: u64) -> (u64, u64) {
    let mac = u128::from(b) * u128::from(c);
    (mac as u64, (mac >> 64) as u64)
}

/// Compute a + (b * c), returning the result and the carry over.
#[inline(always)]
fn mac(a: u64, b: u64, c: u64) -> (u64, u64) {
    let mac = u128::from(a) + (u128::from(b) * u128::from(c));
    (mac as u64, (mac >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
fn mac_with_carry(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let mac = u128::from(a) + (u128::from(b) * u128::from(c)) + u128::from(carry);
    (mac as u64, (mac >> 64) as u64)
}

impl<'a> Neg for &'a Fq {
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

        let (r0, carry) = overflowing_mul(self.0[0], rhs.0[0]);
        let (r1, carry) = mac(carry, self.0[0], rhs.0[1]);
        let (r2, carry) = mac(carry, self.0[0], rhs.0[2]);
        let (r3, r4) = mac(carry, self.0[0], rhs.0[3]);

        let (r1, carry) = mac(r1, self.0[1], rhs.0[0]);
        let (r2, carry) = mac_with_carry(r2, self.0[1], rhs.0[1], carry);
        let (r3, carry) = mac_with_carry(r3, self.0[1], rhs.0[2], carry);
        let (r4, r5) = mac_with_carry(r4, self.0[1], rhs.0[3], carry);

        let (r2, carry) = mac(r2, self.0[2], rhs.0[0]);
        let (r3, carry) = mac_with_carry(r3, self.0[2], rhs.0[1], carry);
        let (r4, carry) = mac_with_carry(r4, self.0[2], rhs.0[2], carry);
        let (r5, r6) = mac_with_carry(r5, self.0[2], rhs.0[3], carry);

        let (r3, carry) = mac(r3, self.0[3], rhs.0[0]);
        let (r4, carry) = mac_with_carry(r4, self.0[3], rhs.0[1], carry);
        let (r5, carry) = mac_with_carry(r5, self.0[3], rhs.0[2], carry);
        let (r6, r7) = mac_with_carry(r6, self.0[3], rhs.0[3], carry);

        self.montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
    }
}

/// INV = -(q^{-1} mod 2^64) mod 2^64
const INV: u64 = 0xfffffffeffffffff;

/// R = 2^256 mod q
const R: Fq = Fq([
    0x00000001fffffffe,
    0x5884b7fa00034802,
    0x998c4fefecbc4ff5,
    0x1824b159acc5056f,
]);

/// R^2 = 2^512 mod q
const R2: Fq = Fq([
    0xc999e990f3f29c6d,
    0x2b6cedcb87925c23,
    0x05d314967254398f,
    0x0748d9d99f59ff11,
]);

impl Fq {
    pub fn new(limbs: [u64; 4]) -> Fq {
        Fq(limbs)
    }

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
    pub fn from_bytes_vartime(bytes: [u8; 32]) -> Option<Fq> {
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

                return Some(tmp);
            }

            if tmp.0[i] > MODULUS.0[i] {
                return None;
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
        tmp.montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);

        let mut res = [0; 32];
        LittleEndian::write_u64(&mut res[0..8], tmp.0[0]);
        LittleEndian::write_u64(&mut res[8..16], tmp.0[1]);
        LittleEndian::write_u64(&mut res[16..24], tmp.0[2]);
        LittleEndian::write_u64(&mut res[24..32], tmp.0[3]);

        res
    }

    /// Squares this element.
    pub fn square_assign(&mut self) {
        let (r1, carry) = overflowing_mul(self.0[0], self.0[1]);
        let (r2, carry) = mac(carry, self.0[0], self.0[2]);
        let (r3, r4) = mac(carry, self.0[0], self.0[3]);

        let (r3, carry) = mac(r3, self.0[1], self.0[2]);
        let (r4, r5) = mac_with_carry(r4, self.0[1], self.0[3], carry);

        let (r5, r6) = mac(r5, self.0[2], self.0[3]);

        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        let (r0, carry) = overflowing_mul(self.0[0], self.0[0]);
        let (r1, carry) = overflowing_add(r1, carry);
        let (r2, carry) = mac_with_carry(r2, self.0[1], self.0[1], carry);
        let (r3, carry) = overflowing_add(r3, carry);
        let (r4, carry) = mac_with_carry(r4, self.0[2], self.0[2], carry);
        let (r5, carry) = overflowing_add(r5, carry);
        let (r6, carry) = mac_with_carry(r6, self.0[3], self.0[3], carry);
        let r7 = r7 + carry;

        self.montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
    }

    /// Exponentiates `self` by `by`, where `by` is a
    /// little-endian order integer exponent.
    pub fn pow(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            let mut e = *e;
            for i in (0..64).rev() {
                res.square_assign();
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
        self.pow(&[
            0xfffffffeffffffff,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ])
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
        r7: u64,
    ) {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = r0.wrapping_mul(INV);
        let (_, carry) = mac(r0, k, MODULUS.0[0]);
        let (r1, carry) = mac_with_carry(r1, k, MODULUS.0[1], carry);
        let (r2, carry) = mac_with_carry(r2, k, MODULUS.0[2], carry);
        let (r3, carry) = mac_with_carry(r3, k, MODULUS.0[3], carry);
        let (r4, carry2) = adc2(r4, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS.0[0]);
        let (r2, carry) = mac_with_carry(r2, k, MODULUS.0[1], carry);
        let (r3, carry) = mac_with_carry(r3, k, MODULUS.0[2], carry);
        let (r4, carry) = mac_with_carry(r4, k, MODULUS.0[3], carry);
        let (r5, carry2) = adc2(r5, carry2, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS.0[0]);
        let (r3, carry) = mac_with_carry(r3, k, MODULUS.0[1], carry);
        let (r4, carry) = mac_with_carry(r4, k, MODULUS.0[2], carry);
        let (r5, carry) = mac_with_carry(r5, k, MODULUS.0[3], carry);
        let (r6, carry2) = adc2(r6, carry2, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS.0[0]);
        let (r4, carry) = mac_with_carry(r4, k, MODULUS.0[1], carry);
        let (r5, carry) = mac_with_carry(r5, k, MODULUS.0[2], carry);
        let (r6, carry) = mac_with_carry(r6, k, MODULUS.0[3], carry);
        let r7 = r7 + carry2 + carry;

        self.0[0] = r4;
        self.0[1] = r5;
        self.0[2] = r6;
        self.0[3] = r7;

        // Result may be within MODULUS of the correct value
        self.sub_assign(&MODULUS);
    }
}

impl<'a> From<&'a Fq> for [u8; 32] {
    fn from(value: &'a Fq) -> [u8; 32] {
        value.into_bytes()
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

#[test]
fn test_debug() {
    assert_eq!(
        format!("{:?}", Fq::zero()),
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        format!("{:?}", Fq::one()),
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(
        format!("{:?}", R2),
        "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe"
    );
}

#[test]
fn test_equality() {
    assert_eq!(Fq::zero(), Fq::zero());
    assert_eq!(Fq::one(), Fq::one());
    assert_eq!(R2, R2);

    assert!(Fq::zero() != Fq::one());
    assert!(Fq::one() != R2);
}

#[test]
fn test_into_bytes() {
    assert_eq!(
        Fq::zero().into_bytes(),
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );

    assert_eq!(
        Fq::one().into_bytes(),
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );

    assert_eq!(
        R2.into_bytes(),
        [
            254, 255, 255, 255, 1, 0, 0, 0, 2, 72, 3, 0, 250, 183, 132, 88, 245, 79, 188, 236, 239,
            79, 140, 153, 111, 5, 197, 172, 89, 177, 36, 24
        ]
    );

    assert_eq!(
        (-&Fq::one()).into_bytes(),
        [
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]
    );

    assert_eq!(
        (-&Fq::one()).into_bytes(),
        [
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]
    );
}

#[test]
fn test_from_bytes_vartime() {
    assert_eq!(
        Fq::from_bytes_vartime([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]).unwrap(),
        Fq::zero()
    );

    assert_eq!(
        Fq::from_bytes_vartime([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]).unwrap(),
        Fq::one()
    );

    assert_eq!(
        Fq::from_bytes_vartime([
            254, 255, 255, 255, 1, 0, 0, 0, 2, 72, 3, 0, 250, 183, 132, 88, 245, 79, 188, 236, 239,
            79, 140, 153, 111, 5, 197, 172, 89, 177, 36, 24
        ]).unwrap(),
        R2
    );

    // -1 should work
    assert!(
        Fq::from_bytes_vartime([
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]).is_some()
    );

    // modulus is invalid
    assert!(
        Fq::from_bytes_vartime([
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]).is_none()
    );

    // Anything larger than the modulus is invalid
    assert!(
        Fq::from_bytes_vartime([
            2, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]).is_none()
    );
    assert!(
        Fq::from_bytes_vartime([
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 58, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]).is_none()
    );
    assert!(
        Fq::from_bytes_vartime([
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 116
        ]).is_none()
    );
}

#[cfg(test)]
const LARGEST: Fq = Fq([
    0xffffffff00000000,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
]);

#[test]
fn test_addition() {
    let mut tmp = LARGEST;
    tmp += &LARGEST;

    assert_eq!(
        tmp,
        Fq([
            0xfffffffeffffffff,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48
        ])
    );

    let mut tmp = LARGEST;
    tmp += &Fq([1, 0, 0, 0]);

    assert_eq!(tmp, Fq::zero());
}

#[test]
fn test_negation() {
    let tmp = -&LARGEST;

    assert_eq!(tmp, Fq([1, 0, 0, 0]));

    let tmp = -&Fq::zero();
    assert_eq!(tmp, Fq::zero());
    let tmp = -&Fq([1, 0, 0, 0]);
    assert_eq!(tmp, LARGEST);
}

#[test]
fn test_subtraction() {
    let mut tmp = LARGEST;
    tmp -= &LARGEST;

    assert_eq!(tmp, Fq::zero());

    let mut tmp = Fq::zero();
    tmp -= &LARGEST;

    let mut tmp2 = MODULUS;
    tmp2 -= &LARGEST;

    assert_eq!(tmp, tmp2);
}

#[test]
fn test_multiplication() {
    let mut cur = LARGEST;

    for _ in 0..100 {
        let mut tmp = cur;
        tmp *= &cur;

        let mut tmp2 = Fq::zero();
        for b in cur
            .into_bytes()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
        {
            let tmp3 = tmp2;
            tmp2.add_assign(&tmp3);

            if b {
                tmp2.add_assign(&cur);
            }
        }

        assert_eq!(tmp, tmp2);

        cur.add_assign(&LARGEST);
    }
}

#[test]
fn test_squaring() {
    let mut cur = LARGEST;

    for _ in 0..100 {
        let mut tmp = cur;
        tmp.square_assign();

        let mut tmp2 = Fq::zero();
        for b in cur
            .into_bytes()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
        {
            let tmp3 = tmp2;
            tmp2.add_assign(&tmp3);

            if b {
                tmp2.add_assign(&cur);
            }
        }

        assert_eq!(tmp, tmp2);

        cur.add_assign(&LARGEST);
    }
}

#[test]
fn test_inversion() {
    assert_eq!(Fq::one().pow_q_minus_2(), Fq::one());
    assert_eq!((-&Fq::one()).pow_q_minus_2(), -&Fq::one());

    let mut tmp = R2;

    for _ in 0..100 {
        let mut tmp2 = tmp.pow_q_minus_2();
        tmp2.mul_assign(&tmp);

        assert_eq!(tmp2, Fq::one());

        tmp.add_assign(&R2);
    }
}

#[test]
fn test_square_assign_equals_mul_assign() {
    let mut n1 = Fq([2, 2, 2, 2]);
    let mut n2 = Fq([2, 2, 2, 2]);
    for _ in 1..100 {
        let tmp = n1;
        n1.mul_assign(&tmp);
        n2.square_assign();
        assert_eq!(n1, n2);
    }
}
