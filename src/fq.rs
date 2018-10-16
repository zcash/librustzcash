use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

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

/// Compute a + b + carry, returning the result and the new carry over.
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = u128::from(a) + u128::from(b) + u128::from(carry);
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = u128::from(a).wrapping_sub(u128::from(b) + u128::from(borrow >> 63));
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = u128::from(a) + (u128::from(b) * u128::from(c)) + u128::from(carry);
    (ret as u64, (ret >> 64) as u64)
}

impl<'a> Neg for &'a Fq {
    type Output = Fq;

    fn neg(self) -> Fq {
        // Subtract `self` from `MODULUS` to negate. Ignore the final
        // borrow because it cannot underflow; self is guaranteed to
        // be in the field.
        let (mut d0, borrow) = sbb(MODULUS.0[0], self.0[0], 0);
        let (mut d1, borrow) = sbb(MODULUS.0[1], self.0[1], borrow);
        let (mut d2, borrow) = sbb(MODULUS.0[2], self.0[2], borrow);
        let (mut d3, _) = sbb(MODULUS.0[3], self.0[3], borrow);

        // `tmp` could be `MODULUS` if `self` was zero. Create a mask that is
        // zero if `self` was zero, and `u64::max_value()` if self was nonzero.
        let mask = u64::from((self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0).wrapping_sub(1);

        d0 &= mask;
        d1 &= mask;
        d2 &= mask;
        d3 &= mask;

        Fq([d0, d1, d2, d3])
    }
}

impl Neg for Fq {
    type Output = Fq;

    fn neg(self) -> Fq {
        -&self
    }
}

impl<'b> SubAssign<&'b Fq> for Fq {
    fn sub_assign(&mut self, rhs: &'b Fq) {
        let (d0, borrow) = sbb(self.0[0], rhs.0[0], 0);
        let (d1, borrow) = sbb(self.0[1], rhs.0[1], borrow);
        let (d2, borrow) = sbb(self.0[2], rhs.0[2], borrow);
        let (d3, borrow) = sbb(self.0[3], rhs.0[3], borrow);

        // If underflow occurred on the final limb, borrow = 0x111...111, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the modulus.
        let (d0, carry) = adc(d0, MODULUS.0[0] & borrow, 0);
        let (d1, carry) = adc(d1, MODULUS.0[1] & borrow, carry);
        let (d2, carry) = adc(d2, MODULUS.0[2] & borrow, carry);
        let (d3, _) = adc(d3, MODULUS.0[3] & borrow, carry);

        self.0 = [d0, d1, d2, d3];
    }
}

impl<'b> AddAssign<&'b Fq> for Fq {
    fn add_assign(&mut self, rhs: &'b Fq) {
        let (d0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (d1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (d2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (d3, _) = adc(self.0[3], rhs.0[3], carry);

        self.0 = [d0, d1, d2, d3];

        // Attempt to subtract the modulus, to ensure the value
        // is smaller than the modulus.
        self.sub_assign(&MODULUS);
    }
}

impl<'b> MulAssign<&'b Fq> for Fq {
    fn mul_assign(&mut self, rhs: &'b Fq) {
        // Schoolbook multiplication

        let (r0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (r1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (r2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (r3, r4) = mac(0, self.0[0], rhs.0[3], carry);

        let (r1, carry) = mac(r1, self.0[1], rhs.0[0], 0);
        let (r2, carry) = mac(r2, self.0[1], rhs.0[1], carry);
        let (r3, carry) = mac(r3, self.0[1], rhs.0[2], carry);
        let (r4, r5) = mac(r4, self.0[1], rhs.0[3], carry);

        let (r2, carry) = mac(r2, self.0[2], rhs.0[0], 0);
        let (r3, carry) = mac(r3, self.0[2], rhs.0[1], carry);
        let (r4, carry) = mac(r4, self.0[2], rhs.0[2], carry);
        let (r5, r6) = mac(r5, self.0[2], rhs.0[3], carry);

        let (r3, carry) = mac(r3, self.0[3], rhs.0[0], 0);
        let (r4, carry) = mac(r4, self.0[3], rhs.0[1], carry);
        let (r5, carry) = mac(r5, self.0[3], rhs.0[2], carry);
        let (r6, r7) = mac(r6, self.0[3], rhs.0[3], carry);

        self.montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
    }
}

impl_binops!(Fq);

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

// /// 7*R mod q
// const GENERATOR: Fq = Fq([
//     0x0000000efffffff1,
//     0x17e363d300189c0f,
//     0xff9c57876f8457b0,
//     0x351332208fc5a8c4,
// ]);

const S: u32 = 32;

/// GENERATOR^t where t * 2^s + 1 = q
/// with t odd.
const ROOT_OF_UNITY: Fq = Fq([
    0xb9b58d8c5f0e466a,
    0x5b1b4c801819d7ec,
    0x0af53ae352a31e64,
    0x5bf3adda19e9b27b,
]);

impl Default for Fq {
    fn default() -> Self {
        Self::zero()
    }
}

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
        // (a.R) / R = a
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
        let (r1, carry) = mac(0, self.0[0], self.0[1], 0);
        let (r2, carry) = mac(0, self.0[0], self.0[2], carry);
        let (r3, r4) = mac(0, self.0[0], self.0[3], carry);

        let (r3, carry) = mac(r3, self.0[1], self.0[2], 0);
        let (r4, r5) = mac(r4, self.0[1], self.0[3], carry);

        let (r5, r6) = mac(r5, self.0[2], self.0[3], 0);

        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        let (r0, carry) = mac(0, self.0[0], self.0[0], 0);
        let (r1, carry) = adc(0, r1, carry);
        let (r2, carry) = mac(r2, self.0[1], self.0[1], carry);
        let (r3, carry) = adc(0, r3, carry);
        let (r4, carry) = mac(r4, self.0[2], self.0[2], carry);
        let (r5, carry) = adc(0, r5, carry);
        let (r6, carry) = mac(r6, self.0[3], self.0[3], carry);
        let (r7, _) = adc(0, r7, carry);

        self.montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
    }

    pub fn square(&self) -> Self {
        let mut tmp = *self;
        tmp.square_assign();
        tmp
    }

    fn legendre_symbol(&self) -> Self {
        // Legendre symbol computed via Euler's criterion:
        // self^((q - 1) // 2)
        self.pow_vartime(&[
            0x7fffffff80000000,
            0xa9ded2017fff2dff,
            0x199cec0404d0ec02,
            0x39f6d3a994cebea4,
        ])
    }

    /// Computes the square root of this element, if it exists.
    ///
    /// **This operation is variable time.**
    pub fn sqrt_vartime(&self) -> Option<Self> {
        let legendre_symbol = self.legendre_symbol();

        if legendre_symbol == Self::zero() {
            Some(*self)
        } else if legendre_symbol != Self::one() {
            None
        } else {
            // Tonelli-Shank's algorithm for q mod 16 = 1
            // https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)

            // Initialize c to the 2^s root of unity
            let mut c = ROOT_OF_UNITY;

            // r = self^((t + 1) // 2)
            let mut r = self.pow_vartime(&[
                0x7fff2dff80000000,
                0x04d0ec02a9ded201,
                0x94cebea4199cec04,
                0x0000000039f6d3a9,
            ]);

            // t = self^t
            let mut t = self.pow_vartime(&[
                0xfffe5bfeffffffff,
                0x09a1d80553bda402,
                0x299d7d483339d808,
                0x0000000073eda753,
            ]);

            let mut m = S;

            while t != Self::one() {
                let mut i = 1;
                {
                    let mut t2i = t.square();
                    while t2i != Self::one() {
                        t2i.square_assign();
                        i += 1;
                    }
                }

                for _ in 0..(m - i - 1) {
                    c.square_assign();
                }

                r *= &c;
                c.square_assign();
                t *= &c;
                m = i;
            }

            Some(r)
        }
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

    /// Exponentiates `self` by `by`, where `by` is a
    /// little-endian order integer exponent.
    ///
    /// **This operation is variable time with respect
    /// to the exponent.** If the exponent is fixed,
    /// this operation is effectively constant time.
    pub fn pow_vartime(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            let mut e = *e;
            for i in (0..64).rev() {
                res.square_assign();

                if ((e >> i) & 1) == 1 {
                    res.mul_assign(self);
                }
            }
        }
        res
    }

    /// Exponentiates `self` by q - 2, which has the
    /// effect of inverting the element if it is
    /// nonzero.
    pub fn pow_q_minus_2(&self) -> Self {
        #[inline(always)]
        fn square_assign_multi(n: &mut Fq, num_times: usize) {
            for _ in 0..num_times {
                n.square_assign();
            }
        }
        // found using https://github.com/kwantam/addchain
        let t10 = *self;
        let mut t0 = t10;
        t0.square_assign();
        let mut t1 = t0;
        t1.mul_assign(&t10);
        let mut t16 = t0;
        t16.square_assign();
        let mut t6 = t16;
        t6.square_assign();
        let mut t5 = t6;
        t5.mul_assign(&t0);
        let mut t0 = t6;
        t0.mul_assign(&t16);
        let mut t12 = t5;
        t12.mul_assign(&t16);
        let mut t2 = t6;
        t2.square_assign();
        let mut t7 = t5;
        t7.mul_assign(&t6);
        let mut t15 = t0;
        t15.mul_assign(&t5);
        let mut t17 = t12;
        t17.square_assign();
        t1.mul_assign(&t17);
        let mut t3 = t7;
        t3.mul_assign(&t2);
        let mut t8 = t1;
        t8.mul_assign(&t17);
        let mut t4 = t8;
        t4.mul_assign(&t2);
        let mut t9 = t8;
        t9.mul_assign(&t7);
        let mut t7 = t4;
        t7.mul_assign(&t5);
        let mut t11 = t4;
        t11.mul_assign(&t17);
        let mut t5 = t9;
        t5.mul_assign(&t17);
        let mut t14 = t7;
        t14.mul_assign(&t15);
        let mut t13 = t11;
        t13.mul_assign(&t12);
        let mut t12 = t11;
        t12.mul_assign(&t17);
        t15.mul_assign(&t12);
        t16.mul_assign(&t15);
        t3.mul_assign(&t16);
        t17.mul_assign(&t3);
        t0.mul_assign(&t17);
        t6.mul_assign(&t0);
        t2.mul_assign(&t6);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t17);
        square_assign_multi(&mut t0, 9);
        t0.mul_assign(&t16);
        square_assign_multi(&mut t0, 9);
        t0.mul_assign(&t15);
        square_assign_multi(&mut t0, 9);
        t0.mul_assign(&t15);
        square_assign_multi(&mut t0, 7);
        t0.mul_assign(&t14);
        square_assign_multi(&mut t0, 7);
        t0.mul_assign(&t13);
        square_assign_multi(&mut t0, 10);
        t0.mul_assign(&t12);
        square_assign_multi(&mut t0, 9);
        t0.mul_assign(&t11);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t8);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t10);
        square_assign_multi(&mut t0, 14);
        t0.mul_assign(&t9);
        square_assign_multi(&mut t0, 10);
        t0.mul_assign(&t8);
        square_assign_multi(&mut t0, 15);
        t0.mul_assign(&t7);
        square_assign_multi(&mut t0, 10);
        t0.mul_assign(&t6);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t5);
        square_assign_multi(&mut t0, 16);
        t0.mul_assign(&t3);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t2);
        square_assign_multi(&mut t0, 7);
        t0.mul_assign(&t4);
        square_assign_multi(&mut t0, 9);
        t0.mul_assign(&t2);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t3);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t2);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t2);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t2);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t3);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t2);
        square_assign_multi(&mut t0, 8);
        t0.mul_assign(&t2);
        square_assign_multi(&mut t0, 5);
        t0.mul_assign(&t1);
        square_assign_multi(&mut t0, 5);
        t0.mul_assign(&t1);

        t0
    }

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
        let (_, carry) = mac(r0, k, MODULUS.0[0], 0);
        let (r1, carry) = mac(r1, k, MODULUS.0[1], carry);
        let (r2, carry) = mac(r2, k, MODULUS.0[2], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[3], carry);
        let (r4, carry2) = adc(r4, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS.0[0], 0);
        let (r2, carry) = mac(r2, k, MODULUS.0[1], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[2], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[3], carry);
        let (r5, carry2) = adc(r5, carry2, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS.0[0], 0);
        let (r3, carry) = mac(r3, k, MODULUS.0[1], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[2], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[3], carry);
        let (r6, carry2) = adc(r6, carry2, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS.0[0], 0);
        let (r4, carry) = mac(r4, k, MODULUS.0[1], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[2], carry);
        let (r6, carry) = mac(r6, k, MODULUS.0[3], carry);
        let (r7, _) = adc(r7, carry2, carry);

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
fn test_pow_q_minus_2_is_pow() {
    let q_minus_2 = [
        0xfffffffeffffffff,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48,
    ];

    let mut r1 = R;
    let mut r2 = R;
    let mut r3 = R;

    for _ in 0..100 {
        r1 = r1.pow_q_minus_2();
        r2 = r2.pow_vartime(&q_minus_2);
        r3 = r3.pow(&q_minus_2);

        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        // Add R so we check something different next time around
        r1.add_assign(&R);
        r2 = r1;
        r3 = r1;
    }
}
