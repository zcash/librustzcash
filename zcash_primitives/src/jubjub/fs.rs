use byteorder::{ByteOrder, LittleEndian};
use ff::{adc, mac_with_carry, sbb, BitIterator, Field, PrimeField};
use rand_core::RngCore;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::ToUniform;

// s = 6554484396890773809930967563523245729705921265872317281365359162392183254199
const MODULUS: FsRepr = FsRepr([
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
]);

const MODULUS_LIMBS: Fs = Fs([
    0xd0970e5ed6f72cb7,
    0xa6682093ccc81082,
    0x6673b0101343b00,
    0xe7db4ea6533afa9,
]);

// The number of bits needed to represent the modulus.
const MODULUS_BITS: u32 = 252;

// The number of bits that must be shaved from the beginning of
// the representation when randomly sampling.
const REPR_SHAVE_BITS: u32 = 4;

// R = 2**256 % s
const R: Fs = Fs([
    0x25f80bb3b99607d9,
    0xf315d62f66b6e750,
    0x932514eeeb8814f4,
    0x9a6fc6f479155c6,
]);

// R2 = R^2 % s
const R2: Fs = Fs([
    0x67719aa495e57731,
    0x51b0cef09ce3fc26,
    0x69dab7fac026e9a5,
    0x4f6547b8d127688,
]);

// INV = -(s^{-1} mod 2^64) mod s
const INV: u64 = 0x1ba3a358ef788ef9;

// GENERATOR = 6 (multiplicative generator of r-1 order, that is also quadratic nonresidue)
const GENERATOR: Fs = Fs([
    0x720b1b19d49ea8f1,
    0xbf4aa36101f13a58,
    0x5fa8cc968193ccbb,
    0xe70cbdc7dccf3ac,
]);

// 2^S * t = MODULUS - 1 with t odd
const S: u32 = 1;

// 2^S root of unity computed by GENERATOR^t
const ROOT_OF_UNITY: Fs = Fs([
    0xaa9f02ab1d6124de,
    0xb3524a6466112932,
    0x7342261215ac260b,
    0x4d6b87b1da259e2,
]);

// -((2**256) mod s) mod s
const NEGATIVE_ONE: Fs = Fs([
    0xaa9f02ab1d6124de,
    0xb3524a6466112932,
    0x7342261215ac260b,
    0x4d6b87b1da259e2,
]);

/// This is the underlying representation of an element of `Fs`.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct FsRepr(pub [u8; 32]);

impl ::std::fmt::Display for FsRepr {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "0x")?;
        for i in self.0.iter().rev() {
            write!(f, "{:02x}", *i)?;
        }

        Ok(())
    }
}

impl AsRef<[u8]> for FsRepr {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for FsRepr {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// This is an element of the scalar field of the Jubjub curve.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Fs([u64; 4]);

impl Default for Fs {
    fn default() -> Self {
        Fs::zero()
    }
}

impl ConstantTimeEq for Fs {
    fn ct_eq(&self, other: &Fs) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl ::std::fmt::Display for Fs {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "Fs({})", self.to_repr())
    }
}

impl From<u64> for Fs {
    #[inline(always)]
    fn from(val: u64) -> Fs {
        let mut raw = [0u64; 4];
        raw[0] = val;
        Fs(raw) * R2
    }
}

impl From<Fs> for FsRepr {
    fn from(e: Fs) -> FsRepr {
        e.to_repr()
    }
}

impl<'a> From<&'a Fs> for FsRepr {
    fn from(e: &'a Fs) -> FsRepr {
        e.to_repr()
    }
}

impl ConditionallySelectable for Fs {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fs([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl Neg for Fs {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self {
        if !self.is_zero() {
            let mut tmp = MODULUS_LIMBS;
            tmp.sub_noborrow(&self);
            self = tmp;
        }
        self
    }
}

impl<'r> Add<&'r Fs> for Fs {
    type Output = Self;

    #[inline]
    fn add(self, other: &Self) -> Self {
        let mut ret = self;
        ret.add_assign(other);
        ret
    }
}

impl Add for Fs {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        self + &other
    }
}

impl<'r> AddAssign<&'r Fs> for Fs {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        // This cannot exceed the backing capacity.
        self.add_nocarry(&other);

        // However, it may need to be reduced.
        self.reduce();
    }
}

impl AddAssign for Fs {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        self.add_assign(&other);
    }
}

impl<'r> Sub<&'r Fs> for Fs {
    type Output = Self;

    #[inline]
    fn sub(self, other: &Self) -> Self {
        let mut ret = self;
        ret.sub_assign(other);
        ret
    }
}

impl Sub for Fs {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        self - &other
    }
}

impl<'r> SubAssign<&'r Fs> for Fs {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        // If `other` is larger than `self`, we'll need to add the modulus to self first.
        if other.cmp_native(self) == ::core::cmp::Ordering::Greater {
            self.add_nocarry(&MODULUS_LIMBS);
        }

        self.sub_noborrow(&other);
    }
}

impl SubAssign for Fs {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        self.sub_assign(&other);
    }
}

impl<'r> Mul<&'r Fs> for Fs {
    type Output = Self;

    #[inline]
    fn mul(self, other: &Self) -> Self {
        let mut ret = self;
        ret.mul_assign(other);
        ret
    }
}

impl Mul for Fs {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        self * &other
    }
}

impl<'r> MulAssign<&'r Fs> for Fs {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        let mut carry = 0;
        let r0 = mac_with_carry(0, self.0[0], other.0[0], &mut carry);
        let r1 = mac_with_carry(0, self.0[0], other.0[1], &mut carry);
        let r2 = mac_with_carry(0, self.0[0], other.0[2], &mut carry);
        let r3 = mac_with_carry(0, self.0[0], other.0[3], &mut carry);
        let r4 = carry;
        let mut carry = 0;
        let r1 = mac_with_carry(r1, self.0[1], other.0[0], &mut carry);
        let r2 = mac_with_carry(r2, self.0[1], other.0[1], &mut carry);
        let r3 = mac_with_carry(r3, self.0[1], other.0[2], &mut carry);
        let r4 = mac_with_carry(r4, self.0[1], other.0[3], &mut carry);
        let r5 = carry;
        let mut carry = 0;
        let r2 = mac_with_carry(r2, self.0[2], other.0[0], &mut carry);
        let r3 = mac_with_carry(r3, self.0[2], other.0[1], &mut carry);
        let r4 = mac_with_carry(r4, self.0[2], other.0[2], &mut carry);
        let r5 = mac_with_carry(r5, self.0[2], other.0[3], &mut carry);
        let r6 = carry;
        let mut carry = 0;
        let r3 = mac_with_carry(r3, self.0[3], other.0[0], &mut carry);
        let r4 = mac_with_carry(r4, self.0[3], other.0[1], &mut carry);
        let r5 = mac_with_carry(r5, self.0[3], other.0[2], &mut carry);
        let r6 = mac_with_carry(r6, self.0[3], other.0[3], &mut carry);
        let r7 = carry;
        self.mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
    }
}

impl MulAssign for Fs {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        self.mul_assign(&other);
    }
}

impl PrimeField for Fs {
    type Repr = FsRepr;
    type ReprEndianness = byteorder::LittleEndian;

    fn from_repr(r: FsRepr) -> Option<Fs> {
        let r = {
            let mut inner = [0; 4];
            LittleEndian::read_u64_into(r.as_ref(), &mut inner[..]);
            Fs(inner)
        };

        if r.is_valid() {
            Some(r * &R2)
        } else {
            None
        }
    }

    fn to_repr(&self) -> FsRepr {
        let mut r = *self;
        r.mont_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);

        let mut repr = [0; 32];
        LittleEndian::write_u64_into(&r.0, &mut repr[..]);
        FsRepr(repr)
    }

    #[inline(always)]
    fn is_odd(&self) -> bool {
        let mut r = *self;
        r.mont_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);

        r.0[0] & 1 == 1
    }

    fn char() -> FsRepr {
        MODULUS
    }

    const NUM_BITS: u32 = MODULUS_BITS;

    const CAPACITY: u32 = Self::NUM_BITS - 1;

    fn multiplicative_generator() -> Self {
        GENERATOR
    }

    const S: u32 = S;

    fn root_of_unity() -> Self {
        ROOT_OF_UNITY
    }
}

impl Field for Fs {
    fn random<R: RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
        loop {
            let mut tmp = {
                let mut repr = [0u64; 4];
                for limb in &mut repr {
                    *limb = rng.next_u64();
                }
                Fs(repr)
            };

            // Mask away the unused most-significant bits.
            tmp.0.as_mut()[3] &= 0xffffffffffffffff >> REPR_SHAVE_BITS;

            if tmp.is_valid() {
                return tmp;
            }
        }
    }

    #[inline]
    fn zero() -> Self {
        Fs::from(0)
    }

    #[inline]
    fn one() -> Self {
        R
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.iter().all(|&e| e == 0)
    }

    #[inline]
    fn double(&self) -> Self {
        let mut ret = *self;

        // This cannot exceed the backing capacity.
        let mut last = 0;
        for i in &mut ret.0 {
            let tmp = *i >> 63;
            *i <<= 1;
            *i |= last;
            last = tmp;
        }

        // However, it may need to be reduced.
        ret.reduce();

        ret
    }

    fn invert(&self) -> CtOption<Self> {
        // We need to find b such that b * a ≡ 1 mod p. As we are in a prime
        // field, we can apply Fermat's Little Theorem:
        //
        //    a^p         ≡ a mod p
        //    a^(p-1)     ≡ 1 mod p
        //    a^(p-2) * a ≡ 1 mod p
        //
        // Thus inversion can be implemented with a single exponentiation.
        let inverse = self.pow_vartime(&[
            0xd097_0e5e_d6f7_2cb5u64,
            0xa668_2093_ccc8_1082,
            0x0667_3b01_0134_3b00,
            0x0e7d_b4ea_6533_afa9,
        ]);

        CtOption::new(inverse, Choice::from(if self.is_zero() { 0 } else { 1 }))
    }

    #[inline]
    fn square(&self) -> Self {
        let mut carry = 0;
        let r1 = mac_with_carry(0, self.0[0], self.0[1], &mut carry);
        let r2 = mac_with_carry(0, self.0[0], self.0[2], &mut carry);
        let r3 = mac_with_carry(0, self.0[0], self.0[3], &mut carry);
        let r4 = carry;
        let mut carry = 0;
        let r3 = mac_with_carry(r3, self.0[1], self.0[2], &mut carry);
        let r4 = mac_with_carry(r4, self.0[1], self.0[3], &mut carry);
        let r5 = carry;
        let mut carry = 0;
        let r5 = mac_with_carry(r5, self.0[2], self.0[3], &mut carry);
        let r6 = carry;

        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        let mut carry = 0;
        let r0 = mac_with_carry(0, self.0[0], self.0[0], &mut carry);
        let r1 = adc(r1, 0, &mut carry);
        let r2 = mac_with_carry(r2, self.0[1], self.0[1], &mut carry);
        let r3 = adc(r3, 0, &mut carry);
        let r4 = mac_with_carry(r4, self.0[2], self.0[2], &mut carry);
        let r5 = adc(r5, 0, &mut carry);
        let r6 = mac_with_carry(r6, self.0[3], self.0[3], &mut carry);
        let r7 = adc(r7, 0, &mut carry);

        let mut ret = *self;
        ret.mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
        ret
    }

    fn sqrt(&self) -> CtOption<Self> {
        // Shank's algorithm for s mod 4 = 3
        // https://eprint.iacr.org/2012/685.pdf (page 9, algorithm 2)

        // a1 = self^((s - 3) // 4)
        let mut a1 = self.pow_vartime([
            0xb425c397b5bdcb2du64,
            0x299a0824f3320420,
            0x4199cec0404d0ec0,
            0x39f6d3a994cebea,
        ]);
        let mut a0 = a1.square();
        a0.mul_assign(self);
        a1.mul_assign(self);

        CtOption::new(a1, !a0.ct_eq(&NEGATIVE_ONE))
    }
}

impl Fs {
    /// Compares two elements in native representation. This is only used
    /// internally.
    #[inline(always)]
    fn cmp_native(&self, other: &Fs) -> ::std::cmp::Ordering {
        for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
            if a < b {
                return ::std::cmp::Ordering::Less;
            } else if a > b {
                return ::std::cmp::Ordering::Greater;
            }
        }

        ::std::cmp::Ordering::Equal
    }

    /// Determines if the element is really in the field. This is only used
    /// internally.
    #[inline(always)]
    fn is_valid(&self) -> bool {
        // The Ord impl calls `reduce`, which in turn calls `is_valid`, so we use
        // this internal function to eliminate the cycle.
        self.cmp_native(&MODULUS_LIMBS) == ::core::cmp::Ordering::Less
    }

    #[inline(always)]
    fn add_nocarry(&mut self, other: &Fs) {
        let mut carry = 0;

        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a = adc(*a, *b, &mut carry);
        }
    }

    #[inline(always)]
    fn sub_noborrow(&mut self, other: &Fs) {
        let mut borrow = 0;

        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a = sbb(*a, *b, &mut borrow);
        }
    }

    /// Subtracts the modulus from this element if this element is not in the
    /// field. Only used internally.
    #[inline(always)]
    fn reduce(&mut self) {
        if !self.is_valid() {
            self.sub_noborrow(&MODULUS_LIMBS);
        }
    }

    #[inline(always)]
    fn mont_reduce(
        &mut self,
        r0: u64,
        mut r1: u64,
        mut r2: u64,
        mut r3: u64,
        mut r4: u64,
        mut r5: u64,
        mut r6: u64,
        mut r7: u64,
    ) {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = r0.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r0, k, MODULUS_LIMBS.0[0], &mut carry);
        r1 = mac_with_carry(r1, k, MODULUS_LIMBS.0[1], &mut carry);
        r2 = mac_with_carry(r2, k, MODULUS_LIMBS.0[2], &mut carry);
        r3 = mac_with_carry(r3, k, MODULUS_LIMBS.0[3], &mut carry);
        r4 = adc(r4, 0, &mut carry);
        let carry2 = carry;
        let k = r1.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r1, k, MODULUS_LIMBS.0[0], &mut carry);
        r2 = mac_with_carry(r2, k, MODULUS_LIMBS.0[1], &mut carry);
        r3 = mac_with_carry(r3, k, MODULUS_LIMBS.0[2], &mut carry);
        r4 = mac_with_carry(r4, k, MODULUS_LIMBS.0[3], &mut carry);
        r5 = adc(r5, carry2, &mut carry);
        let carry2 = carry;
        let k = r2.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r2, k, MODULUS_LIMBS.0[0], &mut carry);
        r3 = mac_with_carry(r3, k, MODULUS_LIMBS.0[1], &mut carry);
        r4 = mac_with_carry(r4, k, MODULUS_LIMBS.0[2], &mut carry);
        r5 = mac_with_carry(r5, k, MODULUS_LIMBS.0[3], &mut carry);
        r6 = adc(r6, carry2, &mut carry);
        let carry2 = carry;
        let k = r3.wrapping_mul(INV);
        let mut carry = 0;
        mac_with_carry(r3, k, MODULUS_LIMBS.0[0], &mut carry);
        r4 = mac_with_carry(r4, k, MODULUS_LIMBS.0[1], &mut carry);
        r5 = mac_with_carry(r5, k, MODULUS_LIMBS.0[2], &mut carry);
        r6 = mac_with_carry(r6, k, MODULUS_LIMBS.0[3], &mut carry);
        r7 = adc(r7, carry2, &mut carry);
        self.0[0] = r4;
        self.0[1] = r5;
        self.0[2] = r6;
        self.0[3] = r7;
        self.reduce();
    }

    fn mul_bits<S: AsRef<[u8]>>(&self, bits: BitIterator<u8, S>) -> Self {
        let mut res = Self::zero();
        for bit in bits {
            res = res.double();

            if bit {
                res.add_assign(self)
            }
        }
        res
    }
}

impl ToUniform for Fs {
    /// Convert a little endian byte string into a uniform
    /// field element. The number is reduced mod s. The caller
    /// is responsible for ensuring the input is 64 bytes of
    /// Random Oracle output.
    fn to_uniform(digest: &[u8]) -> Self {
        assert_eq!(digest.len(), 64);
        Self::one().mul_bits(BitIterator::<u8, _>::new(digest))
    }
}

#[test]
fn test_neg_one() {
    let o = Fs::one().neg();

    assert_eq!(NEGATIVE_ONE, o);
}

#[cfg(test)]
use rand_core::SeedableRng;
#[cfg(test)]
use rand_xorshift::XorShiftRng;

#[test]
fn test_fs_is_valid() {
    let mut a = MODULUS_LIMBS;
    assert!(!a.is_valid());
    a.sub_noborrow(&Fs([1, 0, 0, 0]));
    assert!(a.is_valid());
    assert!(Fs::zero().is_valid());
    assert!(Fs([
        0xd0970e5ed6f72cb6,
        0xa6682093ccc81082,
        0x6673b0101343b00,
        0xe7db4ea6533afa9
    ])
    .is_valid());
    assert!(!Fs([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff
    ])
    .is_valid());

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let a = Fs::random(&mut rng);
        assert!(a.is_valid());
    }
}

#[test]
fn test_fs_add_assign() {
    {
        // Random number
        let mut tmp = Fs::from_str(
            "4577408157467272683998459759522778614363623736323078995109579213719612604198",
        )
        .unwrap();
        assert!(tmp.is_valid());
        // Test that adding zero has no effect.
        tmp.add_assign(&Fs::zero());
        assert_eq!(
            tmp,
            Fs([
                0x8e6bfff4722d6e67,
                0x5643da5c892044f9,
                0x9465f4b281921a69,
                0x25f752d3edd7162
            ])
        );
        // Add one and test for the result.
        tmp.add_assign(&Fs([1, 0, 0, 0]));
        assert_eq!(
            tmp,
            Fs([
                0x8e6bfff4722d6e68,
                0x5643da5c892044f9,
                0x9465f4b281921a69,
                0x25f752d3edd7162
            ])
        );
        // Add another random number that exercises the reduction.
        tmp.add_assign(&Fs([
            0xb634d07bc42d4a70,
            0xf724f0c008411f5f,
            0x456d4053d865af34,
            0x24ce814e8c63027,
        ]));
        assert_eq!(
            tmp,
            Fs([
                0x44a0d070365ab8d8,
                0x4d68cb1c91616459,
                0xd9d3350659f7c99e,
                0x4ac5d4227a3a189
            ])
        );
        // Add one to (s - 1) and test for the result.
        tmp = Fs([
            0xd0970e5ed6f72cb6,
            0xa6682093ccc81082,
            0x6673b0101343b00,
            0xe7db4ea6533afa9,
        ]);
        tmp.add_assign(&Fs([1, 0, 0, 0]));
        assert!(tmp.is_zero());
        // Add a random number to another one such that the result is s - 1
        tmp = Fs([
            0xa11fda5950ce3636,
            0x922e0dbccfe0ca0e,
            0xacebb6e215b82d4a,
            0x97ffb8cdc3aee93,
        ]);
        tmp.add_assign(&Fs([
            0x2f7734058628f680,
            0x143a12d6fce74674,
            0x597b841eeb7c0db6,
            0x4fdb95d88f8c115,
        ]));
        assert_eq!(
            tmp,
            Fs([
                0xd0970e5ed6f72cb6,
                0xa6682093ccc81082,
                0x6673b0101343b00,
                0xe7db4ea6533afa9
            ])
        );
        // Add one to the result and test for it.
        tmp.add_assign(&Fs([1, 0, 0, 0]));
        assert!(tmp.is_zero());
    }

    // Test associativity

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Generate a, b, c and ensure (a + b) + c == a + (b + c).
        let a = Fs::random(&mut rng);
        let b = Fs::random(&mut rng);
        let c = Fs::random(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);

        let mut tmp2 = b;
        tmp2.add_assign(&c);
        tmp2.add_assign(&a);

        assert!(tmp1.is_valid());
        assert!(tmp2.is_valid());
        assert_eq!(tmp1, tmp2);
    }
}

#[test]
fn test_fs_sub_assign() {
    {
        // Test arbitrary subtraction that tests reduction.
        let mut tmp = Fs([
            0xb384d9f6877afd99,
            0x4442513958e1a1c1,
            0x352c4b8a95eccc3f,
            0x2db62dee4b0f2,
        ]);
        tmp.sub_assign(&Fs([
            0xec5bd2d13ed6b05a,
            0x2adc0ab3a39b5fa,
            0x82d3360a493e637e,
            0x53ccff4a64d6679,
        ]));
        assert_eq!(
            tmp,
            Fs([
                0x97c015841f9b79f6,
                0xe7fcb121eb6ffc49,
                0xb8c050814de2a3c1,
                0x943c0589dcafa21
            ])
        );

        // Test the opposite subtraction which doesn't test reduction.
        tmp = Fs([
            0xec5bd2d13ed6b05a,
            0x2adc0ab3a39b5fa,
            0x82d3360a493e637e,
            0x53ccff4a64d6679,
        ]);
        tmp.sub_assign(&Fs([
            0xb384d9f6877afd99,
            0x4442513958e1a1c1,
            0x352c4b8a95eccc3f,
            0x2db62dee4b0f2,
        ]));
        assert_eq!(
            tmp,
            Fs([
                0x38d6f8dab75bb2c1,
                0xbe6b6f71e1581439,
                0x4da6ea7fb351973e,
                0x539f491c768b587
            ])
        );

        // Test for sensible results with zero
        tmp = Fs::zero();
        tmp.sub_assign(&Fs::from(0));
        assert!(tmp.is_zero());

        tmp = Fs([
            0x361e16aef5cce835,
            0x55bbde2536e274c1,
            0x4dc77a63fd15ee75,
            0x1e14bb37c14f230,
        ]);
        tmp.sub_assign(&Fs::from(0));
        assert_eq!(
            tmp,
            Fs([
                0x361e16aef5cce835,
                0x55bbde2536e274c1,
                0x4dc77a63fd15ee75,
                0x1e14bb37c14f230
            ])
        );
    }

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure that (a - b) + (b - a) = 0.
        let a = Fs::random(&mut rng);
        let b = Fs::random(&mut rng);

        let mut tmp1 = a;
        tmp1.sub_assign(&b);

        let mut tmp2 = b;
        tmp2.sub_assign(&a);

        tmp1.add_assign(&tmp2);
        assert!(tmp1.is_zero());
    }
}

#[test]
fn test_fs_mul_assign() {
    let mut tmp = Fs([
        0xb433b01287f71744,
        0x4eafb86728c4d108,
        0xfdd52c14b9dfbe65,
        0x2ff1f3434821118,
    ]);
    tmp.mul_assign(&Fs([
        0xdae00fc63c9fa90f,
        0x5a5ed89b96ce21ce,
        0x913cd26101bd6f58,
        0x3f0822831697fe9,
    ]));
    assert!(
        tmp == Fs([
            0xb68ecb61d54d2992,
            0x5ff95874defce6a6,
            0x3590eb053894657d,
            0x53823a118515933
        ])
    );

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000000 {
        // Ensure that (a * b) * c = a * (b * c)
        let a = Fs::random(&mut rng);
        let b = Fs::random(&mut rng);
        let c = Fs::random(&mut rng);

        let mut tmp1 = a;
        tmp1.mul_assign(&b);
        tmp1.mul_assign(&c);

        let mut tmp2 = b;
        tmp2.mul_assign(&c);
        tmp2.mul_assign(&a);

        assert_eq!(tmp1, tmp2);
    }

    for _ in 0..1000000 {
        // Ensure that r * (a + b + c) = r*a + r*b + r*c

        let r = Fs::random(&mut rng);
        let mut a = Fs::random(&mut rng);
        let mut b = Fs::random(&mut rng);
        let mut c = Fs::random(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);
        tmp1.mul_assign(&r);

        a.mul_assign(&r);
        b.mul_assign(&r);
        c.mul_assign(&r);

        a.add_assign(&b);
        a.add_assign(&c);

        assert_eq!(tmp1, a);
    }
}

#[test]
fn test_fs_squaring() {
    let a = Fs([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xe7db4ea6533afa8,
    ]);
    assert!(a.is_valid());
    assert_eq!(
        a.square(),
        Fs::from_repr(FsRepr([
            0xaa, 0xfb, 0x52, 0xbc, 0x5c, 0xf5, 0xc7, 0x12, 0x9e, 0xce, 0xe6, 0xb5, 0xa0, 0x98,
            0xdc, 0xde, 0x6a, 0x39, 0xa5, 0x26, 0x27, 0x89, 0xd2, 0x0a, 0xb3, 0x77, 0xee, 0x8f,
            0xaf, 0x82, 0xfe, 0x09,
        ]))
        .unwrap()
    );

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000000 {
        // Ensure that (a * a) = a^2
        let a = Fs::random(&mut rng);

        let tmp = a.square();

        let mut tmp2 = a;
        tmp2.mul_assign(&a);

        assert_eq!(tmp, tmp2);
    }
}

#[test]
fn test_fs_invert() {
    assert!(bool::from(Fs::zero().invert().is_none()));

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let one = Fs::one();

    for _ in 0..1000 {
        // Ensure that a * a^-1 = 1
        let mut a = Fs::random(&mut rng);
        let ainv = a.invert().unwrap();
        a.mul_assign(&ainv);
        assert_eq!(a, one);
    }
}

#[test]
fn test_fs_double() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure doubling a is equivalent to adding a to itself.
        let a = Fs::random(&mut rng);
        assert_eq!(a.double(), a + a);
    }
}

#[test]
fn test_fs_neg() {
    {
        let a = Fs::zero().neg();

        assert!(a.is_zero());
    }

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure (a - (-a)) = 0.
        let mut a = Fs::random(&mut rng);
        let b = a.neg();
        a.add_assign(&b);

        assert!(a.is_zero());
    }
}

#[test]
fn test_fs_pow() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for i in 0u64..1000 {
        // Exponentiate by various small numbers and ensure it consists with repeated
        // multiplication.
        let a = Fs::random(&mut rng);
        let target = a.pow_vartime(&[i]);
        let mut c = Fs::one();
        for _ in 0..i {
            c.mul_assign(&a);
        }
        assert_eq!(c, target);
    }

    use byteorder::ByteOrder;
    let mut char_limbs = [0; 4];
    byteorder::LittleEndian::read_u64_into(Fs::char().as_ref(), &mut char_limbs);

    for _ in 0..1000 {
        // Exponentiating by the modulus should have no effect in a prime field.
        let a = Fs::random(&mut rng);

        assert_eq!(a, a.pow_vartime(char_limbs));
    }
}

#[test]
fn test_fs_sqrt() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    assert_eq!(Fs::zero().sqrt().unwrap(), Fs::zero());

    for _ in 0..1000 {
        // Ensure sqrt(a^2) = a or -a
        let a = Fs::random(&mut rng);
        let nega = a.neg();
        let b = a.square();

        let b = b.sqrt().unwrap();

        assert!(a == b || nega == b);
    }

    for _ in 0..1000 {
        // Ensure sqrt(a)^2 = a for random a
        let a = Fs::random(&mut rng);

        let tmp = a.sqrt();
        if tmp.is_some().into() {
            assert_eq!(a, tmp.unwrap().square());
        }
    }
}

#[test]
fn test_fs_from_to_repr() {
    // r + 1 should not be in the field
    assert!(Fs::from_repr(FsRepr([
        0xb8, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68,
        0xa6, 0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4,
        0x7d, 0x0e,
    ]))
    .is_none());

    // r should not be in the field
    assert!(Fs::from_repr(Fs::char()).is_none());

    // Multiply some arbitrary representations to see if the result is as expected.
    let mut a_fs = Fs::from_repr(FsRepr([
        0x71, 0x7b, 0x33, 0xd0, 0x05, 0x0c, 0x2d, 0x5f, 0x79, 0x04, 0xa2, 0xf8, 0xb0, 0xf2, 0x1d,
        0x0a, 0x63, 0xb8, 0x1b, 0xe7, 0x85, 0x37, 0xd7, 0x0a, 0xec, 0xac, 0xc9, 0x80, 0x04, 0xa0,
        0x04, 0x05,
    ]))
    .unwrap();
    let b_fs = Fs::from_repr(FsRepr([
        0x62, 0x75, 0x47, 0x1e, 0xf5, 0x6f, 0x35, 0x66, 0x03, 0x76, 0xcf, 0x55, 0xab, 0x92, 0x0a,
        0x06, 0x92, 0xd1, 0x4d, 0x36, 0xc7, 0x73, 0x42, 0x8e, 0xc5, 0x4d, 0x34, 0x4a, 0x84, 0xf8,
        0x6d, 0x03,
    ]))
    .unwrap();
    let c_fs = Fs::from_repr(FsRepr([
        0x68, 0x28, 0x4f, 0x8f, 0x70, 0x61, 0xef, 0x7e, 0xfb, 0x46, 0x29, 0xf5, 0x6c, 0x7e, 0x7a,
        0x74, 0x17, 0x00, 0x12, 0xc9, 0xd7, 0x75, 0xdd, 0x83, 0xf7, 0x3d, 0x0f, 0x7f, 0x17, 0xf5,
        0x62, 0x07,
    ]))
    .unwrap();
    a_fs.mul_assign(&b_fs);
    assert_eq!(a_fs, c_fs);

    // Zero should be in the field.
    assert!(Fs::from_repr(FsRepr::default()).unwrap().is_zero());

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Try to turn Fs elements into representations and back again, and compare.
        let a = Fs::random(&mut rng);
        let a_repr = a.to_repr();
        let b_repr = FsRepr::from(a);
        assert_eq!(a_repr, b_repr);
        let a_again = Fs::from_repr(a_repr).unwrap();

        assert_eq!(a, a_again);
    }
}

#[test]
fn test_fs_display() {
    assert_eq!(
        format!(
            "{}",
            Fs::from_repr(FsRepr([
                0xa3, 0x01, 0x8a, 0x99, 0xb9, 0xef, 0x28, 0x55, 0x89, 0x70, 0x35, 0xcb, 0xd5, 0xad,
                0xd2, 0x5b, 0x98, 0x1f, 0x49, 0xdb, 0x6a, 0xfa, 0x61, 0xc0, 0xd9, 0x03, 0xdb, 0x43,
                0xd1, 0xb9, 0x0d, 0x07,
            ]))
            .unwrap()
        ),
        "Fs(0x070db9d143db03d9c061fa6adb491f985bd2add5cb3570895528efb9998a01a3)".to_string()
    );
    assert_eq!(
        format!(
            "{}",
            Fs::from_repr(FsRepr([
                0x9e, 0x99, 0x17, 0x27, 0x5e, 0x74, 0x74, 0xd6, 0x38, 0xf3, 0x96, 0x3e, 0x2d, 0xf5,
                0xb1, 0xbe, 0xb9, 0x82, 0x94, 0x54, 0x47, 0xe1, 0x7a, 0x9c, 0x22, 0x0d, 0x53, 0x24,
                0x60, 0x70, 0x99, 0x09,
            ]))
            .unwrap()
        ),
        "Fs(0x0999706024530d229c7ae147549482b9beb1f52d3e96f338d674745e2717999e)".to_string()
    );
}

#[test]
fn test_fs_num_bits() {
    assert_eq!(Fs::NUM_BITS, 252);
    assert_eq!(Fs::CAPACITY, 251);
}

#[test]
fn test_fs_root_of_unity() {
    assert_eq!(Fs::S, 1);
    assert_eq!(Fs::multiplicative_generator(), Fs::from(6));
    assert_eq!(
        Fs::multiplicative_generator().pow_vartime([
            0x684b872f6b7b965bu64,
            0x53341049e6640841,
            0x83339d80809a1d80,
            0x73eda753299d7d4
        ]),
        Fs::root_of_unity()
    );
    assert_eq!(Fs::root_of_unity().pow_vartime([1u64 << Fs::S]), Fs::one());
    assert!(bool::from(Fs::multiplicative_generator().sqrt().is_none()));
}
