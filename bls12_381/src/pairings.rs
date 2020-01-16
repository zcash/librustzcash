use crate::fp12::Fp12;
use crate::fp2::Fp2;
use crate::fp6::Fp6;
use crate::{G1Affine, G2Affine, G2Projective, Scalar, BLS_X, BLS_X_IS_NEGATIVE};

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Represents results of a Miller loop, one of the most expensive portions
/// of the pairing function. `MillerLoopResult`s cannot be compared with each
/// other until `.final_exponentiation()` is called, which is also expensive.
#[derive(Copy, Clone, Debug)]
pub struct MillerLoopResult(pub(crate) Fp12);

impl ConditionallySelectable for MillerLoopResult {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MillerLoopResult(Fp12::conditional_select(&a.0, &b.0, choice))
    }
}

impl MillerLoopResult {
    /// This performs a "final exponentiation" routine to convert the result
    /// of a Miller loop into an element of `Gt` with help of efficient squaring
    /// operation in the so-called `cyclotomic subgroup` of `Fq6` so that
    /// it can be compared with other elements of `Gt`.
    pub fn final_exponentiation(&self) -> Gt {
        #[must_use]
        fn fp4_square(a: Fp2, b: Fp2) -> (Fp2, Fp2) {
            let t0 = a.square();
            let t1 = b.square();
            let mut t2 = t1.mul_by_nonresidue();
            let c0 = t2 + t0;
            t2 = a + b;
            t2 = t2.square();
            t2 -= t0;
            let c1 = t2 - t1;

            (c0, c1)
        }
        // Adaptation of Algorithm 5.5.4, Guide to Pairing-Based Cryptography
        // Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions
        // https://eprint.iacr.org/2009/565.pdf
        #[must_use]
        fn cyclotomic_square(f: Fp12) -> Fp12 {
            let mut z0 = f.c0.c0;
            let mut z4 = f.c0.c1;
            let mut z3 = f.c0.c2;
            let mut z2 = f.c1.c0;
            let mut z1 = f.c1.c1;
            let mut z5 = f.c1.c2;

            let (t0, t1) = fp4_square(z0, z1);

            // For A
            z0 = t0 - z0;
            z0 = z0 + z0 + t0;

            z1 = t1 + z1;
            z1 = z1 + z1 + t1;

            let (mut t0, t1) = fp4_square(z2, z3);
            let (t2, t3) = fp4_square(z4, z5);

            // For C
            z4 = t0 - z4;
            z4 = z4 + z4 + t0;

            z5 = t1 + z5;
            z5 = z5 + z5 + t1;

            // For B
            t0 = t3.mul_by_nonresidue();
            z2 = t0 + z2;
            z2 = z2 + z2 + t0;

            z3 = t2 - z3;
            z3 = z3 + z3 + t2;

            Fp12 {
                c0: Fp6 {
                    c0: z0,
                    c1: z4,
                    c2: z3,
                },
                c1: Fp6 {
                    c0: z2,
                    c1: z1,
                    c2: z5,
                },
            }
        }
        #[must_use]
        fn cycolotomic_exp(f: Fp12) -> Fp12 {
            let x = BLS_X;
            let mut tmp = Fp12::one();
            let mut found_one = false;
            for i in (0..64).rev().map(|b| ((x >> b) & 1) == 1) {
                if found_one {
                    tmp = cyclotomic_square(tmp)
                } else {
                    found_one = i;
                }

                if i {
                    tmp *= f;
                }
            }

            tmp.conjugate()
        }

        let mut f = self.0;
        let mut t0 = f
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map();
        Gt(f.invert()
            .map(|mut t1| {
                let mut t2 = t0 * t1;
                t1 = t2;
                t2 = t2.frobenius_map().frobenius_map();
                t2 *= t1;
                t1 = cyclotomic_square(t2).conjugate();
                let mut t3 = cycolotomic_exp(t2);
                let mut t4 = cyclotomic_square(t3);
                let mut t5 = t1 * t3;
                t1 = cycolotomic_exp(t5);
                t0 = cycolotomic_exp(t1);
                let mut t6 = cycolotomic_exp(t0);
                t6 *= t4;
                t4 = cycolotomic_exp(t6);
                t5 = t5.conjugate();
                t4 *= t5 * t2;
                t5 = t2.conjugate();
                t1 *= t2;
                t1 = t1.frobenius_map().frobenius_map().frobenius_map();
                t6 *= t5;
                t6 = t6.frobenius_map();
                t3 *= t0;
                t3 = t3.frobenius_map().frobenius_map();
                t3 *= t1;
                t3 *= t6;
                f = t3 * t4;

                f
            })
            // We unwrap() because `MillerLoopResult` can only be constructed
            // by a function within this crate, and we uphold the invariant
            // that the enclosed value is nonzero.
            .unwrap())
    }
}

impl<'a, 'b> Add<&'b MillerLoopResult> for &'a MillerLoopResult {
    type Output = MillerLoopResult;

    #[inline]
    fn add(self, rhs: &'b MillerLoopResult) -> MillerLoopResult {
        MillerLoopResult(self.0 * rhs.0)
    }
}

impl_add_binop_specify_output!(MillerLoopResult, MillerLoopResult, MillerLoopResult);

/// This is an element of $\mathbb{G}_T$, the target group of the pairing function. As with
/// $\mathbb{G}_1$ and $\mathbb{G}_2$ this group has order $q$.
///
/// Typically, $\mathbb{G}_T$ is written multiplicatively but we will write it additively to
/// keep code and abstractions consistent.
#[derive(Copy, Clone, Debug)]
pub struct Gt(pub(crate) Fp12);

impl ConstantTimeEq for Gt {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Gt {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gt(Fp12::conditional_select(&a.0, &b.0, choice))
    }
}

impl Eq for Gt {}
impl PartialEq for Gt {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Gt {
    /// Returns the group identity, which is $1$.
    pub fn identity() -> Gt {
        Gt(Fp12::one())
    }

    /// Doubles this group element.
    pub fn double(&self) -> Gt {
        Gt(self.0.square())
    }
}

impl<'a> Neg for &'a Gt {
    type Output = Gt;

    #[inline]
    fn neg(self) -> Gt {
        // The element is unitary, so we just conjugate.
        Gt(self.0.conjugate())
    }
}

impl Neg for Gt {
    type Output = Gt;

    #[inline]
    fn neg(self) -> Gt {
        -&self
    }
}

impl<'a, 'b> Add<&'b Gt> for &'a Gt {
    type Output = Gt;

    #[inline]
    fn add(self, rhs: &'b Gt) -> Gt {
        Gt(self.0 * rhs.0)
    }
}

impl<'a, 'b> Sub<&'b Gt> for &'a Gt {
    type Output = Gt;

    #[inline]
    fn sub(self, rhs: &'b Gt) -> Gt {
        self + (-rhs)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Gt {
    type Output = Gt;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        let mut acc = Gt::identity();

        // This is a simple double-and-add implementation of group element
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading bit because it's always unset for Fq
        // elements.
        for bit in other
            .to_bytes()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8)))
            .skip(1)
        {
            acc = acc.double();
            acc = Gt::conditional_select(&acc, &(acc + self), bit);
        }

        acc
    }
}

impl_binops_additive!(Gt, Gt);
impl_binops_multiplicative!(Gt, Scalar);

#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
/// This structure contains cached computations pertaining to a $\mathbb{G}_2$
/// element as part of the pairing function (specifically, the Miller loop) and
/// so should be computed whenever a $\mathbb{G}_2$ element is being used in
/// multiple pairings or is otherwise known in advance. This should be used in
/// conjunction with the [`multi_miller_loop`](crate::multi_miller_loop)
/// function provided by this crate.
///
/// Requires the `alloc` and `pairing` crate features to be enabled.
pub struct G2Prepared {
    infinity: Choice,
    coeffs: Vec<(Fp2, Fp2, Fp2)>,
}

#[cfg(feature = "alloc")]
impl From<G2Affine> for G2Prepared {
    fn from(q: G2Affine) -> G2Prepared {
        struct Adder {
            cur: G2Projective,
            base: G2Affine,
            coeffs: Vec<(Fp2, Fp2, Fp2)>,
        }

        impl MillerLoopDriver for Adder {
            type Output = ();

            fn doubling_step(&mut self, _: Self::Output) -> Self::Output {
                let coeffs = doubling_step(&mut self.cur);
                self.coeffs.push(coeffs);
            }
            fn addition_step(&mut self, _: Self::Output) -> Self::Output {
                let coeffs = addition_step(&mut self.cur, &self.base);
                self.coeffs.push(coeffs);
            }
            fn square_output(_: Self::Output) -> Self::Output {}
            fn conjugate(_: Self::Output) -> Self::Output {}
            fn one() -> Self::Output {}
        }

        let is_identity = q.is_identity();
        let q = G2Affine::conditional_select(&q, &G2Affine::generator(), is_identity);

        let mut adder = Adder {
            cur: G2Projective::from(q),
            base: q,
            coeffs: Vec::with_capacity(68),
        };

        miller_loop(&mut adder);

        assert_eq!(adder.coeffs.len(), 68);

        G2Prepared {
            infinity: is_identity,
            coeffs: adder.coeffs,
        }
    }
}

#[cfg(feature = "alloc")]
/// Computes $$\sum_{i=1}^n \textbf{ML}(a_i, b_i)$$ given a series of terms
/// $$(a_1, b_1), (a_2, b_2), ..., (a_n, b_n).$$
///
/// Requires the `alloc` and `pairing` crate features to be enabled.
pub fn multi_miller_loop(terms: &[(&G1Affine, &G2Prepared)]) -> MillerLoopResult {
    struct Adder<'a, 'b, 'c> {
        terms: &'c [(&'a G1Affine, &'b G2Prepared)],
        index: usize,
    }

    impl<'a, 'b, 'c> MillerLoopDriver for Adder<'a, 'b, 'c> {
        type Output = Fp12;

        fn doubling_step(&mut self, mut f: Self::Output) -> Self::Output {
            let index = self.index;
            for term in self.terms {
                let either_identity = term.0.is_identity() | term.1.infinity;

                let new_f = ell(f, &term.1.coeffs[index], term.0);
                f = Fp12::conditional_select(&new_f, &f, either_identity);
            }
            self.index += 1;

            f
        }
        fn addition_step(&mut self, mut f: Self::Output) -> Self::Output {
            let index = self.index;
            for term in self.terms {
                let either_identity = term.0.is_identity() | term.1.infinity;

                let new_f = ell(f, &term.1.coeffs[index], term.0);
                f = Fp12::conditional_select(&new_f, &f, either_identity);
            }
            self.index += 1;

            f
        }
        fn square_output(f: Self::Output) -> Self::Output {
            f.square()
        }
        fn conjugate(f: Self::Output) -> Self::Output {
            f.conjugate()
        }
        fn one() -> Self::Output {
            Fp12::one()
        }
    }

    let mut adder = Adder { terms, index: 0 };

    let tmp = miller_loop(&mut adder);

    MillerLoopResult(tmp)
}

/// Invoke the pairing function without the use of precomputation and other optimizations.
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Gt {
    struct Adder {
        cur: G2Projective,
        base: G2Affine,
        p: G1Affine,
    }

    impl MillerLoopDriver for Adder {
        type Output = Fp12;

        fn doubling_step(&mut self, f: Self::Output) -> Self::Output {
            let coeffs = doubling_step(&mut self.cur);
            ell(f, &coeffs, &self.p)
        }
        fn addition_step(&mut self, f: Self::Output) -> Self::Output {
            let coeffs = addition_step(&mut self.cur, &self.base);
            ell(f, &coeffs, &self.p)
        }
        fn square_output(f: Self::Output) -> Self::Output {
            f.square()
        }
        fn conjugate(f: Self::Output) -> Self::Output {
            f.conjugate()
        }
        fn one() -> Self::Output {
            Fp12::one()
        }
    }

    let either_identity = p.is_identity() | q.is_identity();
    let p = G1Affine::conditional_select(&p, &G1Affine::generator(), either_identity);
    let q = G2Affine::conditional_select(&q, &G2Affine::generator(), either_identity);

    let mut adder = Adder {
        cur: G2Projective::from(q),
        base: q,
        p,
    };

    let tmp = miller_loop(&mut adder);
    let tmp = MillerLoopResult(Fp12::conditional_select(
        &tmp,
        &Fp12::one(),
        either_identity,
    ));
    tmp.final_exponentiation()
}

trait MillerLoopDriver {
    type Output;

    fn doubling_step(&mut self, f: Self::Output) -> Self::Output;
    fn addition_step(&mut self, f: Self::Output) -> Self::Output;
    fn square_output(f: Self::Output) -> Self::Output;
    fn conjugate(f: Self::Output) -> Self::Output;
    fn one() -> Self::Output;
}

/// This is a "generic" implementation of the Miller loop to avoid duplicating code
/// structure elsewhere; instead, we'll write concrete instantiations of
/// `MillerLoopDriver` for whatever purposes we need (such as caching modes).
fn miller_loop<D: MillerLoopDriver>(driver: &mut D) -> D::Output {
    let mut f = D::one();

    let mut found_one = false;
    for i in (0..64).rev().map(|b| (((BLS_X >> 1) >> b) & 1) == 1) {
        if !found_one {
            found_one = i;
            continue;
        }

        f = driver.doubling_step(f);

        if i {
            f = driver.addition_step(f);
        }

        f = D::square_output(f);
    }

    f = driver.doubling_step(f);

    if BLS_X_IS_NEGATIVE {
        f = D::conjugate(f);
    }

    f
}

fn ell(f: Fp12, coeffs: &(Fp2, Fp2, Fp2), p: &G1Affine) -> Fp12 {
    let mut c0 = coeffs.0;
    let mut c1 = coeffs.1;

    c0.c0 *= p.y;
    c0.c1 *= p.y;

    c1.c0 *= p.x;
    c1.c1 *= p.x;

    f.mul_by_014(&coeffs.2, &c1, &c0)
}

fn doubling_step(r: &mut G2Projective) -> (Fp2, Fp2, Fp2) {
    // Adaptation of Algorithm 26, https://eprint.iacr.org/2010/354.pdf
    let tmp0 = r.x.square();
    let tmp1 = r.y.square();
    let tmp2 = tmp1.square();
    let tmp3 = (tmp1 + r.x).square() - tmp0 - tmp2;
    let tmp3 = tmp3 + tmp3;
    let tmp4 = tmp0 + tmp0 + tmp0;
    let tmp6 = r.x + tmp4;
    let tmp5 = tmp4.square();
    let zsquared = r.z.square();
    r.x = tmp5 - tmp3 - tmp3;
    r.z = (r.z + r.y).square() - tmp1 - zsquared;
    r.y = (tmp3 - r.x) * tmp4;
    let tmp2 = tmp2 + tmp2;
    let tmp2 = tmp2 + tmp2;
    let tmp2 = tmp2 + tmp2;
    r.y -= tmp2;
    let tmp3 = tmp4 * zsquared;
    let tmp3 = tmp3 + tmp3;
    let tmp3 = -tmp3;
    let tmp6 = tmp6.square() - tmp0 - tmp5;
    let tmp1 = tmp1 + tmp1;
    let tmp1 = tmp1 + tmp1;
    let tmp6 = tmp6 - tmp1;
    let tmp0 = r.z * zsquared;
    let tmp0 = tmp0 + tmp0;

    (tmp0, tmp3, tmp6)
}

fn addition_step(r: &mut G2Projective, q: &G2Affine) -> (Fp2, Fp2, Fp2) {
    // Adaptation of Algorithm 27, https://eprint.iacr.org/2010/354.pdf
    let zsquared = r.z.square();
    let ysquared = q.y.square();
    let t0 = zsquared * q.x;
    let t1 = ((q.y + r.z).square() - ysquared - zsquared) * zsquared;
    let t2 = t0 - r.x;
    let t3 = t2.square();
    let t4 = t3 + t3;
    let t4 = t4 + t4;
    let t5 = t4 * t2;
    let t6 = t1 - r.y - r.y;
    let t9 = t6 * q.x;
    let t7 = t4 * r.x;
    r.x = t6.square() - t5 - t7 - t7;
    r.z = (r.z + t2).square() - zsquared - t3;
    let t10 = q.y + r.z;
    let t8 = (t7 - r.x) * t6;
    let t0 = r.y * t5;
    let t0 = t0 + t0;
    r.y = t8 - t0;
    let t10 = t10.square() - ysquared;
    let ztsquared = r.z.square();
    let t10 = t10 - ztsquared;
    let t9 = t9 + t9 - t10;
    let t10 = r.z + r.z;
    let t6 = -t6;
    let t1 = t6 + t6;

    (t10, t1, t9)
}

#[test]
fn test_bilinearity() {
    use crate::Scalar;

    let a = Scalar::from_raw([1, 2, 3, 4]).invert().unwrap().square();
    let b = Scalar::from_raw([5, 6, 7, 8]).invert().unwrap().square();
    let c = a * b;

    let g = G1Affine::from(G1Affine::generator() * a);
    let h = G2Affine::from(G2Affine::generator() * b);
    let p = pairing(&g, &h);

    assert!(p != Gt::identity());

    let expected = G1Affine::from(G1Affine::generator() * c);

    assert_eq!(p, pairing(&expected, &G2Affine::generator()));
    assert_eq!(
        p,
        pairing(&G1Affine::generator(), &G2Affine::generator()) * c
    );
}

#[test]
fn test_unitary() {
    let g = G1Affine::generator();
    let h = G2Affine::generator();
    let p = -pairing(&g, &h);
    let q = pairing(&g, &-h);
    let r = pairing(&-g, &h);

    assert_eq!(p, q);
    assert_eq!(q, r);
}

#[cfg(feature = "alloc")]
#[test]
fn test_multi_miller_loop() {
    let a1 = G1Affine::generator();
    let b1 = G2Affine::generator();

    let a2 = G1Affine::from(
        G1Affine::generator() * Scalar::from_raw([1, 2, 3, 4]).invert().unwrap().square(),
    );
    let b2 = G2Affine::from(
        G2Affine::generator() * Scalar::from_raw([4, 2, 2, 4]).invert().unwrap().square(),
    );

    let a3 = G1Affine::identity();
    let b3 = G2Affine::from(
        G2Affine::generator() * Scalar::from_raw([9, 2, 2, 4]).invert().unwrap().square(),
    );

    let a4 = G1Affine::from(
        G1Affine::generator() * Scalar::from_raw([5, 5, 5, 5]).invert().unwrap().square(),
    );
    let b4 = G2Affine::identity();

    let a5 = G1Affine::from(
        G1Affine::generator() * Scalar::from_raw([323, 32, 3, 1]).invert().unwrap().square(),
    );
    let b5 = G2Affine::from(
        G2Affine::generator() * Scalar::from_raw([4, 2, 2, 9099]).invert().unwrap().square(),
    );

    let b1_prepared = G2Prepared::from(b1);
    let b2_prepared = G2Prepared::from(b2);
    let b3_prepared = G2Prepared::from(b3);
    let b4_prepared = G2Prepared::from(b4);
    let b5_prepared = G2Prepared::from(b5);

    let expected = pairing(&a1, &b1)
        + pairing(&a2, &b2)
        + pairing(&a3, &b3)
        + pairing(&a4, &b4)
        + pairing(&a5, &b5);

    let test = multi_miller_loop(&[
        (&a1, &b1_prepared),
        (&a2, &b2_prepared),
        (&a3, &b3_prepared),
        (&a4, &b4_prepared),
        (&a5, &b5_prepared),
    ])
    .final_exponentiation();

    assert_eq!(expected, test);
}
