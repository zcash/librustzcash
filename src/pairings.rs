use crate::fp12::Fp12;
use crate::fp2::Fp2;
use crate::{G1Affine, G2Affine, G2Projective, Scalar, BLS_X, BLS_X_IS_NEGATIVE};

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

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
    /// of a Miller loop into an element of `Gt` so that it can be compared
    /// with other elements of `Gt`.
    pub fn final_exponentiation(&self) -> Gt {
        let r = &self.0;

        #[must_use]
        fn exp_by_x(f: Fp12, x: u64) -> Fp12 {
            let mut tmp = Fp12::one();
            let mut found_one = false;
            for i in (0..64).rev().map(|b| ((x >> b) & 1) == 1) {
                if found_one {
                    tmp = tmp.square()
                } else {
                    found_one = i;
                }

                if i {
                    tmp *= f;
                }
            }

            if BLS_X_IS_NEGATIVE {
                tmp = tmp.conjugate();
            }

            tmp
        }

        let f1 = r.conjugate();

        Gt(r.invert()
            .map(|mut f2| {
                let mut r = f1;
                r *= f2;
                f2 = r;
                r = r.frobenius_map().frobenius_map();
                r *= f2;
                let mut x = BLS_X;
                let y0 = r.square();
                let mut y1 = y0;
                y1 = exp_by_x(y1, x);
                x >>= 1;
                let mut y2 = y1;
                y2 = exp_by_x(y2, x);
                x <<= 1;
                let mut y3 = r;
                y3 = y3.conjugate();
                y1 *= y3;
                y1 = y1.conjugate();
                y1 *= y2;
                y2 = y1;
                y2 = exp_by_x(y2, x);
                y3 = y2;
                y3 = exp_by_x(y3, x);
                y1 = y1.conjugate();
                y3 *= y1;
                y1 = y1.conjugate();
                y1 = y1.frobenius_map().frobenius_map().frobenius_map();
                y2 = y2.frobenius_map().frobenius_map();
                y1 *= y2;
                y2 = y3;
                y2 = exp_by_x(y2, x);
                y2 *= y0;
                y2 *= r;
                y1 *= y2;
                y2 = y3;
                y2 = y2.frobenius_map();
                y1 *= y2;

                y1
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
pub struct Gt(Fp12);

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

/// Invoke the pairing function without the use of precomputation and other optimizations.
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Gt {
    struct Adder {
        cur: G2Projective,
        base: G2Affine,
    }

    impl MillerLoopDriver for Adder {
        type Output = Fp12;

        fn doubling_step(&mut self, f: Self::Output, p: &G1Affine) -> Self::Output {
            let coeffs = doubling_step(&mut self.cur);
            ell(f, &coeffs, p)
        }
        fn addition_step(&mut self, f: Self::Output, p: &G1Affine) -> Self::Output {
            let coeffs = addition_step(&mut self.cur, &self.base);
            ell(f, &coeffs, p)
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
    };

    let tmp = miller_loop(&mut adder, &p);
    let tmp = MillerLoopResult(Fp12::conditional_select(
        &tmp,
        &Fp12::one(),
        either_identity,
    ));
    tmp.final_exponentiation()
}

trait MillerLoopDriver {
    type Output;

    fn doubling_step(&mut self, f: Self::Output, p: &G1Affine) -> Self::Output;
    fn addition_step(&mut self, f: Self::Output, p: &G1Affine) -> Self::Output;
    fn square_output(f: Self::Output) -> Self::Output;
    fn conjugate(f: Self::Output) -> Self::Output;
    fn one() -> Self::Output;
}

/// This is a "generic" implementation of the Miller loop to avoid duplicating code
/// structure elsewhere; instead, we'll write concrete instantiations of
/// `MillerLoopDriver` for whatever purposes we need (such as caching modes).
fn miller_loop<D: MillerLoopDriver>(driver: &mut D, p: &G1Affine) -> D::Output {
    let mut f = D::one();

    let mut found_one = false;
    for i in (0..64).rev().map(|b| (((BLS_X >> 1) >> b) & 1) == 1) {
        if !found_one {
            found_one = i;
            continue;
        }

        f = driver.doubling_step(f, p);

        if i {
            f = driver.addition_step(f, p);
        }

        f = D::square_output(f);
    }

    f = driver.doubling_step(f, p);

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
