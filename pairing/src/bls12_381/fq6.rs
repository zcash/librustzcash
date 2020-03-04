use super::fq::{FROBENIUS_COEFF_FQ6_C1, FROBENIUS_COEFF_FQ6_C2};
use super::fq2::Fq2;
use ff::Field;
use rand_core::RngCore;

/// An element of Fq6, represented by c0 + c1 * v + c2 * v^(2).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fq6 {
    pub c0: Fq2,
    pub c1: Fq2,
    pub c2: Fq2,
}

impl ::std::fmt::Display for Fq6 {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "Fq6({} + {} * v, {} * v^2)", self.c0, self.c1, self.c2)
    }
}

impl Fq6 {
    /// Multiply by quadratic nonresidue v.
    pub fn mul_by_nonresidue(&mut self) {
        use std::mem::swap;
        swap(&mut self.c0, &mut self.c1);
        swap(&mut self.c0, &mut self.c2);

        self.c0.mul_by_nonresidue();
    }

    pub fn mul_by_1(&mut self, c1: &Fq2) {
        let mut b_b = self.c1;
        b_b.mul_assign(c1);

        let mut t1 = *c1;
        {
            let mut tmp = self.c1;
            tmp.add_assign(&self.c2);

            t1.mul_assign(&tmp);
            t1.sub_assign(&b_b);
            t1.mul_by_nonresidue();
        }

        let mut t2 = *c1;
        {
            let mut tmp = self.c0;
            tmp.add_assign(&self.c1);

            t2.mul_assign(&tmp);
            t2.sub_assign(&b_b);
        }

        self.c0 = t1;
        self.c1 = t2;
        self.c2 = b_b;
    }

    pub fn mul_by_01(&mut self, c0: &Fq2, c1: &Fq2) {
        let mut a_a = self.c0;
        let mut b_b = self.c1;
        a_a.mul_assign(c0);
        b_b.mul_assign(c1);

        let mut t1 = *c1;
        {
            let mut tmp = self.c1;
            tmp.add_assign(&self.c2);

            t1.mul_assign(&tmp);
            t1.sub_assign(&b_b);
            t1.mul_by_nonresidue();
            t1.add_assign(&a_a);
        }

        let mut t3 = *c0;
        {
            let mut tmp = self.c0;
            tmp.add_assign(&self.c2);

            t3.mul_assign(&tmp);
            t3.sub_assign(&a_a);
            t3.add_assign(&b_b);
        }

        let mut t2 = *c0;
        t2.add_assign(c1);
        {
            let mut tmp = self.c0;
            tmp.add_assign(&self.c1);

            t2.mul_assign(&tmp);
            t2.sub_assign(&a_a);
            t2.sub_assign(&b_b);
        }

        self.c0 = t1;
        self.c1 = t2;
        self.c2 = t3;
    }
}

impl Field for Fq6 {
    fn random<R: RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
        Fq6 {
            c0: Fq2::random(rng),
            c1: Fq2::random(rng),
            c2: Fq2::random(rng),
        }
    }

    fn zero() -> Self {
        Fq6 {
            c0: Fq2::zero(),
            c1: Fq2::zero(),
            c2: Fq2::zero(),
        }
    }

    fn one() -> Self {
        Fq6 {
            c0: Fq2::one(),
            c1: Fq2::zero(),
            c2: Fq2::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }

    fn double(&mut self) {
        self.c0.double();
        self.c1.double();
        self.c2.double();
    }

    fn negate(&mut self) {
        self.c0.negate();
        self.c1.negate();
        self.c2.negate();
    }

    fn add_assign(&mut self, other: &Self) {
        self.c0.add_assign(&other.c0);
        self.c1.add_assign(&other.c1);
        self.c2.add_assign(&other.c2);
    }

    fn sub_assign(&mut self, other: &Self) {
        self.c0.sub_assign(&other.c0);
        self.c1.sub_assign(&other.c1);
        self.c2.sub_assign(&other.c2);
    }

    fn frobenius_map(&mut self, power: usize) {
        self.c0.frobenius_map(power);
        self.c1.frobenius_map(power);
        self.c2.frobenius_map(power);

        self.c1.mul_assign(&FROBENIUS_COEFF_FQ6_C1[power % 6]);
        self.c2.mul_assign(&FROBENIUS_COEFF_FQ6_C2[power % 6]);
    }

    fn square(&mut self) {
        let mut s0 = self.c0;
        s0.square();
        let mut ab = self.c0;
        ab.mul_assign(&self.c1);
        let mut s1 = ab;
        s1.double();
        let mut s2 = self.c0;
        s2.sub_assign(&self.c1);
        s2.add_assign(&self.c2);
        s2.square();
        let mut bc = self.c1;
        bc.mul_assign(&self.c2);
        let mut s3 = bc;
        s3.double();
        let mut s4 = self.c2;
        s4.square();

        self.c0 = s3;
        self.c0.mul_by_nonresidue();
        self.c0.add_assign(&s0);

        self.c1 = s4;
        self.c1.mul_by_nonresidue();
        self.c1.add_assign(&s1);

        self.c2 = s1;
        self.c2.add_assign(&s2);
        self.c2.add_assign(&s3);
        self.c2.sub_assign(&s0);
        self.c2.sub_assign(&s4);
    }

    fn mul_assign(&mut self, other: &Self) {
        let mut a_a = self.c0;
        let mut b_b = self.c1;
        let mut c_c = self.c2;
        a_a.mul_assign(&other.c0);
        b_b.mul_assign(&other.c1);
        c_c.mul_assign(&other.c2);

        let mut t1 = other.c1;
        t1.add_assign(&other.c2);
        {
            let mut tmp = self.c1;
            tmp.add_assign(&self.c2);

            t1.mul_assign(&tmp);
            t1.sub_assign(&b_b);
            t1.sub_assign(&c_c);
            t1.mul_by_nonresidue();
            t1.add_assign(&a_a);
        }

        let mut t3 = other.c0;
        t3.add_assign(&other.c2);
        {
            let mut tmp = self.c0;
            tmp.add_assign(&self.c2);

            t3.mul_assign(&tmp);
            t3.sub_assign(&a_a);
            t3.add_assign(&b_b);
            t3.sub_assign(&c_c);
        }

        let mut t2 = other.c0;
        t2.add_assign(&other.c1);
        {
            let mut tmp = self.c0;
            tmp.add_assign(&self.c1);

            t2.mul_assign(&tmp);
            t2.sub_assign(&a_a);
            t2.sub_assign(&b_b);
            c_c.mul_by_nonresidue();
            t2.add_assign(&c_c);
        }

        self.c0 = t1;
        self.c1 = t2;
        self.c2 = t3;
    }

    fn inverse(&self) -> Option<Self> {
        let mut c0 = self.c2;
        c0.mul_by_nonresidue();
        c0.mul_assign(&self.c1);
        c0.negate();
        {
            let mut c0s = self.c0;
            c0s.square();
            c0.add_assign(&c0s);
        }
        let mut c1 = self.c2;
        c1.square();
        c1.mul_by_nonresidue();
        {
            let mut c01 = self.c0;
            c01.mul_assign(&self.c1);
            c1.sub_assign(&c01);
        }
        let mut c2 = self.c1;
        c2.square();
        {
            let mut c02 = self.c0;
            c02.mul_assign(&self.c2);
            c2.sub_assign(&c02);
        }

        let mut tmp1 = self.c2;
        tmp1.mul_assign(&c1);
        let mut tmp2 = self.c1;
        tmp2.mul_assign(&c2);
        tmp1.add_assign(&tmp2);
        tmp1.mul_by_nonresidue();
        tmp2 = self.c0;
        tmp2.mul_assign(&c0);
        tmp1.add_assign(&tmp2);

        match tmp1.inverse() {
            Some(t) => {
                let mut tmp = Fq6 {
                    c0: t,
                    c1: t,
                    c2: t,
                };
                tmp.c0.mul_assign(&c0);
                tmp.c1.mul_assign(&c1);
                tmp.c2.mul_assign(&c2);

                Some(tmp)
            }
            None => None,
        }
    }
}

#[cfg(test)]
use rand_core::SeedableRng;
#[cfg(test)]
use rand_xorshift::XorShiftRng;

#[test]
fn test_fq6_mul_nonresidue() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let nqr = Fq6 {
        c0: Fq2::zero(),
        c1: Fq2::one(),
        c2: Fq2::zero(),
    };

    for _ in 0..1000 {
        let mut a = Fq6::random(&mut rng);
        let mut b = a;
        a.mul_by_nonresidue();
        b.mul_assign(&nqr);

        assert_eq!(a, b);
    }
}

#[test]
fn test_fq6_mul_by_1() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let c1 = Fq2::random(&mut rng);
        let mut a = Fq6::random(&mut rng);
        let mut b = a;

        a.mul_by_1(&c1);
        b.mul_assign(&Fq6 {
            c0: Fq2::zero(),
            c1,
            c2: Fq2::zero(),
        });

        assert_eq!(a, b);
    }
}

#[test]
fn test_fq6_mul_by_01() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let c0 = Fq2::random(&mut rng);
        let c1 = Fq2::random(&mut rng);
        let mut a = Fq6::random(&mut rng);
        let mut b = a;

        a.mul_by_01(&c0, &c1);
        b.mul_assign(&Fq6 {
            c0,
            c1,
            c2: Fq2::zero(),
        });

        assert_eq!(a, b);
    }
}

#[test]
fn fq6_field_tests() {
    use ff::PrimeField;

    crate::tests::field::random_field_tests::<Fq6>();
    crate::tests::field::random_frobenius_tests::<Fq6, _>(super::fq::Fq::char(), 13);
}
