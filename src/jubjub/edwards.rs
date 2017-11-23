use pairing::{
    Engine,
    Field,
    SqrtField,
    PrimeField,
    PrimeFieldRepr,
    BitIterator
};

use super::{
    JubjubParams,
    Unknown,
    PrimeOrder,
    Fs,
    FsRepr,
    montgomery
};

use rand::{
    Rng
};

use std::marker::PhantomData;

// Represents the affine point (X/Z, Y/Z) via the extended
// twisted Edwards coordinates.
pub struct Point<E: Engine, Subgroup> {
    x: E::Fr,
    y: E::Fr,
    t: E::Fr,
    z: E::Fr,
    _marker: PhantomData<Subgroup>
}

fn convert_subgroup<E: Engine, S1, S2>(from: &Point<E, S1>) -> Point<E, S2>
{
    Point {
        x: from.x,
        y: from.y,
        t: from.t,
        z: from.z,
        _marker: PhantomData
    }
}

impl<E: Engine> From<Point<E, PrimeOrder>> for Point<E, Unknown>
{
    fn from(p: Point<E, PrimeOrder>) -> Point<E, Unknown>
    {
        convert_subgroup(&p)
    }
}

impl<E: Engine, Subgroup> Clone for Point<E, Subgroup>
{
    fn clone(&self) -> Self {
        convert_subgroup(self)
    }
}

impl<E: Engine, Subgroup> PartialEq for Point<E, Subgroup> {
    fn eq(&self, other: &Point<E, Subgroup>) -> bool {
        // p1 = (x1/z1, y1/z1)
        // p2 = (x2/z2, y2/z2)
        // Deciding that these two points are equal is a matter of
        // determining that x1/z1 = x2/z2, or equivalently that
        // x1*z2 = x2*z1, and similarly for y.

        let mut x1 = self.x;
        x1.mul_assign(&other.z);

        let mut y1 = self.y;
        y1.mul_assign(&other.z);

        let mut x2 = other.x;
        x2.mul_assign(&self.z);

        let mut y2 = other.y;
        y2.mul_assign(&self.z);

        x1 == x2 && y1 == y2
    }
}

impl<E: Engine> Point<E, Unknown> {
    /// This guarantees the point is in the prime order subgroup
    pub fn mul_by_cofactor(&self, params: &JubjubParams<E>) -> Point<E, PrimeOrder>
    {
        let tmp = self.double(params)
                      .double(params)
                      .double(params);

        convert_subgroup(&tmp)
    }

    pub fn rand<R: Rng>(rng: &mut R, params: &JubjubParams<E>) -> Self
    {
        loop {
            // given an x on the curve, y^2 = (1 + x^2) / (1 - dx^2)
            let x: E::Fr = rng.gen();
            let mut x2 = x;
            x2.square();

            let mut num = E::Fr::one();
            num.add_assign(&x2);

            x2.mul_assign(&params.edwards_d);

            let mut den = E::Fr::one();
            den.sub_assign(&x2);

            match den.inverse() {
                Some(invden) => {
                    num.mul_assign(&invden);

                    match num.sqrt() {
                        Some(mut y) => {
                            if y.into_repr().is_odd() != rng.gen() {
                                y.negate();
                            }

                            let mut t = x;
                            t.mul_assign(&y);

                            return Point {
                                x: x,
                                y: y,
                                t: t,
                                z: E::Fr::one(),
                                _marker: PhantomData
                            }
                        },
                        None => {}
                    }
                },
                None => {}
            }
        }
    }
}

impl<E: Engine, Subgroup> Point<E, Subgroup> {
    /// Convert from a Montgomery point
    pub fn from_montgomery(
        m: &montgomery::Point<E, Subgroup>,
        params: &JubjubParams<E>
    ) -> Self
    {
        match m.into_xy() {
            None => {
                // Map the point at infinity to the neutral element.
                Point::zero()
            },
            Some((x, y)) => {
                // The map from a Montgomery curve is defined as:
                // (x, y) -> (u, v) where
                //      u = x / y
                //      v = (x - 1) / (x + 1)
                //
                // This map is not defined for y = 0 and x = -1.
                //
                // y = 0 is a valid point only for x = 0:
                //     y^2 = x^3 + A.x^2 + x
                //       0 = x^3 + A.x^2 + x
                //       0 = x(x^2 + A.x + 1)
                // We have: x = 0  OR  x^2 + A.x + 1 = 0
                //       x^2 + A.x + 1 = 0
                //         (2.x + A)^2 = A^2 - 4 (Complete the square.)
                // The left hand side is a square, and so if A^2 - 4
                // is nonsquare, there is no solution. Indeed, A^2 - 4
                // is nonsquare.
                //
                // (0, 0) is a point of order 2, and so we map it to
                // (0, -1) in the twisted Edwards curve, which is the
                // only point of order 2 that is not the neutral element.
                if y.is_zero() {
                    // This must be the point (0, 0) as above.
                    let mut neg1 = E::Fr::one();
                    neg1.negate();

                    Point {
                        x: E::Fr::zero(),
                        y: neg1,
                        t: E::Fr::zero(),
                        z: E::Fr::one(),
                        _marker: PhantomData
                    }
                } else {
                    // Otherwise, as stated above, the mapping is still
                    // not defined at x = -1. However, x = -1 is not
                    // on the curve when A - 2 is nonsquare:
                    //     y^2 = x^3 + A.x^2 + x
                    //     y^2 = (-1) + A + (-1)
                    //     y^2 = A - 2
                    // Indeed, A - 2 is nonsquare.

                    let mut u = x;
                    u.mul_assign(&y.inverse().expect("y is nonzero"));

                    let mut v = x;
                    v.sub_assign(&E::Fr::one());
                    {
                        let mut tmp = x;
                        tmp.add_assign(&E::Fr::one());
                        v.mul_assign(&tmp.inverse().expect("A - 2 is nonsquare"));
                    }

                    // The resulting x-coordinate needs to be scaled.
                    u.mul_assign(&params.scale);

                    let mut t = u;
                    t.mul_assign(&v);

                    Point {
                        x: u,
                        y: v,
                        t: t,
                        z: E::Fr::one(),
                        _marker: PhantomData
                    }
                }
            }
        }
    }

    /// Attempts to cast this as a prime order element, failing if it's
    /// not in the prime order subgroup.
    pub fn as_prime_order(&self, params: &JubjubParams<E>) -> Option<Point<E, PrimeOrder>> {
        if self.mul(Fs::char(), params) == Point::zero() {
            Some(convert_subgroup(self))
        } else {
            None
        }
    }

    pub fn zero() -> Self {
        Point {
            x: E::Fr::zero(),
            y: E::Fr::one(),
            t: E::Fr::zero(),
            z: E::Fr::one(),
            _marker: PhantomData
        }
    }

    pub fn into_xy(&self) -> (E::Fr, E::Fr)
    {
        let zinv = self.z.inverse().unwrap();

        let mut x = self.x;
        x.mul_assign(&zinv);

        let mut y = self.y;
        y.mul_assign(&zinv);

        (x, y)
    }

    pub fn negate(&self) -> Self {
        let mut p = self.clone();

        p.x.negate();
        p.t.negate();

        p
    }

    pub fn double(&self, params: &JubjubParams<E>) -> Self {
        self.add(self, params)
    }

    pub fn add(&self, other: &Self, params: &JubjubParams<E>) -> Self
    {
        // A = x1 * x2
        let mut a = self.x;
        a.mul_assign(&other.x);

        // B = y1 * y2
        let mut b = self.y;
        b.mul_assign(&other.y);

        // C = d * t1 * t2
        let mut c = params.edwards_d;
        c.mul_assign(&self.t);
        c.mul_assign(&other.t);

        // D = z1 * z2
        let mut d = self.z;
        d.mul_assign(&other.z);

        // H = B - aA
        //   = B + A
        let mut h = b;
        h.add_assign(&a);

        // E = (x1 + y1) * (x2 + y2) - A - B
        //   = (x1 + y1) * (x2 + y2) - H
        let mut e = self.x;
        e.add_assign(&self.y);
        {
            let mut tmp = other.x;
            tmp.add_assign(&other.y);
            e.mul_assign(&tmp);
        }
        e.sub_assign(&h);

        // F = D - C
        let mut f = d;
        f.sub_assign(&c);

        // G = D + C
        let mut g = d;
        g.add_assign(&c);

        // x3 = E * F
        let mut x3 = e;
        x3.mul_assign(&f);

        // y3 = G * H
        let mut y3 = g;
        y3.mul_assign(&h);

        // t3 = E * H
        let mut t3 = e;
        t3.mul_assign(&h);

        // z3 = F * G
        let mut z3 = f;
        z3.mul_assign(&g);

        Point {
            x: x3,
            y: y3,
            t: t3,
            z: z3,
            _marker: PhantomData
        }
    }

    pub fn mul<S: Into<FsRepr>>(&self, scalar: S, params: &JubjubParams<E>) -> Self
    {
        let mut res = Self::zero();

        for b in BitIterator::new(scalar.into()) {
            res = res.double(params);

            if b {
                res = res.add(self, params);
            }
        }

        res
    }
}

#[cfg(test)]
mod test {
    use rand::{XorShiftRng, SeedableRng, Rand};
    use super::{JubjubParams, Point, PrimeOrder, Fs};
    use pairing::bls12_381::{Bls12};
    use pairing::{Engine, Field};

    fn is_on_curve<E: Engine>(
        x: E::Fr,
        y: E::Fr,
        params: &JubjubParams<E>
    ) -> bool
    {
        let mut x2 = x;
        x2.square();

        let mut y2 = y;
        y2.square();

        // -x^2 + y^2
        let mut lhs = y2;
        lhs.sub_assign(&x2);

        // 1 + d x^2 y^2
        let mut rhs = y2;
        rhs.mul_assign(&x2);
        rhs.mul_assign(&params.edwards_d);
        rhs.add_assign(&E::Fr::one());

        lhs == rhs
    }

    #[test]
    fn test_rand() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = JubjubParams::new();

        for _ in 0..100 {
            let (x, y) = Point::rand(&mut rng, &params).into_xy();

            assert!(is_on_curve(x, y, &params));
        }
    }

    #[test]
    fn test_identities() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = JubjubParams::new();

        let z = Point::<Bls12, PrimeOrder>::zero();
        assert!(z.double(&params) == z);
        assert!(z.negate() == z);

        for _ in 0..100 {
            let r = Point::rand(&mut rng, &params);

            assert!(r.add(&Point::zero(), &params) == r);
            assert!(r.add(&r.negate(), &params) == Point::zero());
        }
    }

    #[test]
    fn test_associativity() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = JubjubParams::new();

        for _ in 0..1000 {
            let a = Point::rand(&mut rng, &params);
            let b = Point::rand(&mut rng, &params);
            let c = Point::rand(&mut rng, &params);

            assert!(a.add(&b, &params).add(&c, &params) == c.add(&a, &params).add(&b, &params));
        }
    }

    #[test]
    fn test_order() {
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubParams::new();

        // The neutral element is in the prime order subgroup.
        assert!(Point::<Bls12, PrimeOrder>::zero().as_prime_order(params).is_some());

        for _ in 0..50 {
            // Pick a random point and multiply it by the cofactor
            let base = Point::rand(rng, params).mul_by_cofactor(params);

            // Any point multiplied by the cofactor will be in the prime
            // order subgroup
            assert!(base.as_prime_order(params).is_some());
        }

        // It's very likely that at least one out of 50 random points on the curve
        // is not in the prime order subgroup.
        let mut at_least_one_not_in_prime_order_subgroup = false;
        for _ in 0..50 {
            // Pick a random point.
            let base = Point::rand(rng, params);

            at_least_one_not_in_prime_order_subgroup |= base.as_prime_order(params).is_none();
        }
        assert!(at_least_one_not_in_prime_order_subgroup);
    }

    #[test]
    fn test_mul_associativity() {
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubParams::new();

        for _ in 0..100 {
            // Pick a random point and multiply it by the cofactor
            let base = Point::rand(rng, params).mul_by_cofactor(params);

            let mut a = Fs::rand(rng);
            let b = Fs::rand(rng);
            let c = Fs::rand(rng);

            let res1 = base.mul(a, params).mul(b, params).mul(c, params);
            let res2 = base.mul(b, params).mul(c, params).mul(a, params);
            let res3 = base.mul(c, params).mul(a, params).mul(b, params);
            a.mul_assign(&b);
            a.mul_assign(&c);
            let res4 = base.mul(a, params);

            assert!(res1 == res2);
            assert!(res2 == res3);
            assert!(res3 == res4);

            let (x, y) = res1.into_xy();
            assert!(is_on_curve(x, y, params));

            let (x, y) = res2.into_xy();
            assert!(is_on_curve(x, y, params));

            let (x, y) = res3.into_xy();
            assert!(is_on_curve(x, y, params));
        }
    }

    #[test]
    fn test_montgomery_conversion() {
        use super::montgomery;

        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubParams::new();

        for _ in 0..200 {
            // compute base in montgomery
            let base = montgomery::Point::rand(rng, params);

            // sample random exponent
            let exp = Fs::rand(rng);

            // exponentiate in montgomery, convert to edwards
            let ed_expected = Point::from_montgomery(&base.mul(exp, params), params);

            // convert to edwards and exponentiate
            let ed_exponentiated = Point::from_montgomery(&base, params).mul(exp, params);

            let (x, y) = ed_expected.into_xy();
            assert!(is_on_curve(x, y, params));

            assert!(ed_exponentiated == ed_expected);
        }
    }

    #[test]
    fn test_back_and_forth() {
        use super::montgomery;

        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubParams::new();

        for _ in 0..200 {
            // compute base in montgomery
            let base = montgomery::Point::rand(rng, params);

            // convert to edwards
            let base_ed = Point::from_montgomery(&base, params);

            {
                let (x, y) = base_ed.into_xy();
                assert!(is_on_curve(x, y, params));
            }

            // convert back to montgomery
            let base_mont = montgomery::Point::from_edwards(&base_ed, params);

            assert!(base == base_mont);
        }
    }
}
