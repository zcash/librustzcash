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
    edwards
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
    infinity: bool,
    _marker: PhantomData<Subgroup>
}

fn convert_subgroup<E: Engine, S1, S2>(from: &Point<E, S1>) -> Point<E, S2>
{
    Point {
        x: from.x,
        y: from.y,
        infinity: from.infinity,
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
        match (self.infinity, other.infinity) {
            (true, true) => true,
            (true, false) | (false, true) => false,
            (false, false) => {
                self.x == other.x && self.y == other.y
            }
        }
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
            // given an x on the curve, y^2 = x^3 + A*x^2 + x
            let x: E::Fr = rng.gen();

            let mut x2 = x;
            x2.square();

            let mut rhs = x2;
            rhs.mul_assign(&params.montgomery_a);
            rhs.add_assign(&x);
            x2.mul_assign(&x);
            rhs.add_assign(&x2);

            match rhs.sqrt() {
                Some(mut y) => {
                    if y.into_repr().is_odd() != rng.gen() {
                        y.negate();
                    }

                    return Point {
                        x: x,
                        y: y,
                        infinity: false,
                        _marker: PhantomData
                    }
                },
                None => {}
            }
        }
    }
}

impl<E: Engine, Subgroup> Point<E, Subgroup> {
    /// Convert from an Edwards point
    pub fn from_edwards(
        e: &edwards::Point<E, Subgroup>,
        params: &JubjubParams<E>
    ) -> Self
    {
        let (x, y) = e.into_xy();

        if y == E::Fr::one() {
            // The only solution for y = 1 is x = 0. (0, 1) is
            // the neutral element, so we map this to the point
            // at infinity.

            Point::zero()
        } else {
            // The map from a twisted Edwards curve is defined as
            // (x, y) -> (u, v) where
            //      u = (1 + y) / (1 - y)
            //      v = u / x
            //
            // This mapping is not defined for y = 1 and for x = 0.
            //
            // We have that y != 1 above. If x = 0, the only
            // solutions for y are 1 (contradiction) or -1.
            if x.is_zero() {
                // (0, -1) is the point of order two which is not
                // the neutral element, so we map it to (0, 0) which is
                // the only affine point of order 2.

                Point {
                    x: E::Fr::zero(),
                    y: E::Fr::zero(),
                    infinity: false,
                    _marker: PhantomData
                }
            } else {
                // The mapping is defined as above.
                //
                // (x, y) -> (u, v) where
                //      u = (1 + y) / (1 - y)
                //      v = u / x

                let mut u = E::Fr::one();
                u.add_assign(&y);
                {
                    let mut tmp = E::Fr::one();
                    tmp.sub_assign(&y);
                    u.mul_assign(&tmp.inverse().unwrap())
                }

                let mut v = u;
                v.mul_assign(&x.inverse().unwrap());

                // Scale it into the correct curve constants
                v.mul_assign(&params.scale);

                Point {
                    x: u,
                    y: v,
                    infinity: false,
                    _marker: PhantomData
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
            y: E::Fr::zero(),
            infinity: true,
            _marker: PhantomData
        }
    }

    pub fn into_xy(&self) -> Option<(E::Fr, E::Fr)>
    {
        if self.infinity {
            None
        } else {
            Some((self.x, self.y))
        }
    }

    pub fn negate(&self) -> Self {
        let mut p = self.clone();

        p.y.negate();

        p
    }

    pub fn double(&self, params: &JubjubParams<E>) -> Self {
        if self.infinity {
            return Point::zero();
        }

        if self.y == E::Fr::zero() {
            return Point::zero();
        }

        let mut delta = E::Fr::one();
        {
            let mut tmp = params.montgomery_a;
            tmp.mul_assign(&self.x);
            tmp.double();
            delta.add_assign(&tmp);
        }
        {
            let mut tmp = self.x;
            tmp.square();
            delta.add_assign(&tmp);
            tmp.double();
            delta.add_assign(&tmp);
        }
        {
            let mut tmp = self.y;
            tmp.double();
            delta.mul_assign(&tmp.inverse().expect("y is nonzero so this must be nonzero"));
        }

        let mut x3 = delta;
        x3.square();
        x3.sub_assign(&params.montgomery_a);
        x3.sub_assign(&self.x);
        x3.sub_assign(&self.x);

        let mut y3 = x3;
        y3.sub_assign(&self.x);
        y3.mul_assign(&delta);
        y3.add_assign(&self.y);
        y3.negate();

        Point {
            x: x3,
            y: y3,
            infinity: false,
            _marker: PhantomData
        }
    }

    pub fn add(&self, other: &Self, params: &JubjubParams<E>) -> Self
    {
        match (self.infinity, other.infinity) {
            (true, true) => Point::zero(),
            (true, false) => other.clone(),
            (false, true) => self.clone(),
            (false, false) => {
                if self.x == other.x {
                    if self.y == other.y {
                        self.double(params)
                    } else {
                        Point::zero()
                    }
                } else {
                    let mut delta = other.y;
                    delta.sub_assign(&self.y);
                    {
                        let mut tmp = other.x;
                        tmp.sub_assign(&self.x);
                        delta.mul_assign(&tmp.inverse().expect("self.x != other.x, so this must be nonzero"));
                    }

                    let mut x3 = delta;
                    x3.square();
                    x3.sub_assign(&params.montgomery_a);
                    x3.sub_assign(&self.x);
                    x3.sub_assign(&other.x);

                    let mut y3 = x3;
                    y3.sub_assign(&self.x);
                    y3.mul_assign(&delta);
                    y3.add_assign(&self.y);
                    y3.negate();

                    Point {
                        x: x3,
                        y: y3,
                        infinity: false,
                        _marker: PhantomData
                    }
                }
            }
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
    use super::{JubjubParams, Point, PrimeOrder, Unknown, Fs};
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{Engine, Field, PrimeField};
    use std::marker::PhantomData;

    fn is_on_curve<E: Engine>(
        x: E::Fr,
        y: E::Fr,
        params: &JubjubParams<E>
    ) -> bool
    {
        let mut lhs = y;
        lhs.square();

        let mut x2 = x;
        x2.square();

        let mut x3 = x2;
        x3.mul_assign(&x);

        let mut rhs = x2;
        rhs.mul_assign(&params.montgomery_a);
        rhs.add_assign(&x);
        rhs.add_assign(&x3);

        lhs == rhs
    }

    #[test]
    fn test_rand() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = JubjubParams::new();

        for _ in 0..100 {
            let (x, y) = Point::rand(&mut rng, &params).into_xy().unwrap();

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

            let (x, y) = res1.into_xy().unwrap();
            assert!(is_on_curve(x, y, params));

            let (x, y) = res2.into_xy().unwrap();
            assert!(is_on_curve(x, y, params));

            let (x, y) = res3.into_xy().unwrap();
            assert!(is_on_curve(x, y, params));
        }
    }

    #[test]
    fn test_edwards_conversion() {
        use super::edwards;

        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubParams::new();

        for _ in 0..100 {
            // compute base in edwards
            let base = edwards::Point::rand(rng, params);

            // sample random exponent
            let exp = Fs::rand(rng);

            // exponentiate in edwards
            let mont_expected = Point::from_edwards(&base.mul(exp, params), params);

            // convert to montgomery and exponentiate
            let mont_exp = Point::from_edwards(&base, params).mul(exp, params);

            assert!(mont_exp == mont_expected);

            let (x, y) = mont_expected.into_xy().unwrap();
            assert!(is_on_curve(x, y, params));
        }
    }

    #[test]
    fn test_back_and_forth() {
        use super::edwards;

        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubParams::new();

        for _ in 0..100 {
            // compute base in edwards
            let base = edwards::Point::rand(rng, params);

            // convert to montgomery
            let base_mont = Point::from_edwards(&base, params);

            {
                let (x, y) = base_mont.into_xy().unwrap();
                assert!(is_on_curve(x, y, params));
            }

            // convert back to edwards
            let base_ed = edwards::Point::from_montgomery(&base_mont, params);

            assert!(base == base_ed);
        }
    }

    #[test]
    fn test_awkward_points() {
        use super::edwards;

        //let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubParams::new();

        let mut awkward_points: Vec<Point<Bls12, Unknown>> = vec![];

        {
            let mut push_point = |x, y| {
                let x = Fr::from_str(x).unwrap();
                let y = Fr::from_str(y).unwrap();

                assert!(is_on_curve(x, y, params));

                awkward_points.push(Point {
                    x: x,
                    y: y,
                    infinity: false,
                    _marker: PhantomData
                });
            };

            // p is a point of order 8

            // push p
            push_point(
                "26700795483254565448379661158233243896148151268643422869645920428793919977699",
                "38240351061652197568958466618399906060451208175623222883988435386266133962140"
            );

            // push 2p
            push_point(
                "1",
                "40876724960280933289965479552128619538703197557433544801868355907127087029496"
            );

            // push 3p
            push_point(
                "48853380121562139410032601262067414539517111118072400994428343856767649516850",
                "32041076745907035847439769934443325418710075447471957144325987857573529479623"
            );

            // push 4p
            push_point(
                "0",
                "0"
            );

            // push 5p
            push_point(
                "48853380121562139410032601262067414539517111118072400994428343856767649516850",
                "20394798429219154632007970573742640418980477053055680678277670842365051704890"
            );

            // push 6p
            push_point(
                "1",
                "11559150214845257189482260956057346298987354943094093020735302792811494155017"
            );

            // push 7p
            push_point(
                "26700795483254565448379661158233243896148151268643422869645920428793919977699",
                "14195524113473992910489273889786059777239344324904414938615223313672447222373"
            );
        }

        // push 8p (point at infinity)
        awkward_points.push(Point::zero());

        for point in &awkward_points {
            let ed = edwards::Point::from_montgomery(point, params);
            let mut ed_tmp = ed.clone();
            let mut mont_tmp = point.clone();
            for _ in 0..8 {
                let mont_again = Point::from_edwards(&ed_tmp, params);
                assert!(mont_again == mont_tmp);

                let ed_again = edwards::Point::from_montgomery(&mont_tmp, params);
                assert!(ed_again == ed_tmp);

                ed_tmp = ed_tmp.add(&ed, params);
                mont_tmp = mont_tmp.add(point, params);
            }
        }
    }
}
