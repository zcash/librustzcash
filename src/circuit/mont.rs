use pairing::{
    Engine,
    Field,
    PrimeField
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    LinearCombination
};

use super::{
    Assignment
};

use super::num::AllocatedNum;
use super::boolean::{
    Boolean
};
use super::blake2s::blake2s;

use ::jubjub::{
    JubjubEngine,
    JubjubParams,
    montgomery
};

pub struct MontgomeryPoint<E: Engine, Var> {
    x: AllocatedNum<E, Var>,
    y: AllocatedNum<E, Var>
}

impl<E: JubjubEngine, Var: Copy> MontgomeryPoint<E, Var> {
    pub fn group_hash<CS>(
        mut cs: CS,
        tag: &[Boolean<Var>],
        params: &E::Params
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        // This code is specialized for a field of this size
        assert_eq!(E::Fr::NUM_BITS, 255);

        assert!(tag.len() % 8 == 0);

        // Perform BLAKE2s hash
        let h = blake2s(cs.namespace(|| "blake2s"), tag)?;

        // Read the x-coordinate
        let x = AllocatedNum::from_bits_strict(
            cs.namespace(|| "read x coordinate"),
            &h[1..]
        )?;

        // Allocate the y-coordinate given the first bit
        // of the hash as its parity ("sign bit").
        let y = AllocatedNum::alloc(
            cs.namespace(|| "y-coordinate"),
            || {
                let s: bool = *h[0].get_value().get()?;
                let x: E::Fr = *x.get_value().get()?;
                let p = montgomery::Point::<E, _>::get_for_x(x, s, params);
                let p = p.get()?;
                let (_, y) = p.into_xy().expect("can't be the point at infinity");
                Ok(y)
            }
        )?;

        // Unpack the y-coordinate
        let ybits = y.into_bits_strict(cs.namespace(|| "y-coordinate unpacking"))?;

        // Enforce that the y-coordinate has the right sign
        Boolean::enforce_equal(
            cs.namespace(|| "correct sign constraint"),
            &h[0],
            &ybits[E::Fr::NUM_BITS as usize - 1]
        )?;

        // interpret the result as a point on the curve
        let mut p = Self::interpret(
            cs.namespace(|| "point interpretation"),
            &x,
            &y,
            params
        )?;

        // Perform three doublings to move the point into the prime
        // order subgroup.
        for i in 0..3 {
            // Assert the y-coordinate is nonzero (the doubling
            // doesn't work for y=0).
            p.y.assert_nonzero(
                cs.namespace(|| format!("nonzero y-coordinate {}", i))
            )?;

            p = p.double(
                cs.namespace(|| format!("doubling {}", i)),
                params
            )?;
        }

        Ok(p)
    }

    pub fn interpret<CS>(
        mut cs: CS,
        x: &AllocatedNum<E, Var>,
        y: &AllocatedNum<E, Var>,
        params: &E::Params
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        // y^2 = x^3 + A.x^2 + x

        let x2 = x.square(cs.namespace(|| "x^2"))?;
        let x3 = x2.mul(cs.namespace(|| "x^3"), x)?;

        cs.enforce(
            || "on curve check",
            LinearCombination::zero() + y.get_variable(),
            LinearCombination::zero() + y.get_variable(),
            LinearCombination::zero() + x3.get_variable()
                                      + (*params.montgomery_a(), x2.get_variable())
                                      + x.get_variable()
        );

        Ok(MontgomeryPoint {
            x: x.clone(),
            y: y.clone()
        })
    }

    /// Performs an affine point doubling, not defined for
    /// the point of order two (0, 0).
    pub fn double<CS>(
        &self,
        mut cs: CS,
        params: &E::Params
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        // Square x
        let xx = self.x.square(&mut cs)?;

        // Compute lambda = (3.xx + 2.A.x + 1) / 2.y
        let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
            let mut t0 = *xx.get_value().get()?;
            let mut t1 = t0;
            t0.double(); // t0 = 2.xx
            t0.add_assign(&t1); // t0 = 3.xx
            t1 = *self.x.get_value().get()?; // t1 = x
            t1.mul_assign(params.montgomery_2a()); // t1 = 2.A.x
            t0.add_assign(&t1);
            t0.add_assign(&E::Fr::one());
            t1 = *self.y.get_value().get()?; // t1 = y
            t1.double(); // t1 = 2.y
            match t1.inverse() {
                Some(t1) => {
                    t0.mul_assign(&t1);

                    Ok(t0)
                },
                None => {
                    Err(SynthesisError::AssignmentMissing)
                }
            }
        })?;

        // (2.y) * (lambda) = (3.xx + 2.A.x + 1)
        let one = cs.one();
        cs.enforce(
            || "evaluate lambda",
            LinearCombination::<Var, E>::zero() + self.y.get_variable()
                                                + self.y.get_variable(),

            LinearCombination::zero()           + lambda.get_variable(),

            LinearCombination::<Var, E>::zero() + xx.get_variable()
                                                + xx.get_variable()
                                                + xx.get_variable()
                                                + (*params.montgomery_2a(), self.x.get_variable())
                                                + one
        );

        // Compute x' = (lambda^2) - A - 2.x
        let xprime = AllocatedNum::alloc(cs.namespace(|| "xprime"), || {
            let mut t0 = *lambda.get_value().get()?;
            t0.square();
            t0.sub_assign(params.montgomery_a());
            t0.sub_assign(self.x.get_value().get()?);
            t0.sub_assign(self.x.get_value().get()?);

            Ok(t0)
        })?;

        // (lambda) * (lambda) = (A + 2.x + x')
        cs.enforce(
            || "evaluate xprime",
            LinearCombination::zero()           + lambda.get_variable(),
            LinearCombination::zero()           + lambda.get_variable(),
            LinearCombination::<Var, E>::zero() + (*params.montgomery_a(), one)
                                                + self.x.get_variable()
                                                + self.x.get_variable()
                                                + xprime.get_variable()
        );

        // Compute y' = -(y + lambda(x' - x))
        let yprime = AllocatedNum::alloc(cs.namespace(|| "yprime"), || {
            let mut t0 = *xprime.get_value().get()?;
            t0.sub_assign(self.x.get_value().get()?);
            t0.mul_assign(lambda.get_value().get()?);
            t0.add_assign(self.y.get_value().get()?);
            t0.negate();

            Ok(t0)
        })?;

        // y' + y = lambda(x - x')
        cs.enforce(
            || "evaluate yprime",
            LinearCombination::zero()           + self.x.get_variable()
                                                - xprime.get_variable(),

            LinearCombination::zero()           + lambda.get_variable(),

            LinearCombination::<Var, E>::zero() + yprime.get_variable()
                                                + self.y.get_variable()
        );

        Ok(MontgomeryPoint {
            x: xprime,
            y: yprime
        })
    }
}

#[cfg(test)]
mod test {
    use bellman::{ConstraintSystem};
    use rand::{XorShiftRng, SeedableRng, Rng};
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{Field};
    use ::circuit::test::*;
    use ::jubjub::{
        montgomery,
        JubjubBls12
    };
    use super::{MontgomeryPoint, AllocatedNum, Boolean};
    use super::super::boolean::AllocatedBit;
    use ::group_hash::group_hash;

    #[test]
    fn test_group_hash() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let mut num_errs = 0;
        let mut num_unsatisfied = 0;
        let mut num_satisfied = 0;

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let mut tag_bytes = vec![];
            let mut tag = vec![];
            for i in 0..10 {
                let mut byte = 0;
                for j in 0..8 {
                    byte <<= 1;
                    let b: bool = rng.gen();
                    if b {
                        byte |= 1;
                    }
                    tag.push(Boolean::from(
                        AllocatedBit::alloc(
                            cs.namespace(|| format!("bit {} {}", i, j)),
                            Some(b)
                        ).unwrap()
                    ));
                }
                tag_bytes.push(byte);
            }

            let p = MontgomeryPoint::group_hash(
                cs.namespace(|| "gh"),
                &tag,
                params
            );

            let expected = group_hash::<Bls12>(&tag_bytes, params);

            if p.is_err() {
                assert!(expected.is_none());
                num_errs += 1;
            } else {
                if !cs.is_satisfied() {
                    assert!(expected.is_none());
                    num_unsatisfied += 1;
                } else {
                    let p = p.unwrap();
                    let (x, y) = expected.unwrap();

                    assert_eq!(p.x.get_value().unwrap(), x);
                    assert_eq!(p.y.get_value().unwrap(), y);

                    num_satisfied += 1;
                }
            }
        }

        assert_eq!(
            (num_errs, num_unsatisfied, num_satisfied),
            (47, 4, 49)
        );
    }

    #[test]
    fn test_interpret() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            let p = montgomery::Point::<Bls12, _>::rand(rng, &params);
            let (mut x, mut y) = p.into_xy().unwrap();

            {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || {
                    Ok(x)
                }).unwrap();
                let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || {
                    Ok(y)
                }).unwrap();

                let p = MontgomeryPoint::interpret(&mut cs, &numx, &numy, &params).unwrap();

                assert!(cs.is_satisfied());
                assert_eq!(p.x.get_value().unwrap(), x);
                assert_eq!(p.y.get_value().unwrap(), y);

                y.negate();
                cs.set("y/num", y);
                assert!(cs.is_satisfied());
                x.negate();
                cs.set("x/num", x);
                assert!(!cs.is_satisfied());
            }

            {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || {
                    Ok(x)
                }).unwrap();
                let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || {
                    Ok(y)
                }).unwrap();

                MontgomeryPoint::interpret(&mut cs, &numx, &numy, &params).unwrap();

                assert_eq!(cs.which_is_unsatisfied().unwrap(), "on curve check");
            }
        }
    }

    #[test]
    fn test_doubling_order_2() {
        let params = &JubjubBls12::new();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            Ok(Fr::zero())
        }).unwrap();
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(Fr::zero())
        }).unwrap();

        let p = MontgomeryPoint {
            x: x,
            y: y
        };

        assert!(p.double(&mut cs, params).is_err());
    }

    #[test]
    fn test_doubling() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            let p = loop {
                let x: Fr = rng.gen();
                let s: bool = rng.gen();

                if let Some(p) = montgomery::Point::<Bls12, _>::get_for_x(x, s, params) {
                    break p;
                }
            };

            let p2 = p.double(params);

            let (x0, y0) = p.into_xy().unwrap();
            let (x1, y1) = p2.into_xy().unwrap();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
                Ok(x0)
            }).unwrap();
            let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
                Ok(y0)
            }).unwrap();

            let p = MontgomeryPoint {
                x: x,
                y: y
            };

            let p2 = p.double(cs.namespace(|| "doubling"), params).unwrap();

            assert!(cs.is_satisfied());

            assert!(p2.x.get_value().unwrap() == x1);
            assert!(p2.y.get_value().unwrap() == y1);

            cs.set("doubling/yprime/num", rng.gen());
            assert_eq!(cs.which_is_unsatisfied(), Some("doubling/evaluate yprime"));
            cs.set("doubling/yprime/num", y1);
            assert!(cs.is_satisfied());

            cs.set("doubling/xprime/num", rng.gen());
            assert_eq!(cs.which_is_unsatisfied(), Some("doubling/evaluate xprime"));
            cs.set("doubling/xprime/num", x1);
            assert!(cs.is_satisfied());

            cs.set("doubling/lambda/num", rng.gen());
            assert_eq!(cs.which_is_unsatisfied(), Some("doubling/evaluate lambda"));
        }
    }
}
