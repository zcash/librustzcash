use pairing::{
    Engine,
    Field,
// TODO
//    PrimeField
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

use ::jubjub::{
    JubjubEngine,
    JubjubParams
};

pub struct MontgomeryPoint<E: Engine, Var> {
    x: AllocatedNum<E, Var>,
    y: AllocatedNum<E, Var>
}

impl<E: JubjubEngine, Var: Copy> MontgomeryPoint<E, Var> {
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
                    // TODO: add a more descriptive error to bellman
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
    use super::{MontgomeryPoint, AllocatedNum};

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
