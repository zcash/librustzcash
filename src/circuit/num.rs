use pairing::{
    Engine,
    Field
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    LinearCombination
};

use super::{
    Assignment
};

pub struct AllocatedNum<E: Engine, Var> {
    value: Option<E::Fr>,
    variable: Var
}

impl<E: Engine, Var: Copy> AllocatedNum<E, Var> {
    pub fn alloc<CS, F>(
        mut cs: CS,
        value: F,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>,
              F: FnOnce() -> Result<E::Fr, SynthesisError>
    {
        let mut new_value = None;
        let var = cs.alloc(|| "num", || {
            let tmp = value()?;

            new_value = Some(tmp);

            Ok(tmp)
        })?;

        Ok(AllocatedNum {
            value: new_value,
            variable: var
        })
    }

    pub fn square<CS>(
        &self,
        mut cs: CS
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        let mut value = None;

        let var = cs.alloc(|| "squared num", || {
            let mut tmp = *self.value.get()?;
            tmp.square();

            value = Some(tmp);

            Ok(tmp)
        })?;

        // Constrain: a * a = aa
        cs.enforce(
            || "squaring constraint",
            LinearCombination::zero() + self.variable,
            LinearCombination::zero() + self.variable,
            LinearCombination::zero() + var
        );

        Ok(AllocatedNum {
            value: value,
            variable: var
        })
    }

    pub fn assert_nonzero<CS>(
        &self,
        mut cs: CS
    ) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        let inv = cs.alloc(|| "ephemeral inverse", || {
            let tmp = *self.value.get()?;
            
            if tmp.is_zero() {
                // TODO: add a more descriptive error to bellman
                Err(SynthesisError::AssignmentMissing)
            } else {
                Ok(tmp.inverse().unwrap())
            }
        })?;

        // Constrain a * inv = 1, which is only valid
        // iff a has a multiplicative inverse, untrue
        // for zero.
        let one = cs.one();
        cs.enforce(
            || "nonzero assertion constraint",
            LinearCombination::zero() + self.variable,
            LinearCombination::zero() + inv,
            LinearCombination::zero() + one
        );

        Ok(())
    }

    pub fn get_value(&self) -> Option<E::Fr> {
        self.value
    }

    pub fn get_variable(&self) -> Var {
        self.variable
    }
}

#[cfg(test)]
mod test {
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{Field, PrimeField};
    use ::circuit::test::*;
    use super::{AllocatedNum};

    #[test]
    fn test_allocated_num() {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        AllocatedNum::alloc(&mut cs, || Ok(Fr::one())).unwrap();

        assert!(cs.get("num") == Fr::one());
    }

    #[test]
    fn test_num_squaring() {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let n = AllocatedNum::alloc(&mut cs, || Ok(Fr::from_str("3").unwrap())).unwrap();
        let n2 = n.square(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        assert!(cs.get("squared num") == Fr::from_str("9").unwrap());
        assert!(n2.value.unwrap() == Fr::from_str("9").unwrap());
        cs.set("squared num", Fr::from_str("10").unwrap());
        assert!(!cs.is_satisfied());
    }

    #[test]
    fn test_num_nonzero() {
        {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let n = AllocatedNum::alloc(&mut cs, || Ok(Fr::from_str("3").unwrap())).unwrap();
            n.assert_nonzero(&mut cs).unwrap();

            assert!(cs.is_satisfied());
            cs.set("ephemeral inverse", Fr::from_str("3").unwrap());
            assert!(cs.which_is_unsatisfied() == Some("nonzero assertion constraint"));
        }
        {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let n = AllocatedNum::alloc(&mut cs, || Ok(Fr::zero())).unwrap();
            assert!(n.assert_nonzero(&mut cs).is_err());
        }
    }
}
