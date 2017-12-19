use pairing::{
    Engine,
    Field,
    PrimeField,
    BitIterator
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    LinearCombination
};

use super::{
    Assignment
};

use super::boolean::{
   Boolean,
   AllocatedBit
};

pub struct AllocatedNum<E: Engine, Var> {
    value: Option<E::Fr>,
    variable: Var
}

impl<Var: Copy, E: Engine> Clone for AllocatedNum<E, Var> {
    fn clone(&self) -> Self {
        AllocatedNum {
            value: self.value,
            variable: self.variable
        }
    }
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

    pub fn into_bits_strict<CS>(
        &self,
        mut cs: CS
    ) -> Result<Vec<Boolean<Var>>, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        let bits = self.into_bits(&mut cs)?;
        Boolean::enforce_in_field::<_, _, E::Fr>(&mut cs, &bits)?;

        Ok(bits)
    }

    pub fn into_bits<CS>(
        &self,
        mut cs: CS
    ) -> Result<Vec<Boolean<Var>>, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        let bit_values = match self.value {
            Some(value) => {
                let mut field_char = BitIterator::new(E::Fr::char());

                let mut tmp = Vec::with_capacity(E::Fr::NUM_BITS as usize);

                let mut found_one = false;
                for b in BitIterator::new(value.into_repr()) {
                    // Skip leading bits
                    found_one |= field_char.next().unwrap();
                    if !found_one {
                        continue;
                    }

                    tmp.push(Some(b));
                }

                assert_eq!(tmp.len(), E::Fr::NUM_BITS as usize);

                tmp
            },
            None => {
                vec![None; E::Fr::NUM_BITS as usize]
            }
        };

        let mut bits = vec![];
        for (i, b) in bit_values.into_iter().enumerate() {
            bits.push(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                b
            )?);
        }

        let mut lc = LinearCombination::zero();
        let mut coeff = E::Fr::one();

        for bit in bits.iter().rev() {
            lc = lc + (coeff, bit.get_variable());

            coeff.double();
        }

        lc = lc - self.variable;

        cs.enforce(
            || "unpacking constraint",
            LinearCombination::zero(),
            LinearCombination::zero(),
            lc
        );

        Ok(bits.into_iter().map(|b| Boolean::from(b)).collect())
    }

    pub fn from_bits_strict<CS>(
        mut cs: CS,
        bits: &[Boolean<Var>]
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        assert_eq!(bits.len(), E::Fr::NUM_BITS as usize);

        Boolean::enforce_in_field::<_, _, E::Fr>(&mut cs, bits)?;

        let one = cs.one();
        let mut lc = LinearCombination::<Var, E>::zero();
        let mut coeff = E::Fr::one();
        let mut value = Some(E::Fr::zero());
        for bit in bits.iter().rev() {
            match bit {
                &Boolean::Constant(false) => {},
                &Boolean::Constant(true) => {
                    value.as_mut().map(|value| value.add_assign(&coeff));

                    lc = lc + (coeff, one);
                },
                &Boolean::Is(ref bit) => {
                    match bit.get_value() {
                        Some(bit) => {
                            if bit {
                                value.as_mut().map(|value| value.add_assign(&coeff));
                            }
                        },
                        None => {
                            value = None;
                        }
                    }

                    lc = lc + (coeff, bit.get_variable());
                },
                &Boolean::Not(ref bit) => {
                    match bit.get_value() {
                        Some(bit) => {
                            if !bit {
                                value.as_mut().map(|value| value.add_assign(&coeff));
                            }
                        },
                        None => {
                            value = None;
                        }
                    }

                    lc = lc + (coeff, one) - (coeff, bit.get_variable());
                }
            }

            coeff.double();
        }

        let num = Self::alloc(&mut cs, || value.get().map(|v| *v))?;

        lc = lc - num.get_variable();

        cs.enforce(
            || "packing constraint",
            LinearCombination::zero(),
            LinearCombination::zero(),
            lc
        );

        Ok(num)
    }

    pub fn mul<CS>(
        &self,
        mut cs: CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E, Variable=Var>
    {
        let mut value = None;

        let var = cs.alloc(|| "product num", || {
            let mut tmp = *self.value.get()?;
            tmp.mul_assign(other.value.get()?);

            value = Some(tmp);

            Ok(tmp)
        })?;

        // Constrain: a * b = ab
        cs.enforce(
            || "multiplication constraint",
            LinearCombination::zero() + self.variable,
            LinearCombination::zero() + other.variable,
            LinearCombination::zero() + var
        );

        Ok(AllocatedNum {
            value: value,
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
    use rand::{SeedableRng, Rand, Rng, XorShiftRng};
    use bellman::{ConstraintSystem};
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{Field, PrimeField, BitIterator};
    use ::circuit::test::*;
    use super::{AllocatedNum, Boolean};
    use super::super::boolean::AllocatedBit;

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
    fn test_num_multiplication() {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let n = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Fr::from_str("12").unwrap())).unwrap();
        let n2 = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Fr::from_str("10").unwrap())).unwrap();
        let n3 = n.mul(&mut cs, &n2).unwrap();

        assert!(cs.is_satisfied());
        assert!(cs.get("product num") == Fr::from_str("120").unwrap());
        assert!(n3.value.unwrap() == Fr::from_str("120").unwrap());
        cs.set("product num", Fr::from_str("121").unwrap());
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

    #[test]
    fn test_into_bits_strict() {
        let mut negone = Fr::one();
        negone.negate();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let n = AllocatedNum::alloc(&mut cs, || Ok(negone)).unwrap();
        n.into_bits_strict(&mut cs).unwrap();

        assert!(cs.is_satisfied());

        // make the bit representation the characteristic
        cs.set("bit 254/boolean", Fr::one());

        // this makes the unpacking constraint fail
        assert_eq!(cs.which_is_unsatisfied().unwrap(), "unpacking constraint");

        // fix it by making the number zero (congruent to the characteristic)
        cs.set("num", Fr::zero());

        // and constraint is disturbed during enforce in field check
        assert_eq!(cs.which_is_unsatisfied().unwrap(), "nand 121/AND 0/and constraint");
        cs.set("nand 121/AND 0/and result", Fr::one());

        // now the nand should fail (enforce in field is working)
        assert_eq!(cs.which_is_unsatisfied().unwrap(), "nand 121/enforce nand");
    }

    #[test]
    fn test_into_bits() {
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            let r = Fr::rand(&mut rng);
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let n = AllocatedNum::alloc(&mut cs, || Ok(r)).unwrap();

            let bits = n.into_bits(&mut cs).unwrap();

            assert!(cs.is_satisfied());

            for (b, a) in BitIterator::new(r.into_repr()).skip(1).zip(bits.iter()) {
                if let &Boolean::Is(ref a) = a {
                    assert_eq!(b, a.get_value().unwrap());
                } else {
                    unreachable!()
                }
            }

            cs.set("num", Fr::rand(&mut rng));
            assert!(!cs.is_satisfied());
            cs.set("num", r);
            assert!(cs.is_satisfied());

            for i in 0..Fr::NUM_BITS {
                let name = format!("bit {}/boolean", i);
                let cur = cs.get(&name);
                let mut tmp = Fr::one();
                tmp.sub_assign(&cur);
                cs.set(&name, tmp);
                assert!(!cs.is_satisfied());
                cs.set(&name, cur);
                assert!(cs.is_satisfied());
            }
        }
    }

    #[test]
    fn test_from_bits_strict() {
        {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let mut bits = vec![];
            for (i, b) in BitIterator::new(Fr::char()).skip(1).enumerate() {
                bits.push(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    Some(b)
                ).unwrap()));
            }

            let num = AllocatedNum::from_bits_strict(&mut cs, &bits).unwrap();
            assert!(num.value.unwrap().is_zero());
            assert!(!cs.is_satisfied());
        }

        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..1000 {
            let r = Fr::rand(&mut rng);
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let mut bits = vec![];
            for (i, b) in BitIterator::new(r.into_repr()).skip(1).enumerate() {
                let parity: bool = rng.gen();

                if parity {
                    bits.push(Boolean::from(AllocatedBit::alloc(
                        cs.namespace(|| format!("bit {}", i)),
                        Some(b)
                    ).unwrap()));
                } else {
                    bits.push(Boolean::from(AllocatedBit::alloc(
                        cs.namespace(|| format!("bit {}", i)),
                        Some(!b)
                    ).unwrap()).not());
                }
            }

            let num = AllocatedNum::from_bits_strict(&mut cs, &bits).unwrap();
            assert!(cs.is_satisfied());
            assert_eq!(num.value.unwrap(), r);
            assert_eq!(cs.get("num"), r);

            cs.set("num", Fr::rand(&mut rng));
            assert_eq!(cs.which_is_unsatisfied().unwrap(), "packing constraint");
        }
    }
}
