use pairing::{
    Engine,
    Field,
    PrimeField,
    PrimeFieldRepr,
    BitIterator
};

use bellman::{
    ConstraintSystem,
    SynthesisError,
    LinearCombination
};

use super::{
    Assignment
};

/// Represents a variable in the constraint system which is guaranteed
/// to be either zero or one.
#[derive(Clone)]
pub struct AllocatedBit<Var> {
    variable: Var,
    value: Option<bool>
}

impl<Var: Copy> AllocatedBit<Var> {
    pub fn get_value(&self) -> Option<bool> {
        self.value
    }

    pub fn get_variable(&self) -> Var {
        self.variable
    }

    /// Allocate a variable in the constraint system which can only be a
    /// boolean value.
    pub fn alloc<E, CS>(
        mut cs: CS,
        value: Option<bool>,
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let var = cs.alloc(|| "boolean", || {
            if *value.get()? {
                Ok(E::Fr::one())
            } else {
                Ok(E::Fr::zero())
            }
        })?;

        // Constrain: (1 - a) * a = 0
        // This constrains a to be either 0 or 1.
        let one = cs.one();
        cs.enforce(
            || "boolean constraint",
            LinearCombination::zero() + one - var,
            LinearCombination::zero() + var,
            LinearCombination::zero()
        );

        Ok(AllocatedBit {
            variable: var,
            value: value
        })
    }

    /// Performs an XOR operation over the two operands, returning
    /// an `AllocatedBit`.
    pub fn xor<E, CS>(
        mut cs: CS,
        a: &Self,
        b: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let mut result_value = None;

        let result_var = cs.alloc(|| "xor result", || {
            if *a.value.get()? ^ *b.value.get()? {
                result_value = Some(true);

                Ok(E::Fr::one())
            } else {
                result_value = Some(false);

                Ok(E::Fr::zero())
            }
        })?;

        // Constrain (a + a) * (b) = (a + b - c)
        // Given that a and b are boolean constrained, if they
        // are equal, the only solution for c is 0, and if they
        // are different, the only solution for c is 1.
        //
        // ¬(a ∧ b) ∧ ¬(¬a ∧ ¬b) = c
        // (1 - (a * b)) * (1 - ((1 - a) * (1 - b))) = c
        // (1 - ab) * (1 - (1 - a - b + ab)) = c
        // (1 - ab) * (a + b - ab) = c
        // a + b - ab - (a^2)b - (b^2)a + (a^2)(b^2) = c
        // a + b - ab - ab - ab + ab = c
        // a + b - 2ab = c
        // -2a * b = c - a - b
        // 2a * b = a + b - c
        // (a + a) * b = a + b - c
        cs.enforce(
            || "xor constraint",
            LinearCombination::zero() + a.variable + a.variable,
            LinearCombination::zero() + b.variable,
            LinearCombination::zero() + a.variable + b.variable - result_var
        );

        Ok(AllocatedBit {
            variable: result_var,
            value: result_value
        })
    }

    /// Performs an AND operation over the two operands, returning
    /// an `AllocatedBit`.
    pub fn and<E, CS>(
        mut cs: CS,
        a: &Self,
        b: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let mut result_value = None;

        let result_var = cs.alloc(|| "and result", || {
            if *a.value.get()? & *b.value.get()? {
                result_value = Some(true);

                Ok(E::Fr::one())
            } else {
                result_value = Some(false);

                Ok(E::Fr::zero())
            }
        })?;

        // Constrain (a) * (b) = (c), ensuring c is 1 iff
        // a AND b are both 1.
        cs.enforce(
            || "and constraint",
            LinearCombination::zero() + a.variable,
            LinearCombination::zero() + b.variable,
            LinearCombination::zero() + result_var
        );

        Ok(AllocatedBit {
            variable: result_var,
            value: result_value
        })
    }

    /// Calculates `a AND (NOT b)`.
    pub fn and_not<E, CS>(
        mut cs: CS,
        a: &Self,
        b: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let mut result_value = None;

        let result_var = cs.alloc(|| "and not result", || {
            if *a.value.get()? & !*b.value.get()? {
                result_value = Some(true);

                Ok(E::Fr::one())
            } else {
                result_value = Some(false);

                Ok(E::Fr::zero())
            }
        })?;

        // Constrain (a) * (1 - b) = (c), ensuring c is 1 iff
        // a is true and b is false, and otherwise c is 0.
        let one = cs.one();
        cs.enforce(
            || "and not constraint",
            LinearCombination::zero() + a.variable,
            LinearCombination::zero() + one - b.variable,
            LinearCombination::zero() + result_var
        );

        Ok(AllocatedBit {
            variable: result_var,
            value: result_value
        })
    }

    /// Calculates `(NOT a) AND (NOT b)`.
    pub fn nor<E, CS>(
        mut cs: CS,
        a: &Self,
        b: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let mut result_value = None;

        let result_var = cs.alloc(|| "nor result", || {
            if !*a.value.get()? & !*b.value.get()? {
                result_value = Some(true);

                Ok(E::Fr::one())
            } else {
                result_value = Some(false);

                Ok(E::Fr::zero())
            }
        })?;

        // Constrain (1 - a) * (1 - b) = (c), ensuring c is 1 iff
        // a and b are both false, and otherwise c is 0.
        let one = cs.one();
        cs.enforce(
            || "nor constraint",
            LinearCombination::zero() + one - a.variable,
            LinearCombination::zero() + one - b.variable,
            LinearCombination::zero() + result_var
        );

        Ok(AllocatedBit {
            variable: result_var,
            value: result_value
        })
    }
}

/// This is a boolean value which may be either a constant or
/// an interpretation of an `AllocatedBit`.
#[derive(Clone)]
pub enum Boolean<Var> {
    /// Existential view of the boolean variable
    Is(AllocatedBit<Var>),
    /// Negated view of the boolean variable
    Not(AllocatedBit<Var>),
    /// Constant (not an allocated variable)
    Constant(bool)
}

impl<Var: Copy> Boolean<Var> {
    pub fn enforce_equal<E, CS>(
        mut cs: CS,
        a: &Self,
        b: &Self
    ) -> Result<(), SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        // TODO: this is just a cheap hack
        let c = Self::xor(&mut cs, a, b)?;

        Self::enforce_nand(&mut cs, &[c])
    }

    pub fn get_value(&self) -> Option<bool> {
        match self {
            &Boolean::Constant(c) => Some(c),
            &Boolean::Is(ref v) => v.get_value(),
            &Boolean::Not(ref v) => v.get_value().map(|b| !b)
        }
    }

    /// Construct a boolean from a known constant
    pub fn constant(b: bool) -> Self {
        Boolean::Constant(b)
    }

    /// Return a negated interpretation of this boolean.
    pub fn not(&self) -> Self {
        match self {
            &Boolean::Constant(c) => Boolean::Constant(!c),
            &Boolean::Is(ref v) => Boolean::Not(v.clone()),
            &Boolean::Not(ref v) => Boolean::Is(v.clone())
        }
    }

    /// Perform XOR over two boolean operands
    pub fn xor<'a, E, CS>(
        cs: CS,
        a: &'a Self,
        b: &'a Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        match (a, b) {
            (&Boolean::Constant(false), x) | (x, &Boolean::Constant(false)) => Ok(x.clone()),
            (&Boolean::Constant(true), x) | (x, &Boolean::Constant(true)) => Ok(x.not()),
            // a XOR (NOT b) = NOT(a XOR b)
            (is @ &Boolean::Is(_), not @ &Boolean::Not(_)) | (not @ &Boolean::Not(_), is @ &Boolean::Is(_)) => {
                Ok(Boolean::xor(
                    cs,
                    is,
                    &not.not()
                )?.not())
            },
            // a XOR b = (NOT a) XOR (NOT b)
            (&Boolean::Is(ref a), &Boolean::Is(ref b)) | (&Boolean::Not(ref a), &Boolean::Not(ref b)) => {
                Ok(Boolean::Is(AllocatedBit::xor(cs, a, b)?))
            }
        }
    }

    /// Perform AND over two boolean operands
    pub fn and<'a, E, CS>(
        cs: CS,
        a: &'a Self,
        b: &'a Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        match (a, b) {
            // false AND x is always false
            (&Boolean::Constant(false), _) | (_, &Boolean::Constant(false)) => Ok(Boolean::Constant(false)),
            // true AND x is always x
            (&Boolean::Constant(true), x) | (x, &Boolean::Constant(true)) => Ok(x.clone()),
            // a AND (NOT b)
            (&Boolean::Is(ref is), &Boolean::Not(ref not)) | (&Boolean::Not(ref not), &Boolean::Is(ref is)) => {
                Ok(Boolean::Is(AllocatedBit::and_not(cs, is, not)?))
            },
            // (NOT a) AND (NOT b) = a NOR b
            (&Boolean::Not(ref a), &Boolean::Not(ref b)) => {
                Ok(Boolean::Is(AllocatedBit::nor(cs, a, b)?))
            },
            // a AND b
            (&Boolean::Is(ref a), &Boolean::Is(ref b)) => {
                Ok(Boolean::Is(AllocatedBit::and(cs, a, b)?))
            }
        }
    }

    pub fn kary_and<E, CS>(
        mut cs: CS,
        bits: &[Self]
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        assert!(bits.len() > 0);
        let mut bits = bits.iter();

        // TODO: optimize
        let mut cur: Self = bits.next().unwrap().clone();

        let mut i = 0;
        while let Some(next) = bits.next() {
            cur = Boolean::and(cs.namespace(|| format!("AND {}", i)), &cur, next)?;

            i += 1;
        }

        Ok(cur)
    }

    /// Asserts that at least one operand is false.
    pub fn enforce_nand<E, CS>(
        mut cs: CS,
        bits: &[Self]
    ) -> Result<(), SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let res = Self::kary_and(&mut cs, bits)?;

        // TODO: optimize
        match res {
            Boolean::Constant(false) => {
                Ok(())
            },
            Boolean::Constant(true) => {
                // TODO: more descriptive error
                Err(SynthesisError::AssignmentMissing)
            },
            Boolean::Is(ref res) => {
                cs.enforce(
                    || "enforce nand",
                    LinearCombination::zero(),
                    LinearCombination::zero(),
                    LinearCombination::zero() + res.get_variable()
                );

                Ok(())
            },
            Boolean::Not(ref res) => {
                let one = cs.one();
                cs.enforce(
                    || "enforce nand",
                    LinearCombination::zero(),
                    LinearCombination::zero(),
                    LinearCombination::zero() + one - res.get_variable()
                );

                Ok(())
            },
        }
    }

    /// Asserts that this bit representation is "in
    /// the field" when interpreted in big endian.
    pub fn enforce_in_field<E, CS, F: PrimeField>(
        mut cs: CS,
        bits: &[Self]
    ) -> Result<(), SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        assert_eq!(bits.len(), F::NUM_BITS as usize);

        let mut a = bits.iter();

        // b = char() - 1
        let mut b = F::char();
        b.sub_noborrow(&1.into());

        // Runs of ones in r
        let mut last_run = Boolean::<Var>::constant(true);
        let mut current_run = vec![];

        let mut found_one = false;
        let mut run_i = 0;
        let mut nand_i = 0;
        for b in BitIterator::new(b) {
            // Skip over unset bits at the beginning
            found_one |= b;
            if !found_one {
                continue;
            }

            let a = a.next().unwrap();

            if b {
                // This is part of a run of ones.
                current_run.push(a.clone());
            } else {
                if current_run.len() > 0 {
                    // This is the start of a run of zeros, but we need
                    // to k-ary AND against `last_run` first.

                    current_run.push(last_run.clone());
                    last_run = Self::kary_and(
                        cs.namespace(|| format!("run {}", run_i)),
                        &current_run
                    )?;
                    run_i += 1;
                    current_run.truncate(0);
                }

                // TODO: this could be optimized with a k-ary operation
                // (all zeros are required in the run if last_run is zero)

                // If `last_run` is true, `a` must be false, or it would
                // not be in the field.
                //
                // If `last_run` is false, `a` can be true or false.
                //
                // Ergo, at least one of `last_run` and `a` must be false.
                Self::enforce_nand(
                    cs.namespace(|| format!("nand {}", nand_i)),
                    &[last_run.clone(), a.clone()]
                )?;
                nand_i += 1;
            }
        }

        // We should always end in a "run" of zeros, because
        // the characteristic is an odd prime. So, this should
        // be empty.
        assert_eq!(current_run.len(), 0);

        Ok(())
    }
}

impl<Var> From<AllocatedBit<Var>> for Boolean<Var> {
    fn from(b: AllocatedBit<Var>) -> Boolean<Var> {
        Boolean::Is(b)
    }
}

#[cfg(test)]
mod test {
    use rand::{SeedableRng, Rand, XorShiftRng};
    use bellman::{ConstraintSystem};
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{Field, PrimeField, PrimeFieldRepr, BitIterator};
    use ::circuit::test::*;
    use super::{AllocatedBit, Boolean};

    #[test]
    fn test_allocated_bit() {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        AllocatedBit::alloc(&mut cs, Some(true)).unwrap();
        assert!(cs.get("boolean") == Fr::one());
        assert!(cs.is_satisfied());
        cs.set("boolean", Fr::zero());
        assert!(cs.is_satisfied());
        cs.set("boolean", Fr::from_str("2").unwrap());
        assert!(!cs.is_satisfied());
        assert!(cs.which_is_unsatisfied() == Some("boolean constraint"));
    }

    #[test]
    fn test_xor() {
        for a_val in [false, true].iter() {
            for b_val in [false, true].iter() {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let a = AllocatedBit::alloc(cs.namespace(|| "a"), Some(*a_val)).unwrap();
                let b = AllocatedBit::alloc(cs.namespace(|| "b"), Some(*b_val)).unwrap();
                let c = AllocatedBit::xor(&mut cs, &a, &b).unwrap();
                assert_eq!(c.value.unwrap(), *a_val ^ *b_val);

                assert!(cs.is_satisfied());
                assert!(cs.get("a/boolean") == if *a_val { Field::one() } else { Field::zero() });
                assert!(cs.get("b/boolean") == if *b_val { Field::one() } else { Field::zero() });
                assert!(cs.get("xor result") == if *a_val ^ *b_val { Field::one() } else { Field::zero() });

                // Invert the result and check if the constraint system is still satisfied
                cs.set("xor result", if *a_val ^ *b_val { Field::zero() } else { Field::one() });
                assert!(!cs.is_satisfied());
            }
        }
    }

    #[test]
    fn test_and() {
        for a_val in [false, true].iter() {
            for b_val in [false, true].iter() {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let a = AllocatedBit::alloc(cs.namespace(|| "a"), Some(*a_val)).unwrap();
                let b = AllocatedBit::alloc(cs.namespace(|| "b"), Some(*b_val)).unwrap();
                let c = AllocatedBit::and(&mut cs, &a, &b).unwrap();
                assert_eq!(c.value.unwrap(), *a_val & *b_val);

                assert!(cs.is_satisfied());
                assert!(cs.get("a/boolean") == if *a_val { Field::one() } else { Field::zero() });
                assert!(cs.get("b/boolean") == if *b_val { Field::one() } else { Field::zero() });
                assert!(cs.get("and result") == if *a_val & *b_val { Field::one() } else { Field::zero() });

                // Invert the result and check if the constraint system is still satisfied
                cs.set("and result", if *a_val & *b_val { Field::zero() } else { Field::one() });
                assert!(!cs.is_satisfied());
            }
        }
    }

    #[test]
    fn test_and_not() {
        for a_val in [false, true].iter() {
            for b_val in [false, true].iter() {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let a = AllocatedBit::alloc(cs.namespace(|| "a"), Some(*a_val)).unwrap();
                let b = AllocatedBit::alloc(cs.namespace(|| "b"), Some(*b_val)).unwrap();
                let c = AllocatedBit::and_not(&mut cs, &a, &b).unwrap();
                assert_eq!(c.value.unwrap(), *a_val & !*b_val);

                assert!(cs.is_satisfied());
                assert!(cs.get("a/boolean") == if *a_val { Field::one() } else { Field::zero() });
                assert!(cs.get("b/boolean") == if *b_val { Field::one() } else { Field::zero() });
                assert!(cs.get("and not result") == if *a_val & !*b_val { Field::one() } else { Field::zero() });

                // Invert the result and check if the constraint system is still satisfied
                cs.set("and not result", if *a_val & !*b_val { Field::zero() } else { Field::one() });
                assert!(!cs.is_satisfied());
            }
        }
    }

    #[test]
    fn test_nor() {
        for a_val in [false, true].iter() {
            for b_val in [false, true].iter() {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let a = AllocatedBit::alloc(cs.namespace(|| "a"), Some(*a_val)).unwrap();
                let b = AllocatedBit::alloc(cs.namespace(|| "b"), Some(*b_val)).unwrap();
                let c = AllocatedBit::nor(&mut cs, &a, &b).unwrap();
                assert_eq!(c.value.unwrap(), !*a_val & !*b_val);

                assert!(cs.is_satisfied());
                assert!(cs.get("a/boolean") == if *a_val { Field::one() } else { Field::zero() });
                assert!(cs.get("b/boolean") == if *b_val { Field::one() } else { Field::zero() });
                assert!(cs.get("nor result") == if !*a_val & !*b_val { Field::one() } else { Field::zero() });

                // Invert the result and check if the constraint system is still satisfied
                cs.set("nor result", if !*a_val & !*b_val { Field::zero() } else { Field::one() });
                assert!(!cs.is_satisfied());
            }
        }
    }

    #[test]
    fn test_enforce_equal() {
        for a_bool in [false, true].iter().cloned() {
            for b_bool in [false, true].iter().cloned() {
                for a_neg in [false, true].iter().cloned() {
                    for b_neg in [false, true].iter().cloned() {
                        let mut cs = TestConstraintSystem::<Bls12>::new();

                        let mut a = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "a"), Some(a_bool)).unwrap());
                        let mut b = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "b"), Some(b_bool)).unwrap());

                        if a_neg {
                            a = a.not();
                        }
                        if b_neg {
                            b = b.not();
                        }

                        Boolean::enforce_equal(&mut cs, &a, &b).unwrap();

                        assert_eq!(
                            cs.is_satisfied(),
                            (a_bool ^ a_neg) == (b_bool ^ b_neg)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_boolean_negation() {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let mut b = Boolean::from(AllocatedBit::alloc(&mut cs, Some(true)).unwrap());

        match b {
            Boolean::Is(_) => {},
            _ => panic!("unexpected value")
        }

        b = b.not();

        match b {
            Boolean::Not(_) => {},
            _ => panic!("unexpected value")
        }

        b = b.not();

        match b {
            Boolean::Is(_) => {},
            _ => panic!("unexpected value")
        }

        b = Boolean::constant(true);

        match b {
            Boolean::Constant(true) => {},
            _ => panic!("unexpected value")
        }

        b = b.not();

        match b {
            Boolean::Constant(false) => {},
            _ => panic!("unexpected value")
        }

        b = b.not();

        match b {
            Boolean::Constant(true) => {},
            _ => panic!("unexpected value")
        }
    }

    #[derive(Copy, Clone, Debug)]
    enum OperandType {
        True,
        False,
        AllocatedTrue,
        AllocatedFalse,
        NegatedAllocatedTrue,
        NegatedAllocatedFalse
    }

    #[test]
    fn test_boolean_xor() {
        let variants = [
            OperandType::True,
            OperandType::False,
            OperandType::AllocatedTrue,
            OperandType::AllocatedFalse,
            OperandType::NegatedAllocatedTrue,
            OperandType::NegatedAllocatedFalse
        ];

        for first_operand in variants.iter().cloned() {
            for second_operand in variants.iter().cloned() {
                let mut cs = TestConstraintSystem::<Bls12>::new();

                let a;
                let b;

                {
                    let mut dyn_construct = |operand, name| {
                        let cs = cs.namespace(|| name);

                        match operand {
                            OperandType::True => Boolean::constant(true),
                            OperandType::False => Boolean::constant(false),
                            OperandType::AllocatedTrue => Boolean::from(AllocatedBit::alloc(cs, Some(true)).unwrap()),
                            OperandType::AllocatedFalse => Boolean::from(AllocatedBit::alloc(cs, Some(false)).unwrap()),
                            OperandType::NegatedAllocatedTrue => Boolean::from(AllocatedBit::alloc(cs, Some(true)).unwrap()).not(),
                            OperandType::NegatedAllocatedFalse => Boolean::from(AllocatedBit::alloc(cs, Some(false)).unwrap()).not(),
                        }
                    };

                    a = dyn_construct(first_operand, "a");
                    b = dyn_construct(second_operand, "b");
                }

                let c = Boolean::xor(&mut cs, &a, &b).unwrap();

                assert!(cs.is_satisfied());

                match (first_operand, second_operand, c) {
                    (OperandType::True, OperandType::True, Boolean::Constant(false)) => {},
                    (OperandType::True, OperandType::False, Boolean::Constant(true)) => {},
                    (OperandType::True, OperandType::AllocatedTrue, Boolean::Not(_)) => {},
                    (OperandType::True, OperandType::AllocatedFalse, Boolean::Not(_)) => {},
                    (OperandType::True, OperandType::NegatedAllocatedTrue, Boolean::Is(_)) => {},
                    (OperandType::True, OperandType::NegatedAllocatedFalse, Boolean::Is(_)) => {},

                    (OperandType::False, OperandType::True, Boolean::Constant(true)) => {},
                    (OperandType::False, OperandType::False, Boolean::Constant(false)) => {},
                    (OperandType::False, OperandType::AllocatedTrue, Boolean::Is(_)) => {},
                    (OperandType::False, OperandType::AllocatedFalse, Boolean::Is(_)) => {},
                    (OperandType::False, OperandType::NegatedAllocatedTrue, Boolean::Not(_)) => {},
                    (OperandType::False, OperandType::NegatedAllocatedFalse, Boolean::Not(_)) => {},

                    (OperandType::AllocatedTrue, OperandType::True, Boolean::Not(_)) => {},
                    (OperandType::AllocatedTrue, OperandType::False, Boolean::Is(_)) => {},
                    (OperandType::AllocatedTrue, OperandType::AllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedTrue, OperandType::AllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::AllocatedTrue, OperandType::NegatedAllocatedTrue, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedTrue, OperandType::NegatedAllocatedFalse, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },

                    (OperandType::AllocatedFalse, OperandType::True, Boolean::Not(_)) => {},
                    (OperandType::AllocatedFalse, OperandType::False, Boolean::Is(_)) => {},
                    (OperandType::AllocatedFalse, OperandType::AllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::AllocatedFalse, OperandType::AllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedFalse, OperandType::NegatedAllocatedTrue, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::AllocatedFalse, OperandType::NegatedAllocatedFalse, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },

                    (OperandType::NegatedAllocatedTrue, OperandType::True, Boolean::Is(_)) => {},
                    (OperandType::NegatedAllocatedTrue, OperandType::False, Boolean::Not(_)) => {},
                    (OperandType::NegatedAllocatedTrue, OperandType::AllocatedTrue, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedTrue, OperandType::AllocatedFalse, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::NegatedAllocatedTrue, OperandType::NegatedAllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedTrue, OperandType::NegatedAllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },

                    (OperandType::NegatedAllocatedFalse, OperandType::True, Boolean::Is(_)) => {},
                    (OperandType::NegatedAllocatedFalse, OperandType::False, Boolean::Not(_)) => {},
                    (OperandType::NegatedAllocatedFalse, OperandType::AllocatedTrue, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::NegatedAllocatedFalse, OperandType::AllocatedFalse, Boolean::Not(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedFalse, OperandType::NegatedAllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::NegatedAllocatedFalse, OperandType::NegatedAllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("xor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },

                    _ => panic!("this should never be encountered")
                }
            }
        }
    }

    #[test]
    fn test_boolean_and() {
        let variants = [
            OperandType::True,
            OperandType::False,
            OperandType::AllocatedTrue,
            OperandType::AllocatedFalse,
            OperandType::NegatedAllocatedTrue,
            OperandType::NegatedAllocatedFalse
        ];

        for first_operand in variants.iter().cloned() {
            for second_operand in variants.iter().cloned() {
                let mut cs = TestConstraintSystem::<Bls12>::new();

                let a;
                let b;

                {
                    let mut dyn_construct = |operand, name| {
                        let cs = cs.namespace(|| name);

                        match operand {
                            OperandType::True => Boolean::constant(true),
                            OperandType::False => Boolean::constant(false),
                            OperandType::AllocatedTrue => Boolean::from(AllocatedBit::alloc(cs, Some(true)).unwrap()),
                            OperandType::AllocatedFalse => Boolean::from(AllocatedBit::alloc(cs, Some(false)).unwrap()),
                            OperandType::NegatedAllocatedTrue => Boolean::from(AllocatedBit::alloc(cs, Some(true)).unwrap()).not(),
                            OperandType::NegatedAllocatedFalse => Boolean::from(AllocatedBit::alloc(cs, Some(false)).unwrap()).not(),
                        }
                    };

                    a = dyn_construct(first_operand, "a");
                    b = dyn_construct(second_operand, "b");
                }

                let c = Boolean::and(&mut cs, &a, &b).unwrap();

                assert!(cs.is_satisfied());

                match (first_operand, second_operand, c) {
                    (OperandType::True, OperandType::True, Boolean::Constant(true)) => {},
                    (OperandType::True, OperandType::False, Boolean::Constant(false)) => {},
                    (OperandType::True, OperandType::AllocatedTrue, Boolean::Is(_)) => {},
                    (OperandType::True, OperandType::AllocatedFalse, Boolean::Is(_)) => {},
                    (OperandType::True, OperandType::NegatedAllocatedTrue, Boolean::Not(_)) => {},
                    (OperandType::True, OperandType::NegatedAllocatedFalse, Boolean::Not(_)) => {},

                    (OperandType::False, OperandType::True, Boolean::Constant(false)) => {},
                    (OperandType::False, OperandType::False, Boolean::Constant(false)) => {},
                    (OperandType::False, OperandType::AllocatedTrue, Boolean::Constant(false)) => {},
                    (OperandType::False, OperandType::AllocatedFalse, Boolean::Constant(false)) => {},
                    (OperandType::False, OperandType::NegatedAllocatedTrue, Boolean::Constant(false)) => {},
                    (OperandType::False, OperandType::NegatedAllocatedFalse, Boolean::Constant(false)) => {},

                    (OperandType::AllocatedTrue, OperandType::True, Boolean::Is(_)) => {},
                    (OperandType::AllocatedTrue, OperandType::False, Boolean::Constant(false)) => {},
                    (OperandType::AllocatedTrue, OperandType::AllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("and result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::AllocatedTrue, OperandType::AllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("and result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedTrue, OperandType::NegatedAllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedTrue, OperandType::NegatedAllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },

                    (OperandType::AllocatedFalse, OperandType::True, Boolean::Is(_)) => {},
                    (OperandType::AllocatedFalse, OperandType::False, Boolean::Constant(false)) => {},
                    (OperandType::AllocatedFalse, OperandType::AllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("and result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedFalse, OperandType::AllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("and result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedFalse, OperandType::NegatedAllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::AllocatedFalse, OperandType::NegatedAllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },

                    (OperandType::NegatedAllocatedTrue, OperandType::True, Boolean::Not(_)) => {},
                    (OperandType::NegatedAllocatedTrue, OperandType::False, Boolean::Constant(false)) => {},
                    (OperandType::NegatedAllocatedTrue, OperandType::AllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedTrue, OperandType::AllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedTrue, OperandType::NegatedAllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("nor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedTrue, OperandType::NegatedAllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("nor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },

                    (OperandType::NegatedAllocatedFalse, OperandType::True, Boolean::Not(_)) => {},
                    (OperandType::NegatedAllocatedFalse, OperandType::False, Boolean::Constant(false)) => {},
                    (OperandType::NegatedAllocatedFalse, OperandType::AllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },
                    (OperandType::NegatedAllocatedFalse, OperandType::AllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("and not result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedFalse, OperandType::NegatedAllocatedTrue, Boolean::Is(ref v)) => {
                        assert!(cs.get("nor result") == Field::zero());
                        assert_eq!(v.value, Some(false));
                    },
                    (OperandType::NegatedAllocatedFalse, OperandType::NegatedAllocatedFalse, Boolean::Is(ref v)) => {
                        assert!(cs.get("nor result") == Field::one());
                        assert_eq!(v.value, Some(true));
                    },

                    _ => {
                        panic!("unexpected behavior at {:?} AND {:?}", first_operand, second_operand);
                    }
                }
            }
        }
    }

    #[test]
    fn test_enforce_in_field() {
        {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let mut bits = vec![];
            for (i, b) in BitIterator::new(Fr::char()).skip(1).enumerate() {
                bits.push(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    Some(b)
                ).unwrap()));
            }

            Boolean::enforce_in_field::<_, _, Fr>(&mut cs, &bits).unwrap();

            assert!(!cs.is_satisfied());
        }

        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..1000 {
            let r = Fr::rand(&mut rng);
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let mut bits = vec![];
            for (i, b) in BitIterator::new(r.into_repr()).skip(1).enumerate() {
                bits.push(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    Some(b)
                ).unwrap()));
            }

            Boolean::enforce_in_field::<_, _, Fr>(&mut cs, &bits).unwrap();

            assert!(cs.is_satisfied());
        }

        for _ in 0..1000 {
            // Sample a random element not in the field
            let r = loop {
                let mut a = Fr::rand(&mut rng).into_repr();
                let b = Fr::rand(&mut rng).into_repr();

                a.add_nocarry(&b);
                // we're shaving off the high bit later
                a.as_mut()[3] &= 0x7fffffffffffffff;
                if Fr::from_repr(a).is_err() {
                    break a;
                }
            };

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let mut bits = vec![];
            for (i, b) in BitIterator::new(r).skip(1).enumerate() {
                bits.push(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    Some(b)
                ).unwrap()));
            }

            Boolean::enforce_in_field::<_, _, Fr>(&mut cs, &bits).unwrap();

            assert!(!cs.is_satisfied());
        }
    }

    #[test]
    fn test_enforce_nand() {
        {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            Boolean::enforce_nand(&mut cs, &[Boolean::constant(false)]).is_ok();
            Boolean::enforce_nand(&mut cs, &[Boolean::constant(true)]).is_err();
        }

        for i in 1..5 {
            // with every possible assignment for them
            for mut b in 0..(1 << i) {
                // with every possible negation
                for mut n in 0..(1 << i) {
                    let mut cs = TestConstraintSystem::<Bls12>::new();

                    let mut expected = true;

                    let mut bits = vec![];
                    for j in 0..i {
                        expected &= b & 1 == 1;

                        if n & 1 == 1 {
                            bits.push(Boolean::from(AllocatedBit::alloc(
                                cs.namespace(|| format!("bit {}", j)),
                                Some(b & 1 == 1)
                            ).unwrap()));
                        } else {
                            bits.push(Boolean::from(AllocatedBit::alloc(
                                cs.namespace(|| format!("bit {}", j)),
                                Some(b & 1 == 0)
                            ).unwrap()).not());
                        }
                        
                        b >>= 1;
                        n >>= 1;
                    }

                    let expected = !expected;

                    Boolean::enforce_nand(&mut cs, &bits).unwrap();

                    if expected {
                        assert!(cs.is_satisfied());
                    } else {
                        assert!(!cs.is_satisfied());
                    }
                }
            }
        }
    }

    #[test]
    fn test_kary_and() {
        // test different numbers of operands
        for i in 1..15 {
            // with every possible assignment for them
            for mut b in 0..(1 << i) {
                let mut cs = TestConstraintSystem::<Bls12>::new();

                let mut expected = true;

                let mut bits = vec![];
                for j in 0..i {
                    expected &= b & 1 == 1;

                    bits.push(Boolean::from(AllocatedBit::alloc(
                        cs.namespace(|| format!("bit {}", j)),
                        Some(b & 1 == 1)
                    ).unwrap()));
                    b >>= 1;
                }

                let r = Boolean::kary_and(&mut cs, &bits).unwrap();

                assert!(cs.is_satisfied());

                match r {
                    Boolean::Is(ref r) => {
                        assert_eq!(r.value.unwrap(), expected);
                    },
                    _ => unreachable!()
                }
            }
        }
    }
}
