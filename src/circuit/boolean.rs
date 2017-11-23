use pairing::{
    Engine,
    Field
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
}

impl<Var> From<AllocatedBit<Var>> for Boolean<Var> {
    fn from(b: AllocatedBit<Var>) -> Boolean<Var> {
        Boolean::Is(b)
    }
}

#[cfg(test)]
mod test {
    use bellman::{ConstraintSystem};
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{Field, PrimeField};
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
                AllocatedBit::xor(&mut cs, &a, &b).unwrap();

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
                AllocatedBit::and(&mut cs, &a, &b).unwrap();

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

    #[test]
    fn test_boolean_xor() {
        #[derive(Copy, Clone)]
        enum OperandType {
            True,
            False,
            AllocatedTrue,
            AllocatedFalse,
            NegatedAllocatedTrue,
            NegatedAllocatedFalse
        }

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
}
