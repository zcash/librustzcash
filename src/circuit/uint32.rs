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

use super::boolean::{
    Boolean,
    AllocatedBit
};

/// Represents an interpretation of 32 `Boolean` objects as an
/// unsigned integer.
#[derive(Clone)]
pub struct UInt32<Var> {
    // Least significant bit first
    bits: Vec<Boolean<Var>>,
    value: Option<u32>
}

impl<Var: Copy> UInt32<Var> {
    /// Construct a constant `UInt32` from a `u32`
    pub fn constant(value: u32) -> Self
    {
        let mut bits = Vec::with_capacity(32);

        let mut tmp = value;
        for _ in 0..32 {
            if tmp & 1 == 1 {
                bits.push(Boolean::constant(true))
            } else {
                bits.push(Boolean::constant(false))
            }

            tmp >>= 1;
        }

        UInt32 {
            bits: bits,
            value: Some(value)
        }
    }

    /// Allocate a `UInt32` in the constraint system
    pub fn alloc<E, CS>(
        mut cs: CS,
        value: Option<u32>
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let values = match value {
            Some(mut val) => {
                let mut v = Vec::with_capacity(32);

                for _ in 0..32 {
                    v.push(Some(val & 1 == 1));
                    val >>= 1;
                }

                v
            },
            None => vec![None; 32]
        };

        let bits = values.into_iter()
                         .enumerate()
                         .map(|(i, v)| {
                            Ok(Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("allocated bit {}", i)), v)?))
                         })
                         .collect::<Result<Vec<_>, SynthesisError>>()?;

        Ok(UInt32 {
            bits: bits,
            value: value
        })
    }

    /// Turns this `UInt32` into its little-endian byte order representation.
    pub fn into_bits(&self) -> Vec<Boolean<Var>> {
        self.bits.chunks(8)
                 .flat_map(|v| v.iter().rev())
                 .cloned()
                 .collect()
    }

    /// Converts a little-endian byte order representation of bits into a
    /// `UInt32`.
    pub fn from_bits(bits: &[Boolean<Var>]) -> Self
    {
        assert_eq!(bits.len(), 32);

        let new_bits = bits.chunks(8)
                           .flat_map(|v| v.iter().rev())
                           .cloned()
                           .collect::<Vec<_>>();

        let mut value = Some(0u32);
        for b in new_bits.iter().rev() {
            value.as_mut().map(|v| *v <<= 1);

            match b {
                &Boolean::Constant(b) => {
                    if b {
                        value.as_mut().map(|v| *v |= 1);
                    }
                },
                &Boolean::Is(ref b) => {
                    match b.get_value() {
                        Some(true) => { value.as_mut().map(|v| *v |= 1); },
                        Some(false) => {},
                        None => { value = None }
                    }
                },
                &Boolean::Not(ref b) => {
                    match b.get_value() {
                        Some(false) => { value.as_mut().map(|v| *v |= 1); },
                        Some(true) => {},
                        None => { value = None }
                    }
                }
            }
        }

        UInt32 {
            value: value,
            bits: new_bits
        }
    }

    pub fn rotr(&self, by: usize) -> Self {
        let by = by % 32;

        let new_bits = self.bits.iter()
                                .skip(by)
                                .chain(self.bits.iter())
                                .take(32)
                                .cloned()
                                .collect();

        UInt32 {
            bits: new_bits,
            value: self.value.map(|v| v.rotate_right(by as u32))
        }
    }

    /// XOR this `UInt32` with another `UInt32`
    pub fn xor<E, CS>(
        &self,
        mut cs: CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        let new_value = match (self.value, other.value) {
            (Some(a), Some(b)) => {
                Some(a ^ b)
            },
            _ => None
        };

        let bits = self.bits.iter()
                            .zip(other.bits.iter())
                            .enumerate()
                            .map(|(i, (a, b))| {
                                Boolean::xor(cs.namespace(|| format!("xor of bit {}", i)), a, b)
                            })
                            .collect::<Result<_, _>>()?;

        Ok(UInt32 {
            bits: bits,
            value: new_value
        })
    }

    // TODO: could optimize
    /// Perform modular addition of several `UInt32` objects.
    pub fn addmany<E, CS>(
        mut cs: CS,
        operands: &[Self]
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E, Variable=Var>
    {
        // Make some arbitrary bounds for ourselves to avoid overflows
        // in the scalar field
        assert!(E::Fr::NUM_BITS >= 64);
        assert!(operands.len() >= 2); // Weird trivial cases that should never happen
        assert!(operands.len() <= 10);

        // Compute the maximum value of the sum so we allocate enough bits for
        // the result
        let mut max_value = (operands.len() as u64) * (u32::max_value() as u64);

        // Keep track of the resulting value
        let mut result_value = Some(0u64);

        // This is a linear combination that we will enforce to be "zero"
        let mut lc = LinearCombination::zero();

        // Iterate over the operands
        for op in operands {
            // Accumulate the value
            match op.value {
                Some(val) => {
                    result_value.as_mut().map(|v| *v += val as u64);
                },
                None => {
                    // If any of our operands have unknown value, we won't
                    // know the value of the result
                    result_value = None;
                }
            }

            // Iterate over each bit of the operand and add the operand to
            // the linear combination
            let mut coeff = E::Fr::one();
            for bit in &op.bits {
                match bit {
                    &Boolean::Is(ref bit) => {
                        // Add coeff * bit
                        lc = lc + (coeff, bit.get_variable());
                    },
                    &Boolean::Not(ref bit) => {
                        // Add coeff * (1 - bit) = coeff * ONE - coeff * bit
                        lc = lc + (coeff, cs.one()) - (coeff, bit.get_variable());
                    },
                    &Boolean::Constant(bit) => {
                        if bit {
                            lc = lc + (coeff, cs.one());
                        }
                    }
                }

                coeff.double();
            }
        }

        // The value of the actual result is modulo 2^32
        let modular_value = result_value.map(|v| v as u32);

        // Storage area for the resulting bits
        let mut result_bits = vec![];

        // Allocate each bit of the result
        let mut coeff = E::Fr::one();
        let mut i = 0;
        while max_value != 0 {
            // Allocate the bit
            let b = AllocatedBit::alloc(cs.namespace(|| format!("result bit {}", i)), result_value.map(|v| (v >> i) & 1 == 1))?;

            // Subtract this bit from the linear combination to ensure the sums balance out
            lc = lc - (coeff, b.get_variable());

            result_bits.push(b.into());

            max_value >>= 1;
            i += 1;
            coeff.double();
        }

        // Enforce that the linear combination equals zero
        cs.enforce(
            || "modular addition",
            LinearCombination::zero(),
            LinearCombination::zero(),
            lc
        );

        // Discard carry bits that we don't care about
        result_bits.truncate(32);

        Ok(UInt32 {
            bits: result_bits,
            value: modular_value
        })
    }
}

#[cfg(test)]
mod test {
    use rand::{XorShiftRng, SeedableRng, Rng};
    use ::circuit::boolean::{Boolean};
    use super::{UInt32};
    use pairing::bls12_381::{Bls12};
    use pairing::{Field};
    use ::circuit::test::*;
    use bellman::{ConstraintSystem};

    #[test]
    fn test_uint32_from_bits() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut v = (0..32).map(|_| Boolean::<()>::constant(rng.gen())).collect::<Vec<_>>();

            let b = UInt32::from_bits(&v);

            for (i, bit) in b.bits.iter().enumerate() {
                match bit {
                    &Boolean::Constant(bit) => {
                        assert!(bit == ((b.value.unwrap() >> i) & 1 == 1));
                    },
                    _ => unreachable!()
                }
            }

            let expected_to_be_same = b.into_bits();

            for x in v.iter().zip(expected_to_be_same.iter())
            {
                match x {
                    (&Boolean::Constant(true), &Boolean::Constant(true)) => {},
                    (&Boolean::Constant(false), &Boolean::Constant(false)) => {},
                    _ => unreachable!()
                }
            }
        }
    }

    #[test]
    fn test_uint32_xor() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();

            let mut expected = a ^ b ^ c;

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::alloc(cs.namespace(|| "c_bit"), Some(c)).unwrap();

            let r = a_bit.xor(cs.namespace(|| "first xor"), &b_bit).unwrap();
            let r = r.xor(cs.namespace(|| "second xor"), &c_bit).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }
        }
    }

    #[test]
    fn test_uint32_addmany() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();
            let d: u32 = rng.gen();

            let mut expected = (a ^ b).wrapping_add(c).wrapping_add(d);

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::constant(c);
            let d_bit = UInt32::alloc(cs.namespace(|| "d_bit"), Some(d)).unwrap();

            let r = a_bit.xor(cs.namespace(|| "xor"), &b_bit).unwrap();
            let r = UInt32::addmany(cs.namespace(|| "addition"), &[r, c_bit, d_bit]).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }

            // Flip a bit and see if the addition constraint still works
            if cs.get("addition/result bit 0/boolean").is_zero() {
                cs.set("addition/result bit 0/boolean", Field::one());
            } else {
                cs.set("addition/result bit 0/boolean", Field::zero());
            }

            assert!(!cs.is_satisfied());
        }
    }

    #[test]
    fn test_uint32_rotr() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let mut num = rng.gen();

        let a = UInt32::<()>::constant(num);

        for i in 0..32 {
            let b = a.rotr(i);

            assert!(b.value.unwrap() == num);

            let mut tmp = num;
            for b in &b.bits {
                match b {
                    &Boolean::Constant(b) => {
                        assert_eq!(b, tmp & 1 == 1);
                    },
                    _ => unreachable!()
                }

                tmp >>= 1;
            }

            num = num.rotate_right(1);
        }
    }
}
