use pairing::{Engine, Field};
use super::*;
use super::mont::{
    MontgomeryPoint,
    EdwardsPoint
};
use super::num::AllocatedNum;
use super::boolean::Boolean;
use ::jubjub::*;
use bellman::{
    ConstraintSystem,
    LinearCombination
};

// Synthesize the constants for each base pattern.
fn synth<'a, E: Engine, I>(
    window_size: usize,
    constants: I,
    assignment: &mut [E::Fr]
)
    where I: IntoIterator<Item=&'a E::Fr>
{
    assert_eq!(assignment.len(), 1 << window_size);

    for (i, constant) in constants.into_iter().enumerate() {
        let mut cur = assignment[i];
        cur.negate();
        cur.add_assign(constant);
        assignment[i] = cur;
        for (j, eval) in assignment.iter_mut().enumerate().skip(i + 1) {
            if j & i == i {
                eval.add_assign(&cur);
            }
        }
    }
}

pub fn pedersen_hash<E: JubjubEngine, CS, Var: Copy>(
    mut cs: CS,
    bits: &[Boolean<Var>],
    params: &E::Params
) -> Result<EdwardsPoint<E, Var>, SynthesisError>
    where CS: ConstraintSystem<E, Variable=Var>
{
    let mut edwards_result = None;
    let mut bits = bits.iter();
    let mut segment_generators = params.pedersen_circuit_generators().iter();
    let boolean_false = Boolean::constant(false);

    let mut segment_i = 0;
    loop {
        let mut segment_result = None;
        let mut segment_windows = &segment_generators.next()
                                                     .expect("enough segments")[..];

        let mut window_i = 0;
        while let Some(a) = bits.next() {
            let b = bits.next().unwrap_or(&boolean_false);
            let c = bits.next().unwrap_or(&boolean_false);

            let tmp = lookup3_xy_with_conditional_negation(
                cs.namespace(|| format!("segment {}, window {}", segment_i, window_i)),
                &[a.clone(), b.clone(), c.clone()],
                &segment_windows[0]
            )?;

            let tmp = MontgomeryPoint::interpret_unchecked(tmp.0, tmp.1);

            match segment_result {
                None => {
                    segment_result = Some(tmp);
                },
                Some(ref mut segment_result) => {
                    *segment_result = tmp.add(
                        cs.namespace(|| format!("addition of segment {}, window {}", segment_i, window_i)),
                        segment_result,
                        params
                    )?;
                }
            }

            segment_windows = &segment_windows[1..];

            if segment_windows.len() == 0 {
                break;
            }

            window_i += 1;
        }

        match segment_result {
            Some(segment_result) => {
                // Convert this segment into twisted Edwards form.
                let segment_result = segment_result.into_edwards(
                    cs.namespace(|| format!("conversion of segment {} into edwards", segment_i)),
                    params
                )?;

                match edwards_result {
                    Some(ref mut edwards_result) => {
                        *edwards_result = segment_result.add(
                            cs.namespace(|| format!("addition of segment {} to accumulator", segment_i)),
                            edwards_result,
                            params
                        )?;
                    },
                    None => {
                        edwards_result = Some(segment_result);
                    }
                }
            },
            None => {
                // We didn't process any new bits.
                break;
            }
        }

        segment_i += 1;
    }

    // TODO: maybe assert bits.len() > 0
    Ok(edwards_result.unwrap())
}

/// Performs a 3-bit window table lookup, where
/// one of the bits is a sign bit.
fn lookup3_xy_with_conditional_negation<E: Engine, CS, Var: Copy>(
    mut cs: CS,
    bits: &[Boolean<Var>],
    coords: &[(E::Fr, E::Fr)]
) -> Result<(AllocatedNum<E, Var>, AllocatedNum<E, Var>), SynthesisError>
    where CS: ConstraintSystem<E, Variable=Var>
{
    // TODO: This can be made into a 2-constraint lookup
    // if it can return linear combinations rather than
    // allocated numbers.

    assert_eq!(bits.len(), 3);
    assert_eq!(coords.len(), 4);

    // Calculate the index into `coords`
    let i =
    match (bits[0].get_value(), bits[1].get_value()) {
        (Some(a_value), Some(b_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            Some(tmp)
        },
        _ => None
    };

    // Allocate the x-coordinate resulting from the lookup
    let res_x = AllocatedNum::alloc(
        cs.namespace(|| "x"),
        || {
            Ok(coords[*i.get()?].0)
        }
    )?;

    // Allocate the y-coordinate resulting from the lookup
    let res_y = AllocatedNum::alloc(
        cs.namespace(|| "y"),
        || {
            Ok(coords[*i.get()?].1)
        }
    )?;

    let one = cs.one();

    // Compute the coefficients for the lookup constraints
    let mut x_coeffs = [E::Fr::zero(); 4];
    let mut y_coeffs = [E::Fr::zero(); 4];
    synth::<E, _>(2, coords.iter().map(|c| &c.0), &mut x_coeffs);
    synth::<E, _>(2, coords.iter().map(|c| &c.1), &mut y_coeffs);

    cs.enforce(
        || "x-coordinate lookup",
        LinearCombination::<Var, E>::zero() + (x_coeffs[0b01], one)
                                            + &bits[1].lc::<E>(one, x_coeffs[0b11]),
        LinearCombination::<Var, E>::zero() + &bits[0].lc::<E>(one, E::Fr::one()),
        LinearCombination::<Var, E>::zero() + res_x.get_variable()
                                            - (x_coeffs[0b00], one)
                                            - &bits[1].lc::<E>(one, x_coeffs[0b10])
    );

    cs.enforce(
        || "y-coordinate lookup",
        LinearCombination::<Var, E>::zero() + (y_coeffs[0b01], one)
                                            + &bits[1].lc::<E>(one, y_coeffs[0b11]),
        LinearCombination::<Var, E>::zero() + &bits[0].lc::<E>(one, E::Fr::one()),
        LinearCombination::<Var, E>::zero() + res_y.get_variable()
                                            - (y_coeffs[0b00], one)
                                            - &bits[1].lc::<E>(one, y_coeffs[0b10])
    );

    let final_y = res_y.conditionally_negate(&mut cs, &bits[2])?;

    Ok((res_x, final_y))
}

#[cfg(test)]
mod test {
    use rand::{SeedableRng, Rand, Rng, XorShiftRng};
    use super::*;
    use ::circuit::test::*;
    use ::circuit::boolean::{Boolean, AllocatedBit};
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;

    #[test]
    fn test_pedersen_hash_constraints() {
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubBls12::new();
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let input: Vec<bool> = (0..(Fr::NUM_BITS * 2)).map(|_| rng.gen()).collect();

        let input_bools: Vec<Boolean<_>> = input.iter().enumerate().map(|(i, b)| {
            Boolean::from(
                AllocatedBit::alloc(cs.namespace(|| format!("input {}", i)), Some(*b)).unwrap()
            )
        }).collect();

        pedersen_hash(
            cs.namespace(|| "pedersen hash"),
            &input_bools,
            params
        ).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 1539);
    }

    #[test]
    fn test_pedersen_hash() {
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubBls12::new();

        for length in 1..1000 {
            for _ in 0..5 {
                let mut input: Vec<bool> = (0..length).map(|_| rng.gen()).collect();

                let mut cs = TestConstraintSystem::<Bls12>::new();

                let input_bools: Vec<Boolean<_>> = input.iter().enumerate().map(|(i, b)| {
                    Boolean::from(
                        AllocatedBit::alloc(cs.namespace(|| format!("input {}", i)), Some(*b)).unwrap()
                    )
                }).collect();

                let res = pedersen_hash(
                    cs.namespace(|| "pedersen hash"),
                    &input_bools,
                    params
                ).unwrap();

                assert!(cs.is_satisfied());

                let expected = ::pedersen_hash::pedersen_hash::<Bls12, _>(
                    input.into_iter(),
                    params
                ).into_xy();

                assert_eq!(res.x.get_value().unwrap(), expected.0);
                assert_eq!(res.y.get_value().unwrap(), expected.1);
            }
        }
    }

    #[test]
    fn test_lookup3_xy_with_conditional_negation() {
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a_val = rng.gen();
            let a = Boolean::from(
                AllocatedBit::alloc(cs.namespace(|| "a"), Some(a_val)).unwrap()
            );

            let b_val = rng.gen();
            let b = Boolean::from(
                AllocatedBit::alloc(cs.namespace(|| "b"), Some(b_val)).unwrap()
            );

            let c_val = rng.gen();
            let c = Boolean::from(
                AllocatedBit::alloc(cs.namespace(|| "c"), Some(c_val)).unwrap()
            );

            let bits = vec![a, b, c];

            let points: Vec<(Fr, Fr)> = (0..4).map(|_| (rng.gen(), rng.gen())).collect();

            let res = lookup3_xy_with_conditional_negation(&mut cs, &bits, &points).unwrap();

            assert!(cs.is_satisfied());

            let mut index = 0;
            if a_val { index += 1 }
            if b_val { index += 2 }

            assert_eq!(res.0.get_value().unwrap(), points[index].0);
            let mut tmp = points[index].1;
            if c_val { tmp.negate() }
            assert_eq!(res.1.get_value().unwrap(), tmp);
        }
    }

    #[test]
    fn test_synth() {
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let window_size = 4;

        let mut assignment = vec![Fr::zero(); (1 << window_size)];
        let constants: Vec<_> = (0..(1 << window_size)).map(|_| Fr::rand(&mut rng)).collect();

        synth::<Bls12, _>(window_size, &constants, &mut assignment);

        for b in 0..(1 << window_size) {
            let mut acc = Fr::zero();

            for j in 0..(1 << window_size) {
                if j & b == j {
                    acc.add_assign(&assignment[j]);
                }
            }

            assert_eq!(acc, constants[b]);
        }
    }
}
