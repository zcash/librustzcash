#[cfg(test)]
pub mod test;

pub mod boolean;
pub mod uint32;
pub mod blake2s;
pub mod num;
pub mod lookup;
pub mod ecc;
pub mod pedersen_hash;

use pairing::{
    PrimeField,
    PrimeFieldRepr,
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit
};

use jubjub::{
    JubjubEngine,
    PrimeOrder,
    FixedGenerators,
    edwards
};

use constants;

use primitives::{
    ValueCommitment,
    ProofGenerationKey,
    PaymentAddress
};

// TODO: This should probably be removed and we
// should use existing helper methods on `Option`
// for mapping with an error.
/// This basically is just an extension to `Option`
/// which allows for a convenient mapping to an
/// error on `None`.
trait Assignment<T> {
    fn get(&self) -> Result<&T, SynthesisError>;
}

impl<T> Assignment<T> for Option<T> {
    fn get(&self) -> Result<&T, SynthesisError> {
        match *self {
            Some(ref v) => Ok(v),
            None => Err(SynthesisError::AssignmentMissing)
        }
    }
}

/// This is an instance of the `Spend` circuit.
pub struct Spend<'a, E: JubjubEngine> {
    pub params: &'a E::Params,

    /// Pedersen commitment to the value being spent
    pub value_commitment: Option<ValueCommitment<E>>,

    /// Key required to construct proofs for spending notes
    /// for a particular spending key
    pub proof_generation_key: Option<ProofGenerationKey<E>>,

    /// The payment address associated with the note
    pub payment_address: Option<PaymentAddress<E>>,

    /// The randomness of the note commitment
    pub commitment_randomness: Option<E::Fs>,

    /// The authentication path of the commitment in the tree
    pub auth_path: Vec<Option<(E::Fr, bool)>>
}

/// This is an output circuit instance.
pub struct Output<'a, E: JubjubEngine> {
    pub params: &'a E::Params,

    /// Pedersen commitment to the value being spent
    pub value_commitment: Option<ValueCommitment<E>>,

    /// The diversified base, computed by GH(d)
    pub g_d: Option<edwards::Point<E, PrimeOrder>>,

    /// The diversified address point, computed by GH(d)^ivk
    pub pk_d: Option<edwards::Point<E, PrimeOrder>>,

    /// The randomness used to hide the note commitment data
    pub commitment_randomness: Option<E::Fs>,

    /// The ephemeral secret key for DH with recipient
    pub esk: Option<E::Fs>
}

/// Exposes a Pedersen commitment to the value as an
/// input to the circuit
fn expose_value_commitment<E, CS>(
    mut cs: CS,
    value_commitment: Option<ValueCommitment<E>>,
    params: &E::Params
) -> Result<Vec<boolean::Boolean>, SynthesisError>
    where E: JubjubEngine,
          CS: ConstraintSystem<E>
{
    // Booleanize the value into little-endian bit order
    let value_bits = boolean::u64_into_boolean_vec_le(
        cs.namespace(|| "value"),
        value_commitment.as_ref().map(|c| c.value)
    )?;

    // Compute the note value in the exponent
    let gv = ecc::fixed_base_multiplication(
        cs.namespace(|| "compute the value in the exponent"),
        FixedGenerators::ValueCommitmentValue,
        &value_bits,
        params
    )?;

    // Booleanize the randomness. This does not ensure
    // the bit representation is "in the field" because
    // it doesn't matter for security.
    let hr = boolean::field_into_boolean_vec_le(
        cs.namespace(|| "hr"),
        value_commitment.as_ref().map(|c| c.randomness)
    )?;

    // Compute the randomness in the exponent
    let hr = ecc::fixed_base_multiplication(
        cs.namespace(|| "computation of randomization for value commitment"),
        FixedGenerators::ValueCommitmentRandomness,
        &hr,
        params
    )?;

    // Compute the Pedersen commitment to the value
    let gvhr = gv.add(
        cs.namespace(|| "computation of value commitment"),
        &hr,
        params
    )?;

    // Expose the commitment as an input to the circuit
    gvhr.inputize(cs.namespace(|| "commitment point"))?;

    Ok(value_bits)
}

impl<'a, E: JubjubEngine> Circuit<E> for Spend<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        let value_bits = expose_value_commitment(
            cs.namespace(|| "value commitment"),
            self.value_commitment,
            self.params
        )?;

        // Compute rk = [rsk] ProvingPublicKey
        let rk;
        {
            // Witness rsk as bits
            let rsk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rsk"),
                self.proof_generation_key.as_ref().map(|k| k.rsk.clone())
            )?;

            // NB: We don't ensure that the bit representation of rsk
            // is "in the field" (Fs) because it's not used except to
            // demonstrate the prover knows it. If they know a
            // congruency then that's equivalent.

            // Compute rk = [rsk] ProvingPublicKey
            rk = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of rk"),
                FixedGenerators::ProofGenerationKey,
                &rsk,
                self.params
            )?;
        }

        // Prover witnesses ak (ensures that it's on the curve)
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.proof_generation_key.as_ref().map(|k| k.ak.clone()),
            self.params
        )?;

        // There are no sensible attacks on small order points
        // of ak (that we're aware of!) but it's a cheap check,
        // so we do it.
        ak.assert_not_small_order(
            cs.namespace(|| "ak not small order"),
            self.params
        )?;

        // Unpack ak and rk for input to BLAKE2s

        // This is the "viewing key" preimage for CRH^ivk
        let mut vk = vec![];
        vk.extend(
            ak.repr(cs.namespace(|| "representation of ak"))?
        );

        // This is the nullifier randomness preimage for PRF^nr
        let mut nr_preimage = vec![];

        // Extend vk and nr preimages with the representation of
        // rk.
        {
            let repr_rk = rk.repr(
                cs.namespace(|| "representation of rk")
            )?;

            vk.extend(repr_rk.iter().cloned());
            nr_preimage.extend(repr_rk);
        }

        assert_eq!(vk.len(), 512);
        assert_eq!(nr_preimage.len(), 256);

        // Compute the incoming viewing key ivk
        let mut ivk = blake2s::blake2s(
            cs.namespace(|| "computation of ivk"),
            &vk,
            constants::CRH_IVK_PERSONALIZATION
        )?;

        // Little endian bit order
        ivk.reverse();

        // drop_5 to ensure it's in the field
        ivk.truncate(E::Fs::CAPACITY as usize);

        // Witness g_d. Ensures the point is on the
        // curve, but not its order. If the prover
        // manages to witness a commitment in the
        // tree, then the Output circuit would have
        // already guaranteed this.
        // TODO: We might as well just perform the
        // check again here, since it's not expensive.
        let g_d = {
            // This binding is to avoid a weird edge case in Rust's
            // ownership/borrowing rules. self is partially moved
            // above, but the closure for and_then will have to
            // move self (or a reference to self) to reference
            // self.params, so we have to copy self.params here.
            let params = self.params;

            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.payment_address.as_ref().and_then(|a| a.g_d(params)),
                self.params
            )?
        };

        // Compute pk_d = g_d^ivk
        let pk_d = g_d.mul(
            cs.namespace(|| "compute pk_d"),
            &ivk,
            self.params
        )?;

        // Compute note contents
        // value (in big endian) followed by g_d and pk_d
        let mut note_contents = vec![];
        note_contents.extend(value_bits.into_iter().rev());
        note_contents.extend(
            g_d.repr(cs.namespace(|| "representation of g_d"))?
        );
        note_contents.extend(
            pk_d.repr(cs.namespace(|| "representation of pk_d"))?
        );

        assert_eq!(
            note_contents.len(),
            64 + // value
            256 + // g_d
            256 // p_d
        );

        // Compute the hash of the note contents
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_contents,
            self.params
        )?;

        {
            // Booleanize the randomness for the note commitment
            let cmr = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "cmr"),
                self.commitment_randomness
            )?;

            // Compute the note commitment randomness in the exponent
            let cmr = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                FixedGenerators::NoteCommitmentRandomness,
                &cmr,
                self.params
            )?;

            // Randomize the note commitment. Pedersen hashes are not
            // themselves hiding commitments.
            cm = cm.add(
                cs.namespace(|| "randomization of note commitment"),
                &cmr,
                self.params
            )?;
        }

        let tree_depth = self.auth_path.len();

        // This will store (least significant bit first)
        // the position of the note in the tree, for use
        // in nullifier computation.
        let mut position_bits = vec![];

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = cm.get_x().clone();

        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1)
            )?);

            // Push this boolean for nullifier computation later
            position_bits.push(cur_is_right.clone());

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element = num::AllocatedNum::alloc(
                cs.namespace(|| "path element"),
                || {
                    Ok(e.get()?.0)
                }
            )?;

            // Swap the two if the current subtree is on the right
            let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right
            )?;

            // We don't need to be strict, because the function is
            // collision-resistant. If the prover witnesses a congruency,
            // they will be unable to find an authentication path in the
            // tree with high probability.
            let mut preimage = vec![];
            preimage.extend(xl.into_bits_le(cs.namespace(|| "xl into bits"))?);
            preimage.extend(xr.into_bits_le(cs.namespace(|| "xr into bits"))?);

            // Compute the new subtree value
            cur = pedersen_hash::pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                pedersen_hash::Personalization::MerkleTree(i),
                &preimage,
                self.params
            )?.get_x().clone(); // Injective encoding
        }

        assert_eq!(position_bits.len(), tree_depth);

        // Expose the anchor
        cur.inputize(cs.namespace(|| "anchor"))?;

        // Compute the cm + g^position for preventing
        // faerie gold attacks
        {
            // Compute the position in the exponent
            let position = ecc::fixed_base_multiplication(
                cs.namespace(|| "g^position"),
                FixedGenerators::NullifierPosition,
                &position_bits,
                self.params
            )?;

            // Add the position to the commitment
            cm = cm.add(
                cs.namespace(|| "faerie gold prevention"),
                &position,
                self.params
            )?;
        }
        
        // Let's compute nr = BLAKE2s(rk || cm + position)
        nr_preimage.extend(
            cm.repr(cs.namespace(|| "representation of cm"))?
        );

        assert_eq!(nr_preimage.len(), 512);
        
        // Compute nr
        let mut nr = blake2s::blake2s(
            cs.namespace(|| "nr computation"),
            &nr_preimage,
            constants::PRF_NR_PERSONALIZATION
        )?;

        // Little endian bit order
        nr.reverse();

        // We want the randomization in the field to
        // simplify outside code.
        // TODO: This isn't uniformly random.
        nr.truncate(E::Fs::CAPACITY as usize);

        // Compute nullifier
        let nf = ak.mul(
            cs.namespace(|| "computation of nf"),
            &nr,
            self.params
        )?;

        // Expose the nullifier publicly
        nf.inputize(cs.namespace(|| "nullifier"))?;

        Ok(())
    }
}

impl<'a, E: JubjubEngine> Circuit<E> for Output<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        let value_bits = expose_value_commitment(
            cs.namespace(|| "value commitment"),
            self.value_commitment,
            self.params
        )?;

        // Let's start to construct our note, which contains
        // value (big endian)
        let mut note_contents = vec![];
        note_contents.extend(value_bits.into_iter().rev());

        // Let's deal with g_d
        {
            // Prover witnesses g_d, ensuring it's on the
            // curve.
            let g_d = ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.g_d,
                self.params
            )?;

            // g_d is ensured to be large order. The relationship
            // between g_d and pk_d ultimately binds ivk to the
            // note. If this were a small order point, it would
            // not do this correctly, and the prover could
            // double-spend by finding random ivk's that satisfy
            // the relationship.
            //
            // Further, if it were small order, epk would be
            // small order too!
            g_d.assert_not_small_order(
                cs.namespace(|| "g_d not small order"),
                self.params
            )?;

            // Extend our note contents with the representation of
            // g_d.
            note_contents.extend(
                g_d.repr(cs.namespace(|| "representation of g_d"))?
            );

            // Booleanize our ephemeral secret key
            let esk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "esk"),
                self.esk
            )?;

            // Create the ephemeral public key from g_d.
            let epk = g_d.mul(
                cs.namespace(|| "epk computation"),
                &esk,
                self.params
            )?;

            // Expose epk publicly.
            epk.inputize(cs.namespace(|| "epk"))?;
        }

        // Now let's deal with pk_d. We don't do any checks and
        // essentially allow the prover to witness any 256 bits
        // they would like.
        {
            // Just grab pk_d from the witness
            let pk_d = self.pk_d.map(|e| e.into_xy());

            // Witness the y-coordinate, encoded as little
            // endian bits (to match the representation)
            let y_contents = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "pk_d bits of y"),
                pk_d.map(|e| e.1)
            )?;

            // Witness the sign bit
            let sign_bit = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "pk_d bit of x"),
                pk_d.map(|e| e.0.into_repr().is_odd())
            )?);

            // Extend the note with pk_d representation
            note_contents.extend(y_contents);
            note_contents.push(sign_bit);
        }

        assert_eq!(
            note_contents.len(),
            64 + // value
            256 + // g_d
            256 // p_d
        );

        // Compute the hash of the note contents
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_contents,
            self.params
        )?;

        {
            // Booleanize the randomness
            let cmr = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "cmr"),
                self.commitment_randomness
            )?;

            // Compute the note commitment randomness in the exponent
            let cmr = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                FixedGenerators::NoteCommitmentRandomness,
                &cmr,
                self.params
            )?;

            // Randomize our note commitment
            cm = cm.add(
                cs.namespace(|| "randomization of note commitment"),
                &cmr,
                self.params
            )?;
        }

        // Only the x-coordinate of the output is revealed,
        // since we know it is prime order, and we know that
        // the x-coordinate is an injective encoding for
        // prime-order elements.
        cm.get_x().inputize(cs.namespace(|| "commitment"))?;

        Ok(())
    }
}

#[test]
fn test_input_circuit_with_bls12_381() {
    use pairing::{Field, BitIterator};
    use pairing::bls12_381::*;
    use rand::{SeedableRng, Rng, XorShiftRng};
    use ::circuit::test::*;
    use jubjub::{JubjubBls12, fs};

    let params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let tree_depth = 32;

    let value_commitment = ValueCommitment {
        value: rng.gen(),
        randomness: rng.gen()
    };

    let rsk: fs::Fs = rng.gen();
    let ak: edwards::Point<Bls12, PrimeOrder> = edwards::Point::rand(rng, params).mul_by_cofactor(params);

    let proof_generation_key = ::primitives::ProofGenerationKey {
        ak: ak.clone(),
        rsk: rsk.clone()
    };

    let viewing_key = proof_generation_key.into_viewing_key(params);

    let payment_address;

    loop {
        let diversifier = ::primitives::Diversifier(rng.gen());

        if let Some(p) = viewing_key.into_payment_address(
            diversifier,
            params
        )
        {
            payment_address = p;
            break;
        }
    }

    let g_d = payment_address.diversifier.g_d(params).unwrap();
    let commitment_randomness: fs::Fs = rng.gen();
    let auth_path = vec![Some((rng.gen(), rng.gen())); tree_depth];

    {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Spend {
            params: params,
            value_commitment: Some(value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key.clone()),
            payment_address: Some(payment_address.clone()),
            commitment_randomness: Some(commitment_randomness),
            auth_path: auth_path.clone()
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 101550);
        assert_eq!(cs.hash(), "3cc6d9383ca882ae3666267618e826e9d51a3177fc89ef6d42d9f63b84179f77");

        let expected_value_cm = value_commitment.cm(params).into_xy();

        assert_eq!(cs.num_inputs(), 6);
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        assert_eq!(cs.get_input(1, "value commitment/commitment point/x/input variable"), expected_value_cm.0);
        assert_eq!(cs.get_input(2, "value commitment/commitment point/y/input variable"), expected_value_cm.1);

        let note = ::primitives::Note {
            value: value_commitment.value,
            g_d: g_d.clone(),
            pk_d: payment_address.pk_d.clone(),
            r: commitment_randomness.clone()
        };

        let mut position = 0u64;
        let mut cur = note.cm(params);

        assert_eq!(cs.get("randomization of note commitment/x3/num"), cur);

        for (i, val) in auth_path.into_iter().enumerate()
        {
            let (uncle, b) = val.unwrap();

            let mut lhs = cur;
            let mut rhs = uncle;

            if b {
                ::std::mem::swap(&mut lhs, &mut rhs);
            }

            let mut lhs: Vec<bool> = BitIterator::new(lhs.into_repr()).collect();
            let mut rhs: Vec<bool> = BitIterator::new(rhs.into_repr()).collect();

            lhs.reverse();
            rhs.reverse();

            cur = ::pedersen_hash::pedersen_hash::<Bls12, _>(
                ::pedersen_hash::Personalization::MerkleTree(i),
                lhs.into_iter()
                   .take(Fr::NUM_BITS as usize)
                   .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
                params
            ).into_xy().0;

            if b {
                position |= 1 << i;
            }
        }

        let expected_nf = note.nf(&viewing_key, position, params);
        let expected_nf_xy = expected_nf.into_xy();

        assert_eq!(cs.get_input(3, "anchor/input variable"), cur);
        assert_eq!(cs.get_input(4, "nullifier/x/input variable"), expected_nf_xy.0);
        assert_eq!(cs.get_input(5, "nullifier/y/input variable"), expected_nf_xy.1);
    }
}

#[test]
fn test_output_circuit_with_bls12_381() {
    use pairing::{Field};
    use pairing::bls12_381::*;
    use rand::{SeedableRng, Rng, XorShiftRng};
    use ::circuit::test::*;
    use jubjub::{JubjubBls12, fs};

    let params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let value_commitment = ValueCommitment {
        value: rng.gen(),
        randomness: rng.gen()
    };

    let g_d: edwards::Point<Bls12, PrimeOrder> = edwards::Point::rand(rng, params).mul_by_cofactor(params);
    let pk_d: edwards::Point<Bls12, PrimeOrder> = edwards::Point::rand(rng, params).mul_by_cofactor(params);
    let commitment_randomness: fs::Fs = rng.gen();
    let esk: fs::Fs = rng.gen();

    {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Output {
            params: params,
            value_commitment: Some(value_commitment.clone()),
            g_d: Some(g_d.clone()),
            pk_d: Some(pk_d.clone()),
            commitment_randomness: Some(commitment_randomness),
            esk: Some(esk.clone())
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 7827);
        assert_eq!(cs.hash(), "2896f259ad7a50c83604976ee9362358396d547b70f2feaf91d82d287e4ffc1d");

        let expected_cm = ::primitives::Note {
            value: value_commitment.value,
            g_d: g_d.clone(),
            pk_d: pk_d.clone(),
            r: commitment_randomness.clone()
        }.cm(params);

        let expected_value_cm = value_commitment.cm(params).into_xy();

        let expected_epk = g_d.mul(esk, params);
        let expected_epk_xy = expected_epk.into_xy();

        assert_eq!(cs.num_inputs(), 6);
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        assert_eq!(cs.get_input(1, "value commitment/commitment point/x/input variable"), expected_value_cm.0);
        assert_eq!(cs.get_input(2, "value commitment/commitment point/y/input variable"), expected_value_cm.1);
        assert_eq!(cs.get_input(3, "epk/x/input variable"), expected_epk_xy.0);
        assert_eq!(cs.get_input(4, "epk/y/input variable"), expected_epk_xy.1);
        assert_eq!(cs.get_input(5, "commitment/input variable"), expected_cm);
    }
}
