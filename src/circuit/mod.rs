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
    Unknown,
    FixedGenerators,
    edwards
};

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

pub struct Spend<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    /// Value of the note being spent
    pub value: Option<u64>,
    /// Randomness that will hide the value
    pub value_randomness: Option<E::Fs>,
    /// Key which allows the proof to be constructed
    /// as defense-in-depth against a flaw in the
    /// protocol that would otherwise be exploitable
    /// by a holder of a viewing key.
    pub rsk: Option<E::Fs>,
    /// The public key that will be re-randomized for
    /// use as a nullifier and signing key for the
    /// transaction.
    pub ak: Option<edwards::Point<E, Unknown>>,
    /// The diversified base used to compute pk_d.
    pub g_d: Option<edwards::Point<E, Unknown>>,
    /// The randomness used to hide the note commitment data
    pub commitment_randomness: Option<E::Fs>,
    /// The authentication path of the commitment in the tree
    pub auth_path: Vec<Option<(E::Fr, bool)>>
}

impl<'a, E: JubjubEngine> Circuit<E> for Spend<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        // Booleanize the value into little-endian bit order
        let value_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value"),
            self.value
        )?;

        {
            let gv = ecc::fixed_base_multiplication(
                cs.namespace(|| "compute the value in the exponent"),
                FixedGenerators::ValueCommitmentValue,
                &value_bits,
                self.params
            )?;
        
            // Booleanize the randomness
            let hr = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "hr"),
                self.value_randomness
            )?;

            let hr = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of randomization for value commitment"),
                FixedGenerators::ValueCommitmentRandomness,
                &hr,
                self.params
            )?;

            let gvhr = gv.add(
                cs.namespace(|| "computation of value commitment"),
                &hr,
                self.params
            )?;

            gvhr.inputize(cs.namespace(|| "value commitment"))?;
        }

        // Compute rk = [rsk] ProvingPublicKey
        let rk;
        {
            // Witness rsk as bits
            let rsk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rsk"),
                self.rsk
            )?;

            // NB: We don't ensure that the bit representation of rsk
            // is "in the field" (Fs) because it's not used except to
            // demonstrate the prover knows it. If they know a
            // congruency then that's equivalent.

            rk = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of rk"),
                FixedGenerators::ProvingPublicKey,
                &rsk,
                self.params
            )?;
        }

        // Prover witnesses ak (ensures that it's on the curve)
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.ak,
            self.params
        )?;

        // Unpack ak and rk for input to BLAKE2s
        let mut vk = vec![];
        let mut rho_preimage = vec![];
        vk.extend(
            ak.repr(cs.namespace(|| "representation of ak"))?
        );
        {
            let repr_rk = rk.repr(
                cs.namespace(|| "representation of rk")
            )?;

            vk.extend(repr_rk.iter().cloned());
            rho_preimage.extend(repr_rk);
        }

        assert_eq!(vk.len(), 512);

        // Compute the incoming viewing key
        let mut ivk = blake2s::blake2s(
            cs.namespace(|| "computation of ivk"),
            &vk
        )?;

        // Little endian bit order
        ivk.reverse();
        ivk.truncate(E::Fs::CAPACITY as usize); // drop_5

        // Witness g_d
        let g_d = ecc::EdwardsPoint::witness(
            cs.namespace(|| "witness g_d"),
            self.g_d,
            self.params
        )?;

        // Compute pk_d
        let pk_d = g_d.mul(
            cs.namespace(|| "compute pk_d"),
            &ivk,
            self.params
        )?;

        // Compute note contents
        let mut note_contents = vec![];
        note_contents.extend(value_bits);
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
            // Booleanize the randomness
            let cmr = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "cmr"),
                self.commitment_randomness
            )?;

            let cmr = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                FixedGenerators::NoteCommitmentRandomness,
                &cmr,
                self.params
            )?;

            cm = cm.add(
                cs.namespace(|| "randomization of note commitment"),
                &cmr,
                self.params
            )?;
        }

        let tree_depth = self.auth_path.len();

        let mut position_bits = vec![];

        // Injective encoding.
        let mut cur = cm.x.clone();

        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1)
            )?);

            position_bits.push(cur_is_right.clone());

            let path_element = num::AllocatedNum::alloc(
                cs.namespace(|| "path element"),
                || {
                    Ok(e.get()?.0)
                }
            )?;

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

            cur = pedersen_hash::pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                pedersen_hash::Personalization::MerkleTree(tree_depth - i),
                &preimage,
                self.params
            )?.x; // Injective encoding
        }

        assert_eq!(position_bits.len(), tree_depth);

        // Expose the anchor
        cur.inputize(cs.namespace(|| "anchor"))?;

        {
            let position = ecc::fixed_base_multiplication(
                cs.namespace(|| "g^position"),
                FixedGenerators::NullifierPosition,
                &position_bits,
                self.params
            )?;

            cm = cm.add(
                cs.namespace(|| "faerie gold prevention"),
                &position,
                self.params
            )?;
        }
        
        // Let's compute rho = BLAKE2s(rk || cm + position)
        rho_preimage.extend(
            cm.repr(cs.namespace(|| "representation of cm"))?
        );

        assert_eq!(rho_preimage.len(), 512);
        
        let mut rho = blake2s::blake2s(
            cs.namespace(|| "rho computation"),
            &rho_preimage
        )?;

        // Little endian bit order
        rho.reverse();
        rho.truncate(E::Fs::CAPACITY as usize); // drop_5

        // Compute nullifier
        let nf = ak.mul(
            cs.namespace(|| "computation of nf"),
            &rho,
            self.params
        )?;

        nf.inputize(cs.namespace(|| "nullifier"))?;

        Ok(())
    }
}

/// This is an output circuit instance.
pub struct Output<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    /// Value of the note being created
    pub value: Option<u64>,
    /// Randomness that will hide the value
    pub value_randomness: Option<E::Fs>,
    /// The diversified base, computed by GH(d)
    pub g_d: Option<edwards::Point<E, Unknown>>,
    /// The diversified address point, computed by GH(d)^ivk
    pub p_d: Option<edwards::Point<E, Unknown>>,
    /// The randomness used to hide the note commitment data
    pub commitment_randomness: Option<E::Fs>,
    /// The ephemeral secret key for DH with recipient
    pub esk: Option<E::Fs>
}

impl<'a, E: JubjubEngine> Circuit<E> for Output<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        // Booleanize the value into little-endian bit order
        let value_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "value"),
            self.value
        )?;

        {
            let gv = ecc::fixed_base_multiplication(
                cs.namespace(|| "compute the value in the exponent"),
                FixedGenerators::ValueCommitmentValue,
                &value_bits,
                self.params
            )?;
        
            // Booleanize the randomness
            let hr = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "hr"),
                self.value_randomness
            )?;

            let hr = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of randomization for value commitment"),
                FixedGenerators::ValueCommitmentRandomness,
                &hr,
                self.params
            )?;

            let gvhr = gv.add(
                cs.namespace(|| "computation of value commitment"),
                &hr,
                self.params
            )?;

            gvhr.inputize(cs.namespace(|| "value commitment"))?;
        }

        // Let's start to construct our note
        let mut note_contents = vec![];
        note_contents.extend(value_bits);

        // Let's deal with g_d
        {
            let g_d = ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.g_d,
                self.params
            )?;

            // Check that g_d is not of small order
            {
                let g_d = g_d.double(
                    cs.namespace(|| "first doubling of g_d"),
                    self.params
                )?;
                let g_d = g_d.double(
                    cs.namespace(|| "second doubling of g_d"),
                    self.params
                )?;
                let g_d = g_d.double(
                    cs.namespace(|| "third doubling of g_d"),
                    self.params
                )?;

                // (0, -1) is a small order point, but won't ever appear here
                // because cofactor is 2^3, and we performed three doublings.
                // (0, 1) is the neutral element, so checking if x is nonzero
                // is sufficient to prevent small order points here.
                g_d.x.assert_nonzero(cs.namespace(|| "check not inf"))?;
            }

            note_contents.extend(
                g_d.repr(cs.namespace(|| "representation of g_d"))?
            );

            // Compute epk from esk
            let esk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "esk"),
                self.esk
            )?;

            let epk = g_d.mul(
                cs.namespace(|| "epk computation"),
                &esk,
                self.params
            )?;

            epk.inputize(cs.namespace(|| "epk"))?;
        }

        // Now let's deal with p_d. We don't do any checks and
        // essentially allow the prover to witness any 256 bits
        // they would like.
        {
            let p_d = self.p_d.map(|e| e.into_xy());

            let y_contents = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "p_d bits of y"),
                p_d.map(|e| e.1)
            )?;

            let sign_bit = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "p_d bit of x"),
                p_d.map(|e| e.0.into_repr().is_odd())
            )?);

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

            let cmr = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                FixedGenerators::NoteCommitmentRandomness,
                &cmr,
                self.params
            )?;

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
        cm.x.inputize(cs.namespace(|| "commitment"))?;

        Ok(())
    }
}

#[test]
fn test_input_circuit_with_bls12_381() {
    use pairing::bls12_381::*;
    use rand::{SeedableRng, Rng, XorShiftRng};
    use ::circuit::test::*;
    use jubjub::{JubjubBls12, fs};

    let params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let tree_depth = 29;

    let value: u64 = 1;
    let value_randomness: fs::Fs = rng.gen();
    let ak: edwards::Point<Bls12, Unknown> = edwards::Point::rand(rng, params);
    let g_d: edwards::Point<Bls12, Unknown> = edwards::Point::rand(rng, params);
    let commitment_randomness: fs::Fs = rng.gen();
    let rsk: fs::Fs = rng.gen();
    let auth_path = vec![Some((rng.gen(), rng.gen())); tree_depth];

    {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Spend {
            params: params,
            value: Some(value),
            value_randomness: Some(value_randomness),
            rsk: Some(rsk),
            ak: Some(ak),
            g_d: Some(g_d),
            commitment_randomness: Some(commitment_randomness),
            auth_path: auth_path
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 97379);
        assert_eq!(cs.hash(), "cae701c7acd6fee80b8dfc547855f44dcb3eb6cf64e434afa8c77a93bafd9d0e");
    }
}

#[test]
fn test_output_circuit_with_bls12_381() {
    use pairing::bls12_381::*;
    use rand::{SeedableRng, Rng, XorShiftRng};
    use ::circuit::test::*;
    use jubjub::{JubjubBls12, fs};

    let params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let value: u64 = 1;
    let value_randomness: fs::Fs = rng.gen();
    let g_d: edwards::Point<Bls12, Unknown> = edwards::Point::rand(rng, params);
    let p_d: edwards::Point<Bls12, Unknown> = edwards::Point::rand(rng, params);
    let commitment_randomness: fs::Fs = rng.gen();
    let esk: fs::Fs = rng.gen();

    {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Output {
            params: params,
            value: Some(value),
            value_randomness: Some(value_randomness),
            g_d: Some(g_d.clone()),
            p_d: Some(p_d.clone()),
            commitment_randomness: Some(commitment_randomness),
            esk: Some(esk.clone())
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 7827);
        assert_eq!(cs.hash(), "f9c01583d089117e01ee5d0dcc8d8d0d1f6c4af0a420a9981a5af9a572df26f1");
    }
}
