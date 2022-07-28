use bellman::{
    gadgets::multipack,
    groth16::{create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof},
};
use bls12_381::Bls12;
use ff::Field;
use group::{Curve, GroupEncoding};
use rand_core::OsRng;
use std::ops::{AddAssign, Neg};
use zcash_primitives::{
    constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
    merkle_tree::MerklePath,
    sapling::{
        redjubjub::{PrivateKey, PublicKey, Signature},
        Diversifier, Node, Note, PaymentAddress, ProofGenerationKey, Rseed, ValueCommitment,
    },
    transaction::components::Amount,
};

use super::compute_value_balance;
use crate::circuit::sapling::{Output, Spend};

/// A context object for creating the Sapling components of a Zcash transaction.
pub struct SaplingProvingContext {
    bsk: jubjub::Fr,
    // (sum of the Spend value commitments) - (sum of the Output value commitments)
    cv_sum: jubjub::ExtendedPoint,
}

impl Default for SaplingProvingContext {
    fn default() -> Self {
        SaplingProvingContext::new()
    }
}

impl SaplingProvingContext {
    /// Construct a new context to be used with a single transaction.
    pub fn new() -> Self {
        SaplingProvingContext {
            bsk: jubjub::Fr::zero(),
            cv_sum: jubjub::ExtendedPoint::identity(),
        }
    }

    /// Create the value commitment, re-randomized key, and proof for a Sapling
    /// SpendDescription, while accumulating its value commitment randomness
    /// inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn spend_proof(
        &mut self,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
        proving_key: &Parameters<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> Result<(Proof<Bls12>, jubjub::ExtendedPoint, PublicKey), ()> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // We create the randomness of the value commitment
        let rcv = jubjub::Fr::random(&mut rng);

        // Accumulate the value commitment randomness in the context
        {
            let mut tmp = rcv;
            tmp.add_assign(&self.bsk);

            // Update the context
            self.bsk = tmp;
        }

        // Construct the value commitment
        let value_commitment = ValueCommitment {
            value,
            randomness: rcv,
        };

        // Construct the viewing key
        let viewing_key = proof_generation_key.to_viewing_key();

        // Construct the payment address with the viewing key / diversifier
        let payment_address = viewing_key.to_payment_address(diversifier).ok_or(())?;

        // This is the result of the re-randomization, we compute it for the caller
        let rk = PublicKey(proof_generation_key.ak.into()).randomize(ar, SPENDING_KEY_GENERATOR);

        // Let's compute the nullifier while we have the position
        let note = Note {
            value,
            g_d: diversifier.g_d().expect("was a valid diversifier before"),
            pk_d: *payment_address.pk_d(),
            rseed,
        };

        let nullifier = note.nf(&viewing_key, merkle_path.position);

        // We now have the full witness for our circuit
        let instance = Spend {
            value_commitment: Some(value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key),
            payment_address: Some(payment_address),
            commitment_randomness: Some(note.rcm()),
            ar: Some(ar),
            auth_path: merkle_path
                .auth_path
                .iter()
                .map(|(node, b)| Some(((*node).into(), *b)))
                .collect(),
            anchor: Some(anchor),
        };

        // Create proof
        let proof =
            create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

        // Try to verify the proof:
        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::zero(); 7];
        {
            let affine = rk.0.to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[0] = u;
            public_input[1] = v;
        }
        {
            let affine = jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[2] = u;
            public_input[3] = v;
        }
        public_input[4] = anchor;

        // Add the nullifier through multiscalar packing
        {
            let nullifier = multipack::bytes_to_bits_le(&nullifier.0);
            let nullifier = multipack::compute_multipacking(&nullifier);

            assert_eq!(nullifier.len(), 2);

            public_input[5] = nullifier[0];
            public_input[6] = nullifier[1];
        }

        // Verify the proof
        verify_proof(verifying_key, &proof, &public_input[..]).map_err(|_| ())?;

        // Compute value commitment
        let value_commitment: jubjub::ExtendedPoint = value_commitment.commitment().into();

        // Accumulate the value commitment in the context
        self.cv_sum += value_commitment;

        Ok((proof, value_commitment, rk))
    }

    /// Create the value commitment and proof for a Sapling OutputDescription,
    /// while accumulating its value commitment randomness inside the context
    /// for later use.
    pub fn output_proof(
        &mut self,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
        proving_key: &Parameters<Bls12>,
    ) -> (Proof<Bls12>, jubjub::ExtendedPoint) {
        // Initialize secure RNG
        let mut rng = OsRng;

        // We construct ephemeral randomness for the value commitment. This
        // randomness is not given back to the caller, but the synthetic
        // blinding factor `bsk` is accumulated in the context.
        let rcv = jubjub::Fr::random(&mut rng);

        // Accumulate the value commitment randomness in the context
        {
            let mut tmp = rcv.neg(); // Outputs subtract from the total.
            tmp.add_assign(&self.bsk);

            // Update the context
            self.bsk = tmp;
        }

        // Construct the value commitment for the proof instance
        let value_commitment = ValueCommitment {
            value,
            randomness: rcv,
        };

        // We now have a full witness for the output proof.
        let instance = Output {
            value_commitment: Some(value_commitment.clone()),
            payment_address: Some(payment_address),
            commitment_randomness: Some(rcm),
            esk: Some(esk),
        };

        // Create proof
        let proof =
            create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

        // Compute the actual value commitment
        let value_commitment: jubjub::ExtendedPoint = value_commitment.commitment().into();

        // Accumulate the value commitment in the context. We do this to check internal consistency.
        self.cv_sum -= value_commitment; // Outputs subtract from the total.

        (proof, value_commitment)
    }

    /// Create the bindingSig for a Sapling transaction. All calls to spend_proof()
    /// and output_proof() must be completed before calling this function.
    pub fn binding_sig(&self, value_balance: Amount, sighash: &[u8; 32]) -> Result<Signature, ()> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // Grab the current `bsk` from the context
        let bsk = PrivateKey(self.bsk);

        // Grab the `bvk` using DerivePublic.
        let bvk = PublicKey::from_private(&bsk, VALUE_COMMITMENT_RANDOMNESS_GENERATOR);

        // In order to check internal consistency, let's use the accumulated value
        // commitments (as the verifier would) and apply value_balance to compare
        // against our derived bvk.
        {
            // Compute value balance
            let value_balance = compute_value_balance(value_balance).ok_or(())?;

            // Subtract value_balance from cv_sum to get final bvk
            let final_bvk = self.cv_sum - value_balance;

            // The result should be the same, unless the provided valueBalance is wrong.
            if bvk.0 != final_bvk {
                return Err(());
            }
        }

        // Construct signature message
        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
        (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash[..]);

        // Sign
        Ok(bsk.sign(
            &data_to_be_signed,
            &mut rng,
            VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        ))
    }
}
