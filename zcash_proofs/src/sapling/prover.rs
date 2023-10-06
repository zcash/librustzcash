use bellman::groth16::{create_random_proof, Proof};
use bls12_381::Bls12;
use group::GroupEncoding;
use rand_core::{OsRng, RngCore};
use zcash_primitives::{
    sapling::{
        circuit::{Output, Spend, ValueCommitmentOpening},
        constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
        prover::{OutputProver, SpendProver},
        redjubjub::{PublicKey, Signature},
        value::{CommitmentSum, NoteValue, TrapdoorSum, ValueCommitTrapdoor, ValueCommitment},
        Diversifier, MerklePath, Note, PaymentAddress, ProofGenerationKey, Rseed,
    },
    transaction::components::{sapling::GrothProofBytes, Amount, GROTH_PROOF_SIZE},
};

use crate::{OutputParameters, SpendParameters};

impl SpendProver for SpendParameters {
    type Proof = Proof<Bls12>;

    fn prepare_circuit(
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        value: NoteValue,
        alpha: jubjub::Fr,
        rcv: ValueCommitTrapdoor,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath,
    ) -> Option<Spend> {
        // Construct the value commitment
        let value_commitment_opening = ValueCommitmentOpening {
            value: value.inner(),
            randomness: rcv.inner(),
        };

        // Construct the viewing key
        let viewing_key = proof_generation_key.to_viewing_key();

        // Construct the payment address with the viewing key / diversifier
        let payment_address = viewing_key.to_payment_address(diversifier)?;

        let note = Note::from_parts(payment_address, value, rseed);

        // We now have the full witness for our circuit
        let pos: u64 = merkle_path.position().into();
        Some(Spend {
            value_commitment_opening: Some(value_commitment_opening),
            proof_generation_key: Some(proof_generation_key),
            payment_address: Some(payment_address),
            commitment_randomness: Some(note.rcm()),
            ar: Some(alpha),
            auth_path: merkle_path
                .path_elems()
                .iter()
                .enumerate()
                .map(|(i, node)| Some(((*node).into(), pos >> i & 0x1 == 1)))
                .collect(),
            anchor: Some(anchor),
        })
    }

    fn create_proof<R: RngCore>(&self, circuit: Spend, rng: &mut R) -> Self::Proof {
        create_random_proof(circuit, &self.0, rng).expect("proving should not fail")
    }

    fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");
        zkproof
    }
}

impl OutputProver for OutputParameters {
    type Proof = Proof<Bls12>;

    fn prepare_circuit(
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: NoteValue,
        rcv: ValueCommitTrapdoor,
    ) -> Output {
        // Construct the value commitment for the proof instance
        let value_commitment_opening = ValueCommitmentOpening {
            value: value.inner(),
            randomness: rcv.inner(),
        };

        // We now have a full witness for the output proof.
        Output {
            value_commitment_opening: Some(value_commitment_opening),
            payment_address: Some(payment_address),
            commitment_randomness: Some(rcm),
            esk: Some(esk),
        }
    }

    fn create_proof<R: RngCore>(&self, circuit: Output, rng: &mut R) -> Self::Proof {
        create_random_proof(circuit, &self.0, rng).expect("proving should not fail")
    }

    fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");
        zkproof
    }
}

/// A context object for creating the Sapling components of a Zcash transaction.
pub struct SaplingProvingContext {
    bsk: TrapdoorSum,
    // (sum of the Spend value commitments) - (sum of the Output value commitments)
    cv_sum: CommitmentSum,
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
            bsk: TrapdoorSum::zero(),
            cv_sum: CommitmentSum::zero(),
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
        merkle_path: MerklePath,
        proving_key: &SpendParameters,
    ) -> Result<(Proof<Bls12>, ValueCommitment, PublicKey), ()> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // We create the randomness of the value commitment
        let rcv = ValueCommitTrapdoor::random(&mut rng);

        // Accumulate the value commitment randomness in the context
        self.bsk += &rcv;

        // Construct the value commitment
        let value = NoteValue::from_raw(value);
        let value_commitment = ValueCommitment::derive(value, rcv.clone());

        // This is the result of the re-randomization, we compute it for the caller
        let rk = PublicKey(proof_generation_key.ak.into()).randomize(ar, SPENDING_KEY_GENERATOR);

        let instance = SpendParameters::prepare_circuit(
            proof_generation_key,
            diversifier,
            rseed,
            value,
            ar,
            rcv,
            anchor,
            merkle_path,
        )
        .ok_or(())?;

        // Create proof
        let proof = proving_key.create_proof(instance, &mut rng);

        // Accumulate the value commitment in the context
        self.cv_sum += &value_commitment;

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
        proving_key: &OutputParameters,
    ) -> (Proof<Bls12>, ValueCommitment) {
        // Initialize secure RNG
        let mut rng = OsRng;

        // We construct ephemeral randomness for the value commitment. This
        // randomness is not given back to the caller, but the synthetic
        // blinding factor `bsk` is accumulated in the context.
        let rcv = ValueCommitTrapdoor::random(&mut rng);

        // Accumulate the value commitment randomness in the context
        self.bsk -= &rcv; // Outputs subtract from the total.

        // Construct the value commitment for the proof instance
        let value = NoteValue::from_raw(value);
        let value_commitment = ValueCommitment::derive(value, rcv.clone());

        // We now have a full witness for the output proof.
        let instance = OutputParameters::prepare_circuit(esk, payment_address, rcm, value, rcv);

        // Create proof
        let proof = proving_key.create_proof(instance, &mut rng);

        // Accumulate the value commitment in the context. We do this to check internal consistency.
        self.cv_sum -= &value_commitment; // Outputs subtract from the total.

        (proof, value_commitment)
    }

    /// Create the bindingSig for a Sapling transaction. All calls to spend_proof()
    /// and output_proof() must be completed before calling this function.
    pub fn binding_sig(&self, value_balance: Amount, sighash: &[u8; 32]) -> Result<Signature, ()> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // Grab the current `bsk` from the context
        let bsk = self.bsk.into_bsk();

        // Grab the `bvk` using DerivePublic.
        let bvk = PublicKey::from_private(&bsk, VALUE_COMMITMENT_RANDOMNESS_GENERATOR);

        // In order to check internal consistency, let's use the accumulated value
        // commitments (as the verifier would) and apply value_balance to compare
        // against our derived bvk.
        {
            // Compute the final bvk.
            let final_bvk = self.cv_sum.into_bvk(value_balance);

            // The result should be the same, unless the provided valueBalance is wrong.
            if bvk.0 != final_bvk.0 {
                return Err(());
            }
        }

        // Construct signature message
        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
        data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

        // Sign
        Ok(bsk.sign(
            &data_to_be_signed,
            &mut rng,
            VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        ))
    }
}
