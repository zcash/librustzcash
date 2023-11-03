use bellman::groth16::{create_random_proof, Proof};
use bls12_381::Bls12;
use rand_core::RngCore;
use zcash_primitives::{
    sapling::{
        circuit::{Output, Spend, ValueCommitmentOpening},
        prover::{OutputProver, SpendProver},
        value::{NoteValue, ValueCommitTrapdoor},
        Diversifier, MerklePath, Note, PaymentAddress, ProofGenerationKey, Rseed,
    },
    transaction::components::{sapling::GrothProofBytes, GROTH_PROOF_SIZE},
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
            value,
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
            value,
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
