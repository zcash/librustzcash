//! Abstractions over the proving system and parameters.

use rand_core::RngCore;

use crate::{
    sapling::{
        self,
        value::{NoteValue, ValueCommitTrapdoor},
        MerklePath,
    },
    transaction::components::sapling::GrothProofBytes,
};

use super::{Diversifier, PaymentAddress, ProofGenerationKey, Rseed};

/// Interface for creating Sapling Spend proofs.
pub trait SpendProver {
    /// The proof type created by this prover.
    type Proof;

    /// Prepares an instance of the Sapling Spend circuit for the given inputs.
    ///
    /// Returns `None` if `diversifier` is not a valid Sapling diversifier.
    #[allow(clippy::too_many_arguments)]
    fn prepare_circuit(
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        value: NoteValue,
        alpha: jubjub::Fr,
        rcv: ValueCommitTrapdoor,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath,
    ) -> Option<sapling::circuit::Spend>;

    /// Create the proof for a Sapling [`SpendDescription`].
    ///
    /// [`SpendDescription`]: crate::transaction::components::SpendDescription
    fn create_proof<R: RngCore>(
        &self,
        circuit: sapling::circuit::Spend,
        rng: &mut R,
    ) -> Self::Proof;

    /// Encodes the given Sapling [`SpendDescription`] proof, erasing its type.
    ///
    /// [`SpendDescription`]: crate::transaction::components::SpendDescription
    fn encode_proof(proof: Self::Proof) -> GrothProofBytes;
}

/// Interface for creating Sapling Output proofs.
pub trait OutputProver {
    /// The proof type created by this prover.
    type Proof;

    /// Prepares an instance of the Sapling Output circuit for the given inputs.
    ///
    /// Returns `None` if `diversifier` is not a valid Sapling diversifier.
    fn prepare_circuit(
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: NoteValue,
        rcv: ValueCommitTrapdoor,
    ) -> sapling::circuit::Output;

    /// Create the proof for a Sapling [`OutputDescription`].
    ///
    /// [`OutputDescription`]: crate::transaction::components::OutputDescription
    fn create_proof<R: RngCore>(
        &self,
        circuit: sapling::circuit::Output,
        rng: &mut R,
    ) -> Self::Proof;

    /// Encodes the given Sapling [`OutputDescription`] proof, erasing its type.
    ///
    /// [`OutputDescription`]: crate::transaction::components::OutputDescription
    fn encode_proof(proof: Self::Proof) -> GrothProofBytes;
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod mock {
    use ff::Field;

    use super::{OutputProver, SpendProver};
    use crate::{
        sapling::{
            self,
            circuit::ValueCommitmentOpening,
            value::{NoteValue, ValueCommitTrapdoor},
            Diversifier, PaymentAddress, ProofGenerationKey, Rseed,
        },
        transaction::components::{sapling::GrothProofBytes, GROTH_PROOF_SIZE},
    };

    pub struct MockSpendProver;

    impl SpendProver for MockSpendProver {
        type Proof = GrothProofBytes;

        fn prepare_circuit(
            proof_generation_key: ProofGenerationKey,
            diversifier: Diversifier,
            _rseed: Rseed,
            value: NoteValue,
            alpha: jubjub::Fr,
            rcv: ValueCommitTrapdoor,
            anchor: bls12_381::Scalar,
            _merkle_path: sapling::MerklePath,
        ) -> Option<sapling::circuit::Spend> {
            let payment_address = proof_generation_key
                .to_viewing_key()
                .ivk()
                .to_payment_address(diversifier);
            Some(sapling::circuit::Spend {
                value_commitment_opening: Some(ValueCommitmentOpening {
                    value,
                    randomness: rcv.inner(),
                }),
                proof_generation_key: Some(proof_generation_key),
                payment_address,
                commitment_randomness: Some(jubjub::Scalar::ZERO),
                ar: Some(alpha),
                auth_path: vec![],
                anchor: Some(anchor),
            })
        }

        fn create_proof<R: rand_core::RngCore>(
            &self,
            _circuit: sapling::circuit::Spend,
            _rng: &mut R,
        ) -> Self::Proof {
            [0u8; GROTH_PROOF_SIZE]
        }

        fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
            proof
        }
    }

    pub struct MockOutputProver;

    impl OutputProver for MockOutputProver {
        type Proof = GrothProofBytes;

        fn prepare_circuit(
            esk: jubjub::Fr,
            payment_address: PaymentAddress,
            rcm: jubjub::Fr,
            value: NoteValue,
            rcv: ValueCommitTrapdoor,
        ) -> sapling::circuit::Output {
            sapling::circuit::Output {
                value_commitment_opening: Some(ValueCommitmentOpening {
                    value,
                    randomness: rcv.inner(),
                }),
                payment_address: Some(payment_address),
                commitment_randomness: Some(rcm),
                esk: Some(esk),
            }
        }

        fn create_proof<R: rand_core::RngCore>(
            &self,
            _circuit: sapling::circuit::Output,
            _rng: &mut R,
        ) -> Self::Proof {
            [0u8; GROTH_PROOF_SIZE]
        }

        fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
            proof
        }
    }
}
