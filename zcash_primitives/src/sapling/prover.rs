//! Abstractions over the proving system and parameters.

use crate::{
    sapling::{
        self,
        redjubjub::{PublicKey, Signature},
        value::ValueCommitment,
    },
    transaction::components::{Amount, GROTH_PROOF_SIZE},
};

use super::{Diversifier, PaymentAddress, ProofGenerationKey, Rseed};

/// Interface for creating zero-knowledge proofs for shielded transactions.
pub trait TxProver {
    /// Type for persisting any necessary context across multiple Sapling proofs.
    type SaplingProvingContext;

    /// Instantiate a new Sapling proving context.
    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext;

    /// Create the value commitment, re-randomized key, and proof for a Sapling
    /// [`SpendDescription`], while accumulating its value commitment randomness inside
    /// the context for later use.
    ///
    /// [`SpendDescription`]: crate::transaction::components::SpendDescription
    #[allow(clippy::too_many_arguments)]
    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: sapling::MerklePath,
    ) -> Result<([u8; GROTH_PROOF_SIZE], ValueCommitment, PublicKey), ()>;

    /// Create the value commitment and proof for a Sapling [`OutputDescription`],
    /// while accumulating its value commitment randomness inside the context for later
    /// use.
    ///
    /// [`OutputDescription`]: crate::transaction::components::OutputDescription
    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
    ) -> ([u8; GROTH_PROOF_SIZE], ValueCommitment);

    /// Create the `bindingSig` for a Sapling transaction. All calls to
    /// [`TxProver::spend_proof`] and [`TxProver::output_proof`] must be completed before
    /// calling this function.
    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        value_balance: Amount,
        sighash: &[u8; 32],
    ) -> Result<Signature, ()>;
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod mock {
    use rand_core::OsRng;

    use super::TxProver;
    use crate::{
        constants::SPENDING_KEY_GENERATOR,
        sapling::{
            self,
            redjubjub::{PublicKey, Signature},
            value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
            Diversifier, PaymentAddress, ProofGenerationKey, Rseed,
        },
        transaction::components::{Amount, GROTH_PROOF_SIZE},
    };

    pub struct MockTxProver;

    impl TxProver for MockTxProver {
        type SaplingProvingContext = ();

        fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {}

        fn spend_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            proof_generation_key: ProofGenerationKey,
            _diversifier: Diversifier,
            _rcm: Rseed,
            ar: jubjub::Fr,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: sapling::MerklePath,
        ) -> Result<([u8; GROTH_PROOF_SIZE], ValueCommitment, PublicKey), ()> {
            let mut rng = OsRng;

            let value = NoteValue::from_raw(value);
            let rcv = ValueCommitTrapdoor::random(&mut rng);
            let cv = ValueCommitment::derive(value, rcv);

            let rk =
                PublicKey(proof_generation_key.ak.into()).randomize(ar, SPENDING_KEY_GENERATOR);

            Ok(([0u8; GROTH_PROOF_SIZE], cv, rk))
        }

        fn output_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _esk: jubjub::Fr,
            _payment_address: PaymentAddress,
            _rcm: jubjub::Fr,
            value: u64,
        ) -> ([u8; GROTH_PROOF_SIZE], ValueCommitment) {
            let mut rng = OsRng;

            let value = NoteValue::from_raw(value);
            let rcv = ValueCommitTrapdoor::random(&mut rng);
            let cv = ValueCommitment::derive(value, rcv);

            ([0u8; GROTH_PROOF_SIZE], cv)
        }

        fn binding_sig(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _value_balance: Amount,
            _sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            Err(())
        }
    }
}
