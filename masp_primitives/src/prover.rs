//! Abstractions over the proving system and parameters.

use crate::primitives::{Diversifier, PaymentAddress, ProofGenerationKey, Rseed};

use crate::{
    merkle_tree::MerklePath,
    redjubjub::{PublicKey, Signature},
    sapling::Node,
};
use zcash_primitives::transaction::components::GROTH_PROOF_SIZE;

use crate::asset_type::AssetType;

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
    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        asset_type: AssetType,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ()>;

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
        asset_type: AssetType,
        value: u64,
    ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint);

    /// Create the `bindingSig` for a Sapling transaction. All calls to
    /// [`TxProver::spend_proof`] and [`TxProver::output_proof`] must be completed before
    /// calling this function.
    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        assets_and_values: &[(AssetType, i64)],
        sighash: &[u8; 32],
    ) -> Result<Signature, ()>;
}

#[cfg(test)]
pub(crate) mod mock {
    use ff::Field;
    use rand_core::OsRng;

    use crate::{
        asset_type::AssetType,
        constants::SPENDING_KEY_GENERATOR,
        primitives::{Diversifier, PaymentAddress, ProofGenerationKey, Rseed, ValueCommitment},
    };

    use crate::{
        merkle_tree::MerklePath,
        redjubjub::{PublicKey, Signature},
        sapling::Node,
    };
    use zcash_primitives::transaction::components::GROTH_PROOF_SIZE;

    use super::TxProver;

    pub(crate) struct MockTxProver;

    #[cfg(test)]
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
            asset_type: AssetType,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
        ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ()> {
            let mut rng = OsRng;

            let cv = asset_type
                .value_commitment(value, jubjub::Fr::random(&mut rng))
                .commitment()
                .into();

            let rk = PublicKey(proof_generation_key.ak.clone().into())
                .randomize(ar, SPENDING_KEY_GENERATOR);

            Ok(([0u8; GROTH_PROOF_SIZE], cv, rk))
        }

        fn output_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _esk: jubjub::Fr,
            _payment_address: PaymentAddress,
            _rcm: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
        ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
            let mut rng = OsRng;

            let cv = asset_type
                .value_commitment(value, jubjub::Fr::random(&mut rng))
                .commitment()
                .into();

            ([0u8; GROTH_PROOF_SIZE], cv)
        }

        fn binding_sig(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _assets_and_values: &[(AssetType, i64)],
            _sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            Err(())
        }
    }
}
