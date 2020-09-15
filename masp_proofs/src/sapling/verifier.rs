use bellman::{
    gadgets::multipack,
    groth16::{verify_proof, PreparedVerifyingKey, Proof},
};
use bls12_381::Bls12;
use group::{Curve, GroupEncoding};
use masp_primitives::{
    asset_type::AssetType,
    constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
    redjubjub::{PublicKey, Signature},
};

use super::masp_compute_value_balance;

/// A context object for verifying the Sapling components of a Zcash transaction.
pub struct SaplingVerificationContext {
    // (sum of the Spend value commitments) - (sum of the Output value commitments)
    cv_sum: jubjub::ExtendedPoint,
}

impl SaplingVerificationContext {
    /// Construct a new context to be used with a single transaction.
    pub fn new() -> Self {
        SaplingVerificationContext {
            cv_sum: jubjub::ExtendedPoint::identity(),
        }
    }

    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    pub fn check_spend(
        &mut self,
        cv: jubjub::ExtendedPoint,
        anchor: bls12_381::Scalar,
        nullifier: &[u8; 32],
        rk: PublicKey,
        sighash_value: &[u8; 32],
        spend_auth_sig: Signature,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        if (cv.is_small_order() | rk.0.is_small_order()).into() {
            return false;
        }

        // Accumulate the value commitment in the context
        self.cv_sum += cv;

        // Grab the nullifier as a sequence of bytes
        let nullifier = &nullifier[..];

        // Compute the signature's message for rk/spend_auth_sig
        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0..32].copy_from_slice(&rk.0.to_bytes());
        (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash_value[..]);

        // Verify the spend_auth_sig
        if !rk.verify(&data_to_be_signed, &spend_auth_sig, SPENDING_KEY_GENERATOR) {
            return false;
        }

        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::zero(); 7];
        {
            let affine = rk.0.to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[0] = u;
            public_input[1] = v;
        }
        {
            let affine = cv.to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[2] = u;
            public_input[3] = v;
        }
        public_input[4] = anchor;

        // Add the nullifier through multiscalar packing
        {
            let nullifier = multipack::bytes_to_bits_le(nullifier);
            let nullifier = multipack::compute_multipacking(&nullifier);

            assert_eq!(nullifier.len(), 2);

            public_input[5] = nullifier[0];
            public_input[6] = nullifier[1];
        }

        // Verify the proof
        verify_proof(verifying_key, &zkproof, &public_input[..]).is_ok()
    }

    /// Perform consensus checks on a Sapling OutputDescription, while
    /// accumulating its value commitment inside the context for later use.
    pub fn check_output(
        &mut self,
        cv: jubjub::ExtendedPoint,
        cmu: bls12_381::Scalar,
        epk: jubjub::ExtendedPoint,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        if (cv.is_small_order() | epk.is_small_order()).into() {
            return false;
        }

        // Accumulate the value commitment in the context
        self.cv_sum -= cv;

        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::zero(); 5];
        {
            let affine = cv.to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[0] = u;
            public_input[1] = v;
        }
        {
            let affine = epk.to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[2] = u;
            public_input[3] = v;
        }
        public_input[4] = cmu;

        // Verify the proof
        verify_proof(verifying_key, &zkproof, &public_input[..]).is_ok()
    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    pub fn final_check(
        &self,
        assets_and_values: &[(AssetType, i64)],
        sighash_value: &[u8; 32],
        binding_sig: Signature,
    ) -> bool {
        // Obtain current cv_sum from the context
        let mut bvk = PublicKey(self.cv_sum.clone());

        // Compute value balance
        let value_balances = assets_and_values
            .iter()
            .map(|(asset_type, value_balance)| {
                // Compute value balance for each asset
                // Error for bad value balances (-INT64_MAX value)
                masp_compute_value_balance(*asset_type, *value_balance).ok_or(())
            })
            .collect::<Result<Vec<_>, _>>();

        bvk.0 = match value_balances {
            Ok(vb) => vb.iter().fold(bvk.0, |tmp, value_balance| {
                // Compute cv_sum minus sum of all value balances
                tmp - value_balance
            }),
            Err(_) => return false,
        };

        // Compute the signature's message for bvk/binding_sig
        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
        (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash_value[..]);

        // Verify the binding_sig
        bvk.verify(
            &data_to_be_signed,
            &binding_sig,
            VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        )
    }
}
