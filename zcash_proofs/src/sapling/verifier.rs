use bellman::{gadgets::multipack, groth16::Proof};
use bls12_381::Bls12;
use group::{Curve, GroupEncoding};
use zcash_primitives::{
    sapling::redjubjub::{PublicKey, Signature},
    transaction::components::Amount,
};

use super::compute_value_balance;

mod single;
pub use single::SaplingVerificationContext;

mod batch;
pub use batch::BatchValidator;

/// A context object for verifying the Sapling components of a Zcash transaction.
struct SaplingVerificationContextInner {
    // (sum of the Spend value commitments) - (sum of the Output value commitments)
    cv_sum: jubjub::ExtendedPoint,
}

impl SaplingVerificationContextInner {
    /// Construct a new context to be used with a single transaction.
    fn new() -> Self {
        SaplingVerificationContextInner {
            cv_sum: jubjub::ExtendedPoint::identity(),
        }
    }

    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    fn check_spend<C>(
        &mut self,
        cv: jubjub::ExtendedPoint,
        anchor: bls12_381::Scalar,
        nullifier: &[u8; 32],
        rk: PublicKey,
        sighash_value: &[u8; 32],
        spend_auth_sig: Signature,
        zkproof: Proof<Bls12>,
        verifier_ctx: &mut C,
        spend_auth_sig_verifier: impl FnOnce(&mut C, PublicKey, [u8; 64], Signature) -> bool,
        proof_verifier: impl FnOnce(&mut C, Proof<Bls12>, [bls12_381::Scalar; 7]) -> bool,
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
        let rk_affine = rk.0.to_affine();
        if !spend_auth_sig_verifier(verifier_ctx, rk, data_to_be_signed, spend_auth_sig) {
            return false;
        }

        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::zero(); 7];
        {
            let affine = rk_affine;
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
        proof_verifier(verifier_ctx, zkproof, public_input)
    }

    /// Perform consensus checks on a Sapling OutputDescription, while
    /// accumulating its value commitment inside the context for later use.
    fn check_output(
        &mut self,
        cv: jubjub::ExtendedPoint,
        cmu: bls12_381::Scalar,
        epk: jubjub::ExtendedPoint,
        zkproof: Proof<Bls12>,
        proof_verifier: impl FnOnce(Proof<Bls12>, [bls12_381::Scalar; 5]) -> bool,
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
        proof_verifier(zkproof, public_input)
    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    fn final_check(
        &self,
        value_balance: Amount,
        sighash_value: &[u8; 32],
        binding_sig: Signature,
        binding_sig_verifier: impl FnOnce(PublicKey, [u8; 64], Signature) -> bool,
    ) -> bool {
        // Obtain current cv_sum from the context
        let mut bvk = PublicKey(self.cv_sum);

        // Compute value balance
        let value_balance = match compute_value_balance(value_balance) {
            Some(a) => a,
            None => return false,
        };

        // Subtract value_balance from current cv_sum to get final bvk
        bvk.0 -= value_balance;

        // Compute the signature's message for bvk/binding_sig
        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
        (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash_value[..]);

        // Verify the binding_sig
        binding_sig_verifier(bvk, data_to_be_signed, binding_sig)
    }
}
