use bellman::groth16::{verify_proof, PreparedVerifyingKey, Proof};
use bls12_381::Bls12;
use zcash_primitives::{
    constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
    sapling::{
        note::ExtractedNoteCommitment,
        redjubjub::{PublicKey, Signature},
        value::ValueCommitment,
    },
    transaction::components::Amount,
};

use super::SaplingVerificationContextInner;

/// A context object for verifying the Sapling components of a single Zcash transaction.
pub struct SaplingVerificationContext {
    inner: SaplingVerificationContextInner,
    zip216_enabled: bool,
}

impl SaplingVerificationContext {
    /// Construct a new context to be used with a single transaction.
    pub fn new(zip216_enabled: bool) -> Self {
        SaplingVerificationContext {
            inner: SaplingVerificationContextInner::new(),
            zip216_enabled,
        }
    }

    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn check_spend(
        &mut self,
        cv: &ValueCommitment,
        anchor: bls12_381::Scalar,
        nullifier: &[u8; 32],
        rk: PublicKey,
        sighash_value: &[u8; 32],
        spend_auth_sig: Signature,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        let zip216_enabled = self.zip216_enabled;
        self.inner.check_spend(
            cv,
            anchor,
            nullifier,
            &rk,
            sighash_value,
            &spend_auth_sig,
            zkproof,
            &mut (),
            |_, rk, msg, spend_auth_sig| {
                rk.verify_with_zip216(&msg, spend_auth_sig, SPENDING_KEY_GENERATOR, zip216_enabled)
            },
            |_, proof, public_inputs| {
                verify_proof(verifying_key, &proof, &public_inputs[..]).is_ok()
            },
        )
    }

    /// Perform consensus checks on a Sapling OutputDescription, while
    /// accumulating its value commitment inside the context for later use.
    pub fn check_output(
        &mut self,
        cv: &ValueCommitment,
        cmu: ExtractedNoteCommitment,
        epk: jubjub::ExtendedPoint,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        self.inner
            .check_output(cv, cmu, epk, zkproof, |proof, public_inputs| {
                verify_proof(verifying_key, &proof, &public_inputs[..]).is_ok()
            })
    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    pub fn final_check(
        &self,
        value_balance: Amount,
        sighash_value: &[u8; 32],
        binding_sig: Signature,
    ) -> bool {
        self.inner.final_check(
            value_balance,
            sighash_value,
            binding_sig,
            |bvk, msg, binding_sig| {
                bvk.verify_with_zip216(
                    &msg,
                    &binding_sig,
                    VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
                    self.zip216_enabled,
                )
            },
        )
    }
}
