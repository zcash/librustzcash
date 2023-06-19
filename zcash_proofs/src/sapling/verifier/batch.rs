use bellman::groth16;
use bls12_381::Bls12;
use group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};
use zcash_primitives::transaction::components::sapling::{Authorized, Bundle};

use super::SaplingVerificationContextInner;

/// Batch validation context for Sapling.
///
/// This batch-validates Spend and Output proofs, and RedJubjub signatures.
///
/// Signatures are verified assuming ZIP 216 is active.
pub struct BatchValidator {
    bundles_added: bool,
    spend_proofs: groth16::batch::Verifier<Bls12>,
    output_proofs: groth16::batch::Verifier<Bls12>,
    signatures: redjubjub::batch::Verifier,
}

impl Default for BatchValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchValidator {
    /// Constructs a new batch validation context.
    pub fn new() -> Self {
        BatchValidator {
            bundles_added: false,
            spend_proofs: groth16::batch::Verifier::new(),
            output_proofs: groth16::batch::Verifier::new(),
            signatures: redjubjub::batch::Verifier::new(),
        }
    }

    /// Checks the bundle against Sapling-specific consensus rules, and adds its proof and
    /// signatures to the validator.
    ///
    /// Returns `false` if the bundle doesn't satisfy all of the consensus rules. This
    /// `BatchValidator` can continue to be used regardless, but some or all of the proofs
    /// and signatures from this bundle may have already been added to the batch even if
    /// it fails other consensus rules.
    pub fn check_bundle(&mut self, bundle: Bundle<Authorized>, sighash: [u8; 32]) -> bool {
        self.bundles_added = true;

        let mut ctx = SaplingVerificationContextInner::new();

        for spend in bundle.shielded_spends() {
            // Deserialize the proof
            let zkproof = match groth16::Proof::read(&spend.zkproof()[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Check the Spend consensus rules, and batch its proof and spend
            // authorization signature.
            let consensus_rules_passed = ctx.check_spend(
                spend.cv(),
                *spend.anchor(),
                &spend.nullifier().0,
                spend.rk(),
                &sighash,
                spend.spend_auth_sig(),
                zkproof,
                self,
                |this, rk, _, spend_auth_sig| {
                    let rk = redjubjub::VerificationKeyBytes::<redjubjub::SpendAuth>::from(
                        rk.0.to_bytes(),
                    );
                    let spend_auth_sig = {
                        let mut buf = [0; 64];
                        spend_auth_sig.write(&mut buf[..]).unwrap();
                        redjubjub::Signature::<redjubjub::SpendAuth>::from(buf)
                    };

                    this.signatures.queue((rk, spend_auth_sig, &sighash));
                    true
                },
                |this, proof, public_inputs| {
                    this.spend_proofs.queue((proof, public_inputs.to_vec()));
                    true
                },
            );
            if !consensus_rules_passed {
                return false;
            }
        }

        for output in bundle.shielded_outputs() {
            // Deserialize the ephemeral key
            let epk = match jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key().0).into() {
                Some(p) => p,
                None => return false,
            };

            // Deserialize the proof
            let zkproof = match groth16::Proof::read(&output.zkproof()[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Check the Output consensus rules, and batch its proof.
            let consensus_rules_passed = ctx.check_output(
                output.cv(),
                *output.cmu(),
                epk,
                zkproof,
                |proof, public_inputs| {
                    self.output_proofs.queue((proof, public_inputs.to_vec()));
                    true
                },
            );
            if !consensus_rules_passed {
                return false;
            }
        }

        // Check the whole-bundle consensus rules, and batch the binding signature.
        ctx.final_check(
            *bundle.value_balance(),
            &sighash,
            bundle.authorization().binding_sig,
            |bvk, _, binding_sig| {
                let bvk =
                    redjubjub::VerificationKeyBytes::<redjubjub::Binding>::from(bvk.0.to_bytes());
                let binding_sig = {
                    let mut buf = [0; 64];
                    binding_sig.write(&mut buf[..]).unwrap();
                    redjubjub::Signature::<redjubjub::Binding>::from(buf)
                };

                self.signatures.queue((bvk, binding_sig, &sighash));
                true
            },
        )
    }

    /// Batch-validates the accumulated bundles.
    ///
    /// Returns `true` if every proof and signature in every bundle added to the batch
    /// validator is valid, or `false` if one or more are invalid. No attempt is made to
    /// figure out which of the accumulated bundles might be invalid; if that information
    /// is desired, construct separate [`BatchValidator`]s for sub-batches of the bundles.
    pub fn validate<R: RngCore + CryptoRng>(
        self,
        spend_vk: &groth16::VerifyingKey<Bls12>,
        output_vk: &groth16::VerifyingKey<Bls12>,
        mut rng: R,
    ) -> bool {
        if !self.bundles_added {
            // An empty batch is always valid, but is not free to run; skip it.
            return true;
        }

        if let Err(e) = self.signatures.verify(&mut rng) {
            tracing::debug!("Signature batch validation failed: {}", e);
            return false;
        }

        #[cfg(feature = "multicore")]
        let verify_proofs = |batch: groth16::batch::Verifier<Bls12>, vk| batch.verify_multicore(vk);

        #[cfg(not(feature = "multicore"))]
        let mut verify_proofs =
            |batch: groth16::batch::Verifier<Bls12>, vk| batch.verify(&mut rng, vk);

        if verify_proofs(self.spend_proofs, spend_vk).is_err() {
            tracing::debug!("Spend proof batch validation failed");
            return false;
        }

        if verify_proofs(self.output_proofs, output_vk).is_err() {
            tracing::debug!("Output proof batch validation failed");
            return false;
        }

        true
    }
}
