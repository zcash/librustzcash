//! Abstractions over the proving system and parameters for ease of use.

use bellman::groth16::Proof;
use bls12_381::Bls12;
use std::path::Path;

use sapling::{
    bundle::GrothProofBytes,
    prover::{OutputProver, SpendProver},
    value::{NoteValue, ValueCommitTrapdoor},
    Diversifier, MerklePath, PaymentAddress, ProofGenerationKey, Rseed,
};
use zcash_primitives::transaction::components::GROTH_PROOF_SIZE;

use crate::{load_parameters, parse_parameters, OutputParameters, SpendParameters};

#[cfg(feature = "local-prover")]
use crate::{default_params_folder, SAPLING_OUTPUT_NAME, SAPLING_SPEND_NAME};

/// An implementation of [`SpendProver`] and [`OutputProver`] using Sapling Spend and
/// Output parameters from locally-accessible paths.
pub struct LocalTxProver {
    spend_params: SpendParameters,
    output_params: OutputParameters,
}

impl LocalTxProver {
    /// Creates a `LocalTxProver` using parameters from the given local paths.
    ///
    /// # Examples
    ///
    /// ```should_panic
    /// use std::path::Path;
    /// use zcash_proofs::prover::LocalTxProver;
    ///
    /// let tx_prover = LocalTxProver::new(
    ///     Path::new("/path/to/sapling-spend.params"),
    ///     Path::new("/path/to/sapling-output.params"),
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the paths do not point to valid parameter files with
    /// the expected hashes.
    pub fn new(spend_path: &Path, output_path: &Path) -> Self {
        let p = load_parameters(spend_path, output_path, None);
        LocalTxProver {
            spend_params: p.spend_params,
            output_params: p.output_params,
        }
    }

    /// Creates a `LocalTxProver` using parameters specified as byte arrays.
    ///
    /// # Examples
    ///
    /// ```should_panic
    /// use std::path::Path;
    /// use zcash_proofs::prover::LocalTxProver;
    ///
    /// let tx_prover = LocalTxProver::from_bytes(&[0u8], &[0u8]);
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the byte arrays do not contain valid parameters with
    /// the expected hashes.
    pub fn from_bytes(spend_param_bytes: &[u8], output_param_bytes: &[u8]) -> Self {
        let p = parse_parameters(spend_param_bytes, output_param_bytes, None);

        LocalTxProver {
            spend_params: p.spend_params,
            output_params: p.output_params,
        }
    }

    /// Attempts to create a `LocalTxProver` using parameters from the default local
    /// location.
    ///
    /// Returns `None` if any of the parameters cannot be found in the default local
    /// location.
    ///
    /// # Examples
    ///
    /// ```
    /// use zcash_proofs::prover::LocalTxProver;
    ///
    /// match LocalTxProver::with_default_location() {
    ///     Some(tx_prover) => (),
    ///     None => println!("Please run zcash-fetch-params or fetch-params.sh to download the parameters."),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the parameters in the default local location do not
    /// have the expected hashes.
    #[cfg(feature = "local-prover")]
    pub fn with_default_location() -> Option<Self> {
        let params_dir = default_params_folder()?;
        let (spend_path, output_path) = if params_dir.exists() {
            (
                params_dir.join(SAPLING_SPEND_NAME),
                params_dir.join(SAPLING_OUTPUT_NAME),
            )
        } else {
            return None;
        };
        if !(spend_path.exists() && output_path.exists()) {
            return None;
        }

        Some(LocalTxProver::new(&spend_path, &output_path))
    }

    /// Creates a `LocalTxProver` using Sapling parameters bundled inside the binary.
    ///
    /// This requires the `bundled-prover` feature, which will increase the binary size by
    /// around 50 MiB.
    #[cfg(feature = "bundled-prover")]
    pub fn bundled() -> Self {
        let (spend_buf, output_buf) = wagyu_zcash_parameters::load_sapling_parameters();
        let p = parse_parameters(&spend_buf[..], &output_buf[..], None);

        LocalTxProver {
            spend_params: p.spend_params,
            output_params: p.output_params,
        }
    }
}

impl SpendProver for LocalTxProver {
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
    ) -> Option<sapling::circuit::Spend> {
        SpendParameters::prepare_circuit(
            proof_generation_key,
            diversifier,
            rseed,
            value,
            alpha,
            rcv,
            anchor,
            merkle_path,
        )
    }

    fn create_proof<R: rand_core::RngCore>(
        &self,
        circuit: sapling::circuit::Spend,
        rng: &mut R,
    ) -> Self::Proof {
        self.spend_params.create_proof(circuit, rng)
    }

    fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");
        zkproof
    }
}

impl OutputProver for LocalTxProver {
    type Proof = Proof<Bls12>;

    fn prepare_circuit(
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: NoteValue,
        rcv: ValueCommitTrapdoor,
    ) -> sapling::circuit::Output {
        OutputParameters::prepare_circuit(esk, payment_address, rcm, value, rcv)
    }

    fn create_proof<R: rand_core::RngCore>(
        &self,
        circuit: sapling::circuit::Output,
        rng: &mut R,
    ) -> Self::Proof {
        self.output_params.create_proof(circuit, rng)
    }

    fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");
        zkproof
    }
}
