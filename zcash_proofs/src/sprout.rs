//! APIs for creating and verifying Sprout proofs.

use bellman::{
    gadgets::multipack,
    groth16::{self, create_random_proof, Parameters, PreparedVerifyingKey, Proof},
};
use pairing::bls12_381::Bls12;
use rand_core::OsRng;

use crate::circuit::sprout::*;

const GROTH_PROOF_SIZE: usize = 48 // π_A
    + 96 // π_B
    + 48; // π_C
pub const WITNESS_PATH_SIZE: usize = 1 + 33 * TREE_DEPTH + 8;

/// Sprout JoinSplit proof generation.
pub fn create_proof(
    phi: [u8; 32],
    rt: [u8; 32],
    h_sig: [u8; 32],

    // First input
    in_sk1: [u8; 32],
    in_value1: u64,
    in_rho1: [u8; 32],
    in_r1: [u8; 32],
    in_auth1: &[u8; WITNESS_PATH_SIZE],

    // Second input
    in_sk2: [u8; 32],
    in_value2: u64,
    in_rho2: [u8; 32],
    in_r2: [u8; 32],
    in_auth2: &[u8; WITNESS_PATH_SIZE],

    // First output
    out_pk1: [u8; 32],
    out_value1: u64,
    out_r1: [u8; 32],

    // Second output
    out_pk2: [u8; 32],
    out_value2: u64,
    out_r2: [u8; 32],

    // Public value
    vpub_old: u64,
    vpub_new: u64,

    proving_key: &Parameters<Bls12>,
) -> Proof<Bls12> {
    let mut inputs = Vec::with_capacity(2);
    {
        let mut handle_input = |sk, value, rho, r, mut auth: &[u8]| {
            let value = Some(value);
            let rho = Some(UniqueRandomness(rho));
            let r = Some(CommitmentRandomness(r));
            let a_sk = Some(SpendingKey(sk));

            // skip the first byte
            assert_eq!(auth[0], TREE_DEPTH as u8);
            auth = &auth[1..];

            let mut auth_path = [None; TREE_DEPTH];
            for i in (0..TREE_DEPTH).rev() {
                // skip length of inner vector
                assert_eq!(auth[0], 32);
                auth = &auth[1..];

                let mut sibling = [0u8; 32];
                sibling.copy_from_slice(&auth[0..32]);
                auth = &auth[32..];

                auth_path[i] = Some((sibling, false));
            }

            let mut position = {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(&auth[0..8]);
                u64::from_le_bytes(bytes)
            };

            for entry in auth_path.iter_mut() {
                if let Some(p) = entry {
                    p.1 = (position & 1) == 1;
                }

                position >>= 1;
            }

            inputs.push(JSInput {
                value,
                a_sk,
                rho,
                r,
                auth_path,
            });
        };

        handle_input(in_sk1, in_value1, in_rho1, in_r1, &in_auth1[..]);
        handle_input(in_sk2, in_value2, in_rho2, in_r2, &in_auth2[..]);
    }

    let mut outputs = Vec::with_capacity(2);
    {
        let mut handle_output = |a_pk, value, r| {
            outputs.push(JSOutput {
                value: Some(value),
                a_pk: Some(PayingKey(a_pk)),
                r: Some(CommitmentRandomness(r)),
            });
        };

        handle_output(out_pk1, out_value1, out_r1);
        handle_output(out_pk2, out_value2, out_r2);
    }

    let js = JoinSplit {
        vpub_old: Some(vpub_old),
        vpub_new: Some(vpub_new),
        h_sig: Some(h_sig),
        phi: Some(phi),
        inputs,
        outputs,
        rt: Some(rt),
    };

    // Initialize secure RNG
    let mut rng = OsRng;

    create_random_proof(js, proving_key, &mut rng).expect("proving should not fail")
}

/// Sprout JoinSplit proof verification.
pub fn verify_proof(
    proof: &[u8; GROTH_PROOF_SIZE],
    rt: &[u8; 32],
    h_sig: &[u8; 32],
    mac1: &[u8; 32],
    mac2: &[u8; 32],
    nf1: &[u8; 32],
    nf2: &[u8; 32],
    cm1: &[u8; 32],
    cm2: &[u8; 32],
    vpub_old: u64,
    vpub_new: u64,
    verifying_key: &PreparedVerifyingKey<Bls12>,
) -> bool {
    // Prepare the public input for the verifier
    let mut public_input = Vec::with_capacity((32 * 8) + (8 * 2));
    public_input.extend(rt);
    public_input.extend(h_sig);
    public_input.extend(nf1);
    public_input.extend(mac1);
    public_input.extend(nf2);
    public_input.extend(mac2);
    public_input.extend(cm1);
    public_input.extend(cm2);
    public_input.extend(&vpub_old.to_le_bytes());
    public_input.extend(&vpub_new.to_le_bytes());

    let public_input = multipack::bytes_to_bits(&public_input);
    let public_input = multipack::compute_multipacking::<Bls12>(&public_input);

    let proof = match Proof::read(&proof[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Verify the proof
    match groth16::verify_proof(verifying_key, &proof, &public_input[..]) {
        // No error, and proof verification successful
        Ok(true) => true,

        // Any other case
        _ => false,
    }
}
