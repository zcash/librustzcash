use bellman::groth16::*;
use bls12_381::Bls12;
use ff::Field;
use group::Group;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::time::{Duration, Instant};
use zcash_primitives::primitives::{Diversifier, ProofGenerationKey, ValueCommitment};
use zcash_proofs::circuit::sapling::Spend;

const TREE_DEPTH: usize = 32;

fn main() {
    let rng = &mut XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    println!("Creating sample parameters...");
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Spend {
            value_commitment: None,
            proof_generation_key: None,
            payment_address: None,
            commitment_randomness: None,
            ar: None,
            auth_path: vec![None; TREE_DEPTH],
            anchor: None,
        },
        rng,
    )
    .unwrap();

    const SAMPLES: u32 = 50;

    let mut total_time = Duration::new(0, 0);
    for _ in 0..SAMPLES {
        let value_commitment = ValueCommitment {
            value: 1,
            randomness: jubjub::Fr::random(rng),
        };

        let nsk = jubjub::Fr::random(rng);
        let ak = jubjub::SubgroupPoint::random(rng);

        let proof_generation_key = ProofGenerationKey {
            ak: ak.clone(),
            nsk: nsk.clone(),
        };

        let viewing_key = proof_generation_key.to_viewing_key();

        let payment_address;

        loop {
            let diversifier = {
                let mut d = [0; 11];
                rng.fill_bytes(&mut d);
                Diversifier(d)
            };

            if let Some(p) = viewing_key.to_payment_address(diversifier) {
                payment_address = p;
                break;
            }
        }

        let commitment_randomness = jubjub::Fr::random(rng);
        let auth_path =
            vec![Some((bls12_381::Scalar::random(rng), rng.next_u32() % 2 != 0)); TREE_DEPTH];
        let ar = jubjub::Fr::random(rng);
        let anchor = bls12_381::Scalar::random(rng);

        let start = Instant::now();
        let _ = create_random_proof(
            Spend {
                value_commitment: Some(value_commitment),
                proof_generation_key: Some(proof_generation_key),
                payment_address: Some(payment_address),
                commitment_randomness: Some(commitment_randomness),
                ar: Some(ar),
                auth_path: auth_path,
                anchor: Some(anchor),
            },
            &groth_params,
            rng,
        )
        .unwrap();
        total_time += start.elapsed();
    }
    let avg = total_time / SAMPLES;
    let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64 + (avg.as_secs() as f64);

    println!("Average proving time (in seconds): {}", avg);
}
