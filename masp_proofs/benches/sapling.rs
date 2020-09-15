#[macro_use]
extern crate criterion;

use bellman::groth16::*;
use bls12_381::Bls12;
use criterion::Criterion;
use ff::Field;
use group::Group;
use masp_primitives::primitives::{Diversifier, ProofGenerationKey, ValueCommitment};
use masp_proofs::circuit::sapling::Spend;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

const TREE_DEPTH: usize = 32;

fn criterion_benchmark(c: &mut Criterion) {
    let rng = &mut XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

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

    c.bench_function("sapling", |b| {
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

        b.iter(|| {
            create_random_proof(
                Spend {
                    value_commitment: Some(value_commitment.clone()),
                    proof_generation_key: Some(proof_generation_key.clone()),
                    payment_address: Some(payment_address.clone()),
                    commitment_randomness: Some(commitment_randomness),
                    ar: Some(ar),
                    auth_path: auth_path.clone(),
                    anchor: Some(anchor),
                },
                &groth_params,
                rng,
            )
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark);
criterion_main!(benches);
