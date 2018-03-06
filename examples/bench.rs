extern crate sapling_crypto;
extern crate bellman;
extern crate rand;
extern crate pairing;

use std::time::{Duration, Instant};
use sapling_crypto::jubjub::{
    JubjubBls12,
    edwards,
    fs,
    Unknown
};
use sapling_crypto::circuit::{
    Spend
};
use bellman::groth16::*;
use rand::{XorShiftRng, SeedableRng, Rng};
use pairing::bls12_381::Bls12;

const TREE_DEPTH: usize = 32;

fn main() {
    let jubjub_params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    println!("Creating sample parameters...");
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Spend {
            params: jubjub_params,
            /// Value of the note being spent
            value: None,
            /// Randomness that will hide the value
            value_randomness: None,
            /// Key which allows the proof to be constructed
            /// as defense-in-depth against a flaw in the
            /// protocol that would otherwise be exploitable
            /// by a holder of a viewing key.
            rsk: None,
            /// The public key that will be re-randomized for
            /// use as a nullifier and signing key for the
            /// transaction.
            ak: None,
            /// The diversified base used to compute pk_d.
            g_d: None,
            /// The randomness used to hide the note commitment data
            commitment_randomness: None,
            /// The authentication path of the commitment in the tree
            auth_path: vec![None; TREE_DEPTH]
        },
        rng
    ).unwrap();

    const SAMPLES: u32 = 50;

    let mut total_time = Duration::new(0, 0);
    for _ in 0..SAMPLES {
        let value: u64 = 1;
        let value_randomness: fs::Fs = rng.gen();
        let ak: edwards::Point<Bls12, Unknown> = edwards::Point::rand(rng, jubjub_params);
        let g_d: edwards::Point<Bls12, Unknown> = edwards::Point::rand(rng, jubjub_params);
        let commitment_randomness: fs::Fs = rng.gen();
        let rsk: fs::Fs = rng.gen();
        let auth_path = (0..TREE_DEPTH).map(|_| Some((rng.gen(), rng.gen()))).collect();

        let start = Instant::now();
        let _ = create_random_proof(Spend {
            params: jubjub_params,
            value: Some(value),
            value_randomness: Some(value_randomness),
            ak: Some(ak),
            g_d: Some(g_d),
            commitment_randomness: Some(commitment_randomness),
            rsk: Some(rsk),
            auth_path: auth_path
        }, &groth_params, rng).unwrap();
        total_time += start.elapsed();
    }
    let avg = total_time / SAMPLES;
    let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64
              + (avg.as_secs() as f64);

    println!("Average proving time (in seconds): {}", avg);
}
