use criterion::{criterion_group, criterion_main, Criterion};
use ff::Field;
use rand_core::OsRng;
use zcash_primitives::{
    consensus::{NetworkUpgrade::Canopy, Parameters, TestNetwork, TEST_NETWORK},
    memo::MemoBytes,
    sapling::{
        note_encryption::{sapling_note_encryption, try_sapling_note_decryption},
        util::generate_random_rseed,
        Diversifier, PaymentAddress, SaplingIvk, ValueCommitment,
    },
    transaction::components::{
        sapling::{GrothProofBytes, OutputDescription},
        GROTH_PROOF_SIZE,
    },
};

fn bench_note_decryption(c: &mut Criterion) {
    let mut rng = OsRng;
    let height = TEST_NETWORK.activation_height(Canopy).unwrap();

    let valid_ivk = SaplingIvk(jubjub::Fr::random(&mut rng));
    let invalid_ivk = SaplingIvk(jubjub::Fr::random(&mut rng));

    // Construct a fake Sapling output as if we had just deserialized a transaction.
    let output: OutputDescription<GrothProofBytes> = {
        let diversifier = Diversifier([0; 11]);
        let pk_d = diversifier.g_d().unwrap() * valid_ivk.0;
        let pa = PaymentAddress::from_parts(diversifier, pk_d).unwrap();

        let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);

        // Construct the value commitment for the proof instance
        let value = 100;
        let value_commitment = ValueCommitment {
            value,
            randomness: jubjub::Fr::random(&mut rng),
        };
        let cv = value_commitment.commitment().into();

        let note = pa.create_note(value, rseed).unwrap();
        let cmu = note.cmu();

        let ne =
            sapling_note_encryption::<_, TestNetwork>(None, note, pa, MemoBytes::empty(), &mut rng);
        let ephemeral_key = *ne.epk();
        let enc_ciphertext = ne.encrypt_note_plaintext();
        let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);

        OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof: [0; GROTH_PROOF_SIZE],
        }
    };

    let mut group = c.benchmark_group("Sapling note decryption");

    group.bench_function("valid", |b| {
        b.iter(|| try_sapling_note_decryption(&TEST_NETWORK, height, &valid_ivk, &output).unwrap())
    });

    group.bench_function("invalid", |b| {
        b.iter(|| try_sapling_note_decryption(&TEST_NETWORK, height, &invalid_ivk, &output))
    });
}

criterion_group!(benches, bench_note_decryption);
criterion_main!(benches);
