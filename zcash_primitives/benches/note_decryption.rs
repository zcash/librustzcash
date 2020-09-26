use criterion::{criterion_group, criterion_main, Criterion};
use ff::Field;
use rand_core::OsRng;
use zcash_primitives::{
    consensus::{NetworkUpgrade::Canopy, Parameters, TestNetwork},
    note_encryption::{try_sapling_note_decryption, Memo, SaplingNoteEncryption},
    primitives::{Diversifier, PaymentAddress, ValueCommitment},
    transaction::components::{OutputDescription, GROTH_PROOF_SIZE},
    util::generate_random_rseed,
};

fn bench_note_decryption(c: &mut Criterion) {
    let params = TestNetwork;
    let mut rng = OsRng;
    let height = params.activation_height(Canopy).unwrap();

    let valid_ivk = jubjub::Fr::random(&mut rng);
    let invalid_ivk = jubjub::Fr::random(&mut rng);

    // Construct a fake Sapling output as if we had just deserialized a transaction.
    let output = {
        let diversifier = Diversifier([0; 11]);
        let pk_d = diversifier.g_d().unwrap() * valid_ivk;
        let pa = PaymentAddress::from_parts(diversifier, pk_d).unwrap();

        let rseed = generate_random_rseed(&params, height, &mut rng);

        // Construct the value commitment for the proof instance
        let value = 100;
        let value_commitment = ValueCommitment {
            value,
            randomness: jubjub::Fr::random(&mut rng),
        };
        let cv = value_commitment.commitment().into();

        let note = pa.create_note(value, rseed).unwrap();
        let cmu = note.cmu();

        let mut ne = SaplingNoteEncryption::new(None, note, pa, Memo::default(), &mut rng);
        let ephemeral_key = ne.epk().clone().into();
        let enc_ciphertext = ne.encrypt_note_plaintext();
        let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv, &cmu);

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
        b.iter(|| {
            try_sapling_note_decryption(
                &TestNetwork,
                height,
                &valid_ivk,
                &output.ephemeral_key,
                &output.cmu,
                &output.enc_ciphertext,
            )
            .unwrap()
        })
    });

    group.bench_function("invalid", |b| {
        b.iter(|| {
            try_sapling_note_decryption(
                &TestNetwork,
                height,
                &invalid_ivk,
                &output.ephemeral_key,
                &output.cmu,
                &output.enc_ciphertext,
            )
        })
    });
}

criterion_group!(benches, bench_note_decryption);
criterion_main!(benches);
