use criterion::{criterion_group, criterion_main, Criterion};
use pairing::bls12_381::Bls12;
use rand_core::{OsRng, RngCore};
use zcash_primitives::jubjub::JubjubBls12;
use zcash_primitives::pedersen_hash::{pedersen_hash, Personalization};

fn bench_pedersen_hash(c: &mut Criterion) {
    let params = JubjubBls12::new();
    let rng = &mut OsRng;
    let bits = (0..510)
        .map(|_| (rng.next_u32() % 2) != 0)
        .collect::<Vec<_>>();
    let personalization = Personalization::MerkleTree(31);

    c.bench_function("Pedersen hash", |b| {
        b.iter(|| pedersen_hash::<Bls12, _>(personalization, bits.clone(), &params))
    });
}

criterion_group!(benches, bench_pedersen_hash);
criterion_main!(benches);
