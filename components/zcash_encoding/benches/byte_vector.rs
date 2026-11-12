use std::hint::black_box;

use corez::io::{self, Read};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use zcash_encoding::{CompactSize, Vector};

/// The length of a P2PKH `scriptPubKey`, the most common transparent script.
const P2PKH_SCRIPT_LEN: usize = 25;

/// The length of a typical P2PKH `scriptSig`: a DER signature with its sighash type and a
/// compressed public key, each with a push opcode.
const P2PKH_SCRIPT_SIG_LEN: usize = 107;

/// The length of an Equihash solution for the mainnet parameters `n = 200`, `k = 9`.
const EQUIHASH_SOLUTION_LEN: usize = 1344;

/// The fixed part of the length of an Orchard proof.
const ORCHARD_PROOF_BASE_LEN: usize = 2720;

/// The length that each action adds to an Orchard proof.
const ORCHARD_PROOF_PER_ACTION_LEN: usize = 2272;

/// The number of actions in a typical Orchard bundle, which pads to two actions.
const TYPICAL_ORCHARD_ACTIONS: usize = 2;

/// The number of actions in a large Orchard bundle.
const LARGE_ORCHARD_ACTIONS: usize = 50;

/// Returns the length of an Orchard proof for a bundle with `num_actions` actions.
const fn orchard_proof_len(num_actions: usize) -> usize {
    ORCHARD_PROOF_BASE_LEN + ORCHARD_PROOF_PER_ACTION_LEN * num_actions
}

/// Reads a byte vector by decoding each byte separately, as callers did before
/// `Vector::read_bytes` existed.
fn read_per_byte<R: Read>(reader: R) -> io::Result<Vec<u8>> {
    Vector::read(reader, |r| {
        let mut byte = [0];
        r.read_exact(&mut byte)?;
        Ok(byte[0])
    })
}

/// Returns the encoding of a byte vector of length `len`.
fn encoded_byte_vector(len: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    CompactSize::write(&mut encoded, len).expect("benchmark lengths are below MAX_COMPACT_SIZE");
    encoded.extend((0..=u8::MAX).cycle().take(len));
    encoded
}

fn bench_byte_vector_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte-vector-read");
    for (name, len) in [
        ("p2pkh-script-pubkey", P2PKH_SCRIPT_LEN),
        ("p2pkh-script-sig", P2PKH_SCRIPT_SIG_LEN),
        ("equihash-solution", EQUIHASH_SOLUTION_LEN),
        (
            "orchard-proof-2-actions",
            orchard_proof_len(TYPICAL_ORCHARD_ACTIONS),
        ),
        (
            "orchard-proof-50-actions",
            orchard_proof_len(LARGE_ORCHARD_ACTIONS),
        ),
    ] {
        let encoded = encoded_byte_vector(len);
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("per-byte", name),
            &encoded,
            |b, encoded| b.iter(|| read_per_byte(black_box(&encoded[..])).unwrap()),
        );
        group.bench_with_input(BenchmarkId::new("bulk", name), &encoded, |b, encoded| {
            b.iter(|| Vector::read_bytes(black_box(&encoded[..])).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_byte_vector_reads);
criterion_main!(benches);
