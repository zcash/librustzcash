use std::hint::black_box;

use corez::io::{self, Read, Write};
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

/// The byte-vector lengths to benchmark, with the name of the field each one models.
const BENCHMARK_LENGTHS: [(&str, usize); 5] = [
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
];

/// Reads a byte vector by decoding each byte separately, as callers did before
/// `Vector::read_bytes` existed.
fn read_per_byte<R: Read>(reader: R) -> io::Result<Vec<u8>> {
    Vector::read(reader, |r| {
        let mut byte = [0];
        r.read_exact(&mut byte)?;
        Ok(byte[0])
    })
}

/// Writes a byte vector by encoding each byte separately, as callers did before
/// `Vector::write_bytes` existed.
fn write_per_byte<W: Write>(writer: W, bytes: &[u8]) -> io::Result<()> {
    Vector::write(writer, bytes, |w, b| w.write_all(&[*b]))
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
    for (name, len) in BENCHMARK_LENGTHS {
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

fn bench_byte_vector_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte-vector-write");
    for (name, len) in BENCHMARK_LENGTHS {
        let bytes: Vec<u8> = (0..=u8::MAX).cycle().take(len).collect();
        // Reuse one output buffer so that the measurement excludes its allocation.
        let mut output = Vec::with_capacity(Vector::serialized_size_of_u8_vec(&bytes));
        group.throughput(Throughput::Bytes(output.capacity() as u64));
        group.bench_with_input(BenchmarkId::new("per-byte", name), &bytes, |b, bytes| {
            b.iter(|| {
                output.clear();
                write_per_byte(&mut output, black_box(bytes)).unwrap();
                black_box(&output);
            })
        });
        group.bench_with_input(BenchmarkId::new("bulk", name), &bytes, |b, bytes| {
            b.iter(|| {
                output.clear();
                Vector::write_bytes(&mut output, black_box(bytes)).unwrap();
                black_box(&output);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_byte_vector_reads, bench_byte_vector_writes);
criterion_main!(benches);
