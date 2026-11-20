//! Deterministic codec and digest workloads; shielded proofs and signatures are synthetic,
//! so these fixtures are not consensus-valid transactions. No proving is performed.
//! Writers reuse an output buffer; readers include allocation and destruction.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use orchard::bundle::{BundleVersion, Flags};
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::{Config, RngAlgorithm, RngSeed, TestRunner},
};
use transparent::{
    address::{Script, TransparentAddress},
    bundle::{
        Authorized as TransparentAuthorized, Bundle as TransparentBundle, OutPoint, TxIn, TxOut,
    },
};
use zcash_primitives::transaction::{
    Transaction, TransactionData, TxVersion,
    bytes::TransactionBytes,
    components::{
        orchard::testing::arb_bundle, sapling::testing::arb_bundle as arb_sapling_bundle,
    },
    txid::{TxIdDigester, to_txid},
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::{COIN, ZatBalance, Zatoshis},
};

/// A single-input payment and a larger transparent-input aggregation.
const INPUT_COUNTS: [usize; 2] = [1, 16];
/// Payment and change outputs in each transparent bundle.
const OUTPUT_COUNT: usize = 2;
/// Spends, outputs, or actions per shielded pool, keeping shielded work fixed.
const SHIELDED_COUNT: usize = 2;
/// Fixed seed shared by all fixtures so only the requested dimensions change.
const FIXTURE_SEED: u64 = 0x248_2271;
/// An arbitrary expiry height, unrelated to network activation heights.
const EXPIRY_HEIGHT: BlockHeight = BlockHeight::from_u32(2_000_000);
/// No lock-time constraint is needed for codec fixtures.
const LOCK_TIME: u32 = 0;
/// Final sequence numbers avoid a relative lock-time constraint.
const SEQUENCE: u32 = u32::MAX;
/// Each synthetic prevout supplies one coin.
#[cfg(zcash_unstable = "nu8")]
const INPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(COIN);
/// Each output supplies a quarter coin, leaving a positive fee even with one input.
const OUTPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(COIN / 4);
/// A distinct, non-null previous transaction hash.
const PREVOUT_HASH: [u8; 32] = [0x24; 32];
/// A fixed P2PKH receiver supplies representative output and prevout script sizes.
const RECEIVER_HASH: [u8; 20] = [0x71; 20];
/// Synthetic P2PKH scriptSig-sized authorizing data; not an executable signature.
const SCRIPT_SIG: [u8; 107] = [0x48; 107];

struct Fixture {
    name: String,
    tx: Transaction,
    wire: Vec<u8>,
    bytes: TransactionBytes,
}

fn script_pubkey() -> Script {
    TransparentAddress::PublicKeyHash(RECEIVER_HASH)
        .script()
        .into()
}

fn fixture(version: TxVersion, input_count: usize) -> Fixture {
    let mut runner = TestRunner::new(Config {
        rng_seed: RngSeed::Fixed(FIXTURE_SEED),
        rng_algorithm: RngAlgorithm::ChaCha,
        failure_persistence: None,
        ..Config::default()
    });
    let sapling = arb_sapling_bundle()
        .prop_filter_map("two Sapling spends and outputs", |bundle| {
            bundle.filter(|b| {
                b.shielded_spends().len() >= SHIELDED_COUNT
                    && b.shielded_outputs().len() >= SHIELDED_COUNT
            })
        })
        .new_tree(&mut runner)
        .unwrap()
        .current();
    // The canonical strategy normalizes spend anchors. Retain a fixed-size prefix.
    let sapling = sapling::Bundle::from_parts(
        sapling.shielded_spends()[..SHIELDED_COUNT].to_vec(),
        sapling.shielded_outputs()[..SHIELDED_COUNT].to_vec(),
        ZatBalance::zero(),
        *sapling.authorization(),
    )
    .unwrap();
    let orchard = arb_bundle(SHIELDED_COUNT)
        .new_tree(&mut runner)
        .unwrap()
        .current();
    let transparent = TransparentBundle {
        vin: (0..input_count)
            .map(|index| {
                TxIn::from_parts(
                    OutPoint::new(PREVOUT_HASH, u32::try_from(index).unwrap()),
                    Script(zcash_script::script::Code(SCRIPT_SIG.to_vec())),
                    SEQUENCE,
                )
            })
            .collect(),
        vout: (0..OUTPUT_COUNT)
            .map(|_| TxOut::new(OUTPUT_VALUE, script_pubkey()))
            .collect(),
        authorization: TransparentAuthorized,
    };
    let branch = match version {
        TxVersion::V5 => BranchId::Nu5,
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => BranchId::Nu8,
        _ => unreachable!("only v5 and v7 fixtures are constructed"),
    };
    let data = match version {
        TxVersion::V5 => TransactionData::from_parts(
            version,
            branch,
            LOCK_TIME,
            EXPIRY_HEIGHT,
            Some(transparent),
            None,
            Some(sapling),
            Some(orchard_bundle(&orchard, BundleVersion::orchard_v2())),
        ),
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => {
            let input_total = (0..input_count)
                .map(|_| INPUT_VALUE)
                .sum::<Option<Zatoshis>>()
                .unwrap();
            let output_total = (0..OUTPUT_COUNT)
                .map(|_| OUTPUT_VALUE)
                .sum::<Option<Zatoshis>>()
                .unwrap();
            TransactionData::from_parts_v7_balanced(
                branch,
                LOCK_TIME,
                EXPIRY_HEIGHT,
                (ZatBalance::from(input_total) - ZatBalance::from(output_total)).unwrap(),
                Some(transparent),
                Some(sapling),
                Some(orchard_bundle(&orchard, BundleVersion::orchard_v3())),
                Some(orchard_bundle(&orchard, BundleVersion::ironwood_v3())),
            )
            .unwrap()
        }
        _ => unreachable!("only v5 and v7 fixtures are constructed"),
    };
    let tx = data.freeze().unwrap();
    let mut wire = Vec::new();
    tx.write(&mut wire).unwrap();
    let mut reader = wire.as_slice();
    let bytes = TransactionBytes::read(&mut reader).unwrap();
    assert!(reader.is_empty());
    let mut encoded = Vec::new();
    bytes.write(&mut encoded).unwrap();
    assert_eq!(encoded, wire);
    let mut reader = wire.as_slice();
    let roundtrip = Transaction::read(&mut reader, branch).unwrap();
    assert!(reader.is_empty());
    encoded.clear();
    roundtrip.write(&mut encoded).unwrap();
    assert_eq!(encoded, wire);
    assert_eq!(roundtrip.txid(), tx.txid());
    assert_eq!(roundtrip.auth_commitment(), tx.auth_commitment());
    assert_eq!(
        to_txid(version, branch, &tx.digest(TxIdDigester)).unwrap(),
        tx.txid()
    );
    #[cfg(zcash_unstable = "nu8")]
    if version == TxVersion::V7 {
        let supplied = zcash_primitives::transaction::zip248::SuppliedBundleDigests::new();
        assert_eq!(bytes.v7_txid(&supplied).unwrap(), tx.txid());
        assert_eq!(
            bytes.v7_auth_commitment(&supplied).unwrap(),
            tx.auth_commitment()
        );
    }
    Fixture {
        name: format!("{version:?}/transparent_inputs_{input_count}_mixed"),
        tx,
        wire,
        bytes,
    }
}

fn orchard_bundle(
    bundle: &orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
    version: BundleVersion,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    let flags = if version == BundleVersion::orchard_v3() {
        Flags::CROSS_ADDRESS_DISABLED
    } else {
        Flags::ENABLED
    };
    orchard::Bundle::try_from_parts(
        bundle.actions().clone(),
        flags,
        ZatBalance::zero(),
        *bundle.anchor(),
        bundle.authorization().clone(),
        version,
    )
    .unwrap()
}

fn bench_codec(c: &mut Criterion, fixture: &Fixture) {
    let mut group = c.benchmark_group(format!("transaction_codec/{}", fixture.name));
    group.throughput(Throughput::Bytes(
        u64::try_from(fixture.wire.len()).unwrap(),
    ));
    group.bench_function("byte_read", |b| {
        b.iter(|| TransactionBytes::read(black_box(fixture.wire.as_slice())).unwrap())
    });
    group.bench_function("typed_read", |b| {
        b.iter(|| {
            Transaction::read(
                black_box(fixture.wire.as_slice()),
                black_box(fixture.tx.consensus_branch_id()),
            )
            .unwrap()
        })
    });
    let mut output = Vec::with_capacity(fixture.wire.len());
    group.bench_function("byte_write", |b| {
        b.iter(|| {
            output.clear();
            black_box(&fixture.bytes)
                .write(black_box(&mut output))
                .unwrap();
            black_box(output.as_slice());
        })
    });
    group.bench_function("typed_write", |b| {
        b.iter(|| {
            output.clear();
            black_box(&fixture.tx)
                .write(black_box(&mut output))
                .unwrap();
            black_box(output.as_slice());
        })
    });
    group.bench_function("typed_txid_digester", |b| {
        b.iter(|| black_box(&fixture.tx).digest(TxIdDigester))
    });
    group.bench_function("typed_auth_commitment", |b| {
        b.iter(|| black_box(&fixture.tx).auth_commitment())
    });
    #[cfg(zcash_unstable = "nu8")]
    if fixture.tx.version() == TxVersion::V7 {
        let supplied = zcash_primitives::transaction::zip248::SuppliedBundleDigests::new();
        group.bench_function("byte_txid_digests", |b| {
            b.iter(|| {
                black_box(&fixture.bytes)
                    .v7_txid_digests(&supplied)
                    .unwrap()
            })
        });
        group.bench_function("byte_auth_commitment", |b| {
            b.iter(|| {
                black_box(&fixture.bytes)
                    .v7_auth_commitment(&supplied)
                    .unwrap()
            })
        });
    }
    group.finish();
}

#[cfg(zcash_unstable = "nu8")]
mod v7 {
    use std::hint::black_box;

    use criterion::{BenchmarkId, Criterion, Throughput};
    use transparent::{
        address::Script,
        bundle::{Authorization as TransparentAuthorization, Bundle, TxIn, TxOut},
        sighash::{SighashType, SignableInput as TransparentInput, TransparentAuthorizingContext},
    };
    use zcash_primitives::transaction::{
        Authorization, Authorized, Transaction, TransactionData,
        sighash::{PrecomputedSighashData, SignableInput, V7SignatureContext},
    };
    use zcash_protocol::value::Zatoshis;

    use super::{Fixture, INPUT_VALUE, script_pubkey};

    /// One signature and a batch large enough to expose repeated transaction-wide work.
    const CONTEXT_COUNTS: [usize; 2] = [1, 16];

    #[derive(Debug)]
    struct Prevouts(Vec<TxOut<Zatoshis>>);

    impl TransparentAuthorization for Prevouts {
        type ScriptSig = Script;
    }

    impl TransparentAuthorizingContext<Zatoshis> for Prevouts {
        fn input_amounts(&self) -> Vec<Zatoshis> {
            self.0.iter().map(TxOut::value).collect()
        }

        fn input_scriptpubkeys(&self) -> Vec<Script> {
            self.0.iter().map(|p| p.script_pubkey().clone()).collect()
        }
    }

    struct WithPrevouts;

    impl Authorization for WithPrevouts {
        type TransparentAuth = Prevouts;
        type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
        type OrchardAuth = <Authorized as Authorization>::OrchardAuth;
    }

    fn precompute(tx: TransactionData<Authorized>) -> PrecomputedSighashData<WithPrevouts> {
        PrecomputedSighashData::new(tx.map_bundles(
            |bundle| {
                bundle.map(|b| Bundle {
                    authorization: Prevouts(
                        b.vin
                            .iter()
                            .map(|_| TxOut::new(INPUT_VALUE, script_pubkey()))
                            .collect(),
                    ),
                    vin: b
                        .vin
                        .into_iter()
                        .map(|i| {
                            TxIn::from_parts(
                                i.prevout().clone(),
                                i.script_sig().clone(),
                                i.sequence(),
                            )
                        })
                        .collect(),
                    vout: b.vout,
                })
            },
            |bundle| bundle,
            |bundle| bundle,
        ))
    }

    pub(super) fn bench(c: &mut Criterion, fixture: &Fixture) {
        let precomputed = precompute(fixture.tx.clone().into_data());
        let roundtrip = precompute(
            Transaction::read(fixture.wire.as_slice(), fixture.tx.consensus_branch_id())
                .unwrap()
                .into_data(),
        );
        let bundle = precomputed.tx().transparent_bundle().unwrap();
        let script = script_pubkey();
        let contexts: Vec<_> = (0..bundle.vin.len())
            .map(|index| {
                SignableInput::V7(V7SignatureContext::Transparent(
                    TransparentInput::from_parts(
                        bundle,
                        SighashType::ALL,
                        index,
                        &script,
                        &script,
                        INPUT_VALUE,
                    )
                    .unwrap(),
                ))
            })
            .collect();
        let binding = SignableInput::V7(V7SignatureContext::OrchardBinding);
        for context in contexts.iter().chain(std::iter::once(&binding)) {
            assert_eq!(
                precomputed.signature_hash(context).as_ref(),
                roundtrip.signature_hash(context).as_ref()
            );
        }
        let mut group = c.benchmark_group(format!("transaction_sighash/{}", fixture.name));
        for count in CONTEXT_COUNTS {
            group.throughput(Throughput::Elements(u64::try_from(count).unwrap()));
            // Repeat the same binding context to isolate the per-call cost.
            group.bench_with_input(
                BenchmarkId::new("orchard_binding", count),
                &count,
                |b, &n| {
                    b.iter(|| {
                        for _ in 0..n {
                            black_box(black_box(&precomputed).signature_hash(black_box(&binding)));
                        }
                    })
                },
            );
            if count <= contexts.len() {
                let batch = &contexts[..count];
                group.bench_with_input(
                    BenchmarkId::new("transparent", count),
                    &batch,
                    |b, batch| {
                        b.iter(|| {
                            for context in *batch {
                                black_box(
                                    black_box(&precomputed).signature_hash(black_box(context)),
                                );
                            }
                        })
                    },
                );
            }
        }
        group.finish();
    }
}

fn bench_transaction_codec(c: &mut Criterion) {
    let versions = [
        TxVersion::V5,
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7,
    ];
    for version in versions {
        for input_count in INPUT_COUNTS {
            let fixture = fixture(version, input_count);
            bench_codec(c, &fixture);
            #[cfg(zcash_unstable = "nu8")]
            if version == TxVersion::V7 {
                v7::bench(c, &fixture);
            }
        }
    }
}

criterion_group!(benches, bench_transaction_codec);
criterion_main!(benches);
