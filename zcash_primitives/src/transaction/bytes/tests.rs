use alloc::vec;
use alloc::vec::Vec;

use zcash_encoding::CompactSize;
use zcash_protocol::consensus::{BlockHeight, BranchId};
#[cfg(zcash_unstable = "nu8")]
use zcash_protocol::constants::MAX_BLOCK_BYTES;

use crate::transaction::{
    TxVersion,
    bytes::transparent::{
        LegacyTransparentBundleBytes, LegacyTransparentInputBytes, TransparentOutPointBytes,
        TransparentOutputBytes, TransparentOutputValueBytes, TransparentScriptBytes,
    },
    bytes::*,
};
#[cfg(zcash_unstable = "nu8")]
use crate::transaction::{
    bytes::transparent::{
        TransparentAuthBytes, TransparentBundleBytes, TransparentEffectsBytes,
        TransparentInputAuthBytes, TransparentInputEffectingBytes, TransparentSighashInfoBytes,
    },
    zip248::{
        self, BundleId, LevelOfSupport, MinerSignal, POLL_DIGEST_SIZE, PollDigest, SignalCode,
    },
};

fn outpoint(byte: u8, index: u32) -> TransparentOutPointBytes {
    TransparentOutPointBytes::from_parts(crate::transaction::TxId::from_bytes([byte; 32]), index)
}

/// The fixed part of an Orchard proof's length (ZIP 248).
#[cfg(zcash_unstable = "nu8")]
const ORCHARD_PROOF_BASE_SIZE: usize = 2720;

/// The length that each action adds to an Orchard proof (ZIP 248).
#[cfg(zcash_unstable = "nu8")]
const ORCHARD_PROOF_PER_ACTION_SIZE: usize = 2272;

/// Returns a placeholder Orchard proof of the length required for `n_actions` actions.
#[cfg(zcash_unstable = "nu8")]
fn orchard_proof(n_actions: usize) -> Vec<u8> {
    vec![0u8; ORCHARD_PROOF_BASE_SIZE + ORCHARD_PROOF_PER_ACTION_SIZE * n_actions]
}

fn output(value: i64, script: &[u8]) -> TransparentOutputBytes {
    TransparentOutputBytes::from_parts(
        TransparentOutputValueBytes::from_i64(value),
        TransparentScriptBytes::from_bytes(script.to_vec()),
    )
}

fn legacy_transparent() -> LegacyTransparentBundleBytes {
    LegacyTransparentBundleBytes::from_parts(
        vec![LegacyTransparentInputBytes::from_parts(
            outpoint(1, 2),
            TransparentScriptBytes::from_bytes(vec![0x51]),
            3,
        )],
        vec![output(1000, &[0x51, 0x52])],
    )
}

fn sprout_bundle(use_groth: bool) -> SproutBundleBytes {
    let proof = if use_groth {
        SproutProofBytes::Groth([0u8; 192])
    } else {
        SproutProofBytes::Phgr([0u8; 296])
    };
    SproutBundleBytes::from_parts(
        vec![SproutJoinSplitBytes::from_parts(
            0,
            0,
            [0u8; 32],
            [[0u8; 32]; 2],
            [[0u8; 32]; 2],
            [0u8; 32],
            [0u8; 32],
            [[0u8; 32]; 2],
            proof,
            [[0u8; 601]; 2],
        )],
        [0u8; 32],
        [0u8; 64],
    )
    .unwrap()
}

fn v4_sapling() -> V4SaplingBundleBytes {
    V4SaplingBundleBytes::from_parts(
        0,
        vec![SaplingSpendV4Bytes::from_parts(
            [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 192], [0u8; 64],
        )],
        vec![SaplingOutputV4Bytes::from_parts(
            [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80], [0u8; 192],
        )],
    )
}

fn sapling_bundle() -> SaplingBundleBytes {
    SaplingBundleBytes::from_parts(
        vec![SaplingSpendBytes::from_parts(
            [0u8; 32], [0u8; 32], [0u8; 32],
        )],
        vec![SaplingOutputBytes::from_parts(
            [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
        )],
        0,
        Some([0u8; 32]),
        vec![[0u8; 192]],
        vec![[0u8; 64]],
        vec![[0u8; 192]],
        Some([0u8; 64]),
    )
    .unwrap()
}

fn orchard_bundle() -> OrchardBundleBytes {
    OrchardBundleBytes::from_parts(
        vec![OrchardActionBytes::from_parts(
            [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
        )],
        0,
        0,
        [0u8; 32],
        vec![0u8; 32],
        vec![[0u8; 64]],
        [0u8; 64],
    )
    .unwrap()
}

fn legacy_tx(version: TxVersion, body: LegacyTransactionBodyBytes) -> TransactionBytes {
    let expiry = if version.has_overwinter() {
        BlockHeight::from(100u32)
    } else {
        BlockHeight::from(0u32)
    };
    TransactionBytes::from_parts(version, None, 0, expiry, TransactionBodyBytes::Legacy(body))
        .unwrap()
}

fn round_trip(tx: &TransactionBytes) {
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    let decoded = TransactionBytes::read(&encoded[..]).unwrap();
    assert_eq!(&decoded, tx);
}

#[test]
fn legacy_v1_round_trip() {
    let body = LegacyTransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        None,
        None,
        None,
    )
    .unwrap();
    round_trip(&legacy_tx(TxVersion::Sprout(1), body));
}

#[test]
fn legacy_v2_round_trip() {
    let body = LegacyTransactionBodyBytes::from_parts(
        legacy_transparent(),
        None,
        Some(sprout_bundle(false)),
        None,
    )
    .unwrap();
    round_trip(&legacy_tx(TxVersion::Sprout(2), body));
}

#[test]
fn legacy_v3_round_trip() {
    let body = LegacyTransactionBodyBytes::from_parts(
        legacy_transparent(),
        None,
        Some(sprout_bundle(false)),
        None,
    )
    .unwrap();
    round_trip(&legacy_tx(TxVersion::V3, body));
}

#[test]
fn legacy_v4_round_trip() {
    let body = LegacyTransactionBodyBytes::from_parts(
        legacy_transparent(),
        Some(v4_sapling()),
        Some(sprout_bundle(true)),
        Some([0u8; 64]),
    )
    .unwrap();
    round_trip(&legacy_tx(TxVersion::V4, body));
}

#[test]
fn typed_legacy_reader_hashes_version_and_leaves_trailer() {
    /// Bytes belonging to the next record in the stream.
    const TRAILER: &[u8] = b"next-transaction";

    for version in [
        TxVersion::Sprout(1),
        TxVersion::Sprout(2),
        TxVersion::V3,
        TxVersion::V4,
    ] {
        let body = LegacyTransactionBodyBytes::from_parts(
            legacy_transparent(),
            version
                .has_sapling()
                .then(|| V4SaplingBundleBytes::from_parts(0, vec![], vec![])),
            version
                .has_sprout()
                .then(|| sprout_bundle(version.has_sapling())),
            None,
        )
        .unwrap();
        let bytes = legacy_tx(version, body);
        let mut encoded = Vec::new();
        bytes.write(&mut encoded).unwrap();
        let mut hasher = crate::transaction::util::sha256d::HashWriter::default();
        bytes.write(&mut hasher).unwrap();
        let expected: [u8; 32] = hasher.into_hash().into();

        encoded.extend_from_slice(TRAILER);
        let mut reader = encoded.as_slice();
        let tx = crate::transaction::Transaction::read(&mut reader, BranchId::Sapling).unwrap();
        assert_eq!(tx.txid().as_ref(), &expected);
        assert_eq!(reader, TRAILER);
    }
}

#[test]
fn legacy_v3_rejects_groth_sprout_proof() {
    let body = LegacyTransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        None,
        Some(sprout_bundle(true)),
        None,
    )
    .unwrap();
    assert!(
        TransactionBytes::from_parts(
            TxVersion::V3,
            None,
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::Legacy(body),
        )
        .is_err()
    );
}

#[test]
fn legacy_v4_rejects_phgr_sprout_proof() {
    let body = LegacyTransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        Some(v4_sapling()),
        Some(sprout_bundle(false)),
        Some([0u8; 64]),
    )
    .unwrap();
    assert!(
        TransactionBytes::from_parts(
            TxVersion::V4,
            None,
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::Legacy(body),
        )
        .is_err()
    );
}

#[test]
fn transaction_bytes_read_write_round_trip() {
    let body = LegacyTransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        None,
        None,
        None,
    )
    .unwrap();
    let tx: TransactionBytes = TransactionBytes::from_parts(
        TxVersion::Sprout(1),
        None,
        0,
        BlockHeight::from(0u32),
        TransactionBodyBytes::Legacy(body),
    )
    .unwrap();
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    let decoded = TransactionBytes::read(&encoded[..]).unwrap();
    assert_eq!(decoded, tx);
}

#[test]
fn v5_round_trip() {
    let body = V5TransactionBodyBytes::from_parts(
        legacy_transparent(),
        Some(sapling_bundle()),
        Some(orchard_bundle()),
    );
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    round_trip(&tx);
}

#[test]
fn v6_round_trip() {
    let body = V6TransactionBodyBytes::from_parts(
        legacy_transparent(),
        Some(sapling_bundle()),
        Some(orchard_bundle()),
        Some(orchard_bundle()),
    );
    let tx = TransactionBytes::from_parts(
        TxVersion::V6,
        Some(u32::from(BranchId::Nu6_3)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V6(body),
    )
    .unwrap();
    round_trip(&tx);
}

#[test]
fn v5_empty_round_trip() {
    let body =
        V5TransactionBodyBytes::from_parts(LegacyTransparentBundleBytes::default(), None, None);
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    round_trip(&tx);
}

#[test]
fn v5_outputs_only_round_trip() {
    let transparent = LegacyTransparentBundleBytes::from_parts(vec![], vec![output(1000, &[0x51])]);
    let body = V5TransactionBodyBytes::from_parts(transparent, None, None);
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    round_trip(&tx);
}

#[test]
fn v5_sapling_outputs_only_round_trip() {
    let sapling = SaplingBundleBytes::from_parts(
        vec![],
        vec![SaplingOutputBytes::from_parts(
            [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
        )],
        0,
        None,
        vec![],
        vec![],
        vec![[0u8; 192]],
        Some([0u8; 64]),
    )
    .unwrap();
    let body = V5TransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        Some(sapling),
        None,
    );
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    round_trip(&tx);
}

#[test]
fn v6_empty_round_trip() {
    let body = V6TransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        None,
        None,
        None,
    );
    let tx = TransactionBytes::from_parts(
        TxVersion::V6,
        Some(u32::from(BranchId::Nu6_3)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V6(body),
    )
    .unwrap();
    round_trip(&tx);
}

#[test]
fn v6_outputs_only_round_trip() {
    let transparent = LegacyTransparentBundleBytes::from_parts(vec![], vec![output(1000, &[0x51])]);
    let body = V6TransactionBodyBytes::from_parts(transparent, None, None, None);
    let tx = TransactionBytes::from_parts(
        TxVersion::V6,
        Some(u32::from(BranchId::Nu6_3)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V6(body),
    )
    .unwrap();
    round_trip(&tx);
}

#[test]
fn legacy_truncation_is_rejected() {
    let body = LegacyTransactionBodyBytes::from_parts(
        legacy_transparent(),
        Some(v4_sapling()),
        Some(sprout_bundle(true)),
        Some([0u8; 64]),
    )
    .unwrap();
    let tx = legacy_tx(TxVersion::V4, body);
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    for len in 0..encoded.len() {
        assert!(
            TransactionBytes::read(&encoded[..len]).is_err(),
            "truncation at {len} bytes was accepted"
        );
    }
}

#[test]
fn v5_truncation_is_rejected() {
    let body = V5TransactionBodyBytes::from_parts(
        legacy_transparent(),
        Some(sapling_bundle()),
        Some(orchard_bundle()),
    );
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    for len in 0..encoded.len() {
        assert!(
            TransactionBytes::read(&encoded[..len]).is_err(),
            "truncation at {len} bytes was accepted"
        );
    }
}

#[test]
fn excessive_counts_do_not_allocate() {
    // A claimed vector count with no elements behind it must fail on the first
    // element read, not by reserving for the claimed count.
    let mut encoded = Vec::new();
    CompactSize::write(&mut encoded, 0x0200_0000).unwrap();
    assert!(LegacyTransparentBundleBytes::read(&encoded[..]).is_err());

    let mut encoded = Vec::new();
    CompactSize::write(&mut encoded, 0x0200_0000).unwrap();
    assert!(SaplingBundleBytes::read(&encoded[..]).is_err());

    let mut encoded = Vec::new();
    CompactSize::write(&mut encoded, 0x0200_0000).unwrap();
    assert!(OrchardBundleBytes::read(&encoded[..]).is_err());
}

#[test]
fn transaction_rejects_version_body_mismatch() {
    let body =
        V5TransactionBodyBytes::from_parts(LegacyTransparentBundleBytes::default(), None, None);
    assert!(
        TransactionBytes::from_parts(
            TxVersion::V6,
            Some(u32::from(BranchId::Nu6_3)),
            0,
            BlockHeight::from(0u32),
            TransactionBodyBytes::V5(body),
        )
        .is_err()
    );
}

#[test]
fn transparent_only_typed_v5_round_trip() {
    let body = V5TransactionBodyBytes::from_parts(legacy_transparent(), None, None);
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    let mut wire = Vec::new();
    tx.write(&mut wire).unwrap();

    let typed = crate::transaction::Transaction::read(&wire[..], BranchId::Nu5).unwrap();
    let mut reserialized = Vec::new();
    typed.write(&mut reserialized).unwrap();
    assert_eq!(reserialized, wire);
}

#[cfg(not(feature = "sapling"))]
#[test]
fn typed_read_rejects_disabled_sapling_bundle() {
    let body = V5TransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        Some(sapling_bundle()),
        None,
    );
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    let mut wire = Vec::new();
    tx.write(&mut wire).unwrap();

    let error = crate::transaction::Transaction::read(&wire[..], BranchId::Nu5).unwrap_err();
    assert!(alloc::format!("{error:?}").contains("Sapling support is disabled"));
}

#[cfg(not(feature = "orchard"))]
#[test]
fn typed_read_rejects_disabled_orchard_bundle() {
    let body = V5TransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        None,
        Some(orchard_bundle()),
    );
    let tx = TransactionBytes::from_parts(
        TxVersion::V5,
        Some(u32::from(BranchId::Nu5)),
        0,
        BlockHeight::from(100u32),
        TransactionBodyBytes::V5(body),
    )
    .unwrap();
    let mut wire = Vec::new();
    tx.write(&mut wire).unwrap();

    let error = crate::transaction::Transaction::read(&wire[..], BranchId::Nu5).unwrap_err();
    assert!(alloc::format!("{error:?}").contains("Orchard support is disabled"));
}

#[cfg(zcash_unstable = "nu8")]
mod v7 {
    use alloc::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;
    use crate::transaction::{
        Authorized, Transaction, TransactionData,
        zip248::{SuppliedBundleDigests, V7DigestError},
    };

    fn v7_transparent() -> TransparentBundleBytes {
        let effects = TransparentEffectsBytes::from_parts(
            vec![TransparentInputEffectingBytes::from_parts(
                outpoint(1, 2),
                3,
            )],
            vec![output(1000, &[0x51])],
        );
        let auth = TransparentAuthBytes::from_parts(vec![TransparentInputAuthBytes::from_parts(
            TransparentSighashInfoBytes::v0(),
            TransparentScriptBytes::from_bytes(vec![0x51]),
        )]);
        TransparentBundleBytes::from_parts(effects, Some(auth)).unwrap()
    }

    fn v7_transparent_effect_only() -> TransparentBundleBytes {
        let effects = TransparentEffectsBytes::from_parts(
            vec![TransparentInputEffectingBytes::from_parts(
                outpoint(1, 2),
                3,
            )],
            vec![output(1000, &[0x51])],
        );
        TransparentBundleBytes::from_parts(effects, None).unwrap()
    }

    fn miner_signal(signal_code: u8, level_of_support: u8) -> MinerSignal {
        MinerSignal::from_parts(
            SignalCode::new(signal_code),
            LevelOfSupport::new(level_of_support),
        )
    }

    fn poll_digest(byte: u8) -> PollDigest {
        PollDigest::new([byte; POLL_DIGEST_SIZE])
    }

    fn v7_coinbase() -> CoinbaseBundleBytes {
        CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![0x51],
            vec![miner_signal(3, 0x80)],
            Some(poll_digest(0x7E)),
        )
        .unwrap()
    }

    fn v7_sapling() -> V7SaplingBundleBytes {
        V7SaplingBundleBytes::from_parts(
            vec![SaplingSpendBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32],
            )],
            vec![SaplingOutputBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )],
        )
    }

    fn v7_sapling_auth() -> V7SaplingAuthBytes {
        V7SaplingAuthBytes::from_parts(
            Some([0u8; 32]),
            vec![[0u8; 192]],
            vec![SaplingSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )],
            vec![[0u8; 192]],
            Some(SaplingSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )),
        )
    }

    fn v7_sapling_effect_only() -> V7SaplingBundleBytes {
        v7_sapling()
    }

    fn v7_orchard() -> V7OrchardBundleBytes {
        V7OrchardBundleBytes::from_parts(
            vec![OrchardActionBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )],
            0,
        )
    }

    fn v7_orchard_auth() -> V7OrchardAuthBytes {
        V7OrchardAuthBytes::from_parts(
            Some([0u8; 32]),
            orchard_proof(1),
            vec![OrchardSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )],
            Some(OrchardSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )),
        )
    }

    fn v7_orchard_effect_only() -> V7OrchardBundleBytes {
        v7_orchard()
    }

    fn v7_sapling_empty() -> V7SaplingBundleBytes {
        V7SaplingBundleBytes::from_parts(vec![], vec![])
    }

    fn v7_sapling_empty_auth() -> V7SaplingAuthBytes {
        V7SaplingAuthBytes::from_parts(None, vec![], vec![], vec![], None)
    }

    fn v7_orchard_empty() -> V7OrchardBundleBytes {
        V7OrchardBundleBytes::from_parts(vec![], 0)
    }

    fn v7_orchard_empty_auth() -> V7OrchardAuthBytes {
        V7OrchardAuthBytes::from_parts(None, vec![], vec![], None)
    }

    fn zec_delta(bundle_type: u64, value: i64) -> ValuePoolDeltaBytes {
        ValuePoolDeltaBytes::from_parts(
            BundleType::from_u64(bundle_type),
            BundleVariant::from_u64(0),
            value,
        )
        .unwrap()
    }

    fn v7_body(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        effect_bundles: Vec<V7EffectBundleBytes>,
    ) -> V7TransactionBodyBytes {
        v7_body_with_auth(value_pool_deltas, effect_bundles, vec![])
    }

    fn v7_body_with_auth(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        effect_bundles: Vec<V7EffectBundleBytes>,
        auth_bundles: Vec<V7AuthBundleBytes>,
    ) -> V7TransactionBodyBytes {
        V7TransactionBodyBytes::from_parts(value_pool_deltas, effect_bundles, auth_bundles).unwrap()
    }

    fn split_transparent(
        bundle: TransparentBundleBytes,
    ) -> (V7EffectBundleBytes, Option<V7AuthBundleBytes>) {
        let effects = V7EffectBundleBytes::Transparent(bundle.effects().clone());
        let auth = bundle.auth().cloned().map(V7AuthBundleBytes::Transparent);
        (effects, auth)
    }

    fn v7_tx(body: V7TransactionBodyBytes) -> TransactionBytes {
        TransactionBytes::from_parts(
            TxVersion::V7,
            Some(u32::from(BranchId::Nu8)),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body),
        )
        .unwrap()
    }

    fn round_trip(body: &V7TransactionBodyBytes) {
        let mut encoded = Vec::new();
        body.write(&mut encoded).unwrap();
        let effects = body
            .effect_bundles()
            .iter()
            .map(|bundle| {
                let mut payload = Vec::new();
                bundle.write_effects(&mut payload).unwrap();
                (
                    bundle.bundle_type().to_u64(),
                    bundle.bundle_variant().to_u64(),
                    payload,
                )
            })
            .collect::<Vec<_>>();
        let auth = body
            .auth_bundles()
            .iter()
            .map(|bundle| {
                let mut payload = Vec::new();
                bundle.write_auth(&mut payload).unwrap();
                (
                    bundle.bundle_type().to_u64(),
                    bundle.bundle_variant().to_u64(),
                    payload,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(encoded, wire(body.value_pool_deltas(), &effects, &auth));
        let decoded = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert_eq!(&decoded, body);
    }

    fn wire(
        value_pool_deltas: &[ValuePoolDeltaBytes],
        effect_bundles: &[(u64, u64, Vec<u8>)],
        auth_bundles: &[(u64, u64, Vec<u8>)],
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, value_pool_deltas.len()).unwrap();
        for entry in value_pool_deltas {
            entry.write(&mut encoded).unwrap();
        }
        CompactSize::write(&mut encoded, effect_bundles.len()).unwrap();
        for (bundle_type, bundle_variant, data) in effect_bundles {
            write_bundle_data_framing(
                &mut encoded,
                zip248::BundleId::new(
                    BundleType::from_u64(*bundle_type),
                    BundleVariant::from_u64(*bundle_variant),
                ),
                data,
            )
            .unwrap();
        }
        CompactSize::write(&mut encoded, auth_bundles.len()).unwrap();
        for (bundle_type, bundle_variant, data) in auth_bundles {
            write_bundle_data_framing(
                &mut encoded,
                zip248::BundleId::new(
                    BundleType::from_u64(*bundle_type),
                    BundleVariant::from_u64(*bundle_variant),
                ),
                data,
            )
            .unwrap();
        }
        encoded
    }

    fn payloads(
        bundle: &V7EffectBundleBytes,
        authorizing: Option<&V7AuthBundleBytes>,
    ) -> (Vec<u8>, Option<Vec<u8>>) {
        let mut effects = Vec::new();
        bundle.write_effects(&mut effects).unwrap();
        let auth = authorizing.map(|authorizing| {
            let mut payload = Vec::new();
            authorizing.write_auth(&mut payload).unwrap();
            payload
        });
        (effects, auth)
    }

    #[test]
    fn v7_round_trip_known() {
        let (transparent_effects, transparent_auth) = split_transparent(v7_transparent());
        let body = v7_body_with_auth(
            vec![
                zec_delta(0, -1000),
                zec_delta(1, 1_000_000),
                zec_delta(2, 1),
                zec_delta(3, 1),
                zec_delta(4, 1),
            ],
            vec![
                transparent_effects,
                V7EffectBundleBytes::Coinbase(v7_coinbase()),
                V7EffectBundleBytes::Sapling(v7_sapling()),
                V7EffectBundleBytes::Orchard(v7_orchard()),
                V7EffectBundleBytes::Ironwood(v7_orchard()),
            ],
            vec![
                transparent_auth.unwrap(),
                V7AuthBundleBytes::Sapling(v7_sapling_auth()),
                V7AuthBundleBytes::Orchard(v7_orchard_auth()),
                V7AuthBundleBytes::Ironwood(v7_orchard_auth()),
            ],
        );
        round_trip(&body);
        round_trip(&v7_tx(body).body().as_v7().unwrap().clone());
    }

    #[test]
    fn v7_effect_only_bundles_round_trip() {
        let body = v7_body(
            vec![
                zec_delta(0, -1000),
                zec_delta(2, 1),
                zec_delta(3, 1),
                zec_delta(4, 1),
            ],
            vec![
                split_transparent(v7_transparent_effect_only()).0,
                V7EffectBundleBytes::Sapling(v7_sapling_effect_only()),
                V7EffectBundleBytes::Orchard(v7_orchard_effect_only()),
                V7EffectBundleBytes::Ironwood(v7_orchard_effect_only()),
            ],
        );
        round_trip(&body);
        assert!(body.auth_bundles().is_empty());
    }

    #[test]
    fn v7_effect_only_bundles_omit_auth_map() {
        let body = v7_body(
            vec![],
            vec![
                split_transparent(v7_transparent_effect_only()).0,
                V7EffectBundleBytes::Sapling(v7_sapling_effect_only()),
                V7EffectBundleBytes::Orchard(v7_orchard_effect_only()),
                V7EffectBundleBytes::Ironwood(v7_orchard_effect_only()),
            ],
        );
        let mut encoded = Vec::new();
        body.write(&mut encoded).unwrap();
        let decoded = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert!(decoded.auth_bundles().is_empty());
    }

    #[test]
    fn v7_round_trip_unknown() {
        let id = zip248::BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0));
        let unknown_effects = OpaqueEffectBundleBytes::from_parts(id, vec![1, 2, 3]).unwrap();
        let unknown_auth = OpaqueAuthBundleBytes::from_parts(id, vec![4, 5]).unwrap();
        let known_variant = OpaqueEffectBundleBytes::from_parts(
            zip248::BundleId::new(BundleType::from_u64(2), BundleVariant::from_u64(1)),
            vec![6, 7],
        )
        .unwrap();
        let value_only = OpaqueEffectBundleBytes::from_parts(
            zip248::BundleId::new(BundleType::from_u64(5), BundleVariant::from_u64(0)),
            vec![0x00],
        )
        .unwrap();
        let body = v7_body_with_auth(
            vec![zec_delta(5, -1000)],
            vec![
                V7EffectBundleBytes::Opaque(known_variant),
                V7EffectBundleBytes::Opaque(value_only),
                V7EffectBundleBytes::Opaque(unknown_effects),
            ],
            vec![V7AuthBundleBytes::Opaque(unknown_auth)],
        );
        round_trip(&body);
    }

    #[test]
    fn v7_known_type_unknown_variant_is_distinct_from_unknown_type() {
        let known_variant = OpaqueEffectBundleBytes::from_parts(
            zip248::BundleId::new(BundleType::from_u64(2), BundleVariant::from_u64(1)),
            vec![1],
        )
        .unwrap();
        let unknown = OpaqueEffectBundleBytes::from_parts(
            zip248::BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0)),
            vec![1],
        )
        .unwrap();
        let body = v7_body(
            vec![],
            vec![
                V7EffectBundleBytes::Opaque(known_variant),
                V7EffectBundleBytes::Opaque(unknown),
            ],
        );
        let mut encoded = Vec::new();
        body.write(&mut encoded).unwrap();
        let decoded = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded.effect_bundles()[0].bundle_variant().to_u64(), 1);
        assert_eq!(decoded.effect_bundles()[1].bundle_type().to_u64(), 99);
        assert!(
            decoded
                .effect_bundles()
                .iter()
                .all(|bundle| matches!(bundle, V7EffectBundleBytes::Opaque(_)))
        );
    }

    #[test]
    fn v7_value_pool_deltas_round_trip() {
        let body = v7_body(vec![zec_delta(0, -1), zec_delta(2, 2)], vec![]);
        round_trip(&body);

        let typed = body.to_value_pool_deltas().unwrap();
        let (&bundle_type, &(variant, value)) = typed
            .iter()
            .find(|(bundle_type, _)| **bundle_type == BundleType::from_u64(2))
            .expect("the entry is retained");
        assert_eq!(bundle_type, BundleType::from_u64(2));
        assert_eq!(variant, BundleVariant::DEFAULT);
        assert_eq!(
            value,
            zcash_protocol::value::ZatBalance::from_i64(2).unwrap()
        );
    }

    /// The wire encoding of a delta is exactly two one-byte compact sizes
    /// followed by the eight value bytes, with no asset discriminant.
    #[test]
    fn v7_value_pool_delta_wire_has_no_asset_discriminant() {
        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, 1).unwrap();
        CompactSize::write(&mut encoded, 2).unwrap();
        CompactSize::write(&mut encoded, 0).unwrap();
        encoded.extend_from_slice(&5i64.to_le_bytes());
        CompactSize::write(&mut encoded, 0).unwrap(); // nEffectBundles
        CompactSize::write(&mut encoded, 0).unwrap(); // nAuthBundles

        let decoded = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded.value_pool_deltas().len(), 1);
        assert_eq!(decoded.value_pool_deltas()[0].bundle_type().to_u64(), 2);
        assert_eq!(decoded.value_pool_deltas()[0].value(), 5);
    }

    #[test]
    fn v7_rejects_misordered_value_pool_deltas() {
        let encoded = wire(&[zec_delta(2, 1), zec_delta(0, 1)], &[], &[]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_duplicate_value_pool_deltas() {
        let encoded = wire(&[zec_delta(2, 1), zec_delta(2, 2)], &[], &[]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    /// A duplicate bundle type is rejected even when the variant differs.
    #[test]
    fn v7_rejects_duplicate_type_with_different_variant() {
        let duplicate =
            ValuePoolDeltaBytes::from_parts(BundleType::from_u64(2), BundleVariant::from_u64(1), 2)
                .unwrap();
        let encoded = wire(&[zec_delta(2, 1), duplicate], &[], &[]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_zero_value_pool_delta() {
        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, 1).unwrap();
        CompactSize::write(&mut encoded, 2).unwrap();
        CompactSize::write(&mut encoded, 0).unwrap();
        encoded.extend_from_slice(&0i64.to_le_bytes());
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_variant_mismatch() {
        let (effects, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        let encoded = wire(
            &[zec_delta(2, 1)],
            &[(2, 0, effects)],
            &[(2, 1, auth.unwrap())],
        );
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_auth_without_effect() {
        let (_, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        let encoded = wire(&[], &[], &[(2, 0, auth.unwrap())]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    /// An opaque authorizing payload for a bundle that also has a recognized
    /// effecting payload serializes bytes the reader would interpret, so
    /// construction rejects it.
    fn opaque_auth(bundle_type: BundleType, payload: Vec<u8>) -> V7AuthBundleBytes {
        V7AuthBundleBytes::Opaque(
            OpaqueAuthBundleBytes::from_parts(
                BundleId::new(bundle_type, BundleVariant::DEFAULT),
                payload,
            )
            .unwrap(),
        )
    }

    fn opaque_effect(bundle_type: BundleType, payload: Vec<u8>) -> V7EffectBundleBytes {
        V7EffectBundleBytes::Opaque(
            OpaqueEffectBundleBytes::from_parts(
                BundleId::new(bundle_type, BundleVariant::DEFAULT),
                payload,
            )
            .unwrap(),
        )
    }

    fn retained_constructor(
        effects: BTreeMap<BundleType, V7EffectBundleBytes>,
        auth: BTreeMap<BundleType, V7AuthBundleBytes>,
        coinbase: Option<zip248::CoinbaseBundle>,
    ) -> io::Result<TransactionData<Authorized>> {
        TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            BlockHeight::from(100u32),
            zip248::ValuePoolDeltas::empty(),
            None,
            None,
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
            #[cfg(feature = "orchard")]
            None,
            coinbase,
            effects,
            auth,
        )
    }

    #[test]
    fn retained_v7_auth_only_coinbase_preserves_typed_effect() {
        let coinbase = v7_coinbase();
        let auth = opaque_auth(BundleType::COINBASE, vec![0x00, 0xAA, 0xFF]);
        let bytes = v7_tx(v7_body_with_auth(
            vec![],
            vec![V7EffectBundleBytes::Coinbase(coinbase.clone())],
            vec![auth.clone()],
        ));
        let data = TransactionData::from_bytes(bytes.clone(), BranchId::Nu8).unwrap();
        assert_eq!(
            data.coinbase_bundle(),
            Some(&coinbase.to_coinbase_bundle().unwrap())
        );
        assert!(data.uninterpreted_effect_bundles().is_empty());
        assert_eq!(
            data.uninterpreted_auth_bundles(),
            &BTreeMap::from([(BundleType::COINBASE, auth.clone())]),
        );
        assert_eq!(
            data.clone().freeze().unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
        );
        let mut wire = Vec::new();
        bytes.write(&mut wire).unwrap();
        let parsed = Transaction::read(&wire[..], BranchId::Nu8).unwrap();
        assert_eq!(parsed.txid(), bytes.v7_txid(&()).unwrap());
        let key = auth.digest_key();
        assert_eq!(
            parsed.auth_commitment(&()),
            Err(V7DigestError::MissingAuthDigest { key }),
        );
        let mut provider = SuppliedBundleDigests::new();
        provider
            .insert_auth(
                key,
                blake2b_simd::Params::new().hash_length(32).hash(&[0xAA]),
            )
            .unwrap();
        assert_eq!(
            parsed.auth_commitment(&provider).unwrap(),
            bytes.v7_auth_commitment(&provider).unwrap(),
        );
        let mut output = Vec::new();
        assert!(parsed.write(&mut output).is_err());
        assert!(output.is_empty());
        assert_eq!(TransactionBytes::read(&wire[..]).unwrap(), bytes);
        #[cfg(all(feature = "sapling", feature = "orchard"))]
        assert_eq!(
            data.check_v7_consensus_rules(),
            Err(crate::transaction::V7ConsensusError::UnsupportedBundles),
        );
    }

    #[test]
    fn retained_v7_constructor_accepts_typed_coinbase_with_retained_auth() {
        let coinbase = v7_coinbase().to_coinbase_bundle().unwrap();
        let auth = opaque_auth(BundleType::COINBASE, vec![0xAA]);
        let data = retained_constructor(
            BTreeMap::new(),
            BTreeMap::from([(BundleType::COINBASE, auth.clone())]),
            Some(coinbase.clone()),
        )
        .unwrap();
        assert_eq!(data.coinbase_bundle(), Some(&coinbase));
        assert!(data.uninterpreted_effect_bundles().is_empty());
        assert_eq!(
            data.uninterpreted_auth_bundles(),
            &BTreeMap::from([(BundleType::COINBASE, auth)]),
        );
    }

    #[test]
    fn retained_v7_constructor_rejects_auth_without_any_matching_effect() {
        for bundle_type in [BundleType::COINBASE, BundleType::from_u64(99)] {
            let auth = opaque_auth(bundle_type, vec![0xAA]);
            assert_eq!(
                retained_constructor(BTreeMap::new(), BTreeMap::from([(bundle_type, auth)]), None,)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
            );
        }
    }

    #[test]
    fn retained_v7_constructor_rejects_recognized_effect_with_opaque_auth() {
        let (effects, _) = split_transparent(v7_transparent());
        assert_eq!(
            retained_constructor(
                BTreeMap::from([(BundleType::TRANSPARENT, effects)]),
                BTreeMap::from([(
                    BundleType::TRANSPARENT,
                    opaque_auth(BundleType::TRANSPARENT, vec![0xAA]),
                )]),
                None,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput,
        );
    }

    #[test]
    fn retained_v7_constructor_rejects_recognized_pair_count_mismatch() {
        let (effects, _) = split_transparent(v7_transparent());
        let auth = V7AuthBundleBytes::Transparent(TransparentAuthBytes::from_parts(vec![]));
        assert_eq!(
            retained_constructor(
                BTreeMap::from([(BundleType::TRANSPARENT, effects)]),
                BTreeMap::from([(BundleType::TRANSPARENT, auth)]),
                None,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput,
        );
    }

    #[test]
    fn retained_v7_supported_payload_domain_errors_are_not_retained() {
        let bytes = v7_tx(v7_body(
            vec![],
            vec![V7EffectBundleBytes::Transparent(
                TransparentEffectsBytes::from_parts(vec![], vec![output(-1, &[0x51])]),
            )],
        ));
        assert_eq!(
            TransactionData::from_bytes(bytes, BranchId::Nu8)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
        );
    }

    #[cfg(any(not(feature = "sapling"), not(feature = "orchard")))]
    #[test]
    fn retained_v7_disabled_protocol_entries_preserve_exact_bytes() {
        let fixtures = [
            #[cfg(not(feature = "sapling"))]
            (
                V7EffectBundleBytes::Sapling(v7_sapling()),
                V7AuthBundleBytes::Sapling(v7_sapling_auth()),
            ),
            #[cfg(not(feature = "orchard"))]
            (
                V7EffectBundleBytes::Orchard(v7_orchard()),
                V7AuthBundleBytes::Orchard(v7_orchard_auth()),
            ),
            #[cfg(not(feature = "orchard"))]
            (
                V7EffectBundleBytes::Ironwood(v7_orchard()),
                V7AuthBundleBytes::Ironwood(v7_orchard_auth()),
            ),
        ];
        for (effect, auth) in fixtures {
            let bundle_type = effect.bundle_type();
            let bytes = v7_tx(v7_body_with_auth(
                vec![],
                vec![effect.clone()],
                vec![auth.clone()],
            ));
            let data = TransactionData::from_bytes(bytes.clone(), BranchId::Nu8).unwrap();
            assert_eq!(
                data.uninterpreted_effect_bundles(),
                &BTreeMap::from([(bundle_type, effect)]),
            );
            assert_eq!(
                data.uninterpreted_auth_bundles(),
                &BTreeMap::from([(bundle_type, auth)]),
            );
            assert_eq!(
                data.freeze().unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
            );
            let mut wire = Vec::new();
            bytes.write(&mut wire).unwrap();
            assert_eq!(TransactionBytes::read(&wire[..]).unwrap(), bytes);
        }
    }

    #[test]
    fn v7_rejects_recognized_effect_with_opaque_auth() {
        for effect in [
            split_transparent(v7_transparent()).0,
            V7EffectBundleBytes::Sapling(v7_sapling()),
            V7EffectBundleBytes::Orchard(v7_orchard()),
            V7EffectBundleBytes::Ironwood(v7_orchard()),
        ] {
            let bundle_type = effect.bundle_type();
            assert!(
                V7TransactionBodyBytes::from_parts(
                    vec![],
                    vec![effect],
                    vec![opaque_auth(bundle_type, vec![0xAA])],
                )
                .is_err(),
                "bundleType {} accepted an opaque authorizing payload",
                bundle_type.to_u64(),
            );
        }
    }

    /// An authorizing payload that is opaque for an identifier with a
    /// recognized effecting codec is rejected by the effect/auth
    /// correspondence check, and the effect itself can no longer be opaque.
    #[test]
    fn v7_rejects_opaque_effect_with_recognized_auth() {
        for auth in [
            split_transparent(v7_transparent()).1.unwrap(),
            V7AuthBundleBytes::Sapling(v7_sapling_auth()),
            V7AuthBundleBytes::Orchard(v7_orchard_auth()),
            V7AuthBundleBytes::Ironwood(v7_orchard_auth()),
        ] {
            let bundle_type = auth.bundle_type();

            // The recognized effecting identifier cannot be supplied opaquely.
            assert!(
                OpaqueEffectBundleBytes::from_parts(
                    zip248::BundleId::new(bundle_type, BundleVariant::DEFAULT),
                    vec![0xAA],
                )
                .is_err(),
                "bundleType {} accepted an opaque effecting payload",
                bundle_type.to_u64(),
            );

            // A typed effect pairs with a typed authorizing payload only.
            let effect = match bundle_type {
                BundleType::TRANSPARENT => split_transparent(v7_transparent()).0,
                BundleType::SAPLING => V7EffectBundleBytes::Sapling(v7_sapling()),
                BundleType::ORCHARD => V7EffectBundleBytes::Orchard(v7_orchard()),
                _ => V7EffectBundleBytes::Ironwood(v7_orchard()),
            };
            assert!(
                V7TransactionBodyBytes::from_parts(
                    vec![],
                    vec![effect],
                    vec![opaque_auth(bundle_type, vec![0xAA])],
                )
                .is_err(),
                "bundleType {} accepted an opaque authorizing payload",
                bundle_type.to_u64(),
            );
        }
    }

    #[test]
    fn v7_rejects_cross_pool_orchard_ironwood_pairing() {
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Orchard(v7_orchard())],
                vec![V7AuthBundleBytes::Ironwood(v7_orchard_auth())],
            )
            .is_err()
        );
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Ironwood(v7_orchard())],
                vec![V7AuthBundleBytes::Orchard(v7_orchard_auth())],
            )
            .is_err()
        );
    }

    /// The deliberate exceptions still pair: the coinbase bundle has no
    /// authorizing data type, and entries opaque on both sides stay matched.
    #[test]
    fn v7_accepts_coinbase_opaque_auth_and_opaque_pairs() {
        let coinbase = v7_body_with_auth(
            vec![],
            vec![V7EffectBundleBytes::Coinbase(v7_coinbase())],
            vec![opaque_auth(BundleType::COINBASE, vec![0xAA])],
        );
        assert!(matches!(
            coinbase.auth_bundles()[0],
            V7AuthBundleBytes::Opaque(_)
        ));

        let opaque = v7_body_with_auth(
            vec![],
            vec![opaque_effect(BundleType::from_u64(99), vec![0xAA])],
            vec![opaque_auth(BundleType::from_u64(99), vec![0xBB])],
        );
        assert!(opaque.effect_bundles()[0].as_opaque().is_some());
        assert!(opaque.auth_bundles()[0].as_opaque().is_some());
    }

    #[test]
    fn v7_rejects_duplicate_effect_bundle_types() {
        let (effects, _) = payloads(&V7EffectBundleBytes::Sapling(v7_sapling()), None);
        let encoded = wire(&[], &[(2, 0, effects.clone()), (2, 0, effects)], &[]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_duplicate_auth_bundle_types() {
        let (effects, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        let auth = auth.unwrap();
        let encoded = wire(
            &[],
            &[(2, 0, effects)],
            &[(2, 0, auth.clone()), (2, 0, auth)],
        );
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_misordered_auth_bundles() {
        let (transparent_effects, transparent_auth) = split_transparent(v7_transparent());
        let (transparent_effects, transparent_auth) =
            payloads(&transparent_effects, transparent_auth.as_ref());
        let (sapling_effects, sapling_auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        let encoded = wire(
            &[],
            &[(0, 0, transparent_effects), (2, 0, sapling_effects)],
            &[
                (2, 0, sapling_auth.unwrap()),
                (0, 0, transparent_auth.unwrap()),
            ],
        );
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_variant_conflict_between_value_pool_delta_and_effects() {
        let (effects, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        // The value pool delta names variant 1 while both bundle maps name the
        // default variant.
        let delta =
            ValuePoolDeltaBytes::from_parts(BundleType::SAPLING, BundleVariant::from_u64(1), 1)
                .unwrap();
        let encoded = wire(&[delta], &[(2, 0, effects)], &[(2, 0, auth.unwrap())]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_trailing_effect_payload() {
        let (mut effects, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        effects.push(0);
        let encoded = wire(&[], &[(2, 0, effects)], &[(2, 0, auth.unwrap())]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_trailing_auth_payload() {
        let (effects, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        let mut auth = auth.unwrap();
        auth.push(0);
        let encoded = wire(&[], &[(2, 0, effects)], &[(2, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_transparent_auth_count_mismatch() {
        let (effects, auth) = payloads(
            &split_transparent(v7_transparent()).0,
            split_transparent(v7_transparent()).1.as_ref(),
        );
        let mut auth = auth.unwrap();
        // Drop the single authorizing entry.
        auth.clear();
        let encoded = wire(&[], &[(0, 0, effects)], &[(0, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_sapling_auth_count_mismatch() {
        let (effects, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        let mut auth = auth.unwrap();
        // Drop the binding signature.
        auth.truncate(auth.len() - 66);
        let encoded = wire(&[], &[(2, 0, effects)], &[(2, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_orchard_auth_count_mismatch() {
        let (effects, auth) = payloads(
            &V7EffectBundleBytes::Orchard(v7_orchard()),
            Some(&V7AuthBundleBytes::Orchard(v7_orchard_auth())),
        );
        let mut auth = auth.unwrap();
        // Drop the binding signature.
        auth.truncate(auth.len() - 66);
        let encoded = wire(&[], &[(3, 0, effects)], &[(3, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    fn orchard_action() -> OrchardActionBytes {
        OrchardActionBytes::from_parts(
            [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
        )
    }

    /// A complete Orchard-protocol effecting payload with `n_actions` actions.
    fn orchard_effects_payload(n_actions: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        CompactSize::write(&mut payload, n_actions).unwrap();
        for _ in 0..n_actions {
            orchard_action().write(&mut payload).unwrap();
        }
        payload.push(0);
        payload
    }

    /// A complete Orchard-protocol authorizing payload for `n_actions`
    /// actions, with a proof of `proof_len` bytes.
    fn orchard_auth_payload(n_actions: usize, proof_len: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 32]);
        CompactSize::write(&mut payload, proof_len).unwrap();
        payload.resize(payload.len() + proof_len, 0);
        for _ in 0..=n_actions {
            payload.extend_from_slice(&[0x01, 0x00]);
            payload.extend_from_slice(&[0u8; 64]);
        }
        payload
    }

    /// The Orchard proof length rule is checked by the transaction body reader,
    /// not only by the payload constructor: encode the complete maps by hand
    /// and vary only the claimed proof length.
    #[test]
    fn v7_orchard_and_ironwood_proof_length_boundaries() {
        for bundle_type in [BundleType::ORCHARD, BundleType::IRONWOOD] {
            for n_actions in [1usize, 2] {
                let expected = ORCHARD_PROOF_BASE_SIZE + ORCHARD_PROOF_PER_ACTION_SIZE * n_actions;
                let effects = (bundle_type.to_u64(), 0, orchard_effects_payload(n_actions));
                for proof_len in [expected - 1, expected, expected + 1] {
                    let auth = (
                        bundle_type.to_u64(),
                        0,
                        orchard_auth_payload(n_actions, proof_len),
                    );
                    let encoded = wire(&[], core::slice::from_ref(&effects), &[auth]);
                    assert_eq!(
                        V7TransactionBodyBytes::read(&encoded[..]).is_ok(),
                        proof_len == expected,
                        "bundleType {}, n_actions = {n_actions}, proof_len = {proof_len}",
                        bundle_type.to_u64(),
                    );
                }
            }
        }
    }

    #[test]
    fn v7_orchard_read_rejects_invalid_proof_length() {
        let auth = |proof_len: usize| {
            let mut auth = Vec::new();
            auth.extend([0u8; 32]);
            CompactSize::write(&mut auth, proof_len).unwrap();
            auth.resize(auth.len() + proof_len, 0);
            for _ in 0..=1 {
                CompactSize::write(&mut auth, 1).unwrap();
                auth.push(0x00);
                auth.extend([0u8; 64]);
            }
            auth
        };

        let expected = ORCHARD_PROOF_BASE_SIZE + ORCHARD_PROOF_PER_ACTION_SIZE;
        assert!(V7OrchardAuthBytes::read(&auth(expected - 1), 1).is_err());
        assert!(V7OrchardAuthBytes::read(&auth(expected), 1).is_ok());
        assert!(V7OrchardAuthBytes::read(&auth(expected + 1), 1).is_err());
    }

    #[test]
    fn v7_rejects_empty_orchard_effects_with_flags() {
        let effects = V7OrchardBundleBytes::from_parts(vec![], 1);
        assert!(effects.write_effects(Vec::new()).is_err());
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Orchard(effects)],
                vec![],
            )
            .is_err()
        );
    }

    #[test]
    fn v7_reserved_orchard_and_ironwood_flags_are_rejected() {
        /// ZIP 248 defines only the low three flag bits.
        const DEFINED_FLAGS: u8 = 0b0000_0111;
        for flags in 0..=u8::MAX {
            let effects = V7OrchardBundleBytes::from_parts(vec![orchard_action()], flags);
            let valid = flags & !DEFINED_FLAGS == 0;
            assert_eq!(effects.write_effects(Vec::new()).is_ok(), valid);
            let mut payload = orchard_effects_payload(1);
            *payload.last_mut().unwrap() = flags;
            assert_eq!(V7OrchardBundleBytes::read(&payload).is_ok(), valid);
            for effect in [
                V7EffectBundleBytes::Orchard(effects.clone()),
                V7EffectBundleBytes::Ironwood(effects.clone()),
            ] {
                let body = wire(
                    &[],
                    &[(effect.bundle_type().to_u64(), 0, payload.clone())],
                    &[],
                );
                assert_eq!(V7TransactionBodyBytes::read(&body[..]).is_ok(), valid);
                assert_eq!(
                    V7TransactionBodyBytes::from_parts(vec![], vec![effect], vec![]).is_ok(),
                    valid
                );
            }
        }
    }

    #[test]
    fn v7_outputs_only_transparent_auth_is_rejected() {
        let effects = TransparentEffectsBytes::from_parts(vec![], vec![output(1000, &[0x51])]);
        let auth = TransparentAuthBytes::from_parts(vec![]);
        assert!(TransparentBundleBytes::from_parts(effects.clone(), Some(auth.clone())).is_err());
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Transparent(effects.clone())],
                vec![V7AuthBundleBytes::Transparent(auth)],
            )
            .is_err()
        );
        let mut payload = Vec::new();
        effects.write(&mut payload).unwrap();
        let encoded = wire(
            &[],
            &[(BundleType::TRANSPARENT.to_u64(), 0, payload)],
            &[(BundleType::TRANSPARENT.to_u64(), 0, vec![])],
        );
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_orchard_auth_without_binding_signature() {
        let auth = V7OrchardAuthBytes::from_parts(
            Some([0u8; 32]),
            orchard_proof(1),
            vec![OrchardSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )],
            None,
        );
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Orchard(v7_orchard())],
                vec![V7AuthBundleBytes::Orchard(auth)],
            )
            .is_err()
        );
    }

    #[test]
    fn v7_empty_effect_bundles_are_rejected() {
        assert!(V7SaplingAuthBytes::read(&[], 0, 0).is_err());
        assert!(V7OrchardAuthBytes::read(&[], 0).is_err());
        let effects = [
            V7EffectBundleBytes::Transparent(TransparentEffectsBytes::from_parts(vec![], vec![])),
            V7EffectBundleBytes::Sapling(v7_sapling_empty()),
            V7EffectBundleBytes::Orchard(v7_orchard_empty()),
            V7EffectBundleBytes::Ironwood(v7_orchard_empty()),
        ];
        let auth = [
            V7AuthBundleBytes::Transparent(TransparentAuthBytes::from_parts(vec![])),
            V7AuthBundleBytes::Sapling(v7_sapling_empty_auth()),
            V7AuthBundleBytes::Orchard(v7_orchard_empty_auth()),
            V7AuthBundleBytes::Ironwood(v7_orchard_empty_auth()),
        ];
        for (effect, auth) in effects.into_iter().zip(auth) {
            assert!(effect.write_effects(Vec::new()).is_err());
            assert!(auth.write_auth(Vec::new()).is_err());
            let bundle_type = effect.bundle_type();
            let payload = if matches!(bundle_type, BundleType::ORCHARD | BundleType::IRONWOOD) {
                vec![0]
            } else {
                vec![0, 0]
            };
            for auth_present in [false, true] {
                assert!(
                    V7TransactionBodyBytes::from_parts(
                        vec![],
                        vec![effect.clone()],
                        if auth_present {
                            vec![auth.clone()]
                        } else {
                            vec![]
                        },
                    )
                    .is_err()
                );
                let body = wire(
                    &[],
                    &[(bundle_type.to_u64(), 0, payload.clone())],
                    &if auth_present {
                        vec![(bundle_type.to_u64(), 0, vec![])]
                    } else {
                        vec![]
                    },
                );
                assert!(V7TransactionBodyBytes::read(&body[..]).is_err());
                #[cfg(all(feature = "sapling", feature = "orchard"))]
                {
                    let mut tx = Vec::new();
                    TxVersion::V7.write(&mut tx).unwrap();
                    write_header_fragment(&mut tx, Some(BranchId::Nu8.into()), 0, 100u32.into())
                        .unwrap();
                    tx.extend_from_slice(&body);
                    assert!(crate::transaction::Transaction::read(&tx[..], BranchId::Nu8).is_err());
                }
            }
        }
    }

    /// Shielded leaf hashes retain their empty-input definitions independently
    /// of the transaction codec, which rejects explicitly present empty bundles.
    #[test]
    fn v7_empty_bundle_digests_are_personalized_empty_hashes() {
        use crate::transaction::txid::{
            hash_v7_ironwood_auth_bytes, hash_v7_ironwood_effects_bytes,
            hash_v7_orchard_auth_bytes, hash_v7_orchard_effects_bytes, hash_v7_sapling_auth_bytes,
            hash_v7_sapling_effects_bytes,
        };

        fn empty_hash(personal: &[u8; 16]) -> blake2b_simd::Hash {
            blake2b_simd::Params::new()
                .hash_length(32)
                .personal(personal)
                .to_state()
                .finalize()
        }

        let sapling = v7_sapling_empty();
        assert_eq!(
            hash_v7_sapling_effects_bytes(&sapling),
            empty_hash(b"ZTxIdSaplingH_v7")
        );
        let sapling_auth = v7_sapling_empty_auth();
        assert_eq!(
            hash_v7_sapling_auth_bytes(&sapling_auth),
            empty_hash(b"ZTxAuthSapliH_v7")
        );

        let orchard = v7_orchard_empty();
        assert_eq!(
            hash_v7_orchard_effects_bytes(&orchard),
            empty_hash(b"ZTxIdOrchardH_v7")
        );
        let orchard_auth = v7_orchard_empty_auth();
        assert_eq!(
            hash_v7_orchard_auth_bytes(&orchard_auth),
            empty_hash(b"ZTxAuthOrchaH_v7")
        );
        assert_eq!(
            hash_v7_ironwood_effects_bytes(&orchard),
            empty_hash(b"ZTxIdIronwd_Hash")
        );
        assert_eq!(
            hash_v7_ironwood_auth_bytes(&orchard_auth),
            empty_hash(b"ZTxAuthIrnwdHash")
        );
    }

    #[test]
    fn v7_rejects_misordered_bundles() {
        let (effects, auth) = payloads(
            &V7EffectBundleBytes::Sapling(v7_sapling()),
            Some(&V7AuthBundleBytes::Sapling(v7_sapling_auth())),
        );
        let encoded = wire(
            &[],
            &[(2, 0, effects.clone()), (0, 0, vec![0, 0])],
            &[(2, 0, auth.unwrap())],
        );
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_excessive_counts() {
        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, 0x0200_0000).unwrap();
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());

        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, 0).unwrap();
        CompactSize::write(&mut encoded, 0x0200_0000).unwrap();
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_coinbase_with_auth_parses_and_round_trips() {
        let coinbase = v7_coinbase();
        let mut effects = Vec::new();
        coinbase.write(&mut effects).unwrap();
        let auth = vec![0x00, 0xAA];
        let encoded = wire(&[], &[(1, 0, effects)], &[(1, 0, auth.clone())]);
        let body = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert!(matches!(
            body.effect_bundles()[0],
            V7EffectBundleBytes::Coinbase(..)
        ));
        assert_eq!(
            body.auth_bundles()[0].as_opaque().unwrap().payload(),
            auth.as_slice()
        );
        assert_eq!(body.coinbase(), Some(&coinbase));
        round_trip(&body);
    }

    #[test]
    fn v7_coinbase_with_auth_rejects_malformed_effects() {
        let coinbase = v7_coinbase();
        let mut effects = Vec::new();
        coinbase.write(&mut effects).unwrap();
        effects.truncate(effects.len() - 1);
        let encoded = wire(&[], &[(1, 0, effects)], &[(1, 0, vec![0x00])]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());

        let mut effects = Vec::new();
        coinbase.write(&mut effects).unwrap();
        effects.push(0);
        let encoded = wire(&[], &[(1, 0, effects)], &[(1, 0, vec![0x00])]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_coinbase_with_auth_effects_digest_needs_no_provider() {
        let coinbase = v7_coinbase();
        let mut effects = Vec::new();
        coinbase.write(&mut effects).unwrap();
        let encoded = wire(&[], &[(1, 0, effects)], &[(1, 0, vec![0x00])]);
        let body = V7TransactionBodyBytes::read(&encoded[..]).unwrap();

        let provider = zip248::SuppliedBundleDigests::new();
        assert!(body.effects_bundles_digest(&provider).is_ok());
        assert_eq!(
            body.auth_bundles_digest(&provider),
            Err(zip248::V7DigestError::MissingAuthDigest {
                key: body.auth_bundles()[0].digest_key()
            })
        );
    }

    #[test]
    fn v7_value_only_bundle_in_effect_map_is_opaque() {
        let encoded = wire(&[zec_delta(5, -1000)], &[(5, 0, vec![0x00])], &[]);
        let body = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert!(matches!(
            body.effect_bundles()[0],
            V7EffectBundleBytes::Opaque(_)
        ));
    }

    #[test]
    fn v7_opaque_recognized_v0_effect_is_rejected_at_construction() {
        // A valid transparent payload, but supplied as an opaque entry: read
        // would interpret it, so the construction is refused instead.
        for bundle_type in [
            BundleType::TRANSPARENT,
            BundleType::COINBASE,
            BundleType::SAPLING,
            BundleType::ORCHARD,
            BundleType::IRONWOOD,
        ] {
            let id = zip248::BundleId::new(bundle_type, BundleVariant::DEFAULT);
            assert!(
                OpaqueEffectBundleBytes::from_parts(id, vec![0, 0]).is_err(),
                "bundleType {} must have a recognized effecting codec",
                bundle_type.to_u64(),
            );
        }
    }

    /// A malformed payload for a recognized `(bundleType, 0)` identifier is
    /// rejected by the reader that a hand-built opaque entry would have
    /// bypassed, both alone and paired with an authorizing entry.
    #[test]
    fn v7_rejects_malformed_recognized_v0_effect_payloads() {
        // Transparent: a nonempty input count with no input.
        let encoded = wire(&[], &[(0, 0, vec![0x01])], &[]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());

        let encoded = wire(&[], &[(0, 0, vec![0x01])], &[(0, 0, vec![])]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());

        // Sapling: a spend count with no spend data, before and after adding a
        // (stub) authorizing entry.
        let encoded = wire(&[], &[(2, 0, vec![0x01])], &[]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());

        let encoded = wire(&[], &[(2, 0, vec![0x01])], &[(2, 0, vec![0x00])]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_opaque_known_type_unknown_variant_round_trips() {
        let opaque = OpaqueEffectBundleBytes::from_parts(
            zip248::BundleId::new(BundleType::SAPLING, BundleVariant::from_u64(1)),
            vec![1],
        )
        .unwrap();
        let body = v7_body(vec![], vec![V7EffectBundleBytes::Opaque(opaque)]);
        round_trip(&body);
    }

    #[test]
    fn v7_opaque_unknown_type_round_trips() {
        let opaque = OpaqueEffectBundleBytes::from_parts(
            zip248::BundleId::new(BundleType::from_u64(99), BundleVariant::DEFAULT),
            vec![1],
        )
        .unwrap();
        let body = v7_body(vec![], vec![V7EffectBundleBytes::Opaque(opaque)]);
        round_trip(&body);
    }

    #[test]
    fn v7_unknown_empty_shaped_payloads_remain_opaque() {
        /// An unassigned variant of every recognized bundle type.
        const UNKNOWN_VARIANT: u64 = 1;
        /// A bundle type outside the current registry.
        const UNKNOWN_TYPE: u64 = 99;
        for bundle_type in [
            BundleType::TRANSPARENT,
            BundleType::SAPLING,
            BundleType::ORCHARD,
            BundleType::IRONWOOD,
            BundleType::from_u64(UNKNOWN_TYPE),
        ] {
            for payload in [vec![], vec![0], vec![0, 0]] {
                let id =
                    zip248::BundleId::new(bundle_type, BundleVariant::from_u64(UNKNOWN_VARIANT));
                let body = V7TransactionBodyBytes::from_parts(
                    vec![],
                    vec![V7EffectBundleBytes::Opaque(
                        OpaqueEffectBundleBytes::from_parts(id, payload).unwrap(),
                    )],
                    vec![V7AuthBundleBytes::Opaque(
                        OpaqueAuthBundleBytes::from_parts(id, vec![]).unwrap(),
                    )],
                )
                .unwrap();
                round_trip(&body);
                assert!(body.effect_bundles()[0].as_opaque().is_some());
                assert!(body.auth_bundles()[0].as_opaque().is_some());
            }
        }
    }

    #[test]
    fn v7_coinbase_data_length_boundary() {
        let max = zip248::MAX_COINBASE_DATA_LEN;
        let coinbase = CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![0x51; max],
            vec![],
            None,
        )
        .unwrap();
        let mut encoded = Vec::new();
        coinbase.write(&mut encoded).unwrap();
        let decoded = CoinbaseBundleBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded, coinbase);

        // The byte layer retains an over-long payload and re-serializes it
        // unchanged; the typed conversion enforces the ZIP 248 limit.
        let over_long = CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![0x51; max + 1],
            vec![],
            None,
        )
        .unwrap();
        let mut encoded = Vec::new();
        over_long.write(&mut encoded).unwrap();
        let decoded = CoinbaseBundleBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded, over_long);
        assert!(decoded.to_coinbase_bundle().is_err());
    }

    #[test]
    fn v7_coinbase_retains_out_of_domain_field_values() {
        for (height, block_subsidy, lockbox_value) in [
            (BlockHeight::from(0u32), 1_000_000, 0),
            (BlockHeight::from(100u32), 1_000_000, 1_000_001),
        ] {
            let coinbase = CoinbaseBundleBytes::from_parts(
                height,
                block_subsidy,
                lockbox_value,
                vec![],
                vec![],
                None,
            )
            .unwrap();
            let mut encoded = Vec::new();
            coinbase.write(&mut encoded).unwrap();
            let decoded = CoinbaseBundleBytes::read(&encoded[..]).unwrap();
            assert_eq!(decoded, coinbase);
            assert!(decoded.to_coinbase_bundle().is_err());
        }
    }

    #[test]
    fn v7_value_pool_delta_retains_raw_out_of_range_values() {
        let max_balance = zcash_protocol::value::MAX_MONEY as i64;
        for value in [i64::MIN, -max_balance - 1, max_balance + 1, i64::MAX] {
            let delta = ValuePoolDeltaBytes::from_parts(
                BundleType::from_u64(99),
                BundleVariant::from_u64(0),
                value,
            )
            .unwrap();
            assert_eq!(delta.value(), value);

            let mut encoded = Vec::new();
            delta.write(&mut encoded).unwrap();
            let decoded = ValuePoolDeltaBytes::read(&encoded[..]).unwrap();
            assert_eq!(decoded, delta);
            assert_eq!(decoded.value(), value);

            let body = v7_body(vec![delta], vec![]);
            round_trip(&body);
            assert!(body.to_value_pool_deltas().is_err());
        }
    }

    #[test]
    fn v7_coinbase_rejects_duplicate_and_decreasing_signal_codes() {
        for codes in [&[1u8, 1][..], &[2, 1][..]] {
            assert!(
                CoinbaseBundleBytes::from_parts(
                    BlockHeight::from(100u32),
                    1_000_000,
                    0,
                    vec![],
                    codes.iter().map(|&code| miner_signal(code, 0)).collect(),
                    Some(poll_digest(0x11)),
                )
                .is_err()
            );

            let mut encoded = Vec::new();
            encoded.extend_from_slice(&100u32.to_le_bytes());
            encoded.extend_from_slice(&1_000_000u64.to_le_bytes());
            encoded.extend_from_slice(&0u64.to_le_bytes());
            CompactSize::write(&mut encoded, 0).unwrap();
            CompactSize::write(&mut encoded, codes.len()).unwrap();
            for &code in codes {
                encoded.extend_from_slice(&[code, 0]);
            }
            encoded.extend_from_slice(poll_digest(0x11).as_bytes());
            assert_eq!(
                CoinbaseBundleBytes::read(&encoded[..]).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
            );
            let body = wire(&[], &[(BundleType::COINBASE.to_u64(), 0, encoded)], &[]);
            assert!(V7TransactionBodyBytes::read(&body[..]).is_err());
        }
    }

    #[test]
    fn v7_coinbase_truncated_large_data_claim_is_rejected() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&100u32.to_le_bytes());
        encoded.extend_from_slice(&1_000_000u64.to_le_bytes());
        encoded.extend_from_slice(&0u64.to_le_bytes());
        CompactSize::write(&mut encoded, zcash_encoding::MAX_COMPACT_SIZE as usize).unwrap();
        assert!(CoinbaseBundleBytes::read(&encoded[..]).is_err());
        let body = wire(&[], &[(BundleType::COINBASE.to_u64(), 0, encoded)], &[]);
        assert!(V7TransactionBodyBytes::read(&body[..]).is_err());
    }

    #[test]
    fn v7_coinbase_signal_count_boundaries() {
        let signals = (0..zip248::MAX_MINER_SIGNALS)
            .map(|code| miner_signal(code as u8, code as u8))
            .collect::<Vec<_>>();

        let max = CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![],
            signals,
            Some(poll_digest(0x11)),
        )
        .unwrap();
        let mut encoded = Vec::new();
        max.write(&mut encoded).unwrap();
        assert_eq!(max.miner_signals().len(), zip248::MAX_MINER_SIGNALS);
        assert_eq!(CoinbaseBundleBytes::read(&encoded[..]).unwrap(), max);
        assert!(max.to_coinbase_bundle().is_ok());

        let over = (0..=zip248::MAX_MINER_SIGNALS)
            .map(|code| miner_signal(code as u8, 0))
            .collect::<Vec<_>>();
        assert_eq!(over.len(), zip248::MAX_MINER_SIGNALS + 1);
        assert!(
            CoinbaseBundleBytes::from_parts(
                BlockHeight::from(100u32),
                1_000_000,
                0,
                vec![],
                over,
                Some(poll_digest(0x11)),
            )
            .is_err()
        );

        // The read path rejects the count before reading any entry, so a
        // payload holding only the count and no entries is enough.
        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, zip248::MAX_MINER_SIGNALS + 1).unwrap();
        assert!(CoinbaseBundleBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_coinbase_signal_encoding_boundaries() {
        let prefix = || {
            let mut buf = Vec::new();
            buf.extend_from_slice(&100u32.to_le_bytes());
            buf.extend_from_slice(&1_000_000u64.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        };

        // A truncated signal entry.
        let mut encoded = prefix();
        CompactSize::write(&mut encoded, 1).unwrap();
        encoded.push(1);
        assert!(CoinbaseBundleBytes::read(&encoded[..]).is_err());

        // A truncated poll digest.
        let mut encoded = prefix();
        CompactSize::write(&mut encoded, 1).unwrap();
        encoded.extend_from_slice(&[1, 2]);
        encoded.extend_from_slice(&[0x11; POLL_DIGEST_SIZE - 1]);
        assert!(CoinbaseBundleBytes::read(&encoded[..]).is_err());

        // Signals without a digest.
        let mut encoded = prefix();
        CompactSize::write(&mut encoded, 1).unwrap();
        encoded.extend_from_slice(&[1, 2]);
        assert!(CoinbaseBundleBytes::read(&encoded[..]).is_err());

        // A digest with no signals. The bundle reader stops after the zero
        // count, so the digest is left as trailing bytes for the enclosing
        // payload reader to reject.
        let mut encoded = prefix();
        CompactSize::write(&mut encoded, 0).unwrap();
        encoded.extend_from_slice(&[0x11; POLL_DIGEST_SIZE]);
        assert!(CoinbaseBundleBytes::read(&encoded[..]).is_ok());

        // The byte constructor rejects the same presence mismatches.
        assert!(
            CoinbaseBundleBytes::from_parts(
                BlockHeight::from(100u32),
                1_000_000,
                0,
                vec![],
                vec![miner_signal(1, 2)],
                None,
            )
            .is_err()
        );
        assert!(
            CoinbaseBundleBytes::from_parts(
                BlockHeight::from(100u32),
                1_000_000,
                0,
                vec![],
                vec![],
                Some(poll_digest(0x11)),
            )
            .is_err()
        );
    }

    /// A digest appended to a zero-signal payload is trailing data for the
    /// recognized coinbase encoding.
    #[test]
    fn v7_coinbase_rejects_appended_digest_after_zero_signals() {
        let mut effects = Vec::new();
        CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![],
            vec![],
            None,
        )
        .unwrap()
        .write(&mut effects)
        .unwrap();
        effects.extend_from_slice(&[0x11; POLL_DIGEST_SIZE]);

        let encoded = wire(&[], &[(1, 0, effects)], &[]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    /// The multi-signal encoding pins the count, both bytes of every entry in
    /// wire order, and the 16-byte digest.
    #[test]
    fn v7_coinbase_signal_wire_encoding_is_fixed() {
        let coinbase = CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![0x51],
            vec![miner_signal(2, 0x20), miner_signal(9, 0x90)],
            Some(poll_digest(0x7E)),
        )
        .unwrap();

        let mut encoded = Vec::new();
        coinbase.write(&mut encoded).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&100u32.to_le_bytes());
        expected.extend_from_slice(&1_000_000u64.to_le_bytes());
        expected.extend_from_slice(&0u64.to_le_bytes());
        CompactSize::write(&mut expected, 1).unwrap();
        expected.push(0x51);
        CompactSize::write(&mut expected, 2).unwrap();
        expected.extend_from_slice(&[2, 0x20, 9, 0x90]);
        expected.extend_from_slice(&[0x7E; POLL_DIGEST_SIZE]);

        assert_eq!(encoded, expected);
        assert_eq!(CoinbaseBundleBytes::read(&encoded[..]).unwrap(), coinbase);
    }

    #[test]
    fn v7_coinbase_retains_raw_out_of_range_amounts() {
        let max_money = zcash_protocol::value::MAX_MONEY;
        for (block_subsidy, lockbox_value) in [
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
            (max_money + 1, max_money + 1),
        ] {
            let coinbase = CoinbaseBundleBytes::from_parts(
                BlockHeight::from(100u32),
                block_subsidy,
                lockbox_value,
                vec![0x51],
                vec![],
                None,
            )
            .unwrap();
            assert_eq!(coinbase.block_subsidy(), block_subsidy);
            assert_eq!(coinbase.lockbox_value(), lockbox_value);

            let mut encoded = Vec::new();
            coinbase.write(&mut encoded).unwrap();
            let decoded = CoinbaseBundleBytes::read(&encoded[..]).unwrap();
            assert_eq!(decoded, coinbase);
            assert!(decoded.to_coinbase_bundle().is_err());
        }
    }

    #[test]
    fn v7_opaque_payload_size_boundary() {
        let id = zip248::BundleId::new(BundleType::from_u64(99), BundleVariant::DEFAULT);
        let opaque = OpaqueEffectBundleBytes::from_parts(id, vec![0u8; MAX_BLOCK_BYTES]).unwrap();
        let body = v7_body(vec![], vec![V7EffectBundleBytes::Opaque(opaque)]);
        round_trip(&body);

        assert!(OpaqueEffectBundleBytes::from_parts(id, vec![0u8; MAX_BLOCK_BYTES + 1]).is_err());
        assert!(OpaqueAuthBundleBytes::from_parts(id, vec![0u8; MAX_BLOCK_BYTES + 1]).is_err());
    }

    #[test]
    fn v7_rejects_oversized_transparent_auth_payload() {
        let effects = TransparentEffectsBytes::from_parts(
            vec![TransparentInputEffectingBytes::from_parts(
                outpoint(1, 2),
                3,
            )],
            vec![],
        );
        let auth = TransparentAuthBytes::from_parts(vec![TransparentInputAuthBytes::from_parts(
            TransparentSighashInfoBytes::v0(),
            TransparentScriptBytes::from_bytes(vec![0u8; MAX_BLOCK_BYTES]),
        )]);
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Transparent(effects)],
                vec![V7AuthBundleBytes::Transparent(auth)],
            )
            .is_err()
        );
    }

    #[test]
    fn v7_accepts_near_boundary_transparent_auth_payload() {
        let script_len = MAX_BLOCK_BYTES - 10;
        let effects = TransparentEffectsBytes::from_parts(
            vec![TransparentInputEffectingBytes::from_parts(
                outpoint(1, 2),
                3,
            )],
            vec![],
        );
        let auth = TransparentAuthBytes::from_parts(vec![TransparentInputAuthBytes::from_parts(
            TransparentSighashInfoBytes::v0(),
            TransparentScriptBytes::from_bytes(vec![0u8; script_len]),
        )]);
        let body = v7_body_with_auth(
            vec![],
            vec![V7EffectBundleBytes::Transparent(effects)],
            vec![V7AuthBundleBytes::Transparent(auth)],
        );
        round_trip(&body);
    }

    #[test]
    fn v7_rejects_oversized_sapling_auth_payload() {
        let binding_sig = SaplingSignatureBytes::from_parts(
            SighashInfoBytes::from_bytes(vec![0u8; MAX_BLOCK_BYTES]),
            [0u8; 64],
        );
        let effects = V7SaplingBundleBytes::from_parts(
            vec![SaplingSpendBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32],
            )],
            vec![],
        );
        let auth = V7SaplingAuthBytes::from_parts(
            Some([0u8; 32]),
            vec![[0u8; 192]],
            vec![SaplingSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )],
            vec![],
            Some(binding_sig),
        );
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Sapling(effects)],
                vec![V7AuthBundleBytes::Sapling(auth)],
            )
            .is_err()
        );
    }

    #[test]
    fn v7_rejects_oversized_orchard_auth_payload() {
        let binding_sig = OrchardSignatureBytes::from_parts(
            SighashInfoBytes::from_bytes(vec![0u8; MAX_BLOCK_BYTES]),
            [0u8; 64],
        );
        let effects = V7OrchardBundleBytes::from_parts(
            vec![OrchardActionBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )],
            0,
        );
        let auth = V7OrchardAuthBytes::from_parts(
            Some([0u8; 32]),
            orchard_proof(1),
            vec![OrchardSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )],
            Some(binding_sig),
        );
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7EffectBundleBytes::Orchard(effects)],
                vec![V7AuthBundleBytes::Orchard(auth)],
            )
            .is_err()
        );
    }

    #[test]
    fn v7_write_bundle_data_map_rejects_oversized_payload() {
        let mut encoded = Vec::new();
        let result = write_bundle_data_map(
            &mut encoded,
            vec![(
                zip248::BundleId::new(BundleType::from_u64(99), BundleVariant::DEFAULT),
                vec![0u8; MAX_BLOCK_BYTES + 1],
            )],
        );
        assert!(result.is_err());
        assert!(encoded.is_empty());
    }

    #[test]
    fn v7_bundle_data_framing_round_trip() {
        let id = zip248::BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT);
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let mut encoded = Vec::new();
        write_bundle_data_framing(&mut encoded, id, &data).unwrap();

        let (parsed_id, parsed_data) = read_bundle_data_framing(&encoded[..]).unwrap();
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn v7_full_transaction_round_trip() {
        let (transparent_effects, transparent_auth) = split_transparent(v7_transparent());
        let body = v7_body_with_auth(
            vec![zec_delta(0, -1000), zec_delta(2, 1)],
            vec![
                transparent_effects,
                V7EffectBundleBytes::Sapling(v7_sapling()),
            ],
            vec![
                transparent_auth.unwrap(),
                V7AuthBundleBytes::Sapling(v7_sapling_auth()),
            ],
        );
        let tx = v7_tx(body);
        let mut encoded = Vec::new();
        tx.write(&mut encoded).unwrap();
        let decoded = TransactionBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded, tx);
    }

    /// Every proper prefix of a complete body is rejected, and an extra byte
    /// after any recognized payload is rejected, across every recognized payload
    /// shape: transparent, spend-only and output-only Sapling, one- and
    /// two-action Orchard, and Ironwood.
    #[test]
    fn v7_truncation_and_trailing_bytes_are_rejected_across_payload_shapes() {
        // Each shape is (bundleType, effects, auth); `auth` may be absent.
        fn shapes() -> Vec<(u64, Vec<u8>, Option<Vec<u8>>)> {
            let sapling_spend = V7EffectBundleBytes::Sapling(V7SaplingBundleBytes::from_parts(
                vec![SaplingSpendBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32],
                )],
                vec![],
            ));
            let sapling_spend_auth = V7AuthBundleBytes::Sapling(V7SaplingAuthBytes::from_parts(
                Some([0u8; 32]),
                vec![[0u8; 192]],
                vec![SaplingSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    [0u8; 64],
                )],
                vec![],
                Some(SaplingSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    [0u8; 64],
                )),
            ));
            let sapling_output = V7EffectBundleBytes::Sapling(V7SaplingBundleBytes::from_parts(
                vec![],
                vec![SaplingOutputBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
                )],
            ));
            let sapling_output_auth = V7AuthBundleBytes::Sapling(V7SaplingAuthBytes::from_parts(
                None,
                vec![],
                vec![],
                vec![[0u8; 192]],
                Some(SaplingSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    [0u8; 64],
                )),
            ));

            let orchard = |n: usize| {
                V7EffectBundleBytes::Orchard(V7OrchardBundleBytes::from_parts(
                    vec![orchard_action(); n],
                    0,
                ))
            };
            let orchard_auth = |n: usize| {
                V7OrchardAuthBytes::from_parts(
                    Some([0u8; 32]),
                    orchard_proof(n),
                    vec![OrchardSignatureBytes::from_parts(SighashInfoBytes::v0(), [0u8; 64]); n],
                    Some(OrchardSignatureBytes::from_parts(
                        SighashInfoBytes::v0(),
                        [0u8; 64],
                    )),
                )
            };

            let mut shapes = vec![
                {
                    let (effect, auth) = split_transparent(v7_transparent());
                    let (effects, auth) = payloads(&effect, auth.as_ref());
                    (BundleType::TRANSPARENT.to_u64(), effects, auth)
                },
                {
                    let effects = V7EffectBundleBytes::Transparent(
                        TransparentEffectsBytes::from_parts(vec![], vec![output(1000, &[0x51])]),
                    );
                    let (effects, auth) = payloads(&effects, None);
                    (BundleType::TRANSPARENT.to_u64(), effects, auth)
                },
                {
                    let (effects, auth) = payloads(&sapling_spend, Some(&sapling_spend_auth));
                    (2, effects, auth)
                },
                {
                    let (effects, auth) = payloads(&sapling_output, Some(&sapling_output_auth));
                    (2, effects, auth)
                },
            ];
            for n in [1usize, 2] {
                let (effects, auth) = payloads(
                    &orchard(n),
                    Some(&V7AuthBundleBytes::Orchard(orchard_auth(n))),
                );
                shapes.push((3, effects, auth));
            }
            {
                let (effects, auth) = payloads(
                    &V7EffectBundleBytes::Ironwood(V7OrchardBundleBytes::from_parts(
                        vec![orchard_action(), orchard_action()],
                        0,
                    )),
                    Some(&V7AuthBundleBytes::Orchard(orchard_auth(2))),
                );
                shapes.push((4, effects, auth));
            }
            shapes
        }

        for (bundle_type, effects, auth) in shapes() {
            let auth_entries: Vec<(u64, u64, Vec<u8>)> = auth
                .clone()
                .map(|payload| (bundle_type, 0, payload))
                .into_iter()
                .collect();
            let encoded = wire(&[], &[(bundle_type, 0, effects.clone())], &auth_entries);

            for len in 0..encoded.len() {
                assert!(
                    V7TransactionBodyBytes::read(&encoded[..len]).is_err(),
                    "bundleType {bundle_type}: truncation at {len} bytes was accepted",
                );
            }
            assert!(V7TransactionBodyBytes::read(&encoded[..]).is_ok());

            // A byte appended to the effecting payload.
            let mut trailing = effects.clone();
            trailing.push(0);
            let encoded = wire(&[], &[(bundle_type, 0, trailing)], &auth_entries);
            assert!(
                V7TransactionBodyBytes::read(&encoded[..]).is_err(),
                "bundleType {bundle_type}: trailing effecting byte was accepted",
            );

            // A byte appended to the authorizing payload.
            if let Some(auth) = auth {
                let mut trailing = auth;
                trailing.push(0);
                let encoded = wire(
                    &[],
                    &[(bundle_type, 0, effects)],
                    &[(bundle_type, 0, trailing)],
                );
                assert!(
                    V7TransactionBodyBytes::read(&encoded[..]).is_err(),
                    "bundleType {bundle_type}: trailing authorizing byte was accepted",
                );
            }
        }
    }

    /// The byte-level txid and auth commitment for an empty transaction match
    /// the independent ZIP 248 vectors pinned by the typed path.
    #[test]
    fn v7_empty_byte_txid_matches_zip248_vector() {
        let tx = v7_tx(v7_body(vec![], vec![]));
        let empty = zip248::SuppliedBundleDigests::new();

        assert_eq!(
            hex::encode(tx.v7_txid(&empty).unwrap().as_ref()),
            "600c2dd76c15b3683691259781ce79a3757cc7f95714cfbccdb49f69ddf15958",
        );
        assert_eq!(
            hex::encode(tx.v7_auth_commitment(&empty).unwrap().as_bytes()),
            "d3a128d379cd32a6ec49acb8e5da337ed38e80c068fa0e33e4baf2786867241a",
        );
    }

    /// The byte-level txid for a fee-only transaction matches the independent
    /// ZIP 248 vector pinned by the typed path.
    #[test]
    fn v7_fee_byte_txid_matches_zip248_vector() {
        let tx = v7_tx(v7_body(vec![zec_delta(5, -10_000)], vec![]));
        let empty = zip248::SuppliedBundleDigests::new();

        assert_eq!(
            hex::encode(tx.v7_txid(&empty).unwrap().as_ref()),
            "0778b29c2439d15380c97f32c02c0430fdfcbc94ecde260f4503a7fee547191e",
        );
    }

    /// An indexer can parse, inspect, and re-serialize a v7 transaction that
    /// carries a bundle type it does not understand, without converting any
    /// bundle to a typed representation.
    ///
    /// The wire bytes and the expected digests were computed independently
    /// from the ZIP 248 digest tree, using fixed supplied digests for the
    /// opaque bundle.
    #[test]
    fn v7_indexer_round_trips_unknown_bundle_without_typed_conversion() {
        const WIRE: &str = "07000080385f756efbffffff0000000064000000\
                            016300f401000000000000\
                            01630003010203\
                            016300020405";
        const TXID: &str = "f17b15b75a33457fe06a44d5f766e5c2d1c61e78cc63cd256c9bbc0cbdbdb17c";
        const AUTH_COMMITMENT: &str =
            "63ffe5f3ffdecda1785d62fbcb0095b59c250c2916747f7bea373e0e9c4ea24e";

        let wire = hex::decode(WIRE).unwrap();
        let tx = TransactionBytes::read(&wire[..]).unwrap();

        // The known and unknown value flows are visible without interpreting
        // the bundle payload.
        let body = tx.body().as_v7().unwrap();
        assert_eq!(body.value_pool_deltas().len(), 1);
        let delta = &body.value_pool_deltas()[0];
        assert_eq!(delta.bundle_type().to_u64(), 99);
        assert_eq!(delta.bundle_variant().to_u64(), 0);
        assert_eq!(delta.value(), 500);

        assert_eq!(body.effect_bundles().len(), 1);
        let bundle = &body.effect_bundles()[0];
        assert!(matches!(bundle, V7EffectBundleBytes::Opaque(_)));
        let opaque = bundle.as_opaque().unwrap();
        assert_eq!(opaque.id().bundle_type().to_u64(), 99);
        assert_eq!(opaque.id().bundle_variant().to_u64(), 0);
        assert_eq!(opaque.payload(), &[1, 2, 3]);
        assert_eq!(body.auth_bundles().len(), 1);
        assert_eq!(
            body.auth_bundles()[0].as_opaque().unwrap().payload(),
            &[4, 5]
        );

        // Re-serialization is faithful and does not require a typed bundle.
        let mut reserialized = Vec::new();
        tx.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, wire);

        // The identifier is unavailable until the caller supplies the opaque
        // bundle's digests.
        let key = zip248::BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0));
        let empty = zip248::SuppliedBundleDigests::new();
        assert_eq!(
            tx.v7_txid(&empty),
            Err(zip248::V7DigestError::MissingEffectsDigest { key })
        );
        assert_eq!(
            tx.v7_auth_commitment(&empty),
            Err(zip248::V7DigestError::MissingAuthDigest { key })
        );

        let supplied_digest = |byte: u8| {
            blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"test_unknown_efx")
                .hash(&[byte])
        };
        let mut supplied = zip248::SuppliedBundleDigests::new();
        supplied.insert_effects(key, supplied_digest(0x11)).unwrap();
        supplied.insert_auth(key, supplied_digest(0x22)).unwrap();
        assert_eq!(hex::encode(tx.v7_txid(&supplied).unwrap().as_ref()), TXID);
        assert_eq!(
            hex::encode(tx.v7_auth_commitment(&supplied).unwrap().as_bytes()),
            AUTH_COMMITMENT
        );
    }

    /// An opaque effecting payload's supplied digest is merged under its exact
    /// `(bundleType, bundleVariant)` key, for both a known type with an unknown
    /// variant and a wholly unknown type.
    #[test]
    fn v7_opaque_effects_digests_are_merged_under_their_exact_keys() {
        for (bundle_type, bundle_variant) in [(2u64, 1u64), (99, 0)] {
            let id = zip248::BundleId::new(
                BundleType::from_u64(bundle_type),
                BundleVariant::from_u64(bundle_variant),
            );
            let opaque = OpaqueEffectBundleBytes::from_parts(id, vec![0xAA]).unwrap();
            let tx = v7_tx(v7_body(vec![], vec![V7EffectBundleBytes::Opaque(opaque)]));

            let digest = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"test_opaque_key")
                .hash(&[0xAA]);

            let mut supplied = zip248::SuppliedBundleDigests::new();

            supplied.insert_effects(id, digest).unwrap();

            let digests = tx.v7_txid_digests(&supplied).unwrap();
            assert_eq!(digests.unknown_effect_digests, vec![(id, digest)]);

            // Independently rebuild `effects_bundles_digest`: each entry is
            // compactSize(bundleType) || compactSize(bundleVariant) || digest.
            let mut tagged = Vec::new();
            CompactSize::write(&mut tagged, bundle_type as usize).unwrap();
            CompactSize::write(&mut tagged, bundle_variant as usize).unwrap();
            tagged.extend_from_slice(digest.as_bytes());
            let expected = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"ZTxIdEffBnd_Hash")
                .hash(&tagged);
            assert_eq!(
                tx.body()
                    .as_v7()
                    .unwrap()
                    .effects_bundles_digest(&supplied)
                    .unwrap(),
                expected
            );
        }
    }

    /// A delta-only entry for an unknown bundle type has no effecting bundle,
    /// so it needs no supplied effecting-data digest.
    #[test]
    fn v7_unknown_value_only_bundle_needs_no_effects_digest() {
        let tx = v7_tx(v7_body(vec![zec_delta(99, 5)], vec![]));
        let empty = zip248::SuppliedBundleDigests::new();

        assert!(tx.v7_txid_digests(&empty).is_ok());
        assert!(tx.v7_txid(&empty).is_ok());
        assert!(tx.v7_auth_commitment(&empty).is_ok());
    }

    /// Digest vectors over fixed byte-layer fixtures, with expected values
    /// computed independently of this implementation from the ZIP 248 digest
    /// tree. Fixed inputs make a regression in any leaf or personalization
    /// visible as a changed constant.
    mod independent_vectors {
        use super::*;
        use crate::transaction::txid::{
            hash_v7_coinbase_effects_bytes, hash_v7_ironwood_auth_bytes,
            hash_v7_ironwood_effects_bytes, hash_v7_orchard_auth_bytes,
            hash_v7_orchard_effects_bytes, hash_v7_sapling_auth_bytes,
            hash_v7_sapling_effects_bytes, hash_v7_transparent_auth_bytes,
            hash_v7_transparent_effects_bytes,
        };

        fn empty_sighash_info() -> TransparentSighashInfoBytes {
            TransparentSighashInfoBytes::v0()
        }

        fn sapling_signature(byte: u8) -> SaplingSignatureBytes {
            SaplingSignatureBytes::from_parts(SighashInfoBytes::v0(), [byte; 64])
        }

        fn orchard_signature(byte: u8) -> OrchardSignatureBytes {
            OrchardSignatureBytes::from_parts(SighashInfoBytes::v0(), [byte; 64])
        }

        fn action() -> OrchardActionBytes {
            OrchardActionBytes::from_parts(
                [0x11; 32],
                [0x22; 32],
                [0x44; 32],
                [0x55; 32],
                [0x66; 32],
                [0x88; 580],
                [0x99; 80],
            )
        }

        fn orchard_auth(anchor: u8, sig: u8) -> V7OrchardAuthBytes {
            V7OrchardAuthBytes::from_parts(
                Some([anchor; 32]),
                vec![0xAA; ORCHARD_PROOF_BASE_SIZE + ORCHARD_PROOF_PER_ACTION_SIZE],
                vec![orchard_signature(sig)],
                Some(orchard_signature(0xCC)),
            )
        }

        /// The shared v7 header the expected txids commit to: version 7,
        /// branch ID Nu8, lock time 0, expiry height 100.
        fn header_preimage() -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(7u32 | (1 << 31)).to_le_bytes());
            buf.extend_from_slice(&zcash_protocol::constants::V7_VERSION_GROUP_ID.to_le_bytes());
            buf.extend_from_slice(&0xffff_fffbu32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&100u32.to_le_bytes());
            buf
        }

        #[test]
        fn transparent_effects_and_auth_match_independent_digests() {
            let effects = TransparentEffectsBytes::from_parts(
                vec![TransparentInputEffectingBytes::from_parts(
                    outpoint(1, 2),
                    3,
                )],
                vec![output(1000, &[0x51, 0x52])],
            );
            let auth =
                TransparentAuthBytes::from_parts(vec![TransparentInputAuthBytes::from_parts(
                    empty_sighash_info(),
                    TransparentScriptBytes::from_bytes(vec![0x51]),
                )]);

            assert_eq!(
                hex::encode(hash_v7_transparent_effects_bytes(&effects).as_bytes()),
                "d5e1d1105b9afedeb5315f87b47d62c64083697993e3407e9cb8b0521cde5fd0"
            );
            assert_eq!(
                hex::encode(hash_v7_transparent_auth_bytes(&auth).as_bytes()),
                "39c5b754b5ea79a3c9f982923b10240a128f7bd04e5c2a76c1dc4a857ea6b417"
            );

            let tx = v7_tx(v7_body_with_auth(
                vec![zec_delta(0, -1000)],
                vec![V7EffectBundleBytes::Transparent(effects)],
                vec![V7AuthBundleBytes::Transparent(auth)],
            ));
            let empty = zip248::SuppliedBundleDigests::new();
            assert_eq!(
                hex::encode(tx.v7_txid(&empty).unwrap().as_ref()),
                "618a5eff3fc2a1fd94216c7ce75a3b17019cdb8ff8e2474835e4930e765f6e32"
            );
            assert_eq!(
                hex::encode(tx.v7_auth_commitment(&empty).unwrap().as_bytes()),
                "77868f75aa62e6f7e0e9e736000bc9ab8483bd202ff4e6728bd4a99cc6ea0041"
            );
        }

        /// One spend and one output, with matching authorizing data.
        fn sapling_fixture() -> (V7SaplingBundleBytes, V7SaplingAuthBytes) {
            let effects = V7SaplingBundleBytes::from_parts(
                vec![SaplingSpendBytes::from_parts(
                    [0x11; 32], [0x22; 32], [0x44; 32],
                )],
                vec![SaplingOutputBytes::from_parts(
                    [0x55; 32],
                    [0x66; 32],
                    [0x77; 32],
                    [0x88; 580],
                    [0x99; 80],
                )],
            );
            let auth = V7SaplingAuthBytes::from_parts(
                Some([0x33; 32]),
                vec![[0xAA; 192]],
                vec![sapling_signature(0xBB)],
                vec![[0xCC; 192]],
                Some(sapling_signature(0xDD)),
            );
            (effects, auth)
        }

        #[test]
        fn sapling_effects_and_auth_match_independent_digests() {
            let (effects, auth) = sapling_fixture();

            assert_eq!(
                hex::encode(hash_v7_sapling_effects_bytes(&effects).as_bytes()),
                "16a3caaed6dfd7632ded63cb25e46c1d03ee5ac04839e47c402097dbde20e063"
            );
            assert_eq!(
                hex::encode(hash_v7_sapling_auth_bytes(&auth).as_bytes()),
                "5a94a38f38984169af8bf7379e580376b76ad791917dc46fcc92c893d738aca6"
            );

            let tx = v7_tx(v7_body_with_auth(
                vec![zec_delta(2, -1)],
                vec![V7EffectBundleBytes::Sapling(effects)],
                vec![V7AuthBundleBytes::Sapling(auth)],
            ));
            let empty = zip248::SuppliedBundleDigests::new();
            assert_eq!(
                hex::encode(tx.v7_txid(&empty).unwrap().as_ref()),
                "79ceb169c87bdcf27e397e12dbddb4c42c346f5782b512e01666651ff64480f5"
            );
        }

        #[test]
        fn orchard_and_ironwood_effects_match_independent_digests() {
            let effects = V7OrchardBundleBytes::from_parts(vec![action()], 3);

            assert_eq!(
                hex::encode(hash_v7_orchard_effects_bytes(&effects).as_bytes()),
                "8e23f072161182cd7092de2a0946cc6a0f00fc6ba0b8e3aa8cb5cb69768bf082"
            );
            // The Ironwood child digests use their own `_v6` personalizations,
            // so the same actions must not produce the Orchard digest.
            assert_eq!(
                hex::encode(hash_v7_ironwood_effects_bytes(&effects).as_bytes()),
                "03dd472b7bcb192019f7d53b7cea9441b41fb3addb703017671b41db790977b8"
            );

            let auth = orchard_auth(0x33, 0xBB);
            assert_eq!(
                hex::encode(hash_v7_orchard_auth_bytes(&auth).as_bytes()),
                "8b1dd1f5eb913f7d065bea12e2e6fb55a0974286e0599b1cf1dccceaeb42cf66"
            );
            assert_eq!(
                hex::encode(hash_v7_ironwood_auth_bytes(&auth).as_bytes()),
                "83bd702b9532a4831b9d07b33efa6d7df6f9a0e34f188a89035d00a8c24f5a90"
            );

            let orchard_tx = v7_tx(v7_body_with_auth(
                vec![zec_delta(3, -1)],
                vec![V7EffectBundleBytes::Orchard(effects.clone())],
                vec![V7AuthBundleBytes::Orchard(auth.clone())],
            ));
            let empty = zip248::SuppliedBundleDigests::new();
            assert_eq!(
                hex::encode(orchard_tx.v7_txid(&empty).unwrap().as_ref()),
                "c2daa1b9128ec906e6630684658a7ab0547637f178c82fcc0d3e5e12f8ef8d6a"
            );
            assert_eq!(
                hex::encode(orchard_tx.v7_auth_commitment(&empty).unwrap().as_bytes()),
                "c2175c1e2aeba736e72f4a825a9208e04083959a1086fe5183e6cbf566024209"
            );

            let ironwood_tx = v7_tx(v7_body_with_auth(
                vec![zec_delta(4, -1)],
                vec![V7EffectBundleBytes::Ironwood(effects)],
                vec![V7AuthBundleBytes::Ironwood(auth)],
            ));
            assert_eq!(
                hex::encode(ironwood_tx.v7_txid(&empty).unwrap().as_ref()),
                "00f1da46807b218826bc344c5a9da4e304b88b951e9c3d43d6bf81c16ce8b633"
            );
            assert_eq!(
                hex::encode(ironwood_tx.v7_auth_commitment(&empty).unwrap().as_bytes()),
                "57079939a115f14c962e5db9173f1a70b8655835343353d46ea0004b7a77e924"
            );
        }

        #[test]
        fn coinbase_effects_match_independent_digest() {
            let coinbase = CoinbaseBundleBytes::from_parts(
                BlockHeight::from(123_456u32),
                312_500_000,
                31_250_000,
                b"miner".to_vec(),
                vec![],
                None,
            )
            .expect("coinbase bundle construction is infallible");

            assert_eq!(
                hex::encode(hash_v7_coinbase_effects_bytes(&coinbase).as_bytes()),
                "46ceb73aec96091718b895e0d8827e0e572e8cf167bde5c729393559ff4ee266"
            );

            let tx = v7_tx(v7_body(
                vec![zec_delta(1, 281_250_000)],
                vec![V7EffectBundleBytes::Coinbase(coinbase)],
            ));
            let empty = zip248::SuppliedBundleDigests::new();
            assert_eq!(
                hex::encode(tx.v7_txid(&empty).unwrap().as_ref()),
                "94dea93bc55b986319501d8f1ffa1a1afba28225860a44a236bc82c23461cf2e"
            );
        }

        /// Nonempty signals commit the compactSize count, both bytes of every
        /// entry in order, and the poll digest.
        #[test]
        fn multi_signal_coinbase_matches_independent_digest() {
            let coinbase = CoinbaseBundleBytes::from_parts(
                BlockHeight::from(123_456u32),
                312_500_000,
                31_250_000,
                b"miner".to_vec(),
                vec![miner_signal(2, 0x20), miner_signal(9, 0x90)],
                Some(poll_digest(0x7E)),
            )
            .expect("coinbase bundle construction is infallible");

            assert_eq!(
                hex::encode(hash_v7_coinbase_effects_bytes(&coinbase).as_bytes()),
                "0c44da6933fba7caf184dbc6f6f17aa19cf50bd1d466f07d5cfa088247c432fe"
            );

            let tx = v7_tx(v7_body(
                vec![zec_delta(1, 281_250_000)],
                vec![V7EffectBundleBytes::Coinbase(coinbase)],
            ));
            let empty = zip248::SuppliedBundleDigests::new();
            assert_eq!(
                hex::encode(tx.v7_txid(&empty).unwrap().as_ref()),
                "06132e9f4307940a230e2eded484c4b7a6d53276b41cedbe23a72c07a1e3dc93"
            );
        }

        /// An unknown bundle type's supplied digests are committed to under
        /// their exact `(bundleType, bundleVariant)` tags.
        #[test]
        fn unknown_bundle_keys_match_independent_digests() {
            let id = zip248::BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(7));
            let opaque = OpaqueEffectBundleBytes::from_parts(id, vec![0xAA]).unwrap();
            let auth = OpaqueAuthBundleBytes::from_parts(id, vec![0xBB]).unwrap();
            let tx = v7_tx(v7_body_with_auth(
                vec![
                    ValuePoolDeltaBytes::from_parts(
                        BundleType::from_u64(99),
                        BundleVariant::from_u64(7),
                        5,
                    )
                    .unwrap(),
                ],
                vec![V7EffectBundleBytes::Opaque(opaque)],
                vec![V7AuthBundleBytes::Opaque(auth)],
            ));

            let digest = |byte: u8| {
                blake2b_simd::Params::new()
                    .hash_length(32)
                    .personal(b"test_supplied__")
                    .hash(&[byte])
            };
            let mut supplied = zip248::SuppliedBundleDigests::new();
            supplied.insert_effects(id, digest(0x11)).unwrap();
            supplied.insert_auth(id, digest(0x22)).unwrap();

            assert_eq!(
                hex::encode(tx.v7_txid(&supplied).unwrap().as_ref()),
                "9e0ce041a90710b351466c93ed469f4937a72411c9421c4a96216a9dbaa2629a"
            );
            assert_eq!(
                hex::encode(tx.v7_auth_commitment(&supplied).unwrap().as_bytes()),
                "3c5a403d2d8f734925f9a56a7a63049bfdc7b0d7673a1241556f268cb90be8e1"
            );
        }

        /// Keeps `header_preimage` in step with the fixed transaction header,
        /// so the constants above cannot drift from it silently.
        #[test]
        fn vector_header_preimage_matches_a_written_transaction() {
            let tx = v7_tx(v7_body(vec![zec_delta(5, -1)], vec![]));
            let mut wire = Vec::new();
            tx.write(&mut wire).unwrap();
            assert_eq!(&wire[..20], header_preimage().as_slice());
        }

        /// Hashes `data` under `personal`, with no involvement from the code
        /// under test.
        fn h(personal: &[u8; 16], data: &[u8]) -> Blake2bHash {
            blake2b_simd::Params::new()
                .hash_length(32)
                .personal(personal)
                .hash(data)
        }

        /// The canonical `compactSize` encoding of `n`.
        fn compact(n: u64) -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, n as usize).unwrap();
            buf
        }

        /// A `compactSize(1) || 0x00` sighash-info prefix.
        fn sighash_info() -> Vec<u8> {
            vec![0x01, 0x00]
        }

        /// The outer txid personalization for the Nu8 branch this module's
        /// fixtures use.
        fn txid_personal() -> [u8; 16] {
            let mut personal = [0; 16];
            personal[..12].copy_from_slice(b"ZcashTxHash_");
            personal[12..].copy_from_slice(&0xffff_fffbu32.to_le_bytes());
            personal
        }

        /// The outer authorizing-data personalization for the same branch.
        fn auth_personal() -> [u8; 16] {
            let mut personal = [0; 16];
            personal[..12].copy_from_slice(b"ZTxAuthHash_");
            personal[12..].copy_from_slice(&0xffff_fffbu32.to_le_bytes());
            personal
        }

        /// Appends a tagged `(bundleType, bundleVariant, digest)` entry.
        fn push_tagged(
            out: &mut Vec<u8>,
            bundle_type: u64,
            bundle_variant: u64,
            digest: &Blake2bHash,
        ) {
            out.extend_from_slice(&compact(bundle_type));
            out.extend_from_slice(&compact(bundle_variant));
            out.extend_from_slice(digest.as_bytes());
        }

        /// The T.3.2 Sapling effects digest for the module's fixed address
        /// bytes, given each spend's `(cv, nullifier, rk)` and each output's
        /// `cmu`.
        fn sapling_effects_digest(spends: &[[[u8; 32]; 3]], cmus: &[[u8; 32]]) -> Blake2bHash {
            let spends_digest = {
                let mut spends_digest = Vec::new();
                if !spends.is_empty() {
                    let mut compact_h = Vec::new();
                    let mut noncompact_h = Vec::new();
                    for [cv, nullifier, rk] in spends {
                        compact_h.extend_from_slice(nullifier);
                        noncompact_h.extend_from_slice(cv);
                        noncompact_h.extend_from_slice(rk);
                    }
                    spends_digest.extend_from_slice(h(b"ZTxIdSSpendCHash", &compact_h).as_bytes());
                    spends_digest
                        .extend_from_slice(h(b"ZTxIdSSpendNH_v6", &noncompact_h).as_bytes());
                }
                h(b"ZTxIdSSpendsHash", &spends_digest)
            };

            let outputs_digest = {
                let mut outputs_digest = Vec::new();
                if !cmus.is_empty() {
                    let mut compact_h = Vec::new();
                    let mut memos_h = Vec::new();
                    let mut noncompact_h = Vec::new();
                    for cmu in cmus {
                        compact_h.extend_from_slice(cmu);
                        compact_h.extend_from_slice(&[0x77; 32]); // ephemeral key
                        compact_h.extend_from_slice(&[0x88; 52]);
                        memos_h.extend_from_slice(&[0x88; 512]);
                        noncompact_h.extend_from_slice(&[0x66; 32]); // cv
                        noncompact_h.extend_from_slice(&[0x88; 16]);
                        noncompact_h.extend_from_slice(&[0x99; 80]); // out ciphertext
                    }
                    outputs_digest.extend_from_slice(h(b"ZTxIdSOutC__Hash", &compact_h).as_bytes());
                    outputs_digest.extend_from_slice(h(b"ZTxIdSOutM__Hash", &memos_h).as_bytes());
                    outputs_digest
                        .extend_from_slice(h(b"ZTxIdSOutN__Hash", &noncompact_h).as_bytes());
                }
                h(b"ZTxIdSOutputHash", &outputs_digest)
            };

            let mut preimage = Vec::new();
            preimage.extend_from_slice(spends_digest.as_bytes());
            preimage.extend_from_slice(outputs_digest.as_bytes());
            h(b"ZTxIdSaplingH_v7", &preimage)
        }

        /// The T.3.3 Orchard effects digest for `n` copies of the module's
        /// fixed action bytes, with the given flags.
        fn orchard_effects_digest(n: usize, flags: u8) -> Blake2bHash {
            let mut action = Vec::new();
            action.extend_from_slice(&[0x22; 32]); // nullifier
            action.extend_from_slice(&[0x55; 32]); // cmx
            action.extend_from_slice(&[0x66; 32]); // ephemeral key
            action.extend_from_slice(&[0x88; 52]);
            let mut memos = Vec::new();
            memos.extend_from_slice(&[0x88; 512]);
            let mut noncompact = Vec::new();
            noncompact.extend_from_slice(&[0x11; 32]); // cv_net
            noncompact.extend_from_slice(&[0x44; 32]); // rk
            noncompact.extend_from_slice(&[0x88; 16]);
            noncompact.extend_from_slice(&[0x99; 80]);

            let mut preimage = Vec::new();
            preimage.extend_from_slice(h(b"ZTxIdOrcActCHash", &action.repeat(n)).as_bytes());
            preimage.extend_from_slice(h(b"ZTxIdOrcActMHash", &memos.repeat(n)).as_bytes());
            preimage.extend_from_slice(h(b"ZTxIdOrcActNHash", &noncompact.repeat(n)).as_bytes());
            preimage.push(flags);
            h(b"ZTxIdOrchardH_v7", &preimage)
        }

        /// Asserts the txid and authorizing-data commitment of `tx` against
        /// independently assembled preimages.
        fn assert_preimages(
            tx: &TransactionBytes,
            vp_digest: &Blake2bHash,
            effects_bundles: &Blake2bHash,
            auth_bundles: &Blake2bHash,
        ) {
            let mut txid_preimage = h(b"ZTxIdHeadersHash", &header_preimage())
                .as_bytes()
                .to_vec();
            txid_preimage.extend_from_slice(vp_digest.as_bytes());
            txid_preimage.extend_from_slice(effects_bundles.as_bytes());

            let empty = zip248::SuppliedBundleDigests::new();
            assert_eq!(
                tx.v7_txid(&empty).unwrap().as_ref(),
                h(&txid_personal(), &txid_preimage).as_bytes(),
                "txid differs from the independent preimage",
            );
            assert_eq!(
                tx.v7_auth_commitment(&empty).unwrap().as_bytes(),
                h(&auth_personal(), auth_bundles.as_bytes()).as_bytes(),
                "auth commitment differs from the independent preimage",
            );
        }

        /// The T.2 value pool delta digest for the module's fixed fixture.
        fn vp_digest(entries: &[(u64, i64)]) -> Blake2bHash {
            let mut preimage = Vec::new();
            for (bundle_type, value) in entries {
                preimage.extend_from_slice(&compact(*bundle_type));
                preimage.extend_from_slice(&compact(0));
                preimage.extend_from_slice(&value.to_le_bytes());
            }
            h(b"ZTxIdVPDeltaHash", &preimage)
        }

        #[test]
        fn multi_bundle_txid_and_auth_match_independent_preimages() {
            // Two transparent inputs and outputs, so the T.3.0 child digests
            // are pinned across more than one element.
            let inputs = [(outpoint(1, 2), 3u32), (outpoint(3, 4), 5u32)];
            let outputs = [output(1000, &[0x51]), output(2000, &[0x52, 0x53])];
            let effects_transparent = TransparentEffectsBytes::from_parts(
                inputs
                    .iter()
                    .map(|(outpoint, sequence)| {
                        TransparentInputEffectingBytes::from_parts(*outpoint, *sequence)
                    })
                    .collect(),
                outputs.to_vec(),
            );
            let auth_transparent = TransparentAuthBytes::from_parts(vec![
                TransparentInputAuthBytes::from_parts(
                    TransparentSighashInfoBytes::v0(),
                    TransparentScriptBytes::from_bytes(vec![0x61, 0x62]),
                ),
                TransparentInputAuthBytes::from_parts(
                    TransparentSighashInfoBytes::v0(),
                    TransparentScriptBytes::from_bytes(vec![0x63]),
                ),
            ]);

            // Two spends and two outputs.
            let spends = [
                [[0x11; 32], [0x22; 32], [0x44; 32]],
                [[0x12; 32], [0x23; 32], [0x45; 32]],
            ];
            let cmus = [[0x55; 32], [0x56; 32]];
            let effects_sapling = V7SaplingBundleBytes::from_parts(
                spends
                    .iter()
                    .map(|[cv, nullifier, rk]| SaplingSpendBytes::from_parts(*cv, *nullifier, *rk))
                    .collect(),
                cmus.iter()
                    .map(|cmu| {
                        SaplingOutputBytes::from_parts(
                            [0x66; 32],
                            *cmu,
                            [0x77; 32],
                            [0x88; 580],
                            [0x99; 80],
                        )
                    })
                    .collect(),
            );
            let auth_sapling = V7SaplingAuthBytes::from_parts(
                Some([0x33; 32]),
                vec![[0xAA; 192], [0xAB; 192]],
                vec![sapling_signature(0xBB), sapling_signature(0xBC)],
                vec![[0xCC; 192], [0xCD; 192]],
                Some(sapling_signature(0xDD)),
            );

            let effects_orchard =
                V7OrchardBundleBytes::from_parts(vec![action(), action()], 0b0000_0011);
            let auth_orchard = V7OrchardAuthBytes::from_parts(
                Some([0x33; 32]),
                orchard_proof(2),
                vec![orchard_signature(0xBB), orchard_signature(0xBC)],
                Some(orchard_signature(0xCC)),
            );

            let tx = v7_tx(v7_body_with_auth(
                vec![
                    zec_delta(0, -1000),
                    zec_delta(2, -1),
                    zec_delta(3, 1),
                    zec_delta(5, -1),
                ],
                vec![
                    V7EffectBundleBytes::Transparent(effects_transparent),
                    V7EffectBundleBytes::Sapling(effects_sapling),
                    V7EffectBundleBytes::Orchard(effects_orchard),
                ],
                vec![
                    V7AuthBundleBytes::Transparent(auth_transparent),
                    V7AuthBundleBytes::Sapling(auth_sapling),
                    V7AuthBundleBytes::Orchard(auth_orchard),
                ],
            ));

            // T.3.0: the three transparent child digests.
            let mut prevouts = Vec::new();
            let mut sequences = Vec::new();
            for (outpoint, sequence) in &inputs {
                let mut outpoint_bytes = Vec::new();
                outpoint.write(&mut outpoint_bytes).unwrap();
                prevouts.extend_from_slice(&outpoint_bytes);
                sequences.extend_from_slice(&sequence.to_le_bytes());
            }
            let mut outputs_bytes = Vec::new();
            for output in &outputs {
                let mut encoded = Vec::new();
                output.write(&mut encoded).unwrap();
                outputs_bytes.extend_from_slice(&encoded);
            }
            let mut transparent_effects = Vec::new();
            transparent_effects.extend_from_slice(h(b"ZTxIdPrevoutHash", &prevouts).as_bytes());
            transparent_effects.extend_from_slice(h(b"ZTxIdSequencHash", &sequences).as_bytes());
            transparent_effects
                .extend_from_slice(h(b"ZTxIdOutputsHash", &outputs_bytes).as_bytes());
            let transparent_effects = h(b"ZTxIdTranspaHash", &transparent_effects);

            let sapling_effects = sapling_effects_digest(&spends, &cmus);
            let orchard_effects = orchard_effects_digest(2, 0b0000_0011);

            // T.3: the tagged effecting entries.
            let mut effect_entries = Vec::new();
            push_tagged(&mut effect_entries, 0, 0, &transparent_effects);
            push_tagged(&mut effect_entries, 2, 0, &sapling_effects);
            push_tagged(&mut effect_entries, 3, 0, &orchard_effects);

            // A.1.0: each input's sighash info followed by its scriptSig.
            let mut transparent_auth = Vec::new();
            for script in [&[0x61, 0x62][..], &[0x63][..]] {
                transparent_auth.extend_from_slice(&sighash_info());
                transparent_auth.extend_from_slice(&compact(script.len() as u64));
                transparent_auth.extend_from_slice(script);
            }
            let transparent_auth = h(b"ZTxAuthTransHash", &transparent_auth);

            // A.1.2: anchor, proofs, each sighash-info-prefixed spend
            // signature, output proofs, and the binding signature.
            let mut sapling_auth = Vec::new();
            sapling_auth.extend_from_slice(&[0x33; 32]);
            sapling_auth.extend_from_slice(&[0xAA; 192]);
            sapling_auth.extend_from_slice(&[0xAB; 192]);
            for sig in [0xBBu8, 0xBC] {
                sapling_auth.extend_from_slice(&sighash_info());
                sapling_auth.extend_from_slice(&[sig; 64]);
            }
            sapling_auth.extend_from_slice(&[0xCC; 192]);
            sapling_auth.extend_from_slice(&[0xCD; 192]);
            sapling_auth.extend_from_slice(&sighash_info());
            sapling_auth.extend_from_slice(&[0xDD; 64]);
            let sapling_auth = h(b"ZTxAuthSapliH_v7", &sapling_auth);

            // A.1.3: anchor, the aggregated proof, each sighash-info-prefixed
            // spend signature, and the binding signature.
            let mut orchard_auth = Vec::new();
            orchard_auth.extend_from_slice(&[0x33; 32]);
            orchard_auth.extend_from_slice(&orchard_proof(2));
            for sig in [0xBBu8, 0xBC] {
                orchard_auth.extend_from_slice(&sighash_info());
                orchard_auth.extend_from_slice(&[sig; 64]);
            }
            orchard_auth.extend_from_slice(&sighash_info());
            orchard_auth.extend_from_slice(&[0xCC; 64]);
            let orchard_auth = h(b"ZTxAuthOrchaH_v7", &orchard_auth);

            // A.1: the tagged authorizing entries.
            let mut auth_entries = Vec::new();
            push_tagged(&mut auth_entries, 0, 0, &transparent_auth);
            push_tagged(&mut auth_entries, 2, 0, &sapling_auth);
            push_tagged(&mut auth_entries, 3, 0, &orchard_auth);

            assert_preimages(
                &tx,
                &vp_digest(&[(0, -1000), (2, -1), (3, 1), (5, -1)]),
                &h(b"ZTxIdEffBnd_Hash", &effect_entries),
                &h(b"ZTxAuthBnd__Hash", &auth_entries),
            );
        }

        #[test]
        fn sapling_spend_only_matches_independent_preimages() {
            let spends = [[[0x11; 32], [0x22; 32], [0x44; 32]]];
            let effects = V7SaplingBundleBytes::from_parts(
                vec![SaplingSpendBytes::from_parts(
                    spends[0][0],
                    spends[0][1],
                    spends[0][2],
                )],
                vec![],
            );
            let auth = V7SaplingAuthBytes::from_parts(
                Some([0x33; 32]),
                vec![[0xAA; 192]],
                vec![sapling_signature(0xBB)],
                vec![],
                Some(sapling_signature(0xDD)),
            );
            let tx = v7_tx(v7_body_with_auth(
                vec![zec_delta(2, -1)],
                vec![V7EffectBundleBytes::Sapling(effects.clone())],
                vec![V7AuthBundleBytes::Sapling(auth)],
            ));

            let effects_digest = sapling_effects_digest(&spends, &[]);

            let mut auth_preimage = Vec::new();
            auth_preimage.extend_from_slice(&[0x33; 32]);
            auth_preimage.extend_from_slice(&[0xAA; 192]);
            auth_preimage.extend_from_slice(&sighash_info());
            auth_preimage.extend_from_slice(&[0xBB; 64]);
            auth_preimage.extend_from_slice(&sighash_info());
            auth_preimage.extend_from_slice(&[0xDD; 64]);

            let mut effects_entry = Vec::new();
            push_tagged(&mut effects_entry, 2, 0, &effects_digest);
            let mut auth_entry = Vec::new();
            push_tagged(
                &mut auth_entry,
                2,
                0,
                &h(b"ZTxAuthSapliH_v7", &auth_preimage),
            );

            assert_preimages(
                &tx,
                &vp_digest(&[(2, -1)]),
                &h(b"ZTxIdEffBnd_Hash", &effects_entry),
                &h(b"ZTxAuthBnd__Hash", &auth_entry),
            );
        }

        /// An output-only Sapling bundle has no spends, so A.1.2 commits to
        /// neither an anchor nor spend proofs or signatures.
        #[test]
        fn sapling_output_only_auth_omits_the_anchor() {
            let cmus = [[0x55; 32]];
            let effects = V7SaplingBundleBytes::from_parts(
                vec![],
                vec![SaplingOutputBytes::from_parts(
                    [0x66; 32],
                    cmus[0],
                    [0x77; 32],
                    [0x88; 580],
                    [0x99; 80],
                )],
            );
            let auth = V7SaplingAuthBytes::from_parts(
                None,
                vec![],
                vec![],
                vec![[0xCC; 192]],
                Some(sapling_signature(0xDD)),
            );
            let tx = v7_tx(v7_body_with_auth(
                vec![zec_delta(2, -1)],
                vec![V7EffectBundleBytes::Sapling(effects)],
                vec![V7AuthBundleBytes::Sapling(auth)],
            ));

            let effects_digest = sapling_effects_digest(&[], &cmus);

            let mut auth_preimage = Vec::new();
            auth_preimage.extend_from_slice(&[0xCC; 192]);
            auth_preimage.extend_from_slice(&sighash_info());
            auth_preimage.extend_from_slice(&[0xDD; 64]);

            let mut effects_entry = Vec::new();
            push_tagged(&mut effects_entry, 2, 0, &effects_digest);
            let mut auth_entry = Vec::new();
            push_tagged(
                &mut auth_entry,
                2,
                0,
                &h(b"ZTxAuthSapliH_v7", &auth_preimage),
            );

            assert_preimages(
                &tx,
                &vp_digest(&[(2, -1)]),
                &h(b"ZTxIdEffBnd_Hash", &effects_entry),
                &h(b"ZTxAuthBnd__Hash", &auth_entry),
            );
        }

        /// An inputs-only transparent bundle pins the auth entry; its output
        /// list is empty.
        #[test]
        fn transparent_input_only_matches_independent_preimages() {
            let effects = TransparentEffectsBytes::from_parts(
                vec![TransparentInputEffectingBytes::from_parts(
                    outpoint(1, 2),
                    3,
                )],
                vec![],
            );
            let auth =
                TransparentAuthBytes::from_parts(vec![TransparentInputAuthBytes::from_parts(
                    TransparentSighashInfoBytes::v0(),
                    TransparentScriptBytes::from_bytes(vec![0x61]),
                )]);
            let tx = v7_tx(v7_body_with_auth(
                vec![zec_delta(0, -1000)],
                vec![V7EffectBundleBytes::Transparent(effects)],
                vec![V7AuthBundleBytes::Transparent(auth)],
            ));

            let mut prevouts = Vec::new();
            outpoint(1, 2).write(&mut prevouts).unwrap();
            let mut transparent_effects = Vec::new();
            transparent_effects.extend_from_slice(h(b"ZTxIdPrevoutHash", &prevouts).as_bytes());
            transparent_effects
                .extend_from_slice(h(b"ZTxIdSequencHash", &3u32.to_le_bytes()).as_bytes());
            transparent_effects.extend_from_slice(h(b"ZTxIdOutputsHash", &[]).as_bytes());

            let mut auth_preimage = Vec::new();
            auth_preimage.extend_from_slice(&sighash_info());
            auth_preimage.extend_from_slice(&compact(1));
            auth_preimage.extend_from_slice(&[0x61]);

            let mut effects_entry = Vec::new();
            push_tagged(
                &mut effects_entry,
                0,
                0,
                &h(b"ZTxIdTranspaHash", &transparent_effects),
            );
            let mut auth_entry = Vec::new();
            push_tagged(
                &mut auth_entry,
                0,
                0,
                &h(b"ZTxAuthTransHash", &auth_preimage),
            );

            assert_preimages(
                &tx,
                &vp_digest(&[(0, -1000)]),
                &h(b"ZTxIdEffBnd_Hash", &effects_entry),
                &h(b"ZTxAuthBnd__Hash", &auth_entry),
            );
        }

        /// An outputs-only transparent bundle has no authorizing entry at all,
        /// and its empty input and sequence child digests are still hashed.
        #[test]
        fn transparent_output_only_omits_the_auth_entry() {
            let effects = TransparentEffectsBytes::from_parts(vec![], vec![output(1000, &[0x51])]);
            let tx = v7_tx(v7_body(
                vec![zec_delta(0, 1000)],
                vec![V7EffectBundleBytes::Transparent(effects)],
            ));

            let mut output_bytes = Vec::new();
            output(1000, &[0x51]).write(&mut output_bytes).unwrap();
            let mut transparent_effects = Vec::new();
            transparent_effects.extend_from_slice(h(b"ZTxIdPrevoutHash", &[]).as_bytes());
            transparent_effects.extend_from_slice(h(b"ZTxIdSequencHash", &[]).as_bytes());
            transparent_effects.extend_from_slice(h(b"ZTxIdOutputsHash", &output_bytes).as_bytes());

            let mut effects_entry = Vec::new();
            push_tagged(
                &mut effects_entry,
                0,
                0,
                &h(b"ZTxIdTranspaHash", &transparent_effects),
            );

            assert_preimages(
                &tx,
                &vp_digest(&[(0, 1000)]),
                &h(b"ZTxIdEffBnd_Hash", &effects_entry),
                &h(b"ZTxAuthBnd__Hash", &[]),
            );
        }

        /// A bundle identifier above 252 needs a multi-byte `compactSize`, as
        /// does the payload length, so both tagged-map encodings are pinned
        /// beyond one byte.
        #[test]
        fn multi_byte_compact_size_keys_match_independent_preimages() {
            use crate::transaction::zip248::BundleId;

            const BUNDLE_TYPE: u64 = 300;
            const BUNDLE_VARIANT: u64 = 260;
            let id = BundleId::new(
                BundleType::from_u64(BUNDLE_TYPE),
                BundleVariant::from_u64(BUNDLE_VARIANT),
            );
            let effects = OpaqueEffectBundleBytes::from_parts(id, vec![0xAA; 253]).unwrap();
            let auth = OpaqueAuthBundleBytes::from_parts(id, vec![0xBB; 253]).unwrap();
            let tx = v7_tx(v7_body_with_auth(
                vec![
                    ValuePoolDeltaBytes::from_parts(
                        BundleType::from_u64(BUNDLE_TYPE),
                        BundleVariant::from_u64(BUNDLE_VARIANT),
                        5,
                    )
                    .unwrap(),
                ],
                vec![V7EffectBundleBytes::Opaque(effects)],
                vec![V7AuthBundleBytes::Opaque(auth)],
            ));

            let effect_digest = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"test_effects_dgt")
                .hash(&[0xAA; 253]);
            let auth_digest = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"test_auth_digest")
                .hash(&[0xBB; 253]);

            let mut supplied = zip248::SuppliedBundleDigests::new();
            supplied.insert_effects(id, effect_digest).unwrap();
            supplied.insert_auth(id, auth_digest).unwrap();

            let mut effects_entry = Vec::new();
            push_tagged(
                &mut effects_entry,
                BUNDLE_TYPE,
                BUNDLE_VARIANT,
                &effect_digest,
            );
            let mut auth_entry = Vec::new();
            push_tagged(&mut auth_entry, BUNDLE_TYPE, BUNDLE_VARIANT, &auth_digest);

            let mut vp = Vec::new();
            vp.extend_from_slice(&compact(BUNDLE_TYPE));
            vp.extend_from_slice(&compact(BUNDLE_VARIANT));
            vp.extend_from_slice(&5i64.to_le_bytes());

            let mut txid_preimage = h(b"ZTxIdHeadersHash", &header_preimage())
                .as_bytes()
                .to_vec();
            txid_preimage.extend_from_slice(h(b"ZTxIdVPDeltaHash", &vp).as_bytes());
            txid_preimage.extend_from_slice(h(b"ZTxIdEffBnd_Hash", &effects_entry).as_bytes());

            assert_eq!(
                tx.v7_txid(&supplied).unwrap().as_ref(),
                h(&txid_personal(), &txid_preimage).as_bytes(),
            );
            assert_eq!(
                tx.v7_auth_commitment(&supplied).unwrap().as_bytes(),
                h(
                    &auth_personal(),
                    h(b"ZTxAuthBnd__Hash", &auth_entry).as_bytes()
                )
                .as_bytes(),
            );
        }
    }

    // Legitimately opaque entries round-trip byte for byte across
    // `compactSize` boundaries, and their commitments match independently
    // assembled preimages.
    //
    // The generated identifiers avoid the recognized `(bundleType, variant 0)`
    // pairs, which cannot be opaque.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn v7_opaque_entries_round_trip_across_encoding_boundaries(
            pair in prop_oneof![
                (7u64..=700).prop_map(|bundle_type| (bundle_type, 0u64)),
                (0u64..=6).prop_map(|bundle_type| (bundle_type, 1u64)),
            ],
            effect_len in prop_oneof![Just(0usize), Just(1), Just(252), Just(253), Just(300)],
            auth_len in prop_oneof![Just(0usize), Just(1), Just(252), Just(253), Just(300)],
        ) {
            use crate::transaction::zip248::BundleId;

            let (bundle_type, bundle_variant) = pair;
            let id = BundleId::new(
                BundleType::from_u64(bundle_type),
                BundleVariant::from_u64(bundle_variant),
            );
            let effects = vec![0xAA; effect_len];
            let auth = vec![0xBB; auth_len];

            let body = v7_body_with_auth(
                vec![],
                vec![V7EffectBundleBytes::Opaque(
                    OpaqueEffectBundleBytes::from_parts(id, effects.clone()).unwrap(),
                )],
                vec![V7AuthBundleBytes::Opaque(
                    OpaqueAuthBundleBytes::from_parts(id, auth.clone()).unwrap(),
                )],
            );

            let mut wire = Vec::new();
            body.write(&mut wire).unwrap();
            let decoded = V7TransactionBodyBytes::read(&wire[..]).unwrap();
            let mut reserialized = Vec::new();
            decoded.write(&mut reserialized).unwrap();
            prop_assert_eq!(reserialized, wire);

            // T.2 has no entries; both T.3 and A.1 hold one tagged entry.
            let h = |personal: &[u8; 16], data: &[u8]| {
                blake2b_simd::Params::new()
                    .hash_length(32)
                    .personal(personal)
                    .hash(data)
            };
            let compact = |n: u64| {
                let mut buf = Vec::new();
                CompactSize::write(&mut buf, n as usize).unwrap();
                buf
            };
            let tag = |digest: &blake2b_simd::Hash| {
                let mut entry = Vec::new();
                entry.extend_from_slice(&compact(bundle_type));
                entry.extend_from_slice(&compact(bundle_variant));
                entry.extend_from_slice(digest.as_bytes());
                entry
            };

            let effect_digest = h(b"test_effects_dgt", &effects);
            let auth_digest = h(b"test_auth_digest", &auth);
            let mut supplied = zip248::SuppliedBundleDigests::new();
            supplied.insert_effects(id, effect_digest).unwrap();
            supplied.insert_auth(id, auth_digest).unwrap();

            let tx = v7_tx(body);
            let mut header_preimage = Vec::new();
            header_preimage.extend_from_slice(&(7u32 | (1 << 31)).to_le_bytes());
            header_preimage
                .extend_from_slice(&zcash_protocol::constants::V7_VERSION_GROUP_ID.to_le_bytes());
            header_preimage.extend_from_slice(&0xffff_fffbu32.to_le_bytes());
            header_preimage.extend_from_slice(&0u32.to_le_bytes());
            header_preimage.extend_from_slice(&100u32.to_le_bytes());
            let header_digest = h(b"ZTxIdHeadersHash", &header_preimage);
            let vp_digest = h(b"ZTxIdVPDeltaHash", &[]);
            let effects_bundles = h(b"ZTxIdEffBnd_Hash", &tag(&effect_digest));
            let auth_bundles = h(b"ZTxAuthBnd__Hash", &tag(&auth_digest));

            let mut personal = [0; 16];
            personal[..12].copy_from_slice(b"ZcashTxHash_");
            personal[12..].copy_from_slice(&0xffff_fffbu32.to_le_bytes());
            let mut txid_preimage = header_digest.as_bytes().to_vec();
            txid_preimage.extend_from_slice(vp_digest.as_bytes());
            txid_preimage.extend_from_slice(effects_bundles.as_bytes());
            let actual_txid = tx.v7_txid(&supplied).unwrap();
            let expected_txid = h(&personal, &txid_preimage);
            prop_assert_eq!(actual_txid.as_ref(), expected_txid.as_bytes());

            let mut personal = [0; 16];
            personal[..12].copy_from_slice(b"ZTxAuthHash_");
            personal[12..].copy_from_slice(&0xffff_fffbu32.to_le_bytes());
            let actual_auth = tx.v7_auth_commitment(&supplied).unwrap();
            let expected_auth = h(&personal, auth_bundles.as_bytes());
            prop_assert_eq!(actual_auth.as_bytes(), expected_auth.as_bytes());
        }
    }
}

/// Exercises the Sapling byte-to-typed conversion without requiring the
/// Orchard domain. The bundle is generated by the Sapling crate's testing
/// strategy, serialized in the v5 wire format, parsed back as bytes, and
/// converted to a typed bundle.
#[cfg(feature = "sapling")]
mod sapling_typed_conversion {
    use alloc::vec::Vec;

    use proptest::prelude::*;
    #[cfg(zcash_unstable = "nu8")]
    use proptest::{strategy::ValueTree, test_runner::TestRunner};
    use zcash_protocol::value::ZatBalance;

    use crate::transaction::{bytes::SaplingBundleBytes, components::sapling::write_v5_bundle};

    proptest! {
        #[test]
        fn sapling_bytes_convert_to_typed(
            bundle in sapling::bundle::testing::arb_bundle(ZatBalance::zero()),
        ) {
            let Some(bundle) = bundle else { return Ok(()); };

            let mut bytes = Vec::new();
            write_v5_bundle(&mut bytes, Some(&bundle)).unwrap();

            let parsed = SaplingBundleBytes::read(&mut &bytes[..]).unwrap().unwrap();
            let converted = parsed.to_authorized().unwrap();

            let mut reserialized = Vec::new();
            write_v5_bundle(&mut reserialized, Some(&converted)).unwrap();
            prop_assert_eq!(bytes, reserialized);
        }
    }

    /// A wallet built with only the Sapling domain can parse a v7 transaction
    /// carrying both shielded protocols, interpret the Sapling bundle, and
    /// leave the Orchard bundle as bytes.
    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_subset_wallet_converts_only_sapling() {
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        use super::orchard_proof;
        use crate::transaction::{
            TxVersion,
            bytes::{
                BundleType, BundleVariant, OrchardActionBytes, OrchardSignatureBytes,
                SighashInfoBytes, TransactionBodyBytes, TransactionBytes, V7AuthBundleBytes,
                V7EffectBundleBytes, V7OrchardAuthBytes, V7OrchardBundleBytes, V7SaplingAuthBytes,
                V7SaplingBundleBytes, V7TransactionBodyBytes, ValuePoolDeltaBytes,
            },
        };

        fn zec_delta(bundle_type: u64, value: i64) -> ValuePoolDeltaBytes {
            ValuePoolDeltaBytes::from_parts(
                BundleType::from_u64(bundle_type),
                BundleVariant::from_u64(0),
                value,
            )
            .unwrap()
        }

        fn v7_sapling_bytes(
            bundle: &sapling::bundle::Bundle<sapling::bundle::Authorized, ZatBalance>,
        ) -> V7SaplingBundleBytes {
            V7SaplingBundleBytes::from_bundle(bundle)
        }

        fn v7_sapling_auth_bytes(
            bundle: &sapling::bundle::Bundle<sapling::bundle::Authorized, ZatBalance>,
        ) -> V7SaplingAuthBytes {
            V7SaplingAuthBytes::from_bundle(bundle).unwrap()
        }

        fn dummy_v7_orchard() -> V7OrchardBundleBytes {
            V7OrchardBundleBytes::from_parts(
                vec![OrchardActionBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
                )],
                0,
            )
        }

        fn dummy_v7_orchard_auth() -> V7OrchardAuthBytes {
            V7OrchardAuthBytes::from_parts(
                Some([0u8; 32]),
                orchard_proof(1),
                vec![OrchardSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    [0u8; 64],
                )],
                Some(OrchardSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    [0u8; 64],
                )),
            )
        }

        let mut runner = TestRunner::default();
        let sapling = crate::transaction::components::sapling::testing::arb_bundle()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let Some(sapling) = sapling else {
            return;
        };
        let sapling_value = *sapling.value_balance();

        let mut deltas = vec![zec_delta(3, 1)];
        if sapling_value != ZatBalance::zero() {
            deltas.push(zec_delta(2, i64::from(sapling_value)));
        }
        deltas.sort_by_key(|delta| delta.bundle_type().to_u64());

        let body = V7TransactionBodyBytes::from_parts(
            deltas,
            vec![
                V7EffectBundleBytes::Sapling(v7_sapling_bytes(&sapling)),
                V7EffectBundleBytes::Orchard(dummy_v7_orchard()),
            ],
            vec![
                V7AuthBundleBytes::Sapling(v7_sapling_auth_bytes(&sapling)),
                V7AuthBundleBytes::Orchard(dummy_v7_orchard_auth()),
            ],
        )
        .unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(u32::from(BranchId::Nu8)),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();
        let mut wire = Vec::new();
        tx.write(&mut wire).unwrap();

        let parsed = TransactionBytes::read(&wire[..]).unwrap();
        let body = parsed.body().as_v7().unwrap();
        assert_eq!(body.sapling().unwrap(), &v7_sapling_bytes(&sapling));
        let converted = body
            .sapling_auth()
            .unwrap()
            .to_authorized(body.sapling().unwrap(), sapling_value)
            .unwrap();
        assert_eq!(converted.value_balance(), sapling.value_balance());
        assert_eq!(
            converted.shielded_spends().len(),
            sapling.shielded_spends().len()
        );
        assert_eq!(
            converted.shielded_outputs().len(),
            sapling.shielded_outputs().len()
        );
        // The Orchard bundle is retained as bytes and is not interpreted.
        assert!(body.orchard().is_some());
        assert_eq!(
            body.zec_value_pool_delta(BundleType::from_u64(2)),
            (sapling_value != ZatBalance::zero()).then_some(i64::from(sapling_value))
        );
        assert_eq!(body.zec_value_pool_delta(BundleType::from_u64(3)), Some(1));
        assert_eq!(body.zec_value_pool_delta(BundleType::from_u64(4)), None);

        let mut reserialized = Vec::new();
        parsed.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, wire);
    }
}

/// Exercises the Orchard byte-to-typed conversion without requiring the
/// Sapling domain. The bundle is generated by the Orchard crate's testing
/// strategy, serialized in the v5 wire format, parsed back as bytes, and
/// converted to a typed bundle.
#[cfg(feature = "orchard")]
mod orchard_typed_conversion {
    use alloc::vec::Vec;

    use proptest::prelude::*;
    #[cfg(zcash_unstable = "nu8")]
    use proptest::{strategy::ValueTree, test_runner::TestRunner};
    use zcash_protocol::value::ZatBalance;

    use crate::transaction::{bytes::OrchardBundleBytes, components::orchard::write_v5_bundle};

    proptest! {
        #[test]
        fn orchard_bytes_convert_to_typed(
            bundle in orchard::bundle::testing::arb_bundle(1usize),
        ) {
            let Some(bundle) = bundle
                .try_map_value_balance(|value| {
                    let value = i64::try_from(value).map_err(|_| ())?;
                    ZatBalance::from_i64(value).map_err(|_| ())
                })
                .ok()
            else {
                return Ok(());
            };

            let mut bytes = Vec::new();
            write_v5_bundle(Some(&bundle), &mut bytes).unwrap();

            let parsed = OrchardBundleBytes::read(&mut &bytes[..]).unwrap().unwrap();
            let converted = parsed
                .to_authorized(Some(bundle.bundle_version()))
                .unwrap();

            let mut reserialized = Vec::new();
            write_v5_bundle(Some(&converted), &mut reserialized).unwrap();
            prop_assert_eq!(bytes, reserialized);
        }
    }

    /// A wallet built with only the Orchard domain can parse a v7 transaction
    /// carrying both shielded protocols, interpret the Orchard bundle, and
    /// leave the Sapling bundle as bytes.
    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_subset_wallet_converts_only_orchard() {
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        use crate::transaction::{
            TxVersion,
            bytes::{
                BundleType, BundleVariant, SaplingOutputBytes, SaplingSignatureBytes,
                SaplingSpendBytes, SighashInfoBytes, TransactionBodyBytes, TransactionBytes,
                V7AuthBundleBytes, V7EffectBundleBytes, V7OrchardAuthBytes, V7OrchardBundleBytes,
                V7SaplingAuthBytes, V7SaplingBundleBytes, V7TransactionBodyBytes,
                ValuePoolDeltaBytes,
            },
        };

        fn zec_delta(bundle_type: u64, value: i64) -> ValuePoolDeltaBytes {
            ValuePoolDeltaBytes::from_parts(
                BundleType::from_u64(bundle_type),
                BundleVariant::from_u64(0),
                value,
            )
            .unwrap()
        }

        fn v7_orchard_bytes(
            bundle: &orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
        ) -> V7OrchardBundleBytes {
            crate::transaction::components::orchard::v7_bundle_to_bytes(bundle)
                .unwrap()
                .0
        }

        fn v7_orchard_auth_bytes(
            bundle: &orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
        ) -> V7OrchardAuthBytes {
            crate::transaction::components::orchard::v7_bundle_to_bytes(bundle)
                .unwrap()
                .1
        }

        fn dummy_v7_sapling() -> V7SaplingBundleBytes {
            V7SaplingBundleBytes::from_parts(
                vec![SaplingSpendBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32],
                )],
                vec![SaplingOutputBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
                )],
            )
        }

        fn dummy_v7_sapling_auth() -> V7SaplingAuthBytes {
            V7SaplingAuthBytes::from_parts(
                Some([0u8; 32]),
                vec![[0u8; 192]],
                vec![SaplingSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    [0u8; 64],
                )],
                vec![[0u8; 192]],
                Some(SaplingSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    [0u8; 64],
                )),
            )
        }

        let mut runner = TestRunner::default();
        let orchard = orchard::bundle::testing::arb_bundle(1usize)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let Some(orchard) = orchard
            .try_map_value_balance(|value| {
                let value = i64::try_from(value).map_err(|_| ())?;
                ZatBalance::from_i64(value).map_err(|_| ())
            })
            .ok()
        else {
            return;
        };
        let orchard = crate::transaction::components::orchard::testing::rebuild_with_version(
            orchard,
            orchard::bundle::BundleVersion::orchard_v3(),
        );
        let orchard_value = *orchard.value_balance();

        let mut deltas = vec![zec_delta(2, 1)];
        if orchard_value != ZatBalance::zero() {
            deltas.push(zec_delta(3, i64::from(orchard_value)));
        }
        deltas.sort_by_key(|delta| delta.bundle_type().to_u64());

        let body = V7TransactionBodyBytes::from_parts(
            deltas,
            vec![
                V7EffectBundleBytes::Sapling(dummy_v7_sapling()),
                V7EffectBundleBytes::Orchard(v7_orchard_bytes(&orchard)),
            ],
            vec![
                V7AuthBundleBytes::Sapling(dummy_v7_sapling_auth()),
                V7AuthBundleBytes::Orchard(v7_orchard_auth_bytes(&orchard)),
            ],
        )
        .unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(u32::from(BranchId::Nu8)),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();
        let mut wire = Vec::new();
        tx.write(&mut wire).unwrap();

        let parsed = TransactionBytes::read(&wire[..]).unwrap();
        let body = parsed.body().as_v7().unwrap();
        assert_eq!(body.orchard().unwrap(), &v7_orchard_bytes(&orchard));
        let converted = body
            .orchard_auth()
            .unwrap()
            .to_authorized(
                body.orchard().unwrap(),
                orchard_value,
                Some(orchard.bundle_version()),
            )
            .unwrap();
        assert_eq!(converted.value_balance(), orchard.value_balance());
        assert_eq!(converted.actions().len(), orchard.actions().len());
        // The Sapling bundle is retained as bytes and is not interpreted.
        assert!(body.sapling().is_some());
        assert_eq!(body.zec_value_pool_delta(BundleType::from_u64(2)), Some(1));
        assert_eq!(
            body.zec_value_pool_delta(BundleType::from_u64(3)),
            (orchard_value != ZatBalance::zero()).then_some(i64::from(orchard_value))
        );
        assert_eq!(body.zec_value_pool_delta(BundleType::from_u64(4)), None);

        let mut reserialized = Vec::new();
        parsed.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, wire);
    }
}

/// `nConsensusBranchId` is a `uint32` on the wire, so the byte layer retains
/// values this implementation does not recognize instead of rejecting them as
/// malformed. Typed interpretation is where recognition is required.
mod raw_branch_id {
    use alloc::vec::Vec;

    #[cfg(all(feature = "sapling", feature = "orchard"))]
    use corez::io;
    use zcash_protocol::consensus::{BlockHeight, BranchId};

    use crate::transaction::{
        TxVersion,
        bytes::{
            LegacyTransparentBundleBytes, TransactionBodyBytes, TransactionBytes,
            V5TransactionBodyBytes, V6TransactionBodyBytes,
        },
    };

    /// Not a value assigned to any [`BranchId`].
    const UNKNOWN_BRANCH_ID: u32 = 0xdead_beef;

    fn v5_empty() -> TransactionBytes {
        let body =
            V5TransactionBodyBytes::from_parts(LegacyTransparentBundleBytes::default(), None, None);
        TransactionBytes::from_parts(
            TxVersion::V5,
            Some(u32::from(BranchId::Nu5)),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V5(body),
        )
        .unwrap()
    }

    fn v6_empty() -> TransactionBytes {
        let body = V6TransactionBodyBytes::from_parts(
            LegacyTransparentBundleBytes::default(),
            None,
            None,
            None,
        );
        TransactionBytes::from_parts(
            TxVersion::V6,
            Some(u32::from(BranchId::Nu6_3)),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V6(body),
        )
        .unwrap()
    }

    /// Serializes `tx`, then replaces the encoded `nConsensusBranchId` with
    /// `UNKNOWN_BRANCH_ID`. In versions 5 and later the header is
    /// `nVersion || nVersionGroupId || nConsensusBranchId`, so the branch ID
    /// occupies bytes 8 through 12.
    fn with_unknown_branch_id(tx: &TransactionBytes) -> Vec<u8> {
        let mut wire = Vec::new();
        tx.write(&mut wire).unwrap();
        wire[8..12].copy_from_slice(&UNKNOWN_BRANCH_ID.to_le_bytes());
        wire
    }

    fn assert_unknown_branch_id_round_trips(tx: &TransactionBytes) {
        let wire = with_unknown_branch_id(tx);
        let parsed = TransactionBytes::read(&wire[..]).unwrap();
        assert_eq!(parsed.raw_consensus_branch_id(), Some(UNKNOWN_BRANCH_ID));
        assert_eq!(parsed.consensus_branch_id(), None);
        assert!(parsed.try_consensus_branch_id().is_err());

        let mut reserialized = Vec::new();
        parsed.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, wire);
    }

    #[test]
    fn unknown_branch_id_round_trips_v5() {
        assert_unknown_branch_id_round_trips(&v5_empty());
    }

    #[test]
    fn unknown_branch_id_round_trips_v6() {
        assert_unknown_branch_id_round_trips(&v6_empty());
    }

    #[test]
    fn unknown_branch_id_constructs_and_round_trips_v6() {
        let body = V6TransactionBodyBytes::from_parts(
            LegacyTransparentBundleBytes::default(),
            None,
            None,
            None,
        );
        let tx = TransactionBytes::from_parts(
            TxVersion::V6,
            Some(UNKNOWN_BRANCH_ID),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V6(body),
        )
        .unwrap();

        assert_eq!(tx.raw_consensus_branch_id(), Some(UNKNOWN_BRANCH_ID));
        assert_eq!(tx.consensus_branch_id(), None);
        assert!(tx.try_consensus_branch_id().is_err());

        let mut wire = Vec::new();
        tx.write(&mut wire).unwrap();
        assert_eq!(wire, with_unknown_branch_id(&v6_empty()));
        assert_eq!(TransactionBytes::read(&wire[..]).unwrap(), tx);
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_zero_branch_id_is_rejected() {
        let body = super::V7TransactionBodyBytes::from_parts(vec![], vec![], vec![]).unwrap();
        assert!(
            TransactionBytes::from_parts(
                TxVersion::V7,
                Some(0),
                0,
                BlockHeight::from(100u32),
                TransactionBodyBytes::V7(body.clone()),
            )
            .is_err()
        );
        let unchecked = TransactionBytes::from_parts_unchecked(
            TxVersion::V7,
            Some(0),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body.clone()),
        );
        let mut wire = Vec::new();
        assert!(unchecked.write(&mut wire).is_err());
        assert!(wire.is_empty());

        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(UNKNOWN_BRANCH_ID),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();
        assert_unknown_branch_id_round_trips(&tx);
        tx.write(&mut wire).unwrap();
        /// The v5+ wire header places the branch ID after version and group ID.
        const BRANCH_ID_OFFSET: usize = 8;
        const BRANCH_ID_SIZE: usize = size_of::<u32>();
        wire[BRANCH_ID_OFFSET..BRANCH_ID_OFFSET + BRANCH_ID_SIZE].fill(0);
        assert_eq!(
            TransactionBytes::read(&wire[..]).unwrap_err().kind(),
            corez::io::ErrorKind::InvalidData,
        );
    }

    #[cfg(all(feature = "sapling", feature = "orchard"))]
    #[test]
    fn unknown_branch_id_fails_typed_conversion() {
        use alloc::string::ToString;

        let body =
            V5TransactionBodyBytes::from_parts(LegacyTransparentBundleBytes::default(), None, None);
        let tx = TransactionBytes::from_parts(
            TxVersion::V5,
            Some(UNKNOWN_BRANCH_ID),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V5(body),
        )
        .unwrap();
        let mut wire = Vec::new();
        tx.write(&mut wire).unwrap();

        let error = crate::transaction::Transaction::read(&wire[..], BranchId::Nu5)
            .expect_err("typed conversion must reject an unrecognized branch ID");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("unrecognized consensus branch ID")
        );
    }

    #[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
    #[test]
    fn unknown_branch_id_v7_digests_use_raw_branch_and_validation_rejects() {
        use crate::transaction::{
            V7ValidationError,
            bytes::V7TransactionBodyBytes,
            zip248::{self, V7DigestError},
        };

        /// BLAKE2b-256 under `personal` over the concatenation of `parts`.
        fn hash(personal: &[u8; 16], parts: &[&[u8]]) -> blake2b_simd::Hash {
            let mut state = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(personal)
                .to_state();
            for part in parts {
                state.update(part);
            }
            state.finalize()
        }

        let body = V7TransactionBodyBytes::from_parts(vec![], vec![], vec![]).unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(UNKNOWN_BRANCH_ID),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();
        let mut wire = Vec::new();
        tx.write(&mut wire).unwrap();
        let parsed = TransactionBytes::read(&wire[..]).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(parsed.raw_consensus_branch_id(), Some(UNKNOWN_BRANCH_ID));
        assert!(parsed.try_consensus_branch_id().is_err());

        let provider = zip248::SuppliedBundleDigests::new();
        let digests = parsed.v7_txid_digests(&provider).unwrap();
        let txid = parsed.v7_txid(&provider).unwrap();
        let auth_commitment = parsed.v7_auth_commitment(&provider).unwrap();

        // Reconstruct the digest tree independently, committing the raw
        // little-endian branch ID in the header preimage and in both top-level
        // personalizations.
        let version = TxVersion::V7;
        let mut header_preimage = Vec::new();
        header_preimage.extend_from_slice(&version.header().to_le_bytes());
        header_preimage.extend_from_slice(&version.version_group_id().to_le_bytes());
        header_preimage.extend_from_slice(&UNKNOWN_BRANCH_ID.to_le_bytes());
        header_preimage.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        header_preimage.extend_from_slice(&100u32.to_le_bytes()); // expiry_height
        let header_digest = hash(b"ZTxIdHeadersHash", &[&header_preimage]);
        let vp_deltas_digest = hash(b"ZTxIdVPDeltaHash", &[]);
        let effects_bundles_digest = hash(b"ZTxIdEffBnd_Hash", &[]);
        let auth_bundles_digest = hash(b"ZTxAuthBnd__Hash", &[]);

        let mut tx_personal = [0u8; 16];
        tx_personal[..12].copy_from_slice(b"ZcashTxHash_");
        tx_personal[12..].copy_from_slice(&UNKNOWN_BRANCH_ID.to_le_bytes());
        let expected_txid = hash(
            &tx_personal,
            &[
                header_digest.as_bytes(),
                vp_deltas_digest.as_bytes(),
                effects_bundles_digest.as_bytes(),
            ],
        );

        let mut auth_personal = [0u8; 16];
        auth_personal[..12].copy_from_slice(b"ZTxAuthHash_");
        auth_personal[12..].copy_from_slice(&UNKNOWN_BRANCH_ID.to_le_bytes());
        let expected_auth = hash(&auth_personal, &[auth_bundles_digest.as_bytes()]);

        assert_eq!(digests.header_digest, header_digest);
        assert_eq!(txid.as_ref(), expected_txid.as_bytes());
        assert_eq!(auth_commitment, expected_auth);

        // Consensus validation still requires a recognized, activating branch.
        assert_eq!(
            parsed.validate_v7(),
            Err(V7ValidationError::UnrecognizedBranchId {
                branch_id: UNKNOWN_BRANCH_ID,
            })
        );

        // Parsing and re-serialization are unaffected by the digests.
        let mut reserialized = Vec::new();
        parsed.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, wire);

        // An empty digest provider is complete for an empty transaction.
        assert!(parsed.v7_txid_digests(&provider).is_ok());
        assert!(!matches!(
            parsed.v7_txid(&provider),
            Err(V7DigestError::NotV7)
        ));
    }
}
