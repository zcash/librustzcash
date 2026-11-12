use alloc::vec;
use alloc::vec::Vec;

use zcash_encoding::CompactSize;
use zcash_protocol::consensus::{BlockHeight, BranchId};
#[cfg(zcash_unstable = "nu8")]
use zcash_protocol::constants::MAX_BLOCK_BYTES;

use crate::transaction::{
    TxVersion,
    bytes::*,
    components::transparent::{
        LegacyTransparentBundleBytes, LegacyTransparentInputBytes, TransparentOutPointBytes,
        TransparentOutputBytes, TransparentOutputValueBytes, TransparentScriptBytes,
    },
};
#[cfg(zcash_unstable = "nu8")]
use crate::transaction::{
    components::transparent::{
        TransparentAuthBytes, TransparentBundleBytes, TransparentEffectsBytes,
        TransparentInputAuthBytes, TransparentInputEffectingBytes, TransparentSighashInfoBytes,
    },
    zip248,
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
fn transaction_data_bytes_alias_is_usable() {
    let body = LegacyTransactionBodyBytes::from_parts(
        LegacyTransparentBundleBytes::default(),
        None,
        None,
        None,
    )
    .unwrap();
    let tx: TransactionDataBytes = TransactionBytes::from_parts(
        TxVersion::Sprout(1),
        None,
        0,
        BlockHeight::from(0u32),
        TransactionBodyBytes::Legacy(body),
    )
    .unwrap();
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    let decoded = TransactionDataBytes::read(&encoded[..]).unwrap();
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
        Some(BranchId::Nu5),
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
        Some(BranchId::Nu6_3),
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
        Some(BranchId::Nu5),
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
        Some(BranchId::Nu5),
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
        Some(BranchId::Nu5),
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
        Some(BranchId::Nu6_3),
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
        Some(BranchId::Nu6_3),
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
        Some(BranchId::Nu5),
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
            Some(BranchId::Nu6_3),
            0,
            BlockHeight::from(0u32),
            TransactionBodyBytes::V5(body),
        )
        .is_err()
    );
}

#[cfg(zcash_unstable = "nu8")]
mod v7 {
    use super::*;

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

    fn v7_coinbase() -> CoinbaseBundleBytes {
        CoinbaseBundleBytes::from_parts(BlockHeight::from(100u32), 1_000_000, 0, vec![0x51])
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
        .unwrap()
    }

    fn v7_sapling_effect_only() -> V7SaplingBundleBytes {
        V7SaplingBundleBytes::from_parts(
            vec![SaplingSpendBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32],
            )],
            vec![SaplingOutputBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )],
            None,
            vec![],
            vec![],
            vec![],
            None,
        )
        .unwrap()
    }

    fn v7_orchard() -> V7OrchardBundleBytes {
        V7OrchardBundleBytes::from_parts(
            vec![OrchardActionBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )],
            0,
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
        .unwrap()
    }

    fn v7_orchard_effect_only() -> V7OrchardBundleBytes {
        V7OrchardBundleBytes::from_parts(
            vec![OrchardActionBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )],
            0,
            None,
            vec![],
            vec![],
            None,
        )
        .unwrap()
    }

    fn v7_transparent_empty(auth_present: bool) -> TransparentBundleBytes {
        TransparentBundleBytes::from_parts(
            TransparentEffectsBytes::from_parts(vec![], vec![]),
            auth_present.then(|| TransparentAuthBytes::from_parts(vec![])),
        )
        .unwrap()
    }

    fn v7_sapling_empty(auth_present: bool) -> V7SaplingBundleBytes {
        V7SaplingBundleBytes::from_parts_with_auth_presence(
            vec![],
            vec![],
            None,
            vec![],
            vec![],
            vec![],
            None,
            auth_present,
        )
        .unwrap()
    }

    fn v7_orchard_empty(auth_present: bool) -> V7OrchardBundleBytes {
        V7OrchardBundleBytes::from_parts_with_auth_presence(
            vec![],
            0,
            None,
            vec![],
            vec![],
            None,
            auth_present,
        )
        .unwrap()
    }

    fn zec_delta(bundle_type: u64, value: i64) -> ValuePoolDeltaBytes {
        ValuePoolDeltaBytes::from_parts(
            BundleType::from_u64(bundle_type),
            BundleVariant::from_u64(0),
            AssetClass::Zec,
            value,
        )
        .unwrap()
    }

    fn v7_body(
        value_pool_deltas: Vec<ValuePoolDeltaBytes>,
        bundles: Vec<V7BundleBytes>,
    ) -> V7TransactionBodyBytes {
        V7TransactionBodyBytes::from_parts(value_pool_deltas, bundles).unwrap()
    }

    fn v7_tx(body: V7TransactionBodyBytes) -> TransactionBytes {
        TransactionBytes::from_parts(
            TxVersion::V7,
            Some(BranchId::Nu8),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body),
        )
        .unwrap()
    }

    fn round_trip(body: &V7TransactionBodyBytes) {
        let mut encoded = Vec::new();
        body.write(&mut encoded).unwrap();
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
            zip248::write_bundle_data_framing(&mut encoded, *bundle_type, *bundle_variant, data)
                .unwrap();
        }
        CompactSize::write(&mut encoded, auth_bundles.len()).unwrap();
        for (bundle_type, bundle_variant, data) in auth_bundles {
            zip248::write_bundle_data_framing(&mut encoded, *bundle_type, *bundle_variant, data)
                .unwrap();
        }
        encoded
    }

    fn payloads(bundle: &V7BundleBytes) -> (Vec<u8>, Option<Vec<u8>>) {
        let mut effects = Vec::new();
        bundle.write_effects(&mut effects).unwrap();
        let auth = if bundle.has_auth() {
            let mut auth = Vec::new();
            bundle.write_auth(&mut auth).unwrap();
            Some(auth)
        } else {
            None
        };
        (effects, auth)
    }

    #[test]
    fn v7_round_trip_known() {
        let body = v7_body(
            vec![
                zec_delta(0, -1000),
                zec_delta(1, 1_000_000),
                zec_delta(2, 1),
                zec_delta(3, 1),
                zec_delta(4, 1),
            ],
            vec![
                V7BundleBytes::Transparent(v7_transparent()),
                V7BundleBytes::Coinbase(v7_coinbase()),
                V7BundleBytes::Sapling(v7_sapling()),
                V7BundleBytes::Orchard(v7_orchard()),
                V7BundleBytes::Ironwood(v7_orchard()),
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
                V7BundleBytes::Transparent(v7_transparent_effect_only()),
                V7BundleBytes::Sapling(v7_sapling_effect_only()),
                V7BundleBytes::Orchard(v7_orchard_effect_only()),
                V7BundleBytes::Ironwood(v7_orchard_effect_only()),
            ],
        );
        round_trip(&body);
        for bundle in body.bundles() {
            assert!(!bundle.has_auth());
        }
    }

    #[test]
    fn v7_effect_only_bundles_omit_auth_map() {
        let body = v7_body(
            vec![],
            vec![
                V7BundleBytes::Transparent(v7_transparent_effect_only()),
                V7BundleBytes::Sapling(v7_sapling_effect_only()),
                V7BundleBytes::Orchard(v7_orchard_effect_only()),
                V7BundleBytes::Ironwood(v7_orchard_effect_only()),
            ],
        );
        let mut encoded = Vec::new();
        body.write(&mut encoded).unwrap();
        let decoded = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert!(decoded.bundles().iter().all(|bundle| !bundle.has_auth()));
    }

    #[test]
    fn v7_round_trip_unknown() {
        let unknown = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(99),
            BundleVariant::from_u64(0),
            vec![1, 2, 3],
            Some(vec![4, 5]),
        )
        .unwrap();
        let known_type_unknown_variant = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(2),
            BundleVariant::from_u64(1),
            vec![6, 7],
            None,
        )
        .unwrap();
        let known_opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(5),
            BundleVariant::from_u64(0),
            vec![0x00],
            None,
        )
        .unwrap();
        let body = v7_body(
            vec![zec_delta(5, -1000)],
            vec![
                V7BundleBytes::KnownTypeUnknownVariant(known_type_unknown_variant),
                V7BundleBytes::KnownOpaque(known_opaque),
                V7BundleBytes::Unknown(unknown),
            ],
        );
        round_trip(&body);
    }

    #[test]
    fn v7_known_type_unknown_variant_is_distinct_from_unknown_type() {
        let known_type_unknown_variant = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(2),
            BundleVariant::from_u64(1),
            vec![1],
            None,
        )
        .unwrap();
        let unknown = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(99),
            BundleVariant::from_u64(0),
            vec![1],
            None,
        )
        .unwrap();
        let body = v7_body(
            vec![],
            vec![
                V7BundleBytes::KnownTypeUnknownVariant(known_type_unknown_variant),
                V7BundleBytes::Unknown(unknown),
            ],
        );
        let mut encoded = Vec::new();
        body.write(&mut encoded).unwrap();
        let decoded = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert!(matches!(
            decoded.bundles()[0],
            V7BundleBytes::KnownTypeUnknownVariant(_)
        ));
        assert!(matches!(decoded.bundles()[1], V7BundleBytes::Unknown(_)));
    }

    #[test]
    fn v7_value_pool_deltas_round_trip() {
        let other = ValuePoolDeltaBytes::from_parts(
            BundleType::from_u64(2),
            BundleVariant::from_u64(0),
            AssetClass::Other([7u8; 64]),
            5,
        )
        .unwrap();
        let body = v7_body(vec![zec_delta(0, -1), zec_delta(2, 2), other], vec![]);
        round_trip(&body);
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

    #[test]
    fn v7_rejects_zero_value_pool_delta() {
        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, 1).unwrap();
        CompactSize::write(&mut encoded, 2).unwrap();
        CompactSize::write(&mut encoded, 0).unwrap();
        encoded.push(0);
        encoded.extend_from_slice(&0i64.to_le_bytes());
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_invalid_asset_class() {
        let mut encoded = Vec::new();
        CompactSize::write(&mut encoded, 1).unwrap();
        CompactSize::write(&mut encoded, 2).unwrap();
        CompactSize::write(&mut encoded, 0).unwrap();
        encoded.push(2);
        encoded.extend_from_slice(&1i64.to_le_bytes());
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_variant_mismatch() {
        let (effects, auth) = payloads(&V7BundleBytes::Sapling(v7_sapling()));
        let encoded = wire(
            &[zec_delta(2, 1)],
            &[(2, 0, effects)],
            &[(2, 1, auth.unwrap())],
        );
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_auth_without_effect() {
        let (_, auth) = payloads(&V7BundleBytes::Sapling(v7_sapling()));
        let encoded = wire(&[], &[], &[(2, 0, auth.unwrap())]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_trailing_effect_payload() {
        let (mut effects, auth) = payloads(&V7BundleBytes::Sapling(v7_sapling()));
        effects.push(0);
        let encoded = wire(&[], &[(2, 0, effects)], &[(2, 0, auth.unwrap())]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_trailing_auth_payload() {
        let (effects, auth) = payloads(&V7BundleBytes::Sapling(v7_sapling()));
        let mut auth = auth.unwrap();
        auth.push(0);
        let encoded = wire(&[], &[(2, 0, effects)], &[(2, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_transparent_auth_count_mismatch() {
        let (effects, auth) = payloads(&V7BundleBytes::Transparent(v7_transparent()));
        let mut auth = auth.unwrap();
        // Drop the single authorizing entry.
        auth.clear();
        let encoded = wire(&[], &[(0, 0, effects)], &[(0, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_sapling_auth_count_mismatch() {
        let (effects, auth) = payloads(&V7BundleBytes::Sapling(v7_sapling()));
        let mut auth = auth.unwrap();
        // Drop the binding signature.
        auth.truncate(auth.len() - 66);
        let encoded = wire(&[], &[(2, 0, effects)], &[(2, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    #[test]
    fn v7_rejects_orchard_auth_count_mismatch() {
        let (effects, auth) = payloads(&V7BundleBytes::Orchard(v7_orchard()));
        let mut auth = auth.unwrap();
        // Drop the binding signature.
        auth.truncate(auth.len() - 66);
        let encoded = wire(&[], &[(3, 0, effects)], &[(3, 0, auth)]);
        assert!(V7TransactionBodyBytes::read(&encoded[..]).is_err());
    }

    fn v7_orchard_with_proof_len(
        n_actions: usize,
        proof_len: usize,
    ) -> corez::io::Result<V7OrchardBundleBytes> {
        let action = || {
            OrchardActionBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )
        };
        let sig = || OrchardSignatureBytes::from_parts(SighashInfoBytes::v0(), [0u8; 64]);
        V7OrchardBundleBytes::from_parts(
            vec![action(); n_actions],
            0,
            Some([0u8; 32]),
            vec![0u8; proof_len],
            vec![sig(); n_actions],
            Some(sig()),
        )
    }

    #[test]
    fn v7_orchard_and_ironwood_proof_length_boundaries() {
        let wrap: [fn(V7OrchardBundleBytes) -> V7BundleBytes; 2] =
            [V7BundleBytes::Orchard, V7BundleBytes::Ironwood];
        for n_actions in [1usize, 2] {
            let expected = ORCHARD_PROOF_BASE_SIZE + ORCHARD_PROOF_PER_ACTION_SIZE * n_actions;
            for proof_len in [expected - 1, expected, expected + 1] {
                for wrap in wrap {
                    assert_eq!(
                        v7_orchard_with_proof_len(n_actions, proof_len)
                            .map(wrap)
                            .is_ok(),
                        proof_len == expected,
                        "n_actions = {n_actions}, proof_len = {proof_len}",
                    );
                }
            }
        }
    }

    #[test]
    fn v7_orchard_read_rejects_invalid_proof_length() {
        let mut effects = Vec::new();
        v7_orchard().write_effects(&mut effects).unwrap();

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
        assert!(V7OrchardBundleBytes::read(&effects, Some(&auth(expected - 1))).is_err());
        assert!(V7OrchardBundleBytes::read(&effects, Some(&auth(expected))).is_ok());
        assert!(V7OrchardBundleBytes::read(&effects, Some(&auth(expected + 1))).is_err());
    }

    #[test]
    fn v7_accepts_empty_transparent_effect_bundle() {
        let encoded = wire(&[], &[(0, 0, vec![0, 0])], &[]);
        let body = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        let transparent = body.transparent().unwrap();
        assert!(transparent.effects().is_empty());
        assert!(transparent.auth().is_none());

        let mut reserialized = Vec::new();
        body.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, encoded);
    }

    #[test]
    fn v7_accepts_empty_transparent_effect_bundle_with_present_empty_auth() {
        let encoded = wire(&[], &[(0, 0, vec![0, 0])], &[(0, 0, vec![])]);
        let body = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        let transparent = body.transparent().unwrap();
        assert!(transparent.effects().is_empty());
        assert_eq!(
            transparent.auth(),
            Some(&TransparentAuthBytes::from_parts(vec![]))
        );

        let mut reserialized = Vec::new();
        body.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, encoded);
    }

    #[test]
    fn v7_empty_effect_bundles_round_trip() {
        for auth_present in [false, true] {
            let body = v7_body(
                vec![],
                vec![
                    V7BundleBytes::Transparent(v7_transparent_empty(auth_present)),
                    V7BundleBytes::Sapling(v7_sapling_empty(auth_present)),
                    V7BundleBytes::Orchard(v7_orchard_empty(auth_present)),
                    V7BundleBytes::Ironwood(v7_orchard_empty(auth_present)),
                ],
            );
            round_trip(&body);
            for bundle in body.bundles() {
                assert_eq!(bundle.has_auth(), auth_present);
            }
        }
    }

    #[test]
    fn v7_empty_effect_bundle_payloads_are_canonical() {
        let (transparent_effects, transparent_auth) =
            payloads(&V7BundleBytes::Transparent(v7_transparent_empty(false)));
        assert_eq!(transparent_effects, vec![0, 0]);
        assert!(transparent_auth.is_none());

        let (sapling_effects, sapling_auth) =
            payloads(&V7BundleBytes::Sapling(v7_sapling_empty(false)));
        assert_eq!(sapling_effects, vec![0, 0]);
        assert!(sapling_auth.is_none());

        let (orchard_effects, orchard_auth) =
            payloads(&V7BundleBytes::Orchard(v7_orchard_empty(false)));
        assert_eq!(orchard_effects, vec![0]);
        assert!(orchard_auth.is_none());

        let (_, transparent_auth) =
            payloads(&V7BundleBytes::Transparent(v7_transparent_empty(true)));
        assert_eq!(transparent_auth, Some(vec![]));

        let (_, sapling_auth) = payloads(&V7BundleBytes::Sapling(v7_sapling_empty(true)));
        assert_eq!(sapling_auth, Some(vec![]));

        let (_, orchard_auth) = payloads(&V7BundleBytes::Orchard(v7_orchard_empty(true)));
        assert_eq!(orchard_auth, Some(vec![]));
    }

    fn empty_bundles(auth_present: bool) -> Vec<V7BundleBytes> {
        vec![
            V7BundleBytes::Transparent(v7_transparent_empty(auth_present)),
            V7BundleBytes::Sapling(v7_sapling_empty(auth_present)),
            V7BundleBytes::Orchard(v7_orchard_empty(auth_present)),
            V7BundleBytes::Ironwood(v7_orchard_empty(auth_present)),
        ]
    }

    #[test]
    fn v7_empty_bundle_presence_changes_effects_digest() {
        let empty = zip248::SuppliedBundleDigests::new();
        let absent = v7_tx(v7_body(vec![], vec![]));
        let present = v7_tx(v7_body(vec![], empty_bundles(false)));
        assert_ne!(
            absent.v7_txid(&empty).unwrap(),
            present.v7_txid(&empty).unwrap()
        );
    }

    #[test]
    fn v7_present_empty_auth_changes_auth_commitment() {
        let empty = zip248::SuppliedBundleDigests::new();
        let absent = v7_tx(v7_body(vec![], empty_bundles(false)));
        let present = v7_tx(v7_body(vec![], empty_bundles(true)));
        assert_ne!(
            absent.v7_auth_commitment(&empty).unwrap(),
            present.v7_auth_commitment(&empty).unwrap()
        );
    }

    /// The empty-bundle digests are the personalized hashes of the empty byte
    /// string specified by ZIP 248, not the digest of an absent bundle.
    #[test]
    fn v7_empty_bundle_digests_match_zip248() {
        use crate::transaction::txid::{
            hash_v7_ironwood_auth_bytes, hash_v7_ironwood_effects_bytes,
            hash_v7_orchard_auth_bytes, hash_v7_orchard_effects_bytes, hash_v7_sapling_auth_bytes,
            hash_v7_sapling_effects_bytes, hash_v7_transparent_effects_bytes,
        };

        fn empty_hash(personal: &[u8; 16]) -> blake2b_simd::Hash {
            blake2b_simd::Params::new()
                .hash_length(32)
                .personal(personal)
                .to_state()
                .finalize()
        }

        // An empty transparent bundle digests the empty byte string, matching
        // the ZIP 244 rule for a transaction with no transparent inputs or
        // outputs.
        let transparent = v7_transparent_empty(false);
        assert_eq!(
            hash_v7_transparent_effects_bytes(&transparent),
            empty_hash(b"ZTxIdTranspaHash")
        );

        let sapling = v7_sapling_empty(false);
        assert_eq!(
            hash_v7_sapling_effects_bytes(&sapling).unwrap(),
            empty_hash(b"ZTxIdSaplingH_v7")
        );
        assert_eq!(
            hash_v7_sapling_auth_bytes(&sapling),
            empty_hash(b"ZTxAuthSapliH_v7")
        );

        let orchard = v7_orchard_empty(false);
        assert_eq!(
            hash_v7_orchard_effects_bytes(&orchard),
            empty_hash(b"ZTxIdOrchardH_v7")
        );
        assert_eq!(
            hash_v7_orchard_auth_bytes(&orchard),
            empty_hash(b"ZTxAuthOrchaH_v7")
        );
        assert_eq!(
            hash_v7_ironwood_effects_bytes(&orchard),
            empty_hash(b"ZTxIdIronwd_Hash")
        );
        assert_eq!(
            hash_v7_ironwood_auth_bytes(&orchard),
            empty_hash(b"ZTxAuthIrnwdHash")
        );
    }

    #[test]
    fn v7_rejects_misordered_bundles() {
        let (effects, auth) = payloads(&V7BundleBytes::Sapling(v7_sapling()));
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
            body.bundles()[0],
            V7BundleBytes::CoinbaseWithAuth(..)
        ));
        assert_eq!(body.bundles()[0].coinbase_auth(), Some(auth.as_slice()));
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
                key: body.bundles()[0].digest_key()
            })
        );
    }

    #[test]
    fn v7_value_only_bundle_in_effect_map_is_opaque() {
        let encoded = wire(&[zec_delta(5, -1000)], &[(5, 0, vec![0x00])], &[]);
        let body = V7TransactionBodyBytes::read(&encoded[..]).unwrap();
        assert!(matches!(body.bundles()[0], V7BundleBytes::KnownOpaque(_)));
    }

    #[test]
    fn v7_accepts_empty_transparent_bundle() {
        let transparent = v7_transparent_empty(false);
        let body = V7TransactionBodyBytes::from_parts(
            vec![],
            vec![V7BundleBytes::Transparent(transparent)],
        )
        .unwrap();
        round_trip(&body);
    }

    #[test]
    fn v7_rejects_known_opaque_for_parsed_type() {
        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(0),
            BundleVariant::from_u64(0),
            vec![0, 0],
            None,
        )
        .unwrap();
        assert!(
            V7TransactionBodyBytes::from_parts(vec![], vec![V7BundleBytes::KnownOpaque(opaque)])
                .is_err()
        );
    }

    #[test]
    fn v7_rejects_known_type_unknown_variant_with_known_variant() {
        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(2),
            BundleVariant::from_u64(0),
            vec![1],
            None,
        )
        .unwrap();
        assert!(
            V7TransactionBodyBytes::from_parts(
                vec![],
                vec![V7BundleBytes::KnownTypeUnknownVariant(opaque)]
            )
            .is_err()
        );
    }

    #[test]
    fn v7_rejects_unknown_with_known_type() {
        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(2),
            BundleVariant::from_u64(0),
            vec![1],
            None,
        )
        .unwrap();
        assert!(
            V7TransactionBodyBytes::from_parts(vec![], vec![V7BundleBytes::Unknown(opaque)])
                .is_err()
        );
    }

    #[test]
    fn v7_coinbase_data_length_boundary() {
        let max = zip248::MAX_COINBASE_DATA_LEN;
        let coinbase = CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![0x51; max],
        )
        .unwrap();
        let mut encoded = Vec::new();
        coinbase.write(&mut encoded).unwrap();
        let decoded = CoinbaseBundleBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded, coinbase);

        // The byte layer retains an over-long payload; the typed conversion
        // enforces the ZIP 248 limit.
        let over_long = CoinbaseBundleBytes::from_parts(
            BlockHeight::from(100u32),
            1_000_000,
            0,
            vec![0x51; max + 1],
        )
        .unwrap();
        assert!(over_long.to_coinbase_bundle().is_err());
    }

    #[test]
    fn v7_value_pool_delta_retains_raw_out_of_range_values() {
        let max_balance = zcash_protocol::value::MAX_MONEY as i64;
        for value in [i64::MIN, -max_balance - 1, max_balance + 1, i64::MAX] {
            let delta = ValuePoolDeltaBytes::from_parts(
                BundleType::from_u64(99),
                BundleVariant::from_u64(0),
                AssetClass::Zec,
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
        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(99),
            BundleVariant::from_u64(0),
            vec![0u8; MAX_BLOCK_BYTES],
            None,
        )
        .unwrap();
        let body = v7_body(vec![], vec![V7BundleBytes::Unknown(opaque)]);
        round_trip(&body);

        assert!(
            OpaqueBundleBytes::from_parts(
                BundleType::from_u64(99),
                BundleVariant::from_u64(0),
                vec![0u8; MAX_BLOCK_BYTES + 1],
                None,
            )
            .is_err()
        );

        assert!(
            OpaqueBundleBytes::from_parts(
                BundleType::from_u64(99),
                BundleVariant::from_u64(0),
                vec![],
                Some(vec![0u8; MAX_BLOCK_BYTES + 1]),
            )
            .is_err()
        );
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
        let bundle = TransparentBundleBytes::from_parts(effects, Some(auth)).unwrap();
        assert!(
            V7TransactionBodyBytes::from_parts(vec![], vec![V7BundleBytes::Transparent(bundle)])
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
        let bundle = TransparentBundleBytes::from_parts(effects, Some(auth)).unwrap();
        let body = v7_body(vec![], vec![V7BundleBytes::Transparent(bundle)]);
        round_trip(&body);
    }

    #[test]
    fn v7_rejects_oversized_sapling_auth_payload() {
        let binding_sig = SaplingSignatureBytes::from_parts(
            SighashInfoBytes::from_bytes(vec![0u8; MAX_BLOCK_BYTES]),
            [0u8; 64],
        );
        let bundle = V7SaplingBundleBytes::from_parts(
            vec![SaplingSpendBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32],
            )],
            vec![],
            Some([0u8; 32]),
            vec![[0u8; 192]],
            vec![SaplingSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )],
            vec![],
            Some(binding_sig),
        )
        .unwrap();
        assert!(
            V7TransactionBodyBytes::from_parts(vec![], vec![V7BundleBytes::Sapling(bundle)])
                .is_err()
        );
    }

    #[test]
    fn v7_rejects_oversized_orchard_auth_payload() {
        let binding_sig = OrchardSignatureBytes::from_parts(
            SighashInfoBytes::from_bytes(vec![0u8; MAX_BLOCK_BYTES]),
            [0u8; 64],
        );
        let bundle = V7OrchardBundleBytes::from_parts(
            vec![OrchardActionBytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
            )],
            0,
            Some([0u8; 32]),
            orchard_proof(1),
            vec![OrchardSignatureBytes::from_parts(
                SighashInfoBytes::v0(),
                [0u8; 64],
            )],
            Some(binding_sig),
        )
        .unwrap();
        assert!(
            V7TransactionBodyBytes::from_parts(vec![], vec![V7BundleBytes::Orchard(bundle)])
                .is_err()
        );
    }

    #[test]
    fn v7_write_bundle_data_map_rejects_oversized_payload() {
        let mut encoded = Vec::new();
        let result = zip248::write_bundle_data_map(
            &mut encoded,
            vec![(99, 0, vec![0u8; MAX_BLOCK_BYTES + 1])],
        );
        assert!(result.is_err());
        assert!(encoded.is_empty());
    }

    #[test]
    fn v7_full_transaction_round_trip() {
        let body = v7_body(
            vec![zec_delta(0, -1000), zec_delta(2, 1)],
            vec![
                V7BundleBytes::Transparent(v7_transparent()),
                V7BundleBytes::Sapling(v7_sapling()),
            ],
        );
        let tx = v7_tx(body);
        let mut encoded = Vec::new();
        tx.write(&mut encoded).unwrap();
        let decoded = TransactionBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn v7_truncation_is_rejected() {
        let body = v7_body(
            vec![zec_delta(0, -1000)],
            vec![V7BundleBytes::Transparent(v7_transparent())],
        );
        let mut encoded = Vec::new();
        body.write(&mut encoded).unwrap();
        for len in 0..encoded.len() {
            assert!(
                V7TransactionBodyBytes::read(&encoded[..len]).is_err(),
                "truncation at {len} bytes was accepted"
            );
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
            "7d0e9f1bc9f2a1d34760306861a89a2886059ab3e5b31967b4c1d006338f42eb",
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
            "0c4f2e403c749ce18dcb26051e713ef6be72bc3ceda790029700e48c584fbda6",
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
        const WIRE: &str = "0700008068636174fbffffff0000000064000000\
                            01630000f401000000000000\
                            01630003010203\
                            016300020405";
        const TXID: &str = "8f2f99e69230d175327fc966d551c4ebbaa34dc84cc194a46dee93577088c5e9";
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
        assert!(delta.asset_class().is_zec());
        assert_eq!(delta.value(), 500);

        assert_eq!(body.bundles().len(), 1);
        let bundle = &body.bundles()[0];
        assert!(matches!(bundle, V7BundleBytes::Unknown(_)));
        let opaque = bundle.as_opaque().unwrap();
        assert_eq!(opaque.bundle_type().to_u64(), 99);
        assert_eq!(opaque.bundle_variant().to_u64(), 0);
        assert_eq!(opaque.effects(), &[1, 2, 3]);
        assert_eq!(opaque.auth(), Some(&[4, 5][..]));

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
        use ff::PrimeField;
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        use super::orchard_proof;
        use crate::transaction::{
            TxVersion,
            bytes::{
                AssetClass, BundleType, BundleVariant, OrchardActionBytes, OrchardSignatureBytes,
                SaplingOutputBytes, SaplingSignatureBytes, SaplingSpendBytes, SighashInfoBytes,
                TransactionBodyBytes, TransactionBytes, V7BundleBytes, V7OrchardBundleBytes,
                V7SaplingBundleBytes, V7TransactionBodyBytes, ValuePoolDeltaBytes,
            },
        };

        fn zec_delta(bundle_type: u64, value: i64) -> ValuePoolDeltaBytes {
            ValuePoolDeltaBytes::from_parts(
                BundleType::from_u64(bundle_type),
                BundleVariant::from_u64(0),
                AssetClass::Zec,
                value,
            )
            .unwrap()
        }

        fn v7_sapling_bytes(
            bundle: &sapling::bundle::Bundle<sapling::bundle::Authorized, ZatBalance>,
        ) -> V7SaplingBundleBytes {
            let spends = bundle.shielded_spends();
            let outputs = bundle.shielded_outputs();
            V7SaplingBundleBytes::from_parts(
                spends
                    .iter()
                    .map(|spend| {
                        SaplingSpendBytes::from_parts(
                            spend.cv().to_bytes(),
                            spend.nullifier().0,
                            <[u8; 32]>::from(*spend.rk()),
                        )
                    })
                    .collect(),
                outputs
                    .iter()
                    .map(|output| {
                        SaplingOutputBytes::from_parts(
                            output.cv().to_bytes(),
                            output.cmu().to_bytes(),
                            output.ephemeral_key().0,
                            *output.enc_ciphertext(),
                            *output.out_ciphertext(),
                        )
                    })
                    .collect(),
                spends.first().map(|spend| spend.anchor().to_repr()),
                spends.iter().map(|spend| *spend.zkproof()).collect(),
                spends
                    .iter()
                    .map(|spend| {
                        SaplingSignatureBytes::from_parts(
                            SighashInfoBytes::v0(),
                            <[u8; 64]>::from(*spend.spend_auth_sig()),
                        )
                    })
                    .collect(),
                outputs.iter().map(|output| *output.zkproof()).collect(),
                Some(SaplingSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    <[u8; 64]>::from(bundle.authorization().binding_sig),
                )),
            )
            .unwrap()
        }

        fn dummy_v7_orchard() -> V7OrchardBundleBytes {
            V7OrchardBundleBytes::from_parts(
                vec![OrchardActionBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
                )],
                0,
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
            .unwrap()
        }

        let mut runner = TestRunner::default();
        let sapling = sapling::bundle::testing::arb_bundle(ZatBalance::zero())
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
                V7BundleBytes::Sapling(v7_sapling_bytes(&sapling)),
                V7BundleBytes::Orchard(dummy_v7_orchard()),
            ],
        )
        .unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(BranchId::Nu8),
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
            .sapling()
            .unwrap()
            .to_authorized(sapling_value)
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
                AssetClass, BundleType, BundleVariant, OrchardActionBytes, OrchardSignatureBytes,
                SaplingOutputBytes, SaplingSignatureBytes, SaplingSpendBytes, SighashInfoBytes,
                TransactionBodyBytes, TransactionBytes, V7BundleBytes, V7OrchardBundleBytes,
                V7SaplingBundleBytes, V7TransactionBodyBytes, ValuePoolDeltaBytes,
            },
        };

        fn zec_delta(bundle_type: u64, value: i64) -> ValuePoolDeltaBytes {
            ValuePoolDeltaBytes::from_parts(
                BundleType::from_u64(bundle_type),
                BundleVariant::from_u64(0),
                AssetClass::Zec,
                value,
            )
            .unwrap()
        }

        fn v7_orchard_bytes(
            bundle: &orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
        ) -> V7OrchardBundleBytes {
            V7OrchardBundleBytes::from_parts(
                bundle
                    .actions()
                    .iter()
                    .map(|action| {
                        OrchardActionBytes::from_parts(
                            action.cv_net().to_bytes(),
                            action.nullifier().to_bytes(),
                            <[u8; 32]>::from(action.rk()),
                            action.cmx().to_bytes(),
                            action.encrypted_note().epk_bytes,
                            action
                                .encrypted_note()
                                .enc_ciphertext
                                .as_ref()
                                .try_into()
                                .expect("Orchard enc_ciphertext is 580 bytes"),
                            action.encrypted_note().out_ciphertext,
                        )
                    })
                    .collect(),
                bundle.flag_byte(),
                Some(bundle.anchor().to_bytes()),
                bundle.authorization().proof().as_ref().to_vec(),
                bundle
                    .actions()
                    .iter()
                    .map(|action| {
                        OrchardSignatureBytes::from_parts(
                            SighashInfoBytes::v0(),
                            <[u8; 64]>::from(action.authorization()),
                        )
                    })
                    .collect(),
                Some(OrchardSignatureBytes::from_parts(
                    SighashInfoBytes::v0(),
                    <[u8; 64]>::from(bundle.authorization().binding_signature()),
                )),
            )
            .unwrap()
        }

        fn dummy_v7_sapling() -> V7SaplingBundleBytes {
            V7SaplingBundleBytes::from_parts(
                vec![SaplingSpendBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32],
                )],
                vec![SaplingOutputBytes::from_parts(
                    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 580], [0u8; 80],
                )],
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
            .unwrap()
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
        let orchard_value = *orchard.value_balance();

        let mut deltas = vec![zec_delta(2, 1)];
        if orchard_value != ZatBalance::zero() {
            deltas.push(zec_delta(3, i64::from(orchard_value)));
        }
        deltas.sort_by_key(|delta| delta.bundle_type().to_u64());

        let body = V7TransactionBodyBytes::from_parts(
            deltas,
            vec![
                V7BundleBytes::Sapling(dummy_v7_sapling()),
                V7BundleBytes::Orchard(v7_orchard_bytes(&orchard)),
            ],
        )
        .unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(BranchId::Nu8),
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
            .orchard()
            .unwrap()
            .to_authorized(orchard_value, Some(orchard.bundle_version()))
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
            Some(BranchId::Nu5),
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
            Some(BranchId::Nu6_3),
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

    #[cfg(all(feature = "sapling", feature = "orchard"))]
    #[test]
    fn unknown_branch_id_fails_typed_conversion() {
        use alloc::string::ToString;

        let wire = with_unknown_branch_id(&v5_empty());
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
    fn unknown_branch_id_fails_v7_digests_and_validation() {
        use crate::transaction::{
            V7ValidationError,
            bytes::V7TransactionBodyBytes,
            zip248::{self, V7DigestError},
        };

        let body = V7TransactionBodyBytes::from_parts(vec![], vec![]).unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(BranchId::Nu8),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();
        let wire = with_unknown_branch_id(&tx);
        let parsed = TransactionBytes::read(&wire[..]).unwrap();
        assert_eq!(parsed.raw_consensus_branch_id(), Some(UNKNOWN_BRANCH_ID));

        let expected = V7DigestError::UnrecognizedBranchId {
            branch_id: UNKNOWN_BRANCH_ID,
        };
        let provider = zip248::SuppliedBundleDigests::new();
        assert_eq!(parsed.v7_txid(&provider), Err(expected));
        assert_eq!(parsed.v7_auth_commitment(&provider), Err(expected));
        assert_eq!(parsed.v7_txid_digests(&provider).err(), Some(expected));
        assert_eq!(
            parsed.validate_v7(),
            Err(V7ValidationError::UnrecognizedBranchId {
                branch_id: UNKNOWN_BRANCH_ID,
            })
        );

        let mut reserialized = Vec::new();
        parsed.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, wire);
    }
}
