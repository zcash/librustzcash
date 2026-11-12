use proptest::prelude::*;

#[cfg(test)]
use {
    crate::transaction::{
        Authorization, Authorized, Transaction, TransactionData, TransactionDigest, TxIn,
        TxVersion, Zip244Digests,
        sighash::{PrecomputedSighashData, SignableInput},
        sighash_v4::{v4_signature_hash, zip143_digests},
        sighash_v5::v5_signature_hash,
        sighash_v6::v6_signature_hash,
        testing::arb_tx,
        transparent,
        txid::{BlockTxCommitmentDigester, TxIdDigester, hash_sapling_spends},
    },
    ::transparent::{
        address::Script,
        sighash::{SighashType, TransparentAuthorizingContext},
    },
    alloc::vec::Vec,
    blake2b_simd::{Hash as Blake2bHash, Params},
    core::{cell::Cell, ops::Deref},
    ff::PrimeField,
    zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        value::{ZatBalance, Zatoshis},
    },
    zcash_script::script,
};

#[cfg(all(test, zcash_unstable = "nu8"))]
use zcash_protocol::constants::{V7_TX_VERSION, V7_VERSION_GROUP_ID};

#[cfg(all(test, zcash_unstable = "nu8"))]
use super::sighash_v7::v7_signature_hash;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod data;

/// An empty NU7 v6 codec fixture, not a spendable transaction. The header follows ZIP 229;
/// the six zero counts encode transparent inputs/outputs, Sapling spends/outputs,
/// Orchard actions, and Ironwood actions. Expected hashes were independently calculated
/// with Python hashlib.blake2b (32-byte output), using the ZIP 244/229 digest tree:
/// header || empty transparent || empty Sapling || empty v6 Orchard || empty Ironwood.
/// With no transparent bundle, the shielded signature digest equals this transaction digest.
/// Keep these expectations identical in builds with and without the ZIP 233 opt-in.
#[test]
fn nu7_v6_encoding_and_digests_are_feature_independent() {
    const ENCODED: &str = "0600008098b684d8d90a19770000000001000000000000000000";
    const HEADER_DIGEST: &str = "199b8446da5a9247711a94527997d7e87c31dfe5e8efb4b34d020a2aee8ee1c5";
    const TX_DIGEST: &str = "78296c68a370c2e1f058d997c81c7b011c4562c52fc5ca2994ad59cd179fbe9e";
    /// The smallest nonzero expiry height, used only to distinguish header fields.
    const EXPIRY_HEIGHT: u32 = 1;
    /// A suffix owned by an enclosing stream, which transaction parsing must not consume.
    const TRAILER: &[u8] = b"next-record";

    let encoded = hex::decode(ENCODED).unwrap();
    let expected_digest = hex::decode(TX_DIGEST).unwrap();
    let data = TransactionData::<TestUnauthorized>::from_parts_v6(
        BranchId::Nu7,
        0,
        EXPIRY_HEIGHT.into(),
        None,
        None,
        None,
        None,
    );
    let digests = data.digest(TxIdDigester);
    assert_eq!(
        digests.header_digest.as_bytes(),
        hex::decode(HEADER_DIGEST).unwrap()
    );
    assert_eq!(
        v6_signature_hash(&data, &SignableInput::Shielded, &digests, None).as_bytes(),
        expected_digest,
    );

    let tx = TransactionData::from_parts_v6(
        BranchId::Nu7,
        0,
        EXPIRY_HEIGHT.into(),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    assert_eq!(tx_bytes(&tx), encoded);
    assert_eq!(tx.txid().as_ref().as_slice(), expected_digest);

    let mut stream = encoded.clone();
    stream.extend_from_slice(TRAILER);
    let mut reader = stream.as_slice();
    let parsed = Transaction::read(&mut reader, BranchId::Nu7).unwrap();
    assert_eq!(reader, TRAILER);
    assert_eq!(parsed.txid(), tx.txid());
    assert_eq!(tx_bytes(&parsed), encoded);
    for end in 0..encoded.len() {
        assert!(Transaction::read(&encoded[..end], BranchId::Nu7).is_err());
    }

    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    {
        let explicit_zero = TransactionData::from_parts_v6_with_zip233(
            BranchId::Nu7,
            0,
            EXPIRY_HEIGHT.into(),
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        assert_eq!(tx_bytes(&explicit_zero), encoded);
        assert_eq!(explicit_zero.txid(), tx.txid());
        assert!(!TxVersion::V6.has_zip233(BranchId::Nu7));
    }
}

#[test]
fn nu7_v5_encoding_and_digests_are_feature_independent() {
    // Empty codec fixture calculated independently with Python hashlib.blake2b,
    // using the ZIP 244 header and empty transparent, Sapling, and Orchard digests.
    const ENCODED: &str = "050000800a27a726d90a197700000000010000000000000000";
    const DIGEST: &str = "328d975581fbf002206ef6f0b69fe57fb47f40ec31c59ac62c3565d4e259e128";
    /// The smallest nonzero expiry height, matching the v6 fixture.
    const EXPIRY_HEIGHT: u32 = 1;
    let data = TransactionData::<TestUnauthorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu7,
        0,
        EXPIRY_HEIGHT.into(),
        None,
        None,
        None,
        None,
    );
    let expected = hex::decode(DIGEST).unwrap();
    assert_eq!(v5_shielded_sighash(&data).as_bytes(), expected);
    let tx = TransactionData::from_parts(
        TxVersion::V5,
        BranchId::Nu7,
        0,
        EXPIRY_HEIGHT.into(),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    let encoded = hex::decode(ENCODED).unwrap();
    assert_eq!(tx_bytes(&tx), encoded);
    assert_eq!(tx.txid().as_ref().as_slice(), expected);
    let mut reader = encoded.as_slice();
    assert_eq!(
        Transaction::read(&mut reader, BranchId::Nu7)
            .unwrap()
            .txid(),
        tx.txid()
    );
    assert!(reader.is_empty());
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    {
        let zero = TransactionData::from_parts_with_zip233(
            TxVersion::V5,
            BranchId::Nu7,
            0,
            EXPIRY_HEIGHT.into(),
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        assert_eq!(tx_bytes(&zero), encoded);
        assert_eq!(zero.txid(), tx.txid());
    }
}

#[test]
#[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
fn freeze_rejects_nonzero_zip233_in_v5_and_v6() {
    /// The smallest unsupported nonzero amount exercises the rejection boundary.
    const NONZERO_AMOUNT: Zatoshis = Zatoshis::const_from_u64(1);
    for branch in [BranchId::Nu6_3, BranchId::Nu7] {
        for version in [TxVersion::V5, TxVersion::V6] {
            for amount in [
                NONZERO_AMOUNT,
                Zatoshis::const_from_u64(zcash_protocol::value::MAX_MONEY),
            ] {
                let data =
                    TransactionData::<crate::transaction::Authorized>::from_parts_with_zip233(
                        version,
                        branch,
                        0,
                        0u32.into(),
                        amount,
                        None,
                        None,
                        None,
                        None,
                    );
                assert_eq!(
                    data.freeze().unwrap_err().kind(),
                    corez::io::ErrorKind::InvalidInput
                );
            }
        }
    }
}
#[test]
fn tx_read_write() {
    let data = &self::data::tx_read_write::TX_READ_WRITE;
    let tx = Transaction::read(&data[..], BranchId::Canopy).unwrap();
    assert_eq!(
        format!("{}", tx.txid()),
        "64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639"
    );

    let mut encoded = Vec::with_capacity(data.len());
    tx.write(&mut encoded).unwrap();
    assert_eq!(&data[..], &encoded[..]);
}

/// `Transaction::read` parses the legacy versions through the byte layer, so
/// the v1-v3 paths must still round-trip and reproduce their SHA-256d txid.
#[test]
fn legacy_v1_to_v3_read_roundtrip() {
    use ::transparent::bundle::{Authorized, Bundle, TxOut};

    let transparent = Bundle {
        vin: vec![],
        vout: vec![TxOut::new(
            Zatoshis::from_u64(1000).unwrap(),
            Script::default(),
        )],
        authorization: Authorized,
    };

    for (version, branch_id) in [
        (TxVersion::Sprout(1), BranchId::Sprout),
        (TxVersion::Sprout(2), BranchId::Sprout),
        (TxVersion::V3, BranchId::Overwinter),
    ] {
        let tx = TransactionData::from_parts(
            version,
            branch_id,
            0,
            BlockHeight::from(0u32),
            Some(transparent.clone()),
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();

        let mut encoded = Vec::new();
        tx.write(&mut encoded).unwrap();
        let parsed = Transaction::read(&encoded[..], branch_id).unwrap();
        assert_eq!(parsed.version(), version);
        assert_eq!(parsed.txid(), tx.txid());
        assert_eq!(parsed.transparent_bundle(), tx.transparent_bundle());

        let mut reserialized = Vec::new();
        parsed.write(&mut reserialized).unwrap();
        assert_eq!(reserialized, encoded);
    }
}

#[test]
fn suggested_version_for_v5_branches_is_not_v6() {
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::Nu5),
        TxVersion::V5
    );
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::Nu6),
        TxVersion::V5
    );
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::Nu6_1),
        TxVersion::V5
    );
}

/// Cross-checks the v7 digest tree against values computed independently of this
/// implementation, directly from the [ZIP 248] text with Python's
/// `hashlib.blake2b` (see `.plans/zip248_vectors.py`):
///
/// ```text
/// header_digest            = BLAKE2b-256("ZTxIdHeadersHash",
///                              version || nVersionGroupId || nConsensusBranchId
///                                      || lock_time || nExpiryHeight)   [T.1]
/// value_pool_deltas_digest = BLAKE2b-256("ZTxIdVPDeltaHash", [])        [T.2]
/// effects_bundles_digest   = BLAKE2b-256("ZTxIdEffBnd_Hash", [])        [T.3]
/// txid                     = BLAKE2b-256("ZcashTxHash_" || branch_id,
///                              header_digest || value_pool_deltas_digest
///                                            || effects_bundles_digest)
/// auth_bundles_digest      = BLAKE2b-256("ZTxAuthBnd__Hash", [])        [A.1]
/// auth_digest              = BLAKE2b-256("ZTxAuthHash_" || branch_id,
///                              auth_bundles_digest)
/// ```
///
/// These pin the personalizations, the field encodings and the shape of the
/// tree, none of which the roundtrip and consistency tests can observe.
///
/// [ZIP 248]: https://zips.z.cash/zip-0248
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_empty_transaction_matches_zip248_digests() {
    let tx =
        TransactionData::from_parts_v7(BranchId::Nu8, 0, 100u32.into(), None, None, None, None)
            .freeze()
            .unwrap();

    assert_eq!(
        hex::encode(tx.txid().as_ref()),
        "7d0e9f1bc9f2a1d34760306861a89a2886059ab3e5b31967b4c1d006338f42eb",
    );
    assert_eq!(
        hex::encode(tx.auth_commitment().as_bytes()),
        "d3a128d379cd32a6ec49acb8e5da337ed38e80c068fa0e33e4baf2786867241a",
    );
}

/// As [`v7_empty_transaction_matches_zip248_digests`], for a transaction whose
/// only value pool delta is the fee. This pins [ZIP 248]'s per-entry encoding
/// of `mValuePoolDeltas` — `compactSize(bundleType) ||
/// compactSize(bundleVariant) || assetClass || value` — which is specific to
/// this format and has no ZIP 244 counterpart.
///
/// [ZIP 248]: https://zips.z.cash/zip-0248
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_fee_delta_matches_zip248_digests() {
    use super::zip248;

    let mut deltas = zip248::ValuePoolDeltas::empty();
    deltas.set_fee(Zatoshis::const_from_u64(10_000)).unwrap();
    let tx = TransactionData::<super::Authorized>::from_parts_with_value_pool_deltas(
        TxVersion::V7,
        BranchId::Nu8,
        0,
        100u32.into(),
        deltas,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();

    assert_eq!(
        hex::encode(tx.txid().as_ref()),
        "0c4f2e403c749ce18dcb26051e713ef6be72bc3ceda790029700e48c584fbda6",
    );
}

#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_is_enabled_by_nu8_and_roundtrips() {
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::Nu8),
        TxVersion::V7
    );
    assert!(TxVersion::V7.valid_in_branch(BranchId::Nu8));
    assert!(!TxVersion::V7.valid_in_branch(BranchId::Nu6_3));

    let tx = TransactionData::from_parts_v7(BranchId::Nu8, 0, 0u32.into(), None, None, None, None)
        .freeze()
        .unwrap();

    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    assert_eq!(&encoded[..4], &(V7_TX_VERSION | (1 << 31)).to_le_bytes());
    assert_eq!(&encoded[4..8], &V7_VERSION_GROUP_ID.to_le_bytes());
    assert_eq!(&encoded[8..12], &u32::from(BranchId::Nu8).to_le_bytes());

    let decoded = Transaction::read(&encoded[..], BranchId::Sprout).unwrap();
    assert_eq!(decoded.version(), TxVersion::V7);
    assert_eq!(decoded.consensus_branch_id(), BranchId::Nu8);
    let mut reencoded = Vec::new();
    decoded.write(&mut reencoded).unwrap();
    assert_eq!(reencoded, encoded);
}

#[test]
fn v4_transactions_remain_valid_in_nu6_3() {
    assert!(TxVersion::V4.valid_in_branch(BranchId::Nu6_3));
}

#[test]
fn v5_auth_commitment_in_nu6_3_does_not_include_ironwood_digest() {
    fn empty_hash(personal: &[u8; 16]) -> Blake2bHash {
        Params::new().hash_length(32).personal(personal).hash(&[])
    }

    let mut personal = [0; 16];
    personal[..12].copy_from_slice(b"ZTxAuthHash_");
    personal[12..].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());

    let mut expected = Params::new().hash_length(32).personal(&personal).to_state();
    expected.update(empty_hash(b"ZTxAuthTransHash").as_bytes());
    expected.update(empty_hash(b"ZTxAuthSapliHash").as_bytes());
    expected.update(empty_hash(b"ZTxAuthOrchaHash").as_bytes());

    let tx = TransactionData::from_parts(
        TxVersion::V5,
        BranchId::Nu6_3,
        0,
        0u32.into(),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();

    assert_eq!(tx.auth_commitment(), expected.finalize());
}

#[test]
fn v6_empty_auth_commitment_uses_v6_shielded_personalizations() {
    fn empty_hash(personal: &[u8; 16]) -> Blake2bHash {
        Params::new().hash_length(32).personal(personal).hash(&[])
    }

    let mut personal = [0; 16];
    personal[..12].copy_from_slice(b"ZTxAuthHash_");
    personal[12..].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());

    let mut expected = Params::new().hash_length(32).personal(&personal).to_state();
    expected.update(empty_hash(b"ZTxAuthTransHash").as_bytes());
    expected.update(empty_hash(b"ZTxAuthSapliH_v6").as_bytes());
    expected.update(empty_hash(b"ZTxAuthOrchaH_v6").as_bytes());
    expected.update(empty_hash(b"ZTxAuthIrnwdH_v6").as_bytes());

    let tx =
        TransactionData::from_parts_v6(BranchId::Nu6_3, 0, 0u32.into(), None, None, None, None)
            .freeze()
            .unwrap();

    assert_eq!(tx.auth_commitment(), expected.finalize());
}

#[test]
fn v6_empty_orchard_txid_uses_v6_orchard_personalization() {
    fn empty_hash(personal: &[u8; 16]) -> Blake2bHash {
        Params::new().hash_length(32).personal(personal).hash(&[])
    }

    let tx_data =
        TransactionData::from_parts_v6(BranchId::Nu6_3, 0, 0u32.into(), None, None, None, None);
    let txid_parts = tx_data.digest(TxIdDigester);
    let tx = tx_data.freeze().unwrap();

    assert!(txid_parts.orchard_digest.is_none());
    assert!(txid_parts.ironwood_digest.is_none());

    let mut personal = [0; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..].copy_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());

    let mut expected = Params::new().hash_length(32).personal(&personal).to_state();
    expected.update(txid_parts.header_digest.as_bytes());
    expected.update(empty_hash(b"ZTxIdTranspaHash").as_bytes());
    expected.update(empty_hash(b"ZTxIdSaplingHash").as_bytes());
    expected.update(empty_hash(b"ZTxIdOrchardH_v6").as_bytes());
    expected.update(empty_hash(b"ZTxIdIronwd_H_v6").as_bytes());

    let expected = expected.finalize();
    assert_eq!(&tx.txid().as_ref()[..], expected.as_bytes());
}

#[test]
fn v6_branch_reconstruction_preserves_ironwood_bundle() {
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::default();
    let ironwood_bundle = test_ironwood_bundle(&mut runner);
    let tx = TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        None,
        None,
        Some(ironwood_bundle),
    )
    .freeze()
    .unwrap();

    let original_txid = tx.txid();
    let mut tx_bytes = vec![];
    tx.write(&mut tx_bytes).unwrap();

    let tx_data = Transaction::read(&tx_bytes[..], BranchId::Sprout)
        .unwrap()
        .into_data();

    let legacy_rebuilt = TransactionData::from_parts(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        tx_data.transparent_bundle().cloned(),
        tx_data.sprout_bundle().cloned(),
        tx_data.sapling_bundle().cloned(),
        tx_data.orchard_bundle().cloned(),
    )
    .freeze()
    .unwrap();
    assert!(legacy_rebuilt.ironwood_bundle().is_none());
    assert_ne!(legacy_rebuilt.txid(), original_txid);

    let rebuilt = TransactionData::from_parts_v6(
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        tx_data.transparent_bundle().cloned(),
        tx_data.sapling_bundle().cloned(),
        tx_data.orchard_bundle().cloned(),
        tx_data.ironwood_bundle().cloned(),
    )
    .freeze()
    .unwrap();

    assert!(rebuilt.ironwood_bundle().is_some());
    assert_eq!(rebuilt.txid(), original_txid);
}

#[cfg(test)]
fn test_anchor(byte: u8) -> orchard::Anchor {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    orchard::Anchor::from_bytes(bytes).unwrap()
}

#[cfg(test)]
fn test_orchard_bundle(
    runner: &mut proptest::test_runner::TestRunner,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    use proptest::strategy::ValueTree;

    let bundle = crate::transaction::components::orchard::testing::arb_bundle(1)
        .new_tree(runner)
        .unwrap()
        .current();
    crate::transaction::components::orchard::testing::rebuild_with_version(
        bundle,
        orchard::bundle::BundleVersion::orchard_v3(),
    )
}

#[cfg(test)]
fn test_ironwood_bundle(
    runner: &mut proptest::test_runner::TestRunner,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    use proptest::strategy::ValueTree;

    let bundle = crate::transaction::components::orchard::testing::arb_bundle(1)
        .new_tree(runner)
        .unwrap()
        .current();
    crate::transaction::components::orchard::testing::rebuild_with_version(
        bundle,
        orchard::bundle::BundleVersion::ironwood_v3(),
    )
}

#[cfg(test)]
fn bundle_with_anchor(
    bundle: &orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
    anchor: orchard::Anchor,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    orchard::Bundle::try_from_parts(
        bundle.actions().clone(),
        *bundle.flags(),
        *bundle.value_balance(),
        anchor,
        bundle.authorization().clone(),
        bundle.bundle_version(),
    )
    .unwrap()
}

#[cfg(test)]
fn test_sapling_anchor(byte: u8) -> bls12_381::Scalar {
    bls12_381::Scalar::from(u64::from(byte))
}

#[cfg(test)]
fn test_sapling_bundle(
    runner: &mut proptest::test_runner::TestRunner,
) -> sapling::Bundle<sapling::bundle::Authorized, ZatBalance> {
    use proptest::strategy::ValueTree;

    let bundle_strategy =
        crate::transaction::components::sapling::testing::arb_bundle_for_version(TxVersion::V6);

    for _ in 0..100 {
        if let Some(bundle) = bundle_strategy.new_tree(runner).unwrap().current()
            && !bundle.shielded_spends().is_empty()
        {
            // All spends in a Sapling bundle share one anchor, but the
            // strategy generates each spend's anchor independently. Normalize
            // them so the bundle is structurally valid.
            let anchor = *bundle.shielded_spends()[0].anchor();
            return sapling_bundle_with_anchor(&bundle, anchor);
        }
    }

    panic!("Sapling bundle strategy should generate a bundle with spends");
}

#[cfg(test)]
fn test_sapling_output_only_bundle(
    runner: &mut proptest::test_runner::TestRunner,
) -> sapling::Bundle<sapling::bundle::Authorized, ZatBalance> {
    use proptest::strategy::ValueTree;

    let bundle_strategy =
        crate::transaction::components::sapling::testing::arb_bundle_for_version(TxVersion::V6);

    for _ in 0..1000 {
        if let Some(bundle) = bundle_strategy.new_tree(runner).unwrap().current()
            && bundle.shielded_spends().is_empty()
            && !bundle.shielded_outputs().is_empty()
        {
            return bundle;
        }
    }

    panic!("Sapling bundle strategy should generate an output-only bundle");
}

#[cfg(test)]
fn sapling_bundle_with_anchor(
    bundle: &sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
    anchor: bls12_381::Scalar,
) -> sapling::Bundle<sapling::bundle::Authorized, ZatBalance> {
    let spends = bundle
        .shielded_spends()
        .iter()
        .map(|spend| {
            sapling::bundle::SpendDescription::from_parts(
                spend.cv().clone(),
                anchor,
                *spend.nullifier(),
                *spend.rk(),
                *spend.zkproof(),
                *spend.spend_auth_sig(),
            )
        })
        .collect();

    sapling::Bundle::from_parts(
        spends,
        bundle.shielded_outputs().to_vec(),
        *bundle.value_balance(),
        *bundle.authorization(),
    )
    .expect("test bundle has Sapling spends")
}

#[cfg(test)]
fn tx_bytes(tx: &Transaction) -> Vec<u8> {
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    encoded
}

#[cfg(test)]
fn v5_tx_with_orchard_bundle(
    orchard_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> Transaction {
    TransactionData::<crate::transaction::Authorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        0,
        1u32.into(),
        None,
        None,
        None,
        Some(orchard_bundle),
    )
    .freeze()
    .unwrap()
}

#[cfg(test)]
fn v5_tx_data_with_orchard_bundle(
    orchard_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> TransactionData<TestUnauthorized> {
    TransactionData::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        0,
        1u32.into(),
        None,
        None,
        None,
        Some(orchard_bundle),
    )
}

#[cfg(test)]
fn v5_tx_with_sapling_bundle(
    sapling_bundle: sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
) -> Transaction {
    TransactionData::<crate::transaction::Authorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        0,
        1u32.into(),
        None,
        None,
        Some(sapling_bundle),
        None,
    )
    .freeze()
    .unwrap()
}

#[cfg(test)]
fn v5_tx_data_with_sapling_bundle(
    sapling_bundle: sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
) -> TransactionData<TestUnauthorized> {
    TransactionData::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        0,
        1u32.into(),
        None,
        None,
        Some(sapling_bundle),
        None,
    )
}

/// Clears the cross-address flag on an Orchard bundle (preserving spends/outputs)
/// so it is representable in a v6 Orchard slot ([`orchard::bundle::BundleVersion::orchard_v3`],
/// which forbids cross-address transfers; cross-address is Ironwood-only).
#[cfg(test)]
fn disable_cross_address(
    bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    let byte = u8::from(bundle.flags().spends_enabled())
        | (u8::from(bundle.flags().outputs_enabled()) << 1);
    let flags =
        orchard::bundle::Flags::from_byte(byte, orchard::bundle::BundleVersion::orchard_v3())
            .unwrap();
    orchard::Bundle::try_from_parts(
        bundle.actions().clone(),
        flags,
        *bundle.value_balance(),
        *bundle.anchor(),
        bundle.authorization().clone(),
        orchard::bundle::BundleVersion::orchard_v3(),
    )
    .unwrap()
}

#[cfg(test)]
fn v6_tx_with_orchard_bundle(
    orchard_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> Transaction {
    TransactionData::<crate::transaction::Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        None,
        Some(disable_cross_address(orchard_bundle)),
        None,
    )
    .freeze()
    .unwrap()
}

#[cfg(test)]
fn v6_tx_with_sapling_bundle(
    sapling_bundle: sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
) -> Transaction {
    TransactionData::<crate::transaction::Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        Some(sapling_bundle),
        None,
        None,
    )
    .freeze()
    .unwrap()
}

#[cfg(test)]
fn v6_tx_data_with_sapling_bundle(
    sapling_bundle: sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
) -> TransactionData<TestUnauthorized> {
    TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        Some(sapling_bundle),
        None,
        None,
    )
}

#[cfg(test)]
fn v6_tx_data_with_orchard_bundle(
    orchard_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> TransactionData<TestUnauthorized> {
    TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        None,
        Some(disable_cross_address(orchard_bundle)),
        None,
    )
}

#[cfg(test)]
fn v6_tx_with_ironwood_bundle(
    ironwood_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> Transaction {
    TransactionData::<crate::transaction::Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        None,
        None,
        Some(ironwood_bundle),
    )
    .freeze()
    .unwrap()
}

#[cfg(test)]
fn v6_tx_data_with_ironwood_bundle(
    ironwood_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> TransactionData<TestUnauthorized> {
    TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        None,
        None,
        Some(ironwood_bundle),
    )
}

#[cfg(test)]
fn v5_shielded_sighash(tx_data: &TransactionData<TestUnauthorized>) -> Blake2bHash {
    let txid_parts = tx_data.digest(TxIdDigester);
    v5_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts, None)
}

#[cfg(test)]
fn v6_shielded_sighash(tx_data: &TransactionData<TestUnauthorized>) -> Blake2bHash {
    let txid_parts = tx_data.digest(TxIdDigester);
    v6_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts, None)
}

#[test]
fn v6_orchard_anchor_changes_auth_commitment_not_txid_or_sighash() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_orchard_bundle(&mut runner);

    let bundle_a = bundle_with_anchor(&bundle, test_anchor(1));
    let bundle_b = bundle_with_anchor(&bundle, test_anchor(2));
    let tx_data_a = v6_tx_data_with_orchard_bundle(bundle_a.clone());
    let tx_data_b = v6_tx_data_with_orchard_bundle(bundle_b.clone());
    let tx_a = v6_tx_with_orchard_bundle(bundle_a);
    let tx_b = v6_tx_with_orchard_bundle(bundle_b);

    assert_ne!(tx_bytes(&tx_a), tx_bytes(&tx_b));
    assert_eq!(tx_a.txid(), tx_b.txid());
    assert_eq!(
        v6_shielded_sighash(&tx_data_a),
        v6_shielded_sighash(&tx_data_b)
    );
    assert_ne!(tx_a.auth_commitment(), tx_b.auth_commitment());
}

#[test]
fn v6_ironwood_anchor_changes_auth_commitment_not_txid_or_sighash() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_ironwood_bundle(&mut runner);

    let bundle_a = bundle_with_anchor(&bundle, test_anchor(1));
    let bundle_b = bundle_with_anchor(&bundle, test_anchor(2));
    let tx_data_a = v6_tx_data_with_ironwood_bundle(bundle_a.clone());
    let tx_data_b = v6_tx_data_with_ironwood_bundle(bundle_b.clone());
    let tx_a = v6_tx_with_ironwood_bundle(bundle_a);
    let tx_b = v6_tx_with_ironwood_bundle(bundle_b);

    assert_ne!(tx_bytes(&tx_a), tx_bytes(&tx_b));
    assert_eq!(tx_a.txid(), tx_b.txid());
    assert_eq!(
        v6_shielded_sighash(&tx_data_a),
        v6_shielded_sighash(&tx_data_b)
    );
    assert_ne!(tx_a.auth_commitment(), tx_b.auth_commitment());
}

#[test]
fn v5_orchard_anchor_still_changes_txid_and_sighash() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_orchard_bundle(&mut runner);

    let bundle_a = bundle_with_anchor(&bundle, test_anchor(1));
    let bundle_b = bundle_with_anchor(&bundle, test_anchor(2));
    let tx_data_a = v5_tx_data_with_orchard_bundle(bundle_a.clone());
    let tx_data_b = v5_tx_data_with_orchard_bundle(bundle_b.clone());
    let tx_a = v5_tx_with_orchard_bundle(bundle_a);
    let tx_b = v5_tx_with_orchard_bundle(bundle_b);

    assert_ne!(tx_a.txid(), tx_b.txid());
    assert_ne!(
        v5_shielded_sighash(&tx_data_a),
        v5_shielded_sighash(&tx_data_b)
    );
    assert_eq!(tx_a.auth_commitment(), tx_b.auth_commitment());
}

#[test]
fn v6_sapling_anchor_changes_auth_commitment_not_txid_or_sighash() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_sapling_bundle(&mut runner);

    let bundle_a = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(1));
    let bundle_b = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(2));
    let tx_data_a = v6_tx_data_with_sapling_bundle(bundle_a.clone());
    let tx_data_b = v6_tx_data_with_sapling_bundle(bundle_b.clone());
    let tx_a = v6_tx_with_sapling_bundle(bundle_a);
    let tx_b = v6_tx_with_sapling_bundle(bundle_b);

    assert_ne!(tx_bytes(&tx_a), tx_bytes(&tx_b));
    assert_eq!(tx_a.txid(), tx_b.txid());
    assert_eq!(
        v6_shielded_sighash(&tx_data_a),
        v6_shielded_sighash(&tx_data_b)
    );
    assert_ne!(tx_a.auth_commitment(), tx_b.auth_commitment());
}

#[test]
fn v5_sapling_anchor_still_changes_txid_and_sighash() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_sapling_bundle(&mut runner);

    let bundle_a = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(1));
    let bundle_b = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(2));
    let tx_data_a = v5_tx_data_with_sapling_bundle(bundle_a.clone());
    let tx_data_b = v5_tx_data_with_sapling_bundle(bundle_b.clone());
    let tx_a = v5_tx_with_sapling_bundle(bundle_a);
    let tx_b = v5_tx_with_sapling_bundle(bundle_b);

    assert_ne!(tx_a.txid(), tx_b.txid());
    assert_ne!(
        v5_shielded_sighash(&tx_data_a),
        v5_shielded_sighash(&tx_data_b)
    );
    assert_eq!(tx_a.auth_commitment(), tx_b.auth_commitment());
}

#[test]
fn v6_sapling_spends_digest_uses_v6_noncompact_domain_without_anchor() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_sapling_bundle(&mut runner);

    let mut h = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSSpendsHash")
        .to_state();
    let mut ch = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSSpendCHash")
        .to_state();
    let mut nh = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSSpendNH_v6")
        .to_state();

    for spend in bundle.shielded_spends() {
        ch.update(spend.nullifier().as_ref());
        nh.update(&spend.cv().to_bytes());
        nh.update(&<[u8; 32]>::from(*spend.rk()));
    }

    h.update(ch.finalize().as_bytes());
    h.update(nh.finalize().as_bytes());

    assert_eq!(
        hash_sapling_spends(TxVersion::V6, bundle.shielded_spends()),
        h.finalize()
    );

    let bundle_a = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(1));
    let bundle_b = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(2));
    assert_eq!(
        hash_sapling_spends(TxVersion::V6, bundle_a.shielded_spends()),
        hash_sapling_spends(TxVersion::V6, bundle_b.shielded_spends())
    );
}

#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_sapling_spends_digest_hashes_anchor_under_zip244_personalization() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_sapling_bundle(&mut runner);

    let mut h = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSSpendsHash")
        .to_state();
    let mut ch = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSSpendCHash")
        .to_state();
    let mut nh = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSSpendNHash")
        .to_state();

    for spend in bundle.shielded_spends() {
        ch.update(spend.nullifier().as_ref());
        nh.update(&spend.cv().to_bytes());
        nh.update(&spend.anchor().to_repr());
        nh.update(&<[u8; 32]>::from(*spend.rk()));
    }

    h.update(ch.finalize().as_bytes());
    h.update(nh.finalize().as_bytes());

    assert_eq!(
        hash_sapling_spends(TxVersion::V7, bundle.shielded_spends()),
        h.finalize(),
        "v7 hashes cv || anchor || rk per spend under ZTxIdSSpendNHash"
    );

    let bundle_a = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(1));
    let bundle_b = sapling_bundle_with_anchor(&bundle, test_sapling_anchor(2));
    assert_ne!(
        hash_sapling_spends(TxVersion::V7, bundle_a.shielded_spends()),
        hash_sapling_spends(TxVersion::V7, bundle_b.shielded_spends()),
        "the v7 spends digest must commit to the anchor"
    );
}

#[test]
fn v6_sapling_auth_digest_uses_v6_domain_and_appends_anchor() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_sapling_bundle(&mut runner);

    let mut h = Params::new()
        .hash_length(32)
        .personal(b"ZTxAuthSapliH_v6")
        .to_state();
    for spend in bundle.shielded_spends() {
        h.update(spend.zkproof());
    }
    for spend in bundle.shielded_spends() {
        h.update(&<[u8; 64]>::from(*spend.spend_auth_sig()));
    }
    for output in bundle.shielded_outputs() {
        h.update(output.zkproof());
    }
    h.update(&<[u8; 64]>::from(bundle.authorization().binding_sig));
    h.update(bundle.shielded_spends()[0].anchor().to_repr().as_ref());

    let actual = TransactionDigest::<crate::transaction::Authorized>::digest_sapling(
        &BlockTxCommitmentDigester,
        TxVersion::V6,
        Some(&bundle),
    );

    assert_eq!(actual, h.finalize());
}

#[test]
fn v6_sapling_output_only_auth_digest_uses_v6_domain_without_anchor() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_sapling_output_only_bundle(&mut runner);

    let mut h = Params::new()
        .hash_length(32)
        .personal(b"ZTxAuthSapliH_v6")
        .to_state();
    for output in bundle.shielded_outputs() {
        h.update(output.zkproof());
    }
    h.update(&<[u8; 64]>::from(bundle.authorization().binding_sig));

    let actual = TransactionDigest::<crate::transaction::Authorized>::digest_sapling(
        &BlockTxCommitmentDigester,
        TxVersion::V6,
        Some(&bundle),
    );

    assert_eq!(actual, h.finalize());
}

#[test]
fn v6_orchard_non_anchor_bundle_data_still_changes_txid_and_sighash() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let anchor = test_anchor(1);

    let bundle_a = bundle_with_anchor(&test_orchard_bundle(&mut runner), anchor);
    let bundle_b = bundle_with_anchor(&test_orchard_bundle(&mut runner), anchor);
    let tx_data_a = v6_tx_data_with_orchard_bundle(bundle_a.clone());
    let tx_data_b = v6_tx_data_with_orchard_bundle(bundle_b.clone());
    let tx_a = v6_tx_with_orchard_bundle(bundle_a);
    let tx_b = v6_tx_with_orchard_bundle(bundle_b);

    assert_ne!(tx_a.txid(), tx_b.txid());
    assert_ne!(
        v6_shielded_sighash(&tx_data_a),
        v6_shielded_sighash(&tx_data_b)
    );
    assert_ne!(tx_a.auth_commitment(), tx_b.auth_commitment());
}

#[cfg(test)]
fn check_roundtrip(tx: Transaction) -> Result<(), TestCaseError> {
    let mut txn_bytes = vec![];
    tx.write(&mut txn_bytes).unwrap();
    let txo = Transaction::read(&txn_bytes[..], tx.consensus_branch_id).unwrap();

    // Re-serializing must reproduce the bytes it was parsed from. Comparing
    // fields and digests cannot see an encoding the parser accepts but the
    // serializer would not produce, which would give one transaction two wire
    // forms under a single txid.
    let mut reserialized = vec![];
    txo.write(&mut reserialized).unwrap();
    prop_assert_eq!(&txn_bytes, &reserialized);

    prop_assert_eq!(tx.version(), txo.version());
    prop_assert_eq!(tx.lock_time(), txo.lock_time());
    prop_assert_eq!(tx.transparent_bundle(), txo.transparent_bundle());
    prop_assert_eq!(tx.sapling_value_balance(), txo.sapling_value_balance());
    prop_assert_eq!(
        tx.orchard_bundle().map(|v| *v.value_balance()),
        txo.orchard_bundle().map(|v| *v.value_balance())
    );
    prop_assert_eq!(
        tx.ironwood_bundle().map(|v| *v.value_balance()),
        txo.ironwood_bundle().map(|v| *v.value_balance())
    );
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    if tx.version().has_zip233(tx.consensus_branch_id()) {
        prop_assert_eq!(tx.zip233_amount(), txo.zip233_amount());
    }
    // The identifier and the authorizing data commitment cover the bundle
    // fields that the assertions above do not reach, including which side of
    // the effecting/authorizing split each field was encoded on.
    //
    // A Sapling bundle encodes one anchor for all of its spends, so a
    // generated bundle whose spends disagree about the anchor cannot survive
    // a roundtrip; the digests are only meaningful for the rest.
    let sapling_anchors_agree = tx.sapling_bundle().is_none_or(|bundle| {
        let mut anchors = bundle
            .shielded_spends()
            .iter()
            .map(|spend| spend.anchor().to_bytes());
        anchors
            .next()
            .is_none_or(|first| anchors.all(|a| a == first))
    });
    if sapling_anchors_agree {
        prop_assert_eq!(tx.txid(), txo.txid());
        let (auth, auth_o) = (tx.auth_commitment(), txo.auth_commitment());
        prop_assert_eq!(auth.as_bytes(), auth_o.as_bytes());
    }
    Ok(())
}

proptest! {
    #[test]
    #[cfg(all(feature = "expensive-tests", not(feature = "no-expensive-tests")))]
    fn tx_serialization_roundtrip_sprout(tx in arb_tx(BranchId::Sprout)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[cfg(all(feature = "expensive-tests", not(feature = "no-expensive-tests")))]
    fn tx_serialization_roundtrip_overwinter(tx in arb_tx(BranchId::Overwinter)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[cfg(all(feature = "expensive-tests", not(feature = "no-expensive-tests")))]
    fn tx_serialization_roundtrip_sapling(tx in arb_tx(BranchId::Sapling)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[cfg(all(feature = "expensive-tests", not(feature = "no-expensive-tests")))]
    fn tx_serialization_roundtrip_blossom(tx in arb_tx(BranchId::Blossom)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[cfg(all(feature = "expensive-tests", not(feature = "no-expensive-tests")))]
    fn tx_serialization_roundtrip_heartwood(tx in arb_tx(BranchId::Heartwood)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_canopy(tx in arb_tx(BranchId::Canopy)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu5(tx in arb_tx(BranchId::Nu5)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu6_3(tx in arb_tx(BranchId::Nu6_3)) {
        check_roundtrip(tx)?;
    }
}

#[cfg(test)]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu7(tx in arb_tx(BranchId::Nu7)) {
        check_roundtrip(tx)?;
    }
}

#[cfg(zcash_unstable = "nu8")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu8(tx in arb_tx(BranchId::Nu8)) {
        check_roundtrip(tx)?;
    }
}

#[test]
fn zip_0143() {
    for tv in self::data::zip_0143::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], tv.consensus_branch_id).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::Transparent(
                ::transparent::sighash::SignableInput::from_parts(
                    tx.transparent_bundle().unwrap(),
                    SighashType::parse(tv.hash_type as u8).unwrap(),
                    n as usize,
                    &tv.script_code,
                    &tv.script_code,
                    Zatoshis::from_nonnegative_i64(tv.amount).unwrap(),
                )
                .unwrap(),
            ),
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            v4_signature_hash(tx.deref(), &signable_input, &zip143_digests(tx.deref())).as_ref(),
            tv.sighash
        );

        let precomputed =
            PrecomputedSighashData::new(with_test_transparent_auth(tx.into_data(), vec![], vec![]));
        assert_eq!(
            precomputed.signature_hash(&signable_input).as_ref(),
            &tv.sighash
        );
    }
}

#[test]
fn zip_0243() {
    for tv in self::data::zip_0243::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], tv.consensus_branch_id).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::Transparent(
                ::transparent::sighash::SignableInput::from_parts(
                    tx.transparent_bundle().unwrap(),
                    SighashType::parse(tv.hash_type as u8).unwrap(),
                    n as usize,
                    &tv.script_code,
                    &tv.script_code,
                    Zatoshis::from_nonnegative_i64(tv.amount).unwrap(),
                )
                .unwrap(),
            ),
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            v4_signature_hash(tx.deref(), &signable_input, &zip143_digests(tx.deref())).as_ref(),
            tv.sighash
        );

        let precomputed =
            PrecomputedSighashData::new(with_test_transparent_auth(tx.into_data(), vec![], vec![]));
        assert_eq!(
            precomputed.signature_hash(&signable_input).as_ref(),
            &tv.sighash
        );
    }
}

#[cfg(test)]
#[derive(Debug)]
struct TestTransparentAuth {
    input_amounts: Vec<Zatoshis>,
    input_scriptpubkeys: Vec<Script>,
    /// The number of calls to `input_amounts` and `input_scriptpubkeys`.
    reads: Cell<usize>,
}

#[cfg(test)]
impl TestTransparentAuth {
    fn new(input_amounts: Vec<Zatoshis>, input_scriptpubkeys: Vec<Script>) -> Self {
        TestTransparentAuth {
            input_amounts,
            input_scriptpubkeys,
            reads: Cell::new(0),
        }
    }
}

/// Returns `txdata` with a transparent authorization that provides `input_amounts` and
/// `input_scriptpubkeys` to the signature hash.
#[cfg(test)]
fn with_test_transparent_auth(
    txdata: TransactionData<Authorized>,
    input_amounts: Vec<Zatoshis>,
    input_scriptpubkeys: Vec<Script>,
) -> TransactionData<TestUnauthorized> {
    txdata.map_bundles(
        |b| {
            b.map(|b| transparent::Bundle {
                vin: b
                    .vin
                    .iter()
                    .map(|vin| {
                        TxIn::from_parts(
                            vin.prevout().clone(),
                            vin.script_sig().clone(),
                            vin.sequence(),
                        )
                    })
                    .collect(),
                vout: b.vout,
                authorization: TestTransparentAuth::new(input_amounts, input_scriptpubkeys),
            })
        },
        |b| b,
        |b| b,
    )
}

#[cfg(test)]
impl transparent::Authorization for TestTransparentAuth {
    type ScriptSig = Script;
}

#[cfg(test)]
impl TransparentAuthorizingContext for TestTransparentAuth {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.reads.set(self.reads.get() + 1);
        self.input_amounts.clone()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.reads.set(self.reads.get() + 1);
        self.input_scriptpubkeys.clone()
    }
}

#[cfg(test)]
struct TestUnauthorized;

#[cfg(test)]
impl Authorization for TestUnauthorized {
    type TransparentAuth = TestTransparentAuth;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

#[test]
fn zip_0244() {
    fn to_test_txdata(
        tv: &self::data::zip_0244::TestVector,
    ) -> (
        TransactionData<TestUnauthorized>,
        Zip244Digests<Blake2bHash>,
    ) {
        let tx = Transaction::read(&tv.tx[..], BranchId::Nu5).unwrap();

        assert_eq!(tx.txid.as_ref(), &tv.txid);
        assert_eq!(tx.auth_commitment().as_ref(), &tv.auth_digest);

        let txdata = tx.deref();

        let input_amounts = tv
            .amounts
            .iter()
            .map(|amount| Zatoshis::from_nonnegative_i64(*amount).unwrap())
            .collect();
        let input_scriptpubkeys = tv
            .script_pubkeys
            .iter()
            .cloned()
            .map(script::Code)
            .map(Script)
            .collect();

        let test_bundle = txdata.transparent_bundle().map(|b| transparent::Bundle {
            // we have to do this map/clone to make the types line up, since the
            // Authorization::ScriptSig type is bound to transparent::Authorized, and we need
            // it to be bound to TestTransparentAuth.
            vin: b
                .vin
                .iter()
                .map(|vin| {
                    TxIn::from_parts(
                        vin.prevout().clone(),
                        vin.script_sig().clone(),
                        vin.sequence(),
                    )
                })
                .collect(),
            vout: b.vout.clone(),
            authorization: TestTransparentAuth::new(input_amounts, input_scriptpubkeys),
        });

        #[cfg(not(all(feature = "zip-233", zcash_unstable = "zip233")))]
        let tdata = TransactionData::from_parts(
            txdata.version(),
            txdata.consensus_branch_id(),
            txdata.lock_time(),
            txdata.expiry_height(),
            test_bundle,
            txdata.sprout_bundle().cloned(),
            txdata.sapling_bundle().cloned(),
            txdata.orchard_bundle().cloned(),
        );
        #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
        let tdata = TransactionData::from_parts_with_zip233(
            txdata.version(),
            txdata.consensus_branch_id(),
            txdata.lock_time(),
            txdata.expiry_height(),
            txdata.zip233_amount(),
            test_bundle,
            txdata.sprout_bundle().cloned(),
            txdata.sapling_bundle().cloned(),
            txdata.orchard_bundle().cloned(),
        );
        (tdata, txdata.digest(TxIdDigester))
    }

    for tv in self::data::zip_0244::make_test_vectors() {
        let (txdata, txid_parts) = to_test_txdata(&tv);
        let precomputed = PrecomputedSighashData::new(txdata);
        let txdata = precomputed.tx();

        // Computes the signature hash both from the precomputed digests and with the input
        // digests computed on demand, and checks that the results agree.
        let check_sighash = |signable_input: &SignableInput<'_>| {
            let sighash = v5_signature_hash(txdata, signable_input, &txid_parts, None);
            assert_eq!(
                precomputed.signature_hash(signable_input).as_ref(),
                sighash.as_bytes()
            );
            sighash
        };

        if let Some(index) = tv.transparent_input {
            // nIn is a u32, but to actually use it we need a usize.
            let index = index as usize;
            let bundle = txdata.transparent_bundle().unwrap();
            let value = bundle.authorization.input_amounts[index];
            let script_pubkey = &bundle.authorization.input_scriptpubkeys[index];
            let signable_input = |hash_type| {
                SignableInput::Transparent(
                    ::transparent::sighash::SignableInput::from_parts(
                        bundle,
                        hash_type,
                        index,
                        script_pubkey,
                        script_pubkey,
                        value,
                    )
                    .unwrap(),
                )
            };

            assert_eq!(
                check_sighash(&signable_input(SighashType::ALL)).as_ref(),
                &tv.sighash_all.unwrap()
            );

            assert_eq!(
                check_sighash(&signable_input(SighashType::NONE)).as_ref(),
                &tv.sighash_none.unwrap()
            );

            if index < bundle.vout.len() {
                assert_eq!(
                    check_sighash(&signable_input(SighashType::SINGLE)).as_ref(),
                    &tv.sighash_single.unwrap()
                );
            } else {
                assert_eq!(tv.sighash_single, None);
            }

            assert_eq!(
                check_sighash(&signable_input(SighashType::ALL_ANYONECANPAY)).as_ref(),
                &tv.sighash_all_anyone.unwrap()
            );

            assert_eq!(
                check_sighash(&signable_input(SighashType::NONE_ANYONECANPAY)).as_ref(),
                &tv.sighash_none_anyone.unwrap()
            );

            if index < bundle.vout.len() {
                assert_eq!(
                    check_sighash(&signable_input(SighashType::SINGLE_ANYONECANPAY)).as_ref(),
                    &tv.sighash_single_anyone.unwrap()
                );
            } else {
                assert_eq!(tv.sighash_single_anyone, None);
            }
        };

        assert_eq!(
            check_sighash(&SignableInput::Shielded).as_ref(),
            tv.sighash_shielded
        );

        // Computing the signature hashes of every input under every hash type reads the
        // input amounts and `scriptPubKey`s only once.
        let precomputed = PrecomputedSighashData::new(to_test_txdata(&tv).0);
        if let Some(bundle) = precomputed
            .tx()
            .transparent_bundle()
            .filter(|b| !b.is_coinbase() && !b.vin.is_empty())
        {
            for index in 0..bundle.vin.len() {
                for hash_type in [
                    SighashType::ALL,
                    SighashType::NONE,
                    SighashType::SINGLE,
                    SighashType::ALL_ANYONECANPAY,
                    SighashType::NONE_ANYONECANPAY,
                    SighashType::SINGLE_ANYONECANPAY,
                ] {
                    let script_pubkey = &bundle.authorization.input_scriptpubkeys[index];
                    let signable_input = SignableInput::Transparent(
                        ::transparent::sighash::SignableInput::from_parts(
                            bundle,
                            hash_type,
                            index,
                            script_pubkey,
                            script_pubkey,
                            bundle.authorization.input_amounts[index],
                        )
                        .unwrap(),
                    );
                    precomputed.signature_hash(&signable_input);
                }
            }
            // One call each to `input_amounts` and `input_scriptpubkeys`.
            assert_eq!(bundle.authorization.reads.get(), 2);
        }
    }
}

/// V7 value pool delta roundtrip for the fee and ZIP 233 bundle types.
///
/// No implemented transaction format supports ZIP 233, so `freeze` rejects a
/// nonzero ZIP 233 amount. A zero amount is elided from the value pool delta
/// map, leaving the fee entry to round-trip.
#[cfg(all(zcash_unstable = "nu8", feature = "zip-233", zcash_unstable = "zip233"))]
#[test]
fn zip_0233() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    let make_data = |fee: u64, nsm: u64| {
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_fee(Zatoshis::from_u64(fee).unwrap()).unwrap();
        vp.set_zip233(Zatoshis::from_u64(nsm).unwrap()).unwrap();
        TransactionData::<super::Authorized>::from_parts_with_value_pool_deltas(
            super::TxVersion::V7,
            BranchId::Nu8,
            0,
            BlockHeight::from_u32(100),
            vp,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    };

    // A nonzero ZIP 233 amount is not supported by any implemented format.
    assert!(make_data(10_000, 50_000).freeze().is_err());

    // A zero ZIP 233 amount is elided, and the fee round-trips.
    let tx = make_data(10_000, 0).freeze().unwrap();
    let mut buf = Vec::new();
    tx.write(&mut buf).unwrap();
    let tx = Transaction::read(&buf[..], BranchId::Nu8).unwrap();
    assert_eq!(
        tx.value_pool_deltas().fee(),
        Some(Zatoshis::from_u64(10_000).unwrap())
    );
    assert_eq!(tx.value_pool_deltas().zip233_amount(), None);

    // Determinism: same inputs → same txid.
    let tx2 = make_data(10_000, 0).freeze().unwrap();
    assert_eq!(tx.txid(), tx2.txid());

    // Different fee → different txid.
    let tx3 = make_data(20_000, 0).freeze().unwrap();
    assert_ne!(tx.txid(), tx3.txid());
}

/// [ZIP 248 §v0 Signature Digest](https://zips.z.cash/zip-0248#v0-signature-digest):
/// "For transactions that have no transparent inputs, the v0 signature digest
/// is identical to the transaction identifier digest."
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_signature_hash_without_transparent_inputs_is_the_txid() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    let mut vp = zip248::ValuePoolDeltas::empty();
    vp.set_fee(Zatoshis::from_u64(10_000).unwrap()).unwrap();
    vp.set_sapling(zcash_protocol::value::ZatBalance::from_i64(10_000).unwrap())
        .unwrap();
    // `TestUnauthorized` supplies the transparent signing context that the
    // signature hash requires; this transaction has no transparent bundle.
    let tx = TransactionData::<TestUnauthorized>::from_parts_with_value_pool_deltas(
        super::TxVersion::V7,
        BranchId::Nu8,
        0,
        BlockHeight::from_u32(100),
        vp,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let txid_parts = tx.digest_v7();
    let sighash = v7_signature_hash(&tx, &SignableInput::Shielded, &txid_parts, None);
    assert_eq!(
        sighash.as_bytes(),
        super::txid::to_txid(tx.version(), tx.consensus_branch_id(), &txid_parts)
            .unwrap()
            .as_ref(),
    );
}

/// Computes the transparent input amounts digest and scriptPubKeys digest for `bundle`.
#[cfg(all(test, zcash_unstable = "nu8"))]
fn manual_transparent_inputs_digests(
    bundle: &transparent::Bundle<TestTransparentAuth>,
) -> (Blake2bHash, Blake2bHash) {
    use corez::io::Write;
    use zcash_encoding::Array;

    let mut amounts = Params::new()
        .hash_length(32)
        .personal(b"ZTxTrAmountsHash")
        .to_state();
    Array::write(
        &mut amounts,
        bundle.authorization.input_amounts(),
        |w, amount| w.write_all(&amount.to_i64_le_bytes()),
    )
    .unwrap();

    let mut scripts = Params::new()
        .hash_length(32)
        .personal(b"ZTxTrScriptsHash")
        .to_state();
    Array::write(
        &mut scripts,
        bundle.authorization.input_scriptpubkeys(),
        |w, script| script.write(w),
    )
    .unwrap();

    (amounts.finalize(), scripts.finalize())
}

/// Reconstructs the [ZIP 248 §S.3.0](https://zips.z.cash/zip-0248#s-3-0-transparent-sig-digest)
/// transparent signature digest, whose `sequence_sig_digest` is always the transaction's
/// `sequence_digest`, regardless of `hash_type`.
#[cfg(all(test, zcash_unstable = "nu8"))]
fn manual_v7_transparent_sig_digest(
    bundle: &transparent::Bundle<TestTransparentAuth>,
    txid_digests: &super::TransparentDigests<Blake2bHash>,
    input: &SignableInput<'_>,
) -> Blake2bHash {
    use super::txid::{
        ZCASH_TRANSPARENT_HASH_PERSONALIZATION, hash_transparent_txid_data,
        transparent_outputs_hash, transparent_prevout_hash,
    };
    use ::transparent::sighash::{
        SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE,
    };
    use corez::io::Write;

    if bundle.is_coinbase() || bundle.vin.is_empty() {
        return hash_transparent_txid_data(Some(txid_digests));
    }

    let hash_type = input.hash_type();
    let flag_anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;
    let flag_single = hash_type & SIGHASH_MASK == SIGHASH_SINGLE;
    let flag_none = hash_type & SIGHASH_MASK == SIGHASH_NONE;

    let prevouts_digest = if flag_anyonecanpay {
        transparent_prevout_hash::<TestTransparentAuth>(&[])
    } else {
        txid_digests.prevouts_digest
    };

    let (amounts_digest, scripts_digest) = if flag_anyonecanpay {
        (
            Params::new()
                .hash_length(32)
                .personal(b"ZTxTrAmountsHash")
                .to_state()
                .finalize(),
            Params::new()
                .hash_length(32)
                .personal(b"ZTxTrScriptsHash")
                .to_state()
                .finalize(),
        )
    } else {
        manual_transparent_inputs_digests(bundle)
    };

    // S.3.0e: sequence_sig_digest is identical to sequence_digest regardless of hash_type.
    let sequence_digest = txid_digests.sequence_digest;

    let outputs_digest = if let SignableInput::Transparent(input) = input {
        if flag_single {
            if *input.index() < bundle.vout.len() {
                transparent_outputs_hash(&[&bundle.vout[*input.index()]])
            } else {
                transparent_outputs_hash::<transparent::TxOut>(&[])
            }
        } else if flag_none {
            transparent_outputs_hash::<transparent::TxOut>(&[])
        } else {
            txid_digests.outputs_digest
        }
    } else {
        txid_digests.outputs_digest
    };

    let mut ch = Params::new()
        .hash_length(32)
        .personal(b"Zcash___TxInHash")
        .to_state();
    if let SignableInput::Transparent(input) = input {
        let txin = &bundle.vin[*input.index()];
        txin.prevout().write(&mut ch).unwrap();
        ch.write_all(&input.value().to_i64_le_bytes()).unwrap();
        input.script_pubkey().write(&mut ch).unwrap();
        ch.write_all(&txin.sequence().to_le_bytes()).unwrap();
    }
    let txin_sig_digest = ch.finalize();

    let mut h = Params::new()
        .hash_length(32)
        .personal(ZCASH_TRANSPARENT_HASH_PERSONALIZATION)
        .to_state();
    h.write_all(&[hash_type]).unwrap();
    h.write_all(prevouts_digest.as_bytes()).unwrap();
    h.write_all(amounts_digest.as_bytes()).unwrap();
    h.write_all(scripts_digest.as_bytes()).unwrap();
    h.write_all(sequence_digest.as_bytes()).unwrap();
    h.write_all(outputs_digest.as_bytes()).unwrap();
    h.write_all(txin_sig_digest.as_bytes()).unwrap();
    h.finalize()
}

/// [ZIP 248 §S.2](https://zips.z.cash/zip-0248#s-2-value_pool_deltas_sig_digest):
/// the signature digest uses the T.2 value pool deltas digest unchanged, so a
/// transparent input signature commits to every value pool delta entry for
/// every `hash_type`.
///
/// [ZIP 248 §S.3.0e](https://zips.z.cash/zip-0248#s-3-0e-sequence-sig-digest):
/// `sequence_sig_digest` remains the transaction's `sequence_digest` under
/// `SIGHASH_ANYONECANPAY`.
#[test]
#[cfg(all(test, zcash_unstable = "nu8"))]
fn v7_transparent_sighash_commits_to_all_value_pool_deltas() {
    use super::sighash_v5::transparent_sig_digest;
    use super::txid::{
        hash_v7_effects_bundles, hasher, tx_hash_personalization, v7_bundle_digest_entries,
    };
    use super::zip248;
    use alloc::vec;
    use alloc::vec::Vec;
    use corez::io::Write;
    use zcash_protocol::consensus::BlockHeight;

    fn compact_size(value: u64) -> Vec<u8> {
        match value {
            0..=0xfc => vec![value as u8],
            0xfd..=0xffff => {
                let mut out = vec![0xfd];
                out.extend_from_slice(&(value as u16).to_le_bytes());
                out
            }
            0x1_0000..=0xffff_ffff => {
                let mut out = vec![0xfe];
                out.extend_from_slice(&(value as u32).to_le_bytes());
                out
            }
            _ => {
                let mut out = vec![0xff];
                out.extend_from_slice(&value.to_le_bytes());
                out
            }
        }
    }

    fn manual_vp_digest(entries: &[zip248::ValuePoolDeltaEntry]) -> Blake2bHash {
        let mut preimage = Vec::new();
        for entry in entries {
            preimage.extend_from_slice(&compact_size(entry.bundle_type().to_u64()));
            preimage.extend_from_slice(&compact_size(entry.bundle_variant().to_u64()));
            preimage.push(entry.asset_class());
            if let Some(uuid) = entry.asset_uuid() {
                preimage.extend_from_slice(uuid);
            }
            preimage.extend_from_slice(&i64::from(entry.value()).to_le_bytes());
        }
        blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZTxIdVPDeltaHash")
            .hash(&preimage)
    }

    fn make_tx(transparent_value: i64, fee: u64) -> TransactionData<TestUnauthorized> {
        let transparent = transparent::Bundle {
            vin: vec![transparent::TxIn::from_parts(
                transparent::OutPoint::new([1; 32], 0),
                Script::default(),
                0,
            )],
            vout: vec![transparent::TxOut::new(
                Zatoshis::from_u64(1000).unwrap(),
                Script::default(),
            )],
            authorization: transparent::Authorized,
        };

        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_transparent(ZatBalance::from_i64(transparent_value).unwrap())
            .unwrap();
        vp.set_fee(Zatoshis::from_u64(fee).unwrap()).unwrap();
        vp.set_sapling(ZatBalance::from_i64(500).unwrap()).unwrap();
        vp.insert(
            zip248::ValuePoolDeltaKey::from_parts(zip248::BundleType::from_u64(8), 0, [0u8; 64])
                .unwrap(),
            zip248::BundleVariant::from_u64(0),
            ZatBalance::from_i64(7).unwrap(),
        )
        .unwrap();

        let tx = TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            BlockHeight::from(100u32),
            vp,
            Some(transparent),
            None,
            None,
            None,
            None,
            None,
        );
        with_test_transparent_auth(
            tx,
            vec![Zatoshis::from_u64(1000).unwrap()],
            vec![Script::default()],
        )
    }

    let tx = make_tx(-1000, 1000);
    let txid_parts = tx.digest_v7();
    let entries = tx.value_pool_deltas().to_wire_entries();
    let bundle = tx.transparent_bundle().unwrap();
    let script = Script::default();

    for hash_type in [
        SighashType::ALL,
        SighashType::NONE,
        SighashType::SINGLE,
        SighashType::ALL_ANYONECANPAY,
        SighashType::NONE_ANYONECANPAY,
        SighashType::SINGLE_ANYONECANPAY,
    ] {
        let signable_input = SignableInput::Transparent(
            ::transparent::sighash::SignableInput::from_parts(
                bundle,
                hash_type,
                0,
                &script,
                &script,
                Zatoshis::from_u64(1000).unwrap(),
            )
            .unwrap(),
        );

        let expected_vp = manual_vp_digest(&entries);
        assert_eq!(
            txid_parts.value_pool_deltas_digest.as_ref(),
            Some(&expected_vp),
            "T.2 reconstruction mismatch for {hash_type:?}"
        );

        let transparent_sig = manual_v7_transparent_sig_digest(
            bundle,
            txid_parts.transparent_digests.as_ref().unwrap(),
            &signable_input,
        );
        let v5_transparent_sig = transparent_sig_digest(
            Some((bundle, txid_parts.transparent_digests.as_ref().unwrap())),
            None,
            &signable_input,
        );
        if hash_type.encode() & ::transparent::sighash::SIGHASH_ANYONECANPAY != 0 {
            // The V5 helper clears the sequence digest under ANYONECANPAY; the V7
            // reconstruction must keep it, so the two digests differ.
            assert_ne!(
                transparent_sig.as_bytes(),
                v5_transparent_sig.as_bytes(),
                "V7 must preserve the sequence digest under {hash_type:?}"
            );
        } else {
            assert_eq!(
                transparent_sig.as_bytes(),
                v5_transparent_sig.as_bytes(),
                "V7 and V5 transparent digests must agree for {hash_type:?}"
            );
        }
        let expected_bundles = hash_v7_effects_bundles(v7_bundle_digest_entries(
            Some(&transparent_sig),
            txid_parts.coinbase_digest.as_ref(),
            txid_parts.sapling_digest.as_ref(),
            txid_parts.orchard_digest.as_ref(),
            txid_parts.ironwood_digest.as_ref(),
            &txid_parts.unknown_effect_digests,
        ));
        let mut h = hasher(&tx_hash_personalization(BranchId::Nu8));
        h.write_all(txid_parts.header_digest.as_bytes()).unwrap();
        h.write_all(expected_vp.as_bytes()).unwrap();
        h.write_all(expected_bundles.as_bytes()).unwrap();
        let expected = h.finalize();

        let sighash = v7_signature_hash(&tx, &signable_input, &txid_parts, None);
        assert_eq!(
            sighash.as_bytes(),
            expected.as_bytes(),
            "signature digest mismatch for {hash_type:?}"
        );
    }

    // Changing only the transparent and fee deltas must change the signature
    // for every hash type, because S.2 commits to the complete T.2 digest.
    let tx_changed = make_tx(-2000, 2000);
    let changed_parts = tx_changed.digest_v7();
    let changed_bundle = tx_changed.transparent_bundle().unwrap();
    for hash_type in [
        SighashType::ALL,
        SighashType::NONE,
        SighashType::SINGLE,
        SighashType::ALL_ANYONECANPAY,
        SighashType::NONE_ANYONECANPAY,
        SighashType::SINGLE_ANYONECANPAY,
    ] {
        let input = |bundle| {
            SignableInput::Transparent(
                ::transparent::sighash::SignableInput::from_parts(
                    bundle,
                    hash_type,
                    0,
                    &script,
                    &script,
                    Zatoshis::from_u64(1000).unwrap(),
                )
                .unwrap(),
            )
        };
        let original = v7_signature_hash(&tx, &input(bundle), &txid_parts, None);
        let changed = v7_signature_hash(&tx_changed, &input(changed_bundle), &changed_parts, None);
        assert_ne!(
            original.as_bytes(),
            changed.as_bytes(),
            "{hash_type:?} must commit to transparent and fee deltas"
        );
    }
}

/// A v7 digest tree built by `TxIdDigester` lacks the value pool deltas
/// digest, so it cannot produce a v7 transaction identifier. The public
/// `to_txid` path must return `None` rather than substituting an empty-map
/// digest.
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_to_txid_rejects_incomplete_digest_tree() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    let mut vp = zip248::ValuePoolDeltas::empty();
    vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();

    let incomplete_tx = TransactionData::<TestUnauthorized>::from_parts_with_value_pool_deltas(
        TxVersion::V7,
        BranchId::Nu8,
        0,
        BlockHeight::from(100u32),
        vp.clone(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let incomplete = incomplete_tx.digest(TxIdDigester);
    assert!(incomplete.value_pool_deltas_digest.is_none());
    assert_eq!(
        super::txid::to_txid(TxVersion::V7, BranchId::Nu8, &incomplete),
        None
    );

    let complete_tx = TransactionData::<Authorized>::from_parts_with_value_pool_deltas(
        TxVersion::V7,
        BranchId::Nu8,
        0,
        BlockHeight::from(100u32),
        vp,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let complete = complete_tx.digest_v7();
    assert!(complete.value_pool_deltas_digest.is_some());
    let txid = super::txid::to_txid(TxVersion::V7, BranchId::Nu8, &complete).unwrap();
    assert_eq!(txid, complete_tx.freeze().unwrap().txid());
}

#[cfg(test)]
mod zip248_tests {
    use super::super::zip248;
    use alloc::vec;
    use alloc::vec::Vec;
    use zcash_protocol::value::{ZatBalance, Zatoshis};

    #[test]
    fn value_pool_deltas_write_read_roundtrip() {
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_sapling(ZatBalance::from_i64(100_000).unwrap())
            .unwrap();
        vp.set_orchard(ZatBalance::from_i64(-50_000).unwrap())
            .unwrap();
        vp.set_fee(Zatoshis::from_u64(1_000).unwrap()).unwrap();

        let entries = vp.to_wire_entries();
        let mut buf = Vec::new();
        zcash_encoding::CompactSize::write(&mut buf, entries.len()).unwrap();
        for entry in &entries {
            entry.write(&mut buf).unwrap();
        }

        let mut cursor = &buf[..];
        let n = zcash_encoding::CompactSize::read_t::<_, usize>(&mut cursor).unwrap();
        let mut vp2 = zip248::ValuePoolDeltas::empty();
        for _ in 0..n {
            let entry = zip248::ValuePoolDeltaEntry::read(&mut cursor).unwrap();
            let key = zip248::ValuePoolDeltaKey::from_parts(
                entry.bundle_type(),
                entry.asset_class(),
                entry.asset_uuid().copied().unwrap_or([0u8; 64]),
            )
            .unwrap();
            vp2.insert(key, entry.bundle_variant(), entry.value())
                .unwrap();
        }

        assert_eq!(
            vp2.sapling_value(),
            Some(ZatBalance::from_i64(100_000).unwrap())
        );
        assert_eq!(
            vp2.orchard_value(),
            Some(ZatBalance::from_i64(-50_000).unwrap())
        );
        assert_eq!(vp2.fee(), Some(Zatoshis::from_u64(1_000).unwrap()));
    }

    #[test]
    fn bundle_data_framing_empty() {
        let bt = zip248::BundleType::TRANSPARENT;
        let bv = zip248::BundleVariant::DEFAULT;
        let data: Vec<u8> = vec![];

        let mut buf = Vec::new();
        zip248::write_bundle_data_framing(&mut buf, bt.to_u64(), bv.to_u64(), &data).unwrap();

        let ((parsed_bt, parsed_bv), parsed_data) =
            zip248::read_bundle_data_framing(&buf[..]).unwrap();
        assert_eq!(parsed_bt, bt.to_u64());
        assert_eq!(parsed_bv, bv.to_u64());
        assert!(parsed_data.is_empty());
    }

    /// Verifies that a v7 transaction with an unknown bundle type can be
    /// parsed and re-serialized at the byte layer (ZIP 248 forward
    /// compatibility), and that the typed compatibility path rejects it rather
    /// than inventing a digest.
    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn unknown_bundle_roundtrip() {
        use super::super::{
            Transaction, TxVersion,
            bytes::{
                BundleType, BundleVariant, OpaqueBundleBytes, TransactionBodyBytes,
                TransactionBytes, V7BundleBytes, V7TransactionBodyBytes,
            },
        };
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(42),
            BundleVariant::from_u64(0),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            None,
        )
        .unwrap();
        let body = V7TransactionBodyBytes::from_parts(vec![], vec![V7BundleBytes::Unknown(opaque)])
            .unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(BranchId::Nu8),
            0,
            BlockHeight::from_u32(100),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();

        let mut buf = Vec::new();
        tx.write(&mut buf).unwrap();

        // The byte layer parses and re-serializes the unknown bundle.
        let tx2 = TransactionBytes::read(&buf[..]).unwrap();
        let body = tx2.body().as_v7().unwrap();
        let unknowns: Vec<_> = body.opaque_bundles().collect();
        assert_eq!(unknowns.len(), 1);
        assert_eq!(unknowns[0].bundle_type().to_u64(), 42);
        assert_eq!(unknowns[0].effects(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(unknowns[0].auth().is_none());

        let mut buf2 = Vec::new();
        tx2.write(&mut buf2).unwrap();
        assert_eq!(buf, buf2);

        // The typed compatibility path cannot represent the unknown bundle, so
        // it rejects the transaction instead of inventing a digest.
        assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
    }

    // -- Consensus rule tests --------------------------------------------------

    #[cfg(zcash_unstable = "nu8")]
    mod consensus_rules {
        use super::super::super::{
            Authorized, TransactionData, TxVersion, V7ConsensusError, ZatBalance, zip248,
        };
        use zcash_protocol::consensus::{BlockHeight, BranchId};
        use zcash_protocol::value::Zatoshis;

        fn make_v7(vp: zip248::ValuePoolDeltas) -> TransactionData<Authorized> {
            TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                vp,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        }

        /// A transparent bundle with one input and one output, satisfying both
        /// the input- and output-side conditions.
        fn transparent_bundle() -> ::transparent::bundle::Bundle<::transparent::bundle::Authorized>
        {
            use ::transparent::{
                address::Script,
                bundle::{Authorized, Bundle, OutPoint, TxIn, TxOut},
            };

            Bundle {
                vin: vec![TxIn::from_parts(
                    OutPoint::new([1; 32], 2),
                    Script::default(),
                    3,
                )],
                vout: vec![TxOut::new(
                    Zatoshis::from_u64(1000).unwrap(),
                    Script::default(),
                )],
                authorization: Authorized,
            }
        }

        /// A transparent bundle with outputs but no inputs, as a coinbase
        /// transaction may carry.
        fn transparent_outputs_only()
        -> ::transparent::bundle::Bundle<::transparent::bundle::Authorized> {
            use ::transparent::{
                address::Script,
                bundle::{Authorized, Bundle, TxOut},
            };

            Bundle {
                vin: vec![],
                vout: vec![TxOut::new(
                    Zatoshis::from_u64(1000).unwrap(),
                    Script::default(),
                )],
                authorization: Authorized,
            }
        }

        fn make_v7_with_transparent(
            vp: zip248::ValuePoolDeltas,
            transparent: ::transparent::bundle::Bundle<::transparent::bundle::Authorized>,
        ) -> TransactionData<Authorized> {
            TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                vp,
                Some(transparent),
                None,
                None,
                None,
                None,
                None,
            )
        }

        #[test]
        fn fee_asset_class_must_be_zec() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Insert a fee entry with non-ZEC asset class via the raw API.
            vp.insert(
                zip248::ValuePoolDeltaKey::from_parts(
                    zip248::BundleType::FEE,
                    zip248::ASSET_CLASS_OTHER,
                    [0x42; 64],
                )
                .unwrap(),
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(-1000).unwrap(),
            )
            .unwrap();
            let tx = make_v7(vp);
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::FeeAssetClassNotZec {
                    asset_class: zip248::ASSET_CLASS_OTHER
                }),
            );
        }

        /// Builds a coinbase bundle paying out `subsidy` zatoshis with
        /// `lockbox` of it deposited into the lockbox.
        fn coinbase_bundle(subsidy: u64, lockbox: u64) -> zip248::CoinbaseBundle {
            zip248::CoinbaseBundle::from_parts(
                BlockHeight::from(100u32),
                Zatoshis::from_u64(subsidy).unwrap(),
                Zatoshis::from_u64(lockbox).unwrap(),
                vec![],
            )
            .expect("valid coinbase bundle")
        }

        fn make_v7_coinbase(
            vp: zip248::ValuePoolDeltas,
            coinbase: zip248::CoinbaseBundle,
        ) -> TransactionData<Authorized> {
            TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                vp,
                Some(transparent_outputs_only()),
                None,
                None,
                None,
                None,
                Some(coinbase),
            )
        }

        #[test]
        fn coinbase_fee_delta_must_be_nonnegative() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap(); // stored as -1000
            let tx = make_v7_coinbase(vp, coinbase_bundle(0, 0));
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::CoinbaseFeeDeltaNegative {
                    value: ZatBalance::from_i64(-1000).unwrap(),
                }),
            );
        }

        #[test]
        fn coinbase_vp_delta_must_equal_subsidy_less_lockbox() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // The bundle issues 3 and locks 1, so the delta must be 2.
            vp.set_coinbase(ZatBalance::from_i64(3).unwrap()).unwrap();
            vp.set_transparent(ZatBalance::from_i64(-3).unwrap())
                .unwrap();
            let tx = make_v7_coinbase(vp, coinbase_bundle(3, 1));
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::CoinbaseValueDeltaMismatch {
                    expected: 2,
                    actual: ZatBalance::from_i64(3).unwrap(),
                }),
            );
        }

        #[test]
        fn balanced_coinbase_passes() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Issue 3, lock 1: the bundle contributes 2 to the transparent
            // transaction value pool, and the transparent outputs consume it.
            vp.set_coinbase(ZatBalance::from_i64(2).unwrap()).unwrap();
            vp.set_transparent(ZatBalance::from_i64(-2).unwrap())
                .unwrap();
            let tx = make_v7_coinbase(vp, coinbase_bundle(3, 1));
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }

        #[test]
        fn coinbase_bundle_rejects_lockbox_above_subsidy() {
            assert!(
                zip248::CoinbaseBundle::from_parts(
                    BlockHeight::from(100u32),
                    Zatoshis::from_u64(2).unwrap(),
                    Zatoshis::from_u64(3).unwrap(),
                    vec![],
                )
                .is_none()
            );
        }

        #[test]
        fn coinbase_bundle_rejects_oversized_coinbase_data() {
            assert!(
                zip248::CoinbaseBundle::from_parts(
                    BlockHeight::from(100u32),
                    Zatoshis::ZERO,
                    Zatoshis::ZERO,
                    vec![0u8; zip248::MAX_COINBASE_DATA_LEN + 1],
                )
                .is_none()
            );
        }

        #[test]
        fn coinbase_bundle_rejects_out_of_range_block_height() {
            for height in [BlockHeight::from(0u32), BlockHeight::from(500_000_000u32)] {
                assert!(
                    zip248::CoinbaseBundle::from_parts(
                        height,
                        Zatoshis::ZERO,
                        Zatoshis::ZERO,
                        vec![],
                    )
                    .is_none()
                );
            }
        }

        #[test]
        fn coinbase_bundle_roundtrips() {
            let bundle = zip248::CoinbaseBundle::from_parts(
                BlockHeight::from(123_456u32),
                Zatoshis::from_u64(312_500_000).unwrap(),
                Zatoshis::from_u64(31_250_000).unwrap(),
                b"miner data".to_vec(),
            )
            .expect("valid coinbase bundle");

            let mut buf = alloc::vec::Vec::new();
            bundle.write(&mut buf).unwrap();
            assert_eq!(zip248::CoinbaseBundle::read(&buf[..]).unwrap(), bundle);
        }

        #[test]
        fn non_coinbase_fee_delta_must_be_nonpositive() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Manually insert a positive fee delta (simulating a coinbase-style
            // fee entry in a non-coinbase transaction).
            vp.insert(
                zip248::ValuePoolDeltaKey::zec(zip248::BundleType::FEE),
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(1000).unwrap(),
            )
            .unwrap();
            let tx = make_v7(vp);
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::NonCoinbaseFeeDeltaPositive {
                    value: ZatBalance::from_i64(1000).unwrap(),
                }),
            );
        }

        #[test]
        fn vp_deltas_must_balance() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // The transparent bundle adds 100k to the pool but nothing
            // subtracts it.
            vp.set_transparent(zcash_protocol::value::ZatBalance::from_i64(100_000).unwrap())
                .unwrap();
            let tx = make_v7_with_transparent(vp, transparent_bundle());
            let err = tx.check_v7_consensus_rules().unwrap_err();
            assert!(matches!(err, V7ConsensusError::ValueImbalance { .. }));
        }

        #[test]
        fn balanced_non_coinbase_passes() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap(); // -1000
            vp.set_transparent(zcash_protocol::value::ZatBalance::from_i64(1000).unwrap())
                .unwrap(); // +1000
            let tx = make_v7_with_transparent(vp, transparent_bundle());
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }

        /// A non-ZEC asset entry that does not balance per asset is rejected by
        /// conservation, not by a ZEC-only restriction.
        #[test]
        fn unbalanced_non_zec_delta_is_rejected_by_conservation() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.insert(
                zip248::ValuePoolDeltaKey::from_parts(
                    zip248::BundleType::TRANSPARENT,
                    zip248::ASSET_CLASS_OTHER,
                    [0x42; 64],
                )
                .unwrap(),
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(-1000).unwrap(),
            )
            .unwrap();
            let tx = make_v7_with_transparent(vp, transparent_bundle());
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::ValueImbalance {
                    bundle_type_for_asset: zip248::BundleType::TRANSPARENT.to_u64(),
                    asset_class: zip248::ASSET_CLASS_OTHER,
                    sum: -1000,
                }),
            );
        }

        /// Non-ZEC entries in bundle types other than fee and coinbase are
        /// accepted when they balance per asset.
        #[test]
        fn balanced_non_zec_delta_passes() {
            let uuid = [0x42; 64];
            let mut vp = zip248::ValuePoolDeltas::empty();
            for (bundle_type, value) in [
                (zip248::BundleType::TRANSPARENT, -1000),
                (zip248::BundleType::ZIP233_NSM, 1000),
            ] {
                vp.insert(
                    zip248::ValuePoolDeltaKey::from_parts(
                        bundle_type,
                        zip248::ASSET_CLASS_OTHER,
                        uuid,
                    )
                    .unwrap(),
                    zip248::BundleVariant::DEFAULT,
                    ZatBalance::from_i64(value).unwrap(),
                )
                .unwrap();
            }
            let tx = make_v7_with_transparent(vp, transparent_bundle());
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }
    }

    // -- Parsing rule rejection tests ------------------------------------------

    #[cfg(zcash_unstable = "nu8")]
    mod parsing_rules {
        use super::super::super::{Transaction, zip248};
        use alloc::vec::Vec;
        use zcash_encoding::CompactSize;
        use zcash_protocol::consensus::BranchId;
        use zcash_protocol::constants::{MAX_BLOCK_BYTES, V7_TX_VERSION, V7_VERSION_GROUP_ID};

        /// Builds a minimal v7 transaction header (20 bytes).
        fn v7_header(branch_id: BranchId) -> Vec<u8> {
            let mut buf = Vec::new();
            // header: version 7 with overwintered bit
            buf.extend_from_slice(&(V7_TX_VERSION | (1 << 31)).to_le_bytes());
            buf.extend_from_slice(&V7_VERSION_GROUP_ID.to_le_bytes());
            buf.extend_from_slice(&u32::from(branch_id).to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // lock_time
            buf.extend_from_slice(&100u32.to_le_bytes()); // expiry_height
            buf
        }

        /// Appends empty VP deltas + empty effect/auth maps.
        fn append_empty_body(buf: &mut Vec<u8>) {
            CompactSize::write(&mut *buf, 0).unwrap(); // nValuePoolDeltas
            CompactSize::write(&mut *buf, 0).unwrap(); // nEffectBundles
            CompactSize::write(&mut *buf, 0).unwrap(); // nAuthBundles
        }

        /// The effecting data of a coinbase bundle at height 100 that issues
        /// nothing: `blockHeight || blockSubsidy || lockboxValue ||
        /// coinbaseDataLen`.
        fn coinbase_effects() -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&100u32.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        }

        /// Writes a VP delta entry directly to bytes.
        fn write_vp_entry(buf: &mut Vec<u8>, bundle_type: u64, variant: u64, value: i64) {
            CompactSize::write(&mut *buf, bundle_type as usize).unwrap();
            CompactSize::write(&mut *buf, variant as usize).unwrap();
            buf.push(zip248::ASSET_CLASS_ZEC);
            buf.extend_from_slice(&value.to_le_bytes());
        }

        /// Writes an `mEffectBundles`/`mAuthBundles` TLV entry.
        fn write_bundle_entry(
            buf: &mut Vec<u8>,
            bundle_type: zip248::BundleType,
            variant: zip248::BundleVariant,
            data: &[u8],
        ) {
            zip248::write_bundle_data_framing(
                &mut *buf,
                bundle_type.to_u64(),
                variant.to_u64(),
                data,
            )
            .unwrap();
        }

        /// A v7 transaction carrying a single `mEffectBundles` entry.
        fn v7_with_effect_bundle(
            bundle_type: zip248::BundleType,
            variant: zip248::BundleVariant,
            data: &[u8],
        ) -> Vec<u8> {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut buf, 0).unwrap(); // nValuePoolDeltas
            CompactSize::write(&mut buf, 1).unwrap(); // nEffectBundles
            write_bundle_entry(&mut buf, bundle_type, variant, data);
            CompactSize::write(&mut buf, 0).unwrap(); // nAuthBundles
            buf
        }

        /// A transparent bundle holding only outputs has no authorizing input
        /// data, but ZIP 248 permits a present-but-empty `mAuthBundles` entry
        /// and it is a distinct encoding from an absent one. The byte layer
        /// preserves the distinction; typed conversion rejects the present
        /// case because its bundle type cannot represent map presence.
        #[test]
        fn transparent_outputs_only_preserve_auth_entry_presence() {
            // nIn = 0, then one 1000-zatoshi output with an empty script.
            let mut effects = Vec::new();
            CompactSize::write(&mut effects, 0).unwrap();
            CompactSize::write(&mut effects, 1).unwrap();
            effects.extend_from_slice(&1_000u64.to_le_bytes());
            CompactSize::write(&mut effects, 0).unwrap();

            let transparent = zip248::BundleType::TRANSPARENT;
            let variant = zip248::BundleVariant::DEFAULT;
            let buf = v7_with_effect_bundle(transparent, variant, &effects);

            let tx = Transaction::read(&buf[..], BranchId::Nu8).unwrap();
            assert!(tx.transparent_bundle().is_some());
            let mut reserialized = Vec::new();
            tx.write(&mut reserialized).unwrap();
            assert_eq!(reserialized, buf);

            // The same transaction with a present-but-empty auth entry parses
            // and re-serializes exactly at the byte layer.
            let mut with_empty_auth = v7_header(BranchId::Nu8);
            CompactSize::write(&mut with_empty_auth, 0).unwrap(); // nValuePoolDeltas
            CompactSize::write(&mut with_empty_auth, 1).unwrap(); // nEffectBundles
            write_bundle_entry(&mut with_empty_auth, transparent, variant, &effects);
            CompactSize::write(&mut with_empty_auth, 1).unwrap(); // nAuthBundles
            write_bundle_entry(&mut with_empty_auth, transparent, variant, &[]);

            let bytes =
                crate::transaction::bytes::TransactionBytes::read(&with_empty_auth[..]).unwrap();
            assert!(
                bytes
                    .body()
                    .as_v7()
                    .unwrap()
                    .transparent()
                    .unwrap()
                    .auth()
                    .is_some()
            );
            let mut byte_reserialized = Vec::new();
            bytes.write(&mut byte_reserialized).unwrap();
            assert_eq!(byte_reserialized, with_empty_auth);

            // The typed representation cannot retain the present empty entry.
            assert!(Transaction::read(&with_empty_auth[..], BranchId::Nu8).is_err());
        }

        /// An empty transparent effecting payload is a valid byte encoding and
        /// is preserved by the byte layer, but the typed representation has no
        /// way to retain its map presence, so typed conversion rejects it.
        #[test]
        fn rejects_empty_transparent_effect_bundle() {
            let mut effects = Vec::new();
            CompactSize::write(&mut effects, 0).unwrap(); // nIn
            CompactSize::write(&mut effects, 0).unwrap(); // nOut
            let buf = v7_with_effect_bundle(
                zip248::BundleType::TRANSPARENT,
                zip248::BundleVariant::DEFAULT,
                &effects,
            );

            let err = Transaction::read(&buf[..], BranchId::Nu8).unwrap_err();
            let msg = alloc::format!("{err:?}");
            assert!(
                msg.contains("empty transparent bundle"),
                "unexpected error: {msg}"
            );
        }

        /// A transparent input count must not size an allocation before the
        /// inputs it claims have been read.
        #[test]
        fn rejects_transparent_input_count_exceeding_the_data() {
            let mut effects = Vec::new();
            CompactSize::write(&mut effects, 1 << 20).unwrap(); // nIn, with no inputs following
            let buf = v7_with_effect_bundle(
                zip248::BundleType::TRANSPARENT,
                zip248::BundleVariant::DEFAULT,
                &effects,
            );

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        /// A bundle payload longer than a block cannot be part of a valid
        /// transaction, and must be rejected before it is allocated.
        #[test]
        fn rejects_bundle_data_longer_than_a_block() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut buf, 0).unwrap(); // nValuePoolDeltas
            CompactSize::write(&mut buf, 1).unwrap(); // nEffectBundles
            CompactSize::write(&mut buf, zip248::BundleType::TRANSPARENT.to_u64() as usize)
                .unwrap();
            CompactSize::write(&mut buf, 0).unwrap(); // bundleVariant
            CompactSize::write(&mut buf, MAX_BLOCK_BYTES + 1).unwrap(); // claimed length

            let err = Transaction::read(&buf[..], BranchId::Nu8).unwrap_err();
            let msg = alloc::format!("{err:?}");
            assert!(
                msg.contains("maximum block size"),
                "unexpected error: {msg}"
            );
        }

        /// A bundleType this implementation knows may carry a bundleVariant it
        /// does not. Reinterpreting it as the default variant would change the
        /// bytes it re-serializes to, so the byte layer preserves it opaquely.
        /// The typed compatibility path cannot resolve its digest, so it
        /// rejects the transaction.
        #[test]
        fn preserves_unknown_variant_of_known_bundle_type() {
            use crate::transaction::bytes::{TransactionBytes, V7BundleBytes};

            let opaque = [0xAAu8; 8];
            let unknown_variant =
                zip248::BundleVariant::from_u64(zip248::BundleVariant::DEFAULT.to_u64() + 1);
            let buf = v7_with_effect_bundle(zip248::BundleType::SAPLING, unknown_variant, &opaque);

            let tx = TransactionBytes::read(&buf[..]).unwrap();
            let body = tx.body().as_v7().unwrap();
            assert!(matches!(
                body.bundles()[0],
                V7BundleBytes::KnownTypeUnknownVariant(_)
            ));

            let mut reserialized = Vec::new();
            tx.write(&mut reserialized).unwrap();
            assert_eq!(reserialized, buf);

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_out_of_order_vp_deltas() {
            let mut buf = v7_header(BranchId::Nu8);
            // 2 VP delta entries: Orchard (3) then Sapling (2) — wrong order.
            CompactSize::write(&mut *buf, 2).unwrap();
            write_vp_entry(&mut buf, 3, 0, 100_000); // Orchard first (wrong)
            write_vp_entry(&mut buf, 2, 0, -100_000); // Sapling second
            CompactSize::write(&mut *buf, 0).unwrap(); // nEffectBundles
            CompactSize::write(&mut *buf, 0).unwrap(); // nAuthBundles

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_duplicate_vp_deltas() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 2).unwrap();
            write_vp_entry(&mut buf, 2, 0, 50_000);
            write_vp_entry(&mut buf, 2, 0, 50_000);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_coinbase_in_auth_bundles() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 0).unwrap(); // no VP deltas
            // A coinbase effect bundle, and an auth bundle for it: the
            // registry marks the coinbase mAuthBundles column as prohibited.
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 1, 0, &coinbase_effects()).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 1, 0, &[0xAA]).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_oversized_coinbase_data() {
            let mut effects = coinbase_effects();
            // Replace the empty `coinbaseData` with one byte over the limit.
            effects.pop();
            CompactSize::write(&mut effects, zip248::MAX_COINBASE_DATA_LEN + 1).unwrap();
            effects.extend_from_slice(&[0u8; zip248::MAX_COINBASE_DATA_LEN + 1]);

            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 1, 0, &effects).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_zero_vp_delta_value() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 1).unwrap();
            write_vp_entry(&mut buf, 2, 0, 0);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_fee_in_effect_bundles() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            // bundleType 5 is the fee bundle, which is value-only.
            zip248::write_bundle_data_framing(&mut buf, 5, 0, &[0xAA]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_mismatched_variant_across_maps() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 1).unwrap();
            write_vp_entry(&mut buf, 2, 0, 100_000);
            // Effect bundle says bundleType 2 variant 1 — mismatch.
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 2, 1, &[]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_auth_without_effect() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 2, 0, &[0xBB]).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn accepts_empty_v7_transaction() {
            let mut buf = v7_header(BranchId::Nu8);
            append_empty_body(&mut buf);
            let tx = Transaction::read(&buf[..], BranchId::Nu8).unwrap();
            assert!(tx.transparent_bundle().is_none());
            assert!(tx.sapling_bundle().is_none());
            assert!(tx.orchard_bundle().is_none());
        }

        #[test]
        fn rejects_out_of_order_effect_bundles() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 0).unwrap(); // no VP deltas
            // Effect bundles: Orchard (3) before Transparent (0) — wrong order.
            CompactSize::write(&mut *buf, 2).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 3, 0, &[0xAA]).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 0, 0, &[0xBB]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth
            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }
    }

    // -- Whole-transaction roundtrips for the v7 bundle types ------------------

    #[cfg(zcash_unstable = "nu8")]
    mod bundle_roundtrips {
        use proptest::prelude::*;

        use super::super::super::{
            Authorized, Transaction, TransactionData, TxVersion,
            components::orchard::testing::arb_bundle_for_version, zip248,
        };
        use alloc::vec::Vec;
        use zcash_protocol::{
            consensus::{BlockHeight, BranchId},
            value::Zatoshis,
        };

        fn roundtrip(tx: &Transaction) -> Transaction {
            let mut buf = Vec::new();
            tx.write(&mut buf)
                .expect("v7 transactions are serializable");
            Transaction::read(&buf[..], BranchId::Nu8).expect("the encoding just written parses")
        }

        #[test]
        fn coinbase_bundle_roundtrips_through_a_transaction() {
            let coinbase = zip248::CoinbaseBundle::from_parts(
                BlockHeight::from(1_500_000u32),
                Zatoshis::from_u64(156_250_000).unwrap(),
                Zatoshis::from_u64(18_750_000).unwrap(),
                b"a miner was here".to_vec(),
            )
            .expect("valid coinbase bundle");

            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_coinbase(coinbase.value_pool_delta()).unwrap();
            // Something has to consume what the coinbase bundle contributes;
            // a transparent output stands in for the outputs that would.
            vp.set_transparent(-coinbase.value_pool_delta()).unwrap();

            let transparent = {
                use ::transparent::{
                    address::Script,
                    bundle::{Authorized as TransparentAuthorized, Bundle, TxOut},
                };

                Bundle {
                    vin: vec![],
                    vout: vec![TxOut::new(
                        Zatoshis::from_u64(1_000).unwrap(),
                        Script::default(),
                    )],
                    authorization: TransparentAuthorized,
                }
            };

            let tx = TransactionData::<Authorized>::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(1_500_100),
                vp,
                Some(transparent),
                None,
                None,
                None,
                None,
                Some(coinbase.clone()),
            )
            .freeze()
            .expect("v7 transaction data can be frozen");

            let parsed = roundtrip(&tx);
            assert_eq!(parsed.coinbase_bundle(), Some(&coinbase));
            assert_eq!(parsed.txid(), tx.txid());
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }

        proptest! {
            // Generating Orchard bundles is expensive, and this property does
            // not depend on the bundle's shape, so a handful of cases is
            // plenty.
            #![proptest_config(ProptestConfig::with_cases(4))]

            /// An Orchard protocol bundle carried as the Ironwood bundle
            /// survives a serialization roundtrip, and is digested
            /// differently from the same bundle carried as the Orchard
            /// bundle: the two act on different pools.
            #[test]
            fn ironwood_bundle_roundtrips_and_digests_differently(
                bundle in arb_bundle_for_version(TxVersion::V7).prop_filter(
                    "an Ironwood bundle is only interesting when present",
                    |b| b.is_some(),
                ),
            ) {
                let bundle = bundle.expect("filtered to Some");
                let value_balance = *bundle.value_balance();

                let build = |as_ironwood: bool| {
                    let mut vp = zip248::ValuePoolDeltas::empty();
                    let (orchard, ironwood) = if as_ironwood {
                        vp.set_ironwood(value_balance).unwrap();
                        (None, Some(bundle.clone()))
                    } else {
                        vp.set_orchard(value_balance).unwrap();
                        (Some(bundle.clone()), None)
                    };
                    // Balance the transaction so that it satisfies the
                    // value pool delta rule.
                    vp.set_transparent(-value_balance).unwrap();

                    TransactionData::<Authorized>::from_parts_with_value_pool_deltas(
                        TxVersion::V7,
                        BranchId::Nu8,
                        0,
                        BlockHeight::from_u32(100),
                        vp,
                        None,
                        None,
                        None,
                        orchard,
                        ironwood,
                        None,
                    )
                    .freeze()
                    .expect("v7 transaction data can be frozen")
                };

                let as_ironwood = build(true);
                let parsed = roundtrip(&as_ironwood);
                prop_assert_eq!(parsed.txid(), as_ironwood.txid());
                prop_assert!(parsed.ironwood_bundle().is_some());
                prop_assert!(parsed.orchard_bundle().is_none());
                let (parsed_auth, ironwood_auth) =
                    (parsed.auth_commitment(), as_ironwood.auth_commitment());
                prop_assert_eq!(parsed_auth.as_bytes(), ironwood_auth.as_bytes());

                let as_orchard = build(false);
                prop_assert_ne!(as_ironwood.txid(), as_orchard.txid());
                let orchard_auth = as_orchard.auth_commitment();
                prop_assert_ne!(ironwood_auth.as_bytes(), orchard_auth.as_bytes());
            }
        }
    }

    // -- Wire order and roundtrip tests ----------------------------------------

    #[cfg(zcash_unstable = "nu8")]
    mod wire_order {
        use super::super::super::zip248;
        use alloc::vec::Vec;
        use zcash_protocol::value::{ZatBalance, Zatoshis};

        #[test]
        fn to_wire_entries_canonical_order_with_unknown() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Known: Orchard (3), Fee (5)
            vp.set_orchard(ZatBalance::from_i64(50_000).unwrap())
                .unwrap();
            vp.set_fee(Zatoshis::from_u64(1_000).unwrap()).unwrap();
            // Unknown: bundleType 8 (sorts after all known types)
            vp.insert(
                zip248::ValuePoolDeltaKey::from_parts(
                    zip248::BundleType::from_u64(8),
                    0,
                    [0u8; 64],
                )
                .unwrap(),
                zip248::BundleVariant::from_u64(0),
                ZatBalance::from_i64(99_000).unwrap(),
            )
            .unwrap();

            let entries = vp.to_wire_entries();
            let types: Vec<u64> = entries.iter().map(|e| e.bundle_type().to_u64()).collect();
            // Orchard=3, Fee=5, Unknown=8 — strictly increasing.
            assert_eq!(types, vec![3, 5, 8]);
        }
    }

    // -- Sighash version info error tests --------------------------------------

    #[cfg(zcash_unstable = "nu8")]
    mod sighash_info {
        use super::super::super::zip248;

        #[test]
        fn rejects_wrong_sighash_version() {
            // sighashInfo with version byte 0x01 instead of 0x00.
            let data: &[u8] = &[0x01, 0x01]; // compactSize(1), version=1
            let mut cursor = data;
            let result = zip248::consume_v7_sighash_v0_info(&mut cursor, "test");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_wrong_sighash_length() {
            // sighashInfo with length 2 instead of 1.
            let data: &[u8] = &[0x02, 0x00, 0x00]; // compactSize(2), two bytes
            let mut cursor = data;
            let result = zip248::consume_v7_sighash_v0_info(&mut cursor, "test");
            assert!(result.is_err());
        }
    }

    // -- Full transaction-local validation -------------------------------------

    #[cfg(zcash_unstable = "nu8")]
    mod v7_validation {
        use super::super::super::{
            Transaction, TransactionBytes, V7BundleMap, V7ConsensusError, V7ValidationError,
            bytes::{TransactionBodyBytes, V5TransactionBodyBytes},
            zip248,
        };
        use alloc::vec;
        use alloc::vec::Vec;
        use proptest::prelude::*;
        use zcash_encoding::CompactSize;
        #[cfg(not(zcash_unstable = "zip233"))]
        use zcash_protocol::value::MAX_MONEY;
        use zcash_protocol::{
            consensus::{BlockHeight, BranchId},
            constants::{V7_TX_VERSION, V7_VERSION_GROUP_ID},
            value::{ZatBalance, Zatoshis},
        };

        fn v7_header(branch_id: BranchId) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(V7_TX_VERSION | (1 << 31)).to_le_bytes());
            buf.extend_from_slice(&V7_VERSION_GROUP_ID.to_le_bytes());
            buf.extend_from_slice(&u32::from(branch_id).to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&100u32.to_le_bytes());
            buf
        }

        fn vp_entry(
            bundle_type: u64,
            variant: u64,
            asset_class: u8,
            uuid: Option<[u8; 64]>,
            value: i64,
        ) -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, bundle_type as usize).unwrap();
            CompactSize::write(&mut buf, variant as usize).unwrap();
            buf.push(asset_class);
            if let Some(uuid) = uuid {
                buf.extend_from_slice(&uuid);
            }
            buf.extend_from_slice(&value.to_le_bytes());
            buf
        }

        fn wire_tx(
            branch_id: BranchId,
            vp: &[Vec<u8>],
            effects: &[(u64, u64, Vec<u8>)],
            auth: &[(u64, u64, Vec<u8>)],
        ) -> Vec<u8> {
            let mut buf = v7_header(branch_id);
            CompactSize::write(&mut buf, vp.len()).unwrap();
            for entry in vp {
                buf.extend_from_slice(entry);
            }
            CompactSize::write(&mut buf, effects.len()).unwrap();
            for (bundle_type, variant, data) in effects {
                zip248::write_bundle_data_framing(&mut buf, *bundle_type, *variant, data).unwrap();
            }
            CompactSize::write(&mut buf, auth.len()).unwrap();
            for (bundle_type, variant, data) in auth {
                zip248::write_bundle_data_framing(&mut buf, *bundle_type, *variant, data).unwrap();
            }
            buf
        }

        fn validate(bytes: &[u8]) -> Result<Transaction, V7ValidationError> {
            let tx = TransactionBytes::read(bytes).expect("fixture must be well-formed");
            tx.validate_v7()
        }

        fn transparent_outputs_only_effects() -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, 0).unwrap();
            CompactSize::write(&mut buf, 1).unwrap();
            buf.extend_from_slice(&1000i64.to_le_bytes());
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        }

        fn transparent_input_effects(outputs: bool) -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, 1).unwrap();
            buf.extend_from_slice(&[1u8; 32]);
            buf.extend_from_slice(&2u32.to_le_bytes());
            buf.extend_from_slice(&3u32.to_le_bytes());
            CompactSize::write(&mut buf, usize::from(outputs)).unwrap();
            if outputs {
                buf.extend_from_slice(&1000i64.to_le_bytes());
                CompactSize::write(&mut buf, 0).unwrap();
            }
            buf
        }

        fn transparent_auth(sighash_version: u8) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&[0x01, sighash_version]);
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        }

        fn coinbase_effects(subsidy: u64, lockbox: u64) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&100u32.to_le_bytes());
            buf.extend_from_slice(&subsidy.to_le_bytes());
            buf.extend_from_slice(&lockbox.to_le_bytes());
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        }

        fn sapling_effects() -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, 1).unwrap();
            buf.extend_from_slice(&[0u8; 96]);
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        }

        fn sapling_auth() -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&[0u8; 32]);
            buf.extend_from_slice(&[0u8; 192]);
            buf.extend_from_slice(&[0x01, 0x00]);
            buf.extend_from_slice(&[0u8; 64]);
            buf.extend_from_slice(&[0x01, 0x00]);
            buf.extend_from_slice(&[0u8; 64]);
            buf
        }

        fn orchard_effects(flags: u8) -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, 1).unwrap();
            buf.extend_from_slice(&[0u8; 820]);
            buf.push(flags);
            buf
        }

        fn orchard_auth() -> Vec<u8> {
            // ZIP 248: 2720 + 2272 * nActionsOrchard, for the single action
            // encoded by `orchard_effects`.
            const PROOF_LEN: usize = 2720 + 2272;
            let mut buf = Vec::new();
            buf.extend_from_slice(&[0u8; 32]);
            CompactSize::write(&mut buf, PROOF_LEN).unwrap();
            buf.resize(buf.len() + PROOF_LEN, 0);
            buf.extend_from_slice(&[0x01, 0x00]);
            buf.extend_from_slice(&[0u8; 64]);
            buf.extend_from_slice(&[0x01, 0x00]);
            buf.extend_from_slice(&[0u8; 64]);
            buf
        }

        fn transparent_bundle() -> ::transparent::bundle::Bundle<::transparent::bundle::Authorized>
        {
            use ::transparent::{
                address::Script,
                bundle::{Authorized, Bundle, OutPoint, TxIn, TxOut},
            };

            Bundle {
                vin: vec![TxIn::from_parts(
                    OutPoint::new([1; 32], 2),
                    Script::default(),
                    3,
                )],
                vout: vec![TxOut::new(
                    Zatoshis::from_u64(1000).unwrap(),
                    Script::default(),
                )],
                authorization: Authorized,
            }
        }

        #[test]
        fn unknown_bundle_type_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(42, 0, vec![0xAA])], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::UnknownBundleType { bundle_type: 42 })
            ));
        }

        #[test]
        fn unknown_bundle_variant_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(2, 1, vec![0xAA])], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::UnknownBundleVariant {
                    bundle_type: 2,
                    bundle_variant: 1
                })
            ));
        }

        #[test]
        fn coinbase_auth_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(1, 0, coinbase_effects(0, 0))],
                &[(1, 0, vec![0xAA])],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::ProhibitedBundleEntry {
                    bundle_type: 1,
                    map: V7BundleMap::AuthBundles
                })
            ));
        }

        #[test]
        fn fee_effect_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(5, 0, vec![0xAA])], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::ProhibitedBundleEntry {
                    bundle_type: 5,
                    map: V7BundleMap::EffectBundles
                })
            ));
        }

        #[test]
        fn nsm_effect_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(6, 0, vec![0xAA])], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::ProhibitedBundleEntry {
                    bundle_type: 6,
                    map: V7BundleMap::EffectBundles
                })
            ));
        }

        #[test]
        fn missing_effect_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[vp_entry(0, 0, 0, None, -1000)], &[], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::MissingEffectBundle { bundle_type: 0 })
            ));
        }

        #[test]
        fn missing_transparent_auth_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(0, 0, transparent_input_effects(true))],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::MissingTransparentAuth { tx_in_count: 1 })
            ));
        }

        #[test]
        fn missing_sapling_auth_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(2, 0, sapling_effects())], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::MissingShieldedAuth { bundle_type: 2 })
            ));
        }

        #[test]
        fn missing_orchard_auth_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(3, 0, orchard_effects(0))], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::MissingShieldedAuth { bundle_type: 3 })
            ));
        }

        #[test]
        fn missing_ironwood_auth_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(4, 0, orchard_effects(0))], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::MissingShieldedAuth { bundle_type: 4 })
            ));
        }

        #[test]
        fn unbalanced_non_zec_transparent_delta_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, 1, Some([0x42; 64]), -1000)],
                &[(0, 0, transparent_outputs_only_effects())],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::ValueImbalance {
                        asset_class: 1,
                        sum: -1000,
                        ..
                    }
                ))
            ));
        }

        #[test]
        fn balanced_non_zec_transparent_delta_passes() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[
                    vp_entry(0, 0, 1, Some([0x42; 64]), -1000),
                    vp_entry(6, 0, 1, Some([0x42; 64]), 1000),
                ],
                &[(0, 0, transparent_input_effects(true))],
                &[(0, 0, transparent_auth(0))],
            );
            assert!(validate(&bytes).is_ok());
        }

        #[test]
        fn non_zec_fee_delta_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(5, 0, 1, Some([0x42; 64]), -1000)],
                &[],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::FeeAssetClassNotZec { asset_class: 1 }
                ))
            ));
        }

        #[test]
        fn non_zec_coinbase_delta_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(1, 0, 1, Some([0x42; 64]), 1000)],
                &[(1, 0, coinbase_effects(0, 0))],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseAssetClassNotZec { asset_class: 1 }
                ))
            ));
        }

        #[test]
        fn coinbase_transparent_inputs_are_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[
                    (0, 0, transparent_input_effects(true)),
                    (1, 0, coinbase_effects(0, 0)),
                ],
                &[(0, 0, transparent_auth(0))],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseTransparentInputs { tx_in_count: 1 }
                ))
            ));
        }

        #[test]
        fn coinbase_sapling_spends_are_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(1, 0, coinbase_effects(0, 0)), (2, 0, sapling_effects())],
                &[(2, 0, sapling_auth())],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseSaplingSpends { spend_count: 1 }
                ))
            ));
        }

        #[test]
        fn coinbase_orchard_enable_spends_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(1, 0, coinbase_effects(0, 0)), (3, 0, orchard_effects(1))],
                &[(3, 0, orchard_auth())],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseEnableSpendsOrchardSet
                ))
            ));
        }

        #[test]
        fn coinbase_ironwood_enable_spends_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(1, 0, coinbase_effects(0, 0)), (4, 0, orchard_effects(1))],
                &[(4, 0, orchard_auth())],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseEnableSpendsOrchardSet
                ))
            ));
        }

        #[test]
        fn orchard_cross_address_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(3, 0, orchard_effects(0b100))],
                &[(3, 0, orchard_auth())],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::OrchardEnableCrossAddressSet
                ))
            ));
        }

        #[test]
        fn non_coinbase_positive_fee_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(5, 0, 0, None, 1000)],
                &[(0, 0, transparent_outputs_only_effects())],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::NonCoinbaseFeeDeltaPositive { .. }
                ))
            ));
        }

        #[test]
        fn coinbase_negative_fee_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(5, 0, 0, None, -1000)],
                &[(1, 0, coinbase_effects(0, 0))],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseFeeDeltaNegative { .. }
                ))
            ));
        }

        #[test]
        fn coinbase_value_delta_mismatch_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, 0, None, -3), vp_entry(1, 0, 0, None, 3)],
                &[
                    (0, 0, transparent_outputs_only_effects()),
                    (1, 0, coinbase_effects(0, 0)),
                ],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseValueDeltaMismatch {
                        expected: 0,
                        actual
                    }
                )) if actual == ZatBalance::from_i64(3).unwrap()
            ));
        }

        #[test]
        fn coinbase_value_delta_ignores_nsm_contribution() {
            // The coinbase bundle issues 3 and locks 1, so its value pool
            // delta is 2 regardless of the block's ZIP 235 NSM fee
            // contribution. That contribution reduces the miner fee available
            // from the fee bundle; it does not change the coinbase bundle's
            // subsidy-minus-lockbox delta.
            let bytes = wire_tx(
                BranchId::Nu8,
                &[
                    vp_entry(0, 0, 0, None, -2),
                    vp_entry(1, 0, 0, None, 2),
                    vp_entry(5, 0, 0, None, 1),
                    vp_entry(6, 0, 0, None, -1),
                ],
                &[
                    (0, 0, transparent_outputs_only_effects()),
                    (1, 0, coinbase_effects(3, 1)),
                ],
                &[],
            );
            assert!(validate(&bytes).is_ok());
        }

        #[test]
        fn value_imbalance_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, 0, None, 1000)],
                &[(0, 0, transparent_outputs_only_effects())],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::ValueImbalance { .. }
                ))
            ));
        }

        #[test]
        fn missing_input_side_condition_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(0, 0, transparent_outputs_only_effects())],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::MissingInputSideCondition
                ))
            ));
        }

        #[test]
        fn missing_output_side_condition_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(0, 0, transparent_input_effects(false))],
                &[(0, 0, transparent_auth(0))],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::MissingOutputSideCondition
                ))
            ));
        }

        #[test]
        fn positive_zip233_delta_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(6, 0, 0, None, 1000)],
                &[(0, 0, transparent_outputs_only_effects())],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::Zip233DeltaPositive { .. }
                ))
            ));
        }

        #[test]
        fn zip233_amount_satisfies_output_side_condition() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[
                    vp_entry(0, 0, 0, None, 1000),
                    vp_entry(6, 0, 0, None, -1000),
                ],
                &[(0, 0, transparent_input_effects(false))],
                &[(0, 0, transparent_auth(0))],
            );
            assert!(validate(&bytes).is_ok());
        }

        #[test]
        fn domain_invalid_sapling_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(2, 0, sapling_effects())],
                &[(2, 0, sapling_auth())],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::InvalidBundle { .. })
            ));
        }

        #[test]
        fn domain_invalid_orchard_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(3, 0, orchard_effects(0))],
                &[(3, 0, orchard_auth())],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::InvalidBundle { .. })
            ));
        }

        #[test]
        fn unsupported_sighash_version_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(0, 0, transparent_input_effects(true))],
                &[(0, 0, transparent_auth(1))],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::InvalidBundle { .. })
            ));
        }

        #[test]
        fn not_v7_is_rejected() {
            let body = V5TransactionBodyBytes::from_parts(
                crate::transaction::components::transparent::LegacyTransparentBundleBytes::from_parts(
                    vec![],
                    vec![],
                ),
                None,
                None,
            );
            let tx = TransactionBytes::from_parts(
                crate::transaction::TxVersion::V5,
                Some(BranchId::Nu5),
                0,
                BlockHeight::from_u32(100),
                TransactionBodyBytes::V5(body),
            )
            .unwrap();
            assert!(matches!(tx.validate_v7(), Err(V7ValidationError::NotV7)));
        }

        #[test]
        fn not_activated_is_rejected() {
            let bytes = wire_tx(BranchId::Nu7, &[], &[], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::NotActivated {
                    branch_id: BranchId::Nu7
                })
            ));
        }

        #[test]
        fn valid_transparent_transaction_passes() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[
                    vp_entry(0, 0, 0, None, 1000),
                    vp_entry(5, 0, 0, None, -1000),
                ],
                &[(0, 0, transparent_input_effects(true))],
                &[(0, 0, transparent_auth(0))],
            );
            assert!(validate(&bytes).is_ok());
        }

        #[test]
        fn valid_coinbase_transaction_passes() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, 0, None, -2), vp_entry(1, 0, 0, None, 2)],
                &[
                    (0, 0, transparent_outputs_only_effects()),
                    (1, 0, coinbase_effects(3, 1)),
                ],
                &[],
            );
            assert!(validate(&bytes).is_ok());
        }

        #[test]
        fn malformed_coinbase_height_fails_validation() {
            let mut effects = coinbase_effects(0, 0);
            effects[..4].copy_from_slice(&0u32.to_le_bytes());
            let bytes = wire_tx(BranchId::Nu8, &[], &[(1, 0, effects)], &[]);
            // The byte layer retains the raw height; validation rejects it.
            assert!(TransactionBytes::read(&bytes[..]).is_ok());
            assert!(validate(&bytes).is_err());
        }

        #[test]
        fn malformed_coinbase_lockbox_fails_validation() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(1, 0, coinbase_effects(1, 2))], &[]);
            assert!(TransactionBytes::read(&bytes[..]).is_ok());
            assert!(validate(&bytes).is_err());
        }

        #[test]
        fn read_and_validate_v7_returns_the_typed_transaction() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[
                    vp_entry(0, 0, 0, None, 1000),
                    vp_entry(5, 0, 0, None, -1000),
                ],
                &[(0, 0, transparent_input_effects(true))],
                &[(0, 0, transparent_auth(0))],
            );
            let tx = Transaction::read_and_validate_v7(&bytes[..]).unwrap();
            assert_eq!(tx.version(), crate::transaction::TxVersion::V7);
            assert!(tx.transparent_bundle().is_some());

            // The validated typed transaction and the byte layer agree on the
            // identifier, and the unvalidated typed reader produces the same
            // transaction.
            let byte_tx = TransactionBytes::read(&bytes[..]).unwrap();
            let expected_txid = byte_tx
                .v7_txid(&zip248::SuppliedBundleDigests::new())
                .unwrap();
            assert_eq!(tx.txid(), expected_txid);
            assert_eq!(
                Transaction::read(&bytes[..], BranchId::Nu8).unwrap().txid(),
                expected_txid
            );
        }

        #[test]
        fn read_and_validate_v7_reports_encoding_errors() {
            let bytes = [0u8; 4];
            assert!(matches!(
                Transaction::read_and_validate_v7(&bytes[..]),
                Err(V7ValidationError::InvalidEncoding { .. })
            ));
        }

        /// Builds a value pool delta map with a non-ZEC entry for
        /// `bundle_type` balanced against a non-ZEC transparent entry.
        fn balanced_non_zec_vp(bundle_type: zip248::BundleType) -> zip248::ValuePoolDeltas {
            let uuid = [0x42; 64];
            let mut vp = zip248::ValuePoolDeltas::empty();
            for (bundle_type, value) in [
                (zip248::BundleType::TRANSPARENT, -1000i64),
                (bundle_type, 1000i64),
            ] {
                vp.insert(
                    zip248::ValuePoolDeltaKey::from_parts(
                        bundle_type,
                        zip248::ASSET_CLASS_OTHER,
                        uuid,
                    )
                    .unwrap(),
                    zip248::BundleVariant::DEFAULT,
                    ZatBalance::from_i64(value).unwrap(),
                )
                .unwrap();
            }
            vp
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(4))]

            /// A non-ZEC Sapling entry is accepted when it balances per asset.
            #[test]
            fn balanced_non_zec_sapling_delta_passes(
                bundle in crate::transaction::components::sapling::testing::arb_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("a Sapling bundle is only interesting when present", |b| b.is_some()),
            ) {
                let bundle = bundle.expect("filtered to Some");
                let tx = super::super::super::TransactionData::<super::super::super::Authorized>::from_parts_with_value_pool_deltas(
                    crate::transaction::TxVersion::V7,
                    BranchId::Nu8,
                    0,
                    BlockHeight::from_u32(100),
                    balanced_non_zec_vp(zip248::BundleType::SAPLING),
                    Some(transparent_bundle()),
                    None,
                    Some(bundle),
                    None,
                    None,
                    None,
                )
                .freeze()
                .unwrap();

                prop_assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
            }

            /// A non-ZEC Orchard entry is accepted when it balances per asset.
            #[test]
            fn balanced_non_zec_orchard_delta_passes(
                bundle in crate::transaction::components::orchard::testing::arb_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("an Orchard bundle is only interesting when present", |b| b.is_some()),
            ) {
                let bundle = bundle.expect("filtered to Some");
                let tx = super::super::super::TransactionData::<super::super::super::Authorized>::from_parts_with_value_pool_deltas(
                    crate::transaction::TxVersion::V7,
                    BranchId::Nu8,
                    0,
                    BlockHeight::from_u32(100),
                    balanced_non_zec_vp(zip248::BundleType::ORCHARD),
                    Some(transparent_bundle()),
                    None,
                    None,
                    Some(bundle),
                    None,
                    None,
                )
                .freeze()
                .unwrap();

                prop_assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
            }

            /// A valid Ironwood bundle may set `enableCrossAddress`; the
            /// restriction applies only to the Orchard bundle.
            #[test]
            fn valid_ironwood_cross_address_passes(
                bundle in crate::transaction::components::orchard::testing::arb_ironwood_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("an Ironwood bundle is only interesting when present", |b| b.is_some()),
            ) {
                let bundle = bundle.expect("filtered to Some");
                let value_balance = *bundle.value_balance();

                let mut vp = zip248::ValuePoolDeltas::empty();
                vp.set_ironwood(value_balance).unwrap();
                vp.set_transparent(-value_balance).unwrap();

                let tx = super::super::super::TransactionData::<super::super::super::Authorized>::from_parts_with_value_pool_deltas(
                    crate::transaction::TxVersion::V7,
                    BranchId::Nu8,
                    0,
                    BlockHeight::from_u32(100),
                    vp,
                    Some(transparent_bundle()),
                    None,
                    None,
                    None,
                    Some(bundle),
                    None,
                )
                .freeze()
                .unwrap();

                let mut buf = Vec::new();
                tx.write(&mut buf).unwrap();
                let validated = Transaction::read_and_validate_v7(&buf[..])
                    .expect("a valid Ironwood transaction must validate");
                prop_assert_eq!(validated.txid(), tx.txid());
            }

            /// The Orchard pool balance must be nonnegative. Sapling and
            /// Ironwood balances are unrestricted.
            #[test]
            fn orchard_pool_balance_must_be_nonnegative(
                bundle in crate::transaction::components::orchard::testing::arb_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("an Orchard bundle is only interesting when present", |b| b.is_some()),
            ) {
                let bundle = bundle.expect("filtered to Some");

                let build = |orchard_delta: i64| {
                    let mut vp = zip248::ValuePoolDeltas::empty();
                    vp.set_orchard(ZatBalance::from_i64(orchard_delta).unwrap()).unwrap();
                    vp.set_transparent(ZatBalance::from_i64(-orchard_delta).unwrap()).unwrap();
                    super::super::super::TransactionData::<super::super::super::Authorized>::from_parts_with_value_pool_deltas(
                        crate::transaction::TxVersion::V7,
                        BranchId::Nu8,
                        0,
                        BlockHeight::from_u32(100),
                        vp,
                        Some(transparent_bundle()),
                        None,
                        None,
                        Some(bundle.clone()),
                        None,
                        None,
                    )
                    .freeze()
                    .unwrap()
                };

                let negative = build(-1000);
                assert!(matches!(
                    negative.check_v7_consensus_rules(),
                    Err(V7ConsensusError::OrchardPoolBalanceNegative { .. })
                ));

                let mut negative_bytes = Vec::new();
                negative.write(&mut negative_bytes).unwrap();
                assert!(matches!(
                    Transaction::read_and_validate_v7(&negative_bytes[..]),
                    Err(V7ValidationError::Consensus(
                        V7ConsensusError::OrchardPoolBalanceNegative { .. }
                    ))
                ));

                for delta in [0, 1000] {
                    let tx = build(delta);
                    prop_assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
                    let mut buf = Vec::new();
                    tx.write(&mut buf).unwrap();
                    let validated = Transaction::read_and_validate_v7(&buf[..])
                        .expect("a nonnegative Orchard balance must validate");
                    prop_assert_eq!(validated.txid(), tx.txid());
                }
            }

            /// A transaction whose per-asset deltas sum to zero must not be
            /// rejected because an intermediate partial sum leaves the
            /// `ZatBalance` range.
            ///
            /// The ZIP 233 opt-in rejects nonzero ZIP 233 amounts, so this
            /// offsetting case is only applicable without it.
            #[cfg(not(zcash_unstable = "zip233"))]
            #[test]
            fn offsetting_value_pool_deltas_do_not_overflow(
                bundle in crate::transaction::components::orchard::testing::arb_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("an Orchard bundle is only interesting when present", |b| b.is_some()),
            ) {
                let bundle = bundle.expect("filtered to Some");
                let max = i64::try_from(MAX_MONEY).unwrap();

                let mut vp = zip248::ValuePoolDeltas::empty();
                vp.set_transparent(ZatBalance::from_i64(max).unwrap()).unwrap();
                vp.set_orchard(ZatBalance::from_i64(max).unwrap()).unwrap();
                vp.set_fee(Zatoshis::from_u64(MAX_MONEY).unwrap()).unwrap();
                vp.set_zip233(Zatoshis::from_u64(MAX_MONEY).unwrap()).unwrap();

                let tx = super::super::super::TransactionData::<super::super::super::Authorized>::from_parts_with_value_pool_deltas(
                    crate::transaction::TxVersion::V7,
                    BranchId::Nu8,
                    0,
                    BlockHeight::from_u32(100),
                    vp,
                    Some(transparent_bundle()),
                    None,
                    None,
                    Some(bundle),
                    None,
                    None,
                )
                .freeze()
                .unwrap();

                prop_assert_eq!(tx.check_v7_consensus_rules(), Ok(()));

                let mut buf = Vec::new();
                tx.write(&mut buf).unwrap();
                let validated = Transaction::read_and_validate_v7(&buf[..])
                    .expect("an offsetting transaction must validate");
                prop_assert_eq!(validated.txid(), tx.txid());
            }
        }
    }
}

/// Byte-level ZIP 248 digest resolution.
///
/// These tests compare the byte-layer digest tree against the typed path for
/// the same transaction, and exercise the explicit-digest route for bundles the
/// byte layer does not interpret.
#[cfg(all(test, zcash_unstable = "nu8"))]
mod v7_byte_digests {
    use alloc::vec;
    use alloc::vec::Vec;

    use blake2b_simd::Hash as Blake2bHash;
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        value::{ZatBalance, Zatoshis},
    };

    use super::{
        Authorized, TransactionData, TxVersion, test_ironwood_bundle, test_orchard_bundle,
        test_sapling_bundle, test_sapling_output_only_bundle,
    };
    use crate::transaction::{
        bytes::{
            BundleType, BundleVariant, OpaqueBundleBytes, OrchardSignatureBytes,
            SaplingSignatureBytes, SighashInfoBytes, TransactionBodyBytes, TransactionBytes,
            V7BundleBytes, V7OrchardBundleBytes, V7SaplingBundleBytes, V7TransactionBodyBytes,
        },
        zip248::{self, BundleId, SuppliedBundleDigests, V7DigestError},
    };

    fn transparent_bundle() -> ::transparent::bundle::Bundle<::transparent::bundle::Authorized> {
        use ::transparent::{
            address::Script,
            bundle::{Authorized, Bundle, OutPoint, TxIn, TxOut},
        };

        Bundle {
            vin: vec![TxIn::from_parts(
                OutPoint::new([1; 32], 2),
                Script::default(),
                3,
            )],
            vout: vec![TxOut::new(
                Zatoshis::from_u64(1000).unwrap(),
                Script::default(),
            )],
            authorization: Authorized,
        }
    }

    fn typed_v7_tx(
        runner: &mut proptest::test_runner::TestRunner,
        sapling: bool,
        orchard: bool,
        ironwood: bool,
        coinbase: bool,
    ) -> TransactionData<Authorized> {
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_transparent(ZatBalance::from_i64(-1000).unwrap())
            .unwrap();
        vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();

        let transparent = Some(transparent_bundle());

        let coinbase = coinbase.then(|| {
            let bundle = zip248::CoinbaseBundle::from_parts(
                BlockHeight::from(100u32),
                Zatoshis::from_u64(1_000_000).unwrap(),
                Zatoshis::from_u64(0).unwrap(),
                vec![0x51],
            )
            .unwrap();
            vp.set_coinbase(ZatBalance::from_i64(1_000_000).unwrap())
                .unwrap();
            bundle
        });
        let sapling = sapling.then(|| {
            let bundle = test_sapling_bundle(runner);
            vp.set_sapling(*bundle.value_balance()).unwrap();
            bundle
        });
        let orchard = orchard.then(|| {
            let bundle = test_orchard_bundle(runner);
            vp.set_orchard(*bundle.value_balance()).unwrap();
            bundle
        });
        let ironwood = ironwood.then(|| {
            let bundle = test_ironwood_bundle(runner);
            vp.set_ironwood(*bundle.value_balance()).unwrap();
            bundle
        });

        TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            BlockHeight::from_u32(100),
            vp,
            transparent,
            None,
            sapling,
            orchard,
            ironwood,
            coinbase,
        )
    }

    fn byte_tx(tx: &TransactionData<Authorized>) -> TransactionBytes {
        let tx = tx.clone().freeze().unwrap();
        let mut encoded = Vec::new();
        tx.write(&mut encoded).unwrap();
        TransactionBytes::read(&encoded[..]).unwrap()
    }

    fn assert_digests_match(typed: &TransactionData<Authorized>, bytes: &TransactionBytes) {
        let empty = SuppliedBundleDigests::new();
        let typed_digests = typed.digest_v7();
        let byte_digests = bytes.v7_txid_digests(&empty).unwrap();

        assert_eq!(byte_digests.header_digest, typed_digests.header_digest);
        match (
            &byte_digests.transparent_digests,
            &typed_digests.transparent_digests,
        ) {
            (Some(byte), Some(typed)) => {
                assert_eq!(byte.prevouts_digest, typed.prevouts_digest);
                assert_eq!(byte.sequence_digest, typed.sequence_digest);
                assert_eq!(byte.outputs_digest, typed.outputs_digest);
            }
            (None, None) => {}
            _ => panic!("transparent digest presence differs between paths"),
        }
        assert_eq!(byte_digests.coinbase_digest, typed_digests.coinbase_digest);
        assert_eq!(byte_digests.sapling_digest, typed_digests.sapling_digest);
        assert_eq!(byte_digests.orchard_digest, typed_digests.orchard_digest);
        assert_eq!(byte_digests.ironwood_digest, typed_digests.ironwood_digest);
        assert_eq!(
            byte_digests.value_pool_deltas_digest,
            typed_digests.value_pool_deltas_digest
        );
        assert_eq!(
            byte_digests.unknown_effect_digests,
            typed_digests.unknown_effect_digests
        );

        let typed_tx = typed.clone().freeze().unwrap();
        assert_eq!(bytes.v7_txid(&empty).unwrap(), typed_tx.txid());
        assert_eq!(
            bytes.v7_auth_commitment(&empty).unwrap(),
            typed_tx.auth_commitment()
        );
    }

    #[test]
    fn byte_digests_match_typed_path_for_all_known_bundles() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, true, true);
        let bytes = byte_tx(&typed);
        assert_digests_match(&typed, &bytes);
    }

    /// [ZIP 248 §T.3.4] gives the Ironwood action sub-digests their own
    /// personalizations, distinct from both the Orchard ones and the v6
    /// Ironwood ones. Recompute the effects digest from the bundle's actions
    /// using the literal spec strings so that a regression in the shared
    /// constants cannot silently change the txid.
    ///
    /// [ZIP 248 §T.3.4]: https://zips.z.cash/zip-0248#t-3-4-ironwood-effects-digest
    #[test]
    fn ironwood_effects_digest_uses_zip248_action_personalizations() {
        use blake2b_simd::Params;

        let mut runner = proptest::test_runner::TestRunner::default();
        let bundle = test_ironwood_bundle(&mut runner);
        assert!(
            !bundle.actions().is_empty(),
            "the regression fixture must have Ironwood actions"
        );

        let hasher =
            |personal: &[u8; 16]| Params::new().hash_length(32).personal(personal).to_state();

        let mut compact = hasher(b"ZTxIdIrnActCHash");
        let mut memos = hasher(b"ZTxIdIrnActMHash");
        let mut noncompact = hasher(b"ZTxIdIrnActNHash");
        for action in bundle.actions().iter() {
            let note = action.encrypted_note();
            let enc_ciphertext: &[u8; 580] = note
                .enc_ciphertext
                .as_ref()
                .try_into()
                .expect("Orchard enc_ciphertext is 580 bytes");

            compact.update(&action.nullifier().to_bytes());
            compact.update(&action.cmx().to_bytes());
            compact.update(&note.epk_bytes);
            compact.update(&enc_ciphertext[..52]);

            memos.update(&enc_ciphertext[52..564]);

            noncompact.update(&action.cv_net().to_bytes());
            noncompact.update(&<[u8; 32]>::from(action.rk()));
            noncompact.update(&enc_ciphertext[564..]);
            noncompact.update(&note.out_ciphertext);
        }

        let mut expected = hasher(b"ZTxIdIronwd_Hash");
        expected.update(compact.finalize().as_bytes());
        expected.update(memos.finalize().as_bytes());
        expected.update(noncompact.finalize().as_bytes());
        expected.update(&[bundle.flag_byte()]);
        let expected = expected.finalize();

        assert_eq!(
            crate::transaction::txid::hash_v7_ironwood_effects(&bundle).as_bytes(),
            expected.as_bytes(),
        );
    }

    #[test]
    fn v7_byte_bundles_convert_to_typed() {
        use crate::transaction::components::orchard::bundle_version_for_branch;

        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, true, true);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();
        let vp = body.to_value_pool_deltas().unwrap();

        assert_eq!(
            body.transparent().unwrap().to_authorized().unwrap(),
            typed.transparent_bundle().cloned(),
        );
        assert_eq!(
            body.coinbase().unwrap().to_coinbase_bundle().unwrap(),
            *typed.coinbase_bundle().unwrap(),
        );
        let sapling = body
            .sapling()
            .unwrap()
            .to_authorized(vp.sapling_value().unwrap())
            .unwrap();
        let mut effects = Vec::new();
        crate::transaction::components::sapling::write_v7_effects(&mut effects, &sapling).unwrap();
        let mut auth = Vec::new();
        crate::transaction::components::sapling::write_v7_auth(&mut auth, &sapling).unwrap();
        let mut expected_effects = Vec::new();
        body.sapling()
            .unwrap()
            .write_effects(&mut expected_effects)
            .unwrap();
        let mut expected_auth = Vec::new();
        body.sapling()
            .unwrap()
            .write_auth(&mut expected_auth)
            .unwrap();
        assert_eq!(effects, expected_effects);
        assert_eq!(auth, expected_auth);

        let orchard = body
            .orchard()
            .unwrap()
            .to_authorized(
                vp.orchard_value().unwrap(),
                bundle_version_for_branch(BranchId::Nu8, orchard::ValuePool::Orchard),
            )
            .unwrap();
        let mut effects = Vec::new();
        crate::transaction::components::orchard::write_v7_effects(&mut effects, &orchard).unwrap();
        let mut auth = Vec::new();
        crate::transaction::components::orchard::write_v7_auth(&mut auth, &orchard).unwrap();
        let mut expected_effects = Vec::new();
        body.orchard()
            .unwrap()
            .write_effects(&mut expected_effects)
            .unwrap();
        let mut expected_auth = Vec::new();
        body.orchard()
            .unwrap()
            .write_auth(&mut expected_auth)
            .unwrap();
        assert_eq!(effects, expected_effects);
        assert_eq!(auth, expected_auth);

        let ironwood = body
            .ironwood()
            .unwrap()
            .to_authorized(
                vp.ironwood_value().unwrap(),
                bundle_version_for_branch(BranchId::Nu8, orchard::ValuePool::Ironwood),
            )
            .unwrap();
        let mut effects = Vec::new();
        crate::transaction::components::orchard::write_v7_effects(&mut effects, &ironwood).unwrap();
        let mut auth = Vec::new();
        crate::transaction::components::orchard::write_v7_auth(&mut auth, &ironwood).unwrap();
        let mut expected_effects = Vec::new();
        body.ironwood()
            .unwrap()
            .write_effects(&mut expected_effects)
            .unwrap();
        let mut expected_auth = Vec::new();
        body.ironwood()
            .unwrap()
            .write_auth(&mut expected_auth)
            .unwrap();
        assert_eq!(effects, expected_effects);
        assert_eq!(auth, expected_auth);
    }

    #[test]
    fn v7_effect_only_bundles_have_no_typed_representation() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();

        let sapling = body.sapling().unwrap();
        let effect_only = V7SaplingBundleBytes::from_parts(
            sapling.spends().to_vec(),
            sapling.outputs().to_vec(),
            None,
            vec![],
            vec![],
            vec![],
            None,
        )
        .unwrap();
        let err = effect_only.to_authorized(ZatBalance::zero()).unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("no authorizing data"));

        let orchard = body.orchard().unwrap();
        let effect_only = V7OrchardBundleBytes::from_parts(
            orchard.actions().to_vec(),
            orchard.flags(),
            None,
            vec![],
            vec![],
            None,
        )
        .unwrap();
        let err = effect_only
            .to_authorized(
                ZatBalance::zero(),
                crate::transaction::components::orchard::bundle_version_for_branch(
                    BranchId::Nu8,
                    orchard::ValuePool::Orchard,
                ),
            )
            .unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("no authorizing data"));
    }

    #[test]
    fn v7_bundles_reject_unsupported_sighash_versions() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();

        let sapling = body.sapling().unwrap();
        let bad_sig =
            SaplingSignatureBytes::from_parts(SighashInfoBytes::from_bytes(vec![0x01]), [0u8; 64]);
        let bad_sapling = V7SaplingBundleBytes::from_parts(
            sapling.spends().to_vec(),
            sapling.outputs().to_vec(),
            sapling.anchor().copied(),
            sapling.spend_proofs().to_vec(),
            vec![bad_sig.clone(); sapling.spends().len()],
            sapling.output_proofs().to_vec(),
            Some(bad_sig),
        )
        .unwrap();
        let err = bad_sapling.to_authorized(ZatBalance::zero()).unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("sighash version"));

        let orchard = body.orchard().unwrap();
        let bad_sig =
            OrchardSignatureBytes::from_parts(SighashInfoBytes::from_bytes(vec![0x01]), [0u8; 64]);
        let bad_orchard = V7OrchardBundleBytes::from_parts(
            orchard.actions().to_vec(),
            orchard.flags(),
            orchard.anchor().copied(),
            orchard.proof().to_vec(),
            vec![bad_sig.clone(); orchard.actions().len()],
            Some(bad_sig),
        )
        .unwrap();
        let err = bad_orchard
            .to_authorized(
                ZatBalance::zero(),
                crate::transaction::components::orchard::bundle_version_for_branch(
                    BranchId::Nu8,
                    orchard::ValuePool::Orchard,
                ),
            )
            .unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("sighash version"));
    }

    #[test]
    fn v7_orchard_bundle_rejects_unsupported_branch() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, false, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();
        let orchard = body.orchard().unwrap();

        let err = orchard.to_authorized(ZatBalance::zero(), None).unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("may not be present"));
    }

    #[test]
    fn byte_digests_match_typed_path_for_sapling_output_only() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_transparent(ZatBalance::from_i64(-1000).unwrap())
            .unwrap();
        vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();
        let bundle = test_sapling_output_only_bundle(&mut runner);
        vp.set_sapling(*bundle.value_balance()).unwrap();

        let typed = TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            BlockHeight::from_u32(100),
            vp,
            Some(transparent_bundle()),
            None,
            Some(bundle),
            None,
            None,
            None,
        );
        let bytes = byte_tx(&typed);
        assert_digests_match(&typed, &bytes);
    }

    #[test]
    fn sapling_effects_digest_requires_anchor_when_spends_are_present() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, true, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();

        let sapling = body.sapling().unwrap();
        let effect_only = crate::transaction::bytes::V7SaplingBundleBytes::from_parts(
            sapling.spends().to_vec(),
            sapling.outputs().to_vec(),
            None,
            vec![],
            vec![],
            vec![],
            None,
        )
        .unwrap();
        assert_eq!(
            crate::transaction::txid::hash_v7_sapling_effects_bytes(&effect_only),
            Err(V7DigestError::MissingSaplingAnchor),
            "a Sapling bundle with spends cannot resolve its effects digest without an anchor"
        );
    }

    #[test]
    fn orchard_effects_digest_does_not_depend_on_authorizing_data() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, true, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();

        let orchard = body.orchard().unwrap();
        let effect_only = crate::transaction::bytes::V7OrchardBundleBytes::from_parts(
            orchard.actions().to_vec(),
            orchard.flags(),
            None,
            vec![],
            vec![],
            None,
        )
        .unwrap();
        assert_eq!(
            crate::transaction::txid::hash_v7_orchard_effects_bytes(&effect_only),
            crate::transaction::txid::hash_v7_orchard_effects_bytes(orchard)
        );
    }

    #[test]
    fn v7_sapling_anchor_changes_txid_and_auth_commitment() {
        use super::{sapling_bundle_with_anchor, test_sapling_anchor};

        let mut runner = proptest::test_runner::TestRunner::default();
        let base = typed_v7_tx(&mut runner, true, true, false, false);
        let vp = base.value_pool_deltas().clone();
        let sapling = base.sapling_bundle().unwrap().clone();
        let orchard = base.orchard_bundle().unwrap().clone();

        let build = |sapling| {
            TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                vp.clone(),
                Some(transparent_bundle()),
                None,
                Some(sapling),
                Some(orchard.clone()),
                None,
                None,
            )
        };

        let tx_a = build(sapling.clone());
        let tx_b = build(sapling_bundle_with_anchor(&sapling, test_sapling_anchor(1)));

        let bytes_a = byte_tx(&tx_a);
        let bytes_b = byte_tx(&tx_b);
        let empty = SuppliedBundleDigests::new();

        assert_ne!(
            bytes_a.v7_txid(&empty).unwrap(),
            bytes_b.v7_txid(&empty).unwrap(),
            "the v7 Sapling spends digest hashes the anchor once per spend"
        );
        assert_ne!(
            bytes_a.v7_auth_commitment(&empty).unwrap(),
            bytes_b.v7_auth_commitment(&empty).unwrap(),
            "the anchor must change the authorizing-data commitment"
        );
    }

    #[test]
    fn v7_orchard_anchor_changes_auth_commitment_not_txid() {
        use super::{bundle_with_anchor, test_anchor};

        let mut runner = proptest::test_runner::TestRunner::default();
        let base = typed_v7_tx(&mut runner, true, true, false, false);
        let vp = base.value_pool_deltas().clone();
        let sapling = base.sapling_bundle().unwrap().clone();
        let orchard = base.orchard_bundle().unwrap().clone();

        let build = |orchard| {
            TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                vp.clone(),
                Some(transparent_bundle()),
                None,
                Some(sapling.clone()),
                Some(orchard),
                None,
                None,
            )
        };

        let tx_a = build(orchard.clone());
        let tx_b = build(bundle_with_anchor(&orchard, test_anchor(1)));

        let bytes_a = byte_tx(&tx_a);
        let bytes_b = byte_tx(&tx_b);
        let empty = SuppliedBundleDigests::new();

        assert_eq!(
            bytes_a.v7_txid(&empty).unwrap(),
            bytes_b.v7_txid(&empty).unwrap(),
            "the anchor is authorizing data and must not change the txid"
        );
        assert_ne!(
            bytes_a.v7_auth_commitment(&empty).unwrap(),
            bytes_b.v7_auth_commitment(&empty).unwrap(),
            "the anchor must change the authorizing-data commitment"
        );
    }

    fn unknown_body(bundle: V7BundleBytes) -> TransactionBytes {
        let body = V7TransactionBodyBytes::from_parts(vec![], vec![bundle]).unwrap();
        TransactionBytes::from_parts(
            TxVersion::V7,
            Some(BranchId::Nu8),
            0,
            BlockHeight::from_u32(100),
            TransactionBodyBytes::V7(body),
        )
        .unwrap()
    }

    fn test_digest(byte: u8) -> Blake2bHash {
        blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"test_unknown_efx")
            .hash(&[byte])
    }

    #[test]
    fn unknown_bundle_requires_supplied_effect_digest() {
        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(99),
            BundleVariant::from_u64(0),
            vec![1, 2, 3],
            None,
        )
        .unwrap();
        let tx = unknown_body(V7BundleBytes::Unknown(opaque));
        let key = BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0));

        let empty = SuppliedBundleDigests::new();
        assert_eq!(
            tx.v7_txid(&empty),
            Err(V7DigestError::MissingEffectsDigest { key })
        );

        // A digest supplied under the wrong key does not resolve the needed
        // key.
        let mut wrong = SuppliedBundleDigests::new();
        wrong
            .insert_effects(
                BundleId::new(BundleType::from_u64(98), BundleVariant::from_u64(0)),
                test_digest(1),
            )
            .unwrap();
        assert_eq!(
            tx.v7_txid(&wrong),
            Err(V7DigestError::MissingEffectsDigest { key })
        );

        let mut supplied = SuppliedBundleDigests::new();
        supplied.insert_effects(key, test_digest(2)).unwrap();
        assert!(tx.v7_txid(&supplied).is_ok());
    }

    #[test]
    fn known_type_unknown_variant_requires_supplied_digest() {
        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(2),
            BundleVariant::from_u64(1),
            vec![1, 2, 3],
            Some(vec![4, 5]),
        )
        .unwrap();
        let tx = unknown_body(V7BundleBytes::KnownTypeUnknownVariant(opaque));
        let key = BundleId::new(BundleType::from_u64(2), BundleVariant::from_u64(1));

        let empty = SuppliedBundleDigests::new();
        assert_eq!(
            tx.v7_txid(&empty),
            Err(V7DigestError::MissingEffectsDigest { key })
        );
        assert_eq!(
            tx.v7_auth_commitment(&empty),
            Err(V7DigestError::MissingAuthDigest { key })
        );

        let mut supplied = SuppliedBundleDigests::new();
        supplied.insert_effects(key, test_digest(3)).unwrap();
        assert_eq!(
            tx.v7_auth_commitment(&supplied),
            Err(V7DigestError::MissingAuthDigest { key })
        );
        supplied.insert_auth(key, test_digest(4)).unwrap();
        assert!(tx.v7_txid(&supplied).is_ok());
        assert!(tx.v7_auth_commitment(&supplied).is_ok());
    }

    #[test]
    fn known_opaque_bundle_requires_supplied_digest() {
        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(5),
            BundleVariant::from_u64(0),
            vec![0x00],
            None,
        )
        .unwrap();
        let tx = unknown_body(V7BundleBytes::KnownOpaque(opaque));
        let key = BundleId::new(BundleType::from_u64(5), BundleVariant::from_u64(0));

        let empty = SuppliedBundleDigests::new();
        assert_eq!(
            tx.v7_txid(&empty),
            Err(V7DigestError::MissingEffectsDigest { key })
        );

        let mut supplied = SuppliedBundleDigests::new();
        supplied.insert_effects(key, test_digest(5)).unwrap();
        assert!(tx.v7_txid(&supplied).is_ok());
    }

    #[test]
    fn supplied_unknown_digest_gives_canonical_txid() {
        let effect_digest = test_digest(2);
        let auth_digest = test_digest(3);
        let key = BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0));

        let opaque = OpaqueBundleBytes::from_parts(
            BundleType::from_u64(99),
            BundleVariant::from_u64(0),
            vec![1, 2, 3],
            Some(vec![4, 5]),
        )
        .unwrap();
        let tx = unknown_body(V7BundleBytes::Unknown(opaque));

        let mut supplied = SuppliedBundleDigests::new();
        supplied.insert_effects(key, effect_digest).unwrap();
        supplied.insert_auth(key, auth_digest).unwrap();

        let txid = tx.v7_txid(&supplied).unwrap();
        let digests = tx.v7_txid_digests(&supplied).unwrap();
        assert_eq!(
            txid,
            super::super::txid::to_txid(TxVersion::V7, BranchId::Nu8, &digests).unwrap()
        );

        // The supplied digests are what the transaction commits to: changing
        // the effecting digest changes the txid, and changing the authorizing
        // digest changes the auth commitment.
        let auth_commitment = tx.v7_auth_commitment(&supplied).unwrap();
        let mut other_effects = SuppliedBundleDigests::new();
        other_effects.insert_effects(key, test_digest(5)).unwrap();
        other_effects.insert_auth(key, auth_digest).unwrap();
        assert_ne!(txid, tx.v7_txid(&other_effects).unwrap());

        let mut other_auth = SuppliedBundleDigests::new();
        other_auth.insert_effects(key, effect_digest).unwrap();
        other_auth.insert_auth(key, test_digest(4)).unwrap();
        assert_ne!(auth_commitment, tx.v7_auth_commitment(&other_auth).unwrap());
    }

    #[test]
    fn supplied_digests_reject_duplicates_and_conflicts() {
        let key = BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0));
        let mut supplied = SuppliedBundleDigests::new();
        supplied.insert_effects(key, test_digest(1)).unwrap();
        assert_eq!(
            supplied.insert_effects(key, test_digest(1)),
            Err(V7DigestError::DuplicateEffectsDigest { key })
        );
        assert_eq!(
            supplied.insert_effects(key, test_digest(2)),
            Err(V7DigestError::ConflictingEffectsDigest { key })
        );

        supplied.insert_auth(key, test_digest(3)).unwrap();
        assert_eq!(
            supplied.insert_auth(key, test_digest(3)),
            Err(V7DigestError::DuplicateAuthDigest { key })
        );
        assert_eq!(
            supplied.insert_auth(key, test_digest(4)),
            Err(V7DigestError::ConflictingAuthDigest { key })
        );
    }

    #[test]
    fn supplied_digests_reject_unexpected_keys() {
        let key = BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0));
        let mut supplied = SuppliedBundleDigests::new();
        supplied.insert_effects(key, test_digest(1)).unwrap();
        supplied.insert_auth(key, test_digest(2)).unwrap();

        assert_eq!(
            supplied.validate_for(
                [&BundleId::new(
                    BundleType::from_u64(98),
                    BundleVariant::from_u64(0)
                )],
                []
            ),
            Err(V7DigestError::UnexpectedEffectsDigest { key })
        );

        let mut supplied = SuppliedBundleDigests::new();
        supplied.insert_auth(key, test_digest(2)).unwrap();
        assert_eq!(
            supplied.validate_for(
                [&BundleId::new(
                    BundleType::from_u64(98),
                    BundleVariant::from_u64(0)
                )],
                []
            ),
            Err(V7DigestError::UnexpectedAuthDigest { key })
        );
    }
}

/// Byte-to-typed conversion tests for the pre-v7 bundle formats.
#[cfg(test)]
mod conversions {
    use super::*;
    use crate::transaction::{
        bytes::{
            OrchardBundleBytes, SaplingBundleBytes, SaplingSpendV4Bytes, V4SaplingBundleBytes,
        },
        components::{orchard as orchard_serialization, sapling as sapling_serialization},
    };

    #[test]
    fn v4_sapling_requires_a_binding_signature() {
        let bundle = V4SaplingBundleBytes::from_parts(
            0,
            vec![SaplingSpendV4Bytes::from_parts(
                [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 192], [0u8; 64],
            )],
            vec![],
        );

        let err = bundle.to_authorized(None).unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("binding signature"));
    }

    #[test]
    fn v5_sapling_and_orchard_convert_to_typed() {
        let mut runner = proptest::test_runner::TestRunner::default();

        let sapling = test_sapling_bundle(&mut runner);
        let mut buf = Vec::new();
        sapling_serialization::write_v5_bundle(&mut buf, Some(&sapling)).unwrap();
        let bytes = SaplingBundleBytes::read(&buf[..]).unwrap().unwrap();
        let converted = bytes.to_authorized().unwrap();
        let mut reserialized = Vec::new();
        sapling_serialization::write_v5_bundle(&mut reserialized, Some(&converted)).unwrap();
        assert_eq!(reserialized, buf);

        let orchard = test_orchard_bundle(&mut runner);
        let mut buf = Vec::new();
        orchard_serialization::write_v5_bundle(Some(&orchard), &mut buf).unwrap();
        let bytes = OrchardBundleBytes::read(&buf[..]).unwrap().unwrap();
        let version = orchard_serialization::bundle_version_for_branch(
            BranchId::Nu6_3,
            orchard::ValuePool::Orchard,
        );
        let converted = bytes.to_authorized(version).unwrap();
        let mut reserialized = Vec::new();
        orchard_serialization::write_v5_bundle(Some(&converted), &mut reserialized).unwrap();
        assert_eq!(reserialized, buf);
    }

    #[test]
    fn v5_orchard_bundle_rejects_unsupported_branch() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let orchard = test_orchard_bundle(&mut runner);
        let mut buf = Vec::new();
        orchard_serialization::write_v5_bundle(Some(&orchard), &mut buf).unwrap();
        let bytes = OrchardBundleBytes::read(&buf[..]).unwrap().unwrap();

        let err = bytes.to_authorized(None).unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("may not be present"));
    }
}
