use proptest::prelude::*;

#[cfg(test)]
use {
    crate::transaction::{
        Authorization, Authorized, Transaction, TransactionData, TransactionDigest, TxVersion,
        Zip244Digests,
        coinbase::is_coinbase,
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
        bundle::TxIn,
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
#[cfg(target_pointer_width = "64")]
fn transaction_size_excludes_absent_shielded_bundles() {
    /// Upper bound on the in-memory size of a [`Transaction`] on 64-bit targets. Shielded
    /// bundles are boxed, so an absent bundle costs one pointer; storing any of them
    /// inline would exceed this bound.
    const MAX_TRANSACTION_SIZE: usize = 168;

    assert!(core::mem::size_of::<Transaction>() <= MAX_TRANSACTION_SIZE);
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

/// ZIP 248 tells wallets to use the oldest valid format, so NU8 keeps suggesting
/// V6. V7 stays valid in NU8 for callers that opt in.
#[test]
#[cfg(zcash_unstable = "nu8")]
fn suggested_version_for_nu8_is_v6() {
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::Nu8),
        TxVersion::V6
    );
    assert!(TxVersion::V7.valid_in_branch(BranchId::Nu8));
}

/// Cross-checks the v7 digest tree against values computed independently of this
/// implementation, directly from the [ZIP 248] text with Python's
/// `hashlib.blake2b` (see `scripts/zip248_vectors.py`):
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
        "600c2dd76c15b3683691259781ce79a3757cc7f95714cfbccdb49f69ddf15958",
    );
    assert_eq!(
        hex::encode(tx.auth_commitment().as_bytes()),
        "d3a128d379cd32a6ec49acb8e5da337ed38e80c068fa0e33e4baf2786867241a",
    );
}

/// As [`v7_empty_transaction_matches_zip248_digests`], for a transaction whose
/// only value pool delta is the fee. This pins [ZIP 248]'s per-entry encoding
/// of `mValuePoolDeltas` — `compactSize(bundleType) ||
/// compactSize(bundleVariant) || value` — which is specific to this format and
/// has no ZIP 244 counterpart.
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
        "0778b29c2439d15380c97f32c02c0430fdfcbc94ecde260f4503a7fee547191e",
    );
}

/// A typed Sapling bundle with a forced value balance.
#[cfg(all(test, zcash_unstable = "nu8"))]
fn sapling_bundle_with_value_balance(
    bundle: &sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
    value_balance: ZatBalance,
) -> sapling::Bundle<sapling::bundle::Authorized, ZatBalance> {
    sapling::Bundle::from_parts(
        bundle.shielded_spends().to_vec(),
        bundle.shielded_outputs().to_vec(),
        value_balance,
        *bundle.authorization(),
    )
    .expect("the fixture has Sapling spends")
}

/// A typed transaction with no bundles and the given value pool deltas.
#[cfg(all(test, zcash_unstable = "nu8"))]
fn v7_data_with_deltas(
    value_pool_deltas: crate::transaction::zip248::ValuePoolDeltas,
    transparent_bundle: Option<
        ::transparent::bundle::Bundle<
            ::transparent::bundle::Authorized,
            zcash_protocol::value::Zatoshis,
        >,
    >,
    #[cfg(feature = "sapling")] sapling_bundle: Option<
        ::sapling::Bundle<::sapling::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    >,
    #[cfg(feature = "orchard")] orchard_bundle: Option<
        ::orchard::Bundle<::orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    >,
    #[cfg(feature = "orchard")] ironwood_bundle: Option<
        ::orchard::Bundle<::orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    >,
) -> crate::transaction::TransactionData<crate::transaction::Authorized> {
    crate::transaction::TransactionData::from_parts_with_value_pool_deltas(
        crate::transaction::TxVersion::V7,
        zcash_protocol::consensus::BranchId::Nu8,
        0,
        zcash_protocol::consensus::BlockHeight::from_u32(100),
        value_pool_deltas,
        transparent_bundle,
        None,
        #[cfg(feature = "sapling")]
        sapling_bundle,
        #[cfg(feature = "orchard")]
        orchard_bundle,
        #[cfg(feature = "orchard")]
        ironwood_bundle,
        None,
    )
}

/// A value pool delta map holding one entry for `bundle_type` plus an equally
/// sized fee entry, so the deltas balance with no transparent bundle.
#[cfg(all(test, zcash_unstable = "nu8"))]
fn balanced_vp(
    bundle_type: crate::transaction::zip248::BundleType,
) -> crate::transaction::zip248::ValuePoolDeltas {
    let mut vp = crate::transaction::zip248::ValuePoolDeltas::empty();
    vp.insert(
        bundle_type,
        crate::transaction::zip248::BundleVariant::DEFAULT,
        zcash_protocol::value::ZatBalance::from_i64(1).unwrap(),
    )
    .unwrap();
    vp.set_fee(zcash_protocol::value::Zatoshis::const_from_u64(1))
        .unwrap();
    vp
}

/// A typed bundle at the default variant paired with a non-default variant
/// delta for its bundle type cannot be written as v7, so `freeze` must reject it
/// rather than compute an identifier for an unserializable transaction.
#[test]
#[cfg(all(zcash_unstable = "nu8", feature = "sapling"))]
fn v7_freeze_rejects_nondefault_value_pool_delta_variant() {
    use crate::transaction::zip248::{BundleType, BundleVariant, ValuePoolDeltas};

    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = sapling_bundle_with_value_balance(
        &test_sapling_bundle(&mut runner),
        ZatBalance::from_i64(-1).unwrap(),
    );

    let mut vp = ValuePoolDeltas::empty();
    vp.insert(
        BundleType::SAPLING,
        BundleVariant::from_u64(1),
        ZatBalance::from_i64(-1).unwrap(),
    )
    .unwrap();

    let error = v7_data_with_deltas(vp, None, Some(bundle), None, None)
        .freeze()
        .unwrap_err();
    assert_eq!(error.kind(), corez::io::ErrorKind::InvalidInput);
}

/// ZIP 248 has one bundle-wide Sapling anchor, so spends with different anchors
/// are unrepresentable.
#[test]
#[cfg(all(zcash_unstable = "nu8", feature = "sapling"))]
fn v7_freeze_rejects_mixed_sapling_spend_anchors() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = sapling_bundle_with_value_balance(
        &sapling_bundle_with_distinct_spend_anchors(&test_sapling_bundle(&mut runner)),
        ZatBalance::from_i64(-1).unwrap(),
    );

    let mut vp = crate::transaction::zip248::ValuePoolDeltas::empty();
    vp.set_sapling(ZatBalance::from_i64(-1).unwrap()).unwrap();

    let error = v7_data_with_deltas(vp, None, Some(bundle), None, None)
        .freeze()
        .unwrap_err();
    assert_eq!(error.kind(), corez::io::ErrorKind::InvalidInput);
}

/// ZIP 248 omits an empty effecting bundle, but the typed transparent bundle
/// slot can hold one.
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_freeze_rejects_empty_typed_transparent_bundle() {
    let empty = transparent::Bundle {
        vin: vec![],
        vout: vec![],
        authorization: transparent::Authorized,
    };

    let error = v7_data_with_deltas(
        crate::transaction::zip248::ValuePoolDeltas::empty(),
        Some(empty),
        #[cfg(feature = "sapling")]
        None,
        #[cfg(feature = "orchard")]
        None,
        #[cfg(feature = "orchard")]
        None,
    )
    .freeze()
    .unwrap_err();
    assert_eq!(error.kind(), corez::io::ErrorKind::InvalidInput);
}

/// Empty typed Sapling, Orchard, and Ironwood bundles are unrepresentable:
/// their constructors return `None` for an empty spend/output or action list,
/// so there is no typed value to freeze. The byte layer's present-empty
/// full-validation cases cover them.
#[test]
#[cfg(all(zcash_unstable = "nu8", feature = "sapling", feature = "orchard"))]
fn empty_shielded_typed_bundles_are_unrepresentable() {
    let sapling_empty = sapling::Bundle::from_parts(
        vec![],
        vec![],
        ZatBalance::zero(),
        sapling::bundle::Authorized {
            binding_sig: redjubjub::Signature::from([0; 64]),
        },
    );
    assert!(sapling_empty.is_none());
}

/// A type-6 value pool delta is rejected by `freeze` whether or not ZIP 233
/// construction support is compiled in: activation is a property of the
/// registry and the consensus branch, not of a feature.
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_freeze_rejects_unactivated_zip233_delta() {
    use crate::transaction::zip248::{BundleType, BundleVariant, ValuePoolDeltas};

    for value in [1i64, -1] {
        let mut vp = ValuePoolDeltas::empty();
        vp.insert(
            BundleType::ZIP233_NSM,
            BundleVariant::DEFAULT,
            ZatBalance::from_i64(value).unwrap(),
        )
        .unwrap();

        let error = v7_data_with_deltas(
            vp,
            None,
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
            #[cfg(feature = "orchard")]
            None,
        )
        .freeze()
        .unwrap_err();
        assert_eq!(error.kind(), corez::io::ErrorKind::InvalidInput);
    }
}

#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_is_enabled_by_nu8_and_roundtrips() {
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::Nu8),
        TxVersion::V6
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

#[cfg(all(test, zcash_unstable = "nu8"))]
fn bundle_with_flags(
    bundle: &orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
    flags: u8,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    orchard::Bundle::try_from_parts(
        bundle.actions().clone(),
        orchard::bundle::Flags::from_byte(flags, bundle.bundle_version())
            .expect("the flag byte is representable under the bundle version"),
        *bundle.value_balance(),
        *bundle.anchor(),
        bundle.authorization().clone(),
        bundle.bundle_version(),
    )
    .expect("the flag byte is representable under the bundle version")
}

#[cfg(all(test, zcash_unstable = "nu8"))]
fn orchard_with_balance(
    bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
    balance: ZatBalance,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    orchard::Bundle::try_from_parts(
        bundle.actions().clone(),
        *bundle.flags(),
        balance,
        *bundle.anchor(),
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

#[cfg(all(test, zcash_unstable = "nu8"))]
fn sapling_bundle_with_distinct_spend_anchors(
    bundle: &sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
) -> sapling::Bundle<sapling::bundle::Authorized, ZatBalance> {
    let mut spends: Vec<_> = bundle.shielded_spends().to_vec();
    if spends.len() < 2 {
        spends.push(spends[0].clone());
    }
    let spends = spends
        .iter()
        .enumerate()
        .map(|(index, spend)| {
            sapling::bundle::SpendDescription::from_parts(
                spend.cv().clone(),
                test_sapling_anchor(index as u8 + 1),
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
    .expect("the fixture has Sapling spends")
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
fn v7_sapling_spends_digest_hashes_cv_and_rk_under_the_v6_personalization() {
    use crate::transaction::txid::{SaplingSpendDigestParts, hash_sapling_spends_parts};

    // [ZIP 248 §T.3.2a.ii] hashes `nullifier` into the compact digest and
    // `cv || rk` into the non-compact digest, the latter under
    // `ZTxIdSSpendNH_v6`. Fixed inputs keep the expected value independent of
    // the bundle generation code.
    let parts = |anchor: [u8; 32]| SaplingSpendDigestParts {
        cv: [0x11; 32],
        nullifier: [0x22; 32],
        anchor,
        rk: [0x44; 32],
    };

    // Computed with an independent BLAKE2b-256 implementation from the ZIP
    // 248 §T.3.2a digests.
    let expected = "c1402185efee34caedd8e93cb2194686cd7b1e4373499257c7b8a74f85e5f381";
    assert_eq!(
        hex::encode(hash_sapling_spends_parts(TxVersion::V7, [parts([0x33; 32])]).as_bytes()),
        expected,
    );

    // The anchor is authorizing data in v7, so re-anchoring must not change the
    // effects digest.
    assert_eq!(
        hash_sapling_spends_parts(TxVersion::V7, [parts([0x33; 32])]),
        hash_sapling_spends_parts(TxVersion::V7, [parts([0x55; 32])]),
    );
    // v5 still commits to it.
    assert_ne!(
        hash_sapling_spends_parts(TxVersion::V5, [parts([0x33; 32])]),
        hash_sapling_spends_parts(TxVersion::V5, [parts([0x55; 32])]),
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

    #[cfg(zcash_unstable = "nu8")]
    let actual = actual.0;
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
    #[cfg(zcash_unstable = "nu8")]
    let actual = actual.0;

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
pub(crate) struct TestTransparentAuth {
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
pub(crate) fn with_test_transparent_auth(
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
impl TransparentAuthorizingContext<Zatoshis> for TestTransparentAuth {
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
pub(crate) struct TestUnauthorized;

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
            .filter(|b| !is_coinbase(precomputed.tx()) && !b.vin.is_empty())
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

#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_txid_digester_builds_the_complete_tree() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    let mut vp = zip248::ValuePoolDeltas::empty();
    vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();

    let tx = TransactionData::<Authorized>::from_parts_with_value_pool_deltas(
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

    let conventional = tx.digest(TxIdDigester);
    let own = tx.txid_digests();
    assert_eq!(conventional.header_digest, own.header_digest);
    assert!(conventional.transparent_digests.is_none());
    assert!(conventional.coinbase_digest.is_none());
    assert!(conventional.sapling_digest.is_none());
    assert!(conventional.orchard_digest.is_none());
    assert!(conventional.ironwood_digest.is_none());
    assert_eq!(
        conventional.value_pool_deltas_digest,
        own.value_pool_deltas_digest
    );
    assert!(conventional.value_pool_deltas_digest.is_some());

    let txid = super::txid::to_txid(TxVersion::V7, BranchId::Nu8, &conventional).unwrap();
    assert_eq!(txid, tx.freeze().unwrap().txid());
}

#[cfg(all(test, zcash_unstable = "nu8"))]
mod zip248_tests {
    use super::super::zip248;
    use alloc::vec::Vec;
    use zcash_protocol::value::{ZatBalance, Zatoshis};

    /// Writes one `mEffectBundles`/`mAuthBundles` TLV entry.
    fn write_framing(buf: &mut Vec<u8>, bundle_type: u64, bundle_variant: u64, data: &[u8]) {
        crate::transaction::bytes::write_bundle_data_framing(
            &mut *buf,
            zip248::BundleId::new(
                zip248::BundleType::from_u64(bundle_type),
                zip248::BundleVariant::from_u64(bundle_variant),
            ),
            data,
        )
        .unwrap();
    }

    #[test]
    fn value_pool_deltas_write_read_roundtrip() {
        use crate::transaction::bytes::ValuePoolDeltaBytes;

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
            let entry = ValuePoolDeltaBytes::read(&mut cursor).unwrap();
            vp2.insert(
                entry.bundle_type(),
                entry.bundle_variant(),
                ZatBalance::from_i64(entry.value()).unwrap(),
            )
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

    /// Verifies that a v7 transaction with an unknown bundle type can be
    /// parsed and re-serialized at the byte layer (ZIP 248 forward
    /// compatibility), and that the typed compatibility path rejects it rather
    /// than inventing a digest.
    #[test]
    fn unknown_bundle_roundtrip() {
        use super::super::{
            Transaction, TxVersion,
            bytes::{
                BundleType, BundleVariant, OpaqueAuthBundleBytes, OpaqueEffectBundleBytes,
                TransactionBodyBytes, TransactionBytes, V7AuthBundleBytes, V7EffectBundleBytes,
                V7TransactionBodyBytes,
            },
        };
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        let id = zip248::BundleId::new(BundleType::from_u64(42), BundleVariant::from_u64(0));
        let opaque = OpaqueEffectBundleBytes::from_parts(id, vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let opaque_auth = OpaqueAuthBundleBytes::from_parts(id, vec![0xCA, 0xFE]).unwrap();
        let body = V7TransactionBodyBytes::from_parts(
            vec![],
            vec![V7EffectBundleBytes::Opaque(opaque)],
            vec![V7AuthBundleBytes::Opaque(opaque_auth)],
        )
        .unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(u32::from(BranchId::Nu8)),
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
        let unknowns: Vec<_> = body.opaque_effect_bundles().collect();
        assert_eq!(unknowns.len(), 1);
        assert_eq!(unknowns[0].id().bundle_type().to_u64(), 42);
        assert_eq!(unknowns[0].payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let unknown_auth: Vec<_> = body.opaque_auth_bundles().collect();
        assert_eq!(unknown_auth.len(), 1);
        assert_eq!(unknown_auth[0].payload(), &[0xCA, 0xFE]);

        let mut buf2 = Vec::new();
        tx2.write(&mut buf2).unwrap();
        assert_eq!(buf, buf2);

        // The typed compatibility path cannot represent the opaque effecting or
        // authorizing payloads, so it rejects the transaction instead of
        // inventing a digest.
        assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
    }

    /// Value-pool-only entries keep their open identifiers in the typed map,
    /// because they carry no effecting or authorizing payload that the typed
    /// representation would have to interpret.
    #[test]
    fn unknown_value_pool_delta_is_retained_in_typed_transaction() {
        use super::super::{
            Transaction, TxVersion,
            bytes::{
                BundleType, BundleVariant, TransactionBodyBytes, TransactionBytes,
                V7TransactionBodyBytes, ValuePoolDeltaBytes,
            },
        };
        use zcash_protocol::consensus::{BlockHeight, BranchId};
        use zcash_protocol::value::ZatBalance;

        const UNKNOWN_BUNDLE_TYPE: u64 = 77;
        let bundle_type = BundleType::from_u64(UNKNOWN_BUNDLE_TYPE);
        let delta =
            ValuePoolDeltaBytes::from_parts(bundle_type, BundleVariant::DEFAULT, 123).unwrap();
        let body = V7TransactionBodyBytes::from_parts(vec![delta], vec![], vec![]).unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(u32::from(BranchId::Nu8)),
            0,
            BlockHeight::from_u32(100),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();

        let mut buf = Vec::new();
        tx.write(&mut buf).unwrap();

        let typed = Transaction::read(&buf[..], BranchId::Nu8).unwrap();
        assert_eq!(
            typed.value_pool_deltas().zec_value(bundle_type),
            Some(ZatBalance::from_i64(123).unwrap())
        );
        assert_eq!(
            typed.value_pool_deltas().bundle_variant(bundle_type),
            Some(BundleVariant::DEFAULT)
        );
    }

    // -- Consensus rule tests --------------------------------------------------

    mod consensus_rules {
        use super::super::super::{
            Authorized, Transaction, TransactionData, TxVersion, V7ConsensusError, ZatBalance,
            sprout, zip248,
        };
        use alloc::vec::Vec;
        use zcash_encoding::CompactSize;
        use zcash_protocol::consensus::{BlockHeight, BranchId};
        use zcash_protocol::value::{BalanceError, MAX_BALANCE, Zatoshis};

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
        fn transparent_bundle() -> ::transparent::bundle::Bundle<
            ::transparent::bundle::Authorized,
            zcash_protocol::value::Zatoshis,
        > {
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
        fn transparent_outputs_only() -> ::transparent::bundle::Bundle<
            ::transparent::bundle::Authorized,
            zcash_protocol::value::Zatoshis,
        > {
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
            transparent: ::transparent::bundle::Bundle<
                ::transparent::bundle::Authorized,
                zcash_protocol::value::Zatoshis,
            >,
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

        /// Builds a typed v7 transaction with a transparent bundle and an
        /// Ironwood bundle, for balance tests that need a second effecting
        /// bundle type.
        fn make_v7_with_ironwood(
            vp: zip248::ValuePoolDeltas,
            transparent: ::transparent::bundle::Bundle<
                ::transparent::bundle::Authorized,
                zcash_protocol::value::Zatoshis,
            >,
            ironwood: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
        ) -> TransactionData<Authorized> {
            let ironwood = super::super::orchard_with_balance(
                ironwood,
                vp.ironwood_value().unwrap_or(ZatBalance::zero()),
            );
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
                Some(ironwood),
                None,
            )
        }

        /// Builds a coinbase bundle paying out `subsidy` zatoshis with
        /// `lockbox` of it deposited into the lockbox.
        fn coinbase_bundle(subsidy: u64, lockbox: u64) -> zip248::CoinbaseBundle {
            zip248::CoinbaseBundle::from_parts(
                BlockHeight::from(100u32),
                Zatoshis::from_u64(subsidy).unwrap(),
                Zatoshis::from_u64(lockbox).unwrap(),
                vec![],
                vec![],
                None,
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

        /// Records a fee bundle value. [`zip248::ValuePoolDeltas::set_fee`]
        /// stores the negative delta of a fee-paying transaction; a coinbase
        /// collects fees, so its delta is positive.
        fn collect_fee(vp: &mut zip248::ValuePoolDeltas, fee: i64) {
            vp.insert(
                zip248::BundleType::FEE,
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(fee).unwrap(),
            )
            .unwrap();
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
        fn coinbase_vp_delta_must_account_for_the_fee_contribution() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Issue 100, lock 20, gross fees 10. The ZIP 235 contribution is
            // 6, so the required delta is 74, not 80.
            vp.set_coinbase(ZatBalance::from_i64(80).unwrap()).unwrap();
            collect_fee(&mut vp, 10);
            vp.set_transparent(ZatBalance::from_i64(-90).unwrap())
                .unwrap();
            let tx = make_v7_coinbase(vp, coinbase_bundle(100, 20));
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::CoinbaseValueDeltaMismatch {
                    expected: 74,
                    actual: ZatBalance::from_i64(80).unwrap(),
                }),
            );
        }

        #[test]
        fn balanced_coinbase_passes() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // The bundle contributes 74 (100 subsidy less the 20 lockbox
            // deposit and the 6 fee contribution) and the fee bundle
            // contributes the gross 10; the transparent outputs consume all
            // 84.
            vp.set_coinbase(ZatBalance::from_i64(74).unwrap()).unwrap();
            collect_fee(&mut vp, 10);
            vp.set_transparent(ZatBalance::from_i64(-84).unwrap())
                .unwrap();
            let tx = make_v7_coinbase(vp, coinbase_bundle(100, 20));
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }

        /// A coinbase transaction collects fees rather than paying them, so
        /// `fee_paid` reports that it does not know, even when the transaction
        /// balances.
        #[test]
        fn coinbase_fee_paid_is_unknown() {
            use ::transparent::{
                address::Script,
                bundle::{Authorized as TransparentAuthorized, Bundle, TxOut},
            };

            let mut vp = zip248::ValuePoolDeltas::empty();
            // Subsidy 100, lockbox 20, gross fees 10: the bundle contributes
            // 74 and the transparent outputs consume the remaining 84.
            vp.set_coinbase(ZatBalance::from_i64(74).unwrap()).unwrap();
            collect_fee(&mut vp, 10);
            vp.set_transparent(ZatBalance::from_i64(-84).unwrap())
                .unwrap();

            let transparent = Bundle {
                vin: vec![],
                vout: vec![TxOut::new(
                    Zatoshis::from_u64(84).unwrap(),
                    Script::default(),
                )],
                authorization: TransparentAuthorized,
            };
            let tx = TransactionData::<Authorized>::from_parts_with_value_pool_deltas(
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
                Some(coinbase_bundle(100, 20)),
            );
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));

            assert_eq!(
                tx.fee_paid(|_| Ok::<_, zcash_protocol::value::BalanceError>(None))
                    .unwrap(),
                None,
            );
        }

        /// A non-coinbase v7 transaction's fee is explicit, so it is known
        /// without resolving any previous output.
        #[test]
        fn non_coinbase_fee_paid_needs_no_prevouts() {
            /// Called if the prevout callback is used, which it must not be.
            fn panic_prevout(
                _: &::transparent::bundle::OutPoint,
            ) -> Result<Option<Zatoshis>, zcash_protocol::value::BalanceError> {
                panic!("the explicit v7 fee must not consult the prevout callback")
            }

            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_transparent(ZatBalance::from_i64(100).unwrap())
                .unwrap();
            collect_fee(&mut vp, -100);

            let tx = make_v7_with_transparent(vp, transparent_outputs_only());
            assert_eq!(
                tx.fee_paid(panic_prevout).unwrap(),
                Some(Zatoshis::from_u64(100).unwrap()),
            );
        }

        /// An absent fee entry reads as zero.
        #[test]
        fn non_coinbase_fee_paid_defaults_to_zero() {
            let tx = make_v7_with_transparent(
                zip248::ValuePoolDeltas::empty(),
                transparent_outputs_only(),
            );
            assert_eq!(
                tx.fee_paid(|_| Ok::<_, zcash_protocol::value::BalanceError>(None))
                    .unwrap(),
                Some(Zatoshis::ZERO),
            );
        }

        #[test]
        fn non_coinbase_fee_paid_rejects_positive_delta() {
            /// The smallest positive fee delta.
            const MIN_POSITIVE_DELTA: i64 = 1;

            for value in [MIN_POSITIVE_DELTA, MAX_BALANCE] {
                let mut vp = zip248::ValuePoolDeltas::empty();
                collect_fee(&mut vp, value);
                let data = make_v7_with_transparent(vp, transparent_bundle());
                assert_eq!(
                    data.fee_paid(|_| -> Result<Option<Zatoshis>, BalanceError> {
                        panic!("the explicit v7 fee must not consult the prevout callback")
                    }),
                    Err(BalanceError::Underflow),
                );

                let tx = data.freeze().unwrap();
                let mut bytes = Vec::new();
                tx.write(&mut bytes).unwrap();
                let parsed = Transaction::read(&bytes[..], BranchId::Nu8).unwrap();
                assert_eq!(
                    parsed.fee_paid(|_| -> Result<Option<Zatoshis>, BalanceError> {
                        panic!("the explicit v7 fee must not consult the prevout callback")
                    }),
                    Err(BalanceError::Underflow),
                );
            }
        }

        #[test]
        fn coinbase_bundle_rejects_lockbox_above_subsidy() {
            assert!(
                zip248::CoinbaseBundle::from_parts(
                    BlockHeight::from(100u32),
                    Zatoshis::from_u64(2).unwrap(),
                    Zatoshis::from_u64(3).unwrap(),
                    vec![],
                    vec![],
                    None,
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
                    vec![],
                    None,
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
                        vec![],
                        None,
                    )
                    .is_none()
                );
            }
        }

        #[test]
        fn coinbase_bundle_bytes_roundtrip() {
            let bundle = crate::transaction::bytes::CoinbaseBundleBytes::from_parts(
                BlockHeight::from(123_456u32),
                312_500_000,
                31_250_000,
                b"miner data".to_vec(),
                vec![],
                None,
            )
            .expect("coinbase byte bundle construction is infallible");

            let mut buf = alloc::vec::Vec::new();
            bundle.write(&mut buf).unwrap();
            let decoded = crate::transaction::bytes::CoinbaseBundleBytes::read(&buf[..]).unwrap();
            assert_eq!(decoded, bundle);

            let mut rewritten = alloc::vec::Vec::new();
            decoded.write(&mut rewritten).unwrap();
            assert_eq!(rewritten, buf);
        }

        #[test]
        fn typed_coinbase_bundle_writes_expected_encoding() {
            let bundle = zip248::CoinbaseBundle::from_parts(
                BlockHeight::from(123_456u32),
                Zatoshis::from_u64(312_500_000).unwrap(),
                Zatoshis::from_u64(31_250_000).unwrap(),
                b"miner data".to_vec(),
                vec![],
                None,
            )
            .expect("valid coinbase bundle");

            let bytes = crate::transaction::bytes::CoinbaseBundleBytes::from(&bundle);
            let mut encoded = alloc::vec::Vec::new();
            bytes.write(&mut encoded).unwrap();

            let mut expected = alloc::vec::Vec::new();
            expected.extend_from_slice(&123_456u32.to_le_bytes());
            expected.extend_from_slice(&312_500_000u64.to_le_bytes());
            expected.extend_from_slice(&31_250_000u64.to_le_bytes());
            CompactSize::write(&mut expected, b"miner data".len()).unwrap();
            expected.extend_from_slice(b"miner data");
            // The zero miner-signal count is committed and written even with no
            // signals.
            CompactSize::write(&mut expected, 0).unwrap();

            assert_eq!(encoded, expected);
            assert_eq!(bytes.to_coinbase_bundle().unwrap(), bundle);
        }

        #[test]
        fn non_coinbase_fee_delta_must_be_nonpositive() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Manually insert a positive fee delta (simulating a coinbase-style
            // fee entry in a non-coinbase transaction).
            vp.insert(
                zip248::BundleType::FEE,
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

        fn sprout_bundle() -> sprout::Bundle {
            sprout::Bundle {
                joinsplits: vec![],
                joinsplit_pubkey: [0; 32],
                joinsplit_sig: [0; 64],
            }
        }

        /// ZIP 248 has no Sprout bundle type, so the typed consensus check
        /// rejects one rather than leaving the failure to serialization.
        #[test]
        fn sprout_bundle_is_rejected() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();
            vp.set_transparent(ZatBalance::from_i64(1000).unwrap())
                .unwrap();

            let tx = TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                vp,
                Some(transparent_bundle()),
                Some(sprout_bundle()),
                None,
                None,
                None,
                None,
            );
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::SproutBundlePresent)
            );
            // Serialization rejects it too, before writing anything.
            let mut wire = Vec::new();
            let unfrozen = crate::transaction::Transaction {
                txid: crate::transaction::TxId::from_bytes([0; 32]),
                data: tx.clone(),
            };
            assert!(unfrozen.write_v7(&mut wire).is_err());
            assert!(tx.freeze().is_err());
            assert!(wire.is_empty());
        }

        /// Value conservation sums every entry together, whatever its bundle
        /// type.
        #[test]
        fn vp_deltas_balance_across_bundle_types() {
            let mut runner = proptest::test_runner::TestRunner::default();
            let ironwood = super::super::test_ironwood_bundle(&mut runner);

            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.insert(
                zip248::BundleType::TRANSPARENT,
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(2000).unwrap(),
            )
            .unwrap();
            vp.insert(
                zip248::BundleType::FEE,
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(-1000).unwrap(),
            )
            .unwrap();
            vp.insert(
                zip248::BundleType::IRONWOOD,
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(-1000).unwrap(),
            )
            .unwrap();
            let tx = make_v7_with_ironwood(vp, transparent_bundle(), ironwood);
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }

        /// The sum is accumulated widened, so large offsetting entries do not
        /// spuriously fail a transaction whose total is zero.
        #[test]
        fn vp_deltas_balance_with_large_offsetting_entries() {
            let mut runner = proptest::test_runner::TestRunner::default();
            let ironwood = super::super::test_ironwood_bundle(&mut runner);

            let max = i64::try_from(zcash_protocol::value::MAX_MONEY).unwrap();
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.insert(
                zip248::BundleType::TRANSPARENT,
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(max).unwrap(),
            )
            .unwrap();
            vp.insert(
                zip248::BundleType::FEE,
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(-(max - 1)).unwrap(),
            )
            .unwrap();
            vp.insert(
                zip248::BundleType::IRONWOOD,
                zip248::BundleVariant::DEFAULT,
                ZatBalance::from_i64(-1).unwrap(),
            )
            .unwrap();
            let tx = make_v7_with_ironwood(vp, transparent_bundle(), ironwood);
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }
    }

    // -- Parsing rule rejection tests ------------------------------------------

    mod parsing_rules {
        use super::super::super::{Transaction, zip248};
        use super::write_framing;
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
            buf.extend_from_slice(&value.to_le_bytes());
        }

        /// Writes an `mEffectBundles`/`mAuthBundles` TLV entry.
        fn write_bundle_entry(
            buf: &mut Vec<u8>,
            bundle_type: zip248::BundleType,
            variant: zip248::BundleVariant,
            data: &[u8],
        ) {
            write_framing(&mut *buf, bundle_type.to_u64(), variant.to_u64(), data);
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
        /// data, so ZIP 248 requires its `mAuthBundles` entry to be absent.
        #[test]
        fn transparent_outputs_only_reject_auth_entry_presence() {
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

            // A present-but-empty auth entry is prohibited.
            let mut with_empty_auth = v7_header(BranchId::Nu8);
            CompactSize::write(&mut with_empty_auth, 0).unwrap(); // nValuePoolDeltas
            CompactSize::write(&mut with_empty_auth, 1).unwrap(); // nEffectBundles
            write_bundle_entry(&mut with_empty_auth, transparent, variant, &effects);
            CompactSize::write(&mut with_empty_auth, 1).unwrap(); // nAuthBundles
            write_bundle_entry(&mut with_empty_auth, transparent, variant, &[]);

            assert!(
                crate::transaction::bytes::TransactionBytes::read(&with_empty_auth[..]).is_err()
            );
            assert!(Transaction::read(&with_empty_auth[..], BranchId::Nu8).is_err());
        }

        /// An empty transparent effecting payload must be omitted.
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

            assert!(crate::transaction::bytes::TransactionBytes::read(&buf[..]).is_err());
            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
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
            use crate::transaction::bytes::{TransactionBytes, V7EffectBundleBytes};

            let opaque = [0xAAu8; 8];
            let unknown_variant =
                zip248::BundleVariant::from_u64(zip248::BundleVariant::DEFAULT.to_u64() + 1);
            let buf = v7_with_effect_bundle(zip248::BundleType::SAPLING, unknown_variant, &opaque);

            let tx = TransactionBytes::read(&buf[..]).unwrap();
            let body = tx.body().as_v7().unwrap();
            assert!(matches!(
                body.effect_bundles()[0],
                V7EffectBundleBytes::Opaque(_)
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
            write_framing(&mut buf, 1, 0, &coinbase_effects());
            CompactSize::write(&mut *buf, 1).unwrap();
            write_framing(&mut buf, 1, 0, &[0xAA]);

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_oversized_coinbase_data() {
            let mut effects = coinbase_effects();
            // Replace the empty `coinbaseData` with one byte over the limit.
            // Dropping the trailing signal count keeps the truncation pointed
            // at the length prefix rather than the count.
            effects.pop();
            CompactSize::write(&mut effects, zip248::MAX_COINBASE_DATA_LEN + 1).unwrap();
            effects.extend_from_slice(&[0u8; zip248::MAX_COINBASE_DATA_LEN + 1]);
            CompactSize::write(&mut effects, 0).unwrap();

            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            write_framing(&mut buf, 1, 0, &effects);
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
            write_framing(&mut buf, 5, 0, &[0xAA]);
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
            write_framing(&mut buf, 2, 1, &[]);
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth

            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }

        #[test]
        fn rejects_auth_without_effect() {
            let mut buf = v7_header(BranchId::Nu8);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            write_framing(&mut buf, 2, 0, &[0xBB]);

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
            write_framing(&mut buf, 3, 0, &[0xAA]);
            write_framing(&mut buf, 0, 0, &[0xBB]);
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth
            assert!(Transaction::read(&buf[..], BranchId::Nu8).is_err());
        }
    }

    // -- Whole-transaction roundtrips for the v7 bundle types ------------------

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
                vec![],
                None,
            )
            .expect("valid coinbase bundle");

            let mut vp = zip248::ValuePoolDeltas::empty();
            // No fee bundle is present, so the NSM fee contribution is zero.
            let coinbase_delta = coinbase.value_pool_delta(Zatoshis::ZERO);
            vp.set_coinbase(coinbase_delta).unwrap();
            // Something has to consume what the coinbase bundle contributes;
            // a transparent output stands in for the outputs that would.
            vp.set_transparent(-coinbase_delta).unwrap();

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
                    // Each slot fixes its bundle version: the Orchard slot takes
                    // `orchard_v3`, the Ironwood slot `ironwood_v3`.
                    let bundle = crate::transaction::components::orchard::testing::rebuild_with_version(
                        bundle.clone(),
                        if as_ironwood {
                            orchard::bundle::BundleVersion::ironwood_v3()
                        } else {
                            orchard::bundle::BundleVersion::orchard_v3()
                        },
                    );
                    let (orchard, ironwood) = if as_ironwood {
                        vp.set_ironwood(value_balance).unwrap();
                        (None, Some(bundle))
                    } else {
                        vp.set_orchard(value_balance).unwrap();
                        (Some(bundle), None)
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
                zip248::BundleType::from_u64(8),
                zip248::BundleVariant::from_u64(0),
                ZatBalance::from_i64(99_000).unwrap(),
            )
            .unwrap();
            // Two unknown bundle types inserted in reverse order: the map must
            // emit them by bundle type.
            for (bundle_type, value) in [(10u64, 2i64), (9u64, 1i64)] {
                vp.insert(
                    zip248::BundleType::from_u64(bundle_type),
                    zip248::BundleVariant::from_u64(0),
                    ZatBalance::from_i64(value).unwrap(),
                )
                .unwrap();
            }

            let types: Vec<u64> = vp
                .to_wire_entries()
                .iter()
                .map(|entry| entry.bundle_type().to_u64())
                .collect();
            assert_eq!(types, vec![3, 5, 8, 9, 10]);
        }
    }

    // -- Sighash version info error tests --------------------------------------

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

    mod v7_validation {
        use super::super::super::{
            Transaction, TransactionBytes, TxVersion, V7BundleMap, V7ConsensusError,
            V7ValidationError,
            bytes::{TransactionBodyBytes, V5TransactionBodyBytes},
            zip248,
        };
        use super::write_framing;
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

        fn vp_entry(bundle_type: u64, variant: u64, value: i64) -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, bundle_type as usize).unwrap();
            CompactSize::write(&mut buf, variant as usize).unwrap();
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
                write_framing(&mut buf, *bundle_type, *variant, data);
            }
            CompactSize::write(&mut buf, auth.len()).unwrap();
            for (bundle_type, variant, data) in auth {
                write_framing(&mut buf, *bundle_type, *variant, data);
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

        fn transparent_bundle() -> ::transparent::bundle::Bundle<
            ::transparent::bundle::Authorized,
            zcash_protocol::value::Zatoshis,
        > {
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
            let bytes = wire_tx(BranchId::Nu8, &[vp_entry(0, 0, -1000)], &[], &[]);
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

        /// An empty shielded effect entry must be omitted.
        fn empty_sapling_effects() -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, 0).unwrap();
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        }

        fn empty_orchard_effects() -> Vec<u8> {
            let mut buf = Vec::new();
            CompactSize::write(&mut buf, 0).unwrap();
            buf
        }

        #[test]
        fn empty_sapling_effect_without_auth_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(2, 0, empty_sapling_effects())], &[]);
            assert!(Transaction::read(&bytes[..], BranchId::Nu8).is_err());
            assert!(TransactionBytes::read(&bytes[..]).is_err());
        }

        #[test]
        fn empty_orchard_effect_without_auth_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(3, 0, empty_orchard_effects())], &[]);
            assert!(Transaction::read(&bytes[..], BranchId::Nu8).is_err());
            assert!(TransactionBytes::read(&bytes[..]).is_err());
        }

        #[test]
        fn empty_ironwood_effect_without_auth_is_rejected() {
            let bytes = wire_tx(BranchId::Nu8, &[], &[(4, 0, empty_orchard_effects())], &[]);
            assert!(Transaction::read(&bytes[..], BranchId::Nu8).is_err());
            assert!(TransactionBytes::read(&bytes[..]).is_err());
        }

        #[test]
        fn unbalanced_transparent_delta_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, -1000)],
                &[(0, 0, transparent_outputs_only_effects())],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::ValueImbalance { sum: -1000 }
                ))
            ));
        }

        #[test]
        fn balanced_transparent_and_value_only_deltas_pass_validation() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, 1000), vp_entry(5, 0, -1000)],
                &[(0, 0, transparent_input_effects(true))],
                &[(0, 0, transparent_auth(0))],
            );
            assert_eq!(validate(&bytes).unwrap().version(), TxVersion::V7);
        }

        #[test]
        fn fee_only_delta_is_rejected_as_unbalanced() {
            let bytes = wire_tx(BranchId::Nu8, &[vp_entry(5, 0, -1000)], &[], &[]);
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::ValueImbalance { sum: -1000 }
                ))
            ));
        }

        #[test]
        fn coinbase_delta_mismatch_is_rejected_by_validation() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(1, 0, 1000)],
                &[(1, 0, coinbase_effects(0, 0))],
                &[],
            );
            assert!(matches!(
                validate(&bytes),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseValueDeltaMismatch {
                        expected: 0,
                        actual
                    }
                )) if actual == ZatBalance::from_i64(1000).unwrap()
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
                &[vp_entry(5, 0, 1000)],
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
                &[vp_entry(5, 0, -1000)],
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
                &[vp_entry(0, 0, -3), vp_entry(1, 0, 3)],
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
        fn coinbase_value_delta_must_equal_subsidy_less_lockbox_and_fee_contribution() {
            // The bundle issues 100 and locks 20. The gross fee delta of 10
            // gives a ZIP 235 contribution of 6, so the required coinbase
            // delta is 74. A delta of 80 (the old subsidy-minus-lockbox rule)
            // must be rejected, and the correct 74 must be accepted.
            let rejected = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, -90), vp_entry(1, 0, 80), vp_entry(5, 0, 10)],
                &[
                    (0, 0, transparent_outputs_only_effects()),
                    (1, 0, coinbase_effects(100, 20)),
                ],
                &[],
            );
            assert!(matches!(
                validate(&rejected),
                Err(V7ValidationError::Consensus(
                    V7ConsensusError::CoinbaseValueDeltaMismatch {
                        expected: 74,
                        actual
                    }
                )) if actual == ZatBalance::from_i64(80).unwrap()
            ));

            let accepted = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, -84), vp_entry(1, 0, 74), vp_entry(5, 0, 10)],
                &[
                    (0, 0, transparent_outputs_only_effects()),
                    (1, 0, coinbase_effects(100, 20)),
                ],
                &[],
            );
            assert!(validate(&accepted).is_ok());
        }

        #[test]
        fn value_imbalance_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, 1000)],
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

        /// ZIP 233 is registered but not activated, so a type-6 delta is
        /// rejected before its sign is checked, whatever that sign is.
        #[test]
        fn zip233_delta_is_rejected_as_not_activated() {
            for value in [1000i64, -1000] {
                let bytes = wire_tx(
                    BranchId::Nu8,
                    &[vp_entry(0, 0, 1000), vp_entry(6, 0, value)],
                    &[(0, 0, transparent_input_effects(false))],
                    &[(0, 0, transparent_auth(0))],
                );
                assert_eq!(
                    validate(&bytes).unwrap_err(),
                    V7ValidationError::BundleNotActivated { bundle_type: 6 },
                );
                assert_eq!(
                    Transaction::read(&bytes[..], BranchId::Nu8)
                        .unwrap_err()
                        .kind(),
                    corez::io::ErrorKind::InvalidData,
                );
                let parsed = TransactionBytes::read(&bytes[..]).unwrap();
                let mut retained = Vec::new();
                parsed.write(&mut retained).unwrap();
                assert_eq!(retained, bytes);
            }
        }

        /// Direct typed construction agrees with the byte validator: activation
        /// is checked separately from registration.
        #[test]
        fn typed_zip233_delta_is_rejected_as_not_activated() {
            for value in [1i64, -1] {
                let mut vp = zip248::ValuePoolDeltas::empty();
                vp.insert(
                    zip248::BundleType::ZIP233_NSM,
                    zip248::BundleVariant::DEFAULT,
                    ZatBalance::from_i64(value).unwrap(),
                )
                .unwrap();

                let data = super::super::super::TransactionData::<
                    super::super::super::Authorized,
                >::from_parts_with_value_pool_deltas(
                    crate::transaction::TxVersion::V7,
                    BranchId::Nu8,
                    0,
                    BlockHeight::from_u32(100),
                    vp,
                    Some(transparent_bundle()),
                    None,
                    #[cfg(feature = "sapling")]
                    None,
                    #[cfg(feature = "orchard")]
                    None,
                    #[cfg(feature = "orchard")]
                    None,
                    None,
                );
                assert_eq!(
                    data.check_v7_consensus_rules(),
                    Err(V7ConsensusError::BundleNotActivated { bundle_type: 6 }),
                );
            }
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
                crate::transaction::bytes::transparent::LegacyTransparentBundleBytes::from_parts(
                    vec![],
                    vec![],
                ),
                None,
                None,
            );
            let tx = TransactionBytes::from_parts(
                crate::transaction::TxVersion::V5,
                Some(u32::from(BranchId::Nu5)),
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
                &[vp_entry(0, 0, 1000), vp_entry(5, 0, -1000)],
                &[(0, 0, transparent_input_effects(true))],
                &[(0, 0, transparent_auth(0))],
            );
            assert!(validate(&bytes).is_ok());
        }

        #[test]
        fn valid_coinbase_transaction_passes() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[vp_entry(0, 0, -2), vp_entry(1, 0, 2)],
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
                &[vp_entry(0, 0, 1000), vp_entry(5, 0, -1000)],
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

        /// Builds a balanced value pool delta map with one entry for
        /// `bundle_type` and an offsetting transparent entry.
        fn vp_with_bundle_entry(
            bundle_type: zip248::BundleType,
            balance: ZatBalance,
        ) -> zip248::ValuePoolDeltas {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_transparent(-balance).unwrap();
            vp.set_zec_value(
                zip248::BundleId::new(bundle_type, zip248::BundleVariant::DEFAULT),
                balance,
            )
            .unwrap();
            vp
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(4))]

            /// A Sapling entry balances against the transparent entry.
            #[test]
            fn sapling_delta_balances(
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
                    vp_with_bundle_entry(zip248::BundleType::SAPLING, *bundle.value_balance()),
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

            /// An Orchard entry balances against the transparent entry.
            #[test]
            fn orchard_delta_balances(
                bundle in crate::transaction::components::orchard::testing::arb_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("an Orchard bundle is only interesting when present", |b| b.is_some()),
            ) {
                let bundle = bundle.expect("filtered to Some");
                let balance = ZatBalance::from_i64(i64::from(*bundle.value_balance()).abs()).unwrap();
                let bundle = super::super::orchard_with_balance(bundle, balance);
                let tx = super::super::super::TransactionData::<super::super::super::Authorized>::from_parts_with_value_pool_deltas(
                    crate::transaction::TxVersion::V7,
                    BranchId::Nu8,
                    0,
                    BlockHeight::from_u32(100),
                    vp_with_bundle_entry(zip248::BundleType::ORCHARD, balance),
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
                        Some(super::super::orchard_with_balance(
                            bundle.clone(),
                            ZatBalance::from_i64(orchard_delta).unwrap(),
                        )),
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

            /// A transaction whose deltas sum to zero must not be rejected
            /// because an intermediate partial sum leaves the `ZatBalance`
            /// range.
            ///
            /// The ZIP 233 opt-in rejects nonzero ZIP 233 amounts, so this
            /// offsetting case is only applicable without it.
            #[cfg(not(zcash_unstable = "zip233"))]
            #[test]
            fn offsetting_value_pool_deltas_do_not_overflow(
                bundle in crate::transaction::components::orchard::testing::arb_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("an Orchard bundle is only interesting when present", |b| b.is_some()),
                ironwood in crate::transaction::components::orchard::testing::arb_ironwood_bundle_for_version(
                    crate::transaction::TxVersion::V7,
                ).prop_filter("an Ironwood bundle is only interesting when present", |b| b.is_some()),
            ) {
                let bundle = bundle.expect("filtered to Some");
                let ironwood = ironwood.expect("filtered to Some");
                let max = i64::try_from(MAX_MONEY).unwrap();
                let bundle = super::super::orchard_with_balance(
                    bundle,
                    ZatBalance::from_i64(max).unwrap(),
                );
                let ironwood = super::super::orchard_with_balance(
                    ironwood,
                    ZatBalance::from_i64(-max).unwrap(),
                );

                let mut vp = zip248::ValuePoolDeltas::empty();
                vp.set_transparent(ZatBalance::from_i64(max).unwrap()).unwrap();
                vp.set_orchard(ZatBalance::from_i64(max).unwrap()).unwrap();
                vp.set_ironwood(ZatBalance::from_i64(-max).unwrap()).unwrap();
                vp.set_fee(Zatoshis::from_u64(MAX_MONEY).unwrap()).unwrap();

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
                    Some(ironwood),
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

        // -- Input/output-side isolation -------------------------------------

        #[cfg(feature = "sapling")]
        fn tx_with_sapling(
            bundle: sapling::Bundle<sapling::bundle::Authorized, ZatBalance>,
        ) -> super::super::super::TransactionData<super::super::super::Authorized> {
            super::super::super::TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                super::super::balanced_vp(zip248::BundleType::SAPLING),
                None,
                None,
                Some(bundle),
                #[cfg(feature = "orchard")]
                None,
                #[cfg(feature = "orchard")]
                None,
                None,
            )
        }

        #[cfg(feature = "orchard")]
        fn tx_with_orchard_protocol_bundle(
            bundle_type: zip248::BundleType,
            bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
        ) -> super::super::super::TransactionData<super::super::super::Authorized> {
            let vp = super::super::balanced_vp(bundle_type);
            let bundle =
                super::super::orchard_with_balance(bundle, vp.zec_value(bundle_type).unwrap());
            let (orchard, ironwood) = if bundle_type == zip248::BundleType::ORCHARD {
                (Some(bundle), None)
            } else {
                (None, Some(bundle))
            };
            super::super::super::TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                vp,
                None,
                None,
                #[cfg(feature = "sapling")]
                None,
                orchard,
                ironwood,
                None,
            )
        }

        /// The input- and output-side conditions are satisfied by each shielded
        /// pool independently: no transparent bundle is present to mask them.
        #[test]
        #[cfg(feature = "sapling")]
        fn sapling_alone_satisfies_each_side_condition() {
            use super::super::{
                sapling_bundle_with_value_balance, test_sapling_bundle,
                test_sapling_output_only_bundle,
            };

            let mut runner = proptest::test_runner::TestRunner::default();
            let both = sapling_bundle_with_value_balance(
                &test_sapling_bundle(&mut runner),
                ZatBalance::from_i64(1).unwrap(),
            );
            assert_eq!(
                tx_with_sapling(both.clone()).check_v7_consensus_rules(),
                Ok(()),
            );

            // Spend-only: outputs are absent, so the output side fails.
            let spend_only = sapling::Bundle::from_parts(
                both.shielded_spends().to_vec(),
                vec![],
                *both.value_balance(),
                *both.authorization(),
            )
            .unwrap();
            assert_eq!(
                tx_with_sapling(spend_only).check_v7_consensus_rules(),
                Err(V7ConsensusError::MissingOutputSideCondition),
            );

            // Output-only: spends are absent, so the input side fails.
            let output_only = sapling_bundle_with_value_balance(
                &test_sapling_output_only_bundle(&mut runner),
                ZatBalance::from_i64(1).unwrap(),
            );
            assert_eq!(
                tx_with_sapling(output_only).check_v7_consensus_rules(),
                Err(V7ConsensusError::MissingInputSideCondition),
            );
        }

        /// An Orchard-protocol bundle satisfies a side only when its actions are
        /// nonempty and the corresponding flag is set.
        #[test]
        #[cfg(feature = "orchard")]
        fn orchard_protocol_flags_decide_each_side_condition() {
            use super::super::{bundle_with_flags, test_ironwood_bundle, test_orchard_bundle};

            let mut runner = proptest::test_runner::TestRunner::default();
            let orchard = test_orchard_bundle(&mut runner);
            let ironwood = test_ironwood_bundle(&mut runner);

            for (bundle_type, bundle) in [
                (zip248::BundleType::ORCHARD, orchard),
                (zip248::BundleType::IRONWOOD, ironwood),
            ] {
                let with = |flags: u8| {
                    tx_with_orchard_protocol_bundle(bundle_type, bundle_with_flags(&bundle, flags))
                };

                // Both sides enabled.
                assert_eq!(with(0b0000_0011).check_v7_consensus_rules(), Ok(()),);

                // Outputs disabled: the output side fails.
                assert_eq!(
                    with(0b0000_0001).check_v7_consensus_rules(),
                    Err(V7ConsensusError::MissingOutputSideCondition),
                );

                // Spends disabled: the input side fails.
                assert_eq!(
                    with(0b0000_0010).check_v7_consensus_rules(),
                    Err(V7ConsensusError::MissingInputSideCondition),
                );
            }
        }

        // -- Empty bundles ----------------------------------------------------

        /// A present but empty known bundle is invalid: ZIP 248 requires an
        /// empty effecting bundle to be omitted.
        #[test]
        fn empty_effect_and_auth_pairs_are_rejected() {
            for (bundle_type, effects) in [
                (0u64, vec![0u8, 0]),
                (2, empty_sapling_effects()),
                (3, empty_orchard_effects()),
                (4, empty_orchard_effects()),
            ] {
                let bytes = wire_tx(
                    BranchId::Nu8,
                    &[],
                    &[(bundle_type, 0, effects)],
                    &[(bundle_type, 0, vec![])],
                );
                assert!(Transaction::read(&bytes[..], BranchId::Nu8).is_err());
                assert!(TransactionBytes::read(&bytes[..]).is_err());
            }
        }

        /// A transparent bundle with outputs but no inputs has no authorizing
        /// data, so an empty authorizing entry for it is prohibited.
        #[test]
        fn outputs_only_transparent_with_empty_auth_is_rejected() {
            let bytes = wire_tx(
                BranchId::Nu8,
                &[],
                &[(0, 0, transparent_outputs_only_effects())],
                &[(0, 0, vec![])],
            );
            assert!(TransactionBytes::read(&bytes[..]).is_err());
        }

        // -- Missing effecting bundles ----------------------------------------

        /// A lone value pool delta has no effecting bundle for any previous
        /// effect-bearing type.
        #[test]
        fn missing_effect_is_rejected_for_every_effect_bearing_type() {
            for bundle_type in 0u64..=4 {
                let bytes = wire_tx(BranchId::Nu8, &[vp_entry(bundle_type, 0, 1)], &[], &[]);
                assert_eq!(
                    validate(&bytes).unwrap_err(),
                    V7ValidationError::MissingEffectBundle { bundle_type },
                );

                let tx = super::super::super::TransactionData::<
                    super::super::super::Authorized,
                >::from_parts_with_value_pool_deltas(
                    TxVersion::V7,
                    BranchId::Nu8,
                    0,
                    BlockHeight::from_u32(100),
                    super::super::balanced_vp(zip248::BundleType::from_u64(bundle_type)),
                    None,
                    None,
                    #[cfg(feature = "sapling")]
                    None,
                    #[cfg(feature = "orchard")]
                    None,
                    #[cfg(feature = "orchard")]
                    None,
                    None,
                );
                assert_eq!(
                    tx.check_v7_consensus_rules(),
                    Err(V7ConsensusError::MissingEffectBundle { bundle_type }),
                );
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
    use zcash_encoding::CompactSize;
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        value::{ZatBalance, Zatoshis},
    };

    use super::{
        Authorized, Transaction, TransactionData, TxVersion, test_ironwood_bundle,
        test_orchard_bundle, test_sapling_bundle, test_sapling_output_only_bundle,
    };
    use crate::transaction::{
        bytes::{
            BundleType, BundleVariant, OpaqueAuthBundleBytes, OpaqueEffectBundleBytes,
            OrchardSignatureBytes, SaplingSignatureBytes, SighashInfoBytes, TransactionBodyBytes,
            TransactionBytes, V7AuthBundleBytes, V7EffectBundleBytes, V7OrchardAuthBytes,
            V7OrchardBundleBytes, V7SaplingAuthBytes, V7TransactionBodyBytes, ValuePoolDeltaBytes,
        },
        txid::TxIdDigester,
        zip248::{self, BundleId, SuppliedBundleDigests, V7DigestError},
    };

    fn transparent_bundle() -> ::transparent::bundle::Bundle<
        ::transparent::bundle::Authorized,
        zcash_protocol::value::Zatoshis,
    > {
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
                vec![
                    zip248::MinerSignal::from_parts(
                        zip248::SignalCode::new(1),
                        zip248::LevelOfSupport::new(0x10),
                    ),
                    zip248::MinerSignal::from_parts(
                        zip248::SignalCode::new(2),
                        zip248::LevelOfSupport::new(0x20),
                    ),
                ],
                Some(zip248::PollDigest::new([0x7E; zip248::POLL_DIGEST_SIZE])),
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
        let typed_digests = typed.digest(TxIdDigester);
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

    /// [ZIP 248 §T.3.4] gives the Ironwood effecting digests the v6
    /// personalizations for their inputs, so they differ from both the Orchard
    /// ones and the older v7-draft ones. Recompute the effects digest from the
    /// bundle's actions using the literal spec strings so that a regression in
    /// the shared constants cannot silently change the txid.
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

        let mut compact = hasher(b"ZTxIdIrnActCH_v6");
        let mut memos = hasher(b"ZTxIdIrnActMH_v6");
        let mut noncompact = hasher(b"ZTxIdIrnActNH_v6");
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
            crate::transaction::bytes::TransparentBundleBytes::from_parts(
                body.transparent().unwrap().clone(),
                body.transparent_auth().cloned(),
            )
            .unwrap()
            .to_authorized()
            .unwrap(),
            typed.transparent_bundle().cloned(),
        );
        assert_eq!(
            body.coinbase().unwrap().to_coinbase_bundle().unwrap(),
            *typed.coinbase_bundle().unwrap(),
        );
        let sapling = body
            .sapling_auth()
            .unwrap()
            .to_authorized(body.sapling().unwrap(), vp.sapling_value().unwrap())
            .unwrap();
        let sapling_effects =
            crate::transaction::bytes::V7SaplingBundleBytes::from_bundle(&sapling);
        let sapling_auth =
            crate::transaction::bytes::V7SaplingAuthBytes::from_bundle(&sapling).unwrap();
        let mut effects = Vec::new();
        sapling_effects.write_effects(&mut effects).unwrap();
        let mut auth = Vec::new();
        sapling_auth.write_auth(&mut auth).unwrap();
        let mut expected_effects = Vec::new();
        body.sapling()
            .unwrap()
            .write_effects(&mut expected_effects)
            .unwrap();
        let mut expected_auth = Vec::new();
        body.sapling_auth()
            .unwrap()
            .write_auth(&mut expected_auth)
            .unwrap();
        assert_eq!(effects, expected_effects);
        assert_eq!(auth, expected_auth);

        let orchard = body
            .orchard_auth()
            .unwrap()
            .to_authorized(
                body.orchard().unwrap(),
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
        body.orchard_auth()
            .unwrap()
            .write_auth(&mut expected_auth)
            .unwrap();
        assert_eq!(effects, expected_effects);
        assert_eq!(auth, expected_auth);

        let ironwood = body
            .ironwood_auth()
            .unwrap()
            .to_authorized(
                body.ironwood().unwrap(),
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
        body.ironwood_auth()
            .unwrap()
            .write_auth(&mut expected_auth)
            .unwrap();
        assert_eq!(effects, expected_effects);
        assert_eq!(auth, expected_auth);
    }

    #[test]
    fn v7_owned_and_borrowed_conversion_match() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, true, true);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();
        let orchard_proof = body.orchard_auth().unwrap().proof().as_ptr();
        let ironwood_proof = body.ironwood_auth().unwrap().proof().as_ptr();
        let borrowed = Transaction::from_v7_body_ref(
            body,
            BranchId::Nu8,
            bytes.lock_time(),
            bytes.expiry_height(),
        )
        .unwrap();
        let owned = Transaction::from_bytes(bytes, BranchId::Nu8, [0; 32]).unwrap();
        assert_eq!(
            owned
                .orchard_bundle()
                .unwrap()
                .authorization()
                .proof()
                .as_ref()
                .as_ptr(),
            orchard_proof,
        );
        assert_eq!(
            owned
                .ironwood_bundle()
                .unwrap()
                .authorization()
                .proof()
                .as_ref()
                .as_ptr(),
            ironwood_proof,
        );
        assert_eq!(owned.txid(), borrowed.txid());
        let mut owned_bytes = Vec::new();
        owned.write(&mut owned_bytes).unwrap();
        let mut borrowed_bytes = Vec::new();
        borrowed.write(&mut borrowed_bytes).unwrap();
        assert_eq!(owned_bytes, borrowed_bytes);
        assert_eq!(owned.auth_commitment(), borrowed.auth_commitment());
    }

    #[test]
    fn v7_effect_only_bundles_have_no_typed_representation() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();

        let sapling = body.sapling().unwrap();
        let sapling_auth = body.sapling_auth().unwrap();
        let missing_auth = V7SaplingAuthBytes::from_parts(
            sapling_auth.anchor().copied(),
            sapling_auth.spend_proofs().to_vec(),
            sapling_auth.spend_auth_sigs().to_vec(),
            sapling_auth.output_proofs().to_vec(),
            None,
        );
        let err = missing_auth
            .to_authorized(sapling, ZatBalance::zero())
            .unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("no authorizing data"));

        let orchard = body.orchard().unwrap();
        let orchard_auth = body.orchard_auth().unwrap();
        let missing_auth = V7OrchardAuthBytes::from_parts(
            orchard_auth.anchor().copied(),
            orchard_auth.proof().to_vec(),
            orchard_auth.spend_auth_sigs().to_vec(),
            None,
        );
        let err = missing_auth
            .to_authorized(
                orchard,
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

    /// `BlockTxCommitmentDigester` produces the ZIP 248 authorizing-data
    /// commitment for v7, and agrees with both `Transaction::auth_commitment`
    /// and the byte layer. The Sapling bundle is output-only, so its auth
    /// digest omits the anchor, and the transparent bundle carries input
    /// `sighashInfo`.
    #[test]
    fn block_tx_commitment_digester_produces_zip248_auth_commitment() {
        use super::test_sapling_output_only_bundle;
        use crate::transaction::txid::BlockTxCommitmentDigester;

        let mut runner = proptest::test_runner::TestRunner::default();
        let sapling = test_sapling_output_only_bundle(&mut runner);
        let orchard = test_orchard_bundle(&mut runner);

        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_transparent(ZatBalance::from_i64(-1000).unwrap())
            .unwrap();
        vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();
        vp.set_sapling(*sapling.value_balance()).unwrap();
        vp.set_orchard(*orchard.value_balance()).unwrap();
        let typed = TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            BlockHeight::from_u32(100),
            vp,
            Some(transparent_bundle()),
            None,
            Some(sapling),
            Some(orchard),
            None,
            None,
        );

        let digests = typed.digest(BlockTxCommitmentDigester);

        let tx = typed.clone().freeze().unwrap();
        assert_eq!(tx.auth_commitment(), digests);

        let bytes = byte_tx(&typed);
        assert_eq!(
            bytes
                .v7_auth_commitment(&SuppliedBundleDigests::new())
                .unwrap(),
            digests,
        );
        // The digester's output is the byte layer's, so re-parsing the
        // serialized transaction reproduces it too.
        let reparsed = TransactionBytes::read(&super::tx_bytes(&tx)[..]).unwrap();
        assert_eq!(
            reparsed
                .v7_auth_commitment(&SuppliedBundleDigests::new())
                .unwrap(),
            digests,
        );
    }

    /// `flagsOrchard` bits 3 and 7 are reserved and rejected by the byte layer.
    /// The unmodified fixtures validate first, so
    /// an unrelated domain error cannot be the cause.
    #[test]
    fn v7_reserved_orchard_flag_bits_are_rejected() {
        let mut runner = proptest::test_runner::TestRunner::default();

        // A fixture that validates before any flag is modified: Orchard and
        // Ironwood bundles with balanced deltas, an honest Orchard pool
        // balance, and a nonpositive fee delta.
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_orchard(ZatBalance::from_i64(1).unwrap()).unwrap();
        vp.set_ironwood(ZatBalance::from_i64(1).unwrap()).unwrap();
        vp.set_fee(Zatoshis::from_u64(2).unwrap()).unwrap();
        /// Each shielded bundle contributes one zatoshi to the transparent pool.
        const SHIELDED_BALANCE: i64 = 1;
        let balance = ZatBalance::from_i64(SHIELDED_BALANCE).unwrap();
        let sapling = super::sapling_bundle_with_value_balance(
            &test_sapling_bundle(&mut runner),
            ZatBalance::zero(),
        );
        let orchard = super::orchard_with_balance(test_orchard_bundle(&mut runner), balance);
        let ironwood = super::orchard_with_balance(test_ironwood_bundle(&mut runner), balance);
        let typed = TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            BlockHeight::from_u32(100),
            vp,
            Some(transparent_bundle()),
            None,
            Some(sapling),
            Some(orchard),
            Some(ironwood),
            None,
        );
        let bytes = byte_tx(&typed);
        assert!(bytes.validate_v7().is_ok());

        let body = bytes.body().as_v7().unwrap();
        let mut wire = Vec::new();
        bytes.write(&mut wire).unwrap();
        /// The common header contains five 32-bit fields.
        const HEADER_SIZE: usize = 5 * core::mem::size_of::<u32>();
        let mut remaining = &wire[HEADER_SIZE..];
        let delta_count = CompactSize::read_t::<_, usize>(&mut remaining).unwrap();
        for _ in 0..delta_count {
            ValuePoolDeltaBytes::read(&mut remaining).unwrap();
        }
        let effect_count = CompactSize::read_t::<_, usize>(&mut remaining).unwrap();
        let mut flag_offsets = Vec::new();
        for _ in 0..effect_count {
            let bundle_type = CompactSize::read(&mut remaining).unwrap();
            let _variant = CompactSize::read(&mut remaining).unwrap();
            let length = CompactSize::read_t::<_, usize>(&mut remaining).unwrap();
            if [BundleType::ORCHARD.to_u64(), BundleType::IRONWOOD.to_u64()].contains(&bundle_type)
            {
                // Nonempty Orchard-family effects end with their flags byte.
                flag_offsets.push((bundle_type, wire.len() - remaining.len() + length - 1));
            }
            remaining = &remaining[length..];
        }
        for (bundle_type, actions, base_flags) in [
            (
                BundleType::ORCHARD,
                body.orchard().unwrap().actions().to_vec(),
                body.orchard().unwrap().flags(),
            ),
            (
                BundleType::IRONWOOD,
                body.ironwood().unwrap().actions().to_vec(),
                body.ironwood().unwrap().flags(),
            ),
        ] {
            for reserved in [0b0000_1000u8, 0b1000_0000] {
                let effects: Vec<V7EffectBundleBytes> = body
                    .effect_bundles()
                    .iter()
                    .map(|bundle| match bundle {
                        V7EffectBundleBytes::Orchard(_) if bundle_type == BundleType::ORCHARD => {
                            V7EffectBundleBytes::Orchard(V7OrchardBundleBytes::from_parts(
                                actions.clone(),
                                base_flags | reserved,
                            ))
                        }
                        V7EffectBundleBytes::Ironwood(_) if bundle_type == BundleType::IRONWOOD => {
                            V7EffectBundleBytes::Ironwood(V7OrchardBundleBytes::from_parts(
                                actions.clone(),
                                base_flags | reserved,
                            ))
                        }
                        other => other.clone(),
                    })
                    .collect();
                assert!(
                    V7TransactionBodyBytes::from_parts(
                        body.value_pool_deltas().to_vec(),
                        effects,
                        body.auth_bundles().to_vec(),
                    )
                    .is_err()
                );
                let offset = flag_offsets
                    .iter()
                    .find_map(|&(kind, offset)| (kind == bundle_type.to_u64()).then_some(offset))
                    .unwrap();
                let mut malformed = wire.clone();
                malformed[offset] |= reserved;
                assert!(TransactionBytes::read(&malformed[..]).is_err());
                assert!(super::Transaction::read(&malformed[..], BranchId::Nu8).is_err());
            }
        }
    }

    /// Sighash info values that typed conversion rejects: an unsupported
    /// version, an empty value, and version 0 with nonempty associated data.
    fn rejected_sighash_infos() -> [(&'static str, SighashInfoBytes); 3] {
        [
            (
                "unsupported version",
                SighashInfoBytes::from_bytes(vec![0x01]),
            ),
            ("empty", SighashInfoBytes::from_bytes(vec![])),
            (
                "nonempty associated data",
                SighashInfoBytes::from_bytes(vec![0x00, 0xAA]),
            ),
        ]
    }

    fn sapling_spend_sig(
        sig: &SaplingSignatureBytes,
        info: &SighashInfoBytes,
    ) -> SaplingSignatureBytes {
        SaplingSignatureBytes::from_parts(info.clone(), *sig.signature())
    }

    fn sapling_binding_sig(
        sig: &SaplingSignatureBytes,
        info: &SighashInfoBytes,
    ) -> SaplingSignatureBytes {
        SaplingSignatureBytes::from_parts(info.clone(), *sig.signature())
    }

    fn orchard_sig(sig: &OrchardSignatureBytes, info: &SighashInfoBytes) -> OrchardSignatureBytes {
        OrchardSignatureBytes::from_parts(info.clone(), *sig.signature())
    }

    /// Each sighash position is checked on its own, so a failure at a spend
    /// cannot mask a missing (or reversed) binding check, and vice versa.
    #[test]
    fn v7_sighash_info_is_checked_at_each_signature_position() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, true, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();

        let sapling = body.sapling().unwrap();
        let sapling_auth = body.sapling_auth().unwrap();
        let orchard = body.orchard().unwrap();
        let orchard_auth = body.orchard_auth().unwrap();
        let ironwood = body.ironwood().unwrap();
        let ironwood_auth = body.ironwood_auth().unwrap();
        let orchard_version = crate::transaction::components::orchard::bundle_version_for_branch(
            BranchId::Nu8,
            orchard::ValuePool::Orchard,
        );
        let ironwood_version = crate::transaction::components::orchard::bundle_version_for_branch(
            BranchId::Nu8,
            orchard::ValuePool::Ironwood,
        );

        // Every baseline is accepted, so a rejection below is not some
        // unrelated domain error.
        assert!(
            sapling_auth
                .to_authorized(sapling, ZatBalance::zero())
                .is_ok()
        );
        assert!(
            orchard_auth
                .to_authorized(orchard, ZatBalance::zero(), orchard_version)
                .is_ok()
        );
        assert!(
            ironwood_auth
                .to_authorized(ironwood, ZatBalance::zero(), ironwood_version)
                .is_ok()
        );

        for (label, info) in rejected_sighash_infos() {
            // Sapling spend position.
            let mut sigs = sapling_auth.spend_auth_sigs().to_vec();
            sigs[0] = sapling_spend_sig(&sigs[0], &info);
            let mutated = V7SaplingAuthBytes::from_parts(
                sapling_auth.anchor().copied(),
                sapling_auth.spend_proofs().to_vec(),
                sigs,
                sapling_auth.output_proofs().to_vec(),
                sapling_auth.binding_sig().cloned(),
            );
            let err = mutated
                .to_authorized(sapling, ZatBalance::zero())
                .unwrap_err();
            assert!(
                alloc::format!("{err:?}").contains("spend authorization sighash"),
                "{label}: {err:?}"
            );

            // Sapling binding position.
            let mutated = V7SaplingAuthBytes::from_parts(
                sapling_auth.anchor().copied(),
                sapling_auth.spend_proofs().to_vec(),
                sapling_auth.spend_auth_sigs().to_vec(),
                sapling_auth.output_proofs().to_vec(),
                Some(sapling_binding_sig(
                    sapling_auth.binding_sig().unwrap(),
                    &info,
                )),
            );
            let err = mutated
                .to_authorized(sapling, ZatBalance::zero())
                .unwrap_err();
            assert!(
                alloc::format!("{err:?}").contains("binding signature sighash"),
                "{label}: {err:?}"
            );

            for (name, auth, effects, version) in [
                ("Orchard", orchard_auth, orchard, orchard_version),
                ("Ironwood", ironwood_auth, ironwood, ironwood_version),
            ] {
                // Action signature position.
                let mut sigs = auth.spend_auth_sigs().to_vec();
                sigs[0] = orchard_sig(&sigs[0], &info);
                let mutated = V7OrchardAuthBytes::from_parts(
                    auth.anchor().copied(),
                    auth.proof().to_vec(),
                    sigs,
                    auth.binding_sig().cloned(),
                );
                let err = mutated
                    .to_authorized(effects, ZatBalance::zero(), version)
                    .unwrap_err();
                assert!(
                    alloc::format!("{err:?}").contains("spend authorization sighash"),
                    "{label} {name}: {err:?}"
                );

                // Binding position.
                let mutated = V7OrchardAuthBytes::from_parts(
                    auth.anchor().copied(),
                    auth.proof().to_vec(),
                    auth.spend_auth_sigs().to_vec(),
                    Some(orchard_sig(auth.binding_sig().unwrap(), &info)),
                );
                let err = mutated
                    .to_authorized(effects, ZatBalance::zero(), version)
                    .unwrap_err();
                assert!(
                    alloc::format!("{err:?}").contains("binding signature sighash"),
                    "{label} {name}: {err:?}"
                );
            }
        }
    }

    /// An output-only Sapling bundle has no spend signature that could fail
    /// first, so the binding signature's sighash info is checked alone.
    #[test]
    fn v7_output_only_sapling_checks_only_the_binding_sighash() {
        use super::test_sapling_output_only_bundle;

        let mut runner = proptest::test_runner::TestRunner::default();
        let bundle = test_sapling_output_only_bundle(&mut runner);
        let mut vp = zip248::ValuePoolDeltas::empty();
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
        let body = bytes.body().as_v7().unwrap();
        let sapling = body.sapling().unwrap();
        let auth = body.sapling_auth().unwrap();
        assert!(
            sapling.spends().is_empty() && !sapling.outputs().is_empty(),
            "the fixture must be output-only"
        );
        assert!(auth.to_authorized(sapling, ZatBalance::zero()).is_ok());

        for (label, info) in rejected_sighash_infos() {
            let mutated = V7SaplingAuthBytes::from_parts(
                None,
                vec![],
                vec![],
                auth.output_proofs().to_vec(),
                Some(sapling_binding_sig(auth.binding_sig().unwrap(), &info)),
            );
            let err = mutated
                .to_authorized(sapling, ZatBalance::zero())
                .unwrap_err();
            assert!(
                alloc::format!("{err:?}").contains("binding signature sighash"),
                "{label}: {err:?}"
            );
        }
    }

    #[test]
    fn v7_typed_conversion_rejects_effect_auth_mismatches() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, true, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();

        let sapling = body.sapling().unwrap();
        let sapling_auth = body.sapling_auth().unwrap();
        let mut spend_proofs = sapling_auth.spend_proofs().to_vec();
        spend_proofs.pop();
        let bad_sapling_auth = V7SaplingAuthBytes::from_parts(
            sapling_auth.anchor().copied(),
            spend_proofs,
            sapling_auth.spend_auth_sigs().to_vec(),
            sapling_auth.output_proofs().to_vec(),
            sapling_auth.binding_sig().cloned(),
        );
        assert!(
            bad_sapling_auth
                .to_authorized(sapling, ZatBalance::zero())
                .is_err()
        );

        let orchard = body.orchard().unwrap();
        let orchard_auth = body.orchard_auth().unwrap();
        let bad_orchard_auth = V7OrchardAuthBytes::from_parts(
            orchard_auth.anchor().copied(),
            orchard_auth.proof().to_vec(),
            vec![],
            orchard_auth.binding_sig().cloned(),
        );
        assert!(
            bad_orchard_auth
                .to_authorized(
                    orchard,
                    ZatBalance::zero(),
                    crate::transaction::components::orchard::bundle_version_for_branch(
                        BranchId::Nu8,
                        orchard::ValuePool::Orchard,
                    ),
                )
                .is_err()
        );
    }

    #[test]
    fn v7_orchard_bundle_rejects_unsupported_branch() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, false, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();
        let orchard = body.orchard().unwrap();

        let err = body
            .orchard_auth()
            .unwrap()
            .to_authorized(orchard, ZatBalance::zero(), None)
            .unwrap_err();
        assert_eq!(err.kind(), corez::io::ErrorKind::InvalidData);
        assert!(alloc::format!("{err:?}").contains("may not be present"));
    }

    /// The read-side conversion enforces the v7 Orchard bundle versions too, so
    /// v7 bytes decoded under pre-v3 flag semantics are rejected.
    #[test]
    fn v7_orchard_read_rejects_pre_v3_bundle_versions() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, false, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();
        let orchard = body.orchard().unwrap();
        let auth = body.orchard_auth().unwrap();

        for version in [
            orchard::bundle::BundleVersion::orchard_insecure_v1(),
            orchard::bundle::BundleVersion::orchard_v2(),
        ] {
            let err = auth
                .to_authorized(orchard, ZatBalance::zero(), Some(version))
                .unwrap_err();
            assert_eq!(err.kind(), corez::io::ErrorKind::InvalidInput);
            assert!(
                alloc::format!("{err:?}").contains("orchard_v3 or ironwood_v3"),
                "{err:?}"
            );
        }

        // The version the slot actually requires is accepted.
        assert!(
            auth.to_authorized(
                orchard,
                ZatBalance::zero(),
                Some(orchard::bundle::BundleVersion::orchard_v3()),
            )
            .is_ok()
        );
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

    /// [ZIP 248 §T.3.2a.ii] keeps the anchor out of the effecting data, so an
    /// effects-only byte bundle — parsed without authorizing data, and thus
    /// with no anchor available — must still have a computable effects digest,
    /// and re-anchoring must not change it.
    #[test]
    fn sapling_effects_digest_needs_no_anchor() {
        // Fixed spend and output keep the txid the same on every run.
        let sapling = crate::transaction::bytes::V7SaplingBundleBytes::from_parts(
            vec![crate::transaction::bytes::SaplingSpendBytes::from_parts(
                [0x11; 32], [0x22; 32], [0x44; 32],
            )],
            vec![crate::transaction::bytes::SaplingOutputBytes::from_parts(
                [0x55; 32],
                [0x66; 32],
                [0x77; 32],
                [0x88; 580],
                [0x99; 80],
            )],
        );

        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_sapling(ZatBalance::from_i64(-1).unwrap()).unwrap();
        let tx = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(0xffff_fffb),
            0,
            BlockHeight::from(100u32),
            TransactionBodyBytes::V7(
                V7TransactionBodyBytes::from_parts(
                    vp.to_wire_entries(),
                    vec![V7EffectBundleBytes::Sapling(sapling.clone())],
                    vec![],
                )
                .unwrap(),
            ),
        )
        .unwrap();

        let empty = SuppliedBundleDigests::new();
        assert_eq!(
            hex::encode(tx.v7_txid(&empty).unwrap().as_ref()),
            "79ceb169c87bdcf27e397e12dbddb4c42c346f5782b512e01666651ff64480f5"
        );
        assert_eq!(
            hex::encode(
                crate::transaction::txid::hash_v7_sapling_effects_bytes(&sapling).as_bytes()
            ),
            "16a3caaed6dfd7632ded63cb25e46c1d03ee5ac04839e47c402097dbde20e063"
        );
    }

    #[test]
    fn orchard_effects_digest_does_not_depend_on_authorizing_data() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let typed = typed_v7_tx(&mut runner, false, true, false, false);
        let bytes = byte_tx(&typed);
        let body = bytes.body().as_v7().unwrap();
        let effects = V7EffectBundleBytes::Orchard(body.orchard().unwrap().clone());
        let auth = body.orchard_auth().unwrap().clone();
        let vp = body.value_pool_deltas().to_vec();

        let build = |auth: Vec<V7AuthBundleBytes>| {
            TransactionBytes::from_parts(
                TxVersion::V7,
                Some(0xffff_fffb),
                0,
                BlockHeight::from(100u32),
                TransactionBodyBytes::V7(
                    V7TransactionBodyBytes::from_parts(vp.clone(), vec![effects.clone()], auth)
                        .unwrap(),
                ),
            )
            .unwrap()
        };

        let empty = SuppliedBundleDigests::new();
        let effect_only = build(vec![]);
        let auth_tx = build(vec![V7AuthBundleBytes::Orchard(auth.clone())]);

        // The authorizing data is not part of the txid.
        assert_eq!(
            effect_only.v7_txid(&empty).unwrap(),
            auth_tx.v7_txid(&empty).unwrap()
        );

        // Changing an authorizing field changes the auth commitment while the
        // txid stays put.
        let changed = V7OrchardAuthBytes::from_parts(
            Some([0x99; 32]),
            auth.proof().to_vec(),
            auth.spend_auth_sigs().to_vec(),
            auth.binding_sig().cloned(),
        );
        let changed_tx = build(vec![V7AuthBundleBytes::Orchard(changed)]);

        assert_eq!(
            auth_tx.v7_txid(&empty).unwrap(),
            changed_tx.v7_txid(&empty).unwrap()
        );
        assert_ne!(
            auth_tx.v7_auth_commitment(&empty).unwrap(),
            changed_tx.v7_auth_commitment(&empty).unwrap()
        );
    }

    #[test]
    fn v7_sapling_anchor_changes_auth_commitment_only() {
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

        assert_eq!(
            bytes_a.v7_txid(&empty).unwrap(),
            bytes_b.v7_txid(&empty).unwrap(),
            "the anchor is authorizing data in v7 and must not change the txid"
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

    fn unknown_body(bundle: V7EffectBundleBytes) -> TransactionBytes {
        unknown_body_with_auth(bundle, None)
    }

    fn unknown_body_with_auth(
        bundle: V7EffectBundleBytes,
        auth: Option<V7AuthBundleBytes>,
    ) -> TransactionBytes {
        let body =
            V7TransactionBodyBytes::from_parts(vec![], vec![bundle], auth.into_iter().collect())
                .unwrap();
        TransactionBytes::from_parts(
            TxVersion::V7,
            Some(u32::from(BranchId::Nu8)),
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
        let opaque = OpaqueEffectBundleBytes::from_parts(
            BundleId::new(BundleType::from_u64(99), BundleVariant::from_u64(0)),
            vec![1, 2, 3],
        )
        .unwrap();
        let tx = unknown_body(V7EffectBundleBytes::Opaque(opaque));
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
        let key = BundleId::new(BundleType::from_u64(2), BundleVariant::from_u64(1));
        let effects = OpaqueEffectBundleBytes::from_parts(key, vec![1, 2, 3]).unwrap();
        let auth = OpaqueAuthBundleBytes::from_parts(key, vec![4, 5]).unwrap();
        let tx = unknown_body_with_auth(
            V7EffectBundleBytes::Opaque(effects),
            Some(V7AuthBundleBytes::Opaque(auth)),
        );

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
        let opaque = OpaqueEffectBundleBytes::from_parts(
            BundleId::new(BundleType::from_u64(5), BundleVariant::from_u64(0)),
            vec![0x00],
        )
        .unwrap();
        let tx = unknown_body(V7EffectBundleBytes::Opaque(opaque));
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

        let effects = OpaqueEffectBundleBytes::from_parts(key, vec![1, 2, 3]).unwrap();
        let auth = OpaqueAuthBundleBytes::from_parts(key, vec![4, 5]).unwrap();
        let tx = unknown_body_with_auth(
            V7EffectBundleBytes::Opaque(effects),
            Some(V7AuthBundleBytes::Opaque(auth)),
        );

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

/// Version-consistency checks shared by `freeze` and serialization: fields that
/// only some formats carry must not survive into a format that cannot represent
/// them.
#[cfg(all(test, feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
mod version_consistency {
    use super::*;
    use crate::transaction::zip248;
    use corez::io;

    /// Wraps data in a `Transaction` without freezing, so the version check in
    /// the `write_v*` path can be exercised directly.
    fn unfrozen(data: TransactionData<Authorized>) -> Transaction {
        Transaction {
            txid: super::super::TxId::from_bytes([0; 32]),
            data,
        }
    }

    fn data(
        version: TxVersion,
        vp: zip248::ValuePoolDeltas,
        sapling: Option<sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
        orchard: Option<orchard::Bundle<orchard::bundle::Authorized, ZatBalance>>,
        ironwood: Option<orchard::Bundle<orchard::bundle::Authorized, ZatBalance>>,
        coinbase: Option<zip248::CoinbaseBundle>,
    ) -> TransactionData<Authorized> {
        TransactionData::from_parts_with_value_pool_deltas(
            version,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(1),
            vp,
            None,
            None,
            sapling,
            orchard,
            ironwood,
            coinbase,
        )
    }

    fn fee_only() -> zip248::ValuePoolDeltas {
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_fee(Zatoshis::from_u64(1000).unwrap()).unwrap();
        vp
    }

    fn coinbase() -> zip248::CoinbaseBundle {
        zip248::CoinbaseBundle::from_parts(
            BlockHeight::from(1u32),
            Zatoshis::from_u64(10).unwrap(),
            Zatoshis::ZERO,
            vec![],
            vec![],
            None,
        )
        .unwrap()
    }

    fn assert_invalid(result: io::Result<()>) {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn v7_zero_branch_id_fails_freeze_and_write() {
        let data = TransactionData {
            consensus_branch_id: BranchId::Sprout,
            ..data(
                TxVersion::V7,
                zip248::ValuePoolDeltas::empty(),
                None,
                None,
                None,
                None,
            )
        };
        assert_invalid(data.clone().freeze().map(|_| ()));
        assert_invalid(unfrozen(data).write_v7(Vec::new()).map(|_| ()));
    }

    #[test]
    fn v5_data_with_fee_only_delta_fails_freeze() {
        let data = data(TxVersion::V5, fee_only(), None, None, None, None);
        assert_invalid(data.freeze().map(|_| ()));
    }

    #[test]
    fn v5_data_with_coinbase_fails_freeze() {
        let data = data(
            TxVersion::V5,
            zip248::ValuePoolDeltas::empty(),
            None,
            None,
            None,
            Some(coinbase()),
        );
        assert_invalid(data.freeze().map(|_| ()));
    }

    #[test]
    fn v5_data_with_fee_only_delta_fails_write_v5() {
        let tx = unfrozen(data(TxVersion::V5, fee_only(), None, None, None, None));
        assert_invalid(tx.write_v5(Vec::new()).map(|_| ()));
    }

    #[test]
    fn v5_data_with_coinbase_fails_write_v5() {
        let tx = unfrozen(data(
            TxVersion::V5,
            zip248::ValuePoolDeltas::empty(),
            None,
            None,
            None,
            Some(coinbase()),
        ));
        assert_invalid(tx.write_v5(Vec::new()).map(|_| ()));
    }

    /// The check uses the target body version, not the stored header: v7 data
    /// carrying a coinbase bundle cannot be written as a v5 body.
    #[test]
    fn v7_data_with_coinbase_fails_write_v5() {
        let tx = unfrozen(data(
            TxVersion::V7,
            zip248::ValuePoolDeltas::empty(),
            None,
            None,
            None,
            Some(coinbase()),
        ));
        assert_invalid(tx.write_v5(Vec::new()).map(|_| ()));
    }

    fn with_entry(
        mut vp: zip248::ValuePoolDeltas,
        bundle_type: zip248::BundleType,
        value: ZatBalance,
    ) -> zip248::ValuePoolDeltas {
        vp.insert(bundle_type, zip248::BundleVariant::DEFAULT, value)
            .unwrap();
        vp
    }

    #[test]
    fn mismatched_shielded_delta_is_rejected() {
        let mut runner = proptest::test_runner::TestRunner::default();

        let sapling = test_sapling_bundle(&mut runner);
        let sapling_value = *sapling.value_balance();
        let vp = with_entry(
            zip248::ValuePoolDeltas::empty(),
            zip248::BundleType::SAPLING,
            ZatBalance::from_i64(i64::from(sapling_value) + 1).unwrap(),
        );
        assert_invalid(
            data(TxVersion::V5, vp, Some(sapling), None, None, None)
                .freeze()
                .map(|_| ()),
        );

        let orchard = test_orchard_bundle(&mut runner);
        let orchard_value = *orchard.value_balance();
        let vp = with_entry(
            zip248::ValuePoolDeltas::empty(),
            zip248::BundleType::ORCHARD,
            ZatBalance::from_i64(i64::from(orchard_value) - 1).unwrap(),
        );
        assert_invalid(
            data(TxVersion::V6, vp, None, Some(orchard), None, None)
                .freeze()
                .map(|_| ()),
        );
    }

    #[test]
    fn unsupported_bundle_slots_are_rejected_without_deltas() {
        let mut runner = proptest::test_runner::TestRunner::default();
        let sapling = test_sapling_bundle(&mut runner);
        let orchard = test_orchard_bundle(&mut runner);
        let ironwood = test_ironwood_bundle(&mut runner);
        for version in [TxVersion::V3, TxVersion::V4, TxVersion::V5] {
            let invalid = data(
                version,
                zip248::ValuePoolDeltas::empty(),
                None,
                None,
                Some(ironwood.clone()),
                None,
            );
            assert_invalid(invalid.clone().freeze().map(|_| ()));
            assert_invalid(unfrozen(invalid).write(Vec::new()));
        }
        for version in [TxVersion::V3, TxVersion::V4] {
            let invalid = data(
                version,
                zip248::ValuePoolDeltas::empty(),
                None,
                Some(orchard.clone()),
                None,
                None,
            );
            assert_invalid(invalid.clone().freeze().map(|_| ()));
            assert_invalid(unfrozen(invalid).write(Vec::new()));
        }
        let invalid = data(
            TxVersion::V3,
            zip248::ValuePoolDeltas::empty(),
            Some(sapling),
            None,
            None,
            None,
        );
        assert_invalid(invalid.clone().freeze().map(|_| ()));
        assert_invalid(unfrozen(invalid).write(Vec::new()));
    }

    #[test]
    fn v7_shielded_balances_match_deltas_on_every_typed_path() {
        /// Nonzero typed balance to distinguish an absent (zero) delta from a matching one.
        const BUNDLE_BALANCE: i64 = 2;
        /// A distinct nonzero delta to exercise mismatch independently of omission.
        const MISMATCHED_DELTA: i64 = 1;
        let balance = ZatBalance::from_i64(BUNDLE_BALANCE).unwrap();
        let mut runner = proptest::test_runner::TestRunner::default();
        let sapling = sapling_bundle_with_value_balance(&test_sapling_bundle(&mut runner), balance);
        let orchard = orchard_with_balance(test_orchard_bundle(&mut runner), balance);
        let ironwood = orchard_with_balance(test_ironwood_bundle(&mut runner), balance);

        for bundle_type in [
            zip248::BundleType::SAPLING,
            zip248::BundleType::ORCHARD,
            zip248::BundleType::IRONWOOD,
        ] {
            for delta in [0, MISMATCHED_DELTA, BUNDLE_BALANCE] {
                let mut vp = zip248::ValuePoolDeltas::empty();
                vp.set_zec_value(
                    zip248::BundleId::new(bundle_type, zip248::BundleVariant::DEFAULT),
                    ZatBalance::from_i64(delta).unwrap(),
                )
                .unwrap();
                vp.set_fee(Zatoshis::from_u64(delta as u64).unwrap())
                    .unwrap();
                let data = v7_data_with_deltas(
                    vp,
                    None,
                    (bundle_type == zip248::BundleType::SAPLING).then(|| sapling.clone()),
                    (bundle_type == zip248::BundleType::ORCHARD).then(|| orchard.clone()),
                    (bundle_type == zip248::BundleType::IRONWOOD).then(|| ironwood.clone()),
                );
                if delta != BUNDLE_BALANCE {
                    assert_eq!(
                        data.check_v7_consensus_rules(),
                        Err(
                            crate::transaction::V7ConsensusError::ShieldedValueBalanceMismatch {
                                bundle_type,
                                balance,
                                delta: ZatBalance::from_i64(delta).unwrap(),
                            }
                        ),
                    );
                    assert_invalid(data.clone().freeze().map(|_| ()));
                    assert_invalid(unfrozen(data).write_v7(Vec::new()));
                } else {
                    let tx = data.freeze().unwrap();
                    let mut wire = Vec::new();
                    tx.write(&mut wire).unwrap();
                    let parsed = Transaction::read(&wire[..], BranchId::Nu8).unwrap();
                    assert_eq!(parsed.txid(), tx.txid());
                    assert_eq!(parsed.sapling_value_balance(), tx.sapling_value_balance());
                    assert_eq!(
                        parsed.orchard_bundle().map(|b| b.value_balance()),
                        tx.orchard_bundle().map(|b| b.value_balance()),
                    );
                    assert_eq!(
                        parsed.ironwood_bundle().map(|b| b.value_balance()),
                        tx.ironwood_bundle().map(|b| b.value_balance()),
                    );
                }
            }
        }
    }

    #[test]
    fn v7_empty_transparent_is_rejected_with_valid_shielded_sibling() {
        /// Both spend and output flags are enabled for the sibling bundle.
        const SPENDS_AND_OUTPUTS: u8 = 0b11;
        let mut runner = proptest::test_runner::TestRunner::default();
        let orchard = orchard_with_balance(
            bundle_with_flags(&test_orchard_bundle(&mut runner), SPENDS_AND_OUTPUTS),
            ZatBalance::zero(),
        );
        let mut data = v7_data_with_deltas(
            zip248::ValuePoolDeltas::empty(),
            None,
            None,
            Some(orchard),
            None,
        );
        assert_eq!(data.check_v7_consensus_rules(), Ok(()));
        data.transparent_bundle = Some(transparent::Bundle {
            vin: vec![],
            vout: vec![],
            authorization: transparent::Authorized,
        });
        assert_eq!(
            data.check_v7_consensus_rules(),
            Err(crate::transaction::V7ConsensusError::EmptyEffectBundle {
                bundle_type: zip248::BundleType::TRANSPARENT,
            }),
        );
        assert_invalid(data.clone().freeze().map(|_| ()));
        assert_invalid(unfrozen(data).write_v7(Vec::new()));
    }

    #[test]
    fn bundle_derived_deltas_are_accepted_where_supported() {
        let mut runner = proptest::test_runner::TestRunner::default();

        let sapling = test_sapling_bundle(&mut runner);
        let vp = with_entry(
            zip248::ValuePoolDeltas::empty(),
            zip248::BundleType::SAPLING,
            *sapling.value_balance(),
        );
        let tx = data(TxVersion::V5, vp, Some(sapling), None, None, None)
            .freeze()
            .unwrap();
        assert!(tx.write_v5(Vec::new()).is_ok());

        let orchard = test_orchard_bundle(&mut runner);
        let vp = with_entry(
            zip248::ValuePoolDeltas::empty(),
            zip248::BundleType::ORCHARD,
            *orchard.value_balance(),
        );
        let tx = data(TxVersion::V6, vp, None, Some(orchard), None, None)
            .freeze()
            .unwrap();
        assert!(tx.write_v6(Vec::new()).is_ok());

        let ironwood = test_ironwood_bundle(&mut runner);
        let vp = with_entry(
            zip248::ValuePoolDeltas::empty(),
            zip248::BundleType::IRONWOOD,
            *ironwood.value_balance(),
        );
        let tx = data(TxVersion::V6, vp, None, None, Some(ironwood), None)
            .freeze()
            .unwrap();
        assert!(tx.write_v6(Vec::new()).is_ok());
    }
}

/// v7 supports exactly one bundle version per Orchard-protocol slot. An earlier
/// version would be written with the wrong cross-address (bit 2) semantics.
#[cfg(all(test, feature = "orchard", zcash_unstable = "nu8"))]
mod v7_bundle_versions {
    use super::*;
    use crate::transaction::components::orchard::{
        testing::rebuild_with_version, write_v7_auth, write_v7_effects,
    };
    use crate::transaction::zip248;
    use alloc::vec::Vec;
    use corez::io;
    use orchard::bundle::{BundleVersion, Flags};

    type OrchardBundle = orchard::Bundle<orchard::bundle::Authorized, ZatBalance>;

    fn bundle(version: orchard::bundle::BundleVersion) -> OrchardBundle {
        let mut runner = proptest::test_runner::TestRunner::default();
        rebuild_with_version(test_orchard_bundle(&mut runner), version)
    }

    fn data(orchard: Option<OrchardBundle>, ironwood: Option<OrchardBundle>) -> Transaction {
        let mut deltas = zip248::ValuePoolDeltas::empty();
        if let Some(bundle) = &orchard {
            deltas.set_orchard(*bundle.value_balance()).unwrap();
        }
        if let Some(bundle) = &ironwood {
            deltas.set_ironwood(*bundle.value_balance()).unwrap();
        }
        Transaction {
            txid: super::super::TxId::from_bytes([0; 32]),
            data: TransactionData::from_parts_with_value_pool_deltas(
                TxVersion::V7,
                BranchId::Nu8,
                0,
                BlockHeight::from_u32(100),
                deltas,
                None,
                None,
                None,
                orchard,
                ironwood,
                None,
            ),
        }
    }

    fn assert_invalid(result: io::Result<()>) {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn v7_effect_and_auth_adapters_reject_pre_v3_bundles() {
        for version in [
            orchard::bundle::BundleVersion::orchard_insecure_v1(),
            orchard::bundle::BundleVersion::orchard_v2(),
        ] {
            let bundle = bundle(version);
            assert_invalid(write_v7_effects(Vec::new(), &bundle));
            assert_invalid(write_v7_auth(Vec::new(), &bundle));
        }
    }

    #[test]
    fn v7_serialization_rejects_pool_swapped_bundles() {
        assert_invalid(
            data(
                Some(bundle(orchard::bundle::BundleVersion::ironwood_v3())),
                None,
            )
            .write_v7(Vec::new()),
        );
        assert_invalid(
            data(
                None,
                Some(bundle(orchard::bundle::BundleVersion::orchard_v3())),
            )
            .write_v7(Vec::new()),
        );
    }

    #[test]
    fn v7_serialization_accepts_pool_specific_v3_bundles() {
        let tx = data(
            Some(bundle(orchard::bundle::BundleVersion::orchard_v3())),
            Some(bundle(orchard::bundle::BundleVersion::ironwood_v3())),
        );
        let mut wire = Vec::new();
        tx.write_v7(&mut wire)
            .expect("pool-specific v3 bundles are writable");

        let parsed = crate::transaction::bytes::TransactionBytes::read(&wire[..]).unwrap();
        let body = parsed.body().as_v7().unwrap();
        assert_eq!(
            body.orchard().unwrap().flags(),
            tx.data.orchard_bundle().unwrap().flag_byte(),
        );
        assert_eq!(
            body.ironwood().unwrap().flags(),
            tx.data.ironwood_bundle().unwrap().flag_byte(),
        );
    }

    #[test]
    fn v7_consensus_checks_pool_specific_bundle_versions() {
        /// Enable both sides so the bundle satisfies the input/output conditions.
        const FLAGS: u8 = 0b0000_0011;
        let generated =
            test_orchard_bundle(&mut proptest::test_runner::TestRunner::deterministic());
        for version in [
            BundleVersion::orchard_insecure_v1(),
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_v3(),
            BundleVersion::ironwood_v3(),
        ] {
            let bundle = orchard::Bundle::try_from_parts(
                generated.actions().clone(),
                Flags::from_byte(FLAGS, version).unwrap(),
                ZatBalance::zero(),
                *generated.anchor(),
                generated.authorization().clone(),
                version,
            )
            .unwrap();
            for (bundle_type, tx, expected) in [
                (
                    zip248::BundleType::ORCHARD,
                    data(Some(bundle.clone()), None),
                    BundleVersion::orchard_v3(),
                ),
                (
                    zip248::BundleType::IRONWOOD,
                    data(None, Some(bundle.clone())),
                    BundleVersion::ironwood_v3(),
                ),
            ] {
                if version == expected {
                    tx.check_v7_consensus_rules().unwrap();
                    tx.into_data().freeze().unwrap();
                } else {
                    assert_eq!(
                        tx.check_v7_consensus_rules(),
                        Err(crate::transaction::V7ConsensusError::InvalidBundleVersion {
                            bundle_type,
                        })
                    );
                    assert_invalid(tx.write_v7(Vec::new()));
                    assert_eq!(
                        tx.into_data().freeze().unwrap_err().kind(),
                        io::ErrorKind::InvalidInput,
                    );
                }
            }
        }
    }
}
