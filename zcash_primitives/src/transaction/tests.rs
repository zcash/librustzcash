use proptest::prelude::*;

#[cfg(test)]
use {
    crate::transaction::{
        Authorization, Transaction, TransactionData, TransactionDigest, TxDigests, TxIn, TxVersion,
        sighash::SignableInput,
        sighash_v4::v4_signature_hash,
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
    core::ops::Deref,
    ff::PrimeField,
    zcash_protocol::{
        consensus::BranchId,
        value::{ZatBalance, Zatoshis},
    },
    zcash_script::script,
};

#[cfg(all(test, zcash_unstable = "nutachyon"))]
use zcash_protocol::constants::{V7_TX_VERSION, V7_VERSION_GROUP_ID};

#[cfg(all(test, zcash_unstable = "nutachyon"))]
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
        v6_signature_hash(&data, &SignableInput::Shielded, &digests).as_bytes(),
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

#[test]
#[cfg(zcash_unstable = "nutachyon")]
fn v7_is_enabled_by_nu_tachyon_and_roundtrips() {
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::NuTachyon),
        TxVersion::V7
    );
    assert!(TxVersion::V7.valid_in_branch(BranchId::NuTachyon));
    assert!(!TxVersion::V7.valid_in_branch(BranchId::Nu6_3));

    let tx =
        TransactionData::from_parts_v7(BranchId::NuTachyon, 0, 0u32.into(), None, None, None, None)
            .freeze()
            .unwrap();

    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    assert_eq!(&encoded[..4], &(V7_TX_VERSION | (1 << 31)).to_le_bytes());
    assert_eq!(&encoded[4..8], &V7_VERSION_GROUP_ID.to_le_bytes());
    assert_eq!(
        &encoded[8..12],
        &u32::from(BranchId::NuTachyon).to_le_bytes()
    );

    let decoded = Transaction::read(&encoded[..], BranchId::Sprout).unwrap();
    assert_eq!(decoded.version(), TxVersion::V7);
    assert_eq!(decoded.consensus_branch_id(), BranchId::NuTachyon);
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
            return bundle;
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
    v5_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts)
}

#[cfg(test)]
fn v6_shielded_sighash(tx_data: &TransactionData<TestUnauthorized>) -> Blake2bHash {
    let txid_parts = tx_data.digest(TxIdDigester);
    v6_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts)
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

#[cfg(zcash_unstable = "nutachyon")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu_tachyon(tx in arb_tx(BranchId::NuTachyon)) {
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
            v4_signature_hash(tx.deref(), &signable_input).as_ref(),
            tv.sighash
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
            v4_signature_hash(tx.deref(), &signable_input).as_ref(),
            tv.sighash
        );
    }
}

#[cfg(test)]
#[derive(Debug)]
struct TestTransparentAuth {
    input_amounts: Vec<Zatoshis>,
    input_scriptpubkeys: Vec<Script>,
}

#[cfg(test)]
impl transparent::Authorization for TestTransparentAuth {
    type ScriptSig = Script;
}

#[cfg(test)]
impl TransparentAuthorizingContext for TestTransparentAuth {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.input_amounts.clone()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
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
    ) -> (TransactionData<TestUnauthorized>, TxDigests<Blake2bHash>) {
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
            authorization: TestTransparentAuth {
                input_amounts,
                input_scriptpubkeys,
            },
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
                v5_signature_hash(&txdata, &signable_input(SighashType::ALL), &txid_parts).as_ref(),
                &tv.sighash_all.unwrap()
            );

            assert_eq!(
                v5_signature_hash(&txdata, &signable_input(SighashType::NONE), &txid_parts)
                    .as_ref(),
                &tv.sighash_none.unwrap()
            );

            if index < bundle.vout.len() {
                assert_eq!(
                    v5_signature_hash(&txdata, &signable_input(SighashType::SINGLE), &txid_parts)
                        .as_ref(),
                    &tv.sighash_single.unwrap()
                );
            } else {
                assert_eq!(tv.sighash_single, None);
            }

            assert_eq!(
                v5_signature_hash(
                    &txdata,
                    &signable_input(SighashType::ALL_ANYONECANPAY),
                    &txid_parts,
                )
                .as_ref(),
                &tv.sighash_all_anyone.unwrap()
            );

            assert_eq!(
                v5_signature_hash(
                    &txdata,
                    &signable_input(SighashType::NONE_ANYONECANPAY),
                    &txid_parts,
                )
                .as_ref(),
                &tv.sighash_none_anyone.unwrap()
            );

            if index < bundle.vout.len() {
                assert_eq!(
                    v5_signature_hash(
                        &txdata,
                        &signable_input(SighashType::SINGLE_ANYONECANPAY),
                        &txid_parts,
                    )
                    .as_ref(),
                    &tv.sighash_single_anyone.unwrap()
                );
            } else {
                assert_eq!(tv.sighash_single_anyone, None);
            }
        };

        assert_eq!(
            v5_signature_hash(&txdata, &SignableInput::Shielded, &txid_parts).as_ref(),
            tv.sighash_shielded
        );
    }
}

/// Roundtrip test for ZIP 233 NSM + fee VP deltas in ZIP 248 format.
// TODO: regenerate cross-implementation test vectors from zcash-hackworks/zcash-test-vectors
#[cfg(all(
    zcash_unstable = "nutachyon",
    feature = "zip-233",
    zcash_unstable = "zip233"
))]
#[test]
#[ignore = "Historical vectors for the withdrawn ZIP 233 v6-header experiment; \
            current ZIP 233 requires ZIP 248 value-pool deltas, which are not implemented."]
fn zip_0233() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    let make_tx = |fee: u64, nsm: u64| {
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_fee(Zatoshis::from_u64(fee).unwrap());
        vp.set_zip233(Zatoshis::from_u64(nsm).unwrap());
        TransactionData::<super::Authorized>::from_parts_with_bundles(
            super::TxVersion::V7,
            BranchId::NuTachyon,
            0,
            BlockHeight::from_u32(100),
            vp,
            zip248::BundleMap::new(),
        )
        .freeze()
        .unwrap()
    };

    // Roundtrip: serialize → read back → check VP deltas.
    let tx = make_tx(10_000, 50_000);
    let mut buf = Vec::new();
    tx.write(&mut buf).unwrap();
    let tx = Transaction::read(&buf[..], BranchId::NuTachyon).unwrap();
    assert_eq!(
        tx.value_pool_deltas().fee(),
        Some(Zatoshis::from_u64(10_000).unwrap())
    );
    assert_eq!(
        tx.value_pool_deltas().zip233_amount(),
        Some(Zatoshis::from_u64(50_000).unwrap())
    );

    // Determinism: same inputs → same txid.
    let tx2 = make_tx(10_000, 50_000);
    assert_eq!(tx.txid(), tx2.txid());

    // Different VP deltas → different txid.
    let tx3 = make_tx(20_000, 50_000);
    assert_ne!(tx.txid(), tx3.txid());
}

/// [ZIP 248 §v0 Signature Digest](https://zips.z.cash/zip-0248#v0-signature-digest):
/// "For transactions that have no transparent inputs, the v0 signature digest
/// is identical to the transaction identifier digest."
#[test]
#[cfg(zcash_unstable = "nutachyon")]
fn v7_signature_hash_without_transparent_inputs_is_the_txid() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    let mut vp = zip248::ValuePoolDeltas::empty();
    vp.set_fee(Zatoshis::from_u64(10_000).unwrap());
    vp.set_sapling(zcash_protocol::value::ZatBalance::from_i64(10_000).unwrap());
    // `TestUnauthorized` supplies the transparent signing context that the
    // signature hash requires; this transaction has no transparent bundle.
    let tx = TransactionData::<TestUnauthorized>::from_parts_with_bundles(
        super::TxVersion::V7,
        BranchId::NuTachyon,
        0,
        BlockHeight::from_u32(100),
        vp,
        zip248::BundleMap::new(),
    );

    let txid_parts = tx.digest_v7();
    let sighash = v7_signature_hash(&tx, &SignableInput::Shielded, &txid_parts);
    assert_eq!(
        sighash.as_bytes(),
        super::txid::to_txid(tx.version(), tx.consensus_branch_id(), &txid_parts).as_ref(),
    );
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
        vp.set_sapling(ZatBalance::from_i64(100_000).unwrap());
        vp.set_orchard(ZatBalance::from_i64(-50_000).unwrap());
        vp.set_fee(Zatoshis::from_u64(1_000).unwrap());

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
            if let (Some(bt), Some(bv)) = (
                zip248::BundleType::from_u64(entry.bundle_type),
                zip248::BundleVariant::from_u64(entry.bundle_variant),
            ) {
                let key = zip248::ValuePoolDeltaKey {
                    bundle_type: bt,
                    asset_class: entry.asset_class,
                    asset_uuid: entry.asset_uuid.unwrap_or([0u8; 64]),
                };
                vp2.insert_known(key, bv, entry.value);
            }
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
        let bt = zip248::BundleType::Transparent.to_u64();
        let bv = zip248::BundleVariant::Default.to_u64();
        let data: Vec<u8> = vec![];

        let mut buf = Vec::new();
        zip248::write_bundle_data_framing(&mut buf, bt, bv, &data).unwrap();

        let ((parsed_bt, parsed_bv), parsed_data) =
            zip248::read_bundle_data_framing(&buf[..]).unwrap();
        assert_eq!(parsed_bt, bt);
        assert_eq!(parsed_bv, bv);
        assert!(parsed_data.is_empty());
    }

    fn test_unknown_bundle(data: &[u8]) -> zip248::UnknownBundle {
        zip248::UnknownBundle {
            effect_data: data.to_vec(),
            effect_digest: blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"test_unknown_efx")
                .hash(data),
            auth_data: None,
            auth_digest: None,
        }
    }

    #[test]
    fn bundle_map_unknown_iteration_order() {
        use super::super::Authorized;

        let mut map: zip248::BundleMap<Authorized> = zip248::BundleMap::new();
        map.insert_unknown(99, 0, test_unknown_bundle(&[]));
        assert_eq!(
            map.unknown_bundles()
                .map(|(&(bt, _), _)| bt)
                .collect::<Vec<_>>(),
            vec![99],
        );
        map.insert_unknown(50, 0, test_unknown_bundle(&[1]));
        assert_eq!(
            map.unknown_bundles()
                .map(|(&(bt, _), _)| bt)
                .collect::<Vec<_>>(),
            vec![50, 99],
        );
    }

    /// Verifies that a v7 transaction with an unknown bundle type can be
    /// parsed and re-serialized (ZIP 248 forward compatibility).
    #[cfg(zcash_unstable = "nutachyon")]
    #[test]
    fn unknown_bundle_roundtrip() {
        use super::super::{Authorized, Transaction, TransactionData, TxVersion};
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_fee(Zatoshis::from_u64(1_000).unwrap());

        let mut bundles: zip248::BundleMap<Authorized> = zip248::BundleMap::new();
        bundles.insert_unknown(42, 0, test_unknown_bundle(&[0xDE, 0xAD, 0xBE, 0xEF]));

        let txdata = TransactionData::<Authorized>::from_parts_with_bundles(
            TxVersion::V7,
            BranchId::NuTachyon,
            0,
            BlockHeight::from_u32(100),
            vp,
            bundles,
        );

        // Serialize.
        let tx = txdata.freeze().unwrap();
        let mut buf = Vec::new();
        tx.write(&mut buf).unwrap();

        // Parse back.
        let tx2 = Transaction::read(&buf[..], BranchId::NuTachyon).unwrap();

        // The unknown bundle should be preserved.
        let unknowns: Vec<_> = tx2.bundles().unknown_bundles().collect();
        assert_eq!(unknowns.len(), 1);
        assert_eq!(unknowns[0].0, &(42u64, 0u64));
        assert_eq!(unknowns[0].1.effect_data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(unknowns[0].1.auth_data.is_none());

        // Re-serialize should produce identical bytes.
        let mut buf2 = Vec::new();
        tx2.write(&mut buf2).unwrap();
        assert_eq!(buf, buf2);
    }

    // -- Consensus rule tests --------------------------------------------------

    #[cfg(zcash_unstable = "nutachyon")]
    mod consensus_rules {
        use super::super::super::{
            Authorized, TransactionData, TxVersion, V7ConsensusError, ZatBalance, zip248,
        };
        use zcash_protocol::consensus::{BlockHeight, BranchId};
        use zcash_protocol::value::Zatoshis;

        fn make_v7(vp: zip248::ValuePoolDeltas) -> TransactionData<Authorized> {
            TransactionData::from_parts_with_bundles(
                TxVersion::V7,
                BranchId::NuTachyon,
                0,
                BlockHeight::from_u32(100),
                vp,
                zip248::BundleMap::new(),
            )
        }

        #[test]
        fn fee_asset_class_must_be_zec() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Insert a fee entry with non-ZEC asset class via the raw API.
            vp.insert_known(
                zip248::ValuePoolDeltaKey {
                    bundle_type: zip248::BundleType::Fee,
                    asset_class: zip248::ASSET_CLASS_OTHER,
                    asset_uuid: [0x42; 64],
                },
                zip248::BundleVariant::Default,
                ZatBalance::from_i64(-1000).unwrap(),
            );
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
                100,
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
            let mut bundles = zip248::BundleMap::new();
            bundles.insert_coinbase(coinbase);
            TransactionData::from_parts_with_bundles(
                TxVersion::V7,
                BranchId::NuTachyon,
                0,
                BlockHeight::from_u32(100),
                vp,
                bundles,
            )
        }

        #[test]
        fn coinbase_fee_delta_must_be_nonnegative() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_fee(Zatoshis::from_u64(1000).unwrap()); // stored as -1000
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
            vp.set_coinbase(ZatBalance::from_i64(3).unwrap());
            vp.set_transparent(ZatBalance::from_i64(-3).unwrap());
            let tx = make_v7_coinbase(vp, coinbase_bundle(3, 1));
            assert_eq!(
                tx.check_v7_consensus_rules(),
                Err(V7ConsensusError::CoinbaseValueDeltaMismatch {
                    expected: ZatBalance::from_i64(2).unwrap(),
                    actual: ZatBalance::from_i64(3).unwrap(),
                }),
            );
        }

        #[test]
        fn balanced_coinbase_passes() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Issue 3, lock 1: the bundle contributes 2 to the transparent
            // transaction value pool, and the transparent outputs consume it.
            vp.set_coinbase(ZatBalance::from_i64(2).unwrap());
            vp.set_transparent(ZatBalance::from_i64(-2).unwrap());
            let tx = make_v7_coinbase(vp, coinbase_bundle(3, 1));
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }

        #[test]
        fn coinbase_bundle_rejects_lockbox_above_subsidy() {
            assert!(
                zip248::CoinbaseBundle::from_parts(
                    100,
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
                    100,
                    Zatoshis::ZERO,
                    Zatoshis::ZERO,
                    vec![0u8; zip248::MAX_COINBASE_DATA_LEN + 1],
                )
                .is_none()
            );
        }

        #[test]
        fn coinbase_bundle_rejects_out_of_range_block_height() {
            for height in [0, 500_000_000] {
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
                123_456,
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
            vp.insert_known(
                zip248::ValuePoolDeltaKey::zec(zip248::BundleType::Fee),
                zip248::BundleVariant::Default,
                ZatBalance::from_i64(1000).unwrap(),
            );
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
            // Sapling adds 100k to the pool but nothing subtracts it.
            vp.set_sapling(zcash_protocol::value::ZatBalance::from_i64(100_000).unwrap());
            let tx = make_v7(vp);
            let err = tx.check_v7_consensus_rules().unwrap_err();
            assert!(matches!(err, V7ConsensusError::ValueImbalance { .. }));
        }

        #[test]
        fn balanced_non_coinbase_passes() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_fee(Zatoshis::from_u64(1000).unwrap()); // -1000
            vp.set_sapling(zcash_protocol::value::ZatBalance::from_i64(1000).unwrap()); // +1000
            let tx = make_v7(vp);
            assert_eq!(tx.check_v7_consensus_rules(), Ok(()));
        }
    }

    // -- Parsing rule rejection tests ------------------------------------------

    #[cfg(zcash_unstable = "nutachyon")]
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
        fn write_bundle_entry(buf: &mut Vec<u8>, bundle_type: u64, variant: u64, data: &[u8]) {
            zip248::write_bundle_data_framing(&mut *buf, bundle_type, variant, data).unwrap();
        }

        /// A v7 transaction carrying a single `mEffectBundles` entry.
        fn v7_with_effect_bundle(bundle_type: u64, variant: u64, data: &[u8]) -> Vec<u8> {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut buf, 0).unwrap(); // nValuePoolDeltas
            CompactSize::write(&mut buf, 1).unwrap(); // nEffectBundles
            write_bundle_entry(&mut buf, bundle_type, variant, data);
            CompactSize::write(&mut buf, 0).unwrap(); // nAuthBundles
            buf
        }

        /// ZIP 248 encodes an absent bundle by omitting its entry. An entry
        /// that decodes to no contents is a second encoding of the same
        /// transaction, and would re-serialize to the omitted form under a
        /// txid that does not commit to the bytes it was parsed from.
        #[test]
        fn rejects_empty_transparent_effect_bundle() {
            let mut effects = Vec::new();
            CompactSize::write(&mut effects, 0).unwrap(); // nIn
            CompactSize::write(&mut effects, 0).unwrap(); // nOut
            let buf = v7_with_effect_bundle(
                zip248::BundleType::Transparent.to_u64(),
                zip248::BundleVariant::Default.to_u64(),
                &effects,
            );

            let err = Transaction::read(&buf[..], BranchId::NuTachyon).unwrap_err();
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
                zip248::BundleType::Transparent.to_u64(),
                zip248::BundleVariant::Default.to_u64(),
                &effects,
            );

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        /// A bundle payload longer than a block cannot be part of a valid
        /// transaction, and must be rejected before it is allocated.
        #[test]
        fn rejects_bundle_data_longer_than_a_block() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut buf, 0).unwrap(); // nValuePoolDeltas
            CompactSize::write(&mut buf, 1).unwrap(); // nEffectBundles
            CompactSize::write(&mut buf, zip248::BundleType::Transparent.to_u64() as usize)
                .unwrap();
            CompactSize::write(&mut buf, 0).unwrap(); // bundleVariant
            CompactSize::write(&mut buf, MAX_BLOCK_BYTES + 1).unwrap(); // claimed length

            let err = Transaction::read(&buf[..], BranchId::NuTachyon).unwrap_err();
            let msg = alloc::format!("{err:?}");
            assert!(
                msg.contains("maximum block size"),
                "unexpected error: {msg}"
            );
        }

        /// A bundleType this implementation knows may carry a bundleVariant it
        /// does not. Reinterpreting it as the default variant would change the
        /// bytes it re-serializes to, so it is preserved opaquely instead.
        #[test]
        fn preserves_unknown_variant_of_known_bundle_type() {
            let opaque = [0xAAu8; 8];
            let unknown_variant = zip248::BundleVariant::Default.to_u64() + 1;
            let buf = v7_with_effect_bundle(
                zip248::BundleType::Sapling.to_u64(),
                unknown_variant,
                &opaque,
            );

            let tx = Transaction::read(&buf[..], BranchId::NuTachyon).unwrap();
            assert!(
                tx.sapling_bundle().is_none(),
                "a variant this implementation does not understand must not parse as Sapling"
            );
            assert_eq!(tx.bundles().unknown_bundles().count(), 1);

            let mut reserialized = Vec::new();
            tx.write(&mut reserialized).unwrap();
            assert_eq!(reserialized, buf);
        }

        #[test]
        fn rejects_out_of_order_vp_deltas() {
            let mut buf = v7_header(BranchId::NuTachyon);
            // 2 VP delta entries: Orchard (3) then Sapling (2) — wrong order.
            CompactSize::write(&mut *buf, 2).unwrap();
            write_vp_entry(&mut buf, 3, 0, 100_000); // Orchard first (wrong)
            write_vp_entry(&mut buf, 2, 0, -100_000); // Sapling second
            CompactSize::write(&mut *buf, 0).unwrap(); // nEffectBundles
            CompactSize::write(&mut *buf, 0).unwrap(); // nAuthBundles

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn rejects_duplicate_vp_deltas() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 2).unwrap();
            write_vp_entry(&mut buf, 2, 0, 50_000);
            write_vp_entry(&mut buf, 2, 0, 50_000);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn rejects_coinbase_in_auth_bundles() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 0).unwrap(); // no VP deltas
            // A coinbase effect bundle, and an auth bundle for it: the
            // registry marks the coinbase mAuthBundles column as prohibited.
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 1, 0, &coinbase_effects()).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 1, 0, &[0xAA]).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn rejects_oversized_coinbase_data() {
            let mut effects = coinbase_effects();
            // Replace the empty `coinbaseData` with one byte over the limit.
            effects.pop();
            CompactSize::write(&mut effects, zip248::MAX_COINBASE_DATA_LEN + 1).unwrap();
            effects.extend_from_slice(&[0u8; zip248::MAX_COINBASE_DATA_LEN + 1]);

            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 1, 0, &effects).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn rejects_zero_vp_delta_value() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 1).unwrap();
            write_vp_entry(&mut buf, 2, 0, 0);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn rejects_fee_in_effect_bundles() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            // bundleType 5 is the fee bundle, which is value-only.
            zip248::write_bundle_data_framing(&mut buf, 5, 0, &[0xAA]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn rejects_mismatched_variant_across_maps() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 1).unwrap();
            write_vp_entry(&mut buf, 2, 0, 100_000);
            // Effect bundle says bundleType 2 variant 1 — mismatch.
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 2, 1, &[]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn rejects_auth_without_effect() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 2, 0, &[0xBB]).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }

        #[test]
        fn accepts_empty_v7_transaction() {
            let mut buf = v7_header(BranchId::NuTachyon);
            append_empty_body(&mut buf);
            let tx = Transaction::read(&buf[..], BranchId::NuTachyon).unwrap();
            assert!(tx.transparent_bundle().is_none());
            assert!(tx.sapling_bundle().is_none());
            assert!(tx.orchard_bundle().is_none());
        }

        #[test]
        fn rejects_out_of_order_effect_bundles() {
            let mut buf = v7_header(BranchId::NuTachyon);
            CompactSize::write(&mut *buf, 0).unwrap(); // no VP deltas
            // Effect bundles: Orchard (3) before Transparent (0) — wrong order.
            CompactSize::write(&mut *buf, 2).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 3, 0, &[0xAA]).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 0, 0, &[0xBB]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth
            assert!(Transaction::read(&buf[..], BranchId::NuTachyon).is_err());
        }
    }

    // -- Whole-transaction roundtrips for the v7 bundle types ------------------

    #[cfg(zcash_unstable = "nutachyon")]
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
            Transaction::read(&buf[..], BranchId::NuTachyon)
                .expect("the encoding just written parses")
        }

        #[test]
        fn coinbase_bundle_roundtrips_through_a_transaction() {
            let coinbase = zip248::CoinbaseBundle::from_parts(
                1_500_000,
                Zatoshis::from_u64(156_250_000).unwrap(),
                Zatoshis::from_u64(18_750_000).unwrap(),
                b"a miner was here".to_vec(),
            )
            .expect("valid coinbase bundle");

            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_coinbase(coinbase.value_pool_delta());
            // Something has to consume what the coinbase bundle contributes;
            // an Orchard delta stands in for the outputs that would.
            vp.set_orchard(-coinbase.value_pool_delta());

            let mut bundles = zip248::BundleMap::new();
            bundles.insert_coinbase(coinbase.clone());

            let tx = TransactionData::<Authorized>::from_parts_with_bundles(
                TxVersion::V7,
                BranchId::NuTachyon,
                0,
                BlockHeight::from_u32(1_500_100),
                vp,
                bundles,
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
                    let mut bundles = zip248::BundleMap::<Authorized>::new();
                    if as_ironwood {
                        vp.set_ironwood(value_balance);
                        bundles.insert_ironwood(bundle.clone());
                    } else {
                        vp.set_orchard(value_balance);
                        bundles.insert_orchard(bundle.clone());
                    }
                    // Balance the transaction so that it satisfies the
                    // value pool delta rule.
                    vp.set_transparent(-value_balance);

                    TransactionData::<Authorized>::from_parts_with_bundles(
                        TxVersion::V7,
                        BranchId::NuTachyon,
                        0,
                        BlockHeight::from_u32(100),
                        vp,
                        bundles,
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

    #[cfg(zcash_unstable = "nutachyon")]
    mod wire_order {
        use super::super::super::zip248;
        use alloc::vec::Vec;
        use zcash_protocol::value::{ZatBalance, Zatoshis};

        #[test]
        fn to_wire_entries_canonical_order_with_unknown() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Known: Orchard (3), Fee (5)
            vp.set_orchard(ZatBalance::from_i64(50_000).unwrap());
            vp.set_fee(Zatoshis::from_u64(1_000).unwrap());
            // Unknown: bundleType 8 (sorts after all known types)
            vp.insert_unknown(8, 0, [0u8; 64], 0, ZatBalance::from_i64(99_000).unwrap());

            let entries = vp.to_wire_entries();
            let types: Vec<u64> = entries.iter().map(|e| e.bundle_type).collect();
            // Orchard=3, Fee=5, Unknown=8 — strictly increasing.
            assert_eq!(types, vec![3, 5, 8]);
        }
    }

    // -- Sighash version info error tests --------------------------------------

    #[cfg(zcash_unstable = "nutachyon")]
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

    // -- In-memory-only BundleType panic tests ---------------------------------

    #[test]
    #[should_panic(expected = "in-memory-only")]
    fn sprout_bundle_type_has_no_wire_encoding() {
        let _ = zip248::BundleType::Sprout.to_u64();
    }
}
