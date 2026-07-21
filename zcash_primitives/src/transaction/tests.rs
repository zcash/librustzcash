use proptest::prelude::*;

#[cfg(test)]
use {
    crate::transaction::{
        Authorization, Transaction, TransactionData, TxDigests, TxIn, TxVersion,
        sighash::SignableInput, sighash_v4::v4_signature_hash, sighash_v5::v5_signature_hash,
        testing::arb_tx, transparent, txid::TxIdDigester,
    },
    ::transparent::{
        address::Script, sighash::SighashType, sighash::TransparentAuthorizingContext,
    },
    alloc::vec::Vec,
    blake2b_simd::Hash as Blake2bHash,
    core::ops::Deref,
    zcash_protocol::{consensus::BranchId, value::Zatoshis},
    zcash_script::script,
};

#[cfg(all(test, not(zcash_unstable = "nu7")))]
use crate::transaction::{
    TransactionDigest,
    txid::{BlockTxCommitmentDigester, hash_sapling_spends},
};

#[cfg(all(test, not(zcash_unstable = "nu7")))]
use crate::transaction::sighash_v6::v6_signature_hash;
#[cfg(all(test, zcash_unstable = "nu7", feature = "zip-233"))]
use crate::transaction::sighash_v6::v6_signature_hash;

#[cfg(all(test, not(zcash_unstable = "nu7")))]
use blake2b_simd::Params;

#[cfg(all(test, not(zcash_unstable = "nu7")))]
use ff::PrimeField;

#[cfg(all(test, not(zcash_unstable = "nu7")))]
use zcash_protocol::value::ZatBalance;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod data;

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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
#[test]
fn v4_transactions_remain_valid_in_nu6_3() {
    assert!(TxVersion::V4.valid_in_branch(BranchId::Nu6_3));
}

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
fn test_anchor(byte: u8) -> orchard::Anchor {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    orchard::Anchor::from_bytes(bytes).unwrap()
}

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
fn test_sapling_anchor(byte: u8) -> bls12_381::Scalar {
    bls12_381::Scalar::from(u64::from(byte))
}

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
fn tx_bytes(tx: &Transaction) -> Vec<u8> {
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    encoded
}

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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
#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
fn v5_shielded_sighash(tx_data: &TransactionData<TestUnauthorized>) -> Blake2bHash {
    let txid_parts = tx_data.digest(TxIdDigester);
    v5_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts)
}

#[cfg(all(test, not(zcash_unstable = "nu7")))]
fn v6_shielded_sighash(tx_data: &TransactionData<TestUnauthorized>) -> Blake2bHash {
    let txid_parts = tx_data.digest(TxIdDigester);
    v6_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts)
}

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
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

    prop_assert_eq!(tx.version, txo.version);
    prop_assert_eq!(tx.lock_time, txo.lock_time);
    prop_assert_eq!(
        tx.transparent_bundle.as_ref(),
        txo.transparent_bundle.as_ref()
    );
    prop_assert_eq!(tx.sapling_value_balance(), txo.sapling_value_balance());
    prop_assert_eq!(
        tx.orchard_bundle.as_ref().map(|v| *v.value_balance()),
        txo.orchard_bundle.as_ref().map(|v| *v.value_balance())
    );
    #[cfg(all(test, not(zcash_unstable = "nu7")))]
    prop_assert_eq!(
        tx.ironwood_bundle.as_ref().map(|v| *v.value_balance()),
        txo.ironwood_bundle.as_ref().map(|v| *v.value_balance())
    );
    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    if tx.version.has_zip233() {
        prop_assert_eq!(tx.zip233_amount, txo.zip233_amount);
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

#[cfg(all(test, not(zcash_unstable = "nu7")))]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu6_3(tx in arb_tx(BranchId::Nu6_3)) {
        check_roundtrip(tx)?;
    }
}

#[cfg(all(test, zcash_unstable = "nu7"))]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu7(tx in arb_tx(BranchId::Nu7)) {
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

        let test_bundle = txdata
            .transparent_bundle
            .as_ref()
            .map(|b| transparent::Bundle {
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

        let tdata = TransactionData::from_parts(
            txdata.version(),
            txdata.consensus_branch_id(),
            txdata.lock_time(),
            txdata.expiry_height(),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            txdata.zip233_amount,
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

#[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
#[test]
#[ignore = "tachyon test vectors were generated with the placeholder v6 version group ID and \
            must be regenerated for the v7 (tachyon) transaction format"]
fn tachyon_v6_test_vectors() {
    use self::data::tachyon_vectors::*;
    use ff::FromUniformBytes;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use pasta_curves::{EpAffine, Fp};

    // Expected rk bytes for rk_from_seed([0x42; 64]) — derived from zebra's
    // reddsa-based key derivation, hardcoded here since reddsa is not a direct dependency.
    const EXPECTED_RK_42: [u8; 32] = [
        0xba, 0x64, 0x54, 0xc4, 0xa1, 0xd4, 0x27, 0x30, 0xb5, 0x3c, 0xbf, 0x30, 0xd0, 0x5d, 0x3f,
        0x95, 0xaa, 0x54, 0x1c, 0x98, 0xeb, 0xa0, 0x20, 0x5a, 0x75, 0xbb, 0x79, 0x83, 0x44, 0x3b,
        0x37, 0x31,
    ];
    // Expected rk bytes for rk_from_seed([0x43; 64]).
    const EXPECTED_RK_43: [u8; 32] = [
        0x33, 0x6a, 0x1f, 0x7e, 0xd0, 0x90, 0x31, 0x93, 0xf3, 0x9f, 0xa5, 0x30, 0x6f, 0x3f, 0xd8,
        0x8d, 0x8a, 0x0a, 0x89, 0x07, 0xa1, 0xde, 0xfd, 0xe5, 0x47, 0xf1, 0x17, 0xe7, 0x07, 0x5d,
        0x9e, 0x01,
    ];

    // Helper: deserialize, check version, roundtrip
    let read_and_roundtrip = |data: &[u8]| -> Transaction {
        let tx = Transaction::read(data, BranchId::Nu7).unwrap();
        assert_eq!(tx.version, TxVersion::V7);

        let mut encoded = Vec::with_capacity(data.len());
        tx.write(&mut encoded).unwrap();
        assert_eq!(data, &encoded[..]);

        tx
    };

    // EMPTY_V6_TX: no tachyon bundle
    {
        let tx = read_and_roundtrip(&EMPTY_V6_TX);
        assert!(tx.tachyon_bundle().is_none());
    }

    // V6_TX_TACHYON_STRIPPED: 1 action, Adjunct stamp (post-aggregation), value_balance = 0
    {
        let tx = read_and_roundtrip(&V6_TX_TACHYON_STRIPPED);
        let bundle = tx.tachyon_bundle().expect("expected tachyon bundle");
        let stripped = match bundle {
            zcash_tachyon::TachyonBundle::Adjunct(s) => s,
            zcash_tachyon::TachyonBundle::Stamped(_) => panic!("expected Adjunct variant"),
        };
        assert_eq!(stripped.actions.len(), 1);
        assert_eq!(stripped.value_balance, 0);

        let action = &stripped.actions[0];
        let cv_point: EpAffine = action.cv.into();
        assert_eq!(cv_point, EpAffine::generator());
        assert_eq!(<[u8; 32]>::from(action.rk), EXPECTED_RK_42);
        assert_eq!(<[u8; 64]>::from(action.sig), [0x01u8; 64]);
        assert_eq!(<[u8; 64]>::from(stripped.binding_sig), [0x02u8; 64]);
        // Adjunct's covering aggregate wtxid set to [0xEE; 64] in zebra fixture.
        assert_eq!(<[u8; 64]>::from(stripped.stamp), [0xEEu8; 64]);
    }

    // V6_TX_TACHYON_STAMPED: 1 action, stamp with 1 tachygram, value_balance = 100
    {
        let tx = read_and_roundtrip(&V6_TX_TACHYON_STAMPED);
        let bundle = tx.tachyon_bundle().expect("expected tachyon bundle");
        let stamped = match bundle {
            zcash_tachyon::TachyonBundle::Stamped(s) => s,
            zcash_tachyon::TachyonBundle::Adjunct(_) => panic!("expected Stamped variant"),
        };
        assert_eq!(stamped.actions.len(), 1);
        assert_eq!(stamped.value_balance, 100);

        let action = &stamped.actions[0];
        let cv_point: EpAffine = action.cv.into();
        assert_eq!(cv_point, EpAffine::generator());
        assert_eq!(<[u8; 32]>::from(action.rk), EXPECTED_RK_42);
        assert_eq!(<[u8; 64]>::from(action.sig), [0x01u8; 64]);
        assert_eq!(<[u8; 64]>::from(stamped.binding_sig), [0x02u8; 64]);

        assert_eq!(stamped.stamp.tachygrams.len(), 1);
        let tg_fp: Fp = stamped.stamp.tachygrams[0].into();
        assert_eq!(tg_fp, Fp::from_uniform_bytes(&[0xAAu8; 64]));
        // Zebra fixture builds the anchor by reading 64 zero bytes through
        // tachyon's wire format (height 0, commitment from [0; 32]).
        let expected_anchor = zcash_tachyon::Anchor::read(&[0u8; 64][..]).unwrap();
        assert_eq!(stamped.stamp.anchor, expected_anchor);
    }

    // V6_TX_TACHYON_MULTI_ACTION: 2 actions, stamp with 3 tachygrams, value_balance = 300
    {
        let tx = read_and_roundtrip(&V6_TX_TACHYON_MULTI_ACTION);
        let bundle = tx.tachyon_bundle().expect("expected tachyon bundle");
        let stamped = match bundle {
            zcash_tachyon::TachyonBundle::Stamped(s) => s,
            zcash_tachyon::TachyonBundle::Adjunct(_) => panic!("expected Stamped variant"),
        };
        assert_eq!(stamped.actions.len(), 2);
        assert_eq!(stamped.value_balance, 300);

        let action1 = &stamped.actions[0];
        let cv1: EpAffine = action1.cv.into();
        assert_eq!(cv1, EpAffine::generator());
        assert_eq!(<[u8; 32]>::from(action1.rk), EXPECTED_RK_42);
        assert_eq!(<[u8; 64]>::from(action1.sig), [0x01u8; 64]);

        let action2 = &stamped.actions[1];
        let cv2: EpAffine = action2.cv.into();
        assert_eq!(cv2, EpAffine::generator());
        assert_eq!(<[u8; 32]>::from(action2.rk), EXPECTED_RK_43);
        assert_eq!(<[u8; 64]>::from(action2.sig), [0x03u8; 64]);

        assert_eq!(<[u8; 64]>::from(stamped.binding_sig), [0x02u8; 64]);

        assert_eq!(stamped.stamp.tachygrams.len(), 3);
        let tg1: Fp = stamped.stamp.tachygrams[0].into();
        let tg2: Fp = stamped.stamp.tachygrams[1].into();
        let tg3: Fp = stamped.stamp.tachygrams[2].into();
        assert_eq!(tg1, Fp::from_uniform_bytes(&[0xAAu8; 64]));
        assert_eq!(tg2, Fp::from_uniform_bytes(&[0xCCu8; 64]));
        assert_eq!(tg3, Fp::from_uniform_bytes(&[0xDDu8; 64]));
        let expected_anchor = zcash_tachyon::Anchor::read(&[0u8; 64][..]).unwrap();
        assert_eq!(stamped.stamp.anchor, expected_anchor);
    }
}

#[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
#[test]
#[ignore = "The ZIP 233 test vectors were generated using the placeholder v6 version group ID \
            and must be regenerated now that `V6_VERSION_GROUP_ID` has been finalized."]
fn zip_0233() {
    fn to_test_txdata(
        tv: &self::data::zip_0233::TestVector,
    ) -> (TransactionData<TestUnauthorized>, TxDigests<Blake2bHash>) {
        let tx = Transaction::read(tv.tx, BranchId::Nu7).unwrap();

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
            .map(|s| Script(script::Code(s.to_vec())))
            .collect();

        let test_bundle = txdata
            .transparent_bundle
            .as_ref()
            .map(|b| transparent::Bundle {
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

        let tdata = TransactionData::from_parts(
            txdata.version(),
            txdata.consensus_branch_id(),
            txdata.lock_time(),
            txdata.expiry_height(),
            txdata.zip233_amount,
            test_bundle,
            txdata.sprout_bundle().cloned(),
            txdata.sapling_bundle().cloned(),
            txdata.orchard_bundle().cloned(),
        );

        (tdata, txdata.digest(TxIdDigester))
    }

    for tv in self::data::zip_0233::TEST_VECTORS {
        let (txdata, txid_parts) = to_test_txdata(tv);

        assert_eq!(
            v6_signature_hash(&txdata, &SignableInput::Shielded, &txid_parts).as_ref(),
            tv.sighash_shielded
        );
    }
}
