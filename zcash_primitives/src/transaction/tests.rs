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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
use crate::transaction::{
    TransactionDigest,
    components::orchard::testing::with_cross_address_disabled,
    txid::{BlockTxCommitmentDigester, hash_sapling_spends},
};

#[cfg(all(
    test,
    any(
        zcash_unstable = "nu6.3",
        all(zcash_unstable = "nu7", feature = "zip-233")
    )
))]
use crate::transaction::sighash_v6::v6_signature_hash;

#[cfg(all(test, zcash_unstable = "nu6.3"))]
use blake2b_simd::Params;

#[cfg(all(test, zcash_unstable = "nu6.3"))]
use ff::PrimeField;

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
#[test]
fn v4_transactions_remain_valid_in_nu6_3() {
    assert!(TxVersion::V4.valid_in_branch(BranchId::Nu6_3));
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
#[test]
fn v6_branch_reconstruction_preserves_ironwood_bundle() {
    use proptest::{strategy::ValueTree, test_runner::TestRunner};

    let mut runner = TestRunner::default();
    let ironwood_bundle = crate::transaction::components::orchard::testing::arb_bundle(1)
        .new_tree(&mut runner)
        .unwrap()
        .current();
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn test_anchor(byte: u8) -> orchard::Anchor {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    orchard::Anchor::from_bytes(bytes).unwrap()
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn test_orchard_bundle(
    runner: &mut proptest::test_runner::TestRunner,
) -> orchard::Bundle<orchard::bundle::Authorized, ZatBalance> {
    use proptest::strategy::ValueTree;

    crate::transaction::components::orchard::testing::arb_bundle(1)
        .new_tree(runner)
        .unwrap()
        .current()
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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
        orchard::bundle::ProofSizeEnforcement::Strict,
    )
    .unwrap()
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn test_sapling_anchor(byte: u8) -> bls12_381::Scalar {
    bls12_381::Scalar::from(u64::from(byte))
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn test_sapling_bundle(
    runner: &mut proptest::test_runner::TestRunner,
) -> sapling::Bundle<sapling::bundle::Authorized, ZatBalance> {
    use proptest::strategy::ValueTree;

    let bundle_strategy =
        crate::transaction::components::sapling::testing::arb_bundle_for_version(TxVersion::V6);

    for _ in 0..100 {
        if let Some(bundle) = bundle_strategy.new_tree(runner).unwrap().current() {
            if !bundle.shielded_spends().is_empty() {
                return bundle;
            }
        }
    }

    panic!("Sapling bundle strategy should generate a bundle with spends");
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn test_sapling_output_only_bundle(
    runner: &mut proptest::test_runner::TestRunner,
) -> sapling::Bundle<sapling::bundle::Authorized, ZatBalance> {
    use proptest::strategy::ValueTree;

    let bundle_strategy =
        crate::transaction::components::sapling::testing::arb_bundle_for_version(TxVersion::V6);

    for _ in 0..1000 {
        if let Some(bundle) = bundle_strategy.new_tree(runner).unwrap().current() {
            if bundle.shielded_spends().is_empty() && !bundle.shielded_outputs().is_empty() {
                return bundle;
            }
        }
    }

    panic!("Sapling bundle strategy should generate an output-only bundle");
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn tx_bytes(tx: &Transaction) -> Vec<u8> {
    let mut encoded = Vec::new();
    tx.write(&mut encoded).unwrap();
    encoded
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn v6_tx_with_orchard_bundle(
    orchard_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> Transaction {
    TransactionData::<crate::transaction::Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        None,
        Some(with_cross_address_disabled(orchard_bundle)),
        None,
    )
    .freeze()
    .unwrap()
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn v6_tx_data_with_orchard_bundle(
    orchard_bundle: orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
) -> TransactionData<TestUnauthorized> {
    TransactionData::from_parts_v6(
        BranchId::Nu6_3,
        0,
        1u32.into(),
        None,
        None,
        Some(with_cross_address_disabled(orchard_bundle)),
        None,
    )
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn v5_shielded_sighash(tx_data: &TransactionData<TestUnauthorized>) -> Blake2bHash {
    let txid_parts = tx_data.digest(TxIdDigester);
    v5_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts)
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
fn v6_shielded_sighash(tx_data: &TransactionData<TestUnauthorized>) -> Blake2bHash {
    let txid_parts = tx_data.digest(TxIdDigester);
    v6_signature_hash(tx_data, &SignableInput::Shielded, &txid_parts)
}

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
#[test]
fn v6_ironwood_anchor_changes_auth_commitment_not_txid_or_sighash() {
    let mut runner = proptest::test_runner::TestRunner::default();
    let bundle = test_orchard_bundle(&mut runner);

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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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
    #[cfg(all(test, zcash_unstable = "nu6.3"))]
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

#[cfg(all(test, zcash_unstable = "nu6.3"))]
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
fn zip_0233() {
    fn to_test_txdata(
        tv: &self::data::zip_0233::TestVector,
    ) -> (TransactionData<TestUnauthorized>, TxDigests<Blake2bHash>) {
        let tx = Transaction::read(&tv.tx[..], BranchId::Nu7).unwrap();

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
