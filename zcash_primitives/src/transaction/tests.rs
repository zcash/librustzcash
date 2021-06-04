use std::ops::Deref;

use proptest::prelude::*;

use crate::{
    consensus::BranchId,
    legacy::Script
};

use super::{
    components::Amount,
    sighash::{SignableInput, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE},
    txid::TxIdDigester,
    sighash_v4::v4_signature_hash,
    sighash_v5::v5_signature_hash,
    testing::arb_tx,
    Transaction,
};

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

fn check_roundtrip(branch_id: BranchId, tx: Transaction) -> Result<(), TestCaseError> {
    let mut txn_bytes = vec![];
    tx.write(&mut txn_bytes).unwrap();
    let txo = Transaction::read(&txn_bytes[..], branch_id).unwrap();

    prop_assert_eq!(tx.version, txo.version);
    #[cfg(feature = "zfuture")]
    prop_assert_eq!(tx.tze_bundle.as_ref(), txo.tze_bundle.as_ref());
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
    Ok(())
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_sprout(tx in arb_tx(BranchId::Sprout)) {
        check_roundtrip(BranchId::Sprout, tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_overwinter(tx in arb_tx(BranchId::Overwinter)) {
        check_roundtrip(BranchId::Overwinter, tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_sapling(tx in arb_tx(BranchId::Sapling)) {
        check_roundtrip(BranchId::Sapling, tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_blossom(tx in arb_tx(BranchId::Blossom)) {
        check_roundtrip(BranchId::Blossom, tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_heartwood(tx in arb_tx(BranchId::Heartwood)) {
        check_roundtrip(BranchId::Heartwood, tx)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_canopy(tx in arb_tx(BranchId::Canopy)) {
        check_roundtrip(BranchId::Canopy, tx)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu5(tx in arb_tx(BranchId::Nu5)) {
        check_roundtrip(BranchId::Nu5, tx)?;
    }
}

#[cfg(feature = "zfuture")]
proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_future(tx in arb_tx(BranchId::ZFuture)) {
        check_roundtrip(BranchId::ZFuture, tx)?;
    }
}

mod data;
#[test]
fn zip_0143() {
    for tv in self::data::zip_0143::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], tv.consensus_branch_id).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::transparent(
                n as usize,
                &tv.script_code,
                Amount::from_nonnegative_i64(tv.amount).unwrap(),
            ),
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            v4_signature_hash(tx.deref(), &signable_input, tv.hash_type).as_ref(),
            tv.sighash
        );
    }
}

#[test]
fn zip_0243() {
    for tv in self::data::zip_0243::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], tv.consensus_branch_id).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::transparent(
                n as usize,
                &tv.script_code,
                Amount::from_nonnegative_i64(tv.amount).unwrap(),
            ),
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            v4_signature_hash(tx.deref(), &signable_input, tv.hash_type).as_ref(),
            tv.sighash
        );
    }
}

#[test]
fn zip_0244() {
    for tv in self::data::zip_0244::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], BranchId::Nu5).unwrap();
        let txid_parts = tx.deref().digest(TxIdDigester);
        assert_eq!(tx.txid.as_ref(), &tv.txid);

        match tv.transparent_input {
            Some(n) => {
                let script = Script(tv.script_code.unwrap());
                let signable_input = SignableInput::transparent(
                    n as usize,
                    &script,
                    Amount::from_nonnegative_i64(tv.amount.unwrap()).unwrap(),
                );

                assert_eq!(
                    v5_signature_hash(tx.deref(), &txid_parts, &signable_input, SIGHASH_ALL).as_ref(),
                    &tv.sighash_all
                );

                assert_eq!(
                    v5_signature_hash(tx.deref(), &txid_parts, &signable_input, SIGHASH_NONE)
                        .as_ref(),
                    &tv.sighash_none.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(tx.deref(), &txid_parts, &signable_input, SIGHASH_SINGLE)
                        .as_ref(),
                    &tv.sighash_single.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(
                        tx.deref(),
                        &txid_parts,
                        &signable_input,
                        SIGHASH_ALL | SIGHASH_ANYONECANPAY
                    )
                    .as_ref(),
                    &tv.sighash_all_anyone.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(
                        tx.deref(),
                        &txid_parts,
                        &signable_input,
                        SIGHASH_NONE | SIGHASH_ANYONECANPAY
                    )
                    .as_ref(),
                    &tv.sighash_none_anyone.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(
                        tx.deref(),
                        &txid_parts,
                        &signable_input,
                        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
                    )
                    .as_ref(),
                    &tv.sighash_single_anyone.unwrap()
                );
            }
            _ => {
                let signable_input = SignableInput::Shielded;

                assert_eq!(
                    v5_signature_hash(tx.deref(), &txid_parts, &signable_input, SIGHASH_ALL).as_ref(),
                    tv.sighash_all
                );
            }
        };
    }
}
