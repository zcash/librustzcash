use blake2b_simd::Hash as Blake2bHash;
use std::ops::Deref;

use proptest::prelude::*;

use crate::{consensus::BranchId, legacy::Script};

use super::{
    components::Amount,
    sapling,
    sighash::{SignableInput, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE},
    sighash_v4::v4_signature_hash,
    sighash_v5::v5_signature_hash,
    testing::arb_tx,
    transparent::{self, builder::AuthorizingContext},
    txid::TxIdDigester,
    Authorization, Transaction, TransactionData, TxDigests, TxIn,
};

#[cfg(feature = "zfuture")]
use super::components::tze;

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

fn check_roundtrip(tx: Transaction) -> Result<(), TestCaseError> {
    let mut txn_bytes = vec![];
    tx.write(&mut txn_bytes).unwrap();
    let txo = Transaction::read(&txn_bytes[..], tx.consensus_branch_id).unwrap();

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
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_overwinter(tx in arb_tx(BranchId::Overwinter)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_sapling(tx in arb_tx(BranchId::Sapling)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_blossom(tx in arb_tx(BranchId::Blossom)) {
        check_roundtrip(tx)?;
    }
}

proptest! {
    #[test]
    #[ignore]
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

#[cfg(feature = "zfuture")]
proptest! {
    #[test]
    #[ignore]
    fn tx_serialization_roundtrip_future(tx in arb_tx(BranchId::ZFuture)) {
        check_roundtrip(tx)?;
    }
}

mod data;
#[test]
fn zip_0143() {
    for tv in self::data::zip_0143::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], tv.consensus_branch_id).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::Transparent {
                index: n as usize,
                script_code: &tv.script_code,
                value: Amount::from_nonnegative_i64(tv.amount).unwrap(),
            },
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            v4_signature_hash(tx.deref(), tv.hash_type as u8, &signable_input).as_ref(),
            tv.sighash
        );
    }
}

#[test]
fn zip_0243() {
    for tv in self::data::zip_0243::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], tv.consensus_branch_id).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::Transparent {
                index: n as usize,
                script_code: &tv.script_code,
                value: Amount::from_nonnegative_i64(tv.amount).unwrap(),
            },
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            v4_signature_hash(tx.deref(), tv.hash_type as u8, &signable_input).as_ref(),
            tv.sighash
        );
    }
}

#[derive(Debug)]
struct TestTransparentUnauthorized {
    input_amounts: Vec<Amount>,
    input_scripts: Vec<Script>,
}

impl transparent::Authorization for TestTransparentUnauthorized {
    type ScriptSig = ();
}

impl AuthorizingContext for TestTransparentUnauthorized {
    #[cfg(feature = "transparent-inputs")]
    fn input_amounts(&self) -> Vec<Amount> {
        self.input_amounts.clone();
    }

    #[cfg(feature = "transparent-inputs")]
    fn input_scripts(&self) -> Vec<Script> {
        self.input_scripts.clone()
    }
}

struct TestUnauthorized;

impl Authorization for TestUnauthorized {
    type TransparentAuth = TestTransparentUnauthorized;
    type SaplingAuth = sapling::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;

    #[cfg(feature = "zfuture")]
    type TzeAuth = tze::Authorized;
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

        let input_amounts = if tv.transparent_input.is_some() {
            vec![Amount::from_nonnegative_i64(tv.amount.unwrap()).unwrap()]
        } else {
            vec![]
        };
        let input_scripts = if tv.transparent_input.is_some() {
            vec![Script(tv.script_code.clone().unwrap())]
        } else {
            vec![]
        };

        let test_bundle = txdata
            .transparent_bundle
            .as_ref()
            .map(|b| transparent::Bundle {
                vin: b
                    .vin
                    .iter()
                    .map(|v| TxIn {
                        prevout: v.prevout.clone(),
                        script_sig: (),
                        sequence: v.sequence,
                    })
                    .collect(),
                vout: b.vout.clone(),
                authorization: TestTransparentUnauthorized {
                    input_amounts,
                    input_scripts,
                },
            });

        (
            TransactionData::from_parts(
                txdata.version(),
                txdata.consensus_branch_id(),
                txdata.lock_time(),
                txdata.expiry_height(),
                test_bundle,
                txdata.sprout_bundle().cloned(),
                txdata.sapling_bundle().cloned(),
                txdata.orchard_bundle().cloned(),
                #[cfg(feature = "zfuture")]
                txdata.tze_bundle().cloned(),
            ),
            txdata.digest(TxIdDigester),
        )
    }

    for tv in self::data::zip_0244::make_test_vectors() {
        let (txdata, txid_parts) = to_test_txdata(&tv);

        match tv.transparent_input {
            Some(n) => {
                let script = Script(tv.script_code.unwrap());
                let signable_input = SignableInput::Transparent {
                    index: n as usize,
                    script_code: &script,
                    value: Amount::from_nonnegative_i64(tv.amount.unwrap()).unwrap(),
                };

                assert_eq!(
                    v5_signature_hash(&txdata, SIGHASH_ALL, &signable_input, &txid_parts).as_ref(),
                    &tv.sighash_all
                );

                assert_eq!(
                    v5_signature_hash(&txdata, SIGHASH_NONE, &signable_input, &txid_parts).as_ref(),
                    &tv.sighash_none.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(&txdata, SIGHASH_SINGLE, &signable_input, &txid_parts)
                        .as_ref(),
                    &tv.sighash_single.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(
                        &txdata,
                        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                        &signable_input,
                        &txid_parts,
                    )
                    .as_ref(),
                    &tv.sighash_all_anyone.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(
                        &txdata,
                        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                        &signable_input,
                        &txid_parts,
                    )
                    .as_ref(),
                    &tv.sighash_none_anyone.unwrap()
                );

                assert_eq!(
                    v5_signature_hash(
                        &txdata,
                        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
                        &signable_input,
                        &txid_parts,
                    )
                    .as_ref(),
                    &tv.sighash_single_anyone.unwrap()
                );
            }
            _ => {
                let signable_input = SignableInput::Shielded;

                assert_eq!(
                    v5_signature_hash(&txdata, SIGHASH_ALL, &signable_input, &txid_parts).as_ref(),
                    tv.sighash_all
                );
            }
        };
    }
}
