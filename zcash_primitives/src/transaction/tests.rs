use proptest::prelude::*;

#[cfg(test)]
use {
    crate::transaction::{
        Authorization, Transaction, TransactionData, TxDigests, TxIn, sighash::SignableInput,
        sighash_v4::v4_signature_hash, sighash_v5::v5_signature_hash, testing::arb_tx, transparent,
        txid::TxIdDigester,
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

#[cfg(all(test, zcash_unstable = "zfuture"))]
use super::components::tze;

#[cfg(all(test, zcash_unstable = "nu7", feature = "zip-233"))]
use super::sighash_v6::v6_signature_hash;

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

#[cfg(test)]
fn check_roundtrip(tx: Transaction) -> Result<(), TestCaseError> {
    let mut txn_bytes = vec![];
    tx.write(&mut txn_bytes).unwrap();
    let txo = Transaction::read(&txn_bytes[..], tx.consensus_branch_id).unwrap();

    prop_assert_eq!(tx.version, txo.version);
    #[cfg(zcash_unstable = "zfuture")]
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

#[cfg(zcash_unstable = "nu7")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn tx_serialization_roundtrip_nu7(tx in arb_tx(BranchId::Nu7)) {
        check_roundtrip(tx)?;
    }
}

#[cfg(zcash_unstable = "zfuture")]
proptest! {
    #[test]
    #[cfg(all(feature = "expensive-tests", not(feature = "no-expensive-tests")))]
    fn tx_serialization_roundtrip_future(tx in arb_tx(BranchId::ZFuture)) {
        check_roundtrip(tx)?;
    }
}

#[test]
fn zip_0143() {
    for tv in self::data::zip_0143::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..], tv.consensus_branch_id).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => {
                SignableInput::Transparent(::transparent::sighash::SignableInput::from_parts(
                    SighashType::parse(tv.hash_type as u8).unwrap(),
                    n as usize,
                    &tv.script_code,
                    &tv.script_code,
                    Zatoshis::from_nonnegative_i64(tv.amount).unwrap(),
                ))
            }
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
            Some(n) => {
                SignableInput::Transparent(::transparent::sighash::SignableInput::from_parts(
                    SighashType::parse(tv.hash_type as u8).unwrap(),
                    n as usize,
                    &tv.script_code,
                    &tv.script_code,
                    Zatoshis::from_nonnegative_i64(tv.amount).unwrap(),
                ))
            }
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

    #[cfg(zcash_unstable = "zfuture")]
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

        #[cfg(not(zcash_unstable = "zfuture"))]
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
        #[cfg(zcash_unstable = "zfuture")]
        let tdata = TransactionData::from_parts_zfuture(
            txdata.version(),
            txdata.consensus_branch_id(),
            txdata.lock_time(),
            txdata.expiry_height(),
            #[cfg(feature = "zip-233")]
            txdata.zip233_amount,
            test_bundle,
            txdata.sprout_bundle().cloned(),
            txdata.sapling_bundle().cloned(),
            txdata.orchard_bundle().cloned(),
            txdata.tze_bundle().cloned(),
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
                SignableInput::Transparent(::transparent::sighash::SignableInput::from_parts(
                    hash_type,
                    index,
                    script_pubkey,
                    script_pubkey,
                    value,
                ))
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
            .map(|s| Script(s.clone()))
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

    for tv in self::data::zip_0233::make_test_vectors() {
        let (txdata, txid_parts) = to_test_txdata(&tv);

        assert_eq!(
            v6_signature_hash(&txdata, &SignableInput::Shielded, &txid_parts).as_ref(),
            tv.sighash_shielded
        );
    }
}
