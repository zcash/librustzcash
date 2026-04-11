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

    prop_assert_eq!(tx.version(), txo.version());
    #[cfg(zcash_unstable = "zfuture")]
    prop_assert_eq!(tx.tze_bundle(), txo.tze_bundle());
    prop_assert_eq!(tx.lock_time(), txo.lock_time());
    prop_assert_eq!(tx.transparent_bundle(), txo.transparent_bundle());
    prop_assert_eq!(tx.sapling_value_balance(), txo.sapling_value_balance());
    prop_assert_eq!(
        tx.orchard_bundle().map(|v| *v.value_balance()),
        txo.orchard_bundle().map(|v| *v.value_balance())
    );
    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    if tx.version().has_zip233() {
        prop_assert_eq!(tx.zip233_amount(), txo.zip233_amount());
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
            .transparent_bundle()
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
            txdata.value_pool_deltas().clone(),
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
            txdata.value_pool_deltas().clone(),
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

/// Tests ZIP 233 NSM interaction with the v6 (ZIP 248) digest and sighash.
///
/// Constructs a minimal v6 transaction with a ZIP 233 NSM amount and a fee VP
/// delta, serializes it in the ZIP 248 wire format, reads it back, and verifies
/// the write-read roundtrip preserves the VP deltas and that the v6 sighash is
/// deterministic.
///
/// NOTE: The old hardcoded test vectors in `data::zip_0233` were generated for
/// the pre-ZIP-248 wire format and are no longer valid. Cross-implementation
/// test vectors for the ZIP 248 format should be generated from the upstream
/// `zcash-hackworks/zcash-test-vectors` repository once its `zip_0233.py` is
/// updated.
#[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
#[test]
fn zip_0233() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    // Build a minimal v6 transaction with fee + ZIP 233 NSM VP deltas.
    let mut vp = zip248::ValuePoolDeltas::empty();
    vp.set_fee(Zatoshis::from_u64(10_000).unwrap());
    vp.set_zip233(Zatoshis::from_u64(50_000).unwrap());

    let txdata = TransactionData::<super::Authorized>::from_parts_v6(
        super::TxVersion::V6,
        BranchId::Nu7,
        0,
        BlockHeight::from_u32(100),
        vp,
        zip248::BundleMap::new(),
    );

    // Freeze → serialize → read back.
    let tx = txdata.freeze().unwrap();
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes).unwrap();
    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu7).unwrap();

    // VP deltas roundtrip correctly.
    assert_eq!(
        tx.value_pool_deltas().fee(),
        Some(Zatoshis::from_u64(10_000).unwrap()),
    );
    assert_eq!(
        tx.value_pool_deltas().zip233_amount(),
        Some(Zatoshis::from_u64(50_000).unwrap()),
    );

    // Txid is deterministic (same inputs → same txid).
    let txdata2 = TransactionData::<super::Authorized>::from_parts_v6(
        super::TxVersion::V6,
        BranchId::Nu7,
        0,
        BlockHeight::from_u32(100),
        {
            let mut vp2 = zip248::ValuePoolDeltas::empty();
            vp2.set_fee(Zatoshis::from_u64(10_000).unwrap());
            vp2.set_zip233(Zatoshis::from_u64(50_000).unwrap());
            vp2
        },
        zip248::BundleMap::new(),
    );
    let tx2 = txdata2.freeze().unwrap();
    assert_eq!(tx.txid(), tx2.txid());

    // Auth commitment is deterministic.
    assert_eq!(
        tx.auth_commitment().as_ref(),
        tx2.auth_commitment().as_ref(),
    );

    // For a transaction with no transparent inputs and no shielded bundles,
    // the v6 txid digest commits to header + VP deltas + empty effects.
    // Verify the VP deltas actually influence the txid by checking a
    // different fee produces a different txid.
    let mut vp_different = zip248::ValuePoolDeltas::empty();
    vp_different.set_fee(Zatoshis::from_u64(20_000).unwrap());
    vp_different.set_zip233(Zatoshis::from_u64(50_000).unwrap());
    let txdata_different = TransactionData::<super::Authorized>::from_parts_v6(
        super::TxVersion::V6,
        BranchId::Nu7,
        0,
        BlockHeight::from_u32(100),
        vp_different,
        zip248::BundleMap::new(),
    );
    let tx3 = txdata_different.freeze().unwrap();
    assert_ne!(tx.txid(), tx3.txid(), "different fee should produce different txid");
}

#[cfg(test)]
mod zip248_tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use super::super::zip248;
    use zcash_protocol::value::{ZatBalance, Zatoshis};

    #[test]
    fn value_pool_deltas_write_read_roundtrip() {
        // Build VP deltas with various entries
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_sapling(ZatBalance::from_i64(100_000).unwrap());
        vp.set_orchard(ZatBalance::from_i64(-50_000).unwrap());
        vp.set_fee(Zatoshis::from_u64(1_000).unwrap());

        // Serialize VP deltas
        let entries = vp.to_wire_entries();
        let mut buf = Vec::new();
        zcash_encoding::CompactSize::write(&mut buf, entries.len()).unwrap();
        for entry in &entries {
            entry.write(&mut buf).unwrap();
        }

        // Deserialize VP deltas
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

        // Verify round-trip
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

        let ((parsed_bt, parsed_bv), parsed_data) = zip248::read_bundle_data_framing(&buf[..]).unwrap();
        assert_eq!(parsed_bt, bt);
        assert_eq!(parsed_bv, bv);
        assert!(parsed_data.is_empty());
    }

    #[test]
    fn bundle_map_unknown_iteration_order() {
        use super::super::Authorized;

        let placeholder_digest = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"test_unknown_efx")
            .hash(&[]);

        let mut map: zip248::BundleMap<Authorized> = zip248::BundleMap::new();

        // Insert in reverse order
        map.insert_unknown(99u64, 0u64, zip248::UnknownBundle {
            effect_data: vec![],
            effect_digest: placeholder_digest,
            auth_data: None,
            auth_digest: None,
        });

        // Verify iteration is in bundle_type order
        let types: Vec<u64> = map.unknown_bundles().map(|(&(bt, _), _)| bt).collect();
        assert_eq!(types, vec![99]);

        // Adding more bundles should maintain order
        map.insert_unknown(50, 0, zip248::UnknownBundle {
            effect_data: vec![1],
            effect_digest: placeholder_digest,
            auth_data: None,
            auth_digest: None,
        });
        let types: Vec<u64> = map.unknown_bundles().map(|(&(bt, _), _)| bt).collect();
        assert_eq!(types, vec![50, 99]);
    }

    /// Verifies that a v6 transaction containing an unknown bundle type can be
    /// parsed and re-serialized. This is the core forward-compatibility
    /// property of ZIP 248.
    #[cfg(zcash_v6)]
    #[test]
    fn unknown_bundle_roundtrip() {
        use super::super::{Authorized, Transaction, TransactionData, TxVersion};
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        // Construct a transaction with a known fee VP delta and an unknown
        // bundle (type 42, variant 0) that has effect data but no auth data.
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_fee(Zatoshis::from_u64(1_000).unwrap());

        let mut bundles: zip248::BundleMap<Authorized> = zip248::BundleMap::new();
        let unknown_effect = vec![0xDE, 0xAD, 0xBE, 0xEF];
        bundles.insert_unknown(42, 0, zip248::UnknownBundle {
            effect_data: unknown_effect.clone(),
            effect_digest: blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"test_unknown_efx")
                .hash(&unknown_effect),
            auth_data: None,
            auth_digest: None,
        });

        let txdata = TransactionData::<Authorized>::from_parts_v6(
            TxVersion::V6,
            BranchId::Nu7,
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
        let tx2 = Transaction::read(&buf[..], BranchId::Nu7).unwrap();

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
}
