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

/// Roundtrip test for ZIP 233 NSM + fee VP deltas in ZIP 248 format.
// TODO: regenerate cross-implementation test vectors from zcash-hackworks/zcash-test-vectors
#[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
#[test]
fn zip_0233() {
    use super::zip248;
    use zcash_protocol::consensus::BlockHeight;

    let make_tx = |fee: u64, nsm: u64| {
        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_fee(Zatoshis::from_u64(fee).unwrap());
        vp.set_zip233(Zatoshis::from_u64(nsm).unwrap());
        TransactionData::<super::Authorized>::from_parts_v6(
            super::TxVersion::V6,
            BranchId::Nu7,
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
    let tx = Transaction::read(&buf[..], BranchId::Nu7).unwrap();
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

    /// Verifies that a v6 transaction with an unknown bundle type can be
    /// parsed and re-serialized (ZIP 248 forward compatibility).
    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn unknown_bundle_roundtrip() {
        use super::super::{Authorized, Transaction, TransactionData, TxVersion};
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        let mut vp = zip248::ValuePoolDeltas::empty();
        vp.set_fee(Zatoshis::from_u64(1_000).unwrap());

        let mut bundles: zip248::BundleMap<Authorized> = zip248::BundleMap::new();
        bundles.insert_unknown(42, 0, test_unknown_bundle(&[0xDE, 0xAD, 0xBE, 0xEF]));

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

    // -- Consensus rule tests --------------------------------------------------

    #[cfg(zcash_unstable = "nu7")]
    mod consensus_rules {
        use super::super::super::{
            Authorized, TransactionData, TxVersion, V6ConsensusError, ZatBalance, zip248,
        };
        use zcash_protocol::consensus::{BlockHeight, BranchId};
        use zcash_protocol::value::Zatoshis;

        fn make_v6(vp: zip248::ValuePoolDeltas) -> TransactionData<Authorized> {
            TransactionData::from_parts_v6(
                TxVersion::V6,
                BranchId::Nu7,
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
            let tx = make_v6(vp);
            assert_eq!(
                tx.check_v6_consensus_rules(false),
                Err(V6ConsensusError::FeeAssetClassNotZec {
                    asset_class: zip248::ASSET_CLASS_OTHER
                }),
            );
        }

        #[test]
        fn coinbase_fee_delta_must_be_nonnegative() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_fee(Zatoshis::from_u64(1000).unwrap()); // stored as -1000
            let tx = make_v6(vp);
            assert_eq!(
                tx.check_v6_consensus_rules(true),
                Err(V6ConsensusError::CoinbaseFeeDeltaNegative {
                    value: ZatBalance::from_i64(-1000).unwrap(),
                }),
            );
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
            let tx = make_v6(vp);
            assert_eq!(
                tx.check_v6_consensus_rules(false),
                Err(V6ConsensusError::NonCoinbaseFeeDeltaPositive {
                    value: ZatBalance::from_i64(1000).unwrap(),
                }),
            );
        }

        #[test]
        fn non_coinbase_vp_deltas_must_balance() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Sapling adds 100k to the pool but nothing subtracts it.
            vp.set_sapling(zcash_protocol::value::ZatBalance::from_i64(100_000).unwrap());
            let tx = make_v6(vp);
            let err = tx.check_v6_consensus_rules(false).unwrap_err();
            assert!(matches!(
                err,
                V6ConsensusError::NonCoinbaseValueImbalance { .. }
            ));
        }

        #[test]
        fn balanced_non_coinbase_passes() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            vp.set_fee(Zatoshis::from_u64(1000).unwrap()); // -1000
            vp.set_sapling(zcash_protocol::value::ZatBalance::from_i64(1000).unwrap()); // +1000
            let tx = make_v6(vp);
            assert_eq!(tx.check_v6_consensus_rules(false), Ok(()));
        }
    }

    // -- Parsing rule rejection tests ------------------------------------------

    #[cfg(zcash_unstable = "nu7")]
    mod parsing_rules {
        use super::super::super::{Transaction, zip248};
        use alloc::vec::Vec;
        use zcash_encoding::CompactSize;
        use zcash_protocol::consensus::BranchId;
        use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};

        /// Builds a minimal v6 transaction header (20 bytes).
        fn v6_header(branch_id: BranchId) -> Vec<u8> {
            let mut buf = Vec::new();
            // header: version 6 with overwintered bit
            buf.extend_from_slice(&(V6_TX_VERSION | (1 << 31)).to_le_bytes());
            buf.extend_from_slice(&V6_VERSION_GROUP_ID.to_le_bytes());
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

        /// Writes a VP delta entry directly to bytes.
        fn write_vp_entry(buf: &mut Vec<u8>, bundle_type: u64, variant: u64, value: i64) {
            CompactSize::write(&mut *buf, bundle_type as usize).unwrap();
            CompactSize::write(&mut *buf, variant as usize).unwrap();
            buf.push(zip248::ASSET_CLASS_ZEC);
            buf.extend_from_slice(&value.to_le_bytes());
        }

        #[test]
        fn rejects_out_of_order_vp_deltas() {
            let mut buf = v6_header(BranchId::Nu7);
            // 2 VP delta entries: Orchard (3) then Sapling (2) — wrong order.
            CompactSize::write(&mut *buf, 2).unwrap();
            write_vp_entry(&mut buf, 3, 0, 100_000); // Orchard first (wrong)
            write_vp_entry(&mut buf, 2, 0, -100_000); // Sapling second
            CompactSize::write(&mut *buf, 0).unwrap(); // nEffectBundles
            CompactSize::write(&mut *buf, 0).unwrap(); // nAuthBundles

            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }

        #[test]
        fn rejects_duplicate_vp_deltas() {
            let mut buf = v6_header(BranchId::Nu7);
            CompactSize::write(&mut *buf, 2).unwrap();
            write_vp_entry(&mut buf, 2, 0, 50_000);
            write_vp_entry(&mut buf, 2, 0, 50_000);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }

        #[test]
        fn rejects_reserved_bundle_type() {
            let mut buf = v6_header(BranchId::Nu7);
            CompactSize::write(&mut *buf, 1).unwrap();
            write_vp_entry(&mut buf, 1, 0, 1000);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }

        #[test]
        fn rejects_zero_vp_delta_value() {
            let mut buf = v6_header(BranchId::Nu7);
            CompactSize::write(&mut *buf, 1).unwrap();
            write_vp_entry(&mut buf, 2, 0, 0);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }

        #[test]
        fn rejects_fee_in_effect_bundles() {
            let mut buf = v6_header(BranchId::Nu7);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 4, 0, &[0xAA]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }

        #[test]
        fn rejects_mismatched_variant_across_maps() {
            let mut buf = v6_header(BranchId::Nu7);
            CompactSize::write(&mut *buf, 1).unwrap();
            write_vp_entry(&mut buf, 2, 0, 100_000);
            // Effect bundle says bundleType 2 variant 1 — mismatch.
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 2, 1, &[]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth

            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }

        #[test]
        fn rejects_auth_without_effect() {
            let mut buf = v6_header(BranchId::Nu7);
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap();
            CompactSize::write(&mut *buf, 1).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 2, 0, &[0xBB]).unwrap();

            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }

        #[test]
        fn accepts_empty_v6_transaction() {
            let mut buf = v6_header(BranchId::Nu7);
            append_empty_body(&mut buf);
            let tx = Transaction::read(&buf[..], BranchId::Nu7).unwrap();
            assert!(tx.transparent_bundle().is_none());
            assert!(tx.sapling_bundle().is_none());
            assert!(tx.orchard_bundle().is_none());
        }

        #[test]
        fn rejects_out_of_order_effect_bundles() {
            let mut buf = v6_header(BranchId::Nu7);
            CompactSize::write(&mut *buf, 0).unwrap(); // no VP deltas
            // Effect bundles: Orchard (3) before Transparent (0) — wrong order.
            CompactSize::write(&mut *buf, 2).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 3, 0, &[0xAA]).unwrap();
            zip248::write_bundle_data_framing(&mut buf, 0, 0, &[0xBB]).unwrap();
            CompactSize::write(&mut *buf, 0).unwrap(); // no auth
            assert!(Transaction::read(&buf[..], BranchId::Nu7).is_err());
        }
    }

    // -- Wire order and roundtrip tests ----------------------------------------

    #[cfg(zcash_v6)]
    mod wire_order {
        use super::super::super::zip248;
        use alloc::vec::Vec;
        use zcash_protocol::value::{ZatBalance, Zatoshis};

        #[test]
        fn to_wire_entries_canonical_order_with_unknown() {
            let mut vp = zip248::ValuePoolDeltas::empty();
            // Known: Orchard (3), Fee (4)
            vp.set_orchard(ZatBalance::from_i64(50_000).unwrap());
            vp.set_fee(Zatoshis::from_u64(1_000).unwrap());
            // Unknown: bundleType 8 (sorts after all known types)
            vp.insert_unknown(8, 0, [0u8; 64], 0, ZatBalance::from_i64(99_000).unwrap());

            let entries = vp.to_wire_entries();
            let types: Vec<u64> = entries.iter().map(|e| e.bundle_type).collect();
            // Orchard=3, Fee=4, Unknown=8 — strictly increasing.
            assert_eq!(types, vec![3, 4, 8]);
        }
    }

    // -- Sighash version info error tests --------------------------------------

    #[cfg(zcash_v6)]
    mod sighash_info {
        use super::super::super::zip248;

        #[test]
        fn rejects_wrong_sighash_version() {
            // sighashInfo with version byte 0x01 instead of 0x00.
            let data: &[u8] = &[0x01, 0x01]; // compactSize(1), version=1
            let mut cursor = data;
            let result = zip248::consume_v6_sighash_v0_info(&mut cursor, "test");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_wrong_sighash_length() {
            // sighashInfo with length 2 instead of 1.
            let data: &[u8] = &[0x02, 0x00, 0x00]; // compactSize(2), two bytes
            let mut cursor = data;
            let result = zip248::consume_v6_sighash_v0_info(&mut cursor, "test");
            assert!(result.is_err());
        }
    }

    // -- In-memory-only BundleType panic tests ---------------------------------

    #[test]
    #[should_panic(expected = "in-memory-only")]
    fn sprout_bundle_type_has_no_wire_encoding() {
        let _ = zip248::BundleType::Sprout.to_u64();
    }

    #[test]
    #[should_panic(expected = "in-memory-only")]
    fn tze_bundle_type_has_no_wire_encoding() {
        let _ = zip248::BundleType::Tze.to_u64();
    }
}
