use proptest::prelude::*;

use super::{
    components::Amount,
    sighash_v4::{signature_hash, SignableInput},
    Transaction,
};

use super::testing::{arb_branch_id, arb_tx};

#[test]
fn tx_read_write() {
    let data = &self::data::tx_read_write::TX_READ_WRITE;
    let tx = Transaction::read(&data[..]).unwrap();
    assert_eq!(
        format!("{}", tx.txid()),
        "64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639"
    );

    let mut encoded = Vec::with_capacity(data.len());
    tx.write(&mut encoded).unwrap();
    assert_eq!(&data[..], &encoded[..]);
}

proptest! {
    #[test]
    fn tx_serialization_roundtrip(tx in arb_branch_id().prop_flat_map(arb_tx)) {
        let mut txn_bytes = vec![];
        tx.write(&mut txn_bytes).unwrap();

        let txo = Transaction::read(&txn_bytes[..]).unwrap();

        prop_assert_eq!(tx.version, txo.version);
        prop_assert_eq!(tx.lock_time, txo.lock_time);
        prop_assert_eq!(tx.transparent_bundle.as_ref(), txo.transparent_bundle.as_ref());
        prop_assert_eq!(tx.sapling_value_balance(), txo.sapling_value_balance());
        #[cfg(feature = "zfuture")]
        prop_assert_eq!(tx.tze_bundle.as_ref(), txo.tze_bundle.as_ref());
    }
}

mod data;
#[test]
fn zip_0143() {
    for tv in self::data::zip_0143::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..]).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::transparent(
                n as usize,
                &tv.script_code,
                Amount::from_nonnegative_i64(tv.amount).unwrap(),
            ),
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, signable_input).as_ref(),
            tv.sighash
        );
    }
}

#[test]
fn zip_0243() {
    for tv in self::data::zip_0243::make_test_vectors() {
        let tx = Transaction::read(&tv.tx[..]).unwrap();
        let signable_input = match tv.transparent_input {
            Some(n) => SignableInput::transparent(
                n as usize,
                &tv.script_code,
                Amount::from_nonnegative_i64(tv.amount).unwrap(),
            ),
            _ => SignableInput::Shielded,
        };

        assert_eq!(
            signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, signable_input).as_ref(),
            tv.sighash
        );
    }
}
