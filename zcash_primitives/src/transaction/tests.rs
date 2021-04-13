use proptest::prelude::*;

use super::{
    components::Amount,
    sighash::{signature_hash, SignableInput},
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

        assert_eq!(tx.version, txo.version);
        #[cfg(feature = "zfuture")]
        assert_eq!(tx.tze_inputs, txo.tze_inputs);
        #[cfg(feature = "zfuture")]
        assert_eq!(tx.tze_outputs, txo.tze_outputs);
        assert_eq!(tx.lock_time, txo.lock_time);
        assert_eq!(tx.transparent_bundle, txo.transparent_bundle);
        assert_eq!(tx.sapling_value_balance(), txo.sapling_value_balance());
    }
}

#[test]
#[cfg(feature = "zfuture")]
fn test_tze_tx_parse() {
    let txn_bytes = vec![
        0xFF, 0xFF, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x52, 0x52, 0x52, 0x52,
        0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52,
        0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x30, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x20, 0xd9, 0x81, 0x80, 0x87, 0xde, 0x72, 0x44, 0xab, 0xc1, 0xb5, 0xfc,
        0xf2, 0x8e, 0x55, 0xe4, 0x2c, 0x7f, 0xf9, 0xc6, 0x78, 0xc0, 0x60, 0x51, 0x81, 0xf3, 0x7a,
        0xc5, 0xd7, 0x41, 0x4a, 0x7b, 0x95, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let tx = Transaction::read(&txn_bytes[..]);

    match tx {
        Ok(tx) => assert!(!tx.tze_inputs.is_empty()),

        Err(e) => panic!(
            "An error occurred parsing a serialized TZE transaction: {}",
            e
        ),
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
