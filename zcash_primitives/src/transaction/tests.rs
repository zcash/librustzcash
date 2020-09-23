use ff::Field;
use rand_core::OsRng;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;

use crate::{
    consensus::BranchId, constants::SPENDING_KEY_GENERATOR, extensions::transparent as tze,
    legacy::Script, redjubjub::PrivateKey,
};

use super::{
    components::amount::MAX_MONEY,
    components::{Amount, OutPoint, TxIn, TxOut, TzeIn, TzeOut},
    sighash::{signature_hash, SignableInput},
    Transaction, TransactionData, OVERWINTER_TX_VERSION, OVERWINTER_VERSION_GROUP_ID,
    SAPLING_TX_VERSION, SAPLING_VERSION_GROUP_ID, ZFUTURE_TX_VERSION, ZFUTURE_VERSION_GROUP_ID,
};

prop_compose! {
    fn arb_outpoint()(hash in prop::array::uniform32(1u8..), n in 1..(100 as u32)) -> OutPoint {
        OutPoint::new(hash, n)
    }
}

const VALID_OPCODES: [u8; 8] = [
    0x00, // OP_FALSE,
    0x51, // OP_1,
    0x52, // OP_2,
    0x53, // OP_3,
    0xac, // OP_CHECKSIG,
    0x63, // OP_IF,
    0x65, // OP_VERIF,
    0x6a, // OP_RETURN,
];

prop_compose! {
    fn arb_script()(v in vec(select(&VALID_OPCODES[..]), 1..256)) -> Script {
        Script(v)
    }
}

prop_compose! {
    fn arb_txin()(prevout in arb_outpoint(), script_sig in arb_script(), sequence in any::<u32>()) -> TxIn {
        TxIn { prevout, script_sig, sequence }
    }
}

prop_compose! {
    fn arb_amount()(value in 0..MAX_MONEY) -> Amount {
        Amount::from_i64(value).unwrap()
    }
}

prop_compose! {
    fn arb_txout()(value in arb_amount(), script_pubkey in arb_script()) -> TxOut {
        TxOut { value, script_pubkey }
    }
}

prop_compose! {
    fn arb_witness()(extension_id in 0..(100 as u32), mode in (0..100 as u32), payload in vec(any::<u8>(), 32..256))  -> tze::Witness {
        tze::Witness { extension_id, mode, payload }
    }
}

prop_compose! {
    fn arb_tzein()(prevout in arb_outpoint(), witness in arb_witness()) -> TzeIn {
        TzeIn { prevout, witness }
    }
}

prop_compose! {
    fn arb_precondition()(extension_id in 0..(100 as u32), mode in (0..100 as u32), payload in vec(any::<u8>(), 32..256))  -> tze::Precondition {
        tze::Precondition { extension_id, mode, payload }
    }
}

prop_compose! {
    fn arb_tzeout()(value in arb_amount(), precondition in arb_precondition()) -> TzeOut {
        TzeOut { value, precondition }
    }
}

fn tx_versions(branch_id: BranchId) -> impl Strategy<Value = (u32, u32)> {
    match branch_id {
        BranchId::Sprout => (1..(2 as u32)).prop_map(|i| (i, 0)).boxed(),
        BranchId::Overwinter => Just((OVERWINTER_TX_VERSION, OVERWINTER_VERSION_GROUP_ID)).boxed(),
        BranchId::ZFuture => Just((ZFUTURE_TX_VERSION, ZFUTURE_VERSION_GROUP_ID)).boxed(),
        _otherwise => Just((SAPLING_TX_VERSION, SAPLING_VERSION_GROUP_ID)).boxed(),
    }
}

prop_compose! {
    fn arb_txdata(branch_id: BranchId)(
        (version, version_group_id) in tx_versions(branch_id),
        vin in vec(arb_txin(), 0..10),
        vout in vec(arb_txout(), 0..10),
        tze_inputs in vec(arb_tzein(), 0..10),
        tze_outputs in vec(arb_tzeout(), 0..10),
        lock_time in any::<u32>(),
        expiry_height in any::<u32>(),
        value_balance in arb_amount(),
    ) -> TransactionData {
        TransactionData {
            overwintered: branch_id != BranchId::Sprout,
            version,
            version_group_id,
            vin, vout,
            tze_inputs:  if branch_id == BranchId::ZFuture { tze_inputs } else { vec![] },
            tze_outputs: if branch_id == BranchId::ZFuture { tze_outputs } else { vec![] },
            lock_time,
            expiry_height: expiry_height.into(),
            value_balance,
            shielded_spends: vec![], //FIXME
            shielded_outputs: vec![], //FIXME
            joinsplits: vec![], //FIXME
            joinsplit_pubkey: None, //FIXME
            joinsplit_sig: None, //FIXME
            binding_sig: None, //FIXME
        }
    }
}

prop_compose! {
    fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
        Transaction::from_data(tx_data).unwrap()
    }
}

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

#[test]
fn tx_write_rejects_unexpected_joinsplit_pubkey() {
    // Succeeds without a JoinSplit pubkey
    assert!(TransactionData::new().freeze().is_ok());

    // Fails with an unexpected JoinSplit pubkey
    {
        let mut tx = TransactionData::new();
        tx.joinsplit_pubkey = Some([0; 32]);
        assert!(tx.freeze().is_err());
    }
}

#[test]
fn tx_write_rejects_unexpected_joinsplit_sig() {
    // Succeeds without a JoinSplit signature
    assert!(TransactionData::new().freeze().is_ok());

    // Fails with an unexpected JoinSplit signature
    {
        let mut tx = TransactionData::new();
        tx.joinsplit_sig = Some([0; 64]);
        assert!(tx.freeze().is_err());
    }
}

#[test]
fn tx_write_rejects_unexpected_binding_sig() {
    // Succeeds without a binding signature
    assert!(TransactionData::new().freeze().is_ok());

    // Fails with an unexpected binding signature
    {
        let mut rng = OsRng;
        let sk = PrivateKey(jubjub::Fr::random(&mut rng));
        let sig = sk.sign(b"Foo bar", &mut rng, SPENDING_KEY_GENERATOR);

        let mut tx = TransactionData::new();
        tx.binding_sig = Some(sig);
        assert!(tx.freeze().is_err());
    }
}

proptest! {
    #[test]
    fn test_tze_roundtrip(tx in arb_tx(BranchId::ZFuture)) {
        let mut txn_bytes = vec![];
        tx.write(&mut txn_bytes).unwrap();

        let txo = Transaction::read(&txn_bytes[..]).unwrap();

        assert_eq!(tx.overwintered, txo.overwintered);
        assert_eq!(tx.version, txo.version);
        assert_eq!(tx.version_group_id, txo.version_group_id);
        assert_eq!(tx.vin, txo.vin);
        assert_eq!(tx.vout, txo.vout);
        assert_eq!(tx.tze_inputs, txo.tze_inputs);
        assert_eq!(tx.tze_outputs, txo.tze_outputs);
        assert_eq!(tx.lock_time, txo.lock_time);
        assert_eq!(tx.value_balance, txo.value_balance);
    }
}

#[test]
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

        Err(e) => assert!(
            false,
            format!(
                "An error occurred parsing a serialized TZE transaction: {}",
                e
            )
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
            signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, signable_input),
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
            signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, signable_input),
            tv.sighash
        );
    }
}
