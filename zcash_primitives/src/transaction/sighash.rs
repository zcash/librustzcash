use blake2_rfc::blake2b::Blake2b;
use byteorder::{LittleEndian, WriteBytesExt};
use ff::{PrimeField, PrimeFieldRepr};

use super::{
    components::{Amount, Script, TxOut},
    Transaction, TransactionData, OVERWINTER_VERSION_GROUP_ID, SAPLING_TX_VERSION,
    SAPLING_VERSION_GROUP_ID,
};

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &'static [u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &'static [u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &'static [u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &'static [u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &'static [u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &'static [u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &'static [u8; 16] = b"ZcashSOutputHash";

pub const SIGHASH_ALL: u32 = 1;
const SIGHASH_NONE: u32 = 2;
const SIGHASH_SINGLE: u32 = 3;
const SIGHASH_MASK: u32 = 0x1f;
const SIGHASH_ANYONECANPAY: u32 = 0x80;

macro_rules! update_u32 {
    ($h:expr, $value:expr, $tmp:expr) => {
        (&mut $tmp[..4]).write_u32::<LittleEndian>($value).unwrap();
        $h.update(&$tmp[..4]);
    };
}

macro_rules! update_i64 {
    ($h:expr, $value:expr, $tmp:expr) => {
        (&mut $tmp[..8]).write_i64::<LittleEndian>($value).unwrap();
        $h.update(&$tmp[..8]);
    };
}

macro_rules! update_hash {
    ($h:expr, $cond:expr, $value:expr) => {
        if $cond {
            $h.update(&$value);
        } else {
            $h.update(&[0; 32]);
        }
    };
}

#[derive(PartialEq)]
enum SigHashVersion {
    Sprout,
    Overwinter,
    Sapling,
}

impl SigHashVersion {
    fn from_tx(tx: &TransactionData) -> Self {
        if tx.overwintered {
            match tx.version_group_id {
                OVERWINTER_VERSION_GROUP_ID => SigHashVersion::Overwinter,
                SAPLING_VERSION_GROUP_ID => SigHashVersion::Sapling,
                _ => unimplemented!(),
            }
        } else {
            SigHashVersion::Sprout
        }
    }
}

fn prevout_hash(tx: &TransactionData) -> Vec<u8> {
    let mut data = Vec::with_capacity(tx.vin.len() * 36);
    for t_in in &tx.vin {
        t_in.prevout.write(&mut data).unwrap();
    }
    let mut h = Blake2b::with_params(32, &[], &[], ZCASH_PREVOUTS_HASH_PERSONALIZATION);
    h.update(&data);
    h.finalize().as_ref().to_vec()
}

fn sequence_hash(tx: &TransactionData) -> Vec<u8> {
    let mut data = Vec::with_capacity(tx.vin.len() * 4);
    for t_in in &tx.vin {
        (&mut data)
            .write_u32::<LittleEndian>(t_in.sequence)
            .unwrap();
    }
    let mut h = Blake2b::with_params(32, &[], &[], ZCASH_SEQUENCE_HASH_PERSONALIZATION);
    h.update(&data);
    h.finalize().as_ref().to_vec()
}

fn outputs_hash(tx: &TransactionData) -> Vec<u8> {
    let mut data = Vec::with_capacity(tx.vout.len() * (4 + 1));
    for t_out in &tx.vout {
        t_out.write(&mut data).unwrap();
    }
    let mut h = Blake2b::with_params(32, &[], &[], ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    h.update(&data);
    h.finalize().as_ref().to_vec()
}

fn single_output_hash(tx_out: &TxOut) -> Vec<u8> {
    let mut data = vec![];
    tx_out.write(&mut data).unwrap();
    let mut h = Blake2b::with_params(32, &[], &[], ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    h.update(&data);
    h.finalize().as_ref().to_vec()
}

fn joinsplits_hash(tx: &TransactionData) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        tx.joinsplits.len()
            * if tx.version < SAPLING_TX_VERSION {
                1802 // JSDescription with PHGR13 proof
            } else {
                1698 // JSDescription with Groth16 proof
            },
    );
    for js in &tx.joinsplits {
        js.write(&mut data).unwrap();
    }
    data.extend_from_slice(&tx.joinsplit_pubkey.unwrap());
    let mut h = Blake2b::with_params(32, &[], &[], ZCASH_JOINSPLITS_HASH_PERSONALIZATION);
    h.update(&data);
    h.finalize().as_ref().to_vec()
}

fn shielded_spends_hash(tx: &TransactionData) -> Vec<u8> {
    let mut data = Vec::with_capacity(tx.shielded_spends.len() * 384);
    for s_spend in &tx.shielded_spends {
        s_spend.cv.write(&mut data).unwrap();
        s_spend.anchor.into_repr().write_le(&mut data).unwrap();
        data.extend_from_slice(&s_spend.nullifier);
        s_spend.rk.write(&mut data).unwrap();
        data.extend_from_slice(&s_spend.zkproof);
    }
    let mut h = Blake2b::with_params(32, &[], &[], ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION);
    h.update(&data);
    h.finalize().as_ref().to_vec()
}

fn shielded_outputs_hash(tx: &TransactionData) -> Vec<u8> {
    let mut data = Vec::with_capacity(tx.shielded_outputs.len() * 948);
    for s_out in &tx.shielded_outputs {
        s_out.write(&mut data).unwrap();
    }
    let mut h = Blake2b::with_params(32, &[], &[], ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION);
    h.update(&data);
    h.finalize().as_ref().to_vec()
}

pub fn signature_hash_data(
    tx: &TransactionData,
    consensus_branch_id: u32,
    hash_type: u32,
    transparent_input: Option<(usize, Script, Amount)>,
) -> Vec<u8> {
    let sigversion = SigHashVersion::from_tx(tx);
    match sigversion {
        SigHashVersion::Overwinter | SigHashVersion::Sapling => {
            let hash_outputs = if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
            {
                outputs_hash(tx)
            } else if (hash_type & SIGHASH_MASK) == SIGHASH_SINGLE
                && transparent_input.is_some()
                && transparent_input.as_ref().unwrap().0 < tx.vout.len()
            {
                single_output_hash(&tx.vout[transparent_input.as_ref().unwrap().0])
            } else {
                vec![0; 32]
            };

            let mut personal = [0; 16];
            (&mut personal[..12]).copy_from_slice(ZCASH_SIGHASH_PERSONALIZATION_PREFIX);
            (&mut personal[12..])
                .write_u32::<LittleEndian>(consensus_branch_id)
                .unwrap();

            let mut h = Blake2b::with_params(32, &[], &[], &personal);
            let mut tmp = [0; 8];

            update_u32!(h, tx.header(), tmp);
            update_u32!(h, tx.version_group_id, tmp);
            update_hash!(h, hash_type & SIGHASH_ANYONECANPAY == 0, prevout_hash(tx));
            update_hash!(
                h,
                hash_type & SIGHASH_ANYONECANPAY == 0
                    && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                    && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
                sequence_hash(tx)
            );
            h.update(&hash_outputs);
            update_hash!(h, !tx.joinsplits.is_empty(), joinsplits_hash(tx));
            if sigversion == SigHashVersion::Sapling {
                update_hash!(h, !tx.shielded_spends.is_empty(), shielded_spends_hash(tx));
                update_hash!(
                    h,
                    !tx.shielded_outputs.is_empty(),
                    shielded_outputs_hash(tx)
                );
            }
            update_u32!(h, tx.lock_time, tmp);
            update_u32!(h, tx.expiry_height, tmp);
            if sigversion == SigHashVersion::Sapling {
                update_i64!(h, tx.value_balance.0, tmp);
            }
            update_u32!(h, hash_type, tmp);

            if let Some((n, script_code, amount)) = transparent_input {
                let mut data = vec![];
                tx.vin[n].prevout.write(&mut data).unwrap();
                script_code.write(&mut data).unwrap();
                (&mut data).write_i64::<LittleEndian>(amount.0).unwrap();
                (&mut data)
                    .write_u32::<LittleEndian>(tx.vin[n].sequence)
                    .unwrap();
                h.update(&data);
            }

            h.finalize().as_ref().to_vec()
        }
        SigHashVersion::Sprout => unimplemented!(),
    }
}

pub fn signature_hash(
    tx: &Transaction,
    consensus_branch_id: u32,
    hash_type: u32,
    transparent_input: Option<(usize, Script, Amount)>,
) -> Vec<u8> {
    signature_hash_data(tx, consensus_branch_id, hash_type, transparent_input)
}
