use std::convert::TryInto;

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::GroupEncoding;

use crate::{
    consensus,
    extensions::transparent::Precondition,
    legacy::Script,
    serialize::{CompactSize, Vector},
};

use super::{
    components::{Amount, TxOut},
    Transaction, TransactionData, OVERWINTER_VERSION_GROUP_ID, SAPLING_TX_VERSION,
    SAPLING_VERSION_GROUP_ID, ZFUTURE_VERSION_GROUP_ID,
};

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";
const ZCASH_TZE_INPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash_TzeInsHash";
const ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashTzeOutsHash";

const ZCASH_TZE_SIGNED_INPUT_TAG: &[u8; 1] = &[0x00];
const ZCASH_TRANSPARENT_SIGNED_INPUT_TAG: &[u8; 1] = &[0x01];

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

macro_rules! update_hash {
    ($h:expr, $cond:expr, $value:expr) => {
        if $cond {
            $h.update(&$value.as_ref());
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
    ZFuture,
}

impl SigHashVersion {
    fn from_tx(tx: &TransactionData) -> Self {
        if tx.overwintered {
            match tx.version_group_id {
                OVERWINTER_VERSION_GROUP_ID => SigHashVersion::Overwinter,
                SAPLING_VERSION_GROUP_ID => SigHashVersion::Sapling,
                ZFUTURE_VERSION_GROUP_ID => SigHashVersion::ZFuture,
                _ => unimplemented!(),
            }
        } else {
            SigHashVersion::Sprout
        }
    }
}

fn prevout_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.vin.len() * 36);
    for t_in in &tx.vin {
        t_in.prevout.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sequence_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.vin.len() * 4);
    for t_in in &tx.vin {
        (&mut data)
            .write_u32::<LittleEndian>(t_in.sequence)
            .unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SEQUENCE_HASH_PERSONALIZATION)
        .hash(&data)
}

fn outputs_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.vout.len() * (4 + 1));
    for t_out in &tx.vout {
        t_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn single_output_hash(tx_out: &TxOut) -> Blake2bHash {
    let mut data = vec![];
    tx_out.write(&mut data).unwrap();
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn joinsplits_hash(tx: &TransactionData) -> Blake2bHash {
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
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_JOINSPLITS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_spends_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.shielded_spends.len() * 384);
    for s_spend in &tx.shielded_spends {
        data.extend_from_slice(&s_spend.cv.to_bytes());
        data.extend_from_slice(s_spend.anchor.to_repr().as_ref());
        data.extend_from_slice(&s_spend.nullifier);
        s_spend.rk.write(&mut data).unwrap();
        data.extend_from_slice(&s_spend.zkproof);
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_outputs_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.shielded_outputs.len() * 948);
    for s_out in &tx.shielded_outputs {
        s_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn tze_inputs_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = vec![];
    for tzein in &tx.tze_inputs {
        tzein.write_without_witness(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_TZE_INPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn tze_outputs_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = vec![];
    for tzeout in &tx.tze_outputs {
        tzeout.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

pub enum SignableInput<'a> {
    Shielded,
    Transparent {
        index: usize,
        script_code: &'a Script,
        value: Amount,
    },
    Tze {
        index: usize,
        precondition: &'a Precondition,
        value: Amount,
    },
}

impl<'a> SignableInput<'a> {
    pub fn transparent(index: usize, script_code: &'a Script, value: Amount) -> Self {
        SignableInput::Transparent {
            index,
            script_code,
            value,
        }
    }

    pub fn tze(index: usize, precondition: &'a Precondition, value: Amount) -> Self {
        SignableInput::Tze {
            index,
            precondition,
            value,
        }
    }
}

pub fn signature_hash_data<'a>(
    tx: &TransactionData,
    consensus_branch_id: consensus::BranchId,
    hash_type: u32,
    signable_input: SignableInput<'a>,
) -> Vec<u8> {
    let sigversion = SigHashVersion::from_tx(tx);
    match sigversion {
        SigHashVersion::Overwinter | SigHashVersion::Sapling | SigHashVersion::ZFuture => {
            let mut personal = [0; 16];
            (&mut personal[..12]).copy_from_slice(ZCASH_SIGHASH_PERSONALIZATION_PREFIX);
            (&mut personal[12..])
                .write_u32::<LittleEndian>(consensus_branch_id.into())
                .unwrap();

            let mut h = Blake2bParams::new()
                .hash_length(32)
                .personal(&personal)
                .to_state();
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

            if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
            {
                h.update(outputs_hash(tx).as_ref());
            } else if (hash_type & SIGHASH_MASK) == SIGHASH_SINGLE {
                match signable_input {
                    SignableInput::Transparent { index, .. } if index < tx.vout.len() => {
                        h.update(single_output_hash(&tx.vout[index]).as_ref())
                    }
                    _ => h.update(&[0; 32]),
                };
            } else {
                h.update(&[0; 32]);
            };
            if sigversion == SigHashVersion::ZFuture {
                update_hash!(h, !tx.tze_inputs.is_empty(), tze_inputs_hash(tx));
                update_hash!(h, !tx.tze_outputs.is_empty(), tze_outputs_hash(tx));
            }
            update_hash!(h, !tx.joinsplits.is_empty(), joinsplits_hash(tx));
            if sigversion == SigHashVersion::Sapling || sigversion == SigHashVersion::ZFuture {
                update_hash!(h, !tx.shielded_spends.is_empty(), shielded_spends_hash(tx));
                update_hash!(
                    h,
                    !tx.shielded_outputs.is_empty(),
                    shielded_outputs_hash(tx)
                );
            }
            update_u32!(h, tx.lock_time, tmp);
            update_u32!(h, tx.expiry_height.into(), tmp);
            if sigversion == SigHashVersion::Sapling || sigversion == SigHashVersion::ZFuture {
                h.update(&tx.value_balance.to_i64_le_bytes());
            }
            update_u32!(h, hash_type, tmp);

            match signable_input {
                SignableInput::Transparent {
                    index,
                    script_code,
                    value,
                } => {
                    let mut data = if sigversion == SigHashVersion::ZFuture {
                        // domain separation here is to avoid collision attacks
                        // between transparent and TZE inputs.
                        ZCASH_TRANSPARENT_SIGNED_INPUT_TAG.to_vec()
                    } else {
                        vec![]
                    };

                    tx.vin[index].prevout.write(&mut data).unwrap();
                    script_code.write(&mut data).unwrap();
                    data.extend_from_slice(&value.to_i64_le_bytes());
                    (&mut data)
                        .write_u32::<LittleEndian>(tx.vin[index].sequence)
                        .unwrap();
                    h.update(&data);
                }

                SignableInput::Tze {
                    index,
                    precondition,
                    value,
                } if sigversion == SigHashVersion::ZFuture => {
                    // domain separation here is to avoid collision attacks
                    // between transparent and TZE inputs.
                    let mut data = ZCASH_TZE_SIGNED_INPUT_TAG.to_vec();

                    tx.tze_inputs[index].prevout.write(&mut data).unwrap();
                    CompactSize::write(&mut data, precondition.extension_id.try_into().unwrap())
                        .unwrap();
                    CompactSize::write(&mut data, precondition.mode.try_into().unwrap()).unwrap();
                    Vector::write(&mut data, &precondition.payload, |w, e| w.write_u8(*e)).unwrap();
                    data.extend_from_slice(&value.to_i64_le_bytes());
                    h.update(&data);
                }

                SignableInput::Tze { .. } => {
                    panic!("A request has been made to sign a TZE input, but the signature hash version is not ZFuture");
                }

                _ => (),
            }

            h.finalize().as_ref().to_vec()
        }
        SigHashVersion::Sprout => unimplemented!(),
    }
}

pub fn signature_hash<'a>(
    tx: &Transaction,
    consensus_branch_id: consensus::BranchId,
    hash_type: u32,
    signable_input: SignableInput<'a>,
) -> Vec<u8> {
    signature_hash_data(tx, consensus_branch_id, hash_type, signable_input)
}
