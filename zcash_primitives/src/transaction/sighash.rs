#[cfg(feature = "zfuture")]
use std::convert::TryInto;

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::GroupEncoding;

use crate::{consensus, legacy::Script};

#[cfg(feature = "zfuture")]
use crate::{
    extensions::transparent::Precondition,
    serialize::{CompactSize, Vector},
};

use super::{
    components::{Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut},
    Transaction, TransactionData, TxVersion,
};

#[cfg(feature = "zfuture")]
use super::components::{TzeIn, TzeOut};

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";

#[cfg(feature = "zfuture")]
const ZCASH_TZE_INPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash_TzeInsHash";
#[cfg(feature = "zfuture")]
const ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashTzeOutsHash";

#[cfg(feature = "zfuture")]
const ZCASH_TZE_SIGNED_INPUT_TAG: &[u8; 1] = &[0x00];
#[cfg(feature = "zfuture")]
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

fn has_overwinter_components(version: &TxVersion) -> bool {
    !matches!(version, TxVersion::Sprout(_))
}

fn has_sapling_components(version: &TxVersion) -> bool {
    !matches!(version, TxVersion::Sprout(_) | TxVersion::Overwinter)
}

#[cfg(feature = "zfuture")]
fn has_tze_components(version: &TxVersion) -> bool {
    matches!(version, TxVersion::ZFuture)
}

fn prevout_hash(vin: &[TxIn]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vin.len() * 36);
    for t_in in vin {
        t_in.prevout.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sequence_hash(vin: &[TxIn]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vin.len() * 4);
    for t_in in vin {
        (&mut data)
            .write_u32::<LittleEndian>(t_in.sequence)
            .unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SEQUENCE_HASH_PERSONALIZATION)
        .hash(&data)
}

fn outputs_hash(vout: &[TxOut]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vout.len() * (4 + 1));
    for t_out in vout {
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

fn joinsplits_hash(
    txversion: TxVersion,
    joinsplits: &[JSDescription],
    joinsplit_pubkey: &[u8; 32],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(
        joinsplits.len()
            * if txversion.uses_groth_proofs() {
                1698 // JSDescription with Groth16 proof
            } else {
                1802 // JSDescription with PHGR13 proof
            },
    );
    for js in joinsplits {
        js.write(&mut data).unwrap();
    }
    data.extend_from_slice(joinsplit_pubkey);
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_JOINSPLITS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_spends_hash(shielded_spends: &[SpendDescription]) -> Blake2bHash {
    let mut data = Vec::with_capacity(shielded_spends.len() * 384);
    for s_spend in shielded_spends {
        data.extend_from_slice(&s_spend.cv.to_bytes());
        data.extend_from_slice(s_spend.anchor.to_repr().as_ref());
        data.extend_from_slice(&s_spend.nullifier.0);
        s_spend.rk.write(&mut data).unwrap();
        data.extend_from_slice(&s_spend.zkproof);
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_outputs_hash(shielded_outputs: &[OutputDescription]) -> Blake2bHash {
    let mut data = Vec::with_capacity(shielded_outputs.len() * 948);
    for s_out in shielded_outputs {
        s_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

#[cfg(feature = "zfuture")]
fn tze_inputs_hash(tze_inputs: &[TzeIn]) -> Blake2bHash {
    let mut data = vec![];
    for tzein in tze_inputs {
        tzein.write_without_witness(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_TZE_INPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

#[cfg(feature = "zfuture")]
fn tze_outputs_hash(tze_outputs: &[TzeOut]) -> Blake2bHash {
    let mut data = vec![];
    for tzeout in tze_outputs {
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
    #[cfg(feature = "zfuture")]
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

    #[cfg(feature = "zfuture")]
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
    if has_overwinter_components(&tx.version) {
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

        update_u32!(h, tx.version.header(), tmp);
        update_u32!(h, tx.version.version_group_id(), tmp);
        update_hash!(
            h,
            hash_type & SIGHASH_ANYONECANPAY == 0,
            prevout_hash(&tx.vin)
        );
        update_hash!(
            h,
            hash_type & SIGHASH_ANYONECANPAY == 0
                && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
            sequence_hash(&tx.vin)
        );

        if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
            && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
        {
            h.update(outputs_hash(&tx.vout).as_ref());
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
        #[cfg(feature = "zfuture")]
        if has_tze_components(&tx.version) {
            update_hash!(
                h,
                !tx.tze_inputs.is_empty(),
                tze_inputs_hash(&tx.tze_inputs)
            );
            update_hash!(
                h,
                !tx.tze_outputs.is_empty(),
                tze_outputs_hash(&tx.tze_outputs)
            );
        }
        update_hash!(
            h,
            !tx.joinsplits.is_empty(),
            joinsplits_hash(tx.version, &tx.joinsplits, &tx.joinsplit_pubkey.unwrap())
        );
        if has_sapling_components(&tx.version) {
            update_hash!(
                h,
                !tx.shielded_spends.is_empty(),
                shielded_spends_hash(&tx.shielded_spends)
            );
            update_hash!(
                h,
                !tx.shielded_outputs.is_empty(),
                shielded_outputs_hash(&tx.shielded_outputs)
            );
        }
        update_u32!(h, tx.lock_time, tmp);
        update_u32!(h, tx.expiry_height.into(), tmp);
        if has_sapling_components(&tx.version) {
            h.update(&tx.value_balance.to_i64_le_bytes());
        }
        update_u32!(h, hash_type, tmp);

        match signable_input {
            SignableInput::Transparent {
                index,
                script_code,
                value,
            } => {
                #[cfg(feature = "zfuture")]
                let mut data = if has_tze_components(&tx.version) {
                    // domain separation here is to avoid collision attacks
                    // between transparent and TZE inputs.
                    ZCASH_TRANSPARENT_SIGNED_INPUT_TAG.to_vec()
                } else {
                    vec![]
                };

                #[cfg(not(feature = "zfuture"))]
                let mut data = vec![];

                tx.vin[index].prevout.write(&mut data).unwrap();
                script_code.write(&mut data).unwrap();
                data.extend_from_slice(&value.to_i64_le_bytes());
                (&mut data)
                    .write_u32::<LittleEndian>(tx.vin[index].sequence)
                    .unwrap();
                h.update(&data);
            }

            #[cfg(feature = "zfuture")]
            SignableInput::Tze {
                index,
                precondition,
                value,
            } if has_tze_components(&tx.version) => {
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

            #[cfg(feature = "zfuture")]
            SignableInput::Tze { .. } => {
                panic!("A request has been made to sign a TZE input, but the signature hash version is not ZFuture");
            }

            _ => (),
        }

        h.finalize().as_ref().to_vec()
    } else {
        unimplemented!()
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
