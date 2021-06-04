use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::GroupEncoding;

use crate::consensus::BranchId;

use super::{
    components::{
        sapling::{self, GrothProofBytes, OutputDescription, SpendDescription},
        sprout::JsDescription,
        transparent::{self, TxIn, TxOut},
    },
    sighash::{SignableInput, SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE},
    Authorization, TransactionData,
};

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";

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

fn prevout_hash<TA: transparent::Authorization>(vin: &[TxIn<TA>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vin.len() * 36);
    for t_in in vin {
        t_in.prevout.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sequence_hash<TA: transparent::Authorization>(vin: &[TxIn<TA>]) -> Blake2bHash {
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
    consensus_branch_id: BranchId,
    joinsplits: &[JsDescription],
    joinsplit_pubkey: &[u8; 32],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(
        joinsplits.len()
            * if consensus_branch_id.sprout_uses_groth_proofs() {
                1698 // JSDescription with Groth16 proof
            } else {
                1802 // JsDescription with PHGR13 proof
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

fn shielded_spends_hash<A: sapling::Authorization<Proof = GrothProofBytes>>(
    shielded_spends: &[SpendDescription<A>],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(shielded_spends.len() * 384);
    for s_spend in shielded_spends {
        data.extend_from_slice(&s_spend.cv.to_bytes());
        data.extend_from_slice(s_spend.anchor.to_repr().as_ref());
        data.extend_from_slice(&s_spend.nullifier.as_ref());
        s_spend.rk.write(&mut data).unwrap();
        data.extend_from_slice(&s_spend.zkproof);
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_outputs_hash(shielded_outputs: &[OutputDescription<GrothProofBytes>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(shielded_outputs.len() * 948);
    for s_out in shielded_outputs {
        s_out.write_v4(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

pub fn v4_signature_hash<
    SA: sapling::Authorization<Proof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA>,
>(
    tx: &TransactionData<A>,
    signable_input: SignableInput<'_>,
    hash_type: u32,
) -> Blake2bHash {
    if tx.version.has_overwinter() {
        let mut personal = [0; 16];
        (&mut personal[..12]).copy_from_slice(ZCASH_SIGHASH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32::<LittleEndian>(tx.consensus_branch_id.into())
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
            prevout_hash(
                tx.transparent_bundle
                    .as_ref()
                    .map_or(&[], |b| b.vin.as_slice())
            )
        );
        update_hash!(
            h,
            (hash_type & SIGHASH_ANYONECANPAY) == 0
                && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
            sequence_hash(
                tx.transparent_bundle
                    .as_ref()
                    .map_or(&[], |b| b.vin.as_slice())
            )
        );

        if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
            && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
        {
            h.update(
                outputs_hash(
                    tx.transparent_bundle
                        .as_ref()
                        .map_or(&[], |b| b.vout.as_slice()),
                )
                .as_bytes(),
            );
        } else if (hash_type & SIGHASH_MASK) == SIGHASH_SINGLE {
            match (tx.transparent_bundle.as_ref(), &signable_input) {
                (Some(b), SignableInput::Transparent(input)) if input.index() < b.vout.len() => {
                    h.update(single_output_hash(&b.vout[input.index()]).as_bytes())
                }
                _ => h.update(&[0; 32]),
            };
        } else {
            h.update(&[0; 32]);
        };

        update_hash!(
            h,
            !tx.sprout_bundle
                .as_ref()
                .map_or(true, |b| b.joinsplits.is_empty()),
            {
                let bundle = tx.sprout_bundle.as_ref().unwrap();
                joinsplits_hash(
                    tx.consensus_branch_id,
                    &bundle.joinsplits,
                    &bundle.joinsplit_pubkey,
                )
            }
        );

        if tx.version.has_sapling() {
            update_hash!(
                h,
                !tx.sapling_bundle
                    .as_ref()
                    .map_or(true, |b| b.shielded_spends.is_empty()),
                shielded_spends_hash(&tx.sapling_bundle.as_ref().unwrap().shielded_spends)
            );
            update_hash!(
                h,
                !tx.sapling_bundle
                    .as_ref()
                    .map_or(true, |b| b.shielded_outputs.is_empty()),
                shielded_outputs_hash(&tx.sapling_bundle.as_ref().unwrap().shielded_outputs)
            );
        }
        update_u32!(h, tx.lock_time, tmp);
        update_u32!(h, tx.expiry_height.into(), tmp);
        if tx.version.has_sapling() {
            h.update(&tx.sapling_value_balance().to_i64_le_bytes());
        }
        update_u32!(h, hash_type, tmp);

        match signable_input {
            SignableInput::Shielded => (),
            SignableInput::Transparent(input) => {
                if let Some(bundle) = tx.transparent_bundle.as_ref() {
                    let mut data = vec![];
                    bundle.vin[input.index()].prevout.write(&mut data).unwrap();
                    input.script_code().write(&mut data).unwrap();
                    data.extend_from_slice(&input.value().to_i64_le_bytes());
                    (&mut data)
                        .write_u32::<LittleEndian>(bundle.vin[input.index()].sequence)
                        .unwrap();
                    h.update(&data);
                } else {
                    panic!(
                        "A request has been made to sign a transparent input, but none are present."
                    );
                }
            }

            #[cfg(feature = "zfuture")]
            SignableInput::Tze(_) => {
                panic!("A request has been made to sign a TZE input, but the transaction version is not ZFuture");
            }
        }

        h.finalize()
    } else {
        panic!("Signature hashing for pre-overwinter transactions is not supported.")
    }
}
