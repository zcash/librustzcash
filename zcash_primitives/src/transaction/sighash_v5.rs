use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params, State};
use byteorder::{LittleEndian, WriteBytesExt};

use crate::transaction::{
    components::transparent::{self, TxOut},
    sighash::{
        SignableInput, TransparentInput, SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE,
        SIGHASH_SINGLE,
    },
    txid::{
        to_hash, transparent_outputs_hash, transparent_prevout_hash, transparent_sequence_hash,
    },
    Authorization, TransactionData, TransparentDigests, TxDigests,
};

#[cfg(feature = "zfuture")]
use std::convert::TryInto;

#[cfg(feature = "zfuture")]
use crate::{
    serialize::{CompactSize, Vector},
    transaction::{components::tze, sighash::TzeInput, TzeDigests},
};

const ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash___TxInHash";

#[cfg(feature = "zfuture")]
const ZCASH_TZE_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash__TzeInHash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

fn transparent_input_sigdigests<A: transparent::Authorization>(
    bundle: &transparent::Bundle<A>,
    input: &TransparentInput<'_>,
    txid_digests: &TransparentDigests<Blake2bHash>,
    hash_type: u32,
) -> TransparentDigests<Blake2bHash> {
    let flag_anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;
    let flag_single = hash_type & SIGHASH_MASK == SIGHASH_SINGLE;
    let flag_none = hash_type & SIGHASH_MASK == SIGHASH_NONE;

    let prevout_digest = if flag_anyonecanpay {
        transparent_prevout_hash::<A>(&[])
    } else {
        txid_digests.prevout_digest
    };

    let sequence_digest = if flag_anyonecanpay || flag_single || flag_none {
        transparent_sequence_hash::<A>(&[])
    } else {
        txid_digests.sequence_digest
    };

    let outputs_digest = if flag_single {
        if input.index() < bundle.vout.len() {
            transparent_outputs_hash(&[&bundle.vout[input.index()]])
        } else {
            transparent_outputs_hash::<TxOut>(&[])
        }
    } else if flag_none {
        transparent_outputs_hash::<TxOut>(&[])
    } else {
        txid_digests.outputs_digest
    };

    // If we are serializing an input (i.e. this is not a JoinSplit signature hash):
    //   a. outpoint (32-byte hash + 4-byte little endian)
    //   b. scriptCode of the input (serialized as scripts inside CTxOuts)
    //   c. value of the output spent by this input (8-byte little endian)
    //   d. nSequence of the input (4-byte little endian)
    let mut ch = hasher(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION);
    let txin = &bundle.vin[input.index()];
    txin.prevout.write(&mut ch).unwrap();
    input.script_code().write(&mut ch).unwrap();
    ch.write_all(&input.value().to_i64_le_bytes()).unwrap();
    ch.write_u32::<LittleEndian>(txin.sequence).unwrap();
    let per_input_digest = ch.finalize();

    TransparentDigests {
        prevout_digest,
        sequence_digest,
        outputs_digest,
        per_input_digest: Some(per_input_digest),
    }
}

#[cfg(feature = "zfuture")]
fn tze_input_sigdigests<A: tze::Authorization>(
    bundle: &tze::Bundle<A>,
    input: &TzeInput<'_>,
    txid_digests: &TzeDigests<Blake2bHash>,
) -> TzeDigests<Blake2bHash> {
    let mut ch = hasher(ZCASH_TZE_INPUT_HASH_PERSONALIZATION);
    let tzein = &bundle.vin[input.index()];
    tzein.prevout.write(&mut ch).unwrap();
    CompactSize::write(
        &mut ch,
        input.precondition().extension_id.try_into().unwrap(),
    )
    .unwrap();
    CompactSize::write(&mut ch, input.precondition().mode.try_into().unwrap()).unwrap();
    Vector::write(&mut ch, &input.precondition().payload, |w, e| {
        w.write_u8(*e)
    })
    .unwrap();
    ch.write_all(&input.value().to_i64_le_bytes()).unwrap();
    let per_input_digest = ch.finalize();

    TzeDigests {
        inputs_digest: txid_digests.inputs_digest,
        outputs_digest: txid_digests.outputs_digest,
        per_input_digest: Some(per_input_digest),
    }
}

pub fn v5_signature_hash<A: Authorization>(
    tx: &TransactionData<A>,
    txid_parts: &TxDigests<Blake2bHash>,
    signable_input: &SignableInput<'_>,
    hash_type: u32,
) -> Blake2bHash {
    match signable_input {
        SignableInput::Shielded => to_hash(
            tx.version,
            tx.consensus_branch_id,
            txid_parts.header_digest,
            txid_parts.transparent_digests.as_ref(),
            txid_parts.sapling_digest,
            txid_parts.orchard_digest,
            #[cfg(feature = "zfuture")]
            txid_parts.tze_digests.as_ref(),
        ),
        SignableInput::Transparent(input) => {
            if let Some((bundle, txid_digests)) = tx
                .transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref())
            {
                to_hash(
                    tx.version,
                    tx.consensus_branch_id,
                    txid_parts.header_digest,
                    Some(&transparent_input_sigdigests(
                        bundle,
                        input,
                        txid_digests,
                        hash_type,
                    )),
                    txid_parts.sapling_digest,
                    txid_parts.orchard_digest,
                    #[cfg(feature = "zfuture")]
                    txid_parts.tze_digests.as_ref(),
                )
            } else {
                panic!("It is not possible to sign a transparent input with missing bundle data.")
            }
        }
        #[cfg(feature = "zfuture")]
        SignableInput::Tze(input) => {
            if let Some((bundle, txid_digests)) =
                tx.tze_bundle.as_ref().zip(txid_parts.tze_digests.as_ref())
            {
                to_hash(
                    tx.version,
                    tx.consensus_branch_id,
                    txid_parts.header_digest,
                    txid_parts.transparent_digests.as_ref(),
                    txid_parts.sapling_digest,
                    txid_parts.orchard_digest,
                    #[cfg(feature = "zfuture")]
                    Some(&tze_input_sigdigests(bundle, input, txid_digests)),
                )
            } else {
                panic!("It is not possible to sign a tze input with missing bundle data.")
            }
        }
    }
}
