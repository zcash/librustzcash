use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params, State};
use byteorder::{LittleEndian, WriteBytesExt};
use zcash_encoding::Array;

use crate::transaction::{
    components::transparent::{self, TxOut},
    sighash::{
        SignableInput, TransparentAuthorizingContext, SIGHASH_ANYONECANPAY, SIGHASH_MASK,
        SIGHASH_NONE, SIGHASH_SINGLE,
    },
    txid::{
        hash_transparent_txid_data, to_hash, transparent_outputs_hash, transparent_prevout_hash,
        transparent_sequence_hash, ZCASH_TRANSPARENT_HASH_PERSONALIZATION,
    },
    Authorization, TransactionData, TransparentDigests, TxDigests,
};

#[cfg(feature = "zfuture")]
use std::convert::TryInto;

#[cfg(feature = "zfuture")]
use zcash_encoding::{CompactSize, Vector};

#[cfg(feature = "zfuture")]
use crate::transaction::{components::tze, TzeDigests};

const ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash___TxInHash";
const ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrAmountsHash";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrScriptsHash";

#[cfg(feature = "zfuture")]
const ZCASH_TZE_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash__TzeInHash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Implements [ZIP 244 section S.2](https://zips.z.cash/zip-0244#s-2-transparent-sig-digest)
fn transparent_sig_digest<A: TransparentAuthorizingContext>(
    txid_digests: &TransparentDigests<Blake2bHash>,
    bundle: &transparent::Bundle<A>,
    input: &SignableInput<'_>,
) -> Blake2bHash {
    let hash_type = input.hash_type();
    let flag_anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;
    let flag_single = hash_type & SIGHASH_MASK == SIGHASH_SINGLE;
    let flag_none = hash_type & SIGHASH_MASK == SIGHASH_NONE;

    let prevout_digest = if flag_anyonecanpay {
        transparent_prevout_hash::<A>(&[])
    } else {
        txid_digests.prevout_digest
    };

    let amounts_digest = {
        let mut h = hasher(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION);
        Array::write(
            &mut h,
            if flag_anyonecanpay {
                vec![]
            } else {
                bundle.authorization.input_amounts()
            },
            |w, amount| w.write_all(&amount.to_i64_le_bytes()),
        )
        .unwrap();
        h.finalize()
    };

    let scripts_digest = {
        let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
        Array::write(
            &mut h,
            if flag_anyonecanpay {
                vec![]
            } else {
                bundle.authorization.input_scriptpubkeys()
            },
            |w, script| script.write(w),
        )
        .unwrap();
        h.finalize()
    };

    let sequence_digest = if flag_anyonecanpay {
        transparent_sequence_hash::<A>(&[])
    } else {
        txid_digests.sequence_digest
    };

    let outputs_digest = if let SignableInput::Transparent { index, .. } = input {
        if flag_single {
            if *index < bundle.vout.len() {
                transparent_outputs_hash(&[&bundle.vout[*index]])
            } else {
                transparent_outputs_hash::<TxOut>(&[])
            }
        } else if flag_none {
            transparent_outputs_hash::<TxOut>(&[])
        } else {
            txid_digests.outputs_digest
        }
    } else {
        txid_digests.outputs_digest
    };

    // If we are serializing an input (i.e. this is not a JoinSplit signature hash):
    //   a. outpoint (32-byte hash + 4-byte little endian)
    //   b. scriptCode of the input (serialized as scripts inside CTxOuts)
    //   c. value of the output spent by this input (8-byte little endian)
    //   d. nSequence of the input (4-byte little endian)
    let mut ch = hasher(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION);
    if let SignableInput::Transparent {
        index,
        script_pubkey,
        value,
        ..
    } = input
    {
        let txin = &bundle.vin[*index];
        txin.prevout.write(&mut ch).unwrap();
        ch.write_all(&value.to_i64_le_bytes()).unwrap();
        script_pubkey.write(&mut ch).unwrap();
        ch.write_u32::<LittleEndian>(txin.sequence).unwrap();
    }
    let per_input_digest = ch.finalize();

    let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);
    h.write_all(&[hash_type]).unwrap();
    h.write_all(prevout_digest.as_bytes()).unwrap();
    h.write_all(amounts_digest.as_bytes()).unwrap();
    h.write_all(scripts_digest.as_bytes()).unwrap();
    h.write_all(sequence_digest.as_bytes()).unwrap();
    h.write_all(outputs_digest.as_bytes()).unwrap();
    h.write_all(per_input_digest.as_bytes()).unwrap();
    h.finalize()
}

#[cfg(feature = "zfuture")]
fn tze_input_sigdigests<A: tze::Authorization>(
    bundle: &tze::Bundle<A>,
    input: &SignableInput<'_>,
    txid_digests: &TzeDigests<Blake2bHash>,
) -> TzeDigests<Blake2bHash> {
    let mut ch = hasher(ZCASH_TZE_INPUT_HASH_PERSONALIZATION);
    if let SignableInput::Tze {
        index,
        precondition,
        value,
    } = input
    {
        let tzein = &bundle.vin[*index];
        tzein.prevout.write(&mut ch).unwrap();
        CompactSize::write(&mut ch, precondition.extension_id.try_into().unwrap()).unwrap();
        CompactSize::write(&mut ch, precondition.mode.try_into().unwrap()).unwrap();
        Vector::write(&mut ch, &precondition.payload, |w, e| w.write_u8(*e)).unwrap();
        ch.write_all(&value.to_i64_le_bytes()).unwrap();
    }
    let per_input_digest = ch.finalize();

    TzeDigests {
        inputs_digest: txid_digests.inputs_digest,
        outputs_digest: txid_digests.outputs_digest,
        per_input_digest: Some(per_input_digest),
    }
}

/// Implements the [Signature Digest section of ZIP 244](https://zips.z.cash/zip-0244#signature-digest)
pub fn v5_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    to_hash(
        tx.version,
        tx.consensus_branch_id,
        txid_parts.header_digest,
        if let Some(bundle) = &tx.transparent_bundle {
            transparent_sig_digest(
                txid_parts
                    .transparent_digests
                    .as_ref()
                    .expect("Transparent txid digests are missing."),
                &bundle,
                signable_input,
            )
        } else {
            hash_transparent_txid_data(None)
        },
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        #[cfg(feature = "zfuture")]
        tx.tze_bundle
            .as_ref()
            .zip(txid_parts.tze_digests.as_ref())
            .map(|(bundle, tze_digests)| tze_input_sigdigests(bundle, signable_input, tze_digests))
            .as_ref(),
    )
}
