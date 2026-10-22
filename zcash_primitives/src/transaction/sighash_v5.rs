use blake2b_simd::{Hash as Blake2bHash, Params};
use corez::io::Write;

use ::transparent::{
    bundle::{self as transparent, TxOut},
    sighash::{
        SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE,
        TransparentAuthorizingContext,
    },
};
use zcash_encoding::Array;

use crate::{
    encoding::StateWrite,
    transaction::{
        Authorization, TransactionData, TransparentDigests, Zip244Digests,
        sighash::SignableInput,
        txid::{
            ZCASH_TRANSPARENT_HASH_PERSONALIZATION, hash_transparent_txid_data, to_hash,
            transparent_outputs_hash, transparent_prevout_hash, transparent_sequence_hash,
        },
    },
};

const ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash___TxInHash";
const ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrAmountsHash";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrScriptsHash";

fn hasher(personal: &[u8; 16]) -> StateWrite {
    StateWrite(Params::new().hash_length(32).personal(personal).to_state())
}

/// Digests over the transparent input amounts and `scriptPubKey`s that every [ZIP 244]
/// signature hash of a transaction shares.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244#s-2c-amounts-sig-digest
#[derive(Clone, Debug)]
pub(crate) struct TransparentInputsDigests {
    amounts: Blake2bHash,
    scripts: Blake2bHash,
}

impl TransparentInputsDigests {
    /// Computes the digests for the inputs of `bundle`, in time linear in the number of
    /// inputs.
    fn new<A: TransparentAuthorizingContext>(bundle: &transparent::Bundle<A>) -> Self {
        let mut amounts = hasher(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION);
        Array::write(
            &mut amounts,
            bundle.authorization.input_amounts(),
            |w, amount| w.write_all(&amount.to_i64_le_bytes()),
        )
        .unwrap();

        let mut scripts = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
        Array::write(
            &mut scripts,
            bundle.authorization.input_scriptpubkeys(),
            |w, script| script.write(w),
        )
        .unwrap();

        TransparentInputsDigests {
            amounts: amounts.finalize(),
            scripts: scripts.finalize(),
        }
    }

    /// Computes the digests for `bundle` if a [ZIP 244] signature hash of a transaction
    /// containing `bundle` commits to them.
    ///
    /// Returns `None` if `bundle` is a coinbase bundle or has no inputs.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244#s-2-transparent-sig-digest
    pub(crate) fn for_bundle<A: TransparentAuthorizingContext>(
        bundle: &transparent::Bundle<A>,
    ) -> Option<Self> {
        (!bundle.is_coinbase() && !bundle.vin.is_empty()).then(|| Self::new(bundle))
    }
}

/// Implements [ZIP 244 section S.2](https://zips.z.cash/zip-0244#s-2-transparent-sig-digest).
///
/// `inputs_digests` are the digests of the inputs of the bundle in `tx_data`, as computed
/// by [`TransparentInputsDigests::for_bundle`]. If they are `None` while the bundle has
/// non-coinbase inputs, this function computes them, in time linear in the number of inputs.
pub(super) fn transparent_sig_digest<A: TransparentAuthorizingContext>(
    tx_data: Option<(&transparent::Bundle<A>, &TransparentDigests<Blake2bHash>)>,
    inputs_digests: Option<&TransparentInputsDigests>,
    input: &SignableInput<'_>,
) -> Blake2bHash {
    match tx_data {
        // No transparent inputs or outputs.
        None => hash_transparent_txid_data(None),
        // No transparent inputs, or coinbase.
        Some((bundle, txid_digests)) if bundle.is_coinbase() || bundle.vin.is_empty() => {
            hash_transparent_txid_data(Some(txid_digests))
        }
        // Some transparent inputs, and not coinbase.
        Some((bundle, txid_digests)) => {
            let hash_type = input.hash_type();
            let flag_anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;
            let flag_single = hash_type & SIGHASH_MASK == SIGHASH_SINGLE;
            let flag_none = hash_type & SIGHASH_MASK == SIGHASH_NONE;

            let prevouts_digest = if flag_anyonecanpay {
                transparent_prevout_hash::<A>(&[])
            } else {
                txid_digests.prevouts_digest
            };

            let (amounts_digest, scripts_digest) = if flag_anyonecanpay {
                (
                    hasher(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION).finalize(),
                    hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION).finalize(),
                )
            } else {
                match inputs_digests {
                    Some(digests) => (digests.amounts, digests.scripts),
                    None => {
                        let digests = TransparentInputsDigests::new(bundle);
                        (digests.amounts, digests.scripts)
                    }
                }
            };

            let sequence_digest = if flag_anyonecanpay {
                transparent_sequence_hash::<A>(&[])
            } else {
                txid_digests.sequence_digest
            };

            let outputs_digest = if let SignableInput::Transparent(input) = input {
                if flag_single {
                    if *input.index() < bundle.vout.len() {
                        transparent_outputs_hash(&[&bundle.vout[*input.index()]])
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

            //S.2g.i:   prevout      (field encoding)
            //S.2g.ii:  value        (8-byte signed little-endian)
            //S.2g.iii: scriptPubKey (field encoding)
            //S.2g.iv:  nSequence    (4-byte unsigned little-endian)
            let mut ch = hasher(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION);
            if let SignableInput::Transparent(input) = input {
                let txin = &bundle.vin[*input.index()];
                txin.prevout().write(&mut ch).unwrap();
                ch.write_all(&input.value().to_i64_le_bytes()).unwrap();
                input.script_pubkey().write(&mut ch).unwrap();
                ch.write_all(&txin.sequence().to_le_bytes()).unwrap();
            }
            let txin_sig_digest = ch.finalize();

            let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);
            h.write_all(&[hash_type]).unwrap();
            h.write_all(prevouts_digest.as_bytes()).unwrap();
            h.write_all(amounts_digest.as_bytes()).unwrap();
            h.write_all(scripts_digest.as_bytes()).unwrap();
            h.write_all(sequence_digest.as_bytes()).unwrap();
            h.write_all(outputs_digest.as_bytes()).unwrap();
            h.write_all(txin_sig_digest.as_bytes()).unwrap();
            h.finalize()
        }
    }
}

/// Implements the [Signature Digest section of ZIP 244](https://zips.z.cash/zip-0244#signature-digest),
/// using the `txid_parts` and transparent `inputs_digests` of `tx`.
pub(crate) fn v5_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &Zip244Digests<Blake2bHash>,
    inputs_digests: Option<&TransparentInputsDigests>,
) -> Blake2bHash {
    // The caller must provide the transparent digests if and only if the transaction has a
    // transparent component.
    assert_eq!(
        tx.transparent_bundle.is_some(),
        txid_parts.transparent_digests.is_some()
    );

    to_hash(
        tx.version,
        tx.consensus_branch_id,
        txid_parts.header_digest,
        transparent_sig_digest(
            tx.transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            inputs_digests,
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
    )
}
