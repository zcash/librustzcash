use std::convert::TryInto;

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{
    consensus::{BlockHeight, BranchId},
    legacy::Script,
};

#[cfg(feature = "zfuture")]
use crate::{
    extensions::transparent::Precondition,
    serialize::{CompactSize, Vector},
};

use super::{
    components::{Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut},
    txid::{
        joinsplits_hash, outputs_hash, prevout_hash, sequence_hash, shielded_outputs_hash,
        shielded_spends_hash, to_hash, ZCASH_TXID_PERSONALIZATION_PREFIX,
    },
    TransactionData, TransactionDigest, TransparentDigests, TxDigests, TxId, TxVersion,
};

#[cfg(feature = "zfuture")]
use super::{
    components::{TzeIn, TzeOut},
    txid::{tze_inputs_hash, tze_outputs_hash},
    TzeDigests,
};

const ZCASH_TZE_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash__TzeInHash";
const ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash___TxInHash";

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";

// #[cfg(feature = "zfuture")]
// const ZCASH_TZE_INPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash_TzeInsHash";
// #[cfg(feature = "zfuture")]
// const ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashTzeOutsHash";

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
            $h.update(&$value.as_bytes());
        } else {
            $h.update(&[0; 32]);
        }
    };
}

// ZIP-0143.10
// If we are serializing an input (i.e. this is not a JoinSplit signature hash):
//   a. outpoint (32-byte hash + 4-byte little endian)
//   b. scriptCode of the input (serialized as scripts inside CTxOuts)
//   c. value of the output spent by this input (8-byte little endian)
//   d. nSequence of the input (4-byte little endian)
fn txin_sig_data(
    txversion: TxVersion,
    txin: &TxIn,
    script_code: &Script,
    value: Amount,
) -> Vec<u8> {
    #[cfg(feature = "zfuture")]
    let mut data = if txversion.has_tze() {
        // domain separation here is to avoid collision attacks
        // between transparent and TZE inputs.
        ZCASH_TRANSPARENT_SIGNED_INPUT_TAG.to_vec()
    } else {
        vec![]
    };

    #[cfg(not(feature = "zfuture"))]
    let mut data = vec![];

    txin.prevout.write(&mut data).unwrap();
    script_code.write(&mut data).unwrap();
    data.extend_from_slice(&value.to_i64_le_bytes());
    (&mut data)
        .write_u32::<LittleEndian>(txin.sequence)
        .unwrap();

    data
}

#[cfg(feature = "zfuture")]
fn tzein_sig_data(tzein: &TzeIn, precondition: &Precondition, value: Amount) -> Vec<u8> {
    // domain separation here is to avoid collision attacks
    // between transparent and TZE inputs.
    let mut data = ZCASH_TZE_SIGNED_INPUT_TAG.to_vec();

    tzein.prevout.write(&mut data).unwrap();
    CompactSize::write(&mut data, precondition.extension_id.try_into().unwrap()).unwrap();
    CompactSize::write(&mut data, precondition.mode.try_into().unwrap()).unwrap();
    Vector::write(&mut data, &precondition.payload, |w, e| w.write_u8(*e)).unwrap();
    data.extend_from_slice(&value.to_i64_le_bytes());

    data
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

    pub fn signing_data(
        &self,
        txversion: TxVersion,
        vin: &[TxIn],
        #[cfg(feature = "zfuture")] tze_inputs: &[TzeIn],
    ) -> Option<Vec<u8>> {
        match self {
            SignableInput::Transparent {
                index,
                script_code,
                value,
                ..
            } => Some(txin_sig_data(txversion, &vin[*index], script_code, *value)),

            #[cfg(feature = "zfuture")]
            SignableInput::Tze {
                index,
                precondition,
                value,
            } if txversion == TxVersion::ZFuture => {
                Some(tzein_sig_data(&tze_inputs[*index], precondition, *value))
            }

            #[cfg(feature = "zfuture")]
            SignableInput::Tze { .. } => {
                panic!("A request has been made to sign a TZE input, but the signature hash version is not ZFuture");
            }

            SignableInput::Shielded => None,
        }
    }
}

pub fn legacy_sig_hash<'a>(
    tx: &TransactionData,
    consensus_branch_id: BranchId,
    hash_type: u32,
    signable_input: SignableInput<'a>,
) -> Blake2bHash {
    if tx.version.has_overwinter() {
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
            (hash_type & SIGHASH_ANYONECANPAY) == 0
                && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
            sequence_hash(&tx.vin)
        );

        if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
            && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
        {
            h.update(outputs_hash(&tx.vout).as_bytes());
        } else if (hash_type & SIGHASH_MASK) == SIGHASH_SINGLE {
            match signable_input {
                SignableInput::Transparent { index, .. } if index < tx.vout.len() => {
                    h.update(outputs_hash(&tx.vout[index..=index]).as_bytes())
                }
                _ => h.update(&[0; 32]),
            };
        } else {
            h.update(&[0; 32]);
        };

        #[cfg(feature = "zfuture")]
        if tx.version.has_tze() {
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
            joinsplits_hash(&tx.joinsplits, &tx.joinsplit_pubkey.unwrap())
        );

        if tx.version.has_sapling() {
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
        if tx.version.has_sapling() {
            h.update(&tx.value_balance.to_i64_le_bytes());
        }
        update_u32!(h, hash_type, tmp);

        match signable_input.signing_data(
            tx.version,
            &tx.vin,
            #[cfg(feature = "zfuture")]
            &tx.tze_inputs,
        ) {
            Option::Some(data) => {
                h.update(&data);
            }
            Option::None => (),
        };

        h.finalize()
    } else {
        unimplemented!()
    }
}

pub struct SignatureHash(Blake2bHash);

impl AsRef<[u8]> for SignatureHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub fn signature_hash<'a, F>(
    tx: &TransactionData,
    consensus_branch_id: BranchId,
    hash_type: u32,
    signable_input: SignableInput<'a>,
    txid_digest: &mut F,
) -> SignatureHash
where
    F: FnMut(&TransactionData) -> TxDigests<Blake2bHash, TxId>,
{
    // the accepted signature hashes are dependent upon 
    SignatureHash(match tx.version {
        TxVersion::Sprout(_)
        | TxVersion::Overwinter
        | TxVersion::Sapling => legacy_sig_hash(tx, consensus_branch_id, hash_type, signable_input),
        #[cfg(feature = "zfuture")]
        TxVersion::ZFuture => {
            let txid_parts = txid_digest(tx);
            let sig_parts = tx.digest(
                SignatureHashDigester {
                    txid_parts,
                    txversion: tx.version,
                    hash_type,
                    signable_input,
                }
            );

            to_hash(
                &sig_parts,
                ZCASH_TXID_PERSONALIZATION_PREFIX,
                tx.version,
                consensus_branch_id,
            )
        }
    })
}

pub struct SignatureHashDigester<'a> {
    txid_parts: TxDigests<Blake2bHash, TxId>,
    txversion: TxVersion,
    hash_type: u32,
    signable_input: SignableInput<'a>,
}

impl<'a> TransactionDigest<Blake2bHash> for SignatureHashDigester<'a> {
    type Purpose = SignatureHash;

    fn digest_header(
        &self,
        _version: TxVersion,
        _lock_time: u32,
        _expiry_height: BlockHeight,
    ) -> Blake2bHash {
        self.txid_parts.header_digest
    }

    fn digest_transparent(&self, vin: &[TxIn], vout: &[TxOut]) -> TransparentDigests<Blake2bHash> {
        let flag_anyonecanpay = self.hash_type & SIGHASH_ANYONECANPAY != 0;
        let flag_single = self.hash_type & SIGHASH_MASK == SIGHASH_SINGLE;
        let flag_none = self.hash_type & SIGHASH_MASK == SIGHASH_NONE;

        let prevout_digest = if flag_anyonecanpay {
            prevout_hash(&[])
        } else {
            self.txid_parts.transparent_digests.prevout_digest
        };

        let sequence_digest = if flag_anyonecanpay || flag_single || flag_none {
            sequence_hash(&[])
        } else {
            self.txid_parts.transparent_digests.sequence_digest
        };

        let outputs_digest = if flag_single {
            match self.signable_input {
                SignableInput::Transparent { index, .. } if index < vout.len() => {
                    outputs_hash(&[&vout[index]])
                }
                _ => outputs_hash::<TxOut>(&[]),
            }
        } else if flag_none {
            outputs_hash::<TxOut>(&[])
        } else {
            self.txid_parts.transparent_digests.outputs_digest
        };

        let per_input_digest = match self.signable_input {
            SignableInput::Transparent {
                index,
                script_code,
                value,
            } => Some({
                Blake2bParams::new()
                    .hash_length(32)
                    .personal(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION)
                    .hash(&txin_sig_data(
                        self.txversion,
                        &vin[index],
                        script_code,
                        value,
                    ))
            }),

            _ => None,
        };

        TransparentDigests {
            prevout_digest,
            sequence_digest,
            outputs_digest,
            per_input_digest,
        }
    }

    #[cfg(feature = "zfuture")]
    fn digest_tze(&self, tze_inputs: &[TzeIn], _tze_outputs: &[TzeOut]) -> TzeDigests<Blake2bHash> {
        let per_input_digest = match self.signable_input {
            SignableInput::Tze {
                index,
                precondition,
                value,
            } if self.txversion == TxVersion::ZFuture => Some({
                Blake2bParams::new()
                    .hash_length(32)
                    .personal(ZCASH_TZE_INPUT_HASH_PERSONALIZATION)
                    .hash(&tzein_sig_data(&tze_inputs[index], precondition, value))
            }),

            _ => None,
        };

        TzeDigests {
            inputs_digest: self.txid_parts.tze_digests.inputs_digest,
            outputs_digest: self.txid_parts.tze_digests.outputs_digest,
            per_input_digest,
        }
    }

    fn digest_sprout(
        &self,
        _joinsplits: &[JSDescription],
        _joinsplit_pubkey: &Option<[u8; 32]>,
    ) -> Blake2bHash {
        self.txid_parts.sprout_digest
    }

    fn digest_sapling(
        &self,
        _shielded_spends: &[SpendDescription],
        _shielded_outputs: &[OutputDescription],
        _value_balance: Amount,
    ) -> Blake2bHash {
        self.txid_parts.sapling_digest
    }
}
