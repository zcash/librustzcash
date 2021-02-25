use std::convert::TryInto;
use std::io::Write;

use blake2b_simd::Hash as Blake2bHash;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::consensus::BlockHeight;

#[cfg(feature = "zfuture")]
use crate::serialize::{CompactSize, Vector};

use super::{
    blake2b_256::HashWriter,
    components::{Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut},
    sighash::{
        SignableInput, SignatureHash, SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE,
        SIGHASH_SINGLE,
    },
    txid::{outputs_hash, prevout_hash, sequence_hash},
    TransactionDigest, TransparentDigests, TxDigests, TxId, TxVersion,
};

#[cfg(feature = "zfuture")]
use super::{
    components::{TzeIn, TzeOut},
    TzeDigests,
};

const ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash___TxInHash";

#[cfg(feature = "zfuture")]
const ZCASH_TZE_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash__TzeInHash";

pub struct SignatureHashDigester<'a> {
    pub txid_parts: TxDigests<Blake2bHash, TxId>,
    pub txversion: TxVersion,
    pub hash_type: u32,
    pub signable_input: SignableInput<'a>,
}

impl<'a> TransactionDigest<Blake2bHash, TransparentDigests<Blake2bHash>, TzeDigests<Blake2bHash>, Blake2bHash, Blake2bHash> for SignatureHashDigester<'a> {
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

        let mut ch = HashWriter::new(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION);
        let per_input_digest = match self.signable_input {
            SignableInput::Transparent {
                index,
                script_code,
                value,
            } => {
                // ZIP-0143.10
                // If we are serializing an input (i.e. this is not a JoinSplit signature hash):
                //   a. outpoint (32-byte hash + 4-byte little endian)
                //   b. scriptCode of the input (serialized as scripts inside CTxOuts)
                //   c. value of the output spent by this input (8-byte little endian)
                //   d. nSequence of the input (4-byte little endian)
                let txin = &vin[index];
                txin.prevout.write(&mut ch).unwrap();
                script_code.write(&mut ch).unwrap();
                ch.write_all(&value.to_i64_le_bytes()).unwrap();
                ch.write_u32::<LittleEndian>(txin.sequence).unwrap();
                ch.finalize()
            }

            _ => ch.finalize(),
        };

        TransparentDigests {
            prevout_digest,
            sequence_digest,
            outputs_digest,
            per_input_digest: Some(per_input_digest),
        }
    }

    #[cfg(feature = "zfuture")]
    fn digest_tze(&self, tze_inputs: &[TzeIn], _tze_outputs: &[TzeOut]) -> TzeDigests<Blake2bHash> {
        let mut ch = HashWriter::new(ZCASH_TZE_INPUT_HASH_PERSONALIZATION);
        let per_input_digest = match self.signable_input {
            SignableInput::Tze {
                index,
                precondition,
                value,
            } if self.txversion == TxVersion::ZFuture => {
                let tzein = &tze_inputs[index];

                tzein.prevout.write(&mut ch).unwrap();
                CompactSize::write(&mut ch, precondition.extension_id.try_into().unwrap()).unwrap();
                CompactSize::write(&mut ch, precondition.mode.try_into().unwrap()).unwrap();
                Vector::write(&mut ch, &precondition.payload, |w, e| w.write_u8(*e)).unwrap();
                ch.write_all(&value.to_i64_le_bytes()).unwrap();
                ch.finalize()
            }

            _ => ch.finalize(),
        };

        TzeDigests {
            inputs_digest: self.txid_parts.tze_digests.inputs_digest,
            outputs_digest: self.txid_parts.tze_digests.outputs_digest,
            per_input_digest: Some(per_input_digest),
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
