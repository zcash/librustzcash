use std::borrow::Borrow;
use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::GroupEncoding;

use crate::{
    consensus::{BlockHeight, BranchId},
    legacy::Script,
    redjubjub::Signature,
};

use super::{
    blake2b_256::HashWriter,
    components::{Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut},
    TransactionDigest, TransparentDigests, TxDigests, TxId, TxVersion, WitnessDigest,
};

#[cfg(feature = "zfuture")]
use crate::extensions::transparent::{self as tze};

#[cfg(feature = "zfuture")]
use super::{
    components::{TzeIn, TzeOut},
    TzeDigests,
};

pub const ZCASH_TXID_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxIdHsh";
const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcTxHeaders_Hash";
const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZcTxTransparHash";
const ZCASH_TZE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcTxTZE_____Hash";
const ZCASH_SPROUT_HASH_PERSONALIZATION: &[u8; 16] = b"ZcTxSprout__Hash";
const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZcTxSapling_Hash";

const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";
const ZCASH_TZE_INPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash_TzeInsHash";
const ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashTzeOutsHash";

fn hash_header_txid_data(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_HEADERS_HASH_PERSONALIZATION);

    (&mut h)
        .write_u32::<LittleEndian>(version.header())
        .unwrap();
    (&mut h)
        .write_u32::<LittleEndian>(version.version_group_id())
        .unwrap();
    (&mut h)
        .write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();
    (&mut h).write_u32::<LittleEndian>(lock_time).unwrap();
    (&mut h)
        .write_u32::<LittleEndian>(expiry_height.into())
        .unwrap();

    h.finalize()
}

/// Sequentially append the serialized value of each transparent input
/// to a hash personalized by ZCASH_PREVOUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn prevout_hash(vin: &[TxIn]) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
    for t_in in vin {
        t_in.prevout.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Hash of the little-endian u32 interpretation of the
/// `sequence` values for each TxIn record passed in vin.
pub(crate) fn sequence_hash(vin: &[TxIn]) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
    for t_in in vin {
        (&mut h).write_u32::<LittleEndian>(t_in.sequence).unwrap();
    }
    h.finalize()
}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by ZCASH_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn outputs_hash<T: Borrow<TxOut>>(vout: &[T]) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    for t_out in vout {
        t_out.borrow().write(&mut h).unwrap();
    }
    h.finalize()
}

/// Sequentially append the serialized value of each TZE input, excluding
/// witness data, to a hash personalized by ZCASH_TZE_INPUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
#[cfg(feature = "zfuture")]
pub(crate) fn tze_inputs_hash(tze_inputs: &[TzeIn]) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_TZE_INPUTS_HASH_PERSONALIZATION);
    for tzein in tze_inputs {
        tzein.write_without_witness(&mut h).unwrap();
    }
    h.finalize()
}

/// Sequentially append the full serialized value of each TZE output
/// to a hash personalized by ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
#[cfg(feature = "zfuture")]
pub(crate) fn tze_outputs_hash(tze_outputs: &[TzeOut]) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION);
    for tzeout in tze_outputs {
        tzeout.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Sequentially append the full serialized value of each JSDescription
/// followed by the `joinsplit_pubkey` value to a hash personalized
/// by ZCASH_JOINSPLITS_HASH_PERSONALIZATION,
pub(crate) fn joinsplits_hash(
    joinsplits: &[JSDescription],
    joinsplit_pubkey: &[u8; 32],
) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_JOINSPLITS_HASH_PERSONALIZATION);
    for js in joinsplits {
        js.write(&mut h).unwrap();
    }
    h.write(joinsplit_pubkey).unwrap();
    h.finalize()
}

/// Write each spend's (cv, anchor, nullifier, rk, zkproof) to the hash.
pub(crate) fn shielded_spends_hash(shielded_spends: &[SpendDescription]) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION);
    for s_spend in shielded_spends {
        h.write(&s_spend.cv.to_bytes()).unwrap();
        h.write(&s_spend.anchor.to_repr()).unwrap();
        h.write(&s_spend.nullifier.as_ref()).unwrap();
        s_spend.rk.write(&mut h).unwrap();
        h.write(&s_spend.zkproof).unwrap();
    }
    h.finalize()
}

/// Sequentially append the full serialized value of each OutputDescription
/// to a hash personalized by ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION
pub(crate) fn shielded_outputs_hash(shielded_outputs: &[OutputDescription]) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION);
    for s_out in shielded_outputs {
        s_out.write(&mut h).unwrap();
    }
    h.finalize()
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid
fn hashes_transparent_txid_data(vin: &[TxIn], vout: &[TxOut]) -> TransparentDigests<Blake2bHash> {
    TransparentDigests {
        prevout_digest: prevout_hash(vin),
        sequence_digest: sequence_hash(vin),
        outputs_digest: outputs_hash(vout),
        per_input_digest: None,
    }
}

#[cfg(feature = "zfuture")]
fn hashes_tze_txid_data(tze_inputs: &[TzeIn], tze_outputs: &[TzeOut]) -> TzeDigests<Blake2bHash> {
    // The txid commits to the hash for all outputs.
    TzeDigests {
        inputs_digest: tze_inputs_hash(tze_inputs),
        outputs_digest: tze_outputs_hash(tze_outputs),
        per_input_digest: None,
    }
}

fn hash_sprout_txid_data(
    joinsplits: &[JSDescription],
    joinsplit_pubkey: &Option<[u8; 32]>,
) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_SPROUT_HASH_PERSONALIZATION);
    if !joinsplits.is_empty() {
        h.write(joinsplits_hash(joinsplits, &joinsplit_pubkey.unwrap()).as_bytes())
            .unwrap();
    }

    h.finalize()
}

fn hash_sapling_txid_data(
    shielded_spends: &[SpendDescription],
    shielded_outputs: &[OutputDescription],
    value_balance: Amount,
) -> Blake2bHash {
    let mut h = HashWriter::new(ZCASH_SAPLING_HASH_PERSONALIZATION);

    if !shielded_spends.is_empty() {
        h.write(shielded_spends_hash(shielded_spends).as_bytes())
            .unwrap();
    }

    if !shielded_outputs.is_empty() {
        h.write(shielded_outputs_hash(shielded_outputs).as_bytes())
            .unwrap();
    }

    h.write(&value_balance.to_i64_le_bytes()).unwrap();

    h.finalize()
}

fn combine_transparent_digests(
    personalization: &[u8; 16],
    d: &TransparentDigests<Blake2bHash>,
) -> Blake2bHash {
    let mut h = HashWriter::new(personalization);

    h.write(d.prevout_digest.as_bytes()).unwrap();
    h.write(d.sequence_digest.as_bytes()).unwrap();
    h.write(d.outputs_digest.as_bytes()).unwrap();
    match d.per_input_digest {
        Option::Some(s) => {
            h.write(s.as_bytes()).unwrap();
        }
        Option::None => (),
    };

    h.finalize()
}

#[cfg(feature = "zfuture")]
fn combine_tze_digests(personalization: &[u8; 16], d: &TzeDigests<Blake2bHash>) -> Blake2bHash {
    let mut h = HashWriter::new(personalization);

    h.write(d.inputs_digest.as_bytes()).unwrap();
    h.write(d.outputs_digest.as_bytes()).unwrap();
    match d.per_input_digest {
        Option::Some(s) => {
            h.write(s.as_bytes()).unwrap();
        }
        Option::None => (),
    };

    h.finalize()
}

pub struct TxIdDigester {
    pub consensus_branch_id: BranchId
}

// A TransactionDigest implementation that commits to all of the effecting
// data of a transaction to produce a nonmalleable transaction identifier.
//
// This expects and relies upon the existence of canonical encodings for
// each effecting component of a transaction.
impl TransactionDigest<Blake2bHash> for TxIdDigester {
    type Purpose = TxId;

    fn digest_header(
        &self,
        version: TxVersion,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> Blake2bHash {
        hash_header_txid_data(version, self.consensus_branch_id, lock_time, expiry_height)
    }

    fn digest_transparent(&self, vin: &[TxIn], vout: &[TxOut]) -> TransparentDigests<Blake2bHash> {
        hashes_transparent_txid_data(vin, vout)
    }

    #[cfg(feature = "zfuture")]
    fn digest_tze(&self, tze_inputs: &[TzeIn], tze_outputs: &[TzeOut]) -> TzeDigests<Blake2bHash> {
        hashes_tze_txid_data(tze_inputs, tze_outputs)
    }

    fn digest_sprout(
        &self,
        joinsplits: &[JSDescription],
        joinsplit_pubkey: &Option<[u8; 32]>,
    ) -> Blake2bHash {
        hash_sprout_txid_data(joinsplits, joinsplit_pubkey)
    }

    fn digest_sapling(
        &self,
        shielded_spends: &[SpendDescription],
        shielded_outputs: &[OutputDescription],
        value_balance: Amount,
    ) -> Blake2bHash {
        hash_sapling_txid_data(
            shielded_spends,
            shielded_outputs,
            value_balance,
        )
    }
}

pub fn to_hash<A>(
    digests: &TxDigests<Blake2bHash, A>,
    hash_personalization_prefix: &[u8; 12],
    txversion: TxVersion,
    consensus_branch_id: BranchId,
) -> Blake2bHash {
    let mut personal = [0; 16];
    (&mut personal[..12]).copy_from_slice(hash_personalization_prefix);
    (&mut personal[12..])
        .write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();

    let mut h = HashWriter::new(&personal);
    h.write(&digests.header_digest.as_bytes()).unwrap();

    h.write(
        &combine_transparent_digests(
            &ZCASH_TRANSPARENT_HASH_PERSONALIZATION,
            &digests.transparent_digests
        ).as_bytes()
    ).unwrap();

    #[cfg(feature = "zfuture")]
    if txversion.has_tze() {
        h.write(
            &combine_tze_digests(&ZCASH_TZE_HASH_PERSONALIZATION, &digests.tze_digests).as_bytes()
        ).unwrap();
    }

    h.write(digests.sprout_digest.as_bytes()).unwrap();
    h.write(digests.sapling_digest.as_bytes()).unwrap();

    h.finalize()
}

pub fn to_txid(
    digests: &TxDigests<Blake2bHash, TxId>,
    txversion: TxVersion,
    consensus_branch_id: BranchId,
) -> TxId {
    let txid_digest = to_hash(
        digests,
        &ZCASH_TXID_PERSONALIZATION_PREFIX,
        txversion,
        consensus_branch_id,
    );

    let mut txid_bytes = [0; 32];
    (&mut txid_bytes).copy_from_slice(txid_digest.as_bytes());
    TxId(txid_bytes)
}

/// Digester which constructs a digest of only the witness data.
/// This does not internally commit to the txid, so if that is 
/// desired it should be done using the result of this digest
/// function.
struct BlockTxCommitmentDigester {}

impl WitnessDigest<Blake2bHash> for BlockTxCommitmentDigester {
    fn digest_transparent<'a, I: IntoIterator<Item = &'a Script>>(
        &self,
        vin_sig: I,
    ) -> Blake2bHash {
        // TODO: different personalization?
        let mut h = HashWriter::new(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);

        for script in vin_sig {
            h.write(&script.0).unwrap();
        }

        h.finalize()
    }

    #[cfg(feature = "zfuture")]
    fn digest_tze<'a, I: IntoIterator<Item = &'a tze::Witness>>(
        &self,
        tzein_sig: I,
    ) -> Blake2bHash {
        // TODO: different personalization?
        let mut h = HashWriter::new(ZCASH_TZE_HASH_PERSONALIZATION);

        for witness in tzein_sig {
            h.write(&witness.payload).unwrap();
        }

        h.finalize()
    }

    fn digest_sprout(&self, joinsplit_sig: &[u8; 64]) -> Blake2bHash {
        // TODO: different personalization?
        let mut h = HashWriter::new(ZCASH_SPROUT_HASH_PERSONALIZATION);
        h.write(joinsplit_sig).unwrap();
        h.finalize()
    }

    fn digest_sapling<'a, I: IntoIterator<Item = &'a Signature>>(
        &self,
        shielded_spends: I,
        binding_sig: &Signature,
    ) -> Blake2bHash {
        // TODO: different personalization?
        let mut h = HashWriter::new(ZCASH_SAPLING_HASH_PERSONALIZATION);

        for spend_auth_sig in shielded_spends {
            spend_auth_sig.write(&mut h).unwrap();
        }

        binding_sig.write(&mut h).unwrap();

        h.finalize()
    }
}
