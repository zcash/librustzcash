use std::borrow::Borrow;
use std::convert::TryFrom;
use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params, State};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::GroupEncoding;

use crate::consensus::{BlockHeight, BranchId};

use super::{
    components::{
        sapling::{OutputDescription, SpendDescription},
        transparent::{TxIn, TxOut},
    },
    TransactionData, TxId, TxVersion,
};

#[cfg(feature = "zfuture")]
use super::components::tze::{TzeIn, TzeOut};

/// TxId tree root personalization
const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

// TxId level 1 node personalization
const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdHeadersHash";
pub(crate) const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTranspaHash";
const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSaplingHash";
const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
#[cfg(feature = "zfuture")]
const ZCASH_TZE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTZE____Hash";

// TxId transparent level 2 node personalization
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOutputsHash";

// TxId tze level 2 node personalization
#[cfg(feature = "zfuture")]
const ZCASH_TZE_INPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTZEIns_Hash";
#[cfg(feature = "zfuture")]
const ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTZEOutsHash";

// TxId sapling level 2 node personalization
const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendsHash";
const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendCHash";
const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNHash";

const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Sequentially append the serialized value of each transparent input
/// to a hash personalized by ZCASH_PREVOUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn transparent_prevout_hash(vin: &[TxIn]) -> Blake2bHash {
    let mut h = hasher(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
    for t_in in vin {
        t_in.prevout.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Hash of the little-endian u32 interpretation of the
/// `sequence` values for each TxIn record passed in vin.
pub(crate) fn transparent_sequence_hash(vin: &[TxIn]) -> Blake2bHash {
    let mut h = hasher(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
    for t_in in vin {
        (&mut h).write_u32::<LittleEndian>(t_in.sequence).unwrap();
    }
    h.finalize()
}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by ZCASH_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn transparent_outputs_hash<T: Borrow<TxOut>>(vout: &[T]) -> Blake2bHash {
    let mut h = hasher(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
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
pub(crate) fn hash_tze_inputs(tze_inputs: &[TzeIn]) -> Blake2bHash {
    let mut h = hasher(ZCASH_TZE_INPUTS_HASH_PERSONALIZATION);
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
pub(crate) fn hash_tze_outputs(tze_outputs: &[TzeOut]) -> Blake2bHash {
    let mut h = hasher(ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION);
    for tzeout in tze_outputs {
        tzeout.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest)
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk, zkproof)*\] - personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
pub(crate) fn hash_sapling_spends(shielded_spends: &[SpendDescription]) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    if !shielded_spends.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_spend in shielded_spends {
            // we build the hash of nullifiers separately for compact blocks.
            ch.write_all(&s_spend.nullifier.0).unwrap();

            nh.write_all(&s_spend.cv.to_bytes()).unwrap();
            nh.write_all(&s_spend.anchor.to_repr()).unwrap();
            s_spend.rk.write(&mut nh).unwrap();
        }

        let compact_digest = ch.finalize();
        h.write_all(compact_digest.as_bytes()).unwrap();
        let noncompact_digest = nh.finalize();
        h.write_all(noncompact_digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.3b](https://zips.z.cash/zip-0244#t-3b-sapling-outputs-digest)
///
/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext, zkproof)*\] personalized with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
pub(crate) fn hash_sapling_outputs(shielded_outputs: &[OutputDescription]) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);
    if !shielded_outputs.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_out in shielded_outputs {
            ch.write_all(s_out.cmu.to_repr().as_ref()).unwrap();
            ch.write_all(&s_out.ephemeral_key.to_bytes()).unwrap();
            ch.write_all(&s_out.enc_ciphertext[..52]).unwrap();

            mh.write_all(&s_out.enc_ciphertext[52..564]).unwrap();

            nh.write_all(&s_out.cv.to_bytes()).unwrap();
            nh.write_all(&s_out.enc_ciphertext[564..]).unwrap();
            nh.write_all(&s_out.out_ciphertext).unwrap();
        }

        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(mh.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.1](https://zips.z.cash/zip-0244#t-1-header-digest)
fn hash_header_txid_data(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);

    h.write_u32::<LittleEndian>(version.header()).unwrap();
    h.write_u32::<LittleEndian>(version.version_group_id())
        .unwrap();
    h.write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();
    h.write_u32::<LittleEndian>(lock_time).unwrap();
    h.write_u32::<LittleEndian>(expiry_height.into()).unwrap();

    h.finalize()
}

/// Implements [ZIP 244 section T.2](https://zips.z.cash/zip-0244#t-2-transparent-digest)
pub(crate) fn hash_transparent_txid_data(txdata: &TransactionData) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);
    if !txdata.vin.is_empty() || !txdata.vout.is_empty() {
        h.write_all(transparent_prevout_hash(&txdata.vin).as_bytes())
            .unwrap();
        h.write_all(transparent_sequence_hash(&txdata.vin).as_bytes())
            .unwrap();
        h.write_all(transparent_outputs_hash(&txdata.vout).as_bytes())
            .unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.3](https://zips.z.cash/zip-0244#t-3-sapling-digest)
fn hash_sapling_txid_data(txdata: &TransactionData) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if !(txdata.shielded_spends.is_empty() && txdata.shielded_outputs.is_empty()) {
        h.write_all(hash_sapling_spends(&txdata.shielded_spends).as_bytes())
            .unwrap();

        h.write_all(hash_sapling_outputs(&txdata.shielded_outputs).as_bytes())
            .unwrap();

        h.write_all(&txdata.value_balance.to_i64_le_bytes())
            .unwrap();
    }
    h.finalize()
}

#[cfg(feature = "zfuture")]
fn hash_tze_txid_data(txdata: &TransactionData) -> Blake2bHash {
    let mut h = hasher(ZCASH_TZE_HASH_PERSONALIZATION);
    if !(txdata.tze_inputs.is_empty() && txdata.tze_outputs.is_empty()) {
        h.write_all(hash_tze_inputs(&txdata.tze_inputs).as_bytes())
            .unwrap();
        h.write_all(hash_tze_outputs(&txdata.tze_outputs).as_bytes())
            .unwrap();
    }
    h.finalize()
}

pub(crate) fn to_hash(
    consensus_branch_id: BranchId,
    header_digest: Blake2bHash,
    transparent_digest: Blake2bHash,
    sapling_digest: Blake2bHash,
    #[cfg(feature = "zfuture")] tze_digest: Option<Blake2bHash>,
) -> Blake2bHash {
    let mut personal = [0; 16];
    (&mut personal[..12]).copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();

    let mut h = hasher(&personal);
    h.write_all(header_digest.as_bytes()).unwrap();
    h.write_all(transparent_digest.as_bytes()).unwrap();
    h.write_all(sapling_digest.as_bytes()).unwrap();
    h.write_all(
        hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION)
            .finalize()
            .as_bytes(),
    )
    .unwrap();

    #[cfg(feature = "zfuture")]
    if let Some(digest) = tze_digest {
        h.write_all(digest.as_bytes()).unwrap();
    }

    h.finalize()
}

pub fn to_txid(txdata: &TransactionData, consensus_branch_id: BranchId) -> TxId {
    let txid_digest = to_hash(
        consensus_branch_id,
        hash_header_txid_data(
            txdata.version,
            consensus_branch_id,
            txdata.lock_time,
            txdata.expiry_height,
        ),
        hash_transparent_txid_data(&txdata),
        hash_sapling_txid_data(&txdata),
        #[cfg(feature = "zfuture")]
        if txdata.version.has_tze() {
            Some(hash_tze_txid_data(&txdata))
        } else {
            None
        },
    );

    TxId(<[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap())
}
