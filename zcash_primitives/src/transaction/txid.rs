use std::borrow::Borrow;
use std::convert::TryFrom;
use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params, State};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::GroupEncoding;
use orchard::bundle::{self as orchard};

use crate::consensus::{BlockHeight, BranchId};

use super::{
    components::{
        amount::Amount,
        orchard as ser_orch,
        sapling::{self, OutputDescription, SpendDescription},
        transparent::{self, TxIn, TxOut},
    },
    Authorization, Authorized, TransactionDigest, TransparentDigests, TxDigests, TxId, TxVersion,
};

#[cfg(feature = "zfuture")]
use super::{
    components::tze::{self, TzeIn, TzeOut},
    TzeDigests,
};

/// TxId tree root personalization
const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

// TxId level 1 node personalization
const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdHeadersHash";
const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTranspaHash";
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

const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActCHash";
const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActNHash";

const ZCASH_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";
const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";
#[cfg(feature = "zfuture")]
const ZCASH_TZE_WITNESSES_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTZE__Hash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Sequentially append the serialized value of each transparent input
/// to a hash personalized by ZCASH_PREVOUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn transparent_prevout_hash<TransparentAuth: transparent::Authorization>(
    vin: &[TxIn<TransparentAuth>],
) -> Blake2bHash {
    let mut h = hasher(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
    for t_in in vin {
        t_in.prevout.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Hash of the little-endian u32 interpretation of the
/// `sequence` values for each TxIn record passed in vin.
pub(crate) fn transparent_sequence_hash<TransparentAuth: transparent::Authorization>(
    vin: &[TxIn<TransparentAuth>],
) -> Blake2bHash {
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
pub(crate) fn hash_tze_inputs<A>(tze_inputs: &[TzeIn<A>]) -> Blake2bHash {
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

/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * [nullifier*] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * [(cv, anchor, rk, zkproof)*] - personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
pub(crate) fn hash_sapling_spends<A: sapling::Authorization>(
    shielded_spends: &[SpendDescription<A>],
) -> Blake2bHash {
    let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
    let mut nh = hasher(ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION);
    for s_spend in shielded_spends {
        // we build the hash of nullifiers separately for compact blocks.
        ch.write_all(&s_spend.nullifier.as_ref()).unwrap();

        nh.write_all(&s_spend.cv.to_bytes()).unwrap();
        nh.write_all(&s_spend.anchor.to_repr()).unwrap();
        s_spend.rk.write(&mut nh).unwrap();
    }

    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    if !shielded_spends.is_empty() {
        let compact_digest = ch.finalize();
        h.write_all(&compact_digest.as_bytes()).unwrap();
        let noncompact_digest = nh.finalize();
        h.write_all(&noncompact_digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * [(cmu, epk, enc_ciphertext[..52])*] personalized with ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * [enc_ciphertext[52..564]*] (memo ciphertexts) personalized with ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * [(cv, enc_ciphertext[564..], out_ciphertext, zkproof)*] personalized with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
pub(crate) fn hash_sapling_outputs<A>(shielded_outputs: &[OutputDescription<A>]) -> Blake2bHash {
    let mut ch = hasher(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);
    let mut mh = hasher(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);
    let mut nh = hasher(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);
    for s_out in shielded_outputs {
        ch.write_all(&s_out.cmu.to_repr().as_ref()).unwrap();
        ch.write_all(&s_out.ephemeral_key.to_bytes()).unwrap();
        ch.write_all(&s_out.enc_ciphertext[..52]).unwrap();

        mh.write_all(&s_out.enc_ciphertext[52..564]).unwrap();

        nh.write_all(&s_out.cv.to_bytes()).unwrap();
        nh.write_all(&s_out.enc_ciphertext[564..]).unwrap();
        nh.write_all(&s_out.out_ciphertext).unwrap();
    }

    let mut h = hasher(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);
    if !shielded_outputs.is_empty() {
        h.write_all(&ch.finalize().as_bytes()).unwrap();
        h.write_all(&mh.finalize().as_bytes()).unwrap();
        h.write_all(&nh.finalize().as_bytes()).unwrap();
    }
    h.finalize()
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid
fn transparent_digests<A: transparent::Authorization>(
    bundle: &transparent::Bundle<A>,
) -> TransparentDigests<Blake2bHash> {
    TransparentDigests {
        prevout_digest: transparent_prevout_hash(&bundle.vin),
        sequence_digest: transparent_sequence_hash(&bundle.vin),
        outputs_digest: transparent_outputs_hash(&bundle.vout),
        per_input_digest: None,
    }
}

#[cfg(feature = "zfuture")]
fn tze_digests<A: tze::Authorization>(bundle: &tze::Bundle<A>) -> TzeDigests<Blake2bHash> {
    // The txid commits to the hash for all outputs.
    TzeDigests {
        inputs_digest: hash_tze_inputs(&bundle.vin),
        outputs_digest: hash_tze_outputs(&bundle.vout),
        per_input_digest: None,
    }
}

fn hash_header_txid_data(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);

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

fn hash_transparent_txid_data(t_digests: Option<&TransparentDigests<Blake2bHash>>) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);
    if let Some(d) = t_digests {
        h.write_all(d.prevout_digest.as_bytes()).unwrap();
        h.write_all(d.sequence_digest.as_bytes()).unwrap();
        h.write_all(d.outputs_digest.as_bytes()).unwrap();
        if let Some(s) = d.per_input_digest {
            h.write_all(s.as_bytes()).unwrap();
        };
    }
    h.finalize()
}

fn hash_sapling_txid_data<A: sapling::Authorization>(
    sapling_bundle: Option<&sapling::Bundle<A>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if let Some(bundle) = sapling_bundle {
        if !(bundle.shielded_spends.is_empty() && bundle.shielded_outputs.is_empty()) {
            h.write_all(hash_sapling_spends(&bundle.shielded_spends).as_bytes())
                .unwrap();

            h.write_all(hash_sapling_outputs(&bundle.shielded_outputs).as_bytes())
                .unwrap();

            h.write_all(&bundle.value_balance.to_i64_le_bytes())
                .unwrap();
        }
    }
    h.finalize()
}

/// Write disjoint parts of each Orchard shielded action as 3 separate hashes:
/// * [(nullifier, cmx, ephemeral_key, enc_ciphertext[..52])*] personalized
///   with ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION
/// * [enc_ciphertext[52..564]*] (memo ciphertexts) personalized
///   with ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION
/// * [(cv, rk, enc_ciphertext[564..], out_ciphertext)*] personalized
///   with ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together along with (flags, value_balance_orchard, anchor_orchard),
/// personalized with ZCASH_ORCHARD_ACTIONS_HASH_PERSONALIZATION
fn hash_orchard_txid_data<A: orchard::Authorization>(
    orchard_bundle: Option<&orchard::Bundle<A, Amount>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
    if let Some(bundle) = orchard_bundle {
        let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

        for action in bundle.actions().iter() {
            ch.write_all(&action.nullifier().to_bytes()).unwrap();
            ch.write_all(&action.cmx().to_bytes()).unwrap();
            ch.write_all(&action.encrypted_note().epk_bytes).unwrap();
            ch.write_all(&action.encrypted_note().enc_ciphertext[..52])
                .unwrap();

            mh.write_all(&action.encrypted_note().enc_ciphertext[52..564])
                .unwrap();

            nh.write_all(&action.cv_net().to_bytes()).unwrap();
            nh.write_all(&<[u8; 32]>::from(action.rk())).unwrap();
            nh.write_all(&action.encrypted_note().enc_ciphertext[564..])
                .unwrap();
            nh.write_all(&action.encrypted_note().out_ciphertext)
                .unwrap();
        }

        h.write_all(&ch.finalize().as_bytes()).unwrap();
        h.write_all(&mh.finalize().as_bytes()).unwrap();
        h.write_all(&nh.finalize().as_bytes()).unwrap();
        ser_orch::write_flags(&mut h, bundle.flags()).unwrap();
        h.write_all(&bundle.value_balance().to_i64_le_bytes())
            .unwrap();
        ser_orch::write_anchor(&mut h, bundle.anchor()).unwrap();
    }
    h.finalize()
}

#[cfg(feature = "zfuture")]
fn hash_tze_txid_data(tze_digests: Option<&TzeDigests<Blake2bHash>>) -> Blake2bHash {
    let mut h = hasher(ZCASH_TZE_HASH_PERSONALIZATION);
    if let Some(d) = tze_digests {
        h.write_all(d.inputs_digest.as_bytes()).unwrap();
        h.write_all(d.outputs_digest.as_bytes()).unwrap();
        if let Some(s) = d.per_input_digest {
            h.write_all(s.as_bytes()).unwrap();
        }
    }
    h.finalize()
}

pub struct TxIdDigester;

// A TransactionDigest implementation that commits to all of the effecting
// data of a transaction to produce a nonmalleable transaction identifier.
//
// This expects and relies upon the existence of canonical encodings for
// each effecting component of a transaction.
impl<A: Authorization> TransactionDigest<A> for TxIdDigester {
    type HeaderDigest = Blake2bHash;
    type TransparentDigest = Option<TransparentDigests<Blake2bHash>>;
    type SaplingDigest = Blake2bHash;
    type OrchardDigest = Blake2bHash;

    #[cfg(feature = "zfuture")]
    type TzeDigest = Option<TzeDigests<Blake2bHash>>;

    type Digest = TxDigests<Blake2bHash>;

    fn digest_header(
        &self,
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> Self::HeaderDigest {
        hash_header_txid_data(version, consensus_branch_id, lock_time, expiry_height)
    }

    fn digest_transparent(
        &self,
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth>>,
    ) -> Self::TransparentDigest {
        transparent_bundle.map(transparent_digests)
    }

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth>>,
    ) -> Self::SaplingDigest {
        hash_sapling_txid_data(sapling_bundle)
    }

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&orchard::Bundle<A::OrchardAuth, Amount>>,
    ) -> Self::OrchardDigest {
        hash_orchard_txid_data(orchard_bundle)
    }

    #[cfg(feature = "zfuture")]
    fn digest_tze(&self, tze_bundle: Option<&tze::Bundle<A::TzeAuth>>) -> Self::TzeDigest {
        tze_bundle.map(tze_digests)
    }

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digests: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        #[cfg(feature = "zfuture")] tze_digests: Self::TzeDigest,
    ) -> Self::Digest {
        TxDigests {
            header_digest,
            transparent_digests,
            sapling_digest,
            orchard_digest,
            #[cfg(feature = "zfuture")]
            tze_digests,
        }
    }
}

pub fn to_hash(
    _txversion: TxVersion,
    consensus_branch_id: BranchId,
    header_digest: Blake2bHash,
    transparent_digests: Option<&TransparentDigests<Blake2bHash>>,
    sapling_digest: Blake2bHash,
    orchard_digest: Blake2bHash,
    #[cfg(feature = "zfuture")] tze_digests: Option<&TzeDigests<Blake2bHash>>,
) -> Blake2bHash {
    let mut personal = [0; 16];
    (&mut personal[..12]).copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();

    let mut h = hasher(&personal);
    h.write_all(header_digest.as_bytes()).unwrap();
    h.write_all(hash_transparent_txid_data(transparent_digests).as_bytes())
        .unwrap();
    h.write_all(sapling_digest.as_bytes()).unwrap();
    h.write_all(orchard_digest.as_bytes()).unwrap();

    #[cfg(feature = "zfuture")]
    if _txversion.has_tze() {
        h.write_all(hash_tze_txid_data(tze_digests).as_bytes())
            .unwrap();
    }

    h.finalize()
}

pub fn to_txid(
    txversion: TxVersion,
    consensus_branch_id: BranchId,
    digests: &TxDigests<Blake2bHash>,
) -> TxId {
    let txid_digest = to_hash(
        txversion,
        consensus_branch_id,
        digests.header_digest,
        digests.transparent_digests.as_ref(),
        digests.sapling_digest,
        digests.orchard_digest,
        #[cfg(feature = "zfuture")]
        digests.tze_digests.as_ref(),
    );

    TxId(<[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap())
}

/// Digester which constructs a digest of only the witness data.
/// This does not internally commit to the txid, so if that is
/// desired it should be done using the result of this digest
/// function.
pub struct BlockTxCommitmentDigester;

impl TransactionDigest<Authorized> for BlockTxCommitmentDigester {
    /// We use the header digest to pass the transaction ID into
    /// where it needs to be used for personalization string construction.
    type HeaderDigest = BranchId;
    type TransparentDigest = Blake2bHash;
    type SaplingDigest = Blake2bHash;
    type OrchardDigest = Blake2bHash;

    #[cfg(feature = "zfuture")]
    type TzeDigest = Blake2bHash;

    type Digest = Blake2bHash;

    fn digest_header(
        &self,
        _version: TxVersion,
        consensus_branch_id: BranchId,
        _lock_time: u32,
        _expiry_height: BlockHeight,
    ) -> Self::HeaderDigest {
        consensus_branch_id
    }

    fn digest_transparent(
        &self,
        transparent_bundle: Option<&transparent::Bundle<transparent::Authorized>>,
    ) -> Blake2bHash {
        let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
        if let Some(bundle) = transparent_bundle {
            for txin in &bundle.vin {
                h.write_all(&txin.script_sig.0).unwrap();
            }
        }
        h.finalize()
    }

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&sapling::Bundle<sapling::Authorized>>,
    ) -> Blake2bHash {
        let mut h = hasher(ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION);
        if let Some(bundle) = sapling_bundle {
            for spend in &bundle.shielded_spends {
                h.write_all(&spend.zkproof).unwrap();
                spend.spend_auth_sig.write(&mut h).unwrap();
            }

            for output in &bundle.shielded_outputs {
                h.write_all(&output.zkproof).unwrap();
            }

            bundle.authorization.binding_sig.write(&mut h).unwrap();
        }
        h.finalize()
    }

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, Amount>>,
    ) -> Self::OrchardDigest {
        let mut h = hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION);
        if let Some(bundle) = orchard_bundle {
            h.write_all(bundle.authorization().proof().as_ref())
                .unwrap();
            for action in bundle.actions().iter() {
                h.write_all(&<[u8; 64]>::from(action.authorization()))
                    .unwrap();
            }
            h.write_all(&<[u8; 64]>::from(
                bundle.authorization().binding_signature(),
            ))
            .unwrap();
        }
        h.finalize()
    }

    #[cfg(feature = "zfuture")]
    fn digest_tze(&self, tze_bundle: Option<&tze::Bundle<tze::Authorized>>) -> Blake2bHash {
        let mut h = hasher(ZCASH_TZE_WITNESSES_HASH_PERSONALIZATION);
        if let Some(bundle) = tze_bundle {
            for tzein in &bundle.vin {
                h.write_all(&tzein.witness.payload.0).unwrap();
            }
        }
        h.finalize()
    }

    fn combine(
        &self,
        consensus_branch_id: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        #[cfg(feature = "zfuture")] tze_digest: Self::TzeDigest,
    ) -> Self::Digest {
        let digests = [
            transparent_digest,
            sapling_digest,
            orchard_digest,
            #[cfg(feature = "zfuture")]
            tze_digest,
        ];

        let mut personal = [0; 16];
        (&mut personal[..12]).copy_from_slice(ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32::<LittleEndian>(consensus_branch_id.into())
            .unwrap();

        let mut h = hasher(&personal);
        for digest in &digests {
            h.write_all(digest.as_bytes()).unwrap();
        }

        h.finalize()
    }
}
