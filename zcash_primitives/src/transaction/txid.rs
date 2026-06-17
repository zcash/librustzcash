use crate::encoding::{StateWrite, WriteBytesExt};
use core::borrow::Borrow;
use core::convert::TryFrom;
use corez::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params};
#[cfg(feature = "sapling")]
use ff::PrimeField;

#[cfg(feature = "orchard")]
use ::orchard::bundle::{self as orchard};
#[cfg(feature = "sapling")]
use ::sapling::bundle::{OutputDescription, SpendDescription};
use ::transparent::bundle::{self as transparent, TxIn, TxOut};
use zcash_protocol::consensus::{BlockHeight, BranchId};
#[cfg(any(feature = "sapling", feature = "orchard"))]
use zcash_protocol::value::ZatBalance;

#[cfg(not(feature = "orchard"))]
use super::components::orchard_raw::RawOrchardBundle;
#[cfg(not(feature = "sapling"))]
use super::components::sapling_raw::{RawSaplingBundle, RawSaplingOutput, RawSaplingSpend};

use super::{
    Authorization, Authorized, OrchardBundle, SaplingBundle, TransactionDigest, TransparentDigests,
    TxDigests, TxId, TxVersion,
};

#[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
use zcash_protocol::value::Zatoshis;

/// TxId tree root personalization
const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

// TxId level 1 node personalization
const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdHeadersHash";
pub(crate) const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTranspaHash";
const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSaplingHash";

// TxId transparent level 2 node personalization
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOutputsHash";

// TxId sapling level 2 node personalization
const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendsHash";
const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendCHash";
const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNHash";

const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

const ZCASH_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";

fn hasher(personal: &[u8; 16]) -> StateWrite {
    StateWrite(Params::new().hash_length(32).personal(personal).to_state())
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
        t_in.prevout().write(&mut h).unwrap();
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
        h.write_u32_le(t_in.sequence()).unwrap();
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

/// Implements [ZIP 244 section T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest)
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk, zkproof)*\] - personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
#[cfg(feature = "sapling")]
pub(crate) fn hash_sapling_spends<A: sapling::bundle::Authorization>(
    shielded_spends: &[SpendDescription<A>],
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    if !shielded_spends.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_spend in shielded_spends {
            // we build the hash of nullifiers separately for compact blocks.
            ch.write_all(s_spend.nullifier().as_ref()).unwrap();

            nh.write_all(&s_spend.cv().to_bytes()).unwrap();
            nh.write_all(&s_spend.anchor().to_repr()).unwrap();
            nh.write_all(&<[u8; 32]>::from(*s_spend.rk())).unwrap();
        }

        let compact_digest = ch.finalize();
        h.write_all(compact_digest.as_bytes()).unwrap();
        let noncompact_digest = nh.finalize();
        h.write_all(noncompact_digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// Equivalent of [`hash_sapling_spends`] operating on the opaque byte representation of a
/// Sapling bundle used when the `sapling` feature is disabled.
#[cfg(not(feature = "sapling"))]
fn hash_sapling_spends_raw(shielded_spends: &[RawSaplingSpend]) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    if !shielded_spends.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_spend in shielded_spends {
            ch.write_all(&s_spend.nullifier).unwrap();

            nh.write_all(&s_spend.cv).unwrap();
            nh.write_all(&s_spend.anchor).unwrap();
            nh.write_all(&s_spend.rk).unwrap();
        }

        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
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
#[cfg(feature = "sapling")]
pub(crate) fn hash_sapling_outputs<A>(shielded_outputs: &[OutputDescription<A>]) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);
    if !shielded_outputs.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_out in shielded_outputs {
            ch.write_all(s_out.cmu().to_bytes().as_ref()).unwrap();
            ch.write_all(s_out.ephemeral_key().as_ref()).unwrap();
            ch.write_all(&s_out.enc_ciphertext()[..52]).unwrap();

            mh.write_all(&s_out.enc_ciphertext()[52..564]).unwrap();

            nh.write_all(&s_out.cv().to_bytes()).unwrap();
            nh.write_all(&s_out.enc_ciphertext()[564..]).unwrap();
            nh.write_all(&s_out.out_ciphertext()[..]).unwrap();
        }

        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(mh.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
    }
    h.finalize()
}

/// Equivalent of [`hash_sapling_outputs`] operating on the opaque byte representation of a
/// Sapling bundle used when the `sapling` feature is disabled.
#[cfg(not(feature = "sapling"))]
fn hash_sapling_outputs_raw(shielded_outputs: &[RawSaplingOutput]) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);
    if !shielded_outputs.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_out in shielded_outputs {
            ch.write_all(&s_out.cmu).unwrap();
            ch.write_all(&s_out.ephemeral_key).unwrap();
            ch.write_all(&s_out.enc_ciphertext[..52]).unwrap();

            mh.write_all(&s_out.enc_ciphertext[52..564]).unwrap();

            nh.write_all(&s_out.cv).unwrap();
            nh.write_all(&s_out.enc_ciphertext[564..]).unwrap();
            nh.write_all(&s_out.out_ciphertext[..]).unwrap();
        }

        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(mh.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
    }
    h.finalize()
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid
fn transparent_digests<A: transparent::Authorization>(
    bundle: &transparent::Bundle<A>,
) -> TransparentDigests<Blake2bHash> {
    TransparentDigests {
        prevouts_digest: transparent_prevout_hash(&bundle.vin),
        sequence_digest: transparent_sequence_hash(&bundle.vin),
        outputs_digest: transparent_outputs_hash(&bundle.vout),
    }
}

/// Implements [ZIP 244 section T.1](https://zips.z.cash/zip-0244#t-1-header-digest)
fn hash_header_txid_data(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))] zip233_amount: &Zatoshis,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);

    h.write_u32_le(version.header()).unwrap();
    h.write_u32_le(version.version_group_id()).unwrap();
    h.write_u32_le(consensus_branch_id.into()).unwrap();
    h.write_u32_le(lock_time).unwrap();
    h.write_u32_le(expiry_height.into()).unwrap();

    // TODO: Factor this out into a separate txid computation when implementing ZIP 246 in full.
    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    if version.has_zip233() {
        h.write_u64_le((*zip233_amount).into()).unwrap();
    }

    h.finalize()
}

/// Implements [ZIP 244 section T.2](https://zips.z.cash/zip-0244#t-2-transparent-digest)
pub(crate) fn hash_transparent_txid_data(
    t_digests: Option<&TransparentDigests<Blake2bHash>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);
    if let Some(d) = t_digests {
        h.write_all(d.prevouts_digest.as_bytes()).unwrap();
        h.write_all(d.sequence_digest.as_bytes()).unwrap();
        h.write_all(d.outputs_digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.3](https://zips.z.cash/zip-0244#t-3-sapling-digest)
#[cfg(feature = "sapling")]
fn hash_sapling_txid_data<A: sapling::bundle::Authorization>(
    bundle: &sapling::Bundle<A, ZatBalance>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
        h.write_all(hash_sapling_spends(bundle.shielded_spends()).as_bytes())
            .unwrap();

        h.write_all(hash_sapling_outputs(bundle.shielded_outputs()).as_bytes())
            .unwrap();

        h.write_all(&bundle.value_balance().to_i64_le_bytes())
            .unwrap();
    }
    h.finalize()
}

/// Equivalent of [`hash_sapling_txid_data`] operating on the opaque byte representation of a
/// Sapling bundle used when the `sapling` feature is disabled.
#[cfg(not(feature = "sapling"))]
fn hash_sapling_txid_data(bundle: &RawSaplingBundle) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
        h.write_all(hash_sapling_spends_raw(bundle.shielded_spends()).as_bytes())
            .unwrap();

        h.write_all(hash_sapling_outputs_raw(bundle.shielded_outputs()).as_bytes())
            .unwrap();

        h.write_all(&bundle.value_balance().to_i64_le_bytes())
            .unwrap();
    }
    h.finalize()
}

fn hash_sapling_txid_empty() -> Blake2bHash {
    hasher(ZCASH_SAPLING_HASH_PERSONALIZATION).finalize()
}

// Personalizations for the Orchard ZIP 244 digests. When the `orchard` feature is enabled
// these computations are performed by the `orchard` crate; when it is disabled they are
// reimplemented here over the opaque byte representation of a parsed Orchard bundle.
#[cfg(not(feature = "orchard"))]
const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
#[cfg(not(feature = "orchard"))]
const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActCHash";
#[cfg(not(feature = "orchard"))]
const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
#[cfg(not(feature = "orchard"))]
const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActNHash";
#[cfg(not(feature = "orchard"))]
const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";

/// Implements [ZIP 244 section T.5](https://zips.z.cash/zip-0244#t-5-orchard-digest).
///
/// When the `orchard` feature is enabled this delegates to the `orchard` crate; otherwise it
/// reimplements the same computation over the opaque byte representation of a parsed bundle.
#[cfg(feature = "orchard")]
fn hash_orchard_txid_data<A: orchard::Authorization>(
    bundle: &orchard::Bundle<A, ZatBalance>,
) -> Blake2bHash {
    bundle.commitment().0
}

#[cfg(not(feature = "orchard"))]
fn hash_orchard_txid_data(bundle: &RawOrchardBundle) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
    let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
    let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
    let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

    for action in bundle.actions() {
        ch.write_all(&action.nullifier).unwrap();
        ch.write_all(&action.cmx).unwrap();
        ch.write_all(&action.epk_bytes).unwrap();
        ch.write_all(&action.enc_ciphertext[..52]).unwrap();

        mh.write_all(&action.enc_ciphertext[52..564]).unwrap();

        nh.write_all(&action.cv_net).unwrap();
        nh.write_all(&action.rk).unwrap();
        nh.write_all(&action.enc_ciphertext[564..]).unwrap();
        nh.write_all(&action.out_ciphertext).unwrap();
    }

    h.write_all(ch.finalize().as_bytes()).unwrap();
    h.write_all(mh.finalize().as_bytes()).unwrap();
    h.write_all(nh.finalize().as_bytes()).unwrap();
    h.write_all(&[bundle.flags()]).unwrap();
    h.write_all(&bundle.value_balance().to_i64_le_bytes())
        .unwrap();
    h.write_all(bundle.anchor()).unwrap();
    h.finalize()
}

#[cfg(feature = "orchard")]
fn hash_orchard_txid_empty() -> Blake2bHash {
    orchard::commitments::hash_bundle_txid_empty()
}

#[cfg(not(feature = "orchard"))]
fn hash_orchard_txid_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION).finalize()
}

/// Implements the Sapling authorizing-data digest (ZIP 244 section S.2-equivalent for the
/// authorizing-data commitment), used by [`BlockTxCommitmentDigester`].
#[cfg(feature = "sapling")]
fn hash_sapling_auth_data(
    sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION);
    if let Some(bundle) = sapling_bundle {
        for spend in bundle.shielded_spends() {
            h.write_all(spend.zkproof()).unwrap();
        }
        for spend in bundle.shielded_spends() {
            h.write_all(&<[u8; 64]>::from(*spend.spend_auth_sig()))
                .unwrap();
        }
        for output in bundle.shielded_outputs() {
            h.write_all(output.zkproof()).unwrap();
        }
        h.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))
            .unwrap();
    }
    h.finalize()
}

#[cfg(not(feature = "sapling"))]
fn hash_sapling_auth_data(sapling_bundle: Option<&RawSaplingBundle>) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION);
    if let Some(bundle) = sapling_bundle {
        for spend in bundle.shielded_spends() {
            h.write_all(&spend.zkproof).unwrap();
        }
        for spend in bundle.shielded_spends() {
            h.write_all(&spend.spend_auth_sig).unwrap();
        }
        for output in bundle.shielded_outputs() {
            h.write_all(&output.zkproof).unwrap();
        }
        h.write_all(bundle.binding_sig()).unwrap();
    }
    h.finalize()
}

/// Implements the Orchard authorizing-data digest, used by [`BlockTxCommitmentDigester`].
#[cfg(feature = "orchard")]
fn hash_orchard_auth_data(
    orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
    orchard_bundle.map_or_else(orchard::commitments::hash_bundle_auth_empty, |b| {
        b.authorizing_commitment().0
    })
}

#[cfg(not(feature = "orchard"))]
fn hash_orchard_auth_data(orchard_bundle: Option<&RawOrchardBundle>) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION);
    if let Some(bundle) = orchard_bundle {
        h.write_all(bundle.proof()).unwrap();
        for action in bundle.actions() {
            h.write_all(&action.spend_auth_sig).unwrap();
        }
        h.write_all(bundle.binding_sig()).unwrap();
    }
    h.finalize()
}

/// A TransactionDigest implementation that commits to all of the effecting
/// data of a transaction to produce a nonmalleable transaction identifier.
///
/// This expects and relies upon the existence of canonical encodings for
/// each effecting component of a transaction.
///
/// This implements the [TxId Digest section of ZIP 244](https://zips.z.cash/zip-0244#txid-digest)
pub struct TxIdDigester;

impl<A: Authorization> TransactionDigest<A> for TxIdDigester {
    type HeaderDigest = Blake2bHash;
    type TransparentDigest = Option<TransparentDigests<Blake2bHash>>;
    type SaplingDigest = Option<Blake2bHash>;
    type OrchardDigest = Option<Blake2bHash>;

    type Digest = TxDigests<Blake2bHash>;

    fn digest_header(
        &self,
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))] zip233_amount: &Zatoshis,
    ) -> Self::HeaderDigest {
        hash_header_txid_data(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount,
        )
    }

    fn digest_transparent(
        &self,
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth>>,
    ) -> Self::TransparentDigest {
        transparent_bundle.map(transparent_digests)
    }

    fn digest_sapling(&self, sapling_bundle: Option<&SaplingBundle<A>>) -> Self::SaplingDigest {
        sapling_bundle.map(hash_sapling_txid_data)
    }

    fn digest_orchard(&self, orchard_bundle: Option<&OrchardBundle<A>>) -> Self::OrchardDigest {
        orchard_bundle.map(hash_orchard_txid_data)
    }

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digests: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
    ) -> Self::Digest {
        TxDigests {
            header_digest,
            transparent_digests,
            sapling_digest,
            orchard_digest,
        }
    }
}

pub(crate) fn to_hash(
    _txversion: TxVersion,
    consensus_branch_id: BranchId,
    header_digest: Blake2bHash,
    transparent_digest: Blake2bHash,
    sapling_digest: Option<Blake2bHash>,
    orchard_digest: Option<Blake2bHash>,
) -> Blake2bHash {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32_le(consensus_branch_id.into())
        .unwrap();

    let mut h = hasher(&personal);
    h.write_all(header_digest.as_bytes()).unwrap();
    h.write_all(transparent_digest.as_bytes()).unwrap();
    h.write_all(
        sapling_digest
            .unwrap_or_else(hash_sapling_txid_empty)
            .as_bytes(),
    )
    .unwrap();
    h.write_all(
        orchard_digest
            .unwrap_or_else(hash_orchard_txid_empty)
            .as_bytes(),
    )
    .unwrap();

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
        hash_transparent_txid_data(digests.transparent_digests.as_ref()),
        digests.sapling_digest,
        digests.orchard_digest,
    );

    TxId::from_bytes(<[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap())
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

    type Digest = Blake2bHash;

    fn digest_header(
        &self,
        _version: TxVersion,
        consensus_branch_id: BranchId,
        _lock_time: u32,
        _expiry_height: BlockHeight,
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))] _zip233_amount: &Zatoshis,
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
                txin.script_sig().write(&mut h).unwrap();
            }
        }
        h.finalize()
    }

    fn digest_sapling(&self, sapling_bundle: Option<&SaplingBundle<Authorized>>) -> Blake2bHash {
        hash_sapling_auth_data(sapling_bundle)
    }

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&OrchardBundle<Authorized>>,
    ) -> Self::OrchardDigest {
        hash_orchard_auth_data(orchard_bundle)
    }

    fn combine(
        &self,
        consensus_branch_id: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
    ) -> Self::Digest {
        let digests = [transparent_digest, sapling_digest, orchard_digest];

        let mut personal = [0; 16];
        personal[..12].copy_from_slice(ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32_le(consensus_branch_id.into())
            .unwrap();

        let mut h = hasher(&personal);
        for digest in &digests {
            h.write_all(digest.as_bytes()).unwrap();
        }

        h.finalize()
    }
}
