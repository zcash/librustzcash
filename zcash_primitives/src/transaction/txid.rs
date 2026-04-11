use crate::encoding::{StateWrite, WriteBytesExt};
use core::borrow::Borrow;
use core::convert::TryFrom;
use core2::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params};
use ff::PrimeField;

use ::orchard::bundle::{self as orchard};
use ::sapling::bundle::{OutputDescription, SpendDescription};
use ::transparent::bundle::{self as transparent, TxIn, TxOut};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::ZatBalance,
};

use super::{
    Authorization, Authorized, TransactionDigest, TransparentDigests, TxDigests, TxId, TxVersion,
};

#[cfg(all(zcash_v6, feature = "zip-233"))]
use zcash_protocol::value::Zatoshis;

#[cfg(zcash_unstable = "zfuture")]
use super::{
    TzeDigests,
    components::tze::{self, TzeIn, TzeOut},
};

/// TxId tree root personalization
pub(crate) const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

// TxId level 1 node personalization
const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdHeadersHash";
pub(crate) const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTranspaHash";
const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSaplingHash";
#[cfg(zcash_unstable = "zfuture")]
const ZCASH_TZE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTZE____Hash";

// TxId transparent level 2 node personalization
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOutputsHash";

// TxId tze level 2 node personalization
#[cfg(zcash_unstable = "zfuture")]
const ZCASH_TZE_INPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTZEIns_Hash";
#[cfg(zcash_unstable = "zfuture")]
const ZCASH_TZE_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTZEOutsHash";

// TxId sapling level 2 node personalization
const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendsHash";
const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendCHash";
const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNHash";

const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

pub(crate) const ZCASH_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";
#[cfg(zcash_v6)]
const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";
#[cfg(zcash_unstable = "zfuture")]
const ZCASH_TZE_WITNESSES_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTZE__Hash";

// ZIP 248 v6-specific personalization strings
#[cfg(zcash_v6)]
pub(crate) const ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdVPDeltaHash";
#[cfg(zcash_v6)]
pub(crate) const ZCASH_V6_EFFECTS_BUNDLES_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdEffBnd_Hash";
#[cfg(zcash_v6)]
pub(crate) const ZCASH_V6_AUTH_BUNDLES_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthBnd__Hash";

pub(crate) fn hasher(personal: &[u8; 16]) -> StateWrite {
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

/// Sequentially append the serialized value of each TZE input, excluding
/// witness data, to a hash personalized by ZCASH_TZE_INPUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
#[cfg(zcash_unstable = "zfuture")]
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
#[cfg(zcash_unstable = "zfuture")]
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
/// * \[(cv, anchor, rk)*\] - personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
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

/// Implements [ZIP 244 section T.3b](https://zips.z.cash/zip-0244#t-3b-sapling-outputs-digest)
///
/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext, zkproof)*\] personalized with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
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

#[cfg(zcash_unstable = "zfuture")]
fn tze_digests<A: tze::Authorization>(bundle: &tze::Bundle<A>) -> TzeDigests<Blake2bHash> {
    // The txid commits to the hash for all outputs.
    TzeDigests {
        inputs_digest: hash_tze_inputs(&bundle.vin),
        outputs_digest: hash_tze_outputs(&bundle.vout),
        per_input_digest: None,
    }
}

/// Implements [ZIP 244 section T.1](https://zips.z.cash/zip-0244#t-1-header-digest)
fn hash_header_txid_data(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    #[cfg(all(zcash_v6, feature = "zip-233"))] zip233_amount: &Zatoshis,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);

    h.write_u32_le(version.header()).unwrap();
    h.write_u32_le(version.version_group_id()).unwrap();
    h.write_u32_le(consensus_branch_id.into()).unwrap();
    h.write_u32_le(lock_time).unwrap();
    h.write_u32_le(expiry_height.into()).unwrap();

    // TODO: Factor this out into a separate txid computation when implementing ZIP 246 in full.
    #[cfg(all(zcash_v6, feature = "zip-233"))]
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

fn hash_sapling_txid_empty() -> Blake2bHash {
    hasher(ZCASH_SAPLING_HASH_PERSONALIZATION).finalize()
}

#[cfg(zcash_unstable = "zfuture")]
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

// ---------------------------------------------------------------------------
// ZIP 248 v6-specific digest functions
// ---------------------------------------------------------------------------

/// Implements [ZIP 248 §T.1](https://zips.z.cash/zip-0248#t-1-header-digest).
///
/// v6 header digest. Unlike the v5 header digest
/// ([ZIP 244 §T.1](https://zips.z.cash/zip-0244#t-1-header-digest)), this
/// does NOT include `zip233_amount` or the transaction fee -- those concerns
/// are handled entirely by the value-pool-deltas digest
/// ([ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest)).
/// This separation keeps the header focused on consensus-level metadata and
/// avoids coupling it to value-flow semantics.
///
/// Fields committed: `header || nVersionGroupId || nConsensusBranchId ||
/// lock_time || nExpiryHeight`.
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_header(
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);
    h.write_u32_le(version.header()).unwrap();
    h.write_u32_le(version.version_group_id()).unwrap();
    // The consensus branch ID is committed here so that the txid is
    // chain-specific, preventing replay across forks.
    h.write_u32_le(consensus_branch_id.into()).unwrap();
    h.write_u32_le(lock_time).unwrap();
    h.write_u32_le(expiry_height.into()).unwrap();
    h.finalize()
}

/// Implements [ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest).
///
/// Hashes every value-pool delta entry -- both known pool types (transparent,
/// sapling, orchard) and any unknown/future pool types the transaction may
/// carry -- into a single digest.
///
/// `to_wire_entries()` is the key piece: it merge-sorts known and unknown
/// entries by their `(bundleType, assetClass, assetUuid)` composite wire key
/// so that every implementation produces an identical canonical byte sequence
/// regardless of insertion order. This canonicalization is critical because
/// the digest must be deterministic for txid stability -- two implementations
/// that parse the same wire bytes must always compute the same digest.
///
/// Each entry is serialized as `bundleType || bundleVariant || assetClass ||
/// assetUuid || value` using the wire encoding (compactSize for type/variant,
/// 0 or 64 bytes for assetUuid depending on assetClass).
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_value_pool_deltas(vp: &super::zip248::ValuePoolDeltas) -> Blake2bHash {
    let mut h = hasher(ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION);
    for entry in vp.to_wire_entries() {
        entry.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 248 §T.3.2](https://zips.z.cash/zip-0248#t-3-2-sapling-effects-digest).
///
/// Produces `spends_digest || outputs_digest || anchorSapling`.
///
/// # Correctness
///
/// `valueBalanceSapling` is deliberately NOT included here, even though the
/// analogous [ZIP 244 §T.3](https://zips.z.cash/zip-0244#t-3-sapling-digest)
/// `hash_sapling_txid_data` does include it. In v6, all value-balance
/// fields live in the value-pool-deltas digest
/// ([ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest))
/// so they are committed exactly once rather than being split across per-
/// bundle digests. Including `valueBalanceSapling` here would double-commit
/// and create a consensus mismatch with the spec.
///
/// When `nSpendsSapling = 0` the on-wire format omits `anchorSapling`
/// entirely, but per ZIP 248 §T.3.2c the digest must still have 32 bytes
/// at the anchor position. We hash 32 zero bytes in that case so that the
/// digest preimage length is constant regardless of whether spends are
/// present, which simplifies verification and prevents ambiguity about
/// where the anchor field starts.
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_sapling_effects<A: sapling::bundle::Authorization>(
    bundle: &sapling::Bundle<A, ZatBalance>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
        // [ZIP 248 §T.3.2a]: spends_digest commits to nullifiers and (cv, anchor, rk)
        // per spend, split into compact and non-compact sub-hashes.
        h.write_all(hash_sapling_spends(bundle.shielded_spends()).as_bytes())
            .unwrap();
        // [ZIP 248 §T.3.2b]: outputs_digest commits to (cmu, epk, enc, cv, out)
        // per output, split into compact, memo, and non-compact sub-hashes.
        h.write_all(hash_sapling_outputs(bundle.shielded_outputs()).as_bytes())
            .unwrap();
        // # Correctness: when there are no spends the anchor is not on the wire,
        // but the digest still needs 32 bytes here (ZIP 248 §T.3.2c). Using
        // 32 zero bytes is the spec-defined sentinel, not a bug.
        if let Some(spend) = bundle.shielded_spends().first() {
            // All spends in a bundle share the same anchor, so reading from the
            // first spend is sufficient.
            h.write_all(spend.anchor().to_repr().as_ref()).unwrap();
        } else {
            h.write_all(&[0u8; 32]).unwrap();
        }
    }
    h.finalize()
}

/// Implements [ZIP 248 §T.3.3](https://zips.z.cash/zip-0248#t-3-3-orchard-effects-digest).
///
/// Produces `actions_compact || actions_memos || actions_noncompact || flags
/// || anchor`, mirroring the structure of
/// [ZIP 244's orchard digest](https://zips.z.cash/zip-0244#t-4-orchard-digest)
/// but without `valueBalanceOrchard`.
///
/// # Correctness
///
/// `valueBalanceOrchard` is deliberately NOT included -- the same rationale
/// as for sapling (see [`hash_v6_sapling_effects`]). All value balances are
/// committed once in the value-pool-deltas digest
/// ([ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest)).
///
/// We cannot reuse the orchard crate's `commitment()` / `hash_bundle_txid_data`
/// because those implement the ZIP 244 form which includes `valueBalanceOrchard`.
/// Instead we re-derive the per-action sub-hashes inline using the same
/// BLAKE2b personalizations so the sub-digests are byte-identical to
/// ZIP 244 -- only the final composition differs (no value balance appended).
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_orchard_effects(
    bundle: &orchard::Bundle<impl orchard::Authorization, ZatBalance>,
) -> Blake2bHash {
    // Reuse the same top-level personalization as the orchard crate's
    // `hash_bundle_txid_data` so that the empty-bundle sentinel is identical.
    const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
    let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);

    // Per ZIP 248 §T.3.3: the three sub-hashes partition each action's fields
    // into compact (lightweight-client-relevant), memo, and non-compact groups,
    // exactly as ZIP 244 does. The orchard crate's `hash_bundle_txid_data` is
    // the ZIP 244 form and includes valueBalanceOrchard, so we cannot delegate
    // to it and must re-implement the sub-hashes here.
    const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActCHash";
    const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
    const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActNHash";

    if !bundle.actions().is_empty() {
        let mut compact_h = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        let mut memos_h = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        let mut noncompact_h = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

        for action in bundle.actions().iter() {
            // Compact fields: these are the minimum needed by light clients
            // to trial-decrypt and identify relevant transactions.
            compact_h.write_all(&action.nullifier().to_bytes()).unwrap();
            compact_h.write_all(&action.cmx().to_bytes()).unwrap();
            compact_h
                .write_all(&action.encrypted_note().epk_bytes)
                .unwrap();
            compact_h
                .write_all(&action.encrypted_note().enc_ciphertext[..52])
                .unwrap();

            // Memo field: the encrypted memo portion of enc_ciphertext,
            // separated so that memo-trimming nodes can omit it.
            memos_h
                .write_all(&action.encrypted_note().enc_ciphertext[52..564])
                .unwrap();

            // Non-compact fields: value commitment, re-randomized key, the
            // remainder of enc_ciphertext, and the out_ciphertext. These are
            // only needed for full verification.
            noncompact_h.write_all(&action.cv_net().to_bytes()).unwrap();
            noncompact_h
                .write_all(&<[u8; 32]>::from(action.rk()))
                .unwrap();
            noncompact_h
                .write_all(&action.encrypted_note().enc_ciphertext[564..])
                .unwrap();
            noncompact_h
                .write_all(&action.encrypted_note().out_ciphertext)
                .unwrap();
        }

        h.write_all(compact_h.finalize().as_bytes()).unwrap();
        h.write_all(memos_h.finalize().as_bytes()).unwrap();
        h.write_all(noncompact_h.finalize().as_bytes()).unwrap();
        // Flags and anchor follow the three sub-digests.
        h.write_all(&[bundle.flags().to_byte()]).unwrap();
        h.write_all(&bundle.anchor().to_bytes()).unwrap();
    }
    h.finalize()
}

/// The wire encoding of a sighash version 0 `TransparentSighashInfo` /
/// `SaplingSignature` / `OrchardSignature` sighashInfo prefix.
///
/// Per ZIP 248 §"Sighash Versioning", sighash version 0 has empty
/// `associatedData` for every bundle type, so `sighashInfo = [0x00]` (a single
/// version byte) and the wire encoding is `compactSize(1) || [0x00]` =
/// `[0x01, 0x00]`. Sighash version 0 is currently the only defined version.
#[cfg(zcash_v6)]
const V6_SIGHASH_V0_INFO_WIRE: &[u8; 2] = &[0x01, 0x00];

/// Implements [ZIP 248 §A.1.0](https://zips.z.cash/zip-0248#a-1-0-transparent-auth-digest).
///
/// Hashes, for each transparent input, the `TransparentSighashInfo` field
/// encoding followed by the `scriptSig` field encoding (a `compactSize`-
/// prefixed byte array). When there are no transparent inputs, returns
/// `BLAKE2b-256("ZTxAuthTransHash", [])`.
///
/// The `sighashInfo` prefix (`V6_SIGHASH_V0_INFO_WIRE = [0x01, 0x00]`) is
/// prepended to every input's scriptSig so that the auth digest commits to
/// the sighash version in use. This enables future sighash versions to be
/// introduced without ambiguity -- a verifier can always determine which
/// sighash algorithm was used to produce each signature. Without this
/// prefix, a transaction produced under sighash v1 could be confused with
/// one produced under v0 (if such a version were ever defined).
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_transparent_auth(
    transparent_bundle: Option<&transparent::Bundle<transparent::Authorized>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
    if let Some(bundle) = transparent_bundle {
        for txin in &bundle.vin {
            h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
            txin.script_sig().write(&mut h).expect("infallible");
        }
    }
    h.finalize()
}

/// Implements [ZIP 248 §A.1.2](https://zips.z.cash/zip-0248#a-1-2-sapling-auth-digest).
///
/// Hashes the spend proofs, the spend-auth signatures (each wrapped as a
/// sighash version 0 `SaplingSignature`), the output proofs, and the binding
/// signature (also as a `SaplingSignature`). When there are no spends and no
/// outputs, returns `BLAKE2b-256("ZTxAuthSapliHash", [])`.
///
/// The ordering follows the spec: all spend proofs first, then all spend-auth
/// signatures (each prefixed with `sighashInfo`), then all output proofs,
/// and finally the binding signature (also prefixed with `sighashInfo`).
/// Grouping proofs separately from signatures allows a verifier to batch-
/// verify all Groth16 proofs in one pass without interleaving signature
/// checks -- a significant performance win for nodes processing blocks.
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_sapling_auth(
    sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION);
    if let Some(bundle) = sapling_bundle {
        // [ZIP 248 §A.1.2a]: all spend proofs, concatenated. Proofs are
        // grouped first so batch verification can process them contiguously.
        for spend in bundle.shielded_spends() {
            h.write_all(spend.zkproof()).expect("infallible");
        }
        // [ZIP 248 §A.1.2b]: each spend-auth signature, prefixed with
        // sighashInfo to bind it to sighash version 0.
        for spend in bundle.shielded_spends() {
            h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
            h.write_all(&<[u8; 64]>::from(*spend.spend_auth_sig()))
                .expect("infallible");
        }
        // [ZIP 248 §A.1.2c]: all output proofs, concatenated.
        for output in bundle.shielded_outputs() {
            h.write_all(output.zkproof()).expect("infallible");
        }
        // [ZIP 248 §A.1.2d]: binding signature, prefixed with sighashInfo.
        // Only present when the bundle has at least one spend or output,
        // because an empty bundle has no value flow to bind.
        if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
            h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
            h.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))
                .expect("infallible");
        }
    }
    h.finalize()
}

/// Implements [ZIP 248 §A.1.3](https://zips.z.cash/zip-0248#a-1-3-orchard-auth-digest).
///
/// Hashes `proofsOrchard` (the aggregated Halo 2 proof bytes), then each
/// per-action spend-auth signature wrapped as a sighash version 0
/// `OrchardSignature`, then the binding signature (also as an
/// `OrchardSignature`). When there are no actions, returns
/// `BLAKE2b-256("ZTxAuthOrchaHash", [])`.
///
/// Unlike sapling where proofs are per-spend/per-output, orchard uses a
/// single aggregated proof for all actions. The ordering is still proof-
/// first so that a verifier can process the proof before checking any
/// signatures.
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_orchard_auth(
    orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION);
    if let Some(bundle) = orchard_bundle {
        // [ZIP 248 §A.1.3a]: the single aggregated proof for all actions.
        h.write_all(bundle.authorization().proof().as_ref())
            .expect("infallible");
        // [ZIP 248 §A.1.3b]: each per-action spend-auth signature, prefixed
        // with sighashInfo to bind it to sighash version 0.
        for action in bundle.actions().iter() {
            h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
            h.write_all(&<[u8; 64]>::from(action.authorization()))
                .expect("infallible");
        }
        // [ZIP 248 §A.1.3c]: binding signature, also prefixed with sighashInfo.
        h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
        h.write_all(&<[u8; 64]>::from(
            bundle.authorization().binding_signature(),
        ))
        .expect("infallible");
    }
    h.finalize()
}

#[cfg(zcash_v6)]
/// Hashes a sequence of tagged per-bundle digests under the given personalization.
///
/// Each entry is serialized as:
///   `compactSize(bundleType) || compactSize(bundleVariant) || digest`
///
/// This "tagged-entry" pattern allows the digest to be extensible: unknown
/// bundle types from future network upgrades are hashed with the same
/// `(bundleType, bundleVariant, digest)` structure as known types. As long
/// as entries are provided in strictly increasing `(bundleType, bundleVariant)`
/// order (which the caller must guarantee), the digest is canonical and
/// forward-compatible.
///
/// Entries use raw `u64` wire values rather than an enum so that unknown
/// bundle types can participate in the digest without requiring code changes.
fn hash_v6_tagged_bundle_digests<'a, I>(personalization: &[u8; 16], entries: I) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    use zcash_encoding::CompactSize;

    let mut h = hasher(personalization);
    for ((bt, bv), digest) in entries {
        // Each tagged entry: bundleType || bundleVariant || 32-byte digest.
        // bundleType and bundleVariant are compactSize-encoded so that small
        // values (all currently defined types) use a single byte each.
        CompactSize::write(&mut h, bt as usize).unwrap();
        CompactSize::write(&mut h, bv as usize).unwrap();
        h.write_all(digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// v6 effects bundles digest per ZIP 248 §T.3 `effects_bundles_digest`.
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_effects_bundles<'a, I>(entries: I) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    hash_v6_tagged_bundle_digests(ZCASH_V6_EFFECTS_BUNDLES_HASH_PERSONALIZATION, entries)
}

/// v6 auth bundles digest per ZIP 248 §A.1 `auth_bundles_digest`.
#[cfg(zcash_v6)]
pub(crate) fn hash_v6_auth_bundles<'a, I>(entries: I) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    hash_v6_tagged_bundle_digests(ZCASH_V6_AUTH_BUNDLES_HASH_PERSONALIZATION, entries)
}

// ---------------------------------------------------------------------------

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

    #[cfg(zcash_unstable = "zfuture")]
    type TzeDigest = Option<TzeDigests<Blake2bHash>>;

    type Digest = TxDigests<Blake2bHash>;

    fn digest_header(
        &self,
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        #[cfg(all(zcash_v6, feature = "zip-233"))] zip233_amount: &Zatoshis,
    ) -> Self::HeaderDigest {
        hash_header_txid_data(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            #[cfg(all(zcash_v6, feature = "zip-233"))]
            zip233_amount,
        )
    }

    fn digest_transparent(
        &self,
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth>>,
    ) -> Self::TransparentDigest {
        transparent_bundle.map(transparent_digests)
    }

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    ) -> Self::SaplingDigest {
        sapling_bundle.map(hash_sapling_txid_data)
    }

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self::OrchardDigest {
        orchard_bundle.map(|b| b.commitment().0)
    }

    #[cfg(zcash_unstable = "zfuture")]
    fn digest_tze(&self, tze_bundle: Option<&tze::Bundle<A::TzeAuth>>) -> Self::TzeDigest {
        tze_bundle.map(tze_digests)
    }

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digests: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        #[cfg(zcash_unstable = "zfuture")] tze_digests: Self::TzeDigest,
    ) -> Self::Digest {
        TxDigests {
            header_digest,
            transparent_digests,
            sapling_digest,
            orchard_digest,
            #[cfg(zcash_unstable = "zfuture")]
            tze_digests,
            // The fields below are populated by the v6-specific `digest_v6()`
            // path; the legacy `TransactionDigest::combine` path used for
            // pre-v6 transactions leaves them empty.
            #[cfg(zcash_v6)]
            value_pool_deltas_digest: None,
            #[cfg(zcash_v6)]
            unknown_effect_digests: alloc::vec::Vec::new(),
            #[cfg(zcash_v6)]
            unknown_auth_digests: alloc::vec::Vec::new(),
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
    #[cfg(zcash_unstable = "zfuture")] tze_digests: Option<&TzeDigests<Blake2bHash>>,
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
            .unwrap_or_else(orchard::commitments::hash_bundle_txid_empty)
            .as_bytes(),
    )
    .unwrap();

    #[cfg(zcash_unstable = "zfuture")]
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
    let txid_digest = match txversion {
        #[cfg(zcash_v6)]
        TxVersion::V6 => to_hash_v6(consensus_branch_id, digests),
        _ => to_hash(
            txversion,
            consensus_branch_id,
            digests.header_digest,
            hash_transparent_txid_data(digests.transparent_digests.as_ref()),
            digests.sapling_digest,
            digests.orchard_digest,
            #[cfg(zcash_unstable = "zfuture")]
            digests.tze_digests.as_ref(),
        ),
    };

    TxId::from_bytes(<[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap())
}

/// Implements [ZIP 248 §txid_digest](https://zips.z.cash/zip-0248#txid-digest).
///
/// Computes the v6 transaction ID as:
///   `BLAKE2b-256(personal, header_digest || vp_deltas_digest || effects_bundles_digest)`
///
/// This is a three-part Merkle-like tree:
///   1. **header_digest** ([ZIP 248 §T.1](https://zips.z.cash/zip-0248#t-1-header-digest)):
///      consensus metadata (version, branch id, lock_time, expiry).
///   2. **vp_deltas_digest** ([ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest)):
///      all value-pool balance changes across every bundle.
///   3. **effects_bundles_digest** ([ZIP 248 §T.3](https://zips.z.cash/zip-0248#t-3-effects-bundles-digest)):
///      per-bundle effects (transparent, sapling, orchard, unknown),
///      each tagged with `(bundleType, bundleVariant)` for extensibility.
///
/// Personalization is `"ZcashTxHash_" || LE32(consensus_branch_id)`, the
/// same scheme as ZIP 244 so that txids are fork-specific.
#[cfg(zcash_v6)]
fn to_hash_v6(consensus_branch_id: BranchId, digests: &TxDigests<Blake2bHash>) -> Blake2bHash {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32_le(consensus_branch_id.into())
        .unwrap();

    // If there are no value-pool deltas (e.g. a coinbase-only transaction),
    // fall back to the empty-hash sentinel so the three-part structure is
    // always present.
    let vp_deltas_digest = digests
        .value_pool_deltas_digest
        .unwrap_or_else(|| hasher(ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION).finalize());

    // The transparent digest is computed from its sub-digests (prevouts,
    // sequences, outputs) and only included in the tagged entries when the
    // transparent bundle is actually present.
    let transparent_digest = hash_transparent_txid_data(digests.transparent_digests.as_ref());

    // Merge known and unknown bundle digests in strictly increasing
    // (bundleType, bundleVariant) order, then hash them as tagged entries.
    let effects_bundles_digest = hash_v6_effects_bundles(v6_bundle_digest_entries(
        digests
            .transparent_digests
            .is_some()
            .then_some(&transparent_digest),
        digests.sapling_digest.as_ref(),
        digests.orchard_digest.as_ref(),
        &digests.unknown_effect_digests,
    ));

    // Final txid preimage: header || vp_deltas || effects_bundles.
    let mut h = hasher(&personal);
    h.write_all(digests.header_digest.as_bytes()).unwrap();
    h.write_all(vp_deltas_digest.as_bytes()).unwrap();
    h.write_all(effects_bundles_digest.as_bytes()).unwrap();
    h.finalize()
}

/// Builds `((bundleType, bundleVariant), &Blake2bHash)` entries for a v6
/// per-bundle digest, merging known transparent/sapling/orchard digests
/// with unknown-bundle digests in strictly increasing `(bundleType,
/// bundleVariant)` order.
///
/// The merge works in two phases:
/// 1. Push known bundle digests (transparent, sapling, orchard) if present.
///    These have well-known `BundleId` constants whose wire keys are defined
///    by the spec to be in increasing order already.
/// 2. Append all unknown-bundle digests. These come from the wire and their
///    keys are guaranteed to be larger than any known bundle type.
///
/// A final `sort_by_key` ensures canonical ordering even if the unknown
/// entries were not pre-sorted by the caller, since the digest must be
/// deterministic regardless of the order bundles were deserialized.
///
/// Absent bundles (e.g. a transaction with no transparent component) are
/// simply omitted -- they do not contribute a zero-digest entry.
#[cfg(zcash_v6)]
pub(crate) fn v6_bundle_digest_entries<'a>(
    transparent_digest: Option<&'a Blake2bHash>,
    sapling_digest: Option<&'a Blake2bHash>,
    orchard_digest: Option<&'a Blake2bHash>,
    unknown: &'a [((u64, u64), Blake2bHash)],
) -> alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> {
    use super::zip248::BundleId;
    let mut entries: alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> = alloc::vec::Vec::new();
    // Known bundles, pushed in the natural order of their wire keys.
    if let Some(d) = transparent_digest {
        entries.push((BundleId::TRANSPARENT.wire_key(), d));
    }
    if let Some(d) = sapling_digest {
        entries.push((BundleId::SAPLING.wire_key(), d));
    }
    if let Some(d) = orchard_digest {
        entries.push((BundleId::ORCHARD.wire_key(), d));
    }
    // Unknown bundles: these were round-tripped from the wire and may include
    // bundle types introduced by future network upgrades that this code does
    // not yet understand. They participate in the digest identically to known
    // bundles so that the txid is stable across software versions.
    for (key, digest) in unknown {
        entries.push((*key, digest));
    }
    // Sort to guarantee the strictly-increasing order required by ZIP 248.
    entries.sort_by_key(|(key, _)| *key);
    entries
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

    #[cfg(zcash_unstable = "zfuture")]
    type TzeDigest = Blake2bHash;

    type Digest = Blake2bHash;

    fn digest_header(
        &self,
        _version: TxVersion,
        consensus_branch_id: BranchId,
        _lock_time: u32,
        _expiry_height: BlockHeight,
        #[cfg(all(zcash_v6, feature = "zip-233"))] _zip233_amount: &Zatoshis,
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

    fn digest_sapling(
        &self,
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

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    ) -> Self::OrchardDigest {
        orchard_bundle.map_or_else(orchard::commitments::hash_bundle_auth_empty, |b| {
            b.authorizing_commitment().0
        })
    }

    #[cfg(zcash_unstable = "zfuture")]
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
        #[cfg(zcash_unstable = "zfuture")] tze_digest: Self::TzeDigest,
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

        #[cfg(zcash_unstable = "zfuture")]
        if TxVersion::suggested_for_branch(consensus_branch_id).has_tze() {
            h.write_all(tze_digest.as_bytes()).unwrap();
        }

        h.finalize()
    }
}
