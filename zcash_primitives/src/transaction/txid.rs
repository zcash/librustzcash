use crate::encoding::{StateWrite, WriteBytesExt};
use core::borrow::Borrow;
use core::convert::TryFrom;
use corez::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params};
use ff::PrimeField;

use ::orchard::{
    ValuePool,
    bundle::{self as orchard, TxVersion as OrchardTxVersion},
};
use ::sapling::bundle::{OutputDescription, SpendDescription};
use ::transparent::bundle::{self as transparent, TxIn, TxOut};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::ZatBalance,
};

use super::{
    Authorization, Authorized, TransactionDigest, TransparentDigests, TxId, TxVersion,
    Zip244Digests,
};

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
const ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNH_v6";

const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

const ZCASH_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";
const ZCASH_SAPLING_V6_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliH_v6";

fn sapling_spends_noncompact_personalization(version: TxVersion) -> &'static [u8; 16] {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
            ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
        }
        TxVersion::V6 => ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
        #[cfg(zcash_unstable = "nutachyon")]
        TxVersion::V7 => ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
    }
}

fn sapling_auth_personalization(version: TxVersion) -> &'static [u8; 16] {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
            ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION
        }
        TxVersion::V6 => ZCASH_SAPLING_V6_SIGS_HASH_PERSONALIZATION,
        #[cfg(zcash_unstable = "nutachyon")]
        TxVersion::V7 => ZCASH_SAPLING_V6_SIGS_HASH_PERSONALIZATION,
    }
}

fn sapling_auth_includes_anchor(version: TxVersion) -> bool {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => false,
        TxVersion::V6 => true,
        #[cfg(zcash_unstable = "nutachyon")]
        TxVersion::V7 => true,
    }
}

/// Selects the `(value pool, orchard tx version)` pair identifying the
/// `BundleCommitmentDomain` used for Orchard-slot commitments in the given
/// transaction version. The value pool here is only used for empty-bundle
/// commitments (which hash no flags); present bundles compute their commitments
/// from the `BundleVersion` each bundle carries.
fn orchard_commitment_domain(version: TxVersion) -> (ValuePool, OrchardTxVersion) {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
            (ValuePool::Orchard, OrchardTxVersion::V5)
        }
        TxVersion::V6 => (ValuePool::Orchard, OrchardTxVersion::V6),
        #[cfg(zcash_unstable = "nutachyon")]
        TxVersion::V7 => (ValuePool::Orchard, OrchardTxVersion::V6),
    }
}

fn ironwood_v6_domain() -> (ValuePool, OrchardTxVersion) {
    (ValuePool::Ironwood, OrchardTxVersion::V6)
}
const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";

// ZIP 248 V6-specific personalization strings
// ZIP 248 v6 personalizations.
pub(crate) const ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdVPDeltaHash";
// ZIP 248 v6 personalizations.
pub(crate) const ZCASH_V6_EFFECTS_BUNDLES_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdEffBnd_Hash";
// ZIP 248 v6 personalizations.
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

/// Implements [ZIP 244 section T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest);
/// the v6 variant is specified in [ZIP 229](https://zips.z.cash/zip-0229).
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk)*\] for v5 transactions (v4 is not handled here), personalized with
///   ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
/// * \[(cv, rk)*\] for v6 transactions, personalized with
///   ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
pub(crate) fn hash_sapling_spends<A: sapling::bundle::Authorization>(
    version: TxVersion,
    shielded_spends: &[SpendDescription<A>],
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    if !shielded_spends.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
        let mut nh = hasher(sapling_spends_noncompact_personalization(version));
        for s_spend in shielded_spends {
            // we build the hash of nullifiers separately for compact blocks.
            ch.write_all(s_spend.nullifier().as_ref()).unwrap();

            nh.write_all(&s_spend.cv().to_bytes()).unwrap();
            let write_anchor = match version {
                TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => true,
                TxVersion::V6 => false,
                #[cfg(zcash_unstable = "nutachyon")]
                TxVersion::V7 => false,
            };
            if write_anchor {
                nh.write_all(&s_spend.anchor().to_repr()).unwrap();
            }
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

/// Implements [ZIP 244 section T.1](https://zips.z.cash/zip-0244#t-1-header-digest)
fn hash_header_txid_data(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);

    h.write_u32_le(version.header()).unwrap();
    h.write_u32_le(version.version_group_id()).unwrap();
    h.write_u32_le(consensus_branch_id.into()).unwrap();
    h.write_u32_le(lock_time).unwrap();
    h.write_u32_le(expiry_height.into()).unwrap();

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

/// Implements [ZIP 244 section T.3](https://zips.z.cash/zip-0244#t-3-sapling-digest);
/// for v6 transactions the Sapling digest follows
/// [ZIP 229](https://zips.z.cash/zip-0229).
fn hash_sapling_txid_data<A: sapling::bundle::Authorization>(
    version: TxVersion,
    bundle: &sapling::Bundle<A, ZatBalance>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
        h.write_all(hash_sapling_spends(version, bundle.shielded_spends()).as_bytes())
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

/// V6 header digest: same fields as V5 but WITHOUT zip233_amount.
// ZIP 248 v6 digest helpers are always compiled.
pub(crate) fn hash_v6_header(
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);
    h.write_u32_le(version.header()).unwrap();
    h.write_u32_le(version.version_group_id()).unwrap();
    h.write_u32_le(consensus_branch_id.into()).unwrap();
    h.write_u32_le(lock_time).unwrap();
    h.write_u32_le(expiry_height.into()).unwrap();
    h.finalize()
}

/// V6 value pool deltas digest.
// ZIP 248 v6 digest helpers are always compiled.
pub(crate) fn hash_v6_value_pool_deltas(vp: &super::zip248::ValuePoolDeltas) -> Blake2bHash {
    let mut h = hasher(ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION);
    for entry in vp.to_wire_entries() {
        entry.write(&mut h).unwrap();
    }
    h.finalize()
}

/// v6 sapling effects digest per ZIP 248 §T.3.2: spends_digest || outputs_digest
/// || anchorSapling, with valueBalance excluded (it lives in mValuePoolDeltas).
///
/// When `nSpendsSapling = 0` the wire format omits `anchorSapling`; per the
/// clarified ZIP 248 §T.3.2 the digest still includes 32 bytes at position
/// T.3.2c, which are hashed as 32 zero bytes in that case.
// ZIP 248 v6 digest helpers are always compiled.
pub(crate) fn hash_v6_sapling_effects<A: sapling::bundle::Authorization>(
    bundle: &sapling::Bundle<A, ZatBalance>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
        h.write_all(hash_sapling_spends(TxVersion::V6, bundle.shielded_spends()).as_bytes())
            .unwrap();
        h.write_all(hash_sapling_outputs(bundle.shielded_outputs()).as_bytes())
            .unwrap();
        if let Some(spend) = bundle.shielded_spends().first() {
            h.write_all(spend.anchor().to_repr().as_ref()).unwrap();
        } else {
            h.write_all(&[0u8; 32]).unwrap();
        }
    }
    h.finalize()
}

/// v6 orchard effects digest: actions + flags + anchor, WITHOUT value_balance.
/// Computed from bundle accessors rather than delegating to the orchard crate's
/// `commitment()` method (which includes value_balance).
// ZIP 248 v6 digest helpers are always compiled.
pub(crate) fn hash_v6_orchard_effects(
    bundle: &orchard::Bundle<impl orchard::Authorization, ZatBalance>,
) -> Blake2bHash {
    // Use the same personalization as the orchard crate's commitment
    const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
    let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);

    // Per ZIP 248 §T.3.3 the structure of orchard_effects_digest matches that of
    // ZIP 244's orchard_digest, except that valueBalanceOrchard is not committed
    // here (it lives in mValuePoolDeltas instead). The orchard crate's
    // `hash_bundle_txid_data` is the ZIP 244 form and is not directly reusable;
    // we re-implement the per-action sub-hashes inline using identical
    // personalizations.
    const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] =
        b"ZTxIdOrcActCHash";
    const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] =
        b"ZTxIdOrcActMHash";
    const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] =
        b"ZTxIdOrcActNHash";

    if !bundle.actions().is_empty() {
        let mut compact_h = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        let mut memos_h = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        let mut noncompact_h = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

        for action in bundle.actions().iter() {
            compact_h.write_all(&action.nullifier().to_bytes()).unwrap();
            compact_h.write_all(&action.cmx().to_bytes()).unwrap();
            compact_h.write_all(&action.encrypted_note().epk_bytes).unwrap();
            compact_h
                .write_all(&action.encrypted_note().enc_ciphertext.as_ref()[..52])
                .unwrap();

            memos_h
                .write_all(&action.encrypted_note().enc_ciphertext.as_ref()[52..564])
                .unwrap();

            noncompact_h.write_all(&action.cv_net().to_bytes()).unwrap();
            noncompact_h.write_all(&<[u8; 32]>::from(action.rk())).unwrap();
            noncompact_h
                .write_all(&action.encrypted_note().enc_ciphertext.as_ref()[564..])
                .unwrap();
            noncompact_h
                .write_all(&action.encrypted_note().out_ciphertext)
                .unwrap();
        }

        h.write_all(compact_h.finalize().as_bytes()).unwrap();
        h.write_all(memos_h.finalize().as_bytes()).unwrap();
        h.write_all(noncompact_h.finalize().as_bytes()).unwrap();
        let flags_byte = u8::from(bundle.flags().spends_enabled())
            | (u8::from(bundle.flags().outputs_enabled()) << 1);
        h.write_all(&[flags_byte]).unwrap();
        h.write_all(&bundle.anchor().to_bytes()).unwrap();
        // Note: valueBalanceOrchard is deliberately NOT included; it lives in
        // mValuePoolDeltas per ZIP 248.
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
const V6_SIGHASH_V0_INFO_WIRE: &[u8; 2] = &[0x01, 0x00];

/// v6 transparent authorizing-data digest per ZIP 248 §A.1.0.
///
/// Hashes, for each transparent input, the `TransparentSighashInfo` field
/// encoding (sighash version 0: `[0x01, 0x00]`) followed by the `scriptSig`
/// field encoding (a `compactSize`-prefixed byte array). When there are no
/// transparent inputs, returns `BLAKE2b-256("ZTxAuthTransHash", [])`.
// ZIP 248 v6 digest helpers are always compiled.
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

/// v6 sapling authorizing-data digest per ZIP 248 §A.1.2.
///
/// Hashes the spend proofs, the spend auth signatures (each wrapped as a
/// sighash version 0 `SaplingSignature`), the output proofs, and the binding
/// signature (also as a `SaplingSignature`). When there are no spends and no
/// outputs, returns `BLAKE2b-256("ZTxAuthSapliHash", [])`.
// ZIP 248 v6 digest helpers are always compiled.
pub(crate) fn hash_v6_sapling_auth(
    sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION);
    if let Some(bundle) = sapling_bundle {
        for spend in bundle.shielded_spends() {
            h.write_all(spend.zkproof()).expect("infallible");
        }
        for spend in bundle.shielded_spends() {
            h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
            h.write_all(&<[u8; 64]>::from(*spend.spend_auth_sig()))
                .expect("infallible");
        }
        for output in bundle.shielded_outputs() {
            h.write_all(output.zkproof()).expect("infallible");
        }
        if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
            h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
            h.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))
                .expect("infallible");
        }
    }
    h.finalize()
}

/// v6 orchard authorizing-data digest per ZIP 248 §A.1.3.
///
/// Hashes `proofsOrchard` (the aggregated zk-SNARK proof bytes), then each
/// per-action spend-auth signature wrapped as a sighash version 0
/// `OrchardSignature`, then the binding signature (also as an
/// `OrchardSignature`). When there are no actions, returns
/// `BLAKE2b-256("ZTxAuthOrchaHash", [])`.
// ZIP 248 v6 digest helpers are always compiled.
pub(crate) fn hash_v6_orchard_auth(
    orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION);
    if let Some(bundle) = orchard_bundle {
        h.write_all(bundle.authorization().proof().as_ref())
            .expect("infallible");
        for action in bundle.actions().iter() {
            h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
            h.write_all(&<[u8; 64]>::from(action.authorization()))
                .expect("infallible");
        }
        h.write_all(V6_SIGHASH_V0_INFO_WIRE).expect("infallible");
        h.write_all(&<[u8; 64]>::from(
            bundle.authorization().binding_signature(),
        ))
        .expect("infallible");
    }
    h.finalize()
}

/// Hashes a sequence of tagged per-bundle digests under the given personalization,
/// where each entry is `(bundleType compactSize || bundleVariant compactSize || digest)`.
///
/// The caller is responsible for providing entries in the order required by ZIP 248
/// (strictly increasing `(bundleType, bundleVariant)`), including any unknown bundles.
// ZIP 248 v6 digest helpers are always compiled.
fn hash_v6_tagged_bundle_digests<'a, I>(
    personalization: &[u8; 16],
    entries: I,
) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    use zcash_encoding::CompactSize;

    let mut h = hasher(personalization);
    for (id, digest) in entries {
        CompactSize::write(&mut h, id.0 as usize).unwrap();
        CompactSize::write(&mut h, id.1 as usize).unwrap();
        h.write_all(digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// v6 effects bundles digest per ZIP 248 §T.3 `effects_bundles_digest`.
///
/// Wraps each per-bundle effecting-data digest with `(bundleType, bundleVariant)`
/// tags and hashes them in increasing `bundleType` order under the
/// `ZTxIdEffBnd_Hash` personalization.
// ZIP 248 v6 digest helpers are always compiled.
pub(crate) fn hash_v6_effects_bundles<'a, I>(entries: I) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    hash_v6_tagged_bundle_digests(ZCASH_V6_EFFECTS_BUNDLES_HASH_PERSONALIZATION, entries)
}

/// v6 auth bundles digest per ZIP 248 §A.1 `auth_bundles_digest`.
///
/// Wraps each per-bundle authorizing-data digest with `(bundleType, bundleVariant)`
/// tags and hashes them in increasing `bundleType` order under the
/// `ZTxAuthBnd__Hash` personalization.
// ZIP 248 v6 digest helpers are always compiled.
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
/// This implements transaction ID digests for v5 transactions ([ZIP 244]) and for
/// v6 transactions ([ZIP 229]). It cannot be used to compute the transaction ID for
/// v4 or earlier transactions; those used `SHA-256(SHA-256(tx_encoding))` and are
/// malleable.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244#txid-digest
/// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
pub struct TxIdDigester;

impl<A: Authorization> TransactionDigest<A> for TxIdDigester {
    type HeaderDigest = Blake2bHash;
    type TransparentDigest = Option<TransparentDigests<Blake2bHash>>;
    type SaplingDigest = Option<Blake2bHash>;
    type OrchardDigest = Option<Blake2bHash>;
    type IronwoodDigest = Option<Blake2bHash>;

    type Digest = Zip244Digests<Blake2bHash>;

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
        version: TxVersion,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    ) -> Self::SaplingDigest {
        sapling_bundle.map(|bundle| hash_sapling_txid_data(version, bundle))
    }

    fn digest_orchard(
        &self,
        version: TxVersion,
        orchard_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self::OrchardDigest {
        orchard_bundle.map(|b| {
            let (_, tx_version) = orchard_commitment_domain(version);
            b.commitment(tx_version)
                .expect("Orchard bundle flags must be representable in their transaction format")
                .0
        })
    }

    fn digest_ironwood(
        &self,
        ironwood_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self::IronwoodDigest {
        ironwood_bundle.map(|b| {
            let (_, tx_version) = ironwood_v6_domain();
            b.commitment(tx_version)
                .expect("Ironwood bundle flags must be representable")
                .0
        })
    }

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digests: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        ironwood_digest: Self::IronwoodDigest,
    ) -> Self::Digest {
        Zip244Digests {
            header_digest,
            transparent_digests,
            sapling_digest,
            orchard_digest,
            ironwood_digest,
            // Populated by digest_v6() path, not via combine()
            value_pool_deltas_digest: None,
            unknown_effect_digests: alloc::vec::Vec::new(),
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
            .unwrap_or_else(|| {
                let (value_pool, tx_version) = orchard_commitment_domain(_txversion);
                orchard::commitments::hash_bundle_txid_empty(value_pool, tx_version)
                    .expect("empty Orchard bundle txid commitment is valid for its tx format")
            })
            .as_bytes(),
    )
    .unwrap();

    h.finalize()
}

pub(crate) fn to_hash_v6(
    consensus_branch_id: BranchId,
    header_digest: Blake2bHash,
    transparent_digest: Blake2bHash,
    sapling_digest: Option<Blake2bHash>,
    orchard_digest: Option<Blake2bHash>,
    ironwood_digest: Option<Blake2bHash>,
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
            .unwrap_or_else(|| {
                let (value_pool, tx_version) = orchard_commitment_domain(TxVersion::V6);
                orchard::commitments::hash_bundle_txid_empty(value_pool, tx_version)
                    .expect("empty Orchard bundle txid commitment is valid for its tx format")
            })
            .as_bytes(),
    )
    .unwrap();
    h.write_all(
        ironwood_digest
            .unwrap_or_else(|| {
                let (value_pool, tx_version) = ironwood_v6_domain();
                orchard::commitments::hash_bundle_txid_empty(value_pool, tx_version)
                    .expect("empty Ironwood bundle txid commitment is valid")
            })
            .as_bytes(),
    )
    .unwrap();

    h.finalize()
}

/// Combines transaction component digests into a transaction ID.
///
/// Returns `None` if `txversion` is incompatible with `digests`.
///
/// V6 transactions use the ZIP 248 digest tree. V7 transactions include the Ironwood
/// bundle digest as a separate Orchard-shaped digest using Ironwood personalization.
/// If any shielded bundle digest is absent, this substitutes the protocol-defined empty
/// bundle digest for that pool.
pub fn to_txid(
    txversion: TxVersion,
    consensus_branch_id: BranchId,
    digests: &Zip244Digests<Blake2bHash>,
) -> Option<TxId> {
    match txversion {
        // These versions cannot produce a txid just from digests, because they use
        // SHA-256d over the entire tx encoding which is unavailable here.
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => return None,
        // These versions are compatible with `Zip244Digests`.
        TxVersion::V5 | TxVersion::V6 => (),
        #[cfg(zcash_unstable = "nutachyon")]
        TxVersion::V7 => (),
    }

    let txid_digest = if txversion == TxVersion::V6 {
        to_hash_v6_zip248(consensus_branch_id, digests)
    } else if txversion.has_ironwood() {
        to_hash_v6(
            consensus_branch_id,
            digests.header_digest,
            hash_transparent_txid_data(digests.transparent_digests.as_ref()),
            digests.sapling_digest,
            digests.orchard_digest,
            digests.ironwood_digest,
        )
    } else {
        to_hash(
            txversion,
            consensus_branch_id,
            digests.header_digest,
            hash_transparent_txid_data(digests.transparent_digests.as_ref()),
            digests.sapling_digest,
            digests.orchard_digest,
        )
    };

    Some(TxId::from_bytes(
        <[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap(),
    ))
}

/// v6 txid hash per ZIP 248 §T: header_digest || value_pool_deltas_digest ||
/// effects_bundles_digest, all under the consensus-branch-id-personalized
/// "ZcashTxHash_" hash.
// ZIP 248 v6 digest helpers are always compiled.
fn to_hash_v6_zip248(
    consensus_branch_id: BranchId,
    digests: &Zip244Digests<Blake2bHash>,
) -> Blake2bHash {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32_le(consensus_branch_id.into())
        .unwrap();

    let vp_deltas_digest = digests
        .value_pool_deltas_digest
        .unwrap_or_else(|| hasher(ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION).finalize());

    let transparent_digest = hash_transparent_txid_data(digests.transparent_digests.as_ref());

    let effects_bundles_digest = hash_v6_effects_bundles(v6_effect_digest_entries(
        digests.transparent_digests.is_some().then_some(&transparent_digest),
        digests.sapling_digest.as_ref(),
        digests.orchard_digest.as_ref(),
        &digests.unknown_effect_digests,
    ));

    let mut h = hasher(&personal);
    h.write_all(digests.header_digest.as_bytes()).unwrap();
    h.write_all(vp_deltas_digest.as_bytes()).unwrap();
    h.write_all(effects_bundles_digest.as_bytes()).unwrap();
    h.finalize()
}
/// Builds the personalization for the `ZcashTxHash_` root hash of a transaction
/// with the given consensus branch ID.
pub(crate) fn tx_hash_personalization(consensus_branch_id: BranchId) -> [u8; 16] {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32_le(consensus_branch_id.into())
        .unwrap();
    personal
}

/// Builds the `((bundleType, bundleVariant), &Blake2bHash)` entries for the v6
/// tagged bundle digests, merging the known transparent/Sapling/Orchard digests
/// with the unknown-bundle digests in strictly increasing wire-key order.
pub(crate) fn v6_bundle_digest_entries<'a>(
    transparent_digest: Option<&'a Blake2bHash>,
    sapling_digest: Option<&'a Blake2bHash>,
    orchard_digest: Option<&'a Blake2bHash>,
    unknown: &'a [((u64, u64), Blake2bHash)],
) -> alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> {
    use super::zip248::BundleId;
    let mut entries: alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> = alloc::vec::Vec::new();
    if let Some(d) = transparent_digest {
        entries.push((BundleId::TRANSPARENT.wire_key(), d));
    }
    if let Some(d) = sapling_digest {
        entries.push((BundleId::SAPLING.wire_key(), d));
    }
    if let Some(d) = orchard_digest {
        entries.push((BundleId::ORCHARD.wire_key(), d));
    }
    for (key, digest) in unknown {
        entries.push((*key, digest));
    }
    entries.sort_by_key(|(key, _)| *key);
    entries
}


/// Builds the (BundleId, &Blake2bHash) entries for `effects_bundles_digest` /
/// `signature_bundles_digest`, merging the known transparent/sapling/orchard
/// per-bundle digests with any unknown-bundle digests in strictly increasing
/// `(bundleType, bundleVariant)` order. Returns a `Vec` so the caller can pass
/// it directly into `hash_v6_effects_bundles`.
pub(crate) fn v6_effect_digest_entries<'a>(
    transparent_digest: Option<&'a Blake2bHash>,
    sapling_digest: Option<&'a Blake2bHash>,
    orchard_digest: Option<&'a Blake2bHash>,
    unknown: &'a [((u64, u64), Blake2bHash)],
) -> alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> {
    use super::zip248::BundleId;
    let mut entries: alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> = alloc::vec::Vec::new();
    if let Some(d) = transparent_digest {
        entries.push((BundleId::TRANSPARENT.wire_key(), d));
    }
    if let Some(d) = sapling_digest {
        entries.push((BundleId::SAPLING.wire_key(), d));
    }
    if let Some(d) = orchard_digest {
        entries.push((BundleId::ORCHARD.wire_key(), d));
    }
    for (id, digest) in unknown {
        entries.push((*id, digest));
    }
    entries.sort_by_key(|(id, _)| *id);
    entries
}

/// Builds the (BundleId, &Blake2bHash) entries for `auth_bundles_digest`,
/// merging known and unknown per-bundle authorizing-data digests in strictly
/// increasing `(bundleType, bundleVariant)` order.
pub(crate) fn v6_auth_digest_entries<'a>(
    transparent_auth_digest: Option<&'a Blake2bHash>,
    sapling_auth_digest: Option<&'a Blake2bHash>,
    orchard_auth_digest: Option<&'a Blake2bHash>,
    unknown: &'a [((u64, u64), Blake2bHash)],
) -> alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> {
    use super::zip248::BundleId;
    let mut entries: alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> = alloc::vec::Vec::new();
    if let Some(d) = transparent_auth_digest {
        entries.push((BundleId::TRANSPARENT.wire_key(), d));
    }
    if let Some(d) = sapling_auth_digest {
        entries.push((BundleId::SAPLING.wire_key(), d));
    }
    if let Some(d) = orchard_auth_digest {
        entries.push((BundleId::ORCHARD.wire_key(), d));
    }
    for (id, digest) in unknown {
        entries.push((*id, digest));
    }
    entries.sort_by_key(|(id, _)| *id);
    entries
}

/// Digester which constructs a digest of only the witness data.
/// This does not internally commit to the txid, so if that is
/// desired it should be done using the result of this digest
/// function.
pub struct BlockTxCommitmentDigester;

impl TransactionDigest<Authorized> for BlockTxCommitmentDigester {
    /// We use the header digest to pass the transaction version and consensus
    /// branch ID into where they need to be used for personalization string
    /// construction.
    type HeaderDigest = (TxVersion, BranchId);
    type TransparentDigest = Blake2bHash;
    type SaplingDigest = Blake2bHash;
    type OrchardDigest = Blake2bHash;
    type IronwoodDigest = Blake2bHash;

    type Digest = Blake2bHash;

    fn digest_header(
        &self,
        _version: TxVersion,
        consensus_branch_id: BranchId,
        _lock_time: u32,
        _expiry_height: BlockHeight,
    ) -> Self::HeaderDigest {
        (_version, consensus_branch_id)
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
        version: TxVersion,
        sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
    ) -> Blake2bHash {
        let mut h = hasher(sapling_auth_personalization(version));
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

            if sapling_auth_includes_anchor(version) && !bundle.shielded_spends().is_empty() {
                h.write_all(bundle.shielded_spends()[0].anchor().to_repr().as_ref())
                    .unwrap();
            }
        }
        h.finalize()
    }

    fn digest_orchard(
        &self,
        version: TxVersion,
        orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    ) -> Self::OrchardDigest {
        let (value_pool, tx_version) = orchard_commitment_domain(version);
        orchard_bundle.map_or_else(
            || {
                orchard::commitments::hash_bundle_auth_empty(value_pool, tx_version)
                    .expect("empty Orchard bundle auth commitment is valid for its tx format")
            },
            |b| {
                b.authorizing_commitment(tx_version)
                    .expect("Orchard bundle flags must be representable in their tx format")
                    .0
            },
        )
    }

    fn digest_ironwood(
        &self,
        ironwood_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    ) -> Self::IronwoodDigest {
        let (value_pool, tx_version) = ironwood_v6_domain();
        ironwood_bundle.map_or_else(
            || {
                orchard::commitments::hash_bundle_auth_empty(value_pool, tx_version)
                    .expect("empty Ironwood bundle auth commitment is valid")
            },
            |b| {
                b.authorizing_commitment(tx_version)
                    .expect("Ironwood bundle flags must be representable")
                    .0
            },
        )
    }

    fn combine(
        &self,
        tx_context: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        ironwood_digest: Self::IronwoodDigest,
    ) -> Self::Digest {
        let (_txversion, consensus_branch_id) = tx_context;
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32_le(consensus_branch_id.into())
            .unwrap();

        let mut h = hasher(&personal);
        h.write_all(transparent_digest.as_bytes()).unwrap();
        h.write_all(sapling_digest.as_bytes()).unwrap();
        h.write_all(orchard_digest.as_bytes()).unwrap();

        if _txversion.has_ironwood() {
            h.write_all(ironwood_digest.as_bytes()).unwrap();
        }

        h.finalize()
    }
}
