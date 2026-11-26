use crate::encoding::{StateWrite, WriteBytesExt};
use core::borrow::Borrow;
use core::convert::TryFrom;
use corez::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params};

#[cfg(feature = "orchard")]
use ::orchard::{
    ValuePool,
    bundle::{self as orchard, TxVersion as OrchardTxVersion},
};
#[cfg(all(test, feature = "sapling", feature = "orchard"))]
use ::sapling::bundle::SpendDescription;
use ::transparent::bundle::{self as transparent, TxIn, TxOut};
#[cfg(any(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
use zcash_protocol::value::ZatBalance;
use zcash_protocol::value::Zatoshis;
#[cfg(feature = "sapling")]
use {::sapling::bundle::OutputDescription, ff::PrimeField};

use zcash_protocol::consensus::{BlockHeight, BranchId};

use super::components::transparent::{write_outpoint, write_script, write_txout};
#[cfg(any(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
use super::zip248::V7DigestError;
use super::{Authorization, Authorized, TransactionDigest};
use super::{TransparentDigests, TxId, TxVersion, Zip244Digests};

#[cfg(zcash_unstable = "nu8")]
use {
    super::{
        bytes::transparent::TransparentEffectsBytes,
        bytes::{
            CoinbaseBundleBytes, OrchardActionBytes, TransparentAuthBytes, V7AuthBundleBytes,
            V7EffectBundleBytes, V7OrchardAuthBytes, V7OrchardBundleBytes, V7SaplingAuthBytes,
            V7SaplingBundleBytes, ValuePoolDeltaBytes,
        },
        zip248::{BundleDigestProvider, BundleId, BundleType, BundleVariant},
    },
    alloc::{collections::BTreeMap, vec::Vec},
    zcash_encoding::CompactSize,
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
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendsHash";
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendCHash";
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNHash";
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNH_v6";

#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

pub(crate) const ZCASH_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";
const ZCASH_SAPLING_V6_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliH_v6";

/// Selects the personalization for the Sapling spends non-compact digest.
///
/// [ZIP 244 §T.3a.ii] and [ZIP 229]'s v5 form hash `cv || anchor || rk` per
/// spend under `ZTxIdSSpendNHash`. ZIP 229's v6 digest, which ZIP 248 §T.3.2a.ii
/// adopts for v7, hashes `cv || rk` under `ZTxIdSSpendNH_v6`, because the
/// anchor is authorizing data from v6 onward.
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
/// [ZIP 244 §T.3a.ii]: https://zips.z.cash/zip-0244#t-3a-ii-sapling-spends-noncompact-digest
/// [ZIP 248 §T.3.2a.ii]: https://zips.z.cash/zip-0248#t-3-2a-ii-sapling-spends-noncompact-digest
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
fn sapling_spends_noncompact_personalization(version: TxVersion) -> &'static [u8; 16] {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
            ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
        }
        TxVersion::V6 => ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
    }
}

fn sapling_auth_personalization(version: TxVersion) -> &'static [u8; 16] {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
            ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION
        }
        TxVersion::V6 => ZCASH_SAPLING_V6_SIGS_HASH_PERSONALIZATION,
        // Unreachable for v7, whose authorizing data commitment is built by
        // `hash_v7_sapling_auth` under `ZTxAuthSapliH_v7`.
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => ZCASH_V7_SAPLING_AUTH_HASH_PERSONALIZATION,
    }
}

#[cfg(feature = "sapling")]
fn sapling_auth_includes_anchor(version: TxVersion) -> bool {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => false,
        TxVersion::V6 => true,
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => true,
    }
}

/// Selects the `(value pool, orchard tx version)` pair identifying the
/// `BundleCommitmentDomain` used for Orchard-slot commitments in the given
/// transaction version. The value pool here is only used for empty-bundle
/// commitments (which hash no flags); present bundles compute their commitments
/// from the `BundleVersion` each bundle carries.
#[cfg(feature = "orchard")]
fn orchard_commitment_domain(version: TxVersion) -> (ValuePool, OrchardTxVersion) {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
            (ValuePool::Orchard, OrchardTxVersion::V5)
        }
        TxVersion::V6 => (ValuePool::Orchard, OrchardTxVersion::V6),
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => (ValuePool::Orchard, OrchardTxVersion::V6),
    }
}

#[cfg(feature = "orchard")]
fn ironwood_v6_domain() -> (ValuePool, OrchardTxVersion) {
    (ValuePool::Ironwood, OrchardTxVersion::V6)
}

// ZIP 248 v7-specific personalization strings
//
// The Sapling and Orchard digests are personalized differently from their
// ZIP 244 counterparts because what they hash has changed: the value balance
// moved to `value_pool_deltas_digest`, and the anchor moved from the effecting
// data to the authorizing data.
#[cfg(zcash_unstable = "nu8")]
pub(crate) const ZCASH_V7_VP_DELTAS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdVPDeltaHash";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_COINBASE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdCoinbasHash";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSaplingH_v7";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_SAPLING_AUTH_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliH_v7";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardH_v7";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_ORCHARD_AUTH_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaH_v7";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_IRONWOOD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIronwd_Hash";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_IRONWOOD_AUTH_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthIrnwdHash";
#[cfg(zcash_unstable = "nu8")]
pub(crate) const ZCASH_V7_EFFECTS_BUNDLES_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdEffBnd_Hash";
#[cfg(zcash_unstable = "nu8")]
pub(crate) const ZCASH_V7_AUTH_BUNDLES_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthBnd__Hash";

pub(crate) fn hasher(personal: &[u8; 16]) -> StateWrite {
    StateWrite(Params::new().hash_length(32).personal(personal).to_state())
}

/// Builds the 16-byte BLAKE2b personalization used for txid and sighash
/// top-level hashes: `"ZcashTxHash_" || LE32(consensus_branch_id)`.
pub(crate) fn tx_hash_personalization(consensus_branch_id: BranchId) -> [u8; 16] {
    tx_hash_personalization_raw(consensus_branch_id.into())
}

/// Builds the 16-byte BLAKE2b personalization used for txid and sighash
/// top-level hashes from a raw `nConsensusBranchId` value:
/// `"ZcashTxHash_" || LE32(consensus_branch_id)`.
///
/// The raw form is used where the branch ID is committed to verbatim, without
/// requiring it to name a branch this implementation recognizes.
pub(crate) fn tx_hash_personalization_raw(consensus_branch_id: u32) -> [u8; 16] {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32_le(consensus_branch_id)
        .unwrap();
    personal
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
        write_outpoint(&mut h, t_in.prevout()).unwrap();
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
pub(crate) fn transparent_outputs_hash<T: Borrow<TxOut<Zatoshis>>>(vout: &[T]) -> Blake2bHash {
    let mut h = hasher(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    for t_out in vout {
        write_txout(&mut h, t_out.borrow()).unwrap();
    }
    h.finalize()
}

/// The fields of a Sapling spend that the effects digest commits to.
///
/// `anchor` is only committed to by v5 and earlier effects digests. From v6
/// onward the anchor is authorizing data and is committed to by the auth
/// digest instead, but the field remains part of this struct in every
/// transaction version because the types are shared.
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
pub(crate) struct SaplingSpendDigestParts {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub anchor: Option<[u8; 32]>,
    pub rk: [u8; 32],
}

/// Implements [ZIP 244 section T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest);
/// the v6 variant is specified in [ZIP 229](https://zips.z.cash/zip-0229), and
/// the v7 variant in [ZIP 248 §T.3.2a](https://zips.z.cash/zip-0248#t-3-2a-sapling-spends-digest).
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk)*\] for v5 and earlier transactions (v4 is not handled
///   here), personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
/// * \[(cv, rk)*\] for v6 and v7 transactions, personalized with
///   ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
pub(crate) fn hash_sapling_spends_parts(
    version: TxVersion,
    spends: impl IntoIterator<Item = SaplingSpendDigestParts>,
) -> Result<Blake2bHash, V7DigestError> {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
    let mut nh = hasher(sapling_spends_noncompact_personalization(version));
    let mut any = false;
    for spend in spends {
        any = true;
        // we build the hash of nullifiers separately for compact blocks.
        ch.write_all(&spend.nullifier).unwrap();

        nh.write_all(&spend.cv).unwrap();
        // [ZIP 248 §T.3.2a.ii]: the bundle-wide anchor is authorizing data from
        // v6 onward, so the non-compact spends digest only hashes it for v5 and
        // earlier, where ZIP 244 put it in the effecting data.
        let write_anchor = match version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => true,
            TxVersion::V6 => false,
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => false,
        };
        if write_anchor {
            nh.write_all(&spend.anchor.ok_or(V7DigestError::MissingEffectingAnchor)?)
                .unwrap();
        }
        nh.write_all(&spend.rk).unwrap();
    }

    if any {
        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
    }
    Ok(h.finalize())
}

#[cfg(all(test, feature = "sapling", feature = "orchard"))]
pub(crate) fn hash_sapling_spends<A: sapling::bundle::Authorization>(
    version: TxVersion,
    shielded_spends: &[SpendDescription<A>],
) -> Blake2bHash {
    hash_sapling_spends_parts(
        version,
        shielded_spends
            .iter()
            .map(|s_spend| SaplingSpendDigestParts {
                cv: s_spend.cv().to_bytes(),
                nullifier: s_spend.nullifier().0,
                anchor: Into::<Option<jubjub::Base>>::into(*s_spend.anchor())
                    .map(|anchor| anchor.to_repr()),
                rk: <[u8; 32]>::from(*s_spend.rk()),
            }),
    )
    .expect("test spends carry effecting anchors")
}

/// The fields of a Sapling output that the effects digest commits to.
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
pub(crate) struct SaplingOutputDigestParts {
    pub cv: [u8; 32],
    pub cmu: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
}

/// Implements [ZIP 244 section T.3b](https://zips.z.cash/zip-0244#t-3b-sapling-outputs-digest)
///
/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext, zkproof)*\] personalized with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
pub(crate) fn hash_sapling_outputs_parts(
    outputs: impl IntoIterator<Item = SaplingOutputDigestParts>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);
    let mut ch = hasher(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);
    let mut mh = hasher(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);
    let mut nh = hasher(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);
    let mut any = false;
    for output in outputs {
        any = true;
        ch.write_all(&output.cmu).unwrap();
        ch.write_all(&output.ephemeral_key).unwrap();
        ch.write_all(&output.enc_ciphertext[..52]).unwrap();

        mh.write_all(&output.enc_ciphertext[52..564]).unwrap();

        nh.write_all(&output.cv).unwrap();
        nh.write_all(&output.enc_ciphertext[564..]).unwrap();
        nh.write_all(&output.out_ciphertext).unwrap();
    }

    if any {
        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(mh.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
    }
    h.finalize()
}

#[cfg(feature = "sapling")]
pub(crate) fn sapling_output_parts<A>(s_out: &OutputDescription<A>) -> SaplingOutputDigestParts {
    SaplingOutputDigestParts {
        cv: s_out.cv().to_bytes(),
        cmu: s_out.cmu().to_bytes(),
        ephemeral_key: s_out.ephemeral_key().0,
        enc_ciphertext: *s_out.enc_ciphertext(),
        out_ciphertext: *s_out.out_ciphertext(),
    }
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid
fn transparent_digests<A: transparent::Authorization>(
    bundle: &transparent::Bundle<A, Zatoshis>,
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
#[cfg(feature = "sapling")]
pub(crate) fn hash_sapling_txid_data<A: sapling::bundle::Authorization>(
    version: TxVersion,
    bundle: &sapling::Bundle<A, ZatBalance>,
) -> Result<Blake2bHash, V7DigestError> {
    hash_sapling_effects_parts(
        version,
        *bundle.value_balance(),
        bundle
            .shielded_spends()
            .iter()
            .map(|spend| SaplingSpendDigestParts {
                cv: spend.cv().to_bytes(),
                nullifier: spend.nullifier().0,
                anchor: Into::<Option<jubjub::Base>>::into(*spend.anchor())
                    .map(|anchor| anchor.to_repr()),
                rk: (*spend.rk()).into(),
            }),
        bundle.shielded_outputs().iter().map(sapling_output_parts),
    )
}

fn hash_sapling_txid_empty() -> Blake2bHash {
    hasher(ZCASH_SAPLING_HASH_PERSONALIZATION).finalize()
}

// ---------------------------------------------------------------------------
// ZIP 248 v7-specific digest functions
// ---------------------------------------------------------------------------

/// Implements [ZIP 248 §T.1](https://zips.z.cash/zip-0248#t-1-header-digest).
///
/// Value pool deltas, including the fee and ZIP 233 amount, are committed
/// separately by [ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest).
///
/// Fields committed: `header || nVersionGroupId || nConsensusBranchId ||
/// lock_time || nExpiryHeight`.
///
/// `nConsensusBranchId` is committed as its raw little-endian wire value, so a
/// transaction on a branch this implementation does not recognize still has a
/// well-defined header digest.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_header(
    version: TxVersion,
    consensus_branch_id: u32,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);
    h.write_u32_le(version.header()).unwrap();
    h.write_u32_le(version.version_group_id()).unwrap();
    // The consensus branch ID is committed here so that the txid is
    // chain-specific, preventing replay across forks.
    h.write_u32_le(consensus_branch_id).unwrap();
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
/// `ValuePoolDeltas::to_wire_entries` is the key piece: it emits known and
/// unknown entries in `bundleType` canonical order so that every implementation
/// produces an identical byte sequence regardless of insertion order. This
/// canonicalization is critical because the digest must be deterministic for
/// txid stability -- two implementations that parse the same wire bytes must
/// always compute the same digest.
///
/// Each entry is serialized as `bundleType || bundleVariant || value` using the
/// wire encoding (`compactSize` for type/variant, then an 8-byte little-endian
/// signed value).
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_value_pool_deltas(vp: &super::zip248::ValuePoolDeltas) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_VP_DELTAS_HASH_PERSONALIZATION);
    for entry in vp.to_wire_entries() {
        entry.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 248 §T.3.1](https://zips.z.cash/zip-0248#t-3-1-coinbase-effects-digest).
///
/// Hashes the coinbase bundle's effecting data in its field encoding: the block
/// height, the block subsidy, the part of that subsidy deposited into the
/// lockbox, the length-prefixed `coinbaseData`, the miner-signal count and
/// entries, and the poll digest when the signals are nonempty. The zero signal
/// count is committed even when there are no signals.
///
/// Unlike the other per-bundle digests there is no empty-bundle sentinel: a
/// transaction that has no coinbase bundle contributes no entry for it to
/// `effects_bundles_digest` at all.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_coinbase_effects(bundle: &super::zip248::CoinbaseBundle) -> Blake2bHash {
    hash_v7_coinbase_fields(&super::bytes::CoinbaseBundleBytes::from(bundle))
}

/// Hashes a coinbase bundle's field encoding into a fresh personalized hasher.
#[cfg(zcash_unstable = "nu8")]
fn hash_v7_coinbase_fields(bundle: &super::bytes::CoinbaseBundleBytes) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_COINBASE_HASH_PERSONALIZATION);
    bundle
        .write(&mut h)
        .expect("writing to a hasher is infallible");
    h.finalize()
}

/// Implements [ZIP 248 §T.3.2](https://zips.z.cash/zip-0248#t-3-2-sapling-effects-digest).
///
/// Produces `spends_digest || outputs_digest`.
///
/// # Correctness
///
/// `valueBalanceSapling` is deliberately NOT included here, even though the
/// analogous [ZIP 244 §T.3](https://zips.z.cash/zip-0244#t-3-sapling-digest)
/// `hash_sapling_txid_data` does include it. In v7, all value-balance
/// fields live in the value-pool-deltas digest
/// ([ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest))
/// so they are committed exactly once rather than being split across per-
/// bundle digests. Including `valueBalanceSapling` here would double-commit
/// and create a consensus mismatch with the spec.
///
/// `anchorSapling` is likewise excluded from the bundle-level digest: it is
/// authorizing data in v7 and is committed by [`hash_v7_sapling_auth`]. Nor
/// does the per-spend non-compact digest hash it, since v7 adopts the v6 form
/// (see [`hash_sapling_spends_parts`]).
#[cfg(all(feature = "sapling", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_sapling_effects<A: sapling::bundle::Authorization>(
    bundle: &sapling::Bundle<A, ZatBalance>,
) -> Blake2bHash {
    hash_sapling_effects_parts(
        TxVersion::V7,
        *bundle.value_balance(),
        bundle
            .shielded_spends()
            .iter()
            .map(|spend| SaplingSpendDigestParts {
                cv: spend.cv().to_bytes(),
                nullifier: spend.nullifier().0,
                anchor: None,
                rk: (*spend.rk()).into(),
            }),
        bundle.shielded_outputs().iter().map(sapling_output_parts),
    )
    .expect("version 7 does not commit to anchors")
}

#[cfg(any(feature = "sapling", zcash_unstable = "nu8"))]
pub(crate) fn hash_sapling_effects_parts(
    version: TxVersion,
    value_balance: ZatBalance,
    spends: impl IntoIterator<Item = SaplingSpendDigestParts>,
    outputs: impl IntoIterator<Item = SaplingOutputDigestParts>,
) -> Result<Blake2bHash, V7DigestError> {
    let mut spends = spends.into_iter().peekable();
    let mut outputs = outputs.into_iter().peekable();
    #[cfg(zcash_unstable = "nu8")]
    let is_v7 = version == TxVersion::V7;
    #[cfg(not(zcash_unstable = "nu8"))]
    let is_v7 = false;
    #[cfg(zcash_unstable = "nu8")]
    let personalization = if is_v7 {
        ZCASH_V7_SAPLING_HASH_PERSONALIZATION
    } else {
        ZCASH_SAPLING_HASH_PERSONALIZATION
    };
    #[cfg(not(zcash_unstable = "nu8"))]
    let personalization = ZCASH_SAPLING_HASH_PERSONALIZATION;
    let mut h = hasher(personalization);
    if spends.peek().is_some() || outputs.peek().is_some() {
        h.write_all(hash_sapling_spends_parts(version, spends)?.as_bytes())
            .unwrap();
        h.write_all(hash_sapling_outputs_parts(outputs).as_bytes())
            .unwrap();
        if !is_v7 {
            h.write_all(&value_balance.to_i64_le_bytes()).unwrap();
        }
    }
    Ok(h.finalize())
}

/// Implements [ZIP 248 §T.3.3](https://zips.z.cash/zip-0248#t-3-3-orchard-effects-digest).
///
/// Produces `actions_compact || actions_memos || actions_noncompact ||
/// flags`, mirroring the structure of
/// [ZIP 244's orchard digest](https://zips.z.cash/zip-0244#t-4-orchard-digest)
/// but without `valueBalanceOrchard`.
///
/// # Correctness
///
/// Neither `valueBalanceOrchard` nor `anchorOrchard` is included -- the same
/// rationale as for sapling (see [`hash_v7_sapling_effects`]). All value
/// balances are committed once in the value-pool-deltas digest
/// ([ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest)),
/// and the anchor is committed by [`hash_v7_orchard_auth`].
///
/// We cannot reuse the orchard crate's `commitment()` / `hash_bundle_txid_data`
/// because those implement the ZIP 244 form which includes `valueBalanceOrchard`
/// and the anchor.
/// Instead we re-derive the per-action sub-hashes inline using the same
/// BLAKE2b personalizations so the sub-digests are byte-identical to
/// ZIP 244 -- only the final composition differs (no value balance appended).
#[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_orchard_effects(
    bundle: &orchard::Bundle<impl orchard::Authorization, ZatBalance>,
) -> Blake2bHash {
    hash_v7_orchard_protocol_effects(bundle, &ORCHARD_POOL_PERSONALIZATIONS)
}

/// Implements [ZIP 248 §T.3.4](https://zips.z.cash/zip-0248#t-3-4-ironwood-effects-digest).
///
/// The Ironwood bundle uses the same effecting data encoding as the Orchard
/// bundle, so its digest is computed exactly as `orchard_effects_digest` is,
/// with each personalization string replaced by its Ironwood counterpart.
/// The strings differ so that the digest of a bundle acting on one pool
/// cannot be reused as the digest of a bundle acting on the other.
#[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_ironwood_effects(
    bundle: &orchard::Bundle<impl orchard::Authorization, ZatBalance>,
) -> Blake2bHash {
    hash_v7_orchard_protocol_effects(bundle, &IRONWOOD_POOL_PERSONALIZATIONS)
}

/// The BLAKE2b personalizations of one Orchard protocol pool's digests.
///
/// The *Orchard pool* and the *Ironwood pool* are acted on by bundle types
/// that share an encoding, and so share a digest shape; only these strings
/// distinguish them.
#[cfg(zcash_unstable = "nu8")]
struct OrchardPoolPersonalizations {
    effects: &'static [u8; 16],
    actions_compact: &'static [u8; 16],
    actions_memos: &'static [u8; 16],
    actions_noncompact: &'static [u8; 16],
    #[cfg(zcash_unstable = "nu8")]
    auth: &'static [u8; 16],
}

#[cfg(zcash_unstable = "nu8")]
const ORCHARD_POOL_PERSONALIZATIONS: OrchardPoolPersonalizations = OrchardPoolPersonalizations {
    effects: ZCASH_V7_ORCHARD_HASH_PERSONALIZATION,
    actions_compact: b"ZTxIdOrcActCHash",
    actions_memos: b"ZTxIdOrcActMHash",
    actions_noncompact: b"ZTxIdOrcActNHash",
    #[cfg(zcash_unstable = "nu8")]
    auth: ZCASH_V7_ORCHARD_AUTH_HASH_PERSONALIZATION,
};

// [ZIP 248 §T.3.4]: the Ironwood child digests keep the v6 personalizations
// for their inputs, which are unchanged from ZIP 229; the effects root uses
// its own string.
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActCH_v6";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActMH_v6";
#[cfg(zcash_unstable = "nu8")]
const ZCASH_V7_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdIrnActNH_v6";

#[cfg(zcash_unstable = "nu8")]
const IRONWOOD_POOL_PERSONALIZATIONS: OrchardPoolPersonalizations = OrchardPoolPersonalizations {
    effects: ZCASH_V7_IRONWOOD_HASH_PERSONALIZATION,
    actions_compact: ZCASH_V7_IRONWOOD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
    actions_memos: ZCASH_V7_IRONWOOD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    actions_noncompact: ZCASH_V7_IRONWOOD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
    #[cfg(zcash_unstable = "nu8")]
    auth: ZCASH_V7_IRONWOOD_AUTH_HASH_PERSONALIZATION,
};

/// The fields of an Orchard-protocol action that the effects digest commits to.
#[cfg(zcash_unstable = "nu8")]
pub(crate) struct OrchardActionDigestParts {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
}

#[cfg(zcash_unstable = "nu8")]
fn hash_orchard_actions_parts(
    actions: impl IntoIterator<Item = OrchardActionDigestParts>,
    flags: u8,
    personalizations: &OrchardPoolPersonalizations,
) -> Blake2bHash {
    let mut h = hasher(personalizations.effects);

    // Per ZIP 248 §T.3.3: the three sub-hashes partition each action's fields
    // into compact (lightweight-client-relevant), memo, and non-compact groups,
    // exactly as ZIP 244 does. The orchard crate's `hash_bundle_txid_data` is
    // the ZIP 244 form and includes valueBalanceOrchard, so we cannot delegate
    // to it and must re-implement the sub-hashes here.
    let mut compact_h = hasher(personalizations.actions_compact);
    let mut memos_h = hasher(personalizations.actions_memos);
    let mut noncompact_h = hasher(personalizations.actions_noncompact);
    let mut any = false;

    for action in actions {
        any = true;
        // Compact fields: these are the minimum needed by light clients
        // to trial-decrypt and identify relevant transactions.
        compact_h.write_all(&action.nullifier).unwrap();
        compact_h.write_all(&action.cmx).unwrap();
        compact_h.write_all(&action.ephemeral_key).unwrap();
        compact_h.write_all(&action.enc_ciphertext[..52]).unwrap();

        // Memo field: the encrypted memo portion of enc_ciphertext,
        // separated so that memo-trimming nodes can omit it.
        memos_h.write_all(&action.enc_ciphertext[52..564]).unwrap();

        // Non-compact fields: value commitment, re-randomized key, the
        // remainder of enc_ciphertext, and the out_ciphertext. These are
        // only needed for full verification.
        noncompact_h.write_all(&action.cv).unwrap();
        noncompact_h.write_all(&action.rk).unwrap();
        noncompact_h
            .write_all(&action.enc_ciphertext[564..])
            .unwrap();
        noncompact_h.write_all(&action.out_ciphertext).unwrap();
    }

    if any {
        h.write_all(compact_h.finalize().as_bytes()).unwrap();
        h.write_all(memos_h.finalize().as_bytes()).unwrap();
        h.write_all(noncompact_h.finalize().as_bytes()).unwrap();
        // The flags byte follows the three sub-digests.
        h.write_all(&[flags]).unwrap();
    }
    h.finalize()
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
fn hash_v7_orchard_protocol_effects(
    bundle: &orchard::Bundle<impl orchard::Authorization, ZatBalance>,
    personalizations: &OrchardPoolPersonalizations,
) -> Blake2bHash {
    hash_orchard_actions_parts(
        bundle.actions().iter().map(typed_orchard_action_parts),
        bundle.flag_byte(),
        personalizations,
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn hash_orchard_txid_data(
    version: TxVersion,
    pool: ValuePool,
    bundle: &orchard::Bundle<impl orchard::Authorization, ZatBalance>,
) -> Result<Blake2bHash, V7DigestError> {
    #[cfg(zcash_unstable = "nu8")]
    if version == TxVersion::V7 {
        return Ok(match pool {
            ValuePool::Orchard => hash_v7_orchard_effects(bundle),
            ValuePool::Ironwood => hash_v7_ironwood_effects(bundle),
        });
    }
    let (_, tx_version) = match pool {
        ValuePool::Orchard => orchard_commitment_domain(version),
        ValuePool::Ironwood if version == TxVersion::V6 => ironwood_v6_domain(),
        ValuePool::Ironwood => return Err(V7DigestError::EffectsVersionMismatch),
    };
    bundle
        .commitment(tx_version)
        .map(|commitment| commitment.0)
        .map_err(|error| match error {
            ::orchard::bundle::CommitmentError::MissingAnchor => {
                V7DigestError::MissingEffectingAnchor
            }
            _ => V7DigestError::EffectsVersionMismatch,
        })
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
fn typed_orchard_action_parts<A>(action: &::orchard::Action<A>) -> OrchardActionDigestParts {
    OrchardActionDigestParts {
        cv: action.cv_net().to_bytes(),
        nullifier: action.nullifier().to_bytes(),
        rk: action.rk().into(),
        cmx: action.cmx().to_bytes(),
        ephemeral_key: action.encrypted_note().epk_bytes,
        enc_ciphertext: action.encrypted_note().enc_ciphertext.0,
        out_ciphertext: action.encrypted_note().out_ciphertext,
    }
}

/// Implements [ZIP 248 §A.1.0](https://zips.z.cash/zip-0248#a-1-0-transparent-auth-digest).
///
/// Hashes, for each transparent input, the `TransparentSighashInfo` field
/// encoding followed by the `scriptSig` field encoding (a `compactSize`-
/// prefixed byte array). When there are no transparent inputs, returns
/// `BLAKE2b-256("ZTxAuthTransHash", [])`.
///
/// The `sighashInfo` prefix (`[0x01, 0x00]`) is
/// prepended to every input's scriptSig so that the auth digest commits to
/// the sighash variant in use. This enables future sighash variants to be
/// introduced without ambiguity -- a verifier can always determine which
/// sighash algorithm was used to produce each signature. Without this
/// prefix, a transaction produced under sighash v1 could be confused with
/// one produced under v0 (if such a version were ever defined).
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_transparent_auth(
    transparent_bundle: Option<&transparent::Bundle<transparent::Authorized, Zatoshis>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
    if let Some(bundle) = transparent_bundle {
        for txin in &bundle.vin {
            h.write_all(super::zip248::V7_SIGHASH_V0_INFO_WIRE)
                .expect("infallible");
            write_script(&mut h, txin.script_sig()).expect("infallible");
        }
    }
    h.finalize()
}

/// Implements [ZIP 248 §A.1.2](https://zips.z.cash/zip-0248#a-1-2-sapling-auth-digest).
///
/// Hashes the anchor (when there are spends), the spend proofs, the spend-auth
/// signatures (each wrapped as a sighash variant 0 `SaplingSignature`), the
/// output proofs, and the binding signature (also as a `SaplingSignature`).
/// When there are no spends and no outputs, returns
/// `BLAKE2b-256("ZTxAuthSapliH_v7", [])`.
///
/// The ordering follows the spec: all spend proofs first, then all spend-auth
/// signatures (each prefixed with `sighashInfo`), then all output proofs,
/// and finally the binding signature (also prefixed with `sighashInfo`).
/// Grouping proofs separately from signatures allows a verifier to batch-
/// verify all Groth16 proofs in one pass without interleaving signature
/// checks -- a significant performance win for nodes processing blocks.
#[cfg(all(feature = "sapling", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_sapling_auth(
    sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_SAPLING_AUTH_HASH_PERSONALIZATION);
    if let Some(bundle) = sapling_bundle {
        // [ZIP 248 §A.1.2a]: anchorSapling, present iff the bundle has spends.
        // All spends share one anchor, so the first spend carries it.
        if let Some(spend) = bundle.shielded_spends().first() {
            h.write_all(spend.anchor().to_repr().as_ref())
                .expect("infallible");
        }
        // [ZIP 248 §A.1.2b]: all spend proofs, concatenated. Proofs are
        // grouped first so batch verification can process them contiguously.
        for spend in bundle.shielded_spends() {
            h.write_all(spend.zkproof()).expect("infallible");
        }
        // [ZIP 248 §A.1.2c]: each spend-auth signature, prefixed with
        // sighashInfo to bind it to sighash variant 0.
        for spend in bundle.shielded_spends() {
            h.write_all(super::zip248::V7_SIGHASH_V0_INFO_WIRE)
                .expect("infallible");
            h.write_all(&<[u8; 64]>::from(*spend.spend_auth_sig()))
                .expect("infallible");
        }
        // [ZIP 248 §A.1.2d]: all output proofs, concatenated.
        for output in bundle.shielded_outputs() {
            h.write_all(output.zkproof()).expect("infallible");
        }
        // [ZIP 248 §A.1.2e]: binding signature, prefixed with sighashInfo.
        // Only present when the bundle has at least one spend or output,
        // because an empty bundle has no value flow to bind.
        if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
            h.write_all(super::zip248::V7_SIGHASH_V0_INFO_WIRE)
                .expect("infallible");
            h.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))
                .expect("infallible");
        }
    }
    h.finalize()
}

/// Implements [ZIP 248 §A.1.3](https://zips.z.cash/zip-0248#a-1-3-orchard-auth-digest).
///
/// Hashes `proofsOrchard` (the aggregated Halo 2 proof bytes), then each
/// per-action spend-auth signature wrapped as a sighash variant 0
/// `OrchardSignature`, then the binding signature (also as an
/// `OrchardSignature`). When there are no actions, returns
/// `BLAKE2b-256("ZTxAuthOrchaH_v7", [])`.
///
/// Unlike sapling where proofs are per-spend/per-output, orchard uses a
/// single aggregated proof for all actions. The ordering is still proof-
/// first so that a verifier can process the proof before checking any
/// signatures.
#[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_orchard_auth(
    orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
    hash_v7_orchard_protocol_auth(orchard_bundle, &ORCHARD_POOL_PERSONALIZATIONS)
}

/// Implements [ZIP 248 §A.1.4](https://zips.z.cash/zip-0248#a-1-4-ironwood-auth-digest).
///
/// Computed over the Ironwood bundle's authorizing data exactly as
/// `orchard_auth_digest` is, including its commitment to the anchor, with the
/// `ZTxAuthIrnwdHash` personalization in place of `ZTxAuthOrchaH_v7`.
#[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_ironwood_auth(
    ironwood_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
    hash_v7_orchard_protocol_auth(ironwood_bundle, &IRONWOOD_POOL_PERSONALIZATIONS)
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
fn hash_v7_orchard_protocol_auth(
    orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    personalizations: &OrchardPoolPersonalizations,
) -> Blake2bHash {
    let mut h = hasher(personalizations.auth);
    if let Some(bundle) = orchard_bundle {
        // [ZIP 248 §A.1.3a]: anchorOrchard.
        h.write_all(&bundle.anchor().to_bytes())
            .expect("infallible");
        // [ZIP 248 §A.1.3b]: the single aggregated proof for all actions.
        h.write_all(bundle.authorization().proof().as_ref())
            .expect("infallible");
        // [ZIP 248 §A.1.3c]: each per-action spend-auth signature, prefixed
        // with sighashInfo to bind it to sighash variant 0.
        for action in bundle.actions().iter() {
            h.write_all(super::zip248::V7_SIGHASH_V0_INFO_WIRE)
                .expect("infallible");
            h.write_all(&<[u8; 64]>::from(action.authorization()))
                .expect("infallible");
        }
        // [ZIP 248 §A.1.3d]: binding signature, also prefixed with sighashInfo.
        h.write_all(super::zip248::V7_SIGHASH_V0_INFO_WIRE)
            .expect("infallible");
        h.write_all(&<[u8; 64]>::from(
            bundle.authorization().binding_signature(),
        ))
        .expect("infallible");
    }
    h.finalize()
}

#[cfg(zcash_unstable = "nu8")]
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
fn hash_v7_tagged_bundle_digests<'a, I>(personalization: &[u8; 16], entries: I) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    let mut h = hasher(personalization);
    for ((bt, bv), digest) in entries {
        // Each tagged entry: bundleType || bundleVariant || 32-byte digest.
        // bundleType and bundleVariant are compactSize-encoded so that small
        // values (all currently defined types) use a single byte each.
        // Infallible: writing to a hasher cannot fail, and both keys are
        // checked against MAX_COMPACT_SIZE when their bundle is inserted or
        // parsed (see `zip248::WireKeyError`).
        CompactSize::write(&mut h, bt as usize).expect("wire key is in range");
        CompactSize::write(&mut h, bv as usize).expect("wire key is in range");
        h.write_all(digest.as_bytes()).expect("infallible");
    }
    h.finalize()
}

/// v7 effects bundles digest per ZIP 248 §T.3 `effects_bundles_digest`.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_effects_bundles<'a, I>(entries: I) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    hash_v7_tagged_bundle_digests(ZCASH_V7_EFFECTS_BUNDLES_HASH_PERSONALIZATION, entries)
}

/// v7 auth bundles digest per ZIP 248 §A.1 `auth_bundles_digest`.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_auth_bundles<'a, I>(entries: I) -> Blake2bHash
where
    I: IntoIterator<Item = ((u64, u64), &'a Blake2bHash)>,
{
    hash_v7_tagged_bundle_digests(ZCASH_V7_AUTH_BUNDLES_HASH_PERSONALIZATION, entries)
}

// ---------------------------------------------------------------------------
// Byte-level v7 digest leaves
//
// These compute the same leaves as the typed functions above, but from the
// byte-layer bundle representations. They share the personalizations and the
// Sapling/Orchard leaf helpers so that the two paths cannot drift.
// ---------------------------------------------------------------------------

/// [ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest)
/// over the byte-layer value pool delta entries.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_value_pool_deltas_bytes(entries: &[ValuePoolDeltaBytes]) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_VP_DELTAS_HASH_PERSONALIZATION);
    for entry in entries {
        entry
            .write(&mut h)
            .expect("writing to a hasher is infallible");
    }
    h.finalize()
}

/// The transparent effect sub-digests of a byte-layer bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn transparent_digests_bytes(
    bundle: &TransparentEffectsBytes,
) -> TransparentDigests<Blake2bHash> {
    let mut prevouts = hasher(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
    let mut sequences = hasher(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
    for input in bundle.inputs() {
        input
            .prevout()
            .write(&mut prevouts)
            .expect("writing to a hasher is infallible");
        sequences
            .write_u32_le(input.sequence())
            .expect("writing to a hasher is infallible");
    }

    let mut outputs = hasher(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    for output in bundle.outputs() {
        output
            .write(&mut outputs)
            .expect("writing to a hasher is infallible");
    }

    TransparentDigests {
        prevouts_digest: prevouts.finalize(),
        sequence_digest: sequences.finalize(),
        outputs_digest: outputs.finalize(),
    }
}

/// [ZIP 248 §T.3.0](https://zips.z.cash/zip-0248#t-3-0-transparent_effects_digest)
/// over a byte-layer transparent bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_transparent_effects_bytes(bundle: &TransparentEffectsBytes) -> Blake2bHash {
    hash_transparent_txid_data(Some(&transparent_digests_bytes(bundle)))
}

/// [ZIP 248 §T.3.1](https://zips.z.cash/zip-0248#t-3-1-coinbase-effects-digest)
/// over a byte-layer coinbase bundle.
///
/// Shares the field encoding with the typed digest: the whole bundle is written
/// through [`CoinbaseBundleBytes::write`](super::bytes::CoinbaseBundleBytes::write),
/// including the miner signals and the conditional poll digest.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_coinbase_effects_bytes(bundle: &CoinbaseBundleBytes) -> Blake2bHash {
    hash_v7_coinbase_fields(bundle)
}

/// [ZIP 248 §T.3.2](https://zips.z.cash/zip-0248#t-3-2-sapling-effects-digest)
/// over a byte-layer Sapling bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_sapling_effects_bytes(bundle: &V7SaplingBundleBytes) -> Blake2bHash {
    hash_sapling_effects_parts(
        TxVersion::V7,
        ZatBalance::zero(),
        bundle.spends().iter().map(|spend| SaplingSpendDigestParts {
            cv: *spend.cv(),
            nullifier: *spend.nullifier(),
            // The anchor is authorizing data in v7 and does not take part
            // in the effects digest.
            anchor: None,
            rk: *spend.rk(),
        }),
        bundle
            .outputs()
            .iter()
            .map(|output| SaplingOutputDigestParts {
                cv: *output.cv(),
                cmu: *output.cmu(),
                ephemeral_key: *output.ephemeral_key(),
                enc_ciphertext: *output.enc_ciphertext(),
                out_ciphertext: *output.out_ciphertext(),
            }),
    )
    .expect("version 7 does not commit to anchors")
}

/// [ZIP 248 §T.3.3](https://zips.z.cash/zip-0248#t-3-3-orchard-effects-digest)
/// over a byte-layer Orchard bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_orchard_effects_bytes(bundle: &V7OrchardBundleBytes) -> Blake2bHash {
    hash_orchard_actions_parts(
        bundle.actions().iter().map(orchard_action_parts),
        bundle.flags(),
        &ORCHARD_POOL_PERSONALIZATIONS,
    )
}

/// [ZIP 248 §T.3.4](https://zips.z.cash/zip-0248#t-3-4-ironwood-effects-digest)
/// over a byte-layer Ironwood bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_ironwood_effects_bytes(bundle: &V7OrchardBundleBytes) -> Blake2bHash {
    hash_orchard_actions_parts(
        bundle.actions().iter().map(orchard_action_parts),
        bundle.flags(),
        &IRONWOOD_POOL_PERSONALIZATIONS,
    )
}

#[cfg(zcash_unstable = "nu8")]
fn orchard_action_parts(action: &OrchardActionBytes) -> OrchardActionDigestParts {
    OrchardActionDigestParts {
        cv: *action.cv(),
        nullifier: *action.nullifier(),
        rk: *action.rk(),
        cmx: *action.cmx(),
        ephemeral_key: *action.ephemeral_key(),
        enc_ciphertext: *action.enc_ciphertext(),
        out_ciphertext: *action.out_ciphertext(),
    }
}

/// [ZIP 248 §A.1.0](https://zips.z.cash/zip-0248#a-1-0-transparent-auth-digest)
/// over a byte-layer transparent bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_transparent_auth_bytes(bundle: &TransparentAuthBytes) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
    for input in bundle.inputs() {
        input
            .sighash_info()
            .write(&mut h)
            .expect("writing to a hasher is infallible");
        input
            .script_sig()
            .write(&mut h)
            .expect("writing to a hasher is infallible");
    }
    h.finalize()
}

/// [ZIP 248 §A.1.2](https://zips.z.cash/zip-0248#a-1-2-sapling-auth-digest)
/// over a byte-layer Sapling bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_sapling_auth_bytes(bundle: &V7SaplingAuthBytes) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_SAPLING_AUTH_HASH_PERSONALIZATION);
    if let Some(anchor) = bundle.anchor() {
        h.write_all(anchor)
            .expect("writing to a hasher is infallible");
    }
    for proof in bundle.spend_proofs() {
        h.write_all(proof)
            .expect("writing to a hasher is infallible");
    }
    for sig in bundle.spend_auth_sigs() {
        sig.sighash_info()
            .write(&mut h)
            .expect("writing to a hasher is infallible");
        h.write_all(sig.signature())
            .expect("writing to a hasher is infallible");
    }
    for proof in bundle.output_proofs() {
        h.write_all(proof)
            .expect("writing to a hasher is infallible");
    }
    if let Some(binding_sig) = bundle.binding_sig() {
        binding_sig
            .sighash_info()
            .write(&mut h)
            .expect("writing to a hasher is infallible");
        h.write_all(binding_sig.signature())
            .expect("writing to a hasher is infallible");
    }
    h.finalize()
}

/// [ZIP 248 §A.1.3](https://zips.z.cash/zip-0248#a-1-3-orchard-auth-digest)
/// over a byte-layer Orchard bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_orchard_auth_bytes(bundle: &V7OrchardAuthBytes) -> Blake2bHash {
    hash_v7_orchard_protocol_auth_bytes(bundle, &ORCHARD_POOL_PERSONALIZATIONS)
}

/// [ZIP 248 §A.1.4](https://zips.z.cash/zip-0248#a-1-4-ironwood-auth-digest)
/// over a byte-layer Ironwood bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_ironwood_auth_bytes(bundle: &V7OrchardAuthBytes) -> Blake2bHash {
    hash_v7_orchard_protocol_auth_bytes(bundle, &IRONWOOD_POOL_PERSONALIZATIONS)
}

#[cfg(zcash_unstable = "nu8")]
fn hash_v7_orchard_protocol_auth_bytes(
    bundle: &V7OrchardAuthBytes,
    personalizations: &OrchardPoolPersonalizations,
) -> Blake2bHash {
    let mut h = hasher(personalizations.auth);
    if let Some(anchor) = bundle.anchor() {
        h.write_all(anchor)
            .expect("writing to a hasher is infallible");
    }
    h.write_all(bundle.proof())
        .expect("writing to a hasher is infallible");
    for sig in bundle.spend_auth_sigs() {
        sig.sighash_info()
            .write(&mut h)
            .expect("writing to a hasher is infallible");
        h.write_all(sig.signature())
            .expect("writing to a hasher is infallible");
    }
    if let Some(binding_sig) = bundle.binding_sig() {
        binding_sig
            .sighash_info()
            .write(&mut h)
            .expect("writing to a hasher is infallible");
        h.write_all(binding_sig.signature())
            .expect("writing to a hasher is infallible");
    }
    h.finalize()
}

// ---------------------------------------------------------------------------

/// A TransactionDigest implementation that commits to all of the effecting
/// data of a transaction to produce a nonmalleable transaction identifier.
///
/// This expects and relies upon the existence of canonical encodings for
/// each effecting component of a transaction.
///
/// This implements transaction ID digests for v5 transactions ([ZIP 244]), v6
/// transactions ([ZIP 229]), and v7 transactions ([ZIP 248]). It cannot be used
/// to compute the transaction ID for v4 or earlier transactions; those used
/// `SHA-256(SHA-256(tx_encoding))` and are malleable.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244#txid-digest
/// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
/// [ZIP 248]: https://zips.z.cash/zip-0248#txid-digest
pub struct TxIdDigester;

impl<A: Authorization> TransactionDigest<A> for TxIdDigester {
    type HeaderDigest = Blake2bHash;
    type TransparentDigest = Option<TransparentDigests<Blake2bHash>>;
    #[cfg(feature = "sapling")]
    type SaplingDigest = Option<Blake2bHash>;
    #[cfg(feature = "orchard")]
    type OrchardDigest = Option<Blake2bHash>;
    #[cfg(feature = "orchard")]
    type IronwoodDigest = Option<Blake2bHash>;
    #[cfg(zcash_unstable = "nu8")]
    type CoinbaseDigest = Option<Blake2bHash>;
    #[cfg(zcash_unstable = "nu8")]
    type ValuePoolDeltasDigest = Option<Blake2bHash>;
    #[cfg(zcash_unstable = "nu8")]
    type UnrecognizedEffectDigest = Vec<(BundleId, Blake2bHash)>;
    #[cfg(zcash_unstable = "nu8")]
    type UnrecognizedAuthDigest = ();

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
        _version: TxVersion,
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth, Zatoshis>>,
    ) -> Self::TransparentDigest {
        transparent_bundle.map(transparent_digests)
    }

    #[cfg(feature = "sapling")]
    fn digest_sapling(
        &self,
        version: TxVersion,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    ) -> Result<Self::SaplingDigest, V7DigestError> {
        sapling_bundle
            .map(|bundle| {
                #[cfg(zcash_unstable = "nu8")]
                if version == TxVersion::V7 {
                    return Ok(hash_v7_sapling_effects(bundle));
                }
                hash_sapling_txid_data(version, bundle)
            })
            .transpose()
    }

    #[cfg(feature = "orchard")]
    fn digest_orchard(
        &self,
        version: TxVersion,
        orchard_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Result<Self::OrchardDigest, V7DigestError> {
        orchard_bundle
            .map(|bundle| hash_orchard_txid_data(version, ValuePool::Orchard, bundle))
            .transpose()
    }

    #[cfg(feature = "orchard")]
    fn digest_ironwood(
        &self,
        version: TxVersion,
        ironwood_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Result<Self::IronwoodDigest, V7DigestError> {
        ironwood_bundle
            .map(|bundle| hash_orchard_txid_data(version, ValuePool::Ironwood, bundle))
            .transpose()
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_coinbase(
        &self,
        version: TxVersion,
        coinbase_bundle: Option<&super::zip248::CoinbaseBundle>,
    ) -> Self::CoinbaseDigest {
        if version == TxVersion::V7 {
            coinbase_bundle.map(hash_v7_coinbase_effects)
        } else {
            None
        }
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_value_pool_deltas(
        &self,
        version: TxVersion,
        value_pool_deltas: &super::zip248::ValuePoolDeltas,
    ) -> Self::ValuePoolDeltasDigest {
        (version == TxVersion::V7).then(|| hash_v7_value_pool_deltas(value_pool_deltas))
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_unrecognized_effects(
        &self,
        bundles: &BTreeMap<BundleType, V7EffectBundleBytes>,
        provider: &impl BundleDigestProvider,
    ) -> Result<Self::UnrecognizedEffectDigest, V7DigestError> {
        let mut digests = Vec::with_capacity(bundles.len());
        for bundle in bundles.values() {
            digests.push((bundle.digest_key(), bundle.effects_digest(provider)?));
        }
        Ok(digests)
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_unrecognized_auth(
        &self,
        _bundles: &BTreeMap<BundleType, V7AuthBundleBytes>,
        _provider: &impl BundleDigestProvider,
    ) -> Result<Self::UnrecognizedAuthDigest, V7DigestError> {
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digests: Self::TransparentDigest,
        #[cfg(feature = "sapling")] sapling_digest: Self::SaplingDigest,
        #[cfg(feature = "orchard")] orchard_digest: Self::OrchardDigest,
        #[cfg(feature = "orchard")] ironwood_digest: Self::IronwoodDigest,
        #[cfg(zcash_unstable = "nu8")] coinbase_digest: Self::CoinbaseDigest,
        #[cfg(zcash_unstable = "nu8")] value_pool_deltas_digest: Self::ValuePoolDeltasDigest,
        #[cfg(zcash_unstable = "nu8")] unrecognized_effect_digest: Self::UnrecognizedEffectDigest,
        #[cfg(zcash_unstable = "nu8")] _unrecognized_auth_digest: Self::UnrecognizedAuthDigest,
    ) -> Self::Digest {
        Zip244Digests {
            header_digest,
            transparent_digests,
            #[cfg(feature = "sapling")]
            sapling_digest,
            #[cfg(not(feature = "sapling"))]
            sapling_digest: None,
            #[cfg(feature = "orchard")]
            orchard_digest,
            #[cfg(not(feature = "orchard"))]
            orchard_digest: None,
            #[cfg(feature = "orchard")]
            ironwood_digest,
            #[cfg(not(feature = "orchard"))]
            ironwood_digest: None,
            #[cfg(zcash_unstable = "nu8")]
            coinbase_digest,
            #[cfg(zcash_unstable = "nu8")]
            value_pool_deltas_digest,
            #[cfg(zcash_unstable = "nu8")]
            unknown_effect_digests: unrecognized_effect_digest,
        }
    }
}

#[cfg(not(feature = "orchard"))]
fn orchard_empty_digest(txversion: TxVersion, ironwood: bool, authorizing: bool) -> Blake2bHash {
    let personal = match (txversion, ironwood, authorizing) {
        (TxVersion::V5, false, false) => b"ZTxIdOrchardHash",
        (TxVersion::V5, false, true) => b"ZTxAuthOrchaHash",
        (TxVersion::V5, true, _) => unreachable!("Ironwood does not exist in v5"),
        (_, false, false) => b"ZTxIdOrchardH_v6",
        (_, false, true) => b"ZTxAuthOrchaH_v6",
        (_, true, false) => b"ZTxIdIronwd_H_v6",
        (_, true, true) => b"ZTxAuthIrnwdH_v6",
    };
    hasher(personal).finalize()
}

pub(crate) fn to_hash(
    _txversion: TxVersion,
    consensus_branch_id: BranchId,
    header_digest: Blake2bHash,
    transparent_digest: Blake2bHash,
    sapling_digest: Option<Blake2bHash>,
    orchard_digest: Option<Blake2bHash>,
) -> Blake2bHash {
    let personal = tx_hash_personalization(consensus_branch_id);

    let mut h = hasher(&personal);
    h.write_all(header_digest.as_bytes()).unwrap();
    h.write_all(transparent_digest.as_bytes()).unwrap();
    h.write_all(
        sapling_digest
            .unwrap_or_else(hash_sapling_txid_empty)
            .as_bytes(),
    )
    .unwrap();
    #[cfg(feature = "orchard")]
    let empty_orchard_digest = {
        let (value_pool, tx_version) = orchard_commitment_domain(_txversion);
        orchard::commitments::hash_bundle_txid_empty(value_pool, tx_version)
            .expect("empty Orchard bundle txid commitment is valid for its tx format")
    };
    #[cfg(not(feature = "orchard"))]
    let empty_orchard_digest = orchard_empty_digest(_txversion, false, false);
    h.write_all(orchard_digest.unwrap_or(empty_orchard_digest).as_bytes())
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
    #[cfg(feature = "orchard")]
    let (empty_orchard_digest, empty_ironwood_digest) = {
        let (orchard_pool, orchard_version) = orchard_commitment_domain(TxVersion::V6);
        let (ironwood_pool, ironwood_version) = ironwood_v6_domain();
        (
            orchard::commitments::hash_bundle_txid_empty(orchard_pool, orchard_version)
                .expect("empty Orchard bundle txid commitment is valid for its tx format"),
            orchard::commitments::hash_bundle_txid_empty(ironwood_pool, ironwood_version)
                .expect("empty Ironwood bundle txid commitment is valid"),
        )
    };
    #[cfg(not(feature = "orchard"))]
    let (empty_orchard_digest, empty_ironwood_digest) = (
        orchard_empty_digest(TxVersion::V6, false, false),
        orchard_empty_digest(TxVersion::V6, true, false),
    );
    h.write_all(orchard_digest.unwrap_or(empty_orchard_digest).as_bytes())
        .unwrap();
    h.write_all(ironwood_digest.unwrap_or(empty_ironwood_digest).as_bytes())
        .unwrap();

    h.finalize()
}

/// Combines transaction component digests into a transaction ID.
///
/// Returns `None` if `txversion` is incompatible with `digests`.
///
/// V6 and later transactions include the Ironwood bundle digest as a separate
/// Orchard-shaped digest using Ironwood personalization. If any shielded bundle digest is
/// absent, this substitutes the protocol-defined empty bundle digest for that pool.
pub fn to_txid(
    txversion: TxVersion,
    consensus_branch_id: BranchId,
    digests: &Zip244Digests<Blake2bHash>,
) -> Option<TxId> {
    let txid_digest = match txversion {
        // These versions cannot produce a txid just from digests, because they use
        // SHA-256d over the entire tx encoding which is unavailable here.
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => return None,
        TxVersion::V5 => to_hash(
            txversion,
            consensus_branch_id,
            digests.header_digest,
            hash_transparent_txid_data(digests.transparent_digests.as_ref()),
            digests.sapling_digest,
            digests.orchard_digest,
        ),
        // v6 (ZIP 229) commits to the Ironwood bundle as a fourth
        // shielded digest alongside transparent, Sapling and Orchard.
        TxVersion::V6 => to_hash_v6(
            consensus_branch_id,
            digests.header_digest,
            hash_transparent_txid_data(digests.transparent_digests.as_ref()),
            digests.sapling_digest,
            digests.orchard_digest,
            digests.ironwood_digest,
        ),
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => to_hash_v7(consensus_branch_id.into(), digests)?,
    };

    Some(TxId::from_bytes(
        <[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap(),
    ))
}

/// Combines a version 7 transaction's digests into its transaction ID.
///
/// This is the domain-free subset of [`to_txid`]: it needs no shielded
/// protocol crate because the v7 digest tree is computed entirely from the
/// byte layer's digests.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn to_txid_v7(consensus_branch_id: u32, digests: &Zip244Digests<Blake2bHash>) -> TxId {
    let txid_digest = to_hash_v7(consensus_branch_id, digests)
        .expect("byte-layer v7 digests always include the value pool deltas digest");
    TxId::from_bytes(<[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap())
}

/// Implements [ZIP 248 §txid_digest](https://zips.z.cash/zip-0248#txid-digest).
///
/// Computes the v7 transaction ID as:
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
/// same scheme as ZIP 244 so that txids are fork-specific. `consensus_branch_id`
/// is the raw `nConsensusBranchId` value, so a future branch's transaction can
/// be identified without naming the branch.
#[cfg(zcash_unstable = "nu8")]
fn to_hash_v7(
    consensus_branch_id: u32,
    digests: &Zip244Digests<Blake2bHash>,
) -> Option<Blake2bHash> {
    let personal = tx_hash_personalization_raw(consensus_branch_id);

    // A v7 digest tree must include the value pool deltas digest. Only a tree
    // built for a v7 transaction (for example by `TxIdDigester`) has one, so a
    // tree assembled by hand without it cannot produce a v7 txid.
    let vp_deltas_digest = digests.value_pool_deltas_digest?;

    // The transparent digest is computed from its sub-digests (prevouts,
    // sequences, outputs) and only included in the tagged entries when the
    // transparent bundle is actually present.
    let transparent_digest = hash_transparent_txid_data(digests.transparent_digests.as_ref());

    // Merge known and unknown bundle digests in strictly increasing
    // (bundleType, bundleVariant) order, then hash them as tagged entries.
    let effects_bundles_digest = hash_v7_effects_bundles(v7_bundle_digest_entries(
        digests
            .transparent_digests
            .is_some()
            .then_some(&transparent_digest),
        digests.coinbase_digest.as_ref(),
        digests.sapling_digest.as_ref(),
        digests.orchard_digest.as_ref(),
        digests.ironwood_digest.as_ref(),
        &digests.unknown_effect_digests,
    ));

    // Final txid preimage: header || vp_deltas || effects_bundles.
    let mut h = hasher(&personal);
    h.write_all(digests.header_digest.as_bytes()).unwrap();
    h.write_all(vp_deltas_digest.as_bytes()).unwrap();
    h.write_all(effects_bundles_digest.as_bytes()).unwrap();
    Some(h.finalize())
}

/// Builds `((bundleType, bundleVariant), &Blake2bHash)` entries for a v7
/// per-bundle digest, merging typed bundle digests with retained byte-layer
/// bundle digests in strictly increasing `(bundleType, bundleVariant)` order.
///
/// Retained entries include opaque bundles and known bundles whose protocol
/// feature is disabled. Each bundle must occur in exactly one typed slot or
/// retained entry.
///
/// Absent bundles (e.g. a transaction with no transparent component) are
/// simply omitted -- they do not contribute a zero-digest entry.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn v7_bundle_digest_entries<'a>(
    transparent_digest: Option<&'a Blake2bHash>,
    coinbase_digest: Option<&'a Blake2bHash>,
    sapling_digest: Option<&'a Blake2bHash>,
    orchard_digest: Option<&'a Blake2bHash>,
    ironwood_digest: Option<&'a Blake2bHash>,
    retained: &'a [(BundleId, Blake2bHash)],
) -> Vec<((u64, u64), &'a Blake2bHash)> {
    let mut entries = Vec::new();
    // Known bundles, pushed in the natural order of their wire keys.
    if let Some(d) = transparent_digest {
        entries.push((
            BundleId::new(BundleType::TRANSPARENT, BundleVariant::DEFAULT).wire_key(),
            d,
        ));
    }
    if let Some(d) = coinbase_digest {
        entries.push((
            BundleId::new(BundleType::COINBASE, BundleVariant::DEFAULT).wire_key(),
            d,
        ));
    }
    if let Some(d) = sapling_digest {
        entries.push((
            BundleId::new(BundleType::SAPLING, BundleVariant::DEFAULT).wire_key(),
            d,
        ));
    }
    if let Some(d) = orchard_digest {
        entries.push((
            BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT).wire_key(),
            d,
        ));
    }
    if let Some(d) = ironwood_digest {
        entries.push((
            BundleId::new(BundleType::IRONWOOD, BundleVariant::DEFAULT).wire_key(),
            d,
        ));
    }
    // Retained entries carry their exact wire key, including non-default variants.
    for (key, digest) in retained {
        entries.push((key.wire_key(), digest));
    }
    // Sort to guarantee the strictly-increasing order required by ZIP 248.
    entries.sort_by_key(|(key, _)| *key);
    entries
}

/// Digester which constructs a digest of only the witness data.
/// This does not internally commit to the txid, so if that is
/// desired it should be done using the result of this digest
/// function.
///
/// For version 7 transactions this produces the [ZIP 248] authorizing-data
/// commitment ([§ A.1]), including each bundle's `sighashInfo` and the
/// bundle-tagged auth map. For earlier versions it produces the [ZIP 244] or
/// [ZIP 229] witness commitment.
///
/// With NU8 enabled, the transparent callback carries both digest forms because
/// it does not receive the transaction version. Shielded callbacks compute only
/// the version's digest; their second tuple element is present only for a
/// present v7 bundle.
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
/// [ZIP 244]: https://zips.z.cash/zip-0244
/// [ZIP 248]: https://zips.z.cash/zip-0248
/// [§ A.1]: https://zips.z.cash/zip-0248#a-1-auth_bundles_digest
pub struct BlockTxCommitmentDigester;

/// The pre-v7 transparent witness digest: every input's `scriptSig`.
fn transparent_witness_digest(
    transparent_bundle: Option<&transparent::Bundle<transparent::Authorized, Zatoshis>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
    if let Some(bundle) = transparent_bundle {
        for txin in &bundle.vin {
            write_script(&mut h, txin.script_sig()).unwrap();
        }
    }
    h.finalize()
}

/// The pre-v7 Sapling witness digest: proofs, spend auth sigs, and binding sig,
/// followed by the anchor from v6 onward.
#[cfg(feature = "sapling")]
fn sapling_witness_digest(
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

/// The pre-v7 Orchard witness digest.
#[cfg(feature = "orchard")]
fn orchard_witness_digest(
    version: TxVersion,
    orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
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

/// The pre-v7 Ironwood witness digest.
#[cfg(feature = "orchard")]
fn ironwood_witness_digest(
    ironwood_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
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

impl TransactionDigest<Authorized> for BlockTxCommitmentDigester {
    /// We use the header digest to pass the transaction version and consensus
    /// branch ID into where they need to be used for personalization string
    /// construction.
    type HeaderDigest = (TxVersion, BranchId);
    #[cfg(zcash_unstable = "nu8")]
    type TransparentDigest = (Blake2bHash, Option<Blake2bHash>);
    #[cfg(not(zcash_unstable = "nu8"))]
    type TransparentDigest = Blake2bHash;
    #[cfg(all(feature = "sapling", zcash_unstable = "nu8"))]
    type SaplingDigest = (Blake2bHash, Option<Blake2bHash>);
    #[cfg(all(feature = "sapling", not(zcash_unstable = "nu8")))]
    type SaplingDigest = Blake2bHash;
    #[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
    type OrchardDigest = (Blake2bHash, Option<Blake2bHash>);
    #[cfg(all(feature = "orchard", not(zcash_unstable = "nu8")))]
    type OrchardDigest = Blake2bHash;
    #[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
    type IronwoodDigest = (Blake2bHash, Option<Blake2bHash>);
    #[cfg(all(feature = "orchard", not(zcash_unstable = "nu8")))]
    type IronwoodDigest = Blake2bHash;

    type Digest = Blake2bHash;
    /// The coinbase bundle has no authorizing data, so it contributes no entry.
    #[cfg(zcash_unstable = "nu8")]
    type CoinbaseDigest = ();
    #[cfg(zcash_unstable = "nu8")]
    type ValuePoolDeltasDigest = ();
    #[cfg(zcash_unstable = "nu8")]
    type UnrecognizedEffectDigest = ();
    #[cfg(zcash_unstable = "nu8")]
    type UnrecognizedAuthDigest = Vec<(BundleId, Blake2bHash)>;

    fn digest_header(
        &self,
        _version: TxVersion,
        consensus_branch_id: BranchId,
        _lock_time: u32,
        _expiry_height: BlockHeight,
    ) -> Self::HeaderDigest {
        (_version, consensus_branch_id)
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_transparent(
        &self,
        version: TxVersion,
        transparent_bundle: Option<&transparent::Bundle<transparent::Authorized, Zatoshis>>,
    ) -> Self::TransparentDigest {
        // Only inputs are authorized, so an outputs-only bundle has no entry.
        if version == TxVersion::V7 {
            let digest = hash_v7_transparent_auth(transparent_bundle);
            (
                digest,
                transparent_bundle
                    .filter(|b| !b.vin.is_empty())
                    .map(|_| digest),
            )
        } else {
            (transparent_witness_digest(transparent_bundle), None)
        }
    }

    #[cfg(not(zcash_unstable = "nu8"))]
    fn digest_transparent(
        &self,
        _version: TxVersion,
        transparent_bundle: Option<&transparent::Bundle<transparent::Authorized, Zatoshis>>,
    ) -> Self::TransparentDigest {
        transparent_witness_digest(transparent_bundle)
    }

    #[cfg(all(feature = "sapling", zcash_unstable = "nu8"))]
    fn digest_sapling(
        &self,
        version: TxVersion,
        sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
    ) -> Result<Self::SaplingDigest, V7DigestError> {
        if version == TxVersion::V7 {
            let digest = hash_v7_sapling_auth(sapling_bundle);
            Ok((digest, sapling_bundle.map(|_| digest)))
        } else {
            Ok((sapling_witness_digest(version, sapling_bundle), None))
        }
    }

    #[cfg(all(feature = "sapling", not(zcash_unstable = "nu8")))]
    fn digest_sapling(
        &self,
        version: TxVersion,
        sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
    ) -> Result<Self::SaplingDigest, V7DigestError> {
        Ok(sapling_witness_digest(version, sapling_bundle))
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
    fn digest_orchard(
        &self,
        version: TxVersion,
        orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    ) -> Result<Self::OrchardDigest, V7DigestError> {
        if version == TxVersion::V7 {
            let digest = hash_v7_orchard_auth(orchard_bundle);
            Ok((digest, orchard_bundle.map(|_| digest)))
        } else {
            Ok((orchard_witness_digest(version, orchard_bundle), None))
        }
    }

    #[cfg(all(feature = "orchard", not(zcash_unstable = "nu8")))]
    fn digest_orchard(
        &self,
        version: TxVersion,
        orchard_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    ) -> Result<Self::OrchardDigest, V7DigestError> {
        Ok(orchard_witness_digest(version, orchard_bundle))
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
    fn digest_ironwood(
        &self,
        version: TxVersion,
        ironwood_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    ) -> Result<Self::IronwoodDigest, V7DigestError> {
        if version == TxVersion::V7 {
            let digest = hash_v7_ironwood_auth(ironwood_bundle);
            Ok((digest, ironwood_bundle.map(|_| digest)))
        } else {
            Ok((ironwood_witness_digest(ironwood_bundle), None))
        }
    }

    #[cfg(all(feature = "orchard", not(zcash_unstable = "nu8")))]
    fn digest_ironwood(
        &self,
        _version: TxVersion,
        ironwood_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
    ) -> Result<Self::IronwoodDigest, V7DigestError> {
        Ok(ironwood_witness_digest(ironwood_bundle))
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_coinbase(
        &self,
        _version: TxVersion,
        _coinbase_bundle: Option<&super::zip248::CoinbaseBundle>,
    ) -> Self::CoinbaseDigest {
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_value_pool_deltas(
        &self,
        _version: TxVersion,
        _value_pool_deltas: &super::zip248::ValuePoolDeltas,
    ) -> Self::ValuePoolDeltasDigest {
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_unrecognized_effects(
        &self,
        _bundles: &BTreeMap<BundleType, V7EffectBundleBytes>,
        _provider: &impl BundleDigestProvider,
    ) -> Result<Self::UnrecognizedEffectDigest, V7DigestError> {
        Ok(())
    }

    #[cfg(zcash_unstable = "nu8")]
    fn digest_unrecognized_auth(
        &self,
        bundles: &BTreeMap<BundleType, V7AuthBundleBytes>,
        provider: &impl BundleDigestProvider,
    ) -> Result<Self::UnrecognizedAuthDigest, V7DigestError> {
        let mut digests = Vec::with_capacity(bundles.len());
        for bundle in bundles.values() {
            digests.push((bundle.digest_key(), bundle.auth_digest(provider)?));
        }
        Ok(digests)
    }

    #[cfg(not(zcash_unstable = "nu8"))]
    #[allow(clippy::too_many_arguments)]
    fn combine(
        &self,
        tx_context: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        #[cfg(feature = "sapling")] sapling_digest: Self::SaplingDigest,
        #[cfg(feature = "orchard")] orchard_digest: Self::OrchardDigest,
        #[cfg(feature = "orchard")] ironwood_digest: Self::IronwoodDigest,
    ) -> Self::Digest {
        let (_txversion, consensus_branch_id) = tx_context;
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32_le(consensus_branch_id.into())
            .unwrap();

        let mut h = hasher(&personal);
        h.write_all(transparent_digest.as_bytes()).unwrap();
        #[cfg(feature = "sapling")]
        h.write_all(sapling_digest.as_bytes()).unwrap();
        #[cfg(not(feature = "sapling"))]
        h.write_all(
            hasher(sapling_auth_personalization(_txversion))
                .finalize()
                .as_bytes(),
        )
        .unwrap();
        #[cfg(feature = "orchard")]
        h.write_all(orchard_digest.as_bytes()).unwrap();
        #[cfg(not(feature = "orchard"))]
        h.write_all(orchard_empty_digest(_txversion, false, true).as_bytes())
            .unwrap();

        if _txversion.has_ironwood() {
            #[cfg(feature = "orchard")]
            h.write_all(ironwood_digest.as_bytes()).unwrap();
            #[cfg(not(feature = "orchard"))]
            h.write_all(orchard_empty_digest(_txversion, true, true).as_bytes())
                .unwrap();
        }

        h.finalize()
    }

    #[cfg(zcash_unstable = "nu8")]
    #[allow(clippy::too_many_arguments)]
    fn combine(
        &self,
        tx_context: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        #[cfg(feature = "sapling")] sapling_digest: Self::SaplingDigest,
        #[cfg(feature = "orchard")] orchard_digest: Self::OrchardDigest,
        #[cfg(feature = "orchard")] ironwood_digest: Self::IronwoodDigest,
        #[cfg(zcash_unstable = "nu8")] _coinbase_digest: Self::CoinbaseDigest,
        #[cfg(zcash_unstable = "nu8")] _value_pool_deltas_digest: Self::ValuePoolDeltasDigest,
        #[cfg(zcash_unstable = "nu8")] _unrecognized_effect_digest: Self::UnrecognizedEffectDigest,
        #[cfg(zcash_unstable = "nu8")] unrecognized_auth_digest: Self::UnrecognizedAuthDigest,
    ) -> Self::Digest {
        let (txversion, consensus_branch_id) = tx_context;

        if txversion == TxVersion::V7 {
            // ZIP 248 §A.1: tagged bundle entries under the auth-bundles
            // personalization, then the branch-personalized outer hash.
            let (_, transparent_v7) = transparent_digest;
            #[cfg(feature = "sapling")]
            let (_, sapling_v7) = sapling_digest;
            #[cfg(not(feature = "sapling"))]
            let sapling_v7: Option<Blake2bHash> = None;
            #[cfg(feature = "orchard")]
            let (_, orchard_v7) = orchard_digest;
            #[cfg(not(feature = "orchard"))]
            let orchard_v7: Option<Blake2bHash> = None;
            #[cfg(feature = "orchard")]
            let (_, ironwood_v7) = ironwood_digest;
            #[cfg(not(feature = "orchard"))]
            let ironwood_v7: Option<Blake2bHash> = None;

            let auth_bundles_digest = hash_v7_auth_bundles(v7_bundle_digest_entries(
                transparent_v7.as_ref(),
                // The coinbase bundle has no authorizing data.
                None,
                sapling_v7.as_ref(),
                orchard_v7.as_ref(),
                ironwood_v7.as_ref(),
                &unrecognized_auth_digest,
            ));

            let mut personal = [0; 16];
            personal[..12].copy_from_slice(ZCASH_AUTH_PERSONALIZATION_PREFIX);
            (&mut personal[12..])
                .write_u32_le(consensus_branch_id.into())
                .unwrap();

            let mut h = hasher(&personal);
            h.write_all(auth_bundles_digest.as_bytes()).unwrap();
            return h.finalize();
        }

        // Pre-v7: concatenate the per-protocol witness digests.
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32_le(consensus_branch_id.into())
            .unwrap();

        let mut h = hasher(&personal);
        h.write_all(transparent_digest.0.as_bytes()).unwrap();
        #[cfg(feature = "sapling")]
        h.write_all(sapling_digest.0.as_bytes()).unwrap();
        #[cfg(not(feature = "sapling"))]
        h.write_all(
            hasher(sapling_auth_personalization(txversion))
                .finalize()
                .as_bytes(),
        )
        .unwrap();
        #[cfg(feature = "orchard")]
        h.write_all(orchard_digest.0.as_bytes()).unwrap();
        #[cfg(not(feature = "orchard"))]
        h.write_all(orchard_empty_digest(txversion, false, true).as_bytes())
            .unwrap();

        if txversion.has_ironwood() {
            #[cfg(feature = "orchard")]
            h.write_all(ironwood_digest.0.as_bytes()).unwrap();
            #[cfg(not(feature = "orchard"))]
            h.write_all(orchard_empty_digest(txversion, true, true).as_bytes())
                .unwrap();
        }

        h.finalize()
    }
}

#[cfg(all(test, feature = "sapling", feature = "orchard"))]
mod tests {
    use super::{
        ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
        ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
        sapling_spends_noncompact_personalization,
    };
    use crate::transaction::TxVersion;

    /// [ZIP 248 §T.3.2a.ii] hashes `cv || rk` per spend under ZIP 229's
    /// `ZTxIdSSpendNH_v6` personalization. Only v5 and earlier hash
    /// `cv || anchor || rk`, under ZIP 244's `ZTxIdSSpendNHash`.
    ///
    /// Selecting the wrong personalization for v7 produces a transaction
    /// identifier that no other implementation agrees with, and nothing else in
    /// the test suite can see it, so assert the mapping directly.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    /// [ZIP 244 §T.3a.ii]: https://zips.z.cash/zip-0244#t-3a-ii-sapling-spends-noncompact-digest
    /// [ZIP 248 §T.3.2a.ii]: https://zips.z.cash/zip-0248#t-3-2a-ii-sapling-spends-noncompact-digest
    #[test]
    fn sapling_spends_personalization_follows_the_transaction_version() {
        assert_eq!(
            sapling_spends_noncompact_personalization(TxVersion::V5),
            ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
        );
        assert_eq!(
            sapling_spends_noncompact_personalization(TxVersion::V6),
            ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
        );
        #[cfg(zcash_unstable = "nu8")]
        assert_eq!(
            sapling_spends_noncompact_personalization(TxVersion::V7),
            ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
            "v7 hashes cv || rk, so it uses ZIP 229's Sapling spends personalization",
        );
    }
}

#[cfg(all(test, zcash_unstable = "nu8"))]
mod digest_path_tests {
    use alloc::{vec, vec::Vec};

    use ::transparent::{
        address::Script,
        bundle::{Bundle, OutPoint, TxIn},
    };
    use zcash_protocol::consensus::BranchId;

    use super::{
        BlockTxCommitmentDigester, hash_transparent_txid_data, hash_v7_transparent_auth,
        hash_v7_transparent_effects_bytes, transparent_digests_bytes, transparent_witness_digest,
    };
    #[cfg(not(feature = "orchard"))]
    use crate::transaction::bytes::{
        OrchardActionBytes, OrchardSignatureBytes, V7OrchardAuthBytes, V7OrchardBundleBytes,
    };
    use crate::transaction::{
        Authorized, TransactionDigest, TxVersion,
        bytes::{
            TransactionBodyBytes, TransactionBytes, TransparentEffectsBytes,
            TransparentOutputBytes, TransparentOutputValueBytes, TransparentScriptBytes,
            V7EffectBundleBytes, V7TransactionBodyBytes,
        },
        zip248::SuppliedBundleDigests,
    };

    #[cfg(not(feature = "sapling"))]
    use crate::transaction::{
        bytes::{
            SaplingSignatureBytes, SaplingSpendBytes, V7SaplingAuthBytes, V7SaplingBundleBytes,
        },
        components::GROTH_PROOF_SIZE,
    };
    #[cfg(any(not(feature = "sapling"), not(feature = "orchard")))]
    use {
        super::TxIdDigester,
        crate::transaction::bytes::{SighashInfoBytes, V7AuthBundleBytes},
        alloc::collections::BTreeMap,
    };

    #[cfg(all(feature = "sapling", feature = "orchard"))]
    use crate::transaction::{Transaction, tests::data::zip_0244};

    #[test]
    fn transparent_auth_digest_selects_only_the_transaction_version() {
        let bundle = Bundle {
            vin: vec![TxIn::from_parts(
                OutPoint::new([1; 32], 0),
                Script::default(),
                u32::MAX,
            )],
            vout: vec![],
            authorization: ::transparent::bundle::Authorized,
        };
        for version in [TxVersion::V5, TxVersion::V6] {
            let (legacy, v7) = BlockTxCommitmentDigester.digest_transparent(version, Some(&bundle));
            assert_eq!(legacy, transparent_witness_digest(Some(&bundle)));
            assert!(v7.is_none());
        }
        let (digest, v7) =
            BlockTxCommitmentDigester.digest_transparent(TxVersion::V7, Some(&bundle));
        assert_eq!(digest, hash_v7_transparent_auth(Some(&bundle)));
        assert_eq!(v7, Some(digest));
        let (_, absent) = BlockTxCommitmentDigester.digest_transparent(TxVersion::V7, None);
        assert!(absent.is_none());
    }
    #[test]
    fn v7_transparent_effects_use_the_same_structural_digest() {
        let effects = TransparentEffectsBytes::from_parts(Vec::new(), Vec::new());
        assert_eq!(
            hash_v7_transparent_effects_bytes(&effects),
            hash_transparent_txid_data(Some(&transparent_digests_bytes(&effects))),
        );
    }

    #[test]
    fn v7_public_transparent_digest_paths_agree() {
        /// A minimal output amount; the digest parity does not depend on its value.
        const OUTPUT_VALUE: i64 = 1;
        let effects = TransparentEffectsBytes::from_parts(
            Vec::new(),
            vec![TransparentOutputBytes::from_parts(
                TransparentOutputValueBytes::from_i64(OUTPUT_VALUE),
                TransparentScriptBytes::default(),
            )],
        );
        let provider = SuppliedBundleDigests::new();
        let expected = hash_v7_transparent_effects_bytes(&effects);
        let body = V7TransactionBodyBytes::from_parts(
            Vec::new(),
            vec![V7EffectBundleBytes::Transparent(effects)],
            Vec::new(),
        )
        .unwrap();
        let expected_bundles = body.effects_bundles_digest(&provider).unwrap();
        let bytes = TransactionBytes::from_parts(
            TxVersion::V7,
            Some(BranchId::Nu8.into()),
            0,
            0.into(),
            TransactionBodyBytes::V7(body),
        )
        .unwrap();
        let digests = bytes.v7_txid_digests(&provider).unwrap();
        let transparent = hash_transparent_txid_data(digests.transparent_digests.as_ref());
        assert_eq!(transparent, expected);
        let bundles = super::hash_v7_effects_bundles(super::v7_bundle_digest_entries(
            Some(&transparent),
            None,
            None,
            None,
            None,
            &[],
        ));
        assert_eq!(bundles, expected_bundles);
        assert_eq!(
            bytes.v7_txid(&provider).unwrap(),
            super::to_txid_v7(BranchId::Nu8.into(), &digests),
        );
    }

    #[cfg(any(not(feature = "sapling"), not(feature = "orchard")))]
    fn assert_retained_known_bundle_digests(body: V7TransactionBodyBytes) {
        let effects: BTreeMap<_, _> = body
            .effect_bundles()
            .iter()
            .map(|bundle| (bundle.bundle_type(), bundle.clone()))
            .collect();
        let auth: BTreeMap<_, _> = body
            .auth_bundles()
            .iter()
            .map(|bundle| (bundle.bundle_type(), bundle.clone()))
            .collect();
        let effect_digests =
            <TxIdDigester as TransactionDigest<Authorized>>::digest_unrecognized_effects(
                &TxIdDigester,
                &effects,
                &(),
            )
            .unwrap();
        let auth_digests = BlockTxCommitmentDigester
            .digest_unrecognized_auth(&auth, &())
            .unwrap();
        assert_eq!(effect_digests.len(), effects.len());
        assert_eq!(auth_digests.len(), auth.len());
        for (bundle, (key, digest)) in effects.values().zip(&effect_digests) {
            assert_eq!(*key, bundle.digest_key());
            assert_eq!(*digest, bundle.effects_digest(&()).unwrap());
        }
        for (bundle, (key, digest)) in auth.values().zip(&auth_digests) {
            assert_eq!(*key, bundle.digest_key());
            assert_eq!(*digest, bundle.auth_digest(&()).unwrap());
        }

        let effect_entries =
            super::v7_bundle_digest_entries(None, None, None, None, None, &effect_digests);
        let auth_entries =
            super::v7_bundle_digest_entries(None, None, None, None, None, &auth_digests);
        assert_eq!(
            super::hash_v7_effects_bundles(effect_entries.clone()),
            body.effects_bundles_digest(&()).unwrap(),
        );
        assert_eq!(
            super::hash_v7_auth_bundles(auth_entries),
            body.auth_bundles_digest(&()).unwrap(),
        );

        let transparent = hash_transparent_txid_data(None);
        let merged = super::v7_bundle_digest_entries(
            Some(&transparent),
            None,
            None,
            None,
            None,
            &effect_digests,
        );
        assert_eq!(merged.len(), effect_digests.len() + 1);
        assert_eq!(&merged[1..], effect_entries.as_slice());
        assert_eq!(
            merged[0],
            (
                super::BundleId::new(
                    super::BundleType::TRANSPARENT,
                    super::BundleVariant::DEFAULT,
                )
                .wire_key(),
                &transparent,
            ),
        );
    }

    #[cfg(not(feature = "sapling"))]
    #[test]
    fn retained_sapling_bytes_digest_without_sapling_feature() {
        let effects = V7SaplingBundleBytes::from_parts(
            vec![SaplingSpendBytes::from_parts([0; 32], [0; 32], [0; 32])],
            Vec::new(),
        );
        let signature = SaplingSignatureBytes::from_parts(SighashInfoBytes::v0(), [0; 64]);
        let auth = V7SaplingAuthBytes::from_parts(
            Some([0; 32]),
            vec![[0; GROTH_PROOF_SIZE]],
            vec![signature.clone()],
            Vec::new(),
            Some(signature),
        );
        let body = V7TransactionBodyBytes::from_parts(
            Vec::new(),
            vec![V7EffectBundleBytes::Sapling(effects)],
            vec![V7AuthBundleBytes::Sapling(auth)],
        )
        .unwrap();
        assert_retained_known_bundle_digests(body);
    }

    #[cfg(not(feature = "orchard"))]
    #[test]
    fn retained_orchard_and_ironwood_bytes_digest_without_orchard_feature() {
        /// ZIP 248 proof length for an Orchard-protocol bundle with one action.
        const PROOF_LEN: usize = 4992;
        let effects = V7OrchardBundleBytes::from_parts(
            vec![OrchardActionBytes::from_parts(
                [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 580], [0; 80],
            )],
            0,
        );
        let signature = OrchardSignatureBytes::from_parts(SighashInfoBytes::v0(), [0; 64]);
        let auth = V7OrchardAuthBytes::from_parts(
            Some([0; 32]),
            vec![0; PROOF_LEN],
            vec![signature.clone()],
            Some(signature),
        );
        let body = V7TransactionBodyBytes::from_parts(
            Vec::new(),
            vec![
                V7EffectBundleBytes::Orchard(effects.clone()),
                V7EffectBundleBytes::Ironwood(effects),
            ],
            vec![
                V7AuthBundleBytes::Orchard(auth.clone()),
                V7AuthBundleBytes::Ironwood(auth),
            ],
        )
        .unwrap();
        assert_retained_known_bundle_digests(body);
    }

    #[cfg(any(feature = "sapling", feature = "orchard"))]
    #[test]
    fn shielded_auth_callbacks_select_only_the_transaction_version() {
        for version in [TxVersion::V5, TxVersion::V6, TxVersion::V7] {
            #[cfg(feature = "sapling")]
            {
                let (_, v7) =
                    <BlockTxCommitmentDigester as TransactionDigest<Authorized>>::digest_sapling(
                        &BlockTxCommitmentDigester,
                        version,
                        None,
                    )
                    .unwrap();
                assert!(v7.is_none(), "absent bundles have no tagged auth entry");
            }
            #[cfg(feature = "orchard")]
            {
                let (_, v7) =
                    <BlockTxCommitmentDigester as TransactionDigest<Authorized>>::digest_orchard(
                        &BlockTxCommitmentDigester,
                        version,
                        None,
                    )
                    .unwrap();
                assert!(v7.is_none(), "absent bundles have no tagged auth entry");
                let (_, v7) =
                    <BlockTxCommitmentDigester as TransactionDigest<Authorized>>::digest_ironwood(
                        &BlockTxCommitmentDigester,
                        version,
                        None,
                    )
                    .unwrap();
                assert!(v7.is_none(), "absent bundles have no tagged auth entry");
            }
            let _ = version;
        }
    }

    #[cfg(all(feature = "sapling", feature = "orchard"))]
    #[test]
    fn present_sapling_auth_callback_selects_only_the_transaction_version() {
        let mut checked = false;
        for vector in zip_0244::make_test_vectors() {
            let tx = Transaction::read(&vector.tx[..], BranchId::Nu5).unwrap();
            if let Some(bundle) = tx.sapling_bundle() {
                for version in [TxVersion::V5, TxVersion::V6, TxVersion::V7] {
                    let (selected, v7) = <BlockTxCommitmentDigester as TransactionDigest<
                        Authorized,
                    >>::digest_sapling(
                        &BlockTxCommitmentDigester, version, Some(bundle)
                    )
                    .unwrap();
                    if version == TxVersion::V7 {
                        assert_eq!(selected, super::hash_v7_sapling_auth(Some(bundle)));
                        assert_eq!(v7, Some(selected));
                    } else {
                        assert_eq!(
                            selected,
                            super::sapling_witness_digest(version, Some(bundle))
                        );
                        assert!(v7.is_none());
                    }
                }
                checked = true;
            }
        }
        assert!(checked, "vectors must cover a present Sapling bundle");
    }
}
