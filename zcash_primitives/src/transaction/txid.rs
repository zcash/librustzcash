#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
use crate::encoding::{StateWrite, WriteBytesExt};
#[cfg(all(feature = "sapling", feature = "orchard"))]
use core::borrow::Borrow;
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
use core::convert::TryFrom;
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
use corez::io::Write;

#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
use blake2b_simd::{Hash as Blake2bHash, Params};

#[cfg(all(feature = "sapling", feature = "orchard"))]
use {
    ::orchard::{
        ValuePool,
        bundle::{self as orchard, TxVersion as OrchardTxVersion},
    },
    ::sapling::bundle::{OutputDescription, SpendDescription},
    ::transparent::bundle::{self as transparent, TxIn, TxOut},
    ff::PrimeField,
    zcash_protocol::value::ZatBalance,
};

#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
use zcash_protocol::consensus::{BlockHeight, BranchId};

#[cfg(all(feature = "sapling", feature = "orchard"))]
use super::{Authorization, Authorized, TransactionDigest};
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
use super::{TransparentDigests, TxId, TxVersion, Zip244Digests};

#[cfg(zcash_unstable = "nu8")]
use super::zip248::{BundleId, BundleType, BundleVariant};
#[cfg(zcash_unstable = "nu8")]
use super::{
    bytes::transparent::TransparentBundleBytes,
    bytes::{
        CoinbaseBundleBytes, OrchardActionBytes, V7OrchardBundleBytes, V7SaplingBundleBytes,
        ValuePoolDeltaBytes,
    },
    zip248::V7DigestError,
};

/// TxId tree root personalization
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

// TxId level 1 node personalization
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdHeadersHash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
pub(crate) const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTranspaHash";
#[cfg(all(feature = "sapling", feature = "orchard"))]
const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSaplingHash";

// TxId transparent level 2 node personalization
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdPrevoutHash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSequencHash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOutputsHash";

// TxId sapling level 2 node personalization
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendsHash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendCHash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNHash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNH_v6";

#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
pub(crate) const ZCASH_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
#[cfg(all(feature = "sapling", feature = "orchard"))]
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";
#[cfg(all(feature = "sapling", feature = "orchard"))]
const ZCASH_SAPLING_V6_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliH_v6";

/// Selects the personalization for the Sapling spends non-compact digest.
///
/// [ZIP 244 §T.3a.ii] and [ZIP 248 §T.3.2a.ii] hash `cv || anchor || rk` per
/// spend under `ZTxIdSSpendNHash`. [ZIP 229]'s v6 digest hashes `cv || rk`
/// under `ZTxIdSSpendNH_v6`, because the anchor is authorizing data in v6.
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
/// [ZIP 244 §T.3a.ii]: https://zips.z.cash/zip-0244#t-3a-ii-sapling-spends-noncompact-digest
/// [ZIP 248 §T.3.2a.ii]: https://zips.z.cash/zip-0248
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
fn sapling_spends_noncompact_personalization(version: TxVersion) -> &'static [u8; 16] {
    match version {
        TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => {
            ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
        }
        TxVersion::V6 => ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
    }
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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

#[cfg(all(feature = "sapling", feature = "orchard"))]
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
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

#[cfg(all(feature = "sapling", feature = "orchard"))]
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

#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
pub(crate) fn hasher(personal: &[u8; 16]) -> StateWrite {
    StateWrite(Params::new().hash_length(32).personal(personal).to_state())
}

/// Builds the 16-byte BLAKE2b personalization used for txid and sighash
/// top-level hashes: `"ZcashTxHash_" || LE32(consensus_branch_id)`.
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
pub(crate) fn tx_hash_personalization(consensus_branch_id: BranchId) -> [u8; 16] {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32_le(consensus_branch_id.into())
        .unwrap();
    personal
}

/// Sequentially append the serialized value of each transparent input
/// to a hash personalized by ZCASH_PREVOUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
#[cfg(all(feature = "sapling", feature = "orchard"))]
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
pub(crate) fn transparent_outputs_hash<T: Borrow<TxOut>>(vout: &[T]) -> Blake2bHash {
    let mut h = hasher(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    for t_out in vout {
        t_out.borrow().write(&mut h).unwrap();
    }
    h.finalize()
}

/// The fields of a Sapling spend that the effects digest commits to.
///
/// The anchor is shared by every spend in a bundle, but each spend's digest
/// input includes it. V6 is the only transaction version whose effects digest
/// omits it, because v6 carries the anchor as authorizing data instead.
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
pub(crate) struct SaplingSpendDigestParts {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub anchor: [u8; 32],
    pub rk: [u8; 32],
}

/// Implements [ZIP 244 section T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest);
/// the v6 variant is specified in [ZIP 229](https://zips.z.cash/zip-0229), and
/// the v7 variant in [ZIP 248](https://zips.z.cash/zip-0248).
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk)*\] for v5 and v7 transactions (v4 is not handled here),
///   personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
/// * \[(cv, rk)*\] for v6 transactions, personalized with
///   ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
pub(crate) fn hash_sapling_spends_parts(
    version: TxVersion,
    spends: impl IntoIterator<Item = SaplingSpendDigestParts>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
    let mut nh = hasher(sapling_spends_noncompact_personalization(version));
    let mut any = false;
    for spend in spends {
        any = true;
        // we build the hash of nullifiers separately for compact blocks.
        ch.write_all(&spend.nullifier).unwrap();

        nh.write_all(&spend.cv).unwrap();
        // [ZIP 248 §T.3.2a.ii]: the bundle-wide anchor is authorizing data in
        // v7, but the non-compact spends digest still hashes it once per
        // spend. ZIP 244 and ZIP 229's v5 form do the same; v6 omits it
        // because it moved to the auth digest.
        let write_anchor = match version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => true,
            TxVersion::V6 => false,
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => true,
        };
        if write_anchor {
            nh.write_all(&spend.anchor).unwrap();
        }
        nh.write_all(&spend.rk).unwrap();
    }

    if any {
        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
    }
    h.finalize()
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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
                anchor: s_spend.anchor().to_repr(),
                rk: <[u8; 32]>::from(*s_spend.rk()),
            }),
    )
}

/// The fields of a Sapling output that the effects digest commits to.
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
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
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
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

#[cfg(all(feature = "sapling", feature = "orchard"))]
pub(crate) fn hash_sapling_outputs<A>(shielded_outputs: &[OutputDescription<A>]) -> Blake2bHash {
    hash_sapling_outputs_parts(
        shielded_outputs
            .iter()
            .map(|s_out| SaplingOutputDigestParts {
                cv: s_out.cv().to_bytes(),
                cmu: s_out.cmu().to_bytes(),
                ephemeral_key: s_out.ephemeral_key().0,
                enc_ciphertext: *s_out.enc_ciphertext(),
                out_ciphertext: *s_out.out_ciphertext(),
            }),
    )
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid
#[cfg(all(feature = "sapling", feature = "orchard"))]
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
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
#[cfg(any(all(feature = "sapling", feature = "orchard"), zcash_unstable = "nu8"))]
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
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

#[cfg(all(feature = "sapling", feature = "orchard"))]
fn hash_sapling_txid_empty() -> Blake2bHash {
    hasher(ZCASH_SAPLING_HASH_PERSONALIZATION).finalize()
}

// ---------------------------------------------------------------------------
// ZIP 248 v7-specific digest functions
// ---------------------------------------------------------------------------

/// Implements [ZIP 248 §T.1](https://zips.z.cash/zip-0248#t-1-header-digest).
///
/// v7 header digest. Unlike the v5 header digest
/// ([ZIP 244 §T.1](https://zips.z.cash/zip-0244#t-1-header-digest)), this
/// does NOT include `zip233_amount` or the transaction fee -- those concerns
/// are handled entirely by the value-pool-deltas digest
/// ([ZIP 248 §T.2](https://zips.z.cash/zip-0248#t-2-value-pool-deltas-digest)).
/// This separation keeps the header focused on consensus-level metadata and
/// avoids coupling it to value-flow semantics.
///
/// Fields committed: `header || nVersionGroupId || nConsensusBranchId ||
/// lock_time || nExpiryHeight`.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_header(
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
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_value_pool_deltas(vp: &super::zip248::ValuePoolDeltas) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_VP_DELTAS_HASH_PERSONALIZATION);
    for entry in vp.to_wire_entries() {
        entry.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 248 §T.3.1](https://zips.z.cash/zip-0248#t-3-1-coinbase-effects-digest).
///
/// Hashes the coinbase bundle's effecting data: the block height, the block
/// subsidy, the part of that subsidy deposited into the lockbox, and the
/// miner-chosen `coinbaseData`.
///
/// Unlike the other per-bundle digests there is no empty-bundle sentinel: a
/// transaction that has no coinbase bundle contributes no entry for it to
/// `effects_bundles_digest` at all.
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_coinbase_effects(bundle: &super::zip248::CoinbaseBundle) -> Blake2bHash {
    use zcash_encoding::CompactSize;

    let mut h = hasher(ZCASH_V7_COINBASE_HASH_PERSONALIZATION);
    h.write_u32_le(u32::from(bundle.block_height())).unwrap();
    h.write_all(&u64::from(bundle.block_subsidy()).to_le_bytes())
        .unwrap();
    h.write_all(&u64::from(bundle.lockbox_value()).to_le_bytes())
        .unwrap();
    // `coinbaseData` is hashed in its field encoding, i.e. with its leading
    // `compactSize` length.
    CompactSize::write(&mut h, bundle.coinbase_data().len()).unwrap();
    h.write_all(bundle.coinbase_data()).unwrap();
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
/// authorizing data in v7 and is committed by [`hash_v7_sapling_auth`].
/// However, [ZIP 248 §T.3.2a.ii] hashes the bundle anchor once per spend in
/// the non-compact spends digest, so the per-spend anchor does participate
/// (see [`hash_sapling_spends`]).
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_sapling_effects<A: sapling::bundle::Authorization>(
    bundle: &sapling::Bundle<A, ZatBalance>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
        // [ZIP 248 §T.3.2a]: spends_digest commits to nullifiers and
        // (cv, anchor, rk) per spend, split into compact and non-compact
        // sub-hashes. The bundle anchor is authorizing data in v7, but the
        // non-compact spends digest hashes it once per spend.
        h.write_all(hash_sapling_spends(TxVersion::V7, bundle.shielded_spends()).as_bytes())
            .unwrap();
        // [ZIP 248 §T.3.2b]: outputs_digest commits to (cmu, epk, enc, cv, out)
        // per output, split into compact, memo, and non-compact sub-hashes.
        h.write_all(hash_sapling_outputs(bundle.shielded_outputs()).as_bytes())
            .unwrap();
    }
    h.finalize()
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
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
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
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
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
    auth: &'static [u8; 16],
}

#[cfg(zcash_unstable = "nu8")]
const ORCHARD_POOL_PERSONALIZATIONS: OrchardPoolPersonalizations = OrchardPoolPersonalizations {
    effects: ZCASH_V7_ORCHARD_HASH_PERSONALIZATION,
    actions_compact: b"ZTxIdOrcActCHash",
    actions_memos: b"ZTxIdOrcActMHash",
    actions_noncompact: b"ZTxIdOrcActNHash",
    auth: ZCASH_V7_ORCHARD_AUTH_HASH_PERSONALIZATION,
};

#[cfg(zcash_unstable = "nu8")]
const IRONWOOD_POOL_PERSONALIZATIONS: OrchardPoolPersonalizations = OrchardPoolPersonalizations {
    effects: ZCASH_V7_IRONWOOD_HASH_PERSONALIZATION,
    actions_compact: b"ZTxIdIrnActCHash",
    actions_memos: b"ZTxIdIrnActMHash",
    actions_noncompact: b"ZTxIdIrnActNHash",
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

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
fn hash_v7_orchard_protocol_effects(
    bundle: &orchard::Bundle<impl orchard::Authorization, ZatBalance>,
    personalizations: &OrchardPoolPersonalizations,
) -> Blake2bHash {
    hash_orchard_actions_parts(
        bundle
            .actions()
            .iter()
            .map(|action| OrchardActionDigestParts {
                cv: action.cv_net().to_bytes(),
                nullifier: action.nullifier().to_bytes(),
                rk: <[u8; 32]>::from(action.rk()),
                cmx: action.cmx().to_bytes(),
                ephemeral_key: action.encrypted_note().epk_bytes,
                enc_ciphertext: action
                    .encrypted_note()
                    .enc_ciphertext
                    .as_ref()
                    .try_into()
                    .expect("Orchard enc_ciphertext is 580 bytes"),
                out_ciphertext: action.encrypted_note().out_ciphertext,
            }),
        bundle.flag_byte(),
        personalizations,
    )
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
/// the sighash version in use. This enables future sighash versions to be
/// introduced without ambiguity -- a verifier can always determine which
/// sighash algorithm was used to produce each signature. Without this
/// prefix, a transaction produced under sighash v1 could be confused with
/// one produced under v0 (if such a version were ever defined).
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_transparent_auth(
    transparent_bundle: Option<&transparent::Bundle<transparent::Authorized>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
    if let Some(bundle) = transparent_bundle {
        for txin in &bundle.vin {
            h.write_all(super::zip248::V7_SIGHASH_V0_INFO_WIRE)
                .expect("infallible");
            txin.script_sig().write(&mut h).expect("infallible");
        }
    }
    h.finalize()
}

/// Implements [ZIP 248 §A.1.2](https://zips.z.cash/zip-0248#a-1-2-sapling-auth-digest).
///
/// Hashes the anchor (when there are spends), the spend proofs, the spend-auth
/// signatures (each wrapped as a sighash version 0 `SaplingSignature`), the
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
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
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
        // sighashInfo to bind it to sighash version 0.
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
/// per-action spend-auth signature wrapped as a sighash version 0
/// `OrchardSignature`, then the binding signature (also as an
/// `OrchardSignature`). When there are no actions, returns
/// `BLAKE2b-256("ZTxAuthOrchaH_v7", [])`.
///
/// Unlike sapling where proofs are per-spend/per-output, orchard uses a
/// single aggregated proof for all actions. The ordering is still proof-
/// first so that a verifier can process the proof before checking any
/// signatures.
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
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
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
pub(crate) fn hash_v7_ironwood_auth(
    ironwood_bundle: Option<&orchard::Bundle<orchard::Authorized, ZatBalance>>,
) -> Blake2bHash {
    hash_v7_orchard_protocol_auth(ironwood_bundle, &IRONWOOD_POOL_PERSONALIZATIONS)
}

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
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
        // with sighashInfo to bind it to sighash version 0.
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
    use zcash_encoding::CompactSize;

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
    bundle: &TransparentBundleBytes,
) -> TransparentDigests<Blake2bHash> {
    let mut prevouts = hasher(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
    let mut sequences = hasher(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
    for input in bundle.effects().inputs() {
        input
            .prevout()
            .write(&mut prevouts)
            .expect("writing to a hasher is infallible");
        sequences
            .write_u32_le(input.sequence())
            .expect("writing to a hasher is infallible");
    }

    let mut outputs = hasher(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    for output in bundle.effects().outputs() {
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
pub(crate) fn hash_v7_transparent_effects_bytes(bundle: &TransparentBundleBytes) -> Blake2bHash {
    if bundle.effects().inputs().is_empty() && bundle.effects().outputs().is_empty() {
        hash_transparent_txid_data(None)
    } else {
        hash_transparent_txid_data(Some(&transparent_digests_bytes(bundle)))
    }
}

/// [ZIP 248 §T.3.1](https://zips.z.cash/zip-0248#t-3-1-coinbase-effects-digest)
/// over a byte-layer coinbase bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_coinbase_effects_bytes(bundle: &CoinbaseBundleBytes) -> Blake2bHash {
    use zcash_encoding::CompactSize;

    let mut h = hasher(ZCASH_V7_COINBASE_HASH_PERSONALIZATION);
    h.write_u32_le(u32::from(bundle.block_height()))
        .expect("writing to a hasher is infallible");
    h.write_all(&bundle.block_subsidy().to_le_bytes())
        .expect("writing to a hasher is infallible");
    h.write_all(&bundle.lockbox_value().to_le_bytes())
        .expect("writing to a hasher is infallible");
    CompactSize::write(&mut h, bundle.coinbase_data().len())
        .expect("writing to a hasher is infallible");
    h.write_all(bundle.coinbase_data())
        .expect("writing to a hasher is infallible");
    h.finalize()
}

/// [ZIP 248 §T.3.2](https://zips.z.cash/zip-0248#t-3-2-sapling-effects-digest)
/// over a byte-layer Sapling bundle.
///
/// # Errors
///
/// Returns [`V7DigestError::MissingSaplingAnchor`] if the bundle has spends but
/// no anchor. An effects-only bundle parsed without its authorizing data can
/// omit the anchor, but the non-compact spends digest must hash it once per
/// spend, so such a bundle has no computable effects digest.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_sapling_effects_bytes(
    bundle: &V7SaplingBundleBytes,
) -> Result<Blake2bHash, V7DigestError> {
    let mut h = hasher(ZCASH_V7_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.spends().is_empty() && bundle.outputs().is_empty()) {
        let spends_digest = if bundle.spends().is_empty() {
            hash_sapling_spends_parts(TxVersion::V7, core::iter::empty())
        } else {
            let anchor = *bundle.anchor().ok_or(V7DigestError::MissingSaplingAnchor)?;
            hash_sapling_spends_parts(
                TxVersion::V7,
                bundle.spends().iter().map(|spend| SaplingSpendDigestParts {
                    cv: *spend.cv(),
                    nullifier: *spend.nullifier(),
                    anchor,
                    rk: *spend.rk(),
                }),
            )
        };
        h.write_all(spends_digest.as_bytes())
            .expect("writing to a hasher is infallible");
        h.write_all(
            hash_sapling_outputs_parts(bundle.outputs().iter().map(|output| {
                SaplingOutputDigestParts {
                    cv: *output.cv(),
                    cmu: *output.cmu(),
                    ephemeral_key: *output.ephemeral_key(),
                    enc_ciphertext: *output.enc_ciphertext(),
                    out_ciphertext: *output.out_ciphertext(),
                }
            }))
            .as_bytes(),
        )
        .expect("writing to a hasher is infallible");
    }
    Ok(h.finalize())
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
pub(crate) fn hash_v7_transparent_auth_bytes(bundle: &TransparentBundleBytes) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
    if let Some(auth) = bundle.auth() {
        for input in auth.inputs() {
            input
                .sighash_info()
                .write(&mut h)
                .expect("writing to a hasher is infallible");
            input
                .script_sig()
                .write(&mut h)
                .expect("writing to a hasher is infallible");
        }
    }
    h.finalize()
}

/// [ZIP 248 §A.1.2](https://zips.z.cash/zip-0248#a-1-2-sapling-auth-digest)
/// over a byte-layer Sapling bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_sapling_auth_bytes(bundle: &V7SaplingBundleBytes) -> Blake2bHash {
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
pub(crate) fn hash_v7_orchard_auth_bytes(bundle: &V7OrchardBundleBytes) -> Blake2bHash {
    hash_v7_orchard_protocol_auth_bytes(bundle, &ORCHARD_POOL_PERSONALIZATIONS)
}

/// [ZIP 248 §A.1.4](https://zips.z.cash/zip-0248#a-1-4-ironwood-auth-digest)
/// over a byte-layer Ironwood bundle.
#[cfg(zcash_unstable = "nu8")]
pub(crate) fn hash_v7_ironwood_auth_bytes(bundle: &V7OrchardBundleBytes) -> Blake2bHash {
    hash_v7_orchard_protocol_auth_bytes(bundle, &IRONWOOD_POOL_PERSONALIZATIONS)
}

#[cfg(zcash_unstable = "nu8")]
fn hash_v7_orchard_protocol_auth_bytes(
    bundle: &V7OrchardBundleBytes,
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
/// This implements transaction ID digests for v5 transactions ([ZIP 244]) and for
/// v6 transactions ([ZIP 229]). It cannot be used to compute the transaction ID for
/// v4 or earlier transactions; those used `SHA-256(SHA-256(tx_encoding))` and are
/// malleable.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244#txid-digest
/// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
#[cfg(all(feature = "sapling", feature = "orchard"))]
pub struct TxIdDigester;

#[cfg(all(feature = "sapling", feature = "orchard"))]
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
            // The fields below are populated by the v7-specific `digest_v7()`
            // path; the legacy `TransactionDigest::combine` path used for
            // pre-v7 transactions leaves them empty.
            #[cfg(zcash_unstable = "nu8")]
            coinbase_digest: None,
            #[cfg(zcash_unstable = "nu8")]
            value_pool_deltas_digest: None,
            #[cfg(zcash_unstable = "nu8")]
            unknown_effect_digests: alloc::vec::Vec::new(),
        }
    }
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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

#[cfg(all(feature = "sapling", feature = "orchard"))]
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
/// V6 and later transactions include the Ironwood bundle digest as a separate
/// Orchard-shaped digest using Ironwood personalization. If any shielded bundle digest is
/// absent, this substitutes the protocol-defined empty bundle digest for that pool.
#[cfg(all(feature = "sapling", feature = "orchard"))]
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
        TxVersion::V7 => to_hash_v7(consensus_branch_id, digests)?,
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
pub(crate) fn to_txid_v7(
    consensus_branch_id: BranchId,
    digests: &Zip244Digests<Blake2bHash>,
) -> TxId {
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
/// same scheme as ZIP 244 so that txids are fork-specific.
#[cfg(zcash_unstable = "nu8")]
fn to_hash_v7(
    consensus_branch_id: BranchId,
    digests: &Zip244Digests<Blake2bHash>,
) -> Option<Blake2bHash> {
    let personal = tx_hash_personalization(consensus_branch_id);

    // A v7 digest tree must include the value pool deltas digest. A tree built
    // by `TxIdDigester` does not, so it cannot produce a v7 txid.
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
/// per-bundle digest, merging the known bundle digests
/// with unknown-bundle digests in strictly increasing `(bundleType,
/// bundleVariant)` order.
///
/// Known bundle digests (transparent, coinbase, Sapling, Orchard, Ironwood)
/// and opaque-bundle digests are merged and sorted by their raw
/// `(bundleType, bundleVariant)` key, so the digest is deterministic
/// regardless of the order bundles were deserialized.
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
    unknown: &'a [(BundleId, Blake2bHash)],
) -> alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> {
    let mut entries: alloc::vec::Vec<((u64, u64), &'a Blake2bHash)> = alloc::vec::Vec::new();
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
    // Unknown bundles: these were round-tripped from the wire and may include
    // bundle types introduced by future network upgrades that this code does
    // not yet understand. They participate in the digest identically to known
    // bundles so that the txid is stable across software versions.
    for (key, digest) in unknown {
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
pub struct BlockTxCommitmentDigester;

#[cfg(all(feature = "sapling", feature = "orchard"))]
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

#[cfg(all(test, feature = "sapling", feature = "orchard"))]
mod tests {
    use super::{
        ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
        ZCASH_SAPLING_SPENDS_V6_NONCOMPACT_HASH_PERSONALIZATION,
        sapling_spends_noncompact_personalization,
    };
    use crate::transaction::TxVersion;

    /// [ZIP 248 §T.3.2a.ii] hashes `cv || anchor || rk` per spend, under
    /// ZIP 244's `ZTxIdSSpendNHash` personalization. V6 is the exception: it
    /// hashes `cv || rk` under `ZTxIdSSpendNH_v6`, because the anchor moved to
    /// its authorizing data digest.
    ///
    /// Selecting the wrong personalization for v7 produces a transaction
    /// identifier that no other implementation agrees with, and nothing else in
    /// the test suite can see it, so assert the mapping directly.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    /// [ZIP 244 §T.3a.ii]: https://zips.z.cash/zip-0244#t-3a-ii-sapling-spends-noncompact-digest
    /// [ZIP 248 §T.3.2a.ii]: https://zips.z.cash/zip-0248
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
            ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
            "v7 hashes cv || anchor || rk, so it uses ZIP 244's Sapling spends personalization",
        );
    }
}
