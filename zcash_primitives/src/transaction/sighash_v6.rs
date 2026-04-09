use blake2b_simd::Hash as Blake2bHash;
use core2::io::Write;

use ::transparent::sighash::TransparentAuthorizingContext;

use crate::{
    encoding::{StateWrite, WriteBytesExt},
    transaction::{
        Authorization, TransactionData, TxDigests,
        sighash::SignableInput,
        sighash_v5::transparent_sig_digest,
        txid::{
            hash_v6_effects_bundles, v6_effect_digest_entries,
            ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION,
        },
    },
};

/// Personalization prefix for the txid/sighash root hash.
const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

fn hasher(personal: &[u8; 16]) -> StateWrite {
    StateWrite(
        blake2b_simd::Params::new()
            .hash_length(32)
            .personal(personal)
            .to_state(),
    )
}

/// v6 signature hash per ZIP 248.
///
/// For transactions with no transparent inputs, the signature digest is
/// identical to the transaction identifier digest (since `transparent_sig_digest`
/// equals `transparent_effects_digest` in that case).
///
/// For transactions with transparent inputs, `transparent_effects_digest` in the
/// effects bundles is replaced with `transparent_sig_digest`.
#[cfg(any(zcash_unstable = "zfuture", zcash_unstable = "nu7"))]
pub fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32_le(tx.consensus_branch_id().into())
        .unwrap();

    // VP deltas digest (same as txid)
    let vp_deltas_digest = txid_parts
        .value_pool_deltas_digest
        .unwrap_or_else(|| hasher(ZCASH_V6_VP_DELTAS_HASH_PERSONALIZATION).finalize());

    // For the signature bundles digest, replace transparent_effects_digest
    // with transparent_sig_digest when signing transparent inputs.
    let transparent_sig = transparent_sig_digest(
        tx.transparent_bundle()
            .zip(txid_parts.transparent_digests.as_ref()),
        signable_input,
    );

    let signature_bundles_digest = hash_v6_effects_bundles(v6_effect_digest_entries(
        tx.transparent_bundle().is_some().then_some(&transparent_sig),
        txid_parts.sapling_digest.as_ref(),
        txid_parts.orchard_digest.as_ref(),
        &txid_parts.unknown_effect_digests,
    ));

    let mut h = hasher(&personal);
    h.write_all(txid_parts.header_digest.as_bytes()).unwrap();
    h.write_all(vp_deltas_digest.as_bytes()).unwrap();
    h.write_all(signature_bundles_digest.as_bytes()).unwrap();
    h.finalize()
}
