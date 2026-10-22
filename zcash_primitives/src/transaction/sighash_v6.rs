use blake2b_simd::Hash as Blake2bHash;

use ::transparent::sighash::TransparentAuthorizingContext;

use crate::transaction::{
    Authorization, TransactionData, Zip244Digests,
    sighash::SignableInput,
    sighash_v5::{TransparentInputsDigests, transparent_sig_digest},
    txid::to_hash_v6,
};

/// Implements the version 6 transaction signature hash, using the `txid_parts` and
/// transparent `inputs_digests` of `tx`.
pub(crate) fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &Zip244Digests<Blake2bHash>,
    inputs_digests: Option<&TransparentInputsDigests>,
) -> Blake2bHash {
    // The caller must provide the transparent digests if and only if the
    // transaction has a transparent component.
    assert_eq!(
        tx.transparent_bundle.is_some(),
        txid_parts.transparent_digests.is_some()
    );

    to_hash_v6(
        tx.consensus_branch_id,
        txid_parts.header_digest,
        transparent_sig_digest(
            tx.transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            inputs_digests,
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        txid_parts.ironwood_digest,
    )
}
