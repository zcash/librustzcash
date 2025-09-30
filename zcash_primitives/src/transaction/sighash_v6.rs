#[cfg(any(zcash_unstable = "zfuture", zcash_unstable = "nu7"))]
use {
    crate::transaction::{
        sighash::SignableInput, txid::to_hash, Authorization, TransactionData, TxDigests,
    },
    ::transparent::sighash::TransparentAuthorizingContext,
    blake2b_simd::Hash as Blake2bHash,
};

#[cfg(any(zcash_unstable = "nu7", zcash_unstable = "zfuture"))]
pub fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    // The caller must provide the transparent digests if and only if the transaction has a
    // transparent component.
    assert_eq!(
        tx.transparent_bundle.is_some(),
        txid_parts.transparent_digests.is_some()
    );

    to_hash(
        tx.version,
        tx.consensus_branch_id,
        txid_parts.header_digest,
        crate::transaction::sighash_v5::transparent_sig_digest(
            tx.transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        txid_parts.issue_digest,
        #[cfg(zcash_unstable = "zfuture")]
        tx.tze_bundle
            .as_ref()
            .zip(txid_parts.tze_digests.as_ref())
            .map(|(bundle, tze_digests)| {
                crate::transaction::sighash_v5::tze_input_sigdigests(
                    bundle,
                    signable_input,
                    tze_digests,
                )
            })
            .as_ref(),
    )
}
