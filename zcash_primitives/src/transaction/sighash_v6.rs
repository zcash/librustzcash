use blake2b_simd::Hash as Blake2bHash;
use orchard::issuance::IssueAuth;

use crate::transaction::sighash_v5::transparent_sig_digest;
#[cfg(feature = "zfuture")]
use crate::transaction::sighash_v5::tze_input_sigdigests;
use crate::transaction::{
    sighash::{SignableInput, TransparentAuthorizingContext},
    txid::to_hash,
    Authorization, TransactionData, TxDigests,
};

pub fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
    IA: IssueAuth,
>(
    tx: &TransactionData<A, IA>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    // The caller must provide the transparent digests if and only if the transaction has a
    // transparent component.
    assert_eq!(
        tx.transparent_bundle.is_some(),
        txid_parts.transparent_digests.is_some()
    );

    // TODO add ZSA support

    to_hash(
        tx.version,
        tx.consensus_branch_id,
        txid_parts.header_digest,
        transparent_sig_digest(
            tx.transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        txid_parts.issue_digest,
        #[cfg(feature = "zfuture")]
        tx.tze_bundle
            .as_ref()
            .zip(txid_parts.tze_digests.as_ref())
            .map(|(bundle, tze_digests)| tze_input_sigdigests(bundle, signable_input, tze_digests))
            .as_ref(),
    )
}
