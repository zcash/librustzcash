#[cfg(zcash_unstable = "nu6.3")]
use blake2b_simd::Hash as Blake2bHash;

#[cfg(zcash_unstable = "nu6.3")]
use ::transparent::sighash::TransparentAuthorizingContext;

#[cfg(zcash_unstable = "nu6.3")]
use crate::transaction::{
    Authorization, TransactionData, TxDigests, sighash::SignableInput,
    sighash_v5::transparent_sig_digest, txid::to_hash_v6,
};

#[cfg(zcash_unstable = "nu6.3")]
pub fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
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
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        txid_parts.ironwood_digest,
    )
}

#[cfg(all(zcash_unstable = "nu7", not(zcash_unstable = "nu6.3")))]
pub use crate::transaction::sighash_v5::v5_signature_hash as v6_signature_hash;
