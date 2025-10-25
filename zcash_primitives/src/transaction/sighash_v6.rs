use blake2b_simd::Hash as Blake2bHash;

use ::transparent::sighash::TransparentAuthorizingContext;

use crate::transaction::{
    Authorization, TransactionData, TxDigests, sighash::SignableInput,
    sighash_v5::v5_signature_hash,
};

#[cfg(any(zcash_unstable = "zfuture", zcash_unstable = "nu7"))]
pub fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    // TODO: Implement this directly when implementing ZIP 246 in full, rather than delegating to
    // the V5 implementation.
    v5_signature_hash(tx, signable_input, txid_parts)
}
