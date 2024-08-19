use blake2b_simd::Hash as Blake2bHash;

use crate::transaction::sighash_v5::v5_v6_signature_hash;
use crate::transaction::{
    sighash::{SignableInput, TransparentAuthorizingContext},
    Authorization, TransactionData, TxDigests,
};

pub fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    // Currently to_hash is designed in a way that it supports both v5 and v6 signature hash
    v5_v6_signature_hash(tx, signable_input, txid_parts)
}
