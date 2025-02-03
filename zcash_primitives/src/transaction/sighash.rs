use blake2b_simd::Hash as Blake2bHash;

use super::{
    sighash_v4::v4_signature_hash, sighash_v5::v5_signature_hash, Authorization, TransactionData,
    TxDigests, TxVersion,
};
use ::sapling::bundle::GrothProofBytes;

#[cfg(zcash_unstable = "zfuture")]
use {crate::extensions::transparent::Precondition, zcash_protocol::value::Zatoshis};

#[deprecated(note = "use `::zcash_transparent::sighash::SIGHASH_ALL` instead.")]
pub const SIGHASH_ALL: u8 = ::transparent::sighash::SIGHASH_ALL;
#[deprecated(note = "use `::zcash_transparent::sighash::SIGHASH_NONE` instead.")]
pub const SIGHASH_NONE: u8 = ::transparent::sighash::SIGHASH_NONE;
#[deprecated(note = "use `::zcash_transparent::sighash::SIGHASH_SINGLE` instead.")]
pub const SIGHASH_SINGLE: u8 = ::transparent::sighash::SIGHASH_SINGLE;
#[deprecated(note = "use `::zcash_transparent::sighash::SIGHASH_MASK` instead.")]
pub const SIGHASH_MASK: u8 = ::transparent::sighash::SIGHASH_MASK;
#[deprecated(note = "use `::zcash_transparent::sighash::SIGHASH_ANYONECANPAY` instead.")]
pub const SIGHASH_ANYONECANPAY: u8 = ::transparent::sighash::SIGHASH_ANYONECANPAY;

#[deprecated(note = "use `::zcash_transparent::sighash::SighashType` instead.")]
pub type SighashType = ::transparent::sighash::SighashType;

pub enum SignableInput<'a> {
    Shielded,
    Transparent(transparent::sighash::SignableInput<'a>),
    #[cfg(zcash_unstable = "zfuture")]
    Tze {
        index: usize,
        precondition: &'a Precondition,
        value: Zatoshis,
    },
}

impl SignableInput<'_> {
    pub fn hash_type(&self) -> u8 {
        match self {
            SignableInput::Shielded => ::transparent::sighash::SIGHASH_ALL,
            SignableInput::Transparent(input) => input.hash_type().encode(),
            #[cfg(zcash_unstable = "zfuture")]
            SignableInput::Tze { .. } => ::transparent::sighash::SIGHASH_ALL,
        }
    }
}

pub struct SignatureHash(Blake2bHash);

impl AsRef<[u8; 32]> for SignatureHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref().try_into().unwrap()
    }
}

/// Computes the signature hash for an input to a transaction, given
/// the full data of the transaction, the input being signed, and the
/// set of precomputed hashes produced in the construction of the
/// transaction ID.
pub fn signature_hash<
    TA: ::transparent::sighash::TransparentAuthorizingContext,
    SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA, TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> SignatureHash {
    SignatureHash(match tx.version {
        TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
            v4_signature_hash(tx, signable_input)
        }

        TxVersion::Zip225 => v5_signature_hash(tx, signable_input, txid_parts),

        #[cfg(zcash_unstable = "zfuture")]
        TxVersion::ZFuture => v5_signature_hash(tx, signable_input, txid_parts),
    })
}
