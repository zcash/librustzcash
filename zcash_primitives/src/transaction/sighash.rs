use alloc::boxed::Box;
use core::fmt;

use blake2b_simd::Hash as Blake2bHash;

use super::{
    Authorization, TransactionData, TxDigests, TxVersion,
    sighash_v4::{v4_signature_hash, zip143_digests},
    sighash_v5::{TransparentInputsDigests, v5_signature_hash},
    sighash_v6::v6_signature_hash,
    txid::TxIdDigester,
};
use ::sapling::bundle::GrothProofBytes;
use ::transparent::sighash::TransparentAuthorizingContext;

pub enum SignableInput<'a> {
    Shielded,
    Transparent(transparent::sighash::SignableInput<'a>),
}

impl SignableInput<'_> {
    pub fn hash_type(&self) -> u8 {
        match self {
            SignableInput::Shielded => ::transparent::sighash::SIGHASH_ALL,
            SignableInput::Transparent(input) => input.hash_type().encode(),
        }
    }
}

pub struct SignatureHash(Blake2bHash);

impl AsRef<[u8; 32]> for SignatureHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref().try_into().unwrap()
    }
}

/// A transaction, together with the digests over its data that the signature hash of
/// every input of the transaction commits to.
///
/// Computing a value of this type takes time linear in the size of the transaction. Given
/// it, [`PrecomputedSighashData::signature_hash`] computes the signature hash of an input
/// in time independent of the number of inputs and outputs, so computing the signature
/// hashes of all inputs of a transaction takes linear time in total.
#[derive(Debug)]
pub struct PrecomputedSighashData<A: Authorization> {
    tx: TransactionData<A>,
    tx_digests: TxDigests<Blake2bHash>,
    /// The digests of the transparent input amounts and `scriptPubKey`s. This is `Some`
    /// only for a transaction of version 5 or later that has non-coinbase transparent
    /// inputs.
    transparent_inputs_digests: Option<TransparentInputsDigests>,
}

impl<TA, SA, A> PrecomputedSighashData<A>
where
    TA: TransparentAuthorizingContext,
    SA: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA, TransparentAuth = TA>,
{
    /// Computes the digests for `tx`.
    pub fn new(tx: TransactionData<A>) -> Self {
        let tx_digests = match tx.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                TxDigests::Zip143(zip143_digests(&tx))
            }
            TxVersion::V5 | TxVersion::V6 => TxDigests::Zip244(tx.digest(TxIdDigester)),
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => TxDigests::Zip244(tx.digest(TxIdDigester)),
        };
        Self::from_tx_digests(tx, tx_digests)
    }
}

impl<TA, A> PrecomputedSighashData<A>
where
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
{
    /// Computes the digests for `tx`, which must be of version 5 or later.
    ///
    /// Unlike [`PrecomputedSighashData::new`], this does not require the Sapling proofs of
    /// `tx` to be serialized, because [ZIP 244] signature hashes do not commit to them.
    ///
    /// Returns [`Zip244Error::NotZip244`] if `tx` is of version 4 or earlier.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    pub fn new_zip244(tx: TransactionData<A>) -> Result<Self, Zip244Error<A>> {
        match tx.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                Err(Zip244Error::NotZip244(Box::new(tx)))
            }
            TxVersion::V5 | TxVersion::V6 => {
                let tx_digests = TxDigests::Zip244(tx.digest(TxIdDigester));
                Ok(Self::from_tx_digests(tx, tx_digests))
            }
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => {
                let tx_digests = TxDigests::Zip244(tx.digest(TxIdDigester));
                Ok(Self::from_tx_digests(tx, tx_digests))
            }
        }
    }

    /// Combines `tx` with the `tx_digests` computed from it, and computes the digests of
    /// its transparent inputs if its signature hashes commit to them.
    fn from_tx_digests(tx: TransactionData<A>, tx_digests: TxDigests<Blake2bHash>) -> Self {
        let transparent_inputs_digests = match tx_digests {
            TxDigests::Zip143(_) => None,
            TxDigests::Zip244(_) => tx
                .transparent_bundle
                .as_ref()
                .and_then(TransparentInputsDigests::for_bundle),
        };
        PrecomputedSighashData {
            tx,
            tx_digests,
            transparent_inputs_digests,
        }
    }

    /// Returns the transaction.
    pub fn tx(&self) -> &TransactionData<A> {
        &self.tx
    }

    /// Returns the digests of the transaction's effecting data.
    pub fn tx_digests(&self) -> &TxDigests<Blake2bHash> {
        &self.tx_digests
    }

    /// Returns the transaction, discarding the digests.
    pub fn into_tx(self) -> TransactionData<A> {
        self.tx
    }

    /// Computes the signature hash for an input to the transaction.
    ///
    /// This runs in time independent of the number of inputs and outputs of the
    /// transaction.
    ///
    /// # Panics
    ///
    /// Panics if the transaction is a pre-Overwinter transaction, or if it is version 4
    /// or earlier and `signable_input` is a transparent input but the transaction has
    /// no transparent bundle. (In the latter case for v5 and later, the result is the
    /// same as if `SignableInput::Shielded` were provided.)
    pub fn signature_hash(&self, signable_input: &SignableInput) -> SignatureHash {
        let inputs_digests = self.transparent_inputs_digests.as_ref();
        SignatureHash(match &self.tx_digests {
            TxDigests::Zip143(digests) => v4_signature_hash(&self.tx, signable_input, digests),
            TxDigests::Zip244(txid_parts) if self.tx.version.has_ironwood() => {
                v6_signature_hash(&self.tx, signable_input, txid_parts, inputs_digests)
            }
            TxDigests::Zip244(txid_parts) => {
                v5_signature_hash(&self.tx, signable_input, txid_parts, inputs_digests)
            }
        })
    }
}

/// An error returned by [`PrecomputedSighashData::new_zip244`].
#[non_exhaustive]
pub enum Zip244Error<A: Authorization> {
    /// The transaction is of version 4 or earlier, so its signature hashes are not
    /// [ZIP 244] signature hashes. This holds the transaction, unchanged.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    NotZip244(Box<TransactionData<A>>),
}

impl<A: Authorization> fmt::Debug for Zip244Error<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Zip244Error::NotZip244(tx) => f
                .debug_struct("NotZip244")
                .field("version", &tx.version)
                .finish_non_exhaustive(),
        }
    }
}

impl<A: Authorization> fmt::Display for Zip244Error<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Zip244Error::NotZip244(tx) => write!(
                f,
                "transaction version {:?} does not use ZIP 244 signature hashes",
                tx.version
            ),
        }
    }
}

impl<A: Authorization> core::error::Error for Zip244Error<A> {}
