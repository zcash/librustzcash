use alloc::boxed::Box;
use core::fmt;

use blake2b_simd::Hash as Blake2bHash;

use super::{
    Authorization, TransactionData, TxDigests, TxVersion,
    sighash_v4::{v4_signature_hash, zip143_digests},
    sighash_v5::{TransparentInputsDigests, v5_signature_hash},
    sighash_v6::v6_signature_hash,
    txid::TxIdDigester,
    zip248::{BundleDigestProvider, V7DigestError},
};
#[cfg(feature = "sapling")]
use ::sapling::bundle::GrothProofBytes;
use ::transparent::sighash::TransparentAuthorizingContext;
use zcash_protocol::value::Zatoshis;

#[cfg(zcash_unstable = "nu8")]
use super::{
    TxId, sighash_v7::v7_signature_hash_precomputed, txid::to_txid_v7, zip248::BundleType,
};

#[derive(Debug)]
pub enum SignableInput<'a> {
    /// A shielded input of a pre-version 7 transaction, which signs a single digest shared
    /// by every shielded bundle and input. This includes the legacy version 4 path.
    ///
    /// Version 7 transactions sign a distinct digest per Spend, action and binding
    /// signature; use `SignableInput::V7` for them. `PrecomputedSighashData::signature_hash`
    /// panics if this is used with a version 7 transaction.
    Shielded,
    Transparent(transparent::sighash::SignableInput<'a, Zatoshis>),
    /// A signature of a version 7 transaction.
    #[cfg(zcash_unstable = "nu8")]
    V7(V7SignatureContext<'a>),
}

/// The bundle-defined context of a [ZIP 248 variant 0] signature.
///
/// Every variant 0 signature commits to the whole transaction and to the amounts and
/// `scriptPubKey`s of all transparent inputs; the context additionally identifies the
/// signature's position within its bundle. Binding signatures have an empty context.
///
/// [ZIP 248 variant 0]: https://zips.z.cash/zip-0248#variant-0-signature-digest
#[cfg(zcash_unstable = "nu8")]
#[derive(Debug)]
pub enum V7SignatureContext<'a> {
    /// The transparent input at the wrapped [`transparent::sighash::SignableInput`]'s
    /// index.
    ///
    /// Variant 0 requires every nonempty signature checked by the script interpreter
    /// to carry `SIGHASH_ALL`. Verifiers must enforce this separately: the digest
    /// does not commit to the hash-type byte and does not validate it.
    Transparent(transparent::sighash::SignableInput<'a, Zatoshis>),
    /// The Sapling Spend at `index`, which must be its position in the bundle's Spend
    /// vector.
    SaplingSpend { index: usize },
    /// The Sapling binding signature.
    SaplingBinding,
    /// The Orchard action at `index`, which must be its position in the bundle's action
    /// vector.
    OrchardAction { index: usize },
    /// The Orchard binding signature.
    OrchardBinding,
    /// The Ironwood action at `index`, which must be its position in the bundle's action
    /// vector.
    IronwoodAction { index: usize },
    /// The Ironwood binding signature.
    IronwoodBinding,
}

#[cfg(zcash_unstable = "nu8")]
impl V7SignatureContext<'_> {
    /// Returns the bundle type whose signature this context describes.
    pub(crate) fn bundle_type(&self) -> BundleType {
        match self {
            V7SignatureContext::Transparent(_) => BundleType::TRANSPARENT,
            V7SignatureContext::SaplingSpend { .. } | V7SignatureContext::SaplingBinding => {
                BundleType::SAPLING
            }
            V7SignatureContext::OrchardAction { .. } | V7SignatureContext::OrchardBinding => {
                BundleType::ORCHARD
            }
            V7SignatureContext::IronwoodAction { .. } | V7SignatureContext::IronwoodBinding => {
                BundleType::IRONWOOD
            }
        }
    }

    /// Returns the local index of the signed Spend or action, or `None` for a binding
    /// signature.
    pub(crate) fn index(&self) -> Option<usize> {
        match self {
            V7SignatureContext::Transparent(input) => Some(*input.index()),
            V7SignatureContext::SaplingSpend { index }
            | V7SignatureContext::OrchardAction { index }
            | V7SignatureContext::IronwoodAction { index } => Some(*index),
            V7SignatureContext::SaplingBinding
            | V7SignatureContext::OrchardBinding
            | V7SignatureContext::IronwoodBinding => None,
        }
    }
}

impl<'a> SignableInput<'a> {
    /// Selects the transparent signature context for `version`.
    ///
    /// Version 7 uses the [ZIP 248] variant-0 context; earlier versions use the
    /// legacy transparent context. The caller must ensure `input` belongs to the
    /// transaction being signed. For version 7, script verifiers must separately
    /// enforce `SIGHASH_ALL` on every nonempty signature.
    ///
    /// [ZIP 248]: https://zips.z.cash/zip-0248#variant-0-signature-digest
    pub fn transparent(
        version: TxVersion,
        input: transparent::sighash::SignableInput<'a, Zatoshis>,
    ) -> Self {
        #[cfg(zcash_unstable = "nu8")]
        if version == TxVersion::V7 {
            return Self::V7(V7SignatureContext::Transparent(input));
        }
        let _ = version;
        Self::Transparent(input)
    }

    pub fn hash_type(&self) -> u8 {
        match self {
            SignableInput::Shielded => ::transparent::sighash::SIGHASH_ALL,
            SignableInput::Transparent(input) => input.hash_type().encode(),
            #[cfg(zcash_unstable = "nu8")]
            SignableInput::V7(V7SignatureContext::Transparent(input)) => input.hash_type().encode(),
            #[cfg(zcash_unstable = "nu8")]
            SignableInput::V7(_) => ::transparent::sighash::SIGHASH_ALL,
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
    /// for every version 7 transaction (including empty input lists), and for earlier
    /// ZIP 244 transactions with non-coinbase transparent inputs.
    transparent_inputs_digests: Option<TransparentInputsDigests>,
    /// The shared ZIP 248 S.2 digest, present only for version 7.
    #[cfg(zcash_unstable = "nu8")]
    v7_txid: Option<TxId>,
}

#[cfg(feature = "sapling")]
impl<TA, SA, A> PrecomputedSighashData<A>
where
    TA: transparent::bundle::Authorization + TransparentAuthorizingContext<Zatoshis>,
    SA: sapling::bundle::Authorization<
            Anchor = jubjub::Base,
            SpendProof = GrothProofBytes,
            OutputProof = GrothProofBytes,
        >,
    A: Authorization<SaplingAuth = SA, TransparentAuth = TA>,
{
    /// Computes the digests for `tx`.
    ///
    /// Returns an error if `provider` cannot resolve an unrecognized bundle's digest,
    /// or transparent previous-output context is incomplete.
    pub fn new(
        tx: TransactionData<A>,
        provider: &impl BundleDigestProvider,
    ) -> Result<Self, V7DigestError> {
        let tx_digests = match tx.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                TxDigests::Zip143(zip143_digests(&tx))
            }
            _ => TxDigests::Zip244(tx.digest(TxIdDigester, provider)?),
        };
        let inputs = Self::legacy_input_digests(&tx)?;
        Self::from_tx_digests(tx, tx_digests, inputs)
    }
}

impl<TA, A> PrecomputedSighashData<A>
where
    TA: transparent::bundle::Authorization + TransparentAuthorizingContext<Zatoshis>,
    A: Authorization<TransparentAuth = TA>,
{
    /// Computes the digests for `tx` without Sapling domain types.
    ///
    /// Returns an error if `provider` cannot resolve an unrecognized bundle's digest,
    /// or transparent previous-output context is incomplete.
    #[cfg(not(feature = "sapling"))]
    pub fn new(
        tx: TransactionData<A>,
        provider: &impl BundleDigestProvider,
    ) -> Result<Self, V7DigestError> {
        let tx_digests = match tx.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                TxDigests::Zip143(zip143_digests(&tx))
            }
            _ => TxDigests::Zip244(tx.digest(TxIdDigester, provider)?),
        };
        let inputs = Self::legacy_input_digests(&tx)?;
        Self::from_tx_digests(tx, tx_digests, inputs)
    }
}

impl<TA, A> PrecomputedSighashData<A>
where
    TA: transparent::bundle::Authorization + TransparentAuthorizingContext<Zatoshis>,
    A: Authorization<TransparentAuth = TA>,
{
    fn legacy_input_digests(
        tx: &TransactionData<A>,
    ) -> Result<Option<TransparentInputsDigests>, V7DigestError> {
        if matches!(
            tx.version,
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4
        ) {
            return Ok(None);
        }
        tx.transparent_bundle()
            .map(|bundle| {
                TransparentInputsDigests::for_bundle(tx.version, bundle, &bundle.authorization)
            })
            .transpose()
            .map(Option::flatten)
    }

    /// Computes the digests for `tx`, which must be of version 5 or later.
    ///
    /// Unlike [`PrecomputedSighashData::new`], this does not require the Sapling proofs of
    /// `tx` to be serialized, because [ZIP 244], [ZIP 229] and [ZIP 248] signature hashes do
    /// not commit to them.
    ///
    /// Returns [`Zip244Error::NotZip244`] if `tx` is of version 4 or earlier.
    /// Returns [`Zip244Error::Digest`] if a bundle digest cannot be resolved or
    /// transparent previous-output context is incomplete.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    /// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    pub fn new_zip244(
        tx: TransactionData<A>,
        provider: &impl BundleDigestProvider,
    ) -> Result<Self, Zip244Error<A>> {
        match tx.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                Err(Zip244Error::NotZip244(Box::new(tx)))
            }
            _ => {
                let tx_digests = TxDigests::Zip244(
                    tx.digest(TxIdDigester, provider)
                        .map_err(Zip244Error::Digest)?,
                );
                let inputs = Self::legacy_input_digests(&tx).map_err(Zip244Error::Digest)?;
                Self::from_tx_digests(tx, tx_digests, inputs).map_err(Zip244Error::Digest)
            }
        }
    }
}

impl<A: Authorization> PrecomputedSighashData<A> {
    /// Computes V5 and later signature digests with separate previous-output context.
    ///
    /// Context entries must follow transaction input order. Returns
    /// [`Zip244Error::NotZip244`] for earlier formats and [`Zip244Error::Digest`]
    /// for unresolved effects or missing or mismatched previous outputs.
    pub fn new_zip244_with_context(
        tx: TransactionData<A>,
        provider: &impl BundleDigestProvider,
        context: &impl TransparentAuthorizingContext<Zatoshis>,
    ) -> Result<Self, Zip244Error<A>> {
        if matches!(
            tx.version,
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4
        ) {
            return Err(Zip244Error::NotZip244(Box::new(tx)));
        }
        let inputs = match tx.transparent_bundle() {
            Some(bundle) => TransparentInputsDigests::for_bundle(tx.version, bundle, context),
            None => {
                let amounts = context.input_amounts().len();
                let scripts = context.input_scriptpubkeys().len();
                if amounts != 0 || scripts != 0 {
                    Err(V7DigestError::MissingTransparentInputContext {
                        expected: 0,
                        amounts,
                        scripts,
                    })
                } else {
                    Ok(None)
                }
            }
        }
        .map_err(Zip244Error::Digest)?;
        let digests = TxDigests::Zip244(
            tx.digest(TxIdDigester, provider)
                .map_err(Zip244Error::Digest)?,
        );
        Self::from_tx_digests(tx, digests, inputs).map_err(Zip244Error::Digest)
    }

    /// Combines the transaction with its effect and validated input digests.
    fn from_tx_digests(
        tx: TransactionData<A>,
        tx_digests: TxDigests<Blake2bHash>,
        transparent_inputs_digests: Option<TransparentInputsDigests>,
    ) -> Result<Self, V7DigestError> {
        #[cfg(zcash_unstable = "nu8")]
        let (transparent_inputs_digests, v7_txid) = if tx.version == TxVersion::V7 {
            let TxDigests::Zip244(parts) = &tx_digests else {
                unreachable!("version 7 uses ZIP 248 digests");
            };
            (
                Some(transparent_inputs_digests.unwrap_or_else(TransparentInputsDigests::empty)),
                Some(to_txid_v7(tx.consensus_branch_id.into(), parts)),
            )
        } else {
            (transparent_inputs_digests, None)
        };
        Ok(PrecomputedSighashData {
            tx,
            tx_digests,
            transparent_inputs_digests,
            #[cfg(zcash_unstable = "nu8")]
            v7_txid,
        })
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
    ///
    /// Also panics if the transaction is version 7 and `signable_input` is not
    /// `SignableInput::V7`, if a `SignableInput::V7` context is used with any earlier
    /// version, or if a `V7SignatureContext` index is out of range for its bundle
    /// or exceeds the two-byte index encoding.
    pub fn signature_hash(&self, signable_input: &SignableInput) -> SignatureHash {
        #[cfg(zcash_unstable = "nu8")]
        assert!(
            self.tx.version == TxVersion::V7 || !matches!(signable_input, SignableInput::V7(_)),
            "SignableInput::V7 requires a version 7 transaction",
        );
        let inputs_digests = self.transparent_inputs_digests.as_ref();
        SignatureHash(match &self.tx_digests {
            TxDigests::Zip143(digests) => v4_signature_hash(&self.tx, signable_input, digests),
            // v7 signs under ZIP 248, not the v6 sighash.
            #[cfg(zcash_unstable = "nu8")]
            TxDigests::Zip244(_) if matches!(self.tx.version, TxVersion::V7) => {
                let SignableInput::V7(context) = signable_input else {
                    panic!("version 7 signature hashes require SignableInput::V7");
                };
                v7_signature_hash_precomputed(
                    &self.tx,
                    context,
                    self.v7_txid.as_ref().expect("version 7 caches its txid"),
                    inputs_digests.expect("version 7 caches its input digests"),
                )
            }
            TxDigests::Zip244(txid_parts) if self.tx.version.has_ironwood() => {
                v6_signature_hash(&self.tx, signable_input, txid_parts, inputs_digests)
            }
            TxDigests::Zip244(txid_parts) => {
                v5_signature_hash(&self.tx, signable_input, txid_parts, inputs_digests)
            }
        })
    }
}

/// An error returned by ZIP 244 and later signature-hash precomputation.
#[non_exhaustive]
pub enum Zip244Error<A: Authorization> {
    /// Effects could not be digested or previous-output context was invalid.
    Digest(V7DigestError),
    /// The transaction is of version 4 or earlier, so its signature hashes are not
    /// [ZIP 244], [ZIP 229], or [ZIP 248] signature hashes. This holds the
    /// transaction, unchanged.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    /// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    NotZip244(Box<TransactionData<A>>),
}

impl<A: Authorization> fmt::Debug for Zip244Error<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Zip244Error::Digest(error) => f.debug_tuple("Digest").field(error).finish(),
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
            Zip244Error::Digest(error) => {
                write!(f, "could not compute transaction digests: {error}")
            }
            Zip244Error::NotZip244(tx) => write!(
                f,
                "transaction version {:?} does not use ZIP 244, ZIP 229, or ZIP 248 signature hashes",
                tx.version
            ),
        }
    }
}

impl<A: Authorization> core::error::Error for Zip244Error<A> {}

#[cfg(all(test, zcash_unstable = "nu8", feature = "sapling", feature = "orchard"))]
mod context_tests {
    use alloc::{vec, vec::Vec};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use transparent::{
        address::Script,
        bundle::{Bundle, OutPoint, TxIn},
        sighash::{SighashType, SignableInput as TransparentInput},
    };
    use zcash_protocol::{consensus::BranchId, value::Zatoshis};

    use super::{PrecomputedSighashData, SignableInput, V7SignatureContext, Zip244Error};
    use crate::transaction::{
        Authorization, Authorized, TransactionData, TxVersion,
        bytes::{
            OpaqueAuthBundleBytes, OpaqueEffectBundleBytes, V7AuthBundleBytes, V7EffectBundleBytes,
        },
        sighash_v5::TransparentInputsDigests,
        tests::{TestUnauthorized, with_test_transparent_auth},
        zip248::{
            BundleId, BundleType, BundleVariant, SuppliedBundleDigests, V7DigestError,
            ValuePoolDeltas,
        },
    };

    /// A synthetic unregistered bundle identifier.
    const UNKNOWN_BUNDLE: BundleId =
        BundleId::new(BundleType::from_u64(100), BundleVariant::DEFAULT);
    /// The byte length of a ZIP 248 per-bundle digest.
    const DIGEST_LENGTH: usize = 32;

    fn empty_tx(version: TxVersion) -> TransactionData<TestUnauthorized> {
        TransactionData::from_parts_with_value_pool_deltas(
            version,
            BranchId::Nu8,
            0,
            0.into(),
            ValuePoolDeltas::empty(),
            None,
            None,
            None,
            None,
            None,
            None,
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
        )
        .unwrap()
    }

    fn unrecognized_tx<A: Authorization>() -> TransactionData<A> {
        let effects = V7EffectBundleBytes::Opaque(
            OpaqueEffectBundleBytes::from_parts(UNKNOWN_BUNDLE, vec![]).unwrap(),
        );
        let auth = V7AuthBundleBytes::Opaque(
            OpaqueAuthBundleBytes::from_parts(UNKNOWN_BUNDLE, vec![]).unwrap(),
        );
        TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            0.into(),
            ValuePoolDeltas::empty(),
            None,
            None,
            None,
            None,
            None,
            None,
            [(UNKNOWN_BUNDLE.bundle_type(), effects)]
                .into_iter()
                .collect(),
            [(UNKNOWN_BUNDLE.bundle_type(), auth)].into_iter().collect(),
        )
        .unwrap()
    }

    #[test]
    fn unrecognized_sighash_bundles_require_effects_but_not_auth_digests() {
        assert!(matches!(
            PrecomputedSighashData::new(unrecognized_tx::<TestUnauthorized>(), &()),
            Err(V7DigestError::MissingEffectsDigest { key }) if key == UNKNOWN_BUNDLE
        ));
        assert!(matches!(
            PrecomputedSighashData::new_zip244(unrecognized_tx::<TestUnauthorized>(), &()),
            Err(Zip244Error::Digest(V7DigestError::MissingEffectsDigest { key }))
                if key == UNKNOWN_BUNDLE
        ));

        let mut provider = SuppliedBundleDigests::new();
        provider
            .insert_effects(
                UNKNOWN_BUNDLE,
                blake2b_simd::Params::new()
                    .hash_length(DIGEST_LENGTH)
                    .hash(b"first"),
            )
            .unwrap();
        let first =
            PrecomputedSighashData::new(unrecognized_tx::<TestUnauthorized>(), &provider).unwrap();
        let zip244 =
            PrecomputedSighashData::new_zip244(unrecognized_tx::<TestUnauthorized>(), &provider)
                .unwrap();
        let context = SignableInput::V7(V7SignatureContext::SaplingBinding);
        assert_eq!(
            first.signature_hash(&context).as_ref(),
            zip244.signature_hash(&context).as_ref()
        );
        let mut provider = SuppliedBundleDigests::new();
        provider
            .insert_effects(
                UNKNOWN_BUNDLE,
                blake2b_simd::Params::new()
                    .hash_length(DIGEST_LENGTH)
                    .hash(b"second"),
            )
            .unwrap();
        let second =
            PrecomputedSighashData::new(unrecognized_tx::<TestUnauthorized>(), &provider).unwrap();
        assert_ne!(
            first.signature_hash(&context).as_ref(),
            second.signature_hash(&context).as_ref()
        );
    }

    #[test]
    fn new_zip244_retains_pre_zip244_transaction() {
        let tx = empty_tx(TxVersion::V4);
        match PrecomputedSighashData::new_zip244(tx, &()) {
            Err(Zip244Error::NotZip244(tx)) => {
                assert_eq!(tx.version(), TxVersion::V4);
                assert_eq!(tx.consensus_branch_id(), BranchId::Nu8);
                assert_eq!(tx.lock_time(), 0);
                assert!(tx.transparent_bundle().is_none());
            }
            _ => panic!("pre-ZIP 244 transaction must be returned unchanged"),
        }
    }

    #[test]
    fn new_zip244_accepts_proof_free_authorization() {
        let mut provider = SuppliedBundleDigests::new();
        provider
            .insert_effects(
                UNKNOWN_BUNDLE,
                blake2b_simd::Params::new()
                    .hash_length(DIGEST_LENGTH)
                    .hash(b"effects"),
            )
            .unwrap();
        assert!(
            PrecomputedSighashData::new_zip244_with_context(
                unrecognized_tx::<crate::transaction::EffectsOnly>(),
                &provider,
                &transparent::sighash::TransparentSigningContext::new(vec![])
            )
            .is_ok()
        );
    }

    fn panic_message(f: impl FnOnce()) -> alloc::string::String {
        let panic = catch_unwind(AssertUnwindSafe(f)).expect_err("must reject mismatched context");
        if let Some(message) = panic.downcast_ref::<&str>() {
            (*message).into()
        } else {
            panic
                .downcast_ref::<alloc::string::String>()
                .unwrap()
                .clone()
        }
    }

    #[test]
    fn v7_context_rejects_every_pre_v7_version() {
        for version in [
            TxVersion::Sprout(1),
            TxVersion::Sprout(2),
            TxVersion::V3,
            TxVersion::V4,
            TxVersion::V5,
            TxVersion::V6,
        ] {
            let data = PrecomputedSighashData::new(empty_tx(version), &()).unwrap();
            assert_eq!(
                panic_message(|| {
                    data.signature_hash(&SignableInput::V7(V7SignatureContext::SaplingBinding));
                }),
                "SignableInput::V7 requires a version 7 transaction",
            );
        }
    }

    #[test]
    fn v7_rejects_legacy_contexts_without_disclosing_input_data() {
        let bundle = Bundle {
            vin: vec![TxIn::from_parts(
                OutPoint::fake(),
                Script::default(),
                u32::MAX,
            )],
            vout: Vec::new(),
            authorization: transparent::bundle::Authorized,
        };
        let tx = TransactionData::<Authorized>::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            0.into(),
            ValuePoolDeltas::empty(),
            Some(bundle),
            None,
            None,
            None,
            None,
            None,
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
        )
        .unwrap();
        let data = PrecomputedSighashData::new(
            with_test_transparent_auth(tx, vec![Zatoshis::ZERO], vec![Script::default()]),
            &(),
        )
        .unwrap();
        let script = Script::default();
        let input = || {
            TransparentInput::from_parts(
                data.tx().transparent_bundle().unwrap(),
                SighashType::ALL,
                0,
                &script,
                &script,
                Zatoshis::ZERO,
            )
            .unwrap()
        };
        for context in [SignableInput::Shielded, SignableInput::Transparent(input())] {
            assert_eq!(
                panic_message(|| {
                    data.signature_hash(&context);
                }),
                "version 7 signature hashes require SignableInput::V7",
            );
        }
        assert!(matches!(
            SignableInput::transparent(TxVersion::V7, input()),
            SignableInput::V7(V7SignatureContext::Transparent(_)),
        ));
        assert!(matches!(
            SignableInput::transparent(TxVersion::V6, input()),
            SignableInput::Transparent(_),
        ));
    }

    #[test]
    fn v7_null_prevout_commits_input_amounts_and_scripts() {
        /// A nonzero input amount distinguishes the spent coin from the empty list.
        const INPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(7_000);
        // Independently calculated with Python hashlib.blake2b from ZIP 248
        // T.1–T.3 and S.1–S.7, for a null prevout, maximal sequence, empty script,
        // zero lock/expiry heights, and no value-pool deltas or shielded bundles.
        const TXID: &str = "85148ab86193ca6e87e022a63bc4594ed6916169325c48fde5bb959217fcb788";
        const AMOUNTS: &str = "159131ef4b3c5ecf0a3af9e77cf3413e82d1a8c7316456f76c31228a382420b6";
        const SCRIPTS: &str = "7483749f88de7959e1b406eb5064410a2324b83bf1f51d17e1cb7e8b5c3038de";
        const SIGHASH: &str = "b36da24bb839b289ce3adc410bade676d6a4e30099429a4d77a8589f6313de26";

        let tx = TransactionData::<Authorized>::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            0,
            0.into(),
            ValuePoolDeltas::empty(),
            Some(Bundle {
                vin: vec![TxIn::from_parts(
                    OutPoint::NULL,
                    Script::default(),
                    u32::MAX,
                )],
                vout: Vec::new(),
                authorization: transparent::bundle::Authorized,
            }),
            None,
            None,
            None,
            None,
            None,
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
        )
        .unwrap();
        let data = PrecomputedSighashData::new(
            with_test_transparent_auth(tx, vec![INPUT_VALUE], vec![Script::default()]),
            &(),
        )
        .unwrap();
        let bundle = data.tx().transparent_bundle().unwrap();
        assert!(
            TransparentInputsDigests::for_bundle(TxVersion::V5, bundle, &bundle.authorization)
                .unwrap()
                .is_none()
        );
        assert!(
            TransparentInputsDigests::for_bundle(TxVersion::V6, bundle, &bundle.authorization)
                .unwrap()
                .is_none()
        );
        assert!(
            TransparentInputsDigests::for_bundle(TxVersion::V7, bundle, &bundle.authorization)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            data.v7_txid.unwrap().as_ref().as_slice(),
            hex::decode(TXID).unwrap()
        );
        let inputs = data.transparent_inputs_digests.as_ref().unwrap();
        assert_eq!(inputs.amounts().as_bytes(), hex::decode(AMOUNTS).unwrap());
        assert_eq!(inputs.scripts().as_bytes(), hex::decode(SCRIPTS).unwrap());
        let context = SignableInput::V7(V7SignatureContext::SaplingBinding);
        assert_eq!(
            data.signature_hash(&context).as_ref().as_slice(),
            hex::decode(SIGHASH).unwrap()
        );
        assert_eq!(
            data.signature_hash(&context).as_ref().as_slice(),
            hex::decode(SIGHASH).unwrap()
        );
    }

    #[test]
    fn v7_without_transparent_inputs_caches_empty_digests() {
        let data = PrecomputedSighashData::new(empty_tx(TxVersion::V7), &()).unwrap();
        assert!(data.v7_txid.is_some());
        let inputs = data.transparent_inputs_digests.as_ref().unwrap();
        let empty = TransparentInputsDigests::empty();
        assert_eq!(inputs.amounts(), empty.amounts());
        assert_eq!(inputs.scripts(), empty.scripts());
        let context = SignableInput::V7(V7SignatureContext::SaplingBinding);
        assert_eq!(
            data.signature_hash(&context).as_ref(),
            data.signature_hash(&context).as_ref()
        );
        for version in [TxVersion::V5, TxVersion::V6] {
            let data = PrecomputedSighashData::new(empty_tx(version), &()).unwrap();
            assert!(data.v7_txid.is_none());
            assert!(data.transparent_inputs_digests.is_none());
        }
    }
}
