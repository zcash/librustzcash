//! The Transaction Extractor role (anyone can execute).
//!
//! - Creates bindingSig and extracts the final transaction.

use alloc::vec::Vec;
use core::{cell::RefCell, marker::PhantomData};
use rand_core::{CryptoRng, Rng};

use zcash_primitives::transaction::{
    Authorization, Transaction,
    sighash::{PrecomputedSighashData, SignableInput},
};

#[cfg(zcash_unstable = "nu8")]
use ::transparent::sighash::TransparentAuthorizingContext;

#[cfg(zcash_unstable = "nu8")]
use zcash_primitives::transaction::sighash::V7SignatureContext;

use crate::Pczt;

/// The per-index and binding signature hashes of the bundles of a version 7 transaction.
struct V7ExtractorSighashes {
    sapling: Option<(Vec<[u8; 32]>, [u8; 32])>,
    orchard: Option<(Vec<[u8; 32]>, [u8; 32])>,
    ironwood: Option<(Vec<[u8; 32]>, [u8; 32])>,
}

mod orchard;
pub use self::orchard::OrchardError;
pub type IronwoodError = OrchardError;

mod sapling;
pub use self::sapling::SaplingError;

mod transparent;
pub use self::transparent::TransparentError;

pub struct TransactionExtractor<'a> {
    pczt: Pczt,
    sapling_vk: Option<(
        &'a ::sapling::circuit::SpendVerifyingKey,
        &'a ::sapling::circuit::OutputVerifyingKey,
    )>,
    orchard_vk: Option<&'a ::orchard::circuit::VerifyingKey>,
    _unused: PhantomData<&'a ()>,
}

impl<'a> TransactionExtractor<'a> {
    /// Instantiates the Transaction Extractor role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self {
            pczt,
            sapling_vk: None,
            orchard_vk: None,
            _unused: PhantomData,
        }
    }

    /// Provides the Sapling Spend and Output verifying keys for validating the Sapling
    /// proofs (if any).
    ///
    /// If not provided, and the PCZT has a Sapling bundle, [`Self::extract`] will return
    /// an error.
    pub fn with_sapling(
        mut self,
        spend_vk: &'a ::sapling::circuit::SpendVerifyingKey,
        output_vk: &'a ::sapling::circuit::OutputVerifyingKey,
    ) -> Self {
        self.sapling_vk = Some((spend_vk, output_vk));
        self
    }

    /// Provides an existing Orchard verifying key for validating the Orchard proof (if
    /// any).
    ///
    /// If not provided, and the PCZT has an Orchard bundle, an Orchard verifying key will
    /// be generated on the fly.
    pub fn with_orchard(mut self, orchard_vk: &'a ::orchard::circuit::VerifyingKey) -> Self {
        self.orchard_vk = Some(orchard_vk);
        self
    }

    /// Attempts to extract a valid transaction from the PCZT.
    ///
    /// `rng` provides the randomness for the binding signatures and for the batch
    /// validation of the extracted transaction.
    pub fn extract<R: Rng + CryptoRng>(self, mut rng: R) -> Result<Transaction, Error> {
        let Self {
            pczt,
            sapling_vk,
            orchard_vk,
            _unused,
        } = self;

        let crate::ParsedPczt { tx_data, .. } = pczt.extract_tx_data::<Unbound, Error>(
            crate::common::AnchorRequirement::Required,
            |t| {
                t.extract()
                    .map_err(|e| Error::Transparent(TransparentError::Extract(e)))
            },
            |s| {
                s.extract()
                    .map_err(|e| Error::Sapling(SaplingError::Extract(e)))
            },
            |o| {
                o.extract()
                    .map_err(|e| Error::Orchard(OrchardError::Extract(e)))
            },
            |i| {
                i.extract()
                    .map_err(|e| Error::Ironwood(IronwoodError::Extract(e)))
            },
        )?;

        // The commitment being signed is shared across all shielded inputs before
        // version 7; version 7 gives each Spend, action and binding signature its own
        // digest, so compute those before the transaction is consumed.
        let sighash_data = PrecomputedSighashData::new(tx_data);
        #[cfg(zcash_unstable = "nu8")]
        let is_v7 = matches!(
            sighash_data.tx().version(),
            zcash_primitives::transaction::TxVersion::V7
        );
        #[cfg(not(zcash_unstable = "nu8"))]
        let is_v7 = false;
        let shielded_sighash = (!is_v7).then(|| {
            *sighash_data
                .signature_hash(&SignableInput::Shielded)
                .as_ref()
        });

        #[cfg(zcash_unstable = "nu8")]
        let v7_sighashes = is_v7.then(|| V7ExtractorSighashes {
            sapling: sighash_data.tx().sapling_bundle().map(|b| {
                v7_bundle_sighashes(
                    &sighash_data,
                    b.shielded_spends().len(),
                    |index| V7SignatureContext::SaplingSpend { index },
                    V7SignatureContext::SaplingBinding,
                )
            }),
            orchard: sighash_data.tx().orchard_bundle().map(|b| {
                v7_bundle_sighashes(
                    &sighash_data,
                    b.actions().len(),
                    |index| V7SignatureContext::OrchardAction { index },
                    V7SignatureContext::OrchardBinding,
                )
            }),
            ironwood: sighash_data.tx().ironwood_bundle().map(|b| {
                v7_bundle_sighashes(
                    &sighash_data,
                    b.actions().len(),
                    |index| V7SignatureContext::IronwoodAction { index },
                    V7SignatureContext::IronwoodBinding,
                )
            }),
        });
        #[cfg(not(zcash_unstable = "nu8"))]
        let v7_sighashes: Option<V7ExtractorSighashes> = None;

        let tx_data = sighash_data.into_tx();

        let sapling_sighashes = v7_sighashes
            .as_ref()
            .and_then(|s| s.sapling.as_ref())
            .map(|(spends, binding)| (spends.as_slice(), *binding));
        let orchard_sighashes = v7_sighashes
            .as_ref()
            .and_then(|s| s.orchard.as_ref())
            .map(|(actions, binding)| (actions.as_slice(), *binding));
        let ironwood_sighashes = v7_sighashes
            .as_ref()
            .and_then(|s| s.ironwood.as_ref())
            .map(|(actions, binding)| (actions.as_slice(), *binding));

        // Create the binding signatures. The bundle mappers each need the RNG, and
        // `try_map_bundles` calls them one at a time.
        let binding_rng = RefCell::new(&mut rng);
        let tx_data = tx_data.try_map_bundles(
            |t| Ok(t.map(|t| t.map_authorization(transparent::RemoveInputInfo))),
            |s| {
                s.map(|s| {
                    if let Some((spend_sighashes, binding_sighash)) = sapling_sighashes {
                        return s
                            .apply_binding_signature_with_sighashes(
                                spend_sighashes,
                                binding_sighash,
                                &mut **binding_rng.borrow_mut(),
                            )
                            .ok_or(Error::SighashMismatch);
                    }
                    s.apply_binding_signature(
                        shielded_sighash.expect("pre-v7 signs a shared shielded digest"),
                        &mut **binding_rng.borrow_mut(),
                    )
                    .ok_or(Error::SighashMismatch)
                })
                .transpose()
            },
            |o| {
                // `try_map_bundles` applies this closure to the Orchard bundle and then
                // the Ironwood bundle, which have distinct digests. The bundle's own pool
                // selects which set applies.
                o.map(|o| {
                    let sighashes = match o.bundle_version().value_pool() {
                        ::orchard::ValuePool::Orchard => orchard_sighashes,
                        ::orchard::ValuePool::Ironwood => ironwood_sighashes,
                    };
                    if let Some((action_sighashes, binding_sighash)) = sighashes {
                        return o
                            .apply_binding_signature_with_sighashes(
                                action_sighashes,
                                binding_sighash,
                                &mut **binding_rng.borrow_mut(),
                            )
                            .ok_or(Error::SighashMismatch);
                    }
                    o.apply_binding_signature(
                        shielded_sighash.expect("pre-v7 signs a shared shielded digest"),
                        &mut **binding_rng.borrow_mut(),
                    )
                    .ok_or(Error::SighashMismatch)
                })
                .transpose()
            },
        )?;

        let tx = tx_data.freeze().expect("txid construction can't fail here");

        // Now that we have a supposedly fully-authorized transaction, verify it.
        if let Some(bundle) = tx.sapling_bundle() {
            let (spend_vk, output_vk) = sapling_vk.ok_or(Error::SaplingRequired)?;

            sapling::verify_bundle(
                &mut rng,
                bundle,
                spend_vk,
                output_vk,
                shielded_sighash,
                sapling_sighashes,
            )
            .map_err(Error::Sapling)?;
        }
        if let Some(bundle) = tx.orchard_bundle() {
            orchard::verify_bundle(
                &mut rng,
                bundle,
                orchard_vk,
                shielded_sighash,
                orchard_sighashes,
            )
            .map_err(Error::Orchard)?;
        }
        if let Some(bundle) = tx.ironwood_bundle() {
            orchard::verify_bundle(
                &mut rng,
                bundle,
                orchard_vk,
                shielded_sighash,
                ironwood_sighashes,
            )
            .map_err(Error::Ironwood)?;
        }

        Ok(tx)
    }
}

/// Computes the signature hash of every Spend or action of a bundle, plus that of its
/// binding signature.
#[cfg(zcash_unstable = "nu8")]
fn v7_bundle_sighashes<TA, A>(
    sighash_data: &PrecomputedSighashData<A>,
    count: usize,
    index_context: impl Fn(usize) -> V7SignatureContext<'static>,
    binding_context: V7SignatureContext<'static>,
) -> (Vec<[u8; 32]>, [u8; 32])
where
    TA: TransparentAuthorizingContext<zcash_protocol::value::Zatoshis>,
    A: Authorization<TransparentAuth = TA>,
{
    let spends = (0..count)
        .map(|index| {
            *sighash_data
                .signature_hash(&SignableInput::V7(index_context(index)))
                .as_ref()
        })
        .collect();
    let binding = *sighash_data
        .signature_hash(&SignableInput::V7(binding_context))
        .as_ref();
    (spends, binding)
}

struct Unbound;

impl Authorization for Unbound {
    type TransparentAuth = ::transparent::pczt::Unbound<zcash_protocol::value::Zatoshis>;
    type SaplingAuth = ::sapling::pczt::Unbound;
    type OrchardAuth = ::orchard::pczt::Unbound;
}

/// Errors that can occur while extracting a transaction from a PCZT.
#[derive(Debug)]
pub enum Error {
    Extract(crate::ExtractError),
    Ironwood(IronwoodError),
    Orchard(OrchardError),
    Sapling(SaplingError),
    SaplingRequired,
    SighashMismatch,
    Transparent(TransparentError),
}

impl From<crate::ExtractError> for Error {
    fn from(e: crate::ExtractError) -> Self {
        Error::Extract(e)
    }
}
