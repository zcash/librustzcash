//! Constructing the migration transactions as unproven PCZTs, and pre-signing them.
//!
//! [`build_prep_tx`] builds a note-preparation transaction (restructuring the wallet's notes into the
//! self-funding notes a migration run needs), [`build_transfer_pczt`] builds a value-crossing
//! transfer, and [`sign_pczt`] adds the Orchard spend-authorization signatures up front. Each builder
//! runs purely on the transaction [`Builder`](zcash_primitives::transaction::builder::Builder): no
//! database or wallet-backend access. Selecting the notes to spend and resolving their witnesses and
//! the anchor are the wallet backend's job, done separately; here they are inputs, and the returned
//! PCZT is still to be proven and finalized.
//!
//! The shared transaction-builder plumbing (building the config, finishing the PCZT through the
//! [`Creator`]/[`IoFinalizer`] roles, un-shuffling output positions) lives in this module root, so
//! every builder reuses it.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use core::fmt;

use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater};
use zcash_primitives::transaction::builder::PcztParts;
use zcash_protocol::consensus::{NetworkConstants, Parameters};
use zip32::fingerprint::SeedFingerprint;

mod prep;
mod sign;
mod transfer;
pub use prep::{PlacedPrepOutput, build_prep_tx};
pub use sign::sign_pczt;
pub use transfer::build_transfer_pczt;

#[cfg(test)]
mod end_to_end;

/// An error building a migration PCZT.
#[derive(Debug)]
pub enum BuildError {
    /// The requested outputs cannot be balanced against the selected inputs (the real fee versus the
    /// planned outputs).
    Balance(String),
    /// The transaction builder or the PCZT assembly pipeline failed.
    Build(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Balance(m) => write!(f, "cannot balance the transaction: {m}"),
            BuildError::Build(m) => write!(f, "pczt build failed: {m}"),
        }
    }
}

impl core::error::Error for BuildError {}

/// The ZIP 32 account whose spending key authorizes a migration's Orchard spends.
///
/// This is what an external Signer matches on to recognize a spend as the account's, so a wallet
/// that delegates signing must supply it to the builders. Only the network-independent part of the
/// derivation is held: the builders compose the full Orchard path `m/32'/coin_type'/account'` from
/// their own consensus parameters, so a caller cannot address a migration to the wrong coin type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDerivation {
    seed_fingerprint: SeedFingerprint,
    account_index: zip32::AccountId,
}

impl AccountDerivation {
    /// The account at `account_index` under the seed with the given fingerprint.
    pub fn new(seed_fingerprint: SeedFingerprint, account_index: zip32::AccountId) -> Self {
        Self {
            seed_fingerprint,
            account_index,
        }
    }

    /// The [ZIP 32 seed fingerprint](https://zips.z.cash/zip-0032#seed-fingerprints) of the seed
    /// the account is derived from.
    pub fn seed_fingerprint(&self) -> &SeedFingerprint {
        &self.seed_fingerprint
    }

    /// The account-level index in the ZIP 32 derivation path.
    pub fn account_index(&self) -> zip32::AccountId {
        self.account_index
    }

    /// This account's Orchard PCZT derivation metadata on the network `params` describes: the ZIP
    /// 32 path `m/32'/coin_type'/account'`.
    fn to_pczt_derivation<P: Parameters>(&self, params: &P) -> orchard::pczt::Zip32Derivation {
        orchard::pczt::Zip32Derivation::parse(
            self.seed_fingerprint.to_bytes(),
            vec![
                zip32::ChildIndex::hardened(32).index(),
                zip32::ChildIndex::hardened(params.network_type().coin_type()).index(),
                zip32::ChildIndex::hardened(u32::from(self.account_index)).index(),
            ],
        )
        .expect("the standard Orchard account path is a valid derivation")
    }
}

/// A wallet's account derivation identifies the same account here. The migration keeps its own
/// type so the builders stay independent of the wallet layer; this conversion is what lets a
/// `zcash_client_backend`-backed wallet hand its account record straight to them.
#[cfg(feature = "wallet")]
impl From<&zcash_client_backend::data_api::Zip32Derivation> for AccountDerivation {
    fn from(derivation: &zcash_client_backend::data_api::Zip32Derivation) -> Self {
        AccountDerivation::new(*derivation.seed_fingerprint(), derivation.account_index())
    }
}

/// Finish an unproven PCZT from the transaction builder's parts: run the [`Creator`] and
/// [`IoFinalizer`] roles, then stamp `account_derivation` (when known) onto every spend that
/// still needs a signature.
///
/// The stamping runs through the [`Updater`] role AFTER IO finalization, and stamps exactly those
/// actions whose spend has no `spend_auth_sig`. That predicate is what distinguishes the two kinds
/// of dummy the Orchard builder produces: the protocol PADDING dummies hold a random spending key
/// that the IO Finalizer signs with and then clears, so they are already signed and need no
/// derivation; the WALLET-CONTROLLED zero-value spends that the post-NU6.3 builder pairs with each
/// internal change output (the vanilla-pool cross-address rule precludes random-keyed dummies
/// there) are spent with the account's own key and must be signed through the normal signing flow,
/// exactly like the real spends. Without the derivation, a Signer that matches spends by
/// derivation path correctly skips them as "not ours", nothing else can sign them, and extracting
/// the transaction fails with a missing spend-auth signature.
pub(crate) fn finalize_pczt<P: Parameters>(
    params: &P,
    parts: PcztParts<P>,
    account_derivation: Option<&AccountDerivation>,
) -> Result<pczt::Pczt, BuildError> {
    let created = Creator::build_from_parts(parts)
        .ok_or_else(|| BuildError::Build("pczt creation failed".into()))?;
    let finalized = IoFinalizer::new(created)
        .finalize_io()
        .map_err(|e| BuildError::Build(format!("io finalize: {e:?}")))?;

    let Some(derivation) = account_derivation else {
        return Ok(finalized);
    };

    /// Stamps the account's derivation on every action of one bundle whose spend still needs a
    /// signature. The `spend_auth_sig` state is read before entering the action updater, which
    /// borrows the bundle mutably.
    fn stamp<P: Parameters>(
        mut updater: orchard::pczt::Updater<'_>,
        params: &P,
        derivation: &AccountDerivation,
    ) -> Result<(), orchard::pczt::UpdaterError> {
        let needs_signature = updater
            .bundle()
            .actions()
            .iter()
            .map(|action| action.spend().spend_auth_sig().is_none())
            .collect::<Vec<_>>();

        for (index, needs_signature) in needs_signature.into_iter().enumerate() {
            if needs_signature {
                updater.update_action_with(index, |mut action| {
                    // Every spend a migration transaction needs authorized belongs to the one
                    // account it migrates.
                    action.set_spend_zip32_derivation(derivation.to_pczt_derivation(params));
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    Updater::new(finalized)
        .update_orchard_with(|updater| stamp(updater, params, derivation))
        .map_err(|e| BuildError::Build(format!("stamp orchard derivation: {e:?}")))?
        .update_ironwood_with(|updater| stamp(updater, params, derivation))
        .map_err(|e| BuildError::Build(format!("stamp ironwood derivation: {e:?}")))
        .map(|updater| updater.finish())
}

/// Map an output's request-order position to its real Orchard action index. The Orchard builder
/// shuffles action positions, so the caller must look up where each requested output landed.
pub(crate) fn output_action_index(
    meta: &orchard::builder::BundleMetadata,
    output: usize,
) -> Result<u32, BuildError> {
    meta.output_action_index(output)
        .map(|i| i as u32)
        .ok_or_else(|| BuildError::Build(format!("no action index for output {output}")))
}

/// Test helpers shared by the split and transfer builders: a deterministic account, regtest network
/// params, and a single-leaf Orchard witness. The seed-derived key, network, and witness helpers now
/// live in the `zcash_pool_migration_memory` test-support crate and are re-exported here so both
/// submodules' tests reuse them without change.
#[cfg(test)]
pub(crate) mod test_util {
    use orchard::keys::FullViewingKey;

    pub(crate) use zcash_pool_migration_memory::{
        TARGET_HEIGHT, regtest_network, shared_anchor_witnesses, single_note_witness, spending_key,
    };

    /// An account's Orchard full viewing key (see [`spending_key`]).
    pub(crate) fn account(seed: u64) -> FullViewingKey {
        FullViewingKey::from(&spending_key(seed))
    }

    /// The ZIP 32 account derivation a wallet seeded with `seed` would report for the account
    /// [`account`] views. Defined here rather than reused from `zcash_pool_migration_memory`
    /// because that crate links this one as a library, so its `AccountDerivation` is a distinct
    /// type from the one this crate's own test build sees.
    pub(crate) fn account_derivation(seed: u64) -> super::AccountDerivation {
        let mut seed_fingerprint = [0u8; 32];
        seed_fingerprint[..8].copy_from_slice(&seed.to_le_bytes());
        super::AccountDerivation::new(
            zip32::fingerprint::SeedFingerprint::from_bytes(seed_fingerprint),
            zip32::AccountId::ZERO,
        )
    }

    /// How signable a built migration PCZT is, across both its Orchard and Ironwood bundles, as
    /// `(needing a signature, of those, unidentifiable)`.
    ///
    /// An action needs a signature unless it is ALREADY SIGNED (a protocol padding dummy, which
    /// the IO Finalizer signs with its throwaway key and then clears). One that needs a signature
    /// is IDENTIFIABLE if it carries ZIP 32 derivation metadata, which is what lets an external
    /// Signer that matches spends by derivation path recognize it as the account's. An action that
    /// needs a signature and carries no derivation is one such a Signer skips as "not ours",
    /// nothing else can sign, and whose transaction therefore fails to extract.
    ///
    /// The first count guards against a vacuous pass: a bundle of nothing but pre-signed dummies
    /// has no unidentifiable spends while exercising nothing.
    pub(crate) fn spend_signability(pczt: &pczt::Pczt) -> (usize, usize) {
        fn count(bundle: &orchard::pczt::Bundle, unsigned: &mut usize, unidentifiable: &mut usize) {
            for action in bundle.actions() {
                if action.spend().spend_auth_sig().is_some() {
                    continue;
                }
                *unsigned += 1;
                if action.spend().zip32_derivation().is_none() {
                    *unidentifiable += 1;
                }
            }
        }

        let (mut unsigned, mut unidentifiable) = (0, 0);
        pczt::roles::verifier::Verifier::new(pczt.clone())
            .with_orchard::<core::convert::Infallible, _>(|bundle| {
                count(bundle, &mut unsigned, &mut unidentifiable);
                Ok(())
            })
            .expect("the Orchard bundle parses")
            .with_ironwood::<core::convert::Infallible, _>(|bundle| {
                count(bundle, &mut unsigned, &mut unidentifiable);
                Ok(())
            })
            .expect("the Ironwood bundle parses");
        (unsigned, unidentifiable)
    }

    /// Asserts that every spend of `pczt` still needing a signature is identifiable to an external
    /// Signer (see [`spend_signability`]), and returns how many such spends there are.
    pub(crate) fn assert_every_spend_is_identifiable(pczt: &pczt::Pczt) -> usize {
        let (unsigned, unidentifiable) = spend_signability(pczt);
        assert_eq!(
            unidentifiable, 0,
            "{unidentifiable} of {unsigned} spends awaiting a signature carry no ZIP 32 \
             derivation, so no external Signer can identify them as the account's",
        );
        unsigned
    }
}
