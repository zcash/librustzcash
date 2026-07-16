//! Building the migration's note-split transaction as an unproven PCZT.
//!
//! [`build_split_pczt`] takes a note-split plan (the self-funding note values) plus the cryptographic
//! ingredients a wallet backend supplies (the spendable Orchard notes and their witnesses, the
//! anchor, the full viewing key) and assembles the same-pool Orchard send-to-self that mints one
//! self-funding note per planned denomination (plus a plain change output for any leftover),
//! returning the unproven [`pczt::Pczt`] and a [`SplitOutputs`] map from each output to its real
//! Orchard action index. It runs purely on the transaction
//! [`Builder`](zcash_primitives::transaction::builder::Builder): no database or wallet-backend
//! access. Selecting the notes to spend and resolving their witnesses and the anchor are the wallet
//! backend's job, done separately; here they are inputs, and the returned PCZT is still to be proven,
//! signed, and finalized.
//!
//! The transaction-builder plumbing (building the config, finishing the PCZT through the
//! [`Creator`]/[`IoFinalizer`] roles, un-shuffling output positions, the ZIP-317 marginal fee) lives
//! in this module root, so the value-crossing transaction can reuse it when it is added.

use core::fmt;

use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
use zcash_primitives::transaction::builder::{BuildConfig, PcztParts};
use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
use zcash_protocol::consensus::Parameters;

mod split;
pub use split::{SplitOutputs, build_split_pczt, build_split_pczt_for_plan};

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

impl std::error::Error for BuildError {}

/// The ZIP-317 marginal fee (in zatoshi) per logical action.
pub(crate) fn marginal_fee_zatoshi() -> u64 {
    MARGINAL_FEE.into_u64()
}

/// The [`BuildConfig`] shared by the migration transactions: an Orchard-anchored bundle, with the
/// destination-pool (Ironwood) bundle anchored only when that phase produces a crossing output
/// (`None` for the same-pool note split).
pub(crate) fn build_config(
    orchard_anchor: orchard::Anchor,
    ironwood_anchor: Option<orchard::Anchor>,
) -> BuildConfig {
    BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(orchard_anchor),
        ironwood_anchor,
        orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
        ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
    }
}

/// Finish an unproven PCZT from the transaction builder's parts: run the [`Creator`] and
/// [`IoFinalizer`] roles.
pub(crate) fn finalize_pczt<P: Parameters>(parts: PcztParts<P>) -> Result<pczt::Pczt, BuildError> {
    let created = Creator::build_from_parts(parts)
        .ok_or_else(|| BuildError::Build("pczt creation failed".into()))?;
    IoFinalizer::new(created)
        .finalize_io()
        .map_err(|e| BuildError::Build(format!("io finalize: {e:?}")))
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
