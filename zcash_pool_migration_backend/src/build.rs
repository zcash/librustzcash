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

use core::fmt;

use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
use zcash_primitives::transaction::builder::PcztParts;
use zcash_protocol::consensus::Parameters;

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
}
