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
mod transfer;
pub use split::{SplitOutputs, build_split_pczt, build_split_pczt_for_plan};
pub use transfer::build_transfer_pczt;

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

/// Test helpers shared by the split and transfer builders: a deterministic account, regtest network
/// params, and a single-leaf Orchard witness. Kept here so both submodules' tests reuse them.
#[cfg(test)]
pub(crate) mod test_util {
    use incrementalmerkletree::{Hashable, Level};
    use orchard::Anchor;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
    use orchard::tree::{MerkleHashOrchard, MerklePath};
    use orchard::value::NoteValue;
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::local_consensus::LocalNetwork;

    /// An account's Orchard full viewing key, deterministic across the tests.
    pub(crate) fn account() -> FullViewingKey {
        let sk = SpendingKey::from_bytes([7u8; 32]).unwrap();
        FullViewingKey::from(&sk)
    }

    /// A regtest network with the pre-NU6.3 upgrades active, and NU6.3 active only when requested.
    /// The migration builds on a network where NU6.3 (the Ironwood pool) is live.
    pub(crate) fn regtest_network(nu6_3_active: bool) -> LocalNetwork {
        let nu6_3 = if nu6_3_active {
            Some(BlockHeight::from_u32(10))
        } else {
            None
        };
        LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3,
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
        }
    }

    /// An Orchard note owned by `fvk`, with a valid witness placing it as the sole leaf of an
    /// otherwise-empty note-commitment tree, and the matching anchor. The authentication path uses
    /// the empty-subtree roots for a single leaf at position 0, so `add_orchard_spend`'s anchor
    /// check (`path.root(cmx) == anchor`) accepts it.
    pub(crate) fn single_note_witness(
        fvk: &FullViewingKey,
        value: u64,
    ) -> (Note, MerklePath, Anchor) {
        let recipient = fvk.address_at(0u32, Scope::External);
        let note_value = NoteValue::from_raw(value);
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note = Note::from_parts(recipient, note_value, rho, rseed, NoteVersion::V2).unwrap();

        let commitment = note.commitment();
        let cmx = ExtractedNoteCommitment::from(commitment);
        let auth_path = core::array::from_fn(|level| {
            let level = Level::from(level as u8);
            MerkleHashOrchard::empty_root(level)
        });
        let position = 0;
        let path = MerklePath::from_parts(position, auth_path);
        let anchor = path.root(cmx);
        (note, path, anchor)
    }
}
