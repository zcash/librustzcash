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
/// params, and a single-leaf Orchard witness. Kept here so both submodules' tests reuse them.
#[cfg(test)]
pub(crate) mod test_util {
    use alloc::vec::Vec;

    use incrementalmerkletree::{Hashable, Level};
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
    use orchard::tree::{MerkleHashOrchard, MerklePath};
    use orchard::value::NoteValue;
    use orchard::{Anchor, NOTE_COMMITMENT_TREE_DEPTH};
    use rand_chacha::ChaCha8Rng;
    use rand_core::{RngCore, SeedableRng};
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::local_consensus::LocalNetwork;

    /// 32 random bytes from a `seed`-derived RNG, keeping calls deterministic per case.
    fn draw_bytes(rng: &mut ChaCha8Rng) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// A post-NU6.3 height (past the regtest NU6.3 activation) at which the migration transactions
    /// are built and their fees computed.
    pub(crate) const TARGET_HEIGHT: u32 = 100;

    /// An account's Orchard spending key, derived from `seed` so tests can vary the account across
    /// proptest cases. Draws bytes until they form a valid spending key.
    pub(crate) fn spending_key(seed: u64) -> SpendingKey {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        loop {
            let bytes = draw_bytes(&mut rng);
            if let Some(sk) = SpendingKey::from_bytes(bytes).into_option() {
                return sk;
            }
        }
    }

    /// An account's Orchard full viewing key (see [`spending_key`]).
    pub(crate) fn account(seed: u64) -> FullViewingKey {
        FullViewingKey::from(&spending_key(seed))
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

    /// An Orchard note of `value` owned by `fvk`, with its randomness drawn from `rng`.
    fn orchard_note(fvk: &FullViewingKey, value: u64, rng: &mut ChaCha8Rng) -> Note {
        let recipient = fvk.address_at(0u32, Scope::External);
        let note_value = NoteValue::from_raw(value);
        let rho = loop {
            let bytes = draw_bytes(rng);
            if let Some(rho) = Rho::from_bytes(&bytes).into_option() {
                break rho;
            }
        };
        let rseed = loop {
            let bytes = draw_bytes(rng);
            if let Some(rseed) = RandomSeed::from_bytes(bytes, &rho).into_option() {
                break rseed;
            }
        };
        Note::from_parts(recipient, note_value, rho, rseed, NoteVersion::V2)
            .into_option()
            .expect("valid note parts")
    }

    /// An Orchard note of `value` owned by `fvk`, with its randomness derived from `seed` (so
    /// proptest varies the note across cases), placed as the sole leaf of an otherwise-empty
    /// note-commitment tree, with the matching anchor. The authentication path uses the empty-subtree
    /// roots for a single leaf at position 0, so `add_orchard_spend`'s anchor check
    /// (`path.root(cmx) == anchor`) accepts it.
    pub(crate) fn single_note_witness(
        fvk: &FullViewingKey,
        value: u64,
        seed: u64,
    ) -> (Note, MerklePath, Anchor) {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let note = orchard_note(fvk, value, &mut rng);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let auth_path = core::array::from_fn(|level| {
            let level = Level::from(level as u8);
            MerkleHashOrchard::empty_root(level)
        });
        let path = MerklePath::from_parts(0, auth_path);
        let anchor = path.root(cmx);
        (note, path, anchor)
    }

    /// `values.len()` Orchard notes owned by `fvk`, placed as the first leaves of one note-commitment
    /// tree, each paired with its authentication path against the single shared anchor. Randomness is
    /// derived from `seed`. This lets a test build a multi-spend transaction whose spends all anchor to
    /// the same root. Assumes `values` is non-empty.
    pub(crate) fn shared_anchor_witnesses(
        fvk: &FullViewingKey,
        values: &[u64],
        seed: u64,
    ) -> (Vec<(Note, MerklePath)>, Anchor) {
        // The notes and their leaf hashes.
        let notes: Vec<Note> = values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(i as u64));
                orchard_note(fvk, v, &mut rng)
            })
            .collect();
        let leaves: Vec<MerkleHashOrchard> = notes
            .iter()
            .map(|n| MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(n.commitment())))
            .collect();

        // Filled subtree roots per level: `levels[l][p]` is the root of the subtree at level `l`,
        // position `p`. Level 0 is the leaves; each higher level combines pairs, using the
        // empty-subtree root for a missing right sibling. Positions past `levels[l].len()` are empty.
        let mut levels: Vec<Vec<MerkleHashOrchard>> =
            Vec::with_capacity(NOTE_COMMITMENT_TREE_DEPTH + 1);
        levels.push(leaves);
        for l in 0..NOTE_COMMITMENT_TREE_DEPTH {
            let level = Level::from(l as u8);
            let cur = &levels[l];
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut p = 0;
            while p < cur.len() {
                let left = cur[p];
                let right = cur
                    .get(p + 1)
                    .copied()
                    .unwrap_or_else(|| MerkleHashOrchard::empty_root(level));
                next.push(MerkleHashOrchard::combine(level, &left, &right));
                p += 2;
            }
            levels.push(next);
        }

        // Each leaf's authentication path: the sibling subtree root at every level (its computed value
        // when filled, else the empty-subtree root).
        let witnesses: Vec<(Note, MerklePath)> = notes
            .into_iter()
            .enumerate()
            .map(|(i, note)| {
                let auth_path = core::array::from_fn(|l| {
                    let level = Level::from(l as u8);
                    let sibling = (i >> l) ^ 1;
                    levels[l]
                        .get(sibling)
                        .copied()
                        .unwrap_or_else(|| MerkleHashOrchard::empty_root(level))
                });
                (note, MerklePath::from_parts(i as u32, auth_path))
            })
            .collect();

        // Every leaf's path yields the same root; assert it so a broken helper fails loudly rather
        // than silently producing mismatched anchors.
        let root_of = |(note, path): &(Note, MerklePath)| {
            path.root(ExtractedNoteCommitment::from(note.commitment()))
        };
        let anchor = root_of(&witnesses[0]);
        for w in &witnesses {
            assert_eq!(root_of(w), anchor, "shared-anchor witnesses inconsistent");
        }
        (witnesses, anchor)
    }
}
