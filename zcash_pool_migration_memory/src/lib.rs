//! In-memory implementations of the [`zcash_pool_migration_backend`] engine traits, **FOR TESTING
//! ONLY**.
//!
//! This crate provides in-memory implementations of the pool-migration engine traits
//! ([`MigrationBackend`], [`PoolMigrationRead`], [`PoolMigrationWrite`], and [`MigrationCrypto`]) for
//! TESTING ONLY; it is not intended for production use. The mock backends hold their notes and
//! migration state in memory, sign with a hand-held Orchard spend-authorizing key, and
//! deterministically derive keys and note-commitment-tree witnesses from a seed. None of this is a
//! substitute for a real wallet backend.
//!
//! Two mocks are provided: [`MockBackend`], a note-values-and-store backend for the planning and
//! store tests, and [`CommitMock`], which additionally holds the account's key and note plaintexts
//! so it can sign, for the commit tests. The seed-derived witness helpers ([`single_note_witness`],
//! [`shared_anchor_witnesses`]) build single-leaf and shared-anchor Orchard witnesses.
//!
//! It mirrors how [`zcash_client_memory`] relates to `zcash_client_backend`: a shared, test-support
//! crate so several test suites can reuse the same mock implementations.
//!
//! [`MigrationBackend`]: zcash_pool_migration_backend::engine::MigrationBackend
//! [`PoolMigrationRead`]: zcash_pool_migration_backend::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration_backend::engine::PoolMigrationWrite
//! [`MigrationCrypto`]: zcash_pool_migration_backend::engine::MigrationCrypto
//! [`zcash_client_memory`]: https://docs.rs/zcash_client_memory

use incrementalmerkletree::{Hashable, Level};
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::{Anchor, NOTE_COMMITMENT_TREE_DEPTH};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;

use zcash_pool_migration_backend::build::sign_pczt;
use zcash_pool_migration_backend::engine::{
    MigrationBackend, MigrationCrypto, MigrationState, MigrationTransaction, MigrationTxId,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

/// A post-NU6.3 height (past the regtest NU6.3 activation) at which the migration transactions are
/// built and their fees computed.
pub const TARGET_HEIGHT: u32 = 100;

/// 32 random bytes from a `seed`-derived RNG, keeping calls deterministic per case.
fn draw_bytes(rng: &mut ChaCha8Rng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// An account's Orchard spending key, derived from `seed` so tests can vary the account across
/// proptest cases. Draws bytes until they form a valid spending key.
pub fn spending_key(seed: u64) -> SpendingKey {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    loop {
        let bytes = draw_bytes(&mut rng);
        if let Some(sk) = SpendingKey::from_bytes(bytes).into_option() {
            return sk;
        }
    }
}

/// A regtest network with the pre-NU6.3 upgrades active, and NU6.3 active only when requested.
/// The migration builds on a network where NU6.3 (the Ironwood pool) is live.
pub fn regtest_network(nu6_3_active: bool) -> LocalNetwork {
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
pub fn single_note_witness(
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
pub fn shared_anchor_witnesses(
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

/// Rebuild `stored` with the transaction identified by `id` moved to `state`, leaving the rest
/// untouched. The engine's [`MigrationState`] keeps its transactions behind read-only accessors, so
/// an external test backend advances one transaction's lifecycle by reconstructing the state from
/// its public parts.
fn set_transaction_state(stored: &mut MigrationState, id: MigrationTxId, state: MigrationTxState) {
    let transactions: Vec<MigrationTransaction> = stored
        .transactions()
        .iter()
        .map(|t| {
            if t.id() == id {
                MigrationTransaction::from_parts(
                    t.id(),
                    t.kind(),
                    t.pczt().clone(),
                    t.depends_on().clone(),
                    t.scheduled_height(),
                    t.expiry_height(),
                    t.anchor_boundary(),
                    state,
                )
            } else {
                t.clone()
            }
        })
        .collect();
    *stored = MigrationState::from_parts(
        stored.status(),
        stored.note_split().clone(),
        stored.funding_notes().clone(),
        stored.preparation().clone(),
        transactions,
    );
}

/// A minimal in-memory backend: a fixed set of note values and a chain tip. Implements the planning
/// traits ([`MigrationBackend`], [`PoolMigrationRead`], [`PoolMigrationWrite`]); it holds no keys and
/// cannot sign, so it is used for the plan/store tests, not the commit tests.
pub struct MockBackend {
    notes: Vec<Zatoshis>,
    tip: BlockHeight,
    stored: Option<MigrationState>,
}

impl MockBackend {
    /// A backend offering `notes` as the spendable Orchard note values and `tip` as the chain-tip
    /// height, with no migration stored yet.
    pub fn new(notes: Vec<u64>, tip: u32) -> Self {
        MockBackend {
            notes: notes
                .into_iter()
                .map(|v| Zatoshis::from_u64(v).expect("test note values are valid"))
                .collect(),
            tip: BlockHeight::from_u32(tip),
            stored: None,
        }
    }
}

impl MigrationBackend for MockBackend {
    type Error = core::convert::Infallible;

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        Ok(self.notes.clone())
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        Ok(self.tip)
    }
}

impl PoolMigrationRead for MockBackend {
    type Error = core::convert::Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.stored.clone())
    }
}

impl PoolMigrationWrite for MockBackend {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.stored = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(stored) = &mut self.stored {
            set_transaction_state(stored, id, state);
        }
        Ok(())
    }
}

/// A wallet mock holding the account's key and its spendable notes' PLAINTEXTS, nothing more: with
/// anchors and witnesses deferred to proving time (ZIP 374), building and signing an entire
/// migration needs no tree access at all. It signs with its own spend-authorizing key and stores the
/// migration in memory. All fields are public so a test can construct it directly for a specific
/// scenario.
pub struct CommitMock {
    /// The wallet's spendable Orchard note plaintexts (their values are reported to the planner and
    /// resolved by index at build time).
    pub wallet_notes: Vec<Note>,
    /// The account's Orchard full viewing key.
    pub fvk: FullViewingKey,
    /// The account's Orchard spend-authorizing key, used to sign the migration PCZTs.
    pub ask: SpendAuthorizingKey,
    /// The in-memory migration state (`None` until a migration is committed).
    pub stored: Option<MigrationState>,
}

impl CommitMock {
    /// A mock wallet holding single notes of the given values, derived from `seed`.
    pub fn new(seed: u64, values: &[u64]) -> Self {
        let sk = spending_key(seed);
        let fvk = FullViewingKey::from(&sk);
        let wallet_notes = values
            .iter()
            .enumerate()
            .map(|(i, &v)| single_note_witness(&fvk, v, seed.wrapping_add(i as u64)).0)
            .collect();
        CommitMock {
            wallet_notes,
            fvk,
            ask: SpendAuthorizingKey::from(&sk),
            stored: None,
        }
    }
}

impl MigrationBackend for CommitMock {
    type Error = core::convert::Infallible;

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        Ok(self
            .wallet_notes
            .iter()
            .map(|n| Zatoshis::from_u64(n.value().inner()).expect("test note values are valid"))
            .collect())
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        Ok(BlockHeight::from_u32(2_000_000))
    }
}

impl PoolMigrationRead for CommitMock {
    type Error = core::convert::Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.stored.clone())
    }
}

impl PoolMigrationWrite for CommitMock {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.stored = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(stored) = &mut self.stored {
            set_transaction_state(stored, id, state);
        }
        Ok(())
    }
}

impl MigrationCrypto for CommitMock {
    type Error = core::convert::Infallible;

    fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
        Ok(self.fvk.clone())
    }

    fn resolve_wallet_note(&self, index: usize) -> Result<Note, Self::Error> {
        Ok(self.wallet_notes[index])
    }

    fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error> {
        Ok(sign_pczt(pczt, &self.ask).expect("signs the migration PCZT"))
    }
}
