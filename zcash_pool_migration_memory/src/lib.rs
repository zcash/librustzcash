//! In-memory implementations of the [`zcash_pool_migration`] engine traits, **FOR TESTING
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
//! [`MigrationBackend`]: zcash_pool_migration::engine::MigrationBackend
//! [`PoolMigrationRead`]: zcash_pool_migration::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration::engine::PoolMigrationWrite
//! [`MigrationCrypto`]: zcash_pool_migration::engine::MigrationCrypto
//! [`zcash_client_memory`]: https://docs.rs/zcash_client_memory

use core::cell::Cell;
use std::collections::BTreeMap;

use incrementalmerkletree::{Hashable, Level};
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::{Anchor, NOTE_COMMITMENT_TREE_DEPTH};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;

use zcash_pool_migration::build::AccountDerivation;
use zcash_pool_migration::engine::{
    MigrationBackend, MigrationCrypto, MigrationState, MigrationTransaction, MigrationTransferId,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite, ProvedTransaction,
};
use zcash_pool_migration::satisfiability::{ReorgSettleDepth, StepSatisfiability};
use zcash_pool_migration::scheduling::SchedulingParams;

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

/// The ZIP 32 account derivation a wallet seeded with `seed` would report, matching the account
/// [`spending_key`] derives. The seed fingerprint is a stand-in, not a real ZIP 32 fingerprint of
/// the test seed: nothing downstream re-derives keys from it, and an external Signer only needs the
/// derivation to be a stable identifier for the account.
pub fn account_derivation(seed: u64) -> AccountDerivation {
    let mut seed_fingerprint = [0u8; 32];
    seed_fingerprint[..8].copy_from_slice(&seed.to_le_bytes());
    AccountDerivation::new(
        zip32::fingerprint::SeedFingerprint::from_bytes(seed_fingerprint),
        zip32::AccountId::ZERO,
    )
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
///
/// Every other part is carried across verbatim, including the determinations a transaction row
/// carries (its unsatisfiability mark, its broadcast-failure report): a store advancing a
/// lifecycle state records exactly that, and dropping a field here would silently erase a
/// determination the engine is relying on.
fn set_transaction_state(
    stored: &mut MigrationState,
    id: MigrationTransferId,
    state: MigrationTxState,
) {
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
                    t.txid(),
                    state,
                    t.lock_owner(),
                    t.unsatisfiable(),
                    t.spend_nullifiers().clone(),
                    t.broadcast_failure_at(),
                )
            } else {
                t.clone()
            }
        })
        .collect();
    *stored = MigrationState::from_parts(
        stored.status(),
        stored.denominations().clone(),
        stored.preparation().clone(),
        transactions,
        stored.anchor_bucket_interval(),
        stored.replan_threshold(),
    );
}

/// A minimal in-memory backend: a fixed set of note values and a chain tip. Implements the planning
/// traits ([`MigrationBackend`], [`PoolMigrationRead`], [`PoolMigrationWrite`]); it holds no keys and
/// cannot sign, so it is used for the plan/store tests, not the commit tests.
pub struct MockBackend {
    notes: Vec<Zatoshis>,
    tip: BlockHeight,
    stored: Option<MigrationState>,
    sched_params: SchedulingParams,
    /// Configured per-transaction answers for
    /// [`check_step_satisfiability`](PoolMigrationRead::check_step_satisfiability); a transaction
    /// with no entry answers `Satisfiable` at the mock's chain tip.
    pub satisfiability: BTreeMap<MigrationTransferId, StepSatisfiability>,
    /// How many times `check_step_satisfiability` has been called, for tests asserting that a
    /// consumer queries the oracle lazily.
    pub satisfiability_queries: Cell<usize>,
    /// Configured mined heights by transaction id, for
    /// [`mined_height`](PoolMigrationRead::mined_height): a txid with no entry is not observed
    /// mined. The engine's in-flight sweep promotes a broadcast transaction listed here, so a test
    /// models mining by adding its txid rather than by calling `mark_mined`.
    pub mined: BTreeMap<TxId, BlockHeight>,
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
            sched_params: SchedulingParams::ZIP_318,
            satisfiability: BTreeMap::new(),
            satisfiability_queries: Cell::new(0),
            mined: BTreeMap::new(),
        }
    }

    /// Overrides the scheduling parameters this backend reports (the default is
    /// [`SchedulingParams::ZIP_318`]), for tests that exercise a non-standard anchor bucket grid or
    /// compressed delays.
    pub fn with_scheduling_params(mut self, sched_params: SchedulingParams) -> Self {
        self.sched_params = sched_params;
        self
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

    fn scheduling_params(&self) -> SchedulingParams {
        self.sched_params
    }
}

impl PoolMigrationRead for MockBackend {
    type Error = core::convert::Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        // Pending-only, per the trait contract: a terminal state is history.
        Ok(self.stored.clone().filter(|s| !s.is_terminal()))
    }

    fn check_step_satisfiability(
        &self,
        tx: &MigrationTransaction,
        _settle: ReorgSettleDepth,
    ) -> Result<StepSatisfiability, Self::Error> {
        self.satisfiability_queries
            .set(self.satisfiability_queries.get() + 1);
        // The empty-cache-is-corruption contract cannot be honored here: this mock's `Error` is
        // `Infallible`, so there is no error to surface. The mock answers the configured value
        // (or `Satisfiable` at its tip) regardless; tests that need the corruption path use the
        // SQLite implementation.
        Ok(self
            .satisfiability
            .get(&tx.id())
            .cloned()
            .unwrap_or(StepSatisfiability::Satisfiable {
                as_of_height: self.tip,
            }))
    }

    fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self.mined.get(&txid).copied())
    }
}

impl PoolMigrationWrite for MockBackend {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.stored = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(stored) = &mut self.stored {
            set_transaction_state(stored, id, state);
        }
        Ok(())
    }

    /// The contract's no-wallet-tables form: this mock maintains no wallet-level transaction
    /// records, so it applies the proof to the state and persists that alone.
    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: ProvedTransaction,
    ) -> Result<(), Self::Error> {
        proven.apply(state);
        self.replace_migration(state)
    }
}

/// The fixed chain-tip height [`CommitMock`] reports (and the height its default
/// satisfiability answers rest on).
const COMMIT_MOCK_TIP: u32 = 2_000_000;

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
    /// The account's Orchard spend-authorizing key. The mock does NOT sign with it: the engine
    /// takes the spend authority as an argument to the calls that sign, so a test passes this to
    /// `commit_preparation` / `rebuild_expired_transfer` (and uses it to play the external signer)
    /// rather than the backend signing on its own behalf.
    pub ask: SpendAuthorizingKey,
    /// The ZIP 32 account the notes belong to, as a seeded wallet would report it. `None` models a
    /// wallet that knows no derivation for the account (an imported viewing key).
    pub account_derivation: Option<AccountDerivation>,
    /// The in-memory migration state (`None` until a migration is committed).
    pub stored: Option<MigrationState>,
    /// Configured per-transaction answers for
    /// [`check_step_satisfiability`](PoolMigrationRead::check_step_satisfiability); a transaction
    /// with no entry answers `Satisfiable` at the mock's chain tip.
    pub satisfiability: BTreeMap<MigrationTransferId, StepSatisfiability>,
    /// How many times `check_step_satisfiability` has been called, for tests asserting that a
    /// consumer queries the oracle lazily.
    pub satisfiability_queries: Cell<usize>,
    /// Configured mined heights by transaction id, for
    /// [`mined_height`](PoolMigrationRead::mined_height): a txid with no entry is not observed
    /// mined. The engine's in-flight sweep promotes a broadcast transaction listed here, so a test
    /// models mining by adding its txid rather than by calling `mark_mined`.
    pub mined: BTreeMap<TxId, BlockHeight>,
    /// The scheduling parameters this backend reports to the engine.
    sched_params: SchedulingParams,
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
            account_derivation: Some(account_derivation(seed)),
            stored: None,
            satisfiability: BTreeMap::new(),
            satisfiability_queries: Cell::new(0),
            mined: BTreeMap::new(),
            sched_params: SchedulingParams::ZIP_318,
        }
    }

    /// Models a wallet that knows no ZIP 32 derivation for the account, so the migration's spends
    /// carry no derivation metadata and only an in-process signer can authorize them.
    pub fn without_account_derivation(mut self) -> Self {
        self.account_derivation = None;
        self
    }

    /// Overrides the scheduling parameters this backend reports (the default is
    /// [`SchedulingParams::ZIP_318`]), for tests that exercise a non-standard anchor bucket grid or
    /// compressed delays.
    pub fn with_scheduling_params(mut self, sched_params: SchedulingParams) -> Self {
        self.sched_params = sched_params;
        self
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
        Ok(BlockHeight::from_u32(COMMIT_MOCK_TIP))
    }

    fn scheduling_params(&self) -> SchedulingParams {
        self.sched_params
    }
}

impl PoolMigrationRead for CommitMock {
    type Error = core::convert::Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        // Pending-only, per the trait contract: a terminal state is history.
        Ok(self.stored.clone().filter(|s| !s.is_terminal()))
    }

    fn check_step_satisfiability(
        &self,
        tx: &MigrationTransaction,
        _settle: ReorgSettleDepth,
    ) -> Result<StepSatisfiability, Self::Error> {
        self.satisfiability_queries
            .set(self.satisfiability_queries.get() + 1);
        // The empty-cache-is-corruption contract cannot be honored here: this mock's `Error` is
        // `Infallible`, so there is no error to surface. The mock answers the configured value
        // (or `Satisfiable` at its tip) regardless; tests that need the corruption path use the
        // SQLite implementation.
        Ok(self
            .satisfiability
            .get(&tx.id())
            .cloned()
            .unwrap_or(StepSatisfiability::Satisfiable {
                as_of_height: BlockHeight::from_u32(COMMIT_MOCK_TIP),
            }))
    }

    fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self.mined.get(&txid).copied())
    }
}

impl PoolMigrationWrite for CommitMock {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.stored = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(stored) = &mut self.stored {
            set_transaction_state(stored, id, state);
        }
        Ok(())
    }

    /// The contract's no-wallet-tables form: this mock maintains no wallet-level transaction
    /// records, so it applies the proof to the state and persists that alone.
    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: ProvedTransaction,
    ) -> Result<(), Self::Error> {
        proven.apply(state);
        self.replace_migration(state)
    }
}

impl MigrationCrypto for CommitMock {
    type Error = core::convert::Infallible;

    fn orchard_fvk(&self) -> Option<&FullViewingKey> {
        Some(&self.fvk)
    }

    fn account_derivation(&self) -> Result<Option<AccountDerivation>, Self::Error> {
        Ok(self.account_derivation.clone())
    }

    fn resolve_wallet_note(&self, index: usize) -> Result<Note, Self::Error> {
        Ok(self.wallet_notes[index])
    }
}
