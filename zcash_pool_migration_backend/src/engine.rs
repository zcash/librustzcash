//! The migration engine: orchestrating a pool migration end to end through a wallet backend.
//!
//! The crate's other modules are the individual planners and builders: [`note_splitting`] decides the
//! denominations, [`preparation`] plans the transactions that mint them, [`scheduling`] shuffles and
//! times the phase-2 transfers, and the `build` module turns plans into PCZTs. This module ties
//! them together behind a [`MigrationBackend`] trait, so the engine drives the whole flow
//! (plan -> build -> sign -> schedule -> persist) without knowing how the wallet stores notes, resolves
//! witnesses, holds keys, or persists state.
//!
//! This first slice covers PLANNING: [`plan_migration`] decomposes the account's spendable balance into
//! canonical denominations, plans the preparation transactions, schedules the transfers, and reconciles
//! the split against the preparation fees (dropping the smallest denominations when the fees do not fit
//! the balance), producing a [`MigrationPlan`] preview for the user to consent to (ZIP 318 requires
//! consent before any funds leave the pool). Building, signing, anchoring at proving time, persistence,
//! and reconciliation-on-launch are added by later slices, which grow [`MigrationBackend`] with the
//! witness, key, and storage methods they need.
//!
//! # The committed migration is stored as pre-signed PCZTs
//!
//! Planning is only the first phase, and the app that broadcasts is separate from the engine that
//! plans. Once the user consents, the engine will BUILD every preparation and transfer transaction as a
//! PCZT and PRE-SIGN it in a single session (the Orchard spend authorization is fixed independently of
//! the proofs and the anchor), then hand each pre-signed PCZT to the backend to PERSIST alongside its
//! schedule: broadcast height, expiry, layer and dependencies, drawn anchor boundary, and state. The
//! durable artifact is therefore the pre-signed PCZT ready to send, not just the plan. The consuming
//! application later reads the due transactions back from the store, updates each proof against a fresh
//! boundary anchor, broadcasts them at their scheduled heights, and reports the outcome so the engine
//! can advance each transaction's state. A wallet closed between planning and broadcast, or restarted
//! partway through, resumes from the stored PCZTs. This shapes the `MigrationBackend` storage methods
//! (store/load a transaction PCZT + its state) and the persisted state model that later slices add.
//!
//! [`note_splitting`]: crate::note_splitting
//! [`preparation`]: crate::preparation
//! [`scheduling`]: crate::scheduling

use alloc::vec::Vec;

use core::fmt;

use rand_core::RngCore;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{BalanceError, Zatoshis};

use crate::note_splitting::{NoteSplitPlan, plan_note_split};
use crate::preparation::{PrepError, PreparationPlan, plan_preparation};
use crate::scheduling::{self, Schedule};

/// What the migration engine needs from a wallet to PLAN a migration: the account's spendable notes and
/// the chain state. Later slices add the methods for building (note witnesses, viewing keys), signing,
/// persistence, and reconciliation; a backend implements this trait over its own note store and chain
/// view (for example a `zcash_client_backend` wallet, or the migration's own SQLite store).
pub trait MigrationBackend {
    /// The backend's own error type (a store or chain-access failure).
    type Error;

    /// The values of the account's spendable source-pool (Orchard) notes. The migration decomposes
    /// their total into denominations; the same notes are later spent by the preparation
    /// transactions, so the values must line up with what the build step will resolve to witnesses.
    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error>;

    /// The current chain-tip height, from which the transfer schedule's delays accumulate.
    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error>;

    /// Persist the migration state: every transaction as its pre-signed PCZT plus the metadata the
    /// application needs to prove, schedule, and broadcast it. Storing the pre-signed transactions,
    /// not just the plan, is what lets a wallet resume a migration after being closed or restarted.
    fn store_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error>;

    /// Load the persisted migration state, if a migration is in progress.
    fn load_migration(&self) -> Result<Option<MigrationState>, Self::Error>;

    /// Advance one stored transaction's lifecycle state (for example after the application broadcasts
    /// it, or the chain mines it, or it expires).
    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error>;
}

/// A stable identifier for a migration transaction within a migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MigrationTxId(pub u32);

/// What a migration transaction does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationTxKind {
    /// A note-preparation transaction: the `index`-th transaction of preparation `layer`.
    Preparation { layer: usize, index: usize },
    /// A phase-2 pool-crossing transfer of the `crossing`-th funding note.
    Transfer { crossing: usize },
}

/// Where a migration transaction is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationTxState {
    /// Built but not yet signed.
    Planned,
    /// Pre-signed (the account's spend authorization is attached), not yet proved.
    Signed,
    /// Proved against a real anchor, ready to broadcast.
    Proved,
    /// Broadcast to the network, with its transaction id.
    Broadcast { txid: [u8; 32] },
    /// Mined at the given height.
    Mined { height: BlockHeight },
    /// Expired before it could be mined, and to be rebuilt.
    Expired,
}

/// One transaction of a committed migration: its pre-signed PCZT plus the metadata the consuming
/// application needs to prove it against a fresh anchor, wait for its dependencies, broadcast it at
/// its scheduled height, and track its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationTransaction {
    /// This transaction's stable id.
    pub id: MigrationTxId,
    /// What it does (a preparation transaction or a transfer).
    pub kind: MigrationTxKind,
    /// The pre-signed, unproven PCZT, serialized (`pczt::Pczt::serialize`). This is the durable
    /// artifact: the application updates its proof against a fresh anchor and broadcasts it.
    pub pczt: Vec<u8>,
    /// The transactions that must be mined before this one may be broadcast (the preparation layer
    /// dependency graph; empty for an independent transaction).
    pub depends_on: Vec<MigrationTxId>,
    /// The height at which to broadcast (for a transfer; a preparation transaction waits for its
    /// dependencies to mine and a boundary to pass rather than a fixed height).
    pub scheduled_height: BlockHeight,
    /// The height after which the transaction is invalid and must be rebuilt.
    pub expiry_height: BlockHeight,
    /// The boundary height whose tree state the transaction proves against, drawn at proving time (for
    /// a transfer); `None` until proved.
    pub anchor_boundary: Option<BlockHeight>,
    /// The transaction's lifecycle state.
    pub state: MigrationTxState,
}

/// The overall status of a migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Planned and previewed, not yet committed (nothing built or signed).
    Planning,
    /// Built, pre-signed, and persisted; ready for the application to prove and broadcast.
    Committed,
    /// Some transactions have been broadcast or mined.
    InProgress,
    /// Every crossing has been mined.
    Complete,
    /// The migration failed and needs attention.
    Failed,
}

/// The persisted state of a migration: the note split (for the preview and residual accounting) and
/// every transaction, each as its pre-signed PCZT and metadata. A wallet resumes a migration entirely
/// from this state after being closed or restarted; this is what a [`MigrationBackend`] stores.
#[derive(Clone, Debug)]
pub struct MigrationState {
    /// The overall status.
    pub status: MigrationStatus,
    /// The note-split decomposition (the denominations and residual).
    pub note_split: NoteSplitPlan,
    /// Every migration transaction, in dependency order.
    pub transactions: Vec<MigrationTransaction>,
}

/// A planned migration, before anything is built, signed, or broadcast: the denomination split, the
/// preparation transactions that mint the funding notes, and the phase-2 transfer schedule. This is the
/// preview a wallet shows the user for consent (ZIP 318) to the pool-crossing amounts.
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    note_split: NoteSplitPlan,
    funding_notes: Vec<Zatoshis>,
    preparation: PreparationPlan,
    schedule: Vec<Schedule>,
}

impl MigrationPlan {
    /// The note-split decomposition (the denominations and self-funding note values it produced,
    /// before reconciling against the preparation fees; see [`funding_notes`](Self::funding_notes)).
    pub fn note_split(&self) -> &NoteSplitPlan {
        &self.note_split
    }

    /// The funding-note values this migration will actually mint, one per phase-2 crossing. These are
    /// the note split's outputs after reconciliation: when the preparation transactions' fees do not
    /// fit the balance, the smallest denominations are dropped (left in the source pool) until they do.
    pub fn funding_notes(&self) -> &[Zatoshis] {
        &self.funding_notes
    }

    /// The preparation transactions (in dependency layers) that mint the funding notes.
    pub fn preparation(&self) -> &PreparationPlan {
        &self.preparation
    }

    /// The phase-2 transfer schedule, one entry per funding note (its broadcast height and expiry).
    pub fn schedule(&self) -> &[Schedule] {
        &self.schedule
    }
}

/// Why a migration could not be planned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError<E> {
    /// The wallet backend failed (a store or chain-access error).
    Backend(E),
    /// The spendable notes cannot fund the planned migration (see [`PrepError`]).
    Preparation(PrepError),
    /// The account has no migratable balance.
    NothingToMigrate,
    /// The backend's note values do not form a valid balance (their sum exceeds the maximum money
    /// supply).
    InvalidBalance(BalanceError),
}

impl<E: fmt::Display> fmt::Display for MigrationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::Backend(e) => write!(f, "wallet backend error: {e}"),
            MigrationError::Preparation(e) => write!(f, "cannot prepare the migration: {e}"),
            MigrationError::NothingToMigrate => f.write_str("no migratable balance"),
            MigrationError::InvalidBalance(e) => write!(f, "invalid balance: {e}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for MigrationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MigrationError::Backend(e) => Some(e),
            MigrationError::Preparation(e) => Some(e),
            MigrationError::NothingToMigrate => None,
            // `BalanceError` implements `Error` only with `zcash_protocol/std`; the Display text
            // above carries its message instead.
            MigrationError::InvalidBalance(_) => None,
        }
    }
}

/// Plan a migration for the account the `backend` represents: decompose its spendable balance into
/// canonical denominations, plan the preparation transactions that mint the self-funding notes, and
/// schedule the phase-2 transfers. `prep_fee` is the ZIP-317 fee of a padded 16-action preparation
/// transaction, which the note split and the preparation planner both reserve. `rng` must be a
/// cryptographically secure RNG (the schedule's shuffle, delays, and the note split's optional
/// randomization draw from it).
///
/// This is pure orchestration of the note-split, preparation, and scheduling planners: no cryptography,
/// and nothing is built, signed, or persisted. The result is the [`MigrationPlan`] preview to present
/// for user consent before committing the migration.
pub fn plan_migration<B, R>(
    backend: &B,
    prep_fee: Zatoshis,
    rng: &mut R,
) -> Result<MigrationPlan, MigrationError<B::Error>>
where
    B: MigrationBackend,
    R: RngCore,
{
    let notes = backend
        .spendable_orchard_note_values()
        .map_err(MigrationError::Backend)?;
    // Validate the balance once; every value the planners derive from it is bounded by it, so the
    // internal (planner-domain) u64 arithmetic below cannot re-exceed the money-supply cap.
    let balance = notes
        .iter()
        .copied()
        .sum::<Option<Zatoshis>>()
        .ok_or(MigrationError::InvalidBalance(BalanceError::Overflow))?;
    if balance == Zatoshis::ZERO {
        return Err(MigrationError::NothingToMigrate);
    }
    let commit_height = backend
        .chain_tip_height()
        .map_err(MigrationError::Backend)?;

    let note_values: Vec<u64> = notes.iter().map(|&n| u64::from(n)).collect();
    let note_split = plan_note_split(u64::from(balance), u64::from(prep_fee), rng);
    if note_split.migration_outputs().is_empty() {
        return Err(MigrationError::NothingToMigrate);
    }

    // Reconcile the note split against the preparation fees. The split reserves for a single prep
    // transaction, but preparation may need several; when its fees do not fit the balance, drop the
    // smallest funding note (leaving that denomination in the source pool) and retry until it does.
    let mut funding_notes: Vec<u64> = note_split.migration_outputs().to_vec();
    funding_notes.sort_unstable(); // ascending, so the smallest is dropped first
    let preparation = loop {
        if funding_notes.is_empty() {
            return Err(MigrationError::Preparation(PrepError::InsufficientFunds));
        }
        match plan_preparation(&note_values, &funding_notes, u64::from(prep_fee)) {
            Ok(preparation) => break preparation,
            Err(PrepError::InsufficientFunds) => {
                funding_notes.remove(0);
            }
        }
    };

    let schedule = scheduling::schedule(commit_height, funding_notes.len(), rng);

    let funding_notes = funding_notes
        .into_iter()
        .map(Zatoshis::from_u64)
        .collect::<Result<Vec<_>, _>>()
        .map_err(MigrationError::InvalidBalance)?;

    Ok(MigrationPlan {
        note_split,
        funding_notes,
        preparation,
        schedule,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;

    use crate::note_splitting::{FeePolicy, Zip317FeePolicy};
    use crate::preparation::PREP_TX_ACTIONS;

    /// The ZIP-317 fee of a padded preparation transaction, as the engine's caller would compute it.
    fn prep_fee() -> Zatoshis {
        Zatoshis::from_u64(PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi())
            .expect("the preparation fee is far below the money-supply cap")
    }

    /// A minimal in-memory backend: a fixed set of note values and a chain tip.
    struct MockBackend {
        notes: Vec<Zatoshis>,
        tip: BlockHeight,
        stored: Option<MigrationState>,
    }

    impl MockBackend {
        fn new(notes: Vec<u64>, tip: u32) -> Self {
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

        fn store_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.stored = Some(state.clone());
            Ok(())
        }

        fn load_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }

        fn update_transaction(
            &mut self,
            id: MigrationTxId,
            state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            if let Some(stored) = &mut self.stored {
                if let Some(tx) = stored.transactions.iter_mut().find(|t| t.id == id) {
                    tx.state = state;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn plans_a_migration_from_a_balance() {
        let backend = MockBackend::new(vec![100 * COIN, 40 * COIN], 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let plan =
            plan_migration(&backend, prep_fee(), &mut rng).expect("a fundable balance plans");

        // Something is migrated; the schedule has one entry per funding note; the preparation mints
        // exactly the (reconciled) funding notes; and reconciliation only ever drops, never adds.
        assert!(!plan.funding_notes().is_empty());
        assert_eq!(plan.schedule().len(), plan.funding_notes().len());
        assert_eq!(
            plan.preparation().funding_notes().len(),
            plan.funding_notes().len()
        );
        assert!(plan.funding_notes().len() <= plan.note_split().migration_outputs().len());
    }

    #[test]
    fn empty_balance_has_nothing_to_migrate() {
        let backend = MockBackend::new(Vec::new(), 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        assert!(matches!(
            plan_migration(&backend, prep_fee(), &mut rng),
            Err(MigrationError::NothingToMigrate)
        ));
    }

    #[test]
    fn stores_loads_and_updates_a_migration() {
        let mut backend = MockBackend::new(Vec::new(), 0);
        assert!(backend.load_migration().unwrap().is_none());

        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let note_split =
            crate::note_splitting::plan_note_split(100 * COIN, u64::from(prep_fee()), &mut rng);
        let tx = MigrationTransaction {
            id: MigrationTxId(0),
            kind: MigrationTxKind::Transfer { crossing: 0 },
            pczt: vec![1, 2, 3], // a stand-in for the serialized pre-signed PCZT
            depends_on: Vec::new(),
            scheduled_height: BlockHeight::from_u32(2_000_100),
            expiry_height: BlockHeight::from_u32(2_069_220),
            anchor_boundary: None,
            state: MigrationTxState::Signed,
        };
        let state = MigrationState {
            status: MigrationStatus::Committed,
            note_split,
            transactions: vec![tx],
        };
        backend.store_migration(&state).unwrap();

        // The stored transactions round-trip, and a state update persists.
        let loaded = backend
            .load_migration()
            .unwrap()
            .expect("a migration is stored");
        assert_eq!(loaded.status, MigrationStatus::Committed);
        assert_eq!(loaded.transactions, state.transactions);

        backend
            .update_transaction(
                MigrationTxId(0),
                MigrationTxState::Mined {
                    height: BlockHeight::from_u32(2_000_105),
                },
            )
            .unwrap();
        let loaded = backend.load_migration().unwrap().unwrap();
        assert_eq!(
            loaded.transactions[0].state,
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(2_000_105)
            }
        );
    }
}
