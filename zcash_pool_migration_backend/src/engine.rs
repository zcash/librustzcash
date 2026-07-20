//! The migration engine: orchestrating a pool migration end to end through a wallet backend.
//!
//! The crate's other modules are the individual planners and builders: [`note_splitting`] decides the
//! denominations, [`preparation`] plans the transactions that mint them, [`scheduling`] shuffles and
//! times the phase-2 transfers, and the `build` module turns plans into PCZTs. This module ties
//! them together behind a [`MigrationBackend`] trait, so the engine drives the whole flow
//! (plan -> build -> sign -> schedule -> persist) without knowing how the wallet stores notes, resolves
//! witnesses, holds keys, or persists state.
//!
//! [`plan_migration`] decomposes the account's spendable balance into canonical denominations, plans the
//! preparation transactions, schedules the transfers, and reconciles the split against the preparation
//! fees (dropping the smallest denominations when the fees do not fit the balance), producing a
//! [`MigrationPlan`] preview for the user to consent to (ZIP 318 requires consent before any funds leave
//! the pool). After consent, [`commit_preparation`] and [`commit_transfers`] build and pre-sign the
//! transactions (see below), reading the account's notes and witnesses and signing through the backend
//! traits, and persisting each transaction through the store traits. The concrete durable store,
//! anchoring at proving time, and reconciliation-on-launch are grown by a later slice.
//!
//! # The committed migration is stored as its transactions' PCZTs
//!
//! Planning is only the first phase, and the application that broadcasts is separate from the engine that
//! plans and signs. Once the user consents, the engine builds each preparation and transfer transaction
//! as a PCZT and pre-signs it (the Orchard spend authorization is fixed independently of the proofs and
//! the anchor), then hands each to the backend to PERSIST alongside its schedule: broadcast height,
//! expiry, layer and dependencies, drawn anchor boundary, and state. Signing spans MORE THAN ONE session,
//! as ZIP 318 permits: [`commit_preparation`] builds and signs the preparation, and only once it has
//! mined, so the funding notes it mints become witnessable, does [`commit_transfers`] build and sign the
//! transfers. (Later slices extend this to a multi-layer preparation, signing each layer as its
//! predecessor mines, and to an external hardware signer, which builds each transaction UNSIGNED and signs
//! it out of band before it is applied back.) The durable artifact is therefore each transaction's PCZT
//! plus its schedule and state, not just the plan. The consuming application later reads the due
//! transactions back from the store, proves each against a fresh boundary anchor, broadcasts them at
//! their scheduled heights, and reports the outcome so the engine can advance each transaction's state. A
//! wallet closed between planning and broadcast, or restarted partway through, resumes from the stored
//! PCZTs.
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
/// the chain state. Following the `zcash_client_backend` pattern, a later slice replaces this with the
/// wallet's own note-source and chain-view traits (`WalletRead` / `InputSource`), so any such wallet is a
/// migration wallet; for now a backend implements it directly over its note store and chain view.
pub trait MigrationBackend {
    /// The backend's own error type (a store or chain-access failure).
    type Error;

    /// The values of the account's spendable source-pool (Orchard) notes. The migration decomposes
    /// their total into denominations; the same notes are later spent by the preparation
    /// transactions, so the values must line up with what the build step will resolve to witnesses.
    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error>;

    /// The current chain-tip height, from which the transfer schedule's delays accumulate.
    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error>;
}

/// Read access to a persisted pool migration: the store side of the migration interface, mirroring
/// `zcash_client_backend`'s `WalletRead`. A store implements this over its own tables (the
/// `zcash_pool_migration_sqlite` crate does so as a migration registered into `zcash_client_sqlite`'s
/// `WalletDb`). The committed migration is a set of pre-signed PCZTs plus their schedule and lifecycle
/// state, so a wallet resumes a migration entirely from the store after being closed or restarted.
pub trait PoolMigrationRead {
    /// The store's own error type.
    type Error;

    /// The migration currently in progress, if any.
    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error>;
}

/// Write access to a persisted pool migration, mirroring `zcash_client_backend`'s `WalletWrite`.
pub trait PoolMigrationWrite: PoolMigrationRead {
    /// Persist a committed migration: every transaction as its pre-signed PCZT plus the metadata the
    /// application needs to prove, schedule, and broadcast it. Storing the pre-signed transactions, not
    /// just the plan, is what lets a wallet resume a migration after being closed or restarted.
    fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error>;

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
    /// The pre-signed, unproven PCZT, serialized (`pczt::Pczt::serialize`), or `None` until the
    /// transaction is built and signed. A transfer is recorded as a `Planned` placeholder at commit
    /// time and its PCZT is filled in once the preparation is mined (two-phase signing). When present
    /// this is the durable artifact: the application updates its proof against a fresh anchor and
    /// broadcasts it.
    pub pczt: Option<Vec<u8>>,
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
    /// The reconciled self-funding note values (in zatoshi), one per crossing: a `Transfer { crossing }`
    /// transaction spends `funding_notes[crossing]` and crosses `funding_notes[crossing]` minus the fee
    /// buffer into the destination pool.
    pub funding_notes: Vec<Zatoshis>,
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

/// The Orchard-specific wallet operations the engine needs to BUILD and PRE-SIGN a migration: the
/// account's viewing key, note witnesses, an anchor to build against, and spend-authorization signing.
/// Kept separate from [`MigrationBackend`] so the planning and persistence parts stay pure; one wallet
/// implements both over the same account. Behind the `orchard` feature.
#[cfg(feature = "orchard")]
pub trait MigrationCrypto {
    /// The backend's error type (shared with its [`MigrationBackend`] impl).
    type Error;

    /// The account's Orchard full viewing key.
    fn orchard_fvk(&self) -> Result<orchard::keys::FullViewingKey, Self::Error>;

    /// A current Orchard anchor to build against; every spend's witness resolves against this same tree
    /// state. The proof is re-anchored to a drawn boundary at proving time, and the anchor is not in the
    /// sighash, so a current or placeholder anchor is fine here.
    fn orchard_anchor(&self) -> Result<orchard::Anchor, Self::Error>;

    /// A recent Ironwood anchor for a transfer's destination bundle: the output-only bundle's dummy
    /// spends carry this anchor, and consensus requires a recent Ironwood note-commitment-tree root
    /// (the empty-tree root is valid only until the pool holds notes).
    fn ironwood_anchor(&self) -> Result<orchard::Anchor, Self::Error>;

    /// Resolve the spendable wallet note at `index` (into `spendable_orchard_note_values`) to its note
    /// and a witness against `anchor`.
    fn resolve_wallet_note(
        &self,
        index: usize,
        anchor: orchard::Anchor,
    ) -> Result<(orchard::note::Note, orchard::tree::MerklePath), Self::Error>;

    /// Resolve the self-funding notes minted by the preparation, one per requested value, each to its
    /// note and a witness against `anchor`. Called after the preparation is mined, when these notes are
    /// spendable: `values[crossing]` is the funding note for crossing `crossing`, and the backend
    /// returns a DISTINCT note for each requested value (funding notes of equal value are
    /// interchangeable).
    fn resolve_funding_notes(
        &self,
        values: &[Zatoshis],
        anchor: orchard::Anchor,
    ) -> Result<Vec<(orchard::note::Note, orchard::tree::MerklePath)>, Self::Error>;

    /// Add the account's Orchard spend-authorization signatures to a finalized, unproven PCZT.
    fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error>;
}

/// Why committing a migration's preparation failed.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum CommitError<E> {
    /// A wallet backend operation (witness, key, signing, or storage) failed.
    Backend(E),
    /// Building or serializing a transaction failed.
    Build(alloc::string::String),
    /// The plan needs multi-layer preparation. Pre-signing a later layer requires the output notes of
    /// an earlier, unmined layer, which cannot yet be recovered from a built PCZT, so two-phase signing
    /// commits only single-layer preparation. Full one-session pre-signing awaits a public pczt
    /// output-recovery API.
    UnsupportedMultiLayer,
    /// No committed migration was found to build the transfers for (nothing was loaded from storage).
    NoMigrationInProgress,
}

#[cfg(feature = "orchard")]
impl<E: fmt::Display> fmt::Display for CommitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitError::Backend(e) => write!(f, "wallet backend error: {e}"),
            CommitError::Build(m) => write!(f, "building the migration failed: {m}"),
            CommitError::UnsupportedMultiLayer => {
                f.write_str("multi-layer preparation cannot yet be pre-signed (single-layer only)")
            }
            CommitError::NoMigrationInProgress => {
                f.write_str("no committed migration is in progress")
            }
        }
    }
}

#[cfg(feature = "orchard")]
impl<E: core::error::Error> core::error::Error for CommitError<E> {}

/// Commit a planned migration's PREPARATION: build every preparation transaction, pre-sign it with the
/// account's spend authorization, and persist it (as its serialized PCZT and metadata) through the
/// backend, so the application can broadcast the preparation and, once it is mined, build and sign the
/// transfers (the second phase). This is the two-phase signing path (ZIP 318 permits more than one
/// signing session); it handles single-layer preparation, the common case, and reports
/// [`CommitError::UnsupportedMultiLayer`] for a plan whose later layers spend earlier layers' still
/// unmined outputs.
///
/// `params` is the network, `target_height` the height the transactions are built at (post-NU6.3), and
/// `rng` a cryptographically secure RNG.
#[cfg(feature = "orchard")]
pub fn commit_preparation<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
) -> Result<MigrationState, CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    use crate::build::build_prep_tx;
    use crate::preparation::PrepInput;

    let fvk = backend.orchard_fvk().map_err(CommitError::Backend)?;
    let anchor = backend.orchard_anchor().map_err(CommitError::Backend)?;
    let expiry_height = crate::scheduling::expiry_height(target_height);

    let mut transactions: Vec<MigrationTransaction> = Vec::new();
    let mut next_id = 0u32;

    for (layer, prep_layer) in plan.preparation().layers().iter().enumerate() {
        for (index, prep_tx) in prep_layer.iter().enumerate() {
            let mut spends = Vec::with_capacity(prep_tx.inputs().len());
            for input in prep_tx.inputs() {
                match input {
                    PrepInput::Wallet { index, .. } => {
                        let witness = backend
                            .resolve_wallet_note(*index, anchor)
                            .map_err(CommitError::Backend)?;
                        spends.push(witness);
                    }
                    // Two-phase signing cannot pre-sign a spend of an earlier layer's unmined output.
                    PrepInput::Prior { .. } => return Err(CommitError::UnsupportedMultiLayer),
                }
            }

            let (pczt, _placed) = build_prep_tx(
                params,
                u32::from(target_height),
                &fvk,
                anchor,
                spends,
                prep_tx.outputs(),
                &mut *rng,
            )
            .map_err(|e| CommitError::Build(format!("{e}")))?;

            let signed = backend.sign(pczt).map_err(CommitError::Backend)?;
            let bytes = signed
                .serialize()
                .map_err(|e| CommitError::Build(format!("serialize: {e:?}")))?;

            transactions.push(MigrationTransaction {
                id: MigrationTxId(next_id),
                kind: MigrationTxKind::Preparation { layer, index },
                pczt: Some(bytes),
                depends_on: Vec::new(),
                scheduled_height: target_height,
                expiry_height,
                anchor_boundary: None,
                state: MigrationTxState::Signed,
            });
            next_id += 1;
        }
    }

    // Every transfer waits for the whole preparation to be mined, so its funding note exists on chain
    // and can be witnessed before the transfer is built and broadcast.
    let prep_ids: Vec<MigrationTxId> = transactions.iter().map(|tx| tx.id).collect();

    // Record each transfer as a Planned placeholder carrying its schedule; its PCZT is built and
    // signed later, once the preparation is mined (see `commit_transfers`). This persists the drawn
    // schedule (which is not reproducible) as part of the committed migration.
    let funding_notes = plan.funding_notes().to_vec();
    for (crossing, schedule) in plan.schedule().iter().enumerate() {
        transactions.push(MigrationTransaction {
            id: MigrationTxId(next_id),
            kind: MigrationTxKind::Transfer { crossing },
            pczt: None,
            depends_on: prep_ids.clone(),
            scheduled_height: schedule.broadcast_height(),
            expiry_height: schedule.expiry_height(),
            anchor_boundary: None,
            state: MigrationTxState::Planned,
        });
        next_id += 1;
    }

    let state = MigrationState {
        status: MigrationStatus::Committed,
        note_split: plan.note_split().clone(),
        funding_notes,
        transactions,
    };
    backend
        .put_migration(&state)
        .map_err(CommitError::Backend)?;
    Ok(state)
}

/// Commit a migration's TRANSFERS: the second phase of two-phase signing. Once the preparation has been
/// mined and its self-funding notes are spendable, build each transfer transaction (spending one
/// funding note and crossing its value into the destination pool), pre-sign it, and fill it into the
/// migration's stored `Planned` transfer placeholders, persisting the result.
///
/// Loads the committed migration from the backend (the placeholders and their drawn schedule were
/// stored by [`commit_preparation`]), resolves the funding notes, and builds only the transfers still
/// `Planned`, so it is safe to call again after a partial failure. `params` is the network,
/// `target_height` the height the transfers are built at, and `rng` a cryptographically secure RNG.
#[cfg(feature = "orchard")]
pub fn commit_transfers<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    rng: &mut R,
) -> Result<MigrationState, CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    use crate::build::build_transfer_pczt;

    let mut state = backend
        .get_migration()
        .map_err(CommitError::Backend)?
        .ok_or(CommitError::NoMigrationInProgress)?;

    let fvk = backend.orchard_fvk().map_err(CommitError::Backend)?;
    let anchor = backend.orchard_anchor().map_err(CommitError::Backend)?;
    let ironwood_anchor = backend.ironwood_anchor().map_err(CommitError::Backend)?;
    let witnesses = backend
        .resolve_funding_notes(&state.funding_notes, anchor)
        .map_err(CommitError::Backend)?;

    // The fee buffer each self-funding note carries (its value minus the value that crosses) is constant
    // across notes, so a funding note's crossing value is its value minus that buffer.
    let buffer = match (
        state.note_split.migration_outputs().first(),
        state.note_split.crossing_values().first(),
    ) {
        (Some(funding), Some(crossing)) => funding.saturating_sub(*crossing),
        _ => 0,
    };

    for tx in state.transactions.iter_mut() {
        let crossing = match tx.kind {
            MigrationTxKind::Transfer { crossing } => crossing,
            MigrationTxKind::Preparation { .. } => continue,
        };
        if !matches!(tx.state, MigrationTxState::Planned) {
            continue;
        }

        let (note, merkle_path) = witnesses.get(crossing).cloned().ok_or_else(|| {
            CommitError::Build(format!("no funding note for crossing {crossing}"))
        })?;
        let crossing_value = u64::from(state.funding_notes[crossing]).saturating_sub(buffer);

        let pczt = build_transfer_pczt(
            params,
            u32::from(target_height),
            u32::from(tx.expiry_height),
            &fvk,
            anchor,
            note,
            merkle_path,
            ironwood_anchor,
            crossing_value,
            &mut *rng,
        )
        .map_err(|e| CommitError::Build(format!("{e}")))?;

        let signed = backend.sign(pczt).map_err(CommitError::Backend)?;
        let bytes = signed
            .serialize()
            .map_err(|e| CommitError::Build(format!("serialize: {e:?}")))?;

        tx.pczt = Some(bytes);
        tx.state = MigrationTxState::Signed;
    }

    backend
        .put_migration(&state)
        .map_err(CommitError::Backend)?;
    Ok(state)
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
    }

    impl PoolMigrationRead for MockBackend {
        type Error = core::convert::Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }
    }

    impl PoolMigrationWrite for MockBackend {
        fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.stored = Some(state.clone());
            Ok(())
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
        assert!(backend.get_migration().unwrap().is_none());

        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let note_split =
            crate::note_splitting::plan_note_split(100 * COIN, u64::from(prep_fee()), &mut rng);
        let tx = MigrationTransaction {
            id: MigrationTxId(0),
            kind: MigrationTxKind::Transfer { crossing: 0 },
            pczt: Some(vec![1, 2, 3]), // a stand-in for the serialized pre-signed PCZT
            depends_on: Vec::new(),
            scheduled_height: BlockHeight::from_u32(2_000_100),
            expiry_height: BlockHeight::from_u32(2_069_220),
            anchor_boundary: None,
            state: MigrationTxState::Signed,
        };
        let state = MigrationState {
            status: MigrationStatus::Committed,
            note_split,
            funding_notes: Vec::new(),
            transactions: vec![tx],
        };
        backend.put_migration(&state).unwrap();

        // The stored transactions round-trip, and a state update persists.
        let loaded = backend
            .get_migration()
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
        let loaded = backend.get_migration().unwrap().unwrap();
        assert_eq!(
            loaded.transactions[0].state,
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(2_000_105)
            }
        );
    }
}

#[cfg(all(test, feature = "orchard"))]
mod commit_tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;

    use orchard::keys::{FullViewingKey, SpendAuthorizingKey};

    use crate::build::sign_pczt;
    use crate::build::test_util::{
        TARGET_HEIGHT, regtest_network, shared_anchor_witnesses, single_note_witness, spending_key,
    };
    use crate::note_splitting::{FeePolicy, Zip317FeePolicy};
    use crate::preparation::PREP_TX_ACTIONS;

    fn prep_fee() -> Zatoshis {
        Zatoshis::from_u64(PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi())
            .expect("the preparation fee is far below the money-supply cap")
    }

    /// A wallet holding the account's key and a set of note witnesses against one anchor: index 0 is the
    /// source note the preparation spends, and the rest are the funding notes the transfers spend. It
    /// signs with its own spend-authorizing key and stores the migration in memory.
    struct CommitMock {
        notes: Vec<Zatoshis>,
        witnesses: Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
        anchor: orchard::Anchor,
        fvk: FullViewingKey,
        ask: SpendAuthorizingKey,
        stored: Option<MigrationState>,
    }

    impl MigrationBackend for CommitMock {
        type Error = core::convert::Infallible;

        fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
            Ok(self.notes.clone())
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
        fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.stored = Some(state.clone());
            Ok(())
        }

        fn update_transaction(
            &mut self,
            _id: MigrationTxId,
            _state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl MigrationCrypto for CommitMock {
        type Error = core::convert::Infallible;

        fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
            Ok(self.fvk.clone())
        }

        fn orchard_anchor(&self) -> Result<orchard::Anchor, Self::Error> {
            Ok(self.anchor)
        }

        fn ironwood_anchor(&self) -> Result<orchard::Anchor, Self::Error> {
            Ok(self.anchor)
        }

        fn resolve_wallet_note(
            &self,
            index: usize,
            _anchor: orchard::Anchor,
        ) -> Result<(orchard::note::Note, orchard::tree::MerklePath), Self::Error> {
            Ok(self.witnesses[index].clone())
        }

        fn resolve_funding_notes(
            &self,
            values: &[Zatoshis],
            _anchor: orchard::Anchor,
        ) -> Result<Vec<(orchard::note::Note, orchard::tree::MerklePath)>, Self::Error> {
            // The funding notes are the witnesses after the source note (index 0).
            Ok(self.witnesses[1..1 + values.len()].to_vec())
        }

        fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error> {
            Ok(sign_pczt(pczt, &self.ask).expect("signs the migration PCZT"))
        }
    }

    #[test]
    fn commits_preparation_then_transfers() {
        let seed = 7u64;
        let sk = spending_key(seed);
        let fvk = FullViewingKey::from(&sk);
        let balance = 78 * COIN;

        // Plan the migration from the single source note.
        let plan = {
            let (note, path, anchor) = single_note_witness(&fvk, balance, seed);
            let planner = CommitMock {
                notes: vec![Zatoshis::from_u64(balance).expect("test balance is valid")],
                witnesses: vec![(note, path)],
                anchor,
                fvk: fvk.clone(),
                ask: SpendAuthorizingKey::from(&sk),
                stored: None,
            };
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            plan_migration(&planner, prep_fee(), &mut rng).expect("plans a migration")
        };
        // A single note funding a handful of denominations needs one preparation layer.
        assert_eq!(plan.preparation().layers().len(), 1);
        let funding_notes = plan.funding_notes().to_vec();

        // Witness the source note (index 0) and the funding notes against one shared anchor.
        let mut values = vec![balance];
        values.extend(funding_notes.iter().map(|&v| u64::from(v)));
        let (witnesses, anchor) = shared_anchor_witnesses(&fvk, &values, seed);

        let mut backend = CommitMock {
            notes: vec![Zatoshis::from_u64(balance).expect("test balance is valid")],
            witnesses,
            anchor,
            fvk: fvk.clone(),
            ask: SpendAuthorizingKey::from(&sk),
            stored: None,
        };
        let params = regtest_network(true);
        let prep_count: usize = plan.preparation().layers().iter().map(|l| l.len()).sum();
        let transfer_count = funding_notes.len();

        // Phase 1: commit the preparation. It signs the preparation transactions and records the
        // transfers as planned placeholders (no PCZT yet).
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("commits the preparation");
        assert_eq!(state.status, MigrationStatus::Committed);
        assert_eq!(state.transactions.len(), prep_count + transfer_count);
        for tx in &state.transactions {
            match tx.kind {
                MigrationTxKind::Preparation { .. } => {
                    assert_eq!(tx.state, MigrationTxState::Signed);
                    assert!(tx.pczt.is_some());
                }
                MigrationTxKind::Transfer { .. } => {
                    assert_eq!(tx.state, MigrationTxState::Planned);
                    assert!(tx.pczt.is_none());
                    assert!(
                        !tx.depends_on.is_empty(),
                        "a transfer waits for the preparation to mine"
                    );
                }
            }
        }

        // Phase 2: once the preparation is mined, commit the transfers.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        let state = commit_transfers(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &mut rng,
        )
        .expect("commits the transfers");

        // Every transaction is now built, pre-signed, and persisted.
        assert_eq!(state.transactions.len(), prep_count + transfer_count);
        for tx in &state.transactions {
            assert_eq!(
                tx.state,
                MigrationTxState::Signed,
                "every transaction is signed"
            );
            assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
        }
        assert!(backend.get_migration().unwrap().is_some());
    }
}
