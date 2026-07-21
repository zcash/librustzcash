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
//! the pool). After consent, [`commit_preparation`] builds and pre-signs EVERY transaction in one
//! pass, reading the account's note plaintexts and signing through the backend traits, and
//! persisting each transaction through the store traits. The concrete durable store, proving, and
//! reconciliation-on-launch are grown by a later slice.
//!
//! # The committed migration is stored as its transactions' PCZTs
//!
//! Planning is only the first phase, and the application that broadcasts is separate from the engine that
//! plans and signs. Once the user consents, the engine builds each preparation and transfer transaction
//! as a PCZT and pre-signs it (anchors and witnesses are deferred to proving time per ZIP 374, so a
//! spent note's PLAINTEXT fully determines the signed data — even for a note minted by an earlier,
//! still-unmined migration transaction, whose plaintext the engine recovers from the built bundle),
//! then hands each to the backend to PERSIST alongside its schedule: broadcast height, expiry, layer
//! and dependencies, drawn anchor boundary, and state. The whole migration — every preparation
//! layer, in topological order, and every transfer — is therefore built and signed in ONE signing
//! phase, before anything is broadcast; an external hardware signer receives the same transactions
//! UNSIGNED, split into sessions bounded only by its per-interaction action budget (see
//! [`batch_unsigned_by_action_budget`]), never by mining. The durable artifact is each transaction's PCZT
//! plus its schedule and state, not just the plan. The consuming application later reads the due
//! transactions back from the store, proves each transfer against its drawn boundary anchor —
//! installing the anchor and the funding note's witness through the PCZT Updater role (ZIP 374
//! defers both past signing) — broadcasts them at their scheduled heights, and reports the outcome
//! so the engine can advance each transaction's state. A
//! wallet closed between planning and broadcast, or restarted partway through, resumes from the stored
//! PCZTs.
//!
//! [`note_splitting`]: crate::note_splitting
//! [`preparation`]: crate::preparation
//! [`scheduling`]: crate::scheduling

use alloc::vec::Vec;
use core::fmt;
use std::io::{self, Read, Write};

use getset::{CopyGetters, Getters};
use rand_core::RngCore;
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{BalanceError, Zatoshis};

use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::fees::{transparent, zip317};

use crate::note_splitting::{NoteSplitPlan, plan_note_split};
use crate::preparation::{PrepError, PreparationPlan, plan_preparation};
use crate::scheduling::{self, Schedule};

/// The estimated number of blocks for a preparation layer's LAST scheduled transaction to mine and
/// become spendable: mining latency plus the wallet's witness-sync and next-broadcast turnaround, a
/// few 75-second block intervals. Preparation transactions are fully shielded self-sends, so
/// successive layers need only TEMPORAL serialization (the predecessor mined and witnessable) —
/// they do not wait for anchor-bucket boundaries, which only the pool-crossing transfers anchor to.
/// Appended after each layer's last scheduled broadcast to base the next layer's schedule, and
/// after the final layer's to lower-bound the transfer schedule (see [`plan_migration`]); an
/// under-estimate is self-healing (the commit-time anchor draw re-checks and reports a stale plan),
/// an over-estimate merely delays the follow-on schedule.
const EST_PREP_LAYER_MINING_BLOCKS: u32 = 10;

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
    /// it, or the chain mines it).
    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error>;
}

/// A stable ordinal identifier for a migration transaction within a migration. This is a ROW KEY
/// into the persisted migration (usable before a transaction is built, when no [`TxId`] exists yet:
/// deferred preparation layers and transfers are recorded as unbuilt placeholders); it is NOT a
/// Zcash transaction id. The real [`TxId`] becomes available once a transaction is built and signed
/// (it commits only effecting data), and is carried by [`MigrationTxState::Broadcast`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MigrationTxId(pub(crate) u32);

impl MigrationTxId {
    /// Wrap a stored ordinal as a migration-transaction row key (for a store reading a persisted
    /// migration back).
    pub const fn new(index: u32) -> Self {
        MigrationTxId(index)
    }

    /// Writes this id as an unsigned 32-bit little-endian integer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_le_bytes())
    }

    /// Reads an id written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok(MigrationTxId::new(u32::from_le_bytes(bytes)))
    }
}

impl From<MigrationTxId> for u32 {
    fn from(id: MigrationTxId) -> u32 {
        id.0
    }
}

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
    /// Built and awaiting an EXTERNAL signature: its UNSIGNED PCZT is held in
    /// [`pczt`](MigrationTransaction::pczt), exported for a hardware or offline signer.
    /// [`apply_signature`](MigrationState::apply_signature) moves it to [`Signed`](Self::Signed) once the
    /// signed PCZT is returned. Only the external-signing path
    /// ([`build_preparation_unsigned`]) produces this state; the in-process commit function signs
    /// immediately and goes straight to [`Signed`](Self::Signed).
    AwaitingSignature,
    /// Pre-signed (the account's spend authorization is attached), not yet proved.
    Signed,
    /// Proved against a real anchor, ready to broadcast.
    Proved,
    /// Broadcast to the network, with its transaction id.
    Broadcast { txid: TxId },
    /// Mined at the given height.
    Mined { height: BlockHeight },
}

/// One transaction of a committed migration: its pre-signed PCZT plus the metadata the consuming
/// application needs to prove it against a fresh anchor, wait for its dependencies, broadcast it at
/// its scheduled height, and track its state.
#[derive(Clone, Debug, PartialEq, Eq, Getters, CopyGetters)]
pub struct MigrationTransaction {
    /// This transaction's stable id.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTxId,
    /// What it does (a preparation transaction or a transfer).
    #[getset(get_copy = "pub")]
    pub(crate) kind: MigrationTxKind,
    /// The unproven PCZT, serialized (`pczt::Pczt::serialize`): pre-signed, except while the
    /// transaction awaits an external signature
    /// ([`AwaitingSignature`](MigrationTxState::AwaitingSignature)), when these are the unsigned
    /// bytes the signed PCZT replaces. Every transaction is built when the migration is
    /// committed — one signing phase — so this is always present: the durable artifact the
    /// application proves (installing its anchor and witnesses at that point; ZIP 374) and
    /// broadcasts.
    #[getset(get = "pub")]
    pub(crate) pczt: Vec<u8>,
    /// The transactions that must be mined before this one may be broadcast (the preparation layer
    /// dependency graph; empty for an independent transaction).
    #[getset(get = "pub")]
    pub(crate) depends_on: Vec<MigrationTxId>,
    /// The height at which to broadcast (for a transfer; a preparation transaction waits for its
    /// dependencies to mine and a boundary to pass rather than a fixed height).
    #[getset(get_copy = "pub")]
    pub(crate) scheduled_height: BlockHeight,
    /// The height after which the transaction is invalid and must be rebuilt
    /// (rebuild-on-expiry is grown by a later slice, alongside reconciliation-on-launch).
    #[getset(get_copy = "pub")]
    pub(crate) expiry_height: BlockHeight,
    /// The boundary height whose tree state the transaction proves against. For a transfer this is
    /// always present, drawn at SCHEDULING time: `plan_migration` floors the schedule so a
    /// candidate boundary exists for every transfer. `None` only for a preparation transaction
    /// (which waits on its dependencies rather than anchoring to a drawn boundary).
    #[getset(get_copy = "pub")]
    pub(crate) anchor_boundary: Option<BlockHeight>,
    /// The transaction's lifecycle state.
    #[getset(get_copy = "pub")]
    pub(crate) state: MigrationTxState,
}

impl MigrationTransaction {
    /// Reassemble a stored migration transaction from its persisted parts, exactly as a store read
    /// them back (the inverse of the accessors). The caller is responsible for having persisted a
    /// consistent row.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: MigrationTxId,
        kind: MigrationTxKind,
        pczt: Vec<u8>,
        depends_on: Vec<MigrationTxId>,
        scheduled_height: BlockHeight,
        expiry_height: BlockHeight,
        anchor_boundary: Option<BlockHeight>,
        state: MigrationTxState,
    ) -> Self {
        Self {
            id,
            kind,
            pczt,
            depends_on,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state,
        }
    }
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

impl AsRef<str> for MigrationStatus {
    /// The stable lowercase wire name of the status, as stored by a backend and parsed back with
    /// [`TryFrom<&str>`](Self). Borrow-free: it returns a `&'static str`, so encoding a status
    /// allocates nothing.
    fn as_ref(&self) -> &str {
        match self {
            MigrationStatus::Planning => "planning",
            MigrationStatus::Committed => "committed",
            MigrationStatus::InProgress => "in_progress",
            MigrationStatus::Complete => "complete",
            MigrationStatus::Failed => "failed",
        }
    }
}

/// The error returned when a string does not name a [`MigrationStatus`] (its [`TryFrom<&str>`] impl).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationStatusError;

impl fmt::Display for ParseMigrationStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized migration status")
    }
}

impl TryFrom<&str> for MigrationStatus {
    type Error = ParseMigrationStatusError;

    /// Parses the lowercase wire name produced by [`AsRef<str>`](AsRef).
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(match s {
            "planning" => MigrationStatus::Planning,
            "committed" => MigrationStatus::Committed,
            "in_progress" => MigrationStatus::InProgress,
            "complete" => MigrationStatus::Complete,
            "failed" => MigrationStatus::Failed,
            _ => return Err(ParseMigrationStatusError),
        })
    }
}

/// The persisted state of a migration: the note split (for the preview and residual accounting) and
/// every transaction, each as its pre-signed PCZT and metadata. A wallet resumes a migration entirely
/// from this state after being closed or restarted; this is what a [`MigrationBackend`] stores.
#[derive(Clone, Debug, PartialEq, Eq, Getters, CopyGetters)]
pub struct MigrationState {
    /// The overall status.
    #[getset(get_copy = "pub")]
    pub(crate) status: MigrationStatus,
    /// The note-split decomposition (the denominations and residual).
    #[getset(get = "pub")]
    pub(crate) note_split: NoteSplitPlan,
    /// The reconciled self-funding note values (in zatoshi), one per crossing: a `Transfer { crossing }`
    /// transaction spends `funding_notes[crossing]` and crosses `funding_notes[crossing]` minus the fee
    /// buffer into the destination pool.
    #[getset(get = "pub")]
    pub(crate) funding_notes: Vec<Zatoshis>,
    /// The preparation plan (its layers and direct-funding notes), retained for auditability and
    /// for the rebuild-on-expiry slice. A `Preparation { layer, index }` transaction's spends
    /// resolve against `preparation.layers()[layer][index]`.
    #[getset(get = "pub")]
    pub(crate) preparation: PreparationPlan,
    /// Every migration transaction, in dependency order.
    #[getset(get = "pub")]
    pub(crate) transactions: Vec<MigrationTransaction>,
}

impl MigrationState {
    /// Reassemble a persisted migration from its stored parts, exactly as a store read them back
    /// (the inverse of the accessors).
    pub fn from_parts(
        status: MigrationStatus,
        note_split: NoteSplitPlan,
        funding_notes: Vec<Zatoshis>,
        preparation: PreparationPlan,
        transactions: Vec<MigrationTransaction>,
    ) -> Self {
        Self {
            status,
            note_split,
            funding_notes,
            preparation,
            transactions,
        }
    }
}

/// A planned migration, before anything is built, signed, or broadcast: the denomination split, the
/// preparation transactions that mint the funding notes, and the phase-2 transfer schedule. This is the
/// preview a wallet shows the user for consent (ZIP 318) to the pool-crossing amounts.
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    note_split: NoteSplitPlan,
    funding_notes: Vec<Zatoshis>,
    preparation: PreparationPlan,
    prep_schedule: Vec<Vec<BlockHeight>>,
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

    /// The preparation broadcast schedule, one height per preparation transaction, in the same
    /// `[layer][index]` shape as [`preparation`](Self::preparation)'s layers: exponential
    /// inter-arrival delays with the tighter preparation spacing (see
    /// [`scheduling::PREP_MEAN_DELAY`]), each layer based past
    /// the previous layer's last height plus a mining margin, so the transactions are temporally
    /// decoupled from one another while the layers stay serialized.
    pub fn prep_schedule(&self) -> &[Vec<BlockHeight>] {
        &self.prep_schedule
    }

    /// The phase-2 transfer schedule, one entry per funding note (its broadcast height and
    /// expiry), in SHUFFLED broadcast order (ZIP 318): the heights are deliberately not monotone
    /// in crossing index, so the on-chain temporal sequence of denominations is independent of
    /// the balance.
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
    /// Computing the canonical ZIP-317 fees from the canonical transaction shapes failed.
    Fee(zip317::FeeError),
    /// NU6.3 is not active on this network, so there is no destination pool to migrate into (and
    /// no anchor bucket above its activation to schedule against).
    Nu63NotActive,
}

impl<E: fmt::Display> fmt::Display for MigrationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::Backend(e) => write!(f, "wallet backend error: {e}"),
            MigrationError::Preparation(e) => write!(f, "cannot prepare the migration: {e}"),
            MigrationError::NothingToMigrate => f.write_str("no migratable balance"),
            MigrationError::InvalidBalance(e) => write!(f, "invalid balance: {e}"),
            MigrationError::Fee(e) => write!(f, "fee computation failed: {e}"),
            MigrationError::Nu63NotActive => f.write_str("NU6.3 is not active on this network"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for MigrationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MigrationError::Backend(e) => Some(e),
            MigrationError::Preparation(e) => Some(e),
            MigrationError::NothingToMigrate => None,
            // `BalanceError` (and `FeeError`, which wraps it) implements `Error` only with
            // `zcash_protocol/std`; the Display text above carries their messages instead.
            MigrationError::InvalidBalance(_) => None,
            MigrationError::Fee(_) => None,
            MigrationError::Nu63NotActive => None,
        }
    }
}

/// The two canonical ZIP-317 fees of a migration, computed from the canonical transaction shapes:
/// the fee of one padded [`PREP_TX_ACTIONS`](crate::preparation::PREP_TX_ACTIONS)-action preparation
/// transaction, and the transfer-fee buffer each prepared note carries (the fee of the canonical
/// 2-Orchard + 1-Ironwood-action transfer: the Ironwood side is a single unpadded action).
fn canonical_fees<P: zcash_protocol::consensus::Parameters>(
    params: &P,
    height: BlockHeight,
) -> Result<(Zatoshis, Zatoshis), zip317::FeeError> {
    use crate::note_splitting::{DESTINATION_ACTIONS_PER_TRANSFER, SOURCE_ACTIONS_PER_TRANSFER};
    use crate::preparation::PREP_TX_ACTIONS;

    let fee_rule = zip317::FeeRule::standard();
    let prep_tx_fee = fee_rule.fee_required(
        params,
        height,
        core::iter::empty::<transparent::InputSize>(),
        core::iter::empty::<usize>(),
        0,
        0,
        PREP_TX_ACTIONS,
        0,
    )?;
    let transfer_fee_buffer = fee_rule.fee_required(
        params,
        height,
        core::iter::empty::<transparent::InputSize>(),
        core::iter::empty::<usize>(),
        0,
        0,
        SOURCE_ACTIONS_PER_TRANSFER,
        DESTINATION_ACTIONS_PER_TRANSFER,
    )?;
    Ok((prep_tx_fee, transfer_fee_buffer))
}

/// Plan a migration for the account the `backend` represents: decompose its spendable balance into
/// canonical denominations, plan the preparation transactions that mint the self-funding notes, and
/// schedule the phase-2 transfers. The canonical ZIP-317 fees are computed here, once, from the two
/// canonical transaction shapes — the padded [`PREP_TX_ACTIONS`](crate::preparation::PREP_TX_ACTIONS)-action preparation transaction and
/// the 2-Orchard + 1-Ironwood-action transfer — and reused throughout planning; the fee rule is fixed (ZIP 318 requires
/// the canonical fee, since a nonstandard fee would partition the anonymity set), so it is not a
/// parameter. The decomposition reserves the TRUE preparation cost at each step, consulting the
/// preparation planner as it grows the split. `rng` must be a cryptographically secure RNG (the
/// schedule's shuffle, delays, and the note split's optional randomization draw from it).
///
/// This is pure orchestration of the note-split, preparation, and scheduling planners: no cryptography,
/// and nothing is built, signed, or persisted. The result is the [`MigrationPlan`] preview to present
/// for user consent before committing the migration.
pub fn plan_migration<P, B, R>(
    params: &P,
    backend: &B,
    rng: &mut R,
) -> Result<MigrationPlan, MigrationError<B::Error>>
where
    P: zcash_protocol::consensus::Parameters,
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

    // The canonical fees, computed once from the canonical transaction shapes and reused throughout.
    let (prep_tx_fee, transfer_fee_buffer) =
        canonical_fees(params, commit_height).map_err(MigrationError::Fee)?;

    // The preparation-layout capability the decomposition consults at each step: how many
    // preparation transactions minting a candidate funding multiset takes, or `None` when the
    // wallet's notes cannot mint it (so the split stops or steps down a denomination).
    let prep_tx_count = |funding: &[Zatoshis]| {
        plan_preparation(&notes, funding, prep_tx_fee)
            .ok()
            .map(|plan| plan.transaction_count())
    };
    let note_split = plan_note_split(
        balance,
        transfer_fee_buffer,
        prep_tx_fee,
        &prep_tx_count,
        rng,
    );
    let funding_notes = note_split.migration_outputs();
    if funding_notes.is_empty() {
        return Err(MigrationError::NothingToMigrate);
    }

    // The decomposition verified this multiset against the preparation planner at every step, so
    // this final planning pass succeeds by construction; the error path is kept for safety.
    let preparation = plan_preparation(&notes, &funding_notes, prep_tx_fee)
        .map_err(MigrationError::Preparation)?;

    // Schedule the PREPARATION broadcasts: each transaction gets its own drawn height (temporal
    // decoupling — a burst of identically shaped transactions from one wallet is a linkable
    // cluster), with the tighter preparation spacing since no anchor bucketing constrains them.
    // Each later layer's schedule bases past the previous layer's last height plus a mining
    // margin, keeping the layers serialized.
    let mut prep_schedule: Vec<Vec<BlockHeight>> = Vec::with_capacity(preparation.layer_count());
    let mut layer_base = commit_height;
    for layer in preparation.layers() {
        let heights = scheduling::schedule_prep_broadcast_heights(layer_base, layer.len(), rng);
        layer_base = heights.last().copied().unwrap_or(layer_base) + EST_PREP_LAYER_MINING_BLOCKS;
        prep_schedule.push(heights);
    }
    // After the loop, `layer_base` estimates the height at which the last preparation transaction
    // has mined and its funding notes are witnessable.
    let est_last_prep_height = layer_base;

    // Lower-bound the FIRST scheduled transfer so that every transfer is guaranteed a candidate
    // anchor boundary: the funding notes exist only once the preparation has mined, and a boundary
    // must then exist above their creation (see [`scheduling::earliest_broadcast_height`]). Basing
    // the schedule at this bound, rather than the raw commit height, keeps the drawn inter-arrival
    // gaps intact while making an empty candidate set impossible for a plan committed at (or
    // reasonably near) its planning height.
    let nu63_activation = params
        .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
        .ok_or(MigrationError::Nu63NotActive)?;
    let schedule_base = commit_height.max(scheduling::earliest_broadcast_height(
        nu63_activation,
        est_last_prep_height,
    ));
    // SHUFFLE (ZIP 318 MUST): the cumulative broadcast heights are non-decreasing in draw
    // order, and the split's crossing values are a non-increasing function of the balance, so
    // pairing them in order would broadcast the denominations largest-first — an on-chain
    // temporal sequence an observer could read the balance back out of. Drawing a uniform
    // permutation and assigning the i-th drawn slot to the permuted crossing makes the
    // broadcast order of denominations independent of the balance.
    let slots = scheduling::schedule(schedule_base, funding_notes.len(), rng);
    let mut schedule = slots.clone();
    for (slot, &crossing) in scheduling::shuffle_indices(funding_notes.len(), rng)
        .iter()
        .enumerate()
    {
        schedule[crossing] = slots[slot];
    }

    Ok(MigrationPlan {
        note_split,
        funding_notes,
        preparation,
        prep_schedule,
        schedule,
    })
}

/// The Orchard-specific wallet operations the engine needs to BUILD and PRE-SIGN a migration: the
/// account's viewing key, its spendable notes' plaintexts, and spend-authorization signing. Kept
/// separate from [`MigrationBackend`] so the planning and persistence parts stay pure; one wallet
/// implements both over the same account. Behind the `orchard` feature.
///
/// No anchors and no witnesses appear here: every migration transaction is built and signed with
/// its anchor and witnesses DEFERRED to proving time ([ZIP 374]) — a spent note's plaintext fully
/// determines the signed data, and its tree position matters only to the proof, which the consumer
/// creates through the PCZT `Updater` role once the note is mined.
///
/// [ZIP 374]: https://zips.z.cash/zip-0374
#[cfg(feature = "orchard")]
pub trait MigrationCrypto {
    /// The backend's error type (shared with its [`MigrationBackend`] impl).
    type Error;

    /// The account's Orchard full viewing key.
    fn orchard_fvk(&self) -> Result<orchard::keys::FullViewingKey, Self::Error>;

    /// The plaintext of the spendable wallet note at `index` (into
    /// `spendable_orchard_note_values`).
    fn resolve_wallet_note(&self, index: usize) -> Result<orchard::note::Note, Self::Error>;

    /// Add the account's Orchard spend-authorization signatures to a finalized, unproven PCZT.
    fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error>;
}

/// Why committing a migration's preparation failed.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum CommitError<E> {
    /// A wallet backend operation (witness, key, signing, or storage) failed.
    Backend(E),
    /// Building a migration transaction failed. Carries the structured builder error.
    Build(crate::build::BuildError),
    /// Serializing a built migration PCZT (for storage or an external signer) failed.
    Serialize(pczt::EncodingError),
    /// NU6.3 is not active on this network, so there is no destination pool to migrate into. The
    /// planning side models the same recoverable condition as
    /// [`MigrationError::Nu63NotActive`](MigrationError::Nu63NotActive).
    Nu63NotActive,
    /// No committed migration was found to build the transfers for (nothing was loaded from storage).
    NoMigrationInProgress,
    /// The plan is stale and must be re-planned. Either a resolved wallet note's value no longer
    /// matches the value the plan recorded for it (the plan captures notes by their index into the
    /// spendable set at planning time, so any receipt or spend since planning shifts them), or the
    /// build height has advanced past every candidate anchor boundary the schedule can prove
    /// against.
    StalePlan,
    /// A non-terminal migration is already stored. A committed migration is resumed from the
    /// store (or cancelled), never rebuilt over: overwriting it would orphan its pre-signed —
    /// and possibly already broadcast — transactions, and a rebuilt layer 0 would double-spend
    /// the same wallet notes.
    MigrationInProgress,
    /// The migration plan is internally inconsistent: two of its parallel structures disagree
    /// (for example a preparation layer has no matching entry in the preparation schedule), so
    /// it cannot be committed. A plan assembled through `from_parts` is not validated, so a
    /// malformed one reaches the commit boundary as this typed error rather than a panic; the
    /// string names which structure and index disagreed, for diagnosis.
    InconsistentPlan(alloc::string::String),
}

#[cfg(feature = "orchard")]
impl<E: fmt::Display> fmt::Display for CommitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitError::Backend(e) => write!(f, "wallet backend error: {e}"),
            CommitError::Build(e) => write!(f, "building the migration failed: {e}"),
            CommitError::Serialize(e) => {
                write!(f, "serializing a migration transaction failed: {e:?}")
            }
            CommitError::Nu63NotActive => f.write_str("NU6.3 is not active on this network"),
            CommitError::NoMigrationInProgress => {
                f.write_str("no committed migration is in progress")
            }
            CommitError::StalePlan => f.write_str(
                "the plan no longer matches the wallet or the build height and must be re-planned",
            ),
            CommitError::MigrationInProgress => f.write_str(
                "a non-terminal migration is already stored; resume or cancel it instead of \
                 committing a new one",
            ),
            CommitError::InconsistentPlan(m) => {
                write!(f, "the migration plan is internally inconsistent: {m}")
            }
        }
    }
}

#[cfg(feature = "orchard")]
impl<E: core::error::Error> core::error::Error for CommitError<E> {}

/// How a freshly built migration PCZT is finished by the commit functions: signed in-process with the
/// wallet's spend authority, or left unsigned for an external (hardware or offline) signer.
#[cfg(feature = "orchard")]
#[derive(Clone, Copy)]
enum Signing {
    /// Sign in-process via [`MigrationCrypto::sign`].
    InProcess,
    /// Leave the PCZT unsigned for an external signer; the caller receives it to sign out of band.
    External,
}

/// An UNSIGNED migration transaction PCZT to route to an external (hardware or offline) signer, paired
/// with the id that [`MigrationState::apply_signature`] uses to store the signed PCZT it returns as.
///
/// Produced by [`build_preparation_unsigned`]. The `(id, pczt)` pairing MUST survive the
/// round-trip to the signer, because `apply_signature` matches the returned signed PCZT back to
/// its transaction by id; [`batch_unsigned_by_action_budget`] splits a migration's worth of these
/// into device-sized signing sessions.
#[cfg(feature = "orchard")]
#[derive(Clone, Debug, Getters, CopyGetters)]
pub struct UnsignedMigrationTx {
    /// The transaction's id in the committed migration.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTxId,
    /// The serialized UNSIGNED PCZT to sign out of band.
    #[getset(get = "pub")]
    pub(crate) pczt: Vec<u8>,
    /// The number of Orchard-family actions the signer processes for this transaction (its
    /// padded action count), so signing sessions can be bounded by a device's action budget
    /// (see [`batch_unsigned_by_action_budget`]).
    #[getset(get_copy = "pub")]
    pub(crate) actions: usize,
}

#[cfg(feature = "orchard")]
impl UnsignedMigrationTx {
    /// Take the id and the unsigned PCZT bytes (to route the bytes to the external signer while
    /// keeping the id to match the signed result back; see
    /// [`MigrationState::apply_signature`](crate::engine::MigrationState)).
    pub fn into_parts(self) -> (MigrationTxId, Vec<u8>) {
        (self.id, self.pczt)
    }
}

/// Split unsigned migration transactions into SIGNING SESSIONS: consecutive batches, preserving
/// the given order (the commit functions emit topological order), each holding at most
/// `action_budget` total [`actions`](UnsignedMigrationTx::actions) — except that a batch always
/// holds at least one transaction, so a single transaction larger than the budget still gets a
/// session of its own.
///
/// Every transaction is fully built and independent at signing time (anchors and witnesses are
/// deferred to proving; nothing waits on the chain), so a session boundary reflects only the
/// signer's per-interaction capacity — a hardware device's action budget — and each session's
/// results are applied back with [`MigrationState::apply_signature`] in any order.
#[cfg(feature = "orchard")]
pub fn batch_unsigned_by_action_budget(
    unsigned: Vec<UnsignedMigrationTx>,
    action_budget: usize,
) -> Vec<Vec<UnsignedMigrationTx>> {
    let mut sessions: Vec<Vec<UnsignedMigrationTx>> = Vec::new();
    let mut current: Vec<UnsignedMigrationTx> = Vec::new();
    let mut current_actions = 0usize;
    for tx in unsigned {
        if !current.is_empty() && current_actions.saturating_add(tx.actions) > action_budget {
            sessions.push(core::mem::take(&mut current));
            current_actions = 0;
        }
        current_actions = current_actions.saturating_add(tx.actions);
        current.push(tx);
    }
    if !current.is_empty() {
        sessions.push(current);
    }
    sessions
}

/// Serialize a freshly built PCZT for storage. For [`Signing::InProcess`], sign it with the backend and
/// return the signed bytes as [`Signed`](MigrationTxState::Signed); for [`Signing::External`], return the
/// unsigned bytes as [`AwaitingSignature`](MigrationTxState::AwaitingSignature) (the caller also routes a
/// copy of those bytes to the external signer).
#[cfg(feature = "orchard")]
fn finish_built_pczt<B>(
    backend: &mut B,
    pczt: ::pczt::Pczt,
    signing: Signing,
) -> Result<(Vec<u8>, MigrationTxState), CommitError<<B as MigrationBackend>::Error>>
where
    B: MigrationBackend + MigrationCrypto<Error = <B as MigrationBackend>::Error>,
{
    match signing {
        Signing::InProcess => {
            let signed = backend.sign(pczt).map_err(CommitError::Backend)?;
            let bytes = signed.serialize().map_err(CommitError::Serialize)?;
            Ok((bytes, MigrationTxState::Signed))
        }
        Signing::External => {
            let bytes = pczt.serialize().map_err(CommitError::Serialize)?;
            Ok((bytes, MigrationTxState::AwaitingSignature))
        }
    }
}

/// Commit a planned migration: build and pre-sign EVERY transaction — each preparation layer, in
/// topological order, then every transfer — in this one pass, and persist the whole committed
/// migration through the backend. Anchors and witnesses are deferred to proving time (ZIP 374), so
/// a spent note's plaintext is all the builder needs: layer 0 spends the wallet's own notes, and
/// each later layer's feeders and each transfer's funding note are recovered from the built (still
/// unmined) bundles of the transactions that mint them. Mining gates only the BROADCAST order,
/// which the state machine walks by dependencies and scheduled heights; nothing is ever signed in
/// a second session because of on-chain state.
///
/// For an EXTERNAL signer (a hardware wallet), use [`build_preparation_unsigned`] instead, which
/// builds the same transactions but leaves them unsigned for the device.
///
/// Refuses to overwrite a stored non-terminal migration
/// ([`CommitError::MigrationInProgress`]): a committed migration is resumed from the store, or
/// cancelled, never rebuilt over.
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
    commit_preparation_inner(
        params,
        target_height,
        backend,
        plan,
        rng,
        Signing::InProcess,
    )
    .map(|(state, _unsigned)| state)
}

/// Commit a planned migration for an EXTERNAL signer: build EVERY transaction exactly as
/// [`commit_preparation`] does, but leave them UNSIGNED (in the
/// [`AwaitingSignature`](MigrationTxState::AwaitingSignature) state), persist the committed
/// migration, and return the state together with the unsigned PCZTs, in topological order, to
/// route to the signing device — split them into device-sized sessions with
/// [`batch_unsigned_by_action_budget`].
///
/// After the device signs, call [`MigrationState::apply_signature`] for each returned PCZT (matched by
/// [`UnsignedMigrationTx::id`]) to move it to [`Signed`](MigrationTxState::Signed), persist with
/// `put_migration`, and drive the broadcasts through the normal state machine (proving remains a
/// consumer responsibility, at broadcast time).
///
/// `params` is the network, `target_height` the height the transactions are built at (post-NU6.3), and
/// `rng` a cryptographically secure RNG.
#[cfg(feature = "orchard")]
pub fn build_preparation_unsigned<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
) -> Result<(MigrationState, Vec<UnsignedMigrationTx>), CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    commit_preparation_inner(params, target_height, backend, plan, rng, Signing::External)
}

/// Shared body of [`commit_preparation`] (with [`Signing::InProcess`]) and
/// [`build_preparation_unsigned`] (with [`Signing::External`]). Layer-0 transactions are finished via
/// [`finish_built_pczt`]; the returned `Vec<UnsignedMigrationTx>` is empty for the in-process path.
#[cfg(feature = "orchard")]
fn commit_preparation_inner<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
    signing: Signing,
) -> Result<(MigrationState, Vec<UnsignedMigrationTx>), CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    use crate::build::{build_prep_tx, build_transfer_pczt};
    use crate::preparation::{PrepInput, PrepOutput};
    use zcash_protocol::consensus::NetworkUpgrade;

    // A committed migration is resumed from the store (or cancelled), never rebuilt over (see
    // [`MigrationState::is_terminal`]): checked FIRST, before any signing work, so a crashed or
    // re-run consumer cannot orphan in-flight pre-signed transactions by re-committing.
    if backend
        .get_migration()
        .map_err(CommitError::Backend)?
        .is_some_and(|existing| !existing.is_terminal())
    {
        return Err(CommitError::MigrationInProgress);
    }

    let fvk = backend.orchard_fvk().map_err(CommitError::Backend)?;
    let nu63_activation = params
        .activation_height(NetworkUpgrade::Nu6_3)
        .ok_or(CommitError::Nu63NotActive)?;

    let mut transactions: Vec<MigrationTransaction> = Vec::new();
    let mut unsigned: Vec<UnsignedMigrationTx> = Vec::new();
    let mut next_id = 0u32;
    // The transaction ids assigned to each preparation layer, so a later layer can depend on the
    // whole layer before it, and the transfers on the last preparation layer. Dependencies gate
    // BROADCAST order only: every transaction is built and signed here, in this one pass.
    let mut layer_ids: Vec<Vec<MigrationTxId>> = Vec::new();

    // The spendable notes minted by already-built preparation transactions, RECOVERED from their
    // built bundles (a minted note's plaintext is fixed at build time — its rho is the paired
    // spend's nullifier and its rseed is drawn by the builder; mining only assigns its tree
    // position, which matters only to the proof). A later layer's Prior spends and the transfers'
    // funding notes draw from this pool by value, each note spent at most once. This is what
    // makes the WHOLE migration signable in topological order before anything is broadcast:
    // signing sessions are bounded by the signer's action budget, never by mining.
    let mut minted: Vec<(Zatoshis, orchard::note::Note, bool)> = Vec::new();

    for (layer, prep_layer) in plan.preparation().layers().iter().enumerate() {
        let mut this_layer_ids: Vec<MigrationTxId> = Vec::with_capacity(prep_layer.len());
        for (index, prep_tx) in prep_layer.iter().enumerate() {
            let id = MigrationTxId(next_id);
            next_id += 1;
            this_layer_ids.push(id);

            let mut spends = Vec::with_capacity(prep_tx.inputs().len());
            for input in prep_tx.inputs() {
                match input {
                    PrepInput::Wallet { index, value } => {
                        let note = backend
                            .resolve_wallet_note(*index)
                            .map_err(CommitError::Backend)?;
                        // The plan captured this note by its index into the spendable set at
                        // PLANNING time; any receipt or spend since then shifts the indices,
                        // so a resolved note whose value differs from the planned one means
                        // the plan is stale — caught here as a typed error rather than as an
                        // opaque balance failure (or, for an equal-valued interloper, a
                        // silently signed spend of a note the plan reserved elsewhere).
                        if note.value().inner() != u64::from(*value) {
                            return Err(CommitError::StalePlan);
                        }
                        spends.push(note);
                    }
                    PrepInput::Prior { value, .. } => {
                        // A feeder minted by an earlier layer, recovered when that layer was
                        // built above (the plan's layers are in topological order).
                        let pos = minted
                            .iter()
                            .position(|(v, _, used)| !used && v == value)
                            .ok_or_else(|| {
                                CommitError::InconsistentPlan(format!(
                                    "layer {layer} spends a feeder note of value {} that no \
                                     earlier layer mints",
                                    u64::from(*value)
                                ))
                            })?;
                        minted[pos].2 = true;
                        spends.push(minted[pos].1);
                    }
                }
            }

            let depends_on = if layer == 0 {
                Vec::new()
            } else {
                layer_ids
                    .last()
                    .cloned()
                    .expect("a layer after layer 0 has a preceding layer")
            };
            // The drawn preparation schedule temporally decouples the transactions of a layer
            // from one another (see `MigrationPlan::prep_schedule`). The expiry the
            // pre-signature commits to must match that schedule, not the build height: the
            // canonical rolling window at the scheduled height.
            let scheduled_height = *plan
                .prep_schedule()
                .get(layer)
                .and_then(|layer_schedule| layer_schedule.get(index))
                .ok_or_else(|| {
                    CommitError::InconsistentPlan(format!(
                        "preparation schedule has no entry for layer {layer} transaction {index}"
                    ))
                })?;
            let expiry_height = crate::scheduling::expiry_height(scheduled_height);
            let (pczt, placed) = build_prep_tx(
                params,
                u32::from(target_height),
                u32::from(expiry_height),
                &fvk,
                spends,
                prep_tx.outputs(),
                &mut *rng,
            )
            .map_err(CommitError::Build)?;

            // Grow the minted pool with this transaction's recovered spendable outputs. Change
            // outputs are excluded: they stay in the source pool and must never be matched to a
            // feeder or funding request of a coincidentally equal value.
            for (_action_index, output, note) in placed {
                match output {
                    PrepOutput::Funding(value) | PrepOutput::Intermediate(value) => {
                        minted.push((value, note, false));
                    }
                    PrepOutput::Change(_) => {}
                }
            }

            let (bytes, tx_state) = finish_built_pczt(backend, pczt, signing)?;
            if matches!(signing, Signing::External) {
                unsigned.push(UnsignedMigrationTx {
                    id,
                    pczt: bytes.clone(),
                    actions: crate::preparation::PREP_TX_ACTIONS,
                });
            }
            transactions.push(MigrationTransaction {
                id,
                kind: MigrationTxKind::Preparation { layer, index },
                pczt: bytes,
                depends_on,
                scheduled_height,
                expiry_height,
                anchor_boundary: None,
                state: tx_state,
            });
        }
        layer_ids.push(this_layer_ids);
    }

    // Direct-funding wallet notes (already exactly a funding value; no preparation transaction
    // mints them) join the pool the transfers draw from.
    for &(wallet_index, value) in plan.preparation().direct_funding_notes() {
        let note = backend
            .resolve_wallet_note(wallet_index)
            .map_err(CommitError::Backend)?;
        if note.value().inner() != u64::from(value) {
            return Err(CommitError::StalePlan);
        }
        minted.push((value, note, false));
    }

    // Every transfer waits for the last preparation layer to be MINED before it broadcasts (a
    // layer broadcasts only after its predecessor mines, so the last layer mining implies every
    // funding note is on-chain); its PCZT, though, is built and signed right here. An empty
    // preparation (every funding note used directly) leaves the dependency set empty.
    let last_layer_ids: Vec<MigrationTxId> = layer_ids.last().cloned().unwrap_or_default();

    // The boundary anchor each transfer will PROVE against is drawn here, at scheduling time,
    // because the schedule fully determines it: the candidate set lies strictly above the NU6.3
    // activation, at or after the height the funding notes exist on-chain (the last drawn
    // preparation height plus the mining margin — the estimate `plan_migration` floored the
    // schedule on), and strictly below the most recent boundary at the transfer's scheduled
    // broadcast height. The anchor and the funding note's witness are installed against that
    // boundary through the PCZT Updater role at proving time (ZIP 374); nothing here needs them.
    //
    // `plan_migration` floors the first scheduled transfer on this same estimate, so every
    // transfer has a candidate boundary by construction; an empty draw therefore means the plan
    // has gone STALE (committed at a height far past the estimate the schedule was floored on)
    // and must be re-planned — it is an error, never a deferred fallback.
    let est_last_prep_height = plan
        .prep_schedule()
        .last()
        .and_then(|layer| layer.last())
        .map_or(target_height, |&h| h + EST_PREP_LAYER_MINING_BLOCKS);
    let funding_notes = plan.funding_notes().to_vec();
    for (crossing, schedule) in plan.schedule().iter().enumerate() {
        let id = MigrationTxId(next_id);
        next_id += 1;

        let funding_value = *funding_notes.get(crossing).ok_or_else(|| {
            CommitError::InconsistentPlan(format!("no funding note value for crossing {crossing}"))
        })?;
        let pos = minted
            .iter()
            .position(|(v, _, used)| !used && *v == funding_value)
            .ok_or_else(|| {
                CommitError::InconsistentPlan(format!(
                    "no minted funding note for crossing {crossing}"
                ))
            })?;
        minted[pos].2 = true;
        let note = minted[pos].1;
        let crossing_value = *plan
            .note_split()
            .crossing_values()
            .get(crossing)
            .ok_or_else(|| {
                CommitError::InconsistentPlan(format!(
                    "no stored crossing value for transfer {crossing}"
                ))
            })?;

        let pczt = build_transfer_pczt(
            params,
            u32::from(target_height),
            u32::from(schedule.expiry_height()),
            &fvk,
            note,
            crossing_value,
            &mut *rng,
        )
        .map_err(CommitError::Build)?;
        let (bytes, tx_state) = finish_built_pczt(backend, pczt, signing)?;
        if matches!(signing, Signing::External) {
            unsigned.push(UnsignedMigrationTx {
                id,
                pczt: bytes.clone(),
                actions: crate::note_splitting::SOURCE_ACTIONS_PER_TRANSFER
                    + crate::note_splitting::DESTINATION_ACTIONS_PER_TRANSFER,
            });
        }
        transactions.push(MigrationTransaction {
            id,
            kind: MigrationTxKind::Transfer { crossing },
            pczt: bytes,
            depends_on: last_layer_ids.clone(),
            scheduled_height: schedule.broadcast_height(),
            expiry_height: schedule.expiry_height(),
            anchor_boundary: Some(
                scheduling::draw_anchor_boundary(
                    nu63_activation,
                    est_last_prep_height,
                    schedule.broadcast_height(),
                    rng,
                )
                .ok_or(CommitError::StalePlan)?,
            ),
            state: tx_state,
        });
    }

    let state = MigrationState {
        status: MigrationStatus::Committed,
        note_split: plan.note_split().clone(),
        funding_notes,
        preparation: plan.preparation().clone(),
        transactions,
    };
    backend
        .put_migration(&state)
        .map_err(CommitError::Backend)?;
    Ok((state, unsigned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;

    use zcash_protocol::local_consensus::LocalNetwork;

    use crate::preparation::FUNDING_OUTPUTS_PER_TX;

    /// A local network with NU6.3 active at a low height, matching the build test network, so the
    /// canonical fees and activation checks compute in planning tests.
    fn test_net() -> LocalNetwork {
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
            nu6_3: Some(BlockHeight::from_u32(10)),
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
        }
    }

    /// The canonical fees on the test network, computed exactly as `plan_migration` computes them.
    fn test_fees() -> (Zatoshis, Zatoshis) {
        canonical_fees(&test_net(), BlockHeight::from_u32(2_000_000))
            .expect("the canonical fees compute")
    }

    /// A count-only preparation-layout stub for tests that exercise the split in isolation: one
    /// padded transaction per [`FUNDING_OUTPUTS_PER_TX`] funding notes.
    fn prep_tx_count_stub(notes: &[Zatoshis]) -> Option<usize> {
        Some(notes.len().div_ceil(FUNDING_OUTPUTS_PER_TX))
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
            plan_migration(&test_net(), &backend, &mut rng).expect("a fundable balance plans");

        // Something is migrated; the schedule has one entry per funding note; the preparation mints
        // exactly the (reconciled) funding notes; and reconciliation only ever drops, never adds.
        assert!(!plan.funding_notes().is_empty());
        assert_eq!(plan.schedule().len(), plan.funding_notes().len());

        // The preparation schedule mirrors the layers' shape, is non-decreasing within each
        // layer, and each layer starts past the previous one (temporal decoupling with layer
        // serialization).
        assert_eq!(plan.prep_schedule().len(), plan.preparation().layer_count());
        let mut prev_layer_end = BlockHeight::from_u32(2_000_000);
        for (layer, heights) in plan.preparation().layers().iter().zip(plan.prep_schedule()) {
            assert_eq!(heights.len(), layer.len());
            let mut prev = prev_layer_end;
            for &h in heights {
                assert!(h >= prev, "prep schedule is non-decreasing across layers");
                prev = h;
            }
            prev_layer_end = prev;
        }

        // The schedule floor: no transfer is scheduled before the earliest height at which a
        // candidate anchor boundary exists, given the drawn preparation schedule plus the mining
        // margin.
        let est_last_prep = plan
            .prep_schedule()
            .last()
            .and_then(|layer| layer.last())
            .copied()
            .unwrap_or(BlockHeight::from_u32(2_000_000))
            + EST_PREP_LAYER_MINING_BLOCKS;
        let earliest =
            crate::scheduling::earliest_broadcast_height(BlockHeight::from_u32(10), est_last_prep);
        assert!(
            plan.schedule()
                .iter()
                .all(|s| s.broadcast_height() >= earliest),
            "every scheduled transfer is at or after the anchor-viability floor"
        );
        assert_eq!(
            plan.preparation().funding_notes().len(),
            plan.funding_notes().len()
        );
        assert!(plan.funding_notes().len() <= plan.note_split().migration_outputs().len());
    }

    /// SHUFFLE (ZIP 318): the crossings are non-increasing, so an unshuffled schedule would
    /// pair them with non-decreasing broadcast heights and the on-chain temporal sequence of
    /// denominations would spell out the balance. The drawn permutation makes the heights
    /// non-monotone in crossing index (deterministic for this seed).
    #[test]
    fn transfer_schedule_is_shuffled() {
        // A balance that splits into several denominations, so the order is observable.
        let backend = MockBackend::new(vec![78 * COIN], 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let plan =
            plan_migration(&test_net(), &backend, &mut rng).expect("a fundable balance plans");
        assert!(
            plan.funding_notes().len() >= 4,
            "the balance splits into several transfers: {}",
            plan.funding_notes().len()
        );
        let heights: Vec<u32> = plan
            .schedule()
            .iter()
            .map(|s| u32::from(s.broadcast_height()))
            .collect();
        assert!(
            heights.windows(2).any(|w| w[0] > w[1]),
            "the transfer broadcast order is shuffled: {heights:?}"
        );
    }

    #[test]
    fn empty_balance_has_nothing_to_migrate() {
        let backend = MockBackend::new(Vec::new(), 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        assert!(matches!(
            plan_migration(&test_net(), &backend, &mut rng),
            Err(MigrationError::NothingToMigrate)
        ));
    }

    #[test]
    fn stores_loads_and_updates_a_migration() {
        let mut backend = MockBackend::new(Vec::new(), 0);
        assert!(backend.get_migration().unwrap().is_none());

        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let (prep_tx_fee, transfer_buffer) = test_fees();
        let note_split = crate::note_splitting::plan_note_split(
            Zatoshis::from_u64(100 * COIN).expect("test balance is valid"),
            transfer_buffer,
            prep_tx_fee,
            &prep_tx_count_stub,
            &mut rng,
        );
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
            funding_notes: Vec::new(),
            preparation: crate::preparation::PreparationPlan::from_parts(Vec::new(), Vec::new()),
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
        TARGET_HEIGHT, regtest_network, single_note_witness, spending_key,
    };
    use crate::note_splitting::NoteSplitPlan;
    use crate::preparation::{PREP_TX_ACTIONS, plan_preparation};

    /// The canonical fees on the regtest network at the build height, computed exactly as
    /// `plan_migration` computes them.
    fn commit_test_fees() -> (Zatoshis, Zatoshis) {
        canonical_fees(&regtest_network(true), BlockHeight::from_u32(TARGET_HEIGHT))
            .expect("the canonical fees compute")
    }

    fn prep_fee() -> Zatoshis {
        commit_test_fees().0
    }

    /// A wallet mock holding the account's key and its spendable notes' PLAINTEXTS — nothing
    /// more: with anchors and witnesses deferred to proving time (ZIP 374), building and signing
    /// an entire migration needs no tree access at all. It signs with its own spend-authorizing
    /// key and stores the migration in memory.
    struct CommitMock {
        wallet_notes: Vec<orchard::note::Note>,
        fvk: FullViewingKey,
        ask: SpendAuthorizingKey,
        stored: Option<MigrationState>,
    }

    impl CommitMock {
        /// A mock wallet holding single notes of the given values, derived from `seed`.
        fn new(seed: u64, values: &[u64]) -> Self {
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

    impl MigrationCrypto for CommitMock {
        type Error = core::convert::Infallible;

        fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
            Ok(self.fvk.clone())
        }

        fn resolve_wallet_note(&self, index: usize) -> Result<orchard::note::Note, Self::Error> {
            Ok(self.wallet_notes[index])
        }

        fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error> {
            Ok(sign_pczt(pczt, &self.ask).expect("signs the migration PCZT"))
        }
    }

    /// A planned single-note migration and the mock wallet that holds the note.
    fn single_note_setup(seed: u64, balance: u64) -> (CommitMock, MigrationPlan) {
        let backend = CommitMock::new(seed, &[balance]);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
            .expect("a fundable balance plans");
        (backend, plan)
    }

    /// The WHOLE migration — every preparation transaction and every transfer — is built and
    /// SIGNED in the one commit pass, before anything is broadcast or mined: the funding notes
    /// are recovered from the built preparation bundles, and every stored PCZT carries ABSENT
    /// anchors (ZIP 374), to be installed at proving time against each transaction's anchor.
    #[test]
    fn commits_the_whole_migration_in_one_pass() {
        let seed = 7u64;
        let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
        // A single note funding a handful of denominations needs one preparation layer.
        assert_eq!(plan.preparation().layers().len(), 1);
        let params = regtest_network(true);
        let prep_count: usize = plan.preparation().layers().iter().map(|l| l.len()).sum();
        let transfer_count = plan.funding_notes().len();
        assert!(transfer_count >= 2, "several transfers: {transfer_count}");

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("commits the migration");
        assert_eq!(state.status, MigrationStatus::Committed);
        assert_eq!(state.transactions.len(), prep_count + transfer_count);

        // The funding notes exist only once the last preparation transaction has mined; every
        // drawn boundary must lie at or after that estimate, exactly as the draw is floored.
        let est_last_prep = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
            .map(|t| t.scheduled_height)
            .max()
            .expect("the plan has a preparation")
            + EST_PREP_LAYER_MINING_BLOCKS;

        for tx in &state.transactions {
            // ONE signing phase: everything is signed at commit, before anything mines.
            assert_eq!(tx.state, MigrationTxState::Signed, "signed at commit");
            assert!(!tx.pczt.is_empty());
            let parsed = pczt::Pczt::parse(&tx.pczt).expect("the stored PCZT parses");
            // Anchors are deferred (ZIP 374): every stored PCZT carries ABSENT anchors, and the
            // pre-signature commits to the stored canonical expiry for the drawn schedule.
            assert!(parsed.orchard().anchor().is_none());
            assert!(parsed.ironwood().anchor().is_none());
            assert_eq!(
                *parsed.global().expiry_height(),
                u32::from(tx.expiry_height),
                "the embedded expiry matches the stored schedule expiry"
            );
            match tx.kind {
                MigrationTxKind::Preparation { .. } => {
                    assert!(
                        tx.depends_on.is_empty(),
                        "single-layer preps are independent"
                    );
                    assert!(tx.anchor_boundary.is_none());
                }
                MigrationTxKind::Transfer { .. } => {
                    assert!(
                        !tx.depends_on.is_empty(),
                        "a transfer BROADCASTS only after the preparation mines"
                    );
                    // The boundary anchor the transfer will PROVE against is drawn at commit
                    // time: on the boundary grid, strictly above the NU6.3 activation, at or
                    // after the estimated height the last preparation has mined, and strictly
                    // below the most recent boundary at the scheduled broadcast height.
                    let b = u32::from(
                        tx.anchor_boundary
                            .expect("every transfer carries its boundary"),
                    );
                    assert_eq!(b % crate::scheduling::BOUNDARY_MODULUS, 0);
                    assert!(b > 10, "boundary above the regtest NU6.3 activation");
                    assert!(
                        b >= u32::from(est_last_prep).div_ceil(crate::scheduling::BOUNDARY_MODULUS)
                            * crate::scheduling::BOUNDARY_MODULUS
                    );
                    assert!(
                        b < u32::from(crate::scheduling::most_recent_boundary(tx.scheduled_height))
                    );
                }
            }
        }
        assert!(backend.get_migration().unwrap().is_some());
    }

    /// A lone whale fanning out into more funding notes than one transaction holds needs a
    /// MULTI-LAYER preparation — and it still signs in the SAME single pass: the later layer's
    /// feeder spends and the transfers' funding notes are recovered from the earlier layers'
    /// built (unmined) bundles. Mining then gates only the broadcast order, which the state
    /// machine walks layer by layer.
    #[test]
    fn commits_a_multi_layer_migration_in_one_pass() {
        let seed = 11u64;
        let sk = spending_key(seed);
        let fvk = FullViewingKey::from(&sk);

        // 15 funding notes (one more than a single transaction's FUNDING_OUTPUTS_PER_TX) force a
        // two-layer balanced fan-out. Each is a valid self-funding note (a crossing value plus
        // the transfer fee buffer), so its transfer balances.
        let buffer = u64::from(commit_test_fees().1);
        let crossing = COIN; // 1 ZEC crossing per note
        let funding_note = crossing + buffer;
        let funding: Vec<u64> = core::iter::repeat_n(funding_note, 15).collect();

        // A whale generously larger than the balanced-tree cost, so the fan-out fast path
        // triggers.
        let whale = funding.iter().sum::<u64>() + 16 * u64::from(prep_fee());
        let whale_zats = [Zatoshis::from_u64(whale).expect("test whale is valid")];
        let funding_zats: Vec<Zatoshis> = funding
            .iter()
            .map(|&v| Zatoshis::from_u64(v).expect("test funding values are valid"))
            .collect();
        let preparation = plan_preparation(&whale_zats, &funding_zats, prep_fee())
            .expect("a fundable whale plans");
        assert_eq!(
            preparation.layers().len(),
            2,
            "15 funding notes fan out across two layers"
        );

        // A note split whose outputs are the funding notes and whose crossings are those less
        // the buffer, so each transfer crosses one ZEC.
        let crossings: Vec<u64> = funding.iter().map(|&f| f - buffer).collect();
        let note_split = NoteSplitPlan::from_stored_parts(
            crossings
                .iter()
                .map(|&v| Zatoshis::from_u64(v).expect("test crossings are valid"))
                .collect(),
            Zatoshis::from_u64(buffer).expect("the buffer is valid"),
            None,
            Zatoshis::from_u64(preparation.transaction_count() as u64 * u64::from(prep_fee()))
                .expect("the reserved fees are valid"),
            whale_zats[0],
            Zatoshis::from_u64(crossings.iter().sum()).expect("the crossing total is valid"),
        )
        .expect("a consistent stored plan reconstructs");
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        // A drawn preparation schedule in the layers' shape, each layer based past the previous
        // one, exactly as `plan_migration` draws it.
        let mut prep_schedule: Vec<Vec<BlockHeight>> = Vec::new();
        let mut layer_base = BlockHeight::from_u32(2_000_000);
        for layer in preparation.layers() {
            let heights = crate::scheduling::schedule_prep_broadcast_heights(
                layer_base,
                layer.len(),
                &mut rng,
            );
            layer_base =
                heights.last().copied().unwrap_or(layer_base) + EST_PREP_LAYER_MINING_BLOCKS;
            prep_schedule.push(heights);
        }
        // Floor the transfer schedule so every transfer has a candidate anchor boundary above
        // the estimated last-preparation mining height, exactly as `plan_migration` floors it.
        let nu63_activation = {
            use zcash_protocol::consensus::{NetworkUpgrade, Parameters as _};
            regtest_network(true)
                .activation_height(NetworkUpgrade::Nu6_3)
                .expect("NU6.3 is active on the test network")
        };
        let schedule_base =
            crate::scheduling::earliest_broadcast_height(nu63_activation, layer_base);
        let schedule = crate::scheduling::schedule(schedule_base, funding.len(), &mut rng);
        let plan = MigrationPlan {
            note_split,
            funding_notes: funding_zats,
            preparation,
            prep_schedule,
            schedule,
        };

        let mut backend = CommitMock {
            wallet_notes: vec![single_note_witness(&fvk, whale, seed).0],
            fvk,
            ask: SpendAuthorizingKey::from(&sk),
            stored: None,
        };
        let params = regtest_network(true);
        let prep_count = plan.preparation().transaction_count();
        let transfer_count = funding.len();

        // ONE pass builds and signs both layers and every transfer.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("commits the migration");
        assert_eq!(state.transactions.len(), prep_count + transfer_count);
        for tx in &state.transactions {
            assert_eq!(tx.state, MigrationTxState::Signed, "signed at commit");
            assert!(!tx.pczt.is_empty());
        }
        let layer0_ids: Vec<MigrationTxId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 0, .. }))
            .map(|t| t.id)
            .collect();
        assert_eq!(layer0_ids.len(), 1, "one root transaction in layer 0");
        for tx in &state.transactions {
            match tx.kind {
                MigrationTxKind::Preparation { layer, .. } if layer > 0 => {
                    assert_eq!(
                        tx.depends_on, layer0_ids,
                        "a later layer broadcasts only after its predecessor mines"
                    );
                }
                _ => {}
            }
        }

        // The state machine walks the broadcasts in dependency order: layer 0 first; layer 1
        // only once layer 0 mines; the transfers only once the whole preparation mines.
        let mut state = state;
        let target = BlockHeight::from_u32(2_100_000);
        match state.next_step(target) {
            crate::state::AdvanceStep::Broadcast { id } => {
                assert!(layer0_ids.contains(&id), "layer 0 broadcasts first")
            }
            other => panic!("expected a broadcast step, got {other:?}"),
        }
        for id in &layer0_ids {
            state.mark_mined(*id, BlockHeight::from_u32(2_000_010));
        }
        let layer1_ids: Vec<MigrationTxId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 1, .. }))
            .map(|t| t.id)
            .collect();
        match state.next_step(target) {
            crate::state::AdvanceStep::Broadcast { id } => {
                assert!(
                    layer1_ids.contains(&id),
                    "layer 1 broadcasts once layer 0 mines"
                )
            }
            other => panic!("expected a broadcast step, got {other:?}"),
        }
        for id in &layer1_ids {
            state.mark_mined(*id, BlockHeight::from_u32(2_000_020));
        }
        match state.next_step(target) {
            crate::state::AdvanceStep::Broadcast { id } => {
                let tx = state
                    .transactions
                    .iter()
                    .find(|t| t.id == id)
                    .expect("the step names a stored transaction");
                assert!(
                    matches!(tx.kind, MigrationTxKind::Transfer { .. }),
                    "the transfers broadcast once the whole preparation mines"
                );
            }
            other => panic!("expected a broadcast step, got {other:?}"),
        }
    }

    /// The EXTERNAL path builds the whole migration unsigned in the same one pass, and the
    /// unsigned transactions split into signing sessions bounded by the device's action budget —
    /// consecutive topological prefixes, never gated on mining.
    #[test]
    fn external_signing_batches_by_action_budget() {
        let seed = 19u64;
        let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
        let params = regtest_network(true);

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let (mut state, unsigned) = build_preparation_unsigned(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("builds the migration unsigned");
        assert_eq!(unsigned.len(), state.transactions.len());
        for tx in &state.transactions {
            assert_eq!(tx.state, MigrationTxState::AwaitingSignature);
        }

        // Sessions are consecutive prefixes bounded by the action budget; a preparation is
        // PREP_TX_ACTIONS actions, so a budget of one preparation plus one transfer splits the
        // list without ever exceeding the budget (every batch is non-empty and within budget).
        let budget = PREP_TX_ACTIONS
            + crate::note_splitting::SOURCE_ACTIONS_PER_TRANSFER
            + crate::note_splitting::DESTINATION_ACTIONS_PER_TRANSFER;
        let total = unsigned.len();
        let sessions = batch_unsigned_by_action_budget(unsigned, budget);
        assert!(sessions.len() > 1, "several sessions: {}", sessions.len());
        assert_eq!(sessions.iter().map(|s| s.len()).sum::<usize>(), total);
        for session in &sessions {
            assert!(!session.is_empty());
            assert!(session.iter().map(|tx| tx.actions()).sum::<usize>() <= budget);
        }

        // Sign every session out of band and apply the signatures back; the whole migration is
        // then Signed without anything having been broadcast or mined.
        let ask = SpendAuthorizingKey::from(&spending_key(seed));
        for session in sessions {
            for unsigned_tx in session {
                let (id, bytes) = unsigned_tx.into_parts();
                let signed = sign_pczt(
                    pczt::Pczt::parse(&bytes).expect("the unsigned PCZT parses"),
                    &ask,
                )
                .expect("the device signs the transaction");
                assert!(state.apply_signature(id, signed.serialize().expect("serializes")));
            }
        }
        backend.put_migration(&state).unwrap();
        for tx in &state.transactions {
            assert_eq!(tx.state, MigrationTxState::Signed);
        }
    }

    /// A committed migration must be resumed, never rebuilt over: a second commit while the
    /// stored migration is non-terminal is refused (its pre-signed transactions may already be
    /// broadcast, and a rebuilt migration would double-spend the same notes); a terminal
    /// (failed/cancelled) migration may be replaced.
    #[test]
    fn commit_preparation_refuses_to_overwrite_a_live_migration() {
        let seed = 13u64;
        let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
        let params = regtest_network(true);

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("commits the migration");

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        assert!(matches!(
            commit_preparation(
                &params,
                BlockHeight::from_u32(TARGET_HEIGHT),
                &mut backend,
                &plan,
                &mut rng,
            ),
            Err(CommitError::MigrationInProgress)
        ));

        // A terminal (cancelled) migration may be replaced.
        let mut stored = backend.get_migration().unwrap().expect("stored");
        stored.status = MigrationStatus::Failed;
        backend.put_migration(&stored).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 3);
        commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("replaces a terminal migration");
    }

    /// A wallet note is resolved by its index into the CURRENT spendable set; if that set
    /// changed since planning (the value at the planned index no longer matches), the commit
    /// reports a stale plan instead of building against the wrong note.
    #[test]
    fn commit_preparation_detects_a_stale_plan() {
        let seed = 17u64;
        let (_, plan) = single_note_setup(seed, 78 * COIN);

        // The spendable set shifted between planning and commit: the note at index 0 now has a
        // different value than the plan recorded.
        let mut backend = CommitMock::new(seed, &[78 * COIN + COIN]);
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        assert!(matches!(
            commit_preparation(
                &regtest_network(true),
                BlockHeight::from_u32(TARGET_HEIGHT),
                &mut backend,
                &plan,
                &mut rng,
            ),
            Err(CommitError::StalePlan)
        ));
    }
}
