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
use core::num::NonZeroUsize;

use corez::io;

use getset::{CopyGetters, Getters};
use rand_core::RngCore;
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{BalanceError, Zatoshis};

use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::fees::{transparent, zip317};

use crate::note_splitting::{NoteSplitPlan, plan_note_split};
use crate::preparation::{PrepError, PrepInput, PreparationPlan, plan_preparation};
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
/// `zcash_client_backend`'s `WalletRead`. A store implements this over its own tables
/// (`zcash_client_sqlite`'s `pool_migration` module does so over tables registered into its
/// `WalletDb` schema). The committed migration is a set of pre-signed PCZTs plus their schedule and
/// lifecycle state, so a wallet resumes a migration entirely from the store after being closed or
/// restarted.
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
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error>;

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
    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_le_bytes())
    }

    /// Reads an id written by [`write`](Self::write).
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
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

impl AsRef<str> for MigrationTxKind {
    /// The stable lowercase wire name of this kind, as a store persists it (the queryable
    /// discriminant); the per-variant indices are stored alongside and reattached by
    /// [`from_stored`](Self::from_stored).
    fn as_ref(&self) -> &str {
        match self {
            MigrationTxKind::Preparation { .. } => "preparation",
            MigrationTxKind::Transfer { .. } => "transfer",
        }
    }
}

impl MigrationTxKind {
    /// The `(layer, index)` of a [`Preparation`](Self::Preparation) kind (its stored indices), or
    /// `None` for a [`Transfer`](Self::Transfer).
    pub fn preparation_indices(&self) -> Option<(usize, usize)> {
        match self {
            MigrationTxKind::Preparation { layer, index } => Some((*layer, *index)),
            MigrationTxKind::Transfer { .. } => None,
        }
    }

    /// The `crossing` of a [`Transfer`](Self::Transfer) kind (its stored index), or `None` for a
    /// [`Preparation`](Self::Preparation).
    pub fn transfer_crossing(&self) -> Option<usize> {
        match self {
            MigrationTxKind::Transfer { crossing } => Some(*crossing),
            MigrationTxKind::Preparation { .. } => None,
        }
    }

    /// Reconstruct a kind from the stored discriminant (the [`AsRef<str>`](AsRef) value) and the
    /// per-variant index columns (each `None` for the variant that does not carry it). Errors on an
    /// unrecognized discriminant, or a discriminant whose index columns are absent.
    pub fn from_stored(
        kind: &str,
        layer: Option<usize>,
        index: Option<usize>,
        crossing: Option<usize>,
    ) -> Result<Self, ParseMigrationTxKindError> {
        Ok(match kind {
            "preparation" => MigrationTxKind::Preparation {
                layer: layer.ok_or(ParseMigrationTxKindError)?,
                index: index.ok_or(ParseMigrationTxKindError)?,
            },
            "transfer" => MigrationTxKind::Transfer {
                crossing: crossing.ok_or(ParseMigrationTxKindError)?,
            },
            _ => return Err(ParseMigrationTxKindError),
        })
    }
}

/// The error returned when a stored `(kind, layer, index, crossing)` tuple does not reconstruct a
/// [`MigrationTxKind`] (its [`from_stored`](MigrationTxKind::from_stored) constructor): an
/// unrecognized discriminant, or a variant missing its index columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationTxKindError;

impl fmt::Display for ParseMigrationTxKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized or incomplete migration transaction kind")
    }
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

impl AsRef<str> for MigrationTxState {
    /// The stable lowercase wire name of the lifecycle state, as a store persists it (the queryable
    /// discriminant); the `Broadcast` txid and `Mined` height are stored alongside and reattached by
    /// [`from_stored`](Self::from_stored).
    fn as_ref(&self) -> &str {
        match self {
            MigrationTxState::AwaitingSignature => "awaiting_signature",
            MigrationTxState::Signed => "signed",
            MigrationTxState::Proved => "proved",
            MigrationTxState::Broadcast { .. } => "broadcast",
            MigrationTxState::Mined { .. } => "mined",
        }
    }
}

/// The error returned when a stored `(state, txid, mined_height)` triple does not reconstruct a
/// [`MigrationTxState`] (its [`from_stored`](MigrationTxState::from_stored) constructor): an
/// unrecognized discriminant, or a `broadcast`/`mined` row missing its txid/height payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationTxStateError;

impl fmt::Display for ParseMigrationTxStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized or incomplete migration transaction state")
    }
}

impl MigrationTxState {
    /// The transaction id of a [`Broadcast`](Self::Broadcast) state (its stored payload), or `None`
    /// for any other state.
    pub fn broadcast_txid(&self) -> Option<[u8; 32]> {
        match self {
            MigrationTxState::Broadcast { txid } => Some(*txid.as_ref()),
            _ => None,
        }
    }

    /// The block height of a [`Mined`](Self::Mined) state (its stored payload), or `None` for any
    /// other state.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        match self {
            MigrationTxState::Mined { height } => Some(*height),
            _ => None,
        }
    }

    /// Reconstruct a state from a store: the lowercase discriminant produced by
    /// [`AsRef<str>`](AsRef), plus the `broadcast` txid and `mined` height columns (each `None` for a
    /// state that does not carry it). Errors on an unrecognized discriminant, or a `broadcast`/`mined`
    /// discriminant whose payload column is absent.
    pub fn from_stored(
        state: &str,
        txid: Option<[u8; 32]>,
        mined_height: Option<BlockHeight>,
    ) -> Result<Self, ParseMigrationTxStateError> {
        Ok(match state {
            "awaiting_signature" => MigrationTxState::AwaitingSignature,
            "signed" => MigrationTxState::Signed,
            "proved" => MigrationTxState::Proved,
            "broadcast" => MigrationTxState::Broadcast {
                txid: TxId::from_bytes(txid.ok_or(ParseMigrationTxStateError)?),
            },
            "mined" => MigrationTxState::Mined {
                height: mined_height.ok_or(ParseMigrationTxStateError)?,
            },
            _ => return Err(ParseMigrationTxStateError),
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
        preparation: PreparationPlan,
        transactions: Vec<MigrationTransaction>,
    ) -> Self {
        Self {
            status,
            note_split,
            preparation,
            transactions,
        }
    }

    /// The self-funding note values (in zatoshi), one per crossing: a `Transfer { crossing }`
    /// transaction spends `funding_notes()[crossing]` and crosses that value minus the fee buffer
    /// into the destination pool. Derived from the note split (each crossing value plus the fee
    /// buffer), so a store persists only the note split.
    pub fn funding_notes(&self) -> Vec<Zatoshis> {
        self.note_split.migration_outputs()
    }

    /// Replace transfer `id`'s stored PCZT with its proven bytes and move it to
    /// [`Proved`](MigrationTxState::Proved). Called after [`prove_transfer`] installs the drawn
    /// anchor and witnesses and proves the transaction, so the durable artifact becomes the proven,
    /// ready-to-broadcast PCZT.
    #[cfg(feature = "orchard")]
    pub fn set_transaction_proved(&mut self, id: MigrationTxId, proven_pczt: Vec<u8>) {
        for tx in &mut self.transactions {
            if tx.id() == id {
                tx.pczt = proven_pczt;
                tx.state = MigrationTxState::Proved;
                break;
            }
        }
    }
}

/// A planned migration, before anything is built, signed, or broadcast: the denomination split, the
/// preparation transactions that mint the funding notes, and the phase-2 transfer schedule. This is the
/// preview a wallet shows the user for consent (ZIP 318) to the pool-crossing amounts.
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    note_split: NoteSplitPlan,
    preparation: PreparationPlan,
    prep_schedule: Vec<Vec<BlockHeight>>,
    schedule: Vec<Schedule>,
}

impl MigrationPlan {
    /// The note-split decomposition (the denominations and residual). The split already reflects
    /// reconciliation against the preparation fees: when the fees did not fit the balance, the
    /// smallest denominations were dropped (left in the source pool) during the decomposition.
    pub fn note_split(&self) -> &NoteSplitPlan {
        &self.note_split
    }

    /// The funding-note values this migration will mint, one per phase-2 crossing. Derived from the
    /// note split (each crossing value plus the fee buffer).
    pub fn funding_notes(&self) -> Vec<Zatoshis> {
        self.note_split.migration_outputs()
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
    R: RngCore + rand_core::CryptoRng,
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
        preparation,
        prep_schedule,
        schedule,
    })
}

/// A per-run entry of a [`MigrationRunEstimate`]: what one migration run migrates (the note-split
/// side) and what preparing it costs (the note-preparation side), so the two can be compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunEstimate {
    migratable: Zatoshis,
    crossings: usize,
    prep_layers: usize,
    prep_transactions: usize,
}

impl RunEstimate {
    /// The total value that crosses the turnstile in this run (the sum of its crossing denominations).
    pub fn migratable(&self) -> Zatoshis {
        self.migratable
    }

    /// The number of pool-crossing transfers this run makes: one per self-funding note the note split
    /// produced for it.
    pub fn crossings(&self) -> usize {
        self.crossings
    }

    /// The number of sequential note-preparation layers this run needs — its wall-clock depth, since
    /// each layer waits for the previous one to mine before it can be broadcast.
    pub fn prep_layers(&self) -> usize {
        self.prep_layers
    }

    /// The number of note-preparation transactions this run builds across all its layers.
    pub fn prep_transactions(&self) -> usize {
        self.prep_transactions
    }

    /// The total number of transactions this run builds and signs: its preparation transactions plus
    /// one pool-crossing transfer per funding note.
    pub fn transactions(&self) -> usize {
        self.prep_transactions + self.crossings
    }

    /// The number of signing sessions this run needs when an external signer (for example a Keystone
    /// hardware wallet) can sign at most `max_per_session` transactions in one interaction:
    /// `ceil(transactions / max_per_session)`. All of a run's transactions are built and signed
    /// together (anchors and witnesses are deferred to proving time, [ZIP 374]), so they pool into
    /// sessions bounded only by the signer's capacity.
    ///
    /// [ZIP 374]: https://zips.z.cash/zip-0374
    pub fn signing_sessions(&self, max_per_session: NonZeroUsize) -> usize {
        self.transactions().div_ceil(max_per_session.get())
    }
}

/// An estimate of migrating a wallet's whole spendable balance across successive migration RUNS
/// ("rounds"): one [`RunEstimate`] per run and the value left un-migrated at the end.
///
/// A balance beyond one run's capacity (the note cap times the maximum denomination) migrates over
/// several runs, each run's spent notes and preparation residuals forming the next run's note
/// structure (see [`estimate_migration_runs`]). Each run carries BOTH sides so an application can
/// compare them: the note-split crossings it migrates and the note-preparation layers and
/// transactions it costs.
///
/// A capacity-limited external signer adds a third dimension: given how many transactions such a
/// signer can sign in one interaction, [`total_signing_sessions`](Self::total_signing_sessions) gives
/// the number of signing interactions the whole migration requires. That limit is a query parameter,
/// not part of the estimate, so an SDK can evaluate it for any signer capacity without re-running the
/// planners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRunEstimate {
    runs: Vec<RunEstimate>,
    final_residual: Zatoshis,
}

impl MigrationRunEstimate {
    /// The expected number of migration runs ("rounds") to migrate the whole balance: zero when the
    /// balance is below the smallest self-funding note, so nothing migrates.
    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// The per-run estimates, in run order.
    pub fn runs(&self) -> &[RunEstimate] {
        &self.runs
    }

    /// The value left in the source pool after the last run — below the smallest self-funding note, so
    /// it never migrates. Zero when the balance divides exactly into self-funding notes and fees.
    pub fn final_residual(&self) -> Zatoshis {
        self.final_residual
    }

    /// The total value that migrates across all runs (the sum of each run's
    /// [`migratable`](RunEstimate::migratable)).
    pub fn total_migratable(&self) -> Zatoshis {
        self.runs
            .iter()
            .map(RunEstimate::migratable)
            .sum::<Option<Zatoshis>>()
            .expect("the per-run migratable totals sum to at most the validated balance")
    }

    /// The total number of pool-crossing transfers across all runs (the sum of each run's
    /// [`crossings`](RunEstimate::crossings)).
    pub fn total_crossings(&self) -> usize {
        self.runs.iter().map(RunEstimate::crossings).sum()
    }

    /// The total number of note-preparation layers across all runs (the sum of each run's
    /// [`prep_layers`](RunEstimate::prep_layers)).
    pub fn total_prep_layers(&self) -> usize {
        self.runs.iter().map(RunEstimate::prep_layers).sum()
    }

    /// The total number of note-preparation transactions across all runs (the sum of each run's
    /// [`prep_transactions`](RunEstimate::prep_transactions)).
    pub fn total_prep_transactions(&self) -> usize {
        self.runs.iter().map(RunEstimate::prep_transactions).sum()
    }

    /// The total number of transactions the whole migration builds and signs across all runs (the sum
    /// of each run's [`transactions`](RunEstimate::transactions); equivalently
    /// [`total_prep_transactions`](Self::total_prep_transactions) plus
    /// [`total_crossings`](Self::total_crossings)).
    pub fn total_transactions(&self) -> usize {
        self.runs.iter().map(RunEstimate::transactions).sum()
    }

    /// The total number of signing sessions the whole migration needs when an external signer can sign
    /// at most `max_per_session` transactions in one interaction — the number of times the user must
    /// interact with a capacity-limited hardware signer (for example a Keystone, whose limit the SDK
    /// passes in here).
    ///
    /// This is the SUM of each run's [`signing_sessions`](RunEstimate::signing_sessions), NOT
    /// `ceil(total_transactions / max_per_session)`, because signing sessions cannot span runs: a later
    /// run's transactions spend notes an earlier run must mine first, so each run is signed on its own.
    pub fn total_signing_sessions(&self, max_per_session: NonZeroUsize) -> usize {
        self.runs
            .iter()
            .map(|run| run.signing_sessions(max_per_session))
            .sum()
    }
}

/// Estimate how the account the `backend` represents will migrate its whole spendable balance: the
/// number of migration RUNS ("rounds") it takes, and for each run BOTH what it migrates (the
/// note-split crossings) and what preparing it costs (the note-preparation layers and transactions),
/// so an application can preview and compare the two before anything is planned or committed.
///
/// A run prepares a bounded number of capped self-funding notes, so a balance beyond one run's
/// capacity migrates over several runs. The estimate depends on the wallet's NOTE STRUCTURE, not just
/// its total value: each run is decomposed with the REAL preparation planner over the current notes
/// (so its feasibility and fees are exact, exactly as [`plan_migration`] plans one run), and the notes
/// that run spends and the residuals it leaves form the next run's structure.
///
/// The note-split run count itself does NOT depend on an external signer's capacity. When a
/// capacity-limited hardware signer (for example a Keystone) can sign only so many transactions in one
/// interaction, pass that user-configured limit to
/// [`MigrationRunEstimate::total_signing_sessions`] to get the number of signing interactions the
/// migration requires (each run is signed on its own; see that method). Because this iterates the
/// note-split and preparation planners once per run, its cost is roughly one [`plan_migration`] per
/// run.
///
/// A zero (or fully sub-quantum) balance yields a zero-run estimate rather than an error, since this
/// is a preview. `rng` is drawn from only by a randomized note-split strategy; the recommended
/// canonical strategy ignores it.
pub fn estimate_migration_runs<P, B, R>(
    params: &P,
    backend: &B,
    rng: &mut R,
) -> Result<MigrationRunEstimate, MigrationError<B::Error>>
where
    P: zcash_protocol::consensus::Parameters,
    B: MigrationBackend,
    R: RngCore + rand_core::CryptoRng,
{
    let height = backend
        .chain_tip_height()
        .map_err(MigrationError::Backend)?;
    let (prep_tx_fee, transfer_fee_buffer) =
        canonical_fees(params, height).map_err(MigrationError::Fee)?;
    // The note structure the migration works on, evolving run by run: initially the wallet's own
    // spendable notes, then each run's unspent notes plus its preparation residuals.
    let mut notes = backend
        .spendable_orchard_note_values()
        .map_err(MigrationError::Backend)?;

    let mut runs: Vec<RunEstimate> = Vec::new();
    loop {
        let balance = notes
            .iter()
            .copied()
            .sum::<Option<Zatoshis>>()
            .ok_or(MigrationError::InvalidBalance(BalanceError::Overflow))?;

        // This run's note split, decomposing the CURRENT note set. Its per-step preparation cost and
        // feasibility are backed by the real preparation planner over the current notes, so the split
        // — and hence the whole run count — depends on the wallet's note structure, not just its
        // total value. The closure's borrow of `notes` is released with the block, before `notes` is
        // reassigned below.
        let note_split = {
            let prep_tx_count = |funding: &[Zatoshis]| {
                plan_preparation(&notes, funding, prep_tx_fee)
                    .ok()
                    .map(|plan| plan.transaction_count())
            };
            plan_note_split(
                balance,
                transfer_fee_buffer,
                prep_tx_fee,
                &prep_tx_count,
                rng,
            )
        };

        let funding = note_split.migration_outputs();
        if funding.is_empty() {
            // Nothing more migrates from this note set: the remaining balance is the final residual
            // and the migration is complete.
            return Ok(MigrationRunEstimate {
                runs,
                final_residual: balance,
            });
        }

        // The preparation that mints this run's funding notes: its layer and transaction counts are
        // the note-preparation side of the estimate, and which notes it spends and which residuals it
        // leaves give the next run's note structure. The note split only ever proposes a funding
        // multiset the preparation planner accepted, so this plan succeeds by construction.
        let preparation =
            plan_preparation(&notes, &funding, prep_tx_fee).map_err(MigrationError::Preparation)?;
        runs.push(RunEstimate {
            migratable: note_split.total_migratable(),
            crossings: funding.len(),
            prep_layers: preparation.layer_count(),
            prep_transactions: preparation.transaction_count(),
        });
        notes = source_pool_notes_after_run(&notes, &preparation);
    }
}

/// The source-pool notes that remain after a migration run, forming the next run's note structure: the
/// wallet notes the run's preparation did not spend (and did not use directly as a funding note, which
/// crosses out), plus the residual notes the preparation leaves behind. The run's minted funding notes
/// are crossed out by the transfers, so they do not remain.
fn source_pool_notes_after_run(
    wallet: &[Zatoshis],
    preparation: &PreparationPlan,
) -> Vec<Zatoshis> {
    let mut spent = vec![false; wallet.len()];
    for layer in preparation.layers() {
        for tx in layer {
            for input in tx.inputs() {
                if let PrepInput::Wallet { index, .. } = input {
                    if let Some(flag) = spent.get_mut(*index) {
                        *flag = true;
                    }
                }
            }
        }
    }
    // Notes used directly as a funding note cross out with the transfers, so they do not remain.
    for &(index, _) in preparation.direct_funding_notes() {
        if let Some(flag) = spent.get_mut(index) {
            *flag = true;
        }
    }
    let mut remaining: Vec<Zatoshis> = wallet
        .iter()
        .copied()
        .zip(spent)
        .filter_map(|(value, is_spent)| (!is_spent).then_some(value))
        .collect();
    remaining.extend(preparation.residual_notes());
    remaining
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

/// The proving seam for a migration transfer: install a transfer's deferred anchors and witnesses
/// (ZIP 374) against the boundary its schedule drew, then prove it.
///
/// This is deliberately SEPARATE from [`MigrationCrypto`]. Signing needs only the account's spend
/// authority and is a cheap, read-only (`&self`) operation; proving needs MUTABLE access to the
/// wallet's Orchard commitment tree at a historical checkpoint (resolving a witness caches into the
/// tree) plus the Orchard and Ironwood proving keys, a heavier capability with a different lifetime.
/// Keeping proving in its own trait lets a wallet expose signing without dragging commitment-tree
/// access and proving parameters into the same type, and lets a consumer supply a prover
/// independently of the signer.
#[cfg(feature = "orchard")]
pub trait MigrationProver {
    /// The prover's error type.
    type Error;

    /// Prove a pre-signed transfer against the boundary its schedule drew.
    ///
    /// This is where a transfer's DEFERRED anchors and witnesses (ZIP 374) are finally resolved and
    /// installed: the implementation reads the Orchard source-tree root at the `anchor_boundary`
    /// checkpoint (the source anchor) and the funding note's Merkle witness against it, installs both
    /// through the PCZT `Updater` role (`set_anchor` / `set_spend_witness`), installs the Ironwood
    /// destination anchor for the output bundle, then proves both bundles and returns the proven
    /// PCZT, ready to broadcast. The `anchor_boundary` is the boundary height drawn at SCHEDULING
    /// time and persisted on the transaction ([`MigrationTransaction::anchor_boundary`]); passing it
    /// here is what makes the drawn boundary, not the tip, the tree state the transfer proves
    /// against.
    ///
    /// Resolving the funding note's witness requires the boundary checkpoint to still exist in the
    /// wallet's commitment tree at proving time; a wallet backend keeps it alive through migration
    /// anchor-checkpoint retention (see issue #2700).
    fn prove_transfer(
        &mut self,
        pczt: pczt::Pczt,
        anchor_boundary: BlockHeight,
    ) -> Result<pczt::Pczt, Self::Error>;

    /// Prove a pre-signed PREPARATION transaction against a checkpoint at which its spent notes are
    /// witnessable.
    ///
    /// Like a transfer, a preparation transaction defers its Orchard anchor and its spends'
    /// witnesses to proving time (ZIP 374), but it carries NO drawn
    /// [`anchor_boundary`](MigrationTransaction::anchor_boundary) (it anchors to its already-mined
    /// dependencies, not to a bucketed boundary), so the `anchor` height is passed in: the caller
    /// proves a preparation once its inputs are mined and picks a checkpoint at or after that (for
    /// example the current chain tip). A preparation spends the wallet's own notes (layer 0) or
    /// feeder notes minted by an earlier layer — one or MANY, unlike a transfer's single funding
    /// note — and produces only an Orchard bundle (no Ironwood output), so the implementation
    /// installs the anchor and every real spend's witness through the PCZT `Updater` role and proves
    /// the single Orchard bundle.
    fn prove_preparation(
        &mut self,
        pczt: pczt::Pczt,
        anchor: BlockHeight,
    ) -> Result<pczt::Pczt, Self::Error>;
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

/// Why proving a migration transfer failed.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum ProveError<E> {
    /// No transaction with the given id belongs to the migration.
    UnknownTransaction(MigrationTxId),
    /// The transaction is a preparation transaction, not a transfer; only transfers are proved
    /// against a drawn anchor boundary (a preparation transaction carries no boundary).
    NotATransfer(MigrationTxId),
    /// The transaction is a transfer, not a preparation transaction; only preparation transactions
    /// are proved against a caller-supplied anchor (a transfer proves against its drawn boundary).
    NotAPreparation(MigrationTxId),
    /// The transaction is not in the [`Signed`](MigrationTxState::Signed) state, so it is not ready
    /// to prove (it is unsigned, already proved, or already broadcast).
    NotReady(MigrationTxId),
    /// A transfer carries no anchor boundary. Every transfer draws one at scheduling time, so this
    /// indicates a corrupt stored state rather than a normal condition.
    NoAnchorBoundary(MigrationTxId),
    /// The stored PCZT could not be parsed.
    Parse(pczt::ParseError),
    /// The proven PCZT could not be serialized.
    Serialize(pczt::EncodingError),
    /// The prover failed to resolve, install, or prove the transfer.
    Prover(E),
}

#[cfg(feature = "orchard")]
impl<E: fmt::Display> fmt::Display for ProveError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProveError::UnknownTransaction(id) => {
                write!(f, "no migration transaction with id {}", u32::from(*id))
            }
            ProveError::NotATransfer(id) => write!(
                f,
                "transaction {} is a preparation transaction, not a transfer",
                u32::from(*id)
            ),
            ProveError::NotAPreparation(id) => write!(
                f,
                "transaction {} is a transfer, not a preparation transaction",
                u32::from(*id)
            ),
            ProveError::NotReady(id) => {
                write!(
                    f,
                    "transaction {} is not signed and ready to prove",
                    u32::from(*id)
                )
            }
            ProveError::NoAnchorBoundary(id) => write!(
                f,
                "transfer {} has no drawn anchor boundary; the stored state is inconsistent",
                u32::from(*id)
            ),
            ProveError::Parse(e) => write!(f, "parsing the stored PCZT failed: {e:?}"),
            ProveError::Serialize(e) => write!(f, "serializing the proven PCZT failed: {e:?}"),
            ProveError::Prover(e) => write!(f, "proving the transfer failed: {e}"),
        }
    }
}

#[cfg(feature = "orchard")]
impl<E: core::error::Error> core::error::Error for ProveError<E> {}

/// Prove a pre-signed migration transfer against the boundary its schedule drew, moving it
/// `Signed -> Proved`.
///
/// This is the step that finally consults a transfer's PERSISTED
/// [`anchor_boundary`](MigrationTransaction::anchor_boundary), drawn at scheduling time: it reads
/// that boundary and hands the stored PCZT and the boundary to
/// [`MigrationProver::prove_transfer`], which installs the Orchard source anchor and the funding
/// note's witness against that boundary and the Ironwood destination anchor (through the PCZT
/// `Updater` role), then proves both bundles. The proven PCZT replaces the stored one and the
/// transaction becomes [`Proved`](MigrationTxState::Proved), ready to broadcast.
///
/// The CALLER decides WHEN to prove each transfer (once its funding note is mined and witnessable
/// and its scheduled height reached); this function performs the proof for the one transfer `id`. It
/// is idempotent only in the sense that a transaction not in [`Signed`](MigrationTxState::Signed)
/// is rejected with [`ProveError::NotReady`] rather than re-proved.
#[cfg(feature = "orchard")]
pub fn prove_transfer<P>(
    prover: &mut P,
    state: &mut MigrationState,
    id: MigrationTxId,
) -> Result<(), ProveError<P::Error>>
where
    P: MigrationProver,
{
    let tx = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .ok_or(ProveError::UnknownTransaction(id))?;
    if !matches!(tx.kind(), MigrationTxKind::Transfer { .. }) {
        return Err(ProveError::NotATransfer(id));
    }
    if !matches!(tx.state(), MigrationTxState::Signed) {
        return Err(ProveError::NotReady(id));
    }
    let anchor_boundary = tx
        .anchor_boundary()
        .ok_or(ProveError::NoAnchorBoundary(id))?;

    let pczt = pczt::Pczt::parse(tx.pczt()).map_err(ProveError::Parse)?;
    let proven = prover
        .prove_transfer(pczt, anchor_boundary)
        .map_err(ProveError::Prover)?;
    let bytes = proven.serialize().map_err(ProveError::Serialize)?;

    state.set_transaction_proved(id, bytes);
    Ok(())
}

/// Prove a pre-signed migration PREPARATION transaction against a checkpoint at which its spent
/// notes are witnessable, moving it `Signed -> Proved`.
///
/// A preparation transaction carries no drawn
/// [`anchor_boundary`](MigrationTransaction::anchor_boundary) (it anchors to its already-mined
/// dependencies, not to a bucketed boundary), so the `anchor` height is supplied by the caller: it
/// proves a preparation once the notes it spends are mined and picks a checkpoint at or after that
/// (for example the current chain tip). It hands the stored PCZT and the `anchor` to
/// [`MigrationProver::prove_preparation`], which installs the Orchard source anchor and every real
/// spend's witness against that checkpoint (through the PCZT `Updater` role) and proves the single
/// Orchard bundle. The proven PCZT replaces the stored one and the transaction becomes
/// [`Proved`](MigrationTxState::Proved), ready to broadcast.
///
/// A transaction not in [`Signed`](MigrationTxState::Signed) is rejected with
/// [`ProveError::NotReady`] rather than re-proved; a transfer is rejected with
/// [`ProveError::NotAPreparation`].
#[cfg(feature = "orchard")]
pub fn prove_preparation<P>(
    prover: &mut P,
    state: &mut MigrationState,
    id: MigrationTxId,
    anchor: BlockHeight,
) -> Result<(), ProveError<P::Error>>
where
    P: MigrationProver,
{
    let tx = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .ok_or(ProveError::UnknownTransaction(id))?;
    if !matches!(tx.kind(), MigrationTxKind::Preparation { .. }) {
        return Err(ProveError::NotAPreparation(id));
    }
    if !matches!(tx.state(), MigrationTxState::Signed) {
        return Err(ProveError::NotReady(id));
    }

    let pczt = pczt::Pczt::parse(tx.pczt()).map_err(ProveError::Parse)?;
    let proven = prover
        .prove_preparation(pczt, anchor)
        .map_err(ProveError::Prover)?;
    let bytes = proven.serialize().map_err(ProveError::Serialize)?;

    state.set_transaction_proved(id, bytes);
    Ok(())
}

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

/// A spendable note recovered from an already-built preparation transaction, or a direct-funding
/// wallet note, tracked by the commit so a later transaction can spend it BY VALUE before it is
/// mined. Its signable plaintext is fixed at build time (its `rho` is the paired spend's nullifier
/// and its `rseed` is drawn by the builder); only its tree position awaits mining, and that matters
/// only to the proof (deferred to proving time, ZIP 374). `consumed` guards against spending it
/// twice, and `producer` is the preparation transaction that mints it (or `None` for a
/// direct-funding wallet note), so a transfer depends only on its own funding note's producer.
#[cfg(feature = "orchard")]
struct MintedNote {
    value: Zatoshis,
    note: orchard::note::Note,
    consumed: bool,
    producer: Option<MigrationTxId>,
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
    .map(|(state, _unsigned, _funding)| state)
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
/// `replace_migration`, and drive the broadcasts through the normal state machine (proving remains a
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
        .map(|(state, unsigned, _funding)| (state, unsigned))
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
) -> Result<CommitOutput, CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    let mut committer = Committer::start(params, target_height, backend, rng, signing)?;
    committer.build_preparation_layers(plan)?;
    committer.add_direct_funding(plan)?;
    committer.build_transfers(plan)?;
    // `into_state` consumes the committer, releasing its `&mut backend` reborrow, so the store
    // write below can borrow `backend` again.
    let (state, unsigned, transfer_funding) = committer.into_state(plan);
    backend
        .replace_migration(&state)
        .map_err(CommitError::Backend)?;
    Ok((state, unsigned, transfer_funding))
}

/// Commit a planned migration in-process (as [`commit_preparation`]) and additionally return each
/// transfer paired with the funding note it spends. The funding notes are what a prover needs to
/// locate each transfer's spend in the wallet's Orchard commitment tree at proving time; a
/// production consumer recovers them from its own scanned note store, so this entry point exists
/// for tests (and downstream test harnesses) that drive real proving without a scanning wallet.
#[cfg(any(test, feature = "test-dependencies"))]
pub fn commit_preparation_with_funding<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
) -> Result<(MigrationState, TransferFunding), CommitError<<B as MigrationBackend>::Error>>
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
    .map(|(state, _unsigned, funding)| (state, funding))
}

/// Hosts the shared mutable state that building a whole committed migration threads through its
/// stages: the accumulating `transactions`/`unsigned` outputs, the `next_id` counter, the per-layer
/// `layer_ids` (so a later layer, and the transfers, can depend on the layer before them), and the
/// `minted` pool of notes that already-built preparation transactions (and direct-funding wallet
/// notes) mint for later spends. Owning the backend, rng, and resolved `fvk` lets each stage of
/// [`commit_preparation_inner`] be a method: [`Committer::start`] then
/// [`Committer::build_preparation_layers`], [`Committer::add_direct_funding`],
/// [`Committer::build_transfers`], and finally [`Committer::into_state`], which consumes the
/// committer and returns the assembled state (releasing the `&mut backend` reborrow so the caller
/// can persist it). `plan` is deliberately NOT a field: passing it as a method parameter avoids
/// borrowing `self` both immutably (to iterate the plan) and mutably (to call `next_id`/the
/// resolvers) at once.
#[cfg(feature = "orchard")]
struct Committer<'a, P, B, R> {
    params: &'a P,
    target_height: BlockHeight,
    backend: &'a mut B,
    rng: &'a mut R,
    signing: Signing,
    fvk: orchard::keys::FullViewingKey,
    transactions: Vec<MigrationTransaction>,
    unsigned: Vec<UnsignedMigrationTx>,
    next_id: u32,
    layer_ids: Vec<Vec<MigrationTxId>>,
    minted: Vec<MintedNote>,
    /// Each transfer paired with the funding note it spends, captured as the transfer is built.
    /// The commit path already recovers every funding note's plaintext to build the transfer; a
    /// prover needs it at proving time to locate the note in the wallet's commitment tree (in
    /// production the wallet finds it by nullifier in its own note store). Surfaced through
    /// [`commit_preparation_with_funding`]; the normal commit path drops it.
    transfer_funding: TransferFunding,
}

#[cfg(feature = "orchard")]
impl<'a, P, B, R> Committer<'a, P, B, R>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    /// Open a commit: guard against overwriting a live migration, resolve the account's Orchard FVK,
    /// and initialize the empty accumulators.
    fn start(
        params: &'a P,
        target_height: BlockHeight,
        backend: &'a mut B,
        rng: &'a mut R,
        signing: Signing,
    ) -> Result<Self, CommitError<<B as MigrationBackend>::Error>> {
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

        Ok(Self {
            params,
            target_height,
            backend,
            rng,
            signing,
            fvk,
            transactions: Vec::new(),
            unsigned: Vec::new(),
            next_id: 0,
            layer_ids: Vec::new(),
            minted: Vec::new(),
            transfer_funding: Vec::new(),
        })
    }

    /// Assign and consume the next sequential transaction id.
    fn next_id(&mut self) -> MigrationTxId {
        let id = MigrationTxId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Resolve the Orchard notes a preparation transaction spends: wallet notes from the backend
    /// (checking each against its planned value), and feeder notes from the `minted` pool (marking
    /// each consumed).
    fn resolve_prep_spends(
        &mut self,
        prep_tx: &crate::preparation::PrepTransaction,
        layer: usize,
    ) -> Result<Vec<orchard::note::Note>, CommitError<<B as MigrationBackend>::Error>> {
        use crate::preparation::PrepInput;

        let mut spends = Vec::with_capacity(prep_tx.inputs().len());
        for input in prep_tx.inputs() {
            match input {
                PrepInput::Wallet { index, value } => {
                    let note = self
                        .backend
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
                    let feeder = self
                        .minted
                        .iter_mut()
                        .find(|m| !m.consumed && m.value == *value)
                        .ok_or_else(|| {
                            CommitError::InconsistentPlan(format!(
                                "layer {layer} spends a feeder note of value {} that no \
                                 earlier layer mints",
                                u64::from(*value)
                            ))
                        })?;
                    feeder.consumed = true;
                    spends.push(feeder.note);
                }
            }
        }
        Ok(spends)
    }

    /// Build and pre-sign every preparation transaction, layer by layer in topological order,
    /// growing the `minted` pool with each transaction's recovered spendable outputs.
    fn build_preparation_layers(
        &mut self,
        plan: &MigrationPlan,
    ) -> Result<(), CommitError<<B as MigrationBackend>::Error>> {
        use crate::build::build_prep_tx;
        use crate::preparation::PrepOutput;

        for (layer, prep_layer) in plan.preparation().layers().iter().enumerate() {
            let mut this_layer_ids: Vec<MigrationTxId> = Vec::with_capacity(prep_layer.len());
            for (index, prep_tx) in prep_layer.iter().enumerate() {
                let id = self.next_id();
                this_layer_ids.push(id);

                let spends = self.resolve_prep_spends(prep_tx, layer)?;

                let depends_on = if layer == 0 {
                    Vec::new()
                } else {
                    self.layer_ids
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
                // The field accesses `self.params`/`self.fvk`/`self.rng` are DISJOINT, so the
                // borrow checker accepts them together here — as long as no whole-`self` method
                // call (like `next_id`/`resolve_prep_spends` above) is interleaved.
                let (pczt, placed) = build_prep_tx(
                    self.params,
                    u32::from(self.target_height),
                    u32::from(expiry_height),
                    &self.fvk,
                    spends,
                    prep_tx.outputs(),
                    &mut *self.rng,
                )
                .map_err(CommitError::Build)?;

                // Grow the minted pool with this transaction's recovered spendable outputs. Change
                // outputs are excluded: they stay in the source pool and must never be matched to a
                // feeder or funding request of a coincidentally equal value.
                for (_action_index, output, note) in placed {
                    match output {
                        PrepOutput::Funding(value) | PrepOutput::Intermediate(value) => {
                            self.minted.push(MintedNote {
                                value,
                                note,
                                consumed: false,
                                producer: Some(id),
                            });
                        }
                        PrepOutput::Change(_) => {}
                    }
                }

                let (bytes, tx_state) = finish_built_pczt(self.backend, pczt, self.signing)?;
                if matches!(self.signing, Signing::External) {
                    self.unsigned.push(UnsignedMigrationTx {
                        id,
                        pczt: bytes.clone(),
                        actions: crate::preparation::PREP_TX_ACTIONS,
                    });
                }
                self.transactions.push(MigrationTransaction {
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
            self.layer_ids.push(this_layer_ids);
        }
        Ok(())
    }

    /// Add the direct-funding wallet notes (already exactly a funding value; no preparation
    /// transaction mints them) to the `minted` pool the transfers draw from.
    fn add_direct_funding(
        &mut self,
        plan: &MigrationPlan,
    ) -> Result<(), CommitError<<B as MigrationBackend>::Error>> {
        for &(wallet_index, value) in plan.preparation().direct_funding_notes() {
            let note = self
                .backend
                .resolve_wallet_note(wallet_index)
                .map_err(CommitError::Backend)?;
            if note.value().inner() != u64::from(value) {
                return Err(CommitError::StalePlan);
            }
            // A direct-funding wallet note already exists on-chain, so its transfer has no producer
            // to wait on.
            self.minted.push(MintedNote {
                value,
                note,
                consumed: false,
                producer: None,
            });
        }
        Ok(())
    }

    /// Build and pre-sign every transfer, spending each crossing's funding note out of the `minted`
    /// pool and drawing the boundary anchor it will prove against.
    fn build_transfers(
        &mut self,
        plan: &MigrationPlan,
    ) -> Result<(), CommitError<<B as MigrationBackend>::Error>> {
        use crate::build::build_transfer_pczt;

        // Each transfer waits only for the preparation transaction that MINTS ITS OWN funding note
        // to be mined (recorded as that note's producer in `minted`), not for the whole last layer:
        // as soon as a transfer's own funding note is on-chain it may broadcast at its scheduled
        // height, independently of the other crossings' preparation. This follows ZIP 318's
        // per-note availability MUST ("wait until the boundary that closes the anchor-height bucket
        // in which a note-preparation transaction was mined has passed before treating ITS output
        // notes as available for migration") and consciously RELAXES the more conservative SHOULD
        // that all note preparation complete before Phase 2 begins. The relaxation is safe: the
        // schedule is already floored at the estimated last-preparation height, and the
        // boundary-passed half of the MUST is still enforced downstream, since `draw_anchor_boundary`
        // yields an anchor only once a boundary at or after the note's creation exists, so a transfer
        // cannot be proved (hence broadcast) before then. A funding note used directly from the
        // wallet has no producer, so that transfer's dependency set is empty.

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
            .map_or(self.target_height, |&h| h + EST_PREP_LAYER_MINING_BLOCKS);
        // The anchor draw needs the NU6.3 activation height; derive it from `params` here rather
        // than carrying it as a field (it is a pure function of the network).
        let nu63_activation = self
            .params
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
            .ok_or(CommitError::Nu63NotActive)?;
        for (crossing, schedule) in plan.schedule().iter().enumerate() {
            let id = self.next_id();

            let funding_value = *plan.funding_notes().get(crossing).ok_or_else(|| {
                CommitError::InconsistentPlan(format!(
                    "no funding note value for crossing {crossing}"
                ))
            })?;
            // Copy `note`/`producer` (both `Copy`) out of the `minted` borrow so it ends before the
            // disjoint-field build call below.
            let (note, producer) = {
                let funding_note = self
                    .minted
                    .iter_mut()
                    .find(|m| !m.consumed && m.value == funding_value)
                    .ok_or_else(|| {
                        CommitError::InconsistentPlan(format!(
                            "no minted funding note for crossing {crossing}"
                        ))
                    })?;
                funding_note.consumed = true;
                (funding_note.note, funding_note.producer)
            };
            // Depend only on the preparation transaction that mints this funding note (or nothing,
            // for a direct-funding wallet note), so this crossing releases as soon as its own note
            // is mined.
            let depends_on: Vec<MigrationTxId> = producer.into_iter().collect();
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
                self.params,
                u32::from(self.target_height),
                u32::from(schedule.expiry_height()),
                &self.fvk,
                note,
                crossing_value,
                &mut *self.rng,
            )
            .map_err(CommitError::Build)?;
            let anchor_boundary = scheduling::draw_anchor_boundary(
                nu63_activation,
                est_last_prep_height,
                schedule.broadcast_height(),
                self.rng,
            )
            .ok_or(CommitError::StalePlan)?;
            let (bytes, tx_state) = finish_built_pczt(self.backend, pczt, self.signing)?;
            if matches!(self.signing, Signing::External) {
                self.unsigned.push(UnsignedMigrationTx {
                    id,
                    pczt: bytes.clone(),
                    actions: crate::note_splitting::SOURCE_ACTIONS_PER_TRANSFER
                        + crate::note_splitting::DESTINATION_ACTIONS_PER_TRANSFER,
                });
            }
            self.transactions.push(MigrationTransaction {
                id,
                kind: MigrationTxKind::Transfer { crossing },
                pczt: bytes,
                depends_on,
                scheduled_height: schedule.broadcast_height(),
                expiry_height: schedule.expiry_height(),
                anchor_boundary: Some(anchor_boundary),
                state: tx_state,
            });
            self.transfer_funding.push((id, note));
        }
        Ok(())
    }

    /// Assemble the committed [`MigrationState`] from the accumulated transactions and return it
    /// with the unsigned PCZTs and each transfer's funding note. Consuming `self` releases the
    /// `&mut backend` reborrow, so the caller can persist the state through the backend afterward.
    fn into_state(self, plan: &MigrationPlan) -> CommitOutput {
        let state = MigrationState {
            status: MigrationStatus::Committed,
            note_split: plan.note_split().clone(),
            preparation: plan.preparation().clone(),
            transactions: self.transactions,
        };
        (state, self.unsigned, self.transfer_funding)
    }
}

/// Each transfer paired with the funding note it spends, recovered from the built preparation
/// bundles during a commit pass. A prover needs it to locate each transfer's spend in the wallet's
/// commitment tree at proving time.
#[cfg(feature = "orchard")]
type TransferFunding = Vec<(MigrationTxId, orchard::note::Note)>;

/// What one commit pass produces: the persisted [`MigrationState`], the unsigned PCZTs (empty for
/// the in-process signing path), and each transfer paired with the funding note it spends. The
/// public commit entry points drop the parts they do not surface.
#[cfg(feature = "orchard")]
type CommitOutput = (MigrationState, Vec<UnsignedMigrationTx>, TransferFunding);

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

    /// A typical balance migrates in a single run, whose entry carries BOTH the note-split side
    /// (migratable value and crossing count) and the note-preparation side (layers and transactions),
    /// and the aggregates match the single run.
    #[test]
    fn estimates_a_single_run_with_both_sides() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let backend = MockBackend::new(vec![142 * COIN], 2_000_000);
        let est = estimate_migration_runs(&test_net(), &backend, &mut rng)
            .expect("a valid balance estimates");

        assert_eq!(est.run_count(), 1);
        let run = est.runs()[0];
        // Note-split side: it crosses value in one or more canonical denominations.
        assert!(u64::from(run.migratable()) > 0);
        assert!(run.crossings() >= 1);
        // Note-preparation side: minting those notes costs at least one layer and one transaction.
        assert!(run.prep_layers() >= 1);
        assert!(run.prep_transactions() >= 1);
        // The aggregates reduce to the single run.
        assert_eq!(est.total_migratable(), run.migratable());
        assert_eq!(est.total_crossings(), run.crossings());
        assert_eq!(est.total_prep_layers(), run.prep_layers());
        assert_eq!(est.total_prep_transactions(), run.prep_transactions());
    }

    /// An empty (or fully sub-quantum) balance is a zero-run estimate, a preview rather than an error.
    #[test]
    fn empty_balance_estimates_zero_runs() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let empty = MockBackend::new(Vec::new(), 2_000_000);
        let est = estimate_migration_runs(&test_net(), &empty, &mut rng)
            .expect("an empty balance estimates");
        assert_eq!(est.run_count(), 0);
        assert!(est.runs().is_empty());
        assert_eq!(est.total_migratable(), Zatoshis::ZERO);
        assert_eq!(est.final_residual(), Zatoshis::ZERO);
    }

    /// A whale beyond one run's capacity migrates over several runs; its first run crosses the per-run
    /// cap of 50 * 10,000 ZEC in 50 notes, and the aggregate crossings sum the per-run counts.
    #[test]
    fn whale_migrates_over_several_runs() {
        use crate::note_splitting::{
            MIGRATION_MAX_DENOMINATION_ZEC, MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
        };
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let whale = MockBackend::new(vec![1_200_000 * COIN], 2_000_000);
        let est = estimate_migration_runs(&test_net(), &whale, &mut rng)
            .expect("a whale balance estimates");

        assert!(
            est.run_count() >= 2,
            "a whale migrates over several runs, got {}",
            est.run_count()
        );
        let per_run_cap =
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN as u64 * MIGRATION_MAX_DENOMINATION_ZEC * COIN;
        assert_eq!(u64::from(est.runs()[0].migratable()), per_run_cap);
        assert_eq!(
            est.runs()[0].crossings(),
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN
        );
        let summed: usize = est.runs().iter().map(|r| r.crossings()).sum();
        assert_eq!(est.total_crossings(), summed);
    }

    /// The estimate depends on the wallet's NOTE STRUCTURE, not just its total value: the same balance
    /// held as one note versus as many small notes migrates the same value in one run, but the
    /// fragmented wallet costs strictly more note-preparation work (consolidation).
    #[test]
    fn estimate_depends_on_wallet_note_structure() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let one_note = MockBackend::new(vec![200 * COIN], 2_000_000);
        let fragmented = MockBackend::new(vec![COIN; 200], 2_000_000); // 200 ZEC as 200 x 1 ZEC

        let est_one = estimate_migration_runs(&test_net(), &one_note, &mut rng).expect("estimates");
        let est_frag =
            estimate_migration_runs(&test_net(), &fragmented, &mut rng).expect("estimates");

        assert_eq!(est_one.run_count(), 1);
        assert_eq!(est_frag.run_count(), 1);
        assert!(
            est_frag.total_prep_transactions() > est_one.total_prep_transactions(),
            "a fragmented wallet needs more preparation: {} vs {}",
            est_frag.total_prep_transactions(),
            est_one.total_prep_transactions()
        );
    }

    /// The number of signing sessions follows a capacity-limited signer's per-interaction transaction
    /// limit (a Keystone-style hard limit): one session per transaction at capacity one, one session
    /// per run when the capacity exceeds every run, and monotonically more sessions as the limit
    /// tightens. Sessions are summed per run (they cannot span runs).
    #[test]
    fn signing_sessions_follow_the_signer_capacity() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        // A whale, so there are several runs, each with several transactions.
        let whale = MockBackend::new(vec![1_200_000 * COIN], 2_000_000);
        let est = estimate_migration_runs(&test_net(), &whale, &mut rng).expect("estimates");

        // Total transactions reconcile with the per-side aggregates.
        assert_eq!(
            est.total_transactions(),
            est.total_prep_transactions() + est.total_crossings()
        );

        let one = NonZeroUsize::new(1).unwrap();
        let big = NonZeroUsize::new(10_000).unwrap();
        let mid = NonZeroUsize::new(8).unwrap();

        // Capacity of one transaction per session: one session per transaction.
        assert_eq!(est.total_signing_sessions(one), est.total_transactions());
        // Capacity larger than any single run's transaction count: one session per run.
        assert_eq!(est.total_signing_sessions(big), est.run_count());
        // A tighter limit never needs fewer sessions than a looser one.
        assert!(est.total_signing_sessions(mid) >= est.total_signing_sessions(big));
        assert!(est.total_signing_sessions(one) >= est.total_signing_sessions(mid));

        // Per-run consistency: a run's sessions are the ceiling of its transaction count, and the
        // total is the per-run sum (sessions do not span runs).
        let summed: usize = est.runs().iter().map(|r| r.signing_sessions(mid)).sum();
        assert_eq!(est.total_signing_sessions(mid), summed);
        for run in est.runs() {
            assert_eq!(
                run.transactions(),
                run.prep_transactions() + run.crossings()
            );
            assert_eq!(run.signing_sessions(mid), run.transactions().div_ceil(8));
        }
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
            preparation: crate::preparation::PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions: vec![tx],
        };
        backend.replace_migration(&state).unwrap();

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

    impl MigrationProver for CommitMock {
        type Error = core::convert::Infallible;

        fn prove_transfer(
            &mut self,
            pczt: pczt::Pczt,
            _anchor_boundary: BlockHeight,
        ) -> Result<pczt::Pczt, Self::Error> {
            // A stand-in for proving. A real prover resolves the funding note's witness against
            // `anchor_boundary`, installs the Orchard source and Ironwood destination anchors
            // through the PCZT `Updater` role, and runs the Orchard + Ironwood provers. Resolving
            // the funding note requires commitment-tree access this mock does not model, so it
            // returns the PCZT unchanged; the engine's `prove_transfer` orchestration (reading and
            // passing the persisted `anchor_boundary`, and the Signed -> Proved transition) is what
            // the tests exercise.
            Ok(pczt)
        }

        fn prove_preparation(
            &mut self,
            pczt: pczt::Pczt,
            _anchor: BlockHeight,
        ) -> Result<pczt::Pczt, Self::Error> {
            // A stand-in for proving, as `prove_transfer` above: a real prover installs the Orchard
            // anchor and every spend's witness and runs the Orchard prover (see
            // `WalletMigrationProver`). This mock models no commitment tree, so it returns the PCZT
            // unchanged; the engine's `prove_preparation` orchestration is what the tests exercise.
            Ok(pczt)
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
                    // A transfer depends only on the ONE preparation transaction that mints its
                    // funding note, so it releases as soon as its own note is mined, not once the
                    // whole last layer mines.
                    assert_eq!(
                        tx.depends_on.len(),
                        1,
                        "a transfer waits on exactly its funding note's producer"
                    );
                    let producer = tx.depends_on[0];
                    assert!(
                        state.transactions.iter().any(|p| p.id == producer
                            && matches!(p.kind, MigrationTxKind::Preparation { .. })),
                        "the dependency is a preparation transaction"
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
        // only once layer 0 mines; each transfer once its own funding note's producer mines (here
        // the whole last layer is mined at once, so every transfer becomes broadcastable).
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
                    "a transfer broadcasts once its funding note's producer mines"
                );
            }
            other => panic!("expected a broadcast step, got {other:?}"),
        }
    }

    /// A crossing releases as soon as ITS OWN funding note's producer mines — not once the whole
    /// preparation completes. A two-layer whale's funding notes come from more than one producer, so
    /// mining ONE producer makes the crossings it funds releasable while the crossings funded by the
    /// other, still-unmined producer stay blocked.
    #[test]
    fn a_crossing_releases_when_its_own_producer_mines() {
        let seed = 11u64;
        let (mut backend, plan) = single_note_setup(seed, 1_000 * COIN);
        assert_eq!(
            plan.preparation().layers().len(),
            2,
            "the whale fans out across two layers"
        );
        let params = regtest_network(true);
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("commits the migration");

        // The crossings are funded by more than one preparation transaction (each transfer depends
        // on exactly its own producer).
        let mut producers: Vec<MigrationTxId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .map(|t| t.depends_on[0])
            .collect();
        producers.sort_by_key(|p| u32::from(*p));
        producers.dedup();
        assert!(
            producers.len() >= 2,
            "the whale's crossings come from at least two producers, got {}",
            producers.len()
        );
        let (p1, p2) = (producers[0], producers[1]);
        // Each producer funds at least one crossing.
        assert!(state
            .transactions
            .iter()
            .any(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }) && t.depends_on == [p1]));
        assert!(state
            .transactions
            .iter()
            .any(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }) && t.depends_on == [p2]));

        // Before anything mines, crossings from neither producer are releasable.
        assert!(!state.deps_mined(&[p1]));
        assert!(!state.deps_mined(&[p2]));

        // Mine ONLY the first producer.
        state.mark_mined(p1, BlockHeight::from_u32(2_000_000));

        // Crossings funded by p1 are releasable; crossings funded by the still-unmined p2 stay
        // blocked — a crossing does NOT wait for the whole preparation.
        assert!(
            state.deps_mined(&[p1]),
            "a crossing releases once its own producer mines"
        );
        assert!(
            !state.deps_mined(&[p2]),
            "a crossing whose producer has not mined stays blocked"
        );
    }

    /// Consolidating many small notes needs a DEEP preparation — here four layers — and the state
    /// machine still walks the broadcasts strictly layer by layer: each preparation layer depends on
    /// the whole layer before it and broadcasts only once that predecessor mines, and the transfers
    /// come only after the last layer.
    #[test]
    fn commits_a_deep_multi_layer_migration() {
        let seed = 11u64;
        // Thirty 100-ZEC notes consolidate through four preparation layers.
        let mut backend = CommitMock::new(seed, &[100 * COIN; 30]);
        let params = regtest_network(true);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        let layer_count = plan.preparation().layers().len();
        assert_eq!(
            layer_count, 4,
            "deep consolidation fans through four layers"
        );

        let mut rng2 = ChaCha8Rng::seed_from_u64(seed + 1);
        let state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng2,
        )
        .expect("commits the migration");

        let layer_ids = |s: &MigrationState, layer: usize| -> Vec<MigrationTxId> {
            s.transactions
                .iter()
                .filter(|t| {
                    matches!(t.kind, MigrationTxKind::Preparation { layer: l, .. } if l == layer)
                })
                .map(|t| t.id)
                .collect()
        };

        // Every preparation layer after the first depends on the WHOLE layer before it.
        for layer in 1..layer_count {
            let prev = layer_ids(&state, layer - 1);
            for tx in state.transactions.iter().filter(
                |t| matches!(t.kind, MigrationTxKind::Preparation { layer: l, .. } if l == layer),
            ) {
                assert_eq!(
                    tx.depends_on,
                    prev,
                    "layer {layer} depends on the whole layer {}",
                    layer - 1
                );
            }
        }

        // The state machine broadcasts each preparation layer in order — a layer only once its
        // predecessor has mined — then, once the last layer mines, the transfers.
        let mut state = state;
        let target = BlockHeight::from_u32(2_100_000);
        let mut height = 2_000_000u32;
        for layer in 0..layer_count {
            let ids = layer_ids(&state, layer);
            match state.next_step(target) {
                crate::state::AdvanceStep::Broadcast { id } => assert!(
                    ids.contains(&id),
                    "layer {layer} broadcasts once its predecessor has mined"
                ),
                other => panic!("expected a layer-{layer} broadcast, got {other:?}"),
            }
            // The others stay BLOCKED: every LATER preparation layer still depends (transitively)
            // on a layer that has not mined, so none of them is broadcastable yet.
            for later in (layer + 1)..layer_count {
                for later_id in layer_ids(&state, later) {
                    let deps = state
                        .transactions
                        .iter()
                        .find(|t| t.id == later_id)
                        .expect("a stored preparation transaction")
                        .depends_on
                        .clone();
                    assert!(
                        !state.deps_mined(&deps),
                        "layer {later} must not be broadcastable before layer {layer} mines"
                    );
                }
            }
            height += 10;
            for id in &ids {
                state.mark_mined(*id, BlockHeight::from_u32(height));
            }
        }
        match state.next_step(target) {
            crate::state::AdvanceStep::Broadcast { id } => {
                let tx = state.transactions.iter().find(|t| t.id == id).unwrap();
                assert!(
                    matches!(tx.kind, MigrationTxKind::Transfer { .. }),
                    "the transfers broadcast after the last preparation layer mines"
                );
            }
            other => panic!("expected a transfer broadcast, got {other:?}"),
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
        backend.replace_migration(&state).unwrap();
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
        backend.replace_migration(&stored).unwrap();
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

    /// Proving a due transfer consults the anchor boundary the schedule DREW and persisted on the
    /// transaction (not the tip), moving it `Signed -> Proved`. This exercises the engine
    /// orchestration of [`prove_transfer`]: it reads the persisted `anchor_boundary`, hands it to
    /// the crypto backend (here the in-memory mock stands in for the real prover), stores the
    /// returned PCZT, and advances the state. It also checks the guards: a preparation transaction
    /// is not a transfer, and an already-proved transfer is not re-proved.
    #[test]
    fn prove_transfer_consults_the_persisted_anchor_boundary() {
        let seed = 7u64;
        let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
        let params = regtest_network(true);
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("commits the migration");

        // Every transfer is Signed and carries a drawn anchor boundary after commit.
        let transfer_id = state
            .transactions
            .iter()
            .find(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .map(|t| {
                assert!(
                    t.anchor_boundary.is_some(),
                    "a transfer carries the boundary its schedule drew"
                );
                assert!(matches!(t.state, MigrationTxState::Signed));
                t.id
            })
            .expect("a committed migration has transfers");

        // Proving reads the persisted boundary, proves, and advances Signed -> Proved.
        prove_transfer(&mut backend, &mut state, transfer_id).expect("proves the due transfer");
        let proved = state
            .transactions
            .iter()
            .find(|t| t.id == transfer_id)
            .expect("the transfer is still present");
        assert!(
            matches!(proved.state, MigrationTxState::Proved),
            "the transfer is proved"
        );

        // An already-proved transfer is not re-proved.
        assert!(matches!(
            prove_transfer(&mut backend, &mut state, transfer_id),
            Err(ProveError::NotReady(_))
        ));

        // A preparation transaction is not a transfer: it anchors to its dependencies, not a drawn
        // boundary, so it is rejected rather than proved.
        let prep_id = state
            .transactions
            .iter()
            .find(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
            .expect("a committed migration has preparation transactions")
            .id;
        assert!(matches!(
            prove_transfer(&mut backend, &mut state, prep_id),
            Err(ProveError::NotATransfer(_))
        ));
    }
}
