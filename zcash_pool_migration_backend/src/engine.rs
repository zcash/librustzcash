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
use zcash_protocol::TxId;
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

/// A stable ordinal identifier for a migration transaction within a migration. This is a ROW KEY
/// into the persisted migration (usable before a transaction is built, when no [`TxId`] exists yet:
/// deferred preparation layers and transfers are recorded as unbuilt placeholders); it is NOT a
/// Zcash transaction id. The real [`TxId`] becomes available once a transaction is built and signed
/// (it commits only effecting data), and is carried by [`MigrationTxState::Broadcast`].
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
    /// Built and awaiting an EXTERNAL signature: its UNSIGNED PCZT is held in
    /// [`pczt`](MigrationTransaction::pczt), exported for a hardware or offline signer.
    /// [`apply_signature`](MigrationState::apply_signature) moves it to [`Signed`](Self::Signed) once the
    /// signed PCZT is returned. Only the external-signing path
    /// ([`build_preparation_unsigned`]/[`build_transfers_unsigned`]) produces this state; the in-process
    /// commit functions sign immediately and go straight to [`Signed`](Self::Signed).
    AwaitingSignature,
    /// Pre-signed (the account's spend authorization is attached), not yet proved.
    Signed,
    /// Proved against a real anchor, ready to broadcast.
    Proved,
    /// Broadcast to the network, with its transaction id.
    Broadcast { txid: TxId },
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
    /// The boundary height whose tree state the transaction proves against. For a transfer this is
    /// drawn at SCHEDULING time (the schedule fully determines the candidate set; see
    /// [`commit_preparation`]); `None` for a preparation transaction, or when no candidate boundary
    /// exists at the scheduled height (the application then draws against its proving-time view).
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
    /// The preparation plan (its layers and direct-funding notes), retained so the deferred preparation
    /// layers can be rebuilt after their prior layer mines (see
    /// [`commit_pending_preparation`]). A `Preparation { layer, index }` transaction's spends resolve
    /// against `preparation.layers()[layer][index]`.
    pub preparation: PreparationPlan,
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
    /// No committed migration was found to build the transfers for (nothing was loaded from storage).
    NoMigrationInProgress,
}

#[cfg(feature = "orchard")]
impl<E: fmt::Display> fmt::Display for CommitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitError::Backend(e) => write!(f, "wallet backend error: {e}"),
            CommitError::Build(m) => write!(f, "building the migration failed: {m}"),
            CommitError::NoMigrationInProgress => {
                f.write_str("no committed migration is in progress")
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
/// Produced by [`build_preparation_unsigned`] and [`build_transfers_unsigned`]. The `(id, pczt)` pairing
/// MUST survive the round-trip to the signer, because `apply_signature` matches the returned signed PCZT
/// back to its transaction by id.
#[cfg(feature = "orchard")]
#[derive(Clone, Debug)]
pub struct UnsignedMigrationTx {
    /// The transaction's id in the committed migration.
    pub id: MigrationTxId,
    /// The serialized UNSIGNED PCZT to sign out of band.
    pub pczt: Vec<u8>,
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
            let bytes = signed
                .serialize()
                .map_err(|e| CommitError::Build(format!("serialize: {e:?}")))?;
            Ok((bytes, MigrationTxState::Signed))
        }
        Signing::External => {
            let bytes = pczt
                .serialize()
                .map_err(|e| CommitError::Build(format!("serialize: {e:?}")))?;
            Ok((bytes, MigrationTxState::AwaitingSignature))
        }
    }
}

/// Commit a planned migration's PREPARATION: build and pre-sign the FIRST layer of preparation
/// transactions (the ones that spend the wallet's own notes) with the account's spend authorization,
/// record every later preparation layer and every transfer as an unbuilt placeholder, and persist the
/// whole committed migration through the backend. This is the two-phase (in general, multi-phase)
/// signing path that ZIP 318 permits: the application broadcasts layer 0, and once a layer is mined the
/// engine builds and signs the next one (see [`commit_pending_preparation`]) whose spends reference
/// that layer's now-witnessable feeder notes, until the whole preparation is mined and the transfers
/// are built (see [`commit_transfers`]).
///
/// A single-layer plan (the common case: a few wallet notes fanning into a handful of funding notes)
/// signs its one layer here and records only the transfer placeholders; nothing is deferred. A
/// multi-layer plan (a lone whale fanning out, or a dust-heavy balance) signs layer 0 here and defers
/// the rest.
///
/// For an EXTERNAL signer (a hardware wallet), use [`build_preparation_unsigned`] instead, which builds
/// the same layer-0 transactions but leaves them unsigned for the device and returns their PCZTs.
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

/// Commit a planned migration's PREPARATION for an EXTERNAL signer: build the FIRST layer of preparation
/// transactions but leave them UNSIGNED, persist the committed migration (with those transactions in the
/// [`AwaitingSignature`](MigrationTxState::AwaitingSignature) state), and return the state together with
/// the unsigned layer-0 PCZTs to route to the signing device. Later preparation layers and every transfer
/// are recorded as unbuilt placeholders exactly as [`commit_preparation`] records them.
///
/// After the device signs, call [`MigrationState::apply_signature`] for each returned PCZT (matched by
/// [`UnsignedMigrationTx::id`]) to move it to [`Signed`](MigrationTxState::Signed), persist with
/// `put_migration`, and drive the rest of the migration through the normal state machine (proving and
/// broadcasting are unchanged). Transfers are signed later via [`build_transfers_unsigned`].
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
    use crate::build::build_prep_tx;
    use crate::preparation::PrepInput;
    use zcash_protocol::consensus::NetworkUpgrade;

    let fvk = backend.orchard_fvk().map_err(CommitError::Backend)?;
    let anchor = backend.orchard_anchor().map_err(CommitError::Backend)?;
    let expiry_height = crate::scheduling::expiry_height(target_height);
    let nu63_activation = params
        .activation_height(NetworkUpgrade::Nu6_3)
        .ok_or_else(|| CommitError::Build("NU6.3 is not active on this network".into()))?;

    let mut transactions: Vec<MigrationTransaction> = Vec::new();
    let mut unsigned: Vec<UnsignedMigrationTx> = Vec::new();
    let mut next_id = 0u32;
    // The transaction ids assigned to each preparation layer, so a later layer's placeholder can depend
    // on the whole layer before it, and the transfers can depend on the last preparation layer.
    let mut layer_ids: Vec<Vec<MigrationTxId>> = Vec::new();

    for (layer, prep_layer) in plan.preparation().layers().iter().enumerate() {
        let mut this_layer_ids: Vec<MigrationTxId> = Vec::with_capacity(prep_layer.len());
        for (index, prep_tx) in prep_layer.iter().enumerate() {
            let id = MigrationTxId(next_id);
            next_id += 1;
            this_layer_ids.push(id);

            if layer == 0 {
                // Layer 0 spends only the wallet's own notes, so it is built and pre-signed now.
                let mut spends = Vec::with_capacity(prep_tx.inputs().len());
                for input in prep_tx.inputs() {
                    match input {
                        PrepInput::Wallet { index, .. } => {
                            let witness = backend
                                .resolve_wallet_note(*index, anchor)
                                .map_err(CommitError::Backend)?;
                            spends.push(witness);
                        }
                        // A layer-0 transaction spends only wallet notes; a Prior input here is a
                        // planner bug (the layered planner puts every Prior input in a later layer).
                        PrepInput::Prior { .. } => {
                            return Err(CommitError::Build(
                                "layer 0 preparation transaction spends a prior-layer output"
                                    .into(),
                            ));
                        }
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

                let (bytes, tx_state) = finish_built_pczt(backend, pczt, signing)?;
                if matches!(signing, Signing::External) {
                    unsigned.push(UnsignedMigrationTx {
                        id,
                        pczt: bytes.clone(),
                    });
                }

                transactions.push(MigrationTransaction {
                    id,
                    kind: MigrationTxKind::Preparation { layer, index },
                    pczt: Some(bytes),
                    depends_on: Vec::new(),
                    scheduled_height: target_height,
                    expiry_height,
                    anchor_boundary: None,
                    state: tx_state,
                });
            } else {
                // A later layer spends the previous layer's feeder notes, which are not witnessable
                // until that layer is mined. Record it as an unbuilt placeholder depending on the whole
                // immediately-prior layer; `commit_pending_preparation` builds and signs it once its
                // dependencies mine. The height fields are placeholders (a preparation transaction waits
                // for its dependencies, not a fixed height); the real ones are set at build time.
                let depends_on = layer_ids
                    .last()
                    .cloned()
                    .expect("a layer after layer 0 has a preceding layer");
                transactions.push(MigrationTransaction {
                    id,
                    kind: MigrationTxKind::Preparation { layer, index },
                    pczt: None,
                    depends_on,
                    scheduled_height: target_height,
                    expiry_height,
                    anchor_boundary: None,
                    state: MigrationTxState::Planned,
                });
            }
        }
        layer_ids.push(this_layer_ids);
    }

    // Every transfer waits for the last preparation layer to be mined: a layer is broadcast only after
    // its predecessor mines, so the last layer mining implies every layer (hence every funding note) is
    // mined and witnessable. An empty preparation (every funding note used directly) leaves this empty.
    let last_layer_ids: Vec<MigrationTxId> = layer_ids.last().cloned().unwrap_or_default();

    // Record each transfer as a Planned placeholder carrying its schedule; its PCZT is built and
    // signed later, once the preparation is mined (see `commit_transfers`). This persists the drawn
    // schedule (which is not reproducible) as part of the committed migration.
    //
    // The boundary anchor is drawn HERE, at scheduling time, because the schedule fully determines
    // it: the candidate set lies strictly above the NU6.3 activation, at or after the height the
    // funding preparation is built to mine (`target_height` bounds the funding notes' creation from
    // below), and strictly below the most recent boundary at the transfer's scheduled broadcast
    // height (the chain view the wallet will have observed when it proves, just before broadcast).
    // `None` means no candidate boundary exists at that scheduled height (a transfer scheduled very
    // close to activation); the application then draws against the proving-time view instead.
    let funding_notes = plan.funding_notes().to_vec();
    for (crossing, schedule) in plan.schedule().iter().enumerate() {
        transactions.push(MigrationTransaction {
            id: MigrationTxId(next_id),
            kind: MigrationTxKind::Transfer { crossing },
            pczt: None,
            depends_on: last_layer_ids.clone(),
            scheduled_height: schedule.broadcast_height(),
            expiry_height: schedule.expiry_height(),
            anchor_boundary: scheduling::draw_anchor_boundary(
                nu63_activation,
                target_height,
                schedule.broadcast_height(),
                rng,
            ),
            state: MigrationTxState::Planned,
        });
        next_id += 1;
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

/// Build and pre-sign the next READY preparation layer: the deferred second phase of committing a
/// multi-layer preparation. A later preparation layer spends the previous layer's feeder notes, which
/// become witnessable only after that layer is mined, so [`commit_preparation`] records those layers as
/// unbuilt placeholders and this function fills them in once their dependencies mine.
///
/// Loads the committed migration, finds the earliest still-`Planned` preparation layer (a `layer > 0`)
/// whose whole immediately-prior layer is [`Mined`](MigrationTxState::Mined), builds and pre-signs
/// EVERY transaction of that one layer (resolving each transaction's
/// [`PrepInput::Prior`](crate::preparation::PrepInput::Prior) spends to the
/// prior layer's now-witnessable feeder notes by value), and persists the result. If no layer is ready
/// (the next layer's dependencies are not all mined, or every preparation layer is already built), it
/// returns the migration unchanged, so a caller can poll it. Call it once per newly-mined layer until
/// the whole preparation is built, then [`commit_transfers`] for the transfers.
///
/// All the transactions of the one ready layer are resolved together in a single funding-note lookup,
/// so each feeder note is assigned to exactly one transaction (a note is spent at most once) even when
/// two transactions in the layer request equal-valued feeders.
///
/// `params` is the network, `target_height` the height the layer's transactions are built at, and `rng`
/// a cryptographically secure RNG.
#[cfg(feature = "orchard")]
pub fn commit_pending_preparation<P, B, R>(
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
    use crate::build::build_prep_tx;
    use crate::preparation::PrepInput;

    let mut state = backend
        .get_migration()
        .map_err(CommitError::Backend)?
        .ok_or(CommitError::NoMigrationInProgress)?;

    // A stored transaction is Mined iff its state says so; a layer is ready once every dependency is.
    let is_mined = |id: MigrationTxId, txs: &[MigrationTransaction]| -> bool {
        txs.iter()
            .find(|t| t.id == id)
            .is_some_and(|t| matches!(t.state, MigrationTxState::Mined { .. }))
    };

    // Find the earliest still-Planned preparation layer (layer > 0) whose dependencies are all mined.
    let ready_layer = state
        .transactions
        .iter()
        .filter_map(|tx| match tx.kind {
            MigrationTxKind::Preparation { layer, .. }
                if layer > 0
                    && matches!(tx.state, MigrationTxState::Planned)
                    && tx
                        .depends_on
                        .iter()
                        .all(|d| is_mined(*d, &state.transactions)) =>
            {
                Some(layer)
            }
            _ => None,
        })
        .min();

    let Some(ready_layer) = ready_layer else {
        // Nothing to build this step (the next layer is not mined yet, or all layers are built).
        return Ok(state);
    };

    let fvk = backend.orchard_fvk().map_err(CommitError::Backend)?;
    let anchor = backend.orchard_anchor().map_err(CommitError::Backend)?;
    let expiry_height = crate::scheduling::expiry_height(target_height);

    // The (index-into-transactions, plan layer/index) of every still-Planned transaction of the ready
    // layer, in plan order, so the built PCZTs go back into the right rows.
    let mut targets: Vec<(usize, usize)> = Vec::new(); // (transactions index, plan tx index)
    for (ti, tx) in state.transactions.iter().enumerate() {
        if let MigrationTxKind::Preparation { layer, index } = tx.kind {
            if layer == ready_layer && matches!(tx.state, MigrationTxState::Planned) {
                targets.push((ti, index));
            }
        }
    }

    // Collect every Prior-input value of the whole ready layer, in transaction-then-input order, and
    // resolve them together so each feeder note (distinct by tree position, even at equal value) is
    // matched to exactly one spend across the layer. Wallet inputs (not expected past layer 0) resolve
    // individually.
    let mut prior_values: Vec<u64> = Vec::new();
    for &(_, plan_index) in &targets {
        for input in state.preparation.layers()[ready_layer][plan_index].inputs() {
            if let PrepInput::Prior { value, .. } = input {
                prior_values.push(*value);
            }
        }
    }
    let prior_values = prior_values
        .into_iter()
        .map(Zatoshis::from_u64)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CommitError::Build("prior input value out of range".into()))?;
    let mut prior_notes = backend
        .resolve_funding_notes(&prior_values, anchor)
        .map_err(CommitError::Backend)?
        .into_iter();

    for &(ti, plan_index) in &targets {
        let prep_tx = &state.preparation.layers()[ready_layer][plan_index];
        let mut spends = Vec::with_capacity(prep_tx.inputs().len());
        for input in prep_tx.inputs() {
            match input {
                PrepInput::Wallet { index, .. } => {
                    let witness = backend
                        .resolve_wallet_note(*index, anchor)
                        .map_err(CommitError::Backend)?;
                    spends.push(witness);
                }
                PrepInput::Prior { .. } => {
                    let note = prior_notes.next().ok_or_else(|| {
                        CommitError::Build("fewer resolved feeder notes than prior inputs".into())
                    })?;
                    spends.push(note);
                }
            }
        }

        let outputs = prep_tx.outputs().to_vec();
        let (pczt, _placed) = build_prep_tx(
            params,
            u32::from(target_height),
            &fvk,
            anchor,
            spends,
            &outputs,
            &mut *rng,
        )
        .map_err(|e| CommitError::Build(format!("{e}")))?;

        let signed = backend.sign(pczt).map_err(CommitError::Backend)?;
        let bytes = signed
            .serialize()
            .map_err(|e| CommitError::Build(format!("serialize: {e:?}")))?;

        let tx = &mut state.transactions[ti];
        tx.pczt = Some(bytes);
        tx.scheduled_height = target_height;
        tx.expiry_height = expiry_height;
        tx.state = MigrationTxState::Signed;
    }

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
///
/// For an EXTERNAL signer, use [`build_transfers_unsigned`] instead.
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
    commit_transfers_inner(params, target_height, backend, rng, Signing::InProcess)
        .map(|(state, _unsigned)| state)
}

/// Commit a migration's TRANSFERS for an EXTERNAL signer: build each still-`Planned` transfer but leave
/// it UNSIGNED (in the [`AwaitingSignature`](MigrationTxState::AwaitingSignature) state), persist the
/// migration, and return the state together with the unsigned transfer PCZTs to route to the signing
/// device. After the device signs, call [`MigrationState::apply_signature`] for each returned PCZT
/// (matched by [`UnsignedMigrationTx::id`]) to move it to [`Signed`](MigrationTxState::Signed), persist
/// with `put_migration`, then prove and broadcast through the normal state machine.
///
/// Like [`commit_transfers`], only transfers still `Planned` are built, so it is safe to call again
/// after a partial failure. `params` is the network, `target_height` the height the transfers are built
/// at, and `rng` a cryptographically secure RNG.
#[cfg(feature = "orchard")]
pub fn build_transfers_unsigned<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
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
    commit_transfers_inner(params, target_height, backend, rng, Signing::External)
}

/// Shared body of [`commit_transfers`] (with [`Signing::InProcess`]) and [`build_transfers_unsigned`]
/// (with [`Signing::External`]). The returned `Vec<UnsignedMigrationTx>` is empty for the in-process
/// path.
#[cfg(feature = "orchard")]
fn commit_transfers_inner<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
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
    use crate::build::build_transfer_pczt;

    let mut state = backend
        .get_migration()
        .map_err(CommitError::Backend)?
        .ok_or(CommitError::NoMigrationInProgress)?;
    let mut unsigned: Vec<UnsignedMigrationTx> = Vec::new();

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

        let (bytes, tx_state) = finish_built_pczt(backend, pczt, signing)?;
        if matches!(signing, Signing::External) {
            unsigned.push(UnsignedMigrationTx {
                id: tx.id,
                pczt: bytes.clone(),
            });
        }
        tx.pczt = Some(bytes);
        tx.state = tx_state;
    }

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
    use core::cell::RefCell;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;

    use orchard::keys::{FullViewingKey, SpendAuthorizingKey};

    use crate::build::sign_pczt;
    use crate::build::test_util::{
        TARGET_HEIGHT, regtest_network, shared_anchor_witnesses, single_note_witness, spending_key,
    };
    use crate::note_splitting::{FeePolicy, NoteSplitPlan, Zip317FeePolicy};
    use crate::preparation::{PREP_TX_ACTIONS, PrepInput, plan_preparation};

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
                    // The boundary anchor is drawn at scheduling time; when a candidate set exists
                    // it lies on the boundary grid, strictly above the NU6.3 activation, at or
                    // after the funding preparation's build height, and strictly below the most
                    // recent boundary at the scheduled broadcast height.
                    if let Some(b) = tx.anchor_boundary {
                        let b = u32::from(b);
                        assert_eq!(b % crate::scheduling::BOUNDARY_MODULUS, 0);
                        assert!(b > 10, "boundary above the regtest NU6.3 activation");
                        assert!(
                            b >= TARGET_HEIGHT.div_ceil(crate::scheduling::BOUNDARY_MODULUS)
                                * crate::scheduling::BOUNDARY_MODULUS
                        );
                        assert!(
                            b < u32::from(crate::scheduling::most_recent_boundary(
                                tx.scheduled_height
                            ))
                        );
                    }
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

    /// A wallet mock for the MULTI-LAYER preparation test. The first `n_wallet` witnesses are the
    /// wallet notes (resolved by index for layer 0); the rest are the notes later layers and the
    /// transfers mint (feeders, then funding notes), resolved by value. A persistent `used` set models
    /// a real wallet where a spent note leaves the spendable set, so a feeder consumed by one layer is
    /// never handed to a later resolution again. The store is real, so mining a layer persists.
    struct LayeredMock {
        n_wallet: usize,
        witnesses: Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
        used: RefCell<Vec<bool>>,
        anchor: orchard::Anchor,
        fvk: FullViewingKey,
        ask: SpendAuthorizingKey,
        stored: Option<MigrationState>,
    }

    impl MigrationBackend for LayeredMock {
        type Error = core::convert::Infallible;

        fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
            Ok(self.witnesses[..self.n_wallet]
                .iter()
                .map(|(n, _)| {
                    Zatoshis::from_u64(n.value().inner()).expect("test note values are valid")
                })
                .collect())
        }

        fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
            Ok(BlockHeight::from_u32(2_000_000))
        }
    }

    impl PoolMigrationRead for LayeredMock {
        type Error = core::convert::Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }
    }

    impl PoolMigrationWrite for LayeredMock {
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

    impl MigrationCrypto for LayeredMock {
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
            // By-value greedy over the minted notes (index >= n_wallet), with a persistent used-set so
            // successive resolutions (a layer's feeders, then a later layer's, then the funding notes)
            // never reuse a note. Notes of equal value are interchangeable, so first-unused is correct.
            let mut used = self.used.borrow_mut();
            let mut out = Vec::with_capacity(values.len());
            for &v in values {
                let idx = (self.n_wallet..self.witnesses.len())
                    .find(|&i| !used[i] && self.witnesses[i].0.value().inner() == u64::from(v))
                    .expect("a minted note of the requested value exists");
                used[idx] = true;
                out.push(self.witnesses[idx].clone());
            }
            Ok(out)
        }

        fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error> {
            Ok(sign_pczt(pczt, &self.ask).expect("signs the migration PCZT"))
        }
    }

    /// A lone whale fanning out into more funding notes than one transaction holds needs a MULTI-LAYER
    /// preparation. Layer 0 (spending the whale) is signed at commit time; the later layer, which
    /// spends layer 0's feeder notes, is a placeholder until layer 0 mines, at which point
    /// `commit_pending_preparation` builds and signs it; then the transfers build once the whole
    /// preparation is mined. This exercises the phased per-layer commit end to end.
    #[test]
    fn commits_multi_layer_preparation_phase_by_phase() {
        let seed = 11u64;
        let sk = spending_key(seed);
        let fvk = FullViewingKey::from(&sk);

        // 15 funding notes (one more than a single transaction's FUNDING_OUTPUTS_PER_TX) force a
        // two-layer balanced fan-out. Each is a valid self-funding note (a crossing value plus the
        // transfer fee buffer), so its transfer balances.
        let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
        let crossing = COIN; // 1 ZEC crossing per note
        let funding_note = crossing + buffer;
        let funding: Vec<u64> = core::iter::repeat_n(funding_note, 15).collect();

        // A whale generously larger than the balanced-tree cost, so the fan-out fast path triggers.
        let whale = funding.iter().sum::<u64>() + 16 * u64::from(prep_fee());
        let preparation = plan_preparation(&[whale], &funding, u64::from(prep_fee()))
            .expect("a fundable whale plans");
        assert_eq!(
            preparation.layers().len(),
            2,
            "15 funding notes fan out across two layers"
        );

        // A note split whose outputs are the funding notes and whose crossings are those less the
        // buffer, so the engine derives the same buffer and each transfer crosses one ZEC.
        let crossings: Vec<u64> = funding.iter().map(|&f| f - buffer).collect();
        let note_split = NoteSplitPlan::from_stored_parts(
            crossings.clone(),
            buffer,
            None,
            u64::from(prep_fee()),
            whale,
            crossings.iter().sum(),
        );
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let schedule =
            crate::scheduling::schedule(BlockHeight::from_u32(2_000_000), funding.len(), &mut rng);
        let plan = MigrationPlan {
            note_split,
            funding_notes: funding
                .iter()
                .map(|&v| Zatoshis::from_u64(v).expect("test funding values are valid"))
                .collect(),
            preparation,
            schedule,
        };

        // The shared-anchor witness pool: the whale, then every feeder a later layer spends (in the
        // order `commit_pending_preparation` requests them), then the funding notes. All are leaves of
        // one tree, so every spend across every layer and transfer anchors to the same root.
        let mut feeder_values: Vec<u64> = Vec::new();
        for (li, layer) in plan.preparation().layers().iter().enumerate() {
            if li == 0 {
                continue;
            }
            for tx in layer {
                for input in tx.inputs() {
                    if let PrepInput::Prior { value, .. } = input {
                        feeder_values.push(*value);
                    }
                }
            }
        }
        let mut pool_values = vec![whale];
        pool_values.extend_from_slice(&feeder_values);
        pool_values.extend_from_slice(&funding);
        let (witnesses, anchor) = shared_anchor_witnesses(&fvk, &pool_values, seed);

        let used = RefCell::new(vec![false; witnesses.len()]);
        let mut backend = LayeredMock {
            n_wallet: 1, // the whale
            witnesses,
            used,
            anchor,
            fvk: fvk.clone(),
            ask: SpendAuthorizingKey::from(&sk),
            stored: None,
        };
        let params = regtest_network(true);

        let prep_count = plan.preparation().transaction_count();
        let transfer_count = funding.len();

        // Phase 1: commit the preparation. Layer 0 is signed; the later layer and the transfers are
        // planned placeholders.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
        )
        .expect("commits the preparation");
        assert_eq!(state.transactions.len(), prep_count + transfer_count);
        let layer0: Vec<&MigrationTransaction> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 0, .. }))
            .collect();
        assert_eq!(layer0.len(), 1, "one root transaction in layer 0");
        assert_eq!(layer0[0].state, MigrationTxState::Signed);
        assert!(layer0[0].pczt.is_some());
        for tx in &state.transactions {
            if let MigrationTxKind::Preparation { layer, .. } = tx.kind {
                if layer > 0 {
                    assert_eq!(tx.state, MigrationTxState::Planned, "later layer deferred");
                    assert!(tx.pczt.is_none());
                    assert!(
                        !tx.depends_on.is_empty(),
                        "later layer waits for its predecessor"
                    );
                }
            }
        }

        // The plan round-trips through the persisted state.
        assert_eq!(state.preparation.layers().len(), 2);

        // Before layer 0 is mined, there is nothing to build.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        let state = commit_pending_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &mut rng,
        )
        .expect("no ready layer is a no-op");
        assert!(
            state.transactions.iter().any(
                |t| matches!(t.kind, MigrationTxKind::Preparation { layer, .. } if layer > 0)
                    && matches!(t.state, MigrationTxState::Planned)
            ),
            "the later layer is still planned until layer 0 mines"
        );

        // Mine layer 0.
        let layer0_ids: Vec<MigrationTxId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 0, .. }))
            .map(|t| t.id)
            .collect();
        for id in &layer0_ids {
            backend
                .update_transaction(
                    *id,
                    MigrationTxState::Mined {
                        height: BlockHeight::from_u32(2_000_010),
                    },
                )
                .unwrap();
        }

        // Phase 2: the later layer is now ready; build and sign it.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 3);
        let state = commit_pending_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT + 5),
            &mut backend,
            &mut rng,
        )
        .expect("builds the ready layer");
        for tx in &state.transactions {
            if let MigrationTxKind::Preparation { layer, .. } = tx.kind {
                if layer > 0 {
                    assert_eq!(tx.state, MigrationTxState::Signed, "later layer now signed");
                    assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
                }
            }
        }

        // Calling again with no further ready layer is a no-op.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 4);
        let state = commit_pending_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT + 6),
            &mut backend,
            &mut rng,
        )
        .expect("no further ready layer");
        assert!(
            state.transactions.iter().all(|t| !matches!(
                t.kind,
                MigrationTxKind::Preparation { layer, .. } if layer > 0
            ) || matches!(t.state, MigrationTxState::Signed)),
            "every preparation layer is signed"
        );

        // Mine the whole preparation, then commit the transfers.
        let prep_ids: Vec<MigrationTxId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
            .map(|t| t.id)
            .collect();
        for id in &prep_ids {
            backend
                .update_transaction(
                    *id,
                    MigrationTxState::Mined {
                        height: BlockHeight::from_u32(2_000_020),
                    },
                )
                .unwrap();
        }

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 5);
        let state = commit_transfers(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT + 7),
            &mut backend,
            &mut rng,
        )
        .expect("commits the transfers");
        assert_eq!(state.transactions.len(), prep_count + transfer_count);
        for tx in &state.transactions {
            match tx.kind {
                MigrationTxKind::Transfer { .. } => {
                    assert_eq!(tx.state, MigrationTxState::Signed, "transfer signed");
                    assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
                }
                MigrationTxKind::Preparation { .. } => {
                    assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
                }
            }
        }
    }
}
