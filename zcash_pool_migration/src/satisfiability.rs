//! Whether a committed migration's pre-signed transactions can still execute, and the drive loop
//! that acts on the answer.
//!
//! Two things live here. The first is the VOCABULARY a store answers in: [`StepSatisfiability`]
//! and its [`UnsatisfiableCause`]s, the reduced [`UnsatisfiableKind`] persisted beside a mark, the
//! per-nullifier [`InputObservation`]s a store folds through [`classify_input_observations`], and
//! the caller policies ([`ReorgSettleDepth`], [`ReplanThreshold`]) those answers are judged under.
//! A store implements
//! [`check_step_satisfiability`](crate::engine::PoolMigrationRead::check_step_satisfiability) by
//! supplying data access alone; what an observation MEANS is decided once, here. The second is
//! [`advance_migration`], the verified drive API a consuming application turns the crank with: it
//! asks the [`state`](crate::state) kernel what to do next from the persisted state alone, puts the
//! transaction the kernel names to the store's oracle, records and propagates whatever
//! determinations that turns up, and surfaces only a step the wallet has vouched for. So
//! [`engine`](crate::engine) plans, builds, and commits a migration, `state` decides what the
//! committed form permits next, and this module is where those decisions meet the wallet's live
//! view of the chain.

use alloc::vec::Vec;
use core::fmt;

use rand_core::{CryptoRng, RngCore};
use zcash_protocol::consensus::BlockHeight;

use crate::engine::{
    MigrationState, MigrationTransferId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use crate::scheduling::{DelayDistribution, PROVABLE_ANCHOR_DEPTH, SchedulingParams};
use crate::state::{AdvanceStep, StepKind};

/// The share of planned transfer value (an integer percent) above which a migration with
/// unsatisfiable transfers should be re-planned IMMEDIATELY rather than after satisfiable work
/// drains. Stamped on the migration at commit (like the anchor bucket grid), so every consumer
/// of the same state applies the same policy: the threshold governs a determination derived
/// from persisted marks, and two consumers of one migration must not disagree about it.
///
/// The two endpoints have distinct meanings: `0` triggers a replan as soon as ANY value is marked
/// unsatisfiable, however small; `100` never triggers immediately (the strict `>` in
/// [`MigrationState::replan_required`] can never be satisfied), so an unsatisfiable migration is
/// only ever re-planned once satisfiable work drains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplanThreshold(u8);

impl ReplanThreshold {
    /// The default policy: strictly more than 20% of planned transfer value unsatisfiable
    /// triggers an immediate replan.
    pub const DEFAULT: Self = Self(20);

    /// A threshold of `percent` (0 ..= 100), or `None` if `percent > 100`.
    pub const fn new(percent: u8) -> Option<Self> {
        if percent <= 100 {
            Some(Self(percent))
        } else {
            None
        }
    }

    /// The integer percent.
    pub const fn percent(&self) -> u8 {
        self.0
    }
}

/// How many blocks the chain must advance past a divergence before a displacement is treated as
/// PERMANENT. Caller policy, supplied to [`PoolMigrationRead::check_step_satisfiability`]: the
/// right value tracks the chain's block spacing (on the order of the sync wake-up settle margin —
/// minutes, not hours — at the current 75-second target), and keeping it current is the caller's
/// responsibility; this crate deliberately ships no default and never persists it. A displacement
/// judged settled under an aggressive depth self-corrects: the marks it produces are cleared by
/// reorg truncation if the chain swings back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReorgSettleDepth(u32);

impl ReorgSettleDepth {
    /// A settle depth of `blocks` blocks.
    pub const fn new(blocks: u32) -> Self {
        Self(blocks)
    }

    /// The depth in blocks.
    pub const fn blocks(&self) -> u32 {
        self.0
    }
}

/// A store's answer to "does the environment this store lives in obstruct this pre-signed
/// transaction?" — see [`PoolMigrationRead::check_step_satisfiability`]. Deliberately EXHAUSTIVE:
/// executable now, not yet, or never is a complete classification of a step's disposition, and
/// the consumers' cause-dependent responses are compiler-forced over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepSatisfiability {
    /// Every queried input is among the account's unspent notes, and nothing else obstructs.
    Satisfiable {
        /// The fully-scanned height the observation rests on.
        as_of_height: BlockHeight,
    },
    /// Some input's nullifier corresponds to no note the wallet has seen — its source is not yet
    /// mined, or not yet scanned — or a known creator is unmined but still viable. Not an
    /// obstruction: retry after further sync.
    NotYetSatisfiable {
        /// The fully-scanned height the observation rests on.
        as_of_height: BlockHeight,
    },
    /// Permanently obstructed.
    Unsatisfiable {
        /// Why the step can never execute.
        cause: UnsatisfiableCause,
        /// The fully-scanned height the observation rests on.
        as_of_height: BlockHeight,
    },
}

/// Why a step can never execute. `#[non_exhaustive]`: new reasons a step can never execute (a
/// retention-grid change, note-lock conflicts) have a home without breaking consumers' matches.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsatisfiableCause {
    /// The wallet has seen these inputs spent: their nullifiers were recognized in mined
    /// transactions.
    InputsSpent {
        /// The affected inputs' nullifiers, in the cache's action order.
        nullifiers: Vec<[u8; 32]>,
    },
    /// The wallet knows notes for these inputs, but their creating transaction is unmined and can
    /// never mine: it was proven against an anchor a settled reorg permanently invalidated. The
    /// inputs will never exist on chain. Carries the invalidated anchor (raw root bytes) —
    /// evidence the caller cannot recover from the checked transaction itself, since it belongs
    /// to the producer.
    InputsInvalidated {
        /// The dead anchor's raw root bytes.
        anchor: [u8; 32],
    },
    /// The transaction's expiry height has passed without it mining (ZIP 203): the pre-signed
    /// artifact can never be included in a block.
    Expired,
    /// The transaction is broadcast but unmined, its installed anchor is no longer a root on the
    /// current chain, and the invalidating reorg is settled per the caller's
    /// [`ReorgSettleDepth`]: as proven, it can never be mined.
    AnchorInvalidated,
}

impl UnsatisfiableCause {
    /// The [`UnsatisfiableKind`] recorded alongside the mark this cause applies, or `None` for a
    /// cause that applies no mark ([`Expired`](Self::Expired), which only confirms a derivation
    /// the kernel already makes from the same
    /// [`expiry_height`](crate::engine::MigrationTransaction::expiry_height)).
    ///
    /// This is the single definition of BOTH decisions — whether to mark, and under which kind —
    /// so the stamp and the kind stored beside it cannot disagree about whether there is a mark at
    /// all. [`Inherited`](UnsatisfiableKind::Inherited) is never returned here: it names a mark
    /// that arrived through the dependency closure rather than from any observed cause.
    pub const fn kind(&self) -> Option<UnsatisfiableKind> {
        // Compiler-forced over the (in-crate exhaustive) cause vocabulary: a new cause must decide
        // here whether it is an observation to store — and under which kind — or a derivation to
        // confirm.
        match self {
            UnsatisfiableCause::InputsSpent { .. } => Some(UnsatisfiableKind::InputsSpent),
            UnsatisfiableCause::InputsInvalidated { .. } => {
                Some(UnsatisfiableKind::InputsInvalidated)
            }
            UnsatisfiableCause::AnchorInvalidated => Some(UnsatisfiableKind::AnchorInvalidated),
            UnsatisfiableCause::Expired => None,
        }
    }

    /// Whether this cause records a DURABLE mark: it reports chain state the state machine cannot
    /// re-derive (the input-level causes, and the anchor-level one), as opposed to
    /// [`Expired`](Self::Expired), which only confirms a derivation the kernel already makes from
    /// the same [`expiry_height`](crate::engine::MigrationTransaction::expiry_height).
    ///
    /// Derived from [`kind`](Self::kind) rather than restating its match, deliberately: both
    /// [`MigrationState::record_satisfiability`] (which applies the mark) and
    /// [`advance_migration`] (which decides whether an answer is a discovery worth recording and
    /// broadening on) must agree, because the drive loop's TERMINATION rests on their agreement —
    /// each recorded discovery must mark at least the candidate that produced it, or the loop
    /// could re-plan onto the same candidate forever. A second copy of this match could drift into
    /// exactly that hang.
    pub(crate) const fn marks(&self) -> bool {
        self.kind().is_some()
    }
}

/// WHY a transaction can never mine, as persisted beside its
/// [`unsatisfiable_at`](crate::engine::MigrationTransaction::unsatisfiable_at) stamp and rendered
/// by a wallet: a reduced discriminant of the [`UnsatisfiableCause`] that produced the mark, plus
/// [`Inherited`](Self::Inherited) for a mark the dependency closure applied.
///
/// The full cause is deliberately NOT persisted. Its variants carry evidence payloads — a spent
/// nullifier list, a dead anchor root — that nothing in the state machine ever reads back, and
/// that a store can re-derive by asking its oracle again; storing them would grow every marked row
/// by an unbounded list to answer a question consumers ask only in words. What a consumer needs
/// durably is which of these happened, which is what this records.
///
/// `#[non_exhaustive]`: this tracks the cause vocabulary, which is itself open, so a new marking
/// cause is expected to bring a new kind with it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsatisfiableKind {
    /// The wallet saw this transaction's own inputs spent: their nullifiers were recognized in
    /// mined transactions ([`UnsatisfiableCause::InputsSpent`]).
    InputsSpent,
    /// This transaction's own inputs will never exist on chain: the wallet knows notes for them,
    /// but their creating transaction is unmined and was proven against an anchor a settled reorg
    /// permanently invalidated ([`UnsatisfiableCause::InputsInvalidated`]).
    InputsInvalidated,
    /// This transaction is broadcast and unmined, and the anchor its OWN proof installed is no
    /// longer a root of the chain the wallet has scanned
    /// ([`UnsatisfiableCause::AnchorInvalidated`]).
    AnchorInvalidated,
    /// Nothing was observed about this transaction itself: the mark arrived through the DEPENDENCY
    /// CLOSURE (see [`MigrationState::record_satisfiability`]), because a transaction it depends
    /// on can never mine. Which dependency, and what killed it, is read off that dependency's own
    /// mark.
    Inherited,
}

impl AsRef<str> for UnsatisfiableKind {
    /// The stable lowercase wire name of this kind, as a store persists it. Borrow-free: it
    /// returns a `&'static str`, so encoding a kind allocates nothing.
    fn as_ref(&self) -> &str {
        match self {
            UnsatisfiableKind::InputsSpent => "inputs_spent",
            UnsatisfiableKind::InputsInvalidated => "inputs_invalidated",
            UnsatisfiableKind::AnchorInvalidated => "anchor_invalidated",
            UnsatisfiableKind::Inherited => "inherited",
        }
    }
}

/// The error returned when a string does not name an [`UnsatisfiableKind`] (its
/// [`TryFrom<&str>`] impl).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseUnsatisfiableKindError;

impl fmt::Display for ParseUnsatisfiableKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized unsatisfiability kind")
    }
}

impl TryFrom<&str> for UnsatisfiableKind {
    type Error = ParseUnsatisfiableKindError;

    /// Parses the lowercase wire name produced by [`AsRef<str>`](AsRef).
    ///
    /// The vocabulary is open — this enum is `#[non_exhaustive]` — but an unrecognized name is
    /// still an ERROR here, and a store surfaces it as corruption exactly as it does an
    /// unrecognized [`MigrationStatus`] or [`MigrationTxState`] discriminant. A name written by a
    /// future release is not a value this one can render or reason about, and treating it as
    /// "unmarked" would resurrect a dead transaction into the prove and broadcast queues, so it is
    /// reported rather than smoothed over.
    ///
    /// [`MigrationStatus`]: crate::engine::MigrationStatus
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(match s {
            "inputs_spent" => UnsatisfiableKind::InputsSpent,
            "inputs_invalidated" => UnsatisfiableKind::InputsInvalidated,
            "anchor_invalidated" => UnsatisfiableKind::AnchorInvalidated,
            "inherited" => UnsatisfiableKind::Inherited,
            _ => return Err(ParseUnsatisfiableKindError),
        })
    }
}

/// A store implementation's observation for one queried nullifier, fed to
/// [`classify_input_observations`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputObservation {
    /// The note is known and unspent.
    Unspent,
    /// The note is known and the wallet has seen it spent in a mined transaction.
    SeenSpent,
    /// The note is known, its creating transaction is unmined, and that transaction's anchor was
    /// permanently invalidated (settled per the caller's policy). Carries the dead anchor root.
    Invalidated([u8; 32]),
    /// No note with this nullifier has been scanned, or its unmined creator is still viable.
    Unknown,
}

/// Fold per-nullifier observations, plus the transaction-level expiry judgment, into a
/// [`StepSatisfiability`], encoding the answer precedence: `InputsSpent` over
/// `InputsInvalidated` (both are permanent input-level deaths, and a recognized spend is the
/// definitive on-chain fact) over `Expired` (expiry's remedy — a rebuild, fresh proof included —
/// cannot cure missing inputs, so the input-level causes must dominate it) over
/// `NotYetSatisfiable` (anything definite dominates "try later") over `Satisfiable`.
///
/// Pure: an implementation supplies only its data access and composes with this, so the
/// classification is defined once. `AnchorInvalidated` is a transaction-level observation on
/// broadcast-unmined transactions, answered by the implementation directly rather than through
/// this per-input fold, and takes the precedence position below `Expired`. The observation set
/// must come from the transaction's [`spend_nullifiers`] cache, which is non-empty for every
/// validly committed transaction; implementations surface their corruption error for an empty
/// cache on a non-mined transaction rather than calling this with no observations (an empty
/// cache means a backfill-exempted mined row re-entered the watched set after a chain rewind, or
/// deeper corruption — never vacuous satisfiability).
///
/// [`spend_nullifiers`]: crate::engine::MigrationTransaction::spend_nullifiers
pub fn classify_input_observations(
    as_of_height: BlockHeight,
    expired: bool,
    observations: &[([u8; 32], InputObservation)],
) -> StepSatisfiability {
    let spent: Vec<[u8; 32]> = observations
        .iter()
        .filter(|(_, o)| matches!(o, InputObservation::SeenSpent))
        .map(|(nf, _)| *nf)
        .collect();
    if !spent.is_empty() {
        return StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::InputsSpent { nullifiers: spent },
            as_of_height,
        };
    }
    if let Some(anchor) = observations.iter().find_map(|(_, o)| match o {
        InputObservation::Invalidated(a) => Some(*a),
        _ => None,
    }) {
        return StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::InputsInvalidated { anchor },
            as_of_height,
        };
    }
    if expired {
        return StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::Expired,
            as_of_height,
        };
    }
    if observations
        .iter()
        .any(|(_, o)| matches!(o, InputObservation::Unknown))
    {
        return StepSatisfiability::NotYetSatisfiable { as_of_height };
    }
    StepSatisfiability::Satisfiable { as_of_height }
}

/// How many blocks a named step's scheduled height may lag the SERVED target
/// ([`DuenessTargets::effective`]) before [`advance_migration`] re-spreads the remaining
/// schedule: a quarter of `transfer_delay`'s mean inter-broadcast gap, clamped to at least one
/// block. Under the ZIP 318 parameters (a 66-block mean) that is 16 blocks, about 20 minutes at
/// the target block spacing.
///
/// A lag within the tolerance is ordinary wake-up slop (an OS timer delivered late, a block or
/// two of estimation error), and the step is served as scheduled. A larger lag means the wallet
/// slept through part of its broadcast schedule, and serving the backlog as-is would cluster
/// broadcasts the drawn delays exist to spread apart — so the whole pending schedule is shifted
/// forward by the overdue amount instead (see the overdue-shift step in the flow
/// [`advance_migration`] documents).
///
/// The tolerance is a FUNCTION of the schedule's own scale rather than a constant, because
/// "late" only means anything relative to the gaps the schedule draws: a lag that is noise
/// against ZIP 318's 66-block mean would swallow whole broadcast windows on a test network whose
/// delays are compressed by [`SchedulingParams::new_with_default_distributions`]. A quarter of
/// the mean keeps the trigger comfortably above wake-up slop while still re-spreading well
/// before the lag reaches a typical inter-broadcast gap.
///
/// [`advance_migration`] evaluates this against the transfer delay derived from the migration's
/// PERSISTED anchor bucket interval (via the default ZIP 318 ratio), so the tolerance tracks the
/// schedule as it was committed; a migration committed under hand-overridden delay
/// distributions is judged by that ratio-derived approximation.
pub fn overdue_shift_tolerance(transfer_delay: &DelayDistribution) -> u32 {
    (transfer_delay.mean().get() / 4).max(1)
}

/// Drive-level policy for [`advance_migration`]: a struct, so future knobs join without signature
/// churn.
#[derive(Clone, Copy, Debug)]
pub struct AdvanceConfig {
    reorg_settle_depth: ReorgSettleDepth,
}

impl AdvanceConfig {
    /// Drive-level policy under the caller's reorg-settlement policy.
    ///
    /// The settle depth is explicitly required — no `Default` — because the right value tracks the
    /// chain's block spacing, and keeping it current is the caller's responsibility, not this
    /// crate's.
    pub const fn new(reorg_settle_depth: ReorgSettleDepth) -> Self {
        Self { reorg_settle_depth }
    }

    /// The caller's reorg-settlement policy; see [`ReorgSettleDepth`].
    pub const fn reorg_settle_depth(&self) -> ReorgSettleDepth {
        self.reorg_settle_depth
    }
}

/// The two heights a migration's dueness is judged against: what the wallet's chain data SUPPORTS,
/// and where the tip has probably reached.
///
/// Both carry this crate's TARGET convention — `chain_tip + 1`, the height of the next block a
/// transaction could be mined in — so both are directly comparable with an
/// [`expiry_height`](crate::engine::MigrationTransaction::expiry_height) or a
/// [`scheduled_height`](crate::engine::MigrationTransaction::scheduled_height); neither is a raw tip.
///
/// # Why two
///
/// ZIP 318 separates a wallet's SYNC wake-ups from its BROADCAST wake-ups, so a wallet must be able
/// to decide what is due WITHOUT contacting lightwalletd first (only the Tor-guarded submission
/// follows the decision). At that moment it holds exactly two things: the frontier its own database
/// has fully scanned to — an observation — and a wall-clock ESTIMATE of where the chain tip has
/// reached since. Schedule dueness is unknowable from the frontier alone (a wallet that has not
/// synced for a week would consider nothing due), so the estimate must be usable; but every
/// judgment that PERSISTS a verdict or DESTROYS work must rest on chain data, because the state
/// machine cannot tell a guess from an observation.
///
/// # The invariant
///
/// No transition that persists a verdict or destroys work may depend on chain state above the
/// SCANNED frontier. The estimate may only RE-ORDER the service of steps that are already legal, or
/// protectively WITHHOLD them. Concretely:
///
/// | Judged at [`effective`](Self::effective) | Judged at [`scanned`](Self::scanned) |
/// |---|---|
/// | schedule dueness in the prove and broadcast queues | expiry as a DECISION: the kernel's dead set, [`MigrationState::expired_transactions`] and [`AdvanceStep::Rebuild`] eligibility, the drain-time [`Replan`](crate::state::AdvanceStep::Replan) gate |
/// | the doomed-broadcast withhold — a transfer whose expiry has probably passed is not offered, and [`transaction_statuses`](MigrationState::transaction_statuses) reports [`Blocker::ExpiryImminent`](crate::state::Blocker::ExpiryImminent); protective and reversible, since the scanned path still owns the verdict | the dependency closure of [`MigrationState::record_satisfiability`], which writes `Inherited` marks into the store |
/// | the prove-side expiry skip: proving a transfer that has probably lapsed is wasted work, and skipping it is reversible | anchor-boundary settledness, since an estimate cannot conjure a commitment-tree checkpoint |
/// | the overdue re-spread ([`overdue_shift_tolerance`]): a step lagging the served target by more than the tolerance shifts the whole pending schedule forward by the lag. The shift PERSISTS, but what it persists is a schedule, never a verdict: it re-times the service of steps and records no determination, so an overshooting estimate can only delay broadcasts, not condemn work | the [`Expired`](crate::state::Blocker::Expired) blocker in `transaction_statuses`, a rendered determination |
///
/// The clamp in [`new`](Self::new) guarantees `effective >= scanned`, so the transposition
/// hazard — an estimate reaching a destructive check — is unrepresentable by construction rather
/// than by call-site discipline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuenessTargets {
    scanned: BlockHeight,
    effective: BlockHeight,
}

impl DuenessTargets {
    /// Targets from the wallet's own scanned frontier and its estimate of the chain tip, both as
    /// TARGETS (`height + 1`, the next block a transaction could mine in — not the heights
    /// themselves).
    ///
    /// `estimated` is clamped up to `scanned`: an estimate that lags the wallet's own observations
    /// is simply less informed than they are, and letting it lower the effective target would
    /// withhold work the chain data already justifies.
    pub fn new(scanned: BlockHeight, estimated: BlockHeight) -> Self {
        Self {
            scanned,
            effective: core::cmp::max(scanned, estimated),
        }
    }

    /// The degenerate pair, for a caller whose estimate IS its chain view — a server that follows
    /// the chain continuously, or a test.
    ///
    /// Every judgment is then made at the same height, which is exactly the single-target behavior
    /// that preceded this type.
    pub const fn at(target: BlockHeight) -> Self {
        Self {
            scanned: target,
            effective: target,
        }
    }

    /// The target backed by CHAIN DATA (the wallet's fully-scanned frontier, plus one): the height
    /// every persisted verdict and every destructive judgment is made at.
    pub const fn scanned(&self) -> BlockHeight {
        self.scanned
    }

    /// The target the SCHEDULE is served at (the estimated chain tip, plus one; never below
    /// [`scanned`](Self::scanned)): the height dueness is judged at, and the height a doomed
    /// broadcast is withheld from.
    pub const fn effective(&self) -> BlockHeight {
        self.effective
    }
}

/// What one [`advance_migration`] call decides: the verified step to perform NOW, and the
/// OUTLOOK — when the migration will next have work, and of what kind, assuming the returned
/// step is executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advance {
    step: AdvanceStep,
    next: Option<(BlockHeight, StepKind)>,
}

impl Advance {
    /// The step to perform now, verified against the store's satisfiability oracle exactly as
    /// [`advance_migration`] documents.
    pub const fn step(&self) -> &AdvanceStep {
        &self.step
    }

    /// The SUBSEQUENT step, assuming [`step`](Self::step) is executed and recorded: the kind of
    /// work it will be, and the earliest target height (this crate's `chain_tip + 1` convention,
    /// directly comparable with the caller's [`DuenessTargets`]) at which it becomes
    /// serviceable. A height at or below the caller's current target means more work is
    /// serviceable in this same session; a later height is the wake-up to register, with the
    /// kind saying what session to plan (a [`Broadcast`](StepKind::Broadcast) needs no sync, a
    /// [`Prove`](StepKind::Prove) is sync-bound — the ZIP 318 session separation
    /// [`advance_migration`] documents).
    ///
    /// The outlook is ADVISORY, the kernel's unverified plan: the height is a floor, not an
    /// appointment (dependencies still have to mine, and the wake-up's own [`advance_migration`]
    /// call verifies — and may displace — the step and names the transaction it applies to), and
    /// it holds only as of the state this call returned, so the next call's outlook supersedes
    /// it. `None` means nothing is height-schedulable: what follows is chain-driven (an
    /// in-flight transaction mining, a dependency the scan must observe) or user-driven (a
    /// signature, a replan, the sync a [`Reevaluate`](AdvanceStep::Reevaluate) asks for), or the
    /// migration is terminal. In particular, a step whose own execution decides what comes next
    /// — a [`Rebuild`](AdvanceStep::Rebuild), whose fresh schedule is drawn at rebuild time; a
    /// [`Replan`](AdvanceStep::Replan) or [`Reevaluate`](AdvanceStep::Reevaluate), whose outcome
    /// supersedes or re-decides the plan — carries `None`, and the call that follows the
    /// execution reports the fresh outlook.
    pub const fn next(&self) -> Option<(BlockHeight, StepKind)> {
        self.next
    }
}

/// Decide the next step to advance a committed migration and VERIFY it against the store before
/// surfacing it: the entry point a consuming application drives a migration with, against the
/// caller's [`DuenessTargets`] — its scanned frontier and its estimate of where the chain tip has
/// reached, both as targets (`height + 1`). Returns the step paired with the OUTLOOK — the
/// subsequent step's kind and earliest serviceable height, assuming the returned step is
/// executed ([`Advance::next`] defines its semantics).
///
/// A single call plans, verifies, records, and persists:
///
/// 0. It adjudicates any standing BROADCAST-FAILURE REPORT
///    ([`MigrationState::report_broadcast_failure`]) — a node rejected a broadcast, and the
///    rejection is another observer's testimony until this wallet has scanned the chain state it
///    rests on. While the oracle still answers from below the reported tip the call surfaces
///    [`AdvanceStep::Reevaluate`] and does nothing else; once it answers from at or above that
///    tip the report is discharged, either recording the ordinary evidence-backed mark or
///    finding the rejection transient and returning the transaction to the broadcast queue in
///    this same call.
/// 1. It asks the planning kernel what to do next, decided purely from the persisted state.
/// 2. A named `Prove` or `Broadcast` candidate whose scheduled height lags the SERVED target
///    ([`DuenessTargets::effective`]) by more than the schedule-scaled tolerance
///    ([`overdue_shift_tolerance`], sized from the transfer delay the migration's persisted
///    anchor bucket interval implies) means the wallet
///    slept through part of its broadcast schedule, and the whole pending schedule is shifted
///    forward by the lag before anything else happens (for a transfer's `Prove` the overdueness
///    clock starts no earlier than the anchor-depth gate's own floor,
///    `boundary + `[`PROVABLE_ANCHOR_DEPTH`]` + 1`, so a proof the gate itself held back never
///    reads as wallet sleep): the
///    candidate comes due exactly at the served target — so it is still released in this call,
///    which is ZIP 318's "at most one overdue transfer is released immediately" — while every
///    other not-yet-broadcast transaction re-spreads behind it with its drawn gaps intact,
///    instead of the missed steps broadcasting as a cluster. A shifted transfer whose PROOF is
///    still to come also has its anchor boundary redrawn against the shifted schedule
///    ([`redraw_anchor_boundary`](crate::scheduling::redraw_anchor_boundary)): its stored
///    boundary was in-distribution for the original broadcast height, and broadcasting it
///    `delta` blocks late — with every deferred sibling late by the SAME `delta` — would carry
///    an anchor age no honest draw produces, a linkable fingerprint. (A `Proved` transfer's
///    proof pins its anchor, so its boundary is kept; a preparation draws none.) The anchor
///    redraw is why this function takes a [`CryptoRng`]: the drawn boundaries are
///    privacy-relevant observables. A `Rebuild` candidate never triggers the shift: the rebuild
///    itself redraws its transfer's schedule from the target, and an expired candidate's stale
///    height would overstate the shift for the still-live remainder.
/// 3. It puts the transaction the kernel names to the store's satisfiability oracle
///    ([`PoolMigrationRead::check_step_satisfiability`]) — the wallet's live view of whether that
///    pre-signed artifact can still execute.
/// 4. A candidate the wallet reports PERMANENTLY obstructed (its inputs seen spent elsewhere, or
///    unable to ever exist) is recorded through [`MigrationState::record_satisfiability`], and the
///    kernel is asked again — the recorded marks, and everything stranded behind them, now
///    filtered out of its queues. A candidate the wallet cannot YET vouch for is set aside for the
///    rest of this call (no mark: the honest reading of "retry after further sync"), so the
///    migration's other work still surfaces, and the kernel is asked again.
/// 5. The step that survives verification is returned, with every determination made along the way
///    — including a shifted schedule — already written back to the store.
///
/// So a consumer never spends proving or broadcast work on a transaction whose inputs are gone,
/// and a migration whose plan has been undercut — most often by an ordinary wallet spend consuming
/// notes it had allocated — surfaces [`AdvanceStep::Replan`] instead of retrying a dead
/// transaction forever.
///
/// # The drive loop
///
/// One call returns ONE step. The consumer performs that step's I/O, records the outcome in the
/// state, persists it, and calls this again; until the state records the step's completion, the
/// same step is offered again. The steps map onto the crate's operations as follows:
///
/// - [`AdvanceStep::Prove`]: for EACH named transaction in order, install its deferred anchor
///   and witnesses — [`prove_transfer`] / [`prove_preparation`], chosen by the
///   [`kind`](crate::state::ProveTarget::kind) each batch entry carries — and hand the returned
///   proof to
///   [`PoolMigrationWrite::store_proved_transaction`], which records the `Signed -> Proved`
///   transition and persists it (for a wallet-database store, atomically with the wallet's own
///   record of the now fully-constructed transaction). The step names the WHOLE currently
///   provable set at once — proving emits nothing a network observer can see, so unlike
///   broadcasting there is nothing to space out, and a synced session proves everything it can
///   (see [`AdvanceStep::Prove`] for the ordering and the mixed-kinds note). Proving needs a
///   SYNCED wallet and mutable access to its commitment trees, but only the account's viewing
///   key. A consumer interrupted partway through the batch loses nothing: the next call
///   re-offers exactly the still-unproved remainder.
/// - [`AdvanceStep::Broadcast`]: submit the stored proven transaction to the network, then record
///   it with [`MigrationState::mark_broadcast`]. Its mining is later detected through the
///   consumer's own chain view and recorded with [`MigrationState::mark_mined`], which is what
///   unblocks the transactions depending on it.
/// - [`AdvanceStep::Rebuild`]: construct and sign a replacement for an expired transfer —
///   [`rebuild_expired_transfer`] or its unsigned (external-signer) variant. The only step that
///   needs the account's SPEND AUTHORITY.
/// - [`AdvanceStep::Replan`]: the migration itself needs replacing — mark it superseded
///   ([`MigrationState::mark_superseded`]), persist, and re-plan the remaining balance through the
///   ordinary planning flow. Surfaced when the unsatisfiable share of planned transfer value
///   strictly exceeds the committed [`ReplanThreshold`], and — once no live work remains at all —
///   when dead value would otherwise be stranded.
/// - [`AdvanceStep::Reevaluate`]: SYNC the wallet to at least the tip reported alongside a
///   rejected broadcast, then call this again. Surfaced ahead of every step but
///   [`Complete`](AdvanceStep::Complete), and unconditionally: a rejection means another observer
///   saw chain state this wallet has not, and same-seed activity invalidates the whole store
///   view rather than one transaction's answer.
/// - [`AdvanceStep::Waiting`]: nothing is actionable at this height. The returned
///   [`Advance::next`] carries the earliest height at which that changes, and the kind of work it
///   will be; consult [`MigrationState::transaction_statuses`] for what each transaction is
///   blocked on, and [`MigrationState::sync_wakeup_schedule`] for the full proving wake-up
///   schedule a background-constrained wallet registers with its OS.
/// - [`AdvanceStep::Complete`]: the migration is terminal (every transaction mined, or the
///   migration failed/cancelled); nothing will ever be actionable again, so stop polling.
///
/// A transaction that can never mine is never named: those marked unsatisfiable, those expired
/// without mining, and everything stranded behind either are excluded from the prove, broadcast,
/// and rebuild queues alike. And a DUE BROADCAST is named ahead of any proving work, which is what
/// makes a broadcast-only waking session possible (see the ZIP 318 note below).
///
/// # The dueness contract
///
/// `targets` carries two heights because this call makes two KINDS of judgment, and only one of
/// them may rest on a guess (see [`DuenessTargets`] for the classification table and the ZIP 318
/// session separation that forces the split). The invariant this function upholds:
///
/// > No transition that persists a verdict or destroys work depends on chain state above the
/// > SCANNED target. The estimate may only re-order the service of steps that are already legal,
/// > or protectively withhold them.
///
/// So the judgments that are DESTRUCTIVE if made too high are all anchored at
/// [`scanned`](DuenessTargets::scanned):
///
/// - EXPIRY as a determination is `expiry_height < scanned`, so an overshooting estimate can never
///   condemn a live pre-signed transfer as expired — a remedy that requires signing it ANEW.
/// - Expired-and-unmined transactions SEED the kernel's dead set, so the same overshoot cannot
///   strand every dependent behind them.
/// - The durable dependency closure ([`MigrationState::record_satisfiability`]) stamps inherited
///   marks off those seeds, writing them into the store.
/// - The drain-time [`Replan`](AdvanceStep::Replan) fires once every unmined transaction is dead,
///   and the consumer's contracted response to it — [`MigrationState::mark_superseded`] — is
///   terminal.
/// - [`Rebuild`](AdvanceStep::Rebuild) eligibility is judged the same way.
///
/// while the SCHEDULE is served at [`effective`](DuenessTargets::effective), so a wallet woken by
/// wall-clock estimate submits a transfer that is due without first synchronizing. The one further
/// thing the estimate does is WITHHOLD: a proven transfer whose expiry has probably passed
/// (`scanned <= expiry_height < effective`) is not offered for broadcast or proving, because
/// submitting it would be refused by the node and proving it would be wasted work. That withhold
/// records nothing and reverses itself as the wallet's scan catches up, whereupon the scanned path
/// makes the actual determination. [`MigrationState::transaction_statuses`] renders such a
/// transaction as [`Blocker::ExpiryImminent`](crate::state::Blocker::ExpiryImminent), neither
/// `ready` nor carrying an action, so a status-driven consumer never wakes a broadcast session
/// this function would refuse.
///
/// # What a call costs
///
/// Checking is LAZY UNTIL FIRST DISCOVERY and BROAD AT DISCOVERY, so a healthy migration pays
/// almost nothing:
///
/// - the in-flight sweep — per broadcast-but-unmined transaction, one indexed
///   [`mined_height`](PoolMigrationRead::mined_height) lookup, and then, only for one the scan has
///   NOT seen mine, one satisfiability query judging whether its inputs were spent elsewhere or a
///   settled reorg has permanently invalidated the anchor it was proven against. A transaction
///   that has mined costs the lookup alone. The broadcast schedule keeps that set tiny (typically
///   none to two transactions sit between broadcast and mining), and it is the only check for
///   transactions the kernel will never name as a step;
/// - per PROVED transaction, one PCZT parse and txid derivation
///   ([`pczt_txid`](crate::pczt_txid::pczt_txid)) plus the same indexed lookup, catching a
///   broadcast the consumer failed to record. This is the sweep's only per-row cost that is not a
///   database query, and it is paid on a set that empties as transactions are broadcast. A store
///   that persists each transaction's derived id could answer from there instead; nothing here
///   requires the derivation to happen per call;
/// - one query per transaction the step names — a single candidate for `Broadcast` and
///   `Rebuild`, each member of a `Prove` batch in the call that serves it (each is about to
///   cost proving work) — and none at all when the kernel answers
///   [`Waiting`](AdvanceStep::Waiting), [`Complete`](AdvanceStep::Complete), or
///   [`Replan`](AdvanceStep::Replan), which name no transaction.
///
/// A discovery costs more, deliberately: it also checks every pending transaction whose
/// dependencies have mined. That is what makes the migration's remaining value re-assessed in the
/// call that finds the first dead transaction — a send-max that consumed the funding notes trips
/// the replan threshold immediately, rather than one transfer at a time over the weeks a
/// privacy-preserving broadcast schedule spans.
///
/// # Persistence, and what the consumer owns
///
/// This function owns the persistence of the determinations it makes: whenever a check recorded
/// anything, the state is written back with [`PoolMigrationWrite::replace_migration`] BEFORE the
/// step is returned, so the store already agrees with the returned `state` when the consumer acts.
/// Nothing is written when nothing was discovered.
///
/// On an `Err`, treat the passed `state` as UNTRUSTED and re-read it with
/// [`get_migration`](PoolMigrationRead::get_migration) before driving again. A failing store
/// leaves the two views free to disagree in one direction: the store never holds a determination
/// the returned state lacks, but the reverse can happen — a write that failed, or in-flight-sweep
/// marks left unpersisted by a later oracle failure, live only in the in-memory state. Discarding
/// it costs nothing, because marks are re-derivable: the next call asks the same questions again.
///
/// Everything else remains the consumer's: it performs the returned step's I/O and records the
/// outcome through the ordinary mutators ([`MigrationState::mark_broadcast`], the prove and
/// rebuild functions), persisting afterwards as usual, then calls this again. Note what is NOT on
/// that list: MINING. The consumer records what only it can know — that it submitted a
/// transaction to a node — and this function derives inclusion from the wallet's own scan (see the
/// in-flight sweep, and [`mined_height`](PoolMigrationRead::mined_height)). A driver that never
/// calls [`MigrationState::mark_mined`] is the intended shape.
///
/// In particular, the ZIP 318 separation of SYNC wake-ups from
/// BROADCAST wake-ups is the consumer's runtime policy. Broadcasting a stored proven transaction
/// needs no sync at all, while proving is inherently sync-bound, so surfacing every due broadcast
/// first is what lets a wallet wake, submit, and end the session without initiating sync
/// operations. But this function itself has no notion of a session — once every due broadcast is
/// dispatched it offers proving work in the same loop — so a wallet honoring the separation stops
/// driving the migration after broadcasting and leaves the offered proving work to its next sync
/// wake-up.
///
/// [`prove_transfer`]: crate::engine::prove_transfer
/// [`prove_preparation`]: crate::engine::prove_preparation
/// [`rebuild_expired_transfer`]: crate::engine::rebuild_expired_transfer
pub fn advance_migration<St: PoolMigrationWrite, R: RngCore + CryptoRng>(
    store: &mut St,
    state: &mut MigrationState,
    targets: DuenessTargets,
    config: &AdvanceConfig,
    rng: &mut R,
) -> Result<Advance, St::Error> {
    // Whether any determination has been recorded, and so whether the state must be written back
    // before a step is surfaced.
    let mut dirty = false;
    // This call's deferrals: candidates the wallet answered `NotYetSatisfiable` for. They carry no
    // mark — the answer is "retry after further sync", not an obstruction — so the list lives only
    // for this call.
    let mut set_aside: Vec<MigrationTransferId> = Vec::new();

    // The IN-FLIGHT SWEEP, over every transaction that could already be on chain: the ones
    // recorded `Broadcast`, and the `Proved` ones that might have been broadcast without the
    // record landing. The kernel never names either as a step, so no candidate check would reach
    // them; this is where their questions are asked, in the order the chain settles them.
    //
    // FIRST, DID IT MINE? Inclusion is chain-derived and final, so it is asked before anything
    // that could record a verdict about the transaction. `mark_mined` discharges an
    // unsatisfiability mark and an open broadcast-failure report on its way through, which is how
    // "chain inclusion outranks every prior verdict" holds without a single special case anywhere
    // below. Asking here rather than leaving it to the consumer is what keeps the state from
    // trailing the wallet's own scan: a mined transaction the consumer has not noticed is
    // indistinguishable, to every check that follows, from one still competing for its inputs.
    //
    // A `Proved` row is asked the same question against the txid derived from its stored PCZT
    // (`pczt_txid`, stable from signing because the anchor is authorizing rather than effecting
    // data for these transactions). That closes the one gap a recorded-txid sweep cannot see: a
    // consumer that submitted to a node and then died — or failed to persist — before
    // `mark_broadcast` leaves a `Proved` row whose transaction is on chain, which nothing else
    // would ever promote. Such a row is promoted THROUGH `Broadcast`, since that is the state the
    // lost record would have written.
    //
    // SECOND, AND ONLY FOR A TRANSACTION THE SCAN HAS NOT SEEN MINE: is it still viable? Two
    // causes are determinations here:
    //
    // - `InputsSpent` means this transaction's own inputs were seen spent in a MINED transaction
    //   that is not this one — the mining question above has just established, from the same
    //   scanned view, that the wallet has not seen this transaction mine. The two answers rest on
    //   one view by the store's contract (see `PoolMigrationRead::mined_height`), so they cannot
    //   disagree about a transaction at the scan's edge: either the scan has reached the block
    //   that includes it, and both see it, or neither does. A spender that is not this
    //   transaction is a foreign spend, and this transaction can never mine.
    // - `AnchorInvalidated`: the anchor it was PROVEN against no longer exists on the chain, per
    //   a reorg the caller's `ReorgSettleDepth` judges settled.
    //
    // `InputsInvalidated` and `Expired` remain DELIBERATELY deferred rather than acted on here.
    // Their loss is bounded: a producer inside the migration reaches its victim through the
    // dependency closure, and a victim of an EXTERNAL producer self-heals at its own expiry, when
    // the kernel's derived expiry makes it a dead-set seed. The pending-side channel — a candidate
    // check, or the broaden sweep after any discovery — is where those become determinations.
    let mut mined: Vec<(MigrationTransferId, BlockHeight)> = Vec::new();
    let mut unrecorded: Vec<(MigrationTransferId, BlockHeight)> = Vec::new();
    let mut findings: Vec<(MigrationTransferId, StepSatisfiability)> = Vec::new();
    for tx in state.transactions() {
        let txid = match tx.state() {
            MigrationTxState::Broadcast { txid } => txid,
            // A row that was never proved was never broadcast — it carries no proofs, so no node
            // would have accepted it — and cannot be on chain. Nothing to ask.
            MigrationTxState::Proved => {
                if let Some(height) = store.mined_height(tx.txid())? {
                    unrecorded.push((tx.id(), height));
                }
                // A `Proved` row has no other question: the anchor judgment applies to a
                // transaction already in flight, and its inputs are the pending-side channel's
                // business.
                continue;
            }
            _ => continue,
        };
        if let Some(height) = store.mined_height(txid)? {
            mined.push((tx.id(), height));
            // Settled: no verdict may be sought, let alone recorded, about a transaction the
            // chain has included. This also spares the satisfiability query outright, so a
            // migration whose transactions are mining pays LESS here than before, not more.
            continue;
        }
        // Already marked: nothing further to DETERMINE about it. Note that the mining question
        // above was still asked of it, deliberately — a marked transaction that mines anyway is a
        // mark the oracle should not have made (an aggressive settle depth the chain then swung
        // back under), and promoting it is how that self-corrects rather than stranding the row.
        if tx.unsatisfiable_at().is_some() {
            continue;
        }
        let answer = store.check_step_satisfiability(tx, config.reorg_settle_depth())?;
        if matches!(
            &answer,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent { .. }
                    | UnsatisfiableCause::AnchorInvalidated,
                ..
            }
        ) {
            findings.push((tx.id(), answer));
        }
    }
    // Promotions before determinations: `record_satisfiability` seeds its dead set from the
    // transactions that can never mine, and a row promoted above is not one of them.
    for (id, height) in unrecorded {
        // Through `Broadcast` first: that is the state the lost record would have written, and it
        // is what `mark_mined` demotes back to if a reorg later un-mines the transaction.
        state.mark_broadcast(id);
        state.mark_mined(id, height);
        dirty = true;
    }
    for (id, height) in mined {
        state.mark_mined(id, height);
        dirty = true;
    }
    if !findings.is_empty() {
        state.record_satisfiability(targets, &findings);
        dirty = true;
    }

    // ADJUDICATING THE BROADCAST-FAILURE REPORTS. A report says a node refused a broadcast at a
    // tip this wallet may not have reached; it is testimony, so nothing is concluded from it
    // until the wallet's own answers rest at or above that tip. One query per reported
    // transaction, and none at all for the overwhelmingly common case of no reports.
    //
    // Skipped entirely for a TERMINAL migration: it is never driven further, so there is no
    // broadcast to withhold and no benefit in holding the loop at `Reevaluate` instead of the
    // `Complete` the kernel is about to return.
    let mut reevaluation_pending = false;
    if !state.is_terminal() {
        let mut adjudicated: Vec<MigrationTransferId> = Vec::new();
        let mut verdicts: Vec<(MigrationTransferId, StepSatisfiability)> = Vec::new();
        for tx in state.transactions() {
            let Some(reported_tip) = tx.broadcast_failure_at() else {
                continue;
            };
            let answer = store.check_step_satisfiability(tx, config.reorg_settle_depth())?;
            if answer_as_of_height(&answer) < reported_tip {
                // The wallet has not scanned every block that could hold the spend behind the
                // rejection, so neither answer it could give would be about the right chain.
                reevaluation_pending = true;
                continue;
            }
            // At or above the reported tip the question is settled, whichever way it fell: a
            // marking cause records the ordinary evidence-backed determination, and anything
            // else means the rejection was transient (a mempool conflict, a node-local policy)
            // and the transaction returns to the broadcast queue in this same call. Either way
            // the testimony has been discharged and must not withhold the transaction again.
            adjudicated.push(tx.id());
            if records_a_determination(&answer) {
                verdicts.push((tx.id(), answer));
            }
        }
        if !verdicts.is_empty() {
            // A DISCOVERY here broadens exactly as one at a candidate check does: what killed
            // this transaction is a fact about the migration's environment — same-seed spending
            // typically kills several transfers at once — so the whole damage is assessed in the
            // call that finds the first of it, and the replan threshold trips here rather than
            // one broadcast attempt at a time.
            broaden_after_discovery(store, state, &mut verdicts, config.reorg_settle_depth())?;
            state.record_satisfiability(targets, &verdicts);
        }
        for id in &adjudicated {
            state.clear_broadcast_failure(*id);
        }
        dirty |= !adjudicated.is_empty();
    }
    if reevaluation_pending {
        // Unconditional: a rejection means some other observer saw chain state this wallet has
        // not, and same-seed activity invalidates the whole store view rather than one
        // transaction's answer. Whatever was adjudicated above is still persisted first. No
        // outlook: what follows depends on how the adjudication falls, which is exactly what the
        // requested sync exists to decide.
        if dirty {
            store.replace_migration(state)?;
        }
        return Ok(Advance {
            step: AdvanceStep::Reevaluate,
            next: None,
        });
    }

    // The overdue-shift tolerance, sized to the schedule AS COMMITTED: the persisted anchor
    // bucket interval is the state's own record of its schedule's scale, and the default ZIP 318
    // ratio recovers the transfer delay it was (absent a hand-override) drawn from. Judging
    // overdueness by the committed scale rather than a caller-supplied current one is what keeps
    // the tolerance meaningful for a migration committed under different parameters.
    let overdue_tolerance = overdue_shift_tolerance(
        &SchedulingParams::new_with_default_distributions(state.anchor_bucket_interval())
            .transfer_delay(),
    );

    // Plan, verify, record, plan again: ask the kernel for a step, and put every transaction
    // the step names — its CANDIDATES: the members of a `Prove` batch, or the single
    // transaction of a `Broadcast` or `Rebuild` — to the store's satisfiability oracle before
    // the step is surfaced.
    //
    // The loop terminates because each iteration does exactly one of:
    // - BREAK, surfacing a step: one naming no transaction, or one whose every candidate the
    //   oracle vouched for.
    // - Grow `set_aside`, the call-local list of candidates deferred as "not yet satisfiable".
    //   Ids are never removed and the kernel never re-names a set-aside id, so this happens at
    //   most once per transaction.
    // - Record at least one new UNSATISFIABILITY MARK — the durable
    //   `MigrationTransaction::unsatisfiable_at` stamp, written through
    //   `MigrationState::record_satisfiability` when the oracle reports a candidate's inputs
    //   spent or its anchor invalidated. At least one, because the kernel never names an
    //   already-marked transaction (marked transactions are in its dead set), so a discovery
    //   always stamps a previously unmarked one; bounded by the transaction count.
    // - Shift the schedule. The trigger compares pending scheduled heights against
    //   `targets.effective()` — the height the schedule is SERVED at, a constant of this call —
    //   and fires only on a candidate lagging it by more than `overdue_tolerance`; the shift
    //   then raises every pending scheduled height by more than that tolerance. The minimum
    //   pending height therefore climbs by more than the tolerance per shift while the served
    //   height stands still, so after finitely many shifts no candidate lags far enough to
    //   trigger, and shifts stop.
    let step = 'plan: loop {
        let step = state.next_step(targets, &set_aside);
        // The candidates the step names, in the order the step carries them: a `Prove`'s whole
        // batch, or the single transaction of a `Broadcast` or `Rebuild`.
        let candidates: Vec<MigrationTransferId> = match &step {
            AdvanceStep::Prove { transactions } => transactions.iter().map(|t| t.id()).collect(),
            AdvanceStep::Broadcast { id } | AdvanceStep::Rebuild { id } => vec![*id],
            // These name no transaction, so there is nothing to verify. `Reevaluate` is decided
            // above, by this function, and the kernel never returns it — but it is a step like
            // any other here, and matching it explicitly keeps that fact from resting on the
            // absence of an arm.
            AdvanceStep::Waiting
            | AdvanceStep::Complete
            | AdvanceStep::Replan
            | AdvanceStep::Reevaluate => break step,
        };
        // Each candidate's schedule data, copied out so no borrow of `state` outlives the
        // mutations below. The kernel names its candidates out of `state.transactions()`, so an
        // id that is not there means the state is corrupt: nothing can be verified about it and
        // nothing may be surfaced unverified, so the call reports `Waiting` — the safe
        // degradation, and a BREAK rather than another iteration, which leaves no way for a
        // corrupt state to spin the loop. Anything already recorded is still persisted below.
        let mut schedule_data: Vec<(MigrationTransferId, u32, Option<u32>)> =
            Vec::with_capacity(candidates.len());
        for id in &candidates {
            let Some(tx) = state.transactions().iter().find(|t| t.id() == *id) else {
                break 'plan AdvanceStep::Waiting;
            };
            schedule_data.push((
                *id,
                u32::from(tx.scheduled_height()),
                tx.anchor_boundary().map(u32::from),
            ));
        }
        // THE OVERDUE SHIFT: ZIP 318's missed-schedule policy ("at most one overdue transfer is
        // released immediately; the rest are re-spread"). A candidate more than the
        // schedule-scaled tolerance past its scheduled height means the wallet slept through
        // part of the schedule, and serving the backlog as-is would cluster broadcasts the
        // drawn delays exist to spread apart. Shifting EVERY pending transaction forward by
        // the lag moves this candidate's schedule to exactly the served target — the next
        // planning pass names it again, still due, so it is released in this call — while the
        // rest re-spread behind it with their inter-broadcast gaps intact. The shift also
        // redraws the anchor boundary of every deferred not-yet-proved transfer against its new
        // schedule (see `shift_schedule`), so deferral never broadcasts an anchor whose age is
        // out of the ZIP 318 draw's distribution.
        //
        // Judged and sized at the ESTIMATE (`targets.effective()`), which is what lets a
        // wall-clock-woken wallet re-spread without syncing first; legal there because the shift
        // persists a SCHEDULE, never a verdict — it re-times service, records no determination,
        // and destroys no work (see the `DuenessTargets` classification). `Rebuild` is
        // deliberately not a trigger: the rebuild chains its own transfer's fresh schedule past
        // the end of the pending one, and sizing a shift by an expired candidate's stale height
        // would overstate it for everything still live.
        //
        // For a TRANSFER'S PROVE the overdueness clock starts at the height its proof could
        // first have been offered — `boundary + PROVABLE_ANCHOR_DEPTH + 1`, the anchor-depth
        // gate's own floor — when that is later than its scheduled height. A schedule that
        // placed a broadcast inside its own anchor's settling window (compressed test-network
        // intervals, or a boundary redrawn near the tip) makes the proof lag the schedule as a
        // matter of ENGINE TIMING, not wallet sleep, and re-spreading on it would shift the
        // whole plan — and redraw boundaries near the new schedule — every time the gate was
        // waited out, chasing its own tail. The shift's SIZE still moves the candidate's
        // schedule to the served target, exactly as for a genuinely slept-through window.
        if matches!(
            step,
            AdvanceStep::Prove { .. } | AdvanceStep::Broadcast { .. }
        ) {
            // For a batch, the MOST overdue member — the least `overdue_from` — is the trigger,
            // and the shift is sized by that member's schedule, exactly as when it is the sole
            // candidate.
            let most_overdue = schedule_data
                .iter()
                .map(|(_, scheduled, boundary)| {
                    let overdue_from = match (&step, boundary) {
                        (AdvanceStep::Prove { .. }, Some(boundary)) => {
                            (*scheduled).max(boundary + PROVABLE_ANCHOR_DEPTH + 1)
                        }
                        _ => *scheduled,
                    };
                    (overdue_from, *scheduled)
                })
                .min();
            if let Some((overdue_from, scheduled)) = most_overdue {
                let served = u32::from(targets.effective());
                if overdue_from.saturating_add(overdue_tolerance) < served {
                    state.shift_schedule(served - scheduled, rng);
                    dirty = true;
                    continue;
                }
            }
        }
        // VERIFY every candidate the step names. The single-candidate steps pay the same one
        // query as ever; a `Prove` batch pays one query per member in the call that serves it,
        // because every member is about to cost proving work.
        let mut kept: Vec<MigrationTransferId> = Vec::new();
        let mut deferred: Vec<MigrationTransferId> = Vec::new();
        let mut discoveries: Vec<(MigrationTransferId, StepSatisfiability)> = Vec::new();
        for (id, _, _) in &schedule_data {
            let Some(tx) = state.transactions().iter().find(|t| t.id() == *id) else {
                break 'plan AdvanceStep::Waiting;
            };
            let answer = store.check_step_satisfiability(tx, config.reorg_settle_depth())?;
            match answer {
                StepSatisfiability::Satisfiable { .. } => kept.push(*id),
                // Not an obstruction: the wallet cannot yet vouch for the inputs (their source
                // is unmined, or mined but unscanned). Take the candidate out of this call's
                // queues so the migration's other work still surfaces, and leave no mark — a
                // false mark would strand live value behind an observation only a reorg can
                // clear.
                StepSatisfiability::NotYetSatisfiable { .. } => deferred.push(*id),
                answer @ StepSatisfiability::Unsatisfiable { .. } => {
                    if records_a_determination(&answer) {
                        discoveries.push((*id, answer));
                    } else {
                        // `Expired`: never overrides the kernel, which derives expiry itself
                        // from the same `expiry_height`. The two can disagree only under
                        // caller/store height skew, and there the kernel's scanned target
                        // governs, so the member stands exactly as planned (for a transfer, the
                        // rebuild that is expiry's remedy).
                        kept.push(*id);
                    }
                }
            }
        }
        set_aside.extend(deferred.iter().copied());
        if !discoveries.is_empty() {
            // A DISCOVERY, so BROADEN, then record as ONE batch so the durable closure runs
            // once over the whole discovery, and plan again with the marks in force.
            broaden_after_discovery(store, state, &mut discoveries, config.reorg_settle_depth())?;
            state.record_satisfiability(targets, &discoveries);
            dirty = true;
            continue;
        }
        if deferred.is_empty() {
            // Every named candidate verified: the step stands exactly as planned.
            break step;
        }
        // Some members deferred, none died. The survivors are exactly what the next planning
        // pass would name again — the kernel is pure, no marks changed, and the deferrals are
        // now set aside — so a surviving `Prove` batch is served directly rather than re-buying
        // each member's oracle answer; a fully deferred step re-plans.
        if !kept.is_empty()
            && let AdvanceStep::Prove { transactions } = &step
        {
            break AdvanceStep::Prove {
                transactions: transactions
                    .iter()
                    .filter(|t| kept.contains(&t.id()))
                    .copied()
                    .collect(),
            };
        }
    };

    // A determination is durable by the time the step it produced is surfaced: the consumer acts
    // on that step and persists its own outcome, and must not be able to lose the marks this call
    // discovered along the way.
    if dirty {
        store.replace_migration(state)?;
    }
    let next = upcoming_after(state, &step, targets, &set_aside);
    Ok(Advance { step, next })
}

/// The OUTLOOK behind [`Advance::next`]: the subsequent step's kind and earliest serviceable
/// height, computed on the state as it will stand once `step` is executed and recorded.
///
/// The hypothetical is applied to a CLONE of the state — a `Prove` completes to `Proved`, a
/// `Broadcast` is recorded, `Waiting` changes nothing — and the kernel's
/// [`upcoming_step`](MigrationState::upcoming_step) is asked of the result, with this call's
/// `set_aside` carried through so a candidate deferred as "not yet satisfiable" (chain-gated, not
/// height-gated) cannot resurface as a schedulable outlook the drive loop just declined to
/// serve. The steps whose execution DECIDES what comes next carry no outlook at all, per
/// [`Advance::next`]: a `Rebuild` draws its transfer's fresh schedule at rebuild time, a
/// `Replan` supersedes the plan, a `Reevaluate` re-decides it, and after `Complete` nothing
/// follows. The clone is the cost of asking "and then?" without disturbing the state the caller
/// holds; it is paid only when a step is actually surfaced, never per transaction.
fn upcoming_after(
    state: &MigrationState,
    step: &AdvanceStep,
    targets: DuenessTargets,
    set_aside: &[MigrationTransferId],
) -> Option<(BlockHeight, StepKind)> {
    match step {
        AdvanceStep::Complete
        | AdvanceStep::Replan
        | AdvanceStep::Reevaluate
        | AdvanceStep::Rebuild { .. } => None,
        AdvanceStep::Waiting => state.upcoming_step(targets, set_aside),
        AdvanceStep::Prove { transactions } => {
            let mut post = state.clone();
            for t in post
                .transactions
                .iter_mut()
                .filter(|t| transactions.iter().any(|pt| pt.id() == t.id))
            {
                t.state = MigrationTxState::Proved;
            }
            post.upcoming_step(targets, set_aside)
        }
        AdvanceStep::Broadcast { id } => {
            let mut post = state.clone();
            post.mark_broadcast(*id);
            post.upcoming_step(targets, set_aside)
        }
    }
}

/// Whether a satisfiability answer is a DISCOVERY for [`advance_migration`] to record and broaden
/// on: an obstruction whose cause marks ([`UnsatisfiableCause::marks`], the single definition of
/// that decision). The satisfiable and not-yet answers are not determinations at all.
fn records_a_determination(answer: &StepSatisfiability) -> bool {
    matches!(answer, StepSatisfiability::Unsatisfiable { cause, .. } if cause.marks())
}

/// The fully-scanned height a satisfiability answer rests on, whichever answer it is: the height
/// that decides whether the answer is ABOUT the chain state a question was raised at.
fn answer_as_of_height(answer: &StepSatisfiability) -> BlockHeight {
    match answer {
        StepSatisfiability::Satisfiable { as_of_height }
        | StepSatisfiability::NotYetSatisfiable { as_of_height }
        | StepSatisfiability::Unsatisfiable { as_of_height, .. } => *as_of_height,
    }
}

/// Grows `batch` — the determinations [`advance_migration`] has already discovered this call —
/// with every OTHER determination the store will report right now, so a whole discovery is
/// assessed at once.
///
/// What killed one transaction is a fact about the migration's ENVIRONMENT, not about that
/// transaction alone: the ordinary cause is a wallet spend consuming notes the migration had
/// allocated, which typically kills several transfers together. Finding the rest of the damage in
/// the same call is what lets the replan threshold trip immediately rather than one transfer at a
/// time over the weeks a privacy-preserving broadcast schedule spans.
///
/// Every PENDING transaction whose dependencies have mined is checked, and nothing else: a
/// transaction already in `batch` has been answered, mined ones are final, in-flight ones belong
/// to the drive API's own in-flight sweep, already-marked ones would learn nothing, and one whose
/// dependencies are still unmined could only answer "not yet" (its death, if any, arrives through
/// the durable dependency closure).
fn broaden_after_discovery<St: PoolMigrationRead>(
    store: &St,
    state: &MigrationState,
    batch: &mut Vec<(MigrationTransferId, StepSatisfiability)>,
    settle: ReorgSettleDepth,
) -> Result<(), St::Error> {
    for tx in state.transactions() {
        // Unanswered this call, pending, unmarked, and with its dependencies mined: exactly the
        // transactions this sweep is about.
        if !batch.iter().any(|(id, _)| *id == tx.id())
            && !matches!(
                tx.state(),
                MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
            )
            && tx.unsatisfiable_at().is_none()
            && state.deps_mined(tx.depends_on())
        {
            let answer = store.check_step_satisfiability(tx, settle)?;
            if records_a_determination(&answer) {
                batch.push((tx.id(), answer));
            }
        }
    }
    Ok(())
}

/// The drive API's tests, over a minimal in-crate store with a configurable answer set: what
/// [`advance_migration`] surfaces, what it records, how much it asks, and what it persists.
#[cfg(test)]
mod advance_tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::Cell;
    use zcash_protocol::{TxId, value::Zatoshis};

    use crate::denomination::DenominationPlan;
    use crate::engine::{MigrationStatus, MigrationTransaction, MigrationTxKind};
    use crate::preparation::PreparationPlan;
    use crate::state::ProveTarget;

    /// A store that answers satisfiability from a fixed table — anything absent is satisfiable at
    /// `as_of_height`, the healthy default — and counts what the drive loop asks of it.
    struct TestStore {
        stored: Option<MigrationState>,
        satisfiability: BTreeMap<MigrationTransferId, StepSatisfiability>,
        /// The transactions the wallet's scan has seen mine, standing in for the wallet's
        /// `transactions` table. Empty is the healthy in-flight default: nothing mined yet.
        mined: BTreeMap<TxId, BlockHeight>,
        as_of_height: BlockHeight,
        queries: Cell<usize>,
        /// How many times the mining lookup has been asked, separately from `queries`, so a test
        /// can pin which of the sweep's two questions was paid for.
        mined_queries: Cell<usize>,
        replaced: Cell<usize>,
    }

    impl TestStore {
        fn new(
            as_of_height: u32,
            answers: impl IntoIterator<Item = (MigrationTransferId, StepSatisfiability)>,
        ) -> Self {
            TestStore {
                stored: None,
                satisfiability: answers.into_iter().collect(),
                mined: BTreeMap::new(),
                as_of_height: BlockHeight::from_u32(as_of_height),
                queries: Cell::new(0),
                mined_queries: Cell::new(0),
                replaced: Cell::new(0),
            }
        }

        /// Replace one transaction's answer, standing in for the wallet's view changing between
        /// calls (a dependency scanned, a reorg settled).
        fn set_answer(&mut self, id: MigrationTransferId, answer: StepSatisfiability) {
            self.satisfiability.insert(id, answer);
        }

        /// Record that the wallet's scan has seen `txid` mined at `height`, standing in for the
        /// scan reaching the block that included it.
        fn set_mined(&mut self, txid: TxId, height: u32) {
            self.mined.insert(txid, BlockHeight::from_u32(height));
        }
    }

    impl PoolMigrationRead for TestStore {
        type Error = core::convert::Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }

        fn check_step_satisfiability(
            &self,
            tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            self.queries.set(self.queries.get() + 1);
            Ok(self.satisfiability.get(&tx.id()).cloned().unwrap_or(
                StepSatisfiability::Satisfiable {
                    as_of_height: self.as_of_height,
                },
            ))
        }

        fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
            self.mined_queries.set(self.mined_queries.get() + 1);
            Ok(self.mined.get(&txid).copied())
        }
    }

    impl PoolMigrationWrite for TestStore {
        fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.replaced.set(self.replaced.get() + 1);
            self.stored = Some(state.clone());
            Ok(())
        }

        /// The contract's no-wallet-tables form: apply the proof and persist the state alone.
        fn store_proved_transaction(
            &mut self,
            state: &mut MigrationState,
            proven: crate::engine::ProvedTransaction,
        ) -> Result<(), Self::Error> {
            proven.apply(state);
            self.replace_migration(state)
        }

        fn update_transaction(
            &mut self,
            id: MigrationTransferId,
            state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            if let Some(stored) = &mut self.stored
                && let Some(tx) = stored.transactions.iter_mut().find(|t| t.id == id)
            {
                tx.state = state;
            }
            Ok(())
        }
    }

    // The state constructors mirror `state.rs`'s test helpers, so a drive-loop test and a kernel
    // test describe the same migration the same way.

    fn tx(id: u32, kind: MigrationTxKind, state: MigrationTxState) -> MigrationTransaction {
        // The row's id, and the copy any lifecycle state carries, are one value by construction:
        // production derives both from the built PCZT, so a fixture that let them differ would be
        // describing a state the engine cannot produce.
        let txid = TxId::from_bytes([id as u8; 32]);
        let state = match state {
            MigrationTxState::Broadcast { .. } => MigrationTxState::Broadcast { txid },
            MigrationTxState::Mined { height, .. } => MigrationTxState::Mined { txid, height },
            other => other,
        };
        MigrationTransaction {
            id: MigrationTransferId(id),
            kind,
            pczt: Vec::new(),
            depends_on: Vec::new(),
            scheduled_height: BlockHeight::from_u32(0),
            expiry_height: BlockHeight::from_u32(0),
            anchor_boundary: None,
            txid,
            state,
            lock_owner: None,
            unsatisfiable: None,
            spend_nullifiers: Vec::new(),
            broadcast_failure_at: None,
        }
    }

    fn prep(layer: usize, index: usize) -> MigrationTxKind {
        MigrationTxKind::Preparation { layer, index }
    }

    fn transfer(crossing: usize) -> MigrationTxKind {
        MigrationTxKind::Transfer { crossing }
    }

    // One member of an expected `Prove` batch.
    fn pt(id: u32, kind: MigrationTxKind) -> ProveTarget {
        ProveTarget {
            id: MigrationTransferId(id),
            kind,
        }
    }

    fn mined(height: u32) -> MigrationTxState {
        MigrationTxState::Mined {
            txid: TxId::from_bytes([0; 32]),
            height: BlockHeight::from_u32(height),
        }
    }

    /// Broadcast. The txid is a placeholder: `tx` replaces it with the row's own id, so a
    /// fixture never states one that production could not have produced.
    fn broadcast() -> MigrationTxState {
        MigrationTxState::Broadcast {
            txid: TxId::from_bytes([0; 32]),
        }
    }

    /// A transfer with the given anchor boundary and scheduled broadcast height, in the given
    /// lifecycle state (never expiring, like `tx`).
    fn scheduled_transfer(
        id: u32,
        crossing: usize,
        anchor: u32,
        broadcast: u32,
        state: MigrationTxState,
    ) -> MigrationTransaction {
        let mut t = tx(id, transfer(crossing), state);
        t.anchor_boundary = Some(BlockHeight::from_u32(anchor));
        t.scheduled_height = BlockHeight::from_u32(broadcast);
        t
    }

    /// A state whose denomination plan carries the given crossing values, so each transfer's
    /// contribution to the replan threshold is exactly the value at its crossing index.
    fn state_with_crossings(
        crossings: &[u64],
        transactions: Vec<MigrationTransaction>,
    ) -> MigrationState {
        let zats = |v: u64| Zatoshis::from_u64(v).expect("test values are valid");
        let total = zats(crossings.iter().sum());
        MigrationState {
            status: MigrationStatus::Committed,
            denominations: DenominationPlan::from_stored_parts(
                crossings.iter().copied().map(zats).collect(),
                zats(15_000),
                None,
                Zatoshis::ZERO,
                total,
                total,
            )
            .expect("a consistent stored plan reconstructs"),
            preparation: PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            anchor_bucket_interval: crate::scheduling::AnchorBucketInterval::ZIP_318,
            replan_threshold: ReplanThreshold::DEFAULT,
        }
    }

    fn spent(as_of_height: u32) -> StepSatisfiability {
        StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::InputsSpent {
                nullifiers: vec![[9; 32]],
            },
            as_of_height: BlockHeight::from_u32(as_of_height),
        }
    }

    fn config() -> AdvanceConfig {
        AdvanceConfig::new(ReorgSettleDepth::new(10))
    }

    /// A fresh seeded RNG per drive call; only the overdue shift's anchor redraw consumes it, so
    /// tests that never shift are unaffected by the draws.
    fn rng() -> rand_chacha::ChaCha8Rng {
        use rand_core::SeedableRng;
        rand_chacha::ChaCha8Rng::seed_from_u64(0xA5)
    }

    /// Which half of the store interface fails, for the error-propagation test.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure {
        /// The satisfiability oracle fails.
        Oracle,
        /// Persisting fails.
        Write,
    }

    /// A store whose failing half is chosen up front. `TestStore` is infallible, so error
    /// propagation needs a store that can actually fail.
    #[derive(Debug, PartialEq, Eq)]
    struct StoreFailed;

    struct FailingStore {
        stored: Option<MigrationState>,
        satisfiability: BTreeMap<MigrationTransferId, StepSatisfiability>,
        as_of_height: BlockHeight,
        fails: Failure,
        queries: Cell<usize>,
        replaced: Cell<usize>,
    }

    impl FailingStore {
        fn new(
            fails: Failure,
            as_of_height: u32,
            answers: impl IntoIterator<Item = (MigrationTransferId, StepSatisfiability)>,
        ) -> Self {
            FailingStore {
                stored: None,
                satisfiability: answers.into_iter().collect(),
                as_of_height: BlockHeight::from_u32(as_of_height),
                fails,
                queries: Cell::new(0),
                replaced: Cell::new(0),
            }
        }
    }

    impl PoolMigrationRead for FailingStore {
        type Error = StoreFailed;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }

        fn check_step_satisfiability(
            &self,
            tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            self.queries.set(self.queries.get() + 1);
            if self.fails == Failure::Oracle {
                return Err(StoreFailed);
            }
            Ok(self.satisfiability.get(&tx.id()).cloned().unwrap_or(
                StepSatisfiability::Satisfiable {
                    as_of_height: self.as_of_height,
                },
            ))
        }

        /// Never fails, and never reports anything mined: `Failure::Oracle` names the
        /// SATISFIABILITY oracle specifically, so an error-propagation test keeps exercising the
        /// path it was written for rather than short-circuiting in the mining lookup ahead of it.
        fn mined_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
            Ok(None)
        }
    }

    impl PoolMigrationWrite for FailingStore {
        fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.replaced.set(self.replaced.get() + 1);
            if self.fails == Failure::Write {
                return Err(StoreFailed);
            }
            self.stored = Some(state.clone());
            Ok(())
        }

        /// Fails exactly as `replace_migration` does: the proof is applied, and the write is
        /// subject to the configured failure.
        fn store_proved_transaction(
            &mut self,
            state: &mut MigrationState,
            proven: crate::engine::ProvedTransaction,
        ) -> Result<(), Self::Error> {
            proven.apply(state);
            self.replace_migration(state)
        }

        fn update_transaction(
            &mut self,
            _id: MigrationTransferId,
            _state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            Err(StoreFailed)
        }
    }

    /// The invariant the drive API exists for: a step is surfaced only after the store has
    /// vouched for it. The kernel plans A's due broadcast; the check discovers A's inputs spent,
    /// which broadens into a sweep that also finds C dead, and the call surfaces B's prove — never
    /// A's broadcast — with both discoveries recorded and persisted in ONE write. A's and C's
    /// value stays below the replan threshold, so the migration keeps draining.
    #[test]
    fn advance_never_surfaces_a_dead_candidate_and_broadens_on_discovery() {
        let mut state = state_with_crossings(
            &[5_000_000, 90_000_000, 5_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                // A: proved and due at the target height. Overdue by more than the tolerance, so
                // this call also shifts the schedule (and redraws B's and C's boundaries against
                // their shifted heights) before anything is verified.
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                // B and C: signed, boundaries settled, broadcasts still to come. Their schedules
                // sit close enough that even after the shift their (redrawn) boundaries remain
                // below the scanned tip, so B's prove is servable in this same call.
                scheduled_transfer(2, 1, 1440, 1_700, MigrationTxState::Signed),
                scheduled_transfer(3, 2, 1440, 1_700, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (MigrationTransferId(1), spent(1600)),
                (MigrationTransferId(3), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert!(
            matches!(&step, AdvanceStep::Prove { transactions } if *transactions == [pt(2, transfer(1))]),
            "the live transfer's prove is surfaced, not the dead transfer's broadcast: {step:?}"
        );
        let marked = BlockHeight::from_u32(1600);
        assert_eq!(
            state.transactions()[1].unsatisfiable_at(),
            Some(marked),
            "the dead candidate is marked at the answer's height"
        );
        assert_eq!(
            state.transactions()[3].unsatisfiable_at(),
            Some(marked),
            "the broaden sweep marks a transfer whose own broadcast is still to come"
        );
        assert_eq!(
            state.transactions()[2].unsatisfiable_at(),
            None,
            "the satisfiable transfer is untouched"
        );
        assert_eq!(
            store.replaced.get(),
            1,
            "one dirty write persisted the marks"
        );
        assert_eq!(
            store.stored.as_ref().expect("persisted").transactions()[3].unsatisfiable_at(),
            Some(marked),
            "the store holds the marks by the time the step is surfaced"
        );
    }

    /// Broadening is what makes the threshold trip promptly: the marks discovered in one call
    /// carry the unsatisfiable share past the committed threshold, so that SAME call re-plans and
    /// returns `Replan` rather than another step.
    #[test]
    fn advance_replan_when_threshold_crossed() {
        let mut state = state_with_crossings(
            &[30_000_000, 40_000_000, 30_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 1440, 90_000, MigrationTxState::Signed),
                scheduled_transfer(3, 2, 1440, 90_000, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (MigrationTransferId(1), spent(1600)),
                (MigrationTransferId(3), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Replan,
            "60% of the planned crossing value is unsatisfiable, past the 20% threshold"
        );
        assert!(state.replan_required());
        assert_eq!(store.replaced.get(), 1);
        let stored = store.stored.as_ref().expect("persisted");
        assert!(
            stored.transactions()[1].unsatisfiable_at().is_some()
                && stored.transactions()[3].unsatisfiable_at().is_some(),
            "the marks the replan decision rests on are durable before it is surfaced"
        );
    }

    /// A `NotYetSatisfiable` answer is a retry, not an obstruction: the candidate is set aside for
    /// the rest of the call — nothing marked — its sibling surfaces instead, and a FRESH call
    /// offers the deferred transaction again once the wallet can vouch for it.
    #[test]
    fn advance_not_yet_satisfiable_sets_aside_without_marking() {
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                // Due but within the overdue-shift tolerance of the target, so the schedule
                // holds and this test stays about the set-aside alone.
                scheduled_transfer(1, 0, 1440, 1590, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 1440, 1590, MigrationTxState::Proved),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [(
                MigrationTransferId(1),
                StepSatisfiability::NotYetSatisfiable {
                    as_of_height: BlockHeight::from_u32(1600),
                },
            )],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(2)
            },
            "the sibling's due broadcast surfaces while the lagging candidate waits"
        );
        assert!(
            state
                .transactions()
                .iter()
                .all(|t| t.unsatisfiable_at().is_none()),
            "a not-yet answer marks nothing"
        );
        assert_eq!(
            store.replaced.get(),
            0,
            "nothing was recorded, so nothing is written"
        );

        // The deferral was call-local: once the wallet can vouch for it, the next call offers the
        // same transaction again.
        store.set_answer(
            MigrationTransferId(1),
            StepSatisfiability::Satisfiable {
                as_of_height: BlockHeight::from_u32(1600),
            },
        );
        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();
        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "set_aside does not persist across calls"
        );
        assert_eq!(store.replaced.get(), 0);
    }

    /// The laziness profile a healthy migration pays: one query for the candidate the kernel
    /// names, no write at all — and, when nothing is actionable, not even that.
    #[test]
    fn advance_is_lazy_when_healthy() {
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                // Due within the overdue-shift tolerance: a healthy wallet woke on time (give or
                // take ordinary wake-up slop), so nothing reschedules and nothing is written.
                scheduled_transfer(1, 0, 1440, 1590, MigrationTxState::Proved),
            ],
        );
        let mut store = TestStore::new(1600, []);

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );
        assert_eq!(store.queries.get(), 1, "exactly the candidate is checked");
        assert_eq!(store.replaced.get(), 0, "a healthy call writes nothing");

        // Nothing in flight and nothing actionable — the transfer's boundary has yet to settle —
        // so there is nothing to check at all.
        let mut waiting = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1700, 90_000, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(1600, []);
        let step = advance_migration(
            &mut store,
            &mut waiting,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();
        assert_eq!(step, AdvanceStep::Waiting);
        assert_eq!(store.queries.get(), 0, "a waiting call asks nothing");
        assert_eq!(store.replaced.get(), 0);
    }

    /// The in-flight sweep is the only check a broadcast-but-unmined transaction ever gets, and
    /// BOTH of its marking causes are determinations. A settled reorg invalidates a broadcast
    /// preparation's anchor; its pending dependents die through the closure, carrying the
    /// migration past the threshold. A sibling in flight answering an INPUT-level cause is marked
    /// too: the mining question was asked of it first and the wallet has not seen it mine, so —
    /// both answers resting on one scanned view — the spender is some other transaction.
    #[test]
    fn advance_in_flight_anchor_invalidated_flows_to_replan() {
        let mut dependent_a = scheduled_transfer(1, 0, 1440, 90_000, MigrationTxState::Signed);
        dependent_a.depends_on = vec![MigrationTransferId(0)];
        let mut dependent_b = scheduled_transfer(2, 1, 1440, 90_000, MigrationTxState::Signed);
        dependent_b.depends_on = vec![MigrationTransferId(0)];
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000, 10_000_000],
            vec![
                tx(0, prep(0, 0), broadcast()),
                dependent_a,
                dependent_b,
                // In flight, independent, and answering an input-level cause: a FOREIGN
                // spend, since the mining lookup declines it in the same pass.
                scheduled_transfer(3, 2, 1440, 1500, broadcast()),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (
                    MigrationTransferId(0),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::AnchorInvalidated,
                        as_of_height: BlockHeight::from_u32(1600),
                    },
                ),
                (MigrationTransferId(3), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Replan,
            "the stranded dependents carry the migration past the threshold"
        );
        let marked = BlockHeight::from_u32(1600);
        assert_eq!(state.transactions()[0].unsatisfiable_at(), Some(marked));
        assert_eq!(
            state.transactions()[1].unsatisfiable_at(),
            Some(marked),
            "a dependent of the dead preparation inherits its stamp"
        );
        assert_eq!(state.transactions()[2].unsatisfiable_at(), Some(marked));
        assert_eq!(
            state.transactions()[3].unsatisfiable_at(),
            Some(marked),
            "a foreign spend of an in-flight transaction's inputs is a determination"
        );
        assert_eq!(
            state.transactions()[3].unsatisfiable_kind(),
            Some(UnsatisfiableKind::InputsSpent),
            "and it is recorded under the cause that produced it"
        );
        assert_eq!(
            store.queries.get(),
            2,
            "one query per in-flight transaction"
        );
        assert_eq!(store.replaced.get(), 1);
        assert_eq!(
            store.stored.as_ref().expect("persisted").transactions()[1].unsatisfiable_at(),
            Some(marked)
        );
    }

    /// MINING IS DERIVED, NOT REPORTED. The consumer records only that it broadcast; the wallet's
    /// scan then sees the transaction, and the drive call promotes it — unblocking the dependent
    /// the preparation funds, and persisting the promotion before returning. Nothing here calls
    /// `mark_mined`.
    #[test]
    fn advance_promotes_a_mined_transaction_from_the_wallets_own_scan() {
        let dependent = {
            let mut t = scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved);
            t.depends_on = vec![MigrationTransferId(0)];
            t
        };
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![tx(0, prep(0, 0), broadcast()), dependent],
        );
        let mut store = TestStore::new(1600, []);
        store.set_mined(TxId::from_bytes([0; 32]), 1550);

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            state.transactions()[0].state(),
            MigrationTxState::Mined {
                txid: TxId::from_bytes([0; 32]),
                height: BlockHeight::from_u32(1550),
            },
            "the in-flight preparation is promoted from the scan, with no consumer involvement"
        );
        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "the promotion is what makes the dependent's broadcast actionable in this same call"
        );
        assert_eq!(
            store.replaced.get(),
            1,
            "a promotion is a determination, and is durable before the step it enables is surfaced"
        );
        assert_eq!(
            store.stored.as_ref().expect("persisted").transactions()[0].state(),
            MigrationTxState::Mined {
                txid: TxId::from_bytes([0; 32]),
                height: BlockHeight::from_u32(1550),
            },
        );
    }

    /// Inclusion outranks every standing judgment, and the sweep's ORDER is what makes that hold
    /// without a special case: a transaction carrying an open broadcast-failure report that the
    /// scan has now seen mine is promoted — discharging the report — rather than holding the whole
    /// migration at `Reevaluate` over a rejection the chain has answered.
    #[test]
    fn advance_promotion_discharges_a_broadcast_failure_report() {
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
            ],
        );
        // Rejected at a tip the wallet has not reached: on its own this holds at `Reevaluate`.
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1900));
        state.mark_broadcast(MigrationTransferId(1));
        let mut store = TestStore::new(1600, []);
        store.set_mined(TxId::from_bytes([1; 32]), 1590);

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Complete,
            "every transaction is mined: the rejection is moot, not a reason to stall"
        );
        assert_eq!(
            state.transactions()[1].broadcast_failure_at(),
            None,
            "promotion discharges the report on its way through"
        );
    }

    /// The sweep's cost: a transaction the scan has seen mine is settled by the mining lookup
    /// alone and never reaches the satisfiability oracle, so promoting costs strictly less than
    /// the sweep it replaces work in — while an in-flight sibling still pays for both questions.
    #[test]
    fn advance_mined_transaction_skips_the_satisfiability_query() {
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), broadcast()),
                scheduled_transfer(1, 0, 1440, 1500, broadcast()),
            ],
        );
        let mut store = TestStore::new(1600, []);
        store.set_mined(TxId::from_bytes([0; 32]), 1550);

        advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails");

        assert_eq!(
            store.mined_queries.get(),
            2,
            "both in-flight transactions are asked whether they mined"
        );
        assert_eq!(
            store.queries.get(),
            1,
            "only the one still in flight pays for a satisfiability answer"
        );
    }

    /// An `Expired` answer confirms a derivation the kernel already makes from the same
    /// `expiry_height`, so it never overrides the planned step: the rebuild the kernel surfaced —
    /// expiry's remedy — stands, and nothing is marked (a mark would make the transfer dead
    /// rather than rebuildable).
    #[test]
    fn advance_expired_answer_never_overrides_the_kernel() {
        let mut expired = scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Signed);
        expired.expiry_height = BlockHeight::from_u32(1550);
        let mut state =
            state_with_crossings(&[100_000_000], vec![tx(0, prep(0, 0), mined(10)), expired]);
        let mut store = TestStore::new(
            1600,
            [(
                MigrationTransferId(1),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::Expired,
                    as_of_height: BlockHeight::from_u32(1600),
                },
            )],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            },
            "the kernel's rebuild stands"
        );
        assert_eq!(
            state.transactions()[1].unsatisfiable_at(),
            None,
            "expiry is derived, never recorded"
        );
        assert_eq!(store.queries.get(), 1);
        assert_eq!(
            store.replaced.get(),
            0,
            "nothing was recorded, so nothing is written"
        );
    }

    /// The broaden sweep is scoped to transactions the oracle can actually answer about: one
    /// whose dependencies have yet to mine is never asked (it could only answer "not yet", and
    /// its death, if any, arrives through the closure), while its unblocked sibling is.
    #[test]
    fn advance_broaden_sweep_skips_a_transaction_behind_an_unmined_dependency() {
        // A transfer funded by a preparation layer that has not been broadcast yet, alongside one
        // whose funding preparation is already mined.
        let mut behind_unmined_dep =
            scheduled_transfer(3, 1, 1440, 90_000, MigrationTxState::Signed);
        behind_unmined_dep.depends_on = vec![MigrationTransferId(2)];
        let mut unblocked = scheduled_transfer(4, 2, 1440, 90_000, MigrationTxState::Signed);
        unblocked.depends_on = vec![MigrationTransferId(0)];
        let mut state = state_with_crossings(
            &[5_000_000, 90_000_000, 5_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                // The candidate: proved, due, and dead.
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                // A second preparation layer, not yet due, so not itself actionable.
                {
                    let mut t = tx(2, prep(1, 0), MigrationTxState::Signed);
                    t.scheduled_height = BlockHeight::from_u32(90_000);
                    t
                },
                behind_unmined_dep,
                unblocked,
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (MigrationTransferId(1), spent(1600)),
                // Answered only if asked — and the sweep must not ask.
                (MigrationTransferId(3), spent(1600)),
                (MigrationTransferId(4), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1601)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Waiting,
            "the live work is all undue, and the marked share stays below the threshold"
        );
        assert_eq!(
            store.queries.get(),
            3,
            "the candidate, then the two transactions the sweep can answer about"
        );
        assert_eq!(
            state.transactions()[3].unsatisfiable_at(),
            None,
            "a transaction behind an unmined dependency is never asked, so never marked"
        );
        assert_eq!(
            state.transactions()[4].unsatisfiable_at(),
            Some(BlockHeight::from_u32(1600)),
            "its unblocked sibling is swept and marked"
        );
        assert_eq!(store.replaced.get(), 1);
    }

    /// A store error propagates, and the call's contract on the way out: nothing is left half
    /// written. An oracle failure records nothing and writes nothing; a WRITE failure surfaces the
    /// error with the discovery live only in the in-memory state, which is exactly why the caller
    /// must re-read after an error rather than trusting what it holds.
    #[test]
    fn advance_store_errors_propagate_without_recording() {
        let migration = || {
            state_with_crossings(
                &[100_000_000],
                vec![
                    tx(0, prep(0, 0), mined(10)),
                    scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                ],
            )
        };

        // The oracle fails on the candidate check.
        let mut state = migration();
        let mut store = FailingStore::new(Failure::Oracle, 1600, []);
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1601)),
                &config(),
                &mut rng()
            ),
            Err(StoreFailed)
        );
        assert!(
            state
                .transactions()
                .iter()
                .all(|t| t.unsatisfiable_at().is_none()),
            "an unanswered check determines nothing"
        );
        assert_eq!(
            store.replaced.get(),
            0,
            "and nothing is written on the way out"
        );

        // The oracle answers — the candidate is dead, and it is the only checkable transaction —
        // but persisting the discovery fails.
        let mut state = migration();
        let mut store = FailingStore::new(
            Failure::Write,
            1600,
            [(MigrationTransferId(1), spent(1600))],
        );
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1601)),
                &config(),
                &mut rng()
            ),
            Err(StoreFailed)
        );
        assert_eq!(
            store.queries.get(),
            1,
            "the candidate, and nothing to broaden to"
        );
        assert_eq!(store.replaced.get(), 1, "the write was attempted");
        assert!(
            state.transactions()[1].unsatisfiable_at().is_some(),
            "the discovery is in the in-memory state"
        );
        assert!(
            store.stored.is_none(),
            "but not in the store: after an error the caller must re-read, not trust this state"
        );
    }

    /// A rejected broadcast whose explanation lies above the wallet's scanned region: the call
    /// surfaces `Reevaluate` and nothing else, records nothing, and does not fall through to the
    /// migration's other due work — a rejection means another observer saw chain state this
    /// wallet has not, which is a fact about the whole view rather than one transaction.
    #[test]
    fn advance_holds_at_reevaluate_until_the_oracle_reaches_the_reported_tip() {
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 1440, 1500, MigrationTxState::Proved),
            ],
        );
        // The node that refused the broadcast reported a tip 100 blocks above the wallet's
        // fully-scanned height.
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1700));
        let mut store = TestStore::new(1600, []);

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1601)),
                &config(),
                &mut rng()
            )
            .expect("the store never fails")
            .step()
            .clone(),
            AdvanceStep::Reevaluate,
            "the sibling's due broadcast waits behind the unanswered rejection",
        );
        assert_eq!(store.queries.get(), 1, "one query, for the reported row");
        assert_eq!(store.replaced.get(), 0, "nothing was determined to persist");
        assert_eq!(
            state.transactions()[1].broadcast_failure_at(),
            Some(BlockHeight::from_u32(1700)),
            "the report stands until it can be answered",
        );
        assert!(
            state
                .transactions()
                .iter()
                .all(|t| t.unsatisfiable_at().is_none()),
            "testimony never marks",
        );
        assert_eq!(
            state.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(1601)))[1]
                .blocked_on(),
            Some(crate::state::Blocker::AwaitingReevaluation),
        );

        // The wallet syncs past the reported tip and the same answer now decides the question:
        // nothing obstructs, so the rejection was transient, the report is discharged, and the
        // broadcast is offered again IN THIS CALL.
        store.as_of_height = BlockHeight::from_u32(1700);
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1701)),
                &config(),
                &mut rng()
            )
            .expect("the store never fails")
            .step()
            .clone(),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
        );
        assert_eq!(state.transactions()[1].broadcast_failure_at(), None);
        assert_eq!(
            store
                .stored
                .as_ref()
                .expect("the discharge was persisted")
                .transactions()[1]
                .broadcast_failure_at(),
            None,
            "the discharge is durable before the step is surfaced",
        );
    }

    /// The other adjudication: once the wallet has scanned to the reported tip it finds the spend
    /// behind the rejection, and that becomes an ORDINARY evidence-backed mark — closure,
    /// threshold, and `Replan` exactly as any other discovery. The report is discharged either
    /// way; the mark is what stands afterwards.
    #[test]
    fn advance_adjudicates_a_reported_broadcast_into_marks_and_a_replan() {
        let mut prep_layer_1 = tx(1, prep(1, 0), MigrationTxState::Proved);
        prep_layer_1.depends_on = vec![MigrationTransferId(0)];
        prep_layer_1.scheduled_height = BlockHeight::from_u32(1500);
        let mut first = scheduled_transfer(2, 0, 1440, 90_000, MigrationTxState::Signed);
        first.depends_on = vec![MigrationTransferId(1)];
        let mut second = scheduled_transfer(3, 1, 1440, 90_000, MigrationTxState::Signed);
        second.depends_on = vec![MigrationTransferId(1)];

        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![tx(0, prep(0, 0), mined(10)), prep_layer_1, first, second],
        );
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1700));

        // Another wallet on the same seed spent the notes this preparation was built over, and
        // the wallet has now scanned the block that did it.
        let mut store = TestStore::new(1700, [(MigrationTransferId(1), spent(1700))]);
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1701)),
                &config(),
                &mut rng()
            )
            .expect("the store never fails")
            .step()
            .clone(),
            AdvanceStep::Replan,
        );

        let marked = BlockHeight::from_u32(1700);
        assert_eq!(
            state.transactions()[1].unsatisfiable(),
            Some((marked, UnsatisfiableKind::InputsSpent)),
            "the rejection is adjudicated into an evidence-backed mark at the answer's height",
        );
        assert_eq!(
            state.transactions()[1].broadcast_failure_at(),
            None,
            "and the testimony it rested on is discharged",
        );
        for stranded in [2, 3] {
            assert_eq!(
                state.transactions()[stranded].unsatisfiable(),
                Some((marked, UnsatisfiableKind::Inherited)),
                "the durable closure strands the crossings behind the dead preparation",
            );
        }
        assert!(state.replan_required());
        assert_eq!(
            store.replaced.get(),
            1,
            "the marks and the discharge persist in one write"
        );
        let stored = store.stored.as_ref().expect("persisted");
        assert_eq!(
            stored.transactions()[1].unsatisfiable(),
            Some((marked, UnsatisfiableKind::InputsSpent))
        );
        assert_eq!(stored.transactions()[1].broadcast_failure_at(), None);
    }

    /// A TERMINAL migration is never driven further, so a report left standing on it neither
    /// costs a query nor holds the driver at `Reevaluate`: there is no broadcast to withhold.
    #[test]
    fn advance_ignores_a_report_on_a_terminal_migration() {
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
            ],
        );
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1700));
        state.mark_superseded();
        let mut store = TestStore::new(1600, []);

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1601)),
                &config(),
                &mut rng()
            )
            .expect("the store never fails")
            .step()
            .clone(),
            AdvanceStep::Complete,
        );
        assert_eq!(store.queries.get(), 0);
        assert_eq!(store.replaced.get(), 0);
    }

    /// `Reevaluate` is a RETURN like any other, so the determinations made on the way to it are
    /// durable before it is surfaced. Here the in-flight sweep marks a broadcast crossing whose
    /// anchor a settled reorg displaced, while a second crossing's rejection cannot yet be
    /// answered: the call ends at `Reevaluate`, and the mark is in the STORE, not only in the
    /// returned state — a consumer that syncs, restarts, and drives again must not have to
    /// rediscover it.
    #[test]
    fn advance_persists_sweep_marks_before_returning_reevaluate() {
        let mut in_flight = scheduled_transfer(
            1,
            0,
            1440,
            1500,
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([4; 32]),
            },
        );
        in_flight.depends_on = vec![MigrationTransferId(0)];
        let mut reported = scheduled_transfer(2, 1, 1440, 1500, MigrationTxState::Proved);
        reported.depends_on = vec![MigrationTransferId(0)];

        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![tx(0, prep(0, 0), mined(10)), in_flight, reported],
        );
        state.report_broadcast_failure(MigrationTransferId(2), BlockHeight::from_u32(1700));

        let mut store = TestStore::new(
            1600,
            [(
                MigrationTransferId(1),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::AnchorInvalidated,
                    as_of_height: BlockHeight::from_u32(1600),
                },
            )],
        );

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1601)),
                &config(),
                &mut rng()
            )
            .expect("the store never fails")
            .step()
            .clone(),
            AdvanceStep::Reevaluate,
        );
        let marked = BlockHeight::from_u32(1600);
        assert_eq!(
            state.transactions()[1].unsatisfiable(),
            Some((marked, UnsatisfiableKind::AnchorInvalidated)),
        );
        assert_eq!(
            store.replaced.get(),
            1,
            "one write carries every determination this call made"
        );
        assert_eq!(
            store
                .stored
                .as_ref()
                .expect("the sweep's mark was persisted before the step was surfaced")
                .transactions()[1]
                .unsatisfiable(),
            Some((marked, UnsatisfiableKind::AnchorInvalidated)),
        );
    }

    /// The same durability, for the adjudication's own half: with two rejections outstanding and
    /// only one of them answerable, the answerable one is discharged and that discharge is
    /// PERSISTED even though the call still ends at `Reevaluate`. Losing it would leave the
    /// crossing withheld from the broadcast queue on a question already settled.
    #[test]
    fn advance_persists_a_discharged_report_before_returning_reevaluate() {
        let mut answerable = scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved);
        answerable.depends_on = vec![MigrationTransferId(0)];
        let mut pending = scheduled_transfer(2, 1, 1440, 1500, MigrationTxState::Proved);
        pending.depends_on = vec![MigrationTransferId(0)];

        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![tx(0, prep(0, 0), mined(10)), answerable, pending],
        );
        // The first rejection came from a node whose tip the wallet has since scanned past; the
        // second from one reporting a tip it has not reached.
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1500));
        state.report_broadcast_failure(MigrationTransferId(2), BlockHeight::from_u32(1700));
        let mut store = TestStore::new(1600, []);

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1601)),
                &config(),
                &mut rng()
            )
            .expect("the store never fails")
            .step()
            .clone(),
            AdvanceStep::Reevaluate,
            "one unanswerable rejection still holds the whole loop",
        );
        assert_eq!(state.transactions()[1].broadcast_failure_at(), None);
        assert_eq!(
            state.transactions()[2].broadcast_failure_at(),
            Some(BlockHeight::from_u32(1700)),
        );
        assert_eq!(store.replaced.get(), 1);
        let stored = store
            .stored
            .as_ref()
            .expect("the discharge was persisted before the step was surfaced");
        assert_eq!(
            stored.transactions()[1].broadcast_failure_at(),
            None,
            "the settled question does not withhold the crossing again after a restart",
        );
        assert_eq!(
            stored.transactions()[2].broadcast_failure_at(),
            Some(BlockHeight::from_u32(1700)),
            "and the open one still stands",
        );
    }

    /// The dual-target contract at the DRIVE level: a wallet woken by wall-clock estimate, its
    /// scan a couple of hundred blocks behind, submits the transfer whose schedule the estimate
    /// says has arrived — and is refused the one whose expiry the estimate says has passed. The
    /// refusal records NOTHING (the whole point of the scanned anchoring: only a reorg truncation
    /// could withdraw a mark, and an estimate names no chain state to truncate), so the store is
    /// never written to and the transfer is offered again the moment its schedule and its expiry
    /// are both judged the same way.
    #[test]
    fn advance_serves_the_schedule_by_estimate_and_withholds_a_doomed_broadcast() {
        let mut doomed = scheduled_transfer(1, 0, 1440, 1690, MigrationTxState::Proved);
        doomed.expiry_height = BlockHeight::from_u32(1695);
        doomed.depends_on = vec![MigrationTransferId(0)];
        let mut live = scheduled_transfer(2, 1, 1440, 1690, MigrationTxState::Proved);
        live.expiry_height = BlockHeight::from_u32(2000);
        live.depends_on = vec![MigrationTransferId(0)];

        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![tx(0, prep(0, 0), mined(10)), doomed, live],
        );
        let mut store = TestStore::new(1501, []);
        // Scanned to 1500 (target 1501), estimated tip 1700 (target 1701): both transfers are due
        // by the estimate — within the overdue-shift tolerance, so the schedule holds — and
        // neither is due by the scan, and the first one's expiry lies in the doomed window
        // `1501 <= 1695 < 1701`.
        let targets = DuenessTargets::new(BlockHeight::from_u32(1501), BlockHeight::from_u32(1701));

        assert_eq!(
            advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
                .expect("the store never fails")
                .step()
                .clone(),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(2)
            },
            "the live transfer is served by the estimate; the doomed one is withheld"
        );
        assert_eq!(
            state.transactions()[1].unsatisfiable(),
            None,
            "the withhold is protective, never a determination"
        );
        assert_eq!(
            store.replaced.get(),
            0,
            "and so there is nothing to persist"
        );

        // Withheld, not condemned: an estimate that no longer overshoots the expiry — the wallet
        // synced, and the transfer had not lapsed after all — offers the same broadcast.
        state.mark_broadcast(MigrationTransferId(2));
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                DuenessTargets::at(BlockHeight::from_u32(1691)),
                &config(),
                &mut rng(),
            )
            .expect("the store never fails")
            .step()
            .clone(),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
        );
    }

    /// A step overdue by more than the schedule-scaled tolerance ([`overdue_shift_tolerance`])
    /// shifts the WHOLE pending schedule
    /// forward by the overdue amount before it is surfaced: the trigger comes due exactly at the
    /// served target — ZIP 318's one immediately-released overdue transfer — every other pending
    /// transaction keeps its drawn gap behind it, served schedules stay put, and the shifted
    /// state is persisted by the time the step is returned. Judged at the ESTIMATE, so the
    /// re-spread happens in a broadcast-only session, without syncing first.
    #[test]
    fn overdue_step_shifts_the_pending_schedule() {
        let mut state = state_with_crossings(
            &[40_000_000, 30_000_000, 30_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 1_000, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 720, 1_066, MigrationTxState::Signed),
                scheduled_transfer(3, 2, 720, 900, broadcast()),
            ],
        );
        let mut store = TestStore::new(1_010, []);

        // Scanned to 1_010 (target 1_011); the wall-clock estimate has the tip at 2_000 (target
        // 2_001), so the named broadcast is 1_001 blocks overdue.
        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::new(BlockHeight::from_u32(1_011), BlockHeight::from_u32(2_001)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "the overdue transfer is still released in this call"
        );
        let scheduled: Vec<u32> = state
            .transactions()
            .iter()
            .map(|t| u32::from(t.scheduled_height()))
            .collect();
        assert_eq!(
            scheduled,
            vec![0, 2_001, 2_067, 900],
            "pending schedules shift by the overdue amount (gaps intact); served ones stay put"
        );
        assert_eq!(store.replaced.get(), 1, "the shifted schedule is persisted");
        let stored: Vec<u32> = store
            .stored
            .as_ref()
            .expect("persisted")
            .transactions()
            .iter()
            .map(|t| u32::from(t.scheduled_height()))
            .collect();
        assert_eq!(
            stored, scheduled,
            "the store agrees by the time the step is surfaced"
        );

        // The anchor consequences of the deferral. The PROVED trigger keeps the boundary its
        // proof was built against; the deferred SIGNED transfer's boundary is redrawn
        // in-distribution against its shifted schedule — within `ANCHOR_AGE_CAP` (4) buckets
        // strictly below the most recent grid boundary at the new height — because keeping the
        // old one would broadcast an anchor age no honest draw produces.
        assert_eq!(
            state.transactions()[1].anchor_boundary(),
            Some(BlockHeight::from_u32(720)),
            "the proved transfer's proof pins its anchor"
        );
        let new_schedule = u32::from(state.transactions()[2].scheduled_height());
        let most_recent = new_schedule - (new_schedule % 144);
        let boundary = u32::from(
            state.transactions()[2]
                .anchor_boundary()
                .expect("a transfer keeps carrying a boundary"),
        );
        assert_eq!(boundary % 144, 0, "the redrawn boundary is on the grid");
        assert!(
            boundary >= most_recent - 4 * 144 && boundary < most_recent,
            "boundary {boundary} is in-distribution for schedule {new_schedule}"
        );
    }

    /// The tolerance boundary: a step at most [`overdue_shift_tolerance`] blocks past its
    /// schedule is ordinary wake-up slop, served as scheduled with nothing rescheduled or
    /// written; one block further and the whole pending schedule moves. The fixture's committed
    /// interval is the ZIP 318 one, so the tolerance under test is the mainnet value the drive
    /// call derives from the persisted state.
    #[test]
    fn overdue_shift_tolerance_boundary() {
        // A quarter of the ZIP 318 mean of 66: the value `advance_migration` derives from the
        // fixture's persisted ZIP 318 interval.
        let tolerance = overdue_shift_tolerance(&SchedulingParams::ZIP_318.transfer_delay());
        assert_eq!(tolerance, 16, "a quarter of the 66-block ZIP 318 mean");
        let make = || {
            state_with_crossings(
                &[50_000_000, 50_000_000],
                vec![
                    tx(0, prep(0, 0), mined(10)),
                    scheduled_transfer(1, 0, 720, 1_000, MigrationTxState::Proved),
                    scheduled_transfer(2, 1, 720, 1_050, MigrationTxState::Signed),
                ],
            )
        };

        // Exactly AT the tolerance: the schedule holds.
        let mut state = make();
        let mut store = TestStore::new(1_000 + tolerance, []);
        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1_000 + tolerance)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();
        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );
        assert_eq!(
            u32::from(state.transactions()[1].scheduled_height()),
            1_000,
            "within tolerance the schedule holds"
        );
        assert_eq!(store.replaced.get(), 0, "and nothing is written");

        // One block past it: the pending schedule shifts.
        let mut state = make();
        let mut store = TestStore::new(1_000 + tolerance + 1, []);
        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(1_000 + tolerance + 1)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();
        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "the trigger is released at the served target it was shifted to"
        );
        assert_eq!(
            u32::from(state.transactions()[1].scheduled_height()),
            1_000 + tolerance + 1,
        );
        assert_eq!(
            u32::from(state.transactions()[2].scheduled_height()),
            1_050 + tolerance + 1,
        );
        assert_eq!(store.replaced.get(), 1);
    }

    /// The tolerance is a function of the schedule's own scale: a quarter of the mean transfer
    /// gap, so compressed test-network parameters compress it in proportion, clamped to at least
    /// one block at the degenerate end.
    #[test]
    fn overdue_shift_tolerance_scales_with_the_transfer_delay() {
        use crate::scheduling::AnchorBucketInterval;
        let for_interval = |blocks: u32| {
            overdue_shift_tolerance(
                &SchedulingParams::new_with_default_distributions(AnchorBucketInterval::custom(
                    core::num::NonZeroU32::new(blocks).expect("nonzero"),
                ))
                .transfer_delay(),
            )
        };
        assert_eq!(
            for_interval(144),
            16,
            "the ZIP 318 grid gives the mainnet value"
        );
        // A twelfth of the grid scales the mean to 5, and the tolerance to a quarter of that.
        assert_eq!(for_interval(12), 1);
        // Degenerate one-block grids clamp to a tolerance of one rather than zero, so ordinary
        // one-block estimation error never triggers a rewrite of the whole schedule.
        assert_eq!(for_interval(1), 1);
    }

    /// The shift triggers on a PROVE step too: a wallet that slept through both its proving
    /// wake-ups and a broadcast window re-spreads at the FIRST step it is offered, so the backlog
    /// is already re-spread by the time the proofs land — and the prove itself is still surfaced
    /// in the same call, since a transfer's proving is anchor-gated, not schedule-gated.
    #[test]
    fn overdue_prove_shifts_the_pending_schedule() {
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 1_000, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(2_000, []);

        let step = advance_migration(
            &mut store,
            &mut state,
            DuenessTargets::at(BlockHeight::from_u32(2_001)),
            &config(),
            &mut rng(),
        )
        .expect("the store never fails")
        .step()
        .clone();

        assert!(
            matches!(&step, AdvanceStep::Prove { transactions } if *transactions == [pt(1, transfer(0))]),
            "the prove is still surfaced in the shifting call: {step:?}"
        );
        assert_eq!(
            u32::from(state.transactions()[1].scheduled_height()),
            2_001,
            "its broadcast window re-spread to the served target"
        );
        assert_eq!(store.replaced.get(), 1);
    }

    /// The outlook assumes the returned step is EXECUTED. A due preparation's prove reports its
    /// own broadcast servable at that same schedule — the same-session signal — while a transfer
    /// proved early reports its broadcast at its later scheduled height, the wake-up to register
    /// when the proving session ends.
    #[test]
    fn outlook_after_a_prove_is_the_broadcast_that_follows() {
        let mut prep_tx = tx(1, prep(0, 0), MigrationTxState::Signed);
        prep_tx.scheduled_height = BlockHeight::from_u32(1_000);
        let mut state = state_with_crossings(&[100_000_000], vec![prep_tx]);
        let mut store = TestStore::new(1_000, []);
        let targets = DuenessTargets::at(BlockHeight::from_u32(1_001));

        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert!(
            matches!(advance.step(), AdvanceStep::Prove { transactions } if *transactions == [pt(1, prep(0, 0))]),
            "the due preparation's prove is the step: {:?}",
            advance.step()
        );
        assert_eq!(
            advance.next(),
            Some((BlockHeight::from_u32(1_000), StepKind::Broadcast)),
            "once proved, its broadcast is servable at its own (already-due) schedule"
        );

        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 1_200, MigrationTxState::Signed),
            ],
        );
        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert!(
            matches!(advance.step(), AdvanceStep::Prove { transactions } if *transactions == [pt(1, transfer(0))]),
            "the settled-boundary transfer's prove is the step: {:?}",
            advance.step()
        );
        assert_eq!(
            advance.next(),
            Some((BlockHeight::from_u32(1_200), StepKind::Broadcast)),
            "the proof leaves nothing until the transfer's own broadcast window"
        );
    }

    /// A `Waiting` step carries the wake-up: the earliest height-gated floor among the pending
    /// transactions — here the proved transfer's broadcast window, not the later-boundary
    /// transfer's proof — and a broadcast step's outlook reports the next due broadcast in the
    /// same session.
    #[test]
    fn outlook_reports_the_earliest_upcoming_floor() {
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 1_200, MigrationTxState::Proved),
                // Boundary 1_300 is unsettled at the target, so its prove floor (1_302) sits
                // past the broadcast window above.
                scheduled_transfer(2, 1, 1_300, 1_500, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(1_000, []);
        let targets = DuenessTargets::at(BlockHeight::from_u32(1_001));

        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert_eq!(advance.step(), &AdvanceStep::Waiting);
        assert_eq!(
            advance.next(),
            Some((BlockHeight::from_u32(1_200), StepKind::Broadcast)),
            "the earliest floor wins: the broadcast window, not the later prove"
        );

        // Both proved and due: the first broadcast's outlook is the second, servable now.
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 995, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 720, 1_000, MigrationTxState::Proved),
            ],
        );
        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert_eq!(
            advance.step(),
            &AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "the longest-due broadcast is served first"
        );
        assert_eq!(
            advance.next(),
            Some((BlockHeight::from_u32(1_000), StepKind::Broadcast)),
            "the other due broadcast follows in the same session (its floor is already reached)"
        );
    }

    /// No outlook where none is knowable or schedulable: a candidate deferred as "not yet
    /// satisfiable" is chain-gated and must not resurface as a wake-up the loop just declined to
    /// serve; a migration whose every transaction is in flight waits on the chain alone; and a
    /// rebuild's fresh schedule is drawn at rebuild time, so the call that follows it reports
    /// the outlook instead.
    #[test]
    fn outlook_is_none_when_nothing_is_height_schedulable() {
        // The only pending transaction's broadcast is due, but the wallet cannot yet vouch for
        // its inputs: the step defers to Waiting, and the outlook must not name the deferred
        // candidate's own (already-reached) floor.
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 1_000, MigrationTxState::Proved),
            ],
        );
        let mut store = TestStore::new(
            900,
            [(
                MigrationTransferId(1),
                StepSatisfiability::NotYetSatisfiable {
                    as_of_height: BlockHeight::from_u32(900),
                },
            )],
        );
        let targets = DuenessTargets::at(BlockHeight::from_u32(1_001));
        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert_eq!(advance.step(), &AdvanceStep::Waiting);
        assert_eq!(
            advance.next(),
            None,
            "a set-aside candidate is chain-gated: no height re-serves it"
        );

        // Everything in flight: mining is chain-derived, so nothing is height-schedulable.
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 1_000, broadcast()),
            ],
        );
        let mut store = TestStore::new(1_000, []);
        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert_eq!(advance.step(), &AdvanceStep::Waiting);
        assert_eq!(
            advance.next(),
            None,
            "in flight: the chain decides what is next"
        );

        // An expired transfer: the rebuild draws its replacement's schedule when it happens, so
        // the outlook cannot be stated ahead of it.
        let mut expired = scheduled_transfer(1, 0, 720, 900, MigrationTxState::Signed);
        expired.expiry_height = BlockHeight::from_u32(950);
        let mut state =
            state_with_crossings(&[100_000_000], vec![tx(0, prep(0, 0), mined(10)), expired]);
        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert_eq!(
            advance.step(),
            &AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );
        assert_eq!(
            advance.next(),
            None,
            "the rebuild reschedules its transfer; the following call reports the fresh outlook"
        );
    }

    /// A `Prove` batch member the wallet cannot yet vouch for is set aside without costing the
    /// rest of the batch: the survivors are served directly — each member having paid exactly
    /// one oracle query, with no re-planning re-buy — and the outlook assumes the surviving
    /// batch proved, with the set-aside member contributing no wake-up (it is chain-gated).
    #[test]
    fn prove_batch_serves_survivors_when_a_member_defers() {
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 720, 1_400, MigrationTxState::Signed),
                scheduled_transfer(2, 1, 730, 1_500, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(
            900,
            [(
                MigrationTransferId(1),
                StepSatisfiability::NotYetSatisfiable {
                    as_of_height: BlockHeight::from_u32(900),
                },
            )],
        );
        let targets = DuenessTargets::at(BlockHeight::from_u32(1_001));

        let advance = advance_migration(&mut store, &mut state, targets, &config(), &mut rng())
            .expect("the store never fails");
        assert_eq!(
            advance.step(),
            &AdvanceStep::Prove {
                transactions: vec![pt(2, transfer(1))],
            },
            "the deferred member is dropped; the survivor is served"
        );
        assert_eq!(
            store.queries.get(),
            2,
            "each batch member paid exactly one oracle query"
        );
        assert_eq!(store.replaced.get(), 0, "a deferral records nothing");
        assert_eq!(
            advance.next(),
            Some((BlockHeight::from_u32(1_500), StepKind::Broadcast)),
            "the outlook assumes the survivor proved and skips the set-aside member"
        );
    }
}
