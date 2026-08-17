//! Grouping a migration run's transactions into signing ROUNDS bounded by a signer's per-interaction
//! action budget.
//!
//! An external hardware signer bounds how much it will sign in one interaction. A Keystone caps a
//! single round at [`SigningRoundBudget::KEYSTONE`] (96) TOTAL Orchard actions across ALL the
//! transactions in that round — not a per-transaction cap: 6 preparation transactions of
//! [`PREPARATION_ACTIONS`] (16) each, or 32 transfer transactions of [`TRANSFER_ACTIONS`] (3) each,
//! or any mix summing to at most the budget. A software / in-process signer has no device limit but
//! still takes a finite [`SigningRoundBudget::DEFAULT`].
//!
//! # The optimization
//!
//! Partitioning transactions into the fewest rounds of total action-weight at most the budget is
//! one-dimensional BIN PACKING, NP-hard in general. This instance has only two distinct item sizes
//! (16 and 3) with high multiplicity, a polynomial special case solved EXACTLY by a small dynamic
//! program ([`MinRounds`]); we do not settle for a greedy. Reordering is legitimate: every
//! transaction is independent at signing time (anchors and witnesses are deferred to proving, ZIP
//! 374), so the packer may mix preparation and transfer across rounds; broadcast order stays a
//! separate concern of the schedule.
//!
//! # The two inverse queries
//!
//! Packing answers "how many rounds does this run take". Both inverses are here as well, for the
//! application that must decide something rather than display it: [`min_budget_for_rounds`] inverts
//! the map in the BUDGET ("which signer signs this run in one interaction"), and
//! [`largest_run_size_within`] inverts it in the run SIZE ("how big a run does this signer sign in
//! one interaction"). The latter is what sizes a run for a capacity-limited signer, since a run's
//! action count is not a function of its note count alone — see [`RunSigningCapacity`].
//!
//! The pluggable [`SigningRoundStrategy`] is the "named solution of the NP problem" seam, mirroring
//! [`DenominationStrategy`](crate::denomination::DenominationStrategy): [`MinRounds`] (the optimal
//! default) and [`NextFit`] (an order-preserving greedy). Any new solution inherits the crate's
//! reusable conformance suite (`crate::testing`).

use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroUsize};

use zcash_protocol::consensus::BlockHeight;

use crate::{
    denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
    engine::{MigrationTransferId, MigrationTxKind},
};

/// The Orchard-family actions a padded preparation transaction carries.
pub const PREPARATION_ACTIONS: u32 = crate::preparation::PREP_TX_ACTIONS as u32;

/// The Orchard-family actions a canonical migration transfer carries (2 source + 1 destination).
pub const TRANSFER_ACTIONS: u32 = (zcash_protocol::zip318::CROSSING_SOURCE_ACTIONS
    + zcash_protocol::zip318::CROSSING_DESTINATION_ACTIONS)
    as u32;

/// The number of Orchard-family actions a signer processes for a migration transaction of `kind`.
#[must_use]
pub const fn action_weight(kind: MigrationTxKind) -> u32 {
    match kind {
        MigrationTxKind::Preparation { .. } => PREPARATION_ACTIONS,
        MigrationTxKind::Transfer { .. } => TRANSFER_ACTIONS,
    }
}

/// The maximum TOTAL Orchard actions a signer processes in one signing ROUND (one interaction),
/// summed across every transaction in that round. A per-round total, never a per-transaction cap.
///
/// Callers pass the value their signer supports at the API call. Two named values ship:
/// [`Self::KEYSTONE`] (the Keystone hardware wallet) and [`Self::DEFAULT`] (used when no
/// signer-specific cap is given). A budget below [`Self::minimum_feasible`] makes a single
/// preparation transaction larger than a round; the packers never fail (such a transaction still
/// gets a round of its own), they just cannot pack tightly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningRoundBudget(NonZeroU32);

impl SigningRoundBudget {
    /// The Keystone hardware wallet: at most 96 total actions per signing round.
    pub const KEYSTONE: Self = Self(nz(96));

    /// The default per-round budget when the caller has no signer-specific cap: finite, and
    /// comfortably above one migration run's total actions, so a software signer signs a run in a
    /// single round.
    pub const DEFAULT: Self = Self(nz(512));

    /// A caller-specified budget of `max` total actions per round.
    #[must_use]
    pub const fn new(max: NonZeroU32) -> Self {
        Self(max)
    }

    /// The per-round action budget.
    #[must_use]
    pub const fn max_actions(self) -> u32 {
        self.0.get()
    }

    /// The smallest budget any signer must support so no single transaction exceeds a round: equals
    /// [`PREPARATION_ACTIONS`] (16), a preparation transaction being the largest indivisible item.
    #[must_use]
    pub const fn minimum_feasible() -> NonZeroU32 {
        nz(PREPARATION_ACTIONS)
    }
}

impl Default for SigningRoundBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Const `NonZeroU32` construction (panics only on a compile-time zero literal).
const fn nz(n: u32) -> NonZeroU32 {
    match NonZeroU32::new(n) {
        Some(v) => v,
        None => panic!("nonzero"),
    }
}

/// A transaction a migration plan WILL build, described before it is built: its stable ordinal (the
/// [`MigrationTransferId`] the build later assigns, since the plan enumerates in commit order), what it
/// does, how many Orchard actions the signer processes for it, and the two facts that place it in
/// the run — what must mine before it, and when it is scheduled to broadcast.
///
/// Every field is what the COMMIT will stamp on the built transaction, so a consumer can show the
/// whole run's execution shape (its dependency graph and its timeline) from a plan the user has
/// not consented to yet, and then find each preview row again by id once the run is committed. See
/// [`MigrationPlan::planned_transactions`](crate::engine::MigrationPlan::planned_transactions),
/// which is the only thing that should construct one for a real plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedTx {
    id: MigrationTransferId,
    kind: MigrationTxKind,
    actions: u32,
    depends_on: Vec<MigrationTransferId>,
    scheduled_height: Option<BlockHeight>,
}

impl PlannedTx {
    /// A planned transaction of `kind`, identified by `id`, waiting on `depends_on` and scheduled
    /// for `scheduled_height`, with its canonical [`action_weight`].
    #[must_use]
    pub fn new(
        id: MigrationTransferId,
        kind: MigrationTxKind,
        depends_on: Vec<MigrationTransferId>,
        scheduled_height: Option<BlockHeight>,
    ) -> Self {
        Self {
            id,
            kind,
            actions: action_weight(kind),
            depends_on,
            scheduled_height,
        }
    }

    /// The stable ordinal this transaction will carry once built.
    #[must_use]
    pub const fn id(&self) -> MigrationTransferId {
        self.id
    }

    /// What this transaction does.
    #[must_use]
    pub const fn kind(&self) -> MigrationTxKind {
        self.kind
    }

    /// The Orchard-family actions the signer processes for this transaction.
    #[must_use]
    pub const fn actions(&self) -> u32 {
        self.actions
    }

    /// The transactions that must MINE before this one may be broadcast, by the id each will carry
    /// — the value the commit stores as
    /// [`MigrationTransaction::depends_on`](crate::engine::MigrationTransaction::depends_on).
    ///
    /// Empty for a transaction that waits on nothing: a preparation transaction in layer 0, whose
    /// inputs are the wallet's own notes, or a crossing funded directly by a wallet note. (A plan
    /// that named no note at all for a crossing would also show it waiting on nothing, but such a
    /// plan is unconstructible through this crate's API and `commit_preparation` refuses it before
    /// building anything, so no run is ever previewed from one.)
    #[must_use]
    pub fn depends_on(&self) -> &[MigrationTransferId] {
        &self.depends_on
    }

    /// The height at which this transaction is scheduled to broadcast — the value the commit
    /// stores as
    /// [`MigrationTransaction::scheduled_height`](crate::engine::MigrationTransaction::scheduled_height).
    ///
    /// Not a promise of when it WILL broadcast: a dependency that mines late holds a transaction
    /// past its drawn height, and the engine re-spreads a run that falls too far behind. It is the
    /// timeline the user consents to.
    ///
    /// `None` only for a plan that holds no drawn height for a transaction it contains, which the
    /// public API cannot produce (a plan's schedules are drawn one height per transaction) and
    /// which `commit_preparation` refuses to build. The row is still reported, so that no id is
    /// renumbered by the absence.
    #[must_use]
    pub const fn scheduled_height(&self) -> Option<BlockHeight> {
        self.scheduled_height
    }

    /// Whether this is a preparation transaction.
    #[must_use]
    pub const fn is_preparation(&self) -> bool {
        matches!(self.kind, MigrationTxKind::Preparation { .. })
    }

    /// Whether this is a transfer transaction.
    #[must_use]
    pub const fn is_transfer(&self) -> bool {
        matches!(self.kind, MigrationTxKind::Transfer { .. })
    }
}

/// One signing round: the preparation and/or transfer transactions a signer handles in a single
/// interaction, and their total action count (at most the plan's [`SigningRoundBudget`], unless the
/// round is a single transaction that alone exceeds it). The user consents to this grouping as part
/// of the [`MigrationPlan`](crate::engine::MigrationPlan).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedSigningRound {
    txs: Vec<PlannedTx>,
    total_actions: u32,
}

impl PlannedSigningRound {
    /// Assemble a round from its transactions, summing their actions.
    #[must_use]
    pub fn new(txs: Vec<PlannedTx>) -> Self {
        let total_actions = txs.iter().map(PlannedTx::actions).sum();
        Self { txs, total_actions }
    }

    /// The transactions in this round, in canonical (commit) order.
    #[must_use]
    pub fn transactions(&self) -> &[PlannedTx] {
        &self.txs
    }

    /// The number of transactions in this round.
    #[must_use]
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether this round has no transactions (never true for a round a strategy produces).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// The number of preparation transactions in this round.
    #[must_use]
    pub fn preparation_count(&self) -> usize {
        self.txs.iter().filter(|t| t.is_preparation()).count()
    }

    /// The number of transfer transactions in this round.
    #[must_use]
    pub fn transfer_count(&self) -> usize {
        self.txs.iter().filter(|t| t.is_transfer()).count()
    }

    /// The total Orchard-family actions across this round's transactions.
    #[must_use]
    pub const fn total_actions(&self) -> u32 {
        self.total_actions
    }

    /// How full this round is against `budget`, in `[0.0, 1.0]` (or above 1.0 for a single
    /// oversized transaction). For a progress/headroom indicator.
    #[must_use]
    pub fn fill_fraction(&self, budget: SigningRoundBudget) -> f32 {
        self.total_actions as f32 / budget.max_actions() as f32
    }
}

/// A pluggable solution to the signing-round BIN PACKING problem: partition planned transactions
/// into rounds of total action-weight at most `budget`, in as few rounds as the strategy achieves.
/// The named implementations ([`MinRounds`], [`NextFit`]) are the "differently-named NP solutions".
pub trait SigningRoundStrategy {
    /// A short human-readable name for the strategy (for logging and the reusable test suite).
    fn name(&self) -> &'static str;

    /// Partition `txs` into signing rounds within `budget`. Every input transaction appears in
    /// exactly one round, no round is empty, and no round exceeds `budget` unless it is a single
    /// transaction whose own actions exceed the budget.
    fn pack(&self, txs: &[PlannedTx], budget: SigningRoundBudget) -> Vec<PlannedSigningRound>;

    /// The number of rounds this strategy needs for `n_prep` preparation and `n_transfer` transfer
    /// transactions under `budget`, computed without materializing the packing. Consistent with
    /// [`pack`](Self::pack): equals `pack(...).len()` for the same counts.
    fn round_count(&self, n_prep: usize, n_transfer: usize, budget: SigningRoundBudget) -> usize;
}

/// The optimal solution: the minimum number of signing rounds (fewest signer interactions),
/// computed exactly by exploiting the two-item-size structure of the problem (preparation = 16,
/// transfer = 3). Reorders freely, which is sound because signing-time transactions are
/// independent. This is the recommended default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinRounds;

impl SigningRoundStrategy for MinRounds {
    fn name(&self) -> &'static str {
        "min-rounds"
    }

    fn pack(&self, txs: &[PlannedTx], budget: SigningRoundBudget) -> Vec<PlannedSigningRound> {
        let mut preps: Vec<PlannedTx> = txs
            .iter()
            .filter(|tx| tx.is_preparation())
            .cloned()
            .collect();
        let mut transfers: Vec<PlannedTx> =
            txs.iter().filter(|tx| tx.is_transfer()).cloned().collect();
        let assignment = solve_two_size(preps.len(), transfers.len(), budget);

        // Consume preparation and transfer transactions from the front into each round's quota.
        let mut prep_iter = preps.drain(..);
        let mut xfer_iter = transfers.drain(..);
        assignment
            .into_iter()
            .map(|(n_p, n_t)| {
                let mut round = Vec::with_capacity(n_p + n_t);
                round.extend(prep_iter.by_ref().take(n_p));
                round.extend(xfer_iter.by_ref().take(n_t));
                PlannedSigningRound::new(round)
            })
            .collect()
    }

    fn round_count(&self, n_prep: usize, n_transfer: usize, budget: SigningRoundBudget) -> usize {
        solve_two_size(n_prep, n_transfer, budget).len()
    }
}

/// An order-preserving greedy: consecutive next-fit batches in the given (commit) order, each
/// holding at most `budget` total actions, except that a batch always holds at least one
/// transaction. Simpler and stable (preserves the emit order), but not guaranteed minimal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NextFit;

impl SigningRoundStrategy for NextFit {
    fn name(&self) -> &'static str {
        "next-fit"
    }

    fn pack(&self, txs: &[PlannedTx], budget: SigningRoundBudget) -> Vec<PlannedSigningRound> {
        let cap = budget.max_actions();
        let mut rounds: Vec<PlannedSigningRound> = Vec::new();
        let mut current: Vec<PlannedTx> = Vec::new();
        let mut current_actions = 0u32;
        for tx in txs {
            if !current.is_empty() && current_actions.saturating_add(tx.actions()) > cap {
                rounds.push(PlannedSigningRound::new(core::mem::take(&mut current)));
                current_actions = 0;
            }
            current_actions = current_actions.saturating_add(tx.actions());
            current.push(tx.clone());
        }
        if !current.is_empty() {
            rounds.push(PlannedSigningRound::new(current));
        }
        rounds
    }

    fn round_count(&self, n_prep: usize, n_transfer: usize, budget: SigningRoundBudget) -> usize {
        // Next-fit is order-dependent; simulate over the canonical order (preparation then transfer)
        // without materializing transactions.
        let cap = budget.max_actions();
        let mut rounds = 0usize;
        let mut current_actions = 0u32;
        let mut any_in_current = false;
        let push = |w: u32, current_actions: &mut u32, any: &mut bool, rounds: &mut usize| {
            if *any && current_actions.saturating_add(w) > cap {
                *rounds += 1;
                *current_actions = 0;
                *any = false;
            }
            *current_actions = current_actions.saturating_add(w);
            *any = true;
        };
        for _ in 0..n_prep {
            push(
                PREPARATION_ACTIONS,
                &mut current_actions,
                &mut any_in_current,
                &mut rounds,
            );
        }
        for _ in 0..n_transfer {
            push(
                TRANSFER_ACTIONS,
                &mut current_actions,
                &mut any_in_current,
                &mut rounds,
            );
        }
        if any_in_current {
            rounds += 1;
        }
        rounds
    }
}

/// The minimum number of signing rounds to sign `n_prep` preparation and `n_transfer` transfer
/// transactions under `budget`: the [`MinRounds`] optimum. Zero when there is nothing to sign.
#[must_use]
pub fn min_signing_rounds(n_prep: usize, n_transfer: usize, budget: SigningRoundBudget) -> usize {
    MinRounds.round_count(n_prep, n_transfer, budget)
}

/// The smallest per-round budget that signs `n_prep` preparation and `n_transfer` transfer
/// transactions in at most `k` rounds (the inverse query: "your signer must support at least this
/// many actions per round to do this in `k` interactions"). Never below
/// [`SigningRoundBudget::minimum_feasible`].
#[must_use]
pub fn min_budget_for_rounds(n_prep: usize, n_transfer: usize, k: NonZeroUsize) -> NonZeroU32 {
    let floor = SigningRoundBudget::minimum_feasible().get();
    let total = total_actions(n_prep, n_transfer);
    // One round holds everything at `total`; the min feasible per-round budget is the floor.
    let hi = total.max(floor);
    // min_signing_rounds is non-increasing in the budget, so binary-search the smallest feasible.
    let (mut lo, mut hi) = (floor, hi);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let budget = SigningRoundBudget::new(nz(mid));
        if min_signing_rounds(n_prep, n_transfer, budget) <= k.get() {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    nz(lo)
}

/// The transaction counts of one migration run, the only inputs the round count depends on: its
/// preparation transactions (16 actions each) and its pool-crossing transfers (3 actions each).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunShape {
    preparation_transactions: usize,
    transfers: usize,
}

impl RunShape {
    /// A run of `preparation_transactions` preparation transactions and `transfers` transfers.
    #[must_use]
    pub const fn new(preparation_transactions: usize, transfers: usize) -> Self {
        Self {
            preparation_transactions,
            transfers,
        }
    }

    /// The run's preparation transactions.
    #[must_use]
    pub const fn preparation_transactions(self) -> usize {
        self.preparation_transactions
    }

    /// The run's pool-crossing transfers (one per funding note).
    #[must_use]
    pub const fn transfers(self) -> usize {
        self.transfers
    }

    /// The number of signing rounds this run needs under `budget`, the optimal [`MinRounds`] count.
    #[must_use]
    pub fn signing_rounds(self, budget: SigningRoundBudget) -> usize {
        min_signing_rounds(self.preparation_transactions, self.transfers, budget)
    }

    /// The total Orchard-family actions across this run's transactions: the signing WORKLOAD, as
    /// distinct from [`signing_rounds`](Self::signing_rounds), the number of interactions.
    #[must_use]
    pub fn total_actions(self) -> u32 {
        total_actions(self.preparation_transactions, self.transfers)
    }
}

/// What one migration run may ask of a signer: at most [`max_rounds`](Self::max_rounds)
/// interactions of at most [`budget`](Self::budget) total actions each, from a run preparing at most
/// [`max_notes`](Self::max_notes) notes.
///
/// This is the capacity-side statement of a run's size. The note cap alone cannot make it: a run's
/// actions are `16 * preparations + 3 * transfers`, and the preparation count is a function of the
/// wallet's note structure (how deeply it must be consolidated), not of the number of notes the run
/// mints. `max_notes` is therefore a CEILING the sizing never exceeds, not the target; see
/// [`largest_run_size_within`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunSigningCapacity {
    budget: SigningRoundBudget,
    max_rounds: NonZeroUsize,
    max_notes: NonZeroUsize,
}

impl RunSigningCapacity {
    /// A Keystone signing each run in a single interaction: [`SigningRoundBudget::KEYSTONE`], one
    /// round, and the crate's default note ceiling.
    pub const KEYSTONE: Self = Self::single_round(SigningRoundBudget::KEYSTONE);

    /// A signer of `budget` actions per interaction that signs each run in ONE interaction, over a
    /// run of at most [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`] notes.
    #[must_use]
    pub const fn single_round(budget: SigningRoundBudget) -> Self {
        Self::new(
            budget,
            NonZeroUsize::MIN,
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
        )
    }

    /// A signer of `budget` actions per interaction, allowed `max_rounds` interactions per run, over
    /// a run of at most `max_notes` notes.
    #[must_use]
    pub const fn new(
        budget: SigningRoundBudget,
        max_rounds: NonZeroUsize,
        max_notes: NonZeroUsize,
    ) -> Self {
        Self {
            budget,
            max_rounds,
            max_notes,
        }
    }

    /// The per-round action budget.
    #[must_use]
    pub const fn budget(self) -> SigningRoundBudget {
        self.budget
    }

    /// The number of signing interactions one run may take.
    #[must_use]
    pub const fn max_rounds(self) -> NonZeroUsize {
        self.max_rounds
    }

    /// The largest per-run note cap the sizing may choose.
    #[must_use]
    pub const fn max_notes(self) -> NonZeroUsize {
        self.max_notes
    }
}

/// The largest per-run note cap, at most [`RunSigningCapacity::max_notes`], whose run `shape_at`
/// reports as signable within `capacity` — the inverse of "how many rounds does this run take",
/// dual to [`min_budget_for_rounds`] (which inverts the same map in the budget instead of the size).
///
/// `shape_at` answers what a run capped at `n` notes would look like, or `None` if no run can be
/// built at that cap; it is called `O(log max_notes)` times. A `None` is treated as NOT fitting,
/// which is the conservative reading: a cap whose run cannot be built must never be preferred over
/// one that can, and the alternative (reporting an empty shape) would make it the cheapest
/// candidate rather than the worst.
///
/// The returned cap is one `shape_at` reported as fitting, EXCEPT when even a one-note run exceeds
/// the capacity, in which case it is one: a wallet fragmented enough that minting a single funding
/// note takes more consolidation than a round holds cannot be made to fit by shrinking the run, and
/// the caller sees the overflow in the resulting plan's
/// [`signing_round_count`](crate::engine::MigrationPlan::signing_round_count).
///
/// It is the LARGEST such cap whenever the run's round count is non-decreasing in the cap, which
/// holds for this crate's canonical decomposition (raising the cap extends the split rather than
/// reshaping it) and for any preparation portfolio that does not mint more notes with fewer
/// transactions. Under that monotonicity this function and the round count are adjoint —
/// `shape_at(n).signing_rounds(budget) <= max_rounds` exactly when `n` is at most the returned cap —
/// so the result is the greatest run that fits. A portfolio violating it still gets a cap that
/// fits, just not necessarily the largest.
#[must_use]
pub fn largest_run_size_within<F>(capacity: RunSigningCapacity, mut shape_at: F) -> NonZeroUsize
where
    F: FnMut(NonZeroUsize) -> Option<RunShape>,
{
    let mut fits = |n: NonZeroUsize| {
        shape_at(n).is_some_and(|shape| {
            shape.signing_rounds(capacity.budget()) <= capacity.max_rounds().get()
        })
    };
    // The whole run fits: the common case, and the one that costs a single probe.
    if fits(capacity.max_notes()) {
        return capacity.max_notes();
    }
    // Binary-search the largest cap that fits, keeping only caps a probe accepted, so the answer is
    // certified even where the round count is not monotone in the cap.
    let mut best = NonZeroUsize::MIN;
    let (mut lo, mut hi) = (1usize, capacity.max_notes().get() - 1);
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let cap = NonZeroUsize::new(mid).expect("`lo` starts at one, so `mid` is at least one");
        if fits(cap) {
            best = cap;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    best
}

/// Total actions of `n_prep` preparation and `n_transfer` transfer transactions (u32-saturating).
fn total_actions(n_prep: usize, n_transfer: usize) -> u32 {
    let prep = (n_prep as u64).saturating_mul(u64::from(PREPARATION_ACTIONS));
    let xfer = (n_transfer as u64).saturating_mul(u64::from(TRANSFER_ACTIONS));
    u32::try_from(prep.saturating_add(xfer)).unwrap_or(u32::MAX)
}

/// Solve the two-item-size signing-round bin packing EXACTLY, returning one `(preparations,
/// transfers)` quota per round, using the minimum number of rounds. Every quota is non-empty, and
/// the number of rounds equals the optimum.
fn solve_two_size(
    n_prep: usize,
    n_transfer: usize,
    budget: SigningRoundBudget,
) -> Vec<(usize, usize)> {
    if n_prep == 0 && n_transfer == 0 {
        return Vec::new();
    }
    let cap = budget.max_actions();
    let w_hi = PREPARATION_ACTIONS;
    let w_lo = TRANSFER_ACTIONS;

    // Oversized regime: a preparation transaction alone exceeds the budget. Each gets its own round;
    // transfers pack floor(cap / w_lo) per round (or one per round if a transfer also exceeds it).
    if cap < w_hi {
        let mut rounds: Vec<(usize, usize)> = (0..n_prep).map(|_| (1usize, 0usize)).collect();
        let per_round = (cap / w_lo).max(1) as usize;
        let mut left = n_transfer;
        while left > 0 {
            let take = left.min(per_round);
            rounds.push((0, take));
            left -= take;
        }
        return rounds;
    }

    let mp = (cap / w_hi) as usize; // max preparations per round (>= 1)
    // Per-round transfer capacity given `k` preparations in the round.
    let lo_cap = |k: usize| -> usize { ((cap - (k as u32) * w_hi) / w_lo) as usize };

    // Lower bound on rounds: the large-item bound and the volume bound.
    let vol = u64::from(total_actions(n_prep, n_transfer));
    let volume_bound = div_ceil_u64(vol, u64::from(cap)) as usize;
    let large_bound = n_prep.div_ceil(mp);
    let lower = large_bound.max(volume_bound).max(1);
    // A safe feasible upper bound: every preparation alone plus transfers packed at `lo_cap(0)`.
    let upper = n_prep + n_transfer.div_ceil(lo_cap(0).max(1)) + 1;

    for rounds in lower..=upper {
        if let Some(ks) = best_prep_distribution(n_prep, mp, &lo_cap, rounds, n_transfer) {
            // Fill transfers greedily into the rounds up to each round's transfer capacity.
            let mut assignment: Vec<(usize, usize)> = Vec::with_capacity(rounds);
            let mut left = n_transfer;
            for &k in &ks {
                let take = left.min(lo_cap(k));
                left -= take;
                assignment.push((k, take));
            }
            debug_assert_eq!(left, 0, "feasible round count must place every transfer");
            // At the minimal round count no quota is empty (a `(0, 0)` round would prove `rounds - 1`
            // feasible, contradicting minimality); filter defensively regardless.
            assignment.retain(|&(p, t)| p + t > 0);
            return assignment;
        }
    }
    unreachable!("`upper` rounds always suffice")
}

/// The per-round preparation counts (length `rounds`, summing to `n_prep`, each in `0..=mp`) that
/// MAXIMIZE total transfer capacity, if that maximum is at least `need` transfers; else `None`.
/// A dynamic program over `(rounds_used, preparations_placed)`.
fn best_prep_distribution(
    n_prep: usize,
    mp: usize,
    lo_cap: &dyn Fn(usize) -> usize,
    rounds: usize,
    need: usize,
) -> Option<Vec<usize>> {
    const NEG: i64 = i64::MIN / 2;
    // dp[u] = max total transfer capacity having placed `u` preparations in the rounds so far.
    let mut dp = alloc::vec![NEG; n_prep + 1];
    dp[0] = 0;
    // choice[r][u] = preparations put in round r to reach `u` after r rounds.
    let mut choice: Vec<Vec<usize>> = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut next = alloc::vec![NEG; n_prep + 1];
        let mut this_choice = alloc::vec![0usize; n_prep + 1];
        for u in 0..=n_prep {
            if dp[u] == NEG {
                continue;
            }
            let max_k = mp.min(n_prep - u);
            for k in 0..=max_k {
                let cand = dp[u] + lo_cap(k) as i64;
                if cand > next[u + k] {
                    next[u + k] = cand;
                    this_choice[u + k] = k;
                }
            }
        }
        dp = next;
        choice.push(this_choice);
    }
    if dp[n_prep] == NEG || dp[n_prep] < need as i64 {
        return None;
    }
    // Reconstruct the per-round preparation counts.
    let mut ks = alloc::vec![0usize; rounds];
    let mut u = n_prep;
    for r in (0..rounds).rev() {
        let k = choice[r][u];
        ks[r] = k;
        u -= k;
    }
    debug_assert_eq!(u, 0);
    Some(ks)
}

fn div_ceil_u64(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}

#[cfg(test)]
mod tests {
    use proptest::{prop_assert, prop_assert_eq};

    use super::*;

    fn assert_valid(
        strategy: &dyn SigningRoundStrategy,
        n_prep: usize,
        n_transfer: usize,
        cap: u32,
    ) {
        let budget = SigningRoundBudget::new(NonZeroU32::new(cap).unwrap());
        let txs = crate::testing::planned_txs(n_prep, n_transfer);
        let rounds = strategy.pack(&txs, budget);
        // Coverage: every id exactly once.
        let mut ids: Vec<u32> = rounds
            .iter()
            .flat_map(|r| r.transactions().iter().map(|t| u32::from(t.id())))
            .collect();
        ids.sort_unstable();
        let expected: Vec<u32> = (0..(n_prep + n_transfer) as u32).collect();
        assert_eq!(ids, expected, "packing must cover every tx exactly once");
        for r in &rounds {
            assert!(!r.is_empty(), "no empty rounds");
            if r.len() > 1 {
                assert!(r.total_actions() <= cap, "multi-tx round within budget");
            }
            let summed: u32 = r.transactions().iter().map(|t| t.actions()).sum();
            assert_eq!(summed, r.total_actions(), "total_actions accurate");
        }
        assert_eq!(
            rounds.len(),
            strategy.round_count(n_prep, n_transfer, budget),
            "pack length matches round_count"
        );
    }

    // The reusable golden vectors (inputs + expected optimal outputs, in `crate::testing`) validate
    // the optimal packer against a fixed, human-checked table, and every strategy produces a valid
    // packing on those inputs.
    #[test]
    fn golden_vectors_hold() {
        crate::testing::assert_golden_min_rounds();
        crate::testing::assert_golden_vectors_optimal(&MinRounds);
        for gv in crate::testing::SIGNING_ROUND_GOLDEN_VECTORS {
            let budget = SigningRoundBudget::new(NonZeroU32::new(gv.budget_actions).unwrap());
            let txs = crate::testing::planned_txs(gv.n_prep, gv.n_transfer);
            crate::testing::assert_valid_packing(&NextFit, &txs, budget);
        }
    }

    #[test]
    fn min_rounds_matches_the_reference() {
        for n_prep in 0..14 {
            for n_transfer in 0..40 {
                for &cap in &[16u32, 18, 24, 48, 96, 100] {
                    let budget = SigningRoundBudget::new(NonZeroU32::new(cap).unwrap());
                    let want = crate::testing::min_rounds_reference(n_prep, n_transfer, budget);
                    let got = min_signing_rounds(n_prep, n_transfer, budget);
                    assert_eq!(
                        got, want,
                        "n_prep={n_prep} n_transfer={n_transfer} cap={cap}"
                    );
                }
            }
        }
    }

    #[test]
    fn min_rounds_never_beats_next_fit_and_both_valid() {
        for n_prep in 0..12 {
            for n_transfer in 0..30 {
                for &cap in &[16u32, 24, 96] {
                    assert_valid(&MinRounds, n_prep, n_transfer, cap);
                    assert_valid(&NextFit, n_prep, n_transfer, cap);
                    let budget = SigningRoundBudget::new(NonZeroU32::new(cap).unwrap());
                    assert!(
                        MinRounds.round_count(n_prep, n_transfer, budget)
                            <= NextFit.round_count(n_prep, n_transfer, budget),
                        "MinRounds is at least as good as NextFit"
                    );
                }
            }
        }
    }

    // The reusable conformance suite (in `crate::testing`) drives BOTH strategies, demonstrating it
    // is strategy-agnostic: any implementation, including one a downstream crate adds, is validated
    // by the same assertions.
    proptest::proptest! {
        #[test]
        fn strategies_satisfy_the_reusable_conformance_suite(
            txs in crate::testing::arb_planned_txs(),
            budget in crate::testing::arb_signing_round_budget(),
        ) {
            crate::testing::assert_valid_packing(&MinRounds, &txs, budget);
            crate::testing::assert_valid_packing(&NextFit, &txs, budget);

            let n_prep = txs.iter().filter(|t| t.is_preparation()).count();
            let n_transfer = txs.iter().filter(|t| t.is_transfer()).count();
            crate::testing::assert_optimal_round_count(&MinRounds, n_prep, n_transfer, budget);
            crate::testing::assert_no_worse_than(&MinRounds, &NextFit, n_prep, n_transfer, budget);
        }
    }

    /// An oracle over explicit per-cap shapes: `shapes[n - 1]` is the run a cap of `n` notes
    /// produces. Records every cap it was asked about, so a test can bound the probe count.
    fn oracle<'a>(
        shapes: &'a [RunShape],
        probes: &'a mut Vec<usize>,
    ) -> impl FnMut(NonZeroUsize) -> Option<RunShape> + 'a {
        move |n| {
            probes.push(n.get());
            Some(shapes[n.get() - 1])
        }
    }

    /// Per-cap shapes that grow with the cap: `n` transfers, one preparation transaction per
    /// `FUNDING_OUTPUTS_PER_TX` of them — the shape of a run over an unfragmented wallet.
    fn monotone_shapes(ceiling: usize) -> Vec<RunShape> {
        (1..=ceiling)
            .map(|n| RunShape::new(n.div_ceil(crate::preparation::FUNDING_OUTPUTS_PER_TX), n))
            .collect()
    }

    #[test]
    fn sizing_fills_a_keystone_round() {
        let ceiling = MIGRATION_MAX_PREPARED_NOTES_PER_RUN;
        let shapes = monotone_shapes(ceiling.get());
        let mut probes = Vec::new();
        let chosen =
            largest_run_size_within(RunSigningCapacity::KEYSTONE, oracle(&shapes, &mut probes));
        // 5 notes: one preparation transaction (16 actions) and 5 transfers (15) is 31 of the 96;
        // 6 notes would take a second preparation transaction and 34 actions, still one round.
        assert!(chosen.get() > 5, "a Keystone round holds more than 5 notes");
        assert_eq!(
            shapes[chosen.get() - 1].signing_rounds(SigningRoundBudget::KEYSTONE),
            1,
            "the chosen cap signs in one round"
        );
        assert!(
            chosen == ceiling
                || shapes[chosen.get()].signing_rounds(SigningRoundBudget::KEYSTONE) > 1,
            "one note more needs a second round"
        );
        assert!(
            probes.len() <= usize::BITS as usize - ceiling.get().leading_zeros() as usize + 1,
            "the search probes logarithmically, not linearly: {probes:?}"
        );
    }

    // A cap whose run cannot be built must never be chosen, and in particular must never be
    // preferred over one that can. Reading an unbuildable cap as an empty run would make it the
    // CHEAPEST candidate, so the search would settle on exactly the caps that fail to plan.
    #[test]
    fn an_unbuildable_cap_is_never_chosen() {
        // Every cap above 3 is unbuildable; caps 1..=3 fit comfortably.
        let buildable = 3usize;
        let capacity = RunSigningCapacity::new(
            SigningRoundBudget::KEYSTONE,
            NonZeroUsize::MIN,
            NonZeroUsize::new(20).unwrap(),
        );
        let mut probes = Vec::new();
        let chosen = largest_run_size_within(capacity, |n| {
            probes.push(n.get());
            (n.get() <= buildable).then(|| RunShape::new(1, n.get()))
        });
        assert_eq!(
            chosen.get(),
            buildable,
            "the largest buildable cap is chosen, not an unbuildable one that looks cheap"
        );
        assert!(
            probes.iter().any(|&n| n > buildable),
            "the search did probe into the unbuildable range, so it really rejected it"
        );
    }

    #[test]
    fn sizing_bottoms_out_at_one_note() {
        // A wallet so fragmented that minting even one funding note takes 7 preparation
        // transactions (112 actions): no cap fits a Keystone round, and the smallest run is
        // returned rather than a failure.
        let shapes: Vec<RunShape> = (1..=10).map(|n| RunShape::new(6 + n, n)).collect();
        let mut probes = Vec::new();
        let capacity = RunSigningCapacity::new(
            SigningRoundBudget::KEYSTONE,
            NonZeroUsize::MIN,
            NonZeroUsize::new(shapes.len()).unwrap(),
        );
        let chosen = largest_run_size_within(capacity, oracle(&shapes, &mut probes));
        assert_eq!(chosen, NonZeroUsize::MIN);
        assert!(
            shapes[0].signing_rounds(SigningRoundBudget::KEYSTONE) > 1,
            "this wallet cannot be made to fit, which is what the caller must see"
        );
    }

    proptest::proptest! {
        // The ADJUNCTION: for a run whose round count is non-decreasing in the cap, a cap fits the
        // signer exactly when it is at most the chosen one. That is what makes the chosen cap the
        // greatest run the signer signs, not merely one that fits.
        #[test]
        fn sizing_is_adjoint_to_the_round_count(
            capacity in crate::testing::arb_run_signing_capacity(),
        ) {
            let shapes = monotone_shapes(capacity.max_notes().get());
            let mut probes = Vec::new();
            let chosen = largest_run_size_within(capacity, oracle(&shapes, &mut probes));
            prop_assert!(chosen <= capacity.max_notes());
            for (i, shape) in shapes.iter().enumerate() {
                let cap = i + 1;
                let fits = shape.signing_rounds(capacity.budget()) <= capacity.max_rounds().get();
                // The one asymmetry: when not even a one-note run fits, the minimum is returned
                // anyway, since no smaller run exists to fall back to.
                if cap == 1 && !fits {
                    prop_assert_eq!(chosen, NonZeroUsize::MIN);
                    continue;
                }
                prop_assert_eq!(fits, cap <= chosen.get(), "cap {} against {:?}", cap, chosen);
            }
        }

        // Without monotonicity the chosen cap is no longer maximal, but it is still one a probe
        // accepted — the guarantee an arbitrary preparation portfolio gets.
        #[test]
        fn sizing_always_returns_a_cap_that_fits(
            capacity in crate::testing::arb_run_signing_capacity(),
            raw in proptest::collection::vec((0usize..12, 0usize..40), 1..64),
        ) {
            // Reshape the arbitrary (and so arbitrarily non-monotone) counts to the ceiling.
            let shapes: Vec<RunShape> = (0..capacity.max_notes().get())
                .map(|i| {
                    let (prep, transfers) = raw[i % raw.len()];
                    RunShape::new(prep, transfers)
                })
                .collect();
            let mut probes = Vec::new();
            let chosen = largest_run_size_within(capacity, oracle(&shapes, &mut probes));
            prop_assert!(chosen <= capacity.max_notes());
            let fits = shapes[chosen.get() - 1].signing_rounds(capacity.budget())
                <= capacity.max_rounds().get();
            prop_assert!(
                fits || chosen == NonZeroUsize::MIN,
                "only a probed-feasible cap is returned, unless nothing fits"
            );
            prop_assert!(
                probes.contains(&chosen.get()) || chosen == NonZeroUsize::MIN,
                "the returned cap was measured, not assumed"
            );
        }
    }

    #[test]
    fn inverse_budget_query() {
        // With 6 preparations + 32 transfers (192 actions), a single round needs budget >= 192.
        let one = NonZeroUsize::new(1).unwrap();
        let b = min_budget_for_rounds(6, 32, one);
        assert_eq!(
            min_signing_rounds(6, 32, SigningRoundBudget::new(b)),
            1,
            "the returned budget achieves one round"
        );
        if b.get() > SigningRoundBudget::minimum_feasible().get() {
            let smaller = SigningRoundBudget::new(NonZeroU32::new(b.get() - 1).unwrap());
            assert!(
                min_signing_rounds(6, 32, smaller) > 1,
                "one action less needs more than one round"
            );
        }
    }
}
