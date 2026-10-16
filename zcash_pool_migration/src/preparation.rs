//! Note-preparation transaction planning: how to restructure a wallet's spendable source-pool notes
//! into the exact self-funding notes a migration run needs, using transactions that each stay within
//! the [ZIP 318] action budget.
//!
//! # The problem
//!
//! The [`denomination`](super::denomination) planner decides the *values* of the self-funding
//! notes to mint. This module decides the *transactions* that mint them. [ZIP 318] requires each
//! note-preparation transaction to be padded to exactly [`PREP_TX_ACTIONS`] Orchard actions (a
//! mobile-proving-time and on-chain-uniformity constraint). Under NU6.3 a bundle's action count is
//! its spends plus its outputs, so one transaction can consume and produce at most
//! [`PREP_TX_ACTIONS`] notes in total (for example 15 spends and one output when consolidating, or
//! one spend and 15 outputs when splitting). A splitting transaction therefore mints MANY funding
//! notes at once, one output per scheduled part (up to [`FUNDING_OUTPUTS_PER_TX`]); the number of
//! funding notes in a preparation transaction is not one. The one-transaction-per-part shape belongs
//! to the phase-2 crossing transfers (each spends a single funding note), not to preparation.
//!
//! A single transaction therefore cannot always turn the wallet's notes into every funding note: a
//! note that must fan out into more outputs than one transaction holds, or a balance spread across
//! more SUB-QUANTUM notes (each below the smallest funding denomination, so too small to fund a
//! crossing on its own; not to be confused with sub-fee "dust") than one transaction can consume,
//! needs **layers**. A layer is a set of
//! transactions with no dependencies between them (buildable, provable, and broadcastable in
//! parallel); a later layer may spend the outputs of an earlier one, but only after they are mined
//! and witnessable, so each extra layer extends the preparation phase by the mining latency plus
//! the wallet's witness-sync turnaround (only the pool-crossing transfers wait on anchor-bucket
//! boundaries). The planner therefore prefers fewer layers (which dominate the wall-clock) over
//! fewer transactions.
//!
//! # The strategies
//!
//! The rule for choosing the transactions is pluggable: [`PreparationStrategy`] is the problem, and
//! each module in [`self`]'s directory is one named solution of it ([`layered_greedy`] today).
//! [`plan_preparation`], the entry point the wallet calls, runs every strategy the crate ships and
//! returns the best plan any of them found, ranked by [`PlanQuality`].
//!
//! This is a pure planner: it works in note *values* (in zatoshi) and does no cryptography or I/O. It
//! reserves a fixed per-transaction fee (the caller passes the ZIP-317 fee of a padded
//! [`PREP_TX_ACTIONS`]-action transaction) out of each transaction's inputs; the builder later
//! absorbs the real fee into the change.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;

use zcash_protocol::value::Zatoshis;

use core::fmt;

pub mod first_fit_decreasing;
pub mod layered_greedy;

pub use first_fit_decreasing::FirstFitDecreasing;
pub use layered_greedy::LayeredGreedy;

/// The exact number of Orchard actions in every note-preparation transaction ([ZIP 318]): each is
/// padded up to this count, so no preparation transaction is distinguishable from another by its
/// action count, and one transaction handles at most this many notes in total (spends plus outputs).
///
/// Re-exported from [`zcash_protocol::zip318`], which owns the ZIP's specified value.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub use zcash_protocol::zip318::PREP_TX_ACTIONS;

/// The most funding (or feeder) outputs one transaction produces from a single input: the action
/// budget less that one input and one change/feeder slot (`16 - 1 - 1`).
pub const FUNDING_OUTPUTS_PER_TX: usize = PREP_TX_ACTIONS - 2;

/// The most notes one transaction consolidates: the action budget less the single output it produces
/// (`16 - 1`).
pub const CONSOLIDATION_INPUTS_PER_TX: usize = PREP_TX_ACTIONS - 1;

/// A note a preparation transaction spends: either one of the wallet's original spendable notes, or a
/// note an earlier layer produced. Each variant carries the note's `value` (in zatoshi).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepInput {
    /// The wallet note at this `index` in the caller-supplied `available` slice, worth `value`.
    Wallet { index: usize, value: Zatoshis },
    /// The `output`-th output of the `transaction`-th transaction of an earlier `layer`, worth
    /// `value`.
    Prior {
        layer: usize,
        transaction: usize,
        output: usize,
        value: Zatoshis,
    },
}

impl PrepInput {
    /// The note value this input carries.
    pub fn value(&self) -> Zatoshis {
        match self {
            PrepInput::Wallet { value, .. } | PrepInput::Prior { value, .. } => *value,
        }
    }
}

/// A note a preparation transaction produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepOutput {
    /// A final self-funding note: one of the requested funding values.
    Funding(Zatoshis),
    /// An intermediate ("feeder") note, spent by a later layer to route value forward.
    Intermediate(Zatoshis),
    /// Leftover value returned to the source pool.
    Change(Zatoshis),
}

impl PrepOutput {
    /// The note value this output carries.
    pub fn value(&self) -> Zatoshis {
        match self {
            PrepOutput::Funding(v) | PrepOutput::Intermediate(v) | PrepOutput::Change(v) => *v,
        }
    }

    /// Reconstruct an output from its stored `role` (the [`AsRef<str>`](AsRef) discriminant) and its
    /// value, so a persistence backend can round-trip it through typed columns rather than a blob.
    pub fn from_role(role: &str, value: Zatoshis) -> Result<Self, ParsePrepOutputError> {
        Ok(match role {
            "funding" => PrepOutput::Funding(value),
            "intermediate" => PrepOutput::Intermediate(value),
            "change" => PrepOutput::Change(value),
            _ => return Err(ParsePrepOutputError),
        })
    }
}

impl AsRef<str> for PrepOutput {
    /// The stable lowercase wire name of this output's role, as a store persists it (paired with
    /// [`value`](Self::value)); parsed back with [`from_role`](Self::from_role).
    fn as_ref(&self) -> &str {
        match self {
            PrepOutput::Funding(_) => "funding",
            PrepOutput::Intermediate(_) => "intermediate",
            PrepOutput::Change(_) => "change",
        }
    }
}

/// The error returned when a string does not name a [`PrepOutput`] role (its
/// [`from_role`](PrepOutput::from_role) constructor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsePrepOutputError;

impl fmt::Display for ParsePrepOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized preparation output role")
    }
}

/// One note-preparation transaction: a same-pool send-to-self, padded at build time to
/// [`PREP_TX_ACTIONS`] actions. Its logical action count (`inputs.len() + outputs.len()`) never
/// exceeds that budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepTransaction {
    inputs: Vec<PrepInput>,
    outputs: Vec<PrepOutput>,
}

impl PrepTransaction {
    /// Construct a transaction from its spent and produced notes. Used to reconstruct a persisted plan
    /// (the inverse of [`inputs`](Self::inputs) plus [`outputs`](Self::outputs)); the caller supplies
    /// parts a valid plan could have produced.
    pub fn from_parts(inputs: Vec<PrepInput>, outputs: Vec<PrepOutput>) -> Self {
        PrepTransaction { inputs, outputs }
    }

    /// The notes this transaction spends.
    pub fn inputs(&self) -> &[PrepInput] {
        &self.inputs
    }

    /// The notes this transaction produces.
    pub fn outputs(&self) -> &[PrepOutput] {
        &self.outputs
    }

    /// The logical Orchard action count before padding (`inputs + outputs`).
    pub fn action_count(&self) -> usize {
        self.inputs.len() + self.outputs.len()
    }
}

/// A schedule of note-preparation transactions grouped into sequential layers. Every transaction in a
/// layer is independent of the others in that layer; a transaction may spend a [`PrepInput::Prior`]
/// output only from a strictly earlier layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparationPlan {
    layers: Vec<Vec<PrepTransaction>>,
    /// Wallet notes (by their index in `available`) already equal to a funding value, used directly as
    /// that funding note with no preparation transaction, paired with that value.
    direct_funding: Vec<(usize, Zatoshis)>,
}

impl PreparationPlan {
    /// Reconstruct a plan from its parts: the layers in dependency order (see [`layers`](Self::layers))
    /// and the direct-funding notes (see [`direct_funding_notes`](Self::direct_funding_notes)). Used by
    /// a store to round-trip a persisted plan; the caller supplies parts a valid plan could have
    /// produced (no validation beyond what the accessors expose is done here).
    pub fn from_parts(
        layers: Vec<Vec<PrepTransaction>>,
        direct_funding: Vec<(usize, Zatoshis)>,
    ) -> Self {
        PreparationPlan {
            layers,
            direct_funding,
        }
    }

    /// The layers, in dependency order (later layers may spend earlier layers' outputs).
    pub fn layers(&self) -> &[Vec<PrepTransaction>] {
        &self.layers
    }

    /// The number of sequential layers (the depth that governs the preparation phase's duration).
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// The total number of preparation transactions across all layers.
    pub fn transaction_count(&self) -> usize {
        self.layers.iter().map(Vec::len).sum()
    }

    /// An iterator over every output of every transaction, in plan (layer then transaction) order.
    fn all_outputs(&self) -> impl Iterator<Item = &PrepOutput> {
        self.layers
            .iter()
            .flatten()
            .flat_map(PrepTransaction::outputs)
    }

    /// Wallet notes (by their index in the caller's `available` slice) already equal to a funding
    /// value, used directly as that funding note with no preparation transaction, each paired with
    /// that value. The caller must leave these notes unspent by preparation.
    pub fn direct_funding_notes(&self) -> &[(usize, Zatoshis)] {
        &self.direct_funding
    }

    /// The values of the self-funding notes this plan mints, both the [`PrepOutput::Funding`] outputs
    /// its transactions create and the wallet notes used directly (see
    /// [`direct_funding_notes`](Self::direct_funding_notes)): the notes the migration transfers will
    /// each spend.
    pub fn funding_notes(&self) -> Vec<Zatoshis> {
        let mut out: Vec<Zatoshis> = self
            .all_outputs()
            .filter_map(|o| match o {
                PrepOutput::Funding(v) => Some(*v),
                _ => None,
            })
            .collect();
        out.extend(self.direct_funding.iter().map(|&(_, v)| v));
        out
    }

    /// The values of the residual notes this plan leaves in the source pool (its
    /// [`PrepOutput::Change`] outputs): at most one worth a fee, plus any sub-fee dust.
    pub fn residual_notes(&self) -> Vec<Zatoshis> {
        self.all_outputs()
            .filter_map(|o| match o {
                PrepOutput::Change(v) => Some(*v),
                _ => None,
            })
            .collect()
    }

    /// The number of residual notes this plan leaves (see
    /// [`residual_notes`](Self::residual_notes)).
    pub fn residual_count(&self) -> usize {
        self.residual_notes().len()
    }

    /// Whether this plan is a valid solution of the preparation problem for the given inputs: it
    /// mints exactly the requested `funding` multiset, zero-valued requests excluded; no
    /// transaction exceeds the [`PREP_TX_ACTIONS`] budget; every transaction conserves value net of
    /// `fee_per_tx`; and every note it spends exists, carries the value claimed for it, comes from a
    /// strictly earlier layer when it is a [`PrepInput::Prior`], and is spent at most once.
    pub fn is_valid(
        &self,
        available: &[Zatoshis],
        funding: &[Zatoshis],
        fee_per_tx: Zatoshis,
    ) -> bool {
        // Mints exactly the requested funding notes, as a multiset. Zero-valued requests are
        // dropped, matching `plan_preparation`, which never mints a note worth nothing.
        let mut minted = self.funding_notes();
        let mut requested: Vec<Zatoshis> = funding
            .iter()
            .copied()
            .filter(|&v| v != Zatoshis::ZERO)
            .collect();
        minted.sort_unstable();
        requested.sort_unstable();
        if minted != requested {
            return false;
        }

        let fee = u64::from(fee_per_tx);
        // Which source notes and which earlier-layer outputs have been consumed, so a plan that
        // spends one note twice is rejected rather than ranked.
        let mut spent_source = vec![false; available.len()];
        let mut spent_prior: Vec<(usize, usize, usize)> = Vec::new();

        for (layer_index, layer) in self.layers.iter().enumerate() {
            for tx in layer {
                if tx.inputs.is_empty()
                    || tx.outputs.is_empty()
                    || tx.action_count() > PREP_TX_ACTIONS
                {
                    return false;
                }
                let inputs: u64 = tx.inputs.iter().map(|i| u64::from(i.value())).sum();
                let outputs: u64 = tx.outputs.iter().map(|o| u64::from(o.value())).sum();
                if inputs != outputs + fee {
                    return false;
                }
                for input in &tx.inputs {
                    match *input {
                        PrepInput::Wallet { index, value } => {
                            if available.get(index) != Some(&value) {
                                return false;
                            }
                            if core::mem::replace(&mut spent_source[index], true) {
                                return false;
                            }
                        }
                        PrepInput::Prior {
                            layer,
                            transaction,
                            output,
                            value,
                        } => {
                            // A dependency must point strictly backwards, or the layers do not
                            // describe a broadcast order at all.
                            if layer >= layer_index {
                                return false;
                            }
                            let produced = self
                                .layers
                                .get(layer)
                                .and_then(|l| l.get(transaction))
                                .and_then(|t| t.outputs.get(output));
                            if produced.map(PrepOutput::value) != Some(value) {
                                return false;
                            }
                            if spent_prior.contains(&(layer, transaction, output)) {
                                return false;
                            }
                            spent_prior.push((layer, transaction, output));
                        }
                    }
                }
            }
        }

        // A note used directly as a funding note must exist, be worth the value claimed, and not
        // also be spent by a transaction.
        for &(index, value) in &self.direct_funding {
            if available.get(index) != Some(&value) {
                return false;
            }
            if core::mem::replace(&mut spent_source[index], true) {
                return false;
            }
        }

        true
    }
}

/// A rule for turning the wallet's source notes into the funding notes a migration run needs.
///
/// An implementation MUST be a deterministic function of its arguments; [`Portfolio::best_plan`]'s
/// guarantees hold only under that assumption. Several strategies compose into a [`Portfolio`].
pub trait PreparationStrategy {
    /// A stable identifier for this rule, unique among the strategies a caller runs together.
    fn name(&self) -> &'static str;

    /// Plan the transactions that mint `funding` from `available`, reserving `fee_per_tx` per
    /// transaction. Same contract as [`plan_preparation`].
    fn plan(
        &self,
        available: &[Zatoshis],
        funding: &[Zatoshis],
        fee_per_tx: Zatoshis,
    ) -> Result<PreparationPlan, PrepError>;
}

/// How good a [`PreparationPlan`] is, as a TOTAL order: smaller is better.
///
/// The criteria are compared lexicographically: the number of layers, then the number of
/// transactions, then the number of residual notes, then a canonical encoding of the plan. That
/// last criterion is injective up to plan equality, so distinct plans never compare equal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanQuality {
    layers: usize,
    transactions: usize,
    residual_notes: usize,
    shape: Vec<u64>,
}

impl PlanQuality {
    /// Measure `plan`.
    pub fn of(plan: &PreparationPlan) -> Self {
        PlanQuality {
            layers: plan.layer_count(),
            transactions: plan.transaction_count(),
            residual_notes: plan.residual_count(),
            shape: encode_shape(plan),
        }
    }

    /// The number of sequential layers, the criterion compared first.
    pub fn layers(&self) -> usize {
        self.layers
    }

    /// The number of preparation transactions, the criterion compared second.
    pub fn transactions(&self) -> usize {
        self.transactions
    }

    /// The number of residual notes left in the source pool, the criterion compared third.
    pub fn residual_notes(&self) -> usize {
        self.residual_notes
    }
}

/// A faithful encoding of a plan as a sequence of integers, injective up to plan equality: two plans
/// encode identically exactly when they are equal. Used only as [`PlanQuality`]'s final tie-break,
/// so that the total order is antisymmetric and the portfolio's choice never depends on the order
/// its strategies were listed in.
fn encode_shape(plan: &PreparationPlan) -> Vec<u64> {
    let mut out = Vec::new();
    out.push(plan.direct_funding.len() as u64);
    for &(index, value) in &plan.direct_funding {
        out.push(index as u64);
        out.push(u64::from(value));
    }
    out.push(plan.layers.len() as u64);
    for layer in &plan.layers {
        out.push(layer.len() as u64);
        for tx in layer {
            out.push(tx.inputs.len() as u64);
            for input in &tx.inputs {
                match *input {
                    PrepInput::Wallet { index, value } => {
                        out.extend_from_slice(&[0, index as u64, u64::from(value)]);
                    }
                    PrepInput::Prior {
                        layer,
                        transaction,
                        output,
                        value,
                    } => out.extend_from_slice(&[
                        1,
                        layer as u64,
                        transaction as u64,
                        output as u64,
                        u64::from(value),
                    ]),
                }
            }
            out.push(tx.outputs.len() as u64);
            for output in &tx.outputs {
                let role = match output {
                    PrepOutput::Funding(_) => 0,
                    PrepOutput::Intermediate(_) => 1,
                    PrepOutput::Change(_) => 2,
                };
                out.extend_from_slice(&[role, u64::from(output.value())]);
            }
        }
    }
    out
}

/// A plan that passed its certificate, labelled with the strategy that produced it.
type Ranked = Option<(&'static str, PreparationPlan)>;

/// A set of [`PreparationStrategy`]s to run on one instance, as a type-level list: `()` is the
/// empty portfolio, and `(head, tail)` extends `tail` with one more strategy, so a set of three is
/// written `(A, (B, (C, ())))`.
pub trait Portfolio {
    /// The best plan any strategy in this portfolio produces for the given instance, labelled with
    /// the name of the strategy that produced it, ranked by [`PlanQuality`]; `None` when no
    /// strategy returns a plan that passes [`PreparationPlan::is_valid`].
    ///
    /// Ordering the strategies differently, nesting them differently, or repeating one does not
    /// change the result, and extending a portfolio never worsens it. Both hold only while every
    /// strategy is deterministic, as [`PreparationStrategy`] requires.
    fn best_plan(
        &self,
        available: &[Zatoshis],
        funding: &[Zatoshis],
        fee_per_tx: Zatoshis,
    ) -> Ranked;
}

/// The empty portfolio produces no plan.
impl Portfolio for () {
    fn best_plan(&self, _: &[Zatoshis], _: &[Zatoshis], _: Zatoshis) -> Ranked {
        None
    }
}

impl<H, T> Portfolio for (H, T)
where
    H: PreparationStrategy,
    T: Portfolio,
{
    fn best_plan(
        &self,
        available: &[Zatoshis],
        funding: &[Zatoshis],
        fee_per_tx: Zatoshis,
    ) -> Ranked {
        let (head, tail) = self;
        join(
            evaluate(head, available, funding, fee_per_tx),
            tail.best_plan(available, funding, fee_per_tx),
        )
    }
}

/// One strategy's plan, kept only if it passes [`PreparationPlan::is_valid`].
fn evaluate<S>(
    strategy: &S,
    available: &[Zatoshis],
    funding: &[Zatoshis],
    fee_per_tx: Zatoshis,
) -> Ranked
where
    S: PreparationStrategy + ?Sized,
{
    let plan = strategy.plan(available, funding, fee_per_tx).ok()?;
    plan.is_valid(available, funding, fee_per_tx)
        .then(|| (strategy.name(), plan))
}

/// The better of two candidates under [`PlanQuality`], preferring either over `None`.
fn join(left: Ranked, right: Ranked) -> Ranked {
    match (left, right) {
        (Some(left), Some(right)) => {
            if PlanQuality::of(&left.1) <= PlanQuality::of(&right.1) {
                Some(left)
            } else {
                Some(right)
            }
        }
        (candidate, None) | (None, candidate) => candidate,
    }
}

/// Why a preparation plan could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepError {
    /// The available notes cannot fund every requested funding note plus the per-transaction fees.
    InsufficientFunds,
    /// The total of the available (or requested funding) note values exceeds the maximum money
    /// supply, so no consistent plan exists.
    BalanceInvalid,
}

impl fmt::Display for PrepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrepError::InsufficientFunds => {
                f.write_str("available notes cannot fund the requested notes plus preparation fees")
            }
            PrepError::BalanceInvalid => {
                f.write_str("the note values exceed the maximum money supply in total")
            }
        }
    }
}

impl core::error::Error for PrepError {}

/// The strategies [`plan_preparation`] runs.
const STRATEGIES: (FirstFitDecreasing, (LayeredGreedy, ())) =
    (FirstFitDecreasing, (LayeredGreedy, ()));

/// Plan the note-preparation transactions that mint `funding` (the self-funding note values, in
/// zatoshi) from `available` (the wallet's spendable source-pool note values, in zatoshi), reserving
/// `fee_per_tx` zatoshi for each transaction (the ZIP-317 fee of a padded [`PREP_TX_ACTIONS`]-action
/// transaction).
///
/// Returns the best plan, ranked by [`PlanQuality`], that any of the strategies the crate ships
/// produces; which strategy that is may change between releases. Call [`Portfolio::best_plan`] to
/// run a chosen set of strategies instead.
///
/// Returns an empty plan when `funding` is empty, [`PrepError::BalanceInvalid`] when the available or
/// requested totals are not representable amounts, and [`PrepError::InsufficientFunds`] when no
/// strategy could cover the funding notes plus the per-transaction fees.
pub fn plan_preparation(
    available: &[Zatoshis],
    funding: &[Zatoshis],
    fee_per_tx: Zatoshis,
) -> Result<PreparationPlan, PrepError> {
    plan_preparation_with(&default_portfolio(), available, funding, fee_per_tx)
}

/// The strategies [`plan_preparation`] runs, for a caller that wants to plan against a different
/// set and compare.
pub fn default_portfolio() -> impl Portfolio {
    STRATEGIES
}

/// As [`plan_preparation`], against a chosen set of strategies rather than the ones the crate
/// ships.
pub fn plan_preparation_with<P: Portfolio>(
    portfolio: &P,
    available: &[Zatoshis],
    funding: &[Zatoshis],
    fee_per_tx: Zatoshis,
) -> Result<PreparationPlan, PrepError> {
    // A property of the INPUTS, not of any strategy, so it is settled once and reported the same way
    // however the strategy set changes.
    validate_instance(available, funding)?;
    portfolio
        .best_plan(available, funding, fee_per_tx)
        .map(|(_, plan)| plan)
        .ok_or(PrepError::InsufficientFunds)
}

/// Convert a planner-internal value to [`Zatoshis`]. Infallible by construction:
/// every strategy validates the available and funding totals at entry (see
/// [`validate_instance`]), and the affordability checks bound every note a plan mints by the
/// validated available total.
fn zat(value: u64) -> Zatoshis {
    Zatoshis::from_u64(value).expect("planner values are bounded by the validated totals")
}

/// Check that the available and requested note values each sum to a representable amount.
fn validate_instance(available: &[Zatoshis], funding: &[Zatoshis]) -> Result<(), PrepError> {
    for values in [available, funding] {
        let _: Zatoshis = values
            .iter()
            .copied()
            .sum::<Option<Zatoshis>>()
            .ok_or(PrepError::BalanceInvalid)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;

    use crate::denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN;
    use crate::engine::{
        plan_migration_with,
        tests::{MockBackend, test_net},
    };
    use crate::signing_rounds::SigningRoundBudget;
    use crate::testing::{MIGRATION_SCENARIOS, PREPARATION_VECTORS, preparation_fee_per_tx};

    /// Replay a strategy module's scenario table through a whole migration planned under
    /// `portfolio` alone: for each row, plan the named `MIGRATION_SCENARIOS` wallet with
    /// `plan_migration_with` and assert the preparation-transaction count, crossings, Keystone
    /// signing rounds, and migrated value (in units of 0.01 ZEC). Each strategy module keeps its
    /// own table; this is the one driver they all replay it through.
    pub(crate) fn assert_scenarios_under<Pf: Portfolio>(
        portfolio: &Pf,
        scenarios: &[(&str, usize, usize, usize, u64)],
    ) {
        /// One hundredth of a ZEC, the unit the migrated column is written in.
        const H: u64 = zcash_protocol::value::COIN / 100;
        /// Any fixed seed: the canonical decomposition does not consult the RNG.
        const SEED: u64 = 7;
        /// A post-NU6.3 chain tip to plan against.
        const TIP: u32 = 2_000_000;

        for (label, preparations, crossings, keystone_rounds, migrated) in scenarios {
            let scenario = MIGRATION_SCENARIOS
                .iter()
                .find(|sc| sc.label == *label)
                .expect("every row names a shared scenario");
            let backend = MockBackend::new(scenario.source_notes.to_vec(), TIP);
            let mut rng = ChaCha8Rng::seed_from_u64(SEED);
            let plan = plan_migration_with(
                portfolio,
                MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
                &test_net(),
                &backend,
                &mut rng,
            )
            .expect("this rule plans every shared scenario");

            assert_eq!(
                plan.preparation_tx_count(),
                *preparations,
                "{label}: preparations"
            );
            assert_eq!(plan.transfer_tx_count(), *crossings, "{label}: crossings");
            assert_eq!(
                plan.signing_round_count(SigningRoundBudget::KEYSTONE),
                *keystone_rounds,
                "{label}: Keystone rounds",
            );
            assert_eq!(
                u64::from(plan.value_migrated()) / H,
                *migrated,
                "{label}: migrated"
            );
        }
    }

    /// A representative padded [`PREP_TX_ACTIONS`]-action ZIP-317 fee reserve for the tests (each
    /// action costs one ZIP-317 marginal fee). The planner treats it opaquely.
    fn fee_per_tx() -> u64 {
        PREP_TX_ACTIONS as u64 * MARGINAL_FEE.into_u64()
    }

    /// Wrap test values as [`Zatoshis`] at the public boundary; the arithmetic in these tests stays
    /// in the readable u64 domain.
    fn zats(values: &[u64]) -> Vec<Zatoshis> {
        values.iter().map(|&v| zat(v)).collect()
    }

    // --- the strategy seam: the certificate, the order, and the portfolio ---

    /// A deliberately WORSE but valid strategy for the one-note, one-funding-note instance: it
    /// detours through a pointless consolidation, so its plan takes two layers where one suffices.
    /// It exists to check that the portfolio ranks the PLANS, not the strategies.
    struct Detour;

    impl PreparationStrategy for Detour {
        fn name(&self) -> &'static str {
            "detour"
        }

        fn plan(
            &self,
            available: &[Zatoshis],
            funding: &[Zatoshis],
            fee_per_tx: Zatoshis,
        ) -> Result<PreparationPlan, PrepError> {
            let ([note], [want]) = (available, funding) else {
                return Err(PrepError::InsufficientFunds);
            };
            let (note, want, fee) = (u64::from(*note), u64::from(*want), u64::from(fee_per_tx));
            let feeder = note.checked_sub(fee).ok_or(PrepError::InsufficientFunds)?;
            let change = feeder
                .checked_sub(fee + want)
                .ok_or(PrepError::InsufficientFunds)?;
            let mut split = vec![PrepOutput::Funding(zat(want))];
            if change > 0 {
                split.push(PrepOutput::Change(zat(change)));
            }
            Ok(PreparationPlan::from_parts(
                vec![
                    vec![PrepTransaction::from_parts(
                        vec![PrepInput::Wallet {
                            index: 0,
                            value: zat(note),
                        }],
                        vec![PrepOutput::Intermediate(zat(feeder))],
                    )],
                    vec![PrepTransaction::from_parts(
                        vec![PrepInput::Prior {
                            layer: 0,
                            transaction: 0,
                            output: 0,
                            value: zat(feeder),
                        }],
                        split,
                    )],
                ],
                Vec::new(),
            ))
        }
    }

    /// A strategy that returns a plan minting the WRONG notes. The portfolio must reject it on the
    /// certificate rather than rank it.
    struct Bogus;

    impl PreparationStrategy for Bogus {
        fn name(&self) -> &'static str {
            "bogus"
        }

        fn plan(
            &self,
            available: &[Zatoshis],
            _funding: &[Zatoshis],
            fee_per_tx: Zatoshis,
        ) -> Result<PreparationPlan, PrepError> {
            let [note] = available else {
                return Err(PrepError::InsufficientFunds);
            };
            let minted = u64::from(*note)
                .checked_sub(u64::from(fee_per_tx))
                .ok_or(PrepError::InsufficientFunds)?;
            // One output, worth whatever is left: value-conserving, but not what was asked for.
            Ok(PreparationPlan::from_parts(
                vec![vec![PrepTransaction::from_parts(
                    vec![PrepInput::Wallet {
                        index: 0,
                        value: *note,
                    }],
                    vec![PrepOutput::Funding(zat(minted))],
                )]],
                Vec::new(),
            ))
        }
    }

    /// A strategy that never produces a plan, standing for the bottom of the lattice.
    struct NeverPlans;

    impl PreparationStrategy for NeverPlans {
        fn name(&self) -> &'static str {
            "never-plans"
        }

        fn plan(
            &self,
            _available: &[Zatoshis],
            _funding: &[Zatoshis],
            _fee_per_tx: Zatoshis,
        ) -> Result<PreparationPlan, PrepError> {
            Err(PrepError::InsufficientFunds)
        }
    }

    /// The one-note instance the portfolio tests share: a single source note worth the funding note
    /// plus three fees, so both the greedy (one layer) and the `Detour` (two layers, the second
    /// leaving a fee-sized change note) can fund it.
    fn portfolio_instance() -> (Vec<Zatoshis>, Vec<Zatoshis>, Zatoshis) {
        let fee = fee_per_tx();
        let want = 100_000u64;
        (zats(&[want + 3 * fee]), zats(&[want]), zat(fee))
    }

    /// The portfolio ranks PLANS, not strategies: the greedy's one-layer plan beats the `Detour`'s
    /// two-layer plan, whichever order the two are listed in.
    #[test]
    fn best_plan_prefers_the_shallower_plan() {
        let (available, funding, fee) = portfolio_instance();
        let greedy = plan_preparation(&available, &funding, fee).expect("the greedy plans");
        let detour = Detour
            .plan(&available, &funding, fee)
            .expect("the detour plans");
        assert_eq!(greedy.layer_count(), 1);
        assert_eq!(detour.layer_count(), 2);
        assert!(
            detour.is_valid(&available, &funding, fee),
            "the detour is valid, just worse"
        );
        assert!(PlanQuality::of(&greedy) < PlanQuality::of(&detour));

        // The two nestings are DIFFERENT TYPES, so this also exercises both monomorphisations.
        let expected = Some(("layered-greedy", greedy));
        assert_eq!(
            (LayeredGreedy, (Detour, ())).best_plan(&available, &funding, fee),
            expected,
        );
        assert_eq!(
            (Detour, (LayeredGreedy, ())).best_plan(&available, &funding, fee),
            expected,
        );
    }

    /// [`Portfolio::best_plan`] is a join in a bounded semilattice: idempotent, commutative,
    /// associative, with "no plan" as bottom. Observably, the result is the same for any nesting
    /// order, grouping or repetition of the strategies, which is what makes the list safe to extend
    /// over time. Every portfolio below is a distinct TYPE, so each law is checked against its own
    /// monomorphisation rather than against one function walking a slice.
    #[test]
    fn best_plan_is_a_semilattice_join() {
        let (available, funding, fee) = portfolio_instance();
        // Each portfolio below is a distinct TYPE, so a closure cannot stand in for `best` here: a
        // closure is monomorphic and would fix itself to whichever one it saw first. A generic
        // function is what lets one name run every one of them, still statically dispatched.
        fn best<P: Portfolio>(
            portfolio: P,
            instance: &(Vec<Zatoshis>, Vec<Zatoshis>, Zatoshis),
        ) -> Ranked {
            portfolio.best_plan(&instance.0, &instance.1, instance.2)
        }
        let i = &(available, funding, fee);

        // Bottom: the empty portfolio, and a strategy that never plans, are both the identity.
        assert_eq!(best((), i), None);
        assert_eq!(best((NeverPlans, ()), i), None);
        assert_eq!(
            best((LayeredGreedy, (NeverPlans, ())), i),
            best((LayeredGreedy, ()), i)
        );

        // Idempotent and commutative.
        assert_eq!(
            best((LayeredGreedy, (LayeredGreedy, ())), i),
            best((LayeredGreedy, ()), i)
        );
        assert_eq!(
            best((LayeredGreedy, (Detour, ())), i),
            best((Detour, (LayeredGreedy, ())), i)
        );

        // Independent of the nesting order across the whole list: all six permutations of three.
        let expected = best((LayeredGreedy, (Detour, (NeverPlans, ()))), i);
        assert_eq!(
            best((LayeredGreedy, (NeverPlans, (Detour, ()))), i),
            expected
        );
        assert_eq!(
            best((Detour, (LayeredGreedy, (NeverPlans, ()))), i),
            expected
        );
        assert_eq!(
            best((Detour, (NeverPlans, (LayeredGreedy, ()))), i),
            expected
        );
        assert_eq!(
            best((NeverPlans, (LayeredGreedy, (Detour, ()))), i),
            expected
        );
        assert_eq!(
            best((NeverPlans, (Detour, (LayeredGreedy, ()))), i),
            expected
        );

        // Associative: folding the whole list equals folding the parts and joining the results.
        assert_eq!(
            join(
                best((LayeredGreedy, ()), i),
                best((Detour, (NeverPlans, ())), i)
            ),
            expected,
        );
    }

    /// An invalid plan is bottom, not a winner: a strategy that mints the wrong notes is rejected on
    /// the certificate, and cannot displace a valid plan by looking cheaper.
    #[test]
    fn best_plan_rejects_an_invalid_plan() {
        let (available, funding, fee) = portfolio_instance();
        let bogus = Bogus.plan(&available, &funding, fee).expect("bogus plans");
        // It would otherwise WIN: one layer, one transaction, no residual.
        assert!(
            PlanQuality::of(&bogus)
                < PlanQuality::of(&Detour.plan(&available, &funding, fee).unwrap())
        );
        assert!(!bogus.is_valid(&available, &funding, fee));

        assert_eq!((Bogus, ()).best_plan(&available, &funding, fee), None);
        assert_eq!(
            (Bogus, (LayeredGreedy, ()))
                .best_plan(&available, &funding, fee)
                .map(|(name, _)| name),
            Some("layered-greedy"),
        );
    }

    /// The certificate has teeth: each way of corrupting a valid plan is caught.
    #[test]
    fn is_valid_rejects_a_tampered_plan() {
        let fee = zat(fee_per_tx());
        let available = zats(&[1_000_000]);
        let funding = zats(&[100_000, 50_000]);
        let plan = plan_preparation(&available, &funding, fee).expect("plans");
        assert!(plan.is_valid(&available, &funding, fee));

        // A funding note that is not minted.
        let mut short = plan.clone();
        short.layers[0][0]
            .outputs
            .retain(|o| !matches!(o, PrepOutput::Funding(_)));
        assert!(
            !short.is_valid(&available, &funding, fee),
            "missing funding output"
        );

        // Value created out of nothing.
        let mut inflated = plan.clone();
        inflated.layers[0][0]
            .outputs
            .push(PrepOutput::Change(zat(1)));
        assert!(
            !inflated.is_valid(&available, &funding, fee),
            "value not conserved"
        );

        // The same source note spent twice.
        let doubled = PreparationPlan::from_parts(
            vec![vec![plan.layers[0][0].clone(), plan.layers[0][0].clone()]],
            Vec::new(),
        );
        assert!(!doubled.is_valid(&available, &funding, fee), "double spend");

        // A source note that does not exist at that index.
        let mut off_index = plan.clone();
        off_index.layers[0][0].inputs = vec![PrepInput::Wallet {
            index: 7,
            value: available[0],
        }];
        assert!(
            !off_index.is_valid(&available, &funding, fee),
            "unknown source note"
        );

        // A dependency that does not point strictly backwards, so the layers are not a broadcast
        // order at all.
        let self_referential = PreparationPlan::from_parts(
            vec![vec![PrepTransaction::from_parts(
                vec![PrepInput::Prior {
                    layer: 0,
                    transaction: 0,
                    output: 0,
                    value: available[0],
                }],
                plan.layers[0][0].outputs.clone(),
            )]],
            Vec::new(),
        );
        assert!(
            !self_referential.is_valid(&available, &funding, fee),
            "a transaction cannot spend its own layer",
        );

        // More notes than the action budget allows.
        let oversized = PreparationPlan::from_parts(
            vec![vec![PrepTransaction::from_parts(
                vec![PrepInput::Wallet {
                    index: 0,
                    value: available[0],
                }],
                (0..PREP_TX_ACTIONS)
                    .map(|_| PrepOutput::Change(zat(1)))
                    .collect(),
            )]],
            Vec::new(),
        );
        assert!(
            !oversized.is_valid(&available, &funding, fee),
            "over the action budget"
        );
    }

    /// The public entry point IS the portfolio over the shipped strategies, so a strategy added to
    /// `STRATEGIES` reaches every caller without one of them changing.
    #[test]
    fn plan_preparation_is_the_portfolio() {
        let (available, funding, fee) = portfolio_instance();
        assert_eq!(
            plan_preparation(&available, &funding, fee).ok(),
            STRATEGIES
                .best_plan(&available, &funding, fee)
                .map(|(_, plan)| plan),
        );
    }

    /// The entry point is never worse than any single rule the crate ships: whatever a strategy
    /// can plan on its own, [`plan_preparation`] plans, and never with a worse [`PlanQuality`].
    ///
    /// This is what makes registering a strategy safe. It is a property of the PORTFOLIO, not of
    /// any rule, so it is checked here against every rule rather than restated in each of their
    /// modules.
    #[test]
    fn the_entry_point_is_never_worse_than_any_single_strategy() {
        fn assert_never_worse<S: PreparationStrategy>(strategy: &S) {
            let fee = preparation_fee_per_tx();
            for vector in PREPARATION_VECTORS {
                let (available, funding) = (zats(vector.available), zats(vector.funding));
                let Ok(alone) = strategy.plan(&available, &funding, fee) else {
                    continue;
                };
                let best = plan_preparation(&available, &funding, fee).unwrap_or_else(|e| {
                    panic!(
                        "[{}] `{}`: the entry point must plan what a rule plans, got {e:?}",
                        strategy.name(),
                        vector.label,
                    )
                });
                assert!(
                    PlanQuality::of(&best) <= PlanQuality::of(&alone),
                    "[{}] `{}`: the entry point returned the worse plan",
                    strategy.name(),
                    vector.label,
                );
            }
        }
        assert_never_worse(&LayeredGreedy);
        assert_never_worse(&FirstFitDecreasing);
    }

    /// A total that is not a representable amount is rejected on the inputs, before any strategy
    /// runs, so the error does not depend on which rules happen to be registered.
    #[test]
    fn an_unrepresentable_total_is_rejected_on_the_inputs() {
        let half = Zatoshis::const_from_u64(zcash_protocol::value::MAX_MONEY / 2 + 1);
        assert_eq!(
            plan_preparation(&[half, half], &zats(&[1]), zat(fee_per_tx())),
            Err(PrepError::BalanceInvalid),
        );
        assert_eq!(
            validate_instance(&[half, half], &[]),
            Err(PrepError::BalanceInvalid)
        );
    }
}
