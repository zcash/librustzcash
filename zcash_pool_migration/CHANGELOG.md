# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `signing_rounds::PlannedTx::depends_on` and
  `signing_rounds::PlannedTx::scheduled_height`: what each transaction of a
  plan will wait on, and when it will broadcast, as
  `engine::commit_preparation` will stamp them on the built transaction. A
  consumer can now preview a run's whole execution shape — its dependency graph
  and its timeline — from an unconsented `engine::MigrationPlan`, through the
  same two accessors the committed `engine::MigrationTransaction` answers with.
  `scheduled_height` is an `Option`, `None` being the plan that holds no drawn
  height for a transaction it contains: unconstructible through the public API,
  and refused by `engine::commit_preparation`, but reported rather than
  dropped so that no transaction's id depends on it.
- `engine::CommitError::NoOrchardViewingKey` and
  `engine::RebuildError::NoOrchardViewingKey`, reported by the entry points that
  need the account's Orchard full viewing key when `MigrationCrypto::orchard_fvk`
  has none to give.
- `engine::CommitError::WrongSpendAuthority` and
  `engine::RebuildError::WrongSpendAuthority`, reported when the spending key
  passed to a signing entry point is not the account's — its full viewing key is
  not the one the backend reports. Refused before anything is built, because
  signing cannot catch it: `build::sign_pczt` must skip a spend its key does not
  match (a migration PCZT carries padding dummies with throwaway keys), so a
  foreign key would sign nothing, succeed, and persist a run recorded as
  `Signed` whose transactions carry no signatures.
- `denomination::CanonicalOneTwoFive::with_max_notes`, the ZIP 318 canonical
  strategy with a caller-chosen per-run note count. Only the count is a
  parameter: the `{1, 2, 5} * 10^k` denomination set and its `DENOM_CAP` and
  `MAX_RESIDUAL_VALUE` bounds are normative ZIP 318 values, so they are not
  caller-settable and do not appear in the signature. A wallet chooses how big
  one run is; it never chooses which values cross the turnstile, because the
  privacy argument rests on every wallet publishing from the same set.
  `denomination::CanonicalOneTwoFive::recommended` now delegates to it.
- `engine::estimate_migration_runs_with`, the preview counterpart of
  `engine::plan_migration_with`: it takes the same preparation portfolio and the
  same per-run note cap, in the same order, so an application can preview the
  runs it is about to plan. The same values must be passed to both, or the
  preview will not describe the runs that get planned. Its cost scales inversely
  with the cap, since a bigger run means fewer runs to iterate.
- `signing_rounds::RunSigningCapacity`, `signing_rounds::RunShape` and
  `signing_rounds::largest_run_size_within`: bounding a run by what a signer will
  sign, and the search that turns that bound into a per-run note cap. This is the
  inverse of the round count in the run SIZE, as
  `signing_rounds::min_budget_for_rounds` is its inverse in the BUDGET. Under a
  round count non-decreasing in the cap — which the canonical decomposition
  gives — the chosen cap is the largest run the signer signs; otherwise it is
  still one that fits. The shape oracle returns an `Option`, and a `None` — no
  run can be built at that cap — is treated as not fitting, so a cap that cannot
  be planned is never preferred over one that can.
- `signing_rounds::RunShape::total_actions`, `engine::MigrationPlan::shape` and
  `engine::RunEstimate::shape`. A run's signer-facing quantities all derive from
  the same pair of transaction counts, so that pair is now named once and asked
  the questions directly: a plan and an estimate both hand out a
  `signing_rounds::RunShape` and delegate their action and round counts to it,
  instead of each deriving them again.
- `engine::plan_migration_for_signer` and
  `engine::plan_migration_for_signer_with`, which size a run by an external
  signer's capacity instead of by a note count, so one run is one signing
  session. A note cap cannot express that bound: a run's actions are
  `16 * preparations + 3 * transfers`, and the preparation count follows the
  wallet's fragmentation, so the same cap yields a one-round run for one wallet
  and a four-round run for another. Both sizings are supported;
  `engine::plan_migration` and `engine::plan_migration_with` are unchanged and
  keep sizing by note count. The resulting plan exceeds the signer's rounds only
  when a one-note run already does, which no smaller run can fix; the overflow is
  visible in `engine::MigrationPlan::signing_round_count`.
- `engine::estimate_migration_runs_for_signer` and
  `engine::estimate_migration_runs_for_signer_with`, the preview counterparts,
  taking exactly the planning functions' knobs. Sizing is per run, over that
  run's own note structure, so a wallet migrates fewer notes in the runs that
  consolidate its fragmentation and more once its notes are larger.
- `engine::RunSizing`, `engine::plan_migration_sized_with` and
  `engine::estimate_migration_runs_sized_with`: the bound as a VALUE (a note
  count or a signer capacity) and the entry points that take it, for an
  application that lets the user choose between the two and carries that choice.
  The fixed-bound entry points are these with one variant pre-chosen.
- `testing::arb_run_signing_capacity`, a `proptest` strategy over
  `signing_rounds::RunSigningCapacity`.

### Changed
- `denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN` is a `NonZeroUsize` where
  it was a `usize`. A run that prepares no notes migrates nothing, so zero is
  not a cap a caller can now express. Read it with `.get()` where a `usize` is
  wanted.
- `denomination::plan_denominations` takes a `NonZeroUsize` per-run note cap,
  after the spendable note count, and `engine::plan_migration_with` takes one in
  second position, after the portfolio. This is the only denomination knob a
  wallet may set; the denomination scheme and its ZIP 318 bounds remain fixed.
  `engine::plan_migration` is unchanged and passes
  `denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN`, as does
  `engine::estimate_migration_runs`.
- `engine::estimate_migration_runs` now plans each estimated run's preparation
  through the same portfolio the plan will use. It previously always estimated
  against the crate's default strategies, so an application planning under
  `engine::plan_migration_with` with a different portfolio could be previewed a
  run count that its own plans would not produce.
- `wallet::WalletMigration::new` takes the account's `UnifiedFullViewingKey`
  where it took a `UnifiedSpendingKey`, and is infallible. The adapter holds
  viewing authority and nothing else, and it holds the unified key WHOLE rather
  than reducing it to its Orchard component, so constructing one asks nothing of
  the key. A caller passes `usk.to_unified_full_viewing_key()` where it passed
  the spending key, or the account's own stored key. A watch-only account, or
  one whose spending key lives on a hardware wallet, is therefore an ordinary
  user of the adapter — it plans, builds and commits here and routes the signing
  to whoever holds the key.
- `engine::MigrationCrypto::orchard_fvk` returns
  `Option<&orchard::keys::FullViewingKey>` rather than a `Result`: a backend is
  handed the account's key rather than going to look for one, so producing it
  cannot fail, and `None` — a unified key with no Orchard component — is
  reported by the entry point that needs the key, at the point it needs it.
- The spend authority is now an ARGUMENT to the operations that sign, not
  something a backend holds: `engine::MigrationCrypto::sign` is gone, and
  `engine::commit_preparation`, `engine::commit_preparation_with_funding` and
  `engine::rebuild_expired_transfer` each take an
  `&orchard::keys::SpendingKey` (a caller holding a `UnifiedSpendingKey` passes
  `usk.orchard()`). The unsigned entry points —
  `engine::build_preparation_unsigned` and
  `engine::rebuild_expired_transfer_unsigned` — are unchanged and take none. A
  wallet backend therefore no longer has to hold, or be able to reach, its
  account's spending key in order to plan or build a migration, and "signing
  with no authority" is not a state any of these types can be in.

  They take the SPENDING key rather than the spend-authorizing key derived from
  it so that the key can be checked against the account's viewing key before
  anything is built (see `engine::CommitError::WrongSpendAuthority`). Nothing
  retains either key.
- `signing_rounds::PlannedTx` now carries its dependencies and its scheduled
  height, so it is `Clone` rather than `Copy`, and
  `signing_rounds::PlannedTx::new` takes them.
  `engine::MigrationPlan::planned_transactions` is now the single place a
  migration's `(id, depends_on, scheduled_height)` assignment is derived:
  `engine::commit_preparation` reads those rows rather than working the same
  rules out again while it builds, so a previewed run and the committed run
  cannot disagree. The plan likewise decides WHICH minted note each transaction
  spends, and the commit indexes its own recovered notes by that choice instead
  of searching for one again, so the note a crossing spends is necessarily the
  one whose producer that crossing was recorded as waiting on.
- `wallet::WalletMigration`'s `PoolMigrationRead::mined_height` now reads the
  wallet's fully-scanned height FIRST and reports nothing mined when there is
  none, rather than looking the transaction's mined height up first and then
  discarding it. The answer is unchanged wherever the old order produced one —
  nothing is promotable outside the scanned region either way — but a wallet
  that has never synced is now answered instead of surfacing whatever error its
  backend raises for a transaction lookup with no chain tip
  (`zcash_client_sqlite` raises one). Against `zcash_client_sqlite`'s own
  migration store — which applies the same bound in SQL — the adapter is now
  value-equal in every reachable state, which is why it delegates to no store:
  the equality is asserted for that pairing specifically, not claimed for every
  possible store.

### Removed
- `engine::MigrationCrypto::sign`, a required method of that trait. A backend is
  no longer asked to sign, so it need not be able to: the spend authority is an
  argument to `engine::commit_preparation`,
  `engine::commit_preparation_with_funding` and
  `engine::rebuild_expired_transfer`. An implementation should delete its `sign`
  method; a caller that relied on the backend signing passes `usk.orchard()` to
  those calls instead.
- `wallet::Error::Sign(BuildError)`, which reported a failure of that adapter
  method. A signing failure now arrives as `engine::CommitError::Build` or
  `engine::RebuildError::Build`, from the entry point that was given the key.

### Fixed
- `engine::rebuild_expired_transfer` and `engine::rebuild_expired_transfer_unsigned`
  now chain each rebuilt transfer's fresh scheduled height onto the latest
  pending transfer schedule rather than drawing it independently from the chain
  tip. Rebuilding several expired transfers at one tip previously scheduled
  them clustered around it, broadcasting the cohort as a linkable burst instead
  of the spread the ZIP 318 inter-arrival delays require.

## [0.1.0-rc.7] - 2026-08-07

### Added
- `engine::MigrationLockOwner`, the token identifying the holder of the
  wallet-side locks on a migration transaction's input notes.
- `engine::MigrationProver::lock_spent_notes` (required), called by
  `prove_transfer` and `prove_preparation` once the proof succeeds, so a
  transaction reserves the notes it spends for exactly as long as it is proved
  and awaiting broadcast. An implementation that models no lock state returns
  `Ok(None)`.
- `wallet::WalletProveError::Lock`, reporting a note that another flow has
  already reserved.
- `state::MigrationState::mark_cancelled`, which moves a non-terminal migration
  to that status. A no-op on an already-terminal migration, so terminality is
  never overwritten. This is a status change only: it does not release any hold
  the migration's transactions have on the wallet's notes.
- `engine::MigrationStatus::ALL`, `engine::MigrationStatus::is_terminal`, and
  `engine::MigrationStatus::terminal`, so that a store can express terminality
  as a query without restating which statuses are terminal.
- `engine::MigrationStatus::wire_name`, the stable lowercase wire name as a
  `&'static str` (which `AsRef<str>` cannot provide), for stores that embed
  status names in DDL or other `'static` text. `AsRef<str>` now delegates to
  it.
- `satisfiability::overdue_shift_tolerance`: how many blocks a step may lag the
  served target before `satisfiability::advance_migration` re-spreads the
  remaining broadcast schedule, as a function of the schedule's transfer delay
  distribution (a quarter of its mean; 16 blocks under the ZIP 318 parameters).
- `scheduling::redraw_anchor_boundary`: the recency-weighted anchor draw for a
  transfer whose broadcast schedule has moved, floored at the boundary being
  replaced.
- `satisfiability::Advance`: what one `satisfiability::advance_migration` call
  returns — the verified `state::AdvanceStep` to perform now, plus the outlook:
  the subsequent step's kind and the earliest target height at which it becomes
  serviceable, assuming the returned step is executed.
- `scheduling::PROVABLE_ANCHOR_DEPTH`: how many blocks below the wallet's
  fully-scanned tip a transfer's drawn anchor boundary must sit (at least)
  before the planning kernel offers the transfer's proof.
  `scheduling::WakeupParams::DEFAULT`'s settle margin is now defined as this
  constant; its value (10) is unchanged.
- `state::StepKind` and `state::AdvanceStep::kind`: an `AdvanceStep`'s variant
  without its payload.
- `preparation::PreparationStrategy`.
- `preparation::first_fit_decreasing::FirstFitDecreasing`, re-exported as
  `preparation::FirstFitDecreasing`.
- `preparation::plan_preparation_with` and `preparation::default_portfolio`, to
  plan against a chosen set of strategies rather than the ones the crate ships.
- `engine::plan_migration_with`, the same choice at the whole-migration level.
  It reaches the crossings as well as the preparation transactions, since the
  denomination decomposition asks the preparation planner what it can mint at
  every step.
- `preparation::layered_greedy::LayeredGreedy`, re-exported as
  `preparation::LayeredGreedy`.
- `preparation::PreparationPlan::is_valid`.
- `preparation::PlanQuality`.
- `preparation::Portfolio`, implemented for `()` and for `(H, T)` where `H:
  PreparationStrategy` and `T: Portfolio`, so a set of strategies is written
  `(A, (B, (C, ())))`.
- `testing::assert_strategy_conformance` and `testing::assert_dominates`, the
  conformance suite an implementation of `preparation::PreparationStrategy`
  inherits by calling them.

### Changed
- `wallet::WalletMigration` now snapshots the account's spendable Orchard
  notes on its first read and serves every later read from that snapshot, so
  a plan's note indices always resolve against the selection that produced
  them and committing a run performs one note selection instead of one per
  spent note. A consumer that held one adapter across changes to the wallet's
  spendable notes must construct a fresh adapter to observe them.
- `denomination::CanonicalOneTwoFive` (and so `denomination::plan_denominations`
  and every planning entry point above them) now computes the canonical split of
  the balance once and reconciles it against the wallet by dropping unfundable
  parts smallest-first, rather than substituting smaller denominations for the
  parts the preparation planner refused. The published crossing values are now
  always a prefix of the balance's canonical split, so they no longer depend on
  how the wallet's notes happen to hold the balance. A wallet that cannot fund
  the entire canonical split migrates a prefix of it in the current run, with
  the remainder deferred to a later run.
- `denomination::DenominationStrategy::plan` and
  `denomination::plan_denominations` now take the wallet's spendable note
  count alongside its balance. The count participates in the decomposition
  only through the predicate `count == 1`, which gates the exact-funding
  exception to the preparation-fee reserve: a lone note necessarily equals the
  balance, so a balance of exactly one canonical denomination plus its
  transfer buffer is certain to fund that crossing directly and reserves no
  fee, while the same balance held as two or more notes cannot avoid
  preparation and retains the reserve (stepping down the series) instead of
  quantizing into a split no such wallet could fund. Beyond that bit, the
  published values remain a function of the balance alone.
- `engine::MigrationError` has a new `UnfundableSplit` variant, and
  `engine::plan_migration` returns it (rather than `NothingToMigrate`) when the
  balance quantizes to at least one canonical part but the wallet's current
  notes cannot fund any part of that split — a wallet so fragmented that the
  preparation fees for consolidating it exceed what the balance can cover.
  This is deferral, not completion: value above the residual threshold
  remains, and it can migrate once the spendable balance changes.
  `NothingToMigrate` now means only that the balance itself has nothing left
  to quantize.
- `satisfiability::advance_migration` now returns `satisfiability::Advance`
  rather than a bare `state::AdvanceStep`: read the step to perform via
  `Advance::step`, and the outlook — when the migration next has work, and of
  what kind — via `Advance::next`, which replaces deriving the next wake-up
  from each transaction's scheduled height by hand.
- `preparation::plan_preparation` now returns the best plan produced by any of
  the strategies the crate ships, rather than the layered greedy's plan. Its
  signature, its errors and the plans it returns are unchanged. The plans
  differ: a wallet whose funding notes need a transaction that spends several
  notes and mints several is now planned in one transaction and one layer,
  where it previously took a chain of merges and splits across layers or could
  not be planned at all. A consumer that pinned the number of preparation
  transactions, the number of crossings, or the migrated value for a given
  wallet will see those change.
- A transfer's proof is now offered (`state::AdvanceStep::Prove`, and `ready`
  with `state::NextAction::Prove` in `state::MigrationState::transaction_statuses`)
  only once its drawn anchor boundary sits at least
  `scheduling::PROVABLE_ANCHOR_DEPTH` blocks below the wallet's fully-scanned
  tip, rather than merely strictly below it, so proofs are never built against
  a checkpoint a plausible reorg could displace. A consumer that polled for
  provability immediately after a boundary passed will observe the offer
  `PROVABLE_ANCHOR_DEPTH - 1` blocks later than before; the schedule re-spread
  in `satisfiability::advance_migration` does not count that gate-imposed wait
  as a missed schedule.
- `state::AdvanceStep::Prove` now carries `transactions: Vec<state::ProveTarget>`
  — every transaction provable right now, earliest-ready first — in place of a
  single `id` and its `kind`. Proving is not privacy-relevant, so one synced
  session proves everything it can rather than being offered one candidate per
  call. A consumer proves each entry in order; `ProveTarget::kind` selects the
  engine call and says whether the broadcast follows immediately (a
  preparation) or in its own later session (a transfer), exactly as the old
  `kind` field did. A consumer interrupted partway through a batch loses
  nothing, since the next call re-offers the unproved remainder. Consequently
  `state::AdvanceStep` and `satisfiability::Advance` are no longer `Copy`, and
  `satisfiability::Advance::step` returns a reference.
- `engine::MigrationStatus` has added variant `Cancelled`: a terminal status
  recording that the user abandoned the migration, distinct from `Failed` so
  that a deliberate abandonment is distinguishable from a migration that broke. 
- `engine::PoolMigrationRead::get_migration` is now explicitly PENDING-ONLY: a
  migration whose status is terminal is retained history and is not reported.
  A store implementation must filter terminal states out of this read (the
  shared conformance suite in `testing::conformance` now asserts it), and a
  consumer that used `get_migration` to render a finished migration should use
  its store's history accessors instead.
- `satisfiability::advance_migration` now re-spreads a missed broadcast
  schedule: when the `Prove` or `Broadcast` step it would surface is more than
  `satisfiability::overdue_shift_tolerance` blocks past its scheduled height at
  the served (estimated-tip) target — the tolerance derived from the transfer
  delay the migration's persisted anchor bucket interval implies — the
  scheduled height of every not-yet-broadcast transaction is first shifted
  forward by the overdue amount, and the shifted state is persisted with the
  call's other writes. After wallet downtime, at most one overdue step is
  released immediately; the rest keep their drawn inter-broadcast gaps instead
  of broadcasting as a cluster. A deferred transfer whose proof is still to
  come also has its anchor boundary redrawn against its shifted schedule
  (`scheduling::redraw_anchor_boundary`), keeping deferred anchors within the
  ZIP 318 age distribution; a proved transfer keeps the boundary its proof was
  built against. The function now takes a `CryptoRng` for those draws — pass
  the same RNG the other engine entry points use.
- `state::AdvanceStep` selection now offers, within each queue, the candidate
  that has been ready longest rather than the first one in storage order: the
  earliest scheduled height for a broadcast or a rebuild, and the earliest
  anchor boundary (a preparation: its scheduled height) for a proof, with ties
  broken by transaction id. Storage order is dependency order, which diverges
  from the schedule once `engine::rebuild_expired_transfer` reschedules a
  transfer in place.
- `engine::MigrationTransaction::lock_owner` and
  `MigrationTransaction::from_parts` now use `MigrationLockOwner` in place of a
  bare `[u8; 32]`.
- `engine::MigrationState::set_transaction_proved` takes the lock owner the
  transaction's notes were reserved under, so a store write persists the proven
  artifact and its lock token together.
- `wallet::WalletProveError` has a fourth type parameter, the lock store's
  error type.
- `wallet::WalletMigrationProver` implements `engine::MigrationProver` only for
  a wallet that is also an `OutputLockStore`.

### Removed
- `zip318_shape`, and with it `zip318_shape::evidence_from_pczt`. A consumer
  that gathered `zcash_protocol::zip318::Zip318Evidence` from an unmined PCZT
  must now assemble it from the `pczt` bundle observations itself.

## [0.1.0-rc.6] - 2026-08-03

### Added
- `engine::ProvedTransaction`: the proof carried out of a successful
  `engine::prove_transfer` / `engine::prove_preparation` call — the proven PCZT
  bytes and the row id they belong to — consumed only by
  `engine::PoolMigrationWrite::store_proved_transaction` (via its
  `ProvedTransaction::apply`).
- `engine::PoolMigrationWrite::store_proved_transaction` (required): records a
  successfully proved transaction on the migration state and persists it. An implementation over a wallet database
  must, atomically with that write, finalize the now fully-constructed
  transaction and persist it to the wallet's own transaction store (as
  `store_transactions_to_be_sent` records the standard spend flows), so the
  wallet's view protects the migration's inputs from its own spends between
  proving and broadcast. A store with no wallet-level transaction records
  implements it as `proven.apply(state)` followed by `replace_migration`.
- The `satisfiability` module, holding the vocabulary a store answers a
  committed migration's liveness questions in — `StepSatisfiability` and its
  causes, the observations they are folded from, and the caller policies they
  are judged under — together with the drive API built on those answers.
- `satisfiability::{AdvanceConfig, advance_migration}`, the API to drive a
  committed migration with. Call it at each wake-up with the
  `satisfiability::DuenessTargets` for the next `state::AdvanceStep`, perform
  that step, record the outcome, and call it again; every step it returns has
  been checked against the store's satisfiability oracle, and every
  determination it makes is persisted before the step is surfaced.
- `engine::PoolMigrationRead::mined_height` (required), answering whether this
  wallet's scan has observed a transaction mined, at or below its fully-scanned
  height. It and `check_step_satisfiability` must answer from one view of the
  wallet's scan. `satisfiability::advance_migration` asks it about every
  broadcast-but-unmined transaction it sweeps and promotes the ones that have
  mined, so which of a migration's transactions are mined now follows the wallet's
  scan in both directions: forward here, and backward through
  `MigrationState::truncate_to_height`. A consumer driving through
  `advance_migration` records only what it alone can know — that it broadcast —
  and no longer calls `MigrationState::mark_mined`, which remains for a consumer
  standing outside that loop. The promotion precedes every check that could
  record a verdict, so chain inclusion outranks an unsatisfiability mark and an
  open broadcast-failure report. The sweep also now records
  `satisfiability::UnsatisfiableCause::InputsSpent` for a broadcast transaction
  whose inputs it sees spent in some other mined transaction, which it previously
  dropped; such a transfer is known dead at that point rather than at its expiry.
- `pczt_txid`, deriving a migration transaction's `TxId` from its PCZT (`orchard` feature). A
  migration transaction's id exists from the moment its PCZT is PREPARED — computing it is a
  prerequisite of signing, since the signature hash is derived from it — and never moves
  afterwards: signing, and the anchor and witnesses ZIP 374 defers to proving, are all authorizing
  data, outside the effecting data the txid digest covers.
- `engine::MigrationTransaction::txid`, that id, recorded on every transaction when it is built and
  supplied to `MigrationTransaction::from_parts`. Only `rebuild_expired_transfer` changes it, and
  only because a rebuild is a genuinely different transaction.
- `satisfiability::advance_migration` additionally sweeps `Proved` transactions, promoting any the
  wallet's scan has seen mine — through `Broadcast`, since that is the state the missing record
  would have written. This closes the gap a recorded-txid sweep cannot see: a consumer that
  submitted a transaction to a node and then crashed, or failed to persist, before
  `MigrationState::mark_broadcast` leaves a `Proved` row whose transaction is on chain, which
  nothing else would ever promote. Consumers that carried their own submit-crash probe can delete
  it.
- `satisfiability::DuenessTargets`, the pair of heights a migration's dueness is
  judged against: the wallet's fully-scanned frontier and its estimate of where
  the chain tip has reached, both carrying this crate's target convention
  (`height + 1`). Construct it with `DuenessTargets::new(scanned, estimated)`,
  which clamps the effective target up to the scanned one, or with
  `DuenessTargets::at(target)` when the caller's estimate IS its chain view (a
  server that follows the chain continuously). ZIP 318 forbids contacting
  lightwalletd before the next-step decision, so a wallet holds only a local
  scanned frontier and a wall-clock estimate at that moment; the estimate serves
  the broadcast and proving SCHEDULE, while every judgment that persists a
  verdict or destroys work — expiry as a determination, the dead set, rebuild
  eligibility, the drain-time replan, the durable dependency closure, and a
  transfer's anchor-boundary settledness — is made at the scanned target alone.
- `state::Blocker::ExpiryImminent`, reported for a transaction whose expiry
  height is at or above the caller's scanned target and below its effective one:
  the wallet cannot yet observe whether it lapsed, so nothing is determined, but
  its broadcast and its proof are withheld. Reported behind `Blocker::Expired`
  (the same fact once the wallet can see it) and ahead of the state-derived
  blockers, and never `ready` or carrying an action, so a consumer's
  `ready() && action() == Some(NextAction::Broadcast)` sync gate agrees exactly
  with what `satisfiability::advance_migration` will offer. Nothing is recorded,
  so the transaction returns to the ordinary queues if the estimate overstated
  the lapse.
- `engine::MigrationStatus::Superseded` (wire name `"superseded"`) and
  `engine::MigrationState::mark_superseded`, the terminal status and transition
  recording that a migration's remaining value is being re-planned; a superseded
  migration is terminal, so the commit guard accepts a replacement.
- `satisfiability::ReplanThreshold`, the integer percent of planned transfer
  value, unsatisfiable, above which a migration is re-planned immediately rather
  than after satisfiable work drains; stamped on the migration at commit.
- `engine::MigrationState::{replan_threshold, replan_required}`: the accessor
  for the stamped threshold, and the derived determination of whether the
  unsatisfiable share of planned transfer value strictly exceeds it.
- `satisfiability::ReorgSettleDepth`, the caller-supplied number of blocks the
  chain must advance past a divergence before a displacement is treated as
  permanent.
- `satisfiability::StepSatisfiability` and `satisfiability::UnsatisfiableCause`:
  a store's answer to whether the environment obstructs a pre-signed
  transaction — executable now, not yet, or never (and why).
- `satisfiability::InputObservation` and
  `satisfiability::classify_input_observations`, the pure fold from
  per-nullifier observations plus the transaction-level expiry judgment into a
  `StepSatisfiability`, so every store implementation shares one classification
  and precedence.
- `engine::MigrationTransferId` now implements `PartialOrd` and `Ord`.
- `state::AdvanceStep::Replan`, the step directing the consumer to mark the
  migration superseded and re-plan its remaining balance through the ordinary
  planning flow.
- `state::Blocker::Unsatisfiable`, reported (ahead of `Blocker::Expired`) for a
  transaction whose inputs can never again all exist unspent on chain, directly
  observed or inherited from a dead dependency.
- `engine::MigrationState::record_satisfiability`, recording satisfiability
  answers as durable `unsatisfiable_at` marks: input-level and anchor-level
  causes mark the checked transaction at the observation's height, and the
  dependency closure marks the dependents stranded behind a dead transaction.
  Its `satisfiability::DuenessTargets` argument supplies the height that
  closure judges its expired sources at — the scanned target, since the marks
  it writes are durable and only a reorg truncation clears one.
- `engine::ProveFailure`, a prover's typed failure: an input not among the
  account's unspent notes (with the nullifier and the fully-scanned height that
  observation rests on), or any other prover error.
- `engine::ProveOutcome`, the outcome of a prove attempt the engine handled:
  proved, not yet provable, or marked unsatisfiable (carrying
  `replan_required` as it stands after the mark).
- `wallet::WalletProveError::ScannedHeight`, reported when the wallet's
  fully-scanned height could not be read and so a spend's absence from the
  unspent notes could not be classified.
- `engine::MigrationState::truncate_to_height`, which the consumer calls
  wherever it truncates its wallet on a reorg: clears every unsatisfiability
  mark above the given height, demotes mined transactions above it back to
  broadcast (keeping their txids), and reverts a `Complete` status to
  `InProgress`.
- `satisfiability::UnsatisfiableKind` and
  `satisfiability::ParseUnsatisfiableKindError`: the persisted, renderable
  discriminant of an unsatisfiability mark — `InputsSpent`,
  `InputsInvalidated`, `AnchorInvalidated`, or `Inherited` for a mark applied by
  the dependency closure — with `AsRef<str>` / `TryFrom<&str>` over its
  lowercase wire names. A store persists the name and reports an unrecognized
  one as corruption.
- `satisfiability::UnsatisfiableCause::kind`, the `UnsatisfiableKind` a cause
  records, or `None` for a cause that applies no mark (`Expired`).
- `engine::MigrationTransaction::unsatisfiable`, the unsatisfiability mark as
  one optional `(BlockHeight, UnsatisfiableKind)` pair — the chain height the
  observation rests on and which observation it was — with `unsatisfiable_at`
  and `unsatisfiable_kind` projecting its halves. A store that persists the
  halves separately must reject a row holding one without the other as corrupt
  on read.
- `state::TransactionStatus::unsatisfiable_kind`, populated exactly when
  `state::Blocker::Unsatisfiable` is reported. A transaction stranded behind a
  dependency whose deadness is merely derived (expired and unmined) carries no
  stored mark and reports `UnsatisfiableKind::Inherited`.
- `engine::RebuildError::Unsatisfiable`, returned by
  `engine::rebuild_expired_transfer` and
  `engine::rebuild_expired_transfer_unsigned` for a transfer that is itself
  marked `unsatisfiable_at`, or that depends on a transaction which is; it is
  reported ahead of `RebuildError::NotExpired`. Re-plan the migration's
  remaining balance rather than retrying the rebuild.
- `engine::MigrationState::report_broadcast_failure`, recording that a node
  REJECTED a broadcast of a `Proved` transaction, together with the chain tip
  that node reported. The report is testimony rather than evidence, so it
  records no unsatisfiability mark: it withholds the transaction from the
  broadcast queue until `satisfiability::advance_migration` can adjudicate the
  rejection against the wallet's own view. A re-report overwrites; a report on
  a transaction in any other state, or on an unknown id, is a no-op.
- `engine::MigrationTransaction::broadcast_failure_at`, the chain tip carried by
  a standing broadcast-failure report, or `None` when none stands. A store
  persists it independently of the unsatisfiability mark.
- `state::AdvanceStep::Reevaluate`, returned by
  `satisfiability::advance_migration` while a broadcast-failure report stands
  that the store's oracle cannot yet answer (its fully-scanned height is below
  the reported tip). Sync the wallet to at least that tip and call
  `advance_migration` again; it outranks every step but `Complete`, and no other
  work is offered while it stands.
- `state::Blocker::AwaitingReevaluation`, reported for a transaction carrying an
  unadjudicated broadcast-failure report — behind `Blocker::Unsatisfiable` and
  ahead of `Blocker::Expired`.
- The `pczt_spends` module (`orchard` feature), holding
  `pczt_spends::real_spend_nullifiers` — the `(action index,
  orchard::note::Nullifier)` of each real spend of an unproven migration PCZT's
  Orchard bundle — and its `pczt_spends::RealSpendError`. A store crate that
  reconstructs the real-spend nullifier cache from stored PCZT bytes can use
  this instead of restating the rule.

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.7`.
- `engine::ProveOutcome::Proved` now carries the `ProvedTransaction`, and
  `engine::prove_transfer` / `engine::prove_preparation` no longer write the
  proof into the migration state themselves: a caller discharges the returned
  proof through `PoolMigrationWrite::store_proved_transaction` (nothing else
  moves a transaction to `Proved`), and persists a `MarkedUnsatisfiable`
  outcome with `replace_migration` as before. `ProveOutcome` no longer
  implements `Clone`/`Copy`.
- `engine::MigrationState::mark_broadcast` no longer takes a `TxId`. The id is
  read off the row (`MigrationTransaction::txid`), which is the transaction's own and cannot have
  changed: a consumer broadcasting a stored transaction has nothing to tell the engine that the
  engine does not already know, and being able to pass a mismatched id was a way to lose track of
  a transaction that is on chain.
- `engine::MigrationState::{transaction_statuses, expired_transactions}` take an
  `satisfiability::DuenessTargets` in place of a single target height; pass
  `DuenessTargets::at(target_height)` for the previous behavior. Under a pair
  whose estimate runs ahead of the scan, `expired_transactions` and
  `state::Blocker::Expired` report only the expiries the wallet's own chain data
  supports, a transaction due only by the estimate is reported ready to
  broadcast, and one whose expiry the estimate has passed is reported under the
  new `state::Blocker::ExpiryImminent`.
- `engine::MigrationState::truncate_to_height` also discharges every
  broadcast-failure report whose observed tip is strictly above the given
  height, alongside the unsatisfiability marks it already cleared.
- `state::AdvanceStep::Prove` now also carries the transaction's
  `engine::MigrationTxKind`, so a consumer can tell without a lookup whether it
  is proving a preparation transaction — by construction due on its broadcast
  schedule, so broadcastable at the same wake-up once proved — or a transfer,
  whose broadcast follows at its own scheduled height. Match with
  `AdvanceStep::Prove { id, kind }`.
- `engine::MigrationState::mark_mined` also clears the transaction's
  unsatisfiability mark and its broadcast-failure report: chain inclusion
  outranks either judgment about whether it could ever mine, so neither can
  stand on a mined transaction. A consumer that read `unsatisfiable` or
  `broadcast_failure_at` off a mined transaction gets `None` where it may
  previously have seen a stale value; the derived `replan_required` share is
  unaffected, having always excluded mined transfers.
- `engine::MigrationTxState::Mined` now carries the mined transaction's txid
  alongside its height; `MigrationTxState::from_stored` requires the txid
  payload for `"mined"` rows, and `broadcast_txid` also answers for mined
  transactions.
- `state::TransactionStatus::txid` is now populated for a MINED transaction as
  well as a broadcast one; it previously lapsed to `None` once the transaction
  mined. A transaction keeps the txid it was broadcast under, so a consumer
  rendering progress no longer has to hold one from an earlier status view.
- `engine::MigrationTransaction::from_parts` takes four further parameters: the
  transaction's `TxId` (after `anchor_boundary`), `unsatisfiable` (the
  unsatisfiability mark, when the transaction has been determined
  unsatisfiable), `spend_nullifiers` (the transaction's real-spend nullifiers,
  cached from the built PCZT), and `broadcast_failure_at` (the standing
  broadcast-failure report); all four have accessors.
- `engine::MigrationState::from_parts` and the `engine::commit_preparation`,
  `engine::build_preparation_unsigned`, and
  `engine::commit_preparation_with_funding` entry points each take a further
  `satisfiability::ReplanThreshold` parameter, stamped on the committed
  migration.
- `engine::MigrationState::sync_wakeup_schedule` also excludes transfers marked
  unsatisfiable or dependent on a transaction that can never mine, alongside
  the expired transfers it already excluded.
- `engine::PoolMigrationRead` has a new required method,
  `check_step_satisfiability`: an implementation reports, for each cached
  real-spend nullifier of the given transaction, whether the note is unspent,
  seen spent in a mined transaction, known with a dead unmined creator, or
  unknown — plus the transaction-level expiry judgment and, for a
  broadcast-unmined transaction, whether its installed anchor survives on the
  chain judged settled per the supplied `satisfiability::ReorgSettleDepth` —
  and composes `satisfiability::classify_input_observations` into a
  `satisfiability::StepSatisfiability`. An empty nullifier cache on a non-mined
  transaction must surface the store's own error, never an answer.
- `engine::MigrationProver::{prove_transfer, prove_preparation}` now return
  `Result<pczt::Pczt, engine::ProveFailure<Self::Error>>`. An implementation
  reports a spend whose nullifier matches no note in the account's unspent set
  as `ProveFailure::InputNotAvailable`, carrying that nullifier and the
  fully-scanned height the absence rests on, and every other failure as
  `ProveFailure::Other`.
- `engine::{prove_transfer, prove_preparation}` now return
  `Result<engine::ProveOutcome, engine::ProveError<..>>`. An input reported
  unavailable is no longer an error: with every dependency's mined height
  covered by the wallet's scan it is recorded as a spent-input observation (the
  transaction is marked unsatisfiable and the dependency closure applied) and
  answered `ProveOutcome::MarkedUnsatisfiable`, and otherwise
  `ProveOutcome::NotYetProvable` with no state change. Match on the outcome,
  and persist the state after `MarkedUnsatisfiable` as after a successful
  proof.
- `engine::CommitError` and `engine::RebuildError` have two new variants:
  `RealSpends`, reported when a built (or rebuilt) migration PCZT presents no
  well-formed set of real spends to cache nullifiers from, and `TxId`, for a
  built PCZT whose transaction id cannot be derived.

### Removed
- `engine::MigrationState::{next_step, next_provable, next_broadcastable}`. The
  planning kernel is internal to the crate now;
  `satisfiability::advance_migration` is the API to drive a committed migration
  with, and every step it returns has been checked against the store's
  satisfiability oracle, which calling the kernel directly bypassed. Replace
  `state.next_step(target_height)` with
  `advance_migration(&mut store, &mut state, targets, &config)`, which returns
  the same `state::AdvanceStep`.
- `wallet::WalletProveError::{NoRealSpend, MalformedNullifier}`, replaced by the
  single `wallet::WalletProveError::RealSpends`, which carries the
  `pczt_spends::RealSpendError` describing which of the two conditions held.

### Fixed
- `engine::prove_transfer` now re-validates a transfer's persisted anchor boundary
  against its funding preparations' REAL mined heights, and re-draws it (via
  `scheduling::draw_anchor_boundary`, from the funding note's actual creation
  height and the wallet's scanned tip) when the funding note postdates the drawn
  boundary. Previously a preparation that mined later than the commit-time
  estimate left the boundary below the funding note's creation height, where the
  note's witness can never be computed and the transfer deferred forever: reported
  ready to prove, blocked on nothing, proving nothing. When no grid boundary at or
  past the funding note's creation has settled within the scanned tip yet, the
  answer is the ordinary `NotYetProvable` retry. `prove_transfer` takes the network
  parameters, the scanned tip, and an rng for this;
  `MigrationState::set_transfer_anchor_boundary` persists the fresh draw.
- `engine::rebuild_expired_transfer` and
  `engine::rebuild_expired_transfer_unsigned` no longer fail for a transfer
  that was proved or broadcast before it expired; the rebuild now identifies
  the funding note from the persisted real-spend nullifier cache instead of
  the stored (by then proven) PCZT.

## [0.1.0-rc.5] - 2026-07-29

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.6`.
- `scheduling::SchedulingParams::ZIP_318` adopts the revised ZIP 318 timing:
  transfer delays now have a mean of 66 blocks (previously 144) and
  preparation delays a mean of 16 blocks (previously a provisional 24), with
  both caps unchanged; the preparation delay is now defined by
  `zcash_protocol::zip318::{PREP_DELAY_MEAN, PREP_DELAY_CAP}`. The re-exported
  `scheduling::ANCHOR_AGE_CAP` is now 4 boundaries (previously 16).
- `scheduling::SchedulingParams::new_with_default_distributions` now scales
  each ZIP 318 delay mean and cap by the ratio of the given interval to the
  ZIP 318 one, instead of deriving the delays from fixed cap/mean ratios.

### Removed
- `scheduling::DELAY_CAP_RATIO` and `scheduling::PREP_MEAN_DIVISOR`; the
  revised ZIP 318 delay parameters are no longer related by fixed ratios. Read
  the means and caps from a `SchedulingParams` instead.

## [0.1.0-rc.4] - 2026-07-28

### Added
- `zcash_pool_migration::build::AccountDerivation`, the ZIP 32 account whose
  spending key authorizes a migration's Orchard spends. Behind the `orchard`
  feature; convertible from `zcash_client_backend`'s `Zip32Derivation` behind
  the `wallet` feature.
- `zcash_pool_migration::scheduling::{WakeupParams, SyncWakeup, WakeupScheduleError, schedule_sync_wakeups}`,
  computing the minimal schedule of sync-and-proving wake-up heights implied by a
  transfer schedule's drawn anchor boundaries and broadcast heights.
- `zcash_pool_migration::engine::MigrationState::sync_wakeup_schedule`, the above computed over a
  committed migration's transfers that still need proofs.

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.5`.
- The ZIP 318 constants this crate defined are now defined by `zcash_protocol::zip318`
  and re-exported from their existing paths. `denomination::MIGRATION_MAX_DENOMINATION_ZEC`
  is renamed to `denomination::DENOM_CAP` and `denomination::RESIDUAL_MIGRATION_MIN` to
  `denomination::MAX_RESIDUAL_VALUE`; `scheduling::{AnchorBucketInterval, DELAY_CAP_RATIO,
  ANCHOR_AGE_CAP, EXPIRY_MODULUS, EXPIRY_WINDOW}` and `preparation::PREP_TX_ACTIONS` keep
  their paths and values, as does `scheduling::expiry_height`.
- `denomination::DENOM_CAP` is a `Zatoshis` rather than a count of whole ZEC, and
  `CanonicalOneTwoFive::new` takes its maximum denomination as a `Zatoshis`. Pass the
  `Zatoshis` directly and drop any `* COIN`.
- `scheduling::AnchorBucketInterval` and `zcash_client_backend`'s
  `AnchorRetentionInterval` are now the same type; the `From` conversion between them is
  gone. Remove any `.into()` at that boundary.
- `zcash_pool_migration::build::{build_prep_tx, build_transfer_pczt}` take an
  additional `Option<&AccountDerivation>` argument, before the RNG. When it is
  supplied, every spend the built transaction still needs a signature for is
  stamped with the account's Orchard ZIP 32 key path, so an external Signer can
  identify those spends as the account's; previously they carried no derivation
  and such a Signer skipped them, leaving transactions that could not be
  extracted. Pass the account's derivation whenever the wallet knows it; pass
  `None` only for an account with no known derivation, whose transactions then
  only an in-process signer (which matches by key) can authorize.
- `zcash_pool_migration::engine::MigrationCrypto` has a new required method,
  `account_derivation`, supplying the above to the builders. Implement it by
  returning the account's derivation as the wallet records it.
- `zcash_pool_migration::wallet::WalletMigration` implements `MigrationCrypto`
  only where the wallet's `WalletRead::AccountId` and `InputSource::AccountId`
  are the same type, which is required to read the account's derivation.

## [0.1.0-rc.3] - 2026-07-26

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.4`.

### Removed
- The `transparent-inputs` feature flag. It enabled nothing, existing only as a
  marker for an end-to-end test that has moved to `zcash_client_sqlite`.

## [0.1.0-rc.2] - 2026-07-26

Initial release of the `zcash_pool_migration` crate.
