# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffolding of the backend-agnostic Orchard -> Ironwood value-pool migration engine crate.
- Note-split planning (the `note_splitting` module): decomposing a spendable source-pool balance into
  the self-funding notes that cross the turnstile. The module is pool-agnostic (its code names no
  specific pool); Zcash's first use is the Orchard -> Ironwood migration. The composition rule is
  abstracted behind the `DenominationStrategy` trait, with one implementation aligned with ZIP 318:
  - `CanonicalOneTwoFive`: the canonical `{1, 2, 5} * 10^k` quantization of ZIP 318, a deterministic
    descending greedy decomposition over that series (equivalently, decimal-digit expansion into
    `{5, 2, 1}` times each place value), e.g. 12,345 ZEC -> 10,000 + 2,000 + 200 + 100 + 20 + 20 + 5.
    Privacy rests on cross-wallet value collision, as ZIP 318 prescribes.
  The trait is retained as the seam for a future variant (such as ZIP 318's optional
  frequency-constrained randomized substitution). The strategy produces a `NoteSplitPlan` of
  self-funding notes (each holding its crossing value plus a fee buffer), mints denominations from a
  maximum (ZIP 318's `DENOM_CAP`, bounding a whale's crossings to the shared denomination set) down to
  a sub-1-ZEC dust floor (ZIP 318's `MAX_RESIDUAL_VALUE`), and leaves any residual below that floor as
  source-pool change rather than folded into a fee. The canonical fees come from the ZIP-317 fee
  rule applied to the canonical transaction shapes, computed once by the caller (the engine) and
  passed in: the strategy takes the per-note transfer-fee buffer, the per-transaction preparation
  fee, and a preparation-layout capability it consults at each step of the decomposition, so the
  true preparation cost (consolidation and fan-out layers included) is reserved as the split grows.
  The maximum denomination, dust floor, and note cap are strategy parameters. `plan_note_split` is a
  convenience wrapper over the recommended `CanonicalOneTwoFive`. The crate is `no_std` (it needs only `alloc`), depending on
  `zcash_protocol`, `zcash_primitives`, and `rand_core`.
- The pure PCZT transfer builder (`build::build_transfer_pczt`, behind the `orchard` feature): spends
  one self-funding note the note split minted and outputs its crossing value into the Ironwood pool as
  an unproven `pczt::Pczt`, sent to the account's own internal Ironwood change address (derived inside
  the builder, per ZIP 318). It has no change output; the note's fee buffer funds the transfer's fee
  exactly (the Orchard spend and the Ironwood output each pad to the two-action minimum, so the
  transfer is four logical actions, matching the buffer of `2 source + 2 destination` actions). It
  runs post-NU6.3 (when the Ironwood pool is live), is pure (no database or wallet-backend access),
  and takes the RNG as a parameter. Adds optional `orchard` and `pczt` dependencies, enabled only by
  the feature.
- Pre-signing (`build::sign_pczt`, behind the `orchard` feature): adds the Orchard spend-authorization
  signatures for a given `orchard::keys::SpendAuthorizingKey` to an assembled migration PCZT, leaving
  the spends the key does not own (the builder's dummy spends, and any spend from another account)
  unsigned. It signs a finalized but still UNPROVEN PCZT: the spend-authorization signature is over
  the transaction's sighash, which is fixed independently of the zk proofs, so the migration signs up
  front (capturing the account's authorization) and proves later, at scheduling time.
- Note-preparation transaction planning (the `preparation` module): a pure planner that partitions the
  work of minting a note-split plan's self-funding notes into note-preparation transactions of exactly
  `PREP_TX_ACTIONS` (16) Orchard actions, per ZIP 318, organised into the fewest sequential layers
  (with parallel transactions inside a layer). `plan_preparation` takes the wallet's spendable
  source-pool note values, the target funding-note values, and a per-transaction fee reserve, and
  returns a `PreparationPlan` of `PrepTransaction`s (each a same-pool send-to-self referencing wallet
  notes or earlier layers' outputs). It uses a largest-first greedy: feed each output transaction from
  the largest note, route every leftover forward as a feeder note, and consolidate dust; once the
  funding notes are scheduled it consolidates the leftover feeders into a single residual note, per
  ZIP 318's "one note per part plus at most one residual note". A typical wallet needs one layer, and
  extra layers appear only for a lone large note fanning out into many funding notes or a dust-heavy
  balance. It is pure (no cryptography or I/O) and `no_std`.
- The pure PCZT note-preparation builder (`build::build_prep_tx`, behind the `orchard` feature): turns
  one `preparation::PrepTransaction`'s resolved input notes and its outputs into an unproven
  `pczt::Pczt` for a same-pool Orchard send-to-self. Every output (funding, feeder, or residual) is a
  wallet-controlled internal change note, and the Orchard bundle is built with `pad_to_minimum` set to
  `PREP_TX_ACTIONS` (16), so orchard fills it to exactly that many actions with fabricated dummies and
  no preparation transaction is distinguishable by its action count (ZIP 318). It returns each
  output's real post-shuffle action
  index so the caller can locate the notes (and spend the feeders in a later layer). Like the other
  builders it is pure (no database or wallet-backend access) and takes the RNG as a parameter.
- Transfer scheduling and anchor selection (the `scheduling` module): a pure planner, per ZIP 318,
  that decides WHEN each migration transfer is broadcast, WHICH Orchard boundary anchor it proves
  against, and WHEN it expires. It works only in block heights and part indices (no cryptography, no
  note tree, no I/O), takes the RNG as a parameter, and is `no_std`. It implements: `shuffle_indices`
  / `shuffle_in_place` (a uniform Fisher-Yates shuffle so the broadcast order of denominations is
  independent of the balance); `draw_delay` (a truncated exponential inter-arrival delay, mean
  `MEAN_DELAY` = 144 blocks, discard-and-redraw above `MAX_DELAY` = 576, sampled by inverse-CDF);
  `schedule_broadcast_heights` / `schedule` (cumulative per-part broadcast heights from the commit
  height, paired with the canonical expiry); `draw_anchor_boundary` (a recency-weighted
  `Geometric(1/2)` age draw over the candidate boundaries above NU6.3 activation, at/after the funding
  note's creation, and below the most recent boundary, so transfers share common anchors in cohorts,
  and age 0 is never used); `draw_anchor_boundary_bounded` with `BoundaryCounts` / `group_by_boundary`
  (the provisional `K_MAX` per-wallet multiplicity cap, a SHOULD and still an open ZIP issue); and
  `expiry_height` (the canonical rolling window anchored to `EXPIRY_MODULUS` = 34560 blocks plus
  `EXPIRY_WINDOW` = 69120, giving 1 to 2 months of validity as a pure function of the height). The
  engine-enforced MUSTs (sync/broadcast decoupling, and at most one overdue transfer at wallet open)
  are documented as out of scope for this pure module. The exponential draw's natural log uses `libm`,
  since the crate is `no_std` and `std`'s `f64::ln` is unavailable.
- The migration engine (the `engine` module): orchestration of a pool migration through a
  `MigrationBackend` trait. `plan_migration` reads the account's spendable note values and the chain
  tip from the backend, computes the canonical ZIP-317 fees once from the canonical transaction
  shapes (the fee rule is fixed, since ZIP 318 requires the canonical fee), decomposes the balance
  into denominations (`note_splitting`) with the preparation planner (`preparation`) consulted at
  each step for the true fee cost, schedules the transfers (`scheduling`), and returns a
  `MigrationPlan` preview for user consent. It defines the persisted state model
  - a `MigrationState` (status, the note split, the reconciled funding-note values, and the
  transactions) of `MigrationTransaction`s (each a stable id, kind, the pre-signed PCZT as bytes,
  dependencies, scheduled and expiry heights, drawn anchor boundary, and lifecycle state) - and the
  `MigrationBackend` persistence methods (`store_migration` / `load_migration` /
  `update_transaction`), so a committed migration is stored as the pre-signed PCZTs the consuming
  application later proves and broadcasts, and resumes after a restart. Building and signing use the
  `orchard`-gated `MigrationCrypto` trait (the account's viewing key, its spendable notes'
  plaintexts, and signing). Every transaction's anchors and witnesses are deferred to proving time
  (ZIP 374), so a spent note's plaintext fully determines the signed data — including notes minted
  by earlier, still-unmined migration transactions, recovered from their built bundles — and
  `commit_preparation` builds and signs the WHOLE migration (every preparation layer in topological
  order, then every transfer) in ONE signing phase, before anything is broadcast; mining gates only
  the broadcast order. Planning is pure (`no_std`); proving (installing each transaction's anchor
  and witnesses through the PCZT Updater role) and reconciliation-on-launch are consumer
  responsibilities, the latter added by a later slice.
- An external-signer seam on the `engine` module (behind the `orchard` feature), so a hardware or
  offline signer can sign a migration's transactions out of band. `build_preparation_unsigned`
  mirrors `commit_preparation` but leaves every transaction UNSIGNED in a new
  `MigrationTxState::AwaitingSignature` state and returns their serialized PCZTs
  (`UnsignedMigrationTx`, paired with the transaction id and its padded action count) in
  topological order; `batch_unsigned_by_action_budget` splits them into signing sessions bounded
  by the device's per-interaction action budget — consecutive prefixes, never gated on mining.
  Once the device returns a signed PCZT, `MigrationState::apply_signature` stores it and moves the
  transaction to `Signed`, after which the normal state machine broadcasts it unchanged (proving
  remains a consumer responsibility, as for in-process signing). External signing therefore
  replaces only the sign step; the rest of the lifecycle is identical. The status view surfaces an
  awaiting transaction as blocked on `Blocker::Signature`.
- Canonical binary codecs on the migration types (`PreparationPlan`, `NoteSplitPlan`,
  `PrepInput`/`PrepOutput`/`PrepTransaction`, `MigrationTxKind`, and `MigrationTxId`), plus
  `MigrationTxState`'s `AsRef<str>` discriminant and `from_stored` reconstruction, all built on
  `zcash_encoding` over `corez::io`, so a persistence backend serializes the types through their own
  `write`/`read` rather than a bespoke codec.
- A `testing` module (behind the `test-dependencies` feature) with reusable proptest strategies
  (`arb_migration_state` and the per-type `arb_*` it composes) and a store-conformance suite
  (`assert_empty_is_none`, `assert_put_get_roundtrip`, `assert_put_replaces`,
  `assert_update_transaction`) that exercises any `PoolMigrationRead` / `PoolMigrationWrite`
  implementation, so every store shares one test suite.
