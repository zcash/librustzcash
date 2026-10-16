//! `proptest` strategies over the engine's persisted types.
//!
//! Every `arb_*` here generates a value of a type a store must round-trip, from a single
//! `Zatoshis` up to a whole [`MigrationState`]. The crate's own codec proptests consume them, and
//! so does any downstream store crate: generating the SAME values everywhere is what makes one
//! store's coverage comparable to another's.

use core::num::{NonZeroU32, NonZeroUsize};

use proptest::prelude::*;

use zcash_primitives::transaction::testing::arb_txid;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::consensus::testing::arb_block_height;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::value::testing::arb_zatoshis;

use crate::denomination::DenominationPlan;
use crate::engine::{
    MigrationLockOwner, MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId,
    MigrationTxKind, MigrationTxState,
};
use crate::preparation::{PrepInput, PrepOutput, PrepTransaction, PreparationPlan};
use crate::satisfiability::{ReplanThreshold, UnsatisfiableKind};
use crate::scheduling::AnchorBucketInterval;
use crate::signing_rounds::{PlannedTx, RunSigningCapacity, SigningRoundBudget};

use alloc::vec::Vec;

// `arb_planned_txs` is a strategy OVER the shared workload builder, so the random and the
// fixed paths construct runs the same way.
use super::scenarios::planned_txs;

// --- leaf strategies ---

/// An arbitrary [`MigrationTransferId`] row key.
pub fn arb_migration_transfer_id() -> impl Strategy<Value = MigrationTransferId> {
    (0u32..1000).prop_map(MigrationTransferId::new)
}

// --- preparation-plan strategies (moved from `preparation`'s codec tests) ---

/// An arbitrary [`PrepInput`], exercising both tags.
pub fn arb_prep_input() -> impl Strategy<Value = PrepInput> {
    prop_oneof![
        (0usize..1000, arb_zatoshis())
            .prop_map(|(index, value)| PrepInput::Wallet { index, value }),
        (0usize..1000, 0usize..1000, 0usize..1000, arb_zatoshis()).prop_map(
            |(layer, transaction, output, value)| PrepInput::Prior {
                layer,
                transaction,
                output,
                value,
            }
        ),
    ]
}

/// An arbitrary [`PrepOutput`], exercising all three tags.
pub fn arb_prep_output() -> impl Strategy<Value = PrepOutput> {
    prop_oneof![
        arb_zatoshis().prop_map(PrepOutput::Funding),
        arb_zatoshis().prop_map(PrepOutput::Intermediate),
        arb_zatoshis().prop_map(PrepOutput::Change),
    ]
}

/// An arbitrary [`PrepTransaction`]. Like every transaction a real plan produces, it has at least
/// one input and one output (it spends notes and mints funding or change); a store may rely on this
/// to reconstruct the plan's layers/transactions grid from the input and output rows alone.
pub fn arb_prep_transaction() -> impl Strategy<Value = PrepTransaction> {
    (
        prop::collection::vec(arb_prep_input(), 1..6),
        prop::collection::vec(arb_prep_output(), 1..6),
    )
        .prop_map(|(inputs, outputs)| PrepTransaction::from_parts(inputs, outputs))
}

/// An arbitrary [`PreparationPlan`]: layers of transactions plus direct-funding notes. Like every
/// real plan, each layer is non-empty (a layer exists because transactions were placed in it),
/// though the plan may have no layers at all (all funding notes used directly).
pub fn arb_preparation_plan() -> impl Strategy<Value = PreparationPlan> {
    (
        prop::collection::vec(prop::collection::vec(arb_prep_transaction(), 1..4), 0..4),
        prop::collection::vec((0usize..1000, arb_zatoshis()), 0..5),
    )
        .prop_map(|(layers, direct)| PreparationPlan::from_parts(layers, direct))
}

// --- denomination strategy (moved from `denomination`'s codec tests) ---

/// An arbitrary [`DenominationPlan`], covering all stored fields (an empty or populated crossing set,
/// present or absent change). Bounded so every `crossing + note_fee_buffer` is representable, which
/// is what [`DenominationPlan::from_stored_parts`] requires.
pub fn arb_denomination_plan() -> impl Strategy<Value = DenominationPlan> {
    (
        prop::collection::vec(arb_zatoshis(), 0..8),
        (0u64..1_000_000).prop_map(Zatoshis::const_from_u64),
        prop::option::of(arb_zatoshis()),
        (0u64..1_000_000).prop_map(Zatoshis::const_from_u64),
        (0u64..1_000_000_000).prop_map(Zatoshis::const_from_u64),
        (0u64..1_000_000_000).prop_map(Zatoshis::const_from_u64),
    )
        .prop_map(
            |(
                crossing_values,
                note_fee_buffer,
                change,
                prep_fees,
                total_input,
                total_migratable,
            )| {
                DenominationPlan::from_stored_parts(
                    crossing_values,
                    note_fee_buffer,
                    change,
                    prep_fees,
                    total_input,
                    total_migratable,
                )
                .expect("crossing + buffer within the money supply")
            },
        )
}

// --- migration-state strategies (moved and extended from `engine`'s codec tests) ---

/// An arbitrary [`MigrationTxKind`], exercising both variants.
pub fn arb_migration_tx_kind() -> impl Strategy<Value = MigrationTxKind> {
    prop_oneof![
        (0usize..1000, 0usize..1000)
            .prop_map(|(layer, index)| MigrationTxKind::Preparation { layer, index }),
        (0usize..1000).prop_map(|crossing| MigrationTxKind::Transfer { crossing }),
    ]
}

/// An arbitrary [`MigrationTxState`], covering every variant (including the
/// [`Broadcast`](MigrationTxState::Broadcast) txid and the [`Mined`](MigrationTxState::Mined) txid
/// and height payloads).
pub fn arb_migration_tx_state() -> impl Strategy<Value = MigrationTxState> {
    prop_oneof![
        Just(MigrationTxState::AwaitingSignature),
        Just(MigrationTxState::Signed),
        Just(MigrationTxState::Proved),
        arb_txid().prop_map(|txid| MigrationTxState::Broadcast { txid }),
        (arb_txid(), arb_block_height())
            .prop_map(|(txid, height)| MigrationTxState::Mined { txid, height }),
    ]
}

/// An arbitrary [`MigrationStatus`], covering every variant.
pub fn arb_migration_status() -> impl Strategy<Value = MigrationStatus> {
    prop_oneof![
        Just(MigrationStatus::Planning),
        Just(MigrationStatus::Committed),
        Just(MigrationStatus::InProgress),
        Just(MigrationStatus::Complete),
        Just(MigrationStatus::Failed),
        Just(MigrationStatus::Superseded),
        Just(MigrationStatus::Cancelled),
    ]
}

/// An arbitrary lock-owner token: `None` (no lock held) or an arbitrary [`MigrationLockOwner`].
pub fn arb_lock_owner() -> impl Strategy<Value = Option<MigrationLockOwner>> {
    prop::option::of(any::<[u8; 32]>().prop_map(MigrationLockOwner::from_bytes))
}

/// An arbitrary lifecycle state paired with a real-spend nullifier cache the state ADMITS.
///
/// The two are not independent. An empty cache on a non-mined transaction is corruption, not a
/// value a store must round-trip: it would read as "no inputs to observe" to the unsatisfiability
/// machinery, silently exempting the transaction from detection, and every read path treats it as
/// a loud error rather than an answer. Generating it would hold stores to round-tripping a shape
/// they are required to reject. A MINED transaction is the one exemption — the schema migration
/// that introduced the cache leaves such rows empty, because a mined transaction's disposition no
/// longer turns on its inputs — so the empty cache is generated there and only there.
pub fn arb_state_and_spend_nullifiers() -> impl Strategy<Value = (MigrationTxState, Vec<[u8; 32]>)>
{
    arb_migration_tx_state().prop_flat_map(|state| {
        let admits_empty = matches!(state, MigrationTxState::Mined { .. });
        let count = if admits_empty { 0..3usize } else { 1..3usize };
        (
            Just(state),
            prop::collection::vec(prop::array::uniform32(any::<u8>()), count),
        )
    })
}

/// An arbitrary [`UnsatisfiableKind`], covering every variant — the directly observed causes and
/// the [`Inherited`](UnsatisfiableKind::Inherited) mark the dependency closure applies.
pub fn arb_unsatisfiable_kind() -> impl Strategy<Value = UnsatisfiableKind> {
    prop_oneof![
        Just(UnsatisfiableKind::InputsSpent),
        Just(UnsatisfiableKind::InputsInvalidated),
        Just(UnsatisfiableKind::AnchorInvalidated),
        Just(UnsatisfiableKind::Inherited),
    ]
}

/// An arbitrary unsatisfiability mark: the stamp-and-kind pair a [`MigrationTransaction`] carries,
/// or `None` for a transaction under no such determination. A store persisting the halves
/// separately is required to REJECT a row holding one without the other rather than round-trip it,
/// so no half-written mark is generated here.
pub fn arb_unsatisfiability_mark() -> impl Strategy<Value = Option<(BlockHeight, UnsatisfiableKind)>>
{
    prop::option::of((arb_block_height(), arb_unsatisfiable_kind()))
}

/// An arbitrary broadcast-failure report: the chain tip an application observed from a node that
/// rejected a broadcast, or `None` for a transaction under no outstanding rejection.
///
/// Drawn INDEPENDENTLY of the unsatisfiability mark, because the two are independent: a rejection
/// the wallet cannot yet explain carries no mark, an adjudicated one carries a mark and no report,
/// and a store must round-trip every combination it is handed.
pub fn arb_broadcast_failure() -> impl Strategy<Value = Option<BlockHeight>> {
    prop::option::of(arb_block_height())
}

/// An arbitrary [`MigrationTransaction`], built through [`MigrationTransaction::from_parts`]. Its
/// id is arbitrary here; [`arb_migration_state`] re-keys the transactions it holds so their ids
/// stay unique within a migration. Its lifecycle state and nullifier cache are drawn TOGETHER (see
/// [`arb_state_and_spend_nullifiers`]), because not every pairing of the two is a value a store is
/// required to round-trip.
pub fn arb_migration_transaction() -> impl Strategy<Value = MigrationTransaction> {
    (
        arb_migration_transfer_id(),
        arb_migration_tx_kind(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(arb_migration_transfer_id(), 0..4),
        arb_block_height(),
        arb_block_height(),
        prop::option::of(arb_block_height()),
        arb_txid(),
        arb_state_and_spend_nullifiers(),
        arb_lock_owner(),
        arb_unsatisfiability_mark(),
        arb_broadcast_failure(),
    )
        .prop_map(
            |(
                id,
                kind,
                pczt,
                depends_on,
                scheduled_height,
                expiry_height,
                anchor_boundary,
                txid,
                (drawn_state, spend_nullifiers),
                lock_owner,
                unsatisfiable,
                broadcast_failure_at,
            )| {
                // A lifecycle state that carries a txid carries THIS transaction's: the row's id
                // and the copy the state holds are one value, written to one column, so a store is
                // not asked to round-trip a pairing it cannot represent. Same reason
                // `arb_state_and_spend_nullifiers` draws its two together.
                let state = match drawn_state {
                    MigrationTxState::Broadcast { .. } => MigrationTxState::Broadcast { txid },
                    MigrationTxState::Mined { height, .. } => {
                        MigrationTxState::Mined { txid, height }
                    }
                    other => other,
                };
                MigrationTransaction::from_parts(
                    id,
                    kind,
                    pczt,
                    depends_on,
                    scheduled_height,
                    expiry_height,
                    anchor_boundary,
                    txid,
                    state,
                    lock_owner,
                    unsatisfiable,
                    spend_nullifiers,
                    broadcast_failure_at,
                )
            },
        )
}

/// An arbitrary [`AnchorBucketInterval`]: the ZIP 318 grid or an arbitrary non-standard one, so a
/// store is exercised on both the value it will almost always see and values it must not special-case.
pub fn arb_anchor_bucket_interval() -> impl Strategy<Value = AnchorBucketInterval> {
    prop_oneof![
        1 => Just(AnchorBucketInterval::ZIP_318),
        1 => (1u32..100_000).prop_map(|blocks| {
            AnchorBucketInterval::custom(NonZeroU32::new(blocks).expect("nonzero"))
        }),
    ]
}

/// An arbitrary [`ReplanThreshold`]: any valid percent, so a store is exercised across the whole
/// stamped-policy range and not just the [`ReplanThreshold::DEFAULT`].
pub fn arb_replan_threshold() -> impl Strategy<Value = ReplanThreshold> {
    (0u8..=100).prop_map(|p| ReplanThreshold::new(p).expect("<=100"))
}

/// An arbitrary whole [`MigrationState`], built through [`MigrationState::from_parts`]: a status, a
/// denomination plan (from which the funding-note values derive), a preparation plan, a small set of
/// transactions re-keyed with sequential [`MigrationTransferId`]s (so their row keys are unique, as a
/// store requires), the anchor bucket grid it was committed under, and the replan threshold it was
/// stamped with. Generated values are self-consistent enough to persist and read back unchanged.
pub fn arb_migration_state() -> impl Strategy<Value = MigrationState> {
    (
        arb_migration_status(),
        arb_denomination_plan(),
        arb_preparation_plan(),
        prop::collection::vec(arb_migration_transaction(), 0..6),
        arb_anchor_bucket_interval(),
        arb_replan_threshold(),
    )
        .prop_map(
            |(
                status,
                denominations,
                preparation,
                txs,
                anchor_bucket_interval,
                replan_threshold,
            )| {
                // Re-key the transactions with sequential ids so their row keys are unique; a store
                // keys transaction rows by id and returns them in id order.
                let transactions = txs
                    .into_iter()
                    .enumerate()
                    .map(|(i, tx)| {
                        MigrationTransaction::from_parts(
                            MigrationTransferId::new(i as u32),
                            tx.kind(),
                            tx.pczt().clone(),
                            tx.depends_on().clone(),
                            tx.scheduled_height(),
                            tx.expiry_height(),
                            tx.anchor_boundary(),
                            tx.txid(),
                            tx.state(),
                            tx.lock_owner(),
                            tx.unsatisfiable(),
                            tx.spend_nullifiers().clone(),
                            tx.broadcast_failure_at(),
                        )
                    })
                    .collect();
                MigrationState::from_parts(
                    status,
                    denominations,
                    preparation,
                    transactions,
                    anchor_bucket_interval,
                    replan_threshold,
                )
            },
        )
}

// --- conformance suite over the store traits ---

/// An arbitrary [`SigningRoundBudget`], covering the named [`SigningRoundBudget::KEYSTONE`] and
/// [`SigningRoundBudget::DEFAULT`] values plus a spread from the minimum feasible budget upward.
pub fn arb_signing_round_budget() -> impl Strategy<Value = SigningRoundBudget> {
    let floor = SigningRoundBudget::minimum_feasible().get();
    prop_oneof![
        Just(SigningRoundBudget::KEYSTONE),
        Just(SigningRoundBudget::DEFAULT),
        (floor..=1024u32)
            .prop_map(|n| SigningRoundBudget::new(NonZeroU32::new(n).expect("nonzero"))),
    ]
}

/// An arbitrary [`RunSigningCapacity`], covering the named [`RunSigningCapacity::KEYSTONE`] plus a
/// spread of budgets, per-run round allowances, and note ceilings.
pub fn arb_run_signing_capacity() -> impl Strategy<Value = RunSigningCapacity> {
    prop_oneof![
        Just(RunSigningCapacity::KEYSTONE),
        (arb_signing_round_budget(), 1usize..4, 1usize..60).prop_map(
            |(budget, max_rounds, max_notes)| RunSigningCapacity::new(
                budget,
                NonZeroUsize::new(max_rounds).expect("nonzero"),
                NonZeroUsize::new(max_notes).expect("nonzero"),
            )
        ),
    ]
}

/// An arbitrary `(n_prep, n_transfer)` transaction-count pair for a single migration run, in the
/// realistic range a run produces (bounded by the per-run note cap).
pub fn arb_signing_round_counts() -> impl Strategy<Value = (usize, usize)> {
    (0usize..20, 0usize..60)
}

/// An arbitrary set of [`PlannedTx`] for one run: `n_prep` preparation transactions followed by
/// `n_transfer` transfers, in the canonical commit order with sequential ids (the same order a
/// [`MigrationPlan`](crate::engine::MigrationPlan) enumerates).
pub fn arb_planned_txs() -> impl Strategy<Value = Vec<PlannedTx>> {
    arb_signing_round_counts().prop_map(|(n_prep, n_transfer)| planned_txs(n_prep, n_transfer))
}
