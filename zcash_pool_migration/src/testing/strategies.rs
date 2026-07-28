//! `proptest` strategies over the engine's persisted types.
//!
//! Every `arb_*` here generates a value of a type a store must round-trip, from a single
//! `Zatoshis` up to a whole [`MigrationState`]. The crate's own codec proptests consume them, and
//! so does any downstream store crate: generating the SAME values everywhere is what makes one
//! store's coverage comparable to another's.

use core::num::NonZeroU32;

use proptest::prelude::*;

use zcash_primitives::transaction::testing::arb_txid;
use zcash_protocol::consensus::testing::arb_block_height;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::value::testing::arb_zatoshis;

use crate::denomination::DenominationPlan;
use crate::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId, MigrationTxKind,
    MigrationTxState,
};
use crate::preparation::{PrepInput, PrepOutput, PrepTransaction, PreparationPlan};
use crate::scheduling::AnchorBucketInterval;
use crate::signing_rounds::{PlannedTx, SigningRoundBudget};

use alloc::vec::Vec;

// `arb_planned_txs` is a strategy OVER the shared workload builder, so the random and the
// fixed paths construct runs the same way.
use super::scenarios::planned_txs;

/// Convert a bounded `u64` to [`Zatoshis`]; infallible for the ranges the strategies draw from.
fn zat(value: u64) -> Zatoshis {
    Zatoshis::from_u64(value).expect("test amount within the money supply")
}

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
        (0u64..1_000_000).prop_map(zat),
        prop::option::of(arb_zatoshis()),
        (0u64..1_000_000).prop_map(zat),
        (0u64..1_000_000_000).prop_map(zat),
        (0u64..1_000_000_000).prop_map(zat),
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
/// [`Broadcast`](MigrationTxState::Broadcast) txid and [`Mined`](MigrationTxState::Mined) height
/// payloads).
pub fn arb_migration_tx_state() -> impl Strategy<Value = MigrationTxState> {
    prop_oneof![
        Just(MigrationTxState::AwaitingSignature),
        Just(MigrationTxState::Signed),
        Just(MigrationTxState::Proved),
        arb_txid().prop_map(|txid| MigrationTxState::Broadcast { txid }),
        arb_block_height().prop_map(|height| MigrationTxState::Mined { height }),
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
    ]
}

/// An arbitrary lock-owner token: `None` (no lock held) or the raw bytes of a
/// `zcash_client_backend::wallet::LockOwner` (opaque here — this crate does not depend on
/// `zcash_client_backend`).
pub fn arb_lock_owner() -> impl Strategy<Value = Option<[u8; 32]>> {
    prop::option::of(any::<[u8; 32]>())
}

/// An arbitrary [`MigrationTransaction`], built through [`MigrationTransaction::from_parts`]. Its id
/// is arbitrary here; [`arb_migration_state`] re-keys the transactions it holds so their ids stay
/// unique within a migration.
pub fn arb_migration_transaction() -> impl Strategy<Value = MigrationTransaction> {
    (
        arb_migration_transfer_id(),
        arb_migration_tx_kind(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(arb_migration_transfer_id(), 0..4),
        arb_block_height(),
        arb_block_height(),
        prop::option::of(arb_block_height()),
        arb_migration_tx_state(),
        arb_lock_owner(),
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
                state,
                lock_owner,
            )| {
                MigrationTransaction::from_parts(
                    id,
                    kind,
                    pczt,
                    depends_on,
                    scheduled_height,
                    expiry_height,
                    anchor_boundary,
                    state,
                    lock_owner,
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

/// An arbitrary whole [`MigrationState`], built through [`MigrationState::from_parts`]: a status, a
/// denomination plan (from which the funding-note values derive), a preparation plan, a small set of
/// transactions re-keyed with sequential [`MigrationTransferId`]s (so their row keys are unique, as a
/// store requires), and the anchor bucket grid it was committed under. Generated values are
/// self-consistent enough to persist and read back unchanged.
pub fn arb_migration_state() -> impl Strategy<Value = MigrationState> {
    (
        arb_migration_status(),
        arb_denomination_plan(),
        arb_preparation_plan(),
        prop::collection::vec(arb_migration_transaction(), 0..6),
        arb_anchor_bucket_interval(),
    )
        .prop_map(
            |(status, denominations, preparation, txs, anchor_bucket_interval)| {
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
                            tx.state(),
                            tx.lock_owner(),
                        )
                    })
                    .collect();
                MigrationState::from_parts(
                    status,
                    denominations,
                    preparation,
                    transactions,
                    anchor_bucket_interval,
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
