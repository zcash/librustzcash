//! Reusable test utilities for the pool-migration engine.
//!
//! Two things live here, so every store implementation is exercised the same way instead of
//! hand-rolling its own fixtures:
//!
//! - `proptest` strategies (`arb_*`) that generate the engine's persisted types, from a single
//!   [`Zatoshis`] up to a whole [`MigrationState`]. The crate's own codec proptests consume these,
//!   and so does any downstream store crate.
//! - a backend-agnostic conformance suite (`assert_*`) over the [`PoolMigrationRead`] /
//!   [`PoolMigrationWrite`] store traits: an empty store reads back nothing, a replace/get round-trips,
//!   a second replace overwrites the first, and a transaction state update persists. Point any store
//!   (the SQLite store, a future in-memory backend) at these and it inherits the same coverage.
//!
//! Enabled by the `test-dependencies` feature (and by the crate's own `test` build), so a
//! downstream crate reuses these directly rather than duplicating them.

use core::fmt::Debug;

use proptest::prelude::*;

use zcash_primitives::transaction::testing::arb_txid;
use zcash_protocol::consensus::testing::arb_block_height;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::value::testing::arb_zatoshis;

use crate::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use crate::note_splitting::NoteSplitPlan;
use crate::preparation::{PrepInput, PrepOutput, PrepTransaction, PreparationPlan};

/// Convert a bounded `u64` to [`Zatoshis`]; infallible for the ranges the strategies draw from.
fn zat(value: u64) -> Zatoshis {
    Zatoshis::from_u64(value).expect("test amount within the money supply")
}

// --- leaf strategies ---

/// An arbitrary [`MigrationTxId`] row key.
pub fn arb_migration_tx_id() -> impl Strategy<Value = MigrationTxId> {
    (0u32..1000).prop_map(MigrationTxId::new)
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

// --- note-split strategy (moved from `note_splitting`'s codec tests) ---

/// An arbitrary [`NoteSplitPlan`], covering all stored fields (an empty or populated crossing set,
/// present or absent change). Bounded so every `crossing + note_fee_buffer` is representable, which
/// is what [`NoteSplitPlan::from_stored_parts`] requires.
pub fn arb_note_split_plan() -> impl Strategy<Value = NoteSplitPlan> {
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
                NoteSplitPlan::from_stored_parts(
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

/// An arbitrary [`MigrationTransaction`], built through [`MigrationTransaction::from_parts`]. Its id
/// is arbitrary here; [`arb_migration_state`] re-keys the transactions it holds so their ids stay
/// unique within a migration.
pub fn arb_migration_transaction() -> impl Strategy<Value = MigrationTransaction> {
    (
        arb_migration_tx_id(),
        arb_migration_tx_kind(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(arb_migration_tx_id(), 0..4),
        arb_block_height(),
        arb_block_height(),
        prop::option::of(arb_block_height()),
        arb_migration_tx_state(),
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
                )
            },
        )
}

/// An arbitrary whole [`MigrationState`], built through [`MigrationState::from_parts`]: a status, a
/// note split (from which the funding-note values derive), a preparation plan, and a small set of
/// transactions re-keyed with sequential [`MigrationTxId`]s (so their row keys are unique, as a
/// store requires). Generated values are self-consistent enough to persist and read back unchanged.
pub fn arb_migration_state() -> impl Strategy<Value = MigrationState> {
    (
        arb_migration_status(),
        arb_note_split_plan(),
        arb_preparation_plan(),
        prop::collection::vec(arb_migration_transaction(), 0..6),
    )
        .prop_map(|(status, note_split, preparation, txs)| {
            // Re-key the transactions with sequential ids so their row keys are unique; a store
            // keys transaction rows by id and returns them in id order.
            let transactions = txs
                .into_iter()
                .enumerate()
                .map(|(i, tx)| {
                    MigrationTransaction::from_parts(
                        MigrationTxId::new(i as u32),
                        tx.kind(),
                        tx.pczt().clone(),
                        tx.depends_on().clone(),
                        tx.scheduled_height(),
                        tx.expiry_height(),
                        tx.anchor_boundary(),
                        tx.state(),
                    )
                })
                .collect();
            MigrationState::from_parts(status, note_split, preparation, transactions)
        })
}

// --- conformance suite over the store traits ---

/// Assert that an empty store reports no migration: [`get_migration`](PoolMigrationRead::get_migration)
/// is `None`.
pub fn assert_empty_is_none<S: PoolMigrationRead>(store: &S)
where
    S::Error: Debug,
{
    assert!(
        store
            .get_migration()
            .expect("reading an empty store succeeds")
            .is_none(),
        "an empty store must report no migration"
    );
}

/// Assert a replace/get round-trip: after [`replace_migration`](PoolMigrationWrite::replace_migration), the
/// store reads back exactly the migration that was written.
pub fn assert_put_get_roundtrip<S: PoolMigrationWrite>(store: &mut S, state: &MigrationState)
where
    S::Error: Debug,
{
    store
        .replace_migration(state)
        .expect("replace_migration succeeds");
    let loaded = store.get_migration().expect("get_migration succeeds");
    assert_eq!(
        loaded,
        Some(state.clone()),
        "the stored migration must read back unchanged"
    );
}

/// Assert that a second replace overwrites the first: after putting `first` then `second`, the store holds
/// exactly `second`.
pub fn assert_put_replaces<S: PoolMigrationWrite>(
    store: &mut S,
    first: &MigrationState,
    second: &MigrationState,
) where
    S::Error: Debug,
{
    store
        .replace_migration(first)
        .expect("first replace_migration succeeds");
    store
        .replace_migration(second)
        .expect("second replace_migration succeeds");
    assert_eq!(
        store.get_migration().expect("get_migration succeeds"),
        Some(second.clone()),
        "a second put must replace the first migration",
    );
}

/// Assert that a transaction state update persists: after storing `state` and calling
/// [`update_transaction`](PoolMigrationWrite::update_transaction) for `id`, the reloaded transaction
/// with that id carries `new`.
///
/// Call this only with an `id` that `state` actually contains (the store errors on an unknown
/// transaction); [`first_transaction_id`] picks a present one.
pub fn assert_update_transaction<S: PoolMigrationWrite>(
    store: &mut S,
    state: &MigrationState,
    id: MigrationTxId,
    new: MigrationTxState,
) where
    S::Error: Debug,
{
    store
        .replace_migration(state)
        .expect("replace_migration succeeds");
    store
        .update_transaction(id, new)
        .expect("update_transaction succeeds");
    let loaded = store
        .get_migration()
        .expect("get_migration succeeds")
        .expect("a migration is stored");
    let tx = loaded
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .expect("the updated transaction is present");
    assert_eq!(tx.state(), new, "the transaction's state must be updated");
}

/// The id of the first transaction of `state`, or `None` if it has no transactions. A convenience
/// for driving [`assert_update_transaction`] from a generated [`MigrationState`].
pub fn first_transaction_id(state: &MigrationState) -> Option<MigrationTxId> {
    state.transactions().first().map(|t| t.id())
}
