//! Fixtures for this crate's own unit tests.
//!
//! The PCZT-shaped helpers come from [`zcash_pool_migration_memory`], the test-support crate; the
//! rest are defined here because they name types this crate owns. See [`account_derivation`] for
//! what decides which is which.

use alloc::vec::Vec;

use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::denomination::DenominationPlan;
use crate::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId, MigrationTxKind,
    MigrationTxState,
};
use crate::preparation::PreparationPlan;
use crate::satisfiability::DuenessTargets;

#[cfg(feature = "orchard")]
pub(crate) use zcash_pool_migration_memory::{
    TARGET_HEIGHT, account, assert_every_spend_is_identifiable, regtest_network,
    shared_anchor_witnesses, single_note_witness, spend_signability, spending_key,
};

/// The ZIP 32 account derivation a wallet seeded with `seed` would report for the account
/// [`account`] views.
///
/// Defined here rather than re-exported like its siblings, and it is the boundary case that shows
/// where that line falls. `zcash_pool_migration_memory` links this crate as a library, while these
/// tests are a second compilation of it, so the two `AccountDerivation` types are distinct: passing
/// the memory crate's value to this build's `build_prep_tx` is a type error. Every sibling above
/// returns a type owned by another crate, so none of them has the problem.
#[cfg(feature = "orchard")]
pub(crate) fn account_derivation(seed: u64) -> crate::build::AccountDerivation {
    let mut seed_fingerprint = [0u8; 32];
    seed_fingerprint[..8].copy_from_slice(&seed.to_le_bytes());
    crate::build::AccountDerivation::new(
        zip32::fingerprint::SeedFingerprint::from_bytes(seed_fingerprint),
        zip32::AccountId::ZERO,
    )
}

pub(crate) fn tx(id: u32, kind: MigrationTxKind, state: MigrationTxState) -> MigrationTransaction {
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

pub(crate) fn prep(layer: usize, index: usize) -> MigrationTxKind {
    MigrationTxKind::Preparation { layer, index }
}

pub(crate) fn transfer(crossing: usize) -> MigrationTxKind {
    MigrationTxKind::Transfer { crossing }
}

pub(crate) fn mined(height: u32) -> MigrationTxState {
    MigrationTxState::Mined {
        txid: TxId::from_bytes([0; 32]),
        height: BlockHeight::from_u32(height),
    }
}

pub(crate) fn scheduled_transfer(
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

pub(crate) fn state_with_crossings(
    crossings: &[u64],
    buffer: u64,
    transactions: Vec<MigrationTransaction>,
) -> MigrationState {
    let zats = |v: u64| Zatoshis::from_u64(v).expect("test values are valid");
    let total = zats(crossings.iter().sum());
    MigrationState {
        status: MigrationStatus::Committed,
        denominations: DenominationPlan::from_stored_parts(
            crossings.iter().copied().map(zats).collect(),
            zats(buffer),
            None,
            Zatoshis::ZERO,
            total,
            total,
        )
        .expect("a consistent stored plan reconstructs"),
        preparation: PreparationPlan::from_parts(Vec::new(), Vec::new()),
        transactions,
        anchor_bucket_interval: crate::scheduling::AnchorBucketInterval::ZIP_318,
        replan_threshold: crate::satisfiability::ReplanThreshold::DEFAULT,
    }
}

/// Dueness targets at a single settled height, the common case: scanned and estimated agree.
pub(crate) fn at(height: u32) -> DuenessTargets {
    DuenessTargets::at(BlockHeight::from_u32(height))
}

/// Dueness targets whose scan has reached `scanned` while the chain is estimated at `estimated`.
pub(crate) fn est(scanned: u32, estimated: u32) -> DuenessTargets {
    DuenessTargets::new(
        BlockHeight::from_u32(scanned),
        BlockHeight::from_u32(estimated),
    )
}

/// Broadcast. The txid is a placeholder: [`tx`] replaces it with the row's own, so a fixture never
/// states one production could not have produced.
pub(crate) fn broadcast() -> MigrationTxState {
    MigrationTxState::Broadcast {
        txid: TxId::from_bytes([0; 32]),
    }
}

/// Moves the transaction at `index` to Broadcast, carrying the txid that row already has. Assigning
/// the variant directly invites a fixture to state a different one, which production cannot reach:
/// both copies derive from the built PCZT.
pub(crate) fn go_broadcast(state: &mut MigrationState, index: usize) {
    let txid = state.transactions[index].txid;
    state.transactions[index].state = MigrationTxState::Broadcast { txid };
}

/// A migration transfer id, matching the ids [`tx`] assigns.
pub(crate) fn id(n: u32) -> MigrationTransferId {
    MigrationTransferId(n)
}
