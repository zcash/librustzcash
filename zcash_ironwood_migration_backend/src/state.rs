//! A migration run's fine-grained phase.
//!
//! A run advances through the 14 phases below; the store persists each as its string form
//! ([`Phase::as_str`]), and the 6-value public `MigrationState` is derived from it. The string
//! values are a stable persisted format.

/// A migration run's fine-grained phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// No spendable Orchard funds to migrate.
    NoOrchardFunds,
    /// Orchard funds exist but are not yet spendable (awaiting confirmations).
    WaitingForSpendableOrchard,
    /// Ready to prepare the note split.
    ReadyToPrepare,
    /// The note-split transaction is being prepared.
    PreparingDenominations,
    /// The note-split transaction is awaiting on-chain confirmation.
    WaitingDenomConfirmations,
    /// The split is confirmed; ready to propose transfers.
    ReadyToMigrate,
    /// Transfers are scheduled and awaiting broadcast.
    BroadcastScheduled,
    /// Transfers are being broadcast.
    Broadcasting,
    /// Broadcast transfers are awaiting on-chain confirmation.
    WaitingMigrationConfirmations,
    /// Every transfer is confirmed and the Orchard balance is fully migrated.
    Complete,
    /// The run is paused.
    Paused,
    /// The run failed in a recoverable way.
    FailedRecoverable,
    /// The run failed terminally.
    FailedTerminal,
    /// The run was abandoned.
    Abandoned,
}

impl Phase {
    /// The persisted string form of this phase.
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::NoOrchardFunds => "no_orchard_funds",
            Phase::WaitingForSpendableOrchard => "waiting_for_spendable_orchard",
            Phase::ReadyToPrepare => "ready_to_prepare",
            Phase::PreparingDenominations => "preparing_denominations",
            Phase::WaitingDenomConfirmations => "waiting_denom_confirmations",
            Phase::ReadyToMigrate => "ready_to_migrate",
            Phase::BroadcastScheduled => "broadcast_scheduled",
            Phase::Broadcasting => "broadcasting",
            Phase::WaitingMigrationConfirmations => "waiting_migration_confirmations",
            Phase::Complete => "complete",
            Phase::Paused => "paused",
            Phase::FailedRecoverable => "failed_recoverable",
            Phase::FailedTerminal => "failed_terminal",
            Phase::Abandoned => "abandoned",
        }
    }

    /// Parses a persisted phase string, returning `None` if it is unrecognised.
    ///
    /// An unrecognised value indicates the wallet database was written by a newer (or otherwise
    /// incompatible) version of this engine.
    pub fn parse(s: &str) -> Option<Phase> {
        Some(match s {
            "no_orchard_funds" => Phase::NoOrchardFunds,
            "waiting_for_spendable_orchard" => Phase::WaitingForSpendableOrchard,
            "ready_to_prepare" => Phase::ReadyToPrepare,
            "preparing_denominations" => Phase::PreparingDenominations,
            "waiting_denom_confirmations" => Phase::WaitingDenomConfirmations,
            "ready_to_migrate" => Phase::ReadyToMigrate,
            "broadcast_scheduled" => Phase::BroadcastScheduled,
            "broadcasting" => Phase::Broadcasting,
            "waiting_migration_confirmations" => Phase::WaitingMigrationConfirmations,
            "complete" => Phase::Complete,
            "paused" => Phase::Paused,
            "failed_recoverable" => Phase::FailedRecoverable,
            "failed_terminal" => Phase::FailedTerminal,
            "abandoned" => Phase::Abandoned,
            _ => return None,
        })
    }
}
