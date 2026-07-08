//! Mapping from vizor's internal phase strings to the public `MigrationState` machine.
//!
//! vizor tracks a fine-grained 14-value phase; the app contract exposes 6 states. The phase
//! strings are kept identical to vizor's for traceability and are what the `store` persists.
//! See the design spec §8 for the mapping rationale.
//!
//! Ported from the zodl_ironwood_migration prototype.

use crate::types::{AttentionReason, MigrationProgress, MigrationState};

/// A migration run's fine-grained phase (ported from vizor's `PHASE_*` constants).
#[allow(dead_code)]
// Consumed by store (Task 7) and backend (Tasks 10-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    NoOrchardFunds,
    WaitingForSpendableOrchard,
    ReadyToPrepare,
    PreparingDenominations,
    WaitingDenomConfirmations,
    ReadyToMigrate,
    BroadcastScheduled,
    Broadcasting,
    WaitingMigrationConfirmations,
    Complete,
    Paused,
    FailedRecoverable,
    FailedTerminal,
    Abandoned,
}

impl Phase {
    /// The persisted string form (identical to vizor's `PHASE_*` values).
    #[allow(dead_code)]
    // Consumed by store (Task 7).
    pub(crate) fn as_str(&self) -> &'static str {
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

    /// Parse a persisted phase string, or `None` if unrecognised.
    #[allow(dead_code)]
    // Consumed by store (Task 7).
    pub(crate) fn parse(s: &str) -> Option<Phase> {
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

/// Map a run's `phase` to the public state. `progress` is used by in-progress phases;
/// `attention` overrides the reason for attention-requiring phases (defaulting to
/// `TransferExpired`, the common recoverable case).
#[allow(dead_code)]
// Consumed by context (Task 11).
pub(crate) fn to_state(
    phase: Phase,
    progress: MigrationProgress,
    attention: Option<AttentionReason>,
) -> MigrationState {
    match phase {
        Phase::NoOrchardFunds
        | Phase::WaitingForSpendableOrchard
        | Phase::ReadyToPrepare
        | Phase::Abandoned => MigrationState::NotStarted,
        Phase::PreparingDenominations | Phase::WaitingDenomConfirmations => {
            MigrationState::SplitPendingConfirmation
        }
        Phase::ReadyToMigrate => MigrationState::ReadyToPropose,
        Phase::BroadcastScheduled
        | Phase::Broadcasting
        | Phase::WaitingMigrationConfirmations
        | Phase::Paused => MigrationState::InProgress(progress),
        Phase::Complete => MigrationState::Complete,
        Phase::FailedRecoverable | Phase::FailedTerminal => {
            MigrationState::RequiresAttention(attention.unwrap_or(AttentionReason::TransferExpired))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TransferId;
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::value::Zatoshis;

    const ALL_PHASES: [Phase; 14] = [
        Phase::NoOrchardFunds,
        Phase::WaitingForSpendableOrchard,
        Phase::ReadyToPrepare,
        Phase::PreparingDenominations,
        Phase::WaitingDenomConfirmations,
        Phase::ReadyToMigrate,
        Phase::BroadcastScheduled,
        Phase::Broadcasting,
        Phase::WaitingMigrationConfirmations,
        Phase::Complete,
        Phase::Paused,
        Phase::FailedRecoverable,
        Phase::FailedTerminal,
        Phase::Abandoned,
    ];

    fn progress() -> MigrationProgress {
        MigrationProgress::from_parts(
            1,
            3,
            Zatoshis::const_from_u64(600_000_000),
            Some(BlockHeight::from_u32(2_880_864)),
        )
    }

    #[test]
    fn phase_strings_round_trip() {
        for phase in ALL_PHASES {
            assert_eq!(Phase::parse(phase.as_str()), Some(phase));
        }
    }

    #[test]
    fn known_phase_strings_are_vizor_compatible() {
        assert_eq!(Phase::NoOrchardFunds.as_str(), "no_orchard_funds");
        assert_eq!(Phase::ReadyToMigrate.as_str(), "ready_to_migrate");
        assert_eq!(
            Phase::WaitingMigrationConfirmations.as_str(),
            "waiting_migration_confirmations"
        );
        assert_eq!(Phase::FailedRecoverable.as_str(), "failed_recoverable");
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert_eq!(Phase::parse("definitely_not_a_phase"), None);
        assert_eq!(Phase::parse(""), None);
    }

    #[test]
    fn pre_initiation_phases_map_to_not_started() {
        for phase in [
            Phase::NoOrchardFunds,
            Phase::WaitingForSpendableOrchard,
            Phase::ReadyToPrepare,
            Phase::Abandoned,
        ] {
            assert_eq!(
                to_state(phase, progress(), None),
                MigrationState::NotStarted
            );
        }
    }

    #[test]
    fn split_phases_map_to_split_pending_confirmation() {
        for phase in [
            Phase::PreparingDenominations,
            Phase::WaitingDenomConfirmations,
        ] {
            assert_eq!(
                to_state(phase, progress(), None),
                MigrationState::SplitPendingConfirmation
            );
        }
    }

    #[test]
    fn ready_to_migrate_maps_to_ready_to_propose() {
        assert_eq!(
            to_state(Phase::ReadyToMigrate, progress(), None),
            MigrationState::ReadyToPropose
        );
    }

    #[test]
    fn executing_phases_map_to_in_progress_with_progress() {
        for phase in [
            Phase::BroadcastScheduled,
            Phase::Broadcasting,
            Phase::WaitingMigrationConfirmations,
            Phase::Paused,
        ] {
            assert_eq!(
                to_state(phase, progress(), None),
                MigrationState::InProgress(progress())
            );
        }
    }

    #[test]
    fn complete_maps_to_complete() {
        assert_eq!(
            to_state(Phase::Complete, progress(), None),
            MigrationState::Complete
        );
    }

    #[test]
    fn failed_phases_require_attention_defaulting_to_expired() {
        for phase in [Phase::FailedRecoverable, Phase::FailedTerminal] {
            assert_eq!(
                to_state(phase, progress(), None),
                MigrationState::RequiresAttention(AttentionReason::TransferExpired)
            );
        }
    }

    #[test]
    fn failed_recoverable_uses_provided_attention_reason() {
        let reason = AttentionReason::InvalidTransfer(TransferId::from_raw("run-2".into()));
        assert_eq!(
            to_state(Phase::FailedRecoverable, progress(), Some(reason.clone())),
            MigrationState::RequiresAttention(reason)
        );
    }
}
