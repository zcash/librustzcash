//! Migration-transfer scheduling: give each output amount a send window and expiry (the piece
//! vizor does not provide; vizor de-correlates by time, the app contract is height-based).
//!
//! All transfers in a schedule share one **anchor** — the wallet's natural anchor from
//! `get_target_and_anchor_heights`. De-correlation between a wallet's own transfers comes from
//! staggered send heights (`next_executable_after_height`, one bucket apart) and distinct expiry
//! heights. The first transfer is executable immediately (`first_delay_blocks = 0` on both paths):
//! de-correlation from user activity is the *send-time* machinery's job (background delivery, and —
//! future rule — no send earlier than ~10 minutes after the last sync), not the schedule's. Sends
//! do not correlate with the confirm tap because nothing broadcasts in the foreground.
//!
//! NOTE: an earlier design floored the anchor to a shared network-wide 288-block bucket
//! (`floor(natural_anchor / 288) * 288`) to hide the wallet's last sync time. That cannot work
//! against the SDK as-is: `create_pczt` requires a note-commitment-tree checkpoint at the *exact*
//! anchor height, but the wallet only checkpoints at ~100-block scan-batch boundaries, so an
//! arbitrary 288-aligned height is essentially never witnessable (→ `AnchorNotFound`). Reinstating
//! the shared bucket requires the SDK to persist a checkpoint at every 288-boundary during scan.

use crate::types::{MigrationSchedule, TransferId, TransferProposal};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

/// Blocks between successive transfers' send windows.
pub(crate) const TRANSFER_CADENCE_BLOCKS: u32 = 288;
/// Blocks after its send window during which a transfer remains valid.
pub(crate) const TRANSFER_EXPIRY_WINDOW_BLOCKS: u32 = 288;
/// Approximate blocks per hour (~75 s/block).
pub(crate) const BLOCKS_PER_HOUR: u32 = 48;

/// Build a migration schedule mapping each output amount (zatoshi) to a `TransferProposal`.
///
/// All transfers share `natural_anchor` — a real, witnessable note-commitment-tree checkpoint (see
/// the module note on why this is not bucketed). Transfer `i` may broadcast at
/// `target_height + first_delay_blocks + i * TRANSFER_CADENCE_BLOCKS` and expires
/// `TRANSFER_EXPIRY_WINDOW_BLOCKS` later. Both paths pass `first_delay_blocks = 0` today (the first
/// transfer is executable immediately; send-time machinery owns de-correlation) — the parameter
/// remains for schedule shaping.
pub(crate) fn build_schedule(
    run_id: &str,
    crossing_values: &[u64],
    target_height: u32,
    natural_anchor: u32,
    first_delay_blocks: u32,
) -> MigrationSchedule {
    let anchor_height = BlockHeight::from_u32(natural_anchor);
    let transfers = crossing_values
        .iter()
        .enumerate()
        .map(|(i, &amount)| {
            let next = target_height
                .saturating_add(first_delay_blocks)
                .saturating_add((i as u32).saturating_mul(TRANSFER_CADENCE_BLOCKS));
            TransferProposal::from_parts(
                TransferId::for_transfer(run_id, i as u32),
                Zatoshis::const_from_u64(amount),
                anchor_height,
                BlockHeight::from_u32(next),
                BlockHeight::from_u32(next.saturating_add(TRANSFER_EXPIRY_WINDOW_BLOCKS)),
            )
        })
        .collect();

    MigrationSchedule::from_parts(
        transfers,
        estimated_duration_hours(crossing_values.len(), first_delay_blocks),
    )
}

/// Hours until the last transfer's send window, rounded up. Zero for an empty schedule.
fn estimated_duration_hours(transfer_count: usize, first_delay_blocks: u32) -> u32 {
    let Some(last_index) = transfer_count.checked_sub(1) else {
        return 0;
    };
    let span_blocks = first_delay_blocks
        .saturating_add((last_index as u32).saturating_mul(TRANSFER_CADENCE_BLOCKS));
    span_blocks.div_ceil(BLOCKS_PER_HOUR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_empty_for_no_amounts() {
        let s = build_schedule("run", &[], 1000, 2000, 288);
        assert!(s.is_empty());
        assert_eq!(s.estimated_duration_hours(), 0);
    }

    #[test]
    fn schedule_shares_one_natural_anchor_across_transfers() {
        let s = build_schedule("run", &[10, 20, 30], 1000, 2_880_290, 288);
        let anchors: Vec<BlockHeight> = s.transfers().iter().map(|t| t.anchor_height()).collect();
        // The anchor is the wallet's real (witnessable) natural anchor, used verbatim — NOT floored
        // to a 288-bucket (which would land on a height the wallet never checkpointed).
        assert_eq!(
            anchors,
            vec![
                BlockHeight::from_u32(2_880_290),
                BlockHeight::from_u32(2_880_290),
                BlockHeight::from_u32(2_880_290)
            ]
        );
    }

    #[test]
    fn schedule_staggers_send_and_expiry_heights() {
        let s = build_schedule("run", &[10, 20, 30], 1000, 2000, 288);
        let sends: Vec<BlockHeight> = s
            .transfers()
            .iter()
            .map(|t| t.next_executable_after_height())
            .collect();
        assert_eq!(
            sends,
            vec![
                BlockHeight::from_u32(1000 + 288),
                BlockHeight::from_u32(1000 + 576),
                BlockHeight::from_u32(1000 + 864)
            ]
        );
        let expiries: Vec<BlockHeight> = s.transfers().iter().map(|t| t.expiry_height()).collect();
        assert_eq!(
            expiries,
            vec![
                BlockHeight::from_u32(1576),
                BlockHeight::from_u32(1864),
                BlockHeight::from_u32(2152)
            ]
        ); // each send + 288
    }

    #[test]
    fn schedule_maps_amounts_in_order() {
        let s = build_schedule("run", &[10, 20, 30], 1000, 2000, 0);
        let amounts: Vec<Zatoshis> = s.transfers().iter().map(|t| t.amount()).collect();
        assert_eq!(
            amounts,
            vec![
                Zatoshis::const_from_u64(10),
                Zatoshis::const_from_u64(20),
                Zatoshis::const_from_u64(30)
            ]
        );
    }

    #[test]
    fn schedule_transfer_ids_are_unique_and_carry_run_id() {
        let s = build_schedule("RUN42", &[10, 20, 30], 1000, 2000, 0);
        let ids: Vec<&str> = s.transfers().iter().map(|t| t.id().as_str()).collect();
        let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), 3);
        assert!(ids.iter().all(|id| id.contains("RUN42")));
    }

    #[test]
    fn estimated_duration_spans_to_the_last_window() {
        // First transfer immediate (delay 0): three transfers span 2 × 288 blocks ≈ 12h; a single
        // transfer completes immediately.
        let three = build_schedule("r", &[1, 2, 3], 1000, 2000, 0);
        assert_eq!(three.estimated_duration_hours(), 12);
        let one = build_schedule("r", &[1], 1000, 2000, 0);
        assert_eq!(one.estimated_duration_hours(), 0);
    }

    #[test]
    fn immediate_schedule_has_no_first_delay() {
        let s = build_schedule("r", &[1], 1000, 2000, 0);
        assert_eq!(
            s.transfers()[0].next_executable_after_height(),
            BlockHeight::from_u32(1000)
        );
        assert_eq!(s.estimated_duration_hours(), 0);
    }
}
