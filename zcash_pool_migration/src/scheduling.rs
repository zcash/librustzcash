//! Migration-transfer scheduling: give each output amount a send window and expiry (the piece
//! vizor does not provide; vizor de-correlates by time, the app contract is height-based).
//!
//! All transfers in a schedule share one **anchor** — the wallet's natural anchor from
//! `get_target_and_anchor_heights`. De-correlation between a wallet's own transfers comes from
//! staggered send heights and distinct expiry heights, not from the anchor (see the note below on
//! why the anchor is not bucketed). Each transfer's send height is independently sampled from an
//! exponential distribution around a target cadence (see [`sample_cadence_blocks`]) rather than a
//! fixed offset, so the gaps between a wallet's own transfers are not a predictable, uniform
//! pattern. The first transfer is executable immediately (`first_delay_blocks = 0` on both paths):
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

use rand::RngCore;
use rand_distr::{Distribution, Exp};

use crate::types::{MigrationSchedule, TransferId, TransferProposal};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

/// Expected value of the gap between successive transfers' send windows (~6h at ~75 s/block).
pub(crate) const TARGET_CADENCE_BLOCKS: u32 = 288;
/// Hard cap on any single sampled gap between transfers (~24h). The exponential distribution is
/// unbounded, so this bounds the worst case a single draw can produce.
pub(crate) const MAX_CADENCE_BLOCKS: u32 = 1152;
/// Blocks after its send window during which a transfer remains valid.
pub(crate) const TRANSFER_EXPIRY_WINDOW_BLOCKS: u32 = 288;
/// Approximate blocks per hour (~75 s/block).
pub(crate) const BLOCKS_PER_HOUR: u32 = 48;

/// Sample the block-count gap to the next transfer's send window from an exponential
/// distribution with expected value [`TARGET_CADENCE_BLOCKS`], clamped to `[1,
/// MAX_CADENCE_BLOCKS]`.
///
/// Mirrors `zcash_client_sqlite::wallet::transparent::next_check_time`'s inverse-transform
/// sampling (a rate `λ = 1 / mean` gives that expected value). Each transfer's gap is an
/// independent draw, chained onto the previous transfer's send height — gaps are neither uniform
/// nor correlated with each other, unlike a fixed per-index offset. The exponential distribution's
/// support is `(0, ∞)`, so a raw draw below 0.5 would round to 0 — floored to 1 so two consecutive
/// transfers never land on the exact same send/expiry height (rare — well under 1% per gap — but
/// not negligible over a full multi-transfer schedule).
fn sample_cadence_blocks<R: RngCore>(rng: &mut R) -> u32 {
    let dist = Exp::new(1.0 / f64::from(TARGET_CADENCE_BLOCKS)).expect("rate is positive");
    (dist.sample(rng).round() as u32).clamp(1, MAX_CADENCE_BLOCKS)
}

/// Build a migration schedule mapping each output amount (zatoshi) to a `TransferProposal`.
///
/// All transfers share `natural_anchor` — a real, witnessable note-commitment-tree checkpoint (see
/// the module note on why this is not bucketed). The first transfer's send height is
/// `target_height + first_delay_blocks` (both paths pass `first_delay_blocks = 0` today — the
/// first transfer is executable immediately; send-time machinery owns de-correlation). Every
/// subsequent transfer's send height is the previous transfer's plus an independently sampled gap
/// (see [`sample_cadence_blocks`]); each transfer expires [`TRANSFER_EXPIRY_WINDOW_BLOCKS`] after
/// its own send window.
pub(crate) fn build_schedule<R: RngCore>(
    rng: &mut R,
    run_id: &str,
    crossing_values: &[u64],
    target_height: u32,
    natural_anchor: u32,
    first_delay_blocks: u32,
) -> MigrationSchedule {
    let anchor_height = BlockHeight::from_u32(natural_anchor);
    let mut next = target_height.saturating_add(first_delay_blocks);
    let mut transfers = Vec::with_capacity(crossing_values.len());
    for (i, &amount) in crossing_values.iter().enumerate() {
        if i > 0 {
            next = next.saturating_add(sample_cadence_blocks(rng));
        }
        transfers.push(TransferProposal::from_parts(
            TransferId::for_transfer(run_id, i as u32),
            Zatoshis::const_from_u64(amount),
            anchor_height,
            BlockHeight::from_u32(next),
            BlockHeight::from_u32(next.saturating_add(TRANSFER_EXPIRY_WINDOW_BLOCKS)),
        ));
    }

    let duration_hours = estimated_duration_hours(&transfers);
    MigrationSchedule::from_parts(transfers, duration_hours)
}

/// Hours spanned by the schedule, from the first transfer's send window to the last's, rounded
/// up. Zero for an empty or single-transfer schedule.
fn estimated_duration_hours(transfers: &[TransferProposal]) -> u32 {
    match (transfers.first(), transfers.last()) {
        (Some(first), Some(last)) => u32::from(last.next_executable_after_height())
            .saturating_sub(u32::from(first.next_executable_after_height()))
            .div_ceil(BLOCKS_PER_HOUR),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(42)
    }

    #[test]
    fn schedule_is_empty_for_no_amounts() {
        let s = build_schedule(&mut rng(), "run", &[], 1000, 2000, 288);
        assert!(s.is_empty());
        assert_eq!(s.estimated_duration_hours(), 0);
    }

    #[test]
    fn schedule_shares_one_natural_anchor_across_transfers() {
        let s = build_schedule(&mut rng(), "run", &[10, 20, 30], 1000, 2_880_290, 288);
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
    fn schedule_staggers_send_and_expiry_heights_with_independent_gaps() {
        let s = build_schedule(&mut rng(), "run", &[10, 20, 30], 1000, 2000, 288);
        let sends: Vec<u32> = s
            .transfers()
            .iter()
            .map(|t| u32::from(t.next_executable_after_height()))
            .collect();
        // Strictly increasing, each gap independently sampled (not a fixed multiple of the first).
        assert_eq!(sends[0], 1000 + 288);
        assert!(sends[1] > sends[0]);
        assert!(sends[2] > sends[1]);
        // No single sampled gap ever exceeds the hard cap.
        assert!(sends[1] - sends[0] <= MAX_CADENCE_BLOCKS);
        assert!(sends[2] - sends[1] <= MAX_CADENCE_BLOCKS);
        let expiries: Vec<u32> = s
            .transfers()
            .iter()
            .map(|t| u32::from(t.expiry_height()))
            .collect();
        for (send, expiry) in sends.iter().zip(expiries.iter()) {
            assert_eq!(*expiry, send + TRANSFER_EXPIRY_WINDOW_BLOCKS);
        }
    }

    #[test]
    fn sampled_gaps_never_exceed_the_cap() {
        // Draw many samples from a fixed seed and check the hard cap holds for all of them —
        // the exponential distribution is unbounded, so this is the property that matters, not
        // any particular sampled value.
        let mut r = rng();
        for _ in 0..10_000 {
            assert!(sample_cadence_blocks(&mut r) <= MAX_CADENCE_BLOCKS);
        }
    }

    #[test]
    fn sampled_gaps_are_never_zero() {
        // A single fixed seed (as used elsewhere in this module) never happens to draw a value
        // that rounds to 0 — so sweep many distinct seeds instead, giving the near-zero tail of
        // the exponential distribution (~0.17% per draw) many independent chances to appear.
        for seed in 0..2_000u64 {
            let mut r = ChaCha8Rng::seed_from_u64(seed);
            for _ in 0..50 {
                assert_ne!(
                    sample_cadence_blocks(&mut r),
                    0,
                    "seed {seed}: a zero-block gap would let two transfers share a send height"
                );
            }
        }
    }

    #[test]
    fn schedule_maps_amounts_in_order() {
        let s = build_schedule(&mut rng(), "run", &[10, 20, 30], 1000, 2000, 0);
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
        let s = build_schedule(&mut rng(), "RUN42", &[10, 20, 30], 1000, 2000, 0);
        let ids: Vec<&str> = s.transfers().iter().map(|t| t.id().as_str()).collect();
        let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), 3);
        assert!(ids.iter().all(|id| id.contains("RUN42")));
    }

    #[test]
    fn estimated_duration_spans_first_to_last_send_window() {
        let three = build_schedule(&mut rng(), "r", &[1, 2, 3], 1000, 2000, 0);
        let sends: Vec<u32> = three
            .transfers()
            .iter()
            .map(|t| u32::from(t.next_executable_after_height()))
            .collect();
        let expected = (sends[2] - sends[0]).div_ceil(BLOCKS_PER_HOUR);
        assert_eq!(three.estimated_duration_hours(), expected);
        assert!(expected > 0);

        let one = build_schedule(&mut rng(), "r", &[1], 1000, 2000, 0);
        assert_eq!(one.estimated_duration_hours(), 0);
    }

    #[test]
    fn immediate_schedule_has_no_first_delay() {
        let s = build_schedule(&mut rng(), "r", &[1], 1000, 2000, 0);
        assert_eq!(
            s.transfers()[0].next_executable_after_height(),
            BlockHeight::from_u32(1000)
        );
        assert_eq!(s.estimated_duration_hours(), 0);
    }
}
