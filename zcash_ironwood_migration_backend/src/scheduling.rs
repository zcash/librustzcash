//! Migration-transfer scheduling: give each crossing amount a send window and expiry.
//!
//! All transfers in a schedule share one anchor: the wallet's natural anchor from
//! `get_target_and_anchor_heights`. De-correlation between a wallet's own transfers comes from
//! staggered send heights and distinct expiry heights, not from the anchor (see the note below on
//! why the anchor is not bucketed). Each transfer's send height is independently sampled from an
//! exponential distribution around a target cadence (see [`sample_cadence_blocks`]) rather than a
//! fixed offset, so the gaps between a wallet's own transfers are not a predictable, uniform
//! pattern. The first transfer is executable immediately (`first_delay_blocks = 0` on both paths):
//! de-correlation from user activity is the send-time machinery's job (background delivery, and a
//! future rule of no send earlier than ~10 minutes after the last sync), not the schedule's. Sends
//! do not correlate with the confirm tap because nothing broadcasts in the foreground.
//!
//! NOTE: an earlier design floored the anchor to a shared network-wide 288-block bucket
//! (`floor(natural_anchor / 288) * 288`) to hide the wallet's last sync time. That cannot work
//! against the SDK as-is: `create_pczt` requires a note-commitment-tree checkpoint at the *exact*
//! anchor height, but the wallet only checkpoints at ~100-block scan-batch boundaries, so an
//! arbitrary 288-aligned height is essentially never witnessable (giving `AnchorNotFound`).
//! Reinstating the shared bucket requires the SDK to persist a checkpoint at every 288-boundary
//! during scan.

use rand::RngCore;
use rand_distr::{Distribution, Exp};

use crate::types::{MigrationSchedule, TransferId, TransferProposal};
use zcash_protocol::consensus::{BLOCKS_PER_HOUR, BlockHeight};
use zcash_protocol::value::Zatoshis;

/// Target average time, in hours, between successive transfers' send windows.
const TARGET_CADENCE_HOURS: u32 = 6;
/// Hard cap, in hours, on the time any single sampled gap between transfers can represent.
const MAX_CADENCE_HOURS: u32 = 24;
/// Time, in hours, after its send window during which a transfer remains valid.
const TRANSFER_EXPIRY_WINDOW_HOURS: u32 = 6;

/// Expected value of the gap between successive transfers' send windows, in blocks.
pub(crate) const TARGET_CADENCE_BLOCKS: u32 = TARGET_CADENCE_HOURS * BLOCKS_PER_HOUR;
/// Hard cap on any single sampled gap between transfers, in blocks. The exponential distribution is
/// unbounded, so this bounds the worst case a single draw can produce.
pub(crate) const MAX_CADENCE_BLOCKS: u32 = MAX_CADENCE_HOURS * BLOCKS_PER_HOUR;
/// Blocks after its send window during which a transfer remains valid.
pub(crate) const TRANSFER_EXPIRY_WINDOW_BLOCKS: u32 =
    TRANSFER_EXPIRY_WINDOW_HOURS * BLOCKS_PER_HOUR;

/// Sample the block-count gap to the next transfer's send window from an exponential
/// distribution with expected value [`TARGET_CADENCE_BLOCKS`], clamped to `[1,
/// MAX_CADENCE_BLOCKS]`.
///
/// Uses inverse-transform sampling with rate `1 / mean` (which gives that expected value). Each
/// transfer's gap is an independent draw, chained onto the previous transfer's send height, so
/// gaps are neither uniform nor correlated with each other, unlike a fixed per-index offset. The
/// exponential distribution's support is the positive reals, so a raw draw below 0.5 would round
/// to 0; it is floored to 1 so two consecutive transfers never land on the exact same send/expiry
/// height (rare, well under 1% per gap, but not negligible over a full multi-transfer schedule).
fn sample_cadence_blocks<R: RngCore>(rng: &mut R) -> u32 {
    let dist = Exp::new(1.0 / f64::from(TARGET_CADENCE_BLOCKS)).expect("rate is positive");
    (dist.sample(rng).round() as u32).clamp(1, MAX_CADENCE_BLOCKS)
}

/// Build a migration schedule mapping each output amount (zatoshi) to a `TransferProposal`.
///
/// All transfers share `natural_anchor`, a real, witnessable note-commitment-tree checkpoint (see
/// the module note on why this is not bucketed). The first transfer's send height is
/// `target_height + first_delay_blocks` (both paths pass `first_delay_blocks = 0` today, so the
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
