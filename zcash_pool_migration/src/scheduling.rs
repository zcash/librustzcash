//! Transfer scheduling and anchor selection: WHEN each migration transfer is broadcast, WHICH
//! Orchard anchor it proves against, and WHEN it expires.
//!
//! This module is pool-agnostic and pure arithmetic plus RNG draws (no cryptography, no note tree,
//! no I/O); it works only in block heights and part indices. All randomness comes from a caller-
//! supplied `rng`, which the public functions bound as [`CryptoRng`]: the draws decide the
//! privacy-relevant observables (broadcast order, delays, anchors), so a predictable generator
//! would let an observer reconstruct them (the tests pass a seeded `rand_chacha::ChaCha8Rng`,
//! which is a `CryptoRng`). Every function is deterministic given its `rng`.
//!
//! # The problem
//!
//! The denomination plan ([`crate::denomination`]) decides the crossing VALUES (quantized denominations)
//! so many wallets emit colliding amounts. Scheduling decides the TEMPORAL and ANCHOR dimensions of
//! the same crossings, which leak just as much if left predictable:
//!
//! - If the sequence of denominations were a fixed function of the balance, a chain observer could
//!   read the balance back out of the order the transfers appear in.
//! - If every transfer proved against the latest tree state, the anchor would timestamp the transfer
//!   and shrink its anonymity set to the wallets active in that exact block.
//!
//! [ZIP 318] settles this with randomization drawn from principled distributions, which this module
//! implements ("Transfer scheduling" and the anchor-selection rules):
//!
//! 1. SHUFFLE ([`shuffle_indices`]): the quantized parts are broadcast in a uniformly random order,
//!    so the temporal sequence of denominations is independent of the balance.
//! 2. DELAYS ([`DelayDistribution::draw`]): the gap between successive transfers is an exponential
//!    inter-arrival time (mean and cap given by [`SchedulingParams::transfer_delay`]), so broadcasts
//!    look like an unremarkable Poisson process rather than a burst.
//! 3. CUMULATIVE ([`schedule_broadcast_heights`]): each transfer's scheduled height is the running
//!    sum of independent delays from the commit height.
//! 4. ANCHOR ([`draw_anchor_boundary`]): at PROVING time each transfer proves against the Orchard
//!    tree state at a BOUNDARY block (a multiple of the [`AnchorBucketInterval`]), chosen from a
//!    recency-weighted geometric draw over the candidate boundaries, so transfers share a small set
//!    of common anchors (cohorts) instead of each pinning the latest state.
//! 5. EXPIRY ([`expiry_height`]): a canonical rolling window gives every transfer 1 to 2 months of
//!    validity as a pure function of the current height, so the expiry height itself carries no
//!    per-wallet information.
//!
//! Beyond the ZIP 318 draws, [`schedule_sync_wakeups`] derives from a committed transfer schedule
//! the MINIMAL set of sync/proving wake-ups a background-constrained wallet needs: every transfer
//! is proved after its drawn anchor boundary settles and strictly before its broadcast height, and
//! each wake-up lands a settle margin past a bucketed anchor height plus an anti-thundering-herd
//! jitter ([`WakeupParams`]).
//!
//! # Cohorts
//!
//! Transfers (across all wallets) that prove against the same boundary anchor form a COHORT: to an
//! observer they are indistinguishable in their anchor, which is the anonymity set the anchor draw
//! builds. In this pure module a cohort is just "transfers that chose the same boundary height".
//! How many of a wallet's OWN parts land on one boundary is whatever the independent geometric
//! draws produce: ZIP 318 deliberately places no cap on per-wallet multiplicity, since truncating
//! the outcome of random draws with an arbitrary bound would only distort the distribution.
//!
//! # Out of scope (enforced elsewhere, not here)
//!
//! Two ZIP 318 MUSTs are the responsibility of the migration engine and the consuming application,
//! not this pure planner, and are deliberately NOT implemented here:
//!
//! - SYNC/BROADCAST DECOUPLING: a background wake window is used EITHER to sync the wallet OR to
//!   broadcast a due transfer, never both, so an observer cannot correlate a wallet's sync traffic
//!   with its broadcasts. That is a scheduling-engine runtime policy over live network activity.
//! - AT MOST ONE OVERDUE TRANSFER at wallet open: when a wallet reopens after being offline past
//!   several scheduled heights, at most one overdue transfer is released immediately (the rest are
//!   re-spread). That requires the persisted schedule and wall-clock state the engine owns; the
//!   drive API implements it as the overdue shift (see
//!   [`advance_migration`](crate::satisfiability::advance_migration) and
//!   [`overdue_shift_tolerance`](crate::satisfiability::overdue_shift_tolerance)), which moves the
//!   whole pending schedule forward by the overdue amount rather than redrawing it.
//!
//! This module supplies the heights and anchors those policies act on; it does not enact them.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU32;

use rand_core::{CryptoRng, RngCore};
use zcash_protocol::consensus::BlockHeight;

/// The block-height grid defining the BOUNDARY blocks that a transfer may anchor to.
///
/// Re-exported from [`zcash_protocol::zip318`], which owns the single definition shared with the
/// wallet's durable anchor retention. The wallet that will prove a transfer must have RETAINED the
/// checkpoint at the boundary the transfer anchors to, so the migration's grid and the wallet's
/// retention grid must be the same — they are now the same type, rather than two types kept aligned
/// by a conversion.
///
/// See [`draw_anchor_boundary`] for how a boundary is chosen from this grid.
pub use zcash_protocol::zip318::AnchorBucketInterval;

/// [`AnchorBucketInterval::boundary_at_or_below`] on the raw `u32` representation, for the boundary
/// arithmetic below. The public API is `BlockHeight`-typed; the scheduling arithmetic works in `u32`
/// spans, so it converts once here rather than at every call site.
fn boundary_at_or_below_u32(interval: &AnchorBucketInterval, height: u32) -> u32 {
    u32::from(interval.boundary_at_or_below(BlockHeight::from_u32(height)))
}

/// [`AnchorBucketInterval::boundary_at_or_above`] on the raw `u32` representation. See
/// [`boundary_at_or_below_u32`].
fn boundary_at_or_above_u32(interval: &AnchorBucketInterval, height: u32) -> u32 {
    u32::from(interval.boundary_at_or_above(BlockHeight::from_u32(height)))
}

// There is no conversion in either direction, because there is nothing to convert: the wallet's
// retention interval and a migration's bucket interval are one type. The wallet remains the
// authority on the grid — it is the side that retains the checkpoints — so a migration still reads
// its interval off a wallet rather than choosing one. Constructing a non-ZIP-318 interval goes
// through `AnchorBucketInterval::custom`, which is documented for use on test networks only.

/// A truncated exponential inter-arrival delay distribution, in blocks: draws have mean
/// [`Self::mean`], and a draw exceeding [`Self::cap`] is discarded and redrawn (truncating the
/// exponential's heavy tail, so nothing is starved for an unbounded time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelayDistribution {
    mean: NonZeroU32,
    cap: NonZeroU32,
}

impl DelayDistribution {
    /// Constructs a delay distribution, or returns `None` if `cap` is below `mean`.
    ///
    /// A cap below the mean would reject the majority of draws, distorting the distribution into
    /// something no longer recognizably exponential; the rejection region is meant to remove only
    /// the tail.
    pub const fn new(mean: NonZeroU32, cap: NonZeroU32) -> Option<Self> {
        if cap.get() < mean.get() {
            None
        } else {
            Some(Self { mean, cap })
        }
    }

    /// The mean of the untruncated exponential, in blocks. The exponential rate is `1 / mean`.
    pub fn mean(&self) -> NonZeroU32 {
        self.mean
    }

    /// The inclusive upper bound on a single drawn delay, in blocks.
    pub fn cap(&self) -> NonZeroU32 {
        self.cap
    }

    /// Draws one inter-arrival delay in blocks, always in `[0, cap]`.
    ///
    /// Samples by inverse-CDF, `delay = round(-mean * ln(u))` for `u` uniform in `(0, 1]`,
    /// discarding and redrawing above [`Self::cap`].
    pub fn draw<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u32 {
        self.draw_inner(rng)
    }

    /// The RNG-generic body of [`Self::draw`]. The public entry point bounds its `rng` as
    /// [`CryptoRng`] (the drawn delays are privacy-relevant observables); the tests exercise the
    /// distribution through the same code path.
    fn draw_inner<R: RngCore>(&self, rng: &mut R) -> u32 {
        loop {
            let u = draw_unit_left_open(rng);
            // ln(u) <= 0 for u in (0, 1], so -mean * ln(u) >= 0.
            let delay = round_nonneg_to_u32(-(self.mean.get() as f64) * libm::log(u));
            if delay <= self.cap.get() {
                return delay;
            }
        }
    }
}

/// The scheduling parameters a migration runs under: the anchor bucket grid and the two
/// inter-arrival delay distributions.
///
/// [`Self::ZIP_318`] carries the specified values, and is what a migration on the production
/// network must use. A test network may shorten them so a migration completes in a workable time;
/// the anchor bucket interval in particular is not free to choose, since it must match the grid the
/// wallet retains its anchor checkpoints on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulingParams {
    anchor_bucket_interval: AnchorBucketInterval,
    transfer_delay: DelayDistribution,
    preparation_delay: DelayDistribution,
}

impl SchedulingParams {
    /// The parameters specified by [ZIP 318]: a 144-block anchor bucket interval, transfer delays
    /// of mean 66 blocks capped at 576 (about twelve hours), and preparation delays of mean 16
    /// blocks capped at 96 (about two hours).
    ///
    /// Preparation transactions are fully shielded self-sends: they need TEMPORAL decoupling from
    /// one another (a burst of identically shaped transactions from one wallet is a linkable
    /// cluster), but no anchor bucketing — only the pool-crossing transfers anchor to boundaries —
    /// so their spacing is much tighter than the transfers'.
    ///
    /// [ZIP 318]: https://zips.z.cash/zip-0318
    pub const ZIP_318: Self = Self {
        anchor_bucket_interval: AnchorBucketInterval::ZIP_318,
        transfer_delay: DelayDistribution {
            mean: zcash_protocol::zip318::TRANSFER_DELAY_MEAN,
            cap: zcash_protocol::zip318::TRANSFER_DELAY_CAP,
        },
        preparation_delay: DelayDistribution {
            mean: zcash_protocol::zip318::PREP_DELAY_MEAN,
            cap: zcash_protocol::zip318::PREP_DELAY_CAP,
        },
    };

    /// Constructs scheduling parameters from their constituent parts.
    pub fn new(
        anchor_bucket_interval: AnchorBucketInterval,
        transfer_delay: DelayDistribution,
        preparation_delay: DelayDistribution,
    ) -> Self {
        Self {
            anchor_bucket_interval,
            transfer_delay,
            preparation_delay,
        }
    }

    /// Constructs scheduling parameters for `anchor_bucket_interval`, scaling every delay
    /// parameter of [`Self::ZIP_318`] by the ratio the interval bears to
    /// [`AnchorBucketInterval::ZIP_318`]: each mean and cap is its ZIP 318 value multiplied by
    /// `interval / 144`, truncated.
    ///
    /// At [`AnchorBucketInterval::ZIP_318`] this reproduces [`Self::ZIP_318`] exactly. It is the
    /// constructor to reach for on a test network: shortening the bucket interval alone would leave
    /// the ZIP 318 delays spreading a migration over an impractical span of blocks, whereas scaling
    /// the whole schedule by the same factor compresses it while preserving the shape ZIP 318
    /// specifies.
    ///
    /// A scaled value that truncates to zero is clamped up to one block, and one that exceeds
    /// `u32::MAX` saturates, so every interval yields a usable pair of distributions.
    pub fn new_with_default_distributions(anchor_bucket_interval: AnchorBucketInterval) -> Self {
        let scale = |value: NonZeroU32| -> NonZeroU32 {
            let scaled = u64::from(value.get())
                * u64::from(anchor_bucket_interval.block_count().get())
                / u64::from(AnchorBucketInterval::ZIP_318.block_count().get());
            match u32::try_from(scaled) {
                Ok(v) => NonZeroU32::new(v).unwrap_or(NonZeroU32::MIN),
                Err(_) => NonZeroU32::MAX,
            }
        };
        // Built directly rather than through `DelayDistribution::new`: scaling is monotone
        // (truncation, the clamp, and the saturation all preserve order), so each scaled cap is
        // never below its scaled mean and the validated constructor's failure case is unreachable
        // here.
        Self {
            anchor_bucket_interval,
            transfer_delay: DelayDistribution {
                mean: scale(zcash_protocol::zip318::TRANSFER_DELAY_MEAN),
                cap: scale(zcash_protocol::zip318::TRANSFER_DELAY_CAP),
            },
            preparation_delay: DelayDistribution {
                mean: scale(zcash_protocol::zip318::PREP_DELAY_MEAN),
                cap: scale(zcash_protocol::zip318::PREP_DELAY_CAP),
            },
        }
    }

    /// The grid of boundary heights a transfer may anchor to.
    pub fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
        self.anchor_bucket_interval
    }

    /// The inter-arrival delay distribution between successive TRANSFER broadcasts.
    pub fn transfer_delay(&self) -> DelayDistribution {
        self.transfer_delay
    }

    /// The inter-arrival delay distribution between successive PREPARATION broadcasts.
    pub fn preparation_delay(&self) -> DelayDistribution {
        self.preparation_delay
    }
}

impl Default for SchedulingParams {
    fn default() -> Self {
        Self::ZIP_318
    }
}

/// How deep below the wallet's fully-scanned tip a transfer's drawn anchor boundary must sit —
/// AT LEAST this many blocks — before the planning kernel offers the transfer's proof: about
/// 12.5 minutes of reorg stability at the target block spacing, so the boundary checkpoint
/// proved against is one a reorg can no longer plausibly displace. This is the same settling
/// judgment [`WakeupParams::DEFAULT`] expresses as a wake-up margin — that margin IS this
/// constant, so a zero-jitter wake-up landing exactly on its scheduled height syncs to the
/// first tip at which the kernel offers the proofs the wake-up exists to produce — and it
/// matches the conventional [`ReorgSettleDepth`](crate::satisfiability::ReorgSettleDepth).
/// Not specified by ZIP 318; provisional.
///
/// Proving a shallower boundary would cost correctness nothing — the satisfiability oracle
/// detects an anchor a settled reorg invalidated, and the proof is simply redone — but it
/// spends the proving work exactly when a reorg is most plausible, so the kernel holds the
/// proof until the boundary is this deep. The gate is judged only against the SCANNED target
/// ([`DuenessTargets::scanned`](crate::satisfiability::DuenessTargets::scanned)): an estimate
/// cannot conjure the checkpoint, nor its depth.
pub const PROVABLE_ANCHOR_DEPTH: u32 = 10;

/// Parameters shaping the sync/proving wake-up schedule ([`schedule_sync_wakeups`]): how many
/// blocks past an anchor boundary a wake-up waits for that boundary to settle, and how much random
/// jitter spreads independent wallets' wake-ups apart as a thundering-herd defense. These values
/// are provisional; they are not specified by ZIP 318.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeupParams {
    settle_margin: u32,
    jitter_cap: u32,
}

impl WakeupParams {
    /// The provisional defaults: a settle margin of [`PROVABLE_ANCHOR_DEPTH`] blocks (10 —
    /// about 12.5 minutes at the target block spacing; the kernel's provability gate and this
    /// margin are the SAME depth, so a zero-jitter wake-up syncs to the first tip at which the
    /// kernel offers the proofs the wake-up exists to produce) and a 12-block jitter cap (about
    /// 15 minutes).
    ///
    /// The jitter cap exists as a THUNDERING-HERD defense, and for nothing else: anchor
    /// boundaries sit on a GLOBAL grid shared by every migrating wallet, so un-jittered wake-ups
    /// would all land exactly `settle_margin` blocks after the same grid heights, hitting the
    /// light wallet servers in synchronized bursts. A uniform draw over `[0, jitter_cap]` divides
    /// that per-block peak load by roughly the cap, while staying small against the 133-block
    /// worst-case slack a transfer's proving window guarantees, so most of the window remains as
    /// headroom for wake-ups the operating system delivers late.
    ///
    /// The jitter is denominated in blocks even though the herd is a wall-clock phenomenon: a
    /// background wallet realizes a wake-up height as a wall-clock OS timer estimated from the
    /// target block spacing, and the per-wallet estimation error (block-time variance accumulated
    /// between scheduling and the wake-up) plus the OS's own delivery slop already smear
    /// same-height wallets WITHIN a block, so the jitter only needs to spread wallets ACROSS
    /// blocks.
    pub const DEFAULT: Self = Self {
        settle_margin: PROVABLE_ANCHOR_DEPTH,
        jitter_cap: 12,
    };

    /// Constructs wake-up parameters from their parts, for a test network that scales the schedule
    /// down (a production migration uses [`Self::DEFAULT`]).
    pub const fn new(settle_margin: u32, jitter_cap: u32) -> Self {
        Self {
            settle_margin,
            jitter_cap,
        }
    }

    /// The number of blocks past an anchor boundary at which a wake-up may be scheduled, giving
    /// the boundary time to settle. A zero margin is treated as one block when scheduling: a
    /// wake-up AT the boundary height cannot prove against it (the boundary must be strictly below
    /// the tip for its checkpoint to exist).
    pub fn settle_margin(&self) -> u32 {
        self.settle_margin
    }

    /// The inclusive upper bound on the uniform random jitter added to each wake-up height — a
    /// thundering-herd defense that spreads wallets' otherwise-synchronized wake-ups across the
    /// blocks after each shared grid point (see [`Self::DEFAULT`]). The jitter actually drawn is
    /// also bounded by the group's slack to its earliest broadcast deadline, so it never pushes a
    /// wake-up past a deadline.
    pub fn jitter_cap(&self) -> u32 {
        self.jitter_cap
    }
}

impl Default for WakeupParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One sync/proving wake-up of the schedule produced by [`schedule_sync_wakeups`]: the block
/// height at which to wake, and the transfers this wake-up is RESPONSIBLE for proving. At runtime
/// a wallet proves every transfer whose anchor boundary has settled at the time of the wake-up, so
/// a transfer may well be proved earlier than the wake-up that covers it; `covers` is the
/// assignment that guarantees every transfer is proved before its broadcast, not a restriction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncWakeup<T> {
    height: BlockHeight,
    covers: Vec<T>,
}

impl<T> SyncWakeup<T> {
    /// The block height at which the wallet should wake to sync and prove.
    pub fn height(&self) -> BlockHeight {
        self.height
    }

    /// The transfers this wake-up is responsible for proving, in a deterministic order (any
    /// overdue transfers first, then in broadcast-deadline order).
    pub fn covers(&self) -> &[T] {
        &self.covers
    }
}

/// The error returned when a transfer passed to [`schedule_sync_wakeups`] admits no valid wake-up
/// height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeupScheduleError<T> {
    /// The transfer's broadcast height is not at least two blocks above its anchor boundary, so no
    /// height exists at which the boundary has settled (is strictly below the tip) strictly before
    /// the broadcast. Unreachable for a schedule produced by this crate — a drawn anchor sits at
    /// least one full bucket interval below its broadcast height — so it indicates an inconsistent
    /// hand-assembled schedule, or a degenerate custom bucket interval of one block.
    InfeasibleTransfer(T),
}

impl<T: fmt::Debug> fmt::Display for WakeupScheduleError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WakeupScheduleError::InfeasibleTransfer(id) => write!(
                f,
                "transfer {id:?} has no height at which its anchor has settled strictly before its broadcast"
            ),
        }
    }
}

impl<T: fmt::Debug> core::error::Error for WakeupScheduleError<T> {}

/// The anchor-age cap that bounds the recency-weighted anchor draw (see [`draw_anchor_boundary`]),
/// and the modulus and width of the canonical rolling expiry window (see [`expiry_height`]).
///
/// Re-exported from [`zcash_protocol::zip318`], which owns the ZIP's specified values.
pub use zcash_protocol::zip318::{ANCHOR_AGE_CAP, EXPIRY_MODULUS, EXPIRY_WINDOW};

/// The scheduled broadcast and expiry heights of one migration transfer. Produced by
/// [`schedule`]; ties a part's [`broadcast_height`](Self::broadcast_height) (from the cumulative
/// delay draw) to its canonical [`expiry_height`](Self::expiry_height).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    broadcast_height: BlockHeight,
    expiry_height: BlockHeight,
}

impl Schedule {
    /// The block height at which this transfer is scheduled to be broadcast (a cumulative sum of
    /// per-part delays from the commit height; see [`schedule_broadcast_heights`]).
    pub fn broadcast_height(&self) -> BlockHeight {
        self.broadcast_height
    }

    /// The block height at (and after) which this transfer is no longer valid: the canonical rolling
    /// window of [`expiry_height`] applied at the broadcast height.
    pub fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }
}

/// Width of one step when the unit interval `[0, 1)` is split into `2^53` equal parts, i.e.
/// `1 / 2^53`. Drawing 53 random bits and scaling by this yields a value spread uniformly over those
/// `2^53` evenly spaced points; see [`draw_unit_half_open`].
const UNIT_STEP: f64 = 1.0 / ((1u64 << 53) as f64);

/// Number of high bits kept from a drawn `u64` to form a 53-bit mantissa (an `f64` has a 53-bit
/// significand, so this is the most uniform grid representable without rounding bias).
const U64_TO_MANTISSA_SHIFT: u32 = 11;

/// Draw a uniform `f64` in the half-open interval `[0, 1)` from `rng`, quantized to the `2^53` evenly
/// spaced 53-bit values. Keeps the top [`U64_TO_MANTISSA_SHIFT`] bits of a fresh `u64` and scales by
/// [`UNIT_STEP`].
fn draw_unit_half_open<R: RngCore>(rng: &mut R) -> f64 {
    ((rng.next_u64() >> U64_TO_MANTISSA_SHIFT) as f64) * UNIT_STEP
}

/// Draw a uniform `f64` in `(0, 1]` from `rng`. Complements [`draw_unit_half_open`] by mapping
/// `[0, 1)` to `(0, 1]` via `1 - u`, so `0` is excluded (keeping `ln` finite) and `1` is included.
fn draw_unit_left_open<R: RngCore>(rng: &mut R) -> f64 {
    1.0 - draw_unit_half_open(rng)
}

/// Round a non-negative `f64` to the nearest whole number (ties up), returned as `u32`. For `x >= 0`,
/// `round(x) = floor(x + 0.5)`, and `floor` of a non-negative value is truncation via `as u64`.
/// The caller guarantees `x` is non-negative and within `u32` range (delays are small).
fn round_nonneg_to_u32(x: f64) -> u32 {
    (x + 0.5) as u64 as u32
}

/// Produce a uniformly random permutation of `0..n` using an in-place Fisher-Yates shuffle driven by
/// `rng` (ZIP 318 "Transfer scheduling" SHUFFLE MUST). The caller applies the permutation to its
/// quantized parts so the broadcast ORDER of denominations is independent of the balance.
///
/// Returns the identity for `n == 0` or `n == 1`.
pub fn shuffle_indices<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..n).collect();
    shuffle_in_place(&mut indices, rng);
    indices
}

/// In-place uniform Fisher-Yates shuffle of `slice` using `rng` (ZIP 318 SHUFFLE MUST). Iterates
/// from the top, swapping each element with a uniformly chosen one at or below it, so every
/// permutation is equally likely. Leaves the multiset of elements unchanged.
pub fn shuffle_in_place<T, R: RngCore + CryptoRng>(slice: &mut [T], rng: &mut R) {
    let len = slice.len();
    if len < 2 {
        return;
    }
    // Standard downward Fisher-Yates: for i from len-1 down to 1, swap i with a uniform j in [0, i].
    let mut i = len - 1;
    while i > 0 {
        let j = gen_index(rng, i + 1);
        slice.swap(i, j);
        i -= 1;
    }
}

/// Draw a uniform integer in `[0, bound)` from `rng` (`bound > 0`) using Lemire's unbiased
/// widening-multiply method, so the shuffle is free of modulo bias. Reduces a fresh `u64` into the
/// range by taking the high half of `value * bound`, rejecting the rare low remainder region.
fn gen_index<R: RngCore>(rng: &mut R, bound: usize) -> usize {
    debug_assert!(bound > 0);
    let bound = bound as u64;
    loop {
        let value = rng.next_u64();
        let m = (value as u128) * (bound as u128);
        let low = m as u64;
        if low >= bound {
            return (m >> 64) as usize;
        }
        // low < bound: refine the rejection threshold only when we might be in the biased zone.
        let threshold = bound.wrapping_neg() % bound;
        if low >= threshold {
            return (m >> 64) as usize;
        }
    }
}

/// The cumulative-heights core shared by [`schedule_broadcast_heights`] and
/// [`schedule_prep_broadcast_heights`]: starting at `start`, advance a running height by an
/// independently drawn delay for each of the `n` entries. The returned vector has length `n`, is
/// non-decreasing, and every entry is `>= start`; heights saturate at `u32::MAX` rather than
/// overflowing (`BlockHeight`'s delta addition saturates).
fn cumulative_broadcast_heights<R: RngCore>(
    start: BlockHeight,
    n: usize,
    draw: impl Fn(&mut R) -> u32,
    rng: &mut R,
) -> Vec<BlockHeight> {
    let mut heights = Vec::with_capacity(n);
    let mut height = start;
    for _ in 0..n {
        height = height + draw(rng);
        heights.push(height);
    }
    heights
}

/// Compute the per-part scheduled broadcast heights: starting at `commit_height`, advance a running
/// height by an independently drawn `params.transfer_delay()` for each of the `n_parts` transfers
/// (ZIP 318 CUMULATIVE MUST). The returned vector has length `n_parts`, is non-decreasing, and every
/// entry is `>= commit_height`. Heights saturate at `u32::MAX` rather than overflowing.
pub fn schedule_broadcast_heights<R: RngCore + CryptoRng>(
    params: &SchedulingParams,
    commit_height: BlockHeight,
    n_parts: usize,
    rng: &mut R,
) -> Vec<BlockHeight> {
    let delay = params.transfer_delay();
    cumulative_broadcast_heights(commit_height, n_parts, |rng| delay.draw_inner(rng), rng)
}

/// Compute per-transaction scheduled broadcast heights for one PREPARATION layer: starting at
/// `start`, advance a running height by an independently drawn `params.preparation_delay()` for
/// each of the `n_txs` transactions. The returned vector has length `n_txs`, is non-decreasing, and
/// every entry is `>= start`; heights saturate at `u32::MAX`. The caller (the engine) bases each
/// later layer's `start` past the previous layer's last scheduled height plus a mining margin, so
/// layers stay serialized while the transactions within and across layers remain temporally
/// decoupled.
pub fn schedule_prep_broadcast_heights<R: RngCore + CryptoRng>(
    params: &SchedulingParams,
    start: BlockHeight,
    n_txs: usize,
    rng: &mut R,
) -> Vec<BlockHeight> {
    let delay = params.preparation_delay();
    cumulative_broadcast_heights(start, n_txs, |rng| delay.draw_inner(rng), rng)
}

/// The canonical rolling EXPIRY height for a transfer at `current_height` (ZIP 318 EXPIRY MUST):
/// the most recent multiple of [`EXPIRY_MODULUS`] at or below `current_height`, plus
/// [`EXPIRY_WINDOW`] (`2 * EXPIRY_MODULUS`).
///
/// This is a pure function of the height (it reveals nothing per-wallet) and guarantees between one
/// and two [`EXPIRY_MODULUS`] periods (about 1 to 2 months) of remaining validity: the result is
/// always strictly greater than `current_height` and at most `EXPIRY_WINDOW` above it. Saturates at
/// `u32::MAX`.
pub use zcash_protocol::zip318::expiry_height;

/// Compute the MINIMAL schedule of sync/proving wake-ups covering `transfers`, each given as
/// `(id, anchor_boundary, broadcast_height)` — for a committed migration, a transfer's drawn
/// [`MigrationTransaction::anchor_boundary`] and [`Schedule::broadcast_height`]. Returns one
/// [`SyncWakeup`] per wake-up, in strictly increasing height order; at each, the wallet syncs to
/// the wake-up height and proves every transfer whose anchor boundary has settled.
///
/// Each transfer must be proved after its anchor boundary settles (strictly below the tip, at
/// least [`WakeupParams::settle_margin`] blocks past it) and strictly before its broadcast height
/// (sync and broadcast never share a wake window), giving it a proving WINDOW of heights. The
/// fewest wake-ups piercing every window is the classic minimum piercing-set problem, solved
/// optimally by a greedy pass over the windows in deadline order; each wake-up lands at the
/// latest window-opening height of the group it covers — under real parameters, a bucketed anchor
/// height plus the settle margin — plus a uniform random jitter bounded by both
/// [`WakeupParams::jitter_cap`] and the group's slack. The jitter exists as a THUNDERING-HERD
/// defense: anchor boundaries sit on a global grid shared by every migrating wallet, so
/// un-jittered wake-ups would all land on the same heights and stampede the light wallet servers
/// (as well as mark the wallet as migrating). It is drawn from a [`CryptoRng`] because wake-up
/// times are observables.
///
/// No wake-up is scheduled below `current_tip` (the chain tip the wallet has observed — for a
/// freshly committed schedule, the commit height); a wake-up at exactly `current_tip` means
/// "right now". A transfer whose deadline is already below the tip but which still needs a proof
/// joins an immediate wake-up at exactly `current_tip` instead (mirroring
/// [`advance_migration`], which offers `Prove` for it now); this is not an error. That
/// immediate wake-up also absorbs any transfer whose proving window CONTAINS `current_tip` (i.e.
/// whose clamped ready height is exactly `current_tip`): its mandatory piercing point covers them
/// for free, which is what keeps the schedule minimal whenever overdue transfers are present.
///
/// Returns [`WakeupScheduleError::InfeasibleTransfer`] for a transfer whose broadcast height is
/// not at least two blocks above its anchor boundary (no settle-then-prove height exists), which
/// no schedule produced by this crate contains.
///
/// [`MigrationTransaction::anchor_boundary`]: crate::engine::MigrationTransaction::anchor_boundary
/// [`advance_migration`]: crate::satisfiability::advance_migration
pub fn schedule_sync_wakeups<T: Copy, R: RngCore + CryptoRng>(
    params: &WakeupParams,
    current_tip: BlockHeight,
    transfers: &[(T, BlockHeight, BlockHeight)],
    rng: &mut R,
) -> Result<Vec<SyncWakeup<T>>, WakeupScheduleError<T>> {
    let tip = u32::from(current_tip);
    // A zero margin would place a wake-up AT the boundary height, where the boundary is not yet
    // strictly below the tip and cannot be proved against; clamp up to one block.
    let margin = params.settle_margin().max(1);

    // Assemble each transfer's proving window `[ready, deadline]`, splitting off the overdue ones
    // (deadline already below the tip).
    let mut overdue: Vec<T> = Vec::new();
    let mut windows: Vec<(u32, u32, T)> = Vec::new();
    for &(id, anchor, broadcast) in transfers {
        let a = u32::from(anchor);
        let b = u32::from(broadcast);
        if b <= a.saturating_add(1) {
            return Err(WakeupScheduleError::InfeasibleTransfer(id));
        }
        let deadline = b - 1;
        // The min-clamp keeps a window whose gap is below the margin feasible (tiny test-network
        // intervals); the max-clamp keeps the wake-up out of the past.
        let ready = a.saturating_add(margin).min(deadline).max(tip);
        if deadline < tip {
            overdue.push(id);
        } else {
            windows.push((deadline, ready, id));
        }
    }
    windows.sort_by_key(|&(deadline, ready, _)| (deadline, ready));

    // When an overdue transfer forces a mandatory wake-up at the tip, that wake-up's piercing
    // point is fixed in advance; every window whose clamped ready height is exactly the tip (its
    // proving window CONTAINS `current_tip`) is covered by it for free. Fold those ids into the
    // immediate wake-up instead of letting them enter the greedy below, where they could open (or
    // worse, drag later windows into) a suboptimal group. Without an overdue transfer there is no
    // mandatory point, and the classic greedy over all windows is already optimal on its own.
    if !overdue.is_empty() {
        let mut surviving = Vec::with_capacity(windows.len());
        for (deadline, ready, id) in windows {
            if ready == tip {
                overdue.push(id);
            } else {
                surviving.push((deadline, ready, id));
            }
        }
        windows = surviving;
    }

    // Greedy grouping in deadline order: a window joins the open group iff it still contains the
    // group's first (smallest) deadline; the group's wake-up point will lie in
    // `[max_ready, first_deadline]`, which every member's window contains. A window that fails the
    // open group fails every earlier (smaller-deadline) group too, so a new group is opened
    // exactly when the classic optimal greedy would place a new piercing point.
    struct Group<T> {
        first_deadline: u32,
        max_ready: u32,
        covers: Vec<T>,
    }
    let mut groups: Vec<Group<T>> = Vec::new();
    for (deadline, ready, id) in windows {
        match groups.last_mut() {
            Some(g) if ready <= g.first_deadline => {
                g.max_ready = g.max_ready.max(ready);
                g.covers.push(id);
            }
            _ => groups.push(Group {
                first_deadline: deadline,
                max_ready: ready,
                covers: vec![id],
            }),
        }
    }

    // Assemble: an immediate wake-up covering the overdue transfers plus every window that
    // contains `current_tip` (folded in above), then one jittered wake-up per surviving group.
    // Every surviving group's ready height is strictly above the tip (windows landing on it were
    // folded into the immediate wake-up), and group heights were already strictly increasing
    // among themselves, so no merge between the immediate wake-up and the first group is needed.
    let mut wakeups: Vec<SyncWakeup<T>> = Vec::with_capacity(groups.len() + 1);
    if !overdue.is_empty() {
        wakeups.push(SyncWakeup {
            height: BlockHeight::from_u32(tip),
            covers: overdue,
        });
    }
    for g in groups {
        let slack = g.first_deadline - g.max_ready;
        let bound = params.jitter_cap().min(slack);
        let jitter = if bound == 0 {
            0
        } else {
            gen_index(rng, bound as usize + 1) as u32
        };
        let height = g.max_ready + jitter;
        wakeups.push(SyncWakeup {
            height: BlockHeight::from_u32(height),
            covers: g.covers,
        });
    }
    Ok(wakeups)
}

/// Assemble a [`Schedule`] for each part: draw the cumulative broadcast heights from `commit_height`
/// (see [`schedule_broadcast_heights`]) and pair each with its canonical [`expiry_height`]. Returns
/// one [`Schedule`] per part, in the (already shuffled) part order the caller passes.
pub fn schedule<R: RngCore + CryptoRng>(
    params: &SchedulingParams,
    commit_height: BlockHeight,
    n_parts: usize,
    rng: &mut R,
) -> Vec<Schedule> {
    schedule_broadcast_heights(params, commit_height, n_parts, rng)
        .into_iter()
        .map(|broadcast_height| Schedule {
            broadcast_height,
            expiry_height: expiry_height(broadcast_height),
        })
        .collect()
}

/// Draw an anchor AGE `a >= 1` from the recency-weighted `Geometric(1/2)` distribution: `a` is the
/// number of failed fair-coin flips plus one (ZIP 318 ANCHOR-AGE-DRAW MUST). So `P(a = 1) = 1/2`,
/// `P(a = 2) = 1/4`, ...; the modal age is 1, the mean age is 2, and age 0 (the most recent
/// boundary) is NEVER produced. Each bit of a fresh `u64` is one fair coin flip.
///
/// Age 0 is excluded DELIBERATELY, declining a proposed ZIP 318 revision that would admit it: a
/// transfer anchored to the most recent boundary must have been proved in the interval since that
/// boundary, so when its broadcast falls close to the boundary, a light wallet server that also
/// saw the wallet sync inside that narrow window can correlate the two by IP address. Ages `>= 1`
/// keep the proving window at least one full boundary interval wide. See
/// <https://github.com/zcash/zips/pull/1343#issuecomment-5124302101>.
fn draw_anchor_age<R: RngCore>(rng: &mut R) -> u32 {
    let mut age: u32 = 1;
    loop {
        // Consume 64 fair coin flips per word; a set bit is "success" (stop).
        let mut bits = rng.next_u64();
        for _ in 0..u64::BITS {
            if bits & 1 == 1 {
                return age;
            }
            bits >>= 1;
            age += 1;
        }
    }
}

/// Select the boundary height a transfer proves its Orchard anchor against, drawn at PROVING time
/// (ZIP 318 ANCHOR-SELECTION MUST). Returns the chosen boundary HEIGHT, or `None` if the candidate
/// set is empty. The wallet backend later resolves the actual tree state at that height (out of
/// scope here).
///
/// The CANDIDATE ANCHOR SET is the boundaries of `interval` that are simultaneously:
/// - (a) strictly above `nu63_activation` (the NU6.3 activation height),
/// - (b) at or after `funding_creation_height` (the funding note's creation height), and
/// - (c) at or before the most recent boundary at or below `chain_tip_height` (the chain tip the
///   wallet has observed at proving time).
///
/// The most recent boundary is derived internally via
/// [`AnchorBucketInterval::boundary_at_or_below`], so `chain_tip_height` may be any observed
/// height; it need not itself be a boundary. A recency-weighted age `a` in `[1, ANCHOR_AGE_CAP]` is
/// drawn (`Geometric(1/2)`) and the candidate is `most_recent - a * interval`; a draw exceeding
/// [`ANCHOR_AGE_CAP`] or landing outside the candidate set is discarded and redrawn. Because age is
/// always `>= 1`, the chosen boundary is always strictly below the most recent boundary.
pub fn draw_anchor_boundary<R: RngCore + CryptoRng>(
    interval: AnchorBucketInterval,
    nu63_activation: BlockHeight,
    funding_creation_height: BlockHeight,
    chain_tip_height: BlockHeight,
    rng: &mut R,
) -> Option<BlockHeight> {
    let most_recent = boundary_at_or_below_u32(&interval, u32::from(chain_tip_height));
    let (lowest, highest) = candidate_boundary_bounds(
        interval,
        u32::from(nu63_activation),
        u32::from(funding_creation_height),
        most_recent,
    )?;
    Some(BlockHeight::from_u32(sample_recency_weighted_boundary(
        interval,
        lowest,
        highest,
        most_recent,
        rng,
    )))
}

/// Select a REPLACEMENT boundary for a transfer whose broadcast schedule has moved out from under
/// its drawn anchor — the overdue shift
/// ([`advance_migration`](crate::satisfiability::advance_migration)) defers every pending
/// broadcast when a wallet resumes after downtime, and a boundary that was in-distribution for
/// the ORIGINAL schedule sits `delta` blocks too old against the shifted one. With
/// [`ANCHOR_AGE_CAP`] at 4 buckets, even a modest shift leaves an anchor age no honest draw
/// produces, and every deferred transfer of one wallet would carry the SAME excess age — a
/// linkable fingerprint. Redrawing against the new schedule restores the age distribution the
/// anchor cohorts rely on.
///
/// The draw is [`draw_anchor_boundary`]'s recency-weighted draw against the NEW
/// `broadcast_height`, with the candidate set floored at `prior_boundary` — the boundary being
/// replaced — instead of the funding constraints: every note witnessable in the prior boundary's
/// tree state is witnessable in every later one, so the floor preserves provability without the
/// funding-note heights this crate's state does not hold. (A funding note that POSTDATES the
/// prior boundary is the separate staleness `prove_transfer` re-validates and re-draws for at
/// proving time, with the real mined heights in hand.) The prior boundary also subsumes the
/// NU6.3-activation bound, which it satisfies by construction.
///
/// Returns `None` when no candidate at or above `prior_boundary` lies strictly below the most
/// recent boundary at `broadcast_height` — possible only when the prior boundary was itself
/// drawn against a tip past the new schedule (a proving-time re-draw followed by a small shift);
/// the caller keeps the prior boundary, which remains provable.
///
/// [`prove_transfer`]: crate::engine::prove_transfer
pub fn redraw_anchor_boundary<R: RngCore + CryptoRng>(
    interval: AnchorBucketInterval,
    prior_boundary: BlockHeight,
    broadcast_height: BlockHeight,
    rng: &mut R,
) -> Option<BlockHeight> {
    let most_recent = boundary_at_or_below_u32(&interval, u32::from(broadcast_height));
    // Highest candidate: strictly below the most recent boundary (age >= 1), one interval down.
    let highest = most_recent.checked_sub(interval.block_count().get())?;
    let lowest = boundary_at_or_above_u32(&interval, u32::from(prior_boundary));
    if lowest > highest {
        return None;
    }
    Some(BlockHeight::from_u32(sample_recency_weighted_boundary(
        interval,
        lowest,
        highest,
        most_recent,
        rng,
    )))
}

/// The rejection-sampling core shared by [`draw_anchor_boundary`] and
/// [`redraw_anchor_boundary`]: draw recency-weighted ages until `most_recent - age * interval`
/// lands in `[lowest, highest]`, and return that candidate. The caller guarantees
/// `lowest <= highest` and `highest = most_recent - interval` (both grid boundaries), so age 1
/// always yields `highest` and the loop terminates.
fn sample_recency_weighted_boundary<R: RngCore>(
    interval: AnchorBucketInterval,
    lowest: u32,
    highest: u32,
    most_recent: u32,
    rng: &mut R,
) -> u32 {
    loop {
        let age = draw_anchor_age(rng);
        if age > ANCHOR_AGE_CAP {
            continue;
        }
        // age * interval, guarding the overflow a large interval could produce (too-old anchor ->
        // redraw, the same outcome the underflow check below gives).
        let candidate = match age
            .checked_mul(interval.block_count().get())
            .and_then(|offset| most_recent.checked_sub(offset))
        {
            Some(c) => c,
            None => continue,
        };
        if candidate >= lowest && candidate <= highest {
            return candidate;
        }
    }
}

/// The inclusive `[lowest, highest]` boundary-height bounds of the candidate anchor set, or `None`
/// if the set is empty. Encodes the three candidate-set conditions of [`draw_anchor_boundary`]:
/// the highest usable boundary is the one strictly below `most_recent` (age `>= 1`), and the
/// lowest is the first boundary that is both strictly above `nu63_activation` and at or after
/// `funding_creation_height`. `most_recent` is the boundary derived from the observed chain tip.
fn candidate_boundary_bounds(
    interval: AnchorBucketInterval,
    nu63_activation: u32,
    funding_creation_height: u32,
    most_recent: u32,
) -> Option<(u32, u32)> {
    // Highest candidate: strictly below the most recent boundary, i.e. one interval down.
    let highest = most_recent.checked_sub(interval.block_count().get())?;

    let lowest = lowest_candidate_boundary(interval, nu63_activation, funding_creation_height);

    (lowest <= highest).then_some((lowest, highest))
}

/// The lowest boundary that satisfies both lower-bound conditions of [`draw_anchor_boundary`]: the
/// first boundary strictly ABOVE `nu63_activation`, and the first boundary at or AFTER
/// `funding_creation_height`, whichever is higher. Saturates at `u32::MAX`.
fn lowest_candidate_boundary(
    interval: AnchorBucketInterval,
    nu63_activation: u32,
    funding_creation_height: u32,
) -> u32 {
    let above_activation = boundary_at_or_below_u32(&interval, nu63_activation)
        .saturating_add(interval.block_count().get());
    let at_or_after_funding = boundary_at_or_above_u32(&interval, funding_creation_height);
    above_activation.max(at_or_after_funding)
}

/// The first chain height at which a transfer's candidate anchor set (see
/// [`draw_anchor_boundary`]) is non-empty: one full boundary interval past the LOWEST candidate,
/// which is the first boundary strictly above `nu63_activation` and at or after
/// `funding_creation_height`. A transfer whose observed chain tip is at or after this height always
/// has at least one boundary to anchor to, so a schedule that places every broadcast at or after it
/// never needs an anchor fallback; the scheduler MUST NOT place a transfer before it.
pub fn earliest_broadcast_height(
    interval: AnchorBucketInterval,
    nu63_activation: BlockHeight,
    funding_creation_height: BlockHeight,
) -> BlockHeight {
    let lowest = lowest_candidate_boundary(
        interval,
        u32::from(nu63_activation),
        u32::from(funding_creation_height),
    );
    BlockHeight::from_u32(lowest.saturating_add(interval.block_count().get()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::zip318::{PREP_DELAY_CAP, TRANSFER_DELAY_CAP};

    /// A seeded deterministic RNG for a proptest-drawn seed.
    fn rng(seed: u64) -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(seed)
    }

    /// Shorthand [`BlockHeight`] constructor for test literals.
    fn bh(h: u32) -> BlockHeight {
        BlockHeight::from_u32(h)
    }

    /// The ZIP 318 parameters, under which every golden vector in this module was captured.
    const P: SchedulingParams = SchedulingParams::ZIP_318;

    /// An anchor bucket interval of `blocks` blocks.
    fn interval(blocks: u32) -> AnchorBucketInterval {
        AnchorBucketInterval::custom(NonZeroU32::new(blocks).expect("nonzero"))
    }

    /// Scheduling parameters that differ from ZIP 318 only in the anchor bucket interval, for
    /// checking that the boundary logic follows the configured grid.
    fn params_with_interval(blocks: u32) -> SchedulingParams {
        SchedulingParams::new(interval(blocks), P.transfer_delay(), P.preparation_delay())
    }

    // --- AnchorBucketInterval boundary helpers ------------------------------------------------

    proptest! {
        /// Rounding DOWN yields a boundary of the configured interval that does not exceed the
        /// height and is within one interval of it, whatever that interval is.
        #[test]
        fn boundary_at_or_below_props(h in 0u32..5_000_000, blocks in 1u32..10_000) {
            let i = interval(blocks);
            let b = u32::from(i.boundary_at_or_below(bh(h)));
            prop_assert!(i.is_boundary(bh(b)));
            prop_assert!(b <= h);
            prop_assert!(h - b < blocks);
        }

        /// Rounding UP yields a boundary `>= height`, within one interval above it.
        #[test]
        fn boundary_at_or_above_props(h in 0u32..5_000_000, blocks in 1u32..10_000) {
            let i = interval(blocks);
            let b = u32::from(i.boundary_at_or_above(bh(h)));
            prop_assert!(i.is_boundary(bh(b)));
            prop_assert!(b >= h);
            prop_assert!(b - h < blocks);
        }
    }

    /// Assert one hand-derived [`AnchorBucketInterval::boundary_at_or_below`] value plus its
    /// invariants (a boundary, `<= height`, and within one interval of it) at the ZIP 318 interval.
    fn check_most_recent_boundary_golden(height: u32, expected: u32) {
        let i = P.anchor_bucket_interval();
        let b = u32::from(i.boundary_at_or_below(bh(height)));
        assert_eq!(b, expected, "boundary_at_or_below({height})");
        assert!(i.is_boundary(bh(b)), "not a boundary");
        assert!(b <= height, "boundary {b} above height {height}");
        assert!(
            height - b < i.block_count().get(),
            "boundary {b} more than an interval below {height}"
        );
    }

    /// Golden vectors for [`AnchorBucketInterval::boundary_at_or_below`], hand-derived from the
    /// ZIP 318 interval of 144: the result is `height - (height % 144)`.
    #[test]
    fn most_recent_boundary_golden() {
        // Each case is (input height, expected boundary = height rounded down to a multiple of 144).
        let cases: [(u32, u32); 7] = [
            (0, 0),
            (143, 0),
            (144, 144), // exact boundary maps to itself
            (287, 144),
            (288, 288),           // 2 * 144
            (300, 288),           // 300 = 2*144 + 12
            (1_000_000, 999_936), // 6944 * 144 = 999_936, rem 64
        ];
        for (height, exp_output) in cases {
            check_most_recent_boundary_golden(height, exp_output);
        }
    }

    // --- DelayDistribution::draw --------------------------------------------------------------

    proptest! {
        /// Every drawn delay is in the closed range `[0, cap]`, whatever the configured
        /// distribution (DELAYS MUST).
        #[test]
        fn delay_within_bounds(seed in any::<u64>(), mean in 1u32..1_000, extra in 0u32..2_000) {
            let dist = DelayDistribution::new(
                NonZeroU32::new(mean).expect("nonzero"),
                NonZeroU32::new(mean + extra).expect("nonzero"),
            ).expect("cap >= mean");
            let mut r = rng(seed);
            for _ in 0..200 {
                prop_assert!(dist.draw(&mut r) <= dist.cap().get());
            }
        }
    }

    /// The ratio-derived constructor reproduces the ZIP 318 parameters exactly at the ZIP 318
    /// bucket interval. This is what binds the two encodings of the specified values: the literal
    /// `ZIP_318` (which keeps the spec's numbers greppable) and the ratios
    /// `new_with_default_distributions` generalizes them by. If either drifts, this fails.
    #[test]
    fn default_distributions_reproduce_zip_318() {
        assert_eq!(
            SchedulingParams::new_with_default_distributions(AnchorBucketInterval::ZIP_318),
            SchedulingParams::ZIP_318,
        );
    }

    /// A scaled-down interval scales the whole schedule by the same factor, so a test network gets
    /// the ZIP 318 shape compressed rather than a distorted one.
    #[test]
    fn default_distributions_scale_with_the_interval() {
        // A twelfth of the ZIP 318 interval: 12 blocks per bucket, so every delay parameter is a
        // twelfth of its ZIP 318 value, truncated.
        let p = SchedulingParams::new_with_default_distributions(interval(12));
        assert_eq!(p.transfer_delay().mean().get(), 5); // floor(66 / 12)
        assert_eq!(p.transfer_delay().cap().get(), 48); // 576 / 12
        assert_eq!(p.preparation_delay().mean().get(), 1); // floor(16 / 12)
        assert_eq!(p.preparation_delay().cap().get(), 8); // 96 / 12
    }

    /// Every bucket interval yields a usable pair of distributions, including the degenerate ends:
    /// a short enough interval would truncate the preparation mean to zero, and a very large one
    /// would overflow the caps.
    #[test]
    fn default_distributions_are_usable_at_the_extremes() {
        // Up to 8 blocks per bucket the scaled preparation mean (16 * blocks / 144) truncates to
        // zero, and is clamped up.
        for blocks in 1..=8 {
            let p = SchedulingParams::new_with_default_distributions(interval(blocks));
            assert_eq!(p.preparation_delay().mean(), NonZeroU32::MIN, "{blocks}");
            assert!(p.preparation_delay().cap() >= p.preparation_delay().mean());
        }

        // At the top of the range the caps saturate rather than wrapping below their means.
        let huge = SchedulingParams::new_with_default_distributions(interval(u32::MAX));
        assert_eq!(huge.transfer_delay().cap().get(), u32::MAX);
        assert!(huge.transfer_delay().cap() >= huge.transfer_delay().mean());
    }

    proptest! {
        /// Whatever the interval, the derived distributions satisfy `DelayDistribution`'s own
        /// invariant (a cap not below the mean), so they are exactly what the validated constructor
        /// would have accepted.
        #[test]
        fn default_distributions_always_valid(blocks in 1u32..) {
            let p = SchedulingParams::new_with_default_distributions(interval(blocks));
            prop_assert_eq!(p.anchor_bucket_interval().block_count().get(), blocks);
            for dist in [p.transfer_delay(), p.preparation_delay()] {
                prop_assert!(dist.cap() >= dist.mean());
                prop_assert_eq!(DelayDistribution::new(dist.mean(), dist.cap()), Some(dist));
            }
        }
    }

    #[test]
    fn delay_distribution_rejects_cap_below_mean() {
        let nz = |n: u32| NonZeroU32::new(n).expect("nonzero");
        assert!(DelayDistribution::new(nz(144), nz(143)).is_none());
        assert!(DelayDistribution::new(nz(144), nz(144)).is_some());
        assert!(DelayDistribution::new(nz(144), nz(576)).is_some());
    }

    /// The drawn delays scale with the configured mean: a distribution with `k` times the mean
    /// produces approximately `k` times the delays from the same seed, so a shortened test-network
    /// configuration compresses the schedule rather than distorting its shape.
    #[test]
    fn delay_scales_with_configured_mean() {
        let nz = |n: u32| NonZeroU32::new(n).expect("nonzero");
        let base = DelayDistribution::new(nz(24), nz(96)).expect("cap >= mean");
        let scaled = DelayDistribution::new(nz(144), nz(576)).expect("cap >= mean");
        let mut r_base = rng(1);
        let mut r_scaled = rng(1);
        for _ in 0..32 {
            let b = base.draw(&mut r_base);
            let s = scaled.draw(&mut r_scaled);
            // Both round the same underlying unit draw, so they agree within the rounding slack.
            assert!(
                s.abs_diff(b * 6) <= 6,
                "scaled draw {s} is not ~6x the base draw {b}"
            );
        }
    }

    #[test]
    fn delay_mean_is_near_expected() {
        // Sanity on the distribution: the truncated-exponential mean sits below MEAN_DELAY (the
        // tail past TRANSFER_DELAY_CAP is removed). Large sample keeps this deterministic and
        // robust.
        let mut r = rng(42);
        let n = 20_000u64;
        let mut sum = 0u64;
        for _ in 0..n {
            sum += u64::from(P.transfer_delay().draw(&mut r));
        }
        let mean = sum as f64 / n as f64;
        // The cap sits at more than eight means, so truncation barely bites: the analytic
        // truncated mean is ~65.9 blocks. Allow a wide band.
        assert!(
            (60.0..72.0).contains(&mean),
            "empirical mean {mean} out of expected band"
        );
    }

    /// Assert a golden sequence of ZIP 318 transfer-delay draws for a fixed seed, pinning the exact
    /// deterministic [`ChaCha8Rng`] output as a regression guard, plus the documented invariant that
    /// every delay is within the distribution's cap (the truncated-exponential bound).
    fn check_delay_golden(seed: u64, expected: &[u32]) {
        let mut r = rng(seed);
        let got: Vec<u32> = (0..expected.len())
            .map(|_| P.transfer_delay().draw(&mut r))
            .collect();
        assert_eq!(got, expected, "transfer_delay().draw(seed={seed})");
        let cap = TRANSFER_DELAY_CAP.get();
        for &d in &got {
            assert!(d <= cap, "delay {d} exceeds the cap {cap}");
        }
    }

    /// Golden vectors for the ZIP 318 transfer delay over several seeds. These are the captured deterministic
    /// draws; the `seed=1` sequence matches the per-step gaps pinned in
    /// [`schedule_broadcast_heights_golden`] (34, 6, 60, 16, 22, ...).
    #[test]
    fn draw_delay_golden() {
        let exp_seed1 = [34, 6, 60, 16, 22, 82, 41, 11];
        let exp_seed42 = [76, 198, 37, 65, 22, 11, 24, 108];
        let exp_seed7 = [11, 12, 80, 86, 61, 29, 6, 125];
        check_delay_golden(1, &exp_seed1);
        check_delay_golden(42, &exp_seed42);
        check_delay_golden(7, &exp_seed7);
    }

    // --- schedule_sync_wakeups ----------------------------------------------------------------

    /// The provisional default wake-up parameters: the task-specified 10-block settle margin and a
    /// 12-block (about 15 minute) thundering-herd jitter cap.
    #[test]
    fn wakeup_params_default() {
        assert_eq!(WakeupParams::DEFAULT.settle_margin(), 10);
        assert_eq!(WakeupParams::DEFAULT.jitter_cap(), 12);
        assert_eq!(WakeupParams::default(), WakeupParams::DEFAULT);
        let custom = WakeupParams::new(3, 5);
        assert_eq!(custom.settle_margin(), 3);
        assert_eq!(custom.jitter_cap(), 5);
    }

    /// The infeasibility error names the offending transfer and renders a diagnostic.
    #[test]
    fn wakeup_error_display() {
        let e = WakeupScheduleError::InfeasibleTransfer(7u32);
        assert_eq!(
            alloc::format!("{e}"),
            "transfer 7 has no height at which its anchor has settled strictly before its broadcast"
        );
    }

    /// No pending transfers need no wake-ups.
    #[test]
    fn no_transfers_no_wakeups() {
        let got = schedule_sync_wakeups::<u32, _>(&WakeupParams::DEFAULT, bh(0), &[], &mut rng(1))
            .expect("an empty schedule is feasible");
        assert!(got.is_empty());
    }

    /// A single transfer gets one wake-up inside its proving window: at or after its anchor plus
    /// the settle margin, within the jitter cap of that base, and strictly before its broadcast.
    #[test]
    fn single_transfer_single_wakeup() {
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::DEFAULT,
            bh(0),
            &[(7u32, bh(1440), bh(1600))],
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(wakeups.len(), 1);
        let w = u32::from(wakeups[0].height());
        assert!(
            (1450..=1450 + WakeupParams::DEFAULT.jitter_cap()).contains(&w),
            "height {w} outside jitter range"
        );
        assert!(w < 1600, "height {w} not before the broadcast");
        assert_eq!(wakeups[0].covers(), &[7]);
    }

    /// A broadcast not at least two blocks above its anchor admits no settle-then-prove height.
    #[test]
    fn adjacent_broadcast_is_infeasible() {
        for (id, a, b) in [(1u32, 100, 101), (2, 100, 100), (3, 100, 99)] {
            assert_eq!(
                schedule_sync_wakeups(
                    &WakeupParams::DEFAULT,
                    bh(0),
                    &[(id, bh(a), bh(b))],
                    &mut rng(1)
                ),
                Err(WakeupScheduleError::InfeasibleTransfer(id)),
            );
        }
    }

    /// Transfers whose proving windows overlap share one wake-up at the latest ready height among
    /// them (a bucketed anchor + margin), which is what makes the schedule minimal.
    #[test]
    fn overlapping_windows_share_a_wakeup() {
        // Jitter cap 0 makes the chosen heights exact. Windows [154, 999] and [298, 1099] overlap.
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::new(10, 0),
            bh(0),
            &[(0u32, bh(144), bh(1000)), (1, bh(288), bh(1100))],
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(wakeups.len(), 1);
        assert_eq!(u32::from(wakeups[0].height()), 298);
        assert_eq!(wakeups[0].covers(), &[0, 1]);
    }

    /// A transfer whose window opens after an earlier group's deadline gets its own wake-up.
    #[test]
    fn disjoint_windows_get_separate_wakeups() {
        // Window [154, 299] closes before window [1450, 2000] opens.
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::new(10, 0),
            bh(0),
            &[(0u32, bh(144), bh(300)), (1, bh(1440), bh(2001))],
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(wakeups.len(), 2);
        assert_eq!(u32::from(wakeups[0].height()), 154);
        assert_eq!(wakeups[0].covers(), &[0]);
        assert_eq!(u32::from(wakeups[1].height()), 1450);
        assert_eq!(wakeups[1].covers(), &[1]);
    }

    /// A transfer whose broadcast deadline already passed while it is unproved joins an immediate
    /// wake-up at `current_tip`, which also absorbs any transfer whose proving window contains
    /// `current_tip`.
    #[test]
    fn overdue_transfers_wake_immediately() {
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::new(10, 0),
            bh(5000),
            &[
                (0u32, bh(144), bh(300)), // deadline 299 < 5000: overdue
                (1, bh(4320), bh(6000)), // window [4330, 5999] contains 5000: absorbed into the immediate wake-up
                (2, bh(7200), bh(8000)), // ready 7210: its own group
            ],
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(wakeups.len(), 2);
        assert_eq!(u32::from(wakeups[0].height()), 5000);
        assert_eq!(wakeups[0].covers(), &[0, 1]);
        assert_eq!(u32::from(wakeups[1].height()), 7210);
        assert_eq!(wakeups[1].covers(), &[2]);
    }

    /// When an overdue transfer forces an immediate wake-up, a transfer whose proving window
    /// contains `current_tip` is absorbed by that mandatory wake-up even under nonzero jitter,
    /// rather than paying for a jittered wake-up of its own.
    #[test]
    fn overdue_wakeup_absorbs_contained_windows_despite_jitter() {
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::DEFAULT, // jitter cap 12: a separate group would almost surely jitter off 5000
            bh(5000),
            &[
                (0u32, bh(144), bh(300)), // deadline 299 < 5000: overdue
                (1, bh(4320), bh(6000)),  // window [4330, 5999] contains 5000: absorbed
            ],
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(wakeups.len(), 1);
        assert_eq!(u32::from(wakeups[0].height()), 5000);
        assert_eq!(wakeups[0].covers(), &[0, 1]);
    }

    /// Folding `current_tip`-containing windows into the mandatory wake-up keeps the schedule
    /// minimal even when such a window would otherwise drag later windows into a worse grouping:
    /// here the greedy over all three windows would produce three wake-ups, but the mandatory
    /// point covers the first window for free, letting the remaining two share one.
    #[test]
    fn overdue_wakeup_folding_preserves_minimality() {
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::new(10, 0),
            bh(100),
            &[
                (0u32, bh(10), bh(50)), // overdue
                (1, bh(50), bh(106)), // window clamps to [100, 105]: absorbed by the mandatory point
                (2, bh(92), bh(111)), // window [102, 110]
                (3, bh(96), bh(301)), // window [106, 300]: groups with the previous one
            ],
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(wakeups.len(), 2);
        assert_eq!(u32::from(wakeups[0].height()), 100);
        assert_eq!(wakeups[0].covers(), &[0, 1]);
        assert_eq!(u32::from(wakeups[1].height()), 106);
        assert_eq!(wakeups[1].covers(), &[2, 3]);
    }

    /// At a tiny custom bucket interval the default margin exceeds the anchor->broadcast gap; the
    /// ready height clamps to the deadline so the schedule stays feasible.
    #[test]
    fn tiny_interval_clamps_the_margin() {
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::new(10, 0),
            bh(0),
            &[(0u32, bh(100), bh(104))], // window would be [110, 103]; ready clamps to 103
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(u32::from(wakeups[0].height()), 103);
    }

    /// A zero settle margin is clamped up to one block: a wake-up AT the boundary height cannot
    /// prove against it (the boundary must be strictly below the tip).
    #[test]
    fn zero_margin_clamps_to_one() {
        let wakeups = schedule_sync_wakeups(
            &WakeupParams::new(0, 0),
            bh(0),
            &[(0u32, bh(100), bh(300))],
            &mut rng(1),
        )
        .expect("feasible");
        assert_eq!(u32::from(wakeups[0].height()), 101);
    }

    /// A brute-force optimum for the piercing problem: the fewest points covering every window
    /// `(ready, deadline)`, with candidate points drawn from the window deadlines (an optimal
    /// solution always exists on deadlines: any piercing point can be shifted up to the deadline
    /// of the earliest-ending window it pierces without uncovering anything). Exponential in the
    /// window count; usable only for the small inputs the minimality proptest generates.
    fn brute_force_min_wakeups(windows: &[(u32, u32)]) -> usize {
        let n = windows.len();
        let candidates: Vec<u32> = windows.iter().map(|&(_, d)| d).collect();
        let mut best = n;
        for mask in 0u32..(1u32 << n) {
            let covers_all = windows.iter().all(|&(r, d)| {
                (0..n).any(|j| mask & (1 << j) != 0 && r <= candidates[j] && candidates[j] <= d)
            });
            if covers_all {
                best = best.min(mask.count_ones() as usize);
            }
        }
        best
    }

    proptest! {
        /// Every transfer is covered by exactly one wake-up, inside its proving window (or at
        /// exactly `current_tip` when overdue); no wake-up is scheduled in the past; wake heights
        /// strictly increase.
        #[test]
        fn wakeups_cover_every_transfer(
            seed in any::<u64>(),
            tip in 0u32..3_000_000,
            xs in prop::collection::vec((0u32..2_000_000, 2u32..100_000), 1..40),
        ) {
            let transfers: Vec<(usize, BlockHeight, BlockHeight)> = xs
                .iter()
                .enumerate()
                .map(|(i, &(a, gap))| (i, bh(a), bh(a + gap)))
                .collect();
            let wakeups =
                schedule_sync_wakeups(&WakeupParams::DEFAULT, bh(tip), &transfers, &mut rng(seed))
                    .expect("a gap of at least 2 blocks is feasible");
            let margin = WakeupParams::DEFAULT.settle_margin().max(1);

            let mut prev: Option<u32> = None;
            for w in &wakeups {
                let h = u32::from(w.height());
                prop_assert!(h >= tip, "wake-up {h} below the tip {tip}");
                if let Some(p) = prev {
                    prop_assert!(h > p, "wake-up heights not strictly increasing");
                }
                prev = Some(h);
            }

            let mut covered = alloc::vec![0usize; transfers.len()];
            for w in &wakeups {
                let h = u32::from(w.height());
                for &i in w.covers() {
                    covered[i] += 1;
                    let (a, gap) = xs[i];
                    let deadline = a + gap - 1;
                    if deadline < tip {
                        prop_assert_eq!(h, tip, "overdue transfer {} not woken immediately", i);
                    } else {
                        let ready = a.saturating_add(margin).min(deadline).max(tip);
                        prop_assert!(h >= ready, "wake-up {h} before transfer {}'s window", i);
                        prop_assert!(h <= deadline, "wake-up {h} after transfer {}'s deadline", i);
                    }
                }
            }
            prop_assert!(
                covered.iter().all(|&c| c == 1),
                "every transfer must be covered exactly once: {covered:?}"
            );
        }

        /// The wake-up count is MINIMAL: it equals the brute-force optimum over the clamped
        /// proving windows — plus, when overdue transfers force a mandatory immediate wake-up,
        /// exactly one for that wake-up, with every window containing `current_tip` covered by it
        /// for free.
        #[test]
        fn wakeup_count_is_minimal(
            seed in any::<u64>(),
            tip in 0u32..15_000,
            xs in prop::collection::vec((0u32..10_000, 2u32..2_000), 1..8),
        ) {
            let transfers: Vec<(usize, BlockHeight, BlockHeight)> = xs
                .iter()
                .enumerate()
                .map(|(i, &(a, gap))| (i, bh(a), bh(a + gap)))
                .collect();
            let wakeups =
                schedule_sync_wakeups(&WakeupParams::DEFAULT, bh(tip), &transfers, &mut rng(seed))
                    .expect("feasible");
            let margin = WakeupParams::DEFAULT.settle_margin().max(1);
            let mut overdue_exists = false;
            let mut windows: Vec<(u32, u32)> = Vec::new();
            for &(a, gap) in &xs {
                let deadline = a + gap - 1;
                if deadline < tip {
                    overdue_exists = true;
                } else {
                    windows.push((a.saturating_add(margin).min(deadline).max(tip), deadline));
                }
            }
            let expected = if overdue_exists {
                // The mandatory wake-up at `current_tip` covers every window containing it for
                // free; only the windows opening strictly after it need piercing.
                windows.retain(|&(ready, _)| ready > tip);
                1 + brute_force_min_wakeups(&windows)
            } else {
                brute_force_min_wakeups(&windows)
            };
            prop_assert_eq!(wakeups.len(), expected);
        }
    }

    /// Assert one golden wake-up schedule for a fixed input and seed, pinning the exact
    /// deterministic [`ChaCha8Rng`] jitter draws as a regression guard. Inputs are ZIP 318-shaped:
    /// anchors on the 144-block grid, broadcasts a few hundred blocks later.
    fn check_sync_wakeups_golden(
        seed: u64,
        transfers: &[(u32, u32, u32)],
        expected: &[(u32, &[u32])],
    ) {
        let input: Vec<(u32, BlockHeight, BlockHeight)> = transfers
            .iter()
            .map(|&(id, a, b)| (id, bh(a), bh(b)))
            .collect();
        let wakeups = schedule_sync_wakeups(&WakeupParams::DEFAULT, bh(0), &input, &mut rng(seed))
            .expect("feasible");
        let got: Vec<(u32, Vec<u32>)> = wakeups
            .iter()
            .map(|w| (u32::from(w.height()), w.covers().to_vec()))
            .collect();
        let exp: Vec<(u32, Vec<u32>)> = expected.iter().map(|&(h, c)| (h, c.to_vec())).collect();
        assert_eq!(got, exp, "schedule_sync_wakeups(seed={seed})");
    }

    /// Golden vectors for [`schedule_sync_wakeups`]: fixed inputs and seeds pinned to their exact
    /// wake-up schedules (heights are group-base + jitter; the jitter is the pinned draw).
    #[test]
    fn sync_wakeups_golden() {
        // One cohort pair sharing a wake-up plus a distant third transfer.
        check_sync_wakeups_golden(
            1,
            &[(0, 1440, 1700), (1, 1584, 1800), (2, 4320, 4600)],
            // heights: max(1440, 1584) + 10 + j1 = 1594 + 5 = 1599 (group of [0, 1]),
            // 4320 + 10 + j2 = 4330 + 1 = 4331 (transfer 2 alone) — bases are the group max
            // anchors + 10.
            &[(1599, &[0, 1]), (4331, &[2])],
        );
        // A longer mixed schedule under a different seed.
        check_sync_wakeups_golden(
            42,
            &[
                (0, 144, 400),
                (1, 288, 500),
                (2, 288, 600),
                (3, 1440, 1700),
                (4, 2880, 3200),
            ],
            // heights: max(144, 288, 288) + 10 + j0 = 298 + 8 = 306 (group of [0, 1, 2]),
            // 1440 + 10 + j1 = 1450 + 12 = 1462 (transfer 3 alone),
            // 2880 + 10 + j2 = 2890 + 5 = 2895 (transfer 4 alone) — bases are the group max
            // anchors + 10.
            &[(306, &[0, 1, 2]), (1462, &[3]), (2895, &[4])],
        );
    }

    // --- shuffle ------------------------------------------------------------------------------

    proptest! {
        /// A shuffle is a permutation: same multiset, every index present exactly once.
        #[test]
        fn shuffle_is_permutation(n in 0usize..64, seed in any::<u64>()) {
            let mut r = rng(seed);
            let perm = shuffle_indices(n, &mut r);
            prop_assert_eq!(perm.len(), n);
            let mut sorted = perm.clone();
            sorted.sort_unstable();
            prop_assert!(sorted.iter().copied().eq(0..n));
        }

        /// [`shuffle_in_place`] preserves the multiset of elements.
        #[test]
        fn shuffle_in_place_preserves_multiset(mut v in prop::collection::vec(0u32..1000, 0..64),
                                               seed in any::<u64>()) {
            let mut original = v.clone();
            original.sort_unstable();
            let mut r = rng(seed);
            shuffle_in_place(&mut v, &mut r);
            v.sort_unstable();
            prop_assert_eq!(v, original);
        }
    }

    #[test]
    fn gen_index_is_in_range() {
        let mut r = rng(7);
        for bound in 1usize..50 {
            for _ in 0..100 {
                assert!(gen_index(&mut r, bound) < bound);
            }
        }
    }

    /// Assert a golden [`shuffle_indices`] permutation for a fixed `(n, seed)`, pinning the exact
    /// deterministic [`ChaCha8Rng`] shuffle, plus the invariant that the result is a permutation of
    /// `0..n` (each index present exactly once).
    fn check_shuffle_indices_golden(n: usize, seed: u64, expected: &[usize]) {
        let perm = shuffle_indices(n, &mut rng(seed));
        assert_eq!(perm, expected, "shuffle_indices({n}, seed={seed})");
        assert_eq!(perm.len(), n);
        let mut sorted = perm.clone();
        sorted.sort_unstable();
        assert!(
            sorted.iter().copied().eq(0..n),
            "not a permutation of 0..{n}"
        );
    }

    /// Golden vectors for [`shuffle_indices`]: fixed `(n, seed)` pairs pinned to the exact
    /// Fisher-Yates permutation they produce (a regression guard on the shuffle), each verified to be
    /// a genuine permutation of `0..n`.
    #[test]
    fn shuffle_indices_golden() {
        let exp_empty: [usize; 0] = []; // empty stays empty
        let exp_singleton = [0]; // singleton is the identity
        let exp_n5_seed1 = [4, 3, 1, 0, 2];
        let exp_n8_seed42 = [4, 7, 0, 1, 3, 2, 6, 5];
        let exp_n10_seed7 = [4, 6, 2, 0, 8, 3, 7, 5, 9, 1];
        check_shuffle_indices_golden(0, 1, &exp_empty);
        check_shuffle_indices_golden(1, 1, &exp_singleton);
        check_shuffle_indices_golden(5, 1, &exp_n5_seed1);
        check_shuffle_indices_golden(8, 42, &exp_n8_seed42);
        check_shuffle_indices_golden(10, 7, &exp_n10_seed7);
    }

    /// Golden vectors for [`shuffle_in_place`]: a fixed concrete slice shuffled under a fixed seed,
    /// pinned to its exact reordering, and verified to preserve the original multiset of elements.
    #[test]
    fn shuffle_in_place_golden() {
        fn check(seed: u64, expected: &[u32]) {
            let mut v = alloc::vec![10u32, 20, 30, 40, 50, 60];
            let mut original = v.clone();
            original.sort_unstable();
            shuffle_in_place(&mut v, &mut rng(seed));
            assert_eq!(v, expected, "shuffle_in_place(seed={seed})");
            let mut sorted = v.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, original, "multiset changed by shuffle");
        }
        let exp_seed1 = [20, 40, 50, 60, 10, 30];
        let exp_seed42 = [30, 10, 40, 20, 60, 50];
        check(1, &exp_seed1);
        check(42, &exp_seed42);
    }

    // --- schedule_broadcast_heights -----------------------------------------------------------

    proptest! {
        /// Broadcast heights are non-decreasing and start at or above the commit height
        /// (CUMULATIVE MUST).
        #[test]
        fn broadcast_heights_monotone(commit in 0u32..5_000_000,
                                      n in 0usize..40,
                                      seed in any::<u64>()) {
            let mut r = rng(seed);
            let hs = schedule_broadcast_heights(&P, bh(commit), n, &mut r);
            prop_assert_eq!(hs.len(), n);
            let mut prev = bh(commit);
            for h in hs {
                prop_assert!(h >= prev);
                prev = h;
            }
        }
    }

    /// Assert one golden schedule vector: the exact cumulative broadcast heights for a fixed
    /// `(commit, n, seed)`, plus the structural invariants they must satisfy. The heights are captured
    /// from the deterministic [`ChaCha8Rng`], so they pin the exact delay draws as a regression guard;
    /// the invariant checks keep each vector auditable by eye, since each per-step GAP is the drawn
    /// inter-arrival delay and must be a valid `[0, TRANSFER_DELAY_CAP]` value.
    fn check_schedule_golden(commit: u32, n: usize, seed: u64, expected: &[u32]) {
        let hs: Vec<u32> = schedule_broadcast_heights(&P, bh(commit), n, &mut rng(seed))
            .into_iter()
            .map(u32::from)
            .collect();
        assert_eq!(hs, expected, "schedule({commit}, {n}, seed={seed})");
        assert_eq!(hs.len(), n);
        let cap = TRANSFER_DELAY_CAP.get();
        let mut prev = commit;
        for &h in &hs {
            assert!(
                h >= prev,
                "heights must be non-decreasing (commit {commit})"
            );
            let gap = h - prev;
            assert!(gap <= cap, "delay {gap} exceeds the cap {cap}");
            prev = h;
        }
    }

    /// Golden vectors for the cumulative broadcast schedule: fixed `(commit, n, seed)` triples pinned
    /// to their exact height sequences (a regression guard on the delay sampling), with the per-step
    /// gaps noted so the drawn delays are visible. The ZIP 318 transfer delay has mean 66 blocks
    /// and cap 576.
    #[test]
    fn schedule_broadcast_heights_golden() {
        // n = 0 schedules nothing, whatever the seed.
        check_schedule_golden(1_000_000, 0, 1, &[]);
        // gaps: 34, 6, 60, 16, 22
        check_schedule_golden(
            1_000_000,
            5,
            1,
            &[1_000_034, 1_000_040, 1_000_100, 1_000_116, 1_000_138],
        );
        // gaps: 76, 198, 37, 65, 22, 11, 24, 108
        check_schedule_golden(
            2_000_000,
            8,
            42,
            &[
                2_000_076, 2_000_274, 2_000_311, 2_000_376, 2_000_398, 2_000_409, 2_000_433,
                2_000_541,
            ],
        );
        // gaps: 11, 12, 80
        check_schedule_golden(500_000, 3, 7, &[500_011, 500_023, 500_103]);
        // commit height 0; gaps: 5, 3, 103, 27, 6, 13
        check_schedule_golden(0, 6, 12_345, &[5, 8, 111, 138, 144, 157]);
    }

    proptest! {
        /// Preparation delays respect their own (tighter) bounds, and the per-layer schedule is
        /// non-decreasing from its start.
        #[test]
        fn prep_schedule_bounds_and_monotone(start in 0u32..5_000_000,
                                            n in 0usize..40,
                                            seed in any::<u64>()) {
            let mut r = rng(seed);
            let hs = schedule_prep_broadcast_heights(&P, bh(start), n, &mut r);
            prop_assert_eq!(hs.len(), n);
            let mut prev = bh(start);
            for h in hs {
                prop_assert!(h >= prev);
                prop_assert!(u32::from(h) - u32::from(prev) <= PREP_DELAY_CAP.get());
                prev = h;
            }
        }
    }

    /// Golden vectors for the ZIP 318 preparation delay: the exact deterministic draws for fixed
    /// seeds, pinning the tighter preparation spacing as a regression guard, with every delay within
    /// its cap. Derivable from the transfer goldens in [`draw_delay_golden`] by the scale law: the
    /// same unit draws scaled by the mean ratio `16 / 66` (for example seed 1's 34, 6, 60, ...
    /// become 8, 1, 15, ...).
    #[test]
    fn draw_prep_delay_golden() {
        fn check(seed: u64, expected: &[u32]) {
            let mut r = rng(seed);
            let got: Vec<u32> = (0..expected.len())
                .map(|_| P.preparation_delay().draw(&mut r))
                .collect();
            assert_eq!(got, expected, "preparation_delay().draw(seed={seed})");
            for &d in &got {
                assert!(
                    d <= PREP_DELAY_CAP.get(),
                    "delay {d} exceeds the preparation cap"
                );
            }
        }
        let exp_seed1 = [8, 1, 15, 4, 5, 20, 10, 3];
        let exp_seed42 = [18, 48, 9, 16, 5, 3, 6, 26];
        check(1, &exp_seed1);
        check(42, &exp_seed42);
    }

    // --- expiry_height ------------------------------------------------------------------------

    proptest! {
        /// The expiry height lies in the rolling window (current, current + EXPIRY_WINDOW] and its
        /// anchoring point (expiry - EXPIRY_WINDOW) is a multiple of EXPIRY_MODULUS (EXPIRY MUST).
        #[test]
        fn expiry_in_rolling_window(current in 0u32..(u32::MAX - EXPIRY_WINDOW)) {
            let e = u32::from(expiry_height(bh(current)));
            prop_assert!(e > current, "expiry {e} must exceed current {current}");
            prop_assert!(e <= current + EXPIRY_WINDOW);
            // The anchor is a multiple of EXPIRY_MODULUS.
            prop_assert_eq!((e - EXPIRY_WINDOW) % EXPIRY_MODULUS, 0);
            // At least one full modulus of remaining validity.
            prop_assert!(e - current > EXPIRY_MODULUS);
        }
    }

    #[test]
    fn expiry_examples() {
        // At an exact modulus boundary the window is the full 2 * EXPIRY_MODULUS.
        assert_eq!(expiry_height(bh(0)), bh(EXPIRY_WINDOW));
        assert_eq!(
            expiry_height(bh(EXPIRY_MODULUS)),
            bh(EXPIRY_MODULUS + EXPIRY_WINDOW)
        );
        // Just before the next modulus, validity is just over one modulus.
        let just_before = EXPIRY_MODULUS - 1;
        assert_eq!(expiry_height(bh(just_before)), bh(EXPIRY_WINDOW));
    }

    // --- draw_anchor_age ----------------------------------------------------------------------

    proptest! {
        /// The geometric age draw is always >= 1 (age 0, the most recent boundary, is never used).
        #[test]
        fn anchor_age_at_least_one(seed in any::<u64>()) {
            let mut r = rng(seed);
            for _ in 0..500 {
                prop_assert!(draw_anchor_age(&mut r) >= 1);
            }
        }
    }

    #[test]
    fn anchor_age_modal_is_one() {
        // Geometric(1/2): about half the draws are age 1.
        let mut r = rng(99);
        let n = 10_000;
        let ones = (0..n).filter(|_| draw_anchor_age(&mut r) == 1).count();
        let frac = ones as f64 / n as f64;
        assert!((0.45..0.55).contains(&frac), "P(age=1) empirical {frac}");
    }

    // --- draw_anchor_boundary -----------------------------------------------------------------

    /// A valid arrangement of the anchor-draw inputs whose candidate set is guaranteed non-empty:
    /// picks an activation height, a chain tip whose most recent boundary is at least a few
    /// boundaries above the activation, and a funding-creation height at or below the highest
    /// candidate. The tip is offset off the boundary by an arbitrary amount, exercising the
    /// internal boundary derivation.
    /// The interval is drawn too, so the candidate-set invariants are checked against whatever grid
    /// the migration is configured with rather than only the ZIP 318 one.
    fn arb_anchor_inputs() -> impl Strategy<Value = (AnchorBucketInterval, u32, u32, u32)> {
        // nu63_activation in a modest range; span in boundaries above it (>= 2 so a candidate exists).
        (0u32..1000u32, 2u32..40u32, 1u32..500u32, 0u32..1000u32).prop_flat_map(
            |(act, span_boundaries, blocks, tip_offset)| {
                let i = interval(blocks);
                let most_recent =
                    (boundary_at_or_below_u32(&i, act) + span_boundaries * blocks).max(blocks);
                let tip = most_recent + (tip_offset % blocks);
                // funding creation anywhere from activation up to the highest candidate boundary.
                let highest = most_recent - blocks;
                (Just(i), Just(act), Just(tip), act..=highest.max(act))
            },
        )
    }

    proptest! {
        /// Every chosen anchor boundary is in the candidate set: a multiple of the modulus, strictly
        /// below the most recent boundary derived from the chain tip, strictly above
        /// nu63_activation, and at/after the funding creation height (ANCHOR-SELECTION +
        /// ANCHOR-AGE-DRAW MUST).
        #[test]
        fn anchor_in_candidate_set((i, act, tip, funding) in arb_anchor_inputs(),
                                   seed in any::<u64>()) {
            let mut r = rng(seed);
            let blocks = i.block_count().get();
            let most_recent = boundary_at_or_below_u32(&i, tip);
            let chosen = draw_anchor_boundary(i, bh(act), bh(funding), bh(tip), &mut r);
            prop_assert!(chosen.is_some());
            let b = u32::from(chosen.unwrap());
            prop_assert!(i.is_boundary(bh(b)));
            prop_assert!(b < most_recent, "boundary {b} must be below most_recent {most_recent}");
            prop_assert!(b > act, "boundary {b} must be strictly above activation {act}");
            prop_assert!(b >= funding, "boundary {b} must be at/after funding {funding}");
            // Age is within the cap: (most_recent - b) / interval in [1, ANCHOR_AGE_CAP].
            let age = (most_recent - b) / blocks;
            prop_assert!((1..=ANCHOR_AGE_CAP).contains(&age), "age {age} out of [1, cap]");
        }

        /// The most recent boundary is derived from the chain tip internally: any tip within a
        /// boundary interval draws exactly the same anchors as the boundary itself under the same
        /// seed.
        #[test]
        fn anchor_draw_derives_boundary_from_tip(blocks in 1u32..500u32,
                                                 tip_offset in 0u32..500u32,
                                                 seed in any::<u64>()) {
            let i = interval(blocks);
            let (act, funding) = (blocks, 2 * blocks);
            let boundary_tip = 20 * blocks;
            let offset = tip_offset % blocks;
            let mut r_offset = rng(seed);
            let mut r_boundary = rng(seed);
            for _ in 0..16 {
                prop_assert_eq!(
                    draw_anchor_boundary(
                        i, bh(act), bh(funding), bh(boundary_tip + offset), &mut r_offset,
                    ),
                    draw_anchor_boundary(i, bh(act), bh(funding), bh(boundary_tip), &mut r_boundary)
                );
            }
        }
    }

    #[test]
    fn anchor_empty_candidate_set_is_none() {
        for blocks in [AnchorBucketInterval::ZIP_318.block_count().get(), 12] {
            let i = interval(blocks);
            let mut r = rng(1);
            // Chain tip below the second boundary: no candidate strictly below the derived boundary
            // that is also above activation.
            assert_eq!(draw_anchor_boundary(i, bh(0), bh(0), bh(0), &mut r), None);
            assert_eq!(
                draw_anchor_boundary(i, bh(0), bh(0), bh(blocks), &mut r),
                None
            );
            // A non-boundary tip derives the same (first) boundary, so the set is still empty.
            assert_eq!(
                draw_anchor_boundary(i, bh(0), bh(0), bh(2 * blocks - 1), &mut r),
                None
            );
        }
    }

    proptest! {
        /// [`earliest_broadcast_height`] is the exact viability threshold: a tip at that height
        /// always yields an anchor, and a tip one block earlier never does.
        #[test]
        fn earliest_broadcast_height_is_the_viability_threshold(act in 0u32..1_000_000,
                                                               funding_offset in 0u32..2_000,
                                                               blocks in 1u32..500u32,
                                                               seed in any::<u64>()) {
            let i = interval(blocks);
            let funding = act + funding_offset;
            let earliest = earliest_broadcast_height(i, bh(act), bh(funding));
            let mut r = rng(seed);
            prop_assert!(
                draw_anchor_boundary(i, bh(act), bh(funding), earliest, &mut r).is_some(),
                "a tip at the earliest broadcast height must have a candidate boundary"
            );
            let mut r = rng(seed);
            prop_assert!(
                draw_anchor_boundary(i, bh(act), bh(funding), earliest - 1, &mut r).is_none(),
                "a tip below the earliest broadcast height must not"
            );
        }
    }

    #[test]
    fn anchor_funding_after_most_recent_is_none() {
        for blocks in [AnchorBucketInterval::ZIP_318.block_count().get(), 12] {
            let i = interval(blocks);
            let mut r = rng(2);
            // Funding note created after the tip's most recent boundary: nothing at/after it can be
            // a candidate (candidates are all <= most_recent - interval).
            let tip = 10 * blocks;
            let funding = tip + blocks;
            assert_eq!(
                draw_anchor_boundary(i, bh(0), bh(funding), bh(tip), &mut r),
                None
            );
        }
    }

    /// Assert a golden sequence of [`draw_anchor_boundary`] draws for a fixed candidate set and seed,
    /// pinning the exact deterministic recency-weighted picks, plus the documented invariants for
    /// each: a multiple of the modulus, strictly above `act`, strictly below the most recent
    /// boundary derived from `chain_tip`, at/after `funding`, and with an age in
    /// `[1, ANCHOR_AGE_CAP]`.
    fn check_anchor_golden(act: u32, funding: u32, chain_tip: u32, seed: u64, expected: &[u32]) {
        let i = P.anchor_bucket_interval();
        let most_recent = boundary_at_or_below_u32(&i, chain_tip);
        let mut r = rng(seed);
        let got: Vec<u32> = (0..expected.len())
            .map(|_| {
                u32::from(
                    draw_anchor_boundary(i, bh(act), bh(funding), bh(chain_tip), &mut r).unwrap(),
                )
            })
            .collect();
        assert_eq!(got, expected, "draw_anchor_boundary(seed={seed})");
        for &b in &got {
            assert!(
                i.is_boundary(bh(b)),
                "boundary {b} not a multiple of the interval"
            );
            assert!(
                b > act,
                "boundary {b} must be strictly above activation {act}"
            );
            assert!(
                b < most_recent,
                "boundary {b} must be below most_recent {most_recent}"
            );
            assert!(
                b >= funding,
                "boundary {b} must be at/after funding {funding}"
            );
            let age = (most_recent - b) / i.block_count().get();
            assert!(
                (1..=ANCHOR_AGE_CAP).contains(&age),
                "age {age} out of [1, cap]"
            );
        }
    }

    /// Golden vectors for [`draw_anchor_boundary`]. The candidate set spans boundaries `288..=2736`
    /// (`act = 144`, `funding = 288`, chain tip `2880`), of which the `ANCHOR_AGE_CAP` of 4
    /// boundaries admits only `2304..=2736`; each pinned sequence is the exact recency-weighted
    /// draw, and every entry is checked against the candidate-set invariants. The modal pick is the
    /// highest candidate 2736 (age 1), as the `Geometric(1/2)` age draw expects. A tip in the
    /// middle of the same boundary interval derives the same boundary and must reproduce the same
    /// vectors.
    #[test]
    fn draw_anchor_boundary_golden() {
        let m = AnchorBucketInterval::ZIP_318.block_count().get();
        let (act, funding, tip) = (m, 2 * m, 20 * m);
        let exp_seed1 = [2736, 2736, 2736, 2592, 2736, 2304];
        let exp_seed42 = [2736, 2304, 2448, 2592, 2592, 2448];
        let exp_seed7 = [2736, 2592, 2736, 2736, 2304, 2592];
        let exp_seed100 = [2592, 2736, 2736, 2592, 2736, 2736];
        check_anchor_golden(act, funding, tip, 1, &exp_seed1);
        check_anchor_golden(act, funding, tip, 42, &exp_seed42);
        check_anchor_golden(act, funding, tip, 7, &exp_seed7);
        check_anchor_golden(act, funding, tip, 100, &exp_seed100);
        // A mid-interval tip (not itself a boundary) must yield identical draws.
        check_anchor_golden(act, funding, tip + 100, 1, &exp_seed1);
        check_anchor_golden(act, funding, tip + m - 1, 42, &exp_seed42);
    }

    // --- redraw_anchor_boundary ---------------------------------------------------------------

    proptest! {
        /// A replacement boundary, when one exists, is on the grid, at or above the boundary it
        /// replaces, and in-distribution against the NEW broadcast height: within
        /// [`ANCHOR_AGE_CAP`] buckets strictly below its most recent grid boundary. `None` arises
        /// exactly when no candidate at or above the prior boundary lies strictly below that
        /// most recent boundary.
        #[test]
        fn redraw_anchor_boundary_props(
            seed in any::<u64>(),
            prior_bucket in 0u32..100,
            broadcast in 0u32..5_000_000,
            blocks in 2u32..10_000,
        ) {
            let i = interval(blocks);
            let prior = prior_bucket.saturating_mul(blocks);
            let chosen = redraw_anchor_boundary(i, bh(prior), bh(broadcast), &mut rng(seed));
            let most_recent = broadcast - (broadcast % blocks);
            match chosen {
                Some(b) => {
                    let b = u32::from(b);
                    prop_assert!(i.is_boundary(bh(b)));
                    prop_assert!(b >= prior, "replacement {b} regressed below the prior {prior}");
                    prop_assert!(b < most_recent, "age >= 1: strictly below {most_recent}");
                    prop_assert!(
                        b + ANCHOR_AGE_CAP * blocks >= most_recent,
                        "replacement {b} is older than the age cap allows"
                    );
                }
                None => prop_assert!(
                    most_recent < blocks || prior > most_recent - blocks,
                    "a non-empty candidate window must yield a draw"
                ),
            }
        }
    }

    /// The endpoints of the replacement window: a prior boundary above the window keeps its
    /// (still-provable) anchor by yielding `None`, and a prior boundary AT the window's single
    /// candidate returns that candidate deterministically.
    #[test]
    fn redraw_anchor_boundary_window_endpoints() {
        // Broadcast 1_900: most recent boundary 1_872, highest candidate 1_728.
        assert_eq!(
            redraw_anchor_boundary(
                AnchorBucketInterval::ZIP_318,
                bh(1_872),
                bh(1_900),
                &mut rng(1)
            ),
            None,
            "a prior at the most recent boundary has no strictly-older candidate to move to"
        );
        assert_eq!(
            redraw_anchor_boundary(
                AnchorBucketInterval::ZIP_318,
                bh(1_728),
                bh(1_900),
                &mut rng(1)
            ),
            Some(bh(1_728)),
            "a single-candidate window is deterministic"
        );
    }

    /// The two axes of [`SchedulingParams`] are independent: changing only the anchor bucket
    /// interval moves the boundary grid without perturbing the drawn delays, so a test network can
    /// shorten the grid alone. (Shortening the delays as well is what compresses the schedule; see
    /// [`delay_scales_with_configured_mean`].)
    #[test]
    fn interval_moves_the_grid_without_touching_the_delays() {
        let short = params_with_interval(12);

        // Identical delay draws under the same seed: only the grid differs.
        assert_eq!(
            schedule_broadcast_heights(&short, bh(2_000_000), 8, &mut rng(5)),
            schedule_broadcast_heights(&P, bh(2_000_000), 8, &mut rng(5)),
        );

        // The anchor floor and every drawn anchor sit on the SHORT grid, not the ZIP 318 one.
        let (act, funding) = (bh(1_000), bh(1_100));
        let earliest = earliest_broadcast_height(short.anchor_bucket_interval(), act, funding);
        assert!(short.anchor_bucket_interval().is_boundary(earliest));
        assert_eq!(u32::from(earliest), 1_116); // 1_104 (first boundary >= funding) + 12
        assert!(
            earliest < earliest_broadcast_height(P.anchor_bucket_interval(), act, funding),
            "a shorter interval must reach anchor viability sooner"
        );

        let mut r = rng(5);
        for _ in 0..64 {
            let b = draw_anchor_boundary(
                short.anchor_bucket_interval(),
                act,
                funding,
                bh(5_000),
                &mut r,
            )
            .expect("the candidate set is non-empty");
            assert!(short.anchor_bucket_interval().is_boundary(b));
            assert!(b >= funding && b > act);
        }
    }

    #[test]
    fn anchor_tiny_range_single_candidate() {
        for blocks in [AnchorBucketInterval::ZIP_318.block_count().get(), 12] {
            let i = interval(blocks);
            // Exactly one candidate: the boundary below the tip's, and it satisfies all bounds.
            let mut r = rng(3);
            let act = blocks; // first candidate above activation is 2*interval
            let tip = 3 * blocks; // highest candidate is 2*interval
            let funding = 2 * blocks;
            // Only 2*interval qualifies.
            for _ in 0..50 {
                assert_eq!(
                    draw_anchor_boundary(i, bh(act), bh(funding), bh(tip), &mut r),
                    Some(bh(2 * blocks))
                );
            }
        }
    }

    // --- schedule wiring ----------------------------------------------------------------------

    /// Assert one golden [`schedule`] result: the exact broadcast/expiry height pairs for a fixed
    /// `(commit, n, seed)`, plus the wiring invariants. The broadcast heights are cross-checked to
    /// equal [`schedule_broadcast_heights`] on the same seed (identical RNG consumption), and each
    /// expiry is checked to equal [`expiry_height`] of its broadcast height.
    fn check_schedule_golden_pairs(
        commit: u32,
        n: usize,
        seed: u64,
        expected_broadcast: &[u32],
        expected_expiry: &[u32],
    ) {
        let schedules = schedule(&P, bh(commit), n, &mut rng(seed));
        let broadcast: Vec<u32> = schedules
            .iter()
            .map(|s| u32::from(s.broadcast_height()))
            .collect();
        let expiry: Vec<u32> = schedules
            .iter()
            .map(|s| u32::from(s.expiry_height()))
            .collect();
        assert_eq!(
            broadcast, expected_broadcast,
            "schedule({commit}, {n}, seed={seed}) broadcast"
        );
        assert_eq!(
            expiry, expected_expiry,
            "schedule({commit}, {n}, seed={seed}) expiry"
        );
        // Broadcast heights equal the cumulative-delay schedule for the same seed.
        assert_eq!(
            broadcast,
            schedule_broadcast_heights(&P, bh(commit), n, &mut rng(seed))
                .into_iter()
                .map(u32::from)
                .collect::<Vec<u32>>(),
            "broadcast heights must match the cumulative rule"
        );
        // Each expiry is the canonical rolling window of its broadcast height, and broadcast >= commit.
        for (&b, &e) in broadcast.iter().zip(&expiry) {
            assert!(b >= commit, "broadcast {b} below commit {commit}");
            assert_eq!(
                e,
                u32::from(expiry_height(bh(b))),
                "expiry {e} != expiry_height({b})"
            );
        }
    }

    /// Golden vectors for [`schedule`]: the exact `(broadcast, expiry)` height pairs for fixed
    /// `(commit, n, seed)` triples. Broadcast heights reuse the cumulative delays pinned in
    /// [`schedule_broadcast_heights_golden`]; every expiry equals `expiry_height(broadcast)`, and all
    /// broadcasts here fall inside one `EXPIRY_MODULUS` period so they share a single expiry height.
    #[test]
    fn schedule_golden() {
        // n = 0 schedules nothing.
        let exp_broadcast_empty: [u32; 0] = [];
        let exp_expiry_empty: [u32; 0] = [];
        check_schedule_golden_pairs(1_000_000, 0, 1, &exp_broadcast_empty, &exp_expiry_empty);

        // commit = 1_000_000, n = 5, seed = 1: broadcast heights and their shared expiry.
        let exp_broadcast_c1m_seed1 = [1_000_034, 1_000_040, 1_000_100, 1_000_116, 1_000_138];
        let exp_expiry_c1m_seed1 = [1_036_800; 5];
        check_schedule_golden_pairs(
            1_000_000,
            5,
            1,
            &exp_broadcast_c1m_seed1,
            &exp_expiry_c1m_seed1,
        );

        // commit = 0, n = 6, seed = 12_345.
        let exp_broadcast_c0_seed12345 = [5, 8, 111, 138, 144, 157];
        let exp_expiry_c0_seed12345 = [69_120; 6];
        check_schedule_golden_pairs(
            0,
            6,
            12_345,
            &exp_broadcast_c0_seed12345,
            &exp_expiry_c0_seed12345,
        );
    }

    proptest! {
        /// [`schedule`] pairs each broadcast height with its canonical expiry, the broadcast heights
        /// follow the cumulative rule (equal to [`schedule_broadcast_heights`] on the same seed and
        /// non-decreasing from the commit height), and each expiry is [`expiry_height`] of its
        /// broadcast height.
        #[test]
        fn schedule_pairs_broadcast_and_expiry(commit in 0u32..1_000_000,
                                               n in 0usize..24,
                                               seed in any::<u64>()) {
            let mut r = rng(seed);
            let schedules = schedule(&P, bh(commit), n, &mut r);
            prop_assert_eq!(schedules.len(), n);
            // Broadcast heights follow the cumulative delay rule (same RNG => same heights).
            let broadcast: Vec<BlockHeight> =
                schedules.iter().map(|s| s.broadcast_height()).collect();
            prop_assert_eq!(
                &broadcast,
                &schedule_broadcast_heights(&P, bh(commit), n, &mut rng(seed))
            );
            let mut prev = bh(commit);
            for s in &schedules {
                prop_assert!(s.broadcast_height() >= prev, "broadcast heights must be non-decreasing");
                prev = s.broadcast_height();
                prop_assert_eq!(s.expiry_height(), expiry_height(s.broadcast_height()));
            }
        }
    }
}
