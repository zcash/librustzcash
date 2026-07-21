//! Transfer scheduling and anchor selection: WHEN each migration transfer is broadcast, WHICH
//! Orchard anchor it proves against, and WHEN it expires.
//!
//! This module is pool-agnostic and pure arithmetic plus RNG draws (no cryptography, no note tree,
//! no I/O); it works only in block heights and part indices. All randomness comes from a caller-
//! supplied `rng` (a CSPRNG in production; the tests pass a seeded `rand_chacha::ChaCha8Rng`).
//! Every function is deterministic given its `rng`.
//!
//! # The problem
//!
//! The note split ([`crate::note_splitting`]) decides the crossing VALUES (quantized denominations)
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
//! 2. DELAYS ([`draw_delay`]): the gap between successive transfers is an exponential inter-arrival
//!    time (mean [`MEAN_DELAY`], capped at [`MAX_DELAY`]), so broadcasts look like an unremarkable
//!    Poisson process rather than a burst.
//! 3. CUMULATIVE ([`schedule_broadcast_heights`]): each transfer's scheduled height is the running
//!    sum of independent delays from the commit height.
//! 4. ANCHOR ([`draw_anchor_boundary`]): at PROVING time each transfer proves against the Orchard
//!    tree state at a BOUNDARY block (height congruent to 0 mod [`BOUNDARY_MODULUS`]), chosen from a
//!    recency-weighted geometric draw over the candidate boundaries, so transfers share a small set
//!    of common anchors (cohorts) instead of each pinning the latest state.
//! 5. EXPIRY ([`expiry_height`]): a canonical rolling window gives every transfer 1 to 2 months of
//!    validity as a pure function of the current height, so the expiry height itself carries no
//!    per-wallet information.
//!
//! # Cohorts
//!
//! Transfers (across all wallets) that prove against the same boundary anchor form a COHORT: to an
//! observer they are indistinguishable in their anchor, which is the anonymity set the anchor draw
//! builds. In this pure module a cohort is just "transfers that chose the same boundary height";
//! [`group_by_boundary`] groups a single wallet's own transfers that way, and [`K_MAX`] bounds how
//! many of the wallet's OWN parts may land on one boundary (a SHOULD, still an open ZIP issue).
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
//!   re-spread). That requires the persisted schedule and wall-clock state the engine owns.
//!
//! This module supplies the heights and anchors those policies act on; it does not enact them.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;

use rand_core::RngCore;
use zcash_protocol::consensus::BlockHeight;

/// Mean of the exponential inter-arrival delay between successive transfers, in blocks. Also the
/// [`BOUNDARY_MODULUS`]. 144 blocks is about three hours at the Zcash ~75-second target spacing.
/// The exponential rate is `lambda = 1 / MEAN_DELAY`. See [`draw_delay`].
pub const MEAN_DELAY: u32 = 144;

/// Upper bound (inclusive) on a single inter-arrival delay, in blocks. A draw exceeding this is
/// discarded and redrawn (truncating the exponential's heavy tail), so no transfer is starved for
/// an unbounded time. 576 blocks is `4 * MEAN_DELAY`, about twelve hours. See [`draw_delay`].
pub const MAX_DELAY: u32 = 576;

/// Block-height modulus defining the BOUNDARY blocks: a height `h` is a boundary iff
/// `h % BOUNDARY_MODULUS == 0`. Boundaries are the only tree states a transfer may anchor to, so
/// many transfers share a small, common set of anchors (cohorts) rather than each pinning a unique
/// recent block. Equal to [`MEAN_DELAY`] (~three hours). See [`draw_anchor_boundary`].
pub const BOUNDARY_MODULUS: u32 = MEAN_DELAY;

/// Maximum anchor AGE, in boundaries, that the recency-weighted draw will accept. Age `a` counts
/// boundaries strictly before the most recent boundary observed at proving time; a draw exceeding
/// this cap (a very old anchor) is discarded and redrawn. Bounds how stale a proof's anchor can be
/// (16 boundaries is about two days). See [`draw_anchor_boundary`].
pub const ANCHOR_AGE_CAP: u32 = 16;

/// Block-height modulus of the canonical rolling EXPIRY window, in blocks. 34560 blocks is about 30
/// days at the target block spacing. The expiry height is anchored to the most recent multiple of
/// this modulus plus [`EXPIRY_WINDOW`]. See [`expiry_height`].
pub const EXPIRY_MODULUS: u32 = 34_560;

/// Width of the rolling expiry window added past the anchoring modulus, in blocks. Two expiry
/// moduli (`2 * EXPIRY_MODULUS`, about 60 days) so that every transfer, whenever in the current
/// modulus period it is scheduled, keeps between one and two [`EXPIRY_MODULUS`] periods of validity.
/// See [`expiry_height`].
pub const EXPIRY_WINDOW: u32 = 2 * EXPIRY_MODULUS;

/// Provisional cap on how many of a single wallet's OWN transfers may share one boundary anchor.
/// When a fresh anchor draw would place more than `K_MAX` of the wallet's parts on the same
/// boundary, the age is redrawn (see [`draw_anchor_boundary_bounded`]).
///
/// This is a SHOULD, not a MUST, and an OPEN ISSUE in ZIP 318 (not yet ratified): capping a
/// wallet's own multiplicity on a boundary trades a little anonymity-set sharing for less
/// self-linkage of one wallet's transfers. The value 2 is provisional and may change when the ZIP
/// settles.
pub const K_MAX: usize = 2;

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

/// The most recent BOUNDARY block at or below `height`: the largest multiple of [`BOUNDARY_MODULUS`]
/// that is `<= height`. Equivalently `height - (height % BOUNDARY_MODULUS)`.
pub fn most_recent_boundary(height: BlockHeight) -> BlockHeight {
    BlockHeight::from_u32(most_recent_boundary_u32(u32::from(height)))
}

/// [`most_recent_boundary`] on the raw `u32` representation, for internal boundary arithmetic.
fn most_recent_boundary_u32(height: u32) -> u32 {
    height - (height % BOUNDARY_MODULUS)
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

/// Draw one inter-arrival delay in blocks from the truncated exponential distribution: mean
/// [`MEAN_DELAY`], discard-and-redraw above [`MAX_DELAY`] (ZIP 318 "Transfer scheduling" MUST).
///
/// Samples by inverse-CDF, `delay = round(-MEAN_DELAY * ln(u))` for `u` uniform in `(0, 1]` (so the
/// exponential rate is `1 / MEAN_DELAY`), redrawing whenever the rounded delay exceeds
/// [`MAX_DELAY`]. The return is always in `[0, MAX_DELAY]`.
pub fn draw_delay<R: RngCore>(rng: &mut R) -> u32 {
    loop {
        let u = draw_unit_left_open(rng);
        // ln(u) <= 0 for u in (0, 1], so -MEAN_DELAY * ln(u) >= 0.
        let delay = round_nonneg_to_u32(-(MEAN_DELAY as f64) * libm::log(u));
        if delay <= MAX_DELAY {
            return delay;
        }
    }
}

/// Produce a uniformly random permutation of `0..n` using an in-place Fisher-Yates shuffle driven by
/// `rng` (ZIP 318 "Transfer scheduling" SHUFFLE MUST). The caller applies the permutation to its
/// quantized parts so the broadcast ORDER of denominations is independent of the balance.
///
/// Returns the identity for `n == 0` or `n == 1`.
pub fn shuffle_indices<R: RngCore>(n: usize, rng: &mut R) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..n).collect();
    shuffle_in_place(&mut indices, rng);
    indices
}

/// In-place uniform Fisher-Yates shuffle of `slice` using `rng` (ZIP 318 SHUFFLE MUST). Iterates
/// from the top, swapping each element with a uniformly chosen one at or below it, so every
/// permutation is equally likely. Leaves the multiset of elements unchanged.
pub fn shuffle_in_place<T, R: RngCore>(slice: &mut [T], rng: &mut R) {
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

/// Compute the per-part scheduled broadcast heights: starting at `commit_height`, advance a running
/// height by an independently drawn [`draw_delay`] for each of the `n_parts` transfers (ZIP 318
/// CUMULATIVE MUST). The returned vector has length `n_parts`, is non-decreasing, and every entry is
/// `>= commit_height`. Heights saturate at `u32::MAX` rather than overflowing.
pub fn schedule_broadcast_heights<R: RngCore>(
    commit_height: BlockHeight,
    n_parts: usize,
    rng: &mut R,
) -> Vec<BlockHeight> {
    let mut heights = Vec::with_capacity(n_parts);
    let mut height = commit_height;
    for _ in 0..n_parts {
        // `BlockHeight`'s delta addition saturates at `u32::MAX`.
        height = height + draw_delay(rng);
        heights.push(height);
    }
    heights
}

/// The canonical rolling EXPIRY height for a transfer at `current_height` (ZIP 318 EXPIRY MUST):
/// the most recent multiple of [`EXPIRY_MODULUS`] at or below `current_height`, plus
/// [`EXPIRY_WINDOW`] (`2 * EXPIRY_MODULUS`).
///
/// This is a pure function of the height (it reveals nothing per-wallet) and guarantees between one
/// and two [`EXPIRY_MODULUS`] periods (about 1 to 2 months) of remaining validity: the result is
/// always strictly greater than `current_height` and at most `EXPIRY_WINDOW` above it. Saturates at
/// `u32::MAX`.
pub fn expiry_height(current_height: BlockHeight) -> BlockHeight {
    let h = u32::from(current_height);
    // `BlockHeight`'s delta addition saturates at `u32::MAX`.
    BlockHeight::from_u32(h - (h % EXPIRY_MODULUS)) + EXPIRY_WINDOW
}

/// Assemble a [`Schedule`] for each part: draw the cumulative broadcast heights from `commit_height`
/// (see [`schedule_broadcast_heights`]) and pair each with its canonical [`expiry_height`]. Returns
/// one [`Schedule`] per part, in the (already shuffled) part order the caller passes.
pub fn schedule<R: RngCore>(
    commit_height: BlockHeight,
    n_parts: usize,
    rng: &mut R,
) -> Vec<Schedule> {
    schedule_broadcast_heights(commit_height, n_parts, rng)
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
/// The CANDIDATE ANCHOR SET is the boundaries (multiples of [`BOUNDARY_MODULUS`]) that are
/// simultaneously:
/// - (a) strictly above `nu63_activation` (the NU6.3 activation height),
/// - (b) at or after `funding_creation_height` (the funding note's creation height), and
/// - (c) at or before the most recent boundary at or below `chain_tip_height` (the chain tip the
///   wallet has observed at proving time).
///
/// The most recent boundary is derived internally via [`most_recent_boundary`], so
/// `chain_tip_height` may be any observed height; it need not itself be a boundary. A
/// recency-weighted age `a` in `[1, ANCHOR_AGE_CAP]` is drawn (`Geometric(1/2)`) and the candidate
/// is `most_recent_boundary(chain_tip_height) - a * BOUNDARY_MODULUS`; a draw exceeding
/// [`ANCHOR_AGE_CAP`] or landing outside the candidate set is discarded and redrawn. Because age is
/// always `>= 1`, the chosen boundary is always strictly below the most recent boundary.
pub fn draw_anchor_boundary<R: RngCore>(
    nu63_activation: BlockHeight,
    funding_creation_height: BlockHeight,
    chain_tip_height: BlockHeight,
    rng: &mut R,
) -> Option<BlockHeight> {
    let most_recent = most_recent_boundary_u32(u32::from(chain_tip_height));
    let (lowest, highest) = candidate_boundary_bounds(
        u32::from(nu63_activation),
        u32::from(funding_creation_height),
        most_recent,
    )?;

    // Rejection-sample the geometric age until the candidate lands in [lowest, highest].
    loop {
        let age = draw_anchor_age(rng);
        if age > ANCHOR_AGE_CAP {
            continue;
        }
        let offset = age * BOUNDARY_MODULUS;
        // most_recent - offset, guarding the underflow (too-old anchor -> redraw).
        let candidate = match most_recent.checked_sub(offset) {
            Some(c) => c,
            None => continue,
        };
        if candidate >= lowest && candidate <= highest {
            return Some(BlockHeight::from_u32(candidate));
        }
    }
}

/// The inclusive `[lowest, highest]` boundary-height bounds of the candidate anchor set, or `None`
/// if the set is empty. Encodes the three candidate-set conditions of [`draw_anchor_boundary`]:
/// the highest usable boundary is the one strictly below `most_recent` (age `>= 1`), and the
/// lowest is the first boundary that is both strictly above `nu63_activation` and at or after
/// `funding_creation_height`. `most_recent` is the boundary derived from the observed chain tip
/// (a multiple of [`BOUNDARY_MODULUS`]).
fn candidate_boundary_bounds(
    nu63_activation: u32,
    funding_creation_height: u32,
    most_recent: u32,
) -> Option<(u32, u32)> {
    // Highest candidate: strictly below the most recent boundary, i.e. one modulus down.
    let highest = most_recent.checked_sub(BOUNDARY_MODULUS)?;

    // Lowest candidate from condition (a): the first boundary strictly ABOVE nu63_activation.
    let above_activation =
        most_recent_boundary_u32(nu63_activation).saturating_add(BOUNDARY_MODULUS);
    // Lowest candidate from condition (b): the first boundary at or AFTER the funding creation.
    let at_or_after_funding = boundary_at_or_after(funding_creation_height);
    let lowest = above_activation.max(at_or_after_funding);

    (lowest <= highest).then_some((lowest, highest))
}

/// The smallest BOUNDARY height at or after `height`: `height` rounded UP to a multiple of
/// [`BOUNDARY_MODULUS`]. Saturates at `u32::MAX`.
fn boundary_at_or_after(height: u32) -> u32 {
    let r = height % BOUNDARY_MODULUS;
    if r == 0 {
        height
    } else {
        height.saturating_add(BOUNDARY_MODULUS - r)
    }
}

/// The first chain height at which a transfer's candidate anchor set (see
/// [`draw_anchor_boundary`]) is non-empty: one full boundary interval past the LOWEST candidate,
/// which is the first boundary strictly above `nu63_activation` and at or after
/// `funding_creation_height`. A transfer whose observed chain tip is at or after this height always
/// has at least one boundary to anchor to, so a schedule that places every broadcast at or after it
/// never needs an anchor fallback; the scheduler MUST NOT place a transfer before it.
pub fn earliest_broadcast_height(
    nu63_activation: BlockHeight,
    funding_creation_height: BlockHeight,
) -> BlockHeight {
    let lowest = most_recent_boundary_u32(u32::from(nu63_activation))
        .saturating_add(BOUNDARY_MODULUS)
        .max(boundary_at_or_after(u32::from(funding_creation_height)));
    BlockHeight::from_u32(lowest.saturating_add(BOUNDARY_MODULUS))
}

/// Like [`draw_anchor_boundary`], but additionally enforces the provisional per-wallet multiplicity
/// cap [`K_MAX`] (ZIP 318 SHOULD / OPEN ISSUE): `chosen_counts` maps each boundary height already
/// chosen by THIS wallet to how many of its parts landed there. A fresh draw whose boundary already
/// holds [`K_MAX`] of the wallet's parts is discarded and the age redrawn.
///
/// Returns `None` if the candidate set is empty, or if the candidate set cannot satisfy the cap
/// (every reachable boundary is already saturated) within a bounded number of attempts, so the
/// caller can fall back (for example by not bounding this part). Because this is only a SHOULD, a
/// caller may prefer plain [`draw_anchor_boundary`].
pub fn draw_anchor_boundary_bounded<R: RngCore>(
    nu63_activation: BlockHeight,
    funding_creation_height: BlockHeight,
    chain_tip_height: BlockHeight,
    chosen_counts: &BoundaryCounts,
    rng: &mut R,
) -> Option<BlockHeight> {
    // Cheap fast path / feasibility check: is any candidate boundary still below the cap?
    let (lowest, highest) = candidate_boundary_bounds(
        u32::from(nu63_activation),
        u32::from(funding_creation_height),
        most_recent_boundary_u32(u32::from(chain_tip_height)),
    )?;
    let mut any_room = false;
    let mut b = lowest;
    while b <= highest {
        if chosen_counts.count(BlockHeight::from_u32(b)) < K_MAX {
            any_room = true;
            break;
        }
        // Step to the next boundary; stop if we would pass `highest` or overflow.
        match b.checked_add(BOUNDARY_MODULUS) {
            Some(next) => b = next,
            None => break,
        }
    }
    if !any_room {
        return None;
    }

    for _ in 0..K_MAX_DRAW_ATTEMPTS {
        let candidate = draw_anchor_boundary(
            nu63_activation,
            funding_creation_height,
            chain_tip_height,
            rng,
        )?;
        if chosen_counts.count(candidate) < K_MAX {
            return Some(candidate);
        }
    }
    None
}

/// Maximum number of anchor redraws [`draw_anchor_boundary_bounded`] makes while trying to satisfy
/// the [`K_MAX`] cap before giving up and returning `None`. A generous bound so that, whenever the
/// candidate set has room, a valid boundary is found with overwhelming probability, while still
/// guaranteeing termination.
const K_MAX_DRAW_ATTEMPTS: usize = 64;

/// A running tally of how many of a single wallet's OWN transfers have chosen each boundary height,
/// used to enforce the [`K_MAX`] cap in [`draw_anchor_boundary_bounded`] and to describe COHORTS
/// (transfers sharing a boundary anchor). Backed by a simple association list, since one wallet
/// touches only a handful of boundaries per run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundaryCounts {
    entries: Vec<(BlockHeight, usize)>,
}

impl BoundaryCounts {
    /// An empty tally.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of the wallet's transfers recorded at `boundary` (0 if none).
    pub fn count(&self, boundary: BlockHeight) -> usize {
        self.entries
            .iter()
            .find_map(|(b, c)| (*b == boundary).then_some(*c))
            .unwrap_or(0)
    }

    /// Record one more of the wallet's transfers at `boundary`, returning the new count there.
    pub fn record(&mut self, boundary: BlockHeight) -> usize {
        for (b, c) in self.entries.iter_mut() {
            if *b == boundary {
                *c += 1;
                return *c;
            }
        }
        self.entries.push((boundary, 1));
        1
    }

    /// The distinct boundaries recorded, each with its count, sorted ascending by boundary height.
    /// Each `(boundary, count)` pair is one of the wallet's cohorts (its parts sharing that anchor).
    pub fn cohorts(&self) -> Vec<(BlockHeight, usize)> {
        let mut out = self.entries.clone();
        out.sort_unstable_by_key(|(b, _)| *b);
        out
    }
}

/// Group a wallet's own chosen boundary heights into a [`BoundaryCounts`] tally: transfers that
/// chose the same boundary height share a COHORT (a common anchor). A convenience over repeated
/// [`BoundaryCounts::record`] for when the boundaries are already known.
pub fn group_by_boundary(boundaries: &[BlockHeight]) -> BoundaryCounts {
    let mut counts = BoundaryCounts::new();
    for &b in boundaries {
        counts.record(b);
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    /// A seeded deterministic RNG for a proptest-drawn seed.
    fn rng(seed: u64) -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(seed)
    }

    /// Shorthand [`BlockHeight`] constructor for test literals.
    fn bh(h: u32) -> BlockHeight {
        BlockHeight::from_u32(h)
    }

    // --- most_recent_boundary / boundary helpers ----------------------------------------------

    proptest! {
        /// [`most_recent_boundary`] returns a multiple of the modulus, does not exceed the height,
        /// and is within one modulus of it.
        #[test]
        fn most_recent_boundary_props(h in 0u32..5_000_000) {
            let b = u32::from(most_recent_boundary(bh(h)));
            prop_assert_eq!(b % BOUNDARY_MODULUS, 0);
            prop_assert!(b <= h);
            prop_assert!(h - b < BOUNDARY_MODULUS);
        }

        /// [`boundary_at_or_after`] returns a multiple `>= height`, within one modulus above it.
        #[test]
        fn boundary_at_or_after_props(h in 0u32..5_000_000) {
            let b = boundary_at_or_after(h);
            prop_assert_eq!(b % BOUNDARY_MODULUS, 0);
            prop_assert!(b >= h);
            prop_assert!(b - h < BOUNDARY_MODULUS);
        }
    }

    /// Assert one hand-derived [`most_recent_boundary`] value plus its invariants (a multiple of the
    /// modulus, `<= height`, and within one modulus of it). `BOUNDARY_MODULUS` is 144.
    fn check_most_recent_boundary_golden(height: u32, expected: u32) {
        let b = u32::from(most_recent_boundary(bh(height)));
        assert_eq!(b, expected, "most_recent_boundary({height})");
        assert_eq!(b % BOUNDARY_MODULUS, 0, "not a boundary");
        assert!(b <= height, "boundary {b} above height {height}");
        assert!(
            height - b < BOUNDARY_MODULUS,
            "boundary {b} more than a modulus below {height}"
        );
    }

    /// Golden vectors for [`most_recent_boundary`], hand-derived from `BOUNDARY_MODULUS == 144`:
    /// the result is `height - (height % 144)`, i.e. `height` rounded DOWN to a multiple of 144.
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

    // --- draw_delay ---------------------------------------------------------------------------

    proptest! {
        /// Every drawn delay is in the closed range [0, MAX_DELAY] (DELAYS MUST).
        #[test]
        fn delay_within_bounds(seed in any::<u64>()) {
            let mut r = rng(seed);
            for _ in 0..200 {
                let d = draw_delay(&mut r);
                prop_assert!(d <= MAX_DELAY);
            }
        }
    }

    #[test]
    fn delay_mean_is_near_expected() {
        // Sanity on the distribution: the truncated-exponential mean sits below MEAN_DELAY (the
        // tail past MAX_DELAY is removed). Large sample keeps this deterministic and robust.
        let mut r = rng(42);
        let n = 20_000u64;
        let mut sum = 0u64;
        for _ in 0..n {
            sum += u64::from(draw_delay(&mut r));
        }
        let mean = sum as f64 / n as f64;
        // Analytic truncated mean is ~124 blocks; allow a wide band.
        assert!(
            (100.0..150.0).contains(&mean),
            "empirical mean {mean} out of expected band"
        );
    }

    /// Assert a golden sequence of [`draw_delay`] draws for a fixed seed, pinning the exact
    /// deterministic [`ChaCha8Rng`] output as a regression guard, plus the documented invariant that
    /// every delay is in the closed range `[0, MAX_DELAY]` (the truncated-exponential bound).
    fn check_delay_golden(seed: u64, expected: &[u32]) {
        let mut r = rng(seed);
        let got: Vec<u32> = (0..expected.len()).map(|_| draw_delay(&mut r)).collect();
        assert_eq!(got, expected, "draw_delay(seed={seed})");
        for &d in &got {
            assert!(d <= MAX_DELAY, "delay {d} exceeds MAX_DELAY {MAX_DELAY}");
        }
    }

    /// Golden vectors for [`draw_delay`] over several seeds. These are the captured deterministic
    /// draws; the `seed=1` sequence matches the per-step gaps pinned in
    /// [`schedule_broadcast_heights_golden`] (74, 12, 131, 36, 48, ...).
    #[test]
    fn draw_delay_golden() {
        let exp_seed1 = [74, 12, 131, 36, 48, 179, 89, 24];
        let exp_seed42 = [165, 432, 80, 142, 49, 23, 53, 235];
        let exp_seed7 = [25, 26, 175, 187, 132, 64, 12, 273];
        check_delay_golden(1, &exp_seed1);
        check_delay_golden(42, &exp_seed42);
        check_delay_golden(7, &exp_seed7);
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
            let hs = schedule_broadcast_heights(bh(commit), n, &mut r);
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
    /// inter-arrival delay and must be a valid `[0, MAX_DELAY]` value.
    fn check_schedule_golden(commit: u32, n: usize, seed: u64, expected: &[u32]) {
        let hs: Vec<u32> = schedule_broadcast_heights(bh(commit), n, &mut rng(seed))
            .into_iter()
            .map(u32::from)
            .collect();
        assert_eq!(hs, expected, "schedule({commit}, {n}, seed={seed})");
        assert_eq!(hs.len(), n);
        let mut prev = commit;
        for &h in &hs {
            assert!(
                h >= prev,
                "heights must be non-decreasing (commit {commit})"
            );
            let gap = h - prev;
            assert!(
                gap <= MAX_DELAY,
                "delay {gap} exceeds MAX_DELAY {MAX_DELAY}"
            );
            prev = h;
        }
    }

    /// Golden vectors for the cumulative broadcast schedule: fixed `(commit, n, seed)` triples pinned
    /// to their exact height sequences (a regression guard on the delay sampling), with the per-step
    /// gaps noted so the drawn delays are visible. `MEAN_DELAY` is 144 and `MAX_DELAY` is 576 blocks.
    #[test]
    fn schedule_broadcast_heights_golden() {
        // n = 0 schedules nothing, whatever the seed.
        check_schedule_golden(1_000_000, 0, 1, &[]);
        // gaps: 74, 12, 131, 36, 48
        check_schedule_golden(
            1_000_000,
            5,
            1,
            &[1_000_074, 1_000_086, 1_000_217, 1_000_253, 1_000_301],
        );
        // gaps: 165, 432, 80, 142, 49, 23, 53, 235
        check_schedule_golden(
            2_000_000,
            8,
            42,
            &[
                2_000_165, 2_000_597, 2_000_677, 2_000_819, 2_000_868, 2_000_891, 2_000_944,
                2_001_179,
            ],
        );
        // gaps: 25, 26, 175
        check_schedule_golden(500_000, 3, 7, &[500_025, 500_051, 500_226]);
        // commit height 0; gaps: 11, 6, 225, 58, 13, 28
        check_schedule_golden(0, 6, 12_345, &[11, 17, 242, 300, 313, 341]);
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
    fn arb_anchor_inputs() -> impl Strategy<Value = (u32, u32, u32)> {
        // nu63_activation in a modest range; span in boundaries above it (>= 2 so a candidate exists).
        (0u32..1000u32, 2u32..40u32, 0u32..BOUNDARY_MODULUS).prop_flat_map(
            |(act, span_boundaries, tip_offset)| {
                let most_recent = (most_recent_boundary_u32(act)
                    + span_boundaries * BOUNDARY_MODULUS)
                    .max(BOUNDARY_MODULUS);
                let tip = most_recent + tip_offset;
                // funding creation anywhere from activation up to the highest candidate boundary.
                let highest = most_recent - BOUNDARY_MODULUS;
                (Just(act), Just(tip), act..=highest)
            },
        )
    }

    proptest! {
        /// Every chosen anchor boundary is in the candidate set: a multiple of the modulus, strictly
        /// below the most recent boundary derived from the chain tip, strictly above
        /// nu63_activation, and at/after the funding creation height (ANCHOR-SELECTION +
        /// ANCHOR-AGE-DRAW MUST).
        #[test]
        fn anchor_in_candidate_set((act, tip, funding) in arb_anchor_inputs(),
                                   seed in any::<u64>()) {
            let mut r = rng(seed);
            let most_recent = most_recent_boundary_u32(tip);
            let chosen = draw_anchor_boundary(bh(act), bh(funding), bh(tip), &mut r);
            prop_assert!(chosen.is_some());
            let b = u32::from(chosen.unwrap());
            prop_assert_eq!(b % BOUNDARY_MODULUS, 0);
            prop_assert!(b < most_recent, "boundary {b} must be below most_recent {most_recent}");
            prop_assert!(b > act, "boundary {b} must be strictly above activation {act}");
            prop_assert!(b >= funding, "boundary {b} must be at/after funding {funding}");
            // Age is within the cap: (most_recent - b) / modulus in [1, ANCHOR_AGE_CAP].
            let age = (most_recent - b) / BOUNDARY_MODULUS;
            prop_assert!((1..=ANCHOR_AGE_CAP).contains(&age), "age {age} out of [1, cap]");
        }

        /// The most recent boundary is derived from the chain tip internally: any tip within a
        /// boundary interval draws exactly the same anchors as the boundary itself under the same
        /// seed.
        #[test]
        fn anchor_draw_derives_boundary_from_tip(tip_offset in 0u32..BOUNDARY_MODULUS,
                                                 seed in any::<u64>()) {
            let (act, funding) = (BOUNDARY_MODULUS, 2 * BOUNDARY_MODULUS);
            let boundary_tip = 20 * BOUNDARY_MODULUS;
            let mut r_offset = rng(seed);
            let mut r_boundary = rng(seed);
            for _ in 0..16 {
                prop_assert_eq!(
                    draw_anchor_boundary(
                        bh(act), bh(funding), bh(boundary_tip + tip_offset), &mut r_offset,
                    ),
                    draw_anchor_boundary(bh(act), bh(funding), bh(boundary_tip), &mut r_boundary)
                );
            }
        }
    }

    #[test]
    fn anchor_empty_candidate_set_is_none() {
        let mut r = rng(1);
        // Chain tip below the second boundary: no candidate strictly below the derived boundary
        // that is also above activation.
        assert_eq!(draw_anchor_boundary(bh(0), bh(0), bh(0), &mut r), None);
        assert_eq!(
            draw_anchor_boundary(bh(0), bh(0), bh(BOUNDARY_MODULUS), &mut r),
            None
        );
        // A non-boundary tip derives the same (first) boundary, so the set is still empty.
        assert_eq!(
            draw_anchor_boundary(bh(0), bh(0), bh(2 * BOUNDARY_MODULUS - 1), &mut r),
            None
        );
    }

    proptest! {
        /// [`earliest_broadcast_height`] is the exact viability threshold: a tip at that height
        /// always yields an anchor, and a tip one block earlier never does.
        #[test]
        fn earliest_broadcast_height_is_the_viability_threshold(act in 0u32..1_000_000,
                                                               funding_offset in 0u32..2_000,
                                                               seed in any::<u64>()) {
            let funding = act + funding_offset;
            let earliest = earliest_broadcast_height(bh(act), bh(funding));
            let mut r = rng(seed);
            prop_assert!(
                draw_anchor_boundary(bh(act), bh(funding), earliest, &mut r).is_some(),
                "a tip at the earliest broadcast height must have a candidate boundary"
            );
            let mut r = rng(seed);
            prop_assert!(
                draw_anchor_boundary(bh(act), bh(funding), earliest - 1, &mut r).is_none(),
                "a tip below the earliest broadcast height must not"
            );
        }
    }

    #[test]
    fn anchor_funding_after_most_recent_is_none() {
        let mut r = rng(2);
        // Funding note created after the tip's most recent boundary: nothing at/after it can be a
        // candidate (candidates are all <= most_recent - modulus).
        let tip = 10 * BOUNDARY_MODULUS;
        let funding = tip + BOUNDARY_MODULUS;
        assert_eq!(
            draw_anchor_boundary(bh(0), bh(funding), bh(tip), &mut r),
            None
        );
    }

    /// Assert a golden sequence of [`draw_anchor_boundary`] draws for a fixed candidate set and seed,
    /// pinning the exact deterministic recency-weighted picks, plus the documented invariants for
    /// each: a multiple of the modulus, strictly above `act`, strictly below the most recent
    /// boundary derived from `chain_tip`, at/after `funding`, and with an age in
    /// `[1, ANCHOR_AGE_CAP]`.
    fn check_anchor_golden(act: u32, funding: u32, chain_tip: u32, seed: u64, expected: &[u32]) {
        let most_recent = most_recent_boundary_u32(chain_tip);
        let mut r = rng(seed);
        let got: Vec<u32> = (0..expected.len())
            .map(|_| {
                u32::from(
                    draw_anchor_boundary(bh(act), bh(funding), bh(chain_tip), &mut r).unwrap(),
                )
            })
            .collect();
        assert_eq!(got, expected, "draw_anchor_boundary(seed={seed})");
        for &b in &got {
            assert_eq!(
                b % BOUNDARY_MODULUS,
                0,
                "boundary {b} not a multiple of the modulus"
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
            let age = (most_recent - b) / BOUNDARY_MODULUS;
            assert!(
                (1..=ANCHOR_AGE_CAP).contains(&age),
                "age {age} out of [1, cap]"
            );
        }
    }

    /// Golden vectors for [`draw_anchor_boundary`]. The candidate set spans boundaries `288..=2736`
    /// (`act = 144`, `funding = 288`, chain tip `2880`); each pinned sequence is the exact
    /// recency-weighted draw, and every entry is checked against the candidate-set invariants. The
    /// modal pick is the highest candidate 2736 (age 1), as the `Geometric(1/2)` age draw expects.
    /// A tip in the middle of the same boundary interval derives the same boundary and must
    /// reproduce the same vectors.
    #[test]
    fn draw_anchor_boundary_golden() {
        let (act, funding, tip) = (
            BOUNDARY_MODULUS,
            2 * BOUNDARY_MODULUS,
            20 * BOUNDARY_MODULUS,
        );
        let exp_seed1 = [2736, 2736, 2736, 2592, 2736, 2304];
        let exp_seed42 = [2736, 2304, 2448, 2592, 2160, 2592];
        let exp_seed7 = [2736, 2592, 2736, 2736, 2304, 2592];
        let exp_seed100 = [2592, 2736, 2736, 2592, 2016, 2736];
        check_anchor_golden(act, funding, tip, 1, &exp_seed1);
        check_anchor_golden(act, funding, tip, 42, &exp_seed42);
        check_anchor_golden(act, funding, tip, 7, &exp_seed7);
        check_anchor_golden(act, funding, tip, 100, &exp_seed100);
        // A mid-interval tip (not itself a boundary) must yield identical draws.
        check_anchor_golden(act, funding, tip + 100, 1, &exp_seed1);
        check_anchor_golden(act, funding, tip + BOUNDARY_MODULUS - 1, 42, &exp_seed42);
    }

    /// Golden vectors for [`draw_anchor_boundary_bounded`]: a sequence of draws over the same
    /// candidate set (`288..=2736`), each accepted draw recorded into the running
    /// [`BoundaryCounts`], pinned to the exact chosen boundaries. The invariant checked is the
    /// `K_MAX` cap: no boundary ends up holding more than [`K_MAX`] of the wallet's parts.
    #[test]
    fn draw_anchor_boundary_bounded_golden() {
        fn check(seed: u64, expected: &[Option<u32>]) {
            let (act, funding, tip) = (
                BOUNDARY_MODULUS,
                2 * BOUNDARY_MODULUS,
                20 * BOUNDARY_MODULUS,
            );
            let mut r = rng(seed);
            let mut counts = BoundaryCounts::new();
            let mut got: Vec<Option<u32>> = Vec::new();
            for _ in 0..expected.len() {
                match draw_anchor_boundary_bounded(bh(act), bh(funding), bh(tip), &counts, &mut r) {
                    Some(b) => {
                        counts.record(b);
                        got.push(Some(u32::from(b)));
                    }
                    None => got.push(None),
                }
            }
            assert_eq!(got, expected, "draw_anchor_boundary_bounded(seed={seed})");
            for (_, c) in counts.cohorts() {
                assert!(c <= K_MAX, "cohort count {c} exceeds K_MAX {K_MAX}");
            }
        }
        let exp_seed1 = [
            Some(2736),
            Some(2736),
            Some(2592),
            Some(2304),
            Some(2592),
            Some(2304),
            Some(2016),
            Some(2448),
        ];
        let exp_seed42 = [
            Some(2736),
            Some(2304),
            Some(2448),
            Some(2592),
            Some(2160),
            Some(2592),
            Some(2448),
            Some(1296),
        ];
        let exp_seed7 = [
            Some(2736),
            Some(2592),
            Some(2736),
            Some(2304),
            Some(2592),
            Some(2304),
            Some(2448),
            Some(2448),
        ];
        check(1, &exp_seed1);
        check(42, &exp_seed42);
        check(7, &exp_seed7);
    }

    #[test]
    fn anchor_tiny_range_single_candidate() {
        // Exactly one candidate: the boundary below the tip's, and it satisfies all bounds.
        let mut r = rng(3);
        let act = BOUNDARY_MODULUS; // first candidate above activation is 2*modulus
        let tip = 3 * BOUNDARY_MODULUS; // highest candidate is 2*modulus
        let funding = 2 * BOUNDARY_MODULUS;
        // Only 2*BOUNDARY_MODULUS qualifies.
        for _ in 0..50 {
            assert_eq!(
                draw_anchor_boundary(bh(act), bh(funding), bh(tip), &mut r),
                Some(bh(2 * BOUNDARY_MODULUS))
            );
        }
    }

    // --- K_MAX bounded draw / cohorts ---------------------------------------------------------

    proptest! {
        /// The bounded draw never lets one wallet exceed K_MAX parts on a boundary, when it returns
        /// a value (SHOULD / open issue).
        #[test]
        fn bounded_draw_respects_k_max((act, tip, funding) in arb_anchor_inputs(),
                                       seed in any::<u64>()) {
            let mut r = rng(seed);
            let mut counts = BoundaryCounts::new();
            // Draw several parts; each accepted draw is recorded.
            for _ in 0..8 {
                if let Some(b) = draw_anchor_boundary_bounded(bh(act), bh(funding), bh(tip),
                                                              &counts, &mut r) {
                    prop_assert!(counts.count(b) < K_MAX, "would exceed K_MAX at {b}");
                    counts.record(b);
                }
            }
            for (_, c) in counts.cohorts() {
                prop_assert!(c <= K_MAX);
            }
        }
    }

    #[test]
    fn bounded_draw_exhausts_to_none() {
        // Single candidate, filled to K_MAX: the bounded draw must report infeasible (None).
        let mut r = rng(5);
        let act = BOUNDARY_MODULUS;
        let tip = 3 * BOUNDARY_MODULUS;
        let funding = 2 * BOUNDARY_MODULUS;
        let only = 2 * BOUNDARY_MODULUS;
        let mut counts = BoundaryCounts::new();
        for _ in 0..K_MAX {
            counts.record(bh(only));
        }
        assert_eq!(
            draw_anchor_boundary_bounded(bh(act), bh(funding), bh(tip), &counts, &mut r),
            None
        );
    }

    #[test]
    fn group_by_boundary_counts_cohorts() {
        let counts = group_by_boundary(&[bh(144), bh(288), bh(144), bh(144), bh(288)]);
        assert_eq!(counts.count(bh(144)), 3);
        assert_eq!(counts.count(bh(288)), 2);
        assert_eq!(counts.count(bh(432)), 0);
        assert_eq!(counts.cohorts(), alloc::vec![(bh(144), 3), (bh(288), 2)]);
    }

    /// Golden for the [`BoundaryCounts`] primitive operations (`new`, `record`, `count`, `cohorts`)
    /// exercised directly rather than through [`group_by_boundary`]: a fresh tally is empty,
    /// [`BoundaryCounts::record`] returns the incremented running count at that boundary, and
    /// [`BoundaryCounts::cohorts`] lists distinct boundaries sorted ascending regardless of
    /// insertion order.
    #[test]
    fn boundary_counts_golden() {
        let mut c = BoundaryCounts::new();
        assert_eq!(c, BoundaryCounts::default(), "new() must equal default()");
        assert_eq!(c.count(bh(144)), 0, "empty tally counts zero");
        assert!(c.cohorts().is_empty(), "empty tally has no cohorts");
        // record returns the new running count at the boundary; insert out of order (288 before 144).
        // Each expected running count is bound so the incrementing sequence is readable.
        let exp_record_288_first = 1;
        let exp_record_144_first = 1;
        let exp_record_288_second = 2;
        let exp_record_288_third = 3;
        assert_eq!(c.record(bh(288)), exp_record_288_first);
        assert_eq!(c.record(bh(144)), exp_record_144_first);
        assert_eq!(c.record(bh(288)), exp_record_288_second);
        assert_eq!(c.record(bh(288)), exp_record_288_third);
        assert_eq!(c.count(bh(288)), 3);
        assert_eq!(c.count(bh(144)), 1);
        assert_eq!(c.count(bh(432)), 0, "unrecorded boundary counts zero");
        // cohorts sorted ascending by boundary height, not insertion order.
        let exp_cohorts = alloc::vec![(bh(144), 1), (bh(288), 3)];
        assert_eq!(c.cohorts(), exp_cohorts);
    }

    proptest! {
        /// [`group_by_boundary`] / [`BoundaryCounts`] tallies faithfully: the cohort counts sum to the
        /// input length, each boundary's count equals its number of occurrences, an absent boundary
        /// counts zero, and cohorts are strictly ascending by boundary height (distinct + sorted).
        #[test]
        fn group_by_boundary_tallies(boundaries in prop::collection::vec(0u32..2000, 0..64)) {
            let heights: Vec<BlockHeight> = boundaries.iter().copied().map(bh).collect();
            let counts = group_by_boundary(&heights);
            // Sum of cohort counts equals the number of recorded boundaries.
            let total: usize = counts.cohorts().iter().map(|(_, c)| *c).sum();
            prop_assert_eq!(total, boundaries.len());
            // Every recorded boundary is counted with its exact multiplicity.
            for &b in &boundaries {
                let occ = boundaries.iter().filter(|&&x| x == b).count();
                prop_assert_eq!(counts.count(bh(b)), occ);
            }
            // A boundary outside the drawn range is never present.
            prop_assert_eq!(counts.count(bh(9999)), 0);
            // cohorts() is strictly ascending by boundary height (distinct keys, sorted).
            let cohorts = counts.cohorts();
            for w in cohorts.windows(2) {
                prop_assert!(w[0].0 < w[1].0, "cohorts not strictly ascending");
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
        let schedules = schedule(bh(commit), n, &mut rng(seed));
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
            schedule_broadcast_heights(bh(commit), n, &mut rng(seed))
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
        let exp_broadcast_c1m_seed1 = [1_000_074, 1_000_086, 1_000_217, 1_000_253, 1_000_301];
        let exp_expiry_c1m_seed1 = [1_036_800; 5];
        check_schedule_golden_pairs(
            1_000_000,
            5,
            1,
            &exp_broadcast_c1m_seed1,
            &exp_expiry_c1m_seed1,
        );

        // commit = 0, n = 6, seed = 12_345.
        let exp_broadcast_c0_seed12345 = [11, 17, 242, 300, 313, 341];
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
            let schedules = schedule(bh(commit), n, &mut r);
            prop_assert_eq!(schedules.len(), n);
            // Broadcast heights follow the cumulative delay rule (same RNG => same heights).
            let broadcast: Vec<BlockHeight> =
                schedules.iter().map(|s| s.broadcast_height()).collect();
            prop_assert_eq!(&broadcast, &schedule_broadcast_heights(bh(commit), n, &mut rng(seed)));
            let mut prev = bh(commit);
            for s in &schedules {
                prop_assert!(s.broadcast_height() >= prev, "broadcast heights must be non-decreasing");
                prev = s.broadcast_height();
                prop_assert_eq!(s.expiry_height(), expiry_height(s.broadcast_height()));
            }
        }
    }
}
