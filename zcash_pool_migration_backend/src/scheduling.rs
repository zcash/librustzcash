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

/// Mean of the exponential inter-arrival delay between successive transfers, in blocks. Also the
/// [`BOUNDARY_MODULUS`]. 144 blocks is roughly one day at the Zcash ~75-second target spacing. The
/// exponential rate is `lambda = 1 / MEAN_DELAY`. See [`draw_delay`].
pub const MEAN_DELAY: u32 = 144;

/// Upper bound (inclusive) on a single inter-arrival delay, in blocks. A draw exceeding this is
/// discarded and redrawn (truncating the exponential's heavy tail), so no transfer is starved for
/// an unbounded time. 576 blocks is `4 * MEAN_DELAY`, about four days. See [`draw_delay`].
pub const MAX_DELAY: u32 = 576;

/// Block-height modulus defining the BOUNDARY blocks: a height `h` is a boundary iff
/// `h % BOUNDARY_MODULUS == 0`. Boundaries are the only tree states a transfer may anchor to, so
/// many transfers share a small, common set of anchors (cohorts) rather than each pinning a unique
/// recent block. Equal to [`MEAN_DELAY`] (~one day). See [`draw_anchor_boundary`].
pub const BOUNDARY_MODULUS: u32 = MEAN_DELAY;

/// Maximum anchor AGE, in boundaries, that the recency-weighted draw will accept. Age `a` counts
/// boundaries strictly before the most recent boundary observed at proving time; a draw exceeding
/// this cap (a very old anchor) is discarded and redrawn. Bounds how stale a proof's anchor can be
/// (16 boundaries is about 16 days). See [`draw_anchor_boundary`].
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
    broadcast_height: u32,
    expiry_height: u32,
}

impl Schedule {
    /// The block height at which this transfer is scheduled to be broadcast (a cumulative sum of
    /// per-part delays from the commit height; see [`schedule_broadcast_heights`]).
    pub fn broadcast_height(&self) -> u32 {
        self.broadcast_height
    }

    /// The block height at (and after) which this transfer is no longer valid: the canonical rolling
    /// window of [`expiry_height`] applied at the broadcast height.
    pub fn expiry_height(&self) -> u32 {
        self.expiry_height
    }
}

/// The most recent BOUNDARY block at or below `height`: the largest multiple of [`BOUNDARY_MODULUS`]
/// that is `<= height`. Equivalently `height - (height % BOUNDARY_MODULUS)`.
pub fn most_recent_boundary(height: u32) -> u32 {
    height - (height % BOUNDARY_MODULUS)
}

/// Fraction of the unit interval covered by one `u64` step, i.e. `1 / 2^53`. Drawing 53 random bits
/// and scaling by this yields a uniform value on a dyadic grid; see [`draw_unit_half_open`].
const UNIT_STEP: f64 = 1.0 / ((1u64 << 53) as f64);

/// Number of high bits kept from a drawn `u64` to form a 53-bit mantissa (an `f64` has a 53-bit
/// significand, so this is the most uniform grid representable without rounding bias).
const U64_TO_MANTISSA_SHIFT: u32 = 11;

/// Draw a uniform `f64` in the half-open interval `[0, 1)` from `rng`, on the 53-bit dyadic grid.
/// Keeps the top [`U64_TO_MANTISSA_SHIFT`] bits of a fresh `u64` and scales by [`UNIT_STEP`].
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
    commit_height: u32,
    n_parts: usize,
    rng: &mut R,
) -> Vec<u32> {
    let mut heights = Vec::with_capacity(n_parts);
    let mut height = commit_height;
    for _ in 0..n_parts {
        height = height.saturating_add(draw_delay(rng));
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
pub fn expiry_height(current_height: u32) -> u32 {
    let anchor = current_height - (current_height % EXPIRY_MODULUS);
    anchor.saturating_add(EXPIRY_WINDOW)
}

/// Assemble a [`Schedule`] for each part: draw the cumulative broadcast heights from `commit_height`
/// (see [`schedule_broadcast_heights`]) and pair each with its canonical [`expiry_height`]. Returns
/// one [`Schedule`] per part, in the (already shuffled) part order the caller passes.
pub fn schedule<R: RngCore>(commit_height: u32, n_parts: usize, rng: &mut R) -> Vec<Schedule> {
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
/// - (c) at or before `most_recent_boundary` (the most recent boundary observed at proving time).
///
/// A recency-weighted age `a` in `[1, ANCHOR_AGE_CAP]` is drawn (`Geometric(1/2)`) and the
/// candidate is `most_recent_boundary - a * BOUNDARY_MODULUS`; a draw exceeding [`ANCHOR_AGE_CAP`]
/// or landing outside the candidate set is discarded and redrawn. Because age is always `>= 1`, the
/// chosen boundary is always strictly below `most_recent_boundary`.
///
/// `most_recent_boundary` is expected to be a boundary (a multiple of [`BOUNDARY_MODULUS`]); pass
/// [`most_recent_boundary`] of the proving height.
pub fn draw_anchor_boundary<R: RngCore>(
    nu63_activation: u32,
    funding_creation_height: u32,
    most_recent_boundary: u32,
    rng: &mut R,
) -> Option<u32> {
    let (lowest, highest) = candidate_boundary_bounds(
        nu63_activation,
        funding_creation_height,
        most_recent_boundary,
    )?;

    // Rejection-sample the geometric age until the candidate lands in [lowest, highest].
    loop {
        let age = draw_anchor_age(rng);
        if age > ANCHOR_AGE_CAP {
            continue;
        }
        let offset = age * BOUNDARY_MODULUS;
        // most_recent_boundary - offset, guarding the underflow (too-old anchor -> redraw).
        let candidate = match most_recent_boundary.checked_sub(offset) {
            Some(c) => c,
            None => continue,
        };
        if candidate >= lowest && candidate <= highest {
            return Some(candidate);
        }
    }
}

/// The inclusive `[lowest, highest]` boundary-height bounds of the candidate anchor set, or `None`
/// if the set is empty. Encodes the three candidate-set conditions of [`draw_anchor_boundary`]:
/// the highest usable boundary is the one strictly below `most_recent_boundary` (age `>= 1`), and
/// the lowest is the first boundary that is both strictly above `nu63_activation` and at or after
/// `funding_creation_height`.
fn candidate_boundary_bounds(
    nu63_activation: u32,
    funding_creation_height: u32,
    most_recent: u32,
) -> Option<(u32, u32)> {
    // Highest candidate: strictly below the most recent boundary, i.e. one modulus down.
    let highest = most_recent.checked_sub(BOUNDARY_MODULUS)?;

    // Lowest candidate from condition (a): the first boundary strictly ABOVE nu63_activation.
    let above_activation = most_recent_boundary(nu63_activation).saturating_add(BOUNDARY_MODULUS);
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
    nu63_activation: u32,
    funding_creation_height: u32,
    most_recent_boundary: u32,
    chosen_counts: &BoundaryCounts,
    rng: &mut R,
) -> Option<u32> {
    // Cheap fast path / feasibility check: is any candidate boundary still below the cap?
    let (lowest, highest) = candidate_boundary_bounds(
        nu63_activation,
        funding_creation_height,
        most_recent_boundary,
    )?;
    let mut any_room = false;
    let mut b = lowest;
    while b <= highest {
        if chosen_counts.count(b) < K_MAX {
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
            most_recent_boundary,
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
    entries: Vec<(u32, usize)>,
}

impl BoundaryCounts {
    /// An empty tally.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of the wallet's transfers recorded at `boundary` (0 if none).
    pub fn count(&self, boundary: u32) -> usize {
        self.entries
            .iter()
            .find_map(|(b, c)| (*b == boundary).then_some(*c))
            .unwrap_or(0)
    }

    /// Record one more of the wallet's transfers at `boundary`, returning the new count there.
    pub fn record(&mut self, boundary: u32) -> usize {
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
    pub fn cohorts(&self) -> Vec<(u32, usize)> {
        let mut out = self.entries.clone();
        out.sort_unstable_by_key(|(b, _)| *b);
        out
    }
}

/// Group a wallet's own chosen boundary heights into a [`BoundaryCounts`] tally: transfers that
/// chose the same boundary height share a COHORT (a common anchor). A convenience over repeated
/// [`BoundaryCounts::record`] for when the boundaries are already known.
pub fn group_by_boundary(boundaries: &[u32]) -> BoundaryCounts {
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

    // --- most_recent_boundary / boundary helpers ----------------------------------------------

    proptest! {
        /// [`most_recent_boundary`] returns a multiple of the modulus, does not exceed the height,
        /// and is within one modulus of it.
        #[test]
        fn most_recent_boundary_props(h in 0u32..5_000_000) {
            let b = most_recent_boundary(h);
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

    // --- schedule_broadcast_heights -----------------------------------------------------------

    proptest! {
        /// Broadcast heights are non-decreasing and start at or above the commit height
        /// (CUMULATIVE MUST).
        #[test]
        fn broadcast_heights_monotone(commit in 0u32..5_000_000,
                                      n in 0usize..40,
                                      seed in any::<u64>()) {
            let mut r = rng(seed);
            let hs = schedule_broadcast_heights(commit, n, &mut r);
            prop_assert_eq!(hs.len(), n);
            let mut prev = commit;
            for h in hs {
                prop_assert!(h >= prev);
                prev = h;
            }
        }
    }

    // --- expiry_height ------------------------------------------------------------------------

    proptest! {
        /// The expiry height lies in the rolling window (current, current + EXPIRY_WINDOW] and its
        /// anchoring point (expiry - EXPIRY_WINDOW) is a multiple of EXPIRY_MODULUS (EXPIRY MUST).
        #[test]
        fn expiry_in_rolling_window(current in 0u32..(u32::MAX - EXPIRY_WINDOW)) {
            let e = expiry_height(current);
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
        assert_eq!(expiry_height(0), EXPIRY_WINDOW);
        assert_eq!(
            expiry_height(EXPIRY_MODULUS),
            EXPIRY_MODULUS + EXPIRY_WINDOW
        );
        // Just before the next modulus, validity is just over one modulus.
        let just_before = EXPIRY_MODULUS - 1;
        assert_eq!(expiry_height(just_before), EXPIRY_WINDOW);
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
    /// picks an activation height, a most-recent boundary at least a few boundaries above it, and a
    /// funding-creation height at or below the highest candidate.
    fn arb_anchor_inputs() -> impl Strategy<Value = (u32, u32, u32)> {
        // nu63_activation in a modest range; span in boundaries above it (>= 2 so a candidate exists).
        (0u32..1000u32, 2u32..40u32).prop_flat_map(|(act, span_boundaries)| {
            let most_recent = (most_recent_boundary(act) + span_boundaries * BOUNDARY_MODULUS)
                .max(BOUNDARY_MODULUS);
            // funding creation anywhere from activation up to the highest candidate boundary.
            let highest = most_recent - BOUNDARY_MODULUS;
            (Just(act), Just(most_recent), act..=highest)
        })
    }

    proptest! {
        /// Every chosen anchor boundary is in the candidate set: a multiple of the modulus, strictly
        /// below most_recent_boundary, strictly above nu63_activation, and at/after the funding
        /// creation height (ANCHOR-SELECTION + ANCHOR-AGE-DRAW MUST).
        #[test]
        fn anchor_in_candidate_set((act, most_recent, funding) in arb_anchor_inputs(),
                                   seed in any::<u64>()) {
            let mut r = rng(seed);
            let chosen = draw_anchor_boundary(act, funding, most_recent, &mut r);
            prop_assert!(chosen.is_some());
            let b = chosen.unwrap();
            prop_assert_eq!(b % BOUNDARY_MODULUS, 0);
            prop_assert!(b < most_recent, "boundary {b} must be below most_recent {most_recent}");
            prop_assert!(b > act, "boundary {b} must be strictly above activation {act}");
            prop_assert!(b >= funding, "boundary {b} must be at/after funding {funding}");
            // Age is within the cap: (most_recent - b) / modulus in [1, ANCHOR_AGE_CAP].
            let age = (most_recent - b) / BOUNDARY_MODULUS;
            prop_assert!((1..=ANCHOR_AGE_CAP).contains(&age), "age {age} out of [1, cap]");
        }
    }

    #[test]
    fn anchor_empty_candidate_set_is_none() {
        let mut r = rng(1);
        // most_recent_boundary at the very first boundary: no candidate strictly below it that is
        // also above activation.
        assert_eq!(draw_anchor_boundary(0, 0, 0, &mut r), None);
        assert_eq!(draw_anchor_boundary(0, 0, BOUNDARY_MODULUS, &mut r), None);
    }

    #[test]
    fn anchor_funding_after_most_recent_is_none() {
        let mut r = rng(2);
        // Funding note created after the most recent boundary: nothing at/after it can be a
        // candidate (candidates are all <= most_recent - modulus).
        let most_recent = 10 * BOUNDARY_MODULUS;
        let funding = most_recent + BOUNDARY_MODULUS;
        assert_eq!(draw_anchor_boundary(0, funding, most_recent, &mut r), None);
    }

    #[test]
    fn anchor_tiny_range_single_candidate() {
        // Exactly one candidate: most_recent - modulus, and it satisfies all bounds.
        let mut r = rng(3);
        let act = BOUNDARY_MODULUS; // first candidate above activation is 2*modulus
        let most_recent = 3 * BOUNDARY_MODULUS; // highest candidate is 2*modulus
        let funding = 2 * BOUNDARY_MODULUS;
        // Only 2*BOUNDARY_MODULUS qualifies.
        for _ in 0..50 {
            assert_eq!(
                draw_anchor_boundary(act, funding, most_recent, &mut r),
                Some(2 * BOUNDARY_MODULUS)
            );
        }
    }

    // --- K_MAX bounded draw / cohorts ---------------------------------------------------------

    proptest! {
        /// The bounded draw never lets one wallet exceed K_MAX parts on a boundary, when it returns
        /// a value (SHOULD / open issue).
        #[test]
        fn bounded_draw_respects_k_max((act, most_recent, funding) in arb_anchor_inputs(),
                                       seed in any::<u64>()) {
            let mut r = rng(seed);
            let mut counts = BoundaryCounts::new();
            // Draw several parts; each accepted draw is recorded.
            for _ in 0..8 {
                if let Some(b) = draw_anchor_boundary_bounded(act, funding, most_recent,
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
        let most_recent = 3 * BOUNDARY_MODULUS;
        let funding = 2 * BOUNDARY_MODULUS;
        let only = 2 * BOUNDARY_MODULUS;
        let mut counts = BoundaryCounts::new();
        for _ in 0..K_MAX {
            counts.record(only);
        }
        assert_eq!(
            draw_anchor_boundary_bounded(act, funding, most_recent, &counts, &mut r),
            None
        );
    }

    #[test]
    fn group_by_boundary_counts_cohorts() {
        let counts = group_by_boundary(&[144, 288, 144, 144, 288]);
        assert_eq!(counts.count(144), 3);
        assert_eq!(counts.count(288), 2);
        assert_eq!(counts.count(432), 0);
        assert_eq!(counts.cohorts(), alloc::vec![(144, 3), (288, 2)]);
    }

    // --- schedule wiring ----------------------------------------------------------------------

    proptest! {
        /// [`schedule`] pairs each broadcast height with its canonical expiry.
        #[test]
        fn schedule_pairs_broadcast_and_expiry(commit in 0u32..1_000_000,
                                               n in 0usize..24,
                                               seed in any::<u64>()) {
            let mut r = rng(seed);
            let schedules = schedule(commit, n, &mut r);
            prop_assert_eq!(schedules.len(), n);
            for s in schedules {
                prop_assert!(s.broadcast_height() >= commit);
                prop_assert_eq!(s.expiry_height(), expiry_height(s.broadcast_height()));
            }
        }
    }
}
