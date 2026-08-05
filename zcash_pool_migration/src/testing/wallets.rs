//! Generators for MESSY source-note sets: the wallet shapes that stress note preparation.
//!
//! The scenarios in [`scenarios`](super::scenarios) are hand-written note shapes with hand-checked
//! outcomes, which is the right tool for pinning a specific plan. They are the wrong tool for asking
//! how the preparation planner BEHAVES on the wallets that actually hurt it: hundreds or thousands
//! of notes, most of them below the minimum denomination, accumulated over years of change outputs
//! and mining payouts. Those cannot be written out by hand, and their exact plans are not
//! interesting individually; what matters is how the cost SCALES.
//!
//! So this module generates them. A [`WalletShape`] names a value distribution,
//! [`generate_notes`] draws `note_count` notes from it, and the caller plans a migration over the
//! result. Generation is deterministic in the RNG, so a seed reproduces a case exactly.
//!
//! The distributions are anchored on the protocol's own denomination bounds rather than invented
//! magnitudes: [`MIN_DENOMINATION`] is the smallest value a crossing may carry, and a note below it
//! is SUB-QUANTUM (too small to fund a crossing on its own, so it can only reach the migration by
//! being consolidated with others). Sub-quantum notes are what force consolidation layers, and
//! consolidation is what makes a large-note-count plan expensive.

use alloc::vec::Vec;

use rand_core::RngCore;

use zcash_protocol::value::COIN;

/// The minimum denomination, in zatoshi: a note worth less than this is SUB-QUANTUM and cannot fund
/// a crossing on its own.
///
/// This is [`MAX_RESIDUAL_VALUE`](zcash_protocol::zip318::MAX_RESIDUAL_VALUE) as a plain `u64`,
/// spelled out because `Zatoshis::into_u64` is not `const`; `min_denomination_matches_the_protocol`
/// pins the two together.
pub const MIN_DENOMINATION: u64 = COIN / 100;

/// The largest note any generated wallet holds, in zatoshi: the largest value a single crossing may
/// carry, so no generated note is unrepresentable as one denomination.
///
/// This is [`DENOM_CAP`](zcash_protocol::zip318::DENOM_CAP) as a plain `u64`, for the same reason as
/// [`MIN_DENOMINATION`].
pub const MAX_GENERATED_NOTE: u64 = 10_000 * COIN;

/// The value distribution a generated wallet's notes follow. Each is a shape a real wallet reaches,
/// chosen for what it does to PREPARATION rather than for realism alone.
///
/// Every shape draws ARBITRARY zatoshi amounts. A real wallet's notes are change outputs, payments
/// received, and mining payouts; none of those land on a denomination boundary, so a generator that
/// emitted multiples of the minimum denomination would be testing a wallet that does not exist, and
/// would hide exactly the remainder-handling the planner has to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletShape {
    /// Log-uniform over `[1, 3] * MIN_DENOMINATION`: many notes, each just large enough to fund a
    /// crossing on its own but none a round multiple of one. Isolates the cost of the note COUNT
    /// from the cost of consolidating sub-quantum value.
    NearMinimum,
    /// Log-uniform from a tenth of the minimum denomination up to 1000 ZEC: equal weight per decade,
    /// the heavy-tailed shape a long-lived wallet accumulates. A minority of notes are sub-quantum.
    LogUniform,
    /// Four notes in five are sub-quantum, the rest ordinary. The consolidation-dominated regime:
    /// most of the note count carries almost none of the value.
    SubQuantumHeavy,
    /// A few whales carrying nearly all of the value, over a long sub-quantum tail. The shape a
    /// wallet reaches after one large receive and years of small change.
    WhaleOverDust,
}

impl WalletShape {
    /// Every shape, for a caller sweeping all of them.
    pub const ALL: &'static [WalletShape] = &[
        WalletShape::NearMinimum,
        WalletShape::LogUniform,
        WalletShape::SubQuantumHeavy,
        WalletShape::WhaleOverDust,
    ];

    /// A short label for assertion and report messages.
    pub const fn label(self) -> &'static str {
        match self {
            WalletShape::NearMinimum => "near-minimum",
            WalletShape::LogUniform => "log-uniform",
            WalletShape::SubQuantumHeavy => "sub-quantum-heavy",
            WalletShape::WhaleOverDust => "whale-over-dust",
        }
    }
}

/// Draw a value log-uniformly from `[min, max]` (equal probability per decade, so the small
/// magnitudes are not swamped by the large ones the way a uniform draw would swamp them).
fn log_uniform<R>(rng: &mut R, min: u64, max: u64) -> u64
where
    R: RngCore,
{
    debug_assert!(0 < min && min <= max);
    // Work in the log domain over a fixed-point fraction of the span, so no float RNG is needed.
    let ln_min = libm::log(min as f64);
    let ln_max = libm::log(max as f64);
    // 53 bits keeps the fraction exact in an f64.
    const FRACTION_BITS: u32 = 53;
    let fraction =
        (rng.next_u64() >> (u64::BITS - FRACTION_BITS)) as f64 / (1u64 << FRACTION_BITS) as f64;
    let value = libm::exp(ln_min + (ln_max - ln_min) * fraction) as u64;
    value.clamp(min, max)
}

/// Generate `note_count` source-note values (in zatoshi) drawn from `shape`.
///
/// The balance is whatever the draws sum to; that is deliberate, because a real wallet's balance is
/// a consequence of its note history rather than a target. Every note is at least
/// `MIN_DENOMINATION / 100`, so nothing generated is below the fee floor by construction, and no
/// note exceeds [`MAX_GENERATED_NOTE`].
pub fn generate_notes<R>(shape: WalletShape, note_count: usize, rng: &mut R) -> Vec<u64>
where
    R: RngCore,
{
    // The floor on any generated note: well below the minimum denomination (so sub-quantum notes are
    // genuinely sub-quantum) but comfortably above a transaction fee, so no note is unspendable
    // dust that the planner would simply abandon.
    const NOTE_FLOOR: u64 = MIN_DENOMINATION / 100;
    // The ceiling on an "ordinary" (non-whale) note.
    const ORDINARY_CEILING: u64 = 1_000 * COIN;
    // The floor on a whale note.
    const WHALE_FLOOR: u64 = 100 * COIN;
    // In the whale shape, one note in this many is a whale.
    const WHALE_PERIOD: usize = 200;
    // In the sub-quantum-heavy shape, this many notes in five are sub-quantum.
    const SUB_QUANTUM_IN_FIVE: usize = 4;
    // The ceiling on a `NearMinimum` note: a small multiple of the minimum denomination, so the
    // notes cluster just above the quantum without ever landing on it.
    const NEAR_MINIMUM_CEILING: u64 = 3 * MIN_DENOMINATION;

    (0..note_count)
        .map(|i| match shape {
            WalletShape::NearMinimum => log_uniform(rng, MIN_DENOMINATION, NEAR_MINIMUM_CEILING),
            WalletShape::LogUniform => log_uniform(rng, MIN_DENOMINATION / 10, ORDINARY_CEILING),
            WalletShape::SubQuantumHeavy => {
                if i % 5 < SUB_QUANTUM_IN_FIVE {
                    log_uniform(rng, NOTE_FLOOR, MIN_DENOMINATION - 1)
                } else {
                    log_uniform(rng, MIN_DENOMINATION, ORDINARY_CEILING)
                }
            }
            WalletShape::WhaleOverDust => {
                if i % WHALE_PERIOD == 0 {
                    log_uniform(rng, WHALE_FLOOR, MAX_GENERATED_NOTE)
                } else {
                    log_uniform(rng, NOTE_FLOOR, MIN_DENOMINATION - 1)
                }
            }
        })
        .collect()
}

/// How many of `notes` are SUB-QUANTUM (below [`MIN_DENOMINATION`], so unable to fund a crossing on
/// their own and reachable only through consolidation).
pub fn sub_quantum_count(notes: &[u64]) -> usize {
    notes.iter().filter(|&&v| v < MIN_DENOMINATION).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::zip318::{DENOM_CAP, MAX_RESIDUAL_VALUE};

    /// The spelled-out bounds track the protocol constants they stand in for.
    #[test]
    fn min_denomination_matches_the_protocol() {
        assert_eq!(MIN_DENOMINATION, MAX_RESIDUAL_VALUE.into_u64());
        assert_eq!(MAX_GENERATED_NOTE, DENOM_CAP.into_u64());
    }

    /// Every shape generates the requested count, within the documented bounds, and reproduces
    /// exactly from a seed.
    #[test]
    fn generation_is_bounded_and_reproducible() {
        for &shape in WalletShape::ALL {
            let notes = generate_notes(shape, 500, &mut ChaCha8Rng::seed_from_u64(11));
            assert_eq!(notes.len(), 500, "{}", shape.label());
            assert!(
                notes.iter().all(|&v| v > 0 && v <= MAX_GENERATED_NOTE),
                "{}: a note left the generated range",
                shape.label()
            );
            let again = generate_notes(shape, 500, &mut ChaCha8Rng::seed_from_u64(11));
            assert_eq!(
                notes,
                again,
                "{}: generation is seed-reproducible",
                shape.label()
            );
        }
    }

    /// Each shape actually produces the sub-quantum mix its documentation claims, so a sweep over
    /// the shapes really does span the consolidation regimes.
    #[test]
    fn shapes_have_the_documented_sub_quantum_mix() {
        let n = 1_000;
        let mix = |shape| {
            let notes = generate_notes(shape, n, &mut ChaCha8Rng::seed_from_u64(23));
            sub_quantum_count(&notes)
        };
        assert_eq!(mix(WalletShape::NearMinimum), 0);
        // Log-uniform over [min/10, 1000 ZEC] spans 6 decades, one of them sub-quantum.
        let log_uniform = mix(WalletShape::LogUniform);
        assert!(
            (1..n / 2).contains(&log_uniform),
            "log-uniform should be a sub-quantum minority, got {log_uniform}"
        );
        assert_eq!(mix(WalletShape::SubQuantumHeavy), n / 5 * 4);
        assert_eq!(mix(WalletShape::WhaleOverDust), n - n / 200);
    }
}
