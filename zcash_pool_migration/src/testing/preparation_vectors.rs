//! Fixed preparation instances, shared by every [`PreparationStrategy`] implementation.
//!
//! A strategy is only comparable against another if both are measured on the same inputs, so the
//! instances live here rather than in any one strategy's tests. The table holds the INSTANCES and
//! how each one constrains a correct strategy; the plan shape a particular rule produces (its
//! layers, transactions and residual notes) belongs with that rule's own tests, because a better
//! rule legitimately produces different numbers.
//!
//! [`PreparationStrategy`]: crate::preparation::PreparationStrategy

use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
use zcash_protocol::value::{COIN, Zatoshis};

use crate::preparation::PREP_TX_ACTIONS;

use alloc::vec::Vec;

/// The ZIP-317 fee of one padded [`PREP_TX_ACTIONS`]-action preparation transaction: what the
/// planner reserves per transaction. Every vector below is sized against this.
pub fn preparation_fee_per_tx() -> Zatoshis {
    Zatoshis::const_from_u64(PREP_TX_ACTIONS as u64 * MARGINAL_FEE.into_u64())
}

/// Wrap raw zatoshi values as [`Zatoshis`], so a fixture table can stay in the readable u64 domain.
pub fn zats(values: &[u64]) -> Vec<Zatoshis> {
    values
        .iter()
        .map(|&v| Zatoshis::from_u64(v).expect("fixture values are valid amounts"))
        .collect()
}

/// What a preparation instance requires of a correct strategy.
///
/// The middle case is the one that carries information: an instance whose value is amply present
/// but whose funding notes can only be minted by transaction shapes some strategies do not build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fundability {
    /// Every correct strategy must produce a plan: the value is present and one transaction shape
    /// no strategy can lack suffices.
    Always,
    /// No strategy can produce a plan: the value is not there.
    Never,
    /// Whether a strategy produces a plan depends on which transaction shapes it can build, so
    /// both outcomes conform. A strategy that DOES plan here is strictly better than one that does
    /// not.
    Depends,
}

/// One preparation instance: the wallet's spendable notes, the funding notes to mint from them,
/// and what that instance requires of a strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationVector {
    /// A short description, used in assertion messages.
    pub label: &'static str,
    /// The wallet's spendable source-pool note values, in zatoshi.
    pub available: &'static [u64],
    /// The self-funding note values to mint, in zatoshi.
    pub funding: &'static [u64],
    /// What this instance requires of a correct strategy.
    pub fundability: Fundability,
}

// The canonical funding notes for a 9.99 ZEC migratable balance: the ZIP 318 split
// `5, 2, 2, 0.5, 0.2, 0.2, 0.05, 0.02, 0.02` with the per-note transfer buffer added to each.
const BUFFER: u64 = 15_000;
const F5: u64 = 5 * COIN + BUFFER;
const F2: u64 = 2 * COIN + BUFFER;
const F0_5: u64 = COIN / 2 + BUFFER;
const F0_2: u64 = COIN / 5 + BUFFER;
const F0_05: u64 = COIN / 20 + BUFFER;
const F0_02: u64 = COIN / 50 + BUFFER;

/// The canonical 10 ZEC funding set every note-shape vector below asks for.
const TEN_ZEC_CANONICAL: &[u64] = &[F5, F2, F2, F0_5, F0_2, F0_2, F0_05, F0_02, F0_02];

/// The shared preparation corpus.
///
/// The four `10 ZEC as ...` rows are the note-shape family: one balance, one funding set, four
/// ways of holding the notes. Only the single-note row is [`Fundability::Always`]; the rest need a
/// transaction that both spends several notes and produces several, which is exactly the shape a
/// strategy may or may not build.
pub const PREPARATION_VECTORS: &[PreparationVector] = {
    const fn v(
        label: &'static str,
        available: &'static [u64],
        funding: &'static [u64],
        fundability: Fundability,
    ) -> PreparationVector {
        PreparationVector {
            label,
            available,
            funding,
            fundability,
        }
    }
    &[
        // Nothing to do.
        v("no funding requested", &[COIN], &[], Fundability::Always),
        v("no notes to spend", &[], &[100_000], Fundability::Never),
        // One note, enough value: a single splitting transaction suffices.
        v(
            "one note funds one",
            &[1_000_000],
            &[100_000],
            Fundability::Always,
        ),
        v(
            "one note funds several",
            &[1_000_000],
            &[100_000, 100_000, 50_000],
            Fundability::Always,
        ),
        v(
            "one note funds the 10 ZEC canonical set",
            &[10 * COIN],
            TEN_ZEC_CANONICAL,
            Fundability::Always,
        ),
        // A note already worth a funding value is that funding note, with no transaction at all.
        v(
            "a note exactly equals its funding value",
            &[100_000],
            &[100_000],
            Fundability::Always,
        ),
        // Value amply present but spread across notes: the note-shape family.
        v(
            "10 ZEC as 1 + 9",
            &[COIN, 9 * COIN],
            TEN_ZEC_CANONICAL,
            Fundability::Depends,
        ),
        v(
            "10 ZEC as 2 + 8",
            &[2 * COIN, 8 * COIN],
            TEN_ZEC_CANONICAL,
            Fundability::Depends,
        ),
        v(
            "10 ZEC as 5 + 5",
            &[5 * COIN, 5 * COIN],
            TEN_ZEC_CANONICAL,
            Fundability::Depends,
        ),
        // Many equal notes, none individually able to fund the largest part.
        v(
            "ten equal notes",
            &[500_000; 10],
            &[100_000, 100_000, 50_000],
            Fundability::Depends,
        ),
        // Notes too small to fund anything alone must be consolidated first: one transaction to
        // merge them and one to split the merged note, so two fees before any funding note exists.
        v(
            "twelve sub-quantum notes",
            &[20_000; 12],
            &[50_000],
            Fundability::Depends,
        ),
        // The same shape one fee short of affording that consolidation.
        v(
            "sub-quantum notes that cannot pay for their own consolidation",
            &[10_000; 12],
            &[50_000],
            Fundability::Never,
        ),
        // The value simply is not there.
        v(
            "one note short of the fee",
            &[100_000],
            &[100_000, 100_000],
            Fundability::Never,
        ),
        v(
            "many notes, all sub-fee",
            &[100; 20],
            &[100_000],
            Fundability::Never,
        ),
    ]
};
