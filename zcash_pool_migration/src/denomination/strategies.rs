//! The concrete [`DenominationStrategy`] implementation: the canonical `{1, 2, 5} * 10^k`
//! quantization of the Orchard -> Ironwood migration ([ZIP 318]). It decomposes a balance by taking,
//! at each step, the largest `{1, 2, 5} * 10^k` denomination the remaining budget can fund
//! (equivalently, decimal-digit expansion into `{5, 2, 1}` times each place value), working in
//! zatoshi so it mints sub-1-ZEC denominations down to a minimum denomination. See the [parent module](super)
//! for the value-collision privacy rationale.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;
use core::num::NonZeroUsize;

use rand_core::{CryptoRng, RngCore};

use zcash_protocol::value::Zatoshis;
use zcash_protocol::zip318::largest_one_two_five;

use super::{
    DENOM_CAP, DenominationPlan, DenominationStrategy, MAX_RESIDUAL_VALUE,
    MIGRATION_MAX_PREPARED_NOTES_PER_RUN, zat,
};
use crate::preparation::FUNDING_OUTPUTS_PER_TX;

/// The canonical `{1, 2, 5} * 10^k` quantization of [ZIP 318]: at each step it takes the largest such
/// denomination the remaining budget can fund (bounded by the maximum denomination), so the parts are
/// non-increasing. This is exactly the ZIP's greedy decimal-digit expansion, where each decimal digit
/// expands into `{5, 2, 1}` times its place value. It works in zatoshi, minting sub-1-ZEC
/// denominations down to the minimum denomination: 0.53 ZEC decomposes into `0.5 + 0.02 + 0.01`, 540 ZEC into
/// `500 + 20 + 20`, 123.45 ZEC into `100 + 20 + 2 + 1 + 0.2 + 0.2 + 0.05`, and 25,000 ZEC into
/// `10,000 + 10,000 + 5,000` (a balance above the cap emits multiple cap-sized parts). The
/// decomposition is a pure function of the balance; the `rng` argument is ignored.
///
/// Every crossing value is a canonical denomination shared across wallets, so privacy rests on value
/// collision rather than on unpredictability (see [ZIP 318]).
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub struct CanonicalOneTwoFive {
    max_notes: usize,
    max_denomination_zatoshi: u64,
    min_denomination_zatoshi: u64,
    buffer_zatoshi: u64,
}

impl CanonicalOneTwoFive {
    /// A strategy with an explicit note cap, maximum denomination, minimum denomination (which MUST
    /// be a power of ten), and per-note transfer-fee buffer (the ZIP-317 fee of the canonical
    /// transfer shape, computed by the caller).
    pub fn new(
        max_notes: usize,
        max_denomination: Zatoshis,
        min_denomination: Zatoshis,
        transfer_fee_buffer: Zatoshis,
    ) -> Self {
        Self {
            max_notes,
            max_denomination_zatoshi: u64::from(max_denomination),
            min_denomination_zatoshi: u64::from(min_denomination),
            buffer_zatoshi: u64::from(transfer_fee_buffer),
        }
    }

    /// The ZIP 318 configuration with a caller-chosen per-run note count: `max_notes` notes, the
    /// [`DENOM_CAP`] maximum denomination, the [`MAX_RESIDUAL_VALUE`] minimum denomination, and the
    /// caller-computed transfer-fee buffer.
    ///
    /// The two bounds are NOT parameters here: they are the normative ZIP 318 values that fix which
    /// denominations may cross the turnstile, and moving them would move this wallet's crossings out
    /// of the anonymity set every other wallet shares. Only the per-run note count is the caller's
    /// to choose; it bounds one run's transaction and proving cost and says nothing about which
    /// values are published.
    pub fn with_max_notes(max_notes: NonZeroUsize, transfer_fee_buffer: Zatoshis) -> Self {
        Self::new(
            max_notes.get(),
            DENOM_CAP,
            MAX_RESIDUAL_VALUE,
            transfer_fee_buffer,
        )
    }

    /// The recommended configuration: [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`] notes, the
    /// [`DENOM_CAP`] maximum denomination, the [`MAX_RESIDUAL_VALUE`] minimum denomination, and the
    /// caller-computed transfer-fee buffer.
    pub fn recommended(transfer_fee_buffer: Zatoshis) -> Self {
        Self::with_max_notes(MIGRATION_MAX_PREPARED_NOTES_PER_RUN, transfer_fee_buffer)
    }
}

impl CanonicalOneTwoFive {
    /// The UNCONSTRAINED canonical split of `total_input_zatoshi`: the non-increasing sequence of
    /// crossing values the balance quantizes into, a function of the balance (and this strategy's
    /// bounds) plus exactly one bit of the wallet's note structure — whether a single note holds
    /// the whole balance — and nothing else about how the notes hold it.
    ///
    /// Fees are reserved as the split grows, under the optimistic one-transaction-per-
    /// [`FUNDING_OUTPUTS_PER_TX`]-notes preparation model. The exception is a balance of exactly
    /// one self-funding canonical denomination held as a SINGLE note: the note necessarily equals
    /// the balance, so it is certain to fund the crossing directly with no preparation transaction,
    /// and the fee reserve is safely omitted. The count gates that exception rather than merely
    /// informing it: with two or more notes none can equal that funding value, preparation — and
    /// its fee — is inevitable, and omitting the reserve would leave the split unfundable by every
    /// wallet holding the balance. The count participates ONLY through this
    /// `spendable_note_count == 1` predicate; the published values otherwise remain a function of
    /// the balance alone.
    pub(crate) fn unconstrained_split(
        &self,
        total_input_zatoshi: u64,
        spendable_note_count: usize,
        prep_tx_fee_zatoshi: u64,
    ) -> Vec<u64> {
        let buffer = self.buffer_zatoshi;
        // Smallest self-funding note: the minimum denomination plus its transfer buffer.
        let min_note = self.min_denomination_zatoshi + buffer;
        let exact_crossing = total_input_zatoshi.saturating_sub(buffer);
        if spendable_note_count == 1
            && self.max_notes > 0
            && total_input_zatoshi >= buffer
            && (self.min_denomination_zatoshi..=self.max_denomination_zatoshi)
                .contains(&exact_crossing)
            && largest_one_two_five(exact_crossing, self.min_denomination_zatoshi) == exact_crossing
        {
            return alloc::vec![exact_crossing];
        }
        let optimistic_txs = |minted: usize| minted.div_ceil(FUNDING_OUTPUTS_PER_TX) as u64;

        let mut crossings: Vec<u64> = Vec::new();
        // Running sum of the prepared-note values (`crossing + buffer`) chosen so far.
        let mut committed_notes = 0u64;
        while crossings.len() < self.max_notes {
            let committed = committed_notes + optimistic_txs(crossings.len()) * prep_tx_fee_zatoshi;
            let budget = total_input_zatoshi.saturating_sub(committed);
            if budget < min_note {
                break;
            }
            let mut affordable = (budget - buffer).min(self.max_denomination_zatoshi);
            let mut accepted = false;
            while affordable >= self.min_denomination_zatoshi {
                let crossing = largest_one_two_five(affordable, self.min_denomination_zatoshi);
                if crossing < self.min_denomination_zatoshi {
                    break;
                }
                let cost = committed_notes
                    + crossing
                    + buffer
                    + optimistic_txs(crossings.len() + 1) * prep_tx_fee_zatoshi;
                if cost <= total_input_zatoshi {
                    committed_notes += crossing + buffer;
                    crossings.push(crossing);
                    accepted = true;
                    break;
                }
                affordable = crossing - 1;
            }
            if !accepted {
                break;
            }
        }
        crossings
    }
}

impl DenominationStrategy for CanonicalOneTwoFive {
    fn plan<R: RngCore + CryptoRng>(
        &self,
        total_input: Zatoshis,
        spendable_note_count: usize,
        prep_tx_fee: Zatoshis,
        prep_tx_count: &dyn Fn(&[Zatoshis]) -> Option<usize>,
        _rng: &mut R,
    ) -> DenominationPlan {
        // The partition arithmetic below runs in the u64 domain; every value it derives is bounded
        // by the validated total input, so `zat` conversions at the capability boundary and in
        // `from_notes` are infallible.
        let total_input_zatoshi = u64::from(total_input);
        let prep_tx_fee_zatoshi = u64::from(prep_tx_fee);
        let buffer = self.buffer_zatoshi;

        // QUANTIZE once: the canonical split is a function of the BALANCE alone (plus the one
        // exact-funding bit of the note count — see `unconstrained_split`), so the published
        // values can collide across wallets holding the same balance differently.
        let mut crossing_values = self.unconstrained_split(
            total_input_zatoshi,
            spendable_note_count,
            prep_tx_fee_zatoshi,
        );
        let mut notes: Vec<u64> = crossing_values.iter().map(|&c| c + buffer).collect();
        let typed = |notes: &[u64]| notes.iter().map(|&v| zat(v)).collect::<Vec<Zatoshis>>();

        // RECONCILE against the wallet: drop parts smallest-first (the split is non-increasing, so
        // from the back) until the preparation planner can mint the remainder and its true fees fit
        // the balance. Dropping is the ONLY repair — no part is ever replaced by smaller
        // denominations, so the crossing multiset stays a sub-multiset of the canonical split and
        // the note shape can only truncate what is published, never reshape it.
        let n_txs = loop {
            if crossing_values.is_empty() {
                break 0;
            }
            let fits = prep_tx_count(&typed(&notes)).filter(|&n| {
                notes
                    .iter()
                    .sum::<u64>()
                    .checked_add(n as u64 * prep_tx_fee_zatoshi)
                    .is_some_and(|c| c <= total_input_zatoshi)
            });
            match fits {
                Some(n) => break n,
                None => {
                    crossing_values.pop();
                    notes.pop();
                }
            }
        };

        let prep_fees_zatoshi = n_txs as u64 * prep_tx_fee_zatoshi;
        let remaining = total_input_zatoshi
            .saturating_sub(notes.iter().sum::<u64>())
            .saturating_sub(prep_fees_zatoshi);
        DenominationPlan::from_notes(
            total_input_zatoshi,
            prep_fees_zatoshi,
            crossing_values,
            buffer,
            remaining,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
    use zcash_protocol::value::{COIN, MAX_MONEY};

    use crate::preparation::FUNDING_OUTPUTS_PER_TX;
    use zcash_protocol::zip318::{CROSSING_DESTINATION_ACTIONS, CROSSING_SOURCE_ACTIONS};

    /// The ZIP-317 transfer-fee buffer of the canonical transfer shape (all four actions exceed the
    /// grace allowance, so each pays the marginal fee).
    fn zip317_buffer() -> u64 {
        (CROSSING_SOURCE_ACTIONS + CROSSING_DESTINATION_ACTIONS) as u64 * MARGINAL_FEE.into_u64()
    }

    /// A count-only preparation-layout stub: one padded transaction per [`FUNDING_OUTPUTS_PER_TX`]
    /// funding notes. Tests exercising the split in isolation use this in place of the real
    /// preparation planner.
    fn prep_tx_count_stub(notes: &[Zatoshis]) -> Option<usize> {
        Some(notes.len().div_ceil(FUNDING_OUTPUTS_PER_TX))
    }

    /// A generic multi-note wallet count for tests that model no concrete wallet: any count
    /// above one keeps the optimistic fee reserve in place (the exact-funding special case
    /// requires a lone note).
    const MULTI_NOTE: usize = 2;

    /// Read a plan's crossing values back into the tests' u64 domain.
    fn crossings_u64(p: &DenominationPlan) -> Vec<u64> {
        p.crossing_values().iter().map(|&v| u64::from(v)).collect()
    }

    /// Upper bound on the prep fee sampled by [`arb_plan_input`], in zatoshi.
    const MAX_SAMPLED_PREP_FEE_ZATOSHI: u64 = 1_000_000;
    /// Upper bound on the note cap sampled by [`arb_plan_input`].
    const MAX_SAMPLED_NOTE_CAP: usize = 64;

    /// A plan input: a spendable balance anywhere in `[0, MAX_MONEY]`, a small prep fee, and a note
    /// cap. The balance is drawn from the whole range so arbitrary (not round) zatoshi amounts are
    /// exercised.
    fn arb_plan_input() -> impl Strategy<Value = (u64, u64, usize)> {
        (
            0u64..=MAX_MONEY,
            0u64..MAX_SAMPLED_PREP_FEE_ZATOSHI,
            1usize..=MAX_SAMPLED_NOTE_CAP,
        )
    }

    /// A spendable-note count: one (the exact-funding special case `unconstrained_split` gates on)
    /// or more (the general fee-reserving path).
    fn arb_note_count() -> impl Strategy<Value = usize> {
        1usize..=4
    }

    /// One balance and preparation fee, held as some note count, asked of TWO independently drawn
    /// note caps: the input shape of the cap-invariance law.
    fn arb_two_caps_over_one_balance() -> impl Strategy<Value = (u64, u64, usize, usize, usize)> {
        (
            arb_plan_input(),
            1usize..=MAX_SAMPLED_NOTE_CAP,
            arb_note_count(),
        )
            .prop_map(|((total, fee, cap_a), cap_b, note_count)| {
                (total, fee, cap_a, cap_b, note_count)
            })
    }

    /// The canonical strategy with the given note cap and the ZIP-317 transfer buffer.
    fn canonical(max_notes: usize) -> CanonicalOneTwoFive {
        CanonicalOneTwoFive::new(
            max_notes,
            DENOM_CAP,
            MAX_RESIDUAL_VALUE,
            zat(zip317_buffer()),
        )
    }

    /// The exact fee-free crossing decomposition of `total` (no buffer, no preparation fee), for
    /// the golden vectors.
    fn crossings(total: u64) -> Vec<u64> {
        let s = CanonicalOneTwoFive::new(64, DENOM_CAP, MAX_RESIDUAL_VALUE, Zatoshis::ZERO);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        crossings_u64(&s.plan(
            zat(total),
            MULTI_NOTE,
            Zatoshis::ZERO,
            &prep_tx_count_stub,
            &mut rng,
        ))
    }

    proptest! {
        /// The trait contract, over the whole input range: value is conserved, each note is its
        /// crossing plus the buffer, the note cap holds, the migratable total is the crossing sum,
        /// every crossing is a valid, non-increasing `{1, 2, 5} * 10^k` denomination within bounds,
        /// the residual is small unless the cap was reached, and the plan ignores the RNG.
        #[test]
        fn honours_the_contract((total, fee, max_notes) in arb_plan_input()) {
            let s = canonical(max_notes);
            let buffer = zip317_buffer();
            let floor = u64::from(MAX_RESIDUAL_VALUE);
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            let p = s.plan(zat(total), MULTI_NOTE, zat(fee), &prep_tx_count_stub, &mut rng);

            // Value is conserved exactly: the prepared notes, the stepwise-reserved preparation
            // fees, and the change partition the balance; and the reserved fees are the per-tx fee
            // times the layout's transaction count (zero when nothing migrates).
            let outputs = p.migration_outputs();
            let notes: u64 = outputs.iter().map(|&v| u64::from(v)).sum();
            let change = p.change().map(u64::from).unwrap_or(0);
            let prep_fees = u64::from(p.prep_fees());
            prop_assert_eq!(notes + prep_fees + change, total);
            if outputs.is_empty() {
                prop_assert_eq!(prep_fees, 0);
            } else {
                let expected_txs = prep_tx_count_stub(&outputs).unwrap();
                prop_assert_eq!(prep_fees, expected_txs as u64 * fee);
            }

            let cvs = crossings_u64(&p);
            prop_assert_eq!(outputs.len(), cvs.len());
            for (&n, &c) in outputs.iter().zip(&cvs) {
                prop_assert_eq!(u64::from(n), c + buffer);
            }
            prop_assert!(outputs.len() <= max_notes);
            let sum: u64 = cvs.iter().sum();
            prop_assert_eq!(u64::from(p.total_migratable()), sum);

            for &cv in &cvs {
                // One assertion, not two: being a canonical ZIP 318 denomination is exactly being
                // on the `{1, 2, 5} * 10^k` series AND within the specified bounds.
                prop_assert!(
                    zcash_protocol::zip318::is_canonical_denomination(zat(cv)),
                    "not a canonical denomination: {}",
                    cv
                );
            }
            for w in cvs.windows(2) {
                prop_assert!(w[0] >= w[1], "crossings must be non-increasing");
            }
            if outputs.len() < max_notes {
                // The loop stops when not even a minimum note fits — where fitting includes any
                // preparation-fee step the extra note would trigger.
                prop_assert!(change < floor + buffer + fee, "residual {}", change);
            }

            // The RNG is ignored: a different seed yields the same plan.
            let mut other = ChaCha8Rng::seed_from_u64(1);
            prop_assert_eq!(&p, &s.plan(zat(total), MULTI_NOTE, zat(fee), &prep_tx_count_stub, &mut other));
        }

        /// WHETHER a balance quantizes to anything at all is invariant across note caps: the split
        /// is empty under one positive cap exactly when it is empty under every other. The first
        /// part forms (or does not) from the balance, the transfer buffer and the preparation fee
        /// alone, and every positive cap admits that first part, so only the LENGTH of the split
        /// depends on the cap, never its emptiness.
        ///
        /// This is the lemma
        /// [`balance_has_canonical_split`](super::super::balance_has_canonical_split) rests on when
        /// it distinguishes "this balance has nothing to migrate" from "this wallet's note values
        /// cannot fund what the balance quantizes to": that verdict must not turn on the caller's
        /// per-run note count.
        #[test]
        fn split_emptiness_is_cap_invariant(
            (total, fee, cap_a, cap_b, note_count) in arb_two_caps_over_one_balance(),
        ) {
            let a = canonical(cap_a).unconstrained_split(total, note_count, fee);
            let b = canonical(cap_b).unconstrained_split(total, note_count, fee);
            prop_assert_eq!(
                a.is_empty(),
                b.is_empty(),
                "caps {} and {} disagree on emptiness for balance {}",
                cap_a,
                cap_b,
                total
            );
        }
    }

    /// A whale's balance is split into capped notes, so one run migrates at most `max_notes * cap`
    /// and the rest rolls over as change.
    #[test]
    fn whale_is_capped_and_rolls_over() {
        let s = canonical(MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get());
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let p = s.plan(
            zat(MAX_MONEY),
            MULTI_NOTE,
            Zatoshis::ZERO,
            &prep_tx_count_stub,
            &mut rng,
        );
        let per_run_cap = MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get() as u64 * u64::from(DENOM_CAP);
        assert!(u64::from(p.total_migratable()) <= per_run_cap);
        assert!(
            p.change().map(u64::from).unwrap_or(0) > per_run_cap,
            "should roll over"
        );
    }

    /// A balance below the smallest self-funding note migrates nothing and keeps it all as change.
    #[test]
    fn below_min_note_migrates_nothing() {
        let s = canonical(MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get());
        let buffer = zip317_buffer();
        let below = u64::from(MAX_RESIDUAL_VALUE) + buffer - 1;
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let p = s.plan(
            zat(below),
            MULTI_NOTE,
            Zatoshis::ZERO,
            &prep_tx_count_stub,
            &mut rng,
        );
        assert!(p.crossing_values().is_empty());
        assert_eq!(p.change(), Some(zat(below)));
    }

    /// The largest reserved preparation fee the single-quantum tests sample. Kept below the smallest
    /// gap between adjacent denominations (`MAX_RESIDUAL_VALUE`, the 0.01 -> 0.02 ZEC step) so
    /// that `quantum + fee` never rounds up to the next `{1, 2, 5} * 10^k` denomination: the plan
    /// must then pick exactly the quantum. Realistic ZIP-317 preparation fees are far smaller (a
    /// handful of marginal fees).
    const MAX_SINGLE_QUANTUM_PREP_FEE_ZATOSHI: u64 = COIN / 200; // 0.005 ZEC, half the minimum denom

    /// Every `{1, 2, 5} * 10^k` denomination (a "quantum") within the valid range
    /// `[MAX_RESIDUAL_VALUE, DENOM_CAP]`, in zatoshi. These are exactly the
    /// crossing values the strategy can emit, so a balance of one of them plus its fees is the
    /// smallest input that migrates that denomination as a single note.
    fn all_quanta() -> Vec<u64> {
        let min = u64::from(MAX_RESIDUAL_VALUE);
        let cap = u64::from(DENOM_CAP);
        let mut quanta = Vec::new();
        let mut pow = 1u64;
        while pow <= cap {
            for m in [1u64, 2, 5] {
                let q = m * pow;
                if (min..=cap).contains(&q) {
                    quanta.push(q);
                }
            }
            match pow.checked_mul(10) {
                Some(p) => pow = p,
                None => break,
            }
        }
        quanta
    }

    /// A single `{1, 2, 5} * 10^k` denomination drawn from [`all_quanta`].
    fn arb_quantum() -> impl Strategy<Value = u64> {
        prop::sample::select(all_quanta())
    }

    /// A balance of exactly one `quantum` plus its fees (the ZIP-317 transfer buffer that funds the
    /// crossing note, and one reserved preparation-transaction fee) is the smallest input that
    /// migrates that denomination: the plan is a single crossing note of exactly `quantum`, reserves
    /// exactly one preparation fee, and leaves no change.
    fn assert_one_quantum_plus_fees(quantum: u64, prep_fee: u64) {
        let buffer = zip317_buffer();
        let balance = quantum + buffer + prep_fee;
        let s = canonical(MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get());
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let p = s.plan(
            zat(balance),
            MULTI_NOTE,
            zat(prep_fee),
            &prep_tx_count_stub,
            &mut rng,
        );

        assert_eq!(
            crossings_u64(&p),
            vec![quantum],
            "quantum {quantum}, prep fee {prep_fee}",
        );
        assert_eq!(
            p.migration_outputs()
                .iter()
                .map(|&v| u64::from(v))
                .collect::<Vec<u64>>(),
            vec![quantum + buffer],
            "quantum {quantum}, prep fee {prep_fee}",
        );
        assert_eq!(
            u64::from(p.total_migratable()),
            quantum,
            "quantum {quantum}, prep fee {prep_fee}",
        );
        // One prepared note is one padded preparation transaction, so exactly one fee is reserved.
        assert_eq!(
            u64::from(p.prep_fees()),
            prep_fee,
            "quantum {quantum}, prep fee {prep_fee}",
        );
        assert_eq!(p.change(), None, "quantum {quantum}, prep fee {prep_fee}");
    }

    /// A balance of exactly one quantum plus fees migrates that quantum as a single note, across a
    /// few example denominations spanning the `{1, 2, 5} * 10^k` series from the 0.01 ZEC minimum to
    /// the 10,000 ZEC cap.
    #[test]
    fn single_quantum_plus_fees_migrates_exactly_one_note() {
        // A realistic reserved preparation fee: the ZIP-317 marginal fee for a few actions.
        let prep_fee = 3 * MARGINAL_FEE.into_u64();
        let examples = [
            u64::from(MAX_RESIDUAL_VALUE), // 0.01 ZEC, the minimum denomination
            COIN / 50,                     // 0.02 ZEC
            COIN / 20,                     // 0.05 ZEC
            COIN / 10,                     // 0.1 ZEC
            COIN,                          // 1 ZEC
            2 * COIN,                      // 2 ZEC
            5 * COIN,                      // 5 ZEC
            100 * COIN,                    // 100 ZEC
            u64::from(DENOM_CAP),          // 10,000 ZEC, the cap
        ];
        for quantum in examples {
            assert_one_quantum_plus_fees(quantum, prep_fee);
        }
    }

    /// An exact funding note is used directly, so it does not need the preparation fee that the
    /// balance-only quantizer cannot know whether to reserve.
    #[test]
    fn exact_funding_note_needs_no_preparation_fee() {
        let buffer = zip317_buffer();
        let crossing = u64::from(MAX_RESIDUAL_VALUE);
        let funding = crossing + buffer;
        let available = [zat(funding)];
        let prep_fee = 16 * MARGINAL_FEE.into_u64();
        let prep_tx_count = |wanted: &[Zatoshis]| {
            crate::preparation::plan_preparation(&available, wanted, zat(prep_fee))
                .ok()
                .map(|plan| plan.transaction_count())
        };
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let plan = canonical(MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get()).plan(
            zat(funding),
            available.len(),
            zat(prep_fee),
            &prep_tx_count,
            &mut rng,
        );

        assert_eq!(crossings_u64(&plan), vec![crossing]);
        assert_eq!(plan.migration_outputs(), vec![zat(funding)]);
        assert_eq!(plan.prep_fees(), Zatoshis::ZERO);
        assert_eq!(plan.change(), None);
    }

    proptest! {
        /// For any valid `{1, 2, 5} * 10^k` quantum and any realistic reserved preparation fee, a
        /// balance of exactly that quantum plus its fees migrates it as a single note with no change.
        #[test]
        fn single_quantum_plus_fees_is_one_note(
            quantum in arb_quantum(),
            prep_fee in 0u64..=MAX_SINGLE_QUANTUM_PREP_FEE_ZATOSHI,
        ) {
            assert_one_quantum_plus_fees(quantum, prep_fee);
        }
    }

    /// The ZIP 318 worked examples: canonical `{1, 2, 5} * 10^k` quantization.
    #[test]
    fn matches_the_zip_worked_examples() {
        // 540 -> [500, 20, 20].
        assert_eq!(
            crossings(540 * COIN),
            vec![500 * COIN, 20 * COIN, 20 * COIN]
        );
        // 123.45 -> [100, 20, 2, 1, 0.2, 0.2, 0.05].
        assert_eq!(
            crossings(12_345 * (COIN / 100)),
            vec![
                100 * COIN,
                20 * COIN,
                2 * COIN,
                COIN,
                COIN / 5,
                COIN / 5,
                COIN / 20
            ]
        );
        // 25000 -> [10000, 10000, 5000]: above the cap emits multiple cap-sized parts.
        assert_eq!(
            crossings(25_000 * COIN),
            vec![10_000 * COIN, 10_000 * COIN, 5_000 * COIN]
        );
    }

    /// A larger balance across the full 1-2-5 series, and a sub-1-ZEC balance down to the minimum denomination.
    #[test]
    fn expands_large_and_sub_one_zec() {
        let zec: Vec<u64> = crossings(12_345 * COIN).iter().map(|&c| c / COIN).collect();
        assert_eq!(zec, vec![10_000, 2_000, 200, 100, 20, 20, 5]);
        // 0.53 -> [0.5, 0.02, 0.01].
        assert_eq!(
            crossings(53 * (COIN / 100)),
            vec![COIN / 2, COIN / 50, COIN / 100]
        );
    }

    /// Each note is capped at the maximum denomination: 45,000 ZEC = four 10,000 (the cap) plus 5,000.
    #[test]
    fn caps_each_note_at_the_maximum_denomination() {
        let zec: Vec<u64> = crossings(45_000 * COIN).iter().map(|&c| c / COIN).collect();
        assert_eq!(zec, vec![10_000, 10_000, 10_000, 10_000, 5_000]);
    }

    /// Plans a real migration preparation for one user's `balance_zatoshi` with the recommended
    /// ZIP-317-fee strategy (no reserved prep fee), and asserts the WHOLE planned transaction set,
    /// not just the crossing quantization:
    ///
    /// - the crossing values (what an observer sees cross the turnstile),
    /// - the prepared self-funding notes actually created in the source pool, each
    ///   `crossing + transfer buffer` (the output that funds one migration-transfer transaction),
    /// - the source-pool change left behind.
    ///
    /// The transfer buffer is the canonical ZIP-317 transfer fee, so this exercises the fee model the
    /// fee-free [`crossings`] helper deliberately skips.
    fn check_user_preparation(
        balance_zatoshi: u64,
        expected_crossings_zatoshi: &[u64],
        expected_change_zatoshi: Option<u64>,
    ) {
        let buffer = zip317_buffer();
        let expected_notes: Vec<u64> = expected_crossings_zatoshi
            .iter()
            .map(|&c| c + buffer)
            .collect();
        let s = CanonicalOneTwoFive::recommended(zat(zip317_buffer()));
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let plan = s.plan(
            zat(balance_zatoshi),
            MULTI_NOTE,
            Zatoshis::ZERO,
            &prep_tx_count_stub,
            &mut rng,
        );
        assert_eq!(
            crossings_u64(&plan),
            expected_crossings_zatoshi,
            "unexpected crossings for balance {balance_zatoshi} zat",
        );
        assert_eq!(
            plan.migration_outputs()
                .iter()
                .map(|&v| u64::from(v))
                .collect::<Vec<u64>>(),
            expected_notes,
            "unexpected prepared notes for balance {balance_zatoshi} zat",
        );
        assert_eq!(
            plan.change().map(u64::from),
            expected_change_zatoshi,
            "unexpected change for balance {balance_zatoshi} zat",
        );
    }

    /// Golden vectors for the full migration preparation (the planned transaction set, fees included)
    /// of many different users' messy, non-round balances. Each note the plan creates is a real
    /// transaction output holding `crossing + transfer buffer` (15,000 zat under ZIP-317: two
    /// Orchard actions plus the single unpadded Ironwood action), and the leftover that cannot form
    /// a whole self-funding note stays as source-pool change.
    ///
    /// Every expected split is derived BY HAND from the canonical `{1, 2, 5} * 10^k` greedy rule
    /// (digit expansion: 1->[1], 2->[2], 3->[2,1], 4->[2,2], 5->[5], 6->[5,1], 7->[5,2], 8->[5,2,1],
    /// 9->[5,2,2] times each place value; balances above the 10,000 ZEC cap emit multiple cap-sized
    /// parts). For the first group each balance is exactly `sum(crossings) + notes * buffer + change`,
    /// so every crossing self-funds and the residual is the stated change; the last two are
    /// independently chosen balances that exercise the fee model draining the smallest notes.
    #[test]
    fn messy_multi_user_preparations() {
        // `(balance in zatoshi, expected crossings in zatoshi, expected source-pool change)`.
        let cases: Vec<(u64, Vec<u64>, Option<u64>)> = vec![
            // Ari, 3748.6174 ZEC: 3->[2,1] 7->[5,2] 4->[2,2] 8->[5,2,1] .6->[.5,.1] .01->[.01],
            // 12 notes + 0.0056 ZEC sub-floor change (0.0174 - 12 * 0.00015 buffers - 0.01).
            (
                374_861_740_000,
                vec![
                    2_000 * COIN,
                    1_000 * COIN,
                    500 * COIN,
                    200 * COIN,
                    20 * COIN,
                    20 * COIN,
                    5 * COIN,
                    2 * COIN,
                    COIN,
                    COIN / 2,
                    COIN / 10,
                    COIN / 100,
                ],
                Some(560_000),
            ),
            // Bo, 9631.8827 ZEC: 9->[5,2,2] 6->[5,1] 3->[2,1] 1->[1] .8->[.5,.2,.1] .07->[.05,.02];
            // the residual 0.0127 less 13 buffers (0.00195) still affords a 14th self-funding 0.01
            // note, leaving 0.0006 ZEC sub-floor change.
            (
                963_188_270_000,
                vec![
                    5_000 * COIN,
                    2_000 * COIN,
                    2_000 * COIN,
                    500 * COIN,
                    100 * COIN,
                    20 * COIN,
                    10 * COIN,
                    COIN,
                    COIN / 2,
                    COIN / 5,
                    COIN / 10,
                    COIN / 20,
                    COIN / 50,
                    COIN / 100,
                ],
                Some(60_000),
            ),
            // Cleo, 27853.4226 ZEC: above the cap -> two 10,000; then 7853.42 = 7->[5,2] 8->[5,2,1]
            // 5->[5] 3->[2,1] .4->[.2,.2] .02->[.02]. 13 notes + 0.00065 ZEC sub-floor change
            // (0.0026 less 13 buffers).
            (
                2_785_342_260_000,
                vec![
                    10_000 * COIN,
                    10_000 * COIN,
                    5_000 * COIN,
                    2_000 * COIN,
                    500 * COIN,
                    200 * COIN,
                    100 * COIN,
                    50 * COIN,
                    2 * COIN,
                    COIN,
                    COIN / 5,
                    COIN / 5,
                    COIN / 50,
                ],
                Some(65_000),
            ),
            // Dex, 61337.5028 ZEC: above the cap -> six 10,000; then 1337.5 = 1->[1] 3->[2,1]
            // 3->[2,1] 7->[5,2] .5->[.5]. 14 notes + 0.0007 ZEC sub-floor change (0.0028 less
            // 14 buffers).
            (
                6_133_750_280_000,
                vec![
                    10_000 * COIN,
                    10_000 * COIN,
                    10_000 * COIN,
                    10_000 * COIN,
                    10_000 * COIN,
                    10_000 * COIN,
                    1_000 * COIN,
                    200 * COIN,
                    100 * COIN,
                    20 * COIN,
                    10 * COIN,
                    5 * COIN,
                    2 * COIN,
                    COIN / 2,
                ],
                Some(70_000),
            ),
            // Evie, 0.794 ZEC: .7->[.5,.2] .9->[.05,.02,.02], 5 notes + 0.00325 ZEC sub-floor
            // change (0.004 less 5 buffers).
            (
                79_400_000,
                vec![COIN / 2, COIN / 5, COIN / 20, COIN / 50, COIN / 50],
                Some(325_000),
            ),
            // Fin, 0.381 ZEC: .3->[.2,.1] .8->[.05,.02,.01] (down to the 0.01 minimum
            // denomination), 5 notes + 0.00025 ZEC sub-floor change (0.001 less 5 buffers).
            (
                38_100_000,
                vec![COIN / 5, COIN / 10, COIN / 20, COIN / 50, COIN / 100],
                Some(25_000),
            ),
            // Gwen, 0.0152 ZEC: a single 0.01 minimum-denomination note + 0.00505 ZEC sub-floor
            // change.
            (1_520_000, vec![COIN / 100], Some(505_000)),
            // Ivan, 142.5314 ZEC (typical wallet): 1->[1] 4->[2,2] 2->[2] .5->[.5] .03->[.02,.01],
            // 7 notes + 0.00035 ZEC sub-floor change (0.0014 less 7 buffers).
            (
                14_253_140_000,
                vec![
                    100 * COIN,
                    20 * COIN,
                    20 * COIN,
                    2 * COIN,
                    COIN / 2,
                    COIN / 50,
                    COIN / 100,
                ],
                Some(35_000),
            ),
            // Jia, 76.1986 ZEC (typical wallet): 7->[5,2] 6->[5,1] .1->[.1] .09->[.05,.02,.02],
            // 8 notes + 0.0074 ZEC sub-floor change (0.0086 less 8 buffers).
            (
                7_619_860_000,
                vec![
                    50 * COIN,
                    20 * COIN,
                    5 * COIN,
                    COIN,
                    COIN / 10,
                    COIN / 20,
                    COIN / 50,
                    COIN / 50,
                ],
                Some(740_000),
            ),
            // Kai, 999.993 ZEC (every digit a 9 -> every place expands [5,2,2]): 999.99 =
            // 9->[5,2,2] 9->[5,2,2] 9->[5,2,2] .9->[.5,.2,.2] .09->[.05,.02,.02]. 15 notes +
            // 0.00075 ZEC sub-floor change (0.003 less 15 buffers).
            (
                99_999_300_000,
                vec![
                    500 * COIN,
                    200 * COIN,
                    200 * COIN,
                    50 * COIN,
                    20 * COIN,
                    20 * COIN,
                    5 * COIN,
                    2 * COIN,
                    2 * COIN,
                    COIN / 2,
                    COIN / 5,
                    COIN / 5,
                    COIN / 20,
                    COIN / 50,
                    COIN / 50,
                ],
                Some(75_000),
            ),
            // Lex, 32222.2218 ZEC: above the cap -> three 10,000; then 2222.22 (every digit a 2 ->
            // [2]): 2->[2] 2->[2] 2->[2] 2->[2] .2->[.2] .02->[.02]. 9 notes + 0.00045 ZEC
            // sub-floor change (0.0018 less 9 buffers).
            (
                3_222_222_180_000,
                vec![
                    10_000 * COIN,
                    10_000 * COIN,
                    10_000 * COIN,
                    2_000 * COIN,
                    200 * COIN,
                    20 * COIN,
                    2 * COIN,
                    COIN / 5,
                    COIN / 50,
                ],
                Some(45_000),
            ),
            // Mira, 4050.0735 ZEC (interior zero digits skipped): 4->[2,2] 0->[] 5->[5] 0->[] 0->[]
            // .07->[.05,.02], 5 notes + 0.00275 ZEC sub-floor change (0.0035 less 5 buffers).
            (
                405_007_350_000,
                vec![2_000 * COIN, 2_000 * COIN, 50 * COIN, COIN / 20, COIN / 50],
                Some(275_000),
            ),
            // Ozan, 88.884 ZEC (independently chosen): 88.88 = 8->[5,2,1] 8->[5,2,1] .8->[.5,.2,.1]
            // .08->[.05,.02,.01]. The 0.004 ZEC fee-free residual exceeds the 12 notes' buffers
            // (12 * 0.00015 = 0.0018 ZEC), so all 12 notes self-fund and 0.0022 ZEC stays as change.
            (
                8_888_400_000,
                vec![
                    50 * COIN,
                    20 * COIN,
                    10 * COIN,
                    5 * COIN,
                    2 * COIN,
                    COIN,
                    COIN / 2,
                    COIN / 5,
                    COIN / 10,
                    COIN / 20,
                    COIN / 50,
                    COIN / 100,
                ],
                Some(220_000),
            ),
            // Priya, 7.1101 ZEC (independently chosen): the fee-free split is 7->[5,2] .1->[.1]
            // .01->[.01], but only 0.0001 ZEC of residual is left for the buffers, so the 0.01
            // crossing cannot self-fund (it needs 0.01 + 0.00015 ZEC). It is dropped: the plan is
            // [5, 2, 0.1] and the unspent 0.00965 ZEC stays as change.
            (
                711_010_000,
                vec![5 * COIN, 2 * COIN, COIN / 10],
                Some(965_000),
            ),
        ];

        for (balance, crossings, change) in &cases {
            check_user_preparation(*balance, crossings, *change);
        }
    }

    proptest! {
        /// The note shape can only TRUNCATE the published split, never reshape it: against the real
        /// preparation planner, whatever the wallet's notes, the crossings are a prefix of the
        /// balance's canonical split ([`CanonicalOneTwoFive::unconstrained_split`] itself, NOT the
        /// plan under the optimistic stub: for a balance of exactly one denomination plus its
        /// buffer, the split forgoes the fee reserve so an exact note can fund it directly, and a
        /// stub that charges a fee reconciles that split away). This is the reconciliation kernel's
        /// contract — dropping from the bottom is the only repair.
        #[test]
        fn the_note_shape_only_truncates_the_canonical_split(
            notes in prop::collection::vec(1u64..2_000_000_000, 1..20),
        ) {
            let total: u64 = notes.iter().sum();
            let available: Vec<Zatoshis> = notes.iter().map(|&v| zat(v)).collect();
            let fee = 16 * MARGINAL_FEE.into_u64();
            let s = CanonicalOneTwoFive::recommended(zat(zip317_buffer()));

            let real = |funding: &[Zatoshis]| {
                crate::preparation::plan_preparation(&available, funding, zat(fee))
                    .ok()
                    .map(|plan| plan.transaction_count())
            };
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            let constrained =
                crossings_u64(&s.plan(zat(total), notes.len(), zat(fee), &real, &mut rng));
            let canonical = s.unconstrained_split(total, notes.len(), fee);

            prop_assert!(
                constrained.len() <= canonical.len()
                    && constrained == canonical[..constrained.len()],
                "crossings {:?} are not a prefix of the canonical split {:?}",
                constrained,
                canonical,
            );
        }
    }

    /// The exact-funding bit at the corner the proptest's generator cannot reach: a balance of
    /// exactly one canonical denomination plus its transfer buffer. Held as a SINGLE note, the
    /// split is that denomination with NO fee reserve, and the note is certain to fund it directly
    /// — zero preparation fees. Held any other way, no note can equal the funding value, so
    /// preparation is inevitable: the split retains its fee reserve, steps down the series, and the
    /// wallet migrates the stepped-down split in full. The note count is what keeps a balance the
    /// wallet CAN fund from quantizing into one it cannot.
    #[test]
    fn an_exact_denomination_balance_migrates_under_any_holding() {
        let buffer = zip317_buffer();
        let fee = 16 * MARGINAL_FEE.into_u64();
        let total = COIN + buffer;
        let s = CanonicalOneTwoFive::recommended(zat(buffer));
        assert_eq!(s.unconstrained_split(total, 1, fee), vec![COIN]);

        let plan_against = |notes: &[u64]| {
            let available: Vec<Zatoshis> = notes.iter().map(|&v| zat(v)).collect();
            let real = |funding: &[Zatoshis]| {
                crate::preparation::plan_preparation(&available, funding, zat(fee))
                    .ok()
                    .map(|plan| plan.transaction_count())
            };
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            s.plan(zat(total), notes.len(), zat(fee), &real, &mut rng)
        };

        // The exact note: the full canonical split, funded directly, nothing reserved.
        let exact = plan_against(&[total]);
        assert_eq!(crossings_u64(&exact), vec![COIN]);
        assert_eq!(exact.prep_fees(), Zatoshis::ZERO);

        // The same balance as two notes: the fee-reserving split, migrated in full through one
        // preparation transaction rather than deferred.
        let split = plan_against(&[60 * COIN / 100, 40 * COIN / 100 + buffer]);
        assert_eq!(crossings_u64(&split), s.unconstrained_split(total, 2, fee));
        assert!(!split.crossing_values().is_empty());
        assert_eq!(split.prep_fees(), zat(fee));
    }

    /// The cap regime: a balance whose canonical split saturates
    /// [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`] repeated [`DENOM_CAP`] parts, planned against the
    /// real preparation planner over more than 50 source notes. The published crossings are the
    /// full capped split — a prefix of the canonical split by construction — and the excess balance
    /// waits as change.
    #[test]
    fn the_cap_regime_publishes_repeated_denom_cap_parts() {
        let buffer = zip317_buffer();
        let fee = 16 * MARGINAL_FEE.into_u64();
        let cap = DENOM_CAP.into_u64();
        // 55 wallet notes of one DENOM_CAP each: none is an exact funding note (each lacks the
        // buffer), so every funding note is minted by consolidation.
        let notes: Vec<u64> = vec![cap; 55];
        let total: u64 = notes.iter().sum();
        let available: Vec<Zatoshis> = notes.iter().map(|&v| zat(v)).collect();
        let s = CanonicalOneTwoFive::recommended(zat(buffer));

        let canonical = s.unconstrained_split(total, notes.len(), fee);
        assert_eq!(
            canonical,
            vec![cap; MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get()],
            "the canonical split saturates the per-run cap with repeated DENOM_CAP parts"
        );

        let real = |funding: &[Zatoshis]| {
            crate::preparation::plan_preparation(&available, funding, zat(fee))
                .ok()
                .map(|plan| plan.transaction_count())
        };
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let plan = s.plan(zat(total), notes.len(), zat(fee), &real, &mut rng);
        assert_eq!(crossings_u64(&plan), canonical);
    }

    /// Reconciliation drops a SUFFIX when the wallet's true consolidation costs exceed the
    /// optimistic reserve: a wallet of hundreds of sub-funding notes pays its extra preparation
    /// fees by deferring the smallest parts, and what it publishes is still a nonempty strict
    /// prefix of the balance's canonical split.
    #[test]
    fn consolidation_costs_truncate_a_suffix_of_the_split() {
        let buffer = zip317_buffer();
        let fee = 16 * MARGINAL_FEE.into_u64();
        // 300 notes of the minimum denomination: each is below the smallest self-funding note
        // (which needs the buffer on top), so everything must consolidate, and the ~20+ transaction
        // fees far exceed the optimistic single-transaction reserve.
        let notes: Vec<u64> = vec![u64::from(MAX_RESIDUAL_VALUE); 300];
        let total: u64 = notes.iter().sum();
        let available: Vec<Zatoshis> = notes.iter().map(|&v| zat(v)).collect();
        let s = CanonicalOneTwoFive::recommended(zat(buffer));

        let real = |funding: &[Zatoshis]| {
            crate::preparation::plan_preparation(&available, funding, zat(fee))
                .ok()
                .map(|plan| plan.transaction_count())
        };
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let constrained =
            crossings_u64(&s.plan(zat(total), notes.len(), zat(fee), &real, &mut rng));
        let canonical = s.unconstrained_split(total, notes.len(), fee);

        assert!(
            !constrained.is_empty() && constrained.len() < canonical.len(),
            "the split truncates without emptying: {constrained:?} from {canonical:?}"
        );
        assert_eq!(constrained, canonical[..constrained.len()]);
    }
}
