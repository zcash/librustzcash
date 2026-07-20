//! Building one note-preparation transaction as an unproven, exactly-16-action Orchard PCZT.
//!
//! # The mathematical problem
//!
//! Note preparation restructures a wallet's existing Orchard notes into the exact self-funding notes a
//! migration needs (one per planned pool-crossing, each worth its denomination plus the transfer fee),
//! using wallet-internal send-to-self transactions. Formally it is a degree-constrained
//! *merge-and-split value flow*:
//!
//! - The *sources* are the wallet's spendable note values `W = {w_1, ..., w_m}` (in zatoshi); the
//!   *sinks* are the funding-note values `F = {f_1, ..., f_l}` chosen by
//!   [`note_splitting`](crate::note_splitting), plus at most one residual `r`.
//! - A transaction `t = (I_t, O_t)` spends the notes `I_t` and creates the notes `O_t` subject to
//!   three constraints:
//!   - *budget*: `|I_t| + |O_t| <= A`, where `A` is [`PREP_TX_ACTIONS`], i.e. 16 Orchard actions;
//!   - *balance*: `sum(I_t) = sum(O_t) + phi`, where `phi` is the ZIP-317 fee of a padded `A`-action
//!     transaction (so every preparation transaction costs the same `phi`);
//!   - *structure*: each note is spent by at most one transaction (Orchard notes are spent atomically),
//!     and the spend graph is acyclic (a later layer may spend an earlier layer's outputs).
//! - A *plan* is the resulting DAG of transactions whose final (unspent) notes are exactly `F` plus at
//!   most one residual worth a fee. Value is conserved end to end:
//!   `sum(W) = sum(F) + r + |T| * phi`, where `|T|` is the number of transactions.
//!
//! Because an output may take *any* value (internal change is free), exactness is never required, so
//! this is NOT a subset-sum problem. It is a *fixed-charge network flow* (NP-hard in general) whose
//! divisible-value, uniform-fee instance decomposes into two classic k-ary trees, a consolidation
//! merge tree (many sub-quantum notes into one) and a split tree (one large note into many), and is
//! solved by
//! a greedy. The objective is lexicographic: feasibility first, then the fewest *layers* (each layer
//! waits for a confirmation and a boundary, so layers dominate the wall-clock), then the fewest
//! transactions (each a fixed fee `phi`).
//!
//! [`plan_preparation`](crate::preparation::plan_preparation) decides that DAG; THIS module realizes
//! one of its transactions. See the [`preparation`](crate::preparation) module for the planner, its
//! layering, and the k-ary lower bounds, and ZIP 318 for the constraints.
//!
//! # What this builder guarantees (per transaction)
//!
//! Given one [`PrepTransaction`](crate::preparation::PrepTransaction)'s resolved input notes (which the
//! wallet backend witnesses against `anchor`) and its output values, [`build_prep_tx`] produces an
//! unproven `pczt::Pczt` with these properties:
//!
//! - *value conservation*: `sum(spent notes) = sum(outputs) + phi`; an unbalanced request fails to
//!   build.
//! - *exactly `A` actions*: the Orchard bundle is padded to `A` with fabricated dummy actions
//!   (`pad_to_minimum`), so no preparation transaction is distinguishable from another by its action
//!   count (ZIP 318) and the real spend/output split is hidden.
//! - *internal, same-pool send-to-self*: every output (a funding, feeder, or residual note) is a
//!   wallet-controlled internal Orchard change note; there is no other pool and no external recipient.
//! - *locatable outputs*: it returns each requested output's real post-shuffle action index, so the
//!   caller can find the notes on-chain and spend the feeder notes in a later layer.
//! - *pure*: no database, wallet-backend, or network access; the RNG is a parameter.

use alloc::vec::Vec;

use core::convert::Infallible;

use rand_core::{CryptoRng, RngCore};

use orchard::builder::BundleType;
use orchard::keys::{FullViewingKey, Scope};
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use super::{BuildError, finalize_pczt, output_action_index};
use crate::preparation::{PREP_TX_ACTIONS, PrepOutput};

/// The internal-scope diversifier index for the wallet's own preparation outputs.
const INTERNAL_ADDRESS_INDEX: u32 = 0;

/// Build one note-preparation transaction as an unproven PCZT: spend every note in `spends` and create
/// one internal change note per output in `outputs` (a funding, feeder, or residual note), in an
/// Orchard bundle padded to exactly [`PREP_TX_ACTIONS`] actions with fabricated dummies.
///
/// The caller (the wallet backend) resolves the transaction's inputs to the `(Note, MerklePath)`
/// witnesses in `spends` against `anchor`, and supplies the `orchard_fvk` whose internal scope every
/// output is derived from. The spent notes must total the outputs plus the ZIP-317 fee of a padded
/// [`PREP_TX_ACTIONS`]-action transaction (the preparation planner reserves exactly this), or the
/// build does not balance.
///
/// Returns the finalized PCZT and, for each requested output in order, its `(action_index, output)`
/// so the caller can locate each note after the transaction is mined (and spend the feeder notes in a
/// later layer). The fabricated dummy actions are not returned.
///
/// # Errors
///
/// Returns [`BuildError`] if there are no spends or outputs, if the logical action count
/// (`spends + outputs`) exceeds [`PREP_TX_ACTIONS`], or if the builder/PCZT pipeline fails (including
/// when the spent notes do not balance the outputs plus the fee).
///
/// The caller supplies `rng` (a cryptographically secure RNG in production, e.g. `OsRng`; tests can
/// pass a seeded one), keeping this builder pure.
pub fn build_prep_tx<P, R>(
    params: &P,
    target_height: u32,
    orchard_fvk: &FullViewingKey,
    anchor: orchard::Anchor,
    spends: Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
    outputs: &[PrepOutput],
    rng: R,
) -> Result<(pczt::Pczt, Vec<(u32, PrepOutput)>), BuildError>
where
    P: Parameters + Clone,
    R: RngCore + CryptoRng,
{
    if spends.is_empty() {
        return Err(BuildError::Balance(
            "preparation: no spendable notes".into(),
        ));
    }
    if outputs.is_empty() {
        return Err(BuildError::Balance("preparation: no outputs".into()));
    }
    let logical_actions = spends.len() + outputs.len();
    if logical_actions > PREP_TX_ACTIONS {
        return Err(BuildError::Balance(format!(
            "preparation: {logical_actions} logical actions exceed the \
             {PREP_TX_ACTIONS}-action budget"
        )));
    }

    // An Orchard-only send-to-self whose bundle is padded to exactly PREP_TX_ACTIONS actions with
    // orchard's fabricated dummies (`pad_to_minimum`).
    let config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(anchor),
        ironwood_anchor: None,
        orchard_bundle_type: BundleType::Transactional {
            bundle_required: false,
            pad_to_minimum: Some(PREP_TX_ACTIONS as u8),
        },
        ironwood_bundle_type: BundleType::DEFAULT,
    };
    let mut builder = Builder::new(params.clone(), BlockHeight::from_u32(target_height), config);
    for (note, merkle_path) in spends {
        builder
            .add_orchard_spend::<Infallible>(orchard_fvk.clone(), note, merkle_path)
            .map_err(|e| BuildError::Build(format!("preparation: add spend: {e:?}")))?;
    }

    let change_address = orchard_fvk.address_at(INTERNAL_ADDRESS_INDEX, Scope::Internal);
    let internal_ovk = orchard_fvk.to_ovk(Scope::Internal);
    for output in outputs {
        builder
            .add_orchard_change_output::<Infallible>(
                orchard_fvk.clone(),
                Some(internal_ovk.clone()),
                change_address,
                Zatoshis::const_from_u64(output.value()),
                MemoBytes::empty(),
            )
            .map_err(|e| BuildError::Build(format!("preparation: add output: {e:?}")))?;
    }

    let build_result = builder
        .build_for_pczt(rng, &Zip317FeeRule::standard())
        .map_err(|e| BuildError::Build(format!("preparation: build: {e:?}")))?;

    // Un-shuffle: map each requested output to its real action index (the fabricated dummies occupy
    // the remaining actions) so the caller can store the right (action_index, output) references.
    let placed: Vec<(u32, PrepOutput)> = outputs
        .iter()
        .enumerate()
        .map(|(i, &out)| output_action_index(&build_result.orchard_meta, i).map(|ai| (ai, out)))
        .collect::<Result<_, _>>()?;

    let finalized = finalize_pczt(build_result.pczt_parts)?;
    Ok((finalized, placed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;

    use crate::build::test_util::{
        TARGET_HEIGHT, account, regtest_network, shared_anchor_witnesses, single_note_witness,
    };
    use crate::note_splitting::{FeePolicy, Zip317FeePolicy};

    /// The ZIP-317 fee of a padded [`PREP_TX_ACTIONS`]-action preparation transaction (each action
    /// costs one marginal fee), which the planner reserves per transaction.
    fn prep_fee() -> u64 {
        PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi()
    }

    /// The number of Orchard actions in the built transaction.
    fn action_count(pczt: &pczt::Pczt) -> usize {
        pczt.orchard().actions().len()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Every built preparation transaction has EXACTLY `PREP_TX_ACTIONS` Orchard actions, for any
        /// mix of spends and outputs within the budget: `pad_to_minimum` always fills the bundle up to
        /// the fixed count with dummies, so no transaction is distinguishable by its action count.
        #[test]
        fn always_exactly_prep_tx_actions(
            out_zats in prop::collection::vec(1_000_000u64..(50 * COIN), 1..PREP_TX_ACTIONS),
            n_spend in 1usize..PREP_TX_ACTIONS,
            account_seed in any::<u64>(),
            note_seed in any::<u64>(),
        ) {
            let n_out = out_zats.len();
            // Fit spends and outputs into the budget; at least one spend (n_out <= PREP_TX_ACTIONS-1).
            let n_spend = n_spend.min(PREP_TX_ACTIONS - n_out);

            // The spends must fund the outputs plus the padded fee; split that total across the spend
            // notes (the remainder on the first), so the transaction balances exactly.
            let total_in = out_zats.iter().sum::<u64>() + prep_fee();
            let base = total_in / n_spend as u64;
            let mut spend_values = vec![base; n_spend];
            spend_values[0] += total_in % n_spend as u64;

            let fvk = account(account_seed);
            let (spends, anchor) = shared_anchor_witnesses(&fvk, &spend_values, note_seed);
            let outputs: Vec<PrepOutput> =
                out_zats.iter().map(|&v| PrepOutput::Funding(v)).collect();

            let params = regtest_network(true);
            let rng = ChaCha8Rng::seed_from_u64(note_seed);
            let (pczt, placed) = build_prep_tx(
                &params,
                TARGET_HEIGHT,
                &fvk,
                anchor,
                spends,
                &outputs,
                rng,
            )
            .expect("a balanced preparation transaction builds");

            prop_assert_eq!(action_count(&pczt), PREP_TX_ACTIONS);
            prop_assert_eq!(placed.len(), outputs.len());
        }

        /// A single funding note fanned into up to `FUNDING_OUTPUTS_PER_TX` outputs builds into a
        /// padded transaction of exactly `PREP_TX_ACTIONS` actions, and each output is reported at its
        /// real action index with its planned value.
        #[test]
        fn builds_a_padded_funding_prep_tx(
            output_zats in prop::collection::vec(1u64..(50 * COIN), 1..14),
            account_seed in any::<u64>(),
            note_seed in any::<u64>(),
        ) {
            let fvk = account(account_seed);
            let outputs: Vec<PrepOutput> =
                output_zats.iter().map(|&v| PrepOutput::Funding(v)).collect();
            // One spend that funds every output plus the padded fee.
            let spend_value = output_zats.iter().sum::<u64>() + prep_fee();
            let (note, path, anchor) = single_note_witness(&fvk, spend_value, note_seed);

            let params = regtest_network(true);
            let rng = ChaCha8Rng::seed_from_u64(note_seed);
            let (pczt, placed) = build_prep_tx(
                &params,
                100,
                &fvk,
                anchor,
                vec![(note, path)],
                &outputs,
                rng,
            )
            .expect("a balanced preparation transaction should build");

            prop_assert_eq!(action_count(&pczt), PREP_TX_ACTIONS);
            prop_assert_eq!(placed.len(), outputs.len());
            let placed_values: Vec<u64> = placed.iter().map(|(_, o)| o.value()).collect();
            prop_assert_eq!(placed_values, output_zats);
            // Every output maps to a distinct action index.
            let mut indices: Vec<u32> = placed.iter().map(|&(i, _)| i).collect();
            indices.sort_unstable();
            indices.dedup();
            prop_assert_eq!(indices.len(), outputs.len());
        }
    }

    /// A minimal transaction (one spend, one output) is padded up to the full action budget.
    #[test]
    fn pads_a_minimal_prep_tx_to_the_action_budget() {
        let fvk = account(1);
        let outputs = [PrepOutput::Intermediate(10 * COIN)];
        let spend_value = 10 * COIN + prep_fee();
        let (note, path, anchor) = single_note_witness(&fvk, spend_value, 7);
        let params = regtest_network(true);
        let (pczt, placed) = build_prep_tx(
            &params,
            100,
            &fvk,
            anchor,
            vec![(note, path)],
            &outputs,
            ChaCha8Rng::seed_from_u64(7),
        )
        .unwrap();
        assert_eq!(action_count(&pczt), PREP_TX_ACTIONS);
        assert_eq!(placed.len(), 1);
    }

    /// The builder rejects an empty spend set, an empty output set, and an over-budget action count
    /// before touching cryptography.
    #[test]
    fn rejects_bad_inputs() {
        let fvk = account(2);
        let params = regtest_network(true);
        let anchor = orchard::Anchor::empty_tree();
        let one_output = [PrepOutput::Funding(COIN)];

        let no_spends = build_prep_tx(
            &params,
            100,
            &fvk,
            anchor,
            Vec::new(),
            &one_output,
            ChaCha8Rng::seed_from_u64(0),
        );
        assert!(matches!(no_spends, Err(BuildError::Balance(_))));

        let (note, path, real_anchor) = single_note_witness(&fvk, COIN + prep_fee(), 3);
        let no_outputs = build_prep_tx(
            &params,
            100,
            &fvk,
            real_anchor,
            vec![(note, path)],
            &[],
            ChaCha8Rng::seed_from_u64(0),
        );
        assert!(matches!(no_outputs, Err(BuildError::Balance(_))));

        // One spend plus more outputs than the remaining action budget.
        let too_many: Vec<PrepOutput> = (0..PREP_TX_ACTIONS)
            .map(|_| PrepOutput::Funding(COIN))
            .collect();
        let (note2, path2, anchor2) = single_note_witness(&fvk, 1_000 * COIN, 4);
        let over_budget = build_prep_tx(
            &params,
            100,
            &fvk,
            anchor2,
            vec![(note2, path2)],
            &too_many,
            ChaCha8Rng::seed_from_u64(0),
        );
        assert!(matches!(over_budget, Err(BuildError::Balance(_))));
    }
}
