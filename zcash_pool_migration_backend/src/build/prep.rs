//! Building a note-preparation transaction: a same-pool Orchard send-to-self that restructures the
//! spent notes into a preparation plan's output notes, in a bundle of exactly [`PREP_TX_ACTIONS`]
//! Orchard actions.
//!
//! [`build_prep_tx`] turns one
//! [`PrepTransaction`](crate::preparation::PrepTransaction)'s inputs (which the wallet backend
//! resolves to Orchard notes and witnesses) and outputs into an unproven PCZT. Every output (a
//! funding, feeder, or residual note) is a wallet-controlled internal change note. ZIP 318 requires
//! each note-preparation transaction to contain exactly [`PREP_TX_ACTIONS`] actions so none is
//! distinguishable from another by its action count; the Orchard bundle is built with `pad_to_minimum`
//! set to that count, so orchard fills it to exactly [`PREP_TX_ACTIONS`] actions with fabricated
//! dummies.

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

    use crate::build::test_util::{account, regtest_network, single_note_witness};
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
