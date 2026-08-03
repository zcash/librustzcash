//! Reading [ZIP 318] classification evidence off a PCZT.
//!
//! This is the evidence source a TEST uses: it observes a transaction the builders have just
//! produced, before it is proven or mined, which is what lets the conformance suite check that
//! everything this crate builds is recognised by the classifier a wallet will later apply to the
//! mined transaction. Proving a PCZT to obtain a `Transaction` costs a prover run; every field the
//! classifier needs is already in the PCZT, so nothing here requires one.
//!
//! The observations themselves belong to the PCZT, not to ZIP 318, so they live on the `pczt`
//! types ([`Bundle::value_carrying_outputs_all_pay`], [`Bundle::sole_action`],
//! [`Pczt::has_data_in_pool`]). This module only maps them onto the ZIP's clauses, which is why it
//! is as short as it is.
//!
//! It deliberately answers neither confirmatory clause. A PCZT built by this crate carries DEFERRED
//! anchors (ZIP 374), so there is no anchor to place on the retention grid, and the fee is not a
//! PCZT field. Both are left unanswered rather than guessed, which widens the predicate (see
//! [`classify`]) instead of blocking or misleading it.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318
//! [`classify`]: zcash_protocol::zip318::classify
//! [`Bundle::value_carrying_outputs_all_pay`]: pczt::orchard::Bundle::value_carrying_outputs_all_pay
//! [`Bundle::sole_action`]: pczt::orchard::Bundle::sole_action
//! [`Pczt::has_data_in_pool`]: pczt::Pczt::has_data_in_pool

use orchard::keys::{FullViewingKey, Scope};
use zcash_protocol::PoolType;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::zip318::{PoolMigrationConstants, Zip318Evidence};

/// The internal-scope diversifier index the builders send the account's own outputs to. Mirrors
/// `build::prep`'s constant; an output at any other index is not one of ours.
const INTERNAL_ADDRESS_INDEX: u32 = 0;

/// Gathers the [ZIP 318] evidence a PCZT can supply, for classification by
/// [`classify`](zcash_protocol::zip318::classify).
///
/// `fvk` is the account whose transaction this is, used to recognise the account's own internal
/// address. `expiry_reference` is the height the canonical rolling expiry is judged against, which
/// for an unmined PCZT is the target height it was built for; passing anything else (a chain tip,
/// say) makes the expiry clause unstable, because the canonical expiry is a step function of the
/// height. See [`Zip318Evidence`] for that obligation and the others.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub fn evidence_from_pczt<C>(
    pczt: &pczt::Pczt,
    fvk: &FullViewingKey,
    expiry_reference: BlockHeight,
    constants: &C,
) -> Zip318Evidence
where
    C: PoolMigrationConstants + ?Sized,
{
    let internal = fvk
        .address_at(INTERNAL_ADDRESS_INDEX, Scope::Internal)
        .to_raw_address_bytes();
    let expiry = BlockHeight::from_u32(*pczt.global().expiry_height());

    // Neither confirmatory clause is answered: deferred anchors and an absent fee field, see the
    // module documentation.
    Zip318Evidence::default()
        .with_source_actions(Some(pczt.orchard().actions().len()))
        .with_destination_actions(Some(pczt.ironwood().actions().len()))
        .with_other_bundles_present(Some(
            pczt.has_data_in_pool(PoolType::TRANSPARENT)
                || pczt.has_data_in_pool(PoolType::SAPLING),
        ))
        .with_source_is_send_to_self(pczt.orchard().value_carrying_outputs_all_pay(&internal))
        .with_sole_destination_value(sole_destination_value(pczt.ironwood()))
        .with_expiry_is_canonical(Some(
            constants.is_canonical_expiry(expiry, expiry_reference),
        ))
}

/// The value of the sole output of a single-action destination bundle, which is the shape a
/// canonical crossing has.
///
/// `None` when the bundle does not have exactly one action (the action count is a separate clause,
/// so this is not itself a refutation) or when the output's value has been redacted. A zero value
/// is reported as such rather than skipped: zero is not a canonical denomination, so the classifier
/// refuses it, which is the right answer for a destination bundle holding only a dummy.
fn sole_destination_value(bundle: &pczt::orchard::Bundle) -> Option<Zatoshis> {
    let output = bundle.sole_action()?.output();

    Zatoshis::from_u64((*output.value())?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
    use zcash_protocol::value::COIN;
    use zcash_protocol::zip318::{PREP_TX_ACTIONS, Zip318Classification, Zip318TxKind};

    use crate::build::test_util::{TARGET_HEIGHT, account, regtest_network, single_note_witness};
    use crate::build::{build_prep_tx, build_transfer_pczt};
    use crate::denomination::{DESTINATION_ACTIONS_PER_TRANSFER, SOURCE_ACTIONS_PER_TRANSFER, zat};
    use crate::preparation::PrepOutput;

    /// A wallet on the specified ZIP 318 parameters.
    #[derive(Clone)]
    struct Zip318Params;
    impl PoolMigrationConstants for Zip318Params {}

    /// The canonical rolling expiry the engine embeds for a transaction targeting the build
    /// height. Building with anything else is what the "ordinary expiry" case below exercises.
    fn canonical_expiry() -> u32 {
        u32::from(crate::scheduling::expiry_height(BlockHeight::from_u32(
            TARGET_HEIGHT,
        )))
    }

    fn classify_pczt(pczt: &pczt::Pczt, fvk: &FullViewingKey) -> Zip318Classification {
        zcash_protocol::zip318::classify(
            &evidence_from_pczt(
                pczt,
                fvk,
                BlockHeight::from_u32(TARGET_HEIGHT),
                &Zip318Params,
            ),
            &Zip318Params,
        )
    }

    /// Builds a transfer crossing `crossing_value`, with the given expiry.
    fn transfer(crossing_value: u64, expiry: u32) -> (pczt::Pczt, FullViewingKey) {
        let fvk = account(7);
        let buffer = (SOURCE_ACTIONS_PER_TRANSFER + DESTINATION_ACTIONS_PER_TRANSFER) as u64
            * MARGINAL_FEE.into_u64();
        let (note, _path, _anchor) = single_note_witness(&fvk, crossing_value + buffer, 11);

        let pczt = build_transfer_pczt(
            &regtest_network(true),
            TARGET_HEIGHT,
            expiry,
            &fvk,
            note,
            zat(crossing_value),
            None,
            ChaCha8Rng::seed_from_u64(3),
        )
        .expect("a self-funding note builds a balanced transfer");

        (pczt, fvk)
    }

    /// Builds a single-output preparation transaction, with the given expiry.
    fn preparation(expiry: u32) -> (pczt::Pczt, FullViewingKey) {
        let fvk = account(23);
        let output_value = 5 * COIN;
        let fee = PREP_TX_ACTIONS as u64 * MARGINAL_FEE.into_u64();
        let (note, _path, _anchor) = single_note_witness(&fvk, output_value + fee, 29);

        let (pczt, _placed) = build_prep_tx(
            &regtest_network(true),
            TARGET_HEIGHT,
            expiry,
            &fvk,
            vec![note],
            &[PrepOutput::Funding(zat(output_value))],
            None,
            ChaCha8Rng::seed_from_u64(5),
        )
        .expect("a funded note builds a balanced preparation transaction");

        (pczt, fvk)
    }

    /// THE CONFORMANCE LOOP. What this crate builds must be what the classifier recognises: a
    /// transfer classifies as a transfer, a preparation transaction as a preparation transaction.
    /// If these ever disagree, either a builder has drifted from ZIP 318 or the classifier has,
    /// and nothing else in the workspace would notice.
    #[test]
    fn the_builders_emit_what_the_classifier_recognises() {
        let (pczt, fvk) = transfer(COIN, canonical_expiry());
        assert_eq!(
            classify_pczt(&pczt, &fvk),
            Zip318Classification::Conforms(Zip318TxKind::Transfer),
            "a built transfer must be recognised as one"
        );

        let (pczt, fvk) = preparation(canonical_expiry());
        assert_eq!(
            classify_pczt(&pczt, &fvk),
            Zip318Classification::Conforms(Zip318TxKind::Preparation),
            "a built preparation transaction must be recognised as one"
        );
    }

    /// The padding is what makes the shapes uniform, so it is also what the evidence must see: a
    /// preparation transaction is padded to exactly the specified action count and crosses
    /// nothing, and a transfer carries the two-action source bundle and a single unpadded
    /// destination action.
    #[test]
    fn the_evidence_reports_the_padded_shapes() {
        let (pczt, fvk) = preparation(canonical_expiry());
        let evidence = evidence_from_pczt(
            &pczt,
            &fvk,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &Zip318Params,
        );
        assert_eq!(evidence.source_actions(), Some(PREP_TX_ACTIONS));
        assert_eq!(evidence.destination_actions(), Some(0));
        assert_eq!(evidence.other_bundles_present(), Some(false));
        assert_eq!(evidence.source_is_send_to_self(), Some(true));

        let (pczt, fvk) = transfer(COIN, canonical_expiry());
        let evidence = evidence_from_pczt(
            &pczt,
            &fvk,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &Zip318Params,
        );
        assert_eq!(evidence.source_actions(), Some(SOURCE_ACTIONS_PER_TRANSFER));
        assert_eq!(
            evidence.destination_actions(),
            Some(DESTINATION_ACTIONS_PER_TRANSFER)
        );
        assert_eq!(
            evidence.sole_destination_value(),
            Some(zat(COIN)),
            "the crossing carries the canonical denomination"
        );
    }

    /// A PCZT source answers neither confirmatory clause: it has no anchor to place on the grid
    /// (ZIP 374 defers them) and no fee field. Unanswered widens the predicate rather than
    /// blocking it, which is why the classifications above still decide.
    #[test]
    fn a_pczt_answers_neither_confirmatory_clause() {
        let (pczt, fvk) = transfer(COIN, canonical_expiry());
        let evidence = evidence_from_pczt(
            &pczt,
            &fvk,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &Zip318Params,
        );
        assert_eq!(evidence.anchor_on_grid(), None);
        assert_eq!(evidence.fee_is_canonical(), None);
    }

    /// The same transactions built with an ORDINARY expiry are refused. This is the discriminator
    /// that separates ZIP 318 transactions from ordinary ones with the same bundle shape, so it
    /// has to bite even on transactions these builders produced.
    #[test]
    fn an_ordinary_expiry_is_refused() {
        let ordinary = TARGET_HEIGHT + 40;

        for (pczt, fvk) in [transfer(COIN, ordinary), preparation(ordinary)] {
            assert_eq!(
                classify_pczt(&pczt, &fvk),
                Zip318Classification::Nonconforming,
                "an ordinary expiry is not the canonical rolling one"
            );
        }
    }

    /// A crossing of an off-series amount joins no anonymity set, so it is refused even though its
    /// shape is otherwise exact.
    #[test]
    fn an_off_series_crossing_is_refused() {
        let (pczt, fvk) = transfer(3 * COIN, canonical_expiry());
        assert_eq!(
            classify_pczt(&pczt, &fvk),
            Zip318Classification::Nonconforming
        );
    }

    /// A transaction of ANOTHER account's is not this account's migration: the outputs pay an
    /// internal address that is not the one being asked about. This is the property that keeps a
    /// wallet from labelling a stranger's look-alike as its own.
    #[test]
    fn another_accounts_transaction_is_not_ours() {
        let (pczt, _fvk) = preparation(canonical_expiry());
        let stranger = account(99);
        assert_eq!(
            classify_pczt(&pczt, &stranger),
            Zip318Classification::Nonconforming
        );
    }
}
