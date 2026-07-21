//! End-to-end test of the migration pipeline for a typical wallet, using only the crate's public API.
//! It doubles as a usage example: plan the note split, plan the preparation transactions, build and
//! pre-sign one, then build and pre-sign a pool-crossing transfer.

use orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::value::COIN;

use super::test_util::{TARGET_HEIGHT, regtest_network, single_note_witness, spending_key};
use super::{build_prep_tx, build_transfer_pczt, sign_pczt};
use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
use zcash_primitives::transaction::fees::{FeeRule as _, transparent, zip317};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::note_splitting::{
    DESTINATION_ACTIONS_PER_TRANSFER, SOURCE_ACTIONS_PER_TRANSFER, plan_note_split,
};
use crate::preparation::{PREP_TX_ACTIONS, PrepInput, plan_preparation};

/// note split -> preparation plan -> build + sign a preparation transaction -> build + sign a
/// pool-crossing transfer, for a typical single-note wallet.
#[test]
fn migration_pipeline_end_to_end() {
    let seed = 42u64;
    let params = regtest_network(true);

    // The account, and (conceptually) its single spendable Orchard note holding the whole balance.
    let sk = spending_key(seed);
    let fvk = FullViewingKey::from(&sk);
    let ask = SpendAuthorizingKey::from(&sk);
    let balance = 78 * COIN;

    // 1. Note split: decompose the balance into canonical self-funding denominations, accounting
    //    the true preparation cost (via the real preparation planner) at each step.
    let prep_fee = Zatoshis::const_from_u64(PREP_TX_ACTIONS as u64 * MARGINAL_FEE.into_u64());
    let buffer = Zatoshis::const_from_u64(
        (SOURCE_ACTIONS_PER_TRANSFER + DESTINATION_ACTIONS_PER_TRANSFER) as u64
            * MARGINAL_FEE.into_u64(),
    );
    let balance_zats = [Zatoshis::const_from_u64(balance)];
    let prep_tx_count = |funding: &[Zatoshis]| {
        plan_preparation(&balance_zats, funding, prep_fee)
            .ok()
            .map(|p| p.transaction_count())
    };
    let split = {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        plan_note_split(
            Zatoshis::const_from_u64(balance),
            buffer,
            prep_fee,
            &prep_tx_count,
            &mut rng,
        )
    };
    let funding = split.migration_outputs();
    assert!(!funding.is_empty(), "the balance yields funding notes");

    // 2. Preparation: plan the send-to-self transactions that mint those funding notes. A typical
    //    wallet (one note, a handful of funding notes) prepares in a single transaction.
    let prep = plan_preparation(&balance_zats, &funding, prep_fee)
        .expect("the balance funds the preparation");
    assert_eq!(prep.layer_count(), 1);
    assert_eq!(prep.transaction_count(), 1);

    // 3. Build + pre-sign the preparation transaction. The wallet backend resolves the transaction's
    //    single input (PrepInput::Wallet { index: 0, .. }) to the account's note and its witness
    //    against the anchor.
    let tx = &prep.layers()[0][0];
    assert!(matches!(tx.inputs(), [PrepInput::Wallet { index: 0, .. }]));
    let (note, path, anchor) = single_note_witness(&fvk, balance, seed);
    let prep_expiry = u32::from(crate::scheduling::expiry_height(BlockHeight::from_u32(
        TARGET_HEIGHT,
    )));
    let (prep_pczt, placed) = build_prep_tx(
        &params,
        TARGET_HEIGHT,
        prep_expiry,
        &fvk,
        anchor,
        vec![(note, path)],
        tx.outputs(),
        ChaCha8Rng::seed_from_u64(seed + 1),
    )
    .expect("the preparation transaction builds");
    assert_eq!(
        prep_pczt.orchard().actions().len(),
        PREP_TX_ACTIONS,
        "the preparation bundle is padded to exactly 16 actions"
    );
    assert_eq!(placed.len(), tx.outputs().len(), "every output is located");

    // The REAL constructed preparation transaction pays exactly the canonical ZIP-317 fee of its
    // padded shape: the value its spends bring in, minus the value its outputs (including change
    // and zero-valued dummies) carry out, is the fee the planner reserved per transaction.
    let fee_rule = zip317::FeeRule::standard();
    let expected_prep_fee = fee_rule
        .fee_required(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            core::iter::empty::<transparent::InputSize>(),
            core::iter::empty::<usize>(),
            0,
            0,
            PREP_TX_ACTIONS,
            0,
        )
        .expect("the canonical preparation fee computes");
    assert_eq!(
        expected_prep_fee, prep_fee,
        "the planner's per-transaction reserve is the rule's fee for the padded shape"
    );
    // The transaction's only spend is the wallet note supplied above (`balance`); its outputs
    // (funding notes, change, and zero-valued padding dummies) are read back from the built PCZT.
    let prep_out = bundle_output_value(prep_pczt.orchard());
    assert_eq!(
        balance - prep_out,
        u64::from(expected_prep_fee),
        "the built preparation transaction pays exactly the canonical fee"
    );
    sign_pczt(prep_pczt, &ask).expect("pre-signing the preparation transaction");

    // 4. Build + pre-sign a pool-crossing transfer for one funding note (witnessed directly here, as
    //    it would be once the preparation transaction is mined). It sends exactly the canonical
    //    denomination into the Ironwood pool.
    let crossing = split.crossing_values()[0];
    let funding_value = funding[0];
    // Only the funding note itself is needed: the transfer's anchors and its witness are
    // DEFERRED to proving time (ZIP 374), installed through the PCZT Updater role.
    let (fnote, _fpath, _fanchor) = single_note_witness(&fvk, u64::from(funding_value), seed + 2);
    let transfer_pczt = build_transfer_pczt(
        &params,
        TARGET_HEIGHT,
        TARGET_HEIGHT + 40_000,
        &fvk,
        fnote,
        crossing,
        ChaCha8Rng::seed_from_u64(seed + 3),
    )
    .expect("the transfer builds");

    // The REAL constructed transfer pays exactly the canonical fee of the 2+2-action transfer
    // shape (which is the buffer each prepared note carries), and crosses exactly the planned
    // canonical denomination into the Ironwood pool.
    let expected_transfer_fee = fee_rule
        .fee_required(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            core::iter::empty::<transparent::InputSize>(),
            core::iter::empty::<usize>(),
            0,
            0,
            SOURCE_ACTIONS_PER_TRANSFER,
            DESTINATION_ACTIONS_PER_TRANSFER,
        )
        .expect("the canonical transfer fee computes");
    assert_eq!(
        expected_transfer_fee, buffer,
        "the per-note buffer is the rule's fee for the transfer shape"
    );
    // The transfer's only spend is the funding note supplied above (`funding_value`); the value
    // that crosses is the Ironwood bundle's output total, and the change stays in Orchard.
    let orchard_out = bundle_output_value(transfer_pczt.orchard());
    let ironwood_out = bundle_output_value(transfer_pczt.ironwood());
    assert_eq!(
        transfer_pczt.orchard().actions().len(),
        SOURCE_ACTIONS_PER_TRANSFER,
        "the transfer's Orchard bundle is padded to the canonical two actions"
    );
    assert_eq!(
        transfer_pczt.ironwood().actions().len(),
        DESTINATION_ACTIONS_PER_TRANSFER,
        "the transfer's Ironwood bundle is a single unpadded action"
    );
    assert_eq!(
        ironwood_out,
        u64::from(crossing),
        "the value crossing the turnstile is exactly the planned canonical denomination"
    );
    assert_eq!(
        u64::from(funding_value) - orchard_out - ironwood_out,
        u64::from(expected_transfer_fee),
        "the built transfer pays exactly the canonical fee"
    );
    sign_pczt(transfer_pczt, &ask).expect("pre-signing the transfer");
}

/// The total output value a PCZT bundle carries (padded dummy outputs hold zero). Spend values are
/// redactable and expose no getter; the tests know the input values they supplied.
fn bundle_output_value(bundle: &pczt::orchard::Bundle) -> u64 {
    bundle
        .actions()
        .iter()
        .map(|action| action.output().value().unwrap_or(0))
        .sum()
}
