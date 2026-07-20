//! End-to-end test of the migration pipeline for a typical wallet, using only the crate's public API.
//! It doubles as a usage example: plan the note split, plan the preparation transactions, build and
//! pre-sign one, then build and pre-sign a pool-crossing transfer.

use orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::value::COIN;

use super::test_util::{TARGET_HEIGHT, regtest_network, single_note_witness, spending_key};
use super::{build_prep_tx, build_transfer_pczt, sign_pczt};
use crate::note_splitting::{FeePolicy, Zip317FeePolicy, plan_note_split};
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

    // 1. Note split: decompose the balance into canonical self-funding denominations.
    let prep_fee = PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi();
    let split = {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        plan_note_split(balance, prep_fee, &mut rng)
    };
    let funding = split.migration_outputs();
    assert!(!funding.is_empty(), "the balance yields funding notes");

    // 2. Preparation: plan the send-to-self transactions that mint those funding notes. A typical
    //    wallet (one note, a handful of funding notes) prepares in a single transaction.
    let prep = plan_preparation(&[balance], &funding, split.prep_fee_zatoshi())
        .expect("the balance funds the preparation");
    assert_eq!(prep.layer_count(), 1);
    assert_eq!(prep.transaction_count(), 1);

    // 3. Build + pre-sign the preparation transaction. The wallet backend resolves the transaction's
    //    single input (PrepInput::Wallet(0)) to the account's note and its witness against the anchor.
    let tx = &prep.layers()[0][0];
    assert!(matches!(tx.inputs(), [PrepInput::Wallet(0)]));
    let (note, path, anchor) = single_note_witness(&fvk, balance, seed);
    let (prep_pczt, placed) = build_prep_tx(
        &params,
        TARGET_HEIGHT,
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
    sign_pczt(prep_pczt, &ask).expect("pre-signing the preparation transaction");

    // 4. Build + pre-sign a pool-crossing transfer for one funding note (witnessed directly here, as
    //    it would be once the preparation transaction is mined). It sends exactly the canonical
    //    denomination into the Ironwood pool.
    let crossing = split.crossing_values()[0];
    let funding_value = funding[0];
    let (fnote, fpath, fanchor) = single_note_witness(&fvk, funding_value, seed + 2);
    let transfer_pczt = build_transfer_pczt(
        &params,
        TARGET_HEIGHT,
        TARGET_HEIGHT + 40_000,
        &fvk,
        fanchor,
        fnote,
        fpath,
        crossing,
        ChaCha8Rng::seed_from_u64(seed + 3),
    )
    .expect("the transfer builds");
    sign_pczt(transfer_pczt, &ask).expect("pre-signing the transfer");
}
