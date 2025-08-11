use std::{convert::Infallible, num::NonZeroU32};

use assert_matches::assert_matches;

use zcash_keys::address::Address;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{memo::Memo, value::Zatoshis, ShieldedProtocol};

use zip321::Payment;

use crate::{
    data_api::{
        testing::{
            orchard::OrchardPoolTester, pool::ShieldedPoolTester, sapling::SaplingPoolTester,
            AddressType, TestBuilder,
        },
        wallet::{decrypt_and_store_transaction, input_selection::GreedyInputSelector},
        Account as _,
        ShieldedProtocol::Orchard,
        WalletRead, WalletTest,
    },
    decrypt_transaction,
    fees::{standard, DustOutputPolicy, StandardFeeRule},
    wallet::{NoteId, OvkPolicy},
};

use super::{DataStoreFactory, TestCache};

/// Loads wallet with 60k Sapling zats and 60k Orchard zats and
/// verifies that the balance is correct.
/// Creates a transaction proposal to spend 100k zats which will need to use
/// both notes.
/// Checks that the created transaction has the appropriate notes: 1 Sapling and
/// 1 Orchard plus, the change memo to the specified pool (in this case Orchard).
pub fn send_single_step_proposed_transfer(dsf: impl DataStoreFactory, cache: impl TestCache) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let sapling_dfvk = SaplingPoolTester::test_account_fvk(&st);
    let orchard_dfvk = OrchardPoolTester::test_account_fvk(&st);

    // Add sapling funds to the wallet in a single note
    let single_note_value = Zatoshis::const_from_u64(60000);

    let expected_total_value = Zatoshis::const_from_u64(120000);
    let (h, _, _) = st.generate_next_block(
        &sapling_dfvk,
        AddressType::DefaultExternal,
        single_note_value,
    );
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account.id()), single_note_value);
    assert_eq!(st.get_spendable_balance(account.id(), 1), single_note_value);

    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    // Add orchard funds to the wallet in a single note
    let (h, _, _) = st.generate_next_block(
        &orchard_dfvk,
        AddressType::DefaultExternal,
        single_note_value,
    );
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account.id()), expected_total_value);
    assert_eq!(
        st.get_spendable_balance(account.id(), 1),
        expected_total_value
    );

    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    let to_extsk = SaplingPoolTester::sk(&[0xf5; 32]);
    let to: Address = SaplingPoolTester::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(100000),
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;

    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        fee_rule,
        Some(change_memo.clone().into()),
        Orchard,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .unwrap()
        .expect("Created transaction was stored.");
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), None, Some(h), &tx, &ufvks);
    assert_eq!(SaplingPoolTester::decrypted_pool_outputs_count(&d_tx), 1);
    assert_eq!(OrchardPoolTester::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_tx_change_memo = false;
    let mut found_tx_empty_memo = false;
    OrchardPoolTester::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == change_memo {
            found_tx_change_memo = true
        }
    });
    SaplingPoolTester::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_tx_change_memo);
    assert!(found_tx_empty_memo);

    // Verify that the stored sent notes match what we're expecting
    let sapling_sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, ShieldedProtocol::Sapling)
        .unwrap();
    assert_eq!(sapling_sent_note_ids.len(), 1);

    let orchard_sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, ShieldedProtocol::Orchard)
        .unwrap();
    assert_eq!(orchard_sent_note_ids.len(), 1);

    // The sent memo should be the empty memo for the sent output
    let mut found_sent_change_memo = false;
    let mut found_sent_empty_memo = false;
    for sent_note_id in sapling_sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &change_memo => {
                found_sent_change_memo = true;
            }
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    // The change output's memo should be as specified.
    for sent_note_id in orchard_sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &change_memo => {
                found_sent_change_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }
    assert!(found_sent_change_memo);
    assert!(found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, ShieldedProtocol::Sapling, 12345)),
        Ok(None)
    );

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 3);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }

    {
        let tx_1 = &tx_history[2];
        assert_eq!(tx_1.fee_paid(), Some(Zatoshis::const_from_u64(20000)));
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(120000));
        assert_eq!(tx_1.total_received(), Zatoshis::ZERO);
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}
