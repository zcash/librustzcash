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
        Account as _, WalletRead, WalletTest,
    },
    decrypt_transaction,
    fees::{
        standard::{self},
        DustOutputPolicy, StandardFeeRule,
    },
    wallet::{NoteId, OvkPolicy},
};

use super::{DataStoreFactory, TestCache};

#[cfg(feature = "transparent-inputs")]
use {
    super::TestState,
    crate::{
        data_api::{
            TransactionDataRequest,
            DecryptedTransaction, WalletWrite,
        },
        fees::ChangeValue,
        wallet::{TransparentAddressMetadata, WalletTransparentOutput},
    },
    ::transparent::{
        address::TransparentAddress,
        bundle::{OutPoint, TxOut},
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    },
    rand_core::OsRng,
    std::collections::HashSet,
    zcash_primitives::transaction::{
        fees::zip317::{MARGINAL_FEE, MINIMUM_FEE},
        builder::{BuildConfig, Builder},
        fees::zip317,
    },
    zcash_proofs::prover::LocalTxProver,
    zcash_protocol::value::ZatBalance,
    zip32::Scope,
};

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
        ShieldedProtocol::Orchard,
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

/// Loads wallet with 60k Sapling zats and 60k Orchard zats and
/// verifies that the balance is correct.
/// Creates a transaction proposal to spend all funds
/// Checks that the created transaction has the appropriate notes:  1 Orchard
/// and no change.
pub fn send_max_funds_to_sapling_proposed_transfer(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
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

    let fee_rule = StandardFeeRule::Zip317;

    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            to,
            None,
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
    assert_eq!(OrchardPoolTester::decrypted_pool_outputs_count(&d_tx), 0);

    let mut found_tx_empty_memo = false;

    SaplingPoolTester::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });

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

    // there's no change so there should be no orchard note since we are sendin'
    // so sapling
    assert_eq!(orchard_sent_note_ids.len(), 0);

    // The sent memo should be the empty memo for the sent output
    let mut found_sent_empty_memo = false;
    for sent_note_id in sapling_sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }
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

/// Loads wallet with 60k Sapling zats and 60k Orchard zats and
/// verifies that the balance is correct.
/// Creates a transaction proposal to spend all funds
/// Checks that the created transaction has the appropriate notes:  1 Orchard
/// and no change.
pub fn send_max_funds_to_orchard_proposed_transfer(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
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

    let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
    let to: Address = OrchardPoolTester::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            to,
            None,
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

    // we are sending to Orchard, there should be no sapling output
    assert_eq!(SaplingPoolTester::decrypted_pool_outputs_count(&d_tx), 0);

    assert_eq!(OrchardPoolTester::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_tx_empty_memo = false;

    OrchardPoolTester::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });

    assert!(found_tx_empty_memo);

    // Verify that the stored sent notes match what we're expecting
    let sapling_sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, ShieldedProtocol::Sapling)
        .unwrap();
    assert_eq!(sapling_sent_note_ids.len(), 0);

    let orchard_sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, ShieldedProtocol::Orchard)
        .unwrap();

    // there's no change so there should be a single orchard note
    assert_eq!(orchard_sent_note_ids.len(), 1);

    // The sent memo should be the empty memo for the sent output
    let mut found_sent_empty_memo = false;
    for sent_note_id in orchard_sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    assert!(found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, ShieldedProtocol::Orchard, 12345)),
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

/// This test attempts to send the max spendable funds to a TEX address recipient
/// checks that the transactions were stored and that the amounts involved are correct
#[cfg(feature = "transparent-inputs")]
pub fn send_multi_step_max_amount_proposed_transfer<DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
    is_reached_gap_limit: impl Fn(&<DSF::DataStore as WalletRead>::Error, DSF::AccountId, u32) -> bool,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use ::transparent::builder::TransparentSigningSet;

    use crate::data_api::{testing::transparent::GapLimits, OutputOfSentTx};

    let gap_limits = GapLimits::new(10, 5, 3);
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .with_gap_limits(gap_limits)
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let (default_addr, default_index) = account.usk().default_transparent_address();
    let sapling_dfvk = SaplingPoolTester::test_account_fvk(&st);
    let orchard_dfvk = OrchardPoolTester::test_account_fvk(&st);

    let add_sapling_funds = |st: &mut TestState<_, DSF::DataStore, _>, value: Zatoshis| {
        let (h, _, _) = st.generate_next_block(&sapling_dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            st.wallet()
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            h
        );
        h
    };

    let add_orchard_funds = |st: &mut TestState<_, DSF::DataStore, _>, value: Zatoshis| {
        let (h, _, _) = st.generate_next_block(&orchard_dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            st.wallet()
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            h
        );
        h
    };

    let single_note_value = Zatoshis::const_from_u64(100000);
    let cross_pool_value = (single_note_value + single_note_value).unwrap();
    let run_test = |st: &mut TestState<_, DSF::DataStore, _>, expected_index, prior_balance| {
        // Add funds to the wallet.

        add_sapling_funds(st, single_note_value);
        add_orchard_funds(st, single_note_value);

        let initial_balance: Option<Zatoshis> = prior_balance + cross_pool_value;
        assert_eq!(
            st.get_spendable_balance(account_id, 1),
            initial_balance.unwrap()
        );

        let expected_step0_fee = (MARGINAL_FEE * 5u64).unwrap();
        let expected_step1_fee = MINIMUM_FEE;
        let expected_ephemeral_spend =
            (cross_pool_value - expected_step0_fee - expected_step1_fee).unwrap();
        let expected_ephemeral_balance = (cross_pool_value - expected_step0_fee).unwrap();
        let expected_step0_change = (cross_pool_value - expected_step0_fee).unwrap();

        let total_sent =
            (expected_step0_fee + expected_step1_fee + expected_ephemeral_spend).unwrap();

        // check that the napkin math is Ok. Total value send should be the whole
        // value of the wallet
        assert_eq!(total_sent, cross_pool_value);

        // Generate a ZIP 320 proposal, sending to the wallet's default transparent address
        // expressed as a TEX address.
        let tex_addr = match default_addr {
            TransparentAddress::PublicKeyHash(data) => Address::Tex(data),
            _ => unreachable!(),
        };

        let fee_rule = StandardFeeRule::Zip317;

        // We use `st.propose_standard_transfer` here in order to also test round-trip
        // serialization of the proposal.
        let proposal = st
            .propose_send_max_transfer(
                account_id,
                &fee_rule,
                tex_addr.clone(),
                None,
                NonZeroU32::new(1).unwrap(),
            )
            .unwrap();

        let steps: Vec<_> = proposal.steps().iter().cloned().collect();
        assert_eq!(steps.len(), 2);

        assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
        assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
        assert_eq!(
            steps[0].balance().proposed_change(),
            [ChangeValue::ephemeral_transparent(
                (total_sent - expected_step0_fee).expect("value is non-zero")
            ),]
        );
        assert_eq!(steps[1].balance().proposed_change(), []);

        let create_proposed_result = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                account.usk(),
                OvkPolicy::Sender,
                &proposal,
            );
        assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
        let txids = create_proposed_result.unwrap();

        // Mine the created transactions.
        for txid in txids.iter() {
            let (h, _) = st.generate_next_block_including(*txid);
            st.scan_cached_blocks(h, 1);
        }

        // Check that there are sent outputs with the correct values.
        let confirmed_sent: Vec<Vec<_>> = txids
            .iter()
            .map(|sent_txid| st.wallet().get_sent_outputs(sent_txid).unwrap())
            .collect();

        // Verify that a status request has been generated for the second transaction of
        // the ZIP 320 pair.
        let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
        assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(*txids.last())));

        assert!(expected_step0_change > expected_ephemeral_spend);
        assert_eq!(confirmed_sent.len(), 2);
        assert_eq!(confirmed_sent[0].len(), 1);
        assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
        let OutputOfSentTx {
            value: ephemeral_v,
            external_recipient: to_addr,
            ephemeral_address,
        } = confirmed_sent[0][0].clone();
        assert_eq!(ephemeral_v, expected_ephemeral_balance);
        assert!(to_addr.is_some());
        assert_eq!(
            ephemeral_address,
            to_addr.map(|addr| (addr, expected_index)),
        );

        assert_eq!(confirmed_sent[1].len(), 1);
        assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &expected_ephemeral_spend && sent_to_addr == &Some(tex_addr));

        // Check that the transaction history matches what we expect.
        let tx_history = st.wallet().get_tx_history().unwrap();

        let tx_0 = tx_history
            .iter()
            .find(|tx| tx.txid() == *txids.first())
            .unwrap();
        let tx_1 = tx_history
            .iter()
            .find(|tx| tx.txid() == *txids.last())
            .unwrap();

        assert_eq!(tx_0.account_id(), &account_id);
        assert!(!tx_0.expired_unmined());
        assert_eq!(tx_0.has_change(), expected_step0_change.is_zero());
        assert!(!tx_0.is_shielding());
        assert_eq!(
            tx_0.account_value_delta(),
            -ZatBalance::from(expected_step0_fee),
        );

        assert_eq!(tx_1.account_id(), &account_id);
        assert!(!tx_1.expired_unmined());
        assert!(!tx_1.has_change());
        assert!(!tx_0.is_shielding());
        assert_eq!(
            tx_1.account_value_delta(),
            -ZatBalance::from(expected_ephemeral_balance),
        );

        let ending_balance = st.get_spendable_balance(account_id, 1);
        assert_eq!(initial_balance - total_sent, ending_balance.into());

        (ephemeral_address.unwrap().0, txids, ending_balance)
    };

    // Each transfer should use a different ephemeral address.
    let (ephemeral0, _, bal_0) = run_test(&mut st, 0, Zatoshis::ZERO);
    let (ephemeral1, _, _) = run_test(&mut st, 1, bal_0);
    assert_ne!(ephemeral0, ephemeral1);

    let height = add_orchard_funds(&mut st, single_note_value);

    assert_matches!(
        ephemeral0,
        Address::Transparent(TransparentAddress::PublicKeyHash(_))
    );

    // Simulate another wallet sending to an ephemeral address with an index
    // within the current gap limit. The `PaysEphemeralTransparentAddress` error
    // prevents us from doing so straightforwardly, so we'll do it by building
    // a transaction and calling `store_decrypted_tx` with it.
    let known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, None)
        .unwrap();
    assert_eq!(
        known_addrs.len(),
        usize::try_from(gap_limits.ephemeral() + 2).unwrap()
    );

    // Check that the addresses are all distinct.
    let known_set: HashSet<_> = known_addrs.iter().map(|(addr, _)| addr).collect();
    assert_eq!(known_set.len(), known_addrs.len());
    // Check that the metadata is as expected.
    for (i, (_, meta)) in known_addrs.iter().enumerate() {
        assert_eq!(
            meta,
            &TransparentAddressMetadata::new(
                TransparentKeyScope::EPHEMERAL,
                NonHardenedChildIndex::from_index(i.try_into().unwrap()).unwrap()
            )
        );
    }

    let mut builder = Builder::new(
        *st.network(),
        height + 1,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
        },
    );
    let mut transparent_signing_set = TransparentSigningSet::new();
    let (colliding_addr, _) = &known_addrs[usize::try_from(gap_limits.ephemeral() - 1).unwrap()];
    let utxo_value = (single_note_value - MINIMUM_FEE).unwrap();
    assert_matches!(
        builder.add_transparent_output(colliding_addr, utxo_value),
        Ok(_)
    );
    let sk = account
        .usk()
        .transparent()
        .derive_secret_key(Scope::External.into(), default_index)
        .unwrap();
    let pubkey = transparent_signing_set.add_key(sk);
    let outpoint = OutPoint::fake();
    let txout = TxOut {
        script_pubkey: default_addr.script(),
        value: single_note_value,
    };
    // Add the fake input to our UTXO set so that we can ensure we  recognize the outpoint.
    st.wallet_mut()
        .put_received_transparent_utxo(
            &WalletTransparentOutput::from_parts(outpoint.clone(), txout.clone(), None).unwrap(),
        )
        .unwrap();

    assert_matches!(
        builder.add_transparent_input(pubkey, outpoint, txout),
        Ok(_)
    );
    let test_prover = LocalTxProver::bundled();
    let build_result = builder
        .build(
            &transparent_signing_set,
            &[],
            &[],
            OsRng,
            &test_prover,
            &test_prover,
            &zip317::FeeRule::standard(),
        )
        .unwrap();
    let txid = build_result.transaction().txid();

    // Now, store the transaction, pretending it has been mined (we will actually mine the block
    // next). This will cause the the gap start to move & a new `gap_limits.ephemeral()` of
    // addresses to be created.
    let target_height = st.latest_cached_block().unwrap().height() + 1;
    st.wallet_mut()
        .store_decrypted_tx(DecryptedTransaction::new(
            Some(target_height),
            build_result.transaction(),
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
        ))
        .unwrap();

    // Mine the transaction & scan it so that it is will be detected as mined. Note that
    // `generate_next_block_including` does not actually do anything with fully-transparent
    // transactions; we're doing this just to get the mined block that we added via
    // `store_decrypted_tx` into the database.
    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);
    assert_eq!(h, target_height);

    // At this point the start of the gap should be at index `gap_limits.ephemeral()` and the new
    // size of the known address set should be `gap_limits.ephemeral() * 2`.
    let new_known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, None)
        .unwrap();
    assert_eq!(
        new_known_addrs.len(),
        usize::try_from(gap_limits.ephemeral() * 2).unwrap()
    );
    assert!(new_known_addrs.starts_with(&known_addrs));

    let reservation_should_succeed = |st: &mut TestState<_, DSF::DataStore, _>, n: u32| {
        let reserved = st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n.try_into().unwrap())
            .unwrap();
        assert_eq!(reserved.len(), usize::try_from(n).unwrap());
        reserved
    };
    let reservation_should_fail =
        |st: &mut TestState<_, DSF::DataStore, _>, n: u32, expected_bad_index| {
            assert_matches!(st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n.try_into().unwrap()),
            Err(e) if is_reached_gap_limit(&e, account_id, expected_bad_index));
        };

    let next_reserved = reservation_should_succeed(&mut st, 1);
    assert_eq!(
        next_reserved[0],
        known_addrs[usize::try_from(gap_limits.ephemeral()).unwrap()]
    );

    // The range of address indices that are safe to reserve now is
    // 0..(gap_limits.ephemeral() * 2 - 1)`, and we have already reserved or used
    // `gap_limits.ephemeral() + 1`, addresses, so trying to reserve another
    // `gap_limits.ephemeral()` should fail.
    reservation_should_fail(&mut st, gap_limits.ephemeral(), gap_limits.ephemeral() * 2);
    reservation_should_succeed(&mut st, gap_limits.ephemeral() - 1);
    // Now we've reserved everything we can, we can't reserve one more
    reservation_should_fail(&mut st, 1, gap_limits.ephemeral() * 2);
}
