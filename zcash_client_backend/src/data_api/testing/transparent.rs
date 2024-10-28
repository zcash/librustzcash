use crate::{
    data_api::{
        testing::{
            AddressType, DataStoreFactory, ShieldedProtocol, TestBuilder, TestCache, TestState,
        },
        wallet::input_selection::GreedyInputSelector,
        Account as _, Balance, InputSource, WalletRead, WalletWrite,
    },
    fees::{standard, DustOutputPolicy, StandardFeeRule},
    wallet::WalletTransparentOutput,
};
use assert_matches::assert_matches;
use sapling::zip32::ExtendedSpendingKey;
use zcash_primitives::{
    block::BlockHash,
    legacy::TransparentAddress,
    transaction::components::{amount::NonNegativeAmount, OutPoint, TxOut},
};
use zcash_protocol::local_consensus::LocalNetwork;

use super::TestAccount;

fn check_balance<DSF>(
    st: &TestState<impl TestCache, <DSF as DataStoreFactory>::DataStore, LocalNetwork>,
    account: &TestAccount<<DSF as DataStoreFactory>::Account>,
    taddr: &TransparentAddress,
    min_confirmations: u32,
    expected: &Balance,
) where
    DSF: DataStoreFactory,
{
    // Check the wallet summary returns the expected transparent balance.
    let summary = st
        .wallet()
        .get_wallet_summary(min_confirmations)
        .unwrap()
        .unwrap();
    let balance = summary.account_balances().get(&account.id()).unwrap();

    #[allow(deprecated)]
    let old_unshielded_value = balance.unshielded();
    assert_eq!(old_unshielded_value, expected.total());
    assert_eq!(balance.unshielded_balance(), expected);

    // Check the older APIs for consistency.
    let mempool_height = st.wallet().chain_height().unwrap().unwrap() + 1;
    assert_eq!(
        st.wallet()
            .get_transparent_balances(account.id(), mempool_height)
            .unwrap()
            .get(taddr)
            .cloned()
            .unwrap_or(NonNegativeAmount::ZERO),
        expected.total(),
    );
    assert_eq!(
        st.wallet()
            .get_spendable_transparent_outputs(taddr, mempool_height, 0)
            .unwrap()
            .into_iter()
            .map(|utxo| utxo.value())
            .sum::<Option<NonNegativeAmount>>(),
        Some(expected.spendable_value()),
    );

    // we currently treat min_confirmation the same regardless they are 0 or 1
    assert_eq!(
        st.wallet()
            .get_spendable_transparent_outputs(taddr, mempool_height, 1)
            .unwrap()
            .into_iter()
            .map(|utxo| utxo.value())
            .sum::<Option<NonNegativeAmount>>(),
        Some(expected.spendable_value()),
    );
}

pub fn put_received_transparent_utxo<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
    <<DSF as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug + PartialEq,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let birthday = st.test_account().unwrap().birthday().height();
    let account_id = st.test_account().unwrap().id();
    let uaddr = st
        .wallet()
        .get_current_address(account_id)
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

    let height_1 = birthday + 12345;
    st.wallet_mut().update_chain_tip(height_1).unwrap();

    let bal_absent = st
        .wallet()
        .get_transparent_balances(account_id, height_1)
        .unwrap();
    assert!(bal_absent.is_empty());

    // Create a fake transparent output.
    let value = NonNegativeAmount::const_from_u64(100000);
    let outpoint = OutPoint::fake();
    let txout = TxOut {
        value,
        script_pubkey: taddr.script(),
    };

    // Pretend the output's transaction was mined at `height_1`.
    let utxo = WalletTransparentOutput::from_parts(outpoint.clone(), txout.clone(), Some(height_1))
        .unwrap();
    let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
    assert_matches!(res0, Ok(_));

    // Confirm that we see the output unspent as of `height_1`.
    assert_matches!(
        st.wallet().get_spendable_transparent_outputs(
            taddr,
            height_1,
            0
        ).as_deref(),
        Ok([ret]) if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo.outpoint(), utxo.txout(), Some(height_1))
    );
    assert_matches!(
        st.wallet().get_unspent_transparent_output(utxo.outpoint()),
        Ok(Some(ret)) if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo.outpoint(), utxo.txout(), Some(height_1))
    );

    // Change the mined height of the UTXO and upsert; we should get back
    // the same `UtxoId`.
    let height_2 = birthday + 34567;
    st.wallet_mut().update_chain_tip(height_2).unwrap();
    let utxo2 = WalletTransparentOutput::from_parts(outpoint, txout, Some(height_2)).unwrap();
    let res1 = st.wallet_mut().put_received_transparent_utxo(&utxo2);
    assert_matches!(res1, Ok(id) if id == res0.unwrap());

    // Confirm that we no longer see any unspent outputs as of `height_1`.
    assert_matches!(
        st.wallet()
            .get_spendable_transparent_outputs(taddr, height_1, 0)
            .as_deref(),
        Ok(&[])
    );

    // We can still look up the specific output, and it has the expected height.
    assert_matches!(
        st.wallet().get_unspent_transparent_output(utxo2.outpoint()),
        Ok(Some(ret)) if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo2.outpoint(), utxo2.txout(), Some(height_2))
    );

    // If we include `height_2` then the output is returned.
    assert_matches!(
        st.wallet()
            .get_spendable_transparent_outputs(taddr, height_2, 0)
            .as_deref(),
        Ok([ret]) if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo.outpoint(), utxo.txout(), Some(height_2))
    );

    assert_matches!(
        st.wallet().get_transparent_balances(account_id, height_2),
        Ok(h) if h.get(taddr) == Some(&value)
    );
}

pub fn transparent_balance_across_shielding<DSF>(dsf: DSF, cache: impl TestCache)
where
    DSF: DataStoreFactory,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let uaddr = st
        .wallet()
        .get_current_address(account.id())
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

    // Initialize the wallet with chain data that has no shielded notes for us.
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let not_our_value = NonNegativeAmount::const_from_u64(10000);
    let (start_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..10 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }
    st.scan_cached_blocks(start_height, 10);

    // The wallet starts out with zero balance.
    check_balance::<DSF>(&st, &account, taddr, 0, &Balance::ZERO);
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &Balance::ZERO);

    // Create a fake transparent output.
    let value = NonNegativeAmount::from_u64(100000).unwrap();
    let txout = TxOut {
        value,
        script_pubkey: taddr.script(),
    };

    // Pretend the output was received in the chain tip.
    let height = st.wallet().chain_height().unwrap().unwrap();
    let utxo = WalletTransparentOutput::from_parts(OutPoint::fake(), txout, Some(height)).unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // The wallet should detect the balance as available
    let mut zero_or_one_conf_value = Balance::ZERO;

    // add the spendable value to the expected balance
    zero_or_one_conf_value.add_spendable_value(value).unwrap();

    check_balance::<DSF>(&st, &account, taddr, 0, &zero_or_one_conf_value);
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &zero_or_one_conf_value);

    // Shield the output.
    let input_selector = GreedyInputSelector::new();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedProtocol::Sapling,
        DustOutputPolicy::default(),
    );
    let txid = st
        .shield_transparent_funds(
            &input_selector,
            &change_strategy,
            value,
            account.usk(),
            &[*taddr],
            account.id(),
            1,
        )
        .unwrap()[0];

    // The wallet should have zero transparent balance, because the shielding
    // transaction can be mined.
    check_balance::<DSF>(&st, &account, taddr, 0, &Balance::ZERO);
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &Balance::ZERO);

    // Mine the shielding transaction.
    let (mined_height, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(mined_height, 1);

    // The wallet should still have zero transparent balance.
    check_balance::<DSF>(&st, &account, taddr, 0, &Balance::ZERO);
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &Balance::ZERO);

    // Unmine the shielding transaction via a reorg.
    st.wallet_mut()
        .truncate_to_height(mined_height - 1)
        .unwrap();
    assert_eq!(st.wallet().chain_height().unwrap(), Some(mined_height - 1));

    // The wallet should still have zero transparent balance.
    check_balance::<DSF>(&st, &account, taddr, 0, &Balance::ZERO);
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &Balance::ZERO);

    // Expire the shielding transaction.
    let expiry_height = st
        .wallet()
        .get_transaction(txid)
        .unwrap()
        .expect("Transaction exists in the wallet.")
        .expiry_height();
    st.wallet_mut().update_chain_tip(expiry_height).unwrap();

    check_balance::<DSF>(&st, &account, taddr, 0, &zero_or_one_conf_value);
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &zero_or_one_conf_value);
}

/// This test attempts to verify that transparent funds spendability is
/// accounted for properly given the different minimum confirmations values
/// that can be set when querying for balances.
pub fn transparent_balance_spendability<DSF>(dsf: DSF, cache: impl TestCache)
where
    DSF: DataStoreFactory,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let uaddr = st
        .wallet()
        .get_current_address(account.id())
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

    // Initialize the wallet with chain data that has no shielded notes for us.
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let not_our_value = NonNegativeAmount::const_from_u64(10000);
    let (start_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..10 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }
    st.scan_cached_blocks(start_height, 10);

    // The wallet starts out with zero balance.
    check_balance::<DSF>(
        &st as &TestState<_, DSF::DataStore, _>,
        &account,
        taddr,
        0,
        &Balance::ZERO,
    );
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &Balance::ZERO);

    // Create a fake transparent output.
    let value = NonNegativeAmount::from_u64(100000).unwrap();
    let txout = TxOut {
        value,
        script_pubkey: taddr.script(),
    };

    // Pretend the output was received in the chain tip.
    let height = st.wallet().chain_height().unwrap().unwrap();
    let utxo = WalletTransparentOutput::from_parts(OutPoint::fake(), txout, Some(height)).unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // The wallet should detect the balance as available
    let mut zero_or_one_conf_value = Balance::ZERO;

    // add the spendable value to the expected balance
    zero_or_one_conf_value.add_spendable_value(value).unwrap();

    check_balance::<DSF>(&st, &account, taddr, 0, &zero_or_one_conf_value);
    // we currently treat min_confirmation the same regardless they are 0 or 1
    check_balance::<DSF>(&st, &account, taddr, 1, &zero_or_one_conf_value);

    // now if we increase the number of confirmations our spendable balance should
    // be zero and the total balance equal to `value`
    let mut not_confirmed_yet_value = Balance::ZERO;

    not_confirmed_yet_value
        .add_pending_spendable_value(value)
        .unwrap();

    check_balance::<DSF>(&st, &account, taddr, 2, &not_confirmed_yet_value);

    st.generate_empty_block();

    // now we generate one more block and the balance should be the same as when the
    // check_balance function was called with zero or one confirmation.
    check_balance::<DSF>(&st, &account, taddr, 2, &zero_or_one_conf_value);
}
