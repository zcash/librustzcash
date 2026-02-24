use std::collections::BTreeMap;

use assert_matches::assert_matches;

use ::transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use sapling::zip32::ExtendedSpendingKey;
use zcash_keys::{
    address::Address,
    keys::{UnifiedAddressRequest, transparent::gap_limits::GapLimits},
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{local_consensus::LocalNetwork, value::Zatoshis};

use crate::{
    data_api::{
        Account as _, Balance, InputSource as _, WalletRead as _, WalletTest as _, WalletWrite,
        testing::{
            AddressType, DataStoreFactory, ShieldedProtocol, TestBuilder, TestCache, TestState,
        },
        wallet::{
            ConfirmationsPolicy, TargetHeight, decrypt_and_store_transaction,
            input_selection::GreedyInputSelector,
        },
    },
    fees::{DustOutputPolicy, StandardFeeRule, standard},
    wallet::WalletTransparentOutput,
};

#[cfg(feature = "zip-48")]
use {
    crate::data_api::{AccountBirthday, AccountSource, chain::ChainState},
    ::transparent::keys::NonHardenedChildIndex,
    ::transparent::zip48::{AccountPrivKey, FullViewingKey},
    zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters},
    zip32::AccountId,
};

/// Which kind of account to test against.
#[derive(Clone, Copy, Debug)]
pub enum TransparentAccountType {
    Derived,
    #[cfg(feature = "zip-48")]
    Zip48,
}

/// Checks whether the transparent balance of the given account is as `expected`
/// considering the `confirmations_policy`.
fn check_balance<DSF>(
    st: &TestState<impl TestCache, <DSF as DataStoreFactory>::DataStore, LocalNetwork>,
    account_id: &<DSF as DataStoreFactory>::AccountId,
    taddr: &TransparentAddress,
    confirmations_policy: ConfirmationsPolicy,
    expected: &Balance,
) where
    DSF: DataStoreFactory,
{
    // Check the wallet summary returns the expected transparent balance.
    let summary = st
        .wallet()
        .get_wallet_summary(confirmations_policy)
        .unwrap()
        .unwrap();
    let balance = summary.account_balances().get(account_id).unwrap();

    #[allow(deprecated)]
    let old_unshielded_value = balance.unshielded();
    assert_eq!(old_unshielded_value, expected.total());
    assert_eq!(balance.unshielded_balance(), expected);

    // Check the older APIs for consistency.
    let target_height = TargetHeight::from(st.wallet().chain_height().unwrap().unwrap() + 1);
    assert_eq!(
        st.wallet()
            .get_transparent_balances(*account_id, target_height, confirmations_policy)
            .unwrap()
            .get(taddr)
            .cloned()
            .map_or(Zatoshis::ZERO, |(_, b)| b.spendable_value()),
        expected.total(),
    );
    assert_eq!(
        st.wallet()
            .get_spendable_transparent_outputs(taddr, target_height, confirmations_policy)
            .unwrap()
            .into_iter()
            .map(|utxo| utxo.value())
            .sum::<Option<Zatoshis>>(),
        Some(expected.spendable_value()),
    );
}

/// Creates a ZIP 48 test account and returns its ID, transparent address, and birthday height.
#[cfg(feature = "zip-48")]
fn create_zip48_test_account<Cache, DSF: DataStoreFactory>(
    st: &mut TestState<Cache, DSF::DataStore, LocalNetwork>,
) -> (DSF::AccountId, TransparentAddress, BlockHeight)
where
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let birthday = AccountBirthday::from_parts(
        ChainState::empty(
            st.network()
                .activation_height(NetworkUpgrade::Sapling)
                .unwrap()
                - 1,
            BlockHash([0; 32]),
        ),
        None,
    );

    // Create a 2-of-3 FVK from three deterministic seeds.
    let account_id_zip32 = AccountId::ZERO;
    let seeds: [&[u8; 32]; 3] = [&[1; 32], &[2; 32], &[3; 32]];
    let pubkeys: Vec<_> = seeds
        .iter()
        .map(|seed| {
            AccountPrivKey::from_seed(st.network(), *seed, account_id_zip32)
                .unwrap()
                .to_account_pubkey()
        })
        .collect();

    let fvk = FullViewingKey::standard(2, pubkeys).unwrap();

    let account = st
        .wallet_mut()
        .import_account_zip48_multisig("zip48-test", &fvk, &birthday)
        .unwrap();

    let account_id = account.id();
    let (taddr, _redeem) = fvk.derive_address(zip32::Scope::External, NonHardenedChildIndex::ZERO);
    let birthday_height = birthday.height();

    (account_id, taddr, birthday_height)
}

pub fn put_received_transparent_utxo<DSF>(dsf: DSF, account_type: TransparentAccountType)
where
    DSF: DataStoreFactory,
    <<DSF as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug + PartialEq,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let (mut st, account_id, taddr, birthday) = match account_type {
        TransparentAccountType::Derived => {
            let st = TestBuilder::new()
                .with_data_store_factory(dsf)
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let birthday = st.test_account().unwrap().birthday().height();
            let account_id = st.test_account().unwrap().id();
            let uaddr = st
                .wallet()
                .get_last_generated_address_matching(
                    account_id,
                    UnifiedAddressRequest::AllAvailableKeys,
                )
                .unwrap()
                .unwrap();
            let taddr = *uaddr.transparent().unwrap();

            (st, account_id, taddr, birthday)
        }
        #[cfg(feature = "zip-48")]
        TransparentAccountType::Zip48 => {
            let mut st = TestBuilder::new().with_data_store_factory(dsf).build();

            let (account_id, taddr, birthday) = create_zip48_test_account::<_, DSF>(&mut st);
            (st, account_id, taddr, birthday)
        }
    };

    let height_1 = birthday + 12345;
    st.wallet_mut().update_chain_tip(height_1).unwrap();

    let bal_absent = st
        .wallet()
        .get_transparent_balances(
            account_id,
            TargetHeight::from(height_1 + 1),
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    assert!(bal_absent.is_empty());

    // Create a fake transparent output.
    let value = Zatoshis::const_from_u64(100000);
    let outpoint = OutPoint::fake();
    let txout = TxOut::new(value, taddr.script().into());

    // Pretend the output's transaction was mined at `height_1`.
    let utxo = WalletTransparentOutput::from_parts(outpoint.clone(), txout.clone(), Some(height_1))
        .unwrap();
    let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
    assert_matches!(res0, Ok(_));

    let target_height = TargetHeight::from(height_1 + 1);
    // Confirm that we see the output unspent as of `height_1`.
    assert_matches!(
        st.wallet().get_spendable_transparent_outputs(
            &taddr,
            target_height,
            ConfirmationsPolicy::MIN
        ).as_deref(),
        Ok([ret])
        if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo.outpoint(), utxo.txout(), Some(height_1))
    );
    assert_matches!(
        st.wallet().get_unspent_transparent_output(utxo.outpoint(), target_height),
        Ok(Some(ret))
        if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo.outpoint(), utxo.txout(), Some(height_1))
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
            .get_spendable_transparent_outputs(&taddr, target_height, ConfirmationsPolicy::MIN)
            .as_deref(),
        Ok(&[])
    );

    // We can still look up the specific output, and it has the expected height.
    assert_matches!(
        st.wallet().get_unspent_transparent_output(utxo2.outpoint(), target_height),
        Ok(Some(ret))
        if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo2.outpoint(), utxo2.txout(), Some(height_2))
    );

    // If we include `height_2` then the output is returned.
    assert_matches!(
        st.wallet()
            .get_spendable_transparent_outputs(&taddr, TargetHeight::from(height_2 + 1), ConfirmationsPolicy::MIN)
            .as_deref(),
        Ok([ret]) if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo.outpoint(), utxo.txout(), Some(height_2))
    );

    assert_matches!(
        st.wallet().get_transparent_balances(
            account_id,
            TargetHeight::from(height_2 + 1),
            ConfirmationsPolicy::MIN
        ),
        Ok(h) if h.get(&taddr).map(|(_, b)| b.spendable_value()) == Some(value)
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
        .get_last_generated_address_matching(account.id(), UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

    // Initialize the wallet with chain data that has no shielded notes for us.
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let not_our_value = Zatoshis::const_from_u64(10000);
    let (start_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..10 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }
    st.scan_cached_blocks(start_height, 10);

    // The wallet starts out with zero balance.
    check_balance::<DSF>(
        &st,
        &account.id(),
        taddr,
        ConfirmationsPolicy::MIN,
        &Balance::ZERO,
    );

    // Create a fake transparent output.
    let value = Zatoshis::from_u64(100000).unwrap();
    let txout = TxOut::new(value, taddr.script().into());

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

    check_balance::<DSF>(
        &st,
        &account.id(),
        taddr,
        ConfirmationsPolicy::MIN,
        &zero_or_one_conf_value,
    );

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
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    // The wallet should have zero transparent balance, because the shielding
    // transaction can be mined.
    check_balance::<DSF>(
        &st,
        &account.id(),
        taddr,
        ConfirmationsPolicy::MIN,
        &Balance::ZERO,
    );

    // Mine the shielding transaction.
    let (mined_height, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(mined_height, 1);

    // The wallet should still have zero transparent balance.
    check_balance::<DSF>(
        &st,
        &account.id(),
        taddr,
        ConfirmationsPolicy::MIN,
        &Balance::ZERO,
    );

    // Unmine the shielding transaction via a reorg.
    st.wallet_mut()
        .truncate_to_height(mined_height - 1)
        .unwrap();
    assert_eq!(st.wallet().chain_height().unwrap(), Some(mined_height - 1));

    // The wallet should still have zero transparent balance.
    check_balance::<DSF>(
        &st,
        &account.id(),
        taddr,
        ConfirmationsPolicy::MIN,
        &Balance::ZERO,
    );

    // Expire the shielding transaction.
    let expiry_height = st
        .wallet()
        .get_transaction(txid)
        .unwrap()
        .expect("Transaction exists in the wallet.")
        .expiry_height();
    st.wallet_mut().update_chain_tip(expiry_height).unwrap();

    check_balance::<DSF>(
        &st,
        &account.id(),
        taddr,
        ConfirmationsPolicy::MIN,
        &zero_or_one_conf_value,
    );
}

/// This test attempts to verify that transparent funds spendability is
/// accounted for properly given the different minimum confirmations values
/// that can be set when querying for balances.
pub fn transparent_balance_spendability<DSF>(
    dsf: DSF,
    cache: impl TestCache,
    account_type: TransparentAccountType,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let (mut st, account_id, taddr) = match account_type {
        TransparentAccountType::Derived => {
            let st = TestBuilder::new()
                .with_data_store_factory(dsf)
                .with_block_cache(cache)
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let account = st.test_account().cloned().unwrap();
            let uaddr = st
                .wallet()
                .get_last_generated_address_matching(
                    account.id(),
                    UnifiedAddressRequest::AllAvailableKeys,
                )
                .unwrap()
                .unwrap();
            let taddr = *uaddr.transparent().unwrap();

            (st, account.id(), taddr)
        }
        #[cfg(feature = "zip-48")]
        TransparentAccountType::Zip48 => {
            let mut st = TestBuilder::new()
                .with_data_store_factory(dsf)
                .with_block_cache(cache)
                .build();

            let (account_id, taddr, _birthday) = create_zip48_test_account::<_, DSF>(&mut st);
            (st, account_id, taddr)
        }
    };

    // Initialize the wallet with chain data that has no shielded notes for us.
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let not_our_value = Zatoshis::const_from_u64(10000);
    let (start_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..10 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }
    st.scan_cached_blocks(start_height, 10);

    // The wallet starts out with zero balance.
    check_balance::<DSF>(
        &st as &TestState<_, DSF::DataStore, _>,
        &account_id,
        &taddr,
        ConfirmationsPolicy::MIN,
        &Balance::ZERO,
    );

    // Create a fake transparent output.
    let value = Zatoshis::from_u64(100000).unwrap();
    let txout = TxOut::new(value, taddr.script().into());

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

    check_balance::<DSF>(
        &st,
        &account_id,
        &taddr,
        ConfirmationsPolicy::MIN,
        &zero_or_one_conf_value,
    );

    // now if we increase the number of confirmations our spendable balance should
    // be zero and the total balance equal to `value`
    let mut not_confirmed_yet_value = Balance::ZERO;

    not_confirmed_yet_value
        .add_pending_spendable_value(value)
        .unwrap();

    check_balance::<DSF>(
        &st,
        &account_id,
        &taddr,
        ConfirmationsPolicy::new_symmetrical_unchecked(2, false),
        &not_confirmed_yet_value,
    );

    // Add one extra block
    st.generate_empty_block();

    // Scan that block
    st.scan_cached_blocks(height, 1);

    // now we generate one more block and the balance should be the same as when the
    // check_balance function was called with zero or one confirmation.
    st.generate_empty_block();
    st.scan_cached_blocks(height + 1, 1);

    check_balance::<DSF>(
        &st,
        &account_id,
        &taddr,
        ConfirmationsPolicy::new_symmetrical_unchecked(2, true),
        &zero_or_one_conf_value,
    );
}

pub fn zip32_gap_limits<DSF>(ds_factory: DSF, cache: impl TestCache, gap_limits: GapLimits)
where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_gap_limits(gap_limits)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let test_account = st.test_account().cloned().unwrap();
    let account_uuid = test_account.account().id();
    let ufvk = test_account.account().ufvk().unwrap().clone();

    let external_taddrs = st
        .wallet()
        .get_transparent_receivers(account_uuid, false, true)
        .unwrap();
    assert_eq!(
        u32::try_from(external_taddrs.len()).unwrap(),
        gap_limits.external()
    );
    let internal_taddrs = st
        .wallet()
        .get_transparent_receivers(account_uuid, true, false)
        .unwrap();
    assert_eq!(
        u32::try_from(internal_taddrs.len()).unwrap(),
        gap_limits.external() + gap_limits.internal()
    );
    let ephemeral_taddrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_uuid, None)
        .unwrap();
    assert_eq!(
        u32::try_from(ephemeral_taddrs.len()).unwrap(),
        gap_limits.ephemeral()
    );

    // Add some funds to the wallet
    let (h0, _, _) = st.generate_next_block(
        &ufvk.sapling().unwrap(),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(1000000),
    );
    st.scan_cached_blocks(h0, 1);

    // The previous operation was shielded-only, but unified address usage within the
    // valid transparent child index range still count towards the gap limit, so this
    // updates the gap limit by the index of the default Sapling receiver
    let external_taddrs = st
        .wallet()
        .get_transparent_receivers(account_uuid, false, true)
        .unwrap();
    assert_eq!(
        u32::try_from(external_taddrs.len()).unwrap(),
        gap_limits.external()
            + (u32::try_from(ufvk.sapling().unwrap().default_address().0).unwrap() + 1)
    );

    // Pick an address half way through the set of external taddrs
    let external_taddrs_sorted = external_taddrs
        .into_iter()
        .filter_map(|(addr, meta)| meta.address_index().map(|i| (i, addr)))
        .collect::<BTreeMap<_, _>>();
    let to = Address::from(
        *external_taddrs_sorted
            .get(&transparent::keys::NonHardenedChildIndex::from_index(4).unwrap())
            .expect("An address exists at index 4."),
    )
    .to_zcash_address(st.network());

    // Create a transaction & scan the block. Since the txid corresponds to one our wallet
    // generated, this should cause the gap limit to be bumped (generating addresses with index
    // 10..15)
    let txids = st
        .create_standard_transaction(&test_account, to, Zatoshis::const_from_u64(20000))
        .unwrap();
    let (h1, _) = st.generate_next_block_including(txids.head);

    // At this point, the transaction has been created, but since it has not been mined it does
    // not cause an update to the gap limit; we have to wait for the transaction to actually be
    // mined or we could bump the gap limit too soon and start generating addresses that will
    // never be inspected on wallet recovery.
    let external_taddrs = st
        .wallet()
        .get_transparent_receivers(account_uuid, false, true)
        .unwrap();
    assert_eq!(
        u32::try_from(external_taddrs.len()).unwrap(),
        gap_limits.external()
            + (u32::try_from(ufvk.sapling().unwrap().default_address().0).unwrap() + 1)
    );

    // Mine the block, then use `decrypt_and_store_transaction` to ensure that the wallet sees
    // the transaction as mined (since transparent handling doesn't get this from
    // `scan_cached_blocks`)
    st.scan_cached_blocks(h1, 1);
    let tx = st.wallet().get_transaction(txids.head).unwrap().unwrap();
    decrypt_and_store_transaction(&st.network().clone(), st.wallet_mut(), &tx, Some(h1)).unwrap();

    // Now that the transaction has been mined, the gap limit should have increased.
    let external_taddrs = st
        .wallet()
        .get_transparent_receivers(account_uuid, false, true)
        .unwrap();
    assert_eq!(
        u32::try_from(external_taddrs.len()).unwrap(),
        gap_limits.external() + 5
    );

    // The utxo query height should be equal to the minimum mined height among transactions
    // sent to any of the set of {addresses in the gap limit range | address prior to the gap}.
    let query_height = st.wallet().utxo_query_height(account_uuid).unwrap();
    assert_eq!(query_height, h0);
}

/// Tests that a ZIP 48 multisig account can be imported and its properties are correct.
#[cfg(feature = "zip-48")]
pub fn import_account_zip48_multisig<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
    <<DSF as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug + PartialEq,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestBuilder::new().with_data_store_factory(dsf).build();

    let birthday = AccountBirthday::from_parts(
        ChainState::empty(
            st.network()
                .activation_height(NetworkUpgrade::Sapling)
                .unwrap()
                - 1,
            BlockHash([0; 32]),
        ),
        None,
    );

    // Create a 2-of-3 FVK from three deterministic seeds.
    let account_id_zip32 = AccountId::ZERO;
    let seeds: [&[u8; 32]; 3] = [&[1; 32], &[2; 32], &[3; 32]];
    let pubkeys: Vec<_> = seeds
        .iter()
        .map(|seed| {
            AccountPrivKey::from_seed(st.network(), *seed, account_id_zip32)
                .unwrap()
                .to_account_pubkey()
        })
        .collect();

    let fvk = FullViewingKey::standard(2, pubkeys).unwrap();

    // Import succeeds.
    let account = st
        .wallet_mut()
        .import_account_zip48_multisig("zip48-test", &fvk, &birthday)
        .unwrap();

    let account_id = account.id();

    // Account source is Zip48.
    assert_matches!(account.source(), AccountSource::Zip48);

    // Derive the first external address from the FVK and verify it's a P2SH address.
    let (expected_taddr, _redeem) =
        fvk.derive_address(zip32::Scope::External, NonHardenedChildIndex::ZERO);

    // Can receive UTXOs at the P2SH address.
    let height = birthday.height() + 12345;
    st.wallet_mut().update_chain_tip(height).unwrap();

    let value = Zatoshis::const_from_u64(50000);
    let outpoint = OutPoint::fake();
    let txout = TxOut::new(value, expected_taddr.script().into());
    let utxo = WalletTransparentOutput::from_parts(outpoint, txout, Some(height)).unwrap();
    let res = st.wallet_mut().put_received_transparent_utxo(&utxo);
    assert_matches!(res, Ok(_));

    // Balance tracking works after UTXO receipt.
    assert_matches!(
        st.wallet().get_transparent_balances(
            account_id,
            TargetHeight::from(height + 1),
            ConfirmationsPolicy::MIN
        ),
        Ok(h) if h.get(&expected_taddr).map(|(_, b)| b.spendable_value()) == Some(value)
    );
}
