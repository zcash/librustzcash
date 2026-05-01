use std::collections::BTreeMap;

use assert_matches::assert_matches;

use sapling::zip32::ExtendedSpendingKey;
use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use zcash_keys::{
    address::Address,
    keys::{UnifiedAddressRequest, transparent::gap_limits::GapLimits},
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{local_consensus::LocalNetwork, value::Zatoshis};

#[cfg(feature = "transparent-key-import")]
use {
    crate::wallet::TransparentAddressSource,
    zcash_script::{descriptor::sh, script},
};

use super::TestAccount;
use crate::{
    data_api::{
        Account as _, Balance, InputSource as _, TransparentOutputFilter, WalletRead as _,
        WalletTest as _, WalletWrite,
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

/// Checks whether the transparent balance of the given test `account` is as `expected`
/// considering the `confirmations_policy`.
fn check_balance<DSF>(
    st: &TestState<impl TestCache, <DSF as DataStoreFactory>::DataStore, LocalNetwork>,
    account: &TestAccount<<DSF as DataStoreFactory>::Account>,
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
    let balance = summary.account_balances().get(&account.id()).unwrap();

    #[allow(deprecated)]
    let old_unshielded_value = balance.unshielded();
    assert_eq!(old_unshielded_value, expected.total());
    assert_eq!(balance.unshielded_balance(), expected);

    // Check the older APIs for consistency.
    let target_height = TargetHeight::from(st.wallet().chain_height().unwrap().unwrap() + 1);
    assert_eq!(
        st.wallet()
            .get_transparent_balances(account.id(), target_height, confirmations_policy)
            .unwrap()
            .get(taddr)
            .cloned()
            .map_or(Zatoshis::ZERO, |(_, b)| b.spendable_value()),
        expected.total(),
    );
    assert_eq!(
        st.wallet()
            .get_spendable_transparent_outputs(
                taddr,
                target_height,
                confirmations_policy,
                TransparentOutputFilter::All
            )
            .unwrap()
            .into_iter()
            .map(|utxo| utxo.value())
            .sum::<Option<Zatoshis>>(),
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
        .get_last_generated_address_matching(account_id, UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

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
            taddr,
            target_height,
            ConfirmationsPolicy::MIN,
            TransparentOutputFilter::All,
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
            .get_spendable_transparent_outputs(
                taddr,
                target_height,
                ConfirmationsPolicy::MIN,
                TransparentOutputFilter::All
            )
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
            .get_spendable_transparent_outputs(taddr, TargetHeight::from(height_2 + 1), ConfirmationsPolicy::MIN, TransparentOutputFilter::All)
            .as_deref(),
        Ok([ret]) if (ret.outpoint(), ret.txout(), ret.mined_height()) == (utxo.outpoint(), utxo.txout(), Some(height_2))
    );

    assert_matches!(
        st.wallet().get_transparent_balances(
            account_id,
            TargetHeight::from(height_2 + 1),
            ConfirmationsPolicy::MIN
        ),
        Ok(h) if h.get(taddr).map(|(_, b)| b.spendable_value()) == Some(value)
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
        &account,
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
        &account,
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
        &account,
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
        &account,
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
        &account,
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
        &account,
        taddr,
        ConfirmationsPolicy::MIN,
        &zero_or_one_conf_value,
    );
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
        &st as &TestState<_, DSF::DataStore, _>,
        &account,
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
        &account,
        taddr,
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
        &account,
        taddr,
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
        &account,
        taddr,
        ConfirmationsPolicy::new_symmetrical_unchecked(2, true),
        &zero_or_one_conf_value,
    );
}

pub fn gap_limits<DSF>(ds_factory: DSF, cache: impl TestCache, gap_limits: GapLimits)
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

/// Builds a test 1-of-1 multisig redeem script from a single keypair.
#[cfg(feature = "transparent-key-import")]
fn build_test_redeem_script() -> (script::Redeem, secp256k1::SecretKey) {
    use secp256k1::{Secp256k1, SecretKey};
    use zcash_script::pattern::check_multisig;

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    let pubkey = secret_key.public_key(&secp);
    let redeem_script = script::Component(
        check_multisig(1, &[&pubkey.serialize()], false)
            .unwrap()
            .into_iter()
            .collect(),
    );
    (redeem_script, secret_key)
}

/// Tests that importing a standalone transparent public key succeeds.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_pubkey<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    use secp256k1::{Secp256k1, SecretKey};

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    let pubkey = secret_key.public_key(&secp);
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_pubkey(account_id, pubkey),
        Ok(_)
    );
}

/// Tests that importing the same pubkey twice to the same account is idempotent.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_pubkey_idempotent<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    use secp256k1::{Secp256k1, SecretKey};

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    let pubkey = secret_key.public_key(&secp);

    // First import
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_pubkey(account_id, pubkey),
        Ok(_)
    );

    // Snapshot state after first import
    let receivers_before = st
        .wallet()
        .get_transparent_receivers(account_id, false, true)
        .unwrap();

    // Second import to same account should also succeed (idempotent)
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_pubkey(account_id, pubkey),
        Ok(_)
    );

    // Verify wallet state is unchanged
    let receivers_after = st
        .wallet()
        .get_transparent_receivers(account_id, false, true)
        .unwrap();

    assert_eq!(receivers_before.len(), receivers_after.len());

    let taddr = TransparentAddress::from_pubkey(&pubkey);
    let metadata = receivers_after
        .get(&taddr)
        .expect("address should be present");
    assert!(matches!(
        metadata.source(),
        TransparentAddressSource::StandalonePubkey(_)
    ));
}

/// Tests that importing the same pubkey to a different account fails.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_pubkey_conflict<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    use secp256k1::{Secp256k1, SecretKey};
    use secrecy::Secret;

    use crate::data_api::{AccountBirthday, chain::ChainState};
    use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account1_id = st.test_account().unwrap().id();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    let pubkey = secret_key.public_key(&secp);

    // Import to first account
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_pubkey(account1_id, pubkey),
        Ok(_)
    );

    // Create a second account
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
    let seed2 = Secret::new(vec![42u8; 32]);
    let (account2_id, _) = st
        .wallet_mut()
        .create_account("account2", &seed2, &birthday, None)
        .unwrap();

    // Import same pubkey to second account should fail
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_pubkey(account2_id, pubkey),
        Err(_)
    );
}

/// Tests that a UTXO received at a standalone P2PKH address is reflected in the wallet balance.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_pubkey_balance<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
    <<DSF as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use crate::data_api::wallet::ConfirmationsPolicy;
    use secp256k1::{Secp256k1, SecretKey};

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();
    let birthday = st.test_account().unwrap().birthday().height();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    let pubkey = secret_key.public_key(&secp);

    // Import the public key.
    st.wallet_mut()
        .import_standalone_transparent_pubkey(account_id, pubkey)
        .unwrap();

    // Derive the P2PKH address.
    let taddr = TransparentAddress::from_pubkey(&pubkey);

    let height = birthday + 1000;
    st.wallet_mut().update_chain_tip(height).unwrap();

    // Create a fake UTXO at the P2PKH address.
    let value = Zatoshis::const_from_u64(50_000);
    let outpoint = OutPoint::fake();
    let txout = TxOut::new(value, taddr.script().into());
    let utxo = WalletTransparentOutput::from_parts(outpoint, txout, Some(height)).unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // Verify the balance is reflected via get_transparent_balances.
    let target_height = TargetHeight::from(height + 1);
    let balances = st
        .wallet()
        .get_transparent_balances(account_id, target_height, ConfirmationsPolicy::MIN)
        .unwrap();
    assert_eq!(
        balances.get(&taddr).map(|(_, b)| b.spendable_value()),
        Some(value),
    );

    // Verify the UTXO is returned by get_spendable_transparent_outputs.
    let utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &taddr,
            target_height,
            ConfirmationsPolicy::MIN,
            TransparentOutputFilter::All,
        )
        .unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].value(), value);
}

/// Tests spending from a standalone P2PKH address by shielding its balance.
#[cfg(feature = "transparent-key-import")]
pub fn spend_from_standalone_pubkey<DSF>(dsf: DSF, cache: impl TestCache)
where
    DSF: DataStoreFactory,
{
    use crate::data_api::wallet::{self, SpendingKeys};
    use secp256k1::{Secp256k1, SecretKey};
    use std::collections::HashMap;

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();

    // Create a keypair and derive the P2PKH address.
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    let pubkey = secret_key.public_key(&secp);

    // Import the public key.
    st.wallet_mut()
        .import_standalone_transparent_pubkey(account_id, pubkey)
        .unwrap();

    // Derive the P2PKH address.
    let taddr = TransparentAddress::from_pubkey(&pubkey);

    // Initialize chain data with blocks (needed for shielding transaction creation).
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let not_our_value = Zatoshis::const_from_u64(10000);
    let (start_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..10 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }
    st.scan_cached_blocks(start_height, 10);

    // Create a fake UTXO at the P2PKH address.
    let value = Zatoshis::from_u64(100000).unwrap();
    let height = st.wallet().chain_height().unwrap().unwrap();
    let txout = TxOut::new(value, taddr.script().into());
    let utxo = WalletTransparentOutput::from_parts(OutPoint::fake(), txout, Some(height)).unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // Build SpendingKeys with the standalone key for the P2PKH address.
    let mut standalone_keys = HashMap::new();
    standalone_keys.insert(taddr, vec![secret_key]);
    let spending_keys = SpendingKeys::new(
        account.usk().clone(),
        #[cfg(feature = "transparent-key-import")]
        standalone_keys,
    );

    // Shield the P2PKH UTXO.
    let input_selector = GreedyInputSelector::new();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedProtocol::Sapling,
        DustOutputPolicy::default(),
    );

    let prover = ::zcash_proofs::prover::LocalTxProver::bundled();
    let network = *st.network();
    let txids = wallet::shield_transparent_funds(
        st.wallet_mut(),
        &network,
        &prover,
        &prover,
        &input_selector,
        &change_strategy,
        value,
        &spending_keys,
        &[taddr],
        account_id,
        ConfirmationsPolicy::MIN,
    )
    .unwrap();

    assert!(!txids.is_empty());

    // The wallet should have zero transparent balance after shielding.
    check_balance::<DSF>(
        &st,
        &account,
        &taddr,
        ConfirmationsPolicy::MIN,
        &Balance::ZERO,
    );

    // The shielded balance should now include the value minus the fee.
    let fee = st
        .get_tx_from_history(*txids.first())
        .unwrap()
        .unwrap()
        .fee_paid()
        .expect("fee should be known for wallet-created transactions");
    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .unwrap()
        .unwrap();
    let account_balance = summary.account_balances().get(&account_id).unwrap();
    assert_eq!(
        account_balance
            .sapling_balance()
            .change_pending_confirmation(),
        (value - fee).unwrap(),
    );
}

/// Tests that importing a standalone P2SH address succeeds and the address appears
/// in `get_transparent_receivers` with the correct `TransparentAddressSource`.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_p2sh<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();
    let (redeem_script, _) = build_test_redeem_script();

    // Import should succeed
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_script(account_id, redeem_script.clone()),
        Ok(_)
    );

    // Verify the address appears in get_transparent_receivers
    let receivers = st
        .wallet()
        .get_transparent_receivers(account_id, false, true)
        .unwrap();

    // The P2SH address derived from the redeem script should be present
    let script_pubkey = sh(&redeem_script);
    let expected_addr =
        TransparentAddress::from_script_pubkey(&script_pubkey).expect("valid P2SH address");

    let metadata = receivers
        .get(&expected_addr)
        .expect("address should be present");
    assert!(matches!(
        metadata.source(),
        TransparentAddressSource::StandaloneScript(_)
    ));
}

/// Tests that importing the same P2SH address twice to the same account is idempotent.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_p2sh_idempotent<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();
    let (redeem_script, _) = build_test_redeem_script();

    // First import
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_script(account_id, redeem_script.clone()),
        Ok(_)
    );

    // Snapshot state after first import
    let receivers_before = st
        .wallet()
        .get_transparent_receivers(account_id, false, true)
        .unwrap();

    // Second import to same account should also succeed (idempotent)
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_script(account_id, redeem_script.clone()),
        Ok(_)
    );

    // Verify wallet state is unchanged
    let receivers_after = st
        .wallet()
        .get_transparent_receivers(account_id, false, true)
        .unwrap();

    assert_eq!(receivers_before.len(), receivers_after.len());

    let script_pubkey = sh(&redeem_script);
    let expected_addr =
        TransparentAddress::from_script_pubkey(&script_pubkey).expect("valid P2SH address");
    let metadata = receivers_after
        .get(&expected_addr)
        .expect("address should be present");
    assert!(matches!(
        metadata.source(),
        TransparentAddressSource::StandaloneScript(_)
    ));
}

/// Tests that importing the same P2SH address to a different account fails.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_p2sh_conflict<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    use secrecy::Secret;

    use crate::data_api::{AccountBirthday, chain::ChainState};
    use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account1_id = st.test_account().unwrap().id();
    let (redeem_script, _) = build_test_redeem_script();

    // Import to first account
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_script(account1_id, redeem_script.clone()),
        Ok(_)
    );

    // Create a second account
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
    let seed2 = Secret::new(vec![42u8; 32]);
    let (account2_id, _) = st
        .wallet_mut()
        .create_account("account2", &seed2, &birthday, None)
        .unwrap();

    // Import same redeem script to second account should fail
    assert_matches!(
        st.wallet_mut()
            .import_standalone_transparent_script(account2_id, redeem_script),
        Err(_)
    );
}

/// Tests that a UTXO received at a standalone P2SH address is reflected in the wallet balance.
#[cfg(feature = "transparent-key-import")]
pub fn import_standalone_transparent_p2sh_balance<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
    <<DSF as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use crate::data_api::wallet::ConfirmationsPolicy;

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();
    let birthday = st.test_account().unwrap().birthday().height();

    let (redeem_script, _) = build_test_redeem_script();

    // Import the P2SH address.
    st.wallet_mut()
        .import_standalone_transparent_script(account_id, redeem_script.clone())
        .unwrap();

    // Derive the expected transparent address from the redeem script.
    let script_pubkey = sh(&redeem_script);
    let taddr = TransparentAddress::from_script_pubkey(&script_pubkey).expect("valid P2SH address");

    let height = birthday + 1000;
    st.wallet_mut().update_chain_tip(height).unwrap();

    // Create a fake UTXO at the P2SH address.
    let value = Zatoshis::const_from_u64(50_000);
    let outpoint = OutPoint::fake();
    let txout = TxOut::new(value, taddr.script().into());
    let utxo = WalletTransparentOutput::from_parts(outpoint, txout, Some(height)).unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // Verify the balance is reflected via get_transparent_balances.
    let target_height = TargetHeight::from(height + 1);
    let balances = st
        .wallet()
        .get_transparent_balances(account_id, target_height, ConfirmationsPolicy::MIN)
        .unwrap();
    assert_eq!(
        balances.get(&taddr).map(|(_, b)| b.spendable_value()),
        Some(value),
    );

    // Verify the UTXO is returned by get_spendable_transparent_outputs.
    let utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &taddr,
            target_height,
            ConfirmationsPolicy::MIN,
            TransparentOutputFilter::All,
        )
        .unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].value(), value);
}

/// Tests spending from a standalone P2SH (multisig) address by shielding its balance.
#[cfg(feature = "transparent-key-import")]
pub fn spend_from_standalone_p2sh<DSF>(dsf: DSF, cache: impl TestCache)
where
    DSF: DataStoreFactory,
{
    use crate::data_api::wallet::{self, SpendingKeys};
    use std::collections::HashMap;

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    // Build the redeem script and get the signing key.
    let (redeem_script, secret_key) = build_test_redeem_script();

    // Import the P2SH address.
    st.wallet_mut()
        .import_standalone_transparent_script(account_id, redeem_script.clone())
        .unwrap();

    // Derive the P2SH address.
    let script_pubkey = sh(&redeem_script);
    let taddr = TransparentAddress::from_script_pubkey(&script_pubkey).expect("valid P2SH address");

    // Initialize chain data with blocks (needed for shielding transaction creation).
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let not_our_value = Zatoshis::const_from_u64(10000);
    let (start_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..10 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }
    st.scan_cached_blocks(start_height, 10);

    // Create a fake UTXO at the P2SH address.
    let value = Zatoshis::from_u64(100000).unwrap();
    let height = st.wallet().chain_height().unwrap().unwrap();
    let txout = TxOut::new(value, taddr.script().into());
    let utxo = WalletTransparentOutput::from_parts(OutPoint::fake(), txout, Some(height)).unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // Build SpendingKeys with the standalone key for the P2SH address.
    let mut standalone_keys = HashMap::new();
    standalone_keys.insert(taddr, vec![secret_key]);
    let spending_keys = SpendingKeys::new(
        account.usk().clone(),
        #[cfg(feature = "transparent-key-import")]
        standalone_keys,
    );

    // Shield the P2SH UTXO.
    let input_selector = GreedyInputSelector::new();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedProtocol::Sapling,
        DustOutputPolicy::default(),
    );

    let prover = ::zcash_proofs::prover::LocalTxProver::bundled();
    let network = *st.network();
    let txids = wallet::shield_transparent_funds(
        st.wallet_mut(),
        &network,
        &prover,
        &prover,
        &input_selector,
        &change_strategy,
        value,
        &spending_keys,
        &[taddr],
        account_id,
        ConfirmationsPolicy::MIN,
    )
    .unwrap();

    assert!(!txids.is_empty());

    // The wallet should have zero transparent balance after shielding.
    check_balance::<DSF>(
        &st,
        &account,
        &taddr,
        ConfirmationsPolicy::MIN,
        &Balance::ZERO,
    );

    // The shielded balance should now include the value minus the fee.
    let fee = st
        .get_tx_from_history(*txids.first())
        .unwrap()
        .unwrap()
        .fee_paid()
        .expect("fee should be known for wallet-created transactions");
    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .unwrap()
        .unwrap();
    let account_balance = summary.account_balances().get(&account_id).unwrap();
    assert_eq!(
        account_balance
            .sapling_balance()
            .change_pending_confirmation(),
        (value - fee).unwrap(),
    );
}

/// Tests [`WalletWrite::mark_transparent_addresses_exposed`] by observing the effect on the
/// address's exposure metadata via
/// [`WalletRead::get_transparent_address_metadata`](crate::data_api::WalletRead::get_transparent_address_metadata).
pub fn mark_transparent_addresses_exposed<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    use crate::{data_api::WalletRead, wallet::Exposure};
    use zcash_protocol::consensus::BlockHeight;

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();
    let taddr = *st
        .wallet()
        .get_last_generated_address_matching(account_id, UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap()
        .transparent()
        .unwrap();

    let exposure_of = |st: &TestState<_, <DSF as DataStoreFactory>::DataStore, LocalNetwork>,
                       addr: &TransparentAddress|
     -> Exposure {
        st.wallet()
            .get_transparent_address_metadata(account_id, addr)
            .unwrap()
            .unwrap()
            .exposure()
    };

    // Calling with a very high height does not raise an already-recorded exposure,
    // and records the provided height if no prior exposure was tracked.
    let initial = exposure_of(&st, &taddr);
    let very_high = BlockHeight::from(u32::MAX);
    st.wallet_mut()
        .mark_transparent_addresses_exposed(&[(taddr, very_high)])
        .unwrap();
    match initial {
        Exposure::Exposed { at_height, .. } => assert_matches!(
            exposure_of(&st, &taddr),
            Exposure::Exposed { at_height: h, .. } if h == at_height
        ),
        Exposure::Unknown | Exposure::CannotKnow => assert_matches!(
            exposure_of(&st, &taddr),
            Exposure::Exposed { at_height: h, .. } if h == very_high
        ),
    }

    // Calling with a lower height lowers the recorded exposure.
    st.wallet_mut()
        .mark_transparent_addresses_exposed(&[(taddr, BlockHeight::from(0))])
        .unwrap();
    assert_matches!(
        exposure_of(&st, &taddr),
        Exposure::Exposed { at_height, .. } if at_height == BlockHeight::from(0)
    );

    // Calling with a higher height does not raise the recorded exposure.
    st.wallet_mut()
        .mark_transparent_addresses_exposed(&[(taddr, BlockHeight::from(100))])
        .unwrap();
    assert_matches!(
        exposure_of(&st, &taddr),
        Exposure::Exposed { at_height, .. } if at_height == BlockHeight::from(0)
    );

    // An address not tracked by the wallet must return an error.
    let unknown = TransparentAddress::PublicKeyHash([0u8; 20]);
    assert!(
        st.wallet_mut()
            .mark_transparent_addresses_exposed(&[(unknown, BlockHeight::from(1))])
            .is_err()
    );

    // An empty input is a no-op.
    st.wallet_mut()
        .mark_transparent_addresses_exposed(&[])
        .unwrap();
}

/// Tests that [`WalletWrite::mark_transparent_addresses_exposed`] correctly handles bulk
/// input: all addresses in a successful call must be marked, and an unrecognized address
/// must cause the entire call to be rolled back.
pub fn mark_transparent_addresses_exposed_bulk<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    use crate::{data_api::WalletRead, wallet::Exposure};
    use zcash_protocol::consensus::BlockHeight;

    let gap_limits = GapLimits::new(5, 2, 2);
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_gap_limits(gap_limits)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();

    let mut receivers = st
        .wallet()
        .get_transparent_receivers(account_id, false, true)
        .unwrap()
        .into_iter()
        .filter_map(|(addr, meta)| {
            let exposure = meta.exposure();
            meta.address_index().map(|i| (i.index(), addr, exposure))
        })
        .collect::<Vec<_>>();
    receivers.sort_by_key(|(i, _, _)| *i);

    // Use known-unexposed receivers for the bulk-success test, so that the post-call
    // recorded height is exactly the one we pass in regardless of any default exposure
    // that address generation may set on other receivers.
    let unexposed = receivers
        .iter()
        .copied()
        .filter(|(_, _, exposure)| matches!(exposure, Exposure::Unknown))
        .collect::<Vec<_>>();
    assert!(
        unexposed.len() >= 2,
        "account should have at least 2 unexposed derived receivers"
    );

    // Mark two unexposed addresses at distinct heights in a single bulk call.
    let (_idx_a, addr_a, _) = unexposed[0];
    let (_idx_b, addr_b, _) = unexposed[1];
    let height_a = BlockHeight::from(10);
    let height_b = BlockHeight::from(20);
    st.wallet_mut()
        .mark_transparent_addresses_exposed(&[(addr_a, height_a), (addr_b, height_b)])
        .unwrap();

    let exposure_of = |st: &TestState<_, <DSF as DataStoreFactory>::DataStore, LocalNetwork>,
                       addr: &TransparentAddress|
     -> Exposure {
        st.wallet()
            .get_transparent_address_metadata(account_id, addr)
            .unwrap()
            .unwrap()
            .exposure()
    };
    assert_matches!(
        exposure_of(&st, &addr_a),
        Exposure::Exposed { at_height, .. } if at_height == height_a
    );
    assert_matches!(
        exposure_of(&st, &addr_b),
        Exposure::Exposed { at_height, .. } if at_height == height_b
    );

    // Now attempt a bulk call where the second entry is unrecognized. The whole call must
    // fail, and the first entry must not have been partially applied. Pick a third
    // receiver distinct from `addr_a`/`addr_b` — its prior exposure state is irrelevant
    // since the assertion is preservation, not a specific height.
    let (idx_c, addr_c, _) = *receivers
        .iter()
        .find(|(_, addr, _)| *addr != addr_a && *addr != addr_b)
        .expect("account should have a third derived receiver");
    let before = exposure_of(&st, &addr_c);
    let unknown = TransparentAddress::PublicKeyHash([0x7u8; 20]);
    assert!(
        st.wallet_mut()
            .mark_transparent_addresses_exposed(&[
                (addr_c, BlockHeight::from(5)),
                (unknown, BlockHeight::from(5)),
            ])
            .is_err()
    );
    assert_eq!(
        exposure_of(&st, &addr_c),
        before,
        "exposure at index {idx_c} must not change when bulk call fails atomically"
    );
}

/// Tests that [`WalletWrite::mark_transparent_addresses_exposed`] returns an error when
/// asked to mark an address that the wallet does not track.
pub fn mark_transparent_addresses_exposed_unknown_address<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
{
    use zcash_protocol::consensus::BlockHeight;

    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let unknown = TransparentAddress::PublicKeyHash([0u8; 20]);
    assert!(
        st.wallet_mut()
            .mark_transparent_addresses_exposed(&[(unknown, BlockHeight::from(1))])
            .is_err()
    );
}
