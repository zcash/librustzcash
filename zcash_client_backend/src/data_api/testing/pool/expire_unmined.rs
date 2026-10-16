//! The shared, backend-agnostic test suite for
//! [`WalletWrite::expire_unmined_transaction`].
//!
//! Every scenario here is generic over a [`ShieldedPoolTester`] and is instantiated per pool by
//! the concrete backends (see `zcash_client_sqlite`).

use zcash_protocol::{TxId, value::Zatoshis};

use crate::data_api::{
    Account as _, ExpireUnminedOutcome, WalletRead, WalletWrite,
    testing::{DataStoreFactory, TestCache},
    wallet::ConfirmationsPolicy,
};

use super::{ShieldedPoolTester, dsl::TestDsl};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        data_api::{
            CoinbaseFilter, InputSource,
            testing::{AddressType, single_output_change_strategy},
            wallet::{
                TargetHeight,
                input_selection::{GreedyInputSelector, LockFilter},
            },
        },
        fees::StandardFeeRule,
        wallet::WalletTransparentOutput,
    },
    assert_matches::assert_matches,
    transparent::{
        address::TransparentAddress,
        bundle::{OutPoint, TxOut},
        keys::TransparentKeyScope,
    },
    zcash_keys::keys::UnifiedAddressRequest,
};

/// The value of the single note that funds each scenario.
const FUNDING_VALUE: Zatoshis = Zatoshis::const_from_u64(50000);

/// The value sent by the transaction that is expired.
const FIRST_SEND: Zatoshis = Zatoshis::const_from_u64(15000);

/// The value sent by a transaction that re-spends the released inputs.
const SECOND_SEND: Zatoshis = Zatoshis::const_from_u64(2000);

/// The ZIP 317 fee of a transaction spending one note to one recipient, with change.
const ZIP317_FEE: Zatoshis = Zatoshis::const_from_u64(10000);

/// Expiring an unmined transaction makes the notes it spends available for selection at the next
/// target height, without waiting for its expiry height.
pub fn expire_unmined_transaction_releases_inputs<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    st.add_a_single_note_checking_balance(FUNDING_VALUE);
    let account_id = st.test_account().unwrap().id();

    let to = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let txid = st.spend_to(&to, FIRST_SEND);

    // The sole note is committed to the unmined transaction.
    let retry_required = (SECOND_SEND + ZIP317_FEE).unwrap();
    st.expect_insufficient_funds(&to, SECOND_SEND, Zatoshis::ZERO, retry_required);

    assert_eq!(
        st.wallet_mut().expire_unmined_transaction(txid).unwrap(),
        ExpireUnminedOutcome::Expired
    );

    // The note is spendable again, and the expired transaction's change is not counted.
    assert_eq!(st.get_total_balance(account_id), FUNDING_VALUE);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        FUNDING_VALUE
    );

    // Expiring it again changes nothing.
    assert_eq!(
        st.wallet_mut().expire_unmined_transaction(txid).unwrap(),
        ExpireUnminedOutcome::AlreadyExpired
    );

    // The released note can be spent by a new transaction, which is mined.
    let txid2 = st.spend_to(&to, SECOND_SEND);
    let (h, _) = st.generate_next_block_including(txid2);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.wallet().get_tx_height(txid).unwrap(), None);
    assert_eq!(st.wallet().get_tx_height(txid2).unwrap(), Some(h));
    assert_eq!(
        st.get_total_balance(account_id),
        (FUNDING_VALUE - (SECOND_SEND + ZIP317_FEE).unwrap()).unwrap()
    );
}

/// An expired transaction that is nonetheless mined is recorded as mined by scanning, and the
/// notes it spends are again treated as spent.
pub fn expired_unmined_transaction_mined_later_spends_inputs<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    st.add_a_single_note_checking_balance(FUNDING_VALUE);
    let account_id = st.test_account().unwrap().id();

    let to = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let txid = st.spend_to(&to, FIRST_SEND);

    assert_eq!(
        st.wallet_mut().expire_unmined_transaction(txid).unwrap(),
        ExpireUnminedOutcome::Expired
    );
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        FUNDING_VALUE
    );

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    let remaining = (FUNDING_VALUE - (FIRST_SEND + ZIP317_FEE).unwrap()).unwrap();
    assert_eq!(st.wallet().get_tx_height(txid).unwrap(), Some(h));
    assert_eq!(st.get_total_balance(account_id), remaining);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        remaining
    );

    // Once mined, the transaction can no longer be expired.
    assert_eq!(
        st.wallet_mut().expire_unmined_transaction(txid).unwrap(),
        ExpireUnminedOutcome::Mined
    );
    assert_eq!(st.get_total_balance(account_id), remaining);
}

/// Expiring a mined or unknown transaction changes nothing.
pub fn expire_unmined_transaction_ignores_mined_and_unknown<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    st.add_a_single_note_checking_balance(FUNDING_VALUE);
    let account_id = st.test_account().unwrap().id();

    let to = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let txid = st.spend_to(&to, FIRST_SEND);
    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);
    let remaining = (FUNDING_VALUE - (FIRST_SEND + ZIP317_FEE).unwrap()).unwrap();
    assert_eq!(st.get_total_balance(account_id), remaining);

    assert_eq!(
        st.wallet_mut().expire_unmined_transaction(txid).unwrap(),
        ExpireUnminedOutcome::Mined
    );

    let unknown_txid = TxId::from_bytes([0xab; 32]);
    assert_eq!(
        st.wallet_mut()
            .expire_unmined_transaction(unknown_txid)
            .unwrap(),
        ExpireUnminedOutcome::Unknown
    );

    assert_eq!(st.wallet().get_tx_height(txid).unwrap(), Some(h));
    assert_eq!(st.get_total_balance(account_id), remaining);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        remaining
    );
}

/// Expiring an unmined transaction that spends a transparent output makes that output spendable
/// again; if the transaction is then mined, the output is again treated as spent.
#[cfg(feature = "transparent-inputs")]
pub fn expire_unmined_transaction_releases_transparent_inputs<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: core::fmt::Debug,
{
    /// The value of the transparent output that the shielding transaction spends.
    const UTXO_VALUE: Zatoshis = Zatoshis::const_from_u64(100000);
    /// The minimum value that the shielding transaction is permitted to shield.
    const SHIELDING_THRESHOLD: Zatoshis = Zatoshis::const_from_u64(10000);

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);
    let taddr = *st
        .wallet()
        .get_last_generated_address_matching(account.id(), UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap()
        .transparent()
        .unwrap();

    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, FUNDING_VALUE);
    st.scan_cached_blocks(h, 1);

    let utxo = WalletTransparentOutput::from_parts(
        OutPoint::fake(),
        TxOut::new(UTXO_VALUE, taddr.script().into()),
        Some(h),
        Some(account.id()),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    assert_matches!(st.wallet_mut().put_received_transparent_utxo(&utxo), Ok(_));

    assert_eq!(spendable_utxo_count(st.wallet(), &taddr), 1);

    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);
    let txids = st
        .shield_transparent_funds(
            &GreedyInputSelector::new(),
            &change_strategy,
            SHIELDING_THRESHOLD,
            account.usk(),
            &[taddr],
            account.id(),
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    assert_eq!(txids.len(), 1);
    let shielding_txid = *txids.first();
    assert_eq!(spendable_utxo_count(st.wallet(), &taddr), 0);

    assert_eq!(
        st.wallet_mut()
            .expire_unmined_transaction(shielding_txid)
            .unwrap(),
        ExpireUnminedOutcome::Expired
    );
    assert_eq!(spendable_utxo_count(st.wallet(), &taddr), 1);

    let (h, _) = st.generate_next_block_including(shielding_txid);
    st.scan_cached_blocks(h, 1);
    assert_eq!(st.wallet().get_tx_height(shielding_txid).unwrap(), Some(h));
    assert_eq!(spendable_utxo_count(st.wallet(), &taddr), 0);
}

/// Returns the number of transparent outputs received at `address` that are spendable at the
/// target height following the wallet's chain tip.
#[cfg(feature = "transparent-inputs")]
fn spendable_utxo_count<W>(wallet: &W, address: &TransparentAddress) -> usize
where
    W: InputSource + WalletRead<Error = <W as InputSource>::Error>,
    <W as InputSource>::Error: core::fmt::Debug,
{
    let tip = wallet.chain_height().unwrap().unwrap();
    wallet
        .get_spendable_transparent_outputs(
            address,
            TargetHeight::from(tip + 1),
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
            LockFilter::Unfiltered,
        )
        .unwrap()
        .len()
}
