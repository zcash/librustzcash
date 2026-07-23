//! The shared, backend-agnostic test suite for the note-locking feature.
//!
//! Every scenario here is generic over a [`ShieldedPoolTester`] (or a
//! [`DataStoreFactory`] for the transparent scenario) and is instantiated per
//! pool by the concrete backends (see `zcash_client_sqlite`). The semantics
//! under test are specified in [`crate::data_api::locking`].

use std::convert::Infallible;

use assert_matches::assert_matches;
use proptest::prelude::{Just, Strategy, prop_oneof};

use zcash_protocol::{PoolType, TxId, consensus::BlockHeight, value::Zatoshis};
use zip321::Payment;

use crate::{
    data_api::{
        self, Account as _, InputSource, OutputLockStore, WalletRead, WalletTest, WalletWrite,
        error::LockError,
        testing::{AddressType, DataStoreFactory, TestCache, single_output_change_strategy},
        wallet::{
            ConfirmationsPolicy, LockRequest, TargetHeight,
            input_selection::{GreedyInputSelector, LockFilter, LockedInputPolicy},
        },
    },
    fees::StandardFeeRule,
    wallet::{LockOwner, OutputRef, OvkPolicy},
};

use super::{ShieldedPoolTester, dsl::TestDsl};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        data_api::{CoinbaseFilter, testing::TestBuilder},
        wallet::WalletTransparentOutput,
    },
    transparent::{
        bundle::{OutPoint, TxOut},
        keys::TransparentKeyScope,
    },
    zcash_keys::keys::UnifiedAddressRequest,
    zcash_primitives::block::BlockHash,
};

pub fn spend_fails_on_locked_notes<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let fee_rule = StandardFeeRule::Zip317;

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.add_a_single_note_checking_balance(value);

    // Send some of the funds to another address, but don't mine the tx.
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal,),
        Ok(txids) if txids.len() == 1
    );

    // A second proposal fails because there are no usable notes
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::ZERO && required == Zatoshis::const_from_u64(12000)
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 41 (that don't send us funds)
    // until just before the first transaction expires
    for i in 1..42 {
        st.generate_next_block(
            &T::sk_to_fvk(&T::sk(&[i as u8; 32])),
            AddressType::DefaultExternal,
            value,
        );
    }
    st.scan_cached_blocks(h1 + 1, 40);

    // Second proposal still fails
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::ZERO && required == Zatoshis::const_from_u64(12000)
    );

    // Mine block SAPLING_ACTIVATION_HEIGHT + 42 so that the first transaction expires
    let (h43, _, _) = st.generate_next_block(
        &T::sk_to_fvk(&T::sk(&[42; 32])),
        AddressType::DefaultExternal,
        value,
    );
    st.scan_cached_blocks(h43, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );

    // Second spend should now succeed
    let amount_sent2 = Zatoshis::const_from_u64(2000);
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            amount_sent2,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    let txid2 = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid2);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account_id),
        (value - (amount_sent2 + Zatoshis::from_u64(10000).unwrap()).unwrap()).unwrap()
    );
}

pub fn explicit_note_locking<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let fee_rule = StandardFeeRule::Zip317;

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, _) = st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();

    // Find the received note and construct an OutputRef for it
    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), 1);
    let note = &notes[0];
    let output_ref = OutputRef::new(
        *note.txid(),
        PoolType::Shielded(note.note().pool()),
        u32::from(note.output_index()),
    );

    // Balance is available before locking
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );

    // Lock the note with a far-future expiry so it's active during the test
    let owner = LockOwner::new([1; 32]);
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], owner, BlockHeight::from(u32::MAX))
            .unwrap(),
        1
    );

    // Total balance is unchanged, but spendable is zero and locked equals the full value
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_locked_balance(account_id), value);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO
    );

    // Proposal should fail because there are no spendable notes
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds { .. })
    );

    // Unlock the note
    assert!(st.wallet_mut().unlock_output(&output_ref, owner).unwrap());

    // Balance should be restored: spendable equals the full value, locked is zero
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );

    // Proposal should now succeed
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        ),
        Ok(txids) if txids.len() == 1
    );
}

/// Exercises the exact height boundary of the note-locking semantics.
///
/// A lock with `lock_expiry_height == target_height` must keep the output locked (excluded from
/// selection, counted as locked balance), whereas a lock with `lock_expiry_height ==
/// target_height - 1` must leave the output spendable. Balance computation uses
/// `target_height = chain_tip + 1`, so we derive the boundary from the current chain tip.
pub fn note_locking_height_boundary<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, _) = st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();

    // Balance computation targets `chain_tip + 1`.
    let chain_tip = st.latest_cached_block().unwrap().height();
    let target_height = chain_tip + 1;

    // Find the received note and construct an OutputRef for it
    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), 1);
    let note = &notes[0];
    let output_ref = OutputRef::new(
        *note.txid(),
        PoolType::Shielded(note.note().pool()),
        u32::from(note.output_index()),
    );

    // Lock with expiry exactly at the target height: the output must be treated as locked.
    let owner = LockOwner::new([1; 32]);
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], owner, target_height)
            .unwrap(),
        1
    );
    assert_eq!(st.get_locked_balance(account_id), value);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO
    );
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![output_ref]
    );

    // Re-lock with expiry one block below the target height. The existing lock is not yet
    // expired as of the chain tip, but the same owner may re-acquire (and here, shorten) its
    // own lock directly, with no explicit unlock.
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], owner, target_height - 1)
            .unwrap(),
        1
    );

    // With expiry strictly below the target height, the output is spendable again.
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );
    assert!(
        st.wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .is_empty()
    );
}

/// Verifies that [`OutputLockStore::clear_locked_outputs`] unlocks every locked output for an account
/// regardless of expiry height, as required by the lost-proposal recovery path.
///
/// [`OutputLockStore::clear_locked_outputs`]: crate::data_api::OutputLockStore::clear_locked_outputs
pub fn clear_locked_outputs<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, _) = st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();

    // Find the received note and construct an OutputRef for it
    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), 1);
    let note = &notes[0];
    let output_ref = OutputRef::new(
        *note.txid(),
        PoolType::Shielded(note.note().pool()),
        u32::from(note.output_index()),
    );

    // Lock the note with a far-future expiry.
    let owner = LockOwner::new([1; 32]);
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], owner, BlockHeight::from(u32::MAX))
            .unwrap(),
        1
    );
    assert_eq!(st.get_locked_balance(account_id), value);
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![output_ref]
    );

    // Clearing all locks for the account unlocks the output even though its expiry height is far
    // in the future (and regardless of its owner).
    assert_eq!(st.wallet_mut().clear_locked_outputs(account_id).unwrap(), 1);
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );
    assert!(
        st.wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .is_empty()
    );

    // Clearing again is a no-op and reports zero unlocked outputs.
    assert_eq!(st.wallet_mut().clear_locked_outputs(account_id).unwrap(), 0);
}

pub fn proposal_level_note_locking<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let fee_rule = StandardFeeRule::Zip317;

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, _) = st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);

    // Remember the funding note's reference; it is spent at the end of this test, where the
    // lock-a-spent-note behavior is pinned.
    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), 1);
    let funding_note_ref = OutputRef::new(
        *notes[0].txid(),
        PoolType::Shielded(notes[0].note().pool()),
        u32::from(notes[0].output_index()),
    );

    // Create a proposal with lock_for_blocks: Some(100) using propose_transfer
    let input_selector = GreedyInputSelector::new();
    let change_strategy = single_output_change_strategy(fee_rule, None, T::SHIELDED_PROTOCOL);

    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(15000),
    )])
    .unwrap();

    let network = *st.network();
    let owner = LockOwner::new([1; 32]);
    let proposal = crate::data_api::wallet::propose_transfer::<_, _, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &crate::data_api::wallet::input_selection::SpendPolicy::default(),
        Some(LockRequest::new(owner, 100)),
        None,
    )
    .unwrap();

    // Notes should now be locked; a second proposal should fail
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds { .. })
    );

    // Execute the proposal; this should unlock the notes (they become spent)
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        ),
        Ok(txids) if txids.len() == 1
    );

    // All notes should now be unlocked (spent via spends table, lock cleared)
    let locked = st.wallet().get_locked_outputs(account_id).unwrap();
    assert!(
        locked.is_empty(),
        "all notes should be unlocked after create_proposed_transactions"
    );

    // Pin two lock-target edge behaviors:
    //
    // Locking an output the wallet does not know fails with `LockFailure` (the "not found"
    // and "already locked" cases are deliberately indistinguishable to the caller).
    let unknown = OutputRef::new(
        TxId::from_bytes([0xEE; 32]),
        PoolType::Shielded(T::SHIELDED_PROTOCOL),
        0,
    );
    assert_matches!(
        st.wallet_mut()
            .lock_outputs(&[unknown], owner, BlockHeight::from(u32::MAX)),
        Err(LockError::LockFailure(r)) if r == unknown
    );

    // Locking an already-spent note currently SUCCEEDS: `lock_outputs` checks only for an
    // existing active lock, not for spend status. This is harmless in the proposal flow
    // (spent notes never enter selection, and the lock has no balance effect because balance
    // computation only considers unspent notes), but it is pinned here so that any future
    // tightening of the contract is a visible, deliberate change.
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[funding_note_ref], owner, BlockHeight::from(u32::MAX))
            .unwrap(),
        1
    );
    // The stale lock is visible in the raw lock listing but has no balance effect.
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![funding_note_ref]
    );
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);
    assert!(
        st.wallet_mut()
            .unlock_output(&funding_note_ref, owner)
            .unwrap()
    );
}

/// Verifies that a proposal created with `lock_for_blocks: Some(_)` round-trips through its
/// serialized (proto) form.
///
/// A locking proposal locks its own inputs, and decoding re-retrieves each input from the wallet.
/// Input retrieval during decoding must therefore not filter out locked outputs; otherwise a
/// wallet that persists a locking proposal (for example around an app restart, while a PCZT is
/// out for signing) could never decode it again.
pub fn locked_proposal_proto_roundtrip<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let fee_rule = StandardFeeRule::Zip317;

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, _) = st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);

    let input_selector = GreedyInputSelector::new();
    let change_strategy = single_output_change_strategy(fee_rule, None, T::SHIELDED_PROTOCOL);

    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(15000),
    )])
    .unwrap();

    let network = *st.network();
    let owner = LockOwner::new([1; 32]);
    let proposal = crate::data_api::wallet::propose_transfer::<_, _, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &crate::data_api::wallet::input_selection::SpendPolicy::default(),
        Some(LockRequest::new(owner, 100)),
        None,
    )
    .unwrap();

    // The proposal's input is locked.
    assert!(
        !st.wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .is_empty(),
        "the proposal's input must be locked before the round-trip"
    );

    // The serialized proposal must decode back to an identical proposal even though its inputs
    // are locked (a proposal legitimately references its own locked inputs).
    let proto = crate::proto::proposal::Proposal::from_standard_proposal(&proposal);
    let decoded = proto
        .try_into_standard_proposal(&network, st.wallet())
        .expect("a proposal with locked inputs must decode from its serialized form");
    assert_eq!(decoded, proposal);
}

/// Exercises the passed-expiry semantics of note locking under chain advance.
///
/// A lock names an expiry height `h`; balance and selection evaluate it against
/// `target_height = chain_tip + 1`, so the note stays locked while `chain_tip < h` and becomes
/// spendable again, with no unlock call, as soon as the chain tip reaches `h`. The stale
/// `lock_expiry_height` value remains in the row, and a subsequent `lock_outputs` replaces it
/// (the expired-lock branch of the lock-acquisition guard).
pub fn lock_expiry_restores_spendability<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, _) = st.add_a_single_note_checking_balance(value);

    let account_id = st.test_account().unwrap().id();
    let tip = st.latest_cached_block().unwrap().height();

    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), 1);
    let note = &notes[0];
    let output_ref = OutputRef::new(
        *note.txid(),
        PoolType::Shielded(note.note().pool()),
        u32::from(note.output_index()),
    );

    // Lock the note until three blocks past the current tip.
    let owner = LockOwner::new([1; 32]);
    let expiry = tip + 3;
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], owner, expiry)
            .unwrap(),
        1
    );
    assert_eq!(st.get_locked_balance(account_id), value);

    // Advance the chain to two blocks below the expiry... still locked: the balance target
    // height is now `expiry` itself, and a lock covers its expiry height inclusively.
    st.add_empty_blocks(2);
    assert_eq!(st.get_locked_balance(account_id), value);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO
    );
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![output_ref]
    );

    // One more block reaches the expiry height: the lock has now been passed, and the note is
    // spendable again without any unlock call. The stale lock_expiry_height column value is
    // simply ignored by selection and balance.
    st.add_empty_blocks(1);
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );
    assert!(
        st.wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .is_empty()
    );

    // A spend proposal succeeds now that the lock has expired.
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    st.propose_standard_transfer::<Infallible>(
        account_id,
        StandardFeeRule::Zip317,
        ConfirmationsPolicy::MIN,
        &to,
        Zatoshis::const_from_u64(15000),
        None,
        None,
        T::SHIELDED_PROTOCOL,
    )
    .expect("an expired lock must not block proposal creation");

    // The expired lock is replaceable, even by a DIFFERENT owner: a fresh lock_outputs call
    // succeeds without an explicit unlock, overwriting the stale expiry value and taking over
    // ownership of the lock.
    let other_owner = LockOwner::new([2; 32]);
    let new_tip = st.latest_cached_block().unwrap().height();
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], other_owner, new_tip + 5)
            .unwrap(),
        1
    );
    assert_eq!(st.get_locked_balance(account_id), value);
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![output_ref]
    );
}

/// Exercises lock-conflict detection and the all-or-nothing batch contract of
/// [`OutputLockStore::lock_outputs`], along with the `unlock_output` return-value semantics.
///
/// [`OutputLockStore::lock_outputs`]: crate::data_api::OutputLockStore::lock_outputs
pub fn lock_conflict_and_batch_atomicity<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Fund the wallet with two notes of distinct values in a single block, so that each note
    // can be identified by its value below.
    let value1 = Zatoshis::const_from_u64(60000);
    let value2 = Zatoshis::const_from_u64(40000);
    st.add_notes_checking_balance([[value1, value2]]);

    let account_id = st.test_account().unwrap().id();
    let far_expiry = BlockHeight::from(u32::MAX);

    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), 2);
    let output_ref = |value: Zatoshis| {
        let note = notes
            .iter()
            .find(|n| n.note().value() == value)
            .expect("a note with the requested value exists");
        OutputRef::new(
            *note.txid(),
            PoolType::Shielded(note.note().pool()),
            u32::from(note.output_index()),
        )
    };
    let r1 = output_ref(value1);
    let r2 = output_ref(value2);

    let owner_a = LockOwner::new([0xA1; 32]);
    let owner_b = LockOwner::new([0xB2; 32]);

    // The first lock on a note succeeds.
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[r1], owner_a, far_expiry)
            .unwrap(),
        1
    );

    // Re-locking under the SAME owner succeeds while the lock is active: acquisition is
    // idempotent for the holding flow (this is the crash-retry path), and may extend or
    // shorten the expiry.
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[r1], owner_a, far_expiry)
            .unwrap(),
        1
    );
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![r1]
    );

    // A lock by a DIFFERENT owner fails while the first lock is active.
    assert_matches!(
        st.wallet_mut().lock_outputs(&[r1], owner_b, far_expiry),
        Err(LockError::LockFailure(r)) if r == r1
    );

    // A batch containing a foreign-locked output fails all-or-nothing: r2 precedes the
    // conflicting r1 in the batch, but the failure must leave r2 unlocked.
    assert_matches!(
        st.wallet_mut().lock_outputs(&[r2, r1], owner_b, far_expiry),
        Err(LockError::LockFailure(r)) if r == r1
    );
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![r1],
        "a failed batch lock must not leave any of its outputs locked"
    );
    assert_eq!(st.get_locked_balance(account_id), value1);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value2
    );

    // A batch containing the same output twice under one owner succeeds: the second occurrence
    // re-acquires the lock taken by the first (both row updates are counted).
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[r2, r2], owner_b, far_expiry)
            .unwrap(),
        2
    );
    {
        let mut locked = st.wallet().get_locked_outputs(account_id).unwrap();
        locked.sort();
        let mut expected = vec![r1, r2];
        expected.sort();
        assert_eq!(locked, expected);
    }

    // Unlocking is owner-scoped: owner A cannot release owner B's lock on r2, and unlocking
    // an unknown output reports `false`.
    assert!(!st.wallet_mut().unlock_output(&r2, owner_a).unwrap());
    assert_eq!(
        st.get_locked_balance(account_id),
        (value1 + value2).unwrap()
    );
    let unknown = OutputRef::new(
        TxId::from_bytes([0xEE; 32]),
        PoolType::Shielded(T::SHIELDED_PROTOCOL),
        0,
    );
    assert!(!st.wallet_mut().unlock_output(&unknown, owner_a).unwrap());

    // Each owner releases its own lock; unlocking an output that holds no lock reports
    // `false`.
    assert!(st.wallet_mut().unlock_output(&r2, owner_b).unwrap());
    assert!(!st.wallet_mut().unlock_output(&r2, owner_b).unwrap());
    assert!(st.wallet_mut().unlock_output(&r1, owner_a).unwrap());
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);

    // With everything released, a single owner can lock both notes in one batch.
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[r1, r2], owner_a, far_expiry)
            .unwrap(),
        2
    );
    assert_eq!(
        st.get_locked_balance(account_id),
        (value1 + value2).unwrap()
    );
}

/// Verifies that [`unlock_proposal_inputs`] releases the locks taken by a proposal created with
/// a [`LockRequest`], restoring spendability for a subsequent proposal (the abandoned-proposal
/// recovery path), and that the release is scoped to the owner that took the locks.
///
/// [`unlock_proposal_inputs`]: crate::data_api::wallet::unlock_proposal_inputs
pub fn unlock_proposal_inputs_releases_locks<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let fee_rule = StandardFeeRule::Zip317;

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, _) = st.add_a_single_note_checking_balance(value);

    let account_id = st.test_account().unwrap().id();
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);

    let input_selector = GreedyInputSelector::new();
    let change_strategy = single_output_change_strategy(fee_rule, None, T::SHIELDED_PROTOCOL);

    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(15000),
    )])
    .unwrap();

    let network = *st.network();
    let owner = LockOwner::new([1; 32]);
    let proposal = crate::data_api::wallet::propose_transfer::<_, _, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &crate::data_api::wallet::input_selection::SpendPolicy::default(),
        Some(LockRequest::new(owner, 100)),
        None,
    )
    .unwrap();

    // The proposal's input is locked; a competing proposal cannot be created.
    assert_eq!(st.get_locked_balance(account_id), value);
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds { .. })
    );

    // Attempting to release the locks under the WRONG owner is a no-op: the locks are scoped
    // to the owner that took them.
    let other_owner = LockOwner::new([2; 32]);
    crate::data_api::wallet::unlock_proposal_inputs(st.wallet_mut(), &proposal, other_owner)
        .unwrap();
    assert_eq!(st.get_locked_balance(account_id), value);

    // Abandon the proposal: releasing its inputs under the correct owner restores spendable
    // balance...
    crate::data_api::wallet::unlock_proposal_inputs(st.wallet_mut(), &proposal, owner).unwrap();
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );
    assert!(
        st.wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .is_empty()
    );

    // ... and a subsequent proposal can select the released inputs.
    st.propose_standard_transfer::<Infallible>(
        account_id,
        fee_rule,
        ConfirmationsPolicy::MIN,
        &to,
        Zatoshis::const_from_u64(2000),
        None,
        None,
        T::SHIELDED_PROTOCOL,
    )
    .expect("released inputs must be selectable by a new proposal");

    // Releasing an already-released proposal is a no-op.
    crate::data_api::wallet::unlock_proposal_inputs(st.wallet_mut(), &proposal, owner).unwrap();
    assert_eq!(st.get_locked_balance(account_id), Zatoshis::ZERO);
}

/// Verifies that `SpendPolicy::with_locked_input_policy` actually reaches note selection in
/// `GreedyInputSelector::propose_transaction`, end to end.
///
/// With the default policy (`LockedInputPolicy::Exclude`), a proposal that needs more than the
/// unlocked balance fails with `InsufficientFunds`, even though a locked note could cover it.
/// With `LockedInputPolicy::PreferUnlocked` naming the lock's owner, the same proposal succeeds
/// and its selected inputs include the note that owner locked. A note locked by a DIFFERENT
/// owner — one the policy does not name — is never selected, under either policy.
pub fn spend_policy_locked_input_policy_reaches_selection<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use crate::data_api::wallet::input_selection::{
        LockedInputPolicy, NonEmptyBTreeSet, SpendPolicy,
    };

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let fee_rule = StandardFeeRule::Zip317;

    // Fund the account with three notes of distinct values in a single block, so that each can
    // be identified by its value below: `unlocked_value` is left unlocked, `locked_a_value` is
    // locked by owner A, and `locked_b_value` is locked by a DIFFERENT owner B.
    let unlocked_value = Zatoshis::const_from_u64(20_000);
    let locked_a_value = Zatoshis::const_from_u64(60_000);
    let locked_b_value = Zatoshis::const_from_u64(70_000);
    st.add_notes_checking_balance([[unlocked_value, locked_a_value, locked_b_value]]);

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();

    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), 3);
    let output_ref = |value: Zatoshis| {
        let note = notes
            .iter()
            .find(|n| n.note().value() == value)
            .expect("a note with the requested value exists");
        OutputRef::new(
            *note.txid(),
            PoolType::Shielded(note.note().pool()),
            u32::from(note.output_index()),
        )
    };
    let locked_a_ref = output_ref(locked_a_value);
    let locked_b_ref = output_ref(locked_b_value);

    let owner_a = LockOwner::new([0xA1; 32]);
    let owner_b = LockOwner::new([0xB2; 32]);
    let far_expiry = BlockHeight::from(u32::MAX);
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[locked_a_ref], owner_a, far_expiry)
            .unwrap(),
        1
    );
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[locked_b_ref], owner_b, far_expiry)
            .unwrap(),
        1
    );

    // The unlocked note alone cannot cover this request (plus fee); a locked note is required.
    let request_amount = Zatoshis::const_from_u64(50_000);
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        request_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_strategy = single_output_change_strategy(fee_rule, None, T::SHIELDED_PROTOCOL);

    // With the default `Exclude` policy, both locked notes are ineligible, and the unlocked
    // note alone is insufficient: the A-locked note is NOT drawn upon.
    assert_matches!(
        st.propose_transfer_with_policy(
            account_id,
            &input_selector,
            &change_strategy,
            request.clone(),
            ConfirmationsPolicy::MIN,
            &SpendPolicy::default(),
        ),
        Err(data_api::error::Error::InsufficientFunds { .. })
    );

    // With `PreferUnlocked` naming owner A, the proposal succeeds and draws on the note owner A
    // locked, but never on the note locked by owner B (who the policy does not name).
    let policy = SpendPolicy::default().with_locked_input_policy(
        LockedInputPolicy::PreferUnlocked(NonEmptyBTreeSet::singleton(owner_a)),
    );
    let proposal = st
        .propose_transfer_with_policy(
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
        )
        .expect("a note locked by a permitted owner must be selectable to cover the request");

    assert_eq!(proposal.steps().len(), 1);
    let selected_values: Vec<Zatoshis> = proposal
        .steps()
        .head
        .shielded_inputs()
        .expect("the proposal must spend shielded notes")
        .notes()
        .iter()
        .map(|rn| rn.note().value())
        .collect();
    assert!(
        selected_values.contains(&locked_a_value),
        "the note locked by the permitted owner must be selected: {selected_values:?}"
    );
    assert!(
        !selected_values.contains(&locked_b_value),
        "a note locked by a different owner must never be selected: {selected_values:?}"
    );

    // The owner-B lock is untouched by this proposal.
    assert!(
        st.wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .contains(&locked_b_ref)
    );
}

/// An operation in the note-locking model test; see [`check_note_locking_model`].
#[derive(Clone, Debug)]
pub enum LockOp {
    /// Attempt to lock the notes at the given indices on behalf of the given owner
    /// (duplicates permitted: a duplicated index re-acquires the lock taken by its own first
    /// occurrence, which succeeds because it is held by the same owner) with expiry height
    /// `chain_tip + expiry_delta`.
    ///
    /// An `expiry_delta` of zero produces a lock that is expired from the moment it is taken:
    /// balance and selection evaluate locks against `target_height = chain_tip + 1`.
    Lock {
        notes: Vec<usize>,
        owner: usize,
        expiry_delta: u32,
    },
    /// Unlock the note at the given index on behalf of the given owner; only a lock held by
    /// that owner is released.
    Unlock { note: usize, owner: usize },
    /// Clear every lock for the account, regardless of expiry or owner.
    ClearLocked,
    /// Mine the given number of empty blocks, advancing the chain tip (and thereby expiring
    /// any lock whose expiry height the tip reaches).
    MineBlocks { count: usize },
}

/// The owner-index pool used by [`arb_lock_ops`] and [`check_note_locking_model`].
const MODEL_OWNERS: [LockOwner; 2] = [LockOwner::new([0xA1; 32]), LockOwner::new([0xB2; 32])];

/// A `proptest` strategy over sequences of [`LockOp`] for a wallet holding `n_notes` notes.
///
/// Expiry deltas and mining counts are drawn from small ranges so that sequences routinely
/// cross lock-expiry boundaries.
pub fn arb_lock_ops(n_notes: usize, max_ops: usize) -> impl Strategy<Value = Vec<LockOp>> {
    let n_owners = MODEL_OWNERS.len();
    let op = prop_oneof![
        3 => (
            proptest::collection::vec(0..n_notes, 1..=n_notes + 1),
            0..n_owners,
            0u32..=4,
        )
            .prop_map(|(notes, owner, expiry_delta)| LockOp::Lock {
                notes,
                owner,
                expiry_delta
            }),
        2 => (0..n_notes, 0..n_owners)
            .prop_map(|(note, owner)| LockOp::Unlock { note, owner }),
        1 => Just(LockOp::ClearLocked),
        2 => (1usize..=3).prop_map(|count| LockOp::MineBlocks { count }),
    ];
    proptest::collection::vec(op, 1..=max_ops)
}

/// Model-based test of the note-locking storage operations.
///
/// Funds a wallet with three notes, then applies the given operation sequence both to the real
/// data store and to a trivial in-memory model (per-note `Option<(lock_expiry_height, owner)>`
/// plus the chain tip). After every operation, the store must agree with the model on:
///
/// - the outcome of the operation itself, including the all-or-nothing failure of a `Lock`
///   batch containing a conflict (an active, unexpired lock held by a different owner on any
///   requested note), same-owner re-lock idempotency, and owner-scoped unlocking;
/// - the set reported by `get_locked_outputs` (a note is locked while
///   `lock_expiry_height >= chain_tip + 1`);
/// - the account balance decomposition: locked value is exactly the sum of model-locked note
///   values, spendable value is the remainder, and the total is unaffected by lock state.
pub fn check_note_locking_model<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
    ops: &[LockOp],
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Fund the wallet with three notes of distinct values in a single block, so that notes can
    // be matched to model indices by value.
    let values = [
        Zatoshis::const_from_u64(60000),
        Zatoshis::const_from_u64(70000),
        Zatoshis::const_from_u64(80000),
    ];
    st.add_notes_checking_balance([values]);
    let total = values
        .iter()
        .try_fold(Zatoshis::ZERO, |acc, v| acc + *v)
        .unwrap();

    let account_id = st.test_account().unwrap().id();

    let notes = st.wallet().get_notes(T::SHIELDED_PROTOCOL).unwrap();
    assert_eq!(notes.len(), values.len());
    let refs: Vec<OutputRef> = values
        .iter()
        .map(|value| {
            let note = notes
                .iter()
                .find(|n| n.note().value() == *value)
                .expect("a note with the requested value exists");
            OutputRef::new(
                *note.txid(),
                PoolType::Shielded(note.note().pool()),
                u32::from(note.output_index()),
            )
        })
        .collect();

    // The model: per-note lock expiry height and owner index, and the chain tip.
    let mut model: Vec<Option<(u32, usize)>> = vec![None; refs.len()];
    let mut tip = u32::from(st.latest_cached_block().unwrap().height());

    for op in ops {
        match op {
            LockOp::Lock {
                notes,
                owner,
                expiry_delta,
            } => {
                let expiry = tip + expiry_delta;
                // Predict the outcome by simulating the store's sequential update: each
                // requested note may be locked when it holds no lock, when its lock has
                // expired as of the chain tip, or when its lock is held by the requesting
                // owner; the first conflict (an active foreign lock) fails the whole batch.
                let mut scratch = model.clone();
                let mut conflict = None;
                for &i in notes {
                    if scratch[i].is_none_or(|(h, o)| h <= tip || o == *owner) {
                        scratch[i] = Some((expiry, *owner));
                    } else {
                        conflict = Some(i);
                        break;
                    }
                }

                let batch: Vec<OutputRef> = notes.iter().map(|&i| refs[i]).collect();
                let result = st.wallet_mut().lock_outputs(
                    &batch,
                    MODEL_OWNERS[*owner],
                    BlockHeight::from(expiry),
                );
                match conflict {
                    None => {
                        assert_matches!(result, Ok(n) if n == notes.len());
                        model = scratch;
                    }
                    Some(i) => {
                        // The batch fails naming the conflicting note, and (checked by the
                        // post-operation invariants below) locks nothing.
                        assert_matches!(result, Err(LockError::LockFailure(r)) if r == refs[i]);
                    }
                }
            }
            LockOp::Unlock { note, owner } => {
                // Unlocking releases only a lock held by the requesting owner (expired or
                // not), and reports whether one was released.
                let expected = model[*note].is_some_and(|(_, o)| o == *owner);
                assert_eq!(
                    st.wallet_mut()
                        .unlock_output(&refs[*note], MODEL_OWNERS[*owner])
                        .unwrap(),
                    expected
                );
                if expected {
                    model[*note] = None;
                }
            }
            LockOp::ClearLocked => {
                // Clearing removes every lock record, expired or not and regardless of
                // owner, and reports how many rows it touched.
                let expected = model.iter().filter(|h| h.is_some()).count();
                assert_eq!(
                    st.wallet_mut().clear_locked_outputs(account_id).unwrap(),
                    expected
                );
                model.iter_mut().for_each(|h| *h = None);
            }
            LockOp::MineBlocks { count } => {
                st.add_empty_blocks(*count);
                tip += *count as u32;
            }
        }

        // Invariants, checked after every operation. Balance and selection evaluate lock
        // state against the next block to be mined.
        let target = tip + 1;
        let locked_value = model
            .iter()
            .zip(values.iter())
            .filter(|(h, _)| h.is_some_and(|(h, _)| h >= target))
            .try_fold(Zatoshis::ZERO, |acc, (_, v)| acc + *v)
            .unwrap();

        let mut expected_locked: Vec<OutputRef> = model
            .iter()
            .zip(refs.iter())
            .filter(|(h, _)| h.is_some_and(|(h, _)| h >= target))
            .map(|(_, r)| *r)
            .collect();
        expected_locked.sort();
        let mut actual_locked = st.wallet().get_locked_outputs(account_id).unwrap();
        actual_locked.sort();
        assert_eq!(
            actual_locked, expected_locked,
            "locked-output set diverged from the model after {op:?}"
        );

        assert_eq!(
            st.get_locked_balance(account_id),
            locked_value,
            "locked balance diverged from the model after {op:?}"
        );
        assert_eq!(
            st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
            (total - locked_value).unwrap(),
            "spendable balance diverged from the model after {op:?}"
        );
        assert_eq!(
            st.get_total_balance(account_id),
            total,
            "lock state must never change the total balance (after {op:?})"
        );
    }
}

/// Exercises note locking for transparent outputs.
///
/// A locked UTXO is still returned by a by-outpoint lookup (which is not a selection query and
/// so does not filter by lock state), but is excluded from spendable-output listing unless the
/// query passes `LockFilter::Unfiltered`, is reported as locked (not spendable) value in the
/// per-address balances, conflicts with a second lock, and returns to spendability when the
/// chain tip passes the lock expiry height, with no unlock call.
#[cfg(feature = "transparent-inputs")]
pub fn transparent_note_locking<DSF>(dsf: DSF)
where
    DSF: DataStoreFactory,
    <<DSF as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
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

    let height = birthday + 12345;
    st.wallet_mut().update_chain_tip(height).unwrap();

    // Create a fake transparent output mined at `height`.
    let value = Zatoshis::const_from_u64(100000);
    let outpoint = OutPoint::fake();
    let txout = TxOut::new(value, taddr.script().into());
    let utxo = WalletTransparentOutput::from_parts(
        outpoint.clone(),
        txout,
        Some(height),
        Some(account_id),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    let target_height = TargetHeight::from(height + 1);
    let output_ref = OutputRef::new(
        TxId::from_bytes(*outpoint.hash()),
        PoolType::TRANSPARENT,
        outpoint.n(),
    );

    // The output is retrievable and spendable before locking.
    assert_matches!(
        st.wallet()
            .get_unspent_transparent_output(&outpoint, target_height),
        Ok(Some(_))
    );

    // Lock the UTXO until ten blocks past the tip.
    let owner = LockOwner::new([1; 32]);
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], owner, height + 10)
            .unwrap(),
        1
    );

    // A lock by a different owner conflicts while the first is active.
    let other_owner = LockOwner::new([2; 32]);
    assert_matches!(
        st.wallet_mut().lock_outputs(&[output_ref], other_owner, height + 20),
        Err(LockError::LockFailure(r)) if r == output_ref
    );

    // A by-outpoint lookup of a known output is not a selection query, so it does not filter by
    // lock state: the output is still returned even though it is locked. Lock exclusion is
    // verified via `get_spendable_transparent_outputs`, below.
    assert_matches!(
        st.wallet()
            .get_unspent_transparent_output(&outpoint, target_height),
        Ok(Some(_))
    );

    // ... and from the spendable-outputs listing unless the query is unfiltered.
    assert_matches!(
        st.wallet()
            .get_spendable_transparent_outputs(
                taddr,
                target_height,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .as_deref(),
        Ok(&[])
    );
    assert_matches!(
        st.wallet()
            .get_spendable_transparent_outputs(
                taddr,
                target_height,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Unfiltered,
            )
            .as_deref(),
        Ok([_])
    );

    // The per-address balances report the value as locked, not spendable; the total is
    // unaffected by lock state.
    let balances = st
        .wallet()
        .get_transparent_balances(account_id, target_height, ConfirmationsPolicy::MIN)
        .unwrap();
    let (_, bal) = balances
        .get(taddr)
        .expect("the address has a balance entry");
    assert_eq!(bal.locked_value(), value);
    assert_eq!(bal.spendable_value(), Zatoshis::ZERO);
    assert_eq!(bal.total(), value);

    // The locked-outputs listing includes the transparent lock.
    assert_eq!(
        st.wallet().get_locked_outputs(account_id).unwrap(),
        vec![output_ref]
    );

    // Advancing the chain tip to the expiry height restores spendability with no unlock call.
    st.wallet_mut().update_chain_tip(height + 10).unwrap();
    let expired_target = TargetHeight::from(height + 11);
    let balances = st
        .wallet()
        .get_transparent_balances(account_id, expired_target, ConfirmationsPolicy::MIN)
        .unwrap();
    let (_, bal) = balances
        .get(taddr)
        .expect("the address has a balance entry");
    assert_eq!(bal.spendable_value(), value);
    assert_eq!(bal.locked_value(), Zatoshis::ZERO);
    assert!(
        st.wallet()
            .get_locked_outputs(account_id)
            .unwrap()
            .is_empty()
    );

    // The expired lock is replaceable without an explicit unlock, even by a different owner,
    // and the new holder can then release it.
    assert_eq!(
        st.wallet_mut()
            .lock_outputs(&[output_ref], other_owner, height + 30)
            .unwrap(),
        1
    );
    assert!(
        st.wallet_mut()
            .unlock_output(&output_ref, other_owner)
            .unwrap()
    );
    let balances = st
        .wallet()
        .get_transparent_balances(account_id, expired_target, ConfirmationsPolicy::MIN)
        .unwrap();
    let (_, bal) = balances
        .get(taddr)
        .expect("the address has a balance entry");
    assert_eq!(bal.spendable_value(), value);
}
