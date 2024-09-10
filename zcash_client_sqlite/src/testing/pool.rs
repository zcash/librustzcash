//! Test logic involving a single shielded pool.
//!
//! Generalised for sharing across the Sapling and Orchard implementations.

use std::{
    convert::Infallible,
    num::{NonZeroU32, NonZeroU8},
};

use incrementalmerkletree::frontier::Frontier;

use rusqlite::params;
use secrecy::Secret;

use zcash_client_backend::{
    address::Address,
    data_api::{
        self,
        chain::{self, ChainState, CommitmentTreeRoot},
        error::Error,
        testing::{
            input_selector, pool::ShieldedPoolTester, sapling::SaplingPoolTester, AddressType,
            FakeCompactOutput, InitialChainState, TestBuilder, TestState,
        },
        wallet::input_selection::{GreedyInputSelector, GreedyInputSelectorError},
        Account as _, AccountBirthday, Ratio, WalletRead, WalletWrite,
    },
    fees::{fixed, standard, DustOutputPolicy},
    keys::UnifiedSpendingKey,
    scanning::ScanError,
    wallet::{Note, OvkPolicy},
    zip321::{Payment, TransactionRequest},
};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BranchId, NetworkUpgrade, Parameters},
    legacy::TransparentAddress,
    transaction::{
        components::amount::NonNegativeAmount,
        fees::{
            fixed::FeeRule as FixedFeeRule, zip317::FeeError as Zip317FeeError, StandardFeeRule,
        },
        Transaction,
    },
    zip32::Scope,
};
use zcash_protocol::memo::MemoBytes;

use crate::{
    error::SqliteClientError,
    testing::{
        db::{TestDb, TestDbFactory},
        BlockCache,
    },
    wallet::{commitment_tree, parse_scope, truncate_to_height},
    ReceivedNoteId, SAPLING_TABLES_PREFIX,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::AccountId,
    zcash_client_backend::{data_api::DecryptedTransaction, wallet::WalletTransparentOutput},
    zcash_primitives::transaction::{
        components::{OutPoint, TxOut},
        fees::zip317,
    },
    zcash_protocol::memo::Memo,
};

#[cfg(feature = "orchard")]
use {
    crate::ORCHARD_TABLES_PREFIX,
    zcash_client_backend::{data_api::testing::orchard::OrchardPoolTester, PoolType},
    zcash_protocol::{consensus::BlockHeight, ShieldedProtocol},
};

pub(crate) trait ShieldedPoolPersistence {
    const TABLES_PREFIX: &'static str;
}

impl ShieldedPoolPersistence for SaplingPoolTester {
    const TABLES_PREFIX: &'static str = SAPLING_TABLES_PREFIX;
}

#[cfg(feature = "orchard")]
impl ShieldedPoolPersistence for OrchardPoolTester {
    const TABLES_PREFIX: &'static str = ORCHARD_TABLES_PREFIX;
}

pub(crate) fn send_single_step_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_single_step_proposed_transfer::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn send_multi_step_proposed_transfer<T: ShieldedPoolTester>() {
    use std::{collections::HashSet, str::FromStr};

    use rand_core::OsRng;
    use zcash_client_backend::{
        data_api::{TransactionDataRequest, TransactionStatus},
        fees::ChangeValue,
        wallet::TransparentAddressMetadata,
    };
    use zcash_primitives::{
        legacy::keys::{NonHardenedChildIndex, TransparentKeyScope},
        transaction::builder::{BuildConfig, Builder},
    };
    use zcash_proofs::prover::LocalTxProver;
    use zcash_protocol::value::ZatBalance;

    use crate::wallet::{transparent::get_wallet_transparent_output, GAP_LIMIT};

    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory)
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let (default_addr, default_index) = account.usk().default_transparent_address();
    let dfvk = T::test_account_fvk(&st);

    let add_funds = |st: &mut TestState<_, TestDb, _>, value| {
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            st.wallet()
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            h
        );
        assert_eq!(st.get_spendable_balance(account_id, 1), value);
        h
    };

    let value = NonNegativeAmount::const_from_u64(100000);
    let transfer_amount = NonNegativeAmount::const_from_u64(50000);

    let run_test = |st: &mut TestState<_, TestDb, _>, expected_index| {
        // Add funds to the wallet.
        add_funds(st, value);

        let expected_step0_fee = (zip317::MARGINAL_FEE * 3).unwrap();
        let expected_step1_fee = zip317::MINIMUM_FEE;
        let expected_ephemeral = (transfer_amount + expected_step1_fee).unwrap();
        let expected_step0_change =
            (value - expected_ephemeral - expected_step0_fee).expect("sufficient funds");
        assert!(expected_step0_change.is_positive());

        // Generate a ZIP 320 proposal, sending to the wallet's default transparent address
        // expressed as a TEX address.
        let tex_addr = match default_addr {
            TransparentAddress::PublicKeyHash(data) => Address::Tex(data),
            _ => unreachable!(),
        };
        let change_memo = Some(Memo::from_str("change").expect("valid memo").encode());

        // We use `st.propose_standard_transfer` here in order to also test round-trip
        // serialization of the proposal.
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account_id,
                StandardFeeRule::Zip317,
                NonZeroU32::new(1).unwrap(),
                &tex_addr,
                transfer_amount,
                None,
                change_memo.clone(),
                T::SHIELDED_PROTOCOL,
            )
            .unwrap();

        let steps: Vec<_> = proposal.steps().iter().cloned().collect();
        assert_eq!(steps.len(), 2);

        assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
        assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
        assert_eq!(
            steps[0].balance().proposed_change(),
            [
                ChangeValue::shielded(T::SHIELDED_PROTOCOL, expected_step0_change, change_memo),
                ChangeValue::ephemeral_transparent(expected_ephemeral),
            ]
        );
        assert_eq!(steps[1].balance().proposed_change(), []);

        let create_proposed_result = st.create_proposed_transactions::<Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );
        assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
        let txids = create_proposed_result.unwrap();

        // Verify that the stored sent outputs match what we're expecting.
        let mut stmt_sent = st
            .wallet()
            .conn()
            .prepare(
                "SELECT value, to_address, ephemeral_addresses.address, ephemeral_addresses.address_index
                 FROM sent_notes
                 JOIN transactions ON transactions.id_tx = sent_notes.tx
                 LEFT JOIN ephemeral_addresses ON ephemeral_addresses.used_in_tx = sent_notes.tx
                 WHERE transactions.txid = ?
                 ORDER BY value",
            )
            .unwrap();

        // Check that there are sent outputs with the correct values.
        let confirmed_sent: Vec<Vec<_>> = txids
            .iter()
            .map(|sent_txid| {
                stmt_sent
                    .query(rusqlite::params![sent_txid.as_ref()])
                    .unwrap()
                    .mapped(|row| {
                        let v: u32 = row.get(0)?;
                        let to_address: Option<String> = row.get(1)?;
                        let ephemeral_address: Option<String> = row.get(2)?;
                        let address_index: Option<u32> = row.get(3)?;
                        Ok((u64::from(v), to_address, ephemeral_address, address_index))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            })
            .collect();

        // Verify that a status request has been generated for the second transaction of
        // the ZIP 320 pair.
        let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
        assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(*txids.last())));

        assert!(expected_step0_change < expected_ephemeral);
        assert_eq!(confirmed_sent.len(), 2);
        assert_eq!(confirmed_sent[0].len(), 2);
        assert_eq!(
            confirmed_sent[0][0].0,
            u64::try_from(expected_step0_change).unwrap()
        );
        let (ephemeral_v, to_addr, ephemeral_addr, index) = confirmed_sent[0][1].clone();
        assert_eq!(ephemeral_v, u64::try_from(expected_ephemeral).unwrap());
        assert!(to_addr.is_some());
        assert_eq!(ephemeral_addr, to_addr);
        assert_eq!(index, Some(expected_index));

        assert_eq!(confirmed_sent[1].len(), 1);
        assert_matches!(
            confirmed_sent[1][0].clone(),
            (sent_v, sent_to_addr, None, None)
            if sent_v == u64::try_from(transfer_amount).unwrap() && sent_to_addr == Some(tex_addr.encode(st.network())));

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
        assert_eq!(tx_0.has_change(), expected_step0_change.is_positive());
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
            -ZatBalance::from(expected_ephemeral),
        );

        (ephemeral_addr.unwrap(), txids)
    };

    // Each transfer should use a different ephemeral address.
    let (ephemeral0, txids0) = run_test(&mut st, 0);
    let (ephemeral1, txids1) = run_test(&mut st, 1);
    assert_ne!(ephemeral0, ephemeral1);

    let height = add_funds(&mut st, value);

    let ephemeral_taddr = Address::decode(st.network(), &ephemeral0).expect("valid address");
    assert_matches!(
        ephemeral_taddr,
        Address::Transparent(TransparentAddress::PublicKeyHash(_))
    );

    // Attempting to pay to an ephemeral address should cause an error.
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            NonZeroU32::new(1).unwrap(),
            &ephemeral_taddr,
            transfer_amount,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(
        &create_proposed_result,
        Err(Error::PaysEphemeralTransparentAddress(address_str)) if address_str == &ephemeral0);

    // Simulate another wallet sending to an ephemeral address with an index
    // within the current gap limit. The `PaysEphemeralTransparentAddress` error
    // prevents us from doing so straightforwardly, so we'll do it by building
    // a transaction and calling `store_decrypted_tx` with it.
    let known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, None)
        .unwrap();
    assert_eq!(known_addrs.len(), (GAP_LIMIT as usize) + 2);

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
    let (colliding_addr, _) = &known_addrs[10];
    let utxo_value = (value - zip317::MINIMUM_FEE).unwrap();
    assert_matches!(
        builder.add_transparent_output(colliding_addr, utxo_value),
        Ok(_)
    );
    let sk = account
        .usk()
        .transparent()
        .derive_secret_key(Scope::External.into(), default_index)
        .unwrap();
    let outpoint = OutPoint::fake();
    let txout = TxOut {
        script_pubkey: default_addr.script(),
        value,
    };
    // Add the fake input to our UTXO set so that we can ensure we recognize the outpoint.
    st.wallet_mut()
        .put_received_transparent_utxo(
            &WalletTransparentOutput::from_parts(outpoint.clone(), txout.clone(), None).unwrap(),
        )
        .unwrap();

    assert_matches!(builder.add_transparent_input(sk, outpoint, txout), Ok(_));
    let test_prover = LocalTxProver::bundled();
    let build_result = builder
        .build(
            OsRng,
            &test_prover,
            &test_prover,
            &zip317::FeeRule::standard(),
        )
        .unwrap();
    let txid = build_result.transaction().txid();
    st.wallet_mut()
        .store_decrypted_tx(DecryptedTransaction::<AccountId>::new(
            None,
            build_result.transaction(),
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
        ))
        .unwrap();

    // Verify that storing the fully transparent transaction causes a transaction
    // status request to be generated.
    let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
    assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(txid)));

    // We call get_wallet_transparent_output with `allow_unspendable = true` to verify
    // storage because the decrypted transaction has not yet been mined.
    let utxo =
        get_wallet_transparent_output(st.wallet().conn(), &OutPoint::new(txid.into(), 0), true)
            .unwrap();
    assert_matches!(utxo, Some(v) if v.value() == utxo_value);

    // That should have advanced the start of the gap to index 11.
    let new_known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, None)
        .unwrap();
    assert_eq!(new_known_addrs.len(), (GAP_LIMIT as usize) + 11);
    assert!(new_known_addrs.starts_with(&known_addrs));

    let reservation_should_succeed = |st: &mut TestState<_, TestDb, _>, n| {
        let reserved = st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n)
            .unwrap();
        assert_eq!(reserved.len(), n);
        reserved
    };
    let reservation_should_fail = |st: &mut TestState<_, TestDb, _>, n, expected_bad_index| {
        assert_matches!(st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n),
            Err(SqliteClientError::ReachedGapLimit(acct, bad_index))
            if acct == account_id && bad_index == expected_bad_index);
    };

    let next_reserved = reservation_should_succeed(&mut st, 1);
    assert_eq!(next_reserved[0], known_addrs[11]);

    // Calling `reserve_next_n_ephemeral_addresses(account_id, 1)` will have advanced
    // the start of the gap to index 12. This also tests the `index_range` parameter.
    let newer_known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, Some(5..100))
        .unwrap();
    assert_eq!(newer_known_addrs.len(), (GAP_LIMIT as usize) + 12 - 5);
    assert!(newer_known_addrs.starts_with(&new_known_addrs[5..]));

    // None of the five transactions created above (two from each proposal and the
    // one built manually) have been mined yet. So, the range of address indices
    // that are safe to reserve is still 0..20, and we have already reserved 12
    // addresses, so trying to reserve another 9 should fail.
    reservation_should_fail(&mut st, 9, 20);
    reservation_should_succeed(&mut st, 8);
    reservation_should_fail(&mut st, 1, 20);

    // Now mine the transaction with the ephemeral output at index 1.
    // We already reserved 20 addresses, so this should allow 2 more (..22).
    // It does not matter that the transaction with ephemeral output at index 0
    // remains unmined.
    let (h, _) = st.generate_next_block_including(txids1.head);
    st.scan_cached_blocks(h, 1);
    reservation_should_succeed(&mut st, 2);
    reservation_should_fail(&mut st, 1, 22);

    // Mining the transaction with the ephemeral output at index 0 at this point
    // should make no difference.
    let (h, _) = st.generate_next_block_including(txids0.head);
    st.scan_cached_blocks(h, 1);
    reservation_should_fail(&mut st, 1, 22);

    // Now mine the transaction with the ephemeral output at index 10.
    let tx = build_result.transaction();
    let tx_index = 1;
    let (h, _) = st.generate_next_block_from_tx(tx_index, tx);
    st.scan_cached_blocks(h, 1);

    // The above `scan_cached_blocks` does not detect `tx` as interesting to the
    // wallet. If a transaction is in the database with a null `mined_height`,
    // as in this case, its `mined_height` will remain null unless either
    // `put_tx_meta` or `set_transaction_status` is called on it. The former
    // is normally called internally via `put_blocks` as a result of scanning,
    // but not for the case of a fully transparent transaction. The latter is
    // called by the wallet implementation in response to processing the
    // `transaction_data_requests` queue.

    // The reservation should fail because `tx` is not yet seen as mined.
    reservation_should_fail(&mut st, 1, 22);

    // Simulate the wallet processing the `transaction_data_requests` queue.
    let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
    assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(tx.txid())));

    // Respond to the GetStatus request.
    st.wallet_mut()
        .set_transaction_status(tx.txid(), TransactionStatus::Mined(h))
        .unwrap();

    // We already reserved 22 addresses, so mining the transaction with the
    // ephemeral output at index 10 should allow 9 more (..31).
    reservation_should_succeed(&mut st, 9);
    reservation_should_fail(&mut st, 1, 31);

    let newest_known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, None)
        .unwrap();
    assert_eq!(newest_known_addrs.len(), (GAP_LIMIT as usize) + 31);
    assert!(newest_known_addrs.starts_with(&known_addrs));
    assert!(newest_known_addrs[5..].starts_with(&newer_known_addrs));
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn proposal_fails_if_not_all_ephemeral_outputs_consumed<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[allow(deprecated)]
pub(crate) fn create_to_address_fails_on_incorrect_usk<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::create_to_address_fails_on_incorrect_usk::<T>(
        TestDbFactory,
    )
}

#[allow(deprecated)]
pub(crate) fn proposal_fails_with_no_blocks<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::proposal_fails_with_no_blocks::<T, _>(
        TestDbFactory,
    )
}

pub(crate) fn spend_fails_on_unverified_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_fails_on_unverified_notes::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn spend_fails_on_locked_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_fails_on_locked_notes::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn ovk_policy_prevents_recovery_from_chain<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::ovk_policy_prevents_recovery_from_chain::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn spend_succeeds_to_t_addr_zero_change<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_succeeds_to_t_addr_zero_change::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn change_note_spends_succeed<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::change_note_spends_succeed::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn external_address_change_spends_detected_in_restore_from_seed<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::external_address_change_spends_detected_in_restore_from_seed::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn zip317_spend<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::zip317_spend::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn shield_transparent<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::shield_transparent::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn birthday_in_anchor_shard<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::birthday_in_anchor_shard::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn checkpoint_gaps<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::checkpoint_gaps::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn pool_crossing_required<T: ShieldedPoolTester, TT: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::pool_crossing_required::<T, TT>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn fully_funded_fully_private<T: ShieldedPoolTester, TT: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::fully_funded_fully_private::<T, TT>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
pub(crate) fn fully_funded_send_to_t<T: ShieldedPoolTester, TT: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::fully_funded_send_to_t::<T, TT>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn multi_pool_checkpoint<T: ShieldedPoolTester, TT: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::multi_pool_checkpoint::<T, TT>(
        TestDbFactory,
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn multi_pool_checkpoints_with_pruning<T: ShieldedPoolTester, TT: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::multi_pool_checkpoints_with_pruning::<T, TT>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn valid_chain_states<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::valid_chain_states::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn invalid_chain_cache_disconnected<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::invalid_chain_cache_disconnected::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn data_db_truncation<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::data_db_truncation::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn scan_cached_blocks_allows_blocks_out_of_order<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<T>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn scan_cached_blocks_finds_received_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_finds_received_notes::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn scan_cached_blocks_finds_change_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_finds_change_notes::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}

pub(crate) fn scan_cached_blocks_detects_spends_out_of_order<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_detects_spends_out_of_order::<T, _>(
        TestDbFactory,
        BlockCache::new(),
    )
}
