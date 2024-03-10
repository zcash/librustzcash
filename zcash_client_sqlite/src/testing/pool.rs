//! Test logic involving a single shielded pool.
//!
//! Generalised for sharing across the Sapling and Orchard implementations.

use std::{convert::Infallible, num::NonZeroU32};

use incrementalmerkletree::Level;
use rusqlite::params;
use secrecy::Secret;
use shardtree::error::ShardTreeError;
use zcash_primitives::{
    block::BlockHash,
    consensus::BranchId,
    legacy::TransparentAddress,
    memo::{Memo, MemoBytes},
    transaction::{
        components::amount::NonNegativeAmount,
        fees::{
            fixed::FeeRule as FixedFeeRule, zip317::FeeError as Zip317FeeError, StandardFeeRule,
        },
        Transaction,
    },
    zip32::Scope,
};

use zcash_client_backend::{
    address::Address,
    data_api::{
        self,
        chain::CommitmentTreeRoot,
        error::Error,
        wallet::input_selection::{GreedyInputSelector, GreedyInputSelectorError},
        AccountBirthday, DecryptedTransaction, Ratio, WalletRead, WalletSummary, WalletWrite,
    },
    decrypt_transaction,
    fees::{fixed, standard, DustOutputPolicy},
    keys::UnifiedSpendingKey,
    wallet::{Note, OvkPolicy, ReceivedNote},
    zip321::{self, Payment, TransactionRequest},
    ShieldedProtocol,
};
use zcash_protocol::consensus::BlockHeight;

use super::TestFvk;
use crate::{
    error::SqliteClientError,
    testing::{input_selector, AddressType, BlockCache, TestBuilder, TestState},
    wallet::{
        block_max_scanned, commitment_tree, parse_scope,
        scanning::tests::test_with_nu5_birthday_offset,
    },
    AccountId, NoteId, ReceivedNoteId,
};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::{
        fees::TransactionBalance, proposal::Step, wallet::WalletTransparentOutput, PoolType,
    },
    zcash_primitives::{
        legacy::keys::IncomingViewingKey,
        transaction::components::{OutPoint, TxOut},
    },
};

pub(crate) type OutputRecoveryError = Error<
    SqliteClientError,
    commitment_tree::Error,
    GreedyInputSelectorError<Zip317FeeError, ReceivedNoteId>,
    Zip317FeeError,
>;

/// Trait that exposes the pool-specific types and operations necessary to run the
/// single-shielded-pool tests on a given pool.
pub(crate) trait ShieldedPoolTester {
    const SHIELDED_PROTOCOL: ShieldedProtocol;
    const TABLES_PREFIX: &'static str;

    type Sk;
    type Fvk: TestFvk;
    type MerkleTreeHash;

    fn test_account_fvk<Cache>(st: &TestState<Cache>) -> Self::Fvk;
    fn usk_to_sk(usk: &UnifiedSpendingKey) -> &Self::Sk;
    fn sk(seed: &[u8]) -> Self::Sk;
    fn sk_to_fvk(sk: &Self::Sk) -> Self::Fvk;
    fn sk_default_address(sk: &Self::Sk) -> Address;
    fn fvk_default_address(fvk: &Self::Fvk) -> Address;
    fn fvks_equal(a: &Self::Fvk, b: &Self::Fvk) -> bool;

    fn empty_tree_leaf() -> Self::MerkleTreeHash;
    fn empty_tree_root(level: Level) -> Self::MerkleTreeHash;

    fn put_subtree_roots<Cache>(
        st: &mut TestState<Cache>,
        start_index: u64,
        roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
    ) -> Result<(), ShardTreeError<commitment_tree::Error>>;

    fn next_subtree_index(s: &WalletSummary<AccountId>) -> u64;

    fn select_spendable_notes<Cache>(
        st: &TestState<Cache>,
        account: AccountId,
        target_value: NonNegativeAmount,
        anchor_height: BlockHeight,
        exclude: &[ReceivedNoteId],
    ) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>;

    fn decrypted_pool_outputs_count(d_tx: &DecryptedTransaction<'_, AccountId>) -> usize;

    fn with_decrypted_pool_memos(
        d_tx: &DecryptedTransaction<'_, AccountId>,
        f: impl FnMut(&MemoBytes),
    );

    fn try_output_recovery<Cache>(
        st: &TestState<Cache>,
        height: BlockHeight,
        tx: &Transaction,
        fvk: &Self::Fvk,
    ) -> Result<Option<(Note, Address, MemoBytes)>, OutputRecoveryError>;
}

pub(crate) fn send_single_step_proposed_transfer<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    assert_eq!(
        block_max_scanned(&st.wallet().conn, &st.wallet().params)
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment {
        recipient_address: to,
        amount: NonNegativeAmount::const_from_u64(10000),
        memo: None, // this should result in the creation of an empty memo
        label: None,
        message: None,
        other_params: vec![],
    }])
    .unwrap();

    // TODO: This test was originally written to use the pre-zip-313 fee rule
    // and has not yet been updated.
    #[allow(deprecated)]
    let fee_rule = StandardFeeRule::PreZip313;

    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        fee_rule,
        Some(change_memo.clone().into()),
        T::SHIELDED_PROTOCOL,
    );
    let input_selector = &GreedyInputSelector::new(change_strategy, DustOutputPolicy::default());

    let proposal = st
        .propose_transfer(
            sources,
            input_selector,
            request,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let create_proposed_result =
        st.create_proposed_transactions::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal);
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .expect("Created transaction was stored.");
    let ufvks = [(account, usk.to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(&st.network(), h + 1, &tx, &ufvks);
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 2);

    let mut found_tx_change_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == change_memo {
            found_tx_change_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_tx_change_memo);
    assert!(found_tx_empty_memo);

    // Verify that the stored sent notes match what we're expecting
    let mut stmt_sent_notes = st
        .wallet()
        .conn
        .prepare(
            "SELECT output_index
            FROM sent_notes
            JOIN transactions ON transactions.id_tx = sent_notes.tx
            WHERE transactions.txid = ?",
        )
        .unwrap();

    let sent_note_ids = stmt_sent_notes
        .query(rusqlite::params![sent_tx_id.as_ref()])
        .unwrap()
        .mapped(|row| Ok(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, row.get(0)?)))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(sent_note_ids.len(), 2);

    // The sent memo should be the empty memo for the sent output, and the
    // change output's memo should be as specified.
    let mut found_sent_change_memo = false;
    let mut found_sent_empty_memo = false;
    for sent_note_id in sent_note_ids {
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
            Some(other) => panic!("Unexpected memo value: {:?}", other),
            None => panic!("Memo should not be stored as NULL"),
        }
    }
    assert!(found_sent_change_memo);
    assert!(found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, 12345)),
        Ok(None)
    );
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn send_multi_step_proposed_transfer<T: ShieldedPoolTester>() {
    use nonempty::NonEmpty;
    use zcash_client_backend::proposal::{Proposal, StepOutput, StepOutputIndex};

    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(65000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    assert_eq!(
        block_max_scanned(&st.wallet().conn, &st.wallet().params)
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    // Generate a single-step proposal. Then, instead of executing that proposal,
    // we will use its only step as the first step in a multi-step proposal that
    // spends the first step's output.

    // The first step will deshield to the wallet's default transparent address
    let to0 = Address::Transparent(usk.default_transparent_address().0);
    let request0 = zip321::TransactionRequest::new(vec![Payment {
        recipient_address: to0,
        amount: NonNegativeAmount::const_from_u64(50000),
        memo: None,
        label: None,
        message: None,
        other_params: vec![],
    }])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;
    let input_selector = GreedyInputSelector::new(
        standard::SingleOutputChangeStrategy::new(fee_rule, None, T::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );
    let proposal0 = st
        .propose_transfer(
            sources,
            &input_selector,
            request0,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let min_target_height = proposal0.min_target_height();
    let step0 = &proposal0.steps().head;

    assert!(step0.balance().proposed_change().is_empty());
    assert_eq!(
        step0.balance().fee_required(),
        NonNegativeAmount::const_from_u64(15000)
    );

    // We'll use an internal transparent address that hasn't been added to the wallet
    // to simulate an external transparent recipient.
    let to1 = Address::Transparent(
        usk.transparent()
            .to_account_pubkey()
            .derive_internal_ivk()
            .unwrap()
            .default_address()
            .0,
    );
    let request1 = zip321::TransactionRequest::new(vec![Payment {
        recipient_address: to1,
        amount: NonNegativeAmount::const_from_u64(40000),
        memo: None,
        label: None,
        message: None,
        other_params: vec![],
    }])
    .unwrap();

    let step1 = Step::from_parts(
        &[step0.clone()],
        request1,
        [(0, PoolType::Transparent)].into_iter().collect(),
        vec![],
        None,
        vec![StepOutput::new(0, StepOutputIndex::Payment(0))],
        TransactionBalance::new(vec![], NonNegativeAmount::const_from_u64(10000)).unwrap(),
        false,
    )
    .unwrap();

    let proposal = Proposal::multi_step(
        fee_rule,
        min_target_height,
        NonEmpty::from_vec(vec![step0.clone(), step1]).unwrap(),
    )
    .unwrap();

    let create_proposed_result =
        st.create_proposed_transactions::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal);
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
    let txids = create_proposed_result.unwrap();

    // Verify that the stored sent outputs match what we're expecting
    let mut stmt_sent = st
        .wallet()
        .conn
        .prepare(
            "SELECT value
            FROM sent_notes
            JOIN transactions ON transactions.id_tx = sent_notes.tx
            WHERE transactions.txid = ?",
        )
        .unwrap();

    let confirmed_sent = txids
        .iter()
        .map(|sent_txid| {
            // check that there's a sent output with the correct value corresponding to
            stmt_sent
                .query(rusqlite::params![sent_txid.as_ref()])
                .unwrap()
                .mapped(|row| {
                    let value: u32 = row.get(0)?;
                    Ok((sent_txid, value))
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        confirmed_sent.get(0).and_then(|v| v.get(0)),
        Some(&(&txids[0], 50000))
    );
    assert_eq!(
        confirmed_sent.get(1).and_then(|v| v.get(0)),
        Some(&(&txids[1], 40000))
    );
}

#[allow(deprecated)]
pub(crate) fn create_to_address_fails_on_incorrect_usk<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Create a USK that doesn't exist in the wallet
    let acct1 = zip32::AccountId::try_from(1).unwrap();
    let usk1 = UnifiedSpendingKey::from_seed(&st.network(), &[1u8; 32], acct1).unwrap();

    // Attempting to spend with a USK that is not in the wallet results in an error
    assert_matches!(
        st.create_spend_to_address(
            &usk1,
            &to,
            NonNegativeAmount::const_from_u64(1),
            None,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::KeyNotRecognized)
    );
}

#[allow(deprecated)]
pub(crate) fn proposal_fails_with_no_blocks<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (account, _, _) = st.test_account().unwrap();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // We cannot do anything if we aren't synchronised
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account,
            StandardFeeRule::PreZip313,
            NonZeroU32::new(1).unwrap(),
            &to,
            NonNegativeAmount::const_from_u64(1),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::ScanRequired)
    );
}

pub(crate) fn spend_fails_on_unverified_notes<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(st.get_pending_shielded_balance(account, 10), value);
    assert_eq!(
        st.get_spendable_balance(account, 10),
        NonNegativeAmount::ZERO
    );

    // Wallet is fully scanned
    let summary = st.get_wallet_summary(1);
    assert_eq!(
        summary.and_then(|s| s.scan_progress()),
        Some(Ratio::new(1, 1))
    );

    // Add more funds to the wallet in a second note
    let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h2, 1);

    // Verified balance does not include the second note
    let total = (value + value).unwrap();
    assert_eq!(st.get_spendable_balance(account, 2), value);
    assert_eq!(st.get_pending_shielded_balance(account, 2), value);
    assert_eq!(st.get_total_balance(account), total);

    // Wallet is still fully scanned
    let summary = st.get_wallet_summary(1);
    assert_eq!(
        summary.and_then(|s| s.scan_progress()),
        Some(Ratio::new(2, 2))
    );

    // Spend fails because there are insufficient verified notes
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            sources,
            StandardFeeRule::Zip317,
            NonZeroU32::new(2).unwrap(),
            &to,
            NonNegativeAmount::const_from_u64(70000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == NonNegativeAmount::const_from_u64(50000)
            && required == NonNegativeAmount::const_from_u64(80000)
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 2 to 9 until just before the second
    // note is verified
    for _ in 2..10 {
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    }
    st.scan_cached_blocks(h2 + 1, 8);

    // Total balance is value * number of blocks scanned (10).
    assert_eq!(st.get_total_balance(account), (value * 10).unwrap());

    // Spend still fails
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            sources,
            StandardFeeRule::Zip317,
            NonZeroU32::new(10).unwrap(),
            &to,
            NonNegativeAmount::const_from_u64(70000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == NonNegativeAmount::const_from_u64(50000)
            && required == NonNegativeAmount::const_from_u64(80000)
    );

    // Mine block 11 so that the second note becomes verified
    let (h11, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h11, 1);

    // Total balance is value * number of blocks scanned (11).
    assert_eq!(st.get_total_balance(account), (value * 11).unwrap());
    // Spendable balance at 10 confirmations is value * 2.
    assert_eq!(st.get_spendable_balance(account, 10), (value * 2).unwrap());
    assert_eq!(
        st.get_pending_shielded_balance(account, 10),
        (value * 9).unwrap()
    );

    // Should now be able to generate a proposal
    let amount_sent = NonNegativeAmount::from_u64(70000).unwrap();
    let min_confirmations = NonZeroU32::new(10).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            sources,
            StandardFeeRule::Zip317,
            min_confirmations,
            &to,
            amount_sent,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    let txid = st
        .create_proposed_transactions::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal)
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account),
        ((value * 11).unwrap()
            - (amount_sent + NonNegativeAmount::from_u64(10000).unwrap()).unwrap())
        .unwrap()
    );
}

pub(crate) fn spend_fails_on_locked_notes<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // TODO: This test was originally written to use the pre-zip-313 fee rule
    // and has not yet been updated.
    #[allow(deprecated)]
    let fee_rule = StandardFeeRule::PreZip313;

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    // Send some of the funds to another address, but don't mine the tx.
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            sources,
            fee_rule,
            min_confirmations,
            &to,
            NonNegativeAmount::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal,),
        Ok(txids) if txids.len() == 1
    );

    // A second proposal fails because there are no usable notes
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            sources,
            fee_rule,
            NonZeroU32::new(1).unwrap(),
            &to,
            NonNegativeAmount::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == NonNegativeAmount::ZERO && required == NonNegativeAmount::const_from_u64(12000)
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 41 (that don't send us funds)
    // until just before the first transaction expires
    for i in 1..42 {
        st.generate_next_block(
            &T::sk_to_fvk(&T::sk(&[i as u8])),
            AddressType::DefaultExternal,
            value,
        );
    }
    st.scan_cached_blocks(h1 + 1, 41);

    // Second proposal still fails
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            sources,
            fee_rule,
            NonZeroU32::new(1).unwrap(),
            &to,
            NonNegativeAmount::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == NonNegativeAmount::ZERO && required == NonNegativeAmount::const_from_u64(12000)
    );

    // Mine block SAPLING_ACTIVATION_HEIGHT + 42 so that the first transaction expires
    let (h43, _, _) = st.generate_next_block(
        &T::sk_to_fvk(&T::sk(&[42])),
        AddressType::DefaultExternal,
        value,
    );
    st.scan_cached_blocks(h43, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    // Second spend should now succeed
    let amount_sent2 = NonNegativeAmount::const_from_u64(2000);
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            sources,
            fee_rule,
            min_confirmations,
            &to,
            amount_sent2,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    let txid2 = st
        .create_proposed_transactions::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal)
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid2);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account),
        (value - (amount_sent2 + NonNegativeAmount::from_u64(10000).unwrap()).unwrap()).unwrap()
    );
}

pub(crate) fn ovk_policy_prevents_recovery_from_chain<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    let extsk2 = T::sk(&[0xf5; 32]);
    let addr2 = T::sk_default_address(&extsk2);

    // TODO: This test was originally written to use the pre-zip-313 fee rule
    // and has not yet been updated.
    #[allow(deprecated)]
    let fee_rule = StandardFeeRule::PreZip313;

    #[allow(clippy::type_complexity)]
    let send_and_recover_with_policy = |st: &mut TestState<BlockCache>,
                                        ovk_policy|
     -> Result<
        Option<(Note, Address, MemoBytes)>,
        Error<
            SqliteClientError,
            commitment_tree::Error,
            GreedyInputSelectorError<Zip317FeeError, ReceivedNoteId>,
            Zip317FeeError,
        >,
    > {
        let min_confirmations = NonZeroU32::new(1).unwrap();
        let proposal = st.propose_standard_transfer(
            sources,
            fee_rule,
            min_confirmations,
            &addr2,
            NonNegativeAmount::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )?;

        // Executing the proposal should succeed
        let txid = st.create_proposed_transactions(&usk, ovk_policy, &proposal)?[0];

        // Fetch the transaction from the database
        let raw_tx: Vec<_> = st
            .wallet()
            .conn
            .query_row(
                "SELECT raw FROM transactions
                WHERE txid = ?",
                [txid.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        let tx = Transaction::read(&raw_tx[..], BranchId::Canopy).unwrap();

        T::try_output_recovery(st, h1, &tx, &dfvk)
    };

    // Send some of the funds to another address, keeping history.
    // The recipient output is decryptable by the sender.
    assert_matches!(
        send_and_recover_with_policy(&mut st, OvkPolicy::Sender),
        Ok(Some((_, recovered_to, _))) if recovered_to == addr2
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 42 (that don't send us funds)
    // so that the first transaction expires
    for i in 1..=42 {
        st.generate_next_block(
            &T::sk_to_fvk(&T::sk(&[i as u8])),
            AddressType::DefaultExternal,
            value,
        );
    }
    st.scan_cached_blocks(h1 + 1, 42);

    // Send the funds again, discarding history.
    // Neither transaction output is decryptable by the sender.
    assert_matches!(
        send_and_recover_with_policy(&mut st, OvkPolicy::Discard),
        Ok(None)
    );
}

pub(crate) fn spend_succeeds_to_t_addr_zero_change<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    // TODO: This test was originally written to use the pre-zip-313 fee rule
    // and has not yet been updated.
    #[allow(deprecated)]
    let fee_rule = StandardFeeRule::PreZip313;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            sources,
            fee_rule,
            min_confirmations,
            &to,
            NonNegativeAmount::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub(crate) fn change_note_spends_succeed<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note owned by the internal spending key
    let value = NonNegativeAmount::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(st.get_pending_shielded_balance(account, 10), value);
    assert_eq!(
        st.get_spendable_balance(account, 10),
        NonNegativeAmount::ZERO
    );

    let change_note_scope = st.wallet().conn.query_row(
        &format!(
            "SELECT recipient_key_scope
             FROM {}_received_notes
             WHERE value = ?",
            T::TABLES_PREFIX,
        ),
        params![u64::from(value)],
        |row| Ok(parse_scope(row.get(0)?)),
    );
    assert_matches!(change_note_scope, Ok(Some(Scope::Internal)));

    // TODO: This test was originally written to use the pre-zip-313 fee rule
    // and has not yet been updated.
    #[allow(deprecated)]
    let fee_rule = StandardFeeRule::PreZip313;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            sources,
            fee_rule,
            min_confirmations,
            &to,
            NonNegativeAmount::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub(crate) fn external_address_change_spends_detected_in_restore_from_seed<
    T: ShieldedPoolTester,
>() {
    let mut st = TestBuilder::new().with_block_cache().build();

    // Add two accounts to the wallet.
    let seed = Secret::new([0u8; 32].to_vec());
    let birthday = AccountBirthday::from_sapling_activation(&st.network());
    let (account, usk) = st
        .wallet_mut()
        .create_account(&seed, birthday.clone())
        .unwrap();
    let dfvk = T::sk_to_fvk(T::usk_to_sk(&usk));

    let (account2, usk2) = st
        .wallet_mut()
        .create_account(&seed, birthday.clone())
        .unwrap();
    let dfvk2 = T::sk_to_fvk(T::usk_to_sk(&usk2));

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::from_u64(100000).unwrap();
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account), value);
    assert_eq!(st.get_spendable_balance(account, 1), value);
    assert_eq!(st.get_total_balance(account2), NonNegativeAmount::ZERO);

    let amount_sent = NonNegativeAmount::from_u64(20000).unwrap();
    let amount_legacy_change = NonNegativeAmount::from_u64(30000).unwrap();
    let addr = T::fvk_default_address(&dfvk);
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![
        // payment to an external recipient
        Payment {
            recipient_address: addr2,
            amount: amount_sent,
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        },
        // payment back to the originating wallet, simulating legacy change
        Payment {
            recipient_address: addr,
            amount: amount_legacy_change,
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        },
    ])
    .unwrap();

    #[allow(deprecated)]
    let fee_rule = FixedFeeRule::standard();
    let input_selector = GreedyInputSelector::new(
        fixed::SingleOutputChangeStrategy::new(fee_rule, None, T::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );

    let txid = st
        .spend(
            &input_selector,
            &usk,
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap()[0];

    let amount_left = (value - (amount_sent + fee_rule.fixed_fee()).unwrap()).unwrap();
    let pending_change = (amount_left - amount_legacy_change).unwrap();

    // The "legacy change" is not counted by get_pending_change().
    assert_eq!(st.get_pending_change(account, 1), pending_change);
    // We spent the only note so we only have pending change.
    assert_eq!(st.get_total_balance(account), pending_change);

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), amount_sent,);
    assert_eq!(st.get_total_balance(account), amount_left);

    st.reset();

    // Account creation and DFVK derivation should be deterministic.
    let (_, restored_usk) = st
        .wallet_mut()
        .create_account(&seed, birthday.clone())
        .unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk)),
        &dfvk,
    ));

    let (_, restored_usk2) = st.wallet_mut().create_account(&seed, birthday).unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk2)),
        &dfvk2,
    ));

    st.scan_cached_blocks(st.sapling_activation_height(), 2);

    assert_eq!(st.get_total_balance(account2), amount_sent,);
    assert_eq!(st.get_total_balance(account), amount_left);
}

pub(crate) fn zip317_spend<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet
    let (h1, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::Internal,
        NonNegativeAmount::const_from_u64(50000),
    );

    // Add 10 dust notes to the wallet
    for _ in 1..=10 {
        st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            NonNegativeAmount::const_from_u64(1000),
        );
    }

    st.scan_cached_blocks(h1, 11);

    // Spendable balance matches total balance
    let total = NonNegativeAmount::const_from_u64(60000);
    assert_eq!(st.get_total_balance(account), total);
    assert_eq!(st.get_spendable_balance(account, 1), total);

    let input_selector = input_selector(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    // This first request will fail due to insufficient non-dust funds
    let req = TransactionRequest::new(vec![Payment {
        recipient_address: T::fvk_default_address(&dfvk),
        amount: NonNegativeAmount::const_from_u64(50000),
        memo: None,
        label: None,
        message: None,
        other_params: vec![],
    }])
    .unwrap();

    assert_matches!(
        st.spend(
            &input_selector,
            &usk,
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        ),
        Err(Error::InsufficientFunds { available, required })
            if available == NonNegativeAmount::const_from_u64(51000)
            && required == NonNegativeAmount::const_from_u64(60000)
    );

    // This request will succeed, spending a single dust input to pay the 10000
    // ZAT fee in addition to the 41000 ZAT output to the recipient
    let req = TransactionRequest::new(vec![Payment {
        recipient_address: T::fvk_default_address(&dfvk),
        amount: NonNegativeAmount::const_from_u64(41000),
        memo: None,
        label: None,
        message: None,
        other_params: vec![],
    }])
    .unwrap();

    let txid = st
        .spend(
            &input_selector,
            &usk,
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    // We sent back to the same account so the amount_sent should be included
    // in the total balance.
    assert_eq!(
        st.get_total_balance(account),
        (total - NonNegativeAmount::const_from_u64(10000)).unwrap()
    );
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn shield_transparent<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, _) = st.test_account().unwrap();
    let account_id = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    let uaddr = st
        .wallet()
        .get_current_address(account_id)
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

    // Ensure that the wallet has at least one block
    let (h, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::Internal,
        NonNegativeAmount::const_from_u64(50000),
    );
    st.scan_cached_blocks(h, 1);

    let utxo = WalletTransparentOutput::from_parts(
        OutPoint::new([1u8; 32], 1),
        TxOut {
            value: NonNegativeAmount::const_from_u64(10000),
            script_pubkey: taddr.script(),
        },
        h,
    )
    .unwrap();

    let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
    assert!(matches!(res0, Ok(_)));

    // TODO: This test was originally written to use the pre-zip-313 fee rule
    // and has not yet been updated.
    #[allow(deprecated)]
    let fee_rule = StandardFeeRule::PreZip313;

    let input_selector = GreedyInputSelector::new(
        standard::SingleOutputChangeStrategy::new(fee_rule, None, T::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );

    assert_matches!(
        st.shield_transparent_funds(
            &input_selector,
            NonNegativeAmount::from_u64(10000).unwrap(),
            &usk,
            &[*taddr],
            1
        ),
        Ok(_)
    );
}

pub(crate) fn birthday_in_anchor_shard<T: ShieldedPoolTester>() {
    // Use a non-zero birthday offset because Sapling and NU5 are activated at the same height.
    let (mut st, dfvk, birthday, _) = test_with_nu5_birthday_offset::<T>(76);

    // Set up the following situation:
    //
    //        |<------ 500 ------->|<--- 10 --->|<--- 10 --->|
    // last_shard_start   wallet_birthday  received_tx  anchor_height
    //
    // Set up some shard root history before the wallet birthday.
    let prev_shard_start = birthday.height() - 500;
    T::put_subtree_roots(
        &mut st,
        0,
        &[CommitmentTreeRoot::from_parts(
            prev_shard_start,
            // fake a hash, the value doesn't matter
            T::empty_tree_leaf(),
        )],
    )
    .unwrap();

    let received_tx_height = birthday.height() + 10;

    let initial_sapling_tree_size = birthday
        .sapling_frontier()
        .value()
        .map(|f| u64::from(f.position() + 1))
        .unwrap_or(0)
        .try_into()
        .unwrap();
    #[cfg(feature = "orchard")]
    let initial_orchard_tree_size = birthday
        .orchard_frontier()
        .value()
        .map(|f| u64::from(f.position() + 1))
        .unwrap_or(0)
        .try_into()
        .unwrap();
    #[cfg(not(feature = "orchard"))]
    let initial_orchard_tree_size = 0;

    // Generate 9 blocks that have no value for us, starting at the birthday height.
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let not_our_value = NonNegativeAmount::const_from_u64(10000);
    st.generate_block_at(
        birthday.height(),
        BlockHash([0; 32]),
        &not_our_key,
        AddressType::DefaultExternal,
        not_our_value,
        initial_sapling_tree_size,
        initial_orchard_tree_size,
    );
    for _ in 1..9 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }

    // Now, generate a block that belongs to our wallet
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(500000),
    );

    // Generate some more blocks to get above our anchor height
    for _ in 0..15 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }

    // Scan a block range that includes our received note, but skips some blocks we need to
    // make it spendable.
    st.scan_cached_blocks(birthday.height() + 5, 20);

    // Verify that the received note is not considered spendable
    let account = st.test_account().unwrap().0.account_id();
    let spendable = T::select_spendable_notes(
        &st,
        account,
        NonNegativeAmount::const_from_u64(300000),
        received_tx_height + 10,
        &[],
    )
    .unwrap();

    assert_eq!(spendable.len(), 0);

    // Scan the blocks we skipped
    st.scan_cached_blocks(birthday.height(), 5);

    // Verify that the received note is now considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account,
        NonNegativeAmount::const_from_u64(300000),
        received_tx_height + 10,
        &[],
    )
    .unwrap();

    assert_eq!(spendable.len(), 1);
}

pub(crate) fn checkpoint_gaps<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_test_account(AccountBirthday::from_sapling_activation)
        .build();

    let (sources, usk, birthday) = st.test_account().unwrap();
    let account = sources.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Generate a block with funds belonging to our wallet.
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(500000),
    );
    st.scan_cached_blocks(birthday.height(), 1);

    // Create a gap of 10 blocks having no shielded outputs, then add a block that doesn't
    // belong to us so that we can get a checkpoint in the tree.
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let not_our_value = NonNegativeAmount::const_from_u64(10000);
    st.generate_block_at(
        birthday.height() + 10,
        BlockHash([0; 32]),
        &not_our_key,
        AddressType::DefaultExternal,
        not_our_value,
        st.latest_cached_block().unwrap().sapling_end_size,
        st.latest_cached_block().unwrap().orchard_end_size,
    );

    // Scan the block
    st.scan_cached_blocks(birthday.height() + 10, 1);

    // Fake that everything has been scanned
    st.wallet()
        .conn
        .execute_batch("UPDATE scan_queue SET priority = 10")
        .unwrap();

    // Verify that our note is considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account,
        NonNegativeAmount::const_from_u64(300000),
        birthday.height() + 5,
        &[],
    )
    .unwrap();
    assert_eq!(spendable.len(), 1);

    // Attempt to spend the note with 5 confirmations
    let to = T::fvk_default_address(&not_our_key);
    assert_matches!(
        st.create_spend_to_address(
            &usk,
            &to,
            NonNegativeAmount::const_from_u64(10000),
            None,
            OvkPolicy::Sender,
            NonZeroU32::new(5).unwrap(),
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Ok(_)
    );
}
