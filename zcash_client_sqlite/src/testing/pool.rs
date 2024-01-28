//! Test logic involving a single shielded pool.
//!
//! Generalised for sharing across the Sapling and Orchard implementations.

use std::{
    convert::Infallible,
    num::{NonZeroU32, NonZeroU8},
};

use incrementalmerkletree::{frontier::Frontier, Level};
use rand_core::RngCore;
use rusqlite::params;
use secrecy::Secret;
use shardtree::error::ShardTreeError;
use zcash_primitives::{
    block::BlockHash,
    consensus::{BranchId, NetworkUpgrade, Parameters},
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
        chain::{self, ChainState, CommitmentTreeRoot, ScanSummary},
        error::Error,
        wallet::{
            decrypt_and_store_transaction,
            input_selection::{GreedyInputSelector, GreedyInputSelectorError},
        },
        AccountBirthday, DecryptedTransaction, Ratio, WalletRead, WalletSummary, WalletWrite,
    },
    decrypt_transaction,
    fees::{fixed, standard, DustOutputPolicy},
    keys::UnifiedSpendingKey,
    scanning::ScanError,
    wallet::{Note, OvkPolicy, ReceivedNote},
    zip321::{self, Payment, TransactionRequest},
    ShieldedProtocol,
};
use zcash_protocol::consensus::BlockHeight;

use super::TestFvk;
use crate::{
    error::SqliteClientError,
    testing::{input_selector, AddressType, BlockCache, InitialChainState, TestBuilder, TestState},
    wallet::{block_max_scanned, commitment_tree, parse_scope, truncate_to_height},
    AccountId, NoteId, ReceivedNoteId,
};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::{
        fees::TransactionBalance, proposal::Step, wallet::WalletTransparentOutput, PoolType,
    },
    zcash_primitives::transaction::components::{OutPoint, TxOut},
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
    type Note;

    fn test_account_fvk<Cache>(st: &TestState<Cache>) -> Self::Fvk;
    fn usk_to_sk(usk: &UnifiedSpendingKey) -> &Self::Sk;
    fn sk(seed: &[u8]) -> Self::Sk;
    fn sk_to_fvk(sk: &Self::Sk) -> Self::Fvk;
    fn sk_default_address(sk: &Self::Sk) -> Address;
    fn fvk_default_address(fvk: &Self::Fvk) -> Address;
    fn fvks_equal(a: &Self::Fvk, b: &Self::Fvk) -> bool;

    fn random_fvk(mut rng: impl RngCore) -> Self::Fvk {
        let sk = {
            let mut sk_bytes = vec![0; 32];
            rng.fill_bytes(&mut sk_bytes);
            Self::sk(&sk_bytes)
        };

        Self::sk_to_fvk(&sk)
    }
    fn random_address(rng: impl RngCore) -> Address {
        Self::fvk_default_address(&Self::random_fvk(rng))
    }

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
    ) -> Result<Vec<ReceivedNote<ReceivedNoteId, Self::Note>>, SqliteClientError>;

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

    fn received_note_count(summary: &ScanSummary) -> usize;
}

pub(crate) fn send_single_step_proposed_transfer<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account.account_id()), value);
    assert_eq!(st.get_spendable_balance(account.account_id(), 1), value);

    assert_eq!(
        block_max_scanned(&st.wallet().conn, &st.wallet().params)
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(&st.network()),
        NonNegativeAmount::const_from_u64(10000),
    )])
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
            account.account_id(),
            input_selector,
            request,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _>(
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
    let ufvks = [(
        account.account_id(),
        account.usk().to_unified_full_viewing_key(),
    )]
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
    let sent_note_ids = {
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

        stmt_sent_notes
            .query(rusqlite::params![sent_tx_id.as_ref()])
            .unwrap()
            .mapped(|row| Ok(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, row.get(0)?)))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

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

    let tx_history = st.get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);

    assert_matches!(
        decrypt_and_store_transaction(&st.network(), st.wallet_mut(), &tx),
        Ok(_)
    );
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn send_multi_step_proposed_transfer<T: ShieldedPoolTester>() {
    use nonempty::NonEmpty;
    use zcash_client_backend::proposal::{Proposal, StepOutput, StepOutputIndex};
    use zcash_primitives::legacy::keys::IncomingViewingKey;

    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(65000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account.account_id()), value);
    assert_eq!(st.get_spendable_balance(account.account_id(), 1), value);

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
    let to0 = Address::Transparent(account.usk().default_transparent_address().0);
    let request0 = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to0.to_zcash_address(&st.network()),
        NonNegativeAmount::const_from_u64(50000),
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;
    let input_selector = GreedyInputSelector::new(
        standard::SingleOutputChangeStrategy::new(fee_rule, None, T::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );
    let proposal0 = st
        .propose_transfer(
            account.account_id(),
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
        account
            .usk()
            .transparent()
            .to_account_pubkey()
            .derive_internal_ivk()
            .unwrap()
            .default_address()
            .0,
    );
    let request1 = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to1.to_zcash_address(&st.network()),
        NonNegativeAmount::const_from_u64(40000),
    )])
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

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
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
        .with_account_from_sapling_activation(BlockHash([0; 32]))
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
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().account_id();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // We cannot do anything if we aren't synchronised
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
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
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(st.get_pending_shielded_balance(account_id, 10), value);
    assert_eq!(
        st.get_spendable_balance(account_id, 10),
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
    assert_eq!(st.get_spendable_balance(account_id, 2), value);
    assert_eq!(st.get_pending_shielded_balance(account_id, 2), value);
    assert_eq!(st.get_total_balance(account_id), total);

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
            account_id,
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
    assert_eq!(st.get_total_balance(account_id), (value * 10).unwrap());

    // Spend still fails
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
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
    assert_eq!(st.get_total_balance(account_id), (value * 11).unwrap());
    // Spendable balance at 10 confirmations is value * 2.
    assert_eq!(
        st.get_spendable_balance(account_id, 10),
        (value * 2).unwrap()
    );
    assert_eq!(
        st.get_pending_shielded_balance(account_id, 10),
        (value * 9).unwrap()
    );

    // Should now be able to generate a proposal
    let amount_sent = NonNegativeAmount::from_u64(70000).unwrap();
    let min_confirmations = NonZeroU32::new(10).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
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
        .create_proposed_transactions::<Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal)
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account_id),
        ((value * 11).unwrap()
            - (amount_sent + NonNegativeAmount::from_u64(10000).unwrap()).unwrap())
        .unwrap()
    );
}

pub(crate) fn spend_fails_on_locked_notes<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.account_id();
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
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // Send some of the funds to another address, but don't mine the tx.
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
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
        st.create_proposed_transactions::<Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal,),
        Ok(txids) if txids.len() == 1
    );

    // A second proposal fails because there are no usable notes
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
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
        &T::sk_to_fvk(&T::sk(&[42; 32])),
        AddressType::DefaultExternal,
        value,
    );
    st.scan_cached_blocks(h43, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // Second spend should now succeed
    let amount_sent2 = NonNegativeAmount::const_from_u64(2000);
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
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
        .create_proposed_transactions::<Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal)
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid2);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account_id),
        (value - (amount_sent2 + NonNegativeAmount::from_u64(10000).unwrap()).unwrap()).unwrap()
    );
}

pub(crate) fn ovk_policy_prevents_recovery_from_chain<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

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
            account_id,
            fee_rule,
            min_confirmations,
            &addr2,
            NonNegativeAmount::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )?;

        // Executing the proposal should succeed
        let txid = st.create_proposed_transactions(account.usk(), ovk_policy, &proposal)?[0];

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
            &T::sk_to_fvk(&T::sk(&[i as u8; 32])),
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
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // TODO: This test was originally written to use the pre-zip-313 fee rule
    // and has not yet been updated.
    #[allow(deprecated)]
    let fee_rule = StandardFeeRule::PreZip313;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
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
        st.create_proposed_transactions::<Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub(crate) fn change_note_spends_succeed<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.account_id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note owned by the internal spending key
    let value = NonNegativeAmount::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(st.get_pending_shielded_balance(account_id, 10), value);
    assert_eq!(
        st.get_spendable_balance(account_id, 10),
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
            account_id,
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
        st.create_proposed_transactions::<Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub(crate) fn external_address_change_spends_detected_in_restore_from_seed<
    T: ShieldedPoolTester,
>() {
    let mut st = TestBuilder::new().with_block_cache().build();

    // Add two accounts to the wallet.
    let seed = Secret::new([0u8; 32].to_vec());
    let birthday = AccountBirthday::from_sapling_activation(&st.network(), BlockHash([0; 32]));
    let (account_id, usk) = st.wallet_mut().create_account(&seed, &birthday).unwrap();
    let dfvk = T::sk_to_fvk(T::usk_to_sk(&usk));

    let (account2, usk2) = st.wallet_mut().create_account(&seed, &birthday).unwrap();
    let dfvk2 = T::sk_to_fvk(T::usk_to_sk(&usk2));

    // Add funds to the wallet in a single note
    let value = NonNegativeAmount::from_u64(100000).unwrap();
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);
    assert_eq!(st.get_total_balance(account2), NonNegativeAmount::ZERO);

    let amount_sent = NonNegativeAmount::from_u64(20000).unwrap();
    let amount_legacy_change = NonNegativeAmount::from_u64(30000).unwrap();
    let addr = T::fvk_default_address(&dfvk);
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![
        // payment to an external recipient
        Payment::without_memo(addr2.to_zcash_address(&st.network()), amount_sent),
        // payment back to the originating wallet, simulating legacy change
        Payment::without_memo(addr.to_zcash_address(&st.network()), amount_legacy_change),
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
    assert_eq!(st.get_pending_change(account_id, 1), pending_change);
    // We spent the only note so we only have pending change.
    assert_eq!(st.get_total_balance(account_id), pending_change);

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), amount_sent,);
    assert_eq!(st.get_total_balance(account_id), amount_left);

    st.reset();

    // Account creation and DFVK derivation should be deterministic.
    let (_, restored_usk) = st.wallet_mut().create_account(&seed, &birthday).unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk)),
        &dfvk,
    ));

    let (_, restored_usk2) = st.wallet_mut().create_account(&seed, &birthday).unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk2)),
        &dfvk2,
    ));

    st.scan_cached_blocks(st.sapling_activation_height(), 2);

    assert_eq!(st.get_total_balance(account2), amount_sent,);
    assert_eq!(st.get_total_balance(account_id), amount_left);
}

#[allow(dead_code)]
pub(crate) fn zip317_spend<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.account_id();
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
    assert_eq!(st.get_total_balance(account_id), total);
    assert_eq!(st.get_spendable_balance(account_id, 1), total);

    let input_selector = input_selector(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    // This first request will fail due to insufficient non-dust funds
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(&st.network()),
        NonNegativeAmount::const_from_u64(50000),
    )])
    .unwrap();

    assert_matches!(
        st.spend(
            &input_selector,
            account.usk(),
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
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(&st.network()),
        NonNegativeAmount::const_from_u64(41000),
    )])
    .unwrap();

    let txid = st
        .spend(
            &input_selector,
            account.usk(),
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
        st.get_total_balance(account_id),
        (total - NonNegativeAmount::const_from_u64(10000)).unwrap()
    );
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn shield_transparent<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    let uaddr = st
        .wallet()
        .get_current_address(account.account_id())
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
            account.usk(),
            &[*taddr],
            1
        ),
        Ok(_)
    );
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub(crate) fn birthday_in_anchor_shard<T: ShieldedPoolTester>() {
    // Set up the following situation:
    //
    //        |<------ 500 ------->|<--- 10 --->|<--- 10 --->|
    // last_shard_start   wallet_birthday  received_tx  anchor_height
    //
    // We set the Sapling and Orchard frontiers at the birthday block initial state to 1234
    // notes beyond the end of the first shard.
    let frontier_tree_size: u32 = (0x1 << 16) + 1234;
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_initial_chain_state(|rng, network| {
            let birthday_height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 1000;

            // Construct a fake chain state for the end of the block with the given
            // birthday_offset from the Nu5 birthday.
            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    frontier_tree_size.into(),
                    NonZeroU8::new(16).unwrap(),
                );
            // There will only be one prior root
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    frontier_tree_size.into(),
                    NonZeroU8::new(16).unwrap(),
                );
            // There will only be one prior root
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday()
        .build();

    // Generate 9 blocks that have no value for us, starting at the birthday height.
    let not_our_value = NonNegativeAmount::const_from_u64(10000);
    let not_our_key = T::random_fvk(st.rng_mut());
    let (initial_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..9 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }

    // Now, generate a block that belongs to our wallet
    let (received_tx_height, _, _) = st.generate_next_block(
        &T::test_account_fvk(&st),
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(500000),
    );

    // Generate some more blocks to get above our anchor height
    for _ in 0..15 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }

    // Scan a block range that includes our received note, but skips some blocks we need to
    // make it spendable.
    st.scan_cached_blocks(initial_height + 5, 20);

    // Verify that the received note is not considered spendable
    let account = st.test_account().unwrap();
    let account_id = account.account_id();
    let spendable = T::select_spendable_notes(
        &st,
        account_id,
        NonNegativeAmount::const_from_u64(300000),
        received_tx_height + 10,
        &[],
    )
    .unwrap();

    assert_eq!(spendable.len(), 0);

    // Scan the blocks we skipped
    st.scan_cached_blocks(initial_height, 5);

    // Verify that the received note is now considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account_id,
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
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Generate a block with funds belonging to our wallet.
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(500000),
    );
    st.scan_cached_blocks(account.birthday().height(), 1);

    // Create a gap of 10 blocks having no shielded outputs, then add a block that doesn't
    // belong to us so that we can get a checkpoint in the tree.
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let not_our_value = NonNegativeAmount::const_from_u64(10000);
    st.generate_block_at(
        account.birthday().height() + 10,
        BlockHash([0; 32]),
        &not_our_key,
        AddressType::DefaultExternal,
        not_our_value,
        st.latest_cached_block().unwrap().sapling_end_size,
        st.latest_cached_block().unwrap().orchard_end_size,
        false,
    );

    // Scan the block
    st.scan_cached_blocks(account.birthday().height() + 10, 1);

    // Fake that everything has been scanned
    st.wallet()
        .conn
        .execute_batch("UPDATE scan_queue SET priority = 10")
        .unwrap();

    // Verify that our note is considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account.account_id(),
        NonNegativeAmount::const_from_u64(300000),
        account.birthday().height() + 5,
        &[],
    )
    .unwrap();
    assert_eq!(spendable.len(), 1);

    // Attempt to spend the note with 5 confirmations
    let to = T::fvk_default_address(&not_our_key);
    assert_matches!(
        st.create_spend_to_address(
            account.usk(),
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

#[cfg(feature = "orchard")]
pub(crate) fn pool_crossing_required<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    let note_value = NonNegativeAmount::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = note_value;
    assert_eq!(st.get_total_balance(account.account_id()), initial_balance);
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        initial_balance
    );

    let transfer_amount = NonNegativeAmount::const_from_u64(200000);
    let p0_to_p1 = zip321::TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(&st.network()),
        transfer_amount,
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;
    let input_selector = GreedyInputSelector::new(
        standard::SingleOutputChangeStrategy::new(fee_rule, None, P1::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );
    let proposal0 = st
        .propose_transfer(
            account.account_id(),
            &input_selector,
            p0_to_p1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 4 logical actions, two per pool (due to padding).
    let expected_fee = NonNegativeAmount::const_from_u64(20000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.get(0).unwrap();
    // Since this is a cross-pool transfer, change will be sent to the preferred pool.
    assert_eq!(
        change_output.output_pool(),
        std::cmp::max(ShieldedProtocol::Sapling, ShieldedProtocol::Orchard)
    );
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.account_id()),
        (initial_balance - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn fully_funded_fully_private<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    let note_value = NonNegativeAmount::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = (note_value * 2).unwrap();
    assert_eq!(st.get_total_balance(account.account_id()), initial_balance);
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        initial_balance
    );

    let transfer_amount = NonNegativeAmount::const_from_u64(200000);
    let p0_to_p1 = zip321::TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(&st.network()),
        transfer_amount,
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;
    let input_selector = GreedyInputSelector::new(
        // We set the default change output pool to P0, because we want to verify later that
        // change is actually sent to P1 (as the transaction is fully fundable from P1).
        standard::SingleOutputChangeStrategy::new(fee_rule, None, P0::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );
    let proposal0 = st
        .propose_transfer(
            account.account_id(),
            &input_selector,
            p0_to_p1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 2 logical actions, since either pool can pay the full balance required
    // and note selection should choose the fully-private path.
    let expected_fee = NonNegativeAmount::const_from_u64(10000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.get(0).unwrap();
    // Since there are sufficient funds in either pool, change is kept in the same pool as
    // the source note (the target pool), and does not necessarily follow preference order.
    assert_eq!(change_output.output_pool(), P1::SHIELDED_PROTOCOL);
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.account_id()),
        (initial_balance - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn fully_funded_send_to_t<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);
    let (p1_to, _) = account.usk().default_transparent_address();

    let note_value = NonNegativeAmount::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = (note_value * 2).unwrap();
    assert_eq!(st.get_total_balance(account.account_id()), initial_balance);
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        initial_balance
    );

    let transfer_amount = NonNegativeAmount::const_from_u64(200000);
    let p0_to_p1 = zip321::TransactionRequest::new(vec![Payment::without_memo(
        Address::Transparent(p1_to).to_zcash_address(&st.network()),
        transfer_amount,
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;
    let input_selector = GreedyInputSelector::new(
        // We set the default change output pool to P0, because we want to verify later that
        // change is actually sent to P1 (as the transaction is fully fundable from P1).
        standard::SingleOutputChangeStrategy::new(fee_rule, None, P0::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );
    let proposal0 = st
        .propose_transfer(
            account.account_id(),
            &input_selector,
            p0_to_p1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 3 logical actions, one for the transparent output and two for the source pool.
    let expected_fee = NonNegativeAmount::const_from_u64(15000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.get(0).unwrap();
    // Since there are sufficient funds in either pool, change is kept in the same pool as
    // the source note (the target pool), and does not necessarily follow preference order.
    // The source note will always be sapling, as we spend Sapling funds preferentially.
    assert_eq!(change_output.output_pool(), ShieldedProtocol::Sapling);
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.account_id()),
        (initial_balance - transfer_amount - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        (initial_balance - transfer_amount - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn multi_pool_checkpoint<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();
    let acct_id = account.account_id();

    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);

    // Add some funds to the wallet; we add two notes to allow successive spends. Also,
    // we will generate a note in the P1 pool to ensure that we have some tree state.
    let note_value = NonNegativeAmount::const_from_u64(500000);
    let (start_height, _, _) =
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    let scanned = st.scan_cached_blocks(start_height, 3);

    let next_to_scan = scanned.scanned_range().end;

    let initial_balance = (note_value * 3).unwrap();
    assert_eq!(st.get_total_balance(acct_id), initial_balance);
    assert_eq!(st.get_spendable_balance(acct_id, 1), initial_balance);

    // Generate several empty blocks
    for _ in 0..10 {
        st.generate_empty_block();
    }

    // Scan into the middle of the empty range
    let scanned = st.scan_cached_blocks(next_to_scan, 5);
    let next_to_scan = scanned.scanned_range().end;

    // The initial balance should be unchanged.
    assert_eq!(st.get_total_balance(acct_id), initial_balance);
    assert_eq!(st.get_spendable_balance(acct_id, 1), initial_balance);

    // Set up the fee rule and input selector we'll use for all the transfers.
    let fee_rule = StandardFeeRule::Zip317;
    let input_selector = GreedyInputSelector::new(
        standard::SingleOutputChangeStrategy::new(fee_rule, None, P1::SHIELDED_PROTOCOL),
        DustOutputPolicy::default(),
    );

    // First, send funds just to P0
    let transfer_amount = NonNegativeAmount::const_from_u64(200000);
    let p0_transfer = zip321::TransactionRequest::new(vec![Payment::without_memo(
        P0::random_address(&mut st.rng).to_zcash_address(&st.network()),
        transfer_amount,
    )])
    .unwrap();
    let res = st
        .spend(
            &input_selector,
            account.usk(),
            p0_transfer,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
    st.generate_next_block_including(*res.first());

    let expected_fee = NonNegativeAmount::const_from_u64(10000);
    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    assert_eq!(
        st.get_total_balance(acct_id),
        ((note_value * 2).unwrap() + expected_change).unwrap()
    );
    assert_eq!(st.get_pending_change(acct_id, 1), expected_change);

    // In the next block, send funds to both P0 and P1
    let both_transfer = zip321::TransactionRequest::new(vec![
        Payment::without_memo(
            P0::random_address(&mut st.rng).to_zcash_address(&st.network()),
            transfer_amount,
        ),
        Payment::without_memo(
            P1::random_address(&mut st.rng).to_zcash_address(&st.network()),
            transfer_amount,
        ),
    ])
    .unwrap();
    let res = st
        .spend(
            &input_selector,
            account.usk(),
            both_transfer,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
    st.generate_next_block_including(*res.first());

    // Generate a few more empty blocks
    for _ in 0..5 {
        st.generate_empty_block();
    }

    // Generate another block with funds for us
    let (max_height, _, _) =
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);

    // Scan everything.
    st.scan_cached_blocks(
        next_to_scan,
        usize::try_from(u32::from(max_height) - u32::from(next_to_scan) + 1).unwrap(),
    );

    let expected_final = (initial_balance + note_value
        - (transfer_amount * 3).unwrap()
        - (expected_fee * 3).unwrap())
    .unwrap();
    assert_eq!(st.get_total_balance(acct_id), expected_final);

    use incrementalmerkletree::Position;
    let expected_checkpoints_p0: Vec<(BlockHeight, ShieldedProtocol, Option<Position>)> = [
        (99999, None),
        (100000, Some(0)),
        (100001, Some(1)),
        (100002, Some(1)),
        (100007, Some(1)), // synthetic checkpoint in empty span from scan start
        (100013, Some(3)),
        (100014, Some(5)),
        (100020, Some(6)),
    ]
    .into_iter()
    .map(|(h, pos)| {
        (
            BlockHeight::from(h),
            P0::SHIELDED_PROTOCOL,
            pos.map(Position::from),
        )
    })
    .collect();

    let expected_checkpoints_p1: Vec<(BlockHeight, ShieldedProtocol, Option<Position>)> = [
        (99999, None),
        (100000, None),
        (100001, None),
        (100002, Some(0)),
        (100007, Some(0)), // synthetic checkpoint in empty span from scan start
        (100013, Some(0)),
        (100014, Some(2)),
        (100020, Some(2)),
    ]
    .into_iter()
    .map(|(h, pos)| {
        (
            BlockHeight::from(h),
            P1::SHIELDED_PROTOCOL,
            pos.map(Position::from),
        )
    })
    .collect();

    let actual_checkpoints = st.get_checkpoint_history().unwrap();

    assert_eq!(
        actual_checkpoints
            .iter()
            .filter(|(_, p, _)| p == &P0::SHIELDED_PROTOCOL)
            .cloned()
            .collect::<Vec<_>>(),
        expected_checkpoints_p0
    );
    assert_eq!(
        actual_checkpoints
            .iter()
            .filter(|(_, p, _)| p == &P1::SHIELDED_PROTOCOL)
            .cloned()
            .collect::<Vec<_>>(),
        expected_checkpoints_p1
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn multi_pool_checkpoints_with_pruning<
    P0: ShieldedPoolTester,
    P1: ShieldedPoolTester,
>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::random_fvk(&mut st.rng);
    let p1_fvk = P1::random_fvk(&mut st.rng);

    let note_value = NonNegativeAmount::const_from_u64(10000);
    // Generate 100 P0 blocks, then 100 P1 blocks, then another 100 P0 blocks.
    for _ in 0..10 {
        for _ in 0..10 {
            st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
        }
        for _ in 0..10 {
            st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
        }
    }
    st.scan_cached_blocks(account.birthday().height(), 200);
    for _ in 0..100 {
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
        st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    }
    st.scan_cached_blocks(account.birthday().height() + 200, 200);
}

pub(crate) fn valid_chain_states<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let dfvk = T::test_account_fvk(&st);

    // Empty chain should return None
    assert_matches!(st.wallet().chain_height(), Ok(None));

    // Create a fake CompactBlock sending value to the address
    let (h1, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(5),
    );

    // Scan the cache
    st.scan_cached_blocks(h1, 1);

    // Create a second fake CompactBlock sending more value to the address
    let (h2, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(7),
    );

    // Scanning should detect no inconsistencies
    st.scan_cached_blocks(h2, 1);
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub(crate) fn invalid_chain_cache_disconnected<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let dfvk = T::test_account_fvk(&st);

    // Create some fake CompactBlocks
    let (h, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(5),
    );
    let (last_contiguous_height, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(7),
    );

    // Scanning the cache should find no inconsistencies
    st.scan_cached_blocks(h, 2);

    // Create more fake CompactBlocks that don't connect to the scanned ones
    let disconnect_height = last_contiguous_height + 1;
    st.generate_block_at(
        disconnect_height,
        BlockHash([1; 32]),
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(8),
        2,
        2,
        true,
    );
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        NonNegativeAmount::const_from_u64(3),
    );

    // Data+cache chain should be invalid at the data/cache boundary
    assert_matches!(
        st.try_scan_cached_blocks(
            disconnect_height,
            2
        ),
        Err(chain::error::Error::Scan(ScanError::PrevHashMismatch { at_height }))
            if at_height == disconnect_height
    );
}

pub(crate) fn data_db_truncation<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create fake CompactBlocks sending value to the address
    let value = NonNegativeAmount::const_from_u64(5);
    let value2 = NonNegativeAmount::const_from_u64(7);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

    // Scan the cache
    st.scan_cached_blocks(h, 2);

    // Spendable balance should reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        (value + value2).unwrap()
    );

    // "Rewind" to height of last scanned block (this is a no-op)
    st.wallet_mut()
        .transactionally(|wdb| truncate_to_height(wdb.conn.0, &wdb.params, h + 1))
        .unwrap();

    // Spendable balance should be unaltered
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        (value + value2).unwrap()
    );

    // Rewind so that one block is dropped
    st.wallet_mut()
        .transactionally(|wdb| truncate_to_height(wdb.conn.0, &wdb.params, h))
        .unwrap();

    // Spendable balance should only contain the first received note;
    // the rest should be pending.
    assert_eq!(st.get_spendable_balance(account.account_id(), 1), value);
    assert_eq!(
        st.get_pending_shielded_balance(account.account_id(), 1),
        value2
    );

    // Scan the cache again
    st.scan_cached_blocks(h, 2);

    // Account balance should again reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.account_id(), 1),
        (value + value2).unwrap()
    );
}

pub(crate) fn scan_cached_blocks_allows_blocks_out_of_order<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    let value = NonNegativeAmount::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);
    assert_eq!(st.get_total_balance(account.account_id()), value);

    // Create blocks to reach height + 2
    let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    let (h3, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the later block first
    st.scan_cached_blocks(h3, 1);

    // Now scan the block of height height + 1
    st.scan_cached_blocks(h2, 1);
    assert_eq!(
        st.get_total_balance(account.account_id()),
        NonNegativeAmount::const_from_u64(150_000)
    );

    // We can spend the received notes
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(&st.network()),
        NonNegativeAmount::const_from_u64(110_000),
    )])
    .unwrap();

    #[allow(deprecated)]
    let input_selector = GreedyInputSelector::new(
        standard::SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        DustOutputPolicy::default(),
    );
    assert_matches!(
        st.spend(
            &input_selector,
            account.usk(),
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        ),
        Ok(_)
    );
}

pub(crate) fn scan_cached_blocks_finds_received_notes<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create a fake CompactBlock sending value to the address
    let value = NonNegativeAmount::const_from_u64(5);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the cache
    let summary = st.scan_cached_blocks(h1, 1);
    assert_eq!(summary.scanned_range().start, h1);
    assert_eq!(summary.scanned_range().end, h1 + 1);
    assert_eq!(T::received_note_count(&summary), 1);

    // Account balance should reflect the received note
    assert_eq!(st.get_total_balance(account.account_id()), value);

    // Create a second fake CompactBlock sending more value to the address
    let value2 = NonNegativeAmount::const_from_u64(7);
    let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

    // Scan the cache again
    let summary = st.scan_cached_blocks(h2, 1);
    assert_eq!(summary.scanned_range().start, h2);
    assert_eq!(summary.scanned_range().end, h2 + 1);
    assert_eq!(T::received_note_count(&summary), 1);

    // Account balance should reflect both received notes
    assert_eq!(
        st.get_total_balance(account.account_id()),
        (value + value2).unwrap()
    );
}

// TODO: This test can probably be entirely removed, as the following test duplicates it entirely.
pub(crate) fn scan_cached_blocks_finds_change_notes<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create a fake CompactBlock sending value to the address
    let value = NonNegativeAmount::const_from_u64(5);
    let (received_height, _, nf) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the cache
    st.scan_cached_blocks(received_height, 1);

    // Account balance should reflect the received note
    assert_eq!(st.get_total_balance(account.account_id()), value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = NonNegativeAmount::const_from_u64(2);
    let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

    // Scan the cache again
    st.scan_cached_blocks(spent_height, 1);

    // Account balance should equal the change
    assert_eq!(
        st.get_total_balance(account.account_id()),
        (value - value2).unwrap()
    );
}

pub(crate) fn scan_cached_blocks_detects_spends_out_of_order<T: ShieldedPoolTester>() {
    let mut st = TestBuilder::new()
        .with_block_cache()
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create a fake CompactBlock sending value to the address
    let value = NonNegativeAmount::const_from_u64(5);
    let (received_height, _, nf) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = NonNegativeAmount::const_from_u64(2);
    let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

    // Scan the spending block first.
    st.scan_cached_blocks(spent_height, 1);

    // Account balance should equal the change
    assert_eq!(
        st.get_total_balance(account.account_id()),
        (value - value2).unwrap()
    );

    // Now scan the block in which we received the note that was spent.
    st.scan_cached_blocks(received_height, 1);

    // Account balance should be the same.
    assert_eq!(
        st.get_total_balance(account.account_id()),
        (value - value2).unwrap()
    );
}
