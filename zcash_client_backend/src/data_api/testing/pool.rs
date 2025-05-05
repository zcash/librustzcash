use std::{
    cmp::Eq,
    convert::Infallible,
    hash::Hash,
    num::{NonZeroU32, NonZeroU64, NonZeroU8, NonZeroUsize},
};

use assert_matches::assert_matches;
use incrementalmerkletree::{frontier::Frontier, Level, Position};
use rand::{Rng, RngCore};
use secrecy::Secret;
use shardtree::error::ShardTreeError;

use ::transparent::address::TransparentAddress;
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::{
    block::BlockHash,
    transaction::{
        fees::zip317::{FeeRule as Zip317FeeRule, MARGINAL_FEE, MINIMUM_FEE},
        Transaction,
    },
};
use zcash_protocol::{
    consensus::{self, BlockHeight, NetworkUpgrade, Parameters},
    local_consensus::LocalNetwork,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
    ShieldedProtocol,
};
use zip32::Scope;
use zip321::{Payment, TransactionRequest};

use crate::{
    data_api::{
        self,
        chain::{self, ChainState, CommitmentTreeRoot, ScanSummary},
        error::Error,
        testing::{
            single_output_change_strategy, AddressType, FakeCompactOutput, InitialChainState,
            TestBuilder,
        },
        wallet::{
            decrypt_and_store_transaction, input_selection::GreedyInputSelector, TransferErrT,
        },
        Account as _, AccountBirthday, BoundedU8, DecryptedTransaction, InputSource, NoteFilter,
        Ratio, WalletCommitmentTrees, WalletRead, WalletSummary, WalletTest, WalletWrite,
    },
    decrypt_transaction,
    fees::{
        self,
        standard::{self, SingleOutputChangeStrategy},
        DustOutputPolicy, SplitPolicy, StandardFeeRule,
    },
    scanning::ScanError,
    wallet::{Note, NoteId, OvkPolicy, ReceivedNote},
};

use super::{DataStoreFactory, Reset, TestCache, TestFvk, TestState};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        data_api::TransactionDataRequest,
        fees::ChangeValue,
        proposal::{Proposal, ProposalError, StepOutput, StepOutputIndex},
        wallet::{TransparentAddressMetadata, WalletTransparentOutput},
    },
    ::transparent::{
        bundle::{OutPoint, TxOut},
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    },
    nonempty::NonEmpty,
    rand_core::OsRng,
    std::{collections::HashSet, str::FromStr},
    zcash_primitives::transaction::{
        builder::{BuildConfig, Builder},
        fees::zip317,
    },
    zcash_proofs::prover::LocalTxProver,
    zcash_protocol::value::ZatBalance,
};

#[cfg(feature = "orchard")]
use zcash_protocol::PoolType;

#[cfg(feature = "pczt")]
use pczt::roles::{prover::Prover, signer::Signer};

/// Trait that exposes the pool-specific types and operations necessary to run the
/// single-shielded-pool tests on a given pool.
///
/// You should not need to implement this yourself; instead use [`SaplingPoolTester`] or
/// [`OrchardPoolTester`] as appropriate.
///
/// [`SaplingPoolTester`]: super::sapling::SaplingPoolTester
#[cfg_attr(
    feature = "orchard",
    doc = "[`OrchardPoolTester`]: super::orchard::OrchardPoolTester"
)]
#[cfg_attr(
    not(feature = "orchard"),
    doc = "[`OrchardPoolTester`]: https://github.com/zcash/librustzcash/blob/0777cbc2def6ba6b99f96333eaf96c314c1f3a37/zcash_client_backend/src/data_api/testing/orchard.rs#L33"
)]
pub trait ShieldedPoolTester {
    const SHIELDED_PROTOCOL: ShieldedProtocol;

    type Sk;
    type Fvk: TestFvk;
    type MerkleTreeHash;
    type Note;

    fn test_account_fvk<Cache, DbT: WalletTest, P: consensus::Parameters>(
        st: &TestState<Cache, DbT, P>,
    ) -> Self::Fvk;
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

    fn put_subtree_roots<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        start_index: u64,
        roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    fn next_subtree_index<A: Hash + Eq>(s: &WalletSummary<A>) -> u64;

    #[allow(clippy::type_complexity)]
    fn select_spendable_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_value: Zatoshis,
        anchor_height: BlockHeight,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error>;

    fn decrypted_pool_outputs_count<A>(d_tx: &DecryptedTransaction<'_, A>) -> usize;

    fn with_decrypted_pool_memos<A>(d_tx: &DecryptedTransaction<'_, A>, f: impl FnMut(&MemoBytes));

    fn try_output_recovery<P: consensus::Parameters>(
        params: &P,
        height: BlockHeight,
        tx: &Transaction,
        fvk: &Self::Fvk,
    ) -> Option<(Note, Address, MemoBytes)>;

    fn received_note_count(summary: &ScanSummary) -> usize;

    #[cfg(feature = "pczt")]
    fn add_proof_generation_keys(
        pczt: pczt::Pczt,
        usk: &UnifiedSpendingKey,
    ) -> Result<pczt::Pczt, pczt::roles::updater::SaplingError>;

    #[cfg(feature = "pczt")]
    fn apply_signatures_to_pczt(
        signer: &mut Signer,
        usk: &UnifiedSpendingKey,
    ) -> Result<(), pczt::roles::signer::Error>;
}

/// Tests sending funds within the given shielded pool in a single transaction.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend part of that balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn send_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account.id()), value);
    assert_eq!(st.get_spendable_balance(account.id(), 1), value);

    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10000),
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;

    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        fee_rule,
        Some(change_memo.clone().into()),
        T::SHIELDED_PROTOCOL,
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

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
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
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
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

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(40000));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

pub fn send_with_multiple_change_outputs<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(650_0000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account.id()), value);
    assert_eq!(st.get_spendable_balance(account.id(), 1), value);

    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(100_0000),
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = fees::zip317::MultiOutputChangeStrategy::new(
        Zip317FeeRule::standard(),
        Some(change_memo.clone().into()),
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(2).unwrap(),
            Zatoshis::const_from_u64(100_0000),
        ),
    );

    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request.clone(),
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let step = &proposal.steps().head;
    assert_eq!(step.balance().proposed_change().len(), 2);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
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
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 3);

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
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 3);

    // The sent memo should be the empty memo for the sent output, and each
    // change output's memo should be as specified.
    let mut change_memo_count = 0;
    let mut found_sent_empty_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &change_memo => {
                change_memo_count += 1;
            }
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {:?}", other),
            None => panic!("Memo should not be stored as NULL"),
        }
    }
    assert_eq!(change_memo_count, 2);
    assert!(found_sent_empty_memo);

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(650_0000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(650_0000));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(548_5000));
        assert_eq!(tx_1.fee_paid(), Some(Zatoshis::const_from_u64(15000)));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );

    let (h, _) = st.generate_next_block_including(sent_tx_id);
    st.scan_cached_blocks(h, 1);

    // Now, create another proposal with more outputs requested. We have two change notes;
    // we'll spend one of them, and then we'll generate 7 splits.
    let change_strategy = fees::zip317::MultiOutputChangeStrategy::new(
        Zip317FeeRule::standard(),
        Some(change_memo.into()),
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(8).unwrap(),
            Zatoshis::const_from_u64(10_0000),
        ),
    );

    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let step = &proposal.steps().head;
    assert_eq!(step.balance().proposed_change().len(), 7);
}

#[cfg(feature = "transparent-inputs")]
pub fn send_multi_step_proposed_transfer<T: ShieldedPoolTester, DSF>(
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
    let dfvk = T::test_account_fvk(&st);

    let add_funds = |st: &mut TestState<_, DSF::DataStore, _>, value| {
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
        h
    };

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(50000);

    let run_test = |st: &mut TestState<_, DSF::DataStore, _>, expected_index, prior_balance| {
        // Add funds to the wallet.
        add_funds(st, value);
        let initial_balance: Option<Zatoshis> = prior_balance + value;
        assert_eq!(
            st.get_spendable_balance(account_id, 1),
            initial_balance.unwrap()
        );

        let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
        let expected_step1_fee = zip317::MINIMUM_FEE;
        let expected_ephemeral = (transfer_amount + expected_step1_fee).unwrap();
        let expected_step0_change =
            (initial_balance - expected_ephemeral - expected_step0_fee).expect("sufficient funds");
        assert!(expected_step0_change.is_positive());

        let total_sent = (expected_step0_fee + expected_step1_fee + transfer_amount).unwrap();

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

        let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
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

        assert!(expected_step0_change < expected_ephemeral);
        assert_eq!(confirmed_sent.len(), 2);
        assert_eq!(confirmed_sent[0].len(), 2);
        assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
        let OutputOfSentTx {
            value: ephemeral_v,
            external_recipient: to_addr,
            ephemeral_address,
        } = confirmed_sent[0][1].clone();
        assert_eq!(ephemeral_v, expected_ephemeral);
        assert!(to_addr.is_some());
        assert_eq!(
            ephemeral_address,
            to_addr.map(|addr| (addr, expected_index)),
        );

        assert_eq!(confirmed_sent[1].len(), 1);
        assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &transfer_amount && sent_to_addr == &Some(tex_addr));

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

        let ending_balance = st.get_spendable_balance(account_id, 1);
        assert_eq!(initial_balance - total_sent, ending_balance.into());

        (ephemeral_address.unwrap().0, txids, ending_balance)
    };

    // Each transfer should use a different ephemeral address.
    let (ephemeral0, _, bal_0) = run_test(&mut st, 0, Zatoshis::ZERO);
    let (ephemeral1, _, _) = run_test(&mut st, 1, bal_0);
    assert_ne!(ephemeral0, ephemeral1);

    let height = add_funds(&mut st, value);

    assert_matches!(
        ephemeral0,
        Address::Transparent(TransparentAddress::PublicKeyHash(_))
    );

    // Attempting to pay to an ephemeral address should cause an error.
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            NonZeroU32::new(1).unwrap(),
            &ephemeral0,
            transfer_amount,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(
        &create_proposed_result,
        Err(Error::PaysEphemeralTransparentAddress(address_str)) if address_str == &ephemeral0.encode(st.network()));

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
    let pubkey = transparent_signing_set.add_key(sk);
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

/// Tests spending all funds within the given shielded pool in a single transaction.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend all of that balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn spend_all_funds_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(dsf)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(60000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account.id()), value);
    assert_eq!(st.get_spendable_balance(account.id(), 1), value);

    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        h
    );

    let spend_amount = Zatoshis::const_from_u64(50000);
    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        spend_amount,
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;

    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        fee_rule,
        Some(change_memo.clone().into()),
        T::SHIELDED_PROTOCOL,
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

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
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
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
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

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_1.total_received(), Zatoshis::ZERO);
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}
/// Test attempts to sweep a wallet into a TEX address + tests ta that ephemeral
/// addresses are generated properly according to a given gap limit
///
/// 1. funds wallet with 100000 Zatoshis
/// 2. sets that spend amount will be 75000 Zatoshi
/// 3. proposes a transaction to a TEX address spending 75000 Zatoshi
/// 4. attempts to perform the proposal
/// 5. proposes the transaction
/// 6. "mines" the transaction.
/// 7. funds the wallet with 100000 Zatoshis
/// 8. goes through steps 3 to 6
/// 9. checks that the gap limit hodls and that ephemeral addresses are not reused.
///
/// desired effects:
/// - all funds are spent
/// - Fees are the least possible: in this case 15000 for tr0 and 10000 Zats for tr1
/// - ephemeral addresses are generated for each transaction to a TEX recipient
#[cfg(feature = "transparent-inputs")]
pub fn spend_all_funds_multi_step_proposed_transfer<T: ShieldedPoolTester, DSF>(
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
    let dfvk = T::test_account_fvk(&st);

    let add_funds = |st: &mut TestState<_, DSF::DataStore, _>, value| {
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
        h
    };

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(75000);

    let run_test = |st: &mut TestState<_, DSF::DataStore, _>, expected_index, prior_balance| {
        // Add funds to the wallet.
        add_funds(st, value);
        let initial_balance: Option<Zatoshis> = prior_balance + value;
        assert_eq!(
            st.get_spendable_balance(account_id, 1),
            initial_balance.unwrap()
        );

        let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
        let expected_step1_fee = zip317::MINIMUM_FEE;
        let expected_ephemeral = (transfer_amount + expected_step1_fee).unwrap();
        let expected_step0_change =
            (initial_balance - expected_ephemeral - expected_step0_fee).expect("sufficient funds");
        assert!(expected_step0_change.is_zero());

        let total_sent = (expected_step0_fee + expected_step1_fee + transfer_amount).unwrap();

        // Generate a ZIP 320 proposal, sending to the wallet's default transparent address
        // expressed as a TEX address.
        let tex_addr = match default_addr {
            TransparentAddress::PublicKeyHash(data) => Address::Tex(data),
            _ => unreachable!(),
        };
        //let change_memo = Some(Memo::from_str("change").expect("valid memo").encode());
        let change_memo: Option<MemoBytes> = None;
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

        let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
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

        assert!(expected_step0_change < expected_ephemeral);
        assert_eq!(confirmed_sent.len(), 2);
        assert_eq!(confirmed_sent[0].len(), 2);
        assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
        let OutputOfSentTx {
            value: ephemeral_v,
            external_recipient: to_addr,
            ephemeral_address,
        } = confirmed_sent[0][1].clone();
        assert_eq!(ephemeral_v, expected_ephemeral);
        assert!(to_addr.is_some());
        assert_eq!(
            ephemeral_address,
            to_addr.map(|addr| (addr, expected_index)),
        );

        assert_eq!(confirmed_sent[1].len(), 1);
        assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &transfer_amount && sent_to_addr == &Some(tex_addr));

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
            -ZatBalance::from(expected_ephemeral),
        );

        let ending_balance = st.get_spendable_balance(account_id, 1);
        assert_eq!(initial_balance - total_sent, ending_balance.into());

        (ephemeral_address.unwrap().0, txids, ending_balance)
    };

    // Each transfer should use a different ephemeral address.
    let (ephemeral0, _, bal_0) = run_test(&mut st, 0, Zatoshis::ZERO);
    let (ephemeral1, _, _) = run_test(&mut st, 1, bal_0);
    assert_ne!(ephemeral0, ephemeral1);

    let height = add_funds(&mut st, value);

    assert_matches!(
        ephemeral0,
        Address::Transparent(TransparentAddress::PublicKeyHash(_))
    );

    // Attempting to pay to an ephemeral address should cause an error.
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            NonZeroU32::new(1).unwrap(),
            &ephemeral0,
            transfer_amount,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(
        &create_proposed_result,
        Err(Error::PaysEphemeralTransparentAddress(address_str)) if address_str == &ephemeral0.encode(st.network()));

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
    let pubkey = transparent_signing_set.add_key(sk);
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

#[cfg(feature = "transparent-inputs")]
pub fn proposal_fails_if_not_all_ephemeral_outputs_consumed<T: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    let add_funds = |st: &mut TestState<_, DSF::DataStore, _>, value| {
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
    };

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(50000);

    // Add funds to the wallet.
    add_funds(&mut st, value);

    // Generate a ZIP 320 proposal, sending to the wallet's default transparent address
    // expressed as a TEX address.
    let tex_addr = match account.usk().default_transparent_address().0 {
        TransparentAddress::PublicKeyHash(data) => Address::Tex(data),
        _ => unreachable!(),
    };

    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            NonZeroU32::new(1).unwrap(),
            &tex_addr,
            transfer_amount,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // This is somewhat redundant with `send_multi_step_proposed_transfer`,
    // but tests the case with no change memo and ensures we haven't messed
    // up the test setup.
    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(create_proposed_result, Ok(_));

    // Frobnicate the proposal to make it invalid because it does not consume
    // the ephemeral output, by truncating it to the first step.
    let frobbed_proposal = Proposal::multi_step(
        *proposal.fee_rule(),
        proposal.min_target_height(),
        NonEmpty::singleton(proposal.steps().first().clone()),
    )
    .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
        account.usk(),
        OvkPolicy::Sender,
        &frobbed_proposal,
    );
    assert_matches!(
        create_proposed_result,
        Err(Error::Proposal(ProposalError::EphemeralOutputLeftUnspent(so)))
        if so == StepOutput::new(0, StepOutputIndex::Change(1))
    );
}

pub fn create_to_address_fails_on_incorrect_usk<T: ShieldedPoolTester, DSF: DataStoreFactory>(
    ds_factory: DSF,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Create a USK that doesn't exist in the wallet
    let acct1 = zip32::AccountId::try_from(1).unwrap();
    let usk1 = UnifiedSpendingKey::from_seed(st.network(), &[1u8; 32], acct1).unwrap();

    let input_selector = GreedyInputSelector::<DSF::DataStore>::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    let req = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(1),
    )])
    .unwrap();

    // Attempting to spend with a USK that is not in the wallet results in an error
    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            &usk1,
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        ),
        Err(data_api::error::Error::KeyNotRecognized)
    );
}

pub fn proposal_fails_with_no_blocks<T: ShieldedPoolTester, DSF>(ds_factory: DSF)
where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account_id = st.test_account().unwrap().id();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // We cannot do anything if we aren't synchronised
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            NonZeroU32::new(1).unwrap(),
            &to,
            Zatoshis::const_from_u64(1),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::ScanRequired)
    );
}

pub fn spend_fails_on_unverified_notes<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(st.get_pending_shielded_balance(account_id, 10), value);
    assert_eq!(st.get_spendable_balance(account_id, 10), Zatoshis::ZERO);

    // If none of the wallet's accounts have a recover-until height, then there
    // is no recovery phase for the wallet, and therefore the denominator in the
    // resulting ratio (the number of notes in the recovery range) is zero.
    let no_recovery = Some(Ratio::new(0, 0));

    // Wallet is fully scanned
    let summary = st.get_wallet_summary(1);
    assert_eq!(
        summary.as_ref().and_then(|s| s.progress().recovery()),
        no_recovery,
    );
    assert_eq!(summary.map(|s| s.progress().scan()), Some(Ratio::new(1, 1)));

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
        summary.as_ref().and_then(|s| s.progress().recovery()),
        no_recovery
    );
    assert_eq!(summary.map(|s| s.progress().scan()), Some(Ratio::new(2, 2)));

    // Spend fails because there are insufficient verified notes
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            NonZeroU32::new(2).unwrap(),
            &to,
            Zatoshis::const_from_u64(70000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::const_from_u64(50000)
            && required == Zatoshis::const_from_u64(80000)
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 2 to 9 until just before the second
    // note is verified
    for _ in 2..10 {
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    }
    st.scan_cached_blocks(h2 + 1, 8);

    // Total balance is value * number of blocks scanned (10).
    assert_eq!(st.get_total_balance(account_id), (value * 10u64).unwrap());

    // Spend still fails
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            NonZeroU32::new(10).unwrap(),
            &to,
            Zatoshis::const_from_u64(70000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::const_from_u64(50000)
            && required == Zatoshis::const_from_u64(80000)
    );

    // Mine block 11 so that the second note becomes verified
    let (h11, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h11, 1);

    // Total balance is value * number of blocks scanned (11).
    assert_eq!(st.get_total_balance(account_id), (value * 11u64).unwrap());
    // Spendable balance at 10 confirmations is value * 2.
    assert_eq!(
        st.get_spendable_balance(account_id, 10),
        (value * 2u64).unwrap()
    );
    assert_eq!(
        st.get_pending_shielded_balance(account_id, 10),
        (value * 9u64).unwrap()
    );

    // Should now be able to generate a proposal
    let amount_sent = Zatoshis::from_u64(70000).unwrap();
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
        .create_proposed_transactions::<Infallible, _, Infallible>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account_id),
        ((value * 11u64).unwrap() - (amount_sent + Zatoshis::from_u64(10000).unwrap()).unwrap())
            .unwrap()
    );
}

pub fn spend_fails_on_locked_notes<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    let fee_rule = StandardFeeRule::Zip317;

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
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
            Zatoshis::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible>(account.usk(), OvkPolicy::Sender, &proposal,),
        Ok(txids) if txids.len() == 1
    );

    // A second proposal fails because there are no usable notes
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            NonZeroU32::new(1).unwrap(),
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
            NonZeroU32::new(1).unwrap(),
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
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // Second spend should now succeed
    let amount_sent2 = Zatoshis::const_from_u64(2000);
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
        .create_proposed_transactions::<Infallible, _, Infallible>(
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

pub fn ovk_policy_prevents_recovery_from_chain<T: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    let extsk2 = T::sk(&[0xf5; 32]);
    let addr2 = T::sk_default_address(&extsk2);

    let fee_rule = StandardFeeRule::Zip317;

    #[allow(clippy::type_complexity)]
    let send_and_recover_with_policy = |st: &mut TestState<_, DSF::DataStore, _>,
                                        ovk_policy|
     -> Result<
        Option<(Note, Address, MemoBytes)>,
        TransferErrT<
            DSF::DataStore,
            GreedyInputSelector<DSF::DataStore>,
            SingleOutputChangeStrategy<DSF::DataStore>,
        >,
    > {
        let min_confirmations = NonZeroU32::new(1).unwrap();
        let proposal = st.propose_standard_transfer(
            account_id,
            fee_rule,
            min_confirmations,
            &addr2,
            Zatoshis::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )?;

        // Executing the proposal should succeed
        let txid = st.create_proposed_transactions(account.usk(), ovk_policy, &proposal)?[0];

        // Fetch the transaction from the database
        let tx = st
            .wallet()
            .get_transaction(txid)
            .map_err(Error::DataSource)?
            .unwrap();

        Ok(T::try_output_recovery(st.network(), h1, &tx, &dfvk))
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

pub fn spend_succeeds_to_t_addr_zero_change<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(70000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    let fee_rule = StandardFeeRule::Zip317;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            min_confirmations,
            &to,
            Zatoshis::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub fn change_note_spends_succeed<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note owned by the internal spending key
    let value = Zatoshis::const_from_u64(70000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(st.get_spendable_balance(account_id, 1), value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(st.get_pending_shielded_balance(account_id, 10), value);
    assert_eq!(st.get_spendable_balance(account_id, 10), Zatoshis::ZERO);

    let change_note_scope = st
        .wallet()
        .get_notes(T::SHIELDED_PROTOCOL)
        .unwrap()
        .iter()
        .find_map(|note| (note.note().value() == value).then_some(note.spending_key_scope()));
    assert_matches!(change_note_scope, Some(Scope::Internal));

    let fee_rule = StandardFeeRule::Zip317;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let min_confirmations = NonZeroU32::new(1).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            min_confirmations,
            &to,
            Zatoshis::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub fn external_address_change_spends_detected_in_restore_from_seed<T: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::DataStore: Reset,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .build();

    // Add two accounts to the wallet.
    let seed = Secret::new([0u8; 32].to_vec());
    let birthday = AccountBirthday::from_sapling_activation(st.network(), BlockHash([0; 32]));
    let (account1, usk) = st
        .wallet_mut()
        .create_account("account1", &seed, &birthday, None)
        .unwrap();
    let dfvk = T::sk_to_fvk(T::usk_to_sk(&usk));

    let (account2, usk2) = st
        .wallet_mut()
        .create_account("account2", &seed, &birthday, None)
        .unwrap();
    let dfvk2 = T::sk_to_fvk(T::usk_to_sk(&usk2));

    // Add funds to the wallet in a single note
    let value = Zatoshis::from_u64(100000).unwrap();
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account1), value);
    assert_eq!(st.get_spendable_balance(account1, 1), value);
    assert_eq!(st.get_total_balance(account2), Zatoshis::ZERO);

    let amount_sent = Zatoshis::from_u64(20000).unwrap();
    let amount_legacy_change = Zatoshis::from_u64(30000).unwrap();
    let addr = T::fvk_default_address(&dfvk);
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![
        // payment to an external recipient
        Payment::without_memo(addr2.to_zcash_address(st.network()), amount_sent),
        // payment back to the originating wallet, simulating legacy change
        Payment::without_memo(addr.to_zcash_address(st.network()), amount_legacy_change),
    ])
    .unwrap();

    let change_strategy = fees::standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let txid = st
        .spend(
            &input_selector,
            &change_strategy,
            &usk,
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap()[0];

    let amount_left = (value - (amount_sent + MINIMUM_FEE + MARGINAL_FEE).unwrap()).unwrap();
    let pending_change = (amount_left - amount_legacy_change).unwrap();

    // The "legacy change" is not counted by get_pending_change().
    assert_eq!(st.get_pending_change(account1, 1), pending_change);
    // We spent the only note so we only have pending change.
    assert_eq!(st.get_total_balance(account1), pending_change);

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), amount_sent,);
    assert_eq!(st.get_total_balance(account1), amount_left);

    st.reset();

    // Account creation and DFVK derivation should be deterministic.
    let (account1, restored_usk) = st
        .wallet_mut()
        .create_account("account1_restored", &seed, &birthday, None)
        .unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk)),
        &dfvk,
    ));

    let (account2, restored_usk2) = st
        .wallet_mut()
        .create_account("account2_restored", &seed, &birthday, None)
        .unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk2)),
        &dfvk2,
    ));

    st.scan_cached_blocks(st.sapling_activation_height(), 2);

    assert_eq!(st.get_total_balance(account2), amount_sent);
    assert_eq!(st.get_total_balance(account1), amount_left);
}

#[allow(dead_code)]
pub fn zip317_spend<T: ShieldedPoolTester, DSF: DataStoreFactory>(
    ds_factory: DSF,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet
    let (h1, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::Internal,
        Zatoshis::const_from_u64(50000),
    );

    // Add 10 dust notes to the wallet
    for _ in 1..=10 {
        st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(1000),
        );
    }

    st.scan_cached_blocks(h1, 11);

    // Spendable balance matches total balance
    let total = Zatoshis::const_from_u64(60000);
    assert_eq!(st.get_total_balance(account_id), total);
    assert_eq!(st.get_spendable_balance(account_id, 1), total);

    let input_selector = GreedyInputSelector::<DSF::DataStore>::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    // This first request will fail due to insufficient non-dust funds
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(st.network()),
        Zatoshis::const_from_u64(50000),
    )])
    .unwrap();

    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        ),
        Err(Error::InsufficientFunds { available, required })
            if available == Zatoshis::const_from_u64(51000)
            && required == Zatoshis::const_from_u64(60000)
    );

    // This request will succeed, spending a single dust input to pay the 10000
    // ZAT fee in addition to the 41000 ZAT output to the recipient
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(st.network()),
        Zatoshis::const_from_u64(41000),
    )])
    .unwrap();

    let txid = st
        .spend(
            &input_selector,
            &change_strategy,
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
        (total - Zatoshis::const_from_u64(10000)).unwrap()
    );
}

#[cfg(feature = "transparent-inputs")]
pub fn shield_transparent<T: ShieldedPoolTester, DSF>(ds_factory: DSF, cache: impl TestCache)
where
    DSF: DataStoreFactory,
    <<DSF as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use zcash_keys::keys::UnifiedAddressRequest;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    let uaddr = st
        .wallet()
        .get_last_generated_address_matching(account.id(), UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

    // Ensure that the wallet has at least one block
    let (h, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::Internal,
        Zatoshis::const_from_u64(50000),
    );
    st.scan_cached_blocks(h, 1);

    let utxo = WalletTransparentOutput::from_parts(
        OutPoint::fake(),
        TxOut {
            value: Zatoshis::const_from_u64(100000),
            script_pubkey: taddr.script(),
        },
        Some(h),
    )
    .unwrap();

    let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
    assert_matches!(res0, Ok(_));

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    let txids = st
        .shield_transparent_funds(
            &input_selector,
            &change_strategy,
            Zatoshis::from_u64(10000).unwrap(),
            account.usk(),
            &[*taddr],
            account.id(),
            1,
        )
        .unwrap();
    assert_eq!(txids.len(), 1);

    let tx = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
    assert_eq!(tx.spent_note_count(), 1);
    assert!(tx.has_change());
    assert_eq!(tx.received_note_count(), 0);
    assert_eq!(tx.sent_note_count(), 0);
    assert!(tx.is_shielding());

    // Generate and scan the block including the transaction
    let (h, _) = st.generate_next_block_including(*txids.first());
    st.scan_cached_blocks(h, 1);

    // Ensure that the transaction metadata is still correct after the update produced by scanning.
    let tx = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
    assert_eq!(tx.spent_note_count(), 1);
    assert!(tx.has_change());
    assert_eq!(tx.received_note_count(), 0);
    assert_eq!(tx.sent_note_count(), 0);
    assert!(tx.is_shielding());
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub fn birthday_in_anchor_shard<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // Set up the following situation:
    //
    //        |<------ 500 ------->|<--- 10 --->|<--- 10 --->|
    // last_shard_start   wallet_birthday  received_tx  anchor_height
    //
    // We set the Sapling and Orchard frontiers at the birthday block initial state to 1234
    // notes beyond the end of the first shard.
    let frontier_tree_size: u32 = (0x1 << 16) + 1234;
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
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
    let not_our_value = Zatoshis::const_from_u64(10000);
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
        Zatoshis::const_from_u64(500000),
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
    let account_id = account.id();
    let spendable = T::select_spendable_notes(
        &st,
        account_id,
        Zatoshis::const_from_u64(300000),
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
        Zatoshis::const_from_u64(300000),
        received_tx_height + 10,
        &[],
    )
    .unwrap();

    assert_eq!(spendable.len(), 1);
}

pub fn checkpoint_gaps<T: ShieldedPoolTester, DSF: DataStoreFactory>(
    ds_factory: DSF,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Generate a block with funds belonging to our wallet.
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(500000),
    );
    st.scan_cached_blocks(account.birthday().height(), 1);

    // Create a gap of 10 blocks having no shielded outputs, then add a block that doesn't
    // belong to us so that we can get a checkpoint in the tree.
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let not_our_value = Zatoshis::const_from_u64(10000);
    st.generate_block_at(
        account.birthday().height() + 10,
        BlockHash([0; 32]),
        &[FakeCompactOutput::new(
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
        )],
        st.latest_cached_block().unwrap().sapling_end_size(),
        st.latest_cached_block().unwrap().orchard_end_size(),
        false,
    );

    // Scan the block
    st.scan_cached_blocks(account.birthday().height() + 10, 1);

    // Verify that our note is considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account.id(),
        Zatoshis::const_from_u64(300000),
        account.birthday().height() + 5,
        &[],
    )
    .unwrap();
    assert_eq!(spendable.len(), 1);

    let input_selector = GreedyInputSelector::<DSF::DataStore>::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    let to = T::fvk_default_address(&not_our_key);
    let req = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10000),
    )])
    .unwrap();

    // Attempt to spend the note with 5 confirmations
    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(5).unwrap(),
        ),
        Ok(_)
    );
}

#[cfg(feature = "orchard")]
pub fn pool_crossing_required<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = note_value;
    assert_eq!(st.get_total_balance(account.id()), initial_balance);
    assert_eq!(st.get_spendable_balance(account.id(), 1), initial_balance);

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P1::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 4 logical actions, two per pool (due to padding).
    let expected_fee = Zatoshis::const_from_u64(20000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.first().unwrap();
    // Since this is a cross-pool transfer, change will be sent to the preferred pool.
    assert_eq!(
        change_output.output_pool(),
        PoolType::Shielded(std::cmp::max(
            ShieldedProtocol::Sapling,
            ShieldedProtocol::Orchard
        ))
    );
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.id()),
        (initial_balance - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.id(), 1),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub fn fully_funded_fully_private<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = (note_value * 2u64).unwrap();
    assert_eq!(st.get_total_balance(account.id()), initial_balance);
    assert_eq!(st.get_spendable_balance(account.id(), 1), initial_balance);

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    // We set the default change output pool to P0, because we want to verify later that
    // change is actually sent to P1 (as the transaction is fully fundable from P1).
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P0::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 2 logical actions, since either pool can pay the full balance required
    // and note selection should choose the fully-private path.
    let expected_fee = Zatoshis::const_from_u64(10000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.first().unwrap();
    // Since there are sufficient funds in either pool, change is kept in the same pool as
    // the source note (the target pool), and does not necessarily follow preference order.
    assert_eq!(
        change_output.output_pool(),
        PoolType::Shielded(P1::SHIELDED_PROTOCOL)
    );
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.id()),
        (initial_balance - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.id(), 1),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
pub fn fully_funded_send_to_t<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);
    let (p1_to, _) = account.usk().default_transparent_address();

    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = (note_value * 2u64).unwrap();
    assert_eq!(st.get_total_balance(account.id()), initial_balance);
    assert_eq!(st.get_spendable_balance(account.id(), 1), initial_balance);

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        Address::Transparent(p1_to).to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    // We set the default change output pool to P0, because we want to verify later that
    // change is actually sent to P1 (as the transaction is fully fundable from P1).
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P0::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 3 logical actions, one for the transparent output and two for the source pool.
    let expected_fee = Zatoshis::const_from_u64(15000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.first().unwrap();
    // Since there are sufficient funds in either pool, change is kept in the same pool as
    // the source note (the target pool), and does not necessarily follow preference order.
    // The source note will always be sapling, as we spend Sapling funds preferentially.
    assert_eq!(change_output.output_pool(), PoolType::SAPLING);
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.id()),
        (initial_balance - transfer_amount - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.id(), 1),
        (initial_balance - transfer_amount - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub fn multi_pool_checkpoint<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();
    let acct_id = account.id();

    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);

    // Add some funds to the wallet; we add two notes to allow successive spends. Also,
    // we will generate a note in the P1 pool to ensure that we have some tree state.
    let note_value = Zatoshis::const_from_u64(500000);
    let (start_height, _, _) =
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    let scanned = st.scan_cached_blocks(start_height, 3);

    let next_to_scan = scanned.scanned_range().end;

    let initial_balance = (note_value * 3u64).unwrap();
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
    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P1::SHIELDED_PROTOCOL);

    // First, send funds just to P0
    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_transfer = TransactionRequest::new(vec![Payment::without_memo(
        P0::random_address(st.rng_mut()).to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();
    let res = st
        .spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            p0_transfer,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
    st.generate_next_block_including(*res.first());

    let expected_fee = Zatoshis::const_from_u64(10000);
    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    assert_eq!(
        st.get_total_balance(acct_id),
        ((note_value * 2u64).unwrap() + expected_change).unwrap()
    );
    assert_eq!(st.get_pending_change(acct_id, 1), expected_change);

    // In the next block, send funds to both P0 and P1
    let both_transfer = TransactionRequest::new(vec![
        Payment::without_memo(
            P0::random_address(st.rng_mut()).to_zcash_address(st.network()),
            transfer_amount,
        ),
        Payment::without_memo(
            P1::random_address(st.rng_mut()).to_zcash_address(st.network()),
            transfer_amount,
        ),
    ])
    .unwrap();
    let res = st
        .spend(
            &input_selector,
            &change_strategy,
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
        - (transfer_amount * 3u64).unwrap()
        - (expected_fee * 3u64).unwrap())
    .unwrap();
    assert_eq!(st.get_total_balance(acct_id), expected_final);

    let expected_checkpoints_p0: Vec<(BlockHeight, Option<Position>)> = [
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
    .map(|(h, pos)| (BlockHeight::from(h), pos.map(Position::from)))
    .collect();

    let expected_checkpoints_p1: Vec<(BlockHeight, Option<Position>)> = [
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
    .map(|(h, pos)| (BlockHeight::from(h), pos.map(Position::from)))
    .collect();

    let p0_checkpoints = st
        .wallet()
        .get_checkpoint_history(&P0::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(p0_checkpoints.to_vec(), expected_checkpoints_p0);

    let p1_checkpoints = st
        .wallet()
        .get_checkpoint_history(&P1::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(p1_checkpoints.to_vec(), expected_checkpoints_p1);
}

#[cfg(feature = "orchard")]
pub fn multi_pool_checkpoints_with_pruning<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32])) // TODO: Allow for Orchard
        // activation after Sapling
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::random_fvk(st.rng_mut());
    let p1_fvk = P1::random_fvk(st.rng_mut());

    let note_value = Zatoshis::const_from_u64(10000);
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

pub fn valid_chain_states<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let dfvk = T::test_account_fvk(&st);

    // Empty chain should return None
    assert_matches!(st.wallet().chain_height(), Ok(None));

    // Create a fake CompactBlock sending value to the address
    let (h1, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(5),
    );

    // Scan the cache
    st.scan_cached_blocks(h1, 1);

    // Create a second fake CompactBlock sending more value to the address
    let (h2, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(7),
    );

    // Scanning should detect no inconsistencies
    st.scan_cached_blocks(h2, 1);
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub fn invalid_chain_cache_disconnected<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let dfvk = T::test_account_fvk(&st);

    // Create some fake CompactBlocks
    let (h, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(5),
    );
    let (last_contiguous_height, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(7),
    );

    // Scanning the cache should find no inconsistencies
    st.scan_cached_blocks(h, 2);

    // Create more fake CompactBlocks that don't connect to the scanned ones
    let disconnect_height = last_contiguous_height + 1;
    st.generate_block_at(
        disconnect_height,
        BlockHash([1; 32]),
        &[FakeCompactOutput::new(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(8),
        )],
        2,
        2,
        true,
    );
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(3),
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

pub fn data_db_truncation<T: ShieldedPoolTester, DSF>(ds_factory: DSF, cache: impl TestCache)
where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create fake CompactBlocks sending value to the address
    let value = Zatoshis::const_from_u64(5);
    let value2 = Zatoshis::const_from_u64(7);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

    // Scan the cache
    st.scan_cached_blocks(h, 2);

    // Spendable balance should reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.id(), 1),
        (value + value2).unwrap()
    );

    // "Rewind" to height of last scanned block (this is a no-op)
    st.wallet_mut().truncate_to_height(h + 1).unwrap();

    // Spendable balance should be unaltered
    assert_eq!(
        st.get_spendable_balance(account.id(), 1),
        (value + value2).unwrap()
    );

    // Rewind so that one block is dropped
    st.wallet_mut().truncate_to_height(h).unwrap();

    // Spendable balance should only contain the first received note;
    // the rest should be pending.
    assert_eq!(st.get_spendable_balance(account.id(), 1), value);
    assert_eq!(st.get_pending_shielded_balance(account.id(), 1), value2);

    // Scan the cache again
    st.scan_cached_blocks(h, 2);

    // Account balance should again reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.id(), 1),
        (value + value2).unwrap()
    );
}

pub fn reorg_to_checkpoint<T: ShieldedPoolTester, DSF, C>(ds_factory: DSF, cache: C)
where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
    C: TestCache,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();

    // Create a sequence of blocks to serve as the foundation of our chain state.
    let p0_fvk = T::random_fvk(st.rng_mut());
    let gen_random_block = |st: &mut TestState<C, DSF::DataStore, LocalNetwork>,
                            output_count: usize| {
        let fake_outputs =
            std::iter::repeat_with(|| FakeCompactOutput::random(st.rng_mut(), p0_fvk.clone()))
                .take(output_count)
                .collect::<Vec<_>>();
        st.generate_next_block_multi(&fake_outputs[..]);
        output_count
    };

    // The stable portion of the tree will contain 20 notes.
    for _ in 0..10 {
        gen_random_block(&mut st, 4);
    }

    // We will reorg to this height.
    let reorg_height = account.birthday().height() + 4;
    let reorg_position = Position::from(19);

    // Scan the first 5 blocks. The last block in this sequence will be where we simulate a
    // reorg.
    st.scan_cached_blocks(account.birthday().height(), 5);
    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        reorg_height
    );

    // There will be 6 checkpoints: one for the prior block frontier, and then one for each scanned
    // block.
    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(checkpoints.len(), 6);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height, Some(reorg_position)))
    );

    // Scan another block, then simulate a reorg.
    st.scan_cached_blocks(reorg_height + 1, 1);
    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        reorg_height + 1
    );
    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(checkpoints.len(), 7);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height + 1, Some(reorg_position + 4)))
    );

    //        /\  /\  /\
    //  .... /\/\/\/\/\/\
    //          c   d   e

    // Truncate back to the reorg height, but retain the block cache.
    st.truncate_to_height_retaining_cache(reorg_height);

    // The following error-prone tree state is generated by the a previous (buggy) truncate
    // implementation:
    //        /\  /\
    //  .... /\/\/\/\
    //          c

    // We have pruned back to the original checkpoints & tree state.
    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(checkpoints.len(), 6);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height, Some(reorg_position)))
    );

    // Skip two blocks, then (re) scan the same block.
    st.scan_cached_blocks(reorg_height + 2, 1);

    // Given the buggy truncation, this would result in this the following tree state:
    //        /\  /\   \  /\
    //  .... /\/\/\/\   \/\/\
    //          c       e   f

    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    // Even though we only scanned one block, we get a checkpoint at both the start and the end of
    // the block due to the insertion of the prior block frontier.
    assert_eq!(checkpoints.len(), 8);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height + 2, Some(reorg_position + 8)))
    );

    // Now, fully truncate back to the reorg height. This should leave the tree in a state
    // where it can be added to with arbitrary notes.
    st.truncate_to_height(reorg_height);

    // Generate some new random blocks
    for _ in 0..10 {
        let output_count = st.rng_mut().gen_range(2..10);
        gen_random_block(&mut st, output_count);
    }

    // The previous truncation retained the cache, so re-scanning the same blocks would have
    // resulted in the same note commitment tree state, and hence no conflicts; could occur. Now
    // that we have cleared the cache and generated a different sequence blocks, if truncation did
    // not completely clear the tree state this would generates a note commitment tree conflict.
    st.scan_cached_blocks(reorg_height + 1, 1);
}

pub fn scan_cached_blocks_allows_blocks_out_of_order<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);
    assert_eq!(st.get_total_balance(account.id()), value);

    // Create blocks to reach height + 2
    let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    let (h3, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the later block first
    st.scan_cached_blocks(h3, 1);

    // Now scan the block of height height + 1
    st.scan_cached_blocks(h2, 1);
    assert_eq!(
        st.get_total_balance(account.id()),
        Zatoshis::const_from_u64(150_000)
    );

    // We can spend the received notes
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(st.network()),
        Zatoshis::const_from_u64(110_000),
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            req,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        ),
        Ok(_)
    );
}

pub fn scan_cached_blocks_finds_received_notes<T: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(5);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the cache
    let summary = st.scan_cached_blocks(h1, 1);
    assert_eq!(summary.scanned_range().start, h1);
    assert_eq!(summary.scanned_range().end, h1 + 1);
    assert_eq!(T::received_note_count(&summary), 1);

    // Account balance should reflect the received note
    assert_eq!(st.get_total_balance(account.id()), value);

    // Create a second fake CompactBlock sending more value to the address
    let value2 = Zatoshis::const_from_u64(7);
    let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

    // Scan the cache again
    let summary = st.scan_cached_blocks(h2, 1);
    assert_eq!(summary.scanned_range().start, h2);
    assert_eq!(summary.scanned_range().end, h2 + 1);
    assert_eq!(T::received_note_count(&summary), 1);

    // Account balance should reflect both received notes
    assert_eq!(
        st.get_total_balance(account.id()),
        (value + value2).unwrap()
    );
}

// TODO: This test can probably be entirely removed, as the following test duplicates it entirely.
pub fn scan_cached_blocks_finds_change_notes<T: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(5);
    let (received_height, _, nf) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the cache
    st.scan_cached_blocks(received_height, 1);

    // Account balance should reflect the received note
    assert_eq!(st.get_total_balance(account.id()), value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = Zatoshis::const_from_u64(2);
    let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

    // Scan the cache again
    st.scan_cached_blocks(spent_height, 1);

    // Account balance should equal the change
    assert_eq!(
        st.get_total_balance(account.id()),
        (value - value2).unwrap()
    );
}

pub fn scan_cached_blocks_detects_spends_out_of_order<T: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(0), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(5);
    let (received_height, _, nf) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = Zatoshis::const_from_u64(2);
    let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

    // Scan the spending block first.
    st.scan_cached_blocks(spent_height, 1);

    // Account balance should equal the change
    assert_eq!(
        st.get_total_balance(account.id()),
        (value - value2).unwrap()
    );

    // Now scan the block in which we received the note that was spent.
    st.scan_cached_blocks(received_height, 1);

    // Account balance should be the same.
    assert_eq!(
        st.get_total_balance(account.id()),
        (value - value2).unwrap()
    );
}

pub fn metadata_queries_exclude_unwanted_notes<T: ShieldedPoolTester, DSF, TC>(
    ds_factory: DSF,
    cache: TC,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: std::fmt::Debug,
    TC: TestCache,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Create 10 blocks with successively increasing value
    let value = Zatoshis::const_from_u64(100_0000);
    let (h0, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    let mut note_values = vec![value];
    for i in 2..=10 {
        let value = Zatoshis::const_from_u64(i * 100_0000);
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        note_values.push(value);
    }
    st.scan_cached_blocks(h0, 10);

    let test_meta = |st: &TestState<TC, DSF::DataStore, LocalNetwork>, query, expected_count| {
        let metadata = st
            .wallet()
            .get_account_metadata(account.id(), &query, &[])
            .unwrap();

        assert_eq!(metadata.note_count(T::SHIELDED_PROTOCOL), expected_count);
    };

    test_meta(
        &st,
        NoteFilter::ExceedsMinValue(Zatoshis::const_from_u64(1000_0000)),
        Some(1),
    );
    test_meta(
        &st,
        NoteFilter::ExceedsMinValue(Zatoshis::const_from_u64(500_0000)),
        Some(6),
    );
    test_meta(
        &st,
        NoteFilter::ExceedsBalancePercentage(BoundedU8::new_const(10)),
        Some(5),
    );

    // We haven't sent any funds yet, so we can't evaluate this query
    test_meta(
        &st,
        NoteFilter::ExceedsPriorSendPercentile(BoundedU8::new_const(50)),
        None,
    );

    // Spend half of each one of our notes, so that we can get a distribution of sent note values.
    // FIXME: This test is currently excessively specialized to the `zcash_client_sqlite::WalletDb`
    // implmentation of the `InputSource` trait. A better approach would be to create a test input
    // source that can select a set of notes directly based upon their nullifiers.
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to = T::fvk_default_address(&not_our_key).to_zcash_address(st.network());
    let nz2 = NonZeroU64::new(2).unwrap();

    for value in &note_values {
        let txids = st
            .create_standard_transaction(&account, to.clone(), *value / nz2)
            .unwrap();
        st.generate_next_block_including(txids.head);
    }
    st.scan_cached_blocks(h0 + 10, 10);

    // Since we've spent half our notes, our remaining notes each have approximately half their
    // original value. The 50th percentile of our spends should be 250_0000 ZAT, and half of our
    // remaining notes should have value greater than that.
    test_meta(
        &st,
        NoteFilter::ExceedsPriorSendPercentile(BoundedU8::new_const(50)),
        Some(5),
    );
}

#[cfg(feature = "pczt")]
pub fn pczt_single_step<P0: ShieldedPoolTester, P1: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::AccountId: serde::Serialize + serde::de::DeserializeOwned,
{
    use zcash_protocol::consensus::ZIP212_GRACE_PERIOD;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|_, network| {
            // Initialize the chain state to after ZIP 212 became enforced.
            let birthday_height = std::cmp::max(
                network.activation_height(NetworkUpgrade::Nu5).unwrap(),
                network.activation_height(NetworkUpgrade::Canopy).unwrap() + ZIP212_GRACE_PERIOD,
            );

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    Frontier::empty(),
                    #[cfg(feature = "orchard")]
                    Frontier::empty(),
                ),
                prior_sapling_roots: vec![],
                #[cfg(feature = "orchard")]
                prior_orchard_roots: vec![],
            }
        })
        .with_account_having_current_birthday()
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    // Only mine a block in P0 to ensure the transactions source is there.
    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 1);

    assert_eq!(st.get_total_balance(account.id()), note_value);
    assert_eq!(st.get_spendable_balance(account.id(), 1), note_value);

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P0::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);

    let create_proposed_result = st.create_pczt_from_proposal::<Infallible, _, Infallible>(
        account.id(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(_));
    let pczt_created = create_proposed_result.unwrap();

    // If we don't create proofs or signatures, we will fail to extract a transaction.
    assert_matches!(
        st.extract_and_store_transaction_from_pczt(pczt_created.clone()),
        Err(Error::Pczt(data_api::error::PcztError::Extraction(_)))
    );

    // Add proof generation keys to Sapling spends.
    let pczt_updated = P0::add_proof_generation_keys(pczt_created, account.usk()).unwrap();

    // Create proofs.
    let sapling_prover = LocalTxProver::bundled();
    let orchard_pk = ::orchard::circuit::ProvingKey::build();
    let pczt_proven = Prover::new(pczt_updated)
        .create_orchard_proof(&orchard_pk)
        .unwrap()
        .create_sapling_proofs(&sapling_prover, &sapling_prover)
        .unwrap()
        .finish();

    // Apply signatures.
    let mut signer = Signer::new(pczt_proven).unwrap();
    P0::apply_signatures_to_pczt(&mut signer, account.usk()).unwrap();
    let pczt_authorized = signer.finish();

    // Now we can extract the transaction.
    let extract_and_store_result = st.extract_and_store_transaction_from_pczt(pczt_authorized);
    assert_matches!(&extract_and_store_result, Ok(_));
    let txid = extract_and_store_result.unwrap();

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);
}
