use assert_matches::assert_matches;
use incrementalmerkletree::Level;
use rand::RngCore;
use shardtree::error::ShardTreeError;
use std::{cmp::Eq, convert::Infallible, hash::Hash, num::NonZeroU32};

use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::{
    block::BlockHash,
    transaction::{fees::StandardFeeRule, Transaction},
};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::{Memo, MemoBytes},
    value::Zatoshis,
    ShieldedProtocol,
};
use zip321::Payment;

use crate::{
    data_api::{
        chain::{CommitmentTreeRoot, ScanSummary},
        testing::{AddressType, TestBuilder},
        wallet::{decrypt_and_store_transaction, input_selection::GreedyInputSelector},
        Account as _, DecryptedTransaction, InputSource, WalletCommitmentTrees, WalletRead,
        WalletSummary,
    },
    decrypt_transaction,
    fees::{standard, DustOutputPolicy},
    wallet::{Note, NoteId, OvkPolicy, ReceivedNote},
};

use super::{DataStoreFactory, TestCache, TestFvk, TestState};

/// Trait that exposes the pool-specific types and operations necessary to run the
/// single-shielded-pool tests on a given pool.
pub trait ShieldedPoolTester {
    const SHIELDED_PROTOCOL: ShieldedProtocol;

    type Sk;
    type Fvk: TestFvk;
    type MerkleTreeHash;
    type Note;

    fn test_account_fvk<Cache, DbT: WalletRead, P: consensus::Parameters>(
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

    fn put_subtree_roots<Cache, DbT: WalletRead + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        start_index: u64,
        roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    fn next_subtree_index<A: Hash + Eq>(s: &WalletSummary<A>) -> u64;

    #[allow(clippy::type_complexity)]
    fn select_spendable_notes<Cache, DbT: InputSource + WalletRead, P>(
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
}

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
    );
    let input_selector = &GreedyInputSelector::new(change_strategy, DustOutputPolicy::default());

    let proposal = st
        .propose_transfer(
            account.id(),
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
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), h + 1, &tx, &ufvks);
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

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}
