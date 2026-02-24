use std::{
    cmp::Eq,
    collections::HashSet,
    convert::Infallible,
    hash::Hash,
    num::{NonZeroU8, NonZeroU32, NonZeroU64, NonZeroUsize},
};

use assert_matches::assert_matches;
use incrementalmerkletree::{Level, Position, frontier::Frontier};
use rand::{Rng, RngCore};
use secrecy::Secret;
use shardtree::error::ShardTreeError;

use transparent::address::TransparentAddress;
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::{
    block::BlockHash,
    transaction::{
        Transaction,
        fees::zip317::{FeeRule as Zip317FeeRule, MARGINAL_FEE, MINIMUM_FEE},
    },
};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight, NetworkUpgrade, Parameters},
    local_consensus::LocalNetwork,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zip32::Scope;
use zip321::{Payment, TransactionRequest};

use crate::{
    data_api::{
        self, Account as _, AccountBirthday, BoundedU8, DecryptedTransaction, InputSource,
        MaxSpendMode, NoteFilter, Ratio, TargetValue, WalletCommitmentTrees, WalletRead,
        WalletSummary, WalletTest, WalletWrite,
        chain::{self, ChainState, CommitmentTreeRoot, ScanSummary},
        error::Error,
        testing::{
            AddressType, CacheInsertionResult, FakeCompactOutput, InitialChainState, TestBuilder,
            single_output_change_strategy,
        },
        wallet::{
            ConfirmationsPolicy, TargetHeight, TransferErrT, decrypt_and_store_transaction,
            input_selection::GreedyInputSelector,
        },
    },
    decrypt_transaction,
    fees::{
        self, DustOutputPolicy, SplitPolicy, StandardFeeRule,
        standard::{self, SingleOutputChangeStrategy},
    },
    scanning::ScanError,
    wallet::{Note, NoteId, OvkPolicy, ReceivedNote},
};

use super::{DataStoreFactory, Reset, TestCache, TestFvk, TestState};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        data_api::{CoinbaseFilter, TransactionDataRequest},
        fees::ChangeValue,
        proposal::{Proposal, ProposalError, StepOutput, StepOutputIndex},
        wallet::WalletTransparentOutput,
    },
    nonempty::NonEmpty,
    std::str::FromStr,
    transparent::{
        bundle::{OutPoint, TxOut},
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    },
    zcash_primitives::transaction::fees::zip317,
    zcash_protocol::{TxId, value::ZatBalance},
};

#[cfg(feature = "orchard")]
use zcash_protocol::PoolType;

#[cfg(feature = "pczt")]
use {
    crate::data_api::wallet::{redact_pczt_for_batch_signer, redact_pczt_for_signer},
    pczt::roles::{combiner::Combiner, prover::Prover, signer::Signer},
    rand_core::OsRng,
    transparent::builder::TransparentSigningSet,
    zcash_primitives::transaction::builder::{BuildConfig, Builder},
    zcash_proofs::prover::LocalTxProver,
    zcash_script::opcode::PushValue,
};

pub mod dsl;
use dsl::{TestDsl, TestNoteConfig};

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
    const SHIELDED_PROTOCOL: ShieldedPool;

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

    /// Computes the actual root of the `shard_index`-th shard from the wallet's local
    /// shardtree state, reading whatever leaves and cached annotations are currently
    /// stored. Used by tests that need to call [`Self::put_subtree_roots`] with a root
    /// that matches the shard's actual computed root — for example, when declaring a
    /// shard complete after filling its last position via `scan_cached_blocks`.
    fn shard_root<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        shard_index: u64,
    ) -> Result<Self::MerkleTreeHash, ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    fn next_subtree_index<A: Hash + Eq>(s: &WalletSummary<A>) -> u64;

    fn note_value(note: &Self::Note) -> Zatoshis;

    #[allow(clippy::type_complexity)]
    fn select_spendable_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_value: TargetValue,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error>;

    #[allow(clippy::type_complexity)]
    fn select_unspent_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_height: TargetHeight,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error>;

    fn decrypted_pool_outputs_count<A>(d_tx: &DecryptedTransaction<Transaction, A>) -> usize;

    fn with_decrypted_pool_memos<A>(
        d_tx: &DecryptedTransaction<Transaction, A>,
        f: impl FnMut(&MemoBytes),
    );

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
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let (h, _, _) = st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

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

    let account = st.get_account();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
            Some(other) => panic!("Unexpected memo value: {other:?}"),
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

/// Builds a real transaction via the proposal/creation path, assembles it into a full
/// block, and verifies that [`decrypt_block`] followed by [`scan_block`] detects the
/// wallet output (the change note) that it contains.
///
/// [`decrypt_block`]: crate::scanning::full::decrypt_block
/// [`scan_block`]: crate::scanning::full::scan_block
pub fn scan_full_block_detects_outputs<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use incrementalmerkletree::Retention;
    use nonempty::NonEmpty;
    use zcash_primitives::block::{Block, BlockHeaderData};

    use crate::{
        data_api::BlockMetadata,
        scanning::{
            Nullifiers, ScanningKeys,
            full::{decrypt_block, scan_block},
        },
    };

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note.
    let (h, _, _) = st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    // Propose and create a transfer to an external recipient. The resulting transaction
    // has two shielded outputs: the payment, and the change returned to the wallet.
    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account = st.get_account();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let txids = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    assert_eq!(txids.len(), 1);

    let tx = st
        .wallet()
        .get_transaction(*txids.first())
        .unwrap()
        .expect("the created transaction was stored");

    // Build a `ScanningKeys` set for the wallet account. The account identifier used for
    // scanning is independent of the wallet database's account identifier.
    let ufvk = account.usk().to_unified_full_viewing_key();
    let scanning_keys = ScanningKeys::from_account_ufvks([(zip32::AccountId::ZERO, ufvk)]);

    // Assemble a single-transaction block containing the created transaction. The block
    // is scanned in isolation, so we treat the note commitment trees as empty as of the
    // immediately preceding block.
    let network = *st.network();
    let header = BlockHeaderData {
        version: 4,
        prev_block: BlockHash([0; 32]),
        merkle_root: [0; 32],
        final_sapling_root: [0; 32],
        time: 0,
        bits: 0,
        nonce: [0; 32],
        solution: vec![],
    }
    .freeze()
    .unwrap();
    let block = Block::from_parts(header, NonEmpty::singleton(tx), h);

    let prior_block_metadata = BlockMetadata::from_parts(
        h - 1,
        BlockHash([0; 32]),
        Some(0),
        #[cfg(feature = "orchard")]
        Some(0),
        #[cfg(feature = "orchard")]
        Some(0),
    );

    // Phase 1: decrypt the block's shielded outputs.
    let (header, vtx) = decrypt_block(&network, block, &scanning_keys);

    // Phase 2: scan the decrypted block.
    #[cfg(feature = "transparent-inputs")]
    let scanned = scan_block(
        &network,
        h,
        &header,
        vtx,
        &scanning_keys,
        &Nullifiers::empty(),
        Some(&prior_block_metadata),
        |_addr| Ok::<_, Infallible>(None),
    )
    .expect("scanning the block succeeds");
    #[cfg(not(feature = "transparent-inputs"))]
    let scanned = scan_block::<_, _, _, Infallible>(
        &network,
        h,
        &header,
        vtx,
        &scanning_keys,
        &Nullifiers::empty(),
        Some(&prior_block_metadata),
    )
    .expect("scanning the block succeeds");

    // The wallet should have detected exactly the change output returned to its internal
    // address; the payment output was sent to a recipient outside the wallet.
    assert_eq!(scanned.transactions().len(), 1);
    let received_outputs: usize = scanned
        .transactions()
        .iter()
        .map(|wtx| {
            let n = wtx.sapling_outputs().len();
            #[cfg(feature = "orchard")]
            let n = n + wtx.orchard_outputs().len();
            n
        })
        .sum();
    assert_eq!(received_outputs, 1);

    // The note commitment tree should have grown by exactly the two shielded outputs in
    // the block's single transaction (the payment and the change), starting from the
    // empty prior tree. The outputs all belong to the pool under test; the other pool (if
    // compiled in) sees no outputs.
    let total_commitments = scanned.sapling().commitments().len();
    #[cfg(feature = "orchard")]
    let total_commitments = total_commitments + scanned.orchard().commitments().len();
    assert_eq!(total_commitments, 2);

    let total_final_tree_size = scanned.sapling().final_tree_size();
    #[cfg(feature = "orchard")]
    let total_final_tree_size = total_final_tree_size + scanned.orchard().final_tree_size();
    assert_eq!(total_final_tree_size, 2);

    // The final note added in the block must be marked as a checkpoint at this block
    // height; this is what lets the wallet anchor witnesses to the block. Getting the
    // "last outputs in the block" boundary wrong is the most error-prone part of position
    // tracking, so we assert it explicitly.
    let last_retention = scanned.sapling().commitments().last().map(|(_, r)| *r);
    #[cfg(feature = "orchard")]
    let last_retention = scanned
        .orchard()
        .commitments()
        .last()
        .map(|(_, r)| *r)
        .or(last_retention);
    assert!(
        matches!(last_retention, Some(Retention::Checkpoint { id, .. }) if id == h),
        "final note commitment should be a checkpoint at height {h:?}, got {last_retention:?}",
    );
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ConfirmationStep {
    i: u32,
    confirmation_requirement: u32,
    number_of_confirmations: u32,
    pending_balance: Zatoshis,
    spendable_balance: Zatoshis,
    total_balance: Zatoshis,
}

/// An enumeration of mechanisms for generating transaction inputs for confirmations policy
/// testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputTrust {
    /// Generate a wallet-internal output.
    Internal,
    /// Generate an output as if it was sent to the wallet by an untrusted counterparty.
    ExternalUntrusted,
    /// Generate an output as if it was sent to the wallet by a trusted counterparty.
    ExternalTrusted,
}

/// Tests that inputs from a source can be spent according to the default
/// `ConfirmationsPolicy`.
///
/// The test:
/// - Adds funds to the wallet in a single note from an certain source.
/// - Checks that the wallet balances are correct after N confirmations, according to
///   the policy.
pub fn zip_315_confirmations_test_steps<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
    input_trust: InputTrust,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account = st.test_account().cloned().unwrap();
    let starting_balance = Zatoshis::const_from_u64(60_000);

    // Add funds to the wallet in a single note, owned by the internal spending key,
    // which will have one confirmation.
    let confirmations_policy = ConfirmationsPolicy::default();
    let (address_type, min_confirmations) = match input_trust {
        InputTrust::Internal => (AddressType::Internal, confirmations_policy.trusted()),
        InputTrust::ExternalUntrusted => (
            AddressType::DefaultExternal,
            confirmations_policy.untrusted(),
        ),
        InputTrust::ExternalTrusted => {
            (AddressType::DefaultExternal, confirmations_policy.trusted())
        }
    };
    let min_confirmations = u32::from(min_confirmations);

    let (_, r, _) = st.add_a_single_note_checking_balance(
        TestNoteConfig::from(starting_balance).with_address_type(address_type),
    );
    let txid = r.txids()[0];

    // Mark the external input as explicitly trusted, if so requested
    let trusted = input_trust == InputTrust::ExternalTrusted;
    if trusted {
        st.wallet_mut().set_tx_trust(txid, true).unwrap();
    }

    let add_confirmation = |i: u32| {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
        let outputs = st
            .wallet()
            .get_received_outputs(txid, TargetHeight::from(h + 1), confirmations_policy)
            .unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(
            outputs[0].confirmations_until_spendable(),
            u32::from(if trusted {
                confirmations_policy.trusted()
            } else {
                confirmations_policy.untrusted()
            })
            .saturating_sub(i + 1)
        );
        ConfirmationStep {
            i,
            confirmation_requirement: min_confirmations,
            number_of_confirmations: 1 + i,
            pending_balance: st.get_pending_shielded_balance(account.id(), confirmations_policy),
            spendable_balance: st.get_spendable_balance(account.id(), confirmations_policy),
            total_balance: st.get_total_balance(account.id()),
        }
    };

    // Generate N confirmations by mining blocks
    let steps = (1u32..min_confirmations)
        .map(add_confirmation)
        .collect::<Vec<_>>();

    assert!(
        steps
            .iter()
            .filter(|step| step.number_of_confirmations < min_confirmations)
            .all(|step| step.spendable_balance == Zatoshis::ZERO),
        "spendable balance is equal to starting balance until we have sufficient confirmations"
    );

    let to = T::random_address(st.rng_mut());
    // Now that the funds are spendable, propose a transaction
    let proposed = st.propose_standard_transfer::<Infallible>(
        account.id(),
        StandardFeeRule::Zip317,
        confirmations_policy,
        &to,
        Zatoshis::const_from_u64(10_000),
        None,
        None,
        T::SHIELDED_PROTOCOL,
    );
    assert!(
        proposed.is_ok(),
        "Could not spend funds by confirmation policy ({input_trust:?}): {proposed:#?}\n\
        steps: {steps:#?}",
    );
}

/// Tests max spendable funds within the given shielded pool in a
/// single transaction.
///
/// The test:
/// - Adds funds to the wallet in two notes with different confirmation heights
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend the whole balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn spend_max_spendable_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in two notes over 5 blocks
    let value = Zatoshis::const_from_u64(60000);
    let h = st
        .add_notes_checking_balance([Some(value), None, None, None, Some(value)])
        .block_height()
        .unwrap();

    // Spendable balance matches total balance
    let account = st.test_account().cloned().unwrap();
    let confirmation_policy = ConfirmationsPolicy::new_symmetrical(
        NonZeroU32::new(2).expect("2 is not zero"),
        #[cfg(feature = "transparent-inputs")]
        false,
    );
    assert_eq!(
        st.get_spendable_balance(account.id(), confirmation_policy),
        value
    );

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::MaxSpendable,
            confirmation_policy,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_send_max_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == send_max_memo {
            found_send_max_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_send_max_memo);
    assert!(!found_tx_empty_memo); // there's no empty memo in this case

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 1);

    // The sent memo should the specified memo for the sent output
    let mut found_sent_empty_memo = false;
    let mut found_sent_max_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Memo retrieval should succeed")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(m) if m == &send_max_memo => {
                found_sent_max_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    assert!(found_sent_max_memo);
    assert!(!found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, 12345)),
        Ok(None)
    );

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 3);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }
    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(60000));
    }
    {
        let tx_2 = &tx_history[2];
        assert_eq!(tx_2.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_2.total_received(), Zatoshis::const_from_u64(0));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

/// Tests sending every piece of spendable funds within the given shielded pool in a
/// single transaction.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend the whole balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn spend_everything_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();

    // Add funds to the wallet in a single note
    let (h, _, _) = st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_send_max_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == send_max_memo {
            found_send_max_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_send_max_memo);
    assert!(!found_tx_empty_memo); // there's no empty memo in this case

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 1);

    // The sent memo should the specified memo for the sent output
    let mut found_sent_empty_memo = false;
    let mut found_sent_max_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Memo retrieval should succeed")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(m) if m == &send_max_memo => {
                found_sent_max_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    assert!(found_sent_max_memo);
    assert!(!found_sent_empty_memo);

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
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(0));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

/// Tests that sending all the spendable funds within the given shielded pool in a
/// single transaction to a transparent address with a memo fails.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Tries to propose a send max transaction to a T-address with a memo
/// - Fails gracefully with Zip321Error.
#[cfg(feature = "transparent-inputs")]
pub fn fails_to_send_max_spendable_to_transparent_with_memo<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use crate::data_api::MaxSpendMode;

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let account = st.test_account().cloned().unwrap();
    let (default_addr, _) = account.usk().default_transparent_address();

    let to: Address = Address::Transparent(default_addr);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN
        ),
        Err(data_api::error::Error::Payment(
            zip321::PaymentError::TransparentMemo
        ))
    );
}

/// Tests that sending all the spendable funds within the given shielded pool to a
/// transparent (non-TEX) recipient succeeds.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Proposes a send-max transaction to a transparent address, without a memo.
/// - Verifies that the proposal consists of a single step paying the whole balance,
///   less the fee, to the transparent recipient.
/// - Builds the transaction.
#[cfg(feature = "transparent-inputs")]
pub fn send_max_spendable_to_transparent<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use zcash_protocol::PoolType;

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(60000);
    st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();
    let to: Address = Address::Transparent(TransparentAddress::PublicKeyHash([0x7f; 20]));

    let fee_rule = StandardFeeRule::Zip317;

    // The proposed transaction carries one shielded spend (padded to two shielded
    // outputs) and one transparent output.
    let expected_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
    let expected_payment = (value - expected_fee).unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].balance().fee_required(), expected_fee);
    assert_eq!(steps[0].balance().proposed_change(), []);
    assert_eq!(
        steps[0].payment_pools(),
        &std::collections::BTreeMap::from([(0, PoolType::TRANSPARENT)])
    );
    assert_matches!(
        steps[0].transaction_request().payments().get(&0),
        Some(payment) if payment.amount() == Some(expected_payment)
    );

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);
}

/// Tests that a send-max proposal whose total required fee overflows the maximum
/// monetary amount fails with a balance error rather than panicking.
#[cfg(feature = "transparent-inputs")]
pub fn send_max_fee_overflow_is_an_error<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use zcash_primitives::transaction::fees::{FeeRule, transparent::InputSize};
    use zcash_protocol::value::{BalanceError, MAX_MONEY};

    use crate::data_api::wallet::input_selection::GreedyInputSelectorError;

    /// A fee rule that requires the maximum monetary amount for every transaction.
    #[derive(Clone, Debug)]
    struct MaxMoneyFeeRule;

    impl FeeRule for MaxMoneyFeeRule {
        type Error = Infallible;

        fn fee_required<P: consensus::Parameters>(
            &self,
            _params: &P,
            _target_height: BlockHeight,
            _transparent_input_sizes: impl IntoIterator<Item = InputSize>,
            _transparent_output_sizes: impl IntoIterator<Item = usize>,
            _sapling_input_count: usize,
            _sapling_output_count: usize,
            _orchard_action_count: usize,
            _ironwood_action_count: usize,
        ) -> Result<Zatoshis, Self::Error> {
            Ok(Zatoshis::const_from_u64(MAX_MONEY))
        }
    }

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let account = st.test_account().cloned().unwrap();

    // A TEX recipient requires a second transaction, so the total required fee is the
    // sum of two per-transaction fees, which overflows the maximum monetary amount.
    let tex_addr = Address::Tex([0x4; 20]);
    let addy = tex_addr.to_zcash_address(st.network());

    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &MaxMoneyFeeRule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        ),
        Err(data_api::error::Error::NoteSelection(
            GreedyInputSelectorError::Balance(BalanceError::Overflow)
        ))
    );
}

/// Tests that a send-max proposal spends notes from multiple shielded pools in a single
/// transaction when the wallet's funds are split across pools.
///
/// The test:
/// - Adds one note in each of the `P0` and `P1` pools.
/// - Proposes a send-max transaction to an external `P1` recipient, so that the value of
///   the `P0` note crosses pools.
/// - Verifies that the proposal consists of a single step spending both notes and paying
///   the whole balance, less the fee, to the recipient.
/// - Builds the transaction, mines it, and verifies that the wallet is left empty.
#[cfg(feature = "orchard")]
pub fn send_max_spends_inputs_across_pools<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use std::collections::{BTreeMap, BTreeSet};

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();
    let account = st.test_account().cloned().unwrap();

    // Add one note in each of the P0 and P1 pools.
    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);
    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let total = (note_value * 2u64).unwrap();
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        total
    );

    let to: Address = P1::sk_default_address(&P1::sk(&[0xf5; 32]));
    let fee_rule = StandardFeeRule::Zip317;

    // The proposed transaction spends one note in each pool and pays a single shielded
    // output; under ZIP 317, each of the two shielded bundles is padded to two logical
    // actions.
    let expected_fee = (MARGINAL_FEE * 4u64).unwrap();
    let expected_payment = (total - expected_fee).unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].balance().fee_required(), expected_fee);
    assert_eq!(steps[0].balance().proposed_change(), []);
    assert_eq!(
        steps[0].payment_pools(),
        &BTreeMap::from([(0, PoolType::Shielded(P1::SHIELDED_PROTOCOL))])
    );
    assert_matches!(
        steps[0].transaction_request().payments().get(&0),
        Some(payment) if payment.amount() == Some(expected_payment)
    );

    // The proposal spends both notes, one from each pool.
    let input_notes = steps[0]
        .shielded_inputs()
        .expect("the proposal has shielded inputs")
        .notes();
    assert_eq!(input_notes.len(), 2);
    let input_pools = input_notes
        .iter()
        .map(|n| match n.note() {
            Note::Sapling(_) => ShieldedPool::Sapling,
            Note::Orchard { pool, .. } => match pool {
                ::orchard::ValuePool::Orchard => ShieldedPool::Orchard,
                ::orchard::ValuePool::Ironwood => ShieldedPool::Ironwood,
            },
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        input_pools,
        BTreeSet::from([P0::SHIELDED_PROTOCOL, P1::SHIELDED_PROTOCOL])
    );

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    // Mine the transaction and verify that the entire balance has been spent.
    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);
    assert_eq!(st.get_total_balance(account.id()), Zatoshis::ZERO);
}

/// Tests that proposing a send-max transfer to a TEX recipient fails with a meaningful
/// error when the `transparent-inputs` feature is not enabled.
#[cfg(not(feature = "transparent-inputs"))]
pub fn send_max_to_tex_fails_without_transparent_inputs<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use crate::data_api::wallet::input_selection::GreedyInputSelectorError;

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let account = st.test_account().cloned().unwrap();
    let tex_addr = Address::Tex([0x4; 20]);
    let fee_rule = StandardFeeRule::Zip317;

    let addy = tex_addr.to_zcash_address(st.network());
    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        ),
        Err(data_api::error::Error::NoteSelection(
            GreedyInputSelectorError::UnsupportedTexAddress
        ))
    );
}

/// Tests that a send-max proposal to a unified address having both Sapling and Orchard
/// receivers is delivered via the Sapling receiver when the `orchard` feature is not
/// enabled, rather than failing.
#[cfg(not(feature = "orchard"))]
pub fn send_max_delivers_via_sapling_when_orchard_is_unavailable<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use zcash_address::{
        ZcashAddress,
        unified::{self, Encoding as _, Receiver},
    };
    use zcash_protocol::PoolType;

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(60000);
    st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();

    // Construct a unified address carrying both a Sapling receiver and an Orchard
    // receiver. Without the `orchard` feature, the Orchard receiver's contents are
    // not parsed, so arbitrary receiver bytes suffice.
    let sapling_receiver = match T::sk_default_address(&T::sk(&[0xf5; 32])) {
        Address::Sapling(addr) => addr.to_bytes(),
        _ => panic!("expected a Sapling address"),
    };
    let ua = unified::Address::try_from_items(vec![
        Receiver::Sapling(sapling_receiver),
        Receiver::Orchard([0xab; 43]),
    ])
    .unwrap();
    let addy = ZcashAddress::try_from_encoded(&ua.encode(&st.network().network_type())).unwrap();

    let fee_rule = StandardFeeRule::Zip317;

    // The proposed transaction carries one Sapling spend and one requested Sapling
    // output (padded to two logical actions under ZIP 317).
    let expected_fee = MINIMUM_FEE;
    let expected_payment = (value - expected_fee).unwrap();

    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].balance().fee_required(), expected_fee);
    assert_eq!(
        steps[0].payment_pools(),
        &std::collections::BTreeMap::from([(0, PoolType::SAPLING)])
    );
    assert_matches!(
        steps[0].transaction_request().payments().get(&0),
        Some(payment) if payment.amount() == Some(expected_payment)
    );

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);
}

/// Tests that a send-max proposal to a unified address whose only receiver cannot be
/// paid by this build (an Orchard-only address, without the `orchard` feature) fails
/// with `GreedyInputSelectorError::UnsupportedAddress`.
#[cfg(not(feature = "orchard"))]
pub fn send_max_to_orchard_only_ua_fails_without_orchard<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use crate::data_api::wallet::input_selection::GreedyInputSelectorError;
    use zcash_address::{
        ZcashAddress,
        unified::{self, Encoding as _, Receiver},
    };

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let account = st.test_account().cloned().unwrap();

    // Without the `orchard` feature, the Orchard receiver's contents are not parsed,
    // so arbitrary receiver bytes suffice.
    let ua = unified::Address::try_from_items(vec![Receiver::Orchard([0xab; 43])]).unwrap();
    let addy = ZcashAddress::try_from_encoded(&ua.encode(&st.network().network_type())).unwrap();

    let fee_rule = StandardFeeRule::Zip317;

    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        ),
        Err(data_api::error::Error::NoteSelection(
            GreedyInputSelectorError::UnsupportedAddress(_)
        ))
    );
}

/// Tests that a send-max proposal fails with `InsufficientFunds` when the entire wallet
/// balance would be consumed by fees, rather than proposing a transaction that delivers
/// nothing to the recipient.
pub fn send_max_fails_when_balance_is_consumed_by_fees<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds equal to the exact fee of a send-max transaction spending a single note
    // to a same-pool recipient (two logical actions under ZIP 317).
    let value = MINIMUM_FEE;
    st.add_a_single_note_checking_balance(value);

    let account = st.test_account().cloned().unwrap();
    let to: Address = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let fee_rule = StandardFeeRule::Zip317;

    let addy = to.to_zcash_address(st.network());
    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        ),
        Err(data_api::error::Error::InsufficientFunds { available, required })
            if available == value && required > value
    );
}

/// Tests that attempting to send all the spendable funds within the given shielded pool in a
/// single transaction fail if there are funds that are not yet confirmed.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Mine empty blocks
/// - Add more funds
/// - Attempts to construct a request to spend the whole balance to an external address in the
///   same pool.
/// - catches failure
/// - verifies the failure is the one expected
pub fn spend_everything_proposal_fails_when_unconfirmed_funds_present<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    st.add_notes_checking_balance([
        Some(Zatoshis::const_from_u64(60000)),
        None,
        None,
        Some(Zatoshis::const_from_u64(123456)),
    ]);

    // Spendable balance doesn't match total balance
    let account = st.test_account().cloned().unwrap();
    let total_balance = st.get_total_balance(account.id());
    let spendable_balance = st.get_spendable_balance(
        account.id(),
        ConfirmationsPolicy::new_symmetrical_unchecked(
            2,
            #[cfg(feature = "transparent-inputs")]
            true,
        ),
    );
    assert_ne!(total_balance, spendable_balance);

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::Everything,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                true
            )
        ),
        Err(data_api::error::Error::DataSource(_))
    );
}

/// Tests that attempting to send `MaxSpendable` funds within the given shielded pool in a
/// single transaction succeeds if there are funds that are not yet confirmed.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Mine empty blocks
/// - Add more funds
/// - Attempts to construct a request to spend the whole balance to an external address in the
///   same pool.
/// - succeeds at doing so
pub fn send_max_spendable_proposal_succeeds_when_unconfirmed_funds_present<
    T: ShieldedPoolTester,
>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let h = st
        .add_notes_checking_balance([
            Some(Zatoshis::const_from_u64(60000)),
            None,
            None,
            Some(Zatoshis::const_from_u64(123456)),
        ])
        .block_height()
        .unwrap();

    // Spendable balance doesn't match total balance
    let account = st.test_account().cloned().unwrap();
    let total_balance = st.get_total_balance(account.id());
    let spendable_balance = st.get_spendable_balance(
        account.id(),
        ConfirmationsPolicy::new_symmetrical_unchecked(
            2,
            #[cfg(feature = "transparent-inputs")]
            true,
        ),
    );
    assert_ne!(total_balance, spendable_balance);

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::MaxSpendable,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                true,
            ),
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_send_max_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == send_max_memo {
            found_send_max_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_send_max_memo);
    assert!(!found_tx_empty_memo); // there's no empty memo in this case

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 1);

    // The sent memo should the specified memo for the sent output
    let mut found_sent_empty_memo = false;
    let mut found_sent_max_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Memo retrieval should succeed")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(m) if m == &send_max_memo => {
                found_sent_max_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    assert!(found_sent_max_memo);
    assert!(!found_sent_empty_memo);

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
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(0));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

/// This test attempts to send the max spendable funds to a TEX address recipient
/// checks that the transactions were stored and that the amounts involved are correct
#[cfg(feature = "transparent-inputs")]
pub fn spend_everything_multi_step_single_note_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::{MaxSpendMode, OutputOfSentTx};
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();

    let value = Zatoshis::const_from_u64(100000);

    // Add funds to the wallet.
    st.add_a_single_note_checking_balance(value);
    let initial_balance = value;
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral_spend = (value - expected_step0_fee - expected_step1_fee).unwrap();
    let expected_ephemeral_balance = (value - expected_step0_fee).unwrap();
    let expected_step0_change = (value - expected_step0_fee).unwrap();

    let total_sent = (expected_step0_fee + expected_step1_fee + expected_ephemeral_spend).unwrap();

    // check that the napkin math is Ok. Total value send should be the whole
    // value of the wallet
    assert_eq!(total_sent, value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);

    // TODO: Do we want to allow shielded change memos in ephemeral transfers?
    //let change_memo = Memo::from_str("change").expect("valid memo").encode();
    let fee_rule = StandardFeeRule::Zip317;

    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let addy = tex_addr.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account_id,
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 2);

    assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
    assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
    assert_eq!(
        steps[0].balance().proposed_change(),
        [
            // TODO: Do we want to allow shielded change memos in ephemeral transfers?
            //ChangeValue::shielded(
            //    T::SHIELDED_PROTOCOL,
            //    expected_step0_change,
            //    Some(change_memo)
            //),
            ChangeValue::ephemeral_transparent(
                (total_sent - expected_step0_fee).expect("value is non-zero")
            ),
        ]
    );
    assert_eq!(steps[1].balance().proposed_change(), []);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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

    assert!(expected_step0_change > expected_ephemeral_spend);
    assert_eq!(confirmed_sent.len(), 2);
    assert_eq!(confirmed_sent[0].len(), 1);
    assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
    let OutputOfSentTx {
        value: ephemeral_v, ..
    } = confirmed_sent[0][0].clone();
    assert_eq!(ephemeral_v, expected_ephemeral_balance);

    assert_eq!(confirmed_sent[1].len(), 1);
    assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &expected_ephemeral_spend && sent_to_addr == &Some(tex_addr));

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
        -ZatBalance::from(expected_ephemeral_balance),
    );

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(initial_balance - total_sent, ending_balance.into());
}

/// This test attempts to send the max spendable funds to a TEX address recipient
/// checks that the transactions were stored and that the amounts involved are correct
#[cfg(feature = "transparent-inputs")]
pub fn spend_everything_multi_step_many_notes_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::OutputOfSentTx;
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let number_of_notes = 3u64;
    let note_value = Zatoshis::const_from_u64(100000);
    let value = (note_value * number_of_notes).unwrap();

    // Add funds to the wallet.
    for _ in 0..number_of_notes {
        st.add_a_single_note_checking_balance(note_value);
    }

    let initial_balance = value;
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * 4u64).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral_spend = (value - expected_step0_fee - expected_step1_fee).unwrap();
    let expected_ephemeral_balance = (value - expected_step0_fee).unwrap();
    let expected_step0_change = (value - expected_step0_fee).unwrap();

    let total_sent = (expected_step0_fee + expected_step1_fee + expected_ephemeral_spend).unwrap();

    // check that the napkin math is Ok. Total value send should be the whole
    // value of the wallet
    assert_eq!(total_sent, value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);
    let fee_rule = StandardFeeRule::Zip317;

    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let addy = tex_addr.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account_id,
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 2);

    assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
    assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
    assert_eq!(
        steps[0].balance().proposed_change(),
        [ChangeValue::ephemeral_transparent(
            (total_sent - expected_step0_fee).expect("value is non-zero")
        ),]
    );
    assert_eq!(steps[1].balance().proposed_change(), []);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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

    assert!(expected_step0_change > expected_ephemeral_spend);
    assert_eq!(confirmed_sent.len(), 2);
    assert_eq!(confirmed_sent[0].len(), 1);
    assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
    let OutputOfSentTx {
        value: ephemeral_v, ..
    } = confirmed_sent[0][0].clone();
    assert_eq!(ephemeral_v, expected_ephemeral_balance);

    assert_eq!(confirmed_sent[1].len(), 1);
    assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &expected_ephemeral_spend && sent_to_addr == &Some(tex_addr));

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
        -ZatBalance::from(expected_ephemeral_balance),
    );

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(initial_balance - total_sent, ending_balance.into());
}

/// This test attempts to send the max spendable funds to a TEX address recipient.
/// The wallet contains many notes denominated with the marginal fee value.
/// Checks that the transactions were stored and that the amounts involved are correct
#[cfg(feature = "transparent-inputs")]
pub fn spend_everything_multi_step_with_marginal_notes_proposed_transfer<
    T: ShieldedPoolTester,
    Dsf,
>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::{MaxSpendMode, OutputOfSentTx};
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let number_of_notes = 10u64;
    let note_value = Zatoshis::const_from_u64(100000);
    let non_marginal_notes_value =
        (note_value * number_of_notes).expect("sum of notes should not fail.");

    for _ in 0..number_of_notes {
        st.add_a_single_note_checking_balance(note_value);
        st.add_a_single_note_checking_balance(zip317::MARGINAL_FEE);
    }

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        non_marginal_notes_value
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * (number_of_notes + 1)).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral_spend =
        (non_marginal_notes_value - expected_step0_fee - expected_step1_fee).unwrap();
    let expected_ephemeral_balance = (non_marginal_notes_value - expected_step0_fee).unwrap();
    let expected_step0_change = (non_marginal_notes_value - expected_step0_fee).unwrap();

    let total_sent = (expected_step0_fee + expected_step1_fee + expected_ephemeral_spend).unwrap();

    // check that the napkin math is Ok. Total value send should be the whole
    // value of the wallet
    assert_eq!(total_sent, non_marginal_notes_value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);

    let fee_rule = StandardFeeRule::Zip317;

    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let addy = tex_addr.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account_id,
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 2);

    assert_eq!(
        steps[0].shielded_inputs().unwrap().notes().len() as u64,
        number_of_notes
    );
    assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
    assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
    assert_eq!(
        steps[0].balance().proposed_change(),
        [ChangeValue::ephemeral_transparent(
            (total_sent - expected_step0_fee).expect("value is non-zero")
        ),]
    );
    assert_eq!(steps[1].balance().proposed_change(), []);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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

    assert!(expected_step0_change > expected_ephemeral_spend);
    assert_eq!(confirmed_sent.len(), 2);
    assert_eq!(confirmed_sent[0].len(), 1);
    assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
    let OutputOfSentTx {
        value: ephemeral_v, ..
    } = confirmed_sent[0][0].clone();
    assert_eq!(ephemeral_v, expected_ephemeral_balance);

    assert_eq!(confirmed_sent[1].len(), 1);
    assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &expected_ephemeral_spend && sent_to_addr == &Some(tex_addr));

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
        -ZatBalance::from(expected_ephemeral_balance),
    );

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(ending_balance, Zatoshis::ZERO); // ending balance should be zero
}

pub fn send_with_multiple_change_outputs<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(650_0000);
    let (h, _, _) = st.add_a_single_note_checking_balance(value);

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

    let account = st.test_account().cloned().unwrap();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request.clone(),
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let step = &proposal.steps().head;
    assert_eq!(step.balance().proposed_change().len(), 2);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
            Some(other) => panic!("Unexpected memo value: {other:?}"),
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
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let step = &proposal.steps().head;
    assert_eq!(step.balance().proposed_change().len(), 7);
}

#[cfg(feature = "transparent-inputs")]
pub fn send_multi_step_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
    is_reached_gap_limit: impl Fn(&<Dsf::DataStore as WalletRead>::Error, Dsf::AccountId, u32) -> bool,
) where
    Dsf: DataStoreFactory,
{
    use crate::{
        data_api::{OutputOfSentTx, TransactionStatus},
        wallet::{Exposure, TransparentAddressSource},
    };
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let gap_limits = GapLimits::new(10, 5, 3);
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(gap_limits))
        .build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);
    let tex_addr = Address::Tex([0x4; 20]);

    let add_funds = |st: &mut TestState<_, Dsf::DataStore, _>, value| {
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

    let run_test = |st: &mut TestState<_, Dsf::DataStore, _>, expected_index, prior_balance| {
        // Add funds to the wallet.
        add_funds(st, value);
        let initial_balance: Option<Zatoshis> = prior_balance + value;
        assert_eq!(
            st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
            initial_balance.unwrap()
        );

        let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
        let expected_step1_fee = zip317::MINIMUM_FEE;
        let expected_ephemeral = (transfer_amount + expected_step1_fee).unwrap();
        let expected_step0_change =
            (initial_balance - expected_ephemeral - expected_step0_fee).expect("sufficient funds");
        assert!(expected_step0_change.is_positive());

        let total_sent = (expected_step0_fee + expected_step1_fee + transfer_amount).unwrap();

        // Generate a ZIP 320 proposal, sending to another wallet's default transparent address
        // expressed as a TEX address.
        let change_memo = Some(Memo::from_str("change").expect("valid memo").encode());

        // We use `st.propose_standard_transfer` here in order to also test round-trip
        // serialization of the proposal.
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account_id,
                StandardFeeRule::Zip317,
                ConfirmationsPolicy::MIN,
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

        // There should be no ephemeral addresses exposed at the current chain height
        let exposed_at_tip = st
            .wallet()
            .get_ephemeral_transparent_receivers(account.account().id(), 1, false)
            .unwrap();
        assert_eq!(exposed_at_tip.len(), 0);

        let create_proposed_result = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                account.usk(),
                OvkPolicy::Sender,
                &proposal,
            );
        assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
        let txids = create_proposed_result.unwrap();

        // After creation, there should be a new ephemeral address exposed.
        let exposed_at_tip = st
            .wallet()
            .get_ephemeral_transparent_receivers(account.account().id(), 1, false)
            .unwrap();
        assert_eq!(exposed_at_tip.len(), 1);
        let cur_height = st.wallet().chain_height().unwrap().unwrap();
        assert_matches!(
            exposed_at_tip.values().next().map(|m0| m0.exposure()),
            Some(Exposure::Exposed { at_height, .. }) if at_height == cur_height
        );

        // There should be no unused transparent receivers in this range
        let exposed_at_tip = st
            .wallet()
            .get_ephemeral_transparent_receivers(account.account().id(), 1, true)
            .unwrap();
        assert!(exposed_at_tip.is_empty());

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
            to_addr.map(|addr| (
                addr,
                NonHardenedChildIndex::const_from_index(expected_index)
            )),
        );

        assert_eq!(confirmed_sent[1].len(), 1);
        assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &transfer_amount && sent_to_addr.as_ref() == Some(&tex_addr));

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

        let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
        assert_eq!(initial_balance - total_sent, ending_balance.into());

        (ephemeral_address.unwrap().0, txids, ending_balance)
    };

    // Each transfer should use a different ephemeral address.
    let (ephemeral0, _, bal_0) = run_test(&mut st, 0, Zatoshis::ZERO);
    let (ephemeral1, _, _) = run_test(&mut st, 1, bal_0);
    assert_ne!(ephemeral0, ephemeral1);

    add_funds(&mut st, value);

    assert_matches!(
        ephemeral0,
        Address::Transparent(TransparentAddress::PublicKeyHash(_))
    );

    // Simulate another wallet sending to an ephemeral address with an index
    // within the current gap limit.
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
            meta.source(),
            &TransparentAddressSource::Derived {
                scope: TransparentKeyScope::EPHEMERAL,
                address_index: NonHardenedChildIndex::from_index(i.try_into().unwrap()).unwrap(),
            }
        );
    }

    let (colliding_addr, _) = &known_addrs[usize::try_from(gap_limits.ephemeral() - 1).unwrap()];
    let utxo_value = (value - zip317::MINIMUM_FEE).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
            &Address::from(*colliding_addr),
            utxo_value,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Create the transaction. This will cause the the gap start to move & a new
    // `gap_limits.ephemeral()` of addresses to be created.
    let txids = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();

    // Mine the transaction & update its status to advance the gap. We have to manually update the
    // status because scanning will not detect the transparent outputs.
    let (h, _) = st.generate_next_block_including(txids.head);
    st.scan_cached_blocks(h, 1);
    st.wallet_mut()
        .set_transaction_status(txids.head, TransactionStatus::Mined(h))
        .unwrap();

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

    // check that known_addrs is a prefix of new_known_addrs; we have already checked their
    // lengths.
    assert!(
        new_known_addrs
            .iter()
            .map(|a| a.0)
            .zip(known_addrs.iter().map(|a| a.0))
            .all(|(a, b)| a == b),
        "new_known_addrs must have known_addrs as its prefix"
    );

    let reservation_should_succeed = |st: &mut TestState<_, Dsf::DataStore, _>, n: u32| {
        let reserved = st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n.try_into().unwrap())
            .unwrap();
        assert_eq!(reserved.len(), usize::try_from(n).unwrap());
        reserved
    };
    let reservation_should_fail =
        |st: &mut TestState<_, Dsf::DataStore, _>, n: u32, expected_bad_index| {
            assert_matches!(st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n.try_into().unwrap()),
            Err(e) if is_reached_gap_limit(&e, account_id, expected_bad_index));
        };

    assert_matches!(
        known_addrs[usize::try_from(gap_limits.ephemeral()).unwrap()]
            .1
            .exposure(),
        Exposure::Unknown
    );

    let next_reserved = reservation_should_succeed(&mut st, 1);

    // By reserving the address, its exposure has transitioned from "unknown" to "exposed".
    let gap_position = 0;
    let expected = &known_addrs[usize::try_from(gap_limits.ephemeral()).unwrap()];
    let actual = &next_reserved[usize::try_from(gap_position).unwrap()];
    assert_eq!(actual.0, expected.0);
    assert_eq!(actual.1.source(), expected.1.source());
    assert_eq!(expected.1.exposure(), Exposure::Unknown);
    assert_eq!(
        actual.1.exposure(),
        Exposure::Exposed {
            at_height: st.latest_block_height.unwrap(),
            gap_metadata: crate::wallet::GapMetadata::InGap {
                gap_position,
                gap_limit: gap_limits.ephemeral(),
            }
        }
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
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(60000);
    let (h, _, _) = st.add_a_single_note_checking_balance(value);

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

    let account = st.test_account().cloned().unwrap();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
            Some(other) => panic!("Unexpected memo value: {other:?}"),
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
/// Test attempts to sweep a wallet into a TEX address
///
/// 1. funds wallet with 100000 Zatoshis
/// 2. sets that spend amount will be 75000 Zatoshi
/// 3. proposes a transaction to a TEX address spending 75000 Zatoshi
/// 4. attempts to perform the proposal
/// 5. proposes the transaction
/// 6. "mines" the transaction.
/// 7. checks that all funds have been spent by the two involved transactions
///
/// Desired effects:
/// - all funds are spent
/// - Fees are the least possible: in this case 15000 for tr0 and 10000 Zats for tr1
#[cfg(feature = "transparent-inputs")]
pub fn spend_all_funds_multi_step_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::OutputOfSentTx;
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(75000);

    // Add funds to the wallet.
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    let initial_balance = value;
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral = (transfer_amount + expected_step1_fee).unwrap();
    let expected_step0_change =
        (initial_balance - expected_ephemeral - expected_step0_fee).expect("sufficient funds");
    assert!(expected_step0_change.is_zero());

    let total_sent = (expected_step0_fee + expected_step1_fee + transfer_amount).unwrap();

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);

    let change_memo: Option<MemoBytes> = None;
    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
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

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
        ephemeral_address: _,
    } = confirmed_sent[0][1].clone();
    assert_eq!(ephemeral_v, expected_ephemeral);
    assert!(to_addr.is_some());

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

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(initial_balance - total_sent, ending_balance.into());
}

#[cfg(feature = "transparent-inputs")]
pub fn proposal_fails_if_not_all_ephemeral_outputs_consumed<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    let add_funds = |st: &mut TestState<_, Dsf::DataStore, _>, value| {
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
        assert_eq!(
            st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
            value
        );
    };

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(50000);

    // Add funds to the wallet.
    add_funds(&mut st, value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
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
    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
        proposal.confirmations_policy(),
        NonEmpty::singleton(proposal.steps().first().clone()),
    )
    .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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

pub fn create_to_address_fails_on_incorrect_usk<T: ShieldedPoolTester, Dsf: DataStoreFactory>(
    ds_factory: Dsf,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, ()).build::<T>();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Create a USK that doesn't exist in the wallet
    let acct1 = zip32::AccountId::try_from(1).unwrap();
    let usk1 = UnifiedSpendingKey::from_seed(st.network(), &[1u8; 32], acct1).unwrap();

    let input_selector = GreedyInputSelector::<Dsf::DataStore>::new();
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
            ConfirmationsPolicy::MIN,
        ),
        Err(data_api::error::Error::KeyNotRecognized)
    );
}

pub fn proposal_fails_with_no_blocks<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, ()).build::<T>();

    let account_id = st.test_account().unwrap().id();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // We cannot do anything if we aren't synchronised
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
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
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    st.add_a_single_note_checking_balance(value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(
        st.get_pending_shielded_balance(account_id, ConfirmationsPolicy::default()),
        value
    );
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::default()),
        Zatoshis::ZERO
    );

    // If none of the wallet's accounts have a recover-until height, then there
    // is no recovery phase for the wallet, and therefore the denominator in the
    // resulting ratio (the number of notes in the recovery range) is zero.
    let no_recovery = Some(Ratio::new(0, 0));

    // Wallet is fully scanned
    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN);
    assert_eq!(
        summary.as_ref().and_then(|s| s.progress().recovery()),
        no_recovery,
    );
    assert_eq!(summary.map(|s| s.progress().scan()), Some(Ratio::new(1, 1)));

    // Add more funds to the wallet in a second note
    let (h2, _, _) = st.add_a_single_note_checking_balance(value);

    // Verified balance does not include the second note
    let total = (value + value).unwrap();
    assert_eq!(
        st.get_spendable_balance(
            account_id,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                false
            )
        ),
        value
    );
    assert_eq!(
        st.get_pending_shielded_balance(
            account_id,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                false
            )
        ),
        value
    );
    assert_eq!(st.get_total_balance(account_id), total);

    // Wallet is still fully scanned
    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN);
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
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                false
            ),
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
            ConfirmationsPolicy::default(),
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
        st.get_spendable_balance(account_id, ConfirmationsPolicy::default()),
        (value * 2u64).unwrap()
    );
    assert_eq!(
        st.get_pending_shielded_balance(account_id, ConfirmationsPolicy::default()),
        (value * 9u64).unwrap()
    );

    // Should now be able to generate a proposal
    let amount_sent = Zatoshis::from_u64(70000).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::default(),
            &to,
            amount_sent,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    let txid = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
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

pub fn ovk_policy_prevents_recovery_from_chain<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.add_a_single_note_checking_balance(value);

    let extsk2 = T::sk(&[0xf5; 32]);
    let addr2 = T::sk_default_address(&extsk2);

    let fee_rule = StandardFeeRule::Zip317;

    #[allow(clippy::type_complexity)]
    let send_and_recover_with_policy = |st: &mut TestState<_, Dsf::DataStore, _>,
                                        ovk_policy|
     -> Result<
        Option<(Note, Address, MemoBytes)>,
        TransferErrT<
            Dsf::DataStore,
            GreedyInputSelector<Dsf::DataStore>,
            SingleOutputChangeStrategy<Dsf::DataStore>,
        >,
    > {
        let proposal = st.propose_standard_transfer(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
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
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(70000);
    st.add_a_single_note_checking_balance(value);

    let fee_rule = StandardFeeRule::Zip317;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub fn change_note_spends_succeed<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Add funds to the wallet in a single note owned by the internal spending key
    let value = Zatoshis::const_from_u64(70000);
    st.add_a_single_note_checking_balance(
        TestNoteConfig::from(value).with_address_type(AddressType::Internal),
    );

    // Value is considered pending at 10 confirmations.
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    assert_eq!(
        st.get_pending_shielded_balance(account_id, ConfirmationsPolicy::default()),
        value
    );
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::default()),
        Zatoshis::ZERO
    );

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
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub fn account_deletion<T: ShieldedPoolTester, DSF>(ds_factory: DSF, cache: impl TestCache)
where
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

    // Add funds to the account 0 in a single note
    let value = Zatoshis::from_u64(100000).unwrap();
    let (h, b0_result, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);
    let txid0 = *b0_result
        .txids()
        .first()
        .expect("A transaction was created.");

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account1), value);
    assert_eq!(
        st.get_spendable_balance(account1, ConfirmationsPolicy::MIN),
        value
    );
    assert_eq!(st.get_total_balance(account2), Zatoshis::ZERO);

    let bal_2 = Zatoshis::from_u64(50000).unwrap();
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![
        // payment to an account 2
        Payment::without_memo(addr2.to_zcash_address(st.network()), bal_2),
    ])
    .unwrap();

    let change_strategy = fees::standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let txid1 = st
        .spend(
            &input_selector,
            &change_strategy,
            &usk,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let bal_1 = (value - (bal_2 + MINIMUM_FEE).unwrap()).unwrap();
    assert_eq!(st.get_total_balance(account1), bal_1);

    let (h, _) = st.generate_next_block_including(txid1);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), bal_2);
    assert_eq!(st.get_total_balance(account1), bal_1);

    // txid0 should exist; we haven't enhanced it so we'll have the mined height, but not the raw
    // transaction data.
    assert_matches!(st.wallet_mut().get_tx_height(txid0), Ok(Some(_)));

    // delete account 1
    assert_matches!(st.wallet_mut().delete_account(account1), Ok(_));

    // txid0 should no longer exist in the wallet at all, because it only involved account1
    assert_matches!(st.wallet_mut().get_tx_height(txid0), Ok(None));

    // txid1 should exist in the wallet, as it involves account 2
    assert_matches!(st.wallet_mut().get_transaction(txid1), Ok(Some(_)));

    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .unwrap()
        .unwrap();
    assert!(summary.account_balances().get(&account1).is_none());
    assert_eq!(
        summary.account_balances().get(&account2).unwrap().total(),
        bal_2
    );
    assert_eq!(
        summary
            .account_balances()
            .get(&account2)
            .unwrap()
            .spendable_value(),
        bal_2
    );

    // Create a third account
    let (account3, usk3) = st
        .wallet_mut()
        .create_account("account3", &seed, &birthday, None)
        .unwrap();
    let dfvk3 = T::sk_to_fvk(T::usk_to_sk(&usk3));

    // Creating a new account with the original birthday forces a rescan.
    st.scan_cached_blocks(birthday.height(), 2);

    let bal_3 = Zatoshis::from_u64(20000).unwrap();
    let addr3 = T::fvk_default_address(&dfvk3);
    let req = TransactionRequest::new(vec![
        // payment to an account 3
        Payment::without_memo(addr3.to_zcash_address(st.network()), bal_3),
    ])
    .unwrap();

    let txid2 = st
        .spend(
            &input_selector,
            &change_strategy,
            &usk2,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let bal_2_final = (bal_2 - (bal_3 + MINIMUM_FEE).unwrap()).unwrap();
    assert_eq!(st.get_total_balance(account2), bal_2_final);

    let (h, _) = st.generate_next_block_including(txid2);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), bal_2_final);
    assert_eq!(st.get_total_balance(account3), bal_3);

    // txid2 should exist; we haven't enhanced it so we'll have the mined height, but not the raw
    // transaction data.
    assert_matches!(st.wallet_mut().get_tx_height(txid2), Ok(Some(_)));

    // delete account 3
    assert_matches!(st.wallet_mut().delete_account(account3), Ok(_));

    // txid2 should still exist in the wallet, as it involves account 2
    assert_matches!(st.wallet_mut().get_transaction(txid2), Ok(Some(_)));

    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::default())
        .unwrap()
        .unwrap();
    assert!(summary.account_balances().get(&account3).is_none());
    assert_eq!(
        summary.account_balances().get(&account2).unwrap().total(),
        bal_2_final
    );
}

/// Regression test for a bug in which [`WalletWrite::delete_account`] failed with a
/// `rusqlite::Error::InvalidParameterName(":address")` panic when the account being
/// deleted was referenced by a `sent_notes` row via its `to_account_id` column.
///
/// The triggering state is reached when a transaction is sent from one account in the
/// wallet to an address belonging to a second account in the same wallet, and the
/// transaction is then decrypted via [`decrypt_and_store_transaction`] so that the
/// cross-account transfer is recorded with a non-null `to_account_id` and a received
/// output that has an associated address. Deleting the recipient account then exercises
/// the `sent_notes` update path inside `delete_account`.
///
/// [`WalletWrite::delete_account`]: crate::data_api::WalletWrite::delete_account
pub fn account_deletion_with_internal_transfer<T: ShieldedPoolTester, DSF>(
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

    // Add two accounts to the wallet, derived from the same seed.
    let seed = Secret::new([0u8; 32].to_vec());
    let birthday = AccountBirthday::from_sapling_activation(st.network(), BlockHash([0; 32]));
    let (account1, usk1) = st
        .wallet_mut()
        .create_account("account1", &seed, &birthday, None)
        .unwrap();
    let dfvk1 = T::sk_to_fvk(T::usk_to_sk(&usk1));

    let (account2, usk2) = st
        .wallet_mut()
        .create_account("account2", &seed, &birthday, None)
        .unwrap();
    let dfvk2 = T::sk_to_fvk(T::usk_to_sk(&usk2));

    // Add funds to account 1 in a single note.
    let value = Zatoshis::from_u64(100000).unwrap();
    let (h, _, _) = st.generate_next_block(&dfvk1, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account1), value);
    assert_eq!(st.get_total_balance(account2), Zatoshis::ZERO);

    // Send funds from account 1 to an address belonging to account 2.
    let bal_2 = Zatoshis::from_u64(50000).unwrap();
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![Payment::without_memo(
        addr2.to_zcash_address(st.network()),
        bal_2,
    )])
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
            &usk1,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), bal_2);

    // Decrypt and store the transaction. Because the wallet owns the funding inputs
    // (account 1) and the output is received by account 2, this records the send as an
    // internal cross-account transfer, setting `sent_notes.to_account_id` to account 2
    // and associating the received output with account 2's address. This is the state
    // that triggers the `delete_account` bug.
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), &tx, Some(h)).unwrap();

    // Deleting account 2, the recipient of the internal transfer, must succeed. Prior to
    // the fix this failed with `rusqlite::Error::InvalidParameterName(":address")` because
    // the `sent_notes` update statement bound the wrong parameter name.
    assert_matches!(st.wallet_mut().delete_account(account2), Ok(_));

    // account 1 should still exist and retain its change balance.
    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .unwrap()
        .unwrap();
    assert!(summary.account_balances().get(&account2).is_none());
    assert!(summary.account_balances().contains_key(&account1));
}

pub fn external_address_change_spends_detected_in_restore_from_seed<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::DataStore: Reset,
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
    assert_eq!(
        st.get_spendable_balance(account1, ConfirmationsPolicy::MIN),
        value
    );
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
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let amount_left = (value - (amount_sent + MINIMUM_FEE + MARGINAL_FEE).unwrap()).unwrap();
    let pending_change = (amount_left - amount_legacy_change).unwrap();

    // The "legacy change" is not counted by get_pending_change().
    assert_eq!(
        st.get_pending_change(account1, ConfirmationsPolicy::MIN),
        pending_change
    );
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
pub fn zip317_spend<T: ShieldedPoolTester, Dsf: DataStoreFactory>(
    ds_factory: Dsf,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet
    st.add_notes_checking_balance([Some(Zatoshis::const_from_u64(50000))]);

    // Add 10 uneconomic (dust) notes to the wallet
    for _ in 1..=10 {
        st.add_notes_checking_balance([Some(Zatoshis::const_from_u64(1000))]);
    }

    // Spendable balance matches total balance
    let total = Zatoshis::const_from_u64(60000);
    assert_eq!(st.get_total_balance(account_id), total);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        total
    );

    let input_selector = GreedyInputSelector::<Dsf::DataStore>::new();
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
            ConfirmationsPolicy::MIN,
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
            ConfirmationsPolicy::MIN,
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
pub fn shield_transparent<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use zcash_keys::keys::UnifiedAddressRequest;
    use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

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

    let spent_outpoint = OutPoint::fake();
    let utxo = WalletTransparentOutput::from_parts(
        spent_outpoint.clone(),
        TxOut::new(Zatoshis::const_from_u64(100000), taddr.script().into()),
        Some(h),
        Some(account.id()),
        Some(TransparentKeyScope::EXTERNAL),
        None,
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
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    assert_eq!(txids.len(), 1);

    let tx_summary = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
    assert_eq!(tx_summary.spent_note_count(), 1);
    assert!(tx_summary.has_change());
    assert_eq!(tx_summary.received_note_count(), 0);
    assert_eq!(tx_summary.sent_note_count(), 0);
    assert!(tx_summary.is_shielding());

    // Generate and scan the block including the transaction
    let (h, _) = st.generate_next_block_including(*txids.first());
    let scan_result = st.scan_cached_blocks(h, 1);

    // Ensure that the transaction metadata is still correct after the update produced by scanning.
    let tx_summary = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
    assert_eq!(tx_summary.spent_note_count(), 1);
    assert!(tx_summary.has_change());
    assert_eq!(tx_summary.received_note_count(), 0);
    assert_eq!(tx_summary.sent_note_count(), 0);
    assert!(tx_summary.is_shielding());

    // Verify that a transaction enhancement request for the transaction containing the spent
    // outpoint does not yet exist.
    let requests = st.wallet().transaction_data_requests().unwrap();
    assert!(
        !requests
            .iter()
            .any(|req| req == &TransactionDataRequest::Enhancement(*spent_outpoint.txid()))
    );

    // Use `decrypt_and_store_transaction` for the side effect of creating enhancement requests for
    // the transparent inputs of the transaction.
    let tx = st
        .wallet()
        .get_transaction(*txids.first())
        .unwrap()
        .unwrap();
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), &tx, Some(h)).unwrap();

    // Verify that a transaction enhancement request for the received transaction was created
    let requests = st.wallet().transaction_data_requests().unwrap();
    assert!(
        requests
            .iter()
            .any(|req| req == &TransactionDataRequest::Enhancement(*spent_outpoint.txid()))
    );

    // Now advance the chain by 40 blocks; even though a record for the transaction that created
    // `spent_outpoint` exists in the wallet database, the transaction can't be enhanced because
    // the outpoint was fake. Advancing the chain will cause the request for enhancement to expire.
    for _ in 0..DEFAULT_TX_EXPIRY_DELTA {
        st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(
        scan_result.scanned_range().end,
        usize::try_from(DEFAULT_TX_EXPIRY_DELTA).unwrap(),
    );

    // Simulate the situation where the enhancement request results in `TxidNotRecognized`
    st.wallet_mut()
        .set_transaction_status(
            *spent_outpoint.txid(),
            data_api::TransactionStatus::TxidNotRecognized,
        )
        .unwrap();

    // Verify that the transaction enhancement request for the invalid txid has been deleted.
    let requests = st.wallet().transaction_data_requests().unwrap();
    assert!(
        !requests
            .iter()
            .any(|req| req == &TransactionDataRequest::Enhancement(*spent_outpoint.txid()))
    );
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

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
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
        TargetValue::AtLeast(Zatoshis::const_from_u64(300000)),
        TargetHeight::from(received_tx_height + 10),
        ConfirmationsPolicy::default(),
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
        TargetValue::AtLeast(Zatoshis::const_from_u64(300000)),
        TargetHeight::from(received_tx_height + 10),
        ConfirmationsPolicy::default(),
        &[],
    )
    .unwrap();

    assert_eq!(spendable.len(), 1);
}

pub fn checkpoint_gaps<T: ShieldedPoolTester, Dsf: DataStoreFactory>(
    ds_factory: Dsf,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Generate a block with funds belonging to our wallet.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(500000));

    // Create a gap of 10 blocks having no shielded outputs, then add a block that doesn't
    // belong to us so that we can get a checkpoint in the tree.
    let account = st.test_account().cloned().unwrap();
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let not_our_value = Zatoshis::const_from_u64(10000);
    let sapling_end_size = st.latest_cached_block().unwrap().sapling_end_size();
    let orchard_end_size = st.latest_cached_block().unwrap().orchard_end_size();
    let ironwood_end_size = st.latest_cached_block().unwrap().ironwood_end_size();
    st.generate_block_at(
        account.birthday().height() + 10,
        BlockHash([0; 32]),
        &[FakeCompactOutput::new(
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
        )],
        sapling_end_size,
        orchard_end_size,
        ironwood_end_size,
        false,
    );

    // Scan the block
    st.scan_cached_blocks(account.birthday().height() + 10, 1);

    // Verify that our note is considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account.id(),
        TargetValue::AtLeast(Zatoshis::const_from_u64(300000)),
        TargetHeight::from(account.birthday().height() + 5),
        ConfirmationsPolicy::new_unchecked(
            1,
            5,
            #[cfg(feature = "transparent-inputs")]
            false,
        ),
        &[],
    )
    .unwrap();
    assert_eq!(spendable.len(), 1);

    let input_selector = GreedyInputSelector::<Dsf::DataStore>::new();
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
            ConfirmationsPolicy::new_symmetrical_unchecked(
                5,
                #[cfg(feature = "transparent-inputs")]
                false
            ),
        ),
        Ok(_)
    );
}

/// A wallet-level test for note-commitment-tree *anchor retention*: once NU6.3 (Ironwood) is
/// active, checkpoints on the anchor-retention interval are retained as durable anchors, exempt
/// from the ordinary `PRUNING_DEPTH`-checkpoint pruning budget, so that their roots and the
/// witnesses anchored to them remain computable even after they age far behind the chain tip.
///
/// The retention interval and pruning depth are read from `crate::data_api::ll::wallet`, so this
/// test tracks whatever values the implementation defines rather than assuming a particular one.
///
/// The test:
/// - Activates NU6.3 from the Sapling activation height, so anchor retention is live and its
///   floor equals the account birthday.
/// - Receives a single note early, capturing its note-commitment-tree position.
/// - Scans forward in a single batch until an interval-aligned anchor has aged *more than
///   `PRUNING_DEPTH` checkpoints* behind the chain tip — so it would have been pruned to enforce
///   the checkpoint budget had it not been retained.
/// - Proves survival behaviorally: a witness for the received note *as of that buried anchor* is
///   still constructible (it would be `None` if the anchor checkpoint had been pruned).
/// - Confirms the anchors did not consume the pruning budget: the ordinary checkpoint immediately
///   above the buried anchor *was* pruned, exactly the interval-aligned anchors at/above the floor
///   are retained, and the full `PRUNING_DEPTH` window of checkpoints at the chain tip survives.
pub fn anchor_checkpoints_retained_across_deep_scan<
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
>(
    ds_factory: Dsf,
    cache: impl TestCache,
) {
    use std::collections::BTreeSet;

    use shardtree::{ShardTree, store::ShardStore};

    use crate::data_api::ll::wallet::{ANCHOR_RETENTION_INTERVAL, PRUNING_DEPTH};

    // Reads, from any pool's note commitment tree, the set of surviving checkpoint heights, the
    // set of retained-anchor heights, and whether a witness for `note_position` as of
    // `anchor_height` is still constructible.
    #[allow(clippy::type_complexity)]
    fn tree_anchor_state<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
        tree: &mut ShardTree<S, DEPTH, SHARD_HEIGHT>,
        note_position: Position,
        anchor_height: BlockHeight,
    ) -> Result<(bool, BTreeSet<BlockHeight>, BTreeSet<BlockHeight>), ShardTreeError<S::Error>>
    where
        S: ShardStore<CheckpointId = BlockHeight>,
        S::H: incrementalmerkletree::Hashable + Clone + PartialEq,
    {
        let witness_computable = tree
            .witness_at_checkpoint_id(note_position, &anchor_height)?
            .is_some();
        let retained = tree
            .store()
            .retained_checkpoints()
            .map_err(ShardTreeError::Storage)?;
        let checkpoint_count = tree
            .store()
            .checkpoint_count()
            .map_err(ShardTreeError::Storage)?;
        let mut survivors = BTreeSet::new();
        tree.store()
            .for_each_checkpoint(checkpoint_count, |cid, _| {
                survivors.insert(*cid);
                Ok(())
            })
            .map_err(ShardTreeError::Storage)?;
        Ok((witness_computable, survivors, retained))
    }

    // A network on which NU6.3 (Ironwood) is active from the Sapling activation height, so anchor
    // retention is live with its floor at the account birthday.
    let activation = BlockHeight::from_u32(100_000);
    let ironwood_active_network = LocalNetwork {
        nu6: Some(activation),
        nu6_1: Some(activation),
        nu6_2: Some(activation),
        nu6_3: Some(activation),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    };

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<T>();

    // Receive a single note; its position is captured after it is deeply confirmed, below.
    let (received_height, _, _) =
        st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(500_000));
    let received = u32::from(received_height);
    let floor = u32::from(activation);

    // The first interval-aligned anchor height at or above the retention floor and strictly above
    // the received note, so the note's position precedes the anchor's checkpoint.
    let mut anchor = floor.div_ceil(ANCHOR_RETENTION_INTERVAL) * ANCHOR_RETENTION_INTERVAL;
    while anchor <= received {
        anchor += ANCHOR_RETENTION_INTERVAL;
    }

    // Scan forward in a single batch so the anchor ages more than `PRUNING_DEPTH` checkpoints
    // behind the tip: without retention it would be pruned to enforce the checkpoint budget.
    let tip = anchor + PRUNING_DEPTH + 10;

    // Fillers pay a non-wallet key, so each block still adds a commitment (and thus a checkpoint)
    // without changing the received note's position or the wallet's spendable set.
    let not_our_fvk = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let filler_count = tip - received;
    for _ in 0..filler_count {
        st.generate_next_block(
            &not_our_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10_000),
        );
    }
    st.scan_cached_blocks(received_height + 1, filler_count as usize);

    // Capture the received note's commitment-tree position now that it is deeply confirmed.
    let account_id = st.get_account().id();
    let spendable = T::select_spendable_notes(
        &st,
        account_id,
        TargetValue::AtLeast(Zatoshis::const_from_u64(1)),
        TargetHeight::from(BlockHeight::from(tip + 1)),
        ConfirmationsPolicy::MIN,
        &[],
    )
    .unwrap();
    let note_position = spendable
        .first()
        .expect("the received note is spendable")
        .note_commitment_tree_position();

    let anchor_height = BlockHeight::from(anchor);
    let (witness_computable, survivors, retained) = match T::SHIELDED_PROTOCOL {
        ShieldedPool::Sapling => st
            .wallet_mut()
            .with_sapling_tree_mut(|tree| tree_anchor_state(tree, note_position, anchor_height))
            .unwrap(),
        #[cfg(feature = "orchard")]
        ShieldedPool::Orchard => st
            .wallet_mut()
            .with_orchard_tree_mut(|tree| tree_anchor_state(tree, note_position, anchor_height))
            .unwrap(),
        other => {
            unreachable!("anchor retention test covers only Sapling and Orchard, got {other:?}")
        }
    };

    // The witness for the received note, anchored at the buried anchor, must still be computable —
    // impossible if that checkpoint had been pruned.
    assert!(
        witness_computable,
        "a witness for the received note as of the retained anchor at height {anchor} \
         must still be constructible",
    );

    // Exactly the interval-aligned checkpoints at or above the retention floor are retained.
    let expected_anchors: BTreeSet<BlockHeight> = (floor..=tip)
        .filter(|h| h % ANCHOR_RETENTION_INTERVAL == 0)
        .map(BlockHeight::from)
        .collect();
    assert_eq!(
        retained, expected_anchors,
        "only the interval-aligned anchors at/above the NU6.3 floor should be retained",
    );

    // The buried anchor survives, but the ordinary checkpoint immediately above it was pruned — so
    // its survival is due to retention, not to pruning having failed to run.
    assert!(
        survivors.contains(&anchor_height),
        "the buried anchor checkpoint must survive",
    );
    assert!(
        !survivors.contains(&BlockHeight::from(anchor + 1)),
        "the ordinary checkpoint just above the buried anchor must have been pruned",
    );

    // The anchors did not consume the pruning budget: the full `PRUNING_DEPTH` window of
    // checkpoints at the chain tip is still retained.
    for h in (tip - PRUNING_DEPTH + 1)..=tip {
        assert!(
            survivors.contains(&BlockHeight::from(h)),
            "checkpoint at tip-window height {h} must be retained",
        );
    }
}

#[cfg(feature = "orchard")]
pub fn pool_crossing_required<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    // Here we choose P0, but this has no effect since we supply the viewing keys
    // and generate the blocks directly on the state.
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = note_value;
    assert_eq!(st.get_total_balance(account.id()), initial_balance);
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        initial_balance
    );

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
            ConfirmationsPolicy::MIN,
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
        PoolType::Shielded(std::cmp::max(ShieldedPool::Sapling, ShieldedPool::Orchard))
    );
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub fn fully_funded_fully_private<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

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
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        initial_balance
    );

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
            ConfirmationsPolicy::MIN,
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

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
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
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
pub fn fully_funded_send_to_t<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

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
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        initial_balance
    );

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
            ConfirmationsPolicy::MIN,
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

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    // Since the recipient address is in the same account, the total balance includes the transfer
    // amount.
    assert_eq!(
        st.get_total_balance(account.id()),
        (initial_balance - expected_fee).unwrap()
    );
    // The spendable balance doesn't include the transparent value, so it excludes the transfer
    // amount.
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (initial_balance - transfer_amount - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub fn multi_pool_checkpoint<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

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
    assert_eq!(
        st.get_spendable_balance(acct_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    // Generate several empty blocks
    for _ in 0..10 {
        st.generate_empty_block();
    }

    // Scan into the middle of the empty range
    let scanned = st.scan_cached_blocks(next_to_scan, 5);
    let next_to_scan = scanned.scanned_range().end;

    // The initial balance should be unchanged.
    assert_eq!(st.get_total_balance(acct_id), initial_balance);
    assert_eq!(
        st.get_spendable_balance(acct_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

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
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    st.generate_next_block_including(*res.first());

    let expected_fee = Zatoshis::const_from_u64(10000);
    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    assert_eq!(
        st.get_total_balance(acct_id),
        ((note_value * 2u64).unwrap() + expected_change).unwrap()
    );
    assert_eq!(
        st.get_pending_change(acct_id, ConfirmationsPolicy::MIN),
        expected_change
    );

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
            ConfirmationsPolicy::MIN,
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
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

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
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

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
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

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
        0,
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

pub fn data_db_truncation<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create fake CompactBlocks sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let value2 = Zatoshis::const_from_u64(70000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

    // Scan the cache
    st.scan_cached_blocks(h, 2);

    // Spendable balance should reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (value + value2).unwrap()
    );

    // "Rewind" to height of last scanned block (this is a no-op)
    st.wallet_mut().truncate_to_height(h + 1).unwrap();

    // Spendable balance should be unaltered
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (value + value2).unwrap()
    );

    // Rewind so that one block is dropped
    st.wallet_mut().truncate_to_height(h).unwrap();

    // Spendable balance should only contain the first received note;
    // the rest should be pending.
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        value
    );
    assert_eq!(
        st.get_pending_shielded_balance(account.id(), ConfirmationsPolicy::MIN),
        value2
    );

    // Scan the cache again
    st.scan_cached_blocks(h, 2);

    // Account balance should again reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (value + value2).unwrap()
    );
}

pub fn truncate_to_chain_state<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Test plan:
    // 1. Set up test environment with account
    // 2. Generate and scan initial blocks to populate the note commitment tree
    // 3. Capture the chain state at a specific height
    // 4. Generate and scan blocks beyond PRUNING_DEPTH to ensure early checkpoints are pruned
    // 5. Verify that normal truncate_to_height fails due to missing checkpoints
    // 6. Test that truncate_to_chain_state succeeds using the captured chain state
    // 7. Verify wallet state after truncation

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    // Step 2: Generate and scan initial blocks to populate the note commitment tree.
    // The first block pays the wallet's own account, so the wallet holds a witnessed note
    // below the capture height; without one, a store may satisfy the step-5 truncation by
    // emptying the pool's tree outright (which is tolerated when no witness data would be
    // lost). The remaining blocks use an "other" fvk so that their notes won't be tracked
    // by the wallet (keeping the test focused on tree state rather than wallet balances).
    let account_fvk = T::test_account_fvk(&st);
    let seed = [1u8; 32];
    let other_sk = T::sk(&seed);
    let other_fvk = T::sk_to_fvk(&other_sk);

    let initial_block_count = 8u32;
    st.generate_next_block(
        &account_fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(10000),
    );
    for _ in 1..initial_block_count {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    let scan_start = sapling_activation;
    st.scan_cached_blocks(scan_start, initial_block_count as usize);

    // Step 3: Capture the chain state at the current tip. The CachedBlock tracks the
    // exact frontier that corresponds to the end of each generated block.
    let capture_height = sapling_activation + initial_block_count - 1;
    let captured_chain_state = st
        .latest_cached_block()
        .expect("should have cached blocks")
        .chain_state()
        .clone();
    assert_eq!(captured_chain_state.block_height(), capture_height);

    // Step 4: Generate and scan blocks well beyond PRUNING_DEPTH so that the checkpoint
    // at capture_height is pruned from the note commitment tree.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(capture_height + 1, extra_blocks as usize);

    let tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert!(
        tip >= capture_height + PRUNING_DEPTH,
        "tip should be beyond pruning depth from capture height"
    );

    // Step 5: Verify that truncate_to_height fails at capture_height: the checkpoint there
    // has been pruned, and the wallet holds a witnessed note below that height, so the
    // truncation cannot be satisfied by emptying the tree either.
    let truncation_result = st.wallet_mut().truncate_to_height(capture_height);
    assert!(
        truncation_result.is_err(),
        "truncate_to_height should fail when checkpoint has been pruned"
    );

    // Step 6: truncate_to_chain_state should succeed because it inserts the frontier
    // as a checkpoint before truncating.
    st.wallet_mut()
        .truncate_to_chain_state(captured_chain_state.clone())
        .expect("truncate_to_chain_state should succeed");

    // Step 7: Verify wallet state after truncation.
    // The chain tip should now be at the capture height.
    let new_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after truncation");
    assert_eq!(new_tip, capture_height);

    // The block hash at capture_height should match what was in the captured chain state.
    let hash_at_capture = st
        .wallet()
        .get_block_hash(capture_height)
        .unwrap()
        .expect("block hash should exist at capture height");
    assert_eq!(hash_at_capture, captured_chain_state.block_hash());

    // Blocks above the capture height should have been removed.
    assert_eq!(
        st.wallet().get_block_hash(capture_height + 1).unwrap(),
        None,
        "blocks above capture height should be removed"
    );
}

pub fn truncate_to_chain_state_below_birthday<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Regression test: truncate_to_chain_state should succeed when truncating to a height
    // below the wallet birthday (where no entry exists in the blocks table). Previously,
    // this would fail with RequestedRewindInvalid because select_truncation_height requires
    // the target height to have an entry in the blocks table.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|rng, network| {
            let birthday_height = network.activation_height(NetworkUpgrade::Sapling).unwrap() + 200;

            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(rng, 1u64, NonZeroU8::new(16).unwrap());
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 100, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(rng, 1u64, NonZeroU8::new(16).unwrap());
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 100, root))
                .collect::<Vec<_>>();

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday()
        .build();

    // Generate and scan a few initial blocks from the birthday height.
    let other_fvk = T::random_fvk(st.rng_mut());
    let birthday_height = st.test_account().unwrap().birthday().height();

    for _ in 0..5 {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(birthday_height, 5);

    // Generate and scan blocks well beyond PRUNING_DEPTH to ensure early checkpoints
    // are pruned from the note commitment tree.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(birthday_height + 5, extra_blocks as usize);

    // Get the prior chain state from the account birthday. This chain state is at
    // birthday_height - 1, which has valid tree frontiers but NO entry in the blocks
    // table (since the wallet never scanned a block at that height).
    let prior_chain_state = st
        .test_account()
        .unwrap()
        .birthday()
        .prior_chain_state()
        .clone();

    // This should succeed. On the buggy code, this fails with RequestedRewindInvalid
    // because select_truncation_height cannot find an entry in the blocks table at the
    // target height.
    let _target_height = prior_chain_state.block_height();
    st.wallet_mut()
        .truncate_to_chain_state(prior_chain_state)
        .expect("truncate_to_chain_state below birthday should succeed");

    // All blocks were above the target height, so they should have been removed.
    assert_eq!(
        st.wallet().get_block_hash(birthday_height).unwrap(),
        None,
        "blocks at birthday height should be removed after truncating below birthday"
    );
}

pub fn truncate_to_chain_state_above_scanned<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Regression test: when truncate_to_chain_state is called with a target height above
    // the max scanned height, the frontier insertion must be skipped (it would introduce
    // a subtree root discontinuity) but the scan queue must still be trimmed. Without the
    // fix, inserting a frontier in shard 2 when the wallet only has shard 0 fails because
    // shard 1's subtree root is unknown.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let birthday_height = st.test_account().unwrap().birthday().height();

    // Generate and scan initial blocks, then scan beyond PRUNING_DEPTH to ensure
    // early checkpoints are pruned.
    let other_fvk = T::random_fvk(st.rng_mut());
    let initial_blocks = 5u32;
    for _ in 0..initial_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(birthday_height, initial_blocks as usize);

    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(birthday_height + initial_blocks, extra_blocks as usize);
    let max_scanned = birthday_height + initial_blocks + extra_blocks - 1;

    // Simulate downloading subtree roots from the network: add a known subtree root
    // for shard 0 only. This creates a state where shard 0 exists in the shard store
    // but shard 1 does not.
    T::put_subtree_roots(
        &mut st,
        0,
        &[CommitmentTreeRoot::from_parts(
            birthday_height,
            T::empty_tree_leaf(),
        )],
    )
    .unwrap();

    // Extend the scan queue beyond max_scanned.
    let chain_tip = max_scanned + 500;
    st.wallet_mut().update_chain_tip(chain_tip).unwrap();

    // Construct a ChainState above max_scanned with a frontier in shard 2. The wallet
    // has shard 0 (from put_subtree_roots above) but does NOT have shard 1. Inserting a
    // frontier in shard 2 introduces a discontinuity because shard 1's subtree root is
    // unknown.
    let target_height = max_scanned + 50;
    let shard_2_tree_size: u64 = (0x2 << 16) + 2;
    let (_, shard2_sapling_frontier) = Frontier::random_with_prior_subtree_roots(
        st.rng_mut(),
        shard_2_tree_size,
        NonZeroU8::new(16).unwrap(),
    );
    #[cfg(feature = "orchard")]
    let (_, shard2_orchard_frontier) = Frontier::random_with_prior_subtree_roots(
        st.rng_mut(),
        shard_2_tree_size,
        NonZeroU8::new(16).unwrap(),
    );
    // Ironwood is not active at these test heights, so its tree is empty.
    #[cfg(feature = "orchard")]
    let shard2_ironwood_frontier = Frontier::empty();

    let target_chain_state = ChainState::new(
        target_height,
        BlockHash([7; 32]),
        shard2_sapling_frontier,
        #[cfg(feature = "orchard")]
        shard2_orchard_frontier,
        #[cfg(feature = "orchard")]
        shard2_ironwood_frontier,
    );

    // Verify the scan queue extends beyond the target.
    let pre_truncation_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert!(pre_truncation_tip > target_height);

    // Truncate to the target height, which is above max_scanned. With the fix, this
    // skips the frontier insertion (avoiding the discontinuity) and trims the scan queue.
    // Without the fix, this would fail because inserting a frontier in shard 2 requires
    // shard 1's subtree root, which is unknown.
    st.wallet_mut()
        .truncate_to_chain_state(target_chain_state)
        .expect("truncate_to_chain_state above max scanned should succeed");

    // The scan queue should have been trimmed to the target height.
    let post_truncation_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after truncation");
    assert_eq!(
        post_truncation_tip, target_height,
        "scan queue should be trimmed to target height, not extend to the old chain tip"
    );

    // Existing blocks below max_scanned should be preserved.
    assert!(
        st.wallet().get_block_hash(max_scanned).unwrap().is_some(),
        "blocks at max_scanned should be preserved"
    );
}

pub fn rewind_to_chain_state_deep<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Deep-rewind test plan:
    // 1. Set up a birthday-aligned account.
    // 2. Generate and scan initial blocks to populate the note commitment tree.
    // 3. Pick a rewind target well below the future prune floor.
    // 4. Generate and scan more than PRUNING_DEPTH extra blocks so that the checkpoint at the
    //    target is pruned AND the target lies below `tip - PRUNING_DEPTH` (the "deep" branch).
    // 5. Call `rewind_to_chain_state(target)` and verify:
    //    - the scan queue is rewound all the way to `target`;
    //    - blocks, transactions, tx_locator_map entries, and note commitment trees are
    //      only rewound to `tip - (PRUNING_DEPTH - 1)` (the oldest retained checkpoint).

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    // Generate and scan initial blocks using an "other" fvk so notes are not tracked
    // by the wallet.
    let seed = [1u8; 32];
    let other_fvk = T::sk_to_fvk(&T::sk(&seed));

    let initial_block_count = 8u32;
    for _ in 0..initial_block_count {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(sapling_activation, initial_block_count as usize);

    // The rewind target is the tip of the initial range.
    let rewind_target = sapling_activation + initial_block_count - 1;

    // Scan more than PRUNING_DEPTH extra blocks so that the checkpoint at rewind_target is pruned
    // AND rewind_target is below `tip - PRUNING_DEPTH`.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(rewind_target + 1, extra_blocks as usize);

    let pre_rewind_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert!(
        pre_rewind_tip > rewind_target + PRUNING_DEPTH,
        "tip should be strictly beyond pruning depth from the rewind target"
    );

    // Capture the block hash at the prune boundary so we can assert it survives the rewind
    // unchanged (rather than merely that something exists at that height).
    let prune_boundary = pre_rewind_tip - (PRUNING_DEPTH - 1);
    let boundary_hash_before = st
        .wallet()
        .get_block_hash(prune_boundary)
        .unwrap()
        .expect("block at prune boundary should be present before rewind");

    // `rewind_to_chain_state` must succeed at the same target.
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed for a deep target");

    // The chain tip (derived from scan_queue) should still report the pre-rewind tip:
    // `rewind_to_chain_state` overwrites the scan-queue range above the rewind target
    // with a `Historic` rescan range that extends up to the pre-rewind tip.
    let new_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after rewind");
    assert_eq!(new_tip, pre_rewind_tip);

    // A deep rewind preserves block, transaction, tx_locator_map, and note commitment tree
    // data only as far back as the oldest retained checkpoint at `tip - (PRUNING_DEPTH - 1)`.
    // Data at that boundary is kept (so stabilized notes remain spendable); data above it is
    // removed.
    let wallet = st.wallet();
    assert_eq!(
        wallet.get_block_hash(prune_boundary).unwrap(),
        Some(boundary_hash_before),
        "block hash at (tip - (PRUNING_DEPTH - 1)) should be preserved unchanged by a deep rewind"
    );
    assert!(
        wallet.get_block_hash(prune_boundary + 1).unwrap().is_none(),
        "block entries above (tip - (PRUNING_DEPTH - 1)) must be removed by a deep rewind"
    );
    assert!(
        wallet.get_block_hash(pre_rewind_tip).unwrap().is_none(),
        "block entries up to the pre-rewind tip must be removed by a deep rewind"
    );
    assert_eq!(
        wallet
            .block_max_scanned()
            .unwrap()
            .map(|m| m.block_height()),
        Some(prune_boundary),
        "block_max_scanned should equal (tip - (PRUNING_DEPTH - 1)) after a deep rewind"
    );
}

pub fn rewind_to_chain_state_shallow<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Shallow-rewind test plan:
    // 1. Set up a birthday-aligned account.
    // 2. Generate and scan initial blocks to populate the note commitment tree.
    // 3. Pick a rewind target.
    // 4. Generate and scan `PRUNING_DEPTH - 1` extra blocks so that the target sits at
    //    the shallow boundary (`target == tip - (PRUNING_DEPTH - 1)`, exactly the oldest
    //    retained checkpoint).
    // 5. Call `rewind_to_chain_state(target)` and verify all wallet data is rewound to the
    //    target: data at the target is preserved, anything above is removed.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    let seed = [1u8; 32];
    let other_fvk = T::sk_to_fvk(&T::sk(&seed));

    let initial_block_count = 8u32;
    for _ in 0..initial_block_count {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(sapling_activation, initial_block_count as usize);

    let rewind_target = sapling_activation + initial_block_count - 1;

    // Scan `PRUNING_DEPTH - 1` extra blocks so the target sits at the shallow boundary
    // (`target == tip - (PRUNING_DEPTH - 1)`, exactly the oldest retained checkpoint
    // given the tree's `max_checkpoints = PRUNING_DEPTH`).
    let extra_blocks = PRUNING_DEPTH - 1;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(rewind_target + 1, extra_blocks as usize);

    let tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert_eq!(
        tip,
        rewind_target + (PRUNING_DEPTH - 1),
        "tip should be exactly at the shallow boundary from the rewind target"
    );

    let target_hash_before = st
        .wallet()
        .get_block_hash(rewind_target)
        .unwrap()
        .expect("block at the rewind target should be present before rewind");

    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed for a shallow target");

    // The chain tip (derived from scan_queue) should still report the pre-rewind tip:
    // `rewind_to_chain_state` overwrites the scan-queue range above the rewind target with
    // a `Historic` rescan range that extends up to the pre-rewind tip.
    let new_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after rewind");
    assert_eq!(new_tip, tip);

    // A shallow rewind truncates blocks, tx_locator_map, and note commitment trees
    // directly to the rewind target: data at the target is preserved (with the same
    // content it had before), anything above is removed.
    let wallet = st.wallet();
    assert_eq!(
        wallet.get_block_hash(rewind_target).unwrap(),
        Some(target_hash_before),
        "block hash at the rewind target should be preserved unchanged"
    );
    assert!(
        wallet.get_block_hash(rewind_target + 1).unwrap().is_none(),
        "block entries above the rewind target should be removed by a shallow rewind"
    );
    assert_eq!(
        wallet
            .block_max_scanned()
            .unwrap()
            .map(|m| m.block_height()),
        Some(rewind_target),
        "block_max_scanned should equal the rewind target after a shallow rewind"
    );
}

pub fn rewind_after_non_contiguous_scan<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Regression test: after the scan scheduler processes a `ChainTip` range before a
    // lower `Historic` range, `MAX(height) FROM blocks` points into one scanned region
    // while `last_scanned - (PRUNING_DEPTH - 1)` lands inside the unscanned gap between
    // the two regions. `rewind_to_chain_state` must still succeed: an implementation that
    // expected a checkpoint at exactly the PD floor would return `CorruptedData` via
    // `truncate_to_checkpoint`; clamping forward to the lowest checkpoint inside the
    // prune window keeps us aligned with a real checkpoint.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    // Scan is always sequential in cache order, but `scan_cached_blocks` is happy to be
    // invoked on subranges out of order. We pre-generate a contiguous chain of blocks
    // and scan it in two disjoint segments with a gap in between.
    let seed = [1u8; 32];
    let other_fvk = T::sk_to_fvk(&T::sk(&seed));
    let filler_value = Zatoshis::const_from_u64(10_000);

    let low_count: u32 = 10;
    let gap_size: u32 = PRUNING_DEPTH + 5; // must exceed PD so the PD floor lands in the gap
    let high_count: u32 = 10;
    let total_generated = low_count + gap_size + high_count;

    for _ in 0..total_generated {
        st.generate_next_block(&other_fvk, AddressType::DefaultExternal, filler_value);
    }

    let low_start = sapling_activation;
    let low_end_inclusive = low_start + low_count - 1;
    let high_start = low_end_inclusive + gap_size + 1;

    // Scan the low range first (simulating a historic range).
    st.scan_cached_blocks(low_start, low_count as usize);

    // Scan the high range next (simulating a chain-tip range), leaving `gap_size` blocks
    // in the middle unscanned. Because `high_start > low_end_inclusive + PRUNING_DEPTH`,
    // the PD floor after this scan (`high_end_inclusive - (PRUNING_DEPTH - 1)`) lands
    // inside the unscanned gap.
    st.scan_cached_blocks(high_start, high_count as usize);

    let max_scanned_height = st
        .wallet()
        .block_max_scanned()
        .unwrap()
        .map(|m| m.block_height())
        .expect("block_max_scanned should report the high-range tip");
    let high_end_inclusive = high_start + high_count - 1;
    assert_eq!(max_scanned_height, high_end_inclusive);
    let pd_floor = max_scanned_height - (PRUNING_DEPTH - 1);
    assert!(
        pd_floor > low_end_inclusive && pd_floor < high_start,
        "test invariant: PD floor must lie in the unscanned gap (got {pd_floor}, \
         gap is ({low_end_inclusive}, {high_start}))"
    );

    // `rewind_to_chain_state` must return `Ok(_)` rather than `CorruptedData`: clamping
    // forward to the lowest checkpoint inside the window (which sits at `high_start`)
    // keeps us aligned with a real checkpoint.
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(low_end_inclusive, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed across a non-contiguous scan");
}

/// Multiple wallet notes in a stabilized shard remain spendable after a deep
/// `rewind_to_chain_state` moves the scan queue below them.
pub fn stabilized_note_spendable_after_deep_rewind<T, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Test plan:
    // 1. Set up a wallet with an initial chain state whose tree has shard 0 fully
    //    cached and shard 1 one position short of full (frontier at position
    //    `2 * 2^16 - 2 = 131070`). The frontier lives in a partial shard 1 rather
    //    than at a shard boundary; a boundary-aligned frontier would cause
    //    `prior_subtree_roots` to cache shard 1 and then `insert_frontier` would
    //    fail trying to reinstall its leaf into the cached-leaf-form shard.
    // 2. Scan a single block of 65537 outputs. The first output finishes shard 1
    //    (position 131071) and the remaining 65536 outputs fill all of shard 2
    //    (positions 131072..196607). Three of those outputs are wallet-owned and
    //    land at the first, middle, and last slots of shard 2 (tree positions
    //    131072, 163840, and 196607); every other slot is non-wallet filler.
    // 3. Declare shard 2 complete at `note_height` via `put_subtree_roots(2, ...)`
    //    so `mark_stabilized_notes` has the `subtree_end_height` it needs to flip
    //    the shard 2 notes' `witness_stabilized` flag once the pruning floor rises
    //    above the shard.
    // 4. Scan `PRUNING_DEPTH + 10` one-output post-note blocks. They land in shard
    //    3 (positions 196608+), pushing the pruning-floor checkpoint's tree
    //    position into shard 3 so `shardtree::truncate_shards(3)` — invoked by the
    //    upcoming rewind — preserves shard 2 and every row it indexes.
    // 5. Deep-rewind to a height below `note_height` and verify `scan_queue` is
    //    rewound all the way to the target.
    // 6. Before restoring the chain tip: the balance path reads the witness_stabilized
    //    flag directly, so `get_spendable_balance` must return the full
    //    three-note sum; the spend path requires a chain tip for the anchor, so
    //    `propose_transfer` must fail with `ScanRequired`/`InsufficientFunds`.
    // 7. Call `update_chain_tip(pre_rewind_tip)` and re-verify the balance.
    // 8. Build and sign an actual spend — exercising the full note-selection and
    //    witness-construction path — and assert it produces exactly one tx.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    const SHARD_HEIGHT: u32 = 16;
    const SHARD_POSITIONS: u32 = 1 << SHARD_HEIGHT; // 65536

    // Step 1: set up the wallet with shard 0 cached + frontier in a partial shard 1.
    let initial_tree_size: u32 = 2 * SHARD_POSITIONS - 1;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|rng, network| {
            // The birthday is anchored at NU5 + 1000 rather than the more common
            // Sapling-activation baseline because the orchard variant of this test
            // pre-populates an orchard commitment-tree frontier; that requires
            // Orchard to be active at the birthday height, which isn't true at
            // Sapling activation. `+ 1000` is an arbitrary buffer past NU5 so
            // heights like `birthday_height - 500` (see below) stay comfortably
            // within the activated range.
            let birthday_height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 1000;

            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            // Shard 0 is the only complete shard at this tree size.
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday()
        .build();

    let dfvk = T::test_account_fvk(&st);
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let filler_value = Zatoshis::const_from_u64(1000);

    // Step 2: scan a single block whose outputs finish shard 1 and fill all of
    // shard 2. Three wallet outputs at the first, middle, and last slots of
    // shard 2; everything else is non-wallet filler. Distinct wallet-output
    // values keep failures easier to diagnose.
    let note_values = [
        Zatoshis::const_from_u64(100_000),
        Zatoshis::const_from_u64(200_000),
        Zatoshis::const_from_u64(150_000),
    ];
    let total_note_value = note_values.iter().sum::<Option<Zatoshis>>().unwrap();
    // Shard 2 spans tree positions 2 * 2^16 .. 3 * 2^16 - 1 = 131072..196607.
    let note_tree_positions: [u32; 3] = [
        2 * SHARD_POSITIONS,                       // first slot of shard 2
        2 * SHARD_POSITIONS + SHARD_POSITIONS / 2, // middle slot of shard 2
        3 * SHARD_POSITIONS - 1,                   // last slot of shard 2
    ];

    let scan_block_size: u32 = SHARD_POSITIONS + 1; // finish shard 1 + fill shard 2
    let first_scanned_position: u32 = initial_tree_size; // = 131071
    let mut outputs = Vec::with_capacity(scan_block_size as usize);
    let mut next_wallet_ix = 0;
    for offset in 0..scan_block_size {
        let tree_pos = first_scanned_position + offset;
        if next_wallet_ix < note_tree_positions.len()
            && tree_pos == note_tree_positions[next_wallet_ix]
        {
            outputs.push(FakeCompactOutput::new(
                dfvk.clone(),
                AddressType::DefaultExternal,
                note_values[next_wallet_ix],
            ));
            next_wallet_ix += 1;
        } else {
            outputs.push(FakeCompactOutput::new(
                not_our_key.clone(),
                AddressType::DefaultExternal,
                filler_value,
            ));
        }
    }
    let (note_height, _, _) = st.generate_next_block_multi(&outputs);
    st.scan_cached_blocks(note_height, 1);

    // Pick a rewind target well below the wallet's birthday so the rewind
    // drops every initially-seeded scan_queue row — exercising the case where
    // stabilized-shard metadata is the only thing keeping the notes spendable.
    let birthday_height = st
        .wallet()
        .get_wallet_birthday()
        .unwrap()
        .expect("account birthday should be set");
    let rewind_target = birthday_height - 100;

    // Step 3: declare shard 2 complete at `note_height`. We must pass shard 2's
    // actual computed root (not an arbitrary placeholder) because the cap already
    // contains annotations inherited from the initial chain state's frontier, and
    // `put_subtree_roots` refuses to install a conflicting root.
    let shard_2_root = T::shard_root(&mut st, 2).unwrap();
    T::put_subtree_roots(
        &mut st,
        2,
        &[CommitmentTreeRoot::from_parts(note_height, shard_2_root)],
    )
    .unwrap();

    // Step 4: scan more than `PRUNING_DEPTH` blocks past the note-filled block
    // into shard 3, so the rewind's truncation position is in shard 3 and the
    // ensuing `truncate_shards(3)` leaves shard 2 intact.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, filler_value);
    }
    st.scan_cached_blocks(note_height + 1, extra_blocks as usize);

    let account = st.test_account().unwrap().clone();

    // Step 5: deep-rewind to the target. The rewind target is below the account birthday,
    // so the account must be included in the reset set for the birthday to be lowered.
    // `rewind_to_chain_state` overwrites the scan-queue range above the rewind target with
    // a `Historic` rescan range, so the chain tip remains observable as the pre-rewind tip
    // and notes whose `witness_stabilized = 1` flag survives can still be spent.
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::from([account.id()]),
        )
        .expect("rewind_to_chain_state should succeed");

    // Step 6: balance reflects all three stabilized notes, and a spend can be proposed
    // immediately because the chain tip is preserved by the rewind.
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        total_note_value,
        "all stabilized notes should remain spendable after deep rewind"
    );

    // Step 7: build and sign a real spend end-to-end.
    let to_extsk = T::sk(&[0xcc; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let send_value = Zatoshis::const_from_u64(10_000);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        send_value,
    )])
    .unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
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
            ConfirmationsPolicy::MIN,
        )
        .expect("proposal should succeed with stabilized note after deep rewind");
    let txids = st
        .create_proposed_transactions::<std::convert::Infallible, _, std::convert::Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .expect("spend construction should succeed");
    assert_eq!(
        txids.len(),
        1,
        "the spend should produce exactly one transaction"
    );
}

/// Verifies that when a new account is imported into a fully-scanned wallet,
/// the ensuing re-scan discovers the new account's previously-unknown notes
/// and `scan_complete → mark_stabilized_notes` flags them `witness_stabilized`
/// on the fly, so they remain spendable across a subsequent deep
/// `rewind_to_chain_state`.
pub fn newly_discovered_notes_become_stabilized<T, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Test plan:
    //
    // 1. Build a fully-scanned wallet containing account A:
    //    (a) install an initial chain state whose commitment tree has shard 0
    //        cached and a frontier sitting in a partial shard 1 (the same
    //        setup used by `stabilized_note_spendable_after_deep_rewind`);
    //    (b) generate one note-containing block at `birthday_height` that
    //        finishes shard 1 and fills shard 2, with three A-owned outputs
    //        and three outputs for a not-yet-imported account B, non-wallet
    //        filler elsewhere;
    //    (c) generate `PRUNING_DEPTH + 10` filler blocks past the note block
    //        to push the pruning floor past shard 2;
    //    (d) scan the note block, declare shard 2 complete via
    //        `put_subtree_roots`, then scan the filler blocks — the
    //        second-batch `mark_stabilized_notes` call flips A's three notes
    //        to `witness_stabilized = 1`. B's outputs are in the cached
    //        blocks but produce no `*_received_notes` rows because B is not
    //        yet in the wallet.
    // 2. Confirm A's notes are spendable (sanity check on the initial
    //    stabilization).
    // 3. Import account B from the same seed at zip32 index 1, sharing A's
    //    `AccountBirthday`. `add_account` rewrites `scan_queue` to replace
    //    the post-birthday `Scanned` range with `Historic`, forcing a
    //    re-scan.
    // 4. Re-scan the cached blocks from the birthday through the chain tip.
    //    The blocks are now processed against both A and B; three new
    //    `*_received_notes` rows get inserted at B's shard-2 positions.
    //    Confirm both accounts' balances reflect their respective totals.
    // 5. Deep-rewind to well below the birthday. A non-stabilized note
    //    cannot pass the post-rewind scan-state gate in
    //    `select_spendable_notes_matching_value`, so if B's notes remain
    //    spendable after this rewind, they *must* have been flagged
    //    `witness_stabilized` during the re-scan of step 4. Assert that both
    //    A's and B's full totals are spendable.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    const SHARD_HEIGHT: u32 = 16;
    const SHARD_POSITIONS: u32 = 1 << SHARD_HEIGHT; // 65536

    // Matches the hard-coded seed used by
    // `TestBuilder::with_account_having_current_birthday`. Re-using it at
    // zip32 index 1 lets us deterministically derive B's viewing key before
    // B is imported, and guarantees that the later `import_account_hd(index=1)`
    // call recovers the same key (zip32 derivation is deterministic).
    const TEST_SEED: [u8; 32] = [0u8; 32];

    // Step 1a: initial tree state — shard 0 fully cached, frontier at one
    // position short of shard 1's last slot. A boundary-aligned frontier
    // would cause `prior_subtree_roots` to cache shard 1 and then
    // `insert_frontier` would fail trying to reinstall its leaf into the
    // cached-leaf-form shard.
    let initial_tree_size: u32 = 2 * SHARD_POSITIONS - 1;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|rng, network| {
            // The birthday is anchored at NU5 + 1000 rather than the more common
            // Sapling-activation baseline because the orchard variant of this test
            // pre-populates an orchard commitment-tree frontier; that requires
            // Orchard to be active at the birthday height, which isn't true at
            // Sapling activation. `+ 1000` is an arbitrary buffer past NU5 so
            // heights like `birthday_height - 500` (see below) stay comfortably
            // within the activated range.
            let birthday_height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 1000;

            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            // Each prior subtree root is attached to one arbitrary height
            // well before the birthday. 500 is a round buffer past NU5 but
            // strictly below `birthday_height`; the exact value doesn't
            // matter because stabilization only cares about shard *end*
            // heights.
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday()
        .build();

    let dfvk_a = T::test_account_fvk(&st);
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let filler_value = Zatoshis::const_from_u64(1000);

    // Derive account B's viewing key from the same seed at zip32 index 1.
    // This must run before any scanning so the note block below can place
    // B-destined outputs even though B is absent from the wallet.
    let zip32_index_b = zip32::AccountId::ZERO.next().unwrap();
    let usk_b = UnifiedSpendingKey::from_seed(st.network(), &TEST_SEED, zip32_index_b)
        .expect("account B USK derivation from seed should succeed");
    let fvk_b = T::sk_to_fvk(T::usk_to_sk(&usk_b));

    // Step 1b: build the note block. A's three outputs sit at the first,
    // middle, and last slots of shard 2; B's three outputs occupy adjacent
    // (but distinct) slots. Everything else is non-wallet filler.
    let a_positions: [u32; 3] = [
        2 * SHARD_POSITIONS,                       // first slot of shard 2
        2 * SHARD_POSITIONS + SHARD_POSITIONS / 2, // middle slot of shard 2
        3 * SHARD_POSITIONS - 1,                   // last slot of shard 2
    ];
    let b_positions: [u32; 3] = [
        2 * SHARD_POSITIONS + 1,                       // one after A's first
        2 * SHARD_POSITIONS + SHARD_POSITIONS / 2 + 1, // one after A's middle
        3 * SHARD_POSITIONS - 2,                       // one before A's last
    ];
    let a_values = [
        Zatoshis::const_from_u64(100_000),
        Zatoshis::const_from_u64(200_000),
        Zatoshis::const_from_u64(150_000),
    ];
    let b_values = [
        Zatoshis::const_from_u64(70_000),
        Zatoshis::const_from_u64(80_000),
        Zatoshis::const_from_u64(90_000),
    ];
    let total_a = a_values.iter().sum::<Option<Zatoshis>>().unwrap();
    let total_b = b_values.iter().sum::<Option<Zatoshis>>().unwrap();

    // `scan_block_size = SHARD_POSITIONS + 1`: one slot finishes shard 1,
    // the remaining 65 536 fill all of shard 2.
    let scan_block_size: u32 = SHARD_POSITIONS + 1;
    let first_scanned_position: u32 = initial_tree_size;
    let mut outputs = Vec::with_capacity(scan_block_size as usize);
    for offset in 0..scan_block_size {
        let tree_pos = first_scanned_position + offset;
        let output = if let Some(ix) = a_positions.iter().position(|&p| p == tree_pos) {
            FakeCompactOutput::new(dfvk_a.clone(), AddressType::DefaultExternal, a_values[ix])
        } else if let Some(ix) = b_positions.iter().position(|&p| p == tree_pos) {
            FakeCompactOutput::new(fvk_b.clone(), AddressType::DefaultExternal, b_values[ix])
        } else {
            FakeCompactOutput::new(
                not_our_key.clone(),
                AddressType::DefaultExternal,
                filler_value,
            )
        };
        outputs.push(output);
    }
    let (note_height, _, _) = st.generate_next_block_multi(&outputs);

    // Step 1c: filler blocks past the note block, sized to put the pruning
    // floor past shard 2's end height in step 1d.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, filler_value);
    }

    // Step 1d: scan the note block, declare shard 2 complete, scan the
    // filler blocks. The batch ordering mirrors
    // `stabilized_note_spendable_after_deep_rewind`: shard 2's root can
    // only be computed after its leaves are in the wallet's tree, and
    // `put_subtree_roots` must run before the next scan batch so
    // `mark_stabilized_notes` sees shard 2's `subtree_end_height`.
    st.scan_cached_blocks(note_height, 1);
    let shard_2_root = T::shard_root(&mut st, 2).unwrap();
    T::put_subtree_roots(
        &mut st,
        2,
        &[CommitmentTreeRoot::from_parts(note_height, shard_2_root)],
    )
    .unwrap();
    st.scan_cached_blocks(note_height + 1, extra_blocks as usize);

    let account_a = st.test_account().unwrap().clone();

    // Step 2: baseline. A's notes are discovered and stabilized; B's
    // outputs have no corresponding wallet rows (B absent).
    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        total_a,
        "A's three notes must be spendable after the initial scan + stabilization",
    );

    // Step 3: import account B, sharing A's birthday so `add_account`
    // rewrites the post-birthday `Scanned` range to `Historic` (forcing
    // a re-scan).
    let b_birthday = account_a.birthday().clone();
    let seed = Secret::new(TEST_SEED.to_vec());
    let (account_b, _usk_b) = st
        .wallet_mut()
        .import_account_hd("account B", &seed, zip32_index_b, &b_birthday, None)
        .expect("account B import should succeed");

    // Step 4: re-scan every cached block at or after the birthday. The
    // blocks were previously processed only against A; now they're
    // processed against B too, inserting three new `*_received_notes`
    // rows at B's shard-2 positions. After this batch
    // `mark_stabilized_notes` runs and should flip B's new rows to
    // `witness_stabilized = 1`.
    st.scan_cached_blocks(note_height, (1 + extra_blocks) as usize);

    assert_eq!(
        st.get_spendable_balance(account_b.id(), ConfirmationsPolicy::MIN),
        total_b,
        "B's three newly-discovered notes must be spendable after the re-scan",
    );
    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        total_a,
        "A's notes must remain spendable across B's import and re-scan",
    );

    // Step 5: deep-rewind. The rewind target sits well below the wallet's
    // birthday so `scan_queue` is rewound all the way out of any range
    // covering shard 2. Only notes flagged `witness_stabilized = 1` can
    // pass the post-rewind scan-state gate in
    // `select_spendable_notes_matching_value`; any B note that was never
    // stabilized would drop out of the balance here.
    let rewind_target = account_a.birthday().height() - 100;
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::from([account_a.id(), account_b.id()]),
        )
        .expect("rewind_to_chain_state should succeed");

    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        total_a,
        "A's notes must survive the deep rewind, confirming they were and \
         remain witness_stabilized",
    );
    assert_eq!(
        st.get_spendable_balance(account_b.id(), ConfirmationsPolicy::MIN),
        total_b,
        "B's three re-scan-discovered notes must survive the deep rewind, \
         confirming that mark_stabilized_notes fired on the freshly-inserted \
         B rows during the re-scan",
    );
}

pub fn reorg_to_checkpoint<T: ShieldedPoolTester, Dsf, C>(ds_factory: Dsf, cache: C)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
    C: TestCache,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();

    // Create a sequence of blocks to serve as the foundation of our chain state.
    let p0_fvk = T::random_fvk(st.rng_mut());
    let gen_random_block = |st: &mut TestState<C, Dsf::DataStore, LocalNetwork>,
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
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

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
            ConfirmationsPolicy::MIN,
        ),
        Ok(_)
    );
}

pub fn scan_cached_blocks_finds_received_notes<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the cache
    let summary = st.scan_cached_blocks(h1, 1);
    assert_eq!(summary.scanned_range().start, h1);
    assert_eq!(summary.scanned_range().end, h1 + 1);
    assert_eq!(T::received_note_count(&summary), 1);

    // Account balance should reflect the received note
    assert_eq!(st.get_total_balance(account.id()), value);

    // Create a second fake CompactBlock sending more value to the address
    let value2 = Zatoshis::const_from_u64(70000);
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

pub fn scan_cached_blocks_finds_change_notes<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, nf) = st.add_a_single_note_checking_balance(value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = Zatoshis::const_from_u64(20000);
    let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

    // Scan the cache again
    st.scan_cached_blocks(spent_height, 1);

    // Account balance should equal the change
    assert_eq!(
        st.get_total_balance(account.id()),
        (value - value2).unwrap()
    );
}

pub fn scan_cached_blocks_detects_spends_out_of_order<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let (received_height, _, nf) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = Zatoshis::const_from_u64(20000);
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

pub fn metadata_queries_exclude_unwanted_notes<T: ShieldedPoolTester, Dsf, TC>(
    ds_factory: Dsf,
    cache: TC,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
    TC: TestCache,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Create 10 blocks with successively increasing value
    let note_values = (1..=10)
        .map(|i| Zatoshis::const_from_u64(i * 100_0000))
        .collect::<Vec<_>>();
    let h0 = st
        .add_notes_checking_balance(note_values.clone().into_iter().map(Some))
        .first_block_height()
        .unwrap();

    let target_height = TargetHeight::from(h0 + 10);
    let account = st.test_account().cloned().unwrap();
    let test_meta = |st: &TestState<TC, Dsf::DataStore, LocalNetwork>, query, expected_count| {
        let metadata = st
            .wallet()
            .get_account_metadata(account.id(), &query, target_height, &[], false)
            .unwrap();

        assert_eq!(metadata.note_count(T::SHIELDED_PROTOCOL), expected_count);
    };

    test_meta(
        &st,
        NoteFilter::ExceedsMinValue(Zatoshis::const_from_u64(1000_0000)),
        Some(0),
    );
    test_meta(
        &st,
        NoteFilter::ExceedsMinValue(Zatoshis::const_from_u64(500_0000)),
        Some(5),
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
pub fn pczt_single_step<P0: ShieldedPoolTester, P1: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
    pin_expiry_above_target: Option<u32>,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: serde::Serialize + serde::de::DeserializeOwned,
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

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    Frontier::empty(),
                    #[cfg(feature = "orchard")]
                    Frontier::empty(),
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
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
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        note_value
    );

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
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);

    let expiry_height =
        pin_expiry_above_target.map(|delta| BlockHeight::from(min_target_height) + delta);

    if expiry_height.is_some() {
        // This is rejected before transaction building, so the successful call below
        // can reuse the same proposal.
        assert_matches!(
            st.create_pczt_from_proposal::<Infallible, _, Infallible>(
                account.id(),
                OvkPolicy::Sender,
                &proposal0,
                Some(min_target_height.saturating_sub(1)),
            ),
            Err(Error::ExpiryHeightBelowTargetHeight { .. })
        );
    }

    let create_proposed_result = st.create_pczt_from_proposal::<Infallible, _, Infallible>(
        account.id(),
        OvkPolicy::Sender,
        &proposal0,
        expiry_height,
    );
    assert_matches!(&create_proposed_result, Ok(_));
    let pczt_created = create_proposed_result.unwrap();
    let pczt_branch_id =
        consensus::BranchId::try_from(*pczt_created.global().consensus_branch_id())
            .expect("the PCZT carries a valid consensus branch ID");

    // If we don't create proofs or signatures, we will fail to extract a transaction.
    assert_matches!(
        st.extract_and_store_transaction_from_pczt(pczt_created.clone()),
        Err(Error::Pczt(data_api::error::PcztError::Extraction(_)))
    );

    // Add proof generation keys to Sapling spends.
    let pczt_updated = P0::add_proof_generation_keys(pczt_created, account.usk()).unwrap();

    // Create proofs, using the circuit that governs the Orchard pool under the
    // consensus branch the PCZT was created for. (The test network's most recent
    // upgrade is NU5, so this is currently the historical pre-NU6.2 circuit;
    // modernizing the test network fixture is part of the broader Ironwood test
    // coverage work.)
    let sapling_prover = LocalTxProver::bundled();
    let orchard_pk = zcash_primitives::transaction::builder::cached_orchard_proving_key(
        zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
            pczt_branch_id,
            ::orchard::ValuePool::Orchard,
        )
        .expect("the PCZT's consensus branch supports the Orchard pool")
        .circuit_version(),
    );
    let pczt_proven = Prover::new(pczt_updated)
        .create_orchard_proof(orchard_pk)
        .unwrap()
        .create_sapling_proofs(&sapling_prover, &sapling_prover)
        .unwrap()
        .finish();

    // The signer view of a v5 PCZT commits to the same transaction effects. V5
    // anchors are retained, while Orchard effecting fields are compacted using
    // the v2 PCZT encoding. Passing the proof-bearing authoritative copy also
    // exercises redaction of data that the external Signer does not need.
    let original_sighash = Signer::new(pczt_proven.clone()).unwrap().shielded_sighash();
    let original_len = pczt_proven.clone().serialize().unwrap().len();
    let signer_view = redact_pczt_for_signer(&pczt_proven);
    assert_eq!(
        *signer_view.global().tx_version(),
        zcash_protocol::constants::V5_TX_VERSION,
    );
    assert_eq!(
        signer_view.sapling().anchor(),
        pczt_proven.sapling().anchor()
    );
    assert_eq!(
        signer_view.orchard().anchor(),
        pczt_proven.orchard().anchor()
    );
    if !signer_view.orchard().actions().is_empty() {
        assert!(pczt::v1::Pczt::try_from(signer_view.clone()).is_err());
        assert!(
            signer_view
                .orchard()
                .actions()
                .iter()
                .all(|action| action.cv_net().is_none() && action.output().cmx().is_none())
        );
    }

    let signer_view_bytes = signer_view.serialize().unwrap();
    assert!(signer_view_bytes.len() < original_len);
    let signer_view = pczt::Pczt::parse(&signer_view_bytes).unwrap();
    assert_eq!(
        Signer::new(signer_view.clone()).unwrap().shielded_sighash(),
        original_sighash,
    );

    // Apply signatures to the transported signer view, then combine the
    // contribution with the proof-bearing authoritative copy.
    let mut signer = Signer::new(signer_view).unwrap();
    P0::apply_signatures_to_pczt(&mut signer, account.usk()).unwrap();
    let pczt_authorized = Combiner::new(vec![pczt_proven, signer.finish()])
        .combine()
        .unwrap();

    // Now we can extract the transaction.
    let extract_and_store_result = st.extract_and_store_transaction_from_pczt(pczt_authorized);
    assert_matches!(&extract_and_store_result, Ok(_));
    let txid = extract_and_store_result.unwrap();

    if let Some(expiry_height) = expiry_height {
        let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
        assert_eq!(tx.expiry_height(), expiry_height);
    }

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);
}

/// Ensure that wallet recovery recomputes fees.
///
/// Callers must provide an `intervene` function that deletes fee information for the specified
/// txid from the database. This deletion is checked and the test will fail if fee information is
/// not deleted.
#[cfg(feature = "transparent-inputs")]
pub fn wallet_recovery_computes_fees<T: ShieldedPoolTester, DsF: DataStoreFactory>(
    ds_factory: DsF,
    cache: impl TestCache,
    mut intervene: impl FnMut(&mut DsF::DataStore, TxId) -> Result<(), DsF::DsError>,
) {
    use secrecy::ExposeSecret;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let seed = Secret::new(st.test_seed().unwrap().expose_secret().clone());
    let source_account = st.test_account().cloned().unwrap();
    let (dest_account_id, dest_usk) = st
        .wallet_mut()
        .create_account("dest", &seed, source_account.birthday(), None)
        .unwrap();

    let (to, _) = dest_usk.default_transparent_address();

    // Get some funds in the source account
    let note_value = Zatoshis::const_from_u64(350000);
    let _summary = st.add_notes_checking_balance([Some(note_value), Some(note_value)]);

    // Create two transactions sending from the source account to a transparent address in the
    // destination account.
    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);
    let transfer_amount = Zatoshis::const_from_u64(200000);
    let request = TransactionRequest::new(vec![Payment::without_memo(
        Address::from(to).to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let mut send_transparent = || {
        let p0 = st
            .propose_transfer(
                source_account.id(),
                &input_selector,
                &change_strategy,
                request.clone(),
                ConfirmationsPolicy::MIN,
            )
            .unwrap();
        let result0 = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                source_account.usk(),
                OvkPolicy::Sender,
                &p0,
            )
            .unwrap();
        assert_eq!(result0.len(), 1);
        let txid = result0[0];
        let (h, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(h, 1);

        // Make the destination account aware of the received UTXOs
        let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
        let t_bundle = tx.transparent_bundle().unwrap();
        assert_eq!(t_bundle.vout.len(), 1);

        let outpoint = OutPoint::new(*txid.as_ref(), 0);
        let utxo = WalletTransparentOutput::from_parts(
            outpoint,
            t_bundle.vout[0].clone(),
            Some(h),
            Some(dest_account_id),
            Some(TransparentKeyScope::EXTERNAL),
            None,
        )
        .unwrap();
        st.wallet_mut()
            .put_received_transparent_utxo(&utxo)
            .unwrap();

        (txid, h)
    };

    send_transparent();
    let (input_tx_1_txid, input_tx_1_height) = send_transparent();

    assert_eq!(
        st.get_total_balance(dest_account_id),
        (transfer_amount + transfer_amount).unwrap()
    );

    // Shield the funds in the destination account
    let p1 = st
        .propose_shielding(
            &input_selector,
            &change_strategy,
            Zatoshis::const_from_u64(10000),
            &[to],
            dest_account_id,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
    let result1 = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            &dest_usk,
            OvkPolicy::Sender,
            &p1,
        )
        .unwrap();
    assert_eq!(result1.len(), 1);
    let txid = result1[0];
    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // Since our wallet constructed the transaction, we have the fee information;
    // we will need to wipe it out via a backend-level intervention in order to simulate
    // what happens in recovery.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_matches!(shielding_tx.fee_paid, Some(_));
    let created_fee = shielding_tx.fee_paid.unwrap();

    intervene(st.wallet_mut(), txid).unwrap();

    // Verify that the intervention removed the fee information for the transaction.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_matches!(shielding_tx.fee_paid, None);

    // Run `decrypt_and_store_transaction; this should restore the fee, since the wallet has all of
    // the necessary input and output data.
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(h)).unwrap();

    // Verify that the fee information has been restored.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_eq!(shielding_tx.fee_paid, Some(created_fee));

    // Wipe the fee information again; calling `decrypt_and_store_transaction` with the *input* tx
    // should also cause the fees to be restored.
    intervene(st.wallet_mut(), txid).unwrap();

    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_matches!(shielding_tx.fee_paid, None);

    // Run `decrypt_and_store_transaction with one of the inputs; this should also restore the fee,
    // since the wallet has all of the necessary input and output data.
    let tx = st
        .wallet()
        .get_transaction(input_tx_1_txid)
        .unwrap()
        .unwrap();
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(input_tx_1_height)).unwrap();

    // Verify that the fee information has been restored.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_eq!(shielding_tx.fee_paid, Some(created_fee));
}

/// Tests that the wallet correctly reports balance with two notes that are identical
/// other than their note randomness.
pub fn receive_two_notes_with_same_value<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in two identical notes
    let value = Zatoshis::const_from_u64(60000);
    let h = st
        .add_notes_checking_balance([[value, value]])
        .block_height()
        .unwrap();

    // Spendable balance matches total balance.
    let account = st.test_account().cloned().unwrap();
    let total_value = (value + value).unwrap();
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        total_value
    );

    let target_height = (h + 1).into();

    // Both notes are unspent.
    let unspent_notes = T::select_unspent_notes(&st, account.id(), target_height, &[]).unwrap();
    assert_eq!(unspent_notes.len(), 2);
    for note in unspent_notes {
        assert_eq!(T::note_value(note.note()), value);
    }

    // Both notes are spendable with 1 confirmation.
    let spendable_notes = T::select_spendable_notes(
        &st,
        account.id(),
        TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
        target_height,
        ConfirmationsPolicy::MIN,
        &[],
    )
    .unwrap();
    assert_eq!(spendable_notes.len(), 2);
    for note in spendable_notes {
        assert_eq!(T::note_value(note.note()), value);
    }
}

#[cfg(feature = "pczt")]
fn build_transparent_coinbase_tx(
    network: &LocalNetwork,
    target_height: TargetHeight,
    value: Zatoshis,
    recipient: TransparentAddress,
    miner_data: Option<PushValue>,
) -> zcash_primitives::transaction::builder::BuildResult {
    let build_config = BuildConfig::Coinbase { miner_data };
    let mut builder = Builder::new(*network, BlockHeight::from(target_height), build_config);

    // Add transparent output to recipient
    builder.add_transparent_output(&recipient, value).unwrap();

    // Build the transaction (coinbase transactions don't need provers)
    builder
        .build(
            // unused internally
            &TransparentSigningSet::new(),
            // unused internally
            &[],
            // unused internally
            &[],
            OsRng,
            &LocalTxProver::bundled(),
            &LocalTxProver::bundled(),
            // unused internally
            &StandardFeeRule::Zip317,
        )
        .unwrap()
}

#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
/// Tests that immature coinbase outputs are excluded from note selection.
pub fn immature_coinbase_outputs_are_excluded_from_note_selection<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Get the default transparent address
    let (t_addr, _) = st.get_account().usk().default_transparent_address();

    let coinbase_value = Zatoshis::const_from_u64(50000);

    // Get the height where the coinbase tx will be mined
    let coinbase_height = st.sapling_activation_height();

    // Construct the coinbase transaction and mine the block
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(coinbase_height),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);

    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();

    for i in 1..=99 {
        let latest_block_height = st.add_empty_blocks(1);

        // Verify the coinbase UTXO is **not** spendable
        let spendable_utxos = st
            .wallet()
            .get_spendable_transparent_outputs(
                &t_addr,
                TargetHeight::from(h + i),
                ConfirmationsPolicy::default(),
                CoinbaseFilter::AllTransparentOutputs,
                false,
            )
            .unwrap();
        let confirmations = latest_block_height - h;
        assert!(
            spendable_utxos.is_empty(),
            "{i}: Immature coinbase output is spendable at blockheight {latest_block_height} \
            with {confirmations} confirmations \
            (should only be spendable at 100):\n \
            {spendable_utxos:#?}"
        );
    }

    // Add the last block and ensure that the coinbase transaction is spendable
    let latest_height = st.add_empty_blocks(1);
    let confirmations = latest_height - h;
    let target_height = TargetHeight::from(latest_height + 1);
    let spendable_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
            false,
        )
        .unwrap();
    assert!(
        !spendable_utxos.is_empty(),
        "Coinbase output should be spendable at blockheight {latest_height} \
        with {confirmations} confirmations since the coinbase tx was mined (at {h})\n \
        target_height {target_height:?} - coinbase_tx.mined_height {h} = {}",
        u32::from(target_height) - u32::from(h)
    );

    // Verify we can propose shielding the coinbase utxo
    let account = st.get_account().id();
    let _proposal = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
}

#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
/// Tests that `CoinbaseFilter::CoinbaseOnly` excludes non-coinbase outputs and
/// `CoinbaseFilter::NonCoinbaseOnly` excludes coinbase outputs from UTXO selection and
/// shielding proposals, and that `CoinbaseOnly` still allows proposing shielding when only
/// coinbase UTXOs are available.
pub fn coinbase_only_filtering<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use std::collections::BTreeSet;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let account = st.get_account().id();

    // 1. Create a coinbase UTXO (50,000 zats)
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_height = st.sapling_activation_height();
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(coinbase_height),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    // The coinbase transaction has a single transparent output at index 0.
    let coinbase_outpoint = OutPoint::new(coinbase_tx.txid().into(), 0);
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();

    // 2. Create a non-coinbase UTXO (60,000 zats)
    // Inserted via put_received_transparent_utxo, which sets tx_index = NULL.
    // NULL tx_index is treated as non-coinbase by the filter.
    let non_coinbase_value = Zatoshis::const_from_u64(60000);
    let non_coinbase_outpoint = OutPoint::fake();
    let utxo = WalletTransparentOutput::from_parts(
        non_coinbase_outpoint.clone(),
        TxOut::new(non_coinbase_value, t_addr.script().into()),
        Some(h),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // 3. Wait for coinbase maturity (100 confirmations)
    st.add_empty_blocks(100);
    let target_height = TargetHeight::from(h + 101);

    // 4. CoinbaseFilter::All returns both UTXOs
    let all_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
            false,
        )
        .unwrap();
    assert_eq!(
        all_utxos.len(),
        2,
        "Expected both coinbase and non-coinbase UTXOs with CoinbaseFilter::AllTransparentOutputs"
    );
    let all_utxos_value = all_utxos
        .iter()
        .map(|utxo| utxo.value().into_u64())
        .sum::<u64>();
    assert_eq!(
        all_utxos_value,
        coinbase_value.into_u64() + non_coinbase_value.into_u64(),
        "Unexpected total UTXO value when querying for all transparent transactions"
    );

    // 5. CoinbaseFilter::CoinbaseOnly returns only the coinbase UTXO
    let coinbase_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::CoinbaseOnly,
            false,
        )
        .unwrap();
    assert_eq!(
        coinbase_utxos.len(),
        1,
        "Expected only the coinbase UTXO with CoinbaseFilter::CoinbaseOnly"
    );
    assert_eq!(coinbase_utxos[0].value(), coinbase_value);
    assert_eq!(coinbase_utxos[0].outpoint(), &coinbase_outpoint);

    // 5b. CoinbaseFilter::NonCoinbaseOnly returns only the non-coinbase UTXO.
    // The non-coinbase UTXO was inserted with tx_index = NULL, which the filter treats as
    // non-coinbase, so it must be included here.
    let non_coinbase_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::NonCoinbaseOnly,
            false,
        )
        .unwrap();
    assert_eq!(
        non_coinbase_utxos.len(),
        1,
        "Expected only the non-coinbase UTXO with CoinbaseFilter::NonCoinbaseOnly"
    );
    assert_eq!(non_coinbase_utxos[0].value(), non_coinbase_value);
    assert_eq!(non_coinbase_utxos[0].outpoint(), &non_coinbase_outpoint);

    // 6. propose_shielding with CoinbaseOnly includes only the coinbase input
    let proposal = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::CoinbaseOnly,
        )
        .unwrap();
    let coinbase_inputs = proposal.steps().first().transparent_inputs();
    assert_eq!(
        coinbase_inputs.len(),
        1,
        "CoinbaseOnly proposal should contain exactly one transparent input"
    );
    assert_eq!(coinbase_inputs[0].value(), coinbase_value);
    assert_eq!(coinbase_inputs[0].outpoint(), &coinbase_outpoint);

    // 6b. propose_shielding with NonCoinbaseOnly includes only the non-coinbase input
    let proposal_non_coinbase = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::NonCoinbaseOnly,
        )
        .unwrap();
    let non_coinbase_inputs = proposal_non_coinbase.steps().first().transparent_inputs();
    assert_eq!(
        non_coinbase_inputs.len(),
        1,
        "NonCoinbaseOnly proposal should contain exactly one transparent input"
    );
    assert_eq!(non_coinbase_inputs[0].value(), non_coinbase_value);
    assert_eq!(non_coinbase_inputs[0].outpoint(), &non_coinbase_outpoint);

    // 7. propose_shielding with All includes both inputs
    let proposal_all = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
    let all_inputs = proposal_all.steps().first().transparent_inputs();
    assert_eq!(
        all_inputs.len(),
        2,
        "All proposal should contain both transparent inputs"
    );
    // Input ordering is not guaranteed, so compare the set of outpoints.
    let all_outpoints = all_inputs
        .iter()
        .map(|input| input.outpoint().clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        all_outpoints,
        BTreeSet::from([coinbase_outpoint, non_coinbase_outpoint]),
        "All proposal should contain both the coinbase and non-coinbase outpoints"
    );
}

/// Verifies that `propose_shielding_coinbase` with a shielded destination produces
/// a proposal containing a single ZIP-321 payment to the supplied address for the
/// full available value (input total minus fee), with no change.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_succeeds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(100);

    // The destination is a shielded address controlled by a separate spending key
    // (i.e. potentially in a different wallet).
    let to_extsk = T::sk(&[0xab; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address.clone(),
            None,
            None,
        )
        .expect("propose_shielding_coinbase with a shielded destination should succeed");

    let step = proposal.steps().first();
    assert_eq!(
        step.transparent_inputs().len(),
        1,
        "Expected exactly one coinbase transparent input"
    );
    let payments = step.transaction_request().payments();
    assert_eq!(
        payments.len(),
        1,
        "Expected exactly one payment in proposal"
    );
    let (idx, payment) = payments.iter().next().unwrap();
    assert_eq!(*idx, 0);
    assert_eq!(payment.recipient_address(), &to_address);
    assert_eq!(
        step.balance().proposed_change().len(),
        0,
        "Coinbase shielding must produce no change"
    );

    let fee = step.balance().fee_required();
    let payment_amount = payment.amount().expect("payment must have an amount");
    assert_eq!(
        (payment_amount + fee).unwrap(),
        coinbase_value,
        "payment_amount + fee must equal coinbase input value"
    );
}

/// A newly constructed shielding proposal preserves the checkpoint selected by the wallet, even
/// though it spends no shielded notes. A proposal serialized without the confirmations-policy
/// field (as an older library version would have produced) decodes using the default policy and,
/// because it still carries that real anchor, builds. Separately, a shielding step produces a
/// shielded bundle, so a proposal that encodes such a step with the zero anchor sentinel is
/// rejected at the parse boundary.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn proposal_without_confirmations_policy_builds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0xab; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            None,
        )
        .expect("coinbase shielding proposal should succeed");

    // The shielding step keeps the checkpoint selected by input selection.
    let selected_anchor = proposal
        .steps()
        .first()
        .anchor_height()
        .expect("a shielding step must preserve its selected checkpoint");

    let proto = crate::proto::proposal::Proposal::from_standard_proposal(&proposal);
    assert_eq!(
        proto.steps[0].anchor_height,
        u32::from(selected_anchor),
        "a shielding step must serialize its selected checkpoint",
    );

    // The zero anchor is the wire sentinel for "no anchor". A shielding step produces a shielded
    // bundle, so decoding must reject a zero anchor at the parse boundary rather than accepting a
    // step whose dummy spends would commit to no real anchor. (Checked before building below, which
    // spends the input the proposal decodes against.)
    let mut zero_anchor = proto.clone();
    zero_anchor.steps[0].anchor_height = 0;
    assert_matches!(
        zero_anchor.try_into_standard_proposal(&params, st.wallet()),
        Err(crate::proto::ProposalDecodingError::MissingShieldedAnchor)
    );

    // A proposal serialized before the confirmations-policy field existed omits it, so decoding
    // must fall back to the default policy. The real anchor is preserved, so the step still builds.
    let mut without_policy = proto;
    without_policy.confirmations_policy = None;
    let decoded = without_policy
        .try_into_standard_proposal(&params, st.wallet())
        .expect("a proposal without a confirmations policy must decode");
    assert_eq!(
        decoded.confirmations_policy(),
        ConfirmationsPolicy::default(),
        "a missing confirmations policy must decode as the default",
    );
    assert_eq!(
        decoded.steps().first().anchor_height(),
        Some(selected_anchor),
        "decoding must preserve the serialized anchor",
    );

    let usk = st.get_account().usk().clone();
    st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        &usk,
        OvkPolicy::Sender,
        &decoded,
    )
    .expect("a proposal that carries its selected anchor must build");
}

/// Verifies that `propose_shielding_coinbase` rejects a transparent destination
/// with [`ProposalError::ShieldingRequiresShieldedRecipient`].
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_transparent_recipient_rejected<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    st.add_empty_blocks(100);

    let bad_to_address = Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]))
        .to_zcash_address(st.network());

    let result = st.propose_shielding_coinbase(
        &GreedyInputSelector::new(),
        &StandardFeeRule::Zip317,
        Zatoshis::ZERO,
        &[t_addr],
        bad_to_address,
        None,
        None,
    );

    assert_matches!(
        result,
        Err(Error::Proposal(
            ProposalError::ShieldingRequiresShieldedRecipient
        ))
    );
}

/// Verifies that `propose_shielding_coinbase` propagates the supplied `memo`
/// into the resulting payment's memo field.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_with_memo_succeeds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0xcd; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let memo_text = "shielding to external wallet";
    let memo_bytes = MemoBytes::from(memo_text.parse::<Memo>().unwrap());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            Some(memo_bytes.clone()),
            None,
        )
        .expect("propose_shielding_coinbase with memo should succeed");

    let payments = proposal.steps().first().transaction_request().payments();
    let (_, payment) = payments.iter().next().unwrap();
    assert_eq!(payment.memo(), Some(&memo_bytes));
}

/// Verifies that `propose_shielding_coinbase` with `limit = Some(n)` selects at
/// most `n` UTXOs, preferring the highest-value coinbase outputs.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_with_limit_truncates_inputs<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();

    // Mine three coinbase transactions to the same recipient at successive heights,
    // with distinct values so we can verify the highest-value-first selection.
    let values = [
        Zatoshis::const_from_u64(30000),
        Zatoshis::const_from_u64(70000),
        Zatoshis::const_from_u64(50000),
    ];
    let mut first_h = None;
    for v in values {
        let coinbase_height = if let Some(h) = first_h {
            h + values.len() as u32 // arbitrary; only first_h matters for maturity
        } else {
            st.sapling_activation_height()
        };
        let build = build_transparent_coinbase_tx(
            st.network(),
            TargetHeight::from(coinbase_height),
            v,
            t_addr,
            None,
        );
        let tx = build.transaction();
        let (h, _) = st.generate_next_block_from_tx(0, tx);
        st.scan_cached_blocks(h, 1);
        let params = *st.network();
        decrypt_and_store_transaction(&params, st.wallet_mut(), tx, Some(h)).unwrap();
        if first_h.is_none() {
            first_h = Some(h);
        }
    }
    // Mature all three.
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0x55; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            Some(2),
        )
        .expect("propose_shielding_coinbase with limit=Some(2) should succeed");

    let inputs = proposal.steps().first().transparent_inputs();
    assert_eq!(
        inputs.len(),
        2,
        "limit=Some(2) should select exactly 2 inputs"
    );

    // The two highest-value coinbase UTXOs are 70000 and 50000.
    let mut selected_values: Vec<u64> = inputs.iter().map(|i| i.value().into_u64()).collect();
    selected_values.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(selected_values, vec![70000, 50000]);
}

/// Verifies that `propose_shielding_coinbase` with `limit = Some(0)` selects no
/// inputs, returning [`InputSelectorError::InsufficientFunds`].
///
/// [`InputSelectorError::InsufficientFunds`]: crate::data_api::wallet::input_selection::InputSelectorError::InsufficientFunds
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_with_zero_limit_insufficient_funds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0x66; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let shielding_threshold = Zatoshis::const_from_u64(10000);
    let result = st.propose_shielding_coinbase(
        &GreedyInputSelector::new(),
        &StandardFeeRule::Zip317,
        shielding_threshold,
        &[t_addr],
        to_address,
        None,
        Some(0),
    );

    // With no inputs selected, `payment_amount = input_total - fee` underflows
    // (input_total = 0, fee > 0), producing `Error::InsufficientFunds` with
    // `available: 0, required: fee`.
    assert_matches!(result, Err(Error::InsufficientFunds { .. }));
}

/// Regression test for the propose-fee/build-fee mismatch fixed in #2376.
///
/// Both `sapling::builder::BundleType::DEFAULT` and
/// `orchard::builder::BundleType::DEFAULT` pad up to a minimum of 2
/// outputs/actions (`MIN_SHIELDED_OUTPUTS` / `MIN_ACTIONS`). Before the fix,
/// `propose_shielding_coinbase` hardcoded `(1, 0)` / `(0, 1)` when asking the
/// fee rule what fee to charge, so the proposal underestimated the fee by
/// exactly one ZIP-317 marginal unit (5000 zat). The proposal succeeded, but
/// `create_proposed_transactions` then failed at build time with
/// `Insufficient funds for transaction construction; need an additional ZatBalance(5000) zatoshis`.
///
/// This test verifies the propose-and-build round trip succeeds for both
/// Sapling and Orchard destinations (parameterized by `T`).
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_and_build_shielding_coinbase_succeeds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use zcash_protocol::consensus::COINBASE_MATURITY_BLOCKS;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let account = st.get_account();
    let (t_addr, _) = account.usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(COINBASE_MATURITY_BLOCKS as usize);

    // The destination is a shielded address controlled by a separate spending key.
    let to_extsk = T::sk(&[0xcd; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            None,
        )
        .expect("propose_shielding_coinbase should succeed");

    // Prior to #2376 this would fail at build time with `Insufficient funds for transaction
    // construction; need an additional ZatBalance(5000) zatoshis` because the proposal-stage fee
    // was computed assuming N output/action slots but the builder materializes N+1 (after `MIN_*`
    // padding).
    let build_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(
        &build_result,
        Ok(txids) if txids.len() == 1,
        "create_proposed_transactions must succeed for proposal {:?}",
        proposal,
    );
}

/// Verifies that once Ironwood is active, `propose_shielding_coinbase` resolves a destination
/// with an Orchard receiver to the Ironwood pool — the payment is delivered to the Orchard
/// receiver via the Ironwood bundle — and that the proposed transaction builds.
#[cfg(all(feature = "orchard", feature = "pczt", feature = "transparent-inputs"))]
pub fn shielding_coinbase_to_orchard_receiver_delivers_via_ironwood<Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use super::orchard::OrchardPoolTester;
    use zcash_protocol::consensus::COINBASE_MATURITY_BLOCKS;

    // A network on which Ironwood (NU6.3) is active from the Sapling activation height.
    let ironwood_active_network = {
        let activation = BlockHeight::from_u32(100_000);
        LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        }
    };

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();
    let account = st.get_account();
    let (t_addr, _) = account.usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(100000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(COINBASE_MATURITY_BLOCKS as usize);

    // The destination has an Orchard receiver controlled by a separate spending key.
    let to_extsk = OrchardPoolTester::sk(&[0xcd; 32]);
    let to_address =
        OrchardPoolTester::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            None,
        )
        .expect("propose_shielding_coinbase to an Orchard receiver should succeed post-NU6.3");

    // The Orchard-receiver payment is represented as an Ironwood-pool output, matching the
    // bundle the builder will deliver it through; an Orchard-pool payment would violate the
    // Orchard turnstile.
    assert_eq!(
        proposal.steps().head.payment_pools().get(&0),
        Some(&PoolType::IRONWOOD),
    );

    let build_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(
        &build_result,
        Ok(txids) if txids.len() == 1,
        "create_proposed_transactions must succeed for proposal {:?}",
        proposal,
    );
}

/// After NU6.3 activation, a payment to an Orchard receiver must be delivered through the
/// Ironwood pool, which requires a version 6 transaction. Explicitly requesting a version 5
/// transaction — which has no Ironwood bundle — for such a payment must be rejected at proposal
/// time with [`ProposalError::OrchardReceiverRequiresIronwood`], rather than producing a proposal
/// that could only fail later at build time.
#[cfg(feature = "orchard")]
pub fn propose_v5_payment_to_orchard_receiver_is_rejected<Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
{
    use super::orchard::OrchardPoolTester;
    use crate::data_api::wallet::{input_selection::SpendPolicy, propose_transfer};
    use crate::proposal::ProposalError;
    use zcash_primitives::transaction::TxVersion;

    // A network on which Ironwood (NU6.3) is active from the Sapling activation height.
    let ironwood_active_network = {
        let activation = BlockHeight::from_u32(100_000);
        LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        }
    };

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();

    // Fund the wallet with a single spendable Orchard note.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));

    // The destination has an Orchard receiver controlled by a separate spending key.
    let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
    let to = OrchardPoolTester::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10_000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account = st.get_account();
    let network = *st.network();
    let result = propose_transfer::<_, _, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account.id(),
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &SpendPolicy::default(),
        None,
        Some(TxVersion::V5),
    );

    assert_matches!(
        result,
        Err(Error::Proposal(
            ProposalError::OrchardReceiverRequiresIronwood(TxVersion::V5)
        ))
    );
}

/// PCZT construction supports the version 6 transaction format, including its Ironwood bundle.
/// After NU6.3 a payment to an Orchard receiver is delivered through the Ironwood pool, so
/// `create_pczt_from_proposal` realizes such a proposal as a version 6 PCZT that carries a
/// populated Ironwood bundle.
#[cfg(all(feature = "orchard", feature = "pczt"))]
pub fn create_pczt_supports_ironwood_output<Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: serde::Serialize,
{
    use super::orchard::OrchardPoolTester;

    // A network on which NU6.3 — the version 6 transaction format — is active from height 100_000.
    let ironwood_active_network = {
        let activation = BlockHeight::from_u32(100_000);
        LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        }
    };

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();

    // Fund the wallet with a single spendable Orchard note.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));

    // The destination has an Orchard receiver controlled by a separate spending key; post-NU6.3 the
    // payment is routed through the Ironwood pool.
    let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
    let to = OrchardPoolTester::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10_000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account_id = st.get_account().id();
    let proposal = st
        .propose_transfer(
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .expect("proposal construction succeeds; the Orchard-receiver payment routes to Ironwood");

    // The payment routes to the Ironwood pool, so the resulting PCZT must carry an Ironwood bundle.
    assert_eq!(
        proposal.steps().head.payment_pools().get(&0),
        Some(&PoolType::IRONWOOD),
    );

    let pczt = st
        .create_pczt_from_proposal::<Infallible, _, Infallible>(
            account_id,
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .expect("an Ironwood-routed payment builds as a version 6 PCZT");

    // The PCZT is a version 6 transaction carrying a populated Ironwood bundle.
    assert_eq!(
        *pczt.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION,
    );
    assert!(
        !pczt.ironwood().actions().is_empty(),
        "the PCZT carries an Ironwood bundle for the Ironwood-routed payment",
    );

    // The Ironwood output carries the wallet's recipient metadata (the only proprietary field set
    // on Ironwood outputs), confirming the bundle is populated during construction rather than left
    // as an empty shell.
    assert!(
        pczt.ironwood()
            .actions()
            .iter()
            .any(|action| !action.output().proprietary().is_empty()),
        "the Ironwood output carries recipient metadata",
    );

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SpendState {
        has_fvk: bool,
        has_signature: bool,
        has_alpha: bool,
        value: Option<u64>,
    }

    fn spend_states(pczt: pczt::Pczt) -> (Vec<SpendState>, Vec<SpendState>) {
        fn for_bundle(bundle: &orchard::pczt::Bundle) -> Vec<SpendState> {
            bundle
                .actions()
                .iter()
                .map(|action| SpendState {
                    has_fvk: action.spend().fvk().is_some(),
                    has_signature: action.spend().spend_auth_sig().is_some(),
                    has_alpha: action.spend().alpha().is_some(),
                    value: action.spend().value().as_ref().map(|value| value.inner()),
                })
                .collect()
        }

        let mut orchard = vec![];
        let mut ironwood = vec![];
        pczt::roles::verifier::Verifier::new(pczt)
            .with_orchard::<Infallible, _>(|bundle| {
                orchard = for_bundle(bundle);
                Ok(())
            })
            .unwrap()
            .with_ironwood::<Infallible, _>(|bundle| {
                ironwood = for_bundle(bundle);
                Ok(())
            })
            .unwrap();
        (orchard, ironwood)
    }

    let original_sighash = Signer::new(pczt.clone()).unwrap().shielded_sighash();
    let original_spend_states = spend_states(pczt.clone());
    let original_len = pczt.clone().serialize().unwrap().len();
    let signer_view = redact_pczt_for_signer(&pczt);
    let signer_view_bytes = signer_view.serialize().unwrap();
    assert!(signer_view_bytes.len() < original_len);
    let signer_view = pczt::Pczt::parse(&signer_view_bytes).unwrap();
    assert_eq!(spend_states(signer_view.clone()), original_spend_states);

    // The backend metadata belongs to the authoritative wallet copy, not the
    // external Signer.
    assert!(
        signer_view
            .global()
            .proprietary()
            .get("zcash_client_backend:proposal_info")
            .is_none()
    );
    assert!(
        pczt.global()
            .proprietary()
            .contains_key("zcash_client_backend:proposal_info")
    );

    // V6 signatures do not commit to shielded anchors. Orchard action fields
    // that resolve_fields can restore are omitted from the signer view.
    assert!(signer_view.sapling().anchor().is_none());
    assert!(signer_view.orchard().anchor().is_none());
    assert!(signer_view.ironwood().anchor().is_none());

    let assert_redacted_bundle =
        |original: &pczt::orchard::Bundle, redacted: &pczt::orchard::Bundle| {
            assert_eq!(redacted.actions().len(), original.actions().len());
            let mut memo_plaintexts = 0;
            for (redacted, original) in redacted.actions().iter().zip(original.actions()) {
                assert!(redacted.cv_net().is_none());
                assert!(redacted.output().cmx().is_none());
                assert_eq!(redacted.spend().nullifier(), original.spend().nullifier());
                assert_eq!(redacted.spend().rk(), original.spend().rk());
                assert_eq!(
                    redacted.spend().spend_auth_sig(),
                    original.spend().spend_auth_sig()
                );
                assert_eq!(
                    redacted.output().ephemeral_key(),
                    original.output().ephemeral_key()
                );
                assert_eq!(
                    redacted.output().out_ciphertext(),
                    original.output().out_ciphertext()
                );
                assert_eq!(
                    redacted.output().user_address(),
                    original.output().user_address()
                );
                assert!(
                    redacted
                        .output()
                        .proprietary()
                        .get("zcash_client_backend:output_info")
                        .is_none()
                );
                if matches!(
                    redacted.output().enc_ciphertext(),
                    pczt::orchard::EncCiphertext::MemoPlaintext(_)
                ) {
                    memo_plaintexts += 1;
                }
            }
            memo_plaintexts
        };

    let memo_plaintexts = assert_redacted_bundle(pczt.orchard(), signer_view.orchard())
        + assert_redacted_bundle(pczt.ironwood(), signer_view.ironwood());
    assert!(memo_plaintexts > 0);

    let batch_view = redact_pczt_for_batch_signer(&pczt);
    let batch_view_bytes = batch_view.serialize().unwrap();
    assert!(batch_view_bytes.len() < signer_view_bytes.len());
    let batch_view = pczt::Pczt::parse(&batch_view_bytes).unwrap();
    let batch_spend_states = spend_states(batch_view.clone());

    let mut preauthorized_actions = 0;
    let mut unsigned_zero_value_actions = 0;
    for (original_bundle, batch_bundle) in [
        (&original_spend_states.0, &batch_spend_states.0),
        (&original_spend_states.1, &batch_spend_states.1),
    ] {
        assert_eq!(batch_bundle.len(), original_bundle.len());
        for (original, batch) in original_bundle.iter().zip(batch_bundle) {
            assert!(!batch.has_fvk);
            assert!(!batch.has_signature);
            assert_eq!(
                batch.has_alpha,
                original.has_alpha && !original.has_signature
            );

            if original.has_signature {
                preauthorized_actions += 1;
            } else if original.value == Some(0) && original.has_alpha {
                unsigned_zero_value_actions += 1;
            }
        }
    }
    assert!(preauthorized_actions > 0);
    assert!(unsigned_zero_value_actions > 0);

    // Resolving either compact representation restores byte-identical effecting
    // fields and therefore the same shielded signature digest.
    for compact_view in [&signer_view, &batch_view] {
        let mut resolved = (*compact_view).clone();
        resolved.resolve_fields().unwrap();
        for (resolved_bundle, original_bundle) in [
            (resolved.orchard(), pczt.orchard()),
            (resolved.ironwood(), pczt.ironwood()),
        ] {
            for (resolved, original) in resolved_bundle
                .actions()
                .iter()
                .zip(original_bundle.actions())
            {
                assert_eq!(resolved.cv_net(), original.cv_net());
                assert_eq!(resolved.output().cmx(), original.output().cmx());
                assert_eq!(
                    resolved.output().enc_ciphertext(),
                    original.output().enc_ciphertext()
                );
            }
        }
        assert_eq!(
            Signer::new((*compact_view).clone())
                .unwrap()
                .shielded_sighash(),
            original_sighash,
        );
    }

    let signable_indices = |states: &[SpendState]| {
        states
            .iter()
            .enumerate()
            .filter_map(|(index, state)| (!state.has_signature && state.has_alpha).then_some(index))
            .collect::<Vec<_>>()
    };
    let orchard_signable = signable_indices(&original_spend_states.0);
    let ironwood_signable = signable_indices(&original_spend_states.1);
    assert!(
        orchard_signable
            .iter()
            .any(|&index| original_spend_states.0[index].value == Some(0))
    );

    // The transported request contains no existing signatures. The batch Signer
    // contributes signatures for every unsigned action, including the wallet
    // controlled zero value spend, and returns only those new signatures.
    let request = pczt::roles::signer::batch::BatchSignRequest::new(vec![batch_view]);
    let request =
        pczt::roles::signer::batch::BatchSignRequest::parse(&request.serialize().unwrap()).unwrap();
    assert_eq!(request.pczts().len(), 1);
    let transported_view = request.pczts()[0].clone();
    assert_eq!(spend_states(transported_view.clone()), batch_spend_states);

    let usk = st.get_account().usk().clone();
    let ask = orchard::keys::SpendAuthorizingKey::from(OrchardPoolTester::usk_to_sk(&usk));
    let signed_view = pczt::roles::low_level_signer::Signer::new(transported_view)
        .sign_orchard_with::<pczt::roles::low_level_signer::OrchardParseError, _>(|_, bundle, _| {
            for &index in &orchard_signable {
                bundle.actions_mut()[index]
                    .sign(original_sighash, &ask, OsRng)
                    .unwrap();
            }
            Ok(())
        })
        .unwrap()
        .sign_ironwood_with::<pczt::roles::low_level_signer::OrchardParseError, _>(
            |_, bundle, _| {
                for &index in &ironwood_signable {
                    bundle.actions_mut()[index]
                        .sign(original_sighash, &ask, OsRng)
                        .unwrap();
                }
                Ok(())
            },
        )
        .unwrap()
        .finish();

    let signatures = pczt::roles::signer::extract_orchard_spend_auth_signatures(&signed_view);
    let expected_signature_positions = orchard_signable
        .iter()
        .copied()
        .map(|index| (orchard::ValuePool::Orchard, index))
        .chain(
            ironwood_signable
                .iter()
                .copied()
                .map(|index| (orchard::ValuePool::Ironwood, index)),
        )
        .collect::<Vec<_>>();
    let signature_positions = signatures
        .iter()
        .map(|signature| (signature.value_pool(), signature.action_index()))
        .collect::<Vec<_>>();
    assert_eq!(signature_positions, expected_signature_positions);

    let response = pczt::roles::signer::batch::BatchSignResponse::new(vec![signatures]);
    let response =
        pczt::roles::signer::batch::BatchSignResponse::parse(&response.serialize().unwrap())
            .unwrap();
    assert_eq!(response.signatures().len(), 1);

    let mut signer = Signer::new(pczt.clone()).unwrap();
    for signature in &response.signatures()[0] {
        signer
            .apply_orchard_spend_auth_signature(signature)
            .unwrap();
    }
    let authorized = signer.finish();
    assert_eq!(
        authorized.global().proprietary(),
        pczt.global().proprietary()
    );

    let authorized_spend_states = spend_states(authorized.clone());
    for (original_bundle, authorized_bundle) in [
        (&original_spend_states.0, &authorized_spend_states.0),
        (&original_spend_states.1, &authorized_spend_states.1),
    ] {
        for (original, authorized) in original_bundle.iter().zip(authorized_bundle) {
            assert_eq!(authorized.has_fvk, original.has_fvk);
            assert_eq!(authorized.has_alpha, original.has_alpha);
            assert!(authorized.has_signature);
        }
    }
    for (authorized, original) in authorized
        .orchard()
        .actions()
        .iter()
        .zip(pczt.orchard().actions())
        .chain(
            authorized
                .ironwood()
                .actions()
                .iter()
                .zip(pczt.ironwood().actions()),
        )
    {
        if original.spend().spend_auth_sig().is_some() {
            assert_eq!(
                authorized.spend().spend_auth_sig(),
                original.spend().spend_auth_sig()
            );
        }
        assert_eq!(
            authorized.output().proprietary(),
            original.output().proprietary()
        );
    }
}

/// The transaction version requested at proposal time is recorded on the proposal and preserved
/// across serialization, so that transaction building honors it. A proposal serialized without a
/// version request (as older serializers produced) decodes with no requested version and falls
/// back to the target-height version at build time.
#[cfg(feature = "orchard")]
pub fn proposal_records_and_serializes_proposed_version<Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
{
    use super::orchard::OrchardPoolTester;
    use crate::data_api::wallet::{input_selection::SpendPolicy, propose_transfer};
    use zcash_primitives::transaction::TxVersion;

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();

    // Fund the wallet with a single spendable Orchard note.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));

    let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
    let to = OrchardPoolTester::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10_000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account_id = st.get_account().id();
    let network = *st.network();
    // The test network's most recent upgrade is NU5, so version 5 is a valid explicit request.
    let proposal = propose_transfer::<_, _, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &SpendPolicy::default(),
        None,
        Some(TxVersion::V5),
    )
    .expect("proposal construction succeeds");

    // The requested version is recorded on the proposal.
    assert_eq!(proposal.proposed_version(), Some(TxVersion::V5));

    // ... and is preserved across a round-trip through the proposal's serialized (proto) form.
    let proto = crate::proto::proposal::Proposal::from_standard_proposal(&proposal);
    let decoded = proto
        .try_into_standard_proposal(&network, st.wallet())
        .expect("the serialized proposal decodes");
    assert_eq!(decoded.proposed_version(), Some(TxVersion::V5));

    // A proposal serialized without the field (as an older serializer produced) decodes with no
    // requested version.
    let mut legacy_proto = crate::proto::proposal::Proposal::from_standard_proposal(&proposal);
    legacy_proto.proposed_version = None;
    let decoded_legacy = legacy_proto
        .try_into_standard_proposal(&network, st.wallet())
        .expect("a legacy proposal without a requested version must decode");
    assert_eq!(decoded_legacy.proposed_version(), None);
}
