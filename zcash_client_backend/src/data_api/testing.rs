//! Utilities for testing wallets based upon the [`zcash_client_backend::super`] traits.
use assert_matches::assert_matches;
use core::fmt;
use group::ff::Field;
use incrementalmerkletree::{Marking, Retention};
use nonempty::NonEmpty;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use sapling::{
    note_encryption::{sapling_note_encryption, SaplingDomain},
    util::generate_random_rseed,
    zip32::DiversifiableFullViewingKey,
};
use secrecy::{ExposeSecret, Secret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    num::NonZeroU32,
};
use subtle::ConditionallySelectable;
use zcash_keys::address::Address;
use zcash_note_encryption::Domain;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{self, NetworkUpgrade, Parameters as _},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::{ZatBalance, Zatoshis},
};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex};

use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network},
    memo::Memo,
    transaction::{
        components::{amount::NonNegativeAmount, sapling::zip212_enforcement},
        fees::{zip317::FeeError as Zip317FeeError, FeeRule, StandardFeeRule},
        Transaction, TxId,
    },
};

use crate::{
    address::UnifiedAddress,
    fees::{standard, DustOutputPolicy},
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    proposal::Proposal,
    proto::compact_formats::{
        self, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    },
    wallet::{Note, NoteId, OvkPolicy, ReceivedNote, WalletTransparentOutput},
    ShieldedProtocol,
};

#[allow(deprecated)]
use super::{
    chain::{scan_cached_blocks, BlockSource, ChainState, CommitmentTreeRoot, ScanSummary},
    scanning::ScanRange,
    wallet::{
        create_proposed_transactions, create_spend_to_address,
        input_selection::{GreedyInputSelector, GreedyInputSelectorError, InputSelector},
        propose_standard_transfer_to_address, propose_transfer, spend,
    },
    Account, AccountBalance, AccountBirthday, AccountPurpose, AccountSource, BlockMetadata,
    DecryptedTransaction, InputSource, NullifierQuery, ScannedBlock, SeedRelevance,
    SentTransaction, SpendableNotes, TransactionDataRequest, TransactionStatus,
    WalletCommitmentTrees, WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {
    super::wallet::input_selection::ShieldingSelector, crate::wallet::TransparentAddressMetadata,
    std::ops::Range, zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "orchard")]
use {
    super::ORCHARD_SHARD_HEIGHT, crate::proto::compact_formats::CompactOrchardAction,
    group::ff::PrimeField, orchard::tree::MerkleHashOrchard, pasta_curves::pallas,
};

pub struct TransactionSummary<AccountId> {
    account_id: AccountId,
    txid: TxId,
    expiry_height: Option<BlockHeight>,
    mined_height: Option<BlockHeight>,
    account_value_delta: ZatBalance,
    fee_paid: Option<Zatoshis>,
    spent_note_count: usize,
    has_change: bool,
    sent_note_count: usize,
    received_note_count: usize,
    memo_count: usize,
    expired_unmined: bool,
    is_shielding: bool,
}

impl<AccountId> TransactionSummary<AccountId> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        txid: TxId,
        expiry_height: Option<BlockHeight>,
        mined_height: Option<BlockHeight>,
        account_value_delta: ZatBalance,
        fee_paid: Option<Zatoshis>,
        spent_note_count: usize,
        has_change: bool,
        sent_note_count: usize,
        received_note_count: usize,
        memo_count: usize,
        expired_unmined: bool,
        is_shielding: bool,
    ) -> Self {
        Self {
            account_id,
            txid,
            expiry_height,
            mined_height,
            account_value_delta,
            fee_paid,
            spent_note_count,
            has_change,
            sent_note_count,
            received_note_count,
            memo_count,
            expired_unmined,
            is_shielding,
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }

    pub fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }

    pub fn account_value_delta(&self) -> ZatBalance {
        self.account_value_delta
    }

    pub fn fee_paid(&self) -> Option<Zatoshis> {
        self.fee_paid
    }

    pub fn spent_note_count(&self) -> usize {
        self.spent_note_count
    }

    pub fn has_change(&self) -> bool {
        self.has_change
    }

    pub fn sent_note_count(&self) -> usize {
        self.sent_note_count
    }

    pub fn received_note_count(&self) -> usize {
        self.received_note_count
    }

    pub fn expired_unmined(&self) -> bool {
        self.expired_unmined
    }

    pub fn memo_count(&self) -> usize {
        self.memo_count
    }

    pub fn is_shielding(&self) -> bool {
        self.is_shielding
    }
}

#[derive(Clone, Debug)]
pub struct CachedBlock {
    chain_state: ChainState,
    sapling_end_size: u32,
    orchard_end_size: u32,
}

impl CachedBlock {
    pub fn none(sapling_activation_height: BlockHeight) -> Self {
        Self {
            chain_state: ChainState::empty(sapling_activation_height, BlockHash([0; 32])),
            sapling_end_size: 0,
            orchard_end_size: 0,
        }
    }

    pub fn at(chain_state: ChainState, sapling_end_size: u32, orchard_end_size: u32) -> Self {
        assert_eq!(
            chain_state.final_sapling_tree().tree_size() as u32,
            sapling_end_size
        );
        #[cfg(feature = "orchard")]
        assert_eq!(
            chain_state.final_orchard_tree().tree_size() as u32,
            orchard_end_size
        );

        Self {
            chain_state,
            sapling_end_size,
            orchard_end_size,
        }
    }

    fn roll_forward(&self, cb: &CompactBlock) -> Self {
        assert_eq!(self.chain_state.block_height() + 1, cb.height());

        let sapling_final_tree = cb.vtx.iter().flat_map(|tx| tx.outputs.iter()).fold(
            self.chain_state.final_sapling_tree().clone(),
            |mut acc, c_out| {
                acc.append(sapling::Node::from_cmu(&c_out.cmu().unwrap()));
                acc
            },
        );
        let sapling_end_size = sapling_final_tree.tree_size() as u32;

        #[cfg(feature = "orchard")]
        let orchard_final_tree = cb.vtx.iter().flat_map(|tx| tx.actions.iter()).fold(
            self.chain_state.final_orchard_tree().clone(),
            |mut acc, c_act| {
                acc.append(MerkleHashOrchard::from_cmx(&c_act.cmx().unwrap()));
                acc
            },
        );
        #[cfg(feature = "orchard")]
        let orchard_end_size = orchard_final_tree.tree_size() as u32;
        #[cfg(not(feature = "orchard"))]
        let orchard_end_size = cb.vtx.iter().fold(self.orchard_end_size, |sz, tx| {
            sz + (tx.actions.len() as u32)
        });

        Self {
            chain_state: ChainState::new(
                cb.height(),
                cb.hash(),
                sapling_final_tree,
                #[cfg(feature = "orchard")]
                orchard_final_tree,
            ),
            sapling_end_size,
            orchard_end_size,
        }
    }

    pub fn height(&self) -> BlockHeight {
        self.chain_state.block_height()
    }

    pub fn sapling_end_size(&self) -> u32 {
        self.sapling_end_size
    }

    pub fn orchard_end_size(&self) -> u32 {
        self.orchard_end_size
    }
}

#[derive(Clone)]
pub struct TestAccount<A> {
    account: A,
    usk: UnifiedSpendingKey,
    birthday: AccountBirthday,
}

impl<A> TestAccount<A> {
    pub fn account(&self) -> &A {
        &self.account
    }

    pub fn usk(&self) -> &UnifiedSpendingKey {
        &self.usk
    }

    pub fn birthday(&self) -> &AccountBirthday {
        &self.birthday
    }
}

impl<A: Account> Account for TestAccount<A> {
    type AccountId = A::AccountId;

    fn id(&self) -> Self::AccountId {
        self.account.id()
    }

    fn source(&self) -> AccountSource {
        self.account.source()
    }

    fn ufvk(&self) -> Option<&zcash_keys::keys::UnifiedFullViewingKey> {
        self.account.ufvk()
    }

    fn uivk(&self) -> zcash_keys::keys::UnifiedIncomingViewingKey {
        self.account.uivk()
    }
}

pub trait Reset: WalletRead + Sized {
    type Handle;

    fn reset<C>(st: &mut TestState<C, Self, LocalNetwork>) -> Self::Handle;
}

/// The state for a `zcash_client_sqlite` test.
pub struct TestState<Cache, DataStore: WalletRead, Network> {
    cache: Cache,
    cached_blocks: BTreeMap<BlockHeight, CachedBlock>,
    latest_block_height: Option<BlockHeight>,
    wallet_data: DataStore,
    network: Network,
    test_account: Option<(SecretVec<u8>, TestAccount<DataStore::Account>)>,
    rng: ChaChaRng,
}

impl<Cache, DataStore: WalletRead, Network> TestState<Cache, DataStore, Network> {
    /// Exposes an immutable reference to the test's `DataStore`.
    pub fn wallet(&self) -> &DataStore {
        &self.wallet_data
    }

    /// Exposes a mutable reference to the test's `DataStore`.
    pub fn wallet_mut(&mut self) -> &mut DataStore {
        &mut self.wallet_data
    }

    /// Exposes the test framework's source of randomness.
    pub fn rng_mut(&mut self) -> &mut ChaChaRng {
        &mut self.rng
    }

    /// Exposes the network in use.
    pub fn network(&self) -> &Network {
        &self.network
    }
}

impl<Cache, DataStore: WalletRead, Network: consensus::Parameters>
    TestState<Cache, DataStore, Network>
{
    /// Convenience method for obtaining the Sapling activation height for the network under test.
    pub fn sapling_activation_height(&self) -> BlockHeight {
        self.network
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height must be known.")
    }

    /// Convenience method for obtaining the NU5 activation height for the network under test.
    #[allow(dead_code)]
    pub fn nu5_activation_height(&self) -> BlockHeight {
        self.network
            .activation_height(NetworkUpgrade::Nu5)
            .expect("NU5 activation height must be known.")
    }

    /// Exposes the test seed, if enabled via [`TestBuilder::with_test_account`].
    pub fn test_seed(&self) -> Option<&SecretVec<u8>> {
        self.test_account.as_ref().map(|(seed, _)| seed)
    }
}

impl<Cache, DataStore, Network> TestState<Cache, DataStore, Network>
where
    Network: consensus::Parameters,
    DataStore: WalletRead,
{
    /// Exposes the test account, if enabled via [`TestBuilder::with_test_account`].
    pub fn test_account(&self) -> Option<&TestAccount<<DataStore as WalletRead>::Account>> {
        self.test_account.as_ref().map(|(_, acct)| acct)
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    pub fn test_account_sapling(&self) -> Option<&DiversifiableFullViewingKey> {
        let (_, acct) = self.test_account.as_ref()?;
        let ufvk = acct.ufvk()?;
        ufvk.sapling()
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    #[cfg(feature = "orchard")]
    pub fn test_account_orchard(&self) -> Option<&orchard::keys::FullViewingKey> {
        let (_, acct) = self.test_account.as_ref()?;
        let ufvk = acct.ufvk()?;
        ufvk.orchard()
    }
}

impl<Cache: TestCache, DataStore, Network> TestState<Cache, DataStore, Network>
where
    Network: consensus::Parameters,
    DataStore: WalletWrite,
    <Cache::BlockSource as BlockSource>::Error: fmt::Debug,
{
    /// Exposes an immutable reference to the test's [`BlockSource`].
    #[cfg(feature = "unstable")]
    pub fn cache(&self) -> &Cache::BlockSource {
        self.cache.block_source()
    }

    pub fn latest_cached_block(&self) -> Option<&CachedBlock> {
        self.latest_block_height
            .as_ref()
            .and_then(|h| self.cached_blocks.get(h))
    }

    fn latest_cached_block_below_height(&self, height: BlockHeight) -> Option<&CachedBlock> {
        self.cached_blocks.range(..height).last().map(|(_, b)| b)
    }

    fn cache_block(
        &mut self,
        prev_block: &CachedBlock,
        compact_block: CompactBlock,
    ) -> Cache::InsertResult {
        self.cached_blocks.insert(
            compact_block.height(),
            prev_block.roll_forward(&compact_block),
        );
        self.cache.insert(&compact_block)
    }
    /// Creates a fake block at the expected next height containing a single output of the
    /// given value, and inserts it into the cache.
    pub fn generate_next_block<Fvk: TestFvk>(
        &mut self,
        fvk: &Fvk,
        address_type: AddressType,
        value: NonNegativeAmount,
    ) -> (BlockHeight, Cache::InsertResult, Fvk::Nullifier) {
        let pre_activation_block = CachedBlock::none(self.sapling_activation_height() - 1);
        let prior_cached_block = self.latest_cached_block().unwrap_or(&pre_activation_block);
        let height = prior_cached_block.height() + 1;

        let (res, nfs) = self.generate_block_at(
            height,
            prior_cached_block.chain_state.block_hash(),
            &[FakeCompactOutput::new(fvk, address_type, value)],
            prior_cached_block.sapling_end_size,
            prior_cached_block.orchard_end_size,
            false,
        );

        (height, res, nfs[0])
    }

    /// Creates a fake block at the expected next height containing multiple outputs
    /// and inserts it into the cache.
    #[allow(dead_code)]
    pub fn generate_next_block_multi<Fvk: TestFvk>(
        &mut self,
        outputs: &[FakeCompactOutput<Fvk>],
    ) -> (BlockHeight, Cache::InsertResult, Vec<Fvk::Nullifier>) {
        let pre_activation_block = CachedBlock::none(self.sapling_activation_height() - 1);
        let prior_cached_block = self.latest_cached_block().unwrap_or(&pre_activation_block);
        let height = prior_cached_block.height() + 1;

        let (res, nfs) = self.generate_block_at(
            height,
            prior_cached_block.chain_state.block_hash(),
            outputs,
            prior_cached_block.sapling_end_size,
            prior_cached_block.orchard_end_size,
            false,
        );

        (height, res, nfs)
    }

    /// Adds an empty block to the cache, advancing the simulated chain height.
    #[allow(dead_code)] // used only for tests that are flagged off by default
    pub fn generate_empty_block(&mut self) -> (BlockHeight, Cache::InsertResult) {
        let new_hash = {
            let mut hash = vec![0; 32];
            self.rng.fill_bytes(&mut hash);
            hash
        };

        let pre_activation_block = CachedBlock::none(self.sapling_activation_height() - 1);
        let prior_cached_block = self
            .latest_cached_block()
            .unwrap_or(&pre_activation_block)
            .clone();
        let new_height = prior_cached_block.height() + 1;

        let mut cb = CompactBlock {
            hash: new_hash,
            height: new_height.into(),
            ..Default::default()
        };
        cb.prev_hash
            .extend_from_slice(&prior_cached_block.chain_state.block_hash().0);

        cb.chain_metadata = Some(compact_formats::ChainMetadata {
            sapling_commitment_tree_size: prior_cached_block.sapling_end_size,
            orchard_commitment_tree_size: prior_cached_block.orchard_end_size,
        });

        let res = self.cache_block(&prior_cached_block, cb);
        self.latest_block_height = Some(new_height);

        (new_height, res)
    }

    /// Creates a fake block with the given height and hash containing the requested outputs, and
    /// inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] will build on it.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_block_at<Fvk: TestFvk>(
        &mut self,
        height: BlockHeight,
        prev_hash: BlockHash,
        outputs: &[FakeCompactOutput<Fvk>],
        initial_sapling_tree_size: u32,
        initial_orchard_tree_size: u32,
        allow_broken_hash_chain: bool,
    ) -> (Cache::InsertResult, Vec<Fvk::Nullifier>) {
        let mut prior_cached_block = self
            .latest_cached_block_below_height(height)
            .cloned()
            .unwrap_or_else(|| CachedBlock::none(self.sapling_activation_height() - 1));
        assert!(prior_cached_block.chain_state.block_height() < height);
        assert!(prior_cached_block.sapling_end_size <= initial_sapling_tree_size);
        assert!(prior_cached_block.orchard_end_size <= initial_orchard_tree_size);

        // If the block height has increased or the Sapling and/or Orchard tree sizes have changed,
        // we need to generate a new prior cached block that the block to be generated can
        // successfully chain from, with the provided tree sizes.
        if prior_cached_block.chain_state.block_height() == height - 1 {
            if !allow_broken_hash_chain {
                assert_eq!(prev_hash, prior_cached_block.chain_state.block_hash());
            }
        } else {
            let final_sapling_tree =
                (prior_cached_block.sapling_end_size..initial_sapling_tree_size).fold(
                    prior_cached_block.chain_state.final_sapling_tree().clone(),
                    |mut acc, _| {
                        acc.append(sapling::Node::from_scalar(bls12_381::Scalar::random(
                            &mut self.rng,
                        )));
                        acc
                    },
                );

            #[cfg(feature = "orchard")]
            let final_orchard_tree =
                (prior_cached_block.orchard_end_size..initial_orchard_tree_size).fold(
                    prior_cached_block.chain_state.final_orchard_tree().clone(),
                    |mut acc, _| {
                        acc.append(MerkleHashOrchard::random(&mut self.rng));
                        acc
                    },
                );

            prior_cached_block = CachedBlock::at(
                ChainState::new(
                    height - 1,
                    prev_hash,
                    final_sapling_tree,
                    #[cfg(feature = "orchard")]
                    final_orchard_tree,
                ),
                initial_sapling_tree_size,
                initial_orchard_tree_size,
            );

            self.cached_blocks
                .insert(height - 1, prior_cached_block.clone());
        }

        let (cb, nfs) = fake_compact_block(
            &self.network,
            height,
            prev_hash,
            outputs,
            initial_sapling_tree_size,
            initial_orchard_tree_size,
            &mut self.rng,
        );
        assert_eq!(cb.height(), height);

        let res = self.cache_block(&prior_cached_block, cb);
        self.latest_block_height = Some(height);

        (res, nfs)
    }

    /// Creates a fake block at the expected next height spending the given note, and
    /// inserts it into the cache.
    pub fn generate_next_block_spending<Fvk: TestFvk>(
        &mut self,
        fvk: &Fvk,
        note: (Fvk::Nullifier, NonNegativeAmount),
        to: impl Into<Address>,
        value: NonNegativeAmount,
    ) -> (BlockHeight, Cache::InsertResult) {
        let prior_cached_block = self
            .latest_cached_block()
            .cloned()
            .unwrap_or_else(|| CachedBlock::none(self.sapling_activation_height() - 1));
        let height = prior_cached_block.height() + 1;

        let cb = fake_compact_block_spending(
            &self.network,
            height,
            prior_cached_block.chain_state.block_hash(),
            note,
            fvk,
            to.into(),
            value,
            prior_cached_block.sapling_end_size,
            prior_cached_block.orchard_end_size,
            &mut self.rng,
        );
        assert_eq!(cb.height(), height);

        let res = self.cache_block(&prior_cached_block, cb);
        self.latest_block_height = Some(height);

        (height, res)
    }

    /// Creates a fake block at the expected next height containing only the wallet
    /// transaction with the given txid, and inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] (or similar) will build on it.
    pub fn generate_next_block_including(
        &mut self,
        txid: TxId,
    ) -> (BlockHeight, Cache::InsertResult) {
        let tx = self
            .wallet()
            .get_transaction(txid)
            .unwrap()
            .expect("TxId should exist in the wallet");

        // Index 0 is by definition a coinbase transaction, and the wallet doesn't
        // construct coinbase transactions. So we pretend here that the block has a
        // coinbase transaction that does not have shielded coinbase outputs.
        self.generate_next_block_from_tx(1, &tx)
    }

    /// Creates a fake block at the expected next height containing only the given
    /// transaction, and inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] will build on it.
    pub fn generate_next_block_from_tx(
        &mut self,
        tx_index: usize,
        tx: &Transaction,
    ) -> (BlockHeight, Cache::InsertResult) {
        let prior_cached_block = self
            .latest_cached_block()
            .cloned()
            .unwrap_or_else(|| CachedBlock::none(self.sapling_activation_height() - 1));
        let height = prior_cached_block.height() + 1;

        let cb = fake_compact_block_from_tx(
            height,
            prior_cached_block.chain_state.block_hash(),
            tx_index,
            tx,
            prior_cached_block.sapling_end_size,
            prior_cached_block.orchard_end_size,
            &mut self.rng,
        );
        assert_eq!(cb.height(), height);

        let res = self.cache_block(&prior_cached_block, cb);
        self.latest_block_height = Some(height);

        (height, res)
    }
}

impl<Cache, DbT, ParamsT> TestState<Cache, DbT, ParamsT>
where
    Cache: TestCache,
    <Cache::BlockSource as BlockSource>::Error: fmt::Debug,
    ParamsT: consensus::Parameters + Send + 'static,
    DbT: InputSource + WalletWrite + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
{
    /// Invokes [`scan_cached_blocks`] with the given arguments, expecting success.
    pub fn scan_cached_blocks(&mut self, from_height: BlockHeight, limit: usize) -> ScanSummary {
        let result = self.try_scan_cached_blocks(from_height, limit);
        assert_matches!(result, Ok(_));
        result.unwrap()
    }

    /// Invokes [`scan_cached_blocks`] with the given arguments.
    pub fn try_scan_cached_blocks(
        &mut self,
        from_height: BlockHeight,
        limit: usize,
    ) -> Result<
        ScanSummary,
        super::chain::error::Error<
            <DbT as WalletRead>::Error,
            <Cache::BlockSource as BlockSource>::Error,
        >,
    > {
        let prior_cached_block = self
            .latest_cached_block_below_height(from_height)
            .cloned()
            .unwrap_or_else(|| CachedBlock::none(from_height - 1));

        let result = scan_cached_blocks(
            &self.network,
            self.cache.block_source(),
            &mut self.wallet_data,
            from_height,
            &prior_cached_block.chain_state,
            limit,
        );
        result
    }

    /// Insert shard roots for both trees.
    pub fn put_subtree_roots(
        &mut self,
        sapling_start_index: u64,
        sapling_roots: &[CommitmentTreeRoot<sapling::Node>],
        #[cfg(feature = "orchard")] orchard_start_index: u64,
        #[cfg(feature = "orchard")] orchard_roots: &[CommitmentTreeRoot<MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>> {
        self.wallet_mut()
            .put_sapling_subtree_roots(sapling_start_index, sapling_roots)?;

        #[cfg(feature = "orchard")]
        self.wallet_mut()
            .put_orchard_subtree_roots(orchard_start_index, orchard_roots)?;

        Ok(())
    }
}

impl<Cache, DbT, ParamsT, AccountIdT, ErrT> TestState<Cache, DbT, ParamsT>
where
    ParamsT: consensus::Parameters + Send + 'static,
    AccountIdT: std::cmp::Eq + std::hash::Hash,
    ErrT: std::fmt::Debug,
    DbT: InputSource<AccountId = AccountIdT, Error = ErrT>
        + WalletWrite<AccountId = AccountIdT, Error = ErrT>
        + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
{
    /// Invokes [`create_spend_to_address`] with the given arguments.
    #[allow(deprecated)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn create_spend_to_address(
        &mut self,
        usk: &UnifiedSpendingKey,
        to: &Address,
        amount: NonNegativeAmount,
        memo: Option<MemoBytes>,
        ovk_policy: OvkPolicy,
        min_confirmations: NonZeroU32,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
    ) -> Result<
        NonEmpty<TxId>,
        super::error::Error<
            ErrT,
            <DbT as WalletCommitmentTrees>::Error,
            GreedyInputSelectorError<Zip317FeeError, <DbT as InputSource>::NoteRef>,
            Zip317FeeError,
        >,
    > {
        let prover = LocalTxProver::bundled();
        let network = self.network().clone();
        create_spend_to_address(
            self.wallet_mut(),
            &network,
            &prover,
            &prover,
            usk,
            to,
            amount,
            memo,
            ovk_policy,
            min_confirmations,
            change_memo,
            fallback_change_pool,
        )
    }

    /// Invokes [`spend`] with the given arguments.
    #[allow(clippy::type_complexity)]
    pub fn spend<InputsT>(
        &mut self,
        input_selector: &InputsT,
        usk: &UnifiedSpendingKey,
        request: zip321::TransactionRequest,
        ovk_policy: OvkPolicy,
        min_confirmations: NonZeroU32,
    ) -> Result<
        NonEmpty<TxId>,
        super::error::Error<
            ErrT,
            <DbT as WalletCommitmentTrees>::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
        >,
    >
    where
        InputsT: InputSelector<InputSource = DbT>,
    {
        #![allow(deprecated)]
        let prover = LocalTxProver::bundled();
        let network = self.network().clone();
        spend(
            self.wallet_mut(),
            &network,
            &prover,
            &prover,
            input_selector,
            usk,
            request,
            ovk_policy,
            min_confirmations,
        )
    }

    /// Invokes [`propose_transfer`] with the given arguments.
    #[allow(clippy::type_complexity)]
    pub fn propose_transfer<InputsT>(
        &mut self,
        spend_from_account: <DbT as InputSource>::AccountId,
        input_selector: &InputsT,
        request: zip321::TransactionRequest,
        min_confirmations: NonZeroU32,
    ) -> Result<
        Proposal<InputsT::FeeRule, <DbT as InputSource>::NoteRef>,
        super::error::Error<ErrT, Infallible, InputsT::Error, <InputsT::FeeRule as FeeRule>::Error>,
    >
    where
        InputsT: InputSelector<InputSource = DbT>,
    {
        let network = self.network().clone();
        propose_transfer::<_, _, _, Infallible>(
            self.wallet_mut(),
            &network,
            spend_from_account,
            input_selector,
            request,
            min_confirmations,
        )
    }

    /// Invokes [`propose_standard_transfer`] with the given arguments.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose_standard_transfer<CommitmentTreeErrT>(
        &mut self,
        spend_from_account: <DbT as InputSource>::AccountId,
        fee_rule: StandardFeeRule,
        min_confirmations: NonZeroU32,
        to: &Address,
        amount: NonNegativeAmount,
        memo: Option<MemoBytes>,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
    ) -> Result<
        Proposal<StandardFeeRule, <DbT as InputSource>::NoteRef>,
        super::error::Error<
            ErrT,
            CommitmentTreeErrT,
            GreedyInputSelectorError<Zip317FeeError, <DbT as InputSource>::NoteRef>,
            Zip317FeeError,
        >,
    > {
        let network = self.network().clone();
        let result = propose_standard_transfer_to_address::<_, _, CommitmentTreeErrT>(
            self.wallet_mut(),
            &network,
            fee_rule,
            spend_from_account,
            min_confirmations,
            to,
            amount,
            memo,
            change_memo,
            fallback_change_pool,
        );

        if let Ok(proposal) = &result {
            check_proposal_serialization_roundtrip(self.wallet(), proposal);
        }

        result
    }

    /// Invokes [`propose_shielding`] with the given arguments.
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    #[allow(dead_code)]
    pub fn propose_shielding<InputsT>(
        &mut self,
        input_selector: &InputsT,
        shielding_threshold: NonNegativeAmount,
        from_addrs: &[TransparentAddress],
        min_confirmations: u32,
    ) -> Result<
        Proposal<InputsT::FeeRule, Infallible>,
        super::error::Error<ErrT, Infallible, InputsT::Error, <InputsT::FeeRule as FeeRule>::Error>,
    >
    where
        InputsT: ShieldingSelector<InputSource = DbT>,
    {
        use super::wallet::propose_shielding;

        let network = self.network().clone();
        propose_shielding::<_, _, _, Infallible>(
            self.wallet_mut(),
            &network,
            input_selector,
            shielding_threshold,
            from_addrs,
            min_confirmations,
        )
    }

    /// Invokes [`create_proposed_transactions`] with the given arguments.
    #[allow(clippy::type_complexity)]
    pub fn create_proposed_transactions<InputsErrT, FeeRuleT>(
        &mut self,
        usk: &UnifiedSpendingKey,
        ovk_policy: OvkPolicy,
        proposal: &Proposal<FeeRuleT, <DbT as InputSource>::NoteRef>,
    ) -> Result<
        NonEmpty<TxId>,
        super::error::Error<
            ErrT,
            <DbT as WalletCommitmentTrees>::Error,
            InputsErrT,
            FeeRuleT::Error,
        >,
    >
    where
        FeeRuleT: FeeRule,
    {
        let prover = LocalTxProver::bundled();
        let network = self.network().clone();
        create_proposed_transactions(
            self.wallet_mut(),
            &network,
            &prover,
            &prover,
            usk,
            ovk_policy,
            proposal,
        )
    }

    /// Invokes [`shield_transparent_funds`] with the given arguments.
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    pub fn shield_transparent_funds<InputsT>(
        &mut self,
        input_selector: &InputsT,
        shielding_threshold: NonNegativeAmount,
        usk: &UnifiedSpendingKey,
        from_addrs: &[TransparentAddress],
        min_confirmations: u32,
    ) -> Result<
        NonEmpty<TxId>,
        super::error::Error<
            ErrT,
            <DbT as WalletCommitmentTrees>::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
        >,
    >
    where
        InputsT: ShieldingSelector<InputSource = DbT>,
    {
        use crate::data_api::wallet::shield_transparent_funds;

        let prover = LocalTxProver::bundled();
        let network = self.network().clone();
        shield_transparent_funds(
            self.wallet_mut(),
            &network,
            &prover,
            &prover,
            input_selector,
            shielding_threshold,
            usk,
            from_addrs,
            min_confirmations,
        )
    }

    fn with_account_balance<T, F: FnOnce(&AccountBalance) -> T>(
        &self,
        account: AccountIdT,
        min_confirmations: u32,
        f: F,
    ) -> T {
        let binding = self
            .wallet()
            .get_wallet_summary(min_confirmations)
            .unwrap()
            .unwrap();
        f(binding.account_balances().get(&account).unwrap())
    }

    pub fn get_total_balance(&self, account: AccountIdT) -> NonNegativeAmount {
        self.with_account_balance(account, 0, |balance| balance.total())
    }

    pub fn get_spendable_balance(
        &self,
        account: AccountIdT,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.spendable_value()
        })
    }

    pub fn get_pending_shielded_balance(
        &self,
        account: AccountIdT,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.value_pending_spendability() + balance.change_pending_confirmation()
        })
        .unwrap()
    }

    #[allow(dead_code)]
    pub fn get_pending_change(
        &self,
        account: AccountIdT,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.change_pending_confirmation()
        })
    }

    pub fn get_wallet_summary(&self, min_confirmations: u32) -> Option<WalletSummary<AccountIdT>> {
        self.wallet().get_wallet_summary(min_confirmations).unwrap()
    }

    /// Returns a transaction from the history.
    #[allow(dead_code)]
    pub fn get_tx_from_history(
        &self,
        txid: TxId,
    ) -> Result<Option<TransactionSummary<AccountIdT>>, ErrT> {
        let history = self.wallet().get_tx_history()?;
        Ok(history.into_iter().find(|tx| tx.txid() == txid))
    }
}

impl<Cache, DbT: WalletRead + Reset> TestState<Cache, DbT, LocalNetwork> {
    /// Resets the wallet using a new wallet database but with the same cache of blocks,
    /// and returns the old wallet database file.
    ///
    /// This does not recreate accounts, nor does it rescan the cached blocks.
    /// The resulting wallet has no test account.
    /// Before using any `generate_*` method on the reset state, call `reset_latest_cached_block()`.
    pub fn reset(&mut self) -> DbT::Handle {
        self.latest_block_height = None;
        self.test_account = None;
        DbT::reset(self)
    }

    //    /// Reset the latest cached block to the most recent one in the cache database.
    //    #[allow(dead_code)]
    //    pub fn reset_latest_cached_block(&mut self) {
    //        self.cache
    //            .block_source()
    //            .with_blocks::<_, Infallible>(None, None, |block: CompactBlock| {
    //                let chain_metadata = block.chain_metadata.unwrap();
    //                self.latest_cached_block = Some(CachedBlock::at(
    //                    BlockHash::from_slice(block.hash.as_slice()),
    //                    BlockHeight::from_u32(block.height.try_into().unwrap()),
    //                    chain_metadata.sapling_commitment_tree_size,
    //                    chain_metadata.orchard_commitment_tree_size,
    //                ));
    //                Ok(())
    //            })
    //            .unwrap();
    //    }
}

pub fn input_selector<DbT: InputSource>(
    fee_rule: StandardFeeRule,
    change_memo: Option<&str>,
    fallback_change_pool: ShieldedProtocol,
) -> GreedyInputSelector<DbT, standard::SingleOutputChangeStrategy> {
    let change_memo = change_memo.map(|m| MemoBytes::from(m.parse::<Memo>().unwrap()));
    let change_strategy =
        standard::SingleOutputChangeStrategy::new(fee_rule, change_memo, fallback_change_pool);
    GreedyInputSelector::new(change_strategy, DustOutputPolicy::default())
}

// Checks that a protobuf proposal serialized from the provided proposal value correctly parses to
// the same proposal value.
fn check_proposal_serialization_roundtrip<DbT: InputSource>(
    wallet_data: &DbT,
    proposal: &Proposal<StandardFeeRule, DbT::NoteRef>,
) {
    let proposal_proto = crate::proto::proposal::Proposal::from_standard_proposal(proposal);
    let deserialized_proposal = proposal_proto.try_into_standard_proposal(wallet_data);
    assert_matches!(deserialized_proposal, Ok(r) if &r == proposal);
}

pub struct InitialChainState {
    pub chain_state: ChainState,
    pub prior_sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>>,
    #[cfg(feature = "orchard")]
    pub prior_orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>>,
}

pub trait DataStoreFactory {
    type Error: core::fmt::Debug;
    type AccountId: ConditionallySelectable + Default + Send + 'static;
    type DataStore: InputSource<AccountId = Self::AccountId>
        + WalletRead<AccountId = Self::AccountId>
        + WalletWrite
        + WalletCommitmentTrees;

    fn new_data_store(&self, network: LocalNetwork) -> Result<Self::DataStore, Self::Error>;
}

/// A builder for a `zcash_client_sqlite` test.
pub struct TestBuilder<Cache, DataStoreFactory> {
    rng: ChaChaRng,
    network: LocalNetwork,
    cache: Cache,
    ds_factory: DataStoreFactory,
    initial_chain_state: Option<InitialChainState>,
    account_birthday: Option<AccountBirthday>,
    account_index: Option<zip32::AccountId>,
}

impl TestBuilder<(), ()> {
    pub const DEFAULT_NETWORK: LocalNetwork = LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(100_000)),
        blossom: Some(BlockHeight::from_u32(100_000)),
        heartwood: Some(BlockHeight::from_u32(100_000)),
        canopy: Some(BlockHeight::from_u32(100_000)),
        nu5: Some(BlockHeight::from_u32(100_000)),
        nu6: None,
        #[cfg(zcash_unstable = "zfuture")]
        z_future: None,
    };

    /// Constructs a new test environment builder.
    pub fn new() -> Self {
        TestBuilder {
            rng: ChaChaRng::seed_from_u64(0),
            // Use a fake network where Sapling through NU5 activate at the same height.
            // We pick 100,000 to be large enough to handle any hard-coded test offsets.
            network: Self::DEFAULT_NETWORK,
            cache: (),
            ds_factory: (),
            initial_chain_state: None,
            account_birthday: None,
            account_index: None,
        }
    }
}

impl Default for TestBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> TestBuilder<(), A> {
    /// Adds a [`BlockDb`] cache to the test.
    pub fn with_block_cache<C: TestCache>(self, cache: C) -> TestBuilder<C, A> {
        TestBuilder {
            rng: self.rng,
            network: self.network,
            cache,
            ds_factory: self.ds_factory,
            initial_chain_state: self.initial_chain_state,
            account_birthday: self.account_birthday,
            account_index: self.account_index,
        }
    }
}

impl<A> TestBuilder<A, ()> {
    pub fn with_data_store_factory<DsFactory>(
        self,
        ds_factory: DsFactory,
    ) -> TestBuilder<A, DsFactory> {
        TestBuilder {
            rng: self.rng,
            network: self.network,
            cache: self.cache,
            ds_factory,
            initial_chain_state: self.initial_chain_state,
            account_birthday: self.account_birthday,
            account_index: self.account_index,
        }
    }
}

impl<Cache, DsFactory> TestBuilder<Cache, DsFactory> {
    pub fn with_initial_chain_state(
        mut self,
        chain_state: impl FnOnce(&mut ChaChaRng, &LocalNetwork) -> InitialChainState,
    ) -> Self {
        assert!(self.initial_chain_state.is_none());
        assert!(self.account_birthday.is_none());
        self.initial_chain_state = Some(chain_state(&mut self.rng, &self.network));
        self
    }

    pub fn with_account_from_sapling_activation(mut self, prev_hash: BlockHash) -> Self {
        assert!(self.account_birthday.is_none());
        self.account_birthday = Some(AccountBirthday::from_parts(
            ChainState::empty(
                self.network
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap()
                    - 1,
                prev_hash,
            ),
            None,
        ));
        self
    }

    pub fn with_account_having_current_birthday(mut self) -> Self {
        assert!(self.account_birthday.is_none());
        assert!(self.initial_chain_state.is_some());
        self.account_birthday = Some(AccountBirthday::from_parts(
            self.initial_chain_state
                .as_ref()
                .unwrap()
                .chain_state
                .clone(),
            None,
        ));
        self
    }

    /// Sets the [`account_index`] field for the test account
    ///
    /// Call either [`with_account_from_sapling_activation`] or [`with_account_having_current_birthday`] before calling this method.
    pub fn set_account_index(mut self, index: zip32::AccountId) -> Self {
        assert!(self.account_index.is_none());
        self.account_index = Some(index);
        self
    }
}

impl<Cache, DsFactory: DataStoreFactory> TestBuilder<Cache, DsFactory> {
    /// Builds the state for this test.
    pub fn build(self) -> TestState<Cache, DsFactory::DataStore, LocalNetwork> {
        let mut cached_blocks = BTreeMap::new();
        let mut wallet_data = self.ds_factory.new_data_store(self.network).unwrap();

        if let Some(initial_state) = &self.initial_chain_state {
            wallet_data
                .put_sapling_subtree_roots(0, &initial_state.prior_sapling_roots)
                .unwrap();
            wallet_data
                .with_sapling_tree_mut(|t| {
                    t.insert_frontier(
                        initial_state.chain_state.final_sapling_tree().clone(),
                        Retention::Checkpoint {
                            id: initial_state.chain_state.block_height(),
                            marking: Marking::Reference,
                        },
                    )
                })
                .unwrap();

            #[cfg(feature = "orchard")]
            {
                wallet_data
                    .put_orchard_subtree_roots(0, &initial_state.prior_orchard_roots)
                    .unwrap();
                wallet_data
                    .with_orchard_tree_mut(|t| {
                        t.insert_frontier(
                            initial_state.chain_state.final_orchard_tree().clone(),
                            Retention::Checkpoint {
                                id: initial_state.chain_state.block_height(),
                                marking: Marking::Reference,
                            },
                        )
                    })
                    .unwrap();
            }

            let final_sapling_tree_size =
                initial_state.chain_state.final_sapling_tree().tree_size() as u32;
            let _final_orchard_tree_size = 0;
            #[cfg(feature = "orchard")]
            let _final_orchard_tree_size =
                initial_state.chain_state.final_orchard_tree().tree_size() as u32;

            cached_blocks.insert(
                initial_state.chain_state.block_height(),
                CachedBlock {
                    chain_state: initial_state.chain_state.clone(),
                    sapling_end_size: final_sapling_tree_size,
                    orchard_end_size: _final_orchard_tree_size,
                },
            );
        };

        let test_account = self.account_birthday.map(|birthday| {
            let seed = Secret::new(vec![0u8; 32]);
            let (account, usk) = match self.account_index {
                Some(index) => wallet_data
                    .import_account_hd(&seed, index, &birthday)
                    .unwrap(),
                None => {
                    let result = wallet_data.create_account(&seed, &birthday).unwrap();
                    (
                        wallet_data.get_account(result.0).unwrap().unwrap(),
                        result.1,
                    )
                }
            };
            (
                seed,
                TestAccount {
                    account,
                    usk,
                    birthday,
                },
            )
        });

        TestState {
            cache: self.cache,
            cached_blocks,
            latest_block_height: self
                .initial_chain_state
                .map(|s| s.chain_state.block_height()),
            wallet_data,
            network: self.network,
            test_account,
            rng: self.rng,
        }
    }
}

/// Trait used by tests that require a full viewing key.
pub trait TestFvk {
    type Nullifier: Copy;

    fn sapling_ovk(&self) -> Option<sapling::keys::OutgoingViewingKey>;

    #[cfg(feature = "orchard")]
    fn orchard_ovk(&self, scope: zip32::Scope) -> Option<orchard::keys::OutgoingViewingKey>;

    fn add_spend<R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        nf: Self::Nullifier,
        rng: &mut R,
    );

    #[allow(clippy::too_many_arguments)]
    fn add_output<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        params: &P,
        height: BlockHeight,
        req: AddressType,
        value: NonNegativeAmount,
        initial_sapling_tree_size: u32,
        // we don't require an initial Orchard tree size because we don't need it to compute
        // the nullifier.
        rng: &mut R,
    ) -> Self::Nullifier;

    #[allow(clippy::too_many_arguments)]
    fn add_logical_action<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        params: &P,
        height: BlockHeight,
        nf: Self::Nullifier,
        req: AddressType,
        value: NonNegativeAmount,
        initial_sapling_tree_size: u32,
        // we don't require an initial Orchard tree size because we don't need it to compute
        // the nullifier.
        rng: &mut R,
    ) -> Self::Nullifier;
}

impl<'a, A: TestFvk> TestFvk for &'a A {
    type Nullifier = A::Nullifier;

    fn sapling_ovk(&self) -> Option<sapling::keys::OutgoingViewingKey> {
        (*self).sapling_ovk()
    }

    #[cfg(feature = "orchard")]
    fn orchard_ovk(&self, scope: zip32::Scope) -> Option<orchard::keys::OutgoingViewingKey> {
        (*self).orchard_ovk(scope)
    }

    fn add_spend<R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        nf: Self::Nullifier,
        rng: &mut R,
    ) {
        (*self).add_spend(ctx, nf, rng)
    }

    fn add_output<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        params: &P,
        height: BlockHeight,
        req: AddressType,
        value: Zatoshis,
        initial_sapling_tree_size: u32,
        // we don't require an initial Orchard tree size because we don't need it to compute
        // the nullifier.
        rng: &mut R,
    ) -> Self::Nullifier {
        (*self).add_output(
            ctx,
            params,
            height,
            req,
            value,
            initial_sapling_tree_size,
            rng,
        )
    }

    fn add_logical_action<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        params: &P,
        height: BlockHeight,
        nf: Self::Nullifier,
        req: AddressType,
        value: Zatoshis,
        initial_sapling_tree_size: u32,
        // we don't require an initial Orchard tree size because we don't need it to compute
        // the nullifier.
        rng: &mut R,
    ) -> Self::Nullifier {
        (*self).add_logical_action(
            ctx,
            params,
            height,
            nf,
            req,
            value,
            initial_sapling_tree_size,
            rng,
        )
    }
}

impl TestFvk for DiversifiableFullViewingKey {
    type Nullifier = ::sapling::Nullifier;

    fn sapling_ovk(&self) -> Option<sapling::keys::OutgoingViewingKey> {
        Some(self.fvk().ovk)
    }

    #[cfg(feature = "orchard")]
    fn orchard_ovk(&self, _: zip32::Scope) -> Option<orchard::keys::OutgoingViewingKey> {
        None
    }

    fn add_spend<R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        nf: Self::Nullifier,
        _: &mut R,
    ) {
        let cspend = CompactSaplingSpend { nf: nf.to_vec() };
        ctx.spends.push(cspend);
    }

    fn add_output<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        params: &P,
        height: BlockHeight,
        req: AddressType,
        value: NonNegativeAmount,
        initial_sapling_tree_size: u32,
        rng: &mut R,
    ) -> Self::Nullifier {
        let recipient = match req {
            AddressType::DefaultExternal => self.default_address().1,
            AddressType::DiversifiedExternal(idx) => self.find_address(idx).unwrap().1,
            AddressType::Internal => self.change_address().1,
        };

        let position = initial_sapling_tree_size + ctx.outputs.len() as u32;

        let (cout, note) =
            compact_sapling_output(params, height, recipient, value, self.sapling_ovk(), rng);
        ctx.outputs.push(cout);

        note.nf(&self.fvk().vk.nk, position as u64)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_logical_action<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        params: &P,
        height: BlockHeight,
        nf: Self::Nullifier,
        req: AddressType,
        value: NonNegativeAmount,
        initial_sapling_tree_size: u32,
        rng: &mut R,
    ) -> Self::Nullifier {
        self.add_spend(ctx, nf, rng);
        self.add_output(
            ctx,
            params,
            height,
            req,
            value,
            initial_sapling_tree_size,
            rng,
        )
    }
}

#[cfg(feature = "orchard")]
impl TestFvk for orchard::keys::FullViewingKey {
    type Nullifier = orchard::note::Nullifier;

    fn sapling_ovk(&self) -> Option<sapling::keys::OutgoingViewingKey> {
        None
    }

    fn orchard_ovk(&self, scope: zip32::Scope) -> Option<orchard::keys::OutgoingViewingKey> {
        Some(self.to_ovk(scope))
    }

    fn add_spend<R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        revealed_spent_note_nullifier: Self::Nullifier,
        rng: &mut R,
    ) {
        // Generate a dummy recipient.
        let recipient = loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let sk = orchard::keys::SpendingKey::from_bytes(bytes);
            if sk.is_some().into() {
                break orchard::keys::FullViewingKey::from(&sk.unwrap())
                    .address_at(0u32, zip32::Scope::External);
            }
        };

        let (cact, _) = compact_orchard_action(
            revealed_spent_note_nullifier,
            recipient,
            NonNegativeAmount::ZERO,
            self.orchard_ovk(zip32::Scope::Internal),
            rng,
        );
        ctx.actions.push(cact);
    }

    fn add_output<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        _: &P,
        _: BlockHeight,
        req: AddressType,
        value: NonNegativeAmount,
        _: u32, // the position is not required for computing the Orchard nullifier
        mut rng: &mut R,
    ) -> Self::Nullifier {
        // Generate a dummy nullifier for the spend
        let revealed_spent_note_nullifier =
            orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                .unwrap();

        let (j, scope) = match req {
            AddressType::DefaultExternal => (0u32.into(), zip32::Scope::External),
            AddressType::DiversifiedExternal(idx) => (idx, zip32::Scope::External),
            AddressType::Internal => (0u32.into(), zip32::Scope::Internal),
        };

        let (cact, note) = compact_orchard_action(
            revealed_spent_note_nullifier,
            self.address_at(j, scope),
            value,
            self.orchard_ovk(scope),
            rng,
        );
        ctx.actions.push(cact);

        note.nullifier(self)
    }

    // Override so we can merge the spend and output into a single action.
    fn add_logical_action<P: consensus::Parameters, R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        _: &P,
        _: BlockHeight,
        revealed_spent_note_nullifier: Self::Nullifier,
        address_type: AddressType,
        value: NonNegativeAmount,
        _: u32, // the position is not required for computing the Orchard nullifier
        rng: &mut R,
    ) -> Self::Nullifier {
        let (j, scope) = match address_type {
            AddressType::DefaultExternal => (0u32.into(), zip32::Scope::External),
            AddressType::DiversifiedExternal(idx) => (idx, zip32::Scope::External),
            AddressType::Internal => (0u32.into(), zip32::Scope::Internal),
        };

        let (cact, note) = compact_orchard_action(
            revealed_spent_note_nullifier,
            self.address_at(j, scope),
            value,
            self.orchard_ovk(scope),
            rng,
        );
        ctx.actions.push(cact);

        // Return the nullifier of the newly created output note
        note.nullifier(self)
    }
}

#[derive(Clone, Copy)]
pub enum AddressType {
    DefaultExternal,
    #[allow(dead_code)]
    DiversifiedExternal(DiversifierIndex),
    Internal,
}

/// Creates a `CompactSaplingOutput` at the given height paying the given recipient.
///
/// Returns the `CompactSaplingOutput` and the new note.
fn compact_sapling_output<P: consensus::Parameters, R: RngCore + CryptoRng>(
    params: &P,
    height: BlockHeight,
    recipient: sapling::PaymentAddress,
    value: NonNegativeAmount,
    ovk: Option<sapling::keys::OutgoingViewingKey>,
    rng: &mut R,
) -> (CompactSaplingOutput, sapling::Note) {
    let rseed = generate_random_rseed(zip212_enforcement(params, height), rng);
    let note = ::sapling::Note::from_parts(
        recipient,
        sapling::value::NoteValue::from_raw(value.into_u64()),
        rseed,
    );
    let encryptor = sapling_note_encryption(ovk, note.clone(), *MemoBytes::empty().as_array(), rng);
    let cmu = note.cmu().to_bytes().to_vec();
    let ephemeral_key = SaplingDomain::epk_bytes(encryptor.epk()).0.to_vec();
    let enc_ciphertext = encryptor.encrypt_note_plaintext();

    (
        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        },
        note,
    )
}

/// Creates a `CompactOrchardAction` at the given height paying the given recipient.
///
/// Returns the `CompactOrchardAction` and the new note.
#[cfg(feature = "orchard")]
fn compact_orchard_action<R: RngCore + CryptoRng>(
    nf_old: orchard::note::Nullifier,
    recipient: orchard::Address,
    value: NonNegativeAmount,
    ovk: Option<orchard::keys::OutgoingViewingKey>,
    rng: &mut R,
) -> (CompactOrchardAction, orchard::Note) {
    use zcash_note_encryption::ShieldedOutput;

    let (compact_action, note) = orchard::note_encryption::testing::fake_compact_action(
        rng,
        nf_old,
        recipient,
        orchard::value::NoteValue::from_raw(value.into_u64()),
        ovk,
    );

    (
        CompactOrchardAction {
            nullifier: compact_action.nullifier().to_bytes().to_vec(),
            cmx: compact_action.cmx().to_bytes().to_vec(),
            ephemeral_key: compact_action.ephemeral_key().0.to_vec(),
            ciphertext: compact_action.enc_ciphertext().as_ref()[..52].to_vec(),
        },
        note,
    )
}

/// Creates a fake `CompactTx` with a random transaction ID and no spends or outputs.
fn fake_compact_tx<R: RngCore + CryptoRng>(rng: &mut R) -> CompactTx {
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.hash = txid;

    ctx
}

#[derive(Clone)]
pub struct FakeCompactOutput<Fvk> {
    fvk: Fvk,
    address_type: AddressType,
    value: NonNegativeAmount,
}

impl<Fvk> FakeCompactOutput<Fvk> {
    pub fn new(fvk: Fvk, address_type: AddressType, value: NonNegativeAmount) -> Self {
        Self {
            fvk,
            address_type,
            value,
        }
    }
}

/// Create a fake CompactBlock at the given height, containing the specified fake compact outputs.
///
/// Returns the newly created compact block, along with the nullifier for each note created in that
/// block.
#[allow(clippy::too_many_arguments)]
fn fake_compact_block<P: consensus::Parameters, Fvk: TestFvk>(
    params: &P,
    height: BlockHeight,
    prev_hash: BlockHash,
    outputs: &[FakeCompactOutput<Fvk>],
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
    mut rng: impl RngCore + CryptoRng,
) -> (CompactBlock, Vec<Fvk::Nullifier>) {
    // Create a fake CompactBlock containing the note
    let mut ctx = fake_compact_tx(&mut rng);
    let mut nfs = vec![];
    for output in outputs {
        let nf = output.fvk.add_output(
            &mut ctx,
            params,
            height,
            output.address_type,
            output.value,
            initial_sapling_tree_size,
            &mut rng,
        );
        nfs.push(nf);
    }

    let cb = fake_compact_block_from_compact_tx(
        ctx,
        height,
        prev_hash,
        initial_sapling_tree_size,
        initial_orchard_tree_size,
        rng,
    );
    (cb, nfs)
}

/// Create a fake CompactBlock at the given height containing only the given transaction.
fn fake_compact_block_from_tx(
    height: BlockHeight,
    prev_hash: BlockHash,
    tx_index: usize,
    tx: &Transaction,
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
    rng: impl RngCore,
) -> CompactBlock {
    // Create a fake CompactTx containing the transaction.
    let mut ctx = CompactTx {
        index: tx_index as u64,
        hash: tx.txid().as_ref().to_vec(),
        ..Default::default()
    };

    if let Some(bundle) = tx.sapling_bundle() {
        for spend in bundle.shielded_spends() {
            ctx.spends.push(spend.into());
        }
        for output in bundle.shielded_outputs() {
            ctx.outputs.push(output.into());
        }
    }

    #[cfg(feature = "orchard")]
    if let Some(bundle) = tx.orchard_bundle() {
        for action in bundle.actions() {
            ctx.actions.push(action.into());
        }
    }

    fake_compact_block_from_compact_tx(
        ctx,
        height,
        prev_hash,
        initial_sapling_tree_size,
        initial_orchard_tree_size,
        rng,
    )
}

/// Create a fake CompactBlock at the given height, spending a single note from the
/// given address.
#[allow(clippy::too_many_arguments)]
fn fake_compact_block_spending<P: consensus::Parameters, Fvk: TestFvk>(
    params: &P,
    height: BlockHeight,
    prev_hash: BlockHash,
    (nf, in_value): (Fvk::Nullifier, NonNegativeAmount),
    fvk: &Fvk,
    to: Address,
    value: NonNegativeAmount,
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
    mut rng: impl RngCore + CryptoRng,
) -> CompactBlock {
    let mut ctx = fake_compact_tx(&mut rng);

    // Create a fake spend and a fake Note for the change
    fvk.add_logical_action(
        &mut ctx,
        params,
        height,
        nf,
        AddressType::Internal,
        (in_value - value).unwrap(),
        initial_sapling_tree_size,
        &mut rng,
    );

    // Create a fake Note for the payment
    match to {
        Address::Sapling(recipient) => ctx.outputs.push(
            compact_sapling_output(
                params,
                height,
                recipient,
                value,
                fvk.sapling_ovk(),
                &mut rng,
            )
            .0,
        ),
        Address::Transparent(_) | Address::Tex(_) => {
            panic!("transparent addresses not supported in compact blocks")
        }
        Address::Unified(ua) => {
            // This is annoying to implement, because the protocol-aware UA type has no
            // concept of ZIP 316 preference order.
            let mut done = false;

            #[cfg(feature = "orchard")]
            if let Some(recipient) = ua.orchard() {
                // Generate a dummy nullifier
                let nullifier =
                    orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                        .unwrap();

                ctx.actions.push(
                    compact_orchard_action(
                        nullifier,
                        *recipient,
                        value,
                        fvk.orchard_ovk(zip32::Scope::External),
                        &mut rng,
                    )
                    .0,
                );
                done = true;
            }

            if !done {
                if let Some(recipient) = ua.sapling() {
                    ctx.outputs.push(
                        compact_sapling_output(
                            params,
                            height,
                            *recipient,
                            value,
                            fvk.sapling_ovk(),
                            &mut rng,
                        )
                        .0,
                    );
                    done = true;
                }
            }
            if !done {
                panic!("No supported shielded receiver to send funds to");
            }
        }
    }

    fake_compact_block_from_compact_tx(
        ctx,
        height,
        prev_hash,
        initial_sapling_tree_size,
        initial_orchard_tree_size,
        rng,
    )
}

fn fake_compact_block_from_compact_tx(
    ctx: CompactTx,
    height: BlockHeight,
    prev_hash: BlockHash,
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
    mut rng: impl RngCore,
) -> CompactBlock {
    let mut cb = CompactBlock {
        hash: {
            let mut hash = vec![0; 32];
            rng.fill_bytes(&mut hash);
            hash
        },
        height: height.into(),
        ..Default::default()
    };
    cb.prev_hash.extend_from_slice(&prev_hash.0);
    cb.vtx.push(ctx);
    cb.chain_metadata = Some(compact_formats::ChainMetadata {
        sapling_commitment_tree_size: initial_sapling_tree_size
            + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        orchard_commitment_tree_size: initial_orchard_tree_size
            + cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum::<u32>(),
    });
    cb
}

/// Trait used by tests that require a block cache.
pub trait TestCache {
    type BlockSource: BlockSource;
    type InsertResult;

    /// Exposes the block cache as a [`BlockSource`].
    fn block_source(&self) -> &Self::BlockSource;

    /// Inserts a CompactBlock into the cache DB.
    fn insert(&self, cb: &CompactBlock) -> Self::InsertResult;
}

pub struct NoteCommitments {
    sapling: Vec<sapling::Node>,
    #[cfg(feature = "orchard")]
    orchard: Vec<MerkleHashOrchard>,
}

impl NoteCommitments {
    pub fn from_compact_block(cb: &CompactBlock) -> Self {
        NoteCommitments {
            sapling: cb
                .vtx
                .iter()
                .flat_map(|tx| {
                    tx.outputs
                        .iter()
                        .map(|out| sapling::Node::from_cmu(&out.cmu().unwrap()))
                })
                .collect(),
            #[cfg(feature = "orchard")]
            orchard: cb
                .vtx
                .iter()
                .flat_map(|tx| {
                    tx.actions
                        .iter()
                        .map(|act| MerkleHashOrchard::from_cmx(&act.cmx().unwrap()))
                })
                .collect(),
        }
    }

    #[allow(dead_code)]
    pub fn sapling(&self) -> &[sapling::Node] {
        self.sapling.as_ref()
    }

    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> &[MerkleHashOrchard] {
        self.orchard.as_ref()
    }
}

pub struct MockWalletDb {
    pub network: Network,
    pub sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >,
    #[cfg(feature = "orchard")]
    pub orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
}

impl MockWalletDb {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), 100),
            #[cfg(feature = "orchard")]
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), 100),
        }
    }
}

impl InputSource for MockWalletDb {
    type Error = ();
    type NoteRef = u32;
    type AccountId = u32;

    fn get_spendable_note(
        &self,
        _txid: &TxId,
        _protocol: ShieldedProtocol,
        _index: u32,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        Ok(None)
    }

    fn select_spendable_notes(
        &self,
        _account: Self::AccountId,
        _target_value: NonNegativeAmount,
        _sources: &[ShieldedProtocol],
        _anchor_height: BlockHeight,
        _exclude: &[Self::NoteRef],
    ) -> Result<SpendableNotes<Self::NoteRef>, Self::Error> {
        Ok(SpendableNotes::empty())
    }
}

impl WalletRead for MockWalletDb {
    type Error = ();
    type AccountId = u32;
    type Account = (Self::AccountId, UnifiedFullViewingKey);

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        Ok(Vec::new())
    }

    fn get_account(
        &self,
        _account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Ok(None)
    }

    fn get_derived_account(
        &self,
        _seed: &SeedFingerprint,
        _account_id: zip32::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Ok(None)
    }

    fn validate_seed(
        &self,
        _account_id: Self::AccountId,
        _seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        _seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        Ok(SeedRelevance::NoAccounts)
    }

    fn get_account_for_ufvk(
        &self,
        _ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Ok(None)
    }

    fn get_current_address(
        &self,
        _account: Self::AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        Ok(None)
    }

    fn get_account_birthday(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        Err(())
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }

    fn get_wallet_summary(
        &self,
        _min_confirmations: u32,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        Ok(None)
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }

    fn get_block_hash(&self, _block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        Ok(None)
    }

    fn block_metadata(&self, _height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(None)
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(None)
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        Ok(None)
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(None)
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        Ok(vec![])
    }

    fn get_target_and_anchor_heights(
        &self,
        _min_confirmations: NonZeroU32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        Ok(None)
    }

    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }

    fn get_tx_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        Ok(HashMap::new())
    }

    fn get_memo(&self, _id_note: NoteId) -> Result<Option<Memo>, Self::Error> {
        Ok(None)
    }

    fn get_transaction(&self, _txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        Ok(None)
    }

    fn get_sapling_nullifiers(
        &self,
        _query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        Ok(Vec::new())
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        _query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        Ok(Vec::new())
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        _account: Self::AccountId,
    ) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, Self::Error> {
        Ok(HashMap::new())
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        _account: Self::AccountId,
        _max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, NonNegativeAmount>, Self::Error> {
        Ok(HashMap::new())
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_address_metadata(
        &self,
        _account: Self::AccountId,
        _address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        Ok(None)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_known_ephemeral_addresses(
        &self,
        _account: Self::AccountId,
        _index_range: Option<Range<u32>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        Ok(vec![])
    }

    #[cfg(feature = "transparent-inputs")]
    fn find_account_for_ephemeral_address(
        &self,
        _address: &TransparentAddress,
    ) -> Result<Option<Self::AccountId>, Self::Error> {
        Ok(None)
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        Ok(vec![])
    }
}

impl WalletWrite for MockWalletDb {
    type UtxoRef = u32;

    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
        _birthday: &AccountBirthday,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> {
        let account = zip32::AccountId::ZERO;
        UnifiedSpendingKey::from_seed(&self.network, seed.expose_secret(), account)
            .map(|k| (u32::from(account), k))
            .map_err(|_| ())
    }

    fn import_account_hd(
        &mut self,
        _seed: &SecretVec<u8>,
        _account_index: zip32::AccountId,
        _birthday: &AccountBirthday,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> {
        todo!()
    }

    fn import_account_ufvk(
        &mut self,
        _unified_key: &UnifiedFullViewingKey,
        _birthday: &AccountBirthday,
        _purpose: AccountPurpose,
    ) -> Result<Self::Account, Self::Error> {
        todo!()
    }

    fn get_next_available_address(
        &mut self,
        _account: Self::AccountId,
        _request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        Ok(None)
    }

    #[allow(clippy::type_complexity)]
    fn put_blocks(
        &mut self,
        _from_state: &ChainState,
        _blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn update_chain_tip(&mut self, _tip_height: BlockHeight) -> Result<(), Self::Error> {
        Ok(())
    }

    fn store_decrypted_tx(
        &mut self,
        _received_tx: DecryptedTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn store_transactions_to_be_sent(
        &mut self,
        _transactions: &[SentTransaction<Self::AccountId>],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn truncate_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Adds a transparent UTXO received by the wallet to the data store.
    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        Ok(0)
    }

    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        _account_id: Self::AccountId,
        _n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        Err(())
    }

    fn set_transaction_status(
        &mut self,
        _txid: TxId,
        _status: TransactionStatus,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl WalletCommitmentTrees for MockWalletDb {
    type Error = Infallible;
    type SaplingShardStore<'a> = MemoryShardStore<sapling::Node, BlockHeight>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Infallible>>,
    {
        callback(&mut self.sapling_tree)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.with_sapling_tree_mut(|t| {
            for (root, i) in roots.iter().zip(0u64..) {
                let root_addr = incrementalmerkletree::Address::from_parts(
                    SAPLING_SHARD_HEIGHT.into(),
                    start_index + i,
                );
                t.insert(root_addr, *root.root_hash())?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

        Ok(())
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        callback(&mut self.orchard_tree)
    }

    /// Adds a sequence of note commitment tree subtree roots to the data store.
    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.with_orchard_tree_mut(|t| {
            for (root, i) in roots.iter().zip(0u64..) {
                let root_addr = incrementalmerkletree::Address::from_parts(
                    ORCHARD_SHARD_HEIGHT.into(),
                    start_index + i,
                );
                t.insert(root_addr, *root.root_hash())?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

        Ok(())
    }
}
