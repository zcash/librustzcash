//! Utilities for testing wallets based upon the [`crate::data_api`] traits.

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    fmt,
    hash::Hash,
    num::NonZeroU32,
};

use assert_matches::assert_matches;
use group::ff::Field;
use incrementalmerkletree::{Marking, Retention};
use nonempty::NonEmpty;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use secrecy::{ExposeSecret, Secret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use subtle::ConditionallySelectable;

use ::sapling::{
    note_encryption::{sapling_note_encryption, SaplingDomain},
    util::generate_random_rseed,
    zip32::DiversifiableFullViewingKey,
};
use zcash_address::ZcashAddress;
use zcash_keys::{
    address::{Address, UnifiedAddress},
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_note_encryption::Domain;
use zcash_primitives::{
    block::BlockHash,
    transaction::{components::sapling::zip212_enforcement, fees::FeeRule, Transaction, TxId},
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{self, BlockHeight, Network, NetworkUpgrade, Parameters as _},
    local_consensus::LocalNetwork,
    memo::{Memo, MemoBytes},
    value::{TargetValue, ZatBalance, Zatoshis},
    ShieldedProtocol,
};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex};
use zip321::Payment;

use super::{
    chain::{scan_cached_blocks, BlockSource, ChainState, CommitmentTreeRoot, ScanSummary},
    error::Error,
    scanning::ScanRange,
    wallet::{
        create_proposed_transactions,
        input_selection::{GreedyInputSelector, InputSelector},
        propose_standard_transfer_to_address, propose_transfer,
    },
    Account, AccountBalance, AccountBirthday, AccountMeta, AccountPurpose, AccountSource,
    AddressInfo, BlockMetadata, DecryptedTransaction, InputSource, NoteFilter, NullifierQuery,
    ScannedBlock, SeedRelevance, SentTransaction, SpendableNotes, TransactionDataRequest,
    TransactionStatus, WalletCommitmentTrees, WalletRead, WalletSummary, WalletTest, WalletWrite,
    SAPLING_SHARD_HEIGHT,
};
use crate::{
    fees::{
        standard::{self, SingleOutputChangeStrategy},
        ChangeStrategy, DustOutputPolicy, StandardFeeRule,
    },
    proposal::Proposal,
    proto::compact_formats::{
        self, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    },
    wallet::{Note, NoteId, OvkPolicy, ReceivedNote, WalletTransparentOutput},
};

#[cfg(feature = "transparent-inputs")]
use {
    super::wallet::input_selection::ShieldingSelector,
    crate::wallet::TransparentAddressMetadata,
    ::transparent::{address::TransparentAddress, keys::NonHardenedChildIndex},
    std::ops::Range,
    transparent::GapLimits,
};

#[cfg(feature = "orchard")]
use {
    super::ORCHARD_SHARD_HEIGHT, crate::proto::compact_formats::CompactOrchardAction,
    ::orchard::tree::MerkleHashOrchard, group::ff::PrimeField, pasta_curves::pallas,
};

pub mod pool;
pub mod sapling;

#[cfg(feature = "orchard")]
pub mod orchard;
#[cfg(feature = "transparent-inputs")]
pub mod transparent;

/// Information about a transaction that the wallet is interested in.
pub struct TransactionSummary<AccountId> {
    account_id: AccountId,
    txid: TxId,
    expiry_height: Option<BlockHeight>,
    mined_height: Option<BlockHeight>,
    account_value_delta: ZatBalance,
    total_spent: Zatoshis,
    total_received: Zatoshis,
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
    /// Constructs a `TransactionSummary` from its parts.
    ///
    /// See the documentation for each getter method below to determine how each method
    /// argument should be prepared.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        account_id: AccountId,
        txid: TxId,
        expiry_height: Option<BlockHeight>,
        mined_height: Option<BlockHeight>,
        account_value_delta: ZatBalance,
        total_spent: Zatoshis,
        total_received: Zatoshis,
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
            total_spent,
            total_received,
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

    /// Returns the wallet-internal ID for the account that this transaction was received
    /// by or sent from.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the transaction's ID.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// Returns the expiry height of the transaction, if known.
    ///
    /// - `None` means that the expiry height is unknown.
    /// - `Some(0)` means that the transaction does not expire.
    pub fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }

    /// Returns the height of the mined block containing this transaction, or `None` if
    /// the wallet has not yet observed the transaction to be mined.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }

    /// Returns the net change in balance that this transaction caused to the account.
    ///
    /// For example, an account-internal transaction (such as a shielding operation) would
    /// show `-fee_paid` as the account value delta.
    pub fn account_value_delta(&self) -> ZatBalance {
        self.account_value_delta
    }

    /// Returns the total value of notes spent by the account in this transaction.
    pub fn total_spent(&self) -> Zatoshis {
        self.total_spent
    }

    /// Returns the total value of notes received by the account in this transaction.
    pub fn total_received(&self) -> Zatoshis {
        self.total_received
    }

    /// Returns the fee paid by this transaction, if known.
    pub fn fee_paid(&self) -> Option<Zatoshis> {
        self.fee_paid
    }

    /// Returns the number of notes spent by the account in this transaction.
    pub fn spent_note_count(&self) -> usize {
        self.spent_note_count
    }

    /// Returns `true` if the account received a change note as part of this transaction.
    ///
    /// This implies that the transaction was (at least in part) sent from the account.
    pub fn has_change(&self) -> bool {
        self.has_change
    }

    /// Returns the number of notes created in this transaction that were sent to a
    /// wallet-external address.
    pub fn sent_note_count(&self) -> usize {
        self.sent_note_count
    }

    /// Returns the number of notes created in this transaction that were received by the
    /// account.
    pub fn received_note_count(&self) -> usize {
        self.received_note_count
    }

    /// Returns `true` if, from the wallet's current view of the chain, this transaction
    /// expired before it was mined.
    pub fn expired_unmined(&self) -> bool {
        self.expired_unmined
    }

    /// Returns the number of non-empty memos viewable by the account in this transaction.
    pub fn memo_count(&self) -> usize {
        self.memo_count
    }

    /// Returns `true` if this is detectably a shielding transaction.
    ///
    /// Specifically, `true` means that at a minimum:
    /// - All of the wallet-spent and wallet-received notes are consistent with a
    ///   shielding transaction.
    /// - The transaction contains at least one wallet-spent output.
    /// - The transaction contains at least one wallet-received note.
    /// - We do not know about any external outputs of the transaction.
    ///
    /// There may be some shielding transactions for which this method returns `false`,
    /// due to them not being detectable by the wallet as shielding transactions under the
    /// above metrics.
    pub fn is_shielding(&self) -> bool {
        self.is_shielding
    }
}

/// Metadata about a block generated by [`TestState`].
#[derive(Clone, Debug)]
pub struct CachedBlock {
    chain_state: ChainState,
    sapling_end_size: u32,
    orchard_end_size: u32,
}

impl CachedBlock {
    /// Produces metadata for a block "before shielded time", when the Sapling and Orchard
    /// trees were (by definition) empty.
    ///
    /// `block_height` must be a height before Sapling activation (and therefore also
    /// before NU5 activation).
    pub fn none(block_height: BlockHeight) -> Self {
        Self {
            chain_state: ChainState::empty(block_height, BlockHash([0; 32])),
            sapling_end_size: 0,
            orchard_end_size: 0,
        }
    }

    /// Produces metadata for a block as of the given chain state.
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
                acc.append(::sapling::Node::from_cmu(&c_out.cmu().unwrap()));
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

    /// Returns the height of this block.
    pub fn height(&self) -> BlockHeight {
        self.chain_state.block_height()
    }

    /// Returns the size of the Sapling note commitment tree as of the end of this block.
    pub fn sapling_end_size(&self) -> u32 {
        self.sapling_end_size
    }

    /// Returns the size of the Orchard note commitment tree as of the end of this block.
    pub fn orchard_end_size(&self) -> u32 {
        self.orchard_end_size
    }
}

/// The test account configured for a [`TestState`].
///
/// Create this by calling either [`TestBuilder::with_account_from_sapling_activation`] or
/// [`TestBuilder::with_account_having_current_birthday`] while setting up a test, and
/// then access it with [`TestState::test_account`].
#[derive(Clone)]
pub struct TestAccount<A> {
    account: A,
    usk: UnifiedSpendingKey,
    birthday: AccountBirthday,
}

impl<A> TestAccount<A> {
    /// Returns the underlying wallet account.
    pub fn account(&self) -> &A {
        &self.account
    }

    /// Returns the account's unified spending key.
    pub fn usk(&self) -> &UnifiedSpendingKey {
        &self.usk
    }

    /// Returns the birthday that was configured for the account.
    pub fn birthday(&self) -> &AccountBirthday {
        &self.birthday
    }
}

impl<A: Account> Account for TestAccount<A> {
    type AccountId = A::AccountId;

    fn id(&self) -> Self::AccountId {
        self.account.id()
    }

    fn name(&self) -> Option<&str> {
        self.account.name()
    }

    fn source(&self) -> &AccountSource {
        self.account.source()
    }

    fn ufvk(&self) -> Option<&zcash_keys::keys::UnifiedFullViewingKey> {
        self.account.ufvk()
    }

    fn uivk(&self) -> zcash_keys::keys::UnifiedIncomingViewingKey {
        self.account.uivk()
    }
}

/// Trait method exposing the ability to reset the wallet within a test.
// TODO: Does this need to exist separately from DataStoreFactory?
pub trait Reset: WalletTest + Sized {
    /// A handle that confers ownership of a specific wallet instance.
    type Handle;

    /// Replaces the wallet in `st` (via [`TestState::wallet_mut`]) with a new wallet
    /// database.
    ///
    /// This does not recreate accounts. The resulting wallet in `st` has no test account.
    ///
    /// Returns the old wallet.
    fn reset<C>(st: &mut TestState<C, Self, LocalNetwork>) -> Self::Handle;
}

/// The state for a `zcash_client_backend` test.
pub struct TestState<Cache, DataStore: WalletTest, Network> {
    cache: Cache,
    cached_blocks: BTreeMap<BlockHeight, CachedBlock>,
    latest_block_height: Option<BlockHeight>,
    wallet_data: DataStore,
    network: Network,
    test_account: Option<(SecretVec<u8>, TestAccount<DataStore::Account>)>,
    rng: ChaChaRng,
}

impl<Cache, DataStore: WalletTest, Network> TestState<Cache, DataStore, Network> {
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

impl<Cache, DataStore: WalletTest, Network: consensus::Parameters>
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

    /// Exposes the seed for the test wallet.
    pub fn test_seed(&self) -> Option<&SecretVec<u8>> {
        self.test_account.as_ref().map(|(seed, _)| seed)
    }

    /// Returns a reference to the test account, if one was configured.
    pub fn test_account(&self) -> Option<&TestAccount<<DataStore as WalletRead>::Account>> {
        self.test_account.as_ref().map(|(_, acct)| acct)
    }

    /// Returns the test account's Sapling DFVK, if one was configured.
    pub fn test_account_sapling(&self) -> Option<&DiversifiableFullViewingKey> {
        let (_, acct) = self.test_account.as_ref()?;
        let ufvk = acct.ufvk()?;
        ufvk.sapling()
    }

    /// Returns the test account's Orchard FVK, if one was configured.
    #[cfg(feature = "orchard")]
    pub fn test_account_orchard(&self) -> Option<&::orchard::keys::FullViewingKey> {
        let (_, acct) = self.test_account.as_ref()?;
        let ufvk = acct.ufvk()?;
        ufvk.orchard()
    }
}

impl<Cache: TestCache, DataStore, Network> TestState<Cache, DataStore, Network>
where
    Network: consensus::Parameters,
    DataStore: WalletTest + WalletWrite,
    <Cache::BlockSource as BlockSource>::Error: fmt::Debug,
{
    /// Exposes an immutable reference to the test's [`BlockSource`].
    #[cfg(feature = "unstable")]
    pub fn cache(&self) -> &Cache::BlockSource {
        self.cache.block_source()
    }

    /// Returns the cached chain state corresponding to the latest block generated by this
    /// `TestState`.
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
        value: Zatoshis,
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
                        acc.append(::sapling::Node::from_scalar(bls12_381::Scalar::random(
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
        note: (Fvk::Nullifier, Zatoshis),
        to: impl Into<Address>,
        value: Zatoshis,
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

    /// Truncates the test wallet and block cache to the specified height, discarding all data from
    /// blocks at heights greater than the specified height, excluding transaction data that may
    /// not be recoverable from the chain.
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        self.wallet_mut().truncate_to_height(height).unwrap();
        self.cache.truncate_to_height(height);
        self.cached_blocks.split_off(&(height + 1));
        self.latest_block_height = Some(height);
    }

    /// Truncates the test wallet to the specified height, and resets the cache's latest block
    /// height but does not truncate the block cache. This is useful for circumstances when you
    /// want to re-scan a set of cached blocks.
    pub fn truncate_to_height_retaining_cache(&mut self, height: BlockHeight) {
        self.wallet_mut().truncate_to_height(height).unwrap();
        self.latest_block_height = Some(height);
    }
}

impl<Cache, DbT, ParamsT> TestState<Cache, DbT, ParamsT>
where
    Cache: TestCache,
    <Cache::BlockSource as BlockSource>::Error: fmt::Debug,
    ParamsT: consensus::Parameters + Send + 'static,
    DbT: InputSource + WalletTest + WalletWrite + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId:
        std::fmt::Debug + ConditionallySelectable + Default + Send + 'static,
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
        sapling_roots: &[CommitmentTreeRoot<::sapling::Node>],
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
    AccountIdT: std::fmt::Debug + std::cmp::Eq + std::hash::Hash,
    ErrT: std::fmt::Debug,
    DbT: InputSource<AccountId = AccountIdT, Error = ErrT>
        + WalletTest
        + WalletWrite<AccountId = AccountIdT, Error = ErrT>
        + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
{
    // Creates a transaction that sends the specified value from the given account to
    // the provided recipient address, using a greedy input selector and the default
    // mutli-output change strategy.
    pub fn create_standard_transaction(
        &mut self,
        from_account: &TestAccount<DbT::Account>,
        to: ZcashAddress,
        value: Zatoshis,
    ) -> Result<
        NonEmpty<TxId>,
        super::wallet::TransferErrT<
            DbT,
            GreedyInputSelector<DbT>,
            standard::MultiOutputChangeStrategy<DbT>,
        >,
    > {
        let input_selector = GreedyInputSelector::new();

        #[cfg(not(feature = "orchard"))]
        let fallback_change_pool = ShieldedProtocol::Sapling;
        #[cfg(feature = "orchard")]
        let fallback_change_pool = ShieldedProtocol::Orchard;

        let change_strategy = standard::SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            fallback_change_pool,
            DustOutputPolicy::default(),
        );

        let request =
            zip321::TransactionRequest::new(vec![Payment::without_memo(to, value)]).unwrap();

        self.spend(
            &input_selector,
            &change_strategy,
            from_account.usk(),
            request,
            OvkPolicy::Sender,
            NonZeroU32::MIN,
        )
    }

    /// Prepares and executes the given [`zip321::TransactionRequest`] in a single step.
    #[allow(clippy::type_complexity)]
    pub fn spend<InputsT, ChangeT>(
        &mut self,
        input_selector: &InputsT,
        change_strategy: &ChangeT,
        usk: &UnifiedSpendingKey,
        request: zip321::TransactionRequest,
        ovk_policy: OvkPolicy,
        min_confirmations: NonZeroU32,
    ) -> Result<NonEmpty<TxId>, super::wallet::TransferErrT<DbT, InputsT, ChangeT>>
    where
        InputsT: InputSelector<InputSource = DbT>,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
        let prover = LocalTxProver::bundled();
        let network = self.network().clone();

        let account = self
            .wallet()
            .get_account_for_ufvk(&usk.to_unified_full_viewing_key())
            .map_err(Error::DataSource)?
            .ok_or(Error::KeyNotRecognized)?;

        let proposal = propose_transfer(
            self.wallet_mut(),
            &network,
            account.id(),
            input_selector,
            change_strategy,
            request,
            min_confirmations,
        )?;

        create_proposed_transactions(
            self.wallet_mut(),
            &network,
            &prover,
            &prover,
            usk,
            ovk_policy,
            &proposal,
        )
    }

    /// Invokes [`propose_transfer`] with the given arguments.
    #[allow(clippy::type_complexity)]
    pub fn propose_transfer<InputsT, ChangeT>(
        &mut self,
        spend_from_account: <DbT as InputSource>::AccountId,
        input_selector: &InputsT,
        change_strategy: &ChangeT,
        request: zip321::TransactionRequest,
        min_confirmations: NonZeroU32,
    ) -> Result<
        Proposal<ChangeT::FeeRule, <DbT as InputSource>::NoteRef>,
        super::wallet::ProposeTransferErrT<DbT, Infallible, InputsT, ChangeT>,
    >
    where
        InputsT: InputSelector<InputSource = DbT>,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
        let network = self.network().clone();
        propose_transfer::<_, _, _, _, Infallible>(
            self.wallet_mut(),
            &network,
            spend_from_account,
            input_selector,
            change_strategy,
            request,
            min_confirmations,
        )
    }

    /// Invokes [`propose_standard_transfer_to_address`] with the given arguments.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose_standard_transfer<CommitmentTreeErrT>(
        &mut self,
        spend_from_account: <DbT as InputSource>::AccountId,
        fee_rule: StandardFeeRule,
        min_confirmations: NonZeroU32,
        to: &Address,
        amount: Zatoshis,
        memo: Option<MemoBytes>,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
    ) -> Result<
        Proposal<StandardFeeRule, <DbT as InputSource>::NoteRef>,
        super::wallet::ProposeTransferErrT<
            DbT,
            CommitmentTreeErrT,
            GreedyInputSelector<DbT>,
            SingleOutputChangeStrategy<DbT>,
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
    ///
    /// [`propose_shielding`]: crate::data_api::wallet::propose_shielding
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    #[allow(dead_code)]
    pub fn propose_shielding<InputsT, ChangeT>(
        &mut self,
        input_selector: &InputsT,
        change_strategy: &ChangeT,
        shielding_threshold: Zatoshis,
        from_addrs: &[TransparentAddress],
        to_account: <InputsT::InputSource as InputSource>::AccountId,
        min_confirmations: u32,
    ) -> Result<
        Proposal<ChangeT::FeeRule, Infallible>,
        super::wallet::ProposeShieldingErrT<DbT, Infallible, InputsT, ChangeT>,
    >
    where
        InputsT: ShieldingSelector<InputSource = DbT>,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
        use super::wallet::propose_shielding;

        let network = self.network().clone();
        propose_shielding::<_, _, _, _, Infallible>(
            self.wallet_mut(),
            &network,
            input_selector,
            change_strategy,
            shielding_threshold,
            from_addrs,
            to_account,
            min_confirmations,
        )
    }

    /// Invokes [`create_proposed_transactions`] with the given arguments.
    #[allow(clippy::type_complexity)]
    pub fn create_proposed_transactions<InputsErrT, FeeRuleT, ChangeErrT>(
        &mut self,
        usk: &UnifiedSpendingKey,
        ovk_policy: OvkPolicy,
        proposal: &Proposal<FeeRuleT, <DbT as InputSource>::NoteRef>,
    ) -> Result<
        NonEmpty<TxId>,
        super::wallet::CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, DbT::NoteRef>,
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

    /// Invokes [`create_pczt_from_proposal`] with the given arguments.
    ///
    /// [`create_pczt_from_proposal`]: super::wallet::create_pczt_from_proposal
    #[cfg(feature = "pczt")]
    #[allow(clippy::type_complexity)]
    pub fn create_pczt_from_proposal<InputsErrT, FeeRuleT, ChangeErrT>(
        &mut self,
        spend_from_account: <DbT as InputSource>::AccountId,
        ovk_policy: OvkPolicy,
        proposal: &Proposal<FeeRuleT, <DbT as InputSource>::NoteRef>,
    ) -> Result<
        pczt::Pczt,
        super::wallet::CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, DbT::NoteRef>,
    >
    where
        <DbT as WalletRead>::AccountId: serde::Serialize,
        FeeRuleT: FeeRule,
    {
        use super::wallet::create_pczt_from_proposal;

        let network = self.network().clone();

        create_pczt_from_proposal(
            self.wallet_mut(),
            &network,
            spend_from_account,
            ovk_policy,
            proposal,
        )
    }

    /// Invokes [`extract_and_store_transaction_from_pczt`] with the given arguments.
    ///
    /// [`extract_and_store_transaction_from_pczt`]: super::wallet::extract_and_store_transaction_from_pczt
    #[cfg(feature = "pczt")]
    #[allow(clippy::type_complexity)]
    pub fn extract_and_store_transaction_from_pczt(
        &mut self,
        pczt: pczt::Pczt,
    ) -> Result<TxId, super::wallet::ExtractErrT<DbT, DbT::NoteRef>>
    where
        <DbT as WalletRead>::AccountId: serde::de::DeserializeOwned,
    {
        use super::wallet::extract_and_store_transaction_from_pczt;

        let prover = LocalTxProver::bundled();
        let (spend_vk, output_vk) = prover.verifying_keys();

        extract_and_store_transaction_from_pczt(
            self.wallet_mut(),
            pczt,
            Some((&spend_vk, &output_vk)),
            None,
        )
    }

    /// Invokes [`shield_transparent_funds`] with the given arguments.
    ///
    /// [`shield_transparent_funds`]: crate::data_api::wallet::shield_transparent_funds
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn shield_transparent_funds<InputsT, ChangeT>(
        &mut self,
        input_selector: &InputsT,
        change_strategy: &ChangeT,
        shielding_threshold: Zatoshis,
        usk: &UnifiedSpendingKey,
        from_addrs: &[TransparentAddress],
        to_account: <DbT as InputSource>::AccountId,
        min_confirmations: u32,
    ) -> Result<NonEmpty<TxId>, super::wallet::ShieldErrT<DbT, InputsT, ChangeT>>
    where
        InputsT: ShieldingSelector<InputSource = DbT>,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
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
            change_strategy,
            shielding_threshold,
            usk,
            from_addrs,
            to_account,
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

    /// Returns the total balance in the given account at this point in the test.
    pub fn get_total_balance(&self, account: AccountIdT) -> Zatoshis {
        self.with_account_balance(account, 0, |balance| balance.total())
    }

    /// Returns the balance in the given account that is spendable with the given number
    /// of confirmations at this point in the test.
    pub fn get_spendable_balance(&self, account: AccountIdT, min_confirmations: u32) -> Zatoshis {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.spendable_value()
        })
    }

    /// Returns the balance in the given account that is detected but not yet spendable
    /// with the given number of confirmations at this point in the test.
    pub fn get_pending_shielded_balance(
        &self,
        account: AccountIdT,
        min_confirmations: u32,
    ) -> Zatoshis {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.value_pending_spendability() + balance.change_pending_confirmation()
        })
        .unwrap()
    }

    /// Returns the amount of change in the given account that is not yet spendable with
    /// the given number of confirmations at this point in the test.
    #[allow(dead_code)]
    pub fn get_pending_change(&self, account: AccountIdT, min_confirmations: u32) -> Zatoshis {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.change_pending_confirmation()
        })
    }

    /// Returns a summary of the wallet at this point in the test.
    pub fn get_wallet_summary(&self, min_confirmations: u32) -> Option<WalletSummary<AccountIdT>> {
        self.wallet().get_wallet_summary(min_confirmations).unwrap()
    }
}

impl<Cache, DbT, ParamsT, AccountIdT, ErrT> TestState<Cache, DbT, ParamsT>
where
    ParamsT: consensus::Parameters + Send + 'static,
    AccountIdT: std::cmp::Eq + std::hash::Hash,
    ErrT: std::fmt::Debug,
    DbT: InputSource<AccountId = AccountIdT, Error = ErrT>
        + WalletTest
        + WalletWrite<AccountId = AccountIdT, Error = ErrT>
        + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
{
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

pub fn single_output_change_strategy<DbT: InputSource>(
    fee_rule: StandardFeeRule,
    change_memo: Option<&str>,
    fallback_change_pool: ShieldedProtocol,
) -> standard::SingleOutputChangeStrategy<DbT> {
    let change_memo = change_memo.map(|m| MemoBytes::from(m.parse::<Memo>().unwrap()));
    standard::SingleOutputChangeStrategy::new(
        fee_rule,
        change_memo,
        fallback_change_pool,
        DustOutputPolicy::default(),
    )
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

/// The initial chain state for a test.
///
/// This is returned from the closure passed to [`TestBuilder::with_initial_chain_state`]
/// to configure the test state with a starting chain position, to which subsequent test
/// activity is applied.
pub struct InitialChainState {
    /// Information about the chain's state as of the chain tip.
    pub chain_state: ChainState,
    /// Roots of the completed Sapling subtrees as of this chain state.
    pub prior_sapling_roots: Vec<CommitmentTreeRoot<::sapling::Node>>,
    /// Roots of the completed Orchard subtrees as of this chain state.
    #[cfg(feature = "orchard")]
    pub prior_orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>>,
}

/// Trait representing the ability to construct a new data store for use in a test.
pub trait DataStoreFactory {
    type Error: core::fmt::Debug;
    type AccountId: std::fmt::Debug + ConditionallySelectable + Default + Hash + Eq + Send + 'static;
    type Account: Account<AccountId = Self::AccountId> + Clone;
    type DsError: core::fmt::Debug;
    type DataStore: InputSource<AccountId = Self::AccountId, Error = Self::DsError>
        + WalletRead<AccountId = Self::AccountId, Account = Self::Account, Error = Self::DsError>
        + WalletTest
        + WalletWrite
        + WalletCommitmentTrees;

    /// Constructs a new data store.
    fn new_data_store(
        &self,
        network: LocalNetwork,
        #[cfg(feature = "transparent-inputs")] gap_limits: GapLimits,
    ) -> Result<Self::DataStore, Self::Error>;
}

/// A [`TestState`] builder, that configures the environment for a test.
pub struct TestBuilder<Cache, DataStoreFactory> {
    rng: ChaChaRng,
    network: LocalNetwork,
    cache: Cache,
    ds_factory: DataStoreFactory,
    initial_chain_state: Option<InitialChainState>,
    account_birthday: Option<AccountBirthday>,
    account_index: Option<zip32::AccountId>,
    #[cfg(feature = "transparent-inputs")]
    gap_limits: GapLimits,
}

impl TestBuilder<(), ()> {
    /// The default network used by [`TestBuilder::new`].
    ///
    /// This is a fake network where Sapling through NU5 activate at the same height. We
    /// pick height 100,000 to be large enough to handle any hard-coded test offsets.
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
            network: Self::DEFAULT_NETWORK,
            cache: (),
            ds_factory: (),
            initial_chain_state: None,
            account_birthday: None,
            account_index: None,
            #[cfg(feature = "transparent-inputs")]
            gap_limits: GapLimits::new(10, 5, 5),
        }
    }
}

impl Default for TestBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> TestBuilder<(), A> {
    /// Adds a block cache to the test environment.
    pub fn with_block_cache<C: TestCache>(self, cache: C) -> TestBuilder<C, A> {
        TestBuilder {
            rng: self.rng,
            network: self.network,
            cache,
            ds_factory: self.ds_factory,
            initial_chain_state: self.initial_chain_state,
            account_birthday: self.account_birthday,
            account_index: self.account_index,
            #[cfg(feature = "transparent-inputs")]
            gap_limits: self.gap_limits,
        }
    }
}

impl<A> TestBuilder<A, ()> {
    /// Adds a wallet data store to the test environment.
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
            #[cfg(feature = "transparent-inputs")]
            gap_limits: self.gap_limits,
        }
    }
}

impl<A, B> TestBuilder<A, B> {
    #[cfg(feature = "transparent-inputs")]
    pub fn with_gap_limits(self, gap_limits: GapLimits) -> TestBuilder<A, B> {
        TestBuilder {
            rng: self.rng,
            network: self.network,
            cache: self.cache,
            ds_factory: self.ds_factory,
            initial_chain_state: self.initial_chain_state,
            account_birthday: self.account_birthday,
            account_index: self.account_index,
            gap_limits,
        }
    }
}

impl<Cache, DsFactory> TestBuilder<Cache, DsFactory> {
    /// Configures the test to start with the given initial chain state.
    ///
    /// # Panics
    ///
    /// - Must not be called twice.
    /// - Must be called before [`Self::with_account_from_sapling_activation`] or
    ///   [`Self::with_account_having_current_birthday`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::num::NonZeroU8;
    ///
    /// use incrementalmerkletree::frontier::Frontier;
    /// use zcash_primitives::{block::BlockHash, consensus::Parameters};
    /// use zcash_protocol::consensus::NetworkUpgrade;
    /// use zcash_client_backend::data_api::{
    ///     chain::{ChainState, CommitmentTreeRoot},
    ///     testing::{InitialChainState, TestBuilder},
    /// };
    ///
    /// // For this test, we'll start inserting leaf notes 5 notes after the end of the
    /// // third subtree, with a gap of 10 blocks. After `scan_cached_blocks`, the scan
    /// // queue should have a requested scan range of 300..310 with `FoundNote` priority,
    /// // 310..320 with `Scanned` priority. We set both Sapling and Orchard to the same
    /// // initial tree size for simplicity.
    /// let prior_block_hash = BlockHash([0; 32]);
    /// let initial_sapling_tree_size: u32 = (0x1 << 16) * 3 + 5;
    /// let initial_orchard_tree_size: u32 = (0x1 << 16) * 3 + 5;
    /// let initial_height_offset = 310;
    ///
    /// let mut st = TestBuilder::new()
    ///     .with_initial_chain_state(|rng, network| {
    ///         // For simplicity, assume Sapling and NU5 activated at the same height.
    ///         let sapling_activation_height =
    ///             network.activation_height(NetworkUpgrade::Sapling).unwrap();
    ///
    ///         // Construct a fake chain state for the end of block 300
    ///         let (prior_sapling_roots, sapling_initial_tree) =
    ///             Frontier::random_with_prior_subtree_roots(
    ///                 rng,
    ///                 initial_sapling_tree_size.into(),
    ///                 NonZeroU8::new(16).unwrap(),
    ///             );
    ///         let prior_sapling_roots = prior_sapling_roots
    ///             .into_iter()
    ///             .zip(1u32..)
    ///             .map(|(root, i)| {
    ///                 CommitmentTreeRoot::from_parts(sapling_activation_height + (100 * i), root)
    ///             })
    ///             .collect::<Vec<_>>();
    ///
    ///         #[cfg(feature = "orchard")]
    ///         let (prior_orchard_roots, orchard_initial_tree) =
    ///             Frontier::random_with_prior_subtree_roots(
    ///                 rng,
    ///                 initial_orchard_tree_size.into(),
    ///                 NonZeroU8::new(16).unwrap(),
    ///             );
    ///         #[cfg(feature = "orchard")]
    ///         let prior_orchard_roots = prior_orchard_roots
    ///             .into_iter()
    ///             .zip(1u32..)
    ///             .map(|(root, i)| {
    ///                 CommitmentTreeRoot::from_parts(sapling_activation_height + (100 * i), root)
    ///             })
    ///             .collect::<Vec<_>>();
    ///
    ///         InitialChainState {
    ///             chain_state: ChainState::new(
    ///                 sapling_activation_height + initial_height_offset - 1,
    ///                 prior_block_hash,
    ///                 sapling_initial_tree,
    ///                 #[cfg(feature = "orchard")]
    ///                 orchard_initial_tree,
    ///             ),
    ///             prior_sapling_roots,
    ///             #[cfg(feature = "orchard")]
    ///             prior_orchard_roots,
    ///         }
    ///     });
    /// ```
    pub fn with_initial_chain_state(
        mut self,
        chain_state: impl FnOnce(&mut ChaChaRng, &LocalNetwork) -> InitialChainState,
    ) -> Self {
        assert!(self.initial_chain_state.is_none());
        assert!(self.account_birthday.is_none());
        self.initial_chain_state = Some(chain_state(&mut self.rng, &self.network));
        self
    }

    /// Configures the environment with a [`TestAccount`] that has a birthday at Sapling
    /// activation.
    ///
    /// # Panics
    ///
    /// - Must not be called twice.
    /// - Do not call both [`Self::with_account_having_current_birthday`] and this method.
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

    /// Configures the environment with a [`TestAccount`] that has a birthday one block
    /// after the initial chain state.
    ///
    /// # Panics
    ///
    /// - Must not be called twice.
    /// - Must call [`Self::with_initial_chain_state`] before calling this method.
    /// - Do not call both [`Self::with_account_from_sapling_activation`] and this method.
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

    /// Sets the account index for the test account.
    ///
    /// Does nothing unless either [`Self::with_account_from_sapling_activation`] or
    /// [`Self::with_account_having_current_birthday`] is also called.
    ///
    /// # Panics
    ///
    /// - Must not be called twice.
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
        let mut wallet_data = self
            .ds_factory
            .new_data_store(
                self.network,
                #[cfg(feature = "transparent-inputs")]
                self.gap_limits,
            )
            .unwrap();

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
                    .import_account_hd("", &seed, index, &birthday, None)
                    .unwrap(),
                None => {
                    let result = wallet_data
                        .create_account("", &seed, &birthday, None)
                        .unwrap();
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
pub trait TestFvk: Clone {
    /// The type of nullifier corresponding to the kind of note that this full viewing key
    /// can detect (and that its corresponding spending key can spend).
    type Nullifier: Copy;

    /// Returns the Sapling outgoing viewing key corresponding to this full viewing key,
    /// if any.
    fn sapling_ovk(&self) -> Option<::sapling::keys::OutgoingViewingKey>;

    /// Returns the Orchard outgoing viewing key corresponding to this full viewing key,
    /// if any.
    #[cfg(feature = "orchard")]
    fn orchard_ovk(&self, scope: zip32::Scope) -> Option<::orchard::keys::OutgoingViewingKey>;

    /// Adds a single spend to the given [`CompactTx`] of a note previously received by
    /// this full viewing key.
    fn add_spend<R: RngCore + CryptoRng>(
        &self,
        ctx: &mut CompactTx,
        nf: Self::Nullifier,
        rng: &mut R,
    );

    /// Adds a single output to the given [`CompactTx`] that will be received by this full
    /// viewing key.
    ///
    /// `req` allows configuring how the full viewing key will detect the output.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Self::Nullifier;

    /// Adds both a spend and an output to the given [`CompactTx`].
    ///
    /// - If this is a Sapling full viewing key, the transaction will gain both a Spend
    ///   and an Output.
    /// - If this is an Orchard full viewing key, the transaction will gain an Action.
    ///
    /// `req` allows configuring how the full viewing key will detect the output.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Self::Nullifier;
}

impl<A: TestFvk> TestFvk for &A {
    type Nullifier = A::Nullifier;

    fn sapling_ovk(&self) -> Option<::sapling::keys::OutgoingViewingKey> {
        (*self).sapling_ovk()
    }

    #[cfg(feature = "orchard")]
    fn orchard_ovk(&self, scope: zip32::Scope) -> Option<::orchard::keys::OutgoingViewingKey> {
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

    fn sapling_ovk(&self) -> Option<::sapling::keys::OutgoingViewingKey> {
        Some(self.fvk().ovk)
    }

    #[cfg(feature = "orchard")]
    fn orchard_ovk(&self, _: zip32::Scope) -> Option<::orchard::keys::OutgoingViewingKey> {
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
        value: Zatoshis,
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
        value: Zatoshis,
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
impl TestFvk for ::orchard::keys::FullViewingKey {
    type Nullifier = ::orchard::note::Nullifier;

    fn sapling_ovk(&self) -> Option<::sapling::keys::OutgoingViewingKey> {
        None
    }

    fn orchard_ovk(&self, scope: zip32::Scope) -> Option<::orchard::keys::OutgoingViewingKey> {
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
            let sk = ::orchard::keys::SpendingKey::from_bytes(bytes);
            if sk.is_some().into() {
                break ::orchard::keys::FullViewingKey::from(&sk.unwrap())
                    .address_at(0u32, zip32::Scope::External);
            }
        };

        let (cact, _) = compact_orchard_action(
            revealed_spent_note_nullifier,
            recipient,
            Zatoshis::ZERO,
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
        value: Zatoshis,
        _: u32, // the position is not required for computing the Orchard nullifier
        mut rng: &mut R,
    ) -> Self::Nullifier {
        // Generate a dummy nullifier for the spend
        let revealed_spent_note_nullifier =
            ::orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
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
        value: Zatoshis,
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

/// Configures how a [`TestFvk`] receives a particular output.
///
/// Used with [`TestFvk::add_output`] and [`TestFvk::add_logical_action`].
#[derive(Clone, Copy)]
pub enum AddressType {
    /// The output will be sent to the default address of the full viewing key.
    DefaultExternal,
    /// The output will be sent to the specified diversified address of the full viewing
    /// key.
    #[allow(dead_code)]
    DiversifiedExternal(DiversifierIndex),
    /// The output will be sent to the internal receiver of the full viewing key.
    ///
    /// Such outputs are treated as "wallet-internal". A "recipient address" is **NEVER**
    /// exposed to users.
    Internal,
}

/// Creates a `CompactSaplingOutput` at the given height paying the given recipient.
///
/// Returns the `CompactSaplingOutput` and the new note.
fn compact_sapling_output<P: consensus::Parameters, R: RngCore + CryptoRng>(
    params: &P,
    height: BlockHeight,
    recipient: ::sapling::PaymentAddress,
    value: Zatoshis,
    ovk: Option<::sapling::keys::OutgoingViewingKey>,
    rng: &mut R,
) -> (CompactSaplingOutput, ::sapling::Note) {
    let rseed = generate_random_rseed(zip212_enforcement(params, height), rng);
    let note = ::sapling::Note::from_parts(
        recipient,
        ::sapling::value::NoteValue::from_raw(value.into_u64()),
        rseed,
    );
    let encryptor =
        sapling_note_encryption(ovk, note.clone(), MemoBytes::empty().into_bytes(), rng);
    let cmu = note.cmu().to_bytes().to_vec();
    let ephemeral_key = SaplingDomain::epk_bytes(encryptor.epk()).0.to_vec();
    let enc_ciphertext = encryptor.encrypt_note_plaintext();

    (
        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext[..52].to_vec(),
        },
        note,
    )
}

/// Creates a `CompactOrchardAction` at the given height paying the given recipient.
///
/// Returns the `CompactOrchardAction` and the new note.
#[cfg(feature = "orchard")]
fn compact_orchard_action<R: RngCore + CryptoRng>(
    nf_old: ::orchard::note::Nullifier,
    recipient: ::orchard::Address,
    value: Zatoshis,
    ovk: Option<::orchard::keys::OutgoingViewingKey>,
    rng: &mut R,
) -> (CompactOrchardAction, ::orchard::Note) {
    use zcash_note_encryption::ShieldedOutput;

    let (compact_action, note) = ::orchard::note_encryption::testing::fake_compact_action(
        rng,
        nf_old,
        recipient,
        ::orchard::value::NoteValue::from_raw(value.into_u64()),
        ovk,
    );

    (
        CompactOrchardAction {
            nullifier: compact_action.nullifier().to_bytes().to_vec(),
            cmx: compact_action.cmx().to_bytes().to_vec(),
            ephemeral_key: compact_action.ephemeral_key().0.to_vec(),
            ciphertext: compact_action.enc_ciphertext()[..52].to_vec(),
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

/// A fake output of a [`CompactTx`].
///
/// Used with the following block generators:
/// - [`TestState::generate_next_block_multi`]
/// - [`TestState::generate_block_at`]
#[derive(Clone)]
pub struct FakeCompactOutput<Fvk> {
    fvk: Fvk,
    address_type: AddressType,
    value: Zatoshis,
}

impl<Fvk> FakeCompactOutput<Fvk> {
    /// Constructs a new fake output with the given properties.
    pub fn new(fvk: Fvk, address_type: AddressType, value: Zatoshis) -> Self {
        Self {
            fvk,
            address_type,
            value,
        }
    }

    /// Constructs a new random fake external output to the given FVK with a value in the range
    /// 10000..1000000 ZAT.
    pub fn random<R: RngCore>(rng: &mut R, fvk: Fvk) -> Self {
        Self {
            fvk,
            address_type: AddressType::DefaultExternal,
            value: Zatoshis::const_from_u64(rng.gen_range(10000..1000000)),
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
    (nf, in_value): (Fvk::Nullifier, Zatoshis),
    fvk: &Fvk,
    to: Address,
    value: Zatoshis,
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
                let nullifier = ::orchard::note::Nullifier::from_bytes(
                    &pallas::Base::random(&mut rng).to_repr(),
                )
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
    type BsError: core::fmt::Debug;
    type BlockSource: BlockSource<Error = Self::BsError>;
    type InsertResult;

    /// Exposes the block cache as a [`BlockSource`].
    fn block_source(&self) -> &Self::BlockSource;

    /// Inserts a CompactBlock into the cache DB.
    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult;

    /// Deletes block data from the cache, retaining blocks at heights less than or equal to the
    /// specified height.
    fn truncate_to_height(&mut self, height: BlockHeight);
}

/// A convenience type for the note commitments contained within a [`CompactBlock`].
///
/// Indended for use as (part of) the [`TestCache::InsertResult`] associated type.
pub struct NoteCommitments {
    sapling: Vec<::sapling::Node>,
    #[cfg(feature = "orchard")]
    orchard: Vec<MerkleHashOrchard>,
}

impl NoteCommitments {
    /// Extracts the note commitments from the given compact block.
    pub fn from_compact_block(cb: &CompactBlock) -> Self {
        NoteCommitments {
            sapling: cb
                .vtx
                .iter()
                .flat_map(|tx| {
                    tx.outputs
                        .iter()
                        .map(|out| ::sapling::Node::from_cmu(&out.cmu().unwrap()))
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

    /// Returns the Sapling note commitments.
    #[allow(dead_code)]
    pub fn sapling(&self) -> &[::sapling::Node] {
        self.sapling.as_ref()
    }

    /// Returns the Orchard note commitments.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> &[MerkleHashOrchard] {
        self.orchard.as_ref()
    }
}

/// A mock wallet data source that implements the bare minimum necessary to function.
pub struct MockWalletDb {
    pub network: Network,
    pub sapling_tree: ShardTree<
        MemoryShardStore<::sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >,
    #[cfg(feature = "orchard")]
    pub orchard_tree: ShardTree<
        MemoryShardStore<::orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
}

impl MockWalletDb {
    /// Constructs a new mock wallet data source.
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
        _target_value: TargetValue,
        _sources: &[ShieldedProtocol],
        _anchor_height: BlockHeight,
        _exclude: &[Self::NoteRef],
    ) -> Result<SpendableNotes<Self::NoteRef>, Self::Error> {
        Ok(SpendableNotes::empty())
    }

    fn get_account_metadata(
        &self,
        _account: Self::AccountId,
        _selector: &NoteFilter,
        _exclude: &[Self::NoteRef],
    ) -> Result<AccountMeta, Self::Error> {
        Err(())
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

    fn list_addresses(&self, _account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        Ok(vec![])
    }

    fn get_last_generated_address_matching(
        &self,
        _account: Self::AccountId,
        _request: UnifiedAddressRequest,
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
    ) -> Result<Vec<(Self::AccountId, ::sapling::Nullifier)>, Self::Error> {
        Ok(Vec::new())
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        _query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, ::orchard::note::Nullifier)>, Self::Error> {
        Ok(Vec::new())
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        _account: Self::AccountId,
        _include_change: bool,
    ) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, Self::Error> {
        Ok(HashMap::new())
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        _account: Self::AccountId,
        _max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, Zatoshis>, Self::Error> {
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
        _index_range: Option<Range<NonHardenedChildIndex>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        Ok(vec![])
    }

    #[cfg(feature = "transparent-inputs")]
    fn utxo_query_height(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        Ok(BlockHeight::from(0u32))
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
        _account_name: &str,
        seed: &SecretVec<u8>,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> {
        let account = zip32::AccountId::ZERO;
        UnifiedSpendingKey::from_seed(&self.network, seed.expose_secret(), account)
            .map(|k| (u32::from(account), k))
            .map_err(|_| ())
    }

    fn import_account_hd(
        &mut self,
        _account_name: &str,
        _seed: &SecretVec<u8>,
        _account_index: zip32::AccountId,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> {
        todo!()
    }

    fn import_account_ufvk(
        &mut self,
        _account_name: &str,
        _unified_key: &UnifiedFullViewingKey,
        _birthday: &AccountBirthday,
        _purpose: AccountPurpose,
        _key_source: Option<&str>,
    ) -> Result<Self::Account, Self::Error> {
        todo!()
    }

    fn get_next_available_address(
        &mut self,
        _account: Self::AccountId,
        _request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, Self::Error> {
        Ok(None)
    }

    fn get_address_for_index(
        &mut self,
        _account: Self::AccountId,
        _diversifier_index: DiversifierIndex,
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

    fn truncate_to_height(
        &mut self,
        _block_height: BlockHeight,
    ) -> Result<BlockHeight, Self::Error> {
        Err(())
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
    type SaplingShardStore<'a> = MemoryShardStore<::sapling::Node, BlockHeight>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { ::sapling::NOTE_COMMITMENT_TREE_DEPTH },
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
        roots: &[CommitmentTreeRoot<::sapling::Node>],
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
    type OrchardShardStore<'a> = MemoryShardStore<::orchard::tree::MerkleHashOrchard, BlockHeight>;

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
        roots: &[CommitmentTreeRoot<::orchard::tree::MerkleHashOrchard>],
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
