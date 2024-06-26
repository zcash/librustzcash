use std::fmt;
use std::num::NonZeroU32;
use std::{collections::BTreeMap, convert::Infallible};

#[cfg(feature = "unstable")]
use std::fs::File;

use group::ff::Field;
use incrementalmerkletree::{Position, Retention};
use nonempty::NonEmpty;
use prost::Message;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rusqlite::{params, Connection};
use secrecy::{Secret, SecretVec};

use shardtree::error::ShardTreeError;
use tempfile::NamedTempFile;

#[cfg(feature = "unstable")]
use tempfile::TempDir;

use sapling::{
    note_encryption::{sapling_note_encryption, SaplingDomain},
    util::generate_random_rseed,
    zip32::DiversifiableFullViewingKey,
    Note, Nullifier,
};
#[allow(deprecated)]
use zcash_client_backend::{
    address::Address,
    data_api::{
        self,
        chain::{scan_cached_blocks, BlockSource, CommitmentTreeRoot, ScanSummary},
        wallet::{
            create_proposed_transactions, create_spend_to_address,
            input_selection::{GreedyInputSelector, GreedyInputSelectorError, InputSelector},
            propose_standard_transfer_to_address, propose_transfer, spend,
        },
        AccountBalance, AccountBirthday, WalletCommitmentTrees, WalletRead, WalletSummary,
        WalletWrite,
    },
    keys::UnifiedSpendingKey,
    proposal::Proposal,
    proto::compact_formats::{
        self as compact, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    },
    proto::proposal,
    wallet::OvkPolicy,
    zip321,
};
use zcash_client_backend::{
    data_api::chain::ChainState,
    fees::{standard, DustOutputPolicy},
    ShieldedProtocol,
};
use zcash_note_encryption::Domain;
use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
    transaction::{
        components::{amount::NonNegativeAmount, sapling::zip212_enforcement},
        fees::{zip317::FeeError as Zip317FeeError, FeeRule, StandardFeeRule},
        Transaction, TxId,
    },
    zip32::DiversifierIndex,
};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::{
    chain::init::init_cache_database,
    error::SqliteClientError,
    wallet::{
        commitment_tree, get_wallet_summary, init::init_wallet_db, sapling::tests::test_prover,
        SubtreeScanProgress,
    },
    AccountId, ReceivedNoteId, WalletDb,
};

use super::BlockDb;

#[cfg(feature = "orchard")]
use {
    group::ff::PrimeField, orchard::tree::MerkleHashOrchard, pasta_curves::pallas,
    zcash_client_backend::proto::compact_formats::CompactOrchardAction,
};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::data_api::wallet::{
        input_selection::ShieldingSelector, propose_shielding, shield_transparent_funds,
    },
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "unstable")]
use crate::{
    chain::{init::init_blockmeta_db, BlockMeta},
    FsBlockDb,
};

pub(crate) mod pool;

pub(crate) struct InitialChainState {
    pub(crate) chain_state: ChainState,
    pub(crate) prior_sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>>,
    #[cfg(feature = "orchard")]
    pub(crate) prior_orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>>,
}

/// A builder for a `zcash_client_sqlite` test.
pub(crate) struct TestBuilder<Cache> {
    rng: ChaChaRng,
    network: LocalNetwork,
    cache: Cache,
    initial_chain_state: Option<InitialChainState>,
    account_birthday: Option<AccountBirthday>,
}

impl TestBuilder<()> {
    pub const DEFAULT_NETWORK: LocalNetwork = LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(100_000)),
        blossom: Some(BlockHeight::from_u32(100_000)),
        heartwood: Some(BlockHeight::from_u32(100_000)),
        canopy: Some(BlockHeight::from_u32(100_000)),
        nu5: Some(BlockHeight::from_u32(100_000)),
        #[cfg(zcash_unstable = "nu6")]
        nu6: None,
        #[cfg(zcash_unstable = "zfuture")]
        z_future: None,
    };

    /// Constructs a new test.
    pub(crate) fn new() -> Self {
        TestBuilder {
            rng: ChaChaRng::seed_from_u64(0),
            // Use a fake network where Sapling through NU5 activate at the same height.
            // We pick 100,000 to be large enough to handle any hard-coded test offsets.
            network: Self::DEFAULT_NETWORK,
            cache: (),
            initial_chain_state: None,
            account_birthday: None,
        }
    }

    /// Adds a [`BlockDb`] cache to the test.
    pub(crate) fn with_block_cache(self) -> TestBuilder<BlockCache> {
        TestBuilder {
            rng: self.rng,
            network: self.network,
            cache: BlockCache::new(),
            initial_chain_state: self.initial_chain_state,
            account_birthday: self.account_birthday,
        }
    }

    /// Adds a [`FsBlockDb`] cache to the test.
    #[cfg(feature = "unstable")]
    pub(crate) fn with_fs_block_cache(self) -> TestBuilder<FsBlockCache> {
        TestBuilder {
            rng: self.rng,
            network: self.network,
            cache: FsBlockCache::new(),
            initial_chain_state: self.initial_chain_state,
            account_birthday: self.account_birthday,
        }
    }
}

impl<Cache> TestBuilder<Cache> {
    pub(crate) fn with_initial_chain_state(
        mut self,
        chain_state: impl FnOnce(&mut ChaChaRng, &LocalNetwork) -> InitialChainState,
    ) -> Self {
        assert!(self.initial_chain_state.is_none());
        assert!(self.account_birthday.is_none());
        self.initial_chain_state = Some(chain_state(&mut self.rng, &self.network));
        self
    }

    pub(crate) fn with_account_birthday(
        mut self,
        birthday: impl FnOnce(
            &mut ChaChaRng,
            &LocalNetwork,
            Option<&InitialChainState>,
        ) -> AccountBirthday,
    ) -> Self {
        assert!(self.account_birthday.is_none());
        self.account_birthday = Some(birthday(
            &mut self.rng,
            &self.network,
            self.initial_chain_state.as_ref(),
        ));
        self
    }

    pub(crate) fn with_account_from_sapling_activation(mut self, prev_hash: BlockHash) -> Self {
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

    pub(crate) fn with_account_having_current_birthday(mut self) -> Self {
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

    /// Builds the state for this test.
    pub(crate) fn build(self) -> TestState<Cache> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), self.network).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        let mut cached_blocks = BTreeMap::new();

        if let Some(initial_state) = &self.initial_chain_state {
            db_data
                .put_sapling_subtree_roots(0, &initial_state.prior_sapling_roots)
                .unwrap();
            db_data
                .with_sapling_tree_mut(|t| {
                    t.insert_frontier(
                        initial_state.chain_state.final_sapling_tree().clone(),
                        Retention::Checkpoint {
                            id: initial_state.chain_state.block_height(),
                            is_marked: false,
                        },
                    )
                })
                .unwrap();

            #[cfg(feature = "orchard")]
            {
                db_data
                    .put_orchard_subtree_roots(0, &initial_state.prior_orchard_roots)
                    .unwrap();
                db_data
                    .with_orchard_tree_mut(|t| {
                        t.insert_frontier(
                            initial_state.chain_state.final_orchard_tree().clone(),
                            Retention::Checkpoint {
                                id: initial_state.chain_state.block_height(),
                                is_marked: false,
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
            let (account_id, usk) = db_data.create_account(&seed, &birthday).unwrap();
            (
                seed,
                TestAccount {
                    account_id,
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
            _data_file: data_file,
            db_data,
            test_account,
            rng: self.rng,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CachedBlock {
    chain_state: ChainState,
    sapling_end_size: u32,
    orchard_end_size: u32,
}

impl CachedBlock {
    fn none(sapling_activation_height: BlockHeight) -> Self {
        Self {
            chain_state: ChainState::empty(sapling_activation_height, BlockHash([0; 32])),
            sapling_end_size: 0,
            orchard_end_size: 0,
        }
    }

    fn at(chain_state: ChainState, sapling_end_size: u32, orchard_end_size: u32) -> Self {
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

    fn height(&self) -> BlockHeight {
        self.chain_state.block_height()
    }
}

#[derive(Clone)]
pub(crate) struct TestAccount {
    account_id: AccountId,
    usk: UnifiedSpendingKey,
    birthday: AccountBirthday,
}

impl TestAccount {
    pub(crate) fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub(crate) fn usk(&self) -> &UnifiedSpendingKey {
        &self.usk
    }

    pub(crate) fn birthday(&self) -> &AccountBirthday {
        &self.birthday
    }
}

/// The state for a `zcash_client_sqlite` test.
pub(crate) struct TestState<Cache> {
    cache: Cache,
    cached_blocks: BTreeMap<BlockHeight, CachedBlock>,
    latest_block_height: Option<BlockHeight>,
    _data_file: NamedTempFile,
    db_data: WalletDb<Connection, LocalNetwork>,
    test_account: Option<(SecretVec<u8>, TestAccount)>,
    rng: ChaChaRng,
}

impl<Cache: TestCache> TestState<Cache>
where
    <Cache::BlockSource as BlockSource>::Error: fmt::Debug,
{
    /// Exposes an immutable reference to the test's [`BlockSource`].
    #[cfg(feature = "unstable")]
    pub(crate) fn cache(&self) -> &Cache::BlockSource {
        self.cache.block_source()
    }

    pub(crate) fn latest_cached_block(&self) -> Option<&CachedBlock> {
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
    pub(crate) fn generate_next_block<Fvk: TestFvk>(
        &mut self,
        fvk: &Fvk,
        req: AddressType,
        value: NonNegativeAmount,
    ) -> (BlockHeight, Cache::InsertResult, Fvk::Nullifier) {
        let pre_activation_block = CachedBlock::none(self.sapling_activation_height() - 1);
        let prior_cached_block = self.latest_cached_block().unwrap_or(&pre_activation_block);
        let height = prior_cached_block.height() + 1;

        let (res, nf) = self.generate_block_at(
            height,
            prior_cached_block.chain_state.block_hash(),
            fvk,
            req,
            value,
            prior_cached_block.sapling_end_size,
            prior_cached_block.orchard_end_size,
            false,
        );

        (height, res, nf)
    }

    /// Adds an empty block to the cache, advancing the simulated chain height.
    #[allow(dead_code)] // used only for tests that are flagged off by default
    pub(crate) fn generate_empty_block(&mut self) -> (BlockHeight, Cache::InsertResult) {
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

        cb.chain_metadata = Some(compact::ChainMetadata {
            sapling_commitment_tree_size: prior_cached_block.sapling_end_size,
            orchard_commitment_tree_size: prior_cached_block.orchard_end_size,
        });

        let res = self.cache_block(&prior_cached_block, cb);
        self.latest_block_height = Some(new_height);

        (new_height, res)
    }

    /// Creates a fake block with the given height and hash containing a single output of
    /// the given value, and inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] will build on it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generate_block_at<Fvk: TestFvk>(
        &mut self,
        height: BlockHeight,
        prev_hash: BlockHash,
        fvk: &Fvk,
        req: AddressType,
        value: NonNegativeAmount,
        initial_sapling_tree_size: u32,
        initial_orchard_tree_size: u32,
        allow_broken_hash_chain: bool,
    ) -> (Cache::InsertResult, Fvk::Nullifier) {
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

        let (cb, nf) = fake_compact_block(
            &self.network(),
            height,
            prev_hash,
            fvk,
            req,
            value,
            initial_sapling_tree_size,
            initial_orchard_tree_size,
            &mut self.rng,
        );
        assert_eq!(cb.height(), height);

        let res = self.cache_block(&prior_cached_block, cb);
        self.latest_block_height = Some(height);

        (res, nf)
    }

    /// Creates a fake block at the expected next height spending the given note, and
    /// inserts it into the cache.
    pub(crate) fn generate_next_block_spending<Fvk: TestFvk>(
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
            &self.network(),
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
    pub(crate) fn generate_next_block_including(
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
    pub(crate) fn generate_next_block_from_tx(
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

    /// Invokes [`scan_cached_blocks`] with the given arguments, expecting success.
    pub(crate) fn scan_cached_blocks(
        &mut self,
        from_height: BlockHeight,
        limit: usize,
    ) -> ScanSummary {
        let result = self.try_scan_cached_blocks(from_height, limit);
        assert_matches!(result, Ok(_));
        result.unwrap()
    }

    /// Invokes [`scan_cached_blocks`] with the given arguments.
    pub(crate) fn try_scan_cached_blocks(
        &mut self,
        from_height: BlockHeight,
        limit: usize,
    ) -> Result<
        ScanSummary,
        data_api::chain::error::Error<
            SqliteClientError,
            <Cache::BlockSource as BlockSource>::Error,
        >,
    > {
        let prior_cached_block = self
            .latest_cached_block_below_height(from_height)
            .cloned()
            .unwrap_or_else(|| CachedBlock::none(from_height - 1));

        let result = scan_cached_blocks(
            &self.network(),
            self.cache.block_source(),
            &mut self.db_data,
            from_height,
            &prior_cached_block.chain_state,
            limit,
        );
        result
    }

    /// Resets the wallet using a new wallet database but with the same cache of blocks,
    /// and returns the old wallet database file.
    ///
    /// This does not recreate accounts, nor does it rescan the cached blocks.
    /// The resulting wallet has no test account.
    /// Before using any `generate_*` method on the reset state, call `reset_latest_cached_block()`.
    pub(crate) fn reset(&mut self) -> NamedTempFile {
        let network = self.network();
        self.latest_block_height = None;
        let tf = std::mem::replace(&mut self._data_file, NamedTempFile::new().unwrap());
        self.db_data = WalletDb::for_path(self._data_file.path(), network).unwrap();
        self.test_account = None;
        init_wallet_db(&mut self.db_data, None).unwrap();
        tf
    }

    //    /// Reset the latest cached block to the most recent one in the cache database.
    //    #[allow(dead_code)]
    //    pub(crate) fn reset_latest_cached_block(&mut self) {
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

impl<Cache> TestState<Cache> {
    /// Exposes an immutable reference to the test's [`WalletDb`].
    pub(crate) fn wallet(&self) -> &WalletDb<Connection, LocalNetwork> {
        &self.db_data
    }

    /// Exposes a mutable reference to the test's [`WalletDb`].
    pub(crate) fn wallet_mut(&mut self) -> &mut WalletDb<Connection, LocalNetwork> {
        &mut self.db_data
    }

    /// Exposes the test framework's source of randomness.
    pub(crate) fn rng_mut(&mut self) -> &mut ChaChaRng {
        &mut self.rng
    }

    /// Exposes the network in use.
    pub(crate) fn network(&self) -> LocalNetwork {
        self.db_data.params
    }

    /// Convenience method for obtaining the Sapling activation height for the network under test.
    pub(crate) fn sapling_activation_height(&self) -> BlockHeight {
        self.db_data
            .params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height must be known.")
    }

    /// Exposes the test seed, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_seed(&self) -> Option<&SecretVec<u8>> {
        self.test_account.as_ref().map(|(seed, _)| seed)
    }

    /// Exposes the test account, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_account(&self) -> Option<&TestAccount> {
        self.test_account.as_ref().map(|(_, acct)| acct)
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_account_sapling(&self) -> Option<DiversifiableFullViewingKey> {
        self.test_account
            .as_ref()
            .and_then(|(_, acct)| acct.usk.to_unified_full_viewing_key().sapling().cloned())
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    #[cfg(feature = "orchard")]
    pub(crate) fn test_account_orchard(&self) -> Option<orchard::keys::FullViewingKey> {
        self.test_account
            .as_ref()
            .and_then(|(_, acct)| acct.usk.to_unified_full_viewing_key().orchard().cloned())
    }

    /// Insert shard roots for both trees.
    pub(crate) fn put_subtree_roots(
        &mut self,
        sapling_start_index: u64,
        sapling_roots: &[CommitmentTreeRoot<sapling::Node>],
        #[cfg(feature = "orchard")] orchard_start_index: u64,
        #[cfg(feature = "orchard")] orchard_roots: &[CommitmentTreeRoot<MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<commitment_tree::Error>> {
        self.wallet_mut()
            .put_sapling_subtree_roots(sapling_start_index, sapling_roots)?;

        #[cfg(feature = "orchard")]
        self.wallet_mut()
            .put_orchard_subtree_roots(orchard_start_index, orchard_roots)?;

        Ok(())
    }

    /// Invokes [`create_spend_to_address`] with the given arguments.
    #[allow(deprecated)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_spend_to_address(
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
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            GreedyInputSelectorError<Zip317FeeError, ReceivedNoteId>,
            Zip317FeeError,
        >,
    > {
        let params = self.network();
        let prover = test_prover();
        create_spend_to_address(
            &mut self.db_data,
            &params,
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
    pub(crate) fn spend<InputsT>(
        &mut self,
        input_selector: &InputsT,
        usk: &UnifiedSpendingKey,
        request: zip321::TransactionRequest,
        ovk_policy: OvkPolicy,
        min_confirmations: NonZeroU32,
    ) -> Result<
        NonEmpty<TxId>,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
        >,
    >
    where
        InputsT: InputSelector<InputSource = WalletDb<Connection, LocalNetwork>>,
    {
        #![allow(deprecated)]
        let params = self.network();
        let prover = test_prover();
        spend(
            &mut self.db_data,
            &params,
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
    pub(crate) fn propose_transfer<InputsT>(
        &mut self,
        spend_from_account: AccountId,
        input_selector: &InputsT,
        request: zip321::TransactionRequest,
        min_confirmations: NonZeroU32,
    ) -> Result<
        Proposal<InputsT::FeeRule, ReceivedNoteId>,
        data_api::error::Error<
            SqliteClientError,
            Infallible,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
        >,
    >
    where
        InputsT: InputSelector<InputSource = WalletDb<Connection, LocalNetwork>>,
    {
        let params = self.network();
        propose_transfer::<_, _, _, Infallible>(
            &mut self.db_data,
            &params,
            spend_from_account,
            input_selector,
            request,
            min_confirmations,
        )
    }

    /// Invokes [`propose_standard_transfer`] with the given arguments.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn propose_standard_transfer<CommitmentTreeErrT>(
        &mut self,
        spend_from_account: AccountId,
        fee_rule: StandardFeeRule,
        min_confirmations: NonZeroU32,
        to: &Address,
        amount: NonNegativeAmount,
        memo: Option<MemoBytes>,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
    ) -> Result<
        Proposal<StandardFeeRule, ReceivedNoteId>,
        data_api::error::Error<
            SqliteClientError,
            CommitmentTreeErrT,
            GreedyInputSelectorError<Zip317FeeError, ReceivedNoteId>,
            Zip317FeeError,
        >,
    > {
        let params = self.network();
        let result = propose_standard_transfer_to_address::<_, _, CommitmentTreeErrT>(
            &mut self.db_data,
            &params,
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
    pub(crate) fn propose_shielding<InputsT>(
        &mut self,
        input_selector: &InputsT,
        shielding_threshold: NonNegativeAmount,
        from_addrs: &[TransparentAddress],
        min_confirmations: u32,
    ) -> Result<
        Proposal<InputsT::FeeRule, Infallible>,
        data_api::error::Error<
            SqliteClientError,
            Infallible,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
        >,
    >
    where
        InputsT: ShieldingSelector<InputSource = WalletDb<Connection, LocalNetwork>>,
    {
        let params = self.network();
        propose_shielding::<_, _, _, Infallible>(
            &mut self.db_data,
            &params,
            input_selector,
            shielding_threshold,
            from_addrs,
            min_confirmations,
        )
    }

    /// Invokes [`create_proposed_transactions`] with the given arguments.
    pub(crate) fn create_proposed_transactions<InputsErrT, FeeRuleT>(
        &mut self,
        usk: &UnifiedSpendingKey,
        ovk_policy: OvkPolicy,
        proposal: &Proposal<FeeRuleT, ReceivedNoteId>,
    ) -> Result<
        NonEmpty<TxId>,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            InputsErrT,
            FeeRuleT::Error,
        >,
    >
    where
        FeeRuleT: FeeRule,
    {
        let params = self.network();
        let prover = test_prover();
        create_proposed_transactions(
            &mut self.db_data,
            &params,
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
    pub(crate) fn shield_transparent_funds<InputsT>(
        &mut self,
        input_selector: &InputsT,
        shielding_threshold: NonNegativeAmount,
        usk: &UnifiedSpendingKey,
        from_addrs: &[TransparentAddress],
        min_confirmations: u32,
    ) -> Result<
        NonEmpty<TxId>,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
        >,
    >
    where
        InputsT: ShieldingSelector<InputSource = WalletDb<Connection, LocalNetwork>>,
    {
        let params = self.network();
        let prover = test_prover();
        shield_transparent_funds(
            &mut self.db_data,
            &params,
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
        account: AccountId,
        min_confirmations: u32,
        f: F,
    ) -> T {
        let binding = self.get_wallet_summary(min_confirmations).unwrap();
        f(binding.account_balances().get(&account).unwrap())
    }

    pub(crate) fn get_total_balance(&self, account: AccountId) -> NonNegativeAmount {
        self.with_account_balance(account, 0, |balance| balance.total())
    }

    pub(crate) fn get_spendable_balance(
        &self,
        account: AccountId,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.spendable_value()
        })
    }

    pub(crate) fn get_pending_shielded_balance(
        &self,
        account: AccountId,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.value_pending_spendability() + balance.change_pending_confirmation()
        })
        .unwrap()
    }

    #[allow(dead_code)]
    pub(crate) fn get_pending_change(
        &self,
        account: AccountId,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.change_pending_confirmation()
        })
    }

    pub(crate) fn get_wallet_summary(
        &self,
        min_confirmations: u32,
    ) -> Option<WalletSummary<AccountId>> {
        get_wallet_summary(
            &self.wallet().conn.unchecked_transaction().unwrap(),
            &self.wallet().params,
            min_confirmations,
            &SubtreeScanProgress,
        )
        .unwrap()
    }

    /// Returns a vector of transaction summaries
    pub(crate) fn get_tx_history(
        &self,
    ) -> Result<Vec<TransactionSummary<AccountId>>, SqliteClientError> {
        let mut stmt = self.wallet().conn.prepare_cached(
            "SELECT * 
             FROM v_transactions 
             ORDER BY mined_height DESC, tx_index DESC",
        )?;

        let results = stmt
            .query_and_then::<TransactionSummary<AccountId>, SqliteClientError, _, _>([], |row| {
                Ok(TransactionSummary {
                    account_id: AccountId(row.get("account_id")?),
                    txid: TxId::from_bytes(row.get("txid")?),
                    expiry_height: row
                        .get::<_, Option<u32>>("expiry_height")?
                        .map(BlockHeight::from),
                    mined_height: row
                        .get::<_, Option<u32>>("mined_height")?
                        .map(BlockHeight::from),
                    account_value_delta: ZatBalance::from_i64(row.get("account_balance_delta")?)?,
                    fee_paid: row
                        .get::<_, Option<i64>>("fee_paid")?
                        .map(Zatoshis::from_nonnegative_i64)
                        .transpose()?,
                    has_change: row.get("has_change")?,
                    sent_note_count: row.get("sent_note_count")?,
                    received_note_count: row.get("received_note_count")?,
                    memo_count: row.get("memo_count")?,
                    expired_unmined: row.get("expired_unmined")?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    #[allow(dead_code)] // used only for tests that are flagged off by default
    pub(crate) fn get_checkpoint_history(
        &self,
    ) -> Result<Vec<(BlockHeight, ShieldedProtocol, Option<Position>)>, SqliteClientError> {
        let mut stmt = self.wallet().conn.prepare_cached(
            "SELECT checkpoint_id, 2 AS pool, position FROM sapling_tree_checkpoints
             UNION
             SELECT checkpoint_id, 3 AS pool, position FROM orchard_tree_checkpoints
             ORDER BY checkpoint_id",
        )?;

        let results = stmt
            .query_and_then::<_, SqliteClientError, _, _>([], |row| {
                Ok((
                    BlockHeight::from(row.get::<_, u32>(0)?),
                    match row.get::<_, i64>(1)? {
                        2 => ShieldedProtocol::Sapling,
                        3 => ShieldedProtocol::Orchard,
                        _ => unreachable!(),
                    },
                    row.get::<_, Option<u64>>(2)?.map(Position::from),
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }
}

pub(crate) struct TransactionSummary<AccountId> {
    account_id: AccountId,
    txid: TxId,
    expiry_height: Option<BlockHeight>,
    mined_height: Option<BlockHeight>,
    account_value_delta: ZatBalance,
    fee_paid: Option<Zatoshis>,
    has_change: bool,
    sent_note_count: usize,
    received_note_count: usize,
    memo_count: usize,
    expired_unmined: bool,
}

#[allow(dead_code)]
impl<AccountId> TransactionSummary<AccountId> {
    pub(crate) fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub(crate) fn txid(&self) -> TxId {
        self.txid
    }

    pub(crate) fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }

    pub(crate) fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }

    pub(crate) fn account_value_delta(&self) -> ZatBalance {
        self.account_value_delta
    }

    pub(crate) fn fee_paid(&self) -> Option<Zatoshis> {
        self.fee_paid
    }

    pub(crate) fn has_change(&self) -> bool {
        self.has_change
    }

    pub(crate) fn sent_note_count(&self) -> usize {
        self.sent_note_count
    }

    pub(crate) fn received_note_count(&self) -> usize {
        self.received_note_count
    }

    pub(crate) fn expired_unmined(&self) -> bool {
        self.expired_unmined
    }

    pub(crate) fn memo_count(&self) -> usize {
        self.memo_count
    }
}

/// Trait used by tests that require a full viewing key.
pub(crate) trait TestFvk {
    type Nullifier;

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

impl TestFvk for DiversifiableFullViewingKey {
    type Nullifier = Nullifier;

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
        _: u32,
        mut rng: &mut R,
    ) -> Self::Nullifier {
        // Generate a dummy nullifier
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
        req: AddressType,
        value: NonNegativeAmount,
        _: u32,
        rng: &mut R,
    ) -> Self::Nullifier {
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

        // Return the nullifier of the newly created output note
        note.nullifier(self)
    }
}

#[allow(dead_code)]
pub(crate) enum AddressType {
    DefaultExternal,
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
    let note = Note::from_parts(
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

/// Create a fake CompactBlock at the given height, containing a single output paying
/// an address. Returns the CompactBlock and the nullifier for the new note.
#[allow(clippy::too_many_arguments)]
fn fake_compact_block<P: consensus::Parameters, Fvk: TestFvk>(
    params: &P,
    height: BlockHeight,
    prev_hash: BlockHash,
    fvk: &Fvk,
    req: AddressType,
    value: NonNegativeAmount,
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
    mut rng: impl RngCore + CryptoRng,
) -> (CompactBlock, Fvk::Nullifier) {
    // Create a fake CompactBlock containing the note
    let mut ctx = fake_compact_tx(&mut rng);
    let nf = fvk.add_output(
        &mut ctx,
        params,
        height,
        req,
        value,
        initial_sapling_tree_size,
        &mut rng,
    );

    let cb = fake_compact_block_from_compact_tx(
        ctx,
        height,
        prev_hash,
        initial_sapling_tree_size,
        initial_orchard_tree_size,
        rng,
    );
    (cb, nf)
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
        Address::Transparent(_) => panic!("transparent addresses not supported in compact blocks"),
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
    cb.chain_metadata = Some(compact::ChainMetadata {
        sapling_commitment_tree_size: initial_sapling_tree_size
            + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        orchard_commitment_tree_size: initial_orchard_tree_size
            + cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum::<u32>(),
    });
    cb
}

/// Trait used by tests that require a block cache.
pub(crate) trait TestCache {
    type BlockSource: BlockSource;
    type InsertResult;

    /// Exposes the block cache as a [`BlockSource`].
    fn block_source(&self) -> &Self::BlockSource;

    /// Inserts a CompactBlock into the cache DB.
    fn insert(&self, cb: &CompactBlock) -> Self::InsertResult;
}

pub(crate) struct BlockCache {
    _cache_file: NamedTempFile,
    db_cache: BlockDb,
}

impl BlockCache {
    fn new() -> Self {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        BlockCache {
            _cache_file: cache_file,
            db_cache,
        }
    }
}

impl TestCache for BlockCache {
    type BlockSource = BlockDb;
    type InsertResult = ();

    fn block_source(&self) -> &Self::BlockSource {
        &self.db_cache
    }

    fn insert(&self, cb: &CompactBlock) {
        let cb_bytes = cb.encode_to_vec();
        self.db_cache
            .0
            .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
            .unwrap()
            .execute(params![u32::from(cb.height()), cb_bytes,])
            .unwrap();
    }
}

#[cfg(feature = "unstable")]
pub(crate) struct FsBlockCache {
    fsblockdb_root: TempDir,
    db_meta: FsBlockDb,
}

#[cfg(feature = "unstable")]
impl FsBlockCache {
    fn new() -> Self {
        let fsblockdb_root = tempfile::tempdir().unwrap();
        let mut db_meta = FsBlockDb::for_path(&fsblockdb_root).unwrap();
        init_blockmeta_db(&mut db_meta).unwrap();

        FsBlockCache {
            fsblockdb_root,
            db_meta,
        }
    }
}

#[cfg(feature = "unstable")]
impl TestCache for FsBlockCache {
    type BlockSource = FsBlockDb;
    type InsertResult = BlockMeta;

    fn block_source(&self) -> &Self::BlockSource {
        &self.db_meta
    }

    fn insert(&self, cb: &CompactBlock) -> Self::InsertResult {
        use std::io::Write;

        let meta = BlockMeta {
            height: cb.height(),
            block_hash: cb.hash(),
            block_time: cb.time,
            sapling_outputs_count: cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum(),
            orchard_actions_count: cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum(),
        };

        let blocks_dir = self.fsblockdb_root.as_ref().join("blocks");
        let block_path = meta.block_file_path(&blocks_dir);

        File::create(block_path)
            .unwrap()
            .write_all(&cb.encode_to_vec())
            .unwrap();

        meta
    }
}

pub(crate) fn input_selector(
    fee_rule: StandardFeeRule,
    change_memo: Option<&str>,
    fallback_change_pool: ShieldedProtocol,
) -> GreedyInputSelector<
    WalletDb<rusqlite::Connection, LocalNetwork>,
    standard::SingleOutputChangeStrategy,
> {
    let change_memo = change_memo.map(|m| MemoBytes::from(m.parse::<Memo>().unwrap()));
    let change_strategy =
        standard::SingleOutputChangeStrategy::new(fee_rule, change_memo, fallback_change_pool);
    GreedyInputSelector::new(change_strategy, DustOutputPolicy::default())
}

// Checks that a protobuf proposal serialized from the provided proposal value correctly parses to
// the same proposal value.
fn check_proposal_serialization_roundtrip(
    db_data: &WalletDb<rusqlite::Connection, LocalNetwork>,
    proposal: &Proposal<StandardFeeRule, ReceivedNoteId>,
) {
    let proposal_proto = proposal::Proposal::from_standard_proposal(proposal);
    let deserialized_proposal = proposal_proto.try_into_standard_proposal(db_data);
    assert_matches!(deserialized_proposal, Ok(r) if &r == proposal);
}
