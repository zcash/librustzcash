use std::convert::Infallible;
use std::fmt;
use std::num::NonZeroU32;

#[cfg(feature = "unstable")]
use std::fs::File;

use nonempty::NonEmpty;
use prost::Message;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rusqlite::{params, Connection};
use secrecy::{Secret, SecretVec};
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
        chain::{scan_cached_blocks, BlockSource, ScanSummary},
        wallet::{
            create_proposed_transactions, create_spend_to_address,
            input_selection::{GreedyInputSelector, GreedyInputSelectorError, InputSelector},
            propose_standard_transfer_to_address, propose_transfer, spend,
        },
        AccountBalance, AccountBirthday, WalletRead, WalletSummary, WalletWrite,
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
    data_api::AccountSources,
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
    group::ff::{Field, PrimeField},
    orchard::note_encryption::{OrchardDomain, OrchardNoteEncryption},
    pasta_curves::pallas,
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

/// A builder for a `zcash_client_sqlite` test.
pub(crate) struct TestBuilder<Cache> {
    network: LocalNetwork,
    cache: Cache,
    test_account_birthday: Option<AccountBirthday>,
    rng: ChaChaRng,
}

impl TestBuilder<()> {
    /// Constructs a new test.
    pub(crate) fn new() -> Self {
        TestBuilder {
            // Use a fake network where Sapling through NU5 activate at the same height.
            // We pick 100,000 to be large enough to handle any hard-coded test offsets.
            network: LocalNetwork {
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
            },
            cache: (),
            test_account_birthday: None,
            rng: ChaChaRng::seed_from_u64(0),
        }
    }

    /// Adds a [`BlockDb`] cache to the test.
    pub(crate) fn with_block_cache(self) -> TestBuilder<BlockCache> {
        TestBuilder {
            network: self.network,
            cache: BlockCache::new(),
            test_account_birthday: self.test_account_birthday,
            rng: self.rng,
        }
    }

    /// Adds a [`FsBlockDb`] cache to the test.
    #[cfg(feature = "unstable")]
    pub(crate) fn with_fs_block_cache(self) -> TestBuilder<FsBlockCache> {
        TestBuilder {
            network: self.network,
            cache: FsBlockCache::new(),
            test_account_birthday: self.test_account_birthday,
            rng: self.rng,
        }
    }
}

impl<Cache> TestBuilder<Cache> {
    pub(crate) fn with_test_account<F: FnOnce(&LocalNetwork) -> AccountBirthday>(
        mut self,
        birthday: F,
    ) -> Self {
        self.test_account_birthday = Some(birthday(&self.network));
        self
    }

    /// Builds the state for this test.
    pub(crate) fn build(self) -> TestState<Cache> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), self.network).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        let test_account = if let Some(birthday) = self.test_account_birthday {
            let seed = Secret::new(vec![0u8; 32]);
            let (account, usk) = db_data.create_account(&seed, birthday.clone()).unwrap();
            Some((seed, account, usk, birthday))
        } else {
            None
        };

        TestState {
            cache: self.cache,
            latest_cached_block: None,
            _data_file: data_file,
            db_data,
            test_account,
            rng: self.rng,
        }
    }
}

pub(crate) struct CachedBlock {
    height: BlockHeight,
    hash: BlockHash,
    sapling_end_size: u32,
    orchard_end_size: u32,
}

impl CachedBlock {
    fn none(sapling_activation_height: BlockHeight) -> Self {
        Self {
            height: sapling_activation_height,
            hash: BlockHash([0; 32]),
            sapling_end_size: 0,
            orchard_end_size: 0,
        }
    }

    fn at(
        height: BlockHeight,
        hash: BlockHash,
        sapling_tree_size: u32,
        orchard_tree_size: u32,
    ) -> Self {
        Self {
            height,
            hash,
            sapling_end_size: sapling_tree_size,
            orchard_end_size: orchard_tree_size,
        }
    }

    fn roll_forward(self, cb: &CompactBlock) -> Self {
        assert_eq!(self.height + 1, cb.height());
        Self {
            height: cb.height(),
            hash: cb.hash(),
            sapling_end_size: self.sapling_end_size
                + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
            orchard_end_size: self.orchard_end_size
                + cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum::<u32>(),
        }
    }
}

/// The state for a `zcash_client_sqlite` test.
pub(crate) struct TestState<Cache> {
    cache: Cache,
    latest_cached_block: Option<CachedBlock>,
    _data_file: NamedTempFile,
    db_data: WalletDb<Connection, LocalNetwork>,
    test_account: Option<(
        SecretVec<u8>,
        AccountId,
        UnifiedSpendingKey,
        AccountBirthday,
    )>,
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
        self.latest_cached_block.as_ref()
    }

    /// Creates a fake block at the expected next height containing a single output of the
    /// given value, and inserts it into the cache.
    pub(crate) fn generate_next_block<Fvk: TestFvk>(
        &mut self,
        fvk: &Fvk,
        req: AddressType,
        value: NonNegativeAmount,
    ) -> (BlockHeight, Cache::InsertResult, Fvk::Nullifier) {
        let cached_block = self
            .latest_cached_block
            .take()
            .unwrap_or_else(|| CachedBlock::none(self.sapling_activation_height() - 1));
        let height = cached_block.height + 1;

        let (res, nf) = self.generate_block_at(
            height,
            cached_block.hash,
            fvk,
            req,
            value,
            cached_block.sapling_end_size,
            cached_block.orchard_end_size,
        );
        assert!(self.latest_cached_block.is_some());

        (height, res, nf)
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
    ) -> (Cache::InsertResult, Fvk::Nullifier) {
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
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some(
            CachedBlock::at(
                height - 1,
                cb.hash(),
                initial_sapling_tree_size,
                initial_orchard_tree_size,
            )
            .roll_forward(&cb),
        );

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
        let cached_block = self
            .latest_cached_block
            .take()
            .unwrap_or_else(|| CachedBlock::none(self.sapling_activation_height() - 1));
        let height = cached_block.height + 1;

        let cb = fake_compact_block_spending(
            &self.network(),
            height,
            cached_block.hash,
            note,
            fvk,
            to.into(),
            value,
            cached_block.sapling_end_size,
            cached_block.orchard_end_size,
            &mut self.rng,
        );
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some(cached_block.roll_forward(&cb));

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
        let cached_block = self
            .latest_cached_block
            .take()
            .unwrap_or_else(|| CachedBlock::none(self.sapling_activation_height() - 1));
        let height = cached_block.height + 1;

        let cb = fake_compact_block_from_tx(
            height,
            cached_block.hash,
            tx_index,
            tx,
            cached_block.sapling_end_size,
            cached_block.orchard_end_size,
            &mut self.rng,
        );
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some(cached_block.roll_forward(&cb));

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
        scan_cached_blocks(
            &self.network(),
            self.cache.block_source(),
            &mut self.db_data,
            from_height,
            limit,
        )
    }

    /// Resets the wallet using a new wallet database but with the same cache of blocks,
    /// and returns the old wallet database file.
    ///
    /// This does not recreate accounts, nor does it rescan the cached blocks.
    /// The resulting wallet has no test account.
    /// Before using any `generate_*` method on the reset state, call `reset_latest_cached_block()`.
    pub(crate) fn reset(&mut self) -> NamedTempFile {
        let network = self.network();
        self.latest_cached_block = None;
        let tf = std::mem::replace(&mut self._data_file, NamedTempFile::new().unwrap());
        self.db_data = WalletDb::for_path(self._data_file.path(), network).unwrap();
        self.test_account = None;
        init_wallet_db(&mut self.db_data, None).unwrap();
        tf
    }

    /// Reset the latest cached block to the most recent one in the cache database.
    #[allow(dead_code)]
    pub(crate) fn reset_latest_cached_block(&mut self) {
        self.cache
            .block_source()
            .with_blocks::<_, Infallible>(None, None, |block: CompactBlock| {
                let chain_metadata = block.chain_metadata.unwrap();
                self.latest_cached_block = Some(CachedBlock::at(
                    BlockHeight::from_u32(block.height.try_into().unwrap()),
                    BlockHash::from_slice(block.hash.as_slice()),
                    chain_metadata.sapling_commitment_tree_size,
                    chain_metadata.orchard_commitment_tree_size,
                ));
                Ok(())
            })
            .unwrap();
    }
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
        self.test_account.as_ref().map(|(seed, _, _, _)| seed)
    }

    /// Exposes the test account, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_account(
        &self,
    ) -> Option<(
        AccountSources<AccountId>,
        UnifiedSpendingKey,
        AccountBirthday,
    )> {
        self.test_account.as_ref().map(|(_, a, k, b)| {
            (
                AccountSources::new(*a, k.has_orchard(), k.has_sapling(), k.has_transparent()),
                k.clone(),
                b.clone(),
            )
        })
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_account_sapling(&self) -> Option<DiversifiableFullViewingKey> {
        self.test_account
            .as_ref()
            .and_then(|(_, _, usk, _)| usk.to_unified_full_viewing_key().sapling().cloned())
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    #[cfg(feature = "orchard")]
    pub(crate) fn test_account_orchard(&self) -> Option<orchard::keys::FullViewingKey> {
        self.test_account
            .as_ref()
            .and_then(|(_, _, usk, _)| usk.to_unified_full_viewing_key().orchard().cloned())
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
        account_sources: AccountSources<AccountId>,
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
            account_sources,
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
        account_sources: AccountSources<AccountId>,
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
            account_sources,
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
            balance.sapling_balance().spendable_value()
        })
    }

    pub(crate) fn get_pending_shielded_balance(
        &self,
        account: AccountId,
        min_confirmations: u32,
    ) -> NonNegativeAmount {
        self.with_account_balance(account, min_confirmations, |balance| {
            balance.sapling_balance().value_pending_spendability()
                + balance.sapling_balance().change_pending_confirmation()
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
            balance.sapling_balance().change_pending_confirmation()
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
        nf: Self::Nullifier,
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
            nf,
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
        let nullifier =
            orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                .unwrap();

        let (j, scope) = match req {
            AddressType::DefaultExternal => (0u32.into(), zip32::Scope::External),
            AddressType::DiversifiedExternal(idx) => (idx, zip32::Scope::External),
            AddressType::Internal => (0u32.into(), zip32::Scope::Internal),
        };

        let (cact, note) = compact_orchard_action(
            nullifier,
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
        nf: Self::Nullifier,
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
            nf,
            self.address_at(j, scope),
            value,
            self.orchard_ovk(scope),
            rng,
        );
        ctx.actions.push(cact);

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
    nullifier: orchard::note::Nullifier,
    recipient: orchard::Address,
    value: NonNegativeAmount,
    ovk: Option<orchard::keys::OutgoingViewingKey>,
    rng: &mut R,
) -> (CompactOrchardAction, orchard::Note) {
    let nf = nullifier.to_bytes().to_vec();

    let rseed = {
        loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let rseed = orchard::note::RandomSeed::from_bytes(bytes, &nullifier);
            if rseed.is_some().into() {
                break rseed.unwrap();
            }
        }
    };
    let note = orchard::Note::from_parts(
        recipient,
        orchard::value::NoteValue::from_raw(value.into_u64()),
        nullifier,
        rseed,
    )
    .unwrap();
    let encryptor = OrchardNoteEncryption::new(ovk, note, *MemoBytes::empty().as_array());
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment())
        .to_bytes()
        .to_vec();
    let ephemeral_key = OrchardDomain::epk_bytes(encryptor.epk()).0.to_vec();
    let enc_ciphertext = encryptor.encrypt_note_plaintext();

    (
        CompactOrchardAction {
            nullifier: nf,
            cmx,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
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
    let proposal_proto = proposal::Proposal::from_standard_proposal(&db_data.params, proposal);
    let deserialized_proposal = proposal_proto.try_into_standard_proposal(&db_data.params, db_data);
    assert_matches!(deserialized_proposal, Ok(r) if &r == proposal);
}
