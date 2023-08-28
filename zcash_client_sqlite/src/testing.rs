use std::convert::Infallible;
use std::fmt;
use std::{collections::HashMap, num::NonZeroU32};

#[cfg(feature = "unstable")]
use std::fs::File;

use prost::Message;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection};
use secrecy::SecretVec;
use tempfile::NamedTempFile;

#[cfg(feature = "unstable")]
use tempfile::TempDir;

#[allow(deprecated)]
use zcash_client_backend::data_api::wallet::create_spend_to_address;
use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{
        self,
        chain::{scan_cached_blocks, BlockSource},
        wallet::{
            create_proposed_transaction,
            input_selection::{GreedyInputSelectorError, InputSelector, Proposal},
            propose_transfer, spend,
        },
    },
    keys::{sapling, UnifiedFullViewingKey, UnifiedSpendingKey},
    proto::compact_formats::{
        self as compact, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    },
    wallet::OvkPolicy,
    zip321,
};
use zcash_note_encryption::Domain;
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
    legacy::TransparentAddress,
    memo::MemoBytes,
    sapling::{
        note_encryption::{sapling_note_encryption, SaplingDomain},
        util::generate_random_rseed,
        value::NoteValue,
        Note, Nullifier, PaymentAddress,
    },
    transaction::{
        components::{amount::BalanceError, Amount},
        fees::FeeRule,
        TxId,
    },
    zip32::{sapling::DiversifiableFullViewingKey, DiversifierIndex},
};

#[cfg(feature = "transparent-inputs")]
use zcash_client_backend::data_api::wallet::shield_transparent_funds;
#[cfg(feature = "transparent-inputs")]
use zcash_primitives::{
    legacy, legacy::keys::IncomingViewingKey, transaction::components::amount::NonNegativeAmount,
};

use crate::{
    chain::init::init_cache_database,
    error::SqliteClientError,
    wallet::{
        commitment_tree,
        init::{init_accounts_table, init_wallet_db},
        sapling::tests::test_prover,
    },
    AccountId, ReceivedNoteId, WalletDb,
};

use super::BlockDb;

#[cfg(feature = "unstable")]
use crate::{
    chain::{init::init_blockmeta_db, BlockMeta},
    FsBlockDb,
};
/// A builder for a `zcash_client_sqlite` test.
pub(crate) struct TestBuilder<Cache> {
    cache: Cache,
    seed: Option<SecretVec<u8>>,
    with_test_account: bool,
}

impl TestBuilder<()> {
    /// Constructs a new test.
    pub(crate) fn new() -> Self {
        TestBuilder {
            cache: (),
            seed: None,
            with_test_account: false,
        }
    }

    /// Adds a [`BlockDb`] cache to the test.
    pub(crate) fn with_block_cache(self) -> TestBuilder<BlockCache> {
        TestBuilder {
            cache: BlockCache::new(),
            seed: self.seed,
            with_test_account: self.with_test_account,
        }
    }

    /// Adds a [`FsBlockDb`] cache to the test.
    #[cfg(feature = "unstable")]
    pub(crate) fn with_fs_block_cache(self) -> TestBuilder<FsBlockCache> {
        TestBuilder {
            cache: FsBlockCache::new(),
            seed: self.seed,
            with_test_account: self.with_test_account,
        }
    }
}

impl<Cache> TestBuilder<Cache> {
    /// Gives the test knowledge of the wallet seed for initialization.
    pub(crate) fn with_seed(mut self, seed: SecretVec<u8>) -> Self {
        // TODO remove
        self.seed = Some(seed);
        self
    }

    pub(crate) fn with_test_account(mut self) -> Self {
        self.with_test_account = true;
        self
    }

    /// Builds the state for this test.
    pub(crate) fn build(self) -> TestState<Cache> {
        let params = network();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), params).unwrap();
        init_wallet_db(&mut db_data, self.seed).unwrap();

        let test_account = if self.with_test_account {
            // Add an account to the wallet
            Some(init_test_accounts_table_ufvk(&mut db_data))
        } else {
            None
        };

        TestState {
            params,
            cache: self.cache,
            latest_cached_block: None,
            _data_file: data_file,
            db_data,
            test_account,
        }
    }
}

/// The state for a `zcash_client_sqlite` test.
pub(crate) struct TestState<Cache> {
    params: Network,
    cache: Cache,
    latest_cached_block: Option<(BlockHeight, BlockHash, u32)>,
    _data_file: NamedTempFile,
    db_data: WalletDb<Connection, Network>,
    test_account: Option<(UnifiedFullViewingKey, Option<TransparentAddress>)>,
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

    /// Creates a fake block at the expected next height containing a single output of the
    /// given value, and inserts it into the cache.
    pub(crate) fn generate_next_block(
        &mut self,
        dfvk: &DiversifiableFullViewingKey,
        req: AddressType,
        value: Amount,
    ) -> (BlockHeight, Cache::InsertResult, Nullifier) {
        let (height, prev_hash, initial_sapling_tree_size) = self
            .latest_cached_block
            .map(|(prev_height, prev_hash, end_size)| (prev_height + 1, prev_hash, end_size))
            .unwrap_or_else(|| (sapling_activation_height(), BlockHash([0; 32]), 0));

        let (res, nf) = self.generate_block_at(
            height,
            prev_hash,
            dfvk,
            req,
            value,
            initial_sapling_tree_size,
        );

        (height, res, nf)
    }

    /// Creates a fake block with the given height and hash containing a single output of
    /// the given value, and inserts it into the cache.
    ///
    /// This generated block will be treated as the latest block, and subsequent calls to
    /// [`Self::generate_next_block`] will build on it.
    pub(crate) fn generate_block_at(
        &mut self,
        height: BlockHeight,
        prev_hash: BlockHash,
        dfvk: &DiversifiableFullViewingKey,
        req: AddressType,
        value: Amount,
        initial_sapling_tree_size: u32,
    ) -> (Cache::InsertResult, Nullifier) {
        let (cb, nf) = fake_compact_block(
            height,
            prev_hash,
            dfvk,
            req,
            value,
            initial_sapling_tree_size,
        );
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some((
            height,
            cb.hash(),
            initial_sapling_tree_size
                + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ));

        (res, nf)
    }

    /// Creates a fake block at the expected next height spending the given note, and
    /// inserts it into the cache.
    pub(crate) fn generate_next_block_spending(
        &mut self,
        dfvk: &DiversifiableFullViewingKey,
        note: (Nullifier, Amount),
        to: PaymentAddress,
        value: Amount,
    ) -> (BlockHeight, Cache::InsertResult) {
        let (height, prev_hash, initial_sapling_tree_size) = self
            .latest_cached_block
            .map(|(prev_height, prev_hash, end_size)| (prev_height + 1, prev_hash, end_size))
            .unwrap_or_else(|| (sapling_activation_height(), BlockHash([0; 32]), 0));

        let cb = fake_compact_block_spending(
            height,
            prev_hash,
            note,
            dfvk,
            to,
            value,
            initial_sapling_tree_size,
        );
        let res = self.cache.insert(&cb);

        self.latest_cached_block = Some((
            height,
            cb.hash(),
            initial_sapling_tree_size
                + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ));

        (height, res)
    }

    /// Invokes [`scan_cached_blocks`] with the given arguments, expecting success.
    pub(crate) fn scan_cached_blocks(&mut self, from_height: BlockHeight, limit: usize) {
        self.try_scan_cached_blocks(from_height, limit)
            .expect("should succeed for this test");
    }

    /// Invokes [`scan_cached_blocks`] with the given arguments.
    pub(crate) fn try_scan_cached_blocks(
        &mut self,
        from_height: BlockHeight,
        limit: usize,
    ) -> Result<
        (),
        data_api::chain::error::Error<
            SqliteClientError,
            <Cache::BlockSource as BlockSource>::Error,
        >,
    > {
        scan_cached_blocks(
            &self.params,
            self.cache.block_source(),
            &mut self.db_data,
            from_height,
            limit,
        )
    }
}

impl<Cache> TestState<Cache> {
    /// Exposes an immutable reference to the test's [`WalletDb`].
    pub(crate) fn wallet(&self) -> &WalletDb<Connection, Network> {
        &self.db_data
    }

    /// Exposes a mutable reference to the test's [`WalletDb`].
    pub(crate) fn wallet_mut(&mut self) -> &mut WalletDb<Connection, Network> {
        &mut self.db_data
    }

    /// Exposes the test account, if enabled via [`TestBuilder::with_test_account`].
    #[cfg(feature = "unstable")]
    pub(crate) fn test_account(
        &self,
    ) -> Option<(UnifiedFullViewingKey, Option<TransparentAddress>)> {
        self.test_account.as_ref().cloned()
    }

    /// Exposes the test account's Sapling DFVK, if enabled via [`TestBuilder::with_test_account`].
    pub(crate) fn test_account_sapling(&self) -> Option<DiversifiableFullViewingKey> {
        self.test_account
            .as_ref()
            .map(|(ufvk, _)| ufvk.sapling().unwrap().clone())
    }

    /// Invokes [`create_spend_to_address`] with the given arguments.
    #[allow(deprecated)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn create_spend_to_address(
        &mut self,
        usk: &UnifiedSpendingKey,
        to: &RecipientAddress,
        amount: Amount,
        memo: Option<MemoBytes>,
        ovk_policy: OvkPolicy,
        min_confirmations: NonZeroU32,
    ) -> Result<
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            GreedyInputSelectorError<BalanceError, ReceivedNoteId>,
            Infallible,
            ReceivedNoteId,
        >,
    > {
        create_spend_to_address(
            &mut self.db_data,
            &self.params,
            test_prover(),
            usk,
            to,
            amount,
            memo,
            ovk_policy,
            min_confirmations,
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
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
            ReceivedNoteId,
        >,
    >
    where
        InputsT: InputSelector<DataSource = WalletDb<Connection, Network>>,
    {
        spend(
            &mut self.db_data,
            &self.params,
            test_prover(),
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
            ReceivedNoteId,
        >,
    >
    where
        InputsT: InputSelector<DataSource = WalletDb<Connection, Network>>,
    {
        propose_transfer::<_, _, _, Infallible>(
            &mut self.db_data,
            &self.params,
            spend_from_account,
            input_selector,
            request,
            min_confirmations,
        )
    }

    /// Invokes [`create_proposed_transaction`] with the given arguments.
    pub(crate) fn create_proposed_transaction<FeeRuleT>(
        &mut self,
        usk: &UnifiedSpendingKey,
        ovk_policy: OvkPolicy,
        proposal: Proposal<FeeRuleT, ReceivedNoteId>,
        min_confirmations: NonZeroU32,
        change_memo: Option<MemoBytes>,
    ) -> Result<
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            Infallible,
            FeeRuleT::Error,
            ReceivedNoteId,
        >,
    >
    where
        FeeRuleT: FeeRule,
    {
        create_proposed_transaction::<_, _, Infallible, _>(
            &mut self.db_data,
            &self.params,
            test_prover(),
            usk,
            ovk_policy,
            proposal,
            min_confirmations,
            change_memo,
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
        memo: &MemoBytes,
        min_confirmations: NonZeroU32,
    ) -> Result<
        TxId,
        data_api::error::Error<
            SqliteClientError,
            commitment_tree::Error,
            InputsT::Error,
            <InputsT::FeeRule as FeeRule>::Error,
            ReceivedNoteId,
        >,
    >
    where
        InputsT: InputSelector<DataSource = WalletDb<Connection, Network>>,
    {
        shield_transparent_funds(
            &mut self.db_data,
            &self.params,
            test_prover(),
            input_selector,
            shielding_threshold,
            usk,
            from_addrs,
            memo,
            min_confirmations,
        )
    }
}

#[cfg(feature = "mainnet")]
pub(crate) fn network() -> Network {
    Network::MainNetwork
}

#[cfg(not(feature = "mainnet"))]
pub(crate) fn network() -> Network {
    Network::TestNetwork
}

#[cfg(feature = "mainnet")]
pub(crate) fn sapling_activation_height() -> BlockHeight {
    Network::MainNetwork
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap()
}

#[cfg(not(feature = "mainnet"))]
pub(crate) fn sapling_activation_height() -> BlockHeight {
    Network::TestNetwork
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap()
}

#[cfg(test)]
pub(crate) fn init_test_accounts_table_ufvk(
    db_data: &mut WalletDb<rusqlite::Connection, Network>,
) -> (UnifiedFullViewingKey, Option<TransparentAddress>) {
    let seed = [0u8; 32];
    let account = AccountId::from(0);
    let extsk = sapling::spending_key(&seed, network().coin_type(), account);
    let dfvk = extsk.to_diversifiable_full_viewing_key();

    #[cfg(feature = "transparent-inputs")]
    let (tkey, taddr) = {
        let tkey = legacy::keys::AccountPrivKey::from_seed(&network(), &seed, account)
            .unwrap()
            .to_account_pubkey();
        let taddr = tkey.derive_external_ivk().unwrap().default_address().0;
        (Some(tkey), Some(taddr))
    };

    #[cfg(not(feature = "transparent-inputs"))]
    let taddr = None;

    let ufvk = UnifiedFullViewingKey::new(
        #[cfg(feature = "transparent-inputs")]
        tkey,
        Some(dfvk),
        None,
    )
    .unwrap();

    let ufvks = HashMap::from([(account, ufvk.clone())]);
    init_accounts_table(db_data, &ufvks).unwrap();

    (ufvk, taddr)
}

#[allow(dead_code)]
pub(crate) enum AddressType {
    DefaultExternal,
    DiversifiedExternal(DiversifierIndex),
    Internal,
}

/// Create a fake CompactBlock at the given height, containing a single output paying
/// an address. Returns the CompactBlock and the nullifier for the new note.
pub(crate) fn fake_compact_block(
    height: BlockHeight,
    prev_hash: BlockHash,
    dfvk: &DiversifiableFullViewingKey,
    req: AddressType,
    value: Amount,
    initial_sapling_tree_size: u32,
) -> (CompactBlock, Nullifier) {
    let to = match req {
        AddressType::DefaultExternal => dfvk.default_address().1,
        AddressType::DiversifiedExternal(idx) => dfvk.find_address(idx).unwrap().1,
        AddressType::Internal => dfvk.change_address().1,
    };

    // Create a fake Note for the account
    let mut rng = OsRng;
    let rseed = generate_random_rseed(&network(), height, &mut rng);
    let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
    let encryptor = sapling_note_encryption::<_, Network>(
        Some(dfvk.fvk().ovk),
        note.clone(),
        MemoBytes::empty(),
        &mut rng,
    );
    let cmu = note.cmu().to_bytes().to_vec();
    let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
        .0
        .to_vec();
    let enc_ciphertext = encryptor.encrypt_note_plaintext();

    // Create a fake CompactBlock containing the note
    let cout = CompactSaplingOutput {
        cmu,
        ephemeral_key,
        ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
    };
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.hash = txid;
    ctx.outputs.push(cout);
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
        ..Default::default()
    });
    (cb, note.nf(&dfvk.fvk().vk.nk, 0))
}

/// Create a fake CompactBlock at the given height, spending a single note from the
/// given address.
pub(crate) fn fake_compact_block_spending(
    height: BlockHeight,
    prev_hash: BlockHash,
    (nf, in_value): (Nullifier, Amount),
    dfvk: &DiversifiableFullViewingKey,
    to: PaymentAddress,
    value: Amount,
    initial_sapling_tree_size: u32,
) -> CompactBlock {
    let mut rng = OsRng;
    let rseed = generate_random_rseed(&network(), height, &mut rng);

    // Create a fake CompactBlock containing the note
    let cspend = CompactSaplingSpend { nf: nf.to_vec() };
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.hash = txid;
    ctx.spends.push(cspend);

    // Create a fake Note for the payment
    ctx.outputs.push({
        let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        }
    });

    // Create a fake Note for the change
    ctx.outputs.push({
        let change_addr = dfvk.default_address().1;
        let rseed = generate_random_rseed(&network(), height, &mut rng);
        let note = Note::from_parts(
            change_addr,
            NoteValue::from_raw((in_value - value).unwrap().into()),
            rseed,
        );
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        }
    });

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
        ..Default::default()
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
