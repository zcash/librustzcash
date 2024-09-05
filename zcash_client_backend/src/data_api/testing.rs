//! Utilities for testing wallets based upon the [`zcash_client_backend::data_api`] traits.
use incrementalmerkletree::Address;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{collections::HashMap, convert::Infallible, num::NonZeroU32};
use zcash_protocol::value::{ZatBalance, Zatoshis};
use zip32::fingerprint::SeedFingerprint;

use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network},
    memo::Memo,
    transaction::{components::amount::NonNegativeAmount, Transaction, TxId},
};

use crate::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
    ShieldedProtocol,
};

use super::{
    chain::{ChainState, CommitmentTreeRoot},
    scanning::ScanRange,
    AccountBirthday, AccountPurpose, BlockMetadata, DecryptedTransaction, InputSource,
    NullifierQuery, ScannedBlock, SeedRelevance, SentTransaction, SpendableNotes,
    TransactionDataRequest, TransactionStatus, WalletCommitmentTrees, WalletRead, WalletSummary,
    WalletWrite, SAPLING_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::TransparentAddressMetadata, std::ops::Range,
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "orchard")]
use super::ORCHARD_SHARD_HEIGHT;

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
                let root_addr = Address::from_parts(SAPLING_SHARD_HEIGHT.into(), start_index + i);
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
                let root_addr = Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), start_index + i);
                t.insert(root_addr, *root.root_hash())?;
            }
            Ok::<_, ShardTreeError<Self::Error>>(())
        })?;

        Ok(())
    }
}
