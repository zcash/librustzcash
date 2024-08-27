#![allow(unused)]
use core::time;
use incrementalmerkletree::{Address, Marking, Retention};
use sapling::NullifierDerivingKey;
use scanning::ScanQueue;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    convert::Infallible,
    hash::Hash,
    num::NonZeroU32,
    ops::Deref,
};
use zcash_keys::keys::{AddressGenerationError, DerivationError, UnifiedIncomingViewingKey};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex, Scope};

use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network},
    transaction::{components::OutPoint, txid, Authorized, Transaction, TransactionData, TxId},
};
use zcash_protocol::{
    memo::{self, Memo, MemoBytes},
    value::{ZatBalance, Zatoshis},
    PoolType,
    ShieldedProtocol::{Orchard, Sapling},
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState, Account as _, AccountPurpose, AccountSource, SeedRelevance,
        TransactionDataRequest, TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    proto::service::ShieldedProtocol,
    wallet::{Note, NoteId, WalletSaplingOutput, WalletSpend, WalletTransparentOutput, WalletTx},
};

use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, scanning::ScanRange, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "orchard")]
use zcash_client_backend::{data_api::ORCHARD_SHARD_HEIGHT, wallet::WalletOrchardOutput};

use crate::error::Error;

mod scanning;
mod tables;
mod wallet_commitment_trees;
mod wallet_read;
mod wallet_write;
use tables::*;

struct MemoryWalletBlock {
    height: BlockHeight,
    hash: BlockHash,
    block_time: u32,
    // Just the transactions that involve an account in this wallet
    transactions: HashSet<TxId>,
    memos: HashMap<NoteId, MemoBytes>,
    sapling_commitment_tree_size: Option<u32>,
    sapling_output_count: Option<u32>,
    #[cfg(feature = "orchard")]
    orchard_commitment_tree_size: Option<u32>,
    #[cfg(feature = "orchard")]
    orchard_action_count: Option<u32>,
}

pub struct MemoryWalletDb {
    network: Network,
    accounts: Vec<Account>,
    blocks: BTreeMap<BlockHeight, MemoryWalletBlock>,

    tx_table: TransactionTable,

    received_notes: ReceivedNoteTable,
    receieved_note_spends: ReceievdNoteSpends,
    nullifiers: NullifierMap,

    tx_locator: TxLocatorMap,

    scan_queue: ScanQueue,

    sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >,
    #[cfg(feature = "orchard")]
    orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
}
impl MemoryWalletDb {
    pub fn new(network: Network, max_checkpoints: usize) -> Self {
        Self {
            network,
            accounts: Vec::new(),
            blocks: BTreeMap::new(),
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            #[cfg(feature = "orchard")]
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            tx_table: TransactionTable::new(),
            received_notes: ReceivedNoteTable::new(),
            nullifiers: NullifierMap::new(),
            tx_locator: TxLocatorMap::new(),
            receieved_note_spends: ReceievdNoteSpends::new(),
            scan_queue: ScanQueue::new(),
        }
    }
    fn mark_sapling_note_spent(&mut self, nf: sapling::Nullifier, txid: TxId) -> Result<(), Error> {
        let note_id = self
            .received_notes
            .0
            .iter()
            .filter(|v| v.nullifier() == Some(&Nullifier::Sapling(nf)))
            .map(|v| v.note_id())
            .next()
            .ok_or_else(|| Error::NoteNotFound)?;
        self.receieved_note_spends.insert_spend(note_id, txid);
        Ok(())
    }

    fn get_account_mut(&mut self, account_id: AccountId) -> Option<&mut Account> {
        self.accounts.get_mut(*account_id as usize)
    }

    #[cfg(feature = "orchard")]
    fn mark_orchard_note_spent(
        &mut self,
        nf: orchard::note::Nullifier,
        txid: TxId,
    ) -> Result<(), Error> {
        let note_id = self
            .received_notes
            .0
            .iter()
            .filter(|v| v.nullifier() == Some(&Nullifier::Orchard(nf)))
            .map(|v| v.note_id())
            .next()
            .ok_or_else(|| Error::NoteNotFound)?;
        self.receieved_note_spends.insert_spend(note_id, txid);
        Ok(())
    }

    fn max_zip32_account_index(
        &self,
        seed_fingerprint: &SeedFingerprint,
    ) -> Result<Option<zip32::AccountId>, Error> {
        Ok(self
            .accounts
            .iter()
            .filter_map(|a| match a.source() {
                AccountSource::Derived {
                    seed_fingerprint: sf,
                    account_index,
                } => {
                    if &sf == seed_fingerprint {
                        Some(account_index)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .max())
    }
    pub fn insert_received_sapling_note(
        &mut self,
        note_id: NoteId,
        output: &WalletSaplingOutput<AccountId>,
        spent_in: Option<TxId>,
    ) {
        self.received_notes
            .insert_received_note(ReceivedNote::from_wallet_sapling_output(note_id, output));
        if let Some(spent_in) = spent_in {
            self.receieved_note_spends.insert_spend(note_id, spent_in);
        }
    }
    #[cfg(feature = "orchard")]
    pub fn insert_received_orchard_note(
        &mut self,
        note_id: NoteId,
        output: &WalletOrchardOutput<AccountId>,
        spent_in: Option<TxId>,
    ) {
        self.received_notes
            .insert_received_note(ReceivedNote::from_wallet_orchard_output(note_id, output));
        if let Some(spent_in) = spent_in {
            self.receieved_note_spends.insert_spend(note_id, spent_in);
        }
    }
    fn insert_sapling_nullifier_map(
        &mut self,
        block_height: BlockHeight,
        new_entries: &[(TxId, u16, Vec<sapling::Nullifier>)],
    ) -> Result<(), Error> {
        for (txid, tx_index, nullifiers) in new_entries {
            match self.tx_locator.entry((block_height, *tx_index as u32)) {
                Entry::Occupied(x) => {
                    if txid == x.get() {
                        // This is a duplicate entry
                        continue;
                    } else {
                        return Err(Error::ConflictingTxLocator);
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(*txid);
                }
            }
            for nf in nullifiers.iter() {
                self.nullifiers
                    .insert(block_height, *tx_index as u32, Nullifier::Sapling(*nf));
            }
        }
        Ok(())
    }

    #[cfg(feature = "orchard")]
    fn insert_orchard_nullifier_map(
        &mut self,
        block_height: BlockHeight,
        new_entries: &[(TxId, u16, Vec<orchard::note::Nullifier>)],
    ) -> Result<(), Error> {
        for (txid, tx_index, nullifiers) in new_entries {
            match self.tx_locator.entry((block_height, *tx_index as u32)) {
                Entry::Occupied(x) => {
                    if txid == x.get() {
                        // This is a duplicate entry
                        continue;
                    } else {
                        return Err(Error::ConflictingTxLocator);
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(*txid);
                }
            }
            for nf in nullifiers.iter() {
                self.nullifiers
                    .insert(block_height, *tx_index as u32, Nullifier::Orchard(*nf));
            }
        }
        Ok(())
    }
}

/// The viewing key that an [`Account`] has available to it.
#[derive(Debug, Clone)]
pub(crate) enum ViewingKey {
    /// A full viewing key.
    ///
    /// This is available to derived accounts, as well as accounts directly imported as
    /// full viewing keys.
    Full(Box<UnifiedFullViewingKey>),

    /// An incoming viewing key.
    ///
    /// Accounts that have this kind of viewing key cannot be used in wallet contexts,
    /// because they are unable to maintain an accurate balance.
    Incoming(Box<UnifiedIncomingViewingKey>),
}

/// The ID type for accounts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct AccountId(u32);

impl Deref for AccountId {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An account stored in a `zcash_client_sqlite` database.
#[derive(Debug, Clone)]
pub struct Account {
    account_id: AccountId,
    kind: AccountSource,
    viewing_key: ViewingKey,
    birthday: AccountBirthday,
    purpose: AccountPurpose, // TODO: Remove this. AccountSource should be sufficient.
    addresses: BTreeMap<DiversifierIndex, UnifiedAddress>,
    notes: HashSet<NoteId>,
}

impl Account {
    fn new(
        account_id: AccountId,
        kind: AccountSource,
        viewing_key: ViewingKey,
        birthday: AccountBirthday,
        purpose: AccountPurpose,
    ) -> Result<Self, Error> {
        let mut acc = Self {
            account_id,
            kind,
            viewing_key,
            birthday,
            purpose,
            addresses: BTreeMap::new(),
            notes: HashSet::new(),
        };
        let ua_request = acc
            .viewing_key
            .uivk()
            .to_address_request()
            .and_then(|ua_request| ua_request.intersect(&UnifiedAddressRequest::all().unwrap()))
            .ok_or_else(|| {
                Error::AddressGeneration(AddressGenerationError::ShieldedReceiverRequired)
            })?;

        let (addr, diversifier_index) = acc.default_address(ua_request)?;
        acc.addresses.insert(diversifier_index, addr);
        Ok(acc)
    }
    /// Returns the default Unified Address for the account,
    /// along with the diversifier index that generated it.
    ///
    /// The diversifier index may be non-zero if the Unified Address includes a Sapling
    /// receiver, and there was no valid Sapling receiver at diversifier index zero.
    pub(crate) fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.uivk().default_address(request)
    }

    fn birthday(&self) -> &AccountBirthday {
        &self.birthday
    }

    fn addresses(&self) -> &BTreeMap<DiversifierIndex, UnifiedAddress> {
        &self.addresses
    }

    fn current_address(&self) -> Option<(DiversifierIndex, UnifiedAddress)> {
        self.addresses
            .last_key_value()
            .map(|(diversifier_index, address)| (*diversifier_index, address.clone()))
    }
    fn kind(&self) -> &AccountSource {
        &self.kind
    }
    fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }
    fn next_available_address(
        &mut self,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Error> {
        match self.ufvk() {
            Some(ufvk) => {
                let search_from = match self.current_address() {
                    Some((mut last_diversifier_index, _)) => {
                        last_diversifier_index
                            .increment()
                            .map_err(|_| AddressGenerationError::DiversifierSpaceExhausted)?;
                        last_diversifier_index
                    }
                    None => DiversifierIndex::default(),
                };
                let (addr, diversifier_index) = ufvk.find_address(search_from, request)?;
                self.addresses.insert(diversifier_index, addr.clone());
                Ok(Some(addr))
            }
            None => Ok(None),
        }
    }
}

impl zcash_client_backend::data_api::Account<AccountId> for Account {
    fn id(&self) -> AccountId {
        self.account_id
    }

    fn source(&self) -> AccountSource {
        self.kind
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        self.viewing_key.ufvk()
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.viewing_key.uivk()
    }
}

impl ViewingKey {
    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        match self {
            ViewingKey::Full(ufvk) => Some(ufvk),
            ViewingKey::Incoming(_) => None,
        }
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        match self {
            ViewingKey::Full(ufvk) => ufvk.as_ref().to_unified_incoming_viewing_key(),
            ViewingKey::Incoming(uivk) => uivk.as_ref().clone(),
        }
    }
}

impl PartialEq for MemoryWalletBlock {
    fn eq(&self, other: &Self) -> bool {
        (self.height, self.block_time) == (other.height, other.block_time)
    }
}

impl Eq for MemoryWalletBlock {}

impl PartialOrd for MemoryWalletBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some((self.height, self.block_time).cmp(&(other.height, other.block_time)))
    }
}

impl Ord for MemoryWalletBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.height, self.block_time).cmp(&(other.height, other.block_time))
    }
}
