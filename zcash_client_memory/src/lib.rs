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
mod error;
pub mod types;
pub mod wallet_commitment_trees;
pub mod wallet_read;
pub mod wallet_write;
pub(crate) use types::*;

/// The ID type for accounts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct AccountId(u32);

impl Deref for AccountId {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The main in-memory wallet database. Implements all the traits needed to be used as a backend.
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
    pub(crate) fn mark_sapling_note_spent(
        &mut self,
        nf: sapling::Nullifier,
        txid: TxId,
    ) -> Result<(), Error> {
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

    pub(crate) fn get_account_mut(&mut self, account_id: AccountId) -> Option<&mut Account> {
        self.accounts.get_mut(*account_id as usize)
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn mark_orchard_note_spent(
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

    pub(crate) fn max_zip32_account_index(
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
    pub(crate) fn insert_received_sapling_note(
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
    pub(crate) fn insert_received_orchard_note(
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
    pub(crate) fn insert_sapling_nullifier_map(
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
    pub(crate) fn insert_orchard_nullifier_map(
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
