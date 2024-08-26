#![allow(unused)]
use core::time;
use incrementalmerkletree::{Address, Marking, Position, Retention};
use sapling::NullifierDerivingKey;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    convert::Infallible,
    hash::Hash,
    num::NonZeroU32,
    ops::Deref,
    rc::Rc,
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
    ShieldedProtocol::{self, Orchard, Sapling},
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState, Account as _, AccountPurpose, AccountSource, SeedRelevance,
        SentTransactionOutput, TransactionDataRequest, TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{
        Note, NoteId, Recipient, WalletSaplingOutput, WalletSpend, WalletTransparentOutput,
        WalletTx,
    },
};

use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, scanning::ScanRange, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

use super::AccountId;

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "orchard")]
use {
    zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
    zcash_client_backend::wallet::WalletOrchardOutput,
};

use crate::error::Error;

/// Maps a block height and transaction index to a transaction ID.
pub struct TxLocatorMap(HashMap<(BlockHeight, u32), TxId>);

/// Maps a block height and transaction (i.e. transaction locator) index to a nullifier.
pub struct NullifierMap(BTreeMap<Nullifier, (BlockHeight, u32)>);

/// Keeps track of notes that are spent in which transaction
pub struct ReceievdNoteSpends(HashMap<NoteId, TxId>);

pub struct ReceivedNoteTable(pub Vec<ReceivedNote>);

pub struct ReceivedNote {
    // Uniquely identifies this note
    pub note_id: NoteId,
    pub txid: TxId,
    // output_index: sapling, action_index: orchard
    pub output_index: u32,
    pub account_id: AccountId,
    //sapling: (diversifier, value, rcm) orchard: (diversifier, value, rho, rseed)
    pub note: Note,
    pub nf: Option<Nullifier>,
    pub is_change: bool,
    pub memo: Memo,
    pub commitment_tree_position: Option<Position>,
    pub recipient_key_scope: Option<Scope>,
}

/// A table of received notes. Corresponds to sapling_received_notes and orchard_received_notes tables.
pub struct TransactionEntry {
    // created: String,
    /// Combines block height and mined_height into a txn status
    tx_status: TransactionStatus,
    tx_index: Option<u32>,
    expiry_height: Option<BlockHeight>,
    raw: Vec<u8>,
    fee: Option<Zatoshis>,
    /// - `target_height`: stores the target height for which the transaction was constructed, if
    ///   known. This will ordinarily be null for transactions discovered via chain scanning; it
    ///   will only be set for transactions created using this wallet specifically, and not any
    ///   other wallet that uses the same seed (including previous installations of the same
    ///   wallet application.)
    target_height: Option<BlockHeight>,
}
impl TransactionEntry {
    pub fn new_from_tx_meta(tx_meta: WalletTx<AccountId>, height: BlockHeight) -> Self {
        Self {
            tx_status: TransactionStatus::Mined(height),
            tx_index: Some(tx_meta.block_index() as u32),
            expiry_height: None,
            raw: Vec::new(),
            fee: None,
            target_height: None,
        }
    }
}
pub struct TransactionTable(HashMap<TxId, TransactionEntry>);
impl TransactionTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
    /// Returns transaction status for a given transaction ID. None if the transaction is not known.
    pub fn tx_status(&self, txid: &TxId) -> Option<TransactionStatus> {
        self.0.get(txid).map(|entry| entry.tx_status)
    }
    pub fn expiry_height(&self, txid: &TxId) -> Option<BlockHeight> {
        self.0.get(txid).and_then(|entry| entry.expiry_height)
    }
    /// Inserts information about a MINED transaction that was observed to
    /// contain a note related to this wallet
    pub fn put_tx_meta(&mut self, tx_meta: WalletTx<AccountId>, height: BlockHeight) {
        match self.0.entry(tx_meta.txid()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().tx_index = Some(tx_meta.block_index() as u32);
                entry.get_mut().tx_status = TransactionStatus::Mined(height);
            }
            Entry::Vacant(entry) => {
                entry.insert(TransactionEntry::new_from_tx_meta(tx_meta, height));
            }
        }
    }
    /// Inserts full transaction data
    pub fn put_tx_data(
        &mut self,
        tx: &Transaction,
        fee: Option<Zatoshis>,
        target_height: Option<BlockHeight>,
    ) {
        match self.0.entry(tx.txid()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().fee = fee;
                entry.get_mut().expiry_height = Some(tx.expiry_height());
                entry.get_mut().raw = Vec::new();
                tx.write(&mut entry.get_mut().raw).unwrap();
            }
            Entry::Vacant(entry) => {
                let mut raw = Vec::new();
                tx.write(&mut raw).unwrap();
                entry.insert(TransactionEntry {
                    tx_status: TransactionStatus::NotInMainChain,
                    tx_index: None,
                    expiry_height: Some(tx.expiry_height()),
                    raw,
                    fee,
                    target_height,
                });
            }
        }
    }
    pub fn set_transaction_status(
        &mut self,
        txid: &TxId,
        status: TransactionStatus,
    ) -> Result<(), Error> {
        if let Some(entry) = self.0.get_mut(txid) {
            entry.tx_status = status;
            Ok(())
        } else {
            return Err(Error::TransactionNotFound(*txid));
        }
    }
}

impl ReceivedNote {
    pub fn pool(&self) -> PoolType {
        match self.note {
            Note::Sapling { .. } => PoolType::SAPLING,
            #[cfg(feature = "orchard")]
            Note::Orchard { .. } => PoolType::ORCHARD,
        }
    }
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }
    pub fn nullifier(&self) -> Option<&Nullifier> {
        self.nf.as_ref()
    }
    pub fn txid(&self) -> TxId {
        self.txid
    }
    pub fn note_id(&self) -> NoteId {
        self.note_id
    }
    pub fn from_sent_tx_output(
        txid: TxId,
        output: &SentTransactionOutput<AccountId>,
    ) -> Result<Self, Error> {
        match output.recipient() {
            Recipient::InternalAccount {
                receiving_account,
                note: Note::Sapling(note),
                ..
            } => Ok(ReceivedNote {
                note_id: NoteId::new(txid, Sapling, output.output_index() as u16),
                txid: txid,
                output_index: output.output_index() as u32,
                account_id: *receiving_account,
                note: Note::Sapling(note.clone()),
                nf: None,
                is_change: true,
                memo: output.memo().map(|m| Memo::try_from(m).unwrap()).unwrap(),
                commitment_tree_position: None,
                recipient_key_scope: Some(Scope::Internal),
            }),
            #[cfg(feature = "orchard")]
            Recipient::InternalAccount {
                receiving_account,
                note: Note::Orchard(note),
                ..
            } => Ok(ReceivedNote {
                note_id: NoteId::new(txid, Orchard, output.output_index() as u16),
                txid: txid,
                output_index: output.output_index() as u32,
                account_id: *receiving_account,
                note: Note::Orchard(note.clone()),
                nf: None,
                is_change: true,
                memo: output.memo().map(|m| Memo::try_from(m).unwrap()).unwrap(),
                commitment_tree_position: None,
                recipient_key_scope: Some(Scope::Internal),
            }),
            _ => Err(Error::Other(
                "Recipient is not an internal shielded account".to_owned(),
            )),
        }
    }
    pub fn from_wallet_sapling_output(
        note_id: NoteId,
        output: &WalletSaplingOutput<AccountId>,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            output_index: output.index() as u32,
            account_id: *output.account_id(),
            note: Note::Sapling(output.note().clone()),
            nf: output.nf().map(|nf| Nullifier::Sapling(*nf)),
            is_change: output.is_change(),
            memo: Memo::Empty,
            commitment_tree_position: Some(output.note_commitment_tree_position()),
            recipient_key_scope: output.recipient_key_scope(),
        }
    }
    #[cfg(feature = "orchard")]
    pub fn from_wallet_orchard_output(
        note_id: NoteId,
        output: &WalletOrchardOutput<AccountId>,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            output_index: output.index() as u32,
            account_id: *output.account_id(),
            note: Note::Orchard(output.note().clone()),
            nf: output.nf().map(|nf| Nullifier::Orchard(*nf)),
            is_change: output.is_change(),
            memo: Memo::Empty,
            commitment_tree_position: Some(output.note_commitment_tree_position()),
            recipient_key_scope: output.recipient_key_scope(),
        }
    }
}

impl ReceivedNoteTable {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn get_sapling_nullifiers(
        &self,
    ) -> impl Iterator<Item = (AccountId, TxId, sapling::Nullifier)> + '_ {
        self.0.iter().filter_map(|entry| {
            if let Some(Nullifier::Sapling(nf)) = entry.nullifier() {
                Some((entry.account_id(), entry.txid(), *nf))
            } else {
                None
            }
        })
    }
    #[cfg(feature = "orchard")]
    pub fn get_orchard_nullifiers(
        &self,
    ) -> impl Iterator<Item = (AccountId, TxId, orchard::note::Nullifier)> + '_ {
        self.0.iter().filter_map(|entry| {
            if let Some(Nullifier::Orchard(nf)) = entry.nullifier() {
                Some((entry.account_id(), entry.txid(), *nf))
            } else {
                None
            }
        })
    }

    pub fn insert_received_note(&mut self, note: ReceivedNote) {
        self.0.push(note);
    }
}

impl TransactionTable {
    pub fn get(&self, txid: &TxId) -> Option<&TransactionEntry> {
        self.0.get(txid)
    }

    pub fn get_mut(&mut self, txid: &TxId) -> Option<&mut TransactionEntry> {
        self.0.get_mut(txid)
    }

    pub fn remove(&mut self, txid: &TxId) -> Option<TransactionEntry> {
        self.0.remove(txid)
    }
}
impl NullifierMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn insert(&mut self, height: BlockHeight, index: u32, nullifier: Nullifier) {
        self.0.insert(nullifier, (height, index));
    }

    pub fn get(&self, nullifier: &Nullifier) -> Option<&(BlockHeight, u32)> {
        self.0.get(nullifier)
    }
}
impl TxLocatorMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
    pub fn insert(&mut self, height: BlockHeight, index: u32, txid: TxId) {
        self.0.insert((height, index), txid);
    }

    pub fn get(&self, height: BlockHeight, index: u32) -> Option<&TxId> {
        self.0.get(&(height, index))
    }
    pub fn entry(&mut self, k: (BlockHeight, u32)) -> Entry<(BlockHeight, u32), TxId> {
        self.0.entry(k)
    }
}
impl ReceievdNoteSpends {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
    pub fn insert_spend(&mut self, note_id: NoteId, txid: TxId) -> Option<TxId> {
        self.0.insert(note_id, txid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Nullifier {
    #[cfg(feature = "orchard")]
    Orchard(orchard::note::Nullifier),
    Sapling(sapling::Nullifier),
}

impl Nullifier {
    pub fn pool(&self) -> PoolType {
        match self {
            #[cfg(feature = "orchard")]
            Nullifier::Orchard(_) => PoolType::ORCHARD,
            Nullifier::Sapling(_) => PoolType::SAPLING,
        }
    }
}
#[cfg(feature = "orchard")]
impl From<orchard::note::Nullifier> for Nullifier {
    fn from(n: orchard::note::Nullifier) -> Self {
        Nullifier::Orchard(n)
    }
}
impl From<sapling::Nullifier> for Nullifier {
    fn from(n: sapling::Nullifier) -> Self {
        Nullifier::Sapling(n)
    }
}
