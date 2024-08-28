use std::collections::{hash_map::Entry, HashMap};

use zcash_primitives::{
    consensus::BlockHeight,
    transaction::{Transaction, TxId},
};
use zcash_protocol::value::Zatoshis;

use zcash_client_backend::{data_api::TransactionStatus, wallet::WalletTx};

use crate::AccountId;

use crate::error::Error;

/// Maps a block height and transaction index to a transaction ID.
pub struct TxLocatorMap(HashMap<(BlockHeight, u32), TxId>);

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
    pub fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }
    pub fn status(&self) -> TransactionStatus {
        self.tx_status
    }
    pub fn tx_index(&self) -> Option<u32> {
        self.tx_index
    }
    pub fn fee(&self) -> Option<Zatoshis> {
        self.fee
    }
    pub fn target_height(&self) -> Option<BlockHeight> {
        self.target_height
    }
    pub fn raw(&self) -> &[u8] {
        self.raw.as_slice()
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
    pub fn get_transaction(&self, txid: TxId) -> Option<&TransactionEntry> {
        self.0.get(&txid)
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
            Err(Error::TransactionNotFound(*txid))
        }
    }
    pub fn get_tx_raw(&self, txid: &TxId) -> Option<&[u8]> {
        self.0.get(txid).map(|entry| entry.raw.as_slice())
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
