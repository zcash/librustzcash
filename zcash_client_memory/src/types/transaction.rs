use std::{
    collections::{BTreeMap, btree_map::Entry},
    ops::Deref,
};

use zcash_client_backend::{
    data_api::{TransactionStatus, wallet::TargetHeight},
    wallet::WalletTx,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::AccountId;
use crate::error::Error;

/// Maps a block height and transaction index to a transaction ID.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TxLocatorMap(pub(crate) BTreeMap<(BlockHeight, u32), TxId>);

impl Deref for TxLocatorMap {
    type Target = BTreeMap<(BlockHeight, u32), TxId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A table of received notes. Corresponds to sapling_received_notes and orchard_received_notes tables.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TransactionEntry {
    // created: String,
    /// mined_height is rolled into into a txn status
    tx_status: TransactionStatus,
    block: Option<BlockHeight>,
    tx_index: Option<u32>,
    expiry_height: Option<BlockHeight>,
    raw: Option<Vec<u8>>,
    fee: Option<Zatoshis>,
    /// - `target_height`: stores the target height for which the transaction was constructed, if
    ///   known. This will ordinarily be null for transactions discovered via chain scanning; it
    ///   will only be set for transactions created using this wallet specifically, and not any
    ///   other wallet that uses the same seed (including previous installations of the same
    ///   wallet application.)
    _target_height: Option<TargetHeight>,
}
impl TransactionEntry {
    pub fn new_from_tx_meta(tx_meta: WalletTx<AccountId>, height: BlockHeight) -> Self {
        Self {
            tx_status: TransactionStatus::Mined(height),
            tx_index: Some(tx_meta.block_index() as u32),
            block: Some(height),
            expiry_height: None,
            raw: None,
            fee: None,
            _target_height: None,
        }
    }
    pub(crate) fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }
    pub(crate) fn status(&self) -> TransactionStatus {
        self.tx_status
    }

    pub(crate) fn mined_height(&self) -> Option<BlockHeight> {
        match self.tx_status {
            TransactionStatus::Mined(height) => Some(height),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn fee(&self) -> Option<Zatoshis> {
        self.fee
    }

    pub(crate) fn raw(&self) -> Option<&[u8]> {
        self.raw.as_deref()
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn is_mined_or_unexpired_at(&self, height: BlockHeight) -> bool {
        match self.tx_status {
            TransactionStatus::Mined(tx_height) => tx_height <= height,
            TransactionStatus::NotInMainChain => self
                .expiry_height
                .is_some_and(|expiry_height| expiry_height > height),
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct TransactionTable(pub(crate) BTreeMap<TxId, TransactionEntry>);

impl TransactionTable {
    pub(crate) fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Returns transaction status for a given transaction ID. None if the transaction is not known.
    pub(crate) fn tx_status(&self, txid: &TxId) -> Option<TransactionStatus> {
        self.0.get(txid).map(|entry| entry.tx_status)
    }

    pub(crate) fn get_transaction(&self, txid: &TxId) -> Option<&TransactionEntry> {
        self.0.get(txid)
    }

    pub(crate) fn get_by_height_and_index(
        &self,
        height: BlockHeight,
        index: u32,
    ) -> Option<&TransactionEntry> {
        self.0
            .values()
            .find(|entry| entry.block == Some(height) && entry.tx_index == Some(index))
    }

    /// Inserts information about a MINED transaction that was observed to
    /// contain a note related to this wallet
    pub(crate) fn put_tx_meta(&mut self, tx_meta: WalletTx<AccountId>, height: BlockHeight) {
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

    #[cfg(feature = "transparent-inputs")]
    /// Insert partial transaction data ontained from a received transparent output
    /// Will update an existing transaction if it already exists with new date (e.g. will replace Nones with newer Some value)
    pub(crate) fn put_tx_partial(
        &mut self,
        txid: &TxId,
        block: &Option<BlockHeight>,
        mined_height: Option<BlockHeight>,
    ) {
        match self.0.entry(*txid) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().tx_status = mined_height
                    .map(TransactionStatus::Mined)
                    .unwrap_or(TransactionStatus::NotInMainChain);
                // replace the block if it's not already set
                entry.get_mut().block = (*block).or(entry.get().block);
            }
            Entry::Vacant(entry) => {
                entry.insert(TransactionEntry {
                    tx_status: mined_height
                        .map(TransactionStatus::Mined)
                        .unwrap_or(TransactionStatus::NotInMainChain),
                    block: *block,
                    tx_index: None,
                    expiry_height: None,
                    raw: None,
                    fee: None,
                    _target_height: None,
                });
            }
        }
    }

    /// Inserts full transaction data
    pub(crate) fn put_tx_data(
        &mut self,
        tx: &Transaction,
        fee: Option<Zatoshis>,
        target_height: Option<TargetHeight>,
    ) {
        match self.0.entry(tx.txid()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().fee = fee;
                entry.get_mut().expiry_height = Some(tx.expiry_height());

                let mut raw = Vec::new();
                tx.write(&mut raw).unwrap();
                entry.get_mut().raw = Some(raw);
            }
            Entry::Vacant(entry) => {
                let mut raw = Vec::new();
                tx.write(&mut raw).unwrap();
                entry.insert(TransactionEntry {
                    tx_status: TransactionStatus::NotInMainChain,
                    tx_index: None,
                    block: None,
                    expiry_height: Some(tx.expiry_height()),
                    raw: Some(raw),
                    fee,
                    _target_height: target_height,
                });
            }
        }
    }

    pub(crate) fn set_transaction_status(
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

    pub(crate) fn unmine_transactions_greater_than(&mut self, height: BlockHeight) {
        self.0.iter_mut().for_each(|(_, entry)| {
            if let TransactionStatus::Mined(tx_height) = entry.tx_status {
                if tx_height > height {
                    entry.tx_status = TransactionStatus::NotInMainChain;
                    entry.block = None;
                    entry.tx_index = None;
                }
            }
        });
    }
}

impl TransactionTable {
    pub(crate) fn get(&self, txid: &TxId) -> Option<&TransactionEntry> {
        self.0.get(txid)
    }

    pub(crate) fn _get_mut(&mut self, txid: &TxId) -> Option<&mut TransactionEntry> {
        self.0.get_mut(txid)
    }

    pub(crate) fn _remove(&mut self, txid: &TxId) -> Option<TransactionEntry> {
        self.0.remove(txid)
    }
}

impl Deref for TransactionTable {
    type Target = BTreeMap<TxId, TransactionEntry>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TxLocatorMap {
    pub(crate) fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub(crate) fn _insert(&mut self, height: BlockHeight, index: u32, txid: TxId) {
        self.0.insert((height, index), txid);
    }

    pub(crate) fn get(&self, height: BlockHeight, index: u32) -> Option<&TxId> {
        self.0.get(&(height, index))
    }
    pub(crate) fn entry(&mut self, k: (BlockHeight, u32)) -> Entry<'_, (BlockHeight, u32), TxId> {
        self.0.entry(k)
    }
}

mod serialization {
    use super::*;
    use crate::{proto::memwallet as proto, read_optional};

    impl From<TransactionEntry> for proto::TransactionEntry {
        fn from(entry: TransactionEntry) -> Self {
            Self {
                tx_status: match entry.tx_status {
                    TransactionStatus::TxidNotRecognized => {
                        proto::TransactionStatus::TxidNotRecognized.into()
                    }
                    TransactionStatus::NotInMainChain => {
                        proto::TransactionStatus::NotInMainChain.into()
                    }
                    TransactionStatus::Mined(_) => proto::TransactionStatus::Mined.into(),
                },
                block: entry.block.map(Into::into),
                tx_index: entry.tx_index,
                expiry_height: entry.expiry_height.map(Into::into),
                raw_tx: entry.raw,
                fee: entry.fee.map(Into::into),
                target_height: entry._target_height.map(Into::into),
                mined_height: match entry.tx_status {
                    TransactionStatus::Mined(height) => Some(height.into()),
                    _ => None,
                },
            }
        }
    }

    impl TryFrom<proto::TransactionEntry> for TransactionEntry {
        type Error = Error;

        fn try_from(entry: proto::TransactionEntry) -> Result<Self, Self::Error> {
            Ok(Self {
                tx_status: match entry.tx_status() {
                    proto::TransactionStatus::TxidNotRecognized => {
                        TransactionStatus::TxidNotRecognized
                    }
                    proto::TransactionStatus::NotInMainChain => TransactionStatus::NotInMainChain,
                    proto::TransactionStatus::Mined => {
                        TransactionStatus::Mined(read_optional!(entry, mined_height)?.into())
                    }
                },
                block: entry.block.map(Into::into),
                tx_index: entry.tx_index,
                expiry_height: entry.expiry_height.map(Into::into),
                raw: entry.raw_tx,
                fee: entry.fee.map(|fee| fee.try_into()).transpose()?,
                _target_height: entry
                    .target_height
                    .map(|h| TargetHeight::from(BlockHeight::from(h))),
            })
        }
    }
}
