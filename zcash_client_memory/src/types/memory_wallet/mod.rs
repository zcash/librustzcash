#![allow(dead_code)]

mod serialization;

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    num::NonZeroU32,
    ops::{Range, RangeInclusive},
};

use ::transparent::bundle::OutPoint;
#[cfg(feature = "transparent-inputs")]
use ::transparent::keys::NonHardenedChildIndex;
use incrementalmerkletree::{Address, Level, Marking, Position, Retention};
use scanning::ScanQueue;
use shardtree::{
    ShardTree,
    store::{ShardStore, memory::MemoryShardStore},
};
#[cfg(feature = "transparent-inputs")]
use zcash_client_backend::wallet::TransparentAddressMetadata;
use zcash_client_backend::{
    data_api::{
        Account as _, AccountBirthday, AccountSource, InputSource, Ratio, SAPLING_SHARD_HEIGHT,
        TransactionStatus, WalletRead,
        scanning::{ScanPriority, ScanRange},
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{NoteId, WalletSaplingOutput},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    ShieldedProtocol, TxId,
    consensus::{self, BlockHeight, NetworkUpgrade},
};
use zip32::{Scope, fingerprint::SeedFingerprint};

#[cfg(feature = "orchard")]
use zcash_client_backend::{data_api::ORCHARD_SHARD_HEIGHT, wallet::WalletOrchardOutput};

#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::address::TransparentAddress,
    zcash_client_backend::wallet::WalletTransparentOutput,
};

use crate::error::Error;
use crate::types::transparent::{
    TransparentReceivedOutputSpends, TransparentReceivedOutputs, TransparentSpendCache,
};
use crate::types::*;

/// The main in-memory wallet database. Implements all the traits needed to be used as a backend.
#[derive(Debug)]
pub struct MemoryWalletDb<P: consensus::Parameters> {
    /// Zcash network parameters for wallet
    pub(crate) params: P,
    /// The accounts in the wallet
    pub(crate) accounts: Accounts,
    /// The wallet that have been scanned and cached that contain relevant wallet data
    pub(crate) blocks: BTreeMap<BlockHeight, MemoryWalletBlock>,
    /// Scanned transactions relevant to accounts in this wallet
    pub(crate) tx_table: TransactionTable,
    /// Notes that an account has received
    pub(crate) received_notes: ReceivedNoteTable,
    /// Notes that have been spent
    pub(crate) received_note_spends: ReceievedNoteSpends,
    /// Nullifiers for notes that have been spent
    pub(crate) nullifiers: NullifierMap,
    /// Stores the outputs of transactions created by the wallet.
    pub(crate) sent_notes: SentNoteTable,
    /// Maps transaction ids to their block height and index
    pub(crate) tx_locator: TxLocatorMap,
    /// Sapling commitment tree
    pub(crate) sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >,
    /// Stores the block height corresponding to the last note commitment in a shard
    pub(crate) sapling_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    /// Orchard commitment tree
    #[cfg(feature = "orchard")]
    pub(crate) orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
    #[cfg(feature = "orchard")]
    /// Stores the block height corresponding to the last note commitment in a shard
    pub(crate) orchard_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,

    /// Transparent outputs received by the wallet
    pub(crate) transparent_received_outputs: TransparentReceivedOutputs,
    /// Transparent outputs received by the wallet that have been spent
    pub(crate) transparent_received_output_spends: TransparentReceivedOutputSpends,
    /// Map between transparent outpoints and their spend transactions
    pub(crate) transparent_spend_map: TransparentSpendCache,

    /// Pending requests to the external data provider to enhance transaction data
    pub(crate) transaction_data_request_queue: TransactionDataRequestQueue,
    /// Queue of block ranges that should be scanned along with their priority
    pub(crate) scan_queue: ScanQueue,
}

impl<P: consensus::Parameters + PartialEq> PartialEq for MemoryWalletDb<P> {
    /// Tests for equality between two `MemoryWalletDb` instances.
    /// but does NOT compare the sapling_tree and orchard_tree fields.
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "orchard")]
        let orchard_comparisons =
            { self.orchard_tree_shard_end_heights == other.orchard_tree_shard_end_heights };
        #[cfg(not(feature = "orchard"))]
        let orchard_comparisons = true;

        #[cfg(feature = "transparent-inputs")]
        let transparent_comparisons = {
            self.transparent_received_outputs == other.transparent_received_outputs
                && self.transparent_received_output_spends
                    == other.transparent_received_output_spends
                && self.transparent_spend_map == other.transparent_spend_map
        };
        #[cfg(not(feature = "transparent-inputs"))]
        let transparent_comparisons = true;

        self.params == other.params
            && self.accounts == other.accounts
            && self.blocks == other.blocks
            && self.tx_table == other.tx_table
            && self.received_notes == other.received_notes
            && self.received_note_spends == other.received_note_spends
            && self.nullifiers == other.nullifiers
            && self.sent_notes == other.sent_notes
            && self.tx_locator == other.tx_locator
            && self.scan_queue == other.scan_queue
            && self.sapling_tree_shard_end_heights == other.sapling_tree_shard_end_heights
            && orchard_comparisons
            && transparent_comparisons
            && self.transaction_data_request_queue == other.transaction_data_request_queue
    }
}

impl<P: consensus::Parameters> MemoryWalletDb<P> {
    pub fn new(params: P, max_checkpoints: usize) -> Self {
        Self {
            accounts: Accounts::new(),
            params,
            blocks: BTreeMap::new(),
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            sapling_tree_shard_end_heights: BTreeMap::new(),
            #[cfg(feature = "orchard")]
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            #[cfg(feature = "orchard")]
            orchard_tree_shard_end_heights: BTreeMap::new(),
            tx_table: TransactionTable::new(),
            received_notes: ReceivedNoteTable::new(),
            sent_notes: SentNoteTable::new(),
            nullifiers: NullifierMap::new(),
            tx_locator: TxLocatorMap::new(),
            received_note_spends: ReceievedNoteSpends::new(),
            scan_queue: ScanQueue::new(),
            transparent_received_outputs: TransparentReceivedOutputs::new(),
            transparent_received_output_spends: TransparentReceivedOutputSpends::new(),
            transparent_spend_map: TransparentSpendCache::new(),
            transaction_data_request_queue: TransactionDataRequestQueue::new(),
        }
    }

    pub fn params(&self) -> &P {
        &self.params
    }

    pub(crate) fn add_account(
        &mut self,
        account_name: &str,
        kind: AccountSource,
        viewing_key: UnifiedFullViewingKey,
        birthday: AccountBirthday,
    ) -> Result<(AccountId, Account), Error> {
        let (id, account) = self.accounts.new_account(
            account_name,
            kind,
            viewing_key.to_owned(),
            birthday.clone(),
        )?;

        // If a birthday frontier is available, insert it into the note commitment tree. If the
        // birthday frontier is the empty frontier, we don't need to do anything.
        if let Some(frontier) = birthday.sapling_frontier().value() {
            tracing::debug!("Inserting Sapling frontier into ShardTree: {:?}", frontier);
            self.sapling_tree.insert_frontier_nodes(
                frontier.clone(),
                Retention::Checkpoint {
                    // This subtraction is safe, because all leaves in the tree appear in blocks, and
                    // the invariant that birthday.height() always corresponds to the block for which
                    // `frontier` is the tree state at the start of the block. Together, this means
                    // there exists a prior block for which frontier is the tree state at the end of
                    // the block.
                    id: birthday.height() - 1,
                    marking: Marking::Reference,
                },
            )?;
        }

        #[cfg(feature = "orchard")]
        if let Some(frontier) = birthday.orchard_frontier().value() {
            tracing::debug!("Inserting Orchard frontier into ShardTree: {:?}", frontier);
            self.orchard_tree.insert_frontier_nodes(
                frontier.clone(),
                Retention::Checkpoint {
                    // This subtraction is safe, because all leaves in the tree appear in blocks, and
                    // the invariant that birthday.height() always corresponds to the block for which
                    // `frontier` is the tree state at the start of the block. Together, this means
                    // there exists a prior block for which frontier is the tree state at the end of
                    // the block.
                    id: birthday.height() - 1,
                    marking: Marking::Reference,
                },
            )?;
        }

        // The ignored range always starts at Sapling activation
        let sapling_activation_height = self
            .params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height must be available.");

        // Add the ignored range up to the birthday height.
        if sapling_activation_height < birthday.height() {
            let ignored_range = sapling_activation_height..birthday.height();
            self.scan_queue.replace_queue_entries(
                &ignored_range,
                Some(ScanRange::from_parts(
                    ignored_range.clone(),
                    ScanPriority::Ignored,
                ))
                .into_iter(),
                false,
            )?;
        };

        // Rewrite the scan ranges from the birthday height up to the chain tip so that we'll ensure we
        // re-scan to find any notes that might belong to the newly added account.
        if let Some(t) = self.chain_height()? {
            let rescan_range = birthday.height()..(t + 1);
            self.scan_queue.replace_queue_entries(
                &rescan_range,
                Some(ScanRange::from_parts(
                    rescan_range.clone(),
                    ScanPriority::Historic,
                ))
                .into_iter(),
                true, // force rescan
            )?;
        }

        Ok((id, account))
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn first_unsafe_index(&self, account_id: AccountId) -> Result<u32, Error> {
        let first_unmined_index = if let Some(account) = self.accounts.get(account_id) {
            let mut idx = 0;
            for (tidx, eph_addr) in account.ephemeral_addresses.iter().rev() {
                if eph_addr
                    .seen
                    .and_then(|txid| self.tx_table.get(&txid))
                    .and_then(|tx| tx.mined_height())
                    .is_some()
                {
                    idx = tidx.checked_add(1).unwrap();
                    break;
                }
            }
            idx
        } else {
            0
        };

        Ok(core::cmp::min(
            1 << 31,
            first_unmined_index
                .checked_add(account::EPHEMERAL_GAP_LIMIT)
                .unwrap(),
        ))
    }

    pub(crate) fn get_funding_accounts(
        &self,
        tx: &Transaction,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut funding_accounts = BTreeSet::new();
        #[cfg(feature = "transparent-inputs")]
        funding_accounts.extend(
            self.transparent_received_outputs.detect_spending_accounts(
                tx.transparent_bundle()
                    .iter()
                    .flat_map(|bundle| bundle.vin.iter().map(|txin| txin.prevout())),
            )?,
        );

        funding_accounts.extend(self.received_notes.detect_sapling_spending_accounts(
            tx.sapling_bundle().iter().flat_map(|bundle| {
                bundle
                    .shielded_spends()
                    .iter()
                    .map(|spend| spend.nullifier())
            }),
        )?);

        #[cfg(feature = "orchard")]
        funding_accounts.extend(
            self.received_notes.detect_orchard_spending_accounts(
                tx.orchard_bundle()
                    .iter()
                    .flat_map(|bundle| bundle.actions().iter().map(|action| action.nullifier())),
            )?,
        );

        Ok(funding_accounts)
    }

    pub(crate) fn get_received_notes(&self) -> &ReceivedNoteTable {
        &self.received_notes
    }

    // TODO: Update this if we switch from using a vec to store received notes to
    // someething with more efficient lookups
    pub(crate) fn get_received_note(&self, note_id: NoteId) -> Option<&ReceivedNote> {
        self.received_notes.iter().find(|v| v.note_id() == note_id)
    }

    pub(crate) fn mark_sapling_note_spent(
        &mut self,
        nf: sapling::Nullifier,
        txid: TxId,
    ) -> Result<(), Error> {
        let note_id = self
            .received_notes
            .iter()
            .filter(|v| v.nullifier() == Some(&Nullifier::Sapling(nf)))
            .map(|v| v.note_id())
            .next()
            .ok_or(Error::NoteNotFound)?;
        self.received_note_spends.insert_spend(note_id, txid);
        Ok(())
    }

    /// Returns true if the note is in the spent notes table and the transaction that spent it is
    /// in the transaction table and has either been mined or can be mined in the future
    /// (i.e. it hasn't or will not expire)
    pub(crate) fn note_is_spent(
        &self,
        note: &ReceivedNote,
        target_height: TargetHeight,
    ) -> Result<bool, Error> {
        let spend = self.received_note_spends.get(&note.note_id());

        let spent = match spend {
            Some(txid) => {
                let spending_tx = self
                    .tx_table
                    .get(txid)
                    .ok_or(Error::TransactionNotFound(*txid))?;
                match spending_tx.status() {
                    TransactionStatus::Mined(_height) => true,
                    TransactionStatus::TxidNotRecognized => unreachable!(),
                    TransactionStatus::NotInMainChain => {
                        // transaction either never expires, or expires in the future.
                        spending_tx
                            .expiry_height()
                            .iter()
                            .all(|h| *h >= BlockHeight::from(target_height))
                    }
                }
            }
            None => false,
        };
        Ok(spent)
    }

    /// To be spendable a note must be:
    /// - unspent (obviously)
    /// - not dust (value > 5000 ZATs)
    /// - be associated with an account with a ufvk
    /// - have a recipient key scope
    /// - We know the nullifier
    /// - We know the commitment tree position
    /// - be in a block less than or equal to the anchor height
    /// - not be in the given exclude list
    ///
    /// Additionally the tree shard containing the node must not be in an unscanned range
    /// excluding ranges that start above the anchor height or end below the wallet birthday.
    /// This is determined by looking at the scan queue
    pub(crate) fn note_is_spendable(
        &self,
        note: &ReceivedNote,
        birthday_height: BlockHeight,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[<MemoryWalletDb<P> as InputSource>::NoteRef],
    ) -> Result<bool, Error> {
        let note_account = self
            .get_account(note.account_id())?
            .ok_or(Error::AccountUnknown(note.account_id))?;
        let note_txn = self
            .tx_table
            .get(&note.txid())
            .ok_or_else(|| Error::TransactionNotFound(note.txid()))?;

        let unscanned_ranges = self.unscanned_ranges();
        let anchor_height = target_height - u32::from(confirmations_policy.trusted());

        let note_in_unscanned_range =
            unscanned_ranges
                .iter()
                .any(|(start_height, end_height, start, end_exclusive)| {
                    let in_range = note.commitment_tree_position.is_some_and(|pos| {
                        if let (Some(start), Some(end_exclusive)) = (start, end_exclusive) {
                            pos >= *start && pos < *end_exclusive
                        } else {
                            true
                        }
                    });
                    in_range && *end_height > birthday_height && *start_height <= anchor_height
                });

        Ok(!self.note_is_spent(note, target_height)?
            && !note_in_unscanned_range
            && note.note.value().into_u64() > 5000
            && note_account.ufvk().is_some()
            && note.nullifier().is_some()
            && note.commitment_tree_position.is_some()
            && note_txn.mined_height().is_some()
            && match note.recipient_key_scope {
                Some(Scope::External) => {
                    target_height.saturating_sub(u32::from(confirmations_policy.untrusted()))
                        >= note_txn.mined_height().unwrap()
                }
                Some(Scope::Internal) => {
                    target_height.saturating_sub(u32::from(confirmations_policy.trusted()))
                        >= note_txn.mined_height().unwrap()
                }
                None => false,
            }
            && !exclude.contains(&note.note_id()))
    }

    /// To be pending a note must be:
    /// - mined, but without sufficient confirmations to be spent; or
    /// - unmined and unexpired
    pub(crate) fn note_is_pending(
        &self,
        note: &ReceivedNote,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<bool, Error> {
        let tx = self
            .tx_table
            .get(&note.txid())
            .ok_or_else(|| Error::TransactionNotFound(note.txid()))?;

        Ok(tx.mined_height().map_or_else(
            || {
                tx.expiry_height()
                    .iter()
                    .all(|h| *h >= BlockHeight::from(target_height))
            },
            |h| match note.recipient_key_scope {
                // If we don't know the recipient key scope, we treat the note as untrusted.
                Some(Scope::External) | None => {
                    BlockHeight::from(target_height) - h
                        < u32::from(confirmations_policy.untrusted())
                }
                Some(Scope::Internal) => {
                    BlockHeight::from(target_height) - h < u32::from(confirmations_policy.trusted())
                }
            },
        ))
    }

    pub(crate) fn summary_height(
        &self,
        min_confirmations: u32,
    ) -> Result<Option<BlockHeight>, Error> {
        let chain_tip_height = match self.chain_height()? {
            Some(height) => height,
            None => return Ok(None),
        };
        let summary_height =
            (chain_tip_height + 1).saturating_sub(std::cmp::max(min_confirmations, 1));
        Ok(Some(summary_height))
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn mark_orchard_note_spent(
        &mut self,
        nf: orchard::note::Nullifier,
        txid: TxId,
    ) -> Result<(), Error> {
        let note_id = self
            .received_notes
            .iter()
            .filter(|v| v.nullifier() == Some(&Nullifier::Orchard(nf)))
            .map(|v| v.note_id())
            .next()
            .ok_or(Error::NoteNotFound)?;
        self.received_note_spends.insert_spend(note_id, txid);
        Ok(())
    }

    pub(crate) fn max_zip32_account_index(
        &self,
        seed_fingerprint: &SeedFingerprint,
    ) -> Result<Option<zip32::AccountId>, Error> {
        Ok(self
            .accounts
            .iter()
            .filter_map(|(_, a)| match a.source() {
                AccountSource::Derived { derivation, .. } => {
                    if derivation.seed_fingerprint() == seed_fingerprint {
                        Some(derivation.account_index())
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
            self.received_note_spends.insert_spend(note_id, spent_in);
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
            self.received_note_spends.insert_spend(note_id, spent_in);
        }
    }
    pub(crate) fn insert_sapling_nullifier_map(
        &mut self,
        block_height: BlockHeight,
        new_entries: &[(TxId, u16, Vec<sapling::Nullifier>)],
    ) -> Result<(), Error> {
        for (txid, tx_index, nullifiers) in new_entries {
            for nf in nullifiers.iter() {
                self.nullifiers
                    .insert(block_height, *tx_index as u32, Nullifier::Sapling(*nf));
            }
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
            for nf in nullifiers.iter() {
                self.nullifiers
                    .insert(block_height, *tx_index as u32, Nullifier::Orchard(*nf));
            }
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
        }
        Ok(())
    }

    pub(crate) fn block_height_extrema(&self) -> Option<RangeInclusive<BlockHeight>> {
        let (min, max) = self.blocks.keys().fold((None, None), |(min, max), height| {
            (
                Some(min.map_or(height, |min| std::cmp::min(min, height))),
                Some(max.map_or(height, |max| std::cmp::max(max, height))),
            )
        });
        if let (Some(min), Some(max)) = (min, max) {
            Some(*min..=*max)
        } else {
            None
        }
    }

    pub(crate) fn sapling_tip_shard_end_height(&self) -> Option<BlockHeight> {
        self.sapling_tree_shard_end_heights.values().max().copied()
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn orchard_tip_shard_end_height(&self) -> Option<BlockHeight> {
        self.orchard_tree_shard_end_heights.values().max().copied()
    }

    pub(crate) fn get_sapling_max_checkpointed_height(
        &self,
        chain_tip_height: BlockHeight,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<BlockHeight>, Error> {
        let max_checkpoint_height =
            u32::from(chain_tip_height).saturating_sub(u32::from(min_confirmations) - 1);
        // scan backward and find the first checkpoint that matches a blockheight prior to max_checkpoint_height
        for height in (0..=max_checkpoint_height).rev() {
            let height = BlockHeight::from_u32(height);
            if self.sapling_tree.store().get_checkpoint(&height)?.is_some() {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn get_orchard_max_checkpointed_height(
        &self,
        chain_tip_height: BlockHeight,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<BlockHeight>, Error> {
        let max_checkpoint_height =
            u32::from(chain_tip_height).saturating_sub(u32::from(min_confirmations) - 1);
        // scan backward and find the first checkpoint that matches a blockheight prior to max_checkpoint_height
        for height in (0..=max_checkpoint_height).rev() {
            let height = BlockHeight::from_u32(height);
            if self.orchard_tree.store().get_checkpoint(&height)?.is_some() {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    /// Get the unscanned ranges from the scan queue and their corresponding sapling tree indices
    /// This can be used to determine if a note is in an unscanned range and therefore not spendable
    pub(crate) fn unscanned_ranges(
        &self,
    ) -> Vec<(BlockHeight, BlockHeight, Option<Position>, Option<Position>)> {
        self.scan_queue
            .iter()
            .filter(|(_, _, priority)| priority > &ScanPriority::Scanned)
            .map(|(start, end, _)| {
                (
                    *start,
                    *end,
                    self.first_subtree_for_height(start)
                        .map(|a| a.position_range_start()),
                    self.last_subtree_for_height(end)
                        .map(|a| a.position_range_end()),
                )
            })
            .collect()
    }

    /// Return the address of the last subtree in the sapling tree where note for a give block height was found
    pub(crate) fn last_subtree_for_height(&self, height: &BlockHeight) -> Option<Address> {
        self.sapling_tree_shard_end_heights
            .iter()
            .filter(|(_, h)| *h == height)
            .map(|(a, _)| *a)
            .max()
    }

    ///  Return the address of the first subtree in the sapling tree where note for a give block height was found
    pub(crate) fn first_subtree_for_height(&self, height: &BlockHeight) -> Option<Address> {
        // The first subtree is the last subtree for the previous height
        self.last_subtree_for_height(&height.saturating_sub(1))
    }

    /// Makes the required changes to the scan queue to reflect the completion of a scan
    pub(crate) fn scan_complete(
        &mut self,
        range: Range<BlockHeight>,
        wallet_note_positions: &[(ShieldedProtocol, Position)],
    ) -> Result<(), Error> {
        let wallet_birthday = self.get_wallet_birthday()?;

        // Determine the range of block heights for which we will be updating the scan queue.
        let extended_range = {
            // If notes have been detected in the scan, we need to extend any adjacent un-scanned
            // ranges starting from the wallet birthday to include the blocks needed to complete
            // the note commitment tree subtrees containing the positions of the discovered notes.
            // We will query by subtree index to find these bounds.
            let mut required_sapling_subtrees = BTreeSet::new();
            #[cfg(feature = "orchard")]
            let mut required_orchard_subtrees = BTreeSet::new();
            for (protocol, position) in wallet_note_positions {
                match protocol {
                    ShieldedProtocol::Sapling => {
                        required_sapling_subtrees.insert(
                            Address::above_position(SAPLING_SHARD_HEIGHT.into(), *position).index(),
                        );
                    }
                    ShieldedProtocol::Orchard => {
                        #[cfg(feature = "orchard")]
                        required_orchard_subtrees.insert(
                            Address::above_position(ORCHARD_SHARD_HEIGHT.into(), *position).index(),
                        );

                        #[cfg(not(feature = "orchard"))]
                        return Err(Error::OrchardNotEnabled);
                    }
                }
            }

            let extended_range = self.extend_range(
                &ShieldedProtocol::Sapling,
                &range,
                required_sapling_subtrees,
                self.params.activation_height(NetworkUpgrade::Sapling),
                wallet_birthday,
            )?;

            #[cfg(feature = "orchard")]
            let extended_range = self
                .extend_range(
                    &ShieldedProtocol::Orchard,
                    extended_range.as_ref().unwrap_or(&range),
                    required_orchard_subtrees,
                    self.params.activation_height(NetworkUpgrade::Nu5),
                    wallet_birthday,
                )?
                .or(extended_range);

            #[allow(clippy::let_and_return)]
            extended_range
        };

        let query_range = extended_range.clone().unwrap_or_else(|| range.clone());

        let scanned = ScanRange::from_parts(range.clone(), ScanPriority::Scanned);

        // If any of the extended range actually extends beyond the scanned range, we need to
        // scan that extension in order to make the found note(s) spendable. We need to avoid
        // creating empty ranges here, as that acts as an optimization barrier preventing
        // `SpanningTree` from merging non-empty scanned ranges on either side.
        let extended_before = extended_range
            .as_ref()
            .map(|extended| {
                ScanRange::from_parts(extended.start..range.start, ScanPriority::FoundNote)
            })
            .filter(|range| !range.is_empty());
        let extended_after = extended_range
            .map(|extended| ScanRange::from_parts(range.end..extended.end, ScanPriority::FoundNote))
            .filter(|range| !range.is_empty());

        let replacement = Some(scanned)
            .into_iter()
            .chain(extended_before)
            .chain(extended_after);

        self.scan_queue
            .replace_queue_entries(&query_range, replacement, false)
    }

    // Given a range of block heights, extend the range to include the subtrees containing the
    // given subtree indices, bounded by the wallet birthday and the fallback start height.
    fn extend_range(
        &self,
        pool: &ShieldedProtocol,
        range: &Range<BlockHeight>,
        required_subtree_indices: BTreeSet<u64>,
        fallback_start_height: Option<BlockHeight>,
        birthday_height: Option<BlockHeight>,
    ) -> Result<Option<Range<BlockHeight>>, Error> {
        // we'll either have both min and max bounds, or we'll have neither
        let subtree_index_bounds = required_subtree_indices
            .iter()
            .min()
            .zip(required_subtree_indices.iter().max());

        let shard_end = |index| -> Result<_, Error> {
            match pool {
                ShieldedProtocol::Sapling => Ok(self
                    .sapling_tree_shard_end_heights
                    .get(&Address::from_parts(SAPLING_SHARD_HEIGHT.into(), index))
                    .cloned()),
                ShieldedProtocol::Orchard => {
                    #[cfg(feature = "orchard")]
                    {
                        Ok(self
                            .orchard_tree_shard_end_heights
                            .get(&Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index))
                            .cloned())
                    }
                    #[cfg(not(feature = "orchard"))]
                    panic!("Unsupported pool")
                }
            }
        };

        // If no notes belonging to the wallet were found, we don't need to extend the scanning
        // range suggestions to include the associated subtrees, and our bounds are just the
        // scanned range. Otherwise, ensure that all shard ranges starting from the wallet
        // birthday are included.
        subtree_index_bounds
            .map(|(min_idx, max_idx)| {
                let range_min = if *min_idx > 0 {
                    // get the block height of the end of the previous shard
                    shard_end(*min_idx - 1)?
                } else {
                    // our lower bound is going to be the fallback height
                    fallback_start_height
                };

                // bound the minimum to the wallet birthday
                let range_min =
                    range_min.map(|h| birthday_height.map_or(h, |b| std::cmp::max(b, h)));

                // Get the block height for the end of the current shard, and make it an
                // exclusive end bound.
                let range_max = shard_end(*max_idx)?.map(|end| end + 1);

                Ok(Range {
                    start: range.start.min(range_min.unwrap_or(range.start)),
                    end: range.end.max(range_max.unwrap_or(range.end)),
                })
            })
            .transpose()
    }

    pub(crate) fn get_sent_notes(&self) -> &SentNoteTable {
        &self.sent_notes
    }

    pub(crate) fn sapling_scan_progress(
        &self,
        birthday_height: &BlockHeight,
        fully_scanned_height: &BlockHeight,
        chain_tip_height: &BlockHeight,
    ) -> Result<Option<Ratio<u64>>, Error> {
        if fully_scanned_height == chain_tip_height {
            let outputs_sum = self
                .blocks
                .iter()
                .filter(|(height, _)| height >= &birthday_height)
                .fold(0, |sum, (_, block)| {
                    sum + block.sapling_output_count.unwrap_or(0)
                });
            Ok(Some(Ratio::new(outputs_sum as u64, outputs_sum as u64)))
        } else {
            // Get the starting note commitment tree size from the wallet birthday, or failing that
            // from the blocks table.
            let start_size = self
                .accounts
                .iter()
                .filter_map(|(_, account)| {
                    if account.birthday().height() == *birthday_height {
                        Some(account.birthday().sapling_frontier().tree_size())
                    } else {
                        None
                    }
                })
                .next()
                .or_else(|| {
                    self.blocks
                        .iter()
                        .filter(|(height, _)| height <= &birthday_height)
                        .map(|(_, block)| {
                            (block.sapling_commitment_tree_size.unwrap_or(0)
                                - block.sapling_output_count.unwrap_or(0))
                                as u64
                        })
                        .max()
                });

            // Compute the total blocks scanned so far above the starting height
            let scanned_count = self
                .blocks
                .iter()
                .filter(|(height, _)| height > &birthday_height)
                .fold(0_u64, |acc, (_, block)| {
                    acc + block.sapling_output_count.unwrap_or(0) as u64
                });

            // We don't have complete information on how many outputs will exist in the shard at
            // the chain tip without having scanned the chain tip block, so we overestimate by
            // computing the maximum possible number of notes directly from the shard indices.
            //
            // TODO: it would be nice to be able to reliably have the size of the commitment tree
            // at the chain tip without having to have scanned that block.

            let shard_index_iter = self
                .sapling_tree_shard_end_heights
                .iter()
                .filter(|(_, height)| height > &birthday_height)
                .map(|(address, _)| address.index());

            let min_idx = shard_index_iter.clone().min().unwrap_or(0);
            let max_idx = shard_index_iter.max().unwrap_or(0);

            let max_tree_size = Some(min_idx << SAPLING_SHARD_HEIGHT);
            let min_tree_size = Some((max_idx + 1) << SAPLING_SHARD_HEIGHT);

            Ok(start_size.or(min_tree_size).zip(max_tree_size).map(
                |(min_tree_size, max_tree_size)| {
                    Ratio::new(scanned_count, max_tree_size - min_tree_size)
                },
            ))
        }
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn orchard_scan_progress(
        &self,
        birthday_height: &BlockHeight,
        fully_scanned_height: &BlockHeight,
        chain_tip_height: &BlockHeight,
    ) -> Result<Option<Ratio<u64>>, Error> {
        if fully_scanned_height == chain_tip_height {
            let outputs_sum = self
                .blocks
                .iter()
                .filter(|(height, _)| height >= &birthday_height)
                .fold(0, |sum, (_, block)| {
                    sum + block.orchard_action_count.unwrap_or(0)
                });
            Ok(Some(Ratio::new(outputs_sum as u64, outputs_sum as u64)))
        } else {
            // Get the starting note commitment tree size from the wallet birthday, or failing that
            // from the blocks table.
            let start_size = self
                .accounts
                .iter()
                .filter_map(|(_, account)| {
                    if account.birthday().height() == *birthday_height {
                        Some(account.birthday().sapling_frontier().tree_size())
                    } else {
                        None
                    }
                })
                .next()
                .or_else(|| {
                    self.blocks
                        .iter()
                        .filter(|(height, _)| height <= &birthday_height)
                        .map(|(_, block)| {
                            (block.orchard_commitment_tree_size.unwrap_or(0)
                                - block.orchard_action_count.unwrap_or(0))
                                as u64
                        })
                        .max()
                });

            // Compute the total blocks scanned so far above the starting height
            let scanned_count = self
                .blocks
                .iter()
                .filter(|(height, _)| height > &birthday_height)
                .fold(0_u64, |acc, (_, block)| {
                    acc + block.orchard_action_count.unwrap_or(0) as u64
                });

            // We don't have complete information on how many outputs will exist in the shard at
            // the chain tip without having scanned the chain tip block, so we overestimate by
            // computing the maximum possible number of notes directly from the shard indices.
            //
            // TODO: it would be nice to be able to reliably have the size of the commitment tree
            // at the chain tip without having to have scanned that block.

            let shard_index_iter = self
                .orchard_tree_shard_end_heights
                .iter()
                .filter(|(_, height)| height > &birthday_height)
                .map(|(address, _)| address.index());

            let min_idx = shard_index_iter.clone().min().unwrap_or(0);
            let max_idx = shard_index_iter.max().unwrap_or(0);

            let max_tree_size = Some(min_idx << ORCHARD_SHARD_HEIGHT);
            let min_tree_size = Some((max_idx + 1) << ORCHARD_SHARD_HEIGHT);

            Ok(start_size.or(min_tree_size).zip(max_tree_size).map(
                |(min_tree_size, max_tree_size)| {
                    Ratio::new(scanned_count, max_tree_size - min_tree_size)
                },
            ))
        }
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn find_account_for_transparent_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<AccountId>, Error> {
        self.accounts.find_account_for_transparent_address(address)
    }

    pub(crate) fn mark_transparent_output_spent(
        &mut self,
        spent_in_tx: &TxId,
        outpoint: &OutPoint,
    ) -> Result<bool, Error> {
        // TODO: Remove it from the search queue

        self.transparent_received_output_spends
            .insert(outpoint.clone(), *spent_in_tx);

        // TODO: Check if this is an update and therefore we need to add something to transparent_spend_map

        Ok(false)
    }

    #[cfg(feature = "transparent-inputs")]
    #[allow(unreachable_code, unused_variables)] //FIXME: need address key scope detection
    pub(crate) fn put_transparent_output(
        &mut self,
        output: &WalletTransparentOutput,
        receiving_account: &AccountId,
        known_unspent: bool,
    ) -> Result<OutPoint, Error> {
        use crate::types::transparent::ReceivedTransparentOutput;

        let address = output.recipient_address();
        // get the block height of the block that mined the output only if we have it in the block table
        // otherwise return None
        let block = output
            .mined_height()
            .and_then(|h| self.blocks.get(&h).map(|b| b.height));
        let txid = TxId::from_bytes(output.outpoint().hash().to_vec().try_into().unwrap());

        // insert a new tx into the transactions table for the one that spent this output. If there is already one then do an update
        self.tx_table
            .put_tx_partial(&txid, &block, output.mined_height());

        // look for a spent_height for this output by querying transparent_received_output_spends.
        // If there isn't one then return None (this is an unspent output)
        // otherwise return the height found by joining on the tx table
        let spent_height = self
            .transparent_received_output_spends
            .get(output.outpoint())
            .and_then(|txid| {
                self.tx_table
                    .tx_status(txid)
                    .and_then(|status| match status {
                        TransactionStatus::Mined(height) => Some(height),
                        _ => None,
                    })
            });

        // The max observed unspent height is either the spending transaction's mined height - 1, or
        // the current chain tip height if the UTXO was received via a path that confirmed that it was
        // unspent, such as by querying the UTXO set of the network.
        let max_observed_unspent = match spent_height {
            Some(h) => Some(h - 1),
            None => {
                if known_unspent {
                    self.chain_height()?
                } else {
                    None
                }
            }
        };

        // insert into transparent_received_outputs table. Update if it exists
        #[allow(clippy::diverging_sub_expression)] // FIXME
        match self
            .transparent_received_outputs
            .entry(output.outpoint().clone())
        {
            Entry::Occupied(mut entry) => {
                entry.get_mut().transaction_id = txid;
                entry.get_mut().address = *address;
                entry.get_mut().account_id = *receiving_account;
                entry.get_mut().txout = output.txout().clone();
            }
            Entry::Vacant(entry) => {
                entry.insert(ReceivedTransparentOutput::new(
                    txid,
                    *receiving_account,
                    *address,
                    todo!("look up the key scope for the address"),
                    output.txout().clone(),
                    max_observed_unspent.unwrap_or(BlockHeight::from(0)),
                ));
            }
        }

        // look in transparent_spend_map for a record of the output already having been spent, then mark it as spent using the
        // stored reference to the spending transaction.
        if self
            .transparent_spend_map
            .contains(&txid, output.outpoint())
        {
            self.mark_transparent_output_spent(&txid, output.outpoint())?;
        }

        Ok(output.outpoint().clone())
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn get_known_ephemeral_addresses(
        &self,
        account_id: AccountId,
        index_range: Option<Range<NonHardenedChildIndex>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Error> {
        Ok(self
            .accounts
            .get(account_id)
            .map(Account::ephemeral_addresses)
            .unwrap_or_else(|| Ok(vec![]))?
            .into_iter()
            .filter(|(_addr, meta)| {
                index_range
                    .as_ref()
                    .is_none_or(|range| meta.address_index().is_some_and(|i| range.contains(&i)))
            })
            .collect::<Vec<_>>())
    }
}
