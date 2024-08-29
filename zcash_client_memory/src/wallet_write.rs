use incrementalmerkletree::{Marking, Position, Retention};

use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::ShardStore as _};

use std::{collections::HashMap, ops::Range};

use zip32::fingerprint::SeedFingerprint;

use zcash_primitives::{consensus::BlockHeight, transaction::TxId};
use zcash_protocol::{
    consensus::{self, NetworkUpgrade},
    ShieldedProtocol::Sapling,
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState,
        scanning::{ScanPriority, ScanRange},
        AccountPurpose, AccountSource, TransactionStatus, WalletCommitmentTrees as _,
        SAPLING_SHARD_HEIGHT,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{NoteId, Recipient, WalletTransparentOutput},
};

use zcash_client_backend::data_api::{
    Account as _, AccountBirthday, DecryptedTransaction, ScannedBlock, SentTransaction, WalletRead,
    WalletWrite,
};

use crate::{error::Error, PRUNING_DEPTH, VERIFY_LOOKAHEAD};
use crate::{
    Account, AccountId, MemoryWalletBlock, MemoryWalletDb, Nullifier, ReceivedNote, ViewingKey,
};
use maybe_rayon::prelude::*;

#[cfg(feature = "orchard")]
use zcash_protocol::ShieldedProtocol::Orchard;

impl<P: consensus::Parameters> WalletWrite for MemoryWalletDb<P> {
    type UtxoRef = u32;

    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> {
        tracing::debug!("create_account");
        let seed_fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
            .ok_or_else(|| Self::Error::InvalidSeedLength)?;
        let account_index = self
            .max_zip32_account_index(&seed_fingerprint)
            .unwrap()
            .map(|a| a.next().ok_or_else(|| Self::Error::AccountOutOfRange))
            .transpose()?
            .unwrap_or(zip32::AccountId::ZERO);

        let usk = UnifiedSpendingKey::from_seed(&self.params, seed.expose_secret(), account_index)?;
        let ufvk = usk.to_unified_full_viewing_key();

        let account = Account::new(
            AccountId(self.accounts.len() as u32),
            AccountSource::Derived {
                seed_fingerprint,
                account_index,
            },
            ViewingKey::Full(Box::new(ufvk)),
            birthday.clone(),
            AccountPurpose::Spending,
        )?;

        let id = account.id();
        self.accounts.push(account);

        Ok((id, usk))
    }

    fn get_next_available_address(
        &mut self,
        account: Self::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        tracing::debug!("get_next_available_address");
        self.get_account_mut(account)
            .map(|account| account.next_available_address(request))
            .transpose()
            .map(|a| a.flatten())
    }

    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Self::Error> {
        tracing::debug!("update_chain_tip");
        // If the caller provided a chain tip that is before Sapling activation, do nothing.
        let sapling_activation = match self.params.activation_height(NetworkUpgrade::Sapling) {
            Some(h) if h <= tip_height => h,
            _ => return Ok(()),
        };

        let max_scanned = self.block_height_extrema().map(|range| *range.end());
        let wallet_birthday = self.get_wallet_birthday()?;

        // If the chain tip is below the prior max scanned height, then the caller has caught
        // the chain in the middle of a reorg. Do nothing; the caller will continue using the
        // old scan ranges and either:
        // - encounter an error trying to fetch the blocks (and thus trigger the same handling
        //   logic as if this happened with the old linear scanning code); or
        // - encounter a discontinuity error in `scan_cached_blocks`, at which point they will
        //   call `WalletDb::truncate_to_height` as part of their reorg handling which will
        //   resolve the problem.
        //
        // We don't check the shard height, as normal usage would have the caller update the
        // shard state prior to this call, so it is possible and expected to be in a situation
        // where we should update the tip-related scan ranges but not the shard-related ones.
        match max_scanned {
            Some(h) if tip_height < h => return Ok(()),
            _ => (),
        };

        // `ScanRange` uses an exclusive upper bound.
        let chain_end = tip_height + 1;

        let sapling_shard_tip = self.sapling_tip_shard_end_height();
        // TODO: Handle orchard case as well. See zcash_client_sqlite scanning.rs update_chain_tip
        let min_shard_tip = sapling_shard_tip;

        // Create a scanning range for the fragment of the last shard leading up to new tip.
        // We set a lower bound at the wallet birthday (if known), because account creation
        // requires specifying a tree frontier that ensures we don't need tree information
        // prior to the birthday.
        let tip_shard_entry = min_shard_tip.filter(|h| h < &chain_end).map(|h| {
            let min_to_scan = wallet_birthday.filter(|b| b > &h).unwrap_or(h);
            ScanRange::from_parts(min_to_scan..chain_end, ScanPriority::ChainTip)
        });

        // Create scan ranges to either validate potentially invalid blocks at the wallet's
        // view of the chain tip, or connect the prior tip to the new tip.
        let tip_entry = max_scanned.map_or_else(
            || {
                // No blocks have been scanned, so we need to anchor the start of the new scan
                // range to something else.
                wallet_birthday.map_or_else(
                    // We don't have a wallet birthday, which means we have no accounts yet.
                    // We can therefore ignore all blocks up to the chain tip.
                    || ScanRange::from_parts(sapling_activation..chain_end, ScanPriority::Ignored),
                    // We have a wallet birthday, so mark all blocks between that and the
                    // chain tip as `Historic` (performing wallet recovery).
                    |wallet_birthday| {
                        ScanRange::from_parts(wallet_birthday..chain_end, ScanPriority::Historic)
                    },
                )
            },
            |max_scanned| {
                // The scan range starts at the block after the max scanned height. Since
                // `scan_cached_blocks` retrieves the metadata for the block being connected to
                // (if it exists), the connectivity of the scan range to the max scanned block
                // will always be checked if relevant.
                let min_unscanned = max_scanned + 1;

                // If we don't have shard metadata, this means we're doing linear scanning, so
                // create a scan range from the prior tip to the current tip with `Historic`
                // priority.
                if tip_shard_entry.is_none() {
                    ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::Historic)
                } else {
                    // Determine the height to which we expect new blocks retrieved from the
                    // block source to be stable and not subject to being reorg'ed.
                    let stable_height = tip_height.saturating_sub(PRUNING_DEPTH);

                    // If the wallet's max scanned height is above the stable height,
                    // prioritize the range between it and the new tip as `ChainTip`.
                    if max_scanned > stable_height {
                        // We are in the steady-state case, where a wallet is close to the
                        // chain tip and just needs to catch up.
                        //
                        // This overlaps the `tip_shard_entry` range and so will be coalesced
                        // with it.
                        ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::ChainTip)
                    } else {
                        // In this case, the max scanned height is considered stable relative
                        // to the chain tip. However, it may be stable or unstable relative to
                        // the prior chain tip, which we could determine by looking up the
                        // prior chain tip height from the scan queue. For simplicity we merge
                        // these two cases together, and proceed as though the max scanned
                        // block is unstable relative to the prior chain tip.
                        //
                        // To confirm its stability, prioritize the `VERIFY_LOOKAHEAD` blocks
                        // above the max scanned height as `Verify`:
                        //
                        // - We use `Verify` to ensure that a connectivity check is performed,
                        //   along with any required rewinds, before any `ChainTip` ranges
                        //   (from this or any prior `update_chain_tip` call) are scanned.
                        //
                        // - We prioritize `VERIFY_LOOKAHEAD` blocks because this is expected
                        //   to be 12.5 minutes, within which it is reasonable for a user to
                        //   have potentially received a transaction (if they opened their
                        //   wallet to provide an address to someone else, or spent their own
                        //   funds creating a change output), without necessarily having left
                        //   their wallet open long enough for the transaction to be mined and
                        //   the corresponding block to be scanned.
                        //
                        // - We limit the range to at most the stable region, to prevent any
                        //   `Verify` ranges from being susceptible to reorgs, and potentially
                        //   interfering with subsequent `Verify` ranges defined by future
                        //   calls to `update_chain_tip`. Any gap between `stable_height` and
                        //   `shard_start_height` will be filled by the scan range merging
                        //   logic with a `Historic` range.
                        //
                        // If `max_scanned == stable_height` then this is a zero-length range.
                        // In this case, any non-empty `(stable_height+1)..shard_start_height`
                        // will be marked `Historic`, minimising the prioritised blocks at the
                        // chain tip and allowing for other ranges (for example, `FoundNote`)
                        // to take priority.
                        ScanRange::from_parts(
                            min_unscanned
                                ..std::cmp::min(
                                    stable_height + 1,
                                    min_unscanned + VERIFY_LOOKAHEAD,
                                ),
                            ScanPriority::Verify,
                        )
                    }
                }
            },
        );
        if let Some(entry) = &tip_shard_entry {
            tracing::debug!("{} will update latest shard", entry);
        }
        tracing::debug!("{} will connect prior scanned state to new tip", tip_entry);

        let query_range = match tip_shard_entry.as_ref() {
            Some(se) => Range {
                start: std::cmp::min(se.block_range().start, tip_entry.block_range().start),
                end: std::cmp::max(se.block_range().end, tip_entry.block_range().end),
            },
            None => tip_entry.block_range().clone(),
        };

        self.scan_queue.replace_queue_entries(
            &query_range,
            tip_shard_entry.into_iter().chain(Some(tip_entry)),
            false,
        )?;
        Ok(())
    }

    /// Adds a sequence of blocks to the data store.
    ///
    /// Assumes blocks will be here in order.
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error> {
        tracing::debug!("put_blocks");
        // TODO:
        // - Make sure blocks are coming in order.
        // - Make sure the first block in the sequence is tip + 1?
        // - Add a check to make sure the blocks are not already in the data store.
        // let _start_height = blocks.first().map(|b| b.height());
        let mut last_scanned_height = None;
        let sapling_start_leaf_position = blocks.first().map(|block| {
            Position::from(
                u64::from(block.sapling().final_tree_size())
                    - u64::try_from(block.sapling().commitments().len()).unwrap(),
            )
        });

        let mut sapling_commitments = vec![];
        for block in blocks.into_iter() {
            let mut transactions = HashMap::new();
            let mut memos = HashMap::new();
            if last_scanned_height
                .iter()
                .any(|prev| block.height() != *prev + 1)
            {
                return Err(Error::NonSequentialBlocks);
            }

            for transaction in block.transactions().iter() {
                let txid = transaction.txid();

                // Mark the Sapling nullifiers of the spent notes as spent in the `sapling_spends` map.
                for spend in transaction.sapling_spends() {
                    self.mark_sapling_note_spent(*spend.nf(), txid)?;
                }

                // Mark the Orchard nullifiers of the spent notes as spent in the `orchard_spends` map.
                #[cfg(feature = "orchard")]
                for spend in transaction.orchard_spends() {
                    self.mark_orchard_note_spent(*spend.nf(), txid)?;
                }

                for output in transaction.sapling_outputs() {
                    // Insert the memo into the `memos` map.
                    let note_id = NoteId::new(
                        txid,
                        Sapling,
                        u16::try_from(output.index())
                            .expect("output indices are representable as u16"),
                    );
                    if let Ok(Some(memo)) = self.get_memo(note_id) {
                        memos.insert(note_id, memo.encode());
                    }
                    // Check whether this note was spent in a later block range that
                    // we previously scanned.
                    let spent_in = output
                        .nf()
                        .and_then(|nf| self.nullifiers.get(&Nullifier::Sapling(*nf)))
                        .and_then(|(height, tx_idx)| self.tx_locator.get(*height, *tx_idx))
                        .copied();

                    self.insert_received_sapling_note(note_id, output, spent_in);
                }

                #[cfg(feature = "orchard")]
                for output in transaction.orchard_outputs().iter() {
                    // Insert the memo into the `memos` map.
                    let note_id = NoteId::new(
                        txid,
                        Orchard,
                        u16::try_from(output.index())
                            .expect("output indices are representable as u16"),
                    );
                    if let Ok(Some(memo)) = self.get_memo(note_id) {
                        memos.insert(note_id, memo.encode());
                    }
                    // Check whether this note was spent in a later block range that
                    // we previously scanned.
                    let spent_in = output
                        .nf()
                        .and_then(|nf| self.nullifiers.get(&Nullifier::Orchard(*nf)))
                        .and_then(|(height, tx_idx)| self.tx_locator.get(*height, *tx_idx))
                        .copied();

                    self.insert_received_orchard_note(note_id, output, spent_in)
                }

                transactions.insert(txid, transaction.clone());
            }

            // Insert the new nullifiers from this block into the nullifier map
            self.insert_sapling_nullifier_map(block.height(), block.sapling().nullifier_map())?;
            #[cfg(feature = "orchard")]
            self.insert_orchard_nullifier_map(block.height(), block.orchard().nullifier_map())?;

            let memory_block = MemoryWalletBlock {
                height: block.height(),
                hash: block.block_hash(),
                block_time: block.block_time(),
                _transactions: transactions.keys().cloned().collect(),
                _memos: memos,
                sapling_commitment_tree_size: Some(block.sapling().final_tree_size()),
                _sapling_output_count: Some(
                    block.sapling().commitments().len().try_into().unwrap(),
                ),
                #[cfg(feature = "orchard")]
                orchard_commitment_tree_size: Some(block.orchard().final_tree_size()),
                #[cfg(feature = "orchard")]
                _orchard_action_count: Some(
                    block.orchard().commitments().len().try_into().unwrap(),
                ),
            };

            // Insert transaction metadata into the transaction table
            transactions
                .into_iter()
                .for_each(|(_id, tx)| self.tx_table.put_tx_meta(tx, block.height()));

            // Insert the block into the block map
            self.blocks.insert(block.height(), memory_block);
            last_scanned_height = Some(block.height());

            let block_commitments = block.into_commitments();
            sapling_commitments.extend(block_commitments.sapling.into_iter().map(Some));
        }

        if let Some(sapling_start_leaf_position) = sapling_start_leaf_position {
            // Create subtrees from the note commitments in parallel.
            const CHUNK_SIZE: usize = 1024;
            let sapling_subtrees = sapling_commitments
                .par_chunks_mut(CHUNK_SIZE)
                .enumerate()
                .filter_map(|(i, chunk)| {
                    let start = sapling_start_leaf_position + (i * CHUNK_SIZE) as u64;
                    let end = start + chunk.len() as u64;

                    shardtree::LocatedTree::from_iter(
                        start..end,
                        SAPLING_SHARD_HEIGHT.into(),
                        chunk.iter_mut().map(|n| n.take().expect("always Some")),
                    )
                })
                .map(|res| (res.subtree, res.checkpoints))
                .collect::<Vec<_>>();

            // Update the Sapling note commitment tree with all newly read note commitments
            {
                let mut sapling_subtrees_iter = sapling_subtrees.into_iter();
                self.with_sapling_tree_mut::<_, _, Self::Error>(|sapling_tree| {
                    sapling_tree.insert_frontier(
                        from_state.final_sapling_tree().clone(),
                        Retention::Checkpoint {
                            id: from_state.block_height(),
                            marking: Marking::Reference,
                        },
                    )?;

                    for (tree, checkpoints) in &mut sapling_subtrees_iter {
                        sapling_tree.insert_tree(tree, checkpoints)?;
                    }

                    Ok(())
                })?;
            }
        }
        // We can do some pruning of the tx_locator_map here

        // TODO: See: scan_complete() in sqlite.
        // Related to missing subtrees
        Ok(())
    }

    /// Adds a transparent UTXO received by the wallet to the data store.
    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        tracing::debug!("put_received_transparent_utxo");
        Ok(0)
    }

    fn store_decrypted_tx(
        &mut self,
        d_tx: DecryptedTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error> {
        tracing::debug!("store_decrypted_tx");
        self.tx_table.put_tx_data(d_tx.tx(), None, None);
        if let Some(height) = d_tx.mined_height() {
            self.set_transaction_status(d_tx.tx().txid(), TransactionStatus::Mined(height))?
        }
        Ok(())
    }

    /// Truncates the database to the given height.
    ///
    /// If the requested height is greater than or equal to the height of the last scanned
    /// block, this function does nothing.
    ///
    /// This should only be executed inside a transactional context.
    fn truncate_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
        todo!()
    }

    fn import_account_hd(
        &mut self,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> {
        tracing::debug!("import_account_hd");
        let seed_fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
            .ok_or_else(|| "Seed must be between 32 and 252 bytes in length.".to_owned())
            .unwrap();

        let usk = UnifiedSpendingKey::from_seed(&self.params, seed.expose_secret(), account_index)
            .map_err(|_| "key derivation error".to_string())
            .unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        let account = Account::new(
            AccountId(self.accounts.len() as u32),
            AccountSource::Derived {
                seed_fingerprint,
                account_index,
            },
            ViewingKey::Full(Box::new(ufvk)),
            birthday.clone(),
            AccountPurpose::Spending,
        )?;
        // TODO: Do we need to check if duplicate?
        self.accounts.push(account.clone());
        Ok((account, usk))
    }

    fn import_account_ufvk(
        &mut self,
        unified_key: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: AccountPurpose,
    ) -> Result<Self::Account, Self::Error> {
        tracing::debug!("import_account_ufvk");
        let account = Account::new(
            AccountId(self.accounts.len() as u32),
            AccountSource::Imported { purpose },
            ViewingKey::Full(Box::new(unified_key.to_owned())),
            birthday.clone(),
            purpose,
        )?;
        self.accounts.push(account.clone());
        Ok(account)
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<Self::AccountId>],
    ) -> Result<(), Self::Error> {
        tracing::debug!("store_transactions_to_be_sent");
        for sent_tx in transactions {
            self.tx_table.put_tx_data(
                sent_tx.tx(),
                Some(sent_tx.fee_amount()),
                Some(sent_tx.target_height()),
            );
            // Mark sapling notes as spent
            if let Some(bundle) = sent_tx.tx().sapling_bundle() {
                for spend in bundle.shielded_spends() {
                    self.mark_sapling_note_spent(*spend.nullifier(), sent_tx.tx().txid())?;
                }
            }
            // Mark orchard notes as spent
            if let Some(_bundle) = sent_tx.tx().orchard_bundle() {
                #[cfg(feature = "orchard")]
                {
                    for action in _bundle.actions() {
                        self.mark_orchard_note_spent(*action.nullifier(), sent_tx.tx().txid())?;
                    }
                }

                #[cfg(not(feature = "orchard"))]
                panic!("Sent a transaction with Orchard Actions without `orchard` enabled?");
            }
            // Mark transparent UTXOs as spent
            #[cfg(feature = "transparent-inputs")]
            for _utxo_outpoint in sent_tx.utxos_spent() {
                // self.mark_transparent_utxo_spent(wdb.conn.0, tx_ref, utxo_outpoint)?;
                todo!()
            }

            for output in sent_tx.outputs() {
                // TODO: insert sent output

                match output.recipient() {
                    Recipient::InternalAccount { .. } => {
                        self.received_notes.insert_received_note(
                            ReceivedNote::from_sent_tx_output(sent_tx.tx().txid(), output)?,
                        );
                    }
                    Recipient::EphemeralTransparent {
                        receiving_account: _,
                        ephemeral_address: _,
                        outpoint_metadata: _,
                    } => {
                        // mark ephemeral address as used
                    }
                    Recipient::External(_, _) => {}
                }
            }
            // in sqlite they que
        }
        Ok(())
    }

    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: TransactionStatus,
    ) -> Result<(), Self::Error> {
        tracing::debug!("set_transaction_status");
        self.tx_table.set_transaction_status(&txid, status)
    }
}
