use incrementalmerkletree::{Address, Marking, Retention};
use sapling::NullifierDerivingKey;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    hash::Hash,
    num::NonZeroU32,
};
use zcash_keys::{
    address::Receiver,
    keys::{AddressGenerationError, DerivationError, UnifiedIncomingViewingKey},
};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex, Scope};

use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network},
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
    memo::{self, Memo, MemoBytes},
    value::Zatoshis,
    PoolType,
    ShieldedProtocol::{Orchard, Sapling},
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState, AccountPurpose, AccountSource, SeedRelevance, TransactionDataRequest,
        TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{
        Note, NoteId, Recipient, WalletSaplingOutput, WalletSpend, WalletTransparentOutput,
        WalletTx,
    },
    TransferType,
};

use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, scanning::ScanRange, Account as _, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

use crate::error::Error;
use crate::{
    Account, AccountId, MemoryWalletBlock, MemoryWalletDb, Nullifier, ReceivedNote, ViewingKey,
};

impl WalletWrite for MemoryWalletDb {
    type UtxoRef = u32;

    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> {
        let seed_fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
            .ok_or_else(|| Self::Error::InvalidSeedLength)?;
        let account_index = self
            .max_zip32_account_index(&seed_fingerprint)
            .unwrap()
            .map(|a| a.next().ok_or_else(|| Self::Error::AccountOutOfRange))
            .transpose()?
            .unwrap_or(zip32::AccountId::ZERO);

        let usk =
            UnifiedSpendingKey::from_seed(&self.network, seed.expose_secret(), account_index)?;
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
        self.get_account_mut(account)
            .map(|account| account.next_available_address(request))
            .transpose()
            .map(|a| a.flatten())
    }

    fn update_chain_tip(&mut self, _tip_height: BlockHeight) -> Result<(), Self::Error> {
        todo!()
    }

    /// Adds a sequence of blocks to the data store.
    ///
    /// Assumes blocks will be here in order.
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error> {
        // TODO:
        // - Make sure blocks are coming in order.
        // - Make sure the first block in the sequence is tip + 1?
        // - Add a check to make sure the blocks are not already in the data store.
        let start_height = blocks.first().map(|b| b.height());
        let mut last_scanned_height = None;

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
                    self.mark_sapling_note_spent(*spend.nf(), txid);
                }

                // Mark the Orchard nullifiers of the spent notes as spent in the `orchard_spends` map.
                #[cfg(feature = "orchard")]
                for spend in transaction.orchard_spends() {
                    self.mark_orchard_note_spent(*spend.nf(), txid);
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
                        .map(|x| *x);

                    self.insert_received_sapling_note(note_id, &output, spent_in);
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
                        .and_then(|nf| self.nullifiers.get(&&Nullifier::Orchard(*nf)))
                        .and_then(|(height, tx_idx)| self.tx_locator.get(*height, *tx_idx))
                        .map(|x| *x);

                    self.insert_received_orchard_note(note_id, &output, spent_in)
                }
                // Add frontier to the sapling tree
                self.sapling_tree.insert_frontier(
                    from_state.final_sapling_tree().clone(),
                    Retention::Checkpoint {
                        id: from_state.block_height(),
                        marking: Marking::Reference,
                    },
                );

                #[cfg(feature = "orchard")]
                // Add frontier to the orchard tree
                self.orchard_tree.insert_frontier(
                    from_state.final_orchard_tree().clone(),
                    Retention::Checkpoint {
                        id: from_state.block_height(),
                        marking: Marking::Reference,
                    },
                );
                last_scanned_height = Some(block.height());
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
                transactions: transactions.keys().cloned().collect(),
                memos,
                sapling_commitment_tree_size: Some(block.sapling().final_tree_size()),
                sapling_output_count: Some(block.sapling().commitments().len().try_into().unwrap()),
                #[cfg(feature = "orchard")]
                orchard_commitment_tree_size: Some(block.orchard().final_tree_size()),
                #[cfg(feature = "orchard")]
                orchard_action_count: Some(block.orchard().commitments().len().try_into().unwrap()),
            };

            // Insert transaction metadata into the transaction table
            transactions
                .into_iter()
                .for_each(|(_id, tx)| self.tx_table.put_tx_meta(tx, block.height()));

            // Insert the block into the block map
            self.blocks.insert(block.height(), memory_block);

            // Add the Sapling commitments to the sapling tree.
            let block_commitments = block.into_commitments();
            let start_position = from_state
                .final_sapling_tree()
                .value()
                .map_or(0.into(), |t| t.position() + 1);
            self.sapling_tree
                .batch_insert(start_position, block_commitments.sapling.into_iter());

            #[cfg(feature = "orchard")]
            {
                // Add the Orchard commitments to the orchard tree.
                let start_position = from_state
                    .final_orchard_tree()
                    .value()
                    .map_or(0.into(), |t| t.position() + 1);
                self.orchard_tree
                    .batch_insert(start_position, block_commitments.orchard.into_iter());
            }
        }
        // We can do some pruning of the tx_locator_map here

        Ok(())
    }

    /// Adds a transparent UTXO received by the wallet to the data store.
    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        Ok(0)
    }

    fn store_decrypted_tx(
        &mut self,
        d_tx: DecryptedTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error> {
        self.tx_table.put_tx_data(d_tx.tx(), None, None);
        if let Some(height) = d_tx.mined_height() {
            self.set_transaction_status(d_tx.tx().txid(), TransactionStatus::Mined(height))?
        }
        Ok(())
    }

    fn truncate_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
        todo!()
    }

    fn import_account_hd(
        &mut self,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> {
        let seed_fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
            .ok_or_else(|| "Seed must be between 32 and 252 bytes in length.".to_owned())
            .unwrap();

        let usk = UnifiedSpendingKey::from_seed(&self.network, seed.expose_secret(), account_index)
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
        for sent_tx in transactions {
            self.tx_table.put_tx_data(
                sent_tx.tx(),
                Some(sent_tx.fee_amount()),
                Some(sent_tx.target_height()),
            );
            // Mark sapling notes as spent
            if let Some(bundle) = sent_tx.tx().sapling_bundle() {
                for spend in bundle.shielded_spends() {
                    self.mark_sapling_note_spent(*spend.nullifier(), sent_tx.tx().txid());
                }
            }
            // Mark orchard notes as spent
            if let Some(_bundle) = sent_tx.tx().orchard_bundle() {
                #[cfg(feature = "orchard")]
                {
                    for action in _bundle.actions() {
                        self.mark_orchard_note_spent(*action.nullifier(), sent_tx.tx().txid());
                    }
                }

                #[cfg(not(feature = "orchard"))]
                panic!("Sent a transaction with Orchard Actions without `orchard` enabled?");
            }
            // Mark transparent UTXOs as spent
            #[cfg(feature = "transparent-inputs")]
            for utxo_outpoint in sent_tx.utxos_spent() {
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
                    #[cfg(feature = "orchard")]
                    Recipient::InternalAccount { .. } => {
                        self.received_notes.insert_received_note(
                            ReceivedNote::from_sent_tx_output(sent_tx.tx().txid(), output)?,
                        );
                    }
                    Recipient::EphemeralTransparent {
                        receiving_account,
                        ephemeral_address,
                        outpoint_metadata,
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
        self.tx_table.set_transaction_status(&txid, status)
    }
}
