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
    wallet::{Note, NoteId, Recipient, WalletSpend, WalletTransparentOutput, WalletTx},
    TransferType,
};

use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, scanning::ScanRange, Account as _, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

use super::{Account, AccountId, MemoryWalletBlock, MemoryWalletDb, ViewingKey};
use crate::error::Error;

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
        let account = Account {
            account_id: AccountId(self.accounts.len() as u32),
            kind: AccountSource::Derived {
                seed_fingerprint,
                account_index,
            },
            viewing_key: ViewingKey::Full(Box::new(ufvk)),
            birthday: birthday.clone(),
            purpose: AccountPurpose::Spending,
            notes: HashSet::new(),
        };
        let id = account.id();
        self.accounts.push(account);

        Ok((id, usk))
    }

    fn get_next_available_address(
        &mut self,
        _account: Self::AccountId,
        _request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        todo!()
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
        for block in blocks.into_iter() {
            let mut transactions = HashMap::new();
            let mut memos = HashMap::new();
            for transaction in block.transactions().iter() {
                let txid = transaction.txid();
                transaction.sapling_outputs().iter().map(|o| {
                    // Insert the Sapling nullifiers of the spent notes into the `sapling_spends` map.
                    if let Some(nullifier) = o.nf() {
                        self.sapling_spends
                            .entry(*nullifier)
                            .or_insert((txid, false));
                    }

                    // Insert the memo into the `memos` map.
                    let note_id = NoteId::new(
                        txid,
                        Sapling,
                        u16::try_from(o.index()).expect("output indices are representable as u16"),
                    );
                    if let Ok(Some(memo)) = self.get_memo(note_id) {
                        memos.insert(note_id, memo.encode());
                    }
                });

                #[cfg(feature = "orchard")]
                transaction.orchard_outputs().iter().map(|o| {
                    // Insert the Orchard nullifiers of the spent notes into the `orchard_spends` map.
                    if let Some(nullifier) = o.nf() {
                        self.orchard_spends
                            .entry(*nullifier)
                            .or_insert((txid, false));
                    }

                    // Insert the memo into the `memos` map.
                    let note_id = NoteId::new(
                        txid,
                        Orchard,
                        u16::try_from(o.index()).expect("output indices are representable as u16"),
                    );
                    if let Ok(Some(memo)) = self.get_memo(note_id) {
                        memos.insert(note_id, memo.encode());
                    }
                });

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

                // Mark the Sapling nullifiers of the spent notes as spent in the `sapling_spends` map.
                transaction.sapling_spends().iter().map(|s| {
                    let nullifier = s.nf();
                    if let Some((txid, spent)) = self.sapling_spends.get_mut(nullifier) {
                        *spent = true;
                    }
                });

                #[cfg(feature = "orchard")]
                // Mark the Orchard nullifiers of the spent notes as spent in the `orchard_spends` map.
                transaction.orchard_spends().iter().map(|s| {
                    let nullifier = s.nf();
                    if let Some((txid, spent)) = self.orchard_spends.get_mut(nullifier) {
                        *spent = true;
                    }
                });

                transactions.insert(txid, transaction.clone());
            }

            let memory_block = MemoryWalletBlock {
                height: block.height(),
                hash: block.block_hash(),
                block_time: block.block_time(),
                transactions: transactions.keys().cloned().collect(),
                memos,
            };

            transactions
                .into_iter()
                .for_each(|(_id, tx)| self.put_tx_meta(tx, block.height()));

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
        self.put_tx_data(d_tx.tx(), None, None);
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
        let account = Account {
            account_id: AccountId(self.accounts.len() as u32),
            kind: AccountSource::Derived {
                seed_fingerprint,
                account_index,
            },
            viewing_key: ViewingKey::Full(Box::new(ufvk)),
            birthday: birthday.clone(),
            purpose: AccountPurpose::Spending,
            notes: HashSet::new(),
        };
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
        let account = Account {
            account_id: AccountId(self.accounts.len() as u32),
            kind: AccountSource::Imported { purpose },
            viewing_key: ViewingKey::Full(Box::new(unified_key.to_owned())),
            birthday: birthday.clone(),
            purpose,
            notes: HashSet::new(),
        };
        Ok(account)
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<Self::AccountId>],
    ) -> Result<(), Self::Error> {
        for sent_tx in transactions {
            self.put_tx_data(
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
                // insert sent output

                // TODO: Do we actually have to store these notes and outputs?
                // Presumebly we dont actually care about these until theyre mined anyways
                // in which case they will be populated in put_block
                match output.recipient() {
                    Recipient::InternalAccount {
                        receiving_account,
                        note: Note::Sapling(note),
                        ..
                    } => {
                        // insert note
                    }
                    #[cfg(feature = "orchard")]
                    Recipient::InternalAccount {
                        receiving_account,
                        note: Note::Orchard(note),
                        ..
                    } => {}
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
        if let Some(entry) = self.tx_table.0.get_mut(&txid) {
            entry.tx_status = status;
            Ok(())
        } else {
            Err(Error::TransactionNotFound(txid))
        }
    }
}
