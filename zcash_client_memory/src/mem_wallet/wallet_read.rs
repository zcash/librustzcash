use incrementalmerkletree::{Address, Marking, Retention};
use sapling::NullifierDerivingKey;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    clone,
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    hash::Hash,
    num::NonZeroU32,
};
use zcash_keys::keys::{AddressGenerationError, DerivationError, UnifiedIncomingViewingKey};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex, Scope};

use std::ops::Add;
use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState, Account as _, AccountPurpose, AccountSource, SeedRelevance,
        TransactionDataRequest, TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{NoteId, WalletSpend, WalletTransparentOutput, WalletTx},
};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network},
    transaction::{Transaction, TransactionData, TxId},
};
use zcash_protocol::{
    consensus::BranchId,
    memo::{self, Memo, MemoBytes},
    value::Zatoshis,
    ShieldedProtocol::{Orchard, Sapling},
};

use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, scanning::ScanRange, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};
use zcash_primitives::transaction::components::OutPoint;

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_primitives::legacy::TransparentAddress,
};

use super::{Account, AccountId, MemoryWalletDb};
use crate::error::Error;

impl WalletRead for MemoryWalletDb {
    type Error = Error;
    type AccountId = AccountId;
    type Account = Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        Ok(Vec::new())
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Ok(self.accounts.get(*account_id as usize).map(|a| a.clone()))
    }

    fn get_derived_account(
        &self,
        _seed: &SeedFingerprint,
        _account_id: zip32::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        todo!()
    }

    fn validate_seed(
        &self,
        _account_id: Self::AccountId,
        _seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        todo!()
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        todo!()
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        let ufvk_req =
            UnifiedAddressRequest::all().expect("At least one protocol should be enabled");
        Ok(self.accounts.iter().find_map(|acct| {
            if acct.ufvk()?.default_address(ufvk_req).unwrap()
                == ufvk.default_address(ufvk_req).unwrap()
            {
                Some(acct.clone())
            } else {
                None
            }
        }))
    }

    fn get_current_address(
        &self,
        account: Self::AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        Ok(self
            .get_account(account)
            .and_then(Account::current_address)
            .map(|(_, a)| a.clone()))
    }

    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.accounts
            .get(*account as usize)
            .map(|account| account.birthday().height())
            .ok_or(Error::AccountUnknown(account))
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self
            .accounts
            .iter()
            .map(|account| account.birthday().height())
            .min())
    }

    fn get_wallet_summary(
        &self,
        _min_confirmations: u32,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        todo!()
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        todo!()
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        Ok(self.blocks.iter().find_map(|b| {
            if b.0 == &block_height {
                Some(b.1.hash)
            } else {
                None
            }
        }))
    }

    fn block_metadata(&self, _height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        todo!()
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        todo!()
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        todo!()
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        todo!()
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        Ok(vec![])
    }

    fn get_target_and_anchor_heights(
        &self,
        _min_confirmations: NonZeroU32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        todo!()
    }

    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        todo!()
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        if let Some(TransactionStatus::Mined(height)) = self.tx_table.tx_status(&txid) {
            Ok(Some(height))
        } else {
            Ok(None)
        }
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        Ok(self
            .accounts
            .iter()
            .filter_map(|account| match account.ufvk() {
                Some(ufvk) => Some((account.id(), ufvk.clone())),
                None => None,
            })
            .collect())
    }

    fn get_memo(&self, id_note: NoteId) -> Result<Option<Memo>, Self::Error> {
        todo!()
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        let raw = self.tx_table.get_tx_raw(&txid);
        let status = self.tx_table.tx_status(&txid);
        let expiry_height = self.tx_table.expiry_height(&txid);
        self.tx_table
            .get(&txid)
            .and_then(|tx| Some((tx.status(), tx.expiry_height(), tx.raw())))
            .map(|(status, expiry_height, raw)| {
                // We need to provide a consensus branch ID so that pre-v5 `Transaction` structs
                // (which don't commit directly to one) can store it internally.
                // - If the transaction is mined, we use the block height to get the correct one.
                // - If the transaction is unmined and has a cached non-zero expiry height, we use
                //   that (relying on the invariant that a transaction can't be mined across a network
                //   upgrade boundary, so the expiry height must be in the same epoch).
                // - Otherwise, we use a placeholder for the initial transaction parse (as the
                //   consensus branch ID is not used there), and then either use its non-zero expiry
                //   height or return an error.
                if let TransactionStatus::Mined(height) = status {
                    return Ok(Some(
                        Transaction::read(&raw[..], BranchId::for_height(&self.network, height))
                            .map(|t| (height, t)),
                    ));
                }
                if let Some(height) = expiry_height.filter(|h| h > &BlockHeight::from(0)) {
                    return Ok(Some(
                        Transaction::read(&raw[..], BranchId::for_height(&self.network, height))
                            .map(|t| (height, t)),
                    ));
                }

                let tx_data = Transaction::read(&raw[..], BranchId::Sprout)
                    .map_err(Self::Error::from)?
                    .into_data();

                let expiry_height = tx_data.expiry_height();
                if expiry_height > BlockHeight::from(0) {
                    Ok(Some(
                        TransactionData::from_parts(
                            tx_data.version(),
                            BranchId::for_height(&self.network, expiry_height),
                            tx_data.lock_time(),
                            expiry_height,
                            tx_data.transparent_bundle().cloned(),
                            tx_data.sprout_bundle().cloned(),
                            tx_data.sapling_bundle().cloned(),
                            tx_data.orchard_bundle().cloned(),
                        )
                        .freeze()
                        .map(|t| (expiry_height, t)),
                    ))
                } else {
                    Err(Self::Error::CorruptedData(
                    "Consensus branch ID not known, cannot parse this transaction until it is mined"
                        .to_string(),
                ))
                }
            });
        todo!()
    }

    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        let nullifiers = self.received_notes.get_sapling_nullifiers();
        Ok(match query {
            NullifierQuery::All => nullifiers
                .map(|(account_id, _, nf)| (account_id, nf))
                .collect(),
            NullifierQuery::Unspent => nullifiers
                .filter_map(|(account_id, txid, nf)| {
                    let tx_status = self.tx_table.tx_status(&txid);
                    let expiry_height = self.tx_table.expiry_height(&txid);
                    if matches!(tx_status, Some(TransactionStatus::Mined(_)))
                        || expiry_height.is_none()
                    {
                        None
                    } else {
                        Some((account_id, nf))
                    }
                })
                .collect(),
        })
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        let nullifiers = self.received_notes.get_orchard_nullifiers();
        Ok(match query {
            NullifierQuery::All => nullifiers
                .map(|(account_id, _, nf)| (account_id, nf))
                .collect(),
            NullifierQuery::Unspent => nullifiers
                .filter_map(|(account_id, txid, nf)| {
                    let tx_status = self.tx_table.tx_status(&txid);
                    let expiry_height = self.tx_table.expiry_height(&txid);
                    if matches!(tx_status, Some(TransactionStatus::Mined(_)))
                        || expiry_height.is_none()
                    {
                        None
                    } else {
                        Some((account_id, nf))
                    }
                })
                .collect(),
        })
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
        account: Self::AccountId,
        max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, Zatoshis>, Self::Error> {
        todo!()
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        todo!()
    }
}
