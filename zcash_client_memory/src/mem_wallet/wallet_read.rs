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
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
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

use super::{Account, AccountId, MemoryWalletDb, TransparentReceivedOutput};
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
        _account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        todo!()
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
        self.accounts
            .get(*account as usize)
            .map(|account| {
                account
                    .ufvk()
                    .unwrap()
                    .default_address(
                        UnifiedAddressRequest::all()
                            .expect("At least one protocol should be enabled."),
                    )
                    .map(|(addr, _)| addr)
            })
            .transpose()
            .map_err(|e| e.into())
    }

    fn get_account_birthday(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        Err(Error::AccountUnknown(_account))
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        todo!()
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

    fn get_tx_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        todo!()
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        Ok(HashMap::new())
    }

    fn get_memo(&self, id_note: NoteId) -> Result<Option<Memo>, Self::Error> {
        self.tx_idx
            .get(id_note.txid())
            .and_then(|height| self.blocks.get(height))
            .and_then(|block| block.memos.get(&id_note))
            .map(Memo::try_from)
            .transpose()
            .map_err(Error::from)
    }

    fn get_transaction(&self, _id_tx: TxId) -> Result<Option<Transaction>, Self::Error> {
        todo!()
    }

    fn get_sapling_nullifiers(
        &self,
        _query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        Ok(Vec::new())
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        Ok(self
            .orchard_spends
            .iter()
            .filter_map(|(nf, (txid, spent))| match query {
                NullifierQuery::Unspent => {
                    if !spent {
                        Some((txid, self.tx_idx.get(txid).unwrap(), *nf))
                    } else {
                        None
                    }
                }
                NullifierQuery::All => Some((txid, self.tx_idx.get(txid).unwrap(), *nf)),
            })
            .map(|(txid, height, nf)| {
                self.blocks
                    .get(height)
                    .and_then(|block| block.transactions.get(txid))
                    .and_then(|tx| {
                        tx.orchard_outputs()
                            .iter()
                            .find(|o| o.nf() == Some(&nf))
                            .map(|o| (*o.account_id(), *o.nf().unwrap()))
                            .or_else(|| {
                                tx.orchard_spends()
                                    .iter()
                                    .find(|s| s.nf() == &nf)
                                    .map(|s| (*s.account_id(), *s.nf()))
                            })
                    })
            })
            .flatten()
            .collect())
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
        // scan all transparent outputs and return those in a tx belonging to this account
        // as a map between the address and the total value received
        Ok(self
            .transparent_received_outputs
            .iter()
            .filter(|(_, output)| output.account_id == account) // that belong to this account
            .filter(|(outpoint, output)| {
                // where the tx creating the output is mined
                if let Some(height) = self.tx_idx.get(&output.tx_id) {
                    height <= &max_height
                } else {
                    false
                }
            })
            .filter(|(outpoint, _)| {
                // that are unspent
                !self
                    .transparent_received_output_spends
                    .contains_key(&outpoint)
            })
            .fold(
                HashMap::new(),
                |mut res, (_, TransparentReceivedOutput { output, .. })| {
                    let addr = output.recipient_address().clone();
                    let zats = res
                        .get(&addr)
                        .unwrap_or(&Zatoshis::ZERO)
                        .add(output.value())
                        .expect("Can always add a non-negative value to zero");
                    res.insert(addr, zats);
                    res
                },
            ))
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        todo!()
    }
}
