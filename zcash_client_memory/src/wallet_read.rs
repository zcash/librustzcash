use nonempty::NonEmpty;

use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::ShardStore as _};

use std::{
    collections::{hash_map::Entry, HashMap},
    num::NonZeroU32,
};
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zip32::fingerprint::SeedFingerprint;

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        scanning::ScanPriority, Account as _, AccountBalance, AccountSource, SeedRelevance,
        TransactionDataRequest, TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::NoteId,
};
use zcash_primitives::{
    block::BlockHash,
    consensus::BlockHeight,
    transaction::{Transaction, TransactionData, TxId},
};
use zcash_protocol::{
    consensus::{self, BranchId},
    memo::Memo,
    PoolType,
};

use zcash_client_backend::data_api::{
    scanning::ScanRange, BlockMetadata, NullifierQuery, WalletRead, WalletSummary,
};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_primitives::legacy::TransparentAddress,
};

use super::{Account, AccountId, MemoryWalletDb};
use crate::{error::Error, MemoryWalletBlock};

impl<P: consensus::Parameters> WalletRead for MemoryWalletDb<P> {
    type Error = Error;
    type AccountId = AccountId;
    type Account = Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        Ok(self.accounts.iter().map(|a| a.id()).collect())
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Ok(self.accounts.get(*account_id as usize).cloned())
    }

    fn get_derived_account(
        &self,
        seed: &SeedFingerprint,
        account_id: zip32::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Ok(self.accounts.iter().find_map(|acct| match acct.kind() {
            AccountSource::Derived {
                seed_fingerprint,
                account_index,
            } => {
                if seed_fingerprint == seed && account_index == &account_id {
                    Some(acct.clone())
                } else {
                    None
                }
            }
            AccountSource::Imported { purpose: _ } => None,
        }))
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        if let Some(account) = self.get_account(account_id)? {
            if let AccountSource::Derived {
                seed_fingerprint,
                account_index,
            } = account.source()
            {
                seed_matches_derived_account(
                    &self.params,
                    seed,
                    &seed_fingerprint,
                    account_index,
                    &account.uivk(),
                )
            } else {
                Err(Error::UnknownZip32Derivation)
            }
        } else {
            // Missing account is documented to return false.
            Ok(false)
        }
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        let mut has_accounts = false;
        let mut has_derived = false;
        let mut relevant_account_ids = vec![];

        for account_id in self.get_account_ids()? {
            has_accounts = true;
            let account = self.get_account(account_id)?.expect("account ID exists");

            // If the account is imported, the seed _might_ be relevant, but the only
            // way we could determine that is by brute-forcing the ZIP 32 account
            // index space, which we're not going to do. The method name indicates to
            // the caller that we only check derived accounts.
            if let AccountSource::Derived {
                seed_fingerprint,
                account_index,
            } = account.source()
            {
                has_derived = true;

                if seed_matches_derived_account(
                    &self.params,
                    seed,
                    &seed_fingerprint,
                    account_index,
                    &account.uivk(),
                )? {
                    // The seed is relevant to this account.
                    relevant_account_ids.push(account_id);
                }
            }
        }

        Ok(
            if let Some(account_ids) = NonEmpty::from_vec(relevant_account_ids) {
                SeedRelevance::Relevant { account_ids }
            } else if has_derived {
                SeedRelevance::NotRelevant
            } else if has_accounts {
                SeedRelevance::NoDerivedAccounts
            } else {
                SeedRelevance::NoAccounts
            },
        )
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
            .get_account(account)?
            .and_then(|account| Account::current_address(&account))
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
        min_confirmations: u32,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        let chain_tip_height = match self.chain_height()? {
            Some(height) => height,
            None => return Ok(None),
        };
        let birthday_height = self
            .get_wallet_birthday()?
            .expect("If a scan range exists, we know the wallet birthday.");

        let fully_scanned_height = self
            .block_fully_scanned()?
            .map_or(birthday_height - 1, |m| m.block_height());

        let mut account_balances = self
            .accounts
            .iter()
            .map(|account| (account.account_id(), AccountBalance::ZERO))
            .collect::<HashMap<AccountId, AccountBalance>>();

        for note in self.get_received_notes().iter() {
            // don't count spent notes
            if self.note_is_spent(note, min_confirmations)? {
                continue;
            }
            // TODO: We need to receiving transaction to be mined
            // TODO: We require a witness in the shard tree to spend the note

            match note.pool() {
                PoolType::SAPLING => {
                    let account_id = note.account_id();
                    match account_balances.entry(account_id) {
                        Entry::Occupied(mut entry) => {
                            entry.get_mut().with_sapling_balance_mut(|b| {
                                b.add_spendable_value(note.note.value())
                            })?;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(AccountBalance::ZERO);
                        }
                    };
                }
                _ => todo!(),
            }
        }

        let next_sapling_subtree_index = self
            .sapling_tree
            .store()
            .last_shard()?
            .map(|s| s.root_addr().index())
            .unwrap_or(0);

        #[cfg(feature = "orchard")]
        let next_orchard_subtree_index = self
            .orchard_tree
            .store()
            .last_shard()?
            .map(|s| s.root_addr().index())
            .unwrap_or(0);

        let summary = WalletSummary::new(
            account_balances,
            chain_tip_height,
            fully_scanned_height,
            None, // TODO: Deal with scan progress (I dont believe thats actually a hard requirement)
            next_sapling_subtree_index,
            #[cfg(feature = "orchard")]
            next_orchard_subtree_index,
        );
        Ok(Some(summary))
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self
            .scan_queue
            .iter()
            .max_by(|(_, end_a, _), (_, end_b, _)| end_a.cmp(end_b))
            .map(|(_, end, _)| end.saturating_sub(1)))
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

    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(self.blocks.get(&height).map(|block| {
            let MemoryWalletBlock {
                height,
                hash,
                sapling_commitment_tree_size,
                #[cfg(feature = "orchard")]
                orchard_commitment_tree_size,
                ..
            } = block;
            // TODO: Deal with legacy sapling trees
            BlockMetadata::from_parts(
                *height,
                *hash,
                *sapling_commitment_tree_size,
                #[cfg(feature = "orchard")]
                *orchard_commitment_tree_size,
            )
        }))
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        if let Some(birthday_height) = self.get_wallet_birthday()? {
            // We assume that the only way we get a contiguous range of block heights in the `blocks` table
            // starting with the birthday block, is if all scanning operations have been performed on those
            // blocks. This holds because the `blocks` table is only altered by `WalletDb::put_blocks` via
            // `put_block`, and the effective combination of intra-range linear scanning and the nullifier
            // map ensures that we discover all wallet-related information within the contiguous range.
            //
            // We also assume that every contiguous range of block heights in the `blocks` table has a
            // single matching entry in the `scan_queue` table with priority "Scanned". This requires no
            // bugs in the scan queue update logic, which we have had before. However, a bug here would
            // mean that we return a more conservative fully-scanned height, which likely just causes a
            // performance regression.
            //
            // The fully-scanned height is therefore the last height that falls within the first range in
            // the scan queue with priority "Scanned".
            // SQL query problems.

            let mut scanned_ranges: Vec<_> = self
                .scan_queue
                .iter()
                .filter(|(_, _, p)| p == &ScanPriority::Scanned)
                .collect();
            scanned_ranges.sort_by(|(start_a, _, _), (start_b, _, _)| start_a.cmp(start_b));
            if let Some(fully_scanned_height) = scanned_ranges.first().and_then(
                |(block_range_start, block_range_end, _priority)| {
                    // If the start of the earliest scanned range is greater than
                    // the birthday height, then there is an unscanned range between
                    // the wallet birthday and that range, so there is no fully
                    // scanned height.
                    if *block_range_start <= birthday_height {
                        // Scan ranges are end-exclusive.
                        Some(*block_range_end - 1)
                    } else {
                        None
                    }
                },
            ) {
                self.block_metadata(fully_scanned_height)
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        Ok(self
            .blocks
            .last_key_value()
            .map(|(height, block)| (*height, block.hash)))
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        Ok(self
            .blocks
            .last_key_value()
            .map(|(height, _)| self.block_metadata(*height))
            .transpose()?
            .flatten())
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        Ok(self.scan_queue.suggest_scan_ranges(ScanPriority::Historic))
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
            .filter_map(|account| account.ufvk().map(|ufvk| (account.id(), ufvk.clone())))
            .collect())
    }

    fn get_memo(&self, _id_note: NoteId) -> Result<Option<Memo>, Self::Error> {
        todo!()
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        let _raw = self.tx_table.get_tx_raw(&txid);
        let _status = self.tx_table.tx_status(&txid);
        let _expiry_height = self.tx_table.expiry_height(&txid);
        self.tx_table
            .get(&txid)
            .map(|tx| (tx.status(), tx.expiry_height(), tx.raw()))
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
                        Transaction::read(raw, BranchId::for_height(&self.params, height))
                            .map(|t| (height, t)),
                    ));
                }
                if let Some(height) = expiry_height.filter(|h| h > &BlockHeight::from(0)) {
                    return Ok(Some(
                        Transaction::read(raw, BranchId::for_height(&self.params, height))
                            .map(|t| (height, t)),
                    ));
                }

                let tx_data = Transaction::read(raw, BranchId::Sprout)
                    .map_err(Self::Error::from)?
                    .into_data();

                let expiry_height = tx_data.expiry_height();
                if expiry_height > BlockHeight::from(0) {
                    Ok(Some(
                        TransactionData::from_parts(
                            tx_data.version(),
                            BranchId::for_height(&self.params, expiry_height),
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
        _account: Self::AccountId,
        _max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, zcash_protocol::value::Zatoshis>, Self::Error> {
        todo!()
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        todo!()
    }
}

/// Copied from zcash_client_sqlite::wallet::seed_matches_derived_account
fn seed_matches_derived_account<P: consensus::Parameters>(
    params: &P,
    seed: &SecretVec<u8>,
    seed_fingerprint: &SeedFingerprint,
    account_index: zip32::AccountId,
    uivk: &UnifiedIncomingViewingKey,
) -> Result<bool, Error> {
    let seed_fingerprint_match =
        &SeedFingerprint::from_seed(seed.expose_secret()).ok_or_else(|| {
            Error::BadAccountData("Seed must be between 32 and 252 bytes in length.".to_owned())
        })? == seed_fingerprint;

    // Keys are not comparable with `Eq`, but addresses are, so we derive what should
    // be equivalent addresses for each key and use those to check for key equality.
    let uivk_match =
        match UnifiedSpendingKey::from_seed(params, &seed.expose_secret()[..], account_index) {
            // If we can't derive a USK from the given seed with the account's ZIP 32
            // account index, then we immediately know the UIVK won't match because wallet
            // accounts are required to have a known UIVK.
            Err(_) => false,
            Ok(usk) => {
                UnifiedAddressRequest::all().map_or(Ok::<_, Error>(false), |ua_request| {
                    Ok(usk
                        .to_unified_full_viewing_key()
                        .default_address(ua_request)?
                        == uivk.default_address(ua_request)?)
                })?
            }
        };

    if seed_fingerprint_match != uivk_match {
        // If these mismatch, it suggests database corruption.
        Err(Error::CorruptedData(format!(
            "Seed fingerprint match: {seed_fingerprint_match}, uivk match: {uivk_match}"
        )))
    } else {
        Ok(seed_fingerprint_match && uivk_match)
    }
}
