use std::{
    collections::{HashMap, hash_map::Entry},
    num::NonZeroU32,
};

use nonempty::NonEmpty;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::store::ShardStore as _;
use zcash_client_backend::data_api::{
    AddressInfo, BlockMetadata, NullifierQuery, WalletRead, WalletSummary, Zip32Derivation,
    scanning::ScanRange,
    wallet::{ConfirmationsPolicy, TargetHeight},
};
use zcash_client_backend::{
    data_api::{
        Account as _, AccountBalance, AccountSource, Balance, Progress, Ratio, SeedRelevance,
        TransactionDataRequest, TransactionStatus, scanning::ScanPriority,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::NoteId,
};
use zcash_keys::{address::UnifiedAddress, keys::UnifiedIncomingViewingKey};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TransactionData, TxId},
};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight, BranchId},
    memo::Memo,
};
use zip32::fingerprint::SeedFingerprint;

#[cfg(feature = "transparent-inputs")]
use {
    transparent::{
        address::TransparentAddress,
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    },
    zcash_client_backend::wallet::{Exposure, TransparentAddressMetadata},
    zip32::Scope,
};

use crate::{Account, AccountId, MemoryWalletBlock, MemoryWalletDb, Nullifier, error::Error};

impl<P: consensus::Parameters> WalletRead for MemoryWalletDb<P> {
    type Error = Error;
    type AccountId = AccountId;
    type Account = Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        tracing::debug!("get_account_ids");
        Ok(self.accounts.account_ids().copied().collect())
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        tracing::debug!("get_account: {:?}", account_id);
        Ok(self.accounts.get(account_id).cloned())
    }

    fn get_derived_account(
        &self,
        d: &Zip32Derivation,
    ) -> Result<Option<Self::Account>, Self::Error> {
        tracing::debug!("get_derived_account: {:?}", d);
        Ok(self
            .accounts
            .iter()
            .find_map(|(_id, acct)| match acct.kind() {
                AccountSource::Derived { derivation, .. } => {
                    if derivation.seed_fingerprint() == d.seed_fingerprint()
                        && derivation.account_index() == d.account_index()
                    {
                        Some(acct.clone())
                    } else {
                        None
                    }
                }
                AccountSource::Imported { purpose: _, .. } => None,
            }))
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        tracing::debug!("validate_seed: {:?}", account_id);
        if let Some(account) = self.get_account(account_id)? {
            if let AccountSource::Derived { derivation, .. } = account.source() {
                seed_matches_derived_account(
                    &self.params,
                    seed,
                    derivation.seed_fingerprint(),
                    derivation.account_index(),
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
        tracing::debug!("seed_relevance_to_derived_accounts");
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
            if let AccountSource::Derived { derivation, .. } = account.source() {
                has_derived = true;

                if seed_matches_derived_account(
                    &self.params,
                    seed,
                    derivation.seed_fingerprint(),
                    derivation.account_index(),
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
        tracing::debug!("get_account_for_ufvk");
        Ok(self.accounts.iter().find_map(|(_id, acct)| {
            if acct
                .ufvk()?
                .default_address(UnifiedAddressRequest::AllAvailableKeys)
                .unwrap()
                == ufvk
                    .default_address(UnifiedAddressRequest::AllAvailableKeys)
                    .unwrap()
            {
                Some(acct.clone())
            } else {
                None
            }
        }))
    }

    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        tracing::debug!("get_account_birthday: {:?}", account);
        self.accounts
            .get(account)
            .map(|account| account.birthday().height())
            .ok_or(Error::AccountUnknown(account))
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        tracing::debug!("get_wallet_birthday");
        Ok(self
            .accounts
            .values()
            .map(|account| account.birthday().height())
            .min())
    }

    fn get_wallet_summary(
        &self,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        tracing::debug!("get_wallet_summary");
        let chain_tip_height = match self.chain_height()? {
            Some(height) => height,
            None => return Ok(None),
        };
        let target_height = TargetHeight::from(chain_tip_height + 1);
        let birthday_height = self
            .get_wallet_birthday()?
            .expect("If a scan range exists, we know the wallet birthday.");

        let fully_scanned_height = self
            .block_fully_scanned()?
            .map_or(birthday_height - 1, |m| m.block_height());

        let mut account_balances = self
            .accounts
            .values()
            .map(|account| (account.account_id(), AccountBalance::ZERO))
            .collect::<HashMap<AccountId, AccountBalance>>();

        for note in self.get_received_notes().iter() {
            // don't count spent notes
            if self.note_is_spent(note, target_height)? {
                continue;
            }
            // don't count notes in unscanned ranges
            let unscanned_ranges = self.unscanned_ranges();
            for (_, _, start_position, end_position_exclusive) in unscanned_ranges {
                if note.commitment_tree_position >= start_position
                    && note.commitment_tree_position < end_position_exclusive
                {
                    continue; // note is in an unscanned range. Skip it
                }
            }
            // don't count notes in unmined transactions or that have expired
            if let Ok(Some(note_tx)) = self.get_transaction(note.txid) {
                if note_tx.expiry_height() < BlockHeight::from(target_height) {
                    continue;
                }
            }

            let account_id = note.account_id();
            // if this is the first note for this account add a new balance record
            if let Entry::Vacant(entry) = account_balances.entry(account_id) {
                entry.insert(AccountBalance::ZERO);
            }
            let account_balance = account_balances
                .get_mut(&account_id)
                .expect("Account balance should exist");

            // Given a note update the balance for the account
            // This includes determining if it is change, spendable, etc
            let update_balance_with_note = |b: &mut Balance| -> Result<(), Error> {
                match (
                    self.note_is_pending(note, target_height, confirmations_policy)?,
                    note.is_change,
                ) {
                    (true, true) => b.add_pending_change_value(note.note.value()),
                    (true, false) => b.add_pending_spendable_value(note.note.value()),
                    (false, _) => b.add_spendable_value(note.note.value()),
                }?;
                Ok(())
            };

            match note.pool() {
                PoolType::SAPLING => {
                    account_balance.with_sapling_balance_mut(update_balance_with_note)?;
                }
                PoolType::ORCHARD => {
                    account_balance.with_orchard_balance_mut(update_balance_with_note)?;
                }
                _ => unimplemented!("Unknown pool type"),
            }
        }

        #[cfg(feature = "transparent-inputs")]
        for (account, balance) in account_balances.iter_mut() {
            let transparent_balances =
                self.get_transparent_balances(*account, target_height, confirmations_policy)?;
            for (_, (_, bal)) in transparent_balances.into_iter() {
                balance.with_unshielded_balance_mut(|b: &mut Balance| -> Result<(), Error> {
                    *b = (*b + bal)?;
                    Ok(())
                })?;
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

        // Treat Sapling and Orchard outputs as having the same cost to scan.
        let sapling_scan_progress =
            self.sapling_scan_progress(&birthday_height, &fully_scanned_height, &chain_tip_height)?;
        #[cfg(feature = "orchard")]
        let orchard_scan_progress =
            self.orchard_scan_progress(&birthday_height, &fully_scanned_height, &chain_tip_height)?;
        #[cfg(not(feature = "orchard"))]
        let orchard_scan_progress: Option<Ratio<u64>> = None;

        let scan_progress = sapling_scan_progress
            .zip(orchard_scan_progress)
            .map(|(s, o)| {
                Ratio::new(
                    s.numerator() + o.numerator(),
                    s.denominator() + o.denominator(),
                )
            })
            .or(sapling_scan_progress)
            .or(orchard_scan_progress);

        // TODO: This won't work
        let scan_progress = Progress::new(scan_progress.unwrap(), Some(Ratio::new(0, 0)));

        let summary = WalletSummary::new(
            account_balances,
            chain_tip_height,
            fully_scanned_height,
            scan_progress,
            next_sapling_subtree_index,
            #[cfg(feature = "orchard")]
            next_orchard_subtree_index,
        );
        Ok(Some(summary))
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        tracing::debug!("chain_height");
        Ok(self
            .scan_queue
            .iter()
            .max_by(|(_, end_a, _), (_, end_b, _)| end_a.cmp(end_b))
            .map(|(_, end, _)| end.saturating_sub(1)))
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        tracing::debug!("get_block_hash: {:?}", block_height);
        Ok(self.blocks.iter().find_map(|b| {
            if b.0 == &block_height {
                Some(b.1.hash)
            } else {
                None
            }
        }))
    }

    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        tracing::debug!("block_metadata: {:?}", height);
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
        tracing::debug!("block_fully_scanned");
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
        tracing::debug!("get_max_height_hash");
        Ok(self
            .blocks
            .last_key_value()
            .map(|(height, block)| (*height, block.hash)))
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        tracing::debug!("block_max_scanned");
        Ok(self
            .blocks
            .last_key_value()
            .map(|(height, _)| self.block_metadata(*height))
            .transpose()?
            .flatten())
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        tracing::debug!("suggest_scan_ranges");
        Ok(self.scan_queue.suggest_scan_ranges(ScanPriority::Historic))
    }

    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> {
        if let Some(chain_tip_height) = self.chain_height()? {
            let sapling_anchor_height =
                self.get_sapling_max_checkpointed_height(chain_tip_height, min_confirmations)?;

            #[cfg(feature = "orchard")]
            let orchard_anchor_height =
                self.get_orchard_max_checkpointed_height(chain_tip_height, min_confirmations)?;
            #[cfg(not(feature = "orchard"))]
            let orchard_anchor_height: Option<BlockHeight> = None;

            let anchor_height = sapling_anchor_height
                .zip(orchard_anchor_height)
                .map(|(s, o)| std::cmp::min(s, o))
                .or(sapling_anchor_height)
                .or(orchard_anchor_height);

            Ok(anchor_height.map(|h| (TargetHeight::from(chain_tip_height + 1), h)))
        } else {
            Ok(None)
        }
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        tracing::debug!("get_tx_height: {:?}", txid);
        if let Some(TransactionStatus::Mined(height)) = self.tx_table.tx_status(&txid) {
            Ok(Some(height))
        } else {
            Ok(None)
        }
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        tracing::debug!("get_unified_full_viewing_keys");
        Ok(self
            .accounts
            .iter()
            .filter_map(|(_id, account)| account.ufvk().map(|ufvk| (account.id(), ufvk.clone())))
            .collect())
    }

    fn get_memo(&self, id_note: NoteId) -> Result<Option<Memo>, Self::Error> {
        tracing::debug!("get_memo: {:?}", id_note);
        // look in both the received and sent notes
        Ok(self
            .get_received_note(id_note)
            .map(|note| note.memo.clone())
            .or_else(|| {
                self.sent_notes
                    .get_sent_note(&id_note)
                    .map(|note| note.memo.clone())
            }))
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        tracing::debug!("get_transaction: {:?}", txid);
        self.tx_table
            .get(&txid)
            .map(|tx| (tx.status(), tx.expiry_height(), tx.raw()))
            .map(|(status, expiry_height, raw)| {
                let raw = raw.ok_or_else(|| {
                    Self::Error::CorruptedData("Transaction raw data not found".to_string())
                })?;

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
                    return Ok(Transaction::read(
                        raw,
                        BranchId::for_height(&self.params, height),
                    )?);
                }
                if let Some(height) = expiry_height.filter(|h| h > &BlockHeight::from(0)) {
                    return Ok(Transaction::read(
                        raw,
                        BranchId::for_height(&self.params, height),
                    )?);
                }

                let tx_data = Transaction::read(raw, BranchId::Sprout)
                    .map_err(Self::Error::from)?
                    .into_data();

                let expiry_height = tx_data.expiry_height();
                if expiry_height > BlockHeight::from(0) {
                    Ok(TransactionData::from_parts(
                        tx_data.version(),
                        BranchId::for_height(&self.params, expiry_height),
                        tx_data.lock_time(),
                        expiry_height,
                        tx_data.transparent_bundle().cloned(),
                        tx_data.sprout_bundle().cloned(),
                        tx_data.sapling_bundle().cloned(),
                        tx_data.orchard_bundle().cloned(),
                    )
                        .freeze()?)
                } else {
                    Err(Self::Error::CorruptedData(
                        "Consensus branch ID not known, cannot parse this transaction until it is mined"
                            .to_string(),
                    ))
                }
            })
            .transpose()
    }

    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        tracing::debug!("get_sapling_nullifiers");
        let nullifiers = self.received_notes.get_sapling_nullifiers();
        Ok(match query {
            NullifierQuery::All => nullifiers
                .map(|(account_id, _, nf)| (account_id, nf))
                .collect(),
            NullifierQuery::Unspent => nullifiers
                .filter_map(|(account_id, _, nf)| {
                    // find any tx we know of that spends this nullifier and if so require that it is unmined or expired
                    if let Some((height, tx_index)) = self.nullifiers.get(&Nullifier::Sapling(nf)) {
                        if let Some(spending_tx) =
                            self.tx_table.get_by_height_and_index(*height, *tx_index)
                        {
                            if matches!(spending_tx.status(), TransactionStatus::Mined(_))
                                || spending_tx.expiry_height().is_none()
                            {
                                None
                            } else {
                                Some((account_id, nf))
                            }
                        } else {
                            None
                        }
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
        tracing::debug!("get_orchard_nullifiers");
        let nullifiers = self.received_notes.get_orchard_nullifiers();
        Ok(match query {
            NullifierQuery::All => nullifiers
                .map(|(account_id, _, nf)| (account_id, nf))
                .collect(),
            NullifierQuery::Unspent => nullifiers
                .filter_map(|(account_id, _, nf)| {
                    // find any tx we know of that spends this nullifier and if so require that it is unmined or expired
                    if let Some((height, tx_index)) = self.nullifiers.get(&Nullifier::Orchard(nf)) {
                        if let Some(spending_tx) =
                            self.tx_table.get_by_height_and_index(*height, *tx_index)
                        {
                            if matches!(spending_tx.status(), TransactionStatus::Mined(_))
                                || spending_tx.expiry_height().is_none()
                            {
                                None
                            } else {
                                Some((account_id, nf))
                            }
                        } else {
                            None
                        }
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
        account_id: Self::AccountId,
        _include_change: bool,
        _include_standalone: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        let account = self
            .get_account(account_id)?
            .ok_or(Error::AccountUnknown(account_id))?;

        if _include_change {
            unimplemented!("include_change is not yet supported");
        }
        if _include_standalone {
            unimplemented!("include_standalone is not yet supported");
        }

        let t_addresses = account
            .addresses()
            .iter()
            .filter_map(|(diversifier_index, ua)| {
                ua.transparent().map(|ta| {
                    let metadata = TransparentAddressMetadata::derived(
                        Scope::External.into(),
                        NonHardenedChildIndex::from_index((*diversifier_index).try_into().unwrap())
                            .expect(
                                "diversifier index corresponds to a valid NonHardenedChildIndex",
                            ),
                        Exposure::Unknown,
                        None,
                    );

                    (*ta, metadata)
                })
            })
            .collect();
        Ok(t_addresses)
    }

    /// Returns a mapping from each transparent receiver associated with the specified account
    /// to its not-yet-shielded UTXO balance, including only the effects of transactions mined
    /// at a block height less than or equal to `summary_height`.
    ///
    /// Only non-ephemeral transparent receivers with a non-zero balance at the summary height
    /// will be included.
    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        account_id: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<HashMap<TransparentAddress, (TransparentKeyScope, Balance)>, Self::Error> {
        tracing::debug!("get_transparent_balances");

        let mut balances = HashMap::new();

        for (outpoint, txo) in self.transparent_received_outputs.iter().filter(|(_, txo)| {
            if let Ok(Some(txo_account_id)) =
                self.find_account_for_transparent_address(&txo.address)
            {
                txo_account_id == account_id
            } else {
                false
            }
        }) {
            if self.utxo_is_spendable(outpoint, target_height, confirmations_policy)? {
                let address = txo.address;
                let entry = balances
                    .entry(address)
                    .or_insert((txo.key_scope, Balance::ZERO));

                entry.1.add_spendable_value(txo.txout.value())?;
            }
        }

        Ok(balances)
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        tracing::debug!("transaction_data_requests");
        Ok(self
            .transaction_data_request_queue
            .iter()
            .cloned()
            .collect())
    }

    fn list_addresses(&self, _account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        todo!()
    }

    fn get_last_generated_address_matching(
        &self,
        _account: Self::AccountId,
        _address_filter: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        todo!()
    }

    #[cfg(feature = "transparent-inputs")]
    fn utxo_query_height(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
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
                usk.to_unified_full_viewing_key()
                    .default_address(UnifiedAddressRequest::AllAvailableKeys)?
                    == uivk.default_address(UnifiedAddressRequest::AllAvailableKeys)?
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
