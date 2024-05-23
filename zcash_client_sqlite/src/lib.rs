//! *An SQLite-based Zcash light client.*
//!
//! `zcash_client_sqlite` contains complete SQLite-based implementations of the [`WalletRead`],
//! [`WalletWrite`], and [`BlockSource`] traits from the [`zcash_client_backend`] crate. In
//! combination with [`zcash_client_backend`], it provides a full implementation of a SQLite-backed
//! client for the Zcash network.
//!
//! # Design
//!
//! The light client is built around two SQLite databases:
//!
//! - A cache database, used to inform the light client about new [`CompactBlock`]s. It is
//!   read-only within all light client APIs *except* for [`init_cache_database`] which
//!   can be used to initialize the database.
//!
//! - A data database, where the light client's state is stored. It is read-write within
//!   the light client APIs, and **assumed to be read-only outside these APIs**. Callers
//!   **MUST NOT** write to the database without using these APIs. Callers **MAY** read
//!   the database directly in order to extract information for display to users.
//!
//! ## Feature flags
#![doc = document_features::document_features!()]
//!
//! [`WalletRead`]: zcash_client_backend::data_api::WalletRead
//! [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite
//! [`BlockSource`]: zcash_client_backend::data_api::chain::BlockSource
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock
//! [`init_cache_database`]: crate::chain::init::init_cache_database

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

use incrementalmerkletree::{Position, Retention};
use maybe_rayon::{
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use nonempty::NonEmpty;
use rusqlite::{self, Connection};
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, ShardTree};
use std::{
    borrow::Borrow, collections::HashMap, convert::AsRef, fmt, num::NonZeroU32, ops::Range,
    path::Path,
};
use subtle::ConditionallySelectable;
use tracing::{debug, trace, warn};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        self,
        chain::{BlockSource, ChainState, CommitmentTreeRoot},
        scanning::{ScanPriority, ScanRange},
        Account, AccountBirthday, AccountSource, BlockMetadata, DecryptedTransaction, InputSource,
        NullifierQuery, ScannedBlock, SeedRelevance, SentTransaction, SpendableNotes,
        WalletCommitmentTrees, WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
    },
    keys::{
        AddressGenerationError, UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey,
    },
    proto::compact_formats::CompactBlock,
    wallet::{Note, NoteId, ReceivedNote, Recipient, WalletTransparentOutput},
    DecryptedOutput, PoolType, ShieldedProtocol, TransferType,
};
use zcash_keys::address::Receiver;
use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    memo::{Memo, MemoBytes},
    transaction::{components::amount::NonNegativeAmount, Transaction, TxId},
    zip32::{self, DiversifierIndex, Scope},
};
use zip32::fingerprint::SeedFingerprint;

use crate::{error::SqliteClientError, wallet::commitment_tree::SqliteShardStore};

#[cfg(feature = "orchard")]
use {
    incrementalmerkletree::frontier::Frontier,
    shardtree::store::{Checkpoint, ShardStore},
    std::collections::BTreeMap,
    zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_primitives::{legacy::TransparentAddress, transaction::components::OutPoint},
};

#[cfg(feature = "unstable")]
use {
    crate::chain::{fsblockdb_with_blocks, BlockMeta},
    std::path::PathBuf,
    std::{fs, io},
};

pub mod chain;
pub mod error;
pub mod wallet;
use wallet::{
    commitment_tree::{self, put_shard_roots},
    SubtreeScanProgress,
};

#[cfg(test)]
mod testing;

/// The maximum number of blocks the wallet is allowed to rewind. This is
/// consistent with the bound in zcashd, and allows block data deeper than
/// this delta from the chain tip to be pruned.
pub(crate) const PRUNING_DEPTH: u32 = 100;

/// The number of blocks to verify ahead when the chain tip is updated.
pub(crate) const VERIFY_LOOKAHEAD: u32 = 10;

pub(crate) const SAPLING_TABLES_PREFIX: &str = "sapling";

#[cfg(feature = "orchard")]
pub(crate) const ORCHARD_TABLES_PREFIX: &str = "orchard";

#[cfg(not(feature = "orchard"))]
pub(crate) const UA_ORCHARD: bool = false;
#[cfg(feature = "orchard")]
pub(crate) const UA_ORCHARD: bool = true;

#[cfg(not(feature = "transparent-inputs"))]
pub(crate) const UA_TRANSPARENT: bool = false;
#[cfg(feature = "transparent-inputs")]
pub(crate) const UA_TRANSPARENT: bool = true;

pub(crate) const DEFAULT_UA_REQUEST: UnifiedAddressRequest =
    UnifiedAddressRequest::unsafe_new(UA_ORCHARD, true, UA_TRANSPARENT);

/// The ID type for accounts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct AccountId(u32);

impl ConditionallySelectable for AccountId {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        AccountId(ConditionallySelectable::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

/// An opaque type for received note identifiers.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceivedNoteId(pub(crate) ShieldedProtocol, pub(crate) i64);

impl fmt::Display for ReceivedNoteId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceivedNoteId(protocol, id) => write!(f, "Received {:?} Note: {}", protocol, id),
        }
    }
}

/// A newtype wrapper for sqlite primary key values for the utxos
/// table.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UtxoId(pub i64);

/// A wrapper for the SQLite connection to the wallet database.
pub struct WalletDb<C, P> {
    conn: C,
    params: P,
}

/// A wrapper for a SQLite transaction affecting the wallet database.
pub struct SqlTransaction<'conn>(pub(crate) &'conn rusqlite::Transaction<'conn>);

impl Borrow<rusqlite::Connection> for SqlTransaction<'_> {
    fn borrow(&self) -> &rusqlite::Connection {
        self.0
    }
}

impl<P: consensus::Parameters + Clone> WalletDb<Connection, P> {
    /// Construct a connection to the wallet database stored at the specified path.
    pub fn for_path<F: AsRef<Path>>(path: F, params: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).and_then(move |conn| {
            rusqlite::vtab::array::load_module(&conn)?;
            Ok(WalletDb { conn, params })
        })
    }

    pub fn transactionally<F, A, E: From<rusqlite::Error>>(&mut self, f: F) -> Result<A, E>
    where
        F: FnOnce(&mut WalletDb<SqlTransaction<'_>, P>) -> Result<A, E>,
    {
        let tx = self.conn.transaction()?;
        let mut wdb = WalletDb {
            conn: SqlTransaction(&tx),
            params: self.params.clone(),
        };
        let result = f(&mut wdb)?;
        tx.commit()?;
        Ok(result)
    }
}

impl<C: Borrow<rusqlite::Connection>, P: consensus::Parameters> InputSource for WalletDb<C, P> {
    type Error = SqliteClientError;
    type NoteRef = ReceivedNoteId;
    type AccountId = AccountId;

    fn get_spendable_note(
        &self,
        txid: &TxId,
        protocol: ShieldedProtocol,
        index: u32,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        match protocol {
            ShieldedProtocol::Sapling => wallet::sapling::get_spendable_sapling_note(
                self.conn.borrow(),
                &self.params,
                txid,
                index,
            )
            .map(|opt| opt.map(|n| n.map_note(Note::Sapling))),
            ShieldedProtocol::Orchard => {
                #[cfg(feature = "orchard")]
                return wallet::orchard::get_spendable_orchard_note(
                    self.conn.borrow(),
                    &self.params,
                    txid,
                    index,
                )
                .map(|opt| opt.map(|n| n.map_note(Note::Orchard)));

                #[cfg(not(feature = "orchard"))]
                return Err(SqliteClientError::UnsupportedPoolType(PoolType::Shielded(
                    ShieldedProtocol::Orchard,
                )));
            }
        }
    }

    fn select_spendable_notes(
        &self,
        account: AccountId,
        target_value: NonNegativeAmount,
        _sources: &[ShieldedProtocol],
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<SpendableNotes<Self::NoteRef>, Self::Error> {
        Ok(SpendableNotes::new(
            wallet::sapling::select_spendable_sapling_notes(
                self.conn.borrow(),
                &self.params,
                account,
                target_value,
                anchor_height,
                exclude,
            )?,
            #[cfg(feature = "orchard")]
            wallet::orchard::select_spendable_orchard_notes(
                self.conn.borrow(),
                &self.params,
                account,
                target_value,
                anchor_height,
                exclude,
            )?,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<WalletTransparentOutput>, Self::Error> {
        wallet::get_unspent_transparent_output(self.conn.borrow(), outpoint)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_outputs(
        &self,
        address: &TransparentAddress,
        max_height: BlockHeight,
        exclude: &[OutPoint],
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
        wallet::get_unspent_transparent_outputs(
            self.conn.borrow(),
            &self.params,
            address,
            max_height,
            exclude,
        )
    }
}

impl<C: Borrow<rusqlite::Connection>, P: consensus::Parameters> WalletRead for WalletDb<C, P> {
    type Error = SqliteClientError;
    type AccountId = AccountId;
    type Account = wallet::Account;

    fn get_account_ids(&self) -> Result<Vec<AccountId>, Self::Error> {
        wallet::get_account_ids(self.conn.borrow())
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        wallet::get_account(self.conn.borrow(), &self.params, account_id)
    }

    fn get_derived_account(
        &self,
        seed: &SeedFingerprint,
        account_id: zip32::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        wallet::get_derived_account(self.conn.borrow(), &self.params, seed, account_id)
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
                wallet::seed_matches_derived_account(
                    &self.params,
                    seed,
                    &seed_fingerprint,
                    account_index,
                    &account.uivk(),
                )
            } else {
                Err(SqliteClientError::UnknownZip32Derivation)
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

                if wallet::seed_matches_derived_account(
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
        wallet::get_account_for_ufvk(self.conn.borrow(), &self.params, ufvk)
    }

    fn get_current_address(
        &self,
        account: AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        wallet::get_current_address(self.conn.borrow(), &self.params, account)
            .map(|res| res.map(|(addr, _)| addr))
    }

    fn get_account_birthday(&self, account: AccountId) -> Result<BlockHeight, Self::Error> {
        wallet::account_birthday(self.conn.borrow(), account).map_err(SqliteClientError::from)
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::wallet_birthday(self.conn.borrow()).map_err(SqliteClientError::from)
    }

    fn get_wallet_summary(
        &self,
        min_confirmations: u32,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        // This will return a runtime error if we call `get_wallet_summary` from two
        // threads at the same time, as transactions cannot nest.
        wallet::get_wallet_summary(
            &self.conn.borrow().unchecked_transaction()?,
            &self.params,
            min_confirmations,
            &SubtreeScanProgress,
        )
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::scan_queue_extrema(self.conn.borrow())
            .map(|h| h.map(|range| *range.end()))
            .map_err(SqliteClientError::from)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        wallet::get_block_hash(self.conn.borrow(), block_height).map_err(SqliteClientError::from)
    }

    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        wallet::block_metadata(self.conn.borrow(), &self.params, height)
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        wallet::block_fully_scanned(self.conn.borrow(), &self.params)
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        wallet::get_max_height_hash(self.conn.borrow()).map_err(SqliteClientError::from)
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        wallet::block_max_scanned(self.conn.borrow(), &self.params)
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        wallet::scanning::suggest_scan_ranges(self.conn.borrow(), ScanPriority::Historic)
            .map_err(SqliteClientError::from)
    }

    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        wallet::get_target_and_anchor_heights(self.conn.borrow(), min_confirmations)
            .map_err(SqliteClientError::from)
    }

    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::get_min_unspent_height(self.conn.borrow()).map_err(SqliteClientError::from)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::get_tx_height(self.conn.borrow(), txid).map_err(SqliteClientError::from)
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, Self::Error> {
        wallet::get_unified_full_viewing_keys(self.conn.borrow(), &self.params)
    }

    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error> {
        let sent_memo = wallet::get_sent_memo(self.conn.borrow(), note_id)?;
        if sent_memo.is_some() {
            Ok(sent_memo)
        } else {
            wallet::get_received_memo(self.conn.borrow(), note_id)
        }
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        wallet::get_transaction(self.conn.borrow(), &self.params, txid)
            .map(|res| res.map(|(_, tx)| tx))
    }

    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(AccountId, sapling::Nullifier)>, Self::Error> {
        wallet::sapling::get_sapling_nullifiers(self.conn.borrow(), query)
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(AccountId, orchard::note::Nullifier)>, Self::Error> {
        wallet::orchard::get_orchard_nullifiers(self.conn.borrow(), query)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        account: AccountId,
    ) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, Self::Error> {
        wallet::get_transparent_receivers(self.conn.borrow(), &self.params, account)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        account: AccountId,
        max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, NonNegativeAmount>, Self::Error> {
        wallet::get_transparent_balances(self.conn.borrow(), &self.params, account, max_height)
    }
}

impl<P: consensus::Parameters> WalletWrite for WalletDb<rusqlite::Connection, P> {
    type UtxoRef = UtxoId;

    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
    ) -> Result<(AccountId, UnifiedSpendingKey), Self::Error> {
        self.transactionally(|wdb| {
            let seed_fingerprint =
                SeedFingerprint::from_seed(seed.expose_secret()).ok_or_else(|| {
                    SqliteClientError::BadAccountData(
                        "Seed must be between 32 and 252 bytes in length.".to_owned(),
                    )
                })?;
            let account_index = wallet::max_zip32_account_index(wdb.conn.0, &seed_fingerprint)?
                .map(|a| a.next().ok_or(SqliteClientError::AccountIdOutOfRange))
                .transpose()?
                .unwrap_or(zip32::AccountId::ZERO);

            let usk =
                UnifiedSpendingKey::from_seed(&wdb.params, seed.expose_secret(), account_index)
                    .map_err(|_| SqliteClientError::KeyDerivationError(account_index))?;
            let ufvk = usk.to_unified_full_viewing_key();

            let account_id = wallet::add_account(
                wdb.conn.0,
                &wdb.params,
                AccountSource::Derived {
                    seed_fingerprint,
                    account_index,
                },
                wallet::ViewingKey::Full(Box::new(ufvk)),
                birthday,
            )?;

            Ok((account_id, usk))
        })
    }

    fn get_next_available_address(
        &mut self,
        account: AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.transactionally(
            |wdb| match wdb.get_unified_full_viewing_keys()?.get(&account) {
                Some(ufvk) => {
                    let search_from =
                        match wallet::get_current_address(wdb.conn.0, &wdb.params, account)? {
                            Some((_, mut last_diversifier_index)) => {
                                last_diversifier_index.increment().map_err(|_| {
                                    AddressGenerationError::DiversifierSpaceExhausted
                                })?;
                                last_diversifier_index
                            }
                            None => DiversifierIndex::default(),
                        };

                    let (addr, diversifier_index) = ufvk.find_address(search_from, request)?;

                    wallet::insert_address(
                        wdb.conn.0,
                        &wdb.params,
                        account,
                        diversifier_index,
                        &addr,
                    )?;

                    Ok(Some(addr))
                }
                None => Ok(None),
            },
        )
    }

    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Self::Error> {
        let tx = self.conn.transaction()?;
        wallet::scanning::update_chain_tip(&tx, &self.params, tip_height)?;
        tx.commit()?;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(height = blocks.first().map(|b| u32::from(b.height())), count = blocks.len()))]
    #[allow(clippy::type_complexity)]
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error> {
        struct BlockPositions {
            height: BlockHeight,
            sapling_start_position: Position,
            #[cfg(feature = "orchard")]
            orchard_start_position: Position,
        }

        self.transactionally(|wdb| {
            let start_positions = blocks.first().map(|block| BlockPositions {
                height: block.height(),
                sapling_start_position: Position::from(
                    u64::from(block.sapling().final_tree_size())
                        - u64::try_from(block.sapling().commitments().len()).unwrap(),
                ),
                #[cfg(feature = "orchard")]
                orchard_start_position: Position::from(
                    u64::from(block.orchard().final_tree_size())
                        - u64::try_from(block.orchard().commitments().len()).unwrap(),
                ),
            });
            let mut sapling_commitments = vec![];
            #[cfg(feature = "orchard")]
            let mut orchard_commitments = vec![];
            let mut last_scanned_height = None;
            let mut note_positions = vec![];
            for block in blocks.into_iter() {
                if last_scanned_height
                    .iter()
                    .any(|prev| block.height() != *prev + 1)
                {
                    return Err(SqliteClientError::NonSequentialBlocks);
                }

                // Insert the block into the database.
                wallet::put_block(
                    wdb.conn.0,
                    block.height(),
                    block.block_hash(),
                    block.block_time(),
                    block.sapling().final_tree_size(),
                    block.sapling().commitments().len().try_into().unwrap(),
                    #[cfg(feature = "orchard")]
                    block.orchard().final_tree_size(),
                    #[cfg(feature = "orchard")]
                    block.orchard().commitments().len().try_into().unwrap(),
                )?;

                for tx in block.transactions() {
                    let tx_row = wallet::put_tx_meta(wdb.conn.0, tx, block.height())?;

                    // Mark notes as spent and remove them from the scanning cache
                    for spend in tx.sapling_spends() {
                        wallet::sapling::mark_sapling_note_spent(wdb.conn.0, tx_row, spend.nf())?;
                    }
                    #[cfg(feature = "orchard")]
                    for spend in tx.orchard_spends() {
                        wallet::orchard::mark_orchard_note_spent(wdb.conn.0, tx_row, spend.nf())?;
                    }

                    for output in tx.sapling_outputs() {
                        // Check whether this note was spent in a later block range that
                        // we previously scanned.
                        let spent_in = output
                            .nf()
                            .map(|nf| {
                                wallet::query_nullifier_map::<_, Scope>(
                                    wdb.conn.0,
                                    ShieldedProtocol::Sapling,
                                    nf,
                                )
                            })
                            .transpose()?
                            .flatten();

                        wallet::sapling::put_received_note(wdb.conn.0, output, tx_row, spent_in)?;
                    }
                    #[cfg(feature = "orchard")]
                    for output in tx.orchard_outputs() {
                        // Check whether this note was spent in a later block range that
                        // we previously scanned.
                        let spent_in = output
                            .nf()
                            .map(|nf| {
                                wallet::query_nullifier_map::<_, Scope>(
                                    wdb.conn.0,
                                    ShieldedProtocol::Orchard,
                                    &nf.to_bytes(),
                                )
                            })
                            .transpose()?
                            .flatten();

                        wallet::orchard::put_received_note(wdb.conn.0, output, tx_row, spent_in)?;
                    }
                }

                // Insert the new nullifiers from this block into the nullifier map.
                wallet::insert_nullifier_map(
                    wdb.conn.0,
                    block.height(),
                    ShieldedProtocol::Sapling,
                    block.sapling().nullifier_map(),
                )?;
                #[cfg(feature = "orchard")]
                wallet::insert_nullifier_map(
                    wdb.conn.0,
                    block.height(),
                    ShieldedProtocol::Orchard,
                    &block
                        .orchard()
                        .nullifier_map()
                        .iter()
                        .map(|(txid, idx, nfs)| {
                            (*txid, *idx, nfs.iter().map(|nf| nf.to_bytes()).collect())
                        })
                        .collect::<Vec<_>>(),
                )?;

                note_positions.extend(block.transactions().iter().flat_map(|wtx| {
                    let iter = wtx.sapling_outputs().iter().map(|out| {
                        (
                            ShieldedProtocol::Sapling,
                            out.note_commitment_tree_position(),
                        )
                    });
                    #[cfg(feature = "orchard")]
                    let iter = iter.chain(wtx.orchard_outputs().iter().map(|out| {
                        (
                            ShieldedProtocol::Orchard,
                            out.note_commitment_tree_position(),
                        )
                    }));

                    iter
                }));

                last_scanned_height = Some(block.height());
                let block_commitments = block.into_commitments();
                trace!(
                    "Sapling commitments for {:?}: {:?}",
                    last_scanned_height,
                    block_commitments
                        .sapling
                        .iter()
                        .map(|(_, r)| *r)
                        .collect::<Vec<_>>()
                );
                #[cfg(feature = "orchard")]
                trace!(
                    "Orchard commitments for {:?}: {:?}",
                    last_scanned_height,
                    block_commitments
                        .orchard
                        .iter()
                        .map(|(_, r)| *r)
                        .collect::<Vec<_>>()
                );

                sapling_commitments.extend(block_commitments.sapling.into_iter().map(Some));
                #[cfg(feature = "orchard")]
                orchard_commitments.extend(block_commitments.orchard.into_iter().map(Some));
            }

            // Prune the nullifier map of entries we no longer need.
            if let Some(meta) = wdb.block_fully_scanned()? {
                wallet::prune_nullifier_map(
                    wdb.conn.0,
                    meta.block_height().saturating_sub(PRUNING_DEPTH),
                )?;
            }

            // We will have a start position and a last scanned height in all cases where
            // `blocks` is non-empty.
            if let Some((start_positions, last_scanned_height)) =
                start_positions.zip(last_scanned_height)
            {
                // Create subtrees from the note commitments in parallel.
                const CHUNK_SIZE: usize = 1024;
                let sapling_subtrees = sapling_commitments
                    .par_chunks_mut(CHUNK_SIZE)
                    .enumerate()
                    .filter_map(|(i, chunk)| {
                        let start =
                            start_positions.sapling_start_position + (i * CHUNK_SIZE) as u64;
                        let end = start + chunk.len() as u64;

                        shardtree::LocatedTree::from_iter(
                            start..end,
                            SAPLING_SHARD_HEIGHT.into(),
                            chunk.iter_mut().map(|n| n.take().expect("always Some")),
                        )
                    })
                    .map(|res| (res.subtree, res.checkpoints))
                    .collect::<Vec<_>>();

                #[cfg(feature = "orchard")]
                let orchard_subtrees = orchard_commitments
                    .par_chunks_mut(CHUNK_SIZE)
                    .enumerate()
                    .filter_map(|(i, chunk)| {
                        let start =
                            start_positions.orchard_start_position + (i * CHUNK_SIZE) as u64;
                        let end = start + chunk.len() as u64;

                        shardtree::LocatedTree::from_iter(
                            start..end,
                            ORCHARD_SHARD_HEIGHT.into(),
                            chunk.iter_mut().map(|n| n.take().expect("always Some")),
                        )
                    })
                    .map(|res| (res.subtree, res.checkpoints))
                    .collect::<Vec<_>>();

                // Collect the complete set of Sapling checkpoints
                #[cfg(feature = "orchard")]
                let sapling_checkpoint_positions: BTreeMap<BlockHeight, Position> =
                    sapling_subtrees
                        .iter()
                        .flat_map(|(_, checkpoints)| checkpoints.iter())
                        .map(|(k, v)| (*k, *v))
                        .collect();

                #[cfg(feature = "orchard")]
                let orchard_checkpoint_positions: BTreeMap<BlockHeight, Position> =
                    orchard_subtrees
                        .iter()
                        .flat_map(|(_, checkpoints)| checkpoints.iter())
                        .map(|(k, v)| (*k, *v))
                        .collect();

                #[cfg(feature = "orchard")]
                fn ensure_checkpoints<
                    'a,
                    H,
                    I: Iterator<Item = &'a BlockHeight>,
                    const DEPTH: u8,
                >(
                    // An iterator of checkpoints heights for which we wish to ensure that
                    // checkpoints exists.
                    ensure_heights: I,
                    // The map of checkpoint positions from which we will draw note commitment tree
                    // position information for the newly created checkpoints.
                    existing_checkpoint_positions: &BTreeMap<BlockHeight, Position>,
                    // The frontier whose position will be used for an inserted checkpoint when
                    // there is no preceding checkpoint in existing_checkpoint_positions.
                    state_final_tree: &Frontier<H, DEPTH>,
                ) -> Vec<(BlockHeight, Checkpoint)> {
                    ensure_heights
                        .flat_map(|ensure_height| {
                            existing_checkpoint_positions
                                .range::<BlockHeight, _>(..=*ensure_height)
                                .last()
                                .map_or_else(
                                    || {
                                        Some((
                                            *ensure_height,
                                            state_final_tree
                                                .value()
                                                .map_or_else(Checkpoint::tree_empty, |t| {
                                                    Checkpoint::at_position(t.position())
                                                }),
                                        ))
                                    },
                                    |(existing_checkpoint_height, position)| {
                                        if *existing_checkpoint_height < *ensure_height {
                                            Some((
                                                *ensure_height,
                                                Checkpoint::at_position(*position),
                                            ))
                                        } else {
                                            // The checkpoint already exists, so we don't need to
                                            // do anything.
                                            None
                                        }
                                    },
                                )
                                .into_iter()
                        })
                        .collect::<Vec<_>>()
                }

                #[cfg(feature = "orchard")]
                let (missing_sapling_checkpoints, missing_orchard_checkpoints) = (
                    ensure_checkpoints(
                        orchard_checkpoint_positions.keys(),
                        &sapling_checkpoint_positions,
                        from_state.final_sapling_tree(),
                    ),
                    ensure_checkpoints(
                        sapling_checkpoint_positions.keys(),
                        &orchard_checkpoint_positions,
                        from_state.final_orchard_tree(),
                    ),
                );

                // Update the Sapling note commitment tree with all newly read note commitments
                {
                    let mut sapling_subtrees_iter = sapling_subtrees.into_iter();
                    wdb.with_sapling_tree_mut::<_, _, Self::Error>(|sapling_tree| {
                        debug!(
                            "Sapling initial tree size at {:?}: {:?}",
                            from_state.block_height(),
                            from_state.final_sapling_tree().tree_size()
                        );
                        sapling_tree.insert_frontier(
                            from_state.final_sapling_tree().clone(),
                            Retention::Checkpoint {
                                id: from_state.block_height(),
                                is_marked: false,
                            },
                        )?;

                        for (tree, checkpoints) in &mut sapling_subtrees_iter {
                            sapling_tree.insert_tree(tree, checkpoints)?;
                        }

                        // Ensure we have a Sapling checkpoint for each checkpointed Orchard block height.
                        // We skip all checkpoints below the minimum retained checkpoint in the
                        // Sapling tree, because branches below this height may be pruned.
                        #[cfg(feature = "orchard")]
                        {
                            let min_checkpoint_height = sapling_tree
                                .store()
                                .min_checkpoint_id()
                                .map_err(ShardTreeError::Storage)?
                                .expect(
                                    "At least one checkpoint was inserted (by insert_frontier)",
                                );

                            for (height, checkpoint) in &missing_sapling_checkpoints {
                                if *height > min_checkpoint_height {
                                    sapling_tree
                                        .store_mut()
                                        .add_checkpoint(*height, checkpoint.clone())
                                        .map_err(ShardTreeError::Storage)?;
                                }
                            }
                        }

                        Ok(())
                    })?;
                }

                // Update the Orchard note commitment tree with all newly read note commitments
                #[cfg(feature = "orchard")]
                {
                    let mut orchard_subtrees = orchard_subtrees.into_iter();
                    wdb.with_orchard_tree_mut::<_, _, Self::Error>(|orchard_tree| {
                        debug!(
                            "Orchard initial tree size at {:?}: {:?}",
                            from_state.block_height(),
                            from_state.final_orchard_tree().tree_size()
                        );
                        orchard_tree.insert_frontier(
                            from_state.final_orchard_tree().clone(),
                            Retention::Checkpoint {
                                id: from_state.block_height(),
                                is_marked: false,
                            },
                        )?;

                        for (tree, checkpoints) in &mut orchard_subtrees {
                            orchard_tree.insert_tree(tree, checkpoints)?;
                        }

                        // Ensure we have an Orchard checkpoint for each checkpointed Sapling block height.
                        // We skip all checkpoints below the minimum retained checkpoint in the
                        // Orchard tree, because branches below this height may be pruned.
                        {
                            let min_checkpoint_height = orchard_tree
                                .store()
                                .min_checkpoint_id()
                                .map_err(ShardTreeError::Storage)?
                                .expect(
                                    "At least one checkpoint was inserted (by insert_frontier)",
                                );

                            for (height, checkpoint) in &missing_orchard_checkpoints {
                                if *height > min_checkpoint_height {
                                    debug!(
                                        "Adding missing Orchard checkpoint for height: {:?}: {:?}",
                                        height,
                                        checkpoint.position()
                                    );
                                    orchard_tree
                                        .store_mut()
                                        .add_checkpoint(*height, checkpoint.clone())
                                        .map_err(ShardTreeError::Storage)?;
                                }
                            }
                        }
                        Ok(())
                    })?;
                }

                wallet::scanning::scan_complete(
                    wdb.conn.0,
                    &wdb.params,
                    Range {
                        start: start_positions.height,
                        end: last_scanned_height + 1,
                    },
                    &note_positions,
                )?;
            }

            Ok(())
        })
    }

    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        return wallet::put_received_transparent_utxo(&self.conn, &self.params, _output);

        #[cfg(not(feature = "transparent-inputs"))]
        panic!(
            "The wallet must be compiled with the transparent-inputs feature to use this method."
        );
    }

    fn store_decrypted_tx(
        &mut self,
        d_tx: DecryptedTransaction<AccountId>,
    ) -> Result<(), Self::Error> {
        self.transactionally(|wdb| {
            let tx_ref = wallet::put_tx_data(wdb.conn.0, d_tx.tx(), None, None)?;
            let funding_accounts = wallet::get_funding_accounts(wdb.conn.0, d_tx.tx())?;
            let funding_account = funding_accounts.iter().next().copied();
            if funding_accounts.len() > 1 {
                warn!(
                    "More than one wallet account detected as funding transaction {:?}, selecting {:?}",
                    d_tx.tx().txid(),
                    funding_account.unwrap()
                )
            }

            for output in d_tx.sapling_outputs() {
                match output.transfer_type() {
                    TransferType::Outgoing => {
                        let recipient = {
                            let receiver = Receiver::Sapling(output.note().recipient());
                            let wallet_address = wallet::select_receiving_address(
                                &wdb.params,
                                wdb.conn.0,
                                *output.account(),
                                &receiver
                            )?.unwrap_or_else(||
                                receiver.to_zcash_address(wdb.params.network_type())
                            );

                            Recipient::External(wallet_address, PoolType::Shielded(ShieldedProtocol::Sapling))
                        };

                        wallet::put_sent_output(
                            wdb.conn.0,
                            *output.account(),
                            tx_ref,
                            output.index(),
                            &recipient,
                            output.note_value(),
                            Some(output.memo()),
                        )?;
                    }
                    TransferType::WalletInternal => {
                        wallet::sapling::put_received_note(wdb.conn.0, output, tx_ref, None)?;

                        let recipient = Recipient::InternalAccount {
                            receiving_account: *output.account(),
                            external_address: None,
                            note: Note::Sapling(output.note().clone()),
                        };

                        wallet::put_sent_output(
                            wdb.conn.0,
                            *output.account(),
                            tx_ref,
                            output.index(),
                            &recipient,
                            output.note_value(),
                            Some(output.memo()),
                        )?;
                    }
                    TransferType::Incoming => {
                        wallet::sapling::put_received_note(wdb.conn.0, output, tx_ref, None)?;

                        if let Some(account_id) = funding_account {
                            let recipient = Recipient::InternalAccount {
                                receiving_account: *output.account(),
                                external_address: {
                                    let receiver = Receiver::Sapling(output.note().recipient());
                                    Some(wallet::select_receiving_address(
                                        &wdb.params,
                                        wdb.conn.0,
                                        *output.account(),
                                        &receiver
                                    )?.unwrap_or_else(||
                                        receiver.to_zcash_address(wdb.params.network_type())
                                    ))
                                },
                                note: Note::Sapling(output.note().clone()),
                            };

                            wallet::put_sent_output(
                                wdb.conn.0,
                                account_id,
                                tx_ref,
                                output.index(),
                                &recipient,
                                output.note_value(),
                                Some(output.memo()),
                            )?;
                        }
                    }
                }
            }

            #[cfg(feature = "orchard")]
            for output in d_tx.orchard_outputs() {
                match output.transfer_type() {
                    TransferType::Outgoing => {
                        let recipient = {
                            let receiver = Receiver::Orchard(output.note().recipient());
                            let wallet_address = wallet::select_receiving_address(
                                &wdb.params,
                                wdb.conn.0,
                                *output.account(),
                                &receiver
                            )?.unwrap_or_else(||
                                receiver.to_zcash_address(wdb.params.network_type())
                            );

                            Recipient::External(wallet_address, PoolType::Shielded(ShieldedProtocol::Orchard))
                        };

                        wallet::put_sent_output(
                            wdb.conn.0,
                            *output.account(),
                            tx_ref,
                            output.index(),
                            &recipient,
                            output.note_value(),
                            Some(output.memo()),
                        )?;
                    }
                    TransferType::WalletInternal => {
                        wallet::orchard::put_received_note(wdb.conn.0, output, tx_ref, None)?;

                        let recipient = Recipient::InternalAccount {
                            receiving_account: *output.account(),
                            external_address: None,
                            note: Note::Orchard(*output.note()),
                        };

                        wallet::put_sent_output(
                            wdb.conn.0,
                            *output.account(),
                            tx_ref,
                            output.index(),
                            &recipient,
                            output.note_value(),
                            Some(output.memo()),
                        )?;
                    }
                    TransferType::Incoming => {
                        wallet::orchard::put_received_note(wdb.conn.0, output, tx_ref, None)?;

                        if let Some(account_id) = funding_account {
                            // Even if the recipient address is external, record the send as internal.
                            let recipient = Recipient::InternalAccount {
                                receiving_account: *output.account(),
                                external_address: {
                                    let receiver = Receiver::Orchard(output.note().recipient());
                                    Some(wallet::select_receiving_address(
                                        &wdb.params,
                                        wdb.conn.0,
                                        *output.account(),
                                        &receiver
                                    )?.unwrap_or_else(||
                                        receiver.to_zcash_address(wdb.params.network_type())
                                    ))
                                },
                                note: Note::Orchard(*output.note()),
                            };

                            wallet::put_sent_output(
                                wdb.conn.0,
                                account_id,
                                tx_ref,
                                output.index(),
                                &recipient,
                                output.note_value(),
                                Some(output.memo()),
                            )?;
                        }
                    }
                }
            }

            // If any of the utxos spent in the transaction are ours, mark them as spent.
            #[cfg(feature = "transparent-inputs")]
            for txin in d_tx
                .tx()
                .transparent_bundle()
                .iter()
                .flat_map(|b| b.vin.iter())
            {
                wallet::mark_transparent_utxo_spent(wdb.conn.0, tx_ref, &txin.prevout)?;
            }

            // If we have some transparent outputs:
            if d_tx
                .tx()
                .transparent_bundle()
                .iter()
                .any(|b| !b.vout.is_empty())
            {
                // If the transaction contains spends from our wallet, we will store z->t
                // transactions we observe in the same way they would be stored by
                // create_spend_to_address.
                let funding_accounts = wallet::get_funding_accounts(wdb.conn.0, d_tx.tx())?;
                let funding_account = funding_accounts.iter().next().copied();
                if let Some(account_id) = funding_account {
                    if funding_accounts.len() > 1 {
                        warn!(
                            "More than one wallet account detected as funding transaction {:?}, selecting {:?}",
                            d_tx.tx().txid(),
                            account_id
                        )
                    }

                    for (output_index, txout) in d_tx
                        .tx()
                        .transparent_bundle()
                        .iter()
                        .flat_map(|b| b.vout.iter())
                        .enumerate()
                    {
                        if let Some(address) = txout.recipient_address() {
                            let receiver = Receiver::Transparent(address);

                            #[cfg(feature = "transparent-inputs")]
                            let recipient_addr = wallet::select_receiving_address(
                                &wdb.params,
                                wdb.conn.0,
                                account_id,
                                &receiver
                            )?.unwrap_or_else(||
                                receiver.to_zcash_address(wdb.params.network_type())
                            );

                            #[cfg(not(feature = "transparent-inputs"))]
                            let recipient_addr = receiver.to_zcash_address(wdb.params.network_type());

                            let recipient = Recipient::External(recipient_addr, PoolType::Transparent);

                            wallet::put_sent_output(
                                wdb.conn.0,
                                account_id,
                                tx_ref,
                                output_index,
                                &recipient,
                                txout.value,
                                None,
                            )?;
                        }
                    }
                }
            }

            Ok(())
        })
    }

    fn store_sent_tx(&mut self, sent_tx: &SentTransaction<AccountId>) -> Result<(), Self::Error> {
        self.transactionally(|wdb| {
            let tx_ref = wallet::put_tx_data(
                wdb.conn.0,
                sent_tx.tx(),
                Some(sent_tx.fee_amount()),
                Some(sent_tx.created()),
            )?;

            // Mark notes as spent.
            //
            // This locks the notes so they aren't selected again by a subsequent call to
            // create_spend_to_address() before this transaction has been mined (at which point the notes
            // get re-marked as spent).
            //
            // Assumes that create_spend_to_address() will never be called in parallel, which is a
            // reasonable assumption for a light client such as a mobile phone.
            if let Some(bundle) = sent_tx.tx().sapling_bundle() {
                for spend in bundle.shielded_spends() {
                    wallet::sapling::mark_sapling_note_spent(
                        wdb.conn.0,
                        tx_ref,
                        spend.nullifier(),
                    )?;
                }
            }
            if let Some(_bundle) = sent_tx.tx().orchard_bundle() {
                #[cfg(feature = "orchard")]
                for action in _bundle.actions() {
                    wallet::orchard::mark_orchard_note_spent(
                        wdb.conn.0,
                        tx_ref,
                        action.nullifier(),
                    )?;
                }

                #[cfg(not(feature = "orchard"))]
                panic!("Sent a transaction with Orchard Actions without `orchard` enabled?");
            }

            #[cfg(feature = "transparent-inputs")]
            for utxo_outpoint in sent_tx.utxos_spent() {
                wallet::mark_transparent_utxo_spent(wdb.conn.0, tx_ref, utxo_outpoint)?;
            }

            for output in sent_tx.outputs() {
                wallet::insert_sent_output(wdb.conn.0, tx_ref, *sent_tx.account_id(), output)?;

                match output.recipient() {
                    Recipient::InternalAccount {
                        receiving_account,
                        note: Note::Sapling(note),
                        ..
                    } => {
                        wallet::sapling::put_received_note(
                            wdb.conn.0,
                            &DecryptedOutput::new(
                                output.output_index(),
                                note.clone(),
                                *receiving_account,
                                output
                                    .memo()
                                    .map_or_else(MemoBytes::empty, |memo| memo.clone()),
                                TransferType::WalletInternal,
                            ),
                            tx_ref,
                            None,
                        )?;
                    }
                    #[cfg(feature = "orchard")]
                    Recipient::InternalAccount {
                        receiving_account,
                        note: Note::Orchard(note),
                        ..
                    } => {
                        wallet::orchard::put_received_note(
                            wdb.conn.0,
                            &DecryptedOutput::new(
                                output.output_index(),
                                *note,
                                *receiving_account,
                                output
                                    .memo()
                                    .map_or_else(MemoBytes::empty, |memo| memo.clone()),
                                TransferType::WalletInternal,
                            ),
                            tx_ref,
                            None,
                        )?;
                    }
                    _ => (),
                }
            }

            Ok(())
        })
    }

    fn truncate_to_height(&mut self, block_height: BlockHeight) -> Result<(), Self::Error> {
        self.transactionally(|wdb| {
            wallet::truncate_to_height(wdb.conn.0, &wdb.params, block_height)
        })
    }
}

impl<P: consensus::Parameters> WalletCommitmentTrees for WalletDb<rusqlite::Connection, P> {
    type Error = commitment_tree::Error;
    type SaplingShardStore<'a> =
        SqliteShardStore<&'a rusqlite::Transaction<'a>, sapling::Node, SAPLING_SHARD_HEIGHT>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        let shard_store = SqliteShardStore::from_connection(&tx, SAPLING_TABLES_PREFIX)
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        let result = {
            let mut shardtree = ShardTree::new(shard_store, PRUNING_DEPTH.try_into().unwrap());
            callback(&mut shardtree)?
        };

        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(result)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        put_shard_roots::<_, { sapling::NOTE_COMMITMENT_TREE_DEPTH }, SAPLING_SHARD_HEIGHT>(
            &tx,
            SAPLING_TABLES_PREFIX,
            start_index,
            roots,
        )?;
        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(())
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = SqliteShardStore<
        &'a rusqlite::Transaction<'a>,
        orchard::tree::MerkleHashOrchard,
        ORCHARD_SHARD_HEIGHT,
    >;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        let shard_store = SqliteShardStore::from_connection(&tx, ORCHARD_TABLES_PREFIX)
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        let result = {
            let mut shardtree = ShardTree::new(shard_store, PRUNING_DEPTH.try_into().unwrap());
            callback(&mut shardtree)?
        };

        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(result)
    }

    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        put_shard_roots::<_, { ORCHARD_SHARD_HEIGHT * 2 }, ORCHARD_SHARD_HEIGHT>(
            &tx,
            ORCHARD_TABLES_PREFIX,
            start_index,
            roots,
        )?;
        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(())
    }
}

impl<'conn, P: consensus::Parameters> WalletCommitmentTrees for WalletDb<SqlTransaction<'conn>, P> {
    type Error = commitment_tree::Error;
    type SaplingShardStore<'a> =
        SqliteShardStore<&'a rusqlite::Transaction<'a>, sapling::Node, SAPLING_SHARD_HEIGHT>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<commitment_tree::Error>>,
    {
        let mut shardtree = ShardTree::new(
            SqliteShardStore::from_connection(self.conn.0, SAPLING_TABLES_PREFIX)
                .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?,
            PRUNING_DEPTH.try_into().unwrap(),
        );
        let result = callback(&mut shardtree)?;

        Ok(result)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        put_shard_roots::<_, { sapling::NOTE_COMMITMENT_TREE_DEPTH }, SAPLING_SHARD_HEIGHT>(
            self.conn.0,
            SAPLING_TABLES_PREFIX,
            start_index,
            roots,
        )
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = SqliteShardStore<
        &'a rusqlite::Transaction<'a>,
        orchard::tree::MerkleHashOrchard,
        ORCHARD_SHARD_HEIGHT,
    >;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        let mut shardtree = ShardTree::new(
            SqliteShardStore::from_connection(self.conn.0, ORCHARD_TABLES_PREFIX)
                .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?,
            PRUNING_DEPTH.try_into().unwrap(),
        );
        let result = callback(&mut shardtree)?;

        Ok(result)
    }

    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        put_shard_roots::<_, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }, ORCHARD_SHARD_HEIGHT>(
            self.conn.0,
            ORCHARD_TABLES_PREFIX,
            start_index,
            roots,
        )
    }
}

/// A handle for the SQLite block source.
pub struct BlockDb(Connection);

impl BlockDb {
    /// Opens a connection to the wallet database stored at the specified path.
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(BlockDb)
    }
}

impl BlockSource for BlockDb {
    type Error = SqliteClientError;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        with_row: F,
    ) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>,
    {
        chain::blockdb_with_blocks(self, from_height, limit, with_row)
    }
}

/// A block source that reads block data from disk and block metadata from a SQLite database.
///
/// This block source expects each compact block to be stored on disk in the `blocks` subdirectory
/// of the `blockstore_root` path provided at the time of construction. Each block should be
/// written, as the serialized bytes of its protobuf representation, where the path for each block
/// has the pattern:
///
/// `<blockstore_root>/blocks/<block_height>-<block_hash>-compactblock`
///
/// where `<block_height>` is the decimal value of the height at which the block was mined, and
/// `<block_hash>` is the hexadecimal representation of the block hash, as produced by the
/// [`fmt::Display`] implementation for [`zcash_primitives::block::BlockHash`].
///
/// This block source is intended to be used with the following data flow:
/// * When the cache is being filled:
///   * The caller requests the current maximum height height at which cached data is available
///     using [`FsBlockDb::get_max_cached_height`]. If no cached data is available, the caller
///     can use the wallet's synced-to height for the following operations instead.
///   * (recommended for privacy) the caller should round the returned height down to some 100- /
///     1000-block boundary.
///   * The caller uses the lightwalletd's `getblock` gRPC method to obtain a stream of blocks.
///     For each block returned, the caller writes the compact block to `blocks_dir` using the
///     path format specified above. It is fine to overwrite an existing block, since block hashes
///     are immutable and collision-resistant.
///   * Once a caller-determined number of blocks have been successfully written to disk, the
///     caller should invoke [`FsBlockDb::write_block_metadata`] with the metadata for each block
///     written to disk.
/// * The cache can then be scanned using the [`BlockSource`] implementation, providing the
///   wallet's synced-to-height as a starting point.
/// * When part of the cache is no longer needed:
///   * The caller determines some height `H` that is the earliest block data it needs to preserve.
///     This might be determined based on where the wallet is fully-synced to, or other heuristics.
///   * The caller searches the defined filesystem folder for all files beginning in `HEIGHT-*` where
///     `HEIGHT < H`, and deletes those files.
///
/// Note: This API is unstable, and may change in the future. In particular, the [`BlockSource`]
/// API and the above description currently assume that scanning is performed in linear block
/// order; this assumption is likely to be weakened and/or removed in a future update.
#[cfg(feature = "unstable")]
pub struct FsBlockDb {
    conn: Connection,
    blocks_dir: PathBuf,
}

/// Errors that can be generated by the filesystem/sqlite-backed
/// block source.
#[derive(Debug)]
#[cfg(feature = "unstable")]
pub enum FsBlockDbError {
    Fs(io::Error),
    Db(rusqlite::Error),
    Protobuf(prost::DecodeError),
    MissingBlockPath(PathBuf),
    InvalidBlockstoreRoot(PathBuf),
    InvalidBlockPath(PathBuf),
    CorruptedData(String),
    CacheMiss(BlockHeight),
}

#[cfg(feature = "unstable")]
impl From<io::Error> for FsBlockDbError {
    fn from(err: io::Error) -> Self {
        FsBlockDbError::Fs(err)
    }
}

#[cfg(feature = "unstable")]
impl From<rusqlite::Error> for FsBlockDbError {
    fn from(err: rusqlite::Error) -> Self {
        FsBlockDbError::Db(err)
    }
}

#[cfg(feature = "unstable")]
impl From<prost::DecodeError> for FsBlockDbError {
    fn from(e: prost::DecodeError) -> Self {
        FsBlockDbError::Protobuf(e)
    }
}

#[cfg(feature = "unstable")]
impl FsBlockDb {
    /// Creates a filesystem-backed block store at the given path.
    ///
    /// This will construct or open a SQLite database at the path
    /// `<fsblockdb_root>/blockmeta.sqlite` and will ensure that a directory exists at
    /// `<fsblockdb_root>/blocks` where this block store will expect to find serialized block
    /// files as described for [`FsBlockDb`].
    ///
    /// An application using this constructor should ensure that they call
    /// [`crate::chain::init::init_blockmeta_db`] at application startup to ensure
    /// that the resulting metadata database is properly initialized and has had all required
    /// migrations applied before use.
    pub fn for_path<P: AsRef<Path>>(fsblockdb_root: P) -> Result<Self, FsBlockDbError> {
        let meta = fs::metadata(&fsblockdb_root).map_err(FsBlockDbError::Fs)?;
        if meta.is_dir() {
            let db_path = fsblockdb_root.as_ref().join("blockmeta.sqlite");
            let blocks_dir = fsblockdb_root.as_ref().join("blocks");
            fs::create_dir_all(&blocks_dir)?;
            Ok(FsBlockDb {
                conn: Connection::open(db_path).map_err(FsBlockDbError::Db)?,
                blocks_dir,
            })
        } else {
            Err(FsBlockDbError::InvalidBlockstoreRoot(
                fsblockdb_root.as_ref().to_path_buf(),
            ))
        }
    }

    /// Returns the maximum height of blocks known to the block metadata database.
    pub fn get_max_cached_height(&self) -> Result<Option<BlockHeight>, FsBlockDbError> {
        Ok(chain::blockmetadb_get_max_cached_height(&self.conn)?)
    }

    /// Adds a set of block metadata entries to the metadata database, overwriting any
    /// existing entries at the given block heights.
    ///
    /// This will return an error if any block file corresponding to one of these metadata records
    /// is absent from the blocks directory.
    pub fn write_block_metadata(&self, block_meta: &[BlockMeta]) -> Result<(), FsBlockDbError> {
        for m in block_meta {
            let block_path = m.block_file_path(&self.blocks_dir);
            match fs::metadata(&block_path) {
                Err(e) => {
                    return Err(match e.kind() {
                        io::ErrorKind::NotFound => FsBlockDbError::MissingBlockPath(block_path),
                        _ => FsBlockDbError::Fs(e),
                    });
                }
                Ok(meta) => {
                    if !meta.is_file() {
                        return Err(FsBlockDbError::InvalidBlockPath(block_path));
                    }
                }
            }
        }

        Ok(chain::blockmetadb_insert(&self.conn, block_meta)?)
    }

    /// Returns the metadata for the block with the given height, if it exists in the
    /// database.
    pub fn find_block(&self, height: BlockHeight) -> Result<Option<BlockMeta>, FsBlockDbError> {
        Ok(chain::blockmetadb_find_block(&self.conn, height)?)
    }

    /// Rewinds the BlockMeta Db to the `block_height` provided.
    ///
    /// This doesn't delete any files referenced by the records
    /// stored in BlockMeta.
    ///
    /// If the requested height is greater than or equal to the height
    /// of the last scanned block, or if the DB is empty, this function
    /// does nothing.
    pub fn truncate_to_height(&self, block_height: BlockHeight) -> Result<(), FsBlockDbError> {
        Ok(chain::blockmetadb_truncate_to_height(
            &self.conn,
            block_height,
        )?)
    }
}

#[cfg(feature = "unstable")]
impl BlockSource for FsBlockDb {
    type Error = FsBlockDbError;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        with_row: F,
    ) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>,
    {
        fsblockdb_with_blocks(self, from_height, limit, with_row)
    }
}

#[cfg(feature = "unstable")]
impl std::fmt::Display for FsBlockDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FsBlockDbError::Fs(io_error) => {
                write!(f, "Failed to access the file system: {}", io_error)
            }
            FsBlockDbError::Db(e) => {
                write!(f, "There was a problem with the sqlite db: {}", e)
            }
            FsBlockDbError::Protobuf(e) => {
                write!(f, "Failed to parse protobuf-encoded record: {}", e)
            }
            FsBlockDbError::MissingBlockPath(block_path) => {
                write!(
                    f,
                    "CompactBlock file expected but not found at {}",
                    block_path.display(),
                )
            }
            FsBlockDbError::InvalidBlockstoreRoot(fsblockdb_root) => {
                write!(
                    f,
                    "The block storage root {} is not a directory",
                    fsblockdb_root.display(),
                )
            }
            FsBlockDbError::InvalidBlockPath(block_path) => {
                write!(
                    f,
                    "CompactBlock path {} is not a file",
                    block_path.display(),
                )
            }
            FsBlockDbError::CorruptedData(e) => {
                write!(
                    f,
                    "The block cache has corrupted data and this caused an error: {}",
                    e,
                )
            }
            FsBlockDbError::CacheMiss(height) => {
                write!(
                    f,
                    "Requested height {} does not exist in the block cache",
                    height
                )
            }
        }
    }
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
mod tests {
    use secrecy::SecretVec;
    use zcash_client_backend::data_api::{WalletRead, WalletWrite};
    use zcash_primitives::block::BlockHash;

    use crate::{testing::TestBuilder, AccountId, DEFAULT_UA_REQUEST};

    #[cfg(feature = "unstable")]
    use {
        crate::testing::AddressType, zcash_client_backend::keys::sapling,
        zcash_primitives::transaction::components::amount::NonNegativeAmount,
    };

    #[test]
    fn validate_seed() {
        let st = TestBuilder::new()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().unwrap();

        assert!({
            st.wallet()
                .validate_seed(account.account_id(), st.test_seed().unwrap())
                .unwrap()
        });

        // check that passing an invalid account results in a failure
        assert!({
            let wrong_account_index = AccountId(3);
            !st.wallet()
                .validate_seed(wrong_account_index, st.test_seed().unwrap())
                .unwrap()
        });

        // check that passing an invalid seed results in a failure
        assert!({
            !st.wallet()
                .validate_seed(account.account_id(), &SecretVec::new(vec![1u8; 32]))
                .unwrap()
        });
    }

    #[test]
    pub(crate) fn get_next_available_address() {
        let mut st = TestBuilder::new()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().cloned().unwrap();

        let current_addr = st
            .wallet()
            .get_current_address(account.account_id())
            .unwrap();
        assert!(current_addr.is_some());

        let addr2 = st
            .wallet_mut()
            .get_next_available_address(account.account_id(), DEFAULT_UA_REQUEST)
            .unwrap();
        assert!(addr2.is_some());
        assert_ne!(current_addr, addr2);

        let addr2_cur = st
            .wallet()
            .get_current_address(account.account_id())
            .unwrap();
        assert_eq!(addr2, addr2_cur);
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn transparent_receivers() {
        // Add an account to the wallet.
        let st = TestBuilder::new()
            .with_block_cache()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().unwrap();
        let ufvk = account.usk().to_unified_full_viewing_key();
        let (taddr, _) = account.usk().default_transparent_address();

        let receivers = st
            .wallet()
            .get_transparent_receivers(account.account_id())
            .unwrap();

        // The receiver for the default UA should be in the set.
        assert!(receivers.contains_key(
            ufvk.default_address(DEFAULT_UA_REQUEST)
                .expect("A valid default address exists for the UFVK")
                .0
                .transparent()
                .unwrap()
        ));

        // The default t-addr should be in the set.
        assert!(receivers.contains_key(&taddr));
    }

    #[cfg(feature = "unstable")]
    #[test]
    pub(crate) fn fsblockdb_api() {
        use zcash_primitives::consensus::NetworkConstants;
        use zcash_primitives::zip32;

        let mut st = TestBuilder::new().with_fs_block_cache().build();

        // The BlockMeta DB starts off empty.
        assert_eq!(st.cache().get_max_cached_height().unwrap(), None);

        // Generate some fake CompactBlocks.
        let seed = [0u8; 32];
        let hd_account_index = zip32::AccountId::ZERO;
        let extsk = sapling::spending_key(&seed, st.wallet().params.coin_type(), hd_account_index);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let (h1, meta1, _) = st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            NonNegativeAmount::const_from_u64(5),
        );
        let (h2, meta2, _) = st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            NonNegativeAmount::const_from_u64(10),
        );

        // The BlockMeta DB is not updated until we do so explicitly.
        assert_eq!(st.cache().get_max_cached_height().unwrap(), None);

        // Inform the BlockMeta DB about the newly-persisted CompactBlocks.
        st.cache().write_block_metadata(&[meta1, meta2]).unwrap();

        // The BlockMeta DB now sees blocks up to height 2.
        assert_eq!(st.cache().get_max_cached_height().unwrap(), Some(h2),);
        assert_eq!(st.cache().find_block(h1).unwrap(), Some(meta1));
        assert_eq!(st.cache().find_block(h2).unwrap(), Some(meta2));
        assert_eq!(st.cache().find_block(h2 + 1).unwrap(), None);

        // Rewinding to height 1 should cause the metadata for height 2 to be deleted.
        st.cache().truncate_to_height(h1).unwrap();
        assert_eq!(st.cache().get_max_cached_height().unwrap(), Some(h1));
        assert_eq!(st.cache().find_block(h1).unwrap(), Some(meta1));
        assert_eq!(st.cache().find_block(h2).unwrap(), None);
        assert_eq!(st.cache().find_block(h2 + 1).unwrap(), None);
    }
}
