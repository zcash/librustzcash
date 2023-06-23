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
//! # Features
//!
//! The `mainnet` feature configures the light client for use with the Zcash mainnet. By
//! default, the light client is configured for use with the Zcash testnet.
//!
//! [`WalletRead`]: zcash_client_backend::data_api::WalletRead
//! [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite
//! [`BlockSource`]: zcash_client_backend::data_api::chain::BlockSource
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock
//! [`init_cache_database`]: crate::chain::init::init_cache_database

// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretVec};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    legacy::TransparentAddress,
    memo::{Memo, MemoBytes},
    sapling::{self},
    transaction::{
        components::{amount::Amount, OutPoint},
        Transaction, TxId,
    },
    zip32::{AccountId, DiversifierIndex, ExtendedFullViewingKey},
};

use zcash_client_backend::{
    address::{AddressMetadata, UnifiedAddress},
    data_api::{
        self, chain::BlockSource, DecryptedTransaction, NullifierQuery, PoolType, PrunedBlock,
        Recipient, SentTransaction, WalletRead, WalletWrite,
    },
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
    proto::compact_formats::CompactBlock,
    wallet::{ReceivedSaplingNote, WalletTransparentOutput},
    DecryptedOutput, TransferType,
};

use crate::error::SqliteClientError;

#[cfg(feature = "unstable")]
use {
    crate::chain::{fsblockdb_with_blocks, BlockMeta},
    std::path::PathBuf,
    std::{fs, io},
};

mod prepared;
pub use prepared::DataConnStmtCache;

pub mod chain;
pub mod error;
pub mod wallet;

/// The maximum number of blocks the wallet is allowed to rewind. This is
/// consistent with the bound in zcashd, and allows block data deeper than
/// this delta from the chain tip to be pruned.
pub(crate) const PRUNING_HEIGHT: u32 = 100;

/// A newtype wrapper for sqlite primary key values for the notes
/// table.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NoteId {
    SentNoteId(i64),
    ReceivedNoteId(i64),
}

impl fmt::Display for NoteId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NoteId::SentNoteId(id) => write!(f, "Sent Note {}", id),
            NoteId::ReceivedNoteId(id) => write!(f, "Received Note {}", id),
        }
    }
}

/// A newtype wrapper for sqlite primary key values for the utxos
/// table.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UtxoId(pub i64);

/// A wrapper for the SQLite connection to the wallet database.
pub struct WalletDb<P> {
    conn: Connection,
    params: P,
}

impl<P: consensus::Parameters> WalletDb<P> {
    /// Construct a connection to the wallet database stored at the specified path.
    pub fn for_path<F: AsRef<Path>>(path: F, params: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).and_then(move |conn| {
            rusqlite::vtab::array::load_module(&conn)?;
            Ok(WalletDb { conn, params })
        })
    }

    /// Given a wallet database connection, obtain a handle for the write operations
    /// for that database. This operation may eagerly initialize and cache sqlite
    /// prepared statements that are used in write operations.
    pub fn get_update_ops(&self) -> Result<DataConnStmtCache<'_, P>, SqliteClientError> {
        DataConnStmtCache::new(self)
    }
}

impl<P: consensus::Parameters> WalletRead for WalletDb<P> {
    type Error = SqliteClientError;
    type NoteRef = NoteId;
    type TxRef = i64;

    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        wallet::block_height_extrema(self).map_err(SqliteClientError::from)
    }

    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::get_min_unspent_height(self).map_err(SqliteClientError::from)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        wallet::get_block_hash(self, block_height).map_err(SqliteClientError::from)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::get_tx_height(self, txid).map_err(SqliteClientError::from)
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, Self::Error> {
        wallet::get_unified_full_viewing_keys(self)
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<AccountId>, Self::Error> {
        wallet::get_account_for_ufvk(self, ufvk)
    }

    fn get_current_address(
        &self,
        account: AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        wallet::get_current_address(self, account).map(|res| res.map(|(addr, _)| addr))
    }

    fn is_valid_account_extfvk(
        &self,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error> {
        wallet::is_valid_account_extfvk(self, account, extfvk)
    }

    fn get_balance_at(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error> {
        wallet::get_balance_at(self, account, anchor_height)
    }

    fn get_transaction(&self, id_tx: i64) -> Result<Transaction, Self::Error> {
        wallet::get_transaction(self, id_tx)
    }

    fn get_memo(&self, id_note: Self::NoteRef) -> Result<Option<Memo>, Self::Error> {
        match id_note {
            NoteId::SentNoteId(id_note) => wallet::get_sent_memo(self, id_note),
            NoteId::ReceivedNoteId(id_note) => wallet::get_received_memo(self, id_note),
        }
    }

    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<sapling::CommitmentTree>, Self::Error> {
        wallet::sapling::get_sapling_commitment_tree(self, block_height)
    }

    #[allow(clippy::type_complexity)]
    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, sapling::IncrementalWitness)>, Self::Error> {
        wallet::sapling::get_sapling_witnesses(self, block_height)
    }

    fn get_sapling_nullifiers(
        &self,
        query: data_api::NullifierQuery,
    ) -> Result<Vec<(AccountId, sapling::Nullifier)>, Self::Error> {
        match query {
            NullifierQuery::Unspent => wallet::sapling::get_sapling_nullifiers(self),
            NullifierQuery::All => wallet::sapling::get_all_sapling_nullifiers(self),
        }
    }

    fn get_spendable_sapling_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error> {
        wallet::sapling::get_spendable_sapling_notes(self, account, anchor_height, exclude)
    }

    fn select_spendable_sapling_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error> {
        wallet::sapling::select_spendable_sapling_notes(
            self,
            account,
            target_value,
            anchor_height,
            exclude,
        )
    }

    fn get_transparent_receivers(
        &self,
        _account: AccountId,
    ) -> Result<HashMap<TransparentAddress, AddressMetadata>, Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        return wallet::get_transparent_receivers(&self.params, &self.conn, _account);

        #[cfg(not(feature = "transparent-inputs"))]
        panic!(
            "The wallet must be compiled with the transparent-inputs feature to use this method."
        );
    }

    fn get_unspent_transparent_outputs(
        &self,
        _address: &TransparentAddress,
        _max_height: BlockHeight,
        _exclude: &[OutPoint],
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        return wallet::get_unspent_transparent_outputs(self, _address, _max_height, _exclude);

        #[cfg(not(feature = "transparent-inputs"))]
        panic!(
            "The wallet must be compiled with the transparent-inputs feature to use this method."
        );
    }

    fn get_transparent_balances(
        &self,
        _account: AccountId,
        _max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, Amount>, Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        return wallet::get_transparent_balances(self, _account, _max_height);

        #[cfg(not(feature = "transparent-inputs"))]
        panic!(
            "The wallet must be compiled with the transparent-inputs feature to use this method."
        );
    }
}

impl<'a, P: consensus::Parameters> WalletRead for DataConnStmtCache<'a, P> {
    type Error = SqliteClientError;
    type NoteRef = NoteId;
    type TxRef = i64;

    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        self.wallet_db.block_height_extrema()
    }

    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.wallet_db.get_min_unspent_height()
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        self.wallet_db.get_block_hash(block_height)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        self.wallet_db.get_tx_height(txid)
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, Self::Error> {
        self.wallet_db.get_unified_full_viewing_keys()
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<AccountId>, Self::Error> {
        self.wallet_db.get_account_for_ufvk(ufvk)
    }

    fn get_current_address(
        &self,
        account: AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.wallet_db.get_current_address(account)
    }

    fn is_valid_account_extfvk(
        &self,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error> {
        self.wallet_db.is_valid_account_extfvk(account, extfvk)
    }

    fn get_balance_at(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error> {
        self.wallet_db.get_balance_at(account, anchor_height)
    }

    fn get_transaction(&self, id_tx: i64) -> Result<Transaction, Self::Error> {
        self.wallet_db.get_transaction(id_tx)
    }

    fn get_memo(&self, id_note: Self::NoteRef) -> Result<Option<Memo>, Self::Error> {
        self.wallet_db.get_memo(id_note)
    }

    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<sapling::CommitmentTree>, Self::Error> {
        self.wallet_db.get_commitment_tree(block_height)
    }

    #[allow(clippy::type_complexity)]
    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, sapling::IncrementalWitness)>, Self::Error> {
        self.wallet_db.get_witnesses(block_height)
    }

    fn get_sapling_nullifiers(
        &self,
        query: data_api::NullifierQuery,
    ) -> Result<Vec<(AccountId, sapling::Nullifier)>, Self::Error> {
        self.wallet_db.get_sapling_nullifiers(query)
    }

    fn get_spendable_sapling_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error> {
        self.wallet_db
            .get_spendable_sapling_notes(account, anchor_height, exclude)
    }

    fn select_spendable_sapling_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error> {
        self.wallet_db
            .select_spendable_sapling_notes(account, target_value, anchor_height, exclude)
    }

    fn get_transparent_receivers(
        &self,
        account: AccountId,
    ) -> Result<HashMap<TransparentAddress, AddressMetadata>, Self::Error> {
        self.wallet_db.get_transparent_receivers(account)
    }

    fn get_unspent_transparent_outputs(
        &self,
        address: &TransparentAddress,
        max_height: BlockHeight,
        exclude: &[OutPoint],
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
        self.wallet_db
            .get_unspent_transparent_outputs(address, max_height, exclude)
    }

    fn get_transparent_balances(
        &self,
        account: AccountId,
        max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, Amount>, Self::Error> {
        self.wallet_db.get_transparent_balances(account, max_height)
    }
}

impl<'a, P: consensus::Parameters> DataConnStmtCache<'a, P> {
    fn transactionally<F, A>(&mut self, f: F) -> Result<A, SqliteClientError>
    where
        F: FnOnce(&mut Self) -> Result<A, SqliteClientError>,
    {
        self.wallet_db.conn.execute("BEGIN IMMEDIATE", [])?;
        match f(self) {
            Ok(result) => {
                self.wallet_db.conn.execute("COMMIT", [])?;
                Ok(result)
            }
            Err(error) => {
                match self.wallet_db.conn.execute("ROLLBACK", []) {
                    Ok(_) => Err(error),
                    Err(e) =>
                        // Panicking here is probably the right thing to do, because it
                        // means the database is corrupt.
                        panic!(
                            "Rollback failed with error {} while attempting to recover from error {}; database is likely corrupt.",
                            e,
                            error
                        )
                }
            }
        }
    }
}

impl<'a, P: consensus::Parameters> WalletWrite for DataConnStmtCache<'a, P> {
    type UtxoRef = UtxoId;

    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
    ) -> Result<(AccountId, UnifiedSpendingKey), Self::Error> {
        self.transactionally(|stmts| {
            let account = wallet::get_max_account_id(stmts.wallet_db)?
                .map(|a| AccountId::from(u32::from(a) + 1))
                .unwrap_or_else(|| AccountId::from(0));

            if u32::from(account) >= 0x7FFFFFFF {
                return Err(SqliteClientError::AccountIdOutOfRange);
            }

            let usk = UnifiedSpendingKey::from_seed(
                &stmts.wallet_db.params,
                seed.expose_secret(),
                account,
            )
            .map_err(|_| SqliteClientError::KeyDerivationError(account))?;
            let ufvk = usk.to_unified_full_viewing_key();

            wallet::add_account(stmts.wallet_db, account, &ufvk)?;

            Ok((account, usk))
        })
    }

    fn get_next_available_address(
        &mut self,
        account: AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        match self.get_unified_full_viewing_keys()?.get(&account) {
            Some(ufvk) => {
                let search_from = match wallet::get_current_address(self.wallet_db, account)? {
                    Some((_, mut last_diversifier_index)) => {
                        last_diversifier_index
                            .increment()
                            .map_err(|_| SqliteClientError::DiversifierIndexOutOfRange)?;
                        last_diversifier_index
                    }
                    None => DiversifierIndex::default(),
                };

                let (addr, diversifier_index) = ufvk
                    .find_address(search_from)
                    .ok_or(SqliteClientError::DiversifierIndexOutOfRange)?;

                self.stmt_insert_address(account, diversifier_index, &addr)?;

                Ok(Some(addr))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip_all, fields(height = u32::from(block.block_height)))]
    #[allow(clippy::type_complexity)]
    fn advance_by_block(
        &mut self,
        block: &PrunedBlock,
        updated_witnesses: &[(Self::NoteRef, sapling::IncrementalWitness)],
    ) -> Result<Vec<(Self::NoteRef, sapling::IncrementalWitness)>, Self::Error> {
        // database updates for each block are transactional
        self.transactionally(|up| {
            // Insert the block into the database.
            wallet::insert_block(
                up,
                block.block_height,
                block.block_hash,
                block.block_time,
                block.commitment_tree,
            )?;

            let mut new_witnesses = vec![];
            for tx in block.transactions {
                let tx_row = wallet::put_tx_meta(up, tx, block.block_height)?;

                // Mark notes as spent and remove them from the scanning cache
                for spend in &tx.sapling_spends {
                    wallet::sapling::mark_sapling_note_spent(up, tx_row, spend.nf())?;
                }

                for output in &tx.sapling_outputs {
                    let received_note_id = wallet::sapling::put_received_note(up, output, tx_row)?;

                    // Save witness for note.
                    new_witnesses.push((received_note_id, output.witness().clone()));
                }
            }

            // Insert current new_witnesses into the database.
            for (received_note_id, witness) in updated_witnesses.iter().chain(new_witnesses.iter())
            {
                if let NoteId::ReceivedNoteId(rnid) = *received_note_id {
                    wallet::sapling::insert_witness(up, rnid, witness, block.block_height)?;
                } else {
                    return Err(SqliteClientError::InvalidNoteId);
                }
            }

            // Prune the stored witnesses (we only expect rollbacks of at most PRUNING_HEIGHT blocks).
            wallet::prune_witnesses(up, block.block_height - PRUNING_HEIGHT)?;

            // Update now-expired transactions that didn't get mined.
            wallet::update_expired_notes(up, block.block_height)?;

            Ok(new_witnesses)
        })
    }

    fn store_decrypted_tx(
        &mut self,
        d_tx: DecryptedTransaction,
    ) -> Result<Self::TxRef, Self::Error> {
        self.transactionally(|up| {
            let tx_ref = wallet::put_tx_data(up, d_tx.tx, None, None)?;

            let mut spending_account_id: Option<AccountId> = None;
            for output in d_tx.sapling_outputs {
                match output.transfer_type {
                    TransferType::Outgoing | TransferType::WalletInternal => {
                        let recipient = if output.transfer_type == TransferType::Outgoing {
                            Recipient::Sapling(output.note.recipient())
                        } else {
                            Recipient::InternalAccount(output.account, PoolType::Sapling)
                        };

                        wallet::put_sent_output(
                            up,
                            output.account,
                            tx_ref,
                            output.index,
                            &recipient,
                            Amount::from_u64(output.note.value().inner()).map_err(|_|
                                SqliteClientError::CorruptedData("Note value is not a valid Zcash amount.".to_string()))?,
                            Some(&output.memo),
                        )?;

                        if matches!(recipient, Recipient::InternalAccount(_, _)) {
                            wallet::sapling::put_received_note(up, output, tx_ref)?;
                        }
                    }
                    TransferType::Incoming => {
                        match spending_account_id {
                            Some(id) =>
                                if id != output.account {
                                    panic!("Unable to determine a unique account identifier for z->t spend.");
                                }
                            None => {
                                spending_account_id = Some(output.account);
                            }
                        }

                        wallet::sapling::put_received_note(up, output, tx_ref)?;
                    }
                }
            }

            // If any of the utxos spent in the transaction are ours, mark them as spent.
            #[cfg(feature = "transparent-inputs")]
            for txin in d_tx.tx.transparent_bundle().iter().flat_map(|b| b.vin.iter()) {
                wallet::mark_transparent_utxo_spent(up, tx_ref, &txin.prevout)?;
            }

            // If we have some transparent outputs:
            if !d_tx.tx.transparent_bundle().iter().any(|b| b.vout.is_empty()) {
                let nullifiers = self.wallet_db.get_sapling_nullifiers(data_api::NullifierQuery::All)?;
                // If the transaction contains shielded spends from our wallet, we will store z->t
                // transactions we observe in the same way they would be stored by
                // create_spend_to_address.
                if let Some((account_id, _)) = nullifiers.iter().find(
                    |(_, nf)|
                        d_tx.tx.sapling_bundle().iter().flat_map(|b| b.shielded_spends().iter())
                        .any(|input| nf == input.nullifier())
                ) {
                    for (output_index, txout) in d_tx.tx.transparent_bundle().iter().flat_map(|b| b.vout.iter()).enumerate() {
                        if let Some(address) = txout.recipient_address() {
                            wallet::put_sent_output(
                                up,
                                *account_id,
                                tx_ref,
                                output_index,
                                &Recipient::Transparent(address),
                                txout.value,
                                None
                            )?;
                        }
                    }
                }
            }
            Ok(tx_ref)
        })
    }

    fn store_sent_tx(&mut self, sent_tx: &SentTransaction) -> Result<Self::TxRef, Self::Error> {
        // Update the database atomically, to ensure the result is internally consistent.
        self.transactionally(|up| {
            let tx_ref = wallet::put_tx_data(
                up,
                sent_tx.tx,
                Some(sent_tx.fee_amount),
                Some(sent_tx.created),
            )?;

            // Mark notes as spent.
            //
            // This locks the notes so they aren't selected again by a subsequent call to
            // create_spend_to_address() before this transaction has been mined (at which point the notes
            // get re-marked as spent).
            //
            // Assumes that create_spend_to_address() will never be called in parallel, which is a
            // reasonable assumption for a light client such as a mobile phone.
            if let Some(bundle) = sent_tx.tx.sapling_bundle() {
                for spend in bundle.shielded_spends() {
                    wallet::sapling::mark_sapling_note_spent(up, tx_ref, spend.nullifier())?;
                }
            }

            #[cfg(feature = "transparent-inputs")]
            for utxo_outpoint in &sent_tx.utxos_spent {
                wallet::mark_transparent_utxo_spent(up, tx_ref, utxo_outpoint)?;
            }

            for output in &sent_tx.outputs {
                wallet::insert_sent_output(up, tx_ref, sent_tx.account, output)?;

                if let Some((account, note)) = output.sapling_change_to() {
                    wallet::sapling::put_received_note(
                        up,
                        &DecryptedOutput {
                            index: output.output_index(),
                            note: note.clone(),
                            account: *account,
                            memo: output
                                .memo()
                                .map_or_else(MemoBytes::empty, |memo| memo.clone()),
                            transfer_type: TransferType::WalletInternal,
                        },
                        tx_ref,
                    )?;
                }
            }

            // Return the row number of the transaction, so the caller can fetch it for sending.
            Ok(tx_ref)
        })
    }

    fn truncate_to_height(&mut self, block_height: BlockHeight) -> Result<(), Self::Error> {
        wallet::truncate_to_height(self.wallet_db, block_height)
    }

    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        return wallet::put_received_transparent_utxo(self, _output);

        #[cfg(not(feature = "transparent-inputs"))]
        panic!(
            "The wallet must be compiled with the transparent-inputs feature to use this method."
        );
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

    fn with_blocks<F, DbErrT, NoteRef>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error, NoteRef>>
    where
        F: FnMut(
            CompactBlock,
        )
            -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error, NoteRef>>,
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
    /// [`zcash_client_sqlite::chain::init::init_blockmetadb`] at application startup to ensure
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

    /// Adds a set of block metadata entries to the metadata database.
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

    fn with_blocks<F, DbErrT, NoteRef>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error, NoteRef>>
    where
        F: FnMut(
            CompactBlock,
        )
            -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error, NoteRef>>,
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
        }
    }
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
mod tests {
    use prost::Message;
    use rand_core::{OsRng, RngCore};
    use rusqlite::params;
    use std::collections::HashMap;

    #[cfg(feature = "unstable")]
    use std::{fs::File, path::Path};

    #[cfg(feature = "transparent-inputs")]
    use zcash_primitives::{legacy, legacy::keys::IncomingViewingKey};

    use zcash_note_encryption::Domain;
    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
        legacy::TransparentAddress,
        memo::MemoBytes,
        sapling::{
            note_encryption::{sapling_note_encryption, SaplingDomain},
            util::generate_random_rseed,
            value::NoteValue,
            Note, Nullifier, PaymentAddress,
        },
        transaction::components::Amount,
        zip32::{sapling::DiversifiableFullViewingKey, DiversifierIndex},
    };

    use zcash_client_backend::{
        data_api::{WalletRead, WalletWrite},
        keys::{sapling, UnifiedFullViewingKey},
        proto::compact_formats::{
            CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
        },
    };

    use crate::{
        wallet::init::{init_accounts_table, init_wallet_db},
        AccountId, WalletDb,
    };

    use super::BlockDb;

    #[cfg(feature = "unstable")]
    use super::{
        chain::{init::init_blockmeta_db, BlockMeta},
        FsBlockDb,
    };

    #[cfg(feature = "mainnet")]
    pub(crate) fn network() -> Network {
        Network::MainNetwork
    }

    #[cfg(not(feature = "mainnet"))]
    pub(crate) fn network() -> Network {
        Network::TestNetwork
    }

    #[cfg(feature = "mainnet")]
    pub(crate) fn sapling_activation_height() -> BlockHeight {
        Network::MainNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap()
    }

    #[cfg(not(feature = "mainnet"))]
    pub(crate) fn sapling_activation_height() -> BlockHeight {
        Network::TestNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap()
    }

    #[cfg(test)]
    pub(crate) fn init_test_accounts_table(
        db_data: &WalletDb<Network>,
    ) -> (DiversifiableFullViewingKey, Option<TransparentAddress>) {
        let (ufvk, taddr) = init_test_accounts_table_ufvk(db_data);
        (ufvk.sapling().unwrap().clone(), taddr)
    }

    #[cfg(test)]
    pub(crate) fn init_test_accounts_table_ufvk(
        db_data: &WalletDb<Network>,
    ) -> (UnifiedFullViewingKey, Option<TransparentAddress>) {
        let seed = [0u8; 32];
        let account = AccountId::from(0);
        let extsk = sapling::spending_key(&seed, network().coin_type(), account);
        let dfvk = extsk.to_diversifiable_full_viewing_key();

        #[cfg(feature = "transparent-inputs")]
        let (tkey, taddr) = {
            let tkey = legacy::keys::AccountPrivKey::from_seed(&network(), &seed, account)
                .unwrap()
                .to_account_pubkey();
            let taddr = tkey.derive_external_ivk().unwrap().default_address().0;
            (Some(tkey), Some(taddr))
        };

        #[cfg(not(feature = "transparent-inputs"))]
        let taddr = None;

        let ufvk = UnifiedFullViewingKey::new(
            #[cfg(feature = "transparent-inputs")]
            tkey,
            Some(dfvk),
            None,
        )
        .unwrap();

        let ufvks = HashMap::from([(account, ufvk.clone())]);
        init_accounts_table(db_data, &ufvks).unwrap();

        (ufvk, taddr)
    }

    #[allow(dead_code)]
    pub(crate) enum AddressType {
        DefaultExternal,
        DiversifiedExternal(DiversifierIndex),
        Internal,
    }

    /// Create a fake CompactBlock at the given height, containing a single output paying
    /// an address. Returns the CompactBlock and the nullifier for the new note.
    pub(crate) fn fake_compact_block(
        height: BlockHeight,
        prev_hash: BlockHash,
        dfvk: &DiversifiableFullViewingKey,
        req: AddressType,
        value: Amount,
    ) -> (CompactBlock, Nullifier) {
        let to = match req {
            AddressType::DefaultExternal => dfvk.default_address().1,
            AddressType::DiversifiedExternal(idx) => dfvk.find_address(idx).unwrap().1,
            AddressType::Internal => dfvk.change_address().1,
        };

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&network(), height, &mut rng);
        let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let cout = CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        };
        let mut ctx = CompactTx::default();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.hash = txid;
        ctx.outputs.push(cout);
        let mut cb = CompactBlock {
            hash: {
                let mut hash = vec![0; 32];
                rng.fill_bytes(&mut hash);
                hash
            },
            height: height.into(),
            ..Default::default()
        };
        cb.prev_hash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        (cb, note.nf(&dfvk.fvk().vk.nk, 0))
    }

    /// Create a fake CompactBlock at the given height, spending a single note from the
    /// given address.
    pub(crate) fn fake_compact_block_spending(
        height: BlockHeight,
        prev_hash: BlockHash,
        (nf, in_value): (Nullifier, Amount),
        dfvk: &DiversifiableFullViewingKey,
        to: PaymentAddress,
        value: Amount,
    ) -> CompactBlock {
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&network(), height, &mut rng);

        // Create a fake CompactBlock containing the note
        let cspend = CompactSaplingSpend { nf: nf.to_vec() };
        let mut ctx = CompactTx::default();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.hash = txid;
        ctx.spends.push(cspend);

        // Create a fake Note for the payment
        ctx.outputs.push({
            let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
            let encryptor = sapling_note_encryption::<_, Network>(
                Some(dfvk.fvk().ovk),
                note.clone(),
                MemoBytes::empty(),
                &mut rng,
            );
            let cmu = note.cmu().to_bytes().to_vec();
            let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
                .0
                .to_vec();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            CompactSaplingOutput {
                cmu,
                ephemeral_key,
                ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
            }
        });

        // Create a fake Note for the change
        ctx.outputs.push({
            let change_addr = dfvk.default_address().1;
            let rseed = generate_random_rseed(&network(), height, &mut rng);
            let note = Note::from_parts(
                change_addr,
                NoteValue::from_raw((in_value - value).unwrap().into()),
                rseed,
            );
            let encryptor = sapling_note_encryption::<_, Network>(
                Some(dfvk.fvk().ovk),
                note.clone(),
                MemoBytes::empty(),
                &mut rng,
            );
            let cmu = note.cmu().to_bytes().to_vec();
            let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
                .0
                .to_vec();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            CompactSaplingOutput {
                cmu,
                ephemeral_key,
                ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
            }
        });

        let mut cb = CompactBlock {
            hash: {
                let mut hash = vec![0; 32];
                rng.fill_bytes(&mut hash);
                hash
            },
            height: height.into(),
            ..Default::default()
        };
        cb.prev_hash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        cb
    }

    /// Insert a fake CompactBlock into the cache DB.
    pub(crate) fn insert_into_cache(db_cache: &BlockDb, cb: &CompactBlock) {
        let cb_bytes = cb.encode_to_vec();
        db_cache
            .0
            .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
            .unwrap()
            .execute(params![u32::from(cb.height()), cb_bytes,])
            .unwrap();
    }

    #[cfg(feature = "unstable")]
    pub(crate) fn store_in_fsblockdb<P: AsRef<Path>>(
        fsblockdb_root: P,
        cb: &CompactBlock,
    ) -> BlockMeta {
        use std::io::Write;

        let meta = BlockMeta {
            height: cb.height(),
            block_hash: cb.hash(),
            block_time: cb.time,
            sapling_outputs_count: cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum(),
            orchard_actions_count: cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum(),
        };

        let blocks_dir = fsblockdb_root.as_ref().join("blocks");
        let block_path = meta.block_file_path(&blocks_dir);

        File::create(block_path)
            .unwrap()
            .write_all(&cb.encode_to_vec())
            .unwrap();

        meta
    }

    #[test]
    pub(crate) fn get_next_available_address() {
        use tempfile::NamedTempFile;

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), network()).unwrap();

        let account = AccountId::from(0);
        init_wallet_db(&mut db_data, None).unwrap();
        let _ = init_test_accounts_table_ufvk(&db_data);

        let current_addr = db_data.get_current_address(account).unwrap();
        assert!(current_addr.is_some());

        let mut update_ops = db_data.get_update_ops().unwrap();
        let addr2 = update_ops.get_next_available_address(account).unwrap();
        assert!(addr2.is_some());
        assert_ne!(current_addr, addr2);

        let addr2_cur = db_data.get_current_address(account).unwrap();
        assert_eq!(addr2, addr2_cur);
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn transparent_receivers() {
        use secrecy::Secret;
        use tempfile::NamedTempFile;

        use crate::{chain::init::init_cache_database, wallet::init::init_wallet_db};

        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet.
        let (ufvk, taddr) = init_test_accounts_table_ufvk(&db_data);
        let taddr = taddr.unwrap();

        let receivers = db_data.get_transparent_receivers(0.into()).unwrap();

        // The receiver for the default UA should be in the set.
        assert!(receivers.contains_key(ufvk.default_address().0.transparent().unwrap()));

        // The default t-addr should be in the set.
        assert!(receivers.contains_key(&taddr));
    }

    #[cfg(feature = "unstable")]
    #[test]
    pub(crate) fn fsblockdb_api() {
        // Initialise a BlockMeta DB in a new directory.
        let fsblockdb_root = tempfile::tempdir().unwrap();
        let mut db_meta = FsBlockDb::for_path(&fsblockdb_root).unwrap();
        init_blockmeta_db(&mut db_meta).unwrap();

        // The BlockMeta DB starts off empty.
        assert_eq!(db_meta.get_max_cached_height().unwrap(), None);

        // Generate some fake CompactBlocks.
        let seed = [0u8; 32];
        let account = AccountId::from(0);
        let extsk = sapling::spending_key(&seed, network().coin_type(), account);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let (cb1, _) = fake_compact_block(
            BlockHeight::from_u32(1),
            BlockHash([1; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(5).unwrap(),
        );
        let (cb2, _) = fake_compact_block(
            BlockHeight::from_u32(2),
            BlockHash([2; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(10).unwrap(),
        );

        // Write the CompactBlocks to the BlockMeta DB's corresponding disk storage.
        let meta1 = store_in_fsblockdb(&fsblockdb_root, &cb1);
        let meta2 = store_in_fsblockdb(&fsblockdb_root, &cb2);

        // The BlockMeta DB is not updated until we do so explicitly.
        assert_eq!(db_meta.get_max_cached_height().unwrap(), None);

        // Inform the BlockMeta DB about the newly-persisted CompactBlocks.
        db_meta.write_block_metadata(&[meta1, meta2]).unwrap();

        // The BlockMeta DB now sees blocks up to height 2.
        assert_eq!(
            db_meta.get_max_cached_height().unwrap(),
            Some(BlockHeight::from_u32(2)),
        );
        assert_eq!(
            db_meta.find_block(BlockHeight::from_u32(1)).unwrap(),
            Some(meta1),
        );
        assert_eq!(
            db_meta.find_block(BlockHeight::from_u32(2)).unwrap(),
            Some(meta2),
        );
        assert_eq!(db_meta.find_block(BlockHeight::from_u32(3)).unwrap(), None);

        // Rewinding to height 1 should cause the metadata for height 2 to be deleted.
        db_meta
            .truncate_to_height(BlockHeight::from_u32(1))
            .unwrap();
        assert_eq!(
            db_meta.get_max_cached_height().unwrap(),
            Some(BlockHeight::from_u32(1)),
        );
        assert_eq!(
            db_meta.find_block(BlockHeight::from_u32(1)).unwrap(),
            Some(meta1),
        );
        assert_eq!(db_meta.find_block(BlockHeight::from_u32(2)).unwrap(), None);
        assert_eq!(db_meta.find_block(BlockHeight::from_u32(3)).unwrap(), None);
    }
}
