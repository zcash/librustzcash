//! Interfaces for wallet data persistence & low-level wallet utilities.

use std::cmp;
use std::collections::HashMap;
use std::fmt::Debug;

use zcash_primitives::{
    block::BlockHash,
    consensus::BlockHeight,
    memo::{Memo, MemoBytes},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::{Node, Nullifier, PaymentAddress},
    transaction::{components::Amount, Transaction, TxId},
    zip32::{AccountId, ExtendedFullViewingKey},
};

use crate::{
    address::RecipientAddress,
    decrypt::DecryptedOutput,
    keys::UnifiedFullViewingKey,
    proto::compact_formats::CompactBlock,
    wallet::{SpendableNote, WalletTx},
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::WalletTransparentOutput,
    zcash_primitives::{legacy::TransparentAddress, transaction::components::OutPoint},
};

pub mod chain;
pub mod error;
pub mod wallet;

/// Read-only operations required for light wallet functions.
///
/// This trait defines the read-only portion of the storage interface atop which
/// higher-level wallet operations are implemented. It serves to allow wallet functions to
/// be abstracted away from any particular data storage substrate.
pub trait WalletRead {
    /// The type of errors produced by a wallet backend.
    type Error;

    /// Backend-specific note identifier.
    ///
    /// For example, this might be a database identifier type
    /// or a UUID.
    type NoteRef: Copy + Debug;

    /// Backend-specific transaction identifier.
    ///
    /// For example, this might be a database identifier type
    /// or a TxId if the backend is able to support that type
    /// directly.
    type TxRef: Copy + Debug;

    /// Returns the minimum and maximum block heights for stored blocks.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error>;

    /// Returns the default target height (for the block in which a new
    /// transaction would be mined) and anchor height (to use for a new
    /// transaction), given the range of block heights that the backend
    /// knows about.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: u32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        self.block_height_extrema().map(|heights| {
            heights.map(|(min_height, max_height)| {
                let target_height = max_height + 1;

                // Select an anchor min_confirmations back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = BlockHeight::from(cmp::max(
                    u32::from(target_height).saturating_sub(min_confirmations),
                    u32::from(min_height),
                ));

                (target_height, anchor_height)
            })
        })
    }

    /// Returns the block hash for the block at the given height, if the
    /// associated block data is available. Returns `Ok(None)` if the hash
    /// is not found in the database.
    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error>;

    /// Returns the block hash for the block at the maximum height known
    /// in stored data.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        self.block_height_extrema()
            .and_then(|extrema_opt| {
                extrema_opt
                    .map(|(_, max_height)| {
                        self.get_block_hash(max_height)
                            .map(|hash_opt| hash_opt.map(move |hash| (max_height, hash)))
                    })
                    .transpose()
            })
            .map(|oo| oo.flatten())
    }

    /// Returns the block height in which the specified transaction was mined,
    /// or `Ok(None)` if the transaction is not mined in the main chain.
    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the payment address for the specified account, if the account
    /// identifier specified refers to a valid account for this wallet.
    ///
    /// This will return `Ok(None)` if the account identifier does not correspond
    /// to a known account.
    // TODO: This does not appear to be the case.
    fn get_address(&self, account: AccountId) -> Result<Option<PaymentAddress>, Self::Error>;

    /// Returns all unified full viewing keys known to this wallet.
    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, Self::Error>;

    /// Checks whether the specified extended full viewing key is
    /// associated with the account.
    fn is_valid_account_extfvk(
        &self,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error>;

    /// Returns the wallet balance for an account as of the specified block
    /// height.
    ///
    /// This may be used to obtain a balance that ignores notes that have been
    /// received so recently that they are not yet deemed spendable.
    fn get_balance_at(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error>;

    /// Returns the memo for a note.
    ///
    /// Implementations of this method must return an error if the note identifier
    /// does not appear in the backing data store.
    fn get_memo(&self, id_note: Self::NoteRef) -> Result<Memo, Self::Error>;

    /// Returns a transaction.
    fn get_transaction(&self, id_tx: Self::TxRef) -> Result<Transaction, Self::Error>;

    /// Returns the note commitment tree at the specified block height.
    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error>;

    /// Returns the incremental witnesses as of the specified block height.
    #[allow(clippy::type_complexity)]
    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error>;

    /// Returns the nullifiers for notes that the wallet is tracking, along with their
    /// associated account IDs, that are either unspent or have not yet been confirmed as
    /// spent (in that the spending transaction has not yet been included in a block).
    fn get_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error>;

    /// Returns all nullifiers for notes that the wallet is tracking
    /// (including those for notes that have been previously spent),
    /// along with the account identifiers with which they are associated.
    fn get_all_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error>;

    /// Return all unspent Sapling notes.
    fn get_spendable_sapling_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error>;

    /// Returns a list of spendable Sapling notes sufficient to cover the specified
    /// target value, if possible.
    fn select_spendable_sapling_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error>;
}

#[cfg(feature = "transparent-inputs")]
pub trait WalletReadTransparent: WalletRead {
    /// Returns a list of unspent transparent UTXOs that appear in the chain at heights up to and
    /// including `max_height`.
    fn get_unspent_transparent_outputs(
        &self,
        address: &TransparentAddress,
        max_height: BlockHeight,
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error>;
}

/// The subset of information that is relevant to this wallet that has been
/// decrypted and extracted from a [CompactBlock].
pub struct PrunedBlock<'a> {
    pub block_height: BlockHeight,
    pub block_hash: BlockHash,
    pub block_time: u32,
    pub commitment_tree: &'a CommitmentTree<Node>,
    pub transactions: &'a Vec<WalletTx<Nullifier>>,
}

/// A transaction that was detected during scanning of the blockchain,
/// including its decrypted Sapling outputs.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are successfully decrypted.
pub struct DecryptedTransaction<'a> {
    pub tx: &'a Transaction,
    pub sapling_outputs: &'a Vec<DecryptedOutput>,
}

/// A transaction that was constructed and sent by the wallet.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are created and submitted
/// to the network.
pub struct SentTransaction<'a> {
    pub tx: &'a Transaction,
    pub created: time::OffsetDateTime,
    pub account: AccountId,
    pub outputs: Vec<SentTransactionOutput<'a>>,
    #[cfg(feature = "transparent-inputs")]
    pub utxos_spent: Vec<OutPoint>,
}

pub struct SentTransactionOutput<'a> {
    /// The index within the transaction that contains the recipient output.
    ///
    /// - If `recipient_address` is a Sapling address, this is an index into the Sapling
    ///   outputs of the transaction.
    /// - If `recipient_address` is a transparent address, this is an index into the
    ///   transparent outputs of the transaction.
    pub output_index: usize,
    pub recipient_address: &'a RecipientAddress,
    pub value: Amount,
    pub memo: Option<MemoBytes>,
}

/// This trait encapsulates the write capabilities required to update stored
/// wallet data.
pub trait WalletWrite: WalletRead {
    /// Updates the state of the wallet database by persisting the provided
    /// block information, along with the updated witness data that was
    /// produced when scanning the block for transactions pertaining to
    /// this wallet.
    #[allow(clippy::type_complexity)]
    fn advance_by_block(
        &mut self,
        block: &PrunedBlock,
        updated_witnesses: &[(Self::NoteRef, IncrementalWitness<Node>)],
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error>;

    /// Caches a decrypted transaction in the persistent wallet store.
    fn store_decrypted_tx(
        &mut self,
        received_tx: &DecryptedTransaction,
    ) -> Result<Self::TxRef, Self::Error>;

    fn store_sent_tx(&mut self, sent_tx: &SentTransaction) -> Result<Self::TxRef, Self::Error>;

    /// Rewinds the wallet database to the specified height.
    ///
    /// This method assumes that the state of the underlying data store is
    /// consistent up to a particular block height. Since it is possible that
    /// a chain reorg might invalidate some stored state, this method must be
    /// implemented in order to allow users of this API to "reset" the data store
    /// to correctly represent chainstate as of a specified block height.
    ///
    /// After calling this method, the block at the given height will be the
    /// most recent block and all other operations will treat this block
    /// as the chain tip for balance determination purposes.
    ///
    /// There may be restrictions on how far it is possible to rewind.
    fn rewind_to_height(&mut self, block_height: BlockHeight) -> Result<(), Self::Error>;
}

#[cfg(feature = "transparent-inputs")]
pub trait WalletWriteTransparent: WalletWrite + WalletReadTransparent {
    type UtxoRef;

    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error>;
}

/// This trait provides sequential access to raw blockchain data via a callback-oriented
/// API.
pub trait BlockSource {
    type Error;

    /// Scan the specified `limit` number of blocks from the blockchain, starting at
    /// `from_height`, applying the provided callback to each block.
    fn with_blocks<F>(
        &self,
        from_height: BlockHeight,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), Self::Error>
    where
        F: FnMut(CompactBlock) -> Result<(), Self::Error>;
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use std::collections::HashMap;

    use zcash_primitives::{
        block::BlockHash,
        consensus::BlockHeight,
        legacy::TransparentAddress,
        memo::Memo,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        sapling::{Node, Nullifier, PaymentAddress},
        transaction::{components::Amount, Transaction, TxId},
        zip32::{AccountId, ExtendedFullViewingKey},
    };

    use crate::{
        keys::UnifiedFullViewingKey,
        proto::compact_formats::CompactBlock,
        wallet::{SpendableNote, WalletTransparentOutput},
    };

    use super::{
        error::Error, BlockSource, DecryptedTransaction, PrunedBlock, SentTransaction, WalletRead,
        WalletWrite,
    };

    #[cfg(feature = "transparent-inputs")]
    use super::WalletReadTransparent;

    pub struct MockBlockSource {}

    impl BlockSource for MockBlockSource {
        type Error = Error<u32>;

        fn with_blocks<F>(
            &self,
            _from_height: BlockHeight,
            _limit: Option<u32>,
            _with_row: F,
        ) -> Result<(), Self::Error>
        where
            F: FnMut(CompactBlock) -> Result<(), Self::Error>,
        {
            Ok(())
        }
    }

    pub struct MockWalletDb {}

    impl WalletRead for MockWalletDb {
        type Error = Error<u32>;
        type NoteRef = u32;
        type TxRef = TxId;

        fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
            Ok(None)
        }

        fn get_block_hash(
            &self,
            _block_height: BlockHeight,
        ) -> Result<Option<BlockHash>, Self::Error> {
            Ok(None)
        }

        fn get_tx_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
            Ok(None)
        }

        fn get_address(&self, _account: AccountId) -> Result<Option<PaymentAddress>, Self::Error> {
            Ok(None)
        }

        fn get_unified_full_viewing_keys(
            &self,
        ) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, Self::Error> {
            Ok(HashMap::new())
        }

        fn is_valid_account_extfvk(
            &self,
            _account: AccountId,
            _extfvk: &ExtendedFullViewingKey,
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn get_balance_at(
            &self,
            _account: AccountId,
            _anchor_height: BlockHeight,
        ) -> Result<Amount, Self::Error> {
            Ok(Amount::zero())
        }

        fn get_memo(&self, _id_note: Self::NoteRef) -> Result<Memo, Self::Error> {
            Ok(Memo::Empty)
        }

        fn get_transaction(&self, _id_tx: Self::TxRef) -> Result<Transaction, Self::Error> {
            Err(Error::ScanRequired) // wrong error but we'll fix it later.
        }

        fn get_commitment_tree(
            &self,
            _block_height: BlockHeight,
        ) -> Result<Option<CommitmentTree<Node>>, Self::Error> {
            Ok(None)
        }

        #[allow(clippy::type_complexity)]
        fn get_witnesses(
            &self,
            _block_height: BlockHeight,
        ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error> {
            Ok(Vec::new())
        }

        fn get_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error> {
            Ok(Vec::new())
        }

        fn get_all_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error> {
            Ok(Vec::new())
        }

        fn get_spendable_sapling_notes(
            &self,
            _account: AccountId,
            _anchor_height: BlockHeight,
        ) -> Result<Vec<SpendableNote>, Self::Error> {
            Ok(Vec::new())
        }

        fn select_spendable_sapling_notes(
            &self,
            _account: AccountId,
            _target_value: Amount,
            _anchor_height: BlockHeight,
        ) -> Result<Vec<SpendableNote>, Self::Error> {
            Ok(Vec::new())
        }
    }

    #[cfg(feature = "transparent-inputs")]
    impl WalletReadTransparent for MockWalletDb {
        fn get_unspent_transparent_outputs(
            &self,
            _address: &TransparentAddress,
            _anchor_height: BlockHeight,
        ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
            Ok(Vec::new())
        }
    }

    impl WalletWrite for MockWalletDb {
        #[allow(clippy::type_complexity)]
        fn advance_by_block(
            &mut self,
            _block: &PrunedBlock,
            _updated_witnesses: &[(Self::NoteRef, IncrementalWitness<Node>)],
        ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error> {
            Ok(vec![])
        }

        fn store_decrypted_tx(
            &mut self,
            _received_tx: &DecryptedTransaction,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId::from_bytes([0u8; 32]))
        }

        fn store_sent_tx(
            &mut self,
            _sent_tx: &SentTransaction,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId::from_bytes([0u8; 32]))
        }

        fn rewind_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
