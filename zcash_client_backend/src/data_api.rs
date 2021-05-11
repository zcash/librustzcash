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
    zip32::ExtendedFullViewingKey,
};

use crate::{
    address::RecipientAddress,
    data_api::wallet::ANCHOR_OFFSET,
    decrypt::DecryptedOutput,
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, SpendableNote, WalletTx},
};

pub mod chain;
pub mod error;
pub mod wallet;

/// Read-only operations required for light wallet functions.
///
/// This trait defines the read-only portion of the storage
/// interface atop which higher-level wallet operations are
/// implemented. It serves to allow wallet functions to be
/// abstracted away from any particular data storage substrate.
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
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        self.block_height_extrema().map(|heights| {
            heights.map(|(min_height, max_height)| {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = BlockHeight::from(cmp::max(
                    u32::from(target_height).saturating_sub(ANCHOR_OFFSET),
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
    fn get_address(&self, account: AccountId) -> Result<Option<PaymentAddress>, Self::Error>;

    /// Returns all extended full viewing keys known about by this wallet.
    fn get_extended_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, ExtendedFullViewingKey>, Self::Error>;

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

    /// Returns the unspent nullifiers, along with the account identifiers
    /// with which they are associated.
    fn get_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error>;

    /// Return all spendable notes.
    fn get_spendable_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error>;

    /// Returns a list of spendable notes sufficient to cover the specified
    /// target value, if possible.
    fn select_spendable_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error>;
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
pub struct ReceivedTransaction<'a> {
    pub tx: &'a Transaction,
    pub outputs: &'a Vec<DecryptedOutput>,
}

/// A transaction that was constructed and sent by the wallet.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are created and submitted
/// to the network.
pub struct SentTransaction<'a> {
    pub tx: &'a Transaction,
    pub created: time::OffsetDateTime,
    /// The index within the transaction that contains the recipient output.
    ///
    /// - If `recipient_address` is a Sapling address, this is an index into the Sapling
    ///   outputs of the transaction.
    /// - If `recipient_address` is a transparent address, this is an index into the
    ///   transparent outputs of the transaction.
    pub output_index: usize,
    pub account: AccountId,
    pub recipient_address: &'a RecipientAddress,
    pub value: Amount,
    pub memo: Option<MemoBytes>,
}

/// This trait encapsulates the write capabilities required to update stored
/// wallet data.
pub trait WalletWrite: WalletRead {
    #[allow(clippy::type_complexity)]
    fn advance_by_block(
        &mut self,
        block: &PrunedBlock,
        updated_witnesses: &[(Self::NoteRef, IncrementalWitness<Node>)],
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error>;

    fn store_received_tx(
        &mut self,
        received_tx: &ReceivedTransaction,
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
        memo::Memo,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        sapling::{Node, Nullifier, PaymentAddress},
        transaction::{components::Amount, TxId},
        zip32::ExtendedFullViewingKey,
    };

    use crate::{
        proto::compact_formats::CompactBlock,
        wallet::{AccountId, SpendableNote},
    };

    use super::{
        error::Error, BlockSource, PrunedBlock, ReceivedTransaction, SentTransaction, WalletRead,
        WalletWrite,
    };

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

        fn get_extended_full_viewing_keys(
            &self,
        ) -> Result<HashMap<AccountId, ExtendedFullViewingKey>, Self::Error> {
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

        fn get_spendable_notes(
            &self,
            _account: AccountId,
            _anchor_height: BlockHeight,
        ) -> Result<Vec<SpendableNote>, Self::Error> {
            Ok(Vec::new())
        }

        fn select_spendable_notes(
            &self,
            _account: AccountId,
            _target_value: Amount,
            _anchor_height: BlockHeight,
        ) -> Result<Vec<SpendableNote>, Self::Error> {
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

        fn store_received_tx(
            &mut self,
            _received_tx: &ReceivedTransaction,
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
