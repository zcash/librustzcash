//! Interfaces for wallet data persistence & low-level wallet utilities.

use std::cmp;
use std::collections::HashMap;
use std::fmt::Debug;

use zcash_primitives::{
    block::BlockHash,
    consensus::BlockHeight,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    note_encryption::Memo,
    primitives::{Note, Nullifier, PaymentAddress},
    sapling::Node,
    transaction::{components::Amount, Transaction, TxId},
    zip32::ExtendedFullViewingKey,
};

use crate::{
    address::RecipientAddress,
    data_api::wallet::ANCHOR_OFFSET,
    decrypt::DecryptedOutput,
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, SpendableNote, WalletShieldedOutput, WalletTx},
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

    /// Returns the memo for a received note, if it is known and a valid UTF-8 string.
    ///
    /// This will return `Ok(None)` if the note identifier does not appear in the
    /// database as a known note ID.
    fn get_memo_as_utf8(
        &self,
        id_note: Self::NoteRef,
    ) -> Result<Option<String>, Self::Error>;

    /// Returns the note commitment tree at the specified block height.
    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error>;

    /// Returns the incremental witnesses as of the specified block height.
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

/// This trait encapsulates the write capabilities required to update stored
/// wallet data.
pub trait WalletWrite: WalletRead {
    /// Perform one or more write operations of this trait transactionally.
    /// Implementations of this method must ensure that all mutations to the
    /// state of the data store made by the provided closure must be performed
    /// atomically and modifications to state must be automatically rolled back
    /// if the provided closure returns an error.
    fn transactionally<F, A>(&mut self, f: F) -> Result<A, Self::Error>
    where
        F: FnOnce(&mut Self) -> Result<A, Self::Error>;

    /// Add the data for a block to the data store.
    fn insert_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        commitment_tree: &CommitmentTree<Node>,
    ) -> Result<(), Self::Error>;

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

    /// Add wallet-relevant metadata for a specific transaction to the data
    /// store.
    fn put_tx_meta(
        &mut self,
        tx: &WalletTx,
        height: BlockHeight,
    ) -> Result<Self::TxRef, Self::Error>;

    /// Add a full transaction contents to the data store.
    fn put_tx_data(
        &mut self,
        tx: &Transaction,
        created_at: Option<time::OffsetDateTime>,
    ) -> Result<Self::TxRef, Self::Error>;

    /// Mark the specified transaction as spent and record the nullifier.
    fn mark_spent(&mut self, tx_ref: Self::TxRef, nf: &Nullifier) -> Result<(), Self::Error>;

    /// Record a note as having been received, along with its nullifier and the transaction
    /// within which the note was created.
    ///
    /// Implementations of this method must be exclusively additive with respect to stored
    /// data; passing `None` for the nullifier should not be interpreted as deleting nullifier
    /// information from the underlying store.
    ///
    /// Implementations of this method must ensure that attempting to record the same note
    /// with a different nullifier to that already stored will return an error.
    fn put_received_note<T: ShieldedOutput>(
        &mut self,
        output: &T,
        nf: &Option<Nullifier>,
        tx_ref: Self::TxRef,
    ) -> Result<Self::NoteRef, Self::Error>;

    /// Add the incremental witness for the specified note to the database.
    fn insert_witness(
        &mut self,
        note_id: Self::NoteRef,
        witness: &IncrementalWitness<Node>,
        height: BlockHeight,
    ) -> Result<(), Self::Error>;

    /// Remove all incremental witness data before the specified block height.
    //  TODO: this is a backend-specific optimization that probably shouldn't be part of
    //  the public API
    fn prune_witnesses(&mut self, from_height: BlockHeight) -> Result<(), Self::Error>;

    /// Remove the spent marker from any received notes that had been spent in a
    /// transaction constructed by the wallet, but which transaction had not been mined
    /// by the specified block height.
    //  TODO: this is a backend-specific optimization that probably shouldn't be part of
    //  the public API
    fn update_expired_notes(&mut self, from_height: BlockHeight) -> Result<(), Self::Error>;

    /// Add the decrypted contents of a sent note to the database if it does not exist;
    /// otherwise, update the note. This is useful in the case of a wallet restore where
    /// the send of the note is being discovered via trial decryption.
    fn put_sent_note(
        &mut self,
        output: &DecryptedOutput,
        tx_ref: Self::TxRef,
    ) -> Result<(), Self::Error>;

    /// Add the decrypted contents of a sent note to the database.
    fn insert_sent_note(
        &mut self,
        tx_ref: Self::TxRef,
        output_index: usize,
        account: AccountId,
        to: &RecipientAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<(), Self::Error>;
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

/// This trait provides a generalization over shielded output representations
/// that allows a wallet to avoid coupling to a specific one.
// TODO: it'd probably be better not to unify the definitions of
// `WalletShieldedOutput` and `DecryptedOutput` via a compositional
// approach, if possible.
pub trait ShieldedOutput {
    fn index(&self) -> usize;
    fn account(&self) -> AccountId;
    fn to(&self) -> &PaymentAddress;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&Memo>;
    fn is_change(&self) -> Option<bool>;
}

impl ShieldedOutput for WalletShieldedOutput {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        self.account
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&Memo> {
        None
    }
    fn is_change(&self) -> Option<bool> {
        Some(self.is_change)
    }
}

impl ShieldedOutput for DecryptedOutput {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        self.account
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&Memo> {
        Some(&self.memo)
    }
    fn is_change(&self) -> Option<bool> {
        None
    }
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use std::collections::HashMap;

    use zcash_primitives::{
        block::BlockHash,
        consensus::BlockHeight,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        note_encryption::Memo,
        primitives::{Nullifier, PaymentAddress},
        sapling::Node,
        transaction::{components::Amount, Transaction, TxId},
        zip32::ExtendedFullViewingKey,
    };

    use crate::{
        address::RecipientAddress,
        decrypt::DecryptedOutput,
        proto::compact_formats::CompactBlock,
        wallet::{AccountId, SpendableNote, WalletTx},
    };

    use super::{error::Error, BlockSource, ShieldedOutput, WalletRead, WalletWrite};

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

    pub struct MockWalletDB {}

    impl WalletRead for MockWalletDB {
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

        fn get_memo_as_utf8(
            &self,
            _id_note: Self::NoteRef,
        ) -> Result<Option<String>, Self::Error> {
            Ok(None)
        }

        fn get_commitment_tree(
            &self,
            _block_height: BlockHeight,
        ) -> Result<Option<CommitmentTree<Node>>, Self::Error> {
            Ok(None)
        }

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

    impl WalletWrite for MockWalletDB {
        fn transactionally<F, A>(&mut self, f: F) -> Result<A, Self::Error>
        where
            F: FnOnce(&mut Self) -> Result<A, Self::Error>,
        {
            f(self)
        }

        fn insert_block(
            &mut self,
            _block_height: BlockHeight,
            _block_hash: BlockHash,
            _block_time: u32,
            _commitment_tree: &CommitmentTree<Node>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn rewind_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
            Ok(())
        }

        fn put_tx_meta(
            &mut self,
            _tx: &WalletTx,
            _height: BlockHeight,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId([0u8; 32]))
        }

        fn put_tx_data(
            &mut self,
            _tx: &Transaction,
            _created_at: Option<time::OffsetDateTime>,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId([0u8; 32]))
        }

        fn mark_spent(&mut self, _tx_ref: Self::TxRef, _nf: &Nullifier) -> Result<(), Self::Error> {
            Ok(())
        }

        fn put_received_note<T: ShieldedOutput>(
            &mut self,
            _output: &T,
            _nf: &Option<Nullifier>,
            _tx_ref: Self::TxRef,
        ) -> Result<Self::NoteRef, Self::Error> {
            Ok(0u32)
        }

        fn insert_witness(
            &mut self,
            _note_id: Self::NoteRef,
            _witness: &IncrementalWitness<Node>,
            _height: BlockHeight,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn prune_witnesses(&mut self, _from_height: BlockHeight) -> Result<(), Self::Error> {
            Ok(())
        }

        fn update_expired_notes(&mut self, _from_height: BlockHeight) -> Result<(), Self::Error> {
            Ok(())
        }

        fn put_sent_note(
            &mut self,
            _output: &DecryptedOutput,
            _tx_ref: Self::TxRef,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn insert_sent_note(
            &mut self,
            _tx_ref: Self::TxRef,
            _output_index: usize,
            _account: AccountId,
            _to: &RecipientAddress,
            _value: Amount,
            _memo: Option<Memo>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
