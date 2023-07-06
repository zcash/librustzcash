//! Interfaces for wallet data persistence & low-level wallet utilities.

use std::collections::HashMap;
use std::fmt::Debug;
use std::num::NonZeroU32;
use std::{cmp, ops::Range};

use incrementalmerkletree::Retention;
use secrecy::SecretVec;
use shardtree::{ShardStore, ShardTree, ShardTreeError};
use zcash_primitives::{
    block::BlockHash,
    consensus::BlockHeight,
    legacy::TransparentAddress,
    memo::{Memo, MemoBytes},
    sapling,
    transaction::{
        components::{amount::Amount, OutPoint},
        Transaction, TxId,
    },
    zip32::{AccountId, ExtendedFullViewingKey},
};

use crate::{
    address::{AddressMetadata, UnifiedAddress},
    decrypt::DecryptedOutput,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{ReceivedSaplingNote, WalletTransparentOutput, WalletTx},
};

use self::chain::CommitmentTreeRoot;

pub mod chain;
pub mod error;
pub mod wallet;

pub const SAPLING_SHARD_HEIGHT: u8 = sapling::NOTE_COMMITMENT_TREE_DEPTH / 2;

pub enum NullifierQuery {
    Unspent,
    All,
}

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
    type NoteRef: Copy + Debug + Eq + Ord;

    /// Backend-specific transaction identifier.
    ///
    /// For example, this might be a database identifier type
    /// or a TxId if the backend is able to support that type
    /// directly.
    type TxRef: Copy + Debug + Eq + Ord;

    /// Returns the wallet's view of the chain tip to the given depth.
    ///
    /// This may return fewer than `depth` blocks worth of data if insufficient block data is
    /// available in the wallet database to provide metadata contiguous blocks to the requested
    /// depth. Metadata values for returned blocks are sequential and in height order.
    fn chain_tip(&self, depth: usize) -> Result<Vec<BlockMetadata>, Self::Error>;

    /// Returns the minimum and maximum block heights for stored blocks.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error>;

    /// Returns the available block metadata for the block at the specified height, if any.
    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error>;

    /// Returns the metadata for the block at the height to which the wallet has been fully
    /// scanned.
    ///
    /// This is the height for which the wallet has fully trial-decrypted this and all preceding
    /// blocks above the wallet's birthday height. Along with this height, this method returns
    /// metadata describing the state of the wallet's note commitment trees as of the end of that
    /// block.
    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error>;

    /// Returns a vector of suggested scan ranges based upon the current wallet state.
    ///
    /// This method should only be used in cases where the [`CompactBlock`] data that will be made
    /// available to `scan_cached_blocks` for the requested block ranges includes note commitment
    /// tree size information for each block; or else the scan is likely to fail if notes belonging
    /// to the wallet are detected.
    ///
    /// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
    fn suggest_scan_ranges(
        &self,
        batch_size: usize,
        limit: usize,
    ) -> Result<Vec<Range<BlockHeight>>, Self::Error>;

    /// Returns the default target height (for the block in which a new
    /// transaction would be mined) and anchor height (to use for a new
    /// transaction), given the range of block heights that the backend
    /// knows about.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        self.block_height_extrema().map(|heights| {
            heights.map(|(min_height, max_height)| {
                let target_height = max_height + 1;

                // Select an anchor min_confirmations back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = BlockHeight::from(cmp::max(
                    u32::from(target_height).saturating_sub(min_confirmations.into()),
                    u32::from(min_height),
                ));

                (target_height, anchor_height)
            })
        })
    }

    /// Returns the minimum block height corresponding to an unspent note in the wallet.
    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error>;

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

    /// Returns the block height in which the specified transaction was mined, or `Ok(None)` if the
    /// transaction is not in the main chain.
    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the most recently generated unified address for the specified account, if the
    /// account identifier specified refers to a valid account for this wallet.
    ///
    /// This will return `Ok(None)` if the account identifier does not correspond to a known
    /// account.
    fn get_current_address(
        &self,
        account: AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error>;

    /// Returns all unified full viewing keys known to this wallet.
    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, Self::Error>;

    /// Returns the account id corresponding to a given [`UnifiedFullViewingKey`], if any.
    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<AccountId>, Self::Error>;

    /// Checks whether the specified extended full viewing key is associated with the account.
    fn is_valid_account_extfvk(
        &self,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error>;

    /// Returns the wallet balance for an account as of the specified block height.
    ///
    /// This may be used to obtain a balance that ignores notes that have been received so recently
    /// that they are not yet deemed spendable.
    fn get_balance_at(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error>;

    /// Returns the memo for a note.
    ///
    /// Implementations of this method must return an error if the note identifier
    /// does not appear in the backing data store. Returns `Ok(None)` if the note
    /// is known to the wallet but memo data has not yet been populated for that
    /// note.
    fn get_memo(&self, id_note: Self::NoteRef) -> Result<Option<Memo>, Self::Error>;

    /// Returns a transaction.
    fn get_transaction(&self, id_tx: Self::TxRef) -> Result<Transaction, Self::Error>;

    /// Returns the nullifiers for notes that the wallet is tracking, along with their associated
    /// account IDs, that are either unspent or have not yet been confirmed as spent (in that a
    /// spending transaction known to the wallet has not yet been included in a block).
    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(AccountId, sapling::Nullifier)>, Self::Error>;

    /// Return all unspent Sapling notes.
    fn get_spendable_sapling_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error>;

    /// Returns a list of spendable Sapling notes sufficient to cover the specified target value,
    /// if possible.
    fn select_spendable_sapling_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error>;

    /// Returns the set of all transparent receivers associated with the given account.
    ///
    /// The set contains all transparent receivers that are known to have been derived
    /// under this account. Wallets should scan the chain for UTXOs sent to these
    /// receivers.
    fn get_transparent_receivers(
        &self,
        account: AccountId,
    ) -> Result<HashMap<TransparentAddress, AddressMetadata>, Self::Error>;

    /// Returns a list of unspent transparent UTXOs that appear in the chain at heights up to and
    /// including `max_height`.
    fn get_unspent_transparent_outputs(
        &self,
        address: &TransparentAddress,
        max_height: BlockHeight,
        exclude: &[OutPoint],
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error>;

    /// Returns a mapping from transparent receiver to not-yet-shielded UTXO balance,
    /// for each address associated with a nonzero balance.
    fn get_transparent_balances(
        &self,
        account: AccountId,
        max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, Amount>, Self::Error>;
}

/// Metadata describing the sizes of the zcash note commitment trees as of a particular block.
#[derive(Debug, Clone, Copy)]
pub struct BlockMetadata {
    block_height: BlockHeight,
    block_hash: BlockHash,
    sapling_tree_size: u32,
    //TODO: orchard_tree_size: u32
}

impl BlockMetadata {
    /// Constructs a new [`BlockMetadata`] value from its constituent parts.
    pub fn from_parts(
        block_height: BlockHeight,
        block_hash: BlockHash,
        sapling_tree_size: u32,
    ) -> Self {
        Self {
            block_height,
            block_hash,
            sapling_tree_size,
        }
    }

    /// Returns the block height.
    pub fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Returns the hash of the block
    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Returns the size of the Sapling note commitment tree as of the block that this
    /// [`BlockMetadata`] describes.
    pub fn sapling_tree_size(&self) -> u32 {
        self.sapling_tree_size
    }
}

/// The subset of information that is relevant to this wallet that has been
/// decrypted and extracted from a [`CompactBlock`].
///
/// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
pub struct ScannedBlock<Nf> {
    metadata: BlockMetadata,
    block_time: u32,
    transactions: Vec<WalletTx<Nf>>,
    sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
}

impl<Nf> ScannedBlock<Nf> {
    pub fn from_parts(
        metadata: BlockMetadata,
        block_time: u32,
        transactions: Vec<WalletTx<Nf>>,
        sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
    ) -> Self {
        Self {
            metadata,
            block_time,
            transactions,
            sapling_commitments,
        }
    }

    pub fn height(&self) -> BlockHeight {
        self.metadata.block_height
    }

    pub fn block_hash(&self) -> BlockHash {
        self.metadata.block_hash
    }

    pub fn block_time(&self) -> u32 {
        self.block_time
    }

    pub fn metadata(&self) -> &BlockMetadata {
        &self.metadata
    }

    pub fn transactions(&self) -> &[WalletTx<Nf>] {
        &self.transactions
    }

    pub fn sapling_commitments(&self) -> &[(sapling::Node, Retention<BlockHeight>)] {
        &self.sapling_commitments
    }

    pub fn into_sapling_commitments(self) -> Vec<(sapling::Node, Retention<BlockHeight>)> {
        self.sapling_commitments
    }
}

/// A transaction that was detected during scanning of the blockchain,
/// including its decrypted Sapling outputs.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are successfully decrypted.
pub struct DecryptedTransaction<'a> {
    pub tx: &'a Transaction,
    pub sapling_outputs: &'a Vec<DecryptedOutput<sapling::Note>>,
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
    pub outputs: Vec<SentTransactionOutput>,
    pub fee_amount: Amount,
    #[cfg(feature = "transparent-inputs")]
    pub utxos_spent: Vec<OutPoint>,
}

/// A shielded transfer protocol supported by the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ShieldedProtocol {
    /// The Sapling protocol
    Sapling,
    // TODO: Orchard
}

/// A value pool to which the wallet supports sending transaction outputs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PoolType {
    /// The transparent value pool
    Transparent,
    /// A shielded value pool.
    Shielded(ShieldedProtocol),
}

/// A type that represents the recipient of a transaction output; a recipient address (and, for
/// unified addresses, the pool to which the payment is sent) in the case of outgoing output, or an
/// internal account ID and the pool to which funds were sent in the case of a wallet-internal
/// output.
#[derive(Debug, Clone)]
pub enum Recipient {
    Transparent(TransparentAddress),
    Sapling(sapling::PaymentAddress),
    Unified(UnifiedAddress, PoolType),
    InternalAccount(AccountId, PoolType),
}

/// A type that represents an output (either Sapling or transparent) that was sent by the wallet.
pub struct SentTransactionOutput {
    output_index: usize,
    recipient: Recipient,
    value: Amount,
    memo: Option<MemoBytes>,
    sapling_change_to: Option<(AccountId, sapling::Note)>,
}

impl SentTransactionOutput {
    pub fn from_parts(
        output_index: usize,
        recipient: Recipient,
        value: Amount,
        memo: Option<MemoBytes>,
        sapling_change_to: Option<(AccountId, sapling::Note)>,
    ) -> Self {
        Self {
            output_index,
            recipient,
            value,
            memo,
            sapling_change_to,
        }
    }
    /// Returns the index within the transaction that contains the recipient output.
    ///
    /// - If `recipient_address` is a Sapling address, this is an index into the Sapling
    ///   outputs of the transaction.
    /// - If `recipient_address` is a transparent address, this is an index into the
    ///   transparent outputs of the transaction.
    pub fn output_index(&self) -> usize {
        self.output_index
    }
    /// Returns the recipient address of the transaction, or the account id for wallet-internal
    /// transactions.
    pub fn recipient(&self) -> &Recipient {
        &self.recipient
    }
    /// Returns the value of the newly created output.
    pub fn value(&self) -> Amount {
        self.value
    }
    /// Returns the memo that was attached to the output, if any.
    pub fn memo(&self) -> Option<&MemoBytes> {
        self.memo.as_ref()
    }

    /// Returns t decrypted note, if the sent output belongs to this wallet
    pub fn sapling_change_to(&self) -> Option<&(AccountId, sapling::Note)> {
        self.sapling_change_to.as_ref()
    }
}

/// This trait encapsulates the write capabilities required to update stored
/// wallet data.
pub trait WalletWrite: WalletRead {
    /// The type of identifiers used to look up transparent UTXOs.
    type UtxoRef;

    /// Tells the wallet to track the next available account-level spend authority, given
    /// the current set of [ZIP 316] account identifiers known to the wallet database.
    ///
    /// Returns the account identifier for the newly-created wallet database entry, along
    /// with the associated [`UnifiedSpendingKey`].
    ///
    /// If `seed` was imported from a backup and this method is being used to restore a
    /// previous wallet state, you should use this method to add all of the desired
    /// accounts before scanning the chain from the seed's birthday height.
    ///
    /// By convention, wallets should only allow a new account to be generated after funds
    /// have been received by the currently-available account (in order to enable
    /// automated account recovery).
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
    ) -> Result<(AccountId, UnifiedSpendingKey), Self::Error>;

    /// Generates and persists the next available diversified address, given the current
    /// addresses known to the wallet.
    ///
    /// Returns `Ok(None)` if the account identifier does not correspond to a known
    /// account.
    fn get_next_available_address(
        &mut self,
        account: AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error>;

    /// Updates the state of the wallet database by persisting the provided block information,
    /// along with the note commitments that were detected when scanning the block for transactions
    /// pertaining to this wallet.
    fn put_block(
        &mut self,
        block: ScannedBlock<sapling::Nullifier>,
    ) -> Result<Vec<Self::NoteRef>, Self::Error>;

    /// Caches a decrypted transaction in the persistent wallet store.
    fn store_decrypted_tx(
        &mut self,
        received_tx: DecryptedTransaction,
    ) -> Result<Self::TxRef, Self::Error>;

    /// Saves information about a transaction that was constructed and sent by the wallet to the
    /// persistent wallet store.
    fn store_sent_tx(&mut self, sent_tx: &SentTransaction) -> Result<Self::TxRef, Self::Error>;

    /// Truncates the wallet database to the specified height.
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
    /// There may be restrictions on heights to which it is possible to truncate.
    fn truncate_to_height(&mut self, block_height: BlockHeight) -> Result<(), Self::Error>;

    /// Adds a transparent UTXO received by the wallet to the data store.
    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error>;
}

/// This trait describes a capability for manipulating wallet note commitment trees.
///
/// At present, this only serves the Sapling protocol, but it will be modified to
/// also provide operations related to Orchard note commitment trees in the future.
pub trait WalletCommitmentTrees {
    type Error;
    type SaplingShardStore<'a>: ShardStore<
        H = sapling::Node,
        CheckpointId = BlockHeight,
        Error = Self::Error,
    >;

    fn with_sapling_tree_mut<F, A, E>(&mut self, callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>;

    /// Adds a sequence of note commitment tree subtree roots to the data store.
    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>>;
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use incrementalmerkletree::Address;
    use secrecy::{ExposeSecret, SecretVec};
    use shardtree::{MemoryShardStore, ShardTree, ShardTreeError};
    use std::{collections::HashMap, convert::Infallible, ops::Range};

    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, Network},
        legacy::TransparentAddress,
        memo::Memo,
        sapling,
        transaction::{
            components::{Amount, OutPoint},
            Transaction, TxId,
        },
        zip32::{AccountId, ExtendedFullViewingKey},
    };

    use crate::{
        address::{AddressMetadata, UnifiedAddress},
        keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
        wallet::{ReceivedSaplingNote, WalletTransparentOutput},
    };

    use super::{
        chain::CommitmentTreeRoot, BlockMetadata, DecryptedTransaction, NullifierQuery,
        ScannedBlock, SentTransaction, WalletCommitmentTrees, WalletRead, WalletWrite,
        SAPLING_SHARD_HEIGHT,
    };

    pub struct MockWalletDb {
        pub network: Network,
        pub sapling_tree: ShardTree<
            MemoryShardStore<sapling::Node, BlockHeight>,
            { SAPLING_SHARD_HEIGHT * 2 },
            SAPLING_SHARD_HEIGHT,
        >,
    }

    impl MockWalletDb {
        pub fn new(network: Network) -> Self {
            Self {
                network,
                sapling_tree: ShardTree::new(MemoryShardStore::empty(), 100),
            }
        }
    }

    impl WalletRead for MockWalletDb {
        type Error = ();
        type NoteRef = u32;
        type TxRef = TxId;

        fn chain_tip(&self, _depth: usize) -> Result<Vec<BlockMetadata>, Self::Error> {
            Ok(vec![])
        }

        fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
            Ok(None)
        }

        fn block_metadata(
            &self,
            _height: BlockHeight,
        ) -> Result<Option<BlockMetadata>, Self::Error> {
            Ok(None)
        }

        fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
            Ok(None)
        }

        fn suggest_scan_ranges(
            &self,
            _batch_size: usize,
            _limit: usize,
        ) -> Result<Vec<Range<BlockHeight>>, Self::Error> {
            Ok(vec![])
        }

        fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
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

        fn get_current_address(
            &self,
            _account: AccountId,
        ) -> Result<Option<UnifiedAddress>, Self::Error> {
            Ok(None)
        }

        fn get_unified_full_viewing_keys(
            &self,
        ) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, Self::Error> {
            Ok(HashMap::new())
        }

        fn get_account_for_ufvk(
            &self,
            _ufvk: &UnifiedFullViewingKey,
        ) -> Result<Option<AccountId>, Self::Error> {
            Ok(None)
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

        fn get_memo(&self, _id_note: Self::NoteRef) -> Result<Option<Memo>, Self::Error> {
            Ok(None)
        }

        fn get_transaction(&self, _id_tx: Self::TxRef) -> Result<Transaction, Self::Error> {
            Err(())
        }

        fn get_sapling_nullifiers(
            &self,
            _query: NullifierQuery,
        ) -> Result<Vec<(AccountId, sapling::Nullifier)>, Self::Error> {
            Ok(Vec::new())
        }

        fn get_spendable_sapling_notes(
            &self,
            _account: AccountId,
            _anchor_height: BlockHeight,
            _exclude: &[Self::NoteRef],
        ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error> {
            Ok(Vec::new())
        }

        fn select_spendable_sapling_notes(
            &self,
            _account: AccountId,
            _target_value: Amount,
            _anchor_height: BlockHeight,
            _exclude: &[Self::NoteRef],
        ) -> Result<Vec<ReceivedSaplingNote<Self::NoteRef>>, Self::Error> {
            Ok(Vec::new())
        }

        fn get_transparent_receivers(
            &self,
            _account: AccountId,
        ) -> Result<HashMap<TransparentAddress, AddressMetadata>, Self::Error> {
            Ok(HashMap::new())
        }

        fn get_unspent_transparent_outputs(
            &self,
            _address: &TransparentAddress,
            _anchor_height: BlockHeight,
            _exclude: &[OutPoint],
        ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
            Ok(Vec::new())
        }

        fn get_transparent_balances(
            &self,
            _account: AccountId,
            _max_height: BlockHeight,
        ) -> Result<HashMap<TransparentAddress, Amount>, Self::Error> {
            Ok(HashMap::new())
        }
    }

    impl WalletWrite for MockWalletDb {
        type UtxoRef = u32;

        fn create_account(
            &mut self,
            seed: &SecretVec<u8>,
        ) -> Result<(AccountId, UnifiedSpendingKey), Self::Error> {
            let account = AccountId::from(0);
            UnifiedSpendingKey::from_seed(&self.network, seed.expose_secret(), account)
                .map(|k| (account, k))
                .map_err(|_| ())
        }

        fn get_next_available_address(
            &mut self,
            _account: AccountId,
        ) -> Result<Option<UnifiedAddress>, Self::Error> {
            Ok(None)
        }

        #[allow(clippy::type_complexity)]
        fn put_block(
            &mut self,
            _block: ScannedBlock<sapling::Nullifier>,
        ) -> Result<Vec<Self::NoteRef>, Self::Error> {
            Ok(vec![])
        }

        fn store_decrypted_tx(
            &mut self,
            _received_tx: DecryptedTransaction,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId::from_bytes([0u8; 32]))
        }

        fn store_sent_tx(
            &mut self,
            _sent_tx: &SentTransaction,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId::from_bytes([0u8; 32]))
        }

        fn truncate_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
            Ok(())
        }

        /// Adds a transparent UTXO received by the wallet to the data store.
        fn put_received_transparent_utxo(
            &mut self,
            _output: &WalletTransparentOutput,
        ) -> Result<Self::UtxoRef, Self::Error> {
            Ok(0)
        }
    }

    impl WalletCommitmentTrees for MockWalletDb {
        type Error = Infallible;
        type SaplingShardStore<'a> = MemoryShardStore<sapling::Node, BlockHeight>;

        fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
        where
            for<'a> F: FnMut(
                &'a mut ShardTree<
                    Self::SaplingShardStore<'a>,
                    { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                    SAPLING_SHARD_HEIGHT,
                >,
            ) -> Result<A, E>,
            E: From<ShardTreeError<Infallible>>,
        {
            callback(&mut self.sapling_tree)
        }

        fn put_sapling_subtree_roots(
            &mut self,
            start_index: u64,
            roots: &[CommitmentTreeRoot<sapling::Node>],
        ) -> Result<(), ShardTreeError<Self::Error>> {
            self.with_sapling_tree_mut(|t| {
                for (root, i) in roots.iter().zip(0u64..) {
                    let root_addr =
                        Address::from_parts(SAPLING_SHARD_HEIGHT.into(), start_index + i);
                    t.insert(root_addr, *root.root_hash())?;
                }
                Ok::<_, ShardTreeError<Self::Error>>(())
            })?;

            Ok(())
        }
    }
}
