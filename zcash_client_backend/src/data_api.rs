//! Interfaces for wallet data persistence & low-level wallet utilities.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    io,
    num::{NonZeroU32, TryFromIntError},
};

use incrementalmerkletree::{frontier::Frontier, Retention};
use secrecy::SecretVec;
use shardtree::{error::ShardTreeError, store::ShardStore, ShardTree};
use zcash_primitives::{
    block::BlockHash,
    consensus::BlockHeight,
    legacy::TransparentAddress,
    memo::{Memo, MemoBytes},
    sapling::{self, Node, NOTE_COMMITMENT_TREE_DEPTH},
    transaction::{
        components::{
            amount::{Amount, NonNegativeAmount},
            OutPoint,
        },
        Transaction, TxId,
    },
    zip32::{AccountId, ExtendedFullViewingKey},
};

use crate::{
    address::{AddressMetadata, UnifiedAddress},
    decrypt::DecryptedOutput,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
    proto::service::TreeState,
    wallet::{ReceivedSaplingNote, WalletTransparentOutput, WalletTx},
};

use self::chain::CommitmentTreeRoot;
use self::scanning::ScanRange;

pub mod chain;
pub mod error;
pub mod scanning;
pub mod wallet;

/// The height of subtree roots in the Sapling note commitment tree.
///
/// This conforms to the structure of subtree data returned by
/// `lightwalletd` when using the `GetSubtreeRoots` GRPC call.
pub const SAPLING_SHARD_HEIGHT: u8 = sapling::NOTE_COMMITMENT_TREE_DEPTH / 2;

/// An enumeration of constraints that can be applied when querying for nullifiers for notes
/// belonging to the wallet.
pub enum NullifierQuery {
    Unspent,
    All,
}

/// Balance information for a value within a single pool in an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    /// The value in the account that may currently be spent; it is possible to compute witnesses
    /// for all the notes that comprise this value, and all of this value is confirmed to the
    /// required confirmation depth.
    pub spendable_value: NonNegativeAmount,

    /// The value in the account of shielded change notes that do not yet have sufficient
    /// confirmations to be spendable.
    pub change_pending_confirmation: NonNegativeAmount,

    /// The value in the account of all remaining received notes that either do not have sufficient
    /// confirmations to be spendable, or for which witnesses cannot yet be constructed without
    /// additional scanning.
    pub value_pending_spendability: NonNegativeAmount,
}

impl Balance {
    /// The [`Balance`] value having zero values for all its fields.
    pub const ZERO: Self = Self {
        spendable_value: NonNegativeAmount::ZERO,
        change_pending_confirmation: NonNegativeAmount::ZERO,
        value_pending_spendability: NonNegativeAmount::ZERO,
    };

    /// Returns the total value of funds represented by this [`Balance`].
    pub fn total(&self) -> NonNegativeAmount {
        (self.spendable_value + self.change_pending_confirmation + self.value_pending_spendability)
            .expect("Balance cannot overflow MAX_MONEY")
    }
}

/// Balance information for a single account. The sum of this struct's fields is the total balance
/// of the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountBalance {
    /// The value of unspent Sapling outputs belonging to the account.
    pub sapling_balance: Balance,

    /// The value of all unspent transparent outputs belonging to the account, irrespective of
    /// confirmation depth.
    ///
    /// Unshielded balances are not subject to confirmation-depth constraints, because the only
    /// possible operation on a transparent balance is to shield it, it is possible to create a
    /// zero-conf transaction to perform that shielding, and the resulting shielded notes will be
    /// subject to normal confirmation rules.
    pub unshielded: NonNegativeAmount,
}

impl AccountBalance {
    /// The [`Balance`] value having zero values for all its fields.
    pub const ZERO: Self = Self {
        sapling_balance: Balance::ZERO,
        unshielded: NonNegativeAmount::ZERO,
    };

    /// Returns the total value of funds belonging to the account.
    pub fn total(&self) -> NonNegativeAmount {
        (self.sapling_balance.total() + self.unshielded)
            .expect("Account balance cannot overflow MAX_MONEY")
    }
}

/// A polymorphic ratio type, usually used for rational numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ratio<T> {
    numerator: T,
    denominator: T,
}

impl<T> Ratio<T> {
    /// Constructs a new Ratio from a numerator and a denominator.
    pub fn new(numerator: T, denominator: T) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// Returns the numerator of the ratio.
    pub fn numerator(&self) -> &T {
        &self.numerator
    }

    /// Returns the denominator of the ratio.
    pub fn denominator(&self) -> &T {
        &self.denominator
    }
}

/// A type representing the potentially-spendable value of unspent outputs in the wallet.
///
/// The balances reported using this data structure may overestimate the total spendable value of
/// the wallet, in the case that the spend of a previously received shielded note has not yet been
/// detected by the process of scanning the chain. The balances reported using this data structure
/// can only be certain to be unspent in the case that [`Self::is_synced`] is true, and even in
/// this circumstance it is possible that a newly created transaction could conflict with a
/// not-yet-mined transaction in the mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSummary {
    account_balances: BTreeMap<AccountId, AccountBalance>,
    chain_tip_height: BlockHeight,
    fully_scanned_height: BlockHeight,
    scan_progress: Option<Ratio<u64>>,
}

impl WalletSummary {
    /// Constructs a new [`WalletSummary`] from its constituent parts.
    pub fn new(
        account_balances: BTreeMap<AccountId, AccountBalance>,
        chain_tip_height: BlockHeight,
        fully_scanned_height: BlockHeight,
        scan_progress: Option<Ratio<u64>>,
    ) -> Self {
        Self {
            account_balances,
            chain_tip_height,
            fully_scanned_height,
            scan_progress,
        }
    }

    /// Returns the balances of accounts in the wallet, keyed by account ID.
    pub fn account_balances(&self) -> &BTreeMap<AccountId, AccountBalance> {
        &self.account_balances
    }

    /// Returns the height of the current chain tip.
    pub fn chain_tip_height(&self) -> BlockHeight {
        self.chain_tip_height
    }

    /// Returns the height below which all blocks have been scanned by the wallet, ignoring blocks
    /// below the wallet birthday.
    pub fn fully_scanned_height(&self) -> BlockHeight {
        self.fully_scanned_height
    }

    /// Returns the progress of scanning shielded outputs, in terms of the ratio between notes
    /// scanned and the total number of notes added to the chain since the wallet birthday.
    ///
    /// This ratio should only be used to compute progress percentages, and the numerator and
    /// denominator should not be treated as authoritative note counts. Returns `None` if the
    /// wallet is unable to determine the size of the note commitment tree.
    pub fn scan_progress(&self) -> Option<Ratio<u64>> {
        self.scan_progress
    }

    /// Returns whether or not wallet scanning is complete.
    pub fn is_synced(&self) -> bool {
        self.chain_tip_height == self.fully_scanned_height
    }
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

    /// Returns the height of the chain as known to the wallet as of the most recent call to
    /// [`WalletWrite::update_chain_tip`].
    ///
    /// This will return `Ok(None)` if the height of the current consensus chain tip is unknown.
    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error>;

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

    /// Returns block metadata for the maximum height that the wallet has scanned.
    ///
    /// If the wallet is fully synced, this will be equivalent to `block_fully_scanned`;
    /// otherwise the maximal scanned height is likely to be greater than the fully scanned height
    /// due to the fact that out-of-order scanning can leave gaps.
    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error>;

    /// Returns a vector of suggested scan ranges based upon the current wallet state.
    ///
    /// This method should only be used in cases where the [`CompactBlock`] data that will be made
    /// available to `scan_cached_blocks` for the requested block ranges includes note commitment
    /// tree size information for each block; or else the scan is likely to fail if notes belonging
    /// to the wallet are detected.
    ///
    /// The returned range(s) may include block heights beyond the current chain tip.
    ///
    /// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error>;

    /// Returns the default target height (for the block in which a new
    /// transaction would be mined) and anchor height (to use for a new
    /// transaction), given the range of block heights that the backend
    /// knows about.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error>;

    /// Returns the minimum block height corresponding to an unspent note in the wallet.
    fn get_min_unspent_height(&self) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the block hash for the block at the given height, if the
    /// associated block data is available. Returns `Ok(None)` if the hash
    /// is not found in the database.
    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error>;

    /// Returns the block height and hash for the block at the maximum scanned block height.
    ///
    /// This will return `Ok(None)` if no blocks have been scanned.
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error>;

    /// Returns the block height in which the specified transaction was mined, or `Ok(None)` if the
    /// transaction is not in the main chain.
    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the birthday height for the wallet.
    ///
    /// This returns the earliest birthday height among accounts maintained by this wallet,
    /// or `Ok(None)` if the wallet has no initialized accounts.
    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the birthday height for the given account, or an error if the account is not known
    /// to the wallet.
    fn get_account_birthday(&self, account: AccountId) -> Result<BlockHeight, Self::Error>;

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

    /// Returns the wallet balances and sync status for an account given the specified minimum
    /// number of confirmations, or `Ok(None)` if the wallet has no balance data available.
    fn get_wallet_summary(
        &self,
        min_confirmations: u32,
    ) -> Result<Option<WalletSummary>, Self::Error>;

    /// Returns the memo for a note.
    ///
    /// Returns `Ok(None)` if the note is known to the wallet but memo data has not yet been
    /// populated for that note, or if the note identifier does not correspond to a note
    /// that is known to the wallet.
    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error>;

    /// Returns a transaction.
    fn get_transaction(&self, txid: TxId) -> Result<Transaction, Self::Error>;

    /// Returns the nullifiers for notes that the wallet is tracking, along with their associated
    /// account IDs, that are either unspent or have not yet been confirmed as spent (in that a
    /// spending transaction known to the wallet has not yet been included in a block).
    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(AccountId, sapling::Nullifier)>, Self::Error>;

    /// Return all unspent Sapling notes, excluding the specified note IDs.
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
    sapling_nullifier_map: Vec<(TxId, u16, Vec<sapling::Nullifier>)>,
    sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
}

impl<Nf> ScannedBlock<Nf> {
    pub fn from_parts(
        metadata: BlockMetadata,
        block_time: u32,
        transactions: Vec<WalletTx<Nf>>,
        sapling_nullifier_map: Vec<(TxId, u16, Vec<sapling::Nullifier>)>,
        sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
    ) -> Self {
        Self {
            metadata,
            block_time,
            transactions,
            sapling_nullifier_map,
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

    pub fn sapling_nullifier_map(&self) -> &[(TxId, u16, Vec<sapling::Nullifier>)] {
        &self.sapling_nullifier_map
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShieldedProtocol {
    /// The Sapling protocol
    Sapling,
    // TODO: Orchard
}

/// A unique identifier for a shielded transaction output
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoteId {
    txid: TxId,
    protocol: ShieldedProtocol,
    output_index: u16,
}

impl NoteId {
    /// Constructs a new `NoteId` from its parts.
    pub fn new(txid: TxId, protocol: ShieldedProtocol, output_index: u16) -> Self {
        Self {
            txid,
            protocol,
            output_index,
        }
    }

    /// Returns the ID of the transaction containing this note.
    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    /// Returns the shielded protocol used by this note.
    pub fn protocol(&self) -> ShieldedProtocol {
        self.protocol
    }

    /// Returns the index of this note within its transaction's corresponding list of
    /// shielded outputs.
    pub fn output_index(&self) -> u16 {
        self.output_index
    }
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
    /// Returns the memo that was attached to the output, if any. This will only be `None`
    /// for transparent outputs.
    pub fn memo(&self) -> Option<&MemoBytes> {
        self.memo.as_ref()
    }

    /// Returns the account to which change (or wallet-internal value in the case of a shielding
    /// transaction) was sent, along with the change note.
    pub fn sapling_change_to(&self) -> Option<&(AccountId, sapling::Note)> {
        self.sapling_change_to.as_ref()
    }
}

/// A data structure used to set the birthday height for an account, and ensure that the initial
/// note commitment tree state is recorded at that height.
#[derive(Clone, Debug)]
pub struct AccountBirthday {
    height: BlockHeight,
    sapling_frontier: Frontier<Node, NOTE_COMMITMENT_TREE_DEPTH>,
    recover_until: Option<BlockHeight>,
}

/// Errors that can occur in the construction of an [`AccountBirthday`] from a [`TreeState`].
pub enum BirthdayError {
    HeightInvalid(TryFromIntError),
    Decode(io::Error),
}

impl From<TryFromIntError> for BirthdayError {
    fn from(value: TryFromIntError) -> Self {
        Self::HeightInvalid(value)
    }
}

impl From<io::Error> for BirthdayError {
    fn from(value: io::Error) -> Self {
        Self::Decode(value)
    }
}

impl AccountBirthday {
    /// Constructs a new [`AccountBirthday`] from its constituent parts.
    ///
    /// * `height`: The birthday height of the account. This is defined as the height of the first
    ///    block to be scanned in wallet recovery.
    /// * `sapling_frontier`: The Sapling note commitment tree frontier as of the end of the block
    ///    prior to the birthday height.
    /// * `recover_until`: An optional height at which the wallet should exit "recovery mode". In
    ///    order to avoid confusing shifts in wallet balance and spendability that may temporarily be
    ///    visible to a user during the process of recovering from seed, wallets may optionally set a
    ///    "recover until" height. The wallet is considered to be in "recovery mode" until there
    ///    exist no unscanned ranges between the wallet's birthday height and the provided
    ///    `recover_until` height, exclusive.
    ///
    /// This API is intended primarily to be used in testing contexts; under normal circumstances,
    /// [`AccountBirthday::from_treestate`] should be used instead.
    #[cfg(feature = "test-dependencies")]
    pub fn from_parts(
        height: BlockHeight,
        sapling_frontier: Frontier<Node, NOTE_COMMITMENT_TREE_DEPTH>,
        recover_until: Option<BlockHeight>,
    ) -> Self {
        Self {
            height,
            sapling_frontier,
            recover_until,
        }
    }

    /// Constructs a new [`AccountBirthday`] from a [`TreeState`] returned from `lightwalletd`.
    ///
    /// * `treestate`: The tree state corresponding to the last block prior to the wallet's
    ///    birthday height.
    /// * `recover_until`: An optional height at which the wallet should exit "recovery mode". In
    ///    order to avoid confusing shifts in wallet balance and spendability that may temporarily be
    ///    visible to a user during the process of recovering from seed, wallets may optionally set a
    ///    "recover until" height. The wallet is considered to be in "recovery mode" until there
    ///    exist no unscanned ranges between the wallet's birthday height and the provided
    ///    `recover_until` height, exclusive.
    pub fn from_treestate(
        treestate: TreeState,
        recover_until: Option<BlockHeight>,
    ) -> Result<Self, BirthdayError> {
        Ok(Self {
            height: BlockHeight::try_from(treestate.height + 1)?,
            sapling_frontier: treestate.sapling_tree()?.to_frontier(),
            recover_until,
        })
    }

    /// Returns the Sapling note commitment tree frontier as of the end of the block at
    /// [`Self::height`].
    pub fn sapling_frontier(&self) -> &Frontier<Node, NOTE_COMMITMENT_TREE_DEPTH> {
        &self.sapling_frontier
    }

    /// Returns the birthday height of the account.
    pub fn height(&self) -> BlockHeight {
        self.height
    }

    /// Returns the height at which the wallet should exit "recovery mode".
    pub fn recover_until(&self) -> Option<BlockHeight> {
        self.recover_until
    }

    #[cfg(feature = "test-dependencies")]
    /// Constructs a new [`AccountBirthday`] at Sapling activation, with no
    /// "recover until" height.
    ///
    /// # Panics
    ///
    /// Panics if the Sapling activation height is not set.
    pub fn from_sapling_activation<P: zcash_primitives::consensus::Parameters>(
        params: &P,
    ) -> AccountBirthday {
        use zcash_primitives::consensus::NetworkUpgrade;

        AccountBirthday::from_parts(
            params.activation_height(NetworkUpgrade::Sapling).unwrap(),
            Frontier::empty(),
            None,
        )
    }
}

/// This trait encapsulates the write capabilities required to update stored
/// wallet data.
pub trait WalletWrite: WalletRead {
    /// The type of identifiers used to look up transparent UTXOs.
    type UtxoRef;

    /// Tells the wallet to track the next available account-level spend authority, given the
    /// current set of [ZIP 316] account identifiers known to the wallet database.
    ///
    /// Returns the account identifier for the newly-created wallet database entry, along with the
    /// associated [`UnifiedSpendingKey`].
    ///
    /// If `birthday.height()` is below the current chain tip, this operation will
    /// trigger a re-scan of the blocks at and above the provided height. The birthday height is
    /// defined as the minimum block height that will be scanned for funds belonging to the wallet.
    ///
    /// For new wallets, callers should construct the [`AccountBirthday`] using
    /// [`AccountBirthday::from_treestate`] for the block at height `chain_tip_height - 100`.
    /// Setting the birthday height to a tree state below the pruning depth ensures that reorgs
    /// cannot cause funds intended for the wallet to be missed; otherwise, if the chain tip height
    /// were used for the wallet birthday, a transaction targeted at a height greater than the
    /// chain tip could be mined at a height below that tip as part of a reorg.
    ///
    /// If `seed` was imported from a backup and this method is being used to restore a previous
    /// wallet state, you should use this method to add all of the desired accounts before scanning
    /// the chain from the seed's birthday height.
    ///
    /// By convention, wallets should only allow a new account to be generated after confirmed
    /// funds have been received by the currently-available account (in order to enable automated
    /// account recovery).
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
        birthday: AccountBirthday,
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
    ///
    /// `blocks` must be sequential, in order of increasing block height
    fn put_blocks(
        &mut self,
        blocks: Vec<ScannedBlock<sapling::Nullifier>>,
    ) -> Result<(), Self::Error>;

    /// Updates the wallet's view of the blockchain.
    ///
    /// This method is used to provide the wallet with information about the state of the
    /// blockchain, and detect any previously scanned data that needs to be re-validated
    /// before proceeding with scanning. It should be called at wallet startup prior to calling
    /// [`WalletRead::suggest_scan_ranges`] in order to provide the wallet with the information it
    /// needs to correctly prioritize scanning operations.
    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Self::Error>;

    /// Caches a decrypted transaction in the persistent wallet store.
    fn store_decrypted_tx(&mut self, received_tx: DecryptedTransaction) -> Result<(), Self::Error>;

    /// Saves information about a transaction that was constructed and sent by the wallet to the
    /// persistent wallet store.
    fn store_sent_tx(&mut self, sent_tx: &SentTransaction) -> Result<(), Self::Error>;

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
    use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
    use std::{collections::HashMap, convert::Infallible, num::NonZeroU32};

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
        chain::CommitmentTreeRoot, scanning::ScanRange, AccountBirthday, BlockMetadata,
        DecryptedTransaction, NoteId, NullifierQuery, ScannedBlock, SentTransaction,
        WalletCommitmentTrees, WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
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

        fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
            Ok(None)
        }

        fn get_target_and_anchor_heights(
            &self,
            _min_confirmations: NonZeroU32,
        ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
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

        fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
            Ok(None)
        }

        fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
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

        fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
            Ok(None)
        }

        fn get_tx_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
            Ok(None)
        }

        fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
            Ok(None)
        }

        fn get_account_birthday(&self, _account: AccountId) -> Result<BlockHeight, Self::Error> {
            Err(())
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

        fn get_wallet_summary(
            &self,
            _min_confirmations: u32,
        ) -> Result<Option<WalletSummary>, Self::Error> {
            Ok(None)
        }

        fn get_memo(&self, _id_note: NoteId) -> Result<Option<Memo>, Self::Error> {
            Ok(None)
        }

        fn get_transaction(&self, _txid: TxId) -> Result<Transaction, Self::Error> {
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
            _birthday: AccountBirthday,
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
        fn put_blocks(
            &mut self,
            _blocks: Vec<ScannedBlock<sapling::Nullifier>>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn update_chain_tip(&mut self, _tip_height: BlockHeight) -> Result<(), Self::Error> {
            Ok(())
        }

        fn store_decrypted_tx(
            &mut self,
            _received_tx: DecryptedTransaction,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn store_sent_tx(&mut self, _sent_tx: &SentTransaction) -> Result<(), Self::Error> {
            Ok(())
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
