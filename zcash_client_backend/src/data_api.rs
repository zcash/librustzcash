//! # Utilities for Zcash wallet construction
//!
//! This module defines a set of APIs for wallet data persistence, and provides a suite of methods
//! based upon these APIs that can be used to implement a fully functional Zcash wallet. At
//! present, the interfaces provided here are built primarily around the use of a source of
//! [`CompactBlock`] data such as the Zcash Light Client Protocol as defined in
//! [ZIP 307](https://zips.z.cash/zip-0307) but they may be generalized to full-block use cases in
//! the future.
//!
//! ## Important Concepts
//!
//! There are several important operations that a Zcash wallet must perform that distinguish Zcash
//! wallet design from wallets for other cryptocurrencies.
//!
//! * Viewing Keys: Wallets based upon this module are built around the capabilities of Zcash
//!   [`UnifiedFullViewingKey`]s; the wallet backend provides no facilities for the storage
//!   of spending keys, and spending keys must be provided by the caller in order to perform
//!   transaction creation operations.
//! * Blockchain Scanning: A Zcash wallet must download and trial-decrypt each transaction on the
//!   Zcash blockchain using one or more Viewing Keys in order to find new shielded transaction
//!   outputs (generally termed "notes") belonging to the wallet. The primary entrypoint for this
//!   functionality is the [`scan_cached_blocks`] method. See the [`chain`] module for additional
//!   details.
//! * Witness Updates: In order to spend a shielded note, the wallet must be able to compute the
//!   Merkle path to that note in the global note commitment tree. When [`scan_cached_blocks`] is
//!   used to process a range of blocks, the note commitment tree is updated with the note
//!   commitments for the blocks in that range.
//! * Transaction Construction: The [`wallet`] module provides functions for creating Zcash
//!   transactions that spend funds belonging to the wallet.
//!
//! ## Core Traits
//!
//! The utility functions described above depend upon four important traits defined in this
//! module, which between them encompass the data storage requirements of a light wallet.
//! The relevant traits are [`InputSource`], [`WalletRead`], [`WalletWrite`], and
//! [`WalletCommitmentTrees`]. A complete implementation of the data storage layer for a wallet
//! will include an implementation of all four of these traits. See the [`zcash_client_sqlite`]
//! crate for a complete example of the implementation of these traits.
//!
//! ## Accounts
//!
//! The operation of the [`InputSource`], [`WalletRead`] and [`WalletWrite`] traits is built around
//! the concept of a wallet having one or more accounts, with a unique `AccountId` for each
//! account.
//!
//! An account identifier corresponds to at most a single [`UnifiedSpendingKey`]'s worth of spend
//! authority, with the received and spent notes of that account tracked via the corresponding
//! [`UnifiedFullViewingKey`]. Both received notes and change spendable by that spending authority
//! (both the external and internal parts of that key, as defined by
//! [ZIP 316](https://zips.z.cash/zip-0316)) will be interpreted as belonging to that account.
//!
//! [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
//! [`scan_cached_blocks`]: crate::data_api::chain::scan_cached_blocks
//! [`zcash_client_sqlite`]: https://crates.io/crates/zcash_client_sqlite
//! [`TransactionRequest`]: crate::zip321::TransactionRequest
//! [`propose_shielding`]: crate::data_api::wallet::propose_shielding

use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    io,
    num::{NonZeroU32, TryFromIntError},
};

use incrementalmerkletree::{frontier::Frontier, Retention};
use nonempty::NonEmpty;
use secrecy::SecretVec;
use shardtree::{error::ShardTreeError, store::ShardStore, ShardTree};
use zip32::fingerprint::SeedFingerprint;

use self::{
    chain::{ChainState, CommitmentTreeRoot},
    scanning::ScanRange,
};
use crate::{
    address::UnifiedAddress,
    decrypt::DecryptedOutput,
    keys::{
        UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey, UnifiedSpendingKey,
    },
    proto::service::TreeState,
    wallet::{Note, NoteId, ReceivedNote, Recipient, WalletTransparentOutput, WalletTx},
    ShieldedProtocol,
};
use zcash_primitives::{
    block::BlockHash,
    consensus::BlockHeight,
    memo::{Memo, MemoBytes},
    transaction::{
        components::{
            amount::{BalanceError, NonNegativeAmount},
            OutPoint,
        },
        Transaction, TxId,
    },
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::TransparentAddressMetadata, std::ops::Range,
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;

#[cfg(any(test, feature = "test-dependencies"))]
use {zcash_keys::address::Address, zcash_primitives::consensus::NetworkUpgrade};

pub mod chain;
pub mod error;
pub mod scanning;
pub mod wallet;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

/// The height of subtree roots in the Sapling note commitment tree.
///
/// This conforms to the structure of subtree data returned by
/// `lightwalletd` when using the `GetSubtreeRoots` GRPC call.
pub const SAPLING_SHARD_HEIGHT: u8 = sapling::NOTE_COMMITMENT_TREE_DEPTH / 2;

/// The height of subtree roots in the Orchard note commitment tree.
///
/// This conforms to the structure of subtree data returned by
/// `lightwalletd` when using the `GetSubtreeRoots` GRPC call.
#[cfg(feature = "orchard")]
pub const ORCHARD_SHARD_HEIGHT: u8 = { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 } / 2;

/// The number of ephemeral addresses that can be safely reserved without observing any
/// of them to be mined. This is the same as the gap limit in Bitcoin.
pub const GAP_LIMIT: u32 = 20;

/// An enumeration of constraints that can be applied when querying for nullifiers for notes
/// belonging to the wallet.
pub enum NullifierQuery {
    Unspent,
    All,
}

/// Balance information for a value within a single pool in an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    spendable_value: NonNegativeAmount,
    change_pending_confirmation: NonNegativeAmount,
    value_pending_spendability: NonNegativeAmount,
}

impl Balance {
    /// The [`Balance`] value having zero values for all its fields.
    pub const ZERO: Self = Self {
        spendable_value: NonNegativeAmount::ZERO,
        change_pending_confirmation: NonNegativeAmount::ZERO,
        value_pending_spendability: NonNegativeAmount::ZERO,
    };

    fn check_total_adding(
        &self,
        value: NonNegativeAmount,
    ) -> Result<NonNegativeAmount, BalanceError> {
        (self.spendable_value
            + self.change_pending_confirmation
            + self.value_pending_spendability
            + value)
            .ok_or(BalanceError::Overflow)
    }

    /// Returns the value in the account that may currently be spent; it is possible to compute
    /// witnesses for all the notes that comprise this value, and all of this value is confirmed to
    /// the required confirmation depth.
    pub fn spendable_value(&self) -> NonNegativeAmount {
        self.spendable_value
    }

    /// Adds the specified value to the spendable total, checking for overflow.
    pub fn add_spendable_value(&mut self, value: NonNegativeAmount) -> Result<(), BalanceError> {
        self.check_total_adding(value)?;
        self.spendable_value = (self.spendable_value + value).unwrap();
        Ok(())
    }

    /// Returns the value in the account of shielded change notes that do not yet have sufficient
    /// confirmations to be spendable.
    pub fn change_pending_confirmation(&self) -> NonNegativeAmount {
        self.change_pending_confirmation
    }

    /// Adds the specified value to the pending change total, checking for overflow.
    pub fn add_pending_change_value(
        &mut self,
        value: NonNegativeAmount,
    ) -> Result<(), BalanceError> {
        self.check_total_adding(value)?;
        self.change_pending_confirmation = (self.change_pending_confirmation + value).unwrap();
        Ok(())
    }

    /// Returns the value in the account of all remaining received notes that either do not have
    /// sufficient confirmations to be spendable, or for which witnesses cannot yet be constructed
    /// without additional scanning.
    pub fn value_pending_spendability(&self) -> NonNegativeAmount {
        self.value_pending_spendability
    }

    /// Adds the specified value to the pending spendable total, checking for overflow.
    pub fn add_pending_spendable_value(
        &mut self,
        value: NonNegativeAmount,
    ) -> Result<(), BalanceError> {
        self.check_total_adding(value)?;
        self.value_pending_spendability = (self.value_pending_spendability + value).unwrap();
        Ok(())
    }

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
    sapling_balance: Balance,

    /// The value of unspent Orchard outputs belonging to the account.
    orchard_balance: Balance,

    /// The value of all unspent transparent outputs belonging to the account, irrespective of
    /// confirmation depth.
    ///
    /// Unshielded balances are not subject to confirmation-depth constraints, because the only
    /// possible operation on a transparent balance is to shield it, it is possible to create a
    /// zero-conf transaction to perform that shielding, and the resulting shielded notes will be
    /// subject to normal confirmation rules.
    unshielded: NonNegativeAmount,
}

impl AccountBalance {
    /// The [`Balance`] value having zero values for all its fields.
    pub const ZERO: Self = Self {
        sapling_balance: Balance::ZERO,
        orchard_balance: Balance::ZERO,
        unshielded: NonNegativeAmount::ZERO,
    };

    fn check_total(&self) -> Result<NonNegativeAmount, BalanceError> {
        (self.sapling_balance.total() + self.orchard_balance.total() + self.unshielded)
            .ok_or(BalanceError::Overflow)
    }

    /// Returns the [`Balance`] of Sapling funds in the account.
    pub fn sapling_balance(&self) -> &Balance {
        &self.sapling_balance
    }

    /// Provides a `mutable reference to the [`Balance`] of Sapling funds in the account
    /// to the specified callback, checking invariants after the callback's action has been
    /// evaluated.
    pub fn with_sapling_balance_mut<A, E: From<BalanceError>>(
        &mut self,
        f: impl FnOnce(&mut Balance) -> Result<A, E>,
    ) -> Result<A, E> {
        let result = f(&mut self.sapling_balance)?;
        self.check_total()?;
        Ok(result)
    }

    /// Returns the [`Balance`] of Orchard funds in the account.
    pub fn orchard_balance(&self) -> &Balance {
        &self.orchard_balance
    }

    /// Provides a `mutable reference to the [`Balance`] of Orchard funds in the account
    /// to the specified callback, checking invariants after the callback's action has been
    /// evaluated.
    pub fn with_orchard_balance_mut<A, E: From<BalanceError>>(
        &mut self,
        f: impl FnOnce(&mut Balance) -> Result<A, E>,
    ) -> Result<A, E> {
        let result = f(&mut self.orchard_balance)?;
        self.check_total()?;
        Ok(result)
    }

    /// Returns the total value of unspent transparent transaction outputs belonging to the wallet.
    pub fn unshielded(&self) -> NonNegativeAmount {
        self.unshielded
    }

    /// Adds the specified value to the unshielded total, checking for overflow of
    /// the total account balance.
    pub fn add_unshielded_value(&mut self, value: NonNegativeAmount) -> Result<(), BalanceError> {
        self.unshielded = (self.unshielded + value).ok_or(BalanceError::Overflow)?;
        self.check_total()?;
        Ok(())
    }

    /// Returns the total value of funds belonging to the account.
    pub fn total(&self) -> NonNegativeAmount {
        (self.sapling_balance.total() + self.orchard_balance.total() + self.unshielded)
            .expect("Account balance cannot overflow MAX_MONEY")
    }

    /// Returns the total value of shielded (Sapling and Orchard) funds that may immediately be
    /// spent.
    pub fn spendable_value(&self) -> NonNegativeAmount {
        (self.sapling_balance.spendable_value + self.orchard_balance.spendable_value)
            .expect("Account balance cannot overflow MAX_MONEY")
    }

    /// Returns the total value of change and/or shielding transaction outputs that are awaiting
    /// sufficient confirmations for spendability.
    pub fn change_pending_confirmation(&self) -> NonNegativeAmount {
        (self.sapling_balance.change_pending_confirmation
            + self.orchard_balance.change_pending_confirmation)
            .expect("Account balance cannot overflow MAX_MONEY")
    }

    /// Returns the value of shielded funds that are not yet spendable because additional scanning
    /// is required before it will be possible to derive witnesses for the associated notes.
    pub fn value_pending_spendability(&self) -> NonNegativeAmount {
        (self.sapling_balance.value_pending_spendability
            + self.orchard_balance.value_pending_spendability)
            .expect("Account balance cannot overflow MAX_MONEY")
    }
}

/// An enumeration used to control what information is tracked by the wallet for
/// notes received by a given account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccountPurpose {
    /// For spending accounts, the wallet will track information needed to spend
    /// received notes.
    Spending,
    /// For view-only accounts, the wallet will not track spend information.
    ViewOnly,
}

/// The kinds of accounts supported by `zcash_client_backend`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccountSource {
    /// An account derived from a known seed.
    Derived {
        seed_fingerprint: SeedFingerprint,
        account_index: zip32::AccountId,
    },

    /// An account imported from a viewing key.
    Imported { purpose: AccountPurpose },
}

/// A set of capabilities that a client account must provide.
pub trait Account {
    type AccountId: Copy;

    /// Returns the unique identifier for the account.
    fn id(&self) -> Self::AccountId;

    /// Returns whether this account is derived or imported, and the derivation parameters
    /// if applicable.
    fn source(&self) -> AccountSource;

    /// Returns whether the account is a spending account or a view-only account.
    fn purpose(&self) -> AccountPurpose {
        match self.source() {
            AccountSource::Derived { .. } => AccountPurpose::Spending,
            AccountSource::Imported { purpose } => purpose,
        }
    }

    /// Returns the UFVK that the wallet backend has stored for the account, if any.
    ///
    /// Accounts for which this returns `None` cannot be used in wallet contexts, because
    /// they are unable to maintain an accurate balance.
    fn ufvk(&self) -> Option<&UnifiedFullViewingKey>;

    /// Returns the UIVK that the wallet backend has stored for the account.
    ///
    /// All accounts are required to have at least an incoming viewing key. This gives no
    /// indication about whether an account can be used in a wallet context; for that, use
    /// [`Account::ufvk`].
    fn uivk(&self) -> UnifiedIncomingViewingKey;
}

#[cfg(any(test, feature = "test-dependencies"))]
impl<A: Copy> Account for (A, UnifiedFullViewingKey) {
    type AccountId = A;

    fn id(&self) -> A {
        self.0
    }

    fn source(&self) -> AccountSource {
        AccountSource::Imported {
            purpose: AccountPurpose::ViewOnly,
        }
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        Some(&self.1)
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.1.to_unified_incoming_viewing_key()
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
impl<A: Copy> Account for (A, UnifiedIncomingViewingKey) {
    type AccountId = A;

    fn id(&self) -> A {
        self.0
    }

    fn source(&self) -> AccountSource {
        AccountSource::Imported {
            purpose: AccountPurpose::ViewOnly,
        }
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        None
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.1.clone()
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

/// A type representing the progress the wallet has made toward detecting all of the funds
/// belonging to the wallet.
///
/// The window over which progress is computed spans from the wallet's birthday to the current
/// chain tip. It is divided into two regions, the "Scan Window" which covers the region from the
/// wallet recovery height to the current chain tip, and the "Recovery Window" which covers the
/// range from the wallet birthday to the wallet recovery height. If no wallet recovery height is
/// available, the scan window will cover the entire range from the wallet birthday to the chain
/// tip.
///
/// Progress for both scanning and recovery is represented in terms of the ratio between notes
/// scanned and the total number of notes added to the chain in the relevant window. This ratio
/// should only be used to compute progress percentages for display, and the numerator and
/// denominator should not be treated as authoritative note counts. In the case that there are no
/// notes in a given block range, the denominator of these values will be zero, so callers should always
/// use checked division when converting the resulting values to percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    scan: Ratio<u64>,
    recovery: Option<Ratio<u64>>,
}

impl Progress {
    /// Constructs a new progress value from its constituent parts.
    pub fn new(scan: Ratio<u64>, recovery: Option<Ratio<u64>>) -> Self {
        Self { scan, recovery }
    }

    /// Returns the progress the wallet has made in scanning blocks for shielded notes belonging to
    /// the wallet between the wallet recovery height (or the wallet birthday if no recovery height
    /// is set) and the chain tip.
    pub fn scan(&self) -> Ratio<u64> {
        self.scan
    }

    /// Returns the progress the wallet has made in scanning blocks for shielded notes belonging to
    /// the wallet between the wallet birthday and the block height at which recovery from seed was
    /// initiated.
    ///
    /// Returns `None` if no recovery height is set for the wallet.
    pub fn recovery(&self) -> Option<Ratio<u64>> {
        self.recovery
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
pub struct WalletSummary<AccountId: Eq + Hash> {
    account_balances: HashMap<AccountId, AccountBalance>,
    chain_tip_height: BlockHeight,
    fully_scanned_height: BlockHeight,
    progress: Progress,
    next_sapling_subtree_index: u64,
    #[cfg(feature = "orchard")]
    next_orchard_subtree_index: u64,
}

impl<AccountId: Eq + Hash> WalletSummary<AccountId> {
    /// Constructs a new [`WalletSummary`] from its constituent parts.
    pub fn new(
        account_balances: HashMap<AccountId, AccountBalance>,
        chain_tip_height: BlockHeight,
        fully_scanned_height: BlockHeight,
        progress: Progress,
        next_sapling_subtree_index: u64,
        #[cfg(feature = "orchard")] next_orchard_subtree_index: u64,
    ) -> Self {
        Self {
            account_balances,
            chain_tip_height,
            fully_scanned_height,
            progress,
            next_sapling_subtree_index,
            #[cfg(feature = "orchard")]
            next_orchard_subtree_index,
        }
    }

    /// Returns the balances of accounts in the wallet, keyed by account ID.
    pub fn account_balances(&self) -> &HashMap<AccountId, AccountBalance> {
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

    /// Returns the progress of scanning the chain to bring the wallet up to date.
    ///
    /// This progress metric is intended as an indicator of how close the wallet is to
    /// general usability, including the ability to spend existing funds that were
    /// previously spendable.
    ///
    /// The window over which progress is computed spans from the wallet's birthday to the current
    /// chain tip. It is divided into two segments: a "recovery" segment, between the wallet
    /// birthday and the recovery height (currently the height at which recovery from seed was
    /// initiated, but how this boundary is computed may change in the future), and a "scan"
    /// segment, between the recovery height and the current chain tip.
    ///
    /// When converting the ratios returned here to percentages, checked division must be used in
    /// order to avoid divide-by-zero errors. A zero denominator in a returned ratio indicates that
    /// there are no shielded notes to be scanned in the associated block range.
    pub fn progress(&self) -> Progress {
        self.progress
    }

    /// Returns the Sapling subtree index that should start the next range of subtree
    /// roots passed to [`WalletCommitmentTrees::put_sapling_subtree_roots`].
    pub fn next_sapling_subtree_index(&self) -> u64 {
        self.next_sapling_subtree_index
    }

    /// Returns the Orchard subtree index that should start the next range of subtree
    /// roots passed to [`WalletCommitmentTrees::put_orchard_subtree_roots`].
    #[cfg(feature = "orchard")]
    pub fn next_orchard_subtree_index(&self) -> u64 {
        self.next_orchard_subtree_index
    }

    /// Returns whether or not wallet scanning is complete.
    pub fn is_synced(&self) -> bool {
        self.chain_tip_height == self.fully_scanned_height
    }
}

/// A predicate that can be used to choose whether or not a particular note is retained in note
/// selection.
pub trait NoteRetention<NoteRef> {
    /// Returns whether the specified Sapling note should be retained.
    fn should_retain_sapling(&self, note: &ReceivedNote<NoteRef, sapling::Note>) -> bool;
    /// Returns whether the specified Orchard note should be retained.
    #[cfg(feature = "orchard")]
    fn should_retain_orchard(&self, note: &ReceivedNote<NoteRef, orchard::note::Note>) -> bool;
}

pub(crate) struct SimpleNoteRetention {
    pub(crate) sapling: bool,
    #[cfg(feature = "orchard")]
    pub(crate) orchard: bool,
}

impl<NoteRef> NoteRetention<NoteRef> for SimpleNoteRetention {
    fn should_retain_sapling(&self, _: &ReceivedNote<NoteRef, sapling::Note>) -> bool {
        self.sapling
    }

    #[cfg(feature = "orchard")]
    fn should_retain_orchard(&self, _: &ReceivedNote<NoteRef, orchard::note::Note>) -> bool {
        self.orchard
    }
}

/// Spendable shielded outputs controlled by the wallet.
pub struct SpendableNotes<NoteRef> {
    sapling: Vec<ReceivedNote<NoteRef, sapling::Note>>,
    #[cfg(feature = "orchard")]
    orchard: Vec<ReceivedNote<NoteRef, orchard::note::Note>>,
}

/// A request for transaction data enhancement, spentness check, or discovery
/// of spends from a given transparent address within a specific block range.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionDataRequest {
    /// Information about the chain's view of a transaction is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by determining the status of the specified transaction with respect to the main
    /// chain; if using `lightwalletd` for access to chain data, this may be obtained by
    /// interpreting the results of the [`GetTransaction`] RPC method. It should then call
    /// [`WalletWrite::set_transaction_status`] to provide the resulting transaction status
    /// information to the wallet backend.
    ///
    /// [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
    GetStatus(TxId),
    /// Transaction enhancement (download of complete raw transaction data) is requested.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by providing complete data for the specified transaction to
    /// [`wallet::decrypt_and_store_transaction`]; if using `lightwalletd` for access to chain
    /// state, this may be obtained via the [`GetTransaction`] RPC method. If no data is available
    /// for the specified transaction, this should be reported to the backend using
    /// [`WalletWrite::set_transaction_status`]. A [`TransactionDataRequest::Enhancement`] request
    /// subsumes any previously existing [`TransactionDataRequest::GetStatus`] request.
    ///
    /// [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
    Enhancement(TxId),
    /// Information about transactions that receive or spend funds belonging to the specified
    /// transparent address is requested.
    ///
    /// Fully transparent transactions, and transactions that do not contain either shielded inputs
    /// or shielded outputs belonging to the wallet, may not be discovered by the process of chain
    /// scanning; as a consequence, the wallet must actively query to find transactions that spend
    /// such funds. Ideally we'd be able to query by [`OutPoint`] but this is not currently
    /// functionality that is supported by the light wallet server.
    ///
    /// The caller evaluating this request on behalf of the wallet backend should respond to this
    /// request by detecting transactions involving the specified address within the provided block
    /// range; if using `lightwalletd` for access to chain data, this may be performed using the
    /// [`GetTaddressTxids`] RPC method. It should then call [`wallet::decrypt_and_store_transaction`]
    /// for each transaction so detected.
    ///
    /// [`GetTaddressTxids`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_taddress_txids
    #[cfg(feature = "transparent-inputs")]
    SpendsFromAddress {
        address: TransparentAddress,
        block_range_start: BlockHeight,
        block_range_end: Option<BlockHeight>,
    },
}

/// Metadata about the status of a transaction obtained by inspecting the chain state.
#[derive(Clone, Copy, Debug)]
pub enum TransactionStatus {
    /// The requested transaction ID was not recognized by the node.
    TxidNotRecognized,
    /// The requested transaction ID corresponds to a transaction that is recognized by the node,
    /// but is in the mempool or is otherwise not mined in the main chain (but may have been mined
    /// on a fork that was reorged away).
    NotInMainChain,
    /// The requested transaction ID corresponds to a transaction that has been included in the
    /// block at the provided height.
    Mined(BlockHeight),
}

impl<NoteRef> SpendableNotes<NoteRef> {
    /// Construct a new empty [`SpendableNotes`].
    pub fn empty() -> Self {
        Self::new(
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
        )
    }

    /// Construct a new [`SpendableNotes`] from its constituent parts.
    pub fn new(
        sapling: Vec<ReceivedNote<NoteRef, sapling::Note>>,
        #[cfg(feature = "orchard")] orchard: Vec<ReceivedNote<NoteRef, orchard::note::Note>>,
    ) -> Self {
        Self {
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
        }
    }

    /// Returns the set of spendable Sapling notes.
    pub fn sapling(&self) -> &[ReceivedNote<NoteRef, sapling::Note>] {
        self.sapling.as_ref()
    }

    /// Consumes this value and returns the Sapling notes contained within it.
    pub fn take_sapling(self) -> Vec<ReceivedNote<NoteRef, sapling::Note>> {
        self.sapling
    }

    /// Returns the set of spendable Orchard notes.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> &[ReceivedNote<NoteRef, orchard::note::Note>] {
        self.orchard.as_ref()
    }

    /// Consumes this value and returns the Orchard notes contained within it.
    #[cfg(feature = "orchard")]
    pub fn take_orchard(self) -> Vec<ReceivedNote<NoteRef, orchard::note::Note>> {
        self.orchard
    }

    /// Computes the total value of Sapling notes.
    pub fn sapling_value(&self) -> Result<NonNegativeAmount, BalanceError> {
        self.sapling
            .iter()
            .try_fold(NonNegativeAmount::ZERO, |acc, n| {
                (acc + n.note_value()?).ok_or(BalanceError::Overflow)
            })
    }

    /// Computes the total value of Sapling notes.
    #[cfg(feature = "orchard")]
    pub fn orchard_value(&self) -> Result<NonNegativeAmount, BalanceError> {
        self.orchard
            .iter()
            .try_fold(NonNegativeAmount::ZERO, |acc, n| {
                (acc + n.note_value()?).ok_or(BalanceError::Overflow)
            })
    }

    /// Computes the total value of spendable inputs
    pub fn total_value(&self) -> Result<NonNegativeAmount, BalanceError> {
        #[cfg(not(feature = "orchard"))]
        return self.sapling_value();

        #[cfg(feature = "orchard")]
        return (self.sapling_value()? + self.orchard_value()?).ok_or(BalanceError::Overflow);
    }

    /// Consumes this [`SpendableNotes`] value and produces a vector of
    /// [`ReceivedNote<NoteRef, Note>`] values.
    pub fn into_vec(
        self,
        retention: &impl NoteRetention<NoteRef>,
    ) -> Vec<ReceivedNote<NoteRef, Note>> {
        let iter = self.sapling.into_iter().filter_map(|n| {
            retention
                .should_retain_sapling(&n)
                .then(|| n.map_note(Note::Sapling))
        });

        #[cfg(feature = "orchard")]
        let iter = iter.chain(self.orchard.into_iter().filter_map(|n| {
            retention
                .should_retain_orchard(&n)
                .then(|| n.map_note(Note::Orchard))
        }));

        iter.collect()
    }
}

/// Metadata about the structure of the wallet for a particular account.
///
/// At present this just contains counts of unspent outputs in each pool, but it may be extended in
/// the future to contain note values or other more detailed information about wallet structure.
///
/// Values of this type are intended to be used in selection of change output values. A value of
/// this type may represent filtered data, and may therefore not count all of the unspent notes in
/// the wallet.
pub struct WalletMeta {
    sapling_note_count: usize,
    #[cfg(feature = "orchard")]
    orchard_note_count: usize,
}

impl WalletMeta {
    /// Constructs a new [`WalletMeta`] value from its constituent parts.
    pub fn new(
        sapling_note_count: usize,
        #[cfg(feature = "orchard")] orchard_note_count: usize,
    ) -> Self {
        Self {
            sapling_note_count,
            #[cfg(feature = "orchard")]
            orchard_note_count,
        }
    }

    /// Returns the number of unspent notes in the wallet for the given shielded protocol.
    pub fn note_count(&self, protocol: ShieldedProtocol) -> usize {
        match protocol {
            ShieldedProtocol::Sapling => self.sapling_note_count,
            #[cfg(feature = "orchard")]
            ShieldedProtocol::Orchard => self.orchard_note_count,
            #[cfg(not(feature = "orchard"))]
            ShieldedProtocol::Orchard => 0,
        }
    }

    /// Returns the number of unspent Sapling notes belonging to the account for which this was
    /// generated.
    pub fn sapling_note_count(&self) -> usize {
        self.sapling_note_count
    }

    /// Returns the number of unspent Orchard notes belonging to the account for which this was
    /// generated.
    #[cfg(feature = "orchard")]
    pub fn orchard_note_count(&self) -> usize {
        self.orchard_note_count
    }

    /// Returns the total number of unspent shielded notes belonging to the account for which this
    /// was generated.
    pub fn total_note_count(&self) -> usize {
        #[cfg(feature = "orchard")]
        let orchard_note_count = self.orchard_note_count;
        #[cfg(not(feature = "orchard"))]
        let orchard_note_count = 0;

        self.sapling_note_count + orchard_note_count
    }
}

/// A trait representing the capability to query a data store for unspent transaction outputs
/// belonging to a wallet.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait InputSource {
    /// The type of errors produced by a wallet backend.
    type Error: Debug;

    /// Backend-specific account identifier.
    ///
    /// An account identifier corresponds to at most a single unified spending key's worth of spend
    /// authority, such that both received notes and change spendable by that spending authority
    /// will be interpreted as belonging to that account. This might be a database identifier type
    /// or a UUID.
    type AccountId: Copy + Debug + Eq + Hash;

    /// Backend-specific note identifier.
    ///
    /// For example, this might be a database identifier type or a UUID.
    type NoteRef: Copy + Debug + Eq + Ord;

    /// Fetches a spendable note by indexing into a transaction's shielded outputs for the
    /// specified shielded protocol.
    ///
    /// Returns `Ok(None)` if the note is not known to belong to the wallet or if the note
    /// is not spendable.
    fn get_spendable_note(
        &self,
        txid: &TxId,
        protocol: ShieldedProtocol,
        index: u32,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error>;

    /// Returns a list of spendable notes sufficient to cover the specified target value, if
    /// possible. Only spendable notes corresponding to the specified shielded protocol will
    /// be included.
    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: NonNegativeAmount,
        sources: &[ShieldedProtocol],
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<SpendableNotes<Self::NoteRef>, Self::Error>;

    /// Returns metadata describing the structure of the wallet for the specified account.
    ///
    /// The returned metadata value must exclude spent notes and unspent notes having value less
    /// than the specified minimum value or identified in the given exclude list.
    fn get_wallet_metadata(
        &self,
        account: Self::AccountId,
        min_value: NonNegativeAmount,
        exclude: &[Self::NoteRef],
    ) -> Result<WalletMeta, Self::Error>;

    /// Fetches the transparent output corresponding to the provided `outpoint`.
    ///
    /// Returns `Ok(None)` if the UTXO is not known to belong to the wallet or is not
    /// spendable as of the chain tip height.
    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_output(
        &self,
        _outpoint: &OutPoint,
    ) -> Result<Option<WalletTransparentOutput>, Self::Error> {
        Ok(None)
    }

    /// Returns the list of spendable transparent outputs received by this wallet at `address`
    /// such that, at height `target_height`:
    /// * the transaction that produced the output had or will have at least `min_confirmations`
    ///   confirmations; and
    /// * the output is unspent as of the current chain tip.
    ///
    /// An output that is potentially spent by an unmined transaction in the mempool is excluded
    /// iff the spending transaction will not be expired at `target_height`.
    #[cfg(feature = "transparent-inputs")]
    fn get_spendable_transparent_outputs(
        &self,
        _address: &TransparentAddress,
        _target_height: BlockHeight,
        _min_confirmations: u32,
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
        Ok(vec![])
    }
}

/// Read-only operations required for light wallet functions.
///
/// This trait defines the read-only portion of the storage interface atop which
/// higher-level wallet operations are implemented. It serves to allow wallet functions to
/// be abstracted away from any particular data storage substrate.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait WalletRead {
    /// The type of errors that may be generated when querying a wallet data store.
    type Error: Debug;

    /// The type of the account identifier.
    ///
    /// An account identifier corresponds to at most a single unified spending key's worth of spend
    /// authority, such that both received notes and change spendable by that spending authority
    /// will be interpreted as belonging to that account.
    type AccountId: Copy + Debug + Eq + Hash;

    /// The concrete account type used by this wallet backend.
    type Account: Account<AccountId = Self::AccountId>;

    /// Returns a vector with the IDs of all accounts known to this wallet.
    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error>;

    /// Returns the account corresponding to the given ID, if any.
    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error>;

    /// Returns the account corresponding to a given [`SeedFingerprint`] and
    /// [`zip32::AccountId`], if any.
    fn get_derived_account(
        &self,
        seed: &SeedFingerprint,
        account_id: zip32::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error>;

    /// Verifies that the given seed corresponds to the viewing key for the specified account.
    ///
    /// Returns:
    /// - `Ok(true)` if the viewing key for the specified account can be derived from the
    ///   provided seed.
    /// - `Ok(false)` if the derived viewing key does not match, or the specified account is not
    ///   present in the database.
    /// - `Err(_)` if a Unified Spending Key cannot be derived from the seed for the
    ///   specified account or the account has no known ZIP-32 derivation.
    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error>;

    /// Checks whether the given seed is relevant to any of the derived accounts (where
    /// [`Account::source`] is [`AccountSource::Derived`]) in the wallet.
    ///
    /// This API does not check whether the seed is relevant to any imported account,
    /// because that would require brute-forcing the ZIP 32 account index space.
    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error>;

    /// Returns the account corresponding to a given [`UnifiedFullViewingKey`], if any.
    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error>;

    /// Returns the most recently generated unified address for the specified account, if the
    /// account identifier specified refers to a valid account for this wallet.
    ///
    /// This will return `Ok(None)` if the account identifier does not correspond to a known
    /// account.
    fn get_current_address(
        &self,
        account: Self::AccountId,
    ) -> Result<Option<UnifiedAddress>, Self::Error>;

    /// Returns the birthday height for the given account, or an error if the account is not known
    /// to the wallet.
    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error>;

    /// Returns the birthday height for the wallet.
    ///
    /// This returns the earliest birthday height among accounts maintained by this wallet,
    /// or `Ok(None)` if the wallet has no initialized accounts.
    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the wallet balances and sync status for an account given the specified minimum
    /// number of confirmations, or `Ok(None)` if the wallet has no balance data available.
    fn get_wallet_summary(
        &self,
        min_confirmations: u32,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error>;

    /// Returns the height of the chain as known to the wallet as of the most recent call to
    /// [`WalletWrite::update_chain_tip`].
    ///
    /// This will return `Ok(None)` if the height of the current consensus chain tip is unknown.
    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the block hash for the block at the given height, if the
    /// associated block data is available. Returns `Ok(None)` if the hash
    /// is not found in the database.
    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error>;

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

    /// Returns the block height and hash for the block at the maximum scanned block height.
    ///
    /// This will return `Ok(None)` if no blocks have been scanned.
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error>;

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
    /// The returned range(s) may include block heights beyond the current chain tip. Ranges are
    /// returned in order of descending priority, and higher-priority ranges should always be
    /// scanned before lower-priority ranges; in particular, ranges with [`ScanPriority::Verify`]
    /// priority must always be scanned first in order to avoid blockchain continuity errors in the
    /// case of a reorg.
    ///
    /// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
    /// [`ScanPriority::Verify`]: crate::data_api::scanning::ScanPriority
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

    /// Returns the block height in which the specified transaction was mined, or `Ok(None)` if the
    /// transaction is not in the main chain.
    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns all unified full viewing keys known to this wallet.
    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error>;

    /// Returns the memo for a note.
    ///
    /// Returns `Ok(None)` if the note is known to the wallet but memo data has not yet been
    /// populated for that note, or if the note identifier does not correspond to a note
    /// that is known to the wallet.
    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error>;

    /// Returns a transaction.
    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error>;

    /// Returns the nullifiers for Sapling notes that the wallet is tracking, along with their
    /// associated account IDs, that are either unspent or have not yet been confirmed as spent (in
    /// that a spending transaction known to the wallet has not yet been included in a block).
    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error>;

    /// Returns the nullifiers for Orchard notes that the wallet is tracking, along with their
    /// associated account IDs, that are either unspent or have not yet been confirmed as spent (in
    /// that a spending transaction known to the wallet has not yet been included in a block).
    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error>;

    /// Returns the set of non-ephemeral transparent receivers associated with the given
    /// account controlled by this wallet.
    ///
    /// The set contains all non-ephemeral transparent receivers that are known to have
    /// been derived under this account. Wallets should scan the chain for UTXOs sent to
    /// these receivers.
    ///
    /// Use [`Self::get_known_ephemeral_addresses`] to obtain the ephemeral transparent
    /// receivers.
    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        _account: Self::AccountId,
    ) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, Self::Error> {
        Ok(HashMap::new())
    }

    /// Returns a mapping from each transparent receiver associated with the specified account
    /// to its not-yet-shielded UTXO balance as of the end of the block at the provided
    /// `max_height`, when that balance is non-zero.
    ///
    /// Balances of ephemeral transparent addresses will not be included.
    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        _account: Self::AccountId,
        _max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, NonNegativeAmount>, Self::Error> {
        Ok(HashMap::new())
    }

    /// Returns the metadata associated with a given transparent receiver in an account
    /// controlled by this wallet, if available.
    ///
    /// This is equivalent to (but may be implemented more efficiently than):
    /// ```compile_fail
    /// Ok(
    ///     if let Some(result) = self.get_transparent_receivers(account)?.get(address) {
    ///         result.clone()
    ///     } else {
    ///         self.get_known_ephemeral_addresses(account, None)?
    ///             .into_iter()
    ///             .find(|(known_addr, _)| known_addr == address)
    ///             .map(|(_, metadata)| metadata)
    ///     },
    /// )
    /// ```
    ///
    /// Returns `Ok(None)` if the address is not recognized, or we do not have metadata for it.
    /// Returns `Ok(Some(metadata))` if we have the metadata.
    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_address_metadata(
        &self,
        account: Self::AccountId,
        address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        // This should be overridden.
        Ok(
            if let Some(result) = self.get_transparent_receivers(account)?.get(address) {
                result.clone()
            } else {
                self.get_known_ephemeral_addresses(account, None)?
                    .into_iter()
                    .find(|(known_addr, _)| known_addr == address)
                    .map(|(_, metadata)| metadata)
            },
        )
    }

    /// Returns a vector of ephemeral transparent addresses associated with the given
    /// account controlled by this wallet, along with their metadata. The result includes
    /// reserved addresses, and addresses for [`GAP_LIMIT`] additional indices (capped to
    /// the maximum index).
    ///
    /// If `index_range` is some `Range`, it limits the result to addresses with indices
    /// in that range.
    ///
    /// Wallets should scan the chain for UTXOs sent to these ephemeral transparent
    /// receivers, but do not need to do so regularly. Under expected usage, outputs
    /// would only be detected with these receivers in the following situations:
    ///
    /// - This wallet created a payment to a ZIP 320 (TEX) address, but the second
    ///   transaction (that spent the output sent to the ephemeral address) did not get
    ///   mined before it expired.
    ///   - In this case the output will already be known to the wallet (because it
    ///     stores the transactions that it creates).
    ///
    /// - Another wallet app using the same seed phrase created a payment to a ZIP 320
    ///   address, and this wallet queried for the ephemeral UTXOs after the first
    ///   transaction was mined but before the second transaction was mined.
    ///   - In this case, the output should not be considered unspent until the expiry
    ///     height of the transaction it was received in has passed. Wallets creating
    ///     payments to TEX addresses generally set the same expiry height for the first
    ///     and second transactions, meaning that this wallet does not need to observe
    ///     the second transaction to determine when it would have expired.
    ///
    /// - A TEX address recipient decided to return funds that the wallet had sent to
    ///   them.
    ///
    /// In all cases, the wallet should re-shield the unspent outputs, in a separate
    /// transaction per ephemeral address, before re-spending the funds.
    #[cfg(feature = "transparent-inputs")]
    fn get_known_ephemeral_addresses(
        &self,
        _account: Self::AccountId,
        _index_range: Option<Range<u32>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        Ok(vec![])
    }

    /// If a given ephemeral address might have been reserved, i.e. would be included in
    /// the map returned by `get_known_ephemeral_addresses(account_id, false)` for any
    /// of the wallet's accounts, then return `Ok(Some(account_id))`. Otherwise return
    /// `Ok(None)`.
    ///
    /// This is equivalent to (but may be implemented more efficiently than):
    /// ```compile_fail
    /// for account_id in self.get_account_ids()? {
    ///     if self
    ///         .get_known_ephemeral_addresses(account_id, None)?
    ///         .into_iter()
    ///         .any(|(known_addr, _)| &known_addr == address)
    ///     {
    ///         return Ok(Some(account_id));
    ///     }
    /// }
    /// Ok(None)
    /// ```
    #[cfg(feature = "transparent-inputs")]
    fn find_account_for_ephemeral_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<Self::AccountId>, Self::Error> {
        for account_id in self.get_account_ids()? {
            if self
                .get_known_ephemeral_addresses(account_id, None)?
                .into_iter()
                .any(|(known_addr, _)| &known_addr == address)
            {
                return Ok(Some(account_id));
            }
        }
        Ok(None)
    }

    /// Returns a vector of [`TransactionDataRequest`] values that describe information needed by
    /// the wallet to complete its view of transaction history.
    ///
    /// Requests for the same transaction data may be returned repeatedly by successive data
    /// requests. The caller of this method should consider the latest set of requests returned
    /// by this method to be authoritative and to subsume that returned by previous calls.
    ///
    /// Callers should poll this method on a regular interval, not as part of ordinary chain
    /// scanning, which already produces requests for transaction data enhancement. Note that
    /// responding to a set of transaction data requests may result in the creation of new
    /// transaction data requests, such as when it is necessary to fill in purely-transparent
    /// transaction history by walking the chain backwards via transparent inputs.
    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error>;
}

/// Read-only operations required for testing light wallet functions.
///
/// These methods expose internal details or unstable interfaces, primarily to enable use
/// of the [`testing`] framework. They should not be used in production software.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait WalletTest: InputSource + WalletRead {
    /// Returns a vector of transaction summaries.
    ///
    /// Currently test-only, as production use could return a very large number of results; either
    /// pagination or a streaming design will be necessary to stabilize this feature for production
    /// use.
    fn get_tx_history(
        &self,
    ) -> Result<
        Vec<testing::TransactionSummary<<Self as WalletRead>::AccountId>>,
        <Self as WalletRead>::Error,
    >;

    /// Returns the note IDs for shielded notes sent by the wallet in a particular
    /// transaction.
    fn get_sent_note_ids(
        &self,
        _txid: &TxId,
        _protocol: ShieldedProtocol,
    ) -> Result<Vec<NoteId>, <Self as WalletRead>::Error>;

    /// Returns the outputs for a transaction sent by the wallet.
    #[allow(clippy::type_complexity)]
    fn get_sent_outputs(
        &self,
        txid: &TxId,
    ) -> Result<Vec<OutputOfSentTx>, <Self as WalletRead>::Error>;

    #[allow(clippy::type_complexity)]
    fn get_checkpoint_history(
        &self,
        protocol: &ShieldedProtocol,
    ) -> Result<
        Vec<(BlockHeight, Option<incrementalmerkletree::Position>)>,
        <Self as WalletRead>::Error,
    >;

    /// Fetches the transparent output corresponding to the provided `outpoint`.
    /// Allows selecting unspendable outputs for testing purposes.
    ///
    /// Returns `Ok(None)` if the UTXO is not known to belong to the wallet or is not
    /// spendable as of the chain tip height.
    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_output(
        &self,
        outpoint: &OutPoint,
        allow_unspendable: bool,
    ) -> Result<Option<WalletTransparentOutput>, <Self as InputSource>::Error>;

    /// Returns all the notes that have been received by the wallet.
    fn get_notes(
        &self,
        protocol: ShieldedProtocol,
    ) -> Result<Vec<ReceivedNote<Self::NoteRef, Note>>, <Self as InputSource>::Error>;
}

/// The output of a transaction sent by the wallet.
///
/// This type is opaque, and exists for use by tests defined in this crate.
#[cfg(any(test, feature = "test-dependencies"))]
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct OutputOfSentTx {
    value: NonNegativeAmount,
    external_recipient: Option<Address>,
    ephemeral_address: Option<(Address, u32)>,
}

#[cfg(any(test, feature = "test-dependencies"))]
impl OutputOfSentTx {
    /// Constructs an output from its test-relevant parts.
    ///
    /// If the output is to an ephemeral address, `ephemeral_address` should contain the
    /// address along with the `address_index` it was derived from under the BIP 32 path
    /// `m/44'/<coin_type>'/<account>'/2/<address_index>`.
    pub fn from_parts(
        value: NonNegativeAmount,
        external_recipient: Option<Address>,
        ephemeral_address: Option<(Address, u32)>,
    ) -> Self {
        Self {
            value,
            external_recipient,
            ephemeral_address,
        }
    }
}

/// The relevance of a seed to a given wallet.
///
/// This is the return type for [`WalletRead::seed_relevance_to_derived_accounts`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedRelevance<A: Copy> {
    /// The seed is relevant to at least one derived account within the wallet.
    Relevant { account_ids: NonEmpty<A> },
    /// The seed is not relevant to any of the derived accounts within the wallet.
    NotRelevant,
    /// The wallet contains no derived accounts.
    NoDerivedAccounts,
    /// The wallet contains no accounts.
    NoAccounts,
}

/// Metadata describing the sizes of the zcash note commitment trees as of a particular block.
#[derive(Debug, Clone, Copy)]
pub struct BlockMetadata {
    block_height: BlockHeight,
    block_hash: BlockHash,
    sapling_tree_size: Option<u32>,
    #[cfg(feature = "orchard")]
    orchard_tree_size: Option<u32>,
}

impl BlockMetadata {
    /// Constructs a new [`BlockMetadata`] value from its constituent parts.
    pub fn from_parts(
        block_height: BlockHeight,
        block_hash: BlockHash,
        sapling_tree_size: Option<u32>,
        #[cfg(feature = "orchard")] orchard_tree_size: Option<u32>,
    ) -> Self {
        Self {
            block_height,
            block_hash,
            sapling_tree_size,
            #[cfg(feature = "orchard")]
            orchard_tree_size,
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

    /// Returns the size of the Sapling note commitment tree for the final treestate of the block
    /// that this [`BlockMetadata`] describes, if available.
    pub fn sapling_tree_size(&self) -> Option<u32> {
        self.sapling_tree_size
    }

    /// Returns the size of the Orchard note commitment tree for the final treestate of the block
    /// that this [`BlockMetadata`] describes, if available.
    #[cfg(feature = "orchard")]
    pub fn orchard_tree_size(&self) -> Option<u32> {
        self.orchard_tree_size
    }
}

/// The protocol-specific note commitment and nullifier data extracted from the per-transaction
/// shielded bundles in [`CompactBlock`], used by the wallet for note commitment tree maintenance
/// and spend detection.
///
/// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
pub struct ScannedBundles<NoteCommitment, NF> {
    final_tree_size: u32,
    commitments: Vec<(NoteCommitment, Retention<BlockHeight>)>,
    nullifier_map: Vec<(TxId, u16, Vec<NF>)>,
}

impl<NoteCommitment, NF> ScannedBundles<NoteCommitment, NF> {
    pub(crate) fn new(
        final_tree_size: u32,
        commitments: Vec<(NoteCommitment, Retention<BlockHeight>)>,
        nullifier_map: Vec<(TxId, u16, Vec<NF>)>,
    ) -> Self {
        Self {
            final_tree_size,
            nullifier_map,
            commitments,
        }
    }

    /// Returns the size of the note commitment tree as of the end of the scanned block.
    pub fn final_tree_size(&self) -> u32 {
        self.final_tree_size
    }

    /// Returns the vector of nullifiers for each transaction in the block.
    ///
    /// The returned tuple is keyed by both transaction ID and the index of the transaction within
    /// the block, so that either the txid or the combination of the block hash available from
    /// [`ScannedBlock::block_hash`] and returned transaction index may be used to uniquely
    /// identify the transaction, depending upon the needs of the caller.
    pub fn nullifier_map(&self) -> &[(TxId, u16, Vec<NF>)] {
        &self.nullifier_map
    }

    /// Returns the ordered list of note commitments to be added to the note commitment
    /// tree.
    pub fn commitments(&self) -> &[(NoteCommitment, Retention<BlockHeight>)] {
        &self.commitments
    }
}

/// A struct used to return the vectors of note commitments for a [`ScannedBlock`]
/// as owned values.
pub struct ScannedBlockCommitments {
    /// The ordered vector of note commitments for Sapling outputs of the block.
    pub sapling: Vec<(sapling::Node, Retention<BlockHeight>)>,
    /// The ordered vector of note commitments for Orchard outputs of the block.
    /// Present only when the `orchard` feature is enabled.
    #[cfg(feature = "orchard")]
    pub orchard: Vec<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>,
}

/// The subset of information that is relevant to this wallet that has been
/// decrypted and extracted from a [`CompactBlock`].
///
/// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
pub struct ScannedBlock<A> {
    block_height: BlockHeight,
    block_hash: BlockHash,
    block_time: u32,
    transactions: Vec<WalletTx<A>>,
    sapling: ScannedBundles<sapling::Node, sapling::Nullifier>,
    #[cfg(feature = "orchard")]
    orchard: ScannedBundles<orchard::tree::MerkleHashOrchard, orchard::note::Nullifier>,
}

impl<A> ScannedBlock<A> {
    /// Constructs a new `ScannedBlock`
    pub(crate) fn from_parts(
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        transactions: Vec<WalletTx<A>>,
        sapling: ScannedBundles<sapling::Node, sapling::Nullifier>,
        #[cfg(feature = "orchard")] orchard: ScannedBundles<
            orchard::tree::MerkleHashOrchard,
            orchard::note::Nullifier,
        >,
    ) -> Self {
        Self {
            block_height,
            block_hash,
            block_time,
            transactions,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
        }
    }

    /// Returns the height of the block that was scanned.
    pub fn height(&self) -> BlockHeight {
        self.block_height
    }

    /// Returns the block hash of the block that was scanned.
    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Returns the block time of the block that was scanned, as a Unix timestamp in seconds.
    pub fn block_time(&self) -> u32 {
        self.block_time
    }

    /// Returns the list of transactions from this block that are relevant to the wallet.
    pub fn transactions(&self) -> &[WalletTx<A>] {
        &self.transactions
    }

    /// Returns the Sapling note commitment tree and nullifier data for the block.
    pub fn sapling(&self) -> &ScannedBundles<sapling::Node, sapling::Nullifier> {
        &self.sapling
    }

    /// Returns the Orchard note commitment tree and nullifier data for the block.
    #[cfg(feature = "orchard")]
    pub fn orchard(
        &self,
    ) -> &ScannedBundles<orchard::tree::MerkleHashOrchard, orchard::note::Nullifier> {
        &self.orchard
    }

    /// Consumes `self` and returns the lists of Sapling and Orchard note commitments associated
    /// with the scanned block as an owned value.
    pub fn into_commitments(self) -> ScannedBlockCommitments {
        ScannedBlockCommitments {
            sapling: self.sapling.commitments,
            #[cfg(feature = "orchard")]
            orchard: self.orchard.commitments,
        }
    }

    /// Returns the [`BlockMetadata`] corresponding to the scanned block.
    pub fn to_block_metadata(&self) -> BlockMetadata {
        BlockMetadata {
            block_height: self.block_height,
            block_hash: self.block_hash,
            sapling_tree_size: Some(self.sapling.final_tree_size),
            #[cfg(feature = "orchard")]
            orchard_tree_size: Some(self.orchard.final_tree_size),
        }
    }
}

/// A transaction that was detected during scanning of the blockchain,
/// including its decrypted Sapling and/or Orchard outputs.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are successfully decrypted.
pub struct DecryptedTransaction<'a, AccountId> {
    mined_height: Option<BlockHeight>,
    tx: &'a Transaction,
    sapling_outputs: Vec<DecryptedOutput<sapling::Note, AccountId>>,
    #[cfg(feature = "orchard")]
    orchard_outputs: Vec<DecryptedOutput<orchard::note::Note, AccountId>>,
}

impl<'a, AccountId> DecryptedTransaction<'a, AccountId> {
    /// Constructs a new [`DecryptedTransaction`] from its constituent parts.
    pub fn new(
        mined_height: Option<BlockHeight>,
        tx: &'a Transaction,
        sapling_outputs: Vec<DecryptedOutput<sapling::Note, AccountId>>,
        #[cfg(feature = "orchard")] orchard_outputs: Vec<
            DecryptedOutput<orchard::note::Note, AccountId>,
        >,
    ) -> Self {
        Self {
            mined_height,
            tx,
            sapling_outputs,
            #[cfg(feature = "orchard")]
            orchard_outputs,
        }
    }

    /// Returns the height at which the transaction was mined, if known.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }
    /// Returns the raw transaction data.
    pub fn tx(&self) -> &Transaction {
        self.tx
    }
    /// Returns the Sapling outputs that were decrypted from the transaction.
    pub fn sapling_outputs(&self) -> &[DecryptedOutput<sapling::Note, AccountId>] {
        &self.sapling_outputs
    }
    /// Returns the Orchard outputs that were decrypted from the transaction.
    #[cfg(feature = "orchard")]
    pub fn orchard_outputs(&self) -> &[DecryptedOutput<orchard::note::Note, AccountId>] {
        &self.orchard_outputs
    }
}

/// A transaction that was constructed and sent by the wallet.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are created and submitted
/// to the network.
pub struct SentTransaction<'a, AccountId> {
    tx: &'a Transaction,
    created: time::OffsetDateTime,
    target_height: BlockHeight,
    account: AccountId,
    outputs: &'a [SentTransactionOutput<AccountId>],
    fee_amount: NonNegativeAmount,
    #[cfg(feature = "transparent-inputs")]
    utxos_spent: &'a [OutPoint],
}

impl<'a, AccountId> SentTransaction<'a, AccountId> {
    /// Constructs a new [`SentTransaction`] from its constituent parts.
    ///
    /// ### Parameters
    /// - `tx`: the raw transaction data
    /// - `created`: the system time at which the transaction was created
    /// - `target_height`: the target height that was used in the construction of the transaction
    /// - `account`: the account that spent funds in creation of the transaction
    /// - `outputs`: the outputs created by the transaction, including those sent to external
    ///   recipients which may not otherwise be recoverable
    /// - `fee_amount`: the fee value paid by the transaction
    /// - `utxos_spent`: the UTXOs controlled by the wallet that were spent in this transaction
    pub fn new(
        tx: &'a Transaction,
        created: time::OffsetDateTime,
        target_height: BlockHeight,
        account: AccountId,
        outputs: &'a [SentTransactionOutput<AccountId>],
        fee_amount: NonNegativeAmount,
        #[cfg(feature = "transparent-inputs")] utxos_spent: &'a [OutPoint],
    ) -> Self {
        Self {
            tx,
            created,
            target_height,
            account,
            outputs,
            fee_amount,
            #[cfg(feature = "transparent-inputs")]
            utxos_spent,
        }
    }

    /// Returns the transaction that was sent.
    pub fn tx(&self) -> &Transaction {
        self.tx
    }
    /// Returns the timestamp of the transaction's creation.
    pub fn created(&self) -> time::OffsetDateTime {
        self.created
    }
    /// Returns the id for the account that created the outputs.
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Returns the outputs of the transaction.
    pub fn outputs(&self) -> &[SentTransactionOutput<AccountId>] {
        self.outputs
    }
    /// Returns the fee paid by the transaction.
    pub fn fee_amount(&self) -> NonNegativeAmount {
        self.fee_amount
    }
    /// Returns the list of UTXOs spent in the created transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn utxos_spent(&self) -> &[OutPoint] {
        self.utxos_spent
    }

    /// Returns the block height that this transaction was created to target.
    pub fn target_height(&self) -> BlockHeight {
        self.target_height
    }
}

/// An output of a transaction generated by the wallet.
///
/// This type is capable of representing both shielded and transparent outputs.
pub struct SentTransactionOutput<AccountId> {
    output_index: usize,
    recipient: Recipient<AccountId, Note, OutPoint>,
    value: NonNegativeAmount,
    memo: Option<MemoBytes>,
}

impl<AccountId> SentTransactionOutput<AccountId> {
    /// Constructs a new [`SentTransactionOutput`] from its constituent parts.
    ///
    /// ### Fields:
    /// * `output_index` - the index of the output or action in the sent transaction
    /// * `recipient` - the recipient of the output, either a Zcash address or a
    ///    wallet-internal account and the note belonging to the wallet created by
    ///    the output
    /// * `value` - the value of the output, in zatoshis
    /// * `memo` - the memo that was sent with this output
    pub fn from_parts(
        output_index: usize,
        recipient: Recipient<AccountId, Note, OutPoint>,
        value: NonNegativeAmount,
        memo: Option<MemoBytes>,
    ) -> Self {
        Self {
            output_index,
            recipient,
            value,
            memo,
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
    /// Returns the recipient address of the transaction, or the account id and
    /// resulting note/outpoint for wallet-internal outputs.
    pub fn recipient(&self) -> &Recipient<AccountId, Note, OutPoint> {
        &self.recipient
    }
    /// Returns the value of the newly created output.
    pub fn value(&self) -> NonNegativeAmount {
        self.value
    }
    /// Returns the memo that was attached to the output, if any. This will only be `None`
    /// for transparent outputs.
    pub fn memo(&self) -> Option<&MemoBytes> {
        self.memo.as_ref()
    }
}

/// A data structure used to set the birthday height for an account, and ensure that the initial
/// note commitment tree state is recorded at that height.
#[derive(Clone, Debug)]
pub struct AccountBirthday {
    prior_chain_state: ChainState,
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
    /// * `prior_chain_state`: The chain state prior to the birthday height of the account. The
    ///    birthday height is defined as the height of the first block to be scanned in wallet
    ///    recovery.
    /// * `recover_until`: An optional height at which the wallet should exit "recovery mode". In
    ///    order to avoid confusing shifts in wallet balance and spendability that may temporarily be
    ///    visible to a user during the process of recovering from seed, wallets may optionally set a
    ///    "recover until" height. The wallet is considered to be in "recovery mode" until there
    ///    exist no unscanned ranges between the wallet's birthday height and the provided
    ///    `recover_until` height, exclusive.
    ///
    /// This API is intended primarily to be used in testing contexts; under normal circumstances,
    /// [`AccountBirthday::from_treestate`] should be used instead.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn from_parts(prior_chain_state: ChainState, recover_until: Option<BlockHeight>) -> Self {
        Self {
            prior_chain_state,
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
            prior_chain_state: treestate.to_chain_state()?,
            recover_until,
        })
    }

    /// Returns the Sapling note commitment tree frontier as of the end of the block at
    /// [`Self::height`].
    pub fn sapling_frontier(
        &self,
    ) -> &Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }> {
        self.prior_chain_state.final_sapling_tree()
    }

    /// Returns the Orchard note commitment tree frontier as of the end of the block at
    /// [`Self::height`].
    #[cfg(feature = "orchard")]
    pub fn orchard_frontier(
        &self,
    ) -> &Frontier<orchard::tree::MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>
    {
        self.prior_chain_state.final_orchard_tree()
    }

    /// Returns the birthday height of the account.
    pub fn height(&self) -> BlockHeight {
        self.prior_chain_state.block_height() + 1
    }

    /// Returns the height at which the wallet should exit "recovery mode".
    pub fn recover_until(&self) -> Option<BlockHeight> {
        self.recover_until
    }

    #[cfg(any(test, feature = "test-dependencies"))]
    /// Constructs a new [`AccountBirthday`] at the given network upgrade's activation,
    /// with no "recover until" height.
    ///
    /// # Panics
    ///
    /// Panics if the activation height for the given network upgrade is not set.
    pub fn from_activation<P: zcash_primitives::consensus::Parameters>(
        params: &P,
        network_upgrade: NetworkUpgrade,
        prior_block_hash: BlockHash,
    ) -> AccountBirthday {
        AccountBirthday::from_parts(
            ChainState::empty(
                params.activation_height(network_upgrade).unwrap() - 1,
                prior_block_hash,
            ),
            None,
        )
    }

    #[cfg(any(test, feature = "test-dependencies"))]
    /// Constructs a new [`AccountBirthday`] at Sapling activation, with no
    /// "recover until" height.
    ///
    /// # Panics
    ///
    /// Panics if the Sapling activation height is not set.
    pub fn from_sapling_activation<P: zcash_primitives::consensus::Parameters>(
        params: &P,
        prior_block_hash: BlockHash,
    ) -> AccountBirthday {
        Self::from_activation(params, NetworkUpgrade::Sapling, prior_block_hash)
    }
}

/// This trait encapsulates the write capabilities required to update stored wallet data.
///
/// # Adding accounts
///
/// This trait provides several methods for adding accounts to the wallet data:
/// - [`WalletWrite::create_account`]
/// - [`WalletWrite::import_account_hd`]
/// - [`WalletWrite::import_account_ufvk`]
///
/// All of these methods take an [`AccountBirthday`]. The birthday height is defined as
/// the minimum block height that will be scanned for funds belonging to the wallet. If
/// `birthday.height()` is below the current chain tip, the account addition operation
/// will trigger a re-scan of the blocks at and above the provided height.
///
/// The order in which you call these methods will affect the resulting wallet structure:
/// - If only [`WalletWrite::create_account`] is used, the resulting accounts will have
///   sequential [ZIP 32] account indices within each given seed.
/// - If [`WalletWrite::import_account_hd`] is used to import accounts with non-sequential
///   ZIP 32 account indices from the same seed, a call to [`WalletWrite::create_account`]
///   will use the ZIP 32 account index just after the highest-numbered existing account.
/// - If an account is added to the wallet, and then a later call to one of the methods
///   would produce a UFVK that collides with that account on any FVK component (i.e.
///   Sapling, Orchard, or transparent), an error will be returned. This can occur in the
///   following cases:
///   - An account is created via [`WalletWrite::create_account`] with an auto-selected
///     ZIP 32 account index, and that index is later imported explicitly via either
///     [`WalletWrite::import_account_ufvk`] or [`WalletWrite::import_account_hd`].
///   - An account is imported via [`WalletWrite::import_account_ufvk`] or
///     [`WalletWrite::import_account_hd`], and then the ZIP 32 account index
///     corresponding to that account's UFVK is later imported either implicitly
///     via [`WalletWrite::create_account`], or explicitly via a call to
///     [`WalletWrite::import_account_ufvk`] or [`WalletWrite::import_account_hd`].
///
/// Note that an error will be returned on an FVK collision even if the UFVKs do not
/// match exactly, e.g. if they have different subsets of components.
///
/// A future change to this trait might introduce a method to "upgrade" an imported
/// account with derivation information. See [zcash/librustzcash#1284] for details.
///
/// Users of the `WalletWrite` trait should generally distinguish in their APIs and wallet
/// UIs between creating a new account, and importing an account that previously existed.
/// By convention, wallets should only allow a new account to be generated after confirmed
/// funds have been received by the newest existing account; this allows automated account
/// recovery to discover and recover all funds within a particular seed.
///
/// # Creating a new wallet
///
/// To create a new wallet:
/// - Generate a new [BIP 39] mnemonic phrase, using a crate like [`bip0039`].
/// - Derive the corresponding seed from the mnemonic phrase.
/// - Use [`WalletWrite::create_account`] with the resulting seed.
///
/// Callers should construct the [`AccountBirthday`] using [`AccountBirthday::from_treestate`] for
/// the block at height `chain_tip_height - 100`. Setting the birthday height to a tree state below
/// the pruning depth ensures that reorgs cannot cause funds intended for the wallet to be missed;
/// otherwise, if the chain tip height were used for the wallet birthday, a transaction targeted at
/// a height greater than the chain tip could be mined at a height below that tip as part of a
/// reorg.
///
/// # Restoring a wallet from backup
///
/// To restore a backed-up wallet:
/// - Derive the seed from its BIP 39 mnemonic phrase.
/// - Use [`WalletWrite::import_account_hd`] once for each ZIP 32 account index that the
///   user wants to restore.
/// - If the highest previously-used ZIP 32 account index was _not_ restored by the user,
///   remember this index separately as `index_max`. The first time the user wants to
///   generate a new account, use [`WalletWrite::import_account_hd`] to create the account
///   `index_max + 1`.
/// - [`WalletWrite::create_account`] can be used to generate subsequent new accounts in
///   the restored wallet.
///
/// Automated account recovery has not yet been implemented by this crate. A wallet app
/// that supports multiple accounts can implement it manually by tracking account balances
/// relative to [`WalletSummary::fully_scanned_height`], and creating new accounts as
/// funds appear in existing accounts.
///
/// If the number of accounts is known in advance, the wallet should create all accounts before
/// scanning the chain so that the scan can be done in a single pass for all accounts.
///
/// [ZIP 32]: https://zips.z.cash/zip-0032
/// [zcash/librustzcash#1284]: https://github.com/zcash/librustzcash/issues/1284
/// [BIP 39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
/// [`bip0039`]: https://crates.io/crates/bip0039
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait WalletWrite: WalletRead {
    /// The type of identifiers used to look up transparent UTXOs.
    type UtxoRef;

    /// Tells the wallet to track the next available account-level spend authority, given the
    /// current set of [ZIP 316] account identifiers known to the wallet database.
    ///
    /// The "next available account" is defined as the ZIP-32 account index immediately following
    /// the highest existing account index among all accounts in the wallet that share the given
    /// seed. Users of the [`WalletWrite`] trait that only call this method are guaranteed to have
    /// accounts with sequential indices.
    ///
    /// Returns the account identifier for the newly-created wallet database entry, along with the
    /// associated [`UnifiedSpendingKey`]. Note that the unique account identifier should *not* be
    /// assumed equivalent to the ZIP 32 account index. It is an opaque identifier for a pool of
    /// funds or set of outputs controlled by a single spending authority.
    ///
    /// The ZIP-32 account index may be obtained by calling [`WalletRead::get_account`]
    /// with the returned account identifier.
    ///
    /// The [`WalletWrite`] trait documentation has more details about account creation and import.
    ///
    /// # Implementation notes
    ///
    /// Implementations of this method **MUST NOT** "fill in gaps" by selecting an account index
    /// that is lower than any existing account index among all accounts in the wallet that share
    /// the given seed.
    ///
    /// # Panics
    ///
    /// Panics if the length of the seed is not between 32 and 252 bytes inclusive.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    fn create_account(
        &mut self,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error>;

    /// Tells the wallet to track a specific account index for a given seed.
    ///
    /// Returns details about the imported account, including the unique account identifier for
    /// the newly-created wallet database entry, along with the associated [`UnifiedSpendingKey`].
    /// Note that the unique account identifier should *not* be assumed equivalent to the ZIP 32
    /// account index. It is an opaque identifier for a pool of funds or set of outputs controlled
    /// by a single spending authority.
    ///
    /// Import accounts with indices that are exactly one greater than the highest existing account
    /// index to ensure account indices are contiguous, thereby facilitating automated account
    /// recovery.
    ///
    /// The [`WalletWrite`] trait documentation has more details about account creation and import.
    ///
    /// # Panics
    ///
    /// Panics if the length of the seed is not between 32 and 252 bytes inclusive.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    fn import_account_hd(
        &mut self,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error>;

    /// Tells the wallet to track an account using a unified full viewing key.
    ///
    /// Returns details about the imported account, including the unique account identifier for
    /// the newly-created wallet database entry. Unlike the other account creation APIs
    /// ([`Self::create_account`] and [`Self::import_account_hd`]), no spending key is returned
    /// because the wallet has no information about how the UFVK was derived.
    ///
    /// Certain optimizations are possible for accounts which will never be used to spend funds. If
    /// `spending_key_available` is `false`, the wallet may choose to optimize for this case, in
    /// which case any attempt to spend funds from the account will result in an error.
    ///
    /// The [`WalletWrite`] trait documentation has more details about account creation and import.
    ///
    /// # Panics
    ///
    /// Panics if the length of the seed is not between 32 and 252 bytes inclusive.
    fn import_account_ufvk(
        &mut self,
        unified_key: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: AccountPurpose,
    ) -> Result<Self::Account, Self::Error>;

    /// Generates and persists the next available diversified address, given the current
    /// addresses known to the wallet.
    ///
    /// Returns `Ok(None)` if the account identifier does not correspond to a known
    /// account.
    fn get_next_available_address(
        &mut self,
        account: Self::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error>;

    /// Updates the wallet's view of the blockchain.
    ///
    /// This method is used to provide the wallet with information about the state of the
    /// blockchain, and detect any previously scanned data that needs to be re-validated
    /// before proceeding with scanning. It should be called at wallet startup prior to calling
    /// [`WalletRead::suggest_scan_ranges`] in order to provide the wallet with the information it
    /// needs to correctly prioritize scanning operations.
    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Self::Error>;

    /// Updates the state of the wallet database by persisting the provided block information,
    /// along with the note commitments that were detected when scanning the block for transactions
    /// pertaining to this wallet.
    ///
    /// ### Arguments
    /// - `from_state` must be the chain state for the block height prior to the first
    ///   block in `blocks`.
    /// - `blocks` must be sequential, in order of increasing block height.
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error>;

    /// Adds a transparent UTXO received by the wallet to the data store.
    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error>;

    /// Caches a decrypted transaction in the persistent wallet store.
    fn store_decrypted_tx(
        &mut self,
        received_tx: DecryptedTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error>;

    /// Saves information about transactions constructed by the wallet to the persistent
    /// wallet store.
    ///
    /// This must be called before the transactions are sent to the network.
    ///
    /// Transactions that have been stored by this method should be retransmitted while it
    /// is still possible that they could be mined.
    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<Self::AccountId>],
    ) -> Result<(), Self::Error>;

    /// Truncates the wallet database to at most the specified height.
    ///
    /// Implementations of this method may choose a lower block height to which the data store will
    /// be truncated if it is not possible to truncate exactly to the specified height. Upon
    /// successful truncation, this method returns the height to which the data store was actually
    /// truncated.
    ///
    /// This method assumes that the state of the underlying data store is consistent up to a
    /// particular block height. Since it is possible that a chain reorg might invalidate some
    /// stored state, this method must be implemented in order to allow users of this API to
    /// "reset" the data store to correctly represent chainstate as of at most the requested block
    /// height.
    ///
    /// After calling this method, the block at the returned height will be the most recent block
    /// and all other operations will treat this block as the chain tip for balance determination
    /// purposes.
    ///
    /// There may be restrictions on heights to which it is possible to truncate. Specifically, it
    /// will only be possible to truncate to heights at which is is possible to create a witness
    /// given the current state of the wallet's note commitment tree.
    fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Self::Error>;

    /// Reserves the next `n` available ephemeral addresses for the given account.
    /// This cannot be undone, so as far as possible, errors associated with transaction
    /// construction should have been reported before calling this method.
    ///
    /// To ensure that sufficient information is stored on-chain to allow recovering
    /// funds sent back to any of the used addresses, a "gap limit" of 20 addresses
    /// should be observed as described in [BIP 44].
    ///
    /// Returns an error if there is insufficient space within the gap limit to allocate
    /// the given number of addresses, or if the account identifier does not correspond
    /// to a known account.
    ///
    /// [BIP 44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#user-content-Address_gap_limit
    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        _account_id: Self::AccountId,
        _n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        // Default impl is required for feature-flagged trait methods to prevent
        // breakage due to inadvertent activation of features by transitive dependencies
        // of the implementing crate.
        Ok(vec![])
    }

    /// Updates the wallet backend with respect to the status of a specific transaction, from the
    /// perspective of the main chain.
    ///
    /// Fully transparent transactions, and transactions that do not contain either shielded inputs
    /// or shielded outputs belonging to the wallet, may not be discovered by the process of chain
    /// scanning; as a consequence, the wallet must actively query to determine whether such
    /// transactions have been mined.
    fn set_transaction_status(
        &mut self,
        _txid: TxId,
        _status: TransactionStatus,
    ) -> Result<(), Self::Error>;
}

/// This trait describes a capability for manipulating wallet note commitment trees.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait WalletCommitmentTrees {
    type Error: Debug;

    /// The type of the backing [`ShardStore`] for the Sapling note commitment tree.
    type SaplingShardStore<'a>: ShardStore<
        H = sapling::Node,
        CheckpointId = BlockHeight,
        Error = Self::Error,
    >;

    /// Evaluates the given callback function with a reference to the Sapling
    /// note commitment tree maintained by the wallet.
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

    /// Adds a sequence of Sapling note commitment tree subtree roots to the data store.
    ///
    /// Each such value should be the Merkle root of a subtree of the Sapling note commitment tree
    /// containing 2^[`SAPLING_SHARD_HEIGHT`] note commitments.
    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>>;

    /// The type of the backing [`ShardStore`] for the Orchard note commitment tree.
    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a>: ShardStore<
        H = orchard::tree::MerkleHashOrchard,
        CheckpointId = BlockHeight,
        Error = Self::Error,
    >;

    /// Evaluates the given callback function with a reference to the Orchard
    /// note commitment tree maintained by the wallet.
    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>;

    /// Adds a sequence of Orchard note commitment tree subtree roots to the data store.
    ///
    /// Each such value should be the Merkle root of a subtree of the Orchard note commitment tree
    /// containing 2^[`ORCHARD_SHARD_HEIGHT`] note commitments.
    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>>;
}
