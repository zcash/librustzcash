//! Low-level data API
//!
//! This module provides default implementations for several common client operations that rely on
//! lower-level and more granular access to data. Client implementers should consider using the
//! utility functions in this module when implementing traits such as [`WalletRead`] and
//! [`WalletWrite`] in order to provide a consistent and robust user experience.
//!
//! [`WalletRead`]: super::WalletRead
//! [`WalletWrite`]: super::WalletWrite

use core::hash::Hash;
use std::{collections::HashSet, ops::Range};

use incrementalmerkletree::Position;
use transparent::bundle::OutPoint;
use zcash_address::ZcashAddress;
use zcash_keys::address::Receiver;
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TransactionData},
};
use zcash_protocol::{
    ShieldedProtocol, TxId,
    consensus::{BlockHeight, TxIndex},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};
use zip32::Scope;

use super::{Account, TransactionStatus, wallet::TargetHeight};
use crate::{
    DecryptedOutput, TransferType,
    wallet::{Recipient, WalletSaplingOutput, WalletTx},
};

#[cfg(feature = "transparent-inputs")]
use {
    super::WalletUtxo,
    transparent::{address::TransparentAddress, keys::TransparentKeyScope},
    zcash_keys::keys::UnifiedAddressRequest,
};

#[cfg(feature = "orchard")]
use crate::wallet::WalletOrchardOutput;

pub mod wallet;

/// A trait for types that can provide information about outputs spent by and fees that were paid
/// for a given transaction.
pub trait TxMeta {
    /// Returns an iterator over the references to transparent outputs spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    fn transparent_spends(&self) -> impl Iterator<Item = &OutPoint>;

    /// Returns an iterator over the nullifiers of Sapling notes spent in this transaction.
    fn sapling_spent_note_nullifiers(&self) -> impl Iterator<Item = &::sapling::Nullifier>;

    /// Returns an iterator over the nullifiers of Orchard notes spent in this transaction.
    #[cfg(feature = "orchard")]
    fn orchard_spent_note_nullifiers(&self) -> impl Iterator<Item = &::orchard::note::Nullifier>;

    /// Returns the fee paid by this transaction, given a function that can retrieve the value of
    /// prior transparent outputs spent in the transaction.
    ///
    /// Returns `Ok(None)` if insufficient information is available for computing the fee.
    fn fee_paid<E, F>(&self, get_prevout: F) -> Result<Option<Zatoshis>, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<Option<Zatoshis>, E>;
}

impl TxMeta for Transaction {
    #[cfg(feature = "transparent-inputs")]
    fn transparent_spends(&self) -> impl Iterator<Item = &OutPoint> {
        self.transparent_bundle()
            .into_iter()
            .flat_map(|bundle| bundle.vin.iter().map(|txin| txin.prevout()))
    }

    fn sapling_spent_note_nullifiers(&self) -> impl Iterator<Item = &::sapling::Nullifier> {
        self.sapling_bundle().into_iter().flat_map(|bundle| {
            bundle
                .shielded_spends()
                .iter()
                .map(|spend| spend.nullifier())
        })
    }

    #[cfg(feature = "orchard")]
    fn orchard_spent_note_nullifiers(&self) -> impl Iterator<Item = &::orchard::note::Nullifier> {
        self.orchard_bundle()
            .into_iter()
            .flat_map(|bundle| bundle.actions().iter().map(|action| action.nullifier()))
    }

    fn fee_paid<E, F>(&self, get_prevout: F) -> Result<Option<Zatoshis>, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<Option<Zatoshis>, E>,
    {
        TransactionData::fee_paid(self, get_prevout)
    }
}

/// A capability trait that provides low-level wallet database read operations. These operations
/// are used to provide standard implementations for certain [`WalletWrite`] trait methods.
///
/// [`WalletWrite`]: super::WalletWrite
pub trait LowLevelWalletRead {
    /// The type of errors that may be generated when querying a wallet data store.
    type Error;

    /// The type of the account identifier.
    ///
    /// An account identifier corresponds to at most a single unified spending key's worth of spend
    /// authority, such that both received notes and change spendable by that spending authority
    /// will be interpreted as belonging to that account.
    type AccountId: Copy + Eq + Hash;

    /// A wallet-internal account identifier
    type AccountRef: Copy + Eq + Hash;

    /// Type of the account with associated capabilities
    type Account: Account;

    /// A wallet-internal transaction identifier.
    type TxRef: Copy + Eq + Hash;

    /// Returns the set of account identifiers for accounts that spent notes and/or UTXOs in the
    /// construction of the given transaction.
    fn get_funding_accounts<T: TxMeta>(
        &self,
        tx: &T,
    ) -> Result<HashSet<Self::AccountId>, Self::Error> {
        let mut funding_accounts = HashSet::new();

        #[cfg(feature = "transparent-inputs")]
        funding_accounts.extend(self.detect_accounts_transparent(tx.transparent_spends())?);

        funding_accounts.extend(self.detect_accounts_sapling(tx.sapling_spent_note_nullifiers())?);

        #[cfg(feature = "orchard")]
        funding_accounts.extend(self.detect_accounts_orchard(tx.orchard_spent_note_nullifiers())?);

        Ok(funding_accounts)
    }

    /// Returns the most likely wallet address that corresponds to the protocol-level receiver of a
    /// note or UTXO.
    ///
    /// If the wallet database has stored a wallet address that contains the given receiver, then
    /// that address is returned; otherwise, the most likely address containing that receiver
    /// will be returned. The "most likely" address should be produced by generating the "standard"
    /// address (a transparent address if the receiver is transparent, or the default Unified
    /// address for the account) derived at the receiver's diviersifier index if the receiver is
    /// for a shielded pool.
    ///
    /// Returns `Ok(None)` if the receiver cannot be determined to belong to an address produced by
    /// this account.
    fn select_receiving_address(
        &self,
        account: Self::AccountId,
        receiver: &Receiver,
    ) -> Result<Option<ZcashAddress>, Self::Error>;

    /// Detects and returns the identifier for the account to which the address belongs, if any.
    ///
    /// In addition, for HD-derived addresses, the change-level key scope used to derive the
    /// address is returned, so that the caller is able to determine whether any special handling
    /// rules apply to the address for the purposes of preserving user privacy (by limiting address
    /// linking, etc.).
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    fn find_account_for_transparent_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<(Self::AccountId, Option<TransparentKeyScope>)>, Self::Error>;

    /// Finds the set of accounts that either provide inputs to or receive outputs from any of the
    /// provided transactions.
    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    fn find_involved_accounts(
        &self,
        tx_refs: impl IntoIterator<Item = Self::TxRef>,
    ) -> Result<HashSet<(Self::AccountId, Option<TransparentKeyScope>)>, Self::Error>;

    /// Detects the set of accounts that received transparent outputs corresponding to the provided
    /// [`OutPoint`]s. This is used to determine which account(s) funded a given transaction.
    ///
    /// [`OutPoint`]: transparent::bundle::OutPoint
    #[cfg(feature = "transparent-inputs")]
    fn detect_accounts_transparent<'a>(
        &self,
        spends: impl Iterator<Item = &'a transparent::bundle::OutPoint>,
    ) -> Result<HashSet<Self::AccountId>, Self::Error>;

    /// Detects the set of accounts that received Sapling outputs that, when spent, reveal(ed) the
    /// given [`Nullifier`]s. This is used to determine which account(s) funded a given
    /// transaction.
    ///
    /// [`Nullifier`]: sapling::Nullifier
    fn detect_accounts_sapling<'a>(
        &self,
        spends: impl Iterator<Item = &'a sapling::Nullifier>,
    ) -> Result<HashSet<Self::AccountId>, Self::Error>;

    /// Detects the set of accounts that received Orchard outputs that, when spent, reveal(ed) the
    /// given [`Nullifier`]s. This is used to determine which account(s) funded a given
    /// transaction.
    ///
    /// [`Nullifier`]: orchard::note::Nullifier
    #[cfg(feature = "orchard")]
    fn detect_accounts_orchard<'a>(
        &self,
        spends: impl Iterator<Item = &'a orchard::note::Nullifier>,
    ) -> Result<HashSet<Self::AccountId>, Self::Error>;

    /// Get information about a transparent output controlled by the wallet.
    ///
    /// # Parameters
    /// - `outpoint`: The identifier for the output to be retrieved.
    /// - `target_height`: The target height of a transaction under construction that will spend the
    ///   returned output. If this is `None`, no spendability checks are performed.
    #[cfg(feature = "transparent-inputs")]
    fn get_wallet_transparent_output(
        &self,
        outpoint: &OutPoint,
        target_height: Option<TargetHeight>,
    ) -> Result<Option<WalletUtxo>, Self::Error>;

    /// Returns the vector of transactions in the wallet that spend the transparent outputs of the
    /// referenced transaction. This should include conflicted transactions and transactions that
    /// have expired without having been mined.
    ///
    /// This is used as part of [`wallet::store_decrypted_tx`] to allow downstream transactions'
    /// fee amounts to be updated once the value of all their inputs are known.
    fn get_txs_spending_transparent_outputs_of(
        &self,
        tx_ref: Self::TxRef,
    ) -> Result<Vec<(Self::TxRef, Transaction)>, Self::Error>;

    /// Finds the reference to the transaction that reveals the given Sapling nullifier in the
    /// backing data store, if known.
    fn detect_sapling_spend(
        &self,
        nf: &::sapling::Nullifier,
    ) -> Result<Option<Self::TxRef>, Self::Error>;

    /// Finds the reference to the transaction that reveals the given Orchard nullifier in the
    /// backing data store, if known.
    #[cfg(feature = "orchard")]
    fn detect_orchard_spend(
        &self,
        nf: &::orchard::note::Nullifier,
    ) -> Result<Option<Self::TxRef>, Self::Error>;

    /// Get the ephemeral value for working with accounts in the wallet data store
    #[cfg(feature = "transparent-inputs")]
    fn get_account_ref(
        &mut self,
        account_uuid: Self::AccountId,
    ) -> Result<Self::AccountRef, Self::Error>;

    /// Get the account for an internal account reference
    #[cfg(feature = "transparent-inputs")]
    fn get_account_internal(
        &mut self,
        account_id: Self::AccountRef,
    ) -> Result<Option<Self::Account>, Self::Error>;
}

/// A capability trait that provides low-level wallet write operations. These operations are used
/// to provide standard implementations for certain [`WalletWrite`] trait methods.
///
/// [`WalletWrite`]: super::WalletWrite
pub trait LowLevelWalletWrite: LowLevelWalletRead {
    /// Add metadata about a block to the wallet data store.
    #[allow(clippy::too_many_arguments)]
    fn put_block_meta(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        sapling_commitment_tree_size: u32,
        sapling_output_count: u32,
        #[cfg(feature = "orchard")] orchard_commitment_tree_size: u32,
        #[cfg(feature = "orchard")] orchard_action_count: u32,
    ) -> Result<(), Self::Error>;

    /// Add metadata about a transaction to the wallet data store.
    fn put_tx_meta(
        &mut self,
        tx: &WalletTx<Self::AccountId>,
        height: BlockHeight,
    ) -> Result<Self::TxRef, Self::Error>;

    /// Adds the given transaction to the wallet.
    fn put_tx_data(
        &mut self,
        tx: &Transaction,
        fee: Option<Zatoshis>,
        created_at: Option<time::OffsetDateTime>,
        target_height: Option<TargetHeight>,
        observed_height: BlockHeight,
    ) -> Result<Self::TxRef, Self::Error>;

    /// Updates transaction metadata to reflect that the given transaction status has been
    /// observed.
    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: TransactionStatus,
    ) -> Result<(), Self::Error>;

    /// Adds information about a received Sapling note to the wallet, or updates any existing
    /// record for that output.
    fn put_received_sapling_note<T: ReceivedSaplingOutput<AccountId = Self::AccountId>>(
        &mut self,
        output: &T,
        tx_ref: Self::TxRef,
        target_or_mined_height: Option<BlockHeight>,
        spent_in: Option<Self::TxRef>,
    ) -> Result<(), Self::Error>;

    /// Updates the backing store to indicate that the Sapling output having the given nullifier is
    /// spent in the transaction referenced by `spent_in_tx`. This may result in multiple distinct
    /// transactions being recorded as having spent the note; only one of these transactions will
    /// end up having been mined (by consensus.)
    ///
    /// Returns `Ok(true)` if a a new record was added to the data store.
    fn mark_sapling_note_spent(
        &mut self,
        nf: &::sapling::Nullifier,
        spent_in_tx: Self::TxRef,
    ) -> Result<bool, Self::Error>;

    /// Causes the given Sapling output nullifiers to be tracked by the wallet.
    ///
    /// When scanning the chain out-of-order, it is necessary to store the any nullifiers observed
    /// after a gap in the scanned blocks until the blocks in that gap have been fully scanned, in
    /// order to be able to immediately detect that a received output has already been spent. The
    /// data store should track a mapping from each nullifier to the block, transaction index and
    /// ID of the transaction where the spend occurred.
    fn track_block_sapling_nullifiers(
        &mut self,
        block_height: BlockHeight,
        nfs: &[(TxIndex, TxId, Vec<::sapling::Nullifier>)],
    ) -> Result<(), Self::Error>;

    /// Adds information about a received Orchard note to the wallet, or updates any existing
    /// record for that output.
    #[cfg(feature = "orchard")]
    fn put_received_orchard_note<T: ReceivedOrchardOutput<AccountId = Self::AccountId>>(
        &mut self,
        output: &T,
        tx_ref: Self::TxRef,
        target_or_mined_height: Option<BlockHeight>,
        spent_in: Option<Self::TxRef>,
    ) -> Result<(), Self::Error>;

    /// Updates the backing store to indicate that the Orchard output having the given nullifier is
    /// spent in the transaction referenced by `spent_in_tx`. This may result in multiple distinct
    /// transactions being recorded as having spent the note; only one of these transactions will
    /// end up having been mined (by consensus.)
    ///
    /// Returns `Ok(true)` if a a new record was added to the data store.
    #[cfg(feature = "orchard")]
    fn mark_orchard_note_spent(
        &mut self,
        nf: &::orchard::note::Nullifier,
        tx_ref: Self::TxRef,
    ) -> Result<bool, Self::Error>;

    /// Causes the given Orchard output nullifiers to be tracked by the wallet.
    ///
    /// When scanning the chain out-of-order, it is necessary to store the any nullifiers observed
    /// after a gap in the scanned blocks until the blocks in that gap have been fully scanned, in
    /// order to be able to immediately detect that a received output has already been spent. The
    /// data store should track a mapping from each nullifier to the block, transaction index and
    /// ID of the transaction where the spend occurred.
    #[cfg(feature = "orchard")]
    fn track_block_orchard_nullifiers(
        &mut self,
        block_height: BlockHeight,
        nfs: &[(TxIndex, TxId, Vec<::orchard::note::Nullifier>)],
    ) -> Result<(), Self::Error>;

    /// Removes nullifiers tracked by the wallet for transactions mined in blocks at heights less
    /// than `pruning_depth` blocks below the height to which the wallet has been fully scanned.
    fn prune_tracked_nullifiers(&mut self, pruning_depth: u32) -> Result<(), Self::Error>;

    /// Records information about a transaction output that your wallet created, from the constituent
    /// properties of that output.
    ///
    /// - If `recipient` is a Unified address, `output_index` is an index into the outputs of the
    ///   transaction within the bundle associated with the recipient's output pool.
    /// - If `recipient` is a Sapling address, `output_index` is an index into the Sapling outputs of
    ///   the transaction.
    /// - If `recipient` is a transparent address, `output_index` is an index into the transparent
    ///   outputs of the transaction.
    /// - If `recipient` is an internal account, `output_index` is an index into the outputs of
    ///   the bundle indicated by the recipient pool.
    fn put_sent_output(
        &mut self,
        from_account_uuid: Self::AccountId,
        tx_ref: Self::TxRef,
        output_index: usize,
        recipient: &Recipient<Self::AccountId>,
        value: Zatoshis,
        memo: Option<&MemoBytes>,
    ) -> Result<(), Self::Error>;

    /// Updates the wallet's view of a transaction to indicate the miner's fee paid by the
    /// transaction.
    fn update_tx_fee(&mut self, tx_ref: Self::TxRef, fee: Zatoshis) -> Result<(), Self::Error>;

    /// Adds a transparent output observed by the wallet to the data store, or updates any existing
    /// record for that output.
    ///
    /// # Parameters
    /// - `output`: The output data.
    /// - `observation_height`: The chain tip height at the time that the update is made. Note that
    ///   this is likely to differ from the height at which the output was mined (if any).
    /// - `known_unspent`: Set to `true` if the output is known to be a member of the UTXO set as
    ///   of the given observation height.
    #[cfg(feature = "transparent-inputs")]
    fn put_transparent_output(
        &mut self,
        output: &crate::wallet::WalletTransparentOutput,
        observation_height: BlockHeight,
        known_unspent: bool,
    ) -> Result<(Self::AccountId, Option<TransparentKeyScope>), Self::Error>;

    /// Updates the backing store to indicate that the UTXO referred to by `outpoint` is spent
    /// in the transaction referenced by `spent_in_tx`.
    #[cfg(feature = "transparent-inputs")]
    fn mark_transparent_utxo_spent(
        &mut self,
        outpoint: &OutPoint,
        spent_in_tx: Self::TxRef,
    ) -> Result<bool, Self::Error>;

    /// Updates the wallet backend by generating and caching addresses for the given key scope such
    /// that at least the backend's configured gap limit worth of addresses exist at indices
    /// successive from that of the last address that received a mined transaction.
    ///
    /// # Parameters
    /// - `account_id`: The ID of the account holding the UFVK from which addresses should be
    ///   generated.
    /// - `key_scope`: The transparent key scope for addresses to generate. Implementations may
    ///   choose to only support the `external`, `internal`, and `ephemeral` key scopes and return
    ///   an error if an unrecognized scope is used.
    /// - `request`: A request for the Unified Address that will be generated with a diversifier
    ///   index equal to the [`BIP 44`] `address_index` of each generated address.
    ///
    /// [`BIP 44`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    #[cfg(feature = "transparent-inputs")]
    fn generate_transparent_gap_addresses(
        &mut self,
        account_id: Self::AccountId,
        key_scope: TransparentKeyScope,
        request: UnifiedAddressRequest,
    ) -> Result<(), Self::Error>;

    /// Adds a [`TransactionDataRequest::Enhancement`] request for the enhancement of the given
    /// transaction to the transaction data request queue. The `dependent_tx_ref` parameter
    /// specifies the transaction that caused this request to be generated, likely as part of the
    /// process of traversing the transparent transaction graph by inspecting the inputs of a
    /// transaction with outputs that were received by the wallet.
    ///
    /// [`TransactionDataRequest::Enhancement`]: super::TransactionDataRequest
    fn queue_tx_retrieval(
        &mut self,
        txids: impl Iterator<Item = TxId>,
        dependent_tx_ref: Option<Self::TxRef>,
    ) -> Result<(), Self::Error>;

    /// Adds a [`TransactionDataRequest::TransactionsInvolvingAddress`] request to the transaction
    /// data request queue. When the transparent output of `tx_ref` at output index `output_index`
    /// (which must have been received at `receiving_address`) is detected as having been spent,
    /// this request will be considered fulfilled.
    ///
    /// NOTE: The somewhat awkward API of this method is a historical artifact; if the light wallet
    /// protocol is in the future updated to expose a mechanism to find the transaction that spends
    /// a particular `OutPoint`, the `TransactionsInvolvingAddress` variant and this method will
    /// likely be removed.
    ///
    /// [`TransactionDataRequest::TransactionsInvolvingAddress`]: super::TransactionDataRequest
    #[cfg(feature = "transparent-inputs")]
    fn queue_transparent_spend_detection(
        &mut self,
        receiving_address: TransparentAddress,
        tx_ref: Self::TxRef,
        output_index: u32,
    ) -> Result<(), Self::Error>;

    /// Adds [`TransactionDataRequest::Enhancement`] requests for transactions that generated the
    /// transparent inputs to the provided [`DecryptedTransaction`] to the transaction data request
    /// queue.
    ///
    /// [`TransactionDataRequest::Enhancement`]: super::TransactionDataRequest
    /// [`DecryptedTransaction`]: super::DecryptedTransaction
    #[cfg(feature = "transparent-inputs")]
    fn queue_transparent_input_retrieval(
        &mut self,
        tx_ref: Self::TxRef,
        d_tx: &super::DecryptedTransaction<Transaction, Self::AccountId>,
    ) -> Result<(), Self::Error>;

    /// Deletes all [`TransactionDataRequest::Enhancement`] requests for the given transaction ID
    /// from the transaction data request queue.
    ///
    /// [`TransactionDataRequest::Enhancement`]: super::TransactionDataRequest
    fn delete_retrieval_queue_entries(&mut self, txid: TxId) -> Result<(), Self::Error>;

    /// Updates the state of the wallet backend to indicate that the given range of blocks has been
    /// fully scanned, identifying the position in the note commitment tree of any notes belonging
    /// to the wallet that were discovered in the process of scanning.
    fn notify_scan_complete(
        &mut self,
        range: Range<BlockHeight>,
        wallet_note_positions: &[(ShieldedProtocol, Position)],
    ) -> Result<(), Self::Error>;
}

/// This trait provides a generalization over shielded Sapling output representations.
pub trait ReceivedSaplingOutput {
    type AccountId;

    /// Returns the index of the Sapling output within the Sapling bundle.
    fn index(&self) -> usize;
    /// Returns the account ID for the account that received this output.
    fn account_id(&self) -> Self::AccountId;
    /// Returns the received note.
    fn note(&self) -> &::sapling::Note;
    /// Returns any memo associated with the output.
    fn memo(&self) -> Option<&MemoBytes>;
    /// Returns whether or not the received output is counted as wallet-internal change, for the
    /// purpose of display.
    fn is_change(&self) -> bool;
    /// Returns the nullifier that will be revealed when the note is spent, if the output was
    /// observed using a key that provides the capability for nullifier computation.
    fn nullifier(&self) -> Option<&::sapling::Nullifier>;
    /// Returns the position of the note in the note commitment tree, if the transaction that
    /// produced the output has been mined.
    fn note_commitment_tree_position(&self) -> Option<Position>;
    /// Returns the HD derivation scope of the viewing key that decrypted the note, if known.
    fn recipient_key_scope(&self) -> Option<Scope>;
}

impl<AccountId: Copy> ReceivedSaplingOutput for WalletSaplingOutput<AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *WalletSaplingOutput::account_id(self)
    }
    fn note(&self) -> &::sapling::Note {
        WalletSaplingOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        WalletSaplingOutput::is_change(self)
    }
    fn nullifier(&self) -> Option<&::sapling::Nullifier> {
        self.nf()
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(WalletSaplingOutput::note_commitment_tree_position(self))
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        self.recipient_key_scope()
    }
}

impl<AccountId: Copy> ReceivedSaplingOutput for DecryptedOutput<::sapling::Note, AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *self.account()
    }
    fn note(&self) -> &::sapling::Note {
        self.note()
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(self.memo())
    }
    fn is_change(&self) -> bool {
        self.transfer_type() == TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&::sapling::Nullifier> {
        None
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        None
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        if self.transfer_type() == TransferType::WalletInternal {
            Some(Scope::Internal)
        } else {
            Some(Scope::External)
        }
    }
}

/// This trait provides a generalization over shielded Orchard output representations.
#[cfg(feature = "orchard")]
pub trait ReceivedOrchardOutput {
    type AccountId;

    /// Returns the index of the Orchard action that produced this output within the Orchard bundle.
    fn index(&self) -> usize;
    /// Returns the account ID for the account that received this output.
    fn account_id(&self) -> Self::AccountId;
    /// Returns the received note.
    fn note(&self) -> &::orchard::note::Note;
    /// Returns any memo associated with the output.
    fn memo(&self) -> Option<&MemoBytes>;
    /// Returns whether or not the received output is counted as wallet-internal change, for the
    /// purpose of display.
    fn is_change(&self) -> bool;
    /// Returns the nullifier that will be revealed when the note is spent, if the output was
    /// observed using a key that provides the capability for nullifier computation.
    fn nullifier(&self) -> Option<&::orchard::note::Nullifier>;
    /// Returns the position of the note in the note commitment tree, if the transaction that
    /// produced the output has been mined.
    fn note_commitment_tree_position(&self) -> Option<Position>;
    /// Returns the HD derivation scope of the viewing key that decrypted the note, if known.
    fn recipient_key_scope(&self) -> Option<Scope>;
}

#[cfg(feature = "orchard")]
impl<AccountId: Copy> ReceivedOrchardOutput for WalletOrchardOutput<AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *WalletOrchardOutput::account_id(self)
    }
    fn note(&self) -> &::orchard::note::Note {
        WalletOrchardOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        WalletOrchardOutput::is_change(self)
    }
    fn nullifier(&self) -> Option<&::orchard::note::Nullifier> {
        self.nf()
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(WalletOrchardOutput::note_commitment_tree_position(self))
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        self.recipient_key_scope()
    }
}

#[cfg(feature = "orchard")]
impl<AccountId: Copy> ReceivedOrchardOutput for DecryptedOutput<::orchard::note::Note, AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *self.account()
    }
    fn note(&self) -> &orchard::note::Note {
        self.note()
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(self.memo())
    }
    fn is_change(&self) -> bool {
        self.transfer_type() == TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&::orchard::note::Nullifier> {
        None
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        None
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        if self.transfer_type() == TransferType::WalletInternal {
            Some(Scope::Internal)
        } else {
            Some(Scope::External)
        }
    }
}
