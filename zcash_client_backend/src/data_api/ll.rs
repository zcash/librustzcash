//! Low-level data API
//!
//! This module provides default implementations for several common client operations that rely on
//! lower-level and more granular access to data. Client implementers should consider using the
//! utility functions in this module when implementing traits such as [`WalletRead`] and
//! [`WalletWrite`] in order to provide a consistent and robust user experience.
//!
//! [`WalletRead`]: super::WalletRead
//! [`WalletWrite`]: super::WalletWrite

use core::{fmt::Debug, hash::Hash};
use std::collections::HashSet;

use incrementalmerkletree::Position;
use transparent::bundle::OutPoint;
use zcash_address::ZcashAddress;
use zcash_keys::address::Receiver;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    TxId,
    consensus::BlockHeight,
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};
use zip32::Scope;

use super::{TransactionStatus, wallet::TargetHeight};
use crate::{
    DecryptedOutput, TransferType,
    wallet::{Recipient, WalletSaplingOutput},
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

pub trait TxMeta {
    #[cfg(feature = "transparent-inputs")]
    fn transparent_spends(&self) -> impl Iterator<Item = &OutPoint>;

    fn sapling_spent_note_nullifiers(&self) -> impl Iterator<Item = &::sapling::Nullifier>;

    #[cfg(feature = "orchard")]
    fn orchard_spent_note_nullifiers(&self) -> impl Iterator<Item = &::orchard::note::Nullifier>;

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
        self.data().fee_paid(get_prevout)
    }
}

pub trait LowLevelWalletRead {
    /// The type of errors that may be generated when querying a wallet data store.
    type Error: Debug;

    /// The type of the account identifier.
    ///
    /// An account identifier corresponds to at most a single unified spending key's worth of spend
    /// authority, such that both received notes and change spendable by that spending authority
    /// will be interpreted as belonging to that account.
    type AccountId: Debug + Copy + Eq + Hash;

    /// A wallet-internal transaction identifier.
    type TxRef: Copy + Eq;

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
    fn select_receiving_address(
        &self,
        account: Self::AccountId,
        receiver: &Receiver,
    ) -> Result<Option<ZcashAddress>, Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::type_complexity)]
    fn find_account_for_transparent_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<(Self::AccountId, Option<TransparentKeyScope>)>, Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    fn detect_accounts_transparent<'a>(
        &self,
        spends: impl Iterator<Item = &'a transparent::bundle::OutPoint>,
    ) -> Result<std::collections::HashSet<Self::AccountId>, Self::Error>;

    fn detect_accounts_sapling<'a>(
        &self,
        spends: impl Iterator<Item = &'a sapling::Nullifier>,
    ) -> Result<std::collections::HashSet<Self::AccountId>, Self::Error>;

    #[cfg(feature = "orchard")]
    fn detect_accounts_orchard<'a>(
        &self,
        spends: impl Iterator<Item = &'a orchard::note::Nullifier>,
    ) -> Result<std::collections::HashSet<Self::AccountId>, Self::Error>;

    /// Get information about a transparent output controlled by the wallet.
    ///
    /// # Parameters
    /// - `outpoint`: The identifier for the output to be retrieved.
    /// - `spendable_as_of`: The target height of a transaction under construction that will spend the
    ///   returned output. If this is `None`, no spendability checks are performed.
    #[cfg(feature = "transparent-inputs")]
    fn get_wallet_transparent_output(
        &self,
        outpoint: &OutPoint,
        spendable_as_of: Option<TargetHeight>,
    ) -> Result<Option<WalletUtxo>, Self::Error>;

    /// Returns the vector of transactions in the wallet that spend the outputs of the referenced
    /// transaction.
    ///
    /// This is used as part of [`wallet::store_decrypted_tx`] to allow downstream transactions'
    /// fee amounts to be updated once the value of all their inputs are known.
    fn get_spending_transactions(
        &self,
        tx_ref: Self::TxRef,
    ) -> Result<Vec<(Self::TxRef, Transaction)>, Self::Error>;
}

pub trait LowLevelWalletWrite: LowLevelWalletRead {
    fn put_tx_data(
        &mut self,
        tx: &Transaction,
        fee: Option<Zatoshis>,
        created_at: Option<time::OffsetDateTime>,
        target_height: Option<TargetHeight>,
        observed_height: BlockHeight,
    ) -> Result<Self::TxRef, Self::Error>;

    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: TransactionStatus,
    ) -> Result<(), Self::Error>;

    fn put_received_sapling_note<T: ReceivedSaplingOutput<AccountId = Self::AccountId>>(
        &mut self,
        output: &T,
        tx_ref: Self::TxRef,
        target_or_mined_height: Option<BlockHeight>,
        spent_in: Option<Self::TxRef>,
    ) -> Result<(), Self::Error>;

    #[cfg(feature = "orchard")]
    fn put_received_orchard_note<T: ReceivedOrchardOutput<AccountId = Self::AccountId>>(
        &mut self,
        output: &T,
        tx_ref: Self::TxRef,
        target_or_mined_height: Option<BlockHeight>,
        spent_in: Option<Self::TxRef>,
    ) -> Result<(), Self::Error>;

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
    ///   the transaction in the transaction bundle corresponding to the recipient pool.
    fn put_sent_output(
        &mut self,
        from_account_uuid: Self::AccountId,
        tx_ref: Self::TxRef,
        output_index: usize,
        recipient: &Recipient<Self::AccountId>,
        value: Zatoshis,
        memo: Option<&MemoBytes>,
    ) -> Result<(), Self::Error>;

    fn update_tx_fee(&mut self, tx_ref: Self::TxRef, fee: Zatoshis) -> Result<(), Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    fn put_transparent_output(
        &mut self,
        output: &crate::wallet::WalletTransparentOutput,
        observation_height: BlockHeight,
        known_unspent: bool,
    ) -> Result<(Self::AccountId, TransparentKeyScope), Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    fn mark_transparent_utxo_spent(
        &mut self,
        spent_in_tx: Self::TxRef,
        outpoint: &OutPoint,
    ) -> Result<bool, Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    fn generate_transparent_gap_addresses(
        &mut self,
        account_id: Self::AccountId,
        key_scope: TransparentKeyScope,
        request: UnifiedAddressRequest,
        require_key: bool,
    ) -> Result<(), Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    fn queue_transparent_spend_detection(
        &mut self,
        receiving_address: TransparentAddress,
        tx_ref: Self::TxRef,
        output_index: u32,
    ) -> Result<(), Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    fn queue_transparent_input_retrieval(
        &mut self,
        tx_ref: Self::TxRef,
        d_tx: &super::DecryptedTransaction<'_, Self::AccountId>,
    ) -> Result<(), Self::Error>;

    #[cfg(feature = "transparent-inputs")]
    fn queue_unmined_tx_retrieval(
        &mut self,
        d_tx: &super::DecryptedTransaction<'_, Self::AccountId>,
    ) -> Result<(), Self::Error>;

    fn delete_retrieval_queue_entries(&mut self, txid: TxId) -> Result<(), Self::Error>;
}

/// This trait provides a generalization over shielded Sapling output representations.
pub trait ReceivedSaplingOutput {
    type AccountId;

    fn index(&self) -> usize;
    fn account_id(&self) -> Self::AccountId;
    fn note(&self) -> &::sapling::Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&::sapling::Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
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

    fn index(&self) -> usize;
    fn account_id(&self) -> Self::AccountId;
    fn note(&self) -> &::orchard::note::Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&::orchard::note::Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
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
