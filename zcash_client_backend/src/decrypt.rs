use std::collections::HashMap;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    sapling::{
        note_encryption::{
            try_sapling_note_decryption, try_sapling_output_recovery, PreparedIncomingViewingKey,
        },
        Note, PaymentAddress,
    },
    transaction::Transaction,
    zip32::{AccountId, Scope},
};

use crate::keys::UnifiedFullViewingKey;

/// An enumeration of the possible relationships a TXO can have to the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferType {
    /// The transfer was received on one of the wallet's external addresses.
    Incoming,
    /// The transfer was received on one of the wallet's internal-only addresses.
    WalletInternal,
    /// The transfer was decrypted using one of the wallet's outgoing viewing keys.
    Outgoing,
}

/// A decrypted shielded output.
pub struct DecryptedOutput {
    /// The index of the output within [`shielded_outputs`].
    ///
    /// [`shielded_outputs`]: zcash_primitives::transaction::TransactionData
    pub index: usize,
    /// The note within the output.
    pub note: Note,
    /// The account that decrypted the note.
    pub account: AccountId,
    /// The address the note was sent to.
    pub to: PaymentAddress,
    /// The memo bytes included with the note.
    pub memo: MemoBytes,
    /// True if this output was recovered using an [`OutgoingViewingKey`], meaning that
    /// this is a logical output of the transaction.
    ///
    /// [`OutgoingViewingKey`]: zcash_primitives::keys::OutgoingViewingKey
    pub transfer_type: TransferType,
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`UnifiedFullViewingKey`]s.
pub fn decrypt_transaction<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    tx: &Transaction,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> Vec<DecryptedOutput> {
    let mut decrypted = vec![];

    if let Some(bundle) = tx.sapling_bundle() {
        for (account, ufvk) in ufvks.iter() {
            if let Some(dfvk) = ufvk.sapling() {
                let ivk_external = PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External));
                let ivk_internal = PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));
                let ovk = dfvk.fvk().ovk;

                for (index, output) in bundle.shielded_outputs.iter().enumerate() {
                    let decryption_result =
                        try_sapling_note_decryption(params, height, &ivk_external, output)
                            .map(|ret| (ret, TransferType::Incoming))
                            .or_else(|| {
                                try_sapling_note_decryption(params, height, &ivk_internal, output)
                                    .map(|ret| (ret, TransferType::WalletInternal))
                            })
                            .or_else(|| {
                                try_sapling_output_recovery(params, height, &ovk, output)
                                    .map(|ret| (ret, TransferType::Outgoing))
                            });

                    let ((note, to, memo), transfer_type) = match decryption_result {
                        Some(result) => result,
                        None => {
                            continue;
                        }
                    };

                    decrypted.push(DecryptedOutput {
                        index,
                        note,
                        account: *account,
                        to,
                        memo,
                        transfer_type,
                    })
                }
            }
        }
    }

    decrypted
}
