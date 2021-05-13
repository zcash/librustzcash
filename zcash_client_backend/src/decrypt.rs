use std::collections::HashMap;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    sapling::{
        note_encryption::{try_sapling_note_decryption, try_sapling_output_recovery},
        Note, PaymentAddress,
    },
    transaction::Transaction,
    zip32::ExtendedFullViewingKey,
};

use crate::wallet::AccountId;

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
    /// [`OutgoingViewingKey`]: zcash_primitives::sapling::keys::OutgoingViewingKey
    pub outgoing: bool,
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`ExtendedFullViewingKey`]s.
pub fn decrypt_transaction<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    tx: &Transaction,
    extfvks: &HashMap<AccountId, ExtendedFullViewingKey>,
) -> Vec<DecryptedOutput> {
    let mut decrypted = vec![];

    if let Some(bundle) = tx.sapling_bundle() {
        for (account, extfvk) in extfvks.iter() {
            let ivk = extfvk.fvk.vk.ivk();
            let ovk = extfvk.fvk.ovk;

            for (index, output) in bundle.shielded_outputs.iter().enumerate() {
                let ((note, to, memo), outgoing) =
                    match try_sapling_note_decryption(params, height, &ivk, output) {
                        Some(ret) => (ret, false),
                        None => match try_sapling_output_recovery(params, height, &ovk, output) {
                            Some(ret) => (ret, true),
                            None => continue,
                        },
                    };

                decrypted.push(DecryptedOutput {
                    index,
                    note,
                    account: *account,
                    to,
                    memo,
                    outgoing,
                })
            }
        }
    }

    decrypted
}
