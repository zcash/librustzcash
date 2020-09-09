use zcash_primitives::{
    consensus,
    note_encryption::{try_sapling_note_decryption, try_sapling_output_recovery, Memo},
    primitives::{Note, PaymentAddress},
    transaction::Transaction,
    zip32::ExtendedFullViewingKey,
};

/// A decrypted shielded output.
pub struct DecryptedOutput {
    /// The index of the output within [`shielded_outputs`].
    ///
    /// [`shielded_outputs`]: zcash_primitives::transaction::TransactionData
    pub index: usize,
    /// The note within the output.
    pub note: Note,
    /// The account that decrypted the note.
    pub account: usize,
    /// The address the note was sent to.
    pub to: PaymentAddress,
    /// The memo included with the note.
    pub memo: Memo,
    /// True if this output was recovered using an [`OutgoingViewingKey`], meaning that
    /// this is a logical output of the transaction.
    ///
    /// [`OutgoingViewingKey`]: zcash_primitives::keys::OutgoingViewingKey
    pub outgoing: bool,
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`ExtendedFullViewingKey`]s.
pub fn decrypt_transaction<P: consensus::Parameters>(
    height: u32,
    tx: &Transaction,
    extfvks: &[ExtendedFullViewingKey],
) -> Vec<DecryptedOutput> {
    let mut decrypted = vec![];

    // Cache IncomingViewingKey calculation
    let vks: Vec<_> = extfvks
        .iter()
        .map(|extfvk| (extfvk.fvk.vk.ivk(), extfvk.fvk.ovk))
        .collect();

    for (index, output) in tx.shielded_outputs.iter().enumerate() {
        for (account, (ivk, ovk)) in vks.iter().enumerate() {
            let ((note, to, memo), outgoing) = match try_sapling_note_decryption::<P>(
                height,
                ivk,
                &output.ephemeral_key,
                &output.cmu,
                &output.enc_ciphertext,
            ) {
                Some(ret) => (ret, false),
                None => match try_sapling_output_recovery::<P>(
                    height,
                    ovk,
                    &output.cv,
                    &output.cmu,
                    &output.ephemeral_key,
                    &output.enc_ciphertext,
                    &output.out_ciphertext,
                ) {
                    Some(ret) => (ret, true),
                    None => continue,
                },
            };
            decrypted.push(DecryptedOutput {
                index,
                note,
                account,
                to,
                memo,
                outgoing,
            })
        }
    }

    decrypted
}
