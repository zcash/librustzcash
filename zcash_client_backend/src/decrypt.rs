use pairing::bls12_381::Bls12;
use zcash_primitives::{
    note_encryption::{try_sapling_note_decryption, try_sapling_output_recovery, Memo},
    primitives::{Note, PaymentAddress},
    transaction::Transaction,
    zip32::ExtendedFullViewingKey,
    JUBJUB,
};

/// A decrypted shielded output.
pub struct DecryptedOutput {
    /// The index of the output within [`shielded_outputs`].
    ///
    /// [`shielded_outputs`]: zcash_primitives::transaction::TransactionData
    pub index: usize,
    /// The note within the output.
    pub note: Note<Bls12>,
    /// The address the note was sent to.
    pub to: PaymentAddress<Bls12>,
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
pub fn decrypt_transaction(
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
        let epk = match output.ephemeral_key.as_prime_order(&JUBJUB) {
            Some(p) => p,
            None => continue,
        };

        for (ivk, ovk) in &vks {
            let ((note, to, memo), outgoing) =
                match try_sapling_note_decryption(ivk, &epk, &output.cmu, &output.enc_ciphertext) {
                    Some(ret) => (ret, false),
                    None => match try_sapling_output_recovery(
                        ovk,
                        &output.cv,
                        &output.cmu,
                        &epk,
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
                to,
                memo,
                outgoing,
            })
        }
    }

    decrypted
}
