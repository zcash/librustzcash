//! APIs for batch trial decryption.

use alloc::vec::Vec; // module is alloc only
use core::iter;

use crate::{
    try_compact_note_decryption_inner, try_note_decryption_inner, BatchDomain, EphemeralKeyBytes,
    ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};

/// Trial decryption of a batch of notes with a set of recipients.
///
/// This is the batched version of [`crate::try_note_decryption`].
#[allow(clippy::type_complexity)]
pub fn try_note_decryption<D: BatchDomain, Output: ShieldedOutput<D, ENC_CIPHERTEXT_SIZE>>(
    ivks: &[D::IncomingViewingKey],
    outputs: &[(D, Output)],
) -> Vec<Option<(D::Note, D::Recipient, D::Memo)>> {
    batch_note_decryption(ivks, outputs, try_note_decryption_inner)
}

/// Trial decryption of a batch of notes for light clients with a set of recipients.
///
/// This is the batched version of [`crate::try_compact_note_decryption`].
pub fn try_compact_note_decryption<D: BatchDomain, Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>>(
    ivks: &[D::IncomingViewingKey],
    outputs: &[(D, Output)],
) -> Vec<Option<(D::Note, D::Recipient)>> {
    batch_note_decryption(ivks, outputs, try_compact_note_decryption_inner)
}

fn batch_note_decryption<D: BatchDomain, Output: ShieldedOutput<D, CS>, F, FR, const CS: usize>(
    ivks: &[D::IncomingViewingKey],
    outputs: &[(D, Output)],
    decrypt_inner: F,
) -> Vec<Option<FR>>
where
    F: Fn(&D, &D::IncomingViewingKey, &EphemeralKeyBytes, &Output, D::SymmetricKey) -> Option<FR>,
{
    // Fetch the ephemeral keys for each output and batch-parse them.
    let ephemeral_keys = D::batch_epk(outputs.iter().map(|(_, output)| output.ephemeral_key()));

    // Derive the shared secrets for all combinations of (ivk, output).
    // The scalar multiplications cannot benefit from batching.
    let items = ivks.iter().flat_map(|ivk| {
        ephemeral_keys.iter().map(move |(epk, ephemeral_key)| {
            (
                epk.as_ref().map(|epk| D::ka_agree_dec(ivk, epk)),
                ephemeral_key,
            )
        })
    });

    // Run the batch-KDF to obtain the symmetric keys from the shared secrets.
    let keys = D::batch_kdf(items);

    // Finish the trial decryption!
    ivks.iter()
        .flat_map(|ivk| {
            // Reconstruct the matrix of (ivk, output) combinations.
            iter::repeat(ivk)
                .zip(ephemeral_keys.iter())
                .zip(outputs.iter())
        })
        .zip(keys)
        .map(|(((ivk, (_, ephemeral_key)), (domain, output)), key)| {
            // The `and_then` propagates any potential rejection from `D::epk`.
            key.and_then(|key| decrypt_inner(domain, ivk, ephemeral_key, output, key))
        })
        .collect()
}
