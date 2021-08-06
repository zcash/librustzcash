//! APIs for batch trial decryption.

use std::iter;

use crate::{
    try_compact_note_decryption_inner, try_note_decryption_inner, Domain, EphemeralKeyBytes,
    ShieldedOutput,
};

/// Trial decryption of a batch of notes with a set of recipients.
///
/// This is the batched version of [`zcash_note_encryption::try_note_decryption`].
pub fn try_note_decryption<D: Domain, Output: ShieldedOutput<D>>(
    ivks: &[D::IncomingViewingKey],
    outputs: &[(D, Output)],
) -> Vec<Option<(D::Note, D::Recipient, D::Memo)>> {
    batch_note_decryption(ivks, outputs, try_note_decryption_inner)
}

/// Trial decryption of a batch of notes for light clients with a set of recipients.
///
/// This is the batched version of [`zcash_note_encryption::try_compact_note_decryption`].
pub fn try_compact_note_decryption<D: Domain, Output: ShieldedOutput<D>>(
    ivks: &[D::IncomingViewingKey],
    outputs: &[(D, Output)],
) -> Vec<Option<(D::Note, D::Recipient)>> {
    batch_note_decryption(ivks, outputs, try_compact_note_decryption_inner)
}

fn batch_note_decryption<D: Domain, Output: ShieldedOutput<D>, F, FR>(
    ivks: &[D::IncomingViewingKey],
    outputs: &[(D, Output)],
    decrypt_inner: F,
) -> Vec<Option<FR>>
where
    F: Fn(&D, &D::IncomingViewingKey, &EphemeralKeyBytes, &Output, D::SymmetricKey) -> Option<FR>,
{
    // Fetch the ephemeral keys for each output.
    let ephemeral_keys: Vec<_> = outputs
        .iter()
        .map(|(_, output)| output.ephemeral_key())
        .collect();

    // Derive the shared secrets for all combinations of (ivk, output).
    // None of this work can benefit from batching.
    let items = ivks.iter().flat_map(|ivk| {
        ephemeral_keys.iter().map(move |ephemeral_key| {
            (
                D::epk(ephemeral_key).map(|epk| D::ka_agree_dec(ivk, &epk)),
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
        .map(|(((ivk, ephemeral_key), (domain, output)), key)| {
            // The `and_then` propagates any potential rejection from `D::epk`.
            key.and_then(|key| decrypt_inner(domain, ivk, ephemeral_key, output, key))
        })
        .collect()
}
