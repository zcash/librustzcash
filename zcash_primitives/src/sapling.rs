//! Structs and constants specific to the Sapling shielded pool.

mod address;
pub mod builder;
pub mod bundle;
pub mod circuit;
pub mod constants;
pub mod group_hash;
pub mod keys;
pub mod note;
pub mod note_encryption;
pub mod pedersen_hash;
pub mod prover;
pub mod redjubjub;
mod spec;
mod tree;
pub mod util;
pub mod value;
mod verifier;
pub mod zip304;

use group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};

use constants::SPENDING_KEY_GENERATOR;

use self::redjubjub::{PrivateKey, PublicKey, Signature};

pub use address::PaymentAddress;
pub use bundle::Bundle;
pub use keys::{Diversifier, NullifierDerivingKey, ProofGenerationKey, SaplingIvk, ViewingKey};
pub use note::{nullifier::Nullifier, Note, Rseed};
pub use tree::{
    merkle_hash, CommitmentTree, IncrementalWitness, MerklePath, Node, NOTE_COMMITMENT_TREE_DEPTH,
};
pub use verifier::{BatchValidator, SaplingVerificationContext};

/// Create the spendAuthSig for a Sapling SpendDescription.
pub fn spend_sig<R: RngCore + CryptoRng>(
    ask: PrivateKey,
    ar: jubjub::Fr,
    sighash: &[u8; 32],
    rng: &mut R,
) -> Signature {
    spend_sig_internal(&ask, ar, sighash, rng)
}

pub(crate) fn spend_sig_internal<R: RngCore>(
    ask: &PrivateKey,
    ar: jubjub::Fr,
    sighash: &[u8; 32],
    rng: &mut R,
) -> Signature {
    // We compute `rsk`...
    let rsk = ask.randomize(ar);

    // We compute `rk` from there (needed for key prefixing)
    let rk = PublicKey::from_private(&rsk, SPENDING_KEY_GENERATOR);

    // Compute the signature's message for rk/spend_auth_sig
    let mut data_to_be_signed = [0u8; 64];
    data_to_be_signed[0..32].copy_from_slice(&rk.0.to_bytes());
    data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

    // Do the signing
    rsk.sign(&data_to_be_signed, rng, SPENDING_KEY_GENERATOR)
}

/// Verifies a spendAuthSig.
///
/// This only exists because the RedJubjub implementation inside `zcash_primitives` does
/// not implement key prefixing (which was added in response to a Sapling audit). This
/// will be fixed by migrating to the redjubjub crate.
pub(crate) fn verify_spend_sig(
    ak: &PublicKey,
    alpha: jubjub::Fr,
    sighash: &[u8; 32],
    sig: &Signature,
) -> bool {
    // We compute `rk` (needed for key prefixing)
    let rk = ak.randomize(alpha, SPENDING_KEY_GENERATOR);

    verify_spend_sig_internal(&rk, sighash, sig)
}

/// Verifies a spendAuthSig.
///
/// This only exists because the RedJubjub implementation inside `zcash_primitives` does
/// not implement key prefixing (which was added in response to a Sapling audit). This
/// will be fixed by migrating to the redjubjub crate.
pub(crate) fn verify_spend_sig_internal(
    rk: &PublicKey,
    sighash: &[u8; 32],
    sig: &Signature,
) -> bool {
    // Compute the signature's message for rk/spend_auth_sig
    let mut data_to_be_signed = [0u8; 64];
    data_to_be_signed[0..32].copy_from_slice(&rk.0.to_bytes());
    data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

    // Do the verifying
    rk.verify(&data_to_be_signed, sig, SPENDING_KEY_GENERATOR)
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    pub use super::{
        address::testing::arb_payment_address, keys::testing::arb_incoming_viewing_key,
        note::testing::arb_note, tree::testing::arb_node,
    };
}
