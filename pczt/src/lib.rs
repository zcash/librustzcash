//! The Partially Created Zcash Transaction (PCZT) format.
//!
//! General flow for creating a shielded transaction:
//! - Create "unsigned transaction"
//!   - In practice means deciding on the global parts of the transaction
//! - Collect each output
//!   - Proofs can be created at this time
//! - Decide on an anchor
//!   - All spends should use the same anchor for indistinguishability
//!   - In a future transaction version, all spends will be required to do so
//! - Collect each spend
//!   - Proofs can and should be created at this time
//! - Create proofs for each spend and output
//!   - Data necessary for proofs can be stripped out of the format
//! - Collect proofs
//! - Distribute collected data to signers
//!   - Signers must verify the transaction before signing, and reject if not satisfied.
//!   - This is the no-turning-back point regarding spend authorization!
//! - Collect signatures
//! - Create binding signature
//!   - The party that performs this does not need to be trusted, because each signer
//!     has verified the transaction and signed it, so the bindingSig can only be
//!     computed over the same data if a valid transaction is to be created.
//! - Extract final transaction
//!
//! Goal is to split up the parts of creating a transaction across distinct entities.
//! The entity roles roughly match BIP 174: Partially Signed Bitcoin Transaction Format.
//! - Creator
//!   - Creates the base PCZT with no information about spends or outputs.
//! - Constructor
//!   - Adds spends and outputs to the PCZT.
//!   - Before any input or output may be added, the constructor must check the
//!     PSBT_GLOBAL_TX_MODIFIABLE field. Inputs may only be added if the Inputs Modifiable
//!     flag is True. Outputs may only be added if the Outputs Modifiable flag is True.
//!   - A single entity is likely to be both a Creator and Constructor.
//! - IO Finalizer
//!   - Sets the appropriate bits in PSBT_GLOBAL_TX_MODIFIABLE to 0. (TODO fix up)
//!   - Inspects the inputs and outputs throughout the PCZT and picks a transaction
//!     version that is compatible with all of them (or returns an error).
//!   - Updates the various bsk values using the rcv information from spends and outputs.
//!   - This can happen after each spend or output is added if they are added serially.
//!     If spends and outputs are created in parallel, the IO Finalizer must act after
//!     the Combiner.
//! - Updater
//!   - Adds information necessary for subsequent entities to proceed, such as key paths
//!     for signing spends.
//! - Redactor
//!   - Removes information that is unnecessary for subsequent entities to proceed.
//!   - This can be useful e.g. when creating a transaction that has inputs from multiple
//!     independent Signers; each can receive a PCZT with just the information they need
//!     to sign, but (e.g.) not the `alpha` values for other Signers.
//! - Prover
//!   - Needs all private information for a single spend or output.
//!   - In practice, the Updater that adds a given spend or output will either act as
//!     the Prover themselves, or add the necessary data, offload to the Prover, and
//!     then receive back the PCZT with private data stripped and proof added.
//! - Signer
//!   - Needs the spend authorization randomizers to create signatures.
//!   - Needs sufficient information to verify that the proof is over the correct data.
//!     without needing to verify the proof itself.
//!   - A Signer should only need to implement:
//!     - Pedersen commitments using Jubjub arithmetic (for note and value commitments)
//!     - BLAKE2b and BLAKE2s (and the various PRFs / CRHs they are used in)
//!     - Nullifier check (using Jubjub arithmetic)
//!     - KDF plus note decryption (AEAD_CHACHA20_POLY1305)
//!     - SignatureHash algorithm
//!     - Signatures (RedJubjub)
//!     - A source of randomness.
//! - Combiner
//!   - Combines several PCZTs that represent the same transaction into a single PCZT.
//!   - Because we aren't storing the partial transaction in network format, we need to
//!     carefully define equality for PCZTs.
//!     - If we say "pczt.global must be identical" then:
//!       - If we add spends or outputs in series, we should always update bsk when adding
//!         spends or outputs, even if rcv is present.
//!       - If we add spends or outputs in parallel and then combine, we must _never_ update
//!         bsk, and then update it when we prepare for signature creation.
//!       We can't control which happens, ergo we need an IO Finalizer step.
//!     - Once every spend and output has its zkproof field set, PCZT equality MUST include
//!       the SpendDescription and OutputDescription contents being identical.
//!       - In practice enforced by creating a TransactionData / CMutableTransaction from
//!         the PCZT, with spendAuthSigs and bindingSig empty, and then enforcing equality.
//!       - This is equivalent to BIP 147's equality definition (the partial transactions
//!         must be identical).
//! - Spend Finalizer
//!   - Currently unnecessary, but when shielded multisig is implemented, this would be the
//!     entity that combines the separate signatures into a multisignature.
//! - Transaction Extractor
//!   - Creates bindingSig and extracts the final transaction.

pub mod roles;

mod common;
mod orchard;
mod sapling;
mod transparent;

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// A partially-created Zcash transaction.
#[derive(Clone)]
pub struct Pczt {
    /// The version of this PCZT format, for storage.
    version: Version,

    /// Global fields that are relevant to the transaction as a whole.
    global: common::Global,

    //
    // Protocol-specific fields.
    //
    // Unlike the `TransactionData` type in `zcash_primitives`, these are not optional.
    // This is because a PCZT does not always contain a semantically-valid transaction,
    // and there may be phases where we need to store protocol-specific metadata before
    // it has been determined whether there are protocol-specific inputs or outputs.
    //
    transparent: transparent::Bundle,
    sapling: sapling::Bundle,
    orchard: orchard::Bundle,
}

/// The defined versions of PCZT.
///
/// TODO: We might just define the version as a prefix byte included within the encoding,
/// and then permit the entire rest of the format to change arbitrarily in new versions
/// (though it would likely instead be altered via predictable diffs).
#[derive(Clone, PartialEq, Eq)]
enum Version {
    V0,
}

/// Merges two values for an optional field together.
///
/// Returns `false` if the values cannot be merged.
fn merge_optional<T: PartialEq>(lhs: &mut Option<T>, rhs: Option<T>) -> bool {
    match (&lhs, rhs) {
        // If the RHS is not present, keep the LHS.
        (_, None) => (),
        // If the LHS is not present, set it to the RHS.
        (None, Some(rhs)) => *lhs = Some(rhs),
        // If both are present and are equal, nothing to do.
        (Some(lhs), Some(rhs)) if lhs == &rhs => (),
        // If both are present and are not equal, fail. Here we differ from BIP 174.
        (Some(_), Some(_)) => return false,
    }

    // Success!
    true
}
