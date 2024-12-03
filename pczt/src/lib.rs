//! The Partially Created Zcash Transaction (PCZT) format.
//!
//! Goal is to split up the parts of creating a transaction across distinct entities.
//! The entity roles roughly match BIP 174: Partially Signed Bitcoin Transaction Format.
//! - Creator (single entity)
//!   - Creates the base PCZT with no information about spends or outputs.
//! - Constructor (anyone can contribute)
//!   - Adds spends and outputs to the PCZT.
//!   - Before any input or output may be added, the constructor must check the
//!     `Global.tx_modifiable` field. Inputs may only be added if the Inputs Modifiable
//!     flag is True. Outputs may only be added if the Outputs Modifiable flag is True.
//!   - A single entity is likely to be both a Creator and Constructor.
//! - IO Finalizer (anyone can execute)
//!   - Sets the appropriate bits in `Global.tx_modifiable` to 0.
//!   - Updates the various bsk values using the rcv information from spends and outputs.
//! - Prover (capability holders can contribute)
//!   - Needs all private information for a single spend or output.
//!   - In practice, the Updater that adds a given spend or output will either act as
//!     the Prover themselves, or add the necessary data, offload to the Prover, and
//!     then receive back the PCZT with private data stripped and proof added.
//! - Signer (capability holders can contribute)
//!   - Needs the spend authorization randomizers to create signatures.
//!   - Needs sufficient information to verify that the proof is over the correct data,
//!     without needing to verify the proof itself.
//!   - A Signer should only need to implement:
//!     - Pedersen commitments using Jubjub / Pallas arithmetic (for note and value
//!       commitments)
//!     - BLAKE2b and BLAKE2s (and the various PRFs / CRHs they are used in)
//!     - Nullifier check (using Jubjub / Pallas arithmetic)
//!     - KDF plus note decryption (AEAD_CHACHA20_POLY1305)
//!     - SignatureHash algorithm
//!     - Signatures (RedJubjub / RedPallas)
//!     - A source of randomness.
//! - Combiner (anyone can execute)
//!   - Combines several PCZTs that represent the same transaction into a single PCZT.
//! - Spend Finalizer (anyone can execute)
//!   - Combines partial transparent signatures into `script_sig`s.
//! - Transaction Extractor (anyone can execute)
//!   - Creates bindingSig and extracts the final transaction.

pub mod roles;

mod common;
mod orchard;
mod sapling;
mod transparent;

#[cfg(feature = "zcp-builder")]
const SAPLING_TX_VERSION: u32 = 4;
const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// A partially-created Zcash transaction.
#[derive(Clone, Debug)]
pub struct Pczt {
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
