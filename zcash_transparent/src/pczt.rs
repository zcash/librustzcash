//! PCZT support for transparent Zcash.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use bip32::ChildNumber;
use getset::Getters;
use zcash_protocol::{value::Zatoshis, TxId};

use crate::{
    address::Script,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
    sighash::SighashType,
};

mod parse;
pub use parse::ParseError;

mod verify;
pub use verify::VerifyError;

mod updater;
pub use updater::{InputUpdater, OutputUpdater, Updater, UpdaterError};

#[cfg(feature = "transparent-inputs")]
mod signer;
#[cfg(feature = "transparent-inputs")]
pub use signer::SignerError;

mod spend_finalizer;
pub use spend_finalizer::SpendFinalizerError;

mod tx_extractor;
pub use tx_extractor::{TxExtractorError, Unbound};

/// PCZT fields that are specific to producing the transaction's transparent bundle (if
/// any).
///
/// This struct is for representing Sapling in a partially-created transaction. If you
/// have a fully-created transaction, use [the regular `Bundle` struct].
///
/// [the regular `Bundle` struct]: crate::bundle::Bundle
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct Bundle {
    /// The transparent inputs in this bundle.
    ///
    /// Entries are added by the Constructor, and modified by an Updater, IO Finalizer,
    /// Signer, Combiner, or Spend Finalizer.
    pub(crate) inputs: Vec<Input>,

    /// The transparent outputs in this bundle.
    ///
    /// Entries are added by the Constructor, and modified by an Updater, IO Finalizer,
    /// Signer, Combiner, or Spend Finalizer.
    pub(crate) outputs: Vec<Output>,
}

impl Bundle {
    /// Returns a mutable reference to the inputs in this bundle.
    ///
    /// This is used by Signers to apply signatures with [`Input::sign`].
    pub fn inputs_mut(&mut self) -> &mut [Input] {
        &mut self.inputs
    }
}

/// Information about a transparent spend within a transaction.
///
/// This struct is for representing transparent spends in a partially-created transaction.
/// If you have a fully-created transaction, use [the regular `TxIn` struct].
///
/// [the regular `TxIn` struct]: crate::bundle::TxIn
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct Input {
    /// The ID of the previous transaction containing the transparent coin being spent by
    /// this input.
    pub(crate) prevout_txid: TxId,

    /// The index of the entry in the `vout` field of the previous transaction containing
    /// the transparent coin being spent by this input.
    pub(crate) prevout_index: u32,

    /// The sequence number of this input.
    ///
    /// - This is set by the Constructor.
    /// - If omitted, the sequence number is assumed to be the final sequence number
    ///   (`0xffffffff`).
    pub(crate) sequence: Option<u32>,

    /// The minimum Unix timstamp that this input requires to be set as the transaction's
    /// lock time.
    ///
    /// - This is set by the Constructor.
    /// - This must be greater than or equal to 500000000.
    pub(crate) required_time_lock_time: Option<u32>,

    /// The minimum block height that this input requires to be set as the transaction's
    /// lock time.
    ///
    /// - This is set by the Constructor.
    /// - This must be greater than 0 and less than 500000000.
    pub(crate) required_height_lock_time: Option<u32>,

    /// A satisfying witness for the `script_pubkey` of the input being spent.
    ///
    /// This is set by the Spend Finalizer.
    pub(crate) script_sig: Option<Script>,

    /// The value of the input being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the IO Finalizer and Transaction Extractor, to derive the
    ///   shielded sighash needed for computing the binding signatures.
    pub(crate) value: Zatoshis,

    /// The `script_pubkey` of the input being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the IO Finalizer and Transaction Extractor, to derive the
    ///   shielded sighash needed for computing the binding signatures.
    pub(crate) script_pubkey: Script,

    /// The script required to spend this output, if it is P2SH.
    ///
    /// Set to `None` if this is a P2PKH output.
    pub(crate) redeem_script: Option<Script>,

    /// A map from a pubkey to a signature created by it.
    ///
    /// - Each pubkey should appear in `script_pubkey` or `redeem_script`.
    /// - Each entry is set by a Signer, and should contain an ECDSA signature that is
    ///   valid under the corresponding pubkey.
    /// - These are required by the Spend Finalizer to assemble `script_sig`.
    pub(crate) partial_signatures: BTreeMap<[u8; 33], Vec<u8>>,

    /// The sighash type to be used for this input.
    ///
    /// - Signers must use this sighash type to produce their signatures. Signers that
    ///   cannot produce signatures for this sighash type must not provide a signature.
    /// - Spend Finalizers must fail to finalize inputs which have signatures that do not
    ///   match this sighash type.
    pub(crate) sighash_type: SighashType,

    /// A map from a pubkey to the BIP 32 derivation path at which its corresponding
    /// spending key can be found.
    ///
    /// - The pubkeys should appear in `script_pubkey` or `redeem_script`.
    /// - Each entry is set by an Updater.
    /// - Individual entries may be required by a Signer.
    /// - It is not required that the map include entries for all of the used pubkeys.
    ///   In particular, it is not possible to include entries for non-BIP-32 pubkeys.
    pub(crate) bip32_derivation: BTreeMap<[u8; 33], Bip32Derivation>,

    /// Mappings of the form `key = RIPEMD160(value)`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) ripemd160_preimages: BTreeMap<[u8; 20], Vec<u8>>,

    /// Mappings of the form `key = SHA256(value)`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) sha256_preimages: BTreeMap<[u8; 32], Vec<u8>>,

    /// Mappings of the form `key = RIPEMD160(SHA256(value))`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) hash160_preimages: BTreeMap<[u8; 20], Vec<u8>>,

    /// Mappings of the form `key = SHA256(SHA256(value))`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) hash256_preimages: BTreeMap<[u8; 32], Vec<u8>>,

    /// Proprietary fields related to the transparent coin being spent.
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// Information about a transparent output within a transaction.
///
/// This struct is for representing transparent outputs in a partially-created
/// transaction. If you have a fully-created transaction, use
/// [the regular `TxOut` struct].
///
/// [the regular `TxOut` struct]: crate::bundle::TxOut
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct Output {
    /// The value of the output.
    pub(crate) value: Zatoshis,

    /// The script constraining how spending of this output must be authorized.
    pub(crate) script_pubkey: Script,

    /// The script required to spend this output, if it is P2SH.
    ///
    /// Set to `None` if this is a P2PKH output, or a P2SH with an unknown redeem script.
    pub(crate) redeem_script: Option<Script>,

    /// A map from a pubkey to the BIP 32 derivation path at which its corresponding
    /// spending key can be found.
    ///
    /// - The pubkeys should appear in `script_pubkey` or `redeem_script`.
    /// - Each entry is set by an Updater.
    /// - Individual entries may be required by a Signer.
    /// - It is not required that the map include entries for all of the used pubkeys.
    ///   In particular, it is not possible to include entries for non-BIP-32 pubkeys.
    pub(crate) bip32_derivation: BTreeMap<[u8; 33], Bip32Derivation>,

    /// The user-facing address to which this output is being sent, if any.
    ///
    /// - This is set by an Updater.
    /// - Signers must parse this address (if present) and confirm that it contains
    ///   `recipient` (either directly, or e.g. as a receiver within a Unified Address).
    pub(crate) user_address: Option<String>,

    /// Proprietary fields related to the transparent coin being created.
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// The BIP 32 derivation path at which a key can be found.
#[derive(Debug, Getters, PartialEq, Eq)]
#[getset(get = "pub")]
pub struct Bip32Derivation {
    /// The [ZIP 32 seed fingerprint](https://zips.z.cash/zip-0032#seed-fingerprints).
    seed_fingerprint: [u8; 32],

    /// The sequence of indices corresponding to the HD path.
    derivation_path: Vec<ChildNumber>,
}

impl Bip32Derivation {
    /// Extracts the BIP 44 account index, scope, and address index from this derivation
    /// path.
    ///
    /// Returns `None` if the seed fingerprints don't match, or if this is a non-standard
    /// derivation path.
    pub fn extract_bip_44_fields(
        &self,
        seed_fp: &zip32::fingerprint::SeedFingerprint,
        expected_coin_type: ChildNumber,
    ) -> Option<(zip32::AccountId, TransparentKeyScope, NonHardenedChildIndex)> {
        if self.seed_fingerprint == seed_fp.to_bytes() {
            match &self.derivation_path[..] {
                [purpose, coin_type, account_index, scope, address_index]
                    if purpose == &ChildNumber(44 | ChildNumber::HARDENED_FLAG)
                        && coin_type.is_hardened()
                        && coin_type == &expected_coin_type
                        && account_index.is_hardened()
                        && !scope.is_hardened()
                        && !address_index.is_hardened() =>
                {
                    let account_index = zip32::AccountId::try_from(account_index.index())
                        .expect("account_index is hardened");

                    let scope =
                        TransparentKeyScope::custom(scope.index()).expect("scope is not hardened");

                    let address_index = NonHardenedChildIndex::from_index(address_index.index())
                        .expect("address_index is not hardened");

                    Some((account_index, scope, address_index))
                }
                _ => None,
            }
        } else {
            None
        }
    }
}
