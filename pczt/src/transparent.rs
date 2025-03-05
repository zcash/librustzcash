//! The transparent fields of a PCZT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::{
    common::{Global, Zip32Derivation},
    roles::combiner::{merge_map, merge_optional},
};

use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// PCZT fields that are specific to producing the transaction's transparent bundle (if
/// any).
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Bundle {
    #[getset(get = "pub")]
    pub(crate) inputs: Vec<Input>,
    #[getset(get = "pub")]
    pub(crate) outputs: Vec<Output>,
}

/// Information about a transparent input within a transaction.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Input {
    //
    // Transparent effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    #[getset(get = "pub")]
    pub(crate) prevout_txid: [u8; 32],
    #[getset(get = "pub")]
    pub(crate) prevout_index: u32,

    /// The sequence number of this input.
    ///
    /// - This is set by the Constructor.
    /// - If omitted, the sequence number is assumed to be the final sequence number
    ///   (`0xffffffff`).
    #[getset(get = "pub")]
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
    pub(crate) script_sig: Option<Vec<u8>>,

    // These are required by the Transaction Extractor, to derive the shielded sighash
    // needed for computing the binding signatures.
    #[getset(get = "pub")]
    pub(crate) value: u64,
    #[getset(get = "pub")]
    pub(crate) script_pubkey: Vec<u8>,

    /// The script required to spend this output, if it is P2SH.
    ///
    /// Set to `None` if this is a P2PKH output.
    pub(crate) redeem_script: Option<Vec<u8>>,

    /// A map from a pubkey to a signature created by it.
    ///
    /// - Each pubkey should appear in `script_pubkey` or `redeem_script`.
    /// - Each entry is set by a Signer, and should contain an ECDSA signature that is
    ///   valid under the corresponding pubkey.
    /// - These are required by the Spend Finalizer to assemble `script_sig`.
    #[serde_as(as = "BTreeMap<[_; 33], _>")]
    pub(crate) partial_signatures: BTreeMap<[u8; 33], Vec<u8>>,

    /// The sighash type to be used for this input.
    ///
    /// - Signers must use this sighash type to produce their signatures. Signers that
    ///   cannot produce signatures for this sighash type must not provide a signature.
    /// - Spend Finalizers must fail to finalize inputs which have signatures not matching
    ///   this sighash type.
    pub(crate) sighash_type: u8,

    /// A map from a pubkey to the BIP 32 derivation path at which its corresponding
    /// spending key can be found.
    ///
    /// - The pubkeys should appear in `script_pubkey` or `redeem_script`.
    /// - Each entry is set by an Updater.
    /// - Individual entries may be required by a Signer.
    /// - It is not required that the map include entries for all of the used pubkeys.
    ///   In particular, it is not possible to include entries for non-BIP-32 pubkeys.
    #[serde_as(as = "BTreeMap<[_; 33], _>")]
    pub(crate) bip32_derivation: BTreeMap<[u8; 33], Zip32Derivation>,

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

    /// Proprietary fields related to the note being spent.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// Information about a transparent output within a transaction.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Output {
    //
    // Transparent effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    #[getset(get = "pub")]
    pub(crate) value: u64,
    #[getset(get = "pub")]
    pub(crate) script_pubkey: Vec<u8>,

    /// The script required to spend this output, if it is P2SH.
    ///
    /// Set to `None` if this is a P2PKH output.
    pub(crate) redeem_script: Option<Vec<u8>>,

    /// A map from a pubkey to the BIP 32 derivation path at which its corresponding
    /// spending key can be found.
    ///
    /// - The pubkeys should appear in `script_pubkey` or `redeem_script`.
    /// - Each entry is set by an Updater.
    /// - Individual entries may be required by a Signer.
    /// - It is not required that the map include entries for all of the used pubkeys.
    ///   In particular, it is not possible to include entries for non-BIP-32 pubkeys.
    #[serde_as(as = "BTreeMap<[_; 33], _>")]
    pub(crate) bip32_derivation: BTreeMap<[u8; 33], Zip32Derivation>,

    /// The user-facing address to which this output is being sent, if any.
    ///
    /// - This is set by an Updater.
    /// - Signers must parse this address (if present) and confirm that it contains
    ///   `recipient` (either directly, or e.g. as a receiver within a Unified Address).
    #[getset(get = "pub")]
    pub(crate) user_address: Option<String>,

    /// Proprietary fields related to the note being spent.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(
        mut self,
        other: Self,
        self_global: &Global,
        other_global: &Global,
    ) -> Option<Self> {
        // Destructure `other` to ensure we handle everything.
        let Self {
            mut inputs,
            mut outputs,
        } = other;

        match (
            self_global.inputs_modifiable(),
            other_global.inputs_modifiable(),
            self.inputs.len().cmp(&inputs.len()),
        ) {
            // Fail if the merge would add inputs to a non-modifiable bundle.
            (false, _, Ordering::Less) | (_, false, Ordering::Greater) => return None,
            // If the other bundle has more inputs than us, move them over; these cannot
            // conflict by construction.
            (true, _, Ordering::Less) => self.inputs.extend(inputs.drain(self.inputs.len()..)),
            // Do nothing otherwise.
            (_, _, Ordering::Equal) | (_, true, Ordering::Greater) => (),
        }

        match (
            self_global.outputs_modifiable(),
            other_global.outputs_modifiable(),
            self.outputs.len().cmp(&outputs.len()),
        ) {
            // Fail if the merge would add outputs to a non-modifiable bundle.
            (false, _, Ordering::Less) | (_, false, Ordering::Greater) => return None,
            // If the other bundle has more outputs than us, move them over; these cannot
            // conflict by construction.
            (true, _, Ordering::Less) => self.outputs.extend(outputs.drain(self.outputs.len()..)),
            // Do nothing otherwise.
            (_, _, Ordering::Equal) | (_, true, Ordering::Greater) => (),
        }

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.inputs.iter_mut().zip(inputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Input {
                prevout_txid,
                prevout_index,
                sequence,
                required_time_lock_time,
                required_height_lock_time,
                script_sig,
                value,
                script_pubkey,
                redeem_script,
                partial_signatures,
                sighash_type,
                bip32_derivation,
                ripemd160_preimages,
                sha256_preimages,
                hash160_preimages,
                hash256_preimages,
                proprietary,
            } = rhs;

            if lhs.prevout_txid != prevout_txid
                || lhs.prevout_index != prevout_index
                || lhs.value != value
                || lhs.script_pubkey != script_pubkey
                || lhs.sighash_type != sighash_type
            {
                return None;
            }

            if !(merge_optional(&mut lhs.sequence, sequence)
                && merge_optional(&mut lhs.required_time_lock_time, required_time_lock_time)
                && merge_optional(
                    &mut lhs.required_height_lock_time,
                    required_height_lock_time,
                )
                && merge_optional(&mut lhs.script_sig, script_sig)
                && merge_optional(&mut lhs.redeem_script, redeem_script)
                && merge_map(&mut lhs.partial_signatures, partial_signatures)
                && merge_map(&mut lhs.bip32_derivation, bip32_derivation)
                && merge_map(&mut lhs.ripemd160_preimages, ripemd160_preimages)
                && merge_map(&mut lhs.sha256_preimages, sha256_preimages)
                && merge_map(&mut lhs.hash160_preimages, hash160_preimages)
                && merge_map(&mut lhs.hash256_preimages, hash256_preimages)
                && merge_map(&mut lhs.proprietary, proprietary))
            {
                return None;
            }
        }

        for (lhs, rhs) in self.outputs.iter_mut().zip(outputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Output {
                value,
                script_pubkey,
                redeem_script,
                bip32_derivation,
                user_address,
                proprietary,
            } = rhs;

            if lhs.value != value || lhs.script_pubkey != script_pubkey {
                return None;
            }

            if !(merge_optional(&mut lhs.redeem_script, redeem_script)
                && merge_map(&mut lhs.bip32_derivation, bip32_derivation)
                && merge_optional(&mut lhs.user_address, user_address)
                && merge_map(&mut lhs.proprietary, proprietary))
            {
                return None;
            }
        }

        Some(self)
    }
}

#[cfg(feature = "transparent")]
impl Bundle {
    pub(crate) fn into_parsed(
        self,
    ) -> Result<transparent::pczt::Bundle, transparent::pczt::ParseError> {
        let inputs = self
            .inputs
            .into_iter()
            .map(|input| {
                transparent::pczt::Input::parse(
                    input.prevout_txid,
                    input.prevout_index,
                    input.sequence,
                    input.required_time_lock_time,
                    input.required_height_lock_time,
                    input.script_sig,
                    input.value,
                    input.script_pubkey,
                    input.redeem_script,
                    input.partial_signatures,
                    input.sighash_type,
                    input
                        .bip32_derivation
                        .into_iter()
                        .map(|(k, v)| {
                            transparent::pczt::Bip32Derivation::parse(
                                v.seed_fingerprint,
                                v.derivation_path,
                            )
                            .map(|v| (k, v))
                        })
                        .collect::<Result<_, _>>()?,
                    input.ripemd160_preimages,
                    input.sha256_preimages,
                    input.hash160_preimages,
                    input.hash256_preimages,
                    input.proprietary,
                )
            })
            .collect::<Result<_, _>>()?;

        let outputs = self
            .outputs
            .into_iter()
            .map(|output| {
                transparent::pczt::Output::parse(
                    output.value,
                    output.script_pubkey,
                    output.redeem_script,
                    output
                        .bip32_derivation
                        .into_iter()
                        .map(|(k, v)| {
                            transparent::pczt::Bip32Derivation::parse(
                                v.seed_fingerprint,
                                v.derivation_path,
                            )
                            .map(|v| (k, v))
                        })
                        .collect::<Result<_, _>>()?,
                    output.user_address,
                    output.proprietary,
                )
            })
            .collect::<Result<_, _>>()?;

        transparent::pczt::Bundle::parse(inputs, outputs)
    }

    pub(crate) fn serialize_from(bundle: transparent::pczt::Bundle) -> Self {
        let inputs = bundle
            .inputs()
            .iter()
            .map(|input| Input {
                prevout_txid: (*input.prevout_txid()).into(),
                prevout_index: *input.prevout_index(),
                sequence: *input.sequence(),
                required_time_lock_time: *input.required_time_lock_time(),
                required_height_lock_time: *input.required_height_lock_time(),
                script_sig: input
                    .script_sig()
                    .as_ref()
                    .map(|script_sig| script_sig.0.clone()),
                value: input.value().into_u64(),
                script_pubkey: input.script_pubkey().0.clone(),
                redeem_script: input
                    .redeem_script()
                    .as_ref()
                    .map(|redeem_script| redeem_script.0.clone()),
                partial_signatures: input.partial_signatures().clone(),
                sighash_type: input.sighash_type().encode(),
                bip32_derivation: input
                    .bip32_derivation()
                    .iter()
                    .map(|(k, v)| {
                        (
                            *k,
                            Zip32Derivation {
                                seed_fingerprint: *v.seed_fingerprint(),
                                derivation_path: v
                                    .derivation_path()
                                    .iter()
                                    .copied()
                                    .map(u32::from)
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
                ripemd160_preimages: input.ripemd160_preimages().clone(),
                sha256_preimages: input.sha256_preimages().clone(),
                hash160_preimages: input.hash160_preimages().clone(),
                hash256_preimages: input.hash256_preimages().clone(),
                proprietary: input.proprietary().clone(),
            })
            .collect();

        let outputs = bundle
            .outputs()
            .iter()
            .map(|output| Output {
                value: output.value().into_u64(),
                script_pubkey: output.script_pubkey().0.clone(),
                redeem_script: output
                    .redeem_script()
                    .as_ref()
                    .map(|redeem_script| redeem_script.0.clone()),
                bip32_derivation: output
                    .bip32_derivation()
                    .iter()
                    .map(|(k, v)| {
                        (
                            *k,
                            Zip32Derivation {
                                seed_fingerprint: *v.seed_fingerprint(),
                                derivation_path: v
                                    .derivation_path()
                                    .iter()
                                    .copied()
                                    .map(u32::from)
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
                user_address: output.user_address().clone(),
                proprietary: output.proprietary().clone(),
            })
            .collect();

        Self { inputs, outputs }
    }
}
