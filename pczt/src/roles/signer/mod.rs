//! The Signer role (capability holders can contribute).
//!
//! - Needs the spend authorization randomizers to create signatures.
//! - Needs sufficient information to verify that the proof is over the correct data,
//!   without needing to verify the proof itself.
//! - A Signer should only need to implement:
//!   - Pedersen commitments using Jubjub / Pallas arithmetic (for note and value
//!     commitments)
//!   - BLAKE2b and BLAKE2s (and the various PRFs / CRHs they are used in)
//!   - Nullifier check (using Jubjub / Pallas arithmetic)
//!   - KDF plus note decryption (AEAD_CHACHA20_POLY1305)
//!   - SignatureHash algorithm
//!   - Signatures (RedJubjub / RedPallas)
//!   - A source of randomness.

use blake2b_simd::Hash as Blake2bHash;
use orchard::primitives::redpallas;
use rand_core::OsRng;

use ::transparent::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
use zcash_primitives::transaction::{
    Authorization, TransactionData, TxDigests, TxVersion, sighash::SignableInput,
    sighash_v5::v5_signature_hash, txid::TxIdDigester,
};
use zcash_protocol::consensus::BranchId;
#[cfg(all(
    any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
    feature = "zip-233"
))]
use zcash_protocol::value::Zatoshis;

use crate::{
    Pczt,
    common::{
        FLAG_HAS_SIGHASH_SINGLE, FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
        FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE, Global,
    },
};

use crate::common::determine_lock_time;

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

pub struct Signer {
    global: Global,
    transparent: transparent::pczt::Bundle,
    sapling: sapling::pczt::Bundle,
    orchard: orchard::pczt::Bundle,
    /// Cached across multiple signatures.
    tx_data: TransactionData<EffectsOnly>,
    txid_parts: TxDigests<Blake2bHash>,
    shielded_sighash: [u8; 32],
    secp: secp256k1::Secp256k1<secp256k1::All>,
}

impl Signer {
    /// Instantiates the Signer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Result<Self, Error> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = pczt;

        let transparent = transparent.into_parsed().map_err(Error::TransparentParse)?;
        let sapling = sapling.into_parsed().map_err(Error::SaplingParse)?;
        let orchard = orchard.into_parsed().map_err(Error::OrchardParse)?;

        let tx_data = pczt_to_tx_data(&global, &transparent, &sapling, &orchard)?;
        let txid_parts = tx_data.digest(TxIdDigester);

        // TODO: Pick sighash based on tx version.
        match (global.tx_version, global.version_group_id) {
            (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(()),
            (version, version_group_id) => Err(Error::Global(GlobalError::UnsupportedTxVersion {
                version,
                version_group_id,
            })),
        }?;
        let shielded_sighash = sighash(&tx_data, &SignableInput::Shielded, &txid_parts);

        Ok(Self {
            global,
            transparent,
            sapling,
            orchard,
            tx_data,
            txid_parts,
            shielded_sighash,
            secp: secp256k1::Secp256k1::new(),
        })
    }

    /// Calculates the signature digest that must be signed to authorize shielded spends.
    ///
    /// This can be used to produce a signature externally suitable for passing to e.g.
    /// [`Self::apply_orchard_signature`].}
    pub fn shielded_sighash(&self) -> [u8; 32] {
        self.shielded_sighash
    }

    /// Calculates the signature digest that must be signed to authorize the transparent
    /// spend at the given index.
    ///
    /// This can be used to produce a signature externally suitable for passing to e.g.
    /// [`Self::append_transparent_signature`].}
    ///
    /// Returns an error if `index` is invalid for this PCZT.
    pub fn transparent_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        let input = self
            .transparent
            .inputs()
            .get(index)
            .ok_or(Error::InvalidIndex)?;

        input.with_signable_input(index, |signable_input| {
            Ok(sighash(
                &self.tx_data,
                &SignableInput::Transparent(signable_input),
                &self.txid_parts,
            ))
        })
    }

    /// Signs the transparent spend at the given index with the given spending key.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn sign_transparent(
        &mut self,
        index: usize,
        sk: &secp256k1::SecretKey,
    ) -> Result<(), Error> {
        self.generate_or_append_transparent_signature(index, |input, tx_data, txid_parts, secp| {
            input.sign(
                index,
                |input| sighash(tx_data, &SignableInput::Transparent(input), txid_parts),
                sk,
                secp,
            )
        })
    }

    /// Appends the given signature to the transparent spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn append_transparent_signature(
        &mut self,
        index: usize,
        signature: secp256k1::ecdsa::Signature,
    ) -> Result<(), Error> {
        self.generate_or_append_transparent_signature(index, |input, tx_data, txid_parts, secp| {
            input.append_signature(
                index,
                |input| sighash(tx_data, &SignableInput::Transparent(input), txid_parts),
                signature,
                secp,
            )
        })
    }

    fn generate_or_append_transparent_signature<F>(
        &mut self,
        index: usize,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(
            &mut transparent::pczt::Input,
            &TransactionData<EffectsOnly>,
            &TxDigests<Blake2bHash>,
            &secp256k1::Secp256k1<secp256k1::All>,
        ) -> Result<(), transparent::pczt::SignerError>,
    {
        let input = self
            .transparent
            .inputs_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed.
        // TODO

        // Generate or apply the signature.
        f(input, &self.tx_data, &self.txid_parts, &self.secp).map_err(Error::TransparentSign)?;

        // Update transaction modifiability:
        // - If the Signer added a signature that does not use `SIGHASH_ANYONECANPAY`, the
        //   Transparent Inputs Modifiable Flag must be set to False (because the
        //   signature commits to all inputs, not just the one at `index`).
        if input.sighash_type().encode() & SIGHASH_ANYONECANPAY == 0 {
            self.global.tx_modifiable &= !FLAG_TRANSPARENT_INPUTS_MODIFIABLE;
        }
        // - If the Signer added a signature that does not use `SIGHASH_NONE`, the
        //   Transparent Outputs Modifiable Flag must be set to False. Note that this
        //   applies to `SIGHASH_SINGLE` because we could otherwise remove the output at
        //   `index`, which would not remove the signature.
        if (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) != SIGHASH_NONE {
            self.global.tx_modifiable &= !FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE;
        }
        // - If the Signer added a signature that uses `SIGHASH_SINGLE`, the Has
        //   `SIGHASH_SINGLE` flag must be set to True.
        if (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE {
            self.global.tx_modifiable |= FLAG_HAS_SIGHASH_SINGLE;
        }
        // - Always set the Shielded Modifiable Flag to False.
        self.global.tx_modifiable &= !FLAG_SHIELDED_MODIFIABLE;

        Ok(())
    }

    /// Signs the Sapling spend at the given index with the given spend authorizing key.
    ///
    /// Requires the spend's `proof_generation_key` field to be set (because the API does
    /// not take an FVK).
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn sign_sapling(
        &mut self,
        index: usize,
        ask: &sapling::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_sapling_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, OsRng)
        })
    }

    /// Applies the given signature to the Sapling spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn apply_sapling_signature(
        &mut self,
        index: usize,
        signature: redjubjub::Signature<redjubjub::SpendAuth>,
    ) -> Result<(), Error> {
        self.generate_or_apply_sapling_signature(index, |spend, shielded_sighash| {
            spend.apply_signature(shielded_sighash, signature)
        })
    }

    fn generate_or_apply_sapling_signature<F>(&mut self, index: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut sapling::pczt::Spend, [u8; 32]) -> Result<(), sapling::pczt::SignerError>,
    {
        let spend = self
            .sapling
            .spends_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed if we have its note components.
        match spend.verify_nullifier(None) {
            Err(
                sapling::pczt::VerifyError::MissingRecipient
                | sapling::pczt::VerifyError::MissingValue
                | sapling::pczt::VerifyError::MissingRandomSeed,
            ) => Ok(()),
            r => r,
        }
        .map_err(Error::SaplingVerify)?;

        // Generate or apply the signature.
        f(spend, self.shielded_sighash).map_err(Error::SaplingSign)?;

        // Update transaction modifiability: all transaction effects have been committed
        // to by the signature.
        self.global.tx_modifiable &= !(FLAG_TRANSPARENT_INPUTS_MODIFIABLE
            | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
            | FLAG_SHIELDED_MODIFIABLE);

        Ok(())
    }

    /// Signs the Orchard spend at the given index with the given spend authorizing key.
    ///
    /// Requires the spend's `fvk` field to be set (because the API does not take an FVK).
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn sign_orchard(
        &mut self,
        index: usize,
        ask: &orchard::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_orchard_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, OsRng)
        })
    }

    /// Applies the given signature to the Orchard spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn apply_orchard_signature(
        &mut self,
        index: usize,
        signature: redpallas::Signature<redpallas::SpendAuth>,
    ) -> Result<(), Error> {
        self.generate_or_apply_orchard_signature(index, |action, shielded_sighash| {
            action.apply_signature(shielded_sighash, signature)
        })
    }

    fn generate_or_apply_orchard_signature<F>(&mut self, index: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut orchard::pczt::Action, [u8; 32]) -> Result<(), orchard::pczt::SignerError>,
    {
        let action = self
            .orchard
            .actions_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed if we have its note components.
        match action.spend().verify_nullifier(None) {
            Err(
                orchard::pczt::VerifyError::MissingRecipient
                | orchard::pczt::VerifyError::MissingValue
                | orchard::pczt::VerifyError::MissingRho
                | orchard::pczt::VerifyError::MissingRandomSeed,
            ) => Ok(()),
            r => r,
        }
        .map_err(Error::OrchardVerify)?;

        // Generate or apply the signature.
        f(action, self.shielded_sighash).map_err(Error::OrchardSign)?;

        // Update transaction modifiability: all transaction effects have been committed
        // to by the signature.
        self.global.tx_modifiable &= !(FLAG_TRANSPARENT_INPUTS_MODIFIABLE
            | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
            | FLAG_SHIELDED_MODIFIABLE);

        Ok(())
    }

    /// Finishes the Signer role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        Pczt {
            global: self.global,
            transparent: crate::transparent::Bundle::serialize_from(self.transparent),
            sapling: crate::sapling::Bundle::serialize_from(self.sapling),
            orchard: crate::orchard::Bundle::serialize_from(self.orchard),
        }
    }
}

/// Extracts an unauthorized `TransactionData` from the PCZT.
///
/// We don't care about existing proofs or signatures here, because they do not affect the
/// sighash; we only want the effects of the transaction.
pub(crate) fn pczt_to_tx_data(
    global: &Global,
    transparent: &transparent::pczt::Bundle,
    sapling: &sapling::pczt::Bundle,
    orchard: &orchard::pczt::Bundle,
) -> Result<TransactionData<EffectsOnly>, Error> {
    let version = match (global.tx_version, global.version_group_id) {
        (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::V5),
        (version, version_group_id) => Err(Error::Global(GlobalError::UnsupportedTxVersion {
            version,
            version_group_id,
        })),
    }?;

    let consensus_branch_id = BranchId::try_from(global.consensus_branch_id)
        .map_err(|_| Error::Global(GlobalError::UnknownConsensusBranchId))?;

    let transparent_bundle = transparent
        .extract_effects()
        .map_err(Error::TransparentExtract)?;

    let sapling_bundle = sapling.extract_effects().map_err(Error::SaplingExtract)?;

    let orchard_bundle = orchard.extract_effects().map_err(Error::OrchardExtract)?;

    Ok(TransactionData::from_parts(
        version,
        consensus_branch_id,
        determine_lock_time(global, transparent.inputs()).ok_or(Error::IncompatibleLockTimes)?,
        global.expiry_height.into(),
        #[cfg(all(
            any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
            feature = "zip-233"
        ))]
        Zatoshis::ZERO,
        transparent_bundle,
        None,
        sapling_bundle,
        orchard_bundle,
    ))
}

pub struct EffectsOnly;

impl Authorization for EffectsOnly {
    type TransparentAuth = transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling::bundle::EffectsOnly;
    type OrchardAuth = orchard::bundle::EffectsOnly;
    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = core::convert::Infallible;
}

/// Helper to produce the correct sighash for a PCZT.
fn sighash(
    tx_data: &TransactionData<EffectsOnly>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> [u8; 32] {
    v5_signature_hash(tx_data, signable_input, txid_parts)
        .as_ref()
        .try_into()
        .expect("correct length")
}

/// Errors that can occur while creating signatures for a PCZT.
#[derive(Debug)]
pub enum Error {
    Global(GlobalError),
    IncompatibleLockTimes,
    InvalidIndex,
    OrchardExtract(orchard::pczt::TxExtractorError),
    OrchardParse(orchard::pczt::ParseError),
    OrchardSign(orchard::pczt::SignerError),
    OrchardVerify(orchard::pczt::VerifyError),
    SaplingExtract(sapling::pczt::TxExtractorError),
    SaplingParse(sapling::pczt::ParseError),
    SaplingSign(sapling::pczt::SignerError),
    SaplingVerify(sapling::pczt::VerifyError),
    TransparentExtract(transparent::pczt::TxExtractorError),
    TransparentParse(transparent::pczt::ParseError),
    TransparentSign(transparent::pczt::SignerError),
}

#[derive(Debug)]
pub enum GlobalError {
    UnknownConsensusBranchId,
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
}
