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
use rand_core::OsRng;

use ::transparent::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
use zcash_primitives::transaction::{
    sighash::SignableInput, sighash_v5::v5_signature_hash, txid::TxIdDigester, Authorization,
    OrchardBundle, TransactionData, TxDigests, TxVersion,
};
use zcash_protocol::consensus::BranchId;
#[cfg(all(
    any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
    feature = "zip-233"
))]
use zcash_protocol::value::Zatoshis;

use crate::{
    common::{
        Global, FLAG_HAS_SIGHASH_SINGLE, FLAG_SHIELDED_MODIFIABLE,
        FLAG_TRANSPARENT_INPUTS_MODIFIABLE, FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE,
    },
    Pczt,
};

use crate::common::determine_lock_time;

#[cfg(zcash_unstable = "nu7")]
use {
    zcash_primitives::transaction::sighash_v6::v6_signature_hash,
    zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID},
};

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
    secp: secp256k1::Secp256k1<secp256k1::SignOnly>,
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
        let shielded_sighash = match (global.tx_version, global.version_group_id) {
            (V5_TX_VERSION, V5_VERSION_GROUP_ID) => {
                v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts)
            }
            #[cfg(zcash_unstable = "nu7")]
            (V6_TX_VERSION, V6_VERSION_GROUP_ID) => {
                v6_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts)
            }
            (version, version_group_id) => {
                return Err(Error::Global(GlobalError::UnsupportedTxVersion {
                    version,
                    version_group_id,
                }))
            }
        }
        .as_ref()
        .try_into()
        .expect("correct length");

        Ok(Self {
            global,
            transparent,
            sapling,
            orchard,
            tx_data,
            txid_parts,
            shielded_sighash,
            secp: secp256k1::Secp256k1::signing_only(),
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
        let input = self
            .transparent
            .inputs_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed.
        // TODO

        input
            .sign(
                index,
                |input| {
                    match self.tx_data.version() {
                        TxVersion::V5 => v5_signature_hash(
                            &self.tx_data,
                            &SignableInput::Transparent(input),
                            &self.txid_parts,
                        ),
                        #[cfg(zcash_unstable = "nu7")]
                        TxVersion::V6 => v6_signature_hash(
                            &self.tx_data,
                            &SignableInput::Transparent(input),
                            &self.txid_parts,
                        ),
                        _ => panic!("unsupported tx version"),
                    }
                    .as_ref()
                    .try_into()
                    .unwrap()
                },
                sk,
                &self.secp,
            )
            .map_err(Error::TransparentSign)?;

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

        spend
            .sign(self.shielded_sighash, ask, OsRng)
            .map_err(Error::SaplingSign)?;

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

        action
            .sign(self.shielded_sighash, ask, OsRng)
            .map_err(Error::OrchardSign)?;

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
        #[cfg(zcash_unstable = "nu7")]
        (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(TxVersion::V6),
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

    let orchard_bundle = match version {
        TxVersion::V5 => orchard
            .extract_effects()
            .map_err(Error::OrchardExtract)?
            .map(OrchardBundle::OrchardVanilla),
        #[cfg(zcash_unstable = "nu7")]
        TxVersion::V6 => orchard
            .extract_effects()
            .map_err(Error::OrchardExtract)?
            .map(OrchardBundle::OrchardZSA),
        _ => {
            return Err(Error::Global(GlobalError::UnsupportedTxVersion {
                version: global.tx_version,
                version_group_id: global.version_group_id,
            }));
        }
    };

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
        #[cfg(zcash_unstable = "nu7")]
        None,
    ))
}

pub struct EffectsOnly;

impl Authorization for EffectsOnly {
    type TransparentAuth = transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling::bundle::EffectsOnly;
    type OrchardAuth = orchard::bundle::EffectsOnly;
    #[cfg(zcash_unstable = "nu7")]
    type IssueAuth = orchard::issuance::EffectsOnly;
    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = core::convert::Infallible;
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
