use blake2b_simd::Hash as Blake2bHash;
use rand_core::OsRng;
use zcash_primitives::transaction::{
    components::transparent,
    sighash::{SignableInput, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE},
    sighash_v5::v5_signature_hash,
    txid::TxIdDigester,
    Authorization, TransactionData, TxDigests, TxVersion,
};
use zcash_protocol::consensus::BranchId;

use crate::{
    common::{Global, FLAG_HAS_SIGHASH_SINGLE, FLAG_INPUTS_MODIFIABLE, FLAG_OUTPUTS_MODIFIABLE},
    Pczt,
};

use super::tx_extractor::determine_lock_time;

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
        let shielded_sighash = v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts)
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
            .sign(index, &self.tx_data, &self.txid_parts, sk, &self.secp)
            .map_err(Error::TransparentSign)?;

        // Update transaction modifiability:
        // - If the Signer added a signature that does not use SIGHASH_ANYONECANPAY, the
        //   Input Modifiable flag must be set to False.
        if input.sighash_type().encode() & SIGHASH_ANYONECANPAY == 0 {
            self.global.tx_modifiable &= !FLAG_INPUTS_MODIFIABLE;
        }
        // - If the Signer added a signature that does not use SIGHASH_NONE, the Outputs
        //   Modifiable flag must be set to False.
        if (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) != SIGHASH_NONE {
            self.global.tx_modifiable &= !FLAG_OUTPUTS_MODIFIABLE;
        }
        // - If the Signer added a signature that uses SIGHASH_SINGLE, the Has SIGHASH_SINGLE
        //   flag must be set to True.
        if (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE {
            self.global.tx_modifiable |= FLAG_HAS_SIGHASH_SINGLE;
        }

        Ok(())
    }

    /// Signs the Sapling spend at the given index with the given spend authorizing key.
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

        // Check consistency of the input being signed.
        let note_from_fields = spend
            .recipient()
            .zip(spend.value().as_ref())
            .zip(spend.rseed().as_ref())
            .map(|((recipient, value), rseed)| {
                sapling::Note::from_parts(recipient, *value, *rseed)
            });

        if let Some(note) = note_from_fields {
            let tx_spend = self
                .tx_data
                .sapling_bundle()
                .expect("index checked above")
                .shielded_spends()
                .get(index)
                .expect("index checked above");

            let proof_generation_key = spend
                .proof_generation_key()
                .as_ref()
                .ok_or(Error::MissingProofGenerationKey)?;

            let nk = proof_generation_key.to_viewing_key().nk;

            let merkle_path = spend.witness().as_ref().ok_or(Error::MissingWitness)?;

            if &note.nf(&nk, merkle_path.position().into()) != tx_spend.nullifier() {
                return Err(Error::InvalidNullifier);
            }
        }

        spend
            .sign(self.shielded_sighash, ask, OsRng)
            .map_err(Error::SaplingSign)?;

        Ok(())
    }

    /// Signs the Orchard spend at the given index with the given spend authorizing key.
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

        // Check consistency of the input being signed.
        let note_from_fields = action
            .spend()
            .recipient()
            .zip(action.spend().value().as_ref())
            .zip(action.spend().rho().as_ref())
            .zip(action.spend().rseed().as_ref())
            .map(|(((recipient, value), rho), rseed)| {
                orchard::Note::from_parts(recipient, *value, *rho, *rseed)
                    .into_option()
                    .ok_or(Error::InvalidNote)
            })
            .transpose()?;

        if let Some(note) = note_from_fields {
            let tx_action = self
                .tx_data
                .orchard_bundle()
                .expect("index checked above")
                .actions()
                .get(index)
                .expect("index checked above");

            let fvk = action
                .spend()
                .fvk()
                .as_ref()
                .ok_or(Error::MissingFullViewingKey)?;

            if &note.nullifier(fvk) != tx_action.nullifier() {
                return Err(Error::InvalidNullifier);
            }
        }

        action
            .sign(self.shielded_sighash, ask, OsRng)
            .map_err(Error::OrchardSign)?;

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
        (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::Zip225),
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
        determine_lock_time(global, transparent.inputs())
            .map_err(|_| Error::IncompatibleLockTimes)?,
        global.expiry_height.into(),
        transparent_bundle,
        None,
        sapling_bundle,
        orchard_bundle,
    ))
}

pub(crate) struct EffectsOnly;

impl Authorization for EffectsOnly {
    type TransparentAuth = transparent::EffectsOnly;
    type SaplingAuth = sapling::bundle::EffectsOnly;
    type OrchardAuth = orchard::bundle::EffectsOnly;
}

/// Errors that can occur while creating signatures for a PCZT.
#[derive(Debug)]
pub enum Error {
    Global(GlobalError),
    IncompatibleLockTimes,
    InvalidIndex,
    InvalidNote,
    InvalidNullifier,
    MissingFullViewingKey,
    MissingProofGenerationKey,
    MissingWitness,
    OrchardExtract(orchard::pczt::TxExtractorError),
    OrchardParse(orchard::pczt::ParseError),
    OrchardSign(orchard::pczt::SignerError),
    SaplingExtract(sapling::pczt::TxExtractorError),
    SaplingParse(sapling::pczt::ParseError),
    SaplingSign(sapling::pczt::SignerError),
    TransparentExtract(transparent::pczt::TxExtractorError),
    TransparentParse(transparent::pczt::ParseError),
    TransparentSign(transparent::pczt::SignerError),
}

#[derive(Debug)]
pub enum GlobalError {
    UnknownConsensusBranchId,
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
}
