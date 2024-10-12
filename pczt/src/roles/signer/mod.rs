use orchard::primitives::redpallas;
use rand_core::OsRng;
use zcash_primitives::{
    legacy::Script,
    transaction::{
        components::transparent,
        sighash::{SignableInput, TransparentAuthorizingContext},
        sighash_v5::v5_signature_hash,
        txid::TxIdDigester,
        Authorization, TransactionData, TxVersion,
    },
};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};

use crate::{IgnoreMissing, Pczt};

use super::tx_extractor::determine_lock_time;

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

pub struct Signer {
    pczt: Pczt,
    /// Cached across multiple signatures.
    tx_data: TransactionData<EffectsOnly>,
}

impl Signer {
    /// Instantiates the Signer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Result<Self, Error> {
        let tx_data = pczt_to_tx_data(&pczt)?;
        Ok(Self { pczt, tx_data })
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
            .pczt
            .sapling
            .spends
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed.
        let note_from_fields = spend
            .note_from_fields()
            .ignore_missing()
            .map_err(Error::Sapling)?;

        if let Some(note) = note_from_fields {
            let tx_spend = self
                .tx_data
                .sapling_bundle()
                .expect("index checked above")
                .shielded_spends()
                .get(index)
                .expect("index checked above");

            let proof_generation_key = spend
                .proof_generation_key_from_field()
                .map_err(Error::Sapling)?;

            let nk = proof_generation_key.to_viewing_key().nk;

            let merkle_path = spend.witness_from_field().map_err(Error::Sapling)?;

            if &note.nf(&nk, merkle_path.position().into()) != tx_spend.nullifier() {
                return Err(Error::InvalidNullifier);
            }
        }

        let alpha = spend.alpha_from_field().map_err(Error::Sapling)?;

        let rsk = ask.randomize(&alpha);
        let rk = redjubjub::VerificationKey::from(&rsk);

        let txid_parts = self.tx_data.digest(TxIdDigester);
        let shielded_sighash =
            v5_signature_hash(&self.tx_data, &SignableInput::Shielded, &txid_parts);

        if spend.rk == <[u8; 32]>::from(rk) {
            let spend_auth_sig = rsk.sign(OsRng, shielded_sighash.as_ref());
            spend.spend_auth_sig = Some(spend_auth_sig.into());
            Ok(())
        } else {
            Err(Error::WrongSpendAuthorizingKey)
        }
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
            .pczt
            .orchard
            .actions
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed.
        let note_from_fields = action
            .spend
            .note_from_fields()
            .ignore_missing()
            .map_err(Error::Orchard)?;

        if let Some(note) = note_from_fields {
            let tx_action = self
                .tx_data
                .orchard_bundle()
                .expect("index checked above")
                .actions()
                .get(index)
                .expect("index checked above");

            let fvk = action.spend.fvk_from_field().map_err(Error::Orchard)?;

            if &note.nullifier(fvk) != tx_action.nullifier() {
                return Err(Error::InvalidNullifier);
            }
        }

        let alpha = action.spend.alpha_from_field().map_err(Error::Orchard)?;

        let rsk = ask.randomize(&alpha);
        let rk = redpallas::VerificationKey::from(&rsk);

        let txid_parts = self.tx_data.digest(TxIdDigester);
        let shielded_sighash =
            v5_signature_hash(&self.tx_data, &SignableInput::Shielded, &txid_parts);

        if action.spend.rk == <[u8; 32]>::from(&rk) {
            let spend_auth_sig = rsk.sign(OsRng, shielded_sighash.as_ref());
            action.spend.spend_auth_sig = Some((&spend_auth_sig).into());
            Ok(())
        } else {
            Err(Error::WrongSpendAuthorizingKey)
        }
    }

    /// Finishes the Signer role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

/// Extracts an unauthorized `TransactionData` from the PCZT.
///
/// We don't care about existing proofs or signatures here, because they do not affect the
/// sighash; we only want the effects of the transaction.
fn pczt_to_tx_data(pczt: &Pczt) -> Result<TransactionData<EffectsOnly>, Error> {
    let version = match (pczt.global.tx_version, pczt.global.version_group_id) {
        (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::Zip225),
        (version, version_group_id) => Err(Error::Global(GlobalError::UnsupportedTxVersion {
            version,
            version_group_id,
        })),
    }?;

    let consensus_branch_id = BranchId::try_from(pczt.global.consensus_branch_id)
        .map_err(|_| Error::Global(GlobalError::UnknownConsensusBranchId))?;

    let transparent_bundle = pczt
        .transparent
        .to_tx_data(
            |_| Ok(()),
            |bundle| {
                let inputs = bundle
                    .inputs
                    .iter()
                    .map(|input| {
                        let value = Zatoshis::from_u64(input.value)
                            .map_err(|_| crate::transparent::Error::InvalidValue)?;
                        let script_pubkey = Script(input.script_pubkey.clone());

                        Ok(transparent::TxOut {
                            value,
                            script_pubkey,
                        })
                    })
                    .collect::<Result<_, _>>()?;

                Ok(TransparentEffectsOnly { inputs })
            },
        )
        .map_err(Error::Transparent)?;

    let sapling_bundle = pczt
        .sapling
        .to_tx_data(
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(SaplingEffectsOnly),
        )
        .map_err(Error::Sapling)?;

    let orchard_bundle = pczt
        .orchard
        .to_tx_data(|_| Ok(()), |_| Ok(OrchardEffectsOnly))
        .map_err(Error::Orchard)?;

    Ok(TransactionData::from_parts(
        version,
        consensus_branch_id,
        determine_lock_time(&pczt.global, &pczt.transparent.inputs())
            .map_err(|_| Error::IncompatibleLockTimes)?,
        pczt.global.expiry_height.into(),
        transparent_bundle,
        None,
        sapling_bundle,
        orchard_bundle,
    ))
}

struct EffectsOnly;

impl Authorization for EffectsOnly {
    type TransparentAuth = TransparentEffectsOnly;
    type SaplingAuth = SaplingEffectsOnly;
    type OrchardAuth = OrchardEffectsOnly;
}

#[derive(Debug)]
struct TransparentEffectsOnly {
    inputs: Vec<transparent::TxOut>,
}

impl transparent::Authorization for TransparentEffectsOnly {
    type ScriptSig = ();
}

impl TransparentAuthorizingContext for TransparentEffectsOnly {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.inputs.iter().map(|input| input.value).collect()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.inputs
            .iter()
            .map(|input| input.script_pubkey.clone())
            .collect()
    }
}

#[derive(Debug)]
struct SaplingEffectsOnly;

impl sapling::bundle::Authorization for SaplingEffectsOnly {
    type SpendProof = ();
    type OutputProof = ();
    type AuthSig = ();
}

#[derive(Debug)]
struct OrchardEffectsOnly;

impl orchard::bundle::Authorization for OrchardEffectsOnly {
    type SpendAuth = ();
}

/// Errors that can occur while creating signatures for a PCZT.
#[derive(Debug)]
pub enum Error {
    Global(GlobalError),
    IncompatibleLockTimes,
    InvalidIndex,
    InvalidNoteCommitment,
    InvalidNullifier,
    Orchard(crate::orchard::Error),
    Sapling(crate::sapling::Error),
    Transparent(crate::transparent::Error),
    WrongSpendAuthorizingKey,
}

#[derive(Debug)]
pub enum GlobalError {
    UnknownConsensusBranchId,
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
}
