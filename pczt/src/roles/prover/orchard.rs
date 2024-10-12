use orchard::{
    builder::SpendInfo,
    bundle::Flags,
    circuit::{Circuit, Instance, ProvingKey},
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho},
    primitives::redpallas,
    tree::{MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Address, Anchor, Note,
};
use rand_core::OsRng;

impl super::Prover {
    pub fn create_orchard_proof(&mut self, pk: &ProvingKey) -> Result<(), OrchardError> {
        let bundle = &self.pczt.orchard;

        let flags =
            Flags::from_byte(bundle.flags).ok_or(crate::orchard::Error::UnexpectedFlagBitsSet)?;

        let anchor = Anchor::from_bytes(bundle.anchor)
            .into_option()
            .ok_or(crate::orchard::Error::InvalidAnchor)?;

        let circuits = self
            .pczt
            .orchard
            .actions
            .iter()
            .map(|action| {
                let fvk = action.spend.fvk_from_field()?;
                let note = action.spend.note_from_fields()?;

                let merkle_path = {
                    let (position, auth_path_bytes) =
                        action.spend.witness.ok_or(OrchardError::MissingWitness)?;

                    let auth_path = auth_path_bytes
                        .into_iter()
                        .map(|hash| {
                            MerkleHashOrchard::from_bytes(&hash)
                                .into_option()
                                .ok_or(OrchardError::InvalidWitness)
                        })
                        .collect::<Result<Vec<_>, _>>()?;

                    MerklePath::from_parts(
                        position,
                        auth_path[..].try_into().expect("correct length"),
                    )
                };

                let spend =
                    SpendInfo::new(fvk, note, merkle_path).ok_or(OrchardError::WrongFvkForNote)?;

                let output_note = {
                    let recipient = Address::from_raw_address_bytes(
                        action
                            .output
                            .recipient
                            .as_ref()
                            .ok_or(OrchardError::MissingOutputRecipient)?,
                    )
                    .into_option()
                    .ok_or(OrchardError::InvalidOutputRecipient)?;

                    let value =
                        NoteValue::from_raw(action.output.value.ok_or(OrchardError::MissingValue)?);

                    let rho = Rho::from_bytes(&action.spend.nullifier)
                        .into_option()
                        .ok_or(crate::orchard::Error::InvalidNullifier)?;

                    let rseed = RandomSeed::from_bytes(
                        action.output.rseed.ok_or(OrchardError::MissingRandomSeed)?,
                        &rho,
                    )
                    .into_option()
                    .ok_or(OrchardError::InvalidRandomSeed)?;

                    Note::from_parts(recipient, value, rho, rseed)
                        .into_option()
                        .ok_or(OrchardError::InvalidOutputNote)?
                };

                let alpha = action.spend.alpha_from_field()?;

                let rcv = ValueCommitTrapdoor::from_bytes(
                    action.rcv.ok_or(OrchardError::MissingValueCommitTrapdoor)?,
                )
                .into_option()
                .ok_or(OrchardError::InvalidValueCommitTrapdoor)?;

                Ok(Circuit::from_action_context(spend, output_note, alpha, rcv)
                    .expect("rho should match nf by construction above")) // TODO: Check if this changes
            })
            .collect::<Result<Vec<_>, OrchardError>>()?;

        let instances = self
            .pczt
            .orchard
            .actions
            .iter()
            .map(|action| {
                let cv_net = ValueCommitment::from_bytes(&action.cv_net)
                    .into_option()
                    .ok_or(crate::orchard::Error::InvalidValueCommitment)?;

                let nf_old = Nullifier::from_bytes(&action.spend.nullifier)
                    .into_option()
                    .ok_or(crate::orchard::Error::InvalidNullifier)?;

                let rk = redpallas::VerificationKey::try_from(action.spend.rk)
                    .map_err(|_| crate::orchard::Error::InvalidRandomizedKey)?;

                let cmx = ExtractedNoteCommitment::from_bytes(&action.output.cmx)
                    .into_option()
                    .ok_or(crate::orchard::Error::InvalidExtractedNoteCommitment)?;

                Ok(Instance::from_parts(
                    anchor,
                    cv_net,
                    nf_old,
                    rk,
                    cmx,
                    flags.spends_enabled(),
                    flags.outputs_enabled(),
                ))
            })
            .collect::<Result<Vec<_>, OrchardError>>()?;

        let proof = orchard::Proof::create(pk, &circuits, &instances, OsRng)
            .map_err(|_| OrchardError::ProofFailed)?;

        self.pczt.orchard.zkproof = Some(proof.as_ref().to_vec());

        Ok(())
    }
}

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Data(crate::orchard::Error),
    InvalidOutputNote,
    InvalidOutputRecipient,
    InvalidRandomSeed,
    InvalidSpendAuthRandomizer,
    InvalidValueCommitTrapdoor,
    InvalidWitness,
    MissingOutputRecipient,
    MissingRandomSeed,
    MissingSpendAuthRandomizer,
    MissingValue,
    MissingValueCommitTrapdoor,
    MissingWitness,
    ProofFailed,
    WrongFvkForNote,
}

impl From<crate::orchard::Error> for OrchardError {
    fn from(e: crate::orchard::Error) -> Self {
        Self::Data(e)
    }
}
