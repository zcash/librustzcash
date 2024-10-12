use rand_core::OsRng;
use sapling::{
    prover::{OutputProver, SpendProver},
    value::{NoteValue, ValueCommitTrapdoor},
    Note, PaymentAddress,
};

impl super::Prover {
    pub fn create_sapling_proofs<S, O>(
        &mut self,
        spend_prover: &S,
        output_prover: &O,
    ) -> Result<(), SaplingError>
    where
        S: SpendProver,
        O: OutputProver,
    {
        let mut rng = OsRng;

        let anchor = jubjub::Base::from_bytes(&self.pczt.sapling.anchor)
            .into_option()
            .ok_or(crate::sapling::Error::InvalidAnchor)?;

        for spend in &mut self.pczt.sapling.spends {
            let proof_generation_key = spend.proof_generation_key_from_field()?;
            let note = spend.note_from_fields()?;
            let alpha = spend.alpha_from_field()?;

            let rcv = ValueCommitTrapdoor::from_bytes(
                spend.rcv.ok_or(SaplingError::MissingValueCommitTrapdoor)?,
            )
            .into_option()
            .ok_or(SaplingError::InvalidValueCommitTrapdoor)?;

            let merkle_path = spend.witness_from_field()?;

            let circuit = S::prepare_circuit(
                proof_generation_key,
                *note.recipient().diversifier(),
                *note.rseed(),
                note.value(),
                alpha,
                rcv,
                anchor,
                merkle_path,
            )
            .ok_or(SaplingError::InvalidDiversifier)?;

            let proof = spend_prover.create_proof(circuit, &mut rng);
            spend.zkproof = Some(S::encode_proof(proof));
        }

        for output in &mut self.pczt.sapling.outputs {
            let recipient = PaymentAddress::from_bytes(
                output
                    .recipient
                    .as_ref()
                    .ok_or(SaplingError::MissingRecipient)?,
            )
            .ok_or(SaplingError::InvalidRecipient)?;

            let value = NoteValue::from_raw(output.value.ok_or(SaplingError::MissingValue)?);

            let rseed =
                sapling::Rseed::AfterZip212(output.rseed.ok_or(SaplingError::MissingRandomSeed)?);

            let note = Note::from_parts(recipient, value, rseed);

            let esk = note.generate_or_derive_esk(&mut rng);
            let rcm = note.rcm();

            let rcv = ValueCommitTrapdoor::from_bytes(
                output.rcv.ok_or(SaplingError::MissingValueCommitTrapdoor)?,
            )
            .into_option()
            .ok_or(SaplingError::InvalidValueCommitTrapdoor)?;

            let circuit = O::prepare_circuit(&esk, recipient, rcm, value, rcv);
            let proof = output_prover.create_proof(circuit, &mut rng);
            output.zkproof = Some(O::encode_proof(proof));
        }

        Ok(())
    }
}

/// Errors that can occur while creating Sapling proofs for a PCZT.
#[derive(Debug)]
pub enum SaplingError {
    Data(crate::sapling::Error),
    InvalidDiversifier,
    InvalidRecipient,
    InvalidValueCommitTrapdoor,
    MissingRandomSeed,
    MissingRecipient,
    MissingValue,
    MissingValueCommitTrapdoor,
}

impl From<crate::sapling::Error> for SaplingError {
    fn from(e: crate::sapling::Error) -> Self {
        Self::Data(e)
    }
}
