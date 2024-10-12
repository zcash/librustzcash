use pasta_curves::group::ff::PrimeField;
use rand_core::OsRng;
use sapling::{
    keys::SpendValidatingKey,
    prover::{OutputProver, SpendProver},
    value::{NoteValue, ValueCommitTrapdoor},
    MerklePath, Node, Note, PaymentAddress, ProofGenerationKey,
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

        let anchor = jubjub::Base::from_bytes(
            self.pczt
                .sapling
                .anchor
                .as_ref()
                .ok_or(crate::sapling::Error::MissingAnchor)?,
        )
        .into_option()
        .ok_or(crate::sapling::Error::InvalidAnchor)?;

        for spend in &mut self.pczt.sapling.spends {
            let proof_generation_key = {
                let (ak, nsk) = spend
                    .proof_generation_key
                    .ok_or(SaplingError::MissingProofGenerationKey)?;

                ProofGenerationKey {
                    ak: SpendValidatingKey::temporary_zcash_from_bytes(&ak)
                        .ok_or(SaplingError::InvalidProofGenerationKey)?,
                    nsk: jubjub::Scalar::from_repr(nsk)
                        .into_option()
                        .ok_or(SaplingError::InvalidProofGenerationKey)?,
                }
            };

            let recipient = PaymentAddress::from_bytes(
                spend
                    .recipient
                    .as_ref()
                    .ok_or(SaplingError::MissingRecipient)?,
            )
            .ok_or(SaplingError::InvalidRecipient)?;

            let rseed =
                sapling::Rseed::AfterZip212(spend.rseed.ok_or(SaplingError::MissingRandomSeed)?);

            let value = NoteValue::from_raw(spend.value.ok_or(SaplingError::MissingValue)?);

            let alpha = jubjub::Scalar::from_repr(
                spend
                    .alpha
                    .ok_or(SaplingError::MissingSpendAuthRandomizer)?,
            )
            .into_option()
            .ok_or(SaplingError::InvalidSpendAuthRandomizer)?;

            let rcv = ValueCommitTrapdoor::from_bytes(
                spend.rcv.ok_or(SaplingError::MissingValueCommitTrapdoor)?,
            )
            .into_option()
            .ok_or(SaplingError::InvalidValueCommitTrapdoor)?;

            let merkle_path = {
                let (position, auth_path_bytes) =
                    spend.witness.ok_or(SaplingError::MissingWitness)?;

                let path_elems = auth_path_bytes
                    .into_iter()
                    .map(|hash| {
                        Node::from_bytes(hash)
                            .into_option()
                            .ok_or(SaplingError::InvalidWitness)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                MerklePath::from_parts(path_elems, u64::from(position).into())
                    .map_err(|()| SaplingError::InvalidWitness)?
            };

            let circuit = S::prepare_circuit(
                proof_generation_key,
                *recipient.diversifier(),
                rseed,
                value,
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
    InvalidProofGenerationKey,
    InvalidRecipient,
    InvalidSpendAuthRandomizer,
    InvalidValueCommitTrapdoor,
    InvalidWitness,
    MissingProofGenerationKey,
    MissingRandomSeed,
    MissingRecipient,
    MissingSpendAuthRandomizer,
    MissingValue,
    MissingValueCommitTrapdoor,
    MissingWitness,
}

impl From<crate::sapling::Error> for SaplingError {
    fn from(e: crate::sapling::Error) -> Self {
        Self::Data(e)
    }
}
