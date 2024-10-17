use rand_core::OsRng;
use sapling::{
    bundle::{Authorization, Authorized},
    circuit::{OutputVerifyingKey, SpendVerifyingKey},
    BatchValidator, Bundle,
};
use zcash_primitives::transaction::components::{sapling::MapAuth, GROTH_PROOF_SIZE};
use zcash_protocol::value::ZatBalance;

pub(super) fn extract_bundle(
    bundle: crate::sapling::Bundle,
) -> Result<Option<Bundle<Unbound, ZatBalance>>, SaplingError> {
    bundle.to_tx_data(
        |spend| spend.zkproof.ok_or(SaplingError::MissingProof),
        |spend| {
            Ok(redjubjub::Signature::from(
                spend
                    .spend_auth_sig
                    .ok_or(SaplingError::MissingSpendAuthSig)?,
            ))
        },
        |output| output.zkproof.ok_or(SaplingError::MissingProof),
        |bundle| {
            let bsk = redjubjub::SigningKey::try_from(bundle.bsk.ok_or(SaplingError::MissingBsk)?)
                .map_err(|_| SaplingError::InvalidBsk)?;

            Ok(Unbound { bsk })
        },
    )
}

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    spend_vk: &SpendVerifyingKey,
    output_vk: &OutputVerifyingKey,
    sighash: [u8; 32],
) -> Result<(), SaplingError> {
    let mut validator = BatchValidator::new();

    if !validator.check_bundle(bundle.clone(), sighash) {
        return Err(SaplingError::ConsensusRuleViolation);
    }

    if !validator.validate(spend_vk, output_vk, OsRng) {
        return Err(SaplingError::InvalidProofsOrSignatures);
    }

    Ok(())
}

#[derive(Debug)]
pub(super) struct Unbound {
    bsk: redjubjub::SigningKey<redjubjub::Binding>,
}

impl Authorization for Unbound {
    type SpendProof = [u8; GROTH_PROOF_SIZE];
    type OutputProof = [u8; GROTH_PROOF_SIZE];
    type AuthSig = redjubjub::Signature<redjubjub::SpendAuth>;
}

pub(super) struct AddBindingSig<'a> {
    pub(super) sighash: &'a [u8; 32],
}

impl<'a> MapAuth<Unbound, Authorized> for AddBindingSig<'a> {
    fn map_spend_proof(
        &mut self,
        p: <Unbound as Authorization>::SpendProof,
    ) -> <Authorized as Authorization>::SpendProof {
        p
    }

    fn map_output_proof(
        &mut self,
        p: <Unbound as Authorization>::OutputProof,
    ) -> <Authorized as Authorization>::OutputProof {
        p
    }

    fn map_auth_sig(
        &mut self,
        s: <Unbound as Authorization>::AuthSig,
    ) -> <Authorized as Authorization>::AuthSig {
        s
    }

    fn map_authorization(&mut self, a: Unbound) -> Authorized {
        Authorized {
            binding_sig: a.bsk.sign(OsRng, self.sighash),
        }
    }
}

#[derive(Debug)]
pub enum SaplingError {
    ConsensusRuleViolation,
    Data(crate::sapling::Error),
    InvalidBsk,
    InvalidProofsOrSignatures,
    MissingBsk,
    MissingProof,
    MissingSpendAuthSig,
}

impl From<crate::sapling::Error> for SaplingError {
    fn from(e: crate::sapling::Error) -> Self {
        Self::Data(e)
    }
}
