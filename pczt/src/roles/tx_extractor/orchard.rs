use orchard::{
    bundle::{Authorization, Authorized},
    circuit::VerifyingKey,
    primitives::redpallas,
    Bundle, Proof,
};
use rand_core::OsRng;
use zcash_primitives::transaction::components::orchard::MapAuth;
use zcash_protocol::value::ZatBalance;

pub(super) fn extract_bundle(
    bundle: crate::orchard::Bundle,
) -> Result<Option<Bundle<Unbound, ZatBalance>>, OrchardError> {
    bundle.to_tx_data(
        |action| {
            Ok(redpallas::Signature::from(
                action
                    .spend
                    .spend_auth_sig
                    .ok_or(OrchardError::MissingSpendAuthSig)?,
            ))
        },
        |bundle| {
            let proof = Proof::new(bundle.zkproof.clone().ok_or(OrchardError::MissingProof)?);

            let bsk = redpallas::SigningKey::try_from(bundle.bsk.ok_or(OrchardError::MissingBsk)?)
                .map_err(|_| OrchardError::InvalidBsk)?;

            Ok(Unbound { proof, bsk })
        },
    )
}

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    let mut validator = orchard::bundle::BatchValidator::new();
    let rng = OsRng;

    validator.add_bundle(bundle, sighash);

    if let Some(vk) = orchard_vk {
        if validator.validate(vk, rng) {
            Ok(())
        } else {
            Err(OrchardError::InvalidProof)
        }
    } else {
        let vk = VerifyingKey::build();
        if validator.validate(&vk, rng) {
            Ok(())
        } else {
            Err(OrchardError::InvalidProof)
        }
    }
}

#[derive(Debug)]
pub(super) struct Unbound {
    proof: Proof,
    bsk: redpallas::SigningKey<redpallas::Binding>,
}

impl Authorization for Unbound {
    type SpendAuth = redpallas::Signature<redpallas::SpendAuth>;
}

pub(super) struct AddBindingSig<'a> {
    pub(super) sighash: &'a [u8; 32],
}

impl<'a> MapAuth<Unbound, Authorized> for AddBindingSig<'a> {
    fn map_spend_auth(
        &self,
        s: <Unbound as Authorization>::SpendAuth,
    ) -> <Authorized as Authorization>::SpendAuth {
        s
    }

    fn map_authorization(&self, a: Unbound) -> Authorized {
        Authorized::from_parts(a.proof, a.bsk.sign(OsRng, self.sighash))
    }
}

#[derive(Debug)]
pub enum OrchardError {
    Data(crate::orchard::Error),
    InvalidBsk,
    InvalidProof,
    MissingBsk,
    MissingProof,
    MissingSpendAuthSig,
}

impl From<crate::orchard::Error> for OrchardError {
    fn from(e: crate::orchard::Error) -> Self {
        Self::Data(e)
    }
}
