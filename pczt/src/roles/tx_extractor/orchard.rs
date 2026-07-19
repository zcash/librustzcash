use orchard::{Bundle, bundle::Authorized, circuit::VerifyingKey, flavor::OrchardVanilla};
use rand_core::OsRng;
use zcash_protocol::value::ZatBalance;

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance, OrchardVanilla>,
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
        // PCZT extraction produces new transactions, which use the NU6.2 (fixed) circuit.
        let vk = VerifyingKey::build::<OrchardVanilla>();
        if validator.validate(&vk, rng) {
            Ok(())
        } else {
            Err(OrchardError::InvalidProof)
        }
    }
}

#[derive(Debug)]
pub enum OrchardError {
    Extract(orchard::pczt::TxExtractorError),
    InvalidProof,
}
