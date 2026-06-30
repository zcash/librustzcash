use orchard::{
    Bundle,
    bundle::Authorized,
    circuit::{OrchardCircuitVersion, VerifyingKey},
};
use rand_core::OsRng;
use zcash_protocol::value::ZatBalance;

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    if let Some(vk) = orchard_vk {
        verify_bundle_with_key(bundle, vk, sighash)
    } else {
        // PCZT extraction produces new Orchard bundles using the NU6.2 fixed
        // circuit.
        let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        verify_bundle_with_key(bundle, &vk, sighash)
    }
}

#[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
pub(super) fn verify_ironwood_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    if let Some(vk) = orchard_vk {
        verify_bundle_with_key(bundle, vk, sighash)
    } else {
        let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
        verify_bundle_with_key(bundle, &vk, sighash)
    }
}

fn verify_bundle_with_key(
    bundle: &Bundle<Authorized, ZatBalance>,
    vk: &VerifyingKey,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    let mut validator = orchard::bundle::BatchValidator::new(vk);
    validator
        .add_bundle(bundle, sighash)
        .map_err(|_| OrchardError::InvalidProof)?;

    if validator.validate(OsRng) {
        Ok(())
    } else {
        Err(OrchardError::InvalidProof)
    }
}

#[derive(Debug)]
pub enum OrchardError {
    Extract(orchard::pczt::TxExtractorError),
    InvalidProof,
}
