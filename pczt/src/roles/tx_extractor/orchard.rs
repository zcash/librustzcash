use orchard::{Bundle, bundle::Authorized, circuit::VerifyingKey};
use rand_core::OsRng;
use zcash_protocol::value::ZatBalance;

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    match orchard_vk {
        Some(vk) => verify_bundle_with_key(bundle, vk, sighash),
        // The circuit version is fixed by the bundle's own `BundleVersion`, which
        // `extract_tx_data` derives from the PCZT's consensus branch ID.
        None => verify_bundle_with_key(
            bundle,
            &VerifyingKey::build(bundle.bundle_version().circuit_version()),
            sighash,
        ),
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
