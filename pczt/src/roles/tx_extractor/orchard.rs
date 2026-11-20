use orchard::{Bundle, bundle::Authorized, circuit::VerifyingKey};
use rand_core::CryptoRng;
use zcash_protocol::value::ZatBalance;

/// Verifies `bundle`, checking every action against its own sighash when `v7` is
/// `Some`, and otherwise against the shared `sighash`.
pub(super) fn verify_bundle(
    rng: impl CryptoRng,
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: Option<[u8; 32]>,
    v7: Option<(&[[u8; 32]], [u8; 32])>,
) -> Result<(), OrchardError> {
    match orchard_vk {
        Some(vk) => verify_bundle_with_key(rng, bundle, vk, sighash, v7),
        // The circuit version is fixed by the bundle's own `BundleVersion`, which
        // `extract_tx_data` derives from the PCZT's consensus branch ID.
        None => verify_bundle_with_key(
            rng,
            bundle,
            &VerifyingKey::build(bundle.bundle_version().circuit_version()),
            sighash,
            v7,
        ),
    }
}

fn verify_bundle_with_key(
    rng: impl CryptoRng,
    bundle: &Bundle<Authorized, ZatBalance>,
    vk: &VerifyingKey,
    sighash: Option<[u8; 32]>,
    v7: Option<(&[[u8; 32]], [u8; 32])>,
) -> Result<(), OrchardError> {
    let mut validator = orchard::bundle::BatchValidator::new(vk);
    match v7 {
        Some((action_sighashes, binding_sighash)) => validator
            .add_bundle_with_sighashes(bundle, action_sighashes, binding_sighash)
            .map_err(|_| OrchardError::InvalidProof)?,
        None => validator
            .add_bundle(
                bundle,
                sighash.expect("pre-v7 signs a shared shielded digest"),
            )
            .map_err(|_| OrchardError::InvalidProof)?,
    }

    if validator.validate(rng) {
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
