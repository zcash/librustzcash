use orchard::{bundle::Authorized, circuit::VerifyingKey, pczt::Unbound, Bundle};
use rand_core::OsRng;
use zcash_protocol::value::ZatBalance;

pub(super) fn extract_bundle(
    bundle: crate::orchard::Bundle,
) -> Result<Option<Bundle<Unbound, ZatBalance>>, OrchardError> {
    bundle
        .into_parsed()
        .map_err(OrchardError::Parse)?
        .extract()
        .map_err(OrchardError::Extract)
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
pub enum OrchardError {
    Extract(orchard::pczt::TxExtractorError),
    InvalidProof,
    Parse(orchard::pczt::ParseError),
}
