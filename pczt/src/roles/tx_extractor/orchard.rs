use orchard::orchard_flavor::OrchardFlavor;
use orchard::primitives::OrchardPrimitives;
use orchard::{bundle::Authorized, circuit::VerifyingKey, pczt::Unbound, Bundle};
use rand_core::OsRng;
use zcash_protocol::value::ZatBalance;

pub(super) fn extract_bundle<D: OrchardPrimitives>(
    bundle: crate::orchard::Bundle,
) -> Result<Option<Bundle<Unbound, ZatBalance, D>>, OrchardError> {
    bundle
        .into_parsed()
        .map_err(OrchardError::Parse)?
        .extract()
        .map_err(OrchardError::Extract)
}

pub(super) fn verify_bundle<D: OrchardFlavor>(
    bundle: &Bundle<Authorized, ZatBalance, D>,
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
        let vk = VerifyingKey::build::<D>();
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
