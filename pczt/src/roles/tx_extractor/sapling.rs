use rand_core::OsRng;
use sapling::{
    BatchValidator, Bundle,
    bundle::Authorized,
    circuit::{OutputVerifyingKey, SpendVerifyingKey},
    pczt::Unbound,
};
use zcash_protocol::value::ZatBalance;

pub(super) fn extract_bundle(
    bundle: crate::sapling::Bundle,
) -> Result<Option<Bundle<Unbound, ZatBalance>>, SaplingError> {
    bundle
        .into_parsed()
        .map_err(SaplingError::Parse)?
        .extract()
        .map_err(SaplingError::Extract)
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
pub enum SaplingError {
    ConsensusRuleViolation,
    Extract(sapling::pczt::TxExtractorError),
    InvalidProofsOrSignatures,
    Parse(sapling::pczt::ParseError),
}
