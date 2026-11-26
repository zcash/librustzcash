use rand_core::CryptoRng;
use sapling::{
    BatchValidator, Bundle,
    bundle::Authorized,
    circuit::{OutputVerifyingKey, SpendVerifyingKey},
};
use zcash_protocol::value::ZatBalance;

/// Verifies `bundle`, checking every Spend against its own sighash when `v7` is
/// `Some`, and otherwise against the shared `sighash`.
pub(super) fn verify_bundle(
    rng: impl CryptoRng,
    bundle: &Bundle<Authorized, ZatBalance>,
    spend_vk: &SpendVerifyingKey,
    output_vk: &OutputVerifyingKey,
    sighash: Option<[u8; 32]>,
    v7: Option<(&[[u8; 32]], [u8; 32])>,
) -> Result<(), SaplingError> {
    let mut validator = BatchValidator::new();

    let valid = match v7 {
        Some((spend_sighashes, binding_sighash)) => {
            validator.check_bundle_with_sighashes(bundle.clone(), spend_sighashes, binding_sighash)
        }
        None => validator.check_bundle(
            bundle.clone(),
            sighash.expect("pre-v7 signs a shared shielded digest"),
        ),
    };
    if !valid {
        return Err(SaplingError::ConsensusRuleViolation);
    }

    if !validator.validate(spend_vk, output_vk, rng) {
        return Err(SaplingError::InvalidProofsOrSignatures);
    }

    Ok(())
}

#[derive(Debug)]
pub enum SaplingError {
    ConsensusRuleViolation,
    Extract(sapling::pczt::TxExtractorError),
    InvalidProofsOrSignatures,
}
