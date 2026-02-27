//! Shared utilities for extracting transaction data from a PCZT.

use blake2b_simd::Hash as Blake2bHash;
use zcash_primitives::transaction::{
    Authorization, TransactionData, TxDigests, TxVersion, sighash::SignableInput,
    sighash_v5::v5_signature_hash,
};
use zcash_protocol::consensus::BranchId;
#[cfg(all(
    any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
    feature = "zip-233"
))]
use zcash_protocol::value::Zatoshis;

use crate::common::{Global, determine_lock_time};

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// Extracts an unauthorized `TransactionData` from the PCZT.
///
/// We don't care about existing proofs or signatures here, because they do not affect the
/// sighash; we only want the effects of the transaction.
pub(crate) fn pczt_to_tx_data(
    global: &Global,
    transparent: &transparent::pczt::Bundle,
    sapling: &sapling::pczt::Bundle,
    orchard: &orchard::pczt::Bundle,
) -> Result<TransactionData<EffectsOnly>, Error> {
    let version = match (global.tx_version, global.version_group_id) {
        (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::V5),
        (version, version_group_id) => Err(Error::UnsupportedTxVersion {
            version,
            version_group_id,
        }),
    }?;

    let consensus_branch_id = BranchId::try_from(global.consensus_branch_id)
        .map_err(|_| Error::UnknownConsensusBranchId)?;

    let transparent_bundle = transparent
        .extract_effects()
        .map_err(Error::TransparentExtract)?;

    let sapling_bundle = sapling.extract_effects().map_err(Error::SaplingExtract)?;

    let orchard_bundle = orchard.extract_effects().map_err(Error::OrchardExtract)?;

    Ok(TransactionData::from_parts(
        version,
        consensus_branch_id,
        determine_lock_time(global, transparent.inputs()).ok_or(Error::IncompatibleLockTimes)?,
        global.expiry_height.into(),
        #[cfg(all(
            any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
            feature = "zip-233"
        ))]
        Zatoshis::ZERO,
        transparent_bundle,
        None,
        sapling_bundle,
        orchard_bundle,
    ))
}

pub struct EffectsOnly;

impl Authorization for EffectsOnly {
    type TransparentAuth = transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling::bundle::EffectsOnly;
    type OrchardAuth = orchard::bundle::EffectsOnly;
    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = core::convert::Infallible;
}

/// Helper to produce the correct sighash for a PCZT.
pub(crate) fn sighash(
    tx_data: &TransactionData<EffectsOnly>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> [u8; 32] {
    v5_signature_hash(tx_data, signable_input, txid_parts)
        .as_ref()
        .try_into()
        .expect("correct length")
}

/// Errors that can occur while extracting transaction data from a PCZT.
#[derive(Debug)]
pub enum Error {
    IncompatibleLockTimes,
    OrchardExtract(orchard::pczt::TxExtractorError),
    SaplingExtract(sapling::pczt::TxExtractorError),
    TransparentExtract(transparent::pczt::TxExtractorError),
    UnknownConsensusBranchId,
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
}
