//! Sighash versioning as specified in [ZIP-246].
//!
//! [ZIP-246]: https://zips.z.cash/zip-0246

use alloc::{collections::BTreeMap, vec::Vec};
use lazy_static::lazy_static;

use orchard::orchard_sighash_versioning::OrchardSighashVersion;

#[cfg(zcash_unstable = "nu7")]
use orchard::issuance_sighash_versioning::IssueSighashVersion;

/// Orchard `SighashInfo` for V0:
/// sighashInfo = (\[sighashVersion\] || associatedData) = (\[0\] || [])
const ORCHARD_SIGHASH_INFO_V0: [u8; 1] = [0];

lazy_static! {
    /// Mapping from an `OrchardSighashVersion` to the raw byte representation of the corresponding `SighashInfo`.
    pub(crate) static ref ORCHARD_SIGHASH_VERSION_TO_INFO_BYTES: BTreeMap<OrchardSighashVersion, Vec<u8>> =
        BTreeMap::from([(OrchardSighashVersion::V0, ORCHARD_SIGHASH_INFO_V0.to_vec())]);
}

#[cfg(any(zcash_unstable = "nu7", zcash_unstable = "zfuture"))]
pub(crate) fn to_orchard_version(bytes: Vec<u8>) -> Option<OrchardSighashVersion> {
    ORCHARD_SIGHASH_VERSION_TO_INFO_BYTES
        .iter()
        .find(|(_, v)| **v == bytes)
        .map(|(k, _)| k.clone())
}

/// Issuance `SighashInfo` for V0:
/// sighashInfo = (\[sighashVersion\] || associatedData) = (\[0\] || [])
#[cfg(zcash_unstable = "nu7")]
const ISSUE_SIGHASH_INFO_V0: [u8; 1] = [0];

#[cfg(zcash_unstable = "nu7")]
lazy_static! {
    /// Mapping from an `IssueSighashVersion` to the raw byte representation of the corresponding `SighashInfo`.
    pub(crate) static ref ISSUE_SIGHASH_VERSION_TO_INFO_BYTES: BTreeMap<IssueSighashVersion, Vec<u8>> =
        BTreeMap::from([(IssueSighashVersion::V0, ISSUE_SIGHASH_INFO_V0.to_vec())]);
}

#[cfg(zcash_unstable = "nu7")]
pub(crate) fn to_issuance_version(bytes: Vec<u8>) -> Option<IssueSighashVersion> {
    ISSUE_SIGHASH_VERSION_TO_INFO_BYTES
        .iter()
        .find(|(_, v)| **v == bytes)
        .map(|(k, _)| k.clone())
}
